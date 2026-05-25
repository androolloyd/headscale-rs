//! `POST /machine/{node_key}/map` — long-poll peer map.
//!
//! Returns a Tailscale-shape `MapResponse` containing the requesting
//! node's own assignment plus the other peer(s) currently registered
//! in the same tailnet. If only one peer is registered (this one), we
//! long-poll up to [`MAP_LONGPOLL_TIMEOUT`] waiting for a second peer
//! to join; on timeout we still return a valid (empty-peers) response
//! so the client doesn't error out.
//!
//! ## Decision log
//!
//! - **`Stream=true` framing: `[u32 LE size][body]`, with optional
//!   `zstd(JSON)`.** Discovered while diagnosing Wall 5 in
//!   `docs/tailscale-interop-blocker.md`.
//!   Upstream's `tailscale/control/controlclient/direct.go::sendMapRequest`
//!   reads bytes with `binary.LittleEndian.Uint32(siz[:4])`, then
//!   only zstd-decodes when `MapRequest.Compress == "zstd"`. The
//!   framing is NOT newline-delimited, and the stream is NOT
//!   terminated naturally — the client expects keepalive frames
//!   carrying `{"KeepAlive":true}` in the same compression mode every
//!   <120 s (`watchdogTimeout`).
//!   Our `Stream=false` test path emits a single plaintext JSON
//!   `MapResponse` for the non-noise direct-router tests; the prod
//!   `Stream=true` path emits the upstream framed stream.
//! - **Long-poll wake via `tokio::sync::Notify` on the registry.**
//!   Cheaper than a watch channel for the 2-peer test and the
//!   correctness story is simpler — every register notifies, every
//!   waiter wakes and recomputes the snapshot.
//! - **Keepalive interval = 30s.** Upstream watchdog is 120s, so this
//!   leaves 4x headroom for slow links. Keepalive bytes are
//!   a framed `{"KeepAlive":true}` payload, NOT a bare newline.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

use axum::{
    Extension, Json,
    body::{Body, Bytes},
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use super::noise::NoisePeerMachineKey;

/// Decode a `MapRequest` from a raw body without requiring
/// `Content-Type: application/json`. Stock `tailscale up` (via
/// controlhttp over the noise tunnel) posts without the header set;
/// the `axum::Json` extractor 415s those requests.
fn parse_map_body(raw: &[u8]) -> Result<MapRequest, Response> {
    serde_json::from_slice::<MapRequest>(raw).map_err(|e| {
        tracing::error!(target = "tailscale_wire::map", error = %e, "invalid MapRequest JSON");
        plain_map_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
    })
}
use serde::Serialize;

use super::register::{CAPABILITY_FILE_SHARING, record_to_map_node};
use super::routes::{active_exit_routes, auto_approved_routes_for_node, normalize_routes};
use super::wire::{
    DebugConfig, DnsConfig, FilterRule, HostInfo, MapNode, MapRequest, MapResponse, NetPortRange,
    PeerChange, PingRequest, PortRange, UserProfile, ZERO_NODE_KEY_HEX,
    is_supported_capability_version, stable_id_from_key, strip_key_prefix,
    unsupported_client_error,
};
use super::{MachineRecord, MapResponseDebugStore, MapResponseDebugType, WireState};

use crate::dns::{DnsRequester, DnsStore, MachineDnsRecord};
use crate::policy::{NodeView, PacketFilterNode, PeerMapNode, PolicyStore, SshPolicyNode};

const MAP_NODE_NOT_FOUND_ERROR: &str = "node not found";
const MAP_NODE_KEY_MISMATCH_ERROR: &str =
    "node key in request does not match the one associated with this machine key";

fn host_info_for_map_update(current: &HostInfo, requested: &HostInfo) -> HostInfo {
    let mut merged = serde_json::to_value(current).unwrap_or_default();
    let mut update = serde_json::to_value(requested).unwrap_or_default();
    if let Some(fields) = update.as_object_mut() {
        for key in ["Hostname", "OS", "OSVersion"] {
            if fields
                .get(key)
                .and_then(serde_json::Value::as_str)
                .is_some_and(str::is_empty)
            {
                fields.remove(key);
            }
        }
        fields.remove("RoutableIPs");
    }
    if let (Some(merged), Some(update)) = (merged.as_object_mut(), update.as_object()) {
        for (key, value) in update {
            merged.insert(key.clone(), value.clone());
        }
    }
    serde_json::from_value(merged).unwrap_or_else(|_| requested.clone())
}

const MAP_COMPRESSION_ZSTD: &str = "zstd";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MapFrameCompression {
    None,
    Zstd,
}

impl MapFrameCompression {
    fn from_request(compress: &str) -> Self {
        if compress == MAP_COMPRESSION_ZSTD {
            Self::Zstd
        } else {
            Self::None
        }
    }

    fn encode(self, bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        match self {
            Self::None => Ok(bytes.to_vec()),
            Self::Zstd => zstd::bulk::compress(bytes, 3)
                .map_err(|e| std::io::Error::other(format!("zstd encode: {e}"))),
        }
    }
}

fn record_mapresponse_debug(
    store: &MapResponseDebugStore,
    node_id: u64,
    debug_type: MapResponseDebugType,
    response: &MapResponse,
) {
    if let Err(err) = store.record(node_id, debug_type, response) {
        tracing::error!(
            target: "tailscale_wire::map",
            error = %err,
            node_id,
            debug_type = debug_type.as_str(),
            "writing MapResponse debug dump"
        );
    }
}

/// Snapshot the registry into MagicDNS-record shape and ask the
/// operator-configured [`DnsStore`] to build the `DnsConfig` for this
/// MapResponse. Pulled into a helper so both the initial `map_inner`
/// build and the streaming `rebuild_map_chunk` use the same code path
/// — drift here would mean an ExtraRecords hot-reload only lands on
/// one of the two emission sites.
fn build_dns_for_snapshot(
    dns: &DnsStore,
    policy: &PolicyStore,
    snapshot: &HashMap<String, MachineRecord>,
    self_node_key: &str,
) -> DnsConfig {
    let machines: Vec<MachineDnsRecord> = snapshot
        .iter()
        .map(|(node_hex, rec)| MachineDnsRecord {
            hostname: rec.hostname.clone(),
            ipv4: rec.ipv4,
            ipv6: rec.ipv6,
            node_id: rec.stable_node_id_for_key(node_hex),
        })
        .collect();
    let requester = snapshot.get(self_node_key).map(|rec| {
        let primary_ip = rec.primary_addr_string();
        let view = NodeView {
            addr: primary_ip.as_deref(),
            user: Some(&rec.user),
            tags: &rec.forced_tags,
        };
        let node_attrs = policy.node_attrs_for(&view);
        let host_info = rec.host_info_for_node();
        DnsRequester {
            hostname: rec.hostname.clone(),
            os: host_info.os,
            primary_ip,
            node_attrs,
        }
    });
    dns.build_for_requester(&machines, requester.as_ref())
}

fn exit_routes_for_snapshot(
    snapshot: &HashMap<String, MachineRecord>,
) -> HashMap<String, Vec<String>> {
    snapshot
        .iter()
        .filter_map(|(node_key, rec)| {
            let routes = active_exit_routes(&rec.available_routes, &rec.approved_routes);
            if routes.is_empty() {
                None
            } else {
                Some((node_key.clone(), routes))
            }
        })
        .collect()
}

fn served_routes_for_snapshot(
    snapshot: &HashMap<String, MachineRecord>,
) -> HashMap<String, Vec<String>> {
    snapshot
        .iter()
        .filter_map(|(node_key, rec)| {
            let mut routes =
                super::routes::active_approved_routes(&rec.available_routes, &rec.approved_routes);
            routes.extend(active_exit_routes(
                &rec.available_routes,
                &rec.approved_routes,
            ));
            routes.sort();
            routes.dedup();
            if routes.is_empty() {
                None
            } else {
                Some((node_key.clone(), routes))
            }
        })
        .collect()
}

fn route_is_exit_default(route: &str) -> bool {
    matches!(route, "0.0.0.0/0" | "::/0")
}

fn peer_map_nodes_from_snapshot(
    snapshot: &HashMap<String, MachineRecord>,
    served_routes: &HashMap<String, Vec<String>>,
) -> Vec<PeerMapNode> {
    snapshot
        .iter()
        .map(|(node_key, rec)| PeerMapNode {
            id: rec.stable_node_id_for_key(node_key),
            addr: rec.primary_addr_string().unwrap_or_default(),
            user: (!rec.user.is_empty()).then(|| rec.user.clone()),
            tags: rec.forced_tags.clone(),
            routes: served_routes.get(node_key).cloned().unwrap_or_default(),
        })
        .collect()
}

fn packet_filter_nodes_from_snapshot(
    snapshot: &HashMap<String, MachineRecord>,
    served_routes: &HashMap<String, Vec<String>>,
) -> Vec<PacketFilterNode> {
    snapshot
        .iter()
        .map(|(node_key, rec)| PacketFilterNode {
            id: rec.stable_node_id_for_key(node_key),
            user: (!rec.user.is_empty()).then(|| rec.user.clone()),
            addrs: rec.address_strings(),
            tags: rec.forced_tags.clone(),
            routes: served_routes.get(node_key).cloned().unwrap_or_default(),
        })
        .collect()
}

fn node_id_for_key(snapshot: &HashMap<String, MachineRecord>, node_key: &str) -> u64 {
    snapshot.get(node_key).map_or_else(
        || stable_id_from_key(node_key),
        |rec| rec.stable_node_id_for_key(node_key),
    )
}

fn allowed_peer_ids_for_snapshot(
    policy: &PolicyStore,
    snapshot: &HashMap<String, MachineRecord>,
    self_node_key: &str,
    served_routes: &HashMap<String, Vec<String>>,
) -> Option<BTreeSet<u64>> {
    let nodes = peer_map_nodes_from_snapshot(snapshot, served_routes);
    let peer_map = policy.build_peer_map(&nodes)?;
    let self_id = node_id_for_key(snapshot, self_node_key);
    Some(
        peer_map
            .get(&self_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect(),
    )
}

fn peer_allowed(allowed_ids: Option<&BTreeSet<u64>>, node_key: &str, rec: &MachineRecord) -> bool {
    match allowed_ids {
        Some(ids) => ids.contains(&rec.stable_node_id_for_key(node_key)),
        None => true,
    }
}

fn add_co_router_primary_peer_ids(
    allowed_ids: &mut Option<BTreeSet<u64>>,
    snapshot: &HashMap<String, MachineRecord>,
    self_node_key: &str,
    primary_routes: &HashMap<String, Vec<String>>,
    served_routes: &HashMap<String, Vec<String>>,
) {
    let Some(allowed_ids) = allowed_ids else {
        return;
    };
    let Some(viewer_routes) = served_routes.get(self_node_key) else {
        return;
    };
    let viewer_subnet_routes = viewer_routes
        .iter()
        .filter(|route| !route_is_exit_default(route))
        .collect::<BTreeSet<_>>();
    if viewer_subnet_routes.is_empty() {
        return;
    }

    for (node_key, routes) in primary_routes {
        if node_key == self_node_key {
            continue;
        }
        if !routes
            .iter()
            .any(|route| viewer_subnet_routes.contains(route))
        {
            continue;
        }
        if let Some(rec) = snapshot.get(node_key) {
            allowed_ids.insert(rec.stable_node_id_for_key(node_key));
        }
    }
}

fn select_routes_for_viewer(
    policy: &PolicyStore,
    snapshot: &HashMap<String, MachineRecord>,
    self_node_key: &str,
    peer_node_key: &str,
    primary_routes: &HashMap<String, Vec<String>>,
    exit_routes: &HashMap<String, Vec<String>>,
    served_routes: &HashMap<String, Vec<String>>,
) -> (Vec<String>, Vec<String>) {
    let mut selected_primary = primary_routes
        .get(peer_node_key)
        .cloned()
        .unwrap_or_default();
    let mut allowed_routes = selected_primary.clone();
    allowed_routes.extend(exit_routes.get(peer_node_key).cloned().unwrap_or_default());

    let nodes = peer_map_nodes_from_snapshot(snapshot, served_routes);
    let viewer_id = node_id_for_key(snapshot, self_node_key);
    let peer_id = node_id_for_key(snapshot, peer_node_key);
    if let Some(via) = policy.via_routes_for_peer(&nodes, viewer_id, peer_id) {
        selected_primary.retain(|route| !via.exclude.contains(route));
        allowed_routes.retain(|route| !via.exclude.contains(route));
        for route in via.include {
            if !allowed_routes.contains(&route) {
                let use_primary = via.use_primary.contains(&route);
                if !use_primary || selected_primary.contains(&route) {
                    allowed_routes.push(route);
                }
            }
        }
    }

    if let Some(viewer_routes) = served_routes.get(self_node_key) {
        let viewer_subnet_routes = viewer_routes
            .iter()
            .filter(|route| !route_is_exit_default(route))
            .collect::<BTreeSet<_>>();
        if !viewer_subnet_routes.is_empty() {
            for route in primary_routes
                .get(peer_node_key)
                .into_iter()
                .flatten()
                .filter(|route| viewer_subnet_routes.contains(route))
            {
                if !selected_primary.contains(route) {
                    selected_primary.push(route.clone());
                }
                if !allowed_routes.contains(route) {
                    allowed_routes.push(route.clone());
                }
            }
        }
    }

    selected_primary.sort();
    selected_primary.dedup();
    allowed_routes.sort();
    allowed_routes.dedup();
    (selected_primary, allowed_routes)
}

fn peer_state_from_nodes(peers: &[MapNode]) -> BTreeMap<u64, MapNode> {
    peers.iter().map(|peer| (peer.id, peer.clone())).collect()
}

fn peer_ids_from_snapshot(
    snapshot: &HashMap<String, MachineRecord>,
    self_node_key: &str,
) -> BTreeSet<u64> {
    snapshot
        .iter()
        .filter(|(node_key, _rec)| node_key.as_str() != self_node_key)
        .map(|(node_key, rec)| rec.stable_node_id_for_key(node_key))
        .collect()
}

fn apply_transient_lifecycle(
    node: &mut MapNode,
    rec: &MachineRecord,
    online_states: &BTreeMap<u64, bool>,
) {
    let online = !rec.is_expired_at(chrono::Utc::now())
        && online_states.get(&node.id).copied().unwrap_or(false);
    node.online = Some(online);
    node.last_seen = if online { None } else { Some(rec.last_seen) };
}

fn self_map_node_from_snapshot(
    snapshot: &HashMap<String, MachineRecord>,
    self_node_key: &str,
    tailnet_domain: &str,
    primary_routes: &HashMap<String, Vec<String>>,
    exit_routes: &HashMap<String, Vec<String>>,
    online_states: &BTreeMap<u64, bool>,
    policy: &PolicyStore,
    cap_version: u32,
    taildrop_enabled: bool,
) -> Option<MapNode> {
    let own = snapshot.get(self_node_key)?;
    let mut own_node = record_to_map_node(own, tailnet_domain);
    apply_transient_lifecycle(&mut own_node, own, online_states);
    own_node.cap = cap_version;
    apply_routes_to_map_node(
        &mut own_node,
        primary_routes
            .get(self_node_key)
            .map(Vec::as_slice)
            .unwrap_or_default(),
        exit_routes
            .get(self_node_key)
            .map(Vec::as_slice)
            .unwrap_or_default(),
    );
    apply_policy_attrs_to_map_node(&mut own_node, own, policy);
    apply_taildrop_to_map_node(&mut own_node, taildrop_enabled);
    Some(own_node)
}

fn self_map_node_for_registry(
    machines: &crate::tailscale_wire::MachineRegistry,
    policy: &PolicyStore,
    dns: &DnsStore,
    self_node_key: &str,
    cap_version: u32,
    taildrop_enabled: bool,
) -> Option<MapNode> {
    let snapshot = machines.snapshot();
    let tailnet_domain = tailnet_domain(dns);
    let primary_routes = machines.primary_routes_for_snapshot(&snapshot);
    let exit_routes = exit_routes_for_snapshot(&snapshot);
    let online_states = machines.online_states();
    self_map_node_from_snapshot(
        &snapshot,
        self_node_key,
        &tailnet_domain,
        &primary_routes,
        &exit_routes,
        &online_states,
        policy,
        cap_version,
        taildrop_enabled,
    )
}

fn visible_peer_state_for_registry(
    machines: &crate::tailscale_wire::MachineRegistry,
    policy: &PolicyStore,
    dns: &DnsStore,
    self_node_key: &str,
    cap_version: u32,
    taildrop_enabled: bool,
) -> BTreeMap<u64, MapNode> {
    let snapshot = machines.snapshot();
    let tailnet_domain = tailnet_domain(dns);
    let primary_routes = machines.primary_routes_for_snapshot(&snapshot);
    let exit_routes = exit_routes_for_snapshot(&snapshot);
    let online_states = machines.online_states();
    let served_routes = served_routes_for_snapshot(&snapshot);
    let mut allowed_peer_ids =
        allowed_peer_ids_for_snapshot(policy, &snapshot, self_node_key, &served_routes);
    add_co_router_primary_peer_ids(
        &mut allowed_peer_ids,
        &snapshot,
        self_node_key,
        &primary_routes,
        &served_routes,
    );
    let peers = visible_peer_map_nodes(
        &snapshot,
        self_node_key,
        allowed_peer_ids.as_ref(),
        &tailnet_domain,
        &primary_routes,
        &exit_routes,
        &served_routes,
        &online_states,
        policy,
        cap_version,
        taildrop_enabled,
    );
    peer_state_from_nodes(&peers)
}

fn incremental_allowed_peer_ids_for_snapshot(
    policy: &PolicyStore,
    snapshot: &HashMap<String, MachineRecord>,
    self_node_key: &str,
    served_routes: &HashMap<String, Vec<String>>,
    initial_peer_ids: &BTreeSet<u64>,
    last_peer_state: &BTreeMap<u64, MapNode>,
) -> Option<BTreeSet<u64>> {
    if policy.acl_rule_count() == Some(0) {
        let current_peer_ids = peer_ids_from_snapshot(snapshot, self_node_key);
        let mut surfaced_peer_ids = last_peer_state
            .keys()
            .filter(|id| current_peer_ids.contains(id))
            .copied()
            .collect::<BTreeSet<_>>();
        surfaced_peer_ids.extend(current_peer_ids.difference(initial_peer_ids).copied());
        return Some(surfaced_peer_ids);
    }
    allowed_peer_ids_for_snapshot(policy, snapshot, self_node_key, served_routes)
}

fn map_node_json_value(node: &MapNode) -> Option<serde_json::Value> {
    serde_json::to_value(node).ok()
}

fn map_node_has_subnet_route(node: &MapNode) -> bool {
    node.allowed_ips
        .iter()
        .any(|route| !node.addresses.contains(route) && route != "0.0.0.0/0" && route != "::/0")
}

fn peer_patch_if_only_patchable_fields_changed(
    previous: &MapNode,
    current: &MapNode,
) -> Option<PeerChange> {
    let endpoints_changed = previous.endpoints != current.endpoints;
    let derp_changed = previous.home_derp != current.home_derp;
    let online_changed = previous.online != current.online;
    let last_seen_changed = previous.last_seen != current.last_seen;
    let key_expiry_changed = previous.key_expiry != current.key_expiry;
    let last_seen_patch =
        last_seen_changed && !online_changed && !endpoints_changed && !derp_changed;
    if !endpoints_changed
        && !derp_changed
        && !online_changed
        && !last_seen_patch
        && !key_expiry_changed
    {
        return None;
    }
    // `tailcfg.PeerChange.DERPRegion` omits zero, and headscale-go falls
    // back to a full node update for clears instead of an empty patch.
    if derp_changed && current.home_derp == 0 {
        return None;
    }
    // headscale-go sends full updates for subnet-router online/offline
    // transitions so primary-route recalculation is carried with the node.
    if online_changed && (map_node_has_subnet_route(previous) || map_node_has_subnet_route(current))
    {
        return None;
    }

    let previous_normalized = previous.clone();
    let mut current_normalized = current.clone();
    current_normalized.endpoints.clone_from(&previous.endpoints);
    current_normalized.home_derp = previous.home_derp;
    current_normalized
        .legacy_derp_string
        .clone_from(&previous.legacy_derp_string);
    current_normalized
        .hostinfo
        .net_info
        .clone_from(&previous.hostinfo.net_info);
    current_normalized.last_seen = previous.last_seen;
    current_normalized.online = previous.online;
    current_normalized.key_expiry = previous.key_expiry;

    if map_node_json_value(&previous_normalized) != map_node_json_value(&current_normalized) {
        return None;
    }

    Some(PeerChange {
        node_id: current.id,
        endpoints: if endpoints_changed {
            current.endpoints.clone()
        } else {
            Vec::new()
        },
        derp_region: if derp_changed { current.home_derp } else { 0 },
        online: if online_changed { current.online } else { None },
        last_seen: if last_seen_patch {
            current.last_seen
        } else {
            None
        },
        key_expiry: if key_expiry_changed {
            current.key_expiry
        } else {
            None
        },
        ..PeerChange::default()
    })
}

fn visible_peer_map_nodes(
    snapshot: &HashMap<String, MachineRecord>,
    self_node_key: &str,
    allowed_ids: Option<&BTreeSet<u64>>,
    tailnet_domain: &str,
    primary_routes: &HashMap<String, Vec<String>>,
    exit_routes: &HashMap<String, Vec<String>>,
    served_routes: &HashMap<String, Vec<String>>,
    online_states: &BTreeMap<u64, bool>,
    policy: &PolicyStore,
    cap_version: u32,
    taildrop_enabled: bool,
) -> Vec<MapNode> {
    let mut peers: Vec<MapNode> = snapshot
        .iter()
        .filter(|(node_key, _)| node_key.as_str() != self_node_key)
        .filter(|(node_key, rec)| peer_allowed(allowed_ids, node_key, rec))
        .map(|(node_key, rec)| {
            let mut node = record_to_map_node(rec, tailnet_domain);
            apply_transient_lifecycle(&mut node, rec, online_states);
            node.cap = cap_version;
            let (selected_primary, selected_allowed) = select_routes_for_viewer(
                policy,
                snapshot,
                self_node_key,
                node_key,
                primary_routes,
                exit_routes,
                served_routes,
            );
            apply_selected_routes_to_map_node(&mut node, &selected_primary, &selected_allowed);
            apply_policy_attrs_to_map_node(&mut node, rec, policy);
            apply_taildrop_to_map_node(&mut node, taildrop_enabled);
            node
        })
        .collect();
    peers.sort_by_key(|node| node.id);
    peers
}

fn user_profiles_for_snapshot(
    snapshot: &HashMap<String, MachineRecord>,
    self_node_key: &str,
    allowed_ids: Option<&BTreeSet<u64>>,
) -> Vec<UserProfile> {
    let mut profiles = BTreeMap::new();
    for (node_key, rec) in snapshot {
        if node_key == self_node_key || peer_allowed(allowed_ids, node_key, rec) {
            let profile = rec.tailscale_user_profile();
            profiles.entry(profile.id).or_insert(profile);
        }
    }
    profiles.into_values().collect()
}

fn apply_routes_to_map_node(node: &mut MapNode, primary_routes: &[String], exit_routes: &[String]) {
    node.primary_routes = primary_routes.to_vec();
    node.allowed_ips = node.addresses.clone();
    node.allowed_ips.extend(primary_routes.iter().cloned());
    node.allowed_ips.extend(exit_routes.iter().cloned());
    node.allowed_ips.sort();
    node.allowed_ips.dedup();
}

fn apply_selected_routes_to_map_node(
    node: &mut MapNode,
    primary_routes: &[String],
    allowed_routes: &[String],
) {
    node.primary_routes = primary_routes.to_vec();
    node.allowed_ips = node.addresses.clone();
    node.allowed_ips.extend(allowed_routes.iter().cloned());
    node.allowed_ips.sort();
    node.allowed_ips.dedup();
}

fn apply_policy_attrs_to_map_node(
    node: &mut MapNode,
    rec: &super::MachineRecord,
    policy: &PolicyStore,
) {
    let addr = rec.primary_addr_string();
    let view = NodeView {
        addr: addr.as_deref(),
        user: Some(&rec.user),
        tags: &rec.forced_tags,
    };
    for attr in policy.node_attrs_for(&view) {
        node.cap_map.entry(attr).or_default();
    }
}

fn apply_taildrop_to_map_node(node: &mut MapNode, taildrop_enabled: bool) {
    if !taildrop_enabled {
        node.cap_map.remove(CAPABILITY_FILE_SHARING);
    }
}

/// How long we wait for a second peer to join before returning an
/// empty-peers `MapResponse`.
pub const MAP_LONGPOLL_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval between newline keepalives when the client requested
/// `Stream: true`. Stock `tailscale` daemon accepts a keepalive of any
/// length as long as it arrives within its idle timeout (60s upstream);
/// 30s leaves headroom for slow links.
pub const MAP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

fn tailnet_domain(dns: &DnsStore) -> String {
    dns.spec().base_domain.clone()
}

/// Wall 7 (closed in the same commit batch as Wall 6 for the interop
/// path): the canonical "everyone can reach everyone on every port"
/// packet filter. Stock `tailscale` v1.78+ rejects inter-peer traffic
/// with `unknown peer` when `MapResponse.PacketFilter` is empty —
/// even though the netmap holds the target node. Production
/// deployments derive this list from the ACL surface; the interop
/// test runs with an open default so the ping assertion lands.
///
/// Headscale-go parity: this mirrors `tailcfg.FilterAllowAll`, using
/// literal `*` on both source and destination.
pub(crate) fn allow_all_packet_filter() -> Vec<FilterRule> {
    vec![FilterRule {
        src_ips: vec!["*".to_string()],
        dst_ports: vec![NetPortRange {
            ip: "*".to_string(),
            ports: PortRange {
                first: 0,
                last: 65535,
            },
        }],
        ip_proto: Vec::new(),
    }]
}

/// Pick the packet filter to send in a `MapResponse`.
///
/// Decision table:
///
/// | `policy.is_loaded()` | `policy.filter_rules()` | result |
/// |---|---|---|
/// | false                | (any)                   | `allow_all_packet_filter()` |
/// | true                 | non-empty               | the cached `FilterRule` list |
/// | true                 | empty                   | `vec![]` (deny-all on the wire) |
///
/// "Empty result on a loaded policy" is the deny-all path: the
/// operator pushed a doc whose only rules are `deny` (or whose
/// accept rules have no resolvable principals). Stock `tailscale`
/// v1.78+ rejects inter-peer traffic with `unknown peer` in that
/// state, which is the intended UX.
///
/// "No policy loaded" preserves the interop default — the Wall 7
/// fixture still works without an operator-supplied ACL.
pub(crate) fn packet_filter_for(policy: &crate::policy::PolicyStore) -> Vec<FilterRule> {
    if policy.is_loaded() {
        policy.filter_rules()
    } else {
        allow_all_packet_filter()
    }
}

fn packet_filters_for_node(
    policy: &crate::policy::PolicyStore,
    nodes: &[PacketFilterNode],
    self_node_id: u64,
) -> BTreeMap<String, Option<Vec<FilterRule>>> {
    let base = policy
        .filter_rules_for_node(nodes, self_node_id)
        .unwrap_or_else(allow_all_packet_filter);
    BTreeMap::from([("base".to_string(), Some(base))])
}

fn ssh_policy_nodes_from_snapshot(
    snapshot: &std::collections::HashMap<String, super::MachineRecord>,
) -> Vec<SshPolicyNode> {
    snapshot
        .iter()
        .map(|(node_hex, rec)| SshPolicyNode {
            id: rec.stable_node_id_for_key(node_hex),
            user: if rec.user.is_empty() {
                None
            } else {
                Some(rec.user.clone())
            },
            addrs: rec.address_strings(),
            tags: rec.forced_tags.clone(),
        })
        .collect()
}

fn ssh_policy_for_snapshot(
    policy: &crate::policy::PolicyStore,
    snapshot: &std::collections::HashMap<String, super::MachineRecord>,
    self_node_key: &str,
    base_url: &str,
) -> Option<super::wire::SshPolicy> {
    let nodes = ssh_policy_nodes_from_snapshot(snapshot);
    policy.ssh_policy_for(&nodes, node_id_for_key(snapshot, self_node_key), base_url)
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn plain_map_error(status: StatusCode, message: &str) -> Response {
    (status, format!("{message}\n")).into_response()
}

fn canonical_map_node_key(node_key: &str) -> String {
    if node_key.is_empty() {
        return ZERO_NODE_KEY_HEX.to_string();
    }
    match strip_key_prefix(node_key) {
        Some(h) => h.to_string(),
        None => node_key.to_string(),
    }
}

fn map_request_node_key(req: &MapRequest) -> Option<String> {
    (!req.node_key.is_empty()).then(|| canonical_map_node_key(&req.node_key))
}

pub async fn handle_map(
    State(state): State<WireState>,
    machine_key: Option<Extension<NoisePeerMachineKey>>,
    Path(node_key_path): Path<String>,
    raw: Bytes,
) -> Response {
    let machine_key = match require_noise_machine_key(machine_key) {
        Ok(machine_key) => machine_key,
        Err(resp) => return resp,
    };
    let req = match parse_map_body(&raw) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = reject_unsupported_capability(req.version) {
        return resp;
    }
    let node_key_hex =
        map_request_node_key(&req).unwrap_or_else(|| canonical_map_node_key(&node_key_path));
    map_inner(state, node_key_hex, machine_key, req).await
}

/// `POST /machine/map` (v1.78+ flat path).
///
/// NodeKey lives in the request body (`MapRequest.NodeKey`). The
/// keyed `/machine/{node_key}/map` route is kept for older clients.
pub async fn handle_map_flat(
    State(state): State<WireState>,
    machine_key: Option<Extension<NoisePeerMachineKey>>,
    raw: Bytes,
) -> Response {
    let machine_key = match require_noise_machine_key(machine_key) {
        Ok(machine_key) => machine_key,
        Err(resp) => return resp,
    };
    let req = match parse_map_body(&raw) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    if let Err(resp) = reject_unsupported_capability(req.version) {
        return resp;
    }
    let node_key_hex = canonical_map_node_key(&req.node_key);
    map_inner(state, node_key_hex, machine_key, req).await
}

async fn map_inner(
    state: WireState,
    node_key_hex: String,
    machine_key_hex: String,
    req: MapRequest,
) -> Response {
    // The caller must already have registered. If not, 404 — they need
    // to go through `/machine/{node_key}/register` first.
    let Some(mut own) = state.machines.get(&node_key_hex) else {
        return plain_map_error(StatusCode::NOT_FOUND, MAP_NODE_NOT_FOUND_ERROR);
    };
    if let Err(resp) = validate_map_machine_key(&machine_key_hex, &own) {
        return resp;
    }

    // P1 lifecycle: stamp `last_seen` on every /map arrival.
    // (Mirrors upstream's `db.UpdateNodeFromMapRequest`.) The COW
    // update is O(n) in registry size; the perf concern is documented
    // on `MachineRegistry::touch_last_seen` itself.
    state.machines.touch_last_seen(&node_key_hex);
    if let Some(touched) = state.machines.get(&node_key_hex) {
        own.last_seen = touched.last_seen;
    }

    // Wall 7/P1: persist client-provided DiscoKey, Endpoints, and
    // the full Hostinfo snapshot from `MapRequest` into the
    // `MachineRecord` so subsequent map calls for OTHER peers see them
    // on this peer's `MapNode`. Stock `tailscale` v1.78+ sends the
    // disco/endpoint values on every map call (initial + refresh); we
    // treat any non-empty value as a fresh overwrite, and `None` /
    // empty as "keep what was there." This means a client that omits
    // the fields on one call doesn't accidentally clear what previous
    // calls established. If Hostinfo is present but omits NetInfo,
    // preserve the prior NetInfo like headscale-go's
    // `netInfoFromMapRequest`.
    //
    // `upsert` on the registry notifies waiters, which wakes any
    // peer's streaming `/map` so they pick up the new disco/endpoint
    // values on the next chunk.
    let mut record_changed = false;
    if let Some(dk) = req.disco_key.as_ref().filter(|s| !s.is_empty())
        && own.disco_key.as_deref() != Some(dk.as_str())
    {
        own.disco_key = Some(dk.clone());
        record_changed = true;
    }
    if let Some(eps) = req.endpoints.as_ref().filter(|v| !v.is_empty())
        && &own.endpoints != eps
    {
        own.endpoints = eps.clone();
        record_changed = true;
    }
    if let Some(hostinfo) = req.hostinfo.as_ref() {
        let announced_routes = match normalize_routes(&hostinfo.routable_ips) {
            Ok(routes) => routes,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: format!("invalid Hostinfo.RoutableIPs: {e}"),
                    }),
                )
                    .into_response();
            }
        };
        let mut hostinfo = host_info_for_map_update(&own.host_info_for_node(), hostinfo);
        hostinfo.routable_ips.clone_from(&announced_routes);
        let addr = own.primary_addr_string().unwrap_or_default();
        let user = (!own.user.is_empty()).then_some(own.user.as_str());
        let approved_routes = match auto_approved_routes_for_node(
            &state.policy,
            &addr,
            user,
            &own.forced_tags,
            &own.approved_routes,
            &announced_routes,
        ) {
            Ok(routes) => routes,
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: format!("invalid approved routes: {e}"),
                    }),
                )
                    .into_response();
            }
        };
        if own.host_info_for_node() != hostinfo {
            own.replace_host_info(hostinfo);
            record_changed = true;
        }
        if own.approved_routes != approved_routes {
            own.approved_routes = approved_routes;
            record_changed = true;
        }
    }
    if record_changed {
        state.machines.upsert(node_key_hex.clone(), own.clone());
    }
    if let Some(store) = &state.registration_store {
        let current = if record_changed {
            own.clone()
        } else {
            state
                .machines
                .get(&node_key_hex)
                .unwrap_or_else(|| own.clone())
        };
        let saved = match store
            .sync_runtime_machine_state(current, state.policy.as_ref())
            .await
        {
            Ok(saved) => saved,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorBody {
                        error: format!("persisting map node update failed: {error}"),
                    }),
                )
                    .into_response();
            }
        };
        if record_changed {
            if let Some(old_node_key_hex) = saved.replaced_node_key_hex.as_deref() {
                state.machines.replace_node_key(
                    old_node_key_hex,
                    saved.record.node_key_hex.clone(),
                    saved.record,
                );
            } else {
                state
                    .machines
                    .upsert(saved.record.node_key_hex.clone(), saved.record);
            }
        }
    }

    if req.omit_peers && !req.stream {
        state.machines.record_mapresponse_endpoint_update("ok");
        return StatusCode::OK.into_response();
    }

    // Long-poll for a second peer ONLY when this is a non-streaming,
    // non-OmitPeers map call AND we're alone in the tailnet. In every
    // other case the client expects a response IMMEDIATELY — stock
    // `tailscale up` v1.78+ sends Stream=true + OmitPeers=true on
    // its initial noise-channel pre-pump, and waits for both to land
    // before transitioning state.
    //
    // Wall 5 regression cause: the previous code long-polled in
    // every code path, including the streaming + OmitPeers cases.
    // That stalled the first MapResponse by 30 s and timed out
    // the test's 25 s `tailscale up` wrapper.
    if !req.stream && !req.omit_peers {
        let notify = state.machines.notify.clone();
        let deadline = tokio::time::Instant::now() + MAP_LONGPOLL_TIMEOUT;
        while state.machines.len() < 2 {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline - now;
            if tokio::time::timeout(remaining, wait_for_change(notify.clone()))
                .await
                .is_err()
            {
                break;
            }
        }
    }

    let self_node_id = state.machines.stable_node_id_for_key(&node_key_hex);
    let stream_connection_guard = req.stream.then(|| {
        super::MachineRegistry::track_stream_connection(state.machines.clone(), self_node_id)
    });

    // Build the response.
    let snapshot = state.machines.snapshot();
    let tailnet_domain = tailnet_domain(&state.dns);
    let primary_routes = state.machines.primary_routes_for_snapshot(&snapshot);
    let exit_routes = exit_routes_for_snapshot(&snapshot);
    let online_states = state.machines.online_states();
    let taildrop_enabled = state.runtime_config.taildrop.enabled;
    let served_routes = served_routes_for_snapshot(&snapshot);
    let mut allowed_peer_ids =
        allowed_peer_ids_for_snapshot(&state.policy, &snapshot, &node_key_hex, &served_routes);
    add_co_router_primary_peer_ids(
        &mut allowed_peer_ids,
        &snapshot,
        &node_key_hex,
        &primary_routes,
        &served_routes,
    );
    let packet_filter_nodes = packet_filter_nodes_from_snapshot(&snapshot, &served_routes);
    let Some(own_node) = self_map_node_from_snapshot(
        &snapshot,
        &node_key_hex,
        &tailnet_domain,
        &primary_routes,
        &exit_routes,
        &online_states,
        &state.policy,
        req.version,
        taildrop_enabled,
    ) else {
        return plain_map_error(StatusCode::NOT_FOUND, MAP_NODE_NOT_FOUND_ERROR);
    };
    // #238: `snapshot()` returns `Arc<HashMap<…>>` — one Arc clone
    // total. Iterating borrows the map; we never clone individual
    // records. `record_to_map_node` takes `&MachineRecord` so the
    // borrowed iter feeds it directly.
    let peers = visible_peer_map_nodes(
        &snapshot,
        &node_key_hex,
        allowed_peer_ids.as_ref(),
        &tailnet_domain,
        &primary_routes,
        &exit_routes,
        &served_routes,
        &online_states,
        &state.policy,
        req.version,
        taildrop_enabled,
    );

    let dns_config = build_dns_for_snapshot(&state.dns, &state.policy, &snapshot, &node_key_hex);
    let user_profiles =
        user_profiles_for_snapshot(&snapshot, &node_key_hex, allowed_peer_ids.as_ref());
    let resp = MapResponse {
        ping_request: state.pings.pop_next_for_node(self_node_id),
        node: Some(own_node),
        peers,
        user_profiles,
        dns_config: Some(dns_config),
        // Wall 6: serve whatever DERP map the embedder loaded at
        // startup. Empty for non-interop deployments; the interop test
        // populates a one-region fixture pointing at the `derp-1`
        // sidecar (see `derp_config::load_derp_map`).
        derp_map: Some(state.derp_map.snapshot()),
        domain: tailnet_domain,
        collect_services: Some(false),
        // Headscale-go v0.28 sends the full per-node filter through
        // PacketFilters["base"], already reduced for this map
        // recipient.
        packet_filters: packet_filters_for_node(&state.policy, &packet_filter_nodes, self_node_id),
        ssh_policy: ssh_policy_for_snapshot(
            &state.policy,
            &snapshot,
            &node_key_hex,
            state.public_control_url.as_deref().unwrap_or(""),
        ),
        control_time: Some(chrono::Utc::now()),
        debug: Some(DebugConfig {
            disable_log_tail: true,
            ..DebugConfig::default()
        }),
        // FULL MapResponse — NOT a keepalive. Upstream
        // `controlclient/direct.go::sendMapRequest` `continue`s past
        // the netmap-update handler when `KeepAlive=true`, which
        // means our full payload would be silently dropped. The bit
        // that prevented `BackendState` from advancing past
        // `NeedsLogin`. Dedicated keepalive frames go out via
        // [`build_keepalive_chunk`]'s separate `{"KeepAlive":true}`
        // payload — never inlined here.
        keep_alive: false,
        ..MapResponse::default()
    };
    record_mapresponse_debug(
        &state.mapresponse_debug,
        self_node_id,
        MapResponseDebugType::Full,
        &resp,
    );
    if req.stream {
        // Stream:true — emit length-prefixed MapResponse JSON chunks,
        // zstd-compressed only when the request negotiated it. See
        // module decision log for the wire-format details. The first
        // chunk goes out immediately; registry wakes use incremental
        // peer deltas, configuration wakes rebuild the broader
        // snapshot, and keepalive ticks emit a compact
        // `{"KeepAlive":true}` frame in the same compression mode.
        //
        // Per `docs/tailscale-interop-blocker.md` "Wall 5":
        // the body must NOT terminate naturally — the client expects
        // to long-poll until it closes the connection itself.
        let initial_self_node = resp.node.clone();
        let initial_peer_state = peer_state_from_nodes(&resp.peers);
        let initial_peer_ids = peer_ids_from_snapshot(&snapshot, &node_key_hex);
        let compression = MapFrameCompression::from_request(&req.compress);
        let first = match build_framed_chunk(&resp, compression) {
            Ok(v) => v,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorBody {
                        error: format!("encode map response: {e}"),
                    }),
                )
                    .into_response();
            }
        };

        // The stream's carried state is enough to re-build MapResponse
        // on each registry / policy / DNS wake.
        //
        // # audit-2 C-1: lost-wake fix (commit follow-up)
        //
        // We subscribe to the registry's generation-counter watch
        // channel **before** taking the first chunk. The receiver
        // remembers its last-seen generation across `.await` boundaries
        // — any `upsert` / `update_with` that fires while this unfold
        // is *between* iterations bumps the sender, and the next
        // `changed().await` on the receiver returns immediately. This
        // closes the `notify_waiters` lost-wake gap the prior
        // implementation had (the `Notified` was re-registered AFTER
        // the chunk was returned, so wakes fired in the gap were
        // dropped). The companion `tokio::sync::Notify` stays on the
        // registry for any caller that wants raw fan-out wake, but the
        // long-poll path now consumes the watch channel exclusively.
        let machines = state.machines.clone();
        let gen_rx = state.machines.subscribe_gen();
        let policy = state.policy.clone();
        let self_node_key = node_key_hex.clone();
        let cap_version = req.version;
        let taildrop_enabled = state.runtime_config.taildrop.enabled;
        let derp_map_for_stream = state.derp_map.clone();
        let derp_rx = state.derp_map.subscribe();
        let dns_for_stream = state.dns.clone();
        let pings = state.pings.clone();
        let ping_rx = state.pings.subscribe();
        let mapresponse_debug = state.mapresponse_debug.clone();
        let public_control_url = state.public_control_url.clone();
        let connection_guard = stream_connection_guard.expect("stream guard created above");
        let stream = futures_util::stream::unfold(
            (
                Some(first),
                machines,
                gen_rx,
                policy,
                self_node_key,
                derp_map_for_stream,
                derp_rx,
                dns_for_stream,
                pings,
                ping_rx,
                mapresponse_debug,
                initial_self_node,
                initial_peer_state,
                initial_peer_ids,
                connection_guard,
                cap_version,
                taildrop_enabled,
                compression,
                public_control_url,
            ),
            move |(
                first_opt,
                machines,
                mut gen_rx,
                policy,
                self_node_key,
                machines_derp_map,
                mut derp_rx,
                dns,
                pings,
                mut ping_rx,
                mapresponse_debug,
                last_self_node,
                last_peer_state,
                initial_peer_ids,
                connection_guard,
                cap_version,
                taildrop_enabled,
                compression,
                public_control_url,
            )| async move {
                if let Some(initial) = first_opt {
                    return Some((
                        Ok::<_, std::io::Error>(initial),
                        (
                            None,
                            machines,
                            gen_rx,
                            policy,
                            self_node_key,
                            machines_derp_map,
                            derp_rx,
                            dns,
                            pings,
                            ping_rx,
                            mapresponse_debug,
                            last_self_node,
                            last_peer_state,
                            initial_peer_ids,
                            connection_guard,
                            cap_version,
                            taildrop_enabled,
                            compression,
                            public_control_url,
                        ),
                    ));
                }
                let self_node_id = machines.stable_node_id_for_key(&self_node_key);
                if let Some(request) = pings.pop_next_for_node(self_node_id) {
                    return Some((
                        Ok::<_, std::io::Error>(build_ping_request_chunk(
                            request,
                            compression,
                            &mapresponse_debug,
                            self_node_id,
                        )),
                        (
                            None,
                            machines,
                            gen_rx,
                            policy,
                            self_node_key,
                            machines_derp_map,
                            derp_rx,
                            dns,
                            pings,
                            ping_rx,
                            mapresponse_debug,
                            last_self_node,
                            last_peer_state,
                            initial_peer_ids,
                            connection_guard,
                            cap_version,
                            taildrop_enabled,
                            compression,
                            public_control_url,
                        ),
                    ));
                }
                // Wait for either a registry change, a policy change,
                // a DERP map refresh, a DNS extra-records edit, or a keepalive tick,
                // whichever fires first.
                //
                // `gen_rx.changed()` is missed-update tolerant: if the
                // sender bumped the value between the previous chunk
                // emission and this select, the `changed()` future
                // returns immediately rather than parking. That's the
                // load-bearing property that closes the audit-2 C-1
                // race — see the registry's `wake_waiters` doc.
                let (chunk, next_peer_state, next_self_node) = loop {
                    let policy_for_wait = policy.clone();
                    let policy_changed = policy_for_wait.wait_for_change();
                    let dns_for_wait = dns.clone();
                    let dns_changed = dns_for_wait.wait_for_change();
                    tokio::pin!(policy_changed);
                    tokio::pin!(dns_changed);
                    let maybe_chunk = tokio::select! {
                    biased;
                    res = gen_rx.changed() => {
                        // `Err` only happens if every sender has been
                        // dropped — would mean the entire registry's
                        // gone, in which case we degrade to a
                        // keepalive frame and let the next iteration
                        // (or stream end) handle teardown.
                        if res.is_err() {
                            Some((build_keepalive_chunk(compression), last_peer_state.clone(), last_self_node.clone()))
                        } else {
                            rebuild_peer_delta_chunk(
                                &machines,
                                &policy,
                                &self_node_key,
                                &dns,
                                cap_version,
                                taildrop_enabled,
                                compression,
                                last_self_node.as_ref(),
                                &last_peer_state,
                                &initial_peer_ids,
                                &mapresponse_debug,
                                public_control_url.as_deref().unwrap_or(""),
                                PeerDeltaOptions::registry_change(),
                            )
                        }
                    }
                    () = &mut policy_changed => {
                        // Policy edits can remove every visible peer.
                        // Emit an incremental delta with PeersRemoved
                        // rather than a full map whose empty Peers list
                        // would serialize away and leave clients with
                        // stale peers/routes.
                        rebuild_peer_delta_chunk(
                            &machines,
                            &policy,
                            &self_node_key,
                            &dns,
                            cap_version,
                            taildrop_enabled,
                            compression,
                            last_self_node.as_ref(),
                            &last_peer_state,
                            &initial_peer_ids,
                            &mapresponse_debug,
                            public_control_url.as_deref().unwrap_or(""),
                            PeerDeltaOptions::policy_change(),
                        )
                    }
                    () = &mut dns_changed => {
                        // Extra-records file edited (or DnsStore.set_spec
                        // called) — wake every parked poller so the
                        // next chunk carries the refreshed `DNSConfig`.
                        Some((
                            rebuild_map_chunk(
                                &machines,
                                &policy,
                                &self_node_key,
                                &machines_derp_map,
                                &dns,
                                cap_version,
                                taildrop_enabled,
                                compression,
                                "config",
                                &mapresponse_debug,
                                MapResponseDebugType::Change,
                                public_control_url.as_deref().unwrap_or(""),
                            ),
                            visible_peer_state_for_registry(&machines, &policy, &dns, &self_node_key, cap_version, taildrop_enabled),
                            self_map_node_for_registry(&machines, &policy, &dns, &self_node_key, cap_version, taildrop_enabled),
                        ))
                    }
                    res = derp_rx.changed() => {
                        // DERP URL/path refresh — wake every parked
                        // poller so the next chunk carries the new
                        // `DERPMap`.
                        if res.is_err() {
                            Some((build_keepalive_chunk(compression), last_peer_state.clone(), last_self_node.clone()))
                        } else {
                            Some((
                            rebuild_map_chunk(
                                &machines,
                                &policy,
                                &self_node_key,
                                &machines_derp_map,
                                &dns,
                                cap_version,
                                taildrop_enabled,
                                compression,
                                "config",
                                &mapresponse_debug,
                                MapResponseDebugType::Change,
                                public_control_url.as_deref().unwrap_or(""),
                            ),
                            visible_peer_state_for_registry(&machines, &policy, &dns, &self_node_key, cap_version, taildrop_enabled),
                            self_map_node_for_registry(&machines, &policy, &dns, &self_node_key, cap_version, taildrop_enabled),
                        ))
                        }
                    }
                    res = ping_rx.changed() => {
                        if res.is_err() {
                            Some((build_keepalive_chunk(compression), last_peer_state.clone(), last_self_node.clone()))
                        } else if let Some(request) = pings.pop_next_for_node(self_node_id) {
                            Some((
                                build_ping_request_chunk(
                                    request,
                                    compression,
                                    &mapresponse_debug,
                                    self_node_id,
                                ),
                                last_peer_state.clone(),
                                last_self_node.clone(),
                            ))
                        } else {
                            Some((build_keepalive_chunk(compression), last_peer_state.clone(), last_self_node.clone()))
                        }
                    }
                    () = tokio::time::sleep(MAP_KEEPALIVE_INTERVAL) => {
                        machines.record_mapresponse_sent_for_node(
                            "ok",
                            "keepalive",
                            machines.stable_node_id_for_key(&self_node_key),
                        );
                        Some((build_keepalive_chunk(compression), last_peer_state.clone(), last_self_node.clone()))
                    }
                    };
                    if let Some(chunk) = maybe_chunk {
                        break chunk;
                    }
                };
                Some((
                    Ok(chunk),
                    (
                        None,
                        machines,
                        gen_rx,
                        policy,
                        self_node_key,
                        machines_derp_map,
                        derp_rx,
                        dns,
                        pings,
                        ping_rx,
                        mapresponse_debug,
                        next_self_node,
                        next_peer_state,
                        initial_peer_ids,
                        connection_guard,
                        cap_version,
                        taildrop_enabled,
                        compression,
                        public_control_url,
                    ),
                ))
            },
        );

        // Upstream content-type is `application/x-protobuf` historically
        // but newer clients accept any content-type — the framing rules
        // are positional, not header-driven. `application/octet-stream`
        // is the safest neutral choice.
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/octet-stream")
            .body(Body::from_stream(stream))
            .unwrap()
    } else {
        Json(resp).into_response()
    }
}

fn require_noise_machine_key(
    machine_key: Option<Extension<NoisePeerMachineKey>>,
) -> Result<String, Response> {
    let Some(Extension(NoisePeerMachineKey(machine_key))) = machine_key else {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "missing Noise machine key".into(),
            }),
        )
            .into_response());
    };
    if machine_key.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorBody {
                error: "missing Noise machine key".into(),
            }),
        )
            .into_response());
    }
    Ok(machine_key)
}

fn validate_map_machine_key(
    presented_machine_key_hex: &str,
    record: &MachineRecord,
) -> Result<(), Response> {
    if record.machine_key_hex == presented_machine_key_hex {
        return Ok(());
    }

    Err(plain_map_error(
        StatusCode::NOT_FOUND,
        MAP_NODE_KEY_MISMATCH_ERROR,
    ))
}

fn reject_unsupported_capability(version: u32) -> Result<(), Response> {
    if is_supported_capability_version(version) {
        return Ok(());
    }
    Err(plain_map_error(
        StatusCode::BAD_REQUEST,
        &unsupported_client_error(version),
    ))
}

/// Rebuild an incremental peer update for an in-flight `Stream:true`
/// `/machine/map` poller after the registry changes. Upstream
/// headscale sends the initial stream response as a full `Peers`
/// snapshot, then uses `PeersChanged`/`PeersRemoved` for later node
/// add/remove/update events instead of replacing the full peer list on
/// every wake.
type PeerDeltaChunk = (Vec<u8>, BTreeMap<u64, MapNode>, Option<MapNode>);

fn rebuild_peer_delta_chunk(
    machines: &Arc<crate::tailscale_wire::MachineRegistry>,
    policy: &Arc<crate::policy::PolicyStore>,
    self_node_key: &str,
    dns: &Arc<DnsStore>,
    cap_version: u32,
    taildrop_enabled: bool,
    compression: MapFrameCompression,
    last_self_node: Option<&MapNode>,
    last_peer_state: &BTreeMap<u64, MapNode>,
    initial_peer_ids: &BTreeSet<u64>,
    mapresponse_debug: &MapResponseDebugStore,
    public_control_url: &str,
    options: PeerDeltaOptions,
) -> Option<PeerDeltaChunk> {
    if machines.get(self_node_key).is_none() {
        return Some((
            build_keepalive_chunk(compression),
            last_peer_state.clone(),
            last_self_node.cloned(),
        ));
    }
    let snapshot = machines.snapshot();
    let tailnet_domain = tailnet_domain(dns);
    let primary_routes = machines.primary_routes_for_snapshot(&snapshot);
    let exit_routes = exit_routes_for_snapshot(&snapshot);
    let online_states = machines.online_states();
    let served_routes = served_routes_for_snapshot(&snapshot);
    let mut allowed_peer_ids = if options.use_incremental_empty_acl_semantics {
        incremental_allowed_peer_ids_for_snapshot(
            policy,
            &snapshot,
            self_node_key,
            &served_routes,
            initial_peer_ids,
            last_peer_state,
        )
    } else {
        allowed_peer_ids_for_snapshot(policy, &snapshot, self_node_key, &served_routes)
    };
    add_co_router_primary_peer_ids(
        &mut allowed_peer_ids,
        &snapshot,
        self_node_key,
        &primary_routes,
        &served_routes,
    );
    let self_node_id = node_id_for_key(&snapshot, self_node_key);
    let packet_filter_nodes = packet_filter_nodes_from_snapshot(&snapshot, &served_routes);
    let current_self_node = self_map_node_from_snapshot(
        &snapshot,
        self_node_key,
        &tailnet_domain,
        &primary_routes,
        &exit_routes,
        &online_states,
        policy,
        cap_version,
        taildrop_enabled,
    );
    let self_node_changed = match (&current_self_node, last_self_node) {
        (Some(current), Some(previous)) => {
            map_node_json_value(current) != map_node_json_value(previous)
        }
        (Some(_), None) | (None, Some(_)) => true,
        (None, None) => false,
    };
    let peers_changed = visible_peer_map_nodes(
        &snapshot,
        self_node_key,
        allowed_peer_ids.as_ref(),
        &tailnet_domain,
        &primary_routes,
        &exit_routes,
        &served_routes,
        &online_states,
        policy,
        cap_version,
        taildrop_enabled,
    );
    let current_peer_state = peer_state_from_nodes(&peers_changed);
    let current_peer_ids = current_peer_state.keys().copied().collect::<BTreeSet<_>>();
    let previous_peer_ids = last_peer_state.keys().copied().collect::<BTreeSet<_>>();
    let peers_removed = previous_peer_ids
        .difference(&current_peer_ids)
        .copied()
        .collect::<Vec<_>>();
    let mut peer_patches = Vec::new();
    let mut full_peers_changed = Vec::new();
    for peer in peers_changed {
        match last_peer_state.get(&peer.id) {
            None => full_peers_changed.push(peer),
            Some(previous) if map_node_json_value(previous) == map_node_json_value(&peer) => {}
            Some(previous) => match peer_patch_if_only_patchable_fields_changed(previous, &peer) {
                Some(patch) => peer_patches.push(patch),
                None => full_peers_changed.push(peer),
            },
        }
    }

    if !options.include_dns_config
        && !self_node_changed
        && full_peers_changed.is_empty()
        && peers_removed.is_empty()
        && peer_patches.is_empty()
    {
        return None;
    }

    machines.record_mapresponse_generated(options.response_type);
    let mr = MapResponse {
        node: if self_node_changed {
            current_self_node.clone()
        } else {
            None
        },
        peers_changed: full_peers_changed,
        peers_removed,
        peers_changed_patch: peer_patches,
        dns_config: options
            .include_dns_config
            .then(|| build_dns_for_snapshot(dns, policy, &snapshot, self_node_key)),
        user_profiles: user_profiles_for_snapshot(
            &snapshot,
            self_node_key,
            allowed_peer_ids.as_ref(),
        ),
        packet_filters: packet_filters_for_node(policy, &packet_filter_nodes, self_node_id),
        ssh_policy: ssh_policy_for_snapshot(policy, &snapshot, self_node_key, public_control_url),
        control_time: Some(chrono::Utc::now()),
        keep_alive: false,
        ..MapResponse::default()
    };
    record_mapresponse_debug(mapresponse_debug, self_node_id, options.debug_type, &mr);
    Some((
        build_framed_chunk(&mr, compression).unwrap_or_else(|_| build_keepalive_chunk(compression)),
        current_peer_state,
        current_self_node,
    ))
}

#[derive(Clone, Copy)]
struct PeerDeltaOptions {
    response_type: &'static str,
    debug_type: MapResponseDebugType,
    include_dns_config: bool,
    use_incremental_empty_acl_semantics: bool,
}

impl PeerDeltaOptions {
    const fn registry_change() -> Self {
        Self {
            response_type: "peers",
            debug_type: MapResponseDebugType::Change,
            include_dns_config: false,
            use_incremental_empty_acl_semantics: true,
        }
    }

    const fn policy_change() -> Self {
        Self {
            response_type: "policy",
            debug_type: MapResponseDebugType::Policy,
            include_dns_config: true,
            use_incremental_empty_acl_semantics: false,
        }
    }
}

fn build_ping_request_chunk(
    request: PingRequest,
    compression: MapFrameCompression,
    mapresponse_debug: &MapResponseDebugStore,
    node_id: u64,
) -> Vec<u8> {
    let mr = MapResponse {
        ping_request: Some(request),
        keep_alive: false,
        ..MapResponse::default()
    };
    record_mapresponse_debug(
        mapresponse_debug,
        node_id,
        MapResponseDebugType::Change,
        &mr,
    );
    build_framed_chunk(&mr, compression).unwrap_or_else(|_| build_keepalive_chunk(compression))
}

/// Rebuild a full `MapResponse` chunk for an in-flight `Stream:true`
/// `/machine/map` poller. Used for configuration-style wakes that
/// still need the broader snapshot path. If the requesting node has
/// been deleted from the registry between the wake and the rebuild,
/// we emit a keepalive instead of a stale MapResponse — the next
/// iteration handles teardown.
fn rebuild_map_chunk(
    machines: &Arc<crate::tailscale_wire::MachineRegistry>,
    policy: &Arc<crate::policy::PolicyStore>,
    self_node_key: &str,
    derp_map: &Arc<crate::tailscale_wire::DerpMapStore>,
    dns: &Arc<DnsStore>,
    cap_version: u32,
    taildrop_enabled: bool,
    compression: MapFrameCompression,
    response_type: &str,
    mapresponse_debug: &MapResponseDebugStore,
    debug_type: MapResponseDebugType,
    public_control_url: &str,
) -> Vec<u8> {
    if machines.get(self_node_key).is_none() {
        return build_keepalive_chunk(compression);
    }
    machines.record_mapresponse_generated(response_type);
    let snapshot = machines.snapshot();
    let tailnet_domain = tailnet_domain(dns);
    let primary_routes = machines.primary_routes_for_snapshot(&snapshot);
    let exit_routes = exit_routes_for_snapshot(&snapshot);
    let online_states = machines.online_states();
    let served_routes = served_routes_for_snapshot(&snapshot);
    let mut allowed_peer_ids =
        allowed_peer_ids_for_snapshot(policy, &snapshot, self_node_key, &served_routes);
    add_co_router_primary_peer_ids(
        &mut allowed_peer_ids,
        &snapshot,
        self_node_key,
        &primary_routes,
        &served_routes,
    );
    let self_node_id = node_id_for_key(&snapshot, self_node_key);
    let packet_filter_nodes = packet_filter_nodes_from_snapshot(&snapshot, &served_routes);
    let Some(own_node) = self_map_node_from_snapshot(
        &snapshot,
        self_node_key,
        &tailnet_domain,
        &primary_routes,
        &exit_routes,
        &online_states,
        policy,
        cap_version,
        taildrop_enabled,
    ) else {
        return build_keepalive_chunk(compression);
    };
    let peers = visible_peer_map_nodes(
        &snapshot,
        self_node_key,
        allowed_peer_ids.as_ref(),
        &tailnet_domain,
        &primary_routes,
        &exit_routes,
        &served_routes,
        &online_states,
        policy,
        cap_version,
        taildrop_enabled,
    );
    let dns_config = build_dns_for_snapshot(dns, policy, &snapshot, self_node_key);
    let user_profiles =
        user_profiles_for_snapshot(&snapshot, self_node_key, allowed_peer_ids.as_ref());
    let mr = MapResponse {
        node: Some(own_node),
        peers,
        user_profiles,
        dns_config: Some(dns_config),
        derp_map: Some(derp_map.snapshot()),
        domain: tailnet_domain,
        collect_services: Some(false),
        packet_filters: packet_filters_for_node(policy, &packet_filter_nodes, self_node_id),
        ssh_policy: ssh_policy_for_snapshot(policy, &snapshot, self_node_key, public_control_url),
        control_time: Some(chrono::Utc::now()),
        debug: Some(DebugConfig {
            disable_log_tail: true,
            ..DebugConfig::default()
        }),
        keep_alive: false,
        ..MapResponse::default()
    };
    record_mapresponse_debug(mapresponse_debug, self_node_id, debug_type, &mr);
    build_framed_chunk(&mr, compression).unwrap_or_else(|_| build_keepalive_chunk(compression))
}

/// Encode a MapResponse into the wire framing the streaming
/// `/machine/map` endpoint uses: `[u32 LE total size][body]`. The body
/// is plaintext JSON unless `MapRequest.Compress == "zstd"`, matching
/// headscale-go's `poll.go::writeMap`.
pub(crate) fn build_framed_chunk(
    mr: &MapResponse,
    compression: MapFrameCompression,
) -> Result<Vec<u8>, std::io::Error> {
    let json_bytes =
        serde_json::to_vec(mr).map_err(|e| std::io::Error::other(format!("json encode: {e}")))?;
    let body = compression.encode(&json_bytes)?;
    let mut out = Vec::with_capacity(4 + body.len());
    let len = body.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Build the keepalive frame in the negotiated map compression mode.
pub(crate) fn build_keepalive_chunk(compression: MapFrameCompression) -> Vec<u8> {
    // `tailscale/control/controlclient/direct.go::justKeepAliveStr`
    // = `{"KeepAlive":true}` — matched byte-for-byte before optional
    // compression so the upstream fast-path sees the expected body.
    const KEEPALIVE_JSON: &[u8] = b"{\"KeepAlive\":true}";
    let body = compression
        .encode(KEEPALIVE_JSON)
        .expect("encoding static keepalive bytes never fails");
    let mut out = Vec::with_capacity(4 + body.len());
    let len = body.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    out
}

async fn wait_for_change(notify: Arc<tokio::sync::Notify>) {
    notify.notified().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{
        DerpMapStore, MachineRecord, MachineRegistry, MapResponseDebugStore, WireState,
        noise::{NoisePeerMachineKey, ServerNoiseKey, inner_router as machine_router},
        register::{CAPABILITY_ADMIN, CAPABILITY_FILE_SHARING, CAPABILITY_SSH},
        router as public_router,
        test_support::{MockIpAllocator, MockRedeemer},
        wire::{DerpMap, DerpRegion, DerpRegionNode, DnsRecord},
    };
    use axum::body::to_bytes;
    use futures_util::FutureExt;
    use std::fs;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tower::ServiceExt;

    const TEST_MACHINE_KEY_HEX: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    fn router(state: WireState) -> axum::Router {
        machine_router(state).layer(axum::middleware::from_fn(
            |mut req: axum::extract::Request, next: axum::middleware::Next| async move {
                if req.extensions().get::<NoisePeerMachineKey>().is_none() {
                    req.extensions_mut()
                        .insert(NoisePeerMachineKey(TEST_MACHINE_KEY_HEX.to_string()));
                }
                next.run(req).await
            },
        ))
    }

    fn fixture() -> (WireState, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let state = WireState {
            server_noise_key: server,
            preauth: Arc::new(MockRedeemer::new()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
            registration_store: None,
            derp_map: DerpMapStore::shared(DerpMap::default()),
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: None,
            runtime_config: Arc::new(crate::tailscale_wire::RuntimeConfigSnapshot::default()),
            registration_cache: Arc::new(crate::tailscale_wire::RegistrationCache::new()),
            pings: Arc::new(crate::tailscale_wire::PingTracker::new()),
            mapresponse_debug: Arc::new(crate::tailscale_wire::MapResponseDebugStore::disabled()),
        };
        (state, dir)
    }

    fn insert_peer(state: &WireState, node_hex: &str, host: &str, last_octet: u8) {
        state.machines.upsert(
            node_hex.to_string(),
            MachineRecord::new_at(
                chrono::Utc::now(),
                node_hex.to_string(),
                TEST_MACHINE_KEY_HEX.to_string(),
                "u".into(),
                host.into(),
                Ipv4Addr::new(100, 64, 0, last_octet),
                false,
            ),
        );
    }

    fn routed_record(
        node_hex: &str,
        host: &str,
        last_octet: u8,
        routes: Vec<String>,
    ) -> MachineRecord {
        let mut rec = MachineRecord::new_at(
            chrono::Utc::now(),
            node_hex.to_string(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "u".into(),
            host.into(),
            Ipv4Addr::new(100, 64, 0, last_octet),
            false,
        );
        rec.available_routes = routes.clone();
        rec.approved_routes = routes;
        rec
    }

    fn assert_default_cap_map(node: &MapNode) {
        assert!(node.cap_map.contains_key(CAPABILITY_ADMIN));
        assert!(node.cap_map.contains_key(CAPABILITY_FILE_SHARING));
        assert!(node.cap_map.contains_key(CAPABILITY_SSH));
    }

    fn policy_record(
        node_hex: &str,
        host: &str,
        last_octet: u8,
        user: &str,
        tags: Vec<String>,
    ) -> MachineRecord {
        let mut rec = MachineRecord::new_at(
            chrono::Utc::now(),
            node_hex.to_string(),
            TEST_MACHINE_KEY_HEX.to_string(),
            user.into(),
            host.into(),
            Ipv4Addr::new(100, 64, 0, last_octet),
            false,
        );
        rec.forced_tags = tags;
        rec
    }

    fn owner_for_route(
        routes_by_node: &HashMap<String, Vec<String>>,
        route: &str,
    ) -> Option<String> {
        routes_by_node.iter().find_map(|(node_key, routes)| {
            if routes.len() == 1 && routes[0] == route {
                Some(node_key.clone())
            } else {
                None
            }
        })
    }

    #[tokio::test]
    async fn two_peer_map_includes_both() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({ "Version": 113 })).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        // Pin a few load-bearing upstream JSON tag names that would
        // otherwise silently regress past `rename_all = "PascalCase"`'s
        // handling of Go's all-caps acronyms (DNS, DERP, IP, OS).
        let raw_str = String::from_utf8_lossy(&raw);
        assert!(raw_str.contains("\"DNSConfig\""), "DNSConfig field name");
        assert!(raw_str.contains("\"DERPMap\""), "DERPMap field name");
        assert!(raw_str.contains("\"AllowedIPs\""), "AllowedIPs field name");
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        // own node has the requester's IP
        let node = mr.node.as_ref().expect("own node present");
        assert_eq!(node.addresses[0], "100.64.0.10/32");
        assert_eq!(node.cap, 113);
        assert_eq!(mr.peers.len(), 1);
        assert_eq!(mr.peers[0].addresses[0], "100.64.0.11/32");
        assert_eq!(mr.peers[0].name, "peer-b");
        assert_eq!(mr.peers[0].cap, 113);
        assert_eq!(mr.domain, "");
        assert_eq!(mr.collect_services, Some(false));
        assert!(mr.control_time.is_some());
        assert_eq!(
            mr.debug.as_ref().map(|debug| debug.disable_log_tail),
            Some(true)
        );
        assert_eq!(mr.user_profiles.len(), 1);
        assert_eq!(mr.user_profiles[0].id, stable_id_from_key("u"));
        assert_eq!(mr.user_profiles[0].login_name, "u");
        assert_eq!(mr.user_profiles[0].display_name, "u");
        // Full MapResponse — must NOT be flagged as a keepalive.
        // Wall 5 regression: when `KeepAlive=true` the upstream client
        // skips the netmap-update handler and the daemon stays in
        // `NeedsLogin` forever.
        assert!(!mr.keep_alive);
    }

    #[tokio::test]
    async fn map_response_writes_headscale_go_debug_dump_when_enabled() {
        let (mut state, _dir) = fixture();
        let dump_dir = tempdir().unwrap();
        let store = Arc::new(MapResponseDebugStore::with_path(dump_dir.path()));
        state.mapresponse_debug = store.clone();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({ "Version": 113 })).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let node_id = stable_id_from_key(&a);
        let files = fs::read_dir(dump_dir.path().join(node_id.to_string()))
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("-full.json"));
        let responses = store.read().unwrap().unwrap();
        assert_eq!(responses[&node_id][0].peers[0].name, "peer-b");
    }

    #[tokio::test]
    async fn map_response_emits_dual_stack_node_addresses() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);
        state.machines.update_with(|records| {
            records.get_mut(&a).unwrap().ipv6 = Some("fd7a:115c:a1e0::10".parse().unwrap());
            records.get_mut(&b).unwrap().ipv6 = Some("fd7a:115c:a1e0::11".parse().unwrap());
        });

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({ "Version": 113 })).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let node = mr.node.as_ref().expect("own node present");
        assert_eq!(
            node.addresses,
            vec!["100.64.0.10/32", "fd7a:115c:a1e0::10/128"]
        );
        assert!(node.allowed_ips.contains(&"fd7a:115c:a1e0::10/128".into()));
        assert_eq!(
            mr.peers[0].addresses,
            vec!["100.64.0.11/32", "fd7a:115c:a1e0::11/128"]
        );
        assert!(
            mr.peers[0]
                .allowed_ips
                .contains(&"fd7a:115c:a1e0::11/128".into())
        );
    }

    #[tokio::test]
    async fn map_rejects_unsupported_capability_version_before_node_lookup() {
        let (state, _dir) = fixture();
        let node_key = "a2".repeat(32);
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({ "Version": 112 })).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(raw.as_ref(), b"unsupported client version:  (112)\n");
    }

    #[tokio::test]
    async fn flat_map_invalid_json_matches_headscale_go_internal_error() {
        let (state, _dir) = fixture();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/machine/map")
                    .body(axum::body::Body::from(b"{".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(raw.as_ref(), b"internal server error\n");
    }

    #[tokio::test]
    async fn flat_map_missing_node_matches_upstream_404_body() {
        let (state, _dir) = fixture();
        let missing_node_key = "a4".repeat(32);
        let app = router(state);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{missing_node_key}"),
        });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/machine/map")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(raw.as_ref(), b"node not found\n");
    }

    #[tokio::test]
    async fn map_requires_noise_machine_key() {
        let (state, _dir) = fixture();
        let node_key = "a0".repeat(32);
        insert_peer(&state, &node_key, "peer-a", 10);

        let app = machine_router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn map_rejects_mismatched_noise_machine_key() {
        let (state, _dir) = fixture();
        let node_key = "a1".repeat(32);
        insert_peer(&state, &node_key, "peer-a", 10);

        let app = router(state);
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key}/map"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "Version": 113,
                    "NodeKey": format!("nodekey:{node_key}"),
                }))
                .unwrap(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey("11".repeat(32)));

        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            raw.as_ref(),
            b"node key in request does not match the one associated with this machine key\n"
        );
    }

    #[tokio::test]
    async fn keyed_map_validates_body_node_key_against_noise_machine_key() {
        let (state, _dir) = fixture();
        let path_node_key = "a5".repeat(32);
        let body_node_key = "b5".repeat(32);
        insert_peer(&state, &path_node_key, "peer-a", 10);
        state.machines.upsert(
            body_node_key.clone(),
            MachineRecord::new_at(
                chrono::Utc::now(),
                body_node_key.clone(),
                "22".repeat(32),
                "u".into(),
                "peer-b".into(),
                Ipv4Addr::new(100, 64, 0, 11),
                false,
            ),
        );

        let app = router(state);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{body_node_key}"),
        });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{path_node_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            raw.as_ref(),
            b"node key in request does not match the one associated with this machine key\n"
        );
    }

    #[tokio::test]
    async fn keyed_map_prefers_body_node_key_like_upstream_noise_map() {
        let (state, _dir) = fixture();
        let path_node_key = "a6".repeat(32);
        let body_node_key = "b6".repeat(32);
        insert_peer(&state, &path_node_key, "peer-a", 10);
        state.machines.upsert(
            body_node_key.clone(),
            MachineRecord::new_at(
                chrono::Utc::now(),
                body_node_key.clone(),
                "22".repeat(32),
                "u".into(),
                "peer-b".into(),
                Ipv4Addr::new(100, 64, 0, 11),
                false,
            ),
        );

        let app = router(state);
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{body_node_key}"),
        });
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{path_node_key}/map"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        req.extensions_mut()
            .insert(NoisePeerMachineKey("22".repeat(32)));

        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let node = mr.node.as_ref().expect("own node present");
        assert_eq!(node.name, "peer-b");
        assert_eq!(node.addresses[0], "100.64.0.11/32");
    }

    #[tokio::test]
    async fn map_response_reduces_peers_when_policy_is_loaded() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "tagOwners": {"tag:server": ["alice@"]},
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["tag:server:*"]}
            ]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let alice = "aa".repeat(32);
        let server = "bb".repeat(32);
        let bob = "cc".repeat(32);
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            server.clone(),
            policy_record(
                &server,
                "server",
                11,
                "server-owner",
                vec!["tag:server".into()],
            ),
        );
        state.machines.upsert(
            bob.clone(),
            policy_record(&bob, "bob", 12, "bob", Vec::new()),
        );

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{server}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({ "Version": 113 })).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let peer_names: Vec<_> = mr.peers.iter().map(|peer| peer.name.as_str()).collect();
        assert_eq!(peer_names, vec!["alice"]);
    }

    #[tokio::test]
    async fn map_response_user_profiles_include_tagged_devices_identity() {
        let (state, _dir) = fixture();
        let alice = "aa".repeat(32);
        let server = "bb".repeat(32);
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            server.clone(),
            policy_record(
                &server,
                "server",
                11,
                "server-owner",
                vec!["tag:server".into()],
            ),
        );

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{server}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let node = mr.node.as_ref().expect("own node present");
        assert_eq!(
            node.user,
            crate::tailscale_wire::wire::TAGGED_DEVICES_USER_ID
        );

        let profiles = mr
            .user_profiles
            .iter()
            .map(|profile| (profile.id, profile))
            .collect::<std::collections::BTreeMap<_, _>>();
        let tagged = profiles
            .get(&crate::tailscale_wire::wire::TAGGED_DEVICES_USER_ID)
            .expect("tagged devices profile present");
        assert_eq!(tagged.login_name, "tagged-devices");
        assert_eq!(tagged.display_name, "Tagged Devices");
        let alice_profile = profiles
            .get(&stable_id_from_key("alice"))
            .expect("alice profile present");
        assert_eq!(alice_profile.login_name, "alice");
        assert_eq!(alice_profile.display_name, "alice");
    }

    #[tokio::test]
    async fn map_response_user_profiles_prefer_owner_user_metadata() {
        let (state, _dir) = fixture();
        let alice = "aa".repeat(32);
        let mut record = policy_record(&alice, "alice-node", 10, "alice@example.com", Vec::new());
        record.set_user_identity(
            Some(42),
            "alice@example.com".into(),
            "Alice Example".into(),
            "https://example.com/alice.png".into(),
        );
        state.machines.upsert(alice.clone(), record);

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{alice}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();

        assert_eq!(mr.node.as_ref().expect("own node present").user, 42);
        let profile = mr
            .user_profiles
            .iter()
            .find(|profile| profile.id == 42)
            .expect("owner profile present");
        assert_eq!(profile.login_name, "alice@example.com");
        assert_eq!(profile.display_name, "Alice Example");
        assert_eq!(profile.profile_pic_url, "https://example.com/alice.png");
    }

    #[tokio::test]
    async fn map_response_emits_reduced_base_packet_filter_for_target_node() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "tagOwners": {"tag:server": ["alice@"]},
            "acls": [
                {"action":"accept","proto":"tcp","src":["alice@"],"dst":["tag:server:22"]}
            ]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let alice = "aa".repeat(32);
        let server = "bb".repeat(32);
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            server.clone(),
            policy_record(
                &server,
                "server",
                11,
                "server-owner",
                vec!["tag:server".into()],
            ),
        );

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{server}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        assert!(mr.packet_filter.is_empty(), "upstream uses PacketFilters");
        let base = mr
            .packet_filters
            .get("base")
            .and_then(|rules| rules.as_ref())
            .expect("PacketFilters.base present");
        assert_eq!(base.len(), 1);
        assert_eq!(base[0].src_ips, vec!["100.64.0.10"]);
        assert_eq!(base[0].ip_proto, vec![6]);
        assert_eq!(base[0].dst_ports.len(), 1);
        assert_eq!(base[0].dst_ports[0].ip, "100.64.0.11");
        assert_eq!(base[0].dst_ports[0].ports.first, 22);
        assert_eq!(base[0].dst_ports[0].ports.last, 22);
    }

    #[tokio::test]
    async fn map_response_base_packet_filter_keeps_served_routes() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["10.10.0.0/16:*"]}
            ]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let alice = "ad".repeat(32);
        let router_key = "be".repeat(32);
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            router_key.clone(),
            routed_record(&router_key, "router", 11, vec!["10.10.1.0/24".into()]),
        );
        let _router_guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&router_key),
        );

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{router_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let base = mr
            .packet_filters
            .get("base")
            .and_then(|rules| rules.as_ref())
            .expect("PacketFilters.base present");
        assert_eq!(base.len(), 1);
        assert_eq!(base[0].src_ips, vec!["100.64.0.10"]);
        assert_eq!(base[0].dst_ports[0].ip, "10.10.0.0/16");
    }

    #[tokio::test]
    async fn map_response_keeps_subnet_router_visible_when_policy_targets_route() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["10.10.0.0/16:*"]}
            ]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let alice = "ad".repeat(32);
        let router_key = "be".repeat(32);
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            router_key.clone(),
            routed_record(&router_key, "router", 11, vec!["10.10.1.0/24".into()]),
        );
        let _router_guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&router_key),
        );

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{alice}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({ "Version": 113 })).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(mr.peers.len(), 1);
        assert_eq!(mr.peers[0].name, "router");
        assert!(
            mr.peers[0]
                .allowed_ips
                .iter()
                .any(|route| route == "10.10.1.0/24")
        );
    }

    #[tokio::test]
    async fn map_request_auto_approves_policy_routes() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "autoApprovers": {
                "routes": {"10.20.0.0/16": ["alice@"]},
                "exitNode": ["alice@"]
            }
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let alice = "d1".repeat(32);
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );

        let app = router(state.clone());
        let public_app = public_router(state.clone());
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{alice}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "Version": 113,
                            "OmitPeers": true,
                            "Hostinfo": {
                                "RoutableIPs": [
                                    "10.20.1.0/24",
                                    "10.99.0.0/24",
                                    "0.0.0.0/0"
                                ]
                            }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        assert!(
            raw.is_empty(),
            "non-streaming OmitPeers map updates return an empty lite response"
        );

        let rec = state.machines.get(&alice).expect("alice still registered");
        assert_eq!(
            rec.available_routes,
            vec!["0.0.0.0/0", "10.20.1.0/24", "10.99.0.0/24", "::/0"]
        );
        assert_eq!(
            rec.approved_routes,
            vec!["0.0.0.0/0", "10.20.1.0/24", "::/0"]
        );

        let metrics_resp = public_app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metrics_resp.status(), StatusCode::OK);
        let metrics = to_bytes(metrics_resp.into_body(), 32 * 1024).await.unwrap();
        let metrics = String::from_utf8(metrics.to_vec()).unwrap();
        assert!(
            metrics.contains("headscale_mapresponse_endpoint_updates_total{status=\"ok\"} 1\n")
        );

        let peer = "d2".repeat(32);
        state.machines.upsert(
            peer.clone(),
            policy_record(&peer, "peer", 11, "peer", Vec::new()),
        );
        let _alice_guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&alice),
        );
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{alice}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let node = mr.node.expect("self node");
        assert!(node.allowed_ips.iter().any(|route| route == "10.20.1.0/24"));
        assert!(node.allowed_ips.iter().any(|route| route == "0.0.0.0/0"));
        assert!(node.allowed_ips.iter().any(|route| route == "::/0"));
        assert!(!node.allowed_ips.iter().any(|route| route == "10.99.0.0/24"));
    }

    #[tokio::test]
    async fn map_request_updates_hostinfo_identity_fields() {
        let (state, _dir) = fixture();
        let node_key = "e1".repeat(32);
        insert_peer(&state, &node_key, "old-host", 9);

        let app = router(state.clone());
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "Version": 113,
                            "OmitPeers": true,
                            "Hostinfo": {
                                "Hostname": "new-host",
                                "OS": "darwin",
                                "OSVersion": "15.1",
                                "sshHostKeys": ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey"]
                            }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let rec = state
            .machines
            .get(&node_key)
            .expect("node still registered");
        assert_eq!(rec.hostname, "new-host");
        assert_eq!(rec.os, "darwin");
        assert_eq!(rec.os_version, "15.1");
        assert_eq!(
            rec.ssh_host_keys,
            vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey"]
        );

        let map_node = record_to_map_node(&rec, "tail.example");
        assert_eq!(map_node.hostinfo.hostname, "new-host");
        assert_eq!(map_node.hostinfo.os, "darwin");
        assert_eq!(map_node.hostinfo.os_version, "15.1");
        assert_eq!(
            map_node.hostinfo.ssh_host_keys,
            vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAItestkey"]
        );
    }

    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn map_request_persists_runtime_state_to_go_nodes() {
        use crate::admin::machines::PersistentMachineAdmin;
        use crate::admin::users::{PersistentUserAdmin, UserAdmin};

        let db = headscale_db::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        users.create("alice").await.unwrap();
        let preauth = headscale_db::preauth_keys::create_for_test(
            db.pool(),
            headscale_db::preauth_keys::CreateParams {
                user_id: "1".into(),
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap();
        let machines =
            Arc::new(PersistentMachineAdmin::new(db.pool().clone()).with_user_admin(users));
        let mut record = MachineRecord::new_at(
            chrono::Utc::now(),
            "f1".repeat(32),
            TEST_MACHINE_KEY_HEX.to_string(),
            "alice".into(),
            "old-host".into(),
            Ipv4Addr::new(100, 64, 0, 44),
            false,
        );
        record.register_method = 1;
        machines
            .create_or_update_auth_key_path(
                record.clone(),
                &crate::policy::PolicyStore::new(),
                Some(preauth.row.id),
            )
            .await
            .unwrap();

        let (mut state, _dir) = fixture();
        state
            .machines
            .upsert(record.node_key_hex.clone(), record.clone());
        state.registration_store = Some(machines.clone());
        let app = router(state.clone());
        let disco_key = format!("discokey:{}", "aa".repeat(32));
        let endpoints = vec![
            "198.51.100.10:41641".to_string(),
            "[2001:db8::1]:41641".to_string(),
        ];
        let ssh_host_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIpersisted";

        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{}/map", record.node_key_hex))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "Version": 113,
                            "OmitPeers": true,
                            "DiscoKey": disco_key,
                            "Endpoints": endpoints,
                            "Hostinfo": {
                                "IPNVersion": "1.82.0-test",
                                "Hostname": "persisted-host",
                                "OS": "linux",
                                "OSVersion": "6.8",
                                "Distro": "nixos",
                                "RoutableIPs": ["10.70.0.0/24"],
                                "sshHostKeys": [ssh_host_key],
                                "NetInfo": {
                                    "PreferredDERP": 901,
                                    "WorkingUDP": true,
                                    "LinkType": "wired",
                                    "DERPLatency": {
                                        "901-v4": 0.012
                                    }
                                }
                            }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let row = headscale_db::headscale_nodes::get_by_node_key(
            db.pool(),
            &format!("nodekey:{}", record.node_key_hex),
        )
        .await
        .unwrap();
        assert_eq!(row.auth_key_id, Some(preauth.row.id));
        assert_eq!(row.disco_key, disco_key);
        assert_eq!(row.endpoint_list(), endpoints);
        let host_info = row.host_info_value();
        assert_eq!(host_info["Hostname"], "persisted-host");
        assert_eq!(host_info["OS"], "linux");
        assert_eq!(host_info["OSVersion"], "6.8");
        assert_eq!(host_info["IPNVersion"], "1.82.0-test");
        assert_eq!(host_info["Distro"], "nixos");
        assert_eq!(host_info["RoutableIPs"][0], "10.70.0.0/24");
        assert_eq!(host_info["NetInfo"]["PreferredDERP"], 901);
        assert_eq!(host_info["NetInfo"]["WorkingUDP"], true);
        assert_eq!(host_info["NetInfo"]["LinkType"], "wired");
        assert_eq!(host_info["NetInfo"]["DERPLatency"]["901-v4"], 0.012);
        assert_eq!(host_info["sshHostKeys"][0], ssh_host_key);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{}/map", record.node_key_hex))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "Version": 113,
                            "OmitPeers": true,
                            "Hostinfo": {
                                "IPNVersion": "1.82.0-test",
                                "Hostname": "persisted-host",
                                "OS": "linux",
                                "OSVersion": "6.9",
                                "Distro": "nixos",
                                "RoutableIPs": ["10.70.0.0/24"],
                                "sshHostKeys": [ssh_host_key]
                            }
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let row = headscale_db::headscale_nodes::get_by_node_key(
            db.pool(),
            &format!("nodekey:{}", record.node_key_hex),
        )
        .await
        .unwrap();
        let host_info = row.host_info_value();
        assert_eq!(host_info["OSVersion"], "6.9");
        assert_eq!(host_info["NetInfo"]["PreferredDERP"], 901);
        assert_eq!(host_info["NetInfo"]["WorkingUDP"], true);
        assert_eq!(host_info["NetInfo"]["LinkType"], "wired");
        assert_eq!(host_info["NetInfo"]["DERPLatency"]["901-v4"], 0.012);

        let hydrated = MachineRegistry::new();
        machines.hydrate_wire_registry(&hydrated).await.unwrap();
        let wire = hydrated.get(&record.node_key_hex).unwrap();
        assert_eq!(wire.hostname, "persisted-host");
        assert_eq!(wire.os, "linux");
        assert_eq!(wire.os_version, "6.9");
        assert_eq!(wire.disco_key.as_deref(), Some(disco_key.as_str()));
        assert_eq!(wire.endpoints, endpoints);
        assert_eq!(wire.home_derp, 901);
        assert_eq!(wire.available_routes, vec!["10.70.0.0/24"]);
        assert_eq!(wire.ssh_host_keys, vec![ssh_host_key]);
        assert_eq!(wire.host_info.ipn_version, "1.82.0-test");
        assert_eq!(wire.host_info.distro, "nixos");
        let net_info = wire.host_info.net_info.expect("hydrated NetInfo");
        assert_eq!(net_info.preferred_derp, 901);
        assert_eq!(net_info.working_udp, Some(true));
        assert_eq!(net_info.link_type, "wired");
        assert_eq!(net_info.derp_latency.get("901-v4"), Some(&0.012));
    }

    #[tokio::test]
    async fn map_response_uses_dns_base_domain_for_node_names() {
        let (state, _dir) = fixture();
        state.dns.set_spec(crate::dns::DnsConfigSpec {
            base_domain: "headscale.test".into(),
            ..crate::dns::DnsConfigSpec::default()
        });
        let a = "2a".repeat(32);
        let b = "2b".repeat(32);
        insert_peer(&state, &a, "peer-a", 20);
        insert_peer(&state, &b, "peer-b", 21);

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(mr.peers[0].name, "peer-b.headscale.test");
        assert_eq!(mr.domain, "headscale.test");
    }

    #[tokio::test]
    async fn map_response_applies_nextdns_profile_per_requester() {
        let (state, _dir) = fixture();
        state.dns.set_spec(crate::dns::DnsConfigSpec {
            magic_dns: false,
            override_local_dns: true,
            nameservers: vec!["https://dns.nextdns.io/global".into()],
            ..crate::dns::DnsConfigSpec::default()
        });

        let client_key = "2c".repeat(32);
        let mut client = policy_record(
            &client_key,
            "client-node",
            22,
            "alice@example.com",
            vec!["tag:client".into()],
        );
        client.replace_host_info(HostInfo {
            hostname: "client-node".into(),
            os: "linux".into(),
            ..HostInfo::default()
        });
        state.machines.upsert(client_key.clone(), client);

        let server_key = "2d".repeat(32);
        let mut server = policy_record(
            &server_key,
            "server-node",
            23,
            "alice@example.com",
            vec!["tag:server".into()],
        );
        server.replace_host_info(HostInfo {
            hostname: "server-node".into(),
            os: "darwin".into(),
            ..HostInfo::default()
        });
        state.machines.upsert(server_key.clone(), server);

        let raw_policy = r#"
            version = 1

            [tag_owners]
            "tag:client" = ["alice@example.com"]
            "tag:server" = ["alice@example.com"]

            [[node_attrs]]
            target = ["tag:client"]
            attr = ["nextdns:client-profile"]

            [[node_attrs]]
            target = ["tag:server"]
            attr = ["nextdns:server-profile", "nextdns:no-device-info"]
        "#;
        let doc = crate::policy::PolicyDoc::from_toml(raw_policy).unwrap();
        state.policy.set(doc, raw_policy.to_string());

        let app = router(state);
        let client_resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{client_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(client_resp.status(), StatusCode::OK);
        let client_raw = to_bytes(client_resp.into_body(), 32 * 1024).await.unwrap();
        let client_map: MapResponse = serde_json::from_slice(&client_raw).unwrap();
        assert_eq!(
            client_map.dns_config.unwrap().resolvers[0].addr,
            "https://dns.nextdns.io/client-profile?device_ip=100.64.0.22&device_model=linux&device_name=client-node"
        );

        let server_resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{server_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(server_resp.status(), StatusCode::OK);
        let server_raw = to_bytes(server_resp.into_body(), 32 * 1024).await.unwrap();
        let server_map: MapResponse = serde_json::from_slice(&server_raw).unwrap();
        assert_eq!(
            server_map.dns_config.unwrap().resolvers[0].addr,
            "https://dns.nextdns.io/server-profile"
        );
    }

    #[tokio::test]
    async fn stream_true_derp_map_refresh_emits_full_map_response() {
        let (state, _dir) = fixture();
        let a = "d1".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first = next_zstd_map_response(&mut body).await;
        assert!(first.derp_map.unwrap().regions.is_empty());

        state.derp_map.set(DerpMap {
            home_params: None,
            regions: std::collections::HashMap::from([(
                777,
                DerpRegion {
                    region_id: 777,
                    region_code: "refresh".into(),
                    region_name: "Refresh DERP".into(),
                    latitude: 0.0,
                    longitude: 0.0,
                    avoid: false,
                    no_measure_no_home: false,
                    nodes: vec![DerpRegionNode {
                        name: "777a".into(),
                        region_id: 777,
                        host_name: "refresh.example.com".into(),
                        cert_name: String::new(),
                        ipv4: String::new(),
                        ipv6: String::new(),
                        derp_port: 0,
                        stun_port: -1,
                        stun_only: false,
                        insecure_for_tests: false,
                        stun_test_ip: String::new(),
                        can_port80: false,
                    }],
                },
            )]),
            omit_default_regions: false,
        });

        let updated = next_zstd_map_response(&mut body).await;
        let derp_map = updated.derp_map.unwrap();
        assert_eq!(
            derp_map
                .regions
                .get(&777)
                .unwrap()
                .nodes
                .first()
                .unwrap()
                .host_name,
            "refresh.example.com"
        );
    }

    #[tokio::test]
    async fn stream_true_dns_refresh_emits_full_map_response() {
        let (state, _dir) = fixture();
        let a = "d2".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first = next_zstd_map_response(&mut body).await;
        assert_eq!(first.dns_config.unwrap().extra_records.len(), 0);

        let state_for_spawn = state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            state_for_spawn.dns.set_spec(crate::dns::DnsConfigSpec {
                base_domain: "headscale.test".into(),
                override_local_dns: false,
                extra_records: vec![DnsRecord {
                    name: "reload.headscale.test".into(),
                    record_type: "AAAA".into(),
                    value: "fd7a:115c:a1e0::53".into(),
                }],
                ..crate::dns::DnsConfigSpec::default()
            });
        });

        let updated = next_zstd_map_response(&mut body).await;
        let dns = updated.dns_config.expect("dns config");
        assert_eq!(dns.domains, vec!["headscale.test"]);
        assert!(dns.extra_records.iter().any(|record| {
            record.name == "reload.headscale.test"
                && record.record_type == "AAAA"
                && record.value == "fd7a:115c:a1e0::53"
        }));
        assert!(!updated.keep_alive);
    }

    #[tokio::test]
    async fn map_response_marks_only_one_primary_for_conflicting_routes() {
        let (state, _dir) = fixture();
        let a = "31".repeat(32);
        let b = "32".repeat(32);
        let route = "10.0.0.0/24".to_string();

        for (node_key, host, last_octet) in [(&a, "router-a", 31), (&b, "router-b", 32)] {
            state.machines.upsert(
                node_key.clone(),
                routed_record(node_key, host, last_octet, vec![route.clone()]),
            );
        }
        let _guard_a = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&a),
        );
        let _guard_b = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&b),
        );

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();

        let mut nodes = vec![mr.node.expect("self node")];
        nodes.extend(mr.peers);
        assert_eq!(
            nodes
                .iter()
                .filter(|node| node.primary_routes == vec![route.clone()])
                .count(),
            1
        );
        assert_eq!(
            nodes
                .iter()
                .filter(|node| node.allowed_ips.iter().any(|ip| ip == &route))
                .count(),
            1
        );
    }

    fn via_steering_policy(group_a_via: &str, group_b_via: &str) -> String {
        format!(
            r#"{{
                "tagOwners": {{
                    "tag:router-a": ["router@"],
                    "tag:router-b": ["router@"],
                    "tag:group-a": ["client@"],
                    "tag:group-b": ["client@"]
                }},
                "grants": [
                    {{
                        "src": ["tag:router-a", "tag:router-b", "tag:group-a", "tag:group-b"],
                        "dst": ["tag:router-a", "tag:router-b", "tag:group-a", "tag:group-b"],
                        "ip": ["*"]
                    }},
                    {{
                        "src": ["tag:group-a"],
                        "dst": ["10.0.0.0/24"],
                        "ip": ["*"],
                        "via": ["{group_a_via}"]
                    }},
                    {{
                        "src": ["tag:group-b"],
                        "dst": ["10.0.0.0/24"],
                        "ip": ["*"],
                        "via": ["{group_b_via}"]
                    }}
                ]
            }}"#
        )
    }

    fn insert_via_steering_nodes(state: &WireState) -> (String, String, String, String) {
        insert_via_steering_nodes_for_route(state, "10.0.0.0/24", Vec::new())
    }

    fn insert_via_steering_nodes_for_route(
        state: &WireState,
        route: &str,
        router_b_extra_routes: Vec<String>,
    ) -> (String, String, String, String) {
        let route = route.to_string();
        let mut router_b_routes = vec![route.clone()];
        router_b_routes.extend(router_b_extra_routes);

        let router_a = "61".repeat(32);
        let router_b = "62".repeat(32);
        let client_a = "63".repeat(32);
        let client_b = "64".repeat(32);

        for (node_key, host, octet, user, tags, routes) in [
            (
                &router_a,
                "router-a",
                61,
                "router",
                vec!["tag:router-a".to_string()],
                vec![route],
            ),
            (
                &router_b,
                "router-b",
                62,
                "router",
                vec!["tag:router-b".to_string()],
                router_b_routes,
            ),
            (
                &client_a,
                "client-a",
                63,
                "client",
                vec!["tag:group-a".to_string()],
                Vec::new(),
            ),
            (
                &client_b,
                "client-b",
                64,
                "client",
                vec!["tag:group-b".to_string()],
                Vec::new(),
            ),
        ] {
            let mut rec = policy_record(node_key, host, octet, user, tags);
            rec.available_routes = routes.clone();
            rec.approved_routes = routes;
            state.machines.upsert(node_key.clone(), rec);
        }

        (router_a, router_b, client_a, client_b)
    }

    fn via_steering_policy_with_exit_allow(route: &str) -> String {
        format!(
            r#"{{
                "tagOwners": {{
                    "tag:router-a": ["router@"],
                    "tag:router-b": ["router@"],
                    "tag:group-a": ["client@"]
                }},
                "grants": [
                    {{
                        "src": ["tag:group-a"],
                        "dst": ["{route}"],
                        "ip": ["*"],
                        "via": ["tag:router-a"]
                    }},
                    {{
                        "src": ["tag:group-a"],
                        "dst": ["autogroup:internet"],
                        "ip": ["*"]
                    }}
                ]
            }}"#
        )
    }

    fn via_steering_policy_with_regular_overlap(route: &str, via_tag: &str) -> String {
        format!(
            r#"{{
                "tagOwners": {{
                    "tag:router-a": ["router@"],
                    "tag:router-b": ["router@"],
                    "tag:group-a": ["client@"]
                }},
                "grants": [
                    {{
                        "src": ["tag:group-a"],
                        "dst": ["{route}"],
                        "ip": ["*"]
                    }},
                    {{
                        "src": ["tag:group-a"],
                        "dst": ["{route}"],
                        "ip": ["*"],
                        "via": ["{via_tag}"]
                    }}
                ]
            }}"#
        )
    }

    fn via_steering_policy_with_multi_router_via(route: &str) -> String {
        format!(
            r#"{{
                "tagOwners": {{
                    "tag:router-ha": ["router@"],
                    "tag:group-a": ["client@"]
                }},
                "grants": [
                    {{
                        "src": ["tag:group-a"],
                        "dst": ["{route}"],
                        "ip": ["*"],
                        "via": ["tag:router-ha"]
                    }}
                ]
            }}"#
        )
    }

    fn via_steering_policy_with_exit_node_via() -> &'static str {
        r#"{
            "tagOwners": {
                "tag:router-a": ["router@"],
                "tag:router-b": ["router@"],
                "tag:group-a": ["client@"]
            },
            "grants": [
                {
                    "src": ["tag:router-a", "tag:router-b", "tag:group-a"],
                    "dst": ["tag:router-a", "tag:router-b", "tag:group-a"],
                    "ip": ["*"]
                },
                {
                    "src": ["tag:group-a"],
                    "dst": ["autogroup:internet"],
                    "ip": ["*"],
                    "via": ["tag:router-a"]
                }
            ]
        }"#
    }

    fn insert_via_exit_nodes(state: &WireState) -> (String, String, String) {
        let router_a = "65".repeat(32);
        let router_b = "66".repeat(32);
        let client_a = "67".repeat(32);
        let exit_routes = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];

        for (node_key, host, octet, user, tags, routes) in [
            (
                &router_a,
                "router-a",
                65,
                "router",
                vec!["tag:router-a".to_string()],
                exit_routes.clone(),
            ),
            (
                &router_b,
                "router-b",
                66,
                "router",
                vec!["tag:router-b".to_string()],
                exit_routes,
            ),
            (
                &client_a,
                "client-a",
                67,
                "client",
                vec!["tag:group-a".to_string()],
                Vec::new(),
            ),
        ] {
            let mut rec = policy_record(node_key, host, octet, user, tags);
            rec.available_routes = routes.clone();
            rec.approved_routes = routes;
            state.machines.upsert(node_key.clone(), rec);
        }

        (router_a, router_b, client_a)
    }

    fn peer_route<'a>(mr: &'a MapResponse, name: &str, route: &str) -> Option<&'a MapNode> {
        mr.peers.iter().find(|peer| {
            peer.name == name && peer.allowed_ips.iter().any(|allowed| allowed == route)
        })
    }

    fn changed_peer<'a>(mr: &'a MapResponse, name: &str) -> Option<&'a MapNode> {
        mr.peers_changed.iter().find(|peer| peer.name == name)
    }

    #[tokio::test]
    async fn map_response_shows_global_primary_to_same_prefix_secondary_under_deny_policy() {
        let (state, _dir) = fixture();
        let route = "10.80.0.0/24";
        let router_a = "71".repeat(32);
        let router_b = "72".repeat(32);
        let mut guards = Vec::new();
        for (node_key, host, octet) in [(&router_a, "router-a", 71), (&router_b, "router-b", 72)] {
            state.machines.upsert(
                node_key.clone(),
                routed_record(node_key, host, octet, vec![route.to_string()]),
            );
            guards.push(MachineRegistry::track_stream_connection(
                state.machines.clone(),
                stable_id_from_key(node_key),
            ));
        }
        assert_eq!(guards.len(), 2);
        let deny_policy = r#"{"acls":[]}"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(deny_policy).unwrap(),
            deny_policy.to_string(),
        );
        let snapshot = state.machines.snapshot();
        let primary_routes = state.machines.primary_routes_for_snapshot(&snapshot);
        let primary = owner_for_route(&primary_routes, route).expect("global primary");
        let (primary_name, secondary) = if primary == router_a {
            ("router-a", router_b)
        } else {
            ("router-b", router_a)
        };

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{secondary}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let primary_peer =
            peer_route(&mr, primary_name, route).expect("secondary sees global primary route");
        assert_eq!(primary_peer.primary_routes, vec![route.to_string()]);
    }

    #[tokio::test]
    async fn map_response_steers_same_prefix_to_different_via_routers_per_viewer() {
        let (state, _dir) = fixture();
        let policy = via_steering_policy("tag:router-a", "tag:router-b");
        state
            .policy
            .set(crate::policy::parse_hujson_policy(&policy).unwrap(), policy);
        let (_router_a, _router_b, client_a, client_b) = insert_via_steering_nodes(&state);

        let app = router(state);
        let route = "10.0.0.0/24";
        for (client, expected, unexpected) in [
            (&client_a, "router-a", "router-b"),
            (&client_b, "router-b", "router-a"),
        ] {
            let resp = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri(format!("/machine/nodekey:{client}/map"))
                        .header("content-type", "application/json")
                        .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
            let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
            let mr: MapResponse = serde_json::from_slice(&raw).unwrap();

            assert!(peer_route(&mr, expected, route).is_some());
            assert!(peer_route(&mr, unexpected, route).is_none());
        }
    }

    #[tokio::test]
    async fn map_response_via_subnet_excludes_non_via_peer_but_keeps_exit_routes() {
        let (state, _dir) = fixture();
        let route = "10.77.0.0/24";
        let policy = via_steering_policy_with_exit_allow(route);
        state
            .policy
            .set(crate::policy::parse_hujson_policy(&policy).unwrap(), policy);
        let (router_a, router_b, client_a, _client_b) = insert_via_steering_nodes_for_route(
            &state,
            route,
            vec!["0.0.0.0/0".to_string(), "::/0".to_string()],
        );
        let _router_a_guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&router_a),
        );
        let _router_b_guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&router_b),
        );
        let snapshot = state.machines.snapshot();
        let router_b_record = snapshot.get(&router_b).expect("router-b record");
        assert!(router_b_record.available_routes.iter().any(|r| r == route));
        assert!(router_b_record.approved_routes.iter().any(|r| r == route));
        assert_eq!(
            state
                .machines
                .primary_routes_for_snapshot(&snapshot)
                .get(&router_b)
                .cloned()
                .unwrap_or_default(),
            vec![route.to_string()],
            "test setup must make router-b the unfiltered primary for the duplicate subnet"
        );

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{client_a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();

        assert!(peer_route(&mr, "router-a", route).is_some());
        let router_b_node = mr
            .peers
            .iter()
            .find(|peer| peer.name == "router-b")
            .expect("router-b visible through separately allowed exit routes");
        assert!(
            !router_b_node
                .allowed_ips
                .iter()
                .any(|allowed| allowed == route),
            "via should remove router-b's duplicate subnet AllowedIP"
        );
        assert!(
            !router_b_node
                .primary_routes
                .iter()
                .any(|primary| primary == route),
            "via should remove router-b's primary route for the duplicate subnet"
        );
        assert!(
            router_b_node
                .allowed_ips
                .iter()
                .any(|allowed| allowed == "0.0.0.0/0")
        );
        assert!(
            router_b_node
                .allowed_ips
                .iter()
                .any(|allowed| allowed == "::/0")
        );
    }

    #[tokio::test]
    async fn map_response_via_exit_node_keeps_matching_defaults_and_strips_non_matching() {
        let (state, _dir) = fixture();
        let policy = via_steering_policy_with_exit_node_via();
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.to_string(),
        );
        let (router_a, router_b, client_a) = insert_via_exit_nodes(&state);
        let _router_a_guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&router_a),
        );
        let _router_b_guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&router_b),
        );

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{client_a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();

        let router_a_node = mr
            .peers
            .iter()
            .find(|peer| peer.name == "router-a")
            .expect("matching via exit node remains visible");
        assert!(
            router_a_node
                .allowed_ips
                .iter()
                .any(|allowed| allowed == "0.0.0.0/0")
        );
        assert!(
            router_a_node
                .allowed_ips
                .iter()
                .any(|allowed| allowed == "::/0")
        );

        let router_b_node = mr
            .peers
            .iter()
            .find(|peer| peer.name == "router-b")
            .expect("non-matching exit node remains visible through node ACLs");
        assert!(
            !router_b_node
                .allowed_ips
                .iter()
                .any(|allowed| allowed == "0.0.0.0/0"),
            "via should remove router-b's IPv4 default route"
        );
        assert!(
            !router_b_node
                .allowed_ips
                .iter()
                .any(|allowed| allowed == "::/0"),
            "via should remove router-b's IPv6 default route"
        );
    }

    #[tokio::test]
    async fn map_response_via_regular_overlap_uses_global_primary_route() {
        let (state, _dir) = fixture();
        let route = "10.78.0.0/24";
        let (router_a, router_b, client_a, _client_b) =
            insert_via_steering_nodes_for_route(&state, route, Vec::new());
        let _router_a_guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&router_a),
        );
        let _router_b_guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&router_b),
        );
        let snapshot = state.machines.snapshot();
        let primary_routes = state.machines.primary_routes_for_snapshot(&snapshot);
        let global_primary = owner_for_route(&primary_routes, route).expect("global primary");
        let (primary_name, non_primary_name, non_primary_via_tag) = if global_primary == router_a {
            ("router-a", "router-b", "tag:router-b")
        } else {
            ("router-b", "router-a", "tag:router-a")
        };
        let policy = via_steering_policy_with_regular_overlap(route, non_primary_via_tag);
        state
            .policy
            .set(crate::policy::parse_hujson_policy(&policy).unwrap(), policy);

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{client_a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();

        assert!(
            peer_route(&mr, primary_name, route).is_some(),
            "regular grant overlap should defer via steering to the global primary"
        );
        assert!(
            peer_route(&mr, non_primary_name, route).is_none(),
            "non-primary via router should not receive the duplicate route when UsePrimary applies"
        );
    }

    #[tokio::test]
    async fn map_response_via_multi_router_tag_elects_one_router() {
        let (state, _dir) = fixture();
        let route = "10.79.0.0/24";
        let policy = via_steering_policy_with_multi_router_via(route);
        state
            .policy
            .set(crate::policy::parse_hujson_policy(&policy).unwrap(), policy);
        let (router_a, router_b, client_a, _client_b) =
            insert_via_steering_nodes_for_route(&state, route, Vec::new());
        for router in [&router_a, &router_b] {
            let mut rec = state.machines.get(router).expect("router record");
            rec.forced_tags = vec!["tag:router-ha".to_string()];
            state.machines.upsert(router.clone(), rec);
        }

        let (expected, unexpected) =
            if stable_id_from_key(&router_a) < stable_id_from_key(&router_b) {
                ("router-a", "router-b")
            } else {
                ("router-b", "router-a")
            };

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{client_a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();

        assert!(
            peer_route(&mr, expected, route).is_some(),
            "lowest-ID via router should keep the steered route"
        );
        assert!(
            peer_route(&mr, unexpected, route).is_none(),
            "non-primary via router should be excluded for the same prefix"
        );
    }

    #[tokio::test]
    async fn stream_policy_change_moves_via_route_allowed_ips() {
        let (state, _dir) = fixture();
        let policy = via_steering_policy("tag:router-a", "tag:router-b");
        state
            .policy
            .set(crate::policy::parse_hujson_policy(&policy).unwrap(), policy);
        let (_router_a, _router_b, client_a, _client_b) = insert_via_steering_nodes(&state);

        let app = router(state.clone());
        let route = "10.0.0.0/24";
        let mut body = open_zstd_stream(app, &client_a).await;
        let first = next_zstd_map_response(&mut body).await;
        assert!(peer_route(&first, "router-a", route).is_some());
        assert!(peer_route(&first, "router-b", route).is_none());

        let moved_policy = via_steering_policy("tag:router-b", "tag:router-b");
        tokio::spawn({
            let policy = state.policy.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                policy.set(
                    crate::policy::parse_hujson_policy(&moved_policy).unwrap(),
                    moved_policy,
                );
            }
        });

        let updated = next_zstd_map_response(&mut body).await;
        assert!(
            updated.peers.is_empty(),
            "policy wake should use incremental peer deltas"
        );
        assert!(updated.peers_removed.is_empty());
        let router_a = changed_peer(&updated, "router-a").expect("router-a changed");
        assert!(!router_a.allowed_ips.iter().any(|allowed| allowed == route));
        let router_b = changed_peer(&updated, "router-b").expect("router-b changed");
        assert!(router_b.allowed_ips.iter().any(|allowed| allowed == route));
        assert!(
            updated.dns_config.is_some(),
            "policy deltas carry policy-derived DNSConfig updates"
        );
    }

    #[tokio::test]
    async fn map_response_keeps_exit_routes_out_of_primary_routes() {
        let (state, _dir) = fixture();
        let a = "41".repeat(32);
        let b = "42".repeat(32);
        state.machines.upsert(
            a.clone(),
            routed_record(
                &a,
                "exit-a",
                41,
                vec!["0.0.0.0/0".into(), "::/0".into(), "10.0.0.0/24".into()],
            ),
        );
        insert_peer(&state, &b, "peer-b", 42);
        let _guard_a = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&a),
        );

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let node = mr.node.expect("self node");

        assert_eq!(node.primary_routes, vec!["10.0.0.0/24"]);
        assert!(node.allowed_ips.iter().any(|route| route == "0.0.0.0/0"));
        assert!(node.allowed_ips.iter().any(|route| route == "::/0"));
        assert!(node.allowed_ips.iter().any(|route| route == "10.0.0.0/24"));
    }

    #[test]
    fn registry_primary_routes_preserve_owner_when_old_primary_returns() {
        let (state, _dir) = fixture();
        let route = "10.44.0.0/24".to_string();
        let mut guards = Vec::new();
        for (node_key, host, last_octet) in [
            ("51".repeat(32), "router-a", 51),
            ("52".repeat(32), "router-b", 52),
            ("53".repeat(32), "router-c", 53),
        ] {
            state.machines.upsert(
                node_key.clone(),
                routed_record(&node_key, host, last_octet, vec![route.clone()]),
            );
            guards.push(MachineRegistry::track_stream_connection(
                state.machines.clone(),
                stable_id_from_key(&node_key),
            ));
        }
        assert_eq!(guards.len(), 3);

        let first = state
            .machines
            .primary_routes_for_snapshot(&state.machines.snapshot());
        let first_owner = owner_for_route(&first, &route).expect("initial primary owner");
        let old_primary = state
            .machines
            .get(&first_owner)
            .expect("old primary record");
        assert!(state.machines.delete(&first_owner));

        let second = state
            .machines
            .primary_routes_for_snapshot(&state.machines.snapshot());
        let second_owner = owner_for_route(&second, &route).expect("replacement primary owner");
        assert_ne!(second_owner, first_owner);

        state.machines.upsert(first_owner.clone(), old_primary);
        let third = state
            .machines
            .primary_routes_for_snapshot(&state.machines.snapshot());
        assert_eq!(
            third.get(&second_owner).cloned().unwrap_or_default(),
            vec![route]
        );
        assert!(!third.contains_key(&first_owner));
    }

    #[tokio::test]
    async fn unregistered_node_gets_404() {
        let (state, _dir) = fixture();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{}/map", "ff".repeat(32)))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// Long-poll wakes when a second peer registers. We start the map
    /// request when only one peer exists, spawn a delayed insert of the
    /// second peer, and assert the map returns the joined view (not
    /// the timeout-fallback empty view).
    #[tokio::test]
    async fn long_poll_wakes_on_second_register() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);

        let state_for_spawn = state.clone();
        let b_clone = b.clone();
        let waker = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            insert_peer(&state_for_spawn, &b_clone, "peer-b", 11);
        });

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        waker.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(
            mr.peers.len(),
            1,
            "long-poll should have woken on B's register"
        );
    }

    /// Flat v1.78+ path: NodeKey lives in the body.
    #[tokio::test]
    async fn flat_map_extracts_node_key_from_body() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state);
        let req = serde_json::json!({
            "NodeKey": format!("nodekey:{a}"),
            "Version": 113,
        });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/machine/map")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&req).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let node = mr.node.as_ref().expect("own node present");
        assert_eq!(node.addresses[0], "100.64.0.10/32");
        assert_eq!(mr.peers.len(), 1);
    }

    /// Keyed map still works (regression guard).
    #[tokio::test]
    async fn keyed_map_still_works_after_flat_addition() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Flat map follows headscale-go: empty NodeKey parses as the zero key
    /// and misses the registry lookup.
    #[tokio::test]
    async fn flat_map_missing_node_key_returns_not_found() {
        let (state, _dir) = fixture();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/machine/map")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let raw = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(raw.as_ref(), b"node not found\n");
    }

    /// Return the body from a single `[u32 LE size][body]` frame.
    fn framed_body(bytes: &[u8]) -> &[u8] {
        assert!(
            bytes.len() >= 4,
            "framed chunk too short: {} bytes",
            bytes.len()
        );
        let size = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(
            bytes.len(),
            4 + size,
            "frame size mismatch: header says {size}, body has {}",
            bytes.len() - 4
        );
        &bytes[4..]
    }

    /// Decode a single `[u32 LE size][zstd(JSON)]` framed chunk back
    /// into the original JSON bytes. Mirrors what upstream
    /// `controlclient/direct.go::decodeMsg` does when Compress=zstd.
    fn decode_framed(bytes: &[u8]) -> Vec<u8> {
        zstd::bulk::decompress(framed_body(bytes), 16 * 1024 * 1024).expect("valid zstd frame")
    }

    async fn open_zstd_stream(app: axum::Router, node_key_hex: &str) -> axum::body::Body {
        let req_body = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key_hex}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        resp.into_body()
    }

    async fn next_zstd_map_response(body: &mut axum::body::Body) -> MapResponse {
        let frame = http_body_util::BodyExt::frame(body).await.unwrap().unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        serde_json::from_slice(&decoded).unwrap()
    }

    async fn assert_no_stream_frame(body: &mut axum::body::Body, within: Duration) {
        let result = tokio::time::timeout(within, http_body_util::BodyExt::frame(body)).await;
        assert!(
            result.is_err(),
            "stream emitted an unexpected frame within {within:?}"
        );
    }

    /// Stream:true: notify_waiters on the registry produces a follow-up
    /// MapResponse chunk on the existing stream (PR 3 acceptance).
    /// We drive `tokio::time::pause` so the test doesn't actually wait
    /// 30s for the keepalive interval.
    #[tokio::test(start_paused = true)]
    async fn stream_true_emits_mapresponse_chunk_on_registry_change() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        // Note: only peer-a registered initially.

        let app = router(state.clone());
        let public_app = public_router(state.clone());
        let req_body = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // First chunk: a single-peer MapResponse (no peers yet),
        // length-prefixed + zstd-compressed.
        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let first_mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(first_mr.peers.len(), 0);

        // Schedule the registry change. **audit-2 C-1 fix landed**:
        // since the stream now consumes a `watch::Receiver<u64>` (see
        // the wake-channel doc on `MachineRegistry`), the receiver's
        // last-seen generation lags the sender across `.await`
        // boundaries — a bump fired BEFORE the receiver is parked on
        // `changed()` is still captured by the next call. We keep the
        // 50ms spawn-delay here for readability (it preserves the
        // "first chunk → wait → second chunk" pacing that makes the
        // test easy to read), but the previous "registered listener
        // is mandatory before the wake" hazard is gone — see the
        // companion `stream_true_wake_during_chunk_build_is_not_lost`
        // test below for the load-bearing proof.
        let state_for_spawn = state.clone();
        let b_clone = b.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            insert_peer(&state_for_spawn, &b_clone, "peer-b", 11);
        });

        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(
            mr.peers.is_empty(),
            "follow-up stream chunks use incremental peer deltas"
        );
        assert_eq!(
            mr.peers_changed.len(),
            1,
            "second chunk should include the newly-registered peer as a delta"
        );
        assert_eq!(mr.peers_changed[0].addresses[0], "100.64.0.11/32");
        assert!(mr.peers_removed.is_empty());

        let metrics_resp = public_app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let metrics = to_bytes(metrics_resp.into_body(), 32 * 1024).await.unwrap();
        let metrics = String::from_utf8(metrics.to_vec()).unwrap();
        assert!(
            metrics.contains("headscale_mapresponse_generated_total{response_type=\"peers\"} 1\n")
        );

        drop(body);

        let metrics_resp = public_app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let metrics = to_bytes(metrics_resp.into_body(), 32 * 1024).await.unwrap();
        let metrics = String::from_utf8(metrics.to_vec()).unwrap();
        assert!(metrics.contains("headscale_mapresponse_ended_total{reason=\"done\"} 1\n"));
    }

    #[tokio::test]
    async fn stream_true_emits_ping_request_chunk_and_callback_completes() {
        let (mut state, _dir) = fixture();
        state.public_control_url = Some("https://control.example".into());
        let a = "aa".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);

        let app = router(state.clone());
        let public_app = public_router(state.clone());
        let req_body = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let first_mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(first_mr.ping_request.is_none());

        let node_id = stable_id_from_key(&a);
        let (ping_id, response) = state.register_ping(node_id);
        let request = state.dispatch_ping_request(node_id, &ping_id, true, false);
        assert_eq!(
            request.url,
            format!("https://control.example/machine/ping-response?id={ping_id}")
        );
        assert!(!request.url_is_noise);
        assert!(request.log);

        let frame = tokio::time::timeout(
            Duration::from_secs(1),
            http_body_util::BodyExt::frame(&mut body),
        )
        .await
        .expect("ping request map chunk")
        .unwrap()
        .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        let ping_request = mr.ping_request.expect("PingRequest chunk");
        assert_eq!(
            ping_request.url,
            format!("https://control.example/machine/ping-response?id={ping_id}")
        );
        assert!(!ping_request.url_is_noise);
        assert!(ping_request.log);
        assert!(mr.node.is_none());
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());

        let resp = public_app
            .oneshot(
                axum::http::Request::builder()
                    .method(axum::http::Method::HEAD)
                    .uri(format!("/machine/ping-response?id={ping_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(body_bytes.is_empty());
        let latency = tokio::time::timeout(Duration::from_secs(1), response)
            .await
            .expect("ping callback completion")
            .expect("ping response receiver");
        assert!(latency <= Duration::from_secs(5));
    }

    /// Upstream always length-prefixes map stream frames, but only
    /// zstd-compresses the frame body when the request asks for it.
    #[tokio::test]
    async fn stream_true_without_compress_emits_plain_framed_json() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state);
        let req_body = serde_json::json!({ "Stream": true, "Version": 113 });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = framed_body(&chunk);
        let mr: MapResponse = serde_json::from_slice(decoded).unwrap();
        assert_eq!(mr.peers.len(), 1);
        assert!(
            zstd::bulk::decompress(decoded, 16 * 1024 * 1024).is_err(),
            "unnegotiated stream frame should not be zstd-compressed"
        );
    }

    /// audit-2 C-1: a registry change fired **before** the unfold
    /// re-parks on `changed()` MUST still wake the next chunk.
    ///
    /// The prior `Notify::notified()` implementation lost wakes
    /// emitted in the window between "previous chunk yielded" and
    /// "next iteration registers the listener". The watch-channel
    /// receiver is missed-update tolerant: the sender's value is
    /// stored in the channel; if the receiver hasn't observed the
    /// latest yet, `changed()` returns immediately. This test fires
    /// the registry change with NO `sleep` first, exercising exactly
    /// the gap the prior implementation lost.
    #[tokio::test(start_paused = true)]
    async fn stream_true_wake_during_chunk_build_is_not_lost() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);

        let app = router(state.clone());
        let req_body = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Consume the initial chunk.
        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let _ = frame.into_data().unwrap();

        // CRITICAL: bump the registry IMMEDIATELY — no sleep, no yield.
        // Under the old `Notify`-only implementation, the unfold has
        // returned the first chunk into the framed body and is now
        // re-entering its async block; the `Notified` listener for
        // the second iteration has not yet been registered. The
        // `notify_waiters()` call below would have been dropped on
        // the floor. Under the watch-channel implementation, the
        // sender's new value is stored; the next `changed().await`
        // returns immediately.
        insert_peer(&state, &b, "peer-b", 11);

        // Now read the next chunk — must be the refreshed MapResponse
        // (PeersChanged.len == 1), NOT a keepalive.
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(
            mr.peers.is_empty(),
            "follow-up stream chunks use incremental peer deltas"
        );
        assert_eq!(
            mr.peers_changed.len(),
            1,
            "wake fired during chunk-build window must surface on the next chunk; \
             got keepalive instead, indicating the lost-wake race regressed"
        );
        assert_eq!(mr.peers_changed[0].addresses[0], "100.64.0.11/32");
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_empty_acl_registry_delta_matches_headscale_go() {
        let (state, _dir) = fixture();
        let policy = r#"{"acls":[]}"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);

        let app = router(state.clone());
        let req_body = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let first_mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(
            first_mr.peers.is_empty(),
            "full map still uses the empty ACL peer map"
        );
        assert!(
            first_mr
                .packet_filters
                .get("base")
                .and_then(|rules| rules.as_ref())
                .is_none_or(Vec::is_empty),
            "empty ACL still sends an empty packet filter"
        );

        insert_peer(&state, &b, "peer-b", 11);

        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(mr.peers.is_empty());
        assert!(mr.peers_removed.is_empty());
        assert_eq!(mr.peers_changed.len(), 1);
        assert_eq!(mr.peers_changed[0].id, stable_id_from_key(&b));
        assert_eq!(mr.peers_changed[0].name, "peer-b");
        assert!(
            mr.packet_filters
                .get("base")
                .and_then(|rules| rules.as_ref())
                .is_none_or(Vec::is_empty),
            "incremental empty-ACL updates must not loosen packet filters"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_emits_peers_removed_when_peer_disappears() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let req_body = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let first_mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(first_mr.peers.len(), 1);

        assert!(state.machines.delete(&b));

        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());
        assert_eq!(mr.peers_removed, vec![stable_id_from_key(&b)]);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_policy_reload_to_empty_acl_emits_peers_removed() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let req_body = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let first_mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&b));

        let policy_update = tokio::spawn({
            let policy = state.policy.clone();
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                let raw = r#"{"acls":[]}"#;
                policy.set(crate::policy::parse_hujson_policy(raw).unwrap(), raw.into());
            }
        });

        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        policy_update.await.expect("policy update task");
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();

        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());
        assert_eq!(mr.peers_removed, vec![stable_id_from_key(&b)]);
        assert!(
            mr.dns_config.is_some(),
            "policy deltas should carry policy-derived DNSConfig updates"
        );
        assert!(
            mr.packet_filters
                .get("base")
                .and_then(|rules| rules.as_ref())
                .is_some_and(Vec::is_empty),
            "loaded empty ACL should keep the base packet filter empty"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_noop_ephemeral_gc_does_not_emit_empty_delta() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        state.machines.upsert(
            b.clone(),
            MachineRecord::new_at(
                chrono::Utc::now(),
                b.clone(),
                TEST_MACHINE_KEY_HEX.to_string(),
                "u".into(),
                "peer-b".into(),
                Ipv4Addr::new(100, 64, 0, 11),
                true,
            ),
        );

        let app = router(state.clone());
        let req_body = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let first_mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(first_mr.peers.len(), 1);

        assert!(
            state
                .machines
                .gc_ephemeral(Duration::from_secs(60))
                .is_empty()
        );
        tokio::task::yield_now().await;

        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "fresh/no-match ephemeral GC must not wake streams with an empty peers delta"
        );

        tokio::time::advance(MAP_KEEPALIVE_INTERVAL + Duration::from_millis(1)).await;
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        assert_eq!(&decoded[..], br#"{"KeepAlive":true}"#);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_self_expiry_update_emits_self_node_key_expiry() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let req_body = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let first_mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(first_mr.peers.len(), 1);
        assert!(!first_mr.node.as_ref().unwrap().expired);

        let expiry = chrono::Utc::now() - chrono::Duration::seconds(1);
        assert!(state.machines.set_expiry(&a, Some(expiry)));

        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        let self_node = mr.node.as_ref().expect("self node update present");
        assert_eq!(self_node.key_expiry, Some(expiry));
        assert!(self_node.expired);
        assert!(!self_node.machine_authorized);
        assert!(mr.peers_changed.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_peer_key_expiry_uses_peer_changed_patch() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &b).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&a));
        assert!(first_mr.peers[0].key_expiry.is_none());

        let expiry = chrono::Utc::now() + chrono::Duration::days(7);
        assert!(state.machines.set_expiry(&a, Some(expiry)));

        let mr = next_zstd_map_response(&mut body).await;
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());
        assert!(mr.peers_removed.is_empty());
        assert_eq!(mr.peers_changed_patch.len(), 1);
        let patch = &mr.peers_changed_patch[0];
        assert_eq!(patch.node_id, stable_id_from_key(&a));
        assert!(patch.endpoints.is_empty());
        assert_eq!(patch.derp_region, 0);
        assert!(patch.online.is_none());
        assert!(patch.last_seen.is_none());
        assert_eq!(patch.key_expiry, Some(expiry));
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_route_update_emits_full_peer_delta_with_allowed_ips() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["10.30.0.0/16:*"]}
            ],
            "autoApprovers": {
                "routes": {"10.30.0.0/16": ["router@"]}
            }
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let alice = "a1".repeat(32);
        let router_key = "b1".repeat(32);
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            router_key.clone(),
            policy_record(&router_key, "router", 11, "router", Vec::new()),
        );

        let app = router(state.clone());
        let stream_req = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let _router_body = open_zstd_stream(app.clone(), &router_key).await;
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{alice}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&stream_req).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let first_mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(
            first_mr.peers.is_empty(),
            "router is hidden until it serves an allowed route"
        );

        let update_req = serde_json::json!({
            "Version": 113,
            "OmitPeers": true,
            "Hostinfo": {
                "RoutableIPs": ["10.30.1.0/24"]
            },
        });
        let update_resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{router_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&update_req).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update_resp.status(), StatusCode::OK);
        let raw = to_bytes(update_resp.into_body(), 32 * 1024).await.unwrap();
        assert!(
            raw.is_empty(),
            "non-streaming OmitPeers route updates return an empty lite response"
        );

        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        assert!(mr.peers_removed.is_empty());
        assert_eq!(mr.peers_changed.len(), 1);
        let peer = &mr.peers_changed[0];
        assert_eq!(peer.id, stable_id_from_key(&router_key));
        assert_eq!(peer.name, "router");
        assert_eq!(peer.cap, 113);
        assert!(
            peer.hostinfo
                .routable_ips
                .iter()
                .any(|route| route == "10.30.1.0/24")
        );
        assert!(
            peer.allowed_ips.iter().any(|route| route == "10.30.1.0/24"),
            "approved advertised routes must be sent as route-derived AllowedIPs"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_route_withdraw_emits_full_peer_delta_without_route_allowed_ip() {
        let (state, _dir) = fixture();
        let alice = "c1".repeat(32);
        let router_key = "c2".repeat(32);
        let route = "10.30.1.0/24";
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            router_key.clone(),
            routed_record(&router_key, "router", 11, vec![route.into()]),
        );

        let app = router(state.clone());
        let _router_body = open_zstd_stream(app.clone(), &router_key).await;
        let mut alice_body = open_zstd_stream(app, &alice).await;
        let first = next_zstd_map_response(&mut alice_body).await;
        let router_peer = first
            .peers
            .iter()
            .find(|peer| peer.id == stable_id_from_key(&router_key))
            .expect("router visible before withdrawal");
        assert!(router_peer.allowed_ips.iter().any(|ip| ip == route));
        assert!(
            router_peer
                .hostinfo
                .routable_ips
                .iter()
                .any(|routable| routable == route)
        );

        assert!(state.machines.set_available_routes(&router_key, Vec::new()));

        let mr = next_zstd_map_response(&mut alice_body).await;
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        assert!(mr.peers_removed.is_empty());
        assert_eq!(mr.peers_changed.len(), 1);
        let peer = &mr.peers_changed[0];
        assert_eq!(peer.id, stable_id_from_key(&router_key));
        assert!(!peer.allowed_ips.iter().any(|ip| ip == route));
        assert!(peer.hostinfo.routable_ips.is_empty());

        let stored = state
            .machines
            .get(&router_key)
            .expect("router still registered");
        assert!(stored.available_routes.is_empty());
        assert_eq!(stored.approved_routes, vec![route]);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_route_health_failover_emits_peer_deltas() {
        let (state, _dir) = fixture();
        let alice = "d1".repeat(32);
        let router_a = "d2".repeat(32);
        let router_b = "d3".repeat(32);
        let route = "10.40.0.0/24";

        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        for (node_key, host, octet) in [(&router_a, "router-a", 11), (&router_b, "router-b", 12)] {
            state.machines.upsert(
                node_key.clone(),
                routed_record(node_key, host, octet, vec![route.into()]),
            );
        }

        let app = router(state.clone());
        let _router_a_body = open_zstd_stream(app.clone(), &router_a).await;
        let _router_b_body = open_zstd_stream(app.clone(), &router_b).await;
        let mut alice_body = open_zstd_stream(app, &alice).await;

        let first = next_zstd_map_response(&mut alice_body).await;
        let first_route_holders = first
            .peers
            .iter()
            .filter(|peer| peer.allowed_ips.iter().any(|ip| ip == route))
            .collect::<Vec<_>>();
        assert_eq!(
            first_route_holders.len(),
            1,
            "conflicting subnet route should have one primary owner"
        );
        let unhealthy_id = first_route_holders[0].id;
        let healthy_id = [stable_id_from_key(&router_a), stable_id_from_key(&router_b)]
            .into_iter()
            .find(|id| *id != unhealthy_id)
            .expect("second router id present");

        assert!(
            state
                .machines
                .set_route_candidate_health(unhealthy_id, false)
        );

        let delta = next_zstd_map_response(&mut alice_body).await;
        assert!(delta.peers.is_empty());
        assert!(delta.peers_removed.is_empty());
        assert!(delta.peers_changed_patch.is_empty());

        let old_primary = delta
            .peers_changed
            .iter()
            .find(|peer| peer.id == unhealthy_id)
            .expect("old primary peer delta present");
        assert!(
            !old_primary.allowed_ips.iter().any(|ip| ip == route),
            "unhealthy old primary should lose route-derived AllowedIPs"
        );
        assert!(
            old_primary.primary_routes.is_empty(),
            "unhealthy old primary should lose PrimaryRoutes"
        );

        let new_primary = delta
            .peers_changed
            .iter()
            .find(|peer| peer.id == healthy_id)
            .expect("new primary peer delta present");
        assert!(
            new_primary.allowed_ips.iter().any(|ip| ip == route),
            "healthy router should receive route-derived AllowedIPs"
        );
        assert_eq!(new_primary.primary_routes, vec![route.to_string()]);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_peer_connect_emits_online_peer_change_patch() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let mut b_body = open_zstd_stream(app.clone(), &b).await;
        let first = next_zstd_map_response(&mut b_body).await;
        assert_eq!(first.peers.len(), 1);
        assert_eq!(first.peers[0].id, stable_id_from_key(&a));
        assert_eq!(first.peers[0].online, Some(false));
        assert!(first.peers[0].last_seen.is_some());

        let mut a_body = open_zstd_stream(app, &a).await;
        let delta = next_zstd_map_response(&mut b_body).await;
        assert!(delta.peers.is_empty());
        assert!(delta.peers_changed.is_empty());
        assert!(delta.peers_removed.is_empty());
        assert_eq!(delta.peers_changed_patch.len(), 1);
        let patch = &delta.peers_changed_patch[0];
        assert_eq!(patch.node_id, stable_id_from_key(&a));
        assert_eq!(patch.online, Some(true));
        assert!(patch.last_seen.is_none());
        assert!(patch.endpoints.is_empty());
        assert_eq!(patch.derp_region, 0);

        let a_first = next_zstd_map_response(&mut a_body).await;
        assert_eq!(
            a_first.node.as_ref().and_then(|node| node.online),
            Some(true)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_peer_disconnect_emits_offline_patch_after_grace() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let a_body = open_zstd_stream(app.clone(), &a).await;
        let mut b_body = open_zstd_stream(app, &b).await;
        let first = next_zstd_map_response(&mut b_body).await;
        assert_eq!(first.peers[0].id, stable_id_from_key(&a));
        assert_eq!(first.peers[0].online, Some(true));
        assert!(first.peers[0].last_seen.is_none());

        drop(a_body);
        assert_no_stream_frame(&mut b_body, Duration::from_secs(9)).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let delta = next_zstd_map_response(&mut b_body).await;
        assert!(delta.peers.is_empty());
        assert!(delta.peers_changed.is_empty());
        assert!(delta.peers_removed.is_empty());
        assert_eq!(delta.peers_changed_patch.len(), 1);
        let patch = &delta.peers_changed_patch[0];
        assert_eq!(patch.node_id, stable_id_from_key(&a));
        assert_eq!(patch.online, Some(false));
        assert!(patch.last_seen.is_none());

        let rec = state.machines.get(&a).expect("peer-a retained");
        assert!(rec.last_seen <= chrono::Utc::now());
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_second_connection_does_not_emit_duplicate_online_patch() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state);
        let mut b_body = open_zstd_stream(app.clone(), &b).await;
        let first = next_zstd_map_response(&mut b_body).await;
        assert_eq!(first.peers[0].online, Some(false));

        let a_body_1 = open_zstd_stream(app.clone(), &a).await;
        let online_delta = next_zstd_map_response(&mut b_body).await;
        assert_eq!(online_delta.peers_changed_patch.len(), 1);
        assert_eq!(online_delta.peers_changed_patch[0].online, Some(true));

        let _a_body_2 = open_zstd_stream(app, &a).await;
        assert_no_stream_frame(&mut b_body, Duration::from_secs(1)).await;

        drop(a_body_1);
        assert_no_stream_frame(&mut b_body, Duration::from_secs(9)).await;
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_drop_one_of_two_connections_stays_online_until_last_drop() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state);
        let a_body_1 = open_zstd_stream(app.clone(), &a).await;
        let a_body_2 = open_zstd_stream(app.clone(), &a).await;
        let mut b_body = open_zstd_stream(app, &b).await;
        let first = next_zstd_map_response(&mut b_body).await;
        assert_eq!(first.peers[0].online, Some(true));

        drop(a_body_2);
        assert_no_stream_frame(&mut b_body, Duration::from_secs(10)).await;

        drop(a_body_1);
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;
        let delta = next_zstd_map_response(&mut b_body).await;
        assert_eq!(delta.peers_changed_patch.len(), 1);
        assert_eq!(delta.peers_changed_patch[0].online, Some(false));
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_endpoint_update_uses_peer_changed_patch() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let mut peer_a = MachineRecord::new_at(
            chrono::Utc::now(),
            a.clone(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "u".into(),
            "peer-a".into(),
            Ipv4Addr::new(100, 64, 0, 10),
            false,
        );
        peer_a.disco_key = Some(format!("discokey:{}", "1a".repeat(32)));
        peer_a.endpoints = vec!["10.0.0.10:41641".into()];
        state.machines.upsert(a.clone(), peer_a);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let stream_req = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{b}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&stream_req).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let first_mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].endpoints, vec!["10.0.0.10:41641"]);

        let new_endpoints = vec!["10.0.0.10:41641".to_string(), "10.0.0.20:41641".to_string()];
        let update_req = serde_json::json!({
            "Version": 113,
            "OmitPeers": true,
            "DiscoKey": format!("discokey:{}", "1a".repeat(32)),
            "Endpoints": &new_endpoints,
        });
        let update_resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&update_req).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update_resp.status(), StatusCode::OK);

        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());
        assert!(mr.peers_removed.is_empty());
        assert_eq!(mr.peers_changed_patch.len(), 1);
        let patch = &mr.peers_changed_patch[0];
        assert_eq!(patch.node_id, stable_id_from_key(&a));
        assert_eq!(patch.endpoints, new_endpoints);
        assert!(patch.disco_key.is_none());
        assert!(patch.online.is_none());
        assert!(patch.last_seen.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_disco_key_update_uses_full_peer_delta() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let old_disco = format!("discokey:{}", "1a".repeat(32));
        let new_disco = format!("discokey:{}", "2a".repeat(32));
        let mut peer_a = MachineRecord::new_at(
            chrono::Utc::now(),
            a.clone(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "u".into(),
            "peer-a".into(),
            Ipv4Addr::new(100, 64, 0, 10),
            false,
        );
        peer_a.disco_key = Some(old_disco.clone());
        state.machines.upsert(a.clone(), peer_a);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let stream_req = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{b}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&stream_req).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let first_mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(
            first_mr.peers[0].disco_key.as_deref(),
            Some(old_disco.as_str())
        );

        let update_req = serde_json::json!({
            "Version": 113,
            "OmitPeers": true,
            "DiscoKey": &new_disco,
        });
        let update_resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&update_req).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update_resp.status(), StatusCode::OK);
        assert_eq!(
            state
                .machines
                .get(&a)
                .expect("peer-a still registered")
                .disco_key
                .as_deref(),
            Some(new_disco.as_str())
        );

        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        assert!(mr.peers_removed.is_empty());
        assert_eq!(mr.peers_changed.len(), 1);
        let peer = &mr.peers_changed[0];
        assert_eq!(peer.id, stable_id_from_key(&a));
        assert_eq!(peer.disco_key.as_deref(), Some(new_disco.as_str()));
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_derp_update_uses_peer_changed_patch() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let mut peer_a = MachineRecord::new_at(
            chrono::Utc::now(),
            a.clone(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "u".into(),
            "peer-a".into(),
            Ipv4Addr::new(100, 64, 0, 10),
            false,
        );
        peer_a.home_derp = 1;
        state.machines.upsert(a.clone(), peer_a);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let stream_req = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{b}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&stream_req).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let first_mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].home_derp, 1);
        assert_eq!(
            first_mr.peers[0]
                .hostinfo
                .net_info
                .as_ref()
                .map(|net_info| net_info.preferred_derp),
            Some(1)
        );

        let update_req = serde_json::json!({
            "Version": 113,
            "OmitPeers": true,
            "Hostinfo": {
                "NetInfo": {
                    "PreferredDERP": 7
                }
            },
        });
        let update_resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&update_req).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update_resp.status(), StatusCode::OK);
        assert_eq!(
            state
                .machines
                .get(&a)
                .expect("peer-a still registered")
                .home_derp,
            7
        );

        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());
        assert!(mr.peers_removed.is_empty());
        assert_eq!(mr.peers_changed_patch.len(), 1);
        let patch = &mr.peers_changed_patch[0];
        assert_eq!(patch.node_id, stable_id_from_key(&a));
        assert!(patch.endpoints.is_empty());
        assert_eq!(patch.derp_region, 7);
        assert!(patch.disco_key.is_none());
        assert!(patch.online.is_none());
        assert!(patch.last_seen.is_none());
    }

    /// Stream:true: the response body emits the first framed
    /// MapResponse chunk immediately, then a keepalive frame
    /// (`zstd({"KeepAlive":true})`) after [`MAP_KEEPALIVE_INTERVAL`].
    /// We drive `tokio::time::pause` so the test doesn't wait 30s.
    #[tokio::test(start_paused = true)]
    async fn stream_true_emits_keepalive() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let public_app = public_router(state);
        let req_body = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(mr.peers.len(), 1);

        // Advance virtual time past one keepalive interval and confirm
        // the next chunk decodes to the canonical `{"KeepAlive":true}`
        // payload (matches upstream `justKeepAliveStr`).
        tokio::time::advance(MAP_KEEPALIVE_INTERVAL + Duration::from_millis(1)).await;
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        assert_eq!(&decoded[..], br#"{"KeepAlive":true}"#);

        let metrics_resp = public_app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let metrics = to_bytes(metrics_resp.into_body(), 32 * 1024).await.unwrap();
        let metrics = String::from_utf8(metrics.to_vec()).unwrap();
        assert!(
            metrics
                .contains("headscale_mapresponse_sent_total{status=\"ok\",type=\"keepalive\"} 1\n")
        );
    }

    /// First MapResponse chunk must carry the upstream-required `Node`
    /// field with a non-empty `User`. Wall 5 regression guard.
    #[tokio::test]
    async fn stream_true_first_chunk_carries_node_with_user() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);

        let app = router(state);
        let req_body = serde_json::json!({ "Stream": true, "Version": 133, "Compress": "zstd" });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        // Inspect raw JSON: upstream decoder calls
        // `json.Unmarshal(b, v)` and then asserts `resp.Node != nil`.
        // We assert the field exists AND carries `User`/`StableID`.
        let json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        let node = json.get("Node").expect("Node field present");
        assert!(
            node.get("User")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
                > 0
        );
        assert!(
            node.get("StableID")
                .and_then(|s| s.as_str())
                .unwrap_or("")
                .starts_with('n')
        );
        assert!(node.get("Name").is_some());
    }

    /// Wall 7 round-trip: a MapRequest carrying `DiscoKey`,
    /// `Endpoints`, and `Hostinfo.NetInfo.PreferredDERP` for peer-a
    /// must persist into `MachineRecord` and then fan back out on
    /// peer-b's view of peer-a in the MapResponse.Peers list. Without
    /// the disco/endpoint fields, `wgengine.Reconfig` on peer-b runs at
    /// `0/0 peers`; without HomeDERP/NetInfo the peer lacks a DERP home
    /// region for relay contact.
    #[tokio::test]
    async fn map_response_round_trips_disco_key_and_endpoints() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let disco_a = format!("discokey:{}", "1a".repeat(32));
        let endpoints_a = vec!["10.0.0.10:41641".to_string(), "[fe80::1]:41641".to_string()];
        let home_derp_a = 901;
        let ssh_host_keys_a = vec!["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIpeerakey".to_string()];

        // Peer-a posts a /map call with DiscoKey + Endpoints + NetInfo set.
        let req_a = serde_json::json!({
            "Version": 113,
            "DiscoKey": &disco_a,
            "Endpoints": &endpoints_a,
            "Hostinfo": {
                "sshHostKeys": &ssh_host_keys_a,
                "NetInfo": {
                    "PreferredDERP": home_derp_a
                }
            },
        });
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&req_a).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The record on the registry must now carry the fields.
        let rec_a = state.machines.get(&a).expect("peer-a still registered");
        assert_eq!(rec_a.disco_key.as_deref(), Some(disco_a.as_str()));
        assert_eq!(rec_a.endpoints, endpoints_a);
        assert_eq!(rec_a.home_derp, home_derp_a);
        assert_eq!(rec_a.ssh_host_keys, ssh_host_keys_a);

        // Peer-b polls /map and must see peer-a's DiscoKey, Endpoints,
        // HomeDERP, Hostinfo.NetInfo, and Tailscale SSH host keys on its
        // MapNode entry. Pins both the wire-tag spelling and the payload
        // value.
        let req_b = serde_json::json!({ "Version": 113 });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{b}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(serde_json::to_vec(&req_b).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let raw_str = std::str::from_utf8(&raw).unwrap();
        assert!(
            raw_str.contains("\"DiscoKey\""),
            "DiscoKey tag present on the wire: {raw_str}"
        );
        assert!(
            raw_str.contains("\"Endpoints\""),
            "Endpoints tag present on the wire: {raw_str}"
        );
        assert!(
            raw_str.contains("\"HomeDERP\""),
            "HomeDERP tag present on the wire: {raw_str}"
        );
        assert!(
            raw_str.contains("\"PreferredDERP\""),
            "PreferredDERP tag present on the wire: {raw_str}"
        );
        assert!(
            raw_str.contains("\"sshHostKeys\""),
            "sshHostKeys tag present on the wire: {raw_str}"
        );
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(mr.peers.len(), 1);
        let peer_a = &mr.peers[0];
        assert_eq!(peer_a.disco_key.as_deref(), Some(disco_a.as_str()));
        assert_eq!(peer_a.endpoints, endpoints_a);
        assert_eq!(peer_a.home_derp, home_derp_a);
        assert_eq!(
            peer_a.legacy_derp_string,
            format!("127.3.3.40:{home_derp_a}")
        );
        assert_eq!(
            peer_a
                .hostinfo
                .net_info
                .as_ref()
                .map(|net_info| net_info.preferred_derp),
            Some(home_derp_a)
        );
        assert_eq!(peer_a.hostinfo.ssh_host_keys, ssh_host_keys_a);
    }

    #[tokio::test]
    async fn map_response_includes_compiled_ssh_policy_for_target_node() {
        let (state, _dir) = fixture();
        let server = "bb".repeat(32);
        let admin = "cc".repeat(32);

        let mut server_rec = MachineRecord::new_at(
            chrono::Utc::now(),
            server.clone(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "alice".into(),
            "server".into(),
            Ipv4Addr::new(100, 64, 0, 11),
            false,
        );
        server_rec.forced_tags = vec!["tag:server".into()];
        state.machines.upsert(server.clone(), server_rec);

        state.machines.upsert(
            admin.clone(),
            MachineRecord::new_at(
                chrono::Utc::now(),
                admin,
                TEST_MACHINE_KEY_HEX.to_string(),
                "bob".into(),
                "admin".into(),
                Ipv4Addr::new(100, 64, 0, 12),
                false,
            ),
        );

        let raw_policy = r#"{
            "groups": {"group:admins": ["bob@"]},
            "tagOwners": {"tag:server": ["alice@"]},
            "acls": [],
            "ssh": [{
                "action": "check",
                "checkPeriod": "24h",
                "src": ["group:admins"],
                "dst": ["tag:server"],
                "users": ["autogroup:nonroot", "root"]
            }]
        }"#;
        let doc = crate::policy::parse_hujson_policy(raw_policy).unwrap();
        state.policy.set(doc, raw_policy.to_string());

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{server}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let raw_str = std::str::from_utf8(&raw).unwrap();
        assert!(
            raw_str.contains("\"SSHPolicy\""),
            "SSHPolicy field present on the wire: {raw_str}"
        );
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let ssh = mr.ssh_policy.expect("SSH policy present");
        assert_eq!(ssh.rules.len(), 1);
        assert_eq!(ssh.rules[0].principals[0].node_ip, "100.64.0.12");
        assert_eq!(ssh.rules[0].ssh_users["*"], "=");
        assert_eq!(ssh.rules[0].ssh_users["root"], "root");
        assert!(!ssh.rules[0].action.accept);
        assert_eq!(ssh.rules[0].action.session_duration, 0);
        assert!(
            ssh.rules[0]
                .action
                .hold_and_delegate
                .contains("/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID")
        );
    }

    #[tokio::test]
    async fn stream_policy_update_uses_absolute_ssh_delegate_url_when_configured() {
        let (mut state, _dir) = fixture();
        state.public_control_url = Some("https://control.example".into());
        let server = "ba".repeat(32);
        let admin = "ca".repeat(32);

        let mut server_rec = MachineRecord::new_at(
            chrono::Utc::now(),
            server.clone(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "alice".into(),
            "server".into(),
            Ipv4Addr::new(100, 64, 0, 11),
            false,
        );
        server_rec.forced_tags = vec!["tag:server".into()];
        state.machines.upsert(server.clone(), server_rec);
        state.machines.upsert(
            admin,
            MachineRecord::new_at(
                chrono::Utc::now(),
                "ca".repeat(32),
                TEST_MACHINE_KEY_HEX.to_string(),
                "bob".into(),
                "admin".into(),
                Ipv4Addr::new(100, 64, 0, 12),
                false,
            ),
        );

        let app = router(state.clone());
        let req_body = serde_json::json!({ "Stream": true, "Version": 113, "Compress": "zstd" });
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{server}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&req_body).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let mut body = resp.into_body();
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let first = decode_framed(&frame.into_data().unwrap());
        let first_mr: MapResponse = serde_json::from_slice(&first).unwrap();
        assert!(first_mr.ssh_policy.is_none());

        let raw_policy = r#"{
            "groups": {"group:admins": ["bob@"]},
            "tagOwners": {"tag:server": ["alice@"]},
            "acls": [],
            "ssh": [{
                "action": "check",
                "src": ["group:admins"],
                "dst": ["tag:server"],
                "users": ["root"]
            }]
        }"#;
        let policy_update = tokio::spawn({
            let policy = state.policy.clone();
            let raw_policy = raw_policy.to_string();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let doc = crate::policy::parse_hujson_policy(&raw_policy).unwrap();
                policy.set(doc, raw_policy);
            }
        });

        let frame = tokio::time::timeout(
            Duration::from_secs(1),
            http_body_util::BodyExt::frame(&mut body),
        )
        .await
        .expect("policy update map chunk")
        .unwrap()
        .unwrap();
        policy_update.await.expect("policy update task");
        let decoded = decode_framed(&frame.into_data().unwrap());
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        let ssh = mr
            .ssh_policy
            .expect("SSH policy present after policy update");
        assert_eq!(
            ssh.rules[0].action.hold_and_delegate,
            "https://control.example/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER"
        );
    }

    #[tokio::test]
    async fn map_response_includes_default_node_cap_map() {
        let (state, _dir) = fixture();
        let node_key = "dc".repeat(32);
        state.machines.upsert(
            node_key.clone(),
            MachineRecord::new_at(
                chrono::Utc::now(),
                node_key.clone(),
                TEST_MACHINE_KEY_HEX.to_string(),
                "alice".into(),
                "server".into(),
                Ipv4Addr::new(100, 64, 0, 12),
                false,
            ),
        );
        let peer_key = "de".repeat(32);
        insert_peer(&state, &peer_key, "peer", 14);

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let node = mr.node.as_ref().expect("own node present");
        assert_default_cap_map(node);
    }

    #[tokio::test]
    async fn map_response_removes_file_sharing_cap_when_taildrop_is_disabled() {
        let (mut state, _dir) = fixture();
        let mut runtime_config = crate::tailscale_wire::RuntimeConfigSnapshot::default();
        runtime_config.taildrop.enabled = false;
        state.runtime_config = Arc::new(runtime_config);

        let node_key = "d1".repeat(32);
        let mut rec = MachineRecord::new_at(
            chrono::Utc::now(),
            node_key.clone(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "alice".into(),
            "server".into(),
            Ipv4Addr::new(100, 64, 0, 13),
            false,
        );
        rec.forced_tags = vec!["tag:server".into()];
        state.machines.upsert(node_key.clone(), rec);

        let peer_key = "d2".repeat(32);
        insert_peer(&state, &peer_key, "peer", 14);

        let raw_policy = format!(
            r#"
            version = 1

            [tag_owners]
            "tag:server" = ["alice@"]

            [[node_attrs]]
            target = ["tag:server"]
            attr = ["{CAPABILITY_FILE_SHARING}"]
        "#
        );
        let doc = crate::policy::PolicyDoc::from_toml(&raw_policy).unwrap();
        state.policy.set(doc, raw_policy);

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();

        let node = mr.node.as_ref().expect("own node present");
        assert!(node.cap_map.contains_key(CAPABILITY_ADMIN));
        assert!(node.cap_map.contains_key(CAPABILITY_SSH));
        assert!(!node.cap_map.contains_key(CAPABILITY_FILE_SHARING));
    }

    #[tokio::test]
    async fn map_response_applies_node_attrs_to_cap_map_additively() {
        let (state, _dir) = fixture();
        let node_key = "dd".repeat(32);
        let mut rec = MachineRecord::new_at(
            chrono::Utc::now(),
            node_key.clone(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "alice".into(),
            "server".into(),
            Ipv4Addr::new(100, 64, 0, 13),
            false,
        );
        rec.forced_tags = vec!["tag:server".into()];
        state.machines.upsert(node_key.clone(), rec);
        let peer_key = "df".repeat(32);
        insert_peer(&state, &peer_key, "peer", 14);

        let raw_policy = r#"
            version = 1

            [tag_owners]
            "tag:server" = ["alice@"]

            [[node_attrs]]
            target = ["tag:server"]
            attr = ["funnel", "ssh"]
        "#;
        let doc = crate::policy::PolicyDoc::from_toml(raw_policy).unwrap();
        state.policy.set(doc, raw_policy.to_string());

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let node = mr.node.as_ref().expect("own node present");
        assert_default_cap_map(node);
        assert!(node.cap_map.contains_key("funnel"));
        assert!(node.cap_map.contains_key("ssh"));
    }

    #[tokio::test]
    async fn map_response_applies_randomize_client_port_to_cap_map() {
        let (state, _dir) = fixture();
        let node_key = "de".repeat(32);
        let rec = MachineRecord::new_at(
            chrono::Utc::now(),
            node_key.clone(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "alice".into(),
            "laptop".into(),
            Ipv4Addr::new(100, 64, 0, 15),
            false,
        );
        state.machines.upsert(node_key.clone(), rec);
        let peer_key = "e0".repeat(32);
        insert_peer(&state, &peer_key, "peer", 16);

        let raw_policy = r"
            version = 1
            randomizeClientPort = true
        ";
        let doc = crate::policy::PolicyDoc::from_toml(raw_policy).unwrap();
        state.policy.set(doc, raw_policy.to_string());

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let node = mr.node.as_ref().expect("own node present");
        assert_default_cap_map(node);
        assert!(node.cap_map.contains_key("randomize-client-port"));
    }

    fn framed_chunk_fixture() -> MapResponse {
        MapResponse {
            node: Some(MapNode {
                id: 42,
                stable_id: "n42".into(),
                name: "peer-a.headscale.test".into(),
                user: 7,
                key: format!("nodekey:{}", "aa".repeat(32)),
                machine: None,
                addresses: vec!["100.64.0.10/32".into()],
                allowed_ips: vec!["100.64.0.10/32".into()],
                primary_routes: Vec::new(),
                hostinfo: crate::tailscale_wire::wire::HostInfo::default(),
                created: None,
                key_expiry: None,
                cap: 0,
                tags: Vec::new(),
                last_seen: None,
                online: None,
                machine_authorized: true,
                capabilities: Vec::new(),
                cap_map: std::collections::BTreeMap::new(),
                expired: false,
                home_derp: 0,
                disco_key: None,
                endpoints: Vec::new(),
                ..MapNode::default()
            }),
            peers: vec![],
            user_profiles: Vec::new(),
            dns_config: Some(DnsConfig::default()),
            derp_map: Some(DerpMap::default()),
            domain: "headscale.test".into(),
            keep_alive: true,
            packet_filter: allow_all_packet_filter(),
            ssh_policy: None,
            ..MapResponse::default()
        }
    }

    /// Compatibility sample: a hand-built MapResponse, run through
    /// `build_framed_chunk`, must round-trip through the upstream
    /// decoding rule when `MapRequest.Compress == "zstd"`:
    /// `[u32 LE size][zstd(JSON)]` -> `Node` present.
    #[test]
    fn framed_chunk_matches_upstream_zstd_decoder_shape() {
        let mr = framed_chunk_fixture();
        let bytes =
            build_framed_chunk(&mr, MapFrameCompression::Zstd).expect("framed chunk encodes");
        // Decode the way upstream does.
        let size = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(bytes.len(), 4 + size);
        let json_bytes =
            zstd::bulk::decompress(&bytes[4..], 16 * 1024 * 1024).expect("decompress ok");
        let v: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert!(
            v.get("Node").is_some(),
            "Node field present after framed encode"
        );
        assert_eq!(
            v.get("Node")
                .unwrap()
                .get("User")
                .and_then(serde_json::Value::as_u64),
            Some(7)
        );
    }

    /// If `MapRequest.Compress` is absent or unknown, headscale-go
    /// still frames the chunk but leaves the JSON body uncompressed.
    #[test]
    fn framed_chunk_without_compression_is_plain_json() {
        let mr = framed_chunk_fixture();
        let bytes =
            build_framed_chunk(&mr, MapFrameCompression::None).expect("framed chunk encodes");
        let body = framed_body(&bytes);
        let v: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert!(
            v.get("Node").is_some(),
            "Node field present after framed encode"
        );
        assert!(
            zstd::bulk::decompress(body, 16 * 1024 * 1024).is_err(),
            "plain framed body should not be zstd-compressed"
        );
    }
}
