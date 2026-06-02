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

use super::register::{
    CAPABILITY_DEFAULT_AUTO_UPDATE, CAPABILITY_FILE_SHARING, record_to_map_node,
};
use super::routes::{
    active_exit_routes, auto_approved_routes_for_node, normalize_advertised_routes,
};
use super::wire::{
    DebugConfig, DnsConfig, FilterRule, HostInfo, MapNode, MapRequest, MapResponse, NetInfo,
    NetPortRange, PeerChange, PingRequest, PortRange, UserProfile, ZERO_NODE_KEY_HEX,
    is_auto_derived_given_name, is_supported_capability_version, stable_id_from_key,
    strip_key_prefix, unsupported_client_error,
};
use super::{
    MachineRecord, MapChange, MapChangeReason, MapResponseDebugStore, MapResponseDebugType,
    WireState,
};

use crate::dns::{DnsRequester, DnsStore, MachineDnsRecord};
use crate::policy::{NodeView, PacketFilterNode, PeerMapNode, PolicyStore, SshPolicyNode};

const MAP_NODE_NOT_FOUND_ERROR: &str = "node not found";
const MAP_NODE_KEY_MISMATCH_ERROR: &str =
    "node key in request does not match the one associated with this machine key";
const NODE_ATTR_DISABLE_IPV4: &str = "disable-ipv4";
const NODE_ATTR_SUGGEST_EXIT_NODE: &str = "suggest-exit-node";

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

fn hostinfo_preferred_derp(hostinfo: &HostInfo) -> i32 {
    hostinfo
        .net_info
        .as_ref()
        .map_or(0, |net_info| net_info.preferred_derp)
}

fn clear_preferred_derp_for_compare(hostinfo: &mut HostInfo) {
    if let Some(net_info) = hostinfo.net_info.as_mut() {
        net_info.preferred_derp = 0;
        if *net_info == NetInfo::default() {
            hostinfo.net_info = None;
        }
    }
}

fn hostinfo_change_is_only_preferred_derp(previous: &HostInfo, current: &HostInfo) -> bool {
    let previous_derp = hostinfo_preferred_derp(previous);
    let current_derp = hostinfo_preferred_derp(current);
    if current_derp == 0 || previous_derp == current_derp {
        return false;
    }

    let mut previous = previous.clone();
    let mut current = current.clone();
    clear_preferred_derp_for_compare(&mut previous);
    clear_preferred_derp_for_compare(&mut current);
    previous == current
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
        let addrs = rec.address_strings();
        let view = NodeView {
            addr: primary_ip.as_deref(),
            addrs: &addrs,
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

fn policy_auto_approval_updates_for_snapshot(
    policy: &PolicyStore,
    snapshot: &HashMap<String, MachineRecord>,
) -> Result<Vec<(String, Vec<String>)>, String> {
    let mut updates = Vec::new();
    for (node_key, rec) in snapshot {
        let addr = rec.primary_addr_string().unwrap_or_default();
        let user = (!rec.user.is_empty()).then_some(rec.user.as_str());
        let approved = auto_approved_routes_for_node(
            policy,
            &addr,
            user,
            &rec.forced_tags,
            &rec.approved_routes,
            &rec.available_routes,
        )?;
        if approved != rec.approved_routes {
            updates.push((node_key.clone(), approved));
        }
    }
    Ok(updates)
}

fn apply_policy_auto_approvals_for_registry(
    machines: &Arc<crate::tailscale_wire::MachineRegistry>,
    policy: &PolicyStore,
) -> Result<usize, String> {
    let updates = policy_auto_approval_updates_for_snapshot(policy, &machines.snapshot())?;
    if updates.is_empty() {
        return Ok(0);
    }

    let (changed, missing) = machines.set_approved_routes_many(updates);
    if let Some(node_key) = missing.into_iter().next() {
        return Err(format!(
            "node {node_key} disappeared while applying policy auto-approvals"
        ));
    }
    Ok(changed)
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
            addrs: rec.address_strings(),
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
            user_id: rec.user_id,
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
    let global_primary = selected_primary.clone();
    let mut allowed_routes = selected_primary.clone();
    allowed_routes.extend(exit_routes.get(peer_node_key).cloned().unwrap_or_default());

    let nodes = peer_map_nodes_from_snapshot(snapshot, served_routes);
    let viewer_id = node_id_for_key(snapshot, self_node_key);
    let peer_id = node_id_for_key(snapshot, peer_node_key);

    let route_allowed_by_policy = |route: &String| {
        route_is_exit_default(route)
            || policy
                .can_access_route_for_peer(&nodes, viewer_id, peer_id, route)
                .unwrap_or(true)
    };
    selected_primary.retain(route_allowed_by_policy);
    allowed_routes.retain(route_allowed_by_policy);

    if let Some(via) = policy.via_routes_for_peer(&nodes, viewer_id, peer_id) {
        selected_primary.retain(|route| !via.exclude.contains(route));
        allowed_routes.retain(|route| !via.exclude.contains(route));
        for route in via.include {
            let is_global_primary = global_primary.contains(&route);
            if is_global_primary && !selected_primary.contains(&route) {
                selected_primary.push(route.clone());
            }
            if !allowed_routes.contains(&route) {
                let use_primary = via.use_primary.contains(&route);
                if is_global_primary || !use_primary {
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
    auto_update_enabled: bool,
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
    apply_runtime_caps_to_map_node(&mut own_node, taildrop_enabled, auto_update_enabled);
    Some(own_node)
}

fn self_map_node_for_registry(
    machines: &crate::tailscale_wire::MachineRegistry,
    policy: &PolicyStore,
    dns: &DnsStore,
    self_node_key: &str,
    cap_version: u32,
    taildrop_enabled: bool,
    auto_update_enabled: bool,
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
        auto_update_enabled,
    )
}

fn visible_peer_state_for_registry(
    machines: &crate::tailscale_wire::MachineRegistry,
    policy: &PolicyStore,
    dns: &DnsStore,
    self_node_key: &str,
    cap_version: u32,
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

fn map_nodes_equal_ignoring_last_seen(previous: &MapNode, current: &MapNode) -> bool {
    let mut current_normalized = current.clone();
    current_normalized.last_seen = previous.last_seen;
    map_node_json_value(previous) == map_node_json_value(&current_normalized)
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
    let key_expiry_changed = previous.key_expiry != current.key_expiry;
    if !endpoints_changed && !derp_changed && !online_changed && !key_expiry_changed {
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
        last_seen: None,
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
            apply_peer_cap_map_to_map_node(
                &mut node,
                rec,
                policy,
                exit_routes
                    .get(node_key)
                    .is_some_and(|routes| !routes.is_empty()),
            );
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
    let attrs = node_attrs_for_record(rec, policy);
    apply_address_shape_attrs_to_map_node(node, rec, &attrs);
    apply_self_cap_map_attrs_to_map_node(node, &attrs);
}

fn node_attrs_for_record(rec: &super::MachineRecord, policy: &PolicyStore) -> Vec<String> {
    let addr = rec.primary_addr_string();
    let addrs = rec.address_strings();
    let view = NodeView {
        addr: addr.as_deref(),
        addrs: &addrs,
        user: Some(&rec.user),
        tags: &rec.forced_tags,
    };
    policy.node_attrs_for(&view)
}

fn has_node_attr(attrs: &[String], attr: &str) -> bool {
    attrs.iter().any(|candidate| candidate == attr)
}

fn apply_self_cap_map_attrs_to_map_node(node: &mut MapNode, attrs: &[String]) {
    for attr in attrs {
        node.cap_map.entry(attr.clone()).or_default();
    }
}

fn apply_address_shape_attrs_to_map_node(
    node: &mut MapNode,
    rec: &super::MachineRecord,
    attrs: &[String],
) {
    if !has_node_attr(attrs, NODE_ATTR_DISABLE_IPV4) {
        return;
    }
    let Some(ipv4) = rec.ipv4 else {
        return;
    };
    let own_ipv4_prefix = format!("{ipv4}/32");
    node.addresses.retain(|addr| addr != &own_ipv4_prefix);
    node.allowed_ips.retain(|addr| addr != &own_ipv4_prefix);
}

fn apply_peer_cap_map_to_map_node(
    node: &mut MapNode,
    rec: &super::MachineRecord,
    policy: &PolicyStore,
    is_exit_node: bool,
) {
    let attrs = node_attrs_for_record(rec, policy);
    apply_address_shape_attrs_to_map_node(node, rec, &attrs);
    node.cap_map.clear();
    if !is_exit_node {
        return;
    }

    if has_node_attr(&attrs, NODE_ATTR_SUGGEST_EXIT_NODE) {
        node.cap_map
            .insert(NODE_ATTR_SUGGEST_EXIT_NODE.to_string(), Vec::new());
    }
}

fn apply_runtime_caps_to_map_node(
    node: &mut MapNode,
    taildrop_enabled: bool,
    auto_update_enabled: bool,
) {
    if !taildrop_enabled {
        node.cap_map.remove(CAPABILITY_FILE_SHARING);
    }
    node.cap_map.insert(
        CAPABILITY_DEFAULT_AUTO_UPDATE.to_string(),
        vec![serde_json::Value::Bool(auto_update_enabled)],
    );
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
            ..NetPortRange::default()
        }],
        ip_proto: Vec::new(),
        ..FilterRule::default()
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
            user_id: rec.user_id,
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

    // P1 lifecycle: stamp `last_seen` on every /map arrival without
    // waking long-poll streams. This mirrors upstream's quiet timestamp
    // bookkeeping: only peer-visible state changes should produce map
    // churn. The COW update is O(n) in registry size; the perf concern
    // is documented on `MachineRegistry::touch_last_seen` itself.
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
    let mut record_change_reason = MapChangeReason::NodeUpdated;
    if let Some(dk) = req.disco_key.as_ref().filter(|s| !s.is_empty())
        && own.disco_key.as_deref() != Some(dk.as_str())
    {
        own.disco_key = Some(dk.clone());
        record_changed = true;
        record_change_reason = MapChangeReason::EndpointDerpUpdate;
    }
    if let Some(eps) = req.endpoints.as_ref().filter(|v| !v.is_empty())
        && &own.endpoints != eps
    {
        own.endpoints = eps.clone();
        record_changed = true;
        record_change_reason = MapChangeReason::EndpointDerpUpdate;
    }
    if let Some(hostinfo) = req.hostinfo.as_ref() {
        let announced_routes = match normalize_advertised_routes(&hostinfo.routable_ips) {
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
        let previous_hostinfo = own.host_info_for_node();
        let previous_raw_hostname = previous_hostinfo.hostname.clone();
        let auto_derived_name = is_auto_derived_given_name(&own.hostname, &previous_raw_hostname);
        let mut hostinfo = host_info_for_map_update(&previous_hostinfo, hostinfo);
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
        if previous_hostinfo != hostinfo {
            let only_preferred_derp_changed =
                hostinfo_change_is_only_preferred_derp(&previous_hostinfo, &hostinfo);
            let raw_hostname = hostinfo.hostname.clone();
            own.replace_host_info(hostinfo);
            if auto_derived_name && !raw_hostname.is_empty() {
                own.hostname =
                    state
                        .machines
                        .resolve_auto_given_name(&node_key_hex, &raw_hostname, None);
            }
            record_changed = true;
            record_change_reason = if only_preferred_derp_changed {
                MapChangeReason::EndpointDerpUpdate
            } else {
                // Full peer-node delta, not a full/config map refresh.
                MapChangeReason::NodeUpdated
            };
        }
        if own.approved_routes != approved_routes {
            own.approved_routes = approved_routes;
            record_changed = true;
            record_change_reason = MapChangeReason::PolicyChange;
        }
    }
    // headscale-go updates node state before Connect, but dispatches
    // map changes only after the stream is connected. With a durable
    // registration store there is an await between those steps, so
    // Stream:true updates must not wake peers with an offline route
    // snapshot while persistence is still in flight.
    let mut deferred_stream_change = None;
    if record_changed {
        let node_id = own.stable_node_id_for_key(&node_key_hex);
        if req.stream {
            state
                .machines
                .upsert_quiet(node_key_hex.clone(), own.clone());
            deferred_stream_change = Some((record_change_reason, node_id));
        } else {
            state.machines.upsert_with_reason(
                node_key_hex.clone(),
                own.clone(),
                Some(record_change_reason),
            );
        }
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
            let saved_node_id = saved
                .record
                .stable_node_id_for_key(&saved.record.node_key_hex);
            if let Some(old_node_key_hex) = saved.replaced_node_key_hex.as_deref() {
                if req.stream {
                    state.machines.replace_node_key_quiet(
                        old_node_key_hex,
                        saved.record.node_key_hex.clone(),
                        saved.record,
                    );
                } else {
                    state.machines.replace_node_key(
                        old_node_key_hex,
                        saved.record.node_key_hex.clone(),
                        saved.record,
                    );
                }
            } else {
                if req.stream {
                    state
                        .machines
                        .upsert_quiet(saved.record.node_key_hex.clone(), saved.record);
                } else {
                    state
                        .machines
                        .upsert(saved.record.node_key_hex.clone(), saved.record);
                }
            }
            if req.stream {
                deferred_stream_change = Some((record_change_reason, saved_node_id));
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
    if let Some((reason, node_id)) = deferred_stream_change {
        state.machines.wake_node_change(reason, node_id);
    }

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
        state.runtime_config.auto_update.enabled,
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
            disable_log_tail: !state.runtime_config.log_tail.enabled,
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
        // Registry changes are delivered through the tick-published map
        // batch watch when the batcher is running. We still subscribe to
        // the generation counter for self-deletion/cancellation awareness
        // and as a compatibility fallback for embedders that have not
        // started the batch task.
        let machines = state.machines.clone();
        let gen_rx = state.machines.subscribe_gen();
        let last_seen_generation = *gen_rx.borrow();
        let map_batch_rx = state.machines.subscribe_map_batch_events();
        let policy = state.policy.clone();
        let self_node_key = node_key_hex.clone();
        let cap_version = req.version;
        let taildrop_enabled = state.runtime_config.taildrop.enabled;
        let auto_update_enabled = state.runtime_config.auto_update.enabled;
        let disable_log_tail = !state.runtime_config.log_tail.enabled;
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
                last_seen_generation,
                map_batch_rx,
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
                mut last_seen_generation,
                mut map_batch_rx,
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
                            last_seen_generation,
                            map_batch_rx,
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
                            &machines,
                            request,
                            compression,
                            &mapresponse_debug,
                            self_node_id,
                        )),
                        (
                            None,
                            machines,
                            gen_rx,
                            last_seen_generation,
                            map_batch_rx,
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
                    res = map_batch_rx.recv() => {
                        match res {
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                Some((build_keepalive_chunk(compression), last_peer_state.clone(), last_self_node.clone()))
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                Some((
                                    rebuild_map_chunk(
                                        &machines,
                                        &policy,
                                        &self_node_key,
                                        &machines_derp_map,
                                        &dns,
                                        cap_version,
                                        taildrop_enabled,
                                        auto_update_enabled,
                                        disable_log_tail,
                                        compression,
                                        Some(&last_peer_state),
                                        "full",
                                        &mapresponse_debug,
                                        MapResponseDebugType::Change,
                                        public_control_url.as_deref().unwrap_or(""),
                                    ),
                                    visible_peer_state_for_registry(&machines, &policy, &dns, &self_node_key, cap_version),
                                    self_map_node_for_registry(&machines, &policy, &dns, &self_node_key, cap_version, taildrop_enabled, auto_update_enabled),
                                ))
                            }
                            Ok(batch) => {
                            let changes = batch.get(&self_node_id).cloned().unwrap_or_default();
                            rebuild_map_batch_chunk(
                                &machines,
                                &policy,
                                &self_node_key,
                                &machines_derp_map,
                                &dns,
                                cap_version,
                                taildrop_enabled,
                                auto_update_enabled,
                                disable_log_tail,
                                compression,
                                last_self_node.as_ref(),
                                &last_peer_state,
                                &initial_peer_ids,
                                &mapresponse_debug,
                                public_control_url.as_deref().unwrap_or(""),
                                &changes,
                            )
                            }
                        }
                    }
                    res = gen_rx.changed() => {
                        // `Err` only happens if every sender has been
                        // dropped — would mean the entire registry's
                        // gone, in which case we degrade to a
                        // keepalive frame and let the next iteration
                        // (or stream end) handle teardown.
                        if res.is_err() {
                            Some((build_keepalive_chunk(compression), last_peer_state.clone(), last_self_node.clone()))
                        } else if machines.get(&self_node_key).is_none() {
                            return None;
                        } else if machines.map_batcher_enabled() {
                            last_seen_generation = *gen_rx.borrow();
                            None
                        } else {
                            let current_generation = *gen_rx.borrow();
                            let changes = map_changes_for_generation_range(
                                &machines,
                                last_seen_generation,
                                current_generation,
                                self_node_id,
                            );
                            last_seen_generation = current_generation;
                            rebuild_map_batch_chunk(
                                &machines,
                                &policy,
                                &self_node_key,
                                &machines_derp_map,
                                &dns,
                                cap_version,
                                taildrop_enabled,
                                auto_update_enabled,
                                disable_log_tail,
                                compression,
                                last_self_node.as_ref(),
                                &last_peer_state,
                                &initial_peer_ids,
                                &mapresponse_debug,
                                public_control_url.as_deref().unwrap_or(""),
                                &changes,
                            )
                            .or_else(|| {
                                rebuild_peer_delta_chunk(
                                    &machines,
                                    &policy,
                                    &self_node_key,
                                    &dns,
                                    cap_version,
                                    taildrop_enabled,
                                    auto_update_enabled,
                                    compression,
                                    last_self_node.as_ref(),
                                    &last_peer_state,
                                    &initial_peer_ids,
                                    &mapresponse_debug,
                                    public_control_url.as_deref().unwrap_or(""),
                                    PeerDeltaOptions::registry_change(),
                                    &BTreeSet::new(),
                                )
                            })
                        }
                    }
                    () = &mut policy_changed => {
                        // Policy edits can remove every visible peer.
                        // Emit an incremental delta with PeersRemoved
                        // rather than a full map whose empty Peers list
                        // would serialize away and leave clients with
                        // stale peers/routes.
                        match apply_policy_auto_approvals_for_registry(&machines, &policy) {
                            Ok(changed) if changed > 0 => {
                                last_seen_generation = *gen_rx.borrow();
                            }
                            Ok(_) => {}
                            Err(error) => {
                                tracing::error!(
                                    target = "tailscale_wire::map",
                                    error = %error,
                                    "applying policy route auto-approvals"
                                );
                            }
                        }
                        if machines.map_batcher_enabled() {
                            machines.record_observed_map_change(
                                MapChangeReason::PolicyChange,
                                Some(self_node_id),
                                None,
                            );
                            None
                        } else {
                            machines.record_unbatched_map_change(
                                MapChangeReason::PolicyChange,
                                Some(self_node_id),
                                None,
                            );
                            rebuild_peer_delta_chunk(
                                &machines,
                                &policy,
                                &self_node_key,
                                &dns,
                                cap_version,
                                taildrop_enabled,
                                auto_update_enabled,
                                compression,
                                last_self_node.as_ref(),
                                &last_peer_state,
                                &initial_peer_ids,
                                &mapresponse_debug,
                                public_control_url.as_deref().unwrap_or(""),
                                PeerDeltaOptions::policy_change(),
                                &BTreeSet::new(),
                            )
                        }
                    }
                    () = &mut dns_changed => {
                        // Extra-records file edited (or DnsStore.set_spec
                        // called) — wake every parked poller so the
                        // next chunk carries the refreshed `DNSConfig`.
                        machines.record_unbatched_map_change(
                            MapChangeReason::DnsConfigUpdate,
                            Some(self_node_id),
                            None,
                        );
                        Some((
                            rebuild_map_chunk(
                                &machines,
                                &policy,
                                &self_node_key,
                                &machines_derp_map,
                                &dns,
                                cap_version,
                                taildrop_enabled,
                                auto_update_enabled,
                                disable_log_tail,
                                compression,
                                Some(&last_peer_state),
                                "config",
                                &mapresponse_debug,
                                MapResponseDebugType::Change,
                                public_control_url.as_deref().unwrap_or(""),
                            ),
                            visible_peer_state_for_registry(&machines, &policy, &dns, &self_node_key, cap_version),
                            self_map_node_for_registry(&machines, &policy, &dns, &self_node_key, cap_version, taildrop_enabled, auto_update_enabled),
                        ))
                    }
                    res = derp_rx.changed() => {
                        // DERP URL/path refresh — wake every parked
                        // poller so the next chunk carries the new
                        // `DERPMap`.
                        if res.is_err() {
                            Some((build_keepalive_chunk(compression), last_peer_state.clone(), last_self_node.clone()))
                        } else {
                            machines.record_unbatched_map_change(
                                MapChangeReason::DerpMapUpdate,
                                Some(self_node_id),
                                None,
                            );
                            Some((
                            rebuild_map_chunk(
                                &machines,
                                &policy,
                                &self_node_key,
                                &machines_derp_map,
                                &dns,
                                cap_version,
                                taildrop_enabled,
                                auto_update_enabled,
                                disable_log_tail,
                                compression,
                                Some(&last_peer_state),
                                "config",
                                &mapresponse_debug,
                                MapResponseDebugType::Change,
                                public_control_url.as_deref().unwrap_or(""),
                            ),
                            visible_peer_state_for_registry(&machines, &policy, &dns, &self_node_key, cap_version),
                            self_map_node_for_registry(&machines, &policy, &dns, &self_node_key, cap_version, taildrop_enabled, auto_update_enabled),
                        ))
                        }
                    }
                    res = ping_rx.changed() => {
                        if res.is_err() {
                            Some((build_keepalive_chunk(compression), last_peer_state.clone(), last_self_node.clone()))
                        } else {
                            pings.pop_next_for_node(self_node_id).map(|request| (
                                build_ping_request_chunk(
                                    &machines,
                                    request,
                                    compression,
                                    &mapresponse_debug,
                                    self_node_id,
                                ),
                                last_peer_state.clone(),
                                last_self_node.clone(),
                            ))
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
                        last_seen_generation,
                        map_batch_rx,
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

fn map_changes_for_generation_range(
    machines: &Arc<crate::tailscale_wire::MachineRegistry>,
    after_generation: u64,
    through_generation: u64,
    self_node_id: u64,
) -> Vec<MapChange> {
    machines
        .map_change_history()
        .into_iter()
        .filter(|change| {
            change.generation > after_generation
                && change.generation <= through_generation
                && change.should_send_to_node(self_node_id)
        })
        .collect()
}

fn map_batch_requires_full_response(changes: &[MapChange]) -> bool {
    changes.iter().any(|change| {
        change.is_full()
            || change.content.include_derp_map
            || change.content.include_domain
            || (change.content.include_dns && !change.content.requires_runtime_peer_computation)
    })
}

fn map_batch_peer_delta_options(changes: &[MapChange], self_node_id: u64) -> PeerDeltaOptions {
    let requires_policy = changes.iter().any(|change| {
        (change.content.include_policy || change.content.requires_runtime_peer_computation)
            && !is_self_lifecycle_policy_companion(change, self_node_id)
    });
    if requires_policy {
        PeerDeltaOptions::policy_change()
    } else {
        PeerDeltaOptions::registry_change()
    }
}

fn is_self_lifecycle_policy_companion(change: &MapChange, self_node_id: u64) -> bool {
    let is_lifecycle_policy = change.reasons.len() == 2
        && matches!(
            change.reasons.first(),
            Some(MapChangeReason::NodeOnline | MapChangeReason::NodeOffline)
        )
        && change.reasons.get(1) == Some(&MapChangeReason::PolicyChange);

    change.origin_node_id == Some(self_node_id)
        && change.target_node_id.is_none()
        && is_lifecycle_policy
        && change.content.include_policy
        && change.content.requires_runtime_peer_computation
        && !change.content.include_self
        && !change.content.include_derp_map
        && !change.content.include_dns
        && !change.content.include_domain
        && !change.content.send_all_peers
        && change.content.peers_changed.is_empty()
        && change.content.peers_removed.is_empty()
        && change.content.peer_patches == [self_node_id]
}

fn map_batch_response_type(changes: &[MapChange]) -> &'static str {
    if changes.iter().any(MapChange::is_full) {
        return "full";
    }
    if changes.iter().any(|change| {
        change.content.include_derp_map
            || change.content.include_dns
            || change.content.include_domain
    }) {
        return "config";
    }
    if changes.iter().any(|change| change.target_node_id.is_some()) {
        return "self";
    }
    "full"
}

#[allow(clippy::too_many_arguments)]
fn rebuild_map_batch_chunk(
    machines: &Arc<crate::tailscale_wire::MachineRegistry>,
    policy: &Arc<crate::policy::PolicyStore>,
    self_node_key: &str,
    derp_map: &Arc<crate::tailscale_wire::DerpMapStore>,
    dns: &Arc<DnsStore>,
    cap_version: u32,
    taildrop_enabled: bool,
    auto_update_enabled: bool,
    disable_log_tail: bool,
    compression: MapFrameCompression,
    last_self_node: Option<&MapNode>,
    last_peer_state: &BTreeMap<u64, MapNode>,
    initial_peer_ids: &BTreeSet<u64>,
    mapresponse_debug: &MapResponseDebugStore,
    public_control_url: &str,
    changes: &[MapChange],
) -> Option<PeerDeltaChunk> {
    if changes.is_empty() {
        return None;
    }
    if changes.iter().all(|change| change.content.ping_request) {
        return None;
    }

    if map_batch_requires_full_response(changes) {
        return Some((
            rebuild_map_chunk(
                machines,
                policy,
                self_node_key,
                derp_map,
                dns,
                cap_version,
                taildrop_enabled,
                auto_update_enabled,
                disable_log_tail,
                compression,
                Some(last_peer_state),
                map_batch_response_type(changes),
                mapresponse_debug,
                MapResponseDebugType::Change,
                public_control_url,
            ),
            visible_peer_state_for_registry(machines, policy, dns, self_node_key, cap_version),
            self_map_node_for_registry(
                machines,
                policy,
                dns,
                self_node_key,
                cap_version,
                taildrop_enabled,
                auto_update_enabled,
            ),
        ));
    }

    rebuild_peer_delta_chunk(
        machines,
        policy,
        self_node_key,
        dns,
        cap_version,
        taildrop_enabled,
        auto_update_enabled,
        compression,
        last_self_node,
        last_peer_state,
        initial_peer_ids,
        mapresponse_debug,
        public_control_url,
        map_batch_peer_delta_options(changes, machines.stable_node_id_for_key(self_node_key)),
        &map_batch_forced_full_peer_ids(changes),
    )
}

fn map_batch_forced_full_peer_ids(changes: &[MapChange]) -> BTreeSet<u64> {
    changes
        .iter()
        .flat_map(|change| change.content.peers_changed.iter().copied())
        .collect()
}

fn rebuild_peer_delta_chunk(
    machines: &Arc<crate::tailscale_wire::MachineRegistry>,
    policy: &Arc<crate::policy::PolicyStore>,
    self_node_key: &str,
    dns: &Arc<DnsStore>,
    cap_version: u32,
    taildrop_enabled: bool,
    auto_update_enabled: bool,
    compression: MapFrameCompression,
    last_self_node: Option<&MapNode>,
    last_peer_state: &BTreeMap<u64, MapNode>,
    initial_peer_ids: &BTreeSet<u64>,
    mapresponse_debug: &MapResponseDebugStore,
    public_control_url: &str,
    options: PeerDeltaOptions,
    force_full_peer_ids: &BTreeSet<u64>,
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
        auto_update_enabled,
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
        if force_full_peer_ids.contains(&peer.id) {
            full_peers_changed.push(peer);
            continue;
        }
        match last_peer_state.get(&peer.id) {
            None => full_peers_changed.push(peer),
            Some(previous) if map_nodes_equal_ignoring_last_seen(previous, &peer) => {}
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

    let pure_self_update = self_node_changed
        && !options.include_dns_config
        && full_peers_changed.is_empty()
        && peers_removed.is_empty()
        && peer_patches.is_empty();
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
        user_profiles: if pure_self_update {
            Vec::new()
        } else {
            user_profiles_for_snapshot(&snapshot, self_node_key, allowed_peer_ids.as_ref())
        },
        packet_filters: if pure_self_update {
            BTreeMap::new()
        } else {
            packet_filters_for_node(policy, &packet_filter_nodes, self_node_id)
        },
        ssh_policy: if pure_self_update {
            None
        } else {
            ssh_policy_for_snapshot(policy, &snapshot, self_node_key, public_control_url)
        },
        control_time: Some(chrono::Utc::now()),
        keep_alive: false,
        ..MapResponse::default()
    };
    machines
        .record_mapresponse_generated(classify_incremental_mapresponse(options.response_type, &mr));
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

fn classify_incremental_mapresponse(
    default_response_type: &'static str,
    mr: &MapResponse,
) -> &'static str {
    if default_response_type == "policy" {
        return default_response_type;
    }
    if mr.node.is_some() {
        return "self";
    }
    if !mr.peers_changed_patch.is_empty() {
        return "patch";
    }
    if !mr.peers_changed.is_empty() || !mr.peers_removed.is_empty() {
        return "peers";
    }
    default_response_type
}

fn build_ping_request_chunk(
    machines: &crate::tailscale_wire::MachineRegistry,
    request: PingRequest,
    compression: MapFrameCompression,
    mapresponse_debug: &MapResponseDebugStore,
    node_id: u64,
) -> Vec<u8> {
    machines.record_mapresponse_generated("ping");
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
    auto_update_enabled: bool,
    disable_log_tail: bool,
    compression: MapFrameCompression,
    previous_peer_state: Option<&BTreeMap<u64, MapNode>>,
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
        auto_update_enabled,
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
    );
    let peers_removed = if peers.is_empty() {
        previous_peer_state
            .map(|state| state.keys().copied().collect())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let dns_config = build_dns_for_snapshot(dns, policy, &snapshot, self_node_key);
    let user_profiles =
        user_profiles_for_snapshot(&snapshot, self_node_key, allowed_peer_ids.as_ref());
    let mr = MapResponse {
        node: Some(own_node),
        peers,
        peers_removed,
        user_profiles,
        dns_config: Some(dns_config),
        derp_map: Some(derp_map.snapshot()),
        domain: tailnet_domain,
        collect_services: Some(false),
        packet_filters: packet_filters_for_node(policy, &packet_filter_nodes, self_node_id),
        ssh_policy: ssh_policy_for_snapshot(policy, &snapshot, self_node_key, public_control_url),
        control_time: Some(chrono::Utc::now()),
        debug: Some(DebugConfig {
            disable_log_tail,
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
        DerpMapStore, MachineRecord, MachineRegistrationStore, MachineRegistry,
        MapResponseDebugStore, PersistedMachineRegistration, WireState,
        noise::{NoisePeerMachineKey, ServerNoiseKey, inner_router as machine_router},
        register::{
            CAPABILITY_ADMIN, CAPABILITY_DEFAULT_AUTO_UPDATE, CAPABILITY_FILE_SHARING,
            CAPABILITY_SSH,
        },
        router as public_router, spawn_map_change_batcher,
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
            #[cfg(feature = "full")]
            native_derp: None,
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

    struct BlockingRuntimeSyncStore {
        entered: tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }

    #[async_trait::async_trait]
    impl MachineRegistrationStore for BlockingRuntimeSyncStore {
        async fn create_or_update_auth_key_registration(
            &self,
            record: MachineRecord,
            _policy: &crate::policy::PolicyStore,
            _auth_key_id: Option<i64>,
        ) -> Result<PersistedMachineRegistration, String> {
            Ok(PersistedMachineRegistration {
                record,
                replaced_node_key_hex: None,
            })
        }

        async fn sync_runtime_machine_state(
            &self,
            record: MachineRecord,
            _policy: &crate::policy::PolicyStore,
        ) -> Result<PersistedMachineRegistration, String> {
            if let Some(tx) = self.entered.lock().await.take() {
                let _ = tx.send(());
            }
            if let Some(rx) = self.release.lock().await.take() {
                let _ = rx.await;
            }
            Ok(PersistedMachineRegistration {
                record,
                replaced_node_key_hex: None,
            })
        }
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

    const TEST_MAP_BATCH_INTERVAL: Duration = Duration::from_millis(25);

    async fn start_test_map_batcher(state: &WireState) -> tokio::task::JoinHandle<()> {
        let handle = crate::tailscale_wire::spawn_map_change_batcher(
            state.machines.clone(),
            TEST_MAP_BATCH_INTERVAL,
        );
        tokio::task::yield_now().await;
        handle
    }

    async fn publish_test_map_batch() {
        tokio::time::advance(TEST_MAP_BATCH_INTERVAL).await;
        tokio::task::yield_now().await;
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
        assert_default_auto_update(node, false);
    }

    fn assert_default_auto_update(node: &MapNode, enabled: bool) {
        assert_eq!(
            node.cap_map
                .get(CAPABILITY_DEFAULT_AUTO_UPDATE)
                .and_then(|values| values.first())
                .and_then(serde_json::Value::as_bool),
            Some(enabled)
        );
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

    #[test]
    fn ssh_policy_nodes_from_snapshot_preserves_numeric_user_id() {
        let node = "ac".repeat(32);
        let mut record = policy_record(&node, "alice-node", 10, "alice-renamed", Vec::new());
        record.user_id = Some(42);
        let snapshot = HashMap::from([(node.clone(), record)]);

        let nodes = ssh_policy_nodes_from_snapshot(&snapshot);

        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].id, stable_id_from_key(&node));
        assert_eq!(nodes[0].user_id, Some(42));
        assert_eq!(nodes[0].user.as_deref(), Some("alice-renamed"));
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
    async fn map_response_reduces_peer_routes_by_viewer_policy() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["100.64.0.11:*"]}
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
        let peer = &mr.peers[0];
        assert_eq!(peer.name, "router");
        assert!(peer.allowed_ips.contains(&"100.64.0.11/32".to_string()));
        assert!(
            !peer.allowed_ips.contains(&"10.10.1.0/24".to_string()),
            "node visibility must not grant route visibility"
        );
        assert!(
            !peer.primary_routes.contains(&"10.10.1.0/24".to_string()),
            "PrimaryRoutes must be reduced independently from peer visibility"
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
            vec!["0.0.0.0/0", "10.20.1.0/24", "10.99.0.0/24"]
        );
        assert_eq!(rec.approved_routes, vec!["0.0.0.0/0", "10.20.1.0/24"]);

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
        assert!(!node.allowed_ips.iter().any(|route| route == "::/0"));
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

    #[tokio::test]
    async fn map_request_preserves_admin_renamed_given_name() {
        let (state, _dir) = fixture();
        let node_key = "e2".repeat(32);
        insert_peer(&state, &node_key, "old-host", 10);
        assert!(state.machines.rename(&node_key, "admin-name".into()));

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
                                "Hostname": "client-new-host",
                                "OS": "linux"
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
        assert_eq!(rec.hostname, "admin-name");
        assert_eq!(rec.host_info_for_node().hostname, "client-new-host");
    }

    #[tokio::test]
    async fn map_request_preserves_node_fallback_given_name() {
        let (state, _dir) = fixture();
        let node_key = "e6".repeat(32);
        let mut record = MachineRecord::new_at(
            chrono::Utc::now(),
            node_key.clone(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "u".into(),
            "node".into(),
            Ipv4Addr::new(100, 64, 0, 14),
            false,
        );
        record.host_info.hostname = "!!!".into();
        state.machines.upsert(node_key.clone(), record);

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
                                "Hostname": "client-new-host",
                                "OS": "linux"
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
        assert_eq!(rec.hostname, "node");
        assert_eq!(rec.host_info_for_node().hostname, "client-new-host");
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
        record.last_seen = chrono::Utc::now() - chrono::Duration::seconds(10);
        let initial_last_seen = record.last_seen.timestamp();
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
        assert!(
            row.last_seen.is_some_and(|seen| seen > initial_last_seen),
            "map-time last_seen touch should persist to nodes.last_seen"
        );
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

    #[cfg(feature = "admin")]
    #[tokio::test]
    async fn map_request_persists_admin_renamed_given_name() {
        use crate::admin::machines::PersistentMachineAdmin;
        use crate::admin::users::{PersistentUserAdmin, UserAdmin};

        let db = headscale_db::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        users.create("alice").await.unwrap();
        let machines =
            Arc::new(PersistentMachineAdmin::new(db.pool().clone()).with_user_admin(users));
        let node_key = "e7".repeat(32);
        let mut record = MachineRecord::new_at(
            chrono::Utc::now(),
            node_key.clone(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "alice".into(),
            "old-host".into(),
            Ipv4Addr::new(100, 64, 0, 45),
            false,
        );
        record.register_method = 1;
        machines
            .create_or_update_auth_key_path(
                record.clone(),
                &crate::policy::PolicyStore::new(),
                None,
            )
            .await
            .unwrap();
        let row = headscale_db::headscale_nodes::get_by_node_key(
            db.pool(),
            &format!("nodekey:{node_key}"),
        )
        .await
        .unwrap();
        headscale_db::headscale_nodes::rename(db.pool(), row.id, "admin-name")
            .await
            .unwrap();

        record.hostname = "admin-name".into();
        record.host_info.hostname = "old-host".into();
        let (mut state, _dir) = fixture();
        state.machines.upsert(node_key.clone(), record);
        state.registration_store = Some(machines.clone());

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
                                "Hostname": "client-new-host",
                                "OS": "linux"
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
            &format!("nodekey:{node_key}"),
        )
        .await
        .unwrap();
        assert_eq!(row.hostname, "client-new-host");
        assert_eq!(row.given_name, "admin-name");
        assert_eq!(row.host_info_value()["Hostname"], "client-new-host");

        let hydrated = MachineRegistry::new();
        machines.hydrate_wire_registry(&hydrated).await.unwrap();
        let wire = hydrated.get(&node_key).unwrap();
        assert_eq!(wire.hostname, "admin-name");
        assert_eq!(wire.host_info_for_node().hostname, "client-new-host");
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
        assert_eq!(mr.peers[0].name, "peer-b.headscale.test.");
        assert_eq!(mr.domain, "headscale.test");
    }

    #[tokio::test]
    async fn map_response_keeps_multi_address_magicdns_context_out_of_extra_records() {
        let (state, _dir) = fixture();
        state.dns.set_spec(crate::dns::DnsConfigSpec {
            base_domain: "headscale.test".into(),
            ..crate::dns::DnsConfigSpec::default()
        });
        let requester_key = "3a".repeat(32);
        let dual_peer_key = "3b".repeat(32);
        let v6_peer_key = "3c".repeat(32);
        insert_peer(&state, &requester_key, "requester", 30);
        insert_peer(&state, &dual_peer_key, "dual-peer", 31);
        insert_peer(&state, &v6_peer_key, "v6-peer", 32);
        state.machines.update_with(|records| {
            records.get_mut(&requester_key).unwrap().ipv6 =
                Some("fd7a:115c:a1e0::30".parse().unwrap());
            records.get_mut(&dual_peer_key).unwrap().ipv6 =
                Some("fd7a:115c:a1e0::31".parse().unwrap());
            let v6_peer = records.get_mut(&v6_peer_key).unwrap();
            v6_peer.ipv4 = None;
            v6_peer.ipv6 = Some("fd7a:115c:a1e0::32".parse().unwrap());
        });

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{requester_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(mr.domain, "headscale.test");
        let dns = mr.dns_config.expect("dns config");
        assert!(dns.proxied);
        assert_eq!(dns.domains, vec!["headscale.test"]);
        assert!(
            dns.extra_records.is_empty(),
            "headscale-go keeps peer MagicDNS A/AAAA state in MapNode records, not DNSConfig.ExtraRecords"
        );

        let requester = mr.node.as_ref().expect("own node present");
        assert_eq!(
            requester.addresses,
            vec!["100.64.0.30/32", "fd7a:115c:a1e0::30/128"]
        );
        assert_eq!(
            requester.allowed_ips,
            vec!["100.64.0.30/32", "fd7a:115c:a1e0::30/128"]
        );

        let dual_peer = mr
            .peers
            .iter()
            .find(|peer| peer.name == "dual-peer.headscale.test.")
            .expect("dual-stack peer present");
        assert_eq!(
            dual_peer.addresses,
            vec!["100.64.0.31/32", "fd7a:115c:a1e0::31/128"]
        );
        assert_eq!(
            dual_peer.allowed_ips,
            vec!["100.64.0.31/32", "fd7a:115c:a1e0::31/128"]
        );

        let v6_peer = mr
            .peers
            .iter()
            .find(|peer| peer.name == "v6-peer.headscale.test.")
            .expect("IPv6-only peer present");
        assert_eq!(v6_peer.addresses, vec!["fd7a:115c:a1e0::32/128"]);
        assert_eq!(v6_peer.allowed_ips, vec!["fd7a:115c:a1e0::32/128"]);
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
        let (mut state, _dir) = fixture();
        let mut runtime_config = crate::tailscale_wire::RuntimeConfigSnapshot::default();
        runtime_config.auto_update.enabled = true;
        runtime_config.log_tail.enabled = true;
        state.runtime_config = Arc::new(runtime_config);
        let a = "d1".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first = next_zstd_map_response(&mut body).await;
        assert_eq!(
            first.debug.as_ref().map(|debug| debug.disable_log_tail),
            Some(false)
        );
        assert_default_auto_update(first.node.as_ref().expect("own node present"), true);
        assert!(first.derp_map.as_ref().unwrap().regions.is_empty());
        let history_len = state.machines.map_change_history().len();

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
        assert_eq!(
            updated.debug.as_ref().map(|debug| debug.disable_log_tail),
            Some(false)
        );
        assert_default_auto_update(updated.node.as_ref().expect("own node present"), true);
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
        let changes = state.machines.map_change_history();
        let change = changes
            .get(history_len)
            .expect("DERP refresh records a map change");
        assert_eq!(change.reason_labels(), vec!["DERP map update"]);
        assert_eq!(change.change_type(), "config");
        assert!(change.content.include_derp_map);
        assert!(change.content.peers_changed.is_empty());
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

    fn crossed_multiprefix_via_policy(route_a: &str, route_b: &str) -> String {
        format!(
            r#"{{
                "tagOwners": {{
                    "tag:router-a": ["router@"],
                    "tag:router-b": ["router@"]
                }},
                "grants": [
                    {{
                        "src": ["*"],
                        "dst": ["tag:router-a", "tag:router-b"],
                        "ip": ["*"]
                    }},
                    {{
                        "src": ["alice@"],
                        "dst": ["{route_a}"],
                        "ip": ["*"],
                        "via": ["tag:router-a"]
                    }},
                    {{
                        "src": ["alice@"],
                        "dst": ["{route_b}"],
                        "ip": ["*"],
                        "via": ["tag:router-b"]
                    }},
                    {{
                        "src": ["bob@"],
                        "dst": ["{route_a}"],
                        "ip": ["*"],
                        "via": ["tag:router-b"]
                    }},
                    {{
                        "src": ["bob@"],
                        "dst": ["{route_b}"],
                        "ip": ["*"],
                        "via": ["tag:router-a"]
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

    fn via_steering_policy_with_regular_overlap_multi_router_via(route: &str) -> String {
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
                        "ip": ["*"]
                    }},
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

    fn peer_named<'a>(mr: &'a MapResponse, name: &str) -> Option<&'a MapNode> {
        mr.peers.iter().find(|peer| peer.name == name)
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
    async fn map_response_via_crossed_multiprefix_routes_per_viewer() {
        let (state, _dir) = fixture();
        let route_a = "10.77.0.0/24";
        let route_b = "10.88.0.0/24";
        let policy = crossed_multiprefix_via_policy(route_a, route_b);
        state
            .policy
            .set(crate::policy::parse_hujson_policy(&policy).unwrap(), policy);

        let router_a = "81".repeat(32);
        let router_b = "82".repeat(32);
        let alice = "83".repeat(32);
        let bob = "84".repeat(32);
        let router_routes = vec![route_a.to_string(), route_b.to_string()];
        for (node_key, host, octet, user, tags, routes) in [
            (
                &router_a,
                "router-a",
                81,
                "router",
                vec!["tag:router-a".to_string()],
                router_routes.clone(),
            ),
            (
                &router_b,
                "router-b",
                82,
                "router",
                vec!["tag:router-b".to_string()],
                router_routes.clone(),
            ),
            (&alice, "alice", 83, "alice", Vec::new(), Vec::new()),
            (&bob, "bob", 84, "bob", Vec::new(), Vec::new()),
        ] {
            let mut rec = policy_record(node_key, host, octet, user, tags);
            rec.available_routes = routes.clone();
            rec.approved_routes = routes;
            state.machines.upsert(node_key.clone(), rec);
        }
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
        let primary_owner_for = |route: &str| {
            primary_routes
                .iter()
                .find_map(|(node_key, routes)| {
                    routes
                        .iter()
                        .any(|primary| primary == route)
                        .then_some(node_key.as_str())
                })
                .expect("global primary route")
        };
        assert!(
            matches!(primary_owner_for(route_a), owner if owner == router_a || owner == router_b)
        );
        assert!(
            matches!(primary_owner_for(route_b), owner if owner == router_a || owner == router_b)
        );

        let app = router(state);
        for (client, expectations) in [
            (
                &alice,
                [
                    ("router-a", router_a.as_str(), route_a),
                    ("router-b", router_b.as_str(), route_b),
                ],
            ),
            (
                &bob,
                [
                    ("router-b", router_b.as_str(), route_a),
                    ("router-a", router_a.as_str(), route_b),
                ],
            ),
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

            for name in ["router-a", "router-b"] {
                peer_named(&mr, name).unwrap_or_else(|| panic!("{name} peer visible"));
            }

            for (expected_name, expected_key, route) in expectations {
                let expected_peer =
                    peer_named(&mr, expected_name).expect("expected route peer visible");
                assert!(
                    expected_peer
                        .allowed_ips
                        .iter()
                        .any(|allowed| allowed == route),
                    "{expected_name} should carry {route} in AllowedIPs"
                );
                assert_eq!(
                    expected_peer
                        .primary_routes
                        .iter()
                        .any(|primary| primary == route),
                    primary_owner_for(route) == expected_key,
                    "{expected_name} PrimaryRoutes placement for {route}"
                );

                let mut route_field_owners = mr
                    .peers
                    .iter()
                    .filter(|peer| {
                        peer.allowed_ips.iter().any(|allowed| allowed == route)
                            || peer.primary_routes.iter().any(|primary| primary == route)
                    })
                    .map(|peer| peer.name.clone())
                    .collect::<Vec<_>>();
                route_field_owners.sort();
                assert_eq!(
                    route_field_owners,
                    vec![expected_name.to_string()],
                    "only the via-selected peer should expose {route}"
                );
            }
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
    async fn map_response_via_regular_overlap_follows_route_health_primary() {
        let (state, _dir) = fixture();
        let route = "10.80.0.0/24";
        let policy = via_steering_policy_with_regular_overlap_multi_router_via(route);
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
        let initial_primary = owner_for_route(&primary_routes, route).expect("global primary");
        let (initial_primary_name, failover_name, failover_key) = if initial_primary == router_a {
            ("router-a", "router-b", router_b.as_str())
        } else {
            ("router-b", "router-a", router_a.as_str())
        };

        let app = router(state.clone());
        let resp = app
            .clone()
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
        assert!(peer_route(&mr, initial_primary_name, route).is_some());
        assert!(peer_route(&mr, failover_name, route).is_none());

        assert!(
            state
                .machines
                .set_route_candidate_health(stable_id_from_key(&initial_primary), false)
        );

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
        assert!(peer_route(&mr, failover_name, route).is_some());
        assert!(peer_route(&mr, initial_primary_name, route).is_none());
        let failed_over = state
            .machines
            .primary_routes_for_snapshot(&state.machines.snapshot());
        assert_eq!(
            failed_over.get(failover_key).cloned().unwrap_or_default(),
            vec![route.to_string()]
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
    async fn stream_policy_change_adds_newly_visible_cross_user_profile() {
        let (state, _dir) = fixture();
        let deny_policy = r#"{"acls":[]}"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(deny_policy).unwrap(),
            deny_policy.into(),
        );

        let alice = "a7".repeat(32);
        let bob = "b7".repeat(32);
        let mut alice_record = policy_record(&alice, "alice-node", 10, "alice", Vec::new());
        alice_record.set_user_identity(
            Some(1001),
            "alice".into(),
            "Alice Example".into(),
            String::new(),
        );
        state.machines.upsert(alice.clone(), alice_record);

        let mut bob_record = policy_record(&bob, "bob-node", 11, "bob", Vec::new());
        bob_record.set_user_identity(
            Some(1002),
            "bob".into(),
            "Bob Example".into(),
            String::new(),
        );
        state.machines.upsert(bob.clone(), bob_record);

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &alice).await;
        let first = next_zstd_map_response(&mut body).await;
        assert!(
            first
                .peers
                .iter()
                .all(|peer| peer.id != stable_id_from_key(&bob)),
            "deny-all initial stream should not include Bob as a peer"
        );
        assert!(
            first
                .user_profiles
                .iter()
                .all(|profile| profile.id != 1002 && profile.login_name != "bob"),
            "deny-all initial stream should not include Bob's UserProfile"
        );

        let allow_policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["bob@:*"]}
            ]
        }"#;
        let policy_update = tokio::spawn({
            let policy = state.policy.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                policy.set(
                    crate::policy::parse_hujson_policy(allow_policy).unwrap(),
                    allow_policy.into(),
                );
            }
        });

        let updated =
            tokio::time::timeout(Duration::from_secs(1), next_zstd_map_response(&mut body))
                .await
                .expect("policy update map chunk");
        policy_update.await.expect("policy update task");

        assert!(
            updated.peers.is_empty(),
            "policy wake should use incremental peer deltas"
        );
        assert!(updated.peers_removed.is_empty());
        let bob_peer = changed_peer(&updated, "bob-node").expect("Bob peer changed");
        assert_eq!(bob_peer.id, stable_id_from_key(&bob));
        let bob_profile = updated
            .user_profiles
            .iter()
            .find(|profile| profile.id == 1002)
            .expect("Bob UserProfile present");
        assert_eq!(bob_profile.login_name, "bob");
        assert!(
            updated.dns_config.is_some(),
            "policy deltas carry policy-derived DNSConfig updates"
        );
    }

    #[tokio::test]
    async fn stream_policy_refresh_after_profile_churn_carries_updated_user_profile() {
        let (state, _dir) = fixture();
        let allow_policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["bob@:*"]}
            ]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(allow_policy).unwrap(),
            allow_policy.into(),
        );

        let alice = "a8".repeat(32);
        let bob = "b8".repeat(32);
        let mut alice_record = policy_record(&alice, "alice-node", 10, "alice", Vec::new());
        alice_record.set_user_identity(
            Some(1001),
            "alice".into(),
            "Alice Example".into(),
            String::new(),
        );
        state.machines.upsert(alice.clone(), alice_record);

        let mut bob_record = policy_record(&bob, "bob-node", 11, "bob", Vec::new());
        bob_record.set_user_identity(
            Some(1002),
            "bob".into(),
            "Bob Before".into(),
            "https://example.com/bob-before.png".into(),
        );
        state.machines.upsert(bob.clone(), bob_record);

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &alice).await;
        let first = next_zstd_map_response(&mut body).await;
        let initial_bob_profile = first
            .user_profiles
            .iter()
            .find(|profile| profile.id == 1002)
            .expect("initial Bob UserProfile present");
        assert_eq!(initial_bob_profile.display_name, "Bob Before");

        state.machines.update_with(|records| {
            let bob_record = records.get_mut(&bob).expect("Bob record present");
            bob_record.set_user_identity(
                Some(1002),
                "bob".into(),
                "Bob After".into(),
                "https://example.com/bob-after.png".into(),
            );
        });

        let refresh = tokio::spawn({
            let policy = state.policy.clone();
            async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
                policy.refresh();
            }
        });

        let updated =
            tokio::time::timeout(Duration::from_secs(1), next_zstd_map_response(&mut body))
                .await
                .expect("policy refresh map chunk");
        refresh.await.expect("policy refresh task");

        assert!(
            updated.peers.is_empty(),
            "policy refresh should use incremental peer deltas"
        );
        assert!(
            updated.peers_changed.is_empty(),
            "profile-only churn should not force an unchanged peer node delta"
        );
        assert!(updated.peers_removed.is_empty());
        let bob_profile = updated
            .user_profiles
            .iter()
            .find(|profile| profile.id == 1002)
            .expect("updated Bob UserProfile present");
        assert_eq!(bob_profile.login_name, "bob");
        assert_eq!(bob_profile.display_name, "Bob After");
        assert_eq!(
            bob_profile.profile_pic_url,
            "https://example.com/bob-after.png"
        );
        assert!(
            updated.dns_config.is_some(),
            "policy refresh deltas carry policy-derived DNSConfig updates"
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

    /// Stream:true: registry changes are held until the map-change
    /// batcher publishes its tick, then the existing stream emits the
    /// incremental peer delta.
    #[tokio::test(start_paused = true)]
    async fn stream_true_emits_mapresponse_chunk_after_map_batch_tick() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        // Note: only peer-a registered initially.
        let _batcher = start_test_map_batcher(&state).await;

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

        insert_peer(&state, &b, "peer-b", 11);
        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "registry generation wakes must not bypass the batch tick"
        );
        publish_test_map_batch().await;

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

    #[tokio::test(start_paused = true)]
    async fn stream_true_same_key_auth_completion_emits_peer_delta() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "observer", 11);

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &b).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&a));
        assert_eq!(first_mr.peers[0].name, "peer-a");

        let history_len = state.machines.map_change_history().len();
        let mut updated = state.machines.get(&a).expect("peer-a exists");
        updated.hostname = "peer-a-reauth".into();
        updated.host_info.hostname = updated.hostname.clone();
        updated.last_seen = chrono::Utc::now();
        state
            .machines
            .upsert_auth_completion(updated.node_key_hex.clone(), updated);

        let changes = state.machines.map_change_history();
        assert_eq!(changes.len(), history_len + 1);
        assert_eq!(
            changes[history_len].reasons,
            vec![MapChangeReason::NodeAdded]
        );

        let mr = next_zstd_map_response(&mut body).await;
        assert!(mr.peers.is_empty());
        assert_eq!(mr.peers_changed.len(), 1);
        assert_eq!(mr.peers_changed[0].id, stable_id_from_key(&a));
        assert_eq!(mr.peers_changed[0].name, "peer-a-reauth");
        assert!(mr.peers_removed.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        assert!(mr.dns_config.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_admin_rename_emits_self_update_for_changed_node() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.node.as_ref().unwrap().name, "peer-a");
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&b));

        let history_len = state.machines.map_change_history().len();
        assert!(state.machines.rename(&a, "admin-renamed".into()));

        let changes = state.machines.map_change_history();
        assert_eq!(changes.len(), history_len + 1);
        assert_eq!(
            changes[history_len].reasons,
            vec![MapChangeReason::NodeAdded]
        );
        assert_eq!(
            changes[history_len].origin_node_id,
            Some(stable_id_from_key(&a))
        );
        assert_eq!(changes[history_len].target_node_id, None);

        let mr = next_zstd_map_response(&mut body).await;
        let self_node = mr.node.as_ref().expect("self rename update");
        assert_eq!(self_node.id, stable_id_from_key(&a));
        assert_eq!(self_node.name, "admin-renamed");
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());
        assert!(mr.peers_removed.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        assert!(mr.dns_config.is_none());
        assert!(mr.derp_map.is_none());
        assert!(mr.user_profiles.is_empty());
        assert!(mr.packet_filters.is_empty());
        assert!(mr.ssh_policy.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_admin_rename_emits_peer_update_for_observer() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &b).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.node.as_ref().unwrap().name, "peer-b");
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&a));
        assert_eq!(first_mr.peers[0].name, "peer-a");

        assert!(state.machines.rename(&a, "admin-renamed".into()));

        let mr = next_zstd_map_response(&mut body).await;
        assert!(mr.node.is_none());
        assert!(mr.peers.is_empty());
        assert_eq!(mr.peers_changed.len(), 1);
        assert_eq!(mr.peers_changed[0].id, stable_id_from_key(&a));
        assert_eq!(mr.peers_changed[0].name, "admin-renamed");
        assert!(mr.peers_removed.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        assert!(mr.dns_config.is_none());
    }

    #[tokio::test]
    async fn stream_true_records_cancelled_end_reason_when_self_node_deleted() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);

        let app = router(state.clone());
        let public_app = public_router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert!(first_mr.node.is_some());

        assert!(state.machines.delete(&a));
        drop(body);
        tokio::task::yield_now().await;

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
        assert!(metrics.contains("headscale_mapresponse_ended_total{reason=\"cancelled\"} 1\n"));
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
            metrics.contains("headscale_mapresponse_generated_total{response_type=\"ping\"} 1\n")
        );

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

    #[tokio::test]
    async fn stream_true_batch_tick_does_not_duplicate_direct_ping_frame() {
        let (mut state, _dir) = fixture();
        state.public_control_url = Some("https://control.example".into());
        let a = "aa".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        let _batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert!(first_mr.ping_request.is_none());

        let node_id = stable_id_from_key(&a);
        let (ping_id, _response) = state.register_ping(node_id);
        state.dispatch_ping_request(node_id, &ping_id, true, false);

        let ping_mr = next_zstd_map_response(&mut body).await;
        assert!(
            ping_mr.ping_request.is_some(),
            "ping watch should still deliver the direct PingRequest frame"
        );

        tokio::time::sleep(TEST_MAP_BATCH_INTERVAL + Duration::from_millis(10)).await;
        if let Ok(Some(Ok(frame))) = tokio::time::timeout(
            Duration::from_millis(20),
            http_body_util::BodyExt::frame(&mut body),
        )
        .await
        {
            let chunk = frame.into_data().unwrap();
            let decoded = decode_framed(&chunk);
            panic!(
                "the pending PingNode batch should be consumed as a no-op, not emitted as a duplicate frame: {}",
                String::from_utf8_lossy(&decoded)
            );
        }
    }

    #[tokio::test]
    async fn stream_true_cancelled_ping_does_not_emit_stale_ping_frame() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert!(first_mr.ping_request.is_none());

        let node_id = stable_id_from_key(&a);
        let (ping_id, _response) = state.register_ping(node_id);
        state.dispatch_ping_request(node_id, &ping_id, true, false);
        assert!(state.pings.cancel(&ping_id));

        assert_no_stream_frame(&mut body, Duration::from_millis(50)).await;
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

    /// A registry change fired before the unfold re-parks must still
    /// be captured and delivered by the next map-batch tick.
    #[tokio::test(start_paused = true)]
    async fn stream_true_wake_during_chunk_build_is_not_lost_before_batch_tick() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        let _batcher = start_test_map_batcher(&state).await;

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

        // CRITICAL: publish no batch yet. The registry mutation happens
        // immediately after the first chunk and must be retained as
        // pending batch work, not emitted through the generation watch.
        insert_peer(&state, &b, "peer-b", 11);
        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "registry generation wakes must wait for the map-batch tick"
        );
        publish_test_map_batch().await;

        // Now read the next chunk — must be the retained peer delta,
        // not a keepalive and not a lost wake.
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

    #[tokio::test]
    async fn stream_true_consumes_each_published_map_batch_in_order() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        state.machines.enable_map_batcher();

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 0);

        let node_a_id = stable_id_from_key(&a);
        let node_b_id = stable_id_from_key(&b);
        let _guard_b = MachineRegistry::track_stream_connection_with_grace(
            state.machines.clone(),
            node_b_id,
            Duration::ZERO,
        );
        let _ = state.machines.drain_pending_map_changes();

        insert_peer(&state, &b, "peer-b", 11);
        let first_batch = state
            .machines
            .publish_pending_map_changes()
            .expect("peer-add batch published");
        assert!(first_batch.contains_key(&node_a_id));

        state
            .machines
            .record_observed_map_change(MapChangeReason::PingNode, Some(node_b_id), None);
        let second_batch = state
            .machines
            .publish_pending_map_changes()
            .expect("other-node-only batch published");
        assert!(!second_batch.contains_key(&node_a_id));

        let delta = tokio::time::timeout(Duration::from_secs(1), next_zstd_map_response(&mut body))
            .await
            .expect("stream should consume the queued peer-add batch before later batches");
        assert!(
            delta.peers.is_empty(),
            "follow-up stream chunks use incremental peer deltas"
        );
        assert_eq!(delta.peers_changed.len(), 1);
        assert_eq!(delta.peers_changed[0].id, node_b_id);
        assert_eq!(delta.peers_changed[0].name, "peer-b");
        assert_eq!(delta.peers_changed[0].addresses[0], "100.64.0.11/32");
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_with_batcher_waits_for_map_batch_tick() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        let _batcher = spawn_map_change_batcher(state.machines.clone(), Duration::from_millis(50));

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 0);

        insert_peer(&state, &b, "peer-b", 11);
        assert_no_stream_frame(&mut body, Duration::from_millis(49)).await;

        let mr = next_zstd_map_response(&mut body).await;
        assert!(
            mr.peers.is_empty(),
            "batch-delivered follow-up chunks still use incremental peer deltas"
        );
        assert_eq!(mr.peers_changed.len(), 1);
        assert_eq!(mr.peers_changed[0].id, stable_id_from_key(&b));
        assert_eq!(mr.peers_changed[0].name, "peer-b");
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_batched_tag_update_recomputes_peer_visibility() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "tagOwners": {
                "tag:server": ["server-owner@"],
                "tag:db": ["server-owner@"]
            },
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["tag:server:*"]}
            ]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let alice = "a9".repeat(32);
        let server = "b9".repeat(32);
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice-node", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            server.clone(),
            policy_record(&server, "server-node", 11, "server-owner", Vec::new()),
        );
        let _batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &alice).await;
        let first = next_zstd_map_response(&mut body).await;
        assert!(first.peers.is_empty());
        assert!(
            first
                .user_profiles
                .iter()
                .all(|profile| profile.id != crate::tailscale_wire::wire::TAGGED_DEVICES_USER_ID),
            "untagged hidden peer must not contribute the tagged-devices profile"
        );

        assert!(
            state
                .machines
                .set_forced_tags(&server, vec!["tag:server".into()])
        );
        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "tag updates must wait for the map-batch tick"
        );
        publish_test_map_batch().await;

        let tagged = next_zstd_map_response(&mut body).await;
        assert!(
            tagged.peers.is_empty(),
            "batch-delivered tag churn should use incremental peer deltas"
        );
        assert!(tagged.peers_removed.is_empty());
        let server_peer = changed_peer(&tagged, "server-node").expect("tagged peer delta");
        assert_eq!(server_peer.id, stable_id_from_key(&server));
        assert_eq!(
            server_peer.user,
            crate::tailscale_wire::wire::TAGGED_DEVICES_USER_ID
        );
        assert!(
            tagged
                .user_profiles
                .iter()
                .any(|profile| profile.id == crate::tailscale_wire::wire::TAGGED_DEVICES_USER_ID)
        );
        assert!(
            tagged.dns_config.is_some(),
            "tag churn changes policy-visible state and should carry policy-derived DNS updates"
        );

        assert!(
            state
                .machines
                .set_forced_tags(&server, vec!["tag:db".into()])
        );
        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "tag updates must wait for the map-batch tick"
        );
        publish_test_map_batch().await;

        let untagged = next_zstd_map_response(&mut body).await;
        assert!(untagged.peers.is_empty());
        assert!(untagged.peers_changed.is_empty());
        assert!(untagged.peers_changed_patch.is_empty());
        assert_eq!(untagged.peers_removed, vec![stable_id_from_key(&server)]);
        assert!(
            untagged
                .user_profiles
                .iter()
                .all(|profile| profile.id != crate::tailscale_wire::wire::TAGGED_DEVICES_USER_ID),
            "removed tagged peer must also remove the tagged-devices profile"
        );
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
    async fn stream_true_batched_full_update_to_zero_peers_emits_peers_removed() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);
        let _batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&b));

        assert!(state.machines.delete(&b));
        state
            .machines
            .record_observed_map_change(MapChangeReason::FullUpdate, None, None);
        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "batched full update must wait for the map-batch tick"
        );
        publish_test_map_batch().await;

        let mr = next_zstd_map_response(&mut body).await;
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        assert_eq!(mr.peers_removed, vec![stable_id_from_key(&b)]);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_worker_update_delete_same_batch_emits_only_peers_removed() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);
        let _nodestore_batcher = state
            .machines
            .configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&b));

        let peer_id = stable_id_from_key(&b);
        let expiry = chrono::Utc::now() + chrono::Duration::hours(1);
        let machines = state.machines.clone();
        let b_for_update = b.clone();
        let update = std::thread::spawn(move || machines.set_expiry(&b_for_update, Some(expiry)));

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while state.machines.nodestore_queue_depth() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "queued expiry update did not reach the NodeStore worker"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        assert!(state.machines.delete(&b));
        assert!(
            !update.join().expect("queued expiry update should finish"),
            "same-batch update should report false after the node is deleted"
        );
        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "worker update/delete changes must wait for the map-batch tick"
        );

        publish_test_map_batch().await;
        let mr = next_zstd_map_response(&mut body).await;
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        assert_eq!(mr.peers_removed, vec![peer_id]);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_worker_rename_delete_same_batch_emits_only_peers_removed() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);
        let _nodestore_batcher = state
            .machines
            .configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&b));
        assert_eq!(first_mr.peers[0].name, "peer-b");

        let peer_id = stable_id_from_key(&b);
        let machines = state.machines.clone();
        let b_for_rename = b.clone();
        let rename =
            std::thread::spawn(move || machines.rename(&b_for_rename, "peer-b-renamed".into()));

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while state.machines.nodestore_queue_depth() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "queued rename did not reach the NodeStore worker"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        assert!(state.machines.delete(&b));
        assert!(
            !rename.join().expect("queued rename should finish"),
            "same-batch rename should report false after the node is deleted"
        );
        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "worker rename/delete changes must wait for the map-batch tick"
        );

        publish_test_map_batch().await;
        let mr = next_zstd_map_response(&mut body).await;
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        assert_eq!(mr.peers_removed, vec![peer_id]);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_worker_upsert_delete_same_batch_emits_only_peers_removed() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&b));
        let _ = state.machines.drain_pending_map_changes();

        let _nodestore_batcher = state
            .machines
            .configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let history_len = state.machines.map_change_history().len();
        let peer_id = stable_id_from_key(&b);
        let machines = state.machines.clone();
        let b_for_upsert = b.clone();
        let upsert = std::thread::spawn(move || {
            let mut rec = machines
                .get(&b_for_upsert)
                .expect("peer exists before queued upsert");
            rec.hostname = "peer-b-renamed".into();
            machines.upsert(b_for_upsert.clone(), rec);
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while state.machines.nodestore_queue_depth() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "queued upsert did not reach the NodeStore worker"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        assert!(state.machines.delete(&b));
        upsert
            .join()
            .expect("queued upsert should finish after same-batch delete");

        let changes = state.machines.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(new_changes.len(), 1, "{new_changes:?}");
        assert_eq!(new_changes[0].reason_labels(), vec!["peers removed"]);
        assert_eq!(new_changes[0].content.peers_removed, vec![peer_id]);
        assert!(new_changes[0].content.peers_changed.is_empty());
        assert!(new_changes[0].content.peer_patches.is_empty());
        let pending = state.machines.pending_map_changes();
        let observer_changes = pending
            .get(&stable_id_from_key(&a))
            .expect("same-batch delete should queue a peer removal for the observer");
        assert_eq!(observer_changes.len(), 1);
        assert_eq!(observer_changes[0].reason_labels(), vec!["peers removed"]);

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "same-batch upsert/delete should wait for the map-batch tick"
        );

        publish_test_map_batch().await;
        let mr = next_zstd_map_response(&mut body).await;
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        assert_eq!(mr.peers_removed, vec![peer_id]);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_worker_auth_rekey_delete_same_batch_suppresses_stale_auth_reason() {
        let (state, _dir) = fixture();
        let observer = "aa".repeat(32);
        let old_node = "bb".repeat(32);
        let new_node = "cc".repeat(32);
        insert_peer(&state, &observer, "observer", 10);

        let mut old = MachineRecord::new_at(
            chrono::Utc::now(),
            old_node.clone(),
            "reauth-machine".into(),
            "alice".into(),
            "old-auth-node".into(),
            Ipv4Addr::new(100, 64, 0, 11),
            false,
        );
        old.node_id = Some(42);
        old.forced_tags = vec!["tag:server".into()];
        state.machines.upsert(old_node.clone(), old);

        let mut target = MachineRecord::new_at(
            chrono::Utc::now(),
            new_node.clone(),
            "other-machine".into(),
            "alice".into(),
            "target-node".into(),
            Ipv4Addr::new(100, 64, 0, 12),
            false,
        );
        target.node_id = Some(99);
        state.machines.upsert(new_node.clone(), target);
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &observer).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        let initial_peer_ids = first_mr
            .peers
            .iter()
            .map(|peer| peer.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(initial_peer_ids, BTreeSet::from([42, 99]));
        let _ = state.machines.drain_pending_map_changes();

        let _nodestore_batcher = state
            .machines
            .configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let history_len = state.machines.map_change_history().len();
        let machines = state.machines.clone();
        let pending_new_node = new_node.clone();
        let rekey = std::thread::spawn(move || {
            let mut pending = MachineRecord::new_at(
                chrono::Utc::now(),
                pending_new_node.clone(),
                "reauth-machine".into(),
                String::new(),
                "old-auth-node".into(),
                Ipv4Addr::new(100, 64, 0, 13),
                false,
            );
            pending.node_id = Some(42);
            machines.complete_web_registration(pending, "alice", 2);
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while state.machines.nodestore_queue_depth() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "queued auth-completion rekey did not reach the NodeStore worker"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        assert!(state.machines.delete(&new_node));
        rekey
            .join()
            .expect("queued auth-completion rekey should finish");
        assert!(state.machines.get(&old_node).is_none());
        assert!(state.machines.get(&new_node).is_none());

        let changes = state.machines.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(new_changes.len(), 1, "{new_changes:?}");
        assert_eq!(new_changes[0].reason_labels(), vec!["peers removed"]);
        assert_eq!(new_changes[0].content.peers_removed, vec![99]);
        assert!(new_changes[0].content.peers_changed.is_empty());
        assert!(!new_changes[0].content.include_policy);

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "worker-batched auth rekey/delete must wait for the map-batch tick"
        );

        publish_test_map_batch().await;
        let mr = next_zstd_map_response(&mut body).await;
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        assert_eq!(mr.peers_removed, vec![42, 99]);
        assert!(
            mr.dns_config.is_none(),
            "stale auth-completion policy reason should not turn the peer removal into a policy chunk"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_worker_auth_rekey_old_key_delete_same_batch_keeps_auth_peer_delta() {
        let (state, _dir) = fixture();
        let observer = "aa".repeat(32);
        let old_node = "bb".repeat(32);
        let new_node = "cc".repeat(32);
        insert_peer(&state, &observer, "observer", 10);

        let mut old = MachineRecord::new_at(
            chrono::Utc::now(),
            old_node.clone(),
            "reauth-machine".into(),
            "alice".into(),
            "old-auth-node".into(),
            Ipv4Addr::new(100, 64, 0, 11),
            false,
        );
        old.node_id = Some(42);
        state.machines.upsert(old_node.clone(), old);
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &observer).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, 42);
        assert_eq!(first_mr.peers[0].name, "old-auth-node");
        let _ = state.machines.drain_pending_map_changes();

        let _nodestore_batcher = state
            .machines
            .configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let history_len = state.machines.map_change_history().len();
        let machines = state.machines.clone();
        let pending_new_node = new_node.clone();
        let rekey = std::thread::spawn(move || {
            let mut pending = MachineRecord::new_at(
                chrono::Utc::now(),
                pending_new_node.clone(),
                "reauth-machine".into(),
                String::new(),
                "old-auth-node-reauth".into(),
                Ipv4Addr::new(100, 64, 0, 12),
                false,
            );
            pending.node_id = Some(42);
            machines.complete_web_registration(pending, "alice", 2);
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while state.machines.nodestore_queue_depth() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "queued auth-completion rekey did not reach the NodeStore worker"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        assert!(
            !state.machines.delete(&old_node),
            "same-batch stale old-key delete should be a no-op after the rekey wins"
        );
        rekey
            .join()
            .expect("queued auth-completion rekey should finish");
        assert!(state.machines.get(&old_node).is_none());
        assert!(state.machines.get(&new_node).is_some());

        let changes = state.machines.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(new_changes.len(), 1, "{new_changes:?}");
        assert_eq!(new_changes[0].reason_labels(), vec!["node added"]);
        assert_eq!(new_changes[0].content.peers_changed, vec![42]);
        assert!(new_changes[0].content.peers_removed.is_empty());
        assert!(!new_changes[0].content.include_policy);

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "worker-batched old-key delete/rekey must wait for the map-batch tick"
        );

        publish_test_map_batch().await;
        let mr = next_zstd_map_response(&mut body).await;
        assert!(mr.peers.is_empty());
        assert_eq!(mr.peers_changed.len(), 1);
        assert_eq!(mr.peers_changed[0].id, 42);
        assert_eq!(mr.peers_changed[0].name, "old-auth-node-reauth");
        assert!(mr.peers_changed_patch.is_empty());
        assert!(mr.peers_removed.is_empty());
        assert!(
            mr.dns_config.is_none(),
            "auth peer-delta rekey should not become a policy/config chunk"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_worker_gc_ephemeral_emits_batched_peers_removed_reason() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        let mut stale_ephemeral = MachineRecord::new_at(
            chrono::Utc::now(),
            b.clone(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "u".into(),
            "peer-b".into(),
            Ipv4Addr::new(100, 64, 0, 11),
            true,
        );
        stale_ephemeral.last_seen = chrono::Utc::now() - chrono::Duration::minutes(5);
        state.machines.upsert(b.clone(), stale_ephemeral);
        let _nodestore_batcher = state
            .machines
            .configure_nodestore_write_batcher(1, Duration::from_secs(5));
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &a).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&b));
        let _ = state.machines.drain_pending_map_changes();

        let history_len = state.machines.map_change_history().len();
        let removed = state.machines.gc_ephemeral(Duration::from_secs(60));
        assert_eq!(removed, vec![b.clone()]);
        assert!(state.machines.get(&b).is_none());

        let changes = state.machines.map_change_history();
        let change = changes
            .get(history_len)
            .expect("worker GC records a peer-removal map change");
        assert_eq!(change.reason_labels(), vec!["peers removed"]);
        assert_eq!(change.change_type(), "peers");
        assert_eq!(change.content.peers_removed, vec![stable_id_from_key(&b)]);
        assert!(change.content.peers_changed.is_empty());
        assert!(change.content.peer_patches.is_empty());
        assert!(
            state
                .machines
                .pending_map_changes()
                .contains_key(&stable_id_from_key(&a)),
            "worker GC peer removal should be queued for the map batcher"
        );

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "worker GC peer removal must wait for the map-batch tick"
        );
        publish_test_map_batch().await;

        let mr = next_zstd_map_response(&mut body).await;
        assert!(mr.peers.is_empty());
        assert!(mr.peers_changed.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
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
    async fn stream_true_batched_policy_reload_removes_only_newly_hidden_peer() {
        let (state, _dir) = fixture();
        let initial_policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["bob@:*", "carol@:*"]}
            ]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(initial_policy).unwrap(),
            initial_policy.into(),
        );

        let alice = "a5".repeat(32);
        let bob = "b5".repeat(32);
        let carol = "c5".repeat(32);
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            bob.clone(),
            policy_record(&bob, "bob", 11, "bob", Vec::new()),
        );
        state.machines.upsert(
            carol.clone(),
            policy_record(&carol, "carol", 12, "carol", Vec::new()),
        );
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut alice_body = open_zstd_stream(app, &alice).await;
        let first_mr = next_zstd_map_response(&mut alice_body).await;
        let initial_peer_ids = first_mr
            .peers
            .iter()
            .map(|peer| peer.id)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            initial_peer_ids,
            BTreeSet::from([stable_id_from_key(&bob), stable_id_from_key(&carol)])
        );
        assert!(
            first_mr
                .user_profiles
                .iter()
                .any(|profile| profile.login_name == "carol"),
            "initial full map should include the profile for the visible peer that will be hidden"
        );
        let _ = state.machines.drain_pending_map_changes();
        let alice_id = stable_id_from_key(&alice);
        assert_eq!(
            state.machines.active_connections().get(&alice_id),
            Some(&1),
            "Alice stream should be active before policy reload"
        );
        let generated_before = state.machines.mapresponse_generated_metrics();
        let full_before = generated_before.get("full").copied().unwrap_or_default();
        let policy_before = generated_before.get("policy").copied().unwrap_or_default();

        let restrictive_policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["bob@:*"]}
            ]
        }"#;
        state.policy.set_quiet(
            crate::policy::parse_hujson_policy(restrictive_policy).unwrap(),
            restrictive_policy.into(),
        );
        let snapshot = state.machines.snapshot();
        let served_routes = served_routes_for_snapshot(&snapshot);
        let allowed_after_reload =
            allowed_peer_ids_for_snapshot(&state.policy, &snapshot, &alice, &served_routes)
                .expect("restrictive policy should build a peer map");
        assert_eq!(
            allowed_after_reload,
            BTreeSet::from([stable_id_from_key(&bob)]),
            "policy reload should narrow Alice's visible peers before stream batching"
        );

        let mut pending_frame = Box::pin(http_body_util::BodyExt::frame(&mut alice_body));
        assert!(
            pending_frame.as_mut().now_or_never().is_none(),
            "observer stream should be parked before policy reload"
        );

        state.policy.notify_change();
        tokio::task::yield_now().await;
        let immediate = pending_frame.as_mut().now_or_never();
        assert!(
            immediate.is_none(),
            "batched policy reload should wait for the map-batch tick"
        );

        for _ in 0..10 {
            if state.machines.pending_map_changes().contains_key(&alice_id) {
                break;
            }
            tokio::task::yield_now().await;
        }
        let pending = state.machines.pending_map_changes();
        let alice_changes = pending
            .get(&alice_id)
            .expect("parked observer stream should enqueue a policy-change batch");
        assert_eq!(alice_changes.len(), 1);
        assert_eq!(alice_changes[0].reason_labels(), vec!["policy change"]);
        publish_test_map_batch().await;

        let frame = pending_frame.await.unwrap().unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let delta: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(
            delta.node.is_none(),
            "policy visibility narrowing should be a peer delta, not a full self map"
        );
        assert!(delta.peers.is_empty());
        assert!(delta.peers_changed.is_empty());
        assert!(delta.peers_changed_patch.is_empty());
        assert_eq!(delta.peers_removed, vec![stable_id_from_key(&carol)]);
        assert!(
            delta.dns_config.is_some(),
            "policy reload deltas should carry policy-derived DNS updates"
        );
        let profile_names = delta
            .user_profiles
            .iter()
            .map(|profile| profile.login_name.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(profile_names, BTreeSet::from(["alice", "bob"]));

        let generated_after = state.machines.mapresponse_generated_metrics();
        assert_eq!(
            generated_after.get("full").copied().unwrap_or_default(),
            full_before,
            "batched policy reload must not generate a stale full map"
        );
        assert_eq!(
            generated_after.get("policy").copied().unwrap_or_default(),
            policy_before + 1,
            "batched policy reload should generate one policy delta"
        );
        tokio::task::yield_now().await;
        let extra = http_body_util::BodyExt::frame(&mut alice_body).now_or_never();
        assert!(
            extra.is_none(),
            "policy visibility narrowing should emit only one observer delta"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_policy_reload_auto_approval_waits_for_batch_tick() {
        let (state, _dir) = fixture();
        let initial_policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["10.88.0.0/16:*"]}
            ]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(initial_policy).unwrap(),
            initial_policy.into(),
        );

        let alice = "88".repeat(32);
        let router_key = "89".repeat(32);
        let route = "10.88.1.0/24";
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        let mut router_record = policy_record(&router_key, "router", 11, "router", Vec::new());
        router_record.available_routes = vec![route.to_string()];
        state.machines.upsert(router_key.clone(), router_record);
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut router_body = open_zstd_stream(app.clone(), &router_key).await;
        let _router_first = next_zstd_map_response(&mut router_body).await;
        let mut alice_body = open_zstd_stream(app.clone(), &alice).await;
        let first_mr = next_zstd_map_response(&mut alice_body).await;
        assert!(
            first_mr.peers.is_empty(),
            "unapproved advertised route must not make router visible"
        );
        let _ = state.machines.drain_pending_map_changes();
        let history_len = state.machines.map_change_history().len();

        let reloaded_policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["10.88.0.0/16:*"]}
            ],
            "autoApprovers": {
                "routes": {"10.88.0.0/16": ["router@"]}
            }
        }"#;
        state.policy.set_quiet(
            crate::policy::parse_hujson_policy(reloaded_policy).unwrap(),
            reloaded_policy.into(),
        );

        let changes = state.machines.map_change_history();
        assert_eq!(
            changes.len(),
            history_len,
            "policy reload should not record route auto-approval until the stream observes it"
        );

        let mut pending_frame = Box::pin(http_body_util::BodyExt::frame(&mut alice_body));
        assert!(
            pending_frame.as_mut().now_or_never().is_none(),
            "observer stream should be parked before policy reload"
        );

        state.policy.notify_change();
        tokio::task::yield_now().await;
        let immediate = pending_frame.as_mut().now_or_never();
        assert!(
            immediate.is_none(),
            "policy reload must not emit a stale pre-auto-approval frame before the map-batch tick"
        );
        assert_eq!(
            state
                .machines
                .get(&router_key)
                .expect("router remains registered")
                .approved_routes,
            vec![route.to_string()]
        );
        let changes = state.machines.map_change_history();
        let approval_change = changes
            .get(history_len)
            .expect("policy reload auto-approval records a map change");
        assert_eq!(approval_change.reason_labels(), vec!["policy change"]);
        assert_eq!(approval_change.change_type(), "policy");
        assert!(approval_change.content.include_policy);
        assert!(approval_change.content.requires_runtime_peer_computation);
        let pending = state.machines.pending_map_changes();
        assert!(
            pending.contains_key(&stable_id_from_key(&alice)),
            "observer should have a queued policy batch after reload notification"
        );

        publish_test_map_batch().await;

        let frame = pending_frame.await.unwrap().unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let delta: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert!(
            delta.node.is_none(),
            "batched policy reload should be a peer delta, not a full map"
        );
        assert!(delta.peers.is_empty());
        assert!(delta.peers_removed.is_empty());
        assert!(delta.peers_changed_patch.is_empty());
        assert!(
            delta.dns_config.is_some(),
            "policy reload deltas should carry policy-derived DNS updates"
        );
        let peer = changed_peer(&delta, "router").expect("router peer delta");
        assert!(peer.allowed_ips.iter().any(|allowed| allowed == route));
        assert!(
            peer.primary_routes.iter().any(|primary| primary == route),
            "first policy reload frame should already include route auto-approval state"
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

    #[tokio::test]
    async fn stream_true_quiet_last_seen_touch_is_absorbed_on_next_wake() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let c = "cc".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

        let app = router(state.clone());
        let mut body = open_zstd_stream(app.clone(), &b).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&a));
        assert!(first_mr.peers[0].last_seen.is_some());

        let before = state.machines.get(&a).unwrap().last_seen;
        tokio::time::sleep(Duration::from_millis(3)).await;
        let req_body = serde_json::json!({ "OmitPeers": true, "Version": 113 });
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
        assert!(state.machines.get(&a).unwrap().last_seen > before);

        assert_no_stream_frame(&mut body, Duration::from_millis(50)).await;

        insert_peer(&state, &c, "peer-c", 12);
        let mr = next_zstd_map_response(&mut body).await;
        assert_eq!(mr.peers_changed.len(), 1);
        assert_eq!(mr.peers_changed[0].id, stable_id_from_key(&c));
        assert!(
            mr.peers_changed
                .iter()
                .all(|peer| peer.id != stable_id_from_key(&a)),
            "timestamp-only peer-a churn must not become a delayed full peer delta"
        );
        assert!(
            mr.peers_changed_patch
                .iter()
                .all(|patch| patch.node_id != stable_id_from_key(&a)),
            "timestamp-only peer-a churn must not become a delayed peer patch"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_worker_quiet_last_seen_touch_stays_quiet_through_batch_tick() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let c = "cc".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);
        let _nodestore_batcher = state
            .machines
            .configure_nodestore_write_batcher(1, Duration::from_secs(5));
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app.clone(), &b).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&a));

        let before = state.machines.get(&a).unwrap().last_seen;
        std::thread::sleep(Duration::from_millis(3));
        let req_body = serde_json::json!({ "OmitPeers": true, "Version": 113 });
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
        assert!(state.machines.get(&a).unwrap().last_seen > before);

        assert_no_stream_frame(&mut body, Duration::from_millis(50)).await;
        publish_test_map_batch().await;
        assert_no_stream_frame(&mut body, Duration::from_millis(50)).await;

        insert_peer(&state, &c, "peer-c", 12);
        publish_test_map_batch().await;
        let mr = next_zstd_map_response(&mut body).await;
        assert_eq!(mr.peers_changed.len(), 1);
        assert_eq!(mr.peers_changed[0].id, stable_id_from_key(&c));
        assert!(
            mr.peers_changed
                .iter()
                .all(|peer| peer.id != stable_id_from_key(&a)),
            "worker-batched timestamp-only churn must not become a delayed peer delta"
        );
        assert!(
            mr.peers_changed_patch
                .iter()
                .all(|patch| patch.node_id != stable_id_from_key(&a)),
            "worker-batched timestamp-only churn must not become a delayed patch delta"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_self_expiry_update_emits_self_node_key_expiry() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);

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
            metrics.contains("headscale_mapresponse_generated_total{response_type=\"self\"} 1\n")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_direct_peer_expiry_uses_full_peer_update() {
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
        assert!(mr.peers_removed.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        assert_eq!(mr.peers_changed.len(), 1);
        let peer = &mr.peers_changed[0];
        assert_eq!(peer.id, stable_id_from_key(&a));
        assert_eq!(peer.key_expiry, Some(expiry));
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_worker_batched_direct_expiry_updates_wait_for_map_tick() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let observer = "cc".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);
        insert_peer(&state, &observer, "observer", 12);
        let _nodestore_batcher = state
            .machines
            .configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app, &observer).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 2);
        assert!(first_mr.peers.iter().all(|peer| peer.key_expiry.is_none()));
        let _ = state.machines.drain_pending_map_changes();

        let history_len = state.machines.map_change_history().len();
        let expiry_a = chrono::Utc::now() + chrono::Duration::days(7);
        let expiry_b = chrono::Utc::now() + chrono::Duration::days(8);
        let machines = state.machines.clone();
        let a_for_update = a.clone();
        let first_update =
            std::thread::spawn(move || machines.set_expiry(&a_for_update, Some(expiry_a)));

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while state.machines.nodestore_queue_depth() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "queued key-expiry update did not reach the NodeStore worker"
            );
            std::thread::sleep(Duration::from_millis(5));
        }

        assert!(state.machines.set_expiry(&b, Some(expiry_b)));
        assert!(
            first_update
                .join()
                .expect("queued key-expiry update should finish")
        );

        let changes = state.machines.map_change_history();
        let new_labels = changes[history_len..]
            .iter()
            .map(MapChange::reason_label)
            .collect::<Vec<_>>();
        assert_eq!(new_labels, vec!["node added", "node added"]);

        let observer_id = stable_id_from_key(&observer);
        let pending = state.machines.pending_map_changes();
        let pending_labels = pending
            .get(&observer_id)
            .expect("observer has pending worker-batched key-expiry changes")
            .iter()
            .flat_map(MapChange::reason_labels)
            .collect::<Vec<_>>();
        assert_eq!(pending_labels, vec!["node added", "node added"]);

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "worker-batched key-expiry updates must wait for the map-batch tick"
        );
        publish_test_map_batch().await;

        let mr = next_zstd_map_response(&mut body).await;
        assert!(mr.peers.is_empty());
        assert!(mr.peers_removed.is_empty());
        assert!(mr.peers_changed_patch.is_empty());
        let changed = mr
            .peers_changed
            .iter()
            .map(|peer| (peer.id, peer.key_expiry))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(
            changed,
            BTreeMap::from([
                (stable_id_from_key(&a), Some(expiry_a)),
                (stable_id_from_key(&b), Some(expiry_b)),
            ])
        );
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
    async fn stream_true_batched_map_request_auto_approval_uses_policy_reason() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["10.31.0.0/16:*"]}
            ],
            "autoApprovers": {
                "routes": {"10.31.0.0/16": ["router@"]}
            }
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let alice = "f1".repeat(32);
        let router_key = "f2".repeat(32);
        let route = "10.31.1.0/24";
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            router_key.clone(),
            policy_record(&router_key, "router", 11, "router", Vec::new()),
        );
        let _batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut router_body = open_zstd_stream(app.clone(), &router_key).await;
        let _router_first = next_zstd_map_response(&mut router_body).await;
        let mut alice_body = open_zstd_stream(app.clone(), &alice).await;
        let first_mr = next_zstd_map_response(&mut alice_body).await;
        assert!(
            first_mr.peers.is_empty(),
            "router is hidden until it serves an auto-approved route"
        );
        let _ = state.machines.drain_pending_map_changes();

        let history_len = state.machines.map_change_history().len();
        let update_req = serde_json::json!({
            "Version": 113,
            "OmitPeers": true,
            "Hostinfo": {
                "RoutableIPs": [route]
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
        assert!(raw.is_empty());

        let changes = state.machines.map_change_history();
        let change = changes
            .get(history_len)
            .expect("auto-approval map request records a map change");
        assert_eq!(change.reason_labels(), vec!["policy change"]);
        assert_eq!(change.change_type(), "policy");
        assert!(change.content.include_policy);
        assert!(change.content.requires_runtime_peer_computation);

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut alice_body).now_or_never();
        assert!(
            immediate.is_none(),
            "auto-approval map changes should wait for the map-batch tick"
        );
        publish_test_map_batch().await;

        let delta = next_zstd_map_response(&mut alice_body).await;
        assert!(delta.peers.is_empty());
        assert!(delta.peers_removed.is_empty());
        assert!(delta.peers_changed_patch.is_empty());
        assert!(
            delta.dns_config.is_some(),
            "policy-reasoned route auto-approval should carry policy-derived DNS updates"
        );
        let peer = changed_peer(&delta, "router").expect("router peer delta");
        assert!(peer.allowed_ips.iter().any(|allowed| allowed == route));
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_worker_batched_map_request_auto_approval_waits_for_map_tick() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["10.32.0.0/16:*"]}
            ],
            "autoApprovers": {
                "routes": {"10.32.0.0/16": ["router@"]}
            }
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let alice = "32".repeat(32);
        let router_key = "33".repeat(32);
        let route = "10.32.1.0/24";
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            router_key.clone(),
            policy_record(&router_key, "router", 11, "router", Vec::new()),
        );
        let _nodestore_batcher = state
            .machines
            .configure_nodestore_write_batcher(1, Duration::from_secs(5));
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut router_body = open_zstd_stream(app.clone(), &router_key).await;
        let _router_first = next_zstd_map_response(&mut router_body).await;
        let mut alice_body = open_zstd_stream(app.clone(), &alice).await;
        let first_mr = next_zstd_map_response(&mut alice_body).await;
        assert!(
            first_mr.peers.is_empty(),
            "router is hidden until it serves an auto-approved route"
        );
        let _ = state.machines.drain_pending_map_changes();

        let history_len = state.machines.map_change_history().len();
        let generated_before = state.machines.mapresponse_generated_metrics();
        let full_before = generated_before.get("full").copied().unwrap_or_default();
        let policy_before = generated_before.get("policy").copied().unwrap_or_default();
        let update_req = serde_json::json!({
            "Version": 113,
            "OmitPeers": true,
            "Hostinfo": {
                "RoutableIPs": [route]
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
        assert!(raw.is_empty());

        let changes = state.machines.map_change_history();
        let change = changes
            .get(history_len)
            .expect("worker auto-approval map request records a map change");
        assert_eq!(change.reason_labels(), vec!["policy change"]);
        assert_eq!(change.change_type(), "policy");
        assert!(change.content.include_policy);
        assert!(change.content.requires_runtime_peer_computation);
        assert!(
            state
                .machines
                .pending_map_changes()
                .contains_key(&stable_id_from_key(&alice)),
            "worker-applied auto-approval should be queued for the map batcher"
        );

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut alice_body).now_or_never();
        assert!(
            immediate.is_none(),
            "worker auto-approval map changes should wait for the map-batch tick"
        );
        assert_eq!(
            state
                .machines
                .mapresponse_generated_metrics()
                .get("full")
                .copied()
                .unwrap_or_default(),
            full_before,
            "worker-applied auto-approval must not emit a stale full update before the batch tick"
        );

        publish_test_map_batch().await;

        let delta = next_zstd_map_response(&mut alice_body).await;
        assert!(
            delta.node.is_none(),
            "worker-batched route auto-approval should be a peer delta, not a full map"
        );
        assert!(delta.peers.is_empty());
        assert!(delta.peers_removed.is_empty());
        assert!(delta.peers_changed_patch.is_empty());
        assert!(
            delta.dns_config.is_some(),
            "policy-reasoned route auto-approval should carry policy-derived DNS updates"
        );
        let peer = changed_peer(&delta, "router").expect("router peer delta");
        assert!(peer.allowed_ips.iter().any(|allowed| allowed == route));

        let generated_after = state.machines.mapresponse_generated_metrics();
        assert_eq!(
            generated_after.get("full").copied().unwrap_or_default(),
            full_before,
            "worker-batched route auto-approval must not generate a full follow-up response"
        );
        assert_eq!(
            generated_after.get("policy").copied().unwrap_or_default(),
            policy_before + 1,
            "worker-batched route auto-approval should generate one policy peer delta"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_set_approved_routes_many_fans_out_one_policy_delta() {
        let (state, _dir) = fixture();
        let observer = "41".repeat(32);
        let router_key = "42".repeat(32);
        let routes = vec!["10.42.1.0/24".to_string(), "10.42.2.0/24".to_string()];
        state.machines.upsert(
            observer.clone(),
            policy_record(&observer, "observer", 10, "observer", Vec::new()),
        );
        let mut router_record = policy_record(&router_key, "router", 11, "router", Vec::new());
        router_record.available_routes = routes.clone();
        state.machines.upsert(router_key.clone(), router_record);
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut router_body = open_zstd_stream(app.clone(), &router_key).await;
        let _router_first = next_zstd_map_response(&mut router_body).await;
        let mut observer_body = open_zstd_stream(app, &observer).await;
        let first_mr = next_zstd_map_response(&mut observer_body).await;
        let router_peer = peer_named(&first_mr, "router").expect("router peer visible");
        for route in &routes {
            assert!(
                !router_peer
                    .allowed_ips
                    .iter()
                    .any(|allowed| allowed == route),
                "unapproved advertised routes must not be sent as AllowedIPs"
            );
        }
        let _ = state.machines.drain_pending_map_changes();

        let history_len = state.machines.map_change_history().len();
        let generated_before = state.machines.mapresponse_generated_metrics();
        let full_before = generated_before.get("full").copied().unwrap_or_default();
        let policy_before = generated_before.get("policy").copied().unwrap_or_default();

        let (changed, missing) = state
            .machines
            .set_approved_routes_many(vec![(router_key.clone(), routes.clone())]);
        assert_eq!(changed, 1);
        assert!(missing.is_empty());
        assert_eq!(
            state
                .machines
                .get(&router_key)
                .expect("router still registered")
                .approved_routes,
            routes
        );

        let changes = state.machines.map_change_history();
        let change = changes
            .get(history_len)
            .expect("batched route approval records a map change");
        assert_eq!(change.reason_labels(), vec!["policy change"]);
        assert_eq!(change.change_type(), "policy");
        assert!(change.content.include_policy);
        assert!(change.content.requires_runtime_peer_computation);
        let pending = state.machines.pending_map_changes();
        let observer_changes = pending
            .get(&stable_id_from_key(&observer))
            .expect("policy route approval should fan out to the observer stream");
        assert_eq!(
            observer_changes.len(),
            1,
            "one batched approval should enqueue one observer map change"
        );

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut observer_body).now_or_never();
        assert!(
            immediate.is_none(),
            "batched route approvals should wait for the map-batch tick"
        );
        assert_eq!(
            state
                .machines
                .mapresponse_generated_metrics()
                .get("full")
                .copied()
                .unwrap_or_default(),
            full_before,
            "batched route approval must not emit a stale full update before the batch tick"
        );

        publish_test_map_batch().await;

        let delta = next_zstd_map_response(&mut observer_body).await;
        assert!(
            delta.node.is_none(),
            "batched route approval should be a peer delta, not a full map"
        );
        assert!(delta.peers.is_empty());
        assert!(delta.peers_removed.is_empty());
        assert!(delta.peers_changed_patch.is_empty());
        assert!(
            delta.dns_config.is_some(),
            "policy-reasoned route approval should carry policy-derived DNS updates"
        );
        let peer = changed_peer(&delta, "router").expect("router peer delta");
        for route in &routes {
            assert!(
                peer.allowed_ips.iter().any(|allowed| allowed == route),
                "approved route {route} should be sent as a route-derived AllowedIP"
            );
            assert!(
                peer.primary_routes.iter().any(|primary| primary == route),
                "approved route {route} should be marked primary for the only route owner"
            );
        }

        let generated_after = state.machines.mapresponse_generated_metrics();
        assert_eq!(
            generated_after.get("full").copied().unwrap_or_default(),
            full_before,
            "batched route approval must not generate a full follow-up response"
        );
        assert_eq!(
            generated_after.get("policy").copied().unwrap_or_default(),
            policy_before + 1,
            "batched route approval should generate one policy peer delta"
        );
        tokio::task::yield_now().await;
        let extra = http_body_util::BodyExt::frame(&mut observer_body).now_or_never();
        assert!(
            extra.is_none(),
            "one batched route approval should emit only one observer delta"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_batches_peer_online_and_route_approval_into_one_policy_delta() {
        let (state, _dir) = fixture();
        let observer = "45".repeat(32);
        let peer_key = "46".repeat(32);
        let router_key = "47".repeat(32);
        let route = "10.47.1.0/24".to_string();
        state.machines.upsert(
            observer.clone(),
            policy_record(&observer, "observer", 10, "observer", Vec::new()),
        );
        state.machines.upsert(
            peer_key.clone(),
            policy_record(&peer_key, "peer", 11, "peer", Vec::new()),
        );
        let mut router_record = policy_record(&router_key, "router", 12, "router", Vec::new());
        router_record.available_routes = vec![route.clone()];
        state.machines.upsert(router_key.clone(), router_record);
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut router_body = open_zstd_stream(app.clone(), &router_key).await;
        let router_first = next_zstd_map_response(&mut router_body).await;
        assert_eq!(
            router_first.node.as_ref().and_then(|node| node.online),
            Some(true)
        );

        let mut observer_body = open_zstd_stream(app.clone(), &observer).await;
        let first_mr = next_zstd_map_response(&mut observer_body).await;
        let peer = peer_named(&first_mr, "peer").expect("peer visible before connect");
        assert_eq!(peer.online, Some(false));
        let router_peer = peer_named(&first_mr, "router").expect("router visible before approval");
        assert_eq!(router_peer.online, Some(true));
        assert!(
            !router_peer
                .allowed_ips
                .iter()
                .any(|allowed| allowed == &route),
            "unapproved advertised route must not be sent as an AllowedIP"
        );
        let _ = state.machines.drain_pending_map_changes();
        let history_len = state.machines.map_change_history().len();

        let mut peer_body = open_zstd_stream(app, &peer_key).await;
        let peer_first = next_zstd_map_response(&mut peer_body).await;
        assert_eq!(
            peer_first.node.as_ref().and_then(|node| node.online),
            Some(true)
        );

        let (changed, missing) = state
            .machines
            .set_approved_routes_many(vec![(router_key.clone(), vec![route.clone()])]);
        assert_eq!(changed, 1);
        assert!(missing.is_empty());

        let changes = state.machines.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(
            new_changes
                .iter()
                .map(MapChange::reason_labels)
                .collect::<Vec<_>>(),
            vec![vec!["node online", "policy change"], vec!["policy change"]]
        );
        let pending = state.machines.pending_map_changes();
        let observer_changes = pending
            .get(&stable_id_from_key(&observer))
            .expect("observer receives the batched lifecycle and route changes");
        assert_eq!(
            observer_changes
                .iter()
                .map(MapChange::reason_labels)
                .collect::<Vec<_>>(),
            vec![vec!["node online", "policy change"], vec!["policy change"]]
        );

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut observer_body).now_or_never();
        assert!(
            immediate.is_none(),
            "mixed lifecycle/route changes should wait for the map-batch tick"
        );
        publish_test_map_batch().await;

        let delta = next_zstd_map_response(&mut observer_body).await;
        assert!(
            delta.node.is_none(),
            "ordinary peer lifecycle plus route approval should stay incremental"
        );
        assert!(delta.peers.is_empty());
        assert!(delta.peers_removed.is_empty());
        assert!(
            delta.dns_config.is_some(),
            "policy-reasoned batched changes should carry policy-derived DNS updates"
        );
        assert_eq!(delta.peers_changed_patch.len(), 1);
        let patch = &delta.peers_changed_patch[0];
        assert_eq!(patch.node_id, stable_id_from_key(&peer_key));
        assert_eq!(patch.online, Some(true));

        let router_delta = changed_peer(&delta, "router").expect("router route peer delta");
        assert!(
            router_delta
                .allowed_ips
                .iter()
                .any(|allowed| allowed == &route),
            "approved route should be sent as a route-derived AllowedIP"
        );
        assert_eq!(router_delta.primary_routes, vec![route]);

        tokio::task::yield_now().await;
        let extra = http_body_util::BodyExt::frame(&mut observer_body).now_or_never();
        assert!(
            extra.is_none(),
            "one mixed lifecycle/route batch should emit only one observer delta"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_worker_update_many_delete_same_batch_emits_only_peers_removed() {
        let (state, _dir) = fixture();
        let observer = "43".repeat(32);
        let router_key = "44".repeat(32);
        let routes = vec!["10.44.1.0/24".to_string(), "10.44.2.0/24".to_string()];
        state.machines.upsert(
            observer.clone(),
            policy_record(&observer, "observer", 10, "observer", Vec::new()),
        );
        let mut router_record = policy_record(&router_key, "router", 11, "router", Vec::new());
        router_record.available_routes = routes.clone();
        state.machines.upsert(router_key.clone(), router_record);
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut observer_body = open_zstd_stream(app, &observer).await;
        let first_mr = next_zstd_map_response(&mut observer_body).await;
        let router_peer = peer_named(&first_mr, "router").expect("router peer visible");
        for route in &routes {
            assert!(
                !router_peer
                    .allowed_ips
                    .iter()
                    .any(|allowed| allowed == route),
                "unapproved advertised routes must not be sent as AllowedIPs"
            );
        }
        let _ = state.machines.drain_pending_map_changes();

        let _nodestore_batcher = state
            .machines
            .configure_nodestore_write_batcher(2, Duration::from_secs(5));
        let history_len = state.machines.map_change_history().len();
        let router_id = stable_id_from_key(&router_key);
        let machines = state.machines.clone();
        let router_for_update = router_key.clone();
        let routes_for_update = routes.clone();
        let update = std::thread::spawn(move || {
            machines.set_approved_routes_many(vec![(router_for_update, routes_for_update)])
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while state.machines.nodestore_queue_depth() == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "queued update-many did not reach the NodeStore worker"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            state
                .machines
                .get(&router_key)
                .expect("router update should still be queued")
                .approved_routes
                .is_empty(),
            "queued update-many should wait for another item or the timeout"
        );

        assert!(state.machines.delete(&router_key));
        let (changed, missing) = update
            .join()
            .expect("queued update-many should finish after same-batch delete");
        assert_eq!(
            changed, 0,
            "same-batch delete should clear the stale update-many completion"
        );
        assert!(missing.is_empty());

        let changes = state.machines.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(new_changes.len(), 1, "{new_changes:?}");
        assert_eq!(new_changes[0].reason_labels(), vec!["peers removed"]);
        assert_eq!(new_changes[0].content.peers_removed, vec![router_id]);
        assert!(new_changes[0].content.peers_changed.is_empty());
        assert!(new_changes[0].content.peer_patches.is_empty());
        let pending = state.machines.pending_map_changes();
        let observer_changes = pending
            .get(&stable_id_from_key(&observer))
            .expect("same-batch delete should queue a peer removal for the observer");
        assert_eq!(observer_changes.len(), 1);
        assert_eq!(observer_changes[0].reason_labels(), vec!["peers removed"]);

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut observer_body).now_or_never();
        assert!(
            immediate.is_none(),
            "same-batch update-many/delete should wait for the map-batch tick"
        );
        publish_test_map_batch().await;

        let delta = next_zstd_map_response(&mut observer_body).await;
        assert!(delta.peers.is_empty());
        assert!(delta.peers_changed.is_empty());
        assert!(delta.peers_changed_patch.is_empty());
        assert_eq!(delta.peers_removed, vec![router_id]);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_initial_routable_ips_wake_peer_with_allowed_ips() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["10.40.0.0/16:*"]}
            ],
            "autoApprovers": {
                "routes": {"10.40.0.0/16": ["router@"]}
            }
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let alice = "d1".repeat(32);
        let router_key = "d2".repeat(32);
        let route = "10.40.1.0/24";
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            router_key.clone(),
            policy_record(&router_key, "router", 11, "router", Vec::new()),
        );
        let _map_batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut alice_body = open_zstd_stream(app.clone(), &alice).await;
        let alice_first = next_zstd_map_response(&mut alice_body).await;
        assert!(
            alice_first.peers.is_empty(),
            "router is hidden until its initial stream request advertises an allowed route"
        );
        let _ = state.machines.drain_pending_map_changes();
        let history_len = state.machines.map_change_history().len();

        let router_req = serde_json::json!({
            "Stream": true,
            "Version": 113,
            "Compress": "zstd",
            "Hostinfo": {
                "RoutableIPs": [route]
            },
        });
        let router_resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{router_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&router_req).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(router_resp.status(), StatusCode::OK);

        let mut router_body = router_resp.into_body();
        let router_first = next_zstd_map_response(&mut router_body).await;
        let self_node = router_first.node.as_ref().expect("router self node");
        assert!(
            self_node
                .hostinfo
                .routable_ips
                .iter()
                .any(|advertised| advertised == route)
        );
        assert!(
            self_node.allowed_ips.iter().any(|allowed| allowed == route),
            "router self node should be route-aware in its first stream response"
        );

        let router_id = stable_id_from_key(&router_key);
        let alice_id = stable_id_from_key(&alice);
        let changes = state.machines.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(
            new_changes.len(),
            2,
            "initial stream route auto-approval should record lifecycle plus deferred policy changes"
        );
        let online_change = &new_changes[0];
        assert_eq!(online_change.reason_labels(), vec!["subnet router online"]);
        assert_eq!(online_change.change_type(), "full");
        assert!(online_change.is_full());
        assert_eq!(online_change.origin_node_id, Some(router_id));
        let policy_change = &new_changes[1];
        assert_eq!(policy_change.reason_labels(), vec!["policy change"]);
        assert_eq!(policy_change.change_type(), "policy");
        assert!(policy_change.content.include_policy);
        assert!(policy_change.content.requires_runtime_peer_computation);
        assert_eq!(policy_change.origin_node_id, Some(router_id));
        assert!(!policy_change.is_full());

        let pending = state.machines.pending_map_changes();
        let alice_changes = pending
            .get(&alice_id)
            .expect("observer receives initial route auto-approval changes");
        assert_eq!(
            alice_changes
                .iter()
                .map(MapChange::reason_labels)
                .collect::<Vec<_>>(),
            vec![vec!["subnet router online"], vec!["policy change"]]
        );

        publish_test_map_batch().await;
        let alice_delta = tokio::time::timeout(
            Duration::from_secs(1),
            next_zstd_map_response(&mut alice_body),
        )
        .await
        .expect("observer route-aware peer delta");
        assert!(
            alice_delta.node.is_some(),
            "subnet-router online lifecycle emits a full map update"
        );
        assert!(alice_delta.peers_changed.is_empty());
        assert!(alice_delta.peers_removed.is_empty());
        assert!(alice_delta.peers_changed_patch.is_empty());
        let peer = alice_delta
            .peers
            .iter()
            .find(|peer| peer.id == stable_id_from_key(&router_key))
            .expect("router peer in full subnet-router online update");
        assert_eq!(peer.id, stable_id_from_key(&router_key));
        assert_eq!(peer.name, "router");
        assert!(
            peer.hostinfo
                .routable_ips
                .iter()
                .any(|advertised| advertised == route)
        );
        assert!(
            peer.allowed_ips.iter().any(|allowed| allowed == route),
            "observer should see route-derived AllowedIPs from the router's initial stream request"
        );
    }

    #[tokio::test]
    async fn stream_true_route_update_waits_until_connect_after_persistence() {
        let (mut state, _dir) = fixture();
        let policy = r#"{
            "acls": [
                {"action":"accept","src":["alice@"],"dst":["10.41.0.0/16:*"]}
            ],
            "autoApprovers": {
                "routes": {"10.41.0.0/16": ["router@"]}
            }
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(policy).unwrap(),
            policy.into(),
        );

        let alice = "e1".repeat(32);
        let router_key = "e2".repeat(32);
        let route = "10.41.1.0/24";
        state.machines.upsert(
            alice.clone(),
            policy_record(&alice, "alice", 10, "alice", Vec::new()),
        );
        state.machines.upsert(
            router_key.clone(),
            policy_record(&router_key, "router", 11, "router", Vec::new()),
        );

        let app = router(state.clone());
        let mut alice_body = open_zstd_stream(app.clone(), &alice).await;
        let alice_first = next_zstd_map_response(&mut alice_body).await;
        assert!(
            alice_first.peers.is_empty(),
            "router is hidden until its initial stream request advertises an allowed route"
        );

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        state.registration_store = Some(Arc::new(BlockingRuntimeSyncStore {
            entered: tokio::sync::Mutex::new(Some(entered_tx)),
            release: tokio::sync::Mutex::new(Some(release_rx)),
        }));
        let app_with_store = router(state.clone());

        let router_task = tokio::spawn({
            let app = app_with_store.clone();
            let router_key = router_key.clone();
            async move {
                let router_req = serde_json::json!({
                    "Stream": true,
                    "Version": 113,
                    "Compress": "zstd",
                    "Hostinfo": {
                        "RoutableIPs": [route]
                    },
                });
                let resp = app
                    .oneshot(
                        axum::http::Request::builder()
                            .method("POST")
                            .uri(format!("/machine/nodekey:{router_key}/map"))
                            .header("content-type", "application/json")
                            .body(axum::body::Body::from(
                                serde_json::to_vec(&router_req).unwrap(),
                            ))
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(resp.status(), StatusCode::OK);
                resp.into_body()
            }
        });

        entered_rx.await.expect("runtime persistence started");
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                next_zstd_map_response(&mut alice_body),
            )
            .await
            .is_err(),
            "streaming route updates must not notify peers before the router is connected"
        );

        release_tx.send(()).expect("release runtime persistence");
        let mut router_body = router_task.await.expect("router stream opens");
        let router_first = next_zstd_map_response(&mut router_body).await;
        let router_self = router_first.node.as_ref().expect("router self node");
        assert!(
            router_self
                .allowed_ips
                .iter()
                .any(|allowed| allowed == route)
        );

        let alice_delta = tokio::time::timeout(
            Duration::from_secs(1),
            next_zstd_map_response(&mut alice_body),
        )
        .await
        .expect("observer route-aware peer delta");
        assert!(
            alice_delta.node.is_some(),
            "subnet-router online lifecycle emits a full map update after persistence"
        );
        assert!(alice_delta.peers_changed.is_empty());
        assert!(alice_delta.peers_removed.is_empty());
        assert!(alice_delta.peers_changed_patch.is_empty());
        let peer = alice_delta
            .peers
            .iter()
            .find(|peer| peer.id == stable_id_from_key(&router_key))
            .expect("router peer present after connect");
        assert!(
            peer.allowed_ips.iter().any(|allowed| allowed == route),
            "observer should only see the route update once the router is online"
        );
        assert_eq!(peer.online, Some(true));
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
        assert!(
            delta.dns_config.is_some(),
            "route-health failover uses upstream policy-change delta shape"
        );

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
    async fn stream_true_route_health_all_unhealthy_retains_last_known_primary() {
        let (state, _dir) = fixture();
        let alice = "d4".repeat(32);
        let router_a = "d5".repeat(32);
        let router_b = "d6".repeat(32);
        let route = "10.40.2.0/24";

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
        let mut alice_body = open_zstd_stream(app.clone(), &alice).await;

        let first = next_zstd_map_response(&mut alice_body).await;
        let initial_primary = first
            .peers
            .iter()
            .find(|peer| peer.allowed_ips.iter().any(|ip| ip == route))
            .expect("initial primary route owner");
        let initial_primary_id = initial_primary.id;
        let failover_id = [stable_id_from_key(&router_a), stable_id_from_key(&router_b)]
            .into_iter()
            .find(|id| *id != initial_primary_id)
            .expect("second router id present");

        assert!(
            state
                .machines
                .set_route_candidate_health(initial_primary_id, false)
        );
        let failover_delta = next_zstd_map_response(&mut alice_body).await;
        let failover_peer = failover_delta
            .peers_changed
            .iter()
            .find(|peer| peer.id == failover_id)
            .expect("failover primary peer delta");
        assert!(
            failover_peer.allowed_ips.iter().any(|ip| ip == route),
            "healthy failover router should receive the route"
        );
        assert_eq!(failover_peer.primary_routes, vec![route.to_string()]);

        assert!(
            !state
                .machines
                .set_route_candidate_health(failover_id, false),
            "marking every HA candidate unhealthy retains the last known primary"
        );
        assert!(!state.machines.is_route_candidate_healthy(failover_id));
        assert_no_stream_frame(&mut alice_body, Duration::from_millis(50)).await;

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

        let retained_primary = mr
            .peers
            .iter()
            .find(|peer| peer.id == failover_id)
            .expect("last known primary remains visible");
        assert!(
            retained_primary.allowed_ips.iter().any(|ip| ip == route),
            "all-unhealthy HA set should retain the last primary route AllowedIP"
        );
        assert_eq!(retained_primary.primary_routes, vec![route.to_string()]);

        let old_primary = mr
            .peers
            .iter()
            .find(|peer| peer.id == initial_primary_id)
            .expect("old primary remains visible as a peer");
        assert!(
            !old_primary.allowed_ips.iter().any(|ip| ip == route),
            "old unhealthy primary must not regain the route while failover primary is retained"
        );
        assert!(old_primary.primary_routes.is_empty());
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
    async fn stream_true_subnet_router_lifecycle_emits_full_map_response_like_headscale_go() {
        let (state, _dir) = fixture();
        let observer = "a5".repeat(32);
        let router_key = "b5".repeat(32);
        let route = "10.55.0.0/24";
        state.machines.upsert(
            observer.clone(),
            policy_record(&observer, "observer", 10, "observer", Vec::new()),
        );
        state.machines.upsert(
            router_key.clone(),
            routed_record(&router_key, "router", 11, vec![route.into()]),
        );
        state.machines.enable_map_batcher();

        let app = router(state.clone());
        let mut observer_body = open_zstd_stream(app.clone(), &observer).await;
        let first = next_zstd_map_response(&mut observer_body).await;
        let router_peer = peer_named(&first, "router").expect("router peer visible");
        assert_eq!(router_peer.online, Some(false));
        let _ = state.machines.drain_pending_map_changes();

        let mut router_body = open_zstd_stream(app, &router_key).await;
        let router_first = next_zstd_map_response(&mut router_body).await;
        let router_self = router_first.node.as_ref().expect("router self node");
        assert_eq!(router_self.online, Some(true));
        assert!(
            router_self.allowed_ips.iter().any(|ip| ip == route),
            "router self node should serve its approved subnet route"
        );

        let pending_online = state.machines.pending_map_changes();
        let observer_id = stable_id_from_key(&observer);
        let observer_changes = pending_online
            .get(&observer_id)
            .expect("subnet-router online change fans out to observer");
        assert!(observer_changes.iter().any(MapChange::is_full));
        let immediate = http_body_util::BodyExt::frame(&mut observer_body).now_or_never();
        assert!(
            immediate.is_none(),
            "subnet-router lifecycle full update should wait for the map-batch publish"
        );
        state
            .machines
            .publish_pending_map_changes()
            .expect("subnet-router online batch published");

        let online = next_zstd_map_response(&mut observer_body).await;
        assert!(online.node.is_some(), "full map includes self Node");
        assert!(online.peers_changed.is_empty());
        assert!(online.peers_changed_patch.is_empty());
        assert!(online.peers_removed.is_empty());
        let online_router = peer_named(&online, "router").expect("full map includes router peer");
        assert_eq!(online_router.online, Some(true));
        assert!(
            online_router.allowed_ips.iter().any(|ip| ip == route),
            "full map should carry the route-derived AllowedIPs"
        );

        drop(router_body);
        assert_no_stream_frame(&mut observer_body, Duration::from_secs(9)).await;
        tokio::time::advance(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let pending_offline = state.machines.pending_map_changes();
        let observer_changes = pending_offline
            .get(&observer_id)
            .expect("subnet-router offline change fans out to observer");
        assert!(observer_changes.iter().any(MapChange::is_full));
        let immediate = http_body_util::BodyExt::frame(&mut observer_body).now_or_never();
        assert!(
            immediate.is_none(),
            "subnet-router offline full update should wait for the map-batch publish"
        );
        state
            .machines
            .publish_pending_map_changes()
            .expect("subnet-router offline batch published");

        let offline = next_zstd_map_response(&mut observer_body).await;
        assert!(
            offline.node.is_some(),
            "offline full map includes self Node"
        );
        assert!(offline.peers_changed.is_empty());
        assert!(offline.peers_changed_patch.is_empty());
        assert!(offline.peers_removed.is_empty());
        let offline_router = peer_named(&offline, "router").expect("full map includes router peer");
        assert_eq!(offline_router.online, Some(false));
        assert!(
            !offline_router.allowed_ips.iter().any(|ip| ip == route),
            "offline router should no longer serve route-derived AllowedIPs"
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
        let public_app = public_router(state.clone());
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
            metrics.contains("headscale_mapresponse_generated_total{response_type=\"patch\"} 1\n")
        );
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

    #[tokio::test(start_paused = true)]
    async fn stream_true_batched_derp_update_uses_endpoint_derp_patch_reason() {
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
        let _batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app.clone(), &b).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].home_derp, 1);
        let _ = state.machines.drain_pending_map_changes();

        let history_len = state.machines.map_change_history().len();
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
        let raw = to_bytes(update_resp.into_body(), 32 * 1024).await.unwrap();
        assert!(raw.is_empty());

        let changes = state.machines.map_change_history();
        let change = changes
            .get(history_len)
            .expect("DERP map request records a map change");
        assert_eq!(change.reason_labels(), vec!["endpoint/DERP update"]);
        assert_eq!(change.change_type(), "patch");
        assert_eq!(change.content.peer_patches, vec![stable_id_from_key(&a)]);

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "batched DERP updates must wait for the map-batch tick"
        );
        publish_test_map_batch().await;

        let delta = next_zstd_map_response(&mut body).await;
        assert!(delta.peers.is_empty());
        assert!(delta.peers_changed.is_empty());
        assert!(delta.peers_removed.is_empty());
        assert_eq!(delta.peers_changed_patch.len(), 1);
        let patch = &delta.peers_changed_patch[0];
        assert_eq!(patch.node_id, stable_id_from_key(&a));
        assert!(patch.endpoints.is_empty());
        assert_eq!(patch.derp_region, 7);
        assert!(patch.disco_key.is_none());
        assert!(patch.online.is_none());
        assert!(patch.last_seen.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_batched_derp_patch_then_delete_emits_only_peers_removed() {
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
        let _batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app.clone(), &b).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].id, stable_id_from_key(&a));
        assert_eq!(first_mr.peers[0].home_derp, 1);
        let _ = state.machines.drain_pending_map_changes();

        let history_len = state.machines.map_change_history().len();
        let peer_id = stable_id_from_key(&a);
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
        let raw = to_bytes(update_resp.into_body(), 32 * 1024).await.unwrap();
        assert!(raw.is_empty());

        assert!(state.machines.delete(&a));

        let changes = state.machines.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(new_changes.len(), 2, "{new_changes:?}");
        assert_eq!(new_changes[0].reason_labels(), vec!["endpoint/DERP update"]);
        assert_eq!(new_changes[0].change_type(), "patch");
        assert_eq!(new_changes[0].content.peer_patches, vec![peer_id]);
        assert_eq!(new_changes[1].reason_labels(), vec!["peers removed"]);
        assert_eq!(new_changes[1].content.peers_removed, vec![peer_id]);

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "queued patch/delete changes must wait for the map-batch tick"
        );
        publish_test_map_batch().await;

        let delta = next_zstd_map_response(&mut body).await;
        assert!(delta.peers.is_empty());
        assert!(delta.peers_changed.is_empty());
        assert!(
            delta.peers_changed_patch.is_empty(),
            "stale patches for removed peers must be suppressed"
        );
        assert_eq!(delta.peers_removed, vec![peer_id]);
    }

    #[tokio::test(start_paused = true)]
    async fn stream_true_batched_derp_clear_uses_full_peer_delta_reason() {
        let (state, _dir) = fixture();
        let a = "ca".repeat(32);
        let b = "cb".repeat(32);
        let mut peer_a = MachineRecord::new_at(
            chrono::Utc::now(),
            a.clone(),
            TEST_MACHINE_KEY_HEX.to_string(),
            "u".into(),
            "peer-a".into(),
            Ipv4Addr::new(100, 64, 0, 10),
            false,
        );
        peer_a.replace_host_info(HostInfo {
            hostname: "peer-a".into(),
            net_info: Some(NetInfo {
                preferred_derp: 7,
                ..NetInfo::default()
            }),
            ..HostInfo::default()
        });
        state.machines.upsert(a.clone(), peer_a);
        insert_peer(&state, &b, "peer-b", 11);
        let _batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let mut body = open_zstd_stream(app.clone(), &b).await;
        let first_mr = next_zstd_map_response(&mut body).await;
        assert_eq!(first_mr.peers.len(), 1);
        assert_eq!(first_mr.peers[0].home_derp, 7);
        let _ = state.machines.drain_pending_map_changes();

        let history_len = state.machines.map_change_history().len();
        let update_req = serde_json::json!({
            "Version": 113,
            "OmitPeers": true,
            "Hostinfo": {
                "NetInfo": {
                    "PreferredDERP": 0
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
        let raw = to_bytes(update_resp.into_body(), 32 * 1024).await.unwrap();
        assert!(raw.is_empty());
        assert_eq!(
            state
                .machines
                .get(&a)
                .expect("peer-a still registered")
                .home_derp,
            0
        );

        let changes = state.machines.map_change_history();
        let change = changes
            .get(history_len)
            .expect("DERP clear records a map change");
        assert_eq!(change.reason_labels(), vec!["node updated"]);
        assert_eq!(change.change_type(), "peers");
        assert_eq!(change.content.peers_changed, vec![stable_id_from_key(&a)]);
        assert!(change.content.peer_patches.is_empty());
        assert!(!change.content.include_derp_map);

        tokio::task::yield_now().await;
        let immediate = http_body_util::BodyExt::frame(&mut body).now_or_never();
        assert!(
            immediate.is_none(),
            "batched DERP clears must wait for the map-batch tick"
        );
        publish_test_map_batch().await;

        let delta = next_zstd_map_response(&mut body).await;
        assert!(delta.node.is_none());
        assert!(delta.derp_map.is_none());
        assert!(delta.dns_config.is_none());
        assert!(delta.peers.is_empty());
        assert!(delta.peers_changed_patch.is_empty());
        assert!(delta.peers_removed.is_empty());
        assert_eq!(delta.peers_changed.len(), 1);
        let peer = &delta.peers_changed[0];
        assert_eq!(peer.id, stable_id_from_key(&a));
        assert_eq!(peer.home_derp, 0);
        assert!(peer.legacy_derp_string.is_empty());
        assert_eq!(
            peer.hostinfo
                .net_info
                .as_ref()
                .map_or(0, |net_info| net_info.preferred_derp),
            0
        );
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
        let node_id = node
            .get("ID")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let stable_id = node.get("StableID").and_then(|s| s.as_str()).unwrap_or("");
        assert_eq!(stable_id, node_id.to_string());
        assert!(node.get("Name").is_some());
    }

    /// Current headscale-go accepts Tailcfg map-session resume fields but
    /// does not populate `MapResponse.MapSessionHandle`/`Seq`; Tailcfg permits
    /// servers to ignore resume requests and start a fresh stream.
    #[tokio::test(start_paused = true)]
    async fn stream_true_ignores_map_session_resume_fields_like_headscale_go() {
        let (state, _dir) = fixture();
        let a = "aa".repeat(32);
        let b = "bb".repeat(32);
        let c = "cc".repeat(32);
        insert_peer(&state, &a, "peer-a", 10);
        insert_peer(&state, &b, "peer-b", 11);
        let _batcher = start_test_map_batcher(&state).await;

        let app = router(state.clone());
        let req_body = serde_json::json!({
            "Stream": true,
            "Version": 133,
            "Compress": "zstd",
            "MapSessionHandle": "client-resume-handle",
            "MapSessionSeq": 41,
        });
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
        let first = next_zstd_map_response(&mut body).await;
        assert_eq!(first.map_session_handle, "");
        assert_eq!(first.seq, 0);
        assert_eq!(first.peers.len(), 1);

        insert_peer(&state, &c, "peer-c", 12);
        tokio::task::yield_now().await;
        assert_no_stream_frame(&mut body, Duration::from_millis(24)).await;
        publish_test_map_batch().await;

        let delta = next_zstd_map_response(&mut body).await;
        assert_eq!(delta.map_session_handle, "");
        assert_eq!(delta.seq, 0);
        assert!(
            delta.peers.is_empty(),
            "batch-delivered follow-up chunks should use incremental peer deltas"
        );
        assert_eq!(delta.peers_changed.len(), 1);
        assert_eq!(delta.peers_changed[0].id, stable_id_from_key(&c));
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
                "PeerRelay": true,
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
        assert!(
            raw_str.contains("\"PeerRelay\""),
            "PeerRelay tag present on the wire: {raw_str}"
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
        assert!(peer_a.hostinfo.peer_relay);
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
    async fn map_response_projects_auto_update_runtime_config_to_cap_map() {
        let (mut state, _dir) = fixture();
        let mut runtime_config = crate::tailscale_wire::RuntimeConfigSnapshot::default();
        runtime_config.auto_update.enabled = true;
        state.runtime_config = Arc::new(runtime_config);

        let node_key = "d0".repeat(32);
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
        let peer_key = "d3".repeat(32);
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

        assert_default_auto_update(mr.node.as_ref().expect("own node present"), true);
        assert!(
            mr.peers.first().expect("peer present").cap_map.is_empty(),
            "peer CapMap should use upstream PeerCapMap filtering"
        );
    }

    #[tokio::test]
    async fn map_response_filters_peer_cap_map_like_upstream_peer_cap_map() {
        let (mut state, _dir) = fixture();
        let mut runtime_config = crate::tailscale_wire::RuntimeConfigSnapshot::default();
        runtime_config.auto_update.enabled = true;
        state.runtime_config = Arc::new(runtime_config);

        let viewer_key = "e0".repeat(32);
        insert_peer(&state, &viewer_key, "viewer", 10);

        let exit_key = "e1".repeat(32);
        let exit_routes = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];
        state.machines.upsert(
            exit_key.clone(),
            routed_record(&exit_key, "exit", 11, exit_routes),
        );

        let plain_key = "e2".repeat(32);
        insert_peer(&state, &plain_key, "plain", 12);

        let raw_policy = r#"{
            "acls": [
                {"action":"accept","src":["*"],"dst":["*:*"]}
            ],
            "nodeAttrs": [{
                "target": ["*"],
                "attr": ["suggest-exit-node", "randomize-client-port"]
            }]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );

        let exit_id = state.machines.stable_node_id_for_key(&exit_key);
        let plain_id = state.machines.stable_node_id_for_key(&plain_key);
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{viewer_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();

        let self_node = mr.node.as_ref().expect("own node present");
        assert!(self_node.cap_map.contains_key(CAPABILITY_ADMIN));
        assert!(self_node.cap_map.contains_key(CAPABILITY_FILE_SHARING));
        assert!(self_node.cap_map.contains_key(CAPABILITY_SSH));
        assert_default_auto_update(self_node, true);
        assert!(self_node.cap_map.contains_key(NODE_ATTR_SUGGEST_EXIT_NODE));
        assert!(self_node.cap_map.contains_key("randomize-client-port"));

        let exit_peer = mr
            .peers
            .iter()
            .find(|peer| peer.id == exit_id)
            .expect("exit peer present");
        assert_eq!(
            exit_peer.cap_map.keys().cloned().collect::<Vec<_>>(),
            vec![NODE_ATTR_SUGGEST_EXIT_NODE.to_string()]
        );

        let plain_peer = mr
            .peers
            .iter()
            .find(|peer| peer.id == plain_id)
            .expect("plain peer present");
        assert!(
            plain_peer.cap_map.is_empty(),
            "non-exit peer should not inherit baseline, runtime, or arbitrary policy caps"
        );
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
            attr = ["custom-node-attr", "ssh"]
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
        assert!(node.cap_map.contains_key("custom-node-attr"));
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

    #[tokio::test]
    async fn map_response_disable_ipv4_node_attr_strips_self_cgnat_address_only() {
        let (state, _dir) = fixture();
        let node_key = "f1".repeat(32);
        let mut rec = routed_record(&node_key, "self", 20, vec!["10.33.0.0/16".into()]);
        rec.ipv6 = Some("fd7a:115c:a1e0::20".parse().unwrap());
        state.machines.upsert(node_key.clone(), rec);
        let _route_guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&node_key),
        );
        insert_peer(&state, &"f2".repeat(32), "peer", 21);

        let raw_policy = r#"{
            "acls": [
                {"action":"accept","src":["*"],"dst":["*:*"]}
            ],
            "nodeAttrs": [{
                "target": ["*"],
                "attr": ["disable-ipv4"]
            }]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );

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

        assert_eq!(node.addresses, vec!["fd7a:115c:a1e0::20/128"]);
        assert!(!node.allowed_ips.contains(&"100.64.0.20/32".into()));
        assert!(node.allowed_ips.contains(&"fd7a:115c:a1e0::20/128".into()));
        assert!(node.allowed_ips.contains(&"10.33.0.0/16".into()));
        assert!(node.cap_map.contains_key(NODE_ATTR_DISABLE_IPV4));
    }

    #[tokio::test]
    async fn map_response_disable_ipv4_node_attr_strips_peer_cgnat_address_only() {
        let (state, _dir) = fixture();
        let viewer_key = "f3".repeat(32);
        insert_peer(&state, &viewer_key, "viewer", 22);

        let peer_key = "f4".repeat(32);
        let mut rec = routed_record(&peer_key, "peer", 23, vec!["10.44.0.0/16".into()]);
        rec.ipv6 = Some("fd7a:115c:a1e0::23".parse().unwrap());
        rec.forced_tags = vec!["tag:ipv6only".into()];
        state.machines.upsert(peer_key.clone(), rec);
        let _route_guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(&peer_key),
        );

        let raw_policy = r#"{
            "tagOwners": {"tag:ipv6only": ["alice@"]},
            "acls": [
                {"action":"accept","src":["*"],"dst":["*:*"]}
            ],
            "nodeAttrs": [{
                "target": ["tag:ipv6only"],
                "attr": ["disable-ipv4"]
            }]
        }"#;
        state.policy.set(
            crate::policy::parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );

        let peer_id = state.machines.stable_node_id_for_key(&peer_key);
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{viewer_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(br#"{"Version":113}"#.to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let peer = mr
            .peers
            .iter()
            .find(|peer| peer.id == peer_id)
            .expect("tagged peer present");

        assert_eq!(peer.addresses, vec!["fd7a:115c:a1e0::23/128"]);
        assert!(!peer.allowed_ips.contains(&"100.64.0.23/32".into()));
        assert!(peer.allowed_ips.contains(&"fd7a:115c:a1e0::23/128".into()));
        assert!(peer.allowed_ips.contains(&"10.44.0.0/16".into()));
        assert!(
            peer.cap_map.is_empty(),
            "disable-ipv4 shapes peer addresses but is not exposed in peer CapMap"
        );
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
