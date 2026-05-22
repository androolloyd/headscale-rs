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
//! - **`Stream=true` framing: `[u32 LE size][zstd(JSON)]`.** Discovered
//!   while diagnosing Wall 5 in `docs/tailscale-interop-blocker.md`.
//!   Upstream's `tailscale/control/controlclient/direct.go::sendMapRequest`
//!   reads bytes with `binary.LittleEndian.Uint32(siz[:4])` then
//!   `zstdframe.AppendDecode(...)`. The framing is NOT newline-delimited,
//!   the body is NOT plaintext JSON, and the stream is NOT terminated
//!   naturally — the client expects keepalive frames carrying
//!   `zstd({"KeepAlive":true})` every <120 s (`watchdogTimeout`).
//!   Our `Stream=false` test path emits a single plaintext JSON
//!   `MapResponse` for the non-noise direct-router tests; the prod
//!   `Stream=true` path emits the framed/compressed stream.
//! - **Long-poll wake via `tokio::sync::Notify` on the registry.**
//!   Cheaper than a watch channel for the 2-peer test and the
//!   correctness story is simpler — every register notifies, every
//!   waiter wakes and recomputes the snapshot.
//! - **Keepalive interval = 30s.** Upstream watchdog is 120s, so this
//!   leaves 4x headroom for slow links. Keepalive bytes are
//!   `zstd_frame({"KeepAlive":true})`, NOT a bare newline.

use std::{
    collections::{BTreeSet, HashMap},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json,
    body::{Body, Bytes},
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// Decode a `MapRequest` from a raw body without requiring
/// `Content-Type: application/json`. Stock `tailscale up` (via
/// controlhttp over the noise tunnel) posts without the header set;
/// the `axum::Json` extractor 415s those requests. An empty body
/// decodes to the default-constructed `MapRequest`.
fn parse_map_body(raw: &[u8]) -> Result<MapRequest, Response> {
    if raw.is_empty() {
        return Ok(MapRequest::default());
    }
    serde_json::from_slice::<MapRequest>(raw).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: format!("invalid MapRequest JSON: {e}"),
            }),
        )
            .into_response()
    })
}
use serde::Serialize;

use super::register::record_to_map_node;
use super::routes::{active_exit_routes, auto_approved_routes_for_node, normalize_routes};
use super::wire::{
    DnsConfig, FilterRule, MapNode, MapRequest, MapResponse, NetPortRange, PortRange,
    stable_id_from_key, strip_key_prefix,
};
use super::{MachineRecord, WireState};

use crate::dns::{DnsStore, MachineDnsRecord};
use crate::policy::{NodeView, PeerMapNode, PolicyStore, SshPolicyNode};

/// Snapshot the registry into MagicDNS-record shape and ask the
/// operator-configured [`DnsStore`] to build the `DnsConfig` for this
/// MapResponse. Pulled into a helper so both the initial `map_inner`
/// build and the streaming `rebuild_map_chunk` use the same code path
/// — drift here would mean an ExtraRecords hot-reload only lands on
/// one of the two emission sites.
fn build_dns_for_snapshot(dns: &DnsStore, snapshot: &HashMap<String, MachineRecord>) -> DnsConfig {
    let machines: Vec<MachineDnsRecord> = snapshot
        .iter()
        .map(|(node_hex, rec)| MachineDnsRecord {
            hostname: rec.hostname.clone(),
            ipv4: rec.ipv4,
            node_id: stable_id_from_key(node_hex),
        })
        .collect();
    dns.build(&machines)
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

fn active_routes_for_snapshot(
    primary_routes: &HashMap<String, Vec<String>>,
    exit_routes: &HashMap<String, Vec<String>>,
) -> HashMap<String, Vec<String>> {
    let mut out = primary_routes.clone();
    for (node_key, routes) in exit_routes {
        let entry = out.entry(node_key.clone()).or_default();
        entry.extend(routes.iter().cloned());
        entry.sort();
        entry.dedup();
    }
    out
}

fn peer_map_nodes_from_snapshot(
    snapshot: &HashMap<String, MachineRecord>,
    active_routes: &HashMap<String, Vec<String>>,
) -> Vec<PeerMapNode> {
    snapshot
        .iter()
        .map(|(node_key, rec)| PeerMapNode {
            id: stable_id_from_key(node_key),
            addr: rec.ipv4.to_string(),
            user: (!rec.user.is_empty()).then(|| rec.user.clone()),
            tags: rec.forced_tags.clone(),
            routes: active_routes.get(node_key).cloned().unwrap_or_default(),
        })
        .collect()
}

fn allowed_peer_ids_for_snapshot(
    policy: &PolicyStore,
    snapshot: &HashMap<String, MachineRecord>,
    self_node_key: &str,
    active_routes: &HashMap<String, Vec<String>>,
) -> Option<BTreeSet<u64>> {
    let nodes = peer_map_nodes_from_snapshot(snapshot, active_routes);
    let peer_map = policy.build_peer_map(&nodes)?;
    let self_id = stable_id_from_key(self_node_key);
    Some(
        peer_map
            .get(&self_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect(),
    )
}

fn peer_allowed(allowed_ids: Option<&BTreeSet<u64>>, node_key: &str) -> bool {
    match allowed_ids {
        Some(ids) => ids.contains(&stable_id_from_key(node_key)),
        None => true,
    }
}

fn apply_routes_to_map_node(node: &mut MapNode, primary_routes: &[String], exit_routes: &[String]) {
    node.primary_routes = primary_routes.to_vec();
    node.allowed_ips = node.addresses.clone();
    node.allowed_ips.extend(primary_routes.iter().cloned());
    node.allowed_ips.extend(exit_routes.iter().cloned());
    node.allowed_ips.sort();
    node.allowed_ips.dedup();
}

fn apply_policy_attrs_to_map_node(
    node: &mut MapNode,
    rec: &super::MachineRecord,
    policy: &PolicyStore,
) {
    let addr = rec.ipv4.to_string();
    let view = NodeView {
        addr: Some(&addr),
        user: Some(&rec.user),
        tags: &rec.forced_tags,
    };
    for attr in policy.node_attrs_for(&view) {
        node.cap_map.entry(attr).or_default();
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
/// Headscale-go parity: the bypass uses the same IPv4+IPv6 zero-prefix
/// pair the ACL translator emits for `*` principals
/// (`headscale_api_acl::wildcard_filter_cidrs`), and one NetPortRange
/// per address family. Tailscale clients accept both `*` and the
/// cidr-pair, but the cidr-pair matches what upstream Go emits —
/// keeping both code paths in lockstep avoids a class of "works on
/// our policy path, breaks on the bypass" diff bugs.
pub(crate) fn allow_all_packet_filter() -> Vec<FilterRule> {
    let cidrs = headscale_api_acl::wildcard_filter_cidrs();
    let dst_ports = cidrs
        .iter()
        .map(|ip| NetPortRange {
            ip: ip.clone(),
            ports: PortRange {
                first: 0,
                last: 65535,
            },
        })
        .collect();
    vec![FilterRule {
        src_ips: cidrs,
        dst_ports,
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

fn ssh_policy_nodes_from_snapshot(
    snapshot: &std::collections::HashMap<String, super::MachineRecord>,
) -> Vec<SshPolicyNode> {
    snapshot
        .iter()
        .map(|(node_hex, rec)| SshPolicyNode {
            id: stable_id_from_key(node_hex),
            user: if rec.user.is_empty() {
                None
            } else {
                Some(rec.user.clone())
            },
            addrs: vec![rec.ipv4.to_string()],
            tags: rec.forced_tags.clone(),
        })
        .collect()
}

fn ssh_policy_for_snapshot(
    policy: &crate::policy::PolicyStore,
    snapshot: &std::collections::HashMap<String, super::MachineRecord>,
    self_node_key: &str,
) -> Option<super::wire::SshPolicy> {
    let nodes = ssh_policy_nodes_from_snapshot(snapshot);
    policy.ssh_policy_for(&nodes, stable_id_from_key(self_node_key))
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

pub async fn handle_map(
    State(state): State<WireState>,
    Path(node_key_path): Path<String>,
    raw: Bytes,
) -> Response {
    let req = match parse_map_body(&raw) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let node_key_hex = match strip_key_prefix(&node_key_path) {
        Some(h) => h.to_string(),
        None => node_key_path.clone(),
    };
    map_inner(state, node_key_hex, req).await
}

/// `POST /machine/map` (v1.78+ flat path).
///
/// NodeKey lives in the request body (`MapRequest.NodeKey`). The
/// keyed `/machine/{node_key}/map` route is kept for older clients.
pub async fn handle_map_flat(State(state): State<WireState>, raw: Bytes) -> Response {
    let req = match parse_map_body(&raw) {
        Ok(r) => r,
        Err(resp) => return resp,
    };
    let node_key_hex = match strip_key_prefix(&req.node_key) {
        Some(h) => h.to_string(),
        None => req.node_key.clone(),
    };
    if node_key_hex.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: "missing NodeKey in body".into(),
            }),
        )
            .into_response();
    }
    map_inner(state, node_key_hex, req).await
}

async fn map_inner(state: WireState, node_key_hex: String, req: MapRequest) -> Response {
    // The caller must already have registered. If not, 404 — they need
    // to go through `/machine/{node_key}/register` first.
    let Some(mut own) = state.machines.get(&node_key_hex) else {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorBody {
                error: "machine not registered".into(),
            }),
        )
            .into_response();
    };

    // P1 lifecycle: stamp `last_seen` on every /map arrival.
    // (Mirrors upstream's `db.UpdateNodeFromMapRequest`.) The COW
    // update is O(n) in registry size; the perf concern is documented
    // on `MachineRegistry::touch_last_seen` itself.
    state.machines.touch_last_seen(&node_key_hex);

    // P1 lifecycle: if `expiry` is set and elapsed, return a logout
    // response so the client tears down its session and re-registers.
    // Upstream behaviour at `hscontrol/poll.go::handlePoll` — a
    // `MapResponse` carrying `NodeKeyExpired: true` (plus the same
    // fields a fresh map would have, sans peers) tells stock
    // `tailscale` to fall back to its login flow.
    if own.is_expired_at(chrono::Utc::now()) {
        return logout_map_response(&own, &node_key_hex, &state.dns);
    }

    // Wall 7: persist client-provided DiscoKey + Endpoints from
    // `MapRequest` into the `MachineRecord` so subsequent map calls
    // for OTHER peers see them on this peer's `MapNode`. Stock
    // `tailscale` v1.78+ sends these on every map call (initial +
    // refresh); we treat any non-empty value as a fresh overwrite, and
    // `None` / empty as "keep what was there." This means a client
    // that omits the fields on one call doesn't accidentally clear
    // what previous calls established.
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
        let addr = own.ipv4.to_string();
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
        if own.available_routes != announced_routes {
            own.available_routes = announced_routes;
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

    // Build the response.
    let snapshot = state.machines.snapshot();
    let tailnet_domain = tailnet_domain(&state.dns);
    let primary_routes = state.machines.primary_routes_for_snapshot(&snapshot);
    let exit_routes = exit_routes_for_snapshot(&snapshot);
    let active_routes = active_routes_for_snapshot(&primary_routes, &exit_routes);
    let allowed_peer_ids =
        allowed_peer_ids_for_snapshot(&state.policy, &snapshot, &node_key_hex, &active_routes);
    let mut own_node = record_to_map_node(&own, &tailnet_domain);
    apply_routes_to_map_node(
        &mut own_node,
        primary_routes
            .get(&node_key_hex)
            .map(Vec::as_slice)
            .unwrap_or_default(),
        exit_routes
            .get(&node_key_hex)
            .map(Vec::as_slice)
            .unwrap_or_default(),
    );
    apply_policy_attrs_to_map_node(&mut own_node, &own, &state.policy);
    // #238: `snapshot()` returns `Arc<HashMap<…>>` — one Arc clone
    // total. Iterating borrows the map; we never clone individual
    // records. `record_to_map_node` takes `&MachineRecord` so the
    // borrowed iter feeds it directly.
    let mut peers: Vec<MapNode> = snapshot
        .iter()
        .filter(|(k, _)| k.as_str() != node_key_hex.as_str())
        .filter(|(k, _)| peer_allowed(allowed_peer_ids.as_ref(), k.as_str()))
        .map(|(node_key, rec)| {
            let mut node = record_to_map_node(rec, &tailnet_domain);
            apply_routes_to_map_node(
                &mut node,
                primary_routes
                    .get(node_key.as_str())
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
                exit_routes
                    .get(node_key.as_str())
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            );
            apply_policy_attrs_to_map_node(&mut node, rec, &state.policy);
            node
        })
        .collect();
    // Stable order so tests are deterministic.
    peers.sort_by_key(|n| n.id);

    let dns_config = build_dns_for_snapshot(&state.dns, &snapshot);
    let resp = MapResponse {
        node: Some(own_node),
        peers,
        user_profiles: Vec::new(),
        dns_config: Some(dns_config),
        // Wall 6: serve whatever DERP map the embedder loaded at
        // startup. Empty for non-interop deployments; the interop test
        // populates a one-region fixture pointing at the `derp-1`
        // sidecar (see `derp_config::load_derp_map`).
        derp_map: Some((*state.derp_map).clone()),
        domain: tailnet_domain,
        // Packet filter from the live `PolicyStore`. Falls back to
        // `allow_all_packet_filter` when no policy has been pushed —
        // preserves the Wall 7 default for the interop test, while
        // operator-managed deployments serve the cached
        // `FilterRule` list translated from the ACL doc.
        packet_filter: packet_filter_for(&state.policy),
        ssh_policy: ssh_policy_for_snapshot(&state.policy, &snapshot, &node_key_hex),
        // FULL MapResponse — NOT a keepalive. Upstream
        // `controlclient/direct.go::sendMapRequest` `continue`s past
        // the netmap-update handler when `KeepAlive=true`, which
        // means our full payload would be silently dropped. The bit
        // that prevented `BackendState` from advancing past
        // `NeedsLogin`. Dedicated keepalive frames go out via
        // [`build_keepalive_chunk`]'s separate `{"KeepAlive":true}`
        // payload — never inlined here.
        keep_alive: false,
        node_key_expired: false,
        ..MapResponse::default()
    };
    let _ = stable_id_from_key(&node_key_hex); // tickle import-used assertion

    if req.stream {
        // Stream:true — emit length-prefixed zstd-compressed
        // MapResponse JSON chunks. See module decision log for the
        // wire-format details. The first chunk goes out immediately;
        // subsequent chunks land either when the registry changes
        // (full MapResponse rebuild) or after [`MAP_KEEPALIVE_INTERVAL`]
        // (a compact `{"KeepAlive":true}` keepalive frame).
        //
        // Per `docs/tailscale-interop-blocker.md` "Wall 5":
        // the body must NOT terminate naturally — the client expects
        // to long-poll until it closes the connection itself.
        let first = match build_framed_chunk(&resp) {
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
        let derp_map_for_stream = state.derp_map.clone();
        let dns_for_stream = state.dns.clone();
        let connection_guard = super::MachineRegistry::track_stream_connection(
            machines.clone(),
            stable_id_from_key(&node_key_hex),
        );
        let stream = futures_util::stream::unfold(
            (
                Some(first),
                machines,
                gen_rx,
                policy,
                self_node_key,
                derp_map_for_stream,
                dns_for_stream,
                connection_guard,
            ),
            move |(
                first_opt,
                machines,
                mut gen_rx,
                policy,
                self_node_key,
                machines_derp_map,
                dns,
                connection_guard,
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
                            dns,
                            connection_guard,
                        ),
                    ));
                }
                // Wait for either a registry change, a policy change,
                // a DNS extra-records edit, or a keepalive tick,
                // whichever fires first.
                //
                // `gen_rx.changed()` is missed-update tolerant: if the
                // sender bumped the value between the previous chunk
                // emission and this select, the `changed()` future
                // returns immediately rather than parking. That's the
                // load-bearing property that closes the audit-2 C-1
                // race — see the registry's `wake_waiters` doc.
                let chunk = {
                    let policy_for_wait = policy.clone();
                    let policy_changed = policy_for_wait.wait_for_change();
                    let dns_for_wait = dns.clone();
                    let dns_changed = dns_for_wait.wait_for_change();
                    tokio::pin!(policy_changed);
                    tokio::pin!(dns_changed);
                    tokio::select! {
                    biased;
                    res = gen_rx.changed() => {
                        // `Err` only happens if every sender has been
                        // dropped — would mean the entire registry's
                        // gone, in which case we degrade to a
                        // keepalive frame and let the next iteration
                        // (or stream end) handle teardown.
                        if res.is_err() {
                            build_keepalive_chunk()
                        } else {
                            rebuild_map_chunk(&machines, &policy, &self_node_key, &machines_derp_map, &dns, "peers")
                        }
                    }
                    () = &mut policy_changed => {
                        // Policy edited via admin PUT — every parked
                        // poller wakes and emits a refreshed
                        // MapResponse with the new packet_filter.
                        rebuild_map_chunk(&machines, &policy, &self_node_key, &machines_derp_map, &dns, "policy")
                    }
                    () = &mut dns_changed => {
                        // Extra-records file edited (or DnsStore.set_spec
                        // called) — wake every parked poller so the
                        // next chunk carries the refreshed `DNSConfig`.
                        rebuild_map_chunk(&machines, &policy, &self_node_key, &machines_derp_map, &dns, "config")
                    }
                    () = tokio::time::sleep(MAP_KEEPALIVE_INTERVAL) => {
                        machines.record_mapresponse_sent_for_node(
                            "ok",
                            "keepalive",
                            stable_id_from_key(&self_node_key),
                        );
                        build_keepalive_chunk()
                    }
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
                        dns,
                        connection_guard,
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

/// Rebuild a single `MapResponse` chunk for an in-flight `Stream:true`
/// `/machine/map` poller. Called once per registry / policy wake; the
/// caller decides between this and `build_keepalive_chunk` based on
/// what fired in the select. If the requesting node has been deleted
/// from the registry between the wake and the rebuild, we emit a
/// keepalive instead of a stale MapResponse — the next iteration
/// handles teardown.
fn rebuild_map_chunk(
    machines: &Arc<crate::tailscale_wire::MachineRegistry>,
    policy: &Arc<crate::policy::PolicyStore>,
    self_node_key: &str,
    derp_map: &Arc<crate::tailscale_wire::wire::DerpMap>,
    dns: &Arc<DnsStore>,
    response_type: &str,
) -> Vec<u8> {
    let Some(own) = machines.get(self_node_key) else {
        return build_keepalive_chunk();
    };
    machines.record_mapresponse_generated(response_type);
    let snapshot = machines.snapshot();
    let tailnet_domain = tailnet_domain(dns);
    let primary_routes = machines.primary_routes_for_snapshot(&snapshot);
    let exit_routes = exit_routes_for_snapshot(&snapshot);
    let active_routes = active_routes_for_snapshot(&primary_routes, &exit_routes);
    let allowed_peer_ids =
        allowed_peer_ids_for_snapshot(policy, &snapshot, self_node_key, &active_routes);
    let mut own_node = record_to_map_node(&own, &tailnet_domain);
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
    apply_policy_attrs_to_map_node(&mut own_node, &own, policy);
    let mut peers: Vec<MapNode> = snapshot
        .iter()
        .filter(|(k, _)| k.as_str() != self_node_key)
        .filter(|(k, _)| peer_allowed(allowed_peer_ids.as_ref(), k.as_str()))
        .map(|(node_key, rec)| {
            let mut node = record_to_map_node(rec, &tailnet_domain);
            apply_routes_to_map_node(
                &mut node,
                primary_routes
                    .get(node_key.as_str())
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
                exit_routes
                    .get(node_key.as_str())
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            );
            apply_policy_attrs_to_map_node(&mut node, rec, policy);
            node
        })
        .collect();
    peers.sort_by_key(|n| n.id);
    let dns_config = build_dns_for_snapshot(dns, &snapshot);
    let mr = MapResponse {
        node: Some(own_node),
        peers,
        user_profiles: Vec::new(),
        dns_config: Some(dns_config),
        derp_map: Some((**derp_map).clone()),
        domain: tailnet_domain,
        packet_filter: packet_filter_for(policy),
        ssh_policy: ssh_policy_for_snapshot(policy, &snapshot, self_node_key),
        keep_alive: false,
        node_key_expired: false,
        ..MapResponse::default()
    };
    build_framed_chunk(&mr).unwrap_or_else(|_| build_keepalive_chunk())
}

/// P1 lifecycle: emit a `MapResponse` flagged as a forced logout. The
/// stock daemon reads `NodeKeyExpired: true` and falls back to its
/// register/login flow. We strip peers + packet_filter to keep the
/// payload minimal — the client only needs the expired bit.
fn logout_map_response(
    rec: &crate::tailscale_wire::MachineRecord,
    node_key_hex: &str,
    dns: &DnsStore,
) -> Response {
    let tailnet_domain = tailnet_domain(dns);
    let mr = MapResponse {
        node: Some(super::register::record_to_map_node(rec, &tailnet_domain)),
        peers: Vec::new(),
        user_profiles: Vec::new(),
        dns_config: Some(DnsConfig::default()),
        derp_map: Some(crate::tailscale_wire::wire::DerpMap::default()),
        domain: tailnet_domain,
        packet_filter: Vec::new(),
        ssh_policy: None,
        keep_alive: false,
        node_key_expired: true,
        ..MapResponse::default()
    };
    let _ = node_key_hex; // node_key_hex is part of the caller's context — pin for future logging.
    Json(mr).into_response()
}

/// Encode a MapResponse into the wire framing the streaming
/// `/machine/map` endpoint uses: `[u32 LE total size][zstd(JSON)]`.
/// The Go upstream encoder is `klauspost/compress/zstd`'s default
/// frame mode (`zstdframe.AppendEncode`); our `zstd::bulk::compress`
/// with default level produces frame-mode output that the upstream
/// decoder accepts without any custom dictionary.
pub(crate) fn build_framed_chunk(mr: &MapResponse) -> Result<Vec<u8>, std::io::Error> {
    let json_bytes =
        serde_json::to_vec(mr).map_err(|e| std::io::Error::other(format!("json encode: {e}")))?;
    let compressed = zstd::bulk::compress(&json_bytes, 3)
        .map_err(|e| std::io::Error::other(format!("zstd encode: {e}")))?;
    let mut out = Vec::with_capacity(4 + compressed.len());
    let len = compressed.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&compressed);
    Ok(out)
}

/// Build the keepalive frame: `[u32 LE size][zstd({"KeepAlive":true})]`.
/// Cached on the upstream side as `keepAliveZ` for the fast-path
/// compare — caching here is unnecessary because the responder
/// re-uses the same body bytes for every keepalive emission, and the
/// upstream still hashes the compressed bytes for its own cache.
pub(crate) fn build_keepalive_chunk() -> Vec<u8> {
    // `tailscale/control/controlclient/direct.go::justKeepAliveStr`
    // = `{"KeepAlive":true}` — matched byte-for-byte so the upstream
    // fast-path on cached compressed-bytes lights up.
    const KEEPALIVE_JSON: &[u8] = b"{\"KeepAlive\":true}";
    let compressed =
        zstd::bulk::compress(KEEPALIVE_JSON, 3).expect("zstd compress of static bytes never fails");
    let mut out = Vec::with_capacity(4 + compressed.len());
    let len = compressed.len() as u32;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&compressed);
    out
}

async fn wait_for_change(notify: Arc<tokio::sync::Notify>) {
    notify.notified().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{
        MachineRecord, MachineRegistry, WireState,
        noise::ServerNoiseKey,
        router,
        test_support::{MockIpAllocator, MockRedeemer},
        wire::DerpMap,
    };
    use axum::body::to_bytes;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn fixture() -> (WireState, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let state = WireState {
            server_noise_key: server,
            preauth: Arc::new(MockRedeemer::new()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
            derp_map: Arc::new(DerpMap::default()),
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: None,
            registration_cache: Arc::new(crate::tailscale_wire::RegistrationCache::new()),
        };
        (state, dir)
    }

    fn insert_peer(state: &WireState, node_hex: &str, host: &str, last_octet: u8) {
        state.machines.upsert(
            node_hex.to_string(),
            MachineRecord::new_at(
                chrono::Utc::now(),
                node_hex.to_string(),
                String::new(),
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
            String::new(),
            "u".into(),
            host.into(),
            Ipv4Addr::new(100, 64, 0, last_octet),
            false,
        );
        rec.available_routes = routes.clone();
        rec.approved_routes = routes;
        rec
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
            String::new(),
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
                        serde_json::to_vec(&serde_json::json!({})).unwrap(),
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
        assert_eq!(mr.peers.len(), 1);
        assert_eq!(mr.peers[0].addresses[0], "100.64.0.11/32");
        assert_eq!(mr.peers[0].name, "peer-b");
        assert_eq!(mr.domain, "");
        // Full MapResponse — must NOT be flagged as a keepalive.
        // Wall 5 regression: when `KeepAlive=true` the upstream client
        // skips the netmap-update handler and the daemon stays in
        // `NeedsLogin` forever.
        assert!(!mr.keep_alive);
    }

    #[tokio::test]
    async fn map_response_reduces_peers_when_policy_is_loaded() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "version": 1,
            "tag_owners": {"tag:server": ["alice@"]},
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
                        serde_json::to_vec(&serde_json::json!({})).unwrap(),
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
    async fn map_response_keeps_subnet_router_visible_when_policy_targets_route() {
        let (state, _dir) = fixture();
        let policy = r#"{
            "version": 1,
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

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{alice}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({})).unwrap(),
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
            "version": 1,
            "auto_approvers": {
                "routes": {"10.20.0.0/16": ["alice@"]},
                "exit_node": ["alice@"]
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
        let resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{alice}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({
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

        let metrics_resp = app
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
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{alice}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(b"{}".to_vec()))
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
                    .body(axum::body::Body::from(b"{}".to_vec()))
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

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(b"{}".to_vec()))
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

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{a}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(b"{}".to_vec()))
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
        for (node_key, host, last_octet) in [
            ("51".repeat(32), "router-a", 51),
            ("52".repeat(32), "router-b", 52),
            ("53".repeat(32), "router-c", 53),
        ] {
            state.machines.upsert(
                node_key.clone(),
                routed_record(&node_key, host, last_octet, vec![route.clone()]),
            );
        }

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
                    .body(axum::body::Body::from(b"{}".to_vec()))
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
                    .body(axum::body::Body::from(b"{}".to_vec()))
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
            "Version": 39,
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
                    .body(axum::body::Body::from(b"{}".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// Flat map rejects empty NodeKey body.
    #[tokio::test]
    async fn flat_map_rejects_missing_node_key() {
        let (state, _dir) = fixture();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/machine/map")
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(b"{}".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Decode a single `[u32 LE size][zstd(JSON)]` framed chunk back
    /// into the original JSON bytes. Mirrors what upstream
    /// `controlclient/direct.go::decodeMsg` does on the wire.
    fn decode_framed(bytes: &[u8]) -> Vec<u8> {
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
        zstd::bulk::decompress(&bytes[4..], 16 * 1024 * 1024).expect("valid zstd frame")
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
        let req_body = serde_json::json!({ "Stream": true, "Version": 39 });
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
        // length-prefixed + zstd-framed.
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
        assert_eq!(
            mr.peers.len(),
            1,
            "second chunk should include the newly-registered peer"
        );
        assert_eq!(mr.peers[0].addresses[0], "100.64.0.11/32");

        let metrics_resp = app
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

        let metrics_resp = app
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
        let req_body = serde_json::json!({ "Stream": true, "Version": 39 });
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
        // (peers.len == 1), NOT a keepalive.
        let frame = http_body_util::BodyExt::frame(&mut body)
            .await
            .unwrap()
            .unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(
            mr.peers.len(),
            1,
            "wake fired during chunk-build window must surface on the next chunk; \
             got keepalive instead, indicating the lost-wake race regressed"
        );
        assert_eq!(mr.peers[0].addresses[0], "100.64.0.11/32");
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

        let app = router(state);
        let req_body = serde_json::json!({ "Stream": true, "Version": 39 });
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

        let metrics_resp = app
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
        let req_body = serde_json::json!({ "Stream": true, "Version": 133 });
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

    /// Wall 7 round-trip: a MapRequest carrying `DiscoKey` +
    /// `Endpoints` for peer-a must persist into `MachineRecord` and
    /// then fan back out on peer-b's view of peer-a in the
    /// MapResponse.Peers list. Without this, `wgengine.Reconfig` on
    /// peer-b runs at `0/0 peers` and `tailscale ping` returns
    /// `unknown peer`.
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

        // Peer-a posts a /map call with DiscoKey + Endpoints set.
        let req_a = serde_json::json!({
            "Version": 39,
            "DiscoKey": &disco_a,
            "Endpoints": &endpoints_a,
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

        // Peer-b polls /map and must see peer-a's DiscoKey + Endpoints
        // on its MapNode entry. Pins both the wire-tag spelling and
        // the payload value.
        let req_b = serde_json::json!({ "Version": 39 });
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
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        assert_eq!(mr.peers.len(), 1);
        let peer_a = &mr.peers[0];
        assert_eq!(peer_a.disco_key.as_deref(), Some(disco_a.as_str()));
        assert_eq!(peer_a.endpoints, endpoints_a);
    }

    #[tokio::test]
    async fn map_response_includes_compiled_ssh_policy_for_target_node() {
        let (state, _dir) = fixture();
        let server = "bb".repeat(32);
        let admin = "cc".repeat(32);

        let mut server_rec = MachineRecord::new_at(
            chrono::Utc::now(),
            server.clone(),
            String::new(),
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
                String::new(),
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
                    .body(axum::body::Body::from(b"{}".to_vec()))
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
        assert_eq!(
            ssh.rules[0].action.session_duration,
            24 * 60 * 60 * 1_000_000_000
        );
    }

    #[tokio::test]
    async fn map_response_applies_node_attrs_to_cap_map() {
        let (state, _dir) = fixture();
        let node_key = "dd".repeat(32);
        let mut rec = MachineRecord::new_at(
            chrono::Utc::now(),
            node_key.clone(),
            String::new(),
            "alice".into(),
            "server".into(),
            Ipv4Addr::new(100, 64, 0, 13),
            false,
        );
        rec.forced_tags = vec!["tag:server".into()];
        state.machines.upsert(node_key.clone(), rec);

        let raw_policy = r#"{
            "tagOwners": {"tag:server": ["alice@"]},
            "acls": [],
            "nodeAttrs": [{
                "target": ["tag:server"],
                "attr": ["funnel", "ssh"]
            }]
        }"#;
        let doc = crate::policy::parse_hujson_policy(raw_policy).unwrap();
        state.policy.set(doc, raw_policy.to_string());

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(b"{}".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let raw = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let mr: MapResponse = serde_json::from_slice(&raw).unwrap();
        let node = mr.node.as_ref().expect("own node present");
        assert!(node.cap_map.contains_key("funnel"));
        assert!(node.cap_map.contains_key("ssh"));
    }

    /// Compatibility sample: a hand-built MapResponse, run through
    /// `build_framed_chunk`, must round-trip through the upstream
    /// decoding rule — `[u32 LE size][zstd(JSON)]` → `Node` present.
    /// Pins the framing against accidental regressions in
    /// `build_framed_chunk`.
    #[test]
    fn framed_chunk_matches_upstream_decoder_shape() {
        let mr = MapResponse {
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
            node_key_expired: false,
            ..MapResponse::default()
        };
        let bytes = build_framed_chunk(&mr).expect("framed chunk encodes");
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
}
