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

use std::{sync::Arc, time::Duration};

use axum::{
    body::{Body, Bytes},
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
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
use super::wire::{
    stable_id_from_key, strip_key_prefix, DnsConfig, FilterRule, MapNode, MapRequest, MapResponse,
    NetPortRange, PortRange,
};
use super::WireState;

/// How long we wait for a second peer to join before returning an
/// empty-peers `MapResponse`.
pub const MAP_LONGPOLL_TIMEOUT: Duration = Duration::from_secs(30);

/// Interval between newline keepalives when the client requested
/// `Stream: true`. Stock `tailscale` daemon accepts a keepalive of any
/// length as long as it arrives within its idle timeout (60s upstream);
/// 30s leaves headroom for slow links.
pub const MAP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);

/// MagicDNS domain emitted on every map response. Static for the
/// interop test.
const TAILNET_DOMAIN: &str = "octra.test";

/// Wall 7 (closed in the same commit batch as Wall 6 for the interop
/// path): the canonical "everyone can reach everyone on every port"
/// packet filter. Stock `tailscale` v1.78+ rejects inter-peer traffic
/// with `unknown peer` when `MapResponse.PacketFilter` is empty —
/// even though the netmap holds the target node. Production
/// deployments derive this list from the ACL surface; the interop
/// test runs with an open default so the ping assertion lands.
pub(crate) fn allow_all_packet_filter() -> Vec<FilterRule> {
    vec![FilterRule {
        src_ips: vec!["*".into()],
        dst_ports: vec![NetPortRange {
            ip: "*".into(),
            ports: PortRange {
                first: 0,
                last: 65535,
            },
        }],
        ip_proto: Vec::new(),
    }]
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
pub async fn handle_map_flat(
    State(state): State<WireState>,
    raw: Bytes,
) -> Response {
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
    if let Some(dk) = req.disco_key.as_ref().filter(|s| !s.is_empty()) {
        if own.disco_key.as_deref() != Some(dk.as_str()) {
            own.disco_key.clone_from(&Some(dk.clone()));
            record_changed = true;
        }
    }
    if let Some(eps) = req.endpoints.as_ref().filter(|v| !v.is_empty()) {
        if &own.endpoints != eps {
            own.endpoints.clone_from(eps);
            record_changed = true;
        }
    }
    if record_changed {
        state.machines.upsert(node_key_hex.clone(), own.clone());
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
    let own_node = record_to_map_node(&own, TAILNET_DOMAIN);
    let mut peers: Vec<MapNode> = state
        .machines
        .all()
        .into_iter()
        .filter(|(k, _)| k != &node_key_hex)
        .map(|(_, rec)| record_to_map_node(&rec, TAILNET_DOMAIN))
        .collect();
    // Stable order so tests are deterministic.
    peers.sort_by_key(|n| n.id);

    let resp = MapResponse {
        key_expiry_extension: 0,
        node: own_node,
        peers,
        dns_config: DnsConfig::default(),
        // Wall 6: serve whatever DERP map the embedder loaded at
        // startup. Empty for non-interop deployments; the interop test
        // populates a one-region fixture pointing at the `derp-1`
        // sidecar (see `derp_config::load_derp_map`).
        derp_map: (*state.derp_map).clone(),
        domain: TAILNET_DOMAIN.into(),
        // Wall 7: open packet filter. Required for inter-peer
        // traffic to land — see `allow_all_packet_filter`.
        packet_filter: allow_all_packet_filter(),
        // FULL MapResponse — NOT a keepalive. Upstream
        // `controlclient/direct.go::sendMapRequest` `continue`s past
        // the netmap-update handler when `KeepAlive=true`, which
        // means our full payload would be silently dropped. The bit
        // that prevented `BackendState` from advancing past
        // `NeedsLogin`. Dedicated keepalive frames go out via
        // [`build_keepalive_chunk`]'s separate `{"KeepAlive":true}`
        // payload — never inlined here.
        keep_alive: false,
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
        // on each registry wake.
        let machines = state.machines.clone();
        let notify = state.machines.notify.clone();
        let self_node_key = node_key_hex.clone();
        let derp_map_for_stream = state.derp_map.clone();
        let stream = futures_util::stream::unfold(
            (Some(first), machines, notify, self_node_key, derp_map_for_stream),
            move |(first_opt, machines, notify, self_node_key, machines_derp_map)| async move {
                if let Some(initial) = first_opt {
                    return Some((
                        Ok::<_, std::io::Error>(initial),
                        (None, machines, notify, self_node_key, machines_derp_map),
                    ));
                }
                // Wait for either a registry change or a keepalive
                // tick, whichever fires first. We park the `Notified`
                // future inside a small scope so the Arc isn't borrowed
                // when we re-wrap the state for the next iteration.
                let chunk = {
                    let notify_for_wait = notify.clone();
                    let notified = notify_for_wait.notified();
                    tokio::pin!(notified);
                    tokio::select! {
                    _ = &mut notified => {
                        // Registry changed — rebuild + emit a fresh
                        // MapResponse chunk. If our own machine vanished
                        // we emit a keepalive and let the next iteration
                        // handle teardown.
                        if let Some(own) = machines.get(&self_node_key) {
                            let own_node = record_to_map_node(&own, TAILNET_DOMAIN);
                            let mut peers: Vec<MapNode> = machines
                                .all()
                                .into_iter()
                                .filter(|(k, _)| k != &self_node_key)
                                .map(|(_, rec)| record_to_map_node(&rec, TAILNET_DOMAIN))
                                .collect();
                            peers.sort_by_key(|n| n.id);
                            let mr = MapResponse {
                                key_expiry_extension: 0,
                                node: own_node,
                                peers,
                                dns_config: DnsConfig::default(),
                                // Wall 6 — see comment in map_inner.
                                derp_map: (*machines_derp_map).clone(),
                                domain: TAILNET_DOMAIN.into(),
                                // Wall 7 — open packet filter.
                                packet_filter: allow_all_packet_filter(),
                                // Full payload — see comment in
                                // `map_inner` for why this must be
                                // `false`.
                                keep_alive: false,
                            };
                            build_framed_chunk(&mr).unwrap_or_else(|_| build_keepalive_chunk())
                        } else {
                            build_keepalive_chunk()
                        }
                    }
                    _ = tokio::time::sleep(MAP_KEEPALIVE_INTERVAL) => {
                        build_keepalive_chunk()
                    }
                    }
                };
                Some((
                    Ok(chunk),
                    (None, machines, notify, self_node_key, machines_derp_map),
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

/// Encode a MapResponse into the wire framing the streaming
/// `/machine/map` endpoint uses: `[u32 LE total size][zstd(JSON)]`.
/// The Go upstream encoder is `klauspost/compress/zstd`'s default
/// frame mode (`zstdframe.AppendEncode`); our `zstd::bulk::compress`
/// with default level produces frame-mode output that the upstream
/// decoder accepts without any custom dictionary.
pub(crate) fn build_framed_chunk(mr: &MapResponse) -> Result<Vec<u8>, std::io::Error> {
    let json_bytes = serde_json::to_vec(mr)
        .map_err(|e| std::io::Error::other(format!("json encode: {e}")))?;
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
        noise::ServerNoiseKey,
        router,
        test_support::{MockIpAllocator, MockRedeemer},
        wire::DerpMap,
        MachineRecord, MachineRegistry, WireState,
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
        };
        (state, dir)
    }

    fn insert_peer(state: &WireState, node_hex: &str, host: &str, last_octet: u8) {
        state.machines.upsert(
            node_hex.to_string(),
            MachineRecord {
                node_key_hex: node_hex.to_string(),
                machine_key_hex: String::new(),
                user: "u".into(),
                hostname: host.into(),
                ipv4: Ipv4Addr::new(100, 64, 0, last_octet),
                disco_key: None,
                endpoints: Vec::new(),
            },
        );
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
        assert_eq!(mr.node.addresses[0], "100.64.0.10/32");
        assert_eq!(mr.peers.len(), 1);
        assert_eq!(mr.peers[0].addresses[0], "100.64.0.11/32");
        assert_eq!(mr.peers[0].name, "peer-b.octra.test");
        assert_eq!(mr.domain, "octra.test");
        // Full MapResponse — must NOT be flagged as a keepalive.
        // Wall 5 regression: when `KeepAlive=true` the upstream client
        // skips the netmap-update handler and the daemon stays in
        // `NeedsLogin` forever.
        assert!(!mr.keep_alive);
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
        assert_eq!(mr.peers.len(), 1, "long-poll should have woken on B's register");
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
        assert_eq!(mr.node.addresses[0], "100.64.0.10/32");
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
        assert!(bytes.len() >= 4, "framed chunk too short: {} bytes", bytes.len());
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

        // Schedule the registry change for AFTER the unfold has parked
        // on `notify.notified()`. `notify_waiters` only wakes already-
        // parked waiters (it does NOT enqueue a pending notification),
        // so the spawn-with-delay ordering is required — without it
        // the wake fires before the listener is registered and the
        // subsequent `frame()` reads a keepalive instead.
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
        let frame = http_body_util::BodyExt::frame(&mut body).await.unwrap().unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        let mr: MapResponse = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(mr.peers.len(), 1);

        // Advance virtual time past one keepalive interval and confirm
        // the next chunk decodes to the canonical `{"KeepAlive":true}`
        // payload (matches upstream `justKeepAliveStr`).
        tokio::time::advance(MAP_KEEPALIVE_INTERVAL + Duration::from_millis(1)).await;
        let frame = http_body_util::BodyExt::frame(&mut body).await.unwrap().unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        assert_eq!(&decoded[..], br#"{"KeepAlive":true}"#);
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
        let frame = http_body_util::BodyExt::frame(&mut body).await.unwrap().unwrap();
        let chunk = frame.into_data().unwrap();
        let decoded = decode_framed(&chunk);
        // Inspect raw JSON: upstream decoder calls
        // `json.Unmarshal(b, v)` and then asserts `resp.Node != nil`.
        // We assert the field exists AND carries `User`/`StableID`.
        let json: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        let node = json.get("Node").expect("Node field present");
        assert!(node.get("User").and_then(|u| u.as_u64()).unwrap_or(0) > 0);
        assert!(node
            .get("StableID")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .starts_with('n'));
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

    /// Compatibility sample: a hand-built MapResponse, run through
    /// `build_framed_chunk`, must round-trip through the upstream
    /// decoding rule — `[u32 LE size][zstd(JSON)]` → `Node` present.
    /// Pins the framing against accidental regressions in
    /// `build_framed_chunk`.
    #[test]
    fn framed_chunk_matches_upstream_decoder_shape() {
        let mr = MapResponse {
            key_expiry_extension: 0,
            node: MapNode {
                id: 42,
                stable_id: "n42".into(),
                name: "peer-a.octra.test".into(),
                user: 7,
                key: format!("nodekey:{}", "aa".repeat(32)),
                machine: None,
                addresses: vec!["100.64.0.10/32".into()],
                allowed_ips: vec!["100.64.0.10/32".into()],
                hostinfo: crate::tailscale_wire::wire::HostInfo::default(),
                machine_authorized: true,
                disco_key: None,
                endpoints: Vec::new(),
            },
            peers: vec![],
            dns_config: DnsConfig::default(),
            derp_map: DerpMap::default(),
            domain: TAILNET_DOMAIN.into(),
            keep_alive: true,
            packet_filter: allow_all_packet_filter(),
        };
        let bytes = build_framed_chunk(&mr).expect("framed chunk encodes");
        // Decode the way upstream does.
        let size = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        assert_eq!(bytes.len(), 4 + size);
        let json_bytes =
            zstd::bulk::decompress(&bytes[4..], 16 * 1024 * 1024).expect("decompress ok");
        let v: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert!(v.get("Node").is_some(), "Node field present after framed encode");
        assert_eq!(
            v.get("Node").unwrap().get("User").and_then(|u| u.as_u64()),
            Some(7)
        );
    }
}
