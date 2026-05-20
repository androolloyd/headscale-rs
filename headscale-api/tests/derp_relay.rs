//! Integration coverage for the embedded DERP layer.
//!
//! See `headscale-api/src/tailscale_wire/derp/` for the implementation.
//!
//! Per the task brief: **option 2 (sidecar)** — the actual DERP wire
//! protocol is delegated to a spawned `derper` Go binary. These tests
//! cover the parts we actually own in Rust:
//!
//!   - STUN UDP round-trip (`stun_listener_round_trip`)
//!   - `/derp/probe` always-200 (`probe_returns_200`)
//!   - `/derp/probe` HEAD method (`probe_accepts_head`)
//!   - `/bootstrap-dns` JSON shape with prepopulated cache
//!     (`bootstrap_dns_returns_cached_map`)
//!   - `/verify` allow/deny based on key presence
//!     (`verify_allows_well_formed_key`, `verify_rejects_empty_key`)
//!   - `/derp` placeholder 503 when no sidecar is running
//!     (`derp_route_503_without_sidecar`)
//!   - DerpMap region emission when enabled
//!     (`derp_region_lands_in_map_when_enabled`)
//!   - DerpServer lifecycle: STUN binds, sidecar status reported
//!     (`derp_server_starts_with_stun_only`,
//!      `derp_server_disabled_is_noop`,
//!      `derp_server_missing_binary_still_starts`)

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use headscale_api::tailscale_wire;
use headscale_api::tailscale_wire::derp::{
    BootstrapDnsResponse, DerpConfig, DerpHttpState, DerpServer, StunListener, VerifyRequest,
    VerifyResponse, decode_stun_binding_request, encode_stun_binding_response,
    stun::{MSG_TYPE_BINDING_REQUEST, MSG_TYPE_BINDING_RESPONSE, STUN_MAGIC_COOKIE},
};
use headscale_api::tailscale_wire::{
    AllocError, IpAllocator, KnockConfig, MachineRegistry, PreauthRedeemer, RedeemError,
    RedeemOk, ServerNoiseKey, WireState,
};
use http_body_util::BodyExt;
use tower::ServiceExt;

struct RejectAll;
#[async_trait]
impl PreauthRedeemer for RejectAll {
    async fn redeem(&self, _: &str) -> Result<RedeemOk, RedeemError> {
        Err(RedeemError::Unknown)
    }
}
struct FixedAlloc;
impl IpAllocator for FixedAlloc {
    fn allocate(&self, _: &str) -> Result<Ipv4Addr, AllocError> {
        Ok(Ipv4Addr::new(100, 64, 0, 2))
    }
}

fn enabled_cfg() -> DerpConfig {
    DerpConfig {
        enabled: true,
        host_name: "derp.test.invalid".into(),
        derp_port: 443,
        region_id: 909,
        region_code: "test".into(),
        region_name: "Test".into(),
        ..DerpConfig::default()
    }
}

fn build_wire_state(derp: DerpHttpState) -> (WireState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
    let state = WireState {
        server_noise_key: server,
        preauth: Arc::new(RejectAll),
        ip_allocator: Arc::new(FixedAlloc),
        machines: Arc::new(MachineRegistry::new()),
        derp_map: Arc::new(headscale_api::tailscale_wire::wire::DerpMap::default()),
        policy: Arc::new(headscale_api::policy::PolicyStore::new()),
        knock: KnockConfig::disabled(),
        derp,
    };
    (state, dir)
}

#[tokio::test]
async fn probe_returns_200() {
    let state = DerpHttpState::new(enabled_cfg());
    let (wire, _dir) = build_wire_state(state);
    let app = tailscale_wire::router(wire);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/derp/probe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "*"
    );
}

#[tokio::test]
async fn probe_accepts_head() {
    let state = DerpHttpState::new(enabled_cfg());
    let (wire, _dir) = build_wire_state(state);
    let app = tailscale_wire::router(wire);
    let resp = app
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri("/derp/probe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn bootstrap_dns_returns_cached_map() {
    let state = DerpHttpState::new(enabled_cfg());
    {
        let mut w = state.bootstrap_dns.write();
        w.insert(
            "derp.test.invalid",
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))],
        );
    }
    let (wire, _dir) = build_wire_state(state);
    let app = tailscale_wire::router(wire);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/bootstrap-dns")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: BootstrapDnsResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        parsed.get("derp.test.invalid"),
        Some(&vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11))])
    );
}

#[tokio::test]
async fn verify_allows_well_formed_key() {
    let state = DerpHttpState::new(enabled_cfg());
    let (wire, _dir) = build_wire_state(state);
    let app = tailscale_wire::router(wire);
    let body = serde_json::to_vec(&VerifyRequest {
        client_public: "nodekey:1234abcd".into(),
    })
    .unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(parsed.allow);
}

#[tokio::test]
async fn verify_rejects_empty_key() {
    let state = DerpHttpState::new(enabled_cfg());
    let (wire, _dir) = build_wire_state(state);
    let app = tailscale_wire::router(wire);
    let body = serde_json::to_vec(&VerifyRequest {
        client_public: String::new(),
    })
    .unwrap();
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/verify")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(!parsed.allow);
}

#[tokio::test]
async fn derp_route_503_without_sidecar() {
    let state = DerpHttpState::new(enabled_cfg());
    let (wire, _dir) = build_wire_state(state);
    let app = tailscale_wire::router(wire);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/derp")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn derp_routes_absent_when_disabled() {
    let state = DerpHttpState::disabled();
    let (wire, _dir) = build_wire_state(state);
    let app = tailscale_wire::router(wire);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/derp/probe")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn stun_listener_round_trip() {
    let listener = StunListener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client.local_addr().unwrap();

    let txid = *b"abcdefghijkl";
    let mut req = Vec::with_capacity(20);
    req.extend_from_slice(&MSG_TYPE_BINDING_REQUEST.to_be_bytes());
    req.extend_from_slice(&0u16.to_be_bytes());
    req.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    req.extend_from_slice(&txid);
    client.send_to(&req, addr).await.unwrap();

    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut buf),
    )
    .await
    .expect("timeout")
    .expect("recv");
    let resp = &buf[..n];
    assert_eq!(
        u16::from_be_bytes([resp[0], resp[1]]),
        MSG_TYPE_BINDING_RESPONSE
    );
    assert_eq!(&resp[8..20], &txid);
    let x_port = u16::from_be_bytes([resp[26], resp[27]]);
    let decoded_port = x_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    assert_eq!(decoded_port, client_addr.port());
}

#[test]
fn stun_encode_decode_round_trip_is_byte_identical() {
    let txid = *b"112233445566";
    let remote: SocketAddr = "10.0.0.7:54321".parse().unwrap();
    let resp = encode_stun_binding_response(txid, remote);
    let mut got = [0u8; 12];
    got.copy_from_slice(&resp[8..20]);
    assert_eq!(got, txid);

    let mut req = Vec::with_capacity(20);
    req.extend_from_slice(&MSG_TYPE_BINDING_REQUEST.to_be_bytes());
    req.extend_from_slice(&0u16.to_be_bytes());
    req.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    req.extend_from_slice(&txid);
    let decoded = decode_stun_binding_request(&req).unwrap();
    assert_eq!(decoded, txid);
}

#[tokio::test]
async fn derp_server_disabled_is_noop() {
    let srv = DerpServer::start(DerpConfig::disabled()).await.unwrap();
    assert!(srv.stun_local_addr().is_none());
    assert!(srv.sidecar_status().is_none());
}

#[tokio::test]
async fn derp_server_starts_with_stun_only() {
    let cfg = DerpConfig {
        stun_addr: Some("127.0.0.1:0".parse().unwrap()),
        ..enabled_cfg()
    };
    let srv = DerpServer::start(cfg).await.unwrap();
    assert!(srv.stun_local_addr().is_some());
    assert!(srv.sidecar_status().is_none(), "no binary ⇒ no sidecar");
}

#[tokio::test]
async fn derp_server_missing_binary_still_starts() {
    let cfg = DerpConfig {
        stun_addr: Some("127.0.0.1:0".parse().unwrap()),
        derper_binary: std::path::PathBuf::from("/no/such/binary"),
        ..enabled_cfg()
    };
    let srv = DerpServer::start(cfg).await.unwrap();
    assert!(srv.stun_local_addr().is_some());
    assert!(srv.sidecar_status().is_none());
}

#[test]
fn derp_region_lands_in_map_when_enabled() {
    let cfg = DerpConfig {
        stun_addr: Some("0.0.0.0:3478".parse().unwrap()),
        ..enabled_cfg()
    };
    let region = cfg.derp_region().expect("region populated");
    assert_eq!(region.region_id, 909);
    assert_eq!(region.region_code, "test");
    assert_eq!(region.nodes.len(), 1);
    let node = &region.nodes[0];
    assert_eq!(node.host_name, "derp.test.invalid");
    assert_eq!(node.stun_port, 3478);
}

#[test]
fn derp_region_omitted_when_disabled() {
    assert!(DerpConfig::disabled().derp_region().is_none());
}

#[test]
fn config_round_trips_via_toml() {
    let cfg: DerpConfig = toml::from_str(
        r#"
        enabled = true
        host_name = "relay.example.com"
        derp_port = 8443
        region_id = 950
        region_code = "us-w-1"
        region_name = "US West"
    "#,
    )
    .unwrap();
    assert!(cfg.enabled);
    assert_eq!(cfg.host_name, "relay.example.com");
    assert_eq!(cfg.derp_port, 8443);
    assert_eq!(cfg.region_id, 950);
}
