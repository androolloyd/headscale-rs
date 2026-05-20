//! Integration tests for the PSK-gated wire-control handshake.
//!
//! Two-layer coverage:
//!
//!   1. **Router-level**: build the wire router with KnockConfig
//!      enabled, drive it via `tower::ServiceExt::oneshot`, and assert
//!      that requests without a valid knock get the canonical nginx
//!      404 while requests with a valid knock pass through to the
//!      underlying `/key` handler (200 + JSON).
//!
//!   2. **Probe-resistance**: 100 randomized incorrect knock attempts
//!      against `/key` (the cheapest probe surface) all receive the
//!      SAME response body, byte for byte.
//!
//! See `tailscale_wire::knock` for the per-window HMAC math and the
//! 404-body byte-pin (`probe_resistance_404_body_stable`).

use std::net::Ipv4Addr;
use std::sync::Arc;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use headscale_api::{
    WireState, tailscale_wire,
    tailscale_wire::{
        AllocError, IpAllocator, KNOCK_HEADER, KnockConfig, MachineRegistry, NGINX_404_BODY,
        PreauthRedeemer, RedeemError, ServerNoiseKey,
    },
};
use http_body_util::BodyExt;
use tower::ServiceExt;

// Local fixtures (the real `test_support` module is `cfg(test)` so
// integration tests can't see it).
struct AlwaysRejectRedeemer;

#[async_trait]
impl PreauthRedeemer for AlwaysRejectRedeemer {
    async fn redeem(&self, _key: &str) -> Result<String, RedeemError> {
        Err(RedeemError::Unknown)
    }
}

struct FixedIpAllocator;

impl IpAllocator for FixedIpAllocator {
    fn allocate(&self, _node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
        Ok(Ipv4Addr::new(100, 64, 0, 2))
    }
}

// In-process fixture: build a wire router whose KnockConfig is the
// supplied one. PSK is the same 0..0x1f deterministic fixture used by
// the unit tests.
fn fixture(knock: KnockConfig) -> (WireState, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
    let state = WireState {
        server_noise_key: server,
        preauth: Arc::new(AlwaysRejectRedeemer),
        ip_allocator: Arc::new(FixedIpAllocator),
        machines: Arc::new(MachineRegistry::new()),
        derp_map: Arc::new(tailscale_wire::wire::DerpMap::default()),
        policy: Arc::new(headscale_api::policy::PolicyStore::new()),
        knock,
    };
    (state, dir)
}

fn fixed_psk() -> [u8; 32] {
    let mut psk = [0u8; 32];
    for (i, b) in psk.iter_mut().enumerate() {
        *b = i as u8;
    }
    psk
}

#[tokio::test]
async fn ts2021_knock_disabled_passes_through() {
    // KnockConfig disabled (default) — `/key` should serve as before.
    let (state, _dir) = fixture(KnockConfig::disabled());
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn ts2021_knock_enabled_rejects_no_knock() {
    let psk = fixed_psk();
    let (state, _dir) = fixture(KnockConfig::enabled(psk));
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/key")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), NGINX_404_BODY.as_bytes());
}

#[tokio::test]
async fn ts2021_knock_enabled_accepts_valid_header() {
    let psk = fixed_psk();
    let cfg = KnockConfig::enabled(psk);
    let computed = cfg.current_knock();

    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/key")
                .header(KNOCK_HEADER, computed)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn ts2021_knock_enabled_accepts_path_prefix() {
    let psk = fixed_psk();
    let cfg = KnockConfig::enabled(psk);
    let knock = cfg.current_knock();
    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/k/{knock}/key"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn ts2021_knock_bad_header_returns_canonical_404() {
    let psk = fixed_psk();
    let cfg = KnockConfig::enabled(psk);
    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/key")
                .header(KNOCK_HEADER, "deadbeefdeadbeef") // wrong knock
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), NGINX_404_BODY.as_bytes());
}

#[tokio::test]
async fn ts2021_knock_probe_resistance_100_randomized_attempts() {
    // 100 deterministic-but-arbitrary bogus knocks across the router
    // surface; every response body must be byte-identical (so a state
    // probe can't fingerprint the wire layer by response shape).
    let psk = fixed_psk();
    let cfg = KnockConfig::enabled(psk);
    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);

    let mut seed: u64 = 0xDECA_FBAD_1234_5678;
    let mut canonical_body: Option<Vec<u8>> = None;
    for _ in 0..100 {
        // splitmix64 → 8 random bytes → 16-hex bogus knock.
        seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        let z = z ^ (z >> 31);
        let bogus = hex::encode(z.to_le_bytes());

        // Header path.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/key")
                    .header(KNOCK_HEADER, &bogus)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();

        // Path-prefix path.
        let resp2 = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/k/{bogus}/key"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::NOT_FOUND);
        let body2 = resp2
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();

        assert_eq!(body, body2, "header vs path-prefix 404 bodies diverged");
        match &canonical_body {
            None => canonical_body = Some(body.clone()),
            Some(prev) => assert_eq!(prev, &body, "404 body diverged on bogus knock {bogus}"),
        }
    }
    let body = canonical_body.expect("at least one iteration");
    assert_eq!(body, NGINX_404_BODY.as_bytes());
}
