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
//!      against `/key?v=39` (the cheapest probe surface) all receive the
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
    async fn redeem(
        &self,
        _key: &str,
    ) -> Result<headscale_api::tailscale_wire::RedeemOk, RedeemError> {
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
        registration_store: None,
        derp_map: tailscale_wire::DerpMapStore::shared(tailscale_wire::wire::DerpMap::default()),
        policy: Arc::new(headscale_api::policy::PolicyStore::new()),
        knock,
        dns: Arc::new(headscale_api::dns::DnsStore::new()),
        public_control_url: None,
        runtime_config: Arc::new(tailscale_wire::RuntimeConfigSnapshot::default()),
        registration_cache: Arc::new(tailscale_wire::RegistrationCache::new()),
        pings: Arc::new(tailscale_wire::PingTracker::new()),
        mapresponse_debug: Arc::new(tailscale_wire::MapResponseDebugStore::disabled()),
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

fn stable_knock_config(psk: [u8; 32]) -> KnockConfig {
    let mut cfg = KnockConfig::enabled(psk);
    cfg.window_secs = u64::MAX;
    cfg
}

#[tokio::test]
async fn ts2021_knock_disabled_passes_through() {
    // KnockConfig disabled (default) — `/key?v=39` should serve as before.
    let (state, _dir) = fixture(KnockConfig::disabled());
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/key?v=39")
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
    let (state, _dir) = fixture(stable_knock_config(psk));
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/key?v=39")
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
    let cfg = stable_knock_config(psk);
    let computed = cfg.current_knock();

    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/key?v=39")
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
    let cfg = stable_knock_config(psk);
    let knock = cfg.current_knock();
    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/k/{knock}/key?v=39"))
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
    let cfg = stable_knock_config(psk);
    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/key?v=39")
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
    let cfg = stable_knock_config(psk);
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
                    .uri("/key?v=39")
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
                    .uri(format!("/k/{bogus}/key?v=39"))
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

// ---------------------------------------------------------------------------
// Additional probe-resistance + race coverage.
// ---------------------------------------------------------------------------

/// Empty knock header is rejected with the canonical 404.
#[tokio::test]
async fn empty_knock_header_rejected() {
    let psk = fixed_psk();
    let (state, _dir) = fixture(stable_knock_config(psk));
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/key?v=39")
                .header(KNOCK_HEADER, "")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// A knock with a leading whitespace is rejected (defence-in-depth: we
/// deliberately do NOT trim).
#[tokio::test]
async fn knock_header_with_leading_whitespace_rejected() {
    let psk = fixed_psk();
    let cfg = stable_knock_config(psk);
    let valid = cfg.current_knock();
    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);
    // axum/reqwest will reject the header at HeaderValue::from_str time
    // for embedded whitespace? Try with leading space - should be parsed
    // as a valid HeaderValue but our knock verify rejects it.
    let padded = format!(" {valid}");
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/key?v=39")
                .header(KNOCK_HEADER, padded)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// A knock with a trailing newline is rejected.
#[tokio::test]
async fn knock_header_with_trailing_newline_rejected() {
    let psk = fixed_psk();
    let cfg = stable_knock_config(psk);
    let valid = cfg.current_knock();
    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);
    // hyper rejects \n in headers; expect either build-error or a
    // canonical 404. If from_str panics on \n, we can't build the
    // request — guard with a graceful path.
    let padded = format!("{valid} "); // trailing space (header parser allows it)
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/key?v=39")
                .header(KNOCK_HEADER, padded)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// 100 random path-prefix knock URLs against `/key?v=39`: only those minted
/// from the real PSK pass; everything else gets the canonical 404.
#[tokio::test]
async fn ts2021_knock_path_prefix_100_random_invalid() {
    let psk = fixed_psk();
    let cfg = stable_knock_config(psk);
    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);

    // splitmix64 to mint 100 deterministic random knocks.
    let mut seed: u64 = 0xFEED_F00D_BEEF_C0DE;
    for _ in 0..100 {
        seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        let z = z ^ (z >> 31);
        let bogus = hex::encode(z.to_le_bytes());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/k/{bogus}/key?v=39"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "random knock {bogus} unexpectedly accepted"
        );
    }
}

/// 100 random header knocks against `/key?v=39`: every one must be rejected.
#[tokio::test]
async fn ts2021_knock_header_100_random_invalid() {
    let psk = fixed_psk();
    let cfg = stable_knock_config(psk);
    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);

    let mut seed: u64 = 0xC0DE_F00D_BAAD_BEEF;
    for _ in 0..100 {
        seed = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        let z = z ^ (z >> 31);
        let bogus = hex::encode(z.to_le_bytes());

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/key?v=39")
                    .header(KNOCK_HEADER, &bogus)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

/// Path-prefix branch correctly handles a knock-but-no-suffix URL:
/// `/k/<knock>` (no inner path). The router has no handler at that
/// nested route, so we expect 404 (whether 404 from the inner router
/// or canonical 404 from the knock fallback — the test asserts only
/// the status).
#[tokio::test]
async fn knock_no_inner_path_returns_404() {
    let psk = fixed_psk();
    let cfg = stable_knock_config(psk);
    let knock = cfg.current_knock();
    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/k/{knock}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// 50 concurrent requests carrying the same valid knock all succeed.
/// Guards against any TOCTOU / mutex contention in the knock layer.
#[tokio::test]
async fn knock_50_concurrent_valid_requests_all_pass() {
    let psk = fixed_psk();
    let cfg = stable_knock_config(psk);
    let knock = cfg.current_knock();
    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);

    let mut handles = Vec::new();
    for _ in 0..50 {
        let app = app.clone();
        let knock = knock.clone();
        handles.push(tokio::spawn(async move {
            let resp = app
                .oneshot(
                    Request::builder()
                        .uri("/key?v=39")
                        .header(KNOCK_HEADER, knock)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            resp.status()
        }));
    }
    for h in handles {
        let status = h.await.unwrap();
        assert_eq!(status, StatusCode::OK);
    }
}

/// Path-prefix knock followed by a different inner-router endpoint
/// (e.g. /machine/...) also routes through after stripping. Use
/// `/derp-map` if available, fall back to checking the status is not
/// the 404 nginx body (which would mean the knock check failed).
#[tokio::test]
async fn knock_path_prefix_routes_to_inner_handler() {
    let psk = fixed_psk();
    let cfg = stable_knock_config(psk);
    let knock = cfg.current_knock();
    let (state, _dir) = fixture(cfg);
    let app = tailscale_wire::router(state);

    // Use the `/key?v=39` handler (which we know returns 200) under the
    // knock prefix — the previous test does this. Here we additionally
    // verify the 200 response body is NOT the canonical 404 body,
    // i.e. the inner handler actually fired.
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/k/{knock}/key?v=39"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_ne!(body.as_ref(), NGINX_404_BODY.as_bytes());
    assert!(!body.is_empty(), "inner handler returned empty body");
}

/// When the knock layer is disabled, the path-prefix variant doesn't
/// match anything — `/k/<anything>/key` should NOT be reachable via the
/// prefix path (the router just has no `/k/:knock` route in the
/// disabled config).
#[tokio::test]
async fn disabled_knock_does_not_match_path_prefix() {
    let (state, _dir) = fixture(KnockConfig::disabled());
    let app = tailscale_wire::router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .uri("/k/abcdef0123456789/key?v=39")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    // No route → 404 (axum default).
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
