//! `GET /key` — return the server's Noise long-term public key.
//!
//! Wire format: `tailcfg.OverTLSPublicKeyResponse`
//! (`tailscale/tailcfg/tailcfg.go`). Only `PublicKey` is required for
//! a TS2021-capable client (capability version >= 39); older clients
//! also consume a `LegacyPublicKey` field, which we leave empty
//! because we have no legacy bridge.
//!
//! Stock `tailscale up` appends a `?v=<capver>` query parameter
//! advertising the client's capability version. Upstream headscale
//! rejects requests without a parsable `v`, returns the Noise public
//! key for TS2021-capable clients (`v >= 39`), and otherwise writes an
//! empty 200 response because there is no legacy bridge.
//!
//! ## Decision log
//!
//! - **JSON envelope, not raw hex.** The blocker doc's table says
//!   "curl returns hex key" but Tailscale's wire format is
//!   `{"publicKey": "mkey:<hex>"}`. We follow the upstream shape.
//!   A test asserts a real `tailscale up` parse path
//!   (`OverTLSPublicKeyResponse` deserialise) round-trips.

use axum::{
    Json,
    extract::{RawQuery, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{WireState, noise::NOISE_CAPABILITY_VERSION};

/// `GET /key` response.
///
/// JSON field tag: `PublicKey` (PascalCase) per upstream
/// `OverTLSPublicKeyResponse`. The `mkey:` prefix is part of the value
/// so a downstream parser uses the same code path as it would for any
/// other Tailscale machine key.
#[derive(Debug, Serialize, Deserialize)]
pub struct OverTLSPublicKeyResponse {
    /// Server's Noise X25519 public key, formatted as `mkey:<hex>`.
    #[serde(rename = "PublicKey")]
    pub public_key: String,
}

pub async fn handle_key(State(state): State<WireState>, RawQuery(raw_query): RawQuery) -> Response {
    let cap_ver = match parse_capability_version(raw_query.as_deref()) {
        Ok(cap_ver) => cap_ver,
        Err(resp) => return resp,
    };
    if cap_ver < u32::from(NOISE_CAPABILITY_VERSION) {
        return StatusCode::OK.into_response();
    }

    let body = OverTLSPublicKeyResponse {
        public_key: format!("mkey:{}", state.server_noise_key.public_hex()),
    };
    Json(body).into_response()
}

fn parse_capability_version(raw_query: Option<&str>) -> Result<u32, Response> {
    let Some(raw_query) = raw_query else {
        return Err(text_error(
            StatusCode::BAD_REQUEST,
            "capability version must be set",
        ));
    };

    let Some(raw_v) = raw_query.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == "v").then_some(value)
    }) else {
        return Err(text_error(
            StatusCode::BAD_REQUEST,
            "capability version must be set",
        ));
    };

    raw_v
        .parse::<u32>()
        .map_err(|_| text_error(StatusCode::BAD_REQUEST, "invalid capability version"))
}

fn text_error(status: StatusCode, msg: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{msg}\n"),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{
        MachineRegistry, WireState,
        noise::ServerNoiseKey,
        router,
        test_support::{MockIpAllocator, MockRedeemer},
    };
    use axum::body::to_bytes;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn fixture_state() -> (WireState, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let state = WireState {
            server_noise_key: server,
            preauth: Arc::new(MockRedeemer::new()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
            registration_store: None,
            derp_map: crate::tailscale_wire::DerpMapStore::shared(
                crate::tailscale_wire::wire::DerpMap::default(),
            ),
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

    #[tokio::test]
    async fn key_endpoint_returns_mkey_prefixed_hex() {
        let (state, _dir) = fixture_state();
        let expected_pub = state.server_noise_key.public_hex();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/key?v=39")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: OverTLSPublicKeyResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.public_key, format!("mkey:{expected_pub}"));
    }

    #[tokio::test]
    async fn key_endpoint_rejects_missing_query_param() {
        let (state, _dir) = fixture_state();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/key")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), b"capability version must be set\n");
    }

    #[tokio::test]
    async fn key_endpoint_rejects_invalid_query_param() {
        let (state, _dir) = fixture_state();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/key?v=nope")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), b"invalid capability version\n");
    }

    #[tokio::test]
    async fn key_endpoint_returns_empty_200_for_legacy_capability() {
        let (state, _dir) = fixture_state();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/key?v=38")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(body.is_empty());
    }
}
