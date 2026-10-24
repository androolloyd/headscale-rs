//! `GET /key` — return the server's Noise long-term public key.
//!
//! Wire format: `tailcfg.OverTLSPublicKeyResponse`
//! (`tailscale/tailcfg/tailcfg.go`). Only `PublicKey` is required for
//! a supported TS2021-capable client (capability version >= 113). The legacy key
//! is the all-zero machine key because there is no legacy bridge.
//!
//! Stock `tailscale up` appends a `?v=<capver>` query parameter
//! advertising the client's capability version. Pinned headscale-go
//! v0.29.5 rejects versions below its supported floor (113).
//!
//! ## Decision log
//!
//! - **JSON envelope, not raw hex.** The blocker doc's table says
//!   "curl returns hex key" but Tailscale's wire format is
//!   `{"publicKey": "mkey:<hex>"}`. We follow the upstream shape.
//!   A test asserts a real `tailscale up` parse path
//!   (`OverTLSPublicKeyResponse` deserialise) round-trips.

use axum::{
    extract::{RawQuery, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use super::{WireState, wire::MIN_SUPPORTED_CAPABILITY_VERSION};

/// `GET /key` response.
///
/// JSON field tags match upstream `OverTLSPublicKeyResponse`. The `mkey:` prefix is part of the value
/// so a downstream parser uses the same code path as it would for any
/// other Tailscale machine key.
#[derive(Debug, Serialize, Deserialize)]
pub struct OverTLSPublicKeyResponse {
    /// All-zero legacy key, as serialized by headscale-go.
    #[serde(rename = "legacyPublicKey")]
    pub legacy_public_key: String,
    /// Server's Noise X25519 public key, formatted as `mkey:<hex>`.
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

pub async fn handle_key(State(state): State<WireState>, RawQuery(raw_query): RawQuery) -> Response {
    let cap_ver = match parse_capability_version(raw_query.as_deref()) {
        Ok(cap_ver) => cap_ver,
        Err(resp) => return resp,
    };
    if !u64::try_from(cap_ver)
        .is_ok_and(|version| version >= u64::from(MIN_SUPPORTED_CAPABILITY_VERSION))
    {
        return text_error(StatusCode::BAD_REQUEST, "unsupported client version");
    }

    let body = OverTLSPublicKeyResponse {
        legacy_public_key: format!("mkey:{}", "0".repeat(64)),
        public_key: format!("mkey:{}", state.server_noise_key.public_hex()),
    };
    let Ok(mut body) = serde_json::to_vec(&body) else {
        return text_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to encode public key response",
        );
    };
    body.push(b'\n');
    ([(header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn parse_capability_version(raw_query: Option<&str>) -> Result<isize, Response> {
    let Some(raw_query) = raw_query else {
        return Err(text_error(
            StatusCode::BAD_REQUEST,
            "capability version must be set",
        ));
    };

    let Some(raw_v) = super::query::first_value(raw_query, "v").filter(|value| !value.is_empty())
    else {
        return Err(text_error(
            StatusCode::BAD_REQUEST,
            "capability version must be set",
        ));
    };

    std::str::from_utf8(&raw_v)
        .ok()
        .and_then(|value| value.parse::<isize>().ok())
        .ok_or(())
        .map_err(|()| text_error(StatusCode::BAD_REQUEST, "invalid capability version"))
}

fn text_error(status: StatusCode, msg: &str) -> Response {
    (
        status,
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        ],
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
            registration_gate: None,
            derp_map: crate::tailscale_wire::DerpMapStore::shared(
                crate::tailscale_wire::wire::DerpMap::default(),
            ),
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

    #[tokio::test]
    async fn key_endpoint_returns_mkey_prefixed_hex() {
        let (state, _dir) = fixture_state();
        let expected_pub = state.server_noise_key.public_hex();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/key?v=138")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: OverTLSPublicKeyResponse = serde_json::from_slice(&body).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.public_key, format!("mkey:{expected_pub}"));
        assert_eq!(parsed.legacy_public_key, format!("mkey:{}", "0".repeat(64)));
        assert!(value.get("PublicKey").is_none());
        assert!(value.get("publicKey").is_some());
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
    async fn key_endpoint_rejects_unsupported_capability() {
        let (state, _dir) = fixture_state();
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/key?v=112")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), b"unsupported client version\n");
    }
}
