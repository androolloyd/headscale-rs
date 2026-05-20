//! Lightweight DERP HTTP endpoints — native Rust, no sidecar required.
//!
//! - `GET /derp/probe` — used by js/wasm clients (and `tailscale
//!   netcheck`) to measure DERP latency. Upstream returns 200 with
//!   CORS allow-origin `*`.
//! - `GET /bootstrap-dns` — emits a JSON map `{ hostname: [ip,…] }`
//!   so a client whose own DNS resolver is broken can still find the
//!   region nodes.
//! - `POST /verify` — DERP client-verification hook (upstream
//!   `DerpVerifyScheme`). **Crucially, this endpoint is NOT
//!   noise-gated**.
//! - `GET /derp` placeholder — returns 503 when no sidecar is
//!   running so the client gets a definitive "this relay is down"
//!   instead of the misleading default 404.

use std::collections::BTreeMap;
use std::net::IpAddr;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use super::DerpHttpState;

/// `/derp/probe`. Always-200, with `Access-Control-Allow-Origin: *`.
pub async fn probe() -> impl axum::response::IntoResponse {
    (
        StatusCode::OK,
        [
            ("access-control-allow-origin", "*"),
            ("content-type", "text/plain"),
        ],
        "",
    )
}

/// Pre-resolved bootstrap DNS entries. Maps `host_name → [ip, …]`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BootstrapDnsResponse(pub BTreeMap<String, Vec<IpAddr>>);

impl BootstrapDnsResponse {
    pub fn insert(&mut self, host: impl Into<String>, ips: Vec<IpAddr>) {
        self.0.insert(host.into(), ips);
    }
    pub fn get(&self, host: &str) -> Option<&Vec<IpAddr>> {
        self.0.get(host)
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// `GET /bootstrap-dns`.
pub async fn bootstrap_dns(State(state): State<DerpHttpState>) -> impl axum::response::IntoResponse {
    {
        let cached = state.bootstrap_dns.read();
        if !cached.is_empty() {
            return (StatusCode::OK, Json(cached.clone()));
        }
    }
    let host = state.cfg.host_name.clone();
    if host.is_empty() {
        return (StatusCode::OK, Json(BootstrapDnsResponse::default()));
    }
    let port = if state.cfg.derp_port == 0 {
        443
    } else {
        state.cfg.derp_port
    };
    let mut resp = BootstrapDnsResponse::default();
    let target = format!("{host}:{port}");
    let lookup = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::lookup_host(target),
    )
    .await;
    if let Ok(Ok(iter)) = lookup {
        let ips: Vec<IpAddr> = iter.map(|sa| sa.ip()).collect();
        if !ips.is_empty() {
            resp.insert(host.clone(), ips);
            *state.bootstrap_dns.write() = resp.clone();
        }
    }
    (StatusCode::OK, Json(resp))
}

/// Body of a `POST /verify` request, mirroring upstream's
/// `tailscale.com/derp.clientVerifyRequest`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VerifyRequest {
    #[serde(rename = "ClientPublic", default)]
    pub client_public: String,
}

/// Body of a `POST /verify` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResponse {
    #[serde(rename = "Allow")]
    pub allow: bool,
}

/// `POST /verify` — relay → control plane callback.
///
/// Allows any non-empty client public key. Downstream callers that
/// want stricter policy can wrap this handler.
pub async fn verify(
    State(_state): State<DerpHttpState>,
    Json(req): Json<VerifyRequest>,
) -> impl axum::response::IntoResponse {
    let allow = !req.client_public.is_empty();
    (StatusCode::OK, Json(VerifyResponse { allow }))
}

/// Stand-in for `/derp` when no sidecar is running.
pub async fn derp_upgrade_placeholder(
    State(state): State<DerpHttpState>,
) -> impl axum::response::IntoResponse {
    let body = if state.cfg.has_sidecar() {
        "derp relay sidecar unreachable"
    } else {
        "derp relay not enabled"
    };
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [("content-type", "text/plain")],
        body,
    )
}
