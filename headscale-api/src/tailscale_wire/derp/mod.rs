//! Embedded DERP server parity (P1 from `docs/headscale-gap-analysis.md`).
//!
//! Upstream `juanfont/headscale` wraps `tailscale.com/derp.Server` and
//! exposes:
//!
//! - `GET /derp` — websocket / HTTP-upgrade hijack carrying the actual
//!   DERP relay traffic (peer-to-peer encrypted frames).
//! - `GET /derp/probe` — js/wasm probe; returns 200.
//! - `GET /bootstrap-dns` — resolves DERP region nodes' hostnames and
//!   returns a `{ hostname: [ip,…] }` JSON map for clients whose own
//!   DNS is broken.
//! - UDP STUN on a separate port.
//! - `POST /verify` — DERP relay-client verification hook (upstream
//!   `derp_server.go::DerpVerifyScheme`).
//!
//! ## Decision: sidecar + native handlers (option 2 of the spec)
//!
//! The actual DERP wire protocol (TLV frames over a TLS-upgraded
//! socket, peer routing, key-attested PacketForward, restart-please
//! coordination, keepalive math) has **no Rust port**; the upstream
//! reference is `tailscale.com/derp/derpserver.Server`, ~4 kLOC of
//! Go that no one has ported yet. A faithful native re-implementation
//! would either be incomplete (option 1, < 800 LOC, missing edge
//! cases) or would balloon past the budget the task brief sets. We
//! pick option 2 — spawn the upstream `derper` Go binary as a
//! subprocess and reverse-proxy `/derp` upgrades to it — and keep
//! the four lightweight endpoints (`/derp/probe`, `/bootstrap-dns`,
//! `/verify`, STUN) native in Rust because they don't touch the relay
//! wire format.
//!
//! ## What ships in this module
//!
//! - `DerpConfig` (toml `[derp]` block): `enabled`, `listen_addr`,
//!   `stun_addr`, `region_id`, `region_name`, `region_code`, `host_name`.
//! - `DerpServer` — the orchestrator. Owns:
//!     - an [`stun::StunListener`] (UDP, native Rust),
//!     - a [`sidecar::DerperSidecar`] (`derper` subprocess, if a
//!       binary is configured),
//!     - the [`router`] that attaches the four HTTP handlers to the
//!       existing axum wire router.
//! - `derp_region()` — emits a [`super::wire::DerpRegion`] suitable
//!   for stuffing into `MapResponse.DERPMap` when `enabled = true`.
//!
//! ## Caveats / honesty
//!
//! - **PacketForward between two clients in the same process: only
//!   when the sidecar is running.** Two clients connecting to the
//!   embedded relay will route through the spawned `derper`
//!   subprocess. Without the binary, `/derp` returns 503; clients
//!   fall back to public Tailscale relays (when not behind
//!   `OmitDefaultRegions = true`).
//! - **STUN: yes, end-to-end in Rust.** The native handler implements
//!   the RFC 5389 binding-request → success-response with a
//!   XOR-MAPPED-ADDRESS attribute. No software-attribute, no
//!   fingerprint (matches upstream's `tailscale.com/net/stun` which
//!   also omits both for binding responses).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::routing::{get, post};

pub mod handlers;
pub mod sidecar;
pub mod stun;

#[cfg(test)]
mod tests;

pub use handlers::{BootstrapDnsResponse, VerifyRequest, VerifyResponse};
pub use sidecar::{DerperSidecar, SidecarError, SidecarStatus};
pub use stun::{StunError, StunListener, decode_stun_binding_request, encode_stun_binding_response};

/// Operator-facing toml config for the embedded DERP layer.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DerpConfig {
    /// Master switch. When `false`, none of the four endpoints are
    /// mounted, no STUN listener is bound, and no subprocess is
    /// spawned.
    #[serde(default)]
    pub enabled: bool,

    /// Public-facing DERP HTTPS endpoint host. Lands in
    /// `DERPRegion.Nodes[0].host_name`.
    #[serde(default)]
    pub host_name: String,

    /// HTTPS port the client dials. Defaults to 443.
    #[serde(default = "default_derp_port")]
    pub derp_port: u16,

    /// Address the upstream `derper` subprocess binds to. Reverse-
    /// proxied from `/derp` and `/derp/probe` on the public HTTPS
    /// listener. Defaults to `127.0.0.1:8443`.
    #[serde(default = "default_sidecar_addr")]
    pub sidecar_listen_addr: SocketAddr,

    /// Path to the `derper` binary. Empty ⇒ no sidecar.
    #[serde(default)]
    pub derper_binary: PathBuf,

    /// UDP STUN bind. `None` ⇒ no STUN.
    #[serde(default)]
    pub stun_addr: Option<SocketAddr>,

    /// Numeric region ID.
    #[serde(default = "default_region_id")]
    pub region_id: u16,

    /// Short region code.
    #[serde(default = "default_region_code")]
    pub region_code: String,

    /// Human-friendly region name.
    #[serde(default = "default_region_name")]
    pub region_name: String,
}

fn default_derp_port() -> u16 {
    443
}
fn default_sidecar_addr() -> SocketAddr {
    "127.0.0.1:8443".parse().unwrap()
}
fn default_region_id() -> u16 {
    900
}
fn default_region_code() -> String {
    "embedded".to_string()
}
fn default_region_name() -> String {
    "Embedded headscale-rs DERP".to_string()
}

impl Default for DerpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host_name: String::new(),
            derp_port: default_derp_port(),
            sidecar_listen_addr: default_sidecar_addr(),
            derper_binary: PathBuf::new(),
            stun_addr: None,
            region_id: default_region_id(),
            region_code: default_region_code(),
            region_name: default_region_name(),
        }
    }
}

impl DerpConfig {
    /// `true` iff a sidecar binary path was configured.
    pub fn has_sidecar(&self) -> bool {
        !self.derper_binary.as_os_str().is_empty()
    }

    /// Convenience: the disabled-by-default value.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Generate the [`super::wire::DerpRegion`] this config describes.
    /// Returns `None` when the layer is disabled.
    pub fn derp_region(&self) -> Option<super::wire::DerpRegion> {
        if !self.enabled {
            return None;
        }
        Some(super::wire::DerpRegion {
            region_id: self.region_id,
            region_code: self.region_code.clone(),
            region_name: self.region_name.clone(),
            avoid: false,
            nodes: vec![super::wire::DerpRegionNode {
                name: self.region_id.to_string(),
                region_id: self.region_id,
                host_name: self.host_name.clone(),
                ipv4: String::new(),
                ipv6: String::new(),
                derp_port: if self.derp_port == 443 { 0 } else { self.derp_port },
                stun_port: self.stun_addr.map_or(0, |a| i32::from(a.port())),
                stun_only: false,
                insecure_for_tests: false,
            }],
        })
    }
}

/// Running embedded DERP server. Constructed via
/// [`DerpServer::start`]; drop to shut down.
pub struct DerpServer {
    cfg: DerpConfig,
    stun: Option<StunListener>,
    sidecar: Option<DerperSidecar>,
}

impl DerpServer {
    /// Start the layer. Binds STUN (if configured) and spawns the
    /// `derper` subprocess (if a binary path is configured).
    pub async fn start(cfg: DerpConfig) -> Result<Self, std::io::Error> {
        if !cfg.enabled {
            return Ok(Self {
                cfg,
                stun: None,
                sidecar: None,
            });
        }
        let stun = match cfg.stun_addr {
            Some(addr) => Some(StunListener::bind(addr).await?),
            None => None,
        };
        let sidecar = if cfg.has_sidecar() {
            match DerperSidecar::spawn(&cfg) {
                Ok(s) => Some(s),
                Err(SidecarError::BinaryMissing(_)) => None,
                Err(e) => return Err(std::io::Error::other(e.to_string())),
            }
        } else {
            None
        };
        Ok(Self { cfg, stun, sidecar })
    }

    pub fn config(&self) -> &DerpConfig {
        &self.cfg
    }

    pub fn stun_local_addr(&self) -> Option<SocketAddr> {
        self.stun.as_ref().and_then(|s| s.local_addr().ok())
    }

    pub fn sidecar_status(&self) -> Option<SidecarStatus> {
        self.sidecar.as_ref().map(DerperSidecar::status)
    }
}

/// Shared state injected into the DERP HTTP handlers.
#[derive(Clone)]
pub struct DerpHttpState {
    pub cfg: Arc<DerpConfig>,
    /// Pre-resolved IPs for the embedded region's `host_name` — used
    /// by `/bootstrap-dns` to skip a DNS lookup on the hot path.
    pub bootstrap_dns: Arc<parking_lot::RwLock<BootstrapDnsResponse>>,
}

impl DerpHttpState {
    pub fn new(cfg: DerpConfig) -> Self {
        Self {
            cfg: Arc::new(cfg),
            bootstrap_dns: Arc::new(parking_lot::RwLock::new(BootstrapDnsResponse::default())),
        }
    }

    /// Convenience: a disabled-layer state ready to drop into
    /// [`super::WireState`] when the operator hasn't configured a
    /// `[derp]` block.
    pub fn disabled() -> Self {
        Self::new(DerpConfig::disabled())
    }
}

impl Default for DerpHttpState {
    fn default() -> Self {
        Self::disabled()
    }
}

/// Build the DERP HTTP routes that attach to the public wire router.
///
/// Returns an empty router when `cfg.enabled = false` so the caller
/// can unconditionally `.merge(...)` it.
pub fn router(state: DerpHttpState) -> Router {
    if !state.cfg.enabled {
        return Router::new();
    }
    Router::new()
        .route("/derp/probe", get(handlers::probe).head(handlers::probe))
        .route("/bootstrap-dns", get(handlers::bootstrap_dns))
        .route("/verify", post(handlers::verify))
        .route("/derp", get(handlers::derp_upgrade_placeholder))
        .with_state(state)
}
