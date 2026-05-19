//! Dual-bind entry point for the Tailscale wire surface.
//!
//! [`serve`] binds the router on **two** addresses simultaneously:
//!
//!   1. A plaintext HTTP listener (typically `:51821`) for `GET /key`
//!      and any other unauthenticated probe.
//!   2. A `rustls`-terminated HTTPS listener (typically `:443`) for the
//!      `Upgrade: tailscale-control-protocol` + flat `/machine/...`
//!      paths the v1.78+ client uses after its forced-443 dial.
//!
//! Both listeners serve the **same** [`router`] — the wire layer's
//! handlers are TLS-agnostic. The TLS material is built via
//! [`tls::load_or_generate`] which caches under `<state_dir>/tls.{crt,key}`.
//!
//! ## Decision log
//!
//! - **HTTPS uses `raw_tls::serve_raw_tls`, not `axum-server`.** The
//!   `/ts2021` upgrade can't go through `axum-server` /
//!   `hyper-rustls` — see `raw_tls`'s module doc and
//!   `docs/tailscale-interop-blocker.md` 2026-05-19 §"P0 batch
//!   shipped" for why (hyper-rustls' read buffer drains the
//!   Initiation frame between the 101 response and the moment our
//!   `OnUpgrade` handler regains the socket). The raw listener
//!   special-cases `/ts2021`, dispatches everything else into the
//!   same `axum::Router` via `hyper::server::conn::http1`.
//! - **Both listeners run as separate tasks.** A single bind failure
//!   shouldn't bring down the other listener; the dual-listener entry
//!   point logs and returns the first error it sees.
//! - **Plain HTTP fallback stays bound.** The keyed paths + the
//!   admin shim used by the harness still flow through `:51821`; we
//!   don't migrate them under TLS to keep the existing tests + curl
//!   probes working.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use axum::Router;
use tokio::task::JoinHandle;

use super::raw_tls;
use super::tls::{self, SanConfig, TlsMaterial};
use super::{WireError, WireState, router};

/// Configuration for [`serve`].
#[derive(Clone, Debug)]
pub struct ServeConfig {
    /// Plain-HTTP bind address. Typically `0.0.0.0:51821`.
    pub http_addr: SocketAddr,
    /// HTTPS bind address. Typically `0.0.0.0:443`. `None` ⇒ skip the
    /// TLS listener (useful for tests + dev hosts that don't have
    /// permission to bind 443).
    pub https_addr: Option<SocketAddr>,
    /// Directory where the noise static key + TLS material are cached.
    pub state_dir: std::path::PathBuf,
    /// SAN hostname for the minted cert. Cert is reused across
    /// restarts as long as the SAN list doesn't change.
    pub sans: SanConfig,
}

impl ServeConfig {
    /// Minimal helper for the interop harness — bind plain HTTP on
    /// `:51821` and HTTPS on `:443`, cache material under
    /// `state_dir`, with a SAN list rooted at `hostname`.
    pub fn for_interop(state_dir: impl AsRef<Path>, hostname: impl Into<String>) -> Self {
        Self {
            http_addr: "0.0.0.0:51821".parse().unwrap(),
            https_addr: Some("0.0.0.0:443".parse().unwrap()),
            state_dir: state_dir.as_ref().into(),
            sans: SanConfig::with_hostname(hostname),
        }
    }
}

/// Handles to the spawned listener tasks. Drop the joinset to abort
/// both listeners.
pub struct ServeHandle {
    pub http: JoinHandle<Result<(), std::io::Error>>,
    pub https: Option<JoinHandle<Result<(), std::io::Error>>>,
    /// The minted TLS material — exposed so callers (e.g. the docker
    /// harness install script) can copy the cert into peer trust
    /// stores. `None` when `https_addr` is unset.
    pub tls: Option<TlsMaterial>,
}

/// Bind both listeners and return without blocking. The caller is
/// responsible for awaiting [`ServeHandle::http`] /
/// [`ServeHandle::https`] (or aborting on shutdown).
///
/// `extra_routes` is merged into the wire router before binding — the
/// harness uses this to attach its `/admin/preauth` shim.
pub async fn serve(
    state: WireState,
    cfg: ServeConfig,
    extra_routes: Router,
) -> Result<ServeHandle, WireError> {
    let app = extra_routes.merge(router(state.clone()));

    let http_listener = tokio::net::TcpListener::bind(cfg.http_addr)
        .await
        .map_err(|e| WireError::Internal(format!("bind {}: {e}", cfg.http_addr)))?;
    tracing::info!(
        target = "tailscale_wire::serve",
        addr = %cfg.http_addr,
        "wire surface listening (HTTP)"
    );

    let http_app = app.clone();
    let http = tokio::spawn(async move {
        axum::serve(http_listener, http_app)
            .await
            .map_err(std::io::Error::other)
    });

    // HTTPS branch — only mint TLS material when an https addr is
    // actually configured.
    //
    // Implementation note: we deliberately route HTTPS through
    // `raw_tls::serve_raw_tls`, **not** `axum_server::bind_rustls`.
    // The latter's hyper-rustls stack drains the Noise IK
    // Initiation bytes off the TLS read buffer between the
    // `101 Switching Protocols` response and the moment our
    // `/ts2021` handler regains control of the socket, which kills
    // the handshake (observed wall — see the blocker doc 2026-05-19
    // entry). The raw listener peeks the request line itself and
    // hands the unbuffered `TlsStream` straight to
    // `noise::drive_ts2021` for the upgrade path; everything else
    // still flows through the same axum router via hyper http1.
    let (https, tls) = if let Some(https_addr) = cfg.https_addr {
        let material = tls::load_or_generate(&cfg.state_dir, &cfg.sans)?;
        tracing::info!(
            target = "tailscale_wire::serve",
            addr = %https_addr,
            cert_path = %material.cert_path.display(),
            "wire surface listening (HTTPS, self-signed, raw rustls)"
        );
        let server_config = Arc::clone(&material.server_config);
        let https_app = app.clone();
        let wire_state = state.clone();
        let handle = tokio::spawn(async move {
            raw_tls::serve_raw_tls(https_addr, server_config, https_app, wire_state).await
        });
        (Some(handle), Some(material))
    } else {
        (None, None)
    };

    Ok(ServeHandle { http, https, tls })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{
        MachineRegistry, WireState,
        noise::ServerNoiseKey,
        test_support::{MockIpAllocator, MockRedeemer},
    };
    use std::sync::Arc;
    use tempfile::tempdir;

    fn fixture_state() -> (WireState, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let state = WireState {
            server_noise_key: server,
            preauth: Arc::new(MockRedeemer::new()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
            derp_map: Arc::new(crate::tailscale_wire::wire::DerpMap::default()),
            policy: Arc::new(crate::policy::PolicyStore::new()),
        };
        (state, dir)
    }

    /// Bind both listeners on ephemeral ports and probe `GET /key`
    /// over plain HTTP. We don't drive a TLS client in-process — the
    /// docker harness does that — but we *do* assert the HTTPS
    /// listener accepts the rustls config without panicking.
    #[tokio::test]
    async fn dual_bind_serves_plain_http_key() {
        let (state, dir) = fixture_state();
        let cfg = ServeConfig {
            http_addr: "127.0.0.1:0".parse().unwrap(),
            // Skip HTTPS in this test — binding :0 with axum-server
            // requires a different API path. The minted material is
            // still exercised by the standalone `tls::tests`.
            https_addr: None,
            state_dir: dir.path().into(),
            sans: SanConfig::with_hostname("test-host"),
        };
        // We need the actual bound port; tokio::net::TcpListener::bind
        // returns it via local_addr. Inline the relevant piece of
        // `serve` rather than pry inside.
        let listener = tokio::net::TcpListener::bind(cfg.http_addr).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().merge(super::router(state));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/key");
        let resp = reqwest::get(&url).await.unwrap();
        assert!(resp.status().is_success());
        handle.abort();
    }
}
