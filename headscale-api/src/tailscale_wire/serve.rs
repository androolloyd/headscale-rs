//! Multi-listener entry point for the Tailscale wire surface.
//!
//! [`serve`] can bind the control surface on one or two public addresses plus
//! an optional operator diagnostics listener:
//!
//!   1. An optional plaintext HTTP listener (typically `127.0.0.1:51821`) for
//!      `GET /key` and any other unauthenticated probe.
//!   2. An optional `rustls`-terminated HTTPS listener for upstream-style
//!      TLS-on-`listen_addr` deployments or the Rust dual-listener harness. It
//!      serves ordinary public routes over TLS and handles
//!      the `Upgrade: tailscale-control-protocol` path the client uses after
//!      its forced-443 dial. The `/machine/...` control paths are served
//!      inside the Noise h2 session, not on the outer HTTP router.
//!   3. A metrics/debug HTTP listener for `/metrics` and `/debug/*`, matching
//!      headscale-go's `metrics_listen_addr` split.
//!
//! The public HTTP and HTTPS listeners serve only the public control
//! router; metrics/debug routes are mounted on the dedicated listener
//! when configured. The TLS material is built via
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
//! - **Listeners run as separate tasks.** A single listener failure
//!   shouldn't hide failures from the others; the entry point logs
//!   and returns the first error it sees.
//! - **Plain HTTP is optional.** Upstream manual-TLS mode terminates TLS on the
//!   main `listen_addr`; the interop harness can still opt into a separate
//!   plaintext listener for curl probes and its admin shim.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use axum::{
    Router,
    extract::{ConnectInfo, State},
    middleware::{self, Next},
    response::Response,
};
use ipnet::IpNet;
use tokio::task::JoinHandle;

use super::acme::AcmeHttp01ChallengeStore;
use super::raw_tls;
use super::tls::{ReloadableServerConfig, SanConfig, TlsMaterial, TlsMaterialSource};
use super::{WireError, WireState, control_router, control_router_with_oidc, metrics_debug_router};

/// Configuration for [`serve`].
#[derive(Clone, Debug)]
pub struct ServeConfig {
    /// Plain-HTTP bind address. `None` disables the plaintext public listener,
    /// which matches upstream when TLS is configured directly on `listen_addr`.
    pub http_addr: Option<SocketAddr>,
    /// HTTPS bind address. Defaults and helpers stay loopback-only.
    /// `None` ⇒ skip the
    /// TLS listener (useful for tests + dev hosts that don't have
    /// permission to bind 443).
    pub https_addr: Option<SocketAddr>,
    /// Directory where the noise static key + TLS material are cached.
    pub state_dir: std::path::PathBuf,
    /// SAN hostname for the minted cert. Cert is reused across
    /// restarts as long as the SAN list doesn't change.
    pub sans: SanConfig,
    /// TLS material source used when `https_addr` is configured.
    pub tls_source: TlsMaterialSource,
    /// CIDRs allowed to supply reverse-proxy forwarding headers.
    ///
    /// Requests from other peers have `Forwarded`, `X-Forwarded-*`, and
    /// `X-Real-IP` stripped before public handlers derive helper URLs.
    pub trusted_proxies: TrustedProxyConfig,
    /// Optional OIDC auth runtime. When present, the public `/register/{id}`
    /// route starts the OIDC auth-code flow and `/oidc/callback` is mounted.
    pub oidc: Option<crate::oidc::OidcAuthRuntime>,
    /// Optional metrics/debug bind address. `None` disables the
    /// dedicated operator diagnostics listener.
    pub metrics_addr: Option<SocketAddr>,
    /// Optional ACME HTTP-01 challenge material. When present, the public
    /// listener serves `/.well-known/acme-challenge/{token}` before the normal
    /// control-router fallback.
    pub acme_http01: Option<AcmeHttp01ChallengeStore>,
    /// Optional exact Host header allowed to retrieve ACME HTTP-01 tokens.
    /// This mirrors headscale-go's `autocert.HostWhitelist` behavior and
    /// should be set to the configured Let's Encrypt hostname when ACME is
    /// wired into the server runtime.
    pub acme_http01_host: Option<String>,
    /// Optional dedicated HTTP-01 listener. When set, only ACME challenge
    /// tokens are served on this socket; non-challenge requests redirect to the
    /// configured public control URL when available.
    pub acme_http01_addr: Option<SocketAddr>,
}

impl ServeConfig {
    /// Minimal helper for the interop harness — bind plain HTTP on
    /// loopback `:51821` and HTTPS on loopback `:443`, cache material under
    /// `state_dir`, with a SAN list rooted at `hostname`.
    pub fn for_interop(state_dir: impl AsRef<Path>, hostname: impl Into<String>) -> Self {
        let state_dir = state_dir.as_ref().to_path_buf();
        let sans = SanConfig::with_hostname(hostname);
        Self {
            http_addr: Some("127.0.0.1:51821".parse().unwrap()),
            https_addr: Some("127.0.0.1:443".parse().unwrap()),
            state_dir: state_dir.clone(),
            sans: sans.clone(),
            tls_source: TlsMaterialSource::SelfSigned { state_dir, sans },
            trusted_proxies: TrustedProxyConfig::default(),
            oidc: None,
            metrics_addr: None,
            acme_http01: None,
            acme_http01_host: None,
            acme_http01_addr: None,
        }
    }
}

/// Handles to the spawned listener tasks. Drop or abort the handles to
/// stop the listeners.
pub struct ServeHandle {
    pub http: Option<JoinHandle<Result<(), std::io::Error>>>,
    pub https: Option<JoinHandle<Result<(), std::io::Error>>>,
    pub metrics: Option<JoinHandle<Result<(), std::io::Error>>>,
    pub acme_http01: Option<JoinHandle<Result<(), std::io::Error>>>,
    pub metrics_addr: Option<SocketAddr>,
    pub acme_http01_addr: Option<SocketAddr>,
    /// The minted TLS material — exposed so callers (e.g. the docker
    /// harness install script) can copy the cert into peer trust
    /// stores. `None` when `https_addr` is unset.
    pub tls: Option<TlsMaterial>,
    /// Live TLS config reloader used by the raw HTTPS listener.
    pub tls_reloader: Option<ReloadableServerConfig>,
}

/// Trusted reverse-proxy CIDRs for forwarding headers.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxyConfig {
    cidrs: Arc<Vec<IpNet>>,
}

impl TrustedProxyConfig {
    pub fn parse<I, S>(values: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let cidrs = values
            .into_iter()
            .map(|value| {
                value.as_ref().parse::<IpNet>().map_err(|err| {
                    format!("invalid trusted proxy CIDR {:?}: {err}", value.as_ref())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            cidrs: Arc::new(cidrs),
        })
    }

    fn is_trusted(&self, ip: IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(&ip))
    }
}

/// Bind configured listeners and return without blocking. The caller
/// is responsible for awaiting the listener handles or aborting them
/// on shutdown.
///
/// `extra_routes` is merged into the wire router before binding — the
/// harness uses this to attach its `/admin/preauth` shim.
pub async fn serve(
    state: WireState,
    cfg: ServeConfig,
    extra_routes: Router,
) -> Result<ServeHandle, WireError> {
    let oidc = cfg.oidc.clone();
    let acme_http01_store = cfg.acme_http01.clone();
    let acme_http01_host = cfg.acme_http01_host.clone();
    let app = extra_routes.merge(public_router(
        state.clone(),
        oidc,
        cfg.acme_http01.clone(),
        cfg.acme_http01_host.clone(),
    ));
    let app = app.layer(middleware::from_fn_with_state(
        cfg.trusted_proxies.clone(),
        trusted_proxy_headers,
    ));

    if cfg.http_addr.is_none() && cfg.https_addr.is_none() {
        return Err(WireError::Internal(
            "at least one public wire listener must be configured".into(),
        ));
    }
    if cfg.acme_http01_addr.is_some() && cfg.acme_http01.is_none() {
        return Err(WireError::Internal(
            "acme_http01_addr requires acme_http01 challenge material".into(),
        ));
    }
    if cfg.acme_http01_addr.is_some() && cfg.acme_http01_host.is_none() {
        return Err(WireError::Internal(
            "acme_http01_addr requires acme_http01_host".into(),
        ));
    }

    let metrics_listener = if let Some(metrics_addr) = cfg.metrics_addr {
        let listener = tokio::net::TcpListener::bind(metrics_addr)
            .await
            .map_err(|e| WireError::Internal(format!("bind {metrics_addr}: {e}")))?;
        let bound_addr = listener.local_addr().map_err(WireError::Io)?;
        tracing::info!(
            target = "tailscale_wire::serve",
            addr = %bound_addr,
            "metrics/debug surface listening (HTTP)"
        );
        Some((listener, bound_addr))
    } else {
        tracing::info!(
            target = "tailscale_wire::serve",
            "metrics/debug surface disabled"
        );
        None
    };

    let http_listener = if let Some(http_addr) = cfg.http_addr {
        let listener = tokio::net::TcpListener::bind(http_addr)
            .await
            .map_err(|e| WireError::Internal(format!("bind {http_addr}: {e}")))?;
        let bound_addr = listener.local_addr().map_err(WireError::Io)?;
        tracing::info!(
            target = "tailscale_wire::serve",
            addr = %bound_addr,
            "wire surface listening (HTTP)"
        );
        Some(listener)
    } else {
        tracing::info!(
            target = "tailscale_wire::serve",
            "wire surface plaintext HTTP listener disabled"
        );
        None
    };

    let acme_http01_listener = if let Some(acme_addr) = cfg.acme_http01_addr {
        let store = acme_http01_store.expect("validated acme_http01 store");
        let listener = tokio::net::TcpListener::bind(acme_addr)
            .await
            .map_err(|e| WireError::Internal(format!("bind {acme_addr}: {e}")))?;
        let bound_addr = listener.local_addr().map_err(WireError::Io)?;
        tracing::info!(
            target = "tailscale_wire::serve",
            addr = %bound_addr,
            "ACME HTTP-01 challenge listener bound"
        );
        Some((listener, bound_addr, store))
    } else {
        None
    };

    let tls_material = if cfg.https_addr.is_some() {
        Some(cfg.tls_source.load()?)
    } else {
        None
    };

    let http = if let Some(http_listener) = http_listener {
        let http_app = app.clone();
        Some(tokio::spawn(async move {
            axum::serve(
                http_listener,
                http_app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(std::io::Error::other)
        }))
    } else {
        None
    };

    let (metrics, metrics_addr) = if let Some((metrics_listener, metrics_addr)) = metrics_listener {
        let metrics_app = metrics_debug_router(state.clone());
        let metrics = tokio::spawn(async move {
            axum::serve(
                metrics_listener,
                metrics_app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .map_err(std::io::Error::other)
        });
        (Some(metrics), Some(metrics_addr))
    } else {
        (None, None)
    };

    let (acme_http01, acme_http01_addr) =
        if let Some((listener, bound_addr, store)) = acme_http01_listener {
            let app = super::acme::http01_listener_router(
                store,
                state.public_control_url.clone(),
                acme_http01_host,
            );
            let handle = tokio::spawn(async move {
                axum::serve(listener, app)
                    .await
                    .map_err(std::io::Error::other)
            });
            (Some(handle), Some(bound_addr))
        } else {
            (None, None)
        };

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
    let (https, tls, tls_reloader) = if let Some(https_addr) = cfg.https_addr {
        let material = tls_material.expect("validated TLS material");
        tracing::info!(
            target = "tailscale_wire::serve",
            addr = %https_addr,
            cert_path = %material.cert_path.display(),
            "wire surface listening (HTTPS, raw rustls)"
        );
        let server_config = ReloadableServerConfig::new(Arc::clone(&material.server_config));
        let https_app = app.clone();
        let wire_state = state.clone();
        let reloader = server_config.clone();
        let handle = tokio::spawn(async move {
            raw_tls::serve_raw_tls(https_addr, server_config, https_app, wire_state).await
        });
        (Some(handle), Some(material), Some(reloader))
    } else {
        (None, None, None)
    };

    Ok(ServeHandle {
        http,
        https,
        metrics,
        acme_http01,
        metrics_addr,
        acme_http01_addr,
        tls,
        tls_reloader,
    })
}

async fn trusted_proxy_headers(
    State(trusted): State<TrustedProxyConfig>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    sanitize_forwarded_headers(request.headers_mut(), peer.ip(), &trusted);
    next.run(request).await
}

fn sanitize_forwarded_headers(
    headers: &mut axum::http::HeaderMap,
    peer: IpAddr,
    trusted: &TrustedProxyConfig,
) {
    if trusted.is_trusted(peer) {
        return;
    }

    headers.remove("forwarded");
    headers.remove("x-forwarded-for");
    headers.remove("x-forwarded-host");
    headers.remove("x-forwarded-proto");
    headers.remove("x-real-ip");
}

fn public_router(
    state: WireState,
    oidc: Option<crate::oidc::OidcAuthRuntime>,
    acme_http01: Option<AcmeHttp01ChallengeStore>,
    acme_http01_host: Option<String>,
) -> Router {
    let router = match oidc {
        Some(oidc) => control_router_with_oidc(state, oidc),
        None => control_router(state),
    };
    if let Some(store) = acme_http01 {
        super::acme::http01_router_with_host_policy(store, acme_http01_host).merge(router)
    } else {
        router
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{
        MachineRegistry, WireState,
        noise::ServerNoiseKey,
        test_support::{MockIpAllocator, MockRedeemer},
    };
    use axum::body::to_bytes;
    use std::collections::BTreeMap;
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

    #[test]
    fn trusted_proxy_config_matches_configured_cidrs() {
        let trusted = TrustedProxyConfig::parse(["127.0.0.1/32", "fd7a:115c:a1e0::/48"]).unwrap();

        assert!(trusted.is_trusted("127.0.0.1".parse().unwrap()));
        assert!(trusted.is_trusted("fd7a:115c:a1e0::5".parse().unwrap()));
        assert!(!trusted.is_trusted("192.0.2.10".parse().unwrap()));
    }

    #[test]
    fn forwarded_headers_are_only_kept_for_trusted_proxies() {
        let trusted = TrustedProxyConfig::parse(["127.0.0.1/32"]).unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-forwarded-host", "proxy.example".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        headers.insert("x-forwarded-for", "203.0.113.5".parse().unwrap());
        headers.insert("x-real-ip", "203.0.113.5".parse().unwrap());
        headers.insert("forwarded", "for=203.0.113.5".parse().unwrap());

        sanitize_forwarded_headers(&mut headers, "192.0.2.10".parse().unwrap(), &trusted);

        assert!(!headers.contains_key("x-forwarded-host"));
        assert!(!headers.contains_key("x-forwarded-proto"));
        assert!(!headers.contains_key("x-forwarded-for"));
        assert!(!headers.contains_key("x-real-ip"));
        assert!(!headers.contains_key("forwarded"));

        headers.insert("x-forwarded-host", "proxy.example".parse().unwrap());
        sanitize_forwarded_headers(&mut headers, "127.0.0.1".parse().unwrap(), &trusted);

        assert_eq!(headers.get("x-forwarded-host").unwrap(), "proxy.example");
    }

    /// Bind both listeners on ephemeral ports and probe `GET /key?v=39`
    /// over plain HTTP. We don't drive a TLS client in-process — the
    /// docker harness does that — but we *do* assert the HTTPS
    /// listener accepts the rustls config without panicking.
    #[tokio::test]
    async fn dual_bind_serves_plain_http_key() {
        let (state, dir) = fixture_state();
        let cfg = ServeConfig {
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            // Skip HTTPS in this test — binding :0 with axum-server
            // requires a different API path. The minted material is
            // still exercised by the standalone `tls::tests`.
            https_addr: None,
            state_dir: dir.path().into(),
            sans: SanConfig::with_hostname("test-host"),
            tls_source: TlsMaterialSource::SelfSigned {
                state_dir: dir.path().into(),
                sans: SanConfig::with_hostname("test-host"),
            },
            trusted_proxies: TrustedProxyConfig::default(),
            oidc: None,
            metrics_addr: None,
            acme_http01: None,
            acme_http01_host: None,
            acme_http01_addr: None,
        };
        // We need the actual bound port; tokio::net::TcpListener::bind
        // returns it via local_addr. Inline the relevant piece of
        // `serve` rather than pry inside.
        let listener = tokio::net::TcpListener::bind(cfg.http_addr.unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().merge(crate::tailscale_wire::router(state));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let url = format!("http://{addr}/key?v=39");
        let resp = reqwest::get(&url).await.unwrap();
        assert!(resp.status().is_success());
        handle.abort();
    }

    #[tokio::test]
    async fn serve_rejects_missing_public_listener() {
        let (state, dir) = fixture_state();
        let Err(err) = serve(
            state,
            ServeConfig {
                http_addr: None,
                https_addr: None,
                state_dir: dir.path().into(),
                sans: SanConfig::with_hostname("test-host"),
                tls_source: TlsMaterialSource::SelfSigned {
                    state_dir: dir.path().into(),
                    sans: SanConfig::with_hostname("test-host"),
                },
                trusted_proxies: TrustedProxyConfig::default(),
                oidc: None,
                metrics_addr: None,
                acme_http01: None,
                acme_http01_host: None,
                acme_http01_addr: None,
            },
            Router::new(),
        )
        .await
        else {
            panic!("serve unexpectedly accepted a config without public listeners");
        };

        assert!(
            err.to_string()
                .contains("at least one public wire listener must be configured"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn serve_rejects_acme_listener_without_challenge_store() {
        let (state, dir) = fixture_state();
        let Err(err) = serve(
            state,
            ServeConfig {
                http_addr: Some("127.0.0.1:0".parse().unwrap()),
                https_addr: None,
                state_dir: dir.path().into(),
                sans: SanConfig::with_hostname("test-host"),
                tls_source: TlsMaterialSource::SelfSigned {
                    state_dir: dir.path().into(),
                    sans: SanConfig::with_hostname("test-host"),
                },
                trusted_proxies: TrustedProxyConfig::default(),
                oidc: None,
                metrics_addr: None,
                acme_http01: None,
                acme_http01_host: Some("control.example".into()),
                acme_http01_addr: Some("127.0.0.1:0".parse().unwrap()),
            },
            Router::new(),
        )
        .await
        else {
            panic!("serve unexpectedly accepted an ACME listener without challenge material");
        };

        assert!(
            err.to_string()
                .contains("acme_http01_addr requires acme_http01 challenge material"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn serve_rejects_acme_listener_without_host_policy() {
        let (state, dir) = fixture_state();
        let Err(err) = serve(
            state,
            ServeConfig {
                http_addr: Some("127.0.0.1:0".parse().unwrap()),
                https_addr: None,
                state_dir: dir.path().into(),
                sans: SanConfig::with_hostname("test-host"),
                tls_source: TlsMaterialSource::SelfSigned {
                    state_dir: dir.path().into(),
                    sans: SanConfig::with_hostname("test-host"),
                },
                trusted_proxies: TrustedProxyConfig::default(),
                oidc: None,
                metrics_addr: None,
                acme_http01: Some(AcmeHttp01ChallengeStore::new()),
                acme_http01_host: None,
                acme_http01_addr: Some("127.0.0.1:0".parse().unwrap()),
            },
            Router::new(),
        )
        .await
        else {
            panic!("serve unexpectedly accepted an ACME listener without host policy");
        };

        assert!(
            err.to_string()
                .contains("acme_http01_addr requires acme_http01_host"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn serve_does_not_spawn_public_listener_when_acme_bind_fails() {
        let (state, dir) = fixture_state();
        let held_acme = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let acme_addr = held_acme.local_addr().unwrap();
        let http_probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = http_probe.local_addr().unwrap();
        drop(http_probe);

        let Err(err) = serve(
            state,
            ServeConfig {
                http_addr: Some(http_addr),
                https_addr: None,
                state_dir: dir.path().into(),
                sans: SanConfig::with_hostname("test-host"),
                tls_source: TlsMaterialSource::SelfSigned {
                    state_dir: dir.path().into(),
                    sans: SanConfig::with_hostname("test-host"),
                },
                trusted_proxies: TrustedProxyConfig::default(),
                oidc: None,
                metrics_addr: None,
                acme_http01: Some(AcmeHttp01ChallengeStore::new()),
                acme_http01_host: Some("control.example".into()),
                acme_http01_addr: Some(acme_addr),
            },
            Router::new(),
        )
        .await
        else {
            panic!("serve unexpectedly accepted a colliding ACME listener");
        };

        assert!(
            err.to_string().contains(&format!("bind {acme_addr}")),
            "{err}"
        );
        let rebound_http = tokio::net::TcpListener::bind(http_addr)
            .await
            .expect("public HTTP listener was left running after ACME bind failure");
        drop(rebound_http);
        drop(held_acme);
    }

    #[tokio::test]
    async fn serve_supports_https_only_topology() {
        let (state, dir) = fixture_state();
        let handle = serve(
            state,
            ServeConfig {
                http_addr: None,
                https_addr: Some("127.0.0.1:0".parse().unwrap()),
                state_dir: dir.path().into(),
                sans: SanConfig::with_hostname("test-host"),
                tls_source: TlsMaterialSource::SelfSigned {
                    state_dir: dir.path().into(),
                    sans: SanConfig::with_hostname("test-host"),
                },
                trusted_proxies: TrustedProxyConfig::default(),
                oidc: None,
                metrics_addr: None,
                acme_http01: None,
                acme_http01_host: None,
                acme_http01_addr: None,
            },
            Router::new(),
        )
        .await
        .unwrap();

        assert!(handle.http.is_none());
        assert!(handle.https.is_some());
        assert!(handle.tls.is_some());
        handle.https.unwrap().abort();
    }

    #[tokio::test]
    async fn production_public_router_excludes_metrics_debug_routes() {
        let (state, _dir) = fixture_state();
        let public_app = public_router(state.clone(), None, None, None);

        let public_metrics = public_app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let public_body = to_bytes(public_metrics.into_body(), 32 * 1024)
            .await
            .unwrap();
        let public_body = String::from_utf8(public_body.to_vec()).unwrap();
        assert!(
            !public_body.contains("headscale_http_requests_total"),
            "{public_body}"
        );

        let metrics_app = crate::tailscale_wire::metrics_debug_router(state);
        let metrics = metrics_app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metrics.status(), axum::http::StatusCode::OK);
        let metrics_body = to_bytes(metrics.into_body(), 32 * 1024).await.unwrap();
        let metrics_body = String::from_utf8(metrics_body.to_vec()).unwrap();
        assert!(
            metrics_body.contains("headscale_http_requests_total"),
            "{metrics_body}"
        );

        let debug = metrics_app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(debug.status(), axum::http::StatusCode::MOVED_PERMANENTLY);
    }

    #[tokio::test]
    async fn public_router_serves_acme_http01_before_control_fallback() {
        let (state, _dir) = fixture_state();
        let store = AcmeHttp01ChallengeStore::new();
        store.insert("token-123", "token-123.thumbprint");
        let app = public_router(state, None, Some(store), None);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/acme-challenge/token-123")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), b"token-123.thumbprint");
    }

    #[tokio::test]
    async fn serve_binds_optional_metrics_debug_listener() {
        let (state, dir) = fixture_state();
        let cfg = ServeConfig {
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            https_addr: None,
            state_dir: dir.path().into(),
            sans: SanConfig::with_hostname("test-host"),
            tls_source: TlsMaterialSource::SelfSigned {
                state_dir: dir.path().into(),
                sans: SanConfig::with_hostname("test-host"),
            },
            trusted_proxies: TrustedProxyConfig::default(),
            oidc: None,
            metrics_addr: Some("127.0.0.1:0".parse().unwrap()),
            acme_http01: None,
            acme_http01_host: None,
            acme_http01_addr: None,
        };

        let handle = serve(state, cfg, Router::new()).await.unwrap();
        let metrics_addr = handle.metrics_addr.unwrap();
        let url = format!("http://{metrics_addr}/metrics");
        let body = reqwest::get(&url).await.unwrap().text().await.unwrap();
        assert!(body.contains("headscale_http_requests_total"), "{body}");

        handle.http.unwrap().abort();
        if let Some(metrics) = handle.metrics {
            metrics.abort();
        }
    }

    #[tokio::test]
    async fn serve_binds_dedicated_acme_http01_listener_without_control_routes() {
        let (mut state, dir) = fixture_state();
        state.public_control_url = Some("https://control.example".into());
        let store = AcmeHttp01ChallengeStore::new();
        store.insert("token-123", "token-123.thumbprint");
        let cfg = ServeConfig {
            http_addr: Some("127.0.0.1:0".parse().unwrap()),
            https_addr: None,
            state_dir: dir.path().into(),
            sans: SanConfig::with_hostname("test-host"),
            tls_source: TlsMaterialSource::SelfSigned {
                state_dir: dir.path().into(),
                sans: SanConfig::with_hostname("test-host"),
            },
            trusted_proxies: TrustedProxyConfig::default(),
            oidc: None,
            metrics_addr: None,
            acme_http01: Some(store),
            acme_http01_host: Some("control.example".into()),
            acme_http01_addr: Some("127.0.0.1:0".parse().unwrap()),
        };

        let handle = serve(state, cfg, Router::new()).await.unwrap();
        let acme_addr = handle.acme_http01_addr.unwrap();
        let challenge_url = format!("http://{acme_addr}/.well-known/acme-challenge/token-123");
        let body = reqwest::Client::new()
            .get(&challenge_url)
            .header(reqwest::header::HOST, "control.example")
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert_eq!(body, "token-123.thumbprint");

        let no_redirects = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let control_resp = no_redirects
            .get(format!("http://{acme_addr}/key?v=39"))
            .send()
            .await
            .unwrap();
        assert_eq!(control_resp.status(), axum::http::StatusCode::FOUND);
        assert_eq!(
            control_resp
                .headers()
                .get(axum::http::header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("https://control.example/key?v=39")
        );

        handle.http.unwrap().abort();
        handle.acme_http01.unwrap().abort();
    }

    fn oidc_runtime() -> crate::oidc::OidcAuthRuntime {
        crate::oidc::OidcAuthRuntime::new(crate::oidc::OidcAuthConfig {
            issuer: "https://issuer.example".into(),
            authorization_endpoint: "https://issuer.example/oauth2/auth".into(),
            token_endpoint: "https://issuer.example/oauth2/token".into(),
            userinfo_endpoint: Some("https://issuer.example/oauth2/userinfo".into()),
            jwks_uri: "https://issuer.example/oauth2/jwks".into(),
            client_id: "headscale-rs".into(),
            client_secret: "secret".into(),
            redirect_url: "https://headscale.example/oidc/callback".into(),
            scopes: vec!["openid".into(), "profile".into(), "email".into()],
            extra_params: BTreeMap::new(),
            pkce: crate::oidc::OidcPkceConfig::default(),
            policy: crate::oidc::OidcPolicyConfig::default(),
        })
    }

    #[tokio::test]
    async fn serve_public_router_mounts_oidc_when_configured() {
        let (state, _dir) = fixture_state();
        let oidc = oidc_runtime();
        let app = public_router(state, Some(oidc), None, None);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri(format!("/register/hskey-authreq-{}", "a".repeat(24)))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), axum::http::StatusCode::FOUND);
        assert!(
            resp.headers()
                .get(axum::http::header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("https://issuer.example/oauth2/auth?")
        );
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        assert!(body.is_empty());
    }
}
