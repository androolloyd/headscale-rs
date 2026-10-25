//! Server mode - runs the control plane.

use std::collections::{BTreeSet, HashMap};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio_rustls::server::TlsStream;
use tokio_stream::{
    StreamExt,
    wrappers::{TcpListenerStream, UnixListenerStream},
};
use tonic::transport::server::Connected;

use headscale_api::admin::{
    ApiKeyAdmin, MachineAdmin, MachineAdminError, PersistentApiKeyAdmin, PersistentMachineAdmin,
    PersistentOidcRegistrationHandler, PersistentPreauthAdmin, PersistentUserAdmin, PreauthAdmin,
    UserAdmin, UserRegistryError,
};
#[cfg(feature = "postgres-sqlx")]
use headscale_api::admin::{
    PersistentPostgresApiKeyAdmin, PersistentPostgresMachineAdmin,
    PersistentPostgresOidcRegistrationHandler, PersistentPostgresPreauthAdmin,
    PersistentPostgresUserAdmin,
};
use headscale_api::dns::{
    DnsConfigSpec, DnsStore, parse_extra_records, spawn_extra_records_watcher,
};
use headscale_api::grpc::upstream::HeadscaleAdminService;
use headscale_api::grpc_gateway;
use headscale_api::oidc::{OidcAuthRuntime, runtime_from_core_oidc};
use headscale_api::policy::{
    PolicyCheckNodeSnapshot, PolicyStore, warn_policy_tests_at_boot_for_snapshot,
};
use headscale_api::tailscale_wire::derp::{NativeDerpLifecycleDelivery, NativeDerpRuntime};
use headscale_api::tailscale_wire::native_derp::NativeDerpMap;
use headscale_api::tailscale_wire::tls;
use headscale_api::tailscale_wire::tls::{ReloadableServerConfig, SanConfig, TlsMaterialSource};
use headscale_api::tailscale_wire::{
    AllocError, BATCHER_OFFLINE_CLEANUP_INTERVAL, BATCHER_OFFLINE_CLEANUP_THRESHOLD, DerpMap,
    DerpMapStore, DerpRegion, DerpRegionNode, EphemeralGcHandle, IpAllocator, KnockConfig,
    MachineRegistrationStore, MachineRegistry, MapResponseDebugStore, PingTracker, PreauthRedeemer,
    REGISTRATION_CACHE_CLEANUP, REGISTRATION_CACHE_EXPIRATION, REGISTRATION_CACHE_MAX_ENTRIES,
    RegistrationCache, RouteHealthProbeHandle, RuntimeConfigSnapshot, ServerNoiseKey, WireState,
    serve, spawn_map_change_batcher, spawn_node_expiry_waker, spawn_offline_connection_cleanup,
    spawn_route_health_probe,
};
use headscale_core::config::{EmbeddedDerpConfig, OidcConfig};
use headscale_core::derp::{EmbeddedDerpRuntime, native::NativeDerpRelay};

use crate::acme_issuer::{AcmeHttp01IssuerConfig, LazyAcmeProvider};
use crate::config::{
    AdminCliConfig, CliConfig, LoggingConfig, PolicyConfig, ServerConfig, TuningConfig,
    UpstreamDatabaseConfig, UpstreamPostgresConfig, server_url_hostname,
    validate_server_url_base_domain,
};
use crate::derp_config::DerpConfig;
use headscale_db::{Database, DatabaseBackend, SqliteOpenOptions};

const NODE_EXPIRY_UPDATE_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_ACME_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
const DEFAULT_LETSENCRYPT_CACHE_DIR: &str = "/var/www/.cache";
const DEFAULT_LETSENCRYPT_LISTEN: &str = ":http";
const DEFAULT_LETSENCRYPT_CHALLENGE_TYPE: &str = "HTTP-01";
const NATIVE_DERP_SHUTDOWN_NOTICE_FLUSH_GRACE: Duration = Duration::from_millis(50);
/// Upper bound on the final database close (Go's `HSDatabase.Close` has none):
/// a connection that never comes back must not turn shutdown into a hang.
const DATABASE_CLOSE_TIMEOUT: Duration = Duration::from_secs(30);

mod acme_grpc_incoming;

#[derive(Debug, Clone)]
pub(crate) struct RunServerConfig {
    pub listen: String,
    pub db_path: PathBuf,
    pub mesh_cidr: String,
    pub mesh_cidr_v6: Option<String>,
    pub ip_allocation: String,
    pub server_url: Option<String>,
    pub state_dir: PathBuf,
    pub noise_private_key_path: Option<PathBuf>,
    pub https_listen: Option<String>,
    pub metrics_listen_addr: Option<String>,
    pub tls_hostname: Option<String>,
    pub unix_socket: PathBuf,
    pub unix_socket_permission: u32,
    pub grpc_listen_addr: String,
    pub grpc_allow_insecure: bool,
    pub trusted_proxies: Vec<String>,
    pub disable_check_updates: bool,
    pub tls: TlsRuntimeConfig,
    pub oidc: OidcConfig,
    pub node_expiry: Duration,
    pub node_routes_ha_probe_interval: Duration,
    pub node_routes_ha_probe_timeout: Duration,
    pub embedded_derp: EmbeddedDerpConfig,
    pub derp: Option<DerpConfig>,
    pub database: Option<UpstreamDatabaseConfig>,
    pub dns: Option<DnsConfigSpec>,
    pub policy: PolicyConfig,
    pub taildrop_enabled: bool,
    pub logtail_enabled: bool,
    pub auto_update_enabled: bool,
    pub logging: LoggingConfig,
    pub cli: AdminCliConfig,
    pub tuning: TuningConfig,
    pub ephemeral_node_inactivity_timeout: Duration,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TlsRuntimeConfig {
    pub acme_url: Option<String>,
    pub acme_email: Option<String>,
    pub acme_ca_root_path: Option<PathBuf>,
    pub letsencrypt_hostname: Option<String>,
    pub letsencrypt_cache_dir: Option<PathBuf>,
    pub letsencrypt_listen: Option<String>,
    pub letsencrypt_challenge_type: Option<String>,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

impl TlsRuntimeConfig {
    fn letsencrypt_enabled(&self) -> bool {
        self.letsencrypt_hostname
            .as_deref()
            .is_some_and(|hostname| !hostname.is_empty())
    }

    fn manual_paths(&self) -> Option<(&Path, &Path)> {
        let cert_path = self
            .cert_path
            .as_deref()
            .filter(|path| !path.as_os_str().is_empty())?;
        let key_path = self
            .key_path
            .as_deref()
            .filter(|path| !path.as_os_str().is_empty())?;
        Some((cert_path, key_path))
    }

    fn has_manual_tls(&self) -> bool {
        self.manual_paths().is_some()
    }

    fn cache_dir_string(&self) -> String {
        self.cache_dir_path().display().to_string()
    }

    fn cache_dir_path(&self) -> PathBuf {
        self.letsencrypt_cache_dir
            .as_ref()
            .filter(|path| !path.as_os_str().is_empty())
            .cloned()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_LETSENCRYPT_CACHE_DIR))
    }

    fn letsencrypt_listen_string(&self) -> String {
        non_empty_str(self.letsencrypt_listen.as_deref())
            .unwrap_or(DEFAULT_LETSENCRYPT_LISTEN)
            .to_string()
    }

    fn challenge_type_string(&self) -> String {
        non_empty_str(self.letsencrypt_challenge_type.as_deref())
            .unwrap_or(DEFAULT_LETSENCRYPT_CHALLENGE_TYPE)
            .to_string()
    }

    fn acme_url_string(&self) -> String {
        non_empty_str(self.acme_url.as_deref())
            .unwrap_or(DEFAULT_ACME_URL)
            .to_string()
    }

    fn acme_runtime_plan(
        &self,
        public_listeners: PublicListenerPlan,
    ) -> Result<Option<AcmeRuntimePlan>> {
        let Some(hostname) = self
            .letsencrypt_hostname
            .as_deref()
            .filter(|hostname| !hostname.is_empty())
        else {
            return Ok(None);
        };
        let challenge_type = self.challenge_type_string();
        let challenge_listener = match challenge_type.as_str() {
            "HTTP-01" => {
                let listen = self.letsencrypt_listen_string();
                AcmeChallengeListener::Http01 {
                    listen: listen.clone(),
                    addr: parse_acme_http01_listen_addr(&listen)?,
                }
            }
            "TLS-ALPN-01" => AcmeChallengeListener::TlsAlpn01 {
                addr: public_listeners.https_addr.ok_or_else(|| {
                    anyhow::anyhow!(
                        "TLS-ALPN-01 ACME requires a public TLS listener on listen_addr"
                    )
                })?,
            },
            other => anyhow::bail!(
                "unsupported tls_letsencrypt_challenge_type {other:?}; supported values are HTTP-01 and TLS-ALPN-01"
            ),
        };
        Ok(Some(AcmeRuntimePlan {
            hostname: hostname.to_string(),
            acme_url: self.acme_url_string(),
            ca_root_path: self.acme_ca_root_path.clone(),
            cache_dir: self.cache_dir_path(),
            challenge_listener,
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcmeRuntimePlan {
    hostname: String,
    acme_url: String,
    ca_root_path: Option<PathBuf>,
    cache_dir: PathBuf,
    challenge_listener: AcmeChallengeListener,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum AcmeChallengeListener {
    Http01 { listen: String, addr: SocketAddr },
    TlsAlpn01 { addr: SocketAddr },
}

struct AcmeHttp01Runtime {
    issuer_config: AcmeHttp01IssuerConfig,
    store: headscale_api::tailscale_wire::acme::AcmeHttp01ChallengeStore,
    handle: Option<tokio::task::JoinHandle<Result<(), std::io::Error>>>,
}

impl AcmeHttp01Runtime {
    fn take_handle(&mut self) -> Option<tokio::task::JoinHandle<Result<(), std::io::Error>>> {
        self.handle.take()
    }
}

impl Drop for AcmeHttp01Runtime {
    fn drop(&mut self) {
        if let Some(handle) = &self.handle {
            handle.abort();
        }
    }
}

/// Run the control plane server.
pub(crate) async fn run_server(cfg: RunServerConfig) -> Result<()> {
    run_tailscale_wire_server(cfg).await
}

/// Upstream `configtest` constructs a server before exiting. Open the same
/// storage as `serve`, prepare its allocator/policy/nodes and discover OIDC
/// before returning, without binding control or admin listeners.
pub(crate) async fn initialize_configtest_storage(config: &CliConfig) -> Result<()> {
    let defaults = ServerConfig::default();
    let server = config.server.as_ref().unwrap_or(&defaults);
    let server_noise_key = Arc::new(
        ServerNoiseKey::load_or_generate_with_configured_path(
            &server.state_dir,
            server.noise_private_key_path.as_deref(),
        )
        .context("reading or creating Noise protocol private key")?,
    );

    let db = if config
        .database
        .as_ref()
        .and_then(UpstreamDatabaseConfig::runtime_backend)
        == Some(DatabaseBackend::Postgres)
    {
        open_postgres_runtime_database(config.database.as_ref()).await?
    } else {
        RuntimeDatabase::Sqlite(
            open_sqlite_database(&server.db_path, config.database.as_ref()).await?,
        )
    };
    let registration_cache = Arc::new(registration_cache_from_tuning(&config.tuning));
    let prepared = match &db {
        RuntimeDatabase::Sqlite(db) => {
            prepare_sqlite_persistent_wire_runtime(
                db.pool(),
                &server.mesh_cidr,
                server.mesh_cidr_v6.as_deref(),
                &server.ip_allocation,
                &config.policy,
                server_noise_key,
                registration_cache,
            )
            .await
        }
        #[cfg(feature = "postgres-sqlx")]
        RuntimeDatabase::Postgres(pool) => {
            prepare_postgres_persistent_wire_runtime(
                pool,
                &server.mesh_cidr,
                server.mesh_cidr_v6.as_deref(),
                &server.ip_allocation,
                &config.policy,
                server_noise_key,
                registration_cache,
            )
            .await
        }
    }
    .context("init state")?;
    let oidc = upstream_oidc_runtime_config(&config.oidc);
    runtime_from_core_oidc(&oidc, server.server_url.as_deref().unwrap_or_default()).await?;
    let embedded_derp_config = server
        .embedded_derp
        .clone()
        .with_default_derper_config_path(&server.state_dir);
    let _native_derp = prepare_native_derp_runtime(
        &embedded_derp_config,
        &prepared.server_noise_key,
        &prepared.wire_registry,
    )?;
    drop(prepared);
    Ok(())
}

async fn run_tailscale_wire_server(cfg: RunServerConfig) -> Result<()> {
    validate_unsupported_runtime_boundaries(&cfg)?;
    let public_listeners = public_listener_plan(&cfg)?;
    let acme_runtime = cfg.tls.acme_runtime_plan(public_listeners)?;
    validate_supported_runtime_config(&cfg)?;
    tracing::debug!("Starting headscale-compatible Tailscale control plane");
    tracing::debug!(
        "  Public HTTP: {}",
        optional_addr_status(public_listeners.http_addr)
    );
    tracing::debug!(
        "  Public HTTPS: {}",
        optional_addr_status(public_listeners.https_addr)
    );
    tracing::debug!(
        "  Metrics/debug: {}",
        cfg.metrics_listen_addr
            .as_deref()
            .map(str::trim)
            .filter(|addr| !addr.is_empty())
            .unwrap_or("<disabled>")
    );
    tracing::debug!("  Database: {}", runtime_database_status(&cfg));
    tracing::debug!("  State dir: {}", cfg.state_dir.display());
    if cfg.mesh_cidr.trim().is_empty() {
        tracing::debug!("  IPv4 prefix: <disabled>");
    } else {
        tracing::debug!("  IPv4 prefix: {}", cfg.mesh_cidr);
    }
    if let Some(mesh_cidr_v6) = &cfg.mesh_cidr_v6 {
        tracing::debug!("  IPv6 prefix: {}", mesh_cidr_v6);
    }
    tracing::debug!("  Local gRPC socket: {}", cfg.unix_socket.display());
    tracing::debug!("  Remote gRPC: {}", remote_grpc_status(&cfg));
    if let Some(plan) = &acme_runtime {
        let challenge_type = match plan.challenge_listener {
            AcmeChallengeListener::Http01 { .. } => "HTTP-01",
            AcmeChallengeListener::TlsAlpn01 { .. } => "TLS-ALPN-01",
        };
        tracing::debug!(
            hostname = %plan.hostname,
            cache_dir = %plan.cache_dir.display(),
            directory_url = %plan.acme_url,
            challenge_type,
            "ACME TLS configured"
        );
    }

    let server_url = cfg.server_url.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "server.server_url is required so clients receive absolute registration URLs"
        )
    })?;
    create_private_dir_all(&cfg.state_dir).with_context(|| {
        format!(
            "Failed to create state directory: {}",
            cfg.state_dir.display()
        )
    })?;

    // NewHeadscale reads its Noise identity before opening/migrating state.
    // Reuse this exact key in the runtime instead of reading it a second time.
    let server_noise_key = Arc::new(
        ServerNoiseKey::load_or_generate_with_configured_path(
            &cfg.state_dir,
            cfg.noise_private_key_path.as_deref(),
        )
        .context("reading or creating Noise protocol private key")?,
    );
    let db = open_runtime_database(&cfg).await?;
    let prepared = prepare_persistent_wire_runtime_from_database(&db, &cfg, server_noise_key)
        .await
        .context("initializing: creating new headscale: init state")?;
    let oidc_config = upstream_oidc_runtime_config(&cfg.oidc);
    let oidc = runtime_from_core_oidc(&oidc_config, server_url)
        .await
        .context("initializing: creating new headscale")?;
    let version = crate::VersionInfo::current();
    tracing::info!(
        version = version.version,
        commit = version.commit,
        "starting headscale"
    );
    tracing::info!(
        minimum_version = "v1.80",
        "Clients with a lower minimum version will be rejected"
    );
    let embedded_derp_config = cfg
        .embedded_derp
        .clone()
        .with_default_derper_config_path(&cfg.state_dir);
    let native_derp = prepare_native_derp_runtime(
        &embedded_derp_config,
        &prepared.server_noise_key,
        &prepared.wire_registry,
    )
    .context("start native DERP relay runtime")?;
    let embedded_derp_runtime =
        EmbeddedDerpRuntime::start_with_state_dir(embedded_derp_config, &cfg.state_dir)
            .await
            .context("start embedded DERP/STUN runtime")?;
    if let Some(addr) = embedded_derp_runtime.stun_local_addr() {
        tracing::info!(%addr, "embedded STUN listener ready");
    }
    if let Some(status) = embedded_derp_runtime.sidecar_status() {
        tracing::info!(?status, "embedded DERP sidecar ready");
    }
    let derp_shuffle_base_domain = cfg.dns.as_ref().map_or("", |dns| dns.base_domain.as_str());
    let native_derp_map = native_derp_map_from_runtime_config(
        cfg.derp.as_ref(),
        embedded_derp_runtime.config(),
        derp_shuffle_base_domain,
    )
    .await
    .context("load DERP runtime config")?;
    let derp_map = native_derp_map.projection();
    let (dns_store, dns_extra_records_path) = dns_store_from_config(
        cfg.dns.clone(),
        Some(&cfg.mesh_cidr),
        cfg.mesh_cidr_v6.as_deref(),
    )
    .context("load DNS runtime config")?;
    let mut runtime_config = runtime_config_snapshot(&cfg, &derp_map, dns_store.as_ref());
    // YAML can carry non-finite floats. Keep the typed map for the native
    // encoder to reject at response generation, rather than failing startup.
    runtime_config.derp.derp_map = native_derp_map
        .json_value()
        .unwrap_or(serde_json::Value::Null);
    let runtime_config = Arc::new(runtime_config);
    let mut runtime = prepared.finish(
        server_url,
        oidc,
        derp_map,
        dns_store.clone(),
        runtime_config,
    )?;
    runtime.state.derp_map.set_native(native_derp_map);
    runtime.state.native_derp = native_derp;
    let ephemeral_gc = runtime.state.machines.configure_ephemeral_gc(
        runtime
            .state
            .registration_store
            .as_ref()
            .map(Arc::downgrade),
        cfg.ephemeral_node_inactivity_timeout,
    );
    let scheduled_ephemeral = ephemeral_gc.schedule_existing();
    tracing::info!(
        nodes = scheduled_ephemeral,
        timeout = ?ephemeral_gc.inactivity_timeout(),
        "scheduled existing ephemeral nodes for garbage collection"
    );
    let node_store_batch_size = usize::try_from(cfg.tuning.node_store_batch_size).unwrap_or(100);
    let nodestore_write_batcher = runtime.state.machines.configure_nodestore_write_batcher(
        node_store_batch_size,
        Duration::from_nanos(cfg.tuning.node_store_batch_timeout),
    );
    let node_expiry_waker =
        spawn_node_expiry_waker(runtime.state.machines.clone(), NODE_EXPIRY_UPDATE_INTERVAL);
    let map_change_batcher = spawn_map_change_batcher(
        runtime.state.machines.clone(),
        Duration::from_nanos(cfg.tuning.batch_change_delay),
    );
    let route_health_probe = spawn_route_health_probe(
        runtime.state.clone(),
        cfg.node_routes_ha_probe_interval,
        cfg.node_routes_ha_probe_timeout,
    );
    let offline_connection_cleanup = spawn_offline_connection_cleanup(
        runtime.state.machines.clone(),
        BATCHER_OFFLINE_CLEANUP_INTERVAL,
        BATCHER_OFFLINE_CLEANUP_THRESHOLD,
    );

    let metrics_addr =
        optional_socket_addr(cfg.metrics_listen_addr.as_deref(), "metrics_listen_addr")?;
    let grpc_addr = parse_socket_addr(&cfg.grpc_listen_addr, "grpc_listen_addr")?;
    let tls_hostname = cfg
        .tls_hostname
        .clone()
        .unwrap_or_else(|| hostname_from_server_url(server_url));
    let sans = SanConfig::with_hostname(tls_hostname);
    warn_tls_server_url(&cfg, public_listeners, server_url);
    let mut acme_http01_runtime = start_acme_http01_runtime(
        acme_runtime.as_ref(),
        cfg.tls.acme_email.clone(),
        server_url,
    )
    .await?;
    let acme_tls_alpn_issuer_config =
        acme_tls_alpn_issuer_config(acme_runtime.as_ref(), cfg.tls.acme_email.clone());
    // Construct only the empty bound resolver here. Cache reads, key generation
    // and ACME requests belong to the first authorized TLS handshake.
    let (acme_provider, acme_shutdown) = if let Some(http01) = acme_http01_runtime.as_ref() {
        let (provider, shutdown) =
            LazyAcmeProvider::new(http01.issuer_config.clone(), Some(http01.store.clone()))?;
        (
            Some(provider as Arc<dyn tls::AcmeCertificateProvider>),
            Some(shutdown),
        )
    } else if let Some(config) = acme_tls_alpn_issuer_config {
        let (provider, shutdown) = LazyAcmeProvider::new(config, None)?;
        (
            Some(provider as Arc<dyn tls::AcmeCertificateProvider>),
            Some(shutdown),
        )
    } else {
        (None, None)
    };
    let tls_source = tls_material_source(&cfg, &sans)?;
    let (acme_http01, acme_http01_host, acme_http01_addr) =
        if let Some(runtime) = acme_http01_runtime.as_ref() {
            (
                Some(runtime.store.clone()),
                Some(runtime.issuer_config.hostname.clone()),
                None,
            )
        } else {
            (None, None, None)
        };
    let extra_routes = production_extra_routes(&runtime);
    let serve_cfg = serve::ServeConfig {
        http_addr: public_listeners.http_addr,
        https_addr: public_listeners.https_addr,
        state_dir: cfg.state_dir.clone(),
        sans: sans.clone(),
        tls_source: tls_source.clone(),
        trusted_proxies: serve::TrustedProxyConfig::parse(&cfg.trusted_proxies)
            .map_err(anyhow::Error::msg)
            .context("parse trusted_proxies")?,
        oidc: runtime.oidc,
        metrics_addr,
        acme_http01,
        acme_http01_host,
        acme_http01_addr,
    };
    let local_grpc_listener =
        bind_unix_grpc_listener(&cfg.unix_socket, cfg.unix_socket_permission).await?;
    let remote_grpc_security =
        remote_grpc_security_with_provider(&cfg, &tls_source, acme_provider.clone())?;
    let remote_grpc_listener = match remote_grpc_security {
        Some(security) => {
            tracing::info!("enabling remote gRPC at {}", cfg.grpc_listen_addr);
            if matches!(&security, RemoteGrpcSecurity::Insecure) {
                tracing::warn!("gRPC is running without security");
            }
            Some((
                bind_tcp_grpc_listener(grpc_addr).await?,
                grpc_addr,
                security,
            ))
        }
        None => None,
    };
    let derp_auto_update = spawn_derp_auto_update_task(
        cfg.derp.clone(),
        cfg.embedded_derp.clone(),
        runtime.state.derp_map.clone(),
        derp_shuffle_base_domain.to_string(),
    );

    let native_derp_shutdown = runtime.state.native_derp.clone();
    let native_stream_shutdown = runtime.state.machines.clone();
    let (handle, http_shutdown) = match acme_provider {
        Some(provider) => {
            serve::serve_with_acme_provider(runtime.state, serve_cfg, extra_routes, provider).await
        }
        None => serve::serve_with_shutdown(runtime.state, serve_cfg, extra_routes).await,
    }
    .context("start Tailscale wire listeners")?;
    if let Some(addr) = public_listeners.https_addr.or(public_listeners.http_addr) {
        tracing::info!("listening and serving HTTP on: {addr}");
    }
    let dns_extra_records_watcher = dns_extra_records_path.map(|path| {
        tracing::info!(path = %path.display(), "watching DNS extra-records file");
        spawn_extra_records_watcher((*dns_store).clone(), path, None)
    });
    let (local_grpc_stop, local_grpc_stopped) = tokio::sync::oneshot::channel();
    let local_grpc = spawn_local_grpc_listener_with_shutdown(
        local_grpc_listener,
        cfg.unix_socket.clone(),
        runtime.admin_service.clone(),
        async move {
            let _ = local_grpc_stopped.await;
        },
    );
    let (remote_grpc, remote_grpc_stop) = match remote_grpc_listener {
        Some((listener, addr, security)) => {
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let task = spawn_remote_grpc_listener_with_shutdown(
                listener,
                addr,
                runtime.admin_service.clone(),
                security,
                async move {
                    let _ = stopped.await;
                },
            );
            (Some(task), Some(stop))
        }
        None => (None, None),
    };
    let grpc_shutdown = GrpcListenerShutdown {
        local: local_grpc_stop,
        remote: remote_grpc_stop,
    };
    let policy_reload = spawn_policy_reload_signal_task(runtime.admin_service.clone());
    tracing::debug!("Headscale-compatible Tailscale control plane ready");
    let external_acme_http01 = acme_http01_runtime
        .as_mut()
        .and_then(AcmeHttp01Runtime::take_handle);
    // Go stops scheduled work before shutting down its listeners/batcher.
    // Keep only the map batcher and NodeStore worker alive for disconnects.
    let mut maintenance = vec![
        node_expiry_waker.abort_handle(),
        offline_connection_cleanup.abort_handle(),
    ];
    maintenance.extend(
        route_health_probe
            .as_ref()
            .map(RouteHealthProbeHandle::abort_handle),
    );
    maintenance.extend(
        policy_reload
            .as_ref()
            .map(tokio::task::JoinHandle::abort_handle),
    );
    maintenance.extend(
        dns_extra_records_watcher
            .as_ref()
            .map(tokio::task::JoinHandle::abort_handle),
    );
    maintenance.extend(
        derp_auto_update
            .as_ref()
            .map(tokio::task::JoinHandle::abort_handle),
    );
    if let Some(shutdown) = acme_shutdown.as_ref() {
        maintenance.push(shutdown.abort_handle());
    }
    let serve_result = await_serve_handle(
        handle,
        local_grpc,
        remote_grpc,
        external_acme_http01,
        native_derp_shutdown,
        native_stream_shutdown,
        maintenance,
        grpc_shutdown,
        http_shutdown,
        ephemeral_gc.clone(),
    )
    .await;
    if let Some(handle) = policy_reload {
        handle.abort();
    }
    drop(acme_shutdown);
    node_expiry_waker.abort();
    if let Some(handle) = route_health_probe {
        handle.abort();
    }
    map_change_batcher.abort();
    offline_connection_cleanup.abort();
    ephemeral_gc.abort();
    drop(nodestore_write_batcher);
    if let Some(handle) = dns_extra_records_watcher {
        handle.abort();
    }
    if let Some(handle) = derp_auto_update {
        handle.abort();
    }
    drop(embedded_derp_runtime);
    // Last, once the NodeStore worker has drained and joined: Go closes state
    // and database after its batcher and listeners (hscontrol/app.go Serve).
    close_runtime_database(db).await;
    serve_result
}

/// `HSDatabase.Close` (hscontrol/db/db.go): VACUUM a WAL-mode SQLite database,
/// ignoring the result, then close it, so the stopped server leaves no WAL
/// frames behind and the database file alone carries every committed row.
async fn close_runtime_database(db: RuntimeDatabase) {
    let close = async {
        match db {
            RuntimeDatabase::Sqlite(db) => {
                let write_ahead_log = sqlx::query_scalar::<_, String>("PRAGMA journal_mode")
                    .fetch_one(db.pool())
                    .await
                    .is_ok_and(|mode| mode.eq_ignore_ascii_case("wal"));
                if write_ahead_log
                    && let Err(error) = sqlx::query("VACUUM").execute(db.pool()).await
                {
                    tracing::debug!(%error, "VACUUM before closing the database failed");
                }
                db.close().await;
            }
            #[cfg(feature = "postgres-sqlx")]
            RuntimeDatabase::Postgres(pool) => pool.close().await,
        }
    };
    if tokio::time::timeout(DATABASE_CLOSE_TIMEOUT, close)
        .await
        .is_err()
    {
        tracing::warn!(
            timeout = ?DATABASE_CLOSE_TIMEOUT,
            "closing the database did not finish in time; continuing shutdown"
        );
    }
}

#[cfg(test)]
fn attach_native_derp_runtime(state: &mut WireState, cfg: &EmbeddedDerpConfig) -> Result<()> {
    state.native_derp = prepare_native_derp_runtime(cfg, &state.server_noise_key, &state.machines)?;
    Ok(())
}

fn prepare_native_derp_runtime(
    cfg: &EmbeddedDerpConfig,
    server_noise_key: &ServerNoiseKey,
    machines: &Arc<MachineRegistry>,
) -> Result<Option<Arc<NativeDerpRuntime>>> {
    if !cfg.native_relay_enabled() {
        return Ok(None);
    }

    let mut native_derp =
        NativeDerpRuntime::load_or_generate(&cfg.derper_config_path, NativeDerpRelay::new())?;
    if native_derp.public_key() == server_noise_key.public_bytes() {
        bail!("embedded DERP private key must not be the same as the Noise private key");
    }
    if cfg.verify_clients {
        let machines = Arc::clone(machines);
        native_derp = native_derp.with_client_verifier(move |client_public| {
            machines.get(&hex::encode(client_public)).is_some()
        });
    }
    // Rust-only (headscale-go has no such line, and its startup log is compared
    // byte for byte), so keep it below info.
    tracing::debug!(
        public_key = %hex::encode(native_derp.public_key()),
        path = %cfg.derper_config_path.display(),
        verify_clients = native_derp.client_verification_enabled(),
        "embedded native DERP relay ready"
    );
    Ok(Some(Arc::new(native_derp)))
}

struct PersistentWireRuntime {
    state: WireState,
    oidc: Option<OidcAuthRuntime>,
    admin_service: HeadscaleAdminService,
}

/// Validated, hydrated state prepared before provider or relay initialization.
/// Consumed only after the DNS/DERP configuration needed by WireState exists.
struct PreparedPersistentWireRuntime {
    server_noise_key: Arc<ServerNoiseKey>,
    stores: PersistentRuntimeStores,
    wire_registry: Arc<MachineRegistry>,
    registration_cache: Arc<RegistrationCache>,
    ip_allocator: Arc<dyn IpAllocator>,
    policy: Arc<PolicyStore>,
    admin_service: HeadscaleAdminService,
}

impl PreparedPersistentWireRuntime {
    fn finish(
        self,
        server_url: &str,
        oidc: Option<OidcAuthRuntime>,
        derp_map: DerpMap,
        dns: Arc<DnsStore>,
        runtime_config: Arc<RuntimeConfigSnapshot>,
    ) -> Result<PersistentWireRuntime> {
        let Self {
            server_noise_key,
            stores,
            wire_registry,
            registration_cache,
            ip_allocator,
            policy,
            admin_service,
        } = self;
        wire_registry.configure_registration_expiry(runtime_config.node.expiry);
        wire_registry
            .try_configure_policy(&policy)
            .map_err(anyhow::Error::msg)
            .context("initializing policy manager nodes")?;
        wire_registry.configure_given_name_domain(&runtime_config.base_domain);
        wire_registry.configure_ip_allocator(&ip_allocator);
        headscale_api::tailscale_wire::map::log_invalid_persisted_names(
            &wire_registry,
            &runtime_config.base_domain,
        );
        let oidc = stores.configure_oidc(
            oidc,
            registration_cache.clone(),
            policy.clone(),
            wire_registry.clone(),
            ip_allocator.clone(),
        );
        let state = WireState {
            server_noise_key,
            preauth: stores.preauth_redeemer(),
            ip_allocator,
            machines: wire_registry,
            registration_store: Some(stores.registration_store()),
            registration_gate: None,
            derp_map: DerpMapStore::shared(derp_map),
            native_derp: None,
            policy,
            knock: KnockConfig::disabled(),
            dns,
            public_control_url: Some(server_url.to_string()),
            runtime_config,
            registration_cache,
            pings: Arc::new(PingTracker::new()),
            mapresponse_debug: Arc::new(MapResponseDebugStore::from_env()),
        };
        Ok(PersistentWireRuntime {
            state,
            oidc,
            admin_service,
        })
    }
}

enum RuntimeDatabase {
    Sqlite(Database),
    #[cfg(feature = "postgres-sqlx")]
    Postgres(sqlx::PgPool),
}

#[derive(Clone)]
enum PersistentRuntimeStores {
    Sqlite(SqlitePersistentRuntimeStores),
    #[cfg(feature = "postgres-sqlx")]
    Postgres(PostgresPersistentRuntimeStores),
}

#[derive(Clone)]
struct SqlitePersistentRuntimeStores {
    users: Arc<PersistentUserAdmin>,
    api_keys: Arc<PersistentApiKeyAdmin>,
    preauth: Arc<PersistentPreauthAdmin>,
    machines: Arc<PersistentMachineAdmin>,
}

#[cfg(feature = "postgres-sqlx")]
#[derive(Clone)]
struct PostgresPersistentRuntimeStores {
    users: Arc<PersistentPostgresUserAdmin>,
    api_keys: Arc<PersistentPostgresApiKeyAdmin>,
    preauth: Arc<PersistentPostgresPreauthAdmin>,
    machines: Arc<PersistentPostgresMachineAdmin>,
}

impl PersistentRuntimeStores {
    fn sqlite(pool: &sqlx::SqlitePool, wire_registry: Arc<MachineRegistry>) -> Self {
        let users = Arc::new(PersistentUserAdmin::new(pool.clone()));
        let api_keys = Arc::new(PersistentApiKeyAdmin::new(pool.clone()));
        let preauth =
            Arc::new(PersistentPreauthAdmin::new(pool.clone()).with_user_admin(users.clone()));
        let machines = Arc::new(
            PersistentMachineAdmin::new(pool.clone())
                .with_user_admin(users.clone())
                .with_wire_registry(wire_registry),
        );
        Self::Sqlite(SqlitePersistentRuntimeStores {
            users,
            api_keys,
            preauth,
            machines,
        })
    }

    #[cfg(feature = "postgres-sqlx")]
    fn postgres(pool: &sqlx::PgPool, wire_registry: Arc<MachineRegistry>) -> Self {
        let users = Arc::new(PersistentPostgresUserAdmin::new(pool.clone()));
        let api_keys = Arc::new(PersistentPostgresApiKeyAdmin::new(pool.clone()));
        let preauth = Arc::new(
            PersistentPostgresPreauthAdmin::new(pool.clone()).with_user_admin(users.clone()),
        );
        let machines = Arc::new(
            PersistentPostgresMachineAdmin::new(pool.clone())
                .with_user_admin(users.clone())
                .with_wire_registry(wire_registry),
        );
        Self::Postgres(PostgresPersistentRuntimeStores {
            users,
            api_keys,
            preauth,
            machines,
        })
    }

    fn users(&self) -> Arc<dyn UserAdmin> {
        match self {
            Self::Sqlite(stores) => {
                let users: Arc<dyn UserAdmin> = stores.users.clone();
                users
            }
            #[cfg(feature = "postgres-sqlx")]
            Self::Postgres(stores) => {
                let users: Arc<dyn UserAdmin> = stores.users.clone();
                users
            }
        }
    }

    fn api_keys(&self) -> Arc<dyn ApiKeyAdmin> {
        match self {
            Self::Sqlite(stores) => {
                let api_keys: Arc<dyn ApiKeyAdmin> = stores.api_keys.clone();
                api_keys
            }
            #[cfg(feature = "postgres-sqlx")]
            Self::Postgres(stores) => {
                let api_keys: Arc<dyn ApiKeyAdmin> = stores.api_keys.clone();
                api_keys
            }
        }
    }

    fn preauth_admin(&self) -> Arc<dyn PreauthAdmin> {
        match self {
            Self::Sqlite(stores) => {
                let preauth: Arc<dyn PreauthAdmin> = stores.preauth.clone();
                preauth
            }
            #[cfg(feature = "postgres-sqlx")]
            Self::Postgres(stores) => {
                let preauth: Arc<dyn PreauthAdmin> = stores.preauth.clone();
                preauth
            }
        }
    }

    fn preauth_redeemer(&self) -> Arc<dyn PreauthRedeemer> {
        match self {
            Self::Sqlite(stores) => {
                let preauth: Arc<dyn PreauthRedeemer> = stores.preauth.clone();
                preauth
            }
            #[cfg(feature = "postgres-sqlx")]
            Self::Postgres(stores) => {
                let preauth: Arc<dyn PreauthRedeemer> = stores.preauth.clone();
                preauth
            }
        }
    }

    fn machines(&self) -> Arc<dyn MachineAdmin> {
        match self {
            Self::Sqlite(stores) => {
                let machines: Arc<dyn MachineAdmin> = stores.machines.clone();
                machines
            }
            #[cfg(feature = "postgres-sqlx")]
            Self::Postgres(stores) => {
                let machines: Arc<dyn MachineAdmin> = stores.machines.clone();
                machines
            }
        }
    }

    fn registration_store(&self) -> Arc<dyn MachineRegistrationStore> {
        match self {
            Self::Sqlite(stores) => {
                let machines: Arc<dyn MachineRegistrationStore> = stores.machines.clone();
                machines
            }
            #[cfg(feature = "postgres-sqlx")]
            Self::Postgres(stores) => {
                let machines: Arc<dyn MachineRegistrationStore> = stores.machines.clone();
                machines
            }
        }
    }

    async fn hydrate_wire_registry(&self, wire_registry: &MachineRegistry) -> Result<usize> {
        match self {
            Self::Sqlite(stores) => stores
                .machines
                .hydrate_wire_registry(wire_registry)
                .await
                .map_err(startup_node_error),
            #[cfg(feature = "postgres-sqlx")]
            Self::Postgres(stores) => stores
                .machines
                .hydrate_wire_registry(wire_registry)
                .await
                .map_err(startup_node_error),
        }
    }

    fn configure_oidc(
        &self,
        oidc: Option<OidcAuthRuntime>,
        registration_cache: Arc<RegistrationCache>,
        policy: Arc<PolicyStore>,
        wire_registry: Arc<MachineRegistry>,
        ip_allocator: Arc<dyn IpAllocator>,
    ) -> Option<OidcAuthRuntime> {
        let runtime = oidc?;

        match self {
            Self::Sqlite(stores) => {
                let user_store = headscale_api::admin::PolicyOidcUserStore::new(
                    stores.users.clone(),
                    policy.as_ref().clone(),
                    wire_registry.clone(),
                );
                let handler = PersistentOidcRegistrationHandler::new(
                    registration_cache,
                    stores.machines.clone(),
                    policy,
                )
                .with_wire_registry(wire_registry)
                .with_ip_allocator(ip_allocator);
                Some(
                    runtime
                        .with_user_store(Arc::new(user_store))
                        .with_registration_handler(Arc::new(handler)),
                )
            }
            #[cfg(feature = "postgres-sqlx")]
            Self::Postgres(stores) => {
                let user_store = headscale_api::admin::PolicyOidcUserStore::new(
                    stores.users.clone(),
                    policy.as_ref().clone(),
                    wire_registry.clone(),
                );
                let handler = PersistentPostgresOidcRegistrationHandler::new(
                    registration_cache,
                    stores.machines.clone(),
                    policy,
                )
                .with_wire_registry(wire_registry)
                .with_ip_allocator(ip_allocator);
                Some(
                    runtime
                        .with_user_store(Arc::new(user_store))
                        .with_registration_handler(Arc::new(handler)),
                )
            }
        }
    }
}

fn startup_node_error(error: MachineAdminError) -> anyhow::Error {
    match error {
        MachineAdminError::Storage(message) => anyhow::anyhow!(message),
        error => error.into(),
    }
}

fn dns_store_from_config(
    spec: Option<DnsConfigSpec>,
    mesh_cidr: Option<&str>,
    mesh_cidr_v6: Option<&str>,
) -> Result<(Arc<DnsStore>, Option<PathBuf>)> {
    let Some(spec) = spec else {
        return Ok((Arc::new(DnsStore::new()), None));
    };
    let extra_records_path = spec
        .extra_records_path
        .clone()
        .filter(|path| !path.as_os_str().is_empty());
    let store = DnsStore::try_from_spec(spec).context("invalid [dns] config")?;
    store
        .set_magic_dns_reverse_prefixes_from_str(mesh_cidr, mesh_cidr_v6)
        .context("invalid MagicDNS reverse-DNS prefixes")?;
    if let Some(path) = &extra_records_path {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("stat dns.extra_records_path {}", path.display()))?;
        if meta.is_dir() {
            bail!("dns.extra_records_path {} is a directory", path.display());
        }
        let bytes = std::fs::read(path)
            .with_context(|| format!("read dns.extra_records_path {}", path.display()))?;
        let records = parse_extra_records(&bytes)
            .with_context(|| format!("parse dns.extra_records_path {}", path.display()))?;
        store.set_extra_records(records);
    }
    Ok((Arc::new(store), extra_records_path))
}

#[cfg(test)]
async fn build_persistent_wire_runtime(
    pool: &sqlx::SqlitePool,
    state_dir: &Path,
    server_url: &str,
    mesh_cidr: &str,
    oidc: Option<OidcAuthRuntime>,
    derp_map: DerpMap,
) -> Result<PersistentWireRuntime> {
    build_persistent_wire_runtime_with_dns(
        pool,
        state_dir,
        server_url,
        mesh_cidr,
        None,
        "sequential",
        oidc,
        derp_map,
        Arc::new(DnsStore::new()),
        Arc::new(RuntimeConfigSnapshot::default()),
    )
    .await
}

#[cfg(test)]
async fn build_persistent_wire_runtime_with_dns(
    pool: &sqlx::SqlitePool,
    state_dir: &Path,
    server_url: &str,
    mesh_cidr: &str,
    mesh_cidr_v6: Option<&str>,
    ip_allocation: &str,
    oidc: Option<OidcAuthRuntime>,
    derp_map: DerpMap,
    dns: Arc<DnsStore>,
    runtime_config: Arc<RuntimeConfigSnapshot>,
) -> Result<PersistentWireRuntime> {
    build_persistent_wire_runtime_with_dns_and_policy(
        pool,
        state_dir,
        server_url,
        mesh_cidr,
        mesh_cidr_v6,
        ip_allocation,
        oidc,
        derp_map,
        dns,
        &PolicyConfig::database(),
        runtime_config,
        None,
    )
    .await
}

#[cfg(test)]
async fn build_persistent_wire_runtime_with_dns_and_policy(
    pool: &sqlx::SqlitePool,
    state_dir: &Path,
    server_url: &str,
    mesh_cidr: &str,
    mesh_cidr_v6: Option<&str>,
    ip_allocation: &str,
    oidc: Option<OidcAuthRuntime>,
    derp_map: DerpMap,
    dns: Arc<DnsStore>,
    policy_config: &PolicyConfig,
    runtime_config: Arc<RuntimeConfigSnapshot>,
    server_noise_key: Option<Arc<ServerNoiseKey>>,
) -> Result<PersistentWireRuntime> {
    let server_noise_key = match server_noise_key {
        Some(key) => key,
        None => Arc::new(load_server_noise_key(state_dir, &runtime_config)?),
    };
    let registration_cache = Arc::new(registration_cache_from_runtime_config(&runtime_config));
    let prepared = prepare_sqlite_persistent_wire_runtime(
        pool,
        mesh_cidr,
        mesh_cidr_v6,
        ip_allocation,
        policy_config,
        server_noise_key,
        registration_cache,
    )
    .await?;
    prepared.finish(server_url, oidc, derp_map, dns, runtime_config)
}

async fn prepare_sqlite_persistent_wire_runtime(
    pool: &sqlx::SqlitePool,
    mesh_cidr: &str,
    mesh_cidr_v6: Option<&str>,
    ip_allocation: &str,
    policy_config: &PolicyConfig,
    server_noise_key: Arc<ServerNoiseKey>,
    registration_cache: Arc<RegistrationCache>,
) -> Result<PreparedPersistentWireRuntime> {
    let allocation = IpAllocationStrategy::parse(ip_allocation)?;
    let wire_registry = Arc::new(MachineRegistry::new());
    let stores = PersistentRuntimeStores::sqlite(pool, wire_registry.clone());
    let ip_allocator: Arc<dyn IpAllocator> = Arc::new(
        CidrIpAllocator::from_database(pool, mesh_cidr, mesh_cidr_v6, allocation)
            .await
            .context("initializing IP allocator")?,
    );
    let hydrated = stores
        .hydrate_wire_registry(&wire_registry)
        .await
        .context("loading nodes")?;
    let users = load_startup_users(stores.users().as_ref()).await?;
    let source = load_startup_policy_source(pool, policy_config)
        .await
        .context("loading policy")?;
    let policy_loaded = source.as_ref().is_some_and(|(raw, _)| !raw.is_empty());
    let policy = Arc::new(
        PolicyStore::from_initial_registry_bytes(source, users, &wire_registry)
            .map_err(anyhow::Error::msg)
            .context("initializing policy manager")?,
    );
    policy.set_ssh_forwarding(policy_config.ssh.forwarding());
    // Rust-only bookkeeping: headscale-go logs nothing here, and its CLI output
    // (configtest/serve) is compared byte for byte, so keep it below info.
    tracing::debug!(
        loaded = policy_loaded,
        mode = policy_config.mode(),
        "loaded startup policy into wire runtime"
    );
    warn_startup_policy_tests(&policy, &wire_registry)?;
    tracing::debug!(
        nodes = hydrated,
        "hydrated persisted nodes into wire registry"
    );
    let admin_service = HeadscaleAdminService::with_user_admin(
        stores.users(),
        stores.api_keys(),
        stores.preauth_admin(),
        policy.as_ref().clone(),
        stores.machines(),
    )
    .with_database_pool(pool.clone())
    .with_registration_cache(registration_cache.clone())
    .with_wire_registry(wire_registry.clone())
    .with_ip_allocator(ip_allocator.clone());
    let admin_service = match policy_config.mode() {
        "database" => admin_service.with_policy_pool(pool.clone()),
        "file" => admin_service.with_policy_file(policy_config.path.clone()),
        mode => admin_service.with_unsupported_policy_mode(mode),
    };
    Ok(PreparedPersistentWireRuntime {
        server_noise_key,
        stores,
        wire_registry,
        registration_cache,
        ip_allocator,
        policy,
        admin_service,
    })
}

#[cfg(all(test, feature = "postgres-sqlx"))]
async fn build_postgres_persistent_wire_runtime_with_dns_and_policy(
    pool: &sqlx::PgPool,
    state_dir: &Path,
    server_url: &str,
    mesh_cidr: &str,
    mesh_cidr_v6: Option<&str>,
    ip_allocation: &str,
    oidc: Option<OidcAuthRuntime>,
    derp_map: DerpMap,
    dns: Arc<DnsStore>,
    policy_config: &PolicyConfig,
    runtime_config: Arc<RuntimeConfigSnapshot>,
    server_noise_key: Option<Arc<ServerNoiseKey>>,
) -> Result<PersistentWireRuntime> {
    let server_noise_key = match server_noise_key {
        Some(key) => key,
        None => Arc::new(load_server_noise_key(state_dir, &runtime_config)?),
    };
    let registration_cache = Arc::new(registration_cache_from_runtime_config(&runtime_config));
    let prepared = prepare_postgres_persistent_wire_runtime(
        pool,
        mesh_cidr,
        mesh_cidr_v6,
        ip_allocation,
        policy_config,
        server_noise_key,
        registration_cache,
    )
    .await?;
    prepared.finish(server_url, oidc, derp_map, dns, runtime_config)
}

#[cfg(feature = "postgres-sqlx")]
async fn prepare_postgres_persistent_wire_runtime(
    pool: &sqlx::PgPool,
    mesh_cidr: &str,
    mesh_cidr_v6: Option<&str>,
    ip_allocation: &str,
    policy_config: &PolicyConfig,
    server_noise_key: Arc<ServerNoiseKey>,
    registration_cache: Arc<RegistrationCache>,
) -> Result<PreparedPersistentWireRuntime> {
    let allocation = IpAllocationStrategy::parse(ip_allocation)?;
    let wire_registry = Arc::new(MachineRegistry::new());
    let stores = PersistentRuntimeStores::postgres(pool, wire_registry.clone());
    let ip_allocator: Arc<dyn IpAllocator> = Arc::new(
        CidrIpAllocator::from_postgres_database(pool, mesh_cidr, mesh_cidr_v6, allocation)
            .await
            .context("initializing IP allocator")?,
    );
    let hydrated = stores
        .hydrate_wire_registry(&wire_registry)
        .await
        .context("loading nodes")?;
    let users = load_startup_users(stores.users().as_ref()).await?;
    let source = load_postgres_startup_policy_source(pool, policy_config)
        .await
        .context("loading policy")?;
    let policy_loaded = source.as_ref().is_some_and(|(raw, _)| !raw.is_empty());
    let policy = Arc::new(
        PolicyStore::from_initial_registry_bytes(source, users, &wire_registry)
            .map_err(anyhow::Error::msg)
            .context("initializing policy manager")?,
    );
    policy.set_ssh_forwarding(policy_config.ssh.forwarding());
    tracing::info!(
        loaded = policy_loaded,
        mode = policy_config.mode(),
        "loaded startup policy into Postgres-backed wire runtime"
    );
    warn_startup_policy_tests(&policy, &wire_registry)?;
    tracing::info!(
        nodes = hydrated,
        "hydrated persisted Postgres nodes into wire registry"
    );
    let admin_service = HeadscaleAdminService::with_user_admin(
        stores.users(),
        stores.api_keys(),
        stores.preauth_admin(),
        policy.as_ref().clone(),
        stores.machines(),
    )
    .with_postgres_database_pool(pool.clone())
    .with_registration_cache(registration_cache.clone())
    .with_wire_registry(wire_registry.clone())
    .with_ip_allocator(ip_allocator.clone());
    let admin_service = match policy_config.mode() {
        "database" => admin_service.with_postgres_policy_pool(pool.clone()),
        "file" => admin_service.with_policy_file(policy_config.path.clone()),
        mode => admin_service.with_unsupported_policy_mode(mode),
    };
    Ok(PreparedPersistentWireRuntime {
        server_noise_key,
        stores,
        wire_registry,
        registration_cache,
        ip_allocator,
        policy,
        admin_service,
    })
}

async fn prepare_persistent_wire_runtime_from_database(
    db: &RuntimeDatabase,
    cfg: &RunServerConfig,
    server_noise_key: Arc<ServerNoiseKey>,
) -> Result<PreparedPersistentWireRuntime> {
    let registration_cache = Arc::new(registration_cache_from_tuning(&cfg.tuning));
    match db {
        RuntimeDatabase::Sqlite(db) => {
            prepare_sqlite_persistent_wire_runtime(
                db.pool(),
                &cfg.mesh_cidr,
                cfg.mesh_cidr_v6.as_deref(),
                &cfg.ip_allocation,
                &cfg.policy,
                server_noise_key,
                registration_cache,
            )
            .await
        }
        #[cfg(feature = "postgres-sqlx")]
        RuntimeDatabase::Postgres(pool) => {
            prepare_postgres_persistent_wire_runtime(
                pool,
                &cfg.mesh_cidr,
                cfg.mesh_cidr_v6.as_deref(),
                &cfg.ip_allocation,
                &cfg.policy,
                server_noise_key,
                registration_cache,
            )
            .await
        }
    }
}

#[cfg(test)]
fn load_server_noise_key(
    state_dir: &Path,
    runtime_config: &RuntimeConfigSnapshot,
) -> Result<ServerNoiseKey> {
    let legacy_path =
        state_dir.join(headscale_api::tailscale_wire::noise::NOISE_STATIC_KEY_FILENAME);
    let configured_path = Path::new(&runtime_config.noise_private_key_path);
    let configured_path = (!runtime_config.noise_private_key_path.is_empty()
        && configured_path != legacy_path)
        .then_some(configured_path);
    ServerNoiseKey::load_or_generate_with_configured_path(state_dir, configured_path)
        .map_err(Into::into)
}

fn runtime_config_snapshot(
    cfg: &RunServerConfig,
    derp_map: &DerpMap,
    dns: &DnsStore,
) -> RuntimeConfigSnapshot {
    let mut snapshot = RuntimeConfigSnapshot {
        server_url: cfg.server_url.clone().unwrap_or_default(),
        addr: cfg.listen.clone(),
        metrics_addr: cfg.metrics_listen_addr.clone().unwrap_or_default(),
        grpc_addr: cfg.grpc_listen_addr.clone(),
        grpc_allow_insecure: cfg.grpc_allow_insecure,
        trusted_proxies: cfg.trusted_proxies.clone(),
        ephemeral_node_inactivity_timeout: duration_nanos(cfg.ephemeral_node_inactivity_timeout),
        node: headscale_api::tailscale_wire::basic_handlers::DebugNodeConfig {
            expiry: duration_nanos(cfg.node_expiry),
            ephemeral: headscale_api::tailscale_wire::basic_handlers::DebugNodeEphemeralConfig {
                inactivity_timeout: duration_nanos(cfg.ephemeral_node_inactivity_timeout),
            },
            routes: headscale_api::tailscale_wire::basic_handlers::DebugNodeRoutesConfig {
                ha: headscale_api::tailscale_wire::basic_handlers::DebugNodeRoutesHaConfig {
                    probe_interval: duration_nanos(cfg.node_routes_ha_probe_interval),
                    probe_timeout: duration_nanos(cfg.node_routes_ha_probe_timeout),
                },
            },
        },
        prefix_v4: non_empty_string(&cfg.mesh_cidr),
        prefix_v6: cfg
            .mesh_cidr_v6
            .as_ref()
            .and_then(|prefix| non_empty_string(prefix)),
        ip_allocation: cfg.ip_allocation.clone(),
        noise_private_key_path: ServerNoiseKey::effective_key_path(
            &cfg.state_dir,
            cfg.noise_private_key_path.as_deref(),
        )
        .display()
        .to_string(),
        unix_socket: cfg.unix_socket.display().to_string(),
        unix_socket_permission: cfg.unix_socket_permission,
        ..RuntimeConfigSnapshot::default()
    };

    snapshot.database.database_type = "sqlite3".to_string();
    snapshot.database.sqlite.path = cfg.db_path.display().to_string();
    if let Some(database) = &cfg.database {
        snapshot.database.database_type = database.debug_type();
        snapshot.database.debug = database.debug_enabled();
        let gorm = database.debug_gorm();
        snapshot.database.gorm.debug = gorm.debug(database.debug_enabled());
        snapshot.database.gorm.slow_threshold = u64_nanos_to_i64(gorm.slow_threshold_nanos());
        snapshot.database.gorm.skip_err_record_not_found = gorm.skip_err_record_not_found();
        snapshot.database.gorm.parameterized_queries = gorm.parameterized_queries();
        snapshot.database.gorm.prepare_stmt = gorm.prepare_stmt();

        let sqlite = database.debug_sqlite();
        snapshot.database.sqlite.path = sqlite
            .path()
            .map(|path| path.display().to_string())
            .filter(|path| !path.is_empty())
            .unwrap_or_else(|| cfg.db_path.display().to_string());
        snapshot.database.sqlite.write_ahead_log = sqlite.write_ahead_log();
        snapshot.database.sqlite.wal_auto_check_point = sqlite.wal_autocheckpoint();

        let postgres = database.debug_postgres();
        snapshot.database.postgres.host = postgres.host().to_string();
        snapshot.database.postgres.port = postgres.port();
        snapshot.database.postgres.name = postgres.name().to_string();
        snapshot.database.postgres.user = postgres.user().to_string();
        snapshot.database.postgres.ssl = postgres.ssl().to_string();
        snapshot.database.postgres.max_open_connections = postgres.max_open_conns();
        snapshot.database.postgres.max_idle_connections = postgres.max_idle_conns();
        snapshot.database.postgres.conn_max_idle_time_secs = postgres.conn_max_idle_time_secs();
    }
    snapshot.disable_update_check = cfg.disable_check_updates;
    snapshot.log.level.clone_from(&cfg.logging.level);
    snapshot.log.format.clone_from(&cfg.logging.format);
    snapshot.cli.address = cfg.cli.address.clone().unwrap_or_default();
    snapshot.cli.api_key = cfg.cli.api_key.clone().unwrap_or_default();
    snapshot.cli.insecure = cfg.cli.insecure.unwrap_or(false);
    snapshot.cli.timeout = cfg
        .cli
        .timeout
        .unwrap_or_else(crate::config::default_cli_timeout_nanos);

    if let Some(derp) = &cfg.derp {
        snapshot.derp.server_enabled = derp.server.enabled;
        snapshot.derp.automatically_add_embedded_derp_region =
            derp.server.automatically_add_embedded_derp_region;
        snapshot.derp.server_region_id = i32::try_from(derp.server.region_id).unwrap_or_default();
        snapshot
            .derp
            .server_region_code
            .clone_from(&derp.server.region_code);
        snapshot
            .derp
            .server_region_name
            .clone_from(&derp.server.region_name);
        snapshot.derp.server_private_key_path = derp.server.private_key_path.display().to_string();
        snapshot.derp.server_verify_clients = derp.server.verify_clients;
        snapshot.derp.stun_addr = derp
            .server
            .stun_listen_addr
            .map(|addr| addr.to_string())
            .unwrap_or_default();
        snapshot.derp.urls.clone_from(&derp.urls);
        snapshot.derp.paths = derp
            .paths
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        snapshot.derp.auto_update = derp.auto_update_enabled;
        snapshot.derp.update_frequency = duration_nanos(Duration::from_secs(derp.update_frequency));
        snapshot.derp.ipv4 = derp.server.ipv4.clone().unwrap_or_default();
        snapshot.derp.ipv6 = derp.server.ipv6.clone().unwrap_or_default();
    } else if cfg.embedded_derp.enabled {
        snapshot.derp.server_enabled = true;
        snapshot.derp.server_region_id = i32::from(cfg.embedded_derp.region_id);
        snapshot
            .derp
            .server_region_code
            .clone_from(&cfg.embedded_derp.region_code);
        snapshot
            .derp
            .server_region_name
            .clone_from(&cfg.embedded_derp.region_name);
        snapshot.derp.server_private_key_path =
            cfg.embedded_derp.derper_config_path.display().to_string();
        snapshot.derp.server_verify_clients = cfg.embedded_derp.verify_clients;
        snapshot.derp.stun_addr = cfg
            .embedded_derp
            .stun_addr
            .map(|addr| addr.to_string())
            .unwrap_or_default();
        snapshot.derp.ipv4.clone_from(&cfg.embedded_derp.ipv4);
        snapshot.derp.ipv6.clone_from(&cfg.embedded_derp.ipv6);
    }
    snapshot.derp.derp_map = serde_json::to_value(derp_map).unwrap_or(serde_json::Value::Null);

    snapshot.tls.cert_path = cfg
        .tls
        .cert_path
        .as_ref()
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    snapshot.tls.key_path = cfg
        .tls
        .key_path
        .as_ref()
        .filter(|path| !path.as_os_str().is_empty())
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    snapshot.tls.lets_encrypt.hostname = cfg
        .tls
        .letsencrypt_hostname
        .as_deref()
        .unwrap_or("")
        .to_string();
    snapshot.tls.lets_encrypt.cache_dir = cfg.tls.cache_dir_string();
    snapshot.tls.lets_encrypt.listen = cfg.tls.letsencrypt_listen_string();
    snapshot.tls.lets_encrypt.challenge_type = cfg.tls.challenge_type_string();
    snapshot.acme_url = cfg.tls.acme_url_string();
    snapshot.acme_email = non_empty_str(cfg.tls.acme_email.as_deref())
        .unwrap_or("")
        .to_string();

    let dns_spec = dns.spec();
    snapshot.base_domain.clone_from(&dns_spec.base_domain);
    snapshot.dns_config.magic_dns = dns_spec.magic_dns;
    snapshot
        .dns_config
        .base_domain
        .clone_from(&dns_spec.base_domain);
    snapshot.dns_config.override_local_dns = dns_spec.override_local_dns;
    snapshot
        .dns_config
        .nameservers
        .global
        .clone_from(&dns_spec.nameservers);
    snapshot.dns_config.nameservers.split = dns_spec
        .restricted_nameservers
        .iter()
        .map(|(suffix, resolvers)| (suffix.clone(), resolvers.clone()))
        .collect();
    snapshot
        .dns_config
        .search_domains
        .clone_from(&dns_spec.search_domains);
    snapshot.dns_config.extra_records = dns_spec
        .extra_records
        .iter()
        .filter_map(|record| serde_json::to_value(record).ok())
        .collect();
    snapshot.dns_config.extra_records_path = dns_spec
        .extra_records_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    snapshot.tailcfg_dns_config =
        serde_json::to_value(dns.build(&[])).unwrap_or(serde_json::Value::Null);
    snapshot.log_tail.enabled = cfg.logtail_enabled;
    snapshot.taildrop.enabled = cfg.taildrop_enabled;
    snapshot.auto_update.enabled = cfg.auto_update_enabled;

    let oidc_config = upstream_oidc_runtime_config(&cfg.oidc);
    snapshot.oidc.only_start_if_oidc_is_available = oidc_config.only_start_if_oidc_is_available;
    snapshot.oidc.issuer.clone_from(&oidc_config.issuer);
    snapshot.oidc.client_id.clone_from(&oidc_config.client_id);
    snapshot
        .oidc
        .client_secret
        .clone_from(&oidc_config.client_secret);
    snapshot.oidc.scope.clone_from(&oidc_config.scope);
    snapshot
        .oidc
        .extra_params
        .clone_from(&oidc_config.extra_params);
    snapshot
        .oidc
        .allowed_domains
        .clone_from(&oidc_config.allowed_domains);
    snapshot
        .oidc
        .allowed_users
        .clone_from(&oidc_config.allowed_users);
    snapshot
        .oidc
        .allowed_groups
        .clone_from(&oidc_config.allowed_groups);
    snapshot.oidc.email_verified_required = oidc_config.email_verified_required;
    snapshot.oidc.expiry = duration_nanos(oidc_config.expiry);
    snapshot.oidc.use_expiry_from_token = oidc_config.use_expiry_from_token;
    snapshot.oidc.pkce.enabled = oidc_config.pkce.enabled;
    snapshot
        .oidc
        .pkce
        .method
        .clone_from(&oidc_config.pkce.method);
    snapshot.policy.mode = cfg.policy.mode().to_string();
    snapshot.policy.path = cfg.policy.path.display().to_string();
    snapshot.tuning.notifier_send_timeout = u64_nanos_to_i64(cfg.tuning.notifier_send_timeout);
    snapshot.tuning.batch_change_delay = u64_nanos_to_i64(cfg.tuning.batch_change_delay);
    snapshot.tuning.node_map_session_buffered_chan_size =
        cfg.tuning.node_mapsession_buffered_chan_size;
    snapshot.tuning.batcher_workers = cfg.tuning.batcher_workers;
    snapshot.tuning.register_cache_expiration =
        u64_nanos_to_i64(cfg.tuning.register_cache_expiration);
    snapshot.tuning.register_cache_max_entries = cfg.tuning.register_cache_max_entries;
    snapshot.tuning.node_store_batch_size = cfg.tuning.node_store_batch_size;
    snapshot.tuning.node_store_batch_timeout =
        u64_nanos_to_i64(cfg.tuning.node_store_batch_timeout);

    snapshot
}

fn registration_cache_from_tuning(config: &TuningConfig) -> RegistrationCache {
    registration_cache_from_limits(
        u64_nanos_to_i64(config.register_cache_expiration),
        config.register_cache_max_entries,
    )
}

#[cfg(test)]
fn registration_cache_from_runtime_config(config: &RuntimeConfigSnapshot) -> RegistrationCache {
    registration_cache_from_limits(
        config.tuning.register_cache_expiration,
        config.tuning.register_cache_max_entries,
    )
}

fn registration_cache_from_limits(expiration_nanos: i64, entries: i32) -> RegistrationCache {
    let expiration = u64::try_from(expiration_nanos)
        .ok()
        .filter(|nanos| *nanos > 0)
        .map_or(REGISTRATION_CACHE_EXPIRATION, Duration::from_nanos);
    let max_entries = usize::try_from(entries)
        .ok()
        .filter(|entries| *entries > 0)
        .unwrap_or(REGISTRATION_CACHE_MAX_ENTRIES);
    RegistrationCache::with_tuning_and_max_entries(
        expiration,
        REGISTRATION_CACHE_CLEANUP,
        max_entries,
    )
}

fn validate_supported_runtime_config(cfg: &RunServerConfig) -> Result<()> {
    validate_unsupported_runtime_boundaries(cfg)?;
    if let (Some(server_url), Some(dns)) = (cfg.server_url.as_deref(), cfg.dns.as_ref()) {
        validate_server_url_base_domain(server_url, &dns.base_domain)?;
    }
    Ok(())
}

#[cfg_attr(feature = "postgres-sqlx", allow(clippy::unnecessary_wraps))]
fn validate_unsupported_runtime_boundaries(cfg: &RunServerConfig) -> Result<()> {
    if cfg
        .database
        .as_ref()
        .and_then(UpstreamDatabaseConfig::runtime_backend)
        == Some(DatabaseBackend::Postgres)
    {
        #[cfg(not(feature = "postgres-sqlx"))]
        anyhow::bail!(
            "database.type \"postgres\" is recognized for headscale-go compatibility but headscale-rs server currently supports SQLite only; set database.type to \"sqlite\" or \"sqlite3\""
        );
    }
    Ok(())
}

fn upstream_oidc_runtime_config(oidc: &OidcConfig) -> OidcConfig {
    let mut oidc = oidc.clone();
    oidc.expiry = Duration::ZERO;
    oidc
}

fn u64_nanos_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn tls_material_source(cfg: &RunServerConfig, sans: &SanConfig) -> Result<TlsMaterialSource> {
    let has_cert = cfg
        .tls
        .cert_path
        .as_ref()
        .is_some_and(|path| !path.as_os_str().is_empty());
    let has_key = cfg
        .tls
        .key_path
        .as_ref()
        .is_some_and(|path| !path.as_os_str().is_empty());
    if has_cert != has_key {
        anyhow::bail!("tls_cert_path and tls_key_path must both be set");
    }

    if cfg.tls.letsencrypt_enabled() {
        if has_cert || has_key {
            anyhow::bail!(
                "set either tls_letsencrypt_hostname or tls_cert_path/tls_key_path, not both"
            );
        }
        let public_listeners = public_listener_plan(cfg)?;
        let plan = cfg
            .tls
            .acme_runtime_plan(public_listeners)?
            .expect("letsencrypt_enabled produced an ACME runtime plan");
        return match plan.challenge_listener {
            AcmeChallengeListener::Http01 { .. } => {
                Ok(TlsMaterialSource::AcmeAutocertCacheWithHttp01Bootstrap {
                    cache_dir: plan.cache_dir,
                    hostname: plan.hostname,
                })
            }
            AcmeChallengeListener::TlsAlpn01 { .. } => {
                Ok(TlsMaterialSource::AcmeAutocertCacheWithTlsAlpn {
                    cache_dir: plan.cache_dir,
                    hostname: plan.hostname,
                })
            }
        };
    }

    if let Some((cert_path, key_path)) = cfg.tls.manual_paths() {
        return Ok(TlsMaterialSource::Files {
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
        });
    }

    Ok(TlsMaterialSource::SelfSigned {
        state_dir: cfg.state_dir.clone(),
        sans: sans.clone(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PublicListenerPlan {
    http_addr: Option<SocketAddr>,
    https_addr: Option<SocketAddr>,
}

fn warn_tls_server_url(cfg: &RunServerConfig, listeners: PublicListenerPlan, server_url: &str) {
    // Headscale v0.29.5 getTLSSettings warns before constructing/loading TLS
    // material. Keep its exact scheme checks and ACME-specific capitalization.
    // The explicit dual-listener extension also has a TLS listener.
    if listeners.https_addr.is_some() {
        if !server_url.starts_with("https://") {
            if cfg.tls.letsencrypt_enabled() {
                tracing::warn!("Listening with TLS but ServerURL does not start with https://");
            } else {
                tracing::warn!("listening with TLS but ServerURL does not start with https://");
            }
        }
    } else if !server_url.starts_with("http://") {
        tracing::warn!("listening without TLS but ServerURL does not start with http://");
    }
}

fn public_listener_plan(cfg: &RunServerConfig) -> Result<PublicListenerPlan> {
    let listen_addr = parse_socket_addr(&cfg.listen, "listen")?;
    let explicit_https_addr = cfg
        .https_listen
        .as_deref()
        .map(|addr| parse_socket_addr(addr, "https_listen"))
        .transpose()?;

    if let Some(https_addr) = explicit_https_addr {
        return Ok(PublicListenerPlan {
            http_addr: Some(listen_addr),
            https_addr: Some(https_addr),
        });
    }

    if cfg.tls.has_manual_tls() || cfg.tls.letsencrypt_enabled() {
        return Ok(PublicListenerPlan {
            http_addr: None,
            https_addr: Some(listen_addr),
        });
    }

    Ok(PublicListenerPlan {
        http_addr: Some(listen_addr),
        https_addr: None,
    })
}

async fn start_acme_http01_runtime(
    acme_runtime: Option<&AcmeRuntimePlan>,
    acme_email: Option<String>,
    server_url: &str,
) -> Result<Option<AcmeHttp01Runtime>> {
    let Some(AcmeRuntimePlan {
        hostname,
        acme_url,
        ca_root_path,
        cache_dir,
        challenge_listener: AcmeChallengeListener::Http01 { addr, .. },
    }) = acme_runtime
    else {
        return Ok(None);
    };

    let store = headscale_api::tailscale_wire::acme::AcmeHttp01ChallengeStore::new();
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind ACME HTTP-01 challenge listener {addr}"))?;
    let bound_addr = listener
        .local_addr()
        .context("read ACME HTTP-01 challenge listener address")?;
    tracing::info!(
        addr = %bound_addr,
        hostname = %hostname,
        "ACME HTTP-01 challenge listener bound"
    );
    let app = headscale_api::tailscale_wire::acme::http01_listener_router(
        store.clone(),
        Some(server_url.to_string()),
        Some(hostname.clone()),
    );
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .map_err(std::io::Error::other)
    });

    Ok(Some(AcmeHttp01Runtime {
        issuer_config: AcmeHttp01IssuerConfig {
            directory_url: acme_url.clone(),
            email: acme_email,
            hostname: hostname.clone(),
            cache_dir: cache_dir.clone(),
            ca_root_path: ca_root_path.clone(),
        },
        store,
        handle: Some(handle),
    }))
}

fn acme_tls_alpn_issuer_config(
    acme_runtime: Option<&AcmeRuntimePlan>,
    acme_email: Option<String>,
) -> Option<AcmeHttp01IssuerConfig> {
    match acme_runtime {
        Some(AcmeRuntimePlan {
            hostname,
            acme_url,
            ca_root_path,
            cache_dir,
            challenge_listener: AcmeChallengeListener::TlsAlpn01 { .. },
        }) => Some(AcmeHttp01IssuerConfig {
            directory_url: acme_url.clone(),
            email: acme_email,
            hostname: hostname.clone(),
            cache_dir: cache_dir.clone(),
            ca_root_path: ca_root_path.clone(),
        }),
        _ => None,
    }
}

fn parse_acme_http01_listen_addr(value: &str) -> Result<SocketAddr> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case(":http") || trimmed.eq_ignore_ascii_case("http") {
        return Ok(SocketAddr::from(([0, 0, 0, 0], 80)));
    }
    parse_socket_addr(trimmed, "tls_letsencrypt_listen")
}

fn optional_addr_status(addr: Option<SocketAddr>) -> String {
    addr.map_or_else(|| "<disabled>".to_string(), |addr| addr.to_string())
}

fn derp_map_from_embedded_config(cfg: &EmbeddedDerpConfig) -> DerpMap {
    if !cfg.enabled {
        return DerpMap::default();
    }

    let stun_port = cfg.stun_addr.map_or(-1, |addr| i32::from(addr.port()));
    let node = DerpRegionNode {
        name: cfg.region_id.to_string(),
        region_id: cfg.region_id,
        host_name: cfg.host_name.clone(),
        cert_name: String::new(),
        ipv4: cfg.ipv4.clone(),
        ipv6: cfg.ipv6.clone(),
        derp_port: cfg.derp_port,
        stun_port,
        stun_only: cfg.stun_only,
        insecure_for_tests: cfg.insecure_for_tests,
        stun_test_ip: String::new(),
        can_port80: false,
    };
    let region = DerpRegion {
        region_id: cfg.region_id,
        region_code: cfg.region_code.clone(),
        region_name: cfg.region_name.clone(),
        latitude: 0.0,
        longitude: 0.0,
        avoid: false,
        no_measure_no_home: false,
        nodes: vec![node],
    };

    DerpMap {
        home_params: None,
        regions: HashMap::from([(cfg.region_id, region)]),
        omit_default_regions: cfg.omit_default_regions,
    }
}

async fn native_derp_map_from_runtime_config(
    upstream: Option<&DerpConfig>,
    embedded: &EmbeddedDerpConfig,
    base_domain: &str,
) -> Result<NativeDerpMap> {
    let mut map = if let Some(upstream) = upstream {
        crate::derp_config::load_native_derp_map(upstream, base_domain).await?
    } else {
        NativeDerpMap::default()
    };

    let add_embedded_region = upstream
        .filter(|derp| derp.server.enabled)
        .is_none_or(|derp| derp.server.automatically_add_embedded_derp_region);
    if embedded.enabled && add_embedded_region {
        let mut embedded_map =
            NativeDerpMap::from_projection(&derp_map_from_embedded_config(embedded));
        if let Some(upstream) = upstream.filter(|derp| derp.server.enabled) {
            let id = upstream.server.region_id;
            // Physical relay configuration has no region-ID dependency. Its
            // old u16 value is only a compatibility view; advertise the exact
            // signed native ID, including the generated node name.
            let regions = std::mem::take(&mut embedded_map.regions);
            for (_, region) in regions {
                let region = region.map(|mut region| {
                    region.region_id = id;
                    if let Some(nodes) = &mut region.nodes {
                        for node in nodes.iter_mut().flatten() {
                            node.region_id = id;
                            node.name = id.to_string();
                        }
                    }
                    region
                });
                embedded_map.regions.insert(id, region);
            }
        }
        if embedded_map.home_params.is_some() {
            map.home_params = embedded_map.home_params;
        }
        map.regions.extend(embedded_map.regions);
        map.omit_default_regions |= embedded_map.omit_default_regions;
    }
    map.set_server_region_id(
        upstream.map_or(i64::from(embedded.region_id), |derp| derp.server.region_id),
    );

    Ok(map)
}

fn spawn_derp_auto_update_task(
    upstream: Option<DerpConfig>,
    embedded: EmbeddedDerpConfig,
    store: Arc<DerpMapStore>,
    base_domain: String,
) -> Option<tokio::task::JoinHandle<()>> {
    let upstream = upstream?;
    if !derp_auto_update_enabled(&upstream) {
        return None;
    }

    let interval = Duration::from_secs(upstream.update_frequency);
    Some(tokio::spawn(async move {
        tracing::info!(
            interval = ?interval,
            urls = upstream.urls.len(),
            paths = upstream.paths.len(),
            "DERP auto-update task started"
        );
        loop {
            tokio::time::sleep(interval).await;
            match refresh_derp_map_once(&upstream, &embedded, &store, &base_domain).await {
                Ok(()) => {
                    tracing::info!("DERP map auto-update completed");
                }
                Err(err) => {
                    tracing::warn!(
                        error = ?err,
                        "DERP map auto-update failed; keeping previous map"
                    );
                }
            }
        }
    }))
}

#[cfg(unix)]
fn spawn_policy_reload_signal_task(
    admin_service: HeadscaleAdminService,
) -> Option<tokio::task::JoinHandle<()>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(signal) => signal,
        Err(err) => {
            tracing::warn!(error = ?err, "failed to install SIGHUP handler; policy reload disabled");
            return None;
        }
    };

    Some(tokio::spawn(async move {
        loop {
            if sighup.recv().await.is_none() {
                return;
            }
            tracing::info!(signal = "hangup", "Received SIGHUP, reloading ACL policy");
            if let Err(err) = admin_service.reload_policy_from_config().await {
                tracing::error!(error = %err.message(), "reloading policy");
            }
        }
    }))
}

#[cfg(not(unix))]
fn spawn_policy_reload_signal_task(
    _admin_service: HeadscaleAdminService,
) -> Option<tokio::task::JoinHandle<()>> {
    None
}

fn derp_auto_update_enabled(upstream: &DerpConfig) -> bool {
    upstream.auto_update_enabled && upstream.update_frequency != 0
}

async fn refresh_derp_map_once(
    upstream: &DerpConfig,
    embedded: &EmbeddedDerpConfig,
    store: &DerpMapStore,
    base_domain: &str,
) -> Result<()> {
    let map = native_derp_map_from_runtime_config(Some(upstream), embedded, base_domain).await?;
    store.set_native(map);
    Ok(())
}

fn production_extra_routes(runtime: &PersistentWireRuntime) -> axum::Router {
    grpc_gateway::router(runtime.admin_service.clone())
}

#[derive(Clone)]
enum RemoteGrpcSecurity {
    Insecure,
    Tls(ReloadableServerConfig),
}

struct ConnectedTlsStream(TlsStream<TcpStream>);

impl Connected for ConnectedTlsStream {
    type ConnectInfo = ();

    fn connect_info(&self) -> Self::ConnectInfo {}
}

impl AsyncRead for ConnectedTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for ConnectedTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

fn remote_grpc_status(cfg: &RunServerConfig) -> String {
    if cfg.tls.has_manual_tls() || cfg.tls.letsencrypt_enabled() || cfg.https_listen.is_some() {
        format!("{} (TLS)", cfg.grpc_listen_addr)
    } else if cfg.grpc_allow_insecure {
        format!("{} (insecure)", cfg.grpc_listen_addr)
    } else {
        "<disabled>".to_string()
    }
}

#[cfg(test)]
fn remote_grpc_security(
    cfg: &RunServerConfig,
    tls_source: &TlsMaterialSource,
) -> Result<Option<RemoteGrpcSecurity>> {
    remote_grpc_security_with_provider(cfg, tls_source, None)
}

fn remote_grpc_security_with_provider(
    cfg: &RunServerConfig,
    tls_source: &TlsMaterialSource,
    provider: Option<Arc<dyn tls::AcmeCertificateProvider>>,
) -> Result<Option<RemoteGrpcSecurity>> {
    if cfg.tls.has_manual_tls() || cfg.tls.letsencrypt_enabled() || cfg.https_listen.is_some() {
        if let Some(provider) = provider {
            let material = provider.initial_material()?;
            let mut config = (*material.server_config).clone();
            config.alpn_protocols = vec![b"h2".to_vec()];
            let reloader = ReloadableServerConfig::new(Arc::new(config));
            reloader.set_certificate_provider(provider);
            return Ok(Some(RemoteGrpcSecurity::Tls(reloader)));
        }
        let material = tls_source
            .load()
            .context("load TLS material for remote gRPC")?;
        let grpc_tls = tls::build_grpc_server_config(&material.cert_pem, &material.key_pem)
            .context("build remote gRPC TLS config")?;
        return Ok(Some(RemoteGrpcSecurity::Tls(ReloadableServerConfig::new(
            Arc::new(grpc_tls),
        ))));
    }
    if cfg.grpc_allow_insecure {
        return Ok(Some(RemoteGrpcSecurity::Insecure));
    }
    Ok(None)
}

async fn bind_unix_grpc_listener(path: &Path, permission: u32) -> Result<UnixListener> {
    ensure_parent_dir(path)?;
    if path.exists() {
        let metadata = std::fs::metadata(path)
            .with_context(|| format!("inspect Unix gRPC socket {}", path.display()))?;
        if !metadata.file_type().is_socket() {
            anyhow::bail!(
                "Refusing to replace non-socket Unix gRPC path {}",
                path.display()
            );
        }
        match UnixStream::connect(path).await {
            Ok(_) => anyhow::bail!("Unix gRPC socket {} is already in use", path.display()),
            Err(_) => std::fs::remove_file(path)
                .with_context(|| format!("remove stale Unix gRPC socket {}", path.display()))?,
        }
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("bind Unix gRPC socket {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(permission))
        .with_context(|| format!("chmod Unix gRPC socket {}", path.display()))?;
    Ok(listener)
}

async fn bind_tcp_grpc_listener(addr: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(addr)
        .await
        .with_context(|| format!("bind remote gRPC TCP listener {addr}"))
}

#[cfg(test)]
fn spawn_local_grpc_listener(
    listener: UnixListener,
    path: PathBuf,
    service: HeadscaleAdminService,
) -> tokio::task::JoinHandle<Result<()>> {
    spawn_local_grpc_listener_with_shutdown(listener, path, service, std::future::pending::<()>())
}

fn spawn_local_grpc_listener_with_shutdown<F>(
    listener: UnixListener,
    path: PathBuf,
    service: HeadscaleAdminService,
    shutdown: F,
) -> tokio::task::JoinHandle<Result<()>>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let reflection =
            HeadscaleAdminService::reflection_service().context("build gRPC reflection service")?;
        let incoming = UnixListenerStream::new(listener);
        tracing::debug!(path = %path.display(), "admin gRPC listening on Unix socket");
        tonic::transport::Server::builder()
            .add_service(service.into_service_server())
            .add_service(reflection)
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await
            .with_context(|| format!("serve admin gRPC Unix socket {}", path.display()))
    })
}

#[cfg(test)]
fn spawn_remote_grpc_listener(
    listener: TcpListener,
    addr: SocketAddr,
    service: HeadscaleAdminService,
    security: RemoteGrpcSecurity,
) -> tokio::task::JoinHandle<Result<()>> {
    spawn_remote_grpc_listener_with_shutdown(
        listener,
        addr,
        service,
        security,
        std::future::pending::<()>(),
    )
}

fn spawn_remote_grpc_listener_with_shutdown<F>(
    listener: TcpListener,
    addr: SocketAddr,
    service: HeadscaleAdminService,
    security: RemoteGrpcSecurity,
    shutdown: F,
) -> tokio::task::JoinHandle<Result<()>>
where
    F: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let reflection =
            HeadscaleAdminService::reflection_service().context("build gRPC reflection service")?;
        tracing::info!("listening and serving gRPC on: {addr}");
        match security {
            RemoteGrpcSecurity::Insecure => {
                let incoming = TcpListenerStream::new(listener);
                tonic::transport::Server::builder()
                    .add_service(service.into_authenticated_service_server())
                    .add_service(reflection)
                    .serve_with_incoming_shutdown(incoming, shutdown)
                    .await
                    .with_context(|| format!("serve remote gRPC TCP listener {addr}"))
            }
            RemoteGrpcSecurity::Tls(reloader) => {
                let incoming: Pin<
                    Box<
                        dyn tokio_stream::Stream<Item = std::io::Result<ConnectedTlsStream>> + Send,
                    >,
                > = if reloader.certificate_provider().is_some() {
                    Box::pin(
                        acme_grpc_incoming::incoming(listener, reloader)
                            .map(|accepted| accepted.map(ConnectedTlsStream)),
                    )
                } else {
                    Box::pin(TcpListenerStream::new(listener).then(move |accepted| {
                        let reloader = reloader.clone();
                        async move {
                            let stream = accepted?;
                            headscale_api::tailscale_wire::raw_tls::accept_tls_with_config(
                                reloader, stream,
                            )
                            .await
                            .map(ConnectedTlsStream)
                            .map_err(std::io::Error::other)
                        }
                    }))
                };
                tonic::transport::Server::builder()
                    .add_service(service.into_authenticated_service_server())
                    .add_service(reflection)
                    .serve_with_incoming_shutdown(incoming, shutdown)
                    .await
                    .with_context(|| format!("serve remote gRPC TCP listener {addr}"))
            }
        }
    })
}

async fn load_startup_policy_source(
    pool: &sqlx::SqlitePool,
    config: &PolicyConfig,
) -> Result<Option<(Vec<u8>, i64)>> {
    match config.mode.as_str() {
        "database" => headscale_db::policies::get_latest(pool)
            .await
            .map(|row| row.map(|row| (row.data.into_bytes(), row.updated_at)))
            .map_err(|error| anyhow::anyhow!(error.headscale_go_message())),
        "file" => load_startup_file_policy(config).await,
        _ => Ok(None),
    }
}

#[cfg(feature = "postgres-sqlx")]
async fn load_postgres_startup_policy_source(
    pool: &sqlx::PgPool,
    config: &PolicyConfig,
) -> Result<Option<(Vec<u8>, i64)>> {
    match config.mode.as_str() {
        "database" => headscale_db::policies::get_latest_postgres(pool)
            .await
            .map(|row| row.map(|row| (row.data.into_bytes(), row.updated_at)))
            .map_err(|error| anyhow::anyhow!(error.headscale_go_message())),
        "file" => load_startup_file_policy(config).await,
        _ => Ok(None),
    }
}

async fn load_startup_users(
    users: &dyn UserAdmin,
) -> Result<Vec<headscale_api::policy::PolicyUser>> {
    users
        .policy_users()
        .await
        .map_err(|error| match error {
            UserRegistryError::Store(message) => anyhow::anyhow!(message),
            error => error.into(),
        })
        .context("loading users")
}

fn warn_startup_policy_tests(policy: &PolicyStore, registry: &MachineRegistry) -> Result<()> {
    let Some(doc) = policy.doc() else {
        return Ok(());
    };
    let nodes = PolicyCheckNodeSnapshot::from_registry(registry)
        .map_err(anyhow::Error::msg)
        .context("loading policy test node snapshot")?;
    warn_policy_tests_at_boot_for_snapshot(
        &doc,
        policy
            .source_for_compilation()
            .as_deref()
            .unwrap_or_default(),
        &nodes,
    );
    Ok(())
}

async fn load_startup_file_policy(config: &PolicyConfig) -> Result<Option<(Vec<u8>, i64)>> {
    let Some(path) = config.path_if_non_empty() else {
        return Ok(None);
    };
    let raw = tokio::fs::read(path)
        .await
        .map_err(|error| startup_policy_file_error(path, &error))?;
    Ok(Some((raw, chrono::Utc::now().timestamp())))
}

fn startup_policy_file_error(path: &Path, error: &std::io::Error) -> anyhow::Error {
    use std::io::ErrorKind;
    let operation = if error.kind() == ErrorKind::IsADirectory {
        "read"
    } else {
        "open"
    };
    let message = match error.kind() {
        ErrorKind::NotFound => "no such file or directory".to_owned(),
        ErrorKind::PermissionDenied => "permission denied".to_owned(),
        ErrorKind::IsADirectory => "is a directory".to_owned(),
        ErrorKind::NotADirectory => "not a directory".to_owned(),
        _ => {
            let mut message = error.to_string();
            if let Some(code) = error.raw_os_error() {
                let suffix = format!(" (os error {code})");
                if message.ends_with(&suffix) {
                    message.truncate(message.len() - suffix.len());
                }
            }
            message
        }
    };
    anyhow::anyhow!("{operation} {}: {message}", path.display())
}

async fn open_runtime_database(cfg: &RunServerConfig) -> Result<RuntimeDatabase> {
    if cfg
        .database
        .as_ref()
        .and_then(UpstreamDatabaseConfig::runtime_backend)
        == Some(DatabaseBackend::Postgres)
    {
        return open_postgres_runtime_database(cfg.database.as_ref()).await;
    }

    open_sqlite_database(&cfg.db_path, cfg.database.as_ref())
        .await
        .map(RuntimeDatabase::Sqlite)
}

#[cfg(feature = "postgres-sqlx")]
async fn open_postgres_runtime_database(
    database: Option<&UpstreamDatabaseConfig>,
) -> Result<RuntimeDatabase> {
    let database = database.context("database.type \"postgres\" requires a database block")?;
    let postgres = database.debug_postgres();
    let url = postgres_url_from_config(postgres)?;
    let log_path = format!(
        "host={} dbname={} user={}",
        postgres.host(),
        postgres.name(),
        postgres.user()
    );
    tracing::info!(database = "postgres", path = %log_path, "Opening database");
    let pool = headscale_db::open_postgres_pool_with_options(&url, postgres_pool_options(postgres))
        .await
        .with_context(|| {
            format!(
                "open Postgres database {}",
                postgres_database_status(postgres)
            )
        })?;
    headscale_db::migrate_postgres_foundation(&pool)
        .await
        .context("migrate Postgres database")?;
    Ok(RuntimeDatabase::Postgres(pool))
}

#[cfg(not(feature = "postgres-sqlx"))]
async fn open_postgres_runtime_database(
    _database: Option<&UpstreamDatabaseConfig>,
) -> Result<RuntimeDatabase> {
    anyhow::bail!(
        "database.type \"postgres\" is recognized for headscale-go compatibility but this headscale-rs build was compiled without postgres-sqlx support"
    )
}

async fn open_sqlite_database(
    path: &Path,
    database: Option<&UpstreamDatabaseConfig>,
) -> Result<Database> {
    ensure_parent_dir(path)?;
    tracing::info!(database = "sqlite3", path = %path.display(), "Opening database");
    let url = sqlite_url_for_path(path);
    let db = Database::new_with_go_sqlite_options(&url, sqlite_open_options(database)?)
        .await
        .with_context(|| format!("open SQLite database at {}", path.display()))?;
    db.migrate()
        .await
        .with_context(|| format!("migrate SQLite database at {}", path.display()))?;
    Ok(db)
}

fn sqlite_open_options(database: Option<&UpstreamDatabaseConfig>) -> Result<SqliteOpenOptions> {
    let Some(database) = database else {
        return Ok(SqliteOpenOptions::default());
    };

    let sqlite = database.debug_sqlite();
    Ok(headscale_db::go_sqlite_open_options(
        sqlite.write_ahead_log(),
        sqlite.wal_autocheckpoint(),
    )?)
}

#[cfg(feature = "postgres-sqlx")]
pub(crate) fn postgres_pool_options(
    postgres: &crate::config::UpstreamPostgresConfig,
) -> headscale_db::GoPostgresPoolOptions {
    headscale_db::GoPostgresPoolOptions {
        max_open_connections: postgres.max_open_conns(),
        max_idle_connections: postgres.max_idle_conns(),
        conn_max_idle_time_secs: postgres.conn_max_idle_time_secs(),
    }
}

fn sqlite_url_for_path(path: &Path) -> String {
    format!("sqlite://{}?mode=rwc", path.display())
}

fn runtime_database_status(cfg: &RunServerConfig) -> String {
    match cfg
        .database
        .as_ref()
        .and_then(UpstreamDatabaseConfig::runtime_backend)
    {
        Some(DatabaseBackend::Postgres) => cfg.database.as_ref().map_or_else(
            || "postgres://<missing database block>".to_string(),
            |database| postgres_database_status(database.debug_postgres()),
        ),
        Some(DatabaseBackend::Sqlite) | None => cfg.db_path.display().to_string(),
    }
}

fn postgres_database_status(postgres: &UpstreamPostgresConfig) -> String {
    let host = non_empty_str(Some(postgres.host())).unwrap_or("localhost");
    let port = postgres_config_port(postgres).unwrap_or(5432);
    let name = non_empty_str(Some(postgres.name())).unwrap_or("headscale");
    format!("postgres://{host}:{port}/{name}")
}

#[cfg(feature = "postgres-sqlx")]
fn postgres_url_from_config(postgres: &UpstreamPostgresConfig) -> Result<String> {
    postgres.connection_url()
}

fn postgres_config_port(postgres: &UpstreamPostgresConfig) -> Result<u16> {
    let port = postgres.port();
    if port <= 0 {
        return Ok(5432);
    }
    u16::try_from(port).context("database.postgres.port must be between 1 and 65535")
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        create_private_dir_all(parent).with_context(|| {
            format!("Failed to create database directory: {}", parent.display())
        })?;
    }
    Ok(())
}

/// headscale-go creates missing state, database and unix socket directories
/// through util.EnsureDir, i.e. os.MkdirAll(dir, 0o700): every component it
/// creates is private to the service user rather than the umask default.
fn create_private_dir_all(dir: &Path) -> std::io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

fn parse_socket_addr(value: &str, field: &str) -> Result<SocketAddr> {
    let normalized;
    let value = if value.starts_with(':') {
        normalized = format!("0.0.0.0{value}");
        normalized.as_str()
    } else {
        value
    };
    value
        .parse()
        .with_context(|| format!("Invalid {field} address: {value}"))
}

struct GrpcListenerShutdown {
    local: tokio::sync::oneshot::Sender<()>,
    remote: Option<tokio::sync::oneshot::Sender<()>>,
}

async fn await_serve_handle(
    handle: serve::ServeHandle,
    local_grpc: tokio::task::JoinHandle<Result<()>>,
    remote_grpc: Option<tokio::task::JoinHandle<Result<()>>>,
    external_acme_http01: Option<tokio::task::JoinHandle<Result<(), std::io::Error>>>,
    native_derp: Option<Arc<NativeDerpRuntime>>,
    machines: Arc<MachineRegistry>,
    maintenance: Vec<tokio::task::AbortHandle>,
    grpc_shutdown: GrpcListenerShutdown,
    http_shutdown: serve::HttpShutdownControl,
    ephemeral_gc: EphemeralGcHandle,
) -> Result<()> {
    await_serve_handle_with_native_shutdown(
        handle,
        local_grpc,
        remote_grpc,
        external_acme_http01,
        native_derp,
        Some(machines),
        maintenance,
        Some(grpc_shutdown),
        Some(http_shutdown),
        Some(ephemeral_gc),
        shutdown_signal(),
    )
    .await
}

#[cfg(test)]
async fn await_serve_handle_with_shutdown<S>(
    handle: serve::ServeHandle,
    local_grpc: tokio::task::JoinHandle<Result<()>>,
    remote_grpc: Option<tokio::task::JoinHandle<Result<()>>>,
    external_acme_http01: Option<tokio::task::JoinHandle<Result<(), std::io::Error>>>,
    native_derp: Option<Arc<NativeDerpRuntime>>,
    shutdown_signal: S,
) -> Result<()>
where
    S: Future<Output = Result<&'static str>>,
{
    await_serve_handle_with_native_shutdown(
        handle,
        local_grpc,
        remote_grpc,
        external_acme_http01,
        native_derp,
        None,
        Vec::new(),
        None,
        None,
        None,
        shutdown_signal,
    )
    .await
}

async fn await_serve_handle_with_native_shutdown<S>(
    handle: serve::ServeHandle,
    local_grpc: tokio::task::JoinHandle<Result<()>>,
    remote_grpc: Option<tokio::task::JoinHandle<Result<()>>>,
    external_acme_http01: Option<tokio::task::JoinHandle<Result<(), std::io::Error>>>,
    native_derp: Option<Arc<NativeDerpRuntime>>,
    machines: Option<Arc<MachineRegistry>>,
    maintenance: Vec<tokio::task::AbortHandle>,
    grpc_shutdown: Option<GrpcListenerShutdown>,
    http_shutdown: Option<serve::HttpShutdownControl>,
    ephemeral_gc: Option<EphemeralGcHandle>,
    shutdown_signal: S,
) -> Result<()>
where
    S: Future<Output = Result<&'static str>>,
{
    let serve::ServeHandle {
        mut http,
        mut https,
        mut metrics,
        mut acme_http01,
        ..
    } = handle;
    let mut external_acme_http01 = external_acme_http01;
    let mut local_grpc = Some(local_grpc);
    let mut remote_grpc = remote_grpc;
    tokio::pin!(shutdown_signal);
    let mut result = tokio::select! {
        result = await_listener_ref(&mut http, "http") => result,
        result = await_listener_ref(&mut https, "https") => result,
        result = await_listener_ref(&mut metrics, "metrics") => result,
        result = await_listener_ref(&mut acme_http01, "acme http-01") => result,
        result = await_listener_ref(&mut external_acme_http01, "acme http-01") => result,
        result = await_anyhow_listener_ref(&mut local_grpc, "local grpc") => result,
        result = await_anyhow_listener_ref(&mut remote_grpc, "remote grpc") => result,
        signal = &mut shutdown_signal => {
            match signal {
                Ok(signal) => {
                    if let Some(gc) = &ephemeral_gc {
                        gc.abort();
                    }
                    for task in &maintenance {
                        task.abort();
                    }
                    tracing::info!(signal, "Received signal to stop, shutting down gracefully");
                    let delivery = announce_native_derp_server_shutdown(native_derp.as_ref()).await;
                    if delivery.delivered() > 0 {
                        tokio::time::sleep(NATIVE_DERP_SHUTDOWN_NOTICE_FLUSH_GRACE).await;
                    }
                    Ok(())
                }
                Err(error) => Err(error),
            }
        },
    };
    // Retain the losing handles through select: dropping JoinHandles detaches
    // listeners. Stop accepting first, then drain owned native work while its
    // database, NodeStore worker and map batcher are still available.
    for task in maintenance {
        task.abort();
    }
    if let Some(gc) = &ephemeral_gc {
        gc.abort();
    }
    if let Some(control) = http_shutdown {
        // This shares one three-second budget across debug then main. Its
        // listener tasks finish after admission stops; ordinary connection
        // tasks survive timeout without an abort, as in net/http.Shutdown.
        control.shutdown().await;
    } else {
        for task in [&http, &https, &metrics].into_iter().flatten() {
            task.abort();
        }
    }
    // ACME challenge-only listeners are independent of Go's debug/main
    // shutdown context; retain their existing explicit stop behavior.
    for task in [&acme_http01, &external_acme_http01].into_iter().flatten() {
        task.abort();
    }
    for task in [http, https, metrics, acme_http01, external_acme_http01]
        .into_iter()
        .flatten()
    {
        let _ = task.await;
    }
    if let Some(machines) = machines {
        machines.shutdown_native_streams().await;
    }
    if let Some(shutdown) = grpc_shutdown {
        // Headscale keeps RPCs available until map sessions have drained,
        // then gracefully stops local followed by external gRPC without a
        // timeout. Tonic waits for its accepted connections to finish.
        let _ = shutdown.local.send(());
        if let Some(task) = local_grpc {
            let stopped = flatten_anyhow_task_result(task.await, "local grpc");
            if result.is_ok() {
                result = stopped;
            }
        }
        if let Some(stop) = shutdown.remote {
            let _ = stop.send(());
        }
        if let Some(task) = remote_grpc {
            let stopped = flatten_anyhow_task_result(task.await, "remote grpc");
            if result.is_ok() {
                result = stopped;
            }
        }
    } else {
        // Compatibility helper callers do not own shutdown senders.
        for task in [&local_grpc, &remote_grpc].into_iter().flatten() {
            task.abort();
        }
        for task in [local_grpc, remote_grpc].into_iter().flatten() {
            let _ = task.await;
        }
    }
    result
}

async fn await_listener_ref(
    handle: &mut Option<tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>>,
    label: &'static str,
) -> Result<()> {
    let result = match handle.as_mut() {
        Some(task) => task.await,
        None => return std::future::pending::<Result<()>>().await,
    };
    handle.take();
    flatten_listener_result(result, label)
}

async fn await_anyhow_listener_ref(
    handle: &mut Option<tokio::task::JoinHandle<Result<()>>>,
    label: &'static str,
) -> Result<()> {
    let result = match handle.as_mut() {
        Some(task) => task.await,
        None => return std::future::pending::<Result<()>>().await,
    };
    handle.take();
    flatten_anyhow_task_result(result, label)
}

async fn announce_native_derp_server_shutdown(
    native_derp: Option<&Arc<NativeDerpRuntime>>,
) -> NativeDerpLifecycleDelivery {
    let Some(native_derp) = native_derp else {
        return NativeDerpLifecycleDelivery::default();
    };

    let delivery = native_derp.announce_server_shutdown().await;
    tracing::info!(
        health_frames = delivery.health,
        restarting_frames = delivery.restarting,
        "announced native DERP server shutdown lifecycle"
    );
    delivery
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<&'static str> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigint = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;

    tokio::select! {
        signal = sigint.recv() => {
            signal.context("SIGINT stream closed before receiving a signal")?;
            Ok("SIGINT")
        },
        signal = sigterm.recv() => {
            signal.context("SIGTERM stream closed before receiving a signal")?;
            Ok("SIGTERM")
        },
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<&'static str> {
    tokio::signal::ctrl_c()
        .await
        .context("install Ctrl-C handler")?;
    Ok("SIGINT")
}

fn optional_socket_addr(value: Option<&str>, field: &str) -> Result<Option<SocketAddr>> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| parse_socket_addr(value, field))
        .transpose()
}

fn non_empty_str(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn non_empty_string(value: &str) -> Option<String> {
    non_empty_str(Some(value)).map(str::to_string)
}

fn duration_nanos(duration: Duration) -> i64 {
    i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
}

fn flatten_listener_result(
    result: std::result::Result<std::result::Result<(), std::io::Error>, tokio::task::JoinError>,
    label: &str,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(err).with_context(|| format!("{label} listener failed")),
        Err(err) => Err(err).with_context(|| format!("{label} listener task failed")),
    }
}

fn flatten_anyhow_task_result(
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
    label: &str,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(err).with_context(|| format!("{label} listener failed")),
        Err(err) => Err(err).with_context(|| format!("{label} listener task failed")),
    }
}

fn hostname_from_server_url(server_url: &str) -> String {
    server_url_hostname(server_url).unwrap_or_else(|| "headscale-rs".to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpAllocationStrategy {
    Sequential,
    Random,
}

impl IpAllocationStrategy {
    fn parse(value: &str) -> Result<Self> {
        match value.trim() {
            "" | "sequential" => Ok(Self::Sequential),
            "random" => Ok(Self::Random),
            other => anyhow::bail!(
                "config error, prefixes.allocation is set to {other}, which is not a valid strategy, allowed options: sequential, random"
            ),
        }
    }
}

struct CidrIpAllocator {
    allocation: Mutex<()>,
    ipv4: Option<Mutex<IpFamilyAllocator>>,
    ipv6: Option<Mutex<IpFamilyAllocator>>,
    strategy: IpAllocationStrategy,
}

#[derive(Debug)]
struct IpFamilyAllocator {
    network: u128,
    end: u128,
    prev: u128,
    used: BTreeSet<u128>,
}

#[derive(Clone, Copy)]
struct ExistingNodeIpAddresses<'a> {
    ipv4: Option<&'a str>,
    ipv6: Option<&'a str>,
}

impl CidrIpAllocator {
    #[cfg(test)]
    fn from_cidr(cidr: &str) -> Result<Self> {
        Self::from_cidrs(cidr, None)
    }

    #[cfg(test)]
    fn from_cidrs(cidr: &str, cidr_v6: Option<&str>) -> Result<Self> {
        Self::from_cidrs_with_strategy(cidr, cidr_v6, IpAllocationStrategy::Sequential)
    }

    async fn from_database(
        pool: &sqlx::SqlitePool,
        cidr: &str,
        cidr_v6: Option<&str>,
        strategy: IpAllocationStrategy,
    ) -> Result<Self> {
        // Go plucks both raw columns before parsing any address, including
        // rows outside the live-node list. Keep the IPv4/IPv6 query order.
        let ipv4 = sqlx::query_scalar::<_, headscale_db::stored_text::NullableRawTextColumn>(
            "SELECT ipv4 FROM nodes",
        )
        .fetch_all(pool)
        .await
        .context("reading IPv4 addresses from database")?;
        let ipv6 = sqlx::query_scalar::<_, headscale_db::stored_text::NullableRawTextColumn>(
            "SELECT ipv6 FROM nodes",
        )
        .fetch_all(pool)
        .await
        .context("reading IPv6 addresses from database")?;
        Self::from_existing_node_ips(
            cidr,
            cidr_v6,
            strategy,
            ipv4.iter()
                .map(|value| ExistingNodeIpAddresses {
                    ipv4: value.as_deref(),
                    ipv6: None,
                })
                .chain(ipv6.iter().map(|value| ExistingNodeIpAddresses {
                    ipv4: None,
                    ipv6: value.as_deref(),
                })),
        )
    }

    #[cfg(feature = "postgres-sqlx")]
    async fn from_postgres_database(
        pool: &sqlx::PgPool,
        cidr: &str,
        cidr_v6: Option<&str>,
        strategy: IpAllocationStrategy,
    ) -> Result<Self> {
        // Go plucks both raw columns before parsing any address, including
        // rows outside the live-node list. Keep the IPv4/IPv6 query order.
        let ipv4 = sqlx::query_scalar::<_, headscale_db::stored_text::NullableRawTextColumn>(
            "SELECT ipv4 FROM nodes",
        )
        .fetch_all(pool)
        .await
        .context("reading IPv4 addresses from database")?;
        let ipv6 = sqlx::query_scalar::<_, headscale_db::stored_text::NullableRawTextColumn>(
            "SELECT ipv6 FROM nodes",
        )
        .fetch_all(pool)
        .await
        .context("reading IPv6 addresses from database")?;
        Self::from_existing_node_ips(
            cidr,
            cidr_v6,
            strategy,
            ipv4.iter()
                .map(|value| ExistingNodeIpAddresses {
                    ipv4: value.as_deref(),
                    ipv6: None,
                })
                .chain(ipv6.iter().map(|value| ExistingNodeIpAddresses {
                    ipv4: None,
                    ipv6: value.as_deref(),
                })),
        )
    }

    fn from_existing_node_ips<'a>(
        cidr: &str,
        cidr_v6: Option<&str>,
        strategy: IpAllocationStrategy,
        rows: impl IntoIterator<Item = ExistingNodeIpAddresses<'a>>,
    ) -> Result<Self> {
        let allocator = Self::from_cidrs_with_strategy(cidr, cidr_v6, strategy)?;
        let rows = rows.into_iter().collect::<Vec<_>>();
        for row in &rows {
            allocator.seed_existing(row.ipv4, None)?;
        }
        for row in rows {
            allocator.seed_existing(None, row.ipv6)?;
        }
        Ok(allocator)
    }

    fn from_cidrs_with_strategy(
        cidr: &str,
        cidr_v6: Option<&str>,
        strategy: IpAllocationStrategy,
    ) -> Result<Self> {
        let ipv4 = (!cidr.is_empty())
            .then(|| parse_ipv4_cidr(cidr))
            .transpose()?;
        let ipv6 = cidr_v6
            .filter(|cidr| !cidr.is_empty())
            .map(parse_ipv6_cidr)
            .transpose()?;
        if ipv4.is_none() && ipv6.is_none() {
            anyhow::bail!("config error, at least one of prefixes.v4 or prefixes.v6 must be set");
        }

        Ok(Self {
            allocation: Mutex::new(()),
            ipv4,
            ipv6,
            strategy,
        })
    }

    fn seed_existing(&self, ipv4: Option<&str>, ipv6: Option<&str>) -> Result<()> {
        let _allocation = self.allocation.lock().expect("IP allocator lock poisoned");
        for text in [ipv4, ipv6].into_iter().flatten() {
            let (ip, _) = headscale_api_acl::go_netip::parse_addr(text)
                .map_err(|error| anyhow::anyhow!("parsing IP address from database: {error}"))?;
            // Go netipx drops IPv6 zones when inserting an address into its
            // used IP set. Column names do not constrain the stored family.
            let (family, value) = match ip {
                IpAddr::V4(ip) => (&self.ipv4, u128::from(u32::from(ip))),
                IpAddr::V6(ip) => (&self.ipv6, u128::from(ip)),
            };
            if let Some(family) = family {
                family
                    .lock()
                    .expect("IP family allocator lock poisoned")
                    .used
                    .insert(value);
            }
        }
        Ok(())
    }

    fn allocate_ipv4_inner(&self) -> std::result::Result<Ipv4Addr, AllocError> {
        let Some(ipv4) = &self.ipv4 else {
            return Err(AllocError::Internal(
                "IPv4 allocation requested while IPv4 is disabled".into(),
            ));
        };
        let value = ipv4
            .lock()
            .expect("IPv4 allocator lock poisoned")
            .allocate(self.strategy, |candidate| {
                is_tailscale_reserved_ipv4(Ipv4Addr::from(candidate as u32))
            })?;
        Ok(Ipv4Addr::from(value as u32))
    }

    fn allocate_ipv6_inner(&self) -> std::result::Result<Option<Ipv6Addr>, AllocError> {
        let Some(ipv6) = &self.ipv6 else {
            return Ok(None);
        };
        let value = ipv6
            .lock()
            .expect("IPv6 allocator lock poisoned")
            .allocate(self.strategy, |candidate| {
                is_tailscale_reserved_ipv6(Ipv6Addr::from(candidate))
            })?;
        Ok(Some(Ipv6Addr::from(value)))
    }
}

fn parse_ipv4_cidr(cidr: &str) -> Result<Mutex<IpFamilyAllocator>> {
    let (address, prefix) = headscale_api_acl::go_netip::parse_prefix(cidr)
        .map_err(|error| anyhow::anyhow!("invalid server.mesh_cidr: {error}"))?;
    let IpAddr::V4(addr) = address else {
        anyhow::bail!("invalid server.mesh_cidr {cidr:?}: expected IPv4 prefix");
    };
    let host_bits = 32u32 - u32::from(prefix);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << host_bits
    };
    let network = u32::from(addr) & mask;
    let end = network | !mask;

    Ok(Mutex::new(IpFamilyAllocator::new(
        u128::from(network),
        u128::from(end),
    )))
}

fn parse_ipv6_cidr(cidr: &str) -> Result<Mutex<IpFamilyAllocator>> {
    let (address, prefix) = headscale_api_acl::go_netip::parse_prefix(cidr)
        .map_err(|error| anyhow::anyhow!("invalid server.mesh_cidr_v6: {error}"))?;
    let IpAddr::V6(addr) = address else {
        anyhow::bail!("invalid server.mesh_cidr_v6 {cidr:?}: expected IPv6 prefix");
    };
    let host_bits = 128u32 - u32::from(prefix);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << host_bits
    };
    let network = u128::from(addr) & mask;
    let end = network | !mask;

    Ok(Mutex::new(IpFamilyAllocator::new(network, end)))
}

impl IpFamilyAllocator {
    fn new(network: u128, end: u128) -> Self {
        let mut used = BTreeSet::new();
        used.insert(network);
        used.insert(end);
        Self {
            network,
            end,
            prev: network,
            used,
        }
    }

    fn allocate(
        &mut self,
        strategy: IpAllocationStrategy,
        reserved: impl Fn(u128) -> bool + Copy,
    ) -> std::result::Result<u128, AllocError> {
        match strategy {
            IpAllocationStrategy::Sequential => self.allocate_sequential(reserved),
            IpAllocationStrategy::Random => self.allocate_random(reserved),
        }
    }

    fn allocate_sequential(
        &mut self,
        reserved: impl Fn(u128) -> bool,
    ) -> std::result::Result<u128, AllocError> {
        let Some(mut candidate) = self.prev.checked_add(1) else {
            return Err(AllocError::Exhausted);
        };
        while candidate <= self.end {
            if !self.used.contains(&candidate) && !reserved(candidate) {
                self.used.insert(candidate);
                self.prev = candidate;
                return Ok(candidate);
            }
            let Some(next) = candidate.checked_add(1) else {
                return Err(AllocError::Exhausted);
            };
            candidate = next;
        }
        Err(AllocError::Exhausted)
    }

    fn allocate_random(
        &mut self,
        reserved: impl Fn(u128) -> bool + Copy,
    ) -> std::result::Result<u128, AllocError> {
        let start = random_between(self.network, self.end)?;
        let mut candidate = start;
        loop {
            if !self.used.contains(&candidate) && !reserved(candidate) {
                self.used.insert(candidate);
                self.prev = candidate;
                return Ok(candidate);
            }
            candidate = candidate
                .checked_add(1)
                .filter(|candidate| *candidate <= self.end)
                .unwrap_or(self.network);
            if candidate == start {
                return Err(AllocError::Exhausted);
            }
        }
    }
}

impl IpAllocator for CidrIpAllocator {
    fn release_addresses(&self, ipv4: Option<Ipv4Addr>, ipv6: Option<Ipv6Addr>) {
        let _allocation = self.allocation.lock().expect("IP allocator lock poisoned");
        if let (Some(ip), Some(family)) = (ipv4, &self.ipv4) {
            family
                .lock()
                .expect("IPv4 allocator lock poisoned")
                .used
                .remove(&u128::from(u32::from(ip)));
        }
        if let (Some(ip), Some(family)) = (ipv6, &self.ipv6) {
            family
                .lock()
                .expect("IPv6 allocator lock poisoned")
                .used
                .remove(&u128::from(ip));
        }
        // FreeIPs does not rewind the sequential cursor. Random allocation
        // can reuse the hole on a later scan; sequential allocation keeps Next.
    }

    fn allocate(&self, _node_key_hex: &str) -> std::result::Result<Ipv4Addr, AllocError> {
        let _allocation = self.allocation.lock().expect("IP allocator lock poisoned");
        self.allocate_ipv4_inner()
    }

    fn allocate_addresses(
        &self,
        _node_key_hex: &str,
    ) -> std::result::Result<(Option<Ipv4Addr>, Option<Ipv6Addr>), String> {
        let _allocation = self.allocation.lock().expect("IP allocator lock poisoned");
        let ipv4 = if self.ipv4.is_some() {
            Some(
                self.allocate_ipv4_inner()
                    .map_err(|error| format!("allocating IPv4 address: {error}"))?,
            )
        } else {
            None
        };
        let ipv6 = self
            .allocate_ipv6_inner()
            .map_err(|error| format!("allocating IPv6 address: {error}"))?;
        Ok((ipv4, ipv6))
    }

    fn ipv4_enabled(&self) -> bool {
        self.ipv4.is_some()
    }

    fn allocate_ipv6(
        &self,
        _node_key_hex: &str,
    ) -> std::result::Result<Option<Ipv6Addr>, AllocError> {
        let _allocation = self.allocation.lock().expect("IP allocator lock poisoned");
        self.allocate_ipv6_inner()
    }

    fn ipv6_enabled(&self) -> bool {
        self.ipv6.is_some()
    }
}

/// Go crypto/rand.Int uses rejection sampling below (end - start), excluding
/// the upper endpoint; a single-address prefix returns its sole address.
fn random_between(start: u128, end: u128) -> std::result::Result<u128, AllocError> {
    let bound = end - start;
    if bound <= 1 {
        return Ok(start);
    }
    let bits = 128 - (bound - 1).leading_zeros();
    let bytes = bits.div_ceil(8) as usize;
    let high_mask = u8::MAX >> (bytes as u32 * 8 - bits);
    loop {
        let mut raw = [0u8; 16];
        let random = &mut raw[16 - bytes..];
        OsRng.try_fill_bytes(random).map_err(|error| {
            AllocError::Internal(format!("getting random IP: generating random IP: {error}"))
        })?;
        random[0] &= high_mask;
        let sample = u128::from_be_bytes(raw);
        if sample < bound {
            return Ok(start + sample);
        }
    }
}

fn is_tailscale_reserved_ipv4(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    let chrome_start = u32::from(Ipv4Addr::new(100, 115, 92, 0));
    let chrome_end = u32::from(Ipv4Addr::new(100, 115, 93, 255));
    ip == Ipv4Addr::new(100, 100, 100, 100) || (chrome_start..=chrome_end).contains(&value)
}

fn is_tailscale_reserved_ipv6(ip: Ipv6Addr) -> bool {
    ip == Ipv6Addr::new(0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 0x53)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acme_issuer::test_support::{LOCAL_ACME_HOSTNAME, LocalAcmeServer};
    use axum::{
        body::{Body, to_bytes},
        http::{Request as HttpRequest, StatusCode, header},
        routing::post,
    };
    use headscale_api::generated::{
        CreatePreAuthKeyRequest, CreateUserRequest, HealthRequest, RegisterNodeRequest,
        SetApprovedRoutesRequest, SetPolicyRequest, SetTagsRequest,
        headscale_service_client::HeadscaleServiceClient,
        headscale_service_server::HeadscaleService,
    };
    use headscale_api::oidc::{
        OidcAuthConfig, OidcPkceConfig, OidcPolicyConfig, OidcRegistrationHandler, OidcStoredUser,
        REGISTER_METHOD_OIDC,
    };
    use headscale_api::tailscale_wire::derp::{
        NATIVE_DERP_SHUTDOWN_HEALTH_PROBLEM, NATIVE_DERP_SHUTDOWN_RECONNECT_IN,
        NATIVE_DERP_SHUTDOWN_TRY_FOR, drive_native_derp,
    };
    use headscale_api::tailscale_wire::{
        map as wire_map_handlers,
        noise::NoisePeerMachineKey,
        register as wire_register_handlers,
        wire::{MapResponse, RegisterResponse},
    };
    use headscale_core::{
        config::EmbeddedDerpRelayMode,
        derp::{
            native::NativeDerpRelay,
            protocol::{
                ClientInfo, DerpNodeKeyPair, Frame, FrameDecoder, KEY_LEN, MAX_INFO_LEN,
                ServerInfo, encode_client_info_frame, open_server_info,
            },
        },
    };
    use hyper_util::rt::TokioIo;
    use serde_json::Value;
    use std::collections::BTreeMap;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::time::{sleep, timeout};
    use tonic::{
        Request as TonicRequest,
        transport::{Channel, Endpoint, Uri},
    };
    use tonic_reflection::pb::v1::{
        ServerReflectionRequest, server_reflection_client::ServerReflectionClient,
        server_reflection_request::MessageRequest, server_reflection_response::MessageResponse,
    };
    use tower::ServiceExt;
    use tower::service_fn;

    #[cfg(feature = "postgres-sqlx")]
    const POSTGRES_TEST_URL_ENV: &str = "HEADSCALE_DB_POSTGRES_TEST_URL";

    #[cfg(feature = "postgres-sqlx")]
    type BoxTestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

    #[cfg(feature = "postgres-sqlx")]
    struct TempPostgresRuntimeSchema {
        admin_pool: sqlx::PgPool,
        runtime_pool: sqlx::PgPool,
        quoted_name: String,
    }

    #[cfg(feature = "postgres-sqlx")]
    impl TempPostgresRuntimeSchema {
        async fn open(test_name: &str) -> BoxTestResult<Option<Self>> {
            use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
            use std::str::FromStr;
            use std::time::{SystemTime, UNIX_EPOCH};

            let Ok(url) = std::env::var(POSTGRES_TEST_URL_ENV) else {
                eprintln!(
                    "skipping Postgres runtime smoke {test_name}: {POSTGRES_TEST_URL_ENV} is not set"
                );
                return Ok(None);
            };

            let admin_pool = headscale_db::open_postgres_pool(&url).await?;
            let schema = {
                let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
                format!(
                    "headscale_rs_pg_runtime_{}_{}_{}",
                    std::process::id(),
                    test_name,
                    nanos
                )
            };
            let quoted_name = quote_pg_identifier(&schema);

            sqlx::query(&format!("CREATE SCHEMA {quoted_name}"))
                .execute(&admin_pool)
                .await?;

            let runtime_options =
                PgConnectOptions::from_str(&url)?.options([("search_path", schema.as_str())]);
            let runtime_pool = PgPoolOptions::new()
                .max_connections(5)
                .connect_with(runtime_options)
                .await?;

            Ok(Some(Self {
                admin_pool,
                runtime_pool,
                quoted_name,
            }))
        }

        fn pool(&self) -> &sqlx::PgPool {
            &self.runtime_pool
        }

        async fn cleanup(self) -> BoxTestResult {
            self.runtime_pool.close().await;
            sqlx::query(&format!(
                "DROP SCHEMA IF EXISTS {} CASCADE",
                self.quoted_name
            ))
            .execute(&self.admin_pool)
            .await?;
            self.admin_pool.close().await;
            Ok(())
        }
    }

    #[cfg(feature = "postgres-sqlx")]
    fn quote_pg_identifier(identifier: &str) -> String {
        format!(r#""{}""#, identifier.replace('"', r#""""#))
    }

    fn oidc_runtime() -> OidcAuthRuntime {
        OidcAuthRuntime::new(OidcAuthConfig {
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
            pkce: OidcPkceConfig::default(),
            policy: OidcPolicyConfig::default(),
        })
    }

    fn wire_machine_router(state: WireState) -> axum::Router {
        axum::Router::new()
            .route(
                "/machine/:node_key/register",
                post(wire_register_handlers::handle_register),
            )
            .route(
                "/machine/register",
                post(wire_register_handlers::handle_register_flat),
            )
            .route(
                "/machine/:node_key/map",
                post(wire_map_handlers::handle_map),
            )
            .route("/machine/map", post(wire_map_handlers::handle_map_flat))
            .with_state(state)
    }

    async fn wire_register_authkey(
        state: &WireState,
        node_key_hex: &str,
        machine_key_hex: &str,
        authkey: &str,
        hostname: &str,
    ) -> RegisterResponse {
        let app = wire_machine_router(state.clone());
        let mut request = HttpRequest::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "Version": 113,
                    "NodeKey": format!("nodekey:{node_key_hex}"),
                    "Auth": {"AuthKey": authkey},
                    "Hostinfo": {
                        "Hostname": hostname,
                        "OS": "linux",
                        "OSVersion": "6.8",
                    }
                }))
                .unwrap(),
            ))
            .unwrap();
        request
            .extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.to_string()));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn wire_register_interactive(
        state: &WireState,
        node_key_hex: &str,
        machine_key_hex: &str,
        hostname: &str,
        routes: &[&str],
    ) -> RegisterResponse {
        let app = wire_machine_router(state.clone());
        let mut request = HttpRequest::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/register"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "Version": 113,
                    "NodeKey": format!("nodekey:{node_key_hex}"),
                    "Hostinfo": {
                        "Hostname": hostname,
                        "OS": "linux",
                        "OSVersion": "6.8",
                        "RoutableIPs": routes,
                    }
                }))
                .unwrap(),
            ))
            .unwrap();
        request
            .extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.to_string()));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn registration_id_from_auth_url(auth_url: &str) -> String {
        let auth_id = auth_url
            .split_once('?')
            .map_or(auth_url, |(path, _)| path)
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .expect("auth URL includes registration id");
        auth_id
            .strip_prefix("hskey-authreq-")
            .unwrap_or(auth_id)
            .to_string()
    }

    async fn wire_map_status(
        state: &WireState,
        node_key_hex: &str,
        machine_key_hex: &str,
        body: serde_json::Value,
    ) -> StatusCode {
        let app = wire_machine_router(state.clone());
        let mut request = HttpRequest::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/map"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        request
            .extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.to_string()));
        app.oneshot(request).await.unwrap().status()
    }

    async fn wire_full_map(
        state: &WireState,
        node_key_hex: &str,
        machine_key_hex: &str,
    ) -> MapResponse {
        let app = wire_machine_router(state.clone());
        let mut request = HttpRequest::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/map"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"Version":113}"#))
            .unwrap();
        request
            .extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.to_string()));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 256 * 1024).await.unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    async fn wire_map_stream(state: &WireState, node_key_hex: &str, machine_key_hex: &str) -> Body {
        let app = wire_machine_router(state.clone());
        let mut request = HttpRequest::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key_hex}/map"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(r#"{"Version":113,"Stream":true}"#))
            .unwrap();
        request
            .extensions_mut()
            .insert(NoisePeerMachineKey(machine_key_hex.to_string()));
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body()
    }

    async fn next_stream_map(body: &mut Body) -> MapResponse {
        use http_body_util::BodyExt;

        let frame = tokio::time::timeout(Duration::from_secs(2), BodyExt::frame(body))
            .await
            .expect("stream frame timeout")
            .expect("stream frame")
            .expect("stream frame ok");
        let chunk = frame.into_data().expect("data frame");
        assert!(chunk.len() >= 4, "stream frame includes length prefix");
        let len = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) as usize;
        assert_eq!(chunk.len(), 4 + len, "framed chunk size mismatch");
        serde_json::from_slice(&chunk[4..]).expect("map response json")
    }

    #[test]
    fn state_directory_is_created_with_go_private_mode() {
        // readOrCreatePrivateKey goes through util.EnsureDir for the directory
        // holding the Noise key, which is the state directory here.
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("var").join("headscale");
        create_private_dir_all(&state_dir).unwrap();
        for created in [dir.path().join("var"), state_dir.clone()] {
            let mode = std::fs::metadata(&created).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o700,
                "{} created with mode {mode:o}",
                created.display()
            );
        }

        std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        create_private_dir_all(&state_dir).unwrap();
        let mode = std::fs::metadata(&state_dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750, "existing directory mode must be preserved");
    }

    #[test]
    fn ensure_parent_dir_creates_missing_directories_with_go_private_mode() {
        // headscale-go creates the SQLite database and unix socket directories
        // through util.EnsureDir: os.MkdirAll(dir, 0o700), never the umask
        // default. Existing directories are left alone whatever their mode.
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("state").join("nested");
        let path = nested.join("db.sqlite");
        ensure_parent_dir(&path).unwrap();
        for created in [dir.path().join("state"), nested.clone()] {
            let mode = std::fs::metadata(&created).unwrap().permissions().mode() & 0o777;
            assert_eq!(
                mode,
                0o700,
                "{} created with mode {mode:o}",
                created.display()
            );
        }

        std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o750)).unwrap();
        ensure_parent_dir(&path).unwrap();
        let mode = std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750, "existing directory mode must be preserved");
    }

    fn test_run_server_config(dir: &tempfile::TempDir) -> RunServerConfig {
        RunServerConfig {
            listen: "127.0.0.1:8080".into(),
            db_path: dir.path().join("db.sqlite"),
            mesh_cidr: "100.64.0.0/10".into(),
            mesh_cidr_v6: None,
            ip_allocation: "sequential".into(),
            server_url: Some("https://headscale.example".into()),
            state_dir: dir.path().join("state"),
            noise_private_key_path: None,
            https_listen: None,
            metrics_listen_addr: Some("127.0.0.1:9090".into()),
            tls_hostname: None,
            unix_socket: dir.path().join("state/headscale.sock"),
            unix_socket_permission: 0o700,
            grpc_listen_addr: ":50443".into(),
            grpc_allow_insecure: false,
            trusted_proxies: Vec::new(),
            disable_check_updates: false,
            tls: TlsRuntimeConfig::default(),
            oidc: OidcConfig {
                expiry: Duration::ZERO,
                ..OidcConfig::default()
            },
            node_expiry: Duration::default(),
            node_routes_ha_probe_interval: Duration::from_secs(10),
            node_routes_ha_probe_timeout: Duration::from_secs(5),
            embedded_derp: EmbeddedDerpConfig::default(),
            derp: None,
            database: None,
            dns: None,
            policy: PolicyConfig::default(),
            taildrop_enabled: true,
            logtail_enabled: false,
            auto_update_enabled: false,
            logging: LoggingConfig::default(),
            cli: AdminCliConfig::default(),
            tuning: TuningConfig::default(),
            ephemeral_node_inactivity_timeout: Duration::from_secs(120),
        }
    }

    fn unused_loopback_addr() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    async fn read_test_derp_frame<R>(reader: &mut R, decoder: &mut FrameDecoder) -> Frame
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 1024];
        loop {
            if let Some(frame) = decoder.next_frame().unwrap() {
                return frame;
            }
            let n = timeout(Duration::from_secs(2), reader.read(&mut buf))
                .await
                .expect("timed out waiting for DERP frame bytes")
                .expect("read DERP frame bytes");
            assert_ne!(n, 0, "DERP stream closed before the next frame");
            decoder.push(&buf[..n]);
        }
    }

    #[tokio::test]
    async fn serve_shutdown_signal_announces_native_derp_lifecycle_to_raw_session() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let native_derp = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_runtime = native_derp.clone();
        let derp_server =
            tokio::spawn(async move { drive_native_derp(server_runtime, server_io).await });
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);
        let mut decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: server_public, ..
        } = read_test_derp_frame(&mut client_reader, &mut decoder).await
        else {
            panic!("expected server-key frame");
        };
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        client_writer.write_all(&client_info).await.unwrap();
        client_writer.flush().await.unwrap();
        let server_info_frame = read_test_derp_frame(&mut client_reader, &mut decoder).await;
        assert_eq!(
            open_server_info(&client_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );

        let local_grpc = tokio::spawn(async { std::future::pending::<Result<()>>().await });
        let handle = serve::ServeHandle {
            http: None,
            https: None,
            metrics: None,
            acme_http01: None,
            metrics_addr: None,
            acme_http01_addr: None,
            tls: None,
            tls_reloader: None,
        };
        await_serve_handle_with_shutdown(
            handle,
            local_grpc,
            None,
            None,
            Some(native_derp),
            async { Ok("test-shutdown") },
        )
        .await
        .unwrap();

        assert_eq!(
            read_test_derp_frame(&mut client_reader, &mut decoder).await,
            Frame::Health(NATIVE_DERP_SHUTDOWN_HEALTH_PROBLEM.to_string())
        );
        assert_eq!(
            read_test_derp_frame(&mut client_reader, &mut decoder).await,
            Frame::Restarting {
                reconnect_in_ms: NATIVE_DERP_SHUTDOWN_RECONNECT_IN.as_millis() as u32,
                try_for_ms: NATIVE_DERP_SHUTDOWN_TRY_FOR.as_millis() as u32,
            }
        );

        drop(client_writer);
        drop(client_reader);
        assert!(derp_server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn open_sqlite_database_applies_upstream_wal_settings() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            r"
database:
  type: sqlite
  sqlite:
    write_ahead_log: true
    wal_autocheckpoint: 41
",
        )
        .unwrap();
        let config = crate::config::CliConfig::load(&config_path).unwrap();
        let db = open_sqlite_database(
            &dir.path().join("headscale.sqlite"),
            config.database.as_ref(),
        )
        .await
        .unwrap();

        let busy_timeout: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let auto_vacuum: i64 = sqlx::query_scalar("PRAGMA auto_vacuum")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let wal_autocheckpoint: i64 = sqlx::query_scalar("PRAGMA wal_autocheckpoint")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(db.pool())
            .await
            .unwrap();

        assert_eq!(busy_timeout, 10_000);
        assert_eq!(auto_vacuum, 2, "INCREMENTAL");
        assert_eq!(synchronous, 1, "NORMAL");
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(wal_autocheckpoint, 41);
        assert_eq!(foreign_keys, 1);
    }

    #[test]
    fn sqlite_open_options_use_upstream_defaults_without_database_block() {
        assert_eq!(
            sqlite_open_options(None).unwrap(),
            SqliteOpenOptions::default()
        );
    }

    #[test]
    fn configtest_accepts_upstream_sqlite_wal_default_marker() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            r"
database:
  type: sqlite
  sqlite:
    wal_autocheckpoint: -1
",
        )
        .unwrap();
        let config = crate::config::CliConfig::load(&config_path).unwrap();

        let options = sqlite_open_options(config.database.as_ref()).unwrap();
        assert_eq!(options.write_ahead_log, Some(true));
        assert_eq!(options.wal_autocheckpoint, None);
        assert_eq!(
            options.busy_timeout,
            SqliteOpenOptions::default().busy_timeout
        );
    }

    #[test]
    fn server_boundary_disables_legacy_oidc_expiry_default() {
        let oidc = OidcConfig {
            issuer: "https://issuer.example".into(),
            client_id: "headscale-rs".into(),
            use_expiry_from_token: true,
            ..OidcConfig::default()
        };

        let normalized = upstream_oidc_runtime_config(&oidc);

        assert_eq!(oidc.expiry, Duration::from_secs(180 * 24 * 60 * 60));
        assert_eq!(normalized.expiry, Duration::ZERO);
        assert_eq!(normalized.issuer, oidc.issuer);
        assert_eq!(normalized.client_id, oidc.client_id);
        assert!(normalized.use_expiry_from_token);
    }

    #[test]
    fn embedded_derp_config_builds_wire_derp_map() {
        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "derp.example.com".into(),
            derp_port: 8443,
            stun_addr: Some("0.0.0.0:3478".parse().unwrap()),
            stun_only: true,
            region_id: 901,
            region_code: "test".into(),
            region_name: "Test DERP".into(),
            omit_default_regions: true,
            insecure_for_tests: true,
            ipv4: "198.51.100.1".into(),
            ipv6: "2001:db8::1".into(),
            ..EmbeddedDerpConfig::default()
        };

        let map = derp_map_from_embedded_config(&cfg);
        assert!(map.omit_default_regions);
        let region = map.regions.get(&901).unwrap();
        assert_eq!(region.region_code, "test");
        assert_eq!(region.region_name, "Test DERP");
        let node = &region.nodes[0];
        assert_eq!(node.name, "901");
        assert_eq!(node.host_name, "derp.example.com");
        assert_eq!(node.derp_port, 8443);
        assert_eq!(node.stun_port, 3478);
        assert!(node.stun_only);
        assert!(node.insecure_for_tests);
        assert_eq!(node.ipv4, "198.51.100.1");
        assert_eq!(node.ipv6, "2001:db8::1");
    }

    #[test]
    fn disabled_embedded_derp_keeps_empty_wire_derp_map() {
        let map = derp_map_from_embedded_config(&EmbeddedDerpConfig::default());
        assert!(map.regions.is_empty());
        assert!(!map.omit_default_regions);
    }

    #[test]
    fn embedded_derp_map_disables_stun_when_no_listener_is_configured() {
        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "derp.example.com".into(),
            derper_binary: "/usr/local/bin/derper".into(),
            ..EmbeddedDerpConfig::default()
        };

        let map = derp_map_from_embedded_config(&cfg);
        let node = &map.regions.get(&900).unwrap().nodes[0];

        assert_eq!(node.stun_port, -1);
    }

    #[test]
    fn embedded_derp_map_preserves_default_tls_derp_port_like_headscale_go() {
        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "derp.example.com".into(),
            derp_port: 443,
            stun_only: true,
            stun_addr: Some("0.0.0.0:3478".parse().unwrap()),
            ..EmbeddedDerpConfig::default()
        };

        let map = derp_map_from_embedded_config(&cfg);
        let node = &map.regions.get(&900).unwrap().nodes[0];

        assert_eq!(node.derp_port, 443);
        assert_eq!(node.stun_port, 3478);
    }

    #[tokio::test]
    async fn runtime_derp_config_merges_static_paths_and_embedded_region() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(
            &mut file,
            br"
regions:
  901:
    regionid: 901
    regioncode: static
    regionname: Static DERP
    nodes:
      - name: 901a
        regionid: 901
        hostname: static.example.com
",
        )
        .unwrap();
        let derp = DerpConfig {
            urls: Vec::new(),
            paths: vec![file.path().to_path_buf()],
            ..DerpConfig::default()
        };
        let embedded = EmbeddedDerpConfig {
            enabled: true,
            host_name: "embedded.example.com".into(),
            region_id: 900,
            ..EmbeddedDerpConfig::default()
        };

        let map = native_derp_map_from_runtime_config(Some(&derp), &embedded, "")
            .await
            .unwrap()
            .projection();

        assert_eq!(
            map.regions
                .get(&901)
                .unwrap()
                .nodes
                .first()
                .unwrap()
                .host_name,
            "static.example.com"
        );
        assert_eq!(
            map.regions
                .get(&900)
                .unwrap()
                .nodes
                .first()
                .unwrap()
                .host_name,
            "embedded.example.com"
        );
    }

    #[tokio::test]
    async fn runtime_derp_config_rejects_disable_embedded_region_without_paths() {
        let derp = DerpConfig {
            server: crate::derp_config::UpstreamDerpServerConfig {
                enabled: true,
                automatically_add_embedded_derp_region: false,
                ..Default::default()
            },
            urls: Vec::new(),
            ..DerpConfig::default()
        };
        let embedded = EmbeddedDerpConfig {
            enabled: true,
            host_name: "embedded.example.com".into(),
            region_id: 900,
            ..EmbeddedDerpConfig::default()
        };

        let err = native_derp_map_from_runtime_config(Some(&derp), &embedded, "")
            .await
            .unwrap_err();

        assert!(
            format!("{err:#}").contains("requires at least one derp.paths entry"),
            "{err:#}"
        );
    }

    #[test]
    fn derp_auto_update_requires_enabled_flag_and_nonzero_frequency() {
        assert!(!derp_auto_update_enabled(&DerpConfig {
            auto_update_enabled: false,
            update_frequency: 60,
            ..DerpConfig::default()
        }));
        assert!(!derp_auto_update_enabled(&DerpConfig {
            auto_update_enabled: true,
            update_frequency: 0,
            ..DerpConfig::default()
        }));
        assert!(derp_auto_update_enabled(&DerpConfig {
            auto_update_enabled: true,
            update_frequency: 60,
            ..DerpConfig::default()
        }));
    }

    #[tokio::test]
    async fn refresh_derp_map_once_replaces_store_and_merges_embedded_region() {
        let server = httpmock::MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/derp.json");
            then.status(200).json_body(serde_json::json!({
                "Regions": {
                    "901": {
                        "RegionID": 901,
                        "RegionCode": "url",
                        "RegionName": "URL DERP",
                        "Nodes": [{
                            "Name": "901a",
                            "RegionID": 901,
                            "HostName": "url.example.com"
                        }]
                    }
                }
            }));
        });
        let derp = DerpConfig {
            urls: vec![server.url("/derp.json")],
            auto_update_enabled: true,
            update_frequency: 60,
            ..DerpConfig::default()
        };
        let embedded = EmbeddedDerpConfig {
            enabled: true,
            region_id: 902,
            region_code: "embedded".into(),
            region_name: "Embedded DERP".into(),
            host_name: "embedded.example.com".into(),
            stun_addr: None,
            ..EmbeddedDerpConfig::default()
        };
        let store = DerpMapStore::shared(DerpMap::default());

        refresh_derp_map_once(&derp, &embedded, &store, "")
            .await
            .unwrap();

        mock.assert();
        let map = store.snapshot();
        assert_eq!(
            map.regions
                .get(&901)
                .unwrap()
                .nodes
                .first()
                .unwrap()
                .host_name,
            "url.example.com"
        );
        assert_eq!(
            map.regions
                .get(&902)
                .unwrap()
                .nodes
                .first()
                .unwrap()
                .host_name,
            "embedded.example.com"
        );
    }

    #[test]
    fn dns_store_from_config_validates_magic_dns_base_domain() {
        let err =
            dns_store_from_config(Some(DnsConfigSpec::default()), Some("100.64.0.0/10"), None)
                .unwrap_err();
        assert!(format!("{err:#}").contains("dns.base_domain must be set"));
        let (store, path) = dns_store_from_config(None, Some("100.64.0.0/10"), None).unwrap();
        assert!(path.is_none());
        assert_eq!(serde_json::to_string(&store.build(&[])).unwrap(), "{}");
    }

    #[test]
    fn dns_store_from_config_adds_magicdns_reverse_routes_from_prefixes() {
        let (store, path) = dns_store_from_config(
            Some(DnsConfigSpec {
                base_domain: "tail.example.org".to_string(),
                override_local_dns: false,
                ..DnsConfigSpec::default()
            }),
            Some("100.64.0.0/10"),
            Some("fd7a:115c:a1e0::/48"),
        )
        .unwrap();

        let dns = store.build(&[]);

        assert!(path.is_none());
        assert!(dns.routes["64.100.in-addr.arpa"].is_empty());
        assert!(dns.routes["127.100.in-addr.arpa"].is_empty());
        assert!(dns.routes["0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa"].is_empty());
    }

    #[test]
    fn dns_store_from_config_loads_extra_records_path_before_serving() {
        let dir = tempfile::tempdir().unwrap();
        let records_path = dir.path().join("extra-records.json");
        std::fs::write(
            &records_path,
            r#"[{"name":"ops.tail.example.org","type":"A","value":"100.64.0.50"}]"#,
        )
        .unwrap();

        let (store, path) = dns_store_from_config(
            Some(DnsConfigSpec {
                magic_dns: false,
                override_local_dns: false,
                extra_records_path: Some(records_path.clone()),
                ..DnsConfigSpec::default()
            }),
            Some("100.64.0.0/10"),
            None,
        )
        .unwrap();

        assert_eq!(path.as_deref(), Some(records_path.as_path()));
        assert_eq!(store.extra_records().len(), 1);
        assert_eq!(store.extra_records()[0].name, "ops.tail.example.org");
    }

    #[test]
    fn dns_store_from_config_rejects_invalid_extra_records_path() {
        let dir = tempfile::tempdir().unwrap();
        let records_path = dir.path().join("extra-records.json");
        std::fs::write(&records_path, "{not-json").unwrap();

        let err = dns_store_from_config(
            Some(DnsConfigSpec {
                magic_dns: false,
                override_local_dns: false,
                extra_records_path: Some(records_path),
                ..DnsConfigSpec::default()
            }),
            Some("100.64.0.0/10"),
            None,
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("parse dns.extra_records_path"));

        let missing = dir.path().join("missing.json");
        let err = dns_store_from_config(
            Some(DnsConfigSpec {
                magic_dns: false,
                override_local_dns: false,
                extra_records_path: Some(missing),
                ..DnsConfigSpec::default()
            }),
            Some("100.64.0.0/10"),
            None,
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("stat dns.extra_records_path"));

        let err = dns_store_from_config(
            Some(DnsConfigSpec {
                magic_dns: false,
                override_local_dns: false,
                extra_records_path: Some(dir.path().to_path_buf()),
                ..DnsConfigSpec::default()
            }),
            Some("100.64.0.0/10"),
            None,
        )
        .unwrap_err();

        assert!(format!("{err:#}").contains("is a directory"));
    }

    #[tokio::test]
    async fn persistent_wire_runtime_wires_shared_persistent_oidc_state() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();

        let runtime = build_persistent_wire_runtime(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/10",
            Some(oidc_runtime()),
            DerpMap::default(),
        )
        .await
        .unwrap();

        assert!(runtime.oidc.is_some());
        let debug = format!("{:?}", runtime.oidc.as_ref().unwrap());
        assert!(debug.contains("users: Some(\"<configured>\")"));
        assert!(debug.contains("registration_handler: Some(\"<configured>\")"));
        assert_eq!(
            runtime.state.public_control_url.as_deref(),
            Some("https://headscale.example")
        );
        assert!(runtime.state.machines.snapshot().is_empty());
    }

    #[tokio::test]
    async fn native_derp_runtime_attaches_from_embedded_config() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut runtime = build_persistent_wire_runtime(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/10",
            None,
            DerpMap::default(),
        )
        .await
        .unwrap();
        let key_path = dir.path().join("derp").join("server.key");
        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "headscale.example".into(),
            stun_addr: Some("127.0.0.1:3478".parse().unwrap()),
            relay_mode: EmbeddedDerpRelayMode::Native,
            derper_config_path: key_path.clone(),
            ..EmbeddedDerpConfig::default()
        };

        attach_native_derp_runtime(&mut runtime.state, &cfg).unwrap();

        assert!(runtime.state.native_derp.is_some());
        assert!(
            !runtime
                .state
                .native_derp
                .as_ref()
                .unwrap()
                .client_verification_enabled()
        );
        let contents = std::fs::read_to_string(&key_path).unwrap();
        let text = contents.trim();
        assert!(text.starts_with("privkey:"));
        assert_eq!(text.len(), "privkey:".len() + 64);
    }

    #[tokio::test]
    async fn native_derp_runtime_attaches_registry_client_verifier() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut runtime = build_persistent_wire_runtime(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/10",
            None,
            DerpMap::default(),
        )
        .await
        .unwrap();
        let client_key =
            headscale_core::derp::protocol::DerpNodeKeyPair::from_private_key([8u8; 32]).unwrap();
        let allowed_public = client_key.public_key();
        let allowed_hex = hex::encode(allowed_public);
        let rec = headscale_api::tailscale_wire::MachineRecord::new_at(
            chrono::Utc::now(),
            allowed_hex.clone(),
            format!("mkey-{allowed_hex}"),
            "alice".to_string(),
            "derp-client".to_string(),
            "100.64.0.50".parse().unwrap(),
            false,
        );
        runtime.state.machines.upsert(allowed_hex, rec);
        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "headscale.example".into(),
            stun_addr: Some("127.0.0.1:3478".parse().unwrap()),
            relay_mode: EmbeddedDerpRelayMode::Native,
            verify_clients: true,
            derper_config_path: dir.path().join("derp-verify.key"),
            ..EmbeddedDerpConfig::default()
        };

        attach_native_derp_runtime(&mut runtime.state, &cfg).unwrap();

        let native_derp = runtime.state.native_derp.as_ref().unwrap();
        assert!(native_derp.client_verification_enabled());
        assert!(native_derp.admit_client(&allowed_public));
        assert!(!native_derp.admit_client(&[0x42; 32]));
    }

    #[tokio::test]
    async fn native_derp_runtime_rejects_noise_key_reuse() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let mut runtime = build_persistent_wire_runtime(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/10",
            None,
            DerpMap::default(),
        )
        .await
        .unwrap();
        let noise_key = std::fs::read(dir.path().join("noise_static.key")).unwrap();
        assert_eq!(noise_key.len(), 32);
        let key_path = dir.path().join("derp.key");
        std::fs::write(&key_path, format!("privkey:{}", hex::encode(noise_key))).unwrap();
        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "headscale.example".into(),
            stun_addr: Some("127.0.0.1:3478".parse().unwrap()),
            relay_mode: EmbeddedDerpRelayMode::Native,
            derper_config_path: key_path,
            ..EmbeddedDerpConfig::default()
        };

        let err = attach_native_derp_runtime(&mut runtime.state, &cfg).unwrap_err();

        assert!(
            format!("{err:#}").contains("embedded DERP private key must not be the same"),
            "{err:#}"
        );
    }

    #[cfg(feature = "postgres-sqlx")]
    #[tokio::test]
    async fn postgres_runtime_store_configures_oidc_handler_without_live_database() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://headscale:headscale@127.0.0.1/headscale")
            .unwrap();
        let wire_registry = Arc::new(MachineRegistry::new());
        let stores = PersistentRuntimeStores::postgres(&pool, wire_registry.clone());

        let oidc = stores.configure_oidc(
            Some(oidc_runtime()),
            Arc::new(RegistrationCache::new()),
            Arc::new(PolicyStore::new()),
            wire_registry,
            Arc::new(CidrIpAllocator::from_cidr("100.64.0.0/10").unwrap()),
        );

        assert!(oidc.is_some());
        let debug = format!("{:?}", oidc.as_ref().unwrap());
        assert!(debug.contains("users: Some(\"<configured>\")"));
        assert!(debug.contains("registration_handler: Some(\"<configured>\")"));
    }

    #[cfg(feature = "postgres-sqlx")]
    #[tokio::test]
    async fn postgres_persistent_runtime_registers_and_hydrates_against_live_database()
    -> BoxTestResult {
        let Some(schema) = TempPostgresRuntimeSchema::open("runtime_register_hydrate").await?
        else {
            return Ok(());
        };

        let result = async {
            headscale_db::migrate_postgres_foundation(schema.pool()).await?;
            let dir = tempfile::tempdir()?;
            let state_dir = dir.path().join("state");
            let config_path = dir.path().join("postgres-config.yaml");
            std::fs::write(
                &config_path,
                r"
database:
  type: postgres
",
            )?;
            let parsed = crate::config::CliConfig::load(&config_path)?;
            let mut cfg = test_run_server_config(&dir);
            cfg.database = parsed.database;
            cfg.policy = PolicyConfig::database();
            let derp_map = DerpMap::default();
            let dns = Arc::new(DnsStore::new());
            let runtime_config = Arc::new(runtime_config_snapshot(&cfg, &derp_map, dns.as_ref()));

            let runtime = build_postgres_persistent_wire_runtime_with_dns_and_policy(
                schema.pool(),
                &state_dir,
                "https://headscale.example",
                "100.64.0.0/10",
                None,
                "sequential",
                Some(oidc_runtime()),
                derp_map,
                dns,
                &cfg.policy,
                runtime_config,
                None,
            )
            .await?;
            assert!(runtime.oidc.is_some());

            let user = runtime
                .admin_service
                .create_user(TonicRequest::new(CreateUserRequest {
                    name: "alice".into(),
                    display_name: String::new(),
                    email: String::new(),
                    picture_url: String::new(),
                }))
                .await?
                .into_inner()
                .user
                .expect("created user");
            runtime
                .admin_service
                .set_policy(TonicRequest::new(SetPolicyRequest {
                    policy: r#"{"tagOwners":{"tag:server":["alice@"]}}"#.into(),
                }))
                .await?;

            let auth_key = runtime
                .admin_service
                .create_pre_auth_key(TonicRequest::new(CreatePreAuthKeyRequest {
                    user: user.id,
                    reusable: true,
                    ephemeral: false,
                    expiration: None,
                    acl_tags: Vec::new(),
                }))
                .await?
                .into_inner()
                .pre_auth_key
                .expect("preauth key")
                .key;

            let node_key = "a9".repeat(32);
            let machine_key = "b9".repeat(32);
            let register = wire_register_authkey(
                &runtime.state,
                &node_key,
                &machine_key,
                &auth_key,
                "pg-router",
            )
            .await;
            assert!(register.machine_authorized);
            assert!(register.error.is_empty());

            let node_row = headscale_db::headscale_nodes::get_postgres_by_node_key(
                schema.pool(),
                &format!("nodekey:{node_key}"),
            )
            .await?;
            assert_eq!(node_row.hostname, "pg-router");
            assert_eq!(
                node_row.register_method,
                headscale_db::headscale_nodes::REGISTER_METHOD_AUTH_KEY
            );
            assert!(
                headscale_db::policies::get_latest_postgres(schema.pool())
                    .await?
                    .is_some()
            );

            drop(runtime);

            let derp_map = DerpMap::default();
            let dns = Arc::new(DnsStore::new());
            let runtime_config = Arc::new(runtime_config_snapshot(&cfg, &derp_map, dns.as_ref()));
            let restarted = build_postgres_persistent_wire_runtime_with_dns_and_policy(
                schema.pool(),
                &state_dir,
                "https://headscale.example",
                "100.64.0.0/10",
                None,
                "sequential",
                None,
                derp_map,
                dns,
                &cfg.policy,
                runtime_config,
                None,
            )
            .await?;

            let hydrated = restarted
                .state
                .machines
                .get(&node_key)
                .expect("Postgres node hydrated");
            assert_eq!(hydrated.hostname, "pg-router");
            assert_eq!(hydrated.user, "alice");
            assert_eq!(hydrated.register_method, 1);

            let full = wire_full_map(&restarted.state, &node_key, &machine_key).await;
            let self_node = full.node.expect("self node after Postgres restart");
            assert_eq!(self_node.name, "pg-router");
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;

        schema.cleanup().await?;
        result
    }

    #[cfg(feature = "postgres-sqlx")]
    #[tokio::test]
    async fn postgres_persistent_runtime_oidc_register_rekeys_and_projects_live_registry()
    -> BoxTestResult {
        let Some(schema) = TempPostgresRuntimeSchema::open("oidc_rekey_project").await? else {
            return Ok(());
        };

        let result = Box::pin(async {
            headscale_db::migrate_postgres_foundation(schema.pool()).await?;
            let dir = tempfile::tempdir()?;
            let state_dir = dir.path().join("state");
            let config_path = dir.path().join("postgres-config.yaml");
            std::fs::write(
                &config_path,
                r"
database:
  type: postgres
",
            )?;
            let parsed = crate::config::CliConfig::load(&config_path)?;
            let mut cfg = test_run_server_config(&dir);
            cfg.database = parsed.database;
            cfg.policy = PolicyConfig::database();
            let derp_map = DerpMap::default();
            let dns = Arc::new(DnsStore::new());
            let runtime_config = Arc::new(runtime_config_snapshot(&cfg, &derp_map, dns.as_ref()));

            let runtime = build_postgres_persistent_wire_runtime_with_dns_and_policy(
                schema.pool(),
                &state_dir,
                "https://headscale.example",
                "100.64.0.0/10",
                None,
                "sequential",
                Some(oidc_runtime()),
                derp_map,
                dns,
                &cfg.policy,
                runtime_config,
                None,
            )
            .await?;
            assert!(runtime.oidc.is_some());

            let oidc_users = Arc::new(PersistentPostgresUserAdmin::new(schema.pool().clone()));
            let oidc_user = headscale_api::oidc::OidcUserStore::create_or_update_oidc_user(
                oidc_users.as_ref(),
                headscale_api::oidc::OidcUserProfile {
                    name: "alice".into(),
                    display_name: "Alice Example".into(),
                    email: "alice@example.com".into(),
                    provider_identifier: "https://issuer.example/alice-sub".into(),
                    provider: REGISTER_METHOD_OIDC.into(),
                    profile_pic_url: "https://issuer.example/alice.png".into(),
                },
            )
            .await?;
            assert_eq!(oidc_user.provider, REGISTER_METHOD_OIDC);

            runtime
                .admin_service
                .set_policy(TonicRequest::new(SetPolicyRequest {
                    policy: r#"{"tagOwners":{"tag:server":["alice@example.com"]}}"#.into(),
                }))
                .await?;

            let oidc_machines = Arc::new(
                PersistentPostgresMachineAdmin::new(schema.pool().clone())
                    .with_user_admin(oidc_users.clone())
                    .with_wire_registry(runtime.state.machines.clone()),
            );
            let oidc_handler = PersistentPostgresOidcRegistrationHandler::new(
                runtime.state.registration_cache.clone(),
                oidc_machines,
                runtime.state.policy.clone(),
            )
            .with_wire_registry(runtime.state.machines.clone())
            .with_ip_allocator(runtime.state.ip_allocator.clone());

            let first_node_key = "c9".repeat(32);
            let second_node_key = "d9".repeat(32);
            let machine_key = "e9".repeat(32);
            let first_register = wire_register_interactive(
                &runtime.state,
                &first_node_key,
                &machine_key,
                "oidc-router-one",
                &["10.81.0.0/24"],
            )
            .await;
            assert!(!first_register.machine_authorized);
            let first_registration_id = registration_id_from_auth_url(&first_register.auth_url);
            let first_result = oidc_handler
                .complete_oidc_registration(&first_registration_id, &oidc_user, None)
                .await?;
            assert!(first_result.new_node);

            let first_row = headscale_db::headscale_nodes::get_postgres_by_node_key(
                schema.pool(),
                &format!("nodekey:{first_node_key}"),
            )
            .await?;
            assert_eq!(first_row.machine_key, format!("mkey:{machine_key}"));
            assert_eq!(first_row.user_id, Some(i64::try_from(oidc_user.id)?));
            assert_eq!(
                first_row.register_method,
                headscale_db::headscale_nodes::REGISTER_METHOD_OIDC
            );
            assert_eq!(first_row.approved_route_list(), Vec::<String>::new());
            let first_ipv4 = first_row.ipv4.clone();
            let first_wire = runtime
                .state
                .machines
                .get(&first_node_key)
                .expect("first OIDC node projected into live registry");
            assert_eq!(first_wire.hostname, "oidc-router-one");
            assert_eq!(first_wire.user, "alice@example.com");
            assert_eq!(first_wire.register_method, 3);
            assert_eq!(first_wire.available_routes, vec!["10.81.0.0/24"]);

            let second_register = wire_register_interactive(
                &runtime.state,
                &second_node_key,
                &machine_key,
                "oidc-router-two",
                &["10.82.0.0/24"],
            )
            .await;
            assert!(!second_register.machine_authorized);
            let second_registration_id = registration_id_from_auth_url(&second_register.auth_url);
            let second_result = oidc_handler
                .complete_oidc_registration(&second_registration_id, &oidc_user, None)
                .await?;
            assert!(!second_result.new_node);

            assert!(runtime.state.machines.get(&first_node_key).is_none());
            let second_wire = runtime
                .state
                .machines
                .get(&second_node_key)
                .expect("rekeyed OIDC node projected into live registry");
            assert_eq!(second_wire.hostname, "oidc-router-two");
            assert_eq!(second_wire.user, "alice@example.com");
            assert_eq!(second_wire.register_method, 3);
            assert_eq!(second_wire.available_routes, vec!["10.82.0.0/24"]);
            assert_eq!(
                headscale_db::headscale_nodes::list_postgres(schema.pool())
                    .await?
                    .len(),
                1
            );

            let second_row = headscale_db::headscale_nodes::get_postgres_by_machine_key(
                schema.pool(),
                &format!("mkey:{machine_key}"),
            )
            .await?;
            assert_eq!(second_row.node_key, format!("nodekey:{second_node_key}"));
            assert_eq!(second_row.hostname, "oidc-router-two");
            assert_eq!(second_row.user_id, Some(i64::try_from(oidc_user.id)?));
            assert_eq!(second_row.ipv4, first_ipv4);
            assert_eq!(
                second_row.host_info_value()["RoutableIPs"],
                serde_json::json!(["10.82.0.0/24"])
            );

            let full = wire_full_map(&runtime.state, &second_node_key, &machine_key).await;
            let self_node = full.node.expect("self node after OIDC Pg rekey");
            assert_eq!(self_node.name, "oidc-router-two");
            assert_eq!(
                self_node.hostinfo.routable_ips,
                vec!["10.82.0.0/24".to_string()]
            );

            drop(runtime);

            let derp_map = DerpMap::default();
            let dns = Arc::new(DnsStore::new());
            let runtime_config = Arc::new(runtime_config_snapshot(&cfg, &derp_map, dns.as_ref()));
            let restarted = build_postgres_persistent_wire_runtime_with_dns_and_policy(
                schema.pool(),
                &state_dir,
                "https://headscale.example",
                "100.64.0.0/10",
                None,
                "sequential",
                None,
                derp_map,
                dns,
                &cfg.policy,
                runtime_config,
                None,
            )
            .await?;

            let hydrated = restarted
                .state
                .machines
                .get(&second_node_key)
                .expect("rekeyed OIDC Postgres node hydrated");
            assert_eq!(hydrated.hostname, "oidc-router-two");
            assert_eq!(hydrated.user, "alice@example.com");
            assert_eq!(hydrated.register_method, 3);
            assert_eq!(hydrated.available_routes, vec!["10.82.0.0/24"]);
            let restarted_full =
                wire_full_map(&restarted.state, &second_node_key, &machine_key).await;
            let restarted_self = restarted_full
                .node
                .expect("self node after OIDC Pg hydration");
            assert_eq!(restarted_self.name, "oidc-router-two");
            assert_eq!(
                restarted_self.hostinfo.routable_ips,
                vec!["10.82.0.0/24".to_string()]
            );

            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        })
        .await;

        schema.cleanup().await?;
        result
    }

    #[tokio::test]
    async fn persistent_wire_runtime_without_oidc_keeps_web_registration_mode() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();

        let runtime = build_persistent_wire_runtime(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/10",
            None,
            DerpMap::default(),
        )
        .await
        .unwrap();

        assert!(runtime.oidc.is_none());
        assert_eq!(
            runtime.state.public_control_url.as_deref(),
            Some("https://headscale.example")
        );
        assert!(runtime.state.registration_store.is_some());
        assert!(runtime.state.machines.snapshot().is_empty());
    }

    #[tokio::test]
    async fn persistent_wire_runtime_uses_configured_dns_in_map_response() {
        use headscale_api::tailscale_wire::{
            map as wire_map_handlers,
            wire::{DnsRecord, MapResponse},
        };

        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let user = headscale_db::users::create(
            db.pool(),
            headscale_db::users::CreateParams {
                name: "alice".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let a = "2a".repeat(32);
        let b = "2b".repeat(32);
        for (node_key, machine_key, host, ip) in [
            (&a, "3a".repeat(32), "peer-a", "100.64.0.20"),
            (&b, "3b".repeat(32), "peer-b", "100.64.0.21"),
        ] {
            headscale_db::headscale_nodes::create(
                db.pool(),
                headscale_db::headscale_nodes::CreateParams {
                    machine_key: format!("mkey:{machine_key}"),
                    node_key: format!("nodekey:{node_key}"),
                    host_info: serde_json::json!({
                        "Hostname": host,
                        "OS": "linux",
                        "App": "1.80.0",
                    }),
                    ipv4: Some(ip.to_string()),
                    hostname: host.to_string(),
                    given_name: host.to_string(),
                    user_id: Some(user.id),
                    register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        }
        let mut split = std::collections::HashMap::new();
        split.insert(
            "corp.example.org".to_string(),
            vec!["10.0.0.53".to_string()],
        );
        let dns_spec = DnsConfigSpec {
            base_domain: "tail.example.org".to_string(),
            nameservers: vec!["1.1.1.1".to_string()],
            restricted_nameservers: split,
            search_domains: vec!["corp.example.org".to_string()],
            cert_domains: vec!["Node.Tail.Example.Org.".to_string()],
            extra_records: vec![DnsRecord {
                name: "ops.tail.example.org".to_string(),
                record_type: "A".to_string(),
                value: "100.64.0.50".to_string(),
            }],
            ..DnsConfigSpec::default()
        };
        let (dns_store, extra_records_path) =
            dns_store_from_config(Some(dns_spec), Some("100.64.0.0/10"), None).unwrap();
        assert!(extra_records_path.is_none());
        let runtime = build_persistent_wire_runtime_with_dns(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/10",
            None,
            "sequential",
            None,
            DerpMap::default(),
            dns_store,
            Arc::new(RuntimeConfigSnapshot::default()),
        )
        .await
        .unwrap();
        assert!(runtime.state.machines.get(&a).is_some());
        assert!(runtime.state.machines.get(&b).is_some());

        let app = axum::Router::new()
            .route(
                "/machine/:node_key/map",
                axum::routing::post(wire_map_handlers::handle_map),
            )
            .route(
                "/machine/map",
                axum::routing::post(wire_map_handlers::handle_map_flat),
            )
            .with_state(runtime.state);
        let mut req = HttpRequest::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{a}/map"))
            .header("content-type", "application/json")
            .body(Body::from(br#"{"Version":113}"#.to_vec()))
            .unwrap();
        req.extensions_mut()
            .insert(headscale_api::tailscale_wire::noise::NoisePeerMachineKey(
                "3a".repeat(32),
            ));
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let map: MapResponse = serde_json::from_slice(&body).unwrap();
        let dns = map.dns_config.expect("DNSConfig");

        assert_eq!(map.domain, "tail.example.org");
        assert!(
            map.peers
                .iter()
                .any(|peer| peer.name == "peer-b.tail.example.org.")
        );
        assert!(dns.proxied);
        assert_eq!(
            dns.domains,
            vec![
                "tail.example.org".to_string(),
                "corp.example.org".to_string()
            ]
        );
        assert_eq!(dns.resolvers[0].addr, "1.1.1.1");
        assert_eq!(
            dns.routes["corp.example.org"][0].addr,
            "10.0.0.53".to_string()
        );
        assert_eq!(dns.cert_domains, ["node.tail.example.org".to_string()]);
        assert_eq!(dns.extra_records.len(), 1);
        assert!(
            dns.extra_records
                .iter()
                .any(|record| record.name == "ops.tail.example.org")
        );
        assert!(
            !dns.extra_records
                .iter()
                .any(|record| record.name == "peer-b.tail.example.org")
        );
    }

    #[tokio::test]
    async fn persistent_wire_runtime_exposes_authenticated_grpc_gateway() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();

        let runtime = build_persistent_wire_runtime(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/10",
            None,
            DerpMap::default(),
        )
        .await
        .unwrap();
        let token = headscale_db::api_keys::create_with_cost(
            db.pool(),
            headscale_db::api_keys::CreateParams { expiration: None },
            headscale_db::api_keys::BCRYPT_COST_TEST,
        )
        .await
        .unwrap()
        .plaintext;

        let app = production_extra_routes(&runtime);
        let missing_auth = app
            .clone()
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);

        let authed = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/api/v1/health")
                    .header(header::AUTHORIZATION, format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(authed.status(), StatusCode::OK);
        let body = to_bytes(authed.into_body(), usize::MAX).await.unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["databaseConnectivity"], true);
    }

    async fn unix_grpc_channel(path: PathBuf) -> Channel {
        Endpoint::try_from("http://[::]:50051")
            .unwrap()
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = path.clone();
                async move {
                    let stream = UnixStream::connect(path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(stream))
                }
            }))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn local_unix_grpc_listener_serves_health_without_api_key() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("headscale.sock");

        let runtime = build_persistent_wire_runtime(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/10",
            None,
            DerpMap::default(),
        )
        .await
        .unwrap();
        let listener = bind_unix_grpc_listener(&socket_path, 0o700).await.unwrap();
        let handle =
            spawn_local_grpc_listener(listener, socket_path.clone(), runtime.admin_service.clone());

        let channel = unix_grpc_channel(socket_path.clone()).await;
        let response = HeadscaleServiceClient::new(channel)
            .health(HealthRequest {})
            .await
            .unwrap()
            .into_inner();
        assert!(response.database_connectivity);

        handle.abort();
        let _ = handle.await;
    }

    async fn tcp_grpc_channel(addr: SocketAddr) -> Channel {
        Endpoint::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap()
    }

    async fn reflected_service_names(channel: Channel) -> Vec<String> {
        let mut client = ServerReflectionClient::new(channel);
        let request = ServerReflectionRequest {
            host: String::new(),
            message_request: Some(MessageRequest::ListServices(String::new())),
        };
        let mut inbound = client
            .server_reflection_info(TonicRequest::new(tokio_stream::once(request)))
            .await
            .unwrap()
            .into_inner();
        let response = inbound.next().await.unwrap().unwrap();
        match response.message_response.unwrap() {
            MessageResponse::ListServicesResponse(services) => services
                .service
                .into_iter()
                .map(|service| service.name)
                .collect(),
            other => panic!("unexpected reflection response: {other:?}"),
        }
    }

    #[tokio::test]
    async fn remote_grpc_listener_requires_api_key_and_serves_reflection() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let token = headscale_db::api_keys::create_with_cost(
            db.pool(),
            headscale_db::api_keys::CreateParams { expiration: None },
            headscale_db::api_keys::BCRYPT_COST_TEST,
        )
        .await
        .unwrap()
        .plaintext;

        let runtime = build_persistent_wire_runtime(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/10",
            None,
            DerpMap::default(),
        )
        .await
        .unwrap();
        let listener = bind_tcp_grpc_listener("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = spawn_remote_grpc_listener(
            listener,
            addr,
            runtime.admin_service.clone(),
            RemoteGrpcSecurity::Insecure,
        );

        let channel = tcp_grpc_channel(addr).await;
        let err = HeadscaleServiceClient::new(channel.clone())
            .health(HealthRequest {})
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unauthenticated);

        let mut request = TonicRequest::new(HealthRequest {});
        request
            .metadata_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
        let response = HeadscaleServiceClient::new(channel.clone())
            .health(request)
            .await
            .unwrap()
            .into_inner();
        assert!(response.database_connectivity);

        let services = reflected_service_names(channel).await;
        assert_eq!(services, vec!["headscale.v1.HeadscaleService"]);

        handle.abort();
        let _ = handle.await;
    }

    #[test]
    fn remote_grpc_security_tracks_upstream_enablement() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = RunServerConfig {
            listen: "127.0.0.1:0".into(),
            db_path: dir.path().join("db.sqlite"),
            mesh_cidr: "100.64.0.0/10".into(),
            mesh_cidr_v6: None,
            ip_allocation: "sequential".into(),
            server_url: Some("https://headscale.example".into()),
            state_dir: dir.path().join("state"),
            noise_private_key_path: None,
            https_listen: None,
            metrics_listen_addr: Some("127.0.0.1:9090".into()),
            tls_hostname: None,
            unix_socket: dir.path().join("state/headscale.sock"),
            unix_socket_permission: 0o700,
            grpc_listen_addr: ":50443".into(),
            grpc_allow_insecure: false,
            trusted_proxies: Vec::new(),
            disable_check_updates: false,
            tls: TlsRuntimeConfig::default(),
            oidc: OidcConfig::default(),
            node_expiry: Duration::default(),
            node_routes_ha_probe_interval: Duration::from_secs(10),
            node_routes_ha_probe_timeout: Duration::from_secs(5),
            embedded_derp: EmbeddedDerpConfig::default(),
            derp: None,
            database: None,
            dns: None,
            policy: PolicyConfig::default(),
            taildrop_enabled: true,
            logtail_enabled: false,
            auto_update_enabled: false,
            logging: LoggingConfig::default(),
            cli: AdminCliConfig::default(),
            tuning: TuningConfig::default(),
            ephemeral_node_inactivity_timeout: Duration::from_secs(120),
        };
        let sans = SanConfig::with_hostname("headscale.example");
        let tls_source = tls_material_source(&cfg, &sans).unwrap();

        assert!(remote_grpc_security(&cfg, &tls_source).unwrap().is_none());
        cfg.grpc_allow_insecure = true;
        assert!(matches!(
            remote_grpc_security(&cfg, &tls_source).unwrap(),
            Some(RemoteGrpcSecurity::Insecure)
        ));
        cfg.grpc_allow_insecure = false;
        cfg.https_listen = Some("127.0.0.1:0".into());
        let tls_source = tls_material_source(&cfg, &sans).unwrap();
        assert!(matches!(
            remote_grpc_security(&cfg, &tls_source).unwrap(),
            Some(RemoteGrpcSecurity::Tls(_))
        ));
    }

    #[test]
    fn remote_grpc_security_uses_manual_tls_without_https_listener() {
        let dir = tempfile::tempdir().unwrap();
        let material =
            tls::load_or_generate(dir.path().join("manual"), &SanConfig::with_hostname("test"))
                .unwrap();
        let cfg = RunServerConfig {
            listen: "127.0.0.1:0".into(),
            db_path: dir.path().join("db.sqlite"),
            mesh_cidr: "100.64.0.0/10".into(),
            mesh_cidr_v6: None,
            ip_allocation: "sequential".into(),
            server_url: Some("https://headscale.example".into()),
            state_dir: dir.path().join("state"),
            noise_private_key_path: None,
            https_listen: None,
            metrics_listen_addr: Some("127.0.0.1:9090".into()),
            tls_hostname: None,
            unix_socket: dir.path().join("state/headscale.sock"),
            unix_socket_permission: 0o700,
            grpc_listen_addr: ":50443".into(),
            grpc_allow_insecure: false,
            trusted_proxies: Vec::new(),
            disable_check_updates: false,
            tls: TlsRuntimeConfig {
                cert_path: Some(material.cert_path.clone()),
                key_path: Some(material.key_path.clone()),
                ..TlsRuntimeConfig::default()
            },
            oidc: OidcConfig::default(),
            node_expiry: Duration::default(),
            node_routes_ha_probe_interval: Duration::from_secs(10),
            node_routes_ha_probe_timeout: Duration::from_secs(5),
            embedded_derp: EmbeddedDerpConfig::default(),
            derp: None,
            database: None,
            dns: None,
            policy: PolicyConfig::default(),
            taildrop_enabled: true,
            logtail_enabled: false,
            auto_update_enabled: false,
            logging: LoggingConfig::default(),
            cli: AdminCliConfig::default(),
            tuning: TuningConfig::default(),
            ephemeral_node_inactivity_timeout: Duration::from_secs(120),
        };
        let sans = SanConfig::with_hostname("headscale.example");
        let tls_source = tls_material_source(&cfg, &sans).unwrap();

        assert_eq!(remote_grpc_status(&cfg), ":50443 (TLS)");
        assert!(matches!(
            remote_grpc_security(&cfg, &tls_source).unwrap(),
            Some(RemoteGrpcSecurity::Tls(_))
        ));
        match tls_source {
            TlsMaterialSource::Files {
                cert_path,
                key_path,
            } => {
                assert_eq!(cert_path, material.cert_path);
                assert_eq!(key_path, material.key_path);
            }
            TlsMaterialSource::SelfSigned { .. }
            | TlsMaterialSource::AcmeAutocertCache { .. }
            | TlsMaterialSource::AcmeAutocertCacheWithHttp01Bootstrap { .. }
            | TlsMaterialSource::AcmeAutocertCacheWithTlsAlpn { .. } => {
                panic!("expected manual TLS source")
            }
        }
    }

    #[test]
    fn public_listener_plan_uses_plain_listen_without_tls() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_run_server_config(&dir);

        assert_eq!(
            public_listener_plan(&cfg).unwrap(),
            PublicListenerPlan {
                http_addr: Some("127.0.0.1:8080".parse().unwrap()),
                https_addr: None,
            }
        );
    }

    #[test]
    fn public_listener_plan_uses_listen_for_manual_tls_without_https_listen() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.tls = TlsRuntimeConfig {
            cert_path: Some(dir.path().join("tls.crt")),
            key_path: Some(dir.path().join("tls.key")),
            ..TlsRuntimeConfig::default()
        };

        assert_eq!(
            public_listener_plan(&cfg).unwrap(),
            PublicListenerPlan {
                http_addr: None,
                https_addr: Some("127.0.0.1:8080".parse().unwrap()),
            }
        );
    }

    #[test]
    fn public_listener_plan_preserves_explicit_dual_listener() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.https_listen = Some("127.0.0.1:8443".into());
        cfg.tls = TlsRuntimeConfig {
            cert_path: Some(dir.path().join("tls.crt")),
            key_path: Some(dir.path().join("tls.key")),
            ..TlsRuntimeConfig::default()
        };

        assert_eq!(
            public_listener_plan(&cfg).unwrap(),
            PublicListenerPlan {
                http_addr: Some("127.0.0.1:8080".parse().unwrap()),
                https_addr: Some("127.0.0.1:8443".parse().unwrap()),
            }
        );
    }

    #[test]
    fn acme_runtime_plan_resolves_http01_challenge_listener() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.tls.letsencrypt_hostname = Some("headscale.example".into());
        cfg.tls.letsencrypt_challenge_type = Some("HTTP-01".into());
        cfg.tls.letsencrypt_listen = Some(":http".into());

        let public_listeners = public_listener_plan(&cfg).unwrap();
        let plan = cfg
            .tls
            .acme_runtime_plan(public_listeners)
            .unwrap()
            .expect("ACME plan");

        assert_eq!(plan.hostname, "headscale.example");
        assert_eq!(plan.acme_url, DEFAULT_ACME_URL);
        assert_eq!(plan.cache_dir, PathBuf::from(DEFAULT_LETSENCRYPT_CACHE_DIR));
        assert_eq!(
            plan.challenge_listener,
            AcmeChallengeListener::Http01 {
                listen: ":http".into(),
                addr: "0.0.0.0:80".parse().unwrap(),
            }
        );
    }

    #[test]
    fn acme_runtime_plan_uses_public_tls_listener_for_tls_alpn01() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.tls.letsencrypt_hostname = Some("headscale.example".into());
        cfg.tls.letsencrypt_challenge_type = Some("TLS-ALPN-01".into());

        let public_listeners = public_listener_plan(&cfg).unwrap();
        let plan = cfg
            .tls
            .acme_runtime_plan(public_listeners)
            .unwrap()
            .expect("ACME plan");

        assert_eq!(
            plan.challenge_listener,
            AcmeChallengeListener::TlsAlpn01 {
                addr: "127.0.0.1:8080".parse().unwrap(),
            }
        );
    }

    #[tokio::test]
    async fn run_server_http01_acme_issues_through_production_challenge_listener() {
        let dir = tempfile::tempdir().unwrap();
        let public_tls_addr = unused_loopback_addr();
        let challenge_addr = unused_loopback_addr();
        let cache_dir = dir.path().join("acme-cache");
        let acme_server =
            LocalAcmeServer::spawn_http01_listener(challenge_addr, LOCAL_ACME_HOSTNAME).await;
        let mut cfg = test_run_server_config(&dir);
        cfg.listen = public_tls_addr.to_string();
        cfg.grpc_listen_addr = "127.0.0.1:0".into();
        cfg.metrics_listen_addr = None;
        cfg.server_url = Some(format!("https://{LOCAL_ACME_HOSTNAME}"));
        cfg.disable_check_updates = true;
        cfg.tls = TlsRuntimeConfig {
            acme_url: Some(acme_server.directory_url.clone()),
            acme_email: Some("ops@example.com".into()),
            acme_ca_root_path: Some(acme_server.ca_root_path.clone()),
            letsencrypt_hostname: Some(LOCAL_ACME_HOSTNAME.into()),
            letsencrypt_cache_dir: Some(cache_dir.clone()),
            letsencrypt_listen: Some(challenge_addr.to_string()),
            letsencrypt_challenge_type: Some("HTTP-01".into()),
            ..TlsRuntimeConfig::default()
        };

        tokio::task::LocalSet::new()
            .run_until(async move {
                let cache_path = cache_dir.join(LOCAL_ACME_HOSTNAME);
                let mut server_task = tokio::task::spawn_local(run_server(cfg));
                let wait_for_issuance = async {
                    let client = reqwest::Client::builder()
                        .no_proxy()
                        .danger_accept_invalid_certs(true)
                        .resolve(LOCAL_ACME_HOSTNAME, public_tls_addr)
                        .timeout(Duration::from_secs(10))
                        .build().unwrap();
                    loop {
                        if acme_server.finalized() && cache_path.exists() {
                            break;
                        }
                        // Native autocert starts only on an authorized hello.
                        let _ = client.get(format!("https://{LOCAL_ACME_HOSTNAME}:{}/health", public_tls_addr.port())).send().await;
                        sleep(Duration::from_millis(25)).await;
                    }
                };
                tokio::select! {
                    outcome = &mut server_task => {
                        panic!("headscale server exited before HTTP-01 issuance completed: {outcome:?}");
                    }
                    waited = timeout(Duration::from_secs(15), wait_for_issuance) => {
                        waited.expect("HTTP-01 issuance through production challenge listener timed out");
                    }
                }

                server_task.abort();
                let _ = server_task.await;
                assert!(acme_server.challenge_seen());
                assert!(acme_server.finalized());
                let material =
                    tls::load_from_autocert_cache(&cache_dir, LOCAL_ACME_HOSTNAME).unwrap();
                assert!(material.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
            })
            .await;
    }

    #[tokio::test]
    async fn run_server_tls_alpn_acme_issues_through_production_tls_listener() {
        let dir = tempfile::tempdir().unwrap();
        let public_tls_addr = unused_loopback_addr();
        let cache_dir = dir.path().join("acme-cache");
        let acme_server = LocalAcmeServer::spawn_tls_alpn_listener(public_tls_addr).await;
        let mut cfg = test_run_server_config(&dir);
        cfg.listen = public_tls_addr.to_string();
        cfg.grpc_listen_addr = unused_loopback_addr().to_string();
        cfg.metrics_listen_addr = None;
        cfg.server_url = Some(format!("https://{LOCAL_ACME_HOSTNAME}"));
        cfg.disable_check_updates = true;
        cfg.tls = TlsRuntimeConfig {
            acme_url: Some(acme_server.directory_url.clone()),
            acme_email: Some("ops@example.com".into()),
            acme_ca_root_path: Some(acme_server.ca_root_path.clone()),
            letsencrypt_hostname: Some(LOCAL_ACME_HOSTNAME.into()),
            letsencrypt_cache_dir: Some(cache_dir.clone()),
            letsencrypt_challenge_type: Some("TLS-ALPN-01".into()),
            ..TlsRuntimeConfig::default()
        };

        tokio::task::LocalSet::new()
            .run_until(async move {
                let cache_path = cache_dir.join(LOCAL_ACME_HOSTNAME);
                let mut server_task = tokio::task::spawn_local(run_server(cfg));
                let wait_for_issuance = async {
                    let client = reqwest::Client::builder()
                        .no_proxy()
                        .danger_accept_invalid_certs(true)
                        .resolve(LOCAL_ACME_HOSTNAME, public_tls_addr)
                        .timeout(Duration::from_secs(10))
                        .build().unwrap();
                    loop {
                        if acme_server.finalized() && cache_path.exists() {
                            break;
                        }
                        let _ = client.get(format!("https://{LOCAL_ACME_HOSTNAME}:{}/health", public_tls_addr.port())).send().await;
                        sleep(Duration::from_millis(25)).await;
                    }
                };
                tokio::select! {
                    outcome = &mut server_task => {
                        panic!("headscale server exited before TLS-ALPN issuance completed: {outcome:?}");
                    }
                    waited = timeout(Duration::from_secs(15), wait_for_issuance) => {
                        waited.expect("TLS-ALPN issuance through production TLS listener timed out");
                    }
                }

                server_task.abort();
                let _ = server_task.await;
                assert!(acme_server.challenge_seen());
                assert!(acme_server.finalized());
                let material =
                    tls::load_from_autocert_cache_with_tls_alpn(&cache_dir, LOCAL_ACME_HOSTNAME)
                        .unwrap();
                assert!(material.cert_pem.contains("-----BEGIN CERTIFICATE-----"));
                assert!(material.acme_tls_alpn_resolver.is_some());
            })
            .await;
    }

    #[test]
    fn runtime_config_allows_http01_acme_cache_mode() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.tls.letsencrypt_hostname = Some("headscale.example".into());
        cfg.tls.letsencrypt_cache_dir = Some(dir.path().join("acme-cache"));
        cfg.tls.letsencrypt_challenge_type = Some("HTTP-01".into());

        validate_supported_runtime_config(&cfg).unwrap();
    }

    #[test]
    fn tls_material_source_uses_go_autocert_cache_for_http01_acme() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.tls.letsencrypt_hostname = Some("headscale.example".into());
        cfg.tls.letsencrypt_cache_dir = Some(dir.path().join("acme-cache"));
        cfg.tls.letsencrypt_challenge_type = Some("HTTP-01".into());
        let sans = SanConfig::with_hostname("headscale.example");

        let source = tls_material_source(&cfg, &sans).unwrap();

        match source {
            TlsMaterialSource::AcmeAutocertCacheWithHttp01Bootstrap {
                cache_dir,
                hostname,
            } => {
                assert_eq!(cache_dir, dir.path().join("acme-cache"));
                assert_eq!(hostname, "headscale.example");
            }
            other => panic!("expected ACME HTTP-01 bootstrap cache source, got {other:?}"),
        }
    }

    #[test]
    fn remote_grpc_reuses_http01_acme_cached_tls_material() {
        let dir = tempfile::tempdir().unwrap();
        let cache_dir = dir.path().join("acme-cache");
        std::fs::create_dir_all(&cache_dir).unwrap();
        let generated = tls::load_or_generate(
            dir.path().join("generated"),
            &SanConfig::with_hostname("headscale.example"),
        )
        .unwrap();
        std::fs::write(
            cache_dir.join("headscale.example"),
            format!("{}{}", generated.key_pem, generated.cert_pem),
        )
        .unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.tls.letsencrypt_hostname = Some("headscale.example".into());
        cfg.tls.letsencrypt_cache_dir = Some(cache_dir);
        cfg.tls.letsencrypt_challenge_type = Some("HTTP-01".into());
        let sans = SanConfig::with_hostname("headscale.example");
        let tls_source = tls_material_source(&cfg, &sans).unwrap();

        assert_eq!(remote_grpc_status(&cfg), ":50443 (TLS)");
        assert!(matches!(
            remote_grpc_security(&cfg, &tls_source).unwrap(),
            Some(RemoteGrpcSecurity::Tls(_))
        ));
    }

    #[test]
    fn runtime_config_allows_tls_alpn_acme_cache_mode() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.tls.letsencrypt_hostname = Some("headscale.example".into());
        cfg.tls.letsencrypt_cache_dir = Some(dir.path().join("acme-cache"));
        cfg.tls.letsencrypt_challenge_type = Some("TLS-ALPN-01".into());

        validate_supported_runtime_config(&cfg).unwrap();
    }

    #[test]
    fn tls_material_source_uses_tls_alpn_acme_cache_with_resolver() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.tls.letsencrypt_hostname = Some("headscale.example".into());
        cfg.tls.letsencrypt_cache_dir = Some(dir.path().join("acme-cache"));
        cfg.tls.letsencrypt_challenge_type = Some("TLS-ALPN-01".into());
        let sans = SanConfig::with_hostname("headscale.example");

        let source = tls_material_source(&cfg, &sans).unwrap();

        match source {
            TlsMaterialSource::AcmeAutocertCacheWithTlsAlpn {
                cache_dir,
                hostname,
            } => {
                assert_eq!(cache_dir, dir.path().join("acme-cache"));
                assert_eq!(hostname, "headscale.example");
            }
            other => panic!("expected ACME TLS-ALPN autocert cache source, got {other:?}"),
        }
    }

    #[cfg(not(feature = "postgres-sqlx"))]
    #[test]
    fn runtime_config_rejects_unsupported_postgres_before_opening_sqlite() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            "
server_url: \"https://headscale.example\"
database:
  type: postgres
",
        )
        .unwrap();
        let parsed = crate::config::CliConfig::load(&config_path).unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.database = parsed.database;

        let err = validate_supported_runtime_config(&cfg).unwrap_err();

        assert!(format!("{err:#}").contains("headscale-rs server currently supports SQLite only"));
    }

    #[cfg(feature = "postgres-sqlx")]
    #[test]
    fn runtime_config_accepts_postgres_when_feature_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            r#"
server_url: "https://headscale.example"
database:
  type: postgres
"#,
        )
        .unwrap();
        let parsed = crate::config::CliConfig::load(&config_path).unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.database = parsed.database;

        validate_supported_runtime_config(&cfg).unwrap();
    }

    #[test]
    fn runtime_config_rejects_unsafe_server_url_dns_base_domain() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.server_url = Some("https://login.tail.example.org".into());
        cfg.dns = Some(DnsConfigSpec {
            magic_dns: true,
            override_local_dns: false,
            base_domain: "tail.example.org".into(),
            ..DnsConfigSpec::default()
        });

        let err = validate_supported_runtime_config(&cfg).unwrap_err();

        assert!(format!("{err:#}").contains(
            "server_url cannot be part of base_domain in a way that could make the DERP and headscale server unreachable"
        ));
    }

    #[test]
    fn socket_addr_parser_accepts_upstream_leading_colon_listens() {
        assert_eq!(
            parse_socket_addr(":50443", "grpc_listen_addr").unwrap(),
            "0.0.0.0:50443".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn acme_http01_listener_parser_accepts_upstream_http_service_name() {
        assert_eq!(
            parse_acme_http01_listen_addr(":http").unwrap(),
            "0.0.0.0:80".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn optional_socket_addr_treats_empty_metrics_addr_as_disabled() {
        assert_eq!(
            optional_socket_addr(Some("127.0.0.1:9090"), "metrics_listen_addr").unwrap(),
            Some("127.0.0.1:9090".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(
            optional_socket_addr(Some(""), "metrics_listen_addr").unwrap(),
            None
        );
        assert_eq!(
            optional_socket_addr(Some("   "), "metrics_listen_addr").unwrap(),
            None
        );
        assert_eq!(
            optional_socket_addr(None, "metrics_listen_addr").unwrap(),
            None
        );
    }

    #[test]
    fn runtime_config_snapshot_reflects_server_tls_and_dns_config() {
        let dir = tempfile::tempdir().unwrap();
        let dns = Arc::new(
            DnsStore::try_from_spec(DnsConfigSpec {
                magic_dns: true,
                base_domain: "tail.example".to_string(),
                override_local_dns: false,
                nameservers: vec!["1.1.1.1".to_string()],
                cert_domains: vec!["Node.Tail.Example.".to_string()],
                ..DnsConfigSpec::default()
            })
            .unwrap(),
        );
        let cfg = RunServerConfig {
            listen: "0.0.0.0:443".into(),
            db_path: dir.path().join("db.sqlite"),
            mesh_cidr: "100.100.0.0/16".into(),
            mesh_cidr_v6: Some("fd7a:115c:a1e0::/48".into()),
            ip_allocation: "random".into(),
            server_url: Some("https://headscale.example".into()),
            state_dir: dir.path().join("state"),
            noise_private_key_path: None,
            https_listen: None,
            metrics_listen_addr: Some("127.0.0.1:9090".into()),
            tls_hostname: None,
            unix_socket: dir.path().join("headscale.sock"),
            unix_socket_permission: 0o760,
            grpc_listen_addr: "127.0.0.1:50443".into(),
            grpc_allow_insecure: true,
            trusted_proxies: Vec::new(),
            disable_check_updates: false,
            tls: TlsRuntimeConfig {
                acme_url: Some("https://acme.example/directory".into()),
                acme_email: Some("ops@example.com".into()),
                acme_ca_root_path: None,
                letsencrypt_hostname: Some("headscale.example".into()),
                letsencrypt_cache_dir: Some(dir.path().join("cache")),
                letsencrypt_listen: Some(":http".into()),
                letsencrypt_challenge_type: Some("TLS-ALPN-01".into()),
                cert_path: Some(dir.path().join("tls.crt")),
                key_path: Some(dir.path().join("tls.key")),
            },
            oidc: OidcConfig::default(),
            node_expiry: Duration::from_secs(90 * 24 * 60 * 60),
            node_routes_ha_probe_interval: Duration::from_secs(15),
            node_routes_ha_probe_timeout: Duration::from_secs(4),
            embedded_derp: EmbeddedDerpConfig::default(),
            derp: None,
            database: None,
            dns: None,
            policy: PolicyConfig::database(),
            taildrop_enabled: false,
            logtail_enabled: false,
            auto_update_enabled: false,
            logging: LoggingConfig::default(),
            cli: AdminCliConfig::default(),
            tuning: TuningConfig::default(),
            ephemeral_node_inactivity_timeout: Duration::from_secs(180),
        };

        let snapshot = runtime_config_snapshot(&cfg, &DerpMap::default(), dns.as_ref());

        assert_eq!(snapshot.server_url, "https://headscale.example");
        assert_eq!(snapshot.addr, "0.0.0.0:443");
        assert_eq!(snapshot.metrics_addr, "127.0.0.1:9090");
        assert_eq!(snapshot.grpc_addr, "127.0.0.1:50443");
        assert!(snapshot.grpc_allow_insecure);
        assert_eq!(snapshot.prefix_v4.as_deref(), Some("100.100.0.0/16"));
        assert_eq!(snapshot.prefix_v6.as_deref(), Some("fd7a:115c:a1e0::/48"));
        assert_eq!(snapshot.ip_allocation, "random");
        assert_eq!(
            snapshot.tls.cert_path,
            dir.path().join("tls.crt").display().to_string()
        );
        assert_eq!(
            snapshot.tls.key_path,
            dir.path().join("tls.key").display().to_string()
        );
        assert_eq!(snapshot.tls.lets_encrypt.hostname, "headscale.example");
        assert_eq!(
            snapshot.tls.lets_encrypt.cache_dir,
            dir.path().join("cache").display().to_string()
        );
        assert_eq!(snapshot.tls.lets_encrypt.listen, ":http");
        assert_eq!(snapshot.tls.lets_encrypt.challenge_type, "TLS-ALPN-01");
        assert_eq!(snapshot.acme_url, "https://acme.example/directory");
        assert_eq!(snapshot.acme_email, "ops@example.com");
        assert!(snapshot.dns_config.magic_dns);
        assert_eq!(snapshot.dns_config.base_domain, "tail.example");
        assert!(!snapshot.dns_config.override_local_dns);
        assert_eq!(
            snapshot.tailcfg_dns_config["CertDomains"],
            serde_json::json!(["node.tail.example"])
        );
        assert!(
            snapshot.tailcfg_dns_config["CertDomains"]
                .as_array()
                .unwrap()
                .iter()
                .all(|domain| domain.as_str() != Some("headscale.example")),
            "TLS/HTTPS hostnames must not be synthesized into DNSConfig.CertDomains"
        );
        assert_eq!(
            snapshot.node.expiry,
            i64::try_from(Duration::from_secs(90 * 24 * 60 * 60).as_nanos()).unwrap()
        );
        assert_eq!(
            snapshot.node.ephemeral.inactivity_timeout,
            i64::try_from(Duration::from_secs(180).as_nanos()).unwrap()
        );
        assert_eq!(
            snapshot.node.routes.ha.probe_interval,
            i64::try_from(Duration::from_secs(15).as_nanos()).unwrap()
        );
        assert_eq!(
            snapshot.node.routes.ha.probe_timeout,
            i64::try_from(Duration::from_secs(4).as_nanos()).unwrap()
        );
        assert_eq!(snapshot.oidc.expiry, 0);
        assert!(!snapshot.taildrop.enabled);
        assert_eq!(snapshot.unix_socket_permission, 0o760);
    }

    #[test]
    fn runtime_config_snapshot_uses_upstream_acme_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_run_server_config(&dir);
        let dns = DnsStore::new();

        let snapshot = runtime_config_snapshot(&cfg, &DerpMap::default(), &dns);

        assert_eq!(snapshot.acme_url, DEFAULT_ACME_URL);
        assert_eq!(
            snapshot.tls.lets_encrypt.cache_dir,
            DEFAULT_LETSENCRYPT_CACHE_DIR
        );
        assert_eq!(snapshot.tls.lets_encrypt.listen, DEFAULT_LETSENCRYPT_LISTEN);
        assert_eq!(
            snapshot.tls.lets_encrypt.challenge_type,
            DEFAULT_LETSENCRYPT_CHALLENGE_TYPE
        );
    }

    #[test]
    fn runtime_config_snapshot_projects_upstream_derp_config_and_map() {
        let dir = tempfile::tempdir().unwrap();
        let derp_private_key = dir.path().join("derp_server_private.key");
        let derp_path = dir.path().join("derp-map.yaml");
        let mut cfg = test_run_server_config(&dir);
        cfg.derp = Some(DerpConfig {
            server: crate::derp_config::UpstreamDerpServerConfig {
                enabled: true,
                region_id: 777,
                region_code: "hs".into(),
                region_name: "Headscale DERP".into(),
                verify_clients: false,
                stun_listen_addr: Some("127.0.0.1:3478".parse().unwrap()),
                private_key_path: derp_private_key.clone(),
                automatically_add_embedded_derp_region: false,
                ipv4: Some("203.0.113.7".into()),
                ipv6: Some("2001:db8::7".into()),
            },
            urls: vec!["https://derp.example/map.json".into()],
            paths: vec![derp_path.clone()],
            auto_update_enabled: true,
            update_frequency: 600,
        });
        cfg.embedded_derp = EmbeddedDerpConfig {
            enabled: true,
            region_id: 900,
            region_code: "embedded".into(),
            region_name: "Embedded DERP".into(),
            host_name: "embedded.example.com".into(),
            ..EmbeddedDerpConfig::default()
        };
        let derp_map = DerpMap {
            regions: std::collections::HashMap::from([(
                777,
                DerpRegion {
                    region_id: 777,
                    region_code: "hs".into(),
                    region_name: "Headscale DERP".into(),
                    latitude: 0.0,
                    longitude: 0.0,
                    avoid: false,
                    no_measure_no_home: false,
                    nodes: vec![DerpRegionNode {
                        name: "777a".into(),
                        region_id: 777,
                        host_name: "derp.example.com".into(),
                        cert_name: String::new(),
                        ipv4: "203.0.113.7".into(),
                        ipv6: "2001:db8::7".into(),
                        derp_port: 8443,
                        stun_port: 3478,
                        stun_only: false,
                        insecure_for_tests: false,
                        stun_test_ip: String::new(),
                        can_port80: true,
                    }],
                },
            )]),
            omit_default_regions: true,
            ..DerpMap::default()
        };
        let dns = DnsStore::new();

        let snapshot = runtime_config_snapshot(&cfg, &derp_map, &dns);

        assert!(snapshot.derp.server_enabled);
        assert!(!snapshot.derp.automatically_add_embedded_derp_region);
        assert_eq!(snapshot.derp.server_region_id, 777);
        assert_eq!(snapshot.derp.server_region_code, "hs");
        assert_eq!(snapshot.derp.server_region_name, "Headscale DERP");
        assert_eq!(
            snapshot.derp.server_private_key_path,
            derp_private_key.display().to_string()
        );
        assert!(!snapshot.derp.server_verify_clients);
        assert_eq!(snapshot.derp.stun_addr, "127.0.0.1:3478");
        assert_eq!(snapshot.derp.urls, ["https://derp.example/map.json"]);
        assert_eq!(snapshot.derp.paths, [derp_path.display().to_string()]);
        assert!(snapshot.derp.auto_update);
        assert_eq!(snapshot.derp.update_frequency, 600_000_000_000);
        assert_eq!(snapshot.derp.ipv4, "203.0.113.7");
        assert_eq!(snapshot.derp.ipv6, "2001:db8::7");
        assert_eq!(snapshot.derp.derp_map["Regions"]["777"]["RegionCode"], "hs");
        assert_eq!(
            snapshot.derp.derp_map["Regions"]["777"]["Nodes"][0]["DERPPort"],
            8443
        );
        assert_eq!(snapshot.derp.derp_map["omitDefaultRegions"], true);
    }

    #[test]
    fn runtime_config_snapshot_projects_current_upstream_schema_fields() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
prefixes:
  v4: "100.64.0.0/10"
dns:
  magic_dns: false
  override_local_dns: false
trusted_proxies:
  - "127.0.0.1/32"
disable_check_updates: true

logtail:
  enabled: true

auto_update:
  enabled: true

log:
  level: debug
  format: json

cli:
  address: "headscale.example:50443"
  api_key: "hskey-api-debug-projection-secret"
  insecure: true
  timeout: 12

tuning:
  notifier_send_timeout: 900ms
  batch_change_delay: 700ms
  node_mapsession_buffered_chan_size: 42
  batcher_workers: 2
  register_cache_expiration: 5m
  register_cache_max_entries: 2048
  node_store_batch_size: 128
  node_store_batch_timeout: 250ms

database:
  type: sqlite
  debug: true
  gorm:
    prepare_stmt: true
    parameterized_queries: true
    skip_err_record_not_found: true
    slow_threshold: 1000
  sqlite:
    path: "data/db.sqlite"
    write_ahead_log: false
    wal_autocheckpoint: 250
  postgres:
    host: localhost
    port: 5432
    name: headscale
    user: headscale
    pass: secret
    ssl: false
    max_open_conns: 11
    max_idle_conns: 7
    conn_max_idle_time_secs: 120

policy:
  mode: database
  path: "ignored-policy.hujson"
"#,
        )
        .unwrap();
        let parsed = crate::config::CliConfig::load(&config_path).unwrap();
        parsed.validate_for_configtest().unwrap();

        let mut cfg = test_run_server_config(&dir);
        cfg.db_path = parsed.server.as_ref().unwrap().db_path.clone();
        cfg.trusted_proxies = parsed.trusted_proxies.clone();
        cfg.disable_check_updates = parsed.disable_check_updates;
        cfg.database = parsed.database;
        cfg.logtail_enabled = parsed.logtail.enabled;
        cfg.auto_update_enabled = parsed.auto_update.enabled;
        cfg.logging = parsed.logging.unwrap_or_default();
        cfg.cli = parsed.cli.unwrap_or_default();
        cfg.policy = parsed.policy;
        cfg.tuning = parsed.tuning;

        let dns = DnsStore::new();
        let snapshot = runtime_config_snapshot(&cfg, &DerpMap::default(), &dns);

        assert_eq!(snapshot.trusted_proxies, ["127.0.0.1/32"]);
        assert!(snapshot.disable_update_check);
        assert_eq!(snapshot.log.level, "debug");
        assert_eq!(snapshot.log.format, "json");
        assert_eq!(snapshot.cli.address, "headscale.example:50443");
        assert_eq!(snapshot.cli.api_key, "hskey-api-debug-projection-secret");
        assert!(snapshot.cli.insecure);
        assert_eq!(snapshot.cli.timeout, 12);
        assert!(snapshot.log_tail.enabled);
        assert!(snapshot.auto_update.enabled);
        assert_eq!(snapshot.policy.mode, "database");
        assert_eq!(snapshot.policy.path, "ignored-policy.hujson");
        assert_eq!(snapshot.database.database_type, "sqlite3");
        assert!(snapshot.database.debug);
        assert!(snapshot.database.gorm.debug);
        assert_eq!(snapshot.database.gorm.slow_threshold, 1_000_000_000);
        assert!(snapshot.database.gorm.skip_err_record_not_found);
        assert!(snapshot.database.gorm.parameterized_queries);
        assert!(snapshot.database.gorm.prepare_stmt);
        assert_eq!(
            snapshot.database.sqlite.path,
            dir.path().join("data/db.sqlite").display().to_string()
        );
        assert!(!snapshot.database.sqlite.write_ahead_log);
        assert_eq!(snapshot.database.sqlite.wal_auto_check_point, 250);
        assert_eq!(snapshot.database.postgres.host, "localhost");
        assert_eq!(snapshot.database.postgres.port, 5432);
        assert_eq!(snapshot.database.postgres.name, "headscale");
        assert_eq!(snapshot.database.postgres.user, "headscale");
        assert_eq!(snapshot.database.postgres.ssl, "false");
        assert_eq!(snapshot.database.postgres.max_open_connections, 11);
        assert_eq!(snapshot.database.postgres.max_idle_connections, 7);
        assert_eq!(snapshot.database.postgres.conn_max_idle_time_secs, 120);
        assert_eq!(snapshot.tuning.notifier_send_timeout, 900_000_000);
        assert_eq!(snapshot.tuning.batch_change_delay, 700_000_000);
        assert_eq!(snapshot.tuning.node_map_session_buffered_chan_size, 42);
        assert_eq!(snapshot.tuning.batcher_workers, 2);
        assert_eq!(snapshot.tuning.register_cache_expiration, 300_000_000_000);
        assert_eq!(snapshot.tuning.register_cache_max_entries, 2048);
        assert_eq!(snapshot.tuning.node_store_batch_size, 128);
        assert_eq!(snapshot.tuning.node_store_batch_timeout, 250_000_000);
    }

    #[test]
    fn registration_cache_uses_runtime_tuning_with_upstream_defaults() {
        let default_cache =
            registration_cache_from_runtime_config(&RuntimeConfigSnapshot::default());
        assert_eq!(default_cache.expiration(), REGISTRATION_CACHE_EXPIRATION);
        assert_eq!(default_cache.max_entries(), REGISTRATION_CACHE_MAX_ENTRIES);

        let mut tuned = RuntimeConfigSnapshot::default();
        tuned.tuning.register_cache_expiration = 5 * 60 * 1_000_000_000;
        tuned.tuning.register_cache_max_entries = 7;
        let tuned_cache = registration_cache_from_runtime_config(&tuned);
        assert_eq!(tuned_cache.expiration(), Duration::from_secs(5 * 60));
        assert_eq!(tuned_cache.max_entries(), 7);
    }

    #[tokio::test]
    async fn non_oidc_server_requires_public_server_url_before_binding() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_server(RunServerConfig {
            listen: "127.0.0.1:0".into(),
            db_path: dir.path().join("db.sqlite"),
            mesh_cidr: "100.64.0.0/10".into(),
            mesh_cidr_v6: None,
            ip_allocation: "sequential".into(),
            server_url: None,
            state_dir: dir.path().join("state"),
            noise_private_key_path: None,
            https_listen: None,
            metrics_listen_addr: Some("127.0.0.1:9090".into()),
            tls_hostname: None,
            unix_socket: dir.path().join("state/headscale.sock"),
            unix_socket_permission: 0o700,
            grpc_listen_addr: "127.0.0.1:0".into(),
            grpc_allow_insecure: false,
            trusted_proxies: Vec::new(),
            disable_check_updates: false,
            tls: TlsRuntimeConfig::default(),
            oidc: OidcConfig::default(),
            node_expiry: Duration::default(),
            node_routes_ha_probe_interval: Duration::from_secs(10),
            node_routes_ha_probe_timeout: Duration::from_secs(5),
            embedded_derp: EmbeddedDerpConfig::default(),
            derp: None,
            database: None,
            dns: None,
            policy: PolicyConfig::default(),
            taildrop_enabled: true,
            logtail_enabled: false,
            auto_update_enabled: false,
            logging: LoggingConfig::default(),
            cli: AdminCliConfig::default(),
            tuning: TuningConfig::default(),
            ephemeral_node_inactivity_timeout: Duration::from_secs(120),
        })
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains(
                "server.server_url is required so clients receive absolute registration URLs"
            ),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn persistent_wire_runtime_hydrates_existing_sqlite_nodes() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let user = headscale_db::users::create(
            db.pool(),
            headscale_db::users::CreateParams {
                name: "alice".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        headscale_db::headscale_nodes::create(
            db.pool(),
            headscale_db::headscale_nodes::CreateParams {
                machine_key: format!("mkey:{}", "bb".repeat(32)),
                node_key: format!("nodekey:{}", "aa".repeat(32)),
                host_info: serde_json::json!({
                    "Hostname": "alice-laptop",
                    "RoutableIPs": ["10.0.0.0/24"],
                    "OS": "linux",
                    "OSVersion": "1.80.0",
                }),
                ipv4: Some("100.64.0.9".into()),
                hostname: "alice-laptop".into(),
                given_name: "alice-laptop".into(),
                user_id: Some(user.id),
                register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                approved_routes: vec!["10.0.0.0/24".into()],
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let runtime = build_persistent_wire_runtime(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/10",
            Some(oidc_runtime()),
            DerpMap::default(),
        )
        .await
        .unwrap();

        let wire = runtime.state.machines.get(&"aa".repeat(32)).unwrap();
        assert_eq!(wire.machine_key_hex, "bb".repeat(32));
        assert_eq!(wire.hostname, "alice-laptop");
        assert_eq!(wire.user, "alice");
        assert_eq!(
            wire.ipv4.map(|addr| addr.to_string()).as_deref(),
            Some("100.64.0.9")
        );
        assert_eq!(wire.os, "linux");
        assert_eq!(wire.os_version, "1.80.0");
        assert_eq!(wire.available_routes, vec!["10.0.0.0/24"]);
        assert_eq!(wire.approved_routes, vec!["10.0.0.0/24"]);
        assert_eq!(wire.register_method, 2);
    }

    #[tokio::test]
    async fn persistent_wire_runtime_registrations_mutations_and_streams_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite");
        let db = open_sqlite_database(&db_path, None).await.unwrap();
        let state_dir = dir.path().join("state");

        let runtime = build_persistent_wire_runtime(
            db.pool(),
            &state_dir,
            "https://headscale.example",
            "100.64.0.0/10",
            Some(oidc_runtime()),
            DerpMap::default(),
        )
        .await
        .unwrap();
        assert!(runtime.oidc.is_some());
        let user = runtime
            .admin_service
            .create_user(TonicRequest::new(CreateUserRequest {
                name: "alice".into(),
                display_name: String::new(),
                email: String::new(),
                picture_url: String::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .user
            .expect("created user");
        runtime
            .admin_service
            .set_policy(TonicRequest::new(SetPolicyRequest {
                policy: r#"{"tagOwners":{"tag:server":["alice@"],"tag:db":["alice@"]}}"#.into(),
            }))
            .await
            .unwrap();

        let auth_key = runtime
            .admin_service
            .create_pre_auth_key(TonicRequest::new(CreatePreAuthKeyRequest {
                user: user.id,
                reusable: true,
                ephemeral: false,
                // headscale-go turns a missing expiration into the zero time,
                // i.e. an already-expired key, so ask for a real one.
                expiration: Some(prost_types::Timestamp {
                    seconds: chrono::Utc::now().timestamp() + 3600,
                    nanos: 0,
                }),
                acl_tags: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner()
            .pre_auth_key
            .expect("preauth key")
            .key;
        let auth_node_key = "a1".repeat(32);
        let auth_machine_key = "b1".repeat(32);
        let auth_register = wire_register_authkey(
            &runtime.state,
            &auth_node_key,
            &auth_machine_key,
            &auth_key,
            "auth-router",
        )
        .await;
        assert!(
            auth_register.machine_authorized,
            "auth-key register response: {auth_register:?}"
        );
        assert!(auth_register.error.is_empty());

        let interactive_node_key = "c1".repeat(32);
        let interactive_machine_key = "d1".repeat(32);
        let interactive_register = wire_register_interactive(
            &runtime.state,
            &interactive_node_key,
            &interactive_machine_key,
            "cli-router",
            &["10.71.0.0/24"],
        )
        .await;
        assert!(!interactive_register.machine_authorized);
        let interactive_registration_id =
            registration_id_from_auth_url(&interactive_register.auth_url);
        let interactive_node = runtime
            .admin_service
            .register_node(TonicRequest::new(RegisterNodeRequest {
                user: "alice".into(),
                key: format!("hskey-authreq-{interactive_registration_id}"),
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("interactive node");
        assert_eq!(
            interactive_node.node_key,
            format!("nodekey:{interactive_node_key}")
        );
        assert_eq!(interactive_node.available_routes, vec!["10.71.0.0/24"]);

        let oidc_node_key = "e1".repeat(32);
        let oidc_machine_key = "f1".repeat(32);
        let oidc_register = wire_register_interactive(
            &runtime.state,
            &oidc_node_key,
            &oidc_machine_key,
            "oidc-router",
            &["10.72.0.0/24"],
        )
        .await;
        assert!(!oidc_register.machine_authorized);
        let oidc_registration_id = registration_id_from_auth_url(&oidc_register.auth_url);
        let oidc_users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let oidc_machines = Arc::new(
            PersistentMachineAdmin::new(db.pool().clone())
                .with_user_admin(oidc_users)
                .with_wire_registry(runtime.state.machines.clone()),
        );
        let oidc_handler = PersistentOidcRegistrationHandler::new(
            runtime.state.registration_cache.clone(),
            oidc_machines,
            runtime.state.policy.clone(),
        )
        .with_wire_registry(runtime.state.machines.clone())
        .with_ip_allocator(runtime.state.ip_allocator.clone());
        let oidc_result = oidc_handler
            .complete_oidc_registration(
                &oidc_registration_id,
                &OidcStoredUser {
                    id: user.id,
                    name: "alice".into(),
                    display_name: "Alice Smith".into(),
                    email: "alice@example.com".into(),
                    provider_identifier: "https://issuer.example/sub".into(),
                    provider: REGISTER_METHOD_OIDC.into(),
                    profile_pic_url: String::new(),
                },
                None,
            )
            .await
            .unwrap();
        assert!(oidc_result.new_node);

        assert_eq!(
            wire_map_status(
                &runtime.state,
                &auth_node_key,
                &auth_machine_key,
                serde_json::json!({
                    "Version": 113,
                    "OmitPeers": true,
                    "DiscoKey": "discokey:685f7902828cf9128ded2b47e28816f89f3f8315e2301d7b4f01d330c53b8886",
                    "Endpoints": ["198.51.100.44:41641", "[2001:db8::44]:41641"],
                    "Hostinfo": {
                        "Hostname": "auth-router",
                        "OS": "linux",
                        "OSVersion": "6.9",
                        "RoutableIPs": ["10.70.0.0/24"],
                        "sshHostKeys": ["ssh-ed25519 AAAAC3NzaRestart"],
                        "NetInfo": {"PreferredDERP": 901}
                    }
                }),
            )
            .await,
            StatusCode::OK
        );
        let auth_row = headscale_db::headscale_nodes::get_by_node_key(
            db.pool(),
            &format!("nodekey:{auth_node_key}"),
        )
        .await
        .unwrap();
        let auth_node_id = u64::try_from(auth_row.id).unwrap();
        let tagged = runtime
            .admin_service
            .set_tags(TonicRequest::new(SetTagsRequest {
                node_id: auth_node_id,
                tags: vec!["tag:server".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("tagged node");
        assert_eq!(tagged.tags, vec!["tag:server"]);
        let routed = runtime
            .admin_service
            .set_approved_routes(TonicRequest::new(SetApprovedRoutesRequest {
                node_id: auth_node_id,
                routes: vec!["10.70.0.0/24".into()],
            }))
            .await
            .unwrap()
            .into_inner()
            .node
            .expect("routed node");
        assert_eq!(routed.approved_routes, vec!["10.70.0.0/24"]);

        drop(runtime);
        db.close().await;
        let reopened = open_sqlite_database(&db_path, None).await.unwrap();
        let restarted = build_persistent_wire_runtime(
            reopened.pool(),
            &state_dir,
            "https://headscale.example",
            "100.64.0.0/10",
            None,
            DerpMap::default(),
        )
        .await
        .unwrap();

        let hydrated_auth = restarted
            .state
            .machines
            .get(&auth_node_key)
            .expect("auth-key node hydrated");
        assert_eq!(hydrated_auth.forced_tags, vec!["tag:server"]);
        assert_eq!(hydrated_auth.available_routes, vec!["10.70.0.0/24"]);
        assert_eq!(hydrated_auth.approved_routes, vec!["10.70.0.0/24"]);
        assert_eq!(
            hydrated_auth.disco_key.as_deref(),
            Some("discokey:685f7902828cf9128ded2b47e28816f89f3f8315e2301d7b4f01d330c53b8886")
        );
        assert_eq!(
            hydrated_auth.endpoints,
            vec!["198.51.100.44:41641", "[2001:db8::44]:41641"]
        );
        assert_eq!(hydrated_auth.home_derp, 901);
        assert_eq!(
            hydrated_auth.ssh_host_keys,
            vec!["ssh-ed25519 AAAAC3NzaRestart"]
        );

        let hydrated_interactive = restarted
            .state
            .machines
            .get(&interactive_node_key)
            .expect("interactive node hydrated");
        assert_eq!(hydrated_interactive.user, "alice");
        assert_eq!(hydrated_interactive.available_routes, vec!["10.71.0.0/24"]);
        assert_eq!(hydrated_interactive.register_method, 2);

        let hydrated_oidc = restarted
            .state
            .machines
            .get(&oidc_node_key)
            .expect("OIDC node hydrated");
        assert_eq!(hydrated_oidc.user, "alice");
        assert_eq!(hydrated_oidc.hostname, "oidc-router");
        assert_eq!(hydrated_oidc.available_routes, vec!["10.72.0.0/24"]);
        assert_eq!(hydrated_oidc.register_method, 3);

        let full = wire_full_map(&restarted.state, &auth_node_key, &auth_machine_key).await;
        let self_node = full.node.expect("self node after restart");
        assert_eq!(self_node.tags, vec!["tag:server"]);
        assert_eq!(
            self_node.hostinfo.routable_ips,
            vec!["10.70.0.0/24".to_string()]
        );

        let mut stream = wire_map_stream(&restarted.state, &auth_node_key, &auth_machine_key).await;
        let initial = next_stream_map(&mut stream).await;
        let initial_self = initial.node.expect("initial streamed self node");
        assert_eq!(initial_self.tags, vec!["tag:server"]);
        assert_eq!(initial_self.primary_routes, vec!["10.70.0.0/24"]);

        restarted
            .admin_service
            .set_tags(TonicRequest::new(SetTagsRequest {
                node_id: auth_node_id,
                tags: vec!["tag:db".into()],
            }))
            .await
            .unwrap();
        let after_tag_change = next_stream_map(&mut stream).await;
        let changed_self = after_tag_change
            .node
            .expect("streamed self node after tag mutation");
        assert_eq!(changed_self.tags, vec!["tag:db"]);
        drop(stream);
        reopened.close().await;
    }

    #[tokio::test]
    async fn persistent_wire_runtime_allocator_seeds_existing_sqlite_ips() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        let user = headscale_db::users::create(
            db.pool(),
            headscale_db::users::CreateParams {
                name: "alice".into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        headscale_db::headscale_nodes::create(
            db.pool(),
            headscale_db::headscale_nodes::CreateParams {
                machine_key: format!("mkey:{}", "bb".repeat(32)),
                node_key: format!("nodekey:{}", "aa".repeat(32)),
                host_info: serde_json::json!({"Hostname": "alice-laptop"}),
                ipv4: Some("100.64.0.1".into()),
                ipv6: Some("fd7a:115c:a1e0::1".into()),
                hostname: "alice-laptop".into(),
                given_name: "alice-laptop".into(),
                user_id: Some(user.id),
                register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let runtime = build_persistent_wire_runtime_with_dns(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/30",
            Some("fd7a:115c:a1e0::/126"),
            "sequential",
            None,
            DerpMap::default(),
            Arc::new(DnsStore::new()),
            Arc::new(RuntimeConfigSnapshot::default()),
        )
        .await
        .unwrap();

        assert_eq!(
            runtime.state.ip_allocator.allocate("new-node").unwrap(),
            Ipv4Addr::new(100, 64, 0, 2)
        );
        assert_eq!(
            runtime
                .state
                .ip_allocator
                .allocate_ipv6("new-node")
                .unwrap(),
            Some("fd7a:115c:a1e0::2".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn persistent_wire_runtime_accepts_ipv6_only_prefix() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let dir = tempfile::tempdir().unwrap();

        let runtime = build_persistent_wire_runtime_with_dns(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "",
            Some("fd7a:115c:a1e0::/126"),
            "sequential",
            None,
            DerpMap::default(),
            Arc::new(DnsStore::new()),
            Arc::new(RuntimeConfigSnapshot::default()),
        )
        .await
        .unwrap();

        assert!(!runtime.state.ip_allocator.ipv4_enabled());
        assert!(runtime.state.ip_allocator.ipv6_enabled());
        assert_eq!(
            runtime
                .state
                .ip_allocator
                .allocate_ipv6("new-node")
                .unwrap(),
            Some("fd7a:115c:a1e0::1".parse().unwrap())
        );
        assert!(matches!(
            runtime.state.ip_allocator.allocate("new-node"),
            Err(AllocError::Internal(_))
        ));
    }

    #[tokio::test]
    async fn persistent_wire_runtime_loads_latest_sqlite_policy() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        UserAdmin::create(&PersistentUserAdmin::new(db.pool().clone()), "alice")
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let old = r#"{"tagOwners":{"tag:old":["alice@"]}}"#;
        let latest = r#"{"tagOwners":{"tag:server":["alice@"]}}"#;
        headscale_db::policies::set(db.pool(), old).await.unwrap();
        headscale_db::policies::set(db.pool(), latest)
            .await
            .unwrap();

        let runtime = build_persistent_wire_runtime(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/10",
            Some(oidc_runtime()),
            DerpMap::default(),
        )
        .await
        .unwrap();

        let tags = Vec::new();
        let node = headscale_api::policy::NodeView {
            user_id: None,
            addr: Some("100.64.0.9"),
            addrs: &[],
            user: Some("alice"),
            tags: &tags,
        };
        assert_eq!(runtime.state.policy.raw().as_deref(), Some(latest));
        assert!(runtime.state.policy.tag_exists("tag:server"));
        assert!(!runtime.state.policy.tag_exists("tag:old"));
        assert!(runtime.state.policy.node_can_have_tag(&node, "tag:server"));
    }

    #[tokio::test]
    async fn persistent_wire_runtime_loads_configured_file_policy() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        UserAdmin::create(&PersistentUserAdmin::new(db.pool().clone()), "alice")
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.hujson");
        let raw_policy = r#"{"tagOwners":{"tag:file":["alice@"]}}"#;
        tokio::fs::write(&policy_path, raw_policy).await.unwrap();

        let runtime = build_persistent_wire_runtime_with_dns_and_policy(
            db.pool(),
            dir.path(),
            "https://headscale.example",
            "100.64.0.0/10",
            None,
            "sequential",
            Some(oidc_runtime()),
            DerpMap::default(),
            Arc::new(DnsStore::new()),
            &PolicyConfig {
                mode: "file".to_string(),
                path: policy_path,
                ..PolicyConfig::default()
            },
            Arc::new(RuntimeConfigSnapshot::default()),
            None,
        )
        .await
        .unwrap();

        let tags = Vec::new();
        let node = headscale_api::policy::NodeView {
            user_id: None,
            addr: Some("100.64.0.9"),
            addrs: &[],
            user: Some("alice"),
            tags: &tags,
        };
        assert_eq!(runtime.state.policy.raw().as_deref(), Some(raw_policy));
        assert!(runtime.state.policy.tag_exists("tag:file"));
        assert!(runtime.state.policy.node_can_have_tag(&node, "tag:file"));
    }

    #[tokio::test]
    async fn persistent_wire_runtime_installs_ssh_forwarding_opt_out() {
        use headscale_api::policy::SshForwarding;

        for (ssh, want) in [
            (
                crate::config::PolicySshConfig::default(),
                SshForwarding::ALLOW_ALL,
            ),
            (
                crate::config::PolicySshConfig {
                    allow_agent_forwarding: false,
                    allow_remote_port_forwarding: false,
                    ..crate::config::PolicySshConfig::default()
                },
                SshForwarding {
                    agent: false,
                    local_port: true,
                    remote_port: false,
                },
            ),
        ] {
            let db = Database::in_memory().await.unwrap();
            db.migrate().await.unwrap();
            let dir = tempfile::tempdir().unwrap();
            let runtime = build_persistent_wire_runtime_with_dns_and_policy(
                db.pool(),
                dir.path(),
                "https://headscale.example",
                "100.64.0.0/10",
                None,
                "sequential",
                Some(oidc_runtime()),
                DerpMap::default(),
                Arc::new(DnsStore::new()),
                &PolicyConfig {
                    ssh,
                    ..PolicyConfig::database()
                },
                Arc::new(RuntimeConfigSnapshot::default()),
                None,
            )
            .await
            .unwrap();

            assert_eq!(runtime.state.policy.ssh_forwarding(), want);
        }
    }

    #[test]
    fn server_url_hostname_derives_tls_san_default() {
        assert_eq!(
            hostname_from_server_url("https://headscale.example:8443/base"),
            "headscale.example"
        );
        assert_eq!(
            hostname_from_server_url("http://127.0.0.1:8080"),
            "127.0.0.1"
        );
        assert_eq!(
            hostname_from_server_url("https://user:pass@[2001:db8::10]:8443"),
            "2001:db8::10"
        );
        assert_eq!(
            hostname_from_server_url("https://headscale.example:notaport"),
            "headscale-rs"
        );
    }

    #[test]
    fn sqlite_url_enables_create_mode() {
        assert!(sqlite_url_for_path(Path::new("/tmp/headscale.db")).starts_with("sqlite:///tmp/"));
        assert!(sqlite_url_for_path(Path::new("/tmp/headscale.db")).ends_with("?mode=rwc"));
    }

    #[test]
    fn cidr_allocator_uses_configured_ipv4_prefix() {
        let allocator = CidrIpAllocator::from_cidr("10.44.0.0/16").unwrap();
        let ip = allocator.allocate("node-key").unwrap();

        assert!(ip.to_string().starts_with("10.44."));
    }

    #[test]
    fn cidr_allocator_uses_configured_ipv6_prefix() {
        let allocator =
            CidrIpAllocator::from_cidrs("10.44.0.0/16", Some("fd7a:115c:a1e0::/48")).unwrap();

        let ip = allocator.allocate_ipv6("node-key").unwrap().unwrap();

        assert!(ip.to_string().starts_with("fd7a:115c:a1e0:"));
    }

    #[test]
    fn cidr_allocator_supports_ipv6_only_prefix() {
        let allocator = CidrIpAllocator::from_cidrs("", Some("fd7a:115c:a1e0::/126")).unwrap();

        assert!(!allocator.ipv4_enabled());
        assert!(allocator.ipv6_enabled());
        assert!(matches!(
            allocator.allocate("node-key"),
            Err(AllocError::Internal(_))
        ));
        assert_eq!(
            allocator.allocate_ipv6("node-key").unwrap(),
            Some("fd7a:115c:a1e0::1".parse().unwrap())
        );
    }

    #[test]
    fn cidr_allocator_sequential_skips_database_seeded_ips() {
        let allocator =
            CidrIpAllocator::from_cidrs("100.64.0.0/30", Some("fd7a:115c:a1e0::/126")).unwrap();
        allocator
            .seed_existing(Some("100.64.0.1"), Some("fd7a:115c:a1e0::1"))
            .unwrap();

        assert_eq!(
            allocator.allocate("first").unwrap(),
            Ipv4Addr::new(100, 64, 0, 2)
        );
        assert_eq!(
            allocator.allocate_ipv6("first").unwrap(),
            Some("fd7a:115c:a1e0::2".parse().unwrap())
        );
    }

    #[test]
    fn cidr_allocator_seeds_from_backend_loaded_node_ips() {
        let allocator = CidrIpAllocator::from_existing_node_ips(
            "100.64.0.0/30",
            Some("fd7a:115c:a1e0::/126"),
            IpAllocationStrategy::Sequential,
            [ExistingNodeIpAddresses {
                ipv4: Some("100.64.0.1"),
                ipv6: Some("fd7a:115c:a1e0::1"),
            }],
        )
        .unwrap();

        assert_eq!(
            allocator.allocate("first").unwrap(),
            Ipv4Addr::new(100, 64, 0, 2)
        );
        assert_eq!(
            allocator.allocate_ipv6("first").unwrap(),
            Some("fd7a:115c:a1e0::2".parse().unwrap())
        );
    }

    #[test]
    fn cidr_allocator_skips_tailscale_reserved_addresses() {
        let allocator =
            CidrIpAllocator::from_cidrs("100.100.100.96/29", Some("fd7a:115c:a1e0::50/124"))
                .unwrap();
        for ip in ["100.100.100.97", "100.100.100.98", "100.100.100.99"] {
            allocator.seed_existing(Some(ip), None).unwrap();
        }
        for ip in ["fd7a:115c:a1e0::51", "fd7a:115c:a1e0::52"] {
            allocator.seed_existing(None, Some(ip)).unwrap();
        }

        assert_eq!(
            allocator.allocate("reserved-v4").unwrap(),
            Ipv4Addr::new(100, 100, 100, 101)
        );
        assert_eq!(
            allocator.allocate_ipv6("reserved-v6").unwrap(),
            Some("fd7a:115c:a1e0::54".parse().unwrap())
        );
    }

    #[test]
    fn cidr_allocator_reports_exhaustion() {
        let allocator = CidrIpAllocator::from_cidr("100.64.0.0/30").unwrap();
        allocator.seed_existing(Some("100.64.0.1"), None).unwrap();
        allocator.seed_existing(Some("100.64.0.2"), None).unwrap();

        assert!(matches!(
            allocator.allocate("full"),
            Err(AllocError::Exhausted)
        ));
    }

    #[test]
    fn cidr_allocator_rejects_invalid_prefixes_and_defers_tiny_pool_exhaustion() {
        assert!(CidrIpAllocator::from_cidr("not-a-cidr").is_err());
        let ipv4 = CidrIpAllocator::from_cidr("100.64.0.0/32").unwrap();
        assert!(matches!(ipv4.allocate("tiny"), Err(AllocError::Exhausted)));
        assert!(CidrIpAllocator::from_cidrs("", None).is_err());
        assert!(CidrIpAllocator::from_cidrs("100.64.0.0/10", Some("not-a-cidr")).is_err());
        let ipv6 = CidrIpAllocator::from_cidrs("", Some("fd7a:115c:a1e0::/128")).unwrap();
        assert!(matches!(
            ipv6.allocate_ipv6("tiny"),
            Err(AllocError::Exhausted)
        ));
    }
}
