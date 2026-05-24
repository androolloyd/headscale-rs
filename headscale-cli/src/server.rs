//! Server mode - runs the control plane.

use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tokio_stream::{
    StreamExt,
    wrappers::{TcpListenerStream, UnixListenerStream},
};
use tonic::transport::server::Connected;

use headscale_api::admin::{
    PersistentApiKeyAdmin, PersistentMachineAdmin, PersistentOidcRegistrationHandler,
    PersistentPreauthAdmin, PersistentUserAdmin,
};
use headscale_api::dns::{
    DnsConfigSpec, DnsStore, parse_extra_records, spawn_extra_records_watcher,
};
use headscale_api::grpc::upstream::HeadscaleAdminService;
use headscale_api::grpc_gateway;
use headscale_api::oidc::{OidcAuthRuntime, runtime_from_core_oidc};
use headscale_api::policy::{PolicyStore, parse_hujson_policy};
use headscale_api::tailscale_wire::tls;
use headscale_api::tailscale_wire::tls::{SanConfig, TlsMaterialSource};
use headscale_api::tailscale_wire::{
    AllocError, BATCHER_OFFLINE_CLEANUP_INTERVAL, BATCHER_OFFLINE_CLEANUP_THRESHOLD, DerpMap,
    DerpMapStore, DerpRegion, DerpRegionNode, IpAllocator, KnockConfig, MachineRegistry,
    MapResponseDebugStore, PingTracker, RegistrationCache, RuntimeConfigSnapshot, ServerNoiseKey,
    WireState, serve, spawn_node_expiry_waker, spawn_offline_connection_cleanup,
    spawn_route_health_probe,
};
use headscale_core::config::{EmbeddedDerpConfig, OidcConfig};
use headscale_core::derp::EmbeddedDerpRuntime;

use crate::config::{
    PolicyConfig, TuningConfig, UpstreamDatabaseConfig, server_url_hostname,
    validate_server_url_base_domain,
};
use crate::derp_config::DerpConfig;
use headscale_db::Database;

const NODE_EXPIRY_UPDATE_INTERVAL: Duration = Duration::from_secs(5);
const DEFAULT_ACME_URL: &str = "https://acme-v02.api.letsencrypt.org/directory";
const DEFAULT_LETSENCRYPT_CACHE_DIR: &str = "/var/www/.cache";
const DEFAULT_LETSENCRYPT_LISTEN: &str = ":http";
const DEFAULT_LETSENCRYPT_CHALLENGE_TYPE: &str = "HTTP-01";

#[derive(Debug, Clone)]
pub(crate) struct RunServerConfig {
    pub listen: String,
    pub db_path: PathBuf,
    pub mesh_cidr: String,
    pub mesh_cidr_v6: Option<String>,
    pub ip_allocation: String,
    pub server_url: Option<String>,
    pub state_dir: PathBuf,
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
    pub tuning: TuningConfig,
    pub ephemeral_node_inactivity_timeout: Duration,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct TlsRuntimeConfig {
    pub acme_url: Option<String>,
    pub acme_email: Option<String>,
    pub letsencrypt_hostname: Option<String>,
    pub letsencrypt_cache_dir: Option<PathBuf>,
    pub letsencrypt_listen: Option<String>,
    pub letsencrypt_challenge_type: Option<String>,
    pub cert_path: Option<PathBuf>,
    pub key_path: Option<PathBuf>,
}

impl TlsRuntimeConfig {
    fn letsencrypt_enabled(&self) -> bool {
        non_empty_str(self.letsencrypt_hostname.as_deref()).is_some()
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
        self.letsencrypt_cache_dir
            .as_ref()
            .filter(|path| !path.as_os_str().is_empty())
            .map_or_else(
                || DEFAULT_LETSENCRYPT_CACHE_DIR.to_string(),
                |path| path.display().to_string(),
            )
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

    fn unsupported_acme_message(&self) -> String {
        let challenge = self.challenge_type_string();
        let challenge_context = match challenge.as_str() {
            "HTTP-01" => format!(
                "HTTP-01 challenge listener {}",
                self.letsencrypt_listen_string()
            ),
            "TLS-ALPN-01" => "TLS-ALPN-01 on the public TLS listener".to_string(),
            other => format!(
                "challenge {other} with challenge listener {}",
                self.letsencrypt_listen_string()
            ),
        };
        format!(
            "tls_letsencrypt_hostname/ACME TLS is not implemented in headscale-rs yet; configured {} would require ACME certificate issuance using acme_url {} and cache_dir {}. Use tls_cert_path/tls_key_path or terminate TLS before headscale-rs.",
            challenge_context,
            self.acme_url_string(),
            self.cache_dir_string()
        )
    }
}

/// Run the control plane server.
pub(crate) async fn run_server(cfg: RunServerConfig) -> Result<()> {
    run_tailscale_wire_server(cfg).await
}

async fn run_tailscale_wire_server(cfg: RunServerConfig) -> Result<()> {
    let public_listeners = public_listener_plan(&cfg)?;
    validate_supported_runtime_config(&cfg)?;
    tracing::info!("Starting headscale-compatible Tailscale control plane");
    tracing::info!(
        "  Public HTTP: {}",
        optional_addr_status(public_listeners.http_addr)
    );
    tracing::info!(
        "  Public HTTPS: {}",
        optional_addr_status(public_listeners.https_addr)
    );
    tracing::info!(
        "  Metrics/debug: {}",
        cfg.metrics_listen_addr
            .as_deref()
            .map(str::trim)
            .filter(|addr| !addr.is_empty())
            .unwrap_or("<disabled>")
    );
    tracing::info!("  Database: {}", cfg.db_path.display());
    tracing::info!("  State dir: {}", cfg.state_dir.display());
    if cfg.mesh_cidr.trim().is_empty() {
        tracing::info!("  IPv4 prefix: <disabled>");
    } else {
        tracing::info!("  IPv4 prefix: {}", cfg.mesh_cidr);
    }
    if let Some(mesh_cidr_v6) = &cfg.mesh_cidr_v6 {
        tracing::info!("  IPv6 prefix: {}", mesh_cidr_v6);
    }
    tracing::info!("  Local gRPC socket: {}", cfg.unix_socket.display());
    tracing::info!("  Remote gRPC: {}", remote_grpc_status(&cfg));

    let server_url = cfg.server_url.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "server.server_url is required so clients receive absolute registration URLs"
        )
    })?;
    ensure_parent_dir(&cfg.db_path)?;
    std::fs::create_dir_all(&cfg.state_dir).with_context(|| {
        format!(
            "Failed to create state directory: {}",
            cfg.state_dir.display()
        )
    })?;

    let db = open_sqlite_database(&cfg.db_path).await?;
    let oidc_config = upstream_oidc_runtime_config(&cfg.oidc);
    let oidc = runtime_from_core_oidc(&oidc_config, server_url)
        .await
        .context("build OIDC runtime")?;
    let embedded_derp_runtime =
        EmbeddedDerpRuntime::start_with_state_dir(cfg.embedded_derp.clone(), &cfg.state_dir)
            .await
            .context("start embedded DERP/STUN runtime")?;
    if let Some(addr) = embedded_derp_runtime.stun_local_addr() {
        tracing::info!(%addr, "embedded STUN listener ready");
    }
    if let Some(status) = embedded_derp_runtime.sidecar_status() {
        tracing::info!(?status, "embedded DERP sidecar ready");
    }
    let derp_map = derp_map_from_runtime_config(cfg.derp.as_ref(), embedded_derp_runtime.config())
        .await
        .context("load DERP runtime config")?;
    let (dns_store, dns_extra_records_path) = dns_store_from_config(
        cfg.dns.clone(),
        Some(&cfg.mesh_cidr),
        cfg.mesh_cidr_v6.as_deref(),
    )
    .context("load DNS runtime config")?;
    let runtime_config = Arc::new(runtime_config_snapshot(&cfg, &derp_map, dns_store.as_ref()));
    let runtime = build_persistent_wire_runtime_with_dns_and_policy(
        db.pool(),
        &cfg.state_dir,
        server_url,
        &cfg.mesh_cidr,
        cfg.mesh_cidr_v6.as_deref(),
        &cfg.ip_allocation,
        oidc,
        derp_map,
        dns_store.clone(),
        &cfg.policy,
        runtime_config,
    )
    .await?;
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
    let node_expiry_waker =
        spawn_node_expiry_waker(runtime.state.machines.clone(), NODE_EXPIRY_UPDATE_INTERVAL);
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
    let tls_source = tls_material_source(&cfg, &sans)?;
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
    };
    let local_grpc_listener =
        bind_unix_grpc_listener(&cfg.unix_socket, cfg.unix_socket_permission).await?;
    let remote_grpc_security = remote_grpc_security(&cfg, &tls_source)?;
    let remote_grpc_listener = match remote_grpc_security {
        Some(security) => Some((
            bind_tcp_grpc_listener(grpc_addr).await?,
            grpc_addr,
            security,
        )),
        None => None,
    };
    let derp_auto_update = spawn_derp_auto_update_task(
        cfg.derp.clone(),
        cfg.embedded_derp.clone(),
        runtime.state.derp_map.clone(),
    );

    let handle = serve::serve(runtime.state, serve_cfg, extra_routes)
        .await
        .context("start Tailscale wire listeners")?;
    let dns_extra_records_watcher = dns_extra_records_path.map(|path| {
        tracing::info!(path = %path.display(), "watching DNS extra-records file");
        spawn_extra_records_watcher((*dns_store).clone(), path, None)
    });
    let local_grpc = spawn_local_grpc_listener(
        local_grpc_listener,
        cfg.unix_socket.clone(),
        runtime.admin_service.clone(),
    );
    let remote_grpc = remote_grpc_listener.map(|(listener, addr, security)| {
        spawn_remote_grpc_listener(listener, addr, runtime.admin_service.clone(), security)
    });
    let policy_reload = spawn_policy_reload_signal_task(runtime.admin_service.clone());
    tracing::info!("Headscale-compatible Tailscale control plane ready");
    let serve_result = await_serve_handle(handle, local_grpc, remote_grpc).await;
    if let Some(handle) = policy_reload {
        handle.abort();
    }
    node_expiry_waker.abort();
    if let Some(handle) = route_health_probe {
        handle.abort();
    }
    offline_connection_cleanup.abort();
    ephemeral_gc.abort();
    if let Some(handle) = dns_extra_records_watcher {
        handle.abort();
    }
    if let Some(handle) = derp_auto_update {
        handle.abort();
    }
    drop(embedded_derp_runtime);
    serve_result
}

struct PersistentWireRuntime {
    state: WireState,
    oidc: Option<OidcAuthRuntime>,
    admin_service: HeadscaleAdminService,
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
    )
    .await
}

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
) -> Result<PersistentWireRuntime> {
    let allocation = IpAllocationStrategy::parse(ip_allocation)?;
    let users = Arc::new(PersistentUserAdmin::new(pool.clone()));
    let api_keys = Arc::new(PersistentApiKeyAdmin::new(pool.clone()));
    let preauth =
        Arc::new(PersistentPreauthAdmin::new(pool.clone()).with_user_admin(users.clone()));
    let wire_registry = Arc::new(MachineRegistry::new());
    let machines = Arc::new(
        PersistentMachineAdmin::new(pool.clone())
            .with_user_admin(users.clone())
            .with_wire_registry(wire_registry.clone()),
    );
    let registration_cache = Arc::new(RegistrationCache::new());
    let ip_allocator: Arc<dyn IpAllocator> =
        Arc::new(CidrIpAllocator::from_database(pool, mesh_cidr, mesh_cidr_v6, allocation).await?);
    let policy = Arc::new(PolicyStore::new());
    let policy_loaded = load_startup_policy(pool, &policy, policy_config).await?;
    tracing::info!(
        loaded = policy_loaded,
        mode = policy_config.mode(),
        "loaded startup policy into wire runtime"
    );
    let hydrated = machines
        .hydrate_wire_registry(&wire_registry)
        .await
        .context("hydrate wire registry from SQLite nodes")?;
    tracing::info!(
        nodes = hydrated,
        "hydrated persisted nodes into wire registry"
    );
    let admin_service = HeadscaleAdminService::with_user_admin(
        users.clone(),
        api_keys,
        preauth.clone(),
        policy.as_ref().clone(),
        machines.clone(),
    )
    .with_database_pool(pool.clone())
    .with_registration_cache(registration_cache.clone())
    .with_wire_registry(wire_registry.clone())
    .with_ip_allocator(ip_allocator.clone());
    let admin_service = match policy_config.mode() {
        "database" => admin_service.with_policy_pool(pool.clone()),
        "file" => admin_service.with_policy_file(policy_config.path.clone()),
        mode => anyhow::bail!("policy.mode must be either file or database, got {mode:?}"),
    };
    let oidc = oidc.map(|runtime| {
        let handler = PersistentOidcRegistrationHandler::new(
            registration_cache.clone(),
            machines.clone(),
            policy.clone(),
        )
        .with_wire_registry(wire_registry.clone());
        runtime
            .with_user_store(users)
            .with_registration_handler(Arc::new(handler))
    });

    let state = WireState {
        server_noise_key: Arc::new(ServerNoiseKey::load_or_generate(state_dir)?),
        preauth,
        ip_allocator,
        machines: wire_registry,
        registration_store: Some(machines),
        derp_map: DerpMapStore::shared(derp_map),
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
        noise_private_key_path: cfg
            .state_dir
            .join(headscale_api::tailscale_wire::noise::NOISE_STATIC_KEY_FILENAME)
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

    if let Some(derp) = &cfg.derp {
        snapshot.derp.server_enabled = derp.server.enabled;
        snapshot.derp.automatically_add_embedded_derp_region =
            derp.server.automatically_add_embedded_derp_region;
        snapshot.derp.server_region_id = i32::from(derp.server.region_id);
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
    snapshot.tls.lets_encrypt.hostname = non_empty_str(cfg.tls.letsencrypt_hostname.as_deref())
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

fn validate_supported_runtime_config(cfg: &RunServerConfig) -> Result<()> {
    if cfg
        .database
        .as_ref()
        .is_some_and(UpstreamDatabaseConfig::is_postgres)
    {
        anyhow::bail!(
            "database.type \"postgres\" is recognized for headscale-go compatibility but headscale-rs server currently supports SQLite only; set database.type to \"sqlite\" or \"sqlite3\""
        );
    }
    if cfg.tls.letsencrypt_enabled() {
        anyhow::bail!("{}", cfg.tls.unsupported_acme_message());
    }
    if let (Some(server_url), Some(dns)) = (cfg.server_url.as_deref(), cfg.dns.as_ref()) {
        validate_server_url_base_domain(server_url, &dns.base_domain)?;
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
    if cfg.tls.letsencrypt_enabled() {
        anyhow::bail!("{}", cfg.tls.unsupported_acme_message());
    }

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
        derp_port: if cfg.derp_port == 443 {
            0
        } else {
            cfg.derp_port
        },
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

async fn derp_map_from_runtime_config(
    upstream: Option<&DerpConfig>,
    embedded: &EmbeddedDerpConfig,
) -> Result<DerpMap> {
    let mut map = if let Some(upstream) = upstream {
        crate::derp_config::load_derp_map(upstream).await?
    } else {
        DerpMap::default()
    };

    let add_embedded_region = upstream
        .filter(|derp| derp.server.enabled)
        .is_none_or(|derp| derp.server.automatically_add_embedded_derp_region);
    if embedded.enabled && add_embedded_region {
        merge_derp_maps(&mut map, derp_map_from_embedded_config(embedded));
    }

    Ok(map)
}

fn spawn_derp_auto_update_task(
    upstream: Option<DerpConfig>,
    embedded: EmbeddedDerpConfig,
    store: Arc<DerpMapStore>,
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
            match refresh_derp_map_once(&upstream, &embedded, &store).await {
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
            tracing::info!("Received SIGHUP, reloading ACL policy");
            match admin_service.reload_policy_from_config().await {
                Ok(true) => tracing::info!("ACL policy reloaded"),
                Ok(false) => {
                    tracing::info!("ACL policy reload skipped; no configured policy source");
                }
                Err(err) => tracing::error!(error = ?err, "reloading ACL policy failed"),
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
) -> Result<()> {
    let map = derp_map_from_runtime_config(Some(upstream), embedded).await?;
    store.set(map);
    Ok(())
}

fn merge_derp_maps(dest: &mut DerpMap, source: DerpMap) {
    if source.home_params.is_some() {
        dest.home_params = source.home_params;
    }
    dest.regions.extend(source.regions);
    if source.omit_default_regions {
        dest.omit_default_regions = true;
    }
}

fn production_extra_routes(runtime: &PersistentWireRuntime) -> axum::Router {
    grpc_gateway::router(runtime.admin_service.clone())
}

#[derive(Clone)]
enum RemoteGrpcSecurity {
    Insecure,
    Tls(TlsAcceptor),
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

fn remote_grpc_security(
    cfg: &RunServerConfig,
    tls_source: &TlsMaterialSource,
) -> Result<Option<RemoteGrpcSecurity>> {
    if cfg.tls.has_manual_tls() || cfg.https_listen.is_some() {
        let material = tls_source
            .load()
            .context("load TLS material for remote gRPC")?;
        let grpc_tls = tls::build_grpc_server_config(&material.cert_pem, &material.key_pem)
            .context("build remote gRPC TLS config")?;
        return Ok(Some(RemoteGrpcSecurity::Tls(TlsAcceptor::from(Arc::new(
            grpc_tls,
        )))));
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

fn spawn_local_grpc_listener(
    listener: UnixListener,
    path: PathBuf,
    service: HeadscaleAdminService,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let reflection =
            HeadscaleAdminService::reflection_service().context("build gRPC reflection service")?;
        let incoming = UnixListenerStream::new(listener);
        tracing::info!(path = %path.display(), "admin gRPC listening on Unix socket");
        tonic::transport::Server::builder()
            .add_service(service.into_service_server())
            .add_service(reflection)
            .serve_with_incoming(incoming)
            .await
            .with_context(|| format!("serve admin gRPC Unix socket {}", path.display()))
    })
}

fn spawn_remote_grpc_listener(
    listener: TcpListener,
    addr: SocketAddr,
    service: HeadscaleAdminService,
    security: RemoteGrpcSecurity,
) -> tokio::task::JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let reflection =
            HeadscaleAdminService::reflection_service().context("build gRPC reflection service")?;
        tracing::info!(%addr, "admin gRPC listening on TCP");
        match security {
            RemoteGrpcSecurity::Insecure => {
                let incoming = TcpListenerStream::new(listener);
                tonic::transport::Server::builder()
                    .add_service(service.into_authenticated_service_server())
                    .add_service(reflection)
                    .serve_with_incoming(incoming)
                    .await
                    .with_context(|| format!("serve remote gRPC TCP listener {addr}"))
            }
            RemoteGrpcSecurity::Tls(acceptor) => {
                let incoming = TcpListenerStream::new(listener).then(move |accepted| {
                    let acceptor = acceptor.clone();
                    async move {
                        let stream = accepted?;
                        acceptor
                            .accept(stream)
                            .await
                            .map(ConnectedTlsStream)
                            .map_err(std::io::Error::other)
                    }
                });
                tonic::transport::Server::builder()
                    .add_service(service.into_authenticated_service_server())
                    .add_service(reflection)
                    .serve_with_incoming(incoming)
                    .await
                    .with_context(|| format!("serve remote gRPC TCP listener {addr}"))
            }
        }
    })
}

async fn load_persisted_policy(pool: &sqlx::SqlitePool, policy: &PolicyStore) -> Result<bool> {
    let Some(row) = headscale_db::policies::get_latest(pool)
        .await
        .context("load persisted ACL policy")?
    else {
        return Ok(false);
    };
    let doc = parse_hujson_policy(&row.data).context("parse persisted ACL policy")?;
    policy.set_at(doc, row.data, row.updated_at);
    Ok(true)
}

async fn load_startup_policy(
    pool: &sqlx::SqlitePool,
    policy: &PolicyStore,
    config: &PolicyConfig,
) -> Result<bool> {
    match config.mode() {
        "database" => load_persisted_policy(pool, policy).await,
        "file" => load_file_policy(config, policy).await,
        mode => anyhow::bail!("policy.mode must be either file or database, got {mode:?}"),
    }
}

async fn load_file_policy(config: &PolicyConfig, policy: &PolicyStore) -> Result<bool> {
    let Some(path) = config.path_if_non_empty() else {
        return Ok(false);
    };
    let raw = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("read policy.path {}", path.display()))?;
    if raw.is_empty() {
        return Ok(false);
    }
    let doc = parse_hujson_policy(&raw)
        .with_context(|| format!("parse policy.path {}", path.display()))?;
    policy.set(doc, raw);
    Ok(true)
}

async fn open_sqlite_database(path: &Path) -> Result<Database> {
    let url = sqlite_url_for_path(path);
    let db = Database::new(&url)
        .await
        .with_context(|| format!("open SQLite database at {}", path.display()))?;
    db.migrate()
        .await
        .with_context(|| format!("migrate SQLite database at {}", path.display()))?;
    Ok(db)
}

fn sqlite_url_for_path(path: &Path) -> String {
    format!("sqlite://{}?mode=rwc", path.display())
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create database directory: {}", parent.display())
        })?;
    }
    Ok(())
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

async fn await_serve_handle(
    handle: serve::ServeHandle,
    local_grpc: tokio::task::JoinHandle<Result<()>>,
    remote_grpc: Option<tokio::task::JoinHandle<Result<()>>>,
) -> Result<()> {
    let serve::ServeHandle {
        http,
        https,
        metrics,
        ..
    } = handle;
    tokio::select! {
        result = await_optional_listener_result(http, "http") => result,
        result = await_optional_listener_result(https, "https") => result,
        result = await_optional_listener_result(metrics, "metrics") => result,
        result = local_grpc => flatten_anyhow_task_result(result, "local grpc"),
        result = await_optional_anyhow_task_result(remote_grpc, "remote grpc") => result,
    }
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

async fn await_optional_listener_result(
    handle: Option<tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>>,
    label: &'static str,
) -> Result<()> {
    match handle {
        Some(handle) => flatten_listener_result(handle.await, label),
        None => std::future::pending::<Result<()>>().await,
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

async fn await_optional_anyhow_task_result(
    handle: Option<tokio::task::JoinHandle<Result<()>>>,
    label: &'static str,
) -> Result<()> {
    match handle {
        Some(handle) => flatten_anyhow_task_result(handle.await, label),
        None => std::future::pending::<Result<()>>().await,
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
        let allocator = Self::from_cidrs_with_strategy(cidr, cidr_v6, strategy)?;
        let rows = headscale_db::headscale_nodes::list(pool)
            .await
            .context("read existing node IP addresses for allocator")?;
        for row in rows {
            allocator.seed_existing(row.ipv4.as_deref(), row.ipv6.as_deref())?;
        }
        Ok(allocator)
    }

    fn from_cidrs_with_strategy(
        cidr: &str,
        cidr_v6: Option<&str>,
        strategy: IpAllocationStrategy,
    ) -> Result<Self> {
        let ipv4 = (!cidr.trim().is_empty())
            .then(|| parse_ipv4_cidr(cidr))
            .transpose()?;
        let ipv6 = cidr_v6
            .filter(|cidr| !cidr.trim().is_empty())
            .map(parse_ipv6_cidr)
            .transpose()?;
        if ipv4.is_none() && ipv6.is_none() {
            anyhow::bail!("config error, at least one of prefixes.v4 or prefixes.v6 must be set");
        }

        Ok(Self {
            ipv4,
            ipv6,
            strategy,
        })
    }

    fn seed_existing(&self, ipv4: Option<&str>, ipv6: Option<&str>) -> Result<()> {
        if let (Some(state), Some(ipv4)) = (&self.ipv4, ipv4.filter(|value| !value.is_empty())) {
            let ip: Ipv4Addr = ipv4
                .parse()
                .with_context(|| format!("parsing IPv4 address from database: {ipv4}"))?;
            state
                .lock()
                .expect("IPv4 allocator lock poisoned")
                .used
                .insert(u128::from(u32::from(ip)));
        }
        if let Some(ipv6) = ipv6.filter(|value| !value.is_empty()) {
            let ip: Ipv6Addr = ipv6
                .parse()
                .with_context(|| format!("parsing IPv6 address from database: {ipv6}"))?;
            if let Some(state) = &self.ipv6 {
                state
                    .lock()
                    .expect("IPv6 allocator lock poisoned")
                    .used
                    .insert(u128::from(ip));
            }
        }
        Ok(())
    }
}

fn parse_ipv4_cidr(cidr: &str) -> Result<Mutex<IpFamilyAllocator>> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid server.mesh_cidr {cidr:?}: missing prefix"))?;
    let addr: Ipv4Addr = addr
        .parse()
        .with_context(|| format!("invalid server.mesh_cidr {cidr:?}: invalid IPv4 address"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid server.mesh_cidr {cidr:?}: invalid prefix length"))?;
    if prefix > 32 {
        anyhow::bail!("invalid server.mesh_cidr {cidr:?}: prefix length must be <= 32");
    }

    let host_bits = 32u32 - u32::from(prefix);
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << host_bits
    };
    let network = u32::from(addr) & mask;
    let end = network | !mask;
    if end.saturating_sub(network) < 2 {
        anyhow::bail!(
            "invalid server.mesh_cidr {cidr:?}: prefix must leave assignable host addresses"
        );
    }

    Ok(Mutex::new(IpFamilyAllocator::new(
        u128::from(network),
        u128::from(end),
    )))
}

fn parse_ipv6_cidr(cidr: &str) -> Result<Mutex<IpFamilyAllocator>> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid server.mesh_cidr_v6 {cidr:?}: missing prefix"))?;
    let addr: Ipv6Addr = addr
        .parse()
        .with_context(|| format!("invalid server.mesh_cidr_v6 {cidr:?}: invalid IPv6 address"))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid server.mesh_cidr_v6 {cidr:?}: invalid prefix length"))?;
    if prefix > 128 {
        anyhow::bail!("invalid server.mesh_cidr_v6 {cidr:?}: prefix length must be <= 128");
    }

    let host_bits = 128u32 - u32::from(prefix);
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << host_bits
    };
    let network = u128::from(addr) & mask;
    let end = network | !mask;
    if end.saturating_sub(network) < 2 {
        anyhow::bail!(
            "invalid server.mesh_cidr_v6 {cidr:?}: prefix must leave assignable host addresses"
        );
    }

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
        if let Some(count) = self
            .end
            .checked_sub(self.network)
            .and_then(|span| span.checked_add(1))
            && self.used.len() as u128 >= count
        {
            return Err(AllocError::Exhausted);
        }

        for _ in 0..1024 {
            let candidate = random_between(self.network, self.end);
            if !self.used.contains(&candidate) && !reserved(candidate) {
                self.used.insert(candidate);
                self.prev = candidate;
                return Ok(candidate);
            }
        }

        self.allocate_sequential(reserved)
    }
}

impl IpAllocator for CidrIpAllocator {
    fn allocate(&self, node_key_hex: &str) -> std::result::Result<Ipv4Addr, AllocError> {
        let _ = node_key_hex;
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

    fn ipv4_enabled(&self) -> bool {
        self.ipv4.is_some()
    }

    fn allocate_ipv6(
        &self,
        node_key_hex: &str,
    ) -> std::result::Result<Option<Ipv6Addr>, AllocError> {
        let _ = node_key_hex;
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

    fn ipv6_enabled(&self) -> bool {
        self.ipv6.is_some()
    }
}

fn random_between(start: u128, end: u128) -> u128 {
    let span = end - start;
    let mut raw = [0u8; 16];
    OsRng.fill_bytes(&mut raw);
    let sample = u128::from_be_bytes(raw);
    if span == u128::MAX {
        sample
    } else {
        start + (sample % (span + 1))
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
    use headscale_api::tailscale_wire::{
        map as wire_map_handlers,
        noise::NoisePeerMachineKey,
        register as wire_register_handlers,
        wire::{MapResponse, RegisterResponse},
    };
    use hyper_util::rt::TokioIo;
    use serde_json::Value;
    use std::collections::BTreeMap;
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

    fn test_run_server_config(dir: &tempfile::TempDir) -> RunServerConfig {
        RunServerConfig {
            listen: "127.0.0.1:8080".into(),
            db_path: dir.path().join("db.sqlite"),
            mesh_cidr: "100.64.0.0/10".into(),
            mesh_cidr_v6: None,
            ip_allocation: "sequential".into(),
            server_url: Some("https://headscale.example".into()),
            state_dir: dir.path().join("state"),
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
            tuning: TuningConfig::default(),
            ephemeral_node_inactivity_timeout: Duration::from_secs(120),
        }
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
    fn embedded_derp_map_omits_default_tls_derp_port() {
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

        assert_eq!(node.derp_port, 0);
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

        let map = derp_map_from_runtime_config(Some(&derp), &embedded)
            .await
            .unwrap();

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

        let err = derp_map_from_runtime_config(Some(&derp), &embedded)
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

        refresh_derp_map_once(&derp, &embedded, &store)
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
                .any(|peer| peer.name == "peer-b.tail.example.org")
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
        assert!(dns.cert_domains.is_empty());
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
        assert!(
            services
                .iter()
                .any(|s| s == "headscale.v1.HeadscaleService")
        );
        assert!(
            services
                .iter()
                .any(|s| s == "grpc.reflection.v1.ServerReflection")
        );

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
            TlsMaterialSource::SelfSigned { .. } => panic!("expected manual TLS source"),
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
    fn runtime_config_rejects_unsupported_acme_before_serving() {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = test_run_server_config(&dir);
        cfg.tls.letsencrypt_hostname = Some("headscale.example".into());
        cfg.tls.letsencrypt_cache_dir = Some(dir.path().join("acme-cache"));
        cfg.tls.letsencrypt_challenge_type = Some("TLS-ALPN-01".into());

        let err = validate_supported_runtime_config(&cfg).unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("ACME TLS is not implemented"));
        assert!(err.contains("TLS-ALPN-01 on the public TLS listener"));
        assert!(err.contains(&format!(
            "cache_dir {}",
            dir.path().join("acme-cache").display()
        )));
    }

    #[test]
    fn runtime_config_rejects_unsupported_postgres_before_opening_sqlite() {
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

        let err = validate_supported_runtime_config(&cfg).unwrap_err();

        assert!(format!("{err:#}").contains("headscale-rs server currently supports SQLite only"));
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
                nameservers: vec!["1.1.1.1".to_string()],
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
    fn runtime_config_snapshot_projects_current_upstream_schema_fields() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            r#"
server_url: "https://headscale.example"
trusted_proxies:
  - "127.0.0.1/32"
disable_check_updates: true

logtail:
  enabled: true

auto_update:
  enabled: true

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
        cfg.tuning = parsed.tuning;

        let dns = DnsStore::new();
        let snapshot = runtime_config_snapshot(&cfg, &DerpMap::default(), &dns);

        assert_eq!(snapshot.trusted_proxies, ["127.0.0.1/32"]);
        assert!(snapshot.disable_update_check);
        assert!(snapshot.log_tail.enabled);
        assert!(snapshot.auto_update.enabled);
        assert_eq!(snapshot.database.database_type, "sqlite3");
        assert!(snapshot.database.debug);
        assert!(snapshot.database.gorm.debug);
        assert_eq!(snapshot.database.gorm.slow_threshold, 1_000_000_000);
        assert!(snapshot.database.gorm.prepare_stmt);
        assert_eq!(
            snapshot.database.sqlite.path,
            dir.path().join("data/db.sqlite").display().to_string()
        );
        assert!(!snapshot.database.sqlite.write_ahead_log);
        assert_eq!(snapshot.database.sqlite.wal_auto_check_point, 250);
        assert_eq!(snapshot.database.postgres.host, "localhost");
        assert_eq!(snapshot.database.postgres.ssl, "false");
        assert_eq!(snapshot.database.postgres.max_open_connections, 11);
        assert_eq!(snapshot.tuning.notifier_send_timeout, 900_000_000);
        assert_eq!(snapshot.tuning.node_map_session_buffered_chan_size, 42);
        assert_eq!(snapshot.tuning.register_cache_max_entries, 2048);
        assert_eq!(snapshot.tuning.node_store_batch_timeout, 250_000_000);
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
                    "App": "1.80.0",
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
        let db = open_sqlite_database(&db_path).await.unwrap();
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
                expiration: None,
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
        assert!(auth_register.machine_authorized);
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
                key: interactive_registration_id,
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
        .with_wire_registry(runtime.state.machines.clone());
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
                    "DiscoKey": "discokey:auth-restart",
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
        let reopened = open_sqlite_database(&db_path).await.unwrap();
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
            Some("discokey:auth-restart")
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
            addr: Some("100.64.0.9"),
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
            },
            Arc::new(RuntimeConfigSnapshot::default()),
        )
        .await
        .unwrap();

        let tags = Vec::new();
        let node = headscale_api::policy::NodeView {
            addr: Some("100.64.0.9"),
            user: Some("alice"),
            tags: &tags,
        };
        assert_eq!(runtime.state.policy.raw().as_deref(), Some(raw_policy));
        assert!(runtime.state.policy.tag_exists("tag:file"));
        assert!(runtime.state.policy.node_can_have_tag(&node, "tag:file"));
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
    fn cidr_allocator_rejects_invalid_or_tiny_prefixes() {
        assert!(CidrIpAllocator::from_cidr("not-a-cidr").is_err());
        assert!(CidrIpAllocator::from_cidr("100.64.0.0/32").is_err());
        assert!(CidrIpAllocator::from_cidrs("", None).is_err());
        assert!(CidrIpAllocator::from_cidrs("100.64.0.0/10", Some("not-a-cidr")).is_err());
        assert!(
            CidrIpAllocator::from_cidrs("100.64.0.0/10", Some("fd7a:115c:a1e0::/128")).is_err()
        );
    }
}
