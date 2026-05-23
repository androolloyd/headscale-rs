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
    AllocError, DerpMap, DerpMapStore, DerpRegion, DerpRegionNode, IpAllocator, KnockConfig,
    MachineRegistry, PingTracker, RegistrationCache, RuntimeConfigSnapshot, ServerNoiseKey,
    WireState, serve, spawn_node_expiry_waker,
};
use headscale_core::config::{EmbeddedDerpConfig, OidcConfig};
use headscale_core::derp::EmbeddedDerpRuntime;

use crate::config::PolicyConfig;
use crate::derp_config::DerpConfig;
use headscale_db::Database;

const NODE_EXPIRY_UPDATE_INTERVAL: Duration = Duration::from_secs(5);

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
    pub tls: TlsRuntimeConfig,
    pub oidc: OidcConfig,
    pub embedded_derp: EmbeddedDerpConfig,
    pub derp: Option<DerpConfig>,
    pub dns: Option<DnsConfigSpec>,
    pub policy: PolicyConfig,
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
                || "/var/www/.cache".to_string(),
                |path| path.display().to_string(),
            )
    }

    fn challenge_type_string(&self) -> String {
        non_empty_str(self.letsencrypt_challenge_type.as_deref())
            .unwrap_or("HTTP-01")
            .to_string()
    }
}

/// Run the control plane server.
pub(crate) async fn run_server(cfg: RunServerConfig) -> Result<()> {
    run_tailscale_wire_server(cfg).await
}

async fn run_tailscale_wire_server(cfg: RunServerConfig) -> Result<()> {
    let public_listeners = public_listener_plan(&cfg)?;
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
    let oidc = runtime_from_core_oidc(&cfg.oidc, server_url)
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
    let (dns_store, dns_extra_records_path) =
        dns_store_from_config(cfg.dns.clone()).context("load DNS runtime config")?;
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
    tracing::info!("Headscale-compatible Tailscale control plane ready");
    let serve_result = await_serve_handle(handle, local_grpc, remote_grpc).await;
    node_expiry_waker.abort();
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

fn dns_store_from_config(spec: Option<DnsConfigSpec>) -> Result<(Arc<DnsStore>, Option<PathBuf>)> {
    let Some(spec) = spec else {
        return Ok((Arc::new(DnsStore::new()), None));
    };
    let extra_records_path = spec
        .extra_records_path
        .clone()
        .filter(|path| !path.as_os_str().is_empty());
    let store = DnsStore::try_from_spec(spec).context("invalid [dns] config")?;
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
        ephemeral_node_inactivity_timeout: duration_nanos(cfg.ephemeral_node_inactivity_timeout),
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
    snapshot.tls.lets_encrypt.listen = non_empty_str(cfg.tls.letsencrypt_listen.as_deref())
        .unwrap_or("")
        .to_string();
    snapshot.tls.lets_encrypt.challenge_type = cfg.tls.challenge_type_string();
    snapshot.acme_url = non_empty_str(cfg.tls.acme_url.as_deref())
        .unwrap_or("")
        .to_string();
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

    snapshot.oidc.only_start_if_oidc_is_available = cfg.oidc.only_start_if_oidc_is_available;
    snapshot.oidc.issuer.clone_from(&cfg.oidc.issuer);
    snapshot.oidc.client_id.clone_from(&cfg.oidc.client_id);
    snapshot
        .oidc
        .client_secret
        .clone_from(&cfg.oidc.client_secret);
    snapshot.oidc.scope.clone_from(&cfg.oidc.scope);
    snapshot
        .oidc
        .extra_params
        .clone_from(&cfg.oidc.extra_params);
    snapshot
        .oidc
        .allowed_domains
        .clone_from(&cfg.oidc.allowed_domains);
    snapshot
        .oidc
        .allowed_users
        .clone_from(&cfg.oidc.allowed_users);
    snapshot
        .oidc
        .allowed_groups
        .clone_from(&cfg.oidc.allowed_groups);
    snapshot.oidc.email_verified_required = cfg.oidc.email_verified_required;
    snapshot.oidc.expiry = duration_nanos(cfg.oidc.expiry);
    snapshot.oidc.use_expiry_from_token = cfg.oidc.use_expiry_from_token;
    snapshot.oidc.pkce.enabled = cfg.oidc.pkce.enabled;
    snapshot.oidc.pkce.method.clone_from(&cfg.oidc.pkce.method);
    snapshot.policy.mode = cfg.policy.mode().to_string();
    snapshot.policy.path = cfg.policy.path.display().to_string();

    snapshot
}

fn tls_material_source(cfg: &RunServerConfig, sans: &SanConfig) -> Result<TlsMaterialSource> {
    if cfg.tls.letsencrypt_enabled() {
        anyhow::bail!(
            "tls_letsencrypt_hostname/ACME TLS is parsed but not implemented in headscale-rs yet"
        );
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
    server_url
        .trim()
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(['/', ':'])
        .next()
        .filter(|host| !host.is_empty())
        .unwrap_or("headscale-rs")
        .to_string()
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
    };
    use headscale_api::generated::{
        HealthRequest, headscale_service_client::HeadscaleServiceClient,
    };
    use headscale_api::oidc::{OidcAuthConfig, OidcPkceConfig, OidcPolicyConfig};
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
            tls: TlsRuntimeConfig::default(),
            oidc: OidcConfig::default(),
            embedded_derp: EmbeddedDerpConfig::default(),
            derp: None,
            dns: None,
            policy: PolicyConfig::default(),
            ephemeral_node_inactivity_timeout: Duration::from_secs(120),
        }
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
        let err = dns_store_from_config(Some(DnsConfigSpec::default())).unwrap_err();
        assert!(format!("{err:#}").contains("dns.base_domain must be set"));
        let (store, path) = dns_store_from_config(None).unwrap();
        assert!(path.is_none());
        assert_eq!(serde_json::to_string(&store.build(&[])).unwrap(), "{}");
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

        let (store, path) = dns_store_from_config(Some(DnsConfigSpec {
            magic_dns: false,
            override_local_dns: false,
            extra_records_path: Some(records_path.clone()),
            ..DnsConfigSpec::default()
        }))
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

        let err = dns_store_from_config(Some(DnsConfigSpec {
            magic_dns: false,
            override_local_dns: false,
            extra_records_path: Some(records_path),
            ..DnsConfigSpec::default()
        }))
        .unwrap_err();

        assert!(format!("{err:#}").contains("parse dns.extra_records_path"));

        let missing = dir.path().join("missing.json");
        let err = dns_store_from_config(Some(DnsConfigSpec {
            magic_dns: false,
            override_local_dns: false,
            extra_records_path: Some(missing),
            ..DnsConfigSpec::default()
        }))
        .unwrap_err();

        assert!(format!("{err:#}").contains("stat dns.extra_records_path"));

        let err = dns_store_from_config(Some(DnsConfigSpec {
            magic_dns: false,
            override_local_dns: false,
            extra_records_path: Some(dir.path().to_path_buf()),
            ..DnsConfigSpec::default()
        }))
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
        let (dns_store, extra_records_path) = dns_store_from_config(Some(dns_spec)).unwrap();
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
        assert!(
            dns.extra_records
                .iter()
                .any(|record| record.name == "ops.tail.example.org")
        );
        assert!(
            dns.extra_records
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
            tls: TlsRuntimeConfig::default(),
            oidc: OidcConfig::default(),
            embedded_derp: EmbeddedDerpConfig::default(),
            derp: None,
            dns: None,
            policy: PolicyConfig::default(),
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
            tls: TlsRuntimeConfig {
                cert_path: Some(material.cert_path.clone()),
                key_path: Some(material.key_path.clone()),
                ..TlsRuntimeConfig::default()
            },
            oidc: OidcConfig::default(),
            embedded_derp: EmbeddedDerpConfig::default(),
            derp: None,
            dns: None,
            policy: PolicyConfig::default(),
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
            embedded_derp: EmbeddedDerpConfig::default(),
            derp: None,
            dns: None,
            policy: PolicyConfig::database(),
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
        assert_eq!(snapshot.unix_socket_permission, 0o760);
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
            tls: TlsRuntimeConfig::default(),
            oidc: OidcConfig::default(),
            embedded_derp: EmbeddedDerpConfig::default(),
            derp: None,
            dns: None,
            policy: PolicyConfig::default(),
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
