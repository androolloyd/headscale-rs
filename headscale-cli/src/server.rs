//! Server mode - runs the control plane.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use anyhow::{Context, Result};
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
use headscale_api::dns::{DnsConfigSpec, DnsStore, spawn_extra_records_watcher};
use headscale_api::grpc::upstream::HeadscaleAdminService;
use headscale_api::grpc_gateway;
use headscale_api::oidc::{OidcAuthRuntime, runtime_from_core_oidc};
use headscale_api::policy::{PolicyStore, parse_hujson_policy};
use headscale_api::tailscale_wire::tls;
use headscale_api::tailscale_wire::tls::SanConfig;
use headscale_api::tailscale_wire::{
    AllocError, DerpMap, DerpRegion, DerpRegionNode, IpAllocator, KnockConfig, MachineRegistry,
    PingTracker, RegistrationCache, ServerNoiseKey, WireState, serve,
};
use headscale_core::config::{EmbeddedDerpConfig, OidcConfig};
use headscale_core::derp::EmbeddedDerpRuntime;
use headscale_db::Database;

#[derive(Debug, Clone)]
pub(crate) struct RunServerConfig {
    pub listen: String,
    pub db_path: PathBuf,
    pub mesh_cidr: String,
    pub server_url: Option<String>,
    pub state_dir: PathBuf,
    pub https_listen: Option<String>,
    pub tls_hostname: Option<String>,
    pub unix_socket: PathBuf,
    pub unix_socket_permission: u32,
    pub grpc_listen_addr: String,
    pub grpc_allow_insecure: bool,
    pub oidc: OidcConfig,
    pub embedded_derp: EmbeddedDerpConfig,
    pub dns: Option<DnsConfigSpec>,
}

/// Run the control plane server.
pub(crate) async fn run_server(cfg: RunServerConfig) -> Result<()> {
    run_tailscale_wire_server(cfg).await
}

async fn run_tailscale_wire_server(cfg: RunServerConfig) -> Result<()> {
    tracing::info!("Starting headscale-compatible Tailscale control plane");
    tracing::info!("  Listen: {}", cfg.listen);
    tracing::info!(
        "  HTTPS: {}",
        cfg.https_listen.as_deref().unwrap_or("<disabled>")
    );
    tracing::info!("  Database: {}", cfg.db_path.display());
    tracing::info!("  State dir: {}", cfg.state_dir.display());
    tracing::info!("  IPv4 prefix: {}", cfg.mesh_cidr);
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
    let derp_map = derp_map_from_embedded_config(embedded_derp_runtime.config());
    let (dns_store, dns_extra_records_path) =
        dns_store_from_config(cfg.dns.clone()).context("load DNS runtime config")?;
    let runtime = build_persistent_wire_runtime_with_dns(
        db.pool(),
        &cfg.state_dir,
        server_url,
        &cfg.mesh_cidr,
        oidc,
        derp_map,
        dns_store.clone(),
    )
    .await?;

    let http_addr = parse_socket_addr(&cfg.listen, "listen")?;
    let https_addr = cfg
        .https_listen
        .as_deref()
        .map(|addr| parse_socket_addr(addr, "https_listen"))
        .transpose()?;
    let grpc_addr = parse_socket_addr(&cfg.grpc_listen_addr, "grpc_listen_addr")?;
    let tls_hostname = cfg
        .tls_hostname
        .clone()
        .unwrap_or_else(|| hostname_from_server_url(server_url));
    let sans = SanConfig::with_hostname(tls_hostname);
    let extra_routes = production_extra_routes(&runtime);
    let serve_cfg = serve::ServeConfig {
        http_addr,
        https_addr,
        state_dir: cfg.state_dir.clone(),
        sans: sans.clone(),
        oidc: runtime.oidc,
    };
    let local_grpc_listener =
        bind_unix_grpc_listener(&cfg.unix_socket, cfg.unix_socket_permission).await?;
    let remote_grpc_security = remote_grpc_security(&cfg, &sans)?;
    let remote_grpc_listener = match remote_grpc_security {
        Some(security) => Some((
            bind_tcp_grpc_listener(grpc_addr).await?,
            grpc_addr,
            security,
        )),
        None => None,
    };

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
    if let Some(handle) = dns_extra_records_watcher {
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
    let extra_records_path = spec.extra_records_path.clone();
    let store = DnsStore::try_from_spec(spec).context("invalid [dns] config")?;
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
        oidc,
        derp_map,
        Arc::new(DnsStore::new()),
    )
    .await
}

async fn build_persistent_wire_runtime_with_dns(
    pool: &sqlx::SqlitePool,
    state_dir: &Path,
    server_url: &str,
    mesh_cidr: &str,
    oidc: Option<OidcAuthRuntime>,
    derp_map: DerpMap,
    dns: Arc<DnsStore>,
) -> Result<PersistentWireRuntime> {
    let users = Arc::new(PersistentUserAdmin::new(pool.clone()));
    let api_keys = Arc::new(PersistentApiKeyAdmin::new(pool.clone()));
    let preauth =
        Arc::new(PersistentPreauthAdmin::new(pool.clone()).with_user_admin(users.clone()));
    let machines =
        Arc::new(PersistentMachineAdmin::new(pool.clone()).with_user_admin(users.clone()));
    let wire_registry = Arc::new(MachineRegistry::new());
    let registration_cache = Arc::new(RegistrationCache::new());
    let ip_allocator: Arc<dyn IpAllocator> = Arc::new(CidrIpAllocator::from_cidr(mesh_cidr)?);
    let policy = Arc::new(PolicyStore::new());
    let policy_loaded = load_persisted_policy(pool, &policy).await?;
    tracing::info!(
        loaded = policy_loaded,
        "loaded persisted policy into wire runtime"
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
    .with_policy_pool(pool.clone())
    .with_registration_cache(registration_cache.clone())
    .with_wire_registry(wire_registry.clone())
    .with_ip_allocator(ip_allocator.clone());
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
        derp_map: Arc::new(derp_map),
        policy,
        knock: KnockConfig::disabled(),
        dns,
        public_control_url: Some(server_url.to_string()),
        registration_cache,
        pings: Arc::new(PingTracker::new()),
    };

    Ok(PersistentWireRuntime {
        state,
        oidc,
        admin_service,
    })
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
        ipv4: String::new(),
        ipv6: String::new(),
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
    if cfg.https_listen.is_some() {
        format!("{} (TLS)", cfg.grpc_listen_addr)
    } else if cfg.grpc_allow_insecure {
        format!("{} (insecure)", cfg.grpc_listen_addr)
    } else {
        "<disabled>".to_string()
    }
}

fn remote_grpc_security(
    cfg: &RunServerConfig,
    sans: &SanConfig,
) -> Result<Option<RemoteGrpcSecurity>> {
    if cfg.https_listen.is_some() {
        let material = tls::load_or_generate(&cfg.state_dir, sans)
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
    let serve::ServeHandle { http, https, .. } = handle;
    match (https, remote_grpc) {
        (Some(https), Some(remote_grpc)) => {
            tokio::select! {
                result = http => flatten_listener_result(result, "http"),
                result = https => flatten_listener_result(result, "https"),
                result = local_grpc => flatten_anyhow_task_result(result, "local grpc"),
                result = remote_grpc => flatten_anyhow_task_result(result, "remote grpc"),
            }
        }
        (Some(https), None) => {
            tokio::select! {
                result = http => flatten_listener_result(result, "http"),
                result = https => flatten_listener_result(result, "https"),
                result = local_grpc => flatten_anyhow_task_result(result, "local grpc"),
            }
        }
        (None, Some(remote_grpc)) => {
            tokio::select! {
                result = http => flatten_listener_result(result, "http"),
                result = local_grpc => flatten_anyhow_task_result(result, "local grpc"),
                result = remote_grpc => flatten_anyhow_task_result(result, "remote grpc"),
            }
        }
        (None, None) => {
            tokio::select! {
                result = http => flatten_listener_result(result, "http"),
                result = local_grpc => flatten_anyhow_task_result(result, "local grpc"),
            }
        }
    }
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

#[derive(Debug, Clone)]
struct CidrIpAllocator {
    network: u32,
    usable_hosts: u64,
}

impl CidrIpAllocator {
    fn from_cidr(cidr: &str) -> Result<Self> {
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
        let total_hosts = if host_bits == 32 {
            1u64 << 32
        } else {
            1u64 << host_bits
        };
        let usable_hosts = total_hosts.saturating_sub(3);
        if usable_hosts == 0 {
            anyhow::bail!(
                "invalid server.mesh_cidr {cidr:?}: prefix must leave assignable host addresses"
            );
        }

        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << host_bits
        };
        Ok(Self {
            network: u32::from(addr) & mask,
            usable_hosts,
        })
    }
}

impl IpAllocator for CidrIpAllocator {
    fn allocate(&self, node_key_hex: &str) -> std::result::Result<Ipv4Addr, AllocError> {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in node_key_hex.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let host = (h % self.usable_hosts) + 2;
        Ok(Ipv4Addr::from(self.network + host as u32))
    }
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
    fn dns_store_from_config_validates_magic_dns_base_domain() {
        let err = dns_store_from_config(Some(DnsConfigSpec::default())).unwrap_err();
        assert!(format!("{err:#}").contains("dns.base_domain must be set"));
        let (store, path) = dns_store_from_config(None).unwrap();
        assert!(path.is_none());
        assert_eq!(serde_json::to_string(&store.build(&[])).unwrap(), "{}");
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
            DerpMap::default(),
            dns_store,
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
            server_url: Some("https://headscale.example".into()),
            state_dir: dir.path().join("state"),
            https_listen: None,
            tls_hostname: None,
            unix_socket: dir.path().join("state/headscale.sock"),
            unix_socket_permission: 0o700,
            grpc_listen_addr: ":50443".into(),
            grpc_allow_insecure: false,
            oidc: OidcConfig::default(),
            embedded_derp: EmbeddedDerpConfig::default(),
            dns: None,
        };
        let sans = SanConfig::with_hostname("headscale.example");

        assert!(remote_grpc_security(&cfg, &sans).unwrap().is_none());
        cfg.grpc_allow_insecure = true;
        assert!(matches!(
            remote_grpc_security(&cfg, &sans).unwrap(),
            Some(RemoteGrpcSecurity::Insecure)
        ));
        cfg.grpc_allow_insecure = false;
        cfg.https_listen = Some("127.0.0.1:0".into());
        assert!(matches!(
            remote_grpc_security(&cfg, &sans).unwrap(),
            Some(RemoteGrpcSecurity::Tls(_))
        ));
    }

    #[test]
    fn socket_addr_parser_accepts_upstream_leading_colon_listens() {
        assert_eq!(
            parse_socket_addr(":50443", "grpc_listen_addr").unwrap(),
            "0.0.0.0:50443".parse::<SocketAddr>().unwrap()
        );
    }

    #[tokio::test]
    async fn non_oidc_server_requires_public_server_url_before_binding() {
        let dir = tempfile::tempdir().unwrap();
        let err = run_server(RunServerConfig {
            listen: "127.0.0.1:0".into(),
            db_path: dir.path().join("db.sqlite"),
            mesh_cidr: "100.64.0.0/10".into(),
            server_url: None,
            state_dir: dir.path().join("state"),
            https_listen: None,
            tls_hostname: None,
            unix_socket: dir.path().join("state/headscale.sock"),
            unix_socket_permission: 0o700,
            grpc_listen_addr: "127.0.0.1:0".into(),
            grpc_allow_insecure: false,
            oidc: OidcConfig::default(),
            embedded_derp: EmbeddedDerpConfig::default(),
            dns: None,
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
        assert_eq!(wire.ipv4.to_string(), "100.64.0.9");
        assert_eq!(wire.os, "linux");
        assert_eq!(wire.os_version, "1.80.0");
        assert_eq!(wire.available_routes, vec!["10.0.0.0/24"]);
        assert_eq!(wire.approved_routes, vec!["10.0.0.0/24"]);
        assert_eq!(wire.register_method, 2);
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
    fn cidr_allocator_rejects_invalid_or_tiny_prefixes() {
        assert!(CidrIpAllocator::from_cidr("not-a-cidr").is_err());
        assert!(CidrIpAllocator::from_cidr("100.64.0.0/32").is_err());
    }
}
