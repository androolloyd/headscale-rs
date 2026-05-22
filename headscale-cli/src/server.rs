//! Server mode - runs the control plane.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};

use headscale_api::admin::{
    PersistentApiKeyAdmin, PersistentMachineAdmin, PersistentOidcRegistrationHandler,
    PersistentPreauthAdmin, PersistentUserAdmin,
};
use headscale_api::dns::DnsStore;
use headscale_api::grpc::upstream::HeadscaleAdminService;
use headscale_api::grpc_gateway;
use headscale_api::oidc::{OidcAuthRuntime, runtime_from_core_oidc};
use headscale_api::policy::{PolicyStore, parse_hujson_policy};
use headscale_api::tailscale_wire::tls::SanConfig;
use headscale_api::tailscale_wire::{
    AllocError, DerpMap, IpAllocator, KnockConfig, MachineRegistry, RegistrationCache,
    ServerNoiseKey, WireState, serve,
};
use headscale_core::config::OidcConfig;
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
    pub oidc: OidcConfig,
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
    let runtime =
        build_persistent_wire_runtime(db.pool(), &cfg.state_dir, server_url, &cfg.mesh_cidr, oidc)
            .await?;

    let http_addr = parse_socket_addr(&cfg.listen, "listen")?;
    let https_addr = cfg
        .https_listen
        .as_deref()
        .map(|addr| parse_socket_addr(addr, "https_listen"))
        .transpose()?;
    let tls_hostname = cfg
        .tls_hostname
        .unwrap_or_else(|| hostname_from_server_url(server_url));
    let extra_routes = production_extra_routes(&runtime);
    let serve_cfg = serve::ServeConfig {
        http_addr,
        https_addr,
        state_dir: cfg.state_dir,
        sans: SanConfig::with_hostname(tls_hostname),
        oidc: runtime.oidc,
    };

    let handle = serve::serve(runtime.state, serve_cfg, extra_routes)
        .await
        .context("start Tailscale wire listeners")?;
    tracing::info!("Headscale-compatible Tailscale control plane ready");
    await_serve_handle(handle).await
}

struct PersistentWireRuntime {
    state: WireState,
    oidc: Option<OidcAuthRuntime>,
    admin_service: HeadscaleAdminService,
}

async fn build_persistent_wire_runtime(
    pool: &sqlx::SqlitePool,
    state_dir: &Path,
    server_url: &str,
    mesh_cidr: &str,
    oidc: Option<OidcAuthRuntime>,
) -> Result<PersistentWireRuntime> {
    let users = Arc::new(PersistentUserAdmin::new(pool.clone()));
    let api_keys = Arc::new(PersistentApiKeyAdmin::new(pool.clone()));
    let preauth =
        Arc::new(PersistentPreauthAdmin::new(pool.clone()).with_user_admin(users.clone()));
    let machines =
        Arc::new(PersistentMachineAdmin::new(pool.clone()).with_user_admin(users.clone()));
    let wire_registry = Arc::new(MachineRegistry::new());
    let registration_cache = Arc::new(RegistrationCache::new());
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
    .with_wire_registry(wire_registry.clone());
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
        ip_allocator: Arc::new(CidrIpAllocator::from_cidr(mesh_cidr)?),
        machines: wire_registry,
        registration_store: Some(machines),
        derp_map: Arc::new(DerpMap::default()),
        policy,
        knock: KnockConfig::disabled(),
        dns: Arc::new(DnsStore::new()),
        public_control_url: Some(server_url.to_string()),
        registration_cache,
    };

    Ok(PersistentWireRuntime {
        state,
        oidc,
        admin_service,
    })
}

fn production_extra_routes(runtime: &PersistentWireRuntime) -> axum::Router {
    grpc_gateway::router(runtime.admin_service.clone())
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
    value
        .parse()
        .with_context(|| format!("Invalid {field} address: {value}"))
}

async fn await_serve_handle(handle: serve::ServeHandle) -> Result<()> {
    let serve::ServeHandle { http, https, .. } = handle;
    match https {
        Some(https) => {
            tokio::select! {
                result = http => flatten_listener_result(result, "http"),
                result = https => flatten_listener_result(result, "https"),
            }
        }
        None => flatten_listener_result(http.await, "http"),
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
        http::{Request, StatusCode, header},
    };
    use headscale_api::oidc::{OidcAuthConfig, OidcPkceConfig, OidcPolicyConfig};
    use serde_json::Value;
    use std::collections::BTreeMap;
    use tower::ServiceExt;

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
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing_auth.status(), StatusCode::UNAUTHORIZED);

        let authed = app
            .oneshot(
                Request::builder()
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
            oidc: OidcConfig::default(),
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
