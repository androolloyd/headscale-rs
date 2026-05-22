//! Server mode - runs the control plane.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};

use headscale_api::Server;
use headscale_api::admin::{
    PersistentMachineAdmin, PersistentOidcRegistrationHandler, PersistentPreauthAdmin,
    PersistentUserAdmin,
};
use headscale_api::dns::DnsStore;
use headscale_api::oidc::{OidcAuthRuntime, runtime_from_core_oidc};
use headscale_api::policy::PolicyStore;
use headscale_api::tailscale_wire::tls::SanConfig;
use headscale_api::tailscale_wire::{
    AllocError, DerpMap, IpAllocator, KnockConfig, MachineRegistry, RegistrationCache,
    ServerNoiseKey, WireState, serve,
};
use headscale_core::MeshCoordinator;
use headscale_core::config::OidcConfig;
use headscale_db::Database;
use headscale_payments::Ledger;
use headscale_resources::ResourceRegistry;

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
    if oidc_is_configured(&cfg.oidc) {
        return run_tailscale_wire_server(cfg).await;
    }

    run_legacy_server(&cfg.listen, &cfg.db_path, &cfg.mesh_cidr).await
}

async fn run_legacy_server(listen: &str, db_path: &Path, mesh_cidr: &str) -> Result<()> {
    tracing::info!("Starting headscale control plane");
    tracing::info!("  Listen: {}", listen);
    tracing::info!("  Database: {}", db_path.display());
    tracing::info!("  Mesh CIDR: {}", mesh_cidr);

    // Ensure database directory exists
    if let Some(parent) = db_path.parent()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("Failed to create database directory: {}", parent.display())
        })?;
    }

    // Create core components
    let mesh = Arc::new(MeshCoordinator::new(mesh_cidr));
    let ledger = Arc::new(Ledger::new());
    let resources = Arc::new(ResourceRegistry::new());

    // Parse listen address
    let listen_addr = listen
        .parse()
        .with_context(|| format!("Invalid listen address: {listen}"))?;

    // Create and run server
    let server = Server::new(mesh, ledger, resources, listen_addr);

    tracing::info!("Control plane ready");
    server.run().await.context("Server error")?;

    Ok(())
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

    let server_url = cfg.server_url.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "server.server_url is required when OIDC is configured so /oidc/callback can be advertised"
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
    let runtime = build_persistent_wire_runtime(
        db.pool(),
        &cfg.state_dir,
        server_url,
        runtime_from_core_oidc(&cfg.oidc, server_url)
            .await
            .context("build OIDC runtime")?,
    )
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
    let serve_cfg = serve::ServeConfig {
        http_addr,
        https_addr,
        state_dir: cfg.state_dir,
        sans: SanConfig::with_hostname(tls_hostname),
        oidc: runtime.oidc,
    };

    let handle = serve::serve(runtime.state, serve_cfg, axum::Router::new())
        .await
        .context("start Tailscale wire listeners")?;
    tracing::info!("Headscale-compatible Tailscale control plane ready");
    await_serve_handle(handle).await
}

struct PersistentWireRuntime {
    state: WireState,
    oidc: Option<OidcAuthRuntime>,
}

async fn build_persistent_wire_runtime(
    pool: &sqlx::SqlitePool,
    state_dir: &Path,
    server_url: &str,
    oidc: Option<OidcAuthRuntime>,
) -> Result<PersistentWireRuntime> {
    let users = Arc::new(PersistentUserAdmin::new(pool.clone()));
    let preauth =
        Arc::new(PersistentPreauthAdmin::new(pool.clone()).with_user_admin(users.clone()));
    let machines =
        Arc::new(PersistentMachineAdmin::new(pool.clone()).with_user_admin(users.clone()));
    let wire_registry = Arc::new(MachineRegistry::new());
    let registration_cache = Arc::new(RegistrationCache::new());
    let policy = Arc::new(PolicyStore::new());
    let hydrated = machines
        .hydrate_wire_registry(&wire_registry)
        .await
        .context("hydrate wire registry from SQLite nodes")?;
    tracing::info!(
        nodes = hydrated,
        "hydrated persisted nodes into wire registry"
    );
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
        ip_allocator: Arc::new(CgnatIpAllocator),
        machines: wire_registry,
        derp_map: Arc::new(DerpMap::default()),
        policy,
        knock: KnockConfig::disabled(),
        dns: Arc::new(DnsStore::new()),
        public_control_url: Some(server_url.to_string()),
        registration_cache,
    };

    Ok(PersistentWireRuntime { state, oidc })
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

fn oidc_is_configured(oidc: &OidcConfig) -> bool {
    !oidc.issuer.trim().is_empty()
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

struct CgnatIpAllocator;

impl IpAllocator for CgnatIpAllocator {
    fn allocate(&self, node_key_hex: &str) -> std::result::Result<Ipv4Addr, AllocError> {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in node_key_hex.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let host = ((h as u32) % ((1u32 << 22) - 3)) + 2;
        const CGNAT_BASE: u32 = 0x6440_0000;
        Ok(Ipv4Addr::from((CGNAT_BASE | host).to_be_bytes()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use headscale_api::oidc::{OidcAuthConfig, OidcPkceConfig, OidcPolicyConfig};
    use std::collections::BTreeMap;

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
    fn oidc_config_detection_uses_issuer() {
        assert!(!oidc_is_configured(&OidcConfig::default()));
        assert!(oidc_is_configured(&OidcConfig {
            issuer: "https://issuer.example".into(),
            ..OidcConfig::default()
        }));
    }
}
