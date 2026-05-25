use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post, put},
};
use clap::{Parser, ValueEnum};
use headscale_api::{
    dns::{DnsConfigSpec, DnsStore, parse_extra_records},
    policy::{NodeView, PolicyStore, parse_hujson_policy},
    tailscale_wire::{
        AllocError, DerpMap, IpAllocator, KnockConfig, MachineRecord, MachineRegistry,
        MapResponseDebugStore, PingTracker, PreauthRedeemer, RedeemError, RedeemOk,
        RegistrationCache, ServerNoiseKey, WireState, derp_config,
        routes::{DebugRoutes, normalize_routes},
        serve, spawn_offline_connection_cleanup, spawn_route_health_probe,
        wire::{DerpRegion, DerpRegionNode, DnsRecord, DnsResolver},
        BATCHER_OFFLINE_CLEANUP_INTERVAL, BATCHER_OFFLINE_CLEANUP_THRESHOLD,
    },
};
use headscale_core::{config::EmbeddedDerpConfig, derp::EmbeddedDerpRuntime};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

type DnsResolverAddrsBySuffix = HashMap<String, Vec<String>>;
type DnsResolversBySuffix = HashMap<String, Vec<DnsResolver>>;

#[derive(Debug, Parser)]
#[command(
    name = "headscale-rs-real-client-harness",
    about = "Run the headscale-rs Tailscale wire surface for stock-client parity tests"
)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:51821", env = "HSRS_HARNESS_HTTP")]
    http: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:443", env = "HSRS_HARNESS_HTTPS")]
    https: SocketAddr,
    #[arg(long, default_value = "127.0.0.1:0", env = "HSRS_HARNESS_METRICS")]
    metrics: SocketAddr,
    #[arg(long, env = "HSRS_HARNESS_NO_HTTPS")]
    no_https: bool,
    #[arg(
        long,
        default_value = "headscale-rs.test",
        env = "HSRS_HARNESS_HOSTNAME"
    )]
    hostname: String,
    #[arg(long, env = "HSRS_HARNESS_PUBLIC_URL")]
    public_url: Option<String>,
    #[arg(
        long,
        default_value = "target/real-client/headscale-rs",
        env = "HSRS_HARNESS_STATE_DIR"
    )]
    state_dir: PathBuf,
    #[arg(long, env = "HSRS_HARNESS_DERP_MAP")]
    derp_map: Option<PathBuf>,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP")]
    embedded_derp: bool,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_HOSTNAME")]
    embedded_derp_hostname: Option<String>,
    #[arg(
        long,
        default_value_t = 443,
        env = "HSRS_HARNESS_EMBEDDED_DERP_DERP_PORT"
    )]
    embedded_derp_derp_port: u16,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_STUN_ADDR")]
    embedded_derp_stun_addr: Option<SocketAddr>,
    #[arg(
        long,
        default_value_t = 900,
        env = "HSRS_HARNESS_EMBEDDED_DERP_REGION_ID"
    )]
    embedded_derp_region_id: u16,
    #[arg(
        long,
        default_value = "embedded",
        env = "HSRS_HARNESS_EMBEDDED_DERP_REGION_CODE"
    )]
    embedded_derp_region_code: String,
    #[arg(
        long,
        default_value = "Embedded headscale-rs DERP sidecar",
        env = "HSRS_HARNESS_EMBEDDED_DERP_REGION_NAME"
    )]
    embedded_derp_region_name: String,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_OMIT_DEFAULT_REGIONS")]
    embedded_derp_omit_default_regions: bool,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_INSECURE_FOR_TESTS")]
    embedded_derp_insecure_for_tests: bool,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_IPV4")]
    embedded_derp_ipv4: Option<String>,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_IPV6")]
    embedded_derp_ipv6: Option<String>,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_STUN_ONLY")]
    embedded_derp_stun_only: bool,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_DERPER_BINARY")]
    embedded_derp_derper_binary: Option<PathBuf>,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_DERPER_LISTEN_ADDR")]
    embedded_derp_derper_listen_addr: Option<SocketAddr>,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_DERPER_CONFIG_PATH")]
    embedded_derp_derper_config_path: Option<PathBuf>,
    #[arg(
        long,
        default_value = "letsencrypt",
        env = "HSRS_HARNESS_EMBEDDED_DERP_DERPER_CERT_MODE"
    )]
    embedded_derp_derper_cert_mode: String,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_DERPER_CERT_DIR")]
    embedded_derp_derper_cert_dir: Option<PathBuf>,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_VERIFY_CLIENT_URL")]
    embedded_derp_verify_client_url: Option<String>,
    #[arg(long, env = "HSRS_HARNESS_EMBEDDED_DERP_VERIFY_CLIENTS")]
    embedded_derp_verify_clients: bool,
    #[arg(long, env = "HSRS_HARNESS_POLICY")]
    policy: Option<PathBuf>,
    #[arg(long, env = "HSRS_HARNESS_BASE_DOMAIN")]
    base_domain: Option<String>,
    #[arg(long, env = "HSRS_HARNESS_DNS_EXTRA_RECORDS_JSON")]
    dns_extra_records_json: Option<String>,
    #[arg(long, env = "HSRS_HARNESS_DNS_NAMESERVERS_JSON")]
    dns_nameservers_json: Option<String>,
    #[arg(long, env = "HSRS_HARNESS_DNS_SPLIT_NAMESERVERS_JSON")]
    dns_split_nameservers_json: Option<String>,
    #[arg(long, env = "HSRS_HARNESS_DNS_FALLBACK_NAMESERVERS_JSON")]
    dns_fallback_nameservers_json: Option<String>,
    #[arg(long, env = "HSRS_HARNESS_DNS_OVERRIDE_LOCAL")]
    dns_override_local: Option<bool>,
    #[arg(
        long,
        value_enum,
        default_value_t = IpFamilies::Ipv4Only,
        env = "HSRS_HARNESS_IP_FAMILIES"
    )]
    ip_families: IpFamilies,
    #[arg(long = "authkey", value_name = "KEY=USER")]
    authkeys: Vec<String>,
    #[arg(
        long,
        default_value_t = 0,
        env = "HSRS_HARNESS_ROUTE_HEALTH_PROBE_INTERVAL_SECS"
    )]
    route_health_probe_interval_secs: u64,
    #[arg(
        long,
        default_value_t = 0,
        env = "HSRS_HARNESS_ROUTE_HEALTH_PROBE_TIMEOUT_SECS"
    )]
    route_health_probe_timeout_secs: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum IpFamilies {
    Ipv4Only,
    Ipv6Only,
    DualStack,
}

#[derive(Clone)]
struct AppState {
    redeemer: Arc<HarnessRedeemer>,
    machines: Arc<MachineRegistry>,
    policy: Arc<PolicyStore>,
    registration_cache: Arc<RegistrationCache>,
    derp_verify: Arc<DerpVerifyLog>,
}

#[derive(Default)]
struct HarnessRedeemer {
    keys: RwLock<HashMap<String, HarnessKey>>,
}

#[derive(Default)]
struct DerpVerifyLog {
    requests: AtomicU64,
    allowed: AtomicU64,
    denied: AtomicU64,
}

#[derive(Clone)]
struct HarnessKey {
    ok: RedeemOk,
    reusable: bool,
    used: bool,
    expired: bool,
}

#[async_trait]
impl PreauthRedeemer for HarnessRedeemer {
    async fn redeem(&self, key: &str) -> Result<RedeemOk, RedeemError> {
        let mut keys = self.keys.write();
        let Some(entry) = keys.get_mut(key) else {
            return Err(RedeemError::Unknown);
        };
        if entry.expired {
            return Err(RedeemError::Expired);
        }
        if entry.used && !entry.reusable {
            return Err(RedeemError::AlreadyUsed);
        }
        entry.used = true;
        Ok(entry.ok.clone())
    }

    async fn lookup(&self, key: &str) -> Option<RedeemOk> {
        self.keys.read().get(key).map(|entry| entry.ok.clone())
    }
}

impl HarnessRedeemer {
    fn insert(&self, key: String, req: MintPreauthRequest) -> MintPreauthResponse {
        let ok = RedeemOk::for_user(req.user.unwrap_or_else(|| "integration".to_string()))
            .ephemeral(req.ephemeral)
            .tags(req.tags);
        let entry = HarnessKey {
            ok,
            reusable: req.reusable,
            used: false,
            expired: req.expired,
        };
        self.keys.write().insert(key.clone(), entry);
        MintPreauthResponse { key }
    }
}

struct HarnessIpAllocator {
    families: IpFamilies,
}

impl IpAllocator for HarnessIpAllocator {
    fn allocate(&self, node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
        let h = stable_hash(node_key_hex);
        let host = ((h as u32) % ((1u32 << 22) - 3)) + 2;
        const CGNAT_BASE: u32 = 0x6440_0000;
        Ok(Ipv4Addr::from((CGNAT_BASE | host).to_be_bytes()))
    }

    fn ipv4_enabled(&self) -> bool {
        matches!(self.families, IpFamilies::Ipv4Only | IpFamilies::DualStack)
    }

    fn allocate_ipv6(&self, node_key_hex: &str) -> Result<Option<Ipv6Addr>, AllocError> {
        if !matches!(self.families, IpFamilies::Ipv6Only | IpFamilies::DualStack) {
            return Ok(None);
        }

        let host = (u128::from(stable_hash(node_key_hex)) % ((1u128 << 80) - 3)) + 2;
        let addr = 0xfd7a_115c_a1e0_0000_0000_0000_0000_0000u128 | host;
        Ok(Some(Ipv6Addr::from(addr)))
    }

    fn ipv6_enabled(&self) -> bool {
        matches!(self.families, IpFamilies::Ipv6Only | IpFamilies::DualStack)
    }
}

fn stable_hash(value: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in value.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[derive(Debug, Deserialize)]
struct MintPreauthRequest {
    key: Option<String>,
    user: Option<String>,
    #[serde(default)]
    reusable: bool,
    #[serde(default)]
    ephemeral: bool,
    #[serde(default)]
    expired: bool,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Serialize)]
struct MintPreauthResponse {
    key: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
    machines: usize,
    policy_loaded: bool,
}

#[derive(Debug, Serialize)]
struct MachineSummary {
    node_key: String,
    machine_key: String,
    user: String,
    hostname: String,
    ipv4: String,
    ipv6: String,
    addresses: Vec<String>,
    ephemeral: bool,
    forced_tags: Vec<String>,
    available_routes: Vec<String>,
    approved_routes: Vec<String>,
    endpoints: Vec<String>,
    disco_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SetApprovedRoutesRequest {
    routes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SetTagsRequest {
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterPendingRequest {
    #[serde(default = "default_user")]
    user: String,
}

#[derive(Debug, Deserialize)]
struct DerpAdmitClientRequest {
    #[serde(rename = "NodePublic", default)]
    node_public: Option<String>,
    #[serde(rename = "Source", default)]
    source: Option<IpAddr>,
}

#[derive(Debug, Serialize)]
struct DerpAdmitClientResponse {
    #[serde(rename = "Allow")]
    allow: bool,
}

#[derive(Debug, Serialize)]
struct DerpVerifyLogResponse {
    requests: u64,
    allowed: u64,
    denied: u64,
}

#[derive(Debug, Serialize)]
struct StartupInfo {
    http: String,
    https: Option<String>,
    metrics: Option<String>,
    public_url: String,
    tls_cert_path: Option<String>,
    embedded_derp: Option<EmbeddedDerpStartup>,
    harness_routes: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct EmbeddedDerpStartup {
    region_id: u16,
    derp_port: u16,
    stun_addr: Option<String>,
    sidecar_status: Option<String>,
    verify_client_url: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,headscale_api=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let redeemer = Arc::new(HarnessRedeemer::default());
    for seed in &args.authkeys {
        let (key, user) = seed
            .split_once('=')
            .with_context(|| format!("--authkey must be KEY=USER, got {seed:?}"))?;
        redeemer.insert(
            key.to_string(),
            MintPreauthRequest {
                key: Some(key.to_string()),
                user: Some(user.to_string()),
                reusable: true,
                ephemeral: false,
                expired: false,
                tags: Vec::new(),
            },
        );
    }

    let policy = Arc::new(PolicyStore::new());
    if let Some(path) = &args.policy {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read policy {}", path.display()))?;
        load_policy(&policy, raw)?;
    }

    let machines = Arc::new(MachineRegistry::new());
    let dns_extra_records = parse_dns_extra_records(args.dns_extra_records_json.as_deref())?;
    let (nameservers, nameserver_resolvers) =
        parse_dns_resolvers_json(args.dns_nameservers_json.as_deref())?;
    let (restricted_nameservers, restricted_resolvers) =
        parse_dns_split_resolvers_json(args.dns_split_nameservers_json.as_deref())?;
    let (fallback_nameservers, fallback_resolvers) =
        parse_dns_resolvers_json(args.dns_fallback_nameservers_json.as_deref())?;
    let dns = Arc::new(DnsStore::from_spec(DnsConfigSpec {
        magic_dns: args.base_domain.is_some(),
        base_domain: args.base_domain.clone().unwrap_or_default(),
        override_local_dns: args.dns_override_local.unwrap_or(false),
        nameservers,
        nameserver_resolvers,
        restricted_nameservers,
        restricted_resolvers,
        extra_records: dns_extra_records,
        fallback_nameservers,
        fallback_resolvers,
        ..DnsConfigSpec::default()
    }));
    let public_url = args
        .public_url
        .clone()
        .unwrap_or_else(|| format!("https://{}", args.hostname));
    let embedded_derp_runtime = if args.embedded_derp {
        let cfg = embedded_derp_config(&args)?;
        Some(EmbeddedDerpRuntime::start_with_state_dir(cfg, &args.state_dir).await?)
    } else {
        None
    };
    let derp_map = headscale_api::tailscale_wire::DerpMapStore::shared(load_runtime_derp_map(
        args.derp_map.as_ref(),
        embedded_derp_runtime.as_ref(),
    )?);
    let embedded_derp_startup = embedded_derp_runtime
        .as_ref()
        .map(embedded_derp_startup_info);

    let registration_cache = Arc::new(RegistrationCache::new());
    let derp_verify = Arc::new(DerpVerifyLog::default());
    let state = WireState {
        server_noise_key: Arc::new(ServerNoiseKey::load_or_generate(&args.state_dir)?),
        preauth: redeemer.clone(),
        ip_allocator: Arc::new(HarnessIpAllocator {
            families: args.ip_families,
        }),
        machines: machines.clone(),
        registration_store: None,
        derp_map,
        policy: policy.clone(),
        knock: KnockConfig::disabled(),
        dns,
        public_control_url: Some(public_url.clone()),
        runtime_config: Arc::new(headscale_api::tailscale_wire::RuntimeConfigSnapshot::default()),
        registration_cache: registration_cache.clone(),
        pings: Arc::new(PingTracker::new()),
        mapresponse_debug: Arc::new(MapResponseDebugStore::disabled()),
    };

    let app_state = AppState {
        redeemer,
        machines,
        policy,
        registration_cache,
        derp_verify,
    };
    let extra_routes = harness_router(app_state);
    let state_dir = args.state_dir;
    let sans = headscale_api::tailscale_wire::tls::SanConfig::with_hostname(args.hostname);
    let cfg = serve::ServeConfig {
        http_addr: Some(args.http),
        https_addr: (!args.no_https).then_some(args.https),
        state_dir: state_dir.clone(),
        sans: sans.clone(),
        tls_source: headscale_api::tailscale_wire::tls::TlsMaterialSource::SelfSigned {
            state_dir,
            sans,
        },
        trusted_proxies: serve::TrustedProxyConfig::default(),
        oidc: None,
        metrics_addr: Some(args.metrics),
        acme_http01: None,
        acme_http01_host: None,
        acme_http01_addr: None,
    };
    let route_health_probe = spawn_route_health_probe(
        state.clone(),
        Duration::from_secs(args.route_health_probe_interval_secs),
        Duration::from_secs(args.route_health_probe_timeout_secs),
    );
    let _offline_connection_cleanup = spawn_offline_connection_cleanup(
        state.machines.clone(),
        BATCHER_OFFLINE_CLEANUP_INTERVAL,
        BATCHER_OFFLINE_CLEANUP_THRESHOLD,
    );
    let handle = serve::serve(state, cfg, extra_routes).await?;
    let tls_cert_path = handle
        .tls
        .as_ref()
        .map(|tls| tls.cert_path.display().to_string());
    let metrics_addr = handle.metrics_addr.map(|addr| addr.to_string());

    println!(
        "{}",
        serde_json::to_string_pretty(&StartupInfo {
            http: args.http.to_string(),
            https: (!args.no_https).then_some(args.https.to_string()),
            metrics: metrics_addr,
            public_url,
            tls_cert_path,
            embedded_derp: embedded_derp_startup,
            harness_routes: vec![
                "GET /harness/health",
                "POST /harness/preauth",
                "PUT /harness/policy",
                "POST /harness/register/{registration_id}",
                "GET /harness/machines",
                "GET /harness/routes",
                "PUT /harness/machines/{node_key}/routes",
                "PUT /harness/machines/{node_key}/tags",
                "POST /harness/derp/verify",
                "GET /harness/derp/verify-log",
            ],
        })?
    );
    if route_health_probe.is_some() {
        eprintln!(
            "route health probe enabled interval={}s timeout={}s",
            args.route_health_probe_interval_secs, args.route_health_probe_timeout_secs
        );
    }

    let serve::ServeHandle { http, https, .. } = handle;
    match (http, https) {
        (Some(http), Some(https)) => {
            tokio::select! {
                _ = signal::ctrl_c() => Ok(()),
                result = http => flatten_join(result, "http"),
                result = https => flatten_join(result, "https"),
            }
        }
        (Some(http), None) => {
            tokio::select! {
                _ = signal::ctrl_c() => Ok(()),
                result = http => flatten_join(result, "http"),
            }
        }
        (None, Some(https)) => {
            tokio::select! {
                _ = signal::ctrl_c() => Ok(()),
                result = https => flatten_join(result, "https"),
            }
        }
        (None, None) => anyhow::bail!("wire harness started without public listeners"),
    }
}

fn harness_router(state: AppState) -> Router {
    Router::new()
        .route("/harness/health", get(health))
        .route("/harness/preauth", post(mint_preauth))
        .route("/harness/policy", put(set_policy))
        .route("/harness/register/:registration_id", post(register_pending))
        .route("/harness/machines", get(list_machines))
        .route("/harness/routes", get(route_state))
        .route(
            "/harness/machines/:node_key/routes",
            put(set_machine_routes),
        )
        .route("/harness/machines/:node_key/tags", put(set_machine_tags))
        .route("/harness/derp/verify", post(derp_verify))
        .route("/harness/derp/verify-log", get(derp_verify_log))
        .with_state(state)
}

fn parse_dns_extra_records(raw: Option<&str>) -> Result<Vec<DnsRecord>> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(Vec::new());
    };
    parse_extra_records(raw.as_bytes()).context("parse HSRS_HARNESS_DNS_EXTRA_RECORDS_JSON")
}

fn parse_dns_resolvers_json(raw: Option<&str>) -> Result<(Vec<String>, Vec<DnsResolver>)> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok((Vec::new(), Vec::new()));
    };
    let values: Vec<serde_json::Value> =
        serde_json::from_str(raw).context("parse DNS resolver JSON array")?;
    let resolvers = values
        .into_iter()
        .map(value_to_dns_resolver)
        .collect::<Result<Vec<_>>>()?;
    let addrs = resolvers
        .iter()
        .map(|resolver| resolver.addr.clone())
        .collect();
    Ok((addrs, resolvers))
}

fn parse_dns_split_resolvers_json(
    raw: Option<&str>,
) -> Result<(DnsResolverAddrsBySuffix, DnsResolversBySuffix)> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok((HashMap::new(), HashMap::new()));
    };
    let values: HashMap<String, Vec<serde_json::Value>> =
        serde_json::from_str(raw).context("parse DNS split resolver JSON object")?;
    let mut addrs_by_suffix = HashMap::new();
    let mut resolvers_by_suffix = HashMap::new();
    for (suffix, raw_resolvers) in values {
        let resolvers = raw_resolvers
            .into_iter()
            .map(value_to_dns_resolver)
            .collect::<Result<Vec<_>>>()?;
        let addrs = resolvers
            .iter()
            .map(|resolver| resolver.addr.clone())
            .collect();
        addrs_by_suffix.insert(suffix.clone(), addrs);
        resolvers_by_suffix.insert(suffix, resolvers);
    }
    Ok((addrs_by_suffix, resolvers_by_suffix))
}

fn value_to_dns_resolver(value: serde_json::Value) -> Result<DnsResolver> {
    match value {
        serde_json::Value::String(addr) => Ok(DnsResolver {
            addr,
            ..DnsResolver::default()
        }),
        serde_json::Value::Object(map) => {
            let addr = map
                .get("addr")
                .or_else(|| map.get("Addr"))
                .and_then(serde_json::Value::as_str)
                .filter(|addr| !addr.is_empty())
                .ok_or_else(|| anyhow::anyhow!("DNS resolver object requires addr/Addr"))?
                .to_string();
            let bootstrap_resolution = map
                .get("bootstrap_resolution")
                .or_else(|| map.get("BootstrapResolution"))
                .and_then(serde_json::Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .map(|value| {
                            value.as_str().map(ToString::to_string).ok_or_else(|| {
                                anyhow::anyhow!("BootstrapResolution entries must be strings")
                            })
                        })
                        .collect::<Result<Vec<_>>>()
                })
                .transpose()?
                .unwrap_or_default();
            let use_with_exit_node = map
                .get("use_with_exit_node")
                .or_else(|| map.get("UseWithExitNode"))
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            Ok(DnsResolver {
                addr,
                bootstrap_resolution,
                use_with_exit_node,
            })
        }
        other => bail!("DNS resolver entries must be strings or objects, got {other:?}"),
    }
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        ok: true,
        machines: state.machines.snapshot().len(),
        policy_loaded: state.policy.is_loaded(),
    })
}

async fn mint_preauth(
    State(state): State<AppState>,
    Json(mut req): Json<MintPreauthRequest>,
) -> Json<MintPreauthResponse> {
    let key = req.key.take().unwrap_or_else(next_authkey);
    Json(state.redeemer.insert(key, req))
}

async fn set_policy(State(state): State<AppState>, body: Bytes) -> impl IntoResponse {
    match String::from_utf8(body.to_vec())
        .map_err(|err| anyhow::anyhow!("policy body must be UTF-8: {err}"))
        .and_then(|raw| {
            load_policy(&state.policy, raw)?;
            apply_policy_auto_approvals(&state.policy, &state.machines)
        }) {
        Ok(()) => (StatusCode::NO_CONTENT, String::new()).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

fn apply_policy_auto_approvals(policy: &PolicyStore, machines: &MachineRegistry) -> Result<()> {
    for (node_key_hex, machine) in machines.snapshot().iter() {
        let mut approved_routes = normalize_routes(&machine.approved_routes)
            .map_err(|err| anyhow::anyhow!("normalizing approved routes: {err}"))?;
        let announced_routes = normalize_routes(&machine.available_routes)
            .map_err(|err| anyhow::anyhow!("normalizing available routes: {err}"))?;
        let primary_addr = machine.primary_addr_string();
        let user = (!machine.user.is_empty()).then_some(machine.user.as_str());
        let node = NodeView {
            addr: primary_addr.as_deref(),
            user,
            tags: &machine.forced_tags,
        };

        for route in announced_routes {
            if approved_routes.contains(&route) {
                continue;
            }
            let auto_approved = if route == "0.0.0.0/0" || route == "::/0" {
                policy.auto_approves_exit_node(&node)
            } else {
                policy.auto_approves_route(&node, &route)
            };
            if auto_approved {
                approved_routes.push(route);
            }
        }

        approved_routes.sort();
        approved_routes.dedup();
        if approved_routes != machine.approved_routes
            && !machines.set_approved_routes(node_key_hex, approved_routes)
        {
            bail!("machine {node_key_hex} disappeared while auto-approving routes");
        }
    }
    Ok(())
}

async fn register_pending(
    State(state): State<AppState>,
    Path(registration_id): Path<String>,
    Json(req): Json<RegisterPendingRequest>,
) -> impl IntoResponse {
    let Some(mut record) = state.registration_cache.get(&registration_id) else {
        return (StatusCode::NOT_FOUND, "registration not found").into_response();
    };
    let user = req.user;
    record.user = user.clone();
    if let Err(err) = apply_requested_tags(&state.policy, &mut record) {
        return (StatusCode::BAD_REQUEST, err).into_response();
    }

    let record = state.machines.complete_web_registration(record, &user, 2);
    if !state
        .registration_cache
        .complete(&registration_id, record.clone())
    {
        return (StatusCode::NOT_FOUND, "registration not found").into_response();
    }

    Json(machine_summary(&record)).into_response()
}

async fn list_machines(State(state): State<AppState>) -> Json<Vec<MachineSummary>> {
    let mut machines = state
        .machines
        .snapshot()
        .values()
        .map(machine_summary)
        .collect::<Vec<_>>();
    machines.sort_by(|a, b| a.node_key.cmp(&b.node_key));
    Json(machines)
}

async fn route_state(State(state): State<AppState>) -> Json<DebugRoutes> {
    let snapshot = state.machines.snapshot();
    Json(state.machines.debug_routes_for_snapshot(&snapshot))
}

async fn set_machine_routes(
    State(state): State<AppState>,
    Path(node_key): Path<String>,
    Json(req): Json<SetApprovedRoutesRequest>,
) -> impl IntoResponse {
    let routes = match normalize_routes(req.routes) {
        Ok(routes) => routes,
        Err(err) => return (StatusCode::BAD_REQUEST, err).into_response(),
    };
    let node_key_hex = node_key.strip_prefix("nodekey:").unwrap_or(&node_key);
    if !state.machines.set_approved_routes(node_key_hex, routes) {
        return (StatusCode::NOT_FOUND, "machine not found").into_response();
    }

    match state.machines.get(node_key_hex) {
        Some(machine) => Json(machine_summary(&machine)).into_response(),
        None => (StatusCode::NOT_FOUND, "machine not found").into_response(),
    }
}

async fn set_machine_tags(
    State(state): State<AppState>,
    Path(node_key): Path<String>,
    Json(req): Json<SetTagsRequest>,
) -> impl IntoResponse {
    let mut tags = req.tags;
    tags.sort();
    tags.dedup();
    if tags.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            "cannot remove all tags from a node - tagged nodes must have at least one tag"
                .to_string(),
        )
            .into_response();
    }
    let invalid_tags = tags
        .iter()
        .filter(|tag| !valid_tag(tag) || !state.policy.tag_exists(tag))
        .cloned()
        .collect::<Vec<_>>();
    if !invalid_tags.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "requested tags [{}] are invalid or not permitted",
                invalid_tags.join(" ")
            ),
        )
            .into_response();
    }

    let node_key_hex = node_key.strip_prefix("nodekey:").unwrap_or(&node_key);
    if !state.machines.set_forced_tags(node_key_hex, tags) {
        return (StatusCode::NOT_FOUND, "machine not found".to_string()).into_response();
    }

    match state.machines.get(node_key_hex) {
        Some(machine) => Json(machine_summary(&machine)).into_response(),
        None => (StatusCode::NOT_FOUND, "machine not found".to_string()).into_response(),
    }
}

async fn derp_verify(
    State(state): State<AppState>,
    body: Bytes,
) -> (StatusCode, Json<DerpAdmitClientResponse>) {
    let req = match serde_json::from_slice::<DerpAdmitClientRequest>(&body) {
        Ok(req) => req,
        Err(_) => {
            state.derp_verify.requests.fetch_add(1, Ordering::Relaxed);
            state.derp_verify.denied.fetch_add(1, Ordering::Relaxed);
            return (
                StatusCode::BAD_REQUEST,
                Json(DerpAdmitClientResponse { allow: false }),
            );
        }
    };
    let _source = req.source;
    let allow = match req.node_public.as_deref() {
        Some(node_public) => derp_admit_node_key_hex(node_public)
            .ok()
            .is_some_and(|node_key_hex| state.machines.get(node_key_hex).is_some()),
        None => false,
    };

    state.derp_verify.requests.fetch_add(1, Ordering::Relaxed);
    if allow {
        state.derp_verify.allowed.fetch_add(1, Ordering::Relaxed);
    } else {
        state.derp_verify.denied.fetch_add(1, Ordering::Relaxed);
    }

    (StatusCode::OK, Json(DerpAdmitClientResponse { allow }))
}

async fn derp_verify_log(State(state): State<AppState>) -> Json<DerpVerifyLogResponse> {
    Json(DerpVerifyLogResponse {
        requests: state.derp_verify.requests.load(Ordering::Relaxed),
        allowed: state.derp_verify.allowed.load(Ordering::Relaxed),
        denied: state.derp_verify.denied.load(Ordering::Relaxed),
    })
}

fn load_policy(policy: &PolicyStore, raw: String) -> Result<()> {
    let doc = parse_hujson_policy(&raw)?;
    policy.set(doc, raw);
    Ok(())
}

fn load_runtime_derp_map(
    path: Option<&PathBuf>,
    embedded_derp_runtime: Option<&EmbeddedDerpRuntime>,
) -> Result<DerpMap> {
    match path {
        Some(path) => derp_config::load_derp_map(path)
            .with_context(|| format!("load DERP map {}", path.display())),
        None => Ok(embedded_derp_runtime
            .map(derp_map_from_embedded_runtime)
            .unwrap_or_else(derp_config::empty_derp_map)),
    }
}

fn embedded_derp_config(args: &Args) -> Result<EmbeddedDerpConfig> {
    let host_name = args
        .embedded_derp_hostname
        .clone()
        .unwrap_or_else(|| args.hostname.clone());
    let derper_listen_addr = args.embedded_derp_derper_listen_addr.unwrap_or_else(|| {
        SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            args.embedded_derp_derp_port,
        )
    });
    let verify_client_url = args
        .embedded_derp_verify_client_url
        .clone()
        .or_else(|| Some(format!("http://{}/harness/derp/verify", args.http)));

    Ok(EmbeddedDerpConfig {
        enabled: true,
        host_name,
        derp_port: args.embedded_derp_derp_port,
        stun_addr: args.embedded_derp_stun_addr,
        stun_only: args.embedded_derp_stun_only,
        region_id: args.embedded_derp_region_id,
        region_code: args.embedded_derp_region_code.clone(),
        region_name: args.embedded_derp_region_name.clone(),
        omit_default_regions: args.embedded_derp_omit_default_regions,
        insecure_for_tests: args.embedded_derp_insecure_for_tests,
        ipv4: args.embedded_derp_ipv4.clone().unwrap_or_default(),
        ipv6: args.embedded_derp_ipv6.clone().unwrap_or_default(),
        derper_binary: args.embedded_derp_derper_binary.clone().unwrap_or_default(),
        derper_listen_addr,
        derper_config_path: args
            .embedded_derp_derper_config_path
            .clone()
            .unwrap_or_default(),
        derper_cert_mode: args.embedded_derp_derper_cert_mode.clone(),
        derper_cert_dir: args.embedded_derp_derper_cert_dir.clone(),
        verify_client_url,
        verify_clients: args.embedded_derp_verify_clients,
    })
}

fn derp_map_from_embedded_runtime(runtime: &EmbeddedDerpRuntime) -> DerpMap {
    let cfg = runtime.config();
    if !cfg.enabled {
        return DerpMap::default();
    }

    let stun_port = runtime
        .stun_local_addr()
        .map_or(-1, |addr| i32::from(addr.port()));
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

fn embedded_derp_startup_info(runtime: &EmbeddedDerpRuntime) -> EmbeddedDerpStartup {
    let cfg = runtime.config();
    EmbeddedDerpStartup {
        region_id: cfg.region_id,
        derp_port: cfg.derp_port,
        stun_addr: runtime.stun_local_addr().map(|addr| addr.to_string()),
        sidecar_status: runtime.sidecar_status().map(|status| format!("{status:?}")),
        verify_client_url: cfg.verify_client_url.clone(),
    }
}

fn machine_summary(machine: &MachineRecord) -> MachineSummary {
    MachineSummary {
        node_key: format!("nodekey:{}", machine.node_key_hex),
        machine_key: if machine.machine_key_hex.is_empty() {
            String::new()
        } else {
            format!("mkey:{}", machine.machine_key_hex)
        },
        user: machine.user.clone(),
        hostname: machine.hostname.clone(),
        ipv4: machine
            .ipv4
            .map(|addr| addr.to_string())
            .unwrap_or_default(),
        ipv6: machine
            .ipv6
            .map(|addr| addr.to_string())
            .unwrap_or_default(),
        addresses: machine.address_strings(),
        ephemeral: machine.ephemeral,
        forced_tags: machine.forced_tags.clone(),
        available_routes: machine.available_routes.clone(),
        approved_routes: machine.approved_routes.clone(),
        endpoints: machine.endpoints.clone(),
        disco_key: machine.disco_key.clone(),
    }
}

fn apply_requested_tags(policy: &PolicyStore, record: &mut MachineRecord) -> Result<(), String> {
    if record.forced_tags.is_empty() {
        return Ok(());
    }

    record.forced_tags.sort();
    record.forced_tags.dedup();
    let addr = record.primary_addr_string();
    let node = NodeView {
        addr: addr.as_deref(),
        user: Some(record.user.as_str()),
        tags: &[],
    };
    let invalid_tags = record
        .forced_tags
        .iter()
        .filter(|tag| !valid_tag(tag) || !policy.node_can_have_tag(&node, tag))
        .cloned()
        .collect::<Vec<_>>();
    if !invalid_tags.is_empty() {
        return Err(format!(
            "requested tags [{}] are invalid or not permitted",
            invalid_tags.join(" ")
        ));
    }

    record.expiry = None;
    Ok(())
}

fn valid_tag(tag: &str) -> bool {
    tag.starts_with("tag:") && tag.to_lowercase() == tag && tag.split_whitespace().count() <= 1
}

fn derp_admit_node_key_hex(node_public: &str) -> Result<&str, ()> {
    let Some(node_key_hex) = node_public.strip_prefix("nodekey:") else {
        return Err(());
    };
    if node_key_hex.len() == 64 && node_key_hex.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        Ok(node_key_hex)
    } else {
        Err(())
    }
}

fn default_user() -> String {
    "alice".to_string()
}

fn next_authkey() -> String {
    static SEQ: AtomicU64 = AtomicU64::new(1);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let pid = u128::from(std::process::id());
    let suffix = format!(
        "{:016x}{:016x}{:016x}{:016x}",
        nanos as u64,
        (nanos >> 64) as u64,
        seq,
        pid
    );
    format!("hskey-auth-{:012x}-{suffix}", seq & 0x0000_ffff_ffff_ffff)
}

fn flatten_join(
    result: std::result::Result<std::result::Result<(), std::io::Error>, tokio::task::JoinError>,
    name: &str,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(err).with_context(|| format!("{name} listener failed")),
        Err(err) => {
            if err.is_cancelled() {
                Ok(())
            } else {
                bail!("{name} listener task failed: {err}")
            }
        }
    }
}
