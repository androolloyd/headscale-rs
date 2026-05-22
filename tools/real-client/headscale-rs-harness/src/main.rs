use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
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
use clap::Parser;
use headscale_api::{
    dns::{DnsConfigSpec, DnsStore},
    policy::{NodeView, PolicyStore, parse_hujson_policy},
    tailscale_wire::{
        AllocError, DerpMap, IpAllocator, KnockConfig, MachineRecord, MachineRegistry,
        PreauthRedeemer, RedeemError, RedeemOk, RegistrationCache, ServerNoiseKey, WireState,
        derp_config, routes::normalize_routes, serve,
    },
};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::signal;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
    #[arg(long, env = "HSRS_HARNESS_POLICY")]
    policy: Option<PathBuf>,
    #[arg(long, env = "HSRS_HARNESS_BASE_DOMAIN")]
    base_domain: Option<String>,
    #[arg(long = "authkey", value_name = "KEY=USER")]
    authkeys: Vec<String>,
}

#[derive(Clone)]
struct AppState {
    redeemer: Arc<HarnessRedeemer>,
    machines: Arc<MachineRegistry>,
    policy: Arc<PolicyStore>,
    registration_cache: Arc<RegistrationCache>,
}

#[derive(Default)]
struct HarnessRedeemer {
    keys: RwLock<HashMap<String, HarnessKey>>,
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

struct HarnessIpAllocator;

impl IpAllocator for HarnessIpAllocator {
    fn allocate(&self, node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
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
struct RegisterPendingRequest {
    #[serde(default = "default_user")]
    user: String,
}

#[derive(Debug, Serialize)]
struct StartupInfo {
    http: String,
    https: Option<String>,
    public_url: String,
    tls_cert_path: Option<String>,
    harness_routes: Vec<&'static str>,
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
    let dns = Arc::new(DnsStore::from_spec(DnsConfigSpec {
        magic_dns: args.base_domain.is_some(),
        base_domain: args.base_domain.unwrap_or_default(),
        ..DnsConfigSpec::default()
    }));
    let derp_map = Arc::new(load_derp_map(args.derp_map.as_ref())?);
    let public_url = args
        .public_url
        .unwrap_or_else(|| format!("https://{}", args.hostname));

    let registration_cache = Arc::new(RegistrationCache::new());
    let state = WireState {
        server_noise_key: Arc::new(ServerNoiseKey::load_or_generate(&args.state_dir)?),
        preauth: redeemer.clone(),
        ip_allocator: Arc::new(HarnessIpAllocator),
        machines: machines.clone(),
        derp_map,
        policy: policy.clone(),
        knock: KnockConfig::disabled(),
        dns,
        public_control_url: Some(public_url.clone()),
        registration_cache: registration_cache.clone(),
    };

    let app_state = AppState {
        redeemer,
        machines,
        policy,
        registration_cache,
    };
    let extra_routes = harness_router(app_state);
    let cfg = serve::ServeConfig {
        http_addr: args.http,
        https_addr: (!args.no_https).then_some(args.https),
        state_dir: args.state_dir,
        sans: headscale_api::tailscale_wire::tls::SanConfig::with_hostname(args.hostname),
    };
    let handle = serve::serve(state, cfg, extra_routes).await?;
    let tls_cert_path = handle
        .tls
        .as_ref()
        .map(|tls| tls.cert_path.display().to_string());

    println!(
        "{}",
        serde_json::to_string_pretty(&StartupInfo {
            http: args.http.to_string(),
            https: (!args.no_https).then_some(args.https.to_string()),
            public_url,
            tls_cert_path,
            harness_routes: vec![
                "GET /harness/health",
                "POST /harness/preauth",
                "PUT /harness/policy",
                "POST /harness/register/{registration_id}",
                "GET /harness/machines",
                "PUT /harness/machines/{node_key}/routes",
            ],
        })?
    );

    let serve::ServeHandle { http, https, .. } = handle;
    if let Some(https) = https {
        tokio::select! {
            _ = signal::ctrl_c() => Ok(()),
            result = http => flatten_join(result, "http"),
            result = https => flatten_join(result, "https"),
        }
    } else {
        tokio::select! {
            _ = signal::ctrl_c() => Ok(()),
            result = http => flatten_join(result, "http"),
        }
    }
}

fn harness_router(state: AppState) -> Router {
    Router::new()
        .route("/harness/health", get(health))
        .route("/harness/preauth", post(mint_preauth))
        .route("/harness/policy", put(set_policy))
        .route("/harness/register/:registration_id", post(register_pending))
        .route("/harness/machines", get(list_machines))
        .route(
            "/harness/machines/:node_key/routes",
            put(set_machine_routes),
        )
        .with_state(state)
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
        .and_then(|raw| load_policy(&state.policy, raw))
    {
        Ok(()) => (StatusCode::NO_CONTENT, String::new()).into_response(),
        Err(err) => (StatusCode::BAD_REQUEST, err.to_string()).into_response(),
    }
}

async fn register_pending(
    State(state): State<AppState>,
    Path(registration_id): Path<String>,
    Json(req): Json<RegisterPendingRequest>,
) -> impl IntoResponse {
    let Some(mut record) = state.registration_cache.get(&registration_id) else {
        return (StatusCode::NOT_FOUND, "registration not found").into_response();
    };
    record.user = req.user;
    record.register_method = 2;
    if let Err(err) = apply_requested_tags(&state.policy, &mut record) {
        return (StatusCode::BAD_REQUEST, err).into_response();
    }

    state
        .machines
        .upsert(record.node_key_hex.clone(), record.clone());
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

fn load_policy(policy: &PolicyStore, raw: String) -> Result<()> {
    let doc = parse_hujson_policy(&raw)?;
    policy.set(doc, raw);
    Ok(())
}

fn load_derp_map(path: Option<&PathBuf>) -> Result<DerpMap> {
    match path {
        Some(path) => derp_config::load_derp_map(path)
            .with_context(|| format!("load DERP map {}", path.display())),
        None => Ok(derp_config::empty_derp_map()),
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
        ipv4: machine.ipv4.to_string(),
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
    let addr = record.ipv4.to_string();
    let node = NodeView {
        addr: Some(addr.as_str()),
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
