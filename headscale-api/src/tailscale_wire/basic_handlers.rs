//! Basic unauthenticated control-plane endpoints shared with headscale-go.
//!
//! These live next to `/key` in the wire router because upstream serves
//! them from the same public control listener, before API bearer auth.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    env, thread,
};

use axum::{
    Json,
    body::to_bytes,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::policy::{PeerMapNode, PolicyAction, SshPolicyNode};

use super::{
    DerpMap, HistogramMetric, MachineRecord, NODESTORE_BATCH_SIZE_BUCKETS,
    PROMETHEUS_DEFAULT_BUCKETS, WireState,
    wire::{SshPolicy, stable_id_from_key},
};

const ROBOTS_BODY: &str = "User-agent: *\nDisallow: /";
const REGISTRATION_ID_LENGTH: usize = 24;
const MAPRESPONSES_DEBUG_DISABLED_BODY: &str = "HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH not set";
const PROMETHEUS_TEXT_CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
const VERIFY_BODY_LIMIT: usize = 4 * 1024;
const SWAGGER_JSON: &str = include_str!("assets/headscale.swagger.json");
const FAVICON_PNG: &[u8] = include_bytes!("assets/favicon.png");
const DEBUG_INDEX_LINKS: &[(&str, &str)] = &[
    ("/debug/vars", "Metrics (Go)"),
    ("/debug/varz", "Metrics (Prometheus)"),
    ("/debug/pprof/", "pprof (index)"),
    ("/debug/pprof/goroutine?debug=1", "Goroutines (collapsed)"),
    ("/debug/pprof/goroutine?debug=2", "Goroutines (full)"),
    ("/debug/overview", "State overview"),
    ("/debug/config", "Current configuration"),
    ("/debug/policy", "Current policy"),
    ("/debug/filter", "Current filter rules"),
    ("/debug/ssh", "SSH policies per node"),
    ("/debug/derp", "DERP map configuration"),
    ("/debug/nodestore", "NodeStore information"),
    (
        "/debug/registration-cache",
        "Registration cache information",
    ),
    ("/debug/routes", "Primary routes"),
    ("/debug/policy-manager", "Policy manager state"),
    ("/debug/mapresponses", "Map responses for all nodes"),
    ("/debug/batcher", "Batcher connected nodes"),
    ("/debug/gc", "force GC"),
    ("/debug/statsviz", "Statsviz (visualise go metrics)"),
    ("/metrics", "Prometheus metrics"),
];
const PPROF_PROFILE_NAMES: &[&str] = &[
    "allocs",
    "block",
    "goroutine",
    "heap",
    "mutex",
    "threadcreate",
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoInfo {
    pub version: String,
    pub os: String,
    pub arch: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionInfo {
    pub version: String,
    pub commit: String,
    #[serde(rename = "buildTime")]
    pub build_time: String,
    pub go: GoInfo,
    pub dirty: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct DerpAdmitClientRequest {
    #[serde(rename = "NodePublic", default)]
    node_public: Option<String>,
    #[serde(rename = "Source", default)]
    source: Option<IpAddr>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DerpAdmitClientResponse {
    #[serde(rename = "Allow")]
    pub allow: bool,
}

pub async fn handle_robots() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain")],
        ROBOTS_BODY,
    )
        .into_response()
}

pub async fn handle_health() -> Response {
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/health+json; charset=utf-8",
        )],
        Json(HealthResponse {
            status: "pass".into(),
        }),
    )
        .into_response()
}

pub async fn handle_version() -> Response {
    Json(version_info()).into_response()
}

pub async fn handle_swagger() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        swagger_html(),
    )
        .into_response()
}

pub async fn handle_swagger_api_v1() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
        SWAGGER_JSON,
    )
        .into_response()
}

pub async fn handle_web_register(Path(registration_id): Path<String>) -> Response {
    if registration_id.len() != REGISTRATION_ID_LENGTH {
        return http_error(StatusCode::BAD_REQUEST, "invalid registration id");
    }

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        register_web_html(&registration_id),
    )
        .into_response()
}

pub async fn handle_favicon() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/png")],
        FAVICON_PNG,
    )
        .into_response()
}

pub async fn handle_metrics(State(state): State<WireState>) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, PROMETHEUS_TEXT_CONTENT_TYPE)],
        metrics_text(&state),
    )
        .into_response()
}

pub async fn handle_verify(State(state): State<WireState>, req: Request) -> Response {
    let Ok(raw) = to_bytes(req.into_body(), VERIFY_BODY_LIMIT).await else {
        return http_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large");
    };
    let Ok(req) = serde_json::from_slice::<DerpAdmitClientRequest>(&raw) else {
        return http_error(StatusCode::BAD_REQUEST, "Bad Request: invalid JSON");
    };
    let DerpAdmitClientRequest {
        node_public,
        source: _,
    } = req;

    let node_key_hex = match node_public.as_deref() {
        Some(node_public) => match derp_admit_node_key_hex(node_public) {
            Ok(node_key_hex) => Some(node_key_hex),
            Err(()) => return http_error(StatusCode::BAD_REQUEST, "Bad Request: invalid JSON"),
        },
        None => None,
    };

    let allow = node_key_hex.is_some_and(|node_key_hex| state.machines.get(node_key_hex).is_some());
    let body = format!(
        "{}\n",
        serde_json::to_string(&DerpAdmitClientResponse { allow })
            .expect("DERP admit response serialization is infallible")
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

pub async fn handle_derp_probe(method: Method) -> Response {
    match method {
        Method::GET | Method::HEAD => {
            let mut resp = StatusCode::OK.into_response();
            resp.headers_mut().insert(
                header::ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_static("*"),
            );
            resp
        }
        _ => (StatusCode::METHOD_NOT_ALLOWED, "bogus probe method").into_response(),
    }
}

pub async fn handle_derp_bootstrap_dns(State(state): State<WireState>) -> Response {
    let mut dns_entries: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();

    let derp_map = state.derp_map.snapshot();
    for region in derp_map.regions.values() {
        for node in &region.nodes {
            let resolved = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                tokio::net::lookup_host((node.host_name.as_str(), 0)),
            )
            .await;

            let Ok(Ok(addrs)) = resolved else {
                continue;
            };

            let ips = addrs
                .map(|addr| addr.ip())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect::<Vec<_>>();
            if !ips.is_empty() {
                dns_entries.insert(node.host_name.clone(), ips);
            }
        }
    }

    let body = format!(
        "{}\n",
        serde_json::to_string(&dns_entries)
            .expect("DERP bootstrap DNS response serialization is infallible")
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
pub struct PingResponseQuery {
    id: Option<String>,
}

pub async fn handle_ping_response(
    State(state): State<WireState>,
    Query(query): Query<PingResponseQuery>,
) -> Response {
    let Some(ping_id) = query.id.as_deref().filter(|id| !id.is_empty()) else {
        return empty_ping_response(StatusCode::BAD_REQUEST);
    };

    if state.pings.complete(ping_id).is_none() {
        return empty_ping_response(StatusCode::NOT_FOUND);
    }

    empty_ping_response(StatusCode::OK)
}

fn empty_ping_response(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .body(axum::body::Body::from_stream(
            futures_util::stream::empty::<Result<bytes::Bytes, std::convert::Infallible>>(),
        ))
        .expect("empty ping response body is infallible")
}

pub async fn handle_fallback(uri: Uri) -> Response {
    let path = uri.path();
    if path == "/k"
        || path.starts_with(super::knock::KNOCK_PATH_PREFIX)
        || path == "/machine"
        || path.starts_with("/machine/")
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    handle_blank().await
}

pub async fn handle_blank() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        blank_html(),
    )
        .into_response()
}

pub async fn handle_debug_redirect() -> Response {
    (
        StatusCode::MOVED_PERMANENTLY,
        [(header::LOCATION, "/debug/")],
        "",
    )
        .into_response()
}

pub async fn handle_debug_index() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        debug_index_html(),
    )
        .into_response()
}

pub async fn handle_debug_gc() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "running GC...\nDone.\n",
    )
        .into_response()
}

pub async fn handle_debug_vars(State(state): State<WireState>) -> Response {
    let snapshot = state.machines.snapshot();
    let dns_spec = state.dns.spec();
    let payload = serde_json::json!({
        "cmdline": env::args().collect::<Vec<_>>(),
        "rust": {
            "version": env!("CARGO_PKG_VERSION"),
            "os": env::consts::OS,
            "arch": env::consts::ARCH,
            "available_parallelism": thread::available_parallelism()
                .map(std::num::NonZero::get)
                .unwrap_or(1),
        },
        "headscale": {
            "nodes_registered": snapshot.len(),
            "dns_base_domain": dns_spec.base_domain,
            "derp_regions": state.derp_map.snapshot().regions.len(),
        }
    });

    match serde_json::to_string_pretty(&payload) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json; charset=utf-8")],
            body,
        )
            .into_response(),
        Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

pub async fn handle_debug_pprof_redirect() -> Response {
    (
        StatusCode::MOVED_PERMANENTLY,
        [(header::LOCATION, "/debug/pprof/")],
        "",
    )
        .into_response()
}

pub async fn handle_debug_pprof_index() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        debug_pprof_index_html(),
    )
        .into_response()
}

pub async fn handle_debug_pprof_cmdline() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        env::args().collect::<Vec<_>>().join("\0"),
    )
        .into_response()
}

pub async fn handle_debug_pprof_profile(Path(profile): Path<String>) -> Response {
    if !PPROF_PROFILE_NAMES.contains(&profile.as_str()) {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            format!("Unknown profile: {profile}\n"),
        )
            .into_response();
    }

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        rust_pprof_profile_text(&profile),
    )
        .into_response()
}

pub async fn handle_debug_pprof_cpu_profile() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        rust_pprof_profile_text("profile"),
    )
        .into_response()
}

pub async fn handle_debug_pprof_symbol() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "num_symbols: 0\n",
    )
        .into_response()
}

pub async fn handle_debug_pprof_trace() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        rust_pprof_profile_text("trace"),
    )
        .into_response()
}

pub async fn handle_debug_statsviz_redirect() -> Response {
    (
        StatusCode::MOVED_PERMANENTLY,
        [(header::LOCATION, "/debug/statsviz/")],
        "",
    )
        .into_response()
}

pub async fn handle_debug_statsviz_index() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        debug_statsviz_html(),
    )
        .into_response()
}

pub async fn handle_debug_statsviz_ws() -> Response {
    (
        StatusCode::BAD_REQUEST,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "websocket runtime metrics stream is not available in this Rust build\n",
    )
        .into_response()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugDerpInfo {
    pub configured: bool,
    pub total_regions: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub regions: BTreeMap<u16, DebugDerpRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugDerpRegion {
    pub region_id: u16,
    pub region_name: String,
    pub nodes: Vec<DebugDerpNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugDerpNode {
    pub name: String,
    pub hostname: String,
    pub derp_port: u16,
    #[serde(default, skip_serializing_if = "is_zero_i32")]
    pub stun_port: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugRegistrationCacheInfo {
    #[serde(rename = "type")]
    pub cache_type: String,
    pub expiration: String,
    pub cleanup: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugOverviewInfo {
    pub nodes: DebugOverviewNodes,
    pub users: BTreeMap<String, usize>,
    pub total_users: usize,
    pub policy: DebugOverviewPolicy,
    pub derp: DebugOverviewDerp,
    pub primary_routes: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugOverviewNodes {
    pub total: usize,
    pub online: usize,
    pub expired: usize,
    pub ephemeral: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugOverviewPolicy {
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugOverviewDerp {
    pub configured: bool,
    pub regions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugBatcherInfo {
    pub connected_nodes: BTreeMap<String, DebugBatcherNodeInfo>,
    pub total_nodes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugBatcherNodeInfo {
    pub connected: bool,
    pub active_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugNodeStoreNode {
    pub id: u64,
    pub node_key: String,
    pub machine_key: String,
    pub user: String,
    pub hostname: String,
    pub ipv4: String,
    pub online: bool,
    pub expired: bool,
    pub ephemeral: bool,
    pub created_at: String,
    pub last_seen: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry: Option<String>,
    pub forced_tags: Vec<String>,
    pub available_routes: Vec<String>,
    pub approved_routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugStringInfo {
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugConfigInfo {
    #[serde(rename = "ServerURL")]
    pub server_url: String,
    #[serde(rename = "Addr")]
    pub addr: String,
    #[serde(rename = "MetricsAddr")]
    pub metrics_addr: String,
    #[serde(rename = "GRPCAddr")]
    pub grpc_addr: String,
    #[serde(rename = "GRPCAllowInsecure")]
    pub grpc_allow_insecure: bool,
    #[serde(rename = "TrustedProxies")]
    pub trusted_proxies: Vec<String>,
    #[serde(rename = "EphemeralNodeInactivityTimeout")]
    pub ephemeral_node_inactivity_timeout: i64,
    #[serde(rename = "Node")]
    pub node: DebugNodeConfig,
    #[serde(rename = "PrefixV4")]
    pub prefix_v4: Option<String>,
    #[serde(rename = "PrefixV6")]
    pub prefix_v6: Option<String>,
    #[serde(rename = "IPAllocation")]
    pub ip_allocation: String,
    #[serde(rename = "NoisePrivateKeyPath")]
    pub noise_private_key_path: String,
    #[serde(rename = "BaseDomain")]
    pub base_domain: String,
    #[serde(rename = "Log")]
    pub log: DebugLogConfig,
    #[serde(rename = "DisableUpdateCheck")]
    pub disable_update_check: bool,
    #[serde(rename = "Database")]
    pub database: DebugDatabaseConfig,
    #[serde(rename = "DERP")]
    pub derp: DebugDerpConfig,
    #[serde(rename = "TLS")]
    pub tls: DebugTlsConfig,
    #[serde(rename = "ACMEURL")]
    pub acme_url: String,
    #[serde(rename = "ACMEEmail")]
    pub acme_email: String,
    #[serde(rename = "DNSConfig")]
    pub dns_config: DebugDnsConfig,
    #[serde(rename = "TailcfgDNSConfig")]
    pub tailcfg_dns_config: serde_json::Value,
    #[serde(rename = "UnixSocket")]
    pub unix_socket: String,
    #[serde(rename = "UnixSocketPermission")]
    pub unix_socket_permission: u32,
    #[serde(rename = "OIDC")]
    pub oidc: DebugOidcConfig,
    #[serde(rename = "LogTail")]
    pub log_tail: DebugEnabledConfig,
    #[serde(rename = "RandomizeClientPort")]
    pub randomize_client_port: bool,
    #[serde(rename = "Taildrop")]
    pub taildrop: DebugEnabledConfig,
    #[serde(rename = "AutoUpdate")]
    pub auto_update: DebugEnabledConfig,
    #[serde(rename = "CLI")]
    pub cli: DebugCliConfig,
    #[serde(rename = "Policy")]
    pub policy: DebugPolicyConfig,
    #[serde(rename = "Tuning")]
    pub tuning: DebugTuningConfig,
}

impl Default for DebugConfigInfo {
    fn default() -> Self {
        let dns = crate::dns::DnsStore::new();
        let dns_spec = dns.spec();
        let tailcfg_dns_config =
            serde_json::to_value(dns.build(&[])).unwrap_or(serde_json::Value::Null);
        let derp_map = serde_json::to_value(DerpMap::default()).unwrap_or(serde_json::Value::Null);

        Self {
            server_url: String::new(),
            addr: String::new(),
            metrics_addr: String::new(),
            grpc_addr: ":50443".to_string(),
            grpc_allow_insecure: false,
            trusted_proxies: Vec::new(),
            ephemeral_node_inactivity_timeout: duration_nanos(std::time::Duration::from_secs(120)),
            node: DebugNodeConfig {
                expiry: 0,
                ephemeral: DebugNodeEphemeralConfig {
                    inactivity_timeout: duration_nanos(std::time::Duration::from_secs(120)),
                },
                routes: DebugNodeRoutesConfig::default(),
            },
            prefix_v4: None,
            prefix_v6: None,
            ip_allocation: "sequential".to_string(),
            noise_private_key_path: String::new(),
            base_domain: dns_spec.base_domain.clone(),
            log: DebugLogConfig {
                format: "text".to_string(),
                level: "info".to_string(),
            },
            disable_update_check: false,
            database: DebugDatabaseConfig {
                database_type: String::new(),
                debug: false,
                gorm: DebugGormConfig {
                    debug: false,
                    slow_threshold: 0,
                    skip_err_record_not_found: false,
                    parameterized_queries: false,
                    prepare_stmt: false,
                },
                sqlite: DebugSqliteConfig {
                    path: String::new(),
                    write_ahead_log: true,
                    wal_auto_check_point: 1000,
                },
                postgres: DebugPostgresConfig {
                    host: String::new(),
                    port: 0,
                    name: String::new(),
                    user: String::new(),
                    pass: String::new(),
                    ssl: "false".to_string(),
                    max_open_connections: 10,
                    max_idle_connections: 10,
                    conn_max_idle_time_secs: 3600,
                },
            },
            derp: DebugDerpConfig {
                server_enabled: false,
                automatically_add_embedded_derp_region: true,
                server_region_id: 0,
                server_region_code: String::new(),
                server_region_name: String::new(),
                server_private_key_path: String::new(),
                server_verify_clients: true,
                stun_addr: String::new(),
                urls: Vec::new(),
                paths: Vec::new(),
                derp_map,
                auto_update: false,
                update_frequency: duration_nanos(std::time::Duration::from_secs(3 * 60 * 60)),
                ipv4: String::new(),
                ipv6: String::new(),
            },
            tls: DebugTlsConfig {
                cert_path: String::new(),
                key_path: String::new(),
                lets_encrypt: DebugLetsEncryptConfig {
                    listen: String::new(),
                    hostname: String::new(),
                    cache_dir: "/var/www/.cache".to_string(),
                    challenge_type: "HTTP-01".to_string(),
                },
            },
            acme_url: String::new(),
            acme_email: String::new(),
            dns_config: DebugDnsConfig {
                magic_dns: dns_spec.magic_dns,
                base_domain: dns_spec.base_domain.clone(),
                override_local_dns: dns_spec.override_local_dns,
                nameservers: DebugNameservers {
                    global: dns_spec.nameservers.clone(),
                    split: dns_spec
                        .restricted_nameservers
                        .iter()
                        .map(|(suffix, resolvers)| (suffix.clone(), resolvers.clone()))
                        .collect(),
                },
                search_domains: dns_spec.search_domains.clone(),
                extra_records: dns_spec
                    .extra_records
                    .iter()
                    .filter_map(|record| serde_json::to_value(record).ok())
                    .collect(),
                extra_records_path: dns_spec
                    .extra_records_path
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
            },
            tailcfg_dns_config,
            unix_socket: "/var/run/headscale/headscale.sock".to_string(),
            unix_socket_permission: 0o770,
            oidc: DebugOidcConfig {
                only_start_if_oidc_is_available: true,
                issuer: String::new(),
                client_id: String::new(),
                client_secret: String::new(),
                scope: vec![
                    "openid".to_string(),
                    "profile".to_string(),
                    "email".to_string(),
                ],
                extra_params: BTreeMap::new(),
                allowed_domains: Vec::new(),
                allowed_users: Vec::new(),
                allowed_groups: Vec::new(),
                email_verified_required: true,
                expiry: duration_nanos(std::time::Duration::from_secs(180 * 24 * 60 * 60)),
                use_expiry_from_token: false,
                pkce: DebugPkceConfig {
                    enabled: false,
                    method: "S256".to_string(),
                },
            },
            log_tail: DebugEnabledConfig { enabled: false },
            randomize_client_port: false,
            taildrop: DebugEnabledConfig { enabled: true },
            auto_update: DebugEnabledConfig { enabled: false },
            cli: DebugCliConfig {
                address: String::new(),
                api_key: String::new(),
                timeout: duration_nanos(std::time::Duration::from_secs(5)),
                insecure: false,
            },
            policy: DebugPolicyConfig {
                path: String::new(),
                mode: "file".to_string(),
            },
            tuning: DebugTuningConfig {
                notifier_send_timeout: duration_nanos(std::time::Duration::from_millis(800)),
                batch_change_delay: duration_nanos(std::time::Duration::from_millis(800)),
                node_map_session_buffered_chan_size: 30,
                batcher_workers: default_batcher_workers(),
                register_cache_cleanup: 0,
                register_cache_expiration: 0,
                register_cache_max_entries: 0,
                node_store_batch_size: 100,
                node_store_batch_timeout: duration_nanos(std::time::Duration::from_millis(500)),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugLogConfig {
    #[serde(rename = "Format")]
    pub format: String,
    #[serde(rename = "Level")]
    pub level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugNodeConfig {
    #[serde(rename = "Expiry")]
    pub expiry: i64,
    #[serde(rename = "Ephemeral")]
    pub ephemeral: DebugNodeEphemeralConfig,
    #[serde(rename = "Routes")]
    pub routes: DebugNodeRoutesConfig,
}

impl Default for DebugNodeConfig {
    fn default() -> Self {
        Self {
            expiry: 0,
            ephemeral: DebugNodeEphemeralConfig {
                inactivity_timeout: duration_nanos(std::time::Duration::from_secs(120)),
            },
            routes: DebugNodeRoutesConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugNodeEphemeralConfig {
    #[serde(rename = "InactivityTimeout")]
    pub inactivity_timeout: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct DebugNodeRoutesConfig {
    #[serde(rename = "HA")]
    pub ha: DebugNodeRoutesHaConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugNodeRoutesHaConfig {
    #[serde(rename = "ProbeInterval")]
    pub probe_interval: i64,
    #[serde(rename = "ProbeTimeout")]
    pub probe_timeout: i64,
}

impl Default for DebugNodeRoutesHaConfig {
    fn default() -> Self {
        Self {
            probe_interval: duration_nanos(std::time::Duration::from_secs(10)),
            probe_timeout: duration_nanos(std::time::Duration::from_secs(5)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugDatabaseConfig {
    #[serde(rename = "Type")]
    pub database_type: String,
    #[serde(rename = "Debug")]
    pub debug: bool,
    #[serde(rename = "Gorm")]
    pub gorm: DebugGormConfig,
    #[serde(rename = "Sqlite")]
    pub sqlite: DebugSqliteConfig,
    #[serde(rename = "Postgres")]
    pub postgres: DebugPostgresConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugGormConfig {
    #[serde(rename = "Debug")]
    pub debug: bool,
    #[serde(rename = "SlowThreshold")]
    pub slow_threshold: i64,
    #[serde(rename = "SkipErrRecordNotFound")]
    pub skip_err_record_not_found: bool,
    #[serde(rename = "ParameterizedQueries")]
    pub parameterized_queries: bool,
    #[serde(rename = "PrepareStmt")]
    pub prepare_stmt: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugSqliteConfig {
    #[serde(rename = "Path")]
    pub path: String,
    #[serde(rename = "WriteAheadLog")]
    pub write_ahead_log: bool,
    #[serde(rename = "WALAutoCheckPoint")]
    pub wal_auto_check_point: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugPostgresConfig {
    #[serde(rename = "Host")]
    pub host: String,
    #[serde(rename = "Port")]
    pub port: i32,
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "User")]
    pub user: String,
    #[serde(rename = "Pass")]
    #[serde(skip_serializing)]
    pub pass: String,
    #[serde(rename = "Ssl")]
    pub ssl: String,
    #[serde(rename = "MaxOpenConnections")]
    pub max_open_connections: i32,
    #[serde(rename = "MaxIdleConnections")]
    pub max_idle_connections: i32,
    #[serde(rename = "ConnMaxIdleTimeSecs")]
    pub conn_max_idle_time_secs: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugDerpConfig {
    #[serde(rename = "ServerEnabled")]
    pub server_enabled: bool,
    #[serde(rename = "AutomaticallyAddEmbeddedDerpRegion")]
    pub automatically_add_embedded_derp_region: bool,
    #[serde(rename = "ServerRegionID")]
    pub server_region_id: i32,
    #[serde(rename = "ServerRegionCode")]
    pub server_region_code: String,
    #[serde(rename = "ServerRegionName")]
    pub server_region_name: String,
    #[serde(rename = "ServerPrivateKeyPath")]
    pub server_private_key_path: String,
    #[serde(rename = "ServerVerifyClients")]
    pub server_verify_clients: bool,
    #[serde(rename = "STUNAddr")]
    pub stun_addr: String,
    #[serde(rename = "URLs")]
    pub urls: Vec<String>,
    #[serde(rename = "Paths")]
    pub paths: Vec<String>,
    #[serde(rename = "DERPMap")]
    pub derp_map: serde_json::Value,
    #[serde(rename = "AutoUpdate")]
    pub auto_update: bool,
    #[serde(rename = "UpdateFrequency")]
    pub update_frequency: i64,
    #[serde(rename = "IPv4")]
    pub ipv4: String,
    #[serde(rename = "IPv6")]
    pub ipv6: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugTlsConfig {
    #[serde(rename = "CertPath")]
    pub cert_path: String,
    #[serde(rename = "KeyPath")]
    pub key_path: String,
    #[serde(rename = "LetsEncrypt")]
    pub lets_encrypt: DebugLetsEncryptConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugLetsEncryptConfig {
    #[serde(rename = "Listen")]
    pub listen: String,
    #[serde(rename = "Hostname")]
    pub hostname: String,
    #[serde(rename = "CacheDir")]
    pub cache_dir: String,
    #[serde(rename = "ChallengeType")]
    pub challenge_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugDnsConfig {
    #[serde(rename = "MagicDNS")]
    pub magic_dns: bool,
    #[serde(rename = "BaseDomain")]
    pub base_domain: String,
    #[serde(rename = "OverrideLocalDNS")]
    pub override_local_dns: bool,
    #[serde(rename = "Nameservers")]
    pub nameservers: DebugNameservers,
    #[serde(rename = "SearchDomains")]
    pub search_domains: Vec<String>,
    #[serde(rename = "ExtraRecords")]
    pub extra_records: Vec<serde_json::Value>,
    #[serde(rename = "ExtraRecordsPath")]
    pub extra_records_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugNameservers {
    #[serde(rename = "Global")]
    pub global: Vec<String>,
    #[serde(rename = "Split")]
    pub split: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugOidcConfig {
    #[serde(rename = "OnlyStartIfOIDCIsAvailable")]
    pub only_start_if_oidc_is_available: bool,
    #[serde(rename = "Issuer")]
    pub issuer: String,
    #[serde(rename = "ClientID")]
    pub client_id: String,
    #[serde(rename = "ClientSecret")]
    pub client_secret: String,
    #[serde(rename = "Scope")]
    pub scope: Vec<String>,
    #[serde(rename = "ExtraParams")]
    pub extra_params: BTreeMap<String, String>,
    #[serde(rename = "AllowedDomains")]
    pub allowed_domains: Vec<String>,
    #[serde(rename = "AllowedUsers")]
    pub allowed_users: Vec<String>,
    #[serde(rename = "AllowedGroups")]
    pub allowed_groups: Vec<String>,
    #[serde(rename = "EmailVerifiedRequired")]
    pub email_verified_required: bool,
    #[serde(rename = "Expiry")]
    pub expiry: i64,
    #[serde(rename = "UseExpiryFromToken")]
    pub use_expiry_from_token: bool,
    #[serde(rename = "PKCE")]
    pub pkce: DebugPkceConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugPkceConfig {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
    #[serde(rename = "Method")]
    pub method: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugEnabledConfig {
    #[serde(rename = "Enabled")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugCliConfig {
    #[serde(rename = "Address")]
    pub address: String,
    #[serde(rename = "APIKey")]
    pub api_key: String,
    #[serde(rename = "Timeout")]
    pub timeout: i64,
    #[serde(rename = "Insecure")]
    pub insecure: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugPolicyConfig {
    #[serde(rename = "Path")]
    pub path: String,
    #[serde(rename = "Mode")]
    pub mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DebugTuningConfig {
    #[serde(rename = "NotifierSendTimeout")]
    pub notifier_send_timeout: i64,
    #[serde(rename = "BatchChangeDelay")]
    pub batch_change_delay: i64,
    #[serde(rename = "NodeMapSessionBufferedChanSize")]
    pub node_map_session_buffered_chan_size: i32,
    #[serde(rename = "BatcherWorkers")]
    pub batcher_workers: usize,
    #[serde(rename = "RegisterCacheCleanup")]
    pub register_cache_cleanup: i64,
    #[serde(rename = "RegisterCacheExpiration")]
    pub register_cache_expiration: i64,
    #[serde(rename = "RegisterCacheMaxEntries")]
    pub register_cache_max_entries: i32,
    #[serde(rename = "NodeStoreBatchSize")]
    pub node_store_batch_size: i32,
    #[serde(rename = "NodeStoreBatchTimeout")]
    pub node_store_batch_timeout: i64,
}

pub async fn handle_debug_overview(State(state): State<WireState>, headers: HeaderMap) -> Response {
    let info = debug_overview_info(&state);
    if wants_json(&headers) {
        match serde_json::to_string_pretty(&info) {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
    } else {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            debug_overview_string(&info),
        )
            .into_response()
    }
}

pub async fn handle_debug_config(State(state): State<WireState>) -> Response {
    match serde_json::to_string_pretty(&debug_config_info(&state)) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

pub async fn handle_debug_routes(State(state): State<WireState>, headers: HeaderMap) -> Response {
    let snapshot = state.machines.snapshot();
    if wants_json(&headers) {
        let routes = state.machines.debug_routes_for_snapshot(&snapshot);
        match serde_json::to_string_pretty(&routes) {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
    } else {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            state.machines.debug_routes_string_for_snapshot(&snapshot),
        )
            .into_response()
    }
}

pub async fn handle_debug_derp(State(state): State<WireState>, headers: HeaderMap) -> Response {
    let derp_map = state.derp_map.snapshot();
    if wants_json(&headers) {
        let info = debug_derp_info(&derp_map);
        match serde_json::to_string_pretty(&info) {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
    } else {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            debug_derp_string(&derp_map),
        )
            .into_response()
    }
}

pub async fn handle_debug_registration_cache(State(state): State<WireState>) -> Response {
    match serde_json::to_string_pretty(&debug_registration_cache_info(&state)) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

pub async fn handle_debug_filter(State(state): State<WireState>) -> Response {
    let filter = super::map::packet_filter_for(&state.policy);
    match serde_json::to_string_pretty(&filter) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

pub async fn handle_debug_policy(State(state): State<WireState>, headers: HeaderMap) -> Response {
    let Some(policy) = state.policy.raw() else {
        return http_error(StatusCode::INTERNAL_SERVER_ERROR, "internal server error");
    };

    let content_type = if wants_json(&headers) {
        "application/json"
    } else {
        "text/plain"
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, content_type)],
        policy,
    )
        .into_response()
}

pub async fn handle_debug_ssh(State(state): State<WireState>) -> Response {
    let policies = debug_ssh_policies(&state);
    match serde_json::to_string_pretty(&policies) {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
        Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
    }
}

pub async fn handle_debug_nodestore(
    State(state): State<WireState>,
    headers: HeaderMap,
) -> Response {
    if wants_json(&headers) {
        let nodes = debug_nodestore_json(&state);
        match serde_json::to_string_pretty(&nodes) {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
    } else {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            debug_nodestore_string(&state),
        )
            .into_response()
    }
}

pub async fn handle_debug_mapresponses() -> Response {
    // headscale-go returns this exact body when
    // HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH is unset. headscale-rs does
    // not yet implement map-response dump files, so expose the same
    // disabled state instead of leaving the endpoint missing.
    (StatusCode::OK, MAPRESPONSES_DEBUG_DISABLED_BODY).into_response()
}

pub async fn handle_debug_batcher(State(state): State<WireState>, headers: HeaderMap) -> Response {
    let info = debug_batcher_info(&state);
    if wants_json(&headers) {
        match serde_json::to_string_pretty(&info) {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
    } else {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            debug_batcher_string(&info),
        )
            .into_response()
    }
}

pub async fn handle_debug_policy_manager(
    State(state): State<WireState>,
    headers: HeaderMap,
) -> Response {
    let content = debug_policy_manager_string(&state);
    if wants_json(&headers) {
        match serde_json::to_string_pretty(&DebugStringInfo { content }) {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response(),
            Err(err) => http_error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
        }
    } else {
        (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            content,
        )
            .into_response()
    }
}

pub async fn handle_windows(
    State(state): State<WireState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let url = control_url(state.public_control_url.as_deref(), &headers, &uri);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        windows_html(&url),
    )
        .into_response()
}

pub async fn handle_apple(
    State(state): State<WireState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let url = control_url(state.public_control_url.as_deref(), &headers, &uri);
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        apple_html(&url),
    )
        .into_response()
}

pub async fn handle_apple_platform(
    Path(platform): Path<String>,
    State(state): State<WireState>,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    let Some(payload_type) = apple_payload_type(&platform) else {
        return http_error(
            StatusCode::BAD_REQUEST,
            "platform must be ios, macos-app-store or macos-standalone",
        );
    };
    let url = control_url(state.public_control_url.as_deref(), &headers, &uri);
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "application/x-apple-aspen-config; charset=utf-8",
        )],
        apple_mobileconfig(&url, payload_type, &platform),
    )
        .into_response()
}

pub fn version_info() -> VersionInfo {
    VersionInfo {
        version: option_env!("HEADSCALE_RS_VERSION")
            .unwrap_or(env!("CARGO_PKG_VERSION"))
            .to_string(),
        commit: option_env!("HEADSCALE_RS_COMMIT")
            .or(option_env!("GIT_COMMIT"))
            .unwrap_or("unknown")
            .to_string(),
        build_time: option_env!("HEADSCALE_RS_BUILD_TIME")
            .or(option_env!("SOURCE_DATE_EPOCH"))
            .unwrap_or("unknown")
            .to_string(),
        // Preserve the upstream JSON field name (`go`) for clients that
        // decode the headscale-go schema. The value makes the Rust
        // implementation explicit instead of pretending to be built by Go.
        go: GoInfo {
            version: option_env!("RUSTC_VERSION")
                .map(|v| format!("rustc {v}"))
                .unwrap_or_else(|| "rustc unknown".into()),
            os: std::env::consts::OS.into(),
            arch: std::env::consts::ARCH.into(),
        },
        dirty: option_env!("HEADSCALE_RS_DIRTY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false),
    }
}

fn http_error(status: StatusCode, msg: &str) -> Response {
    (
        status,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("{msg}\n"),
    )
        .into_response()
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

fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| accept.contains("application/json"))
}

fn debug_derp_configured(derp_map: &DerpMap) -> bool {
    !derp_map.regions.is_empty() || derp_map.omit_default_regions
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

fn debug_config_info(state: &WireState) -> DebugConfigInfo {
    let mut info = state.runtime_config.as_ref().clone();
    let dns_spec = state.dns.spec();
    let tailcfg_dns_config =
        serde_json::to_value(state.dns.build(&[])).unwrap_or(serde_json::Value::Null);
    let derp_map =
        serde_json::to_value(state.derp_map.snapshot()).unwrap_or(serde_json::Value::Null);

    if let Some(public_control_url) = &state.public_control_url {
        info.server_url.clone_from(public_control_url);
    }
    info.base_domain.clone_from(&dns_spec.base_domain);
    info.derp.derp_map = derp_map;
    info.dns_config.magic_dns = dns_spec.magic_dns;
    info.dns_config
        .base_domain
        .clone_from(&dns_spec.base_domain);
    info.dns_config.override_local_dns = dns_spec.override_local_dns;
    info.dns_config
        .nameservers
        .global
        .clone_from(&dns_spec.nameservers);
    info.dns_config.nameservers.split = dns_spec
        .restricted_nameservers
        .iter()
        .map(|(suffix, resolvers)| (suffix.clone(), resolvers.clone()))
        .collect();
    info.dns_config
        .search_domains
        .clone_from(&dns_spec.search_domains);
    info.dns_config.extra_records = dns_spec
        .extra_records
        .iter()
        .filter_map(|record| serde_json::to_value(record).ok())
        .collect();
    info.dns_config.extra_records_path = dns_spec
        .extra_records_path
        .as_ref()
        .map(|path| path.display().to_string())
        .unwrap_or_default();
    info.tailcfg_dns_config = tailcfg_dns_config;
    info
}

fn duration_nanos(duration: std::time::Duration) -> i64 {
    i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
}

fn default_batcher_workers() -> usize {
    std::thread::available_parallelism().map_or(1, |cpus| (cpus.get() * 3 / 4).max(1))
}

fn metrics_text(state: &WireState) -> String {
    let snapshot = state.machines.snapshot();
    let online_states = state.machines.online_states();
    let now = chrono::Utc::now();
    let mut nodes_online = 0usize;
    let mut nodes_expired = 0usize;
    let mut nodes_ephemeral = 0usize;
    let mut users = BTreeSet::new();

    for (node_key, rec) in snapshot.iter() {
        if rec.is_expired_at(now) {
            nodes_expired += 1;
        } else if online_states
            .get(&stable_id_from_key(node_key))
            .copied()
            .unwrap_or(false)
        {
            nodes_online += 1;
        }
        if rec.ephemeral {
            nodes_ephemeral += 1;
        }
        if !rec.user.is_empty() {
            users.insert(rec.user.clone());
        }
    }

    let derp_map = state.derp_map.snapshot();
    let derp = debug_derp_info(&derp_map);
    let routes = state.machines.debug_routes_for_snapshot(&snapshot);
    let active_connections = state.machines.active_connections();
    let map_stream_connections = active_connections.values().sum::<usize>();
    let map_stream_connected_nodes = active_connections
        .values()
        .filter(|connections| **connections > 0)
        .count();

    let mut out = String::new();
    append_gauge(
        &mut out,
        "headscale_nodes_registered",
        "Current number of registered nodes in the wire registry.",
        snapshot.len(),
    );
    append_gauge(
        &mut out,
        "headscale_nodes_online",
        "Current number of streaming-online nodes in the wire registry.",
        nodes_online,
    );
    append_gauge(
        &mut out,
        "headscale_nodes_expired",
        "Current number of expired nodes in the wire registry.",
        nodes_expired,
    );
    append_gauge(
        &mut out,
        "headscale_nodes_ephemeral",
        "Current number of ephemeral nodes in the wire registry.",
        nodes_ephemeral,
    );
    append_gauge(
        &mut out,
        "headscale_users",
        "Current number of users with at least one node in the wire registry.",
        users.len(),
    );
    append_gauge(
        &mut out,
        "headscale_derp_regions",
        "Current number of configured DERP regions.",
        derp.total_regions,
    );
    append_gauge(
        &mut out,
        "headscale_policy_loaded",
        "Whether an ACL policy is currently loaded.",
        usize::from(state.policy.is_loaded()),
    );
    append_gauge(
        &mut out,
        "headscale_map_stream_connections",
        "Current number of active streaming map connections.",
        map_stream_connections,
    );
    append_gauge(
        &mut out,
        "headscale_map_stream_connected_nodes",
        "Current number of nodes with at least one active streaming map connection.",
        map_stream_connected_nodes,
    );
    append_gauge(
        &mut out,
        "headscale_routes_primary",
        "Current number of primary subnet routes.",
        routes.primary_routes.len(),
    );
    append_counter_family(
        &mut out,
        "headscale_mapresponse_endpoint_updates_total",
        "total count of endpoint updates received",
        "status",
        state.machines.mapresponse_endpoint_update_metrics(),
    );
    append_counter_family(
        &mut out,
        "headscale_mapresponse_ended_total",
        "total count of new mapsessions ended",
        "reason",
        state.machines.mapresponse_ended_metrics(),
    );
    append_counter_family(
        &mut out,
        "headscale_mapresponse_generated_total",
        "total count of mapresponses generated by response type",
        "response_type",
        state.machines.mapresponse_generated_metrics(),
    );
    append_counter_family_2(
        &mut out,
        "headscale_mapresponse_sent_total",
        "total count of mapresponses sent to clients",
        ("status", "type"),
        state.machines.mapresponse_sent_metrics(),
    );
    if super::debug_high_cardinality_metrics_enabled() {
        append_gauge_family_2(
            &mut out,
            "headscale_mapresponse_last_sent_seconds",
            "last sent metric to node.id",
            ("type", "id"),
            state.machines.mapresponse_last_sent_metrics(),
        );
    }
    append_counter_family_3(
        &mut out,
        "headscale_http_requests_total",
        "Total number of http requests processed",
        ("code", "method", "path"),
        state.machines.http_request_metrics(),
    );
    append_histogram_family(
        &mut out,
        "headscale_http_duration_seconds",
        "Duration of HTTP requests.",
        "path",
        PROMETHEUS_DEFAULT_BUCKETS,
        state.machines.http_duration_metrics(),
    );
    append_counter_family(
        &mut out,
        "headscale_nodestore_operations_total",
        "Total number of NodeStore operations",
        "operation",
        state.machines.nodestore_operation_metrics(),
    );
    append_histogram_family(
        &mut out,
        "headscale_nodestore_operation_duration_seconds",
        "Duration of NodeStore operations",
        "operation",
        PROMETHEUS_DEFAULT_BUCKETS,
        state.machines.nodestore_operation_duration_metrics(),
    );
    append_histogram(
        &mut out,
        "headscale_nodestore_batch_size",
        "Size of NodeStore write batches",
        NODESTORE_BATCH_SIZE_BUCKETS,
        &state.machines.nodestore_batch_size_metrics(),
    );
    append_histogram(
        &mut out,
        "headscale_nodestore_batch_duration_seconds",
        "Duration of NodeStore batch processing",
        PROMETHEUS_DEFAULT_BUCKETS,
        &state.machines.nodestore_batch_duration_metrics(),
    );
    append_histogram(
        &mut out,
        "headscale_nodestore_snapshot_build_duration_seconds",
        "Duration of NodeStore snapshot building from nodes",
        PROMETHEUS_DEFAULT_BUCKETS,
        &state.machines.nodestore_snapshot_build_duration_metrics(),
    );
    append_gauge(
        &mut out,
        "headscale_nodestore_nodes_total",
        "Total number of nodes in the NodeStore",
        snapshot.len(),
    );
    append_histogram(
        &mut out,
        "headscale_nodestore_peers_calculation_duration_seconds",
        "Duration of peers calculation in NodeStore",
        PROMETHEUS_DEFAULT_BUCKETS,
        &state
            .machines
            .nodestore_peers_calculation_duration_metrics(),
    );
    append_gauge(
        &mut out,
        "headscale_nodestore_queue_depth",
        "Current depth of NodeStore write queue",
        0,
    );

    out
}

fn append_gauge(out: &mut String, name: &str, help: &str, value: usize) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" gauge\n");
    out.push_str(name);
    out.push(' ');
    out.push_str(&value.to_string());
    out.push('\n');
}

fn append_counter_family(
    out: &mut String,
    name: &str,
    help: &str,
    label_name: &str,
    samples: BTreeMap<String, u64>,
) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" counter\n");
    for (label_value, value) in samples {
        out.push_str(name);
        out.push('{');
        out.push_str(label_name);
        out.push_str("=\"");
        out.push_str(&prometheus_label_value(&label_value));
        out.push_str("\"} ");
        out.push_str(&value.to_string());
        out.push('\n');
    }
}

fn prometheus_label_value(value: &str) -> String {
    value
        .replace('\\', r"\\")
        .replace('\n', r"\n")
        .replace('"', r#"\""#)
}

fn append_counter_family_2(
    out: &mut String,
    name: &str,
    help: &str,
    label_names: (&str, &str),
    samples: BTreeMap<(String, String), u64>,
) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" counter\n");
    for ((label_value_1, label_value_2), value) in samples {
        out.push_str(name);
        out.push('{');
        out.push_str(label_names.0);
        out.push_str("=\"");
        out.push_str(&prometheus_label_value(&label_value_1));
        out.push_str("\",");
        out.push_str(label_names.1);
        out.push_str("=\"");
        out.push_str(&prometheus_label_value(&label_value_2));
        out.push_str("\"} ");
        out.push_str(&value.to_string());
        out.push('\n');
    }
}

fn append_counter_family_3(
    out: &mut String,
    name: &str,
    help: &str,
    label_names: (&str, &str, &str),
    samples: BTreeMap<(String, String, String), u64>,
) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" counter\n");
    for ((label_value_1, label_value_2, label_value_3), value) in samples {
        out.push_str(name);
        out.push('{');
        out.push_str(label_names.0);
        out.push_str("=\"");
        out.push_str(&prometheus_label_value(&label_value_1));
        out.push_str("\",");
        out.push_str(label_names.1);
        out.push_str("=\"");
        out.push_str(&prometheus_label_value(&label_value_2));
        out.push_str("\",");
        out.push_str(label_names.2);
        out.push_str("=\"");
        out.push_str(&prometheus_label_value(&label_value_3));
        out.push_str("\"} ");
        out.push_str(&value.to_string());
        out.push('\n');
    }
}

fn append_gauge_family_2(
    out: &mut String,
    name: &str,
    help: &str,
    label_names: (&str, &str),
    samples: BTreeMap<(String, String), f64>,
) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" gauge\n");
    for ((label_value_1, label_value_2), value) in samples {
        out.push_str(name);
        out.push('{');
        out.push_str(label_names.0);
        out.push_str("=\"");
        out.push_str(&prometheus_label_value(&label_value_1));
        out.push_str("\",");
        out.push_str(label_names.1);
        out.push_str("=\"");
        out.push_str(&prometheus_label_value(&label_value_2));
        out.push_str("\"} ");
        out.push_str(&prometheus_float(value));
        out.push('\n');
    }
}

fn append_histogram_family(
    out: &mut String,
    name: &str,
    help: &str,
    label_name: &str,
    buckets: &[(f64, &str)],
    samples: BTreeMap<String, HistogramMetric>,
) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" histogram\n");
    for (label_value, sample) in samples {
        for (_upper_bound, le) in buckets {
            append_histogram_bucket(out, name, label_name, &label_value, le, sample.bucket(le));
        }
        append_histogram_bucket(out, name, label_name, &label_value, "+Inf", sample.count);
        out.push_str(name);
        out.push_str("_sum{");
        out.push_str(label_name);
        out.push_str("=\"");
        out.push_str(&prometheus_label_value(&label_value));
        out.push_str("\"} ");
        out.push_str(&prometheus_float(sample.sum));
        out.push('\n');
        out.push_str(name);
        out.push_str("_count{");
        out.push_str(label_name);
        out.push_str("=\"");
        out.push_str(&prometheus_label_value(&label_value));
        out.push_str("\"} ");
        out.push_str(&sample.count.to_string());
        out.push('\n');
    }
}

fn append_histogram(
    out: &mut String,
    name: &str,
    help: &str,
    buckets: &[(f64, &str)],
    sample: &HistogramMetric,
) {
    out.push_str("# HELP ");
    out.push_str(name);
    out.push(' ');
    out.push_str(help);
    out.push('\n');
    out.push_str("# TYPE ");
    out.push_str(name);
    out.push_str(" histogram\n");
    for (_upper_bound, le) in buckets {
        out.push_str(name);
        out.push_str("_bucket{le=\"");
        out.push_str(le);
        out.push_str("\"} ");
        out.push_str(&sample.bucket(le).to_string());
        out.push('\n');
    }
    out.push_str(name);
    out.push_str("_bucket{le=\"+Inf\"} ");
    out.push_str(&sample.count.to_string());
    out.push('\n');
    out.push_str(name);
    out.push_str("_sum ");
    out.push_str(&prometheus_float(sample.sum));
    out.push('\n');
    out.push_str(name);
    out.push_str("_count ");
    out.push_str(&sample.count.to_string());
    out.push('\n');
}

fn append_histogram_bucket(
    out: &mut String,
    name: &str,
    label_name: &str,
    label_value: &str,
    le: &str,
    value: u64,
) {
    out.push_str(name);
    out.push_str("_bucket{");
    out.push_str(label_name);
    out.push_str("=\"");
    out.push_str(&prometheus_label_value(label_value));
    out.push_str("\",le=\"");
    out.push_str(le);
    out.push_str("\"} ");
    out.push_str(&value.to_string());
    out.push('\n');
}

fn prometheus_float(value: f64) -> String {
    if value.is_finite() {
        value.to_string()
    } else if value.is_sign_positive() {
        "+Inf".to_string()
    } else {
        "-Inf".to_string()
    }
}

fn debug_nodestore_json(state: &WireState) -> BTreeMap<String, DebugNodeStoreNode> {
    let snapshot = state.machines.snapshot();
    let online_states = state.machines.online_states();
    let now = chrono::Utc::now();
    snapshot
        .iter()
        .map(|(node_key, rec)| {
            let id = stable_id_from_key(node_key);
            (
                id.to_string(),
                DebugNodeStoreNode {
                    id,
                    node_key: node_key.clone(),
                    machine_key: rec.machine_key_hex.clone(),
                    user: rec.user.clone(),
                    hostname: rec.hostname.clone(),
                    ipv4: rec.ipv4.map(|addr| addr.to_string()).unwrap_or_default(),
                    online: !rec.is_expired_at(now)
                        && online_states.get(&id).copied().unwrap_or(false),
                    expired: rec.is_expired_at(now),
                    ephemeral: rec.ephemeral,
                    created_at: rec.created_at.to_rfc3339(),
                    last_seen: rec.last_seen.to_rfc3339(),
                    expiry: rec.expiry.map(|expiry| expiry.to_rfc3339()),
                    forced_tags: rec.forced_tags.clone(),
                    available_routes: rec.available_routes.clone(),
                    approved_routes: rec.approved_routes.clone(),
                },
            )
        })
        .collect()
}

#[allow(clippy::cast_precision_loss, clippy::format_push_string)]
fn debug_nodestore_string(state: &WireState) -> String {
    let snapshot = state.machines.snapshot();
    let mut out = String::from("=== NodeStore Debug Information ===\n\n");

    let mut nodes_by_user: BTreeMap<String, Vec<&MachineRecord>> = BTreeMap::new();
    for rec in snapshot.values() {
        let user = if rec.user.is_empty() {
            "unknown".to_string()
        } else {
            rec.user.clone()
        };
        nodes_by_user.entry(user).or_default().push(rec);
    }

    out.push_str(&format!("Total Nodes: {}\n", snapshot.len()));
    out.push_str(&format!("Users with Nodes: {}\n", nodes_by_user.len()));
    out.push('\n');

    out.push_str("Nodes by Internal User ID:\n");
    for (user, nodes) in &nodes_by_user {
        let tagged_count = nodes
            .iter()
            .filter(|node| !node.forced_tags.is_empty())
            .count();
        if tagged_count > 0 {
            out.push_str(&format!(
                "  - User {user} ({user}): {} nodes ({tagged_count} tagged)\n",
                nodes.len()
            ));
        } else {
            out.push_str(&format!(
                "  - User {user} ({user}): {} nodes\n",
                nodes.len()
            ));
        }
    }
    out.push('\n');

    out.push_str("Peer Relationships:\n");
    let peer_map = debug_peer_map_for_snapshot(&state.policy, &snapshot);
    let mut total_peers = 0usize;
    for (node_key, rec) in sorted_snapshot_nodes(&snapshot) {
        let node_id = stable_id_from_key(node_key);
        let peer_count = peer_map
            .get(&node_id)
            .map_or(snapshot.len().saturating_sub(1), BTreeSet::len);
        total_peers += peer_count;
        out.push_str(&format!(
            "  - Node {node_id} ({}): {peer_count} peers\n",
            rec.hostname
        ));
    }
    if !snapshot.is_empty() {
        let avg_peers = total_peers as f64 / snapshot.len() as f64;
        out.push_str(&format!("  - Average peers per node: {avg_peers:.1}\n"));
    }
    out.push('\n');

    out.push_str(&format!("NodeKey Index: {} entries\n", snapshot.len()));
    out.push('\n');

    out
}

#[allow(clippy::format_push_string)]
fn debug_policy_manager_string(state: &WireState) -> String {
    let version = state.policy.updated_at().unwrap_or(0);
    let mut out = format!("PolicyManager (v{version}):\n\n");

    out.push_str("\n\n");

    if let Some(doc) = state.policy.doc() {
        if let Ok(policy) = serde_json::to_string_pretty(&doc) {
            out.push_str("Policy:\n");
            out.push_str(&policy);
            out.push_str("\n\n");
        }

        out.push_str(&format!(
            "AutoApprover ({}):\n",
            doc.auto_approvers.routes.len() + usize::from(!doc.auto_approvers.exit_node.is_empty())
        ));
        for (prefix, approvers) in &doc.auto_approvers.routes {
            out.push_str(&format!("\t{prefix}:\n"));
            for approver in approvers {
                out.push_str(&format!("\t\t{approver}\n"));
            }
        }
        if !doc.auto_approvers.exit_node.is_empty() {
            out.push_str("\texitNode:\n");
            for approver in &doc.auto_approvers.exit_node {
                out.push_str(&format!("\t\t{approver}\n"));
            }
        }

        out.push_str("\n\n");

        out.push_str(&format!("TagOwner ({}):\n", doc.tag_owners.len()));
        for (tag, owners) in &doc.tag_owners {
            out.push_str(&format!("\t{tag}:\n"));
            for owner in owners {
                out.push_str(&format!("\t\t{owner}\n"));
            }
        }

        out.push_str("\n\n");

        let filter = state.policy.filter_rules();
        if let Ok(filter_json) = serde_json::to_string_pretty(&filter) {
            out.push_str("Compiled filter:\n");
            out.push_str(&filter_json);
            out.push_str("\n\n");
        }
    } else {
        out.push_str("AutoApprover (0):\n");
        out.push_str("\n\n");
        out.push_str("TagOwner (0):\n");
        out.push_str("\n\n");
    }

    out.push_str("\n\n");
    out.push_str("Matchers:\n");
    out.push_str("an internal structure used to filter nodes and routes\n");
    for line in debug_matcher_lines(&state.policy) {
        out.push_str(&line);
        out.push('\n');
    }

    out.push_str("\n\n");
    out.push_str("Nodes:\n");
    for (node_key, rec) in sorted_snapshot_nodes(&state.machines.snapshot()) {
        out.push_str(&format!(
            "id:{} hostname:{} user:{} addr:{}\n",
            stable_id_from_key(node_key),
            rec.hostname,
            rec.user,
            rec.primary_addr_string().unwrap_or_default()
        ));
    }

    out
}

fn debug_matcher_lines(policy: &crate::policy::PolicyStore) -> Vec<String> {
    let Some(doc) = policy.doc() else {
        return Vec::new();
    };

    let mut lines = Vec::new();
    for rule in doc.rules {
        if !matches!(rule.action, PolicyAction::Accept) {
            continue;
        }
        lines.push("Match:".to_string());
        lines.push("  Sources:".to_string());
        for src in rule.src {
            lines.push(format!("    {src}"));
        }
        lines.push("  Destinations:".to_string());
        for dst in rule.dst {
            lines.push(format!("    {dst}"));
        }
    }
    lines
}

fn debug_peer_map_for_snapshot(
    policy: &crate::policy::PolicyStore,
    snapshot: &HashMap<String, MachineRecord>,
) -> BTreeMap<u64, BTreeSet<u64>> {
    let primary_routes = stateful_primary_routes_for_debug(snapshot);
    let nodes = snapshot
        .iter()
        .map(|(node_key, rec)| PeerMapNode {
            id: stable_id_from_key(node_key),
            addr: rec.primary_addr_string().unwrap_or_default(),
            user: (!rec.user.is_empty()).then(|| rec.user.clone()),
            tags: rec.forced_tags.clone(),
            routes: primary_routes.get(node_key).cloned().unwrap_or_default(),
        })
        .collect::<Vec<_>>();

    if let Some(map) = policy.build_peer_map(&nodes) {
        return map
            .into_iter()
            .map(|(node_id, peers)| (node_id, peers.into_iter().collect()))
            .collect();
    }

    let all_ids = snapshot
        .keys()
        .map(|node_key| stable_id_from_key(node_key))
        .collect::<BTreeSet<_>>();
    snapshot
        .keys()
        .map(|node_key| {
            let node_id = stable_id_from_key(node_key);
            let peers = all_ids
                .iter()
                .copied()
                .filter(|peer_id| *peer_id != node_id)
                .collect();
            (node_id, peers)
        })
        .collect()
}

fn stateful_primary_routes_for_debug(
    snapshot: &HashMap<String, MachineRecord>,
) -> BTreeMap<String, Vec<String>> {
    let mut routes_by_prefix: BTreeMap<String, Vec<(&String, u64)>> = BTreeMap::new();
    for (node_key, rec) in snapshot {
        for route in rec
            .available_routes
            .iter()
            .filter(|route| rec.approved_routes.contains(route))
            .filter(|route| *route != "0.0.0.0/0" && *route != "::/0")
        {
            routes_by_prefix
                .entry(route.clone())
                .or_default()
                .push((node_key, stable_id_from_key(node_key)));
        }
    }

    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (prefix, mut nodes) in routes_by_prefix {
        nodes.sort_by_key(|(_, node_id)| *node_id);
        if let Some((node_key, _)) = nodes.first() {
            out.entry((*node_key).clone()).or_default().push(prefix);
        }
    }
    out
}

fn sorted_snapshot_nodes(
    snapshot: &HashMap<String, MachineRecord>,
) -> Vec<(&String, &MachineRecord)> {
    let mut nodes = snapshot.iter().collect::<Vec<_>>();
    nodes.sort_by_key(|(node_key, _)| stable_id_from_key(node_key));
    nodes
}

fn debug_overview_info(state: &WireState) -> DebugOverviewInfo {
    let snapshot = state.machines.snapshot();
    let online_states = state.machines.online_states();
    let now = chrono::Utc::now();
    let mut nodes = DebugOverviewNodes {
        total: snapshot.len(),
        ..DebugOverviewNodes::default()
    };
    let mut users = BTreeMap::new();

    for (node_key, rec) in snapshot.iter() {
        let expired = rec.is_expired_at(now);
        if expired {
            nodes.expired += 1;
        } else if online_states
            .get(&stable_id_from_key(node_key))
            .copied()
            .unwrap_or(false)
        {
            nodes.online += 1;
        }
        if rec.ephemeral {
            nodes.ephemeral += 1;
        }
        if !rec.user.is_empty() {
            *users.entry(rec.user.clone()).or_insert(0) += 1;
        }
    }

    let routes = state.machines.debug_routes_for_snapshot(&snapshot);
    let derp_map = state.derp_map.snapshot();
    let derp = debug_derp_info(&derp_map);
    DebugOverviewInfo {
        nodes,
        total_users: users.len(),
        users,
        policy: DebugOverviewPolicy {
            mode: "memory".to_string(),
            path: None,
        },
        derp: DebugOverviewDerp {
            configured: derp.configured,
            regions: derp.total_regions,
        },
        primary_routes: routes.primary_routes.len(),
    }
}

#[allow(clippy::format_push_string)]
fn debug_overview_string(info: &DebugOverviewInfo) -> String {
    let mut out = String::from("=== Headscale State Overview ===\n\n");

    out.push_str(&format!("Nodes: {} total\n", info.nodes.total));
    out.push_str(&format!("  - Online: {}\n", info.nodes.online));
    out.push_str(&format!("  - Expired: {}\n", info.nodes.expired));
    out.push_str(&format!("  - Ephemeral: {}\n", info.nodes.ephemeral));
    out.push('\n');

    out.push_str(&format!("Users: {} total\n", info.total_users));
    for (user, node_count) in &info.users {
        out.push_str(&format!("  - {user}: {node_count} nodes\n"));
    }
    out.push('\n');

    out.push_str("Policy:\n");
    out.push_str(&format!("  - Mode: {}\n", info.policy.mode));
    if let Some(path) = &info.policy.path {
        out.push_str(&format!("  - Path: {path}\n"));
    }
    out.push('\n');

    if info.derp.configured {
        out.push_str(&format!("DERP: {} regions configured\n", info.derp.regions));
    } else {
        out.push_str("DERP: not configured\n");
    }
    out.push('\n');

    out.push_str(&format!("Primary Routes: {} active\n", info.primary_routes));
    out.push('\n');

    out.push_str("Registration Cache: active\n");
    out.push('\n');

    out
}

fn debug_batcher_info(state: &WireState) -> DebugBatcherInfo {
    let connected_nodes = state
        .machines
        .active_connections()
        .into_iter()
        .map(|(node_id, active_connections)| {
            (
                node_id.to_string(),
                DebugBatcherNodeInfo {
                    connected: active_connections > 0,
                    active_connections,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    DebugBatcherInfo {
        total_nodes: connected_nodes.len(),
        connected_nodes,
    }
}

#[allow(clippy::format_push_string)]
fn debug_batcher_string(info: &DebugBatcherInfo) -> String {
    let mut out = String::from("=== Batcher Connected Nodes ===\n\n");
    let mut connected_count = 0;

    for (node_id, node) in &info.connected_nodes {
        let status = if node.connected {
            connected_count += 1;
            "connected"
        } else {
            "disconnected"
        };
        if node.active_connections > 0 {
            out.push_str(&format!(
                "Node {node_id}:\t{status} ({} connections)\n",
                node.active_connections
            ));
        } else {
            out.push_str(&format!("Node {node_id}:\t{status}\n"));
        }
    }

    out.push_str(&format!(
        "\nSummary: {connected_count} connected, {} total\n",
        info.total_nodes
    ));

    out
}

fn debug_derp_info(derp_map: &DerpMap) -> DebugDerpInfo {
    let configured = debug_derp_configured(derp_map);
    let mut info = DebugDerpInfo {
        configured,
        total_regions: if configured {
            derp_map.regions.len()
        } else {
            0
        },
        regions: BTreeMap::new(),
    };

    if !configured {
        return info;
    }

    for (region_id, region) in &derp_map.regions {
        let nodes = region
            .nodes
            .iter()
            .map(|node| DebugDerpNode {
                name: node.name.clone(),
                hostname: node.host_name.clone(),
                derp_port: node.derp_port,
                stun_port: node.stun_port,
            })
            .collect();
        info.regions.insert(
            *region_id,
            DebugDerpRegion {
                region_id: *region_id,
                region_name: region.region_name.clone(),
                nodes,
            },
        );
    }

    info
}

#[allow(clippy::format_push_string)]
fn debug_derp_string(derp_map: &DerpMap) -> String {
    if !debug_derp_configured(derp_map) {
        return "DERP Map: not configured\n".to_string();
    }

    let mut out = String::from("=== DERP Map Configuration ===\n\n");
    out.push_str(&format!("Total Regions: {}\n\n", derp_map.regions.len()));

    let mut regions = derp_map.regions.iter().collect::<Vec<_>>();
    regions.sort_by_key(|(region_id, _)| **region_id);
    for (region_id, region) in regions {
        out.push_str(&format!("Region {region_id}: {}\n", region.region_name));
        out.push_str(&format!("  - Nodes: {}\n", region.nodes.len()));

        for node in &region.nodes {
            out.push_str(&format!(
                "    - {} ({}:{})\n",
                node.name, node.host_name, node.derp_port
            ));
            if node.stun_port != 0 {
                out.push_str(&format!("      STUN: {}\n", node.stun_port));
            }
        }
        out.push('\n');
    }

    out
}

fn debug_registration_cache_info(state: &WireState) -> DebugRegistrationCacheInfo {
    DebugRegistrationCacheInfo {
        cache_type: "zcache".to_string(),
        expiration: go_duration_string(state.registration_cache.expiration()),
        cleanup: go_duration_string(state.registration_cache.cleanup_interval()),
        status: "active".to_string(),
    }
}

fn go_duration_string(duration: std::time::Duration) -> String {
    let total = duration.as_secs();
    let hours = total / 3600;
    let minutes = (total % 3600) / 60;
    let seconds = total % 60;

    if hours > 0 {
        format!("{hours}h{minutes}m{seconds}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds}s")
    } else {
        format!("{seconds}s")
    }
}

fn debug_ssh_policies(state: &WireState) -> BTreeMap<String, Option<SshPolicy>> {
    let snapshot = state.machines.snapshot();
    let nodes = ssh_policy_nodes_from_snapshot(&snapshot);

    snapshot
        .iter()
        .map(|(node_key, rec)| {
            let id = stable_id_from_key(node_key);
            let policy = state.policy.ssh_policy_for(&nodes, id);
            (
                format!(
                    "id:{id} hostname:{} givenname:{}",
                    rec.hostname, rec.hostname
                ),
                policy,
            )
        })
        .collect()
}

fn ssh_policy_nodes_from_snapshot(
    snapshot: &std::collections::HashMap<String, MachineRecord>,
) -> Vec<SshPolicyNode> {
    snapshot
        .iter()
        .map(|(node_key, rec)| SshPolicyNode {
            id: stable_id_from_key(node_key),
            user: if rec.user.is_empty() {
                None
            } else {
                Some(rec.user.clone())
            },
            addrs: rec.address_strings(),
            tags: rec.forced_tags.clone(),
        })
        .collect()
}

fn control_url(configured: Option<&str>, headers: &HeaderMap, uri: &Uri) -> String {
    if let Some(configured) = configured.map(str::trim).filter(|url| !url.is_empty()) {
        return configured.trim_end_matches('/').to_string();
    }

    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.scheme_str())
        .unwrap_or("http")
        .split(',')
        .next()
        .unwrap_or("http")
        .trim();
    let host = headers
        .get("x-forwarded-host")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get(header::HOST).and_then(|v| v.to_str().ok()))
        .or_else(|| uri.authority().map(http::uri::Authority::as_str))
        .unwrap_or("localhost")
        .split(',')
        .next()
        .unwrap_or("localhost")
        .trim();
    format!("{scheme}://{host}")
}

fn windows_html(url: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Headscale Windows configuration</title></head>
<body>
<h1>Connect Windows to Headscale</h1>
<p>Install <a href="https://tailscale.com/download/windows">Tailscale for Windows</a>, then run:</p>
<pre><code>tailscale up --login-server {url}</code></pre>
</body>
</html>"#
    )
}

fn apple_html(url: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Headscale Apple configuration</title></head>
<body>
<h1>Connect Apple devices to Headscale</h1>
<p>Install Tailscale from the <a href="https://apps.apple.com/app/tailscale/id1470499037">App Store</a>.</p>
<p>Download a configuration profile for this server:</p>
<ul>
<li><a href="/apple/ios">iOS profile</a></li>
<li><a href="/apple/macos-app-store">macOS AppStore profile</a></li>
<li><a href="/apple/macos-standalone">macOS Standalone profile</a></li>
</ul>
<pre><code>curl {url}/apple/macos-app-store</code></pre>
<pre><code>curl {url}/apple/macos-standalone</code></pre>
</body>
</html>"#
    )
}

fn apple_payload_type(platform: &str) -> Option<&'static str> {
    match platform {
        "ios" => Some("io.tailscale.ipn.ios"),
        "macos-app-store" => Some("io.tailscale.ipn.macos"),
        "macos-standalone" => Some("io.tailscale.ipn.macsys"),
        _ => None,
    }
}

fn swagger_html() -> &'static str {
    r#"
<html>
    <head>
    <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@3/swagger-ui.css">
    <link rel="icon" href="/favicon.ico">
    <script src="https://unpkg.com/swagger-ui-dist@3/swagger-ui-standalone-preset.js"></script>
    <script src="https://unpkg.com/swagger-ui-dist@3/swagger-ui-bundle.js" charset="UTF-8"></script>
    </head>
    <body>
    <div id="swagger-ui"></div>
    <script>
        window.addEventListener('load', (event) => {
            const ui = SwaggerUIBundle({
                url: "/swagger/v1/openapiv2.json",
                dom_id: '#swagger-ui',
                presets: [
                  SwaggerUIBundle.presets.apis,
                  SwaggerUIBundle.SwaggerUIStandalonePreset
                ],
                plugins: [
                    SwaggerUIBundle.plugins.DownloadUrl
                ],
                deepLinking: true,
                // TODO(kradalby): Figure out why this does not work
                // layout: "StandaloneLayout",
              })
            window.ui = ui
        });
    </script>
    </body>
</html>"#
}

fn blank_html() -> &'static str {
    r#"<html lang="en"><head><meta charset="UTF-8"><link rel="icon" href="/favicon.ico"></head><body></body></html>"#
}

fn debug_index_html() -> String {
    let version = version_info();
    let mut out = String::from("<html><body><h1>headscale debug</h1><ul>");
    out.push_str("<li><b>Version:</b> ");
    out.push_str(&html_escape(&version.version));
    out.push_str("</li>");

    for (href, description) in DEBUG_INDEX_LINKS {
        out.push_str(r#"<li><a href=""#);
        out.push_str(&html_escape(href));
        out.push_str(r#"">"#);
        out.push_str(&html_escape(href));
        out.push_str("</a> (");
        out.push_str(&html_escape(description));
        out.push_str(")</li>");
    }

    out.push_str("</ul></body></html>");
    out
}

fn debug_pprof_index_html() -> String {
    let mut out = String::from(
        r"<html><head><title>/debug/pprof/</title></head><body><h1>/debug/pprof/</h1><p>Types of profiles available:</p><table>",
    );
    for profile in PPROF_PROFILE_NAMES {
        out.push_str(r#"<tr><td><a href=""#);
        out.push_str(&html_escape(profile));
        out.push_str(r#"?debug=1">"#);
        out.push_str(&html_escape(profile));
        out.push_str("</a></td></tr>");
    }
    out.push_str(
        r#"</table><p><a href="cmdline">cmdline</a></p><p><a href="profile">profile</a></p><p><a href="trace">trace</a></p></body></html>"#,
    );
    out
}

fn rust_pprof_profile_text(profile: &str) -> String {
    format!(
        "profile: {profile}\nruntime: rust\nos: {}\narch: {}\navailable_parallelism: {}\n",
        env::consts::OS,
        env::consts::ARCH,
        thread::available_parallelism()
            .map(std::num::NonZero::get)
            .unwrap_or(1)
    )
}

fn debug_statsviz_html() -> &'static str {
    r#"<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Statsviz</title>
  </head>
  <body>
    <h1>Statsviz</h1>
    <p>Rust runtime metrics are exposed through /metrics and /debug/vars.</p>
    <script>
      window.__STATSVIZ_WS__ = "/debug/statsviz/ws";
    </script>
  </body>
</html>"#
}

fn register_web_html(registration_id: &str) -> String {
    let escaped_registration_id = html_escape(registration_id);
    format!(
        r#"<html lang="en"><head><meta charset="UTF-8"><meta http-equiv="X-UA-Compatible" content="IE=edge"><meta name="viewport" content="width=device-width, initial-scale=1.0"><link rel="icon" href="/favicon.ico"><title>Registration - Headscale</title></head><body translate="no"><main><h1>Machine registration</h1><p>Run the command below in the headscale server to add this machine to your network:</p><pre><code>headscale nodes register --key {escaped_registration_id} --user USERNAME</code></pre><footer>Powered by <a href="https://github.com/juanfont/headscale" rel="noreferrer noopener" target="_blank">Headscale</a></footer></main></body></html>"#
    )
}

fn html_escape(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn apple_mobileconfig(url: &str, payload_type: &str, platform: &str) -> String {
    let payload_uuid = match platform {
        "ios" => "00000000-0000-4000-8000-000000000001",
        "macos-app-store" => "00000000-0000-4000-8000-000000000002",
        "macos-standalone" => "00000000-0000-4000-8000-000000000003",
        _ => "00000000-0000-4000-8000-000000000000",
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>PayloadUUID</key>
    <string>00000000-0000-4000-8000-000000000010</string>
    <key>PayloadDisplayName</key>
    <string>Headscale</string>
    <key>PayloadDescription</key>
    <string>Configure Tailscale login server to: {url}</string>
    <key>PayloadIdentifier</key>
    <string>com.github.juanfont.headscale</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadContent</key>
    <array>
      <dict>
        <key>PayloadType</key>
        <string>{payload_type}</string>
        <key>PayloadUUID</key>
        <string>{payload_uuid}</string>
        <key>PayloadIdentifier</key>
        <string>com.github.juanfont.headscale</string>
        <key>PayloadVersion</key>
        <integer>1</integer>
        <key>PayloadEnabled</key>
        <true/>
        <key>ControlURL</key>
        <string>{url}</string>
      </dict>
    </array>
  </dict>
</plist>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{
        DerpMap, DerpRegion, DerpRegionNode, MachineRecord, MachineRegistry, WireState,
        noise::{NoisePeerMachineKey, ServerNoiseKey, inner_router as machine_router},
        router,
        test_support::{MockIpAllocator, MockRedeemer},
        wire::stable_id_from_key,
    };
    use axum::body::to_bytes;
    use chrono::Utc;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tower::ServiceExt;

    struct HighCardinalityMetricsGuard;

    impl HighCardinalityMetricsGuard {
        fn enable() -> Self {
            crate::tailscale_wire::set_debug_high_cardinality_metrics_for_tests(true);
            Self
        }
    }

    impl Drop for HighCardinalityMetricsGuard {
        fn drop(&mut self) {
            crate::tailscale_wire::set_debug_high_cardinality_metrics_for_tests(false);
        }
    }

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
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: None,
            runtime_config: Arc::new(crate::tailscale_wire::RuntimeConfigSnapshot::default()),
            registration_cache: Arc::new(crate::tailscale_wire::RegistrationCache::new()),
            pings: Arc::new(crate::tailscale_wire::PingTracker::new()),
        };
        (state, dir)
    }

    fn record(
        node_key: &str,
        host: u8,
        available_routes: &[&str],
        approved_routes: &[&str],
    ) -> MachineRecord {
        let mut rec = MachineRecord::new_at(
            Utc::now(),
            node_key.to_string(),
            format!("mkey-{node_key}"),
            "alice".to_string(),
            format!("host-{host}"),
            Ipv4Addr::new(100, 64, 0, host),
            false,
        );
        rec.available_routes = available_routes
            .iter()
            .map(|route| (*route).to_string())
            .collect();
        rec.approved_routes = approved_routes
            .iter()
            .map(|route| (*route).to_string())
            .collect();
        rec
    }

    fn derp_fixture() -> DerpMap {
        DerpMap {
            home_params: None,
            omit_default_regions: true,
            regions: HashMap::from([(
                1,
                DerpRegion {
                    region_id: 1,
                    region_code: "test".to_string(),
                    region_name: "Test region".to_string(),
                    latitude: 0.0,
                    longitude: 0.0,
                    avoid: false,
                    no_measure_no_home: false,
                    nodes: vec![DerpRegionNode {
                        name: "derp-1".to_string(),
                        region_id: 1,
                        host_name: "derp1.example.com".to_string(),
                        cert_name: String::new(),
                        ipv4: "198.51.100.10".to_string(),
                        ipv6: String::new(),
                        derp_port: 443,
                        stun_port: 3478,
                        stun_only: false,
                        insecure_for_tests: false,
                        stun_test_ip: String::new(),
                        can_port80: false,
                    }],
                },
            )]),
        }
    }

    #[tokio::test]
    async fn robots_txt_matches_headscale_go_body() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/robots.txt")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], ROBOTS_BODY.as_bytes());
    }

    #[tokio::test]
    async fn health_endpoint_matches_headscale_go_pass_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/health+json; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.status, "pass");
    }

    #[tokio::test]
    async fn version_endpoint_keeps_headscale_go_json_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/version")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: VersionInfo = serde_json::from_slice(&body).unwrap();
        assert!(!parsed.version.is_empty());
        assert!(!parsed.commit.is_empty());
        assert!(!parsed.build_time.is_empty());
        assert!(parsed.go.version.starts_with("rustc "));
        assert!(!parsed.go.os.is_empty());
        assert!(!parsed.go.arch.is_empty());
    }

    #[tokio::test]
    async fn web_register_renders_headscale_go_cli_instruction() {
        let (state, _dir) = fixture_state();
        let registration_id = "3oYCOZYA2zZmGB4PQ7aHBaMi";
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri(format!("/register/{registration_id}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            body.contains("<title>Registration - Headscale</title>"),
            "{body}"
        );
        assert!(body.contains("<h1>Machine registration</h1>"), "{body}");
        assert!(
            body.contains(&format!(
                "headscale nodes register --key {registration_id} --user USERNAME"
            )),
            "{body}"
        );
    }

    #[tokio::test]
    async fn web_register_rejects_invalid_registration_id_like_headscale_go() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/register/short")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"invalid registration id\n");
    }

    #[test]
    fn web_register_template_escapes_registration_id_in_command() {
        let html = register_web_html("abc<&\"'defghijklmnopqrs");
        assert!(
            html.contains("abc&lt;&amp;&quot;&#39;defghijklmnopqrs"),
            "{html}"
        );
        assert!(!html.contains("abc<&\"'defghijklmnopqrs"), "{html}");
    }

    #[tokio::test]
    async fn verify_endpoint_allows_registered_node_key() {
        let (state, _dir) = fixture_state();
        let node_key = "11".repeat(32);
        let rec = record(&node_key, 11, &[], &[]);
        state.machines.upsert(rec.node_key_hex.clone(), rec);

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .body(axum::body::Body::from(format!(
                        "{{\"NodePublic\":\"nodekey:{node_key}\",\"Source\":\"203.0.113.10\"}}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"{\"Allow\":true}\n");
    }

    #[tokio::test]
    async fn verify_endpoint_denies_unknown_node_key() {
        let (state, _dir) = fixture_state();
        let node_key = "22".repeat(32);

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .body(axum::body::Body::from(format!(
                        "{{\"NodePublic\":\"nodekey:{node_key}\",\"Source\":\"203.0.113.11\"}}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: DerpAdmitClientResponse = serde_json::from_slice(&body).unwrap();
        assert!(!parsed.allow);
    }

    #[tokio::test]
    async fn verify_endpoint_rejects_invalid_admit_json_like_headscale_go() {
        let (state, _dir) = fixture_state();

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .body(axum::body::Body::from(
                        "{\"NodePublic\":\"not-a-node-key\"}",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"Bad Request: invalid JSON\n");
    }

    #[tokio::test]
    async fn verify_endpoint_rejects_oversized_body_like_headscale_go() {
        let (state, _dir) = fixture_state();

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .body(axum::body::Body::from(vec![b'x'; VERIFY_BODY_LIMIT + 1]))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"request body too large\n");
    }

    #[tokio::test]
    async fn derp_probe_get_matches_headscale_go_probe() {
        let (state, _dir) = fixture_state();

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/derp/probe")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn derp_latency_check_head_matches_headscale_go_probe() {
        let (state, _dir) = fixture_state();

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("HEAD")
                    .uri("/derp/latency-check")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn derp_probe_rejects_post_like_headscale_go() {
        let (state, _dir) = fixture_state();

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/derp/probe")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"bogus probe method");
    }

    #[tokio::test]
    async fn derp_bootstrap_dns_empty_map_matches_headscale_go_shape() {
        let (state, _dir) = fixture_state();

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/bootstrap-dns")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"{}\n");
    }

    #[tokio::test]
    async fn derp_bootstrap_dns_resolves_derp_node_hosts_like_headscale_go() {
        let (mut state, _dir) = fixture_state();
        let mut derp_map = derp_fixture();
        derp_map
            .regions
            .get_mut(&1)
            .unwrap()
            .nodes
            .get_mut(0)
            .unwrap()
            .host_name = "192.0.2.10".to_string();
        state.derp_map = crate::tailscale_wire::DerpMapStore::shared(derp_map);

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/bootstrap-dns")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: BTreeMap<String, Vec<std::net::IpAddr>> =
            serde_json::from_slice(&body).unwrap();
        assert_eq!(
            parsed.get("192.0.2.10"),
            Some(&vec![std::net::IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))])
        );
    }

    #[tokio::test]
    async fn debug_root_redirects_to_slash_like_headscale_go_servemux() {
        let (state, _dir) = fixture_state();

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            resp.headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/debug/")
        );
    }

    #[tokio::test]
    async fn debug_index_lists_headscale_go_debug_links() {
        let (state, _dir) = fixture_state();

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(body.contains("<h1>headscale debug</h1>"), "{body}");
        assert!(body.contains("<li><b>Version:</b> "), "{body}");
        for (href, description) in DEBUG_INDEX_LINKS {
            assert!(
                body.contains(&format!(r#"<a href="{href}">{href}</a>"#)),
                "{body}"
            );
            assert!(body.contains(description), "{body}");
        }
    }

    #[tokio::test]
    async fn debug_varz_alias_serves_prometheus_metrics_like_tsweb() {
        let (state, _dir) = fixture_state();

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/varz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some(PROMETHEUS_TEXT_CONTENT_TYPE)
        );
        let body = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            body.contains("# TYPE headscale_nodes_registered gauge"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn debug_vars_serves_expvar_style_runtime_json() {
        let (state, _dir) = fixture_state();

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/vars")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(parsed["cmdline"].is_array(), "{parsed}");
        assert_eq!(parsed["rust"]["os"], env::consts::OS);
        assert_eq!(parsed["rust"]["arch"], env::consts::ARCH);
        assert_eq!(parsed["headscale"]["nodes_registered"], 0);
    }

    #[tokio::test]
    async fn debug_pprof_surface_matches_tsweb_routes() {
        let (state, _dir) = fixture_state();
        let app = router(state);

        let redirect = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/pprof")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(redirect.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            redirect
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/debug/pprof/")
        );

        let index = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/pprof/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(index.status(), StatusCode::OK);
        let body = to_bytes(index.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("Types of profiles available"), "{body}");
        assert!(body.contains("goroutine"), "{body}");
        assert!(body.contains("cmdline"), "{body}");

        let goroutine = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/pprof/goroutine?debug=1")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(goroutine.status(), StatusCode::OK);
        let body = to_bytes(goroutine.into_body(), 4096).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("profile: goroutine"), "{body}");
        assert!(body.contains("runtime: rust"), "{body}");
    }

    #[tokio::test]
    async fn debug_statsviz_surface_matches_upstream_paths() {
        let (state, _dir) = fixture_state();
        let app = router(state);

        let redirect = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/statsviz")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(redirect.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            redirect
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok()),
            Some("/debug/statsviz/")
        );

        let index = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/statsviz/")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(
            index
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(index.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("<title>Statsviz</title>"), "{body}");
        assert!(body.contains("/debug/statsviz/ws"), "{body}");

        let ws = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/statsviz/ws")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ws.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn debug_gc_endpoint_matches_tsweb_text_shape() {
        let (state, _dir) = fixture_state();

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/gc")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"running GC...\nDone.\n");
    }

    #[tokio::test]
    async fn swagger_ui_matches_headscale_go_public_path() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/swagger")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("https://unpkg.com/swagger-ui-dist@3/swagger-ui.css"));
        assert!(body.contains("url: \"/swagger/v1/openapiv2.json\""));
        assert!(body.contains("<link rel=\"icon\" href=\"/favicon.ico\">"));
    }

    #[tokio::test]
    async fn swagger_api_v1_serves_upstream_openapi_document() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/swagger/v1/openapiv2.json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["swagger"], "2.0");
        assert_eq!(parsed["info"]["title"], "headscale/v1/headscale.proto");
        assert!(parsed["paths"].get("/api/v1/node").is_some());
        assert!(parsed["paths"].get("/api/v1/preauthkey").is_some());
        assert!(parsed["definitions"].get("v1Node").is_some());
    }

    #[tokio::test]
    async fn favicon_serves_headscale_go_png_asset() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/favicon.ico")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("image/png")
        );
        let body = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        assert_eq!(&body[..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(body.len(), FAVICON_PNG.len());
    }

    #[tokio::test]
    async fn metrics_endpoint_serves_prometheus_text_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some(PROMETHEUS_TEXT_CONTENT_TYPE)
        );
        let body = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(body.contains("# HELP headscale_nodes_registered "));
        assert!(body.contains("# TYPE headscale_nodes_registered gauge"));
        assert!(body.contains("# TYPE headscale_mapresponse_endpoint_updates_total counter"));
        assert!(body.contains("# TYPE headscale_mapresponse_ended_total counter"));
        assert!(body.contains("# TYPE headscale_mapresponse_generated_total counter"));
        assert!(body.contains("# TYPE headscale_mapresponse_sent_total counter"));
        assert!(body.contains("# TYPE headscale_http_requests_total counter"));
        assert!(body.contains("# TYPE headscale_http_duration_seconds histogram"));
        assert!(body.contains("# TYPE headscale_nodestore_operations_total counter"));
        assert!(body.contains("# TYPE headscale_nodestore_operation_duration_seconds histogram"));
        assert!(body.contains("# TYPE headscale_nodestore_batch_size histogram"));
        assert!(body.contains("# TYPE headscale_nodestore_batch_duration_seconds histogram"));
        assert!(
            body.contains("# TYPE headscale_nodestore_snapshot_build_duration_seconds histogram")
        );
        assert!(body.contains("# TYPE headscale_nodestore_nodes_total gauge"));
        assert!(
            body.contains(
                "# TYPE headscale_nodestore_peers_calculation_duration_seconds histogram"
            )
        );
        assert!(body.contains("# TYPE headscale_nodestore_queue_depth gauge"));
        assert!(body.contains("headscale_nodes_registered 0\n"));
        assert!(body.contains("headscale_nodes_online 0\n"));
        assert!(body.contains("headscale_policy_loaded 0\n"));
        assert!(body.ends_with('\n'));
    }

    #[tokio::test]
    async fn metrics_endpoint_reports_http_request_metrics() {
        let (state, _dir) = fixture_state();
        let app = router(state);

        let health_resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health_resp.status(), StatusCode::OK);

        let apple_resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/apple/macos-app-store")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(apple_resp.status(), StatusCode::OK);

        let verify_resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/verify")
                    .body(axum::body::Body::from(format!(
                        "{{\"NodePublic\":\"nodekey:{}\"}}",
                        "33".repeat(32)
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_resp.status(), StatusCode::OK);

        let register_resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/register/3oYCOZYA2zZmGB4PQ7aHBaMi")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(register_resp.status(), StatusCode::OK);

        let metrics_resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(metrics_resp.status(), StatusCode::OK);

        let body = to_bytes(metrics_resp.into_body(), 32 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(
            body.contains(
                "headscale_http_requests_total{code=\"200\",method=\"GET\",path=\"/health\"} 1\n"
            ),
            "{body}",
        );
        assert!(
            body.contains(
                "headscale_http_requests_total{code=\"200\",method=\"GET\",path=\"/apple/{platform}\"} 1\n"
            ),
            "{body}",
        );
        assert!(
            body.contains(
                "headscale_http_requests_total{code=\"200\",method=\"POST\",path=\"/verify\"} 1\n"
            ),
            "{body}",
        );
        assert!(
            body.contains(
                "headscale_http_requests_total{code=\"200\",method=\"GET\",path=\"/register/{registration_id}\"} 1\n"
            ),
            "{body}",
        );
        assert!(
            body.contains(
                "headscale_http_duration_seconds_bucket{path=\"/health\",le=\"+Inf\"} 1\n"
            ),
            "{body}",
        );
        assert!(
            body.contains("headscale_http_duration_seconds_count{path=\"/health\"} 1\n"),
            "{body}",
        );
        assert!(!body.contains("path=\"/metrics\""), "{body}");
    }

    #[tokio::test]
    async fn metrics_endpoint_reports_nodestore_metrics() {
        let (state, _dir) = fixture_state();

        let rec = record("metrics-nodestore", 43, &[], &[]);
        state.machines.upsert(rec.node_key_hex.clone(), rec.clone());
        assert!(state.machines.get(&rec.node_key_hex).is_some());
        assert!(state.machines.set_expiry(
            &rec.node_key_hex,
            Some(Utc::now() + chrono::Duration::hours(1))
        ));
        assert!(state.machines.delete(&rec.node_key_hex));

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        for sample in [
            "headscale_nodestore_operations_total{operation=\"delete\"} 1\n",
            "headscale_nodestore_operations_total{operation=\"get_by_key\"} 1\n",
            "headscale_nodestore_operations_total{operation=\"put\"} 1\n",
            "headscale_nodestore_operations_total{operation=\"update\"} 1\n",
            "headscale_nodestore_operation_duration_seconds_count{operation=\"put\"} 1\n",
            "headscale_nodestore_batch_size_bucket{le=\"+Inf\"} 3\n",
            "headscale_nodestore_batch_size_count 3\n",
            "headscale_nodestore_batch_duration_seconds_count 3\n",
            "headscale_nodestore_snapshot_build_duration_seconds_count 3\n",
            "headscale_nodestore_nodes_total 0\n",
            "headscale_nodestore_queue_depth 0\n",
            "headscale_nodestore_peers_calculation_duration_seconds_count 0\n",
        ] {
            assert!(body.contains(sample), "missing sample {sample:?}\n{body}");
        }
    }

    #[tokio::test]
    async fn metrics_endpoint_reports_high_cardinality_mapresponse_gauge_when_enabled() {
        let _metrics_guard = HighCardinalityMetricsGuard::enable();

        let (state, _dir) = fixture_state();
        let node_id = stable_id_from_key("metrics-high-cardinality");
        state
            .machines
            .record_mapresponse_sent_for_node("ok", "keepalive", node_id);

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        assert!(body.contains("# TYPE headscale_mapresponse_last_sent_seconds gauge"));
        assert!(
            body.contains(&format!(
                "headscale_mapresponse_last_sent_seconds{{type=\"keepalive\",id=\"{node_id}\"}} "
            )),
            "{body}",
        );
        assert!(
            body.contains("headscale_mapresponse_sent_total{status=\"ok\",type=\"keepalive\"} 1\n"),
            "{body}",
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_reports_runtime_wire_state() {
        let (mut state, _dir) = fixture_state();
        state.derp_map = crate::tailscale_wire::DerpMapStore::shared(derp_fixture());

        let mut alice = record(
            "metrics-alice",
            41,
            &["10.41.0.0/24", "0.0.0.0/0"],
            &["10.41.0.0/24", "0.0.0.0/0"],
        );
        alice.user = "alice".to_string();
        state.machines.upsert(alice.node_key_hex.clone(), alice);

        let mut bob = record("metrics-bob", 42, &[], &[]);
        bob.user = "bob".to_string();
        bob.ephemeral = true;
        bob.expiry = Some(Utc::now() - chrono::Duration::seconds(1));
        state.machines.upsert(bob.node_key_hex.clone(), bob);

        let raw_policy = r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#;
        let doc = crate::policy::parse_hujson_policy(raw_policy).unwrap();
        state.policy.set(doc, raw_policy.to_string());

        let _guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key("metrics-alice"),
        );

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();

        for sample in [
            "headscale_nodes_registered 2\n",
            "headscale_nodes_online 1\n",
            "headscale_nodes_expired 1\n",
            "headscale_nodes_ephemeral 1\n",
            "headscale_users 2\n",
            "headscale_derp_regions 1\n",
            "headscale_policy_loaded 1\n",
            "headscale_map_stream_connections 1\n",
            "headscale_map_stream_connected_nodes 1\n",
            "headscale_routes_primary 1\n",
        ] {
            assert!(body.contains(sample), "missing sample {sample:?}\n{body}");
        }
    }

    #[tokio::test]
    async fn debug_overview_text_matches_headscale_go_empty_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/overview")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            &body[..],
            b"=== Headscale State Overview ===\n\nNodes: 0 total\n  - Online: 0\n  - Expired: 0\n  - Ephemeral: 0\n\nUsers: 0 total\n\nPolicy:\n  - Mode: memory\n\nDERP: not configured\n\nPrimary Routes: 0 active\n\nRegistration Cache: active\n\n"
        );
    }

    #[tokio::test]
    async fn debug_overview_json_reports_runtime_state() {
        let (mut state, _dir) = fixture_state();
        state.derp_map = crate::tailscale_wire::DerpMapStore::shared(derp_fixture());

        let mut alice = record("overview-alice", 21, &["10.0.0.0/24"], &["10.0.0.0/24"]);
        alice.hostname = "alice-node".to_string();
        alice.user = "alice".to_string();
        state.machines.upsert(alice.node_key_hex.clone(), alice);

        let mut bob = record("overview-bob", 22, &[], &[]);
        bob.hostname = "bob-node".to_string();
        bob.user = "bob".to_string();
        bob.ephemeral = true;
        bob.expiry = Some(Utc::now() - chrono::Duration::seconds(1));
        state.machines.upsert(bob.node_key_hex.clone(), bob);

        let _guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key("overview-alice"),
        );

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/overview")
                    .header(header::ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(parsed["nodes"]["total"], 2);
        assert_eq!(parsed["nodes"]["online"], 1);
        assert_eq!(parsed["nodes"]["expired"], 1);
        assert_eq!(parsed["nodes"]["ephemeral"], 1);
        assert_eq!(parsed["users"]["alice"], 1);
        assert_eq!(parsed["users"]["bob"], 1);
        assert_eq!(parsed["total_users"], 2);
        assert_eq!(parsed["policy"]["mode"], "memory");
        assert!(parsed["policy"].get("path").is_none());
        assert_eq!(parsed["derp"]["configured"], true);
        assert_eq!(parsed["derp"]["regions"], 1);
        assert_eq!(parsed["primary_routes"], 1);
    }

    #[tokio::test]
    async fn debug_config_returns_headscale_go_top_level_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/config")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

        for key in [
            "ServerURL",
            "Addr",
            "MetricsAddr",
            "GRPCAddr",
            "GRPCAllowInsecure",
            "TrustedProxies",
            "EphemeralNodeInactivityTimeout",
            "Node",
            "PrefixV4",
            "PrefixV6",
            "IPAllocation",
            "NoisePrivateKeyPath",
            "BaseDomain",
            "Log",
            "DisableUpdateCheck",
            "Database",
            "DERP",
            "TLS",
            "DNSConfig",
            "TailcfgDNSConfig",
            "UnixSocket",
            "UnixSocketPermission",
            "OIDC",
            "LogTail",
            "Taildrop",
            "AutoUpdate",
            "CLI",
            "Policy",
            "Tuning",
        ] {
            assert!(parsed.get(key).is_some(), "missing config field {key}");
        }
        assert_eq!(parsed["GRPCAddr"], ":50443");
        assert_eq!(parsed["GRPCAllowInsecure"], false);
        assert_eq!(parsed["TrustedProxies"], serde_json::json!([]));
        assert_eq!(parsed["EphemeralNodeInactivityTimeout"], 120_000_000_000i64);
        assert_eq!(parsed["Node"]["Expiry"], 0);
        assert_eq!(
            parsed["Node"]["Ephemeral"]["InactivityTimeout"],
            120_000_000_000i64
        );
        assert_eq!(
            parsed["Node"]["Routes"]["HA"]["ProbeInterval"],
            10_000_000_000i64
        );
        assert_eq!(
            parsed["Node"]["Routes"]["HA"]["ProbeTimeout"],
            5_000_000_000i64
        );
        assert!(parsed["PrefixV4"].is_null());
        assert!(parsed["PrefixV6"].is_null());
        assert_eq!(parsed["IPAllocation"], "sequential");
        assert_eq!(parsed["DNSConfig"]["MagicDNS"], false);
        assert_eq!(parsed["DNSConfig"]["OverrideLocalDNS"], true);
        assert_eq!(parsed["Policy"]["Mode"], "file");
        assert_eq!(parsed["Tuning"]["NodeStoreBatchSize"], 100);
        assert_eq!(parsed["Tuning"]["RegisterCacheMaxEntries"], 0);
        assert_eq!(parsed["UnixSocketPermission"], 0o770);
    }

    #[tokio::test]
    async fn debug_config_reflects_runtime_server_url_dns_and_derp() {
        let (mut state, _dir) = fixture_state();
        state.public_control_url = Some("https://headscale.example".to_string());
        state.derp_map = crate::tailscale_wire::DerpMapStore::shared(derp_fixture());
        state.dns.set_spec(crate::dns::DnsConfigSpec {
            magic_dns: true,
            base_domain: "tailnet.example".to_string(),
            nameservers: vec!["1.1.1.1".to_string()],
            restricted_nameservers: HashMap::from([(
                "corp.example".to_string(),
                vec!["10.0.0.53".to_string()],
            )]),
            search_domains: vec!["corp.example".to_string()],
            ..crate::dns::DnsConfigSpec::default()
        });

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/config")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(parsed["ServerURL"], "https://headscale.example");
        assert_eq!(parsed["BaseDomain"], "tailnet.example");
        assert_eq!(parsed["DNSConfig"]["MagicDNS"], true);
        assert_eq!(parsed["DNSConfig"]["BaseDomain"], "tailnet.example");
        assert_eq!(
            parsed["DNSConfig"]["Nameservers"]["Global"],
            serde_json::json!(["1.1.1.1"])
        );
        assert_eq!(
            parsed["DNSConfig"]["Nameservers"]["Split"]["corp.example"],
            serde_json::json!(["10.0.0.53"])
        );
        assert_eq!(
            parsed["TailcfgDNSConfig"]["Domains"],
            serde_json::json!(["tailnet.example", "corp.example"])
        );
        assert_eq!(
            parsed["DERP"]["DERPMap"]["Regions"]["1"]["RegionName"],
            "Test region"
        );
    }

    #[tokio::test]
    async fn debug_config_uses_runtime_config_snapshot_for_static_fields() {
        let (mut state, _dir) = fixture_state();
        let mut snapshot = crate::tailscale_wire::RuntimeConfigSnapshot {
            server_url: "https://snapshot.example".to_string(),
            addr: "0.0.0.0:443".to_string(),
            metrics_addr: "127.0.0.1:9090".to_string(),
            grpc_addr: "127.0.0.1:50443".to_string(),
            grpc_allow_insecure: true,
            trusted_proxies: vec!["127.0.0.1/32".to_string()],
            prefix_v4: Some("100.100.0.0/16".to_string()),
            ip_allocation: "random".to_string(),
            disable_update_check: true,
            acme_url: "https://acme.example/directory".to_string(),
            acme_email: "ops@example.com".to_string(),
            unix_socket: "/run/headscale/headscale.sock".to_string(),
            unix_socket_permission: 0o760,
            ..crate::tailscale_wire::RuntimeConfigSnapshot::default()
        };
        snapshot.tls.cert_path = "/etc/headscale/tls.crt".to_string();
        snapshot.tls.key_path = "/etc/headscale/tls.key".to_string();
        snapshot.tls.lets_encrypt.hostname = "headscale.example".to_string();
        snapshot.tls.lets_encrypt.listen = ":http".to_string();
        snapshot.tls.lets_encrypt.cache_dir = "/var/lib/headscale/cache".to_string();
        snapshot.tls.lets_encrypt.challenge_type = "TLS-ALPN-01".to_string();
        state.runtime_config = Arc::new(snapshot);

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/config")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 32 * 1024).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(parsed["ServerURL"], "https://snapshot.example");
        assert_eq!(parsed["Addr"], "0.0.0.0:443");
        assert_eq!(parsed["MetricsAddr"], "127.0.0.1:9090");
        assert_eq!(parsed["GRPCAddr"], "127.0.0.1:50443");
        assert_eq!(parsed["GRPCAllowInsecure"], true);
        assert_eq!(
            parsed["TrustedProxies"],
            serde_json::json!(["127.0.0.1/32"])
        );
        assert_eq!(parsed["DisableUpdateCheck"], true);
        assert_eq!(parsed["PrefixV4"], "100.100.0.0/16");
        assert_eq!(parsed["IPAllocation"], "random");
        assert_eq!(parsed["Node"]["Expiry"], 0);
        assert_eq!(parsed["TLS"]["CertPath"], "/etc/headscale/tls.crt");
        assert_eq!(parsed["TLS"]["KeyPath"], "/etc/headscale/tls.key");
        assert_eq!(
            parsed["TLS"]["LetsEncrypt"]["Hostname"],
            "headscale.example"
        );
        assert_eq!(parsed["TLS"]["LetsEncrypt"]["Listen"], ":http");
        assert_eq!(
            parsed["TLS"]["LetsEncrypt"]["CacheDir"],
            "/var/lib/headscale/cache"
        );
        assert_eq!(parsed["TLS"]["LetsEncrypt"]["ChallengeType"], "TLS-ALPN-01");
        assert_eq!(parsed["ACMEURL"], "https://acme.example/directory");
        assert_eq!(parsed["ACMEEmail"], "ops@example.com");
        assert_eq!(parsed["UnixSocket"], "/run/headscale/headscale.sock");
        assert_eq!(parsed["UnixSocketPermission"], 0o760);
    }

    #[tokio::test]
    async fn debug_routes_text_matches_headscale_go_empty_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/routes")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            &body[..],
            b"Available routes:\n\n\nCurrent primary routes:\n"
        );
    }

    #[tokio::test]
    async fn debug_routes_json_matches_headscale_go_route_state_shape() {
        let (state, _dir) = fixture_state();
        let node_a = "debug-node-a";
        let node_b = "debug-node-b";
        state.machines.upsert(
            node_a.to_string(),
            record(
                node_a,
                1,
                &["10.0.0.0/24", "0.0.0.0/0"],
                &["10.0.0.0/24", "0.0.0.0/0"],
            ),
        );
        state.machines.upsert(
            node_b.to_string(),
            record(node_b, 2, &["10.0.0.0/24"], &["10.0.0.0/24"]),
        );

        let id_a = stable_id_from_key(node_a);
        let id_b = stable_id_from_key(node_b);
        let _guard_a = MachineRegistry::track_stream_connection(state.machines.clone(), id_a);
        let _guard_b = MachineRegistry::track_stream_connection(state.machines.clone(), id_b);
        let primary = id_a.min(id_b);
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/routes")
                    .header(header::ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let available = parsed["available_routes"].as_object().unwrap();
        assert_eq!(
            available.get(&id_a.to_string()).unwrap(),
            &serde_json::json!(["10.0.0.0/24"])
        );
        assert_eq!(
            available.get(&id_b.to_string()).unwrap(),
            &serde_json::json!(["10.0.0.0/24"])
        );
        assert_eq!(parsed["primary_routes"]["10.0.0.0/24"], primary);
        assert!(
            parsed["primary_routes"].get("0.0.0.0/0").is_none(),
            "exit routes are excluded from primary route debug state"
        );
    }

    #[tokio::test]
    async fn debug_derp_text_matches_headscale_go_unconfigured_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/derp")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], b"DERP Map: not configured\n");
    }

    #[tokio::test]
    async fn debug_derp_text_matches_headscale_go_configured_shape() {
        let (mut state, _dir) = fixture_state();
        state.derp_map = crate::tailscale_wire::DerpMapStore::shared(derp_fixture());
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/derp")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(
            body,
            "=== DERP Map Configuration ===\n\nTotal Regions: 1\n\nRegion 1: Test region\n  - Nodes: 1\n    - derp-1 (derp1.example.com:443)\n      STUN: 3478\n\n"
        );
    }

    #[tokio::test]
    async fn debug_derp_json_matches_headscale_go_shape() {
        let (mut state, _dir) = fixture_state();
        state.derp_map = crate::tailscale_wire::DerpMapStore::shared(derp_fixture());
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/derp")
                    .header(header::ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["configured"], true);
        assert_eq!(parsed["total_regions"], 1);
        assert_eq!(parsed["regions"]["1"]["region_id"], 1);
        assert_eq!(parsed["regions"]["1"]["region_name"], "Test region");
        assert_eq!(parsed["regions"]["1"]["nodes"][0]["name"], "derp-1");
        assert_eq!(
            parsed["regions"]["1"]["nodes"][0]["hostname"],
            "derp1.example.com"
        );
        assert_eq!(parsed["regions"]["1"]["nodes"][0]["derp_port"], 443);
        assert_eq!(parsed["regions"]["1"]["nodes"][0]["stun_port"], 3478);
    }

    #[tokio::test]
    async fn debug_registration_cache_matches_headscale_go_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/registration-cache")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed["type"], "zcache");
        assert_eq!(parsed["expiration"], "15m0s");
        assert_eq!(parsed["cleanup"], "20m0s");
        assert_eq!(parsed["status"], "active");
    }

    #[tokio::test]
    async fn debug_nodestore_text_matches_headscale_go_empty_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/nodestore")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            &body[..],
            b"=== NodeStore Debug Information ===\n\nTotal Nodes: 0\nUsers with Nodes: 0\n\nNodes by Internal User ID:\n\nPeer Relationships:\n\nNodeKey Index: 0 entries\n\n"
        );
    }

    #[tokio::test]
    async fn debug_nodestore_json_reports_runtime_nodes() {
        let (state, _dir) = fixture_state();
        let node_key = "debug-nodestore-node";
        let mut rec = record(node_key, 41, &["10.41.0.0/24"], &["10.41.0.0/24"]);
        rec.user = "charlie".to_string();
        rec.hostname = "charlie-node".to_string();
        rec.forced_tags = vec!["tag:debug".to_string()];
        state.machines.upsert(node_key.to_string(), rec);
        let _guard = MachineRegistry::track_stream_connection(
            state.machines.clone(),
            stable_id_from_key(node_key),
        );

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/nodestore")
                    .header(header::ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let node_id = stable_id_from_key(node_key).to_string();
        let node = parsed.get(&node_id).unwrap();
        assert_eq!(node["id"], stable_id_from_key(node_key));
        assert_eq!(node["node_key"], node_key);
        assert_eq!(node["user"], "charlie");
        assert_eq!(node["hostname"], "charlie-node");
        assert_eq!(node["ipv4"], "100.64.0.41");
        assert_eq!(node["online"], true);
        assert_eq!(node["forced_tags"], serde_json::json!(["tag:debug"]));
        assert_eq!(node["approved_routes"], serde_json::json!(["10.41.0.0/24"]));
    }

    #[tokio::test]
    async fn debug_filter_returns_runtime_allow_all_when_policy_unloaded() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/filter")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 1);
        assert_eq!(
            parsed[0]["SrcIPs"],
            serde_json::json!(["0.0.0.0/0", "::/0"])
        );
        assert_eq!(parsed[0]["DstPorts"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn debug_filter_returns_loaded_policy_filter_rules() {
        let (state, _dir) = fixture_state();
        let raw_policy = r#"{
          "acls": [
            {
              "action": "accept",
              "proto": "tcp",
              "src": ["100.64.0.1/32"],
              "dst": ["100.64.0.2/32:22"]
            }
          ]
        }"#;
        let doc = crate::policy::parse_hujson_policy(raw_policy).unwrap();
        state.policy.set(doc, raw_policy.to_string());

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/filter")
                    .header(header::ACCEPT, "text/plain")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed.as_array().unwrap().len(), 1);
        assert_eq!(parsed[0]["SrcIPs"], serde_json::json!(["100.64.0.1/32"]));
        assert_eq!(parsed[0]["DstPorts"][0]["IP"], "100.64.0.2/32");
        assert_eq!(parsed[0]["DstPorts"][0]["Ports"]["First"], 22);
        assert_eq!(parsed[0]["DstPorts"][0]["Ports"]["Last"], 22);
        assert_eq!(parsed[0]["IPProto"], serde_json::json!([6]));
    }

    #[tokio::test]
    async fn debug_policy_returns_loaded_raw_policy_as_text_by_default() {
        let (state, _dir) = fixture_state();
        let raw_policy = r#"{
          // keep comments and whitespace byte-for-byte
          "acls": [
            {"action": "accept", "src": ["*"], "dst": ["*:*"]},
          ],
        }"#;
        let doc = crate::policy::parse_hujson_policy(raw_policy).unwrap();
        state.policy.set(doc, raw_policy.to_string());

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/policy")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], raw_policy.as_bytes());
    }

    #[tokio::test]
    async fn debug_policy_honours_application_json_accept_header() {
        let (state, _dir) = fixture_state();
        let raw_policy = r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#;
        let doc = crate::policy::parse_hujson_policy(raw_policy).unwrap();
        state.policy.set(doc, raw_policy.to_string());

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/policy")
                    .header(header::ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], raw_policy.as_bytes());
    }

    #[tokio::test]
    async fn debug_mapresponses_matches_headscale_go_disabled_state() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/mapresponses")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], MAPRESPONSES_DEBUG_DISABLED_BODY.as_bytes());
    }

    #[tokio::test]
    async fn debug_batcher_text_matches_headscale_go_empty_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/batcher")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            &body[..],
            b"=== Batcher Connected Nodes ===\n\n\nSummary: 0 connected, 0 total\n"
        );
    }

    #[tokio::test]
    async fn debug_batcher_json_tracks_active_stream_connection() {
        let (state, _dir) = fixture_state();
        let node_key = "debug-batcher-node";
        state
            .machines
            .upsert(node_key.to_string(), record(node_key, 31, &[], &[]));

        let app = router(state.clone());
        let machine_app = machine_router(state.clone());
        let mut stream_req = axum::http::Request::builder()
            .method("POST")
            .uri(format!("/machine/nodekey:{node_key}/map"))
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "Stream": true,
                    "Version": 113
                }))
                .unwrap(),
            ))
            .unwrap();
        stream_req
            .extensions_mut()
            .insert(NoisePeerMachineKey(format!("mkey-{node_key}")));
        let stream_resp = machine_app.oneshot(stream_req).await.unwrap();
        assert_eq!(stream_resp.status(), StatusCode::OK);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/batcher")
                    .header(header::ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let node_id = stable_id_from_key(node_key).to_string();
        assert_eq!(parsed["total_nodes"], 1);
        let node = parsed["connected_nodes"].get(&node_id).unwrap();
        assert_eq!(node["connected"], true);
        assert_eq!(node["active_connections"], 1);

        drop(stream_resp);

        let resp = router(state.clone())
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/batcher")
                    .header(header::ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let node = parsed["connected_nodes"].get(&node_id).unwrap();
        assert_eq!(parsed["total_nodes"], 1);
        assert_eq!(node["connected"], false);
        assert_eq!(node["active_connections"], 0);
    }

    #[tokio::test]
    async fn debug_policy_manager_text_matches_headscale_go_empty_shape() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/policy-manager")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/plain")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            &body[..],
            b"PolicyManager (v0):\n\n\n\nAutoApprover (0):\n\n\nTagOwner (0):\n\n\n\n\nMatchers:\nan internal structure used to filter nodes and routes\n\n\nNodes:\n"
        );
    }

    #[tokio::test]
    async fn debug_policy_manager_json_wraps_loaded_policy_state() {
        let (state, _dir) = fixture_state();
        let raw_policy = r#"{
          "tagOwners": {
            "tag:server": ["group:admins"]
          },
          "groups": {
            "group:admins": ["alice@"]
          },
          "autoApprovers": {
            "routes": {
              "10.0.0.0/24": ["group:admins"]
            }
          },
          "acls": [
            {"action": "accept", "proto": "tcp", "src": ["group:admins"], "dst": ["tag:server:22"]}
          ]
        }"#;
        let doc = crate::policy::parse_hujson_policy(raw_policy).unwrap();
        state.policy.set_at(doc, raw_policy.to_string(), 42);

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/policy-manager")
                    .header(header::ACCEPT, "application/json")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 8192).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let content = parsed["content"].as_str().unwrap();
        assert!(content.starts_with("PolicyManager (v42):"));
        assert!(content.contains("Policy:\n"));
        assert!(content.contains("AutoApprover (1):"));
        assert!(content.contains("\t10.0.0.0/24:\n"));
        assert!(content.contains("TagOwner (1):"));
        assert!(content.contains("\ttag:server:\n"));
        assert!(content.contains("Compiled filter:\n"));
        assert!(content.contains("Matchers:\n"));
    }

    #[tokio::test]
    async fn debug_ssh_returns_empty_json_object_without_nodes() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/ssh")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(parsed, serde_json::json!({}));
    }

    #[tokio::test]
    async fn debug_ssh_returns_policies_per_node() {
        let (state, _dir) = fixture_state();
        let server = "debug-ssh-server";
        let admin = "debug-ssh-admin";

        let mut server_rec = record(server, 11, &[], &[]);
        server_rec.hostname = "server".to_string();
        server_rec.user = "alice".to_string();
        server_rec.forced_tags = vec!["tag:server".to_string()];
        state.machines.upsert(server.to_string(), server_rec);

        let mut admin_rec = record(admin, 12, &[], &[]);
        admin_rec.hostname = "admin".to_string();
        admin_rec.user = "bob".to_string();
        state.machines.upsert(admin.to_string(), admin_rec);

        let raw_policy = r#"{
            "groups": {"group:admins": ["bob@"]},
            "tagOwners": {"tag:server": ["alice@"]},
            "acls": [],
            "ssh": [{
                "action": "check",
                "checkPeriod": "24h",
                "src": ["group:admins"],
                "dst": ["tag:server"],
                "users": ["autogroup:nonroot", "root"]
            }]
        }"#;
        let doc = crate::policy::parse_hujson_policy(raw_policy).unwrap();
        state.policy.set(doc, raw_policy.to_string());

        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/debug/ssh")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/json")
        );
        let body = to_bytes(resp.into_body(), 8192).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let server_key = format!(
            "id:{} hostname:server givenname:server",
            stable_id_from_key(server)
        );
        let admin_key = format!(
            "id:{} hostname:admin givenname:admin",
            stable_id_from_key(admin)
        );

        let server_policy = parsed.get(&server_key).unwrap();
        let admin_policy = parsed.get(&admin_key).unwrap();

        assert_eq!(server_policy["rules"].as_array().unwrap().len(), 1);
        assert_eq!(
            server_policy["rules"][0]["principals"][0]["nodeIP"],
            "100.64.0.12"
        );
        assert_eq!(server_policy["rules"][0]["sshUsers"]["*"], "=");
        assert_eq!(
            server_policy["rules"][0]["action"]["sessionDuration"],
            24_i64 * 60 * 60 * 1_000_000_000
        );
        assert!(admin_policy["rules"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unmatched_public_path_returns_headscale_go_blank_page() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/some/unknown/path")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(&body[..], blank_html().as_bytes());
    }

    #[tokio::test]
    async fn windows_endpoint_uses_configured_login_server() {
        let (mut state, _dir) = fixture_state();
        state.public_control_url = Some("https://configured.example/".into());
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/windows")
                    .header(header::HOST, "ignored.example")
                    .header("x-forwarded-proto", "https")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("https://tailscale.com/download/windows"));
        assert!(body.contains("tailscale up --login-server https://configured.example"));
        assert!(!body.contains("ignored.example"));
    }

    #[tokio::test]
    async fn apple_endpoint_links_all_headscale_go_profile_paths() {
        let (mut state, _dir) = fixture_state();
        state.public_control_url = Some("https://configured.example".into());
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/apple")
                    .header(header::HOST, "ignored.example")
                    .header("x-forwarded-proto", "https")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("text/html; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("https://apps.apple.com/app/tailscale/id1470499037"));
        assert!(body.contains("/apple/ios"));
        assert!(body.contains("/apple/macos-app-store"));
        assert!(body.contains("/apple/macos-standalone"));
        assert!(body.contains("curl https://configured.example/apple/macos-app-store"));
        assert!(!body.contains("ignored.example"));
    }

    #[tokio::test]
    async fn apple_mobileconfig_ios_uses_configured_control_url() {
        let (mut state, _dir) = fixture_state();
        state.public_control_url = Some("https://configured.example/".into());
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/apple/ios")
                    .header(header::HOST, "ignored.example")
                    .header("x-forwarded-proto", "https")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok()),
            Some("application/x-apple-aspen-config; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("<string>io.tailscale.ipn.ios</string>"));
        assert!(body.contains("<key>ControlURL</key>"));
        assert!(body.contains("<string>https://configured.example</string>"));
        assert!(body.contains("<string>Headscale</string>"));
        assert!(!body.contains("ignored.example"));
    }

    #[tokio::test]
    async fn apple_mobileconfig_falls_back_to_request_host_when_unconfigured() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/apple/macos-app-store")
                    .header(header::HOST, "headscale.example")
                    .header("x-forwarded-proto", "https")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 16 * 1024).await.unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("<string>io.tailscale.ipn.macos</string>"));
        assert!(body.contains("<string>https://headscale.example</string>"));
    }

    #[tokio::test]
    async fn apple_mobileconfig_bad_platform_matches_headscale_go_error() {
        let (state, _dir) = fixture_state();
        let resp = router(state)
            .oneshot(
                axum::http::Request::builder()
                    .uri("/apple/linux")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(
            &body[..],
            b"platform must be ios, macos-app-store or macos-standalone\n"
        );
    }
}
