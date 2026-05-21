//! Basic unauthenticated control-plane endpoints shared with headscale-go.
//!
//! These live next to `/key` in the wire router because upstream serves
//! them from the same public control listener, before API bearer auth.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

use crate::policy::{PeerMapNode, PolicyAction, SshPolicyNode};

use super::{
    DerpMap, MachineRecord, WireState,
    wire::{SshPolicy, stable_id_from_key},
};

const ROBOTS_BODY: &str = "User-agent: *\nDisallow: /";
const MAPRESPONSES_DEBUG_DISABLED_BODY: &str = "HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH not set";
const SWAGGER_JSON: &str = include_str!("assets/headscale.swagger.json");
const FAVICON_PNG: &[u8] = include_bytes!("assets/favicon.png");

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

pub async fn handle_favicon() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "image/png")],
        FAVICON_PNG,
    )
        .into_response()
}

pub async fn handle_fallback(uri: Uri) -> Response {
    if uri.path() == "/k" || uri.path().starts_with(super::knock::KNOCK_PATH_PREFIX) {
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
    if wants_json(&headers) {
        let info = debug_derp_info(&state.derp_map);
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
            debug_derp_string(&state.derp_map),
        )
            .into_response()
    }
}

pub async fn handle_debug_registration_cache() -> Response {
    match serde_json::to_string_pretty(&debug_registration_cache_info()) {
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

fn debug_nodestore_json(state: &WireState) -> BTreeMap<String, DebugNodeStoreNode> {
    let snapshot = state.machines.snapshot();
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
                    ipv4: rec.ipv4.to_string(),
                    online: !rec.is_expired_at(now),
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
            rec.ipv4
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
            addr: rec.ipv4.to_string(),
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
    let now = chrono::Utc::now();
    let mut nodes = DebugOverviewNodes {
        total: snapshot.len(),
        ..DebugOverviewNodes::default()
    };
    let mut users = BTreeMap::new();

    for rec in snapshot.values() {
        let expired = rec.is_expired_at(now);
        if expired {
            nodes.expired += 1;
        } else {
            // The in-memory wire registry does not yet track
            // headscale-go's separate online/offline bit. A record
            // that is present and not expired is the closest current
            // equivalent.
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
    let derp = debug_derp_info(&state.derp_map);
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

fn debug_registration_cache_info() -> DebugRegistrationCacheInfo {
    DebugRegistrationCacheInfo {
        cache_type: "zcache".to_string(),
        expiration: "15m0s".to_string(),
        cleanup: "20m0s".to_string(),
        status: "active".to_string(),
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
            addrs: vec![rec.ipv4.to_string()],
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
        .or_else(|| uri.authority().map(|a| a.as_str()))
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
        noise::ServerNoiseKey,
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

    fn fixture_state() -> (WireState, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let state = WireState {
            server_noise_key: server,
            preauth: Arc::new(MockRedeemer::new()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
            derp_map: Arc::new(crate::tailscale_wire::wire::DerpMap::default()),
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: None,
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
            omit_default_regions: true,
            regions: HashMap::from([(
                1,
                DerpRegion {
                    region_id: 1,
                    region_code: "test".to_string(),
                    region_name: "Test region".to_string(),
                    avoid: false,
                    nodes: vec![DerpRegionNode {
                        name: "derp-1".to_string(),
                        region_id: 1,
                        host_name: "derp1.example.com".to_string(),
                        ipv4: "198.51.100.10".to_string(),
                        ipv6: String::new(),
                        derp_port: 443,
                        stun_port: 3478,
                        stun_only: false,
                        insecure_for_tests: false,
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
        state.derp_map = Arc::new(derp_fixture());

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
        state.derp_map = Arc::new(derp_fixture());
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
        state.derp_map = Arc::new(derp_fixture());
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
          "version": 1,
          "rules": [
            {
              "action": "accept",
              "src": ["100.64.0.1/32"],
              "dst": ["100.64.0.2/32"],
              "ports": ["tcp/22"]
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
          "version": 1,
          "rules": [
            {"action": "accept", "src": ["*"], "dst": ["*"], "ports": ["*/*"]},
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
        let raw_policy = r#"{"version":1,"rules":[{"action":"accept","src":["*"],"dst":["*"],"ports":["*/*"]}]}"#;
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
        let stream_resp = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(format!("/machine/nodekey:{node_key}/map"))
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        serde_json::to_vec(&serde_json::json!({
                            "Stream": true,
                            "Version": 39
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
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
          "version": 1,
          "tagOwners": {
            "tag:server": ["group:admins"]
          },
          "groups": {
            "group:admins": ["alice"]
          },
          "autoApprovers": {
            "routes": {
              "10.0.0.0/24": ["group:admins"]
            }
          },
          "rules": [
            {"action": "accept", "src": ["group:admins"], "dst": ["tag:server"], "ports": ["tcp/22"]}
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
