use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    path::PathBuf,
};

mod production_filter;

use anyhow::{Context, Result, bail};
use headscale_api::{
    dns::{DnsConfigSpec, DnsRequester, DnsStore, MachineDnsRecord},
    policy::{
        NodeView, PeerMapNode, PolicyCheckNode, PolicyDoc, SshPolicyNode, ViaRouteCandidate,
        check_policy_semantics, compile_ssh_policy_with_base_url, parse_hujson_policy,
    },
    tailscale_wire::wire::{
        DerpMap, DnsConfig, HostInfo, MapNode, MapRequest, MapResponse, RegisterRequest,
        RegisterResponse, SshPolicy as WireSshPolicy,
    },
};
use ipnet::IpNet;
use production_filter::{ListOrder, ParityNode, ProductionFilters, normalized_json};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct Scenario {
    name: String,
    policy: Value,
    #[serde(default)]
    users: Vec<ScenarioUser>,
    #[serde(default)]
    nodes: Vec<ScenarioNode>,
    #[serde(default)]
    filter_node_checks: Vec<FilterNodeCheck>,
    #[serde(default)]
    peer_map_checks: Vec<PeerMapCheck>,
    #[serde(default)]
    route_checks: Vec<RouteCheck>,
    #[serde(default)]
    via_route_checks: Vec<ViaRouteCheck>,
    #[serde(default)]
    tag_checks: Vec<TagCheck>,
    #[serde(default)]
    node_attr_checks: Vec<NodeAttrCheck>,
    #[serde(default)]
    ssh_checks: Vec<SshCheck>,
    #[serde(default)]
    expect_policy_error: Option<String>,
    #[serde(default)]
    audit_test_verdicts: bool,
    #[serde(default)]
    wire: Option<WireScenario>,
}

#[derive(Debug, Deserialize)]
struct ScenarioUser {
    id: u64,
    name: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    provider_identifier: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ScenarioNode {
    id: u64,
    user_id: u64,
    ipv4: String,
    #[serde(default)]
    ipv6: String,
    #[serde(default)]
    hostname: String,
    #[serde(default)]
    os: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    routes: Vec<String>,
    #[serde(default)]
    approved_routes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FilterNodeCheck {
    name: String,
    node_id: u64,
}

#[derive(Debug, Deserialize)]
struct PeerMapCheck {
    name: String,
    node_id: u64,
}

#[derive(Debug, Deserialize)]
struct RouteCheck {
    name: String,
    node_id: u64,
    #[serde(default)]
    current_approved: Vec<String>,
    #[serde(default)]
    announced_routes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ViaRouteCheck {
    name: String,
    viewer_id: u64,
    peer_id: u64,
}

#[derive(Debug, Deserialize)]
struct TagCheck {
    name: String,
    node_id: u64,
    tag: String,
}

#[derive(Debug, Deserialize)]
struct NodeAttrCheck {
    name: String,
    node_id: u64,
}

#[derive(Debug, Deserialize)]
struct SshCheck {
    name: String,
    node_id: u64,
}

#[derive(Debug, Deserialize)]
struct WireScenario {
    #[serde(default)]
    dns_config: Option<Value>,
    #[serde(default)]
    runtime_dns_config: Option<Value>,
    #[serde(default)]
    runtime_dns_requester_checks: Vec<RuntimeDnsRequesterCheck>,
    #[serde(default)]
    derp_map: Option<Value>,
    #[serde(default)]
    register_request: Option<Value>,
    #[serde(default)]
    register_response: Option<Value>,
    #[serde(default)]
    map_request: Option<Value>,
    #[serde(default)]
    map_response: Option<Value>,
}

#[derive(Debug, Serialize)]
struct ScenarioOutput {
    engine: &'static str,
    name: String,
    filter: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    filter_for_nodes: Vec<FilterForNodeOut>,
    /// Production packet filter for every node, not only the checked ones.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    node_filters: Vec<NodeFilterOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    peer_maps: Vec<PeerMapOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    route_approvals: Vec<RouteApprovalOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    via_routes: Vec<ViaRouteOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tag_checks: Vec<TagCheckOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    node_attrs: Vec<NodeAttrOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ssh_policies: Vec<SshPolicyOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    policy_tests: Vec<PolicyTestOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ssh_tests: Vec<SshPolicyTestOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_tests_passed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ssh_tests_passed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wire: Option<WireOutput>,
}

#[derive(Debug, Serialize)]
struct FilterForNodeOut {
    name: String,
    rules: Value,
}

#[derive(Debug, Serialize)]
struct NodeFilterOut {
    node_id: u64,
    rules: Value,
}

#[derive(Debug, Serialize)]
struct PeerMapOut {
    name: String,
    peers: Vec<u64>,
}

#[derive(Debug, Serialize)]
struct RouteApprovalOut {
    name: String,
    approved_routes: Vec<String>,
    changed: bool,
}

#[derive(Debug, Serialize)]
struct ViaRouteOut {
    name: String,
    include: Vec<String>,
    exclude: Vec<String>,
    use_primary: Vec<String>,
}

#[derive(Debug, Serialize)]
struct TagCheckOut {
    name: String,
    allowed: bool,
}

#[derive(Debug, Serialize)]
struct NodeAttrOut {
    name: String,
    attrs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SshPolicyOut {
    name: String,
    rules: Vec<SshRuleOut>,
}

#[derive(Debug, Serialize)]
struct PolicyTestOut {
    src: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    proto: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    accept: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deny: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SshPolicyTestOut {
    src: String,
    dst: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    accept: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    deny: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    check: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SshRuleOut {
    principals: Vec<String>,
    ssh_users: BTreeMap<String, String>,
    action: SshActionOut,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    accept_env: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
struct SshActionOut {
    accept: bool,
    reject: bool,
    session_duration_nanos: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    hold_and_delegate: String,
    allow_agent_forwarding: bool,
    allow_local_port_forwarding: bool,
    allow_remote_port_forwarding: bool,
}

#[derive(Debug, Serialize, Default)]
struct WireOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_config: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_dns_config: Option<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    runtime_dns_requesters: Vec<RuntimeDnsRequesterOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derp_map: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    register_request: Option<RegisterRequestSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    register_response: Option<RegisterResponseSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    map_request: Option<MapRequestSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    map_response: Option<MapResponseSummary>,
}

#[derive(Debug, Deserialize)]
struct RuntimeDnsRequesterCheck {
    name: String,
    node_id: u64,
}

#[derive(Debug, Serialize)]
struct RuntimeDnsRequesterOut {
    name: String,
    dns_config: Value,
}

#[derive(Debug, Serialize)]
struct RegisterRequestSummary {
    #[serde(skip_serializing_if = "is_zero_u32")]
    version: u32,
    node_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    old_node_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    nl_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    auth_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostinfo: Option<HostInfoSummary>,
    #[serde(skip_serializing_if = "String::is_empty")]
    followup: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    tailnet: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    ephemeral: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    requested_expiry: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    node_key_signature: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    signature_type: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    timestamp: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_cert: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    signature: String,
}

#[derive(Debug, Serialize)]
struct RegisterResponseSummary {
    user: UserSummary,
    login: LoginSummary,
    node_key_expired: bool,
    auth_url: String,
    machine_authorized: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    node_key_signature: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

#[derive(Debug, Serialize)]
struct MapRequestSummary {
    #[serde(skip_serializing_if = "is_zero_u32")]
    version: u32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    keep_alive: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    compress: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    omit_peers: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    node_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    map_session_handle: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    map_session_seq: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    disco_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    hardware_attestation_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    hardware_attestation_key_signature: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    hardware_attestation_key_signature_timestamp: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    endpoint_types: Vec<i32>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    read_only: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    tka_head: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    debug_flags: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    connection_handle_for_test: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostinfo: Option<HostInfoSummary>,
}

#[derive(Debug, Serialize)]
struct UserSummary {
    id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    display_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_pic_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    created: String,
}

#[derive(Debug, Serialize)]
struct LoginSummary {
    id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    provider: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    login_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    display_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_pic_url: String,
}

#[derive(Debug, Serialize)]
struct MapResponseSummary {
    #[serde(skip_serializing_if = "String::is_empty")]
    map_session_handle: String,
    #[serde(skip_serializing_if = "is_zero_i64")]
    seq: i64,
    keep_alive: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    ping_request: Option<Value>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pop_browser_url: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    collect_services: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<MapNodeSummary>,
    peer_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    peers: Vec<MapNodeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    peers_changed: Vec<MapNodeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    peers_removed: Vec<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peers_changed_patch: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_seen_change: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    online_change: Option<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    user_profiles: Vec<UserProfileSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    packet_filter: Vec<FilterRuleOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packet_filters: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    health: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    display_messages: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_config: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derp_map: Option<Value>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ssh_policy: Vec<SshRuleOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    control_time: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tka_info: Option<Value>,
    #[serde(skip_serializing_if = "String::is_empty")]
    domain_data_plane_audit_log_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    debug: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    control_dial_plan: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_version: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_auto_update: Option<bool>,
}

#[derive(Debug, Serialize)]
struct MapNodeSummary {
    id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    stable_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    name: String,
    user: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    key: String,
    #[serde(skip_serializing_if = "is_zero_u64")]
    sharer: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    key_signature: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    machine: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    disco_key: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    primary_routes: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    legacy_derp_string: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostinfo: Option<HostInfoSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    created: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    key_expiry: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    last_seen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    online: Option<bool>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    machine_authorized: bool,
    #[serde(skip_serializing_if = "is_zero_u32")]
    cap: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cap_map: Option<Value>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    expired: bool,
    #[serde(skip_serializing_if = "is_zero_i32")]
    home_derp: i32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    unsigned_peer_api_only: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    computed_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    computed_name_with_host: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    data_plane_audit_log_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    self_node_v4_masq_addr_for_this_peer: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    self_node_v6_masq_addr_for_this_peer: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    is_wire_guard_only: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    is_jailed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_node_dns_resolvers: Option<Value>,
}

#[derive(Debug, Serialize)]
struct UserProfileSummary {
    id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    login_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    display_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_pic_url: String,
}

#[derive(Debug, Serialize)]
struct ServiceSummary {
    #[serde(skip_serializing_if = "String::is_empty")]
    proto: String,
    #[serde(skip_serializing_if = "is_zero_u16")]
    port: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    description: String,
}

#[derive(Debug, Serialize)]
struct LocationSummary {
    #[serde(skip_serializing_if = "String::is_empty")]
    country: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    country_code: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    city: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    city_code: String,
    #[serde(skip_serializing_if = "is_zero_f64")]
    latitude: f64,
    #[serde(skip_serializing_if = "is_zero_f64")]
    longitude: f64,
    #[serde(skip_serializing_if = "is_zero_i32")]
    priority: i32,
}

#[derive(Debug, Serialize)]
struct TpmInfoSummary {
    #[serde(skip_serializing_if = "String::is_empty")]
    manufacturer: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    vendor: String,
    #[serde(skip_serializing_if = "is_zero_i32")]
    model: i32,
    #[serde(skip_serializing_if = "is_zero_u64")]
    firmware_version: u64,
    #[serde(skip_serializing_if = "is_zero_i32")]
    spec_revision: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    family_indicator: String,
}

#[derive(Debug, Serialize)]
struct HostInfoSummary {
    #[serde(skip_serializing_if = "String::is_empty")]
    ipn_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    frontend_log_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    backend_log_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    hostname: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    os: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    os_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    container: Option<bool>,
    #[serde(skip_serializing_if = "String::is_empty")]
    env: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    distro: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    distro_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    distro_code_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    app: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    desktop: Option<bool>,
    #[serde(skip_serializing_if = "String::is_empty")]
    package: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_model: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    push_device_token: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    shields_up: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    sharee_node: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    no_logs_no_support: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    wire_ingress: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    ingress_enabled: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    allows_update: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    machine: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    go_arch: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    go_arch_var: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    go_version: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    routable_ips: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    request_tags: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    wol_macs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    services: Vec<ServiceSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    ssh_host_keys: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    cloud: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    userspace: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    userspace_router: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    app_connector: Option<bool>,
    #[serde(skip_serializing_if = "String::is_empty")]
    services_hash: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    exit_node_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<LocationSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tpm: Option<TpmInfoSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state_encrypted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mapping_varies_by_dest_ip: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    working_ipv6: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    os_has_ipv6: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    working_udp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    working_icmp_v4: Option<bool>,
    #[serde(skip_serializing_if = "is_zero_i32")]
    preferred_derp: i32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    have_port_map: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    upnp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pmp: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pcp: Option<bool>,
    #[serde(skip_serializing_if = "String::is_empty")]
    link_type: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    derp_latency: BTreeMap<String, f64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    firewall_mode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct FilterRuleOut {
    #[serde(rename = "SrcIPs", serialize_with = "serialize_filter_src_ips")]
    src_ips: Vec<String>,
    dst_ports: Vec<NetPortRangeOut>,
    #[serde(rename = "IPProto", skip_serializing_if = "Vec::is_empty")]
    ip_proto: Vec<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cap_grant: Vec<CapGrantOut>,
}

fn serialize_filter_src_ips<S>(src_ips: &[String], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    if src_ips.is_empty() {
        serializer.serialize_none()
    } else {
        serializer.serialize_some(src_ips)
    }
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct CapGrantOut {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    dsts: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    caps: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    cap_map: BTreeMap<String, Option<Vec<Value>>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct NetPortRangeOut {
    #[serde(rename = "IP")]
    ip: String,
    ports: PortRangeOut,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "PascalCase")]
struct PortRangeOut {
    first: u16,
    last: u16,
}

fn main() -> Result<()> {
    let paths = scenario_paths()?;
    let mut out = Vec::with_capacity(paths.len());

    for path in paths {
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("reading scenario {}", path.display()))?;
        let scenario: Scenario = serde_json::from_str(&raw)
            .with_context(|| format!("parsing scenario {}", path.display()))?;
        let policy = serde_json::to_string(&scenario.policy)?;
        let parsed = parse_hujson_policy(&policy).and_then(|mut doc| {
            let users = policy_users(&scenario);
            headscale_api::policy::validate_policy_user_references(&doc, &users)
                .map_err(headscale_api::policy::PolicyParseError::Schema)?;
            doc.users = Some(users);
            Ok(doc)
        });
        if let Some(expect) = scenario.expect_policy_error.as_deref() {
            match parsed {
                Ok(_) => bail!(
                    "headscale-rs policy for {} parsed successfully, want error containing {:?}",
                    scenario.name,
                    expect
                ),
                Err(err) => {
                    let err = err.to_string();
                    if !err.contains(expect) {
                        bail!(
                            "headscale-rs policy error for {} = {:?}, want substring {:?}",
                            scenario.name,
                            err,
                            expect
                        );
                    }
                    out.push(ScenarioOutput {
                        engine: "headscale-rs",
                        name: scenario.name.clone(),
                        filter: Value::Array(Vec::new()),
                        policy_error: Some(expect.to_string()),
                        filter_for_nodes: Vec::new(),
                        node_filters: Vec::new(),
                        peer_maps: Vec::new(),
                        route_approvals: Vec::new(),
                        via_routes: Vec::new(),
                        tag_checks: Vec::new(),
                        node_attrs: Vec::new(),
                        ssh_policies: Vec::new(),
                        policy_tests: Vec::new(),
                        ssh_tests: Vec::new(),
                        policy_tests_passed: None,
                        ssh_tests_passed: None,
                        wire: None,
                    });
                    continue;
                }
            }
        }
        let doc =
            parsed.with_context(|| format!("headscale-rs parsing policy for {}", scenario.name))?;
        let filter_nodes = build_filter_nodes(&scenario)?;
        let (policy_tests_passed, ssh_tests_passed) =
            run_test_verdicts(&scenario, &doc, &filter_nodes);
        let production = ProductionFilters::compile(
            policy.as_bytes(),
            policy_users(&scenario),
            &parity_nodes(&scenario),
        )
        .map_err(|error| {
            anyhow::anyhow!(
                "headscale-rs production policy compile for {}: {error}",
                scenario.name
            )
        })?;
        let order = list_order();
        out.push(ScenarioOutput {
            engine: "headscale-rs",
            name: scenario.name.clone(),
            filter: normalized_json(&production.global(), order),
            policy_error: None,
            filter_for_nodes: run_filter_node_checks(&scenario, &production, order)?,
            node_filters: scenario
                .nodes
                .iter()
                .map(|node| NodeFilterOut {
                    node_id: node.id,
                    rules: normalized_json(&production.for_node(node.id), order),
                })
                .collect(),
            peer_maps: run_peer_map_checks(&scenario, &doc, &filter_nodes)?,
            route_approvals: run_route_checks(&scenario, &doc, &filter_nodes)?,
            via_routes: run_via_route_checks(&scenario, &doc, &filter_nodes)?,
            tag_checks: run_tag_checks(&scenario, &doc, &filter_nodes)?,
            node_attrs: run_node_attr_checks(&scenario, &doc, &filter_nodes)?,
            ssh_policies: run_ssh_checks(&scenario, &doc, &filter_nodes)?,
            policy_tests: normalize_policy_tests(&doc),
            ssh_tests: normalize_ssh_policy_tests(&doc),
            policy_tests_passed,
            ssh_tests_passed,
            wire: normalize_wire(scenario.wire, &scenario.nodes, &filter_nodes, &doc)?,
        });
    }

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn policy_users(scenario: &Scenario) -> Vec<headscale_api::policy::PolicyUser> {
    scenario
        .users
        .iter()
        .map(|user| headscale_api::policy::PolicyUser {
            id: user.id,
            name: user.name.clone(),
            email: user.email.clone(),
            provider_identifier: user.provider_identifier.clone(),
        })
        .collect()
}

fn parity_nodes(scenario: &Scenario) -> Vec<ParityNode> {
    let owners = scenario
        .users
        .iter()
        .map(|user| {
            let name = if user.email.is_empty() {
                user.name.clone()
            } else {
                user.email.clone()
            };
            (user.id, name)
        })
        .collect::<HashMap<_, _>>();
    scenario
        .nodes
        .iter()
        .map(|node| ParityNode {
            id: node.id,
            user_id: node.user_id,
            user: owners.get(&node.user_id).cloned(),
            ipv4: node.ipv4.clone(),
            ipv6: node.ipv6.clone(),
            tags: node.tags.clone(),
            announced_routes: node.routes.clone(),
            approved_routes: node.approved_routes.clone(),
        })
        .collect()
}

/// `PARITY_FILTER_ORDER=emitted` keeps the production compiler's own list
/// order inside each rule (the Go side is switched the same way) instead of
/// the default sorted comparison.
fn list_order() -> ListOrder {
    match env::var("PARITY_FILTER_ORDER").as_deref() {
        Ok("emitted") => ListOrder::AsEmitted,
        _ => ListOrder::SortedLikeGoHarness,
    }
}

#[derive(Debug)]
struct FilterNode {
    id: u64,
    user_id: u64,
    user: Option<String>,
    addrs: Vec<String>,
    tags: Vec<String>,
    routes: Vec<String>,
}

fn build_filter_nodes(scenario: &Scenario) -> Result<Vec<FilterNode>> {
    let users = scenario
        .users
        .iter()
        .map(|user| {
            let name = if user.email.is_empty() {
                user.name.clone()
            } else {
                user.email.clone()
            };
            (user.id, name)
        })
        .collect::<HashMap<_, _>>();

    scenario
        .nodes
        .iter()
        .map(|node| {
            let mut addrs = Vec::new();
            if !node.ipv4.is_empty() {
                addrs.push(node.ipv4.clone());
            }
            if !node.ipv6.is_empty() {
                addrs.push(node.ipv6.clone());
            }
            Ok(FilterNode {
                id: node.id,
                user_id: node.user_id,
                user: users.get(&node.user_id).cloned(),
                addrs,
                tags: node.tags.clone(),
                routes: active_routes(node)?,
            })
        })
        .collect()
}

fn active_routes(node: &ScenarioNode) -> Result<Vec<String>> {
    let announced =
        normalize_prefixes(&node.routes).with_context(|| format!("node {} routes", node.id))?;
    let approved = normalize_prefixes(&node.approved_routes)
        .with_context(|| format!("node {} approved_routes", node.id))?;
    let mut out = announced
        .into_iter()
        .filter(|route| approved.contains(route))
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    Ok(out)
}

fn run_filter_node_checks(
    scenario: &Scenario,
    production: &ProductionFilters,
    order: ListOrder,
) -> Result<Vec<FilterForNodeOut>> {
    let mut out = Vec::with_capacity(scenario.filter_node_checks.len());
    for check in &scenario.filter_node_checks {
        scenario
            .nodes
            .iter()
            .find(|node| node.id == check.node_id)
            .with_context(|| {
                format!(
                    "filter node check {} references unknown node {}",
                    check.name, check.node_id
                )
            })?;
        out.push(FilterForNodeOut {
            name: check.name.clone(),
            rules: normalized_json(&production.for_node(check.node_id), order),
        });
    }
    Ok(out)
}

fn run_test_verdicts(
    scenario: &Scenario,
    doc: &PolicyDoc,
    nodes: &[FilterNode],
) -> (Option<bool>, Option<bool>) {
    if !scenario.audit_test_verdicts {
        return (None, None);
    }
    let check_nodes = nodes
        .iter()
        .map(|node| PolicyCheckNode {
            id: node.id,
            user_id: (node.user_id != 0).then_some(node.user_id),
            name: scenario
                .nodes
                .iter()
                .find(|source| source.id == node.id)
                .map(|source| source.hostname.clone())
                .unwrap_or_else(|| node.id.to_string()),
            user: node.user.clone(),
            addrs: node.addrs.clone(),
            tags: node.tags.clone(),
        })
        .collect::<Vec<_>>();
    let policy_tests_passed = if doc.tests.is_empty() {
        None
    } else {
        let mut test_doc = doc.clone();
        test_doc.ssh_tests.clear();
        Some(check_policy_semantics(&test_doc, &check_nodes).is_ok())
    };
    let ssh_tests_passed = if doc.ssh_tests.is_empty() {
        None
    } else {
        let mut test_doc = doc.clone();
        test_doc.tests.clear();
        Some(check_policy_semantics(&test_doc, &check_nodes).is_ok())
    };
    (policy_tests_passed, ssh_tests_passed)
}

fn run_peer_map_checks(
    scenario: &Scenario,
    doc: &PolicyDoc,
    nodes: &[FilterNode],
) -> Result<Vec<PeerMapOut>> {
    if scenario.peer_map_checks.is_empty() {
        return Ok(Vec::new());
    }

    let peer_nodes = nodes
        .iter()
        .map(|node| PeerMapNode {
            id: node.id,
            addr: node.addrs.first().cloned().unwrap_or_default(),
            addrs: node.addrs.clone(),
            user: node.user.clone(),
            tags: node.tags.clone(),
            routes: node.routes.clone(),
        })
        .collect::<Vec<_>>();
    let owners = nodes
        .iter()
        .filter(|node| node.user_id != 0)
        .map(|node| (node.id, node.user_id))
        .collect();
    let peer_map =
        headscale_api::policy::build_peer_map_for_doc_with_user_ids(doc, &peer_nodes, &owners);

    let mut out = Vec::with_capacity(scenario.peer_map_checks.len());
    for check in &scenario.peer_map_checks {
        nodes
            .iter()
            .find(|node| node.id == check.node_id)
            .with_context(|| {
                format!(
                    "peer map check {} references unknown node {}",
                    check.name, check.node_id
                )
            })?;
        let peers = peer_map.get(&check.node_id).cloned().unwrap_or_default();
        out.push(PeerMapOut {
            name: check.name.clone(),
            peers,
        });
    }
    Ok(out)
}

fn run_tag_checks(
    scenario: &Scenario,
    doc: &PolicyDoc,
    nodes: &[FilterNode],
) -> Result<Vec<TagCheckOut>> {
    let node_views = nodes
        .iter()
        .map(|node| NodeView {
            user_id: (node.user_id != 0).then_some(node.user_id),
            addr: node.addrs.first().map(String::as_str),
            addrs: &node.addrs,
            user: node.user.as_deref(),
            tags: &node.tags,
        })
        .collect::<Vec<_>>();
    let mut out = Vec::with_capacity(scenario.tag_checks.len());
    for check in &scenario.tag_checks {
        let node = nodes
            .iter()
            .find(|node| node.id == check.node_id)
            .with_context(|| {
                format!(
                    "tag check {} references unknown node {}",
                    check.name, check.node_id
                )
            })?;
        let view = NodeView {
            user_id: (node.user_id != 0).then_some(node.user_id),
            addr: node.addrs.first().map(String::as_str),
            addrs: &node.addrs,
            user: node.user.as_deref(),
            tags: &node.tags,
        };
        out.push(TagCheckOut {
            name: check.name.clone(),
            allowed: doc.node_can_have_tag_with_nodes(&view, &check.tag, &node_views),
        });
    }
    Ok(out)
}

fn run_node_attr_checks(
    scenario: &Scenario,
    doc: &PolicyDoc,
    nodes: &[FilterNode],
) -> Result<Vec<NodeAttrOut>> {
    let mut out = Vec::with_capacity(scenario.node_attr_checks.len());
    for check in &scenario.node_attr_checks {
        let node = nodes
            .iter()
            .find(|node| node.id == check.node_id)
            .with_context(|| {
                format!(
                    "node attr check {} references unknown node {}",
                    check.name, check.node_id
                )
            })?;
        let view = NodeView {
            user_id: (node.user_id != 0).then_some(node.user_id),
            addr: node.addrs.first().map(String::as_str),
            addrs: &node.addrs,
            user: node.user.as_deref(),
            tags: &node.tags,
        };
        out.push(NodeAttrOut {
            name: check.name.clone(),
            attrs: doc.attrs_for(&view),
        });
    }
    Ok(out)
}

fn run_ssh_checks(
    scenario: &Scenario,
    doc: &PolicyDoc,
    nodes: &[FilterNode],
) -> Result<Vec<SshPolicyOut>> {
    let mut out = Vec::with_capacity(scenario.ssh_checks.len());
    let ssh_nodes: Vec<SshPolicyNode> = nodes
        .iter()
        .map(|node| SshPolicyNode {
            id: node.id,
            user: node.user.clone(),
            user_id: Some(node.user_id),
            addrs: node.addrs.clone(),
            tags: node.tags.clone(),
        })
        .collect();
    for check in &scenario.ssh_checks {
        let node = nodes
            .iter()
            .find(|node| node.id == check.node_id)
            .with_context(|| {
                format!(
                    "ssh check {} references unknown node {}",
                    check.name, check.node_id
                )
            })?;
        let policy =
            compile_ssh_policy_with_base_url(doc, &ssh_nodes, node.id, "https://control.example");
        out.push(SshPolicyOut {
            name: check.name.clone(),
            rules: normalize_ssh_policy(policy.as_ref()),
        });
    }
    Ok(out)
}

fn normalize_policy_tests(doc: &PolicyDoc) -> Vec<PolicyTestOut> {
    doc.tests
        .iter()
        .map(|test| PolicyTestOut {
            src: test.src.clone(),
            proto: test.proto.clone(),
            accept: test.accept.clone(),
            deny: test.deny.clone(),
        })
        .collect()
}

fn normalize_ssh_policy_tests(doc: &PolicyDoc) -> Vec<SshPolicyTestOut> {
    doc.ssh_tests
        .iter()
        .map(|test| SshPolicyTestOut {
            src: test.src.clone(),
            dst: test.dst.clone(),
            accept: test.accept.clone(),
            deny: test.deny.clone(),
            check: test.check.clone(),
        })
        .collect()
}

fn normalize_ssh_policy(policy: Option<&WireSshPolicy>) -> Vec<SshRuleOut> {
    let Some(policy) = policy else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for rule in &policy.rules {
        let mut principals: Vec<String> = rule
            .principals
            .iter()
            .filter_map(|principal| {
                if principal.node_ip.is_empty() {
                    None
                } else {
                    Some(principal.node_ip.clone())
                }
            })
            .collect();
        principals.sort();
        out.push(SshRuleOut {
            principals,
            ssh_users: rule.ssh_users.clone(),
            action: SshActionOut {
                accept: rule.action.accept,
                reject: rule.action.reject,
                session_duration_nanos: rule.action.session_duration,
                hold_and_delegate: rule.action.hold_and_delegate.clone(),
                allow_agent_forwarding: rule.action.allow_agent_forwarding,
                allow_local_port_forwarding: rule.action.allow_local_port_forwarding,
                allow_remote_port_forwarding: rule.action.allow_remote_port_forwarding,
            },
            accept_env: rule.accept_env.clone(),
        });
    }
    out
}

fn normalize_filter_rule(rule: &mut FilterRuleOut) {
    rule.src_ips.sort();
    rule.src_ips.dedup();
    rule.dst_ports.sort_by(|a, b| {
        a.ip.cmp(&b.ip)
            .then(a.ports.first.cmp(&b.ports.first))
            .then(a.ports.last.cmp(&b.ports.last))
    });
    rule.ip_proto.sort();
    rule.ip_proto.dedup();
    for grant in &mut rule.cap_grant {
        grant.dsts.sort();
        grant.dsts.dedup();
        grant.caps.sort();
        grant.caps.dedup();
    }
    rule.cap_grant.sort_by(|a, b| {
        a.dsts
            .cmp(&b.dsts)
            .then(a.caps.cmp(&b.caps))
            .then(cap_map_sort_key(&a.cap_map).cmp(&cap_map_sort_key(&b.cap_map)))
    });
}

fn cap_map_sort_key(cap_map: &BTreeMap<String, Option<Vec<Value>>>) -> String {
    serde_json::to_string(cap_map).unwrap_or_default()
}

fn run_route_checks(
    scenario: &Scenario,
    doc: &headscale_api::policy::PolicyDoc,
    nodes: &[FilterNode],
) -> Result<Vec<RouteApprovalOut>> {
    if scenario.route_checks.is_empty() {
        return Ok(Vec::new());
    }

    let mut out = Vec::with_capacity(scenario.route_checks.len());
    for check in &scenario.route_checks {
        let node = nodes
            .iter()
            .find(|node| node.id == check.node_id)
            .with_context(|| {
                format!(
                    "route check {} references unknown node {}",
                    check.name, check.node_id
                )
            })?;
        let view = NodeView {
            user_id: (node.user_id != 0).then_some(node.user_id),
            addr: node.addrs.first().map(String::as_str),
            addrs: &node.addrs,
            user: node.user.as_deref(),
            tags: &node.tags,
        };

        let current_approved = parse_prefixes(&check.current_approved)
            .with_context(|| format!("route check {} current_approved", check.name))?;
        let mut approved = current_approved.clone();
        let mut before = current_approved;
        before.sort();
        for route in parse_prefixes(&check.announced_routes)
            .with_context(|| format!("route check {} announced_routes", check.name))?
        {
            if approved.contains(&route) {
                continue;
            }
            let can_approve = if is_default_route(&route)? {
                doc.auto_approves_exit_node(&view)
            } else {
                doc.auto_approves_route(&view, &route)
            };
            if can_approve {
                approved.push(route);
            }
        }
        approved.sort();
        approved.dedup();
        out.push(RouteApprovalOut {
            name: check.name.clone(),
            changed: approved != before,
            approved_routes: approved,
        });
    }

    Ok(out)
}

fn run_via_route_checks(
    scenario: &Scenario,
    doc: &PolicyDoc,
    nodes: &[FilterNode],
) -> Result<Vec<ViaRouteOut>> {
    if scenario.via_route_checks.is_empty() {
        return Ok(Vec::new());
    }

    let candidates = nodes
        .iter()
        .map(|node| ViaRouteCandidate {
            id: node.id,
            tags: &node.tags,
            routes: &node.routes,
        })
        .collect::<Vec<_>>();

    let mut out = Vec::with_capacity(scenario.via_route_checks.len());
    for check in &scenario.via_route_checks {
        let viewer = nodes
            .iter()
            .find(|node| node.id == check.viewer_id)
            .with_context(|| {
                format!(
                    "via route check {} references unknown viewer node {}",
                    check.name, check.viewer_id
                )
            })?;
        let peer = nodes
            .iter()
            .find(|node| node.id == check.peer_id)
            .with_context(|| {
                format!(
                    "via route check {} references unknown peer node {}",
                    check.name, check.peer_id
                )
            })?;
        let viewer_view = NodeView {
            user_id: (viewer.user_id != 0).then_some(viewer.user_id),
            addr: viewer.addrs.first().map(String::as_str),
            addrs: &viewer.addrs,
            user: viewer.user.as_deref(),
            tags: &viewer.tags,
        };
        let peer_view = NodeView {
            user_id: (peer.user_id != 0).then_some(peer.user_id),
            addr: peer.addrs.first().map(String::as_str),
            addrs: &peer.addrs,
            user: peer.user.as_deref(),
            tags: &peer.tags,
        };
        let result = doc.via_routes_for_peer_with_candidates(
            &viewer_view,
            viewer.id,
            &peer_view,
            peer.id,
            &peer.routes,
            &candidates,
        );
        let mut include = result.include;
        let mut exclude = result.exclude;
        let mut use_primary = result.use_primary;
        include.sort();
        exclude.sort();
        use_primary.sort();
        out.push(ViaRouteOut {
            name: check.name.clone(),
            include,
            exclude,
            use_primary,
        });
    }

    Ok(out)
}

fn parse_prefixes(raw: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(raw.len());
    for route in raw {
        let parsed = route
            .parse::<IpNet>()
            .with_context(|| format!("parse prefix {route}"))?;
        out.push(parsed.to_string());
    }
    Ok(out)
}

fn normalize_prefixes(raw: &[String]) -> Result<Vec<String>> {
    let mut out = parse_prefixes(raw)?;
    out.sort();
    out.dedup();
    Ok(out)
}

fn is_default_route(route: &str) -> Result<bool> {
    let parsed = route
        .parse::<IpNet>()
        .with_context(|| format!("parse prefix {route}"))?;
    Ok(parsed.prefix_len() == 0)
}

fn run_runtime_dns_requester_checks(
    checks: &[RuntimeDnsRequesterCheck],
    store: &DnsStore,
    machines: &[MachineDnsRecord],
    nodes: &[ScenarioNode],
    filter_nodes: &[FilterNode],
    doc: &PolicyDoc,
) -> Result<Vec<RuntimeDnsRequesterOut>> {
    let mut out = Vec::with_capacity(checks.len());
    for check in checks {
        let scenario_node = nodes
            .iter()
            .find(|node| node.id == check.node_id)
            .with_context(|| {
                format!(
                    "runtime dns requester check {} references unknown node {}",
                    check.name, check.node_id
                )
            })?;
        let filter_node = filter_nodes
            .iter()
            .find(|node| node.id == check.node_id)
            .with_context(|| {
                format!(
                    "runtime dns requester check {} references unknown filter node {}",
                    check.name, check.node_id
                )
            })?;
        let view = NodeView {
            user_id: (filter_node.user_id != 0).then_some(filter_node.user_id),
            addr: filter_node.addrs.first().map(String::as_str),
            addrs: &filter_node.addrs,
            user: filter_node.user.as_deref(),
            tags: &filter_node.tags,
        };
        let requester = DnsRequester {
            hostname: if scenario_node.hostname.is_empty() {
                format!("node-{}", scenario_node.id)
            } else {
                scenario_node.hostname.clone()
            },
            os: scenario_node.os.clone(),
            primary_ip: filter_node.addrs.first().cloned(),
            node_attrs: doc.attrs_for(&view),
        };
        let config = store.build_for_requester(machines, Some(&requester));
        out.push(RuntimeDnsRequesterOut {
            name: check.name.clone(),
            dns_config: serde_json::to_value(config)?,
        });
    }
    Ok(out)
}

fn normalize_wire(
    wire: Option<WireScenario>,
    nodes: &[ScenarioNode],
    filter_nodes: &[FilterNode],
    doc: &PolicyDoc,
) -> Result<Option<WireOutput>> {
    let Some(wire) = wire else {
        return Ok(None);
    };
    let mut out = WireOutput::default();
    if let Some(value) = wire.dns_config {
        let parsed: DnsConfig = serde_json::from_value(value)?;
        out.dns_config = Some(serde_json::to_value(parsed)?);
    }
    if let Some(value) = wire.runtime_dns_config {
        let spec: DnsConfigSpec = serde_json::from_value(value)?;
        let machines = nodes
            .iter()
            .map(|node| MachineDnsRecord {
                hostname: format!("node-{}", node.id),
                ipv4: node.ipv4.parse().ok(),
                ipv6: if node.ipv6.is_empty() {
                    None
                } else {
                    node.ipv6.parse().ok()
                },
                node_id: node.id,
            })
            .collect::<Vec<_>>();
        let store = DnsStore::from_spec(spec);
        let config = store.build(&machines);
        out.runtime_dns_config = Some(serde_json::to_value(config)?);
        out.runtime_dns_requesters = run_runtime_dns_requester_checks(
            &wire.runtime_dns_requester_checks,
            &store,
            &machines,
            nodes,
            filter_nodes,
            doc,
        )?;
    } else if !wire.runtime_dns_requester_checks.is_empty() {
        bail!("wire runtime_dns_requester_checks require runtime_dns_config");
    }
    if let Some(value) = wire.derp_map {
        let parsed: DerpMap = serde_json::from_value(value)?;
        out.derp_map = Some(serde_json::to_value(parsed)?);
    }
    if let Some(value) = wire.register_request {
        let parsed: RegisterRequest = serde_json::from_value(value)?;
        out.register_request = Some(summarize_register_request(parsed));
    }
    if let Some(value) = wire.register_response {
        let parsed: RegisterResponse = serde_json::from_value(value)?;
        out.register_response = Some(summarize_register_response(parsed));
    }
    if let Some(value) = wire.map_request {
        let parsed: MapRequest = serde_json::from_value(value)?;
        out.map_request = Some(summarize_map_request(parsed));
    }
    if let Some(value) = wire.map_response {
        let parsed: MapResponse = serde_json::from_value(value)?;
        out.map_response = Some(summarize_map_response(parsed)?);
    }
    Ok(Some(out))
}

/// The wire layer decodes an absent key as the all-zero key, as Go's key types
/// do. Go's harness reports a key only when `!IsZero()`, so mirror that.
fn omit_zero_key(key: String) -> String {
    let hex = key.rsplit_once(':').map_or(key.as_str(), |(_, hex)| hex);
    if hex.chars().all(|c| c == '0') {
        String::new()
    } else {
        key
    }
}

fn summarize_register_request(req: RegisterRequest) -> RegisterRequestSummary {
    RegisterRequestSummary {
        version: req.version,
        node_key: req.node_key,
        old_node_key: omit_zero_key(req.old_node_key),
        nl_key: omit_zero_key(req.nl_key),
        auth_key: req.auth.map(|auth| auth.auth_key).unwrap_or_default(),
        hostinfo: req.hostinfo.map(summarize_hostinfo),
        followup: req.followup.unwrap_or_default(),
        tailnet: req.tailnet,
        ephemeral: req.ephemeral,
        requested_expiry: req.expiry.is_some(),
        node_key_signature: req.node_key_signature.unwrap_or_default(),
        signature_type: req.signature_type,
        timestamp: req.timestamp.is_some(),
        device_cert: req.device_cert.unwrap_or_default(),
        signature: req.signature.unwrap_or_default(),
    }
}

fn summarize_register_response(resp: RegisterResponse) -> RegisterResponseSummary {
    RegisterResponseSummary {
        user: UserSummary {
            id: resp.user.id,
            display_name: resp.user.display_name,
            profile_pic_url: resp.user.profile_pic_url,
            created: json_string(resp.user.created),
        },
        login: LoginSummary {
            id: resp.login.id,
            provider: resp.login.provider,
            login_name: resp.login.login_name,
            display_name: resp.login.display_name,
            profile_pic_url: resp.login.profile_pic_url,
        },
        node_key_expired: resp.node_key_expired,
        auth_url: resp.auth_url,
        machine_authorized: resp.machine_authorized,
        node_key_signature: resp.node_key_signature.unwrap_or_default(),
        error: resp.error,
    }
}

fn summarize_map_request(req: MapRequest) -> MapRequestSummary {
    let mut endpoints = req.endpoints.unwrap_or_default();
    endpoints.sort();
    let mut debug_flags = req.debug_flags;
    debug_flags.sort();
    MapRequestSummary {
        version: req.version,
        stream: req.stream,
        keep_alive: req.keep_alive,
        compress: req.compress,
        omit_peers: req.omit_peers,
        node_key: req.node_key,
        map_session_handle: req.map_session_handle,
        map_session_seq: req.map_session_seq,
        disco_key: req.disco_key.unwrap_or_default(),
        hardware_attestation_key: req.hardware_attestation_key.unwrap_or_default(),
        hardware_attestation_key_signature: req.hardware_attestation_key_signature,
        hardware_attestation_key_signature_timestamp: req
            .hardware_attestation_key_signature_timestamp
            .is_some(),
        endpoints,
        endpoint_types: req.endpoint_types,
        read_only: req.read_only,
        tka_head: req.tka_head,
        debug_flags,
        connection_handle_for_test: req.connection_handle_for_test,
        hostinfo: req.hostinfo.map(summarize_hostinfo),
    }
}

fn summarize_map_response(resp: MapResponse) -> Result<MapResponseSummary> {
    let mut peers = resp
        .peers
        .into_iter()
        .map(summarize_map_node)
        .collect::<Vec<_>>();
    peers.sort_by_key(|peer| peer.id);
    let mut peers_changed = resp
        .peers_changed
        .into_iter()
        .map(summarize_map_node)
        .collect::<Vec<_>>();
    peers_changed.sort_by_key(|peer| peer.id);
    let mut peers_removed = resp.peers_removed;
    peers_removed.sort_unstable();
    let packet_filters = if resp.packet_filters.is_empty() {
        None
    } else {
        Some(serde_json::to_value(resp.packet_filters)?)
    };
    let display_messages = if resp.display_messages.is_empty() {
        None
    } else {
        Some(serde_json::to_value(resp.display_messages)?)
    };
    let peer_seen_change = if resp.peer_seen_change.is_empty() {
        None
    } else {
        Some(serde_json::to_value(resp.peer_seen_change)?)
    };
    let online_change = if resp.online_change.is_empty() {
        None
    } else {
        Some(serde_json::to_value(resp.online_change)?)
    };
    let user_profiles = resp
        .user_profiles
        .into_iter()
        .map(|profile| UserProfileSummary {
            id: profile.id,
            login_name: profile.login_name,
            display_name: profile.display_name,
            profile_pic_url: profile.profile_pic_url,
        })
        .collect();
    Ok(MapResponseSummary {
        map_session_handle: resp.map_session_handle,
        seq: resp.seq,
        keep_alive: resp.keep_alive,
        ping_request: resp.ping_request.map(serde_json::to_value).transpose()?,
        pop_browser_url: resp.pop_browser_url,
        domain: resp.domain,
        collect_services: resp.collect_services,
        node: resp.node.map(summarize_map_node),
        peer_count: peers.len(),
        peers,
        peers_changed,
        peers_removed,
        peers_changed_patch: if resp.peers_changed_patch.is_empty() {
            None
        } else {
            Some(serde_json::to_value(resp.peers_changed_patch)?)
        },
        peer_seen_change,
        online_change,
        user_profiles,
        packet_filter: resp
            .packet_filter
            .into_iter()
            .map(filter_rule_out)
            .collect(),
        packet_filters,
        health: resp.health,
        display_messages,
        dns_config: resp.dns_config.map(serde_json::to_value).transpose()?,
        derp_map: resp.derp_map.map(serde_json::to_value).transpose()?,
        ssh_policy: normalize_ssh_policy(resp.ssh_policy.as_ref()),
        control_time: resp.control_time.map(serde_json::to_value).transpose()?,
        tka_info: resp.tka_info.map(serde_json::to_value).transpose()?,
        domain_data_plane_audit_log_id: resp.domain_data_plane_audit_log_id,
        debug: resp.debug.map(serde_json::to_value).transpose()?,
        control_dial_plan: resp
            .control_dial_plan
            .map(serde_json::to_value)
            .transpose()?,
        client_version: resp.client_version.map(serde_json::to_value).transpose()?,
        default_auto_update: resp.deprecated_default_auto_update,
    })
}

fn summarize_map_node(node: MapNode) -> MapNodeSummary {
    let mut addresses = node.addresses;
    addresses.sort();
    let mut allowed_ips = node.allowed_ips;
    allowed_ips.sort();
    let mut primary_routes = node.primary_routes;
    primary_routes.sort();
    let mut endpoints = node.endpoints;
    endpoints.sort();
    let mut tags = node.tags;
    tags.sort();
    let mut capabilities = node.capabilities;
    capabilities.sort();
    let cap_map = if node.cap_map.is_empty() {
        None
    } else {
        Some(serde_json::to_value(node.cap_map).unwrap_or(Value::Null))
    };
    let exit_node_dns_resolvers = if node.exit_node_dns_resolvers.is_empty() {
        None
    } else {
        Some(serde_json::to_value(node.exit_node_dns_resolvers).unwrap_or(Value::Null))
    };
    MapNodeSummary {
        id: node.id,
        stable_id: node.stable_id,
        name: node.name,
        user: node.user,
        sharer: node.sharer,
        key: node.key,
        key_signature: node.key_signature,
        machine: node.machine.unwrap_or_default(),
        disco_key: node.disco_key.unwrap_or_default(),
        addresses,
        allowed_ips,
        primary_routes,
        endpoints,
        legacy_derp_string: node.legacy_derp_string,
        hostinfo: Some(summarize_hostinfo(node.hostinfo)),
        tags,
        created: json_string(node.created),
        key_expiry: json_string(node.key_expiry),
        last_seen: json_string(node.last_seen),
        online: node.online,
        machine_authorized: node.machine_authorized,
        cap: node.cap,
        capabilities,
        cap_map,
        expired: node.expired,
        home_derp: node.home_derp,
        unsigned_peer_api_only: node.unsigned_peer_api_only,
        computed_name: node.computed_name,
        computed_name_with_host: node.computed_name_with_host,
        data_plane_audit_log_id: node.data_plane_audit_log_id,
        self_node_v4_masq_addr_for_this_peer: node
            .self_node_v4_masq_addr_for_this_peer
            .unwrap_or_default(),
        self_node_v6_masq_addr_for_this_peer: node
            .self_node_v6_masq_addr_for_this_peer
            .unwrap_or_default(),
        is_wire_guard_only: node.is_wire_guard_only,
        is_jailed: node.is_jailed,
        exit_node_dns_resolvers,
    }
}

fn json_string<T: Serialize>(value: Option<T>) -> String {
    value
        .and_then(|ts| serde_json::to_value(ts).ok())
        .and_then(|value| value.as_str().map(ToOwned::to_owned))
        .unwrap_or_default()
}

fn summarize_hostinfo(hostinfo: HostInfo) -> HostInfoSummary {
    let (
        mapping_varies_by_dest_ip,
        working_ipv6,
        os_has_ipv6,
        working_udp,
        working_icmp_v4,
        preferred_derp,
        have_port_map,
        upnp,
        pmp,
        pcp,
        link_type,
        derp_latency,
        firewall_mode,
    ) = hostinfo.net_info.map_or_else(
        || {
            (
                None,
                None,
                None,
                None,
                None,
                0,
                false,
                None,
                None,
                None,
                String::new(),
                BTreeMap::new(),
                String::new(),
            )
        },
        |net_info| {
            (
                net_info.mapping_varies_by_dest_ip,
                net_info.working_ipv6,
                net_info.os_has_ipv6,
                net_info.working_udp,
                net_info.working_icmp_v4,
                net_info.preferred_derp,
                net_info.have_port_map,
                net_info.upnp,
                net_info.pmp,
                net_info.pcp,
                net_info.link_type,
                net_info.derp_latency,
                net_info.firewall_mode,
            )
        },
    );
    let mut routable_ips = hostinfo.routable_ips;
    routable_ips.sort();
    let mut services: Vec<ServiceSummary> = hostinfo
        .services
        .into_iter()
        .map(|service| ServiceSummary {
            proto: service.proto,
            port: service.port,
            description: service.description,
        })
        .collect();
    services.sort_by(|a, b| {
        a.proto
            .cmp(&b.proto)
            .then(a.port.cmp(&b.port))
            .then(a.description.cmp(&b.description))
    });
    let location = hostinfo.location.map(|location| LocationSummary {
        country: location.country,
        country_code: location.country_code,
        city: location.city,
        city_code: location.city_code,
        latitude: location.latitude,
        longitude: location.longitude,
        priority: location.priority,
    });
    let tpm = hostinfo.tpm.map(|tpm| TpmInfoSummary {
        manufacturer: tpm.manufacturer,
        vendor: tpm.vendor,
        model: tpm.model,
        firmware_version: tpm.firmware_version,
        spec_revision: tpm.spec_revision,
        family_indicator: tpm.family_indicator,
    });
    HostInfoSummary {
        ipn_version: hostinfo.ipn_version,
        frontend_log_id: hostinfo.frontend_log_id,
        backend_log_id: hostinfo.backend_log_id,
        hostname: hostinfo.hostname,
        os: hostinfo.os,
        os_version: hostinfo.os_version,
        container: hostinfo.container,
        env: hostinfo.env,
        distro: hostinfo.distro,
        distro_version: hostinfo.distro_version,
        distro_code_name: hostinfo.distro_code_name,
        app: hostinfo.app,
        desktop: hostinfo.desktop,
        package: hostinfo.package,
        device_model: hostinfo.device_model,
        push_device_token: hostinfo.push_device_token,
        shields_up: hostinfo.shields_up,
        sharee_node: hostinfo.sharee_node,
        no_logs_no_support: hostinfo.no_logs_no_support,
        wire_ingress: hostinfo.wire_ingress,
        ingress_enabled: hostinfo.ingress_enabled,
        allows_update: hostinfo.allows_update,
        machine: hostinfo.machine,
        go_arch: hostinfo.go_arch,
        go_arch_var: hostinfo.go_arch_var,
        go_version: hostinfo.go_version,
        routable_ips,
        request_tags: hostinfo.request_tags,
        wol_macs: hostinfo.wol_macs,
        services,
        ssh_host_keys: hostinfo.ssh_host_keys,
        cloud: hostinfo.cloud,
        userspace: hostinfo.userspace,
        userspace_router: hostinfo.userspace_router,
        app_connector: hostinfo.app_connector,
        services_hash: hostinfo.services_hash,
        exit_node_id: hostinfo.exit_node_id,
        location,
        tpm,
        state_encrypted: hostinfo.state_encrypted,
        mapping_varies_by_dest_ip,
        working_ipv6,
        os_has_ipv6,
        working_udp,
        working_icmp_v4,
        preferred_derp,
        have_port_map,
        upnp,
        pmp,
        pcp,
        link_type,
        derp_latency,
        firewall_mode,
    }
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}

fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}

fn is_zero_i32(v: &i32) -> bool {
    *v == 0
}

fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}

fn filter_rule_out(rule: headscale_api::tailscale_wire::wire::FilterRule) -> FilterRuleOut {
    let mut out = FilterRuleOut {
        src_ips: rule.src_ips,
        dst_ports: rule
            .dst_ports
            .into_iter()
            .map(|dst| NetPortRangeOut {
                ip: dst.ip,
                ports: PortRangeOut {
                    first: dst.ports.first,
                    last: dst.ports.last,
                },
            })
            .collect(),
        ip_proto: rule.ip_proto,
        cap_grant: rule
            .cap_grant
            .into_iter()
            .map(|grant| CapGrantOut {
                dsts: grant.dsts,
                caps: grant.caps,
                cap_map: grant.cap_map,
            })
            .collect(),
    };
    normalize_filter_rule(&mut out);
    out
}

fn scenario_paths() -> Result<Vec<PathBuf>> {
    let mut args = env::args_os()
        .skip(1)
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    if args.is_empty() {
        bail!("usage: headscale-rs-parity <scenario.json> [scenario.json ...]");
    }
    args.sort();
    Ok(args)
}
