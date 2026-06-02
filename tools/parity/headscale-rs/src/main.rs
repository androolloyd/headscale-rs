use std::{
    collections::{BTreeMap, HashMap},
    env, fs,
    net::IpAddr,
    path::PathBuf,
};

use anyhow::{Context, Result, bail};
use headscale_api::{
    dns::{DnsConfigSpec, DnsRequester, DnsStore, MachineDnsRecord},
    policy::{
        GrantRule, NodeView, PeerMapNode, PolicyAction, PolicyDoc, SshPolicyNode,
        ViaRouteCandidate,
        build_peer_map_for_doc, compile_ssh_policy_with_base_url, parse_hujson_policy,
    },
    tailscale_wire::wire::{
        DerpMap, DnsConfig, HostInfo, MapNode, MapRequest, MapResponse, RegisterRequest,
        RegisterResponse, SshPolicy as WireSshPolicy,
    },
};
use ipnet::IpNet;
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
    wire: Option<WireScenario>,
}

#[derive(Debug, Deserialize)]
struct ScenarioUser {
    id: u64,
    name: String,
    #[serde(default)]
    email: String,
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
    filter: Vec<FilterRuleOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    filter_for_nodes: Vec<FilterForNodeOut>,
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
    wire: Option<WireOutput>,
}

#[derive(Debug, Serialize)]
struct FilterForNodeOut {
    name: String,
    rules: Vec<FilterRuleOut>,
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
    #[serde(rename = "SrcIPs")]
    src_ips: Vec<String>,
    dst_ports: Vec<NetPortRangeOut>,
    #[serde(rename = "IPProto", skip_serializing_if = "Vec::is_empty")]
    ip_proto: Vec<i32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    cap_grant: Vec<CapGrantOut>,
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
        let parsed = parse_hujson_policy(&policy);
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
                        filter: Vec::new(),
                        policy_error: Some(expect.to_string()),
                        filter_for_nodes: Vec::new(),
                        peer_maps: Vec::new(),
                        route_approvals: Vec::new(),
                        via_routes: Vec::new(),
                        tag_checks: Vec::new(),
                        node_attrs: Vec::new(),
                        ssh_policies: Vec::new(),
                        policy_tests: Vec::new(),
                        ssh_tests: Vec::new(),
                        wire: None,
                    });
                    continue;
                }
            }
        }
        let doc =
            parsed.with_context(|| format!("headscale-rs parsing policy for {}", scenario.name))?;
        let filter_nodes = build_filter_nodes(&scenario)?;
        let packet_filter_default_allow = policy_omits_packet_filter_rules(&scenario.policy);
        out.push(ScenarioOutput {
            engine: "headscale-rs",
            name: scenario.name.clone(),
            filter: if packet_filter_default_allow {
                allow_all_filter_rules()
            } else {
                compile_filter_rules(&doc, &filter_nodes, None)
            },
            policy_error: None,
            filter_for_nodes: run_filter_node_checks(
                &scenario,
                &doc,
                &filter_nodes,
                packet_filter_default_allow,
            )?,
            peer_maps: run_peer_map_checks(&scenario, &doc, &filter_nodes)?,
            route_approvals: run_route_checks(&scenario, &doc, &filter_nodes)?,
            via_routes: run_via_route_checks(&scenario, &doc, &filter_nodes)?,
            tag_checks: run_tag_checks(&scenario, &doc, &filter_nodes)?,
            node_attrs: run_node_attr_checks(&scenario, &doc, &filter_nodes)?,
            ssh_policies: run_ssh_checks(&scenario, &doc, &filter_nodes)?,
            policy_tests: normalize_policy_tests(&doc),
            ssh_tests: normalize_ssh_policy_tests(&doc),
            wire: normalize_wire(scenario.wire, &scenario.nodes, &filter_nodes, &doc)?,
        });
    }

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
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

fn policy_omits_packet_filter_rules(policy: &Value) -> bool {
    let Some(object) = policy.as_object() else {
        return false;
    };
    !object.keys().any(|key| {
        matches!(
            key.to_ascii_lowercase().as_str(),
            "acls" | "rules" | "grants"
        )
    })
}

fn allow_all_filter_rules() -> Vec<FilterRuleOut> {
    vec![FilterRuleOut {
        src_ips: vec!["*".to_string()],
        dst_ports: vec![NetPortRangeOut {
            ip: "*".to_string(),
            ports: PortRangeOut {
                first: 0,
                last: 65535,
            },
        }],
        ip_proto: Vec::new(),
        cap_grant: Vec::new(),
    }]
}

fn run_filter_node_checks(
    scenario: &Scenario,
    doc: &PolicyDoc,
    nodes: &[FilterNode],
    packet_filter_default_allow: bool,
) -> Result<Vec<FilterForNodeOut>> {
    let mut out = Vec::with_capacity(scenario.filter_node_checks.len());
    for check in &scenario.filter_node_checks {
        nodes
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
            rules: if packet_filter_default_allow {
                allow_all_filter_rules()
            } else {
                compile_filter_rules(doc, nodes, Some(check.node_id))
            },
        });
    }
    Ok(out)
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
    let peer_map = build_peer_map_for_doc(doc, &peer_nodes);

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
            addr: node.addrs.first().map(String::as_str),
            addrs: &node.addrs,
            user: node.user.as_deref(),
            tags: &node.tags,
        };
        out.push(TagCheckOut {
            name: check.name.clone(),
            allowed: doc.node_can_have_tag(&view, &check.tag),
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

fn compile_filter_rules(
    doc: &PolicyDoc,
    nodes: &[FilterNode],
    node_id: Option<u64>,
) -> Vec<FilterRuleOut> {
    let self_node = node_id.and_then(|id| nodes.iter().find(|node| node.id == id));
    let mut out = Vec::new();
    let projected_grant_indices = projected_network_grant_indices(&doc.grants);
    let via_insert_index = projected_grant_indices.len();
    append_leading_app_only_grant_rules(&mut out, doc, &projected_grant_indices, nodes, self_node);
    let mut via_appended = false;
    if via_insert_index == 0 {
        if let Some(node) = self_node {
            append_via_grant_rules_for_node(&mut out, doc, nodes, node);
            via_appended = true;
        }
    }

    for (rule_index, rule) in doc.rules.iter().enumerate() {
        if !matches!(rule.action, PolicyAction::Accept) {
            append_projected_grant_app_rules_after_rule(
                &mut out,
                doc,
                &projected_grant_indices,
                rule_index,
                nodes,
                self_node,
            );
            if !via_appended && rule_index + 1 == via_insert_index {
                if let Some(node) = self_node {
                    append_via_grant_rules_for_node(&mut out, doc, nodes, node);
                    via_appended = true;
                }
            }
            continue;
        }

        let src_ips = resolve_principals(doc, &rule.src, nodes, None, PrincipalPosition::Source);
        if src_ips.is_empty() {
            append_projected_grant_app_rules_after_rule(
                &mut out,
                doc,
                &projected_grant_indices,
                rule_index,
                nodes,
                self_node,
            );
            if !via_appended && rule_index + 1 == via_insert_index {
                if let Some(node) = self_node {
                    append_via_grant_rules_for_node(&mut out, doc, nodes, node);
                    via_appended = true;
                }
            }
            continue;
        }

        if let Some(node) = self_node {
            let mut self_dsts = Vec::new();
            let mut other_dsts = Vec::new();
            for dst in &rule.dst {
                if dst == "autogroup:self" {
                    self_dsts.push(dst.clone());
                } else {
                    other_dsts.push(dst.clone());
                }
            }

            if !self_dsts.is_empty() && node.tags.is_empty() {
                let same_user = same_user_untagged_nodes(nodes, node);
                let self_src = nodes_matching_prefixes(&same_user, &src_ips);
                let self_dst = same_user
                    .iter()
                    .flat_map(|node| node.addrs.clone())
                    .collect::<Vec<_>>();
                append_filter_rules(&mut out, &self_src, &self_dst, &rule.ports);
            }

            if !other_dsts.is_empty() {
                let dst_ips = resolve_principals(
                    doc,
                    &other_dsts,
                    nodes,
                    self_node,
                    PrincipalPosition::Destination,
                );
                append_filter_rules(&mut out, &src_ips, &dst_ips, &rule.ports);
            }
        } else {
            let dst_ips =
                resolve_principals(doc, &rule.dst, nodes, None, PrincipalPosition::Destination);
            append_filter_rules(&mut out, &src_ips, &dst_ips, &rule.ports);
        }

        append_projected_grant_app_rules_after_rule(
            &mut out,
            doc,
            &projected_grant_indices,
            rule_index,
            nodes,
            self_node,
        );
        if !via_appended && rule_index + 1 == via_insert_index {
            if let Some(node) = self_node {
                append_via_grant_rules_for_node(&mut out, doc, nodes, node);
                via_appended = true;
            }
        }
    }

    if !via_appended {
        if let Some(node) = self_node {
            append_via_grant_rules_for_node(&mut out, doc, nodes, node);
        }
    }

    if let Some(node) = self_node {
        coalesce_filter_rules(reduce_filter_rules_for_node(out, node))
    } else {
        coalesce_filter_rules(out)
    }
}

fn projected_network_grant_indices(grants: &[GrantRule]) -> Vec<usize> {
    grants
        .iter()
        .enumerate()
        .filter_map(|(index, grant)| {
            (grant.via.is_empty() && !grant.ip.is_empty()).then_some(index)
        })
        .collect()
}

fn append_leading_app_only_grant_rules(
    out: &mut Vec<FilterRuleOut>,
    doc: &PolicyDoc,
    projected_grant_indices: &[usize],
    nodes: &[FilterNode],
    self_node: Option<&FilterNode>,
) {
    let end = projected_grant_indices
        .first()
        .copied()
        .unwrap_or(doc.grants.len());
    append_app_only_grant_rules_in_range(out, doc, 0, end, nodes, self_node);
}

fn append_projected_grant_app_rules_after_rule(
    out: &mut Vec<FilterRuleOut>,
    doc: &PolicyDoc,
    projected_grant_indices: &[usize],
    rule_index: usize,
    nodes: &[FilterNode],
    self_node: Option<&FilterNode>,
) {
    let Some(&grant_index) = projected_grant_indices.get(rule_index) else {
        return;
    };
    let Some(grant) = doc.grants.get(grant_index)
    else {
        return;
    };
    append_app_grant_rule(out, doc, grant, nodes, self_node);
    let end = projected_grant_indices
        .get(rule_index + 1)
        .copied()
        .unwrap_or(doc.grants.len());
    append_app_only_grant_rules_in_range(out, doc, grant_index + 1, end, nodes, self_node);
}

fn append_app_only_grant_rules_in_range(
    out: &mut Vec<FilterRuleOut>,
    doc: &PolicyDoc,
    start: usize,
    end: usize,
    nodes: &[FilterNode],
    self_node: Option<&FilterNode>,
) {
    for grant in doc
        .grants
        .iter()
        .skip(start)
        .take(end.saturating_sub(start))
    {
        if !grant.ip.is_empty() {
            continue;
        }
        append_app_grant_rule(out, doc, grant, nodes, self_node);
    }
}

fn append_app_grant_rule(
    out: &mut Vec<FilterRuleOut>,
    doc: &PolicyDoc,
    grant: &GrantRule,
    nodes: &[FilterNode],
    self_node: Option<&FilterNode>,
) {
    if grant.app.is_empty() || !grant.via.is_empty() || grant.src.is_empty() {
        return;
    }

    let src_ips = resolve_principals(doc, &grant.src, nodes, None, PrincipalPosition::Source);
    let mut other_dsts = Vec::new();
    let mut self_dsts = Vec::new();
    for dst in &grant.dst {
        if dst == "autogroup:self" {
            self_dsts.push(dst.clone());
        } else {
            other_dsts.push(dst.clone());
        }
    }

    if !other_dsts.is_empty() {
        append_cap_grant_rules(out, doc, nodes, &src_ips, &other_dsts, &grant.app);
    }

    let Some(node) = self_node else {
        return;
    };
    if self_dsts.is_empty() || !node.tags.is_empty() {
        return;
    }

    let same_user = same_user_untagged_nodes(nodes, node);
    let self_src = nodes_matching_prefixes(&same_user, &src_ips);
    if self_src.is_empty() {
        return;
    }
    let self_dst = same_user
        .iter()
        .flat_map(|node| node_addr_prefixes(node))
        .collect::<Vec<_>>();
    append_cap_grant_rules(out, doc, nodes, &self_src, &self_dst, &grant.app);
}

fn append_cap_grant_rules(
    out: &mut Vec<FilterRuleOut>,
    doc: &PolicyDoc,
    nodes: &[FilterNode],
    src_ips: &[String],
    dsts: &[String],
    app: &BTreeMap<String, Vec<Value>>,
) {
    let mut cap_grants = Vec::new();
    let mut dst_ip_strings = Vec::new();
    for dst in dsts {
        let dst_prefixes = resolve_cap_grant_dst(doc, dst, nodes);
        if dst_prefixes.is_empty() {
            continue;
        }
        for prefix in &dst_prefixes {
            if let Some(net) = parse_ip_net(prefix) {
                push_unique_string(&mut dst_ip_strings, net.addr().to_string());
            }
        }
        cap_grants.push(CapGrantOut {
            dsts: dst_prefixes,
            caps: Vec::new(),
            cap_map: wire_cap_map(app),
        });
    }
    if cap_grants.is_empty() {
        return;
    }

    let mut rule = FilterRuleOut {
        src_ips: src_ips.to_vec(),
        dst_ports: Vec::new(),
        ip_proto: Vec::new(),
        cap_grant: cap_grants,
    };
    normalize_filter_rule(&mut rule);
    append_coalesced_filter_rule(out, rule);

    append_companion_cap_grant_rules(out, &dst_ip_strings, src_ips, app);
}

fn wire_cap_map(app: &BTreeMap<String, Vec<Value>>) -> BTreeMap<String, Option<Vec<Value>>> {
    app.iter()
        .map(|(cap, values)| (cap.clone(), Some(values.clone())))
        .collect()
}

fn companion_cap_map(cap: &str) -> BTreeMap<String, Option<Vec<Value>>> {
    BTreeMap::from([(cap.to_string(), None)])
}

fn companion_cap(cap: &str) -> Option<&'static str> {
    match cap {
        "tailscale.com/cap/drive" => Some("tailscale.com/cap/drive-sharer"),
        "tailscale.com/cap/relay" => Some("tailscale.com/cap/relay-target"),
        _ => None,
    }
}

fn append_companion_cap_grant_rules(
    out: &mut Vec<FilterRuleOut>,
    dst_ip_strings: &[String],
    src_ips: &[String],
    app: &BTreeMap<String, Vec<Value>>,
) {
    let mut src_prefixes = src_ips
        .iter()
        .flat_map(|src| ipset_string_to_cidrs(src))
        .collect::<Vec<_>>();
    src_prefixes.sort();
    src_prefixes.dedup();
    if dst_ip_strings.is_empty() || src_prefixes.is_empty() {
        return;
    }

    let mut caps = app
        .keys()
        .filter_map(|cap| companion_cap(cap))
        .collect::<Vec<_>>();
    caps.sort_unstable();
    for cap in caps {
        let mut rule = FilterRuleOut {
            src_ips: dst_ip_strings.to_vec(),
            dst_ports: Vec::new(),
            ip_proto: Vec::new(),
            cap_grant: vec![CapGrantOut {
                dsts: src_prefixes.clone(),
                caps: Vec::new(),
                cap_map: companion_cap_map(cap),
            }],
        };
        normalize_filter_rule(&mut rule);
        append_coalesced_filter_rule(out, rule);
    }
}

fn resolve_cap_grant_dst(doc: &PolicyDoc, token: &str, nodes: &[FilterNode]) -> Vec<String> {
    if token == "*" {
        return tailnet_filter_srcs()
            .into_iter()
            .flat_map(|prefix| ipset_string_to_cidrs(&prefix))
            .collect();
    }
    if let Some(host) = token.strip_prefix("host:") {
        return doc
            .hosts
            .get(host)
            .and_then(|prefix| parse_ip_net(prefix).map(|net| vec![net.to_string()]))
            .unwrap_or_default();
    }
    if let Some(prefix) = doc.hosts.get(token) {
        return parse_ip_net(prefix)
            .map(|net| vec![net.to_string()])
            .unwrap_or_default();
    }
    if let Some(net) = parse_ip_net(token) {
        return vec![net.to_string()];
    }
    let mut out = resolve_principal(doc, token, nodes, None, PrincipalPosition::Destination);
    out.sort();
    out.dedup();
    out
}

fn append_via_grant_rules_for_node(
    out: &mut Vec<FilterRuleOut>,
    doc: &PolicyDoc,
    nodes: &[FilterNode],
    self_node: &FilterNode,
) {
    for grant in &doc.grants {
        if grant.via.is_empty() || grant.ip.is_empty() {
            continue;
        }
        if !grant
            .via
            .iter()
            .any(|via| self_node.tags.iter().any(|tag| tag == via))
        {
            continue;
        }

        let src_ips = resolve_principals(doc, &grant.src, nodes, None, PrincipalPosition::Source);
        if src_ips.is_empty() {
            continue;
        }

        let dst_ips = resolve_via_destinations_for_node(doc, &grant.dst, nodes, self_node);
        if dst_ips.is_empty() {
            continue;
        }

        let ports = normalize_grant_ip_specs(&grant.ip);
        append_filter_rules(out, &src_ips, &dst_ips, &ports);
    }
}

fn append_filter_rules(
    out: &mut Vec<FilterRuleOut>,
    src_ips: &[String],
    dst_ips: &[String],
    ports: &[String],
) {
    if src_ips.is_empty() || dst_ips.is_empty() {
        return;
    }
    for (ip_proto, port_ranges) in compile_port_groups(ports) {
        let mut dst_ports = Vec::new();
        for ip in dst_ips {
            for range in &port_ranges {
                dst_ports.push(NetPortRangeOut {
                    ip: dst_port_ip_string(ip),
                    ports: range.clone(),
                });
            }
        }
        let mut rule = FilterRuleOut {
            src_ips: src_ips.to_vec(),
            dst_ports,
            ip_proto,
            cap_grant: Vec::new(),
        };
        normalize_filter_rule(&mut rule);
        append_coalesced_filter_rule(out, rule);
    }
}

fn resolve_principals(
    doc: &PolicyDoc,
    tokens: &[String],
    nodes: &[FilterNode],
    self_node: Option<&FilterNode>,
    position: PrincipalPosition,
) -> Vec<String> {
    let mut out = Vec::new();
    for token in tokens {
        let resolved = resolve_principal(doc, token, nodes, self_node, position);
        let normalized = match position {
            PrincipalPosition::Source => resolved,
            PrincipalPosition::Destination => aggregate_prefixes_as_cidrs(resolved),
        };
        for value in normalized {
            push_unique_string(&mut out, value);
        }
    }
    if position == PrincipalPosition::Source && tokens.iter().any(|token| token == "*") {
        for route in approved_subnet_routes(nodes) {
            push_unique_string(&mut out, route);
        }
    }
    match position {
        PrincipalPosition::Source => aggregate_prefixes(out),
        PrincipalPosition::Destination => {
            out.sort();
            out.dedup();
            out
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrincipalPosition {
    Source,
    Destination,
}

fn resolve_principal(
    doc: &PolicyDoc,
    token: &str,
    nodes: &[FilterNode],
    self_node: Option<&FilterNode>,
    position: PrincipalPosition,
) -> Vec<String> {
    if token == "*" {
        return match position {
            PrincipalPosition::Source => tailnet_filter_srcs(),
            PrincipalPosition::Destination => vec!["*".to_string()],
        };
    }
    if token.contains('@') {
        return nodes
            .iter()
            .filter(|node| node.tags.is_empty())
            .filter(|node| {
                node.user
                    .as_deref()
                    .is_some_and(|user| user_matches(token, user))
            })
            .flat_map(node_addr_prefixes)
            .collect();
    }
    if let Some(group) = token.strip_prefix("group:") {
        let Some(members) = doc.groups.get(token).or_else(|| doc.groups.get(group)) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for member in members {
            for value in resolve_principal(doc, member, nodes, self_node, position) {
                push_unique_string(&mut out, value);
            }
        }
        return out;
    }
    if let Some(tag) = token.strip_prefix("tag:") {
        return nodes
            .iter()
            .filter(|node| node.tags.iter().any(|node_tag| tag_matches(node_tag, tag)))
            .flat_map(node_addr_prefixes)
            .collect();
    }
    if let Some(kind) = token.strip_prefix("autogroup:") {
        return match kind {
            "internet" => internet_filter_cidrs(),
            "member" => nodes
                .iter()
                .filter(|node| node.tags.is_empty())
                .flat_map(node_addr_prefixes)
                .collect(),
            "tagged" => nodes
                .iter()
                .filter(|node| !node.tags.is_empty())
                .flat_map(node_addr_prefixes)
                .collect(),
            "self" => self_node
                .filter(|node| node.tags.is_empty())
                .map(|node| same_user_untagged_nodes(nodes, node))
                .unwrap_or_default()
                .iter()
                .flat_map(|node| node_addr_prefixes(node))
                .collect(),
            _ => Vec::new(),
        };
    }
    if let Some(host) = token.strip_prefix("host:") {
        return doc
            .hosts
            .get(host)
            .map(|prefix| resolve_prefix(prefix, nodes, false))
            .unwrap_or_default();
    }
    if let Some(prefix) = doc.hosts.get(token) {
        return resolve_prefix(prefix, nodes, false);
    }
    if parse_ip_net(token).is_some() {
        return resolve_prefix(token, nodes, false);
    }
    Vec::new()
}

fn resolve_via_destinations_for_node(
    doc: &PolicyDoc,
    dsts: &[String],
    nodes: &[FilterNode],
    node: &FilterNode,
) -> Vec<String> {
    let mut out = Vec::new();
    let node_subnet_routes = node
        .routes
        .iter()
        .filter(|route| !is_exit_route(route))
        .collect::<Vec<_>>();

    for dst in dsts {
        if dst == "autogroup:internet" {
            if node.routes.iter().any(|route| is_exit_route(route)) {
                for prefix in internet_filter_cidrs() {
                    push_unique_string(&mut out, prefix);
                }
            }
            continue;
        }

        for prefix in resolve_principal(doc, dst, nodes, None, PrincipalPosition::Destination) {
            if node_subnet_routes
                .iter()
                .any(|route| prefixes_overlap(&prefix, route))
            {
                push_unique_string(&mut out, prefix);
            }
        }
    }

    out.sort();
    out
}

fn same_user_untagged_nodes<'a>(nodes: &'a [FilterNode], node: &FilterNode) -> Vec<&'a FilterNode> {
    nodes
        .iter()
        .filter(|candidate| candidate.tags.is_empty())
        .filter(|candidate| candidate.user == node.user)
        .collect()
}

fn nodes_matching_prefixes(nodes: &[&FilterNode], prefixes: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for node in nodes {
        if node.addrs.iter().any(|addr| {
            prefixes
                .iter()
                .any(|prefix| ipset_string_contains_addr(prefix, addr))
        }) {
            for addr in node_addr_prefixes(node) {
                push_unique_string(&mut out, addr);
            }
        }
    }
    out.sort();
    aggregate_prefixes(out)
}

fn resolve_prefix(prefix: &str, nodes: &[FilterNode], include_nodes_inside: bool) -> Vec<String> {
    let Some(net) = parse_ip_net(prefix) else {
        return Vec::new();
    };
    let mut out = vec![net.to_string()];
    for node in nodes {
        let node_matches = node
            .addrs
            .iter()
            .any(|addr| net_contains_addr(&net, addr) && include_nodes_inside);
        if node_matches {
            for addr in node_addr_prefixes(node) {
                push_unique_string(&mut out, addr);
            }
        }
    }
    aggregate_prefixes(out)
}

fn approved_subnet_routes(nodes: &[FilterNode]) -> Vec<String> {
    let mut out = Vec::new();
    for node in nodes {
        for route in &node.routes {
            if !is_exit_route(route) {
                push_unique_string(&mut out, route.clone());
            }
        }
    }
    out.sort();
    out
}

fn node_addr_prefixes(node: &FilterNode) -> Vec<String> {
    node.addrs
        .iter()
        .filter_map(|addr| parse_ip_net(addr))
        .map(|net| net.to_string())
        .collect()
}

fn reduce_filter_rules_for_node(
    rules: Vec<FilterRuleOut>,
    node: &FilterNode,
) -> Vec<FilterRuleOut> {
    let mut out = Vec::new();
    for mut rule in rules {
        if !rule.cap_grant.is_empty() {
            if let Some(reduced) = reduce_cap_grant_rule_for_node(&rule, node) {
                out.push(reduced);
            }
            continue;
        }

        rule.dst_ports.retain(|dst| {
            if dst.ip == "*" {
                return true;
            }
            node.addrs
                .iter()
                .any(|addr| ipset_string_contains_addr(&dst.ip, addr))
                || node
                    .routes
                    .iter()
                    .any(|route| prefixes_overlap(&dst.ip, route))
                || (node.routes.iter().any(|route| is_exit_route(route))
                    && internet_filter_cidrs()
                        .iter()
                        .any(|prefix| prefix == &dst.ip))
        });
        if rule.dst_ports.is_empty() {
            continue;
        }
        normalize_filter_rule(&mut rule);
        out.push(rule);
    }
    out
}

fn reduce_cap_grant_rule_for_node(
    rule: &FilterRuleOut,
    node: &FilterNode,
) -> Option<FilterRuleOut> {
    let mut cap_grant = Vec::new();
    for grant in &rule.cap_grant {
        let mut dsts = Vec::new();

        for dst in &grant.dsts {
            let Some(dst_net) = parse_ip_net(dst) else {
                continue;
            };
            if is_single_ip(&dst_net) {
                if node
                    .addrs
                    .iter()
                    .any(|addr| net_contains_addr(&dst_net, addr))
                {
                    push_unique_string(&mut dsts, dst_net.to_string());
                }
                continue;
            }

            for addr in &node.addrs {
                if net_contains_addr(&dst_net, addr)
                    && let Some(prefix) = parse_ip_net(addr).map(|net| net.to_string())
                {
                    push_unique_string(&mut dsts, prefix);
                }
            }
        }

        for dst in &grant.dsts {
            if node
                .routes
                .iter()
                .filter(|route| !is_exit_route(route))
                .any(|route| prefixes_overlap(dst, route))
            {
                push_unique_string(&mut dsts, dst.clone());
            }
        }

        if !dsts.is_empty() {
            dsts.sort();
            cap_grant.push(CapGrantOut {
                dsts,
                caps: grant.caps.clone(),
                cap_map: grant.cap_map.clone(),
            });
        }
    }

    if cap_grant.is_empty() {
        return None;
    }

    let mut out = FilterRuleOut {
        src_ips: rule.src_ips.clone(),
        dst_ports: Vec::new(),
        ip_proto: Vec::new(),
        cap_grant,
    };
    normalize_filter_rule(&mut out);
    Some(out)
}

fn tailnet_filter_srcs() -> Vec<String> {
    vec![
        "100.115.94.0-100.127.255.255".to_string(),
        "100.64.0.0-100.115.91.255".to_string(),
        "fd7a:115c:a1e0::/48".to_string(),
    ]
}

fn internet_filter_cidrs() -> Vec<String> {
    vec![
        "0.0.0.0/5".to_string(),
        "8.0.0.0/7".to_string(),
        "11.0.0.0/8".to_string(),
        "12.0.0.0/6".to_string(),
        "16.0.0.0/4".to_string(),
        "32.0.0.0/3".to_string(),
        "64.0.0.0/3".to_string(),
        "96.0.0.0/6".to_string(),
        "100.0.0.0/10".to_string(),
        "100.128.0.0/9".to_string(),
        "101.0.0.0/8".to_string(),
        "102.0.0.0/7".to_string(),
        "104.0.0.0/5".to_string(),
        "112.0.0.0/4".to_string(),
        "128.0.0.0/3".to_string(),
        "160.0.0.0/5".to_string(),
        "168.0.0.0/8".to_string(),
        "169.0.0.0/9".to_string(),
        "169.128.0.0/10".to_string(),
        "169.192.0.0/11".to_string(),
        "169.224.0.0/12".to_string(),
        "169.240.0.0/13".to_string(),
        "169.248.0.0/14".to_string(),
        "169.252.0.0/15".to_string(),
        "169.255.0.0/16".to_string(),
        "170.0.0.0/7".to_string(),
        "172.0.0.0/12".to_string(),
        "172.32.0.0/11".to_string(),
        "172.64.0.0/10".to_string(),
        "172.128.0.0/9".to_string(),
        "173.0.0.0/8".to_string(),
        "174.0.0.0/7".to_string(),
        "176.0.0.0/4".to_string(),
        "192.0.0.0/9".to_string(),
        "192.128.0.0/11".to_string(),
        "192.160.0.0/13".to_string(),
        "192.169.0.0/16".to_string(),
        "192.170.0.0/15".to_string(),
        "192.172.0.0/14".to_string(),
        "192.176.0.0/12".to_string(),
        "192.192.0.0/10".to_string(),
        "193.0.0.0/8".to_string(),
        "194.0.0.0/7".to_string(),
        "196.0.0.0/6".to_string(),
        "200.0.0.0/5".to_string(),
        "208.0.0.0/4".to_string(),
        "224.0.0.0/3".to_string(),
        "2000::/3".to_string(),
    ]
}

fn dst_port_ip_string(ip: &str) -> String {
    parse_ip_net(ip).map_or_else(
        || ip.to_string(),
        |net| {
            if is_single_ip(&net) {
                net.addr().to_string()
            } else {
                net.to_string()
            }
        },
    )
}

fn parse_ip_net(s: &str) -> Option<IpNet> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Some(net);
    }
    let addr = s.parse::<IpAddr>().ok()?;
    IpNet::new(addr, if addr.is_ipv4() { 32 } else { 128 }).ok()
}

fn prefix_contains_addr(prefix: &str, addr: &str) -> bool {
    parse_ip_net(prefix).is_some_and(|net| net_contains_addr(&net, addr))
}

fn ipset_string_contains_addr(ipset: &str, addr: &str) -> bool {
    if prefix_contains_addr(ipset, addr) {
        return true;
    }
    let Some((start, end)) = ipset.split_once('-') else {
        return false;
    };
    match (
        start.trim().parse::<IpAddr>(),
        end.trim().parse::<IpAddr>(),
        addr.parse::<IpAddr>(),
    ) {
        (Ok(IpAddr::V4(start)), Ok(IpAddr::V4(end)), Ok(IpAddr::V4(addr))) => {
            u32::from(start) <= u32::from(addr) && u32::from(addr) <= u32::from(end)
        }
        (Ok(IpAddr::V6(start)), Ok(IpAddr::V6(end)), Ok(IpAddr::V6(addr))) => {
            u128::from(start) <= u128::from(addr) && u128::from(addr) <= u128::from(end)
        }
        _ => false,
    }
}

fn ipset_string_to_cidrs(ipset: &str) -> Vec<String> {
    if let Some(net) = parse_ip_net(ipset) {
        return vec![net.to_string()];
    }
    let Some((start, end)) = ipset.split_once('-') else {
        return Vec::new();
    };
    match (start.trim().parse::<IpAddr>(), end.trim().parse::<IpAddr>()) {
        (Ok(IpAddr::V4(start)), Ok(IpAddr::V4(end))) => {
            cidrs_for_interval(u32::from(start) as u128, u32::from(end) as u128, 32)
        }
        (Ok(IpAddr::V6(start)), Ok(IpAddr::V6(end))) => {
            cidrs_for_interval(u128::from(start), u128::from(end), 128)
        }
        _ => Vec::new(),
    }
}

fn prefixes_overlap(a: &str, b: &str) -> bool {
    match (parse_ip_net(a), parse_ip_net(b)) {
        (Some(a), Some(b)) => nets_overlap(&a, &b),
        _ => false,
    }
}

fn net_contains_addr(net: &IpNet, addr: &str) -> bool {
    let Ok(addr) = addr.parse::<IpAddr>() else {
        return false;
    };
    match (net, addr) {
        (IpNet::V4(v4), IpAddr::V4(addr)) => v4.contains(&addr),
        (IpNet::V6(v6), IpAddr::V6(addr)) => v6.contains(&addr),
        _ => false,
    }
}

fn nets_overlap(a: &IpNet, b: &IpNet) -> bool {
    let (a_bits, a_start, a_end) = ipnet_interval(a);
    let (b_bits, b_start, b_end) = ipnet_interval(b);
    a_bits == b_bits && a_start <= b_end && b_start <= a_end
}

fn is_exit_route(route: &str) -> bool {
    matches!(route, "0.0.0.0/0" | "::/0")
}

fn is_single_ip(net: &IpNet) -> bool {
    match net {
        IpNet::V4(v4) => v4.prefix_len() == 32,
        IpNet::V6(v6) => v6.prefix_len() == 128,
    }
}

fn user_matches(entry: &str, user: &str) -> bool {
    entry == user || entry.strip_suffix('@') == Some(user) || user.strip_suffix('@') == Some(entry)
}

fn tag_matches(node_tag: &str, policy_tag_without_prefix: &str) -> bool {
    node_tag == policy_tag_without_prefix
        || node_tag.strip_prefix("tag:") == Some(policy_tag_without_prefix)
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

fn append_coalesced_filter_rule(out: &mut Vec<FilterRuleOut>, mut rule: FilterRuleOut) {
    normalize_filter_rule(&mut rule);
    if !rule.cap_grant.is_empty() {
        out.push(rule);
        return;
    }
    if let Some(existing) = out.iter_mut().find(|existing| {
        existing.cap_grant.is_empty()
            && existing.src_ips == rule.src_ips
            && existing.ip_proto == rule.ip_proto
    }) {
        existing.dst_ports.extend(rule.dst_ports);
        normalize_filter_rule(existing);
    } else {
        out.push(rule);
    }
}

fn cap_map_sort_key(cap_map: &BTreeMap<String, Option<Vec<Value>>>) -> String {
    serde_json::to_string(cap_map).unwrap_or_default()
}

fn coalesce_filter_rules(rules: Vec<FilterRuleOut>) -> Vec<FilterRuleOut> {
    let mut out = Vec::new();
    for rule in rules {
        append_coalesced_filter_rule(&mut out, rule);
    }
    out
}

fn aggregate_prefixes(values: Vec<String>) -> Vec<String> {
    let mut passthrough = Vec::new();
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    for value in values {
        let Some(net) = parse_ip_net(&value) else {
            push_unique_string(&mut passthrough, value);
            continue;
        };
        match ipnet_interval(&net) {
            (32, start, end) => v4.push((start, end)),
            (128, start, end) => v6.push((start, end)),
            _ => passthrough.push(value),
        }
    }

    let mut out = passthrough;
    out.extend(intervals_to_ipset_strings(v4, 32));
    out.extend(intervals_to_ipset_strings(v6, 128));
    out.sort();
    out.dedup();
    out
}

fn aggregate_prefixes_as_cidrs(values: Vec<String>) -> Vec<String> {
    let mut passthrough = Vec::new();
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();

    for value in values {
        let Some(net) = parse_ip_net(&value) else {
            push_unique_string(&mut passthrough, value);
            continue;
        };
        match ipnet_interval(&net) {
            (32, start, end) => v4.push((start, end)),
            (128, start, end) => v6.push((start, end)),
            _ => passthrough.push(value),
        }
    }

    let mut out = passthrough;
    for (start, end) in merged_intervals(v4) {
        out.extend(cidrs_for_interval(start, end, 32));
    }
    for (start, end) in merged_intervals(v6) {
        out.extend(cidrs_for_interval(start, end, 128));
    }
    out.sort();
    out.dedup();
    out
}

fn ipnet_interval(net: &IpNet) -> (u8, u128, u128) {
    match net {
        IpNet::V4(v4) => {
            let start = u32::from(v4.network()) as u128;
            let host_bits = 32 - v4.prefix_len();
            let size = 1u128 << host_bits;
            (32, start, start + size - 1)
        }
        IpNet::V6(v6) => {
            let start = u128::from(v6.network());
            if v6.prefix_len() == 0 {
                (128, 0, u128::MAX)
            } else {
                let host_bits = 128 - v6.prefix_len();
                let size = 1u128 << host_bits;
                (128, start, start + size - 1)
            }
        }
    }
}

fn intervals_to_ipset_strings(intervals: Vec<(u128, u128)>, bits: u8) -> Vec<String> {
    if intervals.is_empty() {
        return Vec::new();
    }

    let mut out = Vec::new();
    for (start, end) in merged_intervals(intervals) {
        out.push(interval_ipset_string(start, end, bits));
    }
    out
}

fn merged_intervals(mut intervals: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    intervals.sort_by_key(|(start, _)| *start);

    let mut merged: Vec<(u128, u128)> = Vec::new();
    for (start, end) in intervals {
        if let Some((_, last_end)) = merged.last_mut()
            && start <= last_end.saturating_add(1)
        {
            if end > *last_end {
                *last_end = end;
            }
            continue;
        }
        merged.push((start, end));
    }
    merged
}

fn interval_ipset_string(start: u128, end: u128, bits: u8) -> String {
    if start == end {
        return interval_addr_string(start, bits);
    }
    let cidrs = cidrs_for_interval(start, end, bits);
    if cidrs.len() == 1 {
        return cidrs.into_iter().next().unwrap();
    }
    format!(
        "{}-{}",
        interval_addr_string(start, bits),
        interval_addr_string(end, bits)
    )
}

fn cidrs_for_interval(mut start: u128, end: u128, bits: u8) -> Vec<String> {
    if bits == 128 && start == 0 && end == u128::MAX {
        return vec!["::/0".to_string()];
    }
    let mut out = Vec::new();
    while start <= end {
        let mut chosen_prefix = bits;
        for prefix_len in 0..=bits {
            let Some(size) = block_size(bits, prefix_len) else {
                continue;
            };
            if start.is_multiple_of(size) && start.saturating_add(size - 1) <= end {
                chosen_prefix = prefix_len;
                break;
            }
        }
        let size = block_size(bits, chosen_prefix).unwrap_or(1);
        out.push(interval_prefix_string(start, bits, chosen_prefix));
        if end - start < size {
            break;
        }
        start += size;
    }
    out
}

fn block_size(bits: u8, prefix_len: u8) -> Option<u128> {
    let host_bits = bits - prefix_len;
    if host_bits == 128 {
        None
    } else {
        Some(1u128 << host_bits)
    }
}

fn interval_prefix_string(start: u128, bits: u8, prefix_len: u8) -> String {
    let addr = interval_addr(start, bits);
    IpNet::new(addr, prefix_len)
        .expect("valid aggregate prefix")
        .to_string()
}

fn interval_addr_string(value: u128, bits: u8) -> String {
    interval_addr(value, bits).to_string()
}

fn interval_addr(value: u128, bits: u8) -> IpAddr {
    if bits == 32 {
        IpAddr::V4((value as u32).into())
    } else {
        IpAddr::V6(value.into())
    }
}

fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !out.contains(&value) {
        out.push(value);
    }
}

fn normalize_grant_ip_specs(specs: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for spec in specs {
        let trimmed = spec.trim();
        if trimmed == "*" {
            out.push("*/*".to_string());
            continue;
        }
        if trimmed.contains('/') || trimmed.starts_with("*:") {
            out.push(trimmed.to_string());
            continue;
        }
        let (proto, ports) = trimmed
            .split_once(':')
            .map_or(("*", trimmed), |(proto, ports)| {
                (proto.trim(), ports.trim())
            });
        if ports.contains(':') {
            continue;
        }
        for port in ports
            .split(',')
            .map(str::trim)
            .filter(|port| !port.is_empty())
        {
            out.push(format!("{proto}/{port}"));
        }
    }
    out
}

fn compile_port_groups(ports: &[String]) -> Vec<(Vec<i32>, Vec<PortRangeOut>)> {
    if ports.is_empty() {
        return vec![(
            Vec::new(),
            vec![PortRangeOut {
                first: 0,
                last: 65535,
            }],
        )];
    }

    let mut compiled: Vec<(PortRangeOut, Vec<i32>)> = Vec::new();
    for pat in ports {
        let (Some(range), Some(ip_proto)) = (port_pattern_to_range(pat), ip_proto_for_pattern(pat))
        else {
            continue;
        };

        if let Some((_, existing_proto)) = compiled.iter_mut().find(|(existing_range, _)| {
            existing_range.first == range.first && existing_range.last == range.last
        }) {
            merge_ip_proto(existing_proto, &ip_proto);
        } else {
            compiled.push((range, ip_proto));
        }
    }

    let mut groups: Vec<(Vec<i32>, Vec<PortRangeOut>)> = Vec::new();
    for (range, ip_proto) in compiled {
        if let Some((_, ranges)) = groups
            .iter_mut()
            .find(|(existing_proto, _)| *existing_proto == ip_proto)
        {
            ranges.push(range);
        } else {
            groups.push((ip_proto, vec![range]));
        }
    }
    groups
}

fn port_pattern_to_range(pat: &str) -> Option<PortRangeOut> {
    let pat = pat.strip_prefix("*:").unwrap_or(pat);
    let (_proto, port_part) = pat.split_once('/').unwrap_or((pat, "*"));
    if port_part == "*" {
        return Some(PortRangeOut {
            first: 0,
            last: 65535,
        });
    }
    if let Some((lo, hi)) = port_part.split_once('-') {
        let lo: u16 = lo.parse().ok()?;
        let hi: u16 = hi.parse().ok()?;
        if hi < lo {
            return None;
        }
        return Some(PortRangeOut {
            first: lo,
            last: hi,
        });
    }
    let p: u16 = port_part.parse().ok()?;
    Some(PortRangeOut { first: p, last: p })
}

fn ip_proto_for_pattern(pat: &str) -> Option<Vec<i32>> {
    let pat = pat.strip_prefix("*:").unwrap_or(pat);
    let (proto_part, _port_part) = pat.split_once('/').unwrap_or((pat, "*"));
    if proto_part == "*" {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    append_protocol_numbers(proto_part, &mut out)?;
    Some(out)
}

fn append_protocol_numbers(proto: &str, out: &mut Vec<i32>) -> Option<()> {
    let lower = proto.to_ascii_lowercase();
    let nums: &[i32] = match lower.as_str() {
        "" => &[],
        "icmp" => &[1],
        "igmp" => &[2],
        "ipv4" | "ip-in-ip" => &[4],
        "tcp" => &[6],
        "egp" => &[8],
        "igp" => &[9],
        "udp" => &[17],
        "gre" => &[47],
        "esp" => &[50],
        "ah" => &[51],
        "ipv6-icmp" => &[58],
        "sctp" => &[132],
        "fc" => &[133],
        _ => {
            let n: i32 = lower.parse().ok()?;
            if !(1..=255).contains(&n) {
                return None;
            }
            push_unique_i32(out, n);
            return Some(());
        }
    };
    for n in nums {
        push_unique_i32(out, *n);
    }
    Some(())
}

fn merge_ip_proto(existing: &mut Vec<i32>, incoming: &[i32]) {
    if existing.is_empty() || incoming.is_empty() {
        existing.clear();
        return;
    }
    for n in incoming {
        push_unique_i32(existing, *n);
    }
}

fn push_unique_i32(out: &mut Vec<i32>, n: i32) {
    if !out.contains(&n) {
        out.push(n);
    }
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
            addr: viewer.addrs.first().map(String::as_str),
            addrs: &viewer.addrs,
            user: viewer.user.as_deref(),
            tags: &viewer.tags,
        };
        let peer_view = NodeView {
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

fn summarize_register_request(req: RegisterRequest) -> RegisterRequestSummary {
    RegisterRequestSummary {
        version: req.version,
        node_key: req.node_key,
        old_node_key: req.old_node_key,
        nl_key: req.nl_key,
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
