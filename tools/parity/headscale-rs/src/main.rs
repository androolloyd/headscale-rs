use std::{collections::HashMap, env, fs, net::IpAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use headscale_api::{
    policy::{NodeView, PolicyAction, PolicyDoc, parse_hujson_policy},
    tailscale_wire::wire::{
        DerpMap, DnsConfig, HostInfo, MapNode, MapRequest, MapResponse, RegisterRequest,
        RegisterResponse,
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
    route_checks: Vec<RouteCheck>,
    #[serde(default)]
    tag_checks: Vec<TagCheck>,
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
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct FilterNodeCheck {
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
struct TagCheck {
    name: String,
    node_id: u64,
    tag: String,
}

#[derive(Debug, Deserialize)]
struct WireScenario {
    #[serde(default)]
    dns_config: Option<Value>,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    filter_for_nodes: Vec<FilterForNodeOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    route_approvals: Vec<RouteApprovalOut>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tag_checks: Vec<TagCheckOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wire: Option<WireOutput>,
}

#[derive(Debug, Serialize)]
struct FilterForNodeOut {
    name: String,
    rules: Vec<FilterRuleOut>,
}

#[derive(Debug, Serialize)]
struct RouteApprovalOut {
    name: String,
    approved_routes: Vec<String>,
    changed: bool,
}

#[derive(Debug, Serialize)]
struct TagCheckOut {
    name: String,
    allowed: bool,
}

#[derive(Debug, Serialize, Default)]
struct WireOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_config: Option<Value>,
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

#[derive(Debug, Serialize)]
struct RegisterRequestSummary {
    node_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    auth_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostinfo: Option<HostInfoSummary>,
    #[serde(skip_serializing_if = "String::is_empty")]
    followup: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    ephemeral: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    requested_expiry: bool,
}

#[derive(Debug, Serialize)]
struct RegisterResponseSummary {
    user: UserSummary,
    login: LoginSummary,
    node_key_expired: bool,
    auth_url: String,
    machine_authorized: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
}

#[derive(Debug, Serialize)]
struct MapRequestSummary {
    #[serde(skip_serializing_if = "is_zero_u32")]
    version: u32,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    stream: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    compress: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    omit_peers: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    node_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    disco_key: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostinfo: Option<HostInfoSummary>,
}

#[derive(Debug, Serialize)]
struct UserSummary {
    id: u64,
    #[serde(skip_serializing_if = "String::is_empty")]
    display_name: String,
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
}

#[derive(Debug, Serialize)]
struct MapResponseSummary {
    keep_alive: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    node: Option<MapNodeSummary>,
    peer_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    peers: Vec<MapNodeSummary>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    packet_filter: Vec<FilterRuleOut>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns_config: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derp_map: Option<Value>,
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
    #[serde(skip_serializing_if = "String::is_empty")]
    machine: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    disco_key: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    addresses: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    endpoints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostinfo: Option<HostInfoSummary>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    machine_authorized: bool,
}

#[derive(Debug, Serialize)]
struct HostInfoSummary {
    #[serde(skip_serializing_if = "String::is_empty")]
    hostname: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    os: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    os_version: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "PascalCase")]
struct FilterRuleOut {
    #[serde(rename = "SrcIPs")]
    src_ips: Vec<String>,
    dst_ports: Vec<NetPortRangeOut>,
    #[serde(rename = "IPProto", skip_serializing_if = "Vec::is_empty")]
    ip_proto: Vec<i32>,
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
        let doc = parse_hujson_policy(&policy)
            .with_context(|| format!("headscale-rs parsing policy for {}", scenario.name))?;
        let filter_nodes = build_filter_nodes(&scenario);
        out.push(ScenarioOutput {
            engine: "headscale-rs",
            name: scenario.name.clone(),
            filter: compile_filter_rules(&doc, &filter_nodes, None),
            filter_for_nodes: run_filter_node_checks(&scenario, &doc, &filter_nodes)?,
            route_approvals: run_route_checks(&scenario, &doc)?,
            tag_checks: run_tag_checks(&scenario, &doc, &filter_nodes)?,
            wire: normalize_wire(scenario.wire)?,
        });
    }

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

#[derive(Debug)]
struct FilterNode {
    id: u64,
    user: Option<String>,
    addrs: Vec<String>,
    tags: Vec<String>,
}

fn build_filter_nodes(scenario: &Scenario) -> Vec<FilterNode> {
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
            FilterNode {
                id: node.id,
                user: users.get(&node.user_id).cloned(),
                addrs,
                tags: node.tags.clone(),
            }
        })
        .collect()
}

fn run_filter_node_checks(
    scenario: &Scenario,
    doc: &PolicyDoc,
    nodes: &[FilterNode],
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
            rules: compile_filter_rules(doc, nodes, Some(check.node_id)),
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
        out.push(TagCheckOut {
            name: check.name.clone(),
            allowed: node_can_have_tag(doc, node, &check.tag),
        });
    }
    Ok(out)
}

fn compile_filter_rules(
    doc: &PolicyDoc,
    nodes: &[FilterNode],
    node_id: Option<u64>,
) -> Vec<FilterRuleOut> {
    let self_node = node_id.and_then(|id| nodes.iter().find(|node| node.id == id));
    let mut out = Vec::new();

    for rule in &doc.rules {
        if !matches!(rule.action, PolicyAction::Accept) {
            continue;
        }

        let src_ips = resolve_principals(doc, &rule.src, nodes, None);
        if src_ips.is_empty() {
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
                let dst_ips = resolve_principals(doc, &other_dsts, nodes, self_node);
                append_filter_rules(&mut out, &src_ips, &dst_ips, &rule.ports);
            }
        } else {
            let dst_ips = resolve_principals(doc, &rule.dst, nodes, None);
            append_filter_rules(&mut out, &src_ips, &dst_ips, &rule.ports);
        }
    }

    if let Some(node) = self_node {
        reduce_filter_rules_for_node(out, node)
    } else {
        out
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
                    ip: ip.clone(),
                    ports: range.clone(),
                });
            }
        }
        let mut rule = FilterRuleOut {
            src_ips: src_ips.to_vec(),
            dst_ports,
            ip_proto,
        };
        normalize_filter_rule(&mut rule);
        out.push(rule);
    }
}

fn resolve_principals(
    doc: &PolicyDoc,
    tokens: &[String],
    nodes: &[FilterNode],
    self_node: Option<&FilterNode>,
) -> Vec<String> {
    let mut out = Vec::new();
    for token in tokens {
        for value in resolve_principal(doc, token, nodes, self_node) {
            push_unique_string(&mut out, value);
        }
    }
    aggregate_prefixes(out)
}

fn resolve_principal(
    doc: &PolicyDoc,
    token: &str,
    nodes: &[FilterNode],
    self_node: Option<&FilterNode>,
) -> Vec<String> {
    if token == "*" {
        return wildcard_filter_cidrs();
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
            for value in resolve_principal(doc, member, nodes, self_node) {
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
            "internet" => wildcard_filter_cidrs(),
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
            .map(|prefix| resolve_prefix(prefix, nodes, true))
            .unwrap_or_default();
    }
    if let Some(ipset) = token.strip_prefix("ipset:") {
        return doc.ipsets.get(ipset).cloned().unwrap_or_default();
    }
    if let Some(prefix) = doc.hosts.get(token) {
        return resolve_prefix(prefix, nodes, true);
    }
    if parse_ip_net(token).is_some() {
        return resolve_prefix(token, nodes, false);
    }
    Vec::new()
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
                .any(|prefix| prefix_contains_addr(prefix, addr))
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
        let node_matches = node.addrs.iter().any(|addr| {
            net_contains_addr(&net, addr) && (include_nodes_inside || is_single_ip(&net))
        });
        if node_matches {
            for addr in node_addr_prefixes(node) {
                push_unique_string(&mut out, addr);
            }
        }
    }
    aggregate_prefixes(out)
}

fn node_addr_prefixes(node: &FilterNode) -> Vec<String> {
    node.addrs
        .iter()
        .filter_map(|addr| parse_ip_net(addr))
        .map(|net| net.to_string())
        .collect()
}

fn node_can_have_tag(doc: &PolicyDoc, node: &FilterNode, tag: &str) -> bool {
    let Some(owners) = doc.tag_owners.get(tag) else {
        return false;
    };
    owners
        .iter()
        .any(|owner| tag_owner_matches(doc, node, owner))
}

fn tag_owner_matches(doc: &PolicyDoc, node: &FilterNode, owner: &str) -> bool {
    if owner.contains('@') {
        return node
            .user
            .as_deref()
            .is_some_and(|user| user_matches(owner, user));
    }
    if let Some(group) = owner.strip_prefix("group:") {
        let Some(members) = doc.groups.get(owner).or_else(|| doc.groups.get(group)) else {
            return false;
        };
        return members
            .iter()
            .any(|member| tag_owner_matches(doc, node, member));
    }
    if owner.strip_prefix("tag:").is_some() {
        return false;
    }
    false
}

fn reduce_filter_rules_for_node(
    rules: Vec<FilterRuleOut>,
    node: &FilterNode,
) -> Vec<FilterRuleOut> {
    let mut out = Vec::new();
    for mut rule in rules {
        rule.dst_ports.retain(|dst| {
            node.addrs
                .iter()
                .any(|addr| prefix_contains_addr(&dst.ip, addr))
        });
        if rule.dst_ports.is_empty() {
            continue;
        }
        normalize_filter_rule(&mut rule);
        out.push(rule);
    }
    out
}

fn wildcard_filter_cidrs() -> Vec<String> {
    vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
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
    out.extend(intervals_to_cidrs(v4, 32));
    out.extend(intervals_to_cidrs(v6, 128));
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

fn intervals_to_cidrs(mut intervals: Vec<(u128, u128)>, bits: u8) -> Vec<String> {
    if intervals.is_empty() {
        return Vec::new();
    }
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

    let mut out = Vec::new();
    for (mut start, end) in merged {
        if bits == 128 && start == 0 && end == u128::MAX {
            out.push("::/0".to_string());
            continue;
        }
        while start <= end {
            let mut chosen_prefix = bits;
            for prefix_len in 0..=bits {
                let Some(size) = block_size(bits, prefix_len) else {
                    continue;
                };
                if start % size == 0 && start.saturating_add(size - 1) <= end {
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
    let addr = if bits == 32 {
        IpAddr::V4((start as u32).into())
    } else {
        IpAddr::V6(start.into())
    };
    IpNet::new(addr, prefix_len)
        .expect("valid aggregate prefix")
        .to_string()
}

fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !out.contains(&value) {
        out.push(value);
    }
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
        "" => &[6, 17],
        "icmp" => &[1, 58],
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
) -> Result<Vec<RouteApprovalOut>> {
    if scenario.route_checks.is_empty() {
        return Ok(Vec::new());
    }

    let users = scenario
        .users
        .iter()
        .map(|user| (user.id, user))
        .collect::<HashMap<_, _>>();
    let nodes = scenario
        .nodes
        .iter()
        .map(|node| (node.id, node))
        .collect::<HashMap<_, _>>();

    let mut out = Vec::with_capacity(scenario.route_checks.len());
    for check in &scenario.route_checks {
        let node = nodes.get(&check.node_id).with_context(|| {
            format!(
                "route check {} references unknown node {}",
                check.name, check.node_id
            )
        })?;
        let user = users.get(&node.user_id).map(|user| {
            if user.email.is_empty() {
                user.name.as_str()
            } else {
                user.email.as_str()
            }
        });
        let view = NodeView {
            addr: Some(node.ipv4.as_str()),
            user,
            tags: &node.tags,
        };

        let mut approved = normalize_prefixes(&check.current_approved)
            .with_context(|| format!("route check {} current_approved", check.name))?;
        let before = approved.clone();
        for route in normalize_prefixes(&check.announced_routes)
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

fn normalize_prefixes(raw: &[String]) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(raw.len());
    for route in raw {
        let parsed = route
            .parse::<IpNet>()
            .with_context(|| format!("parse prefix {route}"))?;
        out.push(parsed.to_string());
    }
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

fn normalize_wire(wire: Option<WireScenario>) -> Result<Option<WireOutput>> {
    let Some(wire) = wire else {
        return Ok(None);
    };
    let mut out = WireOutput::default();
    if let Some(value) = wire.dns_config {
        let parsed: DnsConfig = serde_json::from_value(value)?;
        out.dns_config = Some(serde_json::to_value(parsed)?);
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
        node_key: req.node_key,
        auth_key: req.auth.map(|auth| auth.auth_key).unwrap_or_default(),
        hostinfo: req.hostinfo.map(summarize_hostinfo),
        followup: req.followup.unwrap_or_default(),
        ephemeral: req.ephemeral,
        requested_expiry: req.expiry.is_some(),
    }
}

fn summarize_register_response(resp: RegisterResponse) -> RegisterResponseSummary {
    RegisterResponseSummary {
        user: UserSummary {
            id: resp.user.id,
            display_name: resp.user.display_name,
        },
        login: LoginSummary {
            id: resp.login.id,
            provider: resp.login.provider,
            login_name: resp.login.login_name,
            display_name: resp.login.display_name,
        },
        node_key_expired: resp.node_key_expired,
        auth_url: resp.auth_url,
        machine_authorized: resp.machine_authorized,
        error: resp.error,
    }
}

fn summarize_map_request(req: MapRequest) -> MapRequestSummary {
    let mut endpoints = req.endpoints.unwrap_or_default();
    endpoints.sort();
    MapRequestSummary {
        version: req.version,
        stream: req.stream,
        compress: req.compress,
        omit_peers: req.omit_peers,
        node_key: req.node_key,
        disco_key: req.disco_key.unwrap_or_default(),
        endpoints,
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
    Ok(MapResponseSummary {
        keep_alive: resp.keep_alive,
        domain: resp.domain,
        node: Some(summarize_map_node(resp.node)),
        peer_count: peers.len(),
        peers,
        packet_filter: resp
            .packet_filter
            .into_iter()
            .map(filter_rule_out)
            .collect(),
        dns_config: Some(serde_json::to_value(resp.dns_config)?),
        derp_map: Some(serde_json::to_value(resp.derp_map)?),
    })
}

fn summarize_map_node(node: MapNode) -> MapNodeSummary {
    let mut addresses = node.addresses;
    addresses.sort();
    let mut allowed_ips = node.allowed_ips;
    allowed_ips.sort();
    let mut endpoints = node.endpoints;
    endpoints.sort();
    MapNodeSummary {
        id: node.id,
        stable_id: node.stable_id,
        name: node.name,
        user: node.user,
        key: node.key,
        machine: node.machine.unwrap_or_default(),
        disco_key: node.disco_key.unwrap_or_default(),
        addresses,
        allowed_ips,
        endpoints,
        hostinfo: Some(summarize_hostinfo(node.hostinfo)),
        machine_authorized: node.machine_authorized,
    }
}

fn summarize_hostinfo(hostinfo: HostInfo) -> HostInfoSummary {
    HostInfoSummary {
        hostname: hostinfo.hostname,
        os: hostinfo.os,
        os_version: hostinfo.os_version,
    }
}

fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}

fn filter_rule_out(rule: headscale_api::tailscale_wire::wire::FilterRule) -> FilterRuleOut {
    FilterRuleOut {
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
    }
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
