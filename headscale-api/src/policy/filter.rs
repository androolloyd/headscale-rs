//! [`PolicyDoc`] → `Vec<FilterRule>` translation.
//!
//! Lives in `headscale-api` (not the leaf `headscale-api-acl` crate)
//! because [`FilterRule`] is a Tailscale-wire type owned by the
//! `tailscale_wire` module here. The canonical eval engine in
//! `headscale-api-acl` is wire-agnostic; this layer is the
//! headscale-specific adapter.
//!
//! ## Translation semantics
//!
//! `accept` ACL rules and policy v2 grants generate `FilterRule`
//! entries. The Tailscale `filter` matcher treats the list as a
//! deny-by-default allowlist — the canonical ACL engine encodes the
//! same semantics, so the ACL mapping is:
//!
//! ```text
//! AclAction::Accept { src, dst, ports }
//!   →  FilterRule {
//!         SrcIPs:   expand_principal(src),
//!         DstPorts: [{ IP: dst_i, Ports: { first, last } } for each dst, port],
//!         IPProto:  protocol_numbers(ports)
//!      }
//! ```
//!
//! `deny` rules are dropped. The canonical engine evaluates
//! top-to-bottom and stops at the first match; encoding that into a
//! deny-by-default FilterRule list is a translation we do NOT
//! attempt here. The current contract is "operators write
//! accept-only ACLs; explicit denies are caught by the on-host
//! `headscale-api-acl` evaluator but never reach the Tailscale
//! daemon's packet filter".
//!
//! ## Static-vs-dynamic principal expansion
//!
//! `expand_principal` (on the canonical [`PolicyDoc`]) handles the
//! SrcIP / DstIP token expansion for groups, hosts, and the flattenable
//! autogroups (`internet`, `member`). The
//! non-flattenable autogroups (`self`, `nonroot`, `tagged`, `tag:*`)
//! need per-evaluation NodeView context and cannot be expressed in
//! a static `FilterRule.SrcIPs` list — they're silently dropped from
//! this layer and enforced only by the on-host
//! `headscale-api-acl` evaluator.

use std::{collections::BTreeMap, net::IpAddr};

use ipnet::IpNet;

use super::{CapabilityMap, GrantRule, PolicyAction, PolicyDoc};
use crate::tailscale_wire::wire::{CapGrant, FilterRule, NetPortRange, PortRange};

/// Node facts needed to compile/reduce a headscale-go-style packet
/// filter for one map recipient.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketFilterNode {
    pub id: u64,
    pub user: Option<String>,
    pub addrs: Vec<String>,
    pub tags: Vec<String>,
    pub routes: Vec<String>,
}

pub fn allow_all_filter_rules() -> Vec<FilterRule> {
    vec![FilterRule {
        src_ips: vec!["*".to_string()],
        dst_ports: vec![NetPortRange {
            ip: "*".to_string(),
            ports: PortRange {
                first: 0,
                last: 65535,
            },
            ..NetPortRange::default()
        }],
        ip_proto: Vec::new(),
        ..FilterRule::default()
    }]
}

pub fn raw_policy_omits_packet_filter_rules(raw: &str) -> bool {
    let stripped = headscale_api_acl::strip_hujson(raw);
    let Ok(serde_json::Value::Object(object)) = serde_json::from_str(&stripped) else {
        return false;
    };
    !object.keys().any(|key| {
        matches!(
            key.to_ascii_lowercase().as_str(),
            "acls" | "rules" | "grants"
        )
    })
}

/// Translate a parsed [`PolicyDoc`] into the on-wire
/// `tailcfg.FilterRule` list the stock Tailscale daemon consumes.
///
/// An empty result is significant: it means the policy
/// default-denies everything. The wire layer pins this to an empty
/// `packet_filter` field, which causes the stock daemon to reject
/// every inter-peer packet with `unknown peer` — the intended
/// behaviour for deny-all policies.
pub fn acl_to_filter_rules(doc: &PolicyDoc) -> Vec<FilterRule> {
    let mut out: Vec<FilterRule> = Vec::new();
    for rule in &doc.rules {
        if !matches!(rule.action, PolicyAction::Accept) {
            continue;
        }
        let src_ips = resolve_principals(doc, &rule.src, &[], None, PrincipalPosition::Source);
        if src_ips.is_empty() {
            continue;
        }

        let dst_ips = resolve_principals(doc, &rule.dst, &[], None, PrincipalPosition::Destination);
        if dst_ips.is_empty() {
            continue;
        }

        let port_groups = compile_port_groups(&rule.ports);
        if port_groups.is_empty() {
            continue;
        }

        for (ip_proto, port_ranges) in port_groups {
            let mut dst_ports: Vec<NetPortRange> = Vec::new();
            for ip in &dst_ips {
                for r in &port_ranges {
                    dst_ports.push(NetPortRange {
                        ip: dst_port_ip_string(ip),
                        ports: r.clone(),
                        ..NetPortRange::default()
                    });
                }
            }

            append_coalesced_filter_rule(
                &mut out,
                FilterRule {
                    src_ips: src_ips.clone(),
                    dst_ports,
                    ip_proto,
                    ..FilterRule::default()
                },
            );
        }
    }
    append_app_grant_rules(&mut out, doc, &doc.grants, &[], None);
    out
}

/// Compile the `PacketFilters["base"]` rules for `node_id`.
///
/// Headscale-go does not send the global policy filter verbatim in a
/// map response. It resolves users/tags against the current node set
/// and reduces the result to destinations relevant to the receiving
/// node.
pub fn acl_to_filter_rules_for_node(
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    node_id: u64,
) -> Vec<FilterRule> {
    let Some(self_node) = nodes.iter().find(|node| node.id == node_id) else {
        return Vec::new();
    };
    let mut out = Vec::new();

    for rule in &doc.rules {
        if !matches!(rule.action, PolicyAction::Accept) {
            continue;
        }

        let src_ips = resolve_principals(doc, &rule.src, nodes, None, PrincipalPosition::Source);
        if src_ips.is_empty() {
            continue;
        }

        let mut self_dsts = Vec::new();
        let mut other_dsts = Vec::new();
        for dst in &rule.dst {
            if dst == "autogroup:self" {
                self_dsts.push(dst.clone());
            } else {
                other_dsts.push(dst.clone());
            }
        }

        if !self_dsts.is_empty() && self_node.tags.is_empty() {
            let same_user = same_user_untagged_nodes(nodes, self_node);
            let self_src = nodes_matching_prefixes(&same_user, &src_ips);
            let self_dst = same_user
                .iter()
                .flat_map(|node| node_addr_prefixes(node))
                .collect::<Vec<_>>();
            append_filter_rules(&mut out, &self_src, &self_dst, &rule.ports);
        }

        if !other_dsts.is_empty() {
            let dst_ips = resolve_principals(
                doc,
                &other_dsts,
                nodes,
                Some(self_node),
                PrincipalPosition::Destination,
            );
            append_filter_rules(&mut out, &src_ips, &dst_ips, &rule.ports);
        }
    }

    append_app_grant_rules(&mut out, doc, &doc.grants, nodes, Some(self_node));
    append_via_grant_rules_for_node(&mut out, doc, &doc.grants, nodes, self_node);

    coalesce_filter_rules(reduce_filter_rules_for_node(out, self_node))
}

fn append_app_grant_rules(
    out: &mut Vec<FilterRule>,
    doc: &PolicyDoc,
    grants: &[GrantRule],
    nodes: &[PacketFilterNode],
    self_node: Option<&PacketFilterNode>,
) {
    for grant in grants {
        if grant.app.is_empty() || !grant.via.is_empty() || grant.src.is_empty() {
            continue;
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
            continue;
        };
        if self_dsts.is_empty() || !node.tags.is_empty() {
            continue;
        }

        let same_user = same_user_untagged_nodes(nodes, node);
        let self_src = nodes_matching_prefixes(&same_user, &src_ips);
        if self_src.is_empty() {
            continue;
        }
        let self_dst = same_user
            .iter()
            .flat_map(|node| node_addr_prefixes(node))
            .collect::<Vec<_>>();
        append_cap_grant_rules(out, doc, nodes, &self_src, &self_dst, &grant.app);
    }
}

fn append_cap_grant_rules(
    out: &mut Vec<FilterRule>,
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    src_ips: &[String],
    dsts: &[String],
    app: &CapabilityMap,
) {
    let mut cap_grants = Vec::new();
    let mut dst_ip_strings = Vec::new();
    for dst in dsts {
        let dst_prefixes = resolve_cap_grant_dst(doc, dst, nodes);
        if !dst_prefixes.is_empty() {
            for prefix in &dst_prefixes {
                if let Some(net) = parse_ip_net(prefix) {
                    push_unique_string(&mut dst_ip_strings, net.addr().to_string());
                }
            }
            cap_grants.push(CapGrant {
                dsts: dst_prefixes,
                cap_map: wire_cap_map(app),
                ..CapGrant::default()
            });
        }
    }

    if cap_grants.is_empty() {
        return;
    }

    let mut rule = FilterRule {
        src_ips: src_ips.to_vec(),
        cap_grant: cap_grants,
        ..FilterRule::default()
    };
    normalize_filter_rule(&mut rule);
    append_coalesced_filter_rule(out, rule);

    append_companion_cap_grant_rules(out, &dst_ip_strings, src_ips, app);
}

fn wire_cap_map(app: &CapabilityMap) -> BTreeMap<String, Option<Vec<serde_json::Value>>> {
    app.iter()
        .map(|(cap, values)| (cap.clone(), Some(values.clone())))
        .collect()
}

fn companion_cap_map(cap: &str) -> BTreeMap<String, Option<Vec<serde_json::Value>>> {
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
    out: &mut Vec<FilterRule>,
    dst_ip_strings: &[String],
    src_ips: &[String],
    app: &CapabilityMap,
) {
    let mut src_prefixes = src_ips
        .iter()
        .filter_map(|src| parse_ip_net(src).map(|net| net.to_string()))
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
        let mut rule = FilterRule {
            src_ips: dst_ip_strings.to_vec(),
            cap_grant: vec![CapGrant {
                dsts: src_prefixes.clone(),
                cap_map: companion_cap_map(cap),
                ..CapGrant::default()
            }],
            ..FilterRule::default()
        };
        normalize_filter_rule(&mut rule);
        append_coalesced_filter_rule(out, rule);
    }
}

fn append_via_grant_rules_for_node(
    out: &mut Vec<FilterRule>,
    doc: &PolicyDoc,
    grants: &[GrantRule],
    nodes: &[PacketFilterNode],
    self_node: &PacketFilterNode,
) {
    for grant in grants {
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
    out: &mut Vec<FilterRule>,
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
                dst_ports.push(NetPortRange {
                    ip: dst_port_ip_string(ip),
                    ports: range.clone(),
                    ..NetPortRange::default()
                });
            }
        }
        let mut rule = FilterRule {
            src_ips: src_ips.to_vec(),
            dst_ports,
            ip_proto,
            ..FilterRule::default()
        };
        normalize_filter_rule(&mut rule);
        append_coalesced_filter_rule(out, rule);
    }
}

fn resolve_principals(
    doc: &PolicyDoc,
    tokens: &[String],
    nodes: &[PacketFilterNode],
    self_node: Option<&PacketFilterNode>,
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
    nodes: &[PacketFilterNode],
    self_node: Option<&PacketFilterNode>,
    position: PrincipalPosition,
) -> Vec<String> {
    if token == "*" {
        return match position {
            PrincipalPosition::Source => headscale_api_acl::tailnet_filter_srcs(),
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
            "internet" => headscale_api_acl::internet_filter_cidrs(),
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

fn resolve_cap_grant_dst(doc: &PolicyDoc, token: &str, nodes: &[PacketFilterNode]) -> Vec<String> {
    if token == "*" {
        return headscale_api_acl::tailnet_filter_srcs()
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
    resolve_principal(doc, token, nodes, None, PrincipalPosition::Destination)
}

fn resolve_via_destinations_for_node(
    doc: &PolicyDoc,
    dsts: &[String],
    nodes: &[PacketFilterNode],
    node: &PacketFilterNode,
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
                for prefix in headscale_api_acl::internet_filter_cidrs() {
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

fn same_user_untagged_nodes<'a>(
    nodes: &'a [PacketFilterNode],
    node: &PacketFilterNode,
) -> Vec<&'a PacketFilterNode> {
    nodes
        .iter()
        .filter(|candidate| candidate.tags.is_empty())
        .filter(|candidate| candidate.user == node.user)
        .collect()
}

fn nodes_matching_prefixes(nodes: &[&PacketFilterNode], prefixes: &[String]) -> Vec<String> {
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

fn resolve_prefix(
    prefix: &str,
    nodes: &[PacketFilterNode],
    include_nodes_inside: bool,
) -> Vec<String> {
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

fn approved_subnet_routes(nodes: &[PacketFilterNode]) -> Vec<String> {
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

fn node_addr_prefixes(node: &PacketFilterNode) -> Vec<String> {
    node.addrs
        .iter()
        .filter_map(|addr| parse_ip_net(addr))
        .map(|net| net.to_string())
        .collect()
}

fn reduce_filter_rules_for_node(
    rules: Vec<FilterRule>,
    node: &PacketFilterNode,
) -> Vec<FilterRule> {
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
                    && headscale_api_acl::internet_filter_cidrs()
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
    rule: &FilterRule,
    node: &PacketFilterNode,
) -> Option<FilterRule> {
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
                    && let Some(prefix) = addr_prefix_string(addr)
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
            cap_grant.push(CapGrant {
                dsts,
                caps: grant.caps.clone(),
                cap_map: grant.cap_map.clone(),
            });
        }
    }

    if cap_grant.is_empty() {
        return None;
    }

    let mut out = FilterRule {
        src_ips: rule.src_ips.clone(),
        cap_grant,
        ..FilterRule::default()
    };
    normalize_filter_rule(&mut out);
    Some(out)
}

fn addr_prefix_string(addr: &str) -> Option<String> {
    let addr = addr.parse::<IpAddr>().ok()?;
    IpNet::new(addr, if addr.is_ipv4() { 32 } else { 128 })
        .ok()
        .map(|net| net.to_string())
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

fn is_exit_route(route: &str) -> bool {
    matches!(route, "0.0.0.0/0" | "::/0")
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

fn normalize_filter_rule(rule: &mut FilterRule) {
    rule.src_ips.sort();
    rule.src_ips.dedup();
    rule.dst_ports.sort_by(|a, b| {
        a.ip.cmp(&b.ip)
            .then(a.ports.first.cmp(&b.ports.first))
            .then(a.ports.last.cmp(&b.ports.last))
    });
    rule.ip_proto.sort_unstable();
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

fn append_coalesced_filter_rule(out: &mut Vec<FilterRule>, mut rule: FilterRule) {
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

fn cap_map_sort_key(cap_map: &BTreeMap<String, Option<Vec<serde_json::Value>>>) -> String {
    serde_json::to_string(cap_map).unwrap_or_default()
}

fn coalesce_filter_rules(rules: Vec<FilterRule>) -> Vec<FilterRule> {
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

/// Map an ACL port pattern (`tcp/22`, `udp/*`, `*/*`, or the legacy
/// `*:tcp/22`) onto a Tailscale `PortRange`.
///
/// Returns `None` for syntactically invalid patterns — the caller
/// drops the entry, keeping the policy strictly less permissive
/// than the operator intended (default-deny on garbage).
fn port_pattern_to_range(pat: &str) -> Option<PortRange> {
    let pat = pat.strip_prefix("*:").unwrap_or(pat);
    let (_proto, port_part) = pat.split_once('/').unwrap_or((pat, "*"));
    if port_part == "*" {
        return Some(PortRange {
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
        return Some(PortRange {
            first: lo,
            last: hi,
        });
    }
    let p: u16 = port_part.parse().ok()?;
    Some(PortRange { first: p, last: p })
}

fn compile_port_groups(ports: &[String]) -> Vec<(Vec<i32>, Vec<PortRange>)> {
    if ports.is_empty() {
        return vec![(
            Vec::new(),
            vec![PortRange {
                first: 0,
                last: 65535,
            }],
        )];
    }

    let mut compiled: Vec<(PortRange, Vec<i32>)> = Vec::new();
    for pat in ports {
        let (Some(range), Some(ip_proto)) = (port_pattern_to_range(pat), ip_proto_for_pattern(pat))
        else {
            continue;
        };

        if let Some((_, existing_proto)) = compiled
            .iter_mut()
            .find(|(existing_range, _)| same_port_range(existing_range, &range))
        {
            merge_ip_proto(existing_proto, &ip_proto);
        } else {
            compiled.push((range, ip_proto));
        }
    }

    let mut groups: Vec<(Vec<i32>, Vec<PortRange>)> = Vec::new();
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

fn same_port_range(a: &PortRange, b: &PortRange) -> bool {
    a.first == b.first && a.last == b.last
}

fn merge_ip_proto(existing: &mut Vec<i32>, incoming: &[i32]) {
    if existing.is_empty() || incoming.is_empty() {
        existing.clear();
        return;
    }
    for n in incoming {
        push_unique(existing, *n);
    }
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
            push_unique(out, n);
            return Some(());
        }
    };
    for n in nums {
        push_unique(out, *n);
    }
    Some(())
}

fn push_unique(out: &mut Vec<i32>, n: i32) {
    if !out.contains(&n) {
        out.push(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AutoApprovers, PolicyAction, PolicyDoc, PolicyRule};
    use std::collections::BTreeMap;

    fn doc(rules: Vec<PolicyRule>, groups: BTreeMap<String, Vec<String>>) -> PolicyDoc {
        PolicyDoc {
            version: 1,
            groups,
            tags: BTreeMap::new(),
            tag_owners: BTreeMap::new(),
            hosts: BTreeMap::new(),
            auto_approvers: AutoApprovers::default(),
            node_attrs: Vec::new(),
            grants: Vec::new(),
            randomize_client_port: false,
            ssh: Vec::new(),
            tests: Vec::new(),
            ssh_tests: Vec::new(),
            rules,
        }
    }

    #[test]
    fn allow_all_emits_wildcard_rule() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["*/*".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].src_ips, headscale_api_acl::tailnet_filter_srcs());
        assert_eq!(rs[0].dst_ports.len(), 1);
        assert_eq!(rs[0].dst_ports[0].ip, "*");
        assert_eq!(rs[0].dst_ports[0].ports.first, 0);
        assert_eq!(rs[0].dst_ports[0].ports.last, 65535);
        assert!(rs[0].ip_proto.is_empty());
    }

    #[test]
    fn tcp_udp_ports_emit_headscale_go_default_ip_proto() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["100.64.0.1/32".into()],
                dst: vec!["100.64.0.2/32".into()],
                ports: vec!["tcp/22".into(), "udp/22".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].dst_ports.len(), 1);
        assert_eq!(rs[0].ip_proto, vec![6, 17]);
    }

    #[test]
    fn mixed_protocol_ports_do_not_cross_apply() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["100.64.0.1/32".into()],
                dst: vec!["100.64.0.2/32".into()],
                ports: vec!["tcp/22".into(), "udp/53".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].ip_proto, vec![6]);
        assert_eq!(rs[0].dst_ports[0].ports.first, 22);
        assert_eq!(rs[1].ip_proto, vec![17]);
        assert_eq!(rs[1].dst_ports[0].ports.first, 53);
    }

    #[test]
    fn deny_all_emits_empty_list() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Deny,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["*/*".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert!(rs.is_empty(), "deny rules do not emit FilterRule entries");
    }

    #[test]
    fn src_by_tag_expands_via_group() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "admins".to_string(),
            vec!["100.64.0.10".to_string(), "100.64.0.11".to_string()],
        );
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["group:admins".into()],
                dst: vec!["*".into()],
                ports: vec!["tcp/22".into()],
            }],
            groups,
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].src_ips, vec!["100.64.0.10/31"]);
        assert_eq!(rs[0].dst_ports[0].ports.first, 22);
        assert_eq!(rs[0].dst_ports[0].ports.last, 22);
    }

    #[test]
    fn dst_by_port_range_emits_range_ports() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["tcp/8000-9000".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].dst_ports[0].ports.first, 8000);
        assert_eq!(rs[0].dst_ports[0].ports.last, 9000);
    }

    #[test]
    fn dst_by_cidr_round_trips_literal_string() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["*".into()],
                dst: vec!["100.64.0.0/10".into()],
                ports: vec!["tcp/443".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].dst_ports[0].ip, "100.64.0.0/10");
    }

    #[test]
    fn src_by_user_passes_through_literal() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["octABC123".into()],
                dst: vec!["*".into()],
                ports: vec![],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert!(rs.is_empty());
    }

    #[test]
    fn unknown_group_drops_rule() {
        let d = doc(
            vec![PolicyRule {
                action: PolicyAction::Accept,
                src: vec!["group:not_defined".into()],
                dst: vec!["*".into()],
                ports: vec!["*/*".into()],
            }],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert!(rs.is_empty());
    }

    #[test]
    fn multi_rule_preserves_order() {
        let d = doc(
            vec![
                PolicyRule {
                    action: PolicyAction::Accept,
                    src: vec!["100.64.0.1".into()],
                    dst: vec!["100.64.0.2".into()],
                    ports: vec!["tcp/22".into()],
                },
                PolicyRule {
                    action: PolicyAction::Accept,
                    src: vec!["100.64.0.3".into()],
                    dst: vec!["100.64.0.4".into()],
                    ports: vec!["tcp/80".into()],
                },
            ],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].src_ips, vec!["100.64.0.1"]);
        assert_eq!(rs[1].src_ips, vec!["100.64.0.3"]);
    }

    #[test]
    fn app_grant_emits_reduced_cap_grant_for_destination_node() {
        let d = crate::policy::parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:server": ["ops@"]},
                "grants": [{
                    "src": ["client@"],
                    "dst": ["tag:server"],
                    "app": {"example.com/cap/use": [{"mode":"rw"}]}
                }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            PacketFilterNode {
                id: 1,
                user: Some("client".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
            PacketFilterNode {
                id: 2,
                user: Some("ops".into()),
                addrs: vec!["100.64.0.2".into()],
                tags: vec!["tag:server".into()],
                routes: Vec::new(),
            },
        ];

        let rs = acl_to_filter_rules_for_node(&d, &nodes, 2);
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].src_ips, vec!["100.64.0.1"]);
        assert!(rs[0].dst_ports.is_empty());
        assert_eq!(rs[0].cap_grant.len(), 1);
        assert_eq!(rs[0].cap_grant[0].dsts, vec!["100.64.0.2/32"]);
        assert!(
            rs[0].cap_grant[0]
                .cap_map
                .contains_key("example.com/cap/use")
        );
    }

    #[test]
    fn app_grant_emits_upstream_companion_cap_grants() {
        let d = crate::policy::parse_hujson_policy(
            r#"{
                "grants": [{
                    "src": ["client@"],
                    "dst": ["server@"],
                    "app": {
                        "tailscale.com/cap/drive": [{}],
                        "tailscale.com/cap/relay": []
                    }
                }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            PacketFilterNode {
                id: 1,
                user: Some("client".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
            PacketFilterNode {
                id: 2,
                user: Some("server".into()),
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
        ];

        let server_rules = acl_to_filter_rules_for_node(&d, &nodes, 2);
        assert_eq!(server_rules.len(), 1);
        assert!(
            server_rules[0].cap_grant[0]
                .cap_map
                .contains_key("tailscale.com/cap/drive")
        );
        assert!(
            server_rules[0].cap_grant[0]
                .cap_map
                .contains_key("tailscale.com/cap/relay")
        );

        let client_rules = acl_to_filter_rules_for_node(&d, &nodes, 1);
        let companion_caps = client_rules
            .iter()
            .flat_map(|rule| &rule.cap_grant)
            .flat_map(|grant| grant.cap_map.keys())
            .cloned()
            .collect::<Vec<_>>();
        assert!(companion_caps.contains(&"tailscale.com/cap/drive-sharer".to_string()));
        assert!(companion_caps.contains(&"tailscale.com/cap/relay-target".to_string()));
        assert!(
            client_rules
                .iter()
                .flat_map(|rule| &rule.cap_grant)
                .all(|grant| grant.cap_map.values().all(Option::is_none))
        );
    }

    #[test]
    fn via_grant_emits_per_node_route_filter_for_matching_router() {
        let d = crate::policy::parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:router": ["router@"]},
                "grants": [{
                    "src": ["client@"],
                    "dst": ["10.10.0.0/16"],
                    "ip": ["tcp:443"],
                    "via": ["tag:router"]
                }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            PacketFilterNode {
                id: 1,
                user: Some("client".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
                routes: Vec::new(),
            },
            PacketFilterNode {
                id: 2,
                user: Some("router".into()),
                addrs: vec!["100.64.0.2".into()],
                tags: vec!["tag:router".into()],
                routes: vec!["10.10.1.0/24".into()],
            },
        ];

        let router_rules = acl_to_filter_rules_for_node(&d, &nodes, 2);
        assert_eq!(router_rules.len(), 1);
        assert_eq!(router_rules[0].src_ips, vec!["100.64.0.1"]);
        assert_eq!(router_rules[0].ip_proto, vec![6]);
        assert_eq!(router_rules[0].dst_ports[0].ip, "10.10.0.0/16");
        assert_eq!(router_rules[0].dst_ports[0].ports.first, 443);

        let client_rules = acl_to_filter_rules_for_node(&d, &nodes, 1);
        assert!(client_rules.is_empty());
    }
}
