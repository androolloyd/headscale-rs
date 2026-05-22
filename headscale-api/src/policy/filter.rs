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
//! Only `accept` rules generate `FilterRule` entries. The Tailscale
//! `filter` matcher treats the list as a deny-by-default allowlist —
//! the canonical ACL engine encodes the same semantics, so the
//! mapping is:
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
//! SrcIP / DstIP token expansion for groups, hosts, ipsets, and the
//! flattenable autogroups (`internet`, `member`). The
//! non-flattenable autogroups (`self`, `nonroot`, `tagged`, `tag:*`)
//! need per-evaluation NodeView context and cannot be expressed in
//! a static `FilterRule.SrcIPs` list — they're silently dropped from
//! this layer and enforced only by the on-host
//! `headscale-api-acl` evaluator.

use std::net::IpAddr;

use ipnet::IpNet;

use super::{PolicyAction, PolicyDoc};
use crate::tailscale_wire::wire::{FilterRule, NetPortRange, PortRange};

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
        let mut src_ips: Vec<String> = Vec::new();
        for token in &rule.src {
            for entry in doc.expand_principal(token) {
                if !src_ips.contains(&entry) {
                    src_ips.push(entry);
                }
            }
        }
        if src_ips.is_empty() {
            continue;
        }

        let mut dst_ips: Vec<String> = Vec::new();
        for token in &rule.dst {
            for entry in doc.expand_principal(token) {
                if !dst_ips.contains(&entry) {
                    dst_ips.push(entry);
                }
            }
        }
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
                        ip: ip.clone(),
                        ports: r.clone(),
                    });
                }
            }

            out.push(FilterRule {
                src_ips: src_ips.clone(),
                dst_ports,
                ip_proto,
            });
        }
    }
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

        let src_ips = resolve_principals(doc, &rule.src, nodes, None);
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
            let dst_ips = resolve_principals(doc, &other_dsts, nodes, Some(self_node));
            append_filter_rules(&mut out, &src_ips, &dst_ips, &rule.ports);
        }
    }

    reduce_filter_rules_for_node(out, self_node)
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
                    ip: ip.clone(),
                    ports: range.clone(),
                });
            }
        }
        let mut rule = FilterRule {
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
    nodes: &[PacketFilterNode],
    self_node: Option<&PacketFilterNode>,
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
    nodes: &[PacketFilterNode],
    self_node: Option<&PacketFilterNode>,
) -> Vec<String> {
    if token == "*" {
        return headscale_api_acl::wildcard_filter_cidrs();
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
            "internet" => headscale_api_acl::wildcard_filter_cidrs(),
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
        rule.dst_ports.retain(|dst| {
            node.addrs
                .iter()
                .any(|addr| prefix_contains_addr(&dst.ip, addr))
                || node
                    .routes
                    .iter()
                    .any(|route| prefixes_overlap(&dst.ip, route))
        });
        if rule.dst_ports.is_empty() {
            continue;
        }
        normalize_filter_rule(&mut rule);
        out.push(rule);
    }
    out
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
            ipsets: BTreeMap::new(),
            auto_approvers: AutoApprovers::default(),
            node_attrs: Vec::new(),
            randomize_client_port: false,
            ssh: Vec::new(),
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
        assert_eq!(rs[0].src_ips, vec!["0.0.0.0/0", "::/0"]);
        assert_eq!(rs[0].dst_ports.len(), 2);
        assert_eq!(rs[0].dst_ports[0].ip, "0.0.0.0/0");
        assert_eq!(rs[0].dst_ports[1].ip, "::/0");
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
        assert_eq!(rs[0].src_ips, vec!["100.64.0.10", "100.64.0.11"]);
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
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].src_ips, vec!["octABC123"]);
        assert_eq!(rs[0].dst_ports[0].ports.first, 0);
        assert_eq!(rs[0].dst_ports[0].ports.last, 65535);
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
                    src: vec!["octA".into()],
                    dst: vec!["octB".into()],
                    ports: vec!["tcp/22".into()],
                },
                PolicyRule {
                    action: PolicyAction::Accept,
                    src: vec!["octC".into()],
                    dst: vec!["octD".into()],
                    ports: vec!["tcp/80".into()],
                },
            ],
            BTreeMap::new(),
        );
        let rs = acl_to_filter_rules(&d);
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].src_ips, vec!["octA"]);
        assert_eq!(rs[1].src_ips, vec!["octC"]);
    }
}
