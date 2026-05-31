//! Semantic evaluation for upstream policy `tests`.
//!
//! Parsing and shape validation live in `headscale-api-acl`. This
//! module owns the live-node pass used by gRPC `CheckPolicy` and
//! `SetPolicy`.

use std::collections::BTreeSet;
use std::net::IpAddr;

use headscale_api_acl::{
    AclAction, AclDoc as PolicyDoc, NodeView, PolicyTest, PortRef, SshPolicyTest, parse_cidr,
};
use ipnet::IpNet;

/// Live node facts needed to evaluate policy tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCheckNode {
    pub id: u64,
    pub name: String,
    pub user: Option<String>,
    pub addrs: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug)]
struct Endpoint {
    id: Option<u64>,
    label: String,
    addr: String,
    user: Option<String>,
    tags: Vec<String>,
}

impl Endpoint {
    fn view(&self) -> NodeView<'_> {
        let view = NodeView::new(&self.addr).with_tags(&self.tags);
        if let Some(user) = self.user.as_deref() {
            view.with_user(user)
        } else {
            view
        }
    }
}

/// Evaluate all currently supported policy semantic checks.
pub fn check_policy_semantics(doc: &PolicyDoc, nodes: &[PolicyCheckNode]) -> Result<(), String> {
    let mut errors = Vec::new();
    errors.extend(run_policy_tests(doc, nodes));
    errors.extend(run_ssh_policy_tests(doc, nodes));

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!("policy test(s) failed:\n{}", errors.join("\n")))
    }
}

fn run_policy_tests(doc: &PolicyDoc, nodes: &[PolicyCheckNode]) -> Vec<String> {
    let mut errors = Vec::new();
    for (index, test) in doc.tests.iter().enumerate() {
        errors.extend(run_policy_test(index, test, doc, nodes));
    }
    errors
}

fn run_policy_test(
    index: usize,
    test: &PolicyTest,
    doc: &PolicyDoc,
    nodes: &[PolicyCheckNode],
) -> Vec<String> {
    let mut errors = Vec::new();
    let srcs = resolve_alias(doc, nodes, &test.src, None);
    if srcs.is_empty() {
        return vec![format!(
            "test {index}: source {:?} resolved to no live node addresses",
            test.src
        )];
    }

    for dst in &test.accept {
        match test_allows(doc, nodes, test, &srcs, dst) {
            Ok(true) => {}
            Ok(false) => errors.push(format!(
                "test {index}: source {:?} cannot reach accept destination {dst:?}",
                test.src
            )),
            Err(err) => errors.push(format!("test {index}: destination {dst:?}: {err}")),
        }
    }

    for dst in &test.deny {
        match test_allows(doc, nodes, test, &srcs, dst) {
            Ok(false) => {}
            Ok(true) => errors.push(format!(
                "test {index}: source {:?} can reach deny destination {dst:?}",
                test.src
            )),
            Err(err) => errors.push(format!("test {index}: destination {dst:?}: {err}")),
        }
    }

    errors
}

fn run_ssh_policy_tests(doc: &PolicyDoc, nodes: &[PolicyCheckNode]) -> Vec<String> {
    let mut errors = Vec::new();
    for (index, test) in doc.ssh_tests.iter().enumerate() {
        errors.extend(run_ssh_policy_test(index, test, doc, nodes));
    }
    errors
}

fn run_ssh_policy_test(
    index: usize,
    test: &SshPolicyTest,
    doc: &PolicyDoc,
    nodes: &[PolicyCheckNode],
) -> Vec<String> {
    let mut errors = Vec::new();
    let srcs = resolve_alias(doc, nodes, &test.src, None);
    if srcs.is_empty() {
        return vec![format!(
            "sshTest {index}: source {:?} resolved to no live node addresses",
            test.src
        )];
    }
    if test.accept.is_empty() && test.deny.is_empty() && test.check.is_empty() {
        errors.push(format!(
            "sshTest {index}: no accept, deny, or check assertions specified"
        ));
    }

    let mut dst_nodes = Vec::new();
    for dst in &test.dst {
        let resolved = resolve_ssh_test_dst_nodes(doc, nodes, test, &srcs, dst);
        if resolved.is_empty() {
            errors.push(format!(
                "sshTest {index}: dst alias {dst:?} resolved to no live nodes"
            ));
            continue;
        }
        for node in resolved {
            if !dst_nodes
                .iter()
                .any(|existing: &&PolicyCheckNode| existing.id == node.id)
            {
                dst_nodes.push(node);
            }
        }
    }

    for user in &test.accept {
        for dst in &dst_nodes {
            if !srcs
                .iter()
                .all(|src| ssh_reachability(doc, nodes, src, dst, user).0)
            {
                errors.push(format!(
                    "sshTest {index}: source {:?} cannot SSH to destination {:?} as accepted user {:?}",
                    test.src, dst.name, user
                ));
            }
        }
    }

    for user in &test.deny {
        for dst in &dst_nodes {
            if srcs
                .iter()
                .any(|src| ssh_reachability(doc, nodes, src, dst, user).0)
            {
                errors.push(format!(
                    "sshTest {index}: source {:?} can SSH to destination {:?} as denied user {:?}",
                    test.src, dst.name, user
                ));
            }
        }
    }

    for user in &test.check {
        for dst in &dst_nodes {
            if !srcs
                .iter()
                .all(|src| ssh_reachability(doc, nodes, src, dst, user).1)
            {
                let accept_only = srcs
                    .iter()
                    .all(|src| ssh_reachability(doc, nodes, src, dst, user).0);
                let reason = if accept_only {
                    "allowed by accept but not check"
                } else {
                    "not allowed by check"
                };
                errors.push(format!(
                    "sshTest {index}: source {:?} cannot SSH-check destination {:?} as user {:?}: {reason}",
                    test.src, dst.name, user
                ));
            }
        }
    }

    errors
}

fn test_allows(
    doc: &PolicyDoc,
    nodes: &[PolicyCheckNode],
    test: &PolicyTest,
    srcs: &[Endpoint],
    dst: &str,
) -> Result<bool, String> {
    let (alias, port) = split_test_destination(dst)?;
    let port = parse_test_port(port)?;
    let protos = test_protocols(&test.proto);

    for src in srcs {
        let dsts = resolve_alias(doc, nodes, alias, None);
        if dsts.is_empty() {
            return Err(format!("alias {alias:?} resolved to no addresses"));
        }
        let src_view = src.view();
        let src_allowed = dsts.iter().any(|dst| {
            let dst_view = dst.view();
            protos.iter().any(|proto| {
                doc.evaluate_with(&src_view, &dst_view, PortRef::new(proto, port))
                    == AclAction::Accept
            })
        });
        if !src_allowed {
            return Ok(false);
        }
    }

    Ok(true)
}

fn resolve_ssh_test_dst_nodes<'a>(
    doc: &PolicyDoc,
    nodes: &'a [PolicyCheckNode],
    test: &SshPolicyTest,
    srcs: &[Endpoint],
    dst: &str,
) -> Vec<&'a PolicyCheckNode> {
    if dst == "autogroup:self" && !test.src.contains('@') {
        return Vec::new();
    }
    let src = srcs.first();
    let endpoints = resolve_alias(doc, nodes, dst, src);
    let mut out = Vec::new();
    for endpoint in endpoints {
        for node in nodes
            .iter()
            .filter(|node| endpoint_matches_node(&endpoint, node))
        {
            if !out
                .iter()
                .any(|existing: &&PolicyCheckNode| existing.id == node.id)
            {
                out.push(node);
            }
        }
    }
    out
}

fn ssh_reachability(
    doc: &PolicyDoc,
    nodes: &[PolicyCheckNode],
    src: &Endpoint,
    dst: &PolicyCheckNode,
    user: &str,
) -> (bool, bool) {
    if user.is_empty() {
        return (false, false);
    }

    let mut accept = false;
    let mut check = false;
    for rule in &doc.ssh {
        if !rule
            .src
            .iter()
            .any(|token| ssh_source_matches(doc, nodes, token, src))
        {
            continue;
        }
        if !rule
            .dst
            .iter()
            .any(|token| ssh_destination_matches(doc, nodes, token, src, dst))
        {
            continue;
        }
        if !ssh_users_allow(&rule.users, user, src.user.as_deref()) {
            continue;
        }

        accept = true;
        if rule.action == "check" {
            check = true;
        }
        if accept && check {
            break;
        }
    }
    (accept, check)
}

fn ssh_source_matches(
    doc: &PolicyDoc,
    nodes: &[PolicyCheckNode],
    token: &str,
    src: &Endpoint,
) -> bool {
    resolve_alias(doc, nodes, token, None)
        .iter()
        .any(|candidate| endpoint_matches_endpoint(candidate, src))
}

fn ssh_destination_matches(
    doc: &PolicyDoc,
    nodes: &[PolicyCheckNode],
    token: &str,
    src: &Endpoint,
    dst: &PolicyCheckNode,
) -> bool {
    resolve_alias(doc, nodes, token, Some(src))
        .iter()
        .any(|candidate| endpoint_matches_node(candidate, dst))
}

fn ssh_users_allow(users: &[String], user: &str, src_user: Option<&str>) -> bool {
    if user.is_empty() {
        return false;
    }
    for candidate in users {
        if let Some(domain) = canonical_localpart_domain(candidate) {
            let Some(src_user) = src_user else {
                continue;
            };
            if localpart_for_user(src_user, domain).as_deref() == Some(user) {
                return true;
            }
            continue;
        }
        if candidate == user {
            return true;
        }
    }
    if users.iter().any(|candidate| candidate == "*") {
        return true;
    }
    if user != "root"
        && users
            .iter()
            .any(|candidate| candidate == "autogroup:nonroot")
    {
        return true;
    }
    false
}

fn canonical_localpart_domain(user: &str) -> Option<&str> {
    let pattern = user.strip_prefix("localpart:")?;
    let (localpart, domain) = pattern.rsplit_once('@')?;
    if localpart == "*" && !domain.is_empty() {
        Some(domain)
    } else {
        None
    }
}

fn localpart_for_user(user: &str, domain: &str) -> Option<String> {
    let (localpart, candidate_domain) = user.rsplit_once('@')?;
    if candidate_domain.eq_ignore_ascii_case(domain) {
        Some(localpart.to_string())
    } else {
        None
    }
}

fn endpoint_matches_endpoint(candidate: &Endpoint, expected: &Endpoint) -> bool {
    if candidate.id.is_some() && candidate.id == expected.id {
        return true;
    }
    candidate.addr == expected.addr
}

fn endpoint_matches_node(candidate: &Endpoint, node: &PolicyCheckNode) -> bool {
    if candidate.id == Some(node.id) {
        return true;
    }
    node.addrs.iter().any(|addr| addr == &candidate.addr)
}

fn test_protocols(proto: &str) -> Vec<&'static str> {
    match proto.trim().to_ascii_lowercase().as_str() {
        "tcp" => vec!["tcp"],
        "udp" => vec!["udp"],
        "sctp" => vec!["sctp"],
        "" => vec!["tcp", "udp", "icmp", "ipv6-icmp"],
        _ => Vec::new(),
    }
}

fn resolve_alias(
    doc: &PolicyDoc,
    nodes: &[PolicyCheckNode],
    token: &str,
    src: Option<&Endpoint>,
) -> Vec<Endpoint> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    resolve_alias_inner(doc, nodes, token.trim(), src, &mut seen, &mut out);
    out.sort_by(|a, b| a.label.cmp(&b.label).then(a.addr.cmp(&b.addr)));
    out.dedup_by(|a, b| a.addr == b.addr && a.user == b.user && a.tags == b.tags);
    out
}

fn resolve_alias_inner(
    doc: &PolicyDoc,
    nodes: &[PolicyCheckNode],
    token: &str,
    src: Option<&Endpoint>,
    seen_groups: &mut BTreeSet<String>,
    out: &mut Vec<Endpoint>,
) {
    if token == "*" {
        push_all_node_addrs(nodes, out);
        return;
    }
    if token.contains('@') {
        for node in nodes.iter().filter(|node| {
            is_untagged_user_owned(node)
                && node
                    .user
                    .as_deref()
                    .is_some_and(|user| user_matches(token, user))
        }) {
            push_node_addrs(node, out);
        }
        return;
    }
    if let Some(group) = token.strip_prefix("group:") {
        if !seen_groups.insert(token.to_string()) {
            return;
        }
        if let Some(members) = doc.groups.get(token).or_else(|| doc.groups.get(group)) {
            for member in members {
                resolve_alias_inner(doc, nodes, member, src, seen_groups, out);
            }
        }
        seen_groups.remove(token);
        return;
    }
    if let Some(tag) = token.strip_prefix("tag:") {
        for node in nodes
            .iter()
            .filter(|node| node.tags.iter().any(|node_tag| tag_matches(node_tag, tag)))
        {
            push_node_addrs(node, out);
        }
        return;
    }
    if let Some(kind) = token.strip_prefix("autogroup:") {
        match kind {
            "member" => {
                for node in nodes.iter().filter(|node| is_untagged_user_owned(node)) {
                    push_node_addrs(node, out);
                }
            }
            "tagged" => {
                for node in nodes.iter().filter(|node| !node.tags.is_empty()) {
                    push_node_addrs(node, out);
                }
            }
            "self" => {
                if let Some(src) = src {
                    for node in nodes.iter().filter(|node| {
                        node.tags.is_empty()
                            && src.tags.is_empty()
                            && node.user.as_deref().is_some_and(|user| !user.is_empty())
                            && src.user.as_deref().is_some_and(|user| !user.is_empty())
                            && node.user.as_deref() == src.user.as_deref()
                    }) {
                        push_node_addrs(node, out);
                    }
                }
            }
            _ => {}
        }
        return;
    }
    if let Some(host) = token.strip_prefix("host:") {
        resolve_host_or_prefix(doc, nodes, token, host, out);
        return;
    }
    resolve_host_or_prefix(doc, nodes, token, token, out);
}

fn resolve_host_or_prefix(
    doc: &PolicyDoc,
    nodes: &[PolicyCheckNode],
    label: &str,
    host_or_prefix: &str,
    out: &mut Vec<Endpoint>,
) {
    if let Some(prefix) = doc.hosts.get(host_or_prefix) {
        resolve_prefix(nodes, prefix, out);
        if !contains_label(out, label) {
            push_synthetic_prefix(label, prefix, out);
        }
        return;
    }
    if parse_cidr(host_or_prefix).is_some() {
        resolve_prefix(nodes, host_or_prefix, out);
        if !contains_label(out, label) {
            push_synthetic_prefix(label, host_or_prefix, out);
        }
    }
}

fn resolve_prefix(nodes: &[PolicyCheckNode], prefix: &str, out: &mut Vec<Endpoint>) {
    let Some(net) = parse_cidr(prefix) else {
        return;
    };
    for node in nodes {
        if node.addrs.iter().any(|addr| net_contains_addr(&net, addr)) {
            push_node_addrs(node, out);
        }
    }
}

fn push_all_node_addrs(nodes: &[PolicyCheckNode], out: &mut Vec<Endpoint>) {
    for node in nodes {
        push_node_addrs(node, out);
    }
}

fn push_node_addrs(node: &PolicyCheckNode, out: &mut Vec<Endpoint>) {
    for addr in &node.addrs {
        out.push(Endpoint {
            id: Some(node.id),
            label: node.name.clone(),
            addr: addr.clone(),
            user: node.user.clone(),
            tags: node.tags.clone(),
        });
    }
}

fn push_synthetic_prefix(label: &str, prefix: &str, out: &mut Vec<Endpoint>) {
    let Some(net) = parse_cidr(prefix) else {
        return;
    };
    out.push(Endpoint {
        id: None,
        label: label.to_string(),
        addr: net.addr().to_string(),
        user: None,
        tags: Vec::new(),
    });
}

fn contains_label(out: &[Endpoint], label: &str) -> bool {
    out.iter().any(|endpoint| endpoint.label == label)
}

fn net_contains_addr(net: &IpNet, addr: &str) -> bool {
    let Ok(addr) = addr.parse::<IpAddr>() else {
        return false;
    };
    match (net, addr) {
        (IpNet::V4(net), IpAddr::V4(addr)) => net.contains(&addr),
        (IpNet::V6(net), IpAddr::V6(addr)) => net.contains(&addr),
        _ => false,
    }
}

fn split_test_destination(dst: &str) -> Result<(&str, &str), String> {
    let Some((alias, port)) = dst.rsplit_once(':') else {
        return Err("tests destination must include one explicit port".to_string());
    };
    if alias.is_empty() || alias.ends_with(':') || is_namespaced_alias_without_port(dst) {
        return Err("tests destination must include one explicit port".to_string());
    }
    Ok((alias, port))
}

fn is_namespaced_alias_without_port(dst: &str) -> bool {
    ["tag:", "group:", "autogroup:", "host:"]
        .iter()
        .any(|prefix| dst.starts_with(prefix) && !dst[prefix.len()..].contains(':'))
}

fn parse_test_port(port: &str) -> Result<u16, String> {
    let parsed = port
        .parse::<u16>()
        .map_err(|_| "tests destination port must be a single number".to_string())?;
    if parsed == 0 {
        Err("tests destination port must be greater than zero".to_string())
    } else {
        Ok(parsed)
    }
}

fn is_untagged_user_owned(node: &PolicyCheckNode) -> bool {
    node.tags.is_empty() && node.user.as_deref().is_some_and(|user| !user.is_empty())
}

fn user_matches(entry: &str, user: &str) -> bool {
    entry == user || entry.strip_suffix('@') == Some(user) || user.strip_suffix('@') == Some(entry)
}

fn tag_matches(node_tag: &str, policy_tag_without_prefix: &str) -> bool {
    node_tag == policy_tag_without_prefix
        || node_tag.strip_prefix("tag:") == Some(policy_tag_without_prefix)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_hujson_policy;

    fn node(id: u64, name: &str, user: &str, addr: &str, tags: &[&str]) -> PolicyCheckNode {
        PolicyCheckNode {
            id,
            name: name.to_string(),
            user: Some(user.to_string()),
            addrs: vec![addr.to_string()],
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        }
    }

    #[test]
    fn acl_tests_accept_and_deny_pass_against_live_nodes() {
        let doc = parse_hujson_policy(
            r#"{
                "acls": [
                    {"action": "accept", "proto": "tcp", "src": ["alice@"], "dst": ["100.64.0.2:22"]}
                ],
                "tests": [
                    {"src": "alice@", "accept": ["100.64.0.2:22"], "deny": ["100.64.0.2:80"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice", "alice", "100.64.0.1", &[]),
            node(2, "server", "bob", "100.64.0.2", &[]),
        ];

        check_policy_semantics(&doc, &nodes).unwrap();
    }

    #[test]
    fn acl_tests_report_failed_assertion() {
        let doc = parse_hujson_policy(
            r#"{
                "acls": [],
                "tests": [
                    {"src": "alice@", "accept": ["100.64.0.2:22"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice", "alice", "100.64.0.1", &[]),
            node(2, "server", "bob", "100.64.0.2", &[]),
        ];

        let err = check_policy_semantics(&doc, &nodes).unwrap_err();
        assert!(err.contains("cannot reach accept destination"));
    }

    #[test]
    fn acl_tests_do_not_resolve_autogroup_self_per_source() {
        let doc = parse_hujson_policy(
            r#"{
                "acls": [
                    {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:22"]}
                ],
                "tests": [
                    {"src": "alice@", "accept": ["autogroup:self:22"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice-a", "alice", "100.64.0.1", &[]),
            node(2, "alice-b", "alice", "100.64.0.2", &[]),
            node(3, "bob", "bob", "100.64.0.3", &[]),
        ];

        let err = check_policy_semantics(&doc, &nodes).unwrap_err();
        assert!(err.contains("autogroup:self"));
        assert!(err.contains("resolved to no addresses"));
    }

    #[test]
    fn ssh_tests_accept_deny_and_check_pass_against_live_nodes() {
        let doc = parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:server": ["alice@"], "tag:db": ["alice@"]},
                "ssh": [
                    {"action": "accept", "src": ["alice@"], "dst": ["tag:server"], "users": ["root"]},
                    {"action": "check", "checkPeriod": "12h", "src": ["alice@"], "dst": ["tag:db"], "users": ["admin"]}
                ],
                "sshTests": [
                    {"src": "alice@", "dst": ["tag:server"], "accept": ["root"], "deny": ["ubuntu"]},
                    {"src": "alice@", "dst": ["tag:db"], "check": ["admin"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice", "alice", "100.64.0.1", &[]),
            node(2, "server", "bob", "100.64.0.2", &["tag:server"]),
            node(3, "db", "bob", "100.64.0.3", &["tag:db"]),
        ];

        check_policy_semantics(&doc, &nodes).unwrap();
    }

    #[test]
    fn ssh_tests_resolve_autogroup_self_for_user_source() {
        let doc = parse_hujson_policy(
            r#"{
                "ssh": [
                    {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["root"]}
                ],
                "sshTests": [
                    {"src": "alice@", "dst": ["autogroup:self"], "accept": ["root"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice-a", "alice", "100.64.0.1", &[]),
            node(2, "alice-b", "alice", "100.64.0.2", &[]),
            node(3, "bob", "bob", "100.64.0.3", &[]),
        ];

        check_policy_semantics(&doc, &nodes).unwrap();
    }

    #[test]
    fn ssh_tests_apply_canonical_localpart_users_to_source_email() {
        let doc = parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:server": ["alice@example.com"]},
                "ssh": [
                    {
                        "action": "accept",
                        "src": ["autogroup:member"],
                        "dst": ["tag:server"],
                        "users": ["localpart:*@EXAMPLE.COM"]
                    }
                ],
                "sshTests": [
                    {"src": "alice@example.com", "dst": ["tag:server"], "accept": ["alice"], "deny": ["localpart:*@EXAMPLE.COM", "bob"]},
                    {"src": "bob@example.com", "dst": ["tag:server"], "accept": ["bob"], "deny": ["alice"]},
                    {"src": "eve@other.example", "dst": ["tag:server"], "deny": ["eve"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice", "alice@example.com", "100.64.0.1", &[]),
            node(2, "bob", "bob@example.com", "100.64.0.2", &[]),
            node(3, "eve", "eve@other.example", "100.64.0.3", &[]),
            node(
                4,
                "server",
                "alice@example.com",
                "100.64.0.4",
                &["tag:server"],
            ),
        ];

        check_policy_semantics(&doc, &nodes).unwrap();
    }

    #[test]
    fn ssh_tests_treat_nonroot_as_tailcfg_wildcard() {
        let doc = parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:server": ["alice@"]},
                "ssh": [
                    {"action": "accept", "src": ["alice@"], "dst": ["tag:server"], "users": ["autogroup:nonroot"]}
                ],
                "sshTests": [
                    {"src": "alice@", "dst": ["tag:server"], "accept": ["ubuntu"], "deny": ["root"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice", "alice", "100.64.0.1", &[]),
            node(2, "server", "alice", "100.64.0.2", &["tag:server"]),
        ];

        check_policy_semantics(&doc, &nodes).unwrap();
    }

    #[test]
    fn ssh_tests_require_every_resolved_destination_to_match() {
        let doc = parse_hujson_policy(
            r#"{
                "tagOwners": {
                    "tag:server": ["alice@"],
                    "tag:prod": ["alice@"]
                },
                "ssh": [
                    {"action": "accept", "src": ["alice@"], "dst": ["tag:server"], "users": ["root"]}
                ],
                "sshTests": [
                    {"src": "alice@", "dst": ["tag:server", "tag:prod"], "accept": ["root"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice", "alice", "100.64.0.1", &[]),
            node(2, "server", "bob", "100.64.0.2", &["tag:server"]),
            node(3, "prod", "bob", "100.64.0.3", &["tag:prod"]),
        ];

        let err = check_policy_semantics(&doc, &nodes).unwrap_err();
        assert!(err.contains("alice@"));
        assert!(err.contains("prod"));
        assert!(err.contains("root"));
        assert!(err.contains("cannot SSH to destination"));
    }

    #[test]
    fn ssh_tests_do_not_use_acl_packet_filter_rules() {
        let acl_allows_tcp22_without_ssh = parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:server": ["alice@"]},
                "acls": [
                    {"action": "accept", "src": ["alice@"], "dst": ["tag:server:22"]}
                ],
                "sshTests": [
                    {"src": "alice@", "dst": ["tag:server"], "accept": ["root"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice", "alice", "100.64.0.1", &[]),
            node(2, "server", "bob", "100.64.0.2", &["tag:server"]),
        ];

        let err = check_policy_semantics(&acl_allows_tcp22_without_ssh, &nodes).unwrap_err();
        assert!(err.contains("cannot SSH to destination"));

        let acl_denies_tcp22_ssh_allows = parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:server": ["alice@"]},
                "acls": [
                    {"action": "accept", "src": ["alice@"], "dst": ["tag:server:80"]}
                ],
                "ssh": [
                    {"action": "accept", "src": ["alice@"], "dst": ["tag:server"], "users": ["root"]}
                ],
                "sshTests": [
                    {"src": "alice@", "dst": ["tag:server"], "accept": ["root"]}
                ]
            }"#,
        )
        .unwrap();

        check_policy_semantics(&acl_denies_tcp22_ssh_allows, &nodes).unwrap();
    }

    #[test]
    fn ssh_tests_report_failed_accept_and_check_assertions() {
        let doc = parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:server": ["alice@"]},
                "ssh": [
                    {"action": "accept", "src": ["alice@"], "dst": ["tag:server"], "users": ["root"]}
                ],
                "sshTests": [
                    {"src": "alice@", "dst": ["tag:server"], "accept": ["ubuntu"], "check": ["root"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice", "alice", "100.64.0.1", &[]),
            node(2, "server", "bob", "100.64.0.2", &["tag:server"]),
        ];

        let err = check_policy_semantics(&doc, &nodes).unwrap_err();
        assert!(err.contains("cannot SSH to destination"));
        assert!(err.contains("allowed by accept but not check"));
    }
}
