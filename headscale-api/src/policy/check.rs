//! Semantic evaluation for upstream policy `tests`.
//!
//! Parsing and shape validation live in `headscale-api-acl`. This
//! module owns the live-node pass used by gRPC `CheckPolicy` and
//! `SetPolicy`.

use std::collections::BTreeSet;
use std::net::IpAddr;

use headscale_api_acl::{
    AclAction, AclDoc as PolicyDoc, NodeView, PolicyTest, PortRef, parse_cidr,
};
use ipnet::IpNet;

/// Live node facts needed to evaluate policy tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCheckNode {
    pub name: String,
    pub user: Option<String>,
    pub addrs: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug)]
struct Endpoint {
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

    if !doc.ssh_tests.is_empty() {
        errors.push(
            "sshTests semantic evaluation is not implemented yet; TODO: compile candidate SSH \
             policy per destination and evaluate accept, deny, and check assertions against live \
             source nodes"
                .to_string(),
        );
    }

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
        let dsts = resolve_alias(doc, nodes, alias, Some(src));
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
            node.tags.is_empty()
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
                for node in nodes.iter().filter(|node| node.tags.is_empty()) {
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
    if let Some(ipset) = token.strip_prefix("ipset:") {
        if let Some(prefixes) = doc.ipsets.get(ipset) {
            for prefix in prefixes {
                resolve_prefix(nodes, prefix, out);
            }
        }
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
    ["tag:", "group:", "autogroup:", "host:", "ipset:"]
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

    fn node(name: &str, user: &str, addr: &str, tags: &[&str]) -> PolicyCheckNode {
        PolicyCheckNode {
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
            node("alice", "alice", "100.64.0.1", &[]),
            node("server", "bob", "100.64.0.2", &[]),
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
            node("alice", "alice", "100.64.0.1", &[]),
            node("server", "bob", "100.64.0.2", &[]),
        ];

        let err = check_policy_semantics(&doc, &nodes).unwrap_err();
        assert!(err.contains("cannot reach accept destination"));
    }

    #[test]
    fn non_empty_ssh_tests_are_explicit_gap() {
        let doc = parse_hujson_policy(
            r#"{
                "ssh": [{"action": "accept", "src": ["alice@"], "dst": ["autogroup:self"], "users": ["root"]}],
                "sshTests": [{"src": "alice@", "dst": ["autogroup:self"], "accept": ["root"]}]
            }"#,
        )
        .unwrap();
        let nodes = vec![node("alice", "alice", "100.64.0.1", &[])];

        let err = check_policy_semantics(&doc, &nodes).unwrap_err();
        assert!(err.contains("sshTests semantic evaluation is not implemented yet"));
    }
}
