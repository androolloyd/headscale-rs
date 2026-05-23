use std::collections::BTreeMap;

use super::PolicyDoc;
use crate::tailscale_wire::wire::{SshAction, SshPolicy, SshPrincipal, SshRule};

/// Node facets required to compile Tailscale SSH policy for a target node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshPolicyNode {
    pub id: u64,
    pub user: Option<String>,
    pub addrs: Vec<String>,
    pub tags: Vec<String>,
}

/// Compile a headscale policy `ssh` block into the `tailcfg.SSHPolicy`
/// shape sent in `MapResponse.SSHPolicy`.
///
/// Mirrors headscale-go v0.28.0's policy/v2 compiler for the currently
/// supported alias set: users, groups, tags, `autogroup:member`,
/// `autogroup:tagged`, `autogroup:self`, and host destinations.
pub fn compile_ssh_policy(
    doc: &PolicyDoc,
    nodes: &[SshPolicyNode],
    target_node_id: u64,
) -> Option<SshPolicy> {
    if doc.ssh.is_empty() {
        return None;
    }
    let target_node = nodes.iter().find(|node| node.id == target_node_id)?;
    let mut out = Vec::new();

    for rule in &doc.ssh {
        let src_ips = resolve_ssh_sources(doc, &rule.src, nodes);
        if src_ips.is_empty() {
            continue;
        }

        let action = ssh_action(&rule.action, rule.check_period.as_deref());
        let ssh_users = ssh_user_map(&rule.users);
        let mut self_dsts = Vec::new();
        let mut other_dsts = Vec::new();
        for dst in &rule.dst {
            if dst == "autogroup:self" {
                self_dsts.push(dst.clone());
            } else {
                other_dsts.push(dst.clone());
            }
        }

        if !self_dsts.is_empty() && target_node.tags.is_empty() {
            let same_user = same_user_untagged_nodes(nodes, target_node);
            let mut principals = Vec::new();
            for node in same_user {
                if node
                    .addrs
                    .iter()
                    .any(|addr| src_ips.iter().any(|src| src == addr))
                {
                    for addr in &node.addrs {
                        push_unique_string(&mut principals, addr.clone());
                    }
                }
            }
            principals.sort();
            if !principals.is_empty() {
                out.push(SshRule {
                    principals: principals
                        .into_iter()
                        .map(|node_ip| SshPrincipal {
                            node_ip,
                            ..SshPrincipal::default()
                        })
                        .collect(),
                    ssh_users: ssh_users.clone(),
                    action: action.clone(),
                    ..SshRule::default()
                });
            }
        }

        if !other_dsts.is_empty()
            && other_dsts
                .iter()
                .any(|dst| ssh_destination_matches(doc, dst, target_node))
        {
            let mut principals = src_ips.clone();
            principals.sort();
            principals.dedup();
            out.push(SshRule {
                principals: principals
                    .into_iter()
                    .map(|node_ip| SshPrincipal {
                        node_ip,
                        ..SshPrincipal::default()
                    })
                    .collect(),
                ssh_users: ssh_users.clone(),
                action: action.clone(),
                ..SshRule::default()
            });
        }
    }

    Some(SshPolicy { rules: out })
}

fn resolve_ssh_sources(doc: &PolicyDoc, tokens: &[String], nodes: &[SshPolicyNode]) -> Vec<String> {
    let mut out = Vec::new();
    for token in tokens {
        for value in resolve_ssh_source(doc, token, nodes) {
            push_unique_string(&mut out, value);
        }
    }
    out.sort();
    out
}

fn resolve_ssh_source(doc: &PolicyDoc, token: &str, nodes: &[SshPolicyNode]) -> Vec<String> {
    if token.contains('@') {
        return nodes
            .iter()
            .filter(|node| node.tags.is_empty())
            .filter(|node| {
                node.user
                    .as_deref()
                    .is_some_and(|user| user_matches(token, user))
            })
            .flat_map(|node| node.addrs.clone())
            .collect();
    }
    if let Some(group) = token.strip_prefix("group:") {
        let Some(members) = doc.groups.get(token).or_else(|| doc.groups.get(group)) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for member in members {
            for value in resolve_ssh_source(doc, member, nodes) {
                push_unique_string(&mut out, value);
            }
        }
        return out;
    }
    if let Some(tag) = token.strip_prefix("tag:") {
        return nodes
            .iter()
            .filter(|node| node.tags.iter().any(|node_tag| tag_matches(node_tag, tag)))
            .flat_map(|node| node.addrs.clone())
            .collect();
    }
    if let Some(kind) = token.strip_prefix("autogroup:") {
        return match kind {
            "member" => nodes
                .iter()
                .filter(|node| node.tags.is_empty())
                .flat_map(|node| node.addrs.clone())
                .collect(),
            "tagged" => nodes
                .iter()
                .filter(|node| !node.tags.is_empty())
                .flat_map(|node| node.addrs.clone())
                .collect(),
            _ => Vec::new(),
        };
    }
    Vec::new()
}

fn ssh_destination_matches(doc: &PolicyDoc, token: &str, node: &SshPolicyNode) -> bool {
    if token.contains('@') {
        return node.tags.is_empty()
            && node
                .user
                .as_deref()
                .is_some_and(|user| user_matches(token, user));
    }
    if let Some(tag) = token.strip_prefix("tag:") {
        return node.tags.iter().any(|node_tag| tag_matches(node_tag, tag));
    }
    if let Some(kind) = token.strip_prefix("autogroup:") {
        return match kind {
            "member" => node.tags.is_empty(),
            "tagged" => !node.tags.is_empty(),
            _ => false,
        };
    }
    let host = token.strip_prefix("host:").unwrap_or(token);
    if let Some(prefix) = doc.hosts.get(host) {
        return node
            .addrs
            .iter()
            .any(|addr| prefix_contains_addr(prefix, addr));
    }
    false
}

fn same_user_untagged_nodes<'a>(
    nodes: &'a [SshPolicyNode],
    node: &SshPolicyNode,
) -> Vec<&'a SshPolicyNode> {
    nodes
        .iter()
        .filter(|candidate| candidate.tags.is_empty())
        .filter(|candidate| candidate.user == node.user)
        .collect()
}

fn ssh_user_map(users: &[String]) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if users.iter().any(|user| user == "autogroup:nonroot") {
        out.insert("*".to_string(), "=".to_string());
        out.insert("root".to_string(), String::new());
    }
    if users.iter().any(|user| user == "root") {
        out.insert("root".to_string(), "root".to_string());
    }
    for user in users {
        if user == "root" || user == "autogroup:nonroot" {
            continue;
        }
        out.insert(user.clone(), user.clone());
    }
    out
}

fn ssh_action(action: &str, check_period: Option<&str>) -> SshAction {
    let session_duration = if action == "check" {
        check_period.and_then(parse_duration_nanos).unwrap_or(0)
    } else {
        0
    };
    SshAction {
        accept: true,
        reject: false,
        session_duration,
        allow_agent_forwarding: true,
        allow_local_port_forwarding: true,
        allow_remote_port_forwarding: true,
        ..SshAction::default()
    }
}

fn parse_duration_nanos(input: &str) -> Option<i64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed == "0" {
        return Some(0);
    }

    let bytes = trimmed.as_bytes();
    let mut pos = 0usize;
    let mut total: i128 = 0;
    while pos < bytes.len() {
        if !bytes[pos].is_ascii_digit() {
            return None;
        }
        let start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        let value: i128 = trimmed[start..pos].parse().ok()?;
        let unit_start = pos;
        while pos < bytes.len() && !bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        let unit = &trimmed[unit_start..pos];
        let multiplier: i128 = match unit {
            "ns" => 1,
            "us" | "µs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 60 * 60 * 1_000_000_000,
            "d" => 24 * 60 * 60 * 1_000_000_000,
            "w" => 7 * 24 * 60 * 60 * 1_000_000_000,
            "y" => 365 * 24 * 60 * 60 * 1_000_000_000,
            _ => return None,
        };
        total = total.checked_add(value.checked_mul(multiplier)?)?;
    }
    i64::try_from(total).ok()
}

fn user_matches(entry: &str, user: &str) -> bool {
    entry == user || entry.strip_suffix('@') == Some(user) || user.strip_suffix('@') == Some(entry)
}

fn tag_matches(node_tag: &str, policy_tag_without_prefix: &str) -> bool {
    node_tag == policy_tag_without_prefix
        || node_tag.strip_prefix("tag:") == Some(policy_tag_without_prefix)
}

fn prefix_contains_addr(prefix: &str, addr: &str) -> bool {
    let Some(net) = headscale_api_acl::parse_cidr(prefix) else {
        return false;
    };
    let Ok(addr) = addr.parse::<std::net::IpAddr>() else {
        return false;
    };
    net.contains(&addr)
}

fn push_unique_string(out: &mut Vec<String>, value: String) {
    if !out.contains(&value) {
        out.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_hujson_policy;

    #[test]
    fn compiles_ssh_policy_for_tagged_target() {
        let doc = parse_hujson_policy(
            r#"{
              "groups": {"group:admins": ["bob@"]},
              "tagOwners": {"tag:server": ["alice@"]},
              "ssh": [{
                "action": "accept",
                "src": ["group:admins"],
                "dst": ["tag:server"],
                "users": ["autogroup:nonroot", "root", "deploy"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("bob".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice".into()),
                addrs: vec!["100.64.0.2".into()],
                tags: vec!["tag:server".into()],
            },
        ];
        let pol = compile_ssh_policy(&doc, &nodes, 2).unwrap();
        assert_eq!(pol.rules.len(), 1);
        assert_eq!(pol.rules[0].principals[0].node_ip, "100.64.0.1");
        assert_eq!(pol.rules[0].ssh_users["*"], "=");
        assert_eq!(pol.rules[0].ssh_users["root"], "root");
        assert_eq!(pol.rules[0].ssh_users["deploy"], "deploy");
    }

    #[test]
    fn compiles_group_sources_for_self_without_cross_user_leak() {
        let doc = parse_hujson_policy(
            r#"{
              "groups": {
                "group:primary": ["user1@"],
                "group:secondary": ["user2@"],
                "group:auditors": ["user3@"]
              },
              "ssh": [{
                "action": "accept",
                "src": ["group:primary", "group:secondary", "group:auditors"],
                "dst": ["autogroup:self"],
                "users": ["ssh-it-user"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("user1".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("user1".into()),
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 3,
                user: Some("user2".into()),
                addrs: vec!["100.64.0.3".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 4,
                user: Some("user3".into()),
                addrs: vec!["100.64.0.4".into()],
                tags: Vec::new(),
            },
        ];

        let user1_target = compile_ssh_policy(&doc, &nodes, 2).unwrap();
        let user2_target = compile_ssh_policy(&doc, &nodes, 3).unwrap();
        let user3_target = compile_ssh_policy(&doc, &nodes, 4).unwrap();

        assert_eq!(
            principal_ips(&user1_target),
            vec!["100.64.0.1", "100.64.0.2"]
        );
        assert_eq!(principal_ips(&user2_target), vec!["100.64.0.3"]);
        assert_eq!(principal_ips(&user3_target), vec!["100.64.0.4"]);
    }

    #[test]
    fn check_period_serialises_as_duration_nanos() {
        let doc = parse_hujson_policy(
            r#"{
              "groups": {"group:admins": ["bob@"]},
              "tagOwners": {"tag:db": ["alice@"]},
              "ssh": [{
                "action": "check",
                "checkPeriod": "24h",
                "src": ["group:admins"],
                "dst": ["tag:db"],
                "users": ["admin"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("bob".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice".into()),
                addrs: vec!["100.64.0.2".into()],
                tags: vec!["tag:db".into()],
            },
        ];
        let pol = compile_ssh_policy(&doc, &nodes, 2).unwrap();
        assert_eq!(
            pol.rules[0].action.session_duration,
            24 * 60 * 60 * 1_000_000_000
        );
    }

    fn principal_ips(policy: &SshPolicy) -> Vec<&str> {
        policy.rules[0]
            .principals
            .iter()
            .map(|principal| principal.node_ip.as_str())
            .collect()
    }
}
