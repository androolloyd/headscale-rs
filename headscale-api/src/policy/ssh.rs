use std::collections::{BTreeMap, BTreeSet};

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct SshUserRule {
    ssh_users: BTreeMap<String, String>,
    source_node_ids: BTreeSet<u64>,
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
        let source_nodes = resolve_ssh_source_nodes(doc, &rule.src, nodes);
        if source_nodes.is_empty() {
            continue;
        }

        let action = ssh_action(&rule.action, rule.check_period.as_deref());
        let ssh_user_rules = ssh_user_rules(&rule.users, &source_nodes);
        if ssh_user_rules.is_empty() {
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

        if !self_dsts.is_empty() && is_untagged_user_owned(target_node) {
            let same_user = same_user_untagged_nodes(&source_nodes, target_node);
            push_ssh_rules_for_nodes(&mut out, &same_user, &ssh_user_rules, &action);
        }

        if !other_dsts.is_empty()
            && other_dsts
                .iter()
                .any(|dst| ssh_destination_matches(doc, dst, target_node))
        {
            push_ssh_rules_for_nodes(&mut out, &source_nodes, &ssh_user_rules, &action);
        }
    }

    Some(SshPolicy { rules: out })
}

fn push_ssh_rules_for_nodes(
    out: &mut Vec<SshRule>,
    nodes: &[&SshPolicyNode],
    ssh_user_rules: &[SshUserRule],
    action: &SshAction,
) {
    for ssh_user_rule in ssh_user_rules {
        let principals = source_node_addrs_for_rule(nodes, ssh_user_rule);
        push_ssh_rule(out, &principals, &ssh_user_rule.ssh_users, action);
    }
}

fn push_ssh_rule(
    out: &mut Vec<SshRule>,
    principals: &[String],
    ssh_users: &BTreeMap<String, String>,
    action: &SshAction,
) {
    if principals.is_empty() {
        return;
    }

    out.push(SshRule {
        principals: principals
            .iter()
            .cloned()
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

fn source_node_addrs_for_rule(nodes: &[&SshPolicyNode], rule: &SshUserRule) -> Vec<String> {
    let mut out = Vec::new();
    for node in nodes {
        if !rule.source_node_ids.contains(&node.id) {
            continue;
        }
        for addr in &node.addrs {
            push_unique_string(&mut out, addr.clone());
        }
    }
    out.sort();
    out
}

fn resolve_ssh_source_nodes<'a>(
    doc: &PolicyDoc,
    tokens: &[String],
    nodes: &'a [SshPolicyNode],
) -> Vec<&'a SshPolicyNode> {
    let mut out = Vec::new();
    let mut seen_nodes = BTreeSet::new();
    for token in tokens {
        let mut seen_groups = BTreeSet::new();
        resolve_ssh_source_node(
            doc,
            token,
            nodes,
            &mut seen_groups,
            &mut seen_nodes,
            &mut out,
        );
    }
    out.sort_by_key(|node| node.id);
    out
}

fn resolve_ssh_source_node<'a>(
    doc: &PolicyDoc,
    token: &str,
    nodes: &'a [SshPolicyNode],
    seen_groups: &mut BTreeSet<String>,
    seen_nodes: &mut BTreeSet<u64>,
    out: &mut Vec<&'a SshPolicyNode>,
) {
    if token.contains('@') {
        for node in nodes
            .iter()
            .filter(|node| is_untagged_user_owned(node))
            .filter(|node| {
                node.user
                    .as_deref()
                    .is_some_and(|user| user_matches(token, user))
            })
        {
            push_unique_node(out, seen_nodes, node);
        }
        return;
    }
    if let Some(group) = token.strip_prefix("group:") {
        let group_ref = format!("group:{group}");
        if !seen_groups.insert(group_ref.clone()) {
            return;
        }
        let Some(members) = doc.groups.get(token).or_else(|| doc.groups.get(group)) else {
            seen_groups.remove(&group_ref);
            return;
        };
        for member in members {
            resolve_ssh_source_node(doc, member, nodes, seen_groups, seen_nodes, out);
        }
        seen_groups.remove(&group_ref);
        return;
    }
    if let Some(tag) = token.strip_prefix("tag:") {
        for node in nodes
            .iter()
            .filter(|node| node.tags.iter().any(|node_tag| tag_matches(node_tag, tag)))
        {
            push_unique_node(out, seen_nodes, node);
        }
        return;
    }
    if let Some(kind) = token.strip_prefix("autogroup:") {
        match kind {
            "member" => {
                for node in nodes.iter().filter(|node| is_untagged_user_owned(node)) {
                    push_unique_node(out, seen_nodes, node);
                }
            }
            "tagged" => {
                for node in nodes.iter().filter(|node| !node.tags.is_empty()) {
                    push_unique_node(out, seen_nodes, node);
                }
            }
            _ => {}
        }
    }
}

fn ssh_destination_matches(doc: &PolicyDoc, token: &str, node: &SshPolicyNode) -> bool {
    if token.contains('@') {
        return is_untagged_user_owned(node)
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
            "member" => is_untagged_user_owned(node),
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
    nodes: &'a [&'a SshPolicyNode],
    node: &SshPolicyNode,
) -> Vec<&'a SshPolicyNode> {
    let Some(user) = node.user.as_deref().filter(|user| !user.is_empty()) else {
        return Vec::new();
    };

    nodes
        .iter()
        .copied()
        .filter(|candidate| is_untagged_user_owned(candidate))
        .filter(|candidate| candidate.user.as_deref() == Some(user))
        .collect()
}

fn ssh_user_rules(users: &[String], source_nodes: &[&SshPolicyNode]) -> Vec<SshUserRule> {
    let all_source_node_ids: BTreeSet<u64> = source_nodes.iter().map(|node| node.id).collect();
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

    let mut maps = Vec::new();
    if !out.is_empty() || users.is_empty() {
        maps.push(SshUserRule {
            ssh_users: out,
            source_node_ids: all_source_node_ids,
        });
    }

    maps
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

fn is_untagged_user_owned(node: &SshPolicyNode) -> bool {
    node.tags.is_empty() && node.user.as_deref().is_some_and(|user| !user.is_empty())
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

fn push_unique_node<'a>(
    out: &mut Vec<&'a SshPolicyNode>,
    seen: &mut BTreeSet<u64>,
    node: &'a SshPolicyNode,
) {
    if seen.insert(node.id) {
        out.push(node);
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

    #[test]
    fn literal_star_user_maps_to_tailcfg_star_like_headscale_go() {
        let doc = parse_hujson_policy(
            r#"{
              "tagOwners": {"tag:server": ["alice@"]},
              "ssh": [{
                "action": "accept",
                "src": ["alice@"],
                "dst": ["tag:server"],
                "users": ["*"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("alice".into()),
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

        assert_eq!(pol.rules[0].ssh_users["*"], "*");
        assert!(!pol.rules[0].ssh_users.contains_key("root"));
    }

    #[test]
    fn localpart_like_users_compile_as_literals_like_headscale_go_v0_28() {
        let doc = parse_hujson_policy(
            r#"{
              "tagOwners": {"tag:server": ["alice@example.com"]},
              "ssh": [{
                "action": "accept",
                "src": ["autogroup:member"],
                "dst": ["tag:server"],
                "users": ["localpart:*@example.com"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("alice@example.com".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("bob@example.com".into()),
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 3,
                user: Some("eve@other.example".into()),
                addrs: vec!["100.64.0.3".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 4,
                user: Some("alice@example.com".into()),
                addrs: vec!["100.64.0.4".into()],
                tags: vec!["tag:server".into()],
            },
        ];

        let pol = compile_ssh_policy(&doc, &nodes, 4).unwrap();

        assert_eq!(pol.rules.len(), 1);
        assert_eq!(
            principal_ips_for_rule(&pol.rules[0]),
            vec!["100.64.0.1", "100.64.0.2", "100.64.0.3"]
        );
        assert_eq!(
            pol.rules[0].ssh_users["localpart:*@example.com"],
            "localpart:*@example.com"
        );
        assert!(!pol.rules[0].ssh_users.contains_key("alice"));
        assert!(!pol.rules[0].ssh_users.contains_key("bob"));
    }

    #[test]
    fn localpart_like_users_stay_literal_for_autogroup_self() {
        let doc = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "accept",
                "src": ["autogroup:member"],
                "dst": ["autogroup:self"],
                "users": ["localpart:*@example.com"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("alice@example.com".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice@example.com".into()),
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 3,
                user: Some("bob@example.com".into()),
                addrs: vec!["100.64.0.3".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 4,
                user: Some("bob@example.com".into()),
                addrs: vec!["100.64.0.4".into()],
                tags: Vec::new(),
            },
        ];

        let alice_target = compile_ssh_policy(&doc, &nodes, 2).unwrap();
        let bob_target = compile_ssh_policy(&doc, &nodes, 4).unwrap();

        assert_eq!(alice_target.rules.len(), 1);
        assert_eq!(
            principal_ips_for_rule(&alice_target.rules[0]),
            vec!["100.64.0.1", "100.64.0.2"]
        );
        assert_eq!(
            alice_target.rules[0].ssh_users["localpart:*@example.com"],
            "localpart:*@example.com"
        );

        assert_eq!(bob_target.rules.len(), 1);
        assert_eq!(
            principal_ips_for_rule(&bob_target.rules[0]),
            vec!["100.64.0.3", "100.64.0.4"]
        );
        assert_eq!(
            bob_target.rules[0].ssh_users["localpart:*@example.com"],
            "localpart:*@example.com"
        );
    }

    #[test]
    fn userless_nodes_do_not_match_member_or_self() {
        let doc = parse_hujson_policy(
            r#"{
              "ssh": [
                {
                  "action": "accept",
                  "src": ["autogroup:member"],
                  "dst": ["autogroup:member"],
                  "users": ["deploy"]
                },
                {
                  "action": "accept",
                  "src": ["autogroup:member"],
                  "dst": ["autogroup:self"],
                  "users": ["root"]
                }
              ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("alice".into()),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: None,
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
            },
        ];

        let alice_target = compile_ssh_policy(&doc, &nodes, 1).unwrap();
        let userless_target = compile_ssh_policy(&doc, &nodes, 2).unwrap();

        assert_eq!(alice_target.rules.len(), 2);
        assert_eq!(
            principal_ips_for_rule(&alice_target.rules[0]),
            vec!["100.64.0.1"]
        );
        assert_eq!(
            principal_ips_for_rule(&alice_target.rules[1]),
            vec!["100.64.0.1"]
        );
        assert!(userless_target.rules.is_empty());
    }

    fn principal_ips(policy: &SshPolicy) -> Vec<&str> {
        principal_ips_for_rule(&policy.rules[0])
    }

    fn principal_ips_for_rule(rule: &SshRule) -> Vec<&str> {
        rule.principals
            .iter()
            .map(|principal| principal.node_ip.as_str())
            .collect()
    }
}
