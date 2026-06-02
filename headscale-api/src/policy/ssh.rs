use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use super::PolicyDoc;
use crate::tailscale_wire::wire::{SshAction, SshPolicy, SshPrincipal, SshRule};

/// Node facets required to compile Tailscale SSH policy for a target node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SshPolicyNode {
    pub id: u64,
    pub user: Option<String>,
    pub user_id: Option<u64>,
    pub addrs: Vec<String>,
    pub tags: Vec<String>,
}

const SSH_CHECK_PERIOD_DEFAULT: Duration = Duration::from_secs(12 * 60 * 60);

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
/// `autogroup:tagged`, and `autogroup:self`.
pub fn compile_ssh_policy(
    doc: &PolicyDoc,
    nodes: &[SshPolicyNode],
    target_node_id: u64,
) -> Option<SshPolicy> {
    compile_ssh_policy_with_base_url(doc, nodes, target_node_id, "")
}

pub fn compile_ssh_policy_with_base_url(
    doc: &PolicyDoc,
    nodes: &[SshPolicyNode],
    target_node_id: u64,
    base_url: &str,
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

        let action = ssh_action(base_url, &rule.action);
        let ssh_user_rules = ssh_user_rules(&rule.users, &source_nodes);
        if ssh_user_rules.is_empty() {
            continue;
        }
        let has_localpart_users = users_have_canonical_localpart(&rule.users);
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
            push_ssh_rules_for_nodes(
                &mut out,
                &same_user,
                &ssh_user_rules,
                &action,
                &rule.accept_env,
            );
        }

        if !other_dsts.is_empty() {
            if other_dsts
                .iter()
                .any(|dst| ssh_destination_matches(dst, target_node))
            {
                push_ssh_rules_for_nodes(
                    &mut out,
                    &source_nodes,
                    &ssh_user_rules,
                    &action,
                    &rule.accept_env,
                );
            } else if has_localpart_users
                && source_nodes.iter().any(|node| node.id == target_node.id)
            {
                push_localpart_self_access_rules(
                    &mut out,
                    &source_nodes,
                    target_node,
                    &ssh_user_rules,
                    &action,
                    &rule.accept_env,
                );
            }
        }
    }

    out.sort_by_key(|rule| i32::from(rule.action.hold_and_delegate.is_empty()));
    Some(SshPolicy { rules: out })
}

pub fn ssh_check_period_for(
    doc: &PolicyDoc,
    nodes: &[SshPolicyNode],
    src_node_id: u64,
    dst_node_id: u64,
    local_user: &str,
) -> Option<Duration> {
    if doc.ssh.is_empty() {
        return None;
    }
    let src_node = nodes.iter().find(|node| node.id == src_node_id)?;
    let dst_node = nodes.iter().find(|node| node.id == dst_node_id)?;

    for rule in &doc.ssh {
        if rule.action != "check" {
            continue;
        }
        let source_nodes = resolve_ssh_source_nodes(doc, &rule.src, nodes);
        if !source_nodes.iter().any(|node| node.id == src_node.id) {
            continue;
        }
        let ssh_user_rules = ssh_user_rules(&rule.users, &source_nodes);
        if !ssh_user_rules
            .iter()
            .filter(|rule| rule.source_node_ids.contains(&src_node_id))
            .any(|rule| ssh_user_rule_allows_local_user(rule, local_user))
        {
            continue;
        }

        for dst in &rule.dst {
            if dst == "autogroup:self" {
                if same_ssh_user_owner(src_node, dst_node) {
                    return Some(check_period_from_rule(rule.check_period.as_deref()));
                }
                continue;
            }

            if ssh_destination_matches(dst, dst_node) {
                return Some(check_period_from_rule(rule.check_period.as_deref()));
            }
        }
    }

    None
}

fn ssh_user_rule_allows_local_user(rule: &SshUserRule, local_user: &str) -> bool {
    if local_user.is_empty() {
        return false;
    }
    if let Some(target) = rule.ssh_users.get(local_user) {
        return !target.is_empty();
    }
    if local_user != "root"
        && let Some(target) = rule.ssh_users.get("*")
    {
        return !target.is_empty();
    }
    false
}

fn push_ssh_rules_for_nodes(
    out: &mut Vec<SshRule>,
    nodes: &[&SshPolicyNode],
    ssh_user_rules: &[SshUserRule],
    action: &SshAction,
    accept_env: &[String],
) {
    for ssh_user_rule in ssh_user_rules {
        let principals = source_node_addrs_for_rule(nodes, ssh_user_rule);
        push_ssh_rule(
            out,
            &principals,
            &ssh_user_rule.ssh_users,
            action,
            accept_env,
        );
    }
}

fn push_localpart_self_access_rules(
    out: &mut Vec<SshRule>,
    source_nodes: &[&SshPolicyNode],
    target_node: &SshPolicyNode,
    ssh_user_rules: &[SshUserRule],
    action: &SshAction,
    accept_env: &[String],
) {
    if is_untagged_user_owned(target_node) {
        let same_user = same_user_untagged_nodes(source_nodes, target_node);
        push_ssh_rules_for_nodes(out, &same_user, ssh_user_rules, action, accept_env);
        return;
    }

    let principals = unique_node_addrs(target_node);
    for ssh_user_rule in ssh_user_rules {
        if ssh_user_rule.source_node_ids.contains(&target_node.id) {
            push_ssh_rule(
                out,
                &principals,
                &ssh_user_rule.ssh_users,
                action,
                accept_env,
            );
        }
    }
}

fn push_ssh_rule(
    out: &mut Vec<SshRule>,
    principals: &[String],
    ssh_users: &BTreeMap<String, String>,
    action: &SshAction,
    accept_env: &[String],
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
        accept_env: accept_env.to_vec(),
        ..SshRule::default()
    });
}

fn source_node_addrs_for_rule(nodes: &[&SshPolicyNode], rule: &SshUserRule) -> Vec<String> {
    let mut out = Vec::new();
    for node in nodes {
        if !rule.source_node_ids.contains(&node.id) {
            continue;
        }
        if node.tags.is_empty() {
            for addr in &node.addrs {
                push_unique_string(&mut out, addr.clone());
            }
        } else {
            for _ in 0..node.tags.len() {
                for addr in &node.addrs {
                    out.push(addr.clone());
                }
            }
        }
    }
    out.sort();
    out
}

fn unique_node_addrs(node: &SshPolicyNode) -> Vec<String> {
    let mut out = Vec::new();
    for addr in &node.addrs {
        push_unique_string(&mut out, addr.clone());
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

fn ssh_destination_matches(token: &str, node: &SshPolicyNode) -> bool {
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
    false
}

fn same_user_untagged_nodes<'a>(
    nodes: &'a [&'a SshPolicyNode],
    node: &SshPolicyNode,
) -> Vec<&'a SshPolicyNode> {
    nodes
        .iter()
        .copied()
        .filter(|candidate| same_ssh_user_owner(candidate, node))
        .collect()
}

fn same_ssh_user_owner(left: &SshPolicyNode, right: &SshPolicyNode) -> bool {
    if !is_untagged_user_owned(left) || !is_untagged_user_owned(right) {
        return false;
    }

    match (left.user_id, right.user_id) {
        (Some(left_id), Some(right_id)) => left_id == right_id,
        (None, None) => {
            let Some(left_user) = left.user.as_deref().filter(|user| !user.is_empty()) else {
                return false;
            };
            right.user.as_deref().filter(|user| !user.is_empty()) == Some(left_user)
        }
        _ => false,
    }
}

fn ssh_user_rules(users: &[String], source_nodes: &[&SshPolicyNode]) -> Vec<SshUserRule> {
    let all_source_node_ids: BTreeSet<u64> = source_nodes.iter().map(|node| node.id).collect();
    let localpart_domains = canonical_localpart_domains(users);
    if !localpart_domains.is_empty() {
        return ssh_user_rules_with_localparts(users, source_nodes, &localpart_domains);
    }

    let mut out = BTreeMap::new();
    if users.iter().any(|user| user == "autogroup:nonroot") {
        out.insert("*".to_string(), "=".to_string());
    }
    if users.iter().any(|user| user == "root") {
        out.insert("root".to_string(), "root".to_string());
    } else {
        out.insert("root".to_string(), String::new());
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

fn ssh_user_rules_with_localparts(
    users: &[String],
    source_nodes: &[&SshPolicyNode],
    localpart_domains: &[String],
) -> Vec<SshUserRule> {
    let mut base = BTreeMap::new();
    if users.iter().any(|user| user == "autogroup:nonroot") {
        base.insert("*".to_string(), "=".to_string());
    }
    if users.iter().any(|user| user == "root") {
        base.insert("root".to_string(), "root".to_string());
    } else {
        base.insert("root".to_string(), String::new());
    }
    for user in users {
        if user == "root"
            || user == "autogroup:nonroot"
            || canonical_localpart_domain(user).is_some()
        {
            continue;
        }
        base.insert(user.clone(), user.clone());
    }

    let mut groups: Vec<(Option<String>, BTreeSet<u64>)> = Vec::new();
    for node in source_nodes {
        let user = if is_untagged_user_owned(node) {
            node.user.clone()
        } else {
            None
        };
        if let Some((_, ids)) = groups.iter_mut().find(|(candidate, _)| *candidate == user) {
            ids.insert(node.id);
        } else {
            groups.push((user, BTreeSet::from([node.id])));
        }
    }

    let mut rules = Vec::new();
    for (user, source_node_ids) in groups {
        rules.push(SshUserRule {
            ssh_users: base.clone(),
            source_node_ids: source_node_ids.clone(),
        });
        if let Some(user) = user.as_deref()
            && let Some(localpart) = localpart_for_user(user, localpart_domains)
        {
            rules.push(SshUserRule {
                ssh_users: BTreeMap::from([(localpart.clone(), localpart)]),
                source_node_ids,
            });
        }
    }
    rules
}

fn ssh_action(base_url: &str, action: &str) -> SshAction {
    if action == "check" {
        return SshAction {
            hold_and_delegate: ssh_check_hold_url(base_url, None),
            ..SshAction::default()
        };
    }

    SshAction {
        accept: true,
        allow_agent_forwarding: true,
        allow_local_port_forwarding: true,
        allow_remote_port_forwarding: true,
        ..SshAction::default()
    }
}

fn ssh_check_hold_url(base_url: &str, auth_id: Option<&str>) -> String {
    let mut url = format!(
        "{}/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER",
        base_url.trim_end_matches('/')
    );
    if let Some(auth_id) = auth_id {
        url.push_str("&auth_id=");
        url.push_str(auth_id);
    }
    url
}

pub(crate) fn ssh_check_hold_url_with_auth(base_url: &str, auth_id: &str) -> String {
    ssh_check_hold_url(base_url, Some(auth_id))
}

fn check_period_from_rule(check_period: Option<&str>) -> Duration {
    match check_period {
        None => SSH_CHECK_PERIOD_DEFAULT,
        Some("always" | "0") => Duration::ZERO,
        Some(period) => parse_duration_nanos(period)
            .and_then(|nanos| u64::try_from(nanos).ok())
            .map_or(SSH_CHECK_PERIOD_DEFAULT, Duration::from_nanos),
    }
}

fn parse_duration_nanos(input: &str) -> Option<i64> {
    if input.is_empty() {
        return None;
    }
    if input == "always" {
        return Some(0);
    }

    let bytes = input.as_bytes();
    let mut pos = 0usize;
    let mut negative = false;
    if bytes[pos] == b'+' || bytes[pos] == b'-' {
        negative = bytes[pos] == b'-';
        pos += 1;
        if pos == bytes.len() {
            return None;
        }
    }
    if &input[pos..] == "0" {
        return Some(0);
    }

    let mut total: i128 = 0;
    while pos < bytes.len() {
        let start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        let has_integer = pos > start;
        let whole: i128 = if has_integer {
            input[start..pos].parse().ok()?
        } else {
            0
        };

        let mut fraction = 0i128;
        let mut scale = 1i128;
        let mut has_fraction = false;
        if pos < bytes.len() && bytes[pos] == b'.' {
            pos += 1;
            while pos < bytes.len() && bytes[pos].is_ascii_digit() {
                has_fraction = true;
                if scale < 1_000_000_000_000_000_000 {
                    fraction = fraction
                        .checked_mul(10)?
                        .checked_add(i128::from(bytes[pos] - b'0'))?;
                    scale = scale.checked_mul(10)?;
                }
                pos += 1;
            }
        }
        if !has_integer && !has_fraction {
            return None;
        }

        let unit_start = pos;
        while pos < bytes.len() && !bytes[pos].is_ascii_digit() && bytes[pos] != b'.' {
            pos += 1;
        }
        if unit_start == pos {
            return None;
        }
        let unit = &input[unit_start..pos];
        let multiplier: i128 = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 60 * 60 * 1_000_000_000,
            _ => return None,
        };
        let whole_nanos = whole.checked_mul(multiplier)?;
        let fraction_nanos = fraction.checked_mul(multiplier)?.checked_div(scale)?;
        total = total
            .checked_add(whole_nanos)?
            .checked_add(fraction_nanos)?;
    }
    if negative {
        total = total.checked_neg()?;
    }
    i64::try_from(total).ok()
}

fn user_matches(entry: &str, user: &str) -> bool {
    entry == user || entry.strip_suffix('@') == Some(user) || user.strip_suffix('@') == Some(entry)
}

fn canonical_localpart_domains(users: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for user in users {
        if let Some(domain) = canonical_localpart_domain(user) {
            push_unique_string(&mut out, domain.to_ascii_lowercase());
        }
    }
    out
}

fn users_have_canonical_localpart(users: &[String]) -> bool {
    users
        .iter()
        .any(|user| canonical_localpart_domain(user).is_some())
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

fn localpart_for_user(user: &str, domains: &[String]) -> Option<String> {
    let (localpart, domain) = user.rsplit_once('@')?;
    if domains
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(domain))
    {
        Some(localpart.to_string())
    } else {
        None
    }
}

fn is_untagged_user_owned(node: &SshPolicyNode) -> bool {
    node.tags.is_empty()
        && (node.user_id.is_some() || node.user.as_deref().is_some_and(|user| !user.is_empty()))
}

fn tag_matches(node_tag: &str, policy_tag_without_prefix: &str) -> bool {
    node_tag == policy_tag_without_prefix
        || node_tag.strip_prefix("tag:") == Some(policy_tag_without_prefix)
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
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice".into()),
                user_id: None,
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
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("user1".into()),
                user_id: None,
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 3,
                user: Some("user2".into()),
                user_id: None,
                addrs: vec!["100.64.0.3".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 4,
                user: Some("user3".into()),
                user_id: None,
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
    fn autogroup_self_matches_same_numeric_user_id_without_user_label_match() {
        let doc = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "check",
                "checkPeriod": "1h",
                "src": ["autogroup:member"],
                "dst": ["autogroup:self"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("alice".into()),
                user_id: Some(42),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some(String::new()),
                user_id: Some(42),
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 3,
                user: Some("tagged".into()),
                user_id: Some(42),
                addrs: vec!["100.64.0.3".into()],
                tags: vec!["tag:client".into()],
            },
        ];

        let pol = compile_ssh_policy(&doc, &nodes, 2).unwrap();

        assert_eq!(pol.rules.len(), 1);
        assert_eq!(
            principal_ips_for_rule(&pol.rules[0]),
            vec!["100.64.0.1", "100.64.0.2"]
        );
        assert_eq!(
            ssh_check_period_for(&doc, &nodes, 1, 2, "root"),
            Some(Duration::from_secs(60 * 60))
        );
        assert_eq!(ssh_check_period_for(&doc, &nodes, 3, 2, "root"), None);
    }

    #[test]
    fn autogroup_self_does_not_match_different_numeric_user_ids_with_same_label() {
        let doc = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "check",
                "checkPeriod": "1h",
                "src": ["autogroup:member"],
                "dst": ["autogroup:self"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("alice".into()),
                user_id: Some(1),
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice".into()),
                user_id: Some(2),
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 3,
                user: Some("alice".into()),
                user_id: None,
                addrs: vec!["100.64.0.3".into()],
                tags: Vec::new(),
            },
        ];

        let pol = compile_ssh_policy(&doc, &nodes, 2).unwrap();

        assert_eq!(pol.rules.len(), 1);
        assert_eq!(principal_ips_for_rule(&pol.rules[0]), vec!["100.64.0.2"]);
        assert_eq!(ssh_check_period_for(&doc, &nodes, 1, 2, "root"), None);
        assert_eq!(ssh_check_period_for(&doc, &nodes, 3, 2, "root"), None);
    }

    #[test]
    fn check_action_delegates_and_check_period_stays_server_side() {
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
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice".into()),
                user_id: None,
                addrs: vec!["100.64.0.2".into()],
                tags: vec!["tag:db".into()],
            },
        ];
        let pol =
            compile_ssh_policy_with_base_url(&doc, &nodes, 2, "https://headscale.example").unwrap();
        assert!(!pol.rules[0].action.accept);
        assert!(!pol.rules[0].action.reject);
        assert_eq!(pol.rules[0].action.session_duration, 0);
        assert_eq!(
            pol.rules[0].action.hold_and_delegate,
            "https://headscale.example/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER"
        );
        assert_eq!(
            ssh_check_period_for(&doc, &nodes, 1, 2, "admin"),
            Some(Duration::from_secs(24 * 60 * 60))
        );
        assert_eq!(ssh_check_period_for(&doc, &nodes, 1, 2, "root"), None);
    }

    #[test]
    fn recording_policy_fields_are_rejected_like_headscale_go() {
        for (field, value) in [
            ("recorders", r#"["100.64.0.10:1234"]"#),
            (
                "onRecordingFailure",
                r#"{"RejectSessionWithMessage":"recording required"}"#,
            ),
        ] {
            let raw = format!(
                r#"{{
                  "tagOwners": {{"tag:server": ["alice@"]}},
                  "ssh": [{{
                    "action": "accept",
                    "src": ["alice@"],
                    "dst": ["tag:server"],
                    "users": ["root"],
                    "{field}": {value}
                  }}]
                }}"#
            );
            let err = parse_hujson_policy(&raw).expect_err(field);
            let msg = err.to_string();

            assert!(
                msg.contains("unknown field") && msg.contains(field),
                "{field} should be rejected as an unsupported SSH policy field, got: {msg}"
            );
        }
    }

    #[test]
    fn compiled_ssh_actions_do_not_synthesize_recorders_like_headscale_go() {
        let doc = parse_hujson_policy(
            r#"{
              "tagOwners": {"tag:server": ["alice@"]},
              "ssh": [
                {
                  "action": "accept",
                  "src": ["alice@"],
                  "dst": ["tag:server"],
                  "users": ["root"]
                },
                {
                  "action": "check",
                  "src": ["alice@"],
                  "dst": ["tag:server"],
                  "users": ["deploy"]
                }
              ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("alice".into()),
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice".into()),
                user_id: None,
                addrs: vec!["100.64.0.2".into()],
                tags: vec!["tag:server".into()],
            },
        ];
        let pol =
            compile_ssh_policy_with_base_url(&doc, &nodes, 2, "https://headscale.example").unwrap();

        assert_eq!(pol.rules.len(), 2);
        assert!(
            pol.rules
                .iter()
                .all(|rule| rule.action.recorders.is_empty())
        );
        assert!(
            pol.rules
                .iter()
                .all(|rule| rule.action.on_recording_failure.is_none())
        );

        let check = &pol.rules[0].action;
        assert!(!check.accept);
        assert!(check.hold_and_delegate.contains("/machine/ssh/action/"));

        let accept = &pol.rules[1].action;
        assert!(accept.accept);
        assert!(accept.hold_and_delegate.is_empty());
    }

    #[test]
    fn fractional_check_period_uses_go_duration_grammar() {
        let doc = parse_hujson_policy(
            r#"{
              "groups": {"group:admins": ["bob@"]},
              "tagOwners": {"tag:db": ["alice@"]},
              "ssh": [{
                "action": "check",
                "checkPeriod": "1.5h",
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
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice".into()),
                user_id: None,
                addrs: vec!["100.64.0.2".into()],
                tags: vec!["tag:db".into()],
            },
        ];

        assert_eq!(
            ssh_check_period_for(&doc, &nodes, 1, 2, "admin"),
            Some(Duration::from_secs(90 * 60))
        );
    }

    #[test]
    fn accept_env_compiles_to_tailcfg_rule_like_headscale_go() {
        let doc = parse_hujson_policy(
            r#"{
              "tagOwners": {"tag:server": ["alice@"]},
              "ssh": [{
                "action": "accept",
                "acceptEnv": ["LANG", "LC_*"],
                "src": ["alice@"],
                "dst": ["tag:server"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("alice".into()),
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice".into()),
                user_id: None,
                addrs: vec!["100.64.0.2".into()],
                tags: vec!["tag:server".into()],
            },
        ];
        let pol = compile_ssh_policy(&doc, &nodes, 2).unwrap();

        assert_eq!(pol.rules[0].accept_env, vec!["LANG", "LC_*"]);
        assert_eq!(pol.rules[0].ssh_users["root"], "root");
    }

    #[test]
    fn tagged_sources_preserve_per_tag_principal_duplicates_like_headscale_go() {
        let doc = parse_hujson_policy(
            r#"{
              "tagOwners": {"tag:client": ["alice@"], "tag:server": ["alice@"]},
              "ssh": [{
                "action": "accept",
                "src": ["tag:client"],
                "dst": ["tag:server"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("alice".into()),
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: vec!["tag:client".into(), "tag:admin".into()],
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice".into()),
                user_id: None,
                addrs: vec!["100.64.0.2".into()],
                tags: vec!["tag:server".into()],
            },
        ];
        let pol = compile_ssh_policy(&doc, &nodes, 2).unwrap();

        assert_eq!(
            principal_ips_for_rule(&pol.rules[0]),
            vec!["100.64.0.1", "100.64.0.1"]
        );
    }

    #[test]
    fn canonical_localpart_users_compile_per_matching_source_user() {
        let doc = parse_hujson_policy(
            r#"{
              "tagOwners": {"tag:server": ["alice@example.com"]},
              "ssh": [{
                "action": "accept",
                "src": ["autogroup:member"],
                "dst": ["tag:server"],
                "users": ["localpart:*@EXAMPLE.COM", "ubuntu"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("alice@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("bob@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 3,
                user: Some("eve@other.example".into()),
                user_id: None,
                addrs: vec!["100.64.0.3".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 4,
                user: Some("alice@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.4".into()],
                tags: vec!["tag:server".into()],
            },
        ];

        let pol = compile_ssh_policy(&doc, &nodes, 4).unwrap();

        assert_eq!(pol.rules.len(), 5);
        assert_eq!(principal_ips_for_rule(&pol.rules[0]), vec!["100.64.0.1"]);
        assert_eq!(pol.rules[0].ssh_users["root"], "");
        assert_eq!(pol.rules[0].ssh_users["ubuntu"], "ubuntu");
        assert_eq!(pol.rules[1].ssh_users["alice"], "alice");
        assert!(
            !pol.rules[1]
                .ssh_users
                .contains_key("localpart:*@EXAMPLE.COM")
        );
        assert_eq!(principal_ips_for_rule(&pol.rules[2]), vec!["100.64.0.2"]);
        assert_eq!(pol.rules[2].ssh_users["root"], "");
        assert_eq!(pol.rules[2].ssh_users["ubuntu"], "ubuntu");
        assert_eq!(pol.rules[3].ssh_users["bob"], "bob");
        assert_eq!(principal_ips_for_rule(&pol.rules[4]), vec!["100.64.0.3"]);
        assert_eq!(pol.rules[4].ssh_users["root"], "");
        assert_eq!(pol.rules[4].ssh_users["ubuntu"], "ubuntu");
        assert!(!pol.rules[4].ssh_users.contains_key("eve"));
    }

    #[test]
    fn canonical_localpart_users_apply_to_autogroup_self() {
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
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 3,
                user: Some("bob@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.3".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 4,
                user: Some("bob@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.4".into()],
                tags: Vec::new(),
            },
        ];

        let alice_target = compile_ssh_policy(&doc, &nodes, 2).unwrap();
        let bob_target = compile_ssh_policy(&doc, &nodes, 4).unwrap();

        assert_eq!(alice_target.rules.len(), 2);
        assert_eq!(
            principal_ips_for_rule(&alice_target.rules[0]),
            vec!["100.64.0.1", "100.64.0.2"]
        );
        assert_eq!(alice_target.rules[0].ssh_users["root"], "");
        assert_eq!(alice_target.rules[1].ssh_users["alice"], "alice");

        assert_eq!(bob_target.rules.len(), 2);
        assert_eq!(
            principal_ips_for_rule(&bob_target.rules[0]),
            vec!["100.64.0.3", "100.64.0.4"]
        );
        assert_eq!(bob_target.rules[0].ssh_users["root"], "");
        assert_eq!(bob_target.rules[1].ssh_users["bob"], "bob");
    }

    #[test]
    fn malformed_localpart_users_stay_literal() {
        let doc = parse_hujson_policy(
            r#"{
              "tagOwners": {"tag:server": ["alice@example.com"]},
              "ssh": [{
                "action": "accept",
                "src": ["alice@example.com"],
                "dst": ["tag:server"],
                "users": ["localpart:alice@example.com", "localpart:*@"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("alice@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.2".into()],
                tags: vec!["tag:server".into()],
            },
        ];

        let pol = compile_ssh_policy(&doc, &nodes, 2).unwrap();

        assert_eq!(pol.rules.len(), 1);
        assert_eq!(
            pol.rules[0].ssh_users["localpart:alice@example.com"],
            "localpart:alice@example.com"
        );
        assert_eq!(pol.rules[0].ssh_users["localpart:*@"], "localpart:*@");
    }

    #[test]
    fn localpart_plus_root_users_compile_for_member_destinations() {
        let doc = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": "accept",
                "src": ["autogroup:member"],
                "dst": ["autogroup:member", "autogroup:tagged"],
                "users": ["localpart:*@example.com", "root"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            SshPolicyNode {
                id: 1,
                user: Some("alice@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("bob@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
            },
        ];

        let pol = compile_ssh_policy(&doc, &nodes, 2).unwrap();

        assert_eq!(pol.rules.len(), 4);
        assert_eq!(principal_ips_for_rule(&pol.rules[0]), vec!["100.64.0.1"]);
        assert_eq!(pol.rules[0].ssh_users["root"], "root");
        assert_eq!(pol.rules[1].ssh_users["alice"], "alice");
        assert_eq!(principal_ips_for_rule(&pol.rules[2]), vec!["100.64.0.2"]);
        assert_eq!(pol.rules[2].ssh_users["root"], "root");
        assert_eq!(pol.rules[3].ssh_users["bob"], "bob");
        for rule in &pol.rules {
            assert!(
                !rule.ssh_users.contains_key("localpart:*@example.com"),
                "the localpart pattern must not leak into client-facing login users"
            );
        }
    }

    #[test]
    fn localpart_sources_get_self_access_when_target_is_not_destination() {
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
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: Some("alice@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.2".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 3,
                user: Some("bob@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.3".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 4,
                user: Some("alice@example.com".into()),
                user_id: None,
                addrs: vec!["100.64.0.4".into()],
                tags: vec!["tag:server".into()],
            },
        ];

        let pol = compile_ssh_policy(&doc, &nodes, 2).unwrap();

        assert_eq!(pol.rules.len(), 2);
        assert_eq!(
            principal_ips_for_rule(&pol.rules[0]),
            vec!["100.64.0.1", "100.64.0.2"]
        );
        assert_eq!(pol.rules[0].ssh_users["root"], "");
        assert_eq!(pol.rules[1].ssh_users["alice"], "alice");
    }

    #[test]
    fn tagged_localpart_source_self_access_uses_unique_target_principals() {
        let doc = parse_hujson_policy(
            r#"{
              "tagOwners": {"tag:client": ["alice@example.com"], "tag:server": ["alice@example.com"]},
              "ssh": [{
                "action": "accept",
                "src": ["tag:client"],
                "dst": ["tag:server"],
                "users": ["localpart:*@example.com", "deploy"]
              }]
            }"#,
        )
        .unwrap();
        let nodes = vec![SshPolicyNode {
            id: 1,
            user: Some("alice@example.com".into()),
            user_id: None,
            addrs: vec!["100.64.0.1".into()],
            tags: vec!["tag:client".into(), "tag:admin".into()],
        }];

        let pol = compile_ssh_policy(&doc, &nodes, 1).unwrap();

        assert_eq!(pol.rules.len(), 1);
        assert_eq!(principal_ips_for_rule(&pol.rules[0]), vec!["100.64.0.1"]);
        assert_eq!(pol.rules[0].ssh_users["root"], "");
        assert_eq!(pol.rules[0].ssh_users["deploy"], "deploy");
        assert!(!pol.rules[0].ssh_users.contains_key("alice"));
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
                user_id: None,
                addrs: vec!["100.64.0.1".into()],
                tags: Vec::new(),
            },
            SshPolicyNode {
                id: 2,
                user: None,
                user_id: None,
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
