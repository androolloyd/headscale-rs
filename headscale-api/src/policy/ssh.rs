use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use super::{NodeView, PacketFilterNode, PolicyDoc, filter};
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

/// Content plus native slice shape retained for per-connection reflection
/// equality. The wire projection intentionally keeps its existing field types.
#[derive(Clone, Default, Eq, PartialEq)]
pub(crate) struct NativeSshPolicy {
    pub(crate) policy: SshPolicy,
    accept_env_nil: Vec<bool>,
}

const SSH_CHECK_PERIOD_DEFAULT: Duration = Duration::from_secs(12 * 60 * 60);

/// Operator opt-out for the three forwarding permissions carried by every
/// `tailcfg.SSHAction` the control server sends.
///
/// headscale-go v0.29.5 hard-codes `AllowAgentForwarding`,
/// `AllowLocalPortForwarding` and `AllowRemotePortForwarding` to true on
/// accepted rules (`policy/v2/filter.go` `sshAccept`) and on the dynamic
/// check-mode actions (`noise.go` `sshAction`), so the default here is
/// all-true to stay byte-compatible. Setting a flag to false makes
/// headscale-rs emit it as false everywhere; see `policy.ssh` in the server
/// config and `docs/HARDENING.md`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SshForwarding {
    pub agent: bool,
    pub local_port: bool,
    pub remote_port: bool,
}

impl Default for SshForwarding {
    fn default() -> Self {
        Self::ALLOW_ALL
    }
}

impl SshForwarding {
    /// headscale-go's behaviour: every forwarding permission granted.
    pub const ALLOW_ALL: Self = Self {
        agent: true,
        local_port: true,
        remote_port: true,
    };

    /// Base for the dynamic check-mode actions (`/machine/ssh/action`).
    /// Go starts every one of them, including hold-and-delegate and reject,
    /// from an action with all three flags set, so the operator setting
    /// applies to all of them alike.
    pub(crate) fn base_action(self) -> SshAction {
        SshAction {
            allow_agent_forwarding: self.agent,
            allow_local_port_forwarding: self.local_port,
            allow_remote_port_forwarding: self.remote_port,
            ..SshAction::default()
        }
    }

    /// Narrow a compiled policy to what the operator allows. This only ever
    /// clears flags: check-mode rules, whose static action is already
    /// all-false in Go, are untouched, and with the default every action is
    /// byte-identical to the compiler output.
    pub(crate) fn restrict(self, policy: &mut SshPolicy) {
        if self == Self::ALLOW_ALL {
            return;
        }
        for rule in &mut policy.rules {
            rule.action.allow_agent_forwarding &= self.agent;
            rule.action.allow_local_port_forwarding &= self.local_port;
            rule.action.allow_remote_port_forwarding &= self.remote_port;
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SshUserRule {
    ssh_users: BTreeMap<String, String>,
    source_node_ids: BTreeSet<u64>,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
enum SourceOwner {
    User(u64),
    Legacy(String),
    Tagged,
}

fn source_owner(node: &SshPolicyNode) -> Option<SourceOwner> {
    if !node.tags.is_empty() {
        Some(SourceOwner::Tagged)
    } else if let Some(id) = node.user_id {
        Some(SourceOwner::User(id))
    } else {
        node.user
            .as_ref()
            .filter(|user| !user.is_empty())
            .cloned()
            .map(SourceOwner::Legacy)
    }
}

/// Compile a headscale policy `ssh` block into the `tailcfg.SSHPolicy`
/// shape sent in `MapResponse.SSHPolicy`.
///
/// Mirrors headscale-go v0.29.5's policy/v2 compiler for the currently
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
    compile_ssh_policy_for_target(doc, nodes, target_node, base_url)
}

pub(super) fn compile_ssh_policy_for_target(
    doc: &PolicyDoc,
    nodes: &[SshPolicyNode],
    target_node: &SshPolicyNode,
    base_url: &str,
) -> Option<SshPolicy> {
    compile_ssh_policy_snapshot(doc, nodes, target_node, base_url, &[])
        .map(|snapshot| snapshot.policy)
}

pub(super) fn compile_ssh_policy_snapshot(
    doc: &PolicyDoc,
    nodes: &[SshPolicyNode],
    target_node: &SshPolicyNode,
    base_url: &str,
    rule_accept_env_nil: &[bool],
) -> Option<NativeSshPolicy> {
    if doc.ssh.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    let mut accept_env_nil = Vec::new();

    for (index, rule) in doc.ssh.iter().enumerate() {
        let start = out.len();
        let source_nodes = resolve_ssh_source_nodes(doc, &rule.src, nodes);
        if source_nodes.is_empty() {
            continue;
        }

        let action = ssh_action(base_url, &rule.action);
        let ssh_user_rules = ssh_user_rules(doc, &rule.users, &source_nodes);
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
                .any(|dst| ssh_destination_matches(doc, dst, target_node, nodes))
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
        accept_env_nil.extend(std::iter::repeat_n(
            rule.accept_env.is_empty() && rule_accept_env_nil.get(index).copied().unwrap_or(false),
            out.len() - start,
        ));
    }

    let mut paired = out.into_iter().zip(accept_env_nil).collect::<Vec<_>>();
    paired.sort_by_key(|(rule, _)| i32::from(rule.action.hold_and_delegate.is_empty()));
    let (rules, accept_env_nil) = paired.into_iter().unzip();
    Some(NativeSshPolicy {
        policy: SshPolicy { rules },
        accept_env_nil,
    })
}

pub fn ssh_check_period_for(
    doc: &PolicyDoc,
    nodes: &[SshPolicyNode],
    src_node_id: u64,
    dst_node_id: u64,
    local_user: &str,
) -> Option<Duration> {
    ssh_check_period_for_bytes(doc, nodes, src_node_id, dst_node_id, local_user.as_bytes())
}

pub(super) fn ssh_check_period_for_bytes(
    doc: &PolicyDoc,
    nodes: &[SshPolicyNode],
    src_node_id: u64,
    dst_node_id: u64,
    local_user: &[u8],
) -> Option<Duration> {
    if doc.ssh.is_empty() || local_user.is_empty() {
        return None;
    }
    let src_node = nodes.iter().find(|node| node.id == src_node_id)?;
    let dst_node = nodes.iter().find(|node| node.id == dst_node_id)?;

    for rule in &doc.ssh {
        if rule.action != "check" {
            continue;
        }
        let Ok(source_ips) = resolved_ssh_aliases(doc, &rule.src, nodes).checked() else {
            continue;
        };
        let source_nodes = ssh_source_nodes_for_ips(&source_ips, nodes);
        if !source_nodes.iter().any(|node| node.id == src_node.id) {
            continue;
        }
        if !ssh_rule_allows_user(doc, &rule.users, src_node, local_user) {
            continue;
        }
        for dst in &rule.dst {
            if dst == "autogroup:self" {
                if same_ssh_user_owner(src_node, dst_node) {
                    return Some(check_period_from_rule(rule.check_period.as_deref()));
                }
                continue;
            }

            if resolved_ssh_aliases(doc, std::slice::from_ref(dst), nodes)
                .checked()
                .is_ok_and(|ips| filter::any_ip_matches(&ips, &ssh_node_view(dst_node)))
            {
                return Some(check_period_from_rule(rule.check_period.as_deref()));
            }
        }
        if users_have_canonical_localpart(&rule.users)
            && rule.dst.iter().any(|dst| dst != "autogroup:self")
            && source_nodes.iter().any(|node| node.id == dst_node_id)
            && ((is_untagged_user_owned(dst_node) && same_ssh_user_owner(src_node, dst_node))
                || (!is_untagged_user_owned(dst_node) && src_node_id == dst_node_id))
        {
            return Some(check_period_from_rule(rule.check_period.as_deref()));
        }
    }

    None
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
    let mut by_user: BTreeMap<SourceOwner, Vec<String>> = BTreeMap::new();
    let mut tagged = Vec::new();
    for node in nodes {
        if !rule.source_node_ids.contains(&node.id) {
            continue;
        }
        if node.tags.is_empty() {
            if let Some(owner) = source_owner(node) {
                by_user
                    .entry(owner)
                    .or_default()
                    .extend(node.addrs.iter().cloned());
            }
        } else {
            for _ in 0..node.tags.len() {
                for addr in &node.addrs {
                    // Tagged principals use Addr.String directly, including
                    // zones and the typed zero Addr's "invalid IP" display.
                    tagged.push(if addr.is_empty() {
                        "invalid IP".into()
                    } else {
                        headscale_api_acl::go_netip::addr_text(addr).unwrap_or_else(|| addr.clone())
                    });
                }
            }
        }
    }
    let mut out = Vec::new();
    for addresses in by_user.into_values() {
        // One IPSet per numeric account, followed by the raw tagged list.
        // IPRangeFrom removes zones; any invalid typed address invalidates
        // this account's builder instead of silently dropping one address.
        if let Some(ips) = ipset_principal_addresses(&addresses) {
            out.extend(ips);
        }
    }
    out.extend(tagged);
    out
}

fn ipset_principal_addresses(addresses: &[String]) -> Option<Vec<String>> {
    addresses
        .iter()
        .map(|address| {
            let (address, _) = headscale_api_acl::go_netip::parse_addr(address).ok()?;
            Some(address)
        })
        .collect::<Option<BTreeSet<_>>>()
        .map(|addresses| {
            addresses
                .into_iter()
                .map(|address| address.to_string())
                .collect()
        })
}

fn unique_node_addrs(node: &SshPolicyNode) -> Vec<String> {
    ipset_principal_addresses(&node.addrs).unwrap_or_default()
}

fn ssh_node_view(node: &SshPolicyNode) -> NodeView<'_> {
    NodeView {
        user_id: node.user_id,
        user: node.user.as_deref(),
        addr: node.addrs.first().map(String::as_str),
        addrs: &node.addrs,
        tags: &node.tags,
    }
}

fn resolve_ssh_aliases(
    doc: &PolicyDoc,
    aliases: &[String],
    nodes: &[SshPolicyNode],
) -> Vec<String> {
    resolved_ssh_aliases(doc, aliases, nodes).partial()
}

fn resolved_ssh_aliases(
    doc: &PolicyDoc,
    aliases: &[String],
    nodes: &[SshPolicyNode],
) -> super::resolution::ResolvedAlias {
    let nodes = nodes
        .iter()
        .map(|node| PacketFilterNode {
            id: node.id,
            user_id: node.user_id,
            user: node.user.clone(),
            addrs: node.addrs.clone(),
            tags: node.tags.clone(),
            routes: Vec::new(),
        })
        .collect::<Vec<_>>();
    super::resolution::aliases(doc, aliases, &nodes)
}

fn resolve_ssh_source_nodes<'a>(
    doc: &PolicyDoc,
    tokens: &[String],
    nodes: &'a [SshPolicyNode],
) -> Vec<&'a SshPolicyNode> {
    // Sources resolve to an IP set before grouping nodes by their numeric
    // owner. A second node sharing a matching IP is included, as in Go.
    let ips = resolve_ssh_aliases(doc, tokens, nodes);
    ssh_source_nodes_for_ips(&ips, nodes)
}

fn ssh_source_nodes_for_ips<'a>(
    ips: &[String],
    nodes: &'a [SshPolicyNode],
) -> Vec<&'a SshPolicyNode> {
    // groupSourcesByUser walks the retained node slice. User principal sets
    // are sorted separately by owner/address, while tagged principals retain
    // node order and per-tag duplication from this slice.
    nodes
        .iter()
        .filter(|node| filter::any_ip_matches(ips, &ssh_node_view(node)))
        .collect()
}

fn ssh_destination_matches(
    doc: &PolicyDoc,
    token: &str,
    node: &SshPolicyNode,
    nodes: &[SshPolicyNode],
) -> bool {
    // The target may be a current quiet NodeStore view, but destination
    // aliases resolve through the policy manager's retained node list.
    let ips = resolve_ssh_aliases(doc, &[token.to_owned()], nodes);
    filter::any_ip_matches(&ips, &ssh_node_view(node))
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

fn ssh_user_rules(
    doc: &PolicyDoc,
    users: &[String],
    source_nodes: &[&SshPolicyNode],
) -> Vec<SshUserRule> {
    let all_source_node_ids: BTreeSet<u64> = source_nodes
        .iter()
        .filter(|node| source_owner(node).is_some())
        .map(|node| node.id)
        .collect();
    let localpart_domains = canonical_localpart_domains(users);
    if !localpart_domains.is_empty() {
        return ssh_user_rules_with_localparts(doc, users, source_nodes, &localpart_domains);
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
    doc: &PolicyDoc,
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

    let mut groups: BTreeMap<SourceOwner, (Option<String>, BTreeSet<u64>)> = BTreeMap::new();
    for node in source_nodes {
        let user = if is_untagged_user_owned(node) {
            node.user.clone()
        } else {
            None
        };
        let Some(owner) = source_owner(node) else {
            continue;
        };
        groups
            .entry(owner)
            .or_insert_with(|| (user, BTreeSet::new()))
            .1
            .insert(node.id);
    }

    let mut rules = Vec::new();
    for (owner, (user, source_node_ids)) in groups {
        rules.push(SshUserRule {
            ssh_users: base.clone(),
            source_node_ids: source_node_ids.clone(),
        });
        let localpart = localpart_for_owner(doc, &owner, user.as_deref(), localpart_domains);
        if let Some(localpart) = localpart {
            rules.push(SshUserRule {
                ssh_users: BTreeMap::from([(localpart.clone(), localpart)]),
                source_node_ids,
            });
        }
    }
    rules
}

fn localpart_for_owner(
    doc: &PolicyDoc,
    owner: &SourceOwner,
    legacy_user: Option<&str>,
    domains: &[String],
) -> Option<String> {
    match (owner, &doc.users) {
        (SourceOwner::User(id), Some(accounts)) => domains
            .iter()
            .flat_map(|domain| {
                accounts
                    .iter()
                    .filter(move |account| account.id == *id)
                    .filter_map(move |account| localpart_for_domain(&account.email, domain))
            })
            .last(),
        (SourceOwner::Tagged, _) | (_, Some(_)) => None,
        (_, None) => legacy_user.and_then(|user| localpart_for_user(user, domains)),
    }
}

/// SSHCheckParams evaluates rule users directly, independently of whether
/// groupSourcesByUser can emit a principal for this source's association.
fn ssh_rule_allows_user(
    doc: &PolicyDoc,
    users: &[String],
    source: &SshPolicyNode,
    local_user: &[u8],
) -> bool {
    if local_user.is_empty() {
        return false;
    }
    let is_root = local_user == b"root";
    if (is_root && users.iter().any(|user| user == "root"))
        || (!is_root
            && users.iter().any(|user| {
                user == "autogroup:nonroot"
                    || (user.as_bytes() == local_user && canonical_localpart_domain(user).is_none())
            }))
    {
        return true;
    }
    if !is_untagged_user_owned(source) {
        return false;
    }
    let Some(owner) = source_owner(source) else {
        return false;
    };
    localpart_for_owner(
        doc,
        &owner,
        source.user.as_deref(),
        &canonical_localpart_domains(users),
    )
    .is_some_and(|localpart| localpart.as_bytes() == local_user)
}

fn ssh_action(base_url: &str, action: &str) -> SshAction {
    if action == "check" {
        return SshAction {
            hold_and_delegate: ssh_check_hold_url(base_url),
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

fn ssh_check_hold_url(base_url: &str) -> String {
    format!("{base_url}/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER")
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
    if input == "always" {
        Some(0)
    } else {
        headscale_api_acl::go_duration::parse_nanos(input).ok()
    }
}

fn canonical_localpart_domains(users: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for user in users {
        if let Some(domain) = canonical_localpart_domain(user) {
            out.push(domain.to_string());
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

fn localpart_for_domain(user: &str, expected: &str) -> Option<String> {
    let (localpart, domain) = user.rsplit_once('@')?;
    headscale_api_acl::go_unicode::equal_fold(expected, domain).then(|| localpart.to_string())
}

fn localpart_for_user(user: &str, domains: &[String]) -> Option<String> {
    domains
        .iter()
        .filter_map(|domain| localpart_for_domain(user, domain))
        .next_back()
}

fn is_untagged_user_owned(node: &SshPolicyNode) -> bool {
    node.tags.is_empty()
        && (node.user_id.is_some() || node.user.as_deref().is_some_and(|user| !user.is_empty()))
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
        assert_eq!(ssh_check_period_for(&doc, &nodes, 1, 2, ""), None);
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
        assert_eq!(accept.hold_and_delegate, "");
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
        // headscale-go v0.29.5: autogroup:member is every untagged node
        // (policy/v2/types.go AutoGroupMember, no user check), so the userless
        // node is a member *destination* and receives the member->member rule;
        // autogroup:self only expands for nodes with a valid user. Confirmed
        // with the differential harness's Go side (pm.SSHPolicy for a node with
        // no user returns exactly this one rule, principal 100.64.0.1).
        assert_eq!(userless_target.rules.len(), 1);
        assert_eq!(
            principal_ips_for_rule(&userless_target.rules[0]),
            vec!["100.64.0.1"]
        );
        assert_eq!(userless_target.rules[0].ssh_users["deploy"], "deploy");
        assert_eq!(userless_target.rules[0].ssh_users["root"], "");
        assert_eq!(userless_target.rules[0].ssh_users.len(), 2);
    }

    fn forwarding_fixture() -> (PolicyDoc, Vec<SshPolicyNode>) {
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
        (doc, nodes)
    }

    fn forwarding_flags(action: &SshAction) -> [bool; 3] {
        [
            action.allow_agent_forwarding,
            action.allow_local_port_forwarding,
            action.allow_remote_port_forwarding,
        ]
    }

    #[test]
    fn compiled_ssh_actions_keep_headscale_go_forwarding_flags_by_default() {
        // policy/v2/filter.go: sshAccept sets all three, sshCheck none.
        let (doc, nodes) = forwarding_fixture();
        let store = crate::policy::PolicyStore::new();
        store.set(doc.clone(), "{}".into());
        assert_eq!(store.ssh_forwarding(), SshForwarding::ALLOW_ALL);

        let compiled =
            compile_ssh_policy_with_base_url(&doc, &nodes, 2, "https://h.example").unwrap();
        let served = store
            .ssh_policy_for(&nodes, 2, "https://h.example")
            .unwrap();
        assert_eq!(
            serde_json::to_string(&served).unwrap(),
            serde_json::to_string(&compiled).unwrap(),
            "default output is exactly the compiler output"
        );
        let accept = compiled
            .rules
            .iter()
            .find(|rule| rule.action.accept)
            .unwrap();
        let check = compiled
            .rules
            .iter()
            .find(|rule| !rule.action.hold_and_delegate.is_empty())
            .unwrap();
        assert_eq!(forwarding_flags(&accept.action), [true, true, true]);
        assert_eq!(forwarding_flags(&check.action), [false, false, false]);
    }

    #[test]
    fn forwarding_opt_out_clears_only_the_chosen_flags_on_served_policy() {
        let (doc, nodes) = forwarding_fixture();
        let default =
            compile_ssh_policy_with_base_url(&doc, &nodes, 2, "https://h.example").unwrap();
        let cases = [
            ([false, true, true], "agent"),
            ([true, false, true], "local port"),
            ([true, true, false], "remote port"),
            ([false, false, false], "all"),
        ];
        for (allowed, label) in cases {
            let store = crate::policy::PolicyStore::new();
            store.set(doc.clone(), "{}".into());
            store.set_ssh_forwarding(SshForwarding {
                agent: allowed[0],
                local_port: allowed[1],
                remote_port: allowed[2],
            });
            let served = store
                .ssh_policy_for(&nodes, 2, "https://h.example")
                .unwrap();

            assert_eq!(served.rules.len(), default.rules.len(), "{label}");
            for (got, want) in served.rules.iter().zip(&default.rules) {
                let mut expected = want.clone();
                if expected.action.accept {
                    expected.action.allow_agent_forwarding = allowed[0];
                    expected.action.allow_local_port_forwarding = allowed[1];
                    expected.action.allow_remote_port_forwarding = allowed[2];
                }
                assert_eq!(
                    serde_json::to_string(got).unwrap(),
                    serde_json::to_string(&expected).unwrap(),
                    "{label}: everything but the cleared flags is unchanged"
                );
            }
            let accept = served.rules.iter().find(|rule| rule.action.accept).unwrap();
            assert_eq!(forwarding_flags(&accept.action), allowed, "{label}");
        }
    }

    #[test]
    fn forwarding_opt_out_survives_policy_replacement() {
        let (doc, nodes) = forwarding_fixture();
        let store = crate::policy::PolicyStore::new();
        store.set_ssh_forwarding(SshForwarding {
            agent: false,
            local_port: false,
            remote_port: false,
        });
        for round in 0..3 {
            store.set(doc.clone(), format!("{{\"round\":{round}}}"));
            let served = store.ssh_policy_for(&nodes, 2, "").unwrap();
            let accept = served.rules.iter().find(|rule| rule.action.accept).unwrap();
            assert_eq!(
                forwarding_flags(&accept.action),
                [false, false, false],
                "round {round}"
            );
        }
    }

    #[test]
    fn restricting_forwarding_only_narrows_and_never_grants() {
        for bits in 0..8_u8 {
            let have = [bits & 1 != 0, bits & 2 != 0, bits & 4 != 0];
            for setting in 0..8_u8 {
                let allow = SshForwarding {
                    agent: setting & 1 != 0,
                    local_port: setting & 2 != 0,
                    remote_port: setting & 4 != 0,
                };
                let mut policy = SshPolicy {
                    rules: vec![SshRule {
                        action: SshAction {
                            accept: true,
                            allow_agent_forwarding: have[0],
                            allow_local_port_forwarding: have[1],
                            allow_remote_port_forwarding: have[2],
                            ..SshAction::default()
                        },
                        ..SshRule::default()
                    }],
                };
                allow.restrict(&mut policy);
                assert_eq!(
                    forwarding_flags(&policy.rules[0].action),
                    [
                        have[0] && allow.agent,
                        have[1] && allow.local_port,
                        have[2] && allow.remote_port,
                    ],
                    "have {have:?} under {allow:?}"
                );
                assert!(policy.rules[0].action.accept);
            }
        }
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
