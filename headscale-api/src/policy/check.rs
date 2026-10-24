// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Semantic evaluation for upstream policy `tests`.
//!
//! Parsing and shape validation live in `headscale-api-acl`. This
//! module owns the live-node pass used by gRPC `CheckPolicy` and
//! `SetPolicy`.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

use super::{PacketFilterNode, filter, matcher::IpSet, ssh::SshPolicyNode};
use crate::tailscale_wire::wire::{FilterRule, SshPolicy};
use headscale_api_acl::{
    AclDoc as PolicyDoc, NodeView, PolicyTest, SshPolicyTest, go_policy_shape, go_strconv,
};

/// Live node facts needed to evaluate policy tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCheckNode {
    pub id: u64,
    pub user_id: Option<u64>,
    pub name: String,
    pub user: Option<String>,
    pub addrs: Vec<String>,
    pub tags: Vec<String>,
}

impl PolicyCheckNode {
    /// Borrow all address families and the stored ownership for policy checks.
    pub fn as_view(&self) -> NodeView<'_> {
        NodeView {
            addr: self.addrs.first().map(String::as_str),
            addrs: &self.addrs,
            user: self.user.as_deref(),
            user_id: self.user_id,
            tags: &self.tags,
        }
    }
}

/// One node and its route facts from the same policy-input snapshot. The
/// legacy PolicyCheckNode fields stay unchanged for downstream callers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyCheckNodeSnapshot {
    pub node: PolicyCheckNode,
    pub advertised_routes: Vec<String>,
    pub approved_routes: Vec<String>,
}

impl PolicyCheckNodeSnapshot {
    /// Read identity, typed addresses and routes from one retained registry
    /// snapshot, including native association/zero-address metadata.
    pub fn from_registry(
        registry: &crate::tailscale_wire::MachineRegistry,
    ) -> Result<Vec<Self>, String> {
        let snapshot = registry.snapshot_with_metadata();
        let mut seen = BTreeSet::new();
        let mut nodes = Vec::with_capacity(snapshot.len());
        for (key, record) in &snapshot {
            let id = record.stable_node_id_for_key(key);
            if !seen.insert(id) {
                return Err("duplicate live node ID in policy snapshot".to_owned());
            }
            let (user_id, user) = snapshot.policy_identity(record);
            nodes.push(Self {
                node: PolicyCheckNode {
                    id,
                    user_id,
                    user,
                    name: record.hostname.clone(),
                    addrs: snapshot.policy_addresses(record),
                    tags: record.forced_tags.clone(),
                },
                advertised_routes: record.available_routes.clone(),
                approved_routes: record.approved_routes.clone(),
            });
        }
        nodes.sort_by_key(|snapshot| snapshot.node.id);
        Ok(nodes)
    }

    fn active_routes(&self) -> Vec<String> {
        // Go iterates announcements and tests typed-prefix membership in
        // approvals. Preserve announcement order and multiplicity.
        self.advertised_routes
            .iter()
            .filter(|route| self.approved_routes.contains(route))
            .cloned()
            .collect()
    }
}

/// Compile an isolated candidate using the same retained node and route facts
/// as policy checks. This runs constructor compilation without evaluating
/// policy tests or emitting their boot warnings.
pub fn compile_policy_for_snapshot(
    doc: &PolicyDoc,
    raw: &str,
    snapshots: &[PolicyCheckNodeSnapshot],
) -> Result<(), String> {
    super::PolicyStore::from_initial_inputs(
        Some((doc.clone(), raw.to_owned(), super::now_unix())),
        doc.users.clone(),
        snapshots
            .iter()
            .map(super::lifecycle::NodeInput::from_policy_check_snapshot)
            .collect(),
    )
    .map(|_| ())
}

/// Evaluate all currently supported policy semantic checks.
pub fn check_policy_semantics(doc: &PolicyDoc, nodes: &[PolicyCheckNode]) -> Result<(), String> {
    check_policy_semantics_inner(doc, None, nodes, None)
}

/// Evaluate a native candidate with its original ACL rows and nil-filter
/// default. Source metadata is used only for a matching public projection.
pub fn check_policy_semantics_for_source(
    doc: &PolicyDoc,
    raw: &str,
    nodes: &[PolicyCheckNode],
) -> Result<(), String> {
    check_policy_semantics_inner(doc, Some(raw), nodes, None)
}

/// Evaluate a native candidate using identity/address/route facts captured
/// together, without extending the legacy public node representation.
pub fn check_policy_semantics_for_snapshot(
    doc: &PolicyDoc,
    raw: &str,
    snapshots: &[PolicyCheckNodeSnapshot],
) -> Result<(), String> {
    let nodes = snapshots
        .iter()
        .map(|snapshot| snapshot.node.clone())
        .collect::<Vec<_>>();
    check_policy_semantics_inner(doc, Some(raw), &nodes, Some(snapshots))
}

fn check_policy_semantics_inner(
    doc: &PolicyDoc,
    raw: Option<&str>,
    nodes: &[PolicyCheckNode],
    snapshots: Option<&[PolicyCheckNodeSnapshot]>,
) -> Result<(), String> {
    let (acl_errors, ssh_errors) = policy_test_failures(doc, raw, nodes, snapshots);
    let errors = std::iter::once(acl_errors)
        .chain(std::iter::once(ssh_errors))
        .filter(|errors| !errors.is_empty())
        .map(|errors| format!("test(s) failed:\n{}", errors.join("\n")))
        .collect::<Vec<_>>();
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.into_iter().next().unwrap()),
        // tailscale.com/util/multierr prefixes each complete error with a tab;
        // it does not indent the embedded newlines inside that error.
        _ => Err(format!("multiple errors:\n\t{}", errors.join("\n\t"))),
    }
}

/// Return ACL and SSH failures separately for the boot warning boundary.
/// Boot callers can report failures without rejecting a stored policy, while
/// user-write/check callers retain the combined hard-failure boundary above.
fn policy_test_failures(
    doc: &PolicyDoc,
    raw: Option<&str>,
    nodes: &[PolicyCheckNode],
    snapshots: Option<&[PolicyCheckNodeSnapshot]>,
) -> (Vec<String>, Vec<String>) {
    (
        run_policy_tests(doc, raw, nodes, snapshots),
        run_ssh_policy_tests(doc, nodes),
    )
}

/// Report both classes of stored-policy test failures without rejecting boot.
/// Callers validate policy structure and user references before this point.
pub fn warn_policy_tests_at_boot(doc: &PolicyDoc, nodes: &[PolicyCheckNode]) {
    warn_policy_tests_at_boot_inner(doc, None, nodes, None);
}

/// Boot warnings use the same source-aware sandbox as the write boundary.
pub fn warn_policy_tests_at_boot_for_source(doc: &PolicyDoc, raw: &str, nodes: &[PolicyCheckNode]) {
    warn_policy_tests_at_boot_inner(doc, Some(raw), nodes, None);
}

/// Warn on stored policy failures using a retained native route snapshot.
pub fn warn_policy_tests_at_boot_for_snapshot(
    doc: &PolicyDoc,
    raw: &str,
    snapshots: &[PolicyCheckNodeSnapshot],
) {
    let nodes = snapshots
        .iter()
        .map(|snapshot| snapshot.node.clone())
        .collect::<Vec<_>>();
    warn_policy_tests_at_boot_inner(doc, Some(raw), &nodes, Some(snapshots));
}

fn warn_policy_tests_at_boot_inner(
    doc: &PolicyDoc,
    raw: Option<&str>,
    nodes: &[PolicyCheckNode],
    snapshots: Option<&[PolicyCheckNodeSnapshot]>,
) {
    let (acl_errors, ssh_errors) = policy_test_failures(doc, raw, nodes, snapshots);
    if !acl_errors.is_empty() {
        tracing::warn!(error = %format!("test(s) failed:\n{}", acl_errors.join("\n")),
            "policy tests failed at boot; server starting anyway, fix the policy and reload");
    }
    if !ssh_errors.is_empty() {
        tracing::warn!(error = %format!("test(s) failed:\n{}", ssh_errors.join("\n")),
            "policy sshTests failed at boot; server starting anyway, fix the policy and reload");
    }
}

fn run_policy_tests(
    doc: &PolicyDoc,
    raw: Option<&str>,
    nodes: &[PolicyCheckNode],
    snapshots: Option<&[PolicyCheckNodeSnapshot]>,
) -> Vec<String> {
    if doc.tests.is_empty() {
        return Vec::new();
    }
    let nodes = nodes
        .iter()
        .enumerate()
        .map(|(index, node)| PacketFilterNode {
            id: node.id,
            user_id: node.user_id,
            user: node.user.clone(),
            addrs: node.addrs.clone(),
            tags: node.tags.clone(),
            // Snapshot entrypoints clone these nodes in the same order.
            // Keep route facts paired by entry, without an ID-map overwrite.
            routes: snapshots
                .and_then(|snapshots| snapshots.get(index))
                .map(PolicyCheckNodeSnapshot::active_routes)
                .unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    let raw = raw.filter(|raw| go_policy_shape::policy_container_shape(raw, doc).is_some());
    let rules = if let Some(raw) = raw {
        if go_policy_shape::packet_filter_default_allow(raw) {
            filter::allow_all_filter_rules()
        } else {
            let acls =
                go_policy_shape::original_acl_rules(raw, doc).unwrap_or_else(|| doc.rules.clone());
            let compiled = match go_policy_shape::packet_filter_document(doc, &acls) {
                Ok(compiled) => compiled,
                Err(error) => return vec![format!("compiling policy tests: {error}")],
            };
            filter::acl_to_global_filter_rules_with_apps(
                &compiled,
                &nodes,
                &go_policy_shape::grant_app_shapes(raw),
            )
        }
    } else {
        filter::acl_to_global_filter_rules(doc, &nodes)
    };
    let mut errors = Vec::new();
    for test in &doc.tests {
        errors.extend(run_policy_test(test, doc, &nodes, &rules));
    }
    errors
}

fn run_policy_test(
    test: &PolicyTest,
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    rules: &[FilterRule],
) -> Vec<String> {
    let mut errors = Vec::new();
    let proto_suffix = if test.proto.is_empty() {
        String::new()
    } else {
        format!(" ({})", test.proto)
    };
    let label = format!("{}{proto_suffix}", test.src);
    let srcs = match resolve_test_source(doc, nodes, &test.src) {
        Ok(prefixes) => prefixes,
        Err(error) => {
            return vec![format!(
                "{label}: failed to resolve source {}: {error}",
                go_strconv::quote(&test.src)
            )];
        }
    };
    if srcs.is_empty() {
        return vec![format!(
            "{label}: source {} resolved to no IP addresses",
            go_strconv::quote(&test.src)
        )];
    }
    let mut accept_failures = Vec::new();
    let mut deny_failures = Vec::new();
    for dst in &test.accept {
        match test_allows(doc, nodes, test, &srcs, dst, rules) {
            Ok(true) => {}
            Ok(false) => accept_failures.push(format!(
                "{} -> {dst}{proto_suffix}: expected ALLOWED, got DENIED",
                test.src,
            )),
            Err(err) => errors.push(format!(
                "{label}: error testing {}: {err}",
                go_strconv::quote(dst)
            )),
        }
    }

    for dst in &test.deny {
        match test_allows(doc, nodes, test, &srcs, dst, rules) {
            Ok(false) => {}
            Ok(true) => deny_failures.push(format!(
                "{} -> {dst}{proto_suffix}: expected DENIED, got ALLOWED",
                test.src,
            )),
            Err(err) => errors.push(format!(
                "{label}: error testing {}: {err}",
                go_strconv::quote(dst)
            )),
        }
    }

    errors.extend(accept_failures);
    errors.extend(deny_failures);
    errors
}

fn run_ssh_policy_tests(doc: &PolicyDoc, nodes: &[PolicyCheckNode]) -> Vec<String> {
    if doc.ssh_tests.is_empty() {
        return Vec::new();
    }
    let packet_nodes = nodes
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
    let ssh_nodes = nodes
        .iter()
        .map(|node| SshPolicyNode {
            id: node.id,
            user_id: node.user_id,
            user: node.user.clone(),
            addrs: node.addrs.clone(),
            tags: node.tags.clone(),
        })
        .collect::<Vec<_>>();
    // Go caches one compiled destination policy for the entire SSH test pass.
    let mut cache = BTreeMap::new();
    let mut errors = Vec::new();
    for test in &doc.ssh_tests {
        errors.extend(run_ssh_policy_test(
            test,
            doc,
            nodes,
            &packet_nodes,
            &ssh_nodes,
            &mut cache,
        ));
    }
    errors
}

fn run_ssh_policy_test(
    test: &SshPolicyTest,
    doc: &PolicyDoc,
    nodes: &[PolicyCheckNode],
    packet_nodes: &[PacketFilterNode],
    ssh_nodes: &[SshPolicyNode],
    cache: &mut BTreeMap<u64, Option<SshPolicy>>,
) -> Vec<String> {
    // The native SSH-test decoder represents an empty source as a nil Alias.
    let src_prefixes = if test.src.is_empty() {
        Vec::new()
    } else {
        match resolve_test_source(doc, packet_nodes, &test.src) {
            Ok(prefixes) => prefixes,
            Err(error) => {
                return vec![format!(
                    "{}: failed to resolve source {}: {error}",
                    test.src,
                    go_strconv::quote(&test.src)
                )];
            }
        }
    };
    if src_prefixes.is_empty() {
        return vec![format!(
            "{}: source {} resolved to no IP addresses",
            test.src,
            go_strconv::quote(&test.src)
        )];
    }
    if test.accept.is_empty() && test.deny.is_empty() && test.check.is_empty() {
        return vec![format!(
            "{}: no accept, deny, or check assertions specified",
            test.src
        )];
    }
    let (destinations, empty) = match resolve_ssh_test_destinations(doc, nodes, packet_nodes, test)
    {
        Ok(resolved) => resolved,
        Err(error) => {
            return vec![format!(
                "{}: failed to resolve destinations: {error}",
                test.src
            )];
        }
    };
    let mut errors = empty
        .into_iter()
        .map(|dst| {
            format!(
                "{}: dst alias {} resolved to no nodes",
                test.src,
                go_strconv::quote(&dst)
            )
        })
        .collect::<Vec<_>>();
    let sources = IpSet::from_strings(src_prefixes.iter().map(String::as_str));
    let mut accept_ok: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut accept_fail: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut deny_fail: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut check_fail: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (kind, users) in [(0, &test.accept), (1, &test.deny), (2, &test.check)] {
        for user in users {
            for &index in &destinations {
                let dst = &nodes[index];
                let policy = cache.entry(dst.id).or_insert_with(|| {
                    super::ssh::compile_ssh_policy_for_target(doc, ssh_nodes, &ssh_nodes[index], "")
                });
                let (accepted, checked) = ssh_reachable_sources(policy.as_ref(), user);
                let failure = match kind {
                    0 => {
                        let failed = sources.first_not_in(&accepted).is_some();
                        if !failed {
                            accept_ok
                                .entry(user.clone())
                                .or_default()
                                .insert(dst.name.clone());
                        }
                        failed
                    }
                    1 => sources.intersects(&accepted),
                    _ => {
                        if let Some(first_missing) = sources.first_not_in(&checked) {
                            if accepted.contains_ip(&first_missing) {
                                accept_ok
                                    .entry(user.clone())
                                    .or_default()
                                    .insert(dst.name.clone());
                            }
                            true
                        } else {
                            false
                        }
                    }
                };
                if failure {
                    let failures = match kind {
                        0 => &mut accept_fail,
                        1 => &mut deny_fail,
                        _ => &mut check_fail,
                    };
                    failures
                        .entry(user.clone())
                        .or_default()
                        .push(dst.name.clone());
                }
            }
        }
    }
    // Results render sorted usernames but retain destination order and repeated
    // failures. Check reasons consult the final AcceptOK map across assertions.
    for (kind, failures) in [(0, accept_fail), (1, deny_fail), (2, check_fail)] {
        for (user, destinations) in failures {
            for dst in destinations {
                let outcome = match kind {
                    0 => "expected ALLOWED, got DENIED",
                    1 => "expected DENIED, got ALLOWED",
                    _ if accept_ok
                        .get(&user)
                        .is_some_and(|names| names.contains(&dst)) =>
                    {
                        "expected ALLOWED via check, got ALLOWED via accept"
                    }
                    _ => "expected ALLOWED via check, got DENIED",
                };
                errors.push(format!(
                    "{}/{} -> {dst}: {outcome}",
                    test.src,
                    display_ssh_test_user(&user)
                ));
            }
        }
    }
    errors
}

fn display_ssh_test_user(user: &str) -> &str {
    if user.is_empty() { "\"\"" } else { user }
}

fn resolve_ssh_test_destinations(
    doc: &PolicyDoc,
    nodes: &[PolicyCheckNode],
    packet_nodes: &[PacketFilterNode],
    test: &SshPolicyTest,
) -> Result<(Vec<usize>, Vec<String>), String> {
    let username_source =
        go_policy_shape::alias_kind(&test.src) == Some(go_policy_shape::AliasKind::Username);
    let source_user_id = username_source
        .then(|| doc.resolve_user(&test.src))
        .flatten()
        .filter(|id| *id != 0);
    let mut seen = BTreeSet::new();
    let mut destinations = Vec::new();
    let mut empty = Vec::new();
    for dst in &test.dst {
        let ips = if dst == "autogroup:self" {
            None
        } else {
            let ips = super::resolution::alias(doc, dst, packet_nodes)
                .checked()
                .map_err(|error| {
                    format!("resolving destination {}: {error}", go_strconv::quote(dst))
                })?;
            Some(IpSet::from_strings(ips.iter().map(String::as_str)))
        };
        let mut matched = false;
        for (index, node) in nodes.iter().enumerate() {
            let matches = if let Some(ips) = &ips {
                ips.contains_view(&node.as_view())
            } else if !node.tags.is_empty() || !username_source {
                false
            } else if doc.users.is_some() {
                source_user_id.is_some() && node.user_id == source_user_id
            } else {
                // Source-less embedding retains its legacy login projection;
                // native snapshots always carry the loaded user directory.
                doc.user_matches(&test.src, node.user_id, node.user.as_deref())
            };
            if matches {
                matched = true;
                if seen.insert(node.id) {
                    destinations.push(index);
                }
            }
        }
        if !matched {
            empty.push(dst.clone());
        }
    }
    Ok((destinations, empty))
}

fn ssh_reachable_sources(policy: Option<&SshPolicy>, user: &str) -> (IpSet, IpSet) {
    let mut accepted = Vec::new();
    let mut checked = Vec::new();
    if let Some(policy) = policy {
        for rule in &policy.rules {
            if !ssh_user_map_allows(&rule.ssh_users, user) {
                continue;
            }
            for principal in &rule.principals {
                let Ok((ip, zone)) = headscale_api_acl::go_netip::parse_addr(&principal.node_ip)
                else {
                    continue;
                };
                // IPSet iteration yields unzoned addresses; Go Addr equality
                // cannot match a zoned principal to any source in that set.
                if zone.is_some() {
                    continue;
                }
                accepted.push(ip.to_string());
                if !rule.action.hold_and_delegate.is_empty() {
                    checked.push(ip.to_string());
                }
            }
        }
    }
    (
        IpSet::from_strings(accepted.iter().map(String::as_str)),
        IpSet::from_strings(checked.iter().map(String::as_str)),
    )
}

fn ssh_user_map_allows(users: &BTreeMap<String, String>, user: &str) -> bool {
    if user.is_empty() {
        return false;
    }
    if let Some(value) = users.get(user) {
        return !value.is_empty();
    }
    user != "root" && users.get("*").is_some_and(|value| !value.is_empty())
}

fn resolve_test_source(
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    source: &str,
) -> Result<Vec<String>, String> {
    let alias = go_policy_shape::canonical_alias(source)
        .map_err(|error| format!("invalid alias: {error}"))?;
    if go_policy_shape::alias_kind(&alias) == Some(go_policy_shape::AliasKind::Username)
        && let Some(users) = &doc.users
    {
        let token = alias.strip_suffix('@').unwrap_or(&alias);
        let provider = users
            .iter()
            .any(|user| user.provider_identifier.as_deref() == Some(token));
        if !provider {
            let matching = users
                .iter()
                .filter(|user| user.name == token || user.email == token)
                .collect::<Vec<_>>();
            if matching.is_empty() {
                return Err(format!(
                    "resolving: user not found: token {}",
                    go_strconv::quote(&alias)
                ));
            }
            if matching.len() > 1 {
                // resolveUser fails before Alias.Resolve can inspect the zero
                // user's nodes or append address-builder errors.
                let found = matching.iter().fold(String::new(), |mut found, user| {
                    let _ = write!(found, "{}: {}, ", user.id, user.name);
                    found
                });
                return Err(format!(
                    "resolving: multiple users found: token {} found: [ {found} ]",
                    go_strconv::quote(&alias)
                ));
            }
        }
    }
    super::resolution::alias(doc, &alias, nodes)
        .checked()
        .map(|ips| IpSet::from_strings(ips.iter().map(String::as_str)).prefixes())
        .map_err(|error| format!("resolving: {error}"))
}

fn test_allows(
    doc: &PolicyDoc,
    nodes: &[PacketFilterNode],
    test: &PolicyTest,
    srcs: &[String],
    dst: &str,
    rules: &[FilterRule],
) -> Result<bool, String> {
    let destination = go_policy_shape::parse_test_destination(dst)
        .map_err(|error| format!("invalid destination {}: {error}", go_strconv::quote(dst)))?;
    let dst_ips = super::resolution::alias(doc, &destination.alias, nodes)
        .checked()
        .map_err(|error| format!("resolving destination: {error}"))?;
    let dsts = IpSet::from_strings(dst_ips.iter().map(String::as_str)).prefixes();
    if dsts.is_empty() {
        return Err(format!(
            "destination resolved to no IP addresses: {}",
            go_strconv::quote(dst)
        ));
    }
    let protocols = test_protocols(&test.proto);
    // Go tests require every merged source prefix to overlap an allowing
    // global rule. CapGrant destinations do not admit packet traffic here.
    Ok(srcs.iter().all(|source| {
        rules.iter().any(|rule| {
            rule.src_ips.iter().any(|raw| {
                IpSet::from_filter_string(raw).is_some_and(|set| set.overlaps_prefix(source))
            }) && (rule.ip_proto.is_empty()
                || rule
                    .ip_proto
                    .iter()
                    .any(|protocol| protocols.contains(protocol)))
                && rule.dst_ports.iter().any(|allowed| {
                    IpSet::from_filter_string(&allowed.ip)
                        .is_some_and(|set| dsts.iter().any(|prefix| set.overlaps_prefix(prefix)))
                        && (destination.ports.is_empty()
                            || destination.ports.iter().any(|&(first, last)| {
                                first >= allowed.ports.first && last <= allowed.ports.last
                            }))
                })
        })
    }))
}

fn test_protocols(proto: &str) -> Vec<i32> {
    match proto {
        "tcp" | "6" => vec![6],
        "udp" | "17" => vec![17],
        "sctp" | "132" => vec![132],
        "" => vec![6, 17, 1, 58],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::parse_hujson_policy;

    fn node(id: u64, name: &str, user: &str, addr: &str, tags: &[&str]) -> PolicyCheckNode {
        node_with_user_id(id, name, None, Some(user), addr, tags)
    }

    fn node_with_user_id(
        id: u64,
        name: &str,
        user_id: Option<u64>,
        user: Option<&str>,
        addr: &str,
        tags: &[&str],
    ) -> PolicyCheckNode {
        PolicyCheckNode {
            id,
            user_id,
            name: name.to_string(),
            user: user.map(str::to_string),
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
    fn policy_tests_accept_grants_only_with_omitted_proto() {
        let doc = parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:server": ["alice@"]},
                "grants": [
                    {"src": ["alice@"], "dst": ["tag:server"], "ip": ["tcp:22"]}
                ],
                "tests": [
                    {"src": "alice@", "accept": ["tag:server:22"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice", "alice", "100.64.0.1", &[]),
            node(2, "server", "bob", "100.64.0.2", &["tag:server"]),
        ];

        check_policy_semantics(&doc, &nodes).unwrap();
    }

    #[test]
    fn policy_tests_accept_bracketed_ipv6_literal_destination() {
        let doc = parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:client": ["alice@"]},
                "grants": [{"src": ["tag:client"], "dst": ["fd7a:115c:a1e0::10"], "ip": ["tcp:22"]}],
                "tests": [{"src": "tag:client", "accept": ["[fd7a:115c:a1e0::10]:22"]}]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "client", "alice", "fd7a:115c:a1e0::11", &["tag:client"]),
            node(2, "server", "bob", "fd7a:115c:a1e0::10", &[]),
        ];
        check_policy_semantics(&doc, &nodes).unwrap();
    }

    #[test]
    fn policy_tests_accept_numeric_tcp_proto() {
        let doc = parse_hujson_policy(
            r#"{
                "acls": [
                    {"action": "accept", "proto": "tcp", "src": ["alice@"], "dst": ["100.64.0.2:443"]}
                ],
                "tests": [
                    {"src": "alice@", "proto": "6", "accept": ["100.64.0.2:443"]}
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
        // headscale-go v0.29.5 policy/v2/test.go PolicyTestResults.Errors():
        // "test(s) failed:\n<src> -> <dst>: expected ALLOWED, got DENIED"
        // (confirmed against a live Go server's CheckPolicy).
        assert_eq!(
            err, "test(s) failed:\nalice@ -> 100.64.0.2:22: expected ALLOWED, got DENIED",
            "{err}"
        );
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
        // headscale-go v0.29.5 evalReachability: AliasWithPorts.Resolve for
        // autogroup:self returns ErrAutogroupSelfRequiresPerNodeResolution,
        // wrapped as `error testing "<dst>": resolving destination: ...`
        // (confirmed against a live Go server's CheckPolicy).
        assert_eq!(
            err,
            "test(s) failed:\nalice@: error testing \"autogroup:self:22\": resolving destination: \
             autogroup:self requires per-node resolution and cannot be resolved in this context",
            "{err}"
        );
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
    fn ssh_tests_resolve_autogroup_self_by_numeric_user_id() {
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
            node_with_user_id(1, "alice-a", Some(7), Some("alice"), "100.64.0.1", &[]),
            node_with_user_id(2, "alice-b", Some(7), None, "100.64.0.2", &[]),
            node_with_user_id(
                3,
                "tagged",
                Some(7),
                Some("alice"),
                "100.64.0.3",
                &["tag:client"],
            ),
        ];

        check_policy_semantics(&doc, &nodes).unwrap();
    }

    #[test]
    fn ssh_tests_do_not_resolve_autogroup_self_by_label_when_user_ids_differ() {
        let doc = parse_hujson_policy(
            r#"{
                "ssh": [
                    {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["root"]}
                ],
                "sshTests": [
                    {"src": "alice@", "dst": ["alice@"], "accept": ["root"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node_with_user_id(1, "alice-a", Some(7), Some("alice"), "100.64.0.1", &[]),
            node_with_user_id(2, "alice-b", Some(8), Some("alice"), "100.64.0.2", &[]),
        ];

        let err = check_policy_semantics(&doc, &nodes).unwrap_err();
        assert!(err.contains("alice@/root -> alice-b: expected ALLOWED, got DENIED"));
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
    fn ssh_tests_apply_localpart_self_access_for_source_targets() {
        let doc = parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:server": ["alice@example.com"]},
                "ssh": [
                    {
                        "action": "accept",
                        "src": ["autogroup:member"],
                        "dst": ["tag:server"],
                        "users": ["localpart:*@example.com"]
                    }
                ],
                "sshTests": [
                    {"src": "alice@example.com", "dst": ["alice@example.com"], "accept": ["alice"], "deny": ["bob"]},
                    {"src": "bob@example.com", "dst": ["bob@example.com"], "accept": ["bob"], "deny": ["alice"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice", "alice@example.com", "100.64.0.1", &[]),
            node(2, "bob", "bob@example.com", "100.64.0.2", &[]),
            node(
                3,
                "server",
                "alice@example.com",
                "100.64.0.3",
                &["tag:server"],
            ),
        ];

        check_policy_semantics(&doc, &nodes).unwrap();
    }

    #[test]
    fn ssh_tests_do_not_apply_localpart_user_for_tagged_self_access() {
        let doc = parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:client": ["alice@example.com"], "tag:server": ["alice@example.com"]},
                "ssh": [
                    {
                        "action": "accept",
                        "src": ["tag:client"],
                        "dst": ["tag:server"],
                        "users": ["localpart:*@example.com", "deploy"]
                    }
                ],
                "sshTests": [
                    {"src": "tag:client", "dst": ["tag:client"], "accept": ["deploy"], "deny": ["alice"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![node(
            1,
            "client",
            "alice@example.com",
            "100.64.0.1",
            &["tag:client"],
        )];

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
        assert!(err.contains("alice@/root -> prod: expected ALLOWED, got DENIED"));
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
        assert!(err.contains("alice@/root -> server: expected ALLOWED, got DENIED"));

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
    fn ssh_tests_report_failed_assertions_in_upstream_shape() {
        let doc = parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:server": ["alice@"]},
                "ssh": [
                    {"action": "accept", "src": ["alice@"], "dst": ["tag:server"], "users": ["root"]}
                ],
                "sshTests": [
                    {"src": "alice@", "dst": ["tag:server"], "accept": ["ubuntu"], "deny": ["root"], "check": ["root"]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice", "alice", "100.64.0.1", &[]),
            node(2, "server", "bob", "100.64.0.2", &["tag:server"]),
        ];

        let err = check_policy_semantics(&doc, &nodes).unwrap_err();
        assert!(err.contains("alice@/ubuntu -> server: expected ALLOWED, got DENIED"));
        assert!(err.contains("alice@/root -> server: expected DENIED, got ALLOWED"));
        assert!(
            err.contains(
                "alice@/root -> server: expected ALLOWED via check, got ALLOWED via accept"
            )
        );
    }

    #[test]
    fn ssh_tests_reject_empty_login_user_in_accept() {
        let doc = parse_hujson_policy(
            r#"{
                "tagOwners": {"tag:server": ["alice@"]},
                "ssh": [
                    {"action": "accept", "src": ["alice@"], "dst": ["tag:server"], "users": ["root"]}
                ],
                "sshTests": [
                    {"src": "alice@", "dst": ["tag:server"], "accept": [""]}
                ]
            }"#,
        )
        .unwrap();
        let nodes = vec![
            node(1, "alice", "alice", "100.64.0.1", &[]),
            node(2, "server", "bob", "100.64.0.2", &["tag:server"]),
        ];

        let err = check_policy_semantics(&doc, &nodes).unwrap_err();

        assert!(err.contains(r#"alice@/"" -> server: expected ALLOWED, got DENIED"#));
    }

    #[test]
    fn ssh_tests_report_resolver_and_shape_failures_in_upstream_shape() {
        let nodes = vec![
            node(1, "alice", "alice", "100.64.0.1", &[]),
            node(2, "server", "bob", "100.64.0.2", &["tag:server"]),
            node(3, "prod", "alice", "100.64.0.3", &["tag:prod"]),
        ];

        for (name, raw, want) in [
            (
                "empty assertions",
                r#"{
                    "tagOwners": {"tag:server": ["alice@"]},
                    "sshTests": [
                        {"src": "alice@", "dst": ["tag:server"]}
                    ]
                }"#,
                "alice@: no accept, deny, or check assertions specified",
            ),
            (
                "source resolves empty",
                r#"{
                    "sshTests": [
                        {"src": "ghost@", "dst": ["autogroup:member"], "accept": ["root"]}
                    ]
                }"#,
                r#"ghost@: source "ghost@" resolved to no IP addresses"#,
            ),
            (
                "destination resolves empty",
                r#"{
                    "tagOwners": {"tag:empty": ["alice@"]},
                    "sshTests": [
                        {"src": "alice@", "dst": ["tag:empty"], "accept": ["root"]}
                    ]
                }"#,
                r#"alice@: dst alias "tag:empty" resolved to no nodes"#,
            ),
            (
                "autogroup self from tag source resolves empty",
                r#"{
                    "tagOwners": {"tag:prod": ["alice@"]},
                    "sshTests": [
                        {"src": "tag:prod", "dst": ["autogroup:self"], "accept": ["root"]}
                    ]
                }"#,
                r#"tag:prod: dst alias "autogroup:self" resolved to no nodes"#,
            ),
        ] {
            let doc = parse_hujson_policy(raw).unwrap();
            let err = check_policy_semantics(&doc, &nodes).unwrap_err();
            assert!(
                err.starts_with("test(s) failed:\n"),
                "{name} should use upstream wrapper, got {err}"
            );
            assert!(
                err.contains(want),
                "{name} should contain {want:?}, got {err}"
            );
            assert!(
                !err.contains("sshTest "),
                "{name} should not expose internal sshTest index labels, got {err}"
            );
        }
    }
}
