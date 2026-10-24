// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Serving caches follow v0.29.5 PolicyManager's refresh boundaries. Resolver
//! inputs are retained independently of the current requesting node. All
//! methods run under PolicyState's outer lock; per-node misses use short locks.

use std::collections::{BTreeMap, BTreeSet};

use parking_lot::Mutex;

use super::{NativeSshPolicy, diagnostics};
use super::{
    NodeView, PacketFilterNode, PolicyDoc, SshPolicyNode, filter,
    matcher::{IpSet, RuleMatcher},
    ssh,
};
use crate::tailscale_wire::wire::FilterRule;

#[derive(Default)]
pub(super) struct CompiledRuntime {
    doc: Option<PolicyDoc>,
    opaque_doc: Option<PolicyDoc>,
    opaque_global: super::opaque::OpaqueFilter,
    apps: Vec<super::lifecycle::GrantAppShape>,
    ssh_doc: Option<PolicyDoc>,
    ssh_accept_env_nil: Vec<bool>,
    resolver_nodes: Vec<PacketFilterNode>,
    global: Vec<FilterRule>,
    per_node: bool,
    filters: Mutex<BTreeMap<u64, super::opaque::FilterSnapshot>>,
    ssh: Mutex<BTreeMap<u64, Option<NativeSshPolicy>>>,
    attrs: BTreeMap<u64, Vec<String>>,
    tag_owners: BTreeMap<String, IpSet>,
    approvers: RouteApprovers,
    global_matchers: Vec<RuleMatcher>,
    matchers: Mutex<BTreeMap<u64, Vec<RuleMatcher>>>,
    peer_recompute_targets: PeerRecomputeTargets,
}

/// PolicyManager keeps these roles with its compiled grants, independently of
/// whether the node currently has an online session or is the elected router.
#[derive(Default)]
pub(super) struct PeerRecomputeTargets {
    relay: IpSet,
    via_tags: BTreeSet<String>,
}

impl PeerRecomputeTargets {
    pub(super) fn compile(
        doc: Option<&PolicyDoc>,
        nodes: &[PacketFilterNode],
        global: &[FilterRule],
    ) -> Self {
        let relay = IpSet::from_strings(
            global
                .iter()
                .flat_map(|rule| &rule.cap_grant)
                .filter(|grant| grant.cap_map.contains_key("tailscale.com/cap/relay"))
                .flat_map(|grant| grant.dsts.iter().map(String::as_str)),
        );
        // compileOneViaGrant retains the target tags once a network grant has
        // nonempty resolved sources. Empty/unresolved destinations do not
        // remove its role; recipient/route intersection is deferred until map.
        let via_tags = doc
            .into_iter()
            .flat_map(|doc| {
                doc.grants.iter().filter(move |grant| {
                    !grant.via.is_empty()
                        && !grant.ip.is_empty()
                        && !filter::resolved_source_cidrs(doc, &grant.src, nodes).is_empty()
                })
            })
            .flat_map(|grant| grant.via.iter().cloned())
            .collect();
        Self { relay, via_tags }
    }

    pub(super) fn contains(&self, node: &NodeView<'_>) -> bool {
        self.relay.contains_view(node) || node.tags.iter().any(|tag| self.via_tags.contains(tag))
    }
}

#[derive(Clone, Default, Eq, PartialEq)]
struct RouteApprovers {
    routes: BTreeMap<String, IpSet>,
    // A configured alias resolving to no addresses is non-nil in Go.
    exit: Option<IpSet>,
}

impl RouteApprovers {
    fn compile(doc: &PolicyDoc, nodes: &[PacketFilterNode]) -> Self {
        Self {
            routes: doc
                .auto_approvers
                .routes
                .iter()
                .map(|(prefix, aliases)| {
                    (
                        prefix.clone(),
                        IpSet::from_strings(
                            filter::resolve_owner_ips(doc, aliases, nodes)
                                .iter()
                                .map(String::as_str),
                        ),
                    )
                })
                .collect(),
            exit: (!doc.auto_approvers.exit_node.is_empty()).then(|| {
                IpSet::from_strings(
                    filter::resolve_owner_ips(doc, &doc.auto_approvers.exit_node, nodes)
                        .iter()
                        .map(String::as_str),
                )
            }),
        }
    }

    fn route(&self, node: &NodeView<'_>, route: &str) -> bool {
        if matches!(route, "0.0.0.0/0" | "::/0") {
            return false;
        }
        self.routes.iter().any(|(prefix, ips)| {
            filter::prefix_covers_route(prefix, route) && ips.contains_view(node)
        })
    }

    fn exit(&self, node: &NodeView<'_>) -> bool {
        self.exit
            .as_ref()
            .is_some_and(|ips| ips.contains_view(node))
    }
}

fn compile_tag_owners(
    doc: Option<&PolicyDoc>,
    aliases: &BTreeMap<String, Vec<String>>,
    nodes: &[PacketFilterNode],
) -> BTreeMap<String, IpSet> {
    doc.map(|doc| {
        aliases
            .iter()
            .map(|(tag, aliases)| {
                (
                    tag.clone(),
                    IpSet::from_strings(
                        filter::resolve_owner_ips(doc, aliases, nodes)
                            .iter()
                            .map(String::as_str),
                    ),
                )
            })
            .collect()
    })
    .unwrap_or_default()
}

// An embedding store can compile before its registry supplies retained nodes.
// Produce diagnostic snapshots without installing the serving runtime early.
pub(super) fn diagnose_without_nodes(
    diagnostics: &mut diagnostics::PolicyDiagnostics,
    policy: &[u8],
    doc: Option<&PolicyDoc>,
    apps: &[super::lifecycle::GrantAppShape],
    tag_owner_aliases: &BTreeMap<String, Vec<String>>,
    default_allow: bool,
    global: &[FilterRule],
) -> diagnostics::Changes {
    diagnose_snapshot(
        diagnostics,
        policy,
        doc,
        apps,
        tag_owner_aliases,
        default_allow,
        global,
        &[],
    )
}

pub(super) fn diagnose_snapshot(
    diagnostics: &mut diagnostics::PolicyDiagnostics,
    policy: &[u8],
    doc: Option<&PolicyDoc>,
    apps: &[super::lifecycle::GrantAppShape],
    tag_owner_aliases: &BTreeMap<String, Vec<String>>,
    default_allow: bool,
    global: &[FilterRule],
    nodes: &[PacketFilterNode],
) -> diagnostics::Changes {
    let opaque = doc.map(|doc| super::opaque::document(doc, apps));
    let opaque_global = match opaque.as_ref() {
        Some(doc) if !default_allow => {
            filter::acl_to_global_filter_rules_with_apps(doc, nodes, apps)
        }
        _ => filter::allow_all_filter_rules(),
    };
    let filter = diagnostics.filter(global, &opaque_global, policy);
    let tags = compile_tag_owners(doc, tag_owner_aliases, nodes);
    let tags = diagnostics.tags(&tags);
    let approvers = doc
        .map(|doc| RouteApprovers::compile(doc, nodes))
        .unwrap_or_default();
    let routes = diagnostics.routes(&approvers.routes, doc.is_some());
    let exit = diagnostics.exit(approvers.exit.as_ref());
    diagnostics.changes(diagnostics::StageChanges {
        filter,
        tags,
        routes,
        exit,
    })
}

/// Resolve static tag topology before publishing a candidate policy. A cycle
/// drops only its back edge; other owners in that branch still contribute.
pub(super) fn flatten_tag_owners(doc: &PolicyDoc) -> Result<BTreeMap<String, Vec<String>>, String> {
    fn visit(
        doc: &PolicyDoc,
        tag: &str,
        visiting: &mut BTreeSet<String>,
    ) -> Result<Vec<String>, String> {
        if !visiting.insert(tag.to_owned()) {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        for owner in &doc.tag_owners[tag] {
            if !owner.contains('@') && owner.starts_with("tag:") {
                if !doc.tag_owners.contains_key(owner) {
                    return Err(format!(
                        "resolving tag owners map: tag {} references undefined tag {}",
                        headscale_api_acl::go_strconv::quote(tag),
                        headscale_api_acl::go_strconv::quote(owner),
                    ));
                }
                result.extend(visit(doc, owner, visiting)?);
            } else {
                result.push(owner.clone());
            }
        }
        visiting.remove(tag);
        Ok(result)
    }
    doc.tag_owners
        .keys()
        .map(|tag| {
            let mut owners = visit(doc, tag, &mut BTreeSet::new())?;
            owners.sort();
            owners.dedup();
            Ok((tag.clone(), owners))
        })
        .collect()
}

/// One retained policy-manager approver snapshot can plan an entire batch.
#[derive(Clone)]
pub(crate) struct RouteApprovalSnapshot {
    doc: Option<PolicyDoc>,
    approvers: Option<RouteApprovers>,
}

impl RouteApprovalSnapshot {
    pub(super) fn legacy(doc: Option<PolicyDoc>) -> Self {
        Self {
            doc,
            approvers: None,
        }
    }

    pub(crate) fn approves(&self, node: &NodeView<'_>, route: &str, exit: bool) -> bool {
        if let Some(approvers) = &self.approvers {
            return if exit {
                approvers.exit(node)
            } else {
                approvers.route(node, route)
            };
        }
        self.doc.as_ref().is_some_and(|doc| {
            if exit {
                doc.auto_approves_exit_node(node)
            } else {
                doc.auto_approves_route(node, route)
            }
        })
    }
}

impl CompiledRuntime {
    pub(super) fn recompile(
        &mut self,
        doc: Option<&PolicyDoc>,
        apps: &[super::lifecycle::GrantAppShape],
        ssh_accept_env_nil: &[bool],
        tag_owner_aliases: &BTreeMap<String, Vec<String>>,
        resolver_nodes: Vec<PacketFilterNode>,
        default_allow: bool,
        per_node: bool,
        invalidate: bool,
        diagnostics: &mut diagnostics::PolicyDiagnostics,
        diagnostic_policy: &[u8],
    ) -> Result<(BTreeSet<u64>, bool), String> {
        let global = match doc {
            Some(doc) if !default_allow => {
                filter::acl_to_global_filter_rules_with_apps(doc, &resolver_nodes, apps)
            }
            _ => filter::allow_all_filter_rules(),
        };
        let opaque_doc = doc.map(|doc| super::opaque::document(doc, apps));
        let opaque_global = super::opaque::OpaqueFilter(match opaque_doc.as_ref() {
            Some(doc) if !default_allow => {
                filter::acl_to_global_filter_rules_with_apps(doc, &resolver_nodes, apps)
            }
            _ => filter::allow_all_filter_rules(),
        });
        self.peer_recompute_targets = PeerRecomputeTargets::compile(doc, &resolver_nodes, &global);
        let filter_changed = diagnostics.filter(&global, &opaque_global.0, diagnostic_policy);
        let tag_owners = compile_tag_owners(doc, tag_owner_aliases, &resolver_nodes);
        let tags_changed = diagnostics.tags(&tag_owners);
        let approvers = doc
            .map(|doc| RouteApprovers::compile(doc, &resolver_nodes))
            .unwrap_or_default();
        let routes_changed = diagnostics.routes(&approvers.routes, doc.is_some());
        let exit_changed = diagnostics.exit(approvers.exit.as_ref());
        let diagnostic_changes = diagnostics.changes(diagnostics::StageChanges {
            filter: filter_changed,
            tags: tags_changed,
            routes: routes_changed,
            exit: exit_changed,
        });
        let effects_changed = global != self.global
            || opaque_global != self.opaque_global
            || tag_owners != self.tag_owners
            || approvers != self.approvers;
        let invalidate = invalidate || effects_changed || self.per_node != per_node;
        self.doc = doc.cloned();
        self.opaque_doc = opaque_doc;
        self.opaque_global = opaque_global;
        self.apps = apps.to_vec();
        self.ssh_doc = doc.cloned();
        self.ssh_accept_env_nil = ssh_accept_env_nil.to_vec();
        self.resolver_nodes = resolver_nodes;
        self.per_node = per_node;
        self.global.clone_from(&global);
        self.global_matchers = RuleMatcher::from_rules(&global);
        self.tag_owners = tag_owners;
        self.approvers = approvers;

        let attrs = match doc {
            Some(doc) if !doc.node_attrs.is_empty() || doc.randomize_client_port => {
                filter::compile_node_attrs(doc, &self.resolver_nodes)?
            }
            _ => BTreeMap::new(),
        };
        let changed = self
            .attrs
            .keys()
            .chain(attrs.keys())
            .copied()
            .filter(|id| self.attrs.get(id) != attrs.get(id))
            .collect();
        self.attrs = attrs;
        if invalidate {
            self.clear_caches();
        }
        diagnostic_changes.finish();
        Ok((changed, effects_changed))
    }

    pub(super) fn global_rules(&self) -> Vec<FilterRule> {
        self.global.clone()
    }

    pub(super) fn is_relay_or_via_target(&self, node: &NodeView<'_>) -> bool {
        self.peer_recompute_targets.contains(node)
    }

    pub(super) fn clear_caches(&mut self) {
        self.filters.get_mut().clear();
        self.ssh.get_mut().clear();
        self.matchers.get_mut().clear();
    }

    pub(super) fn restore_user_directory(&mut self, users: Option<Vec<super::PolicyUser>>) {
        // SetUsers rolls back its directory after an error without restoring
        // the already compiled filter/approver state. Lazy SSH reads old users.
        if let Some(doc) = &mut self.ssh_doc {
            doc.users = users;
        }
    }

    pub(super) fn invalidate_network(&mut self, ids: &BTreeSet<u64>, known: &BTreeSet<u64>) {
        // SetNodes' global selective invalidation does not clear SSH entries.
        self.filters
            .get_mut()
            .retain(|id, _| known.contains(id) && !ids.contains(id));
        self.matchers
            .get_mut()
            .retain(|id, _| known.contains(id) && !ids.contains(id));
    }

    pub(super) fn filter_for(&self, receiver: &PacketFilterNode) -> Vec<FilterRule> {
        self.filter_snapshot(receiver).rules
    }

    pub(super) fn filter_snapshot(
        &self,
        receiver: &PacketFilterNode,
    ) -> super::opaque::FilterSnapshot {
        if let Some(snapshot) = self.filters.lock().get(&receiver.id).cloned() {
            return snapshot;
        }
        let rules = if self.per_node {
            match &self.doc {
                Some(doc) => filter::acl_to_filter_rules_for_receiver_with_apps(
                    doc,
                    &self.resolver_nodes,
                    receiver,
                    &self.apps,
                ),
                None => self.global.clone(),
            }
        } else {
            filter::reduce_filter_rules_for_node(self.global.clone(), receiver)
        };
        let opaque = {
            let opaque_rules = if self.per_node {
                self.opaque_doc.as_ref().map_or_else(
                    || self.opaque_global.0.clone(),
                    |doc| {
                        filter::acl_to_filter_rules_for_receiver_with_apps(
                            doc,
                            &self.resolver_nodes,
                            receiver,
                            &self.apps,
                        )
                    },
                )
            } else {
                filter::reduce_filter_rules_for_node(self.opaque_global.0.clone(), receiver)
            };
            super::opaque::OpaqueFilter(opaque_rules)
        };
        // A concurrent miss may compile a different quiet recipient view.
        // Publish/return each pair together rather than mixing two caches.
        let snapshot = super::opaque::FilterSnapshot::new(rules, opaque);
        self.filters.lock().insert(receiver.id, snapshot.clone());
        snapshot
    }

    pub(super) fn ssh_for(
        &self,
        nodes: &[SshPolicyNode],
        receiver: &SshPolicyNode,
        base_url: &str,
    ) -> Option<NativeSshPolicy> {
        if let Some(policy) = self.ssh.lock().get(&receiver.id).cloned() {
            return policy;
        }
        let policy = self.ssh_doc.as_ref().and_then(|doc| {
            ssh::compile_ssh_policy_snapshot(
                doc,
                nodes,
                receiver,
                base_url,
                &self.ssh_accept_env_nil,
            )
        });
        self.ssh.lock().insert(receiver.id, policy.clone());
        policy
    }

    pub(super) fn attrs_for(&self, id: u64) -> Vec<String> {
        self.attrs.get(&id).cloned().unwrap_or_default()
    }

    pub(super) fn node_can_have_tag(&self, node: &NodeView<'_>, tag: &str) -> bool {
        self.tag_owners
            .get(tag)
            .is_some_and(|ips| ips.contains_view(node))
            || self
                .ssh_doc
                .as_ref()
                .is_some_and(|doc| doc.user_can_have_tag(node.user_id, node.user, tag))
    }

    pub(super) fn approval_snapshot(&self) -> RouteApprovalSnapshot {
        RouteApprovalSnapshot {
            doc: None,
            approvers: Some(self.approvers.clone()),
        }
    }

    pub(super) fn auto_approves_route(&self, node: &NodeView<'_>, route: &str) -> bool {
        self.approvers.route(node, route)
    }

    pub(super) fn auto_approves_exit(&self, node: &NodeView<'_>) -> bool {
        self.approvers.exit(node)
    }

    fn fresh_matchers_for(&self, node: &PacketFilterNode) -> Vec<RuleMatcher> {
        let rules = self.doc.as_ref().map_or_else(
            || self.global.clone(),
            |doc| {
                filter::unreduced_filter_rules_for_receiver(
                    doc,
                    &self.resolver_nodes,
                    node,
                    &self.apps,
                )
            },
        );
        RuleMatcher::from_rules(&rules)
    }

    pub(super) fn reduce_self_routes(
        &self,
        node: &PacketFilterNode,
        routes: &[String],
    ) -> Vec<String> {
        routes
            .iter()
            .filter(|route| RuleMatcher::can_access_route(&self.global_matchers, node, route))
            .cloned()
            .collect()
    }

    pub(super) fn can_access_route(&self, node: &PacketFilterNode, route: &str) -> bool {
        if !self.per_node {
            return RuleMatcher::can_access_route(&self.global_matchers, node, route);
        }
        let cached = self.matchers.lock().get(&node.id).cloned();
        let matchers = cached.unwrap_or_else(|| {
            let matchers = self.fresh_matchers_for(node);
            self.matchers.lock().insert(node.id, matchers.clone());
            matchers
        });
        RuleMatcher::can_access_route(&matchers, node, route)
    }

    pub(super) fn build_peer_map(&self, nodes: &[PacketFilterNode]) -> BTreeMap<u64, Vec<u64>> {
        // BuildPeerMap computes unreduced per-node matchers afresh; it does
        // not use MatchersForNode's lazy per-ID cache or exit-node self rules.
        let per_node = if self.per_node {
            nodes
                .iter()
                .map(|node| (node.id, self.fresh_matchers_for(node)))
                .collect::<BTreeMap<_, _>>()
        } else {
            BTreeMap::new()
        };
        let mut peers: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for (index, left) in nodes.iter().enumerate() {
            for right in nodes.iter().skip(index + 1) {
                if left.id == right.id {
                    continue;
                }
                let left_rules = per_node.get(&left.id).unwrap_or(&self.global_matchers);
                let right_rules = per_node.get(&right.id).unwrap_or(&self.global_matchers);
                let visible = RuleMatcher::can_access(left_rules, left, right)
                    || RuleMatcher::can_access(right_rules, right, left)
                    || (self.per_node
                        && (RuleMatcher::can_access(left_rules, right, left)
                            || RuleMatcher::can_access(right_rules, left, right)));
                if visible {
                    peers.entry(left.id).or_default().insert(right.id);
                    peers.entry(right.id).or_default().insert(left.id);
                }
            }
        }
        peers
            .into_iter()
            .map(|(id, peers)| (id, peers.into_iter().collect()))
            .collect()
    }
}
