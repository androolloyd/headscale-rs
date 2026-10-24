// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Policy-manager inputs are distinct from the latest quiet NodeStore edit.
//! Follow v0.29.5 SetNodes/HasPolicyChange/HasNetworkChanges without hashing
//! mutable wire/profile/clock fields into the policy identity.

use std::collections::{BTreeMap, BTreeSet};

use super::{PacketFilterNode, PolicyCheckNodeSnapshot, PolicyDoc, SshPolicyNode, filter};
use crate::tailscale_wire::MachineRecord;
pub(crate) use headscale_api_acl::go_policy_shape::{GrantAppShape, grant_app_shapes};

#[derive(Clone)]
pub(crate) struct NodeInput {
    pub(crate) id: u64,
    pub(crate) owner_id: u64,
    association_id: Option<u64>,
    legacy_user: Option<String>,
    user: Option<String>,
    pub(crate) addrs: Vec<String>,
    tags: Vec<String>,
    announced: Vec<String>,
    active: Vec<String>,
}

impl NodeInput {
    pub(super) fn from_policy_check_snapshot(snapshot: &PolicyCheckNodeSnapshot) -> Self {
        let node = &snapshot.node;
        let announced = snapshot.advertised_routes.clone();
        let active = announced
            .iter()
            .filter(|route| snapshot.approved_routes.contains(route))
            .cloned()
            .collect();
        Self {
            id: node.id,
            owner_id: node.user_id.unwrap_or(0),
            association_id: node.user_id,
            legacy_user: node.user_id.is_none().then(|| node.user.clone()).flatten(),
            user: node.user.clone(),
            addrs: node.addrs.clone(),
            tags: node.tags.clone(),
            announced,
            active,
        }
    }

    #[cfg(feature = "admin")]
    pub(crate) fn set_native_association(&mut self, association: Option<u64>) {
        self.association_id = association;
        self.legacy_user = None;
        if association.is_none() {
            self.user = None;
        }
    }
    pub(crate) fn from_record(id: u64, record: &MachineRecord) -> Self {
        let announced = record.available_routes.clone();
        let active = announced
            .iter()
            .filter(|route| record.approved_routes.contains(route))
            .cloned()
            .collect();
        Self {
            id,
            owner_id: record.user_id.unwrap_or(0),
            association_id: record.user_id,
            legacy_user: (record.user_id.is_none() && !record.user.is_empty())
                .then(|| record.user.clone()),
            user: (!record.user.is_empty()).then(|| record.user.clone()),
            addrs: record.address_strings(),
            tags: record.forced_tags.clone(),
            announced,
            active,
        }
    }

    fn policy_changed(&self, before: &Self, per_node: bool) -> bool {
        self.owner_id != before.owner_id
            || self.association_id != before.association_id
            || self.legacy_user != before.legacy_user
            || self.addrs != before.addrs
            || self.tags != before.tags
            // Announced order is immaterial; multiplicity remains significant.
            // Subnet and exit route classes cannot overlap, so comparing their
            // combined sorted multiset gives the same equality result.
            || !route_multisets_equal(&self.active, &before.active)
            || (per_node && !route_multisets_equal(&self.announced, &before.announced))
    }

    fn network_changed(&self, before: &Self) -> bool {
        self.addrs != before.addrs
            || !route_multisets_equal(&self.announced, &before.announced)
            || !route_multisets_equal(&self.active, &before.active)
    }

    fn filter_node(&self) -> PacketFilterNode {
        PacketFilterNode {
            id: self.id,
            user_id: self.association_id,
            user: self.user.clone(),
            addrs: self.addrs.clone(),
            tags: self.tags.clone(),
            routes: self.active.clone(),
        }
    }

    fn ssh_node(&self) -> SshPolicyNode {
        SshPolicyNode {
            id: self.id,
            user: self.user.clone(),
            user_id: self.association_id,
            addrs: self.addrs.clone(),
            tags: self.tags.clone(),
        }
    }
}

fn route_multisets_equal(left: &[String], right: &[String]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut left = left.iter().collect::<Vec<_>>();
    let mut right = right.iter().collect::<Vec<_>>();
    left.sort_unstable();
    right.sort_unstable();
    left == right
}

#[derive(Default)]
pub(crate) struct NodeInputs {
    nodes: Option<Vec<NodeInput>>,
    needs_per_node_filter: bool,
}

impl NodeInputs {
    pub(crate) fn initialize(&mut self, nodes: Vec<NodeInput>) -> bool {
        if self.nodes.is_none() {
            self.nodes = Some(nodes);
            true
        } else {
            false
        }
    }

    pub(crate) fn replace(&mut self, nodes: Vec<NodeInput>) -> bool {
        let old = self.nodes.as_deref().unwrap_or_default();
        let changed = if old.len() == nodes.len() {
            let by_id = old
                .iter()
                .map(|node| (node.id, node))
                .collect::<BTreeMap<_, _>>();
            nodes.iter().any(|node| {
                by_id
                    .get(&node.id)
                    .is_none_or(|before| node.policy_changed(before, self.needs_per_node_filter))
            })
        } else {
            true
        };
        // Go replaces pm.nodes even for endpoint/clock-only changes, but only
        // recompiles the grants when a policy-affecting input moved.
        self.nodes = Some(nodes);
        changed
    }

    pub(super) fn nodes(&self) -> Option<&[NodeInput]> {
        self.nodes.as_deref()
    }

    pub(super) fn filter_nodes(&self) -> Option<Vec<PacketFilterNode>> {
        self.nodes
            .as_ref()
            .map(|nodes| nodes.iter().map(NodeInput::filter_node).collect())
    }

    pub(super) fn ssh_nodes(&self) -> Option<Vec<SshPolicyNode>> {
        self.nodes
            .as_ref()
            .map(|nodes| nodes.iter().map(NodeInput::ssh_node).collect())
    }

    pub(super) fn needs_per_node_filter(&self) -> bool {
        self.needs_per_node_filter
    }

    pub(super) fn network_invalidations(&self, new: &[NodeInput]) -> BTreeSet<u64> {
        let new_by_id = new
            .iter()
            .map(|node| (node.id, node))
            .collect::<BTreeMap<_, _>>();
        self.nodes
            .as_deref()
            .unwrap_or_default()
            .iter()
            .filter_map(|before| {
                new_by_id
                    .get(&before.id)
                    .is_none_or(|node| node.network_changed(before))
                    .then_some(before.id)
            })
            .collect()
    }

    pub(super) fn cache_invalidations(&self, new: &[NodeInput]) -> (BTreeSet<u64>, BTreeSet<u64>) {
        if !self.needs_per_node_filter {
            return (
                self.network_invalidations(new),
                new.iter().map(|node| node.id).collect(),
            );
        }
        let old = self.nodes.as_deref().unwrap_or_default();
        let old_by_id = old
            .iter()
            .map(|node| (node.id, node))
            .collect::<BTreeMap<_, _>>();
        let new_by_id = new
            .iter()
            .map(|node| (node.id, node))
            .collect::<BTreeMap<_, _>>();
        let mut affected = BTreeSet::new();
        for before in old {
            if !new_by_id.contains_key(&before.id) && before.tags.is_empty() {
                affected.insert(before.owner_id);
            }
        }
        for node in new {
            let Some(before) = old_by_id.get(&node.id) else {
                if node.tags.is_empty() {
                    affected.insert(node.owner_id);
                }
                continue;
            };
            if node.tags.is_empty() != before.tags.is_empty() {
                affected.insert(if before.tags.is_empty() {
                    before.owner_id
                } else {
                    node.owner_id
                });
            } else if node.tags.is_empty() {
                if node.owner_id != before.owner_id {
                    affected.extend([before.owner_id, node.owner_id]);
                } else if node.addrs != before.addrs {
                    affected.insert(node.owner_id);
                }
            }
        }
        let known = old_by_id
            .keys()
            .chain(new_by_id.keys())
            .copied()
            .collect::<BTreeSet<_>>();
        let invalid = known
            .iter()
            .copied()
            .filter(|id| {
                let node = new_by_id.get(id).or_else(|| old_by_id.get(id)).unwrap();
                // Go leaves the zero user key for tagged entries while walking
                // this cache; preserve that behavior for zero-owner native shapes.
                affected.contains(&if node.tags.is_empty() {
                    node.owner_id
                } else {
                    0
                })
            })
            .collect();
        (invalid, known)
    }

    pub(crate) fn recompile(&mut self, doc: Option<&PolicyDoc>, apps: &[GrantAppShape]) {
        self.needs_per_node_filter = doc.is_some_and(|doc| {
            let nodes = self
                .nodes
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(NodeInput::filter_node)
                .collect::<Vec<_>>();
            filter::has_per_node_filters(doc, &nodes, apps)
        });
    }
}
