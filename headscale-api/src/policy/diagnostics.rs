// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Headscale v0.29.5 PolicyManager.updateLocked diagnostic stages.
//! Fingerprints below hash the retained Rust projections with SHA-256, not
//! Go's process-seeded, reflected-type-dependent deephash representation.
//! Diagnostic comparisons never determine cache invalidation or publication.
//! Unrepresented Go nil/type distinctions remain a compatibility boundary.
//! The optional legacy staged API defers snapshots until completion; failures
//! before that boundary do not replay partial Go events. Native constructors
//! instead compile once from final inputs and retain ordinary partial events.

use std::{collections::BTreeMap, fmt::Write as _};

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{PolicyDoc, lifecycle::GrantAppShape, matcher::IpSet};
use crate::tailscale_wire::wire::FilterRule;

pub(super) fn policy_identity(
    doc: Option<&PolicyDoc>,
    apps: &[GrantAppShape],
    ssh_accept_env_nil: &[bool],
    acl: Option<&headscale_api_acl::go_policy_shape::OriginalAclIdentity>,
    containers: Option<&headscale_api_acl::go_policy_shape::PolicyContainerShape>,
) -> Vec<u8> {
    // PolicyDoc serialization excludes the runtime user directory. Preserve
    // the source shapes lost by its public Vec/map fields independently.
    encode(&(
        doc,
        format!("{apps:?}"),
        ssh_accept_env_nil,
        format!("{acl:?}"),
        format!("{containers:?}"),
    ))
}

fn encode(value: &impl Serialize) -> Vec<u8> {
    serde_json::to_vec(value).expect("typed policy diagnostic snapshot serializes")
}

#[derive(Default)]
struct Snapshot {
    bytes: Option<Vec<u8>>,
    fingerprint: [u8; 32],
}

impl Snapshot {
    fn replace(&mut self, bytes: Vec<u8>) -> Option<(String, String)> {
        if self.bytes.as_ref() == Some(&bytes) {
            return None;
        }
        let old = short_hash(&self.fingerprint);
        self.fingerprint = Sha256::digest(&bytes).into();
        self.bytes = Some(bytes);
        Some((old, short_hash(&self.fingerprint)))
    }
}

fn short_hash(hash: &[u8; 32]) -> String {
    hash[..4].iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

#[derive(Default)]
pub(super) struct PolicyDiagnostics {
    deferred: bool,
    suppress_next_no_change: bool,
    filter: Snapshot,
    tags: Snapshot,
    routes: Snapshot,
    exit: Snapshot,
    rule_count: usize,
    tag_count: usize,
    route_count: usize,
}

impl PolicyDiagnostics {
    pub(super) fn defer_initial(&mut self) {
        self.deferred = true;
    }

    pub(super) fn resume_initial(&mut self) -> bool {
        std::mem::take(&mut self.deferred)
    }

    pub(super) fn suppress_initial_attach_no_change(&mut self) {
        self.suppress_next_no_change = true;
    }

    pub(super) fn changes(&mut self, stages: StageChanges) -> Changes {
        Changes {
            filter: stages.filter,
            tags: stages.tags,
            routes: stages.routes,
            exit: stages.exit,
            emit_no_change: !self.deferred && !std::mem::take(&mut self.suppress_next_no_change),
        }
    }

    pub(super) fn filter(
        &mut self,
        rules: &[FilterRule],
        opaque_rules: &[FilterRule],
        policy: &[u8],
    ) -> bool {
        if self.deferred {
            return false;
        }
        let changed = self.filter.replace(encode(&(rules, opaque_rules, policy)));
        if let Some((old, new)) = &changed {
            tracing::debug!(
                "filter.hash.old" = %old,
                "filter.hash.new" = %new,
                "filter.rules" = self.rule_count,
                "filter.rules.new" = rules.len(),
                "Policy filter hash changed"
            );
        }
        self.rule_count = rules.len();
        changed.is_some()
    }

    pub(super) fn tags(&mut self, tags: &BTreeMap<String, IpSet>) -> bool {
        if self.deferred {
            return false;
        }
        let changed = self.tags.replace(encode(&ip_map(tags)));
        if let Some((old, new)) = &changed {
            tracing::debug!(
                "tagOwner.hash.old" = %old,
                "tagOwner.hash.new" = %new,
                "tagOwners.old" = self.tag_count,
                "tagOwners.new" = tags.len(),
                "Tag owner hash changed"
            );
        }
        self.tag_count = tags.len();
        changed.is_some()
    }

    pub(super) fn routes(&mut self, routes: &BTreeMap<String, IpSet>, present: bool) -> bool {
        if self.deferred {
            return false;
        }
        // resolveAutoApprovers returns a nil map only for a nil policy.
        let changed = self
            .routes
            .replace(encode(&present.then(|| ip_map(routes))));
        if let Some((old, new)) = &changed {
            tracing::debug!(
                "autoApprove.hash.old" = %old,
                "autoApprove.hash.new" = %new,
                "autoApprovers.old" = self.route_count,
                "autoApprovers.new" = routes.len(),
                "Auto-approvers hash changed"
            );
        }
        self.route_count = routes.len();
        changed.is_some()
    }

    pub(super) fn exit(&mut self, exit: Option<&IpSet>) -> bool {
        if self.deferred {
            return false;
        }
        let changed = self.exit.replace(encode(&exit.map(IpSet::strings)));
        if let Some((old, new)) = &changed {
            tracing::debug!(
                "exitSet.hash.old" = %old,
                "exitSet.hash.new" = %new,
                "Exit node set hash changed"
            );
        }
        changed.is_some()
    }
}

fn ip_map(map: &BTreeMap<String, IpSet>) -> BTreeMap<&str, Vec<String>> {
    map.iter()
        .map(|(key, ips)| (key.as_str(), ips.strings()))
        .collect()
}

/// Which diagnostic stages reported a changed hash.
#[derive(Clone, Copy)]
pub(super) struct StageChanges {
    pub(super) filter: bool,
    pub(super) tags: bool,
    pub(super) routes: bool,
    pub(super) exit: bool,
}

pub(super) struct Changes {
    filter: bool,
    tags: bool,
    routes: bool,
    exit: bool,
    emit_no_change: bool,
}

impl Changes {
    // This stage is reached only after nodeAttrs compilation succeeds, either
    // during serving refresh or the diagnostic-only constructor snapshot.
    pub(super) fn finish(self) {
        if self.filter || self.tags || self.routes || self.exit {
            tracing::debug!(
                "filter.changed" = self.filter,
                "tagOwners.changed" = self.tags,
                "autoApprovers.changed" = self.routes,
                "exitNodes.changed" = self.exit,
                "Policy changes require node updates"
            );
        } else if self.emit_no_change {
            tracing::trace!("Policy evaluation detected no changes - all hashes match");
        }
    }
}
