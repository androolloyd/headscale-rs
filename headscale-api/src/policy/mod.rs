//! Tailnet ACL policy: storage, hujson parser, ACL → FilterRule
//! translation, and a live-reload broadcast for `/map` long-pollers.
//!
//! ## Design
//!
//! The policy document on the wire is hujson (Tailscale's flavour of
//! JSON with `//` line comments, `/* … */` block comments, and trailing
//! commas). After stripping comments + trailing commas the body must
//! parse as a [`PolicyDoc`] — a serde mirror of OctraVPN's
//! `octravpn_mesh::acl::AclDoc`. We intentionally duplicate the type
//! here rather than depend on `octravpn-mesh`: that crate already
//! depends on `headscale-api`, and cycles in cargo are loud and
//! permanent. The struct is small and the wire format is the contract,
//! not the Rust type.
//!
//! [`PolicyStore`] is the single mutable cell. It carries:
//!
//! * the most-recent loaded `PolicyDoc` (or `None` if no operator has
//!   pushed a policy yet — the wire layer treats this as
//!   "allow-everything" to preserve the existing interop default), and
//! * a `tokio::sync::Notify` that fires every time the policy changes.
//!
//! `/map` long-pollers register on the Notify; the admin PUT route
//! flips the doc and calls `notify_waiters()`. Stock `tailscale`
//! daemons pick up the new `PacketFilter` on the next streamed chunk —
//! < 1 s for the common case.

pub mod doc;
pub mod filter;
pub mod hujson;
pub mod ssh;

use std::sync::Arc;

use parking_lot::RwLock;
use tokio::sync::Notify;

pub use doc::{
    AutoApprovers, NodeAttrGrant, NodeView, PolicyAction, PolicyDoc, PolicyRule, SshRule,
};
pub use filter::acl_to_filter_rules;
pub use hujson::{PolicyParseError, parse_hujson_policy};
pub use ssh::{SshPolicyNode, compile_ssh_policy};

use crate::tailscale_wire::wire::{FilterRule, SshPolicy};

/// Shared, swap-on-write policy store. Cheap to clone (`Arc`).
///
/// Construct once at server startup and hand to both the wire layer
/// (`WireState::policy`) and the admin layer (`AdminState::policy`).
#[derive(Clone, Default)]
pub struct PolicyStore {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    /// Currently loaded doc + the raw hujson bytes the operator pushed.
    /// We keep the raw bytes so `GET /api/v1/policy` round-trips the
    /// operator's exact source (comments preserved) rather than a
    /// serde re-emission.
    state: RwLock<PolicyState>,
    /// Wakes pending `/map` long-pollers when [`Self::set`] is called.
    /// Uses `tokio::sync::Notify` for the same reason the
    /// `MachineRegistry` does — `notify_waiters` is enqueue-free and
    /// the wake fans out to every parked task in one shot.
    notify: Notify,
}

#[derive(Default)]
struct PolicyState {
    doc: Option<PolicyDoc>,
    raw: Option<String>,
    updated_at: Option<i64>,
    /// Cached `Vec<FilterRule>` — recomputed inside [`PolicyStore::set`]
    /// so every `/map` rebuild is a single `read()` + clone.
    filters: Vec<FilterRule>,
}

impl PolicyStore {
    /// Construct an empty store. Callers must call [`Self::set`] before
    /// `/map` will emit non-default `PacketFilter` rules.
    pub fn new() -> Self {
        Self::default()
    }

    /// Atomically replace the policy. The raw hujson is preserved so
    /// `GET /api/v1/policy` round-trips the operator's source.
    /// Recomputes the cached `FilterRule` list and notifies every
    /// parked `/map` long-poller.
    pub fn set(&self, doc: PolicyDoc, raw: String) {
        let filters = acl_to_filter_rules(&doc);
        {
            let mut g = self.inner.state.write();
            g.doc = Some(doc);
            g.raw = Some(raw);
            g.updated_at = Some(now_unix());
            g.filters = filters;
        }
        self.inner.notify.notify_waiters();
    }

    /// True if [`Self::set`] has ever been called. Wire fallback
    /// reads this to decide between "allow-all default" and "use the
    /// cached FilterRules".
    pub fn is_loaded(&self) -> bool {
        self.inner.state.read().doc.is_some()
    }

    /// Snapshot the cached `FilterRule` list. Returns an empty vec if
    /// no policy has been pushed (callers decide whether to fall back
    /// to `allow_all_packet_filter`).
    pub fn filter_rules(&self) -> Vec<FilterRule> {
        self.inner.state.read().filters.clone()
    }

    /// Return the raw hujson bytes the operator most recently pushed,
    /// if any. Preserved verbatim across set→get.
    pub fn raw(&self) -> Option<String> {
        self.inner.state.read().raw.clone()
    }

    /// Unix-seconds timestamp for the most recent successful policy
    /// update, if a policy has been loaded.
    pub fn updated_at(&self) -> Option<i64> {
        self.inner.state.read().updated_at
    }

    /// Snapshot the parsed doc. `None` until the first successful PUT.
    pub fn doc(&self) -> Option<PolicyDoc> {
        self.inner.state.read().doc.clone()
    }

    /// Capability flags `node` should receive per the loaded policy's
    /// `node_attrs` block. Empty vec when no policy is loaded.
    ///
    /// The wire layer drives this from `MapResponse` construction so
    /// every emitted peer carries the correct
    /// `tailcfg.Node.CapMap` (`funnel`, `exit-node`, `ssh`, …).
    pub fn node_attrs_for(&self, node: &NodeView<'_>) -> Vec<String> {
        match self.inner.state.read().doc.as_ref() {
            Some(doc) => doc.node_attrs_for(node),
            None => Vec::new(),
        }
    }

    /// Compile the loaded policy's `ssh` block for `target_node_id`.
    /// Returns `None` when no policy is loaded or the policy has no
    /// SSH rules; returns an empty-policy object when SSH rules exist
    /// but none match the target. Mirrors headscale-go's
    /// `PolicyManager.SSHPolicy(node)` semantics.
    pub fn ssh_policy_for(
        &self,
        nodes: &[SshPolicyNode],
        target_node_id: u64,
    ) -> Option<SshPolicy> {
        match self.inner.state.read().doc.as_ref() {
            Some(doc) => compile_ssh_policy(doc, nodes, target_node_id),
            None => None,
        }
    }

    /// True iff `node` should have a route covering `prefix`
    /// auto-approved. Returns false when no policy is loaded — the
    /// admin path must then require an explicit operator action
    /// (i.e. `headscale nodes routes enable`).
    pub fn auto_approves_route(&self, node: &NodeView<'_>, prefix: &str) -> bool {
        match self.inner.state.read().doc.as_ref() {
            Some(doc) => doc.auto_approves_route(node, prefix),
            None => false,
        }
    }

    /// True iff `node` is auto-approved as an exit-node. Returns false
    /// when no policy is loaded.
    pub fn auto_approves_exit_node(&self, node: &NodeView<'_>) -> bool {
        match self.inner.state.read().doc.as_ref() {
            Some(doc) => doc.auto_approves_exit_node(node),
            None => false,
        }
    }

    /// Handle to the broadcast. Map long-pollers register
    /// `notify.notified()` futures in their `select!` loop; the next
    /// [`Self::set`] wakes them all.
    pub fn notify(&self) -> Arc<NotifyHandle> {
        Arc::new(NotifyHandle {
            inner: self.inner.clone(),
        })
    }

    /// Wait for the next policy change. Convenience around
    /// `notify().notified()` for callers that already hold the store.
    pub async fn wait_for_change(&self) {
        self.inner.notify.notified().await;
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Opaque waiter handle. Holds a strong ref to the underlying store so
/// the notify doesn't drop while a `/map` poller is parked on it.
pub struct NotifyHandle {
    inner: Arc<Inner>,
}

impl NotifyHandle {
    pub async fn changed(&self) {
        self.inner.notify.notified().await;
    }
}
