//! Tailnet ACL policy: storage, hujson parser, ACL → FilterRule
//! translation, and a live-reload broadcast for `/map` long-pollers.
//!
//! ## Design
//!
//! The policy document on the wire is hujson (Tailscale's flavour of
//! JSON with `//` line comments, `/* … */` block comments, and trailing
//! commas). After stripping comments + trailing commas the body must
//! parse as a [`PolicyDoc`] backed by the shared `headscale-api-acl`
//! leaf crate. The public contract is the upstream headscale policy
//! wire format, not any downstream Rust type.
//!
//! [`PolicyStore`] is the single mutable cell. It carries:
//!
//! * the most-recent loaded `PolicyDoc` (or `None` if no operator has
//!   pushed a policy yet — the wire layer treats this as
//!   "allow-everything" to preserve the existing interop default), and
//! * a retained watch notification for streamed map consumers, plus the
//!   existing Notify handle for callers waiting on the next policy change.
//!
//! `/map` streams retain a watch receiver across response chunks. Policy
//! publication wakes it so the next map rebuild reads the current filter.
//! The Notify handle remains available for callers waiting on the next change.

pub mod check;
mod diagnostics;
pub mod doc;
pub mod filter;
pub mod hujson;
pub(crate) mod lifecycle;
mod matcher;
mod opaque;
pub mod persistence;
mod resolution;
mod runtime;
pub mod ssh;
pub mod users;
mod via;

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    pin::Pin,
    sync::{Arc, Weak},
};

use parking_lot::{Mutex as SyncMutex, RwLock};
#[cfg(feature = "admin")]
use tokio::sync::{Mutex, OwnedMutexGuard};
use tokio::sync::{Notify, watch};

pub use check::{
    PolicyCheckNode, PolicyCheckNodeSnapshot, check_policy_semantics,
    check_policy_semantics_for_snapshot, check_policy_semantics_for_source,
    compile_policy_for_snapshot, warn_policy_tests_at_boot, warn_policy_tests_at_boot_for_snapshot,
    warn_policy_tests_at_boot_for_source,
};
pub use doc::{
    AutoApprovers, CapabilityMap, GrantRule, NodeAttrGrant, NodeView, PolicyAction, PolicyDoc,
    PolicyRule, PortRef, SshRule, ViaRouteCandidate, ViaRouteGrantResult,
};
pub use filter::{
    PacketFilterNode, acl_to_filter_rules, acl_to_filter_rules_for_node, allow_all_filter_rules,
};
pub use hujson::{PolicyParseError, parse_hujson_policy, parse_hujson_policy_bytes};
pub(crate) use opaque::FilterSnapshot;
pub(crate) use runtime::RouteApprovalSnapshot;
pub(crate) use ssh::NativeSshPolicy;
pub use ssh::{SshForwarding, SshPolicyNode, compile_ssh_policy, compile_ssh_policy_with_base_url};
pub use users::{
    PolicyUser, validate_policy_user_references, validate_policy_user_references_for_source,
};

use crate::tailscale_wire::wire::{FilterRule, SshPolicy};

/// Shared, swap-on-write policy store. Cheap to clone (`Arc`).
///
/// Construct once at server startup and hand to both the wire layer
/// (`WireState::policy`) and the admin layer (`AdminState::policy`).
#[derive(Clone, Default)]
pub struct PolicyStore {
    inner: Arc<Inner>,
}

/// Go PolicyManager.SetUsers reports client-policy and peer-map changes
/// separately. Display names, avatars and row timestamps are not policy facts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PolicyUserChange {
    pub policy_changed: bool,
    pub peer_map_changed: bool,
}

struct Inner {
    registry: SyncMutex<Option<Weak<crate::tailscale_wire::MachineRegistry>>>,
    /// Serializes asynchronous control-plane mutations through persistence,
    /// live projection and notification. Map readers use only `state`.
    #[cfg(feature = "admin")]
    mutation: Arc<Mutex<()>>,
    /// Currently loaded doc + the raw hujson bytes the operator pushed.
    /// We keep the raw bytes so `GET /api/v1/policy` round-trips the
    /// operator's exact source (comments preserved) rather than a
    /// serde re-emission.
    state: RwLock<PolicyState>,
    /// Legacy handle for callers waiting on the next policy change.
    notify: Notify,
    /// Retained map-stream receivers observe changes made between polls.
    changes: watch::Sender<()>,
    /// Native debug reads the configured source afresh, independently of the
    /// last accepted compiled policy. Keep its adapter outside policy state.
    debug_source: RwLock<Option<Arc<DebugPolicyReader>>>,
    /// Operator opt-out for SSH forwarding permissions. It is server config,
    /// not policy content, so it survives policy replacement and reload, and
    /// is applied to compiled SSH policies on read rather than baked into
    /// the per-node compile cache.
    ssh_forwarding: SyncMutex<SshForwarding>,
}

type DebugPolicyRead = Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send>>;
type DebugPolicyReader = dyn Fn() -> DebugPolicyRead + Send + Sync;

impl Default for Inner {
    fn default() -> Self {
        let (changes, _) = watch::channel(());
        Self {
            registry: SyncMutex::new(None),
            #[cfg(feature = "admin")]
            mutation: Arc::new(Mutex::new(())),
            state: RwLock::new(PolicyState::default()),
            notify: Notify::new(),
            changes,
            debug_source: RwLock::new(None),
            ssh_forwarding: SyncMutex::new(SshForwarding::default()),
        }
    }
}

#[derive(Default)]
struct PolicyState {
    doc: Option<PolicyDoc>,
    // Packet compilation expects generated network-grant rows before ACLs.
    // Keep that projection private so doc() returns the supplied document.
    filter_doc: Option<PolicyDoc>,
    users: Option<Vec<PolicyUser>>,
    raw: Option<String>,
    // Exact native source, which may not be representable by the public String.
    raw_bytes: Option<Vec<u8>>,
    compilation_source: Option<String>,
    updated_at: Option<i64>,
    // Independent of persisted wall-clock precision. Retained Arc identities
    // cannot collide while any SSH approval still refers to the old policy.
    ssh_auth_epoch: Arc<()>,
    /// Cached `Vec<FilterRule>` — recomputed inside [`PolicyStore::set`]
    /// so every `/map` rebuild is a single `read()` + clone.
    filters: Vec<FilterRule>,
    packet_filter_default_allow: bool,
    node_inputs: lifecycle::NodeInputs,
    grant_apps: Vec<lifecycle::GrantAppShape>,
    ssh_accept_env_nil: Vec<bool>,
    source_acl_rules: Vec<PolicyRule>,
    source_acl_identity: Option<headscale_api_acl::go_policy_shape::OriginalAclIdentity>,
    source_container_shape: Option<headscale_api_acl::go_policy_shape::PolicyContainerShape>,
    tag_owner_aliases: BTreeMap<String, Vec<String>>,
    compiled: Option<runtime::CompiledRuntime>,
    pending_attrs: BTreeSet<u64>,
    compile_error: Option<String>,
    diagnostics: diagnostics::PolicyDiagnostics,
    diagnostics_initial_snapshot: bool,
}

#[derive(Clone, Copy)]
enum Installation {
    Initial,
    Replacement,
}

impl PolicyState {
    fn complete_initial_diagnostics(&mut self, nodes: &[PacketFilterNode]) {
        if !self.diagnostics.resume_initial() {
            return;
        }
        let policy = diagnostics::policy_identity(
            self.doc.as_ref(),
            &self.grant_apps,
            &self.ssh_accept_env_nil,
            self.source_acl_identity.as_ref(),
            self.source_container_shape.as_ref(),
        );
        let global = match self.filter_doc.as_ref() {
            Some(doc) if !self.packet_filter_default_allow => {
                filter::acl_to_global_filter_rules_with_apps(doc, nodes, &self.grant_apps)
            }
            _ => allow_all_filter_rules(),
        };
        let diagnostic_changes = runtime::diagnose_snapshot(
            &mut self.diagnostics,
            &policy,
            self.filter_doc.as_ref(),
            &self.grant_apps,
            &self.tag_owner_aliases,
            self.packet_filter_default_allow,
            &global,
            nodes,
        );
        // The serving runtime refreshes nodeAttrs after these four stages.
        // Its initial bind can still be pending, so check the same projection
        // without installing attributes or changing validation/error outcomes.
        // A failure preserves the stage events but omits aggregate success.
        let attrs_succeeded = match self.filter_doc.as_ref() {
            Some(doc) if !doc.node_attrs.is_empty() || doc.randomize_client_port => {
                filter::compile_node_attrs(doc, nodes).is_ok()
            }
            _ => true,
        };
        if attrs_succeeded {
            diagnostic_changes.finish();
        }
        // Optional staged setup can finish diagnostics before its registry binds
        // retained inputs. Only that first identical bind omits its redundant
        // no-change trace; changed snapshots still emit all normal events.
        self.diagnostics_initial_snapshot = self.node_inputs.nodes().is_none();
    }

    fn recompile(&mut self, invalidate: bool) -> Result<bool, String> {
        let result = self.recompile_inner(invalidate);
        self.compile_error = result.as_ref().err().cloned();
        result
    }

    fn recompile_inner(&mut self, invalidate: bool) -> Result<bool, String> {
        let diagnostic_policy = diagnostics::policy_identity(
            self.doc.as_ref(),
            &self.grant_apps,
            &self.ssh_accept_env_nil,
            self.source_acl_identity.as_ref(),
            self.source_container_shape.as_ref(),
        );
        self.node_inputs
            .recompile(self.filter_doc.as_ref(), &self.grant_apps);
        if self.node_inputs.nodes().is_none() {
            let filters = match self.filter_doc.as_ref() {
                Some(doc) if !self.packet_filter_default_allow => {
                    filter::acl_to_global_filter_rules_with_apps(doc, &[], &self.grant_apps)
                }
                _ => allow_all_filter_rules(),
            };
            let changed = self.filters != filters;
            let diagnostic_changes = runtime::diagnose_without_nodes(
                &mut self.diagnostics,
                &diagnostic_policy,
                self.filter_doc.as_ref(),
                &self.grant_apps,
                &self.tag_owner_aliases,
                self.packet_filter_default_allow,
                &filters,
            );
            self.filters = filters;
            if let Some(doc) = &self.doc {
                filter::compile_node_attrs(doc, &[])?;
            }
            diagnostic_changes.finish();
            return Ok(changed);
        }
        let resolver_nodes = self.node_inputs.filter_nodes().unwrap_or_default();
        let compiled = self
            .compiled
            .get_or_insert_with(runtime::CompiledRuntime::default);
        let result = compiled.recompile(
            self.filter_doc.as_ref(),
            &self.grant_apps,
            &self.ssh_accept_env_nil,
            &self.tag_owner_aliases,
            resolver_nodes,
            self.packet_filter_default_allow,
            self.node_inputs.needs_per_node_filter(),
            invalidate,
            &mut self.diagnostics,
            &diagnostic_policy,
        );
        // Go updateLocked installs the global filter before nodeAttrs can
        // fail. SetUsers restores only its directory; SetPolicy recompiles
        // the previous document instead.
        self.filters = compiled.global_rules();
        let (changed_attrs, effects_changed) = result?;
        // Keep the union through multiple SetPolicy/SetUsers/SetNodes calls;
        // the next state-change dispatch owns the drain.
        self.pending_attrs.extend(changed_attrs);
        Ok(effects_changed)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct SshPolicyStamp {
    pub(crate) updated_at: Option<i64>,
    epoch: Arc<()>,
}

impl PartialEq for SshPolicyStamp {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.epoch, &other.epoch)
    }
}

impl Eq for SshPolicyStamp {}

impl PolicyStore {
    #[cfg(feature = "admin")]
    pub(crate) async fn lock_mutation(&self) -> OwnedMutexGuard<()> {
        self.inner.mutation.clone().lock_owned().await
    }

    /// Construct an empty store. Callers must call [`Self::set`] before
    /// `/map` will emit non-default `PacketFilter` rules.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct native policy state after users, nodes, and policy bytes have
    /// all loaded. The first compilation uses the complete input snapshot.
    /// A rejected constructor is discarded without replacement rollback.
    pub fn from_initial_registry(
        source: Option<(String, i64)>,
        users: Vec<PolicyUser>,
        registry: &crate::tailscale_wire::MachineRegistry,
    ) -> Result<Self, String> {
        let policy = source
            .filter(|(raw, _)| !raw.is_empty())
            .map(|(raw, updated_at)| {
                parse_hujson_policy(&raw)
                    .map(|doc| (doc, raw, updated_at))
                    .map_err(|error| {
                        let (PolicyParseError::Json(message) | PolicyParseError::Schema(message)) =
                            error;
                        format!("parsing policy: {message}")
                    })
            })
            .transpose()?;
        Self::from_initial_inputs(policy, Some(users), registry.policy_node_inputs())
    }

    /// Native byte-source constructor. Retains original bytes separately from
    /// the metadata-stripped source used for compilation and source shapes.
    pub fn from_initial_registry_bytes(
        source: Option<(Vec<u8>, i64)>,
        users: Vec<PolicyUser>,
        registry: &crate::tailscale_wire::MachineRegistry,
    ) -> Result<Self, String> {
        let mut original = None;
        let policy = source
            .filter(|(raw, _)| !raw.is_empty())
            .map(|(raw, updated_at)| {
                parse_hujson_policy_bytes(&raw)
                    .map(|(doc, compilation)| {
                        original = Some(raw);
                        (doc, compilation, updated_at)
                    })
                    .map_err(|error| {
                        let (PolicyParseError::Json(message) | PolicyParseError::Schema(message)) =
                            error;
                        format!("parsing policy: {message}")
                    })
            })
            .transpose()?;
        Self::from_initial_inputs_with_bytes(
            policy,
            Some(users),
            registry.policy_node_inputs(),
            original,
        )
    }

    fn from_initial_inputs(
        policy: Option<(PolicyDoc, String, i64)>,
        users: Option<Vec<PolicyUser>>,
        nodes: Vec<lifecycle::NodeInput>,
    ) -> Result<Self, String> {
        Self::from_initial_inputs_with_bytes(policy, users, nodes, None)
    }

    fn from_initial_inputs_with_bytes(
        policy: Option<(PolicyDoc, String, i64)>,
        mut users: Option<Vec<PolicyUser>>,
        nodes: Vec<lifecycle::NodeInput>,
        original: Option<Vec<u8>>,
    ) -> Result<Self, String> {
        if let Some(users) = &mut users {
            users.sort_by_key(|user| user.id);
        }
        let store = Self::new();
        {
            let mut state = store.inner.state.write();
            state.users.clone_from(&users);
            state.node_inputs.initialize(nodes);
        }
        if let Some((mut doc, raw, updated_at)) = policy {
            doc.users = users;
            store.install_at_quiet(doc, raw, updated_at, Installation::Initial, original)?;
        } else {
            store.inner.state.write().recompile(true)?;
        }
        Ok(store)
    }

    /// Construct staged native startup state without provisional policy logs.
    /// Complete diagnostics once the final users/policy/node snapshot exists.
    /// Serving, validation, and publication retain their ordinary boundaries.
    /// Errors before completion do not replay constructor diagnostic events.
    pub fn new_with_deferred_diagnostics() -> Self {
        let store = Self::new();
        store.inner.state.write().diagnostics.defer_initial();
        store
    }

    /// Emit the initial diagnostic lifecycle from one hydrated registry view.
    /// This does not bind the registry, install caches, or change validation
    /// outcomes. A nodeAttrs diagnostic check only gates the aggregate event.
    pub fn complete_initial_diagnostics_from_registry(
        &self,
        registry: &crate::tailscale_wire::MachineRegistry,
    ) {
        // Share the real retained-input projection, including native owner,
        // association and address overrides, without binding serving state.
        let mut inputs = lifecycle::NodeInputs::default();
        inputs.initialize(registry.policy_node_inputs());
        let nodes = inputs.filter_nodes().unwrap_or_default();
        self.inner
            .state
            .write()
            .complete_initial_diagnostics(&nodes);
    }

    /// Atomically replace the policy. The raw hujson is preserved so
    /// `GET /api/v1/policy` round-trips the operator's source.
    /// Recomputes the cached `FilterRule` list and notifies every
    /// parked `/map` long-poller.
    /// Rejected input is logged; use [`Self::try_set`] to handle its error.
    pub fn set(&self, doc: PolicyDoc, raw: String) {
        self.set_at(doc, raw, now_unix());
    }

    /// Replace the policy without notifying parked `/map` pollers.
    ///
    /// Callers that need to apply dependent runtime state, such as route
    /// auto-approvals, should call this and then [`Self::notify_change`]
    /// after the dependent updates complete.
    pub fn set_quiet(&self, doc: PolicyDoc, raw: String) {
        self.set_at_quiet(doc, raw, now_unix());
    }

    /// Same as [`Self::set`], but preserves the caller supplied
    /// update timestamp. DB-backed policy mode uses this to keep the
    /// in-memory cache and latest `policies.updated_at` row aligned.
    pub fn set_at(&self, doc: PolicyDoc, raw: String, updated_at: i64) {
        if let Err(error) = self.try_set_at(doc, raw, updated_at) {
            tracing::error!(%error, "rejecting policy replacement");
        }
    }

    /// Same as [`Self::set_at`], but leaves stream notification to the caller.
    /// Use [`Self::try_set_at_quiet`] when the caller must handle rejection.
    pub fn set_at_quiet(&self, doc: PolicyDoc, raw: String, updated_at: i64) {
        if let Err(error) = self.try_set_at_quiet(doc, raw, updated_at) {
            tracing::error!(%error, "rejecting policy replacement");
        }
    }

    /// Fallible replacement for callers that must propagate resolution errors.
    /// Rejected policy input leaves the active source and user directory intact.
    pub fn try_set(&self, doc: PolicyDoc, raw: String) -> Result<(), String> {
        self.try_set_at(doc, raw, now_unix())
    }

    /// Fallible replacement with a persisted timestamp and notification.
    pub fn try_set_at(&self, doc: PolicyDoc, raw: String, updated_at: i64) -> Result<(), String> {
        self.try_set_at_quiet(doc, raw, updated_at)?;
        self.notify_change();
        Ok(())
    }

    /// Fallible replacement that leaves dependent updates and dispatch to its caller.
    pub fn try_set_quiet(&self, doc: PolicyDoc, raw: String) -> Result<(), String> {
        self.try_set_at_quiet(doc, raw, now_unix())
    }

    /// Fallible quiet replacement with a caller-supplied persistence timestamp.
    pub fn try_set_at_quiet(
        &self,
        doc: PolicyDoc,
        raw: String,
        updated_at: i64,
    ) -> Result<(), String> {
        self.install_at_quiet(doc, raw, updated_at, Installation::Replacement, None)
    }

    /// Install an already parsed byte source after caller-owned validation.
    /// Compilation uses the supplied metadata-stripped source; reads retain
    /// the original bytes. Rejected replacements retain all previous sources.
    pub fn try_set_bytes_quiet(
        &self,
        doc: PolicyDoc,
        original: Vec<u8>,
        compilation: String,
    ) -> Result<(), String> {
        self.install_at_quiet(
            doc,
            compilation,
            now_unix(),
            Installation::Replacement,
            Some(original),
        )
    }

    fn install_at_quiet(
        &self,
        mut doc: PolicyDoc,
        raw: String,
        updated_at: i64,
        installation: Installation,
        original: Option<Vec<u8>>,
    ) -> Result<(), String> {
        let mut g = self.inner.state.write();
        if let Some(users) = &mut doc.users {
            users.sort_by_key(|user| user.id);
        } else {
            doc.users.clone_from(&g.users);
        }
        let (source_acl_rules, source_acl_aliases, source_acl_identity) =
            headscale_api_acl::go_policy_shape::original_acl_details(&raw, &doc).map_or_else(
                || (doc.rules.clone(), users::acl_user_aliases(&doc.rules), None),
                |(shape, identity)| (shape.rules, shape.user_aliases, Some(identity)),
            );
        if let Some(users) = &doc.users {
            users::validate_policy_user_references_with_acl_aliases(
                &doc,
                users,
                &source_acl_aliases,
            )
            .map_err(|error| match installation {
                Installation::Initial => format!("validating policy user references: {error}"),
                Installation::Replacement => error,
            })?;
        }
        let tag_owner_aliases = runtime::flatten_tag_owners(&doc)?;
        let users_changed = doc
            .users
            .as_ref()
            .is_some_and(|users| g.users.as_ref() != Some(users));
        // Raw nil/omitted slices supply the default only for an empty typed
        // policy. A programmatic policy can carry rules absent from its raw
        // display source; those rules must not be replaced by allow-all.
        let packet_filter_default_allow = doc.rules.is_empty()
            && doc.grants.is_empty()
            && filter::raw_policy_omits_packet_filter_rules(&raw);
        let grant_apps = lifecycle::grant_app_shapes(&raw);
        let ssh_accept_env_nil = headscale_api_acl::go_policy_shape::ssh_accept_env_nil(&raw);
        let source_container_shape =
            headscale_api_acl::go_policy_shape::policy_container_shape(&raw, &doc);
        // Resolve fallible grant projection before publishing candidate state.
        let filter_doc =
            headscale_api_acl::go_policy_shape::packet_filter_document(&doc, &source_acl_rules)?;
        let mut previous_content = g.doc.clone();
        if let Some(previous) = &mut previous_content {
            previous.users = None;
        }
        let mut next_content = doc.clone();
        next_content.users = None;
        let invalidate = previous_content.as_ref() != Some(&next_content)
            || g.packet_filter_default_allow != packet_filter_default_allow
            || g.grant_apps != grant_apps
            || g.ssh_accept_env_nil != ssh_accept_env_nil
            || g.source_acl_rules != source_acl_rules
            || g.source_acl_identity != source_acl_identity
            || g.source_container_shape != source_container_shape
            || users_changed;
        let previous_users = g.users.clone();
        g.users.clone_from(&doc.users);
        let previous_doc = g.doc.replace(doc);
        let previous_filter_doc = g.filter_doc.replace(filter_doc);
        let previous_default_allow = std::mem::replace(
            &mut g.packet_filter_default_allow,
            packet_filter_default_allow,
        );
        let previous_app_presence = std::mem::replace(&mut g.grant_apps, grant_apps);
        let previous_ssh_shape = std::mem::replace(&mut g.ssh_accept_env_nil, ssh_accept_env_nil);
        let previous_acls = std::mem::replace(&mut g.source_acl_rules, source_acl_rules);
        let previous_acl_identity =
            std::mem::replace(&mut g.source_acl_identity, source_acl_identity);
        let previous_container_shape =
            std::mem::replace(&mut g.source_container_shape, source_container_shape);
        let previous_tag_owners = std::mem::replace(&mut g.tag_owner_aliases, tag_owner_aliases);
        if let Err(error) = g.recompile(invalidate) {
            if matches!(installation, Installation::Initial) {
                return Err(error);
            }
            g.doc = previous_doc;
            g.filter_doc = previous_filter_doc;
            g.users = previous_users;
            g.packet_filter_default_allow = previous_default_allow;
            g.grant_apps = previous_app_presence;
            g.ssh_accept_env_nil = previous_ssh_shape;
            g.source_acl_rules = previous_acls;
            g.source_acl_identity = previous_acl_identity;
            g.source_container_shape = previous_container_shape;
            g.tag_owner_aliases = previous_tag_owners;
            if let Err(restore_error) = g.recompile(true) {
                tracing::error!(error = %restore_error, "restoring previous policy after rejected SetPolicy");
            }
            return Err(error);
        }
        if let Some(original) = original {
            g.raw = String::from_utf8(original.clone()).ok();
            g.raw_bytes = Some(original);
            g.compilation_source = Some(raw);
        } else {
            g.raw = Some(raw);
            g.raw_bytes = None;
            g.compilation_source = None;
        }
        g.updated_at = Some(updated_at);
        g.ssh_auth_epoch = Arc::new(());
        Ok(())
    }

    /// Go State.SetPolicy and ReloadPolicy clear SSH check auth even when no
    /// replacement bytes were supplied. Keep this separate from map notification.
    #[cfg(all(feature = "admin", feature = "full"))]
    pub(crate) fn invalidate_ssh_auth(&self) {
        self.inner.state.write().ssh_auth_epoch = Arc::new(());
    }

    pub(crate) fn with_ssh_auth_stamp<T>(&self, decide: impl FnOnce(SshPolicyStamp) -> T) -> T {
        let state = self.inner.state.read();
        decide(SshPolicyStamp {
            updated_at: state.updated_at,
            epoch: state.ssh_auth_epoch.clone(),
        })
    }

    /// Refresh account resolution without changing the stored policy source.
    /// An empty list is authoritative too. Unlike SetPolicy, SetUsers does not
    /// prevalidate every reference: each consuming resolver handles its error.
    pub fn set_users_quiet(&self, users: Vec<PolicyUser>) -> Result<(), String> {
        self.set_users_with_change_quiet(users).map(|_| ())
    }

    /// Refresh policy facts and report Go's independent policy/peer-map results.
    /// Current wire peer maps read the newly compiled matchers directly.
    pub fn set_users_with_change_quiet(
        &self,
        mut users: Vec<PolicyUser>,
    ) -> Result<PolicyUserChange, String> {
        users.sort_by_key(|user| user.id);
        let mut state = self.inner.state.write();
        if state.users.as_ref() == Some(&users) {
            return Ok(PolicyUserChange::default());
        }
        let peer_map_changed = state.users.as_deref().unwrap_or_default() != users.as_slice();
        let previous_users = state.users.replace(users.clone());
        if let Some(doc) = &mut state.doc {
            doc.users = Some(users.clone());
        }
        if let Some(doc) = &mut state.filter_doc {
            doc.users = Some(users);
        }
        if let Some(compiled) = &mut state.compiled {
            compiled.clear_caches();
        }
        let effects_changed = match state.recompile(true) {
            Ok(changed) => changed,
            Err(error) => {
                state.users.clone_from(&previous_users);
                if let Some(doc) = &mut state.doc {
                    doc.users.clone_from(&previous_users);
                }
                if let Some(doc) = &mut state.filter_doc {
                    doc.users.clone_from(&previous_users);
                }
                if let Some(compiled) = &mut state.compiled {
                    compiled.restore_user_directory(previous_users);
                }
                return Err(error);
            }
        };
        let policy_changed = effects_changed
            || (peer_map_changed
                && (state.node_inputs.needs_per_node_filter()
                    || state.doc.as_ref().is_some_and(|doc| !doc.ssh.is_empty())));
        Ok(PolicyUserChange {
            policy_changed,
            peer_map_changed,
        })
    }

    #[cfg(feature = "admin")]
    pub(crate) fn has_user_id(&self, id: u64) -> bool {
        self.inner
            .state
            .read()
            .users
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|user| user.id == id)
    }

    /// Dispatch a user refresh without re-running policy route auto-approval.
    /// An empty broad change may still carry accumulated node-attribute updates.
    pub fn notify_user_change(&self, change: PolicyUserChange) {
        if change.policy_changed {
            self.refresh();
        } else {
            let registry = self.inner.registry.lock().as_ref().and_then(Weak::upgrade);
            if let Some(registry) = registry {
                registry.dispatch_map_change(None);
            }
        }
    }

    pub(crate) fn same_store(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    pub(crate) fn bind_registry(&self, registry: Weak<crate::tailscale_wire::MachineRegistry>) {
        *self.inner.registry.lock() = Some(registry);
    }

    pub(crate) fn compilation_result(&self) -> Result<(), String> {
        self.inner
            .state
            .read()
            .compile_error
            .clone()
            .map_or(Ok(()), Err)
    }

    pub(crate) fn initialize_node_inputs(
        &self,
        nodes: Vec<lifecycle::NodeInput>,
    ) -> Result<(), String> {
        let mut state = self.inner.state.write();
        if state.node_inputs.initialize(nodes) {
            if std::mem::take(&mut state.diagnostics_initial_snapshot) {
                state.diagnostics.suppress_initial_attach_no_change();
            }
            state.recompile(true)?;
        }
        state.compile_error.clone().map_or(Ok(()), Err)
    }

    pub(crate) fn try_replace_node_inputs(
        &self,
        nodes: Vec<lifecycle::NodeInput>,
    ) -> Result<bool, String> {
        let mut state = self.inner.state.write();
        let (invalidations, known) = state.node_inputs.cache_invalidations(&nodes);
        if let Some(compiled) = &mut state.compiled {
            compiled.invalidate_network(&invalidations, &known);
        }
        let changed = state.node_inputs.replace(nodes);
        if changed {
            state.recompile(true)?;
        }
        Ok(changed)
    }

    pub(crate) fn drain_changed_node_attrs(&self) -> BTreeSet<u64> {
        std::mem::take(&mut self.inner.state.write().pending_attrs)
    }

    /// Notify parked `/map` pollers after a policy update is fully observable.
    pub fn notify_change(&self) {
        self.emit_change(true);
    }

    fn emit_change(&self, approve_routes: bool) {
        let registry = self.inner.registry.lock().as_ref().and_then(Weak::upgrade);
        if let Some(registry) = registry {
            if approve_routes
                && !registry.policy_routes_require_persistence()
                && let Err(error) =
                    crate::tailscale_wire::map::apply_policy_auto_approvals_for_registry(
                        &registry, self,
                    )
            {
                tracing::error!(%error, "applying policy route auto-approvals");
            }
            // Native callers have already persisted their approval batch.
            // Volatile callers complete their quiet batch before dispatch.
            // The registry also drains accumulated policy CapMap changes.
            registry.wake_policy_change(None);
        } else {
            // send_modify records a new watch version even when the payload is (),
            // including while there are no receivers. A retained map receiver
            // observes changes that occurred between response chunks.
            self.inner.changes.send_modify(|()| {});
        }
        self.inner.notify.notify_waiters();
    }

    pub(crate) fn subscribe_changes(&self) -> watch::Receiver<()> {
        self.inner.changes.subscribe()
    }

    /// True if [`Self::set`] has ever been called. Wire fallback
    /// reads this to decide between "allow-all default" and "use the
    /// cached FilterRules".
    pub fn is_loaded(&self) -> bool {
        self.inner.state.read().doc.is_some()
    }

    /// Number of ACL rules in the loaded policy, or `None` when no
    /// policy is loaded.
    pub fn acl_rule_count(&self) -> Option<usize> {
        self.inner
            .state
            .read()
            .doc
            .as_ref()
            .map(|doc| doc.rules.len())
    }

    /// Snapshot the cached `FilterRule` list. Returns an empty vec if
    /// no policy has been pushed (callers decide whether to fall back
    /// to `allow_all_packet_filter`).
    pub fn filter_rules(&self) -> Vec<FilterRule> {
        self.inner.state.read().filters.clone()
    }

    /// Snapshot packet-filter rules for a specific map recipient.
    ///
    /// Returns `None` when no policy is loaded so callers can apply
    /// their no-policy compatibility default. A loaded deny-all policy
    /// returns `Some(vec![])`, which is distinct and must stay empty on
    /// the wire.
    pub fn filter_rules_for_node(
        &self,
        nodes: &[PacketFilterNode],
        node_id: u64,
    ) -> Option<Vec<FilterRule>> {
        let state = self.inner.state.read();
        let doc = state.filter_doc.as_ref()?;
        if let Some(compiled) = &state.compiled {
            return Some(
                nodes
                    .iter()
                    .find(|node| node.id == node_id)
                    .map(|node| compiled.filter_for(node))
                    .unwrap_or_default(),
            );
        }
        if state.packet_filter_default_allow {
            return state.doc.as_ref().map(|_| state.filters.clone());
        }
        Some(
            nodes
                .iter()
                .find(|node| node.id == node_id)
                .map(|node| {
                    filter::acl_to_filter_rules_for_receiver_with_apps(
                        doc,
                        nodes,
                        node,
                        &state.grant_apps,
                    )
                })
                .unwrap_or_default(),
        )
    }

    pub(crate) fn filter_snapshot_for_node(
        &self,
        nodes: &[PacketFilterNode],
        node_id: u64,
    ) -> Option<FilterSnapshot> {
        let state = self.inner.state.read();
        let doc = state.filter_doc.as_ref()?;
        let Some(receiver) = nodes.iter().find(|node| node.id == node_id) else {
            return Some(FilterSnapshot::new(
                Vec::new(),
                opaque::OpaqueFilter::default(),
            ));
        };
        if let Some(compiled) = &state.compiled {
            return Some(compiled.filter_snapshot(receiver));
        }
        if state.packet_filter_default_allow {
            return Some(FilterSnapshot::allow_all());
        }
        let rules = filter::acl_to_filter_rules_for_receiver_with_apps(
            doc,
            nodes,
            receiver,
            &state.grant_apps,
        );
        let opaque_doc = opaque::document(doc, &state.grant_apps);
        let opaque = opaque::OpaqueFilter(filter::acl_to_filter_rules_for_receiver_with_apps(
            &opaque_doc,
            nodes,
            receiver,
            &state.grant_apps,
        ));
        Some(FilterSnapshot::new(rules, opaque))
    }

    /// Return the raw hujson bytes the operator most recently pushed,
    /// if any. Preserved verbatim across set→get.
    pub fn raw(&self) -> Option<String> {
        self.inner.state.read().raw.clone()
    }

    /// Exact operator source, including bytes not representable by `raw()`.
    pub fn raw_bytes(&self) -> Option<Vec<u8>> {
        let state = self.inner.state.read();
        state
            .raw_bytes
            .clone()
            .or_else(|| state.raw.as_ref().map(|raw| raw.as_bytes().to_vec()))
    }

    // Only the gRPC admin service installs a debug source, and it exists
    // only when both `admin` and `full` (which gates `grpc`) are enabled.
    #[cfg(all(feature = "admin", feature = "full"))]
    pub(crate) fn set_debug_source<F, Fut>(&self, read: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<u8>, String>> + Send + 'static,
    {
        *self.inner.debug_source.write() =
            Some(Arc::new(move || -> DebugPolicyRead { Box::pin(read()) }));
    }

    pub(crate) async fn debug_source_bytes(&self) -> Result<Vec<u8>, String> {
        // Release the adapter lock before file/database I/O. No policy mutation
        // lock is needed: debug source can differ from the last accepted policy.
        let read = self.inner.debug_source.read().clone();
        match read {
            Some(read) => read().await,
            None => self
                .raw_bytes()
                .ok_or_else(|| "no policy loaded".to_owned()),
        }
    }

    /// Valid source for compilation and source-shape inspection. This may have
    /// metadata removed and must not be presented as the original source.
    pub fn source_for_compilation(&self) -> Option<String> {
        let state = self.inner.state.read();
        state
            .compilation_source
            .clone()
            .or_else(|| state.raw.clone())
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

    /// SetPolicy and ReloadPolicy resolve against the policy manager's retained
    /// directory, independently of a fresh database list operation.
    #[cfg(feature = "admin")]
    pub(crate) fn users_snapshot(&self) -> Vec<PolicyUser> {
        self.inner.state.read().users.clone().unwrap_or_default()
    }

    /// True iff the loaded policy defines `tag`.
    ///
    /// Mirrors headscale-go's `PolicyManager.TagExists` use in
    /// `State.SetNodeTags`: admin/gRPC tag assignment is an operator
    /// action, so it checks tag existence in policy, not per-user
    /// ownership. No loaded policy means no tag is assignable.
    pub fn tag_exists(&self, tag: &str) -> bool {
        self.inner.state.read().doc.as_ref().is_some_and(|doc| {
            doc.tag_owners.contains_key(tag)
                || doc.tags.contains_key(tag)
                || tag.strip_prefix("tag:").is_some_and(|short| {
                    doc.tag_owners.contains_key(short) || doc.tags.contains_key(short)
                })
        })
    }

    /// Target roles read the retained compiled policy, rather than treating
    /// every node in a tailnet with relay/via grants as a recompute source.
    pub(crate) fn is_relay_or_via_target(&self, node: &NodeView<'_>) -> bool {
        let state = self.inner.state.read();
        if let Some(compiled) = &state.compiled {
            return compiled.is_relay_or_via_target(node);
        }
        runtime::PeerRecomputeTargets::compile(
            state.doc.as_ref(),
            &state.node_inputs.filter_nodes().unwrap_or_default(),
            &state.filters,
        )
        .contains(node)
    }

    /// Go's direct user/group fallback without a registered-node snapshot.
    /// Nested tag owners require `node_can_have_tag_with_nodes`. No loaded
    /// policy means no client-requested tag is assignable.
    pub fn node_can_have_tag(&self, node: &NodeView<'_>, tag: &str) -> bool {
        let state = self.inner.state.read();
        if let Some(compiled) = &state.compiled {
            return compiled.node_can_have_tag(node, tag);
        }
        state
            .doc
            .as_ref()
            .is_some_and(|doc| doc.node_can_have_tag(node, tag))
    }

    pub fn node_can_have_tag_with_nodes(
        &self,
        node: &NodeView<'_>,
        tag: &str,
        nodes: &[NodeView<'_>],
    ) -> bool {
        let state = self.inner.state.read();
        if let Some(compiled) = &state.compiled {
            return compiled.node_can_have_tag(node, tag);
        }
        state
            .doc
            .as_ref()
            .is_some_and(|doc| doc.node_can_have_tag_with_nodes(node, tag, nodes))
    }

    pub fn user_can_have_tag(&self, user_id: Option<u64>, user: Option<&str>, tag: &str) -> bool {
        self.inner
            .state
            .read()
            .doc
            .as_ref()
            .is_some_and(|doc| doc.user_can_have_tag(user_id, user, tag))
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

    pub(crate) fn node_attrs_for_id(&self, id: u64, node: &NodeView<'_>) -> Vec<String> {
        let state = self.inner.state.read();
        if let Some(compiled) = &state.compiled {
            return compiled.attrs_for(id);
        }
        state
            .doc
            .as_ref()
            .map(|doc| doc.node_attrs_for(node))
            .unwrap_or_default()
    }

    /// Capture all map-builder attributes under one policy read. The caller
    /// retains the result with its node snapshot through wire encoding.
    pub(crate) fn node_attrs_snapshot<'a>(
        &self,
        nodes: impl IntoIterator<Item = (u64, NodeView<'a>)>,
    ) -> std::collections::HashMap<u64, Vec<String>> {
        let state = self.inner.state.read();
        nodes
            .into_iter()
            .map(|(id, node)| {
                let attrs = if let Some(compiled) = &state.compiled {
                    compiled.attrs_for(id)
                } else {
                    state
                        .doc
                        .as_ref()
                        .map(|doc| doc.node_attrs_for(&node))
                        .unwrap_or_default()
                };
                (id, attrs)
            })
            .collect()
    }

    /// Compile the loaded policy's `ssh` block for `target_node_id`.
    /// Returns `None` when no policy is loaded or the target is unknown;
    /// returns an empty-policy object when the policy has no SSH rules
    /// or none match the target. headscale-go v0.29.5's
    /// `compileSSHPolicy` never returns nil: clients read an omitted
    /// policy as "keep the previous rules", so revocation must be explicit.
    pub fn ssh_policy_for(
        &self,
        nodes: &[SshPolicyNode],
        target_node_id: u64,
        base_url: &str,
    ) -> Option<SshPolicy> {
        self.ssh_policy_snapshot_for(nodes, target_node_id, base_url)
            .map(|snapshot| snapshot.policy)
    }

    pub(crate) fn ssh_policy_snapshot_for(
        &self,
        nodes: &[SshPolicyNode],
        target_node_id: u64,
        base_url: &str,
    ) -> Option<NativeSshPolicy> {
        let mut snapshot = self.compiled_ssh_policy_for(nodes, target_node_id, base_url)?;
        // Applied here, after the per-node compile cache, so every reader of a
        // compiled SSH policy (map responses, debug) sees the same narrowing
        // and a policy reload cannot resurrect a flag the operator cleared.
        self.ssh_forwarding().restrict(&mut snapshot.policy);
        Some(snapshot)
    }

    fn compiled_ssh_policy_for(
        &self,
        nodes: &[SshPolicyNode],
        target_node_id: u64,
        base_url: &str,
    ) -> Option<NativeSshPolicy> {
        let state = self.inner.state.read();
        if let Some(compiled) = &state.compiled {
            let receiver = nodes.iter().find(|node| node.id == target_node_id)?;
            let sources = state.node_inputs.ssh_nodes().unwrap_or_default();
            return compiled.ssh_for(&sources, receiver, base_url);
        }
        match state.doc.as_ref() {
            Some(doc) => {
                let receiver = nodes.iter().find(|node| node.id == target_node_id)?;
                Some(ssh::compile_ssh_policy_snapshot(
                    doc,
                    nodes,
                    receiver,
                    base_url,
                    &state.ssh_accept_env_nil,
                ))
            }
            None => None,
        }
    }

    /// Install the operator's SSH forwarding opt-out (server config
    /// `policy.ssh.*`). Call once at startup; later policy replacement and
    /// reload leave it in place.
    pub fn set_ssh_forwarding(&self, forwarding: SshForwarding) {
        *self.inner.ssh_forwarding.lock() = forwarding;
    }

    /// The forwarding permissions SSH actions may carry. Defaults to every
    /// permission, matching headscale-go.
    pub fn ssh_forwarding(&self) -> SshForwarding {
        *self.inner.ssh_forwarding.lock()
    }

    pub fn ssh_check_period_for(
        &self,
        nodes: &[SshPolicyNode],
        src_node_id: u64,
        dst_node_id: u64,
        local_user: &str,
    ) -> Option<std::time::Duration> {
        self.with_ssh_check_period_for(nodes, src_node_id, dst_node_id, local_user, |period, _| {
            period
        })
    }

    /// Hold one policy snapshot through a synchronous SSH cache decision.
    /// A policy swap cannot split rule evaluation from approval stamping.
    pub(crate) fn with_ssh_check_period_for<T>(
        &self,
        nodes: &[SshPolicyNode],
        src_node_id: u64,
        dst_node_id: u64,
        local_user: &str,
        decide: impl FnOnce(Option<std::time::Duration>, SshPolicyStamp) -> T,
    ) -> T {
        self.with_ssh_check_period_for_bytes(
            nodes,
            src_node_id,
            dst_node_id,
            local_user.as_bytes(),
            decide,
        )
    }

    pub(crate) fn with_ssh_check_period_for_bytes<T>(
        &self,
        nodes: &[SshPolicyNode],
        src_node_id: u64,
        dst_node_id: u64,
        local_user: &[u8],
        decide: impl FnOnce(Option<std::time::Duration>, SshPolicyStamp) -> T,
    ) -> T {
        let state = self.inner.state.read();
        let retained_nodes = state.node_inputs.ssh_nodes();
        let nodes = retained_nodes.as_deref().unwrap_or(nodes);
        let period = state.doc.as_ref().and_then(|doc| {
            ssh::ssh_check_period_for_bytes(doc, nodes, src_node_id, dst_node_id, local_user)
        });
        decide(
            period,
            SshPolicyStamp {
                updated_at: state.updated_at,
                epoch: state.ssh_auth_epoch.clone(),
            },
        )
    }

    /// True iff `node` should have a route covering `prefix`
    /// auto-approved. Returns false when no policy is loaded — the
    /// admin path must then require an explicit operator action
    /// (i.e. `headscale nodes routes enable`).
    pub fn auto_approves_route(&self, node: &NodeView<'_>, prefix: &str) -> bool {
        let state = self.inner.state.read();
        if let Some(compiled) = &state.compiled {
            return compiled.auto_approves_route(node, prefix);
        }
        match state.doc.as_ref() {
            Some(doc) => doc.auto_approves_route(node, prefix),
            None => false,
        }
    }

    /// True iff `node` is auto-approved as an exit-node. Returns false
    /// when no policy is loaded.
    pub fn auto_approves_exit_node(&self, node: &NodeView<'_>) -> bool {
        let state = self.inner.state.read();
        if let Some(compiled) = &state.compiled {
            return compiled.auto_approves_exit(node);
        }
        match state.doc.as_ref() {
            Some(doc) => doc.auto_approves_exit_node(node),
            None => false,
        }
    }

    pub(crate) fn route_approval_snapshot(&self) -> RouteApprovalSnapshot {
        let state = self.inner.state.read();
        state.compiled.as_ref().map_or_else(
            || RouteApprovalSnapshot::legacy(state.doc.clone()),
            runtime::CompiledRuntime::approval_snapshot,
        )
    }

    /// Build symmetric peer visibility for the loaded policy. Returns
    /// `None` when no operator policy has been loaded, which callers
    /// should treat as headscale-rs' legacy open default.
    pub fn build_peer_map(&self, nodes: &[PeerMapNode]) -> Option<BTreeMap<u64, Vec<u64>>> {
        self.build_peer_map_with_user_ids(nodes, &BTreeMap::new())
    }

    pub fn build_peer_map_with_user_ids(
        &self,
        nodes: &[PeerMapNode],
        owners: &BTreeMap<u64, u64>,
    ) -> Option<BTreeMap<u64, Vec<u64>>> {
        let state = self.inner.state.read();
        let doc = state.doc.as_ref()?;
        if let Some(compiled) = &state.compiled {
            let nodes = nodes
                .iter()
                .map(|node| node.packet_node(owners.get(&node.id).copied()))
                .collect::<Vec<_>>();
            return Some(compiled.build_peer_map(&nodes));
        }
        Some(build_peer_map_for_doc_with_user_ids(doc, nodes, owners))
    }

    /// Compute `grants[*].via` route effects for one map recipient
    /// viewing one peer. `None` means no operator policy is loaded.
    pub fn via_routes_for_peer(
        &self,
        nodes: &[PeerMapNode],
        viewer_id: u64,
        peer_id: u64,
    ) -> Option<ViaRouteGrantResult> {
        self.via_routes_for_peer_with_user_ids(nodes, viewer_id, peer_id, &BTreeMap::new())
    }

    pub fn via_routes_for_peer_with_user_ids(
        &self,
        nodes: &[PeerMapNode],
        viewer_id: u64,
        peer_id: u64,
        owners: &BTreeMap<u64, u64>,
    ) -> Option<ViaRouteGrantResult> {
        let state = self.inner.state.read();
        let doc = state.doc.as_ref()?;
        let viewer = nodes.iter().find(|node| node.id == viewer_id)?;
        let peer = nodes.iter().find(|node| node.id == peer_id)?;
        let retained = state.node_inputs.filter_nodes().unwrap_or_else(|| {
            nodes
                .iter()
                .map(|node| node.packet_node(owners.get(&node.id).copied()))
                .collect()
        });
        Some(via::routes_for_peer(
            doc,
            &state.source_acl_rules,
            &retained,
            &viewer.packet_node(owners.get(&viewer.id).copied()),
            &peer.packet_node(owners.get(&peer.id).copied()),
        ))
    }

    /// WithSelfNode uses global State.Filter matchers, including when peer
    /// views need per-node matchers. Preserve the input route order.
    pub(crate) fn reduce_self_routes(
        &self,
        node: &PacketFilterNode,
        routes: &[String],
    ) -> Vec<String> {
        let state = self.inner.state.read();
        if let Some(compiled) = &state.compiled {
            return compiled.reduce_self_routes(node, routes);
        }
        let default;
        let rules = if state.doc.is_none() {
            default = allow_all_filter_rules();
            default.as_slice()
        } else {
            state.filters.as_slice()
        };
        let matchers = matcher::RuleMatcher::from_rules(rules);
        routes
            .iter()
            .filter(|route| matcher::RuleMatcher::can_access_route(&matchers, node, route))
            .cloned()
            .collect()
    }

    /// True iff `viewer_id` is authorized to receive `route` from
    /// `peer_id`, without treating direct peer node-IP visibility as
    /// route authorization. Returns `None` when no policy is loaded,
    /// which callers should treat as the legacy open default.
    pub fn can_access_route_for_peer(
        &self,
        nodes: &[PeerMapNode],
        viewer_id: u64,
        peer_id: u64,
        route: &str,
    ) -> Option<bool> {
        self.can_access_route_for_peer_with_user_ids(
            nodes,
            viewer_id,
            peer_id,
            route,
            &BTreeMap::new(),
        )
    }

    pub fn can_access_route_for_peer_with_user_ids(
        &self,
        nodes: &[PeerMapNode],
        viewer_id: u64,
        peer_id: u64,
        route: &str,
        owners: &BTreeMap<u64, u64>,
    ) -> Option<bool> {
        let state = self.inner.state.read();
        let doc = state.doc.as_ref()?;
        let Some(viewer) = nodes.iter().find(|node| node.id == viewer_id) else {
            return Some(false);
        };
        let Some(peer) = nodes.iter().find(|node| node.id == peer_id) else {
            return Some(false);
        };
        if let Some(compiled) = &state.compiled {
            let viewer = viewer.packet_node(owners.get(&viewer.id).copied());
            return Some(compiled.can_access_route(&viewer, route));
        }
        Some(doc.can_access_route(
            &viewer.view(owners.get(&viewer.id).copied()),
            &viewer.routes,
            &peer.view(owners.get(&peer.id).copied()),
            route,
        ))
    }

    /// Wake every parked `/map` long-poller without changing the
    /// loaded policy bytes.
    ///
    /// Upstream refreshes PolicyManager-derived map state on adjacent
    /// control-plane mutations such as user CRUD. The Rust policy store
    /// retains the policy source while its account snapshot changes. The
    /// stream needs a full rebuild so user/profile/policy-derived
    /// map fields are observed promptly.
    pub fn refresh(&self) {
        // User-list changes do not run State.ReloadPolicy's route fan-out.
        self.emit_change(false);
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

/// Sort, dedupe, and validate client-requested ACL tags for a node.
///
/// Returns `Ok(true)` when at least one valid requested tag remains.
/// Callers should clear node-key expiry in that case, matching
/// headscale-go's tagged-node registration semantics.
pub fn validate_requested_tags_for_node(
    policy: &PolicyStore,
    ipv4: &str,
    user: &str,
    tags: &mut Vec<String>,
) -> Result<bool, String> {
    validate_requested_tags_for_node_with_user_id(policy, ipv4, user, None, tags)
}

pub fn validate_requested_tags_for_node_with_user_id(
    policy: &PolicyStore,
    _ipv4: &str,
    user: &str,
    user_id: Option<u64>,
    tags: &mut Vec<String>,
) -> Result<bool, String> {
    // No stored-node snapshot is supplied at this legacy/new-node boundary.
    validate_requested_tags_for_auth_path(policy, None, &[], user, user_id, tags)
}

/// Authorize reauthentication against the stored node OR the authenticating
/// user. Fresh nodes have no owner-IP-set membership before allocation.
/// Rejected tags retain request order and duplicates; only successful tags
/// are sorted and compacted before persistence, matching pinned Go.
pub fn validate_requested_tags_for_auth_path(
    policy: &PolicyStore,
    existing: Option<&NodeView<'_>>,
    nodes: &[NodeView<'_>],
    user: &str,
    user_id: Option<u64>,
    tags: &mut Vec<String>,
) -> Result<bool, String> {
    if tags.is_empty() {
        return Ok(false);
    }
    let invalid_tags = {
        let state = policy.inner.state.read();
        let mut permissions = BTreeMap::new();
        tags.iter()
            .filter(|tag| {
                !*permissions.entry(tag.as_str()).or_insert_with(|| {
                    state.doc.as_ref().is_some_and(|doc| {
                        existing.is_some_and(|node| {
                            state.compiled.as_ref().map_or_else(
                                || doc.node_can_have_tag_with_nodes(node, tag, nodes),
                                |compiled| compiled.node_can_have_tag(node, tag),
                            )
                        }) || doc.user_can_have_tag(user_id, Some(user), tag)
                    })
                })
            })
            .cloned()
            .collect::<Vec<_>>()
    };
    if !invalid_tags.is_empty() {
        return Err(format!(
            "requested tags [{}] are invalid or not permitted",
            invalid_tags.join(" ")
        ));
    }
    tags.sort();
    tags.dedup();
    Ok(true)
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

/// Node facets needed for headscale-go peer-map reduction.
///
/// `routes` must contain the active routes this node serves to peers:
/// primary subnet routes plus active exit-node defaults.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerMapNode {
    pub id: u64,
    pub addr: String,
    pub addrs: Vec<String>,
    pub user: Option<String>,
    pub tags: Vec<String>,
    pub routes: Vec<String>,
}

impl PeerMapNode {
    fn packet_node(&self, user_id: Option<u64>) -> PacketFilterNode {
        PacketFilterNode {
            id: self.id,
            user_id,
            user: self.user.clone(),
            addrs: if self.addrs.is_empty() {
                (!self.addr.is_empty())
                    .then(|| self.addr.clone())
                    .into_iter()
                    .collect()
            } else {
                self.addrs.clone()
            },
            tags: self.tags.clone(),
            routes: self.routes.clone(),
        }
    }

    fn view(&self, user_id: Option<u64>) -> NodeView<'_> {
        let primary = if self.addr.is_empty() {
            self.addrs.first().map(String::as_str)
        } else {
            Some(self.addr.as_str())
        };
        NodeView {
            user_id,
            addr: primary,
            addrs: &self.addrs,
            user: self.user.as_deref(),
            tags: &self.tags,
        }
    }
}

/// Build headscale-go-style symmetric peer visibility for a loaded policy.
///
/// If either side can access the other node IP or one of the other
/// node's served routes, both nodes are included in each other's peer
/// list. This mirrors upstream `PolicyManager.BuildPeerMap`.
pub fn build_peer_map_for_doc(doc: &PolicyDoc, nodes: &[PeerMapNode]) -> BTreeMap<u64, Vec<u64>> {
    build_peer_map_for_doc_with_user_ids(doc, nodes, &BTreeMap::new())
}

pub fn build_peer_map_for_doc_with_user_ids(
    doc: &PolicyDoc,
    nodes: &[PeerMapNode],
    owners: &BTreeMap<u64, u64>,
) -> BTreeMap<u64, Vec<u64>> {
    let mut out: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for i in 0..nodes.len() {
        let node_i = &nodes[i];
        let view_i = node_i.view(owners.get(&node_i.id).copied());
        for node_j in nodes.iter().skip(i + 1) {
            if node_i.id == node_j.id {
                continue;
            }
            let view_j = node_j.view(owners.get(&node_j.id).copied());
            let i_can_access_j = doc.can_access_node(
                &view_i,
                &node_i.routes,
                &view_j,
                &node_j.routes,
                PortRef::any(),
            );
            let j_can_access_i = doc.can_access_node(
                &view_j,
                &node_j.routes,
                &view_i,
                &node_i.routes,
                PortRef::any(),
            );
            if i_can_access_j || j_can_access_i {
                out.entry(node_i.id).or_default().insert(node_j.id);
                out.entry(node_j.id).or_default().insert(node_i.id);
            }
        }
    }

    out.into_iter()
        .map(|(id, peers)| (id, peers.into_iter().collect()))
        .collect()
}

#[cfg(test)]
mod release_0295_tests {
    use super::*;

    // headscale-go v0.29.5 clears every cached SSH check approval on each
    // policy replacement (state.ClearSSHCheckAuth), including two reloads
    // that share one wall-clock second or one persisted timestamp, and
    // policy/v2 compileSSHPolicy never returns a nil policy: a document with
    // no `ssh` block compiles to an explicit empty rule list.
    #[test]
    fn release_0295_revoked_ssh_policy_is_explicit_and_each_reload_invalidates_auth() {
        let store = PolicyStore::new();
        let raw = r#"{"ssh": [{"action":"check", "src":["alice@"], "dst":["autogroup:self"], "users":["root"]}]}"#;
        let doc = parse_hujson_policy(raw).unwrap();
        store.try_set_at(doc.clone(), raw.into(), 1).unwrap();
        let first = store.with_ssh_auth_stamp(|stamp| stamp);
        store.try_set_at(doc, raw.into(), 1).unwrap();
        let second = store.with_ssh_auth_stamp(|stamp| stamp);
        assert_eq!(first.updated_at, second.updated_at);
        assert_ne!(
            first, second,
            "reloads with an identical timestamp invalidate cached SSH authorization"
        );

        store
            .try_set(parse_hujson_policy("{}").unwrap(), "{}".into())
            .unwrap();
        let nodes = [SshPolicyNode {
            id: 1,
            user: Some("alice".into()),
            user_id: Some(1),
            addrs: vec!["100.64.0.1".into()],
            tags: Vec::new(),
        }];
        assert_eq!(
            store.ssh_policy_for(&nodes, 1, ""),
            Some(SshPolicy::default())
        );
    }
}
