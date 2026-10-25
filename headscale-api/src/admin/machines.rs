//! Admin-side machine surface.
//!
//! [`MachineAdmin`] separates the admin surface from registry and database
//! implementations. [`WireMachineAdmin`] uses the live wire registry as its
//! authority; expiry and deletion have the same visibility in admin and map
//! views. Attached persistent adapters use the live registry for native admin
//! reads/mutations and save the selected cached columns. Headless adapters use
//! database rows; registration and deletion retain their own durable boundaries.
//!
//! ## P1 lifecycle parity
//!
//! The trait now exposes the upstream `juanfont/headscale` admin
//! verbs:
//!
//! | upstream `cmd/headscale/nodes.go`           | Rust trait method      |
//! |---------------------------------------------|------------------------|
//! | `headscale nodes expire`                    | [`MachineAdmin::expire`] (now optional ISO timestamp) |
//! | `headscale nodes logout`                    | [`MachineAdmin::logout`] |
//! | `headscale nodes rename`                    | [`MachineAdmin::rename`] |
//! | `headscale nodes delete`                    | [`MachineAdmin::delete`] |
//! | `headscale nodes tag`                       | [`MachineAdmin::set_tags`] |
//!
//! Existing-node wire mutations share registration's per-machine locks and resolve the
//! selected stable node again after waiting, including across node-key rotation.

use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

mod native_snapshot;
pub(crate) use native_snapshot::{NativeAuthKey, NativeNodeAssociations, NativeNodePersistence};

use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
#[cfg(feature = "postgres-sqlx")]
use sqlx::PgPool;
use sqlx::SqlitePool;

use crate::policy::{
    PolicyCheckNode, PolicyCheckNodeSnapshot, PolicyStore, validate_requested_tags_for_auth_path,
};
use crate::tailscale_wire::{
    AuthRequestKind, IpAllocator, MachineRecord, MachineRegistrationStore, MachineRegistry,
    MachineSnapshot, PersistedMachineRegistration, RegistrationCache,
    routes::{auto_approval_changed, auto_approved_routes_with_snapshot},
    wire::{HostInfo, ZERO_DISCO_KEY, is_auto_derived_given_name},
};

use super::auth::now_unix;
use super::users::{UserAdmin, UserRecord};

const REGISTER_METHOD_AUTH_KEY: i32 = 1;
const REGISTER_METHOD_OIDC: i32 = 3;
const EMPTY_TAGS_ERROR: &str =
    "cannot remove all tags from a node - tagged nodes must have at least one tag";

#[derive(Clone, Debug, Default)]
struct UserIdentity {
    id: Option<u64>,
    login_name: String,
    display_name: String,
    profile_pic_url: String,
    provider: String,
    created_at: Option<DateTime<Utc>>,
    #[allow(clippy::option_option)] // tri-state: unset / explicit nil Go association / loaded user
    association: Option<Option<UserRecord>>,
}

/// Admin-side view of one registered machine.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineAdminRecord {
    /// Upstream numeric node ID. Persistent stores populate this from
    /// `nodes.id`; legacy volatile records may leave it at zero and
    /// gRPC then falls back to the deterministic node-key hash.
    #[serde(default)]
    pub node_id: u64,
    /// `node_key_hex` from the wire registry. Used as the URL slug.
    pub id: String,
    /// Server-managed DNS label (`nodes.given_name`). The raw client name
    /// is available separately through MachineAdmin::raw_hostname.
    pub name: String,
    pub user: String,
    /// Upstream numeric owner ID. Persistent stores populate this from
    /// `nodes.user_id`; volatile records may leave it unset and fall
    /// back to login-name matching in policy-only contexts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<u64>,
    /// Upstream numeric `nodes.auth_key_id`. Internal-only; gRPC uses
    /// it to attach `Node.pre_auth_key` while admin JSON stays stable.
    #[serde(default, skip_serializing)]
    pub auth_key_id: Option<i64>,
    /// Allocated tailnet IPv4 (string form for stable JSON).
    pub ipv4: String,
    /// Optional allocated tailnet IPv6. Persistent DB-backed nodes can
    /// project this from `nodes.ipv6`; the current wire runtime only
    /// allocates IPv4.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    /// Best-effort online flag. v0 returns `true` for any record
    /// present in the wire registry that hasn't been "expired" by
    /// the admin; richer tracking lands with NodeMetrics integration.
    pub online: bool,
    /// Unix-seconds, best-effort. v0 stubs to `created_at` for any
    /// record we have a stamp for (none today); fills 0 otherwise.
    pub last_seen: u64,
    #[serde(skip)]
    pub last_seen_precise: Option<DateTime<Utc>>,
    /// Unix-seconds node creation timestamp.
    #[serde(default)]
    pub created_at: u64,
    #[serde(skip)]
    pub created_at_precise: Option<DateTime<Utc>>,
    /// Unix-seconds node expiry timestamp. `None` means never expires.
    #[serde(default)]
    pub expiry: Option<u64>,
    #[serde(skip)]
    pub expiry_precise: Option<DateTime<Utc>>,
    /// Hex machine key bound to the node's Noise identity.
    pub machine_key_hex: String,
    /// Tailscale discovery key as an upstream `discokey:` string.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub disco_key: String,
    /// Client OS, rendered as "unknown" when the stored value is empty.
    pub os: String,
    /// Client version, rendered as "unknown" when empty.
    pub version: String,
    /// Current tag ownership, including preauth and administrative changes.
    pub tags: Vec<String>,
    /// Routes the node advertises.
    pub routes: Vec<String>,
    /// Routes approved by operator/policy and emitted in `AllowedIPs`.
    #[serde(default)]
    pub approved_routes: Vec<String>,
    /// Upstream `RegisterMethod` enum numeric value.
    #[serde(default)]
    pub register_method: i32,
    /// Whether the node's stored expiry has passed.
    pub expired: bool,
}

/// One admin response retains its node fields and loaded associations. Native
/// adapters construct it from a NodeStore/SQL projection before releasing the
/// operation's guards. Custom adapters can use the ordinary record fallback.
#[derive(Clone)]
pub struct MachineAdminView {
    pub record: MachineAdminRecord,
    pub raw_hostname: String,
    // Only the gRPC node renderer (`full`) reads the retained associations.
    #[cfg(feature = "full")]
    pub(crate) associations: NativeNodeAssociations,
}

impl MachineAdminView {
    pub fn from_record(record: MachineAdminRecord) -> Self {
        Self {
            raw_hostname: record.name.clone(),
            record,
            #[cfg(feature = "full")]
            associations: NativeNodeAssociations::default(),
        }
    }

    pub(crate) fn from_wire(
        key: &str,
        wire: &MachineRecord,
        native: Option<&NativeNodePersistence>,
        online: bool,
    ) -> Self {
        let mut record = machine_admin_record_from_wire(wire);
        record.node_id = wire.stable_node_id_for_key(key);
        record.online = online && !record.expired;
        if let Some(native) = native {
            record.last_seen_precise = native.last_seen(wire);
            record.last_seen = record
                .last_seen_precise
                .map_or(0, |time| time.timestamp().max(0) as u64);
        }
        #[cfg(feature = "full")]
        let associations = native
            .map(|native| NativeNodeAssociations {
                user: native
                    .user_association(wire)
                    .map(Option::<&UserRecord>::cloned),
                auth_key: native
                    .auth_key_association(wire)
                    .map(Option::<&NativeAuthKey>::cloned),
            })
            .unwrap_or_default();
        Self {
            record,
            raw_hostname: wire.raw_hostname.clone(),
            #[cfg(feature = "full")]
            associations,
        }
    }
}

/// Administrative edit whose result can retain the native response view.
/// Expiry(None) disables expiry; callers expiring now pass Some(Utc::now()).
#[derive(Clone)]
pub enum MachineAdminMutation {
    Expiry(Option<DateTime<Utc>>),
    Rename(String),
    Tags(Vec<String>),
    ApprovedRoutes(Vec<String>),
    AvailableRoutes(Vec<String>),
}

/// Errors the admin trait can surface.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MachineAdminError {
    #[error("machine '{0}' not found")]
    NotFound(String),
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("{0}")]
    Policy(String),
    #[error("{0}")]
    Storage(String),
}

impl From<crate::tailscale_wire::RegistryMutationError> for MachineAdminError {
    fn from(error: crate::tailscale_wire::RegistryMutationError) -> Self {
        match error {
            crate::tailscale_wire::RegistryMutationError::Invalid(message) => {
                Self::BadRequest(message.into_owned())
            }
            crate::tailscale_wire::RegistryMutationError::Policy(message) => Self::Policy(message),
        }
    }
}

/// Admin surface for machine management. Async to match
/// [`super::preauth::PreauthAdmin`] and to leave room for a real DB.
///
/// The lifecycle methods (`expire_at` / `logout` / `rename` /
/// `set_tags`) all return `Err(MachineAdminError::NotFound(id))` when
/// the node doesn't exist; the routes lift that into a `404`.
#[async_trait]
pub trait MachineAdmin: Send + Sync {
    async fn list(&self) -> Vec<MachineAdminRecord>;
    /// Mutation paths must distinguish an unavailable store from an empty one.
    /// Legacy custom adapters retain their existing infallible list contract.
    async fn list_checked(&self) -> Result<Vec<MachineAdminRecord>, MachineAdminError> {
        Ok(self.list().await)
    }
    /// Native/wire implementations coordinate the complete snapshot and live
    /// publication before persistence. Custom adapters keep the batch fallback.
    /// The caller publishes the policy change after successful persistence.
    async fn auto_approve_routes(&self, policy: &PolicyStore) -> Result<usize, MachineAdminError> {
        let plan = policy_auto_approval_plan(policy, self.list_checked().await?)?;
        let updates = plan
            .into_iter()
            .map(|(node, routes)| (self.mutation_selector(&node), routes))
            .collect();
        self.set_approved_routes_batch(updates).await
    }
    async fn get(&self, id: &str) -> Option<MachineAdminRecord>;

    /// Checked response projections. Native adapters retain loaded pointers;
    /// the defaults preserve the existing custom-adapter record contract.
    async fn get_view(&self, id: &str) -> Result<Option<MachineAdminView>, MachineAdminError> {
        let Some(record) = self.get(id).await else {
            return Ok(None);
        };
        let mut view = MachineAdminView::from_record(record);
        if let Some(hostname) = self.raw_hostname(id).await {
            view.raw_hostname = hostname;
        }
        Ok(Some(view))
    }

    async fn list_views(&self) -> Result<Vec<MachineAdminView>, MachineAdminError> {
        let records = self.list_checked().await?;
        let mut views = Vec::with_capacity(records.len());
        for record in records {
            let hostname = self.raw_hostname(&record.id).await;
            let mut view = MachineAdminView::from_record(record);
            if let Some(hostname) = hostname {
                view.raw_hostname = hostname;
            }
            views.push(view);
        }
        Ok(views)
    }

    async fn mutate_with_view(
        &self,
        id: &str,
        mutation: MachineAdminMutation,
    ) -> Result<MachineAdminView, MachineAdminError> {
        mutate_with_fallback_view(self, id, mutation).await
    }
    /// Raw client node hostname (`nodes.hostname`), distinct from the admin
    /// DNS label exposed by MachineAdminRecord.name. Legacy stores may use
    /// the same value for both names.
    async fn raw_hostname(&self, id: &str) -> Option<String> {
        self.get(id).await.map(|record| record.name)
    }
    /// Prepare a record for publication into the supplied registry. The caller
    /// retains the machine registration guard through the subsequent upsert.
    /// Native stores preserve nullable database values here; ordinary reads
    /// through wire_record never change that persistence baseline.
    async fn wire_record_for_publication(
        &self,
        id: &str,
        _registry: Option<&MachineRegistry>,
    ) -> Result<Option<MachineRecord>, MachineAdminError> {
        self.wire_record(id).await
    }

    /// Canonical wire projection after a durable registration write. Backends
    /// without a richer node representation can retain the caller's payload.
    async fn wire_record(&self, _id: &str) -> Result<Option<MachineRecord>, MachineAdminError> {
        Ok(None)
    }
    /// Serialize an auth completion through its persistence/publication step.
    /// Callers hold the guard; complete_registration must not reacquire it.
    async fn registration_guard(
        &self,
        _machine_key: &str,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        None
    }
    /// Serialize competing machines claiming the same node key. Acquire after
    /// registration_guard and retain both through persistence/publication.
    async fn node_key_registration_guard(
        &self,
        _node_key: &str,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        None
    }
    /// Return the node that an auth/web/CLI registration would update
    /// instead of creating, if one exists.
    async fn existing_auth_path_record(
        &self,
        _record: &MachineAdminRecord,
    ) -> Option<MachineAdminRecord> {
        None
    }
    /// Fallible selection before allocating a fresh node's addresses. Native
    /// stores propagate lookup/ownership errors instead of treating them as a miss.
    async fn existing_auth_path_record_checked(
        &self,
        record: &MachineAdminRecord,
    ) -> Result<Option<MachineAdminRecord>, MachineAdminError> {
        Ok(self.existing_auth_path_record(record).await)
    }
    /// Stored node ownership/address snapshot used to resolve tag-owner IPs.
    /// Native stores propagate database errors; custom stores retain list's
    /// existing contract unless they override this fallible method.
    async fn policy_nodes_for_registration(
        &self,
    ) -> Result<Vec<PolicyCheckNode>, MachineAdminError> {
        Ok(self
            .list()
            .await
            .iter()
            .map(policy_check_node_from_machine)
            .collect())
    }
    /// Identity/address/route facts captured together for native policy tests.
    /// Custom adapters can override this fallible record-list projection.
    async fn policy_nodes_for_check(
        &self,
    ) -> Result<Vec<PolicyCheckNodeSnapshot>, MachineAdminError> {
        Ok(self
            .list_checked()
            .await?
            .into_iter()
            .map(|record| PolicyCheckNodeSnapshot {
                node: policy_check_node_from_machine(&record),
                advertised_routes: record.routes,
                approved_routes: record.approved_routes,
            })
            .collect())
    }
    /// Insert a synthetic/admin-created machine record. Used by
    /// upstream debug/register gRPC paths and by future DB-backed node
    /// creation. Implementations must reject duplicate node IDs.
    async fn create(
        &self,
        record: MachineAdminRecord,
    ) -> Result<MachineAdminRecord, MachineAdminError>;
    /// Complete a web/CLI/OIDC-style registration record.
    ///
    /// The default is a straight create for simple admin backends.
    /// Stores with headscale-go auth-path semantics override this to
    /// rekey an existing same-machine node and preserve upstream node
    /// identity.
    async fn complete_registration(
        &self,
        record: MachineAdminRecord,
        _policy: &PolicyStore,
        _wire_record: Option<MachineRecord>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        let record = self.create(record).await?;
        Ok(AuthPathRegistrationResult {
            record,
            new_node: true,
            replaced_node_key_hex: None,
        })
    }

    async fn complete_registration_with_hostinfo(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        wire_record: Option<MachineRecord>,
        _hostinfo: Option<Value>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.complete_registration(record, policy, wire_record)
            .await
    }

    /// Keep the user captured by the accepting RPC through native Save.
    async fn complete_registration_with_user_snapshot(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        wire_record: Option<MachineRecord>,
        hostinfo: Option<Value>,
        _user: super::users::UserRegistrationSnapshot,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.complete_registration_with_hostinfo(record, policy, wire_record, hostinfo)
            .await
    }
    /// Select a mutation independently of node-key rotation. Generic adapters
    /// retain key selectors; native adapters opt into their stable numeric ID.
    fn mutation_selector(&self, record: &MachineAdminRecord) -> String {
        record.id.clone()
    }

    fn numeric_mutation_selector(&self, _node_id: u64) -> Option<String> {
        None
    }

    /// Mark a machine expired. `expiry = None` ⇒ expire immediately
    /// (`Utc::now()`); `Some(t)` ⇒ schedule expiry for `t`. Mirrors
    /// upstream `db.SetExpiry`.
    async fn expire_at(
        &self,
        id: &str,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), MachineAdminError>;
    /// Clear node-key expiry so the node never expires.
    async fn disable_expiry(&self, id: &str) -> Result<(), MachineAdminError>;
    /// Back-compat shim: expire immediately. Default impl forwards to
    /// `expire_at(id, None)`. Existing call sites that took the old
    /// single-arg signature keep working.
    async fn expire(&self, id: &str) -> Result<(), MachineAdminError> {
        self.expire_at(id, None).await
    }
    /// Apply the administrative logout operation to the backing node store.
    async fn logout(&self, id: &str) -> Result<(), MachineAdminError>;
    /// Rename a machine. Empty hostname returns
    /// `MachineAdminError::BadRequest`. Mirrors `db.NodeRenameNode`.
    async fn rename(&self, id: &str, hostname: &str) -> Result<(), MachineAdminError>;
    /// Replace the tag list. Empty lists are rejected, matching Go's rule
    /// that tagged nodes retain at least one tag.
    async fn set_tags(&self, id: &str, tags: Vec<String>) -> Result<(), MachineAdminError>;
    /// Replace approved routes. Empty list clears the approval.
    async fn set_approved_routes(
        &self,
        id: &str,
        routes: Vec<String>,
    ) -> Result<(), MachineAdminError>;
    /// Replace approved routes on multiple machines. Implementations that can
    /// update a live NodeStore atomically should override this; the default
    /// preserves existing backend behaviour by applying each node in sequence.
    async fn set_approved_routes_batch(
        &self,
        updates: Vec<(String, Vec<String>)>,
    ) -> Result<usize, MachineAdminError> {
        let mut changed = 0usize;
        for (id, routes) in updates {
            self.set_approved_routes(&id, routes).await?;
            changed += 1;
        }
        Ok(changed)
    }
    /// Replace the node's advertised route list while preserving
    /// operator approvals.
    async fn set_routes(&self, id: &str, routes: Vec<String>) -> Result<(), MachineAdminError>;
    /// Assign missing node IPs where the backing store supports it.
    ///
    /// Legacy wire-only allocators may return IPv4 only, so the
    /// persistent implementation can backfill missing IPv4 without
    /// inventing IPv6 prefix/config semantics.
    async fn backfill_node_ips(
        &self,
        _ip_allocator: Option<&dyn IpAllocator>,
    ) -> Result<Vec<String>, MachineAdminError> {
        Ok(Vec::new())
    }
    /// Wake live map streams after a user has been removed.
    ///
    /// Headscale-go emits `change.UserRemoved()` as a full update when
    /// deleting a user does not otherwise produce a policy-manager
    /// change. Implementations with access to the live wire registry
    /// should forward that full-map wake and return true. Backends with
    /// no live registry keep the default false so callers can fall back
    /// to the legacy policy refresh.
    fn notify_user_removed_full_update(&self) -> bool {
        false
    }
    /// Delete a machine from its backing store and live registry.
    async fn delete(&self, id: &str) -> Result<(), MachineAdminError>;
}

async fn mutate_with_fallback_view<A: MachineAdmin + ?Sized>(
    administrator: &A,
    id: &str,
    mutation: MachineAdminMutation,
) -> Result<MachineAdminView, MachineAdminError> {
    match mutation {
        MachineAdminMutation::Expiry(Some(expiry)) => {
            administrator.expire_at(id, Some(expiry)).await?;
        }
        MachineAdminMutation::Expiry(None) => administrator.disable_expiry(id).await?,
        MachineAdminMutation::Rename(name) => administrator.rename(id, &name).await?,
        MachineAdminMutation::Tags(tags) => administrator.set_tags(id, tags).await?,
        MachineAdminMutation::ApprovedRoutes(routes) => {
            administrator.set_approved_routes(id, routes).await?;
        }
        MachineAdminMutation::AvailableRoutes(routes) => {
            administrator.set_routes(id, routes).await?;
        }
    }
    administrator
        .get_view(id)
        .await?
        .ok_or_else(|| MachineAdminError::NotFound(id.into()))
}

fn admin_view_from_native_row(
    row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    wire: &MachineRecord,
    associations: NativeNodeAssociations,
) -> Result<MachineAdminView, MachineAdminError> {
    let mut native = NativeNodePersistence::capture(row, wire)?;
    native.set_associations(associations);
    let mut view = MachineAdminView::from_wire(&wire.node_key_hex, wire, Some(&native), false);
    view.record.node_id = native_row_id(row)?;
    view.record.ipv4 = row.ipv4.clone().unwrap_or_default();
    view.record.ipv6 = row.ipv6.clone().filter(|value| !value.is_empty());
    // A NULL non-pointer Go CreatedAt scans as time.Time's zero value.
    if row.created_at_text.is_empty() {
        view.record.created_at = 0;
        view.record.created_at_precise = DateTime::from_timestamp(-62_135_596_800, 0);
    }
    Ok(view)
}

/// Re-run policy auto-approvers for every visible machine.
///
/// Shared live-node projection for gRPC and legacy admin policy checks.
pub(crate) fn policy_check_node_from_machine(
    machine: &MachineAdminRecord,
) -> crate::policy::PolicyCheckNode {
    let mut addrs = Vec::with_capacity(1 + usize::from(machine.ipv6.is_some()));
    if !machine.ipv4.is_empty() {
        addrs.push(machine.ipv4.clone());
    }
    if let Some(ipv6) = machine.ipv6.as_ref().filter(|ipv6| !ipv6.is_empty()) {
        addrs.push(ipv6.clone());
    }
    crate::policy::PolicyCheckNode {
        id: if machine.node_id == 0 {
            crate::tailscale_wire::wire::stable_id_from_key(&machine.id)
        } else {
            machine.node_id
        },
        user_id: machine.user_id,
        name: machine.name.clone(),
        user: (!machine.user.is_empty()).then(|| machine.user.clone()),
        addrs,
        tags: machine.tags.clone(),
    }
}

/// Existing approved routes are preserved; newly advertised routes are
/// approved only when the loaded policy allows the node to advertise
/// them. This mirrors headscale-go policy reload behaviour.
pub(crate) async fn apply_policy_auto_approvals(
    policy: &PolicyStore,
    machines: &dyn MachineAdmin,
) -> Result<usize, MachineAdminError> {
    machines.auto_approve_routes(policy).await
}

/// Go `State.AutoApproveRoutes` for one node: the gRPC `RegisterNode` handler
/// (grpcv1.go), the pre-auth-key register path (auth.go) and the OIDC callback
/// run it right after the node has been persisted and added to the policy
/// manager. Returns the new approved set only when it differs from the
/// node's current one.
pub(crate) fn policy_route_approval_for_node(
    policy: &PolicyStore,
    node: &MachineAdminRecord,
) -> Result<Option<Vec<String>>, MachineAdminError> {
    Ok(policy_auto_approval_plan(policy, vec![node.clone()])?
        .into_iter()
        .next()
        .map(|(_, approved)| approved))
}

/// Apply Go `State.AutoApproveRoutes` to a node that registration has just
/// persisted: compute the approved set against the loaded policy and, only
/// when it changed, store it through the machine admin (NodeStore, database
/// row and the `change.PolicyChange()` that follows the registration's own
/// change; `State.SetApprovedRoutes`). The caller must have released the
/// registration guards, as Go's `HandleNodeFromAuthPath` does on return.
///
/// An embedder may attach the live registry to the registration handler only;
/// a machine admin that already owns it has projected the approval itself.
pub(crate) async fn auto_approve_registered_node(
    machines: &dyn MachineAdmin,
    policy: &PolicyStore,
    wire_registry: Option<&MachineRegistry>,
    node: &MachineAdminRecord,
) -> Result<(), MachineAdminError> {
    let Some(approved) = policy_route_approval_for_node(policy, node)? else {
        return Ok(());
    };
    machines
        .set_approved_routes(&node.id, approved.clone())
        .await?;
    if let Some(registry) = wire_registry
        && registry
            .get(&node.id)
            .is_some_and(|live| live.approved_routes != approved)
    {
        registry
            .try_set_approved_routes(&node.id, approved)
            .map_err(MachineAdminError::Policy)?;
    }
    Ok(())
}

fn policy_auto_approval_plan(
    policy: &PolicyStore,
    nodes: Vec<MachineAdminRecord>,
) -> Result<Vec<(MachineAdminRecord, Vec<String>)>, MachineAdminError> {
    let approvers = policy.route_approval_snapshot();
    let mut updates = Vec::new();
    for node in nodes {
        let user = (!node.user.is_empty()).then_some(node.user.as_str());
        let approved = auto_approved_routes_with_snapshot(
            &approvers,
            &admin_node_addresses(&node),
            user,
            node.user_id,
            &node.tags,
            &node.approved_routes,
            &node.routes,
        )
        .map_err(|e| {
            MachineAdminError::BadRequest(format!(
                "auto approving routes for node {}: {e}",
                node.id
            ))
        })?;
        if auto_approval_changed(&node.approved_routes, &approved)
            .map_err(MachineAdminError::BadRequest)?
        {
            updates.push((node, approved));
        }
    }
    Ok(updates)
}

fn native_row_id(
    row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
) -> Result<u64, MachineAdminError> {
    u64::try_from(row.id)
        .ok()
        .filter(|id| *id > 0)
        .ok_or_else(|| MachineAdminError::BadRequest("invalid persisted node identity".into()))
}

fn stage_native_row(
    registry: &MachineRegistry,
    row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    record: &MachineRecord,
    associations: NativeNodeAssociations,
) -> Result<(), MachineAdminError> {
    let id = native_row_id(row)?;
    let mut native = NativeNodePersistence::capture(row, record)?;
    native.set_associations(associations);
    if let Some(snapshot) = registry.take_native_registration_hostinfo(id, record) {
        native.replace_hostinfo_snapshot(snapshot);
    }
    registry.stage_native_row(record.clone(), native);
    Ok(())
}

// Reuse the native planning representation without reading node authority
// from SQL. These are projections of the current NodeStore, not fetched rows;
// UpdatedAt/DeletedAt are not registration inputs or selected save columns.
fn registration_rows_from_cache(
    registry: &MachineRegistry,
    machine_key: &str,
) -> Result<Vec<headscale_db::headscale_nodes::HeadscaleNodeRow>, MachineAdminError> {
    let records = registry.snapshot_with_metadata();
    let mut rows = Vec::new();
    for (key, record) in records
        .iter()
        .filter(|(_, record)| record.machine_key_hex == machine_key)
    {
        let id = record.stable_node_id_for_key(key);
        let native = records.native_persistence(id);
        let snapshot = NativeNodePersistence::snapshot(id, record, native.as_ref())?;
        let hostinfo = records
            .map_hostinfo_value(record)
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        let json = |value: Value| {
            serde_json::to_string(&value)
                .map_err(|error| MachineAdminError::BadRequest(error.to_string()))
        };
        rows.push(headscale_db::headscale_nodes::HeadscaleNodeRow {
            id: snapshot.id,
            machine_key: snapshot.machine_key,
            node_key: snapshot.node_key,
            disco_key: snapshot.disco_key,
            endpoints: json(
                serde_json::to_value(snapshot.endpoints)
                    .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?,
            )?,
            host_info: json(hostinfo)?,
            ipv4: snapshot.ipv4,
            ipv6: snapshot.ipv6,
            hostname: snapshot.hostname,
            given_name: snapshot.given_name,
            user_id: snapshot.user_id,
            register_method: snapshot.register_method,
            tags: json(
                serde_json::to_value(snapshot.tags)
                    .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?,
            )?,
            auth_key_id: record.auth_key_id,
            expiry: record.expiry.map(|time| time.timestamp()),
            expiry_text: record
                .expiry
                .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
            last_seen: snapshot.last_seen.map(|time| time.timestamp()),
            last_seen_text: snapshot
                .last_seen
                .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)),
            approved_routes: json(
                serde_json::to_value(snapshot.approved_routes)
                    .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?,
            )?,
            created_at: record.created_at.timestamp(),
            created_at_text: record
                .created_at
                .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            updated_at: 0,
            deleted_at: None,
        });
    }
    rows.sort_by_key(|row| row.id);
    Ok(rows)
}

#[derive(Clone)]
enum NativeNodeStore {
    Volatile,
    Sqlite(SqlitePool),
    #[cfg(feature = "postgres-sqlx")]
    Postgres(PgPool),
}

pub(crate) fn native_save_error(error: MachineAdminError) -> MachineAdminError {
    let message = match error {
        MachineAdminError::BadRequest(message)
        | MachineAdminError::Storage(message)
        | MachineAdminError::Policy(message) => message,
        error @ MachineAdminError::NotFound(_) => error.to_string(),
    };
    MachineAdminError::Storage(format!("saving node: {message}"))
}

impl NativeNodeStore {
    async fn save_snapshot(
        &self,
        id: u64,
        record: &MachineRecord,
        native: Option<&NativeNodePersistence>,
    ) -> Result<Option<NativeNodePersistence>, MachineAdminError> {
        if matches!(self, Self::Volatile) {
            return Ok(None);
        }
        let snapshot =
            NativeNodePersistence::snapshot(id, record, native).map_err(native_save_error)?;
        let saved_native = NativeNodePersistence::from_snapshot(record, &snapshot, native);
        self.save_selected_snapshot(snapshot).await?;
        Ok(Some(saved_native))
    }

    async fn save_selected_snapshot(
        &self,
        snapshot: headscale_db::headscale_nodes::CachedNodeSnapshot,
    ) -> Result<(), MachineAdminError> {
        let result = match self {
            Self::Volatile => return Ok(()),
            Self::Sqlite(pool) => {
                headscale_db::headscale_nodes::save_cached_node_snapshot(pool, snapshot).await
            }
            #[cfg(feature = "postgres-sqlx")]
            Self::Postgres(pool) => {
                headscale_db::headscale_nodes::save_postgres_cached_node_snapshot(pool, snapshot)
                    .await
            }
        };
        result.map_err(|error| {
            MachineAdminError::Storage(format!("saving node: {}", error.headscale_go_message()))
        })
    }

    async fn save_expiry(
        &self,
        id: u64,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), MachineAdminError> {
        if matches!(self, Self::Volatile) {
            return Ok(());
        }
        let id = i64::try_from(id)
            .map_err(|_| MachineAdminError::BadRequest("invalid cached node identity".into()))?;
        let result = match self {
            Self::Volatile => return Ok(()),
            Self::Sqlite(pool) => {
                headscale_db::headscale_nodes::save_cached_node_expiry(pool, id, expiry).await
            }
            #[cfg(feature = "postgres-sqlx")]
            Self::Postgres(pool) => {
                headscale_db::headscale_nodes::save_postgres_cached_node_expiry(pool, id, expiry)
                    .await
            }
        };
        result.map_err(|error| {
            MachineAdminError::Storage(format!(
                "setting node expiry in database: {}",
                error.headscale_go_message()
            ))
        })
    }

    async fn destroy(&self, id: u64) -> Result<(), MachineAdminError> {
        if matches!(self, Self::Volatile) {
            return Ok(());
        }
        let id = i64::try_from(id)
            .map_err(|_| MachineAdminError::BadRequest("invalid cached node identity".into()))?;
        let result = match self {
            Self::Volatile => return Ok(()),
            Self::Sqlite(pool) => {
                headscale_db::headscale_nodes::destroy_cached_node(pool, id).await
            }
            #[cfg(feature = "postgres-sqlx")]
            Self::Postgres(pool) => {
                headscale_db::headscale_nodes::destroy_postgres_cached_node(pool, id).await
            }
        };
        result.map_err(|error| MachineAdminError::Storage(error.headscale_go_message()))
    }

    // Headless adapters have no NodeStore to supply Go's full cached snapshot.
    // Keep their unrelated durable fields rather than inventing a wire view.
    async fn save(&self, id: u64, routes: &[String]) -> Result<(), MachineAdminError> {
        if matches!(self, Self::Volatile) {
            return Ok(());
        }
        let id = i64::try_from(id).map_err(|_| {
            MachineAdminError::BadRequest("invalid node ID in policy route batch".into())
        })?;
        let result = match self {
            Self::Volatile => return Ok(()),
            Self::Sqlite(pool) => {
                headscale_db::headscale_nodes::save_policy_approved_routes(pool, id, routes).await
            }
            #[cfg(feature = "postgres-sqlx")]
            Self::Postgres(pool) => {
                headscale_db::headscale_nodes::save_postgres_policy_approved_routes(
                    pool, id, routes,
                )
                .await
            }
        };
        result.map_err(|error| db_error_to_machine(error, &id.to_string()))
    }
}

type NativeNodeMutation = MachineAdminMutation;

async fn mutate_live_native_node(
    registry: Arc<MachineRegistry>,
    store: NativeNodeStore,
    id: &str,
    mutation: NativeNodeMutation,
) -> Result<(), MachineAdminError> {
    mutate_live_native_node_with_view(registry, store, id, mutation)
        .await
        .map(|_| ())
}

async fn mutate_live_native_node_with_view(
    registry: Arc<MachineRegistry>,
    store: NativeNodeStore,
    id: &str,
    mutation: NativeNodeMutation,
) -> Result<MachineAdminView, MachineAdminError> {
    let id = id.to_owned();
    crate::tailscale_wire::complete_state_mutation(async move {
        complete_live_native_node_mutation(registry, store, &id, mutation).await
    })
    .await
    .map_err(|error| MachineAdminError::BadRequest(format!("finishing node mutation: {error}")))?
}

async fn complete_live_native_node_mutation(
    registry: Arc<MachineRegistry>,
    store: NativeNodeStore,
    id: &str,
    mut mutation: NativeNodeMutation,
) -> Result<MachineAdminView, MachineAdminError> {
    match &mut mutation {
        NativeNodeMutation::Rename(name) => {
            registry
                .validate_given_name(name)
                .map_err(MachineAdminError::BadRequest)?;
        }
        NativeNodeMutation::Tags(tags) => {
            if tags.is_empty() {
                return Err(MachineAdminError::BadRequest(EMPTY_TAGS_ERROR.into()));
            }
            tags.sort();
            tags.dedup();
        }
        NativeNodeMutation::ApprovedRoutes(routes) => {
            *routes = crate::tailscale_wire::routes::normalize_routes(&*routes)
                .map_err(MachineAdminError::BadRequest)?;
        }
        NativeNodeMutation::AvailableRoutes(routes) => {
            *routes = crate::tailscale_wire::routes::normalize_advertised_routes(&*routes)
                .map_err(MachineAdminError::BadRequest)?;
        }
        NativeNodeMutation::Expiry(_) => {}
    }
    let selector = key_without_prefix("nodekey:", id);
    let adapter = WireMachineAdmin::new(registry.clone());
    let (guards, key) = adapter.lock_existing_node(&selector).await?;
    let selected = registry
        .get(&key)
        .ok_or_else(|| MachineAdminError::NotFound(id.into()))?;
    let node_id = selected.stable_node_id_for_key(&key);
    crate::tailscale_wire::complete_state_mutation(async move {
        let _guards = guards;
        let name = match &mutation {
            NativeNodeMutation::Rename(name) => Some(name.clone()),
            _ => None,
        };
        let change = mutation.clone();
        let mut metadata = match &mutation {
            NativeNodeMutation::Expiry(_) => None,
            NativeNodeMutation::Tags(_) => Some(NativeNodeMetadataEdit {
                nil_user: true,
                nil_routes: false,
                require_native: false,
            }),
            NativeNodeMutation::ApprovedRoutes(routes) => Some(NativeNodeMetadataEdit {
                nil_user: false,
                nil_routes: routes.is_empty(),
                require_native: false,
            }),
            _ => Some(NativeNodeMetadataEdit::default()),
        };
        if let Some(metadata) = &mut metadata {
            metadata.require_native = matches!(&store, NativeNodeStore::Volatile);
        }
        let online_changed = Arc::new(AtomicBool::new(false));
        let expiry_online_changed = online_changed.clone();
        let online_registry = registry.clone();
        let applied = registry
            .mutate_native_node_with_view(node_id, name, metadata, move |record| {
                let check_routes = matches!(
                    &change,
                    NativeNodeMutation::ApprovedRoutes(_) | NativeNodeMutation::AvailableRoutes(_)
                );
                match change {
                    NativeNodeMutation::Expiry(expiry) => {
                        record.expiry = expiry;
                        expiry_online_changed.store(
                            online_registry.update_online_for_expiry(node_id, record),
                            Ordering::SeqCst,
                        );
                    }
                    NativeNodeMutation::Rename(name) => record.hostname = name,
                    NativeNodeMutation::Tags(tags) => {
                        record.forced_tags = tags;
                        record.clear_user_identity();
                    }
                    NativeNodeMutation::ApprovedRoutes(routes) => record.approved_routes = routes,
                    NativeNodeMutation::AvailableRoutes(routes) => record.available_routes = routes,
                }
                check_routes
                    && crate::tailscale_wire::routes::active_approved_routes(
                        &record.available_routes,
                        &record.approved_routes,
                    )
                    .is_empty()
            })
            .map_err(|message| match &mutation {
                NativeNodeMutation::Rename(name)
                    if message == "given name already in use by another node" =>
                {
                    MachineAdminError::BadRequest(format!("node name is not unique: {name}"))
                }
                _ => MachineAdminError::BadRequest(message),
            })?;
        let mut update_view = applied.ok_or_else(|| {
            MachineAdminError::Storage(format!("node no longer exists in NodeStore: {node_id}"))
        })?;
        update_view.record.online = registry
            .online_states()
            .get(&node_id)
            .copied()
            .unwrap_or(false)
            && !update_view.record.expired;

        // Hold the same save lock as policy auto-approval while re-reading and
        // writing the current cache. A database error keeps the quiet live edit.
        let _persist = registry.lock_native_persistence().await;
        let current = registry.snapshot_with_metadata();
        let record = {
            let mut matches = current
                .iter()
                .filter(|(key, record)| record.stable_node_id_for_key(key) == node_id);
            let (_, record) = matches.next().ok_or_else(|| {
                MachineAdminError::Storage(format!("node no longer exists in NodeStore: {node_id}"))
            })?;
            if matches.next().is_some() {
                return Err(MachineAdminError::BadRequest(
                    "ambiguous node identity".into(),
                ));
            }
            record.clone()
        };
        let response_view = if matches!(&mutation, NativeNodeMutation::Expiry(_)) {
            update_view
        } else {
            view_from_snapshot(
                &current,
                &record.node_key_hex,
                &record,
                registry
                    .online_states()
                    .get(&node_id)
                    .copied()
                    .unwrap_or(false),
            )
        };
        if !matches!(&store, NativeNodeStore::Volatile) {
            if let NativeNodeMutation::Expiry(_) = &mutation {
                store
                    .save_expiry(node_id, response_view.record.expiry_precise)
                    .await?;
            } else {
                let native = current.native_persistence(node_id);
                let snapshot = NativeNodePersistence::snapshot(node_id, &record, native.as_ref())
                    .map_err(native_save_error)?;
                store.save_selected_snapshot(snapshot).await?;
            }
        }
        let policy_changed = registry
            .try_refresh_policy_node_inputs()
            .map_err(|error| {
                MachineAdminError::Policy(format!(
                    "{}: {error}",
                    if matches!(&mutation, NativeNodeMutation::Expiry(_)) {
                        "updating policy manager after setting expiry"
                    } else {
                        "updating policy manager after node save"
                    }
                ))
            })?
            .unwrap_or(matches!(
                mutation,
                NativeNodeMutation::Tags(_)
                    | NativeNodeMutation::ApprovedRoutes(_)
                    | NativeNodeMutation::AvailableRoutes(_)
            ));
        if matches!(mutation, NativeNodeMutation::Expiry(_)) {
            registry.wake_node_expiry_change(
                node_id,
                policy_changed,
                online_changed.load(Ordering::SeqCst),
            );
            return Ok(response_view);
        }
        if policy_changed || matches!(mutation, NativeNodeMutation::ApprovedRoutes(_)) {
            // SetNodeTags adds its origin to the policy change. Ordinary
            // rename/route policy changes have no synthetic origin node.
            registry.wake_policy_change(
                matches!(mutation, NativeNodeMutation::Tags(_)).then_some(node_id),
            );
        } else {
            registry.wake_node_change(crate::tailscale_wire::MapChangeReason::NodeAdded, node_id);
        }
        Ok(response_view)
    })
    .await
    .map_err(|error| MachineAdminError::BadRequest(format!("finishing node mutation: {error}")))?
}

fn requested_live_node_id(
    registry: &MachineRegistry,
    requested: &MachineRecord,
) -> Result<u64, String> {
    requested
        .node_id
        .or_else(|| {
            registry
                .get(&requested.node_key_hex)
                .map(|record| record.stable_node_id_for_key(&requested.node_key_hex))
        })
        .ok_or_else(|| "node no longer exists in NodeStore".to_string())
}

// The caller already applied State.SetNodeExpiry's quiet live edit and owns
// its original online transition. Persist that current cached expiry without
// repeating the live mutation or acquiring the same machine guard again.
async fn persist_live_logout_expiry(
    registry: &MachineRegistry,
    store: NativeNodeStore,
    requested: &MachineRecord,
    _at: DateTime<Utc>,
) -> Result<(), String> {
    let id = requested_live_node_id(registry, requested)?;
    let _persist = registry.lock_native_persistence().await;
    let expiry = {
        let current = registry.snapshot();
        let mut records = current
            .iter()
            .filter(|(key, record)| record.stable_node_id_for_key(key) == id);
        let (_, record) = records
            .next()
            .ok_or_else(|| format!("node no longer exists in NodeStore: {id}"))?;
        if records.next().is_some() {
            return Err("ambiguous node identity".into());
        }
        record.expiry
    };
    store
        .save_expiry(id, expiry)
        .await
        .map_err(|error| error.to_string())
}

// The map caller already holds the machine guard and has updated NodeStore.
// Re-read only by stable ID under the same save mutex as native admin writes;
// SQL rows are not the authority for ownership, names, tags or client fields.
async fn persist_live_runtime_node(
    registry: &MachineRegistry,
    store: NativeNodeStore,
    requested: &MachineRecord,
) -> Result<PersistedMachineRegistration, String> {
    let id = requested_live_node_id(registry, requested)?;
    persist_live_runtime_node_by_id(registry, store, id).await
}

// Disconnect owns a stable node ID, including across a key rotation. The
// supplied old timestamp is not a new write: LastSeen already changed in the
// NodeStore writer, and persistNode re-reads its latest full selected snapshot.
async fn persist_live_runtime_node_by_id(
    registry: &MachineRegistry,
    store: NativeNodeStore,
    id: u64,
) -> Result<PersistedMachineRegistration, String> {
    let _persist = registry.lock_native_persistence().await;
    let current = registry.snapshot_with_metadata();
    let record = {
        let mut records = current
            .iter()
            .filter(|(key, record)| record.stable_node_id_for_key(key) == id);
        let (_, record) = records
            .next()
            .ok_or_else(|| format!("node no longer exists in NodeStore: {id}"))?;
        if records.next().is_some() {
            return Err("ambiguous node identity".into());
        }
        record.clone()
    };
    let native = current.native_persistence(id);
    let mut snapshot = NativeNodePersistence::snapshot(id, &record, native.as_ref())
        .map_err(|error| error.to_string())?;
    if native.is_none() {
        // An embedding may attach a native store after publishing a wire-only
        // node. Its map snapshot still owns shapes hidden by the projection.
        let value = current
            .map_hostinfo_value(&record)
            .map_err(|error| error.to_string())?;
        snapshot.host_info = (!value.is_null()).then_some(value);
    }
    // These shapes now describe the live cache even if the following SQL save
    // fails. Keep a later same-value edit from reviving an older nil shape.
    registry.remember_native_persistence(
        id,
        &current,
        NativeNodePersistence::from_snapshot(&record, &snapshot, native.as_ref()),
    );
    store
        .save_selected_snapshot(snapshot)
        .await
        .map_err(|error| error.to_string())?;
    Ok(PersistedMachineRegistration {
        record,
        replaced_node_key_hex: None,
    })
}

async fn delete_live_native_node(
    registry: Arc<MachineRegistry>,
    store: NativeNodeStore,
    id: &str,
) -> Result<(), MachineAdminError> {
    let id = id.to_owned();
    crate::tailscale_wire::complete_state_mutation(async move {
        complete_live_native_node_deletion(registry, store, &id).await
    })
    .await
    .map_err(|error| MachineAdminError::BadRequest(format!("finishing node deletion: {error}")))?
}

async fn complete_live_native_node_deletion(
    registry: Arc<MachineRegistry>,
    store: NativeNodeStore,
    id: &str,
) -> Result<(), MachineAdminError> {
    let selector = key_without_prefix("nodekey:", id);
    let adapter = WireMachineAdmin::new(registry.clone());
    let (guards, key) = adapter.lock_existing_node(&selector).await?;
    let selected = registry
        .get(&key)
        .ok_or_else(|| MachineAdminError::NotFound(id.into()))?;
    let node_id = selected.stable_node_id_for_key(&key);
    crate::tailscale_wire::complete_state_mutation(async move {
        let _guards = guards;
        complete_guarded_native_node_deletion(&registry, store, node_id, &key).await
    })
    .await
    .map_err(|error| MachineAdminError::BadRequest(format!("finishing node deletion: {error}")))?
}

// The caller already owns the machine guard (admin, wire logout or GC).
async fn complete_guarded_native_node_deletion(
    registry: &MachineRegistry,
    store: NativeNodeStore,
    node_id: u64,
    key: &str,
) -> Result<(), MachineAdminError> {
    let persist = registry.lock_native_persistence().await;
    store.destroy(node_id).await?;
    let removed = registry.remove_node_quiet(key);
    drop(persist);
    if let Some(removed) = removed {
        let node_id = removed.id;
        registry.release_removed_node_addresses(removed);
        registry
            .finish_node_removal(node_id)
            .map_err(MachineAdminError::Policy)?;
    }
    Ok(())
}

struct LockedPolicyNodes {
    guards: Vec<tokio::sync::OwnedMutexGuard<()>>,
    records: Vec<MachineAdminRecord>,
}

fn view_from_snapshot(
    snapshot: &MachineSnapshot,
    key: &str,
    wire: &MachineRecord,
    online: bool,
) -> MachineAdminView {
    let native = snapshot.native_persistence(wire.stable_node_id_for_key(key));
    MachineAdminView::from_wire(key, wire, native.as_ref(), online)
}

fn checked_live_views(
    registry: &MachineRegistry,
) -> Result<Vec<MachineAdminView>, MachineAdminError> {
    let online = registry.online_states();
    let snapshot = registry.snapshot_with_metadata();
    let mut seen = BTreeSet::new();
    let mut views = Vec::with_capacity(snapshot.len());
    for (key, record) in &snapshot {
        let id = record.stable_node_id_for_key(key);
        if !seen.insert(id) {
            return Err(MachineAdminError::BadRequest(
                "duplicate live node ID in admin snapshot".into(),
            ));
        }
        views.push(view_from_snapshot(
            &snapshot,
            key,
            record,
            online.get(&id).copied().unwrap_or(false),
        ));
    }
    views.sort_by_key(|view| view.record.node_id);
    Ok(views)
}

fn checked_live_view(
    registry: &MachineRegistry,
    id: &str,
) -> Result<Option<MachineAdminView>, MachineAdminError> {
    let id = key_without_prefix("nodekey:", id);
    let online = registry.online_states();
    let snapshot = registry.snapshot_with_metadata();
    let selected = if let Ok(node_id) = id.parse::<u64>()
        && node_id > 0
        && node_id.to_string() == id
    {
        let mut matches = snapshot
            .iter()
            .filter(|(key, record)| record.stable_node_id_for_key(key) == node_id);
        let selected = matches.next();
        if matches.next().is_some() {
            return Err(MachineAdminError::BadRequest(
                "ambiguous live node identity".into(),
            ));
        }
        selected
    } else {
        snapshot.get_key_value(&id)
    };
    Ok(selected.map(|(key, record)| {
        let online = online
            .get(&record.stable_node_id_for_key(key))
            .copied()
            .unwrap_or(false);
        view_from_snapshot(&snapshot, key, record, online)
    }))
}

fn checked_live_records(
    registry: &MachineRegistry,
) -> Result<Vec<MachineAdminRecord>, MachineAdminError> {
    checked_live_views(registry).map(|views| views.into_iter().map(|view| view.record).collect())
}

fn checked_live_policy_nodes(
    registry: &MachineRegistry,
) -> Result<Vec<PolicyCheckNode>, MachineAdminError> {
    Ok(checked_live_policy_check_snapshot(registry)?
        .into_iter()
        .map(|snapshot| snapshot.node)
        .collect())
}

fn checked_live_policy_check_snapshot(
    registry: &MachineRegistry,
) -> Result<Vec<PolicyCheckNodeSnapshot>, MachineAdminError> {
    PolicyCheckNodeSnapshot::from_registry(registry).map_err(MachineAdminError::BadRequest)
}

fn policy_node_from_native_row(
    row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    record: &MachineRecord,
    association: NativeNodeAssociations,
) -> Result<PolicyCheckNode, MachineAdminError> {
    let mut node = policy_check_node_from_machine(&machine_admin_record_from_wire(record));
    node.addrs = NativeNodePersistence::capture(row, record)?
        .policy_owner_and_addresses(record)
        .1;
    if let Some(user) = association.user {
        node.user_id = user.as_ref().map(|user| user.id);
        if user.is_none() {
            node.user = None;
        }
    }
    Ok(node)
}

async fn locked_policy_nodes(
    registry: &Arc<MachineRegistry>,
) -> Result<LockedPolicyNodes, MachineAdminError> {
    let snapshot = registry.snapshot();
    let mut selected_ids = BTreeSet::new();
    let mut machines = BTreeSet::new();
    for (key, record) in snapshot.iter() {
        if !selected_ids.insert(record.stable_node_id_for_key(key)) {
            return Err(MachineAdminError::BadRequest(
                "duplicate live node ID in policy snapshot".into(),
            ));
        }
        machines.insert(record.machine_key_hex.clone());
    }
    drop(snapshot);
    let mut guards = Vec::with_capacity(machines.len());
    for machine in &machines {
        guards.push(registry.lock_registration(machine).await);
    }
    let current = registry.snapshot_with_metadata();
    let mut seen = BTreeSet::new();
    let mut records = Vec::new();
    for (key, record) in &current {
        let id = record.stable_node_id_for_key(key);
        if selected_ids.contains(&id) && machines.contains(&record.machine_key_hex) {
            if !seen.insert(id) {
                return Err(MachineAdminError::BadRequest(
                    "duplicate live node ID in policy snapshot".into(),
                ));
            }
            let mut node = machine_admin_record_from_wire(record);
            node.node_id = id;
            let (user_id, user) = current.policy_identity(record);
            node.user_id = user_id;
            node.user = user.unwrap_or_default();
            let addresses = current.policy_addresses(record);
            node.ipv4 = addresses
                .iter()
                .find(|addr| !addr.contains(':'))
                .cloned()
                .unwrap_or_default();
            node.ipv6 = addresses.iter().find(|addr| addr.contains(':')).cloned();
            records.push(node);
        }
    }
    records.sort_by_key(|record| record.node_id);
    Ok(LockedPolicyNodes { guards, records })
}

async fn auto_approve_live_registry(
    policy: &PolicyStore,
    registry: Arc<MachineRegistry>,
    store: NativeNodeStore,
) -> Result<usize, MachineAdminError> {
    let locked = locked_policy_nodes(&registry).await?;
    let plan = policy_auto_approval_plan(policy, locked.records)?;
    if plan.is_empty() {
        return Ok(0);
    }
    let updates = plan
        .into_iter()
        .map(|(record, routes)| (record.node_id, routes))
        .collect();
    crate::tailscale_wire::complete_state_mutation(async move {
        let _guards = locked.guards;
        // Go updates all live routes first, then saves each still-present ID.
        // A database error can leave the full live batch with partial durable
        // progress; there is deliberately no rollback of that live snapshot.
        let ids = registry
            .apply_policy_route_approvals(updates)
            .into_iter()
            .collect::<BTreeSet<_>>();
        let snapshot = registry.snapshot();
        let keys = snapshot
            .iter()
            .filter_map(|(key, record)| {
                let id = record.stable_node_id_for_key(key);
                ids.contains(&id).then(|| (id, key.clone()))
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        drop(snapshot);
        let mut saved = 0;
        for id in ids {
            // Go persistNode serializes a fresh NodeStore read and its SQL
            // update. Never save the earlier plan or recreate an absent ID.
            let _persist = registry.lock_native_persistence().await;
            let current = registry.snapshot_with_metadata();
            let record = keys
                .get(&id)
                .and_then(|key| {
                    current
                        .get(key)
                        .filter(|record| record.stable_node_id_for_key(key) == id)
                })
                .or_else(|| {
                    current.iter().find_map(|(key, record)| {
                        (record.stable_node_id_for_key(key) == id).then_some(record)
                    })
                })
                .cloned();
            let native = current.native_persistence(id);
            let Some(record) = record else {
                continue;
            };
            if let Some(saved_native) = store.save_snapshot(id, &record, native.as_ref()).await? {
                registry.remember_native_persistence(id, &current, saved_native);
            }
            saved += 1;
        }
        registry
            .try_refresh_policy_node_inputs()
            .map_err(MachineAdminError::Policy)?;
        Ok(saved)
    })
    .await
    .map_err(|error| {
        MachineAdminError::BadRequest(format!("finishing policy route approvals: {error}"))
    })?
}

async fn auto_approve_without_registry(
    policy: &PolicyStore,
    nodes: Vec<MachineAdminRecord>,
    store: NativeNodeStore,
) -> Result<usize, MachineAdminError> {
    let plan = policy_auto_approval_plan(policy, nodes)?;
    crate::tailscale_wire::complete_state_mutation(async move {
        for (record, routes) in &plan {
            store.save(record.node_id, routes).await?;
        }
        Ok(plan.len())
    })
    .await
    .map_err(|error| {
        MachineAdminError::BadRequest(format!("finishing policy route approvals: {error}"))
    })?
}

/// Default impl: adapts [`MachineRegistry`] for the admin panel.
///
/// The wire registry owns expiry/deletion and remains volatile by design.
/// Existing-node admin mutations share its registration locks; no sidecar flags can hide a
/// later registration or turn a scheduled future expiry into immediate expiry.
#[derive(Clone)]
pub struct WireMachineAdmin {
    registry: Arc<MachineRegistry>,
}

impl WireMachineAdmin {
    pub fn new(registry: Arc<MachineRegistry>) -> Self {
        Self { registry }
    }

    fn selected_record(&self, id: &str) -> Option<(String, MachineRecord)> {
        if let Ok(node_id) = id.parse::<u64>()
            && node_id > 0
            && node_id.to_string() == id
        {
            let snapshot = self.registry.snapshot();
            let mut matches = snapshot
                .iter()
                .filter(|(key, record)| record.stable_node_id_for_key(key) == node_id);
            let (key, record) = matches.next()?;
            if matches.next().is_some() {
                return None;
            }
            return Some((key.clone(), record.clone()));
        }
        self.registry.get(id).map(|record| (id.to_owned(), record))
    }

    async fn lock_existing_nodes(
        &self,
        ids: &[String],
    ) -> Result<(Vec<tokio::sync::OwnedMutexGuard<()>>, Vec<String>), MachineAdminError> {
        let originals = ids
            .iter()
            .map(|id| {
                self.selected_record(id)
                    .ok_or_else(|| MachineAdminError::NotFound(id.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let machine_keys = originals
            .iter()
            .map(|(_, record)| record.machine_key_hex.clone())
            .collect::<BTreeSet<_>>();
        // Deduplicate and order locks for policy route batches containing
        // multiple nodes on one machine or overlapping batches.
        let mut guards = Vec::with_capacity(machine_keys.len());
        for machine_key in machine_keys {
            guards.push(self.registry.lock_registration(&machine_key).await);
        }
        let snapshot = self.registry.snapshot();
        let mut current_keys = Vec::with_capacity(originals.len());
        for (id, original) in originals {
            let node_id = original.stable_node_id_for_key(&id);
            let mut matches = snapshot.iter().filter(|(key, record)| {
                record.stable_node_id_for_key(key) == node_id
                    && record.machine_key_hex == original.machine_key_hex
                    && record.created_at == original.created_at
            });
            let Some((key, _)) = matches.next() else {
                return Err(MachineAdminError::NotFound(id));
            };
            if matches.next().is_some() {
                return Err(MachineAdminError::BadRequest(
                    "ambiguous node identity".into(),
                ));
            }
            current_keys.push(key.clone());
        }
        Ok((guards, current_keys))
    }

    async fn lock_existing_node(
        &self,
        id: &str,
    ) -> Result<(Vec<tokio::sync::OwnedMutexGuard<()>>, String), MachineAdminError> {
        let (guards, mut keys) = self.lock_existing_nodes(&[id.to_owned()]).await?;
        let key = keys
            .pop()
            .ok_or_else(|| MachineAdminError::NotFound(id.into()))?;
        Ok((guards, key))
    }

    /// Render a borrowed `(id, rec)` pair into the admin DTO without
    /// consuming the source record. #238: avoids cloning the
    /// `MachineRecord` strings out of the registry snapshot in
    /// `list()` — the few strings the DTO needs are cloned only out of
    /// the kept records.
    fn render(
        id: &str,
        rec: &crate::tailscale_wire::MachineRecord,
        online: bool,
    ) -> MachineAdminRecord {
        let now = Utc::now();
        let is_expired = rec.is_expired_at(now);
        // Expiry changes authorization, not the durable last-seen history.
        let last_seen = rec.last_seen.timestamp().max(0) as u64;
        let last_seen = if last_seen == 0 {
            now_unix()
        } else {
            last_seen
        };
        MachineAdminRecord {
            node_id: rec.node_id.unwrap_or_default(),
            id: id.to_string(),
            name: rec.hostname.clone(),
            user: rec.user.clone(),
            user_id: rec.user_id,
            auth_key_id: rec.auth_key_id,
            ipv4: rec.ipv4.map(|addr| addr.to_string()).unwrap_or_default(),
            ipv6: rec.ipv6.map(|addr| addr.to_string()),
            online: online && !is_expired,
            last_seen,
            last_seen_precise: Some(rec.last_seen),
            created_at: rec.created_at.timestamp().max(0) as u64,
            created_at_precise: Some(rec.created_at),
            expiry: rec.expiry.map(|t| t.timestamp().max(0) as u64),
            expiry_precise: rec.expiry,
            machine_key_hex: rec.machine_key_hex.clone(),
            disco_key: rec.disco_key.clone().unwrap_or_default(),
            os: nonempty_or_unknown(&rec.os),
            version: nonempty_or_unknown(&rec.os_version),
            tags: rec.forced_tags.clone(),
            routes: rec.available_routes.clone(),
            approved_routes: rec.approved_routes.clone(),
            register_method: rec.register_method,
            expired: is_expired,
        }
    }
}

fn precise_stored_timestamp(raw: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(raw)
        .or_else(|_| DateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f%:z"))
        .map(|value| value.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(raw, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|value| value.and_utc())
        })
        .or_else(|| {
            raw.parse::<i64>()
                .ok()
                .and_then(|secs| DateTime::from_timestamp(secs, 0))
        })
}

fn stored_node_created_at(
    row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
) -> Option<DateTime<Utc>> {
    if row.created_at_text.is_empty() {
        DateTime::from_timestamp(-62_135_596_800, 0)
    } else {
        precise_stored_timestamp(&row.created_at_text)
            .or_else(|| DateTime::from_timestamp(row.created_at, 0))
    }
}

fn node_expiry_is_elapsed(expiry: DateTime<Utc>, now: DateTime<Utc>) -> bool {
    (expiry.timestamp() != -62_135_596_800 || expiry.timestamp_subsec_nanos() != 0) && expiry < now
}

fn nonempty_or_unknown(value: &str) -> String {
    if value.is_empty() {
        "unknown".into()
    } else {
        value.to_string()
    }
}

fn optional_ipv4(value: &str) -> Result<Option<Ipv4Addr>, MachineAdminError> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse::<Ipv4Addr>()
        .map(Some)
        .map_err(|e| MachineAdminError::BadRequest(format!("invalid IPv4: {e}")))
}

fn optional_ipv6(value: Option<&str>) -> Result<Option<Ipv6Addr>, MachineAdminError> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    value
        .parse::<Ipv6Addr>()
        .map(Some)
        .map_err(|e| MachineAdminError::BadRequest(format!("invalid IPv6: {e}")))
}

fn require_any_address(
    ipv4: Option<Ipv4Addr>,
    ipv6: Option<Ipv6Addr>,
) -> Result<(), MachineAdminError> {
    if ipv4.is_none() && ipv6.is_none() {
        return Err(MachineAdminError::BadRequest(
            "node must have at least one IP address".into(),
        ));
    }
    Ok(())
}

fn admin_node_addresses(record: &MachineAdminRecord) -> Vec<String> {
    let mut addresses = Vec::with_capacity(2);
    if !record.ipv4.is_empty() {
        addresses.push(record.ipv4.clone());
    }
    if let Some(address) = record.ipv6.as_ref().filter(|address| !address.is_empty()) {
        addresses.push(address.clone());
    }
    addresses
}

async fn lock_backfill_nodes(
    registry: Option<&Arc<MachineRegistry>>,
    rows: &[headscale_db::headscale_nodes::HeadscaleNodeRow],
) -> Vec<tokio::sync::OwnedMutexGuard<()>> {
    let Some(registry) = registry else {
        return Vec::new();
    };
    let machine_keys = rows
        .iter()
        .map(|row| key_without_prefix("mkey:", &row.machine_key))
        .collect::<BTreeSet<_>>();
    let mut guards = Vec::with_capacity(machine_keys.len());
    for machine_key in machine_keys {
        guards.push(registry.lock_registration(&machine_key).await);
    }
    guards
}

fn prepare_ip_backfill(
    row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    allocator: &dyn IpAllocator,
) -> Result<(headscale_db::headscale_nodes::IpAddressUpdate, Vec<String>), MachineAdminError> {
    let mut ipv4 = row.ipv4.clone();
    let mut ipv6 = row.ipv6.clone();
    let mut changes = Vec::new();
    let key = key_without_prefix("nodekey:", &row.node_key);
    let key = if key.is_empty() {
        row.id.to_string()
    } else {
        key
    };
    let name = headscale_api_acl::go_strconv::quote(&row.hostname);
    if allocator.ipv4_enabled() && ipv4.is_none() {
        let address = allocator
            .allocate(&key)
            .map_err(|error| {
                MachineAdminError::BadRequest(format!(
                    "allocating IPv4 for node({}): {error}",
                    row.id
                ))
            })?
            .to_string();
        changes.push(format!(
            "assigned IPv4 {} to Node({}) {name}",
            headscale_api_acl::go_strconv::quote(&address),
            row.id
        ));
        ipv4 = Some(address);
    }
    if allocator.ipv6_enabled()
        && ipv6.is_none()
        && let Some(address) = allocator.allocate_ipv6(&key).map_err(|error| {
            MachineAdminError::BadRequest(format!("allocating IPv6 for node({}): {error}", row.id))
        })?
    {
        let address = address.to_string();
        changes.push(format!(
            "assigned IPv6 {} to Node({}) {name}",
            headscale_api_acl::go_strconv::quote(&address),
            row.id
        ));
        ipv6 = Some(address);
    }
    if !allocator.ipv4_enabled()
        && let Some(address) = ipv4.take()
    {
        let address = if address.is_empty() {
            "invalid IP"
        } else {
            &address
        };
        changes.push(format!(
            "removing IPv4 {} from Node({}) {name}",
            headscale_api_acl::go_strconv::quote(address),
            row.id
        ));
    }
    if !allocator.ipv6_enabled()
        && let Some(address) = ipv6.take()
    {
        let address = if address.is_empty() {
            "invalid IP"
        } else {
            &address
        };
        changes.push(format!(
            "removing IPv6 {} from Node({}) {name}",
            headscale_api_acl::go_strconv::quote(address),
            row.id
        ));
    }
    Ok((
        headscale_db::headscale_nodes::IpAddressUpdate {
            node_id: row.id,
            ipv4,
            ipv6,
        },
        changes,
    ))
}

fn optional_ipv4_string(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// sqlx-backed node admin adapter over the canonical headscale-go
/// `nodes` table.
///
/// The URL/admin slug remains the node key hex (`MachineAdminRecord::id`)
/// for legacy admin route stability. The upstream-visible numeric ID is
/// carried separately in `MachineAdminRecord::node_id` and is what gRPC
/// uses when present.
#[derive(Clone)]
pub struct PersistentMachineAdmin {
    pool: SqlitePool,
    users: Option<Arc<dyn UserAdmin>>,
    wire_registry: Option<Arc<MachineRegistry>>,
}

/// Postgres-backed node admin adapter over the canonical headscale-go
/// `nodes` table.
///
/// This is feature-gated for the Postgres runtime parity path. It
/// intentionally does not change the default SQLite `headscale server`
/// wiring or remove the explicit Postgres serve guard.
#[cfg(feature = "postgres-sqlx")]
#[derive(Clone)]
pub struct PersistentPostgresMachineAdmin {
    pool: PgPool,
    users: Option<Arc<dyn UserAdmin>>,
    wire_registry: Option<Arc<MachineRegistry>>,
}

#[derive(Clone)]
pub struct PersistentOidcRegistrationHandler {
    registration_cache: Arc<RegistrationCache>,
    machines: Arc<PersistentMachineAdmin>,
    policy: Arc<PolicyStore>,
    wire_registry: Option<Arc<MachineRegistry>>,
    ip_allocator: Option<Arc<dyn IpAllocator>>,
}

#[cfg(feature = "postgres-sqlx")]
#[derive(Clone)]
pub struct PersistentPostgresOidcRegistrationHandler {
    registration_cache: Arc<RegistrationCache>,
    machines: Arc<PersistentPostgresMachineAdmin>,
    policy: Arc<PolicyStore>,
    wire_registry: Option<Arc<MachineRegistry>>,
    ip_allocator: Option<Arc<dyn IpAllocator>>,
}

/// Reauthentication keeps the selected node's addresses. Pending registrations
/// carry no reservation; a fresh node receives its addresses at approval time.
#[derive(Debug, thiserror::Error)]
pub(crate) enum AuthPathAddressError {
    #[error("{0}")]
    Selection(#[from] MachineAdminError),
    #[error("{0}")]
    Tags(String),
    #[error("{0}")]
    Allocation(String),
}

// Only the gRPC test helper `apply_requested_tags` (`full`) calls this.
#[cfg(all(test, feature = "full"))]
pub(crate) fn validate_auth_path_tags(
    policy: &PolicyStore,
    record: &mut MachineAdminRecord,
) -> Result<(), String> {
    validate_auth_path_tags_with_nodes(policy, record, None, &[])
}

fn validate_auth_path_tags_with_nodes(
    policy: &PolicyStore,
    record: &mut MachineAdminRecord,
    existing: Option<&MachineAdminRecord>,
    nodes: &[PolicyCheckNode],
) -> Result<(), String> {
    let fallback = existing.map(policy_check_node_from_machine);
    let existing = fallback.as_ref().map(|node| {
        nodes
            .iter()
            .find(|loaded| loaded.id == node.id)
            .unwrap_or(node)
    });
    let existing_view = existing.map(PolicyCheckNode::as_view);
    let nodes = nodes
        .iter()
        .map(PolicyCheckNode::as_view)
        .collect::<Vec<_>>();
    if validate_requested_tags_for_auth_path(
        policy,
        existing_view.as_ref(),
        &nodes,
        &record.user,
        record.user_id,
        &mut record.tags,
    )? {
        record.expiry = None;
        record.expiry_precise = None;
    }
    Ok(())
}

pub(crate) async fn prepare_auth_path_addresses(
    machines: &dyn MachineAdmin,
    allocator: Option<&dyn IpAllocator>,
    policy: &PolicyStore,
    record: &mut MachineAdminRecord,
) -> Result<(), AuthPathAddressError> {
    let existing = machines.existing_auth_path_record_checked(record).await?;
    let reauthentication = existing.is_some();
    if let Some(existing) = &existing {
        record.ipv4.clone_from(&existing.ipv4);
        record.ipv6.clone_from(&existing.ipv6);
    }
    let nodes = if record.tags.is_empty() {
        Vec::new()
    } else {
        machines.policy_nodes_for_registration().await?
    };
    validate_auth_path_tags_with_nodes(policy, record, existing.as_ref(), &nodes)
        .map_err(AuthPathAddressError::Tags)?;
    if reauthentication {
        return Ok(());
    }
    let Some(allocator) = allocator else {
        if record.ipv4.is_empty() && record.ipv6.is_none() {
            record.ipv4 = crate::tailscale_wire::legacy_registration_ipv4(&record.id).to_string();
        }
        return Ok(());
    };
    let (ipv4, ipv6) =
        crate::tailscale_wire::allocate_registration_addresses(allocator, &record.id)
            .map_err(AuthPathAddressError::Allocation)?;
    record.ipv4 = ipv4.map(|ip| ip.to_string()).unwrap_or_default();
    record.ipv6 = ipv6.map(|ip| ip.to_string());
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthPathRegistrationResult {
    pub record: MachineAdminRecord,
    pub new_node: bool,
    pub replaced_node_key_hex: Option<String>,
}

struct PreparedAuthPathRegistration {
    existing: Option<headscale_db::headscale_nodes::HeadscaleNodeRow>,
    params: headscale_db::headscale_nodes::CreateParams,
    associations: NativeNodeAssociations,
    user_write: Option<headscale_db::users::UserWriteSnapshot>,
}

fn new_native_registration(
    params: &headscale_db::headscale_nodes::CreateParams,
) -> Result<headscale_db::headscale_nodes::NewNodeRegistration, MachineAdminError> {
    let tagged = !params.tags.is_empty();
    let expiry = if tagged {
        None
    } else if let Some(precise) = params.expiry_precise {
        Some(precise)
    } else {
        params
            .expiry
            .map(|seconds| {
                DateTime::from_timestamp(seconds, 0)
                    .ok_or_else(|| MachineAdminError::BadRequest("invalid new node expiry".into()))
            })
            .transpose()?
    };
    let last_seen = if let Some(precise) = params.last_seen_precise {
        precise
    } else if let Some(seconds) = params.last_seen {
        DateTime::from_timestamp(seconds, 0)
            .ok_or_else(|| MachineAdminError::BadRequest("invalid new node last seen".into()))?
    } else {
        Utc::now()
    };
    Ok(headscale_db::headscale_nodes::NewNodeRegistration {
        machine_key: params.machine_key.clone(),
        node_key: params.node_key.clone(),
        disco_key: params.disco_key.clone(),
        endpoints: (!params.endpoints.is_empty()).then(|| params.endpoints.clone()),
        host_info: Some(params.host_info.clone()),
        ipv4: params.ipv4.clone(),
        ipv6: params.ipv6.clone(),
        hostname: params.hostname.clone(),
        given_name: crate::tailscale_wire::wire::sanitize_hostname_for_given_name(&params.hostname),
        user_id: if tagged { None } else { params.user_id },
        register_method: params.register_method.clone(),
        tags: tagged.then(|| params.tags.clone()),
        auth_key_id: params.auth_key_id,
        expiry,
        last_seen: Some(last_seen),
        approved_routes: None,
    })
}

fn apply_new_association_projection(
    associations: &mut NativeNodeAssociations,
    node: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    saved: &headscale_db::headscale_nodes::NewNodeAssociations,
) -> Result<(), MachineAdminError> {
    use headscale_db::headscale_nodes::NewNodeAssociations;
    match saved {
        NewNodeAssociations::None => {}
        NewNodeAssociations::User(user) => {
            associations.user = Some(Some(
                super::users::PersistentUserAdmin::row_to_association_record(user.row.clone()),
            ));
        }
        NewNodeAssociations::AuthKey(key) => {
            let user = key.user.as_ref().map(|user| {
                super::users::PersistentUserAdmin::row_to_association_record(user.row.clone())
            });
            associations.auth_key =
                Some(Some(NativeAuthKey::from_row(&key.key, Some(user.clone()))?));
            associations.user = Some(if node.user_id.is_some() { user } else { None });
        }
    }
    Ok(())
}

async fn finish_new_native_registration(
    registry: Option<&MachineRegistry>,
    row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    mut record: MachineRecord,
    auth_key: bool,
    associations: NativeNodeAssociations,
) -> Result<MachineRecord, MachineAdminError> {
    let id = native_row_id(row)?;
    record.node_id = Some(id);
    record.node_key_hex = key_without_prefix("nodekey:", &row.node_key);
    record.machine_key_hex = key_without_prefix("mkey:", &row.machine_key);
    record.auth_key_id = row.auth_key_id;
    record.user_id = row
        .user_id
        .map(u64::try_from)
        .transpose()
        .map_err(|_| MachineAdminError::BadRequest("invalid new user identity".into()))?;
    record.ipv4 = optional_ipv4(row.ipv4.as_deref().unwrap_or_default())?;
    record.ipv6 = optional_ipv6(row.ipv6.as_deref())?;
    record.hostname.clone_from(&row.given_name);
    record.replace_host_info(host_info_from_row(row)?);
    record.raw_hostname.clone_from(&row.hostname);
    record.disco_key = (!row.disco_key.is_empty()).then(|| row.disco_key.clone());
    record.endpoints = row
        .try_endpoint_list()
        .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
    record.forced_tags = row
        .try_tag_list()
        .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
    record.approved_routes = row
        .try_approved_route_list()
        .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
    record.created_at = precise_stored_timestamp(&row.created_at_text)
        .ok_or_else(|| MachineAdminError::BadRequest("invalid new node creation time".into()))?;
    record.last_seen = row
        .last_seen_text
        .as_deref()
        .and_then(precise_stored_timestamp)
        .ok_or_else(|| MachineAdminError::BadRequest("invalid new node last seen".into()))?;
    record.expiry = row
        .expiry_text
        .as_deref()
        .map(|value| {
            precise_stored_timestamp(value)
                .ok_or_else(|| MachineAdminError::BadRequest("invalid new node expiry".into()))
        })
        .transpose()?;
    record.register_method = register_method_from_db(&row.register_method);
    if !auth_key {
        record.ephemeral = false;
    }
    if record.is_tagged() {
        record.clear_user_identity();
    } else {
        apply_loaded_user_identity(&mut record, associations.user.as_ref());
    }
    if auth_key && let Some(Some(key)) = &associations.auth_key {
        key.consume();
        record.ephemeral = key.ephemeral;
    }
    let Some(registry) = registry else {
        // Keep the database's original sanitized seed. A detached adapter has
        // no retained NodeStore collision authority, but the empty-label
        // fallback in its returned model is still the same as Go's PutNode.
        if record.hostname.is_empty() {
            record.hostname = "node".into();
        }
        return Ok(record);
    };
    let mut native = NativeNodePersistence::capture(row, &record)?;
    native.set_associations(associations);
    let hostinfo = row
        .try_host_info_value()
        .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
    let record = registry
        .put_new_native_registration(record, hostinfo, native)
        .await
        .map_err(MachineAdminError::BadRequest)?;
    Ok(record)
}

/// Explicit nil assignments that the public Vec/Option projection cannot
/// distinguish from preserving a previous native value.
#[derive(Clone, Copy, Default)]
pub(crate) struct NativeNodeMetadataEdit {
    pub(crate) nil_user: bool,
    pub(crate) nil_routes: bool,
    pub(crate) require_native: bool,
}

pub(crate) struct PreparedNativeRegistration {
    pub(crate) record: MachineRecord,
    pub(crate) native: NativeNodePersistence,
    pub(crate) registration: headscale_db::headscale_nodes::CachedNodeRegistration,
}

struct LiveRegistrationSave {
    update: crate::tailscale_wire::NativeRegistrationUpdate,
    registration: headscale_db::headscale_nodes::CachedNodeRegistration,
    auth_key_to_consume: Option<NativeAuthKey>,
}

fn prepare_cached_auth_registration(
    id: u64,
    before: &MachineRecord,
    prior_native: Option<&NativeNodePersistence>,
    params: &headscale_db::headscale_nodes::CreateParams,
    wire: Option<&MachineRecord>,
    auth_key: bool,
    mut associations: NativeNodeAssociations,
) -> Result<PreparedNativeRegistration, MachineAdminError> {
    use headscale_db::headscale_nodes::{CachedNodeRegistration, RegistrationAuthKey};
    let mut proposed = before.clone();
    proposed.node_key_hex = key_without_prefix("nodekey:", &params.node_key);
    proposed.replace_host_info(host_info_from_value(&params.host_info)?);
    proposed.raw_hostname.clone_from(&params.hostname);
    if !auth_key {
        proposed.disco_key = Some(params.disco_key.clone());
        if !params.endpoints.is_empty() {
            proposed.endpoints.clone_from(&params.endpoints);
        }
    }
    proposed.forced_tags.clone_from(&params.tags);
    proposed.user_id = params
        .user_id
        .map(u64::try_from)
        .transpose()
        .map_err(|_| MachineAdminError::BadRequest("invalid user identity".into()))?;
    if proposed.is_tagged() {
        proposed.clear_user_identity();
    } else if let Some(wire) = wire.as_ref()
        && !auth_key
    {
        proposed.set_user_identity(
            proposed.user_id,
            wire.user.clone(),
            wire.user_display_name.clone(),
            wire.user_profile_pic_url.clone(),
        );
        proposed.set_user_account_metadata(
            wire.user_provider.clone(),
            wire.user_created_at.or_else(|| {
                (wire.user_id == before.user_id)
                    .then_some(before.user_created_at)
                    .flatten()
            }),
        );
    }
    proposed.auth_key_id = if auth_key {
        if params.auth_key_id.is_some_and(|id| id < 0) {
            return Err(MachineAdminError::BadRequest(
                "invalid auth key identity".into(),
            ));
        }
        params.auth_key_id
    } else if before.is_tagged() && !proposed.is_tagged() {
        None
    } else {
        before.auth_key_id
    };
    if auth_key {
        if let Some(key) = &associations.auth_key {
            proposed.ephemeral = key.as_ref().is_some_and(|key| key.ephemeral);
        } else if let Some(wire) = wire.as_ref() {
            proposed.ephemeral = wire.ephemeral;
        }
        if proposed.is_tagged() {
            associations.user = Some(None);
        } else if !before.is_tagged() {
            associations.user = prior_native
                .and_then(|native| native.user_association(before))
                .map(Option::<&UserRecord>::cloned)
                .or(associations.user);
        }
    }
    if !auth_key {
        if before.is_tagged() && !proposed.is_tagged() {
            proposed.ephemeral = false;
        }
        if !proposed.is_tagged() {
            apply_loaded_user_identity(&mut proposed, associations.user.as_ref());
        }
    }
    proposed.register_method = register_method_from_db(&params.register_method);
    proposed.expiry = params.expiry_precise.or_else(|| {
        params
            .expiry
            .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
    });
    if !before.is_tagged() && proposed.is_tagged() {
        proposed.expiry = None;
    }
    if auth_key && let Some(Some(key)) = &associations.auth_key {
        proposed.forced_tags.clone_from(&before.forced_tags);
        proposed.user_id = before.user_id;
        proposed.user.clone_from(&before.user);
        proposed
            .user_display_name
            .clone_from(&before.user_display_name);
        proposed
            .user_profile_pic_url
            .clone_from(&before.user_profile_pic_url);
        proposed.user_provider.clone_from(&before.user_provider);
        proposed.user_created_at = before.user_created_at;
        let key_id = i64::try_from(key.id)
            .map_err(|_| MachineAdminError::BadRequest("invalid auth key identity".into()))?;
        proposed.auth_key_id = Some(key_id);
        if !key.tags.is_empty() && (!before.is_tagged() || before.auth_key_id != Some(key_id)) {
            proposed.forced_tags.clone_from(&key.tags);
            proposed.clear_user_identity();
        }
        if proposed.is_tagged() {
            associations.user = Some(None);
            proposed.expiry = if !before.is_tagged() || before.is_expired_at(Utc::now()) {
                None
            } else {
                before.expiry
            };
        } else {
            associations.user = prior_native
                .and_then(|native| native.user_association(before))
                .map(Option::<&UserRecord>::cloned)
                .or(associations.user);
        }
    }
    proposed.last_seen = Utc::now();
    // Registration callbacks do not auto-approve routes or replace IPs,
    // CreatedAt, online state, or GivenName on an existing node.
    proposed.approved_routes.clone_from(&before.approved_routes);
    let mut node = NativeNodePersistence::snapshot(id, &proposed, prior_native)?;
    node.host_info = Some(params.host_info.clone());
    node.last_seen = Some(proposed.last_seen);
    if proposed.is_tagged() {
        node.user_id = None;
    }
    if before.is_tagged() && !proposed.is_tagged() {
        node.tags = None;
    }
    let mut native = NativeNodePersistence::from_snapshot(&proposed, &node, prior_native);
    native.set_associations(associations);
    let registration = CachedNodeRegistration {
        node,
        expiry: proposed.expiry,
        auth_key: if auth_key {
            RegistrationAuthKey::Set(proposed.auth_key_id)
        } else if proposed.auth_key_id.is_none() {
            RegistrationAuthKey::Set(None)
        } else {
            RegistrationAuthKey::Preserve
        },
    };
    Ok(PreparedNativeRegistration {
        record: proposed,
        native,
        registration,
    })
}

impl LiveRegistrationSave {
    async fn begin(
        registry: &MachineRegistry,
        prior: &headscale_db::headscale_nodes::HeadscaleNodeRow,
        params: &headscale_db::headscale_nodes::CreateParams,
        wire: Option<&MachineRecord>,
        auth_key: bool,
        associations: NativeNodeAssociations,
    ) -> Result<Box<Self>, MachineAdminError> {
        let id = native_row_id(prior)?;
        let params = params.clone();
        let wire = wire.cloned();
        let auth_key_to_consume = if auth_key {
            associations.auth_key.as_ref().and_then(Clone::clone)
        } else {
            None
        };
        let (update, registration) = registry
            .begin_native_registration(id, move |before, prior_native| {
                prepare_cached_auth_registration(
                    id,
                    before,
                    prior_native,
                    &params,
                    wire.as_ref(),
                    auth_key,
                    associations,
                )
            })
            .await?;
        // Boxed: this is held across the SQL save, and inline it would more
        // than double the size of every registration future above it.
        Ok(Box::new(Self {
            update,
            registration,
            auth_key_to_consume,
        }))
    }

    async fn rollback(&self, registry: &MachineRegistry) -> Result<(), MachineAdminError> {
        registry
            .rollback_native_registration(&self.update)
            .await
            .map_err(MachineAdminError::BadRequest)?;
        Ok(())
    }

    fn finish(self: Box<Self>, registry: &MachineRegistry) -> MachineRecord {
        if let Some(key) = &self.auth_key_to_consume {
            key.consume();
        }
        let record = self.update.after.clone();
        registry.defer_native_registration_publication(self.update);
        record
    }
}

fn apply_registration_hostinfo(
    params: &mut headscale_db::headscale_nodes::CreateParams,
    requested: Option<&Value>,
) -> Result<(), MachineAdminError> {
    let Some(requested) = requested else {
        return Ok(());
    };
    let projection = host_info_from_value(&params.host_info)?;
    let preserved_netinfo = params.host_info.get("NetInfo").cloned();
    params.host_info = crate::tailscale_wire::hostinfo::registration_value(
        requested,
        &projection,
        preserved_netinfo.as_ref(),
    )
    .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
    Ok(())
}

fn finalize_auth_path_clock(
    params: &mut headscale_db::headscale_nodes::CreateParams,
    registry: Option<&MachineRegistry>,
) {
    let now = Utc::now();
    params.last_seen = Some(now.timestamp());
    params.last_seen_precise = Some(now);
    let Some(registry) = registry else {
        return;
    };
    let expiry = match (params.expiry_precise, params.expiry) {
        (Some(expiry), _) => Some(expiry),
        (None, Some(seconds)) => {
            let Some(expiry) = DateTime::from_timestamp(seconds, 0) else {
                // An invalid supplied timestamp must not become a default.
                return;
            };
            Some(expiry)
        }
        (None, None) => None,
    };
    let expiry = registry.registration_expiry(expiry, !params.tags.is_empty(), now);
    params.expiry = expiry.map(|value| value.timestamp());
    params.expiry_precise = expiry;
}

/// Match the pinned Go machine/user index without promoting a cached wire ID
/// or an arbitrary first row into authority to replace another user's node.
fn select_auth_path_node(
    rows: Vec<headscale_db::headscale_nodes::HeadscaleNodeRow>,
    user_id: Option<i64>,
    allow_unscoped_owner: bool,
    auth_key_path: bool,
    tagged_registration: bool,
) -> Result<Option<headscale_db::headscale_nodes::HeadscaleNodeRow>, MachineAdminError> {
    if auth_key_path && user_id.is_none() && !tagged_registration && !allow_unscoped_owner {
        return Ok(None);
    }
    let mut same_owner = None;
    let mut tagged = None;
    let mut user_owned = Vec::new();
    for row in rows {
        if row
            .try_tag_list()
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?
            .is_empty()
        {
            if row.user_id.is_some_and(|id| id != 0)
                || (row.user_id.is_none() && allow_unscoped_owner)
            {
                user_owned.push(row.clone());
            }
            if row.user_id == user_id
                && (user_id.is_some() || allow_unscoped_owner)
                && same_owner.replace(row).is_some()
            {
                return Err(MachineAdminError::BadRequest(
                    "machine key maps to ambiguous node ownership".into(),
                ));
            }
        } else if tagged.replace(row).is_some() {
            return Err(MachineAdminError::BadRequest(
                "machine key maps to ambiguous node ownership".into(),
            ));
        }
    }
    if !auth_key_path && tagged.is_some() && !user_owned.is_empty() {
        return Err(MachineAdminError::BadRequest(
            "machine key maps to ambiguous node ownership".into(),
        ));
    }
    if let Some(node) = same_owner.or(tagged) {
        return Ok(Some(node));
    }
    if auth_key_path && tagged_registration && user_id.is_none() {
        if user_owned.len() > 1 {
            return Err(MachineAdminError::BadRequest(
                "machine key maps to ambiguous node ownership".into(),
            ));
        }
        return Ok(user_owned.pop());
    }
    Ok(None)
}

async fn resolve_record_owner(
    users: Option<&dyn UserAdmin>,
    record: &MachineAdminRecord,
) -> Result<Option<i64>, MachineAdminError> {
    if let Some(id) = record.user_id {
        let numeric = i64::try_from(id)
            .ok()
            .filter(|id| *id > 0)
            .ok_or_else(|| MachineAdminError::BadRequest("user id out of range".into()))?;
        if let Some(users) = users
            && users
                .get_by_id(id)
                .await
                .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?
                .is_none()
        {
            return Err(MachineAdminError::BadRequest("user not found".into()));
        }
        return Ok(Some(numeric));
    }
    if record.user.trim().is_empty() {
        return Ok(None);
    }
    let Some(users) = users else {
        return Ok(record.user.parse::<i64>().ok());
    };
    let user = users
        .get(&record.user)
        .await
        .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?
        .ok_or_else(|| MachineAdminError::BadRequest("user not found".into()))?;
    i64::try_from(user.id)
        .map(Some)
        .map_err(|_| MachineAdminError::BadRequest("user id out of range".into()))
}

fn auth_key_owner_override(record: &MachineRecord) -> Result<Option<i64>, MachineAdminError> {
    record
        .user_id
        .map(i64::try_from)
        .transpose()
        .map_err(|_| MachineAdminError::BadRequest("user id out of range".into()))
}

fn atomic_registration_error(
    error: headscale_db::auth_key_registration::Error,
) -> crate::tailscale_wire::AuthKeyRegistrationError {
    match error {
        headscale_db::auth_key_registration::Error::Credential(error) => {
            crate::tailscale_wire::AuthKeyRegistrationError::Credential(
                super::preauth_persistent::use_error_to_redeem(error),
            )
        }
        error => {
            crate::tailscale_wire::AuthKeyRegistrationError::Storage(error.headscale_go_message())
        }
    }
}

// Preserve Go's operation context for storage failures while credential errors
// retain their leaf message for the register handler's PAKError response.
fn captured_registration_error(
    error: headscale_db::auth_key_registration::Error,
    context: &'static str,
) -> crate::tailscale_wire::AuthKeyRegistrationError {
    match atomic_registration_error(error) {
        crate::tailscale_wire::AuthKeyRegistrationError::Storage(error) => {
            crate::tailscale_wire::AuthKeyRegistrationError::Storage(format!("{context}: {error}"))
        }
        error @ crate::tailscale_wire::AuthKeyRegistrationError::Credential(_) => error,
    }
}

fn captured_auth_key(
    credential: Option<&NativeAuthKey>,
) -> Result<
    Option<headscale_db::auth_key_registration::CapturedAuthKey>,
    crate::tailscale_wire::AuthKeyRegistrationError,
> {
    credential
        .map(|key| {
            Ok(headscale_db::auth_key_registration::CapturedAuthKey {
                id: i64::try_from(key.id).map_err(|_| {
                    crate::tailscale_wire::AuthKeyRegistrationError::Storage(
                        "auth key id out of range".into(),
                    )
                })?,
                reusable: key.reusable,
                used: key.used_flag(),
            })
        })
        .transpose()
}

impl PersistentOidcRegistrationHandler {
    pub fn new(
        registration_cache: Arc<RegistrationCache>,
        machines: Arc<PersistentMachineAdmin>,
        policy: Arc<PolicyStore>,
    ) -> Self {
        Self {
            registration_cache,
            machines,
            policy,
            wire_registry: None,
            ip_allocator: None,
        }
    }

    pub fn with_wire_registry(mut self, wire_registry: Arc<MachineRegistry>) -> Self {
        self.wire_registry = Some(wire_registry);
        self
    }

    pub fn with_ip_allocator(mut self, ip_allocator: Arc<dyn IpAllocator>) -> Self {
        self.ip_allocator = Some(ip_allocator);
        self
    }
}

#[cfg(feature = "postgres-sqlx")]
impl PersistentPostgresOidcRegistrationHandler {
    pub fn new(
        registration_cache: Arc<RegistrationCache>,
        machines: Arc<PersistentPostgresMachineAdmin>,
        policy: Arc<PolicyStore>,
    ) -> Self {
        Self {
            registration_cache,
            machines,
            policy,
            wire_registry: None,
            ip_allocator: None,
        }
    }

    pub fn with_wire_registry(mut self, wire_registry: Arc<MachineRegistry>) -> Self {
        self.wire_registry = Some(wire_registry);
        self
    }

    pub fn with_ip_allocator(mut self, ip_allocator: Arc<dyn IpAllocator>) -> Self {
        self.ip_allocator = Some(ip_allocator);
        self
    }
}

impl PersistentMachineAdmin {
    async fn lock_existing_node(
        &self,
        id: &str,
    ) -> Result<
        (
            Option<tokio::sync::OwnedMutexGuard<()>>,
            headscale_db::headscale_nodes::HeadscaleNodeRow,
        ),
        MachineAdminError,
    > {
        let row = self.row_by_slug(id).await?;
        let Some(registry) = &self.wire_registry else {
            return Ok((None, row));
        };
        let machine_key = key_without_prefix("mkey:", &row.machine_key);
        let guard = registry.lock_registration(&machine_key).await;
        // Resolve by stable database ID again: the node key may have rotated
        // while this operation waited behind registration.
        let row = headscale_db::headscale_nodes::get_by_id(&self.pool, row.id)
            .await
            .map_err(|error| db_error_to_machine(error, id))?;
        Ok((Some(guard), row))
    }

    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            users: None,
            wire_registry: None,
        }
    }

    pub fn with_user_admin(mut self, users: Arc<dyn UserAdmin>) -> Self {
        self.users = Some(users);
        self
    }

    pub fn with_wire_registry(mut self, registry: Arc<MachineRegistry>) -> Self {
        registry.require_native_policy_persistence();
        self.wire_registry = Some(registry);
        self
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    async fn registration_user_association(
        &self,
        raw_id: Option<i64>,
        captured: Option<&super::users::UserRegistrationSnapshot>,
    ) -> Result<RegistrationUserAssociation, MachineAdminError> {
        let Some(id) = raw_id else {
            return Ok((Some(None), None));
        };
        if let Some(user) = captured {
            return Ok((Some(Some(user.user.clone())), user.write.clone()));
        }
        let write = headscale_db::users::get_for_registration(&self.pool, id)
            .await
            .map_err(|error| {
                let message = match error {
                    headscale_db::DbError::NotFound(_) => "user not found".to_string(),
                    error => error.headscale_go_message(),
                };
                MachineAdminError::Storage(format!("finding user: {message}"))
            })?;
        let user = super::users::PersistentUserAdmin::row_to_association_record(write.row.clone());
        Ok((Some(Some(user)), Some(write)))
    }

    async fn loaded_user_association(
        &self,
        raw_id: Option<i64>,
    ) -> Result<Option<UserRecord>, MachineAdminError> {
        let Some(id) = raw_id else {
            return Ok(None);
        };
        if id < 0 {
            return Err(MachineAdminError::Storage(
                "invalid stored user identity".into(),
            ));
        }
        match headscale_db::users::get_by_id(&self.pool, id).await {
            Ok(row) => Ok(Some(
                super::users::PersistentUserAdmin::row_to_association_record(row),
            )),
            Err(headscale_db::DbError::NotFound(_)) => Ok(None),
            Err(error) => Err(MachineAdminError::Storage(format!(
                "loading node user association: {}",
                error.headscale_go_message(),
            ))),
        }
    }

    async fn auth_key_association(
        &self,
        auth_key_id: Option<i64>,
    ) -> Result<Option<NativeAuthKey>, MachineAdminError> {
        let Some(id) = auth_key_id else {
            return Ok(None);
        };
        if id < 0 {
            return Err(MachineAdminError::Storage(
                "invalid stored preauth key identity".into(),
            ));
        }
        let row = match headscale_db::preauth_keys::get_by_id(&self.pool, id).await {
            Ok(row) => row,
            Err(headscale_db::DbError::NotFound(_)) => return Ok(None),
            Err(error) => {
                return Err(MachineAdminError::Storage(format!(
                    "loading node preauth key: {}",
                    error.headscale_go_message()
                )));
            }
        };
        let user_id = if row.user_id.is_empty() {
            None
        } else {
            Some(row.user_id.parse::<i64>().map_err(|_| {
                MachineAdminError::Storage("invalid stored preauth key user identity".into())
            })?)
        };
        let user = self.loaded_user_association(user_id).await?;
        NativeAuthKey::from_row(&row, Some(user)).map(Some)
    }

    pub async fn hydrate_wire_registry(
        &self,
        registry: &MachineRegistry,
    ) -> Result<usize, MachineAdminError> {
        let rows = headscale_db::headscale_nodes::list(&self.pool)
            .await
            .map_err(|error| MachineAdminError::Storage(error.headscale_go_message()))?;
        let mut hydrated = 0usize;
        for row in rows {
            let (wire, association) = self.row_to_wire_record_with_association(&row).await?;
            stage_native_row(registry, &row, &wire, association)?;
            registry.upsert(wire.node_key_hex.clone(), wire);
            hydrated += 1;
        }
        Ok(hydrated)
    }

    pub async fn create_or_update_auth_path(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.create_or_update_auth_path_inner(record, policy, None, None, true, None)
            .await
    }

    pub async fn create_or_update_auth_key_path(
        &self,
        record: MachineRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        let wire_record = record;
        let mut record = machine_admin_record_from_wire(&wire_record);
        record.register_method = REGISTER_METHOD_AUTH_KEY;
        self.create_or_update_auth_path_inner(
            record,
            policy,
            auth_key_id,
            auth_key_owner_override(&wire_record)?,
            false,
            Some(&wire_record),
        )
        .await
    }

    async fn create_or_update_auth_path_inner(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
        user_id_override: Option<i64>,
        validate_requested_tags: bool,
        wire_record: Option<&MachineRecord>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.create_or_update_auth_path_with_hostinfo(
            record,
            policy,
            auth_key_id,
            user_id_override,
            validate_requested_tags,
            wire_record,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_or_update_auth_path_with_hostinfo(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
        user_id_override: Option<i64>,
        validate_requested_tags: bool,
        wire_record: Option<&MachineRecord>,
        hostinfo: Option<Value>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.create_or_update_auth_path_with_user_snapshot(
            record,
            policy,
            auth_key_id,
            user_id_override,
            validate_requested_tags,
            wire_record,
            hostinfo,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_or_update_auth_path_with_user_snapshot(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
        user_id_override: Option<i64>,
        validate_requested_tags: bool,
        wire_record: Option<&MachineRecord>,
        hostinfo: Option<Value>,
        captured_user: Option<&super::users::UserRegistrationSnapshot>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        let subject = record.id.clone();
        let mut plan = Box::pin(self.prepare_auth_path_registration(
            record,
            policy,
            auth_key_id,
            user_id_override,
            validate_requested_tags,
            wire_record,
            None,
            captured_user,
        ))
        .await?;
        apply_registration_hostinfo(&mut plan.params, hostinfo.as_ref())?;
        if let (Some(registry), Some(prior)) = (&self.wire_registry, plan.existing.as_ref()) {
            // Batch wait first, lock second: the live edit goes through the
            // NodeStore writer like Go's UpdateNode, so concurrent registrations
            // share one batch. The save lock covers only the SQL write.
            let live = Box::pin(LiveRegistrationSave::begin(
                registry,
                prior,
                &plan.params,
                wire_record,
                !validate_requested_tags,
                plan.associations.clone(),
            ))
            .await?;
            let _persist = registry.lock_native_persistence().await;
            if let Err(error) = headscale_db::headscale_nodes::save_cached_registration(
                &self.pool,
                live.registration.clone(),
            )
            .await
            {
                if !validate_requested_tags {
                    live.rollback(registry).await?;
                }
                return Err(db_error_to_machine(error, &subject));
            }
            let previous_key = live.update.before.node_key_hex.clone();
            let record = live.finish(registry);
            return Ok(AuthPathRegistrationResult {
                new_node: false,
                replaced_node_key_hex: (previous_key != record.node_key_hex)
                    .then_some(previous_key),
                record: machine_admin_record_from_wire(&record),
            });
        }
        if let Some(prior) = plan.existing.as_ref() {
            let prepared = self
                .prepare_headless_registration(
                    prior,
                    &plan.params,
                    wire_record,
                    !validate_requested_tags,
                    plan.associations.clone(),
                )
                .await?;
            headscale_db::headscale_nodes::save_cached_registration(
                &self.pool,
                prepared.registration,
            )
            .await
            .map_err(|error| {
                MachineAdminError::Storage(format!(
                    "writing node to database: saving node: {}",
                    error.headscale_go_message(),
                ))
            })?;
            let record = machine_admin_record_from_wire(&prepared.record);
            let previous_key = key_without_prefix("nodekey:", &prior.node_key);
            return Ok(AuthPathRegistrationResult {
                replaced_node_key_hex: (previous_key != record.id).then_some(previous_key),
                record,
                new_node: false,
            });
        }
        let node = new_native_registration(&plan.params)?;
        let material = plan
            .user_write
            .take()
            .map(|user| headscale_db::headscale_nodes::NewNodeAssociations::User(Box::new(user)))
            .unwrap_or_default();
        let saved = headscale_db::headscale_nodes::create_new_registration_with_associations(
            &self.pool, node, material,
        )
        .await
        .map_err(|error| {
            MachineAdminError::Storage(format!(
                "creating new node: {}",
                error.headscale_go_message()
            ))
        })?;
        apply_new_association_projection(&mut plan.associations, &saved.node, &saved.associations)?;
        let row = saved.node;
        let record = match wire_record {
            Some(record) => record.clone(),
            None => {
                self.row_to_wire_record_using_associations(&row, Some(&plan.associations))
                    .await?
                    .0
            }
        };
        let record = Box::pin(finish_new_native_registration(
            self.wire_registry.as_deref(),
            &row,
            record,
            !validate_requested_tags,
            plan.associations.clone(),
        ))
        .await?;
        Ok(AuthPathRegistrationResult {
            record: machine_admin_record_from_wire(&record),
            new_node: true,
            replaced_node_key_hex: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_auth_path_registration(
        &self,
        mut record: MachineAdminRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
        user_id_override: Option<i64>,
        validate_requested_tags: bool,
        wire_record: Option<&MachineRecord>,
        credential: Option<&NativeAuthKey>,
        captured_user: Option<&super::users::UserRegistrationSnapshot>,
    ) -> Result<PreparedAuthPathRegistration, MachineAdminError> {
        if record.id.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "node key must not be empty".into(),
            ));
        }
        let ipv4 = optional_ipv4(&record.ipv4)?;
        let ipv6 = optional_ipv6(record.ipv6.as_deref())?;
        require_any_address(ipv4, ipv6)?;
        let user_id = if let Some(credential) = credential {
            credential
                .user
                .as_ref()
                .and_then(Option::as_ref)
                .map(|user| i64::try_from(user.id))
                .transpose()
                .map_err(|_| MachineAdminError::BadRequest("user id out of range".into()))?
        } else if let Some(user) = captured_user {
            Some(
                i64::try_from(user.user.id)
                    .map_err(|_| MachineAdminError::BadRequest("user id out of range".into()))?,
            )
        } else {
            match user_id_override {
                Some(user_id) => Some(user_id),
                None => self.user_id_for_record(&record).await?,
            }
        };
        if let Some(registry) = &self.wire_registry {
            registry
                .validate_registration_node_key(&record.id, &record.machine_key_hex)
                .map_err(|error| MachineAdminError::BadRequest(error.into()))?;
        }
        let machine_key = key_with_prefix("mkey:", &record.machine_key_hex);
        let candidates = if let Some(registry) = &self.wire_registry {
            registration_rows_from_cache(registry, &record.machine_key_hex)?
        } else {
            headscale_db::headscale_nodes::list_by_machine_key(&self.pool, &machine_key)
                .await
                .map_err(|error| db_error_to_machine(error, &record.id))?
        };
        // A different user's node on the same machine is a fresh identity.
        // Go carries only its NetInfo into that new node when the request
        // omitted it; ownership, addresses and routes must not carry over.
        let previous_net_info = if let Some(node) = candidates.iter().find(|node| {
            node.tag_list().is_empty() && node.user_id.is_some() && node.user_id != user_id
        }) {
            node.try_host_info_value()
                .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?
                .get("NetInfo")
                .cloned()
        } else {
            None
        };
        let existing = select_auth_path_node(
            candidates,
            user_id,
            self.users.is_none() && credential.is_none(),
            !validate_requested_tags,
            !record.tags.is_empty(),
        )?;

        if validate_requested_tags && !record.tags.is_empty() {
            record.user_id = user_id.and_then(|id| u64::try_from(id).ok());
            let existing_record = match &existing {
                Some(existing) => Some(self.row_to_record(existing.clone()).await),
                None => None,
            };
            let nodes = self.policy_nodes_for_registration().await?;
            validate_auth_path_tags_with_nodes(
                policy,
                &mut record,
                existing_record.as_ref(),
                &nodes,
            )
            .map_err(MachineAdminError::BadRequest)?;
        }

        if let Some(existing) = existing {
            if let Some(ipv4) = existing.ipv4.as_ref().filter(|value| !value.is_empty()) {
                record.ipv4.clone_from(ipv4);
            }
            if let Some(ipv6) = existing.ipv6.as_ref().filter(|value| !value.is_empty()) {
                record.ipv6 = Some(ipv6.clone());
            }
            record.approved_routes = existing
                .try_approved_route_list()
                .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;

            let mut params = create_params_for_auth_path(
                &record,
                wire_record,
                user_id,
                auth_key_id,
                Some(&existing),
            )?;
            finalize_auth_path_clock(&mut params, self.wire_registry.as_deref());
            let mut associations = if let Some(key) = credential {
                if params.auth_key_id.and_then(|id| u64::try_from(id).ok()) != Some(key.id) {
                    return Err(MachineAdminError::BadRequest(
                        "preauth key identity changed during registration".into(),
                    ));
                }
                NativeNodeAssociations {
                    user: Some(None),
                    auth_key: Some(Some(key.clone())),
                }
            } else {
                NativeNodeAssociations {
                    user: self
                        .registration_user_association(params.user_id, captured_user)
                        .await?
                        .0,
                    auth_key: if validate_requested_tags {
                        None
                    } else {
                        Some(self.auth_key_association(params.auth_key_id).await?)
                    },
                }
            };
            if params.user_id.is_some()
                && let Some(Some(key)) = &associations.auth_key
            {
                associations.user.clone_from(&key.user);
            }
            Ok(PreparedAuthPathRegistration {
                associations,
                params,
                existing: Some(existing),
                user_write: None,
            })
        } else {
            record.approved_routes.clear();
            let mut params =
                create_params_for_auth_path(&record, wire_record, user_id, auth_key_id, None)?;
            if let Some(net_info) = previous_net_info
                && params.host_info.get("NetInfo").is_none_or(Value::is_null)
            {
                params.host_info["NetInfo"] = net_info;
            }
            finalize_auth_path_clock(&mut params, self.wire_registry.as_deref());
            let (user, user_write) = if credential.is_some() {
                (Some(None), None)
            } else {
                self.registration_user_association(params.user_id, captured_user)
                    .await?
            };
            let mut associations = if let Some(key) = credential {
                if params.auth_key_id.and_then(|id| u64::try_from(id).ok()) != Some(key.id) {
                    return Err(MachineAdminError::BadRequest(
                        "preauth key identity changed during registration".into(),
                    ));
                }
                NativeNodeAssociations {
                    user: Some(None),
                    auth_key: Some(Some(key.clone())),
                }
            } else {
                NativeNodeAssociations {
                    user,
                    auth_key: if validate_requested_tags {
                        None
                    } else {
                        Some(self.auth_key_association(params.auth_key_id).await?)
                    },
                }
            };
            if params.user_id.is_some()
                && let Some(Some(key)) = &associations.auth_key
            {
                associations.user.clone_from(&key.user);
            }
            Ok(PreparedAuthPathRegistration {
                associations,
                params,
                existing: None,
                user_write,
            })
        }
    }

    async fn prepare_headless_registration(
        &self,
        prior: &headscale_db::headscale_nodes::HeadscaleNodeRow,
        params: &headscale_db::headscale_nodes::CreateParams,
        wire: Option<&MachineRecord>,
        auth_key: bool,
        associations: NativeNodeAssociations,
    ) -> Result<PreparedNativeRegistration, MachineAdminError> {
        let (before, loaded) = self.row_to_wire_record_with_association(prior).await?;
        let mut native = NativeNodePersistence::capture(prior, &before)?;
        native.set_associations(loaded);
        prepare_cached_auth_registration(
            native_row_id(prior)?,
            &before,
            Some(&native),
            params,
            wire,
            auth_key,
            associations,
        )
    }

    async fn row_by_slug(
        &self,
        id: &str,
    ) -> Result<headscale_db::headscale_nodes::HeadscaleNodeRow, MachineAdminError> {
        // Only canonical decimal strings are numeric selectors. A stale hex
        // key such as 000...001 must never fall back to database node ID 1.
        if let Ok(node_id) = id.parse::<i64>()
            && node_id > 0
            && node_id.to_string() == id
        {
            return headscale_db::headscale_nodes::get_by_id(&self.pool, node_id)
                .await
                .map_err(|error| db_error_to_machine(error, id));
        }
        let node_key = headscale_api_acl::go_key::PublicKeyKind::Node
            .parse_text(&key_with_prefix("nodekey:", id))
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        // The loaded node-key index already uses typed canonical identities.
        // Resolve it to the primary key before reading SQL; imported uppercase
        // hex must not turn every map write into a normalized text scan.
        if let Some(registry) = &self.wire_registry
            && let Some(existing) = registry.get(&key_without_prefix("nodekey:", &node_key))
            && let Some(node_id) = existing.node_id.and_then(|id| i64::try_from(id).ok())
        {
            let row = headscale_db::headscale_nodes::get_by_id(&self.pool, node_id)
                .await
                .map_err(|error| db_error_to_machine(error, id))?;
            if row.node_key != node_key {
                return Err(MachineAdminError::NotFound(id.into()));
            }
            return Ok(row);
        }
        headscale_db::headscale_nodes::get_by_node_key(&self.pool, &node_key)
            .await
            .map_err(|error| db_error_to_machine(error, id))
    }

    async fn user_id_for_record(
        &self,
        record: &MachineAdminRecord,
    ) -> Result<Option<i64>, MachineAdminError> {
        resolve_record_owner(self.users.as_deref(), record).await
    }

    async fn reject_duplicate_addresses(
        &self,
        current_row_id: Option<i64>,
        record: &MachineAdminRecord,
    ) -> Result<(), MachineAdminError> {
        let ipv4 = (!record.ipv4.trim().is_empty()).then_some(record.ipv4.trim());
        let ipv6 = record
            .ipv6
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if ipv4.is_none() && ipv6.is_none() {
            return Ok(());
        }

        let rows = headscale_db::headscale_nodes::list(&self.pool)
            .await
            .map_err(|e| db_error_to_machine(e, &record.id))?;
        for row in rows {
            if current_row_id == Some(row.id) {
                continue;
            }
            if let Some(candidate) = ipv4
                && row.ipv4.as_deref().map(str::trim) == Some(candidate)
            {
                return Err(MachineAdminError::BadRequest(format!(
                    "IPv4 address {candidate} already in use"
                )));
            }
            if let Some(candidate) = ipv6
                && row.ipv6.as_deref().map(str::trim) == Some(candidate)
            {
                return Err(MachineAdminError::BadRequest(format!(
                    "IPv6 address {candidate} already in use"
                )));
            }
        }
        Ok(())
    }

    async fn user_identity_for_row(
        &self,
        row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> UserIdentity {
        match self.user_identity_for_row_checked(row).await {
            Ok(identity) => identity,
            Err(error) => {
                tracing::error!(%error, "loading node user association");
                let mut identity = unloaded_user_identity(row.user_id);
                identity.association = Some(None);
                identity.login_name.clear();
                identity.display_name.clear();
                identity
            }
        }
    }

    async fn user_identity_for_row_checked(
        &self,
        row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> Result<UserIdentity, MachineAdminError> {
        let loaded = self.loaded_user_association(row.user_id).await?;
        Ok(identity_from_loaded_user(row.user_id, loaded.as_ref()))
    }

    async fn row_to_record(
        &self,
        row: headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> MachineAdminRecord {
        self.row_to_record_using_associations(row, None).await
    }

    async fn row_to_record_using_associations(
        &self,
        row: headscale_db::headscale_nodes::HeadscaleNodeRow,
        captured: Option<&NativeNodeAssociations>,
    ) -> MachineAdminRecord {
        let host_info = row.host_info_value();
        let routes = routes_from_host_info(&host_info);
        let now = Utc::now();
        let expired = row
            .expiry_text
            .as_deref()
            .and_then(precise_stored_timestamp)
            .or_else(|| {
                row.expiry
                    .and_then(|expiry| DateTime::from_timestamp(expiry, 0))
            })
            .is_some_and(|expiry| node_expiry_is_elapsed(expiry, now));
        let name = row.given_name.clone();
        let node_key_hex = key_without_prefix("nodekey:", &row.node_key);
        let live = self.wire_registry.as_ref().and_then(|registry| {
            let record = registry.get(&node_key_hex)?;
            let online = registry
                .online_states()
                .get(&record.stable_node_id())
                .copied()
                .unwrap_or(false);
            Some((online, record.last_seen))
        });
        let user_identity = match captured.and_then(|associations| associations.user.as_ref()) {
            Some(user) => identity_from_loaded_user(row.user_id, user.as_ref()),
            None => self.user_identity_for_row(&row).await,
        };
        MachineAdminRecord {
            node_id: u64::try_from(row.id).unwrap_or_default(),
            id: node_key_hex.clone(),
            name,
            user: user_identity.login_name,
            user_id: user_identity.id,
            auth_key_id: row.auth_key_id,
            ipv4: row.ipv4.clone().unwrap_or_default(),
            ipv6: row.ipv6.clone().filter(|value| !value.is_empty()),
            online: live.as_ref().is_some_and(|(online, _)| *online && !expired),
            last_seen: live.as_ref().map_or_else(
                || row.last_seen.unwrap_or(row.created_at).max(0) as u64,
                |(_, last_seen)| last_seen.timestamp().max(0) as u64,
            ),
            last_seen_precise: live.as_ref().map(|(_, last_seen)| *last_seen).or_else(|| {
                row.last_seen_text
                    .as_deref()
                    .and_then(precise_stored_timestamp)
            }),
            created_at: row.created_at.max(0) as u64,
            created_at_precise: stored_node_created_at(&row),
            expiry: row.expiry.map(|expiry| expiry.max(0) as u64),
            expiry_precise: self
                .wire_registry
                .as_ref()
                .and_then(|registry| registry.get(&node_key_hex))
                .and_then(|record| record.expiry)
                .or_else(|| {
                    row.expiry_text
                        .as_deref()
                        .and_then(precise_stored_timestamp)
                }),
            machine_key_hex: key_without_prefix("mkey:", &row.machine_key),
            disco_key: row.disco_key.clone(),
            os: os_from_host_info(&host_info),
            version: version_from_host_info(&host_info),
            tags: row.tag_list(),
            routes,
            approved_routes: row.approved_route_list(),
            register_method: register_method_from_db(&row.register_method),
            expired,
        }
    }

    async fn row_to_wire_record(
        &self,
        row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> Result<MachineRecord, MachineAdminError> {
        self.row_to_wire_record_with_association(row)
            .await
            .map(|(record, _)| record)
    }

    async fn row_to_wire_record_with_association(
        &self,
        row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> Result<(MachineRecord, NativeNodeAssociations), MachineAdminError> {
        self.row_to_wire_record_using_associations(row, None).await
    }

    async fn row_to_wire_record_using_associations(
        &self,
        row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
        captured: Option<&NativeNodeAssociations>,
    ) -> Result<(MachineRecord, NativeNodeAssociations), MachineAdminError> {
        let host_info = row
            .try_host_info_value()
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        let node_key = key_without_prefix("nodekey:", &row.node_key);
        if node_key.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "persisted node has empty node key".to_string(),
            ));
        }
        let created_at = stored_node_created_at(row).ok_or_else(|| {
            MachineAdminError::BadRequest(format!(
                "persisted node {node_key} has invalid created_at"
            ))
        })?;
        let last_seen = row
            .last_seen_text
            .as_deref()
            .and_then(precise_stored_timestamp)
            .or_else(|| {
                row.last_seen
                    .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
            })
            .unwrap_or(created_at);
        let ipv4 = row
            .ipv4
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value.parse::<Ipv4Addr>().map_err(|e| {
                    MachineAdminError::BadRequest(format!(
                        "persisted node {node_key} has invalid IPv4 '{value}': {e}"
                    ))
                })
            })
            .transpose()?;
        let ipv6 = row
            .ipv6
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| {
                value.parse::<Ipv6Addr>().map_err(|e| {
                    MachineAdminError::BadRequest(format!(
                        "persisted node {node_key} has invalid IPv6 '{value}': {e}"
                    ))
                })
            })
            .transpose()?;
        require_any_address(ipv4, ipv6)?;
        // Preserve a corrupt stored given name for map validation.
        let name = row.given_name.clone();
        let auth_key = match captured.and_then(|associations| associations.auth_key.as_ref()) {
            Some(key) => key.clone(),
            None => self.auth_key_association(row.auth_key_id).await?,
        };
        let ephemeral = auth_key.as_ref().is_some_and(|key| key.ephemeral);
        let user_identity = match captured.and_then(|associations| associations.user.as_ref()) {
            Some(user) => identity_from_loaded_user(row.user_id, user.as_ref()),
            None => self.user_identity_for_row_checked(row).await?,
        };
        let association = NativeNodeAssociations {
            user: user_identity.association.clone(),
            auth_key: Some(auth_key),
        };
        let mut record = MachineRecord::new_at_with_addresses(
            created_at,
            node_key.clone(),
            key_without_prefix("mkey:", &row.machine_key),
            user_identity.login_name.clone(),
            name.clone(),
            ipv4,
            ipv6,
            ephemeral,
        );
        record.node_id = u64::try_from(row.id).ok();
        record.auth_key_id = row.auth_key_id;
        record.set_user_account_metadata(user_identity.provider.clone(), user_identity.created_at);
        record.set_user_identity(
            user_identity.id,
            user_identity.login_name,
            user_identity.display_name,
            user_identity.profile_pic_url,
        );
        record.replace_host_info(host_info_from_value(&host_info)?);
        record.raw_hostname = row.hostname.clone();
        record.hostname = name;
        record.disco_key = (!row.disco_key.is_empty()).then_some(row.disco_key.clone());
        record.endpoints = row
            .try_endpoint_list()
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        record.home_derp = preferred_derp_from_host_info(&host_info);
        record.expiry = row
            .expiry_text
            .as_deref()
            .and_then(precise_stored_timestamp)
            .or(row
                .expiry
                .map(|expiry| unix_timestamp_for_record(expiry.max(0) as u64, &node_key, "expiry"))
                .transpose()?);
        record.last_seen = last_seen;
        record.forced_tags = row
            .try_tag_list()
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        record.approved_routes = row
            .try_approved_route_list()
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        record.register_method = register_method_from_db(&row.register_method);
        Ok((record, association))
    }

    // Capture nullable native values only when this row is being published.
    // Read-only wire projections must not refresh the NodeStore's baseline.
    async fn row_to_wire_record_for_publication(
        &self,
        row: headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> Result<MachineRecord, MachineAdminError> {
        let (record, association) = self.row_to_wire_record_with_association(&row).await?;
        if let Some(registry) = &self.wire_registry {
            stage_native_row(registry, &row, &record, association)?;
        }
        Ok(record)
    }

    async fn sync_wire_row(
        &self,
        row: headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> Result<(), MachineAdminError> {
        let Some(registry) = &self.wire_registry else {
            return Ok(());
        };
        let record = self.row_to_wire_record_for_publication(row).await?;
        registry
            .publish_saved_admin_record(record)
            .map_err(MachineAdminError::Policy)?;
        Ok(())
    }
}

#[cfg(feature = "postgres-sqlx")]
impl PersistentPostgresMachineAdmin {
    async fn lock_existing_node(
        &self,
        id: &str,
    ) -> Result<
        (
            Option<tokio::sync::OwnedMutexGuard<()>>,
            headscale_db::headscale_nodes::HeadscaleNodeRow,
        ),
        MachineAdminError,
    > {
        let row = self.row_by_slug(id).await?;
        let Some(registry) = &self.wire_registry else {
            return Ok((None, row));
        };
        let machine_key = key_without_prefix("mkey:", &row.machine_key);
        let guard = registry.lock_registration(&machine_key).await;
        // Resolve by stable database ID again: the node key may have rotated
        // while this operation waited behind registration.
        let row = headscale_db::headscale_nodes::get_postgres_by_id(&self.pool, row.id)
            .await
            .map_err(|error| db_error_to_machine(error, id))?;
        Ok((Some(guard), row))
    }

    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            users: None,
            wire_registry: None,
        }
    }

    pub fn with_user_admin(mut self, users: Arc<dyn UserAdmin>) -> Self {
        self.users = Some(users);
        self
    }

    pub fn with_wire_registry(mut self, registry: Arc<MachineRegistry>) -> Self {
        registry.require_native_policy_persistence();
        self.wire_registry = Some(registry);
        self
    }

    async fn registration_user_association(
        &self,
        raw_id: Option<i64>,
        captured: Option<&super::users::UserRegistrationSnapshot>,
    ) -> Result<RegistrationUserAssociation, MachineAdminError> {
        let Some(id) = raw_id else {
            return Ok((Some(None), None));
        };
        if let Some(user) = captured {
            return Ok((Some(Some(user.user.clone())), user.write.clone()));
        }
        let write = headscale_db::users::get_postgres_for_registration(&self.pool, id)
            .await
            .map_err(|error| {
                let message = match error {
                    headscale_db::DbError::NotFound(_) => "user not found".to_string(),
                    error => error.headscale_go_message(),
                };
                MachineAdminError::Storage(format!("finding user: {message}"))
            })?;
        let user = super::users::PersistentUserAdmin::row_to_association_record(write.row.clone());
        Ok((Some(Some(user)), Some(write)))
    }

    async fn loaded_user_association(
        &self,
        raw_id: Option<i64>,
    ) -> Result<Option<UserRecord>, MachineAdminError> {
        let Some(id) = raw_id else {
            return Ok(None);
        };
        if id < 0 {
            return Err(MachineAdminError::Storage(
                "invalid stored user identity".into(),
            ));
        }
        match headscale_db::users::get_postgres_by_id(&self.pool, id).await {
            Ok(row) => Ok(Some(
                super::users::PersistentUserAdmin::row_to_association_record(row),
            )),
            Err(headscale_db::DbError::NotFound(_)) => Ok(None),
            Err(error) => Err(MachineAdminError::Storage(format!(
                "loading node user association: {}",
                error.headscale_go_message(),
            ))),
        }
    }

    async fn auth_key_association(
        &self,
        auth_key_id: Option<i64>,
    ) -> Result<Option<NativeAuthKey>, MachineAdminError> {
        let Some(id) = auth_key_id else {
            return Ok(None);
        };
        if id < 0 {
            return Err(MachineAdminError::Storage(
                "invalid stored preauth key identity".into(),
            ));
        }
        let row = match headscale_db::preauth_keys::get_postgres_by_id(&self.pool, id).await {
            Ok(row) => row,
            Err(headscale_db::DbError::NotFound(_)) => return Ok(None),
            Err(error) => {
                return Err(MachineAdminError::Storage(format!(
                    "loading node preauth key: {}",
                    error.headscale_go_message()
                )));
            }
        };
        let user_id = if row.user_id.is_empty() {
            None
        } else {
            Some(row.user_id.parse::<i64>().map_err(|_| {
                MachineAdminError::Storage("invalid stored preauth key user identity".into())
            })?)
        };
        let user = self.loaded_user_association(user_id).await?;
        NativeAuthKey::from_row(&row, Some(user)).map(Some)
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub async fn hydrate_wire_registry(
        &self,
        registry: &MachineRegistry,
    ) -> Result<usize, MachineAdminError> {
        let rows = headscale_db::headscale_nodes::list_postgres(&self.pool)
            .await
            .map_err(|error| MachineAdminError::Storage(error.headscale_go_message()))?;
        let mut hydrated = 0usize;
        for row in rows {
            let (wire, association) = self.row_to_wire_record_with_association(&row).await?;
            stage_native_row(registry, &row, &wire, association)?;
            registry.upsert(wire.node_key_hex.clone(), wire);
            hydrated += 1;
        }
        Ok(hydrated)
    }

    pub async fn create_or_update_auth_path(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.create_or_update_auth_path_inner(record, policy, None, None, true, None)
            .await
    }

    pub async fn create_or_update_auth_key_path(
        &self,
        record: MachineRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        let wire_record = record;
        let mut record = machine_admin_record_from_wire(&wire_record);
        record.register_method = REGISTER_METHOD_AUTH_KEY;
        self.create_or_update_auth_path_inner(
            record,
            policy,
            auth_key_id,
            auth_key_owner_override(&wire_record)?,
            false,
            Some(&wire_record),
        )
        .await
    }

    async fn create_or_update_auth_path_inner(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
        user_id_override: Option<i64>,
        validate_requested_tags: bool,
        wire_record: Option<&MachineRecord>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.create_or_update_auth_path_with_hostinfo(
            record,
            policy,
            auth_key_id,
            user_id_override,
            validate_requested_tags,
            wire_record,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_or_update_auth_path_with_hostinfo(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
        user_id_override: Option<i64>,
        validate_requested_tags: bool,
        wire_record: Option<&MachineRecord>,
        hostinfo: Option<Value>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.create_or_update_auth_path_with_user_snapshot(
            record,
            policy,
            auth_key_id,
            user_id_override,
            validate_requested_tags,
            wire_record,
            hostinfo,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_or_update_auth_path_with_user_snapshot(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
        user_id_override: Option<i64>,
        validate_requested_tags: bool,
        wire_record: Option<&MachineRecord>,
        hostinfo: Option<Value>,
        captured_user: Option<&super::users::UserRegistrationSnapshot>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        let subject = record.id.clone();
        let mut plan = Box::pin(self.prepare_auth_path_registration(
            record,
            policy,
            auth_key_id,
            user_id_override,
            validate_requested_tags,
            wire_record,
            None,
            captured_user,
        ))
        .await?;
        apply_registration_hostinfo(&mut plan.params, hostinfo.as_ref())?;
        if let (Some(registry), Some(prior)) = (&self.wire_registry, plan.existing.as_ref()) {
            // Batch wait first, lock second: the live edit goes through the
            // NodeStore writer like Go's UpdateNode, so concurrent registrations
            // share one batch. The save lock covers only the SQL write.
            let live = Box::pin(LiveRegistrationSave::begin(
                registry,
                prior,
                &plan.params,
                wire_record,
                !validate_requested_tags,
                plan.associations.clone(),
            ))
            .await?;
            let _persist = registry.lock_native_persistence().await;
            if let Err(error) = headscale_db::headscale_nodes::save_postgres_cached_registration(
                &self.pool,
                live.registration.clone(),
            )
            .await
            {
                if !validate_requested_tags {
                    live.rollback(registry).await?;
                }
                return Err(db_error_to_machine(error, &subject));
            }
            let previous_key = live.update.before.node_key_hex.clone();
            let record = live.finish(registry);
            return Ok(AuthPathRegistrationResult {
                new_node: false,
                replaced_node_key_hex: (previous_key != record.node_key_hex)
                    .then_some(previous_key),
                record: machine_admin_record_from_wire(&record),
            });
        }
        if let Some(prior) = plan.existing.as_ref() {
            let prepared = self
                .prepare_headless_registration(
                    prior,
                    &plan.params,
                    wire_record,
                    !validate_requested_tags,
                    plan.associations.clone(),
                )
                .await?;
            headscale_db::headscale_nodes::save_postgres_cached_registration(
                &self.pool,
                prepared.registration,
            )
            .await
            .map_err(|error| {
                MachineAdminError::Storage(format!(
                    "writing node to database: saving node: {}",
                    error.headscale_go_message(),
                ))
            })?;
            let record = machine_admin_record_from_wire(&prepared.record);
            let previous_key = key_without_prefix("nodekey:", &prior.node_key);
            return Ok(AuthPathRegistrationResult {
                replaced_node_key_hex: (previous_key != record.id).then_some(previous_key),
                record,
                new_node: false,
            });
        }
        let node = new_native_registration(&plan.params)?;
        let material = plan
            .user_write
            .take()
            .map(|user| headscale_db::headscale_nodes::NewNodeAssociations::User(Box::new(user)))
            .unwrap_or_default();
        let saved =
            headscale_db::headscale_nodes::create_postgres_new_registration_with_associations(
                &self.pool, node, material,
            )
            .await
            .map_err(|error| {
                MachineAdminError::Storage(format!(
                    "creating new node: {}",
                    error.headscale_go_message()
                ))
            })?;
        apply_new_association_projection(&mut plan.associations, &saved.node, &saved.associations)?;
        let row = saved.node;
        let record = match wire_record {
            Some(record) => record.clone(),
            None => {
                self.row_to_wire_record_using_associations(&row, Some(&plan.associations))
                    .await?
                    .0
            }
        };
        let record = Box::pin(finish_new_native_registration(
            self.wire_registry.as_deref(),
            &row,
            record,
            !validate_requested_tags,
            plan.associations.clone(),
        ))
        .await?;
        Ok(AuthPathRegistrationResult {
            record: machine_admin_record_from_wire(&record),
            new_node: true,
            replaced_node_key_hex: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn prepare_auth_path_registration(
        &self,
        mut record: MachineAdminRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
        user_id_override: Option<i64>,
        validate_requested_tags: bool,
        wire_record: Option<&MachineRecord>,
        credential: Option<&NativeAuthKey>,
        captured_user: Option<&super::users::UserRegistrationSnapshot>,
    ) -> Result<PreparedAuthPathRegistration, MachineAdminError> {
        if record.id.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "node key must not be empty".into(),
            ));
        }
        let ipv4 = optional_ipv4(&record.ipv4)?;
        let ipv6 = optional_ipv6(record.ipv6.as_deref())?;
        require_any_address(ipv4, ipv6)?;
        let user_id = if let Some(credential) = credential {
            credential
                .user
                .as_ref()
                .and_then(Option::as_ref)
                .map(|user| i64::try_from(user.id))
                .transpose()
                .map_err(|_| MachineAdminError::BadRequest("user id out of range".into()))?
        } else if let Some(user) = captured_user {
            Some(
                i64::try_from(user.user.id)
                    .map_err(|_| MachineAdminError::BadRequest("user id out of range".into()))?,
            )
        } else {
            match user_id_override {
                Some(user_id) => Some(user_id),
                None => self.user_id_for_record(&record).await?,
            }
        };
        if let Some(registry) = &self.wire_registry {
            registry
                .validate_registration_node_key(&record.id, &record.machine_key_hex)
                .map_err(|error| MachineAdminError::BadRequest(error.into()))?;
        }
        let machine_key = key_with_prefix("mkey:", &record.machine_key_hex);
        let candidates = if let Some(registry) = &self.wire_registry {
            registration_rows_from_cache(registry, &record.machine_key_hex)?
        } else {
            headscale_db::headscale_nodes::list_postgres_by_machine_key(&self.pool, &machine_key)
                .await
                .map_err(|error| db_error_to_machine(error, &record.id))?
        };
        // A different user's node on the same machine is a fresh identity.
        // Go carries only its NetInfo into that new node when the request
        // omitted it; ownership, addresses and routes must not carry over.
        let previous_net_info = if let Some(node) = candidates.iter().find(|node| {
            node.tag_list().is_empty() && node.user_id.is_some() && node.user_id != user_id
        }) {
            node.try_host_info_value()
                .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?
                .get("NetInfo")
                .cloned()
        } else {
            None
        };
        let existing = select_auth_path_node(
            candidates,
            user_id,
            self.users.is_none() && credential.is_none(),
            !validate_requested_tags,
            !record.tags.is_empty(),
        )?;

        if validate_requested_tags && !record.tags.is_empty() {
            record.user_id = user_id.and_then(|id| u64::try_from(id).ok());
            let existing_record = match &existing {
                Some(existing) => Some(self.row_to_record(existing.clone()).await),
                None => None,
            };
            let nodes = self.policy_nodes_for_registration().await?;
            validate_auth_path_tags_with_nodes(
                policy,
                &mut record,
                existing_record.as_ref(),
                &nodes,
            )
            .map_err(MachineAdminError::BadRequest)?;
        }

        if let Some(existing) = existing {
            if let Some(ipv4) = existing.ipv4.as_ref().filter(|value| !value.is_empty()) {
                record.ipv4.clone_from(ipv4);
            }
            if let Some(ipv6) = existing.ipv6.as_ref().filter(|value| !value.is_empty()) {
                record.ipv6 = Some(ipv6.clone());
            }
            record.approved_routes = existing
                .try_approved_route_list()
                .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;

            let mut params = create_params_for_auth_path(
                &record,
                wire_record,
                user_id,
                auth_key_id,
                Some(&existing),
            )?;
            finalize_auth_path_clock(&mut params, self.wire_registry.as_deref());
            let mut associations = if let Some(key) = credential {
                if params.auth_key_id.and_then(|id| u64::try_from(id).ok()) != Some(key.id) {
                    return Err(MachineAdminError::BadRequest(
                        "preauth key identity changed during registration".into(),
                    ));
                }
                NativeNodeAssociations {
                    user: Some(None),
                    auth_key: Some(Some(key.clone())),
                }
            } else {
                NativeNodeAssociations {
                    user: self
                        .registration_user_association(params.user_id, captured_user)
                        .await?
                        .0,
                    auth_key: if validate_requested_tags {
                        None
                    } else {
                        Some(self.auth_key_association(params.auth_key_id).await?)
                    },
                }
            };
            if params.user_id.is_some()
                && let Some(Some(key)) = &associations.auth_key
            {
                associations.user.clone_from(&key.user);
            }
            Ok(PreparedAuthPathRegistration {
                associations,
                params,
                existing: Some(existing),
                user_write: None,
            })
        } else {
            record.approved_routes.clear();
            let mut params =
                create_params_for_auth_path(&record, wire_record, user_id, auth_key_id, None)?;
            if let Some(net_info) = previous_net_info
                && params.host_info.get("NetInfo").is_none_or(Value::is_null)
            {
                params.host_info["NetInfo"] = net_info;
            }
            finalize_auth_path_clock(&mut params, self.wire_registry.as_deref());
            let (user, user_write) = if credential.is_some() {
                (Some(None), None)
            } else {
                self.registration_user_association(params.user_id, captured_user)
                    .await?
            };
            let mut associations = if let Some(key) = credential {
                if params.auth_key_id.and_then(|id| u64::try_from(id).ok()) != Some(key.id) {
                    return Err(MachineAdminError::BadRequest(
                        "preauth key identity changed during registration".into(),
                    ));
                }
                NativeNodeAssociations {
                    user: Some(None),
                    auth_key: Some(Some(key.clone())),
                }
            } else {
                NativeNodeAssociations {
                    user,
                    auth_key: if validate_requested_tags {
                        None
                    } else {
                        Some(self.auth_key_association(params.auth_key_id).await?)
                    },
                }
            };
            if params.user_id.is_some()
                && let Some(Some(key)) = &associations.auth_key
            {
                associations.user.clone_from(&key.user);
            }
            Ok(PreparedAuthPathRegistration {
                associations,
                params,
                existing: None,
                user_write,
            })
        }
    }

    async fn prepare_headless_registration(
        &self,
        prior: &headscale_db::headscale_nodes::HeadscaleNodeRow,
        params: &headscale_db::headscale_nodes::CreateParams,
        wire: Option<&MachineRecord>,
        auth_key: bool,
        associations: NativeNodeAssociations,
    ) -> Result<PreparedNativeRegistration, MachineAdminError> {
        let (before, loaded) = self.row_to_wire_record_with_association(prior).await?;
        let mut native = NativeNodePersistence::capture(prior, &before)?;
        native.set_associations(loaded);
        prepare_cached_auth_registration(
            native_row_id(prior)?,
            &before,
            Some(&native),
            params,
            wire,
            auth_key,
            associations,
        )
    }

    async fn row_by_slug(
        &self,
        id: &str,
    ) -> Result<headscale_db::headscale_nodes::HeadscaleNodeRow, MachineAdminError> {
        // Only canonical decimal strings are numeric selectors. A stale hex
        // key such as 000...001 must never fall back to database node ID 1.
        if let Ok(node_id) = id.parse::<i64>()
            && node_id > 0
            && node_id.to_string() == id
        {
            return headscale_db::headscale_nodes::get_postgres_by_id(&self.pool, node_id)
                .await
                .map_err(|error| db_error_to_machine(error, id));
        }
        let node_key = headscale_api_acl::go_key::PublicKeyKind::Node
            .parse_text(&key_with_prefix("nodekey:", id))
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        // The loaded node-key index already uses typed canonical identities.
        // Resolve it to the primary key before reading SQL; imported uppercase
        // hex must not turn every map write into a normalized text scan.
        if let Some(registry) = &self.wire_registry
            && let Some(existing) = registry.get(&key_without_prefix("nodekey:", &node_key))
            && let Some(node_id) = existing.node_id.and_then(|id| i64::try_from(id).ok())
        {
            let row = headscale_db::headscale_nodes::get_postgres_by_id(&self.pool, node_id)
                .await
                .map_err(|error| db_error_to_machine(error, id))?;
            if row.node_key != node_key {
                return Err(MachineAdminError::NotFound(id.into()));
            }
            return Ok(row);
        }
        headscale_db::headscale_nodes::get_postgres_by_node_key(&self.pool, &node_key)
            .await
            .map_err(|error| db_error_to_machine(error, id))
    }

    async fn user_id_for_record(
        &self,
        record: &MachineAdminRecord,
    ) -> Result<Option<i64>, MachineAdminError> {
        resolve_record_owner(self.users.as_deref(), record).await
    }

    async fn reject_duplicate_addresses(
        &self,
        current_row_id: Option<i64>,
        record: &MachineAdminRecord,
    ) -> Result<(), MachineAdminError> {
        let ipv4 = (!record.ipv4.trim().is_empty()).then_some(record.ipv4.trim());
        let ipv6 = record
            .ipv6
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if ipv4.is_none() && ipv6.is_none() {
            return Ok(());
        }

        let rows = headscale_db::headscale_nodes::list_postgres(&self.pool)
            .await
            .map_err(|e| db_error_to_machine(e, &record.id))?;
        for row in rows {
            if current_row_id == Some(row.id) {
                continue;
            }
            if let Some(candidate) = ipv4
                && row.ipv4.as_deref().map(str::trim) == Some(candidate)
            {
                return Err(MachineAdminError::BadRequest(format!(
                    "IPv4 address {candidate} already in use"
                )));
            }
            if let Some(candidate) = ipv6
                && row.ipv6.as_deref().map(str::trim) == Some(candidate)
            {
                return Err(MachineAdminError::BadRequest(format!(
                    "IPv6 address {candidate} already in use"
                )));
            }
        }
        Ok(())
    }

    async fn user_identity_for_row(
        &self,
        row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> UserIdentity {
        match self.user_identity_for_row_checked(row).await {
            Ok(identity) => identity,
            Err(error) => {
                tracing::error!(%error, "loading node user association");
                let mut identity = unloaded_user_identity(row.user_id);
                identity.association = Some(None);
                identity.login_name.clear();
                identity.display_name.clear();
                identity
            }
        }
    }

    async fn user_identity_for_row_checked(
        &self,
        row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> Result<UserIdentity, MachineAdminError> {
        let loaded = self.loaded_user_association(row.user_id).await?;
        Ok(identity_from_loaded_user(row.user_id, loaded.as_ref()))
    }

    async fn row_to_record(
        &self,
        row: headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> MachineAdminRecord {
        self.row_to_record_using_associations(row, None).await
    }

    async fn row_to_record_using_associations(
        &self,
        row: headscale_db::headscale_nodes::HeadscaleNodeRow,
        captured: Option<&NativeNodeAssociations>,
    ) -> MachineAdminRecord {
        let host_info = row.host_info_value();
        let routes = routes_from_host_info(&host_info);
        let now = Utc::now();
        let expired = row
            .expiry_text
            .as_deref()
            .and_then(precise_stored_timestamp)
            .or_else(|| {
                row.expiry
                    .and_then(|expiry| DateTime::from_timestamp(expiry, 0))
            })
            .is_some_and(|expiry| node_expiry_is_elapsed(expiry, now));
        let name = row.given_name.clone();
        let node_key_hex = key_without_prefix("nodekey:", &row.node_key);
        let live = self.wire_registry.as_ref().and_then(|registry| {
            let record = registry.get(&node_key_hex)?;
            let online = registry
                .online_states()
                .get(&record.stable_node_id())
                .copied()
                .unwrap_or(false);
            Some((online, record.last_seen))
        });
        let user_identity = match captured.and_then(|associations| associations.user.as_ref()) {
            Some(user) => identity_from_loaded_user(row.user_id, user.as_ref()),
            None => self.user_identity_for_row(&row).await,
        };
        MachineAdminRecord {
            node_id: u64::try_from(row.id).unwrap_or_default(),
            id: node_key_hex.clone(),
            name,
            user: user_identity.login_name,
            user_id: user_identity.id,
            auth_key_id: row.auth_key_id,
            ipv4: row.ipv4.clone().unwrap_or_default(),
            ipv6: row.ipv6.clone().filter(|value| !value.is_empty()),
            online: live.as_ref().is_some_and(|(online, _)| *online && !expired),
            last_seen: live.as_ref().map_or_else(
                || row.last_seen.unwrap_or(row.created_at).max(0) as u64,
                |(_, last_seen)| last_seen.timestamp().max(0) as u64,
            ),
            last_seen_precise: live.as_ref().map(|(_, last_seen)| *last_seen).or_else(|| {
                row.last_seen_text
                    .as_deref()
                    .and_then(precise_stored_timestamp)
            }),
            created_at: row.created_at.max(0) as u64,
            created_at_precise: stored_node_created_at(&row),
            expiry: row.expiry.map(|expiry| expiry.max(0) as u64),
            expiry_precise: self
                .wire_registry
                .as_ref()
                .and_then(|registry| registry.get(&node_key_hex))
                .and_then(|record| record.expiry)
                .or_else(|| {
                    row.expiry_text
                        .as_deref()
                        .and_then(precise_stored_timestamp)
                }),
            machine_key_hex: key_without_prefix("mkey:", &row.machine_key),
            disco_key: row.disco_key.clone(),
            os: os_from_host_info(&host_info),
            version: version_from_host_info(&host_info),
            tags: row.tag_list(),
            routes,
            approved_routes: row.approved_route_list(),
            register_method: register_method_from_db(&row.register_method),
            expired,
        }
    }

    async fn row_to_wire_record(
        &self,
        row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> Result<MachineRecord, MachineAdminError> {
        self.row_to_wire_record_with_association(row)
            .await
            .map(|(record, _)| record)
    }

    async fn row_to_wire_record_with_association(
        &self,
        row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> Result<(MachineRecord, NativeNodeAssociations), MachineAdminError> {
        self.row_to_wire_record_using_associations(row, None).await
    }

    async fn row_to_wire_record_using_associations(
        &self,
        row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
        captured: Option<&NativeNodeAssociations>,
    ) -> Result<(MachineRecord, NativeNodeAssociations), MachineAdminError> {
        let host_info = row
            .try_host_info_value()
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        let node_key = key_without_prefix("nodekey:", &row.node_key);
        if node_key.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "persisted node has empty node key".to_string(),
            ));
        }
        let created_at = stored_node_created_at(row).ok_or_else(|| {
            MachineAdminError::BadRequest(format!(
                "persisted node {node_key} has invalid created_at"
            ))
        })?;
        let last_seen = row
            .last_seen_text
            .as_deref()
            .and_then(precise_stored_timestamp)
            .or_else(|| {
                row.last_seen
                    .and_then(|seconds| DateTime::from_timestamp(seconds, 0))
            })
            .unwrap_or(created_at);
        let ipv4 = row
            .ipv4
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .map(|value| {
                value.parse::<Ipv4Addr>().map_err(|e| {
                    MachineAdminError::BadRequest(format!(
                        "persisted node {node_key} has invalid IPv4 '{value}': {e}"
                    ))
                })
            })
            .transpose()?;
        let ipv6 = row
            .ipv6
            .as_deref()
            .filter(|value| !value.is_empty())
            .map(|value| {
                value.parse::<Ipv6Addr>().map_err(|e| {
                    MachineAdminError::BadRequest(format!(
                        "persisted node {node_key} has invalid IPv6 '{value}': {e}"
                    ))
                })
            })
            .transpose()?;
        require_any_address(ipv4, ipv6)?;
        // Preserve a corrupt stored given name for map validation.
        let name = row.given_name.clone();
        let auth_key = match captured.and_then(|associations| associations.auth_key.as_ref()) {
            Some(key) => key.clone(),
            None => self.auth_key_association(row.auth_key_id).await?,
        };
        let ephemeral = auth_key.as_ref().is_some_and(|key| key.ephemeral);
        let user_identity = match captured.and_then(|associations| associations.user.as_ref()) {
            Some(user) => identity_from_loaded_user(row.user_id, user.as_ref()),
            None => self.user_identity_for_row_checked(row).await?,
        };
        let association = NativeNodeAssociations {
            user: user_identity.association.clone(),
            auth_key: Some(auth_key),
        };
        let mut record = MachineRecord::new_at_with_addresses(
            created_at,
            node_key.clone(),
            key_without_prefix("mkey:", &row.machine_key),
            user_identity.login_name.clone(),
            name.clone(),
            ipv4,
            ipv6,
            ephemeral,
        );
        record.node_id = u64::try_from(row.id).ok();
        record.auth_key_id = row.auth_key_id;
        record.set_user_account_metadata(user_identity.provider.clone(), user_identity.created_at);
        record.set_user_identity(
            user_identity.id,
            user_identity.login_name,
            user_identity.display_name,
            user_identity.profile_pic_url,
        );
        record.replace_host_info(host_info_from_value(&host_info)?);
        record.raw_hostname = row.hostname.clone();
        record.hostname = name;
        record.disco_key = (!row.disco_key.is_empty()).then_some(row.disco_key.clone());
        record.endpoints = row
            .try_endpoint_list()
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        record.home_derp = preferred_derp_from_host_info(&host_info);
        record.expiry = row
            .expiry_text
            .as_deref()
            .and_then(precise_stored_timestamp)
            .or(row
                .expiry
                .map(|expiry| unix_timestamp_for_record(expiry.max(0) as u64, &node_key, "expiry"))
                .transpose()?);
        record.last_seen = last_seen;
        record.forced_tags = row
            .try_tag_list()
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        record.approved_routes = row
            .try_approved_route_list()
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        record.register_method = register_method_from_db(&row.register_method);
        Ok((record, association))
    }

    // Capture nullable native values only when this row is being published.
    // Read-only wire projections must not refresh the NodeStore's baseline.
    async fn row_to_wire_record_for_publication(
        &self,
        row: headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> Result<MachineRecord, MachineAdminError> {
        let (record, association) = self.row_to_wire_record_with_association(&row).await?;
        if let Some(registry) = &self.wire_registry {
            stage_native_row(registry, &row, &record, association)?;
        }
        Ok(record)
    }

    async fn sync_wire_row(
        &self,
        row: headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> Result<(), MachineAdminError> {
        let Some(registry) = &self.wire_registry else {
            return Ok(());
        };
        let record = self.row_to_wire_record_for_publication(row).await?;
        registry
            .publish_saved_admin_record(record)
            .map_err(MachineAdminError::Policy)?;
        Ok(())
    }
}

#[async_trait]
impl crate::oidc::OidcRegistrationHandler for PersistentOidcRegistrationHandler {
    async fn complete_oidc_registration(
        &self,
        registration_id: &str,
        user: &crate::oidc::OidcStoredUser,
        node_expiry: Option<DateTime<Utc>>,
    ) -> Result<crate::oidc::OidcRegistrationResult, crate::oidc::OidcRegistrationError> {
        let (mut pending, hostinfo, completion) = self
            .registration_cache
            .pending_registration_completion(registration_id)
            .ok_or(crate::oidc::OidcRegistrationError::SessionExpired)?;
        let handler = Self::clone(self);
        let selected_user_id = user.id;
        crate::tailscale_wire::complete_state_mutation(Box::pin(async move {
            let user_id = i64::try_from(selected_user_id).map_err(|_| {
                crate::oidc::OidcRegistrationError::Store(
                    "finding user: user id out of range".into(),
                )
            })?;
            let write = headscale_db::users::get_for_registration(&handler.machines.pool, user_id)
                .await
                .map_err(|error| {
                    let message = match error {
                        headscale_db::DbError::NotFound(_) => "user not found".to_string(),
                        error => error.headscale_go_message(),
                    };
                    crate::oidc::OidcRegistrationError::Store(format!("finding user: {message}"))
                })?;
            let captured_user = super::users::UserRegistrationSnapshot::from_native(write);
            let user = &captured_user.user;
            let machine_key = pending.machine_key_hex.clone();
            let node_key = pending.node_key_hex.clone();
            let registration_lock = match handler.machines.registration_guard(&machine_key).await {
                Some(guard) => Some(guard),
                None => match &handler.wire_registry {
                    Some(registry) => Some(registry.lock_registration(&machine_key).await),
                    None => None,
                },
            };
            let node_key_lock = match handler
                .machines
                .node_key_registration_guard(&node_key)
                .await
            {
                Some(guard) => Some(guard),
                None => match &handler.wire_registry {
                    Some(registry) => Some(registry.lock_node_key_registration(&node_key).await),
                    None => None,
                },
            };
            let publication_scope = handler
                .machines
                .wire_registry
                .as_ref()
                .or(handler.wire_registry.as_ref())
                .map(|registry| registry.registration_publication_scope(&pending));
            let identity = user_identity_from_record(user);
            pending.set_user_identity(
                Some(user.id),
                identity.login_name,
                identity.display_name,
                identity.profile_pic_url,
            );
            pending.set_user_account_metadata(identity.provider, identity.created_at);
            let mut record = machine_admin_record_from_wire(&pending);
            record.user = user_login_name(user);
            let effective_expiry = if pending.forced_tags.is_empty() {
                node_expiry.or(pending.expiry)
            } else {
                None
            };
            record.expiry = effective_expiry.map(|expiry| expiry.timestamp().max(0) as u64);
            record.expiry_precise = effective_expiry;
            record.register_method = REGISTER_METHOD_OIDC;
            prepare_auth_path_addresses(
                handler.machines.as_ref(),
                handler.ip_allocator.as_deref(),
                &handler.policy,
                &mut record,
            )
            .await
            .map_err(|error| crate::oidc::OidcRegistrationError::Store(error.to_string()))?;

            let result = handler
                .machines
                .create_or_update_auth_path_with_user_snapshot(
                    record,
                    &handler.policy,
                    None,
                    Some(user_id),
                    true,
                    Some(&pending),
                    hostinfo,
                    Some(&captured_user),
                )
                .await
                .map_err(|err| crate::oidc::OidcRegistrationError::Store(err.to_string()))?;
            let mut wire_record = handler
                .machines
                .wire_record_for_publication(&result.record.id, handler.wire_registry.as_deref())
                .await
                .map_err(|error| crate::oidc::OidcRegistrationError::Store(error.to_string()))?
                .ok_or_else(|| {
                    crate::oidc::OidcRegistrationError::Store("registered node disappeared".into())
                })?;
            hydrate_wire_owner_from_user_admin(
                handler.machines.users.as_ref(),
                handler.wire_registry.as_deref(),
                user.id,
                &mut wire_record,
            )
            .await;
            if let Some(registry) = &handler.wire_registry {
                if let Some(old_node_key_hex) = result.replaced_node_key_hex.as_deref() {
                    registry
                        .try_replace_node_key_auth_completion(
                            old_node_key_hex,
                            wire_record.node_key_hex.clone(),
                            wire_record.clone(),
                        )
                        .await
                        .map_err(crate::oidc::OidcRegistrationError::Store)?;
                } else {
                    registry
                        .try_upsert_auth_completion(
                            wire_record.node_key_hex.clone(),
                            wire_record.clone(),
                        )
                        .await
                        .map_err(crate::oidc::OidcRegistrationError::Store)?;
                }
            }
            handler
                .registration_cache
                .finish_registration(completion, wire_record);
            // Go's HandleNodeFromAuthPath releases the machine-key lock on
            // return; the approval below takes the same locks again.
            drop(publication_scope);
            drop(node_key_lock);
            drop(registration_lock);
            // oidc.go handleRegistration: the node is now persisted and known
            // to the policy manager, so State.AutoApproveRoutes can match the
            // owner's addresses against the autoApprovers. Its change (a
            // PolicyChange) follows the registration's own.
            Box::pin(auto_approve_registered_node(
                handler.machines.as_ref(),
                &handler.policy,
                handler.wire_registry.as_deref(),
                &result.record,
            ))
            .await
            .map_err(|error| {
                crate::oidc::OidcRegistrationError::Store(format!("auto approving routes: {error}"))
            })?;
            Ok(crate::oidc::OidcRegistrationResult {
                new_node: result.new_node,
            })
        }))
        .await
        .map_err(|error| {
            crate::oidc::OidcRegistrationError::Store(format!(
                "finishing node registration: {error}"
            ))
        })?
    }

    async fn complete_oidc_auth_request(
        &self,
        auth_id: &str,
        user: &crate::oidc::OidcStoredUser,
    ) -> Result<(), crate::oidc::OidcAuthError> {
        let Some(binding) = self.registration_cache.ssh_binding(auth_id) else {
            if self.registration_cache.get(auth_id).is_some() {
                return Err(crate::oidc::OidcAuthError::NotSshCheck);
            }
            return Err(crate::oidc::OidcAuthError::SessionExpired);
        };
        let src_node_id = i64::try_from(binding.src_node_id)
            .map_err(|_| crate::oidc::OidcAuthError::Store("src node id out of range".into()))?;
        let source = match headscale_db::headscale_nodes::get_by_id(
            &self.machines.pool,
            src_node_id,
        )
        .await
        {
            Ok(row) => row,
            Err(headscale_db::DbError::NotFound(_)) => {
                return Err(crate::oidc::OidcAuthError::SourceNodeMissing);
            }
            Err(err) => return Err(crate::oidc::OidcAuthError::Store(err.to_string())),
        };

        if !source.tag_list().is_empty() || source.user_id.is_none() {
            return Err(crate::oidc::OidcAuthError::SourceNodeNoUserOwner);
        }
        let user_id = i64::try_from(user.id)
            .map_err(|_| crate::oidc::OidcAuthError::Store("OIDC user id out of range".into()))?;
        if source.user_id != Some(user_id) {
            return Err(crate::oidc::OidcAuthError::UserNotSourceOwner);
        }

        if self.registration_cache.approve_without_node(auth_id) {
            Ok(())
        } else {
            Err(crate::oidc::OidcAuthError::SessionExpired)
        }
    }

    fn oidc_registration_exists(&self, registration_id: &str) -> bool {
        matches!(
            self.registration_cache.auth_request_kind(registration_id),
            Some(AuthRequestKind::Registration)
        )
    }

    fn oidc_auth_request_kind(&self, auth_id: &str) -> Option<crate::oidc::OidcAuthRequestKind> {
        match self.registration_cache.auth_request_kind(auth_id)? {
            AuthRequestKind::Registration => Some(crate::oidc::OidcAuthRequestKind::Registration),
            AuthRequestKind::SshCheck(_) => Some(crate::oidc::OidcAuthRequestKind::SshCheck),
        }
    }

    fn oidc_registration_confirmation_info(
        &self,
        registration_id: &str,
    ) -> Option<crate::oidc::OidcRegistrationConfirmInfo> {
        let record = self.registration_cache.get(registration_id)?;
        Some(crate::oidc::OidcRegistrationConfirmInfo {
            hostname: record.hostname,
            os: record.os,
            machine_key: short_oidc_machine_key(&record.machine_key_hex),
        })
    }

    fn store_oidc_registration_confirmation(
        &self,
        pending: crate::oidc::OidcPendingRegistrationConfirmation,
    ) -> bool {
        let registration_id = pending.registration_id.clone();
        self.registration_cache
            .store_oidc_confirmation(&registration_id, pending)
    }

    fn oidc_pending_registration_confirmation(
        &self,
        registration_id: &str,
    ) -> Option<crate::oidc::OidcPendingRegistrationConfirmation> {
        self.registration_cache.oidc_confirmation(registration_id)
    }

    fn remove_oidc_registration_confirmation(
        &self,
        registration_id: &str,
    ) -> Option<crate::oidc::OidcPendingRegistrationConfirmation> {
        self.registration_cache
            .remove_oidc_confirmation(registration_id)
    }
}

#[cfg(feature = "postgres-sqlx")]
#[async_trait]
impl crate::oidc::OidcRegistrationHandler for PersistentPostgresOidcRegistrationHandler {
    async fn complete_oidc_registration(
        &self,
        registration_id: &str,
        user: &crate::oidc::OidcStoredUser,
        node_expiry: Option<DateTime<Utc>>,
    ) -> Result<crate::oidc::OidcRegistrationResult, crate::oidc::OidcRegistrationError> {
        let (mut pending, hostinfo, completion) = self
            .registration_cache
            .pending_registration_completion(registration_id)
            .ok_or(crate::oidc::OidcRegistrationError::SessionExpired)?;
        let handler = Self::clone(self);
        let selected_user_id = user.id;
        crate::tailscale_wire::complete_state_mutation(Box::pin(async move {
            let user_id = i64::try_from(selected_user_id).map_err(|_| {
                crate::oidc::OidcRegistrationError::Store(
                    "finding user: user id out of range".into(),
                )
            })?;
            let write =
                headscale_db::users::get_postgres_for_registration(&handler.machines.pool, user_id)
                    .await
                    .map_err(|error| {
                        let message = match error {
                            headscale_db::DbError::NotFound(_) => "user not found".to_string(),
                            error => error.headscale_go_message(),
                        };
                        crate::oidc::OidcRegistrationError::Store(format!(
                            "finding user: {message}"
                        ))
                    })?;
            let captured_user = super::users::UserRegistrationSnapshot::from_native(write);
            let user = &captured_user.user;
            let machine_key = pending.machine_key_hex.clone();
            let node_key = pending.node_key_hex.clone();
            let registration_lock = match handler.machines.registration_guard(&machine_key).await {
                Some(guard) => Some(guard),
                None => match &handler.wire_registry {
                    Some(registry) => Some(registry.lock_registration(&machine_key).await),
                    None => None,
                },
            };
            let node_key_lock = match handler
                .machines
                .node_key_registration_guard(&node_key)
                .await
            {
                Some(guard) => Some(guard),
                None => match &handler.wire_registry {
                    Some(registry) => Some(registry.lock_node_key_registration(&node_key).await),
                    None => None,
                },
            };
            let publication_scope = handler
                .machines
                .wire_registry
                .as_ref()
                .or(handler.wire_registry.as_ref())
                .map(|registry| registry.registration_publication_scope(&pending));
            let identity = user_identity_from_record(user);
            pending.set_user_identity(
                Some(user.id),
                identity.login_name,
                identity.display_name,
                identity.profile_pic_url,
            );
            pending.set_user_account_metadata(identity.provider, identity.created_at);
            let mut record = machine_admin_record_from_wire(&pending);
            record.user = user_login_name(user);
            let effective_expiry = if pending.forced_tags.is_empty() {
                node_expiry.or(pending.expiry)
            } else {
                None
            };
            record.expiry = effective_expiry.map(|expiry| expiry.timestamp().max(0) as u64);
            record.expiry_precise = effective_expiry;
            record.register_method = REGISTER_METHOD_OIDC;
            prepare_auth_path_addresses(
                handler.machines.as_ref(),
                handler.ip_allocator.as_deref(),
                &handler.policy,
                &mut record,
            )
            .await
            .map_err(|error| crate::oidc::OidcRegistrationError::Store(error.to_string()))?;

            let result = handler
                .machines
                .create_or_update_auth_path_with_user_snapshot(
                    record,
                    &handler.policy,
                    None,
                    Some(user_id),
                    true,
                    Some(&pending),
                    hostinfo,
                    Some(&captured_user),
                )
                .await
                .map_err(|err| crate::oidc::OidcRegistrationError::Store(err.to_string()))?;
            let mut wire_record = handler
                .machines
                .wire_record_for_publication(&result.record.id, handler.wire_registry.as_deref())
                .await
                .map_err(|error| crate::oidc::OidcRegistrationError::Store(error.to_string()))?
                .ok_or_else(|| {
                    crate::oidc::OidcRegistrationError::Store("registered node disappeared".into())
                })?;
            hydrate_wire_owner_from_user_admin(
                handler.machines.users.as_ref(),
                handler.wire_registry.as_deref(),
                user.id,
                &mut wire_record,
            )
            .await;
            if let Some(registry) = &handler.wire_registry {
                if let Some(old_node_key_hex) = result.replaced_node_key_hex.as_deref() {
                    registry
                        .try_replace_node_key_auth_completion(
                            old_node_key_hex,
                            wire_record.node_key_hex.clone(),
                            wire_record.clone(),
                        )
                        .await
                        .map_err(crate::oidc::OidcRegistrationError::Store)?;
                } else {
                    registry
                        .try_upsert_auth_completion(
                            wire_record.node_key_hex.clone(),
                            wire_record.clone(),
                        )
                        .await
                        .map_err(crate::oidc::OidcRegistrationError::Store)?;
                }
            }
            handler
                .registration_cache
                .finish_registration(completion, wire_record);
            // Go's HandleNodeFromAuthPath releases the machine-key lock on
            // return; the approval below takes the same locks again.
            drop(publication_scope);
            drop(node_key_lock);
            drop(registration_lock);
            // oidc.go handleRegistration: the node is now persisted and known
            // to the policy manager, so State.AutoApproveRoutes can match the
            // owner's addresses against the autoApprovers. Its change (a
            // PolicyChange) follows the registration's own.
            Box::pin(auto_approve_registered_node(
                handler.machines.as_ref(),
                &handler.policy,
                handler.wire_registry.as_deref(),
                &result.record,
            ))
            .await
            .map_err(|error| {
                crate::oidc::OidcRegistrationError::Store(format!("auto approving routes: {error}"))
            })?;
            Ok(crate::oidc::OidcRegistrationResult {
                new_node: result.new_node,
            })
        }))
        .await
        .map_err(|error| {
            crate::oidc::OidcRegistrationError::Store(format!(
                "finishing node registration: {error}"
            ))
        })?
    }

    async fn complete_oidc_auth_request(
        &self,
        auth_id: &str,
        user: &crate::oidc::OidcStoredUser,
    ) -> Result<(), crate::oidc::OidcAuthError> {
        let Some(binding) = self.registration_cache.ssh_binding(auth_id) else {
            if self.registration_cache.get(auth_id).is_some() {
                return Err(crate::oidc::OidcAuthError::NotSshCheck);
            }
            return Err(crate::oidc::OidcAuthError::SessionExpired);
        };
        let src_node_id = i64::try_from(binding.src_node_id)
            .map_err(|_| crate::oidc::OidcAuthError::Store("src node id out of range".into()))?;
        let source = match headscale_db::headscale_nodes::get_postgres_by_id(
            &self.machines.pool,
            src_node_id,
        )
        .await
        {
            Ok(row) => row,
            Err(headscale_db::DbError::NotFound(_)) => {
                return Err(crate::oidc::OidcAuthError::SourceNodeMissing);
            }
            Err(err) => return Err(crate::oidc::OidcAuthError::Store(err.to_string())),
        };

        if !source.tag_list().is_empty() || source.user_id.is_none() {
            return Err(crate::oidc::OidcAuthError::SourceNodeNoUserOwner);
        }
        let user_id = i64::try_from(user.id)
            .map_err(|_| crate::oidc::OidcAuthError::Store("OIDC user id out of range".into()))?;
        if source.user_id != Some(user_id) {
            return Err(crate::oidc::OidcAuthError::UserNotSourceOwner);
        }

        if self.registration_cache.approve_without_node(auth_id) {
            Ok(())
        } else {
            Err(crate::oidc::OidcAuthError::SessionExpired)
        }
    }

    fn oidc_registration_exists(&self, registration_id: &str) -> bool {
        matches!(
            self.registration_cache.auth_request_kind(registration_id),
            Some(AuthRequestKind::Registration)
        )
    }

    fn oidc_auth_request_kind(&self, auth_id: &str) -> Option<crate::oidc::OidcAuthRequestKind> {
        match self.registration_cache.auth_request_kind(auth_id)? {
            AuthRequestKind::Registration => Some(crate::oidc::OidcAuthRequestKind::Registration),
            AuthRequestKind::SshCheck(_) => Some(crate::oidc::OidcAuthRequestKind::SshCheck),
        }
    }

    fn oidc_registration_confirmation_info(
        &self,
        registration_id: &str,
    ) -> Option<crate::oidc::OidcRegistrationConfirmInfo> {
        let record = self.registration_cache.get(registration_id)?;
        Some(crate::oidc::OidcRegistrationConfirmInfo {
            hostname: record.hostname,
            os: record.os,
            machine_key: short_oidc_machine_key(&record.machine_key_hex),
        })
    }

    fn store_oidc_registration_confirmation(
        &self,
        pending: crate::oidc::OidcPendingRegistrationConfirmation,
    ) -> bool {
        let registration_id = pending.registration_id.clone();
        self.registration_cache
            .store_oidc_confirmation(&registration_id, pending)
    }

    fn oidc_pending_registration_confirmation(
        &self,
        registration_id: &str,
    ) -> Option<crate::oidc::OidcPendingRegistrationConfirmation> {
        self.registration_cache.oidc_confirmation(registration_id)
    }

    fn remove_oidc_registration_confirmation(
        &self,
        registration_id: &str,
    ) -> Option<crate::oidc::OidcPendingRegistrationConfirmation> {
        self.registration_cache
            .remove_oidc_confirmation(registration_id)
    }
}

fn short_oidc_machine_key(machine_key_hex: &str) -> String {
    let short = machine_key_hex.chars().take(12).collect::<String>();
    if short.is_empty() {
        "unknown".to_string()
    } else {
        format!("[{short}]")
    }
}

impl PersistentMachineAdmin {
    #[allow(clippy::too_many_arguments)]
    async fn complete_atomic_auth_key_registration(
        &self,
        wire_record: MachineRecord,
        policy: &PolicyStore,
        candidate: &str,
        auth_key_id: Option<i64>,
        require_fresh: bool,
        hostinfo: Option<Value>,
        credential: Option<NativeAuthKey>,
        material: Option<Arc<headscale_db::preauth_keys::RegistrationKey>>,
    ) -> Result<PersistedMachineRegistration, crate::tailscale_wire::AuthKeyRegistrationError> {
        use crate::tailscale_wire::AuthKeyRegistrationError;
        let capture_from_candidate = credential.is_none() && material.is_none();
        let (credential, material) = if capture_from_candidate {
            let material =
                headscale_db::preauth_keys::get_by_token_for_registration(&self.pool, candidate)
                    .await
                    .map_err(|_| {
                        AuthKeyRegistrationError::Credential(
                            crate::tailscale_wire::RedeemError::Unknown,
                        )
                    })?;
            let user = material.user.as_ref().map(|user| {
                super::users::PersistentUserAdmin::row_to_association_record(user.row.clone())
            });
            let credential = NativeAuthKey::from_row(&material.key, Some(user))
                .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
            (Some(credential), Some(Arc::new(material)))
        } else {
            (credential, material)
        };
        let captured = captured_auth_key(credential.as_ref())?;
        let mut record = machine_admin_record_from_wire(&wire_record);
        record.register_method = REGISTER_METHOD_AUTH_KEY;
        let mut plan = Box::pin(
            self.prepare_auth_path_registration(
                record,
                policy,
                auth_key_id,
                auth_key_owner_override(&wire_record)
                    .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?,
                false,
                Some(&wire_record),
                credential.as_ref(),
                None,
            ),
        )
        .await
        .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
        apply_registration_hostinfo(&mut plan.params, hostinfo.as_ref())
            .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
        if capture_from_candidate {
            let material = material.as_ref().expect("candidate snapshot captured");
            headscale_db::auth_key_registration::validate_captured_registration_key(
                plan.existing.as_ref(),
                &material.key,
                &plan.params,
                require_fresh,
            )
            .map_err(atomic_registration_error)?;
        }
        let previous_key = plan
            .existing
            .as_ref()
            .map(|row| key_without_prefix("nodekey:", &row.node_key));
        if let (Some(registry), Some(prior)) = (&self.wire_registry, plan.existing.as_ref()) {
            // Batch wait first, lock second: the live edit goes through the
            // NodeStore writer like Go's UpdateNode, so concurrent registrations
            // share one batch. The save lock covers only the SQL write.
            let live = Box::pin(LiveRegistrationSave::begin(
                registry,
                prior,
                &plan.params,
                Some(&wire_record),
                true,
                plan.associations.clone(),
            ))
            .await
            .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
            let _persist = registry.lock_native_persistence().await;
            let committed = match captured.as_ref() {
                Some(key) => {
                    headscale_db::auth_key_registration::commit_cached_sqlite_with_key(
                        &self.pool,
                        prior,
                        live.registration.clone(),
                        key,
                    )
                    .await
                }
                None => {
                    headscale_db::auth_key_registration::commit_cached_sqlite(
                        &self.pool,
                        prior,
                        live.registration.clone(),
                        candidate,
                        require_fresh,
                    )
                    .await
                }
            };
            if let Err(error) = committed {
                live.rollback(registry).await.map_err(|rollback| {
                    AuthKeyRegistrationError::Storage(format!(
                        "{error}; rollback failed: {rollback}"
                    ))
                })?;
                return Err(if captured.is_some() {
                    captured_registration_error(error, "writing node to database")
                } else {
                    atomic_registration_error(error)
                });
            }
            let previous_key = live.update.before.node_key_hex.clone();
            let record = live.finish(registry);
            return Ok(PersistedMachineRegistration {
                replaced_node_key_hex: (previous_key != record.node_key_hex)
                    .then_some(previous_key),
                record,
            });
        }
        if let Some(prior) = plan.existing.as_ref() {
            let prepared = self
                .prepare_headless_registration(
                    prior,
                    &plan.params,
                    Some(&wire_record),
                    true,
                    plan.associations.clone(),
                )
                .await
                .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
            let committed = match captured.as_ref() {
                Some(key) => {
                    headscale_db::auth_key_registration::commit_cached_sqlite_with_key(
                        &self.pool,
                        prior,
                        prepared.registration.clone(),
                        key,
                    )
                    .await
                }
                None => {
                    headscale_db::auth_key_registration::commit_cached_sqlite(
                        &self.pool,
                        prior,
                        prepared.registration.clone(),
                        candidate,
                        require_fresh,
                    )
                    .await
                }
            };
            committed
                .map_err(|error| captured_registration_error(error, "writing node to database"))?;
            return Ok(PersistedMachineRegistration {
                replaced_node_key_hex: previous_key
                    .filter(|key| key != &prepared.record.node_key_hex),
                record: prepared.record,
            });
        }
        let node = new_native_registration(&plan.params)
            .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
        let row = match captured.as_ref() {
            Some(key) => {
                if let Some(material) = &material {
                    let saved =
                        headscale_db::auth_key_registration::commit_new_sqlite_with_associations(
                            &self.pool,
                            node,
                            key,
                            (**material).clone(),
                        )
                        .await
                        .map_err(|error| captured_registration_error(error, "creating new node"))?;
                    apply_new_association_projection(
                        &mut plan.associations,
                        &saved.node,
                        &saved.associations,
                    )
                    .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
                    saved.node
                } else {
                    headscale_db::auth_key_registration::commit_new_sqlite_with_key(
                        &self.pool, node, key,
                    )
                    .await
                    .map_err(|error| captured_registration_error(error, "creating new node"))?
                }
            }

            None => {
                headscale_db::auth_key_registration::commit_new_sqlite(&self.pool, node, candidate)
                    .await
                    .map_err(atomic_registration_error)?
            }
        };
        let record = Box::pin(finish_new_native_registration(
            self.wire_registry.as_deref(),
            &row,
            wire_record,
            true,
            plan.associations.clone(),
        ))
        .await
        .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
        Ok(PersistedMachineRegistration {
            record,
            replaced_node_key_hex: None,
        })
    }
}

#[async_trait]
impl MachineRegistrationStore for PersistentMachineAdmin {
    fn runtime_sync_returns_live_snapshot(&self) -> bool {
        self.wire_registry.is_some()
    }

    fn supports_guarded_ephemeral_deletion(&self) -> bool {
        true
    }

    async fn delete_ephemeral_registration(&self, record: &MachineRecord) -> Result<(), String> {
        if !record.ephemeral {
            return Err("refusing ephemeral cleanup of a non-ephemeral node".into());
        }
        if let Some(registry) = &self.wire_registry {
            let id = requested_live_node_id(registry, record)?;
            return complete_guarded_native_node_deletion(
                registry,
                NativeNodeStore::Sqlite(self.pool.clone()),
                id,
                &record.node_key_hex,
            )
            .await
            .map_err(|error| error.to_string());
        }
        self.persist_wire_logout(record, Utc::now()).await
    }

    fn supports_atomic_auth_key_registration(&self) -> bool {
        true
    }

    async fn create_or_update_auth_key_registration_atomic(
        &self,
        wire_record: MachineRecord,
        policy: &PolicyStore,
        candidate: &str,
        auth_key_id: Option<i64>,
        require_fresh: bool,
    ) -> Result<PersistedMachineRegistration, crate::tailscale_wire::AuthKeyRegistrationError> {
        self.create_or_update_auth_key_registration_atomic_with_hostinfo(
            wire_record,
            policy,
            candidate,
            auth_key_id,
            require_fresh,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_or_update_auth_key_registration_atomic_with_hostinfo(
        &self,
        wire_record: MachineRecord,
        policy: &PolicyStore,
        candidate: &str,
        auth_key_id: Option<i64>,
        require_fresh: bool,
        hostinfo: Option<Value>,
    ) -> Result<PersistedMachineRegistration, crate::tailscale_wire::AuthKeyRegistrationError> {
        Box::pin(self.complete_atomic_auth_key_registration(
            wire_record,
            policy,
            candidate,
            auth_key_id,
            require_fresh,
            hostinfo,
            None,
            None,
        ))
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_or_update_auth_key_registration_atomic_with_lookup(
        &self,
        wire_record: MachineRecord,
        policy: &PolicyStore,
        candidate: &str,
        auth_key_id: Option<i64>,
        require_fresh: bool,
        hostinfo: Option<Value>,
        lookup: Option<crate::tailscale_wire::PreauthLookup>,
    ) -> Result<PersistedMachineRegistration, crate::tailscale_wire::AuthKeyRegistrationError> {
        let (credential, material) = lookup
            .map(|lookup| (lookup.native, lookup.native_save))
            .unwrap_or_default();
        Box::pin(self.complete_atomic_auth_key_registration(
            wire_record,
            policy,
            candidate,
            auth_key_id,
            require_fresh,
            hostinfo,
            credential,
            material,
        ))
        .await
    }

    async fn create_or_update_auth_key_registration(
        &self,
        record: MachineRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
    ) -> Result<PersistedMachineRegistration, String> {
        self.create_or_update_auth_key_registration_with_hostinfo(record, policy, auth_key_id, None)
            .await
    }

    async fn create_or_update_auth_key_registration_with_hostinfo(
        &self,
        wire_record: MachineRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
        hostinfo: Option<Value>,
    ) -> Result<PersistedMachineRegistration, String> {
        let mut record = machine_admin_record_from_wire(&wire_record);
        record.register_method = REGISTER_METHOD_AUTH_KEY;
        let result = self
            .create_or_update_auth_path_with_hostinfo(
                record,
                policy,
                auth_key_id,
                auth_key_owner_override(&wire_record).map_err(|error| error.to_string())?,
                false,
                Some(&wire_record),
                hostinfo,
            )
            .await
            .map_err(|error| error.to_string())?;
        if let Some(registry) = &self.wire_registry
            && let Some(record) = registry.native_registration_record(result.record.node_id)
        {
            return Ok(PersistedMachineRegistration {
                record,
                replaced_node_key_hex: result.replaced_node_key_hex,
            });
        }
        let row =
            headscale_db::headscale_nodes::get_by_id(&self.pool, result.record.node_id as i64)
                .await
                .map_err(|err| err.to_string())?;
        let mut record = self
            .row_to_wire_record_for_publication(row)
            .await
            .map_err(|err| err.to_string())?;
        record.disco_key = wire_record.disco_key;
        record.endpoints = wire_record.endpoints;
        Ok(PersistedMachineRegistration {
            record,
            replaced_node_key_hex: result.replaced_node_key_hex,
        })
    }

    async fn sync_runtime_machine_state(
        &self,
        record: MachineRecord,
        _policy: &PolicyStore,
    ) -> Result<PersistedMachineRegistration, String> {
        if let Some(registry) = &self.wire_registry {
            return persist_live_runtime_node(
                registry,
                NativeNodeStore::Sqlite(self.pool.clone()),
                &record,
            )
            .await;
        }
        let node_key = key_with_prefix("nodekey:", &record.node_key_hex);
        let row = headscale_db::headscale_nodes::get_by_node_key(&self.pool, &node_key)
            .await
            .map_err(|err| db_error_to_machine(err, &record.node_key_hex).to_string())?;
        let params = create_params_for_wire_record(&record, row.user_id, row.auth_key_id)
            .map_err(|error| error.to_string())?;
        let auto_rename = is_auto_derived_given_name(&row.given_name, &row.hostname);
        let row = headscale_db::headscale_nodes::update_runtime_state(
            &self.pool,
            &row,
            params,
            auto_rename,
        )
        .await
        .map_err(|err| db_error_to_machine(err, &record.node_key_hex).to_string())?;
        let record = self
            .row_to_wire_record_for_publication(row)
            .await
            .map_err(|err| err.to_string())?;
        Ok(PersistedMachineRegistration {
            record,
            replaced_node_key_hex: None,
        })
    }

    async fn delete_machine_registration(&self, node_key_hex: &str) -> Result<(), String> {
        self.delete(node_key_hex)
            .await
            .map_err(|err| err.to_string())
    }

    async fn persist_wire_logout(
        &self,
        record: &MachineRecord,
        at: DateTime<Utc>,
    ) -> Result<(), String> {
        if record.ephemeral
            && let Some(id) = record.node_id
        {
            let id = i64::try_from(id).map_err(|_| "invalid cached node identity".to_string())?;
            let _persist = match &self.wire_registry {
                Some(registry) => Some(registry.lock_native_persistence().await),
                None => None,
            };
            return headscale_db::headscale_nodes::destroy_cached_node(&self.pool, id)
                .await
                .map_err(|error| error.headscale_go_message());
        }
        if !record.ephemeral
            && !record.is_tagged()
            && let Some(registry) = &self.wire_registry
        {
            return persist_live_logout_expiry(
                registry,
                NativeNodeStore::Sqlite(self.pool.clone()),
                record,
                at,
            )
            .await;
        }
        let node_key = key_with_prefix("nodekey:", &record.node_key_hex);
        let row = headscale_db::headscale_nodes::get_by_node_key(&self.pool, &node_key)
            .await
            .map_err(|error| error.to_string())?;
        if key_without_prefix("mkey:", &row.machine_key) != record.machine_key_hex
            || record
                .node_id
                .is_some_and(|id| u64::try_from(row.id).ok() != Some(id))
        {
            return Err("node identity changed during logout".into());
        }
        if record.ephemeral {
            headscale_db::headscale_nodes::destroy_cached_node(&self.pool, row.id)
                .await
                .map_err(|error| error.to_string())?;
        } else if !record.is_tagged() {
            headscale_db::headscale_nodes::set_expiry_precise(&self.pool, row.id, Some(at))
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    async fn persist_last_seen(&self, node_id: u64, at: DateTime<Utc>) -> Result<(), String> {
        if let Some(registry) = &self.wire_registry {
            return persist_live_runtime_node_by_id(
                registry,
                NativeNodeStore::Sqlite(self.pool.clone()),
                node_id,
            )
            .await
            .map(|_| ());
        }
        let id = i64::try_from(node_id).map_err(|err| err.to_string())?;
        headscale_db::headscale_nodes::persist_last_seen_at(&self.pool, id, &at)
            .await
            .map_err(|err| err.to_string())
    }
}

#[cfg(feature = "postgres-sqlx")]
impl PersistentPostgresMachineAdmin {
    #[allow(clippy::too_many_arguments)]
    async fn complete_atomic_auth_key_registration(
        &self,
        wire_record: MachineRecord,
        policy: &PolicyStore,
        candidate: &str,
        auth_key_id: Option<i64>,
        require_fresh: bool,
        hostinfo: Option<Value>,
        credential: Option<NativeAuthKey>,
        material: Option<Arc<headscale_db::preauth_keys::RegistrationKey>>,
    ) -> Result<PersistedMachineRegistration, crate::tailscale_wire::AuthKeyRegistrationError> {
        use crate::tailscale_wire::AuthKeyRegistrationError;
        let capture_from_candidate = credential.is_none() && material.is_none();
        let (credential, material) = if capture_from_candidate {
            let material = headscale_db::preauth_keys::get_postgres_by_token_for_registration(
                &self.pool, candidate,
            )
            .await
            .map_err(|_| {
                AuthKeyRegistrationError::Credential(crate::tailscale_wire::RedeemError::Unknown)
            })?;
            let user = material.user.as_ref().map(|user| {
                super::users::PersistentUserAdmin::row_to_association_record(user.row.clone())
            });
            let credential = NativeAuthKey::from_row(&material.key, Some(user))
                .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
            (Some(credential), Some(Arc::new(material)))
        } else {
            (credential, material)
        };
        let captured = captured_auth_key(credential.as_ref())?;
        let mut record = machine_admin_record_from_wire(&wire_record);
        record.register_method = REGISTER_METHOD_AUTH_KEY;
        let mut plan = Box::pin(
            self.prepare_auth_path_registration(
                record,
                policy,
                auth_key_id,
                auth_key_owner_override(&wire_record)
                    .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?,
                false,
                Some(&wire_record),
                credential.as_ref(),
                None,
            ),
        )
        .await
        .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
        apply_registration_hostinfo(&mut plan.params, hostinfo.as_ref())
            .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
        if capture_from_candidate {
            let material = material.as_ref().expect("candidate snapshot captured");
            headscale_db::auth_key_registration::validate_captured_registration_key(
                plan.existing.as_ref(),
                &material.key,
                &plan.params,
                require_fresh,
            )
            .map_err(atomic_registration_error)?;
        }
        let previous_key = plan
            .existing
            .as_ref()
            .map(|row| key_without_prefix("nodekey:", &row.node_key));
        if let (Some(registry), Some(prior)) = (&self.wire_registry, plan.existing.as_ref()) {
            // Batch wait first, lock second: the live edit goes through the
            // NodeStore writer like Go's UpdateNode, so concurrent registrations
            // share one batch. The save lock covers only the SQL write.
            let live = Box::pin(LiveRegistrationSave::begin(
                registry,
                prior,
                &plan.params,
                Some(&wire_record),
                true,
                plan.associations.clone(),
            ))
            .await
            .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
            let _persist = registry.lock_native_persistence().await;
            let committed = match captured.as_ref() {
                Some(key) => {
                    headscale_db::auth_key_registration::commit_cached_postgres_with_key(
                        &self.pool,
                        prior,
                        live.registration.clone(),
                        key,
                    )
                    .await
                }
                None => {
                    headscale_db::auth_key_registration::commit_cached_postgres(
                        &self.pool,
                        prior,
                        live.registration.clone(),
                        candidate,
                        require_fresh,
                    )
                    .await
                }
            };
            if let Err(error) = committed {
                live.rollback(registry).await.map_err(|rollback| {
                    AuthKeyRegistrationError::Storage(format!(
                        "{error}; rollback failed: {rollback}"
                    ))
                })?;
                return Err(if captured.is_some() {
                    captured_registration_error(error, "writing node to database")
                } else {
                    atomic_registration_error(error)
                });
            }
            let previous_key = live.update.before.node_key_hex.clone();
            let record = live.finish(registry);
            return Ok(PersistedMachineRegistration {
                replaced_node_key_hex: (previous_key != record.node_key_hex)
                    .then_some(previous_key),
                record,
            });
        }
        if let Some(prior) = plan.existing.as_ref() {
            let prepared = self
                .prepare_headless_registration(
                    prior,
                    &plan.params,
                    Some(&wire_record),
                    true,
                    plan.associations.clone(),
                )
                .await
                .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
            let committed = match captured.as_ref() {
                Some(key) => {
                    headscale_db::auth_key_registration::commit_cached_postgres_with_key(
                        &self.pool,
                        prior,
                        prepared.registration.clone(),
                        key,
                    )
                    .await
                }
                None => {
                    headscale_db::auth_key_registration::commit_cached_postgres(
                        &self.pool,
                        prior,
                        prepared.registration.clone(),
                        candidate,
                        require_fresh,
                    )
                    .await
                }
            };
            committed
                .map_err(|error| captured_registration_error(error, "writing node to database"))?;
            return Ok(PersistedMachineRegistration {
                replaced_node_key_hex: previous_key
                    .filter(|key| key != &prepared.record.node_key_hex),
                record: prepared.record,
            });
        }
        let node = new_native_registration(&plan.params)
            .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
        let row = match captured.as_ref() {
            Some(key) => {
                if let Some(material) = &material {
                    let saved =
                        headscale_db::auth_key_registration::commit_new_postgres_with_associations(
                            &self.pool,
                            node,
                            key,
                            (**material).clone(),
                        )
                        .await
                        .map_err(|error| captured_registration_error(error, "creating new node"))?;
                    apply_new_association_projection(
                        &mut plan.associations,
                        &saved.node,
                        &saved.associations,
                    )
                    .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
                    saved.node
                } else {
                    headscale_db::auth_key_registration::commit_new_postgres_with_key(
                        &self.pool, node, key,
                    )
                    .await
                    .map_err(|error| captured_registration_error(error, "creating new node"))?
                }
            }

            None => headscale_db::auth_key_registration::commit_new_postgres(
                &self.pool, node, candidate,
            )
            .await
            .map_err(atomic_registration_error)?,
        };
        let record = Box::pin(finish_new_native_registration(
            self.wire_registry.as_deref(),
            &row,
            wire_record,
            true,
            plan.associations.clone(),
        ))
        .await
        .map_err(|error| AuthKeyRegistrationError::Storage(error.to_string()))?;
        Ok(PersistedMachineRegistration {
            record,
            replaced_node_key_hex: None,
        })
    }
}

#[cfg(feature = "postgres-sqlx")]
#[async_trait]
impl MachineRegistrationStore for PersistentPostgresMachineAdmin {
    fn runtime_sync_returns_live_snapshot(&self) -> bool {
        self.wire_registry.is_some()
    }

    fn supports_guarded_ephemeral_deletion(&self) -> bool {
        true
    }

    async fn delete_ephemeral_registration(&self, record: &MachineRecord) -> Result<(), String> {
        if !record.ephemeral {
            return Err("refusing ephemeral cleanup of a non-ephemeral node".into());
        }
        if let Some(registry) = &self.wire_registry {
            let id = requested_live_node_id(registry, record)?;
            return complete_guarded_native_node_deletion(
                registry,
                NativeNodeStore::Postgres(self.pool.clone()),
                id,
                &record.node_key_hex,
            )
            .await
            .map_err(|error| error.to_string());
        }
        self.persist_wire_logout(record, Utc::now()).await
    }

    fn supports_atomic_auth_key_registration(&self) -> bool {
        true
    }

    async fn create_or_update_auth_key_registration_atomic(
        &self,
        wire_record: MachineRecord,
        policy: &PolicyStore,
        candidate: &str,
        auth_key_id: Option<i64>,
        require_fresh: bool,
    ) -> Result<PersistedMachineRegistration, crate::tailscale_wire::AuthKeyRegistrationError> {
        self.create_or_update_auth_key_registration_atomic_with_hostinfo(
            wire_record,
            policy,
            candidate,
            auth_key_id,
            require_fresh,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_or_update_auth_key_registration_atomic_with_hostinfo(
        &self,
        wire_record: MachineRecord,
        policy: &PolicyStore,
        candidate: &str,
        auth_key_id: Option<i64>,
        require_fresh: bool,
        hostinfo: Option<Value>,
    ) -> Result<PersistedMachineRegistration, crate::tailscale_wire::AuthKeyRegistrationError> {
        Box::pin(self.complete_atomic_auth_key_registration(
            wire_record,
            policy,
            candidate,
            auth_key_id,
            require_fresh,
            hostinfo,
            None,
            None,
        ))
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn create_or_update_auth_key_registration_atomic_with_lookup(
        &self,
        wire_record: MachineRecord,
        policy: &PolicyStore,
        candidate: &str,
        auth_key_id: Option<i64>,
        require_fresh: bool,
        hostinfo: Option<Value>,
        lookup: Option<crate::tailscale_wire::PreauthLookup>,
    ) -> Result<PersistedMachineRegistration, crate::tailscale_wire::AuthKeyRegistrationError> {
        let (credential, material) = lookup
            .map(|lookup| (lookup.native, lookup.native_save))
            .unwrap_or_default();
        Box::pin(self.complete_atomic_auth_key_registration(
            wire_record,
            policy,
            candidate,
            auth_key_id,
            require_fresh,
            hostinfo,
            credential,
            material,
        ))
        .await
    }

    async fn create_or_update_auth_key_registration(
        &self,
        record: MachineRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
    ) -> Result<PersistedMachineRegistration, String> {
        self.create_or_update_auth_key_registration_with_hostinfo(record, policy, auth_key_id, None)
            .await
    }

    async fn create_or_update_auth_key_registration_with_hostinfo(
        &self,
        wire_record: MachineRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
        hostinfo: Option<Value>,
    ) -> Result<PersistedMachineRegistration, String> {
        let mut record = machine_admin_record_from_wire(&wire_record);
        record.register_method = REGISTER_METHOD_AUTH_KEY;
        let result = self
            .create_or_update_auth_path_with_hostinfo(
                record,
                policy,
                auth_key_id,
                auth_key_owner_override(&wire_record).map_err(|error| error.to_string())?,
                false,
                Some(&wire_record),
                hostinfo,
            )
            .await
            .map_err(|error| error.to_string())?;
        if let Some(registry) = &self.wire_registry
            && let Some(record) = registry.native_registration_record(result.record.node_id)
        {
            return Ok(PersistedMachineRegistration {
                record,
                replaced_node_key_hex: result.replaced_node_key_hex,
            });
        }
        let row = headscale_db::headscale_nodes::get_postgres_by_id(
            &self.pool,
            result.record.node_id as i64,
        )
        .await
        .map_err(|err| err.to_string())?;
        let mut record = self
            .row_to_wire_record_for_publication(row)
            .await
            .map_err(|err| err.to_string())?;
        record.disco_key = wire_record.disco_key;
        record.endpoints = wire_record.endpoints;
        Ok(PersistedMachineRegistration {
            record,
            replaced_node_key_hex: result.replaced_node_key_hex,
        })
    }

    async fn sync_runtime_machine_state(
        &self,
        record: MachineRecord,
        _policy: &PolicyStore,
    ) -> Result<PersistedMachineRegistration, String> {
        if let Some(registry) = &self.wire_registry {
            return persist_live_runtime_node(
                registry,
                NativeNodeStore::Postgres(self.pool.clone()),
                &record,
            )
            .await;
        }
        let node_key = key_with_prefix("nodekey:", &record.node_key_hex);
        let row = headscale_db::headscale_nodes::get_postgres_by_node_key(&self.pool, &node_key)
            .await
            .map_err(|err| db_error_to_machine(err, &record.node_key_hex).to_string())?;
        let params = create_params_for_wire_record(&record, row.user_id, row.auth_key_id)
            .map_err(|error| error.to_string())?;
        let auto_rename = is_auto_derived_given_name(&row.given_name, &row.hostname);
        let row = headscale_db::headscale_nodes::update_postgres_runtime_state(
            &self.pool,
            &row,
            params,
            auto_rename,
        )
        .await
        .map_err(|err| db_error_to_machine(err, &record.node_key_hex).to_string())?;
        let record = self
            .row_to_wire_record_for_publication(row)
            .await
            .map_err(|err| err.to_string())?;
        Ok(PersistedMachineRegistration {
            record,
            replaced_node_key_hex: None,
        })
    }

    async fn delete_machine_registration(&self, node_key_hex: &str) -> Result<(), String> {
        self.delete(node_key_hex)
            .await
            .map_err(|err| err.to_string())
    }

    async fn persist_wire_logout(
        &self,
        record: &MachineRecord,
        at: DateTime<Utc>,
    ) -> Result<(), String> {
        if record.ephemeral
            && let Some(id) = record.node_id
        {
            let id = i64::try_from(id).map_err(|_| "invalid cached node identity".to_string())?;
            let _persist = match &self.wire_registry {
                Some(registry) => Some(registry.lock_native_persistence().await),
                None => None,
            };
            return headscale_db::headscale_nodes::destroy_postgres_cached_node(&self.pool, id)
                .await
                .map_err(|error| error.headscale_go_message());
        }
        if !record.ephemeral
            && !record.is_tagged()
            && let Some(registry) = &self.wire_registry
        {
            return persist_live_logout_expiry(
                registry,
                NativeNodeStore::Postgres(self.pool.clone()),
                record,
                at,
            )
            .await;
        }
        let node_key = key_with_prefix("nodekey:", &record.node_key_hex);
        let row = headscale_db::headscale_nodes::get_postgres_by_node_key(&self.pool, &node_key)
            .await
            .map_err(|error| error.to_string())?;
        if key_without_prefix("mkey:", &row.machine_key) != record.machine_key_hex
            || record
                .node_id
                .is_some_and(|id| u64::try_from(row.id).ok() != Some(id))
        {
            return Err("node identity changed during logout".into());
        }
        if record.ephemeral {
            headscale_db::headscale_nodes::destroy_postgres_cached_node(&self.pool, row.id)
                .await
                .map_err(|error| error.to_string())?;
        } else if !record.is_tagged() {
            headscale_db::headscale_nodes::set_postgres_expiry_precise(
                &self.pool,
                row.id,
                Some(at),
            )
            .await
            .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    async fn persist_last_seen(&self, node_id: u64, at: DateTime<Utc>) -> Result<(), String> {
        if let Some(registry) = &self.wire_registry {
            return persist_live_runtime_node_by_id(
                registry,
                NativeNodeStore::Postgres(self.pool.clone()),
                node_id,
            )
            .await
            .map(|_| ());
        }
        let id = i64::try_from(node_id).map_err(|err| err.to_string())?;
        headscale_db::headscale_nodes::persist_postgres_last_seen_at(&self.pool, id, &at)
            .await
            .map_err(|err| err.to_string())
    }
}

#[async_trait]
impl MachineAdmin for PersistentMachineAdmin {
    fn numeric_mutation_selector(&self, node_id: u64) -> Option<String> {
        Some(node_id.to_string())
    }

    async fn get_view(&self, id: &str) -> Result<Option<MachineAdminView>, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return checked_live_view(registry, id);
        }
        let row = match self.row_by_slug(id).await {
            Ok(row) => row,
            Err(MachineAdminError::NotFound(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let (wire, associations) = self.row_to_wire_record_with_association(&row).await?;
        admin_view_from_native_row(&row, &wire, associations).map(Some)
    }

    async fn list_views(&self) -> Result<Vec<MachineAdminView>, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return checked_live_views(registry);
        }
        let rows = headscale_db::headscale_nodes::list(&self.pool)
            .await
            .map_err(|error| db_error_to_machine(error, "nodes"))?;
        let mut views = Vec::with_capacity(rows.len());
        for row in rows {
            let (wire, associations) = self.row_to_wire_record_with_association(&row).await?;
            views.push(admin_view_from_native_row(&row, &wire, associations)?);
        }
        Ok(views)
    }

    async fn mutate_with_view(
        &self,
        id: &str,
        mutation: MachineAdminMutation,
    ) -> Result<MachineAdminView, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node_with_view(
                registry.clone(),
                NativeNodeStore::Sqlite(self.pool.clone()),
                id,
                mutation,
            )
            .await;
        }
        mutate_with_fallback_view(self, id, mutation).await
    }

    async fn policy_nodes_for_registration(
        &self,
    ) -> Result<Vec<PolicyCheckNode>, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return checked_live_policy_nodes(registry);
        }
        let rows = headscale_db::headscale_nodes::list(&self.pool)
            .await
            .map_err(|error| db_error_to_machine(error, "registration policy nodes"))?;
        let mut nodes = Vec::with_capacity(rows.len());
        for row in rows {
            let (record, association) = self.row_to_wire_record_with_association(&row).await?;
            nodes.push(policy_node_from_native_row(&row, &record, association)?);
        }
        Ok(nodes)
    }

    async fn policy_nodes_for_check(
        &self,
    ) -> Result<Vec<PolicyCheckNodeSnapshot>, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return checked_live_policy_check_snapshot(registry);
        }
        let rows = headscale_db::headscale_nodes::list(&self.pool)
            .await
            .map_err(|error| db_error_to_machine(error, "policy check nodes"))?;
        let mut nodes = Vec::with_capacity(rows.len());
        for row in rows {
            let (record, association) = self.row_to_wire_record_with_association(&row).await?;
            nodes.push(PolicyCheckNodeSnapshot {
                node: policy_node_from_native_row(&row, &record, association)?,
                advertised_routes: record.available_routes,
                approved_routes: record.approved_routes,
            });
        }
        Ok(nodes)
    }

    fn mutation_selector(&self, record: &MachineAdminRecord) -> String {
        let node_id = if record.node_id == 0 {
            crate::tailscale_wire::wire::stable_id_from_key(&record.id)
        } else {
            record.node_id
        };
        node_id.to_string()
    }

    async fn list_checked(&self) -> Result<Vec<MachineAdminRecord>, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return checked_live_records(registry);
        }
        let rows = headscale_db::headscale_nodes::list(&self.pool)
            .await
            .map_err(|error| db_error_to_machine(error, "policy nodes"))?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            records.push(self.row_to_record(row).await);
        }
        Ok(records)
    }

    async fn list(&self) -> Vec<MachineAdminRecord> {
        match self.list_checked().await {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(?error, "persistent machine list failed");
                Vec::new()
            }
        }
    }

    async fn auto_approve_routes(&self, policy: &PolicyStore) -> Result<usize, MachineAdminError> {
        let store = NativeNodeStore::Sqlite(self.pool.clone());
        if let Some(registry) = &self.wire_registry {
            auto_approve_live_registry(policy, registry.clone(), store).await
        } else {
            let mut records = self.list_checked().await?;
            let identities = self.policy_nodes_for_registration().await?;
            for record in &mut records {
                if let Some(identity) = identities.iter().find(|node| node.id == record.node_id) {
                    record.user_id = identity.user_id;
                    record.user = identity.user.clone().unwrap_or_default();
                    record.ipv4 = identity
                        .addrs
                        .iter()
                        .find(|addr| !addr.contains(':'))
                        .cloned()
                        .unwrap_or_default();
                    record.ipv6 = identity
                        .addrs
                        .iter()
                        .find(|addr| addr.contains(':'))
                        .cloned();
                }
            }
            auto_approve_without_registry(policy, records, store).await
        }
    }

    async fn registration_guard(
        &self,
        machine_key: &str,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        match &self.wire_registry {
            Some(registry) => Some(registry.lock_registration(machine_key).await),
            None => None,
        }
    }

    async fn node_key_registration_guard(
        &self,
        node_key: &str,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        match &self.wire_registry {
            Some(registry) => Some(registry.lock_node_key_registration(node_key).await),
            None => None,
        }
    }

    async fn wire_record(&self, id: &str) -> Result<Option<MachineRecord>, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return Ok(WireMachineAdmin::new(registry.clone())
                .selected_record(&key_without_prefix("nodekey:", id))
                .map(|(_, record)| record));
        }
        let row = self.row_by_slug(id).await?;
        self.row_to_wire_record(&row).await.map(Some)
    }

    async fn wire_record_for_publication(
        &self,
        id: &str,
        registry: Option<&MachineRegistry>,
    ) -> Result<Option<MachineRecord>, MachineAdminError> {
        if let Some(registry) = registry.or(self.wire_registry.as_deref()) {
            let cached = registry.get(&key_without_prefix("nodekey:", id));
            let node_id = cached
                .as_ref()
                .map(MachineRecord::stable_node_id)
                .or_else(|| id.parse().ok());
            if let Some(record) = node_id.and_then(|id| registry.native_registration_record(id)) {
                return Ok(Some(record));
            }
        }
        let row = self.row_by_slug(id).await?;
        let (record, association) = self.row_to_wire_record_with_association(&row).await?;
        if let Some(registry) = registry {
            stage_native_row(registry, &row, &record, association)?;
        }
        Ok(Some(record))
    }

    async fn raw_hostname(&self, id: &str) -> Option<String> {
        if let Some(registry) = &self.wire_registry {
            return WireMachineAdmin::new(registry.clone())
                .selected_record(&key_without_prefix("nodekey:", id))
                .map(|(_, record)| record.raw_hostname);
        }
        self.row_by_slug(id).await.ok().map(|row| row.hostname)
    }

    async fn get(&self, id: &str) -> Option<MachineAdminRecord> {
        if let Some(registry) = &self.wire_registry {
            return WireMachineAdmin::new(registry.clone())
                .get(&key_without_prefix("nodekey:", id))
                .await;
        }
        match self.row_by_slug(id).await {
            Ok(row) => Some(self.row_to_record(row).await),
            Err(MachineAdminError::NotFound(_)) => None,
            Err(e) => {
                tracing::warn!(?e, id, "persistent machine get failed");
                None
            }
        }
    }

    async fn existing_auth_path_record(
        &self,
        record: &MachineAdminRecord,
    ) -> Option<MachineAdminRecord> {
        self.existing_auth_path_record_checked(record)
            .await
            .ok()
            .flatten()
    }

    async fn existing_auth_path_record_checked(
        &self,
        record: &MachineAdminRecord,
    ) -> Result<Option<MachineAdminRecord>, MachineAdminError> {
        let user_id = self.user_id_for_record(record).await?;
        if let Some(registry) = &self.wire_registry {
            registry
                .validate_registration_node_key(&record.id, &record.machine_key_hex)
                .map_err(|error| MachineAdminError::BadRequest(error.into()))?;
        }
        let machine_key = key_with_prefix("mkey:", &record.machine_key_hex);
        let candidates = if let Some(registry) = &self.wire_registry {
            registration_rows_from_cache(registry, &record.machine_key_hex)?
        } else {
            headscale_db::headscale_nodes::list_by_machine_key(&self.pool, &machine_key)
                .await
                .map_err(|error| db_error_to_machine(error, &record.id))?
        };
        let Some(existing) = select_auth_path_node(
            candidates,
            user_id,
            self.users.is_none(),
            false,
            !record.tags.is_empty(),
        )?
        else {
            return Ok(None);
        };
        Ok(Some(self.row_to_record(existing).await))
    }

    async fn create(
        &self,
        record: MachineAdminRecord,
    ) -> Result<MachineAdminRecord, MachineAdminError> {
        if record.id.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "node key must not be empty".into(),
            ));
        }
        let machine_key = key_without_prefix("mkey:", &record.machine_key_hex);
        let raw_node_key = key_without_prefix("nodekey:", record.id.trim());
        let registration = self.registration_guard(&machine_key).await;
        let node_key_registration = self.node_key_registration_guard(&raw_node_key).await;
        let administrator = Self::clone(self);
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = registration;
            let _node_key_registration = node_key_registration;
            let node_key = key_with_prefix("nodekey:", record.id.trim());
            match headscale_db::headscale_nodes::get_by_node_key(&administrator.pool, &node_key)
                .await
            {
                Ok(_) => return Err(MachineAdminError::BadRequest("node already exists".into())),
                Err(headscale_db::DbError::NotFound(_)) => {}
                Err(e) => return Err(db_error_to_machine(e, &record.id)),
            }
            let ipv4 = optional_ipv4(&record.ipv4)?;
            let ipv6 = optional_ipv6(record.ipv6.as_deref())?;
            require_any_address(ipv4, ipv6)?;
            administrator
                .reject_duplicate_addresses(None, &record)
                .await?;
            let user_id = administrator.user_id_for_record(&record).await?;
            let row = headscale_db::headscale_nodes::create(
                &administrator.pool,
                create_params_for_record(&record, user_id),
            )
            .await
            .map_err(|e| db_error_to_machine(e, &record.id))?;
            administrator.sync_wire_row(row.clone()).await?;
            Ok(administrator.row_to_record(row).await)
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node creation: {error}"))
        })?
    }

    async fn complete_registration(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        wire_record: Option<MachineRecord>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.complete_registration_with_hostinfo(record, policy, wire_record, None)
            .await
    }

    async fn complete_registration_with_hostinfo(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        wire_record: Option<MachineRecord>,
        hostinfo: Option<Value>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.create_or_update_auth_path_with_hostinfo(
            record,
            policy,
            None,
            None,
            true,
            wire_record.as_ref(),
            hostinfo,
        )
        .await
    }

    async fn complete_registration_with_user_snapshot(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        wire_record: Option<MachineRecord>,
        hostinfo: Option<Value>,
        user: super::users::UserRegistrationSnapshot,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.create_or_update_auth_path_with_user_snapshot(
            record,
            policy,
            None,
            None,
            true,
            wire_record.as_ref(),
            hostinfo,
            Some(&user),
        )
        .await
    }

    async fn expire_at(
        &self,
        id: &str,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node(
                registry.clone(),
                NativeNodeStore::Sqlite(self.pool.clone()),
                id,
                NativeNodeMutation::Expiry(Some(expiry.unwrap_or_else(Utc::now))),
            )
            .await;
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let current_key = key_without_prefix("nodekey:", &row.node_key);
            let stamp = expiry.unwrap_or_else(Utc::now);
            let row = headscale_db::headscale_nodes::set_expiry_precise(
                &administrator.pool,
                row.id,
                Some(stamp),
            )
            .await
            .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await?;
            if let Some(registry) = &administrator.wire_registry {
                registry
                    .try_set_expiry(&current_key, Some(stamp))
                    .map_err(MachineAdminError::Policy)?;
            }
            Ok(())
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn disable_expiry(&self, id: &str) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node(
                registry.clone(),
                NativeNodeStore::Sqlite(self.pool.clone()),
                id,
                NativeNodeMutation::Expiry(None),
            )
            .await;
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let row = headscale_db::headscale_nodes::set_expiry(&administrator.pool, row.id, None)
                .await
                .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn logout(&self, id: &str) -> Result<(), MachineAdminError> {
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let row = headscale_db::headscale_nodes::logout(&administrator.pool, row.id)
                .await
                .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn rename(&self, id: &str, hostname: &str) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node(
                registry.clone(),
                NativeNodeStore::Sqlite(self.pool.clone()),
                id,
                NativeNodeMutation::Rename(hostname.to_owned()),
            )
            .await;
        }
        if hostname.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "hostname must not be empty".into(),
            ));
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        let hostname = hostname.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let row = headscale_db::headscale_nodes::rename(
                &administrator.pool,
                row.id,
                hostname.as_str(),
            )
            .await
            .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn set_tags(&self, id: &str, tags: Vec<String>) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node(
                registry.clone(),
                NativeNodeStore::Sqlite(self.pool.clone()),
                id,
                NativeNodeMutation::Tags(tags),
            )
            .await;
        }
        if tags.is_empty() {
            return Err(MachineAdminError::BadRequest(EMPTY_TAGS_ERROR.into()));
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let row = headscale_db::headscale_nodes::set_tags(&administrator.pool, row.id, tags)
                .await
                .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn set_approved_routes(
        &self,
        id: &str,
        routes: Vec<String>,
    ) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node(
                registry.clone(),
                NativeNodeStore::Sqlite(self.pool.clone()),
                id,
                NativeNodeMutation::ApprovedRoutes(routes),
            )
            .await;
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let row = headscale_db::headscale_nodes::set_approved_routes(
                &administrator.pool,
                row.id,
                routes,
            )
            .await
            .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn set_routes(&self, id: &str, routes: Vec<String>) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node(
                registry.clone(),
                NativeNodeStore::Sqlite(self.pool.clone()),
                id,
                NativeNodeMutation::AvailableRoutes(routes),
            )
            .await;
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let row = headscale_db::headscale_nodes::set_host_info_routable_ips(
                &administrator.pool,
                row.id,
                routes,
            )
            .await
            .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn backfill_node_ips(
        &self,
        ip_allocator: Option<&dyn IpAllocator>,
    ) -> Result<Vec<String>, MachineAdminError> {
        let ip_allocator = ip_allocator.ok_or_else(|| {
            MachineAdminError::BadRequest("backfilling IPs: ip allocator was nil".into())
        })?;
        let selected = headscale_db::headscale_nodes::list(&self.pool)
            .await
            .map_err(|error| db_error_to_machine(error, "nodes"))?;
        let guards = lock_backfill_nodes(self.wire_registry.as_ref(), &selected).await;
        let mut rows = Vec::with_capacity(selected.len());
        for before in selected {
            let row = headscale_db::headscale_nodes::get_by_id(&self.pool, before.id)
                .await
                .map_err(|error| db_error_to_machine(error, &before.id.to_string()))?;
            if row.machine_key != before.machine_key {
                return Err(MachineAdminError::BadRequest(
                    "node registration changed during IP backfill; retry backfill".into(),
                ));
            }
            rows.push(row);
        }
        // Complete every awaitable snapshot read before reserving addresses.
        // No cancellation point separates allocation from spawning the owned
        // transaction/publication worker below.
        let mut updates = Vec::new();
        let mut changes = Vec::new();
        for row in rows {
            let (update, node_changes) = prepare_ip_backfill(&row, ip_allocator)?;
            if !node_changes.is_empty() {
                updates.push(update);
                changes.extend(node_changes);
            }
        }
        let administrator = Self::clone(self);
        crate::tailscale_wire::complete_state_mutation(async move {
            let _guards = guards;
            headscale_db::headscale_nodes::set_ip_addresses_batch(&administrator.pool, updates)
                .await
                .map_err(|error| db_error_to_machine(error, "nodes"))?;
            if !changes.is_empty()
                && let Some(registry) = &administrator.wire_registry
            {
                let rows = headscale_db::headscale_nodes::list(&administrator.pool)
                    .await
                    .map_err(|error| {
                        MachineAdminError::BadRequest(format!(
                            "refreshing NodeStore after IP backfill: {error}"
                        ))
                    })?;
                let mut records = Vec::with_capacity(rows.len());
                let mut native = Vec::with_capacity(rows.len());
                for row in rows {
                    let (record, association) = administrator
                        .row_to_wire_record_with_association(&row)
                        .await?;
                    let id = native_row_id(&row)?;
                    let mut captured = NativeNodePersistence::capture(&row, &record)?;
                    captured.set_associations(association);
                    native.push((id, captured));
                    records.push(record);
                }
                registry.refresh_nodes_after_ip_backfill(records, native);
            }
            Ok(changes)
        })
        .await
        .map_err(|error| MachineAdminError::BadRequest(format!("finishing IP backfill: {error}")))?
    }

    fn notify_user_removed_full_update(&self) -> bool {
        let Some(registry) = &self.wire_registry else {
            return false;
        };
        registry.wake_user_removed_full_update();
        true
    }

    async fn delete(&self, id: &str) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return delete_live_native_node(
                registry.clone(),
                NativeNodeStore::Sqlite(self.pool.clone()),
                id,
            )
            .await;
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let node_key_hex = key_without_prefix("nodekey:", &row.node_key);
            headscale_db::headscale_nodes::destroy(&administrator.pool, row.id)
                .await
                .map_err(|e| db_error_to_machine(e, &id))?;
            if let Some(registry) = &administrator.wire_registry {
                registry
                    .try_delete(&node_key_hex)
                    .map_err(MachineAdminError::Policy)?;
            }
            Ok(())
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }
}

#[cfg(feature = "postgres-sqlx")]
#[async_trait]
impl MachineAdmin for PersistentPostgresMachineAdmin {
    fn numeric_mutation_selector(&self, node_id: u64) -> Option<String> {
        Some(node_id.to_string())
    }

    async fn get_view(&self, id: &str) -> Result<Option<MachineAdminView>, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return checked_live_view(registry, id);
        }
        let row = match self.row_by_slug(id).await {
            Ok(row) => row,
            Err(MachineAdminError::NotFound(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        let (wire, associations) = self.row_to_wire_record_with_association(&row).await?;
        admin_view_from_native_row(&row, &wire, associations).map(Some)
    }

    async fn list_views(&self) -> Result<Vec<MachineAdminView>, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return checked_live_views(registry);
        }
        let rows = headscale_db::headscale_nodes::list_postgres(&self.pool)
            .await
            .map_err(|error| db_error_to_machine(error, "nodes"))?;
        let mut views = Vec::with_capacity(rows.len());
        for row in rows {
            let (wire, associations) = self.row_to_wire_record_with_association(&row).await?;
            views.push(admin_view_from_native_row(&row, &wire, associations)?);
        }
        Ok(views)
    }

    async fn mutate_with_view(
        &self,
        id: &str,
        mutation: MachineAdminMutation,
    ) -> Result<MachineAdminView, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node_with_view(
                registry.clone(),
                NativeNodeStore::Postgres(self.pool.clone()),
                id,
                mutation,
            )
            .await;
        }
        mutate_with_fallback_view(self, id, mutation).await
    }

    async fn policy_nodes_for_registration(
        &self,
    ) -> Result<Vec<PolicyCheckNode>, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return checked_live_policy_nodes(registry);
        }
        let rows = headscale_db::headscale_nodes::list_postgres(&self.pool)
            .await
            .map_err(|error| db_error_to_machine(error, "registration policy nodes"))?;
        let mut nodes = Vec::with_capacity(rows.len());
        for row in rows {
            let (record, association) = self.row_to_wire_record_with_association(&row).await?;
            nodes.push(policy_node_from_native_row(&row, &record, association)?);
        }
        Ok(nodes)
    }

    async fn policy_nodes_for_check(
        &self,
    ) -> Result<Vec<PolicyCheckNodeSnapshot>, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return checked_live_policy_check_snapshot(registry);
        }
        let rows = headscale_db::headscale_nodes::list_postgres(&self.pool)
            .await
            .map_err(|error| db_error_to_machine(error, "policy check nodes"))?;
        let mut nodes = Vec::with_capacity(rows.len());
        for row in rows {
            let (record, association) = self.row_to_wire_record_with_association(&row).await?;
            nodes.push(PolicyCheckNodeSnapshot {
                node: policy_node_from_native_row(&row, &record, association)?,
                advertised_routes: record.available_routes,
                approved_routes: record.approved_routes,
            });
        }
        Ok(nodes)
    }

    fn mutation_selector(&self, record: &MachineAdminRecord) -> String {
        let node_id = if record.node_id == 0 {
            crate::tailscale_wire::wire::stable_id_from_key(&record.id)
        } else {
            record.node_id
        };
        node_id.to_string()
    }

    async fn list_checked(&self) -> Result<Vec<MachineAdminRecord>, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return checked_live_records(registry);
        }
        let rows = headscale_db::headscale_nodes::list_postgres(&self.pool)
            .await
            .map_err(|error| db_error_to_machine(error, "policy nodes"))?;
        let mut records = Vec::with_capacity(rows.len());
        for row in rows {
            records.push(self.row_to_record(row).await);
        }
        Ok(records)
    }

    async fn list(&self) -> Vec<MachineAdminRecord> {
        match self.list_checked().await {
            Ok(records) => records,
            Err(error) => {
                tracing::warn!(?error, "persistent postgres machine list failed");
                Vec::new()
            }
        }
    }

    async fn auto_approve_routes(&self, policy: &PolicyStore) -> Result<usize, MachineAdminError> {
        let store = NativeNodeStore::Postgres(self.pool.clone());
        if let Some(registry) = &self.wire_registry {
            auto_approve_live_registry(policy, registry.clone(), store).await
        } else {
            let mut records = self.list_checked().await?;
            let identities = self.policy_nodes_for_registration().await?;
            for record in &mut records {
                if let Some(identity) = identities.iter().find(|node| node.id == record.node_id) {
                    record.user_id = identity.user_id;
                    record.user = identity.user.clone().unwrap_or_default();
                    record.ipv4 = identity
                        .addrs
                        .iter()
                        .find(|addr| !addr.contains(':'))
                        .cloned()
                        .unwrap_or_default();
                    record.ipv6 = identity
                        .addrs
                        .iter()
                        .find(|addr| addr.contains(':'))
                        .cloned();
                }
            }
            auto_approve_without_registry(policy, records, store).await
        }
    }

    async fn registration_guard(
        &self,
        machine_key: &str,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        match &self.wire_registry {
            Some(registry) => Some(registry.lock_registration(machine_key).await),
            None => None,
        }
    }

    async fn node_key_registration_guard(
        &self,
        node_key: &str,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        match &self.wire_registry {
            Some(registry) => Some(registry.lock_node_key_registration(node_key).await),
            None => None,
        }
    }

    async fn wire_record(&self, id: &str) -> Result<Option<MachineRecord>, MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return Ok(WireMachineAdmin::new(registry.clone())
                .selected_record(&key_without_prefix("nodekey:", id))
                .map(|(_, record)| record));
        }
        let row = self.row_by_slug(id).await?;
        self.row_to_wire_record(&row).await.map(Some)
    }

    async fn wire_record_for_publication(
        &self,
        id: &str,
        registry: Option<&MachineRegistry>,
    ) -> Result<Option<MachineRecord>, MachineAdminError> {
        if let Some(registry) = registry.or(self.wire_registry.as_deref()) {
            let cached = registry.get(&key_without_prefix("nodekey:", id));
            let node_id = cached
                .as_ref()
                .map(MachineRecord::stable_node_id)
                .or_else(|| id.parse().ok());
            if let Some(record) = node_id.and_then(|id| registry.native_registration_record(id)) {
                return Ok(Some(record));
            }
        }
        let row = self.row_by_slug(id).await?;
        let (record, association) = self.row_to_wire_record_with_association(&row).await?;
        if let Some(registry) = registry {
            stage_native_row(registry, &row, &record, association)?;
        }
        Ok(Some(record))
    }

    async fn raw_hostname(&self, id: &str) -> Option<String> {
        if let Some(registry) = &self.wire_registry {
            return WireMachineAdmin::new(registry.clone())
                .selected_record(&key_without_prefix("nodekey:", id))
                .map(|(_, record)| record.raw_hostname);
        }
        self.row_by_slug(id).await.ok().map(|row| row.hostname)
    }

    async fn get(&self, id: &str) -> Option<MachineAdminRecord> {
        if let Some(registry) = &self.wire_registry {
            return WireMachineAdmin::new(registry.clone())
                .get(&key_without_prefix("nodekey:", id))
                .await;
        }
        match self.row_by_slug(id).await {
            Ok(row) => Some(self.row_to_record(row).await),
            Err(MachineAdminError::NotFound(_)) => None,
            Err(e) => {
                tracing::warn!(?e, id, "persistent postgres machine get failed");
                None
            }
        }
    }

    async fn existing_auth_path_record(
        &self,
        record: &MachineAdminRecord,
    ) -> Option<MachineAdminRecord> {
        self.existing_auth_path_record_checked(record)
            .await
            .ok()
            .flatten()
    }

    async fn existing_auth_path_record_checked(
        &self,
        record: &MachineAdminRecord,
    ) -> Result<Option<MachineAdminRecord>, MachineAdminError> {
        let user_id = self.user_id_for_record(record).await?;
        if let Some(registry) = &self.wire_registry {
            registry
                .validate_registration_node_key(&record.id, &record.machine_key_hex)
                .map_err(|error| MachineAdminError::BadRequest(error.into()))?;
        }
        let machine_key = key_with_prefix("mkey:", &record.machine_key_hex);
        let candidates = if let Some(registry) = &self.wire_registry {
            registration_rows_from_cache(registry, &record.machine_key_hex)?
        } else {
            headscale_db::headscale_nodes::list_postgres_by_machine_key(&self.pool, &machine_key)
                .await
                .map_err(|error| db_error_to_machine(error, &record.id))?
        };
        let Some(existing) = select_auth_path_node(
            candidates,
            user_id,
            self.users.is_none(),
            false,
            !record.tags.is_empty(),
        )?
        else {
            return Ok(None);
        };
        Ok(Some(self.row_to_record(existing).await))
    }

    async fn create(
        &self,
        record: MachineAdminRecord,
    ) -> Result<MachineAdminRecord, MachineAdminError> {
        if record.id.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "node key must not be empty".into(),
            ));
        }
        let machine_key = key_without_prefix("mkey:", &record.machine_key_hex);
        let raw_node_key = key_without_prefix("nodekey:", record.id.trim());
        let registration = self.registration_guard(&machine_key).await;
        let node_key_registration = self.node_key_registration_guard(&raw_node_key).await;
        let administrator = Self::clone(self);
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = registration;
            let _node_key_registration = node_key_registration;
            let node_key = key_with_prefix("nodekey:", record.id.trim());
            match headscale_db::headscale_nodes::get_postgres_by_node_key(
                &administrator.pool,
                &node_key,
            )
            .await
            {
                Ok(_) => return Err(MachineAdminError::BadRequest("node already exists".into())),
                Err(headscale_db::DbError::NotFound(_)) => {}
                Err(e) => return Err(db_error_to_machine(e, &record.id)),
            }
            let ipv4 = optional_ipv4(&record.ipv4)?;
            let ipv6 = optional_ipv6(record.ipv6.as_deref())?;
            require_any_address(ipv4, ipv6)?;
            administrator
                .reject_duplicate_addresses(None, &record)
                .await?;
            let user_id = administrator.user_id_for_record(&record).await?;
            let row = headscale_db::headscale_nodes::create_postgres(
                &administrator.pool,
                create_params_for_record(&record, user_id),
            )
            .await
            .map_err(|e| db_error_to_machine(e, &record.id))?;
            administrator.sync_wire_row(row.clone()).await?;
            Ok(administrator.row_to_record(row).await)
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node creation: {error}"))
        })?
    }

    async fn complete_registration(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        wire_record: Option<MachineRecord>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.complete_registration_with_hostinfo(record, policy, wire_record, None)
            .await
    }

    async fn complete_registration_with_hostinfo(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        wire_record: Option<MachineRecord>,
        hostinfo: Option<Value>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.create_or_update_auth_path_with_hostinfo(
            record,
            policy,
            None,
            None,
            true,
            wire_record.as_ref(),
            hostinfo,
        )
        .await
    }

    async fn complete_registration_with_user_snapshot(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        wire_record: Option<MachineRecord>,
        hostinfo: Option<Value>,
        user: super::users::UserRegistrationSnapshot,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.create_or_update_auth_path_with_user_snapshot(
            record,
            policy,
            None,
            None,
            true,
            wire_record.as_ref(),
            hostinfo,
            Some(&user),
        )
        .await
    }

    async fn expire_at(
        &self,
        id: &str,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node(
                registry.clone(),
                NativeNodeStore::Postgres(self.pool.clone()),
                id,
                NativeNodeMutation::Expiry(Some(expiry.unwrap_or_else(Utc::now))),
            )
            .await;
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let current_key = key_without_prefix("nodekey:", &row.node_key);
            let stamp = expiry.unwrap_or_else(Utc::now);
            let row = headscale_db::headscale_nodes::set_postgres_expiry_precise(
                &administrator.pool,
                row.id,
                Some(stamp),
            )
            .await
            .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await?;
            if let Some(registry) = &administrator.wire_registry {
                registry
                    .try_set_expiry(&current_key, Some(stamp))
                    .map_err(MachineAdminError::Policy)?;
            }
            Ok(())
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn disable_expiry(&self, id: &str) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node(
                registry.clone(),
                NativeNodeStore::Postgres(self.pool.clone()),
                id,
                NativeNodeMutation::Expiry(None),
            )
            .await;
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let row = headscale_db::headscale_nodes::set_postgres_expiry(
                &administrator.pool,
                row.id,
                None,
            )
            .await
            .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn logout(&self, id: &str) -> Result<(), MachineAdminError> {
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let row = headscale_db::headscale_nodes::logout_postgres(&administrator.pool, row.id)
                .await
                .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn rename(&self, id: &str, hostname: &str) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node(
                registry.clone(),
                NativeNodeStore::Postgres(self.pool.clone()),
                id,
                NativeNodeMutation::Rename(hostname.to_owned()),
            )
            .await;
        }
        if hostname.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "hostname must not be empty".into(),
            ));
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        let hostname = hostname.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let row = headscale_db::headscale_nodes::rename_postgres(
                &administrator.pool,
                row.id,
                hostname.as_str(),
            )
            .await
            .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn set_tags(&self, id: &str, tags: Vec<String>) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node(
                registry.clone(),
                NativeNodeStore::Postgres(self.pool.clone()),
                id,
                NativeNodeMutation::Tags(tags),
            )
            .await;
        }
        if tags.is_empty() {
            return Err(MachineAdminError::BadRequest(EMPTY_TAGS_ERROR.into()));
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let row =
                headscale_db::headscale_nodes::set_postgres_tags(&administrator.pool, row.id, tags)
                    .await
                    .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn set_approved_routes(
        &self,
        id: &str,
        routes: Vec<String>,
    ) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node(
                registry.clone(),
                NativeNodeStore::Postgres(self.pool.clone()),
                id,
                NativeNodeMutation::ApprovedRoutes(routes),
            )
            .await;
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let row = headscale_db::headscale_nodes::set_postgres_approved_routes(
                &administrator.pool,
                row.id,
                routes,
            )
            .await
            .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn set_routes(&self, id: &str, routes: Vec<String>) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return mutate_live_native_node(
                registry.clone(),
                NativeNodeStore::Postgres(self.pool.clone()),
                id,
                NativeNodeMutation::AvailableRoutes(routes),
            )
            .await;
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let row = headscale_db::headscale_nodes::set_postgres_host_info_routable_ips(
                &administrator.pool,
                row.id,
                routes,
            )
            .await
            .map_err(|e| db_error_to_machine(e, &id))?;
            administrator.sync_wire_row(row).await
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }

    async fn backfill_node_ips(
        &self,
        ip_allocator: Option<&dyn IpAllocator>,
    ) -> Result<Vec<String>, MachineAdminError> {
        let ip_allocator = ip_allocator.ok_or_else(|| {
            MachineAdminError::BadRequest("backfilling IPs: ip allocator was nil".into())
        })?;
        let selected = headscale_db::headscale_nodes::list_postgres(&self.pool)
            .await
            .map_err(|error| db_error_to_machine(error, "nodes"))?;
        let guards = lock_backfill_nodes(self.wire_registry.as_ref(), &selected).await;
        let mut rows = Vec::with_capacity(selected.len());
        for before in selected {
            let row = headscale_db::headscale_nodes::get_postgres_by_id(&self.pool, before.id)
                .await
                .map_err(|error| db_error_to_machine(error, &before.id.to_string()))?;
            if row.machine_key != before.machine_key {
                return Err(MachineAdminError::BadRequest(
                    "node registration changed during IP backfill; retry backfill".into(),
                ));
            }
            rows.push(row);
        }
        // Complete every awaitable snapshot read before reserving addresses.
        // No cancellation point separates allocation from spawning the owned
        // transaction/publication worker below.
        let mut updates = Vec::new();
        let mut changes = Vec::new();
        for row in rows {
            let (update, node_changes) = prepare_ip_backfill(&row, ip_allocator)?;
            if !node_changes.is_empty() {
                updates.push(update);
                changes.extend(node_changes);
            }
        }
        let administrator = Self::clone(self);
        crate::tailscale_wire::complete_state_mutation(async move {
            let _guards = guards;
            headscale_db::headscale_nodes::set_postgres_ip_addresses_batch(
                &administrator.pool,
                updates,
            )
            .await
            .map_err(|error| db_error_to_machine(error, "nodes"))?;
            if !changes.is_empty()
                && let Some(registry) = &administrator.wire_registry
            {
                let rows = headscale_db::headscale_nodes::list_postgres(&administrator.pool)
                    .await
                    .map_err(|error| {
                        MachineAdminError::BadRequest(format!(
                            "refreshing NodeStore after IP backfill: {error}"
                        ))
                    })?;
                let mut records = Vec::with_capacity(rows.len());
                let mut native = Vec::with_capacity(rows.len());
                for row in rows {
                    let (record, association) = administrator
                        .row_to_wire_record_with_association(&row)
                        .await?;
                    let id = native_row_id(&row)?;
                    let mut captured = NativeNodePersistence::capture(&row, &record)?;
                    captured.set_associations(association);
                    native.push((id, captured));
                    records.push(record);
                }
                registry.refresh_nodes_after_ip_backfill(records, native);
            }
            Ok(changes)
        })
        .await
        .map_err(|error| MachineAdminError::BadRequest(format!("finishing IP backfill: {error}")))?
    }

    fn notify_user_removed_full_update(&self) -> bool {
        let Some(registry) = &self.wire_registry else {
            return false;
        };
        registry.wake_user_removed_full_update();
        true
    }

    async fn delete(&self, id: &str) -> Result<(), MachineAdminError> {
        if let Some(registry) = &self.wire_registry {
            return delete_live_native_node(
                registry.clone(),
                NativeNodeStore::Postgres(self.pool.clone()),
                id,
            )
            .await;
        }
        let (_registration, row) = self.lock_existing_node(id).await?;
        let administrator = Self::clone(self);
        let id = id.to_owned();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _registration = _registration;
            let node_key_hex = key_without_prefix("nodekey:", &row.node_key);
            headscale_db::headscale_nodes::destroy_postgres(&administrator.pool, row.id)
                .await
                .map_err(|e| db_error_to_machine(e, &id))?;
            if let Some(registry) = &administrator.wire_registry {
                registry
                    .try_delete(&node_key_hex)
                    .map_err(MachineAdminError::Policy)?;
            }
            Ok(())
        })
        .await
        .map_err(|error| {
            MachineAdminError::BadRequest(format!("finishing node mutation: {error}"))
        })?
    }
}

#[async_trait]
impl MachineAdmin for WireMachineAdmin {
    fn numeric_mutation_selector(&self, node_id: u64) -> Option<String> {
        Some(node_id.to_string())
    }

    async fn get_view(&self, id: &str) -> Result<Option<MachineAdminView>, MachineAdminError> {
        checked_live_view(&self.registry, id)
    }

    async fn list_views(&self) -> Result<Vec<MachineAdminView>, MachineAdminError> {
        checked_live_views(&self.registry)
    }

    async fn mutate_with_view(
        &self,
        id: &str,
        mutation: MachineAdminMutation,
    ) -> Result<MachineAdminView, MachineAdminError> {
        mutate_live_native_node_with_view(
            self.registry.clone(),
            NativeNodeStore::Volatile,
            id,
            mutation,
        )
        .await
    }

    async fn policy_nodes_for_registration(
        &self,
    ) -> Result<Vec<PolicyCheckNode>, MachineAdminError> {
        checked_live_policy_nodes(&self.registry)
    }

    async fn policy_nodes_for_check(
        &self,
    ) -> Result<Vec<PolicyCheckNodeSnapshot>, MachineAdminError> {
        checked_live_policy_check_snapshot(&self.registry)
    }

    async fn list_checked(&self) -> Result<Vec<MachineAdminRecord>, MachineAdminError> {
        checked_live_records(&self.registry)
    }

    async fn auto_approve_routes(&self, policy: &PolicyStore) -> Result<usize, MachineAdminError> {
        auto_approve_live_registry(policy, self.registry.clone(), NativeNodeStore::Volatile).await
    }

    fn mutation_selector(&self, record: &MachineAdminRecord) -> String {
        let node_id = if record.node_id == 0 {
            crate::tailscale_wire::wire::stable_id_from_key(&record.id)
        } else {
            record.node_id
        };
        node_id.to_string()
    }

    async fn list(&self) -> Vec<MachineAdminRecord> {
        let online_states = self.registry.online_states();
        // #238: walk borrowed entries and clone only the admin DTO fields.
        let snapshot = self.registry.snapshot();
        let mut out: Vec<_> = snapshot
            .iter()
            .map(|(k, rec)| {
                let online = online_states
                    .get(&rec.stable_node_id_for_key(k))
                    .copied()
                    .unwrap_or(false);
                Self::render(k.as_str(), rec, online)
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        out
    }

    async fn registration_guard(
        &self,
        machine_key: &str,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        Some(self.registry.lock_registration(machine_key).await)
    }

    async fn node_key_registration_guard(
        &self,
        node_key: &str,
    ) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        Some(self.registry.lock_node_key_registration(node_key).await)
    }

    async fn wire_record(&self, id: &str) -> Result<Option<MachineRecord>, MachineAdminError> {
        Ok(self.selected_record(id).map(|(_, record)| record))
    }

    async fn raw_hostname(&self, id: &str) -> Option<String> {
        self.selected_record(id)
            .map(|(_, record)| record.raw_hostname)
    }

    async fn get(&self, id: &str) -> Option<MachineAdminRecord> {
        let (current_key, rec) = self.selected_record(id)?;
        let online = self
            .registry
            .online_states()
            .get(&rec.stable_node_id_for_key(&current_key))
            .copied()
            .unwrap_or(false);
        Some(Self::render(&current_key, &rec, online))
    }

    async fn existing_auth_path_record(
        &self,
        record: &MachineAdminRecord,
    ) -> Option<MachineAdminRecord> {
        self.existing_auth_path_record_checked(record)
            .await
            .ok()
            .flatten()
    }

    async fn existing_auth_path_record_checked(
        &self,
        record: &MachineAdminRecord,
    ) -> Result<Option<MachineAdminRecord>, MachineAdminError> {
        self.registry
            .validate_registration_node_key(&record.id, &record.machine_key_hex)
            .map_err(|error| MachineAdminError::BadRequest(error.into()))?;
        let existing = self
            .registry
            .auth_path_existing_machine(&record.machine_key_hex, &record.user, record.user_id)
            .map_err(|error| MachineAdminError::BadRequest(error.into()))?;
        Ok(existing.map(|(_, existing)| machine_admin_record_from_wire(&existing)))
    }

    async fn create(
        &self,
        record: MachineAdminRecord,
    ) -> Result<MachineAdminRecord, MachineAdminError> {
        if record.id.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "node key must not be empty".into(),
            ));
        }
        let mut wire = machine_admin_record_to_wire(&record)?;
        if wire.is_tagged() {
            wire.clear_user_identity();
        }
        let _registration = self.registry.lock_registration(&wire.machine_key_hex).await;
        let _node_key_registration = self
            .registry
            .lock_node_key_registration(&wire.node_key_hex)
            .await;
        let committed = self
            .registry
            .insert_volatile_admin_record(wire)
            .map_err(MachineAdminError::from)?;
        let online = self
            .registry
            .online_states()
            .get(&committed.stable_node_id_for_key(&committed.node_key_hex))
            .copied()
            .unwrap_or(false);
        Ok(Self::render(&committed.node_key_hex, &committed, online))
    }

    async fn complete_registration(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        wire_record: Option<MachineRecord>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.complete_registration_with_hostinfo(record, policy, wire_record, None)
            .await
    }

    async fn complete_registration_with_hostinfo(
        &self,
        mut record: MachineAdminRecord,
        policy: &PolicyStore,
        wire_record: Option<MachineRecord>,
        hostinfo: Option<Value>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        let existing = self
            .registry
            .auth_path_existing_machine(&record.machine_key_hex, &record.user, record.user_id)
            .map_err(|error| MachineAdminError::BadRequest(error.into()))?;
        let existing_record = existing
            .as_ref()
            .map(|(_, node)| machine_admin_record_from_wire(node));
        let nodes = if record.tags.is_empty() {
            Vec::new()
        } else {
            self.policy_nodes_for_registration().await?
        };
        validate_auth_path_tags_with_nodes(policy, &mut record, existing_record.as_ref(), &nodes)
            .map_err(MachineAdminError::BadRequest)?;
        let old_node_key_hex = existing.map(|(node_key, _)| node_key);
        let wire = canonical_wire_record_for_auth_path(&record, wire_record.as_ref())?;
        let registered = self
            .registry
            .complete_web_registration_with_hostinfo(
                wire,
                &record.user,
                record.register_method,
                hostinfo,
            )
            .map_err(MachineAdminError::from)?;
        let replaced_node_key_hex = old_node_key_hex
            .as_ref()
            .filter(|old_node_key_hex| *old_node_key_hex != &registered.node_key_hex)
            .cloned();
        let record = machine_admin_record_from_wire(&registered);
        Ok(AuthPathRegistrationResult {
            new_node: old_node_key_hex.is_none(),
            replaced_node_key_hex,
            record,
        })
    }

    async fn expire_at(
        &self,
        id: &str,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), MachineAdminError> {
        let (_registration, current_key) = self.lock_existing_node(id).await?;
        let id = current_key.as_str();
        // Write through to the wire layer so the next /map call returns
        // a logout response. `None` ⇒ expire immediately.
        let stamp = expiry.unwrap_or_else(Utc::now);
        if !self
            .registry
            .try_set_expiry(id, Some(stamp))
            .map_err(MachineAdminError::Policy)?
        {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn disable_expiry(&self, id: &str) -> Result<(), MachineAdminError> {
        let (_registration, current_key) = self.lock_existing_node(id).await?;
        let id = current_key.as_str();
        if !self
            .registry
            .try_set_expiry(id, None)
            .map_err(MachineAdminError::Policy)?
        {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn logout(&self, id: &str) -> Result<(), MachineAdminError> {
        let (_registration, current_key) = self.lock_existing_node(id).await?;
        let id = current_key.as_str();
        if !self
            .registry
            .try_set_expiry(id, Some(Utc::now()))
            .map_err(MachineAdminError::Policy)?
        {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn rename(&self, id: &str, hostname: &str) -> Result<(), MachineAdminError> {
        self.registry
            .validate_given_name(hostname)
            .map_err(MachineAdminError::BadRequest)?;
        let (_registration, current_key) = self.lock_existing_node(id).await?;
        let id = current_key.as_str();
        if self
            .registry
            .snapshot()
            .iter()
            .any(|(node_key, rec)| node_key != id && rec.hostname == hostname)
        {
            return Err(MachineAdminError::BadRequest(
                "given name already in use by another node".into(),
            ));
        }
        if !self
            .registry
            .try_rename(id, hostname.to_string())
            .map_err(MachineAdminError::Policy)?
        {
            return Err(if self.registry.get(id).is_some() {
                MachineAdminError::BadRequest("given name already in use by another node".into())
            } else {
                MachineAdminError::NotFound(id.to_string())
            });
        }
        Ok(())
    }

    async fn set_tags(&self, id: &str, tags: Vec<String>) -> Result<(), MachineAdminError> {
        if tags.is_empty() {
            return Err(MachineAdminError::BadRequest(EMPTY_TAGS_ERROR.into()));
        }
        let (_registration, current_key) = self.lock_existing_node(id).await?;
        let id = current_key.as_str();
        if !self
            .registry
            .try_set_forced_tags(id, tags)
            .map_err(MachineAdminError::Policy)?
        {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn set_approved_routes(
        &self,
        id: &str,
        routes: Vec<String>,
    ) -> Result<(), MachineAdminError> {
        let (_registration, current_key) = self.lock_existing_node(id).await?;
        let id = current_key.as_str();
        if !self
            .registry
            .try_set_approved_routes(id, routes)
            .map_err(MachineAdminError::Policy)?
        {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn set_approved_routes_batch(
        &self,
        updates: Vec<(String, Vec<String>)>,
    ) -> Result<usize, MachineAdminError> {
        if updates.is_empty() {
            return Ok(0);
        }
        let ids = updates.iter().map(|(id, _)| id.clone()).collect::<Vec<_>>();
        let (_registration, current_keys) = self.lock_existing_nodes(&ids).await?;
        let updates = updates
            .into_iter()
            .zip(current_keys)
            .map(|((_, routes), id)| (id, routes))
            .collect();
        let (changed, missing) = self
            .registry
            .try_set_approved_routes_many(updates)
            .map_err(MachineAdminError::Policy)?;
        if let Some(id) = missing.into_iter().next() {
            return Err(MachineAdminError::NotFound(id));
        }
        Ok(changed)
    }

    async fn set_routes(&self, id: &str, routes: Vec<String>) -> Result<(), MachineAdminError> {
        let (_registration, current_key) = self.lock_existing_node(id).await?;
        let id = current_key.as_str();
        if !self
            .registry
            .try_set_available_routes(id, routes)
            .map_err(MachineAdminError::Policy)?
        {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    fn notify_user_removed_full_update(&self) -> bool {
        self.registry.wake_user_removed_full_update();
        true
    }

    async fn delete(&self, id: &str) -> Result<(), MachineAdminError> {
        let (_registration, current_key) = self.lock_existing_node(id).await?;
        if !self
            .registry
            .try_delete(&current_key)
            .map_err(MachineAdminError::Policy)?
        {
            return Err(MachineAdminError::NotFound(id.to_owned()));
        }
        Ok(())
    }
}

fn create_params_for_record(
    record: &MachineAdminRecord,
    user_id: Option<i64>,
) -> headscale_db::headscale_nodes::CreateParams {
    create_params_for_record_with_auth_key(record, user_id, None)
}

fn create_params_for_record_with_auth_key(
    record: &MachineAdminRecord,
    user_id: Option<i64>,
    auth_key_id: Option<i64>,
) -> headscale_db::headscale_nodes::CreateParams {
    headscale_db::headscale_nodes::CreateParams {
        machine_key: key_with_prefix("mkey:", &record.machine_key_hex),
        node_key: key_with_prefix("nodekey:", &record.id),
        disco_key: if record.disco_key.is_empty() {
            ZERO_DISCO_KEY.to_string()
        } else {
            record.disco_key.clone()
        },
        endpoints: Vec::new(),
        host_info: host_info_for_record(record),
        ipv4: optional_ipv4_string(&record.ipv4),
        ipv6: record.ipv6.clone(),
        hostname: record.name.clone(),
        given_name: record.name.clone(),
        user_id,
        register_method: register_method_to_db(record.register_method),
        tags: record.tags.clone(),
        auth_key_id,
        expiry: record.expiry.map(|expiry| expiry as i64),
        expiry_precise: record.expiry_precise,
        last_seen: (record.last_seen != 0).then_some(record.last_seen as i64),
        last_seen_precise: record.last_seen_precise,
        approved_routes: record.approved_routes.clone(),
    }
}

fn create_params_for_auth_path(
    record: &MachineAdminRecord,
    wire_record: Option<&MachineRecord>,
    user_id: Option<i64>,
    auth_key_id: Option<i64>,
    existing: Option<&headscale_db::headscale_nodes::HeadscaleNodeRow>,
) -> Result<headscale_db::headscale_nodes::CreateParams, MachineAdminError> {
    let mut canonical = canonical_wire_record_for_auth_path(record, wire_record)?;
    let tagged = !record.tags.is_empty();
    let was_tagged = match existing {
        Some(row) => !row
            .try_tag_list()
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?
            .is_empty(),
        None => false,
    };
    if tagged && existing.is_none() && record.register_method != REGISTER_METHOD_AUTH_KEY {
        canonical.compact_fresh_web_request_tags();
    }
    let effective_user_id = if tagged { None } else { user_id };
    let effective_auth_key_id = if was_tagged && !tagged {
        None
    } else {
        auth_key_id.or_else(|| existing.and_then(|row| row.auth_key_id))
    };
    let preserved_netinfo = if canonical.host_info_for_node().net_info.is_none() {
        existing
            .map(headscale_db::headscale_nodes::HeadscaleNodeRow::try_host_info_value)
            .transpose()
            .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?
            .and_then(|value| value.get("NetInfo").cloned())
    } else {
        None
    };
    if let Some(existing) = existing {
        let mut host_info = canonical.host_info_for_node();
        if host_info.net_info.is_none() {
            host_info.net_info = host_info_from_row(existing)?.net_info;
        }
        canonical.replace_host_info(host_info);
        if canonical.endpoints.is_empty() {
            canonical.endpoints = existing
                .try_endpoint_list()
                .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
        }
    }
    let mut params =
        create_params_for_wire_record(&canonical, effective_user_id, effective_auth_key_id)?;
    if let Some(netinfo) = preserved_netinfo {
        params.host_info["NetInfo"] = netinfo;
    }
    if record.register_method != REGISTER_METHOD_AUTH_KEY
        && (!was_tagged || tagged)
        && let Some(existing) = existing
    {
        params.register_method.clone_from(&existing.register_method);
    }
    if tagged && was_tagged {
        let now = Utc::now();
        params.expiry_precise = existing
            .and_then(|row| {
                row.expiry_text
                    .as_deref()
                    .and_then(precise_stored_timestamp)
                    .or_else(|| {
                        row.expiry
                            .and_then(|expiry| DateTime::from_timestamp(expiry, 0))
                    })
            })
            .filter(|expiry| *expiry >= now);
        params.expiry = params.expiry_precise.map(|expiry| expiry.timestamp());
    }
    if let Some(existing) = existing {
        if !existing.given_name.is_empty()
            && !is_auto_derived_given_name(&existing.given_name, &existing.hostname)
        {
            params.given_name.clone_from(&existing.given_name);
        } else {
            params.given_name.clear();
        }
    } else {
        params.given_name.clear();
    }
    params.ipv6.clone_from(&record.ipv6);
    Ok(params)
}

fn canonical_wire_record_for_auth_path(
    record: &MachineAdminRecord,
    wire_record: Option<&MachineRecord>,
) -> Result<MachineRecord, MachineAdminError> {
    let mut canonical = match wire_record {
        Some(wire_record) => wire_record.clone(),
        None => machine_admin_record_to_wire(record)?,
    };
    if wire_record.is_some() {
        canonical
            .raw_hostname
            .clone_from(&canonical.host_info.hostname);
    }
    canonical.node_key_hex.clone_from(&record.id);
    canonical.node_id = (record.node_id != 0).then_some(record.node_id);
    canonical
        .machine_key_hex
        .clone_from(&record.machine_key_hex);
    canonical.user.clone_from(&record.user);
    canonical.user_id = record.user_id;
    canonical.hostname.clone_from(&record.name);
    let ipv4 = optional_ipv4(&record.ipv4)?;
    let ipv6 = optional_ipv6(record.ipv6.as_deref())?;
    require_any_address(ipv4, ipv6)?;
    canonical.ipv4 = ipv4;
    canonical.ipv6 = ipv6;
    canonical.last_seen = if let Some(value) = record.last_seen_precise {
        value
    } else {
        unix_timestamp_for_record(record.last_seen, &record.id, "last_seen")?
    };
    canonical.expiry = record.expiry_precise.or(record
        .expiry
        .map(|expiry| unix_timestamp_for_record(expiry, &record.id, "expiry"))
        .transpose()?);
    if wire_record.is_none() {
        canonical.os.clone_from(&record.os);
        canonical.os_version.clone_from(&record.version);
    }
    canonical.forced_tags.clone_from(&record.tags);
    canonical.available_routes.clone_from(&record.routes);
    canonical
        .approved_routes
        .clone_from(&record.approved_routes);
    canonical.register_method = record.register_method;
    Ok(canonical)
}

fn create_params_for_wire_record(
    record: &MachineRecord,
    user_id: Option<i64>,
    auth_key_id: Option<i64>,
) -> Result<headscale_db::headscale_nodes::CreateParams, MachineAdminError> {
    let admin = machine_admin_record_from_wire(record);
    let mut params = create_params_for_record_with_auth_key(&admin, user_id, auth_key_id);
    params.hostname.clone_from(&record.raw_hostname);
    params.disco_key = record
        .disco_key
        .clone()
        .unwrap_or_else(|| ZERO_DISCO_KEY.to_string());
    params.endpoints.clone_from(&record.endpoints);
    params.host_info = host_info_for_wire_record(record)?;
    Ok(params)
}

fn machine_admin_record_from_wire(record: &MachineRecord) -> MachineAdminRecord {
    let expired = record.is_expired_at(Utc::now());
    MachineAdminRecord {
        node_id: record.node_id.unwrap_or_default(),
        id: record.node_key_hex.clone(),
        name: record.hostname.clone(),
        user: record.user.clone(),
        user_id: record.user_id,
        auth_key_id: record.auth_key_id,
        ipv4: record.ipv4.map(|addr| addr.to_string()).unwrap_or_default(),
        ipv6: record.ipv6.map(|ipv6| ipv6.to_string()),
        online: !expired,
        last_seen: record.last_seen.timestamp().max(0) as u64,
        last_seen_precise: Some(record.last_seen),
        created_at: record.created_at.timestamp().max(0) as u64,
        created_at_precise: Some(record.created_at),
        expiry: record.expiry.map(|expiry| expiry.timestamp().max(0) as u64),
        expiry_precise: record.expiry,
        machine_key_hex: record.machine_key_hex.clone(),
        disco_key: record.disco_key.clone().unwrap_or_default(),
        os: nonempty_or_unknown(&record.os),
        version: nonempty_or_unknown(&record.os_version),
        tags: record.forced_tags.clone(),
        routes: record.available_routes.clone(),
        approved_routes: record.approved_routes.clone(),
        register_method: record.register_method,
        expired,
    }
}

fn machine_admin_record_to_wire(
    machine: &MachineAdminRecord,
) -> Result<MachineRecord, MachineAdminError> {
    if machine.id.trim().is_empty() {
        return Err(MachineAdminError::BadRequest(
            "persisted node has empty node key".to_string(),
        ));
    }
    let created_at = if let Some(value) = machine.created_at_precise {
        value
    } else {
        unix_timestamp_for_record(machine.created_at, &machine.id, "created_at")?
    };
    let last_seen = if let Some(value) = machine.last_seen_precise {
        value
    } else {
        unix_timestamp_for_record(machine.last_seen, &machine.id, "last_seen")?
    };
    let ipv4 = optional_ipv4(&machine.ipv4)?;
    let ipv6 = optional_ipv6(machine.ipv6.as_deref())?;
    require_any_address(ipv4, ipv6)?;
    let mut record = MachineRecord::new_at_with_addresses(
        created_at,
        machine.id.clone(),
        machine.machine_key_hex.clone(),
        machine.user.clone(),
        machine.name.clone(),
        ipv4,
        ipv6,
        false,
    );
    record.node_id = (machine.node_id != 0).then_some(machine.node_id);
    record.user_id = machine.user_id;
    record.auth_key_id = machine.auth_key_id;
    record.expiry = machine.expiry_precise.or(machine
        .expiry
        .map(|expiry| unix_timestamp_for_record(expiry, &machine.id, "expiry"))
        .transpose()?);
    record.last_seen = last_seen;
    record.os.clone_from(&machine.os);
    record.os_version.clone_from(&machine.version);
    record.forced_tags.clone_from(&machine.tags);
    record.available_routes.clone_from(&machine.routes);
    record.approved_routes.clone_from(&machine.approved_routes);
    record.register_method = machine.register_method;
    record.disco_key = (!machine.disco_key.is_empty()).then_some(machine.disco_key.clone());
    record.host_info = HostInfo {
        hostname: record.hostname.clone(),
        os: record.os.clone(),
        os_version: record.os_version.clone(),
        routable_ips: record.available_routes.clone(),
        ssh_host_keys: record.ssh_host_keys.clone(),
        ..HostInfo::default()
    };
    Ok(record)
}

fn unix_timestamp_for_record(
    timestamp: u64,
    node_key: &str,
    field: &str,
) -> Result<DateTime<Utc>, MachineAdminError> {
    let timestamp = i64::try_from(timestamp).map_err(|_| {
        MachineAdminError::BadRequest(format!(
            "persisted node {node_key} has out-of-range {field} timestamp"
        ))
    })?;
    chrono::DateTime::from_timestamp(timestamp, 0).ok_or_else(|| {
        MachineAdminError::BadRequest(format!(
            "persisted node {node_key} has invalid {field} timestamp"
        ))
    })
}

fn user_login_name(user: &crate::admin::users::UserRecord) -> String {
    if !user.email.is_empty() {
        user.email.clone()
    } else if !user.name.is_empty() {
        user.name.clone()
    } else if !user.provider_id.is_empty() {
        user.provider_id.clone()
    } else {
        user.id.to_string()
    }
}

fn identity_from_loaded_user(raw_id: Option<i64>, user: Option<&UserRecord>) -> UserIdentity {
    let mut identity = match user {
        Some(user) => user_identity_from_record(user),
        None => UserIdentity {
            association: Some(None),
            ..Default::default()
        },
    };
    identity.id = raw_id.and_then(|id| u64::try_from(id).ok());
    identity
}

fn user_identity_from_record(user: &UserRecord) -> UserIdentity {
    let login_name = user_login_name(user);
    UserIdentity {
        association: Some(Some(user.clone())),
        id: Some(user.id),
        display_name: if user.display_name.is_empty() {
            login_name.clone()
        } else {
            user.display_name.clone()
        },
        login_name,
        profile_pic_url: user.profile_pic_url.clone(),
        provider: user.provider.clone(),
        created_at: user.created_at_precise.or_else(|| {
            i64::try_from(user.created_at)
                .ok()
                .filter(|timestamp| *timestamp > 0)
                .and_then(|timestamp| DateTime::from_timestamp(timestamp, 0))
        }),
    }
}

fn apply_loaded_user_identity(
    record: &mut MachineRecord,
    association: Option<&Option<UserRecord>>,
) {
    let Some(user) = association else {
        return;
    };
    let identity = user
        .as_ref()
        .map(user_identity_from_record)
        .unwrap_or_default();
    record.set_user_identity(
        record.user_id,
        identity.login_name,
        identity.display_name,
        identity.profile_pic_url,
    );
    record.set_user_account_metadata(identity.provider, identity.created_at);
}

fn unloaded_user_identity(raw: Option<i64>) -> UserIdentity {
    let Some(raw) = raw else {
        return UserIdentity {
            association: Some(None),
            ..Default::default()
        };
    };
    let name = raw.to_string();
    UserIdentity {
        id: u64::try_from(raw).ok(),
        login_name: name.clone(),
        display_name: name,
        ..Default::default()
    }
}

type RegistrationUserAssociation = (
    Option<Option<super::users::UserRecord>>,
    Option<headscale_db::users::UserWriteSnapshot>,
);

async fn hydrate_wire_owner_from_user_admin(
    users: Option<&Arc<dyn UserAdmin>>,
    registry: Option<&MachineRegistry>,
    user_id: u64,
    wire_record: &mut MachineRecord,
) {
    if wire_record.is_tagged() {
        wire_record.clear_user_identity();
        return;
    }
    let user = match registry.and_then(|registry| registry.cached_native_user(wire_record)) {
        Some(Some(user)) => user,
        Some(None) => {
            wire_record.set_user_identity(
                wire_record.user_id,
                String::new(),
                String::new(),
                String::new(),
            );
            wire_record.set_user_account_metadata(String::new(), None);
            return;
        }
        None => {
            let Some(users) = users else {
                return;
            };
            let Ok(Some(user)) = users.get_for_node_association(user_id).await else {
                return;
            };
            user
        }
    };
    let identity = user_identity_from_record(&user);
    wire_record.set_user_identity(
        wire_record.user_id,
        identity.login_name,
        identity.display_name,
        identity.profile_pic_url,
    );
    wire_record.set_user_account_metadata(identity.provider, identity.created_at);
}

fn key_with_prefix(prefix: &str, value: &str) -> String {
    if value.is_empty() || value.starts_with(prefix) {
        value.to_string()
    } else {
        format!("{prefix}{value}")
    }
}

fn key_without_prefix(prefix: &str, value: &str) -> String {
    value.strip_prefix(prefix).unwrap_or(value).to_string()
}

fn register_method_to_db(method: i32) -> String {
    match method {
        1 => headscale_db::headscale_nodes::REGISTER_METHOD_AUTH_KEY.to_string(),
        2 => headscale_db::headscale_nodes::REGISTER_METHOD_CLI.to_string(),
        3 => headscale_db::headscale_nodes::REGISTER_METHOD_OIDC.to_string(),
        _ => String::new(),
    }
}

fn register_method_from_db(method: &str) -> i32 {
    match method {
        headscale_db::headscale_nodes::REGISTER_METHOD_AUTH_KEY => 1,
        headscale_db::headscale_nodes::REGISTER_METHOD_CLI => 2,
        headscale_db::headscale_nodes::REGISTER_METHOD_OIDC => 3,
        _ => 0,
    }
}

fn routes_from_host_info(host_info: &Value) -> Vec<String> {
    host_info
        .get("RoutableIPs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
}

#[cfg(test)]
fn ssh_host_keys_from_host_info(host_info: &Value) -> Vec<String> {
    host_info
        .get("sshHostKeys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(ToString::to_string)
        .collect()
}

fn preferred_derp_from_host_info(host_info: &Value) -> i32 {
    host_info
        .get("NetInfo")
        .and_then(|net_info| net_info.get("PreferredDERP"))
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or_default()
}

fn os_from_host_info(host_info: &Value) -> String {
    host_info
        .get("OS")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

fn version_from_host_info(host_info: &Value) -> String {
    host_info
        .get("OSVersion")
        .or_else(|| host_info.get("App"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string()
}

fn host_info_from_value(host_info: &Value) -> Result<HostInfo, MachineAdminError> {
    if host_info.is_null() {
        return Ok(HostInfo::default());
    }
    serde_json::from_value(host_info.clone()).map_err(|_| {
        MachineAdminError::BadRequest(
            "persisted Hostinfo cannot be represented by the wire projection".into(),
        )
    })
}

fn host_info_from_row(
    row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
) -> Result<HostInfo, MachineAdminError> {
    let value = row
        .try_host_info_value()
        .map_err(|error| MachineAdminError::BadRequest(error.to_string()))?;
    host_info_from_value(&value)
}

fn host_info_for_record(record: &MachineAdminRecord) -> Value {
    json!({
        "Hostname": record.name,
        "OS": record.os,
        "OSVersion": record.version,
        "RoutableIPs": record.routes,
    })
}

fn host_info_for_wire_record(record: &MachineRecord) -> Result<Value, MachineAdminError> {
    native_snapshot::encode_hostinfo(&record.host_info_for_node())
}

fn db_error_to_machine(e: headscale_db::DbError, subject: &str) -> MachineAdminError {
    match e {
        headscale_db::DbError::NotFound(_) => MachineAdminError::NotFound(subject.to_string()),
        headscale_db::DbError::General(msg)
            if msg.contains("hostname")
                || msg.contains("name is not unique")
                || msg.contains("already exists") =>
        {
            MachineAdminError::BadRequest(msg)
        }
        other => MachineAdminError::BadRequest(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::users::PersistentUserAdmin;
    use super::*;
    use crate::oidc::OidcRegistrationHandler;
    use crate::policy::parse_hujson_policy;
    use crate::tailscale_wire::{AllocError, MachineRecord, MachineRegistry, SshCheckBinding};
    use chrono::TimeZone;
    use headscale_db::Database;
    use std::net::{Ipv4Addr, Ipv6Addr};

    struct FixedDualStackAllocator(Ipv4Addr, Ipv6Addr);

    impl IpAllocator for FixedDualStackAllocator {
        fn allocate(&self, _node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
            Ok(self.0)
        }

        fn allocate_ipv6(&self, _node_key_hex: &str) -> Result<Option<Ipv6Addr>, AllocError> {
            Ok(Some(self.1))
        }
    }

    struct FixedIpv4OnlyAllocator(Ipv4Addr);

    impl IpAllocator for FixedIpv4OnlyAllocator {
        fn allocate(&self, _node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
            Ok(self.0)
        }

        fn ipv6_enabled(&self) -> bool {
            false
        }
    }

    struct FixedIpv6OnlyAllocator(Ipv6Addr);

    impl IpAllocator for FixedIpv6OnlyAllocator {
        fn allocate(&self, _node_key_hex: &str) -> Result<Ipv4Addr, AllocError> {
            Err(AllocError::Internal(
                "IPv4 allocator should not be called when disabled".into(),
            ))
        }

        fn ipv4_enabled(&self) -> bool {
            false
        }

        fn allocate_ipv6(&self, _node_key_hex: &str) -> Result<Option<Ipv6Addr>, AllocError> {
            Ok(Some(self.0))
        }
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    async fn create_oidc_test_user(
        users: &Arc<PersistentUserAdmin>,
    ) -> crate::oidc::OidcStoredUser {
        create_oidc_test_user_with(
            users,
            "alice",
            "Alice Smith",
            "alice@example.com",
            "https://issuer.example/subject",
        )
        .await
    }

    async fn create_oidc_test_user_with(
        users: &Arc<PersistentUserAdmin>,
        name: &str,
        display_name: &str,
        email: &str,
        provider_identifier: &str,
    ) -> crate::oidc::OidcStoredUser {
        crate::oidc::OidcUserStore::create_or_update_oidc_user(
            users.as_ref(),
            crate::oidc::OidcUserProfile {
                name: name.into(),
                display_name: display_name.into(),
                email: email.into(),
                provider_identifier: provider_identifier.into(),
                provider: crate::oidc::REGISTER_METHOD_OIDC.into(),
                profile_pic_url: String::new(),
            },
        )
        .await
        .unwrap()
    }

    fn fixture() -> (WireMachineAdmin, Arc<MachineRegistry>) {
        let reg = Arc::new(MachineRegistry::new());
        reg.upsert(
            "aa".repeat(32),
            MachineRecord::new_at(
                chrono::Utc::now(),
                "aa".repeat(32),
                "bb".repeat(32),
                "alice".into(),
                "node-1".into(),
                Ipv4Addr::new(100, 64, 0, 5),
                false,
            ),
        );
        (WireMachineAdmin::new(reg.clone()), reg)
    }

    #[test]
    fn list_returns_registered() {
        let (a, _) = fixture();
        let v = rt().block_on(a.list());
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].user, "alice");
        assert_eq!(v[0].name, "node-1");
        assert!(!v[0].online);
    }

    #[test]
    fn expire_flips_online() {
        let (a, _) = fixture();
        let id = "aa".repeat(32);
        rt().block_on(a.expire(&id)).unwrap();
        let r = rt().block_on(a.get(&id)).unwrap();
        assert!(!r.online);
        assert!(r.expired);
    }

    #[test]
    fn policy_auto_approvals_use_wire_update_many() {
        let reg = Arc::new(MachineRegistry::new());
        for idx in 1..=2 {
            let node_key = format!("{idx:064x}");
            let machine_key = format!("{:064x}", idx + 10);
            let mut rec = MachineRecord::new_at(
                chrono::Utc::now(),
                node_key.clone(),
                machine_key,
                "alice".into(),
                format!("router-{idx}"),
                Ipv4Addr::new(100, 64, 0, idx as u8),
                false,
            );
            rec.available_routes = vec![format!("10.{idx}.0.0/24")];
            reg.upsert(node_key, rec);
        }
        let _handle = reg.configure_nodestore_write_batcher(1, std::time::Duration::from_secs(5));

        let raw = r#"{
          "autoApprovers": {
            "routes": {"10.0.0.0/8": ["alice@"]}
          }
        }"#;
        let policy = PolicyStore::new();
        policy.set(parse_hujson_policy(raw).unwrap(), raw.into());
        let admin = WireMachineAdmin::new(reg.clone());

        let changed = rt()
            .block_on(apply_policy_auto_approvals(&policy, &admin))
            .unwrap();

        assert_eq!(changed, 2);
        assert_eq!(
            reg.get(&format!("{:064x}", 1)).unwrap().approved_routes,
            vec!["10.1.0.0/24"]
        );
        assert_eq!(
            reg.get(&format!("{:064x}", 2)).unwrap().approved_routes,
            vec!["10.2.0.0/24"]
        );
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("update_multi")
                .copied()
                .unwrap_or_default(),
            1
        );
        assert_eq!(
            reg.nodestore_operation_metrics()
                .get("update")
                .copied()
                .unwrap_or_default(),
            0
        );
    }

    #[test]
    fn delete_hides_record() {
        let (a, _) = fixture();
        let id = "aa".repeat(32);
        rt().block_on(a.delete(&id)).unwrap();
        assert!(rt().block_on(a.get(&id)).is_none());
        assert_eq!(rt().block_on(a.list()).len(), 0);
    }

    #[test]
    fn expire_unknown_errors() {
        let (a, _) = fixture();
        let e = rt()
            .block_on(a.expire("zz".repeat(32).as_str()))
            .unwrap_err();
        assert!(matches!(e, MachineAdminError::NotFound(_)));
    }

    // ---- P1 lifecycle parity tests ----------------------------------

    /// `expire_at(None)` writes through to the wire registry —
    /// subsequent `MachineRegistry::get` shows expiry stamped at ~now.
    #[test]
    fn expire_at_now_writes_through_to_wire_registry() {
        let (a, reg) = fixture();
        let id = "aa".repeat(32);
        let before = chrono::Utc::now();
        rt().block_on(a.expire_at(&id, None)).unwrap();
        let rec = reg.get(&id).expect("record still present after expire");
        let exp = rec.expiry.expect("expiry stamped on wire record");
        assert!(exp >= before);
        assert!(exp <= chrono::Utc::now() + chrono::Duration::seconds(1));
        // Admin view sees `expired = true` / `online = false`.
        let view = rt().block_on(a.get(&id)).unwrap();
        assert!(view.expired);
        assert!(!view.online);
    }

    /// `expire_at(Some(future))` schedules the expiry — admin view
    /// shows `expired = false` until the timestamp lands.
    #[test]
    fn expire_at_future_schedules_expiry() {
        let (a, reg) = fixture();
        let id = "aa".repeat(32);
        let future = chrono::Utc::now() + chrono::Duration::seconds(60);
        rt().block_on(a.expire_at(&id, Some(future))).unwrap();
        let rec = reg.get(&id).unwrap();
        assert_eq!(rec.expiry, Some(future));
        // Scheduling a future expiry does not revoke authorization now.
        let view = rt().block_on(a.get(&id)).unwrap();
        assert!(!view.expired);
    }

    /// `logout` preserves the machine key and stamps expiry=now on the wire record.
    #[test]
    fn logout_writes_through_to_wire_registry() {
        let (a, reg) = fixture();
        let id = "aa".repeat(32);
        let original_machine_key = reg.get(&id).unwrap().machine_key_hex;
        rt().block_on(a.logout(&id)).unwrap();
        let rec = reg.get(&id).unwrap();
        assert_eq!(rec.machine_key_hex, original_machine_key);
        assert!(rec.expiry.is_some());
        assert!(rec.is_expired_at(chrono::Utc::now()));
    }

    /// `rename` rewrites the hostname; empty payload is BadRequest.
    #[test]
    fn rename_writes_hostname() {
        let (a, reg) = fixture();
        let id = "aa".repeat(32);
        rt().block_on(a.rename(&id, "newhost")).unwrap();
        assert_eq!(reg.get(&id).unwrap().hostname, "newhost");
        let e = rt().block_on(a.rename(&id, "")).unwrap_err();
        assert!(matches!(e, MachineAdminError::BadRequest(_)));
    }

    /// `set_tags` writes through; admin DTO carries the forced tags.
    #[test]
    fn set_tags_round_trips_through_dto() {
        let (a, reg) = fixture();
        let id = "aa".repeat(32);
        rt().block_on(a.set_tags(&id, vec!["tag:prod".into(), "tag:db".into()]))
            .unwrap();
        let view = rt().block_on(a.get(&id)).unwrap();
        // headscale-go State.SetNodeTags does slices.Sort + slices.Compact on
        // the validated tags (state.go), so the stored order is sorted.
        assert_eq!(view.tags, vec!["tag:db", "tag:prod"]);

        let err = rt().block_on(a.set_tags(&id, Vec::new())).unwrap_err();
        assert!(matches!(err, MachineAdminError::BadRequest(_)));
        assert_eq!(
            reg.get(&id).unwrap().forced_tags,
            vec!["tag:db", "tag:prod"]
        );
    }

    /// `create` inserts a synthetic node through the same admin
    /// boundary gRPC debug/register uses.
    #[test]
    fn create_inserts_wire_record_and_rejects_duplicate() {
        let (a, reg) = fixture();
        let id = "cc".repeat(32);
        let record = MachineAdminRecord {
            node_id: 0,
            id: id.clone(),
            name: "debug-node".into(),
            user: "alice".into(),
            user_id: None,
            auth_key_id: None,
            ipv4: "100.64.0.44".into(),
            ipv6: Some("fd7a:115c:a1e0::44".into()),
            online: false,
            last_seen: 1_700_000_000,
            last_seen_precise: None,
            created_at: 1_700_000_000,
            created_at_precise: None,
            expiry: None,
            expiry_precise: None,
            machine_key_hex: "dd".repeat(32),
            disco_key: String::new(),
            os: "TestOS".into(),
            version: "unknown".into(),
            tags: Vec::new(),
            routes: vec!["10.0.0.0/24".into()],
            approved_routes: Vec::new(),
            register_method: 2,
            expired: false,
        };

        let created = rt().block_on(a.create(record.clone())).unwrap();
        assert_eq!(created.id, id);
        assert_eq!(created.routes, vec!["10.0.0.0/24"]);
        assert_eq!(created.register_method, 2);

        let rec = reg.get(&record.id).expect("wire record inserted");
        assert_eq!(rec.hostname, "debug-node");
        assert_eq!(
            rec.ipv6.map(|ip| ip.to_string()).as_deref(),
            Some("fd7a:115c:a1e0::44")
        );
        assert_eq!(rec.available_routes, vec!["10.0.0.0/24"]);
        assert_eq!(rec.register_method, 2);

        let err = rt().block_on(a.create(record.clone())).unwrap_err();
        assert!(matches!(err, MachineAdminError::BadRequest(_)));

        let mut duplicate_ipv4 = record.clone();
        duplicate_ipv4.id = "ee".repeat(32);
        duplicate_ipv4.name = "duplicate-v4".into();
        duplicate_ipv4.ipv4 = "100.64.0.5".into();
        duplicate_ipv4.ipv6 = None;
        let err = rt().block_on(a.create(duplicate_ipv4)).unwrap_err();
        assert!(
            err.to_string()
                .contains("IPv4 address 100.64.0.5 already in use")
        );

        let mut duplicate_ipv6 = record;
        duplicate_ipv6.id = "ff".repeat(32);
        duplicate_ipv6.name = "duplicate-v6".into();
        duplicate_ipv6.ipv4 = "100.64.0.45".into();
        duplicate_ipv6.ipv6 = Some("fd7a:115c:a1e0::44".into());
        let err = rt().block_on(a.create(duplicate_ipv6)).unwrap_err();
        assert!(
            err.to_string()
                .contains("IPv6 address fd7a:115c:a1e0::44 already in use")
        );
    }

    /// `delete` removes the record from the wire registry too, not
    /// just the sidecar.
    #[test]
    fn delete_removes_from_wire_registry() {
        let (a, reg) = fixture();
        let id = "aa".repeat(32);
        rt().block_on(a.delete(&id)).unwrap();
        assert!(reg.get(&id).is_none(), "wire record gone");
        assert!(rt().block_on(a.get(&id)).is_none(), "admin view gone");
    }

    /// Logout on unknown id ⇒ NotFound.
    #[test]
    fn logout_unknown_errors() {
        let (a, _) = fixture();
        let e = rt()
            .block_on(a.logout("zz".repeat(32).as_str()))
            .unwrap_err();
        assert!(matches!(e, MachineAdminError::NotFound(_)));
    }

    async fn persistent_fixture() -> (PersistentMachineAdmin, Database, Arc<PersistentUserAdmin>) {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        users.create("alice").await.unwrap();
        let admin = PersistentMachineAdmin::new(db.pool().clone()).with_user_admin(users.clone());
        (admin, db, users)
    }

    async fn persistent_file_fixture(
        url: &str,
        create_user: bool,
    ) -> (PersistentMachineAdmin, Database, Arc<PersistentUserAdmin>) {
        let db = Database::new(url).await.unwrap();
        db.migrate().await.unwrap();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        if create_user {
            users.create("alice").await.unwrap();
        }
        let admin = PersistentMachineAdmin::new(db.pool().clone()).with_user_admin(users.clone());
        (admin, db, users)
    }

    fn persistent_record() -> MachineAdminRecord {
        MachineAdminRecord {
            node_id: 0,
            id: "aa".repeat(32),
            name: "alice-laptop".into(),
            user: "alice".into(),
            user_id: None,
            auth_key_id: None,
            ipv4: "100.64.0.9".into(),
            ipv6: None,
            online: true,
            last_seen: 1_700_000_000,
            last_seen_precise: None,
            created_at: 1_700_000_000,
            created_at_precise: None,
            expiry: None,
            expiry_precise: None,
            machine_key_hex: "bb".repeat(32),
            disco_key: String::new(),
            os: "linux".into(),
            version: "unknown".into(),
            tags: Vec::new(),
            routes: vec!["10.0.0.0/24".into()],
            approved_routes: Vec::new(),
            register_method: 2,
            expired: false,
        }
    }

    /// A stock client rotates its node key on every re-authentication. With
    /// no users store attached — how octravpn's `mesh serve` runs — the
    /// (machine key, user) lookup cannot match, so before this the rotated
    /// key created a second row for the same device and both showed up as
    /// peers in every netmap.
    #[tokio::test]
    async fn persistent_auth_key_path_reuses_the_row_when_the_node_key_rotates() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let admin = PersistentMachineAdmin::new(db.pool().clone());
        let policy = crate::policy::PolicyStore::new();
        let record = |node_key: &str, ip: u8| {
            crate::tailscale_wire::MachineRecord::new_at(
                chrono::Utc::now(),
                node_key.to_string(),
                "e3".repeat(32),
                "interop-test".to_string(),
                "peer-b".to_string(),
                std::net::Ipv4Addr::new(100, 64, 0, ip),
                false,
            )
        };
        let first = admin
            .create_or_update_auth_key_registration(record(&"11".repeat(32), 1), &policy, None)
            .await
            .expect("first registration");
        let rotated = admin
            .create_or_update_auth_key_registration(record(&"22".repeat(32), 2), &policy, None)
            .await
            .expect("re-registration under a rotated node key");

        assert_eq!(
            first.record.node_id, rotated.record.node_id,
            "same device, same row"
        );
        assert_eq!(
            rotated.replaced_node_key_hex.as_deref(),
            Some("11".repeat(32).as_str()),
            "the wire registry is told which key to drop"
        );
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE deleted_at IS NULL")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(rows, 1, "one row per device, not one per node key");
    }

    /// A node re-registering with the same node key from the same machine
    /// (`tailscale up` after a control-plane restart) updates its row —
    /// even with no users store attached, where the row carries no user id
    /// and the user/machine lookup cannot match it. Before this, the second
    /// registration fell into `create` and was rejected with
    /// "IPv4 address … already in use" by its own row.
    #[tokio::test]
    async fn persistent_auth_key_path_reregisters_same_node_key_without_users_store() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let admin = PersistentMachineAdmin::new(db.pool().clone());
        let policy = crate::policy::PolicyStore::new();
        let record = || {
            crate::tailscale_wire::MachineRecord::new_at(
                chrono::Utc::now(),
                "13".repeat(32),
                "0b".repeat(32),
                "interop-test".to_string(),
                "peer-a".to_string(),
                std::net::Ipv4Addr::new(100, 83, 93, 76),
                false,
            )
        };
        let first = admin
            .create_or_update_auth_key_registration(record(), &policy, None)
            .await
            .expect("first registration");
        let second = admin
            .create_or_update_auth_key_registration(record(), &policy, None)
            .await
            .expect("re-registration of the same node key must update, not collide");
        assert_eq!(first.record.node_id, second.record.node_id);
        assert_eq!(
            second.record.ipv4,
            Some(std::net::Ipv4Addr::new(100, 83, 93, 76))
        );
        assert!(second.replaced_node_key_hex.is_none());
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes WHERE deleted_at IS NULL")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(rows, 1, "one row, updated in place");
    }

    #[tokio::test]
    async fn persistent_machine_admin_uses_go_nodes_table() {
        let (admin, db, _users) = persistent_fixture().await;
        let created = admin.create(persistent_record()).await.unwrap();
        assert_eq!(created.node_id, 1);
        assert_eq!(created.id, "aa".repeat(32));
        assert_eq!(created.user, "alice");
        assert_eq!(created.routes, vec!["10.0.0.0/24"]);
        assert_eq!(created.register_method, 2);

        let raw = sqlx::query(
            "
            SELECT
                id,
                node_key,
                machine_key,
                given_name,
                user_id,
                typeof(user_id) AS user_id_type,
                register_method,
                host_info
            FROM nodes
            WHERE id = 1
            ",
        )
        .fetch_one(db.pool())
        .await
        .unwrap();
        use sqlx::Row;
        assert_eq!(raw.get::<i64, _>("id"), 1);
        assert_eq!(
            raw.get::<String, _>("node_key"),
            format!("nodekey:{}", "aa".repeat(32))
        );
        assert_eq!(
            raw.get::<String, _>("machine_key"),
            format!("mkey:{}", "bb".repeat(32))
        );
        assert_eq!(raw.get::<String, _>("given_name"), "alice-laptop");
        assert_eq!(raw.get::<i64, _>("user_id"), 1);
        assert_eq!(raw.get::<String, _>("user_id_type"), "integer");
        assert_eq!(raw.get::<String, _>("register_method"), "cli");
        assert!(raw.get::<String, _>("host_info").contains("RoutableIPs"));

        let listed = admin.list().await;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].node_id, 1);
        assert_eq!(
            admin.get(&"aa".repeat(32)).await.unwrap().node_id,
            created.node_id
        );
        assert_eq!(admin.get("1").await.unwrap().id, "aa".repeat(32));
    }

    #[tokio::test]
    async fn persistent_machine_admin_projects_ipv6_from_go_nodes_table() {
        let (admin, _db, _users) = persistent_fixture().await;
        let mut record = persistent_record();
        record.ipv6 = Some("fd7a:115c:a1e0::9".into());

        let created = admin.create(record).await.unwrap();
        let listed = admin.list().await;

        assert_eq!(created.ipv6.as_deref(), Some("fd7a:115c:a1e0::9"));
        assert_eq!(listed[0].ipv6.as_deref(), Some("fd7a:115c:a1e0::9"));
    }

    #[tokio::test]
    async fn persistent_machine_admin_allows_ipv6_only_nodes() {
        let (admin, db, _users) = persistent_fixture().await;
        let mut record = persistent_record();
        record.ipv4 = String::new();
        record.ipv6 = Some("fd7a:115c:a1e0::66".into());

        let created = admin.create(record).await.unwrap();
        let row = headscale_db::headscale_nodes::get_by_id(db.pool(), created.node_id as i64)
            .await
            .unwrap();
        let registry = MachineRegistry::new();

        let hydrated = admin.hydrate_wire_registry(&registry).await.unwrap();
        let wire = registry.get(&created.id).unwrap();

        assert_eq!(row.ipv4, None);
        assert_eq!(row.ipv6.as_deref(), Some("fd7a:115c:a1e0::66"));
        assert_eq!(hydrated, 1);
        assert_eq!(wire.ipv4, None);
        assert_eq!(
            wire.ipv6.map(|addr| addr.to_string()).as_deref(),
            Some("fd7a:115c:a1e0::66")
        );
    }

    #[tokio::test]
    async fn persistent_machine_admin_rejects_duplicate_ipv4_on_create() {
        let (admin, _db, _users) = persistent_fixture().await;
        admin.create(persistent_record()).await.unwrap();

        let mut duplicate = persistent_record();
        duplicate.id = "cc".repeat(32);
        duplicate.machine_key_hex = "dd".repeat(32);
        duplicate.name = "duplicate-v4".into();

        let err = admin.create(duplicate).await.unwrap_err();
        assert!(matches!(err, MachineAdminError::BadRequest(_)));
        assert!(
            err.to_string()
                .contains("IPv4 address 100.64.0.9 already in use")
        );
    }

    #[tokio::test]
    async fn persistent_machine_admin_rejects_duplicate_ipv6_on_create() {
        let (admin, _db, _users) = persistent_fixture().await;
        let mut first = persistent_record();
        first.ipv6 = Some("fd7a:115c:a1e0::9".into());
        admin.create(first).await.unwrap();

        let mut duplicate = persistent_record();
        duplicate.id = "cc".repeat(32);
        duplicate.machine_key_hex = "dd".repeat(32);
        duplicate.name = "duplicate-v6".into();
        duplicate.ipv4 = "100.64.0.10".into();
        duplicate.ipv6 = Some("fd7a:115c:a1e0::9".into());

        let err = admin.create(duplicate).await.unwrap_err();
        assert!(matches!(err, MachineAdminError::BadRequest(_)));
        assert!(
            err.to_string()
                .contains("IPv6 address fd7a:115c:a1e0::9 already in use")
        );
    }

    #[tokio::test]
    async fn persistent_machine_admin_backfill_assigns_missing_ipv4_and_ipv6() {
        let (admin, db, users) = persistent_fixture().await;
        let user = users.get("alice").await.unwrap().unwrap();
        headscale_db::headscale_nodes::create(
            db.pool(),
            headscale_db::headscale_nodes::CreateParams {
                machine_key: format!("mkey:{}", "bb".repeat(32)),
                node_key: format!("nodekey:{}", "aa".repeat(32)),
                host_info: json!({"Hostname": "needs-ip"}),
                ipv4: None,
                ipv6: None,
                hostname: "needs-ip".into(),
                given_name: "needs-ip".into(),
                user_id: Some(user.id as i64),
                register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let changes = admin
            .backfill_node_ips(Some(&FixedDualStackAllocator(
                Ipv4Addr::new(100, 64, 0, 10),
                "fd7a:115c:a1e0::10".parse().unwrap(),
            )))
            .await
            .unwrap();
        let row = headscale_db::headscale_nodes::get_by_id(db.pool(), 1)
            .await
            .unwrap();

        assert_eq!(
            changes,
            vec![
                "assigned IPv4 \"100.64.0.10\" to Node(1) \"needs-ip\"",
                "assigned IPv6 \"fd7a:115c:a1e0::10\" to Node(1) \"needs-ip\""
            ]
        );
        assert_eq!(row.ipv4.as_deref(), Some("100.64.0.10"));
        assert_eq!(row.ipv6.as_deref(), Some("fd7a:115c:a1e0::10"));
    }

    #[tokio::test]
    async fn persistent_machine_admin_backfill_assigns_missing_ipv6_to_existing_ipv4() {
        let (admin, db, users) = persistent_fixture().await;
        let user = users.get("alice").await.unwrap().unwrap();
        headscale_db::headscale_nodes::create(
            db.pool(),
            headscale_db::headscale_nodes::CreateParams {
                machine_key: format!("mkey:{}", "bb".repeat(32)),
                node_key: format!("nodekey:{}", "aa".repeat(32)),
                host_info: json!({"Hostname": "needs-v6"}),
                ipv4: Some("100.64.0.10".into()),
                ipv6: None,
                hostname: "needs-v6".into(),
                given_name: "needs-v6".into(),
                user_id: Some(user.id as i64),
                register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let changes = admin
            .backfill_node_ips(Some(&FixedDualStackAllocator(
                Ipv4Addr::new(100, 64, 0, 20),
                "fd7a:115c:a1e0::10".parse().unwrap(),
            )))
            .await
            .unwrap();
        let row = headscale_db::headscale_nodes::get_by_id(db.pool(), 1)
            .await
            .unwrap();

        assert_eq!(
            changes,
            vec!["assigned IPv6 \"fd7a:115c:a1e0::10\" to Node(1) \"needs-v6\""]
        );
        assert_eq!(row.ipv4.as_deref(), Some("100.64.0.10"));
        assert_eq!(row.ipv6.as_deref(), Some("fd7a:115c:a1e0::10"));
    }

    #[tokio::test]
    async fn persistent_machine_admin_backfill_removes_disabled_ipv6_family() {
        let (admin, db, users) = persistent_fixture().await;
        let user = users.get("alice").await.unwrap().unwrap();
        headscale_db::headscale_nodes::create(
            db.pool(),
            headscale_db::headscale_nodes::CreateParams {
                machine_key: format!("mkey:{}", "bb".repeat(32)),
                node_key: format!("nodekey:{}", "aa".repeat(32)),
                host_info: json!({"Hostname": "v4-only"}),
                ipv4: Some("100.64.0.10".into()),
                ipv6: Some("fd7a:115c:a1e0::10".into()),
                hostname: "v4-only".into(),
                given_name: "v4-only".into(),
                user_id: Some(user.id as i64),
                register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let changes = admin
            .backfill_node_ips(Some(&FixedIpv4OnlyAllocator(Ipv4Addr::new(100, 64, 0, 20))))
            .await
            .unwrap();
        let row = headscale_db::headscale_nodes::get_by_id(db.pool(), 1)
            .await
            .unwrap();

        assert_eq!(
            changes,
            vec!["removing IPv6 \"fd7a:115c:a1e0::10\" from Node(1) \"v4-only\""]
        );
        assert_eq!(row.ipv4.as_deref(), Some("100.64.0.10"));
        assert!(row.ipv6.is_none());
    }

    #[tokio::test]
    async fn persistent_machine_admin_backfill_removes_disabled_ipv4_family() {
        let (admin, db, users) = persistent_fixture().await;
        let user = users.get("alice").await.unwrap().unwrap();
        headscale_db::headscale_nodes::create(
            db.pool(),
            headscale_db::headscale_nodes::CreateParams {
                machine_key: format!("mkey:{}", "bb".repeat(32)),
                node_key: format!("nodekey:{}", "aa".repeat(32)),
                host_info: json!({"Hostname": "v6-only"}),
                ipv4: Some("100.64.0.10".into()),
                ipv6: Some("fd7a:115c:a1e0::10".into()),
                hostname: "v6-only".into(),
                given_name: "v6-only".into(),
                user_id: Some(user.id as i64),
                register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let changes = admin
            .backfill_node_ips(Some(&FixedIpv6OnlyAllocator(
                "fd7a:115c:a1e0::20".parse().unwrap(),
            )))
            .await
            .unwrap();
        let row = headscale_db::headscale_nodes::get_by_id(db.pool(), 1)
            .await
            .unwrap();

        assert_eq!(
            changes,
            vec!["removing IPv4 \"100.64.0.10\" from Node(1) \"v6-only\""]
        );
        assert!(row.ipv4.is_none());
        assert_eq!(row.ipv6.as_deref(), Some("fd7a:115c:a1e0::10"));
    }

    #[tokio::test]
    async fn persistent_machine_admin_hydrates_wire_registry_from_go_nodes() {
        let (admin, _db, _users) = persistent_fixture().await;
        let mut record = persistent_record();
        record.ipv6 = Some("fd7a:115c:a1e0::9".into());
        record.tags = vec!["tag:prod".into()];
        record.approved_routes = vec!["10.0.0.0/24".into()];
        let created = admin.create(record).await.unwrap();
        let registry = MachineRegistry::new();

        let hydrated = admin.hydrate_wire_registry(&registry).await.unwrap();

        assert_eq!(hydrated, 1);
        let wire = registry.get(&created.id).unwrap();
        assert_eq!(wire.node_key_hex, created.id);
        assert_eq!(wire.machine_key_hex, created.machine_key_hex);
        assert_eq!(wire.hostname, "alice-laptop");
        assert_eq!(wire.user, "");
        assert_eq!(
            wire.ipv4.map(|ip| ip.to_string()).as_deref(),
            Some("100.64.0.9")
        );
        assert_eq!(
            wire.ipv6.map(|ipv6| ipv6.to_string()).as_deref(),
            Some("fd7a:115c:a1e0::9")
        );
        assert_eq!(wire.forced_tags, vec!["tag:prod"]);
        assert_eq!(wire.available_routes, vec!["10.0.0.0/24"]);
        assert_eq!(wire.approved_routes, vec!["10.0.0.0/24"]);
        assert_eq!(wire.register_method, 2);
    }

    #[tokio::test]
    async fn persistent_machine_admin_preserves_invalid_stored_given_name_on_wire() {
        let (admin, db, _users) = persistent_fixture().await;
        let created = admin.create(persistent_record()).await.unwrap();
        sqlx::query("UPDATE nodes SET given_name = '' WHERE id = ?")
            .bind(created.node_id as i64)
            .execute(db.pool())
            .await
            .unwrap();

        let registry = MachineRegistry::new();
        assert_eq!(admin.hydrate_wire_registry(&registry).await.unwrap(), 1);
        let wire = registry.get(&created.id).unwrap();
        assert_eq!(wire.hostname, "");
        assert_eq!(wire.host_info_for_node().hostname, "alice-laptop");
    }

    #[tokio::test]
    async fn persistent_machine_admin_reports_live_online_and_last_seen() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        users.create("alice").await.unwrap();
        let registry = Arc::new(MachineRegistry::new());
        let admin = PersistentMachineAdmin::new(db.pool().clone())
            .with_user_admin(users)
            .with_wire_registry(registry.clone());
        let created = admin.create(persistent_record()).await.unwrap();
        let registration_store: Arc<dyn MachineRegistrationStore> = Arc::new(admin.clone());
        let _gc = registry.configure_ephemeral_gc(
            Some(Arc::downgrade(&registration_store)),
            std::time::Duration::from_secs(120),
        );

        let offline = admin.get(&created.id).await.unwrap();
        assert!(!offline.online);
        assert_eq!(offline.last_seen, created.last_seen);

        let guard = MachineRegistry::track_stream_connection_with_grace(
            registry.clone(),
            registry.stable_node_id_for_key(&created.id),
            std::time::Duration::ZERO,
        );
        let online = admin.get(&created.id).await.unwrap();
        assert!(online.online);

        let live = registry.get(&created.id).unwrap();
        registry.touch_last_seen(&created.id);
        assert!(registry.get(&created.id).unwrap().last_seen >= live.last_seen);
        let touched = admin.get(&created.id).await.unwrap();
        let live_precise = registry.get(&created.id).unwrap().last_seen;
        assert_eq!(touched.last_seen, live_precise.timestamp().max(0) as u64);
        assert_eq!(touched.last_seen_precise, Some(live_precise));

        drop(guard);
        tokio::task::yield_now().await;
        let disconnected = admin.get(&created.id).await.unwrap();
        assert!(!disconnected.online);
        assert_eq!(
            disconnected.last_seen_precise,
            Some(registry.get(&created.id).unwrap().last_seen)
        );
        let expected = registry
            .get(&created.id)
            .unwrap()
            .last_seen
            .to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
        let mut stored = String::new();
        for _ in 0..100 {
            let row = headscale_db::headscale_nodes::get_by_id(db.pool(), created.node_id as i64)
                .await
                .unwrap();
            stored = row.last_seen_text.unwrap_or_default();
            if stored == expected {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert_eq!(stored, expected, "disconnect LastSeen must be durable");
        let restarted = PersistentMachineAdmin::new(db.pool().clone());
        assert_eq!(
            restarted.get(&created.id).await.unwrap().last_seen_precise,
            disconnected.last_seen_precise
        );
    }

    #[tokio::test]
    async fn persistent_machine_admin_mutations_update_live_wire_registry() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        users.create("alice").await.unwrap();
        let registry = Arc::new(MachineRegistry::new());
        let admin = PersistentMachineAdmin::new(db.pool().clone())
            .with_user_admin(users)
            .with_wire_registry(registry.clone());
        let created = admin.create(persistent_record()).await.unwrap();
        assert!(registry.get(&created.id).is_some());

        let expiry = DateTime::<Utc>::from_timestamp(
            (Utc::now() + chrono::Duration::seconds(90)).timestamp(),
            0,
        )
        .unwrap();
        admin.expire_at(&created.id, Some(expiry)).await.unwrap();
        assert_eq!(registry.get(&created.id).unwrap().expiry, Some(expiry));

        admin.rename(&created.id, "renamed-node").await.unwrap();
        assert_eq!(registry.get(&created.id).unwrap().hostname, "renamed-node");

        admin.delete(&created.id).await.unwrap();
        assert!(registry.get(&created.id).is_none());
    }

    #[tokio::test]
    async fn persistent_machine_admin_hydration_rejects_invalid_persisted_ip() {
        let (admin, db, users) = persistent_fixture().await;
        let user = users.get("alice").await.unwrap().unwrap();
        // The database layer now refuses to write an unparsable address
        // (Go stores nodes.ipv4 through a netip.Addr text serializer), so
        // corrupt the persisted row behind its back to exercise hydration.
        let row = headscale_db::headscale_nodes::create(
            db.pool(),
            headscale_db::headscale_nodes::CreateParams {
                machine_key: format!("mkey:{}", "bb".repeat(32)),
                node_key: format!("nodekey:{}", "aa".repeat(32)),
                host_info: json!({"Hostname": "bad-ip-node"}),
                ipv4: Some("100.64.0.77".into()),
                hostname: "bad-ip-node".into(),
                given_name: "bad-ip-node".into(),
                user_id: Some(user.id as i64),
                register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        sqlx::query("UPDATE nodes SET ipv4 = 'not-an-ip' WHERE id = ?")
            .bind(row.id)
            .execute(db.pool())
            .await
            .unwrap();
        let registry = MachineRegistry::new();

        let err = admin.hydrate_wire_registry(&registry).await.unwrap_err();

        // Go loads Node.IPv4 through gorm's `serializer:text` (netip.Addr), so
        // an unparsable column fails the whole node listing at row decode; the
        // Rust database layer reports the same condition as a storage error
        // naming the column.
        assert!(
            matches!(
                &err,
                MachineAdminError::Storage(message)
                    if message.contains("decoding column \"ipv4\"")
                        && message.contains("invalid persisted IP address")
            ),
            "{err:?}"
        );
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn persistent_machine_admin_auth_path_reauth_updates_existing_row() {
        let (admin, db, _users) = persistent_fixture().await;
        let mut original = persistent_record();
        original.ipv6 = Some("fd7a:115c:a1e0::9".into());
        original.approved_routes = vec!["10.0.0.0/24".into()];
        let created = admin.create(original).await.unwrap();

        let mut pending = persistent_record();
        pending.id = "cc".repeat(32);
        pending.machine_key_hex = created.machine_key_hex.clone();
        pending.register_method = REGISTER_METHOD_OIDC;
        pending.routes = vec!["10.0.0.0/24".into(), "10.1.0.0/24".into()];
        pending.approved_routes = vec!["10.1.0.0/24".into()];
        pending.ipv4 = "100.64.99.99".into();
        pending.expiry = Some(4_102_444_800);

        let result = admin
            .create_or_update_auth_path(pending, &PolicyStore::new())
            .await
            .unwrap();
        let updated = result.record;

        assert!(!result.new_node);
        assert_eq!(result.replaced_node_key_hex, Some("aa".repeat(32)));
        assert_eq!(updated.node_id, created.node_id);
        assert_eq!(updated.id, "cc".repeat(32));
        assert_eq!(updated.machine_key_hex, created.machine_key_hex);
        assert_eq!(updated.ipv4, created.ipv4, "reauth keeps existing IP");
        assert_eq!(
            updated.ipv6, created.ipv6,
            "reauth keeps existing IPv6 projection"
        );
        // Go applyAuthNodeUpdate: "On plain reauth we preserve the existing
        // node.RegisterMethod" (only tag->user conversion sets it), so the
        // row created with the CLI method (2) stays CLI after an OIDC reauth.
        assert_eq!(updated.register_method, 2);
        assert_eq!(updated.expiry, Some(4_102_444_800));
        // Go applyAuthNodeUpdate never touches ApprovedRoutes on reauth (the
        // pending entry's approvals are not merged); policy auto-approval is
        // a separate State.AutoApproveRoutes step run by the caller.
        assert_eq!(updated.approved_routes, vec!["10.0.0.0/24"]);

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
        let raw = headscale_db::headscale_nodes::get_by_id(db.pool(), created.node_id as i64)
            .await
            .unwrap();
        assert_eq!(raw.node_key, format!("nodekey:{}", "cc".repeat(32)));
        assert_eq!(
            raw.register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_CLI
        );
    }

    #[tokio::test]
    async fn persistent_machine_admin_auth_path_rejects_duplicate_new_node_ip() {
        let (admin, db, _users) = persistent_fixture().await;
        admin.create(persistent_record()).await.unwrap();

        let mut pending = persistent_record();
        pending.id = "cc".repeat(32);
        pending.machine_key_hex = "dd".repeat(32);
        pending.name = "auth-path-duplicate".into();

        let err = admin
            .create_or_update_auth_path(pending, &PolicyStore::new())
            .await
            .unwrap_err();

        // headscale-go has no IP pre-check on the registration path (its
        // allocator never hands an address out twice) and createAndSaveNewNode
        // wraps a failed `tx.Save` as "saving node: ...". The collision is
        // rejected by the unique nodes.ipv4 index, a Rust-side guard
        // (migration 20260523000011), and surfaces as that storage error
        // rather than the old pre-check BadRequest.
        assert!(
            matches!(
                &err,
                MachineAdminError::Storage(message)
                    if message.starts_with("creating new node: saving node:")
                        && message.contains("nodes.ipv4")
            ),
            "{err:?}"
        );
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 1, "the colliding registration must not add a row");
    }

    #[tokio::test]
    async fn persistent_machine_admin_auth_key_path_writes_auth_key_metadata() {
        let (admin, db, _users) = persistent_fixture().await;
        let preauth = headscale_db::preauth_keys::create_for_test(
            db.pool(),
            headscale_db::preauth_keys::CreateParams {
                user_id: "1".into(),
                reusable: false,
                ephemeral: false,
                tags: vec!["tag:server".into()],
                expiration: None,
            },
        )
        .await
        .unwrap();
        let mut record = machine_admin_record_to_wire(&persistent_record()).unwrap();
        record.forced_tags = vec!["tag:server".into()];
        record.available_routes = vec!["10.0.0.0/24".into()];
        record.approved_routes = vec!["10.0.0.0/24".into()];

        let result = admin
            .create_or_update_auth_key_path(
                record.clone(),
                &PolicyStore::new(),
                Some(preauth.row.id),
            )
            .await
            .unwrap();

        assert!(result.new_node);
        assert_eq!(result.record.register_method, REGISTER_METHOD_AUTH_KEY);
        assert_eq!(result.record.tags, vec!["tag:server"]);
        assert_eq!(result.record.routes, vec!["10.0.0.0/24"]);
        // Go createAndSaveNewNode saves the node without ApprovedRoutes; the
        // registration caller approves them afterwards via
        // State.AutoApproveRoutes (empty policy here), so none are persisted.
        assert!(result.record.approved_routes.is_empty());
        let raw = headscale_db::headscale_nodes::get_by_node_key(
            db.pool(),
            &format!("nodekey:{}", record.node_key_hex),
        )
        .await
        .unwrap();
        assert!(raw.approved_route_list().is_empty());
        assert_eq!(
            raw.register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_AUTH_KEY
        );
        assert_eq!(raw.auth_key_id, Some(preauth.row.id));
        assert_eq!(raw.tag_list(), vec!["tag:server"]);
    }

    #[tokio::test]
    async fn persistent_auth_key_hydration_derives_ephemeral_from_preauth_key() {
        let (admin, db, _users) = persistent_fixture().await;
        let preauth = headscale_db::preauth_keys::create_for_test(
            db.pool(),
            headscale_db::preauth_keys::CreateParams {
                user_id: "1".into(),
                reusable: false,
                ephemeral: true,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap();
        let record = machine_admin_record_to_wire(&persistent_record()).unwrap();

        admin
            .create_or_update_auth_key_path(
                record.clone(),
                &PolicyStore::new(),
                Some(preauth.row.id),
            )
            .await
            .unwrap();

        let raw = headscale_db::headscale_nodes::get_by_node_key(
            db.pool(),
            &format!("nodekey:{}", record.node_key_hex),
        )
        .await
        .unwrap();
        assert_eq!(raw.auth_key_id, Some(preauth.row.id));

        let registry = MachineRegistry::new();
        assert_eq!(admin.hydrate_wire_registry(&registry).await.unwrap(), 1);
        let hydrated = registry.get(&record.node_key_hex).unwrap();
        assert!(hydrated.ephemeral);
    }

    #[tokio::test]
    async fn persistent_auth_key_registration_hydrates_canonical_fields_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headscale.db");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let node_key = "ab".repeat(32);
        let machine_key = "cd".repeat(32);

        let (admin, db, users) = persistent_file_fixture(&url, true).await;
        let preauth = headscale_db::preauth_keys::create_for_test(
            db.pool(),
            headscale_db::preauth_keys::CreateParams {
                user_id: "1".into(),
                reusable: false,
                ephemeral: true,
                tags: vec!["tag:server".into()],
                expiration: None,
            },
        )
        .await
        .unwrap();
        let mut record = MachineRecord::new_at(
            Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            node_key.clone(),
            machine_key.clone(),
            "alice".into(),
            "authkey-node".into(),
            Ipv4Addr::new(100, 64, 0, 88),
            false,
        );
        record.last_seen = Utc.timestamp_opt(1_700_000_111, 0).unwrap();
        record.disco_key = Some(format!("discokey:{}", "d1".repeat(32)));
        record.endpoints = vec!["192.0.2.10:41641".into(), "[2001:db8::10]:41641".into()];
        record.home_derp = 7;
        record.os = "linux".into();
        record.os_version = "6.8.0".into();
        record.ssh_host_keys = vec!["ssh-ed25519 AAAAC3NzaAuth".into()];
        record.forced_tags = vec!["tag:server".into()];
        record.available_routes = vec!["10.40.0.0/24".into()];
        record.approved_routes = vec!["10.40.0.0/24".into()];

        let created = admin
            .create_or_update_auth_key_path(
                record.clone(),
                &PolicyStore::new(),
                Some(preauth.row.id),
            )
            .await
            .unwrap()
            .record;
        assert_eq!(created.node_id, 1);
        assert_eq!(created.id, node_key);
        assert_eq!(created.user, "");
        assert_eq!(created.machine_key_hex, machine_key);
        assert_eq!(created.register_method, REGISTER_METHOD_AUTH_KEY);
        assert_eq!(created.tags, vec!["tag:server"]);
        assert_eq!(created.routes, vec!["10.40.0.0/24"]);
        // Go createAndSaveNewNode persists no ApprovedRoutes for a new node
        // (State.AutoApproveRoutes runs afterwards in the caller). Approve
        // explicitly so the reopen/hydration assertions below still cover them.
        assert!(created.approved_routes.is_empty());
        admin
            .set_approved_routes(&created.id, vec!["10.40.0.0/24".into()])
            .await
            .unwrap();

        let raw = headscale_db::headscale_nodes::get_by_id(db.pool(), created.node_id as i64)
            .await
            .unwrap();
        assert_eq!(raw.id, 1);
        assert_eq!(raw.user_id, None);
        assert_eq!(raw.node_key, format!("nodekey:{}", record.node_key_hex));
        assert_eq!(raw.machine_key, format!("mkey:{}", record.machine_key_hex));
        assert_eq!(raw.disco_key, format!("discokey:{}", "d1".repeat(32)));
        assert_eq!(raw.endpoint_list(), record.endpoints);
        assert_eq!(
            raw.register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_AUTH_KEY
        );
        assert_eq!(raw.auth_key_id, Some(preauth.row.id));
        assert_eq!(raw.tag_list(), vec!["tag:server"]);
        assert_eq!(raw.approved_route_list(), vec!["10.40.0.0/24"]);
        assert!(
            headscale_db::preauth_keys::get_by_id(db.pool(), preauth.row.id)
                .await
                .unwrap()
                .ephemeral
        );
        let host_info = raw.host_info_value();
        assert_eq!(host_info.get("OS").and_then(Value::as_str), Some("linux"));
        assert_eq!(
            host_info.get("OSVersion").and_then(Value::as_str),
            Some("6.8.0")
        );
        assert_eq!(
            routes_from_host_info(&host_info),
            vec!["10.40.0.0/24".to_string()]
        );
        assert_eq!(preferred_derp_from_host_info(&host_info), 7);
        assert_eq!(
            ssh_host_keys_from_host_info(&host_info),
            vec!["ssh-ed25519 AAAAC3NzaAuth".to_string()]
        );
        drop(admin);
        drop(users);
        db.close().await;

        let (reopened_admin, reopened_db, reopened_users) =
            persistent_file_fixture(&url, false).await;
        let registry = MachineRegistry::new();
        assert_eq!(
            reopened_admin
                .hydrate_wire_registry(&registry)
                .await
                .unwrap(),
            1
        );
        let hydrated = registry.get(&record.node_key_hex).unwrap();
        assert_eq!(hydrated.node_key_hex, record.node_key_hex);
        assert_eq!(hydrated.machine_key_hex, record.machine_key_hex);
        assert!(
            hydrated.ephemeral,
            "hydration should derive Node.IsEphemeral from the assigned preauth key"
        );
        assert_eq!(hydrated.user, "");
        assert_eq!(hydrated.hostname, "authkey-node");
        assert_eq!(
            hydrated.ipv4.map(|ip| ip.to_string()).as_deref(),
            Some("100.64.0.88")
        );
        assert_eq!(
            hydrated.disco_key,
            Some(format!("discokey:{}", "d1".repeat(32)))
        );
        assert_eq!(hydrated.endpoints, record.endpoints);
        assert_eq!(hydrated.home_derp, 7);
        assert_eq!(hydrated.os, "linux");
        assert_eq!(hydrated.os_version, "6.8.0");
        assert_eq!(hydrated.ssh_host_keys, vec!["ssh-ed25519 AAAAC3NzaAuth"]);
        assert_eq!(hydrated.forced_tags, vec!["tag:server"]);
        assert_eq!(hydrated.available_routes, vec!["10.40.0.0/24"]);
        assert_eq!(hydrated.approved_routes, vec!["10.40.0.0/24"]);
        assert_eq!(hydrated.register_method, REGISTER_METHOD_AUTH_KEY);
        drop(reopened_admin);
        drop(reopened_users);
        reopened_db.close().await;
    }

    #[tokio::test]
    async fn persistent_auth_key_registration_returns_upstream_user_identity() {
        let (admin, db, _users) = persistent_fixture().await;
        let preauth = headscale_db::preauth_keys::create_for_test(
            db.pool(),
            headscale_db::preauth_keys::CreateParams {
                user_id: "1".into(),
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap();
        let record = MachineRecord::new_at(
            Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            "ca".repeat(32),
            "cb".repeat(32),
            "alice".into(),
            "authkey-identity-node".into(),
            Ipv4Addr::new(100, 64, 0, 99),
            false,
        );

        let saved = admin
            .create_or_update_auth_key_registration(
                record,
                &PolicyStore::new(),
                Some(preauth.row.id),
            )
            .await
            .unwrap()
            .record;

        assert_eq!(saved.user_id, Some(1));
        assert_eq!(saved.tailscale_user_id(), 1);
        let profile = saved.tailscale_user_profile();
        assert_eq!(profile.id, 1);
        assert_eq!(profile.login_name, "alice");
        assert_eq!(profile.display_name, "alice");
        assert_eq!(profile.profile_pic_url, "");
    }

    #[tokio::test]
    async fn persistent_machine_admin_auth_key_path_reauth_updates_existing_row() {
        let (admin, db, _users) = persistent_fixture().await;
        let first_key = headscale_db::preauth_keys::create_for_test(
            db.pool(),
            headscale_db::preauth_keys::CreateParams {
                user_id: "1".into(),
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap();
        let second_key = headscale_db::preauth_keys::create_for_test(
            db.pool(),
            headscale_db::preauth_keys::CreateParams {
                user_id: "1".into(),
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap();
        let original = machine_admin_record_to_wire(&persistent_record()).unwrap();
        let created = admin
            .create_or_update_auth_key_path(
                original.clone(),
                &PolicyStore::new(),
                Some(first_key.row.id),
            )
            .await
            .unwrap();
        headscale_db::headscale_nodes::rename(
            db.pool(),
            created.record.node_id as i64,
            "AdminName",
        )
        .await
        .unwrap();

        let mut rotated = original.clone();
        rotated.node_key_hex = "cc".repeat(32);
        rotated.hostname = "alice-rotated".into();
        rotated.host_info.hostname = "alice-rotated".into();
        rotated.ipv4 = Some(Ipv4Addr::new(100, 64, 99, 99));
        rotated.available_routes = vec!["10.1.0.0/24".into()];
        let result = admin
            .create_or_update_auth_key_path(
                rotated.clone(),
                &PolicyStore::new(),
                Some(second_key.row.id),
            )
            .await
            .unwrap();

        assert!(!result.new_node);
        assert_eq!(result.replaced_node_key_hex, Some(original.node_key_hex));
        assert_eq!(result.record.node_id, created.record.node_id);
        assert_eq!(result.record.id, rotated.node_key_hex);
        assert_eq!(result.record.name, "AdminName");
        assert_eq!(result.record.ipv4, created.record.ipv4);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
        let raw =
            headscale_db::headscale_nodes::get_by_id(db.pool(), created.record.node_id as i64)
                .await
                .unwrap();
        assert_eq!(raw.node_key, format!("nodekey:{}", rotated.node_key_hex));
        assert_eq!(raw.hostname, "alice-rotated");
        assert_eq!(raw.given_name, "AdminName");
        assert_eq!(raw.auth_key_id, Some(second_key.row.id));
        assert_eq!(
            raw.register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_AUTH_KEY
        );
    }

    #[tokio::test]
    async fn persistent_auth_key_path_different_user_creates_new_row() {
        let (admin, db, users) = persistent_fixture().await;
        let bob = users.create("bob").await.unwrap();
        let first_key = headscale_db::preauth_keys::create_for_test(
            db.pool(),
            headscale_db::preauth_keys::CreateParams {
                user_id: "1".into(),
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap();
        let second_key = headscale_db::preauth_keys::create_for_test(
            db.pool(),
            headscale_db::preauth_keys::CreateParams {
                user_id: bob.id.to_string(),
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap();
        let original = machine_admin_record_to_wire(&persistent_record()).unwrap();
        let created = admin
            .create_or_update_auth_key_path(
                original.clone(),
                &PolicyStore::new(),
                Some(first_key.row.id),
            )
            .await
            .unwrap();

        let mut relogin = original.clone();
        relogin.user = "bob".into();
        relogin.hostname = "bob-relogin".into();
        relogin.host_info.hostname = "bob-relogin".into();
        relogin.ipv4 = Some(Ipv4Addr::new(100, 64, 0, 77));
        let result = admin
            .create_or_update_auth_key_path(relogin, &PolicyStore::new(), Some(second_key.row.id))
            .await
            .unwrap();

        assert!(result.new_node);
        assert_eq!(result.replaced_node_key_hex, None);
        assert_ne!(result.record.node_id, created.record.node_id);
        assert_eq!(result.record.id, original.node_key_hex);
        assert_eq!(result.record.user, "bob");
        assert_eq!(result.record.user_id, Some(bob.id));
        assert_eq!(result.record.auth_key_id, Some(second_key.row.id));
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 2);
        let raw =
            headscale_db::headscale_nodes::get_by_id(db.pool(), created.record.node_id as i64)
                .await
                .unwrap();
        assert_eq!(raw.node_key, format!("nodekey:{}", original.node_key_hex));
        assert_eq!(raw.user_id, Some(1));
        assert_eq!(raw.auth_key_id, Some(first_key.row.id));
        assert_eq!(
            headscale_db::headscale_nodes::get_by_node_key(
                db.pool(),
                &format!("nodekey:{}", original.node_key_hex)
            )
            .await
            .unwrap()
            .id,
            raw.id,
            "NodeKey lookup follows headscale-go's first-row ambiguity"
        );
        let relogin_raw =
            headscale_db::headscale_nodes::get_by_id(db.pool(), result.record.node_id as i64)
                .await
                .unwrap();
        assert_eq!(relogin_raw.node_key, raw.node_key);
        assert_eq!(relogin_raw.machine_key, raw.machine_key);
        assert_eq!(relogin_raw.user_id, Some(bob.id as i64));
        assert_eq!(relogin_raw.auth_key_id, Some(second_key.row.id));
    }

    #[tokio::test]
    async fn persistent_auth_key_registration_same_node_key_different_user_returns_new_row() {
        let (admin, db, users) = persistent_fixture().await;
        let bob = users.create("bob").await.unwrap();
        let first_key = headscale_db::preauth_keys::create_for_test(
            db.pool(),
            headscale_db::preauth_keys::CreateParams {
                user_id: "1".into(),
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap();
        let second_key = headscale_db::preauth_keys::create_for_test(
            db.pool(),
            headscale_db::preauth_keys::CreateParams {
                user_id: bob.id.to_string(),
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap();
        let original = MachineRecord::new_at(
            Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
            "dc".repeat(32),
            "dd".repeat(32),
            "alice".into(),
            "alice-duplicate-nodekey".into(),
            Ipv4Addr::new(100, 64, 0, 111),
            false,
        );
        let created = admin
            .create_or_update_auth_key_registration(
                original.clone(),
                &PolicyStore::new(),
                Some(first_key.row.id),
            )
            .await
            .unwrap()
            .record;

        let mut relogin = original.clone();
        relogin.user = "bob".into();
        relogin.hostname = "bob-duplicate-nodekey".into();
        relogin.host_info.hostname = "bob-duplicate-nodekey".into();
        relogin.ipv4 = Some(Ipv4Addr::new(100, 64, 0, 112));
        let saved = admin
            .create_or_update_auth_key_registration(
                relogin,
                &PolicyStore::new(),
                Some(second_key.row.id),
            )
            .await
            .unwrap()
            .record;

        assert_eq!(created.node_key_hex, original.node_key_hex);
        assert_eq!(saved.node_key_hex, original.node_key_hex);
        assert_ne!(saved.node_id, created.node_id);
        let created_node_id = created.node_id.expect("created node id");
        let saved_node_id = saved.node_id.expect("saved node id");
        assert_eq!(saved.user, "bob");
        assert_eq!(saved.user_id, Some(bob.id));
        assert_eq!(saved.auth_key_id, Some(second_key.row.id));
        let rows: Vec<(i64, String, Option<i64>)> =
            sqlx::query_as("SELECT id, node_key, user_id FROM nodes ORDER BY id")
                .fetch_all(db.pool())
                .await
                .unwrap();
        assert_eq!(
            rows,
            vec![
                (
                    created_node_id as i64,
                    format!("nodekey:{}", original.node_key_hex),
                    Some(1)
                ),
                (
                    saved_node_id as i64,
                    format!("nodekey:{}", original.node_key_hex),
                    Some(bob.id as i64)
                )
            ]
        );
    }

    #[tokio::test]
    async fn persistent_oidc_registration_handler_writes_db_and_completes_cache() {
        let (admin, db, users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
        let user = create_oidc_test_user(&users).await;
        let mut pending = MachineRecord::new_at(
            Utc::now(),
            "dd".repeat(32),
            "ee".repeat(32),
            String::new(),
            "alice-oidc".into(),
            Ipv4Addr::new(100, 64, 0, 55),
            false,
        );
        pending.available_routes = vec!["10.20.0.0/24".into()];
        let registration_id = "p".repeat(24);
        cache.insert(registration_id.clone(), pending.clone());
        let waiter = {
            let cache = cache.clone();
            let registration_id = registration_id.clone();
            tokio::spawn(async move { cache.wait_for_registration(&registration_id).await })
        };
        tokio::task::yield_now().await;

        let handler = PersistentOidcRegistrationHandler::new(
            cache.clone(),
            admin.clone(),
            Arc::new(PolicyStore::new()),
        )
        .with_wire_registry(registry.clone());
        let expiry = Utc.timestamp_opt(4_102_444_800, 0).unwrap();
        let result = handler
            .complete_oidc_registration(&registration_id, &user, Some(expiry))
            .await
            .unwrap();

        assert!(result.new_node);
        assert!(cache.get(&registration_id).is_none());
        let stored = admin.get(&pending.node_key_hex).await.unwrap();
        assert_eq!(stored.user, "alice@example.com");
        assert_eq!(stored.register_method, REGISTER_METHOD_OIDC);
        assert_eq!(stored.expiry, Some(4_102_444_800));
        assert_eq!(stored.routes, vec!["10.20.0.0/24"]);
        assert_eq!(
            headscale_db::headscale_nodes::get_by_node_key(
                db.pool(),
                &format!("nodekey:{}", pending.node_key_hex)
            )
            .await
            .unwrap()
            .register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_OIDC
        );
        let wire = registry.get(&pending.node_key_hex).unwrap();
        assert_eq!(wire.user, "alice@example.com");
        assert_eq!(wire.expiry, Some(expiry));
        let owner = users.get_by_id(user.id).await.unwrap().unwrap();
        assert_eq!(wire.user_provider, owner.provider);
        assert_eq!(
            wire.user_created_at
                .map(|created_at| created_at.timestamp()),
            Some(owner.created_at as i64)
        );

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        match outcome {
            crate::tailscale_wire::RegistrationWaitOutcome::Registered(record) => {
                assert_eq!(record.user, "alice@example.com");
                assert_eq!(record.register_method, REGISTER_METHOD_OIDC);
                assert_eq!(record.user_provider, owner.provider);
                assert_eq!(record.user_created_at, wire.user_created_at);
            }
            other => panic!("unexpected registration outcome: {other:?}"),
        }
    }

    #[tokio::test]
    async fn persistent_oidc_auth_request_approves_owned_ssh_check() {
        let (admin, _db, users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let user = create_oidc_test_user(&users).await;
        let mut source = persistent_record();
        source.id = "31".repeat(32);
        source.machine_key_hex = "32".repeat(32);
        source.name = "alice-ssh-source".into();
        source.user = "alice@example.com".into();
        source.ipv4 = "100.64.0.31".into();
        let source = admin.create(source).await.unwrap();

        let cache = Arc::new(RegistrationCache::new());
        let auth_id = "a".repeat(24);
        cache.insert_ssh_check(
            auth_id.clone(),
            SshCheckBinding {
                src_node_id: source.node_id,
                dst_node_id: source.node_id,
                local_user: "root".into(),
            },
        );
        let waiter = {
            let cache = cache.clone();
            let auth_id = auth_id.clone();
            tokio::spawn(async move { cache.wait_for_auth(&auth_id).await })
        };
        tokio::task::yield_now().await;

        let handler = PersistentOidcRegistrationHandler::new(
            cache.clone(),
            admin,
            Arc::new(PolicyStore::new()),
        );
        handler
            .complete_oidc_auth_request(&auth_id, &user)
            .await
            .unwrap();

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome, crate::tailscale_wire::AuthWaitOutcome::Accepted);
    }

    #[tokio::test]
    async fn persistent_oidc_auth_request_rejects_wrong_source_owner() {
        let (admin, _db, users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let user = create_oidc_test_user(&users).await;
        users.create("bob").await.unwrap();
        let mut source = persistent_record();
        source.id = "33".repeat(32);
        source.machine_key_hex = "34".repeat(32);
        source.name = "local-user-ssh-source".into();
        source.user = "bob".into();
        source.ipv4 = "100.64.0.33".into();
        let source = admin.create(source).await.unwrap();

        let cache = Arc::new(RegistrationCache::new());
        let auth_id = "b".repeat(24);
        cache.insert_ssh_check(
            auth_id.clone(),
            SshCheckBinding {
                src_node_id: source.node_id,
                dst_node_id: source.node_id,
                local_user: "root".into(),
            },
        );
        let handler = PersistentOidcRegistrationHandler::new(
            cache.clone(),
            admin,
            Arc::new(PolicyStore::new()),
        );

        let err = handler
            .complete_oidc_auth_request(&auth_id, &user)
            .await
            .unwrap_err();

        assert_eq!(err, crate::oidc::OidcAuthError::UserNotSourceOwner);
        assert!(cache.ssh_binding(&auth_id).is_some());
    }

    #[tokio::test]
    async fn persistent_oidc_auth_request_rejects_tagged_source_node() {
        let (admin, _db, users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let user = create_oidc_test_user(&users).await;
        let mut source = persistent_record();
        source.id = "35".repeat(32);
        source.machine_key_hex = "36".repeat(32);
        source.name = "tagged-ssh-source".into();
        source.user = "alice@example.com".into();
        source.ipv4 = "100.64.0.35".into();
        source.tags = vec!["tag:server".into()];
        let source = admin.create(source).await.unwrap();

        let cache = Arc::new(RegistrationCache::new());
        let auth_id = "c".repeat(24);
        cache.insert_ssh_check(
            auth_id.clone(),
            SshCheckBinding {
                src_node_id: source.node_id,
                dst_node_id: source.node_id,
                local_user: "root".into(),
            },
        );
        let handler = PersistentOidcRegistrationHandler::new(
            cache.clone(),
            admin,
            Arc::new(PolicyStore::new()),
        );

        let err = handler
            .complete_oidc_auth_request(&auth_id, &user)
            .await
            .unwrap_err();

        assert_eq!(err, crate::oidc::OidcAuthError::SourceNodeNoUserOwner);
        assert!(cache.ssh_binding(&auth_id).is_some());
    }

    #[tokio::test]
    async fn persistent_oidc_registration_prefers_email_for_owner_identity() {
        let (admin, _db, users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
        let user = create_oidc_test_user_with(
            &users,
            "preferred",
            "Preferred User",
            "preferred@example.com",
            "https://issuer.example/preferred",
        )
        .await;
        let mut pending = MachineRecord::new_at(
            Utc::now(),
            "c9".repeat(32),
            "ca".repeat(32),
            String::new(),
            "oidc-email-owner".into(),
            Ipv4Addr::new(100, 64, 0, 64),
            false,
        );
        pending.user.clear();
        let registration_id = "y".repeat(24);
        cache.insert(registration_id.clone(), pending.clone());

        let handler = PersistentOidcRegistrationHandler::new(
            cache,
            admin.clone(),
            Arc::new(PolicyStore::new()),
        )
        .with_wire_registry(registry.clone());
        handler
            .complete_oidc_registration(&registration_id, &user, None)
            .await
            .unwrap();

        let stored = admin.get(&pending.node_key_hex).await.unwrap();
        assert_eq!(stored.user, "preferred@example.com");
        let wire = registry.get(&pending.node_key_hex).unwrap();
        assert_eq!(wire.user, "preferred@example.com");
    }

    #[tokio::test]
    async fn persistent_oidc_registration_handler_preserves_pending_expiry_without_provider_expiry()
    {
        let (admin, _db, users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
        let mut pending = MachineRecord::new_at(
            Utc::now(),
            "da".repeat(32),
            "db".repeat(32),
            String::new(),
            "alice-oidc-default".into(),
            Ipv4Addr::new(100, 64, 0, 56),
            false,
        );
        let pending_expiry = Utc.timestamp_opt(4_102_358_400, 0).unwrap();
        pending.expiry = Some(pending_expiry);
        let registration_id = "u".repeat(24);
        cache.insert(registration_id.clone(), pending.clone());

        let handler = PersistentOidcRegistrationHandler::new(
            cache.clone(),
            admin.clone(),
            Arc::new(PolicyStore::new()),
        )
        .with_wire_registry(registry.clone());
        let user = create_oidc_test_user(&users).await;
        let result = handler
            .complete_oidc_registration(&registration_id, &user, None)
            .await
            .unwrap();

        assert!(result.new_node);
        assert!(cache.get(&registration_id).is_none());
        let stored = admin.get(&pending.node_key_hex).await.unwrap();
        assert_eq!(stored.user, "alice@example.com");
        assert_eq!(stored.register_method, REGISTER_METHOD_OIDC);
        assert_eq!(stored.expiry, Some(4_102_358_400));
        let wire = registry.get(&pending.node_key_hex).unwrap();
        assert_eq!(wire.expiry, Some(pending_expiry));
    }

    #[tokio::test]
    async fn persistent_oidc_registration_handler_provider_expiry_overrides_pending_expiry() {
        let (admin, _db, users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
        let mut pending = MachineRecord::new_at(
            Utc::now(),
            "dc".repeat(32),
            "dd".repeat(32),
            String::new(),
            "alice-oidc-token".into(),
            Ipv4Addr::new(100, 64, 0, 57),
            false,
        );
        pending.expiry = Some(Utc.timestamp_opt(4_102_358_400, 0).unwrap());
        let token_expiry = Utc.timestamp_opt(4_102_444_800, 0).unwrap();
        let registration_id = "v".repeat(24);
        cache.insert(registration_id.clone(), pending.clone());

        let handler = PersistentOidcRegistrationHandler::new(
            cache.clone(),
            admin.clone(),
            Arc::new(PolicyStore::new()),
        )
        .with_wire_registry(registry.clone());
        let user = create_oidc_test_user(&users).await;
        let result = handler
            .complete_oidc_registration(&registration_id, &user, Some(token_expiry))
            .await
            .unwrap();

        assert!(result.new_node);
        let stored = admin.get(&pending.node_key_hex).await.unwrap();
        assert_eq!(stored.expiry, Some(4_102_444_800));
        let wire = registry.get(&pending.node_key_hex).unwrap();
        assert_eq!(wire.expiry, Some(token_expiry));
    }

    fn oidc_route_policy(approver: &str, prefix: &str) -> Arc<PolicyStore> {
        let policy = Arc::new(PolicyStore::new());
        let raw_policy =
            format!(r#"{{"autoApprovers":{{"routes":{{"{prefix}":["{approver}"]}}}}}}"#);
        policy.set(parse_hujson_policy(&raw_policy).unwrap(), raw_policy);
        policy
    }

    fn oidc_router_pending(
        node_byte: &str,
        machine_byte: &str,
        hostname: &str,
        last_octet: u8,
        routes: &[&str],
    ) -> MachineRecord {
        let mut pending = MachineRecord::new_at(
            Utc::now(),
            node_byte.repeat(32),
            machine_byte.repeat(32),
            String::new(),
            hostname.into(),
            Ipv4Addr::new(100, 64, 0, last_octet),
            false,
        );
        pending.user.clear();
        pending.available_routes = routes.iter().map(ToString::to_string).collect();
        pending
    }

    // headscale-go oidc.go handleRegistration: HandleNodeFromAuthPath, then
    // State.AutoApproveRoutes (SetApprovedRoutes persists the approval and
    // yields change.PolicyChange()), then Change(nodeChange, routesChange).
    // The registry is attached to the handler only, as an embedder may do.
    #[tokio::test]
    async fn persistent_oidc_registration_auto_approves_policy_routes() {
        let (admin, db, users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
        let policy = oidc_route_policy("alice@example.com", "10.80.0.0/16");
        registry.configure_policy(&policy);
        let user = create_oidc_test_user(&users).await;
        let pending = oidc_router_pending(
            "c1",
            "c2",
            "oidc-router",
            80,
            &["10.80.1.0/24", "10.99.0.0/24"],
        );
        let registration_id = "r".repeat(24);
        cache.insert(registration_id.clone(), pending.clone());
        let history_len = registry.map_change_history().len();

        let handler = PersistentOidcRegistrationHandler::new(cache.clone(), admin.clone(), policy)
            .with_wire_registry(registry.clone());
        let result = handler
            .complete_oidc_registration(&registration_id, &user, None)
            .await
            .unwrap();
        assert!(result.new_node);

        let stored = admin.get(&pending.node_key_hex).await.unwrap();
        assert_eq!(stored.routes, vec!["10.80.1.0/24", "10.99.0.0/24"]);
        assert_eq!(stored.approved_routes, vec!["10.80.1.0/24"]);
        let row = headscale_db::headscale_nodes::get_by_id(db.pool(), stored.node_id as i64)
            .await
            .unwrap();
        assert_eq!(row.approved_route_list(), vec!["10.80.1.0/24"]);
        let live = registry.get(&pending.node_key_hex).unwrap();
        assert_eq!(live.approved_routes, vec!["10.80.1.0/24"]);

        // HandleNodeFromAuthPath answers PolicyChange because the new node's
        // addresses join alice's autoApprover set; State.AutoApproveRoutes ->
        // SetApprovedRoutes then always yields PolicyChange. Same order and
        // labels as the gRPC RegisterNode path; neither carries an origin.
        let changes = registry.map_change_history();
        let new_changes = &changes[history_len..];
        assert_eq!(
            new_changes
                .iter()
                .map(crate::tailscale_wire::MapChange::reason_labels)
                .collect::<Vec<_>>(),
            vec![vec!["policy change"], vec!["policy change"]]
        );
        for change in new_changes {
            assert_eq!(change.origin_node_id, None);
            assert!(change.content.include_policy);
            assert!(change.content.requires_runtime_peer_computation);
        }
    }

    // The production composition (headscale-cli server.rs): the machine admin
    // owns the live registry and the handler holds the same one, so the
    // approval is projected by the admin and must not be applied twice.
    #[tokio::test]
    async fn persistent_oidc_registration_auto_approve_with_registry_owning_admin() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        users.create("alice").await.unwrap();
        let registry = Arc::new(MachineRegistry::new());
        let admin = Arc::new(
            PersistentMachineAdmin::new(db.pool().clone())
                .with_user_admin(users.clone())
                .with_wire_registry(registry.clone()),
        );
        let cache = Arc::new(RegistrationCache::new());
        let policy = oidc_route_policy("alice@example.com", "10.82.0.0/16");
        registry.configure_policy(&policy);
        let user = create_oidc_test_user(&users).await;
        let pending = oidc_router_pending(
            "c3",
            "c4",
            "oidc-owned",
            82,
            &["10.82.1.0/24", "10.99.0.0/24"],
        );
        let registration_id = "q".repeat(24);
        cache.insert(registration_id.clone(), pending.clone());
        let history_len = registry.map_change_history().len();

        let handler = PersistentOidcRegistrationHandler::new(cache, admin.clone(), policy)
            .with_wire_registry(registry.clone());
        handler
            .complete_oidc_registration(&registration_id, &user, None)
            .await
            .unwrap();

        let stored = admin.get(&pending.node_key_hex).await.unwrap();
        assert_eq!(stored.approved_routes, vec!["10.82.1.0/24"]);
        let row = headscale_db::headscale_nodes::get_by_id(db.pool(), stored.node_id as i64)
            .await
            .unwrap();
        assert_eq!(row.approved_route_list(), vec!["10.82.1.0/24"]);
        let live = registry.get(&pending.node_key_hex).unwrap();
        assert_eq!(live.approved_routes, vec!["10.82.1.0/24"]);
        let labels = registry.map_change_history()[history_len..]
            .iter()
            .map(crate::tailscale_wire::MapChange::reason_labels)
            .collect::<Vec<_>>();
        assert_eq!(labels, vec![vec!["policy change"], vec!["policy change"]]);
    }

    // State.AutoApproveRoutes only persists and emits a change when the
    // approved set differs; an uncovered route leaves the node's approvals
    // empty and adds nothing after the registration's own change.
    #[tokio::test]
    async fn persistent_oidc_registration_without_matching_approver_approves_nothing() {
        let (admin, db, users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
        let policy = oidc_route_policy("someone-else@example.com", "10.83.0.0/16");
        registry.configure_policy(&policy);
        let user = create_oidc_test_user(&users).await;
        let pending = oidc_router_pending("c5", "c6", "oidc-uncovered", 83, &["10.83.1.0/24"]);
        let registration_id = "p".repeat(24);
        cache.insert(registration_id.clone(), pending.clone());
        let history_len = registry.map_change_history().len();

        let handler = PersistentOidcRegistrationHandler::new(cache, admin.clone(), policy)
            .with_wire_registry(registry.clone());
        handler
            .complete_oidc_registration(&registration_id, &user, None)
            .await
            .unwrap();

        let stored = admin.get(&pending.node_key_hex).await.unwrap();
        assert_eq!(stored.routes, vec!["10.83.1.0/24"]);
        assert!(stored.approved_routes.is_empty());
        let row = headscale_db::headscale_nodes::get_by_id(db.pool(), stored.node_id as i64)
            .await
            .unwrap();
        assert!(row.approved_route_list().is_empty());
        assert!(
            registry
                .get(&pending.node_key_hex)
                .unwrap()
                .approved_routes
                .is_empty()
        );
        // Only the registration's own change (HandleNodeFromAuthPath); an
        // unchanged approval adds no SetApprovedRoutes PolicyChange.
        assert_eq!(registry.map_change_history()[history_len..].len(), 1);
    }

    #[tokio::test]
    async fn persistent_oidc_registration_auto_approved_routes_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headscale.db");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let (admin, db, users) = persistent_file_fixture(&url, true).await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
        let policy = oidc_route_policy("alice@example.com", "10.84.0.0/16");
        registry.configure_policy(&policy);
        let user = create_oidc_test_user(&users).await;
        let pending = oidc_router_pending(
            "c7",
            "c8",
            "oidc-durable",
            84,
            &["10.84.1.0/24", "10.99.0.0/24"],
        );
        let registration_id = "o".repeat(24);
        cache.insert(registration_id.clone(), pending.clone());

        let handler = PersistentOidcRegistrationHandler::new(cache.clone(), admin.clone(), policy)
            .with_wire_registry(registry);
        handler
            .complete_oidc_registration(&registration_id, &user, None)
            .await
            .unwrap();
        drop(handler);
        drop(cache);
        drop(admin);
        drop(users);
        db.close().await;

        let (reopened_admin, reopened_db, reopened_users) =
            persistent_file_fixture(&url, false).await;
        let stored = reopened_admin.get(&pending.node_key_hex).await.unwrap();
        assert_eq!(stored.routes, vec!["10.84.1.0/24", "10.99.0.0/24"]);
        assert_eq!(stored.approved_routes, vec!["10.84.1.0/24"]);
        let registry = MachineRegistry::new();
        assert_eq!(
            reopened_admin
                .hydrate_wire_registry(&registry)
                .await
                .unwrap(),
            1
        );
        let hydrated = registry.get(&pending.node_key_hex).unwrap();
        assert_eq!(hydrated.approved_routes, vec!["10.84.1.0/24"]);
        drop(reopened_admin);
        drop(reopened_users);
        reopened_db.close().await;
    }

    #[tokio::test]
    async fn persistent_oidc_registration_hydrates_canonical_fields_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headscale.db");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let node_key = "de".repeat(32);
        let machine_key = "ef".repeat(32);

        let (admin, db, users) = persistent_file_fixture(&url, true).await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let policy = Arc::new(PolicyStore::new());
        let user = create_oidc_test_user(&users).await;
        let raw_policy = r#"{"tagOwners":{"tag:server":["alice@example.com"]}}"#;
        policy.set(
            parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );
        let mut pending = MachineRecord::new_at(
            Utc.timestamp_opt(1_700_001_000, 0).unwrap(),
            node_key.clone(),
            machine_key.clone(),
            String::new(),
            "oidc-node".into(),
            Ipv4Addr::new(100, 64, 0, 89),
            false,
        );
        pending.last_seen = Utc.timestamp_opt(1_700_001_111, 0).unwrap();
        pending.disco_key = Some(format!("discokey:{}", "d2".repeat(32)));
        pending.endpoints = vec!["192.0.2.20:41641".into(), "[2001:db8::20]:41641".into()];
        pending.home_derp = 9;
        pending.os = "darwin".into();
        pending.os_version = "14.5".into();
        pending.ssh_host_keys = vec!["ssh-ed25519 AAAAC3NzaOidc".into()];
        pending.forced_tags = vec!["tag:server".into()];
        pending.available_routes = vec!["10.50.0.0/24".into()];
        pending.approved_routes = vec!["10.50.0.0/24".into()];
        let registration_id = "t".repeat(24);
        cache.insert(registration_id.clone(), pending.clone());

        let handler = PersistentOidcRegistrationHandler::new(cache.clone(), admin.clone(), policy);
        let expiry = Utc.timestamp_opt(4_102_444_800, 0).unwrap();
        let result = handler
            .complete_oidc_registration(&registration_id, &user, Some(expiry))
            .await
            .unwrap();

        assert!(result.new_node);
        let stored = admin.get(&node_key).await.unwrap();
        assert_eq!(stored.node_id, 1);
        assert_eq!(stored.id, node_key);
        assert_eq!(stored.user, "");
        assert_eq!(stored.machine_key_hex, machine_key);
        assert_eq!(stored.register_method, REGISTER_METHOD_OIDC);
        assert_eq!(stored.expiry, None);
        assert_eq!(stored.tags, vec!["tag:server"]);
        assert_eq!(stored.routes, vec!["10.50.0.0/24"]);
        // Go createAndSaveNewNode persists no ApprovedRoutes for a new node
        // (State.AutoApproveRoutes runs afterwards in the caller). Approve
        // explicitly so the reopen/hydration assertions below still cover them.
        assert!(stored.approved_routes.is_empty());
        admin
            .set_approved_routes(&node_key, vec!["10.50.0.0/24".into()])
            .await
            .unwrap();

        let raw = headscale_db::headscale_nodes::get_by_id(db.pool(), stored.node_id as i64)
            .await
            .unwrap();
        assert_eq!(raw.id, 1);
        assert_eq!(raw.user_id, None);
        assert_eq!(raw.node_key, format!("nodekey:{}", pending.node_key_hex));
        assert_eq!(raw.machine_key, format!("mkey:{}", pending.machine_key_hex));
        assert_eq!(raw.disco_key, format!("discokey:{}", "d2".repeat(32)));
        assert_eq!(raw.endpoint_list(), pending.endpoints);
        assert_eq!(
            raw.register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_OIDC
        );
        assert_eq!(raw.auth_key_id, None);
        assert_eq!(raw.tag_list(), vec!["tag:server"]);
        assert_eq!(raw.approved_route_list(), vec!["10.50.0.0/24"]);
        assert_eq!(raw.expiry, None);
        let host_info = raw.host_info_value();
        assert_eq!(host_info.get("OS").and_then(Value::as_str), Some("darwin"));
        assert_eq!(
            host_info.get("OSVersion").and_then(Value::as_str),
            Some("14.5")
        );
        assert_eq!(
            routes_from_host_info(&host_info),
            vec!["10.50.0.0/24".to_string()]
        );
        assert_eq!(preferred_derp_from_host_info(&host_info), 9);
        assert_eq!(
            ssh_host_keys_from_host_info(&host_info),
            vec!["ssh-ed25519 AAAAC3NzaOidc".to_string()]
        );
        drop(handler);
        drop(cache);
        drop(admin);
        drop(users);
        db.close().await;

        let (reopened_admin, reopened_db, reopened_users) =
            persistent_file_fixture(&url, false).await;
        let registry = MachineRegistry::new();
        assert_eq!(
            reopened_admin
                .hydrate_wire_registry(&registry)
                .await
                .unwrap(),
            1
        );
        let hydrated = registry.get(&pending.node_key_hex).unwrap();
        assert_eq!(hydrated.node_key_hex, pending.node_key_hex);
        assert_eq!(hydrated.machine_key_hex, pending.machine_key_hex);
        assert_eq!(hydrated.user, "");
        assert_eq!(hydrated.hostname, "oidc-node");
        assert_eq!(
            hydrated.ipv4.map(|ip| ip.to_string()).as_deref(),
            Some("100.64.0.89")
        );
        assert_eq!(
            hydrated.disco_key,
            Some(format!("discokey:{}", "d2".repeat(32)))
        );
        assert_eq!(hydrated.endpoints, pending.endpoints);
        assert_eq!(hydrated.home_derp, 9);
        assert_eq!(hydrated.os, "darwin");
        assert_eq!(hydrated.os_version, "14.5");
        assert_eq!(hydrated.ssh_host_keys, vec!["ssh-ed25519 AAAAC3NzaOidc"]);
        assert_eq!(hydrated.forced_tags, vec!["tag:server"]);
        assert_eq!(hydrated.available_routes, vec!["10.50.0.0/24"]);
        assert_eq!(hydrated.approved_routes, vec!["10.50.0.0/24"]);
        assert_eq!(hydrated.register_method, REGISTER_METHOD_OIDC);
        assert_eq!(hydrated.expiry, None);
        drop(reopened_admin);
        drop(reopened_users);
        reopened_db.close().await;
    }

    #[tokio::test]
    async fn persistent_oidc_registration_handler_rekeys_live_registry() {
        let (admin, db, users) = persistent_fixture().await;
        let user = create_oidc_test_user(&users).await;
        let mut existing = persistent_record();
        existing.user = user.username();
        existing.register_method = REGISTER_METHOD_OIDC;
        let created = admin
            .create_or_update_auth_path_inner(
                existing,
                &PolicyStore::new(),
                None,
                Some(user.id as i64),
                false,
                None,
            )
            .await
            .unwrap()
            .record;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
        registry.upsert(
            created.id.clone(),
            machine_admin_record_to_wire(&created).unwrap(),
        );

        let mut pending = MachineRecord::new_at(
            Utc::now(),
            "dd".repeat(32),
            created.machine_key_hex.clone(),
            String::new(),
            "alice-oidc".into(),
            Ipv4Addr::new(100, 64, 99, 99),
            false,
        );
        pending.available_routes = vec!["10.30.0.0/24".into()];
        pending.disco_key = Some(format!("discokey:{}", "d3".repeat(32)));
        pending.endpoints = vec!["192.0.2.30:41641".into()];
        pending.home_derp = 30;
        pending.ssh_host_keys = vec!["ssh-ed25519 AAAAC3NzaOidcRekey".into()];
        let registration_id = "q".repeat(24);
        cache.insert(registration_id.clone(), pending.clone());

        let handler = PersistentOidcRegistrationHandler::new(
            cache.clone(),
            admin.clone(),
            Arc::new(PolicyStore::new()),
        )
        .with_wire_registry(registry.clone());
        let result = handler
            .complete_oidc_registration(
                &registration_id,
                &user,
                Some(Utc.timestamp_opt(4_102_444_800, 0).unwrap()),
            )
            .await
            .unwrap();

        assert!(!result.new_node);
        assert!(registry.get(&created.id).is_none());
        let wire = registry.get(&pending.node_key_hex).unwrap();
        assert_eq!(
            wire.ipv4.map(|ip| ip.to_string()).as_deref(),
            Some(created.ipv4.as_str())
        );
        assert_eq!(wire.machine_key_hex, created.machine_key_hex);
        assert_eq!(wire.user, "alice@example.com");
        assert_eq!(
            wire.disco_key.as_deref(),
            Some(format!("discokey:{}", "d3".repeat(32)).as_str())
        );
        assert_eq!(wire.endpoints, vec!["192.0.2.30:41641"]);
        assert_eq!(wire.home_derp, 30);
        assert_eq!(wire.ssh_host_keys, vec!["ssh-ed25519 AAAAC3NzaOidcRekey"]);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn persistent_oidc_registration_handler_validates_requested_tags() {
        let (admin, db, users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
        let policy = Arc::new(PolicyStore::new());
        let user = create_oidc_test_user(&users).await;
        let raw_policy = r#"{"tagOwners":{"tag:server":["alice@example.com"]}}"#;
        policy.set(
            parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );

        let mut pending = MachineRecord::new_at(
            Utc::now(),
            "99".repeat(32),
            "98".repeat(32),
            String::new(),
            "alice-tagged".into(),
            Ipv4Addr::new(100, 64, 0, 77),
            false,
        );
        pending.forced_tags = vec!["tag:server".into(), "tag:server".into()];
        let registration_id = "r".repeat(24);
        cache.insert(registration_id.clone(), pending.clone());

        let handler = PersistentOidcRegistrationHandler::new(cache.clone(), admin.clone(), policy)
            .with_wire_registry(registry.clone());
        let result = handler
            .complete_oidc_registration(
                &registration_id,
                &user,
                Some(Utc.timestamp_opt(4_102_444_800, 0).unwrap()),
            )
            .await
            .unwrap();

        assert!(result.new_node);
        let stored = admin.get(&pending.node_key_hex).await.unwrap();
        assert_eq!(stored.tags, vec!["tag:server"]);
        assert_eq!(
            stored.expiry, None,
            "tagged OIDC registrations disable node-key expiry"
        );
        let wire = registry.get(&pending.node_key_hex).unwrap();
        assert_eq!(wire.forced_tags, vec!["tag:server"]);
        assert_eq!(wire.expiry, None);
        let raw = headscale_db::headscale_nodes::get_by_node_key(
            db.pool(),
            &format!("nodekey:{}", pending.node_key_hex),
        )
        .await
        .unwrap();
        assert_eq!(raw.tag_list(), vec!["tag:server"]);
    }

    #[tokio::test]
    async fn persistent_oidc_registration_handler_rejects_unowned_requested_tags() {
        let (admin, db, users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
        let policy = Arc::new(PolicyStore::new());
        let user = create_oidc_test_user(&users).await;
        let raw_policy = r#"{"tagOwners":{"tag:server":["alice@example.com"]}}"#;
        policy.set(
            parse_hujson_policy(raw_policy).unwrap(),
            raw_policy.to_string(),
        );

        let mut pending = MachineRecord::new_at(
            Utc::now(),
            "88".repeat(32),
            "87".repeat(32),
            String::new(),
            "alice-bad-tag".into(),
            Ipv4Addr::new(100, 64, 0, 78),
            false,
        );
        pending.forced_tags = vec!["tag:db".into()];
        let registration_id = "s".repeat(24);
        cache.insert(registration_id.clone(), pending.clone());

        let handler = PersistentOidcRegistrationHandler::new(cache.clone(), admin.clone(), policy)
            .with_wire_registry(registry.clone());
        let err = handler
            .complete_oidc_registration(
                &registration_id,
                &user,
                Some(Utc.timestamp_opt(4_102_444_800, 0).unwrap()),
            )
            .await
            .unwrap_err();

        assert!(matches!(err, crate::oidc::OidcRegistrationError::Store(_)));
        assert!(err.to_string().contains("requested tags [tag:db]"));
        assert!(cache.get(&registration_id).is_some());
        assert!(registry.get(&pending.node_key_hex).is_none());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn persistent_machine_admin_mutations_write_go_nodes_table() {
        let (admin, db, _users) = persistent_fixture().await;
        let created = admin.create(persistent_record()).await.unwrap();
        let node_key = created.id.clone();
        let machine_key = created.machine_key_hex.clone();

        admin.rename(&node_key, "alice-renamed").await.unwrap();
        assert_eq!(admin.get(&node_key).await.unwrap().name, "alice-renamed");

        admin
            .set_tags(
                &node_key,
                vec!["tag:prod".into(), "tag:dev".into(), "tag:prod".into()],
            )
            .await
            .unwrap();
        assert_eq!(
            admin.get(&node_key).await.unwrap().tags,
            vec!["tag:dev", "tag:prod"]
        );

        admin
            .set_approved_routes(&node_key, vec!["0.0.0.0/0".into()])
            .await
            .unwrap();
        assert_eq!(
            admin.get(&node_key).await.unwrap().approved_routes,
            vec!["0.0.0.0/0", "::/0"]
        );

        let expiry = Utc::now() + chrono::Duration::seconds(60);
        admin.expire_at(&node_key, Some(expiry)).await.unwrap();
        assert_eq!(
            admin.get(&node_key).await.unwrap().expiry,
            Some(expiry.timestamp() as u64)
        );

        admin.logout(&node_key).await.unwrap();
        let logged_out = admin.get(&node_key).await.unwrap();
        assert_eq!(logged_out.machine_key_hex, machine_key);
        assert!(logged_out.expiry.is_some());

        admin.delete(&node_key).await.unwrap();
        assert!(admin.get(&node_key).await.is_none());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM nodes")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn persistent_machine_admin_route_withdraw_preserves_approved_routes() {
        let (admin, _db, _users) = persistent_fixture().await;
        let mut record = persistent_record();
        record.routes = vec!["10.0.0.0/24".into(), "10.1.0.0/24".into()];
        record.approved_routes = vec!["10.0.0.0/24".into()];
        let created = admin.create(record).await.unwrap();

        admin
            .set_routes(
                &created.id,
                vec!["10.1.0.0/24".into(), "10.2.0.0/24".into()],
            )
            .await
            .unwrap();
        let updated = admin.get(&created.id).await.unwrap();
        assert_eq!(updated.routes, vec!["10.1.0.0/24", "10.2.0.0/24"]);
        assert_eq!(updated.approved_routes, vec!["10.0.0.0/24"]);
    }
}
