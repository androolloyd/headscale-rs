//! Admin-side machine surface.
//!
//! The wire-layer [`crate::tailscale_wire::MachineRegistry`] is
//! intentionally read-only from outside the wire crate's own
//! `register` handler. The admin panel needs `expire` + `delete` too,
//! and we don't want to expand the wire registry's API (it's frozen
//! while Wall 6 / Gateway WIP land in parallel branches).
//!
//! So this module defines a parallel trait — [`MachineAdmin`] — which
//! the embedding host implements on whatever registry it owns. For
//! v0 the admin panel ships with a default adapter
//! [`WireMachineAdmin`] that wraps `MachineRegistry` and stores
//! "expired" / "deleted" decisions in a sidecar set. The sidecar
//! doesn't try to remove records from the wire registry (that would
//! need a write-API change); it just hides them from the admin views
//! and records the operator intent so a future migration that adds
//! `MachineRegistry::remove` can drain it.
//!
//! ## What we render
//!
//! `MachineAdminRecord` carries everything the wire `MachineRecord`
//! exposes (id = node_key_hex, name from hostname, user, ipv4, OS
//! placeholders) plus admin-only fields (`expired`, `last_seen`,
//! `version`) that v0 stubs out — they'll be populated once the
//! NodeMetrics subagent lands.
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
//! The default [`WireMachineAdmin`] adapter writes through to the
//! wire-layer [`crate::tailscale_wire::MachineRegistry`] — the
//! sidecar-only behaviour from the original v0 design is retained for
//! `expire` (so a never-cleared expiry intent stays visible after a
//! restart that drops the wire registry), but the new verbs all mutate
//! the registry directly.

use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sqlx::SqlitePool;

use crate::policy::{PolicyStore, validate_requested_tags_for_node};
use crate::tailscale_wire::{
    MachineRecord, MachineRegistrationStore, MachineRegistry, PersistedMachineRegistration,
    RegistrationCache, routes::auto_approved_routes_for_node,
};

use super::auth::now_unix;
use super::users::UserAdmin;

const REGISTER_METHOD_AUTH_KEY: i32 = 1;
const REGISTER_METHOD_OIDC: i32 = 3;

/// Admin-side view of one registered machine.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineAdminRecord {
    /// Upstream numeric node ID. Persistent stores populate this from
    /// `nodes.id`; volatile wire-only adapters leave it at zero and
    /// gRPC falls back to the deterministic legacy node-key hash.
    #[serde(default)]
    pub node_id: u64,
    /// `node_key_hex` from the wire registry. Used as the URL slug.
    pub id: String,
    /// Hostname the client advertised (may be empty).
    pub name: String,
    pub user: String,
    /// Allocated tailnet IPv4 (string form for stable JSON).
    pub ipv4: String,
    /// Best-effort online flag. v0 returns `true` for any record
    /// present in the wire registry that hasn't been "expired" by
    /// the admin; richer tracking lands with NodeMetrics integration.
    pub online: bool,
    /// Unix-seconds, best-effort. v0 stubs to `created_at` for any
    /// record we have a stamp for (none today); fills 0 otherwise.
    pub last_seen: u64,
    /// Unix-seconds node creation timestamp.
    #[serde(default)]
    pub created_at: u64,
    /// Unix-seconds node expiry timestamp. `None` means never expires.
    #[serde(default)]
    pub expiry: Option<u64>,
    /// Hex machine key (may be empty if the registrant only carried a
    /// NodeKey).
    pub machine_key_hex: String,
    /// OS placeholder. The wire `MachineRecord` doesn't carry OS today
    /// (HostInfo is only used inside the register handler); v0 shows
    /// "unknown" and the field exists for the JSON contract.
    pub os: String,
    /// Client version placeholder. Same story as `os`.
    pub version: String,
    /// Tags placeholder. Wired through preauth on a follow-up.
    pub tags: Vec<String>,
    /// Routes the node advertises. Empty in v0.
    pub routes: Vec<String>,
    /// Routes approved by operator/policy and emitted in `AllowedIPs`.
    #[serde(default)]
    pub approved_routes: Vec<String>,
    /// Upstream `RegisterMethod` enum numeric value.
    #[serde(default)]
    pub register_method: i32,
    /// Whether an admin marked this machine "expired".
    pub expired: bool,
}

/// Errors the admin trait can surface.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MachineAdminError {
    #[error("machine '{0}' not found")]
    NotFound(String),
    #[error("bad request: {0}")]
    BadRequest(String),
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
    async fn get(&self, id: &str) -> Option<MachineAdminRecord>;
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
    /// Logout a machine — clear Noise/disco keys + stamp expiry=now.
    /// Mirrors `db.NodeLogout`.
    async fn logout(&self, id: &str) -> Result<(), MachineAdminError>;
    /// Rename a machine. Empty hostname returns
    /// `MachineAdminError::BadRequest`. Mirrors `db.NodeRenameNode`.
    async fn rename(&self, id: &str, hostname: &str) -> Result<(), MachineAdminError>;
    /// Replace the operator-forced tag list. Empty list clears the
    /// override. Mirrors `db.SetTags`.
    async fn set_tags(&self, id: &str, tags: Vec<String>) -> Result<(), MachineAdminError>;
    /// Replace approved routes. Empty list clears the approval.
    async fn set_approved_routes(
        &self,
        id: &str,
        routes: Vec<String>,
    ) -> Result<(), MachineAdminError>;
    /// Replace the node's advertised route list while preserving
    /// operator approvals.
    async fn set_routes(&self, id: &str, routes: Vec<String>) -> Result<(), MachineAdminError>;
    /// Mark a machine deleted. Same sidecar story as `expire`. The
    /// record disappears from `list()` once flagged.
    async fn delete(&self, id: &str) -> Result<(), MachineAdminError>;
}

/// Re-run policy auto-approvers for every visible machine.
///
/// Existing approved routes are preserved; newly advertised routes are
/// approved only when the loaded policy allows the node to advertise
/// them. This mirrors headscale-go policy reload behaviour.
pub(crate) async fn apply_policy_auto_approvals(
    policy: &PolicyStore,
    machines: &dyn MachineAdmin,
) -> Result<usize, MachineAdminError> {
    let mut changed = 0usize;
    for node in machines.list().await {
        let user = (!node.user.is_empty()).then_some(node.user.as_str());
        let approved = auto_approved_routes_for_node(
            policy,
            &node.ipv4,
            user,
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
        if approved != node.approved_routes {
            machines.set_approved_routes(&node.id, approved).await?;
            changed += 1;
        }
    }
    Ok(changed)
}

/// Default impl: adapts [`MachineRegistry`] for the admin panel.
///
/// The wire registry exposes `all()` + `get(node_key)`; we layer two
/// in-memory sets on top for the "expired" / "deleted" admin decisions.
/// Both sets are cleared on process restart — same volatile-by-design
/// model the rest of the admin v0 uses.
#[derive(Clone)]
pub struct WireMachineAdmin {
    registry: Arc<MachineRegistry>,
    expired: Arc<RwLock<BTreeSet<String>>>,
    deleted: Arc<RwLock<BTreeSet<String>>>,
}

impl WireMachineAdmin {
    pub fn new(registry: Arc<MachineRegistry>) -> Self {
        Self {
            registry,
            expired: Arc::new(RwLock::new(BTreeSet::new())),
            deleted: Arc::new(RwLock::new(BTreeSet::new())),
        }
    }

    /// Render a borrowed `(id, rec)` pair into the admin DTO without
    /// consuming the source record. #238: avoids cloning the
    /// `MachineRecord` strings out of the registry snapshot in
    /// `list()` — the few strings the DTO needs are cloned only out of
    /// the kept records.
    fn render(
        id: &str,
        rec: &crate::tailscale_wire::MachineRecord,
        sidecar_expired: bool,
    ) -> MachineAdminRecord {
        // P1 lifecycle: the wire registry now carries `expiry` itself.
        // A machine is "expired" if the sidecar flag is set OR the
        // wire record's expiry has elapsed against wall-clock. The
        // sidecar survives across `set_expiry(None)` calls so the
        // admin's intent stays visible until an explicit "unexpire".
        let now = Utc::now();
        let wire_expired = rec.is_expired_at(now);
        let is_expired = sidecar_expired || wire_expired;
        // last_seen on the wire is the authoritative value; fall back
        // to `now_unix` only when zero (record was inserted by tests
        // that didn't stamp it).
        let last_seen = rec.last_seen.timestamp().max(0) as u64;
        let last_seen = if is_expired {
            0
        } else if last_seen == 0 {
            now_unix()
        } else {
            last_seen
        };
        MachineAdminRecord {
            node_id: 0,
            id: id.to_string(),
            name: rec.hostname.clone(),
            user: rec.user.clone(),
            ipv4: rec.ipv4.to_string(),
            online: !is_expired,
            last_seen,
            created_at: rec.created_at.timestamp().max(0) as u64,
            expiry: rec.expiry.map(|t| t.timestamp().max(0) as u64),
            machine_key_hex: rec.machine_key_hex.clone(),
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

fn nonempty_or_unknown(value: &str) -> String {
    if value.is_empty() {
        "unknown".into()
    } else {
        value.to_string()
    }
}

/// sqlx-backed node admin adapter over the canonical headscale-go
/// `nodes` table.
///
/// The URL/admin slug remains the node key hex (`MachineAdminRecord::id`)
/// so existing Octra admin routes stay stable. The upstream-visible
/// numeric ID is carried separately in `MachineAdminRecord::node_id`
/// and is what gRPC uses when present.
#[derive(Clone)]
pub struct PersistentMachineAdmin {
    pool: SqlitePool,
    users: Option<Arc<dyn UserAdmin>>,
}

#[derive(Clone)]
pub struct PersistentOidcRegistrationHandler {
    registration_cache: Arc<RegistrationCache>,
    machines: Arc<PersistentMachineAdmin>,
    policy: Arc<PolicyStore>,
    wire_registry: Option<Arc<MachineRegistry>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthPathRegistrationResult {
    pub record: MachineAdminRecord,
    pub new_node: bool,
    pub replaced_node_key_hex: Option<String>,
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
        }
    }

    pub fn with_wire_registry(mut self, wire_registry: Arc<MachineRegistry>) -> Self {
        self.wire_registry = Some(wire_registry);
        self
    }
}

impl PersistentMachineAdmin {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool, users: None }
    }

    pub fn with_user_admin(mut self, users: Arc<dyn UserAdmin>) -> Self {
        self.users = Some(users);
        self
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn hydrate_wire_registry(
        &self,
        registry: &MachineRegistry,
    ) -> Result<usize, MachineAdminError> {
        let rows = headscale_db::headscale_nodes::list(&self.pool)
            .await
            .map_err(|e| db_error_to_machine(e, "nodes"))?;
        let mut hydrated = 0usize;
        for row in rows {
            let wire = self.row_to_wire_record(row).await?;
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
        self.create_or_update_auth_path_inner(record, policy, None, true, None)
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
            false,
            Some(&wire_record),
        )
        .await
    }

    async fn create_or_update_auth_path_inner(
        &self,
        mut record: MachineAdminRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
        validate_requested_tags: bool,
        wire_record: Option<&MachineRecord>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        if record.id.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "node key must not be empty".into(),
            ));
        }
        record
            .ipv4
            .parse::<Ipv4Addr>()
            .map_err(|e| MachineAdminError::BadRequest(format!("invalid IPv4: {e}")))?;
        let user_id = self.user_id_for_record(&record).await?;
        if validate_requested_tags
            && validate_requested_tags_for_node(
                policy,
                record.ipv4.as_str(),
                record.user.as_str(),
                &mut record.tags,
            )
            .map_err(MachineAdminError::BadRequest)?
        {
            record.expiry = None;
        }
        let node_key = key_with_prefix("nodekey:", record.id.trim());
        let machine_key = key_with_prefix("mkey:", &record.machine_key_hex);

        let existing_for_user = match user_id {
            Some(user_id) => match headscale_db::headscale_nodes::get_by_machine_key_and_user(
                &self.pool,
                &machine_key,
                user_id,
            )
            .await
            {
                Ok(row) => Some(row),
                Err(headscale_db::DbError::NotFound(_)) => None,
                Err(e) => return Err(db_error_to_machine(e, &record.id)),
            },
            None => None,
        };
        let existing_for_machine =
            match headscale_db::headscale_nodes::get_by_machine_key(&self.pool, &machine_key).await
            {
                Ok(row) => Some(row),
                Err(headscale_db::DbError::NotFound(_)) => None,
                Err(e) => return Err(db_error_to_machine(e, &record.id)),
            };
        let existing = existing_for_user.or_else(|| {
            existing_for_machine
                .as_ref()
                .filter(|row| !row.tag_list().is_empty())
                .cloned()
        });

        if let Some(existing) = existing {
            let replaced_node_key_hex = key_without_prefix("nodekey:", &existing.node_key);
            match headscale_db::headscale_nodes::get_by_node_key(&self.pool, &node_key).await {
                Ok(row) if row.id != existing.id => {
                    return Err(MachineAdminError::BadRequest("node already exists".into()));
                }
                Ok(_) | Err(headscale_db::DbError::NotFound(_)) => {}
                Err(e) => return Err(db_error_to_machine(e, &record.id)),
            }
            if let Some(ipv4) = existing.ipv4.as_ref().filter(|value| !value.is_empty()) {
                record.ipv4.clone_from(ipv4);
            }
            let mut approved = existing.approved_route_list();
            approved.extend(record.approved_routes.clone());
            record.approved_routes = auto_approved_routes_for_node(
                policy,
                &record.ipv4,
                Some(&record.user),
                &record.tags,
                &approved,
                &record.routes,
            )
            .map_err(MachineAdminError::BadRequest)?;

            let row = headscale_db::headscale_nodes::update_from_auth_path(
                &self.pool,
                existing.id,
                create_params_for_auth_path(&record, wire_record, user_id, auth_key_id),
            )
            .await
            .map_err(|e| db_error_to_machine(e, &record.id))?;
            let record = self.row_to_record(row).await;
            Ok(AuthPathRegistrationResult {
                replaced_node_key_hex: (replaced_node_key_hex != record.id)
                    .then_some(replaced_node_key_hex),
                record,
                new_node: false,
            })
        } else {
            record.approved_routes = auto_approved_routes_for_node(
                policy,
                &record.ipv4,
                Some(&record.user),
                &record.tags,
                &record.approved_routes,
                &record.routes,
            )
            .map_err(MachineAdminError::BadRequest)?;
            let row = headscale_db::headscale_nodes::create(
                &self.pool,
                create_params_for_auth_path(&record, wire_record, user_id, auth_key_id),
            )
            .await
            .map_err(|e| db_error_to_machine(e, &record.id))?;
            let record = self.row_to_record(row).await;
            Ok(AuthPathRegistrationResult {
                record,
                new_node: true,
                replaced_node_key_hex: None,
            })
        }
    }

    async fn row_by_slug(
        &self,
        id: &str,
    ) -> Result<headscale_db::headscale_nodes::HeadscaleNodeRow, MachineAdminError> {
        let node_key = key_with_prefix("nodekey:", id);
        match headscale_db::headscale_nodes::get_by_node_key(&self.pool, &node_key).await {
            Ok(row) => Ok(row),
            Err(headscale_db::DbError::NotFound(_)) => {
                if let Ok(node_id) = id.parse::<i64>() {
                    headscale_db::headscale_nodes::get_by_id(&self.pool, node_id)
                        .await
                        .map_err(|e| db_error_to_machine(e, id))
                } else {
                    Err(MachineAdminError::NotFound(id.to_string()))
                }
            }
            Err(e) => Err(db_error_to_machine(e, id)),
        }
    }

    async fn user_id_for_record(
        &self,
        record: &MachineAdminRecord,
    ) -> Result<Option<i64>, MachineAdminError> {
        if record.user.trim().is_empty() {
            return Ok(None);
        }
        let Some(users) = &self.users else {
            return Ok(record.user.parse::<i64>().ok());
        };
        let user = users
            .get(&record.user)
            .await
            .map_err(|e| MachineAdminError::BadRequest(e.to_string()))?
            .ok_or_else(|| MachineAdminError::BadRequest("user not found".to_string()))?;
        i64::try_from(user.id)
            .map(Some)
            .map_err(|_| MachineAdminError::BadRequest("user id out of range".to_string()))
    }

    async fn user_name_for_row(
        &self,
        row: &headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> String {
        let Some(user_id) = row.user_id else {
            return String::new();
        };
        let Some(users) = &self.users else {
            return user_id.to_string();
        };
        match u64::try_from(user_id).ok().map(|id| users.get_by_id(id)) {
            Some(fut) => match fut.await {
                Ok(Some(user)) => user.name,
                Ok(None) | Err(_) => user_id.to_string(),
            },
            None => user_id.to_string(),
        }
    }

    async fn row_to_record(
        &self,
        row: headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> MachineAdminRecord {
        let host_info = row.host_info_value();
        let routes = routes_from_host_info(&host_info);
        let now = now_unix() as i64;
        let expired = row.expiry.is_some_and(|expiry| expiry <= now);
        let name = if row.given_name.is_empty() {
            row.hostname.clone()
        } else {
            row.given_name.clone()
        };
        MachineAdminRecord {
            node_id: u64::try_from(row.id).unwrap_or_default(),
            id: key_without_prefix("nodekey:", &row.node_key),
            name,
            user: self.user_name_for_row(&row).await,
            ipv4: row.ipv4.clone().unwrap_or_default(),
            online: !expired,
            last_seen: row.last_seen.unwrap_or(row.created_at).max(0) as u64,
            created_at: row.created_at.max(0) as u64,
            expiry: row.expiry.map(|expiry| expiry.max(0) as u64),
            machine_key_hex: key_without_prefix("mkey:", &row.machine_key),
            os: host_info
                .get("OS")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            version: host_info
                .get("OSVersion")
                .or_else(|| host_info.get("App"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            tags: row.tag_list(),
            routes,
            approved_routes: row.approved_route_list(),
            register_method: register_method_from_db(&row.register_method),
            expired,
        }
    }

    async fn row_to_wire_record(
        &self,
        row: headscale_db::headscale_nodes::HeadscaleNodeRow,
    ) -> Result<MachineRecord, MachineAdminError> {
        let host_info = row.host_info_value();
        let node_key = key_without_prefix("nodekey:", &row.node_key);
        if node_key.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "persisted node has empty node key".to_string(),
            ));
        }
        let created_at =
            unix_timestamp_for_record(row.created_at.max(0) as u64, &node_key, "created_at")?;
        let last_seen = unix_timestamp_for_record(
            row.last_seen.unwrap_or(row.created_at).max(0) as u64,
            &node_key,
            "last_seen",
        )?;
        let ipv4 = row
            .ipv4
            .as_deref()
            .unwrap_or_default()
            .parse()
            .map_err(|e| {
                MachineAdminError::BadRequest(format!(
                    "persisted node {node_key} has invalid IPv4 '{}': {e}",
                    row.ipv4.as_deref().unwrap_or_default()
                ))
            })?;
        let name = if row.given_name.is_empty() {
            row.hostname.clone()
        } else {
            row.given_name.clone()
        };
        let mut record = MachineRecord::new_at(
            created_at,
            node_key.clone(),
            key_without_prefix("mkey:", &row.machine_key),
            self.user_name_for_row(&row).await,
            name,
            ipv4,
            false,
        );
        record.disco_key = (!row.disco_key.is_empty()).then_some(row.disco_key.clone());
        record.endpoints = row.endpoint_list();
        record.home_derp = preferred_derp_from_host_info(&host_info);
        record.expiry = row
            .expiry
            .map(|expiry| unix_timestamp_for_record(expiry.max(0) as u64, &node_key, "expiry"))
            .transpose()?;
        record.last_seen = last_seen;
        record.os = host_info
            .get("OS")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        record.os_version = host_info
            .get("OSVersion")
            .or_else(|| host_info.get("App"))
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        record.ssh_host_keys = ssh_host_keys_from_host_info(&host_info);
        record.forced_tags = row.tag_list();
        record.available_routes = routes_from_host_info(&host_info);
        record.approved_routes = row.approved_route_list();
        record.register_method = register_method_from_db(&row.register_method);
        Ok(record)
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
        let pending = self
            .registration_cache
            .get(registration_id)
            .ok_or(crate::oidc::OidcRegistrationError::SessionExpired)?;
        let mut record = machine_admin_record_from_wire(&pending);
        record.user = oidc_user_name(user);
        record.expiry = node_expiry.map(|expiry| expiry.timestamp().max(0) as u64);
        record.register_method = REGISTER_METHOD_OIDC;

        let result = self
            .machines
            .create_or_update_auth_path_inner(record, &self.policy, None, true, Some(&pending))
            .await
            .map_err(|err| crate::oidc::OidcRegistrationError::Store(err.to_string()))?;
        let wire_record = canonical_wire_record_for_auth_path(&result.record, Some(&pending))
            .map_err(|err| crate::oidc::OidcRegistrationError::Store(err.to_string()))?;
        if let Some(registry) = &self.wire_registry {
            if let Some(old_node_key_hex) = result.replaced_node_key_hex.as_deref() {
                registry.replace_node_key(
                    old_node_key_hex,
                    wire_record.node_key_hex.clone(),
                    wire_record.clone(),
                );
            } else {
                registry.upsert(wire_record.node_key_hex.clone(), wire_record.clone());
            }
        }
        if self
            .registration_cache
            .complete(registration_id, wire_record)
        {
            Ok(crate::oidc::OidcRegistrationResult {
                new_node: result.new_node,
            })
        } else {
            Err(crate::oidc::OidcRegistrationError::SessionExpired)
        }
    }
}

#[async_trait]
impl MachineRegistrationStore for PersistentMachineAdmin {
    async fn create_or_update_auth_key_registration(
        &self,
        record: MachineRecord,
        policy: &PolicyStore,
        auth_key_id: Option<i64>,
    ) -> Result<PersistedMachineRegistration, String> {
        let result = self
            .create_or_update_auth_key_path(record, policy, auth_key_id)
            .await
            .map_err(|err| err.to_string())?;
        let record = machine_admin_record_to_wire(&result.record).map_err(|err| err.to_string())?;
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
        let node_key = key_with_prefix("nodekey:", &record.node_key_hex);
        let row = headscale_db::headscale_nodes::get_by_node_key(&self.pool, &node_key)
            .await
            .map_err(|err| db_error_to_machine(err, &record.node_key_hex).to_string())?;
        let user_id = self
            .user_id_for_record(&machine_admin_record_from_wire(&record))
            .await
            .map_err(|err| err.to_string())?;
        let row = headscale_db::headscale_nodes::update_from_auth_path(
            &self.pool,
            row.id,
            create_params_for_wire_record(&record, user_id, row.auth_key_id),
        )
        .await
        .map_err(|err| db_error_to_machine(err, &record.node_key_hex).to_string())?;
        let record = self
            .row_to_wire_record(row)
            .await
            .map_err(|err| err.to_string())?;
        Ok(PersistedMachineRegistration {
            record,
            replaced_node_key_hex: None,
        })
    }
}

#[async_trait]
impl MachineAdmin for PersistentMachineAdmin {
    async fn list(&self) -> Vec<MachineAdminRecord> {
        match headscale_db::headscale_nodes::list(&self.pool).await {
            Ok(rows) => {
                let mut out = Vec::with_capacity(rows.len());
                for row in rows {
                    out.push(self.row_to_record(row).await);
                }
                out
            }
            Err(e) => {
                tracing::warn!(?e, "persistent machine list failed");
                Vec::new()
            }
        }
    }

    async fn get(&self, id: &str) -> Option<MachineAdminRecord> {
        match self.row_by_slug(id).await {
            Ok(row) => Some(self.row_to_record(row).await),
            Err(MachineAdminError::NotFound(_)) => None,
            Err(e) => {
                tracing::warn!(?e, id, "persistent machine get failed");
                None
            }
        }
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
        let node_key = key_with_prefix("nodekey:", record.id.trim());
        match headscale_db::headscale_nodes::get_by_node_key(&self.pool, &node_key).await {
            Ok(_) => return Err(MachineAdminError::BadRequest("node already exists".into())),
            Err(headscale_db::DbError::NotFound(_)) => {}
            Err(e) => return Err(db_error_to_machine(e, &record.id)),
        }
        record
            .ipv4
            .parse::<Ipv4Addr>()
            .map_err(|e| MachineAdminError::BadRequest(format!("invalid IPv4: {e}")))?;
        let user_id = self.user_id_for_record(&record).await?;
        let row = headscale_db::headscale_nodes::create(
            &self.pool,
            create_params_for_record(&record, user_id),
        )
        .await
        .map_err(|e| db_error_to_machine(e, &record.id))?;
        Ok(self.row_to_record(row).await)
    }

    async fn complete_registration(
        &self,
        record: MachineAdminRecord,
        policy: &PolicyStore,
        wire_record: Option<MachineRecord>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        self.create_or_update_auth_path_inner(record, policy, None, true, wire_record.as_ref())
            .await
    }

    async fn expire_at(
        &self,
        id: &str,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), MachineAdminError> {
        let row = self.row_by_slug(id).await?;
        let stamp = expiry.unwrap_or_else(Utc::now).timestamp();
        headscale_db::headscale_nodes::set_expiry(&self.pool, row.id, Some(stamp))
            .await
            .map(|_| ())
            .map_err(|e| db_error_to_machine(e, id))
    }

    async fn disable_expiry(&self, id: &str) -> Result<(), MachineAdminError> {
        let row = self.row_by_slug(id).await?;
        headscale_db::headscale_nodes::set_expiry(&self.pool, row.id, None)
            .await
            .map(|_| ())
            .map_err(|e| db_error_to_machine(e, id))
    }

    async fn logout(&self, id: &str) -> Result<(), MachineAdminError> {
        let row = self.row_by_slug(id).await?;
        headscale_db::headscale_nodes::logout(&self.pool, row.id)
            .await
            .map(|_| ())
            .map_err(|e| db_error_to_machine(e, id))
    }

    async fn rename(&self, id: &str, hostname: &str) -> Result<(), MachineAdminError> {
        if hostname.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "hostname must not be empty".into(),
            ));
        }
        let row = self.row_by_slug(id).await?;
        headscale_db::headscale_nodes::rename(&self.pool, row.id, hostname)
            .await
            .map(|_| ())
            .map_err(|e| db_error_to_machine(e, id))
    }

    async fn set_tags(&self, id: &str, tags: Vec<String>) -> Result<(), MachineAdminError> {
        let row = self.row_by_slug(id).await?;
        headscale_db::headscale_nodes::set_tags(&self.pool, row.id, tags)
            .await
            .map(|_| ())
            .map_err(|e| db_error_to_machine(e, id))
    }

    async fn set_approved_routes(
        &self,
        id: &str,
        routes: Vec<String>,
    ) -> Result<(), MachineAdminError> {
        let row = self.row_by_slug(id).await?;
        headscale_db::headscale_nodes::set_approved_routes(&self.pool, row.id, routes)
            .await
            .map(|_| ())
            .map_err(|e| db_error_to_machine(e, id))
    }

    async fn set_routes(&self, id: &str, routes: Vec<String>) -> Result<(), MachineAdminError> {
        let row = self.row_by_slug(id).await?;
        headscale_db::headscale_nodes::set_host_info_routable_ips(&self.pool, row.id, routes)
            .await
            .map(|_| ())
            .map_err(|e| db_error_to_machine(e, id))
    }

    async fn delete(&self, id: &str) -> Result<(), MachineAdminError> {
        let row = self.row_by_slug(id).await?;
        headscale_db::headscale_nodes::destroy(&self.pool, row.id)
            .await
            .map_err(|e| db_error_to_machine(e, id))
    }
}

#[async_trait]
impl MachineAdmin for WireMachineAdmin {
    async fn list(&self) -> Vec<MachineAdminRecord> {
        let deleted = self.deleted.read();
        let expired = self.expired.read();
        // #238: walk the snapshot's borrowed entries; only allocate
        // for records that survive the `deleted` filter.
        let snapshot = self.registry.snapshot();
        let mut out: Vec<_> = snapshot
            .iter()
            .filter(|(k, _)| !deleted.contains(k.as_str()))
            .map(|(k, rec)| {
                let is_exp = expired.contains(k.as_str());
                Self::render(k.as_str(), rec, is_exp)
            })
            .collect();
        out.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        out
    }

    async fn get(&self, id: &str) -> Option<MachineAdminRecord> {
        if self.deleted.read().contains(id) {
            return None;
        }
        let rec = self.registry.get(id)?;
        let is_exp = self.expired.read().contains(id);
        Some(Self::render(id, &rec, is_exp))
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
        if self.registry.get(&record.id).is_some() {
            return Err(MachineAdminError::BadRequest("node already exists".into()));
        }
        let ipv4 = record
            .ipv4
            .parse()
            .map_err(|e| MachineAdminError::BadRequest(format!("invalid IPv4: {e}")))?;
        let created_at =
            DateTime::from_timestamp(record.created_at as i64, 0).unwrap_or_else(Utc::now);
        let expiry = record
            .expiry
            .and_then(|seconds| DateTime::from_timestamp(seconds as i64, 0));
        let mut rec = crate::tailscale_wire::MachineRecord::new_at(
            created_at,
            record.id.clone(),
            record.machine_key_hex.clone(),
            record.user.clone(),
            record.name.clone(),
            ipv4,
            false,
        );
        rec.expiry = expiry;
        rec.last_seen = DateTime::from_timestamp(record.last_seen as i64, 0).unwrap_or(created_at);
        rec.os = record.os.clone();
        rec.os_version = record.version.clone();
        rec.forced_tags = record.tags.clone();
        rec.available_routes = record.routes.clone();
        rec.approved_routes = record.approved_routes.clone();
        rec.register_method = record.register_method;

        self.registry.upsert(record.id.clone(), rec);
        self.deleted.write().remove(&record.id);
        self.expired.write().remove(&record.id);
        self.get(&record.id)
            .await
            .ok_or(MachineAdminError::NotFound(record.id))
    }

    async fn complete_registration(
        &self,
        record: MachineAdminRecord,
        _policy: &PolicyStore,
        wire_record: Option<MachineRecord>,
    ) -> Result<AuthPathRegistrationResult, MachineAdminError> {
        let wire = canonical_wire_record_for_auth_path(&record, wire_record.as_ref())?;
        let old_node_key_hex = self
            .registry
            .get_by_machine_key_for_user(&wire.machine_key_hex, &record.user)
            .map(|(node_key, _)| node_key);
        let registered =
            self.registry
                .complete_web_registration(wire, &record.user, record.register_method);
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
        if self.deleted.read().contains(id) || self.registry.get(id).is_none() {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        // Sidecar bit keeps the admin's intent visible even after the
        // wire `expiry` is cleared by a future "unexpire" admin verb.
        self.expired.write().insert(id.to_string());
        // Write through to the wire layer so the next /map call returns
        // a logout response. `None` ⇒ expire immediately.
        let stamp = expiry.unwrap_or_else(Utc::now);
        if !self.registry.set_expiry(id, Some(stamp)) {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn disable_expiry(&self, id: &str) -> Result<(), MachineAdminError> {
        if self.deleted.read().contains(id) || self.registry.get(id).is_none() {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        self.expired.write().remove(id);
        if !self.registry.set_expiry(id, None) {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn logout(&self, id: &str) -> Result<(), MachineAdminError> {
        if self.deleted.read().contains(id) || self.registry.get(id).is_none() {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        if !self.registry.logout(id) {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn rename(&self, id: &str, hostname: &str) -> Result<(), MachineAdminError> {
        if hostname.trim().is_empty() {
            return Err(MachineAdminError::BadRequest(
                "hostname must not be empty".into(),
            ));
        }
        if self.deleted.read().contains(id) || self.registry.get(id).is_none() {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        if !self.registry.rename(id, hostname.to_string()) {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn set_tags(&self, id: &str, tags: Vec<String>) -> Result<(), MachineAdminError> {
        if self.deleted.read().contains(id) || self.registry.get(id).is_none() {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        if !self.registry.set_forced_tags(id, tags) {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn set_approved_routes(
        &self,
        id: &str,
        routes: Vec<String>,
    ) -> Result<(), MachineAdminError> {
        if self.deleted.read().contains(id) || self.registry.get(id).is_none() {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        if !self.registry.set_approved_routes(id, routes) {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn set_routes(&self, id: &str, routes: Vec<String>) -> Result<(), MachineAdminError> {
        if self.deleted.read().contains(id) || self.registry.get(id).is_none() {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        if !self.registry.set_available_routes(id, routes) {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<(), MachineAdminError> {
        if self.registry.get(id).is_none() {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        // P1 lifecycle: write through to the wire registry too so the
        // wire layer stops emitting peer entries / responding to /map.
        // The sidecar still records the deletion (idempotent for
        // operators that call delete twice).
        self.registry.delete(id);
        self.deleted.write().insert(id.to_string());
        self.expired.write().remove(id);
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
        disco_key: String::new(),
        endpoints: Vec::new(),
        host_info: host_info_for_record(record),
        ipv4: Some(record.ipv4.clone()),
        ipv6: None,
        hostname: record.name.clone(),
        given_name: record.name.clone(),
        user_id,
        register_method: register_method_to_db(record.register_method),
        tags: record.tags.clone(),
        auth_key_id,
        expiry: record.expiry.map(|expiry| expiry as i64),
        last_seen: (record.last_seen != 0).then_some(record.last_seen as i64),
        approved_routes: record.approved_routes.clone(),
    }
}

fn create_params_for_auth_path(
    record: &MachineAdminRecord,
    wire_record: Option<&MachineRecord>,
    user_id: Option<i64>,
    auth_key_id: Option<i64>,
) -> headscale_db::headscale_nodes::CreateParams {
    let Ok(canonical) = canonical_wire_record_for_auth_path(record, wire_record) else {
        return create_params_for_record_with_auth_key(record, user_id, auth_key_id);
    };
    create_params_for_wire_record(&canonical, user_id, auth_key_id)
}

fn canonical_wire_record_for_auth_path(
    record: &MachineAdminRecord,
    wire_record: Option<&MachineRecord>,
) -> Result<MachineRecord, MachineAdminError> {
    let mut canonical = match wire_record {
        Some(wire_record) => wire_record.clone(),
        None => machine_admin_record_to_wire(record)?,
    };
    canonical.node_key_hex.clone_from(&record.id);
    canonical
        .machine_key_hex
        .clone_from(&record.machine_key_hex);
    canonical.user.clone_from(&record.user);
    canonical.hostname.clone_from(&record.name);
    canonical.ipv4 = record.ipv4.parse().map_err(|e| {
        MachineAdminError::BadRequest(format!(
            "persisted node {} has invalid IPv4 '{}': {e}",
            record.id, record.ipv4
        ))
    })?;
    canonical.last_seen = unix_timestamp_for_record(record.last_seen, &record.id, "last_seen")?;
    canonical.expiry = record
        .expiry
        .map(|expiry| unix_timestamp_for_record(expiry, &record.id, "expiry"))
        .transpose()?;
    canonical.os.clone_from(&record.os);
    canonical.os_version.clone_from(&record.version);
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
) -> headscale_db::headscale_nodes::CreateParams {
    let admin = machine_admin_record_from_wire(record);
    let mut params = create_params_for_record_with_auth_key(&admin, user_id, auth_key_id);
    params.disco_key = record.disco_key.clone().unwrap_or_default();
    params.endpoints.clone_from(&record.endpoints);
    params.host_info = host_info_for_wire_record(record);
    params
}

fn machine_admin_record_from_wire(record: &MachineRecord) -> MachineAdminRecord {
    let expired = record.is_expired_at(Utc::now());
    MachineAdminRecord {
        node_id: 0,
        id: record.node_key_hex.clone(),
        name: record.hostname.clone(),
        user: record.user.clone(),
        ipv4: record.ipv4.to_string(),
        online: !expired,
        last_seen: record.last_seen.timestamp().max(0) as u64,
        created_at: record.created_at.timestamp().max(0) as u64,
        expiry: record.expiry.map(|expiry| expiry.timestamp().max(0) as u64),
        machine_key_hex: record.machine_key_hex.clone(),
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
    let created_at = unix_timestamp_for_record(machine.created_at, &machine.id, "created_at")?;
    let last_seen = unix_timestamp_for_record(machine.last_seen, &machine.id, "last_seen")?;
    let ipv4 = machine.ipv4.parse().map_err(|e| {
        MachineAdminError::BadRequest(format!(
            "persisted node {} has invalid IPv4 '{}': {e}",
            machine.id, machine.ipv4
        ))
    })?;
    let mut record = MachineRecord::new_at(
        created_at,
        machine.id.clone(),
        machine.machine_key_hex.clone(),
        machine.user.clone(),
        machine.name.clone(),
        ipv4,
        false,
    );
    record.expiry = machine
        .expiry
        .map(|expiry| unix_timestamp_for_record(expiry, &machine.id, "expiry"))
        .transpose()?;
    record.last_seen = last_seen;
    record.os.clone_from(&machine.os);
    record.os_version.clone_from(&machine.version);
    record.forced_tags.clone_from(&machine.tags);
    record.available_routes.clone_from(&machine.routes);
    record.approved_routes.clone_from(&machine.approved_routes);
    record.register_method = machine.register_method;
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

fn oidc_user_name(user: &crate::oidc::OidcStoredUser) -> String {
    if !user.name.is_empty() {
        user.name.clone()
    } else if !user.email.is_empty() {
        user.email.clone()
    } else {
        user.provider_identifier.clone()
    }
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

fn host_info_for_record(record: &MachineAdminRecord) -> Value {
    json!({
        "Hostname": record.name,
        "OS": record.os,
        "OSVersion": record.version,
        "RoutableIPs": record.routes,
    })
}

fn host_info_for_wire_record(record: &MachineRecord) -> Value {
    let mut host_info = json!({
        "Hostname": record.hostname,
        "OS": record.os,
        "OSVersion": record.os_version,
        "RoutableIPs": record.available_routes,
    });
    let Some(fields) = host_info.as_object_mut() else {
        return host_info;
    };
    if record.hostname.is_empty() {
        fields.remove("Hostname");
    }
    if record.os.is_empty() {
        fields.remove("OS");
    }
    if record.os_version.is_empty() {
        fields.remove("OSVersion");
    }
    if record.available_routes.is_empty() {
        fields.remove("RoutableIPs");
    }
    if record.home_derp != 0 {
        fields.insert(
            "NetInfo".into(),
            json!({
                "PreferredDERP": record.home_derp,
            }),
        );
    }
    if !record.ssh_host_keys.is_empty() {
        fields.insert(
            "sshHostKeys".into(),
            Value::Array(
                record
                    .ssh_host_keys
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            ),
        );
    }
    host_info
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
    use crate::tailscale_wire::{MachineRecord, MachineRegistry};
    use chrono::TimeZone;
    use headscale_db::Database;
    use std::net::Ipv4Addr;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
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
        assert!(v[0].online);
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
        // Sidecar bit set ⇒ admin view shows "expired" intent even
        // though wall-clock hasn't reached the timestamp. (Upstream
        // behaviour: an operator that scheduled expiry sees the node
        // greyed out immediately.)
        let view = rt().block_on(a.get(&id)).unwrap();
        assert!(view.expired);
    }

    /// `logout` clears keys + stamps expiry=now on the wire record.
    #[test]
    fn logout_writes_through_to_wire_registry() {
        let (a, reg) = fixture();
        let id = "aa".repeat(32);
        // Pre-condition: machine_key_hex is populated.
        assert!(!reg.get(&id).unwrap().machine_key_hex.is_empty());
        rt().block_on(a.logout(&id)).unwrap();
        let rec = reg.get(&id).unwrap();
        assert!(rec.machine_key_hex.is_empty());
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
        let (a, _reg) = fixture();
        let id = "aa".repeat(32);
        rt().block_on(a.set_tags(&id, vec!["tag:prod".into(), "tag:db".into()]))
            .unwrap();
        let view = rt().block_on(a.get(&id)).unwrap();
        assert_eq!(view.tags, vec!["tag:prod", "tag:db"]);
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
            ipv4: "100.64.0.44".into(),
            online: false,
            last_seen: 1_700_000_000,
            created_at: 1_700_000_000,
            expiry: None,
            machine_key_hex: "dd".repeat(32),
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
        assert_eq!(rec.available_routes, vec!["10.0.0.0/24"]);
        assert_eq!(rec.register_method, 2);

        let err = rt().block_on(a.create(record)).unwrap_err();
        assert!(matches!(err, MachineAdminError::BadRequest(_)));
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
            ipv4: "100.64.0.9".into(),
            online: true,
            last_seen: 1_700_000_000,
            created_at: 1_700_000_000,
            expiry: None,
            machine_key_hex: "bb".repeat(32),
            os: "linux".into(),
            version: "unknown".into(),
            tags: Vec::new(),
            routes: vec!["10.0.0.0/24".into()],
            approved_routes: Vec::new(),
            register_method: 2,
            expired: false,
        }
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
    async fn persistent_machine_admin_hydrates_wire_registry_from_go_nodes() {
        let (admin, _db, _users) = persistent_fixture().await;
        let mut record = persistent_record();
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
        assert_eq!(wire.user, "alice");
        assert_eq!(wire.ipv4.to_string(), "100.64.0.9");
        assert_eq!(wire.forced_tags, vec!["tag:prod"]);
        assert_eq!(wire.available_routes, vec!["10.0.0.0/24"]);
        assert_eq!(wire.approved_routes, vec!["10.0.0.0/24"]);
        assert_eq!(wire.register_method, 2);
    }

    #[tokio::test]
    async fn persistent_machine_admin_hydration_rejects_invalid_persisted_ip() {
        let (admin, db, users) = persistent_fixture().await;
        let user = users.get("alice").await.unwrap().unwrap();
        headscale_db::headscale_nodes::create(
            db.pool(),
            headscale_db::headscale_nodes::CreateParams {
                machine_key: format!("mkey:{}", "bb".repeat(32)),
                node_key: format!("nodekey:{}", "aa".repeat(32)),
                host_info: json!({"Hostname": "bad-ip-node"}),
                ipv4: Some("not-an-ip".into()),
                hostname: "bad-ip-node".into(),
                given_name: "bad-ip-node".into(),
                user_id: Some(user.id as i64),
                register_method: headscale_db::headscale_nodes::REGISTER_METHOD_CLI.into(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let registry = MachineRegistry::new();

        let err = admin.hydrate_wire_registry(&registry).await.unwrap_err();

        assert!(matches!(err, MachineAdminError::BadRequest(_)));
        assert!(err.to_string().contains("invalid IPv4"));
        assert!(registry.is_empty());
    }

    #[tokio::test]
    async fn persistent_machine_admin_auth_path_reauth_updates_existing_row() {
        let (admin, db, _users) = persistent_fixture().await;
        let mut original = persistent_record();
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
        assert_eq!(updated.register_method, REGISTER_METHOD_OIDC);
        assert_eq!(updated.expiry, Some(4_102_444_800));
        assert_eq!(updated.approved_routes, vec!["10.0.0.0/24", "10.1.0.0/24"]);

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
            headscale_db::headscale_nodes::REGISTER_METHOD_OIDC
        );
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
        assert_eq!(result.record.approved_routes, vec!["10.0.0.0/24"]);
        let raw = headscale_db::headscale_nodes::get_by_node_key(
            db.pool(),
            &format!("nodekey:{}", record.node_key_hex),
        )
        .await
        .unwrap();
        assert_eq!(
            raw.register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_AUTH_KEY
        );
        assert_eq!(raw.auth_key_id, Some(preauth.row.id));
        assert_eq!(raw.tag_list(), vec!["tag:server"]);
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
                ephemeral: false,
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
        record.disco_key = Some("discokey:authkey-node".into());
        record.endpoints = vec!["192.0.2.10:41641".into(), "2001:db8::10:41641".into()];
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
        assert_eq!(created.user, "alice");
        assert_eq!(created.machine_key_hex, machine_key);
        assert_eq!(created.register_method, REGISTER_METHOD_AUTH_KEY);
        assert_eq!(created.tags, vec!["tag:server"]);
        assert_eq!(created.routes, vec!["10.40.0.0/24"]);
        assert_eq!(created.approved_routes, vec!["10.40.0.0/24"]);

        let raw = headscale_db::headscale_nodes::get_by_id(db.pool(), created.node_id as i64)
            .await
            .unwrap();
        assert_eq!(raw.id, 1);
        assert_eq!(raw.user_id, Some(1));
        assert_eq!(raw.node_key, format!("nodekey:{}", record.node_key_hex));
        assert_eq!(raw.machine_key, format!("mkey:{}", record.machine_key_hex));
        assert_eq!(raw.disco_key, "discokey:authkey-node");
        assert_eq!(raw.endpoint_list(), record.endpoints);
        assert_eq!(
            raw.register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_AUTH_KEY
        );
        assert_eq!(raw.auth_key_id, Some(preauth.row.id));
        assert_eq!(raw.tag_list(), vec!["tag:server"]);
        assert_eq!(raw.approved_route_list(), vec!["10.40.0.0/24"]);
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
        assert_eq!(hydrated.user, "alice");
        assert_eq!(hydrated.hostname, "authkey-node");
        assert_eq!(hydrated.ipv4.to_string(), "100.64.0.88");
        assert_eq!(hydrated.disco_key, Some("discokey:authkey-node".into()));
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

        let mut rotated = original.clone();
        rotated.node_key_hex = "cc".repeat(32);
        rotated.hostname = "alice-rotated".into();
        rotated.ipv4 = Ipv4Addr::new(100, 64, 99, 99);
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
        assert_eq!(raw.auth_key_id, Some(second_key.row.id));
        assert_eq!(
            raw.register_method,
            headscale_db::headscale_nodes::REGISTER_METHOD_AUTH_KEY
        );
    }

    #[tokio::test]
    async fn persistent_oidc_registration_handler_writes_db_and_completes_cache() {
        let (admin, db, _users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
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
            .complete_oidc_registration(
                &registration_id,
                &crate::oidc::OidcStoredUser {
                    id: 1,
                    name: "alice".into(),
                    display_name: "Alice Smith".into(),
                    email: "alice@example.com".into(),
                    provider_identifier: "https://issuer.example/subject".into(),
                    provider: crate::oidc::REGISTER_METHOD_OIDC.into(),
                    profile_pic_url: String::new(),
                },
                Some(expiry),
            )
            .await
            .unwrap();

        assert!(result.new_node);
        assert!(cache.get(&registration_id).is_none());
        let stored = admin.get(&pending.node_key_hex).await.unwrap();
        assert_eq!(stored.user, "alice");
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
        assert_eq!(wire.user, "alice");
        assert_eq!(wire.expiry, Some(expiry));

        let outcome = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
        match outcome {
            crate::tailscale_wire::RegistrationWaitOutcome::Registered(record) => {
                assert_eq!(record.user, "alice");
                assert_eq!(record.register_method, REGISTER_METHOD_OIDC);
            }
            other => panic!("unexpected registration outcome: {other:?}"),
        }
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
        let raw_policy = r#"{"tagOwners":{"tag:server":["alice@"]}}"#;
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
        pending.disco_key = Some("discokey:oidc-node".into());
        pending.endpoints = vec!["192.0.2.20:41641".into(), "2001:db8::20:41641".into()];
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
            .complete_oidc_registration(
                &registration_id,
                &crate::oidc::OidcStoredUser {
                    id: 1,
                    name: "alice".into(),
                    display_name: "Alice Smith".into(),
                    email: "alice@example.com".into(),
                    provider_identifier: "https://issuer.example/subject".into(),
                    provider: crate::oidc::REGISTER_METHOD_OIDC.into(),
                    profile_pic_url: String::new(),
                },
                Some(expiry),
            )
            .await
            .unwrap();

        assert!(result.new_node);
        let stored = admin.get(&node_key).await.unwrap();
        assert_eq!(stored.node_id, 1);
        assert_eq!(stored.id, node_key);
        assert_eq!(stored.user, "alice");
        assert_eq!(stored.machine_key_hex, machine_key);
        assert_eq!(stored.register_method, REGISTER_METHOD_OIDC);
        assert_eq!(stored.expiry, None);
        assert_eq!(stored.tags, vec!["tag:server"]);
        assert_eq!(stored.routes, vec!["10.50.0.0/24"]);
        assert_eq!(stored.approved_routes, vec!["10.50.0.0/24"]);

        let raw = headscale_db::headscale_nodes::get_by_id(db.pool(), stored.node_id as i64)
            .await
            .unwrap();
        assert_eq!(raw.id, 1);
        assert_eq!(raw.user_id, Some(1));
        assert_eq!(raw.node_key, format!("nodekey:{}", pending.node_key_hex));
        assert_eq!(raw.machine_key, format!("mkey:{}", pending.machine_key_hex));
        assert_eq!(raw.disco_key, "discokey:oidc-node");
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
        assert_eq!(hydrated.user, "alice");
        assert_eq!(hydrated.hostname, "oidc-node");
        assert_eq!(hydrated.ipv4.to_string(), "100.64.0.89");
        assert_eq!(hydrated.disco_key, Some("discokey:oidc-node".into()));
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
        let (admin, db, _users) = persistent_fixture().await;
        let created = admin.create(persistent_record()).await.unwrap();
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
        pending.disco_key = Some("discokey:oidc-rekey".into());
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
                &crate::oidc::OidcStoredUser {
                    id: 1,
                    name: "alice".into(),
                    display_name: "Alice Smith".into(),
                    email: "alice@example.com".into(),
                    provider_identifier: "https://issuer.example/subject".into(),
                    provider: crate::oidc::REGISTER_METHOD_OIDC.into(),
                    profile_pic_url: String::new(),
                },
                Some(Utc.timestamp_opt(4_102_444_800, 0).unwrap()),
            )
            .await
            .unwrap();

        assert!(!result.new_node);
        assert!(registry.get(&created.id).is_none());
        let wire = registry.get(&pending.node_key_hex).unwrap();
        assert_eq!(wire.ipv4.to_string(), created.ipv4);
        assert_eq!(wire.machine_key_hex, created.machine_key_hex);
        assert_eq!(wire.user, "alice");
        assert_eq!(wire.disco_key.as_deref(), Some("discokey:oidc-rekey"));
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
        let (admin, db, _users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
        let policy = Arc::new(PolicyStore::new());
        let raw_policy = r#"{"tagOwners":{"tag:server":["alice@"]}}"#;
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
                &crate::oidc::OidcStoredUser {
                    id: 1,
                    name: "alice".into(),
                    display_name: "Alice Smith".into(),
                    email: "alice@example.com".into(),
                    provider_identifier: "https://issuer.example/subject".into(),
                    provider: crate::oidc::REGISTER_METHOD_OIDC.into(),
                    profile_pic_url: String::new(),
                },
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
        let (admin, db, _users) = persistent_fixture().await;
        let admin = Arc::new(admin);
        let cache = Arc::new(RegistrationCache::new());
        let registry = Arc::new(MachineRegistry::new());
        let policy = Arc::new(PolicyStore::new());
        let raw_policy = r#"{"tagOwners":{"tag:server":["alice@"]}}"#;
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
                &crate::oidc::OidcStoredUser {
                    id: 1,
                    name: "alice".into(),
                    display_name: "Alice Smith".into(),
                    email: "alice@example.com".into(),
                    provider_identifier: "https://issuer.example/subject".into(),
                    provider: crate::oidc::REGISTER_METHOD_OIDC.into(),
                    profile_pic_url: String::new(),
                },
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
        assert!(logged_out.machine_key_hex.is_empty());
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
