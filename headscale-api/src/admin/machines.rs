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

use crate::policy::PolicyStore;
use crate::tailscale_wire::{
    MachineRecord, MachineRegistry, RegistrationCache, routes::auto_approved_routes_for_node,
};

use super::auth::now_unix;
use super::users::UserAdmin;

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
    /// Mark a machine expired. `expiry = None` ⇒ expire immediately
    /// (`Utc::now()`); `Some(t)` ⇒ schedule expiry for `t`. Mirrors
    /// upstream `db.SetExpiry`.
    async fn expire_at(
        &self,
        id: &str,
        expiry: Option<DateTime<Utc>>,
    ) -> Result<(), MachineAdminError>;
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

    pub async fn create_or_update_auth_path(
        &self,
        mut record: MachineAdminRecord,
        policy: &PolicyStore,
    ) -> Result<(MachineAdminRecord, bool), MachineAdminError> {
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
                create_params_for_record(&record, user_id),
            )
            .await
            .map_err(|e| db_error_to_machine(e, &record.id))?;
            Ok((self.row_to_record(row).await, false))
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
            self.create(record).await.map(|record| (record, true))
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
                .get("App")
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
}

#[async_trait]
impl crate::oidc::OidcRegistrationHandler for PersistentOidcRegistrationHandler {
    async fn complete_oidc_registration(
        &self,
        registration_id: &str,
        user: &crate::oidc::OidcStoredUser,
        node_expiry: DateTime<Utc>,
    ) -> Result<crate::oidc::OidcRegistrationResult, crate::oidc::OidcRegistrationError> {
        let pending = self
            .registration_cache
            .get(registration_id)
            .ok_or(crate::oidc::OidcRegistrationError::SessionExpired)?;
        let mut record = machine_admin_record_from_wire(&pending);
        record.user = oidc_user_name(user);
        record.expiry = Some(node_expiry.timestamp().max(0) as u64);
        record.register_method = REGISTER_METHOD_OIDC;

        let (created, new_node) = self
            .machines
            .create_or_update_auth_path(record, &self.policy)
            .await
            .map_err(|err| crate::oidc::OidcRegistrationError::Store(err.to_string()))?;
        let wire_record = machine_admin_record_to_wire(&created);
        if let Some(registry) = &self.wire_registry {
            registry.upsert(wire_record.node_key_hex.clone(), wire_record.clone());
        }
        if self
            .registration_cache
            .complete(registration_id, wire_record)
        {
            Ok(crate::oidc::OidcRegistrationResult { new_node })
        } else {
            Err(crate::oidc::OidcRegistrationError::SessionExpired)
        }
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
        auth_key_id: None,
        expiry: record.expiry.map(|expiry| expiry as i64),
        last_seen: (record.last_seen != 0).then_some(record.last_seen as i64),
        approved_routes: record.approved_routes.clone(),
    }
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

fn machine_admin_record_to_wire(machine: &MachineAdminRecord) -> MachineRecord {
    let created_at =
        chrono::DateTime::from_timestamp(machine.created_at as i64, 0).unwrap_or_else(Utc::now);
    let last_seen =
        chrono::DateTime::from_timestamp(machine.last_seen as i64, 0).unwrap_or(created_at);
    let ipv4 = machine
        .ipv4
        .parse()
        .unwrap_or_else(|_| Ipv4Addr::new(100, 64, 0, 1));
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
        .and_then(|expiry| chrono::DateTime::from_timestamp(expiry as i64, 0));
    record.last_seen = last_seen;
    record.os = machine.os.clone();
    record.os_version = machine.version.clone();
    record.forced_tags = machine.tags.clone();
    record.available_routes = machine.routes.clone();
    record.approved_routes = machine.approved_routes.clone();
    record.register_method = machine.register_method;
    record
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

fn host_info_for_record(record: &MachineAdminRecord) -> Value {
    json!({
        "Hostname": record.name,
        "RoutableIPs": record.routes,
    })
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

        let (updated, new_node) = admin
            .create_or_update_auth_path(pending, &PolicyStore::new())
            .await
            .unwrap();

        assert!(!new_node);
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
                expiry,
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
