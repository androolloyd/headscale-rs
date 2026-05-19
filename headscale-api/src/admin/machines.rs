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

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::tailscale_wire::MachineRegistry;

use super::auth::now_unix;

/// Admin-side view of one registered machine.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MachineAdminRecord {
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
    /// Whether an admin marked this machine "expired".
    pub expired: bool,
}

/// Errors the admin trait can surface.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MachineAdminError {
    #[error("machine '{0}' not found")]
    NotFound(String),
}

/// Admin surface for machine management. Async to match
/// [`super::preauth::PreauthAdmin`] and to leave room for a real DB.
#[async_trait]
pub trait MachineAdmin: Send + Sync {
    async fn list(&self) -> Vec<MachineAdminRecord>;
    async fn get(&self, id: &str) -> Option<MachineAdminRecord>;
    /// Mark a machine expired. v0 records the intent in a sidecar; the
    /// wire registry is not mutated.
    async fn expire(&self, id: &str) -> Result<(), MachineAdminError>;
    /// Mark a machine deleted. Same sidecar story as `expire`. The
    /// record disappears from `list()` once flagged.
    async fn delete(&self, id: &str) -> Result<(), MachineAdminError>;
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

    fn render(
        &self,
        id: String,
        rec: crate::tailscale_wire::MachineRecord,
        is_expired: bool,
    ) -> MachineAdminRecord {
        MachineAdminRecord {
            id,
            name: rec.hostname,
            user: rec.user,
            ipv4: rec.ipv4.to_string(),
            online: !is_expired,
            last_seen: if is_expired { 0 } else { now_unix() },
            machine_key_hex: rec.machine_key_hex,
            os: "unknown".into(),
            version: "unknown".into(),
            tags: Vec::new(),
            routes: Vec::new(),
            expired: is_expired,
        }
    }
}

#[async_trait]
impl MachineAdmin for WireMachineAdmin {
    async fn list(&self) -> Vec<MachineAdminRecord> {
        let deleted = self.deleted.read();
        let expired = self.expired.read();
        let mut out: Vec<_> = self
            .registry
            .all()
            .into_iter()
            .filter(|(k, _)| !deleted.contains(k))
            .map(|(k, rec)| {
                let is_exp = expired.contains(&k);
                self.render(k, rec, is_exp)
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
        Some(self.render(id.to_string(), rec, is_exp))
    }

    async fn expire(&self, id: &str) -> Result<(), MachineAdminError> {
        if self.deleted.read().contains(id) || self.registry.get(id).is_none() {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        self.expired.write().insert(id.to_string());
        Ok(())
    }

    async fn delete(&self, id: &str) -> Result<(), MachineAdminError> {
        if self.registry.get(id).is_none() {
            return Err(MachineAdminError::NotFound(id.to_string()));
        }
        self.deleted.write().insert(id.to_string());
        // Also strip the expired flag (redundant — record is gone).
        self.expired.write().remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{MachineRecord, MachineRegistry};
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
            MachineRecord {
                node_key_hex: "aa".repeat(32),
                machine_key_hex: "bb".repeat(32),
                user: "alice".into(),
                hostname: "node-1".into(),
                ipv4: Ipv4Addr::new(100, 64, 0, 5),
            },
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
        let e = rt().block_on(a.expire("zz".repeat(32).as_str())).unwrap_err();
        assert!(matches!(e, MachineAdminError::NotFound(_)));
    }
}
