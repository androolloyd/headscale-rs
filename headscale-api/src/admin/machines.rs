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
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
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
        let last_seen = if is_expired { 0 } else if last_seen == 0 { now_unix() } else { last_seen };
        MachineAdminRecord {
            id: id.to_string(),
            name: rec.hostname.clone(),
            user: rec.user.clone(),
            ipv4: rec.ipv4.to_string(),
            online: !is_expired,
            last_seen,
            machine_key_hex: rec.machine_key_hex.clone(),
            os: "unknown".into(),
            version: "unknown".into(),
            tags: rec.forced_tags.clone(),
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
        let e = rt().block_on(a.logout("zz".repeat(32).as_str())).unwrap_err();
        assert!(matches!(e, MachineAdminError::NotFound(_)));
    }
}
