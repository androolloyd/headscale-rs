//! In-memory user registry, mounted alongside `MachineRegistry`.
//!
//! Headscale-go ships a SQL-backed user table. We deliberately keep this
//! one in memory for v0 — it covers the admin-panel's CRUD surface
//! without dragging `headscale-db` into the wire crate. Persistence
//! lands when the admin panel grows beyond v0 (#229 follow-up).
//!
//! The registry tracks two things:
//!   1. A canonical user name (must match `^[a-z0-9_-]{1,32}$`).
//!   2. A creation timestamp + best-effort "last activity" stamp the
//!      admin handlers bump whenever a related entity (preauth key /
//!      machine) is created or registered for that user.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use super::auth::now_unix;

/// Maximum user-name length. Picked to match `octravpn-mesh`'s implicit
/// convention (preauth keys carry the user verbatim and the wire
/// protocol caps fields well below 64 bytes).
pub const MAX_USER_NAME_LEN: usize = 32;

/// Validation regex for user names. Lower-case ASCII letters, digits,
/// `-`, `_`. No empty strings.
fn is_valid_user_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_USER_NAME_LEN
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// One row in the registry. Cheap to clone; the admin handlers return
/// it directly in JSON responses.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    pub name: String,
    pub created_at: u64,
    pub last_activity: u64,
}

/// Shared user registry. Same `Arc`-wrapped-`RwLock` pattern as
/// [`crate::tailscale_wire::MachineRegistry`].
#[derive(Clone, Default)]
pub struct UserRegistry {
    inner: Arc<RwLock<BTreeMap<String, UserRecord>>>,
}

/// Reasons a write to the registry can fail.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UserRegistryError {
    #[error("user name '{0}' is invalid (lowercase, digits, '-' or '_', 1..=32 chars)")]
    InvalidName(String),
    #[error("user '{0}' already exists")]
    Exists(String),
    #[error("user '{0}' does not exist")]
    Missing(String),
}

impl UserRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a fresh user. Fails on name-validation or duplicate.
    pub fn create(&self, name: &str) -> Result<UserRecord, UserRegistryError> {
        if !is_valid_user_name(name) {
            return Err(UserRegistryError::InvalidName(name.to_string()));
        }
        let mut g = self.inner.write();
        if g.contains_key(name) {
            return Err(UserRegistryError::Exists(name.to_string()));
        }
        let now = now_unix();
        let rec = UserRecord {
            name: name.to_string(),
            created_at: now,
            last_activity: now,
        };
        g.insert(name.to_string(), rec.clone());
        Ok(rec)
    }

    /// Delete an existing user. Errors if missing.
    pub fn delete(&self, name: &str) -> Result<(), UserRegistryError> {
        let mut g = self.inner.write();
        if g.remove(name).is_none() {
            return Err(UserRegistryError::Missing(name.to_string()));
        }
        Ok(())
    }

    /// Look up a single user.
    pub fn get(&self, name: &str) -> Option<UserRecord> {
        self.inner.read().get(name).cloned()
    }

    /// Snapshot all users, sorted by name (the `BTreeMap` iter order).
    pub fn all(&self) -> Vec<UserRecord> {
        self.inner.read().values().cloned().collect()
    }

    /// Bump `last_activity` for `name` to now. No-op for unknown users
    /// (the upstream caller may pass any string).
    pub fn touch(&self, name: &str) {
        let mut g = self.inner.write();
        if let Some(rec) = g.get_mut(name) {
            rec.last_activity = now_unix();
        }
    }

    /// Number of registered users.
    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_get() {
        let r = UserRegistry::new();
        let u = r.create("alice").unwrap();
        assert_eq!(u.name, "alice");
        assert_eq!(r.get("alice").unwrap().name, "alice");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn invalid_names_rejected() {
        let r = UserRegistry::new();
        assert!(r.create("").is_err());
        assert!(r.create("Alice").is_err()); // uppercase
        assert!(r.create("alice.smith").is_err()); // dot
        assert!(r.create(&"a".repeat(33)).is_err());
        assert!(r.create("alice@host").is_err());
        // Boundary: 32 chars OK.
        assert!(r.create(&"a".repeat(32)).is_ok());
    }

    #[test]
    fn duplicate_rejected() {
        let r = UserRegistry::new();
        r.create("alice").unwrap();
        assert_eq!(
            r.create("alice").unwrap_err(),
            UserRegistryError::Exists("alice".to_string())
        );
    }

    #[test]
    fn delete_works() {
        let r = UserRegistry::new();
        r.create("alice").unwrap();
        assert!(r.delete("alice").is_ok());
        assert!(r.get("alice").is_none());
        assert_eq!(
            r.delete("alice").unwrap_err(),
            UserRegistryError::Missing("alice".to_string())
        );
    }

    #[test]
    fn touch_bumps_activity() {
        let r = UserRegistry::new();
        let u = r.create("alice").unwrap();
        let before = u.last_activity;
        std::thread::sleep(std::time::Duration::from_millis(1100));
        r.touch("alice");
        let after = r.get("alice").unwrap().last_activity;
        assert!(after >= before);
        // Unknown user: no-op, no panic.
        r.touch("bob");
    }
}
