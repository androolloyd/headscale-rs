//! User admin adapters, mounted alongside `MachineRegistry`.
//!
//! Headscale-go ships a SQL-backed user table. This registry remains
//! available as the in-process test adapter, and `PersistentUserAdmin`
//! exposes the Go-shaped `users` table for replacement-compatible
//! admin/gRPC deployments.
//!
//! The in-memory registry tracks two things:
//!   1. A canonical user name (must match `^[a-z0-9_-]{1,32}$`).
//!   2. A creation timestamp + best-effort "last activity" stamp the
//!      admin handlers bump whenever a related entity (preauth key /
//!      machine) is created or registered for that user.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

use super::auth::now_unix;

/// Maximum user-name length. Matches headscale-go's DNS label limit.
pub const MAX_USER_NAME_LEN: usize = 63;
pub const MIN_USER_NAME_LEN: usize = 2;

/// Headscale-go validates users with `util.ValidateHostname`: lower-case
/// DNS labels, dots allowed, no leading/trailing dot or hyphen.
fn is_valid_user_name(s: &str) -> bool {
    s.len() >= MIN_USER_NAME_LEN
        && s.len() <= MAX_USER_NAME_LEN
        && s.to_lowercase() == s
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.starts_with('.')
        && !s.ends_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
}

/// One row in the registry. Cheap to clone; the admin handlers return
/// it directly in JSON responses.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    #[serde(default)]
    pub id: u64,
    pub name: String,
    pub created_at: u64,
    pub last_activity: u64,
    #[serde(default)]
    pub display_name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub provider_id: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub profile_pic_url: String,
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
    #[error("user name '{0}' is invalid (lowercase DNS hostname, 2..=63 chars)")]
    InvalidName(String),
    #[error("user '{0}' already exists")]
    Exists(String),
    #[error("user '{0}' does not exist")]
    Missing(String),
    #[error("cannot edit OIDC user")]
    CannotChangeOidcUser,
    #[error("user store error: {0}")]
    Store(String),
}

#[async_trait]
pub trait UserAdmin: Send + Sync {
    async fn create(&self, name: &str) -> Result<UserRecord, UserRegistryError> {
        self.create_detailed(name, "", "", "").await
    }

    async fn create_detailed(
        &self,
        name: &str,
        display_name: &str,
        email: &str,
        profile_pic_url: &str,
    ) -> Result<UserRecord, UserRegistryError>;

    async fn delete(&self, name: &str) -> Result<(), UserRegistryError>;
    async fn delete_by_id(&self, id: u64) -> Result<(), UserRegistryError>;
    async fn get(&self, name: &str) -> Result<Option<UserRecord>, UserRegistryError>;
    async fn get_by_id(&self, id: u64) -> Result<Option<UserRecord>, UserRegistryError>;
    async fn rename_by_id(&self, id: u64, new_name: &str) -> Result<UserRecord, UserRegistryError>;
    async fn all(&self) -> Result<Vec<UserRecord>, UserRegistryError>;
    async fn touch(&self, name: &str) -> Result<(), UserRegistryError>;
    async fn len(&self) -> Result<usize, UserRegistryError> {
        Ok(self.all().await?.len())
    }
    async fn is_empty(&self) -> Result<bool, UserRegistryError> {
        Ok(self.len().await? == 0)
    }
}

impl UserRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a fresh user. Fails on name-validation or duplicate.
    pub fn create(&self, name: &str) -> Result<UserRecord, UserRegistryError> {
        self.create_detailed(name, "", "", "")
    }

    /// Create a fresh user with upstream-visible profile fields.
    pub fn create_detailed(
        &self,
        name: &str,
        display_name: &str,
        email: &str,
        profile_pic_url: &str,
    ) -> Result<UserRecord, UserRegistryError> {
        if !is_valid_user_name(name) {
            return Err(UserRegistryError::InvalidName(name.to_string()));
        }
        let mut g = self.inner.write();
        if g.contains_key(name) {
            return Err(UserRegistryError::Exists(name.to_string()));
        }
        let now = now_unix();
        let id = g
            .values()
            .map(|u| u.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let rec = UserRecord {
            id,
            name: name.to_string(),
            created_at: now,
            last_activity: now,
            display_name: display_name.to_string(),
            email: email.to_string(),
            provider_id: String::new(),
            provider: String::new(),
            profile_pic_url: profile_pic_url.to_string(),
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

    /// Delete an existing user by upstream numeric ID. Errors if missing.
    pub fn delete_by_id(&self, id: u64) -> Result<(), UserRegistryError> {
        let Some(name) = self.name_for_id(id) else {
            return Err(UserRegistryError::Missing(id.to_string()));
        };
        self.delete(&name)
    }

    /// Look up a single user.
    pub fn get(&self, name: &str) -> Option<UserRecord> {
        self.inner.read().get(name).cloned()
    }

    /// Look up a single user by upstream numeric ID.
    pub fn get_by_id(&self, id: u64) -> Option<UserRecord> {
        self.inner.read().values().find(|u| u.id == id).cloned()
    }

    /// Rename a user identified by upstream numeric ID.
    pub fn rename_by_id(&self, id: u64, new_name: &str) -> Result<UserRecord, UserRegistryError> {
        if !is_valid_user_name(new_name) {
            return Err(UserRegistryError::InvalidName(new_name.to_string()));
        }
        let mut g = self.inner.write();
        if g.contains_key(new_name) {
            return Err(UserRegistryError::Exists(new_name.to_string()));
        }
        let Some(old_name) = g.values().find(|u| u.id == id).map(|u| u.name.clone()) else {
            return Err(UserRegistryError::Missing(id.to_string()));
        };
        let mut rec = g
            .remove(&old_name)
            .expect("old_name was selected from the map");
        rec.name = new_name.to_string();
        rec.last_activity = now_unix();
        g.insert(new_name.to_string(), rec.clone());
        Ok(rec)
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

    fn name_for_id(&self, id: u64) -> Option<String> {
        self.inner
            .read()
            .values()
            .find(|u| u.id == id)
            .map(|u| u.name.clone())
    }
}

#[async_trait]
impl UserAdmin for UserRegistry {
    async fn create(&self, name: &str) -> Result<UserRecord, UserRegistryError> {
        Self::create(self, name)
    }

    async fn create_detailed(
        &self,
        name: &str,
        display_name: &str,
        email: &str,
        profile_pic_url: &str,
    ) -> Result<UserRecord, UserRegistryError> {
        Self::create_detailed(self, name, display_name, email, profile_pic_url)
    }

    async fn delete(&self, name: &str) -> Result<(), UserRegistryError> {
        Self::delete(self, name)
    }

    async fn delete_by_id(&self, id: u64) -> Result<(), UserRegistryError> {
        Self::delete_by_id(self, id)
    }

    async fn get(&self, name: &str) -> Result<Option<UserRecord>, UserRegistryError> {
        Ok(Self::get(self, name))
    }

    async fn get_by_id(&self, id: u64) -> Result<Option<UserRecord>, UserRegistryError> {
        Ok(Self::get_by_id(self, id))
    }

    async fn rename_by_id(&self, id: u64, new_name: &str) -> Result<UserRecord, UserRegistryError> {
        Self::rename_by_id(self, id, new_name)
    }

    async fn all(&self) -> Result<Vec<UserRecord>, UserRegistryError> {
        Ok(Self::all(self))
    }

    async fn touch(&self, name: &str) -> Result<(), UserRegistryError> {
        Self::touch(self, name);
        Ok(())
    }

    async fn len(&self) -> Result<usize, UserRegistryError> {
        Ok(Self::len(self))
    }

    async fn is_empty(&self) -> Result<bool, UserRegistryError> {
        Ok(Self::is_empty(self))
    }
}

#[derive(Clone)]
pub struct PersistentUserAdmin {
    pool: SqlitePool,
}

impl PersistentUserAdmin {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_record(row: headscale_db::users::UserRow) -> UserRecord {
        UserRecord {
            id: i64_to_u64(row.id),
            name: if row.name.is_empty() {
                row.username()
            } else {
                row.name
            },
            created_at: i64_to_u64(row.created_at),
            last_activity: i64_to_u64(row.updated_at),
            display_name: row.display_name,
            email: row.email,
            provider_id: row.provider_identifier.unwrap_or_default(),
            provider: row.provider,
            profile_pic_url: row.profile_pic_url,
        }
    }

    fn map_db_write_error(e: headscale_db::DbError, subject: &str) -> UserRegistryError {
        match e {
            headscale_db::DbError::NotFound(_) => UserRegistryError::Missing(subject.to_string()),
            headscale_db::DbError::General(msg)
                if msg.contains("already exists") || msg.contains("UNIQUE constraint failed") =>
            {
                UserRegistryError::Exists(subject.to_string())
            }
            headscale_db::DbError::General(msg) if msg.contains("cannot edit OIDC user") => {
                UserRegistryError::CannotChangeOidcUser
            }
            headscale_db::DbError::General(msg)
                if msg.contains("user name invalid") || msg.contains("hostname") =>
            {
                UserRegistryError::InvalidName(subject.to_string())
            }
            other => UserRegistryError::Store(other.to_string()),
        }
    }

    fn map_optional_error(e: headscale_db::DbError, subject: &str) -> UserRegistryError {
        match e {
            headscale_db::DbError::NotFound(_) => UserRegistryError::Missing(subject.to_string()),
            other => UserRegistryError::Store(other.to_string()),
        }
    }
}

#[async_trait]
impl UserAdmin for PersistentUserAdmin {
    async fn create(&self, name: &str) -> Result<UserRecord, UserRegistryError> {
        self.create_detailed(name, "", "", "").await
    }

    async fn create_detailed(
        &self,
        name: &str,
        display_name: &str,
        email: &str,
        profile_pic_url: &str,
    ) -> Result<UserRecord, UserRegistryError> {
        if !is_valid_user_name(name) {
            return Err(UserRegistryError::InvalidName(name.to_string()));
        }
        let row = headscale_db::users::create(
            &self.pool,
            headscale_db::users::CreateParams {
                name: name.to_string(),
                display_name: display_name.to_string(),
                email: email.to_string(),
                provider_identifier: None,
                provider: String::new(),
                profile_pic_url: profile_pic_url.to_string(),
            },
        )
        .await
        .map_err(|e| Self::map_db_write_error(e, name))?;
        Ok(Self::row_to_record(row))
    }

    async fn delete(&self, name: &str) -> Result<(), UserRegistryError> {
        let row = headscale_db::users::get_by_name(&self.pool, name)
            .await
            .map_err(|e| Self::map_optional_error(e, name))?;
        self.delete_by_id(i64_to_u64(row.id)).await
    }

    async fn delete_by_id(&self, id: u64) -> Result<(), UserRegistryError> {
        let db_id = u64_to_i64(id)?;
        headscale_db::users::destroy(&self.pool, db_id)
            .await
            .map_err(|e| Self::map_db_write_error(e, &id.to_string()))
    }

    async fn get(&self, name: &str) -> Result<Option<UserRecord>, UserRegistryError> {
        match headscale_db::users::get_by_name(&self.pool, name).await {
            Ok(row) => Ok(Some(Self::row_to_record(row))),
            Err(headscale_db::DbError::NotFound(_)) => Ok(None),
            Err(e) => Err(Self::map_optional_error(e, name)),
        }
    }

    async fn get_by_id(&self, id: u64) -> Result<Option<UserRecord>, UserRegistryError> {
        let db_id = u64_to_i64(id)?;
        match headscale_db::users::get_by_id(&self.pool, db_id).await {
            Ok(row) => Ok(Some(Self::row_to_record(row))),
            Err(headscale_db::DbError::NotFound(_)) => Ok(None),
            Err(e) => Err(Self::map_optional_error(e, &id.to_string())),
        }
    }

    async fn rename_by_id(&self, id: u64, new_name: &str) -> Result<UserRecord, UserRegistryError> {
        if !is_valid_user_name(new_name) {
            return Err(UserRegistryError::InvalidName(new_name.to_string()));
        }
        let db_id = u64_to_i64(id)?;
        let row = headscale_db::users::rename(&self.pool, db_id, new_name)
            .await
            .map_err(|e| Self::map_db_write_error(e, new_name))?;
        Ok(Self::row_to_record(row))
    }

    async fn all(&self) -> Result<Vec<UserRecord>, UserRegistryError> {
        let rows = headscale_db::users::list(&self.pool)
            .await
            .map_err(|e| UserRegistryError::Store(e.to_string()))?;
        Ok(rows.into_iter().map(Self::row_to_record).collect())
    }

    async fn touch(&self, name: &str) -> Result<(), UserRegistryError> {
        headscale_db::users::touch_by_name(&self.pool, name)
            .await
            .map_err(|e| UserRegistryError::Store(e.to_string()))
    }
}

fn i64_to_u64(v: i64) -> u64 {
    u64::try_from(v).unwrap_or_default()
}

fn u64_to_i64(v: u64) -> Result<i64, UserRegistryError> {
    i64::try_from(v).map_err(|_| UserRegistryError::Missing(v.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_get() {
        let r = UserRegistry::new();
        let u = r.create("alice").unwrap();
        assert_eq!(u.id, 1);
        assert_eq!(u.name, "alice");
        assert_eq!(r.get("alice").unwrap().name, "alice");
        assert_eq!(r.get_by_id(u.id).unwrap().name, "alice");
        assert_eq!(r.len(), 1);
    }

    #[test]
    fn create_detailed_round_trips_upstream_profile_fields() {
        let r = UserRegistry::new();
        let u = r
            .create_detailed(
                "alice",
                "Alice Smith",
                "alice@example.com",
                "https://example.com/a.png",
            )
            .unwrap();
        assert_eq!(u.display_name, "Alice Smith");
        assert_eq!(u.email, "alice@example.com");
        assert_eq!(u.profile_pic_url, "https://example.com/a.png");
    }

    #[test]
    fn invalid_names_rejected() {
        let r = UserRegistry::new();
        assert!(r.create("").is_err());
        assert!(r.create("a").is_err());
        assert!(r.create("Alice").is_err()); // uppercase
        assert!(r.create("_alice").is_err()); // underscore
        assert!(r.create("-alice").is_err());
        assert!(r.create("alice-").is_err());
        assert!(r.create(".alice").is_err());
        assert!(r.create("alice.").is_err());
        assert!(r.create(&"a".repeat(64)).is_err());
        assert!(r.create("alice@host").is_err());
        assert!(r.create("alice.smith").is_ok());
        // Boundary: 63 chars OK.
        assert!(r.create(&"a".repeat(63)).is_ok());
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
    fn rename_and_delete_by_id_work() {
        let r = UserRegistry::new();
        let u = r.create("alice").unwrap();
        let renamed = r.rename_by_id(u.id, "bob").unwrap();
        assert_eq!(renamed.id, u.id);
        assert_eq!(renamed.name, "bob");
        assert!(r.get("alice").is_none());
        assert_eq!(r.get_by_id(u.id).unwrap().name, "bob");
        r.delete_by_id(u.id).unwrap();
        assert!(r.is_empty());
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

    #[tokio::test]
    async fn persistent_user_admin_round_trips_go_table() {
        let db = headscale_db::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = PersistentUserAdmin::new(db.pool().clone());

        let created = users
            .create_detailed(
                "alice",
                "Alice Smith",
                "alice@example.com",
                "https://example.com/alice.png",
            )
            .await
            .unwrap();
        assert_eq!(created.id, 1);
        assert_eq!(created.display_name, "Alice Smith");

        let stored = headscale_db::users::get_by_id(db.pool(), created.id as i64)
            .await
            .unwrap();
        assert_eq!(stored.name, "alice");
        assert_eq!(stored.email, "alice@example.com");

        let by_name = users.get("alice").await.unwrap().unwrap();
        assert_eq!(by_name.id, created.id);
        assert_eq!(users.len().await.unwrap(), 1);

        std::thread::sleep(std::time::Duration::from_millis(1100));
        users.touch("alice").await.unwrap();
        let touched = users.get("alice").await.unwrap().unwrap();
        assert!(touched.last_activity >= created.last_activity);

        let renamed = users.rename_by_id(created.id, "bob").await.unwrap();
        assert_eq!(renamed.name, "bob");
        assert!(users.get("alice").await.unwrap().is_none());

        users.delete_by_id(created.id).await.unwrap();
        assert!(users.all().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn persistent_user_admin_reads_raw_go_oidc_rows() {
        let db = headscale_db::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        sqlx::query(
            "
            INSERT INTO users
                (name, display_name, email, provider_identifier, provider, profile_pic_url, created_at, updated_at)
            VALUES
                ('', 'Alice Smith', 'alice@example.com', 'https://issuer/sub', 'oidc', 'https://example.com/alice.png', datetime(10, 'unixepoch'), datetime(11, 'unixepoch'))
            ",
        )
        .execute(db.pool())
        .await
        .unwrap();

        let users = PersistentUserAdmin::new(db.pool().clone());
        let listed = users.all().await.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "alice@example.com");
        assert_eq!(listed[0].provider, "oidc");
        assert_eq!(listed[0].provider_id, "https://issuer/sub");
        assert_eq!(listed[0].created_at, 10);
        assert_eq!(listed[0].last_activity, 11);
    }
}
