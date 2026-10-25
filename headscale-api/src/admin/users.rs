//! User admin adapters, mounted alongside `MachineRegistry`.
//!
//! Headscale-go ships a SQL-backed user table. This registry remains
//! available as the in-process test adapter, and `PersistentUserAdmin`
//! exposes the Go-shaped `users` table for replacement-compatible
//! admin/gRPC deployments.
//!
//! The in-memory registry tracks two things:
//!   1. A canonical user name matching headscale-go's `ValidateUsername`.
//!   2. A creation timestamp + best-effort "last activity" stamp the
//!      admin handlers bump whenever a related entity (preauth key /
//!      machine) is created or registered for that user.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, NaiveDateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
#[cfg(feature = "postgres-sqlx")]
use sqlx::PgPool;
use sqlx::SqlitePool;

use super::auth::now_unix;

fn is_valid_user_name(s: &str) -> bool {
    headscale_db::users::validate_username(s).is_ok()
}

/// One row in the registry. Cheap to clone; the admin handlers return
/// it directly in JSON responses.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    #[serde(default)]
    pub id: u64,
    pub name: String,
    pub created_at: u64,
    #[serde(skip)]
    pub created_at_precise: Option<DateTime<Utc>>,
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

/// One user read with optional native association-write material. The raw
/// model fields are transient; UserRecord's public shape remains unchanged.
#[derive(Clone)]
pub struct UserRegistrationSnapshot {
    pub user: UserRecord,
    pub(crate) write: Option<headscale_db::users::UserWriteSnapshot>,
}

impl UserRegistrationSnapshot {
    pub fn from_user(user: UserRecord) -> Self {
        Self { user, write: None }
    }

    pub(crate) fn from_native(write: headscale_db::users::UserWriteSnapshot) -> Self {
        Self {
            user: PersistentUserAdmin::row_to_association_record(write.row.clone()),
            write: Some(write),
        }
    }
}

impl UserRecord {
    pub fn policy_identity(&self) -> crate::policy::PolicyUser {
        crate::policy::PolicyUser {
            id: self.id,
            name: self.name.clone(),
            email: self.email.clone(),
            provider_identifier: (!self.provider_id.is_empty()).then(|| self.provider_id.clone()),
        }
    }
}

fn policy_identity_from_row(row: headscale_db::users::UserRow) -> crate::policy::PolicyUser {
    crate::policy::PolicyUser {
        id: i64_to_u64(row.id),
        name: row.name,
        email: row.email,
        provider_identifier: row.provider_identifier,
    }
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
    #[error("user name '{0}' is invalid")]
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

    /// Go State.CreateUser is distinct from the validating legacy DB helper.
    async fn create_for_state(
        &self,
        name: &str,
        display_name: &str,
        email: &str,
        profile_pic_url: &str,
    ) -> Result<UserRecord, UserRegistryError> {
        self.create_detailed(name, display_name, email, profile_pic_url)
            .await
    }

    /// Native DestroyUser checks durable node ownership in its transaction.
    fn checks_user_owned_nodes_in_storage(&self) -> bool {
        false
    }

    async fn delete(&self, name: &str) -> Result<(), UserRegistryError>;
    async fn delete_by_id(&self, id: u64) -> Result<(), UserRegistryError>;
    async fn get(&self, name: &str) -> Result<Option<UserRecord>, UserRegistryError>;
    async fn get_by_id(&self, id: u64) -> Result<Option<UserRecord>, UserRegistryError>;
    /// Load the stored identity used by a node's native User association.
    async fn get_for_node_association(
        &self,
        id: u64,
    ) -> Result<Option<UserRecord>, UserRegistryError> {
        self.get_by_id(id).await
    }
    async fn get_for_registration(
        &self,
        id: u64,
    ) -> Result<Option<UserRegistrationSnapshot>, UserRegistryError> {
        self.get_for_node_association(id)
            .await
            .map(|user| user.map(UserRegistrationSnapshot::from_user))
    }

    async fn get_for_registration_by_name(
        &self,
        name: &str,
    ) -> Result<Option<UserRegistrationSnapshot>, UserRegistryError> {
        self.get(name)
            .await
            .map(|user| user.map(UserRegistrationSnapshot::from_user))
    }

    async fn rename_by_id(&self, id: u64, new_name: &str) -> Result<UserRecord, UserRegistryError>;

    async fn rename_for_state(&self, id: u64, name: &str) -> Result<UserRecord, UserRegistryError> {
        self.rename_by_id(id, name).await
    }
    async fn all(&self) -> Result<Vec<UserRecord>, UserRegistryError>;
    /// Go ListUsers returns every matching stored model. Name takes priority
    /// over email, which takes priority over a nonzero ID; no fields means all.
    async fn list_for_state(
        &self,
        name: &str,
        email: &str,
        id: u64,
    ) -> Result<Vec<UserRecord>, UserRegistryError> {
        Ok(self
            .all()
            .await?
            .into_iter()
            .filter(|user| {
                if !name.is_empty() {
                    user.name == name
                } else if !email.is_empty() {
                    user.email == email
                } else {
                    id == 0 || user.id == id
                }
            })
            .collect())
    }
    /// Policy matching uses the stored name, not the display-name fallback
    /// supplied by some admin adapters for unnamed imported accounts.
    async fn policy_users(&self) -> Result<Vec<crate::policy::PolicyUser>, UserRegistryError> {
        Ok(self
            .all()
            .await?
            .iter()
            .map(UserRecord::policy_identity)
            .collect())
    }
    async fn touch(&self, name: &str) -> Result<(), UserRegistryError>;
    async fn len(&self) -> Result<usize, UserRegistryError> {
        Ok(self.all().await?.len())
    }
    async fn is_empty(&self) -> Result<bool, UserRegistryError> {
        Ok(self.len().await? == 0)
    }
}

/// Production OIDC user writes must refresh account-based policy resolution
/// even when authentication later ends without registering a new node.
#[derive(Clone)]
pub struct PolicyOidcUserStore {
    store: Arc<dyn crate::oidc::OidcUserStore>,
    users: Arc<dyn UserAdmin>,
    policy: crate::policy::PolicyStore,
    registry: Arc<crate::tailscale_wire::MachineRegistry>,
}

impl PolicyOidcUserStore {
    pub fn new<T>(
        users: Arc<T>,
        policy: crate::policy::PolicyStore,
        registry: Arc<crate::tailscale_wire::MachineRegistry>,
    ) -> Self
    where
        T: UserAdmin + crate::oidc::OidcUserStore + 'static,
    {
        Self {
            store: users.clone(),
            users,
            policy,
            registry,
        }
    }
}

#[async_trait]
impl crate::oidc::OidcUserStore for PolicyOidcUserStore {
    async fn refresh_oidc_user(
        &self,
        user: &crate::oidc::OidcStoredUser,
    ) -> Result<crate::oidc::OidcStoredUser, String> {
        self.store.refresh_oidc_user(user).await
    }

    async fn create_or_update_oidc_user(
        &self,
        profile: crate::oidc::OidcUserProfile,
    ) -> Result<crate::oidc::OidcStoredUser, String> {
        let guard = self.policy.lock_mutation().await;
        let adapter = self.clone();
        crate::tailscale_wire::complete_state_mutation(async move {
            let _guard = guard;
            let user = adapter.store.create_or_update_oidc_user(profile).await?;
            let identities = adapter
                .users
                .policy_users()
                .await
                .map_err(|error| error.to_string())?;
            let new_user = !adapter.policy.has_user_id(user.id);
            let change = adapter.policy.set_users_with_change_quiet(identities)?;
            // CreateUser always dispatches PolicyChange. UpdateUser leaves the
            // live nodes' cached user profiles intact and may return no change.
            if new_user || change.policy_changed {
                adapter.policy.refresh();
            } else {
                adapter.registry.dispatch_map_change(None);
            }
            Ok(user)
        })
        .await
        .map_err(|error| format!("finishing OIDC user update: {error}"))?
    }
}

fn oidc_stored_user(record: UserRecord) -> crate::oidc::OidcStoredUser {
    crate::oidc::OidcStoredUser {
        id: record.id,
        name: record.name,
        display_name: record.display_name,
        email: record.email,
        provider_identifier: record.provider_id,
        provider: record.provider,
        profile_pic_url: record.profile_pic_url,
    }
}

fn oidc_refresh_error(error: UserRegistryError) -> String {
    match error {
        UserRegistryError::Store(message) => message,
        error => error.to_string(),
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
        self.create_state_detailed(name, display_name, email, profile_pic_url)
    }

    fn create_state_detailed(
        &self,
        name: &str,
        display_name: &str,
        email: &str,
        profile_pic_url: &str,
    ) -> Result<UserRecord, UserRegistryError> {
        let mut g = self.inner.write();
        if g.contains_key(name) {
            return Err(UserRegistryError::Exists(name.to_string()));
        }
        let precise_now = Utc::now();
        let now = precise_now.timestamp().max(0) as u64;
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
            created_at_precise: Some(precise_now),
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

    fn rename_state_by_id(&self, id: u64, name: &str) -> Result<UserRecord, UserRegistryError> {
        let mut users = self.inner.write();
        let Some(old_key) = users
            .iter()
            .find(|(_, user)| user.id == id)
            .map(|(key, _)| key.clone())
        else {
            return Err(UserRegistryError::Missing(id.to_string()));
        };
        if !name.is_empty()
            && users
                .values()
                .any(|user| user.id != id && user.name == name)
        {
            return Err(UserRegistryError::Exists(name.to_owned()));
        }
        let mut stored = users.remove(&old_key).expect("selected user");
        stored.last_activity = now_unix();
        if !name.is_empty() {
            name.clone_into(&mut stored.name);
        }
        let mut returned = stored.clone();
        name.clone_into(&mut returned.name);
        users.insert(
            if name.is_empty() {
                old_key
            } else {
                name.to_owned()
            },
            stored,
        );
        Ok(returned)
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

    async fn create_for_state(
        &self,
        name: &str,
        display_name: &str,
        email: &str,
        profile_pic_url: &str,
    ) -> Result<UserRecord, UserRegistryError> {
        self.create_state_detailed(name, display_name, email, profile_pic_url)
    }

    async fn rename_for_state(&self, id: u64, name: &str) -> Result<UserRecord, UserRegistryError> {
        self.rename_state_by_id(id, name)
    }

    async fn get_for_registration_by_name(
        &self,
        name: &str,
    ) -> Result<Option<UserRegistrationSnapshot>, UserRegistryError> {
        let users = self.inner.read();
        let mut matching = users
            .values()
            .filter(|user| name.is_empty() || user.name == name);
        let Some(user) = matching.next() else {
            return Ok(None);
        };
        let count = 1 + matching.count();
        if count != 1 {
            return Err(UserRegistryError::Store(format!(
                "expected exactly one user, found {count}"
            )));
        }
        Ok(Some(UserRegistrationSnapshot::from_user(user.clone())))
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

    fn state_list_filter<'a>(
        name: &'a str,
        email: &'a str,
        id: u64,
    ) -> Result<headscale_db::users::UserListFilter<'a>, UserRegistryError> {
        use headscale_db::users::UserListFilter;
        Ok(if !name.is_empty() {
            UserListFilter::Name(name)
        } else if !email.is_empty() {
            UserListFilter::Email(email)
        } else if id != 0 {
            UserListFilter::Id(u64_to_i64(id)?)
        } else {
            UserListFilter::All
        })
    }

    pub(crate) fn row_to_association_record(row: headscale_db::users::UserRow) -> UserRecord {
        let name = row.name.clone();
        let mut user = Self::row_to_record(row);
        user.name = name;
        user
    }

    fn row_to_record(row: headscale_db::users::UserRow) -> UserRecord {
        let created_at_precise = if row.created_at_text.is_empty() {
            DateTime::from_timestamp(-62_135_596_800, 0)
        } else {
            DateTime::parse_from_rfc3339(&row.created_at_text)
                .or_else(|_| {
                    DateTime::parse_from_str(&row.created_at_text, "%Y-%m-%d %H:%M:%S%.f%:z")
                })
                .map(|timestamp| timestamp.with_timezone(&Utc))
                .ok()
                .or_else(|| {
                    NaiveDateTime::parse_from_str(&row.created_at_text, "%Y-%m-%d %H:%M:%S%.f")
                        .ok()
                        .map(|timestamp| timestamp.and_utc())
                })
                .or_else(|| DateTime::from_timestamp(row.created_at, 0))
        };
        UserRecord {
            id: i64_to_u64(row.id),
            name: if row.name.is_empty() {
                row.username()
            } else {
                row.name
            },
            created_at: i64_to_u64(row.created_at),
            created_at_precise,
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
                if msg.contains("user name invalid")
                    || msg.contains("hostname")
                    || msg.contains("username") =>
            {
                UserRegistryError::InvalidName(subject.to_string())
            }
            other => UserRegistryError::Store(other.to_string()),
        }
    }

    fn map_state_error(error: headscale_db::DbError, id: u64) -> UserRegistryError {
        match error {
            headscale_db::DbError::NotFound(_) => UserRegistryError::Missing(id.to_string()),
            error => UserRegistryError::Store(error.headscale_go_message()),
        }
    }

    fn map_optional_error(e: headscale_db::DbError, subject: &str) -> UserRegistryError {
        match e {
            headscale_db::DbError::NotFound(_) => UserRegistryError::Missing(subject.to_string()),
            other => UserRegistryError::Store(other.to_string()),
        }
    }

    async fn get_by_username(&self, name: &str) -> Result<Option<UserRecord>, UserRegistryError> {
        match headscale_db::users::get_by_name(&self.pool, name).await {
            Ok(row) => return Ok(Some(Self::row_to_record(row))),
            Err(headscale_db::DbError::NotFound(_)) => {}
            Err(e) => return Err(Self::map_optional_error(e, name)),
        }

        let rows = headscale_db::users::list(&self.pool)
            .await
            .map_err(|e| UserRegistryError::Store(e.to_string()))?;
        let matches = rows
            .into_iter()
            .filter(|row| row.username() == name)
            .collect::<Vec<_>>();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(Some(Self::row_to_record(
                matches.into_iter().next().expect("len checked"),
            ))),
            n => Err(UserRegistryError::Store(format!(
                "expected exactly one user, found {n}"
            ))),
        }
    }
}

#[async_trait]
impl crate::oidc::OidcUserStore for PersistentUserAdmin {
    async fn refresh_oidc_user(
        &self,
        user: &crate::oidc::OidcStoredUser,
    ) -> Result<crate::oidc::OidcStoredUser, String> {
        let record = UserAdmin::get_for_node_association(self, user.id)
            .await
            .map_err(oidc_refresh_error)?
            .ok_or_else(|| "record not found".to_owned())?;
        Ok(oidc_stored_user(record))
    }

    async fn create_or_update_oidc_user(
        &self,
        profile: crate::oidc::OidcUserProfile,
    ) -> Result<crate::oidc::OidcStoredUser, String> {
        let pool = self.pool.clone();
        let write = crate::tailscale_wire::complete_state_mutation(async move {
            headscale_db::users::create_or_update_oidc_user_for_registration(
                &pool,
                headscale_db::users::OidcUserParams {
                    name: profile.name,
                    display_name: profile.display_name,
                    email: profile.email,
                    provider_identifier: profile.provider_identifier,
                    profile_pic_url: profile.profile_pic_url,
                },
            )
            .await
        })
        .await
        .map_err(|error| format!("finishing OIDC user update: {error}"))?
        .map_err(|error| error.headscale_go_message())?;

        let record = Self::row_to_association_record(write.row);
        Ok(oidc_stored_user(record))
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

    async fn create_for_state(
        &self,
        name: &str,
        display_name: &str,
        email: &str,
        profile_pic_url: &str,
    ) -> Result<UserRecord, UserRegistryError> {
        let row = headscale_db::users::create_for_state(
            &self.pool,
            headscale_db::users::CreateParams {
                name: name.to_owned(),
                display_name: display_name.to_owned(),
                email: email.to_owned(),
                provider_identifier: None,
                provider: String::new(),
                profile_pic_url: profile_pic_url.to_owned(),
            },
        )
        .await
        .map_err(|error| UserRegistryError::Store(error.headscale_go_message()))?;
        Ok(Self::row_to_association_record(row))
    }

    async fn rename_for_state(&self, id: u64, name: &str) -> Result<UserRecord, UserRegistryError> {
        let id = u64_to_i64(id)?;
        let row = headscale_db::users::rename_for_state(&self.pool, id, name)
            .await
            .map_err(|error| match error {
                headscale_db::DbError::NotFound(_) => UserRegistryError::Missing(id.to_string()),
                error => UserRegistryError::Store(error.headscale_go_message()),
            })?;
        Ok(Self::row_to_association_record(row))
    }

    fn checks_user_owned_nodes_in_storage(&self) -> bool {
        true
    }

    async fn delete(&self, name: &str) -> Result<(), UserRegistryError> {
        let user = self
            .get_by_username(name)
            .await?
            .ok_or_else(|| UserRegistryError::Missing(name.to_string()))?;
        self.delete_by_id(user.id).await
    }

    async fn delete_by_id(&self, id: u64) -> Result<(), UserRegistryError> {
        let db_id = u64_to_i64(id)?;
        headscale_db::users::destroy(&self.pool, db_id)
            .await
            .map_err(|error| Self::map_state_error(error, id))
    }

    async fn get(&self, name: &str) -> Result<Option<UserRecord>, UserRegistryError> {
        self.get_by_username(name).await
    }

    async fn get_by_id(&self, id: u64) -> Result<Option<UserRecord>, UserRegistryError> {
        let db_id = u64_to_i64(id)?;
        match headscale_db::users::get_by_id(&self.pool, db_id).await {
            Ok(row) => Ok(Some(Self::row_to_record(row))),
            Err(headscale_db::DbError::NotFound(_)) => Ok(None),
            Err(e) => Err(Self::map_optional_error(e, &id.to_string())),
        }
    }

    async fn get_for_node_association(
        &self,
        id: u64,
    ) -> Result<Option<UserRecord>, UserRegistryError> {
        let db_id = u64_to_i64(id)?;
        match headscale_db::users::get_by_id(&self.pool, db_id).await {
            Ok(row) => Ok(Some(Self::row_to_association_record(row))),
            Err(headscale_db::DbError::NotFound(_)) => Ok(None),
            Err(e) => Err(Self::map_optional_error(e, &id.to_string())),
        }
    }

    async fn get_for_registration(
        &self,
        id: u64,
    ) -> Result<Option<UserRegistrationSnapshot>, UserRegistryError> {
        let db_id = u64_to_i64(id)?;
        match headscale_db::users::get_for_registration(&self.pool, db_id).await {
            Ok(write) => Ok(Some(UserRegistrationSnapshot {
                user: Self::row_to_association_record(write.row.clone()),
                write: Some(write),
            })),
            Err(headscale_db::DbError::NotFound(_)) => Ok(None),
            Err(error) => Err(UserRegistryError::Store(error.headscale_go_message())),
        }
    }

    async fn get_for_registration_by_name(
        &self,
        name: &str,
    ) -> Result<Option<UserRegistrationSnapshot>, UserRegistryError> {
        // Gorm omits a zero Name in Where(&User{Name: name}).
        let result = if name.is_empty() {
            let users = headscale_db::users::list_for_registration(&self.pool)
                .await
                .map_err(|error| UserRegistryError::Store(error.headscale_go_message()))?;
            match users.len() {
                0 => return Ok(None),
                1 => Ok(users.into_iter().next().expect("length checked")),
                count => {
                    return Err(UserRegistryError::Store(format!(
                        "expected exactly one user, found {count}"
                    )));
                }
            }
        } else {
            headscale_db::users::get_by_name_for_registration(&self.pool, name).await
        };
        match result {
            Ok(write) => Ok(Some(UserRegistrationSnapshot::from_native(write))),
            Err(headscale_db::DbError::NotFound(_)) => Ok(None),
            Err(error) => Err(UserRegistryError::Store(error.headscale_go_message())),
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

    async fn list_for_state(
        &self,
        name: &str,
        email: &str,
        id: u64,
    ) -> Result<Vec<UserRecord>, UserRegistryError> {
        let filter = Self::state_list_filter(name, email, id)?;
        let rows = headscale_db::users::list_for_state(&self.pool, filter)
            .await
            .map_err(|error| UserRegistryError::Store(error.headscale_go_message()))?;
        Ok(rows
            .into_iter()
            .map(Self::row_to_association_record)
            .collect())
    }

    async fn policy_users(&self) -> Result<Vec<crate::policy::PolicyUser>, UserRegistryError> {
        let rows = headscale_db::users::list(&self.pool)
            .await
            .map_err(|error| UserRegistryError::Store(error.headscale_go_message()))?;
        Ok(rows.into_iter().map(policy_identity_from_row).collect())
    }

    async fn touch(&self, name: &str) -> Result<(), UserRegistryError> {
        let Some(user) = self.get_by_username(name).await? else {
            return Ok(());
        };
        let db_id = u64_to_i64(user.id)?;
        let now = i64::try_from(now_unix()).unwrap_or(i64::MAX);
        sqlx::query(
            "
            UPDATE users
            SET updated_at = datetime(?, 'unixepoch')
            WHERE id = ? AND deleted_at IS NULL
            ",
        )
        .bind(now)
        .bind(db_id)
        .execute(&self.pool)
        .await
        .map_err(|e| UserRegistryError::Store(e.to_string()))
        .map(|_| ())
    }
}

#[cfg(feature = "postgres-sqlx")]
#[derive(Clone)]
pub struct PersistentPostgresUserAdmin {
    pool: PgPool,
}

#[cfg(feature = "postgres-sqlx")]
impl PersistentPostgresUserAdmin {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    async fn get_by_username(&self, name: &str) -> Result<Option<UserRecord>, UserRegistryError> {
        match headscale_db::users::get_postgres_by_name(&self.pool, name).await {
            Ok(row) => return Ok(Some(PersistentUserAdmin::row_to_record(row))),
            Err(headscale_db::DbError::NotFound(_)) => {}
            Err(e) => return Err(PersistentUserAdmin::map_optional_error(e, name)),
        }

        let rows = headscale_db::users::list_postgres(&self.pool)
            .await
            .map_err(|e| UserRegistryError::Store(e.to_string()))?;
        let matches = rows
            .into_iter()
            .filter(|row| row.username() == name)
            .collect::<Vec<_>>();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(Some(PersistentUserAdmin::row_to_record(
                matches.into_iter().next().expect("len checked"),
            ))),
            n => Err(UserRegistryError::Store(format!(
                "expected exactly one user, found {n}"
            ))),
        }
    }
}

#[cfg(feature = "postgres-sqlx")]
#[async_trait]
impl crate::oidc::OidcUserStore for PersistentPostgresUserAdmin {
    async fn refresh_oidc_user(
        &self,
        user: &crate::oidc::OidcStoredUser,
    ) -> Result<crate::oidc::OidcStoredUser, String> {
        let record = UserAdmin::get_for_node_association(self, user.id)
            .await
            .map_err(oidc_refresh_error)?
            .ok_or_else(|| "record not found".to_owned())?;
        Ok(oidc_stored_user(record))
    }

    async fn create_or_update_oidc_user(
        &self,
        profile: crate::oidc::OidcUserProfile,
    ) -> Result<crate::oidc::OidcStoredUser, String> {
        let pool = self.pool.clone();
        let write = crate::tailscale_wire::complete_state_mutation(async move {
            headscale_db::users::create_or_update_oidc_user_postgres_for_registration(
                &pool,
                headscale_db::users::OidcUserParams {
                    name: profile.name,
                    display_name: profile.display_name,
                    email: profile.email,
                    provider_identifier: profile.provider_identifier,
                    profile_pic_url: profile.profile_pic_url,
                },
            )
            .await
        })
        .await
        .map_err(|error| format!("finishing OIDC user update: {error}"))?
        .map_err(|error| error.headscale_go_message())?;

        let record = PersistentUserAdmin::row_to_association_record(write.row);
        Ok(oidc_stored_user(record))
    }
}

#[cfg(feature = "postgres-sqlx")]
#[async_trait]
impl UserAdmin for PersistentPostgresUserAdmin {
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
        let row = headscale_db::users::create_postgres(
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
        .map_err(|e| PersistentUserAdmin::map_db_write_error(e, name))?;
        Ok(PersistentUserAdmin::row_to_record(row))
    }

    async fn create_for_state(
        &self,
        name: &str,
        display_name: &str,
        email: &str,
        profile_pic_url: &str,
    ) -> Result<UserRecord, UserRegistryError> {
        let row = headscale_db::users::create_postgres_for_state(
            &self.pool,
            headscale_db::users::CreateParams {
                name: name.to_owned(),
                display_name: display_name.to_owned(),
                email: email.to_owned(),
                provider_identifier: None,
                provider: String::new(),
                profile_pic_url: profile_pic_url.to_owned(),
            },
        )
        .await
        .map_err(|error| UserRegistryError::Store(error.headscale_go_message()))?;
        Ok(PersistentUserAdmin::row_to_association_record(row))
    }

    async fn rename_for_state(&self, id: u64, name: &str) -> Result<UserRecord, UserRegistryError> {
        let id = u64_to_i64(id)?;
        let row = headscale_db::users::rename_postgres_for_state(&self.pool, id, name)
            .await
            .map_err(|error| match error {
                headscale_db::DbError::NotFound(_) => UserRegistryError::Missing(id.to_string()),
                error => UserRegistryError::Store(error.headscale_go_message()),
            })?;
        Ok(PersistentUserAdmin::row_to_association_record(row))
    }

    fn checks_user_owned_nodes_in_storage(&self) -> bool {
        true
    }

    async fn delete(&self, name: &str) -> Result<(), UserRegistryError> {
        let user = self
            .get_by_username(name)
            .await?
            .ok_or_else(|| UserRegistryError::Missing(name.to_string()))?;
        self.delete_by_id(user.id).await
    }

    async fn delete_by_id(&self, id: u64) -> Result<(), UserRegistryError> {
        let db_id = u64_to_i64(id)?;
        headscale_db::users::destroy_postgres(&self.pool, db_id)
            .await
            .map_err(|error| PersistentUserAdmin::map_state_error(error, id))
    }

    async fn get(&self, name: &str) -> Result<Option<UserRecord>, UserRegistryError> {
        self.get_by_username(name).await
    }

    async fn get_by_id(&self, id: u64) -> Result<Option<UserRecord>, UserRegistryError> {
        let db_id = u64_to_i64(id)?;
        match headscale_db::users::get_postgres_by_id(&self.pool, db_id).await {
            Ok(row) => Ok(Some(PersistentUserAdmin::row_to_record(row))),
            Err(headscale_db::DbError::NotFound(_)) => Ok(None),
            Err(e) => Err(PersistentUserAdmin::map_optional_error(e, &id.to_string())),
        }
    }

    async fn get_for_node_association(
        &self,
        id: u64,
    ) -> Result<Option<UserRecord>, UserRegistryError> {
        let db_id = u64_to_i64(id)?;
        match headscale_db::users::get_postgres_by_id(&self.pool, db_id).await {
            Ok(row) => Ok(Some(PersistentUserAdmin::row_to_association_record(row))),
            Err(headscale_db::DbError::NotFound(_)) => Ok(None),
            Err(e) => Err(PersistentUserAdmin::map_optional_error(e, &id.to_string())),
        }
    }

    async fn get_for_registration(
        &self,
        id: u64,
    ) -> Result<Option<UserRegistrationSnapshot>, UserRegistryError> {
        let db_id = u64_to_i64(id)?;
        match headscale_db::users::get_postgres_for_registration(&self.pool, db_id).await {
            Ok(write) => Ok(Some(UserRegistrationSnapshot {
                user: PersistentUserAdmin::row_to_association_record(write.row.clone()),
                write: Some(write),
            })),
            Err(headscale_db::DbError::NotFound(_)) => Ok(None),
            Err(error) => Err(UserRegistryError::Store(error.headscale_go_message())),
        }
    }

    async fn get_for_registration_by_name(
        &self,
        name: &str,
    ) -> Result<Option<UserRegistrationSnapshot>, UserRegistryError> {
        // Gorm omits a zero Name in Where(&User{Name: name}).
        let result = if name.is_empty() {
            let users = headscale_db::users::list_postgres_for_registration(&self.pool)
                .await
                .map_err(|error| UserRegistryError::Store(error.headscale_go_message()))?;
            match users.len() {
                0 => return Ok(None),
                1 => Ok(users.into_iter().next().expect("length checked")),
                count => {
                    return Err(UserRegistryError::Store(format!(
                        "expected exactly one user, found {count}"
                    )));
                }
            }
        } else {
            headscale_db::users::get_postgres_by_name_for_registration(&self.pool, name).await
        };
        match result {
            Ok(write) => Ok(Some(UserRegistrationSnapshot::from_native(write))),
            Err(headscale_db::DbError::NotFound(_)) => Ok(None),
            Err(error) => Err(UserRegistryError::Store(error.headscale_go_message())),
        }
    }

    async fn rename_by_id(&self, id: u64, new_name: &str) -> Result<UserRecord, UserRegistryError> {
        if !is_valid_user_name(new_name) {
            return Err(UserRegistryError::InvalidName(new_name.to_string()));
        }
        let db_id = u64_to_i64(id)?;
        let row = headscale_db::users::rename_postgres(&self.pool, db_id, new_name)
            .await
            .map_err(|e| PersistentUserAdmin::map_db_write_error(e, new_name))?;
        Ok(PersistentUserAdmin::row_to_record(row))
    }

    async fn all(&self) -> Result<Vec<UserRecord>, UserRegistryError> {
        let rows = headscale_db::users::list_postgres(&self.pool)
            .await
            .map_err(|e| UserRegistryError::Store(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(PersistentUserAdmin::row_to_record)
            .collect())
    }

    async fn list_for_state(
        &self,
        name: &str,
        email: &str,
        id: u64,
    ) -> Result<Vec<UserRecord>, UserRegistryError> {
        let filter = PersistentUserAdmin::state_list_filter(name, email, id)?;
        let rows = headscale_db::users::list_postgres_for_state(&self.pool, filter)
            .await
            .map_err(|error| UserRegistryError::Store(error.headscale_go_message()))?;
        Ok(rows
            .into_iter()
            .map(PersistentUserAdmin::row_to_association_record)
            .collect())
    }

    async fn policy_users(&self) -> Result<Vec<crate::policy::PolicyUser>, UserRegistryError> {
        let rows = headscale_db::users::list_postgres(&self.pool)
            .await
            .map_err(|error| UserRegistryError::Store(error.headscale_go_message()))?;
        Ok(rows.into_iter().map(policy_identity_from_row).collect())
    }

    async fn touch(&self, name: &str) -> Result<(), UserRegistryError> {
        let Some(user) = self.get_by_username(name).await? else {
            return Ok(());
        };
        let db_id = u64_to_i64(user.id)?;
        let now = i64::try_from(now_unix()).unwrap_or(i64::MAX);
        sqlx::query(
            "
            UPDATE users
            SET updated_at = to_timestamp(($1::BIGINT)::DOUBLE PRECISION)
            WHERE id = $2 AND deleted_at IS NULL
            ",
        )
        .bind(now)
        .bind(db_id)
        .execute(&self.pool)
        .await
        .map_err(|e| UserRegistryError::Store(e.to_string()))
        .map(|_| ())
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
    fn user_names_follow_headscale_go_validation() {
        let r = UserRegistry::new();
        assert!(r.create("").is_err());
        assert!(r.create("a").is_err());
        assert!(r.create("1alice").is_err());
        assert!(r.create("_alice").is_err());
        assert!(r.create("-alice").is_err());
        assert!(r.create(".alice").is_err());
        assert!(r.create("alice@@host").is_err());
        assert!(r.create("alice host").is_err());
        assert!(r.create("alice/host").is_err());

        assert!(r.create("Alice").is_ok());
        assert!(r.create("alice_smith").is_ok());
        assert!(r.create("alice@example.com").is_ok());
        assert!(r.create("alice-").is_ok());
        assert!(r.create("alice.").is_ok());
        assert!(r.create("alice.smith").is_ok());
        assert!(r.create(&"a".repeat(64)).is_ok());
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
        assert_eq!(
            created.created_at_precise.unwrap().timestamp_micros(),
            DateTime::parse_from_rfc3339(&stored.created_at_text)
                .unwrap()
                .timestamp_micros()
        );
        assert_ne!(
            created
                .created_at_precise
                .unwrap()
                .timestamp_subsec_micros(),
            0
        );

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
        assert_eq!(users.all().await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn persistent_user_admin_accepts_headscale_go_username_charset() {
        let db = headscale_db::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = PersistentUserAdmin::new(db.pool().clone());

        let created = users
            .create_detailed(
                "Alice_Example@example.com",
                "Alice Example",
                "alice@example.com",
                "",
            )
            .await
            .unwrap();
        assert_eq!(created.name, "Alice_Example@example.com");

        let stored = headscale_db::users::get_by_name(db.pool(), "Alice_Example@example.com")
            .await
            .unwrap();
        assert_eq!(stored.id, created.id as i64);

        let renamed = users
            .rename_by_id(created.id, "Alice-Renamed@example.com")
            .await
            .unwrap();
        assert_eq!(renamed.name, "Alice-Renamed@example.com");
        assert!(
            users
                .get("Alice_Example@example.com")
                .await
                .unwrap()
                .is_none()
        );
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
                ('', 'Alice Smith', 'alice@example.com', 'https://issuer/sub', 'oidc', 'https://example.com/alice.png', '1969-12-31 21:00:10.123456-03:00', datetime(11, 'unixepoch'))
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
        assert_eq!(
            listed[0].created_at_precise.unwrap().timestamp_micros(),
            10_123_456
        );
        assert_eq!(listed[0].last_activity, 11);
    }

    #[tokio::test]
    async fn persistent_user_admin_resolves_oidc_username_fallbacks() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("headscale.db");
        let db = headscale_db::Database::new(&format!("sqlite://{}?mode=rwc", db_path.display()))
            .await
            .unwrap();
        db.migrate().await.unwrap();
        let users = PersistentUserAdmin::new(db.pool().clone());

        let created = crate::oidc::OidcUserStore::create_or_update_oidc_user(
            &users,
            crate::oidc::OidcUserProfile {
                name: String::new(),
                display_name: "Alice OIDC".into(),
                email: "alice@example.com".into(),
                provider_identifier: "https://issuer.example/alice".into(),
                provider: crate::oidc::REGISTER_METHOD_OIDC.into(),
                profile_pic_url: String::new(),
            },
        )
        .await
        .unwrap();

        // Go User.FromClaim only sets Name when the username claim passes
        // util.ValidateUsername, so an empty claim leaves the stored Name
        // empty; Email carries the identity and User.Username() (used for
        // lookups below) is Email > Name > ProviderIdentifier > ID.
        assert_eq!(created.name, "");
        assert_eq!(created.email, "alice@example.com");
        let by_username = users.get("alice@example.com").await.unwrap().unwrap();
        assert_eq!(by_username.id, created.id);
        assert_eq!(by_username.provider, crate::oidc::REGISTER_METHOD_OIDC);

        users.touch("alice@example.com").await.unwrap();
        let touched = users.get_by_id(created.id).await.unwrap().unwrap();
        assert!(touched.last_activity >= by_username.last_activity);

        users.delete("alice@example.com").await.unwrap();
        assert!(users.get_by_id(created.id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn persistent_user_admin_upserts_oidc_profiles_for_callback() {
        let db = headscale_db::Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = PersistentUserAdmin::new(db.pool().clone());

        let created = crate::oidc::OidcUserStore::create_or_update_oidc_user(
            &users,
            crate::oidc::OidcUserProfile {
                name: "alice".into(),
                display_name: "Alice Smith".into(),
                email: "alice@example.com".into(),
                provider_identifier: "https://issuer.example/subject".into(),
                provider: crate::oidc::REGISTER_METHOD_OIDC.into(),
                profile_pic_url: "https://example.com/alice.png".into(),
            },
        )
        .await
        .unwrap();

        assert_eq!(created.name, "alice");
        assert_eq!(created.provider, crate::oidc::REGISTER_METHOD_OIDC);

        let updated = crate::oidc::OidcUserStore::create_or_update_oidc_user(
            &users,
            crate::oidc::OidcUserProfile {
                name: String::new(),
                display_name: "Alice Jones".into(),
                email: "alice.jones@example.com".into(),
                provider_identifier: "https://issuer.example/subject".into(),
                provider: crate::oidc::REGISTER_METHOD_OIDC.into(),
                profile_pic_url: "https://example.com/alice-jones.png".into(),
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.id, created.id);
        assert_eq!(updated.name, "alice");
        assert_eq!(updated.display_name, "Alice Jones");
        assert_eq!(updated.email, "alice.jones@example.com");
        assert_eq!(
            updated.provider_identifier,
            "https://issuer.example/subject"
        );
        assert_eq!(
            updated.profile_pic_url,
            "https://example.com/alice-jones.png"
        );
        assert_eq!(users.all().await.unwrap().len(), 1);
    }
}
