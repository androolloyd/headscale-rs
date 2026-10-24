//! sqlx-backed [`PreauthAdmin`] adapter.
//!
//! Brings the persistent pre-auth-key store from
//! [`headscale_db::preauth_keys`] up to the [`PreauthAdmin`] trait so
//! the admin router can serve a real DB instead of the
//! [`super::preauth::InMemoryPreauthAdmin`].
//!
//! Newly minted bearer tokens are returned once. Later reads use the Go
//! display key (public prefix plus `***` for modern keys); plaintext is not
//! retained in an adapter cache. Imported legacy rows retain Go's existing
//! plaintext-key display behavior.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
#[cfg(feature = "postgres-sqlx")]
use sqlx::PgPool;
use sqlx::SqlitePool;

use crate::tailscale_wire::{
    PreauthLookup, PreauthRedeemer, RedeemError, RedeemOk, RegistrationRedeemError,
};

use super::preauth::{
    PreauthAdmin, PreauthAdminError, PreauthAdminKey, PreauthAdminKeyView, PreauthMintRequest,
};
use super::users::{UserAdmin, UserRecord};
use headscale_db::DbError;
use headscale_db::preauth_keys::{self, CreateParams, PreauthKeyRow, UseError};

/// Persistent admin-side preauth store.
///
/// Cheap to clone (everything inside is `Arc`).
#[derive(Clone)]
pub struct PersistentPreauthAdmin {
    pool: SqlitePool,
    /// Bcrypt cost. Defaults to
    /// [`headscale_db::preauth_keys::BCRYPT_COST_DEFAULT`]; tests
    /// inject the cheap cost so they finish quickly.
    cost: u32,
    /// Optional user resolver. When present, minted rows store
    /// headscale-go's numeric `user_id` while admin responses keep
    /// returning the user name expected by the current REST surface.
    users: Option<Arc<dyn UserAdmin>>,
}

impl PersistentPreauthAdmin {
    /// Wrap an existing sqlx pool. The caller is responsible for
    /// having run `db.migrate()` first (the
    /// `20260520000005_create_preauth_keys.sql` migration creates the
    /// table this store reads from).
    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            cost: preauth_keys::BCRYPT_COST_DEFAULT,
            users: None,
        }
    }

    /// Test-only constructor that uses [`preauth_keys::BCRYPT_COST_TEST`]
    /// so the suite finishes in <2s. Not part of the public stability
    /// surface.
    #[doc(hidden)]
    pub fn new_for_test(pool: SqlitePool) -> Self {
        Self {
            pool,
            cost: preauth_keys::BCRYPT_COST_TEST,
            users: None,
        }
    }

    pub fn with_user_admin(mut self, users: Arc<dyn UserAdmin>) -> Self {
        self.users = Some(users);
        self
    }

    /// Direct access to the underlying pool — useful for the wire
    /// layer's `PreauthRedeemer` adapter to share the same DB.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    async fn mint_inner(
        &self,
        req: PreauthMintRequest,
        explicit_expiration: Option<i64>,
        precise_expiration: Option<DateTime<Utc>>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        let store = Self::clone(self);
        finish_preauth_work(async move {
            store
                .mint_inner_impl(req, explicit_expiration, precise_expiration)
                .await
        })
        .await
    }

    async fn mint_inner_impl(
        &self,
        req: PreauthMintRequest,
        explicit_expiration: Option<i64>,
        precise_expiration: Option<DateTime<Utc>>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        if req.user.trim().is_empty() && req.tags.is_empty() {
            return Err(PreauthAdminError::Invalid(
                "user must be non-empty unless acl_tags are provided".into(),
            ));
        }
        let expiration = super::preauth::expiration_for_mint(
            req.ttl_secs,
            precise_expiration
                .map(|value| value.timestamp())
                .or(explicit_expiration),
        );
        let storage_user_id = self.storage_user_id(&req.user).await?;
        let params = CreateParams {
            user_id: storage_user_id,
            reusable: req.reusable,
            ephemeral: req.ephemeral,
            tags: req.tags,
            expiration,
        };
        let result = if self.users.is_some() {
            preauth_keys::create_with_cost_precise_for_user_id(
                &self.pool,
                params,
                self.cost,
                precise_expiration,
            )
            .await
        } else {
            preauth_keys::create_with_cost_precise_with_user(
                &self.pool,
                params,
                self.cost,
                precise_expiration,
            )
            .await
        }
        .map_err(|error| PreauthAdminError::Store(error.to_string()))?;
        Ok(created_key_view(result)?.key)
    }

    /// Atomically try to redeem the given candidate plaintext. Mirror
    /// of [`preauth_keys::try_use`]; surfaced here so an embedding
    /// host can wire this into their wire-layer
    /// [`crate::tailscale_wire::PreauthRedeemer`] impl without
    /// having to depend on `headscale-db` directly.
    pub async fn try_use(&self, candidate: &str) -> Result<PreauthKeyRow, UseError> {
        preauth_keys::try_use(&self.pool, candidate).await
    }

    async fn storage_user_id(&self, user: &str) -> Result<String, PreauthAdminError> {
        if user.trim().is_empty() {
            return Ok(String::new());
        }
        let Some(users) = &self.users else {
            return Ok(user.to_string());
        };
        let record = users
            .get(user)
            .await
            .map_err(|e| PreauthAdminError::Store(e.to_string()))?
            .ok_or_else(|| PreauthAdminError::Invalid("user not found".to_string()))?;
        Ok(record.id.to_string())
    }
}

/// Postgres-backed admin-side preauth store.
///
/// Mirrors [`PersistentPreauthAdmin`] while using the feature-gated
/// headscale-go-compatible Postgres primitives in
/// [`headscale_db::preauth_keys`].
#[cfg(feature = "postgres-sqlx")]
#[derive(Clone)]
pub struct PersistentPostgresPreauthAdmin {
    pool: PgPool,
    cost: u32,
    users: Option<Arc<dyn UserAdmin>>,
}

#[cfg(feature = "postgres-sqlx")]
impl PersistentPostgresPreauthAdmin {
    /// Wrap an existing sqlx Postgres pool. The caller is responsible
    /// for having run migrations before wiring the adapter into the
    /// admin router.
    pub fn new(pool: PgPool) -> Self {
        Self {
            pool,
            cost: preauth_keys::BCRYPT_COST_DEFAULT,
            users: None,
        }
    }

    /// Test-only constructor that uses [`preauth_keys::BCRYPT_COST_TEST`].
    #[doc(hidden)]
    pub fn new_for_test(pool: PgPool) -> Self {
        Self {
            pool,
            cost: preauth_keys::BCRYPT_COST_TEST,
            users: None,
        }
    }

    pub fn with_user_admin(mut self, users: Arc<dyn UserAdmin>) -> Self {
        self.users = Some(users);
        self
    }

    /// Direct access to the underlying pool for embedding wire-layer
    /// integrations that need to share the same DB.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn mint_inner(
        &self,
        req: PreauthMintRequest,
        explicit_expiration: Option<i64>,
        precise_expiration: Option<DateTime<Utc>>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        let store = Self::clone(self);
        finish_preauth_work(async move {
            store
                .mint_inner_impl(req, explicit_expiration, precise_expiration)
                .await
        })
        .await
    }

    async fn mint_inner_impl(
        &self,
        req: PreauthMintRequest,
        explicit_expiration: Option<i64>,
        precise_expiration: Option<DateTime<Utc>>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        if req.user.trim().is_empty() && req.tags.is_empty() {
            return Err(PreauthAdminError::Invalid(
                "user must be non-empty unless acl_tags are provided".into(),
            ));
        }
        let expiration = super::preauth::expiration_for_mint(
            req.ttl_secs,
            precise_expiration
                .map(|value| value.timestamp())
                .or(explicit_expiration),
        );
        let storage_user_id = self.storage_user_id(&req.user).await?;
        let params = CreateParams {
            user_id: storage_user_id,
            reusable: req.reusable,
            ephemeral: req.ephemeral,
            tags: req.tags,
            expiration,
        };
        let result = if self.users.is_some() {
            preauth_keys::create_postgres_with_cost_precise_for_user_id(
                &self.pool,
                params,
                self.cost,
                precise_expiration,
            )
            .await
        } else {
            preauth_keys::create_postgres_with_cost_precise_with_user(
                &self.pool,
                params,
                self.cost,
                precise_expiration,
            )
            .await
        }
        .map_err(|error| PreauthAdminError::Store(error.to_string()))?;
        Ok(created_key_view(result)?.key)
    }

    /// Atomically try to redeem the given candidate plaintext.
    pub async fn try_use(&self, candidate: &str) -> Result<PreauthKeyRow, UseError> {
        preauth_keys::try_use_postgres(&self.pool, candidate).await
    }

    async fn storage_user_id(&self, user: &str) -> Result<String, PreauthAdminError> {
        if user.trim().is_empty() {
            return Ok(String::new());
        }
        let Some(users) = &self.users else {
            return Ok(user.to_string());
        };
        let record = users
            .get(user)
            .await
            .map_err(|e| PreauthAdminError::Store(e.to_string()))?
            .ok_or_else(|| PreauthAdminError::Invalid("user not found".to_string()))?;
        Ok(record.id.to_string())
    }
}

#[async_trait]
impl PreauthRedeemer for PersistentPreauthAdmin {
    fn supports_deferred_redemption(&self) -> bool {
        true
    }

    async fn validate(&self, key: &str) -> Result<RedeemOk, RedeemError> {
        self.validate_for_registration(key)
            .await
            .map_err(|error| error.kind)
    }

    async fn lookup_for_registration(
        &self,
        key: &str,
    ) -> Result<Option<PreauthLookup>, RegistrationRedeemError> {
        let pool = self.pool.clone();
        let candidate = key.to_owned();
        finish_credential_work(async move {
            let loaded = preauth_keys::get_by_token_for_registration(&pool, &candidate)
                .await
                .map_err(registration_lookup_error)?;
            credential_lookup(loaded).map(Some)
        })
        .await
    }

    async fn validate_for_registration(
        &self,
        key: &str,
    ) -> Result<RedeemOk, RegistrationRedeemError> {
        let lookup = self
            .lookup_for_registration(key)
            .await?
            .ok_or(RedeemError::Unknown)?;
        if let Some(valid) = lookup.validation_result() {
            valid?;
        }
        Ok(lookup.metadata)
    }

    async fn redeem(&self, key: &str) -> Result<RedeemOk, RedeemError> {
        let lookup = self
            .lookup_for_registration(key)
            .await
            .map_err(|error| error.kind)?
            .ok_or(RedeemError::Unknown)?;
        if let Some(valid) = lookup.validation_result() {
            valid.map_err(|error| error.kind)?;
        }
        self.try_use(key).await.map_err(use_error_to_redeem)?;
        Ok(lookup.metadata)
    }

    async fn lookup(&self, key: &str) -> Option<RedeemOk> {
        self.lookup_for_registration(key)
            .await
            .ok()
            .flatten()
            .map(|lookup| lookup.metadata)
    }
}

#[cfg(feature = "postgres-sqlx")]
#[async_trait]
impl PreauthRedeemer for PersistentPostgresPreauthAdmin {
    fn supports_deferred_redemption(&self) -> bool {
        true
    }

    async fn validate(&self, key: &str) -> Result<RedeemOk, RedeemError> {
        self.validate_for_registration(key)
            .await
            .map_err(|error| error.kind)
    }

    async fn lookup_for_registration(
        &self,
        key: &str,
    ) -> Result<Option<PreauthLookup>, RegistrationRedeemError> {
        let pool = self.pool.clone();
        let candidate = key.to_owned();
        finish_credential_work(async move {
            let loaded = preauth_keys::get_postgres_by_token_for_registration(&pool, &candidate)
                .await
                .map_err(registration_lookup_error)?;
            credential_lookup(loaded).map(Some)
        })
        .await
    }

    async fn validate_for_registration(
        &self,
        key: &str,
    ) -> Result<RedeemOk, RegistrationRedeemError> {
        let lookup = self
            .lookup_for_registration(key)
            .await?
            .ok_or(RedeemError::Unknown)?;
        if let Some(valid) = lookup.validation_result() {
            valid?;
        }
        Ok(lookup.metadata)
    }

    async fn redeem(&self, key: &str) -> Result<RedeemOk, RedeemError> {
        let lookup = self
            .lookup_for_registration(key)
            .await
            .map_err(|error| error.kind)?
            .ok_or(RedeemError::Unknown)?;
        if let Some(valid) = lookup.validation_result() {
            valid.map_err(|error| error.kind)?;
        }
        self.try_use(key).await.map_err(use_error_to_redeem)?;
        Ok(lookup.metadata)
    }

    async fn lookup(&self, key: &str) -> Option<RedeemOk> {
        self.lookup_for_registration(key)
            .await
            .ok()
            .flatten()
            .map(|lookup| lookup.metadata)
    }
}

async fn finish_credential_work<F, T>(work: F) -> Result<T, RegistrationRedeemError>
where
    F: std::future::Future<Output = Result<T, RegistrationRedeemError>> + Send + 'static,
    T: Send + 'static,
{
    crate::tailscale_wire::complete_state_mutation(work)
        .await
        .map_err(|error| RegistrationRedeemError {
            kind: RedeemError::Unknown,
            message: format!(
                "handling register with auth key: finishing credential lookup: {error}"
            ),
        })?
}

fn credential_lookup(
    loaded: preauth_keys::RegistrationKey,
) -> Result<PreauthLookup, RegistrationRedeemError> {
    let label = loaded
        .user
        .as_ref()
        .map(|user| user.row.username())
        .unwrap_or_default();
    let user = loaded
        .user
        .as_ref()
        .map(|user| super::users::PersistentUserAdmin::row_to_association_record(user.row.clone()));
    let native = super::machines::NativeAuthKey::from_row(&loaded.key, Some(user.clone()))
        .map_err(|error| RegistrationRedeemError {
            kind: RedeemError::Unknown,
            message: format!("handling register with auth key: {error}"),
        })?;
    let metadata = RedeemOk::for_user(label)
        .user_id(user.as_ref().map(|user| user.id))
        .ephemeral(native.ephemeral)
        .tags(native.tags.clone())
        .auth_key_id(loaded.key.id);
    Ok(PreauthLookup::from_native(metadata, native, loaded))
}

async fn finish_preauth_work<F, T>(work: F) -> Result<T, PreauthAdminError>
where
    F: std::future::Future<Output = Result<T, PreauthAdminError>> + Send + 'static,
    T: Send + 'static,
{
    crate::tailscale_wire::complete_state_mutation(work)
        .await
        .map_err(|error| {
            PreauthAdminError::Store(format!("finishing preauth key operation: {error}"))
        })?
}

fn created_key_view(
    result: preauth_keys::CreatedWithUser,
) -> Result<PreauthAdminKeyView, PreauthAdminError> {
    let user = result
        .user
        .map(super::users::PersistentUserAdmin::row_to_association_record);
    let mut view = native_key_view(&result.created.row, user)?;
    view.key.key = result.created.plaintext;
    Ok(view)
}

fn native_key_view(
    row: &PreauthKeyRow,
    user: Option<UserRecord>,
) -> Result<PreauthAdminKeyView, PreauthAdminError> {
    let loaded = super::machines::NativeAuthKey::from_row(row, Some(user.clone()))
        .map_err(|error| PreauthAdminError::Store(error.to_string()))?;
    let label = user
        .as_ref()
        .map(|user| {
            if !user.name.is_empty() {
                user.name.clone()
            } else if !user.email.is_empty() {
                user.email.clone()
            } else if !user.provider_id.is_empty() {
                user.provider_id.clone()
            } else {
                user.id.to_string()
            }
        })
        .unwrap_or_default();
    Ok(PreauthAdminKeyView {
        key: PreauthAdminKey {
            id: loaded.id,
            key: loaded.display_key,
            user: label,
            created_at: row.created_at.max(0) as u64,
            created_at_precise: loaded.created_at,
            expires_at: super::preauth::display_expires_at(row.expiration),
            expires_at_precise: loaded.expiration,
            reusable: loaded.reusable,
            ephemeral: loaded.ephemeral,
            tags: loaded.tags,
            redemptions: u64::from(row.used_at.is_some()),
        },
        user,
        created_at: loaded.created_at,
        expiration: loaded.expiration,
    })
}

fn unique_display_prefix(rows: &[PreauthKeyRow], prefix: &str) -> Result<i64, PreauthAdminError> {
    let mut matches = rows
        .iter()
        .filter(|row| row.display_key().starts_with(prefix));
    let first = matches
        .next()
        .ok_or_else(|| PreauthAdminError::Unknown(prefix.to_owned()))?;
    if matches.next().is_some() {
        return Err(PreauthAdminError::Invalid(
            "prefix matches multiple preauth keys; use the full public prefix or numeric ID".into(),
        ));
    }
    Ok(first.id)
}

fn registration_lookup_error(error: DbError) -> RegistrationRedeemError {
    match error {
        // Go maps every failed row query to its record-not-found sentinel.
        DbError::NotFound(_) | DbError::Sqlx(_) => RedeemError::Unknown.into(),
        DbError::General(message) => RegistrationRedeemError {
            kind: RedeemError::Unknown,
            message: format!("handling register with auth key: {message}"),
        },
        error => RegistrationRedeemError {
            kind: RedeemError::Unknown,
            message: format!("handling register with auth key: {error}"),
        },
    }
}

pub(crate) fn use_error_to_redeem(e: UseError) -> RedeemError {
    match e {
        UseError::NotFound => RedeemError::Unknown,
        UseError::Expired => RedeemError::Expired,
        UseError::AlreadyUsed => RedeemError::AlreadyUsed,
    }
}

#[async_trait]
impl PreauthAdmin for PersistentPreauthAdmin {
    fn checks_key_owner_in_storage(&self) -> bool {
        true
    }

    async fn list(&self) -> Vec<PreauthAdminKey> {
        self.list_checked().await.unwrap_or_else(|error| {
            tracing::warn!(%error, "preauth list failed");
            Vec::new()
        })
    }

    async fn list_checked(&self) -> Result<Vec<PreauthAdminKey>, PreauthAdminError> {
        Ok(self
            .list_with_associations()
            .await?
            .unwrap_or_default()
            .into_iter()
            .map(|view| view.key)
            .collect())
    }

    async fn list_with_associations(
        &self,
    ) -> Result<Option<Vec<PreauthAdminKeyView>>, PreauthAdminError> {
        let pool = self.pool.clone();
        finish_preauth_work(async move {
            let rows = preauth_keys::list_all_with_users(&pool)
                .await
                .map_err(db_error_to_admin)?;
            let mut views = Vec::with_capacity(rows.len());
            for row in rows {
                let user = row
                    .user
                    .map(super::users::PersistentUserAdmin::row_to_association_record);
                views.push(native_key_view(&row.key, user)?);
            }
            Ok(Some(views))
        })
        .await
    }

    async fn mint_with_user_id(
        &self,
        user_id: Option<u64>,
        req: PreauthMintRequest,
        expiration: Option<DateTime<Utc>>,
    ) -> Result<Option<PreauthAdminKeyView>, PreauthAdminError> {
        let pool = self.pool.clone();
        let cost = self.cost;
        finish_preauth_work(async move {
            let result = preauth_keys::create_with_cost_precise_for_user_id(
                &pool,
                CreateParams {
                    user_id: user_id.map(|id| id.to_string()).unwrap_or_default(),
                    reusable: req.reusable,
                    ephemeral: req.ephemeral,
                    tags: req.tags,
                    expiration: expiration.map(|stamp| stamp.timestamp()),
                },
                cost,
                expiration,
            )
            .await
            .map_err(|error| PreauthAdminError::Store(error.headscale_go_message()))?;
            created_key_view(result).map(Some)
        })
        .await
    }

    async fn mint(&self, req: PreauthMintRequest) -> Result<PreauthAdminKey, PreauthAdminError> {
        self.mint_inner(req, None, None).await
    }

    async fn mint_with_expiration(
        &self,
        req: PreauthMintRequest,
        expiration: Option<i64>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        self.mint_inner(req, expiration, None).await
    }

    async fn mint_with_precise_expiration(
        &self,
        req: PreauthMintRequest,
        expiration: Option<DateTime<Utc>>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        self.mint_inner(req, None, expiration).await
    }

    async fn expire_by_prefix(&self, prefix: &str) -> Result<(), PreauthAdminError> {
        if prefix.len() < 4 {
            return Err(PreauthAdminError::Invalid(
                "prefix must be at least 4 chars".into(),
            ));
        }
        let pool = self.pool.clone();
        let prefix = prefix.to_owned();
        finish_preauth_work(async move {
            let id = if let Ok(row) = preauth_keys::get_by_token(&pool, &prefix).await {
                row.id
            } else {
                let rows = preauth_keys::list_all(&pool)
                    .await
                    .map_err(db_error_to_admin)?;
                unique_display_prefix(&rows, &prefix)?
            };
            preauth_keys::expire(&pool, id)
                .await
                .map_err(db_error_to_admin)
        })
        .await
    }

    async fn expire_by_id(&self, id: u64) -> Result<(), PreauthAdminError> {
        let id =
            i64::try_from(id).map_err(|_| PreauthAdminError::Store("id out of range".into()))?;
        let pool = self.pool.clone();
        finish_preauth_work(async move {
            preauth_keys::expire(&pool, id)
                .await
                .map_err(db_error_to_admin)
        })
        .await
    }

    async fn delete_by_id(&self, id: u64) -> Result<(), PreauthAdminError> {
        let id =
            i64::try_from(id).map_err(|_| PreauthAdminError::Store("id out of range".into()))?;
        let pool = self.pool.clone();
        finish_preauth_work(async move {
            preauth_keys::destroy(&pool, id)
                .await
                .map_err(db_error_to_admin)
        })
        .await
    }
}

#[cfg(feature = "postgres-sqlx")]
#[async_trait]
impl PreauthAdmin for PersistentPostgresPreauthAdmin {
    fn checks_key_owner_in_storage(&self) -> bool {
        true
    }

    async fn list(&self) -> Vec<PreauthAdminKey> {
        self.list_checked().await.unwrap_or_else(|error| {
            tracing::warn!(%error, "preauth list failed");
            Vec::new()
        })
    }

    async fn list_checked(&self) -> Result<Vec<PreauthAdminKey>, PreauthAdminError> {
        Ok(self
            .list_with_associations()
            .await?
            .unwrap_or_default()
            .into_iter()
            .map(|view| view.key)
            .collect())
    }

    async fn list_with_associations(
        &self,
    ) -> Result<Option<Vec<PreauthAdminKeyView>>, PreauthAdminError> {
        let pool = self.pool.clone();
        finish_preauth_work(async move {
            let rows = preauth_keys::list_all_postgres_with_users(&pool)
                .await
                .map_err(db_error_to_admin)?;
            let mut views = Vec::with_capacity(rows.len());
            for row in rows {
                let user = row
                    .user
                    .map(super::users::PersistentUserAdmin::row_to_association_record);
                views.push(native_key_view(&row.key, user)?);
            }
            Ok(Some(views))
        })
        .await
    }

    async fn mint_with_user_id(
        &self,
        user_id: Option<u64>,
        req: PreauthMintRequest,
        expiration: Option<DateTime<Utc>>,
    ) -> Result<Option<PreauthAdminKeyView>, PreauthAdminError> {
        let pool = self.pool.clone();
        let cost = self.cost;
        finish_preauth_work(async move {
            let result = preauth_keys::create_postgres_with_cost_precise_for_user_id(
                &pool,
                CreateParams {
                    user_id: user_id.map(|id| id.to_string()).unwrap_or_default(),
                    reusable: req.reusable,
                    ephemeral: req.ephemeral,
                    tags: req.tags,
                    expiration: expiration.map(|stamp| stamp.timestamp()),
                },
                cost,
                expiration,
            )
            .await
            .map_err(|error| PreauthAdminError::Store(error.headscale_go_message()))?;
            created_key_view(result).map(Some)
        })
        .await
    }

    async fn mint(&self, req: PreauthMintRequest) -> Result<PreauthAdminKey, PreauthAdminError> {
        self.mint_inner(req, None, None).await
    }

    async fn mint_with_expiration(
        &self,
        req: PreauthMintRequest,
        expiration: Option<i64>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        self.mint_inner(req, expiration, None).await
    }

    async fn mint_with_precise_expiration(
        &self,
        req: PreauthMintRequest,
        expiration: Option<DateTime<Utc>>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        self.mint_inner(req, None, expiration).await
    }

    async fn expire_by_prefix(&self, prefix: &str) -> Result<(), PreauthAdminError> {
        if prefix.len() < 4 {
            return Err(PreauthAdminError::Invalid(
                "prefix must be at least 4 chars".into(),
            ));
        }
        let pool = self.pool.clone();
        let prefix = prefix.to_owned();
        finish_preauth_work(async move {
            let id = if let Ok(row) = preauth_keys::get_postgres_by_token(&pool, &prefix).await {
                row.id
            } else {
                let rows = preauth_keys::list_all_postgres(&pool)
                    .await
                    .map_err(db_error_to_admin)?;
                unique_display_prefix(&rows, &prefix)?
            };
            preauth_keys::expire_postgres(&pool, id)
                .await
                .map_err(db_error_to_admin)
        })
        .await
    }

    async fn expire_by_id(&self, id: u64) -> Result<(), PreauthAdminError> {
        let id =
            i64::try_from(id).map_err(|_| PreauthAdminError::Store("id out of range".into()))?;
        let pool = self.pool.clone();
        finish_preauth_work(async move {
            preauth_keys::expire_postgres(&pool, id)
                .await
                .map_err(db_error_to_admin)
        })
        .await
    }

    async fn delete_by_id(&self, id: u64) -> Result<(), PreauthAdminError> {
        let id =
            i64::try_from(id).map_err(|_| PreauthAdminError::Store("id out of range".into()))?;
        let pool = self.pool.clone();
        finish_preauth_work(async move {
            preauth_keys::destroy_postgres(&pool, id)
                .await
                .map_err(db_error_to_admin)
        })
        .await
    }
}

fn db_error_to_admin(e: DbError) -> PreauthAdminError {
    match e {
        DbError::NotFound(msg) => PreauthAdminError::Unknown(msg),
        other => PreauthAdminError::Store(other.headscale_go_message()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::users::{PersistentUserAdmin, UserAdmin};
    use super::*;
    use crate::tailscale_wire::{PreauthRedeemer, RedeemError};
    use headscale_db::Database;

    async fn store() -> PersistentPreauthAdmin {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        users.create("alice").await.unwrap();
        PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users)
    }

    fn alice_req() -> PreauthMintRequest {
        PreauthMintRequest {
            user: "alice".into(),
            ttl_secs: 3600,
            reusable: false,
            ephemeral: false,
            tags: vec![],
        }
    }

    #[tokio::test]
    async fn mint_then_list_redacts_plaintext() {
        let s = store().await;
        let k = s.mint(alice_req()).await.unwrap();
        assert!(k.key.starts_with(headscale_db::preauth_keys::TOKEN_PREFIX));
        let list = s.list().await;
        assert_eq!(list.len(), 1);
        assert_ne!(list[0].key, k.key);
        assert!(list[0].key.ends_with("-***"));
        assert_eq!(list[0].user, "alice");
    }

    #[tokio::test]
    async fn mint_rejects_empty_user() {
        let s = store().await;
        let mut r = alice_req();
        r.user = String::new();
        let e = s.mint(r).await.unwrap_err();
        assert!(matches!(e, PreauthAdminError::Invalid(_)));
    }

    #[tokio::test]
    async fn mint_then_try_use_redeems() {
        let s = store().await;
        let k = s.mint(alice_req()).await.unwrap();
        let row = s.try_use(&k.key).await.unwrap();
        assert_eq!(row.user_id, "1");
        assert!(row.used_at.is_some());
    }

    #[tokio::test]
    async fn user_admin_resolver_stores_numeric_user_id_but_lists_name() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let users = Arc::new(PersistentUserAdmin::new(db.pool().clone()));
        let alice = users.create("alice").await.unwrap();
        let store =
            PersistentPreauthAdmin::new_for_test(db.pool().clone()).with_user_admin(users.clone());

        let key = store.mint(alice_req()).await.unwrap();
        assert_eq!(key.user, "alice");

        let raw = headscale_db::preauth_keys::get_by_id(db.pool(), key.id as i64)
            .await
            .unwrap();
        assert_eq!(raw.user_id, alice.id.to_string());
        let (raw_user_id, storage_type): (i64, String) =
            sqlx::query_as("SELECT user_id, typeof(user_id) FROM pre_auth_keys WHERE id = ?")
                .bind(key.id as i64)
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(raw_user_id, alice.id as i64);
        assert_eq!(storage_type, "integer");

        let listed = store.list().await;
        assert_eq!(listed[0].user, "alice");

        let redeemed = store.try_use(&key.key).await.unwrap();
        assert_eq!(redeemed.user_id, alice.id.to_string());
    }

    #[tokio::test]
    async fn single_use_rejects_replay() {
        let s = store().await;
        let k = s.mint(alice_req()).await.unwrap();
        let _ = s.try_use(&k.key).await.unwrap();
        let e = s.try_use(&k.key).await.unwrap_err();
        assert_eq!(e, UseError::AlreadyUsed);
    }

    #[tokio::test]
    async fn preauth_redeemer_lookup_surfaces_used_and_expired_keys() {
        let s = store().await;
        let used = s.mint(alice_req()).await.unwrap();

        let first = s.redeem(&used.key).await.unwrap();
        assert_eq!(first.user, "alice");
        assert_eq!(first.auth_key_id, Some(used.id as i64));
        let e = s.redeem(&used.key).await.unwrap_err();
        assert_eq!(e, RedeemError::AlreadyUsed);
        let looked_up = s.lookup(&used.key).await.unwrap();
        assert_eq!(looked_up.user, "alice");
        assert_eq!(looked_up.auth_key_id, Some(used.id as i64));

        let expired = s.mint(alice_req()).await.unwrap();
        s.expire_by_id(expired.id).await.unwrap();
        let e = s.redeem(&expired.key).await.unwrap_err();
        assert_eq!(e, RedeemError::Expired);
        let looked_up = s.lookup(&expired.key).await.unwrap();
        assert_eq!(looked_up.user, "alice");
        assert_eq!(looked_up.auth_key_id, Some(expired.id as i64));
    }

    #[tokio::test]
    async fn reusable_persists_across_redemptions() {
        let s = store().await;
        let mut r = alice_req();
        r.reusable = true;
        let k = s.mint(r).await.unwrap();
        for _ in 0..3 {
            let _ = s.try_use(&k.key).await.unwrap();
        }
        let list = s.list().await;
        assert_eq!(list.len(), 1);
        assert!(list[0].reusable);
    }

    #[tokio::test]
    async fn expire_by_full_token_prefix_works() {
        let s = store().await;
        let k = s.mint(alice_req()).await.unwrap();
        // Use the first 20 chars (brand + 7 hex chars) — same prefix
        // shape the admin table renders.
        let prefix = &k.key[..20];
        s.expire_by_prefix(prefix).await.unwrap();
        // After expiry, try_use must fail.
        let e = s.try_use(&k.key).await.unwrap_err();
        assert_eq!(e, UseError::Expired);
    }

    #[tokio::test]
    async fn expire_unknown_prefix_errors() {
        let s = store().await;
        let _ = s.mint(alice_req()).await.unwrap();
        let e = s.expire_by_prefix("hskey-auth-deadbeef").await.unwrap_err();
        assert!(matches!(e, PreauthAdminError::Unknown(_)));
    }

    #[tokio::test]
    async fn tags_and_ephemeral_round_trip() {
        let s = store().await;
        let req = PreauthMintRequest {
            user: "alice".into(),
            ttl_secs: 3600,
            reusable: false,
            ephemeral: true,
            tags: vec!["tag:dev".into(), "tag:server".into()],
        };
        let k = s.mint(req).await.unwrap();
        assert!(k.ephemeral);
        assert_eq!(k.tags, vec!["tag:dev".to_string(), "tag:server".into()]);
        let list = s.list().await;
        assert_eq!(list[0].tags.len(), 2);
        assert!(list[0].ephemeral);
    }

    #[tokio::test]
    async fn ttl_zero_means_no_expiry() {
        let s = store().await;
        let mut r = alice_req();
        r.ttl_secs = 0;
        let k = s.mint(r).await.unwrap();
        // `expires_at` is i64::MAX cast to u64 when expiration is NULL.
        assert!(k.expires_at > 10_000_000_000, "ttl=0 => effectively never");
    }

    #[tokio::test]
    async fn absolute_expiration_is_not_ttl_clamped() {
        let s = store().await;
        let key = s
            .mint_with_expiration(alice_req(), Some(4_102_444_800))
            .await
            .unwrap();
        assert_eq!(key.expires_at, 4_102_444_800);

        let listed = s.list().await;
        assert_eq!(listed[0].expires_at, 4_102_444_800);
    }
}
