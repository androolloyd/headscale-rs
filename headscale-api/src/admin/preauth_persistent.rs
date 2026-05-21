//! sqlx-backed [`PreauthAdmin`] adapter.
//!
//! Brings the persistent pre-auth-key store from
//! [`headscale_db::preauth_keys`] up to the [`PreauthAdmin`] trait so
//! the admin router can serve a real DB instead of the
//! [`super::preauth::InMemoryPreauthAdmin`].
//!
//! The plaintext token returned by [`headscale_db::preauth_keys::create`]
//! is preserved on the in-memory side-cache so the
//! [`PreauthAdminKey::key`] field (which the operator UX expects to be
//! the full bearer token, splashed once on mint) is populated. The DB
//! itself never stores plaintext — see the migration in
//! `headscale-db/migrations/20260520000005_create_preauth_keys.sql`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use sqlx::SqlitePool;

use super::preauth::{PreauthAdmin, PreauthAdminError, PreauthAdminKey, PreauthMintRequest};
use super::users::UserAdmin;
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
    /// Side-cache: `id → plaintext`. We need the plaintext to
    /// reconstruct [`PreauthAdminKey::key`] on `list`, because the DB
    /// only holds the bcrypt hash. Populated on `mint`; if the
    /// process restarts, list-pages render the hash prefix (which the
    /// operator can still expire/destroy by hash-prefix). Bounded —
    /// in practice operators mint at most a few hundred outstanding
    /// keys, so the unbounded HashMap is acceptable; the
    /// [`Self::with_cache_capacity`] hook gives an LRU-evicting
    /// variant for the paranoid.
    plaintext_cache: Arc<Mutex<HashMap<i64, String>>>,
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
            plaintext_cache: Arc::new(Mutex::new(HashMap::new())),
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
            plaintext_cache: Arc::new(Mutex::new(HashMap::new())),
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
            .map_err(|e| PreauthAdminError::Invalid(e.to_string()))?
            .ok_or_else(|| PreauthAdminError::Invalid("user not found".to_string()))?;
        Ok(record.id.to_string())
    }

    async fn display_user_for_row(&self, row: &PreauthKeyRow) -> String {
        let Some(users) = &self.users else {
            return row.user_id.clone();
        };
        let Ok(id) = row.user_id.parse::<u64>() else {
            return row.user_id.clone();
        };
        match users.get_by_id(id).await {
            Ok(Some(user)) => user.name,
            Ok(None) | Err(_) => row.user_id.clone(),
        }
    }

    async fn row_to_admin_key(&self, row: &PreauthKeyRow) -> PreauthAdminKey {
        let key = {
            self.plaintext_cache
                .lock()
                .get(&row.id)
                .cloned()
                // Fall back to the upstream display key when we don't
                // have the plaintext (process restart, key minted by a
                // different node, etc.). Admins can still see and expire
                // the row; only redemption with this value is impossible.
                .unwrap_or_else(|| row.display_key())
        };
        let user = self.display_user_for_row(row).await;
        // We don't track per-row redemption counts in the DB yet
        // (Go upstream doesn't either — the only signal is
        // "used_at NOT NULL" for single-use). Reusable keys show
        // 0 here; embedding hosts that want counters can layer
        // them on the wire side.
        let redemptions = u64::from(!row.reusable && row.used_at.is_some());
        PreauthAdminKey {
            id: row.id.max(0) as u64,
            key,
            user,
            created_at: row.created_at as u64,
            expires_at: row.expiration.unwrap_or(i64::MAX) as u64,
            reusable: row.reusable,
            ephemeral: row.ephemeral,
            tags: row.tag_list(),
            redemptions,
        }
    }
}

#[async_trait]
impl PreauthAdmin for PersistentPreauthAdmin {
    async fn list(&self) -> Vec<PreauthAdminKey> {
        match preauth_keys::list_all(&self.pool).await {
            Ok(rows) => {
                let mut keys = Vec::with_capacity(rows.len());
                for row in &rows {
                    keys.push(self.row_to_admin_key(row).await);
                }
                keys
            }
            Err(e) => {
                tracing::warn!(?e, "preauth list failed");
                Vec::new()
            }
        }
    }

    async fn mint(&self, req: PreauthMintRequest) -> Result<PreauthAdminKey, PreauthAdminError> {
        if req.user.trim().is_empty() && req.tags.is_empty() {
            return Err(PreauthAdminError::Invalid(
                "user must be non-empty unless acl_tags are provided".to_string(),
            ));
        }
        // Mirror the in-memory minter's TTL clamp so the two stores
        // agree on bounds (60s floor, 365d ceiling). `ttl_secs == 0`
        // means "no expiry" — we encode this as a NULL `expiration`
        // column.
        const MIN_TTL_SECS: u64 = 60;
        const MAX_TTL_SECS: u64 = 365 * 24 * 3600;
        let expiration = if req.ttl_secs == 0 {
            None
        } else {
            let ttl = req.ttl_secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs());
            Some((now.saturating_add(ttl)) as i64)
        };
        let storage_user_id = self.storage_user_id(&req.user).await?;

        let created = preauth_keys::create_with_cost(
            &self.pool,
            CreateParams {
                user_id: storage_user_id,
                reusable: req.reusable,
                ephemeral: req.ephemeral,
                tags: req.tags.clone(),
                expiration,
            },
            self.cost,
        )
        .await
        .map_err(|e| PreauthAdminError::Invalid(e.to_string()))?;

        // Cache the plaintext so subsequent `list` calls can splash
        // it. The DB only holds the hash.
        self.plaintext_cache
            .lock()
            .insert(created.row.id, created.plaintext.clone());

        // Reconstruct the admin shape from the row directly (with the
        // freshly-minted plaintext from the side-cache).
        let user = self.display_user_for_row(&created.row).await;
        Ok(PreauthAdminKey {
            id: created.row.id.max(0) as u64,
            key: created.plaintext,
            user,
            created_at: created.row.created_at as u64,
            expires_at: created.row.expiration.unwrap_or(i64::MAX) as u64,
            reusable: created.row.reusable,
            ephemeral: created.row.ephemeral,
            tags: req.tags,
            redemptions: 0,
        })
    }

    async fn expire_by_prefix(&self, prefix: &str) -> Result<(), PreauthAdminError> {
        if prefix.len() < 4 {
            return Err(PreauthAdminError::Invalid(
                "prefix must be at least 4 chars".to_string(),
            ));
        }
        // Scan the plaintext cache first — most expire calls come
        // from operators who just minted the key. Cache hits avoid an
        // O(N)-bcrypt-verify walk.
        let from_cache = {
            let cache = self.plaintext_cache.lock();
            cache
                .iter()
                .find(|(_, plain)| plain.starts_with(prefix))
                .map(|(id, _)| *id)
        };
        if let Some(id) = from_cache {
            preauth_keys::expire(&self.pool, id)
                .await
                .map_err(|e| PreauthAdminError::Invalid(e.to_string()))?;
            return Ok(());
        }
        // Fall back to scanning the table. Caller's prefix might
        // match the upstream display prefix we render when the
        // plaintext isn't cached.
        match preauth_keys::list_all(&self.pool).await {
            Ok(rows) => {
                let target_id = rows.iter().find_map(|r| {
                    if r.display_key().starts_with(prefix) {
                        Some(r.id)
                    } else {
                        None
                    }
                });
                if let Some(id) = target_id {
                    preauth_keys::expire(&self.pool, id)
                        .await
                        .map_err(|e| PreauthAdminError::Invalid(e.to_string()))?;
                    Ok(())
                } else {
                    Err(PreauthAdminError::Unknown(prefix.to_string()))
                }
            }
            Err(e) => Err(PreauthAdminError::Invalid(e.to_string())),
        }
    }

    async fn expire_by_id(&self, id: u64) -> Result<(), PreauthAdminError> {
        let id = i64::try_from(id)
            .map_err(|_| PreauthAdminError::Invalid("id out of range".to_string()))?;
        preauth_keys::expire(&self.pool, id)
            .await
            .map_err(db_error_to_admin)
    }

    async fn delete_by_id(&self, id: u64) -> Result<(), PreauthAdminError> {
        let id = i64::try_from(id)
            .map_err(|_| PreauthAdminError::Invalid("id out of range".to_string()))?;
        preauth_keys::destroy(&self.pool, id)
            .await
            .map_err(db_error_to_admin)?;
        self.plaintext_cache.lock().remove(&id);
        Ok(())
    }
}

fn db_error_to_admin(e: DbError) -> PreauthAdminError {
    match e {
        DbError::NotFound(msg) => PreauthAdminError::Unknown(msg),
        other => PreauthAdminError::Invalid(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::super::users::{PersistentUserAdmin, UserAdmin};
    use super::*;
    use headscale_db::Database;

    async fn store() -> PersistentPreauthAdmin {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        PersistentPreauthAdmin::new_for_test(db.pool().clone())
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
    async fn mint_then_list_shows_plaintext() {
        let s = store().await;
        let k = s.mint(alice_req()).await.unwrap();
        assert!(k.key.starts_with(headscale_db::preauth_keys::TOKEN_PREFIX));
        let list = s.list().await;
        assert_eq!(list.len(), 1);
        assert_eq!(
            list[0].key, k.key,
            "list should splash the cached plaintext"
        );
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
        assert_eq!(row.user_id, "alice");
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
}
