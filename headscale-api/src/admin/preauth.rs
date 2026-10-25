//! Admin-side preauth-key surface.
//!
//! The wire layer only exposes `PreauthRedeemer` (a one-way redeem
//! verb). The admin panel needs `list` + `mint` + `expire` too, so we
//! define a separate trait — [`PreauthAdmin`] — which the embedding
//! host implements on its real key store.
//!
//! For testing + standalone admin-panel-only deployments we ship an
//! in-memory implementation [`InMemoryPreauthAdmin`] with the same
//! upstream-facing fields exposed by the persistent pre-auth-key store.
//!
//! ## Wire compatibility
//!
//! `PreauthAdminKey` carries the fields the admin UI and upstream gRPC
//! compatibility paths need (`key`, `user`, timestamps, reuse state,
//! lifecycle flags, and tags). Implementations are free to keep
//! `ephemeral` / `tags` flat-mapped or stub them out — the admin panel
//! renders "[none]" when the slice is empty.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use crate::tailscale_wire::{PreauthRedeemer, RedeemError, RedeemOk};

use super::auth::now_unix;
use super::users::UserRecord;

/// Admin-side view of one preauth key. Stable JSON shape across
/// implementations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreauthAdminKey {
    /// Upstream-visible numeric row ID.
    #[serde(default)]
    pub id: u64,
    /// Full opaque bearer token. Pages show only the first ~10 chars
    /// (so the table doesn't leak the secret to an over-the-shoulder
    /// viewer), but the value here is the actual key — the panel
    /// reveals it once on the create-success flash.
    pub key: String,
    /// User the key was minted for. Empty means a tags-only key with no
    /// owning user, matching headscale-go v0.28's optional user field.
    pub user: String,
    /// Unix-seconds creation timestamp.
    pub created_at: u64,
    /// Original database timestamp, including fractional seconds.
    #[serde(skip)]
    pub created_at_precise: Option<DateTime<Utc>>,
    /// Unix-seconds expiry.
    pub expires_at: u64,
    #[serde(skip)]
    pub expires_at_precise: Option<DateTime<Utc>>,
    /// Whether the key can be redeemed more than once.
    pub reusable: bool,
    /// Whether the key is ephemeral (one-shot device, auto-cleaned).
    /// v0 stores but doesn't act on this flag — present for the
    /// roundtrip with the Tailscale CLI.
    #[serde(default)]
    pub ephemeral: bool,
    /// Tags attached to the key. Carried through to the registered
    /// machine record (not enforced by the wire layer in v0).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Native adapters project Go's Used bit as zero or one. Custom
    /// adapters may retain a redemption count; gRPC treats nonzero as used.
    #[serde(default)]
    pub redemptions: u64,
}

/// Native RPC projection, including independently loaded user and nullable
/// timestamps. `key.key` is already the exact create/list display value.
#[derive(Clone, Debug)]
pub struct PreauthAdminKeyView {
    pub key: PreauthAdminKey,
    pub user: Option<UserRecord>,
    pub created_at: Option<DateTime<Utc>>,
    pub expiration: Option<DateTime<Utc>>,
}

/// Parameters for minting a new preauth key from the admin panel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreauthMintRequest {
    pub user: String,
    /// TTL in seconds. Capped at 365 days by the handler for relative
    /// admin/UI minting. `0` means no expiry.
    pub ttl_secs: u64,
    pub reusable: bool,
    pub ephemeral: bool,
    pub tags: Vec<String>,
}

/// Errors the admin trait can surface.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PreauthAdminError {
    #[error("unknown key prefix '{0}'")]
    Unknown(String),
    #[error("invalid mint parameters: {0}")]
    Invalid(String),
    #[error("{0}")]
    Store(String),
}

/// Admin surface for the preauth-key store.
///
/// Async because production impls may need to hit a DB; the in-tree
/// impls are sync but adopt the signature trivially.
#[async_trait]
pub trait PreauthAdmin: Send + Sync {
    /// Native state mint checks nil-owner/empty-tags after beginning its write
    /// transaction. Other adapters retain the RPC's preliminary check.
    fn checks_key_owner_in_storage(&self) -> bool {
        false
    }

    /// All known (live OR redeemed-but-not-pruned) keys.
    async fn list(&self) -> Vec<PreauthAdminKey>;

    async fn list_checked(&self) -> Result<Vec<PreauthAdminKey>, PreauthAdminError> {
        Ok(self.list().await)
    }

    /// Native stores retain nil associations/timestamps and legacy display
    /// provenance. Other adapters keep the established key projection.
    async fn list_with_associations(
        &self,
    ) -> Result<Option<Vec<PreauthAdminKeyView>>, PreauthAdminError> {
        Ok(None)
    }

    /// Mint using the upstream numeric owner, without resolving its name a
    /// second time, with an absolute expiration. The TTL field is unused.
    /// Returning None selects the adapter's established mint path.
    async fn mint_with_user_id(
        &self,
        user_id: Option<u64>,
        req: PreauthMintRequest,
        expiration: Option<DateTime<Utc>>,
    ) -> Result<Option<PreauthAdminKeyView>, PreauthAdminError> {
        let _ = (user_id, req, expiration);
        Ok(None)
    }

    /// Mint a fresh key.
    async fn mint(&self, req: PreauthMintRequest) -> Result<PreauthAdminKey, PreauthAdminError>;

    /// Mint a fresh key with an upstream absolute expiration timestamp.
    ///
    /// This is used by gRPC/REST-gateway `CreatePreAuthKey`, whose proto
    /// carries `google.protobuf.Timestamp expiration`. Admin/UI callers should
    /// keep using [`Self::mint`] with relative TTLs.
    async fn mint_with_expiration(
        &self,
        req: PreauthMintRequest,
        expiration: Option<i64>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        let _ = expiration;
        self.mint(req).await
    }

    async fn mint_with_precise_expiration(
        &self,
        req: PreauthMintRequest,
        expiration: Option<DateTime<Utc>>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        self.mint_with_expiration(req, expiration.map(|value| value.timestamp()))
            .await
    }

    /// Expire — set `expires_at` to now, OR remove — a key identified
    /// by its **prefix** (so admins can paste the truncated form
    /// shown in the table).
    async fn expire_by_prefix(&self, prefix: &str) -> Result<(), PreauthAdminError>;

    /// Expire a key by upstream numeric row ID.
    async fn expire_by_id(&self, id: u64) -> Result<(), PreauthAdminError>;

    /// Delete a key outright by upstream numeric row ID.
    async fn delete_by_id(&self, id: u64) -> Result<(), PreauthAdminError>;
}

/// In-memory preauth admin. Used by tests + by deployments that don't
/// wire in a persistent store. Compatible with the upstream
/// `hskey-auth-<12>-<64>` token format.
#[derive(Clone, Default)]
pub struct InMemoryPreauthAdmin {
    inner: Arc<Mutex<HashMap<String, PreauthAdminKey>>>,
}

const TOKEN_PREFIX: &str = "hskey-auth-";
const TOKEN_PREFIX_LEN: usize = 12;
const TOKEN_SECRET_LEN: usize = 64;
const URLSAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
pub const NEVER_EXPIRES_AT: u64 = i64::MAX as u64;

fn generate_urlsafe(len: usize) -> String {
    let mut raw = vec![0u8; len];
    rand_core::OsRng.fill_bytes(&mut raw);
    raw.into_iter()
        .map(|b| URLSAFE[(b & 0b0011_1111) as usize] as char)
        .collect()
}

fn generate_preauth_key() -> String {
    let prefix = generate_urlsafe(TOKEN_PREFIX_LEN);
    let secret = generate_urlsafe(TOKEN_SECRET_LEN);
    format!("{TOKEN_PREFIX}{prefix}-{secret}")
}

pub(crate) fn expiration_for_mint(ttl_secs: u64, explicit_expiration: Option<i64>) -> Option<i64> {
    if let Some(expiration) = explicit_expiration {
        return Some(expiration);
    }
    if ttl_secs == 0 {
        return None;
    }
    const MIN_TTL_SECS: u64 = 60;
    const MAX_TTL_SECS: u64 = 365 * 24 * 3600;
    let ttl = ttl_secs.clamp(MIN_TTL_SECS, MAX_TTL_SECS);
    let expires_at = now_unix().saturating_add(ttl);
    Some(i64::try_from(expires_at).unwrap_or(i64::MAX))
}

pub(crate) fn display_expires_at(expiration: Option<i64>) -> u64 {
    match expiration {
        Some(expiration) => u64::try_from(expiration).unwrap_or_default(),
        None => NEVER_EXPIRES_AT,
    }
}

impl InMemoryPreauthAdmin {
    pub fn new() -> Self {
        Self::default()
    }

    fn mint_inner(
        &self,
        mut req: PreauthMintRequest,
        explicit_expiration: Option<i64>,
        precise_expiration: Option<DateTime<Utc>>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        if req.user.trim().is_empty() && req.tags.is_empty() {
            return Err(PreauthAdminError::Invalid(
                "user must be non-empty unless acl_tags are provided".to_string(),
            ));
        }
        req.tags.sort();
        req.tags.dedup();
        if let Some(tag) = req.tags.iter().find(|tag| !tag.starts_with("tag:")) {
            return Err(PreauthAdminError::Invalid(format!(
                "auth-key tag is invalid: '{tag}' did not begin with 'tag:'"
            )));
        }
        let expiration = expiration_for_mint(
            req.ttl_secs,
            precise_expiration
                .map(|value| value.timestamp())
                .or(explicit_expiration),
        );
        let precise_now = Utc::now();
        let now = precise_now.timestamp().max(0) as u64;
        let key = generate_preauth_key();
        let mut g = self.inner.lock();
        let id = g
            .values()
            .map(|key| key.id)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let rec = PreauthAdminKey {
            id,
            key: key.clone(),
            user: req.user,
            created_at: now,
            created_at_precise: Some(precise_now),
            expires_at: display_expires_at(expiration),
            expires_at_precise: precise_expiration
                .or_else(|| expiration.and_then(|secs| DateTime::from_timestamp(secs, 0))),
            reusable: req.reusable,
            ephemeral: req.ephemeral,
            tags: req.tags,
            redemptions: 0,
        };
        g.insert(key, rec.clone());
        Ok(rec)
    }
}

fn in_memory_key_to_redeem_ok(key: &PreauthAdminKey) -> RedeemOk {
    let mut ok = RedeemOk::for_user(key.user.clone())
        .ephemeral(key.ephemeral)
        .tags(key.tags.clone());
    if let Ok(id) = i64::try_from(key.id) {
        ok = ok.auth_key_id(id);
    }
    ok
}

#[async_trait]
impl PreauthAdmin for InMemoryPreauthAdmin {
    async fn list(&self) -> Vec<PreauthAdminKey> {
        let g = self.inner.lock();
        let mut v: Vec<_> = g.values().cloned().collect();
        v.sort_by_key(|key| std::cmp::Reverse(key.created_at));
        v
    }

    async fn mint(&self, req: PreauthMintRequest) -> Result<PreauthAdminKey, PreauthAdminError> {
        self.mint_inner(req, None, None)
    }

    async fn mint_with_expiration(
        &self,
        req: PreauthMintRequest,
        expiration: Option<i64>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        self.mint_inner(req, expiration, None)
    }

    async fn mint_with_precise_expiration(
        &self,
        req: PreauthMintRequest,
        expiration: Option<DateTime<Utc>>,
    ) -> Result<PreauthAdminKey, PreauthAdminError> {
        self.mint_inner(req, None, expiration)
    }

    async fn expire_by_prefix(&self, prefix: &str) -> Result<(), PreauthAdminError> {
        let mut g = self.inner.lock();
        // Look for the unique key whose prefix matches. Empty prefix
        // intentionally never matches — operator error guard.
        if prefix.len() < 4 {
            return Err(PreauthAdminError::Invalid(
                "prefix must be at least 4 chars".to_string(),
            ));
        }
        let target: Option<String> = g.keys().find(|k| k.starts_with(prefix)).cloned();
        match target {
            Some(k) => {
                if let Some(rec) = g.get_mut(&k) {
                    let now = Utc::now();
                    rec.expires_at = now.timestamp().max(0) as u64;
                    rec.expires_at_precise = Some(now);
                }
                Ok(())
            }
            None => Err(PreauthAdminError::Unknown(prefix.to_string())),
        }
    }

    async fn expire_by_id(&self, id: u64) -> Result<(), PreauthAdminError> {
        let mut keys = self.inner.lock();
        if let Some(key) = keys.values_mut().find(|key| key.id == id) {
            let now = Utc::now();
            key.expires_at = now.timestamp().max(0) as u64;
            key.expires_at_precise = Some(now);
        }
        Ok(())
    }

    async fn delete_by_id(&self, id: u64) -> Result<(), PreauthAdminError> {
        let mut keys = self.inner.lock();
        keys.retain(|_, key| key.id != id);
        Ok(())
    }
}

#[async_trait]
impl PreauthRedeemer for InMemoryPreauthAdmin {
    async fn redeem(&self, key: &str) -> Result<RedeemOk, RedeemError> {
        let mut g = self.inner.lock();
        let Some(rec) = g.get_mut(key) else {
            return Err(RedeemError::Unknown);
        };
        let now = Utc::now();
        if rec.expires_at_precise.map_or_else(
            || rec.expires_at != NEVER_EXPIRES_AT && rec.expires_at < now.timestamp().max(0) as u64,
            |expiry| expiry < now,
        ) {
            return Err(RedeemError::Expired);
        }
        if !rec.reusable && rec.redemptions > 0 {
            return Err(RedeemError::AlreadyUsed);
        }
        if !rec.reusable {
            rec.redemptions = rec.redemptions.saturating_add(1);
        }
        Ok(in_memory_key_to_redeem_ok(rec))
    }

    async fn lookup(&self, key: &str) -> Option<RedeemOk> {
        let g = self.inner.lock();
        g.get(key).map(in_memory_key_to_redeem_ok)
    }
}

/// Convenience: derive a stable, table-safe display prefix for `key`.
pub(crate) fn key_prefix(key: &str) -> String {
    if let Some(rest) = key.strip_prefix(TOKEN_PREFIX)
        && rest.len() >= TOKEN_PREFIX_LEN
    {
        return format!("{TOKEN_PREFIX}{}-***", &rest[..TOKEN_PREFIX_LEN]);
    }
    key.to_string()
}

/// Default TTL used when the form doesn't specify (24 hours).
pub const DEFAULT_TTL_SECS: u64 = 24 * 3600;

/// Default ephemeral/reusable defaults the create-form pre-fills with.
pub fn default_mint() -> PreauthMintRequest {
    PreauthMintRequest {
        user: String::new(),
        ttl_secs: DEFAULT_TTL_SECS,
        reusable: false,
        ephemeral: false,
        tags: Vec::new(),
    }
}

/// Cap on the TTL we accept from the create form. Mirrors what the
/// in-memory impl clamps to; exported so handlers can render the hint.
pub const MAX_TTL_DAYS: u64 = 365;

// Tiny shim that drives an async future on a fresh tokio current-thread
// runtime — used by the unit tests below so they don't need to be
// `#[tokio::test]`'d. Kept module-private.
#[cfg(test)]
mod _shim {
    use std::future::Future;

    pub(super) fn block_on<F: Future>(f: F) -> F::Output {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("tokio rt");
        rt.block_on(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block<F: std::future::Future>(f: F) -> F::Output {
        super::_shim::block_on(f)
    }

    #[test]
    fn mint_and_list() {
        let a = InMemoryPreauthAdmin::new();
        let req = PreauthMintRequest {
            user: "alice".into(),
            ttl_secs: 600,
            reusable: false,
            ephemeral: false,
            tags: vec!["tag:dev".into()],
        };
        let k = block(a.mint(req)).unwrap();
        assert_eq!(k.user, "alice");
        assert!(k.key.starts_with(TOKEN_PREFIX));
        let l = block(a.list());
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn empty_user_rejected() {
        let a = InMemoryPreauthAdmin::new();
        let req = PreauthMintRequest {
            user: String::new(),
            ttl_secs: 600,
            reusable: false,
            ephemeral: false,
            tags: vec![],
        };
        assert!(block(a.mint(req)).is_err());
    }

    #[test]
    fn expire_by_prefix_works() {
        let a = InMemoryPreauthAdmin::new();
        let k = block(a.mint(PreauthMintRequest {
            user: "alice".into(),
            ttl_secs: 600,
            reusable: false,
            ephemeral: false,
            tags: vec![],
        }))
        .unwrap();
        let prefix = &k.key[..20];
        assert!(block(a.expire_by_prefix(prefix)).is_ok());
        let live = block(a.list());
        assert!(live[0].expires_at <= now_unix() + 1);
    }

    #[test]
    fn ttl_zero_means_no_expiry() {
        let a = InMemoryPreauthAdmin::new();
        let k = block(a.mint(PreauthMintRequest {
            user: "alice".into(),
            ttl_secs: 0,
            reusable: false,
            ephemeral: false,
            tags: vec![],
        }))
        .unwrap();
        assert_eq!(k.expires_at, NEVER_EXPIRES_AT);
    }

    #[test]
    fn absolute_expiration_is_preserved() {
        let a = InMemoryPreauthAdmin::new();
        let k = block(a.mint_with_expiration(
            PreauthMintRequest {
                user: "alice".into(),
                ttl_secs: 0,
                reusable: false,
                ephemeral: false,
                tags: vec![],
            },
            Some(4_102_444_800),
        ))
        .unwrap();
        assert_eq!(k.expires_at, 4_102_444_800);
    }

    #[test]
    fn expire_unknown_prefix_errors() {
        let a = InMemoryPreauthAdmin::new();
        let e = block(a.expire_by_prefix("hskey-auth-deadbeef")).unwrap_err();
        assert!(matches!(e, PreauthAdminError::Unknown(_)));
    }

    #[test]
    fn key_prefix_truncates_long_keys() {
        let p = key_prefix("hskey-auth-abcdefghijkl-0123456789abcdef");
        assert_eq!(p, "hskey-auth-abcdefghijkl-***");
    }

    #[test]
    fn redeem_one_shot_key_marks_used_and_preserves_metadata() {
        let a = InMemoryPreauthAdmin::new();
        let k = block(a.mint(PreauthMintRequest {
            user: "alice".into(),
            ttl_secs: 600,
            reusable: false,
            ephemeral: true,
            tags: vec!["tag:dev".into()],
        }))
        .unwrap();

        let ok = block(a.redeem(&k.key)).unwrap();
        assert_eq!(ok.user, "alice");
        assert!(ok.ephemeral);
        assert_eq!(ok.tags, vec!["tag:dev"]);
        let expected_id = i64::try_from(k.id).ok();
        assert_eq!(ok.auth_key_id, expected_id);

        let keys = block(a.list());
        assert_eq!(keys[0].redemptions, 1);
        let err = block(a.redeem(&k.key)).unwrap_err();
        assert_eq!(err, RedeemError::AlreadyUsed);

        let lookup = block(a.lookup(&k.key)).expect("lookup used key");
        assert_eq!(lookup.user, "alice");
        assert_eq!(lookup.auth_key_id, expected_id);
    }

    #[test]
    fn redeem_reusable_key_allows_multiple_uses() {
        let a = InMemoryPreauthAdmin::new();
        let k = block(a.mint(PreauthMintRequest {
            user: "alice".into(),
            ttl_secs: 600,
            reusable: true,
            ephemeral: false,
            tags: vec![],
        }))
        .unwrap();

        assert!(block(a.redeem(&k.key)).is_ok());
        assert!(block(a.redeem(&k.key)).is_ok());
        let keys = block(a.list());
        assert_eq!(keys[0].redemptions, 0);
    }

    #[test]
    fn redeem_expired_key_fails_but_lookup_surfaces_metadata() {
        let a = InMemoryPreauthAdmin::new();
        let k = block(a.mint_with_expiration(
            PreauthMintRequest {
                user: "alice".into(),
                ttl_secs: 0,
                reusable: false,
                ephemeral: false,
                tags: vec![],
            },
            Some(i64::try_from(now_unix().saturating_sub(1)).unwrap_or(i64::MAX)),
        ))
        .unwrap();

        let err = block(a.redeem(&k.key)).unwrap_err();
        assert_eq!(err, RedeemError::Expired);
        let lookup = block(a.lookup(&k.key)).expect("lookup expired key");
        assert_eq!(lookup.user, "alice");
    }
}
