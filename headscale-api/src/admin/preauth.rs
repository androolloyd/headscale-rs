//! Admin-side preauth-key surface.
//!
//! The wire layer only exposes `PreauthRedeemer` (a one-way redeem
//! verb). The admin panel needs `list` + `mint` + `expire` too, so we
//! define a separate trait — [`PreauthAdmin`] — which the embedding
//! host implements on its real key store (e.g. OctraVPN's
//! `PreauthMinter`).
//!
//! For testing + standalone admin-panel-only deployments we ship an
//! in-memory implementation [`InMemoryPreauthAdmin`] that mirrors the
//! shape of `octravpn-mesh::PreauthMinter` but doesn't depend on it.
//!
//! ## Wire compatibility
//!
//! `PreauthAdminKey` carries the same field names that
//! `octravpn-mesh::headscale_bridge::PreauthKey` serialises with (key,
//! user, created_at, expires_at, reusable) plus two admin-only fields
//! (`ephemeral`, `tags`). Implementations are free to keep `ephemeral`
//! / `tags` flat-mapped or stub them out — the admin panel renders
//! "[none]" when the slice is empty.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

use super::auth::now_unix;

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
    /// Unix-seconds expiry.
    pub expires_at: u64,
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
    /// Times the key has been redeemed. Reusable keys grow this;
    /// non-reusable keys stop at 1 then disappear from the list.
    #[serde(default)]
    pub redemptions: u64,
}

/// Parameters for minting a new preauth key from the admin panel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreauthMintRequest {
    pub user: String,
    /// TTL in seconds. Capped at 365 days by the handler to avoid
    /// "forever" keys.
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
}

/// Admin surface for the preauth-key store.
///
/// Async because production impls may need to hit a DB; the in-tree
/// impls are sync but adopt the signature trivially.
#[async_trait]
pub trait PreauthAdmin: Send + Sync {
    /// All known (live OR redeemed-but-not-pruned) keys.
    async fn list(&self) -> Vec<PreauthAdminKey>;

    /// Mint a fresh key.
    async fn mint(&self, req: PreauthMintRequest) -> Result<PreauthAdminKey, PreauthAdminError>;

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

impl InMemoryPreauthAdmin {
    pub fn new() -> Self {
        Self::default()
    }
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
        if req.user.trim().is_empty() && req.tags.is_empty() {
            return Err(PreauthAdminError::Invalid(
                "user must be non-empty unless acl_tags are provided".to_string(),
            ));
        }
        const MAX_TTL_SECS: u64 = 365 * 24 * 3600;
        let ttl = req.ttl_secs.clamp(60, MAX_TTL_SECS);
        let now = now_unix();
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
            expires_at: now.saturating_add(ttl),
            reusable: req.reusable,
            ephemeral: req.ephemeral,
            tags: req.tags,
            redemptions: 0,
        };
        g.insert(key, rec.clone());
        Ok(rec)
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
                    rec.expires_at = now_unix();
                }
                Ok(())
            }
            None => Err(PreauthAdminError::Unknown(prefix.to_string())),
        }
    }

    async fn expire_by_id(&self, id: u64) -> Result<(), PreauthAdminError> {
        if id == 0 {
            return Err(PreauthAdminError::Invalid(
                "id must be non-zero".to_string(),
            ));
        }
        let mut g = self.inner.lock();
        let Some(rec) = g.values_mut().find(|rec| rec.id == id) else {
            return Err(PreauthAdminError::Unknown(id.to_string()));
        };
        rec.expires_at = now_unix();
        Ok(())
    }

    async fn delete_by_id(&self, id: u64) -> Result<(), PreauthAdminError> {
        if id == 0 {
            return Err(PreauthAdminError::Invalid(
                "id must be non-zero".to_string(),
            ));
        }
        let mut g = self.inner.lock();
        let Some(key) = g
            .iter()
            .find(|(_, rec)| rec.id == id)
            .map(|(key, _)| key.clone())
        else {
            return Err(PreauthAdminError::Unknown(id.to_string()));
        };
        g.remove(&key);
        Ok(())
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
}
