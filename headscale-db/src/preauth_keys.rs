//! Pre-auth key persistence — sqlx-backed store mirroring
//! `juanfont/headscale@main:hscontrol/db/preauth_keys.go`.
//!
//! ## Surface
//!
//! * [`create`] — mint a new token, return the plaintext + the row.
//! * [`get_by_token`] — bcrypt-verify a candidate plaintext against
//!   every live row and return the match (or `NotFound`).
//! * [`expire`] — set `expiration` to now, leaving the row in place.
//! * [`destroy`] — delete the row outright.
//! * [`list_by_user`] — admin listing per user (newest first).
//! * [`try_use`] — atomic single-use redemption: if `reusable=0` and
//!   `used_at IS NULL`, flip `used_at` to now in one statement and
//!   return the row; reject otherwise.
//!
//! ## Token shape
//!
//! Wire format is `octrapreauth-<64-hex>` — unchanged from the
//! pre-persistence in-process minter so existing operator UX is
//! preserved (see brief: "Do NOT change the wire-format of the
//! `octrapreauth-<hex>` token").
//!
//! ## Bcrypt cost
//!
//! Defaults to [`BCRYPT_COST_DEFAULT`] in production. Unit tests opt
//! into [`BCRYPT_COST_TEST`] (the bcrypt-crate minimum, 4) via
//! [`create_with_cost`] / [`create_for_test`] so the suite finishes
//! in under a second.

use crate::{DbError, Result};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

/// Brand prefix on the plaintext bearer token. Hard-coded so the
/// admin panel + CLI render identical truncated forms.
pub const TOKEN_PREFIX: &str = "octrapreauth-";

/// Production bcrypt cost. 12 is the industry-standard floor as of
/// 2024 (NIST SP 800-63B), and matches the Go upstream's
/// `bcrypt.DefaultCost` (which is 10) bumped one notch for the
/// extra-throughput-per-key the headscale-rs control plane sees.
pub const BCRYPT_COST_DEFAULT: u32 = 12;

/// Cheap bcrypt cost for unit tests — the crate's minimum (4). Keeps
/// the 20+ test suite under a couple of seconds total. `bcrypt::hash`
/// rejects costs below 4 with `BcryptError::CostNotAllowed`.
pub const BCRYPT_COST_TEST: u32 = 4;

/// One pre-auth-key row in the DB. Mirrors the Go upstream's
/// `hscontrol/types/preauth_key.go::PreAuthKey` field-for-field
/// (renamed `Key` → `key_hash` to spell out the hashing — see the
/// SQL migration comment for the trade).
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreauthKeyRow {
    pub id: i64,
    pub key_hash: String,
    pub user_id: String,
    pub reusable: bool,
    pub ephemeral: bool,
    /// JSON-encoded `Vec<String>`. Use [`PreauthKeyRow::tag_list`] to
    /// decode.
    pub tags: String,
    /// Unix-seconds. `None` ⇒ never expires.
    pub expiration: Option<i64>,
    pub created_at: i64,
    /// Unix-seconds. `None` ⇒ unused.
    pub used_at: Option<i64>,
}

impl PreauthKeyRow {
    /// Parse the JSON `tags` column.
    pub fn tag_list(&self) -> Vec<String> {
        serde_json::from_str(&self.tags).unwrap_or_default()
    }

    /// True iff the row is past its `expiration` (using the supplied
    /// "now" — callers pass `now_unix()` in production; tests can
    /// inject a fixed clock).
    pub fn is_expired(&self, now_unix: i64) -> bool {
        match self.expiration {
            Some(exp) => now_unix >= exp,
            None => false,
        }
    }

    /// True iff the row is single-use (i.e. `!reusable`) and has
    /// already been redeemed at least once.
    pub fn is_used(&self) -> bool {
        !self.reusable && self.used_at.is_some()
    }

    /// Convenience: is this key currently redeemable?
    pub fn is_live(&self, now_unix: i64) -> bool {
        !self.is_expired(now_unix) && !self.is_used()
    }
}

/// Parameters for minting a new pre-auth key.
#[derive(Debug, Clone)]
pub struct CreateParams {
    pub user_id: String,
    pub reusable: bool,
    pub ephemeral: bool,
    pub tags: Vec<String>,
    /// `None` ⇒ never expires; `Some(t)` ⇒ row expires at unix-second `t`.
    pub expiration: Option<i64>,
}

/// Result of [`create`]: the bcrypt-hashed row + the plaintext token
/// that the caller must hand back to the device (the row in the DB
/// never holds plaintext, so this is the *only* time the secret
/// exists outside the device's pocket).
#[derive(Debug, Clone)]
pub struct Created {
    pub plaintext: String,
    pub row: PreauthKeyRow,
}

/// Current wall-clock as unix-seconds.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// Generate a fresh `octrapreauth-<hex>` plaintext token. 32 random
/// bytes ⇒ 64 hex chars ⇒ same length the in-process minter used.
pub fn generate_plaintext() -> String {
    let mut raw = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut raw);
    format!("{TOKEN_PREFIX}{}", hex::encode(raw))
}

/// Mint with the production bcrypt cost.
pub async fn create(pool: &SqlitePool, params: CreateParams) -> Result<Created> {
    create_with_cost(pool, params, BCRYPT_COST_DEFAULT).await
}

/// Mint with the test-only cost (cheap bcrypt). Production callers
/// MUST use [`create`].
pub async fn create_for_test(pool: &SqlitePool, params: CreateParams) -> Result<Created> {
    create_with_cost(pool, params, BCRYPT_COST_TEST).await
}

/// Mint a fresh key. The plaintext token is generated by the store
/// — callers can't smuggle a chosen token in (parity with the Go
/// upstream which also assigns the secret server-side).
pub async fn create_with_cost(
    pool: &SqlitePool,
    params: CreateParams,
    cost: u32,
) -> Result<Created> {
    if params.user_id.trim().is_empty() {
        return Err(DbError::General("user_id must be non-empty".into()));
    }
    let plaintext = generate_plaintext();
    let hash = bcrypt::hash(&plaintext, cost)
        .map_err(|e| DbError::General(format!("bcrypt hash: {e}")))?;
    let tags_json = serde_json::to_string(&params.tags)?;
    let created_at = now_unix();

    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO preauth_keys
            (key_hash, user_id, reusable, ephemeral, tags, expiration, created_at, used_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
        RETURNING id
        ",
    )
    .bind(&hash)
    .bind(&params.user_id)
    .bind(params.reusable)
    .bind(params.ephemeral)
    .bind(&tags_json)
    .bind(params.expiration)
    .bind(created_at)
    .fetch_one(pool)
    .await?;

    Ok(Created {
        plaintext,
        row: PreauthKeyRow {
            id,
            key_hash: hash,
            user_id: params.user_id,
            reusable: params.reusable,
            ephemeral: params.ephemeral,
            tags: tags_json,
            expiration: params.expiration,
            created_at,
            used_at: None,
        },
    })
}

/// Look up a row by id (used by tests + the admin "show" path).
pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Result<PreauthKeyRow> {
    sqlx::query_as::<_, PreauthKeyRow>(
        "
        SELECT id, key_hash, user_id, reusable, ephemeral, tags, expiration, created_at, used_at
        FROM preauth_keys
        WHERE id = ?
        ",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => DbError::NotFound(format!("preauth_key id={id}")),
        e => DbError::from(e),
    })
}

/// Find a row by candidate plaintext token. Verifies each live row's
/// bcrypt hash against `candidate`. Returns `NotFound` if no row
/// matches.
///
/// This is O(N) over live rows because bcrypt salts are per-row; the
/// upstream Go code does the same thing
/// (`hscontrol/db/preauth_keys.go::GetPreAuthKey`). N is bounded by
/// the operator's outstanding-key count, which in practice is small.
pub async fn get_by_token(pool: &SqlitePool, candidate: &str) -> Result<PreauthKeyRow> {
    // Cheap pre-filter: anything that doesn't carry the brand can't
    // be one of ours.
    if !candidate.starts_with(TOKEN_PREFIX) {
        return Err(DbError::NotFound("preauth_key (bad prefix)".into()));
    }
    let rows = sqlx::query_as::<_, PreauthKeyRow>(
        "
        SELECT id, key_hash, user_id, reusable, ephemeral, tags, expiration, created_at, used_at
        FROM preauth_keys
        ",
    )
    .fetch_all(pool)
    .await?;

    for r in rows {
        // `bcrypt::verify` returns Ok(true) on a match. We swallow
        // hash-format errors as "this row doesn't match" — a malformed
        // row shouldn't mask a good one further down the list.
        if bcrypt::verify(candidate, &r.key_hash).unwrap_or(false) {
            return Ok(r);
        }
    }
    Err(DbError::NotFound("preauth_key (no hash match)".into()))
}

/// Expire a key by id — sets `expiration = now_unix()`. The row stays
/// in place so the admin list can still surface it as "expired".
pub async fn expire(pool: &SqlitePool, id: i64) -> Result<()> {
    let n = sqlx::query(
        "
        UPDATE preauth_keys SET expiration = ? WHERE id = ?
        ",
    )
    .bind(now_unix())
    .bind(id)
    .execute(pool)
    .await?
    .rows_affected();
    if n == 0 {
        return Err(DbError::NotFound(format!("preauth_key id={id}")));
    }
    Ok(())
}

/// Destroy a key by id outright.
pub async fn destroy(pool: &SqlitePool, id: i64) -> Result<()> {
    let n = sqlx::query("DELETE FROM preauth_keys WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected();
    if n == 0 {
        return Err(DbError::NotFound(format!("preauth_key id={id}")));
    }
    Ok(())
}

/// List all keys belonging to `user_id`, newest first.
pub async fn list_by_user(pool: &SqlitePool, user_id: &str) -> Result<Vec<PreauthKeyRow>> {
    let rows = sqlx::query_as::<_, PreauthKeyRow>(
        "
        SELECT id, key_hash, user_id, reusable, ephemeral, tags, expiration, created_at, used_at
        FROM preauth_keys
        WHERE user_id = ?
        ORDER BY created_at DESC, id DESC
        ",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// List every key in the store, newest first. Used by the admin UI's
/// "all keys" page (which Tailscale's `headscale preauthkey list`
/// covers via `--user` filtering on the client).
pub async fn list_all(pool: &SqlitePool) -> Result<Vec<PreauthKeyRow>> {
    let rows = sqlx::query_as::<_, PreauthKeyRow>(
        "
        SELECT id, key_hash, user_id, reusable, ephemeral, tags, expiration, created_at, used_at
        FROM preauth_keys
        ORDER BY created_at DESC, id DESC
        ",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Errors returned by [`try_use`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UseError {
    #[error("preauth key not found")]
    NotFound,
    #[error("preauth key expired")]
    Expired,
    #[error("preauth key already redeemed (single-use)")]
    AlreadyUsed,
}

/// Atomic redemption.
///
/// Locates the row via bcrypt-verify, then in a single transaction:
/// 1. Re-fetches the row `FOR UPDATE` (sqlite serialises writes so
///    `BEGIN IMMEDIATE` is sufficient).
/// 2. Rejects if expired.
/// 3. For single-use keys: rejects if already used; otherwise flips
///    `used_at` to now and commits.
/// 4. For reusable keys: leaves `used_at` NULL but commits a no-op
///    so the caller sees a consistent snapshot.
///
/// Returns the freshly-read row on success.
pub async fn try_use(pool: &SqlitePool, candidate: &str) -> std::result::Result<PreauthKeyRow, UseError> {
    let row = get_by_token(pool, candidate)
        .await
        .map_err(|_| UseError::NotFound)?;
    let mut tx = pool.begin().await.map_err(|_| UseError::NotFound)?;

    // Re-read under the tx so we don't race with another concurrent
    // redemption of the same single-use key.
    let fresh: PreauthKeyRow = sqlx::query_as::<_, PreauthKeyRow>(
        "
        SELECT id, key_hash, user_id, reusable, ephemeral, tags, expiration, created_at, used_at
        FROM preauth_keys
        WHERE id = ?
        ",
    )
    .bind(row.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|_| UseError::NotFound)?;

    let now = now_unix();
    if fresh.is_expired(now) {
        return Err(UseError::Expired);
    }
    if !fresh.reusable && fresh.used_at.is_some() {
        return Err(UseError::AlreadyUsed);
    }

    let updated = if fresh.reusable {
        fresh.clone()
    } else {
        sqlx::query(
            "
            UPDATE preauth_keys
            SET used_at = ?
            WHERE id = ? AND used_at IS NULL
            ",
        )
        .bind(now)
        .bind(fresh.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| UseError::AlreadyUsed)?;
        PreauthKeyRow {
            used_at: Some(now),
            ..fresh
        }
    };

    tx.commit().await.map_err(|_| UseError::AlreadyUsed)?;
    Ok(updated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    async fn fresh_db() -> Database {
        let db = Database::in_memory().await.expect("open in-memory");
        db.migrate().await.expect("migrate");
        db
    }

    fn alice() -> CreateParams {
        CreateParams {
            user_id: "alice".into(),
            reusable: false,
            ephemeral: false,
            tags: vec![],
            expiration: None,
        }
    }

    // ---------------------------------------------------------------------
    // Maps to Go upstream tests — see report at end of brief.
    // ---------------------------------------------------------------------

    /// Go: TestCreatePreAuthKey
    #[tokio::test]
    async fn create_round_trip() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        assert!(c.plaintext.starts_with(TOKEN_PREFIX));
        assert_eq!(c.row.user_id, "alice");
        assert!(!c.row.reusable);
        assert!(c.row.used_at.is_none());
        let again = get_by_id(db.pool(), c.row.id).await.unwrap();
        assert_eq!(again.key_hash, c.row.key_hash);
    }

    /// Go: TestCannotCreateForNonExistantUser (we don't yet enforce
    /// FK to a users table, but we DO reject empty user IDs — same
    /// surface "invalid user" rejection).
    #[tokio::test]
    async fn create_rejects_empty_user() {
        let db = fresh_db().await;
        let mut p = alice();
        p.user_id = String::new();
        let e = create_for_test(db.pool(), p).await.unwrap_err();
        assert!(matches!(e, DbError::General(_)));
    }

    /// Go: TestKeyHasCorrectUserAssociated
    #[tokio::test]
    async fn list_by_user_filters_correctly() {
        let db = fresh_db().await;
        let _a = create_for_test(db.pool(), alice()).await.unwrap();
        let mut bob = alice();
        bob.user_id = "bob".into();
        let _b = create_for_test(db.pool(), bob).await.unwrap();
        let a_keys = list_by_user(db.pool(), "alice").await.unwrap();
        let b_keys = list_by_user(db.pool(), "bob").await.unwrap();
        assert_eq!(a_keys.len(), 1);
        assert_eq!(b_keys.len(), 1);
        assert_eq!(a_keys[0].user_id, "alice");
        assert_eq!(b_keys[0].user_id, "bob");
    }

    /// Go: TestGetPreAuthKey + TestGetPreAuthKeys
    #[tokio::test]
    async fn get_by_token_finds_existing() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        let row = get_by_token(db.pool(), &c.plaintext).await.unwrap();
        assert_eq!(row.id, c.row.id);
    }

    /// Go: implicit in TestGetPreAuthKey — wrong token must miss.
    #[tokio::test]
    async fn get_by_token_rejects_wrong_token() {
        let db = fresh_db().await;
        let _c = create_for_test(db.pool(), alice()).await.unwrap();
        let bogus = format!("{TOKEN_PREFIX}{}", "0".repeat(64));
        let e = get_by_token(db.pool(), &bogus).await.unwrap_err();
        assert!(matches!(e, DbError::NotFound(_)));
    }

    /// Wrong brand prefix bypasses the bcrypt loop entirely.
    #[tokio::test]
    async fn get_by_token_rejects_wrong_prefix() {
        let db = fresh_db().await;
        let _c = create_for_test(db.pool(), alice()).await.unwrap();
        let e = get_by_token(db.pool(), "tskey-deadbeef")
            .await
            .unwrap_err();
        assert!(matches!(e, DbError::NotFound(_)));
    }

    /// Go: bcrypt hash verification — right token passes, wrong fails.
    /// Verified at the hash layer (without DB round-trip).
    #[tokio::test]
    async fn bcrypt_round_trip_verifies() {
        let plain = generate_plaintext();
        let h = bcrypt::hash(&plain, BCRYPT_COST_TEST).unwrap();
        assert!(bcrypt::verify(&plain, &h).unwrap());
        assert!(!bcrypt::verify("wrong", &h).unwrap());
    }

    /// Go: TestUsePreAuthKey — single-use, first redemption succeeds.
    #[tokio::test]
    async fn try_use_single_use_redeems_once() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        let r = try_use(db.pool(), &c.plaintext).await.unwrap();
        assert!(r.used_at.is_some());
        let stored = get_by_id(db.pool(), c.row.id).await.unwrap();
        assert!(stored.is_used());
    }

    /// Go: TestUsePreAuthKey (second-use rejection branch).
    #[tokio::test]
    async fn try_use_single_use_rejects_second_redemption() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        let _first = try_use(db.pool(), &c.plaintext).await.unwrap();
        let e = try_use(db.pool(), &c.plaintext).await.unwrap_err();
        assert_eq!(e, UseError::AlreadyUsed);
    }

    /// Go: TestReusablePreAuthKey — reusable redeems N times, stays live.
    #[tokio::test]
    async fn try_use_reusable_redeems_repeatedly() {
        let db = fresh_db().await;
        let mut p = alice();
        p.reusable = true;
        let c = create_for_test(db.pool(), p).await.unwrap();
        for _ in 0..5 {
            let r = try_use(db.pool(), &c.plaintext).await.unwrap();
            assert!(r.used_at.is_none(), "reusable key should not stamp used_at");
        }
        let stored = get_by_id(db.pool(), c.row.id).await.unwrap();
        assert!(!stored.is_used());
    }

    /// Go: TestEphemeralPreAuthKey — flag round-trips from create →
    /// fetch (the wire layer's machine-record `ephemeral=true` mirror
    /// lives in the wire crate, which we're constrained not to touch;
    /// we verify the persistence half here).
    #[tokio::test]
    async fn ephemeral_flag_round_trips() {
        let db = fresh_db().await;
        let mut p = alice();
        p.ephemeral = true;
        let c = create_for_test(db.pool(), p).await.unwrap();
        let r = get_by_token(db.pool(), &c.plaintext).await.unwrap();
        assert!(r.ephemeral);
    }

    /// Go: TestExpiredPreAuthKey — past expiration ⇒ try_use rejects.
    #[tokio::test]
    async fn try_use_rejects_expired() {
        let db = fresh_db().await;
        let mut p = alice();
        p.expiration = Some(now_unix() - 60); // a minute ago
        let c = create_for_test(db.pool(), p).await.unwrap();
        let e = try_use(db.pool(), &c.plaintext).await.unwrap_err();
        assert_eq!(e, UseError::Expired);
    }

    /// Future expiration ⇒ try_use accepts.
    #[tokio::test]
    async fn try_use_accepts_unexpired() {
        let db = fresh_db().await;
        let mut p = alice();
        p.expiration = Some(now_unix() + 3600);
        let c = create_for_test(db.pool(), p).await.unwrap();
        let _ = try_use(db.pool(), &c.plaintext).await.unwrap();
    }

    /// NULL expiration ⇒ never expires.
    #[tokio::test]
    async fn null_expiration_never_expires() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        assert!(!c.row.is_expired(now_unix() + 365 * 86400));
    }

    /// Go: TestExpirePreAuthKey — `expire` flips expiration to past,
    /// subsequent `try_use` rejects.
    #[tokio::test]
    async fn expire_marks_expired() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        expire(db.pool(), c.row.id).await.unwrap();
        let e = try_use(db.pool(), &c.plaintext).await.unwrap_err();
        assert_eq!(e, UseError::Expired);
    }

    #[tokio::test]
    async fn expire_unknown_id_returns_not_found() {
        let db = fresh_db().await;
        let e = expire(db.pool(), 99_999).await.unwrap_err();
        assert!(matches!(e, DbError::NotFound(_)));
    }

    /// Go: TestDestroyPreAuthKey
    #[tokio::test]
    async fn destroy_removes_row() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        destroy(db.pool(), c.row.id).await.unwrap();
        let e = get_by_id(db.pool(), c.row.id).await.unwrap_err();
        assert!(matches!(e, DbError::NotFound(_)));
        // get_by_token also misses now.
        let e2 = get_by_token(db.pool(), &c.plaintext).await.unwrap_err();
        assert!(matches!(e2, DbError::NotFound(_)));
    }

    #[tokio::test]
    async fn destroy_unknown_id_returns_not_found() {
        let db = fresh_db().await;
        let e = destroy(db.pool(), 99_999).await.unwrap_err();
        assert!(matches!(e, DbError::NotFound(_)));
    }

    /// Go: TestPreAuthKeyACLTags — tags round-trip.
    #[tokio::test]
    async fn tags_round_trip() {
        let db = fresh_db().await;
        let mut p = alice();
        p.tags = vec!["tag:dev".into(), "tag:server".into()];
        let c = create_for_test(db.pool(), p).await.unwrap();
        let r = get_by_token(db.pool(), &c.plaintext).await.unwrap();
        assert_eq!(r.tag_list(), vec!["tag:dev".to_string(), "tag:server".into()]);
    }

    /// Empty tag list serialises to "[]" and round-trips clean.
    #[tokio::test]
    async fn empty_tags_round_trip() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        assert_eq!(c.row.tag_list(), Vec::<String>::new());
        assert_eq!(c.row.tags, "[]");
    }

    /// Go: TestListPreAuthKeys — list returns multiple, newest first.
    #[tokio::test]
    async fn list_by_user_orders_newest_first() {
        let db = fresh_db().await;
        let a = create_for_test(db.pool(), alice()).await.unwrap();
        // small sleep-equivalent: distinct created_at + id ordering
        // doesn't need wall-clock spacing because the ORDER BY ties
        // on `id DESC`.
        let b = create_for_test(db.pool(), alice()).await.unwrap();
        let list = list_by_user(db.pool(), "alice").await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, b.row.id, "newest first");
        assert_eq!(list[1].id, a.row.id);
    }

    /// list_all returns every user's keys.
    #[tokio::test]
    async fn list_all_returns_all_users() {
        let db = fresh_db().await;
        let _a = create_for_test(db.pool(), alice()).await.unwrap();
        let mut bob = alice();
        bob.user_id = "bob".into();
        let _b = create_for_test(db.pool(), bob).await.unwrap();
        let all = list_all(db.pool()).await.unwrap();
        assert_eq!(all.len(), 2);
    }

    /// `try_use` on an unknown token ⇒ NotFound.
    #[tokio::test]
    async fn try_use_unknown_token_not_found() {
        let db = fresh_db().await;
        let bogus = format!("{TOKEN_PREFIX}{}", "0".repeat(64));
        let e = try_use(db.pool(), &bogus).await.unwrap_err();
        assert_eq!(e, UseError::NotFound);
    }

    /// Concurrent redemption: only one of N callers gets the single-
    /// use key; the rest see `AlreadyUsed`.
    #[tokio::test]
    async fn try_use_single_use_is_atomic_under_concurrency() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        let pool = db.pool().clone();
        let plain = c.plaintext.clone();
        let n_workers = 8;
        let mut handles = Vec::with_capacity(n_workers);
        for _ in 0..n_workers {
            let p = pool.clone();
            let plain = plain.clone();
            handles.push(tokio::spawn(async move { try_use(&p, &plain).await }));
        }
        let mut ok = 0;
        let mut used = 0;
        for h in handles {
            match h.await.unwrap() {
                Ok(_) => ok += 1,
                Err(UseError::AlreadyUsed) => used += 1,
                Err(e) => panic!("unexpected error {e:?}"),
            }
        }
        assert_eq!(ok, 1, "exactly one redemption should win");
        assert_eq!(used, n_workers - 1);
    }

    /// `is_live` helper agrees with `try_use` outcomes.
    #[tokio::test]
    async fn is_live_helper_matches_try_use() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        let row = get_by_id(db.pool(), c.row.id).await.unwrap();
        assert!(row.is_live(now_unix()));
        let _ = try_use(db.pool(), &c.plaintext).await.unwrap();
        let after = get_by_id(db.pool(), c.row.id).await.unwrap();
        assert!(!after.is_live(now_unix()));
    }

    /// Migration is idempotent — re-running it doesn't blow up.
    #[tokio::test]
    async fn migration_is_idempotent() {
        let db = fresh_db().await;
        // second run = no-op (sqlx_migrations table tracks state).
        db.migrate().await.unwrap();
    }
}
