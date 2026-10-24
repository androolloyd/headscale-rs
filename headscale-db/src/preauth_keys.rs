//! Pre-auth key persistence — sqlx-backed store mirroring
//! `juanfont/headscale@v0.29.5:hscontrol/db/preauth_keys.go`.
//!
//! ## Surface
//!
//! * [`create`] — mint a new token, return the plaintext + the row.
//! * [`get_by_token`] — parse the modern key prefix or legacy
//!   plaintext, bcrypt-verify the secret, and return the row.
//! * [`expire`] — set `expiration` to now, leaving the row in place.
//! * [`destroy`] — clear assigned nodes, then delete the row outright.
//! * [`list_by_user`] — admin listing per user (oldest first).
//! * [`try_use`] — atomic single-use redemption: validate the credential,
//!   then claim `used = false` for a one-shot key. SQL NULL is not false;
//!   `used_at` is a projection of the stored Used bit.
//!
//! ## Token shape
//!
//! Wire format is `hskey-auth-<12 urlsafe chars>-<64 urlsafe chars>`,
//! matching headscale-go v0.28.0. Octra-specific callers should adapt
//! at the Octra boundary instead of changing this upstream-compatible
//! store.
//!
//! ## Bcrypt cost
//!
//! Defaults to [`BCRYPT_COST_DEFAULT`] in production. Unit tests opt
//! into [`BCRYPT_COST_TEST`] (the bcrypt-crate minimum, 4) via
//! [`create_with_cost`] / [`create_for_test`] so the suite finishes
//! in under a second.

use crate::{DbError, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, SqliteConnection, SqlitePool};
#[cfg(feature = "postgres-sqlx")]
use sqlx::{PgConnection, PgPool};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) mod timestamp;

/// Brand prefix on the plaintext bearer token.
pub const TOKEN_PREFIX: &str = "hskey-auth-";
pub const TOKEN_PREFIX_LEN: usize = 12;
pub const TOKEN_SECRET_LEN: usize = 64;

/// Production bcrypt cost, matching headscale-go's `bcrypt.DefaultCost`.
pub const BCRYPT_COST_DEFAULT: u32 = 10;

/// Cheap bcrypt cost for unit tests — the crate's minimum (4). Keeps
/// the 20+ test suite under a couple of seconds total. `bcrypt::hash`
/// rejects costs below 4 with `BcryptError::CostNotAllowed`.
pub const BCRYPT_COST_TEST: u32 = 4;

const GO_ZERO_TIME_UNIX_SECONDS: i64 = -62_135_596_800;

const AUTH_KEY_PARSE_ERROR: &str = "failed to parse auth-key";
const PREAUTH_KEY_COLUMNS: &str = r"
        id,
        key,
        prefix,
        hash AS key_hash,
        COALESCE(CAST(user_id AS TEXT), '') AS user_id,
        COALESCE(reusable, false) AS reusable,
        COALESCE(ephemeral, false) AS ephemeral,
        COALESCE(tags, '[]') AS tags,
        CASE
            WHEN expiration IS NULL THEN NULL
            WHEN typeof(expiration) = 'integer' THEN expiration
            ELSE unixepoch(expiration)
        END AS expiration,
        json_array(
            CASE WHEN typeof(expiration) = 'integer' AND EXISTS (
                SELECT 1 FROM main.sqlite_master
                WHERE type = 'table' AND name = '_sqlx_migrations'
            ) THEN 'legacy_integer' ELSE typeof(expiration) END,
            CASE WHEN typeof(expiration) = 'blob' THEN NULL ELSE CAST(expiration AS TEXT) END,
            (SELECT cid FROM pragma_table_info('pre_auth_keys') WHERE name = 'expiration'),
            'expiration'
        ) AS expiration_text,
        CASE
            WHEN created_at IS NULL THEN 0
            WHEN typeof(created_at) = 'integer' THEN created_at
            ELSE unixepoch(created_at)
        END AS created_at,
        COALESCE(CAST(created_at AS TEXT), '') AS created_at_text,
        CASE
            WHEN used THEN COALESCE(
                CASE
                    WHEN expiration IS NULL THEN NULL
                    WHEN typeof(expiration) = 'integer' THEN expiration
                    ELSE unixepoch(expiration)
                END,
                CASE
                    WHEN created_at IS NULL THEN 0
                    WHEN typeof(created_at) = 'integer' THEN created_at
                    ELSE unixepoch(created_at)
                END
            )
            ELSE NULL
        END AS used_at
";

pub(crate) fn preauth_key_select(suffix: &str) -> String {
    format!("SELECT {PREAUTH_KEY_COLUMNS} FROM pre_auth_keys {suffix}")
}

#[cfg(feature = "postgres-sqlx")]
const POSTGRES_PREAUTH_KEY_COLUMNS: &str = r#"
        id,
        key,
        prefix,
        hash AS key_hash,
        COALESCE(user_id::TEXT, '') AS user_id,
        COALESCE(reusable, false) AS reusable,
        COALESCE(ephemeral, false) AS ephemeral,
        COALESCE(tags, '[]') AS tags,
        FLOOR(EXTRACT(EPOCH FROM expiration))::BIGINT AS expiration,
        to_char(expiration AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS expiration_text,
        COALESCE(FLOOR(EXTRACT(EPOCH FROM created_at))::BIGINT, 0) AS created_at,
        COALESCE(to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '') AS created_at_text,
        CASE
            WHEN used THEN COALESCE(
                FLOOR(EXTRACT(EPOCH FROM expiration))::BIGINT,
                COALESCE(FLOOR(EXTRACT(EPOCH FROM created_at))::BIGINT, 0)
            )
            ELSE NULL
        END AS used_at
"#;

#[cfg(feature = "postgres-sqlx")]
pub(crate) fn postgres_preauth_key_select(suffix: &str) -> String {
    format!("SELECT {POSTGRES_PREAUTH_KEY_COLUMNS} FROM pre_auth_keys {suffix}")
}

/// One pre-auth-key row in the DB. Mirrors the Go upstream's
/// `hscontrol/types/preauth_key.go::PreAuthKey` fields while keeping
/// Unix-second timestamps at the Rust boundary.
#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreauthKeyRow {
    pub id: i64,
    pub key: Option<String>,
    pub prefix: Option<String>,
    #[sqlx(try_from = "crate::stored_hash::HashColumn")]
    pub key_hash: String,
    pub user_id: String,
    pub reusable: bool,
    pub ephemeral: bool,
    /// JSON-encoded Go string slice. SQL reads validate the encoding; use
    /// [`PreauthKeyRow::try_tag_list`] for fallible credential decisions.
    #[sqlx(try_from = "crate::stored_json::StringListColumn")]
    pub tags: String,
    /// Unix-seconds. `None` ⇒ never expires.
    pub expiration: Option<i64>,
    #[sqlx(try_from = "timestamp::ExpirationColumn")]
    pub expiration_text: Option<String>,
    pub created_at: i64,
    pub created_at_text: String,
    /// Unix-seconds. `None` ⇒ unused.
    pub used_at: Option<i64>,
}

impl PreauthKeyRow {
    pub fn display_key(&self) -> String {
        if let Some(prefix) = self.prefix.as_deref().filter(|prefix| !prefix.is_empty()) {
            format!("{TOKEN_PREFIX}{prefix}-***")
        } else if let Some(key) = &self.key {
            key.clone()
        } else {
            String::new()
        }
    }

    /// Convenience for validated SQL rows. Manually constructed rows needing
    /// an authorization decision must use try_tag_list instead.
    pub fn tag_list(&self) -> Vec<String> {
        self.try_tag_list().unwrap_or_default()
    }

    /// Decode credential tags without treating malformed data as untagged.
    pub fn try_tag_list(&self) -> Result<Vec<String>> {
        crate::stored_json::string_list(&self.tags)
    }

    /// True iff the row is past its `expiration` (using the supplied
    /// "now" — callers pass `now_unix()` in production; tests can
    /// inject a fixed clock).
    pub fn is_expired(&self, now_unix: i64) -> bool {
        parse_database_timestamp(self.expiration, self.expiration_text.as_deref())
            .map(|expiry| expiry.timestamp())
            .or(self.expiration)
            .is_some_and(|expiry| expiry < now_unix)
    }

    /// Production validation retains the stored fractional-second deadline.
    pub fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        parse_database_timestamp(self.expiration, self.expiration_text.as_deref())
            .is_some_and(|expiry| expiry < now)
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

/// Nodes disable expiry at Go's zero time; preauth keys do not.
pub(crate) fn node_timestamp_is_expired(
    seconds: Option<i64>,
    raw: Option<&str>,
    now: DateTime<Utc>,
) -> bool {
    parse_database_timestamp(seconds, raw).is_some_and(|expiry| {
        (expiry.timestamp() != GO_ZERO_TIME_UNIX_SECONDS || expiry.timestamp_subsec_nanos() != 0)
            && expiry < now
    })
}

pub(crate) fn parse_database_timestamp(
    seconds: Option<i64>,
    raw: Option<&str>,
) -> Option<DateTime<Utc>> {
    // Other callers still project legacy integer columns as decimal text.
    // Credential row decoding canonicalizes those integers before this point;
    // do not reinterpret a node's integer seconds as a compact calendar date.
    if raw.is_some_and(|raw| raw.parse::<i64>().is_ok())
        && let Some(seconds) = seconds
    {
        return DateTime::from_timestamp(seconds, 0);
    }
    raw.and_then(timestamp::parse_text)
        .or_else(|| seconds.and_then(|seconds| DateTime::from_timestamp(seconds, 0)))
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

/// Result of [`create`]: the original insert projection + the plaintext token
/// that the caller must hand back to the device (the row in the DB
/// never holds plaintext, so this is the *only* time the secret
/// exists outside the device's pocket). The projection retains pre-insert
/// timestamp precision, as Go does, even when SQL stores fewer fractional digits.
#[derive(Debug, Clone)]
pub struct Created {
    pub plaintext: String,
    pub row: PreauthKeyRow,
}

/// User loaded within the same transaction as the minted key.
#[derive(Debug, Clone)]
pub struct CreatedWithUser {
    pub created: Created,
    pub user: Option<crate::users::UserRow>,
}

/// A database association preload, including a known missing user.
#[derive(Debug, Clone)]
pub struct PreauthKeyWithUser {
    pub key: PreauthKeyRow,
    pub user: Option<crate::users::UserRow>,
}

/// Verified credential and original SQL association material for one fresh
/// registration. It is deliberately neither Debug nor Serialize and must not
/// be retained in the node cache; Hash/legacy Key are credential material.
#[derive(Clone)]
pub struct RegistrationKey {
    pub key: PreauthKeyRow,
    pub hash: Option<Vec<u8>>,
    pub tags_nil: bool,
    pub user: Option<crate::users::UserWriteSnapshot>,
}

impl RegistrationKey {
    pub fn into_loaded(self) -> PreauthKeyWithUser {
        PreauthKeyWithUser {
            key: self.key,
            user: self.user.map(|user| user.row),
        }
    }
}

#[derive(sqlx::FromRow)]
struct RegistrationKeyRow {
    #[sqlx(flatten)]
    key: PreauthKeyRow,
    association_hash: Option<Vec<u8>>,
    association_tags: Option<String>,
}

fn registration_key_select(suffix: &str) -> String {
    format!(
        "SELECT {PREAUTH_KEY_COLUMNS}, CAST(hash AS BLOB) AS association_hash, tags AS association_tags FROM pre_auth_keys {suffix}"
    )
}

#[cfg(feature = "postgres-sqlx")]
fn postgres_registration_key_select(suffix: &str) -> String {
    format!(
        "SELECT {POSTGRES_PREAUTH_KEY_COLUMNS}, hash AS association_hash, tags AS association_tags FROM pre_auth_keys {suffix}"
    )
}

impl RegistrationKeyRow {
    fn tags_nil(&self) -> bool {
        self.association_tags.as_deref().is_none_or(|tags| {
            let tags = crate::go_json::trim(tags.as_bytes());
            tags.is_empty() || tags == b"null"
        })
    }
}

pub async fn get_by_token_for_registration(
    pool: &SqlitePool,
    candidate: &str,
) -> Result<RegistrationKey> {
    let parsed = parse_auth_key(candidate)?;
    let (predicate, value) = match parsed {
        ParsedAuthKey::Modern { prefix, .. } => ("prefix = ?", prefix),
        ParsedAuthKey::Legacy { key } => ("key = ?", key),
    };
    let (row, user) = {
        let mut connection = pool.acquire().await?;
        let query = registration_key_select(&format!("WHERE {predicate} ORDER BY id ASC LIMIT 1"));
        let row = sqlx::query_as::<_, RegistrationKeyRow>(&query)
            .bind(value)
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| DbError::NotFound("preauth_key".into()))?;
        let user = if let Some(id) =
            association_user_id(&row.key).map_err(|_| DbError::NotFound("preauth_key".into()))?
        {
            match crate::users::get_for_registration_on_connection(&mut connection, id).await {
                Ok(user) => Some(user),
                Err(DbError::NotFound(_)) => None,
                Err(_) => return Err(DbError::NotFound("preauth_key".into())),
            }
        } else {
            None
        };
        (row, user)
    };
    let tags_nil = row.tags_nil();
    let key = verify_candidate(
        row.key,
        candidate,
        row.association_hash.as_deref().unwrap_or_default(),
    )
    .await?;
    Ok(RegistrationKey {
        key,
        hash: row.association_hash,
        tags_nil,
        user,
    })
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_token_for_registration(
    pool: &PgPool,
    candidate: &str,
) -> Result<RegistrationKey> {
    let parsed = parse_auth_key(candidate)?;
    let (predicate, value) = match parsed {
        ParsedAuthKey::Modern { prefix, .. } => ("prefix = $1", prefix),
        ParsedAuthKey::Legacy { key } => ("key = $1", key),
    };
    let (row, user) = {
        let mut connection = pool.acquire().await?;
        let query =
            postgres_registration_key_select(&format!("WHERE {predicate} ORDER BY id ASC LIMIT 1"));
        let row = sqlx::query_as::<_, RegistrationKeyRow>(&query)
            .bind(value)
            .fetch_one(&mut *connection)
            .await
            .map_err(|_| DbError::NotFound("preauth_key".into()))?;
        let user = if let Some(id) =
            association_user_id(&row.key).map_err(|_| DbError::NotFound("preauth_key".into()))?
        {
            match crate::users::get_postgres_for_registration_on_connection(&mut connection, id)
                .await
            {
                Ok(user) => Some(user),
                Err(DbError::NotFound(_)) => None,
                Err(_) => return Err(DbError::NotFound("preauth_key".into())),
            }
        } else {
            None
        };
        (row, user)
    };
    let tags_nil = row.tags_nil();
    let key = verify_candidate(
        row.key,
        candidate,
        row.association_hash.as_deref().unwrap_or_default(),
    )
    .await?;
    Ok(RegistrationKey {
        key,
        hash: row.association_hash,
        tags_nil,
        user,
    })
}

/// Current wall-clock as unix-seconds.
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn is_valid_urlsafe_bytes(bytes: &[u8]) -> bool {
    bytes
        .iter()
        .copied()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn normalize_acl_tags(mut tags: Vec<String>) -> Result<Vec<String>> {
    tags.sort();
    tags.dedup();

    if let Some(tag) = tags.iter().find(|tag| !tag.starts_with("tag:")) {
        return Err(DbError::General(format!(
            "auth-key tag is invalid: '{tag}' did not begin with 'tag:'"
        )));
    }

    Ok(tags)
}

/// Generate a fresh `hskey-auth-<12>-<64>` plaintext token.
pub fn generate_plaintext() -> String {
    let (plaintext, _, _) =
        generate_plaintext_parts().expect("OS entropy for preauth key generation");
    plaintext
}

fn generate_plaintext_parts() -> Result<(String, String, String)> {
    let prefix = crate::credential_entropy::urlsafe(TOKEN_PREFIX_LEN)?;
    let secret = crate::credential_entropy::urlsafe(TOKEN_SECRET_LEN)?;
    let key = format!("{TOKEN_PREFIX}{prefix}-{secret}");
    Ok((key, prefix, secret))
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
    create_with_cost_precise(pool, params, cost, None).await
}

/// Preserve the fractional timestamp supplied by the upstream gRPC API.
pub async fn create_with_cost_precise(
    pool: &SqlitePool,
    params: CreateParams,
    cost: u32,
    expiration_precise: Option<DateTime<Utc>>,
) -> Result<Created> {
    create_with_cost_precise_inner(pool, params, cost, expiration_precise, false)
        .await
        .map(|result| result.created)
}

/// Retain the user loaded in the key-creation transaction for API projection.
pub async fn create_with_cost_precise_with_user(
    pool: &SqlitePool,
    params: CreateParams,
    cost: u32,
    expiration_precise: Option<DateTime<Utc>>,
) -> Result<CreatedWithUser> {
    create_with_cost_precise_inner(pool, params, cost, expiration_precise, false).await
}

/// Mint for a numeric upstream owner without falling back to a same-named user.
pub async fn create_with_cost_precise_for_user_id(
    pool: &SqlitePool,
    params: CreateParams,
    cost: u32,
    expiration_precise: Option<DateTime<Utc>>,
) -> Result<CreatedWithUser> {
    create_with_cost_precise_inner(pool, params, cost, expiration_precise, true).await
}

async fn create_with_cost_precise_inner(
    pool: &SqlitePool,
    params: CreateParams,
    cost: u32,
    expiration_precise: Option<DateTime<Utc>>,
    strict_user_id: bool,
) -> Result<CreatedWithUser> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    if strict_user_id && params.user_id.is_empty() && params.tags.is_empty() {
        return Err(DbError::General(
            "auth-key must be either tagged or owned by user".into(),
        ));
    }
    let user_snapshot = if strict_user_id && !params.user_id.is_empty() {
        let id = params
            .user_id
            .parse::<i64>()
            .map_err(|_| DbError::General("user id out of range".into()))?;
        Some(crate::users::get_for_registration_on_connection(&mut tx, id).await?)
    } else {
        resolve_registration_user_on_connection(&mut tx, &params.user_id).await?
    };
    let storage_user_id = user_snapshot.as_ref().map(|user| user.row.id);
    let tags = normalize_acl_tags(params.tags)?;
    if storage_user_id.is_none() && tags.is_empty() {
        return Err(DbError::General(
            "user_id must be non-empty unless tags are provided".into(),
        ));
    }
    let created_time = Utc::now();
    let (plaintext, prefix, secret) = generate_plaintext_parts()?;
    let hash = crate::credential_hash::hash(secret, cost)
        .await
        .map_err(DbError::General)?;
    let user = match user_snapshot {
        Some(user) => Some(
            crate::headscale_nodes::save_captured_user(&mut tx, user)
                .await
                .map_err(creating_key_in_database)?
                .row,
        ),
        None => None,
    };
    let storage_user_id = user.as_ref().map(|user| user.id);
    let tags_json = crate::stored_json::text_for_write(&tags)?;
    let created_at = created_time.to_rfc3339_opts(SecondsFormat::Nanos, true);
    let expiration_time = expiration_precise.or_else(|| {
        params
            .expiration
            .and_then(|value| DateTime::from_timestamp(value, 0))
    });
    let expiration = expiration_time.map(|value| value.to_rfc3339_opts(SecondsFormat::Nanos, true));

    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO pre_auth_keys
            (key, prefix, hash, user_id, reusable, ephemeral, used, tags, expiration, created_at)
        VALUES (
            '',
            ?,
            ?,
            ?,
            ?,
            ?,
            false,
            ?,
            ?,
            ?
        )
        RETURNING id
        ",
    )
    .bind(&prefix)
    .bind(hash.as_bytes())
    .bind(storage_user_id)
    .bind(params.reusable)
    .bind(params.ephemeral)
    .bind(&tags_json)
    .bind(expiration)
    .bind(created_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(creating_key_in_database)?;

    let created = Created {
        plaintext,
        row: PreauthKeyRow {
            id,
            key: Some(String::new()),
            prefix: Some(prefix),
            key_hash: hash,
            user_id: storage_user_id.map(|id| id.to_string()).unwrap_or_default(),
            reusable: params.reusable,
            ephemeral: params.ephemeral,
            tags: tags_json,
            expiration: expiration_time.map(|stamp| stamp.timestamp()),
            expiration_text: expiration_time
                .map(|stamp| stamp.to_rfc3339_opts(SecondsFormat::Nanos, true)),
            created_at: created_time.timestamp(),
            created_at_text: created_time.to_rfc3339_opts(SecondsFormat::Nanos, true),
            used_at: None,
        },
    };
    tx.commit().await?;
    Ok(CreatedWithUser { created, user })
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres(pool: &PgPool, params: CreateParams) -> Result<Created> {
    create_postgres_with_cost(pool, params, BCRYPT_COST_DEFAULT).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_for_test(pool: &PgPool, params: CreateParams) -> Result<Created> {
    create_postgres_with_cost(pool, params, BCRYPT_COST_TEST).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_with_cost(
    pool: &PgPool,
    params: CreateParams,
    cost: u32,
) -> Result<Created> {
    let mut conn = pool.acquire().await?;
    create_postgres_with_cost_on_connection(&mut conn, params, cost).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_for_test_on_connection(
    conn: &mut PgConnection,
    params: CreateParams,
) -> Result<Created> {
    create_postgres_with_cost_on_connection(conn, params, BCRYPT_COST_TEST).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_with_cost_on_connection(
    conn: &mut PgConnection,
    params: CreateParams,
    cost: u32,
) -> Result<Created> {
    create_postgres_with_cost_precise_on_connection(conn, params, cost, None, false)
        .await
        .map(|result| result.created)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_with_cost_precise(
    pool: &PgPool,
    params: CreateParams,
    cost: u32,
    expiration_precise: Option<DateTime<Utc>>,
) -> Result<Created> {
    let mut conn = pool.acquire().await?;
    create_postgres_with_cost_precise_on_connection(
        &mut conn,
        params,
        cost,
        expiration_precise,
        false,
    )
    .await
    .map(|result| result.created)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_with_cost_precise_with_user(
    pool: &PgPool,
    params: CreateParams,
    cost: u32,
    expiration_precise: Option<DateTime<Utc>>,
) -> Result<CreatedWithUser> {
    let mut conn = pool.acquire().await?;
    create_postgres_with_cost_precise_on_connection(
        &mut conn,
        params,
        cost,
        expiration_precise,
        false,
    )
    .await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_with_cost_precise_for_user_id(
    pool: &PgPool,
    params: CreateParams,
    cost: u32,
    expiration_precise: Option<DateTime<Utc>>,
) -> Result<CreatedWithUser> {
    let mut conn = pool.acquire().await?;
    create_postgres_with_cost_precise_on_connection(
        &mut conn,
        params,
        cost,
        expiration_precise,
        true,
    )
    .await
}

#[cfg(feature = "postgres-sqlx")]
async fn create_postgres_with_cost_precise_on_connection(
    conn: &mut PgConnection,
    params: CreateParams,
    cost: u32,
    expiration_precise: Option<DateTime<Utc>>,
    strict_user_id: bool,
) -> Result<CreatedWithUser> {
    let mut tx = conn.begin().await?;
    if strict_user_id && params.user_id.is_empty() && params.tags.is_empty() {
        return Err(DbError::General(
            "auth-key must be either tagged or owned by user".into(),
        ));
    }
    let user_snapshot = if strict_user_id && !params.user_id.is_empty() {
        let id = params
            .user_id
            .parse::<i64>()
            .map_err(|_| DbError::General("user id out of range".into()))?;
        Some(crate::users::get_postgres_for_registration_on_connection(&mut tx, id).await?)
    } else {
        resolve_postgres_registration_user_on_connection(&mut tx, &params.user_id).await?
    };
    let storage_user_id = user_snapshot.as_ref().map(|user| user.row.id);
    let tags = normalize_acl_tags(params.tags)?;
    if storage_user_id.is_none() && tags.is_empty() {
        return Err(DbError::General(
            "user_id must be non-empty unless tags are provided".into(),
        ));
    }
    let created_time = Utc::now();
    let (plaintext, prefix, secret) = generate_plaintext_parts()?;
    let hash = crate::credential_hash::hash(secret, cost)
        .await
        .map_err(DbError::General)?;
    let user = match user_snapshot {
        Some(user) => Some(
            crate::headscale_nodes::save_postgres_captured_user(&mut tx, user)
                .await
                .map_err(creating_key_in_database)?
                .row,
        ),
        None => None,
    };
    let storage_user_id = user.as_ref().map(|user| user.id);
    let tags_json = crate::stored_json::text_for_write(&tags)?;
    let created_at = created_time.to_rfc3339_opts(SecondsFormat::Micros, true);
    let expiration_time = expiration_precise.or_else(|| {
        params
            .expiration
            .and_then(|value| DateTime::from_timestamp(value, 0))
    });
    let expiration =
        expiration_time.map(|value| value.to_rfc3339_opts(SecondsFormat::Micros, true));

    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO pre_auth_keys
            (key, prefix, hash, user_id, reusable, ephemeral, used, tags, expiration, created_at)
        VALUES (
            '',
            $1,
            $2,
            $3,
            $4,
            $5,
            false,
            $6,
            $7::TIMESTAMPTZ,
            $8::TIMESTAMPTZ
        )
        RETURNING id
        ",
    )
    .bind(&prefix)
    .bind(hash.as_bytes())
    .bind(storage_user_id)
    .bind(params.reusable)
    .bind(params.ephemeral)
    .bind(&tags_json)
    .bind(expiration)
    .bind(created_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(creating_key_in_database)?;

    let created = Created {
        plaintext,
        row: PreauthKeyRow {
            id,
            key: Some(String::new()),
            prefix: Some(prefix),
            key_hash: hash,
            user_id: storage_user_id.map(|id| id.to_string()).unwrap_or_default(),
            reusable: params.reusable,
            ephemeral: params.ephemeral,
            tags: tags_json,
            expiration: expiration_time.map(|stamp| stamp.timestamp()),
            expiration_text: expiration_time
                .map(|stamp| stamp.to_rfc3339_opts(SecondsFormat::Nanos, true)),
            created_at: created_time.timestamp(),
            created_at_text: created_time.to_rfc3339_opts(SecondsFormat::Nanos, true),
            used_at: None,
        },
    };
    tx.commit().await?;
    Ok(CreatedWithUser { created, user })
}

async fn resolve_storage_user_id(pool: &SqlitePool, selector: &str) -> Result<Option<i64>> {
    let mut conn = pool.acquire().await?;
    Ok(resolve_storage_user_on_connection(&mut conn, selector)
        .await?
        .map(|user| user.id))
}

async fn resolve_storage_user_on_connection(
    conn: &mut SqliteConnection,
    selector: &str,
) -> Result<Option<crate::users::UserRow>> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Ok(None);
    }
    if let Ok(id) = selector.parse::<i64>() {
        match crate::users::get_by_id_on_connection(conn, id).await {
            Ok(user) => return Ok(Some(user)),
            Err(DbError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
    }
    match crate::users::get_by_name_on_connection(conn, selector).await {
        Ok(user) => Ok(Some(user)),
        Err(DbError::NotFound(_)) => Err(DbError::Constraint(format!(
            "preauth key user {selector:?} does not exist"
        ))),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "postgres-sqlx")]
async fn resolve_postgres_storage_user_id(
    conn: &mut PgConnection,
    selector: &str,
) -> Result<Option<i64>> {
    Ok(resolve_postgres_storage_user_on_connection(conn, selector)
        .await?
        .map(|user| user.id))
}

#[cfg(feature = "postgres-sqlx")]
async fn resolve_postgres_storage_user_on_connection(
    conn: &mut PgConnection,
    selector: &str,
) -> Result<Option<crate::users::UserRow>> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Ok(None);
    }
    if let Ok(id) = selector.parse::<i64>() {
        match crate::users::get_postgres_by_id_on_connection(conn, id).await {
            Ok(user) => return Ok(Some(user)),
            Err(DbError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
    }
    match crate::users::get_postgres_by_name_on_connection(conn, selector).await {
        Ok(user) => Ok(Some(user)),
        Err(DbError::NotFound(_)) => Err(DbError::Constraint(format!(
            "preauth key user {selector:?} does not exist"
        ))),
        Err(error) => Err(error),
    }
}

async fn resolve_registration_user_on_connection(
    connection: &mut SqliteConnection,
    selector: &str,
) -> Result<Option<crate::users::UserWriteSnapshot>> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Ok(None);
    }
    if let Ok(id) = selector.parse::<i64>() {
        match crate::users::get_for_registration_on_connection(connection, id).await {
            Ok(user) => return Ok(Some(user)),
            Err(DbError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
    }
    match crate::users::get_by_name_for_registration_on_connection(connection, selector).await {
        Ok(user) => Ok(Some(user)),
        Err(DbError::NotFound(_)) => Err(DbError::Constraint(format!(
            "preauth key user {selector:?} does not exist"
        ))),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "postgres-sqlx")]
async fn resolve_postgres_registration_user_on_connection(
    connection: &mut PgConnection,
    selector: &str,
) -> Result<Option<crate::users::UserWriteSnapshot>> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Ok(None);
    }
    if let Ok(id) = selector.parse::<i64>() {
        match crate::users::get_postgres_for_registration_on_connection(connection, id).await {
            Ok(user) => return Ok(Some(user)),
            Err(DbError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
    }
    match crate::users::get_postgres_by_name_for_registration_on_connection(connection, selector)
        .await
    {
        Ok(user) => Ok(Some(user)),
        Err(DbError::NotFound(_)) => Err(DbError::Constraint(format!(
            "preauth key user {selector:?} does not exist"
        ))),
        Err(error) => Err(error),
    }
}

fn creating_key_in_database(error: impl Into<DbError>) -> DbError {
    let error = error.into();
    DbError::General(format!(
        "creating key in database: {}",
        error.headscale_go_message()
    ))
}

pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Result<PreauthKeyRow> {
    let query = preauth_key_select("WHERE id = ?");
    sqlx::query_as::<_, PreauthKeyRow>(&query)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => DbError::NotFound(format!("preauth_key id={id}")),
            e => DbError::from(e),
        })
}

/// Return the auth-key ephemeral bit after validating its stored tag list.
pub async fn is_ephemeral_by_id(pool: &SqlitePool, id: i64) -> Result<bool> {
    sqlx::query_as::<_, (bool, crate::stored_json::StringListColumn)>(
        "SELECT COALESCE(ephemeral, false), COALESCE(tags, '[]') FROM pre_auth_keys WHERE id = ?",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map(|(ephemeral, _)| ephemeral)
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => DbError::NotFound(format!("preauth_key id={id}")),
        e => DbError::from(e),
    })
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_id(pool: &PgPool, id: i64) -> Result<PreauthKeyRow> {
    let mut conn = pool.acquire().await?;
    get_postgres_by_id_on_connection(&mut conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_id_on_connection(
    conn: &mut PgConnection,
    id: i64,
) -> Result<PreauthKeyRow> {
    let query = postgres_preauth_key_select("WHERE id = $1");
    sqlx::query_as::<_, PreauthKeyRow>(&query)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => DbError::NotFound(format!("preauth_key id={id}")),
            e => DbError::from(e),
        })
}

#[cfg(feature = "postgres-sqlx")]
pub async fn is_postgres_ephemeral_by_id(pool: &PgPool, id: i64) -> Result<bool> {
    let mut conn = pool.acquire().await?;
    is_postgres_ephemeral_by_id_on_connection(&mut conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn is_postgres_ephemeral_by_id_on_connection(
    conn: &mut PgConnection,
    id: i64,
) -> Result<bool> {
    sqlx::query_as::<_, (bool, crate::stored_json::StringListColumn)>(
        "SELECT COALESCE(ephemeral, false), COALESCE(tags, '[]') FROM pre_auth_keys WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map(|(ephemeral, _)| ephemeral)
    .map_err(|e| match e {
        sqlx::Error::RowNotFound => DbError::NotFound(format!("preauth_key id={id}")),
        e => DbError::from(e),
    })
}

enum ParsedAuthKey<'a> {
    Modern { prefix: &'a str, secret: &'a str },
    Legacy { key: &'a str },
}

fn parse_auth_key(candidate: &str) -> Result<ParsedAuthKey<'_>> {
    if candidate.is_empty() {
        return Err(DbError::General(AUTH_KEY_PARSE_ERROR.into()));
    }
    if let Some((_, rest)) = candidate.split_once(TOKEN_PREFIX) {
        let expected = TOKEN_PREFIX_LEN + 1 + TOKEN_SECRET_LEN;
        if rest.len() < expected {
            return Err(DbError::General(format!(
                "{AUTH_KEY_PARSE_ERROR}: key too short, expected at least {expected} chars after prefix, got {}",
                rest.len()
            )));
        }
        let rest = rest.as_bytes();
        let prefix = &rest[..TOKEN_PREFIX_LEN];
        let separator = rest[TOKEN_PREFIX_LEN];
        if separator != b'-' {
            return Err(DbError::General(format!(
                "{AUTH_KEY_PARSE_ERROR}: expected separator '-' at position {TOKEN_PREFIX_LEN}, got '{}'",
                char::from(separator)
            )));
        }
        let secret = &rest[TOKEN_PREFIX_LEN + 1..];
        if secret.len() != TOKEN_SECRET_LEN {
            return Err(DbError::General(format!(
                "{AUTH_KEY_PARSE_ERROR}: hash length mismatch, expected {TOKEN_SECRET_LEN} chars, got {}",
                secret.len()
            )));
        }
        if !is_valid_urlsafe_bytes(prefix) {
            return Err(DbError::General(format!(
                "{AUTH_KEY_PARSE_ERROR}: prefix contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)"
            )));
        }
        if !is_valid_urlsafe_bytes(secret) {
            return Err(DbError::General(format!(
                "{AUTH_KEY_PARSE_ERROR}: hash contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)"
            )));
        }
        let prefix = std::str::from_utf8(prefix).expect("URL-safe auth key prefix is ASCII");
        let secret = std::str::from_utf8(secret).expect("URL-safe auth key secret is ASCII");
        return Ok(ParsedAuthKey::Modern { prefix, secret });
    }
    Ok(ParsedAuthKey::Legacy { key: candidate })
}

/// Find a row by candidate plaintext token. Modern rows are indexed by
/// the public prefix; legacy rows are looked up by their plaintext
/// `key` column. Returns `NotFound` if no row matches.
pub async fn get_by_token(pool: &SqlitePool, candidate: &str) -> Result<PreauthKeyRow> {
    get_by_token_with_user(pool, candidate)
        .await
        .map(|loaded| loaded.key)
}

/// Go preloads User before bcrypt without starting a new read transaction.
pub async fn get_by_token_with_user(
    pool: &SqlitePool,
    candidate: &str,
) -> Result<PreauthKeyWithUser> {
    get_by_token_for_registration(pool, candidate)
        .await
        .map(RegistrationKey::into_loaded)
}

pub async fn get_by_token_on_connection(
    conn: &mut SqliteConnection,
    candidate: &str,
) -> Result<PreauthKeyRow> {
    let key = find_by_token_on_connection(conn, candidate).await?;
    let _user = lookup_user_on_connection(conn, &key.key).await?;
    verify_candidate(
        key.key,
        candidate,
        key.association_hash.as_deref().unwrap_or_default(),
    )
    .await
}

async fn lookup_user_on_connection(
    conn: &mut SqliteConnection,
    key: &PreauthKeyRow,
) -> Result<Option<crate::users::UserRow>> {
    let id = association_user_id(key).map_err(|_| DbError::NotFound("preauth_key".into()))?;
    let Some(id) = id else {
        return Ok(None);
    };
    match crate::users::get_by_id_on_connection(conn, id).await {
        Ok(user) => Ok(Some(user)),
        Err(DbError::NotFound(_)) => Ok(None),
        Err(_) => Err(DbError::NotFound("preauth_key".into())),
    }
}

async fn verify_candidate(
    row: PreauthKeyRow,
    candidate: &str,
    hash: &[u8],
) -> Result<PreauthKeyRow> {
    if let ParsedAuthKey::Modern { secret, .. } = parse_auth_key(candidate)? {
        let valid = crate::credential_hash::verify_bytes(secret, hash)
            .await
            .map_err(|e| DbError::General(format!("invalid auth key: {e}")))?;
        if !valid {
            return Err(DbError::General("invalid auth key: crypto/bcrypt: hashedPassword is not the hash of the given password".to_string()));
        }
    }
    Ok(row)
}

// Only expose verified lookups publicly. Pool callers release the SQL
// connection before waiting for CPU capacity; connection/transaction callers
// keep their explicitly supplied connection.
async fn find_by_token_on_connection(
    conn: &mut SqliteConnection,
    candidate: &str,
) -> Result<RegistrationKeyRow> {
    match parse_auth_key(candidate)? {
        ParsedAuthKey::Modern { prefix, .. } => {
            let query = registration_key_select("WHERE prefix = ? ORDER BY id ASC LIMIT 1");
            sqlx::query_as::<_, RegistrationKeyRow>(&query)
                .bind(prefix)
                .fetch_one(&mut *conn)
                .await
                .map_err(|_| DbError::NotFound("preauth_key".into()))
        }
        ParsedAuthKey::Legacy { key } => {
            let query = registration_key_select("WHERE key = ? ORDER BY id ASC LIMIT 1");
            sqlx::query_as::<_, RegistrationKeyRow>(&query)
                .bind(key)
                .fetch_one(&mut *conn)
                .await
                .map_err(|_| DbError::NotFound("preauth_key".into()))
        }
    }
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_token(pool: &PgPool, candidate: &str) -> Result<PreauthKeyRow> {
    get_postgres_by_token_with_user(pool, candidate)
        .await
        .map(|loaded| loaded.key)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_token_with_user(
    pool: &PgPool,
    candidate: &str,
) -> Result<PreauthKeyWithUser> {
    get_postgres_by_token_for_registration(pool, candidate)
        .await
        .map(RegistrationKey::into_loaded)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_token_on_connection(
    conn: &mut PgConnection,
    candidate: &str,
) -> Result<PreauthKeyRow> {
    let key = find_postgres_by_token_on_connection(conn, candidate).await?;
    let _user = lookup_postgres_user_on_connection(conn, &key.key).await?;
    verify_candidate(
        key.key,
        candidate,
        key.association_hash.as_deref().unwrap_or_default(),
    )
    .await
}

#[cfg(feature = "postgres-sqlx")]
async fn lookup_postgres_user_on_connection(
    conn: &mut PgConnection,
    key: &PreauthKeyRow,
) -> Result<Option<crate::users::UserRow>> {
    let id = association_user_id(key).map_err(|_| DbError::NotFound("preauth_key".into()))?;
    let Some(id) = id else {
        return Ok(None);
    };
    match crate::users::get_postgres_by_id_on_connection(conn, id).await {
        Ok(user) => Ok(Some(user)),
        Err(DbError::NotFound(_)) => Ok(None),
        Err(_) => Err(DbError::NotFound("preauth_key".into())),
    }
}

#[cfg(feature = "postgres-sqlx")]
async fn find_postgres_by_token_on_connection(
    conn: &mut PgConnection,
    candidate: &str,
) -> Result<RegistrationKeyRow> {
    match parse_auth_key(candidate)? {
        ParsedAuthKey::Modern { prefix, .. } => {
            let query =
                postgres_registration_key_select("WHERE prefix = $1 ORDER BY id ASC LIMIT 1");
            sqlx::query_as::<_, RegistrationKeyRow>(&query)
                .bind(prefix)
                .fetch_one(&mut *conn)
                .await
                .map_err(|_| DbError::NotFound("preauth_key".into()))
        }
        ParsedAuthKey::Legacy { key } => {
            let query = postgres_registration_key_select("WHERE key = $1 ORDER BY id ASC LIMIT 1");
            sqlx::query_as::<_, RegistrationKeyRow>(&query)
                .bind(key)
                .fetch_one(&mut *conn)
                .await
                .map_err(|_| DbError::NotFound("preauth_key".into()))
        }
    }
}

/// Expire a key by id with the current fractional timestamp. The row stays
/// in place so the admin list can still surface it as "expired".
/// Missing IDs are no-op success, matching headscale-go's unchecked
/// `RowsAffected` behavior.
pub async fn expire(pool: &SqlitePool, id: i64) -> Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query(
        "
        UPDATE pre_auth_keys SET expiration = ? WHERE id = ?
        ",
    )
    .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true))
    .bind(id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn expire_postgres(pool: &PgPool, id: i64) -> Result<()> {
    let mut conn = pool.acquire().await?;
    expire_postgres_on_connection(&mut conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn expire_postgres_on_connection(conn: &mut PgConnection, id: i64) -> Result<()> {
    let mut tx = conn.begin().await?;
    sqlx::query(
        "
        UPDATE pre_auth_keys
        SET expiration = $1::TIMESTAMPTZ
        WHERE id = $2
        ",
    )
    .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true))
    .bind(id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Destroy a key by id outright.
///
/// Mirrors headscale-go: assigned nodes keep existing registration
/// state, but their `auth_key_id` is cleared before the key row is
/// removed so the FK does not block the admin destroy operation.
/// Missing IDs are no-op success, matching headscale-go's unchecked
/// `RowsAffected` behavior.
pub async fn destroy(pool: &SqlitePool, id: i64) -> Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    destroy_on_connection(&mut tx, id).await?;
    tx.commit().await?;
    Ok(())
}

/// Go's DestroyPreAuthKey owns a transaction/savepoint inside its caller's
/// write transaction. Node.DeletedAt is a plain timestamp, so all references
/// participate; Gorm's Update also advances the node's UpdatedAt.
pub async fn destroy_on_connection(conn: &mut SqliteConnection, id: i64) -> Result<()> {
    let mut tx = conn.begin().await?;
    sqlx::query("UPDATE nodes SET auth_key_id = NULL, updated_at = ? WHERE auth_key_id = ?")
        .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true))
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(clear_auth_key_error)?;
    sqlx::query("DELETE FROM pre_auth_keys WHERE id = ?")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn destroy_postgres(pool: &PgPool, id: i64) -> Result<()> {
    let mut tx = pool.begin().await?;
    destroy_postgres_on_connection(&mut tx, id).await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn destroy_postgres_on_connection(conn: &mut PgConnection, id: i64) -> Result<()> {
    let mut tx = conn.begin().await?;

    sqlx::query(
        "UPDATE nodes SET auth_key_id = NULL, updated_at = $1::TIMESTAMPTZ WHERE auth_key_id = $2",
    )
    .bind(Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true))
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(clear_auth_key_error)?;

    sqlx::query("DELETE FROM pre_auth_keys WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

fn clear_auth_key_error(error: sqlx::Error) -> DbError {
    DbError::General(format!(
        "clearing auth_key_id on nodes: {}",
        DbError::from(error).headscale_go_message()
    ))
}

/// List all keys belonging to `user_id`, oldest first.
pub async fn list_by_user(pool: &SqlitePool, user_id: &str) -> Result<Vec<PreauthKeyRow>> {
    let storage_user_id = match resolve_storage_user_id(pool, user_id).await {
        Ok(Some(user_id)) => user_id,
        Ok(None) | Err(DbError::Constraint(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let query = preauth_key_select("WHERE user_id = ? ORDER BY id ASC");
    let rows = sqlx::query_as::<_, PreauthKeyRow>(&query)
        .bind(storage_user_id)
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_by_user(pool: &PgPool, user_id: &str) -> Result<Vec<PreauthKeyRow>> {
    let mut conn = pool.acquire().await?;
    list_postgres_by_user_on_connection(&mut conn, user_id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_by_user_on_connection(
    conn: &mut PgConnection,
    user_id: &str,
) -> Result<Vec<PreauthKeyRow>> {
    let storage_user_id = match resolve_postgres_storage_user_id(conn, user_id).await {
        Ok(Some(user_id)) => user_id,
        Ok(None) | Err(DbError::Constraint(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let query = postgres_preauth_key_select("WHERE user_id = $1 ORDER BY id ASC");
    let rows = sqlx::query_as::<_, PreauthKeyRow>(&query)
        .bind(storage_user_id)
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows)
}

/// List every key in the store, oldest first. Used by the admin UI's
/// "all keys" page (which Tailscale's `headscale preauthkey list`
/// covers via `--user` filtering on the client).
pub async fn list_all(pool: &SqlitePool) -> Result<Vec<PreauthKeyRow>> {
    let query = preauth_key_select("ORDER BY id ASC");
    let rows = sqlx::query_as::<_, PreauthKeyRow>(&query)
        .fetch_all(pool)
        .await?;
    Ok(rows)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_all_postgres(pool: &PgPool) -> Result<Vec<PreauthKeyRow>> {
    let mut conn = pool.acquire().await?;
    list_all_postgres_on_connection(&mut conn).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_all_postgres_on_connection(
    conn: &mut PgConnection,
) -> Result<Vec<PreauthKeyRow>> {
    let query = postgres_preauth_key_select("ORDER BY id ASC");
    let rows = sqlx::query_as::<_, PreauthKeyRow>(&query)
        .fetch_all(&mut *conn)
        .await?;
    Ok(rows)
}

fn association_user_id(key: &PreauthKeyRow) -> Result<Option<i64>> {
    if key.user_id.is_empty() {
        return Ok(None);
    }
    let id = key
        .user_id
        .parse::<u64>()
        .ok()
        .and_then(|id| i64::try_from(id).ok())
        .ok_or_else(|| DbError::General("invalid stored preauth key user identity".into()))?;
    Ok(Some(id))
}

pub(crate) fn association_user_ids(keys: &[PreauthKeyRow]) -> Result<Vec<i64>> {
    let mut ids = BTreeSet::new();
    for key in keys {
        if let Some(id) = association_user_id(key)? {
            ids.insert(id);
        }
    }
    Ok(ids.into_iter().collect())
}

fn attach_users(
    keys: Vec<PreauthKeyRow>,
    users: Vec<crate::users::UserRow>,
) -> Result<Vec<PreauthKeyWithUser>> {
    let users = users
        .into_iter()
        .map(|user| (user.id, user))
        .collect::<BTreeMap<_, _>>();
    keys.into_iter()
        .map(|key| {
            let user = association_user_id(&key)?.and_then(|id| users.get(&id).cloned());
            Ok(PreauthKeyWithUser { key, user })
        })
        .collect()
}

/// Read keys and their loaded users in Go's SQLite read transaction.
pub async fn list_all_with_users(pool: &SqlitePool) -> Result<Vec<PreauthKeyWithUser>> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let query = preauth_key_select("ORDER BY id ASC");
    let keys = sqlx::query_as::<_, PreauthKeyRow>(&query)
        .fetch_all(&mut *tx)
        .await?;
    let ids = association_user_ids(&keys)?;
    let users = crate::users::list_by_ids_on_connection(&mut tx, &ids).await?;
    let result = attach_users(keys, users);
    let _ = tx.rollback().await;
    result
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_all_postgres_with_users(pool: &PgPool) -> Result<Vec<PreauthKeyWithUser>> {
    let mut conn = pool.acquire().await?;
    let mut tx = conn.begin().await?;
    let keys = list_all_postgres_on_connection(&mut tx).await?;
    let ids = association_user_ids(&keys)?;
    let users = crate::users::list_postgres_by_ids_on_connection(&mut tx, &ids).await?;
    let result = attach_users(keys, users);
    let _ = tx.rollback().await;
    result
}

/// Errors returned by [`try_use`].
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone, Copy)]
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
pub async fn try_use(
    pool: &SqlitePool,
    candidate: &str,
) -> std::result::Result<PreauthKeyRow, UseError> {
    let row = get_by_token(pool, candidate)
        .await
        .map_err(|_| UseError::NotFound)?;
    let mut tx = pool
        .begin_with("BEGIN IMMEDIATE")
        .await
        .map_err(|_| UseError::NotFound)?;

    // Re-read under the tx so we don't race with another concurrent
    // redemption of the same single-use key.
    let query = preauth_key_select("WHERE id = ?");
    let fresh: PreauthKeyRow = sqlx::query_as::<_, PreauthKeyRow>(&query)
        .bind(row.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| UseError::NotFound)?;

    let now = now_unix();
    if fresh.is_expired_at(Utc::now()) {
        return Err(UseError::Expired);
    }
    if !fresh.reusable && fresh.used_at.is_some() {
        return Err(UseError::AlreadyUsed);
    }

    let updated = if fresh.reusable {
        fresh.clone()
    } else {
        let affected = sqlx::query(
            "
            UPDATE pre_auth_keys
            SET used = true
            WHERE id = ? AND used = false
            ",
        )
        .bind(fresh.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| UseError::AlreadyUsed)?
        .rows_affected();
        if affected == 0 {
            return Err(UseError::AlreadyUsed);
        }
        PreauthKeyRow {
            used_at: Some(now),
            ..fresh
        }
    };

    tx.commit().await.map_err(|_| UseError::AlreadyUsed)?;
    Ok(updated)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn try_use_postgres(
    pool: &PgPool,
    candidate: &str,
) -> std::result::Result<PreauthKeyRow, UseError> {
    let mut conn = pool.acquire().await.map_err(|_| UseError::NotFound)?;
    try_use_postgres_on_connection(&mut conn, candidate).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn try_use_postgres_on_connection(
    conn: &mut PgConnection,
    candidate: &str,
) -> std::result::Result<PreauthKeyRow, UseError> {
    let row = get_postgres_by_token_on_connection(conn, candidate)
        .await
        .map_err(|_| UseError::NotFound)?;
    let mut tx = conn.begin().await.map_err(|_| UseError::NotFound)?;

    let query = postgres_preauth_key_select("WHERE id = $1 FOR UPDATE");
    let fresh: PreauthKeyRow = sqlx::query_as::<_, PreauthKeyRow>(&query)
        .bind(row.id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| UseError::NotFound)?;

    let now = now_unix();
    if fresh.is_expired_at(Utc::now()) {
        return Err(UseError::Expired);
    }
    if !fresh.reusable && fresh.used_at.is_some() {
        return Err(UseError::AlreadyUsed);
    }

    let updated = if fresh.reusable {
        fresh.clone()
    } else {
        let affected = sqlx::query(
            "
            UPDATE pre_auth_keys
            SET used = true
            WHERE id = $1 AND used = false
            ",
        )
        .bind(fresh.id)
        .execute(&mut *tx)
        .await
        .map_err(|_| UseError::AlreadyUsed)?
        .rows_affected();
        if affected == 0 {
            return Err(UseError::AlreadyUsed);
        }
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
    use crate::{Database, headscale_nodes, users};
    use serde_json::json;

    async fn fresh_db() -> Database {
        let db = Database::in_memory().await.expect("open in-memory");
        db.migrate().await.expect("migrate");
        seed_user(&db, "alice").await;
        seed_user(&db, "bob").await;
        db
    }

    async fn seed_user(db: &Database, name: &str) -> users::UserRow {
        users::create(
            db.pool(),
            users::CreateParams {
                name: name.into(),
                display_name: name.into(),
                email: format!("{name}@example.com"),
                provider_identifier: None,
                provider: headscale_nodes::REGISTER_METHOD_CLI.into(),
                profile_pic_url: String::new(),
            },
        )
        .await
        .unwrap()
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
        assert_eq!(c.row.user_id, "1");
        assert!(!c.row.reusable);
        assert!(c.row.used_at.is_none());
        let again = get_by_id(db.pool(), c.row.id).await.unwrap();
        assert_eq!(again.key_hash, c.row.key_hash);
        assert_eq!(again.created_at_text, c.row.created_at_text);
        let created_at_precise = chrono::DateTime::parse_from_rfc3339(&again.created_at_text)
            .expect("RFC3339 creation time survives database read");
        assert_ne!(created_at_precise.timestamp_subsec_nanos(), 0);

        let (legacy_key, prefix, stored_hash, used, created_at): (
            Option<String>,
            Option<String>,
            String,
            bool,
            i64,
        ) = sqlx::query_as(
            "
            SELECT key, prefix, CAST(hash AS TEXT), used, unixepoch(created_at)
            FROM pre_auth_keys
            WHERE id = ?
            ",
        )
        .bind(c.row.id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert_eq!(legacy_key.as_deref(), Some(""));
        assert_eq!(prefix, c.row.prefix);
        assert_eq!(stored_hash, c.row.key_hash);
        assert!(!used);
        assert_eq!(created_at, c.row.created_at);
    }

    /// Go: TestCannotCreateForNonExistantUser. Empty user IDs are
    /// rejected unless tags make the key userless.
    #[tokio::test]
    async fn create_rejects_empty_user() {
        let db = fresh_db().await;
        let mut p = alice();
        p.user_id = String::new();
        let e = create_for_test(db.pool(), p).await.unwrap_err();
        assert!(matches!(e, DbError::General(_)));
    }

    #[tokio::test]
    async fn create_rejects_missing_user() {
        let db = fresh_db().await;
        let mut p = alice();
        p.user_id = "missing".into();
        let e = create_for_test(db.pool(), p).await.unwrap_err();
        assert!(matches!(e, DbError::Constraint(_)));
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
        assert_eq!(a_keys[0].user_id, "1");
        assert_eq!(b_keys[0].user_id, "2");
    }

    /// Go: TestGetPreAuthKey + TestGetPreAuthKeys
    #[tokio::test]
    async fn get_by_token_finds_existing() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        let row = get_by_token(db.pool(), &c.plaintext).await.unwrap();
        assert_eq!(row.id, c.row.id);
    }

    #[tokio::test]
    async fn get_by_token_accepts_headscale_go_legacy_plaintext_row() {
        let db = fresh_db().await;
        let key = "legacy-preauth-key";
        let now = now_unix();
        sqlx::query(
            "
            INSERT INTO pre_auth_keys
                (key, prefix, hash, user_id, reusable, ephemeral, used, tags, expiration, created_at)
            VALUES (?, NULL, NULL, ?, false, false, false, ?, NULL, datetime(?, 'unixepoch'))
            ",
        )
        .bind(key)
        .bind(1_i64)
        .bind(r#"["tag:legacy"]"#)
        .bind(now)
        .execute(db.pool())
        .await
        .unwrap();

        let row = get_by_token(db.pool(), key).await.unwrap();
        assert_eq!(row.key.as_deref(), Some(key));
        assert_eq!(row.user_id, "1");
        assert_eq!(row.tag_list(), vec!["tag:legacy".to_string()]);
        assert_eq!(row.created_at, now);
    }

    /// Go: implicit in TestGetPreAuthKey — wrong token must miss.
    #[tokio::test]
    async fn get_by_token_rejects_wrong_token() {
        let db = fresh_db().await;
        let _c = create_for_test(db.pool(), alice()).await.unwrap();
        let bogus = format!("{TOKEN_PREFIX}{}-{}", "A".repeat(12), "0".repeat(64));
        let e = get_by_token(db.pool(), &bogus).await.unwrap_err();
        assert!(matches!(e, DbError::NotFound(_)));
    }

    #[test]
    fn parse_auth_key_reports_headscale_go_error_details() {
        fn assert_parse_error(candidate: &str, expected: &str) {
            match parse_auth_key(candidate) {
                Err(DbError::General(msg)) => assert_eq!(msg, expected),
                Err(err) => panic!("expected parse error {expected:?}, got {err:?}"),
                Ok(_) => panic!("candidate should be rejected"),
            }
        }

        assert_parse_error("", AUTH_KEY_PARSE_ERROR);
        assert_parse_error(
            &format!("{TOKEN_PREFIX}short"),
            "failed to parse auth-key: key too short, expected at least 77 chars after prefix, got 5",
        );
        assert_parse_error(
            &format!(
                "{TOKEN_PREFIX}{}{}",
                "A".repeat(TOKEN_PREFIX_LEN),
                "B".repeat(TOKEN_SECRET_LEN + 1)
            ),
            "failed to parse auth-key: expected separator '-' at position 12, got 'B'",
        );
        assert_parse_error(
            &format!(
                "{TOKEN_PREFIX}{}-{}",
                "A".repeat(TOKEN_PREFIX_LEN),
                "B".repeat(TOKEN_SECRET_LEN + 1)
            ),
            "failed to parse auth-key: hash length mismatch, expected 64 chars, got 65",
        );
        assert_parse_error(
            &format!(
                "{TOKEN_PREFIX}{}-{}",
                "A".repeat(TOKEN_PREFIX_LEN - 1) + "!",
                "B".repeat(TOKEN_SECRET_LEN)
            ),
            "failed to parse auth-key: prefix contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)",
        );
        assert_parse_error(
            &format!(
                "{TOKEN_PREFIX}{}-{}",
                "A".repeat(TOKEN_PREFIX_LEN),
                "B".repeat(TOKEN_SECRET_LEN - 1) + "!"
            ),
            "failed to parse auth-key: hash contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)",
        );
        assert_parse_error(
            &format!(
                "{TOKEN_PREFIX}{}-{}",
                "é".to_string() + &"A".repeat(TOKEN_PREFIX_LEN - 2),
                "B".repeat(TOKEN_SECRET_LEN)
            ),
            "failed to parse auth-key: prefix contains invalid characters (expected base64 URL-safe: A-Za-z0-9_-)",
        );
    }

    #[tokio::test]
    async fn get_by_token_reports_invalid_secret_for_known_prefix_like_headscale_go() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        let mut tampered = c.plaintext.clone();
        let last = tampered.pop().expect("generated key is non-empty");
        tampered.push(if last == 'A' { 'B' } else { 'A' });

        let e = get_by_token(db.pool(), &tampered).await.unwrap_err();
        assert!(matches!(e, DbError::General(msg) if msg.contains("invalid auth key")));
    }

    /// Wrong brand prefix bypasses the bcrypt loop entirely.
    #[tokio::test]
    async fn get_by_token_rejects_wrong_prefix() {
        let db = fresh_db().await;
        let _c = create_for_test(db.pool(), alice()).await.unwrap();
        let e = get_by_token(db.pool(), "tskey-deadbeef").await.unwrap_err();
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

    #[tokio::test]
    async fn is_ephemeral_by_id_reads_flag() {
        let db = fresh_db().await;
        let mut p = alice();
        p.ephemeral = true;
        let c = create_for_test(db.pool(), p).await.unwrap();

        assert!(is_ephemeral_by_id(db.pool(), c.row.id).await.unwrap());
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

    /// A non-nil Go zero timestamp is expired for auth keys. NULL is
    /// the separate no-expiration case.
    #[tokio::test]
    async fn try_use_rejects_go_zero_expiration() {
        let db = fresh_db().await;
        let mut p = alice();
        p.expiration = Some(GO_ZERO_TIME_UNIX_SECONDS);
        let c = create_for_test(db.pool(), p).await.unwrap();

        let error = try_use(db.pool(), &c.plaintext).await.unwrap_err();
        assert_eq!(error, UseError::Expired);
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
    async fn expire_unknown_id_is_noop_success() {
        let db = fresh_db().await;
        expire(db.pool(), 99_999).await.unwrap();
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

    /// Go: DestroyPreAuthKey clears assigned nodes before deleting.
    #[tokio::test]
    async fn destroy_assigned_key_clears_node_auth_key_id() {
        let db = fresh_db().await;
        let user = users::create(
            db.pool(),
            users::CreateParams {
                name: "assigned-user".into(),
                display_name: "Assigned User".into(),
                email: "assigned@example.com".into(),
                provider_identifier: None,
                provider: headscale_nodes::REGISTER_METHOD_CLI.into(),
                profile_pic_url: String::new(),
            },
        )
        .await
        .unwrap();
        let created = create_for_test(
            db.pool(),
            CreateParams {
                user_id: user.id.to_string(),
                reusable: false,
                ephemeral: false,
                tags: vec!["tag:good".into()],
                expiration: None,
            },
        )
        .await
        .unwrap();
        let node = headscale_nodes::create(
            db.pool(),
            headscale_nodes::CreateParams {
                machine_key:
                    "mkey:b3bfa157213313fb215dd3d0e13e51ef6a50e8f3513e3237583842dbbcea3357".into(),
                node_key:
                    "nodekey:dd920d91b135023815d22848f03a86a686367b12f2354ed362a8571fd846372a"
                        .into(),
                disco_key:
                    "discokey:575333e3d7c7df9b3eef854e28b87e375e1d8e64fb8ac1e0b3baaaff3699a6c5"
                        .into(),
                endpoints: Vec::new(),
                host_info: json!({"Hostname": "assigned-node"}),
                ipv4: Some("100.64.0.10".into()),
                ipv6: None,
                hostname: "assigned-node".into(),
                given_name: "assigned-node".into(),
                user_id: Some(user.id),
                register_method: headscale_nodes::REGISTER_METHOD_AUTH_KEY.into(),
                tags: vec!["tag:good".into()],
                auth_key_id: Some(created.row.id),
                expiry: None,
                expiry_precise: None,
                last_seen: None,
                last_seen_precise: None,
                approved_routes: Vec::new(),
            },
        )
        .await
        .unwrap();

        destroy(db.pool(), created.row.id).await.unwrap();
        assert_eq!(
            headscale_nodes::get_by_id(db.pool(), node.id)
                .await
                .unwrap()
                .auth_key_id,
            None
        );
        assert!(matches!(
            get_by_id(db.pool(), created.row.id).await.unwrap_err(),
            DbError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn destroy_unknown_id_is_noop_success() {
        let db = fresh_db().await;
        destroy(db.pool(), 99_999).await.unwrap();
    }

    /// Go: TestPreAuthKeyACLTags — tags round-trip.
    #[tokio::test]
    async fn tags_round_trip() {
        let db = fresh_db().await;
        let mut p = alice();
        p.tags = vec!["tag:dev".into(), "tag:server".into()];
        let c = create_for_test(db.pool(), p).await.unwrap();
        let r = get_by_token(db.pool(), &c.plaintext).await.unwrap();
        assert_eq!(
            r.tag_list(),
            vec!["tag:dev".to_string(), "tag:server".into()]
        );
    }

    /// Go: CreatePreAuthKey sorts/deduplicates ACL tags and accepts
    /// userless tagged keys.
    #[tokio::test]
    async fn tags_are_canonical_and_can_own_userless_keys() {
        let db = fresh_db().await;
        let c = create_for_test(
            db.pool(),
            CreateParams {
                user_id: String::new(),
                reusable: false,
                ephemeral: false,
                tags: vec!["tag:web".into(), "tag:dev".into(), "tag:web".into()],
                expiration: None,
            },
        )
        .await
        .unwrap();

        assert_eq!(c.row.user_id, "");
        assert_eq!(c.row.tag_list(), vec!["tag:dev", "tag:web"]);
        assert_eq!(c.row.tags, r#"["tag:dev","tag:web"]"#);
    }

    /// Go: TestPreAuthKeyACLTags rejects tags that do not start with `tag:`.
    #[tokio::test]
    async fn create_rejects_invalid_acl_tag() {
        let db = fresh_db().await;
        let mut p = alice();
        p.tags = vec!["badtag".into()];
        let e = create_for_test(db.pool(), p).await.unwrap_err();

        assert!(matches!(e, DbError::General(msg) if msg.contains("did not begin with 'tag:'")));
    }

    /// Empty tag list serialises to "[]" and round-trips clean.
    #[tokio::test]
    async fn empty_tags_round_trip() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), alice()).await.unwrap();
        assert_eq!(c.row.tag_list(), Vec::<String>::new());
        assert_eq!(c.row.tags, "[]");
    }

    /// Go: TestListPreAuthKeys — list returns multiple in ID order.
    #[tokio::test]
    async fn list_by_user_orders_by_id_ascending() {
        let db = fresh_db().await;
        let a = create_for_test(db.pool(), alice()).await.unwrap();
        let b = create_for_test(db.pool(), alice()).await.unwrap();
        let list = list_by_user(db.pool(), "alice").await.unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, a.row.id);
        assert_eq!(list[1].id, b.row.id);
    }

    /// list_all returns every user's keys.
    #[tokio::test]
    async fn list_all_returns_all_users() {
        let db = fresh_db().await;
        let a = create_for_test(db.pool(), alice()).await.unwrap();
        let mut bob = alice();
        bob.user_id = "bob".into();
        let b = create_for_test(db.pool(), bob).await.unwrap();
        let all = list_all(db.pool()).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(
            all.iter().map(|row| row.id).collect::<Vec<_>>(),
            vec![a.row.id, b.row.id]
        );
    }

    /// `try_use` on an unknown token ⇒ NotFound.
    #[tokio::test]
    async fn try_use_unknown_token_not_found() {
        let db = fresh_db().await;
        let bogus = format!("{TOKEN_PREFIX}{}-{}", "A".repeat(12), "0".repeat(64));
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

    #[tokio::test]
    async fn file_database_persists_preauth_keys_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headscale.db");
        let url = format!("sqlite://{}?mode=rwc", path.display());

        let plaintext = {
            let db = Database::new(&url).await.unwrap();
            db.migrate().await.unwrap();
            seed_user(&db, "alice").await;
            let mut p = alice();
            p.tags = vec!["tag:router".into()];
            let created = create_for_test(db.pool(), p).await.unwrap();
            db.close().await;
            created.plaintext
        };

        let reopened = Database::new(&url).await.unwrap();
        reopened.migrate().await.unwrap();
        let row = get_by_token(reopened.pool(), &plaintext).await.unwrap();
        assert_eq!(row.user_id, "1");
        assert_eq!(row.tag_list(), vec!["tag:router".to_string()]);
    }

    #[tokio::test]
    async fn expired_single_use_key_is_not_marked_used() {
        let db = fresh_db().await;
        let mut p = alice();
        p.expiration = Some(now_unix() - 60);
        let created = create_for_test(db.pool(), p).await.unwrap();

        assert_eq!(
            try_use(db.pool(), &created.plaintext).await.unwrap_err(),
            UseError::Expired
        );

        let stored = get_by_id(db.pool(), created.row.id).await.unwrap();
        assert!(stored.used_at.is_none());
    }
}
