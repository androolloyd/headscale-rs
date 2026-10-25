//! API-key persistence matching headscale-go v0.29.5.
//!
//! Upstream creates plaintext keys as
//! `hskey-api-<12 urlsafe chars>-<64 urlsafe chars>`, stores only the
//! 12-character prefix and a bcrypt hash of the 64-character secret,
//! and accepts legacy `prefix.secret` keys for older rows. This module
//! follows that contract while using sqlx/SQLite instead of GORM.

use crate::{DbError, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
#[cfg(feature = "postgres-sqlx")]
use sqlx::{PgConnection, PgPool};

mod state;
pub use state::list_for_state;
#[cfg(feature = "postgres-sqlx")]
pub use state::list_postgres_for_state;

pub const API_KEY_PREFIX: &str = "hskey-api-";
pub const API_KEY_PREFIX_LEN: usize = 12;
pub const API_KEY_SECRET_LEN: usize = 64;
pub const LEGACY_API_KEY_PREFIX_LEN: usize = 7;
pub const LEGACY_API_KEY_SECRET_LEN: usize = 32;

/// Same production cost family as headscale-go (`bcrypt.DefaultCost`).
pub const BCRYPT_COST_DEFAULT: u32 = 10;
pub const BCRYPT_COST_TEST: u32 = 4;

const API_KEY_COLUMNS: &str = r"
        id,
        COALESCE(prefix, '') AS prefix,
        hash AS secret_hash,
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
            (SELECT cid FROM pragma_table_info('api_keys') WHERE name = 'expiration'),
            'expiration'
        ) AS expiration_text,
        CASE
            WHEN created_at IS NULL THEN 0
            WHEN typeof(created_at) = 'integer' THEN created_at
            ELSE unixepoch(created_at)
        END AS created_at,
        CAST(created_at AS TEXT) AS created_at_text,
        CASE
            WHEN last_seen IS NULL THEN NULL
            WHEN typeof(last_seen) = 'integer' THEN last_seen
            ELSE unixepoch(last_seen)
        END AS last_seen,
        CAST(last_seen AS TEXT) AS last_seen_text
";

fn api_key_select(suffix: &str) -> String {
    format!("SELECT {API_KEY_COLUMNS} FROM api_keys {suffix}")
}

#[cfg(feature = "postgres-sqlx")]
const POSTGRES_API_KEY_COLUMNS: &str = r#"
        id,
        COALESCE(prefix, '') AS prefix,
        hash AS secret_hash,
        FLOOR(EXTRACT(EPOCH FROM expiration))::BIGINT AS expiration,
        to_char(expiration AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS expiration_text,
        COALESCE(FLOOR(EXTRACT(EPOCH FROM created_at))::BIGINT, 0) AS created_at,
        to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS created_at_text,
        FLOOR(EXTRACT(EPOCH FROM last_seen))::BIGINT AS last_seen,
        to_char(last_seen AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS last_seen_text
"#;

#[cfg(feature = "postgres-sqlx")]
fn postgres_api_key_select(suffix: &str) -> String {
    format!("SELECT {POSTGRES_API_KEY_COLUMNS} FROM api_keys {suffix}")
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKeyRow {
    pub id: i64,
    pub prefix: String,
    #[sqlx(try_from = "crate::stored_hash::HashColumn")]
    pub secret_hash: String,
    pub expiration: Option<i64>,
    #[serde(default)]
    #[sqlx(try_from = "crate::preauth_keys::timestamp::ExpirationColumn")]
    pub expiration_text: Option<String>,
    pub created_at: i64,
    #[serde(default)]
    pub created_at_text: Option<String>,
    pub last_seen: Option<i64>,
    #[serde(default)]
    pub last_seen_text: Option<String>,
}

#[derive(sqlx::FromRow)]
struct ApiKeyCredentialRow {
    #[sqlx(flatten)]
    row: ApiKeyRow,
    credential_hash: Option<Vec<u8>>,
}

impl ApiKeyRow {
    pub fn display_prefix(&self) -> String {
        if self.prefix.len() == API_KEY_PREFIX_LEN {
            format!("{API_KEY_PREFIX}{}-***", self.prefix)
        } else {
            format!("{}***", self.prefix)
        }
    }

    pub fn is_expired(&self, now_unix: i64) -> bool {
        self.expiration_datetime()
            .map(|expiry| expiry.timestamp())
            .or(self.expiration)
            .is_some_and(|expiry| expiry < now_unix)
    }

    pub fn expiration_datetime(&self) -> Option<DateTime<Utc>> {
        crate::preauth_keys::parse_database_timestamp(
            self.expiration,
            self.expiration_text.as_deref(),
        )
    }

    pub fn created_at_datetime(&self) -> Option<DateTime<Utc>> {
        if self.created_at == 0 && self.created_at_text.is_none() {
            return None;
        }
        crate::preauth_keys::parse_database_timestamp(
            Some(self.created_at),
            self.created_at_text.as_deref(),
        )
    }

    pub fn last_seen_datetime(&self) -> Option<DateTime<Utc>> {
        crate::preauth_keys::parse_database_timestamp(
            self.last_seen,
            self.last_seen_text.as_deref(),
        )
    }

    async fn validate_secret(
        &self,
        secret: &str,
        hash: &[u8],
    ) -> std::result::Result<bool, ApiKeyError> {
        if !crate::credential_hash::verify_bytes(secret, hash)
            .await
            .map_err(|_| ApiKeyError::Invalid)?
        {
            return Err(ApiKeyError::Invalid);
        }
        // Go's API-key validator does not exempt a non-null year-one zero
        // time. Only SQL NULL means unlimited.
        Ok(self
            .expiration_datetime()
            .is_none_or(|expiry| expiry >= Utc::now()))
    }
}

#[derive(Debug, Clone)]
pub struct CreateParams {
    pub expiration: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct Created {
    pub plaintext: String,
    pub row: ApiKeyRow,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApiKeyError {
    #[error("api key failed to parse")]
    FailedToParse,
    #[error("api key not found")]
    NotFound,
    #[error("api key invalid")]
    Invalid,
}

#[cfg(test)]
fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn is_valid_urlsafe(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn generate_plaintext() -> (String, String, String) {
    try_generate_plaintext().expect("OS entropy for API key generation")
}

fn try_generate_plaintext() -> Result<(String, String, String)> {
    let prefix = crate::credential_entropy::urlsafe(API_KEY_PREFIX_LEN)?;
    let secret = crate::credential_entropy::urlsafe(API_KEY_SECRET_LEN)?;
    let key = format!("{API_KEY_PREFIX}{prefix}-{secret}");
    Ok((key, prefix, secret))
}

pub async fn create(pool: &SqlitePool, params: CreateParams) -> Result<Created> {
    create_with_cost(pool, params, BCRYPT_COST_DEFAULT).await
}

pub async fn create_for_test(pool: &SqlitePool, params: CreateParams) -> Result<Created> {
    create_with_cost(pool, params, BCRYPT_COST_TEST).await
}

pub async fn create_with_cost(
    pool: &SqlitePool,
    params: CreateParams,
    cost: u32,
) -> Result<Created> {
    create_with_cost_precise(pool, params, cost, None).await
}

pub async fn create_with_cost_precise(
    pool: &SqlitePool,
    params: CreateParams,
    cost: u32,
    expiration_precise: Option<DateTime<Utc>>,
) -> Result<Created> {
    let key = state::prepare(params, cost, expiration_precise).await?;
    state::create(pool, key).await
}

pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Result<ApiKeyRow> {
    let query = api_key_select("WHERE id = ?");
    sqlx::query_as::<_, ApiKeyRow>(&query)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => DbError::NotFound(format!("api_key id={id}")),
            e => DbError::from(e),
        })
}

pub async fn get_by_prefix(pool: &SqlitePool, display_prefix: &str) -> Result<ApiKeyRow> {
    let prefix = parse_display_prefix(display_prefix)?;
    let query = api_key_select("WHERE prefix = ? ORDER BY id LIMIT 1");
    sqlx::query_as::<_, ApiKeyRow>(&query)
        .bind(&prefix)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => {
                DbError::NotFound(format!("api_key prefix={display_prefix}"))
            }
            e => DbError::from(e),
        })
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<ApiKeyRow>> {
    let query = api_key_select("ORDER BY id ASC");
    sqlx::query_as::<_, ApiKeyRow>(&query)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)
}

pub async fn expire(pool: &SqlitePool, id: i64) -> Result<()> {
    let key = get_by_id(pool, id).await?;
    state::expire(pool, &key).await
}

pub async fn expire_by_prefix(pool: &SqlitePool, display_prefix: &str) -> Result<()> {
    let row = get_by_prefix(pool, display_prefix).await?;
    state::expire(pool, &row).await
}

pub async fn destroy(pool: &SqlitePool, id: i64) -> Result<()> {
    let key = get_by_id(pool, id).await?;
    state::destroy(pool, &key).await
}

pub async fn destroy_by_prefix(pool: &SqlitePool, display_prefix: &str) -> Result<()> {
    let row = get_by_prefix(pool, display_prefix).await?;
    state::destroy(pool, &row).await
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
    create_postgres_with_cost_precise(pool, params, cost, None).await
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
    create_postgres_with_cost_precise_on_connection(conn, params, cost, None).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_with_cost_precise(
    pool: &PgPool,
    params: CreateParams,
    cost: u32,
    expiration_precise: Option<DateTime<Utc>>,
) -> Result<Created> {
    let key = state::prepare(params, cost, expiration_precise).await?;
    let mut conn = pool.acquire().await.map_err(state::saving_error)?;
    state::create_postgres(&mut conn, key).await
}

#[cfg(feature = "postgres-sqlx")]
async fn create_postgres_with_cost_precise_on_connection(
    conn: &mut PgConnection,
    params: CreateParams,
    cost: u32,
    expiration_precise: Option<DateTime<Utc>>,
) -> Result<Created> {
    let key = state::prepare(params, cost, expiration_precise).await?;
    state::create_postgres(conn, key).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_id(pool: &PgPool, id: i64) -> Result<ApiKeyRow> {
    let mut conn = pool.acquire().await?;
    get_postgres_by_id_on_connection(&mut conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_id_on_connection(
    conn: &mut PgConnection,
    id: i64,
) -> Result<ApiKeyRow> {
    let query = postgres_api_key_select("WHERE id = $1");
    sqlx::query_as::<_, ApiKeyRow>(&query)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => DbError::NotFound(format!("api_key id={id}")),
            e => DbError::from(e),
        })
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_prefix(pool: &PgPool, display_prefix: &str) -> Result<ApiKeyRow> {
    let mut conn = pool.acquire().await?;
    get_postgres_by_prefix_on_connection(&mut conn, display_prefix).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_prefix_on_connection(
    conn: &mut PgConnection,
    display_prefix: &str,
) -> Result<ApiKeyRow> {
    let prefix = parse_display_prefix(display_prefix)?;
    let query = postgres_api_key_select("WHERE prefix = $1 ORDER BY id LIMIT 1");
    sqlx::query_as::<_, ApiKeyRow>(&query)
        .bind(&prefix)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => {
                DbError::NotFound(format!("api_key prefix={display_prefix}"))
            }
            e => DbError::from(e),
        })
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres(pool: &PgPool) -> Result<Vec<ApiKeyRow>> {
    let mut conn = pool.acquire().await?;
    list_postgres_on_connection(&mut conn).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_on_connection(conn: &mut PgConnection) -> Result<Vec<ApiKeyRow>> {
    let query = postgres_api_key_select("ORDER BY id ASC");
    sqlx::query_as::<_, ApiKeyRow>(&query)
        .fetch_all(&mut *conn)
        .await
        .map_err(DbError::from)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn expire_postgres(pool: &PgPool, id: i64) -> Result<()> {
    let key = get_postgres_by_id(pool, id).await?;
    let expiration = Utc::now();
    let mut conn = pool.acquire().await?;
    state::expire_postgres_at(&mut conn, &key, expiration).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn expire_postgres_on_connection(conn: &mut PgConnection, id: i64) -> Result<()> {
    let key = get_postgres_by_id_on_connection(conn, id).await?;
    state::expire_postgres(conn, &key).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn expire_postgres_by_prefix(pool: &PgPool, display_prefix: &str) -> Result<()> {
    let key = get_postgres_by_prefix(pool, display_prefix).await?;
    let expiration = Utc::now();
    let mut conn = pool.acquire().await?;
    state::expire_postgres_at(&mut conn, &key, expiration).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn expire_postgres_by_prefix_on_connection(
    conn: &mut PgConnection,
    display_prefix: &str,
) -> Result<()> {
    let row = get_postgres_by_prefix_on_connection(conn, display_prefix).await?;
    state::expire_postgres(conn, &row).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn destroy_postgres(pool: &PgPool, id: i64) -> Result<()> {
    let key = get_postgres_by_id(pool, id).await?;
    let mut conn = pool.acquire().await?;
    state::destroy_postgres(&mut conn, &key).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn destroy_postgres_on_connection(conn: &mut PgConnection, id: i64) -> Result<()> {
    let key = get_postgres_by_id_on_connection(conn, id).await?;
    state::destroy_postgres(conn, &key).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn destroy_postgres_by_prefix(pool: &PgPool, display_prefix: &str) -> Result<()> {
    let key = get_postgres_by_prefix(pool, display_prefix).await?;
    let mut conn = pool.acquire().await?;
    state::destroy_postgres(&mut conn, &key).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn destroy_postgres_by_prefix_on_connection(
    conn: &mut PgConnection,
    display_prefix: &str,
) -> Result<()> {
    let row = get_postgres_by_prefix_on_connection(conn, display_prefix).await?;
    state::destroy_postgres(conn, &row).await
}

pub fn parse_display_prefix(display_prefix: &str) -> Result<String> {
    if display_prefix.len() == API_KEY_PREFIX_LEN && is_valid_urlsafe(display_prefix) {
        return Ok(display_prefix.to_string());
    }
    if let Some(rest) = display_prefix.strip_prefix(API_KEY_PREFIX) {
        if rest.len() < API_KEY_PREFIX_LEN {
            return Err(DbError::General(
                "failed to parse ApiKey: prefix too short".into(),
            ));
        }
        let prefix = &rest.as_bytes()[..API_KEY_PREFIX_LEN];
        if !prefix
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        {
            return Err(DbError::General(
                "failed to parse ApiKey: prefix contains invalid characters".into(),
            ));
        }
        return Ok(std::str::from_utf8(prefix)
            .expect("URL-safe API key prefix is ASCII")
            .to_string());
    }
    Ok(display_prefix.to_string())
}

enum ParsedKey<'a> {
    Modern { prefix: &'a str, secret: &'a str },
    Legacy { prefix: &'a str, secret: &'a str },
}

fn parse_api_key(candidate: &str) -> std::result::Result<ParsedKey<'_>, ApiKeyError> {
    if candidate.is_empty() {
        return Err(ApiKeyError::FailedToParse);
    }
    if let Some((_, rest)) = candidate.split_once(API_KEY_PREFIX) {
        let expected = API_KEY_PREFIX_LEN + 1 + API_KEY_SECRET_LEN;
        if rest.len() != expected {
            return Err(ApiKeyError::FailedToParse);
        }
        let rest = rest.as_bytes();
        let prefix = &rest[..API_KEY_PREFIX_LEN];
        if rest[API_KEY_PREFIX_LEN] != b'-' {
            return Err(ApiKeyError::FailedToParse);
        }
        let secret = &rest[API_KEY_PREFIX_LEN + 1..];
        if !prefix
            .iter()
            .chain(secret)
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-'))
        {
            return Err(ApiKeyError::FailedToParse);
        }
        return Ok(ParsedKey::Modern {
            prefix: std::str::from_utf8(prefix).expect("URL-safe API key prefix is ASCII"),
            secret: std::str::from_utf8(secret).expect("URL-safe API key secret is ASCII"),
        });
    }
    let Some((prefix, secret)) = candidate.split_once('.') else {
        return Err(ApiKeyError::FailedToParse);
    };
    if prefix.len() != LEGACY_API_KEY_PREFIX_LEN {
        return Err(ApiKeyError::FailedToParse);
    }
    Ok(ParsedKey::Legacy { prefix, secret })
}

/// Validate an API-key bearer token.
///
/// Returns `Ok(false)` for correctly parsed and authenticated keys that are
/// expired, matching headscale-go's `ValidateAPIKey` `(false, nil)` result.
pub async fn validate(
    pool: &SqlitePool,
    candidate: &str,
) -> std::result::Result<bool, ApiKeyError> {
    let parsed = parse_api_key(candidate)?;
    let (prefix, secret) = match parsed {
        ParsedKey::Modern { prefix, secret } | ParsedKey::Legacy { prefix, secret } => {
            (prefix, secret)
        }
    };
    let query = format!(
        "SELECT {API_KEY_COLUMNS}, CAST(hash AS BLOB) AS credential_hash FROM api_keys WHERE prefix = ? ORDER BY id LIMIT 1"
    );
    let row = sqlx::query_as::<_, ApiKeyCredentialRow>(&query)
        .bind(prefix)
        .fetch_one(pool)
        .await
        .map_err(|_| ApiKeyError::NotFound)?;

    row.row
        .validate_secret(secret, row.credential_hash.as_deref().unwrap_or_default())
        .await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn validate_postgres(
    pool: &PgPool,
    candidate: &str,
) -> std::result::Result<bool, ApiKeyError> {
    let parsed = parse_api_key(candidate)?;
    let (prefix, secret) = match parsed {
        ParsedKey::Modern { prefix, secret } | ParsedKey::Legacy { prefix, secret } => {
            (prefix, secret)
        }
    };
    let query = format!(
        "SELECT {POSTGRES_API_KEY_COLUMNS}, hash AS credential_hash FROM api_keys WHERE prefix = $1 ORDER BY id LIMIT 1"
    );
    let row = sqlx::query_as::<_, ApiKeyCredentialRow>(&query)
        .bind(prefix)
        .fetch_one(pool)
        .await
        .map_err(|_| ApiKeyError::NotFound)?;
    row.row
        .validate_secret(secret, row.credential_hash.as_deref().unwrap_or_default())
        .await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn validate_postgres_on_connection(
    conn: &mut PgConnection,
    candidate: &str,
) -> std::result::Result<bool, ApiKeyError> {
    let parsed = parse_api_key(candidate)?;
    let (prefix, secret) = match parsed {
        ParsedKey::Modern { prefix, secret } | ParsedKey::Legacy { prefix, secret } => {
            (prefix, secret)
        }
    };
    let query = format!(
        "SELECT {POSTGRES_API_KEY_COLUMNS}, hash AS credential_hash FROM api_keys WHERE prefix = $1 ORDER BY id LIMIT 1"
    );
    let row = sqlx::query_as::<_, ApiKeyCredentialRow>(&query)
        .bind(prefix)
        .fetch_one(&mut *conn)
        .await
        .map_err(|_| ApiKeyError::NotFound)?;

    row.row
        .validate_secret(secret, row.credential_hash.as_deref().unwrap_or_default())
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;

    const GO_ZERO_TIME_UNIX_SECONDS: i64 = -62_135_596_800;

    async fn fresh_db() -> Database {
        let db = Database::in_memory().await.expect("open in-memory");
        db.migrate().await.expect("migrate");
        db
    }

    #[tokio::test]
    async fn create_matches_headscale_go_shape() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), CreateParams { expiration: None })
            .await
            .unwrap();
        assert!(c.plaintext.starts_with(API_KEY_PREFIX));
        let rest = c.plaintext.strip_prefix(API_KEY_PREFIX).unwrap();
        assert_eq!(rest.as_bytes()[API_KEY_PREFIX_LEN], b'-');
        let prefix = &rest[..API_KEY_PREFIX_LEN];
        let secret = &rest[API_KEY_PREFIX_LEN + 1..];
        assert_eq!(prefix.len(), API_KEY_PREFIX_LEN);
        assert_eq!(secret.len(), API_KEY_SECRET_LEN);
        assert_eq!(c.row.prefix, prefix);
        assert_eq!(
            c.row.display_prefix(),
            format!("{API_KEY_PREFIX}{prefix}-***")
        );

        let (stored_prefix, stored_hash, stored_created_at): (String, String, i64) =
            sqlx::query_as(
                "SELECT prefix, CAST(hash AS TEXT), unixepoch(created_at) FROM api_keys",
            )
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(stored_prefix, prefix);
        assert_eq!(stored_hash, c.row.secret_hash);
        assert_eq!(stored_created_at, c.row.created_at);
    }

    #[tokio::test]
    async fn validate_accepts_created_key() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), CreateParams { expiration: None })
            .await
            .unwrap();
        assert!(validate(db.pool(), &c.plaintext).await.unwrap());
    }

    #[tokio::test]
    async fn validate_rejects_go_zero_expiration() {
        let db = fresh_db().await;
        let c = create_for_test(
            db.pool(),
            CreateParams {
                expiration: Some(GO_ZERO_TIME_UNIX_SECONDS),
            },
        )
        .await
        .unwrap();
        let row = get_by_id(db.pool(), c.row.id).await.unwrap();
        assert_eq!(row.expiration, Some(GO_ZERO_TIME_UNIX_SECONDS));
        assert!(row.is_expired(now_unix()));
        assert!(!validate(db.pool(), &c.plaintext).await.unwrap());
    }

    #[tokio::test]
    async fn validate_accepts_headscale_go_legacy_hash_row() {
        let db = fresh_db().await;
        let prefix = "legacy1";
        let secret = "s".repeat(LEGACY_API_KEY_SECRET_LEN);
        let hash = bcrypt::hash(&secret, BCRYPT_COST_TEST).unwrap();
        let now = now_unix();
        sqlx::query(
            "
            INSERT INTO api_keys (prefix, hash, expiration, last_seen, created_at)
            VALUES (
                ?,
                ?,
                datetime(?, 'unixepoch'),
                datetime(?, 'unixepoch'),
                datetime(?, 'unixepoch')
            )
            ",
        )
        .bind(prefix)
        .bind(hash.as_bytes())
        .bind(now + 3600)
        .bind(now - 60)
        .bind(now)
        .execute(db.pool())
        .await
        .unwrap();

        assert!(
            validate(db.pool(), &format!("{prefix}.{secret}"))
                .await
                .unwrap()
        );
        let row = get_by_prefix(db.pool(), prefix).await.unwrap();
        assert_eq!(row.secret_hash, hash);
        assert_eq!(row.expiration, Some(now + 3600));
        assert_eq!(row.last_seen, Some(now - 60));
        assert_eq!(row.created_at, now);
    }

    #[tokio::test]
    async fn validate_rejects_tampered_secret() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), CreateParams { expiration: None })
            .await
            .unwrap();
        let mut tampered = c.plaintext.clone();
        let last = tampered.pop().expect("generated key is non-empty");
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        let err = validate(db.pool(), &tampered).await.unwrap_err();
        assert!(matches!(err, ApiKeyError::Invalid | ApiKeyError::NotFound));
    }

    #[tokio::test]
    async fn validate_reports_expired_key_as_invalid_without_error() {
        let db = fresh_db().await;
        let c = create_for_test(
            db.pool(),
            CreateParams {
                expiration: Some(now_unix() - 60),
            },
        )
        .await
        .unwrap();
        assert!(!validate(db.pool(), &c.plaintext).await.unwrap());
    }

    #[tokio::test]
    async fn list_expire_and_destroy_by_prefix() {
        let db = fresh_db().await;
        let c = create_for_test(db.pool(), CreateParams { expiration: None })
            .await
            .unwrap();
        assert_eq!(list(db.pool()).await.unwrap().len(), 1);
        expire_by_prefix(db.pool(), &c.row.display_prefix())
            .await
            .unwrap();
        let row = get_by_id(db.pool(), c.row.id).await.unwrap();
        assert!(row.expiration.is_some());
        destroy_by_prefix(db.pool(), &row.display_prefix())
            .await
            .unwrap();
        assert_eq!(list(db.pool()).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn list_orders_by_id_ascending_like_headscale_go() {
        let db = fresh_db().await;
        let first = create_for_test(db.pool(), CreateParams { expiration: None })
            .await
            .unwrap();
        let second = create_for_test(db.pool(), CreateParams { expiration: None })
            .await
            .unwrap();

        let rows = list(db.pool()).await.unwrap();
        assert_eq!(
            rows.iter().map(|row| row.id).collect::<Vec<_>>(),
            vec![first.row.id, second.row.id]
        );
    }

    #[tokio::test]
    async fn parse_display_prefix_accepts_upstream_forms() {
        assert_eq!(
            parse_display_prefix("abcdefghijkl").unwrap(),
            "abcdefghijkl"
        );
        assert_eq!(
            parse_display_prefix("hskey-api-abcdefghijkl-***").unwrap(),
            "abcdefghijkl"
        );
        assert_eq!(
            parse_display_prefix("hskey-api-abcdefghijkl").unwrap(),
            "abcdefghijkl"
        );
        assert_eq!(parse_display_prefix("legacy1***").unwrap(), "legacy1***");
    }
}
