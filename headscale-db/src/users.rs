//! User persistence matching headscale-go v0.29.5.
//!
//! Upstream stores users in a `users` table with optional OIDC
//! provider identity fields and uniqueness rules around
//! `(name, provider_identifier)`. This module exposes that table with
//! Unix-second timestamps at the Rust boundary, with the original user
//! creation timestamp retained for Tailscale register responses.

use crate::{DbError, Result};
use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
#[cfg(feature = "postgres-sqlx")]
use sqlx::{Connection, PgConnection, PgPool};
use sqlx::{SqliteConnection, SqlitePool};

mod delete_preloads;
mod oidc_registration;
mod state_mutations;
mod state_queries;
pub use oidc_registration::create_or_update_oidc_user_for_registration;
#[cfg(feature = "postgres-sqlx")]
pub use oidc_registration::{
    create_or_update_oidc_user_postgres_for_registration,
    create_or_update_oidc_user_postgres_for_registration_on_connection,
};
pub use state_mutations::{create_for_state, rename_for_state};
#[cfg(feature = "postgres-sqlx")]
pub use state_mutations::{create_postgres_for_state, rename_postgres_for_state};
#[cfg(feature = "postgres-sqlx")]
pub use state_queries::list_postgres_for_state;
pub use state_queries::{UserListFilter, list_for_state};

const REGISTER_METHOD_OIDC: &str = "oidc";
const USER_COLUMNS: &str = r"
        id,
        COALESCE(name, '') AS name,
        COALESCE(display_name, '') AS display_name,
        COALESCE(email, '') AS email,
        provider_identifier,
        COALESCE(provider, '') AS provider,
        COALESCE(profile_pic_url, '') AS profile_pic_url,
        CASE
            WHEN created_at IS NULL THEN 0
            WHEN typeof(created_at) = 'integer' THEN created_at
            ELSE unixepoch(created_at)
        END AS created_at,
        COALESCE(CAST(created_at AS TEXT), '') AS created_at_text,
        CASE
            WHEN updated_at IS NULL THEN 0
            WHEN typeof(updated_at) = 'integer' THEN updated_at
            ELSE unixepoch(updated_at)
        END AS updated_at,
        CASE
            WHEN deleted_at IS NULL THEN NULL
            WHEN typeof(deleted_at) = 'integer' THEN deleted_at
            ELSE unixepoch(deleted_at)
        END AS deleted_at
";

fn user_select(suffix: &str) -> String {
    format!("SELECT {USER_COLUMNS} FROM users {suffix}")
}

#[cfg(feature = "postgres-sqlx")]
const POSTGRES_USER_COLUMNS: &str = r#"
        id,
        COALESCE(name, '') AS name,
        COALESCE(display_name, '') AS display_name,
        COALESCE(email, '') AS email,
        provider_identifier,
        COALESCE(provider, '') AS provider,
        COALESCE(profile_pic_url, '') AS profile_pic_url,
        COALESCE(FLOOR(EXTRACT(EPOCH FROM created_at))::BIGINT, 0) AS created_at,
        COALESCE(to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '') AS created_at_text,
        COALESCE(FLOOR(EXTRACT(EPOCH FROM updated_at))::BIGINT, 0) AS updated_at,
        FLOOR(EXTRACT(EPOCH FROM deleted_at))::BIGINT AS deleted_at
"#;

#[cfg(feature = "postgres-sqlx")]
fn postgres_user_select(suffix: &str) -> String {
    format!("SELECT {POSTGRES_USER_COLUMNS} FROM users {suffix}")
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRow {
    pub id: i64,
    pub name: String,
    pub display_name: String,
    pub email: String,
    pub provider_identifier: Option<String>,
    pub provider: String,
    pub profile_pic_url: String,
    pub created_at: i64,
    pub created_at_text: String,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

/// Ephemeral Gorm association insert material. Keep raw model timestamps in
/// the original preload so fresh saves do not reread a later user version.
#[derive(Clone, sqlx::FromRow)]
pub struct UserWriteSnapshot {
    #[sqlx(flatten)]
    pub row: UserRow,
    pub updated_at_text: String,
    pub deleted_at_text: Option<String>,
}

pub async fn get_for_registration(pool: &SqlitePool, id: i64) -> Result<UserWriteSnapshot> {
    let mut connection = pool.acquire().await?;
    get_for_registration_on_connection(&mut connection, id).await
}

pub async fn get_for_registration_on_connection(
    connection: &mut SqliteConnection,
    id: i64,
) -> Result<UserWriteSnapshot> {
    let query = format!(
        "SELECT {USER_COLUMNS}, COALESCE(CAST(updated_at AS TEXT), '') AS updated_at_text, CAST(deleted_at AS TEXT) AS deleted_at_text FROM users WHERE id = ? AND deleted_at IS NULL"
    );
    sqlx::query_as(&query)
        .bind(id)
        .fetch_one(connection)
        .await
        .map_err(map_not_found)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_for_registration(pool: &PgPool, id: i64) -> Result<UserWriteSnapshot> {
    let mut connection = pool.acquire().await?;
    get_postgres_for_registration_on_connection(&mut connection, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_for_registration_on_connection(
    connection: &mut PgConnection,
    id: i64,
) -> Result<UserWriteSnapshot> {
    let query = format!(
        r#"SELECT {POSTGRES_USER_COLUMNS}, COALESCE(to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '') AS updated_at_text, to_char(deleted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS deleted_at_text FROM users WHERE id = $1 AND deleted_at IS NULL"#
    );
    sqlx::query_as(&query)
        .bind(id)
        .fetch_one(connection)
        .await
        .map_err(map_not_found)
}

pub async fn get_by_name_for_registration(
    pool: &SqlitePool,
    name: &str,
) -> Result<UserWriteSnapshot> {
    let mut connection = pool.acquire().await?;
    get_by_name_for_registration_on_connection(&mut connection, name).await
}

pub async fn list_for_registration(pool: &SqlitePool) -> Result<Vec<UserWriteSnapshot>> {
    let query = format!(
        "SELECT {USER_COLUMNS}, COALESCE(CAST(updated_at AS TEXT), '') AS updated_at_text, CAST(deleted_at AS TEXT) AS deleted_at_text FROM users WHERE deleted_at IS NULL ORDER BY id"
    );
    Ok(sqlx::query_as(&query).fetch_all(pool).await?)
}

pub async fn get_by_name_for_registration_on_connection(
    connection: &mut SqliteConnection,
    name: &str,
) -> Result<UserWriteSnapshot> {
    let query = format!(
        "SELECT {USER_COLUMNS}, COALESCE(CAST(updated_at AS TEXT), '') AS updated_at_text, CAST(deleted_at AS TEXT) AS deleted_at_text FROM users WHERE name = ? AND deleted_at IS NULL ORDER BY id"
    );
    let rows = sqlx::query_as::<_, UserWriteSnapshot>(&query)
        .bind(name)
        .fetch_all(connection)
        .await?;
    match rows.len() {
        0 => Err(DbError::NotFound(format!("user name={name}"))),
        1 => Ok(rows.into_iter().next().expect("length checked")),
        n => Err(DbError::General(format!(
            "expected exactly one user, found {n}"
        ))),
    }
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_name_for_registration(
    pool: &PgPool,
    name: &str,
) -> Result<UserWriteSnapshot> {
    let mut connection = pool.acquire().await?;
    get_postgres_by_name_for_registration_on_connection(&mut connection, name).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_for_registration(pool: &PgPool) -> Result<Vec<UserWriteSnapshot>> {
    let query = format!(
        r#"SELECT {POSTGRES_USER_COLUMNS}, COALESCE(to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '') AS updated_at_text, to_char(deleted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS deleted_at_text FROM users WHERE deleted_at IS NULL ORDER BY id"#
    );
    Ok(sqlx::query_as(&query).fetch_all(pool).await?)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_name_for_registration_on_connection(
    connection: &mut PgConnection,
    name: &str,
) -> Result<UserWriteSnapshot> {
    let query = format!(
        r#"SELECT {POSTGRES_USER_COLUMNS}, COALESCE(to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'), '') AS updated_at_text, to_char(deleted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS deleted_at_text FROM users WHERE name = $1 AND deleted_at IS NULL ORDER BY id"#
    );
    let rows = sqlx::query_as::<_, UserWriteSnapshot>(&query)
        .bind(name)
        .fetch_all(connection)
        .await?;
    match rows.len() {
        0 => Err(DbError::NotFound(format!("user name={name}"))),
        1 => Ok(rows.into_iter().next().expect("length checked")),
        n => Err(DbError::General(format!(
            "expected exactly one user, found {n}"
        ))),
    }
}

impl UserRow {
    pub fn username(&self) -> String {
        if !self.email.is_empty() {
            self.email.clone()
        } else if !self.name.is_empty() {
            self.name.clone()
        } else if let Some(id) = self
            .provider_identifier
            .as_ref()
            .filter(|id| !id.is_empty())
        {
            id.clone()
        } else {
            self.id.to_string()
        }
    }

    pub fn display(&self) -> String {
        if self.display_name.is_empty() {
            self.username()
        } else {
            self.display_name.clone()
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct CreateParams {
    pub name: String,
    pub display_name: String,
    pub email: String,
    pub provider_identifier: Option<String>,
    pub provider: String,
    pub profile_pic_url: String,
}

#[derive(Debug, Clone, Default)]
pub struct OidcUserParams {
    pub name: String,
    pub display_name: String,
    pub email: String,
    pub provider_identifier: String,
    pub profile_pic_url: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UserError {
    #[error("user name invalid: {0}")]
    InvalidName(String),
    #[error("user already exists")]
    Exists,
    #[error("user not found")]
    NotFound,
    #[error("cannot edit OIDC user")]
    CannotChangeOidcUser,
    #[error("OIDC provider_identifier is required")]
    MissingOidcProviderIdentifier,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn normalize_provider_identifier(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.is_empty())
}

fn normalize_oidc_provider_identifier(value: String) -> std::result::Result<String, UserError> {
    normalize_provider_identifier(Some(value)).ok_or(UserError::MissingOidcProviderIdentifier)
}

pub fn validate_username(name: &str) -> std::result::Result<(), UserError> {
    if name.len() < 2 {
        return Err(UserError::InvalidName(format!(
            "username {name:?} must be at least 2 characters long"
        )));
    }

    let Some(first) = name.chars().next() else {
        return Err(UserError::InvalidName(format!(
            "username {name:?} must be at least 2 characters long"
        )));
    };
    if !first.is_alphabetic() {
        return Err(UserError::InvalidName(format!(
            "username {name:?} must start with a letter"
        )));
    }

    let mut at_count = 0usize;
    for ch in name.chars() {
        match ch {
            '-' | '.' | '_' => {}
            '@' => {
                at_count += 1;
                if at_count > 1 {
                    return Err(UserError::InvalidName(format!(
                        "username {name:?} cannot contain more than one '@'"
                    )));
                }
            }
            _ if ch.is_alphanumeric() => {}
            _ => {
                return Err(UserError::InvalidName(format!(
                    "username {name:?} contains invalid character {ch:?}"
                )));
            }
        }
    }
    Ok(())
}

pub fn validate_hostname(name: &str) -> std::result::Result<(), UserError> {
    validate_username(name)
}

pub async fn create(pool: &SqlitePool, params: CreateParams) -> Result<UserRow> {
    validate_username(&params.name).map_err(|e| DbError::General(e.to_string()))?;
    let provider_identifier = normalize_provider_identifier(params.provider_identifier);
    let now = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);
    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO users
            (name, display_name, email, provider_identifier, provider, profile_pic_url, created_at, updated_at, deleted_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
        RETURNING id
        ",
    )
    .bind(&params.name)
    .bind(&params.display_name)
    .bind(&params.email)
    .bind(&provider_identifier)
    .bind(&params.provider)
    .bind(&params.profile_pic_url)
    .bind(&now)
    .bind(&now)
    .fetch_one(pool)
    .await
    .map_err(map_create_sqlx_err)?;
    get_by_id(pool, id).await
}

pub async fn create_or_update_oidc_user(
    pool: &SqlitePool,
    params: OidcUserParams,
) -> Result<UserRow> {
    create_or_update_oidc_user_for_registration(pool, params)
        .await
        .map(|user| user.row)
}

pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Result<UserRow> {
    let mut conn = pool.acquire().await?;
    get_by_id_on_connection(&mut conn, id).await
}

pub async fn get_by_id_on_connection(conn: &mut SqliteConnection, id: i64) -> Result<UserRow> {
    let query = user_select("WHERE id = ? AND deleted_at IS NULL");
    sqlx::query_as::<_, UserRow>(&query)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(map_not_found)
}

pub async fn get_by_name(pool: &SqlitePool, name: &str) -> Result<UserRow> {
    let mut conn = pool.acquire().await?;
    get_by_name_on_connection(&mut conn, name).await
}

pub async fn get_by_name_on_connection(conn: &mut SqliteConnection, name: &str) -> Result<UserRow> {
    let query = user_select("WHERE name = ? AND deleted_at IS NULL ORDER BY id");
    let rows = sqlx::query_as::<_, UserRow>(&query)
        .bind(name)
        .fetch_all(&mut *conn)
        .await?;
    match rows.len() {
        0 => Err(DbError::NotFound(format!("user name={name}"))),
        1 => Ok(rows.into_iter().next().expect("len checked")),
        n => Err(DbError::General(format!(
            "expected exactly one user, found {n}"
        ))),
    }
}

/// Gorm's association preload batches the referenced users in one query.
pub async fn list_by_ids_on_connection(
    conn: &mut SqliteConnection,
    ids: &[i64],
) -> Result<Vec<UserRow>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut query = sqlx::QueryBuilder::<sqlx::Sqlite>::new(format!(
        "SELECT {USER_COLUMNS} FROM users WHERE deleted_at IS NULL AND id IN ("
    ));
    let mut values = query.separated(", ");
    for id in ids {
        values.push_bind(*id);
    }
    values.push_unseparated(")");
    Ok(query
        .build_query_as::<UserRow>()
        .fetch_all(&mut *conn)
        .await?)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_by_ids_on_connection(
    conn: &mut PgConnection,
    ids: &[i64],
) -> Result<Vec<UserRow>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut query = sqlx::QueryBuilder::<sqlx::Postgres>::new(format!(
        "SELECT {POSTGRES_USER_COLUMNS} FROM users WHERE deleted_at IS NULL AND id IN ("
    ));
    let mut values = query.separated(", ");
    for id in ids {
        values.push_bind(*id);
    }
    values.push_unseparated(")");
    Ok(query
        .build_query_as::<UserRow>()
        .fetch_all(&mut *conn)
        .await?)
}

pub async fn get_by_oidc_identifier(pool: &SqlitePool, id: &str) -> Result<UserRow> {
    let query = user_select("WHERE provider_identifier = ? AND deleted_at IS NULL");
    sqlx::query_as::<_, UserRow>(&query)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(map_not_found)
}

pub async fn list(pool: &SqlitePool) -> Result<Vec<UserRow>> {
    let query = user_select("WHERE deleted_at IS NULL ORDER BY id");
    sqlx::query_as::<_, UserRow>(&query)
        .fetch_all(pool)
        .await
        .map_err(DbError::from)
}

pub async fn rename(pool: &SqlitePool, id: i64, new_name: &str) -> Result<UserRow> {
    validate_username(new_name).map_err(|e| DbError::General(e.to_string()))?;
    let existing = get_by_id(pool, id).await?;
    if existing.provider == REGISTER_METHOD_OIDC {
        return Err(DbError::General(
            UserError::CannotChangeOidcUser.to_string(),
        ));
    }
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE users
        SET name = ?, updated_at = datetime(?, 'unixepoch')
        WHERE id = ? AND deleted_at IS NULL
        ",
    )
    .bind(new_name)
    .bind(now)
    .bind(id)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("user id={id}")));
    }
    get_by_id(pool, id).await
}

pub async fn touch_by_name(pool: &SqlitePool, name: &str) -> Result<()> {
    let now = now_unix();
    sqlx::query(
        "
        UPDATE users
        SET updated_at = datetime(?, 'unixepoch')
        WHERE name = ? AND deleted_at IS NULL
        ",
    )
    .bind(now)
    .bind(name)
    .execute(pool)
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

pub async fn destroy(pool: &SqlitePool, id: i64) -> Result<()> {
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;

    let user = get_by_id_on_connection(&mut tx, id).await?;

    let keys = delete_preloads::load_keys_for_deletion(&mut tx, id).await?;
    for key in keys {
        crate::preauth_keys::destroy_on_connection(&mut tx, key.id).await?;
    }

    // Unscoped Delete(&user) still enforces Gorm's primary-key WHERE guard.
    // Keep this after key cleanup so failures roll back the whole transaction.
    if user.id == 0 {
        return Err(DbError::General("WHERE conditions required".into()));
    }
    sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres(pool: &PgPool, params: CreateParams) -> Result<UserRow> {
    let mut conn = pool.acquire().await?;
    create_postgres_on_connection(&mut conn, params).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_postgres_on_connection(
    conn: &mut PgConnection,
    params: CreateParams,
) -> Result<UserRow> {
    validate_username(&params.name).map_err(|e| DbError::General(e.to_string()))?;
    let provider_identifier = normalize_provider_identifier(params.provider_identifier);
    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO users
            (name, display_name, email, provider_identifier, provider, profile_pic_url, created_at, updated_at, deleted_at)
        VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, NULL)
        RETURNING id
        ",
    )
    .bind(&params.name)
    .bind(&params.display_name)
    .bind(&params.email)
    .bind(&provider_identifier)
    .bind(&params.provider)
    .bind(&params.profile_pic_url)
    .fetch_one(&mut *conn)
    .await
    .map_err(map_create_sqlx_err)?;
    get_postgres_by_id_on_connection(conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_or_update_oidc_user_postgres(
    pool: &PgPool,
    params: OidcUserParams,
) -> Result<UserRow> {
    let mut conn = pool.acquire().await?;
    create_or_update_oidc_user_postgres_on_connection(&mut conn, params).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn create_or_update_oidc_user_postgres_on_connection(
    conn: &mut PgConnection,
    params: OidcUserParams,
) -> Result<UserRow> {
    create_or_update_oidc_user_postgres_for_registration_on_connection(conn, params)
        .await
        .map(|user| user.row)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_id(pool: &PgPool, id: i64) -> Result<UserRow> {
    let mut conn = pool.acquire().await?;
    get_postgres_by_id_on_connection(&mut conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_id_on_connection(conn: &mut PgConnection, id: i64) -> Result<UserRow> {
    let query = postgres_user_select("WHERE id = $1 AND deleted_at IS NULL");
    sqlx::query_as::<_, UserRow>(&query)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(map_not_found)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_name(pool: &PgPool, name: &str) -> Result<UserRow> {
    let mut conn = pool.acquire().await?;
    get_postgres_by_name_on_connection(&mut conn, name).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_name_on_connection(
    conn: &mut PgConnection,
    name: &str,
) -> Result<UserRow> {
    let query = postgres_user_select("WHERE name = $1 AND deleted_at IS NULL ORDER BY id");
    let rows = sqlx::query_as::<_, UserRow>(&query)
        .bind(name)
        .fetch_all(&mut *conn)
        .await?;
    match rows.len() {
        0 => Err(DbError::NotFound(format!("user name={name}"))),
        1 => Ok(rows.into_iter().next().expect("len checked")),
        n => Err(DbError::General(format!(
            "expected exactly one user, found {n}"
        ))),
    }
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_oidc_identifier(pool: &PgPool, id: &str) -> Result<UserRow> {
    let mut conn = pool.acquire().await?;
    get_postgres_by_oidc_identifier_on_connection(&mut conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_oidc_identifier_on_connection(
    conn: &mut PgConnection,
    id: &str,
) -> Result<UserRow> {
    let query = postgres_user_select("WHERE provider_identifier = $1 AND deleted_at IS NULL");
    sqlx::query_as::<_, UserRow>(&query)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(map_not_found)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres(pool: &PgPool) -> Result<Vec<UserRow>> {
    let mut conn = pool.acquire().await?;
    list_postgres_on_connection(&mut conn).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn list_postgres_on_connection(conn: &mut PgConnection) -> Result<Vec<UserRow>> {
    let query = postgres_user_select("WHERE deleted_at IS NULL ORDER BY id");
    sqlx::query_as::<_, UserRow>(&query)
        .fetch_all(&mut *conn)
        .await
        .map_err(DbError::from)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn rename_postgres(pool: &PgPool, id: i64, new_name: &str) -> Result<UserRow> {
    let mut conn = pool.acquire().await?;
    rename_postgres_on_connection(&mut conn, id, new_name).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn rename_postgres_on_connection(
    conn: &mut PgConnection,
    id: i64,
    new_name: &str,
) -> Result<UserRow> {
    validate_username(new_name).map_err(|e| DbError::General(e.to_string()))?;
    let existing = get_postgres_by_id_on_connection(conn, id).await?;
    if existing.provider == REGISTER_METHOD_OIDC {
        return Err(DbError::General(
            UserError::CannotChangeOidcUser.to_string(),
        ));
    }
    let now = now_unix();
    let affected = sqlx::query(
        "
        UPDATE users
        SET name = $1, updated_at = to_timestamp($2)
        WHERE id = $3 AND deleted_at IS NULL
        ",
    )
    .bind(new_name)
    .bind(now)
    .bind(id)
    .execute(&mut *conn)
    .await
    .map_err(map_sqlx_err)?
    .rows_affected();
    if affected == 0 {
        return Err(DbError::NotFound(format!("user id={id}")));
    }
    get_postgres_by_id_on_connection(conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn touch_postgres_by_name(pool: &PgPool, name: &str) -> Result<()> {
    let mut conn = pool.acquire().await?;
    touch_postgres_by_name_on_connection(&mut conn, name).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn touch_postgres_by_name_on_connection(
    conn: &mut PgConnection,
    name: &str,
) -> Result<()> {
    let now = now_unix();
    sqlx::query(
        "
        UPDATE users
        SET updated_at = to_timestamp($1)
        WHERE name = $2 AND deleted_at IS NULL
        ",
    )
    .bind(now)
    .bind(name)
    .execute(&mut *conn)
    .await
    .map_err(map_sqlx_err)?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub async fn destroy_postgres(pool: &PgPool, id: i64) -> Result<()> {
    let mut conn = pool.acquire().await?;
    destroy_postgres_on_connection(&mut conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn destroy_postgres_on_connection(conn: &mut PgConnection, id: i64) -> Result<()> {
    let mut tx = conn.begin().await?;

    let user = get_postgres_by_id_on_connection(&mut tx, id).await?;

    let keys = delete_preloads::load_postgres_keys_for_deletion(&mut tx, id).await?;
    for key in keys {
        crate::preauth_keys::destroy_postgres_on_connection(&mut tx, key.id).await?;
    }

    if user.id == 0 {
        return Err(DbError::General("WHERE conditions required".into()));
    }
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

fn map_not_found(e: sqlx::Error) -> DbError {
    match e {
        sqlx::Error::RowNotFound => DbError::NotFound("user".into()),
        e => DbError::from(e),
    }
}

fn map_sqlx_err(e: sqlx::Error) -> DbError {
    match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            DbError::General(UserError::Exists.to_string())
        }
        _ => DbError::from(e),
    }
}

fn map_create_sqlx_err(e: sqlx::Error) -> DbError {
    match &e {
        sqlx::Error::Database(db) if db.is_unique_violation() => {
            if let Some(message) = headscale_go_sqlite_constraint_message(db.as_ref()) {
                DbError::General(format!("creating user: {message}"))
            } else {
                DbError::General(UserError::Exists.to_string())
            }
        }
        _ => DbError::from(e),
    }
}

fn headscale_go_sqlite_constraint_message(
    db: &(dyn sqlx::error::DatabaseError + 'static),
) -> Option<String> {
    let code = db.code()?;
    let message = db.message();
    if code.as_ref() == "2067" && message.starts_with("UNIQUE constraint failed:") {
        Some(format!("constraint failed: {message} ({code})"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Database,
        headscale_nodes::{self, CreateParams as NodeCreateParams},
        preauth_keys::{self, CreateParams as PreauthCreateParams},
    };
    use serde_json::json;

    async fn fresh_db() -> Database {
        let db = Database::in_memory().await.expect("open in-memory");
        db.migrate().await.expect("migrate");
        db
    }

    fn alice() -> CreateParams {
        CreateParams {
            name: "alice".into(),
            display_name: "Alice Smith".into(),
            email: "alice@example.com".into(),
            provider_identifier: None,
            provider: "cli".into(),
            profile_pic_url: "https://example.com/alice.png".into(),
        }
    }

    #[tokio::test]
    async fn create_matches_headscale_go_row_shape() {
        let db = fresh_db().await;
        let user = create(db.pool(), alice()).await.unwrap();
        assert_eq!(user.id, 1);
        assert_eq!(user.name, "alice");
        assert_eq!(user.display_name, "Alice Smith");
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.provider, "cli");
        assert_eq!(user.profile_pic_url, "https://example.com/alice.png");
        assert!(user.created_at > 0);
        assert_eq!(user.created_at, user.updated_at);

        let (name, created_at, updated_at, deleted_at): (String, i64, i64, Option<i64>) =
            sqlx::query_as(
                "
                SELECT name, unixepoch(created_at), unixepoch(updated_at), unixepoch(deleted_at)
                FROM users
                WHERE id = ?
                ",
            )
            .bind(user.id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(name, "alice");
        assert_eq!(created_at, user.created_at);
        assert_eq!(updated_at, user.updated_at);
        assert_eq!(deleted_at, None);
    }

    #[tokio::test]
    async fn duplicate_create_reports_headscale_go_sqlite_constraint_text() {
        let db = fresh_db().await;
        create(db.pool(), alice()).await.unwrap();

        let err = create(db.pool(), alice()).await.unwrap_err();

        assert!(matches!(
            err,
            DbError::General(msg)
                if msg == "creating user: constraint failed: UNIQUE constraint failed: users.name (2067)"
        ));
    }

    #[tokio::test]
    async fn validates_usernames_like_headscale_go() {
        assert!(validate_username("valid-hostname").is_ok());
        assert!(validate_username("valid.name").is_ok());
        assert!(validate_username("Alice").is_ok());
        assert!(validate_username("alice_smith").is_ok());
        assert!(validate_username("alice@example.com").is_ok());
        assert!(validate_username("alice-").is_ok());
        assert!(validate_username("alice.").is_ok());
        assert!(validate_username(&"a".repeat(64)).is_ok());

        assert!(validate_username("").is_err());
        assert!(validate_username("a").is_err());
        assert!(validate_username("1alice").is_err());
        assert!(validate_username("-alice").is_err());
        assert!(validate_username(".alice").is_err());
        assert!(validate_username("_alice").is_err());
        assert!(validate_username("alice@@example.com").is_err());
        assert!(validate_username("alice smith").is_err());
        assert!(validate_username("alice/slash").is_err());
    }

    #[tokio::test]
    async fn create_and_rename_accept_headscale_go_username_charset() {
        let db = fresh_db().await;
        let user = create(
            db.pool(),
            CreateParams {
                name: "Alice_Example@example.com".into(),
                display_name: "Alice Example".into(),
                email: "alice@example.com".into(),
                provider_identifier: None,
                provider: "cli".into(),
                profile_pic_url: String::new(),
            },
        )
        .await
        .unwrap();

        assert_eq!(
            get_by_name(db.pool(), "Alice_Example@example.com")
                .await
                .unwrap()
                .id,
            user.id
        );

        let renamed = rename(db.pool(), user.id, "Alice-Renamed@example.com")
            .await
            .unwrap();
        assert_eq!(renamed.name, "Alice-Renamed@example.com");
    }

    #[tokio::test]
    async fn list_get_rename_destroy_round_trip() {
        let db = fresh_db().await;
        let user = create(db.pool(), alice()).await.unwrap();
        assert_eq!(get_by_id(db.pool(), user.id).await.unwrap().name, "alice");
        assert_eq!(get_by_name(db.pool(), "alice").await.unwrap().id, user.id);

        let renamed = rename(db.pool(), user.id, "bob").await.unwrap();
        assert_eq!(renamed.name, "bob");
        assert!(renamed.updated_at >= renamed.created_at);
        assert!(get_by_name(db.pool(), "alice").await.is_err());

        let users = list(db.pool()).await.unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0].name, "bob");

        destroy(db.pool(), user.id).await.unwrap();
        assert_eq!(list(db.pool()).await.unwrap().len(), 0);
    }

    #[tokio::test]
    async fn destroy_unknown_id_returns_user_not_found() {
        let db = fresh_db().await;
        let err = destroy(db.pool(), 99_999).await.unwrap_err();

        assert!(matches!(err, DbError::NotFound(msg) if msg == "user"));
    }

    async fn preauth_key_id(db: &Database, user_id: i64) -> i64 {
        preauth_keys::create_for_test(
            db.pool(),
            PreauthCreateParams {
                user_id: user_id.to_string(),
                reusable: false,
                ephemeral: false,
                tags: Vec::new(),
                expiration: None,
            },
        )
        .await
        .unwrap()
        .row
        .id
    }

    /// A well-formed key (`<prefix>:` plus 64 hex digits) derived from `name`;
    /// the node tables reject anything else, as Go's typed keys do.
    fn test_key(prefix: &str, name: &str) -> String {
        use std::fmt::Write as _;
        let mut hex = String::new();
        for byte in name.bytes() {
            write!(hex, "{byte:02x}").unwrap();
        }
        hex.truncate(64);
        format!("{prefix}:{hex:0<64}")
    }

    fn node_params(user_id: Option<i64>, auth_key_id: Option<i64>, name: &str) -> NodeCreateParams {
        NodeCreateParams {
            machine_key: test_key("mkey", name),
            node_key: test_key("nodekey", name),
            disco_key: test_key("discokey", name),
            endpoints: Vec::new(),
            host_info: json!({ "Hostname": name }),
            ipv4: None,
            ipv6: None,
            hostname: name.into(),
            given_name: name.into(),
            user_id,
            register_method: headscale_nodes::REGISTER_METHOD_AUTH_KEY.into(),
            tags: Vec::new(),
            auth_key_id,
            expiry: None,
            expiry_precise: None,
            last_seen: None,
            last_seen_precise: None,
            approved_routes: Vec::new(),
        }
    }

    #[tokio::test]
    async fn destroy_refuses_user_with_owned_nodes() {
        let db = fresh_db().await;
        let user = create(db.pool(), alice()).await.unwrap();
        let key_id = preauth_key_id(&db, user.id).await;
        headscale_nodes::create(
            db.pool(),
            node_params(Some(user.id), Some(key_id), "owned-node"),
        )
        .await
        .unwrap();

        let err = destroy(db.pool(), user.id).await.unwrap_err();
        assert!(matches!(err, DbError::Constraint(_)));
        assert_eq!(get_by_id(db.pool(), user.id).await.unwrap().id, user.id);
        assert_eq!(
            preauth_keys::get_by_id(db.pool(), key_id).await.unwrap().id,
            key_id
        );
    }

    #[tokio::test]
    async fn destroy_cleans_preauth_keys_and_clears_tagged_node_auth_key_id() {
        let db = fresh_db().await;
        let user = create(db.pool(), alice()).await.unwrap();
        let key_id = preauth_key_id(&db, user.id).await;
        let tagged = headscale_nodes::create(
            db.pool(),
            NodeCreateParams {
                tags: vec!["tag:server".into()],
                ..node_params(None, Some(key_id), "tagged-node")
            },
        )
        .await
        .unwrap();

        destroy(db.pool(), user.id).await.unwrap();

        assert!(matches!(
            preauth_keys::get_by_id(db.pool(), key_id)
                .await
                .unwrap_err(),
            DbError::NotFound(_)
        ));
        assert_eq!(
            headscale_nodes::get_by_id(db.pool(), tagged.id)
                .await
                .unwrap()
                .auth_key_id,
            None
        );
        assert!(matches!(
            get_by_id(db.pool(), user.id).await.unwrap_err(),
            DbError::NotFound(_)
        ));
    }

    #[tokio::test]
    async fn destroy_deletes_only_target_users_preauth_keys() {
        let db = fresh_db().await;
        let alice = create(db.pool(), alice()).await.unwrap();
        let bob = create(
            db.pool(),
            CreateParams {
                name: "bob".into(),
                display_name: "Bob".into(),
                email: "bob@example.com".into(),
                provider_identifier: None,
                provider: headscale_nodes::REGISTER_METHOD_CLI.into(),
                profile_pic_url: String::new(),
            },
        )
        .await
        .unwrap();
        let alice_key = preauth_key_id(&db, alice.id).await;
        let bob_key = preauth_key_id(&db, bob.id).await;

        destroy(db.pool(), bob.id).await.unwrap();

        assert!(matches!(
            preauth_keys::get_by_id(db.pool(), bob_key)
                .await
                .unwrap_err(),
            DbError::NotFound(_)
        ));
        assert_eq!(
            preauth_keys::get_by_id(db.pool(), alice_key)
                .await
                .unwrap()
                .id,
            alice_key
        );
        assert_eq!(get_by_id(db.pool(), alice.id).await.unwrap().id, alice.id);
    }

    #[tokio::test]
    async fn uniqueness_matches_headscale_go_indexes() {
        let db = fresh_db().await;
        create(db.pool(), alice()).await.unwrap();
        assert!(create(db.pool(), alice()).await.is_err());

        let oidc_a = CreateParams {
            name: "same".into(),
            provider_identifier: Some("issuer/a".into()),
            provider: REGISTER_METHOD_OIDC.into(),
            ..CreateParams::default()
        };
        let oidc_b = CreateParams {
            name: "same".into(),
            provider_identifier: Some("issuer/b".into()),
            provider: REGISTER_METHOD_OIDC.into(),
            ..CreateParams::default()
        };
        create(db.pool(), oidc_a.clone()).await.unwrap();
        create(db.pool(), oidc_b).await.unwrap();

        let duplicate_provider = CreateParams {
            name: "other".into(),
            ..oidc_a
        };
        assert!(create(db.pool(), duplicate_provider).await.is_err());
    }

    #[tokio::test]
    async fn get_by_name_reports_ambiguous_oidc_names_like_go() {
        let db = fresh_db().await;
        create(
            db.pool(),
            CreateParams {
                name: "same".into(),
                provider_identifier: Some("issuer/a".into()),
                provider: REGISTER_METHOD_OIDC.into(),
                ..CreateParams::default()
            },
        )
        .await
        .unwrap();
        create(
            db.pool(),
            CreateParams {
                name: "same".into(),
                provider_identifier: Some("issuer/b".into()),
                provider: REGISTER_METHOD_OIDC.into(),
                ..CreateParams::default()
            },
        )
        .await
        .unwrap();

        assert!(matches!(
            get_by_name(db.pool(), "same").await.unwrap_err(),
            DbError::General(_)
        ));
    }

    #[tokio::test]
    async fn oidc_lookup_and_rename_rejection() {
        let db = fresh_db().await;
        let user = create(
            db.pool(),
            CreateParams {
                name: "oidc-user".into(),
                email: "oidc@example.com".into(),
                display_name: "OIDC User".into(),
                provider_identifier: Some("https://issuer/sub".into()),
                provider: REGISTER_METHOD_OIDC.into(),
                profile_pic_url: String::new(),
            },
        )
        .await
        .unwrap();
        assert_eq!(
            get_by_oidc_identifier(db.pool(), "https://issuer/sub")
                .await
                .unwrap()
                .id,
            user.id
        );
        assert!(rename(db.pool(), user.id, "new-name").await.is_err());
    }

    #[tokio::test]
    async fn oidc_upsert_creates_user_without_hostname_name() {
        let db = fresh_db().await;
        let user = create_or_update_oidc_user(
            db.pool(),
            OidcUserParams {
                email: "oidc@example.com".into(),
                display_name: "OIDC User".into(),
                provider_identifier: "https://issuer/sub".into(),
                profile_pic_url: "https://example.com/oidc.png".into(),
                ..OidcUserParams::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(user.name, "");
        assert_eq!(user.username(), "oidc@example.com");
        assert_eq!(user.display(), "OIDC User");
        assert_eq!(user.email, "oidc@example.com");
        assert_eq!(
            user.provider_identifier.as_deref(),
            Some("https://issuer/sub")
        );
        assert_eq!(user.provider, REGISTER_METHOD_OIDC);
        assert_eq!(user.profile_pic_url, "https://example.com/oidc.png");
        assert_eq!(
            get_by_oidc_identifier(db.pool(), "https://issuer/sub")
                .await
                .unwrap()
                .id,
            user.id
        );
    }

    #[tokio::test]
    async fn oidc_upsert_updates_profile_like_headscale_go_from_claim() {
        let db = fresh_db().await;
        let original = create_or_update_oidc_user(
            db.pool(),
            OidcUserParams {
                name: "oidc-user".into(),
                email: "old@example.com".into(),
                display_name: "Old Name".into(),
                provider_identifier: "issuer/sub".into(),
                profile_pic_url: "https://example.com/old.png".into(),
            },
        )
        .await
        .unwrap();

        let updated = create_or_update_oidc_user(
            db.pool(),
            OidcUserParams {
                display_name: "New Name".into(),
                provider_identifier: "issuer/sub".into(),
                ..OidcUserParams::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(updated.id, original.id);
        assert_eq!(updated.name, "oidc-user");
        assert_eq!(updated.email, "old@example.com");
        assert_eq!(updated.display_name, "New Name");
        assert_eq!(updated.profile_pic_url, "");
        assert_eq!(updated.provider_identifier.as_deref(), Some("issuer/sub"));
        assert_eq!(updated.provider, REGISTER_METHOD_OIDC);
        assert!(updated.updated_at >= original.updated_at);
        assert_eq!(list(db.pool()).await.unwrap().len(), 1);

        let cleared_profile = create_or_update_oidc_user(
            db.pool(),
            OidcUserParams {
                provider_identifier: "issuer/sub".into(),
                ..OidcUserParams::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(cleared_profile.id, original.id);
        assert_eq!(cleared_profile.name, "oidc-user");
        assert_eq!(cleared_profile.email, "old@example.com");
        assert_eq!(cleared_profile.display_name, "");
        assert_eq!(cleared_profile.profile_pic_url, "");
    }

    #[tokio::test]
    async fn oidc_upsert_requires_provider_identifier() {
        let db = fresh_db().await;
        assert!(matches!(
            create_or_update_oidc_user(db.pool(), OidcUserParams::default())
                .await
                .unwrap_err(),
            DbError::General(_)
        ));
    }

    #[tokio::test]
    async fn list_ignores_soft_deleted_go_rows() {
        let db = fresh_db().await;
        let now = now_unix();
        sqlx::query(
            "
            INSERT INTO users (name, created_at, updated_at, deleted_at)
            VALUES (?, datetime(?, 'unixepoch'), datetime(?, 'unixepoch'), datetime(?, 'unixepoch'))
            ",
        )
        .bind("deleted")
        .bind(now)
        .bind(now)
        .bind(now)
        .execute(db.pool())
        .await
        .unwrap();
        assert_eq!(list(db.pool()).await.unwrap().len(), 0);
    }
}
