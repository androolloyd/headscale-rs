//! Headscale-go-compatible policy persistence.
//!
//! Upstream stores policy history in a `policies` table with GORM's
//! standard timestamp/soft-delete columns and raw HuJSON `data`. Each
//! update appends a new row; reads return the newest non-deleted row.

use crate::{DbError, Result};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
#[cfg(feature = "postgres-sqlx")]
use sqlx::{PgConnection, PgPool};

const POLICY_COLUMNS: &str = r"
        id,
        COALESCE(data, '') AS data,
        CASE
            WHEN created_at IS NULL THEN 0
            WHEN typeof(created_at) = 'integer' THEN created_at
            ELSE unixepoch(created_at)
        END AS created_at,
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

fn policy_select(suffix: &str) -> String {
    format!("SELECT {POLICY_COLUMNS} FROM policies {suffix}")
}

#[cfg(feature = "postgres-sqlx")]
const POSTGRES_POLICY_COLUMNS: &str = r"
        id,
        COALESCE(data, '') AS data,
        COALESCE(FLOOR(EXTRACT(EPOCH FROM created_at))::BIGINT, 0) AS created_at,
        COALESCE(FLOOR(EXTRACT(EPOCH FROM updated_at))::BIGINT, 0) AS updated_at,
        FLOOR(EXTRACT(EPOCH FROM deleted_at))::BIGINT AS deleted_at
";

#[cfg(feature = "postgres-sqlx")]
fn postgres_policy_select(suffix: &str) -> String {
    format!("SELECT {POSTGRES_POLICY_COLUMNS} FROM policies {suffix}")
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRow {
    pub id: i64,
    pub data: String,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted_at: Option<i64>,
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

pub async fn set(pool: &SqlitePool, data: &str) -> Result<PolicyRow> {
    let now = now_unix();
    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO policies (data, created_at, updated_at, deleted_at)
        VALUES (?, datetime(?, 'unixepoch'), datetime(?, 'unixepoch'), NULL)
        RETURNING id
        ",
    )
    .bind(data)
    .bind(now)
    .bind(now)
    .fetch_one(pool)
    .await?;

    get_by_id(pool, id).await
}

pub async fn get_latest(pool: &SqlitePool) -> Result<Option<PolicyRow>> {
    let query = policy_select("WHERE deleted_at IS NULL ORDER BY id DESC LIMIT 1");
    sqlx::query_as::<_, PolicyRow>(&query)
        .fetch_optional(pool)
        .await
        .map_err(DbError::from)
}

pub async fn get_by_id(pool: &SqlitePool, id: i64) -> Result<PolicyRow> {
    let query = policy_select("WHERE id = ? AND deleted_at IS NULL");
    sqlx::query_as::<_, PolicyRow>(&query)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => DbError::NotFound(format!("policy id={id}")),
            e => DbError::from(e),
        })
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres(pool: &PgPool, data: &str) -> Result<PolicyRow> {
    let now = now_unix();
    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO policies (data, created_at, updated_at, deleted_at)
        VALUES ($1, to_timestamp($2), to_timestamp($2), NULL)
        RETURNING id
        ",
    )
    .bind(data)
    .bind(now)
    .fetch_one(pool)
    .await?;

    get_postgres_by_id(pool, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn set_postgres_on_connection(conn: &mut PgConnection, data: &str) -> Result<PolicyRow> {
    let now = now_unix();
    let id: i64 = sqlx::query_scalar(
        "
        INSERT INTO policies (data, created_at, updated_at, deleted_at)
        VALUES ($1, to_timestamp($2), to_timestamp($2), NULL)
        RETURNING id
        ",
    )
    .bind(data)
    .bind(now)
    .fetch_one(&mut *conn)
    .await?;

    get_postgres_by_id_on_connection(conn, id).await
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_latest_postgres(pool: &PgPool) -> Result<Option<PolicyRow>> {
    let query = postgres_policy_select("WHERE deleted_at IS NULL ORDER BY id DESC LIMIT 1");
    sqlx::query_as::<_, PolicyRow>(&query)
        .fetch_optional(pool)
        .await
        .map_err(DbError::from)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_latest_postgres_on_connection(
    conn: &mut PgConnection,
) -> Result<Option<PolicyRow>> {
    let query = postgres_policy_select("WHERE deleted_at IS NULL ORDER BY id DESC LIMIT 1");
    sqlx::query_as::<_, PolicyRow>(&query)
        .fetch_optional(&mut *conn)
        .await
        .map_err(DbError::from)
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_id(pool: &PgPool, id: i64) -> Result<PolicyRow> {
    let query = postgres_policy_select("WHERE id = $1 AND deleted_at IS NULL");
    sqlx::query_as::<_, PolicyRow>(&query)
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => DbError::NotFound(format!("policy id={id}")),
            e => DbError::from(e),
        })
}

#[cfg(feature = "postgres-sqlx")]
pub async fn get_postgres_by_id_on_connection(
    conn: &mut PgConnection,
    id: i64,
) -> Result<PolicyRow> {
    let query = postgres_policy_select("WHERE id = $1 AND deleted_at IS NULL");
    sqlx::query_as::<_, PolicyRow>(&query)
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| match e {
            sqlx::Error::RowNotFound => DbError::NotFound(format!("policy id={id}")),
            e => DbError::from(e),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database;
    use sqlx::Row;

    async fn fresh_db() -> Database {
        let db = Database::in_memory().await.expect("open in-memory");
        db.migrate().await.expect("migrate");
        db
    }

    #[tokio::test]
    async fn get_latest_empty_returns_none() {
        let db = fresh_db().await;
        assert!(get_latest(db.pool()).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn set_appends_and_get_latest_returns_newest_raw_policy() {
        let db = fresh_db().await;
        let first = set(db.pool(), "{\n  // first\n  \"acls\": []\n}")
            .await
            .unwrap();
        let second = set(db.pool(), "{\n  // second\n  \"acls\": []\n}")
            .await
            .unwrap();

        assert!(second.id > first.id);
        let latest = get_latest(db.pool()).await.unwrap().expect("latest policy");
        assert_eq!(latest.id, second.id);
        assert_eq!(latest.data, "{\n  // second\n  \"acls\": []\n}");
        assert_eq!(latest.created_at, latest.updated_at);
        assert!(latest.deleted_at.is_none());

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 2);

        let raw = sqlx::query("SELECT typeof(created_at) AS ty FROM policies WHERE id = ?")
            .bind(second.id)
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(raw.get::<String, _>("ty"), "text");
    }

    #[tokio::test]
    async fn get_latest_ignores_soft_deleted_rows() {
        let db = fresh_db().await;
        let first = set(db.pool(), "first").await.unwrap();
        let second = set(db.pool(), "second").await.unwrap();
        sqlx::query("UPDATE policies SET deleted_at = datetime('now') WHERE id = ?")
            .bind(second.id)
            .execute(db.pool())
            .await
            .unwrap();

        let latest = get_latest(db.pool()).await.unwrap().expect("latest policy");
        assert_eq!(latest.id, first.id);
        assert_eq!(latest.data, "first");
    }
}
