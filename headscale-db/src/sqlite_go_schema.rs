//! Pinned headscale-go v0.29.5 primary schema with Rust-only data in a sidecar.

use crate::Result;
use sqlx::SqlitePool;

pub(crate) const GO_SCHEMA: &str = include_str!("../schema/headscale-go-v0295.sql");
const RUST_AUX_SCHEMA: &str = include_str!("../schema/rust-aux.sql");

// IDs observed in a fresh database created by the pinned v0.29.5 executable.
// They are required so Go does not try to replay historical migrations onto
// the already-current primary schema.
pub(crate) const GO_MIGRATIONS: &[&str] = &[
    "SCHEMA_INIT",
    "202501221827",
    "202501311657",
    "202502070949",
    "202502131714",
    "202502171819",
    "202505091439",
    "202505141324",
    "202507021200",
    "202510311551",
    "202511011637-preauthkey-bcrypt",
    "202511101554-drop-old-idx",
    "202511122344-remove-newline-index",
    "202511131445-node-forced-tags-to-tags",
    "202601121700-migrate-hostinfo-request-tags",
    "202602201200-clear-tagged-node-user-id",
    "202605221435-clear-zero-time-node-expiry",
    "202606181200-recover-null-tags-node-user-id",
    "202607241200-clear-tagged-node-expiry",
];

pub(crate) async fn has_auxiliary_database(pool: &SqlitePool) -> Result<bool> {
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pragma_database_list WHERE name = 'rust_aux'")
            .fetch_one(pool)
            .await?;
    Ok(count == 1)
}

pub(crate) async fn initialize_fresh_primary(pool: &SqlitePool) -> Result<()> {
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::raw_sql(GO_SCHEMA).execute(&mut *transaction).await?;
    for id in GO_MIGRATIONS {
        sqlx::query("INSERT INTO migrations (id) VALUES (?)")
            .bind(id)
            .execute(&mut *transaction)
            .await?;
    }
    sqlx::query(
        "INSERT INTO database_versions (id, version, updated_at) \
         VALUES (1, 'v0.29.5', CURRENT_TIMESTAMP)",
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

pub(crate) async fn initialize_auxiliary(pool: &SqlitePool) -> Result<()> {
    sqlx::raw_sql(RUST_AUX_SCHEMA).execute(pool).await?;
    Ok(())
}
