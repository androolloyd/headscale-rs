//! Database persistence layer for headscale-rs.
//!
//! This crate provides SQLite-based persistence for nodes, transactions,
//! resources, and sessions using sqlx for connection pooling and migrations.

use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Pool, Sqlite, SqlitePool};
use std::time::Duration;

pub mod api_keys;
pub mod error;
pub mod headscale_nodes;
pub mod models;
pub mod nodes;
pub mod payments;
pub mod policies;
pub mod preauth_keys;
pub mod resources;
pub mod sessions;
pub mod users;
mod version_guard;

pub use error::{DbError, Result};
pub use version_guard::{HEADSCALE_GO_IMPORT_BASELINE, HeadscaleGoImportCompatibility};

/// Database connection pool and operations.
pub struct Database {
    pool: Pool<Sqlite>,
}

impl Database {
    /// Create a new database connection.
    ///
    /// # Arguments
    /// * `url` - Database URL (e.g., "sqlite://headscale.db" or "sqlite::memory:")
    pub async fn new(url: &str) -> Result<Self> {
        // `Duration::from_mins(5)` would be more readable, but it's the
        // unstable `duration_constructors` API which trips E0658 on
        // Rust toolchains older than 1.95 (the downstream octra
        // workspace path-deps this crate and CI there runs stable
        // 1.88). Keep `from_secs` until 1.95+ is the floor.
        #[allow(unknown_lints, clippy::duration_suboptimal_units)]
        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .idle_timeout(Duration::from_secs(300))
            .after_connect(|conn, _meta| {
                Box::pin(async move {
                    sqlx::query("PRAGMA foreign_keys = ON")
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(url)
            .await?;

        Ok(Self { pool })
    }

    /// Create a new in-memory database (useful for testing).
    pub async fn in_memory() -> Result<Self> {
        Self::new("sqlite::memory:").await
    }

    /// Run database migrations.
    pub async fn migrate(&self) -> Result<()> {
        version_guard::check_headscale_go_import_compatibility(&self.pool).await?;
        sqlx::migrate!("./migrations").run(&self.pool).await?;
        Ok(())
    }

    /// Check whether an existing SQLite database is within the
    /// supported headscale-go import window.
    pub async fn check_headscale_go_import_compatibility(
        &self,
    ) -> Result<HeadscaleGoImportCompatibility> {
        version_guard::check_headscale_go_import_compatibility(&self.pool).await
    }

    /// Get a reference to the connection pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Close the database connection pool.
    pub async fn close(self) {
        self.pool.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_creation() {
        let db = Database::in_memory().await.unwrap();
        db.migrate().await.unwrap();
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(foreign_keys, 1);
        db.close().await;
    }
}
