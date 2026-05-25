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
pub use version_guard::{
    HEADSCALE_GO_CURRENT_VERSION, HEADSCALE_GO_IMPORT_BASELINE, HeadscaleGoImportCompatibility,
};

/// Supported database-backend matrix for headscale-db.
///
/// headscale-go v0.28 supports SQLite and Postgres. This crate is
/// intentionally SQLite-only today because the import/migration guard
/// validates SQLite migration histories and the compiled sqlx backend is
/// `sqlite`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatabaseBackendSupport {
    pub upstream_name: &'static str,
    pub url_schemes: &'static [&'static str],
    pub headscale_go_supported: bool,
    pub headscale_db_supported: bool,
    pub sqlite_import_supported: bool,
}

pub const DATABASE_BACKEND_MATRIX: &[DatabaseBackendSupport] = &[
    DatabaseBackendSupport {
        upstream_name: "sqlite3",
        url_schemes: &["sqlite"],
        headscale_go_supported: true,
        headscale_db_supported: true,
        sqlite_import_supported: true,
    },
    DatabaseBackendSupport {
        upstream_name: "postgres",
        url_schemes: &["postgres", "postgresql"],
        headscale_go_supported: true,
        headscale_db_supported: false,
        sqlite_import_supported: false,
    },
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SqliteOpenOptions {
    pub write_ahead_log: Option<bool>,
    pub wal_autocheckpoint: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseBackend {
    Sqlite,
    Postgres,
}

impl DatabaseBackend {
    pub fn from_url(url: &str) -> Option<Self> {
        url.split_once(':')
            .and_then(|(scheme, _)| Self::from_url_scheme(scheme))
    }

    pub fn from_url_scheme(scheme: &str) -> Option<Self> {
        match scheme {
            "sqlite" => Some(Self::Sqlite),
            "postgres" | "postgresql" => Some(Self::Postgres),
            _ => None,
        }
    }

    pub const fn upstream_name(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite3",
            Self::Postgres => "postgres",
        }
    }

    pub const fn url_schemes(self) -> &'static [&'static str] {
        match self {
            Self::Sqlite => &["sqlite"],
            Self::Postgres => &["postgres", "postgresql"],
        }
    }

    pub const fn headscale_go_supported(self) -> bool {
        true
    }

    pub const fn headscale_db_supported(self) -> bool {
        matches!(self, Self::Sqlite)
    }

    pub const fn sqlite_import_supported(self) -> bool {
        matches!(self, Self::Sqlite)
    }

    pub const fn sqlx_driver_compiled(self) -> bool {
        match self {
            Self::Sqlite => true,
            Self::Postgres => cfg!(feature = "postgres-sqlx"),
        }
    }
}

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
        Self::new_with_sqlite_options(url, SqliteOpenOptions::default()).await
    }

    /// Create a new SQLite database connection with runtime PRAGMA options.
    pub async fn new_with_sqlite_options(url: &str, options: SqliteOpenOptions) -> Result<Self> {
        match DatabaseBackend::from_url(url) {
            Some(DatabaseBackend::Sqlite) => {}
            Some(DatabaseBackend::Postgres) => {
                return Err(DbError::UnsupportedDatabaseBackend(
                    "postgres is supported by headscale-go, but headscale-db currently supports SQLite URLs only".into(),
                ));
            }
            None => {
                return Err(DbError::UnsupportedDatabaseBackend(
                    "expected a sqlite: URL; supported headscale-db backend matrix is SQLite only"
                        .into(),
                ));
            }
        }

        // `Duration::from_mins(5)` would be more readable, but it's the
        // unstable `duration_constructors` API which trips E0658 on
        // Rust toolchains older than 1.95 (the downstream octra
        // workspace path-deps this crate and CI there runs stable
        // 1.88). Keep `from_secs` until 1.95+ is the floor.
        #[allow(unknown_lints, clippy::duration_suboptimal_units)]
        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .idle_timeout(Duration::from_secs(300))
            .after_connect(move |conn, _meta| {
                Box::pin(async move {
                    if let Some(write_ahead_log) = options.write_ahead_log {
                        let journal_mode = if write_ahead_log { "WAL" } else { "DELETE" };
                        sqlx::query(&format!("PRAGMA journal_mode = {journal_mode}"))
                            .execute(&mut *conn)
                            .await?;
                    }
                    if let Some(wal_autocheckpoint) = options.wal_autocheckpoint {
                        sqlx::query(&format!("PRAGMA wal_autocheckpoint = {wal_autocheckpoint}"))
                            .execute(&mut *conn)
                            .await?;
                    }
                    sqlx::query("PRAGMA foreign_keys = ON")
                        .execute(&mut *conn)
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
        version_guard::stamp_rust_managed_database_version(&self.pool).await?;
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

    #[tokio::test]
    async fn sqlite_open_options_apply_wal_and_checkpoint_pragmas() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headscale.sqlite");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let db = Database::new_with_sqlite_options(
            &url,
            SqliteOpenOptions {
                write_ahead_log: Some(true),
                wal_autocheckpoint: Some(37),
            },
        )
        .await
        .unwrap();

        let journal_mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let wal_autocheckpoint: i64 = sqlx::query_scalar("PRAGMA wal_autocheckpoint")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(db.pool())
            .await
            .unwrap();

        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(wal_autocheckpoint, 37);
        assert_eq!(foreign_keys, 1);
    }

    #[tokio::test]
    async fn postgres_urls_are_rejected_clearly() {
        for url in [
            "postgres://localhost/headscale",
            "postgresql://localhost/headscale",
        ] {
            let Err(err) = Database::new(url).await else {
                panic!("{url} should be rejected by headscale-db");
            };

            assert!(matches!(err, DbError::UnsupportedDatabaseBackend(_)));
            assert!(err.to_string().contains("postgres"));
            assert!(err.to_string().contains("SQLite URLs only"));
        }
    }

    #[test]
    fn database_backend_classifies_supported_url_schemes_without_enabling_postgres_runtime() {
        assert_eq!(
            DatabaseBackend::from_url("sqlite::memory:"),
            Some(DatabaseBackend::Sqlite)
        );
        assert_eq!(
            DatabaseBackend::from_url("postgres://localhost/headscale"),
            Some(DatabaseBackend::Postgres)
        );
        assert_eq!(
            DatabaseBackend::from_url("postgresql://localhost/headscale"),
            Some(DatabaseBackend::Postgres)
        );
        assert_eq!(
            DatabaseBackend::from_url("mysql://localhost/headscale"),
            None
        );

        assert!(DatabaseBackend::Sqlite.headscale_go_supported());
        assert!(DatabaseBackend::Sqlite.headscale_db_supported());
        assert!(DatabaseBackend::Sqlite.sqlite_import_supported());
        assert!(DatabaseBackend::Sqlite.sqlx_driver_compiled());
        assert_eq!(DatabaseBackend::Sqlite.upstream_name(), "sqlite3");
        assert_eq!(DatabaseBackend::Sqlite.url_schemes(), &["sqlite"]);

        assert!(DatabaseBackend::Postgres.headscale_go_supported());
        assert!(!DatabaseBackend::Postgres.headscale_db_supported());
        assert!(!DatabaseBackend::Postgres.sqlite_import_supported());
        assert_eq!(DatabaseBackend::Postgres.upstream_name(), "postgres");
        assert_eq!(
            DatabaseBackend::Postgres.url_schemes(),
            &["postgres", "postgresql"]
        );
    }
}
