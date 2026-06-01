//! Database persistence layer for headscale-rs.
//!
//! This crate provides SQLite-based persistence for nodes, transactions,
//! resources, and sessions using sqlx for connection pooling and migrations.
//! With the `postgres-sqlx` feature, it also exposes a narrow Postgres
//! foundation API for schema parity smoke tests. That API does not enable
//! Postgres use through the server/runtime `Database` type.

use sqlx::SqlitePool;
#[cfg(feature = "postgres-sqlx")]
use sqlx::postgres::PgPoolOptions;
use sqlx::sqlite::{
    SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
#[cfg(feature = "postgres-sqlx")]
pub use sqlx::{PgConnection, PgPool};
use std::str::FromStr;
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
/// headscale-go supports SQLite and Postgres. This crate's runtime `Database`
/// type is intentionally SQLite-only today because the import/migration guard
/// validates SQLite migration histories and the compiled runtime backend is
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteAutoVacuumMode {
    None,
    Full,
    Incremental,
}

impl From<SqliteAutoVacuumMode> for SqliteAutoVacuum {
    fn from(value: SqliteAutoVacuumMode) -> Self {
        match value {
            SqliteAutoVacuumMode::None => Self::None,
            SqliteAutoVacuumMode::Full => Self::Full,
            SqliteAutoVacuumMode::Incremental => Self::Incremental,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqliteSynchronousMode {
    Off,
    Normal,
    Full,
    Extra,
}

impl From<SqliteSynchronousMode> for SqliteSynchronous {
    fn from(value: SqliteSynchronousMode) -> Self {
        match value {
            SqliteSynchronousMode::Off => Self::Off,
            SqliteSynchronousMode::Normal => Self::Normal,
            SqliteSynchronousMode::Full => Self::Full,
            SqliteSynchronousMode::Extra => Self::Extra,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqliteOpenOptions {
    pub write_ahead_log: Option<bool>,
    pub wal_autocheckpoint: Option<u32>,
    pub busy_timeout: Option<Duration>,
    pub auto_vacuum: Option<SqliteAutoVacuumMode>,
    pub synchronous: Option<SqliteSynchronousMode>,
    pub foreign_keys: Option<bool>,
}

impl Default for SqliteOpenOptions {
    fn default() -> Self {
        Self {
            write_ahead_log: Some(true),
            wal_autocheckpoint: Some(1000),
            busy_timeout: Some(Duration::from_secs(10)),
            auto_vacuum: Some(SqliteAutoVacuumMode::Incremental),
            synchronous: Some(SqliteSynchronousMode::Normal),
            foreign_keys: Some(true),
        }
    }
}

impl SqliteOpenOptions {
    pub const fn memory() -> Self {
        Self {
            write_ahead_log: None,
            wal_autocheckpoint: None,
            busy_timeout: None,
            auto_vacuum: None,
            synchronous: None,
            foreign_keys: Some(true),
        }
    }
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

    pub const fn headscale_db_foundation_supported(self) -> bool {
        match self {
            Self::Sqlite => true,
            Self::Postgres => cfg!(feature = "postgres-sqlx"),
        }
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
    pool: DatabasePool,
}

enum DatabasePool {
    Sqlite(SqlitePool),
}

impl DatabasePool {
    const fn backend(&self) -> DatabaseBackend {
        match self {
            Self::Sqlite(_) => DatabaseBackend::Sqlite,
        }
    }

    fn sqlite(&self) -> &SqlitePool {
        match self {
            Self::Sqlite(pool) => pool,
        }
    }

    async fn migrate(&self) -> Result<()> {
        match self {
            Self::Sqlite(pool) => {
                version_guard::check_headscale_go_import_compatibility(pool).await?;
                sqlx::migrate!("./migrations").run(pool).await?;
                version_guard::stamp_rust_managed_database_version(pool).await?;
                Ok(())
            }
        }
    }

    async fn check_headscale_go_import_compatibility(
        &self,
    ) -> Result<HeadscaleGoImportCompatibility> {
        match self {
            Self::Sqlite(pool) => {
                version_guard::check_headscale_go_import_compatibility(pool).await
            }
        }
    }

    async fn close(self) {
        match self {
            Self::Sqlite(pool) => pool.close().await,
        }
    }
}

impl Database {
    /// Create a new database connection.
    ///
    /// # Arguments
    /// * `url` - Database URL (e.g., "sqlite://headscale.db" or "sqlite::memory:")
    pub async fn new(url: &str) -> Result<Self> {
        let options = if sqlite_url_is_memory(url) {
            SqliteOpenOptions::memory()
        } else {
            SqliteOpenOptions::default()
        };
        Self::new_with_sqlite_options(url, options).await
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

        let sqlite_options = sqlite_connect_options(url, options)?;

        // `Duration::from_mins(5)` would be more readable, but it's the
        // unstable `duration_constructors` API which trips E0658 on
        // Rust toolchains older than 1.95 (the downstream octra
        // workspace path-deps this crate and CI there runs stable
        // 1.88). Keep `from_secs` until 1.95+ is the floor.
        #[allow(unknown_lints, clippy::duration_suboptimal_units)]
        let pool = SqlitePoolOptions::new()
            .max_connections(10)
            .idle_timeout(Duration::from_secs(300))
            .connect_with(sqlite_options)
            .await?;

        Ok(Self {
            pool: DatabasePool::Sqlite(pool),
        })
    }

    /// Create a new in-memory database (useful for testing).
    pub async fn in_memory() -> Result<Self> {
        Self::new_with_sqlite_options("sqlite::memory:", SqliteOpenOptions::memory()).await
    }

    /// Run database migrations.
    pub async fn migrate(&self) -> Result<()> {
        self.pool.migrate().await
    }

    /// Check whether an existing SQLite database is within the
    /// supported headscale-go import window.
    pub async fn check_headscale_go_import_compatibility(
        &self,
    ) -> Result<HeadscaleGoImportCompatibility> {
        self.pool.check_headscale_go_import_compatibility().await
    }

    /// Get a reference to the connection pool.
    pub fn pool(&self) -> &SqlitePool {
        self.pool.sqlite()
    }

    /// Get the runtime database backend.
    pub fn backend(&self) -> DatabaseBackend {
        self.pool.backend()
    }

    /// Close the database connection pool.
    pub async fn close(self) {
        self.pool.close().await;
    }
}

fn sqlite_connect_options(url: &str, options: SqliteOpenOptions) -> Result<SqliteConnectOptions> {
    let mut connect_options = SqliteConnectOptions::from_str(url)?;
    if let Some(timeout) = options.busy_timeout {
        connect_options = connect_options.busy_timeout(timeout);
    }
    if let Some(auto_vacuum) = options.auto_vacuum {
        connect_options = connect_options.auto_vacuum(auto_vacuum.into());
    }
    if let Some(write_ahead_log) = options.write_ahead_log {
        connect_options = connect_options.journal_mode(if write_ahead_log {
            SqliteJournalMode::Wal
        } else {
            SqliteJournalMode::Delete
        });
    }
    if let Some(foreign_keys) = options.foreign_keys {
        connect_options = connect_options.foreign_keys(foreign_keys);
    }
    if let Some(synchronous) = options.synchronous {
        connect_options = connect_options.synchronous(synchronous.into());
    }
    if let Some(wal_autocheckpoint) = options.wal_autocheckpoint {
        connect_options =
            connect_options.pragma("wal_autocheckpoint", wal_autocheckpoint.to_string());
    }
    Ok(connect_options)
}

fn sqlite_url_is_memory(url: &str) -> bool {
    url == "sqlite::memory:" || url.contains("mode=memory")
}

/// Open a Postgres pool for foundation-only parity checks.
///
/// This is intentionally separate from [`Database`]. The headscale server
/// runtime remains SQLite-only until the higher-level stores are ported.
#[cfg(feature = "postgres-sqlx")]
pub async fn open_postgres_pool(url: &str) -> Result<PgPool> {
    match DatabaseBackend::from_url(url) {
        Some(DatabaseBackend::Postgres) => {}
        Some(DatabaseBackend::Sqlite) | None => {
            return Err(DbError::UnsupportedDatabaseBackend(
                "expected a postgres: or postgresql: URL for Postgres foundation checks".into(),
            ));
        }
    }

    #[allow(unknown_lints, clippy::duration_suboptimal_units)]
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .idle_timeout(Duration::from_secs(300))
        .connect(url)
        .await?;

    Ok(pool)
}

/// Apply the narrow Postgres foundation schema to a pool.
///
/// This creates and stamps the foundation Postgres tables only. It deliberately
/// does not run the SQLite migrations or enable Postgres through the runtime
/// `Database` type.
#[cfg(feature = "postgres-sqlx")]
pub async fn migrate_postgres_foundation(pool: &PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;
    migrate_postgres_foundation_on_connection(&mut conn).await
}

/// Apply the narrow Postgres foundation schema on an existing connection.
///
/// Tests use this to run the smoke path in a temporary schema without changing
/// unrelated tables in the configured database.
#[cfg(feature = "postgres-sqlx")]
pub async fn migrate_postgres_foundation_on_connection(conn: &mut PgConnection) -> Result<()> {
    version_guard::migrate_postgres_foundation_on_connection(conn).await
}

/// Check Postgres connectivity for foundation-only health probes.
///
/// This intentionally stays outside [`Database`] so it does not imply server
/// runtime support for Postgres.
#[cfg(feature = "postgres-sqlx")]
pub async fn check_postgres_health(pool: &PgPool) -> Result<()> {
    sqlx::query_scalar::<_, i64>("SELECT 1::BIGINT")
        .fetch_one(pool)
        .await?;
    Ok(())
}

/// Check Postgres connectivity on an existing connection.
#[cfg(feature = "postgres-sqlx")]
pub async fn check_postgres_health_on_connection(conn: &mut PgConnection) -> Result<()> {
    sqlx::query_scalar::<_, i64>("SELECT 1::BIGINT")
        .fetch_one(&mut *conn)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_database_creation() {
        let db = Database::in_memory().await.unwrap();
        assert_eq!(db.backend(), DatabaseBackend::Sqlite);
        db.migrate().await.unwrap();
        let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(foreign_keys, 1);
        db.close().await;
    }

    #[tokio::test]
    async fn sqlite_default_open_options_apply_upstream_file_pragmas() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headscale-default.sqlite");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let db = Database::new(&url).await.unwrap();

        let busy_timeout: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let auto_vacuum: i64 = sqlx::query_scalar("PRAGMA auto_vacuum")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(db.pool())
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

        assert_eq!(busy_timeout, 10_000);
        assert_eq!(auto_vacuum, 2, "INCREMENTAL");
        assert_eq!(synchronous, 1, "NORMAL");
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");
        assert_eq!(wal_autocheckpoint, 1000);
        assert_eq!(foreign_keys, 1);
    }

    #[tokio::test]
    async fn sqlite_open_options_apply_connection_pragmas() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("headscale.sqlite");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let db = Database::new_with_sqlite_options(
            &url,
            SqliteOpenOptions {
                write_ahead_log: Some(true),
                wal_autocheckpoint: Some(37),
                busy_timeout: Some(Duration::from_millis(1234)),
                auto_vacuum: Some(SqliteAutoVacuumMode::Full),
                synchronous: Some(SqliteSynchronousMode::Full),
                foreign_keys: Some(true),
            },
        )
        .await
        .unwrap();

        let busy_timeout: i64 = sqlx::query_scalar("PRAGMA busy_timeout")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let auto_vacuum: i64 = sqlx::query_scalar("PRAGMA auto_vacuum")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let synchronous: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(db.pool())
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

        assert_eq!(busy_timeout, 1234);
        assert_eq!(auto_vacuum, 1, "FULL");
        assert_eq!(synchronous, 2, "FULL");
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
        assert_eq!(
            DatabaseBackend::Postgres.headscale_db_foundation_supported(),
            cfg!(feature = "postgres-sqlx")
        );
        assert_eq!(
            DatabaseBackend::Postgres.sqlx_driver_compiled(),
            cfg!(feature = "postgres-sqlx")
        );
        assert_eq!(DatabaseBackend::Postgres.upstream_name(), "postgres");
        assert_eq!(
            DatabaseBackend::Postgres.url_schemes(),
            &["postgres", "postgresql"]
        );
    }
}
