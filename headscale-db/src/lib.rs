//! Database persistence layer for headscale-rs.
//!
//! This crate provides SQLite-based persistence for nodes, transactions,
//! resources, and sessions using sqlx for connection pooling and migrations.
//! With the `postgres-sqlx` feature, it also exposes Postgres pool factories
//! and foundation migrations used by the production stores and parity tools.
//! The `Database` wrapper itself remains SQLite-specific.

#[cfg(all(feature = "postgres-sqlx", feature = "go-pool-compat"))]
use sqlx::Connection as _;
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
pub mod auth_key_registration;
mod credential_entropy;
mod credential_hash;
pub mod error;
mod go_bcrypt;
mod go_error;
pub mod go_json;
pub mod headscale_nodes;
pub mod models;
pub mod nodes;
pub mod payments;
pub mod policies;
pub mod preauth_keys;
pub mod resources;
pub mod sessions;
mod sqlite_go_schema;
mod sqlite_legacy_upgrade;
pub mod stored_hash;
mod stored_hostinfo;
#[doc(hidden)]
pub mod stored_json;
#[doc(hidden)]
pub mod stored_text;
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

/// Translate the control-plane SQLite flags exactly as pinned Go's opener:
/// disabling the WAL override retains sqliteconfig.Default's WAL/1000.
pub fn go_sqlite_open_options(
    write_ahead_log: bool,
    wal_autocheckpoint: i32,
) -> Result<SqliteOpenOptions> {
    if !write_ahead_log {
        return Ok(SqliteOpenOptions::default());
    }
    let checkpoint = match wal_autocheckpoint {
        -1 => None,
        value => Some(u32::try_from(value).map_err(|_| {
            DbError::General(
                "building sqlite connection URL: wal_autocheckpoint must be >= -1".into(),
            )
        })?),
    };
    Ok(SqliteOpenOptions {
        wal_autocheckpoint: checkpoint,
        ..SqliteOpenOptions::default()
    })
}

#[cfg(feature = "postgres-sqlx")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoPostgresPoolOptions {
    pub max_open_connections: i32,
    pub max_idle_connections: i32,
    pub conn_max_idle_time_secs: i32,
}

#[cfg(feature = "postgres-sqlx")]
impl Default for GoPostgresPoolOptions {
    fn default() -> Self {
        Self {
            max_open_connections: 10,
            max_idle_connections: 10,
            conn_max_idle_time_secs: 3600,
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
                let compatibility =
                    version_guard::check_headscale_go_import_compatibility(pool).await?;
                let file_backed = sqlite_go_schema::has_auxiliary_database(pool).await?;
                let go_current = match &compatibility {
                    HeadscaleGoImportCompatibility::Fresh => true,
                    HeadscaleGoImportCompatibility::Versioned { stored_version } => {
                        stored_version == "v0.29.5"
                    }
                    _ => false,
                };
                if go_current && file_backed {
                    if compatibility == HeadscaleGoImportCompatibility::Fresh {
                        sqlite_go_schema::initialize_fresh_primary(pool).await?;
                    }
                    sqlite_go_schema::initialize_auxiliary(pool).await?;
                    return Ok(());
                }
                if file_backed {
                    // Capture the operator's primary before ledger adoption,
                    // one-time data repairs, legacy DDL or version stamping.
                    sqlite_legacy_upgrade::backup_before_migration(pool).await?;
                }
                version_guard::prepare_sqlite_import_ledger(pool).await?;
                version_guard::normalize_null_tags_before_migration(pool).await?;
                version_guard::run_sqlite_migrations(pool, file_backed).await?;
                version_guard::stamp_rust_managed_database_version(pool).await?;
                if file_backed {
                    sqlite_legacy_upgrade::upgrade(pool).await?;
                }
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
    #[allow(unknown_lints, clippy::duration_suboptimal_units)]
    pub async fn new_with_sqlite_options(url: &str, options: SqliteOpenOptions) -> Result<Self> {
        Self::new_sqlite_with_pool_options(
            url,
            options,
            SqlitePoolOptions::new()
                .max_connections(10)
                .idle_timeout(Duration::from_secs(300)),
        )
        .await
    }

    /// Pinned headscale-go pool behavior for control-plane and offline admin
    /// processes. Existing generic constructors keep their embedding defaults.
    /// Requires `go-pool-compat` and the workspace's SQLx-core patch.
    #[cfg(feature = "go-pool-compat")]
    #[allow(unknown_lints, clippy::duration_suboptimal_units)]
    pub async fn new_with_go_sqlite_options(url: &str, options: SqliteOpenOptions) -> Result<Self> {
        Self::new_sqlite_with_pool_options(
            url,
            options,
            SqlitePoolOptions::new()
                .max_connections(1)
                .idle_timeout(Duration::from_secs(3600))
                .max_lifetime(None)
                .direct_connect(true),
        )
        .await
    }

    /// Go pool behavior requires the opt-in native compatibility bridge.
    #[cfg(not(feature = "go-pool-compat"))]
    pub async fn new_with_go_sqlite_options(
        _url: &str,
        _options: SqliteOpenOptions,
    ) -> Result<Self> {
        Err(DbError::General(
            "Go pool compatibility requires the go-pool-compat feature and SQLx-core patch".into(),
        ))
    }

    async fn new_sqlite_with_pool_options(
        url: &str,
        options: SqliteOpenOptions,
        mut pool_options: SqlitePoolOptions,
    ) -> Result<Self> {
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

        if !sqlite_url_is_memory(url) {
            let mut auxiliary_name = sqlite_options.get_filename().as_os_str().to_os_string();
            auxiliary_name.push(".rust-aux.sqlite");
            let auxiliary_path = auxiliary_name
                .to_str()
                .ok_or_else(|| DbError::General("SQLite sidecar path is not UTF-8".into()))?
                .to_owned();
            pool_options = pool_options.after_connect(move |connection, _metadata| {
                let auxiliary_path = auxiliary_path.clone();
                Box::pin(async move {
                    sqlx::query("ATTACH DATABASE ? AS rust_aux")
                        .bind(auxiliary_path)
                        .execute(connection)
                        .await?;
                    Ok(())
                })
            });
        }
        let pool = pool_options.connect_with(sqlite_options).await?;

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

/// Open a Postgres pool with the original foundation-tool defaults.
///
/// Production and offline policy commands use [`open_postgres_pool_with_options`]
/// so configured headscale pool limits also apply there.
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

/// Open the production pool using pinned database/sql option semantics.
/// Requires `go-pool-compat` and the pinned SQLx-core/SQLx-postgres patches.
#[cfg(all(feature = "postgres-sqlx", feature = "go-pool-compat"))]
pub async fn open_postgres_pool_with_options(
    url: &str,
    options: GoPostgresPoolOptions,
) -> Result<PgPool> {
    if DatabaseBackend::from_url(url) != Some(DatabaseBackend::Postgres) {
        return Err(DbError::UnsupportedDatabaseBackend(
            "expected a postgres: or postgresql: URL".into(),
        ));
    }
    let connect_options = sqlx::postgres::PgConnectOptions::from_headscale_go_url(url)?;
    // database/sql treats nonpositive open limits as unlimited. SQLx's size
    // counter is u32; its explicit sparse idle queue avoids eagerly allocating
    // billions of slots for that representational ceiling.
    let max_open = if options.max_open_connections <= 0 {
        u32::MAX
    } else {
        options.max_open_connections.unsigned_abs()
    };
    // Tokio's semaphore has a smaller capacity on 32-bit targets. Keep the
    // representational ceiling within it instead of panicking at pool setup.
    let max_open =
        max_open.min(u32::try_from(tokio::sync::Semaphore::MAX_PERMITS).unwrap_or(u32::MAX));
    let max_idle = u32::try_from(options.max_idle_connections)
        .unwrap_or_default()
        .min(max_open);
    let idle_timeout = u64::try_from(options.conn_max_idle_time_secs)
        .ok()
        .filter(|seconds| *seconds > 0)
        .map(Duration::from_secs);
    let pool = PgPoolOptions::new()
        .max_connections(max_open)
        .max_idle_connections(max_idle)
        .min_connections(0)
        .max_lifetime(None)
        .idle_timeout(idle_timeout)
        .direct_connect(true)
        .test_before_acquire(false)
        .test_on_release(false)
        .before_acquire(|connection, metadata| {
            Box::pin(async move {
                // Drain cancelled work/queued rollbacks before reuse, rather
                // than adding SQLx's unconditional Sync ping. The tracked
                // transaction and wire status checks reject unfinished or
                // failed transactions, including those opened through raw SQL.
                connection.flush().await?;
                if connection.is_in_transaction() || !connection.transaction_status_is_idle() {
                    return Ok(false);
                }
                // pgx ResetSession measures from the prior successful reuse,
                // including time checked out. Its zero initial timestamp
                // makes the first reuse ping even after a short idle period.
                if metadata
                    .since_last_reuse
                    .is_none_or(|elapsed| elapsed > Duration::from_secs(1))
                {
                    ping_postgres_connection(connection).await?;
                }
                Ok(true)
            })
        })
        .after_release(|connection, _metadata| {
            Box::pin(async move {
                // Returning a connection must still flush pending protocol
                // work and rollback commands before it enters the idle queue.
                connection.flush().await?;
                Ok(!connection.is_in_transaction() && connection.transaction_status_is_idle())
            })
        })
        .connect_lazy_with(connect_options);
    // gorm.Open performs one explicit Ping on the first fresh connection.
    // Keep it separate from pgx ResetSession's later first-reuse ping, and
    // return it eagerly so the first schema query can reuse that connection.
    let mut connection = pool.acquire().await?;
    sqlx::raw_sql("-- ping").execute(&mut *connection).await?;
    connection.return_to_pool().await;
    Ok(pool)
}

/// pgx `ResetSession` ping. Goes through `Executor::execute` (a `BoxFuture`)
/// rather than `RawSql::execute`: the latter is an `async fn` generic over the
/// executor lifetime, and rustc cannot prove such a future `Send` inside the
/// pool callback ("implementation of `Executor` is not general enough").
#[cfg(all(feature = "postgres-sqlx", feature = "go-pool-compat"))]
async fn ping_postgres_connection(
    connection: &mut sqlx::PgConnection,
) -> std::result::Result<(), sqlx::Error> {
    use sqlx::Executor as _;
    connection.execute(sqlx::raw_sql("-- ping")).await?;
    Ok(())
}

/// Go pool behavior requires the opt-in native compatibility bridge.
#[cfg(all(feature = "postgres-sqlx", not(feature = "go-pool-compat")))]
pub async fn open_postgres_pool_with_options(
    _url: &str,
    _options: GoPostgresPoolOptions,
) -> Result<PgPool> {
    Err(DbError::General(
        "Go pool compatibility requires go-pool-compat and the SQLx-core/SQLx-postgres patches"
            .into(),
    ))
}

/// Apply the narrow Postgres foundation schema to a pool.
///
/// This creates and stamps the foundation Postgres tables only. It deliberately
/// does not run the SQLite migrations or enable Postgres through the runtime
/// `Database` type.
#[cfg(feature = "postgres-sqlx")]
pub async fn migrate_postgres_foundation(pool: &PgPool) -> Result<()> {
    let mut conn = pool.acquire().await?;
    // Migration holds a session advisory lock, whose explicit unlock can be
    // skipped by cancellation. Keep this startup session out of the reusable
    // pool even when work fails or is cancelled while acquiring the lock.
    // Closing the session releases any advisory lock still held by the server.
    conn.close_on_drop();
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
