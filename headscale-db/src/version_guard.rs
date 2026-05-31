//! Compatibility guard for importing headscale-go SQLite databases.
//!
//! The Rust database shape tracks the pinned headscale-go v0.29 schema
//! while accepting the supported v0.28 import baseline. It can read
//! databases already migrated to that shape, but it should not attempt
//! arbitrary headscale-go upgrades or downgrades.

use crate::{DbError, Result};
#[cfg(feature = "postgres-sqlx")]
use sqlx::PgConnection;
use sqlx::SqlitePool;

pub const HEADSCALE_GO_IMPORT_BASELINE: &str = "v0.28.0";
pub const HEADSCALE_GO_CURRENT_VERSION: &str = "v0.29.0-beta.2";

const SUPPORTED_MAJOR: u64 = 0;
const SUPPORTED_MINOR: u64 = 28;
const CURRENT_UPSTREAM_MINOR: u64 = 29;
const REQUIRED_GO_MIGRATION: &str = "202601121700-migrate-hostinfo-request-tags";
const CLEAR_TAGGED_NODE_USER_ID_MIGRATION: &str = "202602201200-clear-tagged-node-user-id";
const CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION: &str = "202605221435-clear-zero-time-node-expiry";

const GO_SHAPED_TABLES: &[&str] = &["users", "pre_auth_keys", "api_keys", "nodes", "policies"];

#[cfg(feature = "postgres-sqlx")]
static POSTGRES_FOUNDATION_MIGRATOR: sqlx::migrate::Migrator =
    sqlx::migrate!("./migrations/postgres");

const KNOWN_GO_MIGRATIONS: &[&str] = &[
    "202312101416",
    "202312101430",
    "202402151347",
    "2024041121742",
    "202406021630",
    "202407191627",
    "202408181235",
    "202409271400",
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
    REQUIRED_GO_MIGRATION,
    CLEAR_TAGGED_NODE_USER_ID_MIGRATION,
    CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadscaleGoImportCompatibility {
    Fresh,
    RustManaged,
    Versioned { stored_version: String },
    DevelopmentVersion { stored_version: String },
    GoMigrations { required_migration: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Semver {
    major: u64,
    minor: u64,
    patch: u64,
}

pub async fn check_headscale_go_import_compatibility(
    pool: &SqlitePool,
) -> Result<HeadscaleGoImportCompatibility> {
    if table_exists(pool, "_sqlx_migrations").await? {
        return Ok(HeadscaleGoImportCompatibility::RustManaged);
    }

    if table_exists(pool, "database_versions").await? {
        return check_database_versions_table(pool).await;
    }

    if table_exists(pool, "migrations").await? {
        return check_go_migrations_table(pool).await;
    }

    if has_any_go_shaped_table(pool).await? {
        return unsupported(
            "Go-shaped tables are present, but neither database_versions nor \
             headscale-go migrations identify a supported v0.28 import",
        );
    }

    Ok(HeadscaleGoImportCompatibility::Fresh)
}

pub(crate) async fn stamp_rust_managed_database_version(pool: &SqlitePool) -> Result<()> {
    sqlx::query(
        "
        INSERT INTO database_versions (id, version, updated_at)
        VALUES (1, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(id) DO UPDATE SET
            version = excluded.version,
            updated_at = excluded.updated_at
        ",
    )
    .bind(HEADSCALE_GO_CURRENT_VERSION)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub(crate) async fn migrate_postgres_foundation_on_connection(
    conn: &mut PgConnection,
) -> Result<()> {
    check_postgres_headscale_go_import_compatibility(conn).await?;
    POSTGRES_FOUNDATION_MIGRATOR.run(&mut *conn).await?;
    stamp_postgres_database_version(conn).await
}

#[cfg(feature = "postgres-sqlx")]
pub(crate) async fn check_postgres_headscale_go_import_compatibility(
    conn: &mut PgConnection,
) -> Result<HeadscaleGoImportCompatibility> {
    let rust_managed = postgres_table_exists(conn, "_sqlx_migrations").await?;

    if postgres_table_exists(conn, "database_versions").await? {
        if rust_managed {
            return check_postgres_rust_managed_database_versions_table(conn).await;
        }
        return check_postgres_database_versions_table(conn).await;
    }

    if rust_managed {
        return Ok(HeadscaleGoImportCompatibility::RustManaged);
    }

    if postgres_table_exists(conn, "migrations").await? {
        return check_postgres_go_migrations_table(conn).await;
    }

    if postgres_has_any_go_shaped_table(conn).await? {
        return unsupported(
            "Go-shaped Postgres tables are present, but neither database_versions nor \
             headscale-go migrations identify a supported v0.28 import",
        );
    }

    Ok(HeadscaleGoImportCompatibility::Fresh)
}

#[cfg(feature = "postgres-sqlx")]
async fn stamp_postgres_database_version(conn: &mut PgConnection) -> Result<()> {
    sqlx::query(
        "
        INSERT INTO database_versions (id, version, updated_at)
        VALUES (1, $1, CURRENT_TIMESTAMP)
        ON CONFLICT (id) DO UPDATE SET
            version = EXCLUDED.version,
            updated_at = EXCLUDED.updated_at
        ",
    )
    .bind(HEADSCALE_GO_CURRENT_VERSION)
    .execute(&mut *conn)
    .await?;

    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
async fn check_postgres_rust_managed_database_versions_table(
    conn: &mut PgConnection,
) -> Result<HeadscaleGoImportCompatibility> {
    let rows = postgres_database_version_rows(conn).await?;

    if rows.is_empty() {
        return Ok(HeadscaleGoImportCompatibility::RustManaged);
    }

    if rows.len() != 1 || rows[0].0 != 1 {
        return unsupported(
            "database_versions must contain at most the upstream single row with id=1",
        );
    }

    let stored_version = rows[0].1.trim();
    if stored_version.is_empty() {
        return unsupported("database_versions.version is empty");
    }

    if stored_version == HEADSCALE_GO_CURRENT_VERSION {
        return Ok(HeadscaleGoImportCompatibility::RustManaged);
    }

    if postgres_table_exists(conn, "migrations").await? {
        return check_postgres_database_versions_table(conn).await;
    }

    if postgres_has_any_go_shaped_table(conn).await? {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but Rust-managed Postgres databases \
             must be stamped with {HEADSCALE_GO_CURRENT_VERSION} or include supported \
             headscale-go migration history"
        ));
    }

    check_postgres_database_versions_table(conn).await
}

#[cfg(feature = "postgres-sqlx")]
async fn check_postgres_database_versions_table(
    conn: &mut PgConnection,
) -> Result<HeadscaleGoImportCompatibility> {
    let rows = postgres_database_version_rows(conn).await?;

    if rows.is_empty() {
        if postgres_table_exists(conn, "_sqlx_migrations").await? {
            return Ok(HeadscaleGoImportCompatibility::RustManaged);
        }
        if postgres_table_exists(conn, "migrations").await? {
            return check_postgres_go_migrations_table(conn).await;
        }
        if postgres_has_any_go_shaped_table(conn).await? {
            return unsupported(
                "database_versions is empty for an existing Go-shaped Postgres database, and no \
                 supported headscale-go migration history is present",
            );
        }

        return Ok(HeadscaleGoImportCompatibility::Fresh);
    }

    if rows.len() != 1 || rows[0].0 != 1 {
        return unsupported(
            "database_versions must contain at most the upstream single row with id=1",
        );
    }

    let stored_version = rows[0].1.trim();
    if is_development_version(stored_version) {
        return check_postgres_database_versions_without_comparable_version(conn, stored_version)
            .await;
    }

    let stored = parse_version(stored_version).map_err(|message| {
        DbError::UnsupportedHeadscaleGoDatabaseVersion(format!(
            "cannot parse database_versions.version {stored_version:?}: {message}"
        ))
    })?;

    match (stored.major == SUPPORTED_MAJOR, stored.minor) {
        (true, SUPPORTED_MINOR) => {
            validate_postgres_versioned_go_shape(conn, stored_version).await?;
            Ok(HeadscaleGoImportCompatibility::Versioned {
                stored_version: stored_version.to_string(),
            })
        }
        (true, CURRENT_UPSTREAM_MINOR) => {
            validate_postgres_current_upstream_go_shape(conn, stored_version).await?;
            Ok(HeadscaleGoImportCompatibility::Versioned {
                stored_version: stored_version.to_string(),
            })
        }
        (false, _) => unsupported(format!(
            "database was last used by headscale-go {stored_version}, but this crate only \
             imports {HEADSCALE_GO_IMPORT_BASELINE}-compatible Postgres schemas"
        )),
        (true, minor) if minor < SUPPORTED_MINOR => unsupported(format!(
            "database was last used by headscale-go {stored_version}; upgrade it with \
             headscale-go {HEADSCALE_GO_IMPORT_BASELINE} before importing"
        )),
        (true, _) => unsupported(format!(
            "database was last used by newer headscale-go {stored_version}; this crate only \
             imports {HEADSCALE_GO_IMPORT_BASELINE}-compatible Postgres schemas"
        )),
    }
}

#[cfg(feature = "postgres-sqlx")]
async fn postgres_database_version_rows(conn: &mut PgConnection) -> Result<Vec<(i64, String)>> {
    Ok(
        sqlx::query_as("SELECT id, version FROM database_versions ORDER BY id")
            .fetch_all(&mut *conn)
            .await?,
    )
}

#[cfg(feature = "postgres-sqlx")]
async fn check_postgres_database_versions_without_comparable_version(
    conn: &mut PgConnection,
    stored_version: &str,
) -> Result<HeadscaleGoImportCompatibility> {
    if postgres_table_exists(conn, "migrations").await? {
        return check_postgres_go_migrations_table(conn).await;
    }

    if postgres_has_any_go_shaped_table(conn).await? {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but a Go-shaped Postgres database \
             without supported headscale-go migration history cannot be imported"
        ));
    }

    Ok(HeadscaleGoImportCompatibility::DevelopmentVersion {
        stored_version: stored_version.to_string(),
    })
}

#[cfg(feature = "postgres-sqlx")]
async fn validate_postgres_versioned_go_shape(
    conn: &mut PgConnection,
    stored_version: &str,
) -> Result<()> {
    if postgres_table_exists(conn, "migrations").await? {
        check_postgres_go_migrations_table(conn).await?;
        return Ok(());
    }

    if postgres_has_any_go_shaped_table(conn).await? {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but Go-shaped Postgres tables are \
             present without headscale-go migration history through {REQUIRED_GO_MIGRATION}"
        ));
    }

    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
async fn validate_postgres_current_upstream_go_shape(
    conn: &mut PgConnection,
    stored_version: &str,
) -> Result<()> {
    if !postgres_table_exists(conn, "migrations").await? {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but current headscale-go Postgres \
             imports require migration history through {CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION}"
        ));
    }

    let migration_ids = postgres_go_migration_ids(conn).await?;
    validate_known_go_migrations(&migration_ids)?;
    if !migration_ids.iter().any(|id| id == REQUIRED_GO_MIGRATION) {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but headscale-go migrations table is \
             not migrated through {REQUIRED_GO_MIGRATION}"
        ));
    }
    if !migration_ids
        .iter()
        .any(|id| id == CLEAR_TAGGED_NODE_USER_ID_MIGRATION)
    {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but headscale-go migrations table is \
             not migrated through {CLEAR_TAGGED_NODE_USER_ID_MIGRATION}"
        ));
    }
    if !migration_ids
        .iter()
        .any(|id| id == CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION)
    {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but headscale-go migrations table is \
             not migrated through {CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION}"
        ));
    }

    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
async fn check_postgres_go_migrations_table(
    conn: &mut PgConnection,
) -> Result<HeadscaleGoImportCompatibility> {
    let migration_ids = postgres_go_migration_ids(conn).await?;

    if migration_ids.is_empty() {
        if postgres_has_any_go_shaped_table(conn).await? {
            return unsupported(
                "headscale-go migrations table is empty for an existing Go-shaped Postgres database",
            );
        }

        return Ok(HeadscaleGoImportCompatibility::Fresh);
    }

    validate_known_go_migrations(&migration_ids)?;

    if !migration_ids.iter().any(|id| id == REQUIRED_GO_MIGRATION) {
        return unsupported(format!(
            "headscale-go migrations table is not migrated through {REQUIRED_GO_MIGRATION}; \
             upgrade with headscale-go {HEADSCALE_GO_IMPORT_BASELINE} before importing"
        ));
    }

    let required_migration = if migration_ids
        .iter()
        .any(|id| id == CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION)
    {
        CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION
    } else if migration_ids
        .iter()
        .any(|id| id == CLEAR_TAGGED_NODE_USER_ID_MIGRATION)
    {
        CLEAR_TAGGED_NODE_USER_ID_MIGRATION
    } else {
        REQUIRED_GO_MIGRATION
    };
    Ok(HeadscaleGoImportCompatibility::GoMigrations {
        required_migration: required_migration.to_string(),
    })
}

#[cfg(feature = "postgres-sqlx")]
async fn postgres_go_migration_ids(conn: &mut PgConnection) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar("SELECT id FROM migrations ORDER BY id")
        .fetch_all(&mut *conn)
        .await?)
}

async fn check_database_versions_table(
    pool: &SqlitePool,
) -> Result<HeadscaleGoImportCompatibility> {
    let rows: Vec<(i64, String)> =
        sqlx::query_as("SELECT id, version FROM database_versions ORDER BY id")
            .fetch_all(pool)
            .await?;

    if rows.is_empty() {
        if table_exists(pool, "_sqlx_migrations").await? {
            return Ok(HeadscaleGoImportCompatibility::RustManaged);
        }
        if table_exists(pool, "migrations").await? {
            return check_go_migrations_table(pool).await;
        }
        if has_any_go_shaped_table(pool).await? {
            return unsupported(
                "database_versions is empty for an existing Go-shaped database, and no \
                 supported headscale-go migration history is present",
            );
        }

        return Ok(HeadscaleGoImportCompatibility::Fresh);
    }

    if rows.len() != 1 || rows[0].0 != 1 {
        return unsupported(
            "database_versions must contain at most the upstream single row with id=1",
        );
    }

    let stored_version = rows[0].1.trim();
    if is_development_version(stored_version) {
        return check_database_versions_without_comparable_version(pool, stored_version).await;
    }

    let stored = parse_version(stored_version).map_err(|message| {
        DbError::UnsupportedHeadscaleGoDatabaseVersion(format!(
            "cannot parse database_versions.version {stored_version:?}: {message}"
        ))
    })?;

    match (stored.major == SUPPORTED_MAJOR, stored.minor) {
        (true, SUPPORTED_MINOR) => {
            validate_versioned_go_shape(pool, stored_version).await?;
            Ok(HeadscaleGoImportCompatibility::Versioned {
                stored_version: stored_version.to_string(),
            })
        }
        (true, CURRENT_UPSTREAM_MINOR) => {
            validate_current_upstream_go_shape(pool, stored_version).await?;
            Ok(HeadscaleGoImportCompatibility::Versioned {
                stored_version: stored_version.to_string(),
            })
        }
        (false, _) => unsupported(format!(
            "database was last used by headscale-go {stored_version}, but this crate only \
             imports {HEADSCALE_GO_IMPORT_BASELINE}-compatible SQLite schemas"
        )),
        (true, minor) if minor < SUPPORTED_MINOR => unsupported(format!(
            "database was last used by headscale-go {stored_version}; upgrade it with \
             headscale-go {HEADSCALE_GO_IMPORT_BASELINE} before importing"
        )),
        (true, _) => unsupported(format!(
            "database was last used by newer headscale-go {stored_version}; this crate only \
             imports {HEADSCALE_GO_IMPORT_BASELINE}-compatible SQLite schemas"
        )),
    }
}

async fn check_database_versions_without_comparable_version(
    pool: &SqlitePool,
    stored_version: &str,
) -> Result<HeadscaleGoImportCompatibility> {
    if table_exists(pool, "migrations").await? {
        return check_go_migrations_table(pool).await;
    }

    if has_any_go_shaped_table(pool).await? {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but a Go-shaped database without \
             supported headscale-go migration history cannot be imported"
        ));
    }

    Ok(HeadscaleGoImportCompatibility::DevelopmentVersion {
        stored_version: stored_version.to_string(),
    })
}

async fn validate_versioned_go_shape(pool: &SqlitePool, stored_version: &str) -> Result<()> {
    if table_exists(pool, "migrations").await? {
        check_go_migrations_table(pool).await?;
        return Ok(());
    }

    if has_any_go_shaped_table(pool).await? {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but Go-shaped tables are present \
             without headscale-go migration history through {REQUIRED_GO_MIGRATION}"
        ));
    }

    Ok(())
}

async fn validate_current_upstream_go_shape(pool: &SqlitePool, stored_version: &str) -> Result<()> {
    if !table_exists(pool, "migrations").await? {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but current headscale-go imports \
             require migration history through {CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION}"
        ));
    }

    let migration_ids = go_migration_ids(pool).await?;
    validate_known_go_migrations(&migration_ids)?;
    if !migration_ids.iter().any(|id| id == REQUIRED_GO_MIGRATION) {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but headscale-go migrations table is \
             not migrated through {REQUIRED_GO_MIGRATION}"
        ));
    }
    if !migration_ids
        .iter()
        .any(|id| id == CLEAR_TAGGED_NODE_USER_ID_MIGRATION)
    {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but headscale-go migrations table is \
             not migrated through {CLEAR_TAGGED_NODE_USER_ID_MIGRATION}"
        ));
    }
    if !migration_ids
        .iter()
        .any(|id| id == CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION)
    {
        return unsupported(format!(
            "database_versions.version is {stored_version}, but headscale-go migrations table is \
             not migrated through {CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION}"
        ));
    }

    Ok(())
}

async fn check_go_migrations_table(pool: &SqlitePool) -> Result<HeadscaleGoImportCompatibility> {
    let migration_ids = go_migration_ids(pool).await?;

    if migration_ids.is_empty() {
        if has_any_go_shaped_table(pool).await? {
            return unsupported(
                "headscale-go migrations table is empty for an existing Go-shaped database",
            );
        }

        return Ok(HeadscaleGoImportCompatibility::Fresh);
    }

    validate_known_go_migrations(&migration_ids)?;

    if !migration_ids.iter().any(|id| id == REQUIRED_GO_MIGRATION) {
        return unsupported(format!(
            "headscale-go migrations table is not migrated through {REQUIRED_GO_MIGRATION}; \
             upgrade with headscale-go {HEADSCALE_GO_IMPORT_BASELINE} before importing"
        ));
    }

    let required_migration = if migration_ids
        .iter()
        .any(|id| id == CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION)
    {
        CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION
    } else if migration_ids
        .iter()
        .any(|id| id == CLEAR_TAGGED_NODE_USER_ID_MIGRATION)
    {
        CLEAR_TAGGED_NODE_USER_ID_MIGRATION
    } else {
        REQUIRED_GO_MIGRATION
    };
    Ok(HeadscaleGoImportCompatibility::GoMigrations {
        required_migration: required_migration.to_string(),
    })
}

async fn go_migration_ids(pool: &SqlitePool) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar("SELECT id FROM migrations ORDER BY id")
        .fetch_all(pool)
        .await?)
}

fn validate_known_go_migrations(migration_ids: &[String]) -> Result<()> {
    let unknown: Vec<&str> = migration_ids
        .iter()
        .map(String::as_str)
        .filter(|id| !KNOWN_GO_MIGRATIONS.contains(id))
        .collect();

    if !unknown.is_empty() {
        return unsupported(format!(
            "headscale-go migrations table contains unsupported migration id(s): {}",
            unknown.join(", ")
        ));
    }

    Ok(())
}

async fn table_exists(pool: &SqlitePool, table: &str) -> Result<bool> {
    let count: i64 = sqlx::query_scalar(
        "
        SELECT COUNT(*)
        FROM sqlite_master
        WHERE type = 'table' AND name = ?
        ",
    )
    .bind(table)
    .fetch_one(pool)
    .await?;

    Ok(count > 0)
}

async fn has_any_go_shaped_table(pool: &SqlitePool) -> Result<bool> {
    for table in GO_SHAPED_TABLES {
        if table_exists(pool, table).await? {
            return Ok(true);
        }
    }

    Ok(false)
}

#[cfg(feature = "postgres-sqlx")]
async fn postgres_table_exists(conn: &mut PgConnection, table: &str) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
        .bind(table)
        .fetch_one(&mut *conn)
        .await?)
}

#[cfg(feature = "postgres-sqlx")]
async fn postgres_has_any_go_shaped_table(conn: &mut PgConnection) -> Result<bool> {
    for table in GO_SHAPED_TABLES {
        if postgres_table_exists(conn, table).await? {
            return Ok(true);
        }
    }

    Ok(false)
}

fn is_development_version(version: &str) -> bool {
    version.is_empty() || matches!(version, "dev" | "(devel)") || is_go_pseudo_version(version)
}

fn is_go_pseudo_version(version: &str) -> bool {
    let Some((prefix, hash)) = version.rsplit_once('-') else {
        return false;
    };
    if hash.len() != 12
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return false;
    }
    if prefix.len() < 15 {
        return false;
    }

    let timestamp_start = prefix.len() - 14;
    let Some(separator) = prefix.as_bytes().get(timestamp_start - 1).copied() else {
        return false;
    };
    if !matches!(separator, b'-' | b'.') {
        return false;
    }

    let timestamp = &prefix[timestamp_start..];
    timestamp.bytes().all(|byte| byte.is_ascii_digit())
        && is_valid_pseudo_version_timestamp(timestamp)
}

fn is_valid_pseudo_version_timestamp(timestamp: &str) -> bool {
    if timestamp.len() != 14 {
        return false;
    }

    let Ok(year) = timestamp[0..4].parse::<u32>() else {
        return false;
    };
    let Ok(month) = timestamp[4..6].parse::<u32>() else {
        return false;
    };
    let Ok(day) = timestamp[6..8].parse::<u32>() else {
        return false;
    };
    let Ok(hour) = timestamp[8..10].parse::<u32>() else {
        return false;
    };
    let Ok(minute) = timestamp[10..12].parse::<u32>() else {
        return false;
    };
    let Ok(second) = timestamp[12..14].parse::<u32>() else {
        return false;
    };

    let Some(max_day) = days_in_month(year, month) else {
        return false;
    };

    day >= 1 && day <= max_day && hour <= 23 && minute <= 59 && second <= 59
}

fn days_in_month(year: u32, month: u32) -> Option<u32> {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => Some(31),
        4 | 6 | 9 | 11 => Some(30),
        2 if is_leap_year(year) => Some(29),
        2 => Some(28),
        _ => None,
    }
}

const fn is_leap_year(year: u32) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

fn parse_version(version: &str) -> std::result::Result<Semver, String> {
    let version = version.strip_prefix('v').unwrap_or(version);
    let version = version
        .split_once(['-', '+'])
        .map_or(version, |(base, _)| base);
    let mut parts = version.split('.');
    let major = parse_version_part(parts.next(), "major")?;
    let minor = parse_version_part(parts.next(), "minor")?;
    let patch = parse_version_part(parts.next(), "patch")?;

    if parts.next().is_some() {
        return Err("version must use major.minor.patch format".to_string());
    }

    Ok(Semver {
        major,
        minor,
        patch,
    })
}

fn parse_version_part(part: Option<&str>, name: &str) -> std::result::Result<u64, String> {
    part.ok_or_else(|| "version must use major.minor.patch format".to_string())?
        .parse::<u64>()
        .map_err(|e| format!("invalid {name} version: {e}"))
}

fn unsupported<T>(message: impl Into<String>) -> Result<T> {
    Err(DbError::UnsupportedHeadscaleGoDatabaseVersion(
        message.into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_version_accepts_headscale_go_shapes() {
        assert_eq!(
            parse_version("v0.28.0").unwrap(),
            Semver {
                major: 0,
                minor: 28,
                patch: 0
            }
        );
        assert_eq!(
            parse_version("0.28.1-beta.1+build").unwrap(),
            Semver {
                major: 0,
                minor: 28,
                patch: 1
            }
        );
    }

    #[test]
    fn parse_version_rejects_non_semver() {
        assert!(parse_version("").is_err());
        assert!(parse_version("dev").is_err());
        assert!(parse_version("v0.28").is_err());
        assert!(parse_version("v0.28.0.1").is_err());
    }

    #[test]
    fn development_version_matches_go_pseudo_versions() {
        assert!(is_development_version(""));
        assert!(is_development_version("dev"));
        assert!(is_development_version("(devel)"));
        assert!(is_development_version("v0.0.0-20260522092201-58a85b68b3d9"));
        assert!(is_development_version(
            "v0.29.0-beta.1.0.20260522092201-58a85b68b3d9"
        ));
        assert!(is_development_version(
            "v0.29.1-0.20260522092201-58a85b68b3d9"
        ));

        assert!(!is_development_version("v0.29.0-beta.2"));
        assert!(!is_development_version(
            "v0.0.0-20261322092201-58a85b68b3d9"
        ));
        assert!(!is_development_version(
            "v0.0.0-20260522092201-58A85B68B3D9"
        ));
        assert!(!is_development_version("v0.0.0-20260522092201-58a85b68b3d"));
    }
}
