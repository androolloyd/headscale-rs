//! Compatibility guard for importing headscale-go SQLite databases.
//!
//! The Rust database shape tracks the pinned headscale-go v0.29 schema
//! while accepting the supported v0.28 import baseline. It can read
//! databases already migrated to that shape, but it should not attempt
//! arbitrary headscale-go upgrades or downgrades.

use std::fmt::Write as _;

use crate::{DbError, Result};
use sqlx::SqlitePool;
use sqlx::migrate::{Migrate, MigrateError};
#[cfg(feature = "postgres-sqlx")]
use sqlx::{Connection, PgConnection};

pub const HEADSCALE_GO_IMPORT_BASELINE: &str = "v0.28.0";
pub const HEADSCALE_GO_CURRENT_VERSION: &str = "v0.29.5";
const LEGACY_RUST_SQLITE_VERSION: &str = "v0.29.0-beta.2";

const SUPPORTED_MAJOR: u64 = 0;
const SUPPORTED_MINOR: u64 = 28;
const CURRENT_UPSTREAM_MINOR: u64 = 29;
const REQUIRED_GO_MIGRATION: &str = "202601121700-migrate-hostinfo-request-tags";
const CLEAR_TAGGED_NODE_USER_ID_MIGRATION: &str = "202602201200-clear-tagged-node-user-id";
const CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION: &str = "202605221435-clear-zero-time-node-expiry";
const RECOVER_NULL_TAGS_NODE_USER_ID_MIGRATION: &str =
    "202606181200-recover-null-tags-node-user-id";
const CLEAR_TAGGED_NODE_EXPIRY_MIGRATION: &str = "202607241200-clear-tagged-node-expiry";

const GO_SHAPED_TABLES: &[&str] = &["users", "pre_auth_keys", "api_keys", "nodes", "policies"];

pub(crate) static SQLITE_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub(crate) async fn run_sqlite_migrations(pool: &SqlitePool, file_backed: bool) -> Result<()> {
    let migrations = SQLITE_MIGRATOR
        .iter()
        .cloned()
        .map(|mut migration| {
            let tables: &[&str] = match migration.version {
                20_260_522_000_009 => &["nodes"],
                20_260_523_000_012 => &["nodes", "pre_auth_keys"],
                _ => return migration,
            };
            // ALTER RENAME moves the original sqlite_sequence entry to the old
            // table name, and DROP removes it. Copying only surviving IDs into
            // the replacement would otherwise forget previously allocated IDs.
            let snapshot = format!("__hs_sqlx_sequence_floor_{}", migration.version);
            let names = tables
                .iter()
                .map(|table| format!("'{table}'"))
                .collect::<Vec<_>>()
                .join(", ");
            let mut sql = format!(
                "CREATE TEMP TABLE {snapshot} AS \
                 SELECT name, seq FROM main.sqlite_sequence WHERE name IN ({names});\n{}\n",
                migration.sql,
            );
            for table in tables {
                let _ = write!(
                    sql,
                    "UPDATE main.sqlite_sequence SET seq = MAX(\
                     COALESCE(seq, 0), \
                     COALESCE((SELECT seq FROM temp.{snapshot} WHERE name = '{table}'), 0), \
                     COALESCE((SELECT MAX(id) FROM main.{table}), 0)) \
                     WHERE name = '{table}';\n\
                     INSERT INTO main.sqlite_sequence(name, seq) \
                     SELECT '{table}', MAX(\
                     COALESCE((SELECT seq FROM temp.{snapshot} WHERE name = '{table}'), 0), \
                     COALESCE((SELECT MAX(id) FROM main.{table}), 0)) \
                     WHERE NOT EXISTS(SELECT 1 FROM main.sqlite_sequence WHERE name = '{table}') \
                     AND (EXISTS(SELECT 1 FROM temp.{snapshot} WHERE name = '{table}') \
                     OR EXISTS(SELECT 1 FROM main.{table}));\n",
                );
            }
            let _ = writeln!(sql, "DROP TABLE temp.{snapshot};");
            // SQLx executes this entire script and records completion in one
            // transaction. Keep its immutable original metadata/checksum so
            // existing ledgers still validate against the checked-in SQL files.
            migration.sql = std::borrow::Cow::Owned(sql);
            migration
        })
        .collect::<Vec<_>>();
    let migrator = sqlx::migrate::Migrator {
        migrations: std::borrow::Cow::Owned(migrations),
        ignore_missing: SQLITE_MIGRATOR.ignore_missing,
        locking: SQLITE_MIGRATOR.locking,
        no_tx: SQLITE_MIGRATOR.no_tx,
    };
    let mut connection = pool.acquire().await?;
    if file_backed {
        // Never recycle an interrupted migration session with a partial TEMP
        // snapshot or rollback pending. In-memory databases must retain their
        // connection; SQLx's normal transaction rollback still covers them.
        connection.close_on_drop();
    }
    migrator.run(&mut *connection).await?;
    Ok(())
}

const SQLITE_GO_DATA_REPAIRS: &[(i64, &str)] = &[
    (20_260_524_000_014, CLEAR_TAGGED_NODE_USER_ID_MIGRATION),
    (20_260_530_000_015, CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION),
    (20_261_016_000_018, RECOVER_NULL_TAGS_NODE_USER_ID_MIGRATION),
    (20_261_016_000_019, CLEAR_TAGGED_NODE_EXPIRY_MIGRATION),
];
const SQLITE_OBSOLETE_NODE_KEY_INDEX_MIGRATIONS: [i64; 2] =
    [20_260_531_000_016, 20_260_602_000_017];

#[cfg(feature = "postgres-sqlx")]
static POSTGRES_FOUNDATION_MIGRATOR: sqlx::migrate::Migrator = {
    let mut migrator = sqlx::migrate!("./migrations/postgres");
    // The caller holds this same SQLx advisory lock across compatibility
    // checks, foundation changes and Go ledger/version publication.
    migrator.locking = false;
    migrator
};

// These SQLx migrations perform the same one-time repairs as the named Go
// migrations. Importing an existing Go ledger must not repeat those repairs:
// administrators can legitimately change the repaired values afterward.
#[cfg(feature = "postgres-sqlx")]
const POSTGRES_GO_DATA_REPAIRS: &[(i64, &str)] = &[
    (20_260_530_000_007, CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION),
    (20_260_601_000_009, CLEAR_TAGGED_NODE_USER_ID_MIGRATION),
    (20_261_016_000_011, RECOVER_NULL_TAGS_NODE_USER_ID_MIGRATION),
    (20_261_016_000_012, CLEAR_TAGGED_NODE_EXPIRY_MIGRATION),
];

// The temporary Rust-only uniqueness constraint is absent from Go's Node
// model (NodeKey has only serializer:text) and was removed by the later SQLx
// migration. Running its create against imported duplicate keys can fail before
// reaching the drop. When neither ran, install their final schema directly.
#[cfg(feature = "postgres-sqlx")]
const POSTGRES_OBSOLETE_NODE_KEY_INDEX_MIGRATIONS: [i64; 2] =
    [20_260_531_000_008, 20_260_602_000_010];

const KNOWN_GO_MIGRATIONS: &[&str] = &[
    // Present in a fresh v0.29.5 database created by headscale-go itself.
    "SCHEMA_INIT",
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
    RECOVER_NULL_TAGS_NODE_USER_ID_MIGRATION,
    CLEAR_TAGGED_NODE_EXPIRY_MIGRATION,
];

// The ledger in a freshly initialized headscale-go v0.29.5 Postgres database.
// SQLx creates the current schema directly, so Go must not replay its older
// schema/data migrations when it next opens a Rust-created database.
#[cfg(feature = "postgres-sqlx")]
const FRESH_GO_POSTGRES_MIGRATIONS: &[&str] = &[
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
    REQUIRED_GO_MIGRATION,
    CLEAR_TAGGED_NODE_USER_ID_MIGRATION,
    CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION,
    RECOVER_NULL_TAGS_NODE_USER_ID_MIGRATION,
    CLEAR_TAGGED_NODE_EXPIRY_MIGRATION,
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

// The SQLite SQLx migration path is an intermediate legacy shape. File-backed
// databases are rebuilt into the exact Go v0.29.5 primary schema immediately
// afterward; in-memory databases retain this shape and must not claim v0.29.5.
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
    .bind(LEGACY_RUST_SQLITE_VERSION)
    .execute(pool)
    .await?;

    Ok(())
}

pub(crate) async fn normalize_null_tags_before_migration(pool: &SqlitePool) -> Result<()> {
    let owner_repair_applied: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM main._sqlx_migrations WHERE version = ? AND success)",
    )
    .bind(20_260_524_000_014_i64)
    .fetch_one(pool)
    .await?;
    if owner_repair_applied {
        return Ok(());
    }
    if table_exists(pool, "nodes").await? {
        // The historical Rust tagged-owner migration predates headscale-go's
        // `tags='null'` fix. Normalize that untagged spelling before it runs,
        // including CLI/OIDC nodes whose owner cannot be reconstructed later.
        sqlx::query("UPDATE nodes SET tags = '[]' WHERE tags = 'null'")
            .execute(pool)
            .await?;
    }
    Ok(())
}

pub(crate) async fn prepare_sqlite_import_ledger(pool: &SqlitePool) -> Result<()> {
    // SQLx's SQLite migration lock is a no-op. Serialize completed Go repair
    // adoption and compatible pending repair execution with SQLite's writer
    // transaction, keeping changes plus metadata atomic without changing PRAGMAs.
    let mut transaction = pool.begin_with("BEGIN IMMEDIATE").await?;
    let has_go_ledger: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM main.sqlite_master \
         WHERE type = 'table' AND name = 'migrations')",
    )
    .fetch_one(&mut *transaction)
    .await?;
    let go_migration_ids: Vec<String> = if has_go_ledger {
        sqlx::query_scalar("SELECT id FROM main.migrations ORDER BY id")
            .fetch_all(&mut *transaction)
            .await?
    } else {
        Vec::new()
    };
    Migrate::ensure_migrations_table(&mut *transaction).await?;
    if let Some(version) = Migrate::dirty_version(&mut *transaction).await? {
        return Err(MigrateError::Dirty(version).into());
    }
    let applied = Migrate::list_applied_migrations(&mut *transaction).await?;
    for recorded in &applied {
        let migration = SQLITE_MIGRATOR
            .iter()
            .find(|migration| migration.version == recorded.version)
            .ok_or(MigrateError::VersionMissing(recorded.version))?;
        if migration.checksum != recorded.checksum {
            return Err(MigrateError::VersionMismatch(recorded.version).into());
        }
    }

    let mut completed_versions = Vec::new();
    for &(version, go_id) in SQLITE_GO_DATA_REPAIRS {
        if go_migration_ids.iter().any(|id| id == go_id)
            && !applied.iter().any(|recorded| recorded.version == version)
        {
            completed_versions.push(version);
        }
    }
    let owner_repair_version = 20_260_524_000_014;
    if !applied
        .iter()
        .any(|recorded| recorded.version == owner_repair_version)
        && !go_migration_ids
            .iter()
            .any(|id| id == CLEAR_TAGGED_NODE_USER_ID_MIGRATION)
    {
        let owner_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pragma_table_info('nodes', 'main') \
             WHERE name IN ('user_id', 'tags')",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if owner_columns == 2 {
            // Execute a pending repair with Go's fixed predicate. The older
            // SQLx predicate also matches tags='null'; do not rewrite that valid
            // nil-tag spelling just to make its historical SQL safe to replay.
            sqlx::query(
                "UPDATE main.nodes SET user_id = NULL \
                 WHERE tags IS NOT NULL AND tags != '[]' AND tags != '' AND tags != 'null'",
            )
            .execute(&mut *transaction)
            .await
            .map_err(|error| MigrateError::ExecuteMigration(error, owner_repair_version))?;
            completed_versions.push(owner_repair_version);
        }
    }
    if SQLITE_OBSOLETE_NODE_KEY_INDEX_MIGRATIONS
        .iter()
        .all(|version| !applied.iter().any(|recorded| recorded.version == *version))
    {
        // As on Postgres, only this obsolete pair is adopted by its net final
        // schema. Go never required unique live NodeKeys. When the create is
        // already recorded, leave its pending drop to the normal migrator.
        sqlx::query("DROP INDEX IF EXISTS main.idx_nodes_node_key_live")
            .execute(&mut *transaction)
            .await?;
        completed_versions.extend(SQLITE_OBSOLETE_NODE_KEY_INDEX_MIGRATIONS);
    }
    for version in completed_versions {
        let migration = SQLITE_MIGRATOR
            .iter()
            .find(|migration| migration.version == version)
            .ok_or(MigrateError::VersionNotPresent(version))?;
        // Use the immutable embedded SQLx metadata, including its original
        // checksum, after exact-ID adoption or the compatible repair execution
        // above. A version stamp cannot stand in for the exact Go repair ID.
        sqlx::query(
            "INSERT INTO main._sqlx_migrations \
             (version, description, success, checksum, execution_time) \
             VALUES (?, ?, TRUE, ?, -1)",
        )
        .bind(migration.version)
        .bind(&*migration.description)
        .bind(&*migration.checksum)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
pub(crate) async fn migrate_postgres_foundation_on_connection(
    conn: &mut PgConnection,
) -> Result<()> {
    // Acquire before inspecting imported tables, and retain the lock until the
    // final markers commit. Otherwise a concurrent Rust startup can observe a
    // partially installed foundation or race CREATE TABLE for the Go ledger.
    Migrate::lock(conn).await?;
    let result: Result<()> = async {
        check_postgres_headscale_go_import_compatibility(conn).await?;
        prepare_postgres_foundation_ledger(conn).await?;
        normalize_postgres_null_tags_before_migration(conn).await?;
        POSTGRES_FOUNDATION_MIGRATOR.run(&mut *conn).await?;
        // Publish the Go ledger and current-version marker as one unit. In
        // particular, cancellation must not leave a newly created migrations
        // table containing only the first few fresh-Go IDs: a later restart
        // would treat it as an imported ledger and skip the remaining fresh IDs.
        let mut transaction = conn.begin().await?;
        stamp_postgres_go_release_migrations(&mut transaction).await?;
        stamp_postgres_database_version(&mut transaction).await?;
        transaction.commit().await?;
        Ok(())
    }
    .await;
    // Try to release on ordinary failure too, retaining the original error.
    // The pooled entry point closes the session if this future is cancelled;
    // owners of directly borrowed connections retain cancellation cleanup.
    let unlock_result = Migrate::unlock(conn).await;
    result?;
    unlock_result?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
async fn prepare_postgres_foundation_ledger(conn: &mut PgConnection) -> Result<()> {
    let go_migration_ids = if postgres_table_exists(conn, "migrations").await? {
        postgres_go_migration_ids(conn).await?
    } else {
        Vec::new()
    };

    // The caller holds the foundation advisory lock. Record all already-run
    // Go repairs, the compatible pending repair below, and the obsolete index
    // pair together, including creation of the SQLx ledger on first import.
    // Cancellation cannot publish metadata without its corresponding changes.
    let mut transaction = conn.begin().await?;
    Migrate::ensure_migrations_table(&mut *transaction).await?;
    if let Some(version) = Migrate::dirty_version(&mut *transaction).await? {
        return Err(MigrateError::Dirty(version).into());
    }
    let applied = Migrate::list_applied_migrations(&mut *transaction).await?;
    for recorded in &applied {
        let migration = POSTGRES_FOUNDATION_MIGRATOR
            .iter()
            .find(|migration| migration.version == recorded.version)
            .ok_or(MigrateError::VersionMissing(recorded.version))?;
        if migration.checksum != recorded.checksum {
            return Err(MigrateError::VersionMismatch(recorded.version).into());
        }
    }

    let mut completed_versions = Vec::new();
    for &(version, go_id) in POSTGRES_GO_DATA_REPAIRS {
        if go_migration_ids.iter().any(|id| id == go_id)
            && !applied.iter().any(|recorded| recorded.version == version)
        {
            completed_versions.push(version);
        }
    }
    let owner_repair_version = 20_260_601_000_009;
    if !applied
        .iter()
        .any(|recorded| recorded.version == owner_repair_version)
        && !go_migration_ids
            .iter()
            .any(|id| id == CLEAR_TAGGED_NODE_USER_ID_MIGRATION)
    {
        let owner_columns: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pg_attribute \
             WHERE attrelid = to_regclass('nodes') AND attnum > 0 AND NOT attisdropped \
             AND attname IN ('user_id', 'tags')",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if owner_columns == 2 {
            // This is an executed pending repair, not Go-ledger adoption. Keep
            // nil tags unchanged while applying the pinned Go owner predicate.
            sqlx::query(
                "UPDATE nodes SET user_id = NULL \
                 WHERE tags IS NOT NULL AND tags != '[]' AND tags != '' AND tags != 'null'",
            )
            .execute(&mut *transaction)
            .await
            .map_err(|error| MigrateError::ExecuteMigration(error, owner_repair_version))?;
            completed_versions.push(owner_repair_version);
        }
    }
    let zero_expiry_version = 20_260_530_000_007;
    if !applied
        .iter()
        .any(|recorded| recorded.version == zero_expiry_version)
        && !go_migration_ids
            .iter()
            .any(|id| id == CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION)
        && postgres_table_exists(&mut transaction, "nodes").await?
    {
        // This executes a pending repair; it is not Go-ledger adoption. Go's
        // unqualified date literal uses the session's TimeZone. The historical
        // SQLx file instead fixed UTC, which changes the cutoff on native
        // non-UTC sessions. Keep that immutable file/checksum while applying
        // the pinned Go predicate and recording its completion atomically.
        sqlx::query(
            "UPDATE nodes SET expiry = NULL \
             WHERE expiry IS NOT NULL AND expiry < '1900-01-01'",
        )
        .execute(&mut *transaction)
        .await
        .map_err(|error| MigrateError::ExecuteMigration(error, zero_expiry_version))?;
        completed_versions.push(zero_expiry_version);
    }
    if POSTGRES_OBSOLETE_NODE_KEY_INDEX_MIGRATIONS
        .iter()
        .all(|version| !applied.iter().any(|recorded| recorded.version == *version))
    {
        // This is net-schema adoption, not evidence of a Go migration ID. Run
        // the final drop even if an unrecorded index happens to exist. If the
        // create is already recorded, the normal migrator still runs its drop.
        sqlx::query("DROP INDEX IF EXISTS idx_nodes_node_key_live")
            .execute(&mut *transaction)
            .await?;
        completed_versions.extend(POSTGRES_OBSOLETE_NODE_KEY_INDEX_MIGRATIONS);
    }
    for version in completed_versions {
        let migration = POSTGRES_FOUNDATION_MIGRATOR
            .iter()
            .find(|migration| migration.version == version)
            .ok_or(MigrateError::VersionNotPresent(version))?;
        // Retain the immutable migration's original description and checksum.
        // Except for the pending compatible repairs executed above, missing Go
        // IDs still run through the normal SQLx migrator below. Neither the
        // current version stamp nor a neighboring ID proves that a repair ran.
        // As in SQLx, -1 means no execution duration was recorded.
        sqlx::query(
            "INSERT INTO _sqlx_migrations \
             (version, description, success, checksum, execution_time) \
             VALUES ($1, $2, TRUE, $3, -1)",
        )
        .bind(migration.version)
        .bind(&*migration.description)
        .bind(&*migration.checksum)
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
async fn stamp_postgres_go_release_migrations(conn: &mut PgConnection) -> Result<()> {
    // An imported Go database retains its historical ledger. A Rust-created
    // database needs the full fresh-Go ledger so a direct Go reopen does not
    // replay migrations against a schema that is already current.
    let has_go_ledger = postgres_table_exists(conn, "migrations").await?;
    let fresh_go_ledger = !has_go_ledger || postgres_go_migration_ids(conn).await?.is_empty();
    if fresh_go_ledger {
        if !has_go_ledger {
            sqlx::query("CREATE TABLE migrations (id TEXT PRIMARY KEY)")
                .execute(&mut *conn)
                .await?;
        }
        for id in FRESH_GO_POSTGRES_MIGRATIONS {
            sqlx::query("INSERT INTO migrations (id) VALUES ($1)")
                .bind(id)
                .execute(&mut *conn)
                .await?;
        }
        return Ok(());
    }

    for id in [
        CLEAR_TAGGED_NODE_USER_ID_MIGRATION,
        CLEAR_ZERO_TIME_NODE_EXPIRY_MIGRATION,
        RECOVER_NULL_TAGS_NODE_USER_ID_MIGRATION,
        CLEAR_TAGGED_NODE_EXPIRY_MIGRATION,
    ] {
        sqlx::query("INSERT INTO migrations (id) VALUES ($1) ON CONFLICT (id) DO NOTHING")
            .bind(id)
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
}

#[cfg(feature = "postgres-sqlx")]
async fn normalize_postgres_null_tags_before_migration(conn: &mut PgConnection) -> Result<()> {
    // Only the pending historical Rust owner repair needs this workaround for
    // its older predicate. Already-applied/adopted repairs must leave imported
    // Go's valid null-tag spelling unchanged.
    let owner_repair_applied: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM _sqlx_migrations WHERE version = $1 AND success)",
    )
    .bind(20_260_601_000_009_i64)
    .fetch_one(&mut *conn)
    .await?;
    if owner_repair_applied {
        return Ok(());
    }
    if postgres_table_exists(conn, "nodes").await? {
        sqlx::query("UPDATE nodes SET tags = '[]' WHERE tags = 'null'")
            .execute(&mut *conn)
            .await?;
    }
    Ok(())
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

    if stored_version == HEADSCALE_GO_CURRENT_VERSION
        || stored_version == LEGACY_RUST_SQLITE_VERSION
    {
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
            validate_postgres_current_upstream_go_shape(conn, stored_version, stored.patch).await?;
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
    patch: u64,
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
    validate_release_migrations(&migration_ids, stored_version, patch)?;

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
        .any(|id| id == CLEAR_TAGGED_NODE_EXPIRY_MIGRATION)
    {
        CLEAR_TAGGED_NODE_EXPIRY_MIGRATION
    } else if migration_ids
        .iter()
        .any(|id| id == RECOVER_NULL_TAGS_NODE_USER_ID_MIGRATION)
    {
        RECOVER_NULL_TAGS_NODE_USER_ID_MIGRATION
    } else if migration_ids
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
            validate_current_upstream_go_shape(pool, stored_version, stored.patch).await?;
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

async fn validate_current_upstream_go_shape(
    pool: &SqlitePool,
    stored_version: &str,
    patch: u64,
) -> Result<()> {
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
    validate_release_migrations(&migration_ids, stored_version, patch)?;

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
        .any(|id| id == CLEAR_TAGGED_NODE_EXPIRY_MIGRATION)
    {
        CLEAR_TAGGED_NODE_EXPIRY_MIGRATION
    } else if migration_ids
        .iter()
        .any(|id| id == RECOVER_NULL_TAGS_NODE_USER_ID_MIGRATION)
    {
        RECOVER_NULL_TAGS_NODE_USER_ID_MIGRATION
    } else if migration_ids
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

fn validate_release_migrations(
    migration_ids: &[String],
    stored_version: &str,
    patch: u64,
) -> Result<()> {
    for (minimum_patch, migration) in [
        (1, RECOVER_NULL_TAGS_NODE_USER_ID_MIGRATION),
        (3, CLEAR_TAGGED_NODE_EXPIRY_MIGRATION),
    ] {
        if patch >= minimum_patch && !migration_ids.iter().any(|id| id == migration) {
            return unsupported(format!(
                "database_versions.version is {stored_version}, but headscale-go migrations table is not migrated through {migration}"
            ));
        }
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
