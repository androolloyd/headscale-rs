//! Convert a fully migrated legacy Rust SQLite file into the pinned Go primary
//! schema and a Rust-only sidecar. Native startup backs up the primary before
//! legacy/import migrations; the converter also backs up its own input before
//! changing either database's schema. VACUUM preserves logical database state,
//! rather than the byte layout before connection PRAGMAs or sidecar attachment.

use crate::{DbError, Result, sqlite_go_schema};
use chrono::{DateTime, Datelike, Utc};
use sqlx::{Connection, SqlitePool};
use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::time::{SystemTime, UNIX_EPOCH};

const LEGACY_VERSION: &str = "v0.29.0-beta.2";
const LATEST_RUST_MIGRATION: i64 = 20_261_016_000_019;
const AUXILIARY: &[&str] = &[
    "octra_nodes",
    "transactions",
    "account_balances",
    "resources",
    "resource_usage",
    "sessions",
];
const KNOWN_LEGACY_INDEXES: &[&str] = &[
    "idx_api_keys_expiration",
    "idx_api_keys_prefix",
    "idx_name_no_provider_identifier",
    "idx_name_provider_identifier",
    "idx_nodes_auth_key_id",
    "idx_nodes_deleted_at",
    "idx_nodes_given_name",
    "idx_nodes_ipv4",
    "idx_nodes_ipv6",
    "idx_nodes_user_id",
    "idx_octra_nodes_capabilities",
    "idx_octra_nodes_online",
    "idx_octra_nodes_wg_pubkey",
    "idx_policies_deleted_at",
    "idx_pre_auth_keys_expiration",
    "idx_pre_auth_keys_prefix",
    "idx_pre_auth_keys_user_id",
    "idx_provider_identifier",
    "idx_resources_provider",
    "idx_resources_type",
    "idx_sessions_did",
    "idx_sessions_expiry",
    "idx_transactions_from",
    "idx_transactions_timestamp",
    "idx_transactions_to",
    "idx_transactions_type",
    "idx_usage_active",
    "idx_usage_consumer",
    "idx_usage_provider",
    "idx_users_deleted_at",
];
const PRIMARY: &[(&str, &str)] = &[
    (
        "users",
        "id, name, display_name, email, provider_identifier, provider, \
         profile_pic_url, created_at, updated_at, deleted_at",
    ),
    (
        "pre_auth_keys",
        "id, key, prefix, hash, user_id, reusable, ephemeral, used, tags, \
         expiration, created_at",
    ),
    (
        "api_keys",
        "id, prefix, hash, expiration, last_seen, created_at",
    ),
    (
        "nodes",
        "id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, \
         ipv6, hostname, given_name, user_id, register_method, tags, auth_key_id, \
         last_seen, expiry, approved_routes, created_at, updated_at, deleted_at",
    ),
    ("policies", "id, data, created_at, updated_at, deleted_at"),
];
// The legacy Rust writers stored Unix seconds in these DATETIME columns.
// glebarez/go-sqlite v1.22.0 only turns TEXT timestamps into time.Time;
// database/sql cannot scan an INTEGER into Gorm's **time.Time destination.
const PRIMARY_TIME_COLUMNS: &[(&str, &[&str])] = &[
    ("users", &["created_at", "updated_at", "deleted_at"]),
    ("pre_auth_keys", &["expiration", "created_at"]),
    ("api_keys", &["expiration", "last_seen", "created_at"]),
    (
        "nodes",
        &[
            "last_seen",
            "expiry",
            "created_at",
            "updated_at",
            "deleted_at",
        ],
    ),
    ("policies", &["created_at", "updated_at", "deleted_at"]),
];

pub(crate) async fn backup_before_migration(pool: &SqlitePool) -> Result<()> {
    let (main_file, backup) = backup_primary(pool).await?;
    tracing::info!(source = %main_file, path = %backup, "saved SQLite primary backup before legacy/import migrations");
    Ok(())
}

async fn backup_primary(pool: &SqlitePool) -> Result<(String, String)> {
    let mut connection = pool.acquire().await?;
    // VACUUM runs outside an explicit transaction. If its future is cancelled,
    // do not return the worker session to the application pool while it may
    // still be finishing the copy. The source remains unmodified by this copy.
    connection.close_on_drop();
    let main_file: String =
        sqlx::query_scalar("SELECT file FROM pragma_database_list WHERE name = 'main'")
            .fetch_one(&mut *connection)
            .await?;
    if main_file.is_empty() {
        return Err(DbError::General(
            "legacy SQLite upgrade requires a file-backed database".into(),
        ));
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| DbError::General(format!("system clock before epoch: {error}")))?
        .as_nanos();
    let backup = format!("{main_file}.pre-v0295-{nanos}.sqlite");
    // SQLite accepts an existing empty VACUUM INTO destination. Reserve it
    // exclusively so a naming collision cannot overwrite someone else's file.
    let mut backup_options = OpenOptions::new();
    backup_options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        backup_options.mode(0o600);
    }
    let reserved = backup_options
        .open(&backup)
        .map_err(|error| DbError::General(format!("reserving SQLite backup {backup}: {error}")))?;
    drop(reserved);
    // Keep a failed/cancelled destination: unlinking from Drop could race a
    // still-running SQLite worker. Only a successful return is a usable backup;
    // callers must not begin migration writes until this copy succeeds.
    sqlx::query("VACUUM main INTO ?")
        .bind(&backup)
        .execute(&mut *connection)
        .await?;
    Ok((main_file, backup))
}

pub(crate) async fn upgrade(pool: &SqlitePool) -> Result<()> {
    // Preserve the converter's standalone recovery point, independently of
    // the earlier native-startup backup. Release its connection before the
    // pool-based auxiliary initializer, including when max_connections is one.
    let (main_file, backup) = backup_primary(pool).await?;
    tracing::info!(path = %backup, "saved legacy SQLite backup before Go-schema upgrade");
    sqlite_go_schema::initialize_auxiliary(pool).await?;
    let mut connection = pool.acquire().await?;
    // Rebuilding temporarily disables this connection's foreign keys and
    // creates temporary tables. Cancellation can bypass the explicit PRAGMA
    // restoration below, so this migration session must never reenter the
    // application pool with altered connection-local state.
    connection.close_on_drop();

    let version: String =
        sqlx::query_scalar("SELECT version FROM main.database_versions WHERE id = 1")
            .fetch_one(&mut *connection)
            .await?;
    let latest: i64 = sqlx::query_scalar(
        "SELECT COALESCE(MAX(version), 0) FROM main._sqlx_migrations WHERE success = 1",
    )
    .fetch_one(&mut *connection)
    .await?;
    let failures: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM main._sqlx_migrations WHERE success != 1")
            .fetch_one(&mut *connection)
            .await?;
    if version != LEGACY_VERSION || latest != LATEST_RUST_MIGRATION || failures != 0 {
        return Err(DbError::General(format!(
            "legacy SQLite upgrade requires {LEGACY_VERSION}, successful SQLx migration \
             {LATEST_RUST_MIGRATION}, and no failed migrations; got {version}, {latest}, \
             {failures} failed"
        )));
    }
    if sqlx::query("PRAGMA main.foreign_key_check")
        .fetch_optional(&mut *connection)
        .await?
        .is_some()
    {
        return Err(DbError::General(
            "legacy SQLite database has foreign-key violations".into(),
        ));
    }
    let expected_tables: BTreeSet<&str> = AUXILIARY
        .iter()
        .copied()
        .chain(PRIMARY.iter().map(|(table, _)| *table))
        .chain(["database_versions", "_sqlx_migrations"])
        .collect();
    let actual_tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM main.sqlite_master WHERE type = 'table' \
         AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .fetch_all(&mut *connection)
    .await?;
    let missing: Vec<&str> = expected_tables
        .iter()
        .copied()
        .filter(|table| !actual_tables.iter().any(|name| name == table))
        .collect();
    let extra: Vec<&str> = actual_tables
        .iter()
        .map(String::as_str)
        .filter(|table| !expected_tables.contains(table) && *table != "migrations")
        .collect();
    if !missing.is_empty() || !extra.is_empty() {
        return Err(DbError::General(format!(
            "legacy SQLite upgrade found unsupported tables: missing={missing:?}, extra={extra:?}"
        )));
    }
    let extra_objects: Vec<String> = sqlx::query_scalar(
        "SELECT type || ':' || name FROM main.sqlite_master \
         WHERE type IN ('view', 'trigger') \
         AND NOT (type = 'trigger' AND name = 'cleanup_expired_sessions')",
    )
    .fetch_all(&mut *connection)
    .await?;
    if !extra_objects.is_empty() {
        return Err(DbError::General(format!(
            "legacy SQLite upgrade found unsupported views/triggers: {extra_objects:?}"
        )));
    }
    let extra_indexes: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM main.sqlite_master WHERE type = 'index' \
         AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )
    .fetch_all(&mut *connection)
    .await?
    .into_iter()
    .filter(|index: &String| !KNOWN_LEGACY_INDEXES.contains(&index.as_str()))
    .collect();
    if !extra_indexes.is_empty() {
        return Err(DbError::General(format!(
            "legacy SQLite upgrade found unsupported indexes: {extra_indexes:?}"
        )));
    }

    copy_auxiliary(&mut connection).await?;
    rebuild_primary(&mut connection).await?;
    tracing::info!(path = %main_file, backup = %backup, "upgraded legacy SQLite primary to headscale-go v0.29.5 schema");
    Ok(())
}

async fn copy_auxiliary(connection: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>) -> Result<()> {
    let mut transaction = connection.begin_with("BEGIN IMMEDIATE").await?;
    sqlx::query("DROP TRIGGER rust_aux.cleanup_expired_sessions")
        .execute(&mut *transaction)
        .await?;
    for table in AUXILIARY {
        let source_count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM main.{table}"))
            .fetch_one(&mut *transaction)
            .await?;
        let target_count: i64 =
            sqlx::query_scalar(&format!("SELECT COUNT(*) FROM rust_aux.{table}"))
                .fetch_one(&mut *transaction)
                .await?;
        if target_count == 0 {
            sqlx::query(&format!(
                "INSERT INTO rust_aux.{table} SELECT * FROM main.{table}"
            ))
            .execute(&mut *transaction)
            .await?;
        } else {
            let different: i64 = sqlx::query_scalar(&format!(
                "SELECT EXISTS(SELECT * FROM main.{table} EXCEPT SELECT * FROM rust_aux.{table}) \
                 OR EXISTS(SELECT * FROM rust_aux.{table} EXCEPT SELECT * FROM main.{table})"
            ))
            .fetch_one(&mut *transaction)
            .await?;
            if source_count != target_count || different != 0 {
                return Err(DbError::General(format!(
                    "existing Rust sidecar {table} differs from legacy primary"
                )));
            }
        }
    }

    for table in ["resources", "resource_usage"] {
        let old: Option<i64> =
            sqlx::query_scalar("SELECT seq FROM main.sqlite_sequence WHERE name = ?")
                .bind(table)
                .fetch_optional(&mut *transaction)
                .await?;
        if let Some(sequence) = old {
            let result =
                sqlx::query("UPDATE rust_aux.sqlite_sequence SET seq = MAX(seq, ?) WHERE name = ?")
                    .bind(sequence)
                    .bind(table)
                    .execute(&mut *transaction)
                    .await?;
            if result.rows_affected() == 0 {
                sqlx::query("INSERT INTO rust_aux.sqlite_sequence(name, seq) VALUES (?, ?)")
                    .bind(table)
                    .bind(sequence)
                    .execute(&mut *transaction)
                    .await?;
            }
        }
    }
    sqlx::raw_sql(
        "CREATE TRIGGER rust_aux.cleanup_expired_sessions AFTER INSERT ON sessions \
         BEGIN DELETE FROM sessions WHERE expires_at < unixepoch(); END;",
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn rebuild_primary(connection: &mut sqlx::pool::PoolConnection<sqlx::Sqlite>) -> Result<()> {
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut **connection)
        .await?;
    let result = async {
        let mut transaction = connection.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            "CREATE TEMP TABLE __hs_upgrade_sequences AS \
             SELECT name, seq FROM main.sqlite_sequence",
        )
        .execute(&mut *transaction)
        .await?;
        for (table, columns) in PRIMARY {
            sqlx::query(&format!(
                "CREATE TEMP TABLE __hs_upgrade_{table} AS \
                 SELECT {columns} FROM main.{table}"
            ))
            .execute(&mut *transaction)
            .await?;
        }
        // Normalize only the transaction's copies, before dropping any source
        // table or publishing the Go ledger/version. A conversion error rolls
        // back the entire primary rebuild and leaves the original backup.
        normalize_legacy_timestamps(&mut transaction).await?;
        for table in ["nodes", "pre_auth_keys", "api_keys", "policies", "users"] {
            sqlx::query(&format!("DROP TABLE main.{table}"))
                .execute(&mut *transaction)
                .await?;
        }
        for table in AUXILIARY {
            sqlx::query(&format!("DROP TABLE main.{table}"))
                .execute(&mut *transaction)
                .await?;
        }
        for table in ["migrations", "database_versions", "_sqlx_migrations"] {
            sqlx::query(&format!("DROP TABLE IF EXISTS main.{table}"))
                .execute(&mut *transaction)
                .await?;
        }
        sqlx::raw_sql(sqlite_go_schema::GO_SCHEMA)
            .execute(&mut *transaction)
            .await?;
        for (table, columns) in PRIMARY {
            sqlx::query(&format!(
                "INSERT INTO main.{table} ({columns}) \
                 SELECT {columns} FROM temp.__hs_upgrade_{table}"
            ))
            .execute(&mut *transaction)
            .await?;
        }
        for table in ["users", "pre_auth_keys", "api_keys", "nodes", "policies"] {
            let old: Option<i64> =
                sqlx::query_scalar("SELECT seq FROM temp.__hs_upgrade_sequences WHERE name = ?")
                    .bind(table)
                    .fetch_optional(&mut *transaction)
                    .await?;
            if let Some(sequence) = old {
                let result =
                    sqlx::query("UPDATE main.sqlite_sequence SET seq = MAX(seq, ?) WHERE name = ?")
                        .bind(sequence)
                        .bind(table)
                        .execute(&mut *transaction)
                        .await?;
                if result.rows_affected() == 0 {
                    sqlx::query("INSERT INTO main.sqlite_sequence(name, seq) VALUES (?, ?)")
                        .bind(table)
                        .bind(sequence)
                        .execute(&mut *transaction)
                        .await?;
                }
            }
        }
        for migration in sqlite_go_schema::GO_MIGRATIONS {
            sqlx::query("INSERT INTO migrations(id) VALUES (?)")
                .bind(migration)
                .execute(&mut *transaction)
                .await?;
        }
        sqlx::query(
            "INSERT INTO database_versions(id, version, updated_at) \
             VALUES (1, 'v0.29.5', CURRENT_TIMESTAMP)",
        )
        .execute(&mut *transaction)
        .await?;
        if sqlx::query("PRAGMA main.foreign_key_check")
            .fetch_optional(&mut *transaction)
            .await?
            .is_some()
        {
            return Err(DbError::General(
                "Go-schema SQLite rebuild has foreign-key violations".into(),
            ));
        }
        let integrity: String = sqlx::query_scalar("PRAGMA main.integrity_check")
            .fetch_one(&mut *transaction)
            .await?;
        if integrity != "ok" {
            return Err(DbError::General(format!(
                "Go-schema SQLite rebuild failed integrity check: {integrity}"
            )));
        }
        for (table, _) in PRIMARY {
            sqlx::query(&format!("DROP TABLE temp.__hs_upgrade_{table}"))
                .execute(&mut *transaction)
                .await?;
        }
        sqlx::query("DROP TABLE temp.__hs_upgrade_sequences")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }
    .await;
    let restore = sqlx::query("PRAGMA foreign_keys = ON")
        .execute(&mut **connection)
        .await;
    result?;
    restore?;
    Ok(())
}

async fn normalize_legacy_timestamps(
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
) -> Result<()> {
    for (table, columns) in PRIMARY_TIME_COLUMNS {
        // CREATE TABLE AS does not retain the source primary-key index.
        // Restore an index on the temporary copy for bounded forward scans.
        sqlx::query(&format!(
            "CREATE INDEX temp.__hs_upgrade_time_ids_{table} \
             ON __hs_upgrade_{table}(id)"
        ))
        .execute(&mut **transaction)
        .await?;
        for column in *columns {
            let mut last_id: Option<i64> = None;
            loop {
                // Bound temporary row storage independently of database size.
                // SQL names come only from the private constants above.
                let after_id = if last_id.is_some() { " AND id > ?" } else { "" };
                let sql = format!(
                    "SELECT id, typeof({column}), \
                     CASE WHEN typeof({column}) = 'integer' THEN {column} END, \
                     CASE WHEN typeof({column}) = 'text' THEN {column} END \
                     FROM temp.__hs_upgrade_{table} \
                     WHERE {column} IS NOT NULL{after_id} \
                     ORDER BY id LIMIT 256"
                );
                let query = sqlx::query_as(&sql);
                let query = if let Some(id) = last_id {
                    query.bind(id)
                } else {
                    query
                };
                let rows: Vec<(i64, String, Option<i64>, Option<String>)> =
                    query.fetch_all(&mut **transaction).await?;
                if rows.is_empty() {
                    break;
                }
                for (id, kind, seconds, raw) in rows {
                    match (kind.as_str(), seconds) {
                        ("integer", Some(seconds)) => {
                            let time = DateTime::<Utc>::from_timestamp(seconds, 0)
                                .filter(|time| (0..=9999).contains(&time.year()))
                                .ok_or_else(|| {
                                    DbError::General(format!(
                                        "legacy SQLite upgrade cannot normalize {table}.{column} \
                                         for id {id}: Unix seconds {seconds} are outside Go's \
                                         four-digit timestamp year range 0000..9999"
                                    ))
                                })?;
                            // The first pinned driver layout accepts this
                            // exact UTC form. Only INTEGER cells change.
                            let text = time.format("%Y-%m-%d %H:%M:%S+00:00").to_string();
                            sqlx::query(&format!(
                                "UPDATE temp.__hs_upgrade_{table} SET {column} = ? WHERE id = ?"
                            ))
                            .bind(text)
                            .bind(id)
                            .execute(&mut **transaction)
                            .await?;
                        }
                        ("text", None)
                            if crate::preauth_keys::parse_database_timestamp(
                                None,
                                raw.as_deref(),
                            )
                            .is_some() =>
                        {
                            // Preserve valid TEXT bytes and fractional
                            // precision; validation uses only driver layouts.
                        }
                        _ => {
                            return Err(DbError::General(format!(
                                "legacy SQLite upgrade cannot publish {table}.{column} \
                                 for id {id}: {kind} value cannot scan as Go time.Time"
                            )));
                        }
                    }
                    last_id = Some(id);
                }
            }
        }
    }
    Ok(())
}
