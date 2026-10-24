//! Native headscale-go driver error envelopes. Generic DbError Display stays
//! unchanged for existing Rust callers. See UPSTREAM.md and driver notices.

use crate::{DbError, preauth_keys::timestamp::TimestampScanError};

pub(crate) fn message(error: &DbError) -> String {
    match error {
        DbError::Sqlx(error) => sqlx_message(error),
        DbError::NotFound(_) => "record not found".into(),
        DbError::Constraint(message) | DbError::General(message) => message.clone(),
        DbError::Serialization(error) => error.to_string(),
        error => error.to_string(),
    }
}

fn sqlx_message(error: &sqlx::Error) -> String {
    match error {
        sqlx::Error::Database(error) => database_message(error.as_ref()),
        sqlx::Error::RowNotFound => "record not found".into(),
        sqlx::Error::PoolClosed => "sql: database is closed".into(),
        sqlx::Error::ColumnDecode { source, .. } => {
            // The typed source retains measured SQLite model-column context.
            // SQLx's synthetic projection index is not that native ordinal.
            source
                .downcast_ref::<TimestampScanError>()
                .map_or_else(|| error.to_string(), TimestampScanError::native_message)
        }
        error => error.to_string(),
    }
}

fn database_message(error: &(dyn sqlx::error::DatabaseError + 'static)) -> String {
    if error
        .try_downcast_ref::<sqlx::sqlite::SqliteError>()
        .is_some()
        && let Some(code) = error.code().and_then(|code| code.parse::<i32>().ok())
    {
        let label = sqlite_error_label(code);
        let suffix = if code == 5 { " (SQLITE_BUSY)" } else { "" };
        return if error.message() == label {
            format!("{label} ({code}){suffix}")
        } else {
            format!("{label}: {} ({code}){suffix}", error.message())
        };
    }
    #[cfg(feature = "postgres-sqlx")]
    if let Some(error) = error.try_downcast_ref::<sqlx::postgres::PgDatabaseError>() {
        let severity = format!("{:?}", error.severity()).to_uppercase();
        return format!(
            "{severity}: {} (SQLSTATE {})",
            error.message(),
            error.code()
        );
    }
    error.to_string()
}

fn sqlite_error_label(code: i32) -> &'static str {
    match code {
        516 => "abort due to ROLLBACK",
        100 => "another row available",
        101 => "no more rows available",
        code => match code & 0xff {
            0 => "not an error",
            1 => "SQL logic error",
            3 => "access permission denied",
            4 => "query aborted",
            5 => "database is locked",
            6 => "database table is locked",
            7 => "out of memory",
            8 => "attempt to write a readonly database",
            9 => "interrupted",
            10 => "disk I/O error",
            11 => "database disk image is malformed",
            12 => "unknown operation",
            13 => "database or disk is full",
            14 => "unable to open database file",
            15 => "locking protocol",
            17 => "database schema has changed",
            18 => "string or blob too big",
            19 => "constraint failed",
            20 => "datatype mismatch",
            21 => "bad parameter or other API misuse",
            23 => "authorization denied",
            25 => "column index out of range",
            26 => "file is not a database",
            27 => "notification message",
            28 => "warning message",
            _ => "unknown error",
        },
    }
}
