//! Preserve public String hash projections without requiring Go SQL []byte
//! fields to be UTF-8. Authentication uses a separate raw-byte projection.

use sqlx::{Decode, Sqlite, Type, ValueRef};

type ColumnError = Box<dyn std::error::Error + Send + Sync + 'static>;

#[doc(hidden)]
pub struct HashColumn(String);

impl Type<Sqlite> for HashColumn {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <Vec<u8> as Type<Sqlite>>::type_info()
    }

    fn compatible(_: &sqlx::sqlite::SqliteTypeInfo) -> bool {
        // SQLite's dynamic scalar/blob/string values all scan into Go []byte.
        true
    }
}

impl<'r> Decode<'r, Sqlite> for HashColumn {
    fn decode(value: sqlx::sqlite::SqliteValueRef<'r>) -> Result<Self, ColumnError> {
        let bytes = if value.is_null() {
            &[][..]
        } else {
            <&[u8] as Decode<'r, Sqlite>>::decode(value)?
        };
        Ok(Self(String::from_utf8_lossy(bytes).into_owned()))
    }
}

#[cfg(feature = "postgres-sqlx")]
impl Type<sqlx::Postgres> for HashColumn {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <Vec<u8> as Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(info: &sqlx::postgres::PgTypeInfo) -> bool {
        <Vec<u8> as Type<sqlx::Postgres>>::compatible(info)
            || <String as Type<sqlx::Postgres>>::compatible(info)
    }
}

#[cfg(feature = "postgres-sqlx")]
impl<'r> Decode<'r, sqlx::Postgres> for HashColumn {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, ColumnError> {
        if value.is_null() {
            return Ok(Self(String::new()));
        }
        let bytes = if <Vec<u8> as Type<sqlx::Postgres>>::compatible(value.type_info().as_ref()) {
            <Vec<u8> as Decode<'r, sqlx::Postgres>>::decode(value)?
        } else {
            value.as_bytes()?.to_vec()
        };
        Ok(Self(String::from_utf8_lossy(&bytes).into_owned()))
    }
}

impl From<HashColumn> for String {
    fn from(column: HashColumn) -> Self {
        column.0
    }
}
