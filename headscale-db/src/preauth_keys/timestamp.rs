// Copyright 2010 The Go Authors. All rights reserved.
// Copyright (c) 2020, Juan Font
// Copyright (c) 2017 The Sqlite Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Validate nullable expiration during SQL row decoding. SQLite's private
//! projection includes storage type, distinguishing numeric date TEXT from
//! Rust-managed legacy INTEGER Unix seconds. Unparsed driver strings cannot scan into
//! Gorm's pooled **time.Time; its string setter is a separate code path.

use chrono::{DateTime, SecondsFormat, Utc};
use sqlx::{Decode, Sqlite, Type, ValueRef};

mod error;
mod layout;
pub(crate) use error::TimestampScanError;

type ColumnError = Box<dyn std::error::Error + Send + Sync + 'static>;

pub(crate) struct ExpirationColumn {
    raw: Option<String>,
    time: Option<DateTime<Utc>>,
}

pub(crate) struct CanonicalExpirationColumn(Option<String>);

fn validate(raw: Option<String>) -> Result<ExpirationColumn, ColumnError> {
    let time = if let Some(text) = &raw {
        Some(layout::read(text).ok_or(TimestampScanError::String(None))?)
    } else {
        None
    };
    Ok(ExpirationColumn { raw, time })
}

impl Type<Sqlite> for ExpirationColumn {
    fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
        <String as Type<Sqlite>>::type_info()
    }

    fn compatible(info: &sqlx::sqlite::SqliteTypeInfo) -> bool {
        <String as Type<Sqlite>>::compatible(info)
    }
}

impl<'r> Decode<'r, Sqlite> for ExpirationColumn {
    fn decode(value: sqlx::sqlite::SqliteValueRef<'r>) -> Result<Self, ColumnError> {
        if value.is_null() {
            return validate(None);
        }
        let projection = <String as Decode<'r, Sqlite>>::decode(value)?;
        let (kind, raw, index, column): (String, Option<String>, Option<i64>, String) =
            serde_json::from_str(&projection)?;
        let result: Result<Self, ColumnError> = match (kind.as_str(), raw) {
            ("null", None) => validate(None),
            ("legacy_integer", Some(raw)) => {
                let seconds = raw.parse::<i64>()?;
                let time = DateTime::from_timestamp(seconds, 0).ok_or_else(|| {
                    crate::DbError::General("persisted expiration timestamp out of range".into())
                })?;
                Ok(Self {
                    raw: Some(time.to_rfc3339_opts(SecondsFormat::Nanos, true)),
                    time: Some(time),
                })
            }
            ("integer", _) => Err(TimestampScanError::Int64(None).into()),
            ("real", _) => Err(TimestampScanError::Float64(None).into()),
            ("blob", _) => Err(TimestampScanError::Bytes(None).into()),
            ("text", Some(raw)) => validate(Some(raw)),
            _ => Err(
                crate::DbError::General("invalid persisted expiration storage type".into()).into(),
            ),
        };
        result.map_err(|error| match error.downcast::<TimestampScanError>() {
            Ok(error) => Box::new((*error).with_column(index, &column)) as ColumnError,
            Err(error) => error,
        })
    }
}

#[cfg(feature = "postgres-sqlx")]
impl Type<sqlx::Postgres> for ExpirationColumn {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as Type<sqlx::Postgres>>::type_info()
    }

    fn compatible(info: &sqlx::postgres::PgTypeInfo) -> bool {
        <String as Type<sqlx::Postgres>>::compatible(info)
    }
}

#[cfg(feature = "postgres-sqlx")]
impl<'r> Decode<'r, sqlx::Postgres> for ExpirationColumn {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, ColumnError> {
        if value.is_null() {
            return validate(None);
        }
        validate(Some(<String as Decode<'r, sqlx::Postgres>>::decode(value)?))
    }
}

impl From<ExpirationColumn> for Option<String> {
    fn from(column: ExpirationColumn) -> Self {
        column.raw
    }
}

impl From<ExpirationColumn> for CanonicalExpirationColumn {
    fn from(column: ExpirationColumn) -> Self {
        Self(
            column
                .time
                .map(|time| time.to_rfc3339_opts(SecondsFormat::Nanos, true)),
        )
    }
}

macro_rules! canonical_column {
    ($database:ty, $info:ty) => {
        impl Type<$database> for CanonicalExpirationColumn {
            fn type_info() -> $info {
                <ExpirationColumn as Type<$database>>::type_info()
            }

            fn compatible(info: &$info) -> bool {
                <ExpirationColumn as Type<$database>>::compatible(info)
            }
        }

        impl<'r> Decode<'r, $database> for CanonicalExpirationColumn {
            fn decode(
                value: <$database as sqlx::Database>::ValueRef<'r>,
            ) -> Result<Self, ColumnError> {
                <ExpirationColumn as Decode<'r, $database>>::decode(value).map(Into::into)
            }
        }
    };
}

canonical_column!(Sqlite, sqlx::sqlite::SqliteTypeInfo);
#[cfg(feature = "postgres-sqlx")]
canonical_column!(sqlx::Postgres, sqlx::postgres::PgTypeInfo);

impl From<CanonicalExpirationColumn> for Option<String> {
    fn from(column: CanonicalExpirationColumn) -> Self {
        column.0
    }
}

pub(super) fn parse_text(raw: &str) -> Option<DateTime<Utc>> {
    layout::read(raw)
}
