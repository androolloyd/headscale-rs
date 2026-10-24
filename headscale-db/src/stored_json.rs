//! SQLx adapter for Go/Gorm JSON string-list columns.
//!
//! The intermediate column type validates data during FromRow while retaining
//! String row fields. Representable source text is preserved; invalid UTF-8
//! within otherwise valid JSON strings uses Go's replacement characters.
//! Endpoint and route columns also validate their netip text, including the
//! zero values produced by null array elements.
//! Hostinfo uses the same column boundary with its pinned tailcfg schema.

use sqlx::{Decode, Sqlite, Type, ValueRef};

use crate::{DbError, Result};

/// encoding/json.Marshal's HTML-safe envelope at the Gorm SQL boundary.
pub(crate) fn text_for_write<T: serde::Serialize + ?Sized>(value: &T) -> Result<String> {
    let source = serde_json::to_vec(value)?;
    let source =
        headscale_api_acl::go_json_output::compact_html(&source).map_err(DbError::General)?;
    String::from_utf8(source).map_err(|_| DbError::General("invalid JSON text encoding".into()))
}

fn string_list_bytes(source: &[u8]) -> Result<Vec<String>> {
    crate::go_json::gorm_string_list(source)
        .map_err(|_| DbError::General("invalid persisted JSON string list".into()))
}

pub(crate) fn string_list(source: &str) -> Result<Vec<String>> {
    string_list_bytes(source.as_bytes())
}

pub(crate) fn endpoint_values(values: &[String]) -> Result<Vec<String>> {
    values
        .iter()
        .map(|value| {
            headscale_api_acl::go_netip::addr_port_text(value)
                .ok_or_else(|| DbError::General("invalid persisted endpoint address".into()))
        })
        .collect()
}

pub(crate) fn prefix_values(values: &[String]) -> Result<Vec<String>> {
    values
        .iter()
        .map(|value| {
            headscale_api_acl::go_netip::prefix_text(value)
                .ok_or_else(|| DbError::General("invalid persisted approved route".into()))
        })
        .collect()
}

fn endpoint_list_bytes(source: &[u8]) -> Result<Vec<String>> {
    endpoint_values(&string_list_bytes(source)?)
}

fn prefix_list_bytes(source: &[u8]) -> Result<Vec<String>> {
    prefix_values(&string_list_bytes(source)?)
}

pub(crate) fn endpoint_list(source: &str) -> Result<Vec<String>> {
    endpoint_list_bytes(source.as_bytes())
}

pub(crate) fn prefix_list(source: &str) -> Result<Vec<String>> {
    prefix_list_bytes(source.as_bytes())
}

type ColumnError = Box<dyn std::error::Error + Send + Sync + 'static>;

fn checked_text(
    source: &[u8],
    decode: fn(&[u8]) -> Result<Vec<String>>,
) -> std::result::Result<String, ColumnError> {
    let values = decode(source)?;
    Ok(match std::str::from_utf8(source) {
        Ok(text) => text.to_owned(),
        // Go's JSON decoder replaces invalid bytes within string values.
        // Preserve the decoded values through representable JSON text.
        Err(_) => serde_json::to_string(&values)?,
    })
}

fn string_list_text(source: &[u8]) -> std::result::Result<String, ColumnError> {
    checked_text(source, string_list_bytes)
}

fn endpoint_list_text(source: &[u8]) -> std::result::Result<String, ColumnError> {
    checked_text(source, endpoint_list_bytes)
}

fn prefix_list_text(source: &[u8]) -> std::result::Result<String, ColumnError> {
    checked_text(source, prefix_list_bytes)
}

fn host_info_text(source: &[u8]) -> std::result::Result<String, ColumnError> {
    crate::stored_hostinfo::text_from_bytes(source).map_err(Into::into)
}

macro_rules! json_column {
    ($name:ident, $decode:ident) => {
        /// Intermediate type named by SQLx's derived row conversion.
        #[doc(hidden)]
        pub struct $name(String);

        impl Type<Sqlite> for $name {
            fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
                <String as Type<Sqlite>>::type_info()
            }

            fn compatible(ty: &sqlx::sqlite::SqliteTypeInfo) -> bool {
                <String as Type<Sqlite>>::compatible(ty)
                    || <Vec<u8> as Type<Sqlite>>::compatible(ty)
            }
        }

        impl<'r> Decode<'r, Sqlite> for $name {
            fn decode(
                value: sqlx::sqlite::SqliteValueRef<'r>,
            ) -> std::result::Result<Self, ColumnError> {
                let bytes = if value.is_null() {
                    &[][..]
                } else {
                    <&[u8] as Decode<'r, Sqlite>>::decode(value)?
                };
                $decode(bytes).map(Self)
            }
        }

        #[cfg(feature = "postgres-sqlx")]
        impl Type<sqlx::Postgres> for $name {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                <String as Type<sqlx::Postgres>>::type_info()
            }

            fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
                <String as Type<sqlx::Postgres>>::compatible(ty)
                    || <Vec<u8> as Type<sqlx::Postgres>>::compatible(ty)
            }
        }

        #[cfg(feature = "postgres-sqlx")]
        impl<'r> Decode<'r, sqlx::Postgres> for $name {
            fn decode(
                value: sqlx::postgres::PgValueRef<'r>,
            ) -> std::result::Result<Self, ColumnError> {
                let text = if value.is_null() {
                    $decode(&[])?
                } else if <Vec<u8> as Type<sqlx::Postgres>>::compatible(value.type_info().as_ref())
                {
                    let bytes = <Vec<u8> as Decode<'r, sqlx::Postgres>>::decode(value)?;
                    $decode(&bytes)?
                } else {
                    $decode(value.as_bytes()?)?
                };
                Ok(Self(text))
            }
        }

        impl From<$name> for String {
            fn from(column: $name) -> Self {
                column.0
            }
        }
    };
}

json_column!(StringListColumn, string_list_text);
json_column!(EndpointListColumn, endpoint_list_text);
json_column!(PrefixListColumn, prefix_list_text);
json_column!(HostInfoColumn, host_info_text);
