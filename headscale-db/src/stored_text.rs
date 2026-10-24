//! SQLx adapters for Headscale's typed text serializer.
//!
//! Nullable netip.Addr fields retain SQL NULL versus a present empty zero Addr.
//! Non-null text/blob values validate and canonicalize during row decoding;
//! callers keep their existing Option<String> fields.
//! Public-key SQL NULL values decode as typed zero keys. A present empty
//! string fails text decoding; constructor defaults write full zero-key text.

use sqlx::{Decode, Sqlite, Type, ValueRef};

use crate::{DbError, Result};

type ColumnError = Box<dyn std::error::Error + Send + Sync + 'static>;

fn address_bytes(source: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(source)
        .map_err(|_| DbError::General("invalid UTF-8 in persisted IP address".into()))?;
    headscale_api_acl::go_netip::addr_text(text)
        .ok_or_else(|| DbError::General("invalid persisted IP address".into()))
}

/// Canonicalize a typed address before SQL mutation, preserving nil/zero.
pub(crate) fn optional_address(source: Option<&str>) -> Result<Option<String>> {
    source
        .map(|text| address_bytes(text.as_bytes()))
        .transpose()
}

fn raw_text_bytes(source: &[u8]) -> Result<String> {
    std::str::from_utf8(source)
        .map(str::to_owned)
        .map_err(|_| DbError::General("invalid UTF-8 in persisted text value".into()))
}

macro_rules! nullable_text_column {
    ($name:ident, $decode:ident) => {
        /// Intermediate type named by SQLx's derived row conversion.
        #[doc(hidden)]
        pub struct $name(Option<String>);

        impl $name {
            pub fn as_deref(&self) -> Option<&str> {
                self.0.as_deref()
            }
        }

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
                if value.is_null() {
                    return Ok(Self(None));
                }
                let bytes = <&[u8] as Decode<'r, Sqlite>>::decode(value)?;
                $decode(bytes)
                    .map(|address| Self(Some(address)))
                    .map_err(Into::into)
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
                if value.is_null() {
                    return Ok(Self(None));
                }
                // A custom bytea column is decoded through SQLx's bytea codec so its
                // text format is not mistaken for the serializer's address bytes.
                let address =
                    if <Vec<u8> as Type<sqlx::Postgres>>::compatible(value.type_info().as_ref()) {
                        let bytes = <Vec<u8> as Decode<'r, sqlx::Postgres>>::decode(value)?;
                        $decode(&bytes)?
                    } else {
                        $decode(value.as_bytes()?)?
                    };
                Ok(Self(Some(address)))
            }
        }

        impl From<$name> for Option<String> {
            fn from(column: $name) -> Self {
                column.0
            }
        }
    };
}

nullable_text_column!(NullableAddrColumn, address_bytes);
// Allocator startup plucks raw text first, then applies ParseAddr (not
// UnmarshalText), so a present empty string must fail at that boundary.
nullable_text_column!(NullableRawTextColumn, raw_text_bytes);

fn key_text(
    source: Option<&str>,
    kind: headscale_api_acl::go_key::PublicKeyKind,
) -> Result<String> {
    match source {
        None => Ok(kind.zero_text().to_owned()),
        Some(text) => kind
            .parse_text(text)
            .map_err(|error| DbError::General(error.to_string())),
    }
}

/// Empty constructor input represents Go's zero-valued public key, which is
/// persisted as its full prefixed text. Non-null empty stored text rejects.
pub(crate) fn key_for_write(
    source: &str,
    kind: headscale_api_acl::go_key::PublicKeyKind,
) -> Result<String> {
    key_text((!source.is_empty()).then_some(source), kind)
}

macro_rules! public_key_column {
    ($name:ident, $kind:ident) => {
        #[doc(hidden)]
        pub struct $name(String);

        impl Type<Sqlite> for $name {
            fn type_info() -> sqlx::sqlite::SqliteTypeInfo {
                <NullableRawTextColumn as Type<Sqlite>>::type_info()
            }
            fn compatible(ty: &sqlx::sqlite::SqliteTypeInfo) -> bool {
                <NullableRawTextColumn as Type<Sqlite>>::compatible(ty)
            }
        }
        impl<'r> Decode<'r, Sqlite> for $name {
            fn decode(
                value: sqlx::sqlite::SqliteValueRef<'r>,
            ) -> std::result::Result<Self, ColumnError> {
                let raw = <NullableRawTextColumn as Decode<'r, Sqlite>>::decode(value)?;
                key_text(
                    raw.as_deref(),
                    headscale_api_acl::go_key::PublicKeyKind::$kind,
                )
                .map(Self)
                .map_err(Into::into)
            }
        }
        #[cfg(feature = "postgres-sqlx")]
        impl Type<sqlx::Postgres> for $name {
            fn type_info() -> sqlx::postgres::PgTypeInfo {
                <NullableRawTextColumn as Type<sqlx::Postgres>>::type_info()
            }
            fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
                <NullableRawTextColumn as Type<sqlx::Postgres>>::compatible(ty)
            }
        }
        #[cfg(feature = "postgres-sqlx")]
        impl<'r> Decode<'r, sqlx::Postgres> for $name {
            fn decode(
                value: sqlx::postgres::PgValueRef<'r>,
            ) -> std::result::Result<Self, ColumnError> {
                let raw = <NullableRawTextColumn as Decode<'r, sqlx::Postgres>>::decode(value)?;
                key_text(
                    raw.as_deref(),
                    headscale_api_acl::go_key::PublicKeyKind::$kind,
                )
                .map(Self)
                .map_err(Into::into)
            }
        }
        impl From<$name> for String {
            fn from(column: $name) -> Self {
                column.0
            }
        }
    };
}

public_key_column!(MachineKeyColumn, Machine);
public_key_column!(NodeKeyColumn, Node);
public_key_column!(DiscoKeyColumn, Disco);
