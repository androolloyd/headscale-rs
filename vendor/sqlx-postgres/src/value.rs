use crate::error::{BoxDynError, UnexpectedNullError};
use crate::type_info::{PgType, PgTypeKind};
use crate::{PgTypeInfo, Postgres};
use sqlx_core::bytes::{Buf, Bytes};
pub(crate) use sqlx_core::value::{Value, ValueRef};
use std::borrow::Cow;
use std::str::from_utf8;

fn fixed_binary_width(ty: &PgTypeInfo, depth: usize) -> Option<usize> {
    if depth > 32 {
        return None;
    }
    match &ty.0 {
        PgType::Bool | PgType::Char => Some(1),
        PgType::Int2 => Some(2),
        PgType::Int4 | PgType::Oid | PgType::Float4 | PgType::Date => Some(4),
        PgType::Int8
        | PgType::Float8
        | PgType::Money
        | PgType::Time
        | PgType::Timestamp
        | PgType::Timestamptz
        | PgType::Macaddr8 => Some(8),
        PgType::Timetz => Some(12),
        PgType::Interval | PgType::Uuid | PgType::Point => Some(16),
        PgType::Line | PgType::Circle => Some(24),
        PgType::Lseg | PgType::Box => Some(32),
        PgType::Macaddr => Some(6),
        PgType::Custom(custom) => match &custom.kind {
            PgTypeKind::Domain(base) => fixed_binary_width(base, depth + 1),
            _ => None,
        },
        PgType::DeclareWithOid(oid) => {
            PgTypeInfo::try_from_oid(*oid).and_then(|ty| fixed_binary_width(&ty, depth + 1))
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(u8)]
pub enum PgValueFormat {
    Text = 0,
    Binary = 1,
}

/// Implementation of [`ValueRef`] for PostgreSQL.
#[derive(Clone)]
pub struct PgValueRef<'r> {
    pub(crate) value: Option<&'r [u8]>,
    pub(crate) row: Option<&'r Bytes>,
    pub(crate) type_info: PgTypeInfo,
    pub(crate) format: PgValueFormat,
}

/// Implementation of [`Value`] for PostgreSQL.
#[derive(Clone)]
pub struct PgValue {
    pub(crate) value: Option<Bytes>,
    pub(crate) type_info: PgTypeInfo,
    pub(crate) format: PgValueFormat,
}

impl<'r> PgValueRef<'r> {
    pub(crate) fn get(
        buf: &mut &'r [u8],
        format: PgValueFormat,
        ty: PgTypeInfo,
    ) -> Result<Self, String> {
        if buf.len() < 4 {
            return Err("short PostgreSQL value length".to_owned());
        }
        let element_len = buf.get_i32();

        let element_val = if element_len == -1 {
            None
        } else {
            let element_len: usize = element_len
                .try_into()
                .map_err(|_| format!("overflow converting element_len ({element_len}) to usize"))?;

            let val = buf
                .get(..element_len)
                .ok_or_else(|| "PostgreSQL value exceeds its buffer".to_owned())?;
            buf.advance(element_len);
            Some(val)
        };

        Ok(PgValueRef {
            value: element_val,
            row: None,
            type_info: ty,
            format,
        })
    }

    pub fn format(&self) -> PgValueFormat {
        self.format
    }

    pub fn as_bytes(&self) -> Result<&'r [u8], BoxDynError> {
        match &self.value {
            Some(v) => {
                if self.format == PgValueFormat::Binary {
                    if let Some(width) = fixed_binary_width(&self.type_info, 0) {
                        if v.len() != width {
                            return Err("invalid fixed-width PostgreSQL binary value".into());
                        }
                    }
                }
                Ok(v)
            }
            None => Err(UnexpectedNullError.into()),
        }
    }

    pub(crate) fn as_fixed_bytes<const N: usize>(&self) -> Result<&'r [u8; N], BoxDynError> {
        self.as_bytes()?.try_into().map_err(Into::into)
    }

    pub fn as_str(&self) -> Result<&'r str, BoxDynError> {
        Ok(from_utf8(self.as_bytes()?)?)
    }
}

impl Value for PgValue {
    type Database = Postgres;

    #[inline]
    fn as_ref(&self) -> PgValueRef<'_> {
        PgValueRef {
            value: self.value.as_deref(),
            row: None,
            type_info: self.type_info.clone(),
            format: self.format,
        }
    }

    fn type_info(&self) -> Cow<'_, PgTypeInfo> {
        Cow::Borrowed(&self.type_info)
    }

    fn is_null(&self) -> bool {
        self.value.is_none()
    }
}

impl<'r> ValueRef<'r> for PgValueRef<'r> {
    type Database = Postgres;

    fn to_owned(&self) -> PgValue {
        let value = match (self.row, self.value) {
            (Some(row), Some(value)) => Some(row.slice_ref(value)),

            (None, Some(value)) => Some(Bytes::copy_from_slice(value)),

            _ => None,
        };

        PgValue {
            value,
            format: self.format,
            type_info: self.type_info.clone(),
        }
    }

    fn type_info(&self) -> Cow<'_, PgTypeInfo> {
        Cow::Borrowed(&self.type_info)
    }

    fn is_null(&self) -> bool {
        self.value.is_none()
    }
}
