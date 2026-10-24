use sqlx_core::bytes::Buf;

use crate::decode::Decode;
use crate::encode::Encode;
use crate::error::{mismatched_types, BoxDynError};
use crate::type_info::TypeInfo;
use crate::type_info::{PgType, PgTypeKind};
use crate::types::Oid;
use crate::types::Type;
use crate::{PgArgumentBuffer, PgTypeInfo, PgValueFormat, PgValueRef, Postgres};

#[doc(hidden)]
pub struct PgRecordEncoder<'a> {
    buf: &'a mut PgArgumentBuffer,
    off: usize,
    num: u32,
}

impl<'a> PgRecordEncoder<'a> {
    #[doc(hidden)]
    pub fn new(buf: &'a mut PgArgumentBuffer) -> Self {
        let off = buf.len();

        // reserve space for a field count
        buf.extend(&(0_u32).to_be_bytes());

        Self { buf, off, num: 0 }
    }

    #[doc(hidden)]
    pub fn finish(&mut self) {
        // fill in the record length
        self.buf[self.off..(self.off + 4)].copy_from_slice(&self.num.to_be_bytes());
    }

    #[doc(hidden)]
    pub fn encode<'q, T>(&mut self, value: T) -> Result<&mut Self, BoxDynError>
    where
        'a: 'q,
        T: Encode<'q, Postgres> + Type<Postgres>,
    {
        let ty = value.produces().unwrap_or_else(T::type_info);

        match ty.0 {
            // push a hole for this type ID
            // to be filled in on query execution
            PgType::DeclareWithName(name) => self.buf.patch_type_by_name(&name),
            PgType::DeclareArrayOf(array) => self.buf.patch_array_type(array),
            // write type id
            pg_type => self.buf.extend(&pg_type.oid().0.to_be_bytes()),
        }

        self.buf.encode(value)?;
        self.num += 1;

        Ok(self)
    }
}

#[doc(hidden)]
pub struct PgRecordDecoder<'r> {
    buf: &'r [u8],
    typ: PgTypeInfo,
    fmt: PgValueFormat,
    ind: usize,
    remaining: Option<usize>,
    text_field_pending: bool,
}

impl<'r> PgRecordDecoder<'r> {
    #[doc(hidden)]
    pub fn new(value: PgValueRef<'r>) -> Result<Self, BoxDynError> {
        let fmt = value.format();
        let mut buf = value.as_bytes()?;
        let typ = value.type_info;
        let mut remaining = None;

        match fmt {
            PgValueFormat::Binary => {
                if buf.len() < 4 {
                    return Err("short PostgreSQL record header".into());
                }
                let len = buf.get_u32();
                if u64::from(len) > u64::try_from(buf.len() / 8).unwrap_or(u64::MAX) {
                    return Err("PostgreSQL record count exceeds its buffer".into());
                }
                remaining = Some(len as usize);
            }

            PgValueFormat::Text => {
                // remove the enclosing `(` .. `)`
                buf = buf
                    .strip_prefix(b"(")
                    .and_then(|value| value.strip_suffix(b")"))
                    .ok_or("invalid PostgreSQL text record bounds")?;
            }
        }

        Ok(Self {
            buf,
            fmt,
            typ,
            ind: 0,
            remaining,
            // The final empty field in `(a,)`, and the sole field in `()`,
            // are NULL even though no payload bytes remain after the comma.
            text_field_pending: fmt == PgValueFormat::Text,
        })
    }

    #[doc(hidden)]
    pub fn try_decode<T>(&mut self) -> Result<T, BoxDynError>
    where
        T: for<'a> Decode<'a, Postgres> + Type<Postgres>,
    {
        if self.remaining == Some(0)
            || (self.fmt == PgValueFormat::Text && !self.text_field_pending)
        {
            return Err(format!("no field `{0}` found on record", self.ind).into());
        }

        match self.fmt {
            PgValueFormat::Binary => {
                if self.buf.len() < 4 {
                    return Err("short PostgreSQL record field OID".into());
                }
                let element_type_oid = Oid(self.buf.get_u32());
                let element_type_opt = match self.typ.0.kind() {
                    PgTypeKind::Simple if self.typ.0 == PgType::Record => {
                        PgTypeInfo::try_from_oid(element_type_oid)
                    }

                    PgTypeKind::Composite(fields) => {
                        let ty = fields
                            .get(self.ind)
                            .ok_or("PostgreSQL record metadata has too few fields")?
                            .1
                            .clone();
                        if ty.0.oid() != element_type_oid {
                            return Err("unexpected mismatch of composite type information".into());
                        }

                        Some(ty)
                    }

                    _ => {
                        return Err(
                            "unexpected non-composite type being decoded as a composite type"
                                .into(),
                        );
                    }
                };

                if let Some(ty) = &element_type_opt {
                    if !ty.is_null() && !T::compatible(ty) {
                        return Err(mismatched_types::<Postgres, T>(ty));
                    }
                }

                let element_type =
                    element_type_opt
                        .ok_or_else(|| BoxDynError::from(format!("custom types in records are not fully supported yet: failed to retrieve type info for field {} with type oid {}", self.ind, element_type_oid.0)))?;

                self.ind += 1;
                if let Some(remaining) = &mut self.remaining {
                    *remaining -= 1;
                }

                T::decode(PgValueRef::get(&mut self.buf, self.fmt, element_type)?)
            }

            PgValueFormat::Text => {
                let mut element = String::new();
                let mut quoted = false;
                let mut in_quotes = false;
                let mut in_escape = false;
                let mut prev_ch = '\0';
                let mut next_field = false;

                while !self.buf.is_empty() {
                    let width = match self.buf[0] {
                        0..=0x7f => 1,
                        0xc2..=0xdf => 2,
                        0xe0..=0xef => 3,
                        0xf0..=0xf4 => 4,
                        _ => return Err("invalid UTF-8 in PostgreSQL text record".into()),
                    };
                    let character = self
                        .buf
                        .get(..width)
                        .ok_or("short UTF-8 record character")?;
                    let ch = std::str::from_utf8(character)?
                        .chars()
                        .next()
                        .ok_or("empty PostgreSQL record character")?;
                    self.buf.advance(width);
                    match ch {
                        _ if in_escape => {
                            element.push(ch);
                            in_escape = false;
                        }

                        '"' if in_quotes => {
                            in_quotes = false;
                        }

                        '"' => {
                            in_quotes = true;
                            quoted = true;

                            if prev_ch == '"' {
                                element.push('"')
                            }
                        }

                        '\\' if !in_escape => {
                            in_escape = true;
                        }

                        ',' if !in_quotes => {
                            next_field = true;
                            break;
                        }

                        _ => {
                            element.push(ch);
                        }
                    }
                    prev_ch = ch;
                }
                if in_quotes || in_escape {
                    return Err("unterminated PostgreSQL text record field".into());
                }
                self.text_field_pending = next_field;
                self.ind += 1;

                let buf = if element.is_empty() && !quoted {
                    // completely empty input means NULL
                    None
                } else {
                    Some(element.as_bytes())
                };

                // NOTE: we do not call [`accepts`] or give a chance to from a user as
                //       TEXT sequences are not strongly typed

                T::decode(PgValueRef {
                    // NOTE: We pass `0` as the type ID because we don't have a reasonable value
                    //       we could use.
                    type_info: PgTypeInfo::with_oid(Oid(0)),
                    format: self.fmt,
                    value: buf,
                    row: None,
                })
            }
        }
    }
}
