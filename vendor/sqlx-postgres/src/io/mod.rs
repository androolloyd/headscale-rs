mod buf_mut;

pub use buf_mut::PgBufMutExt;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::num::{NonZeroU32, Saturating};

pub(crate) use sqlx_core::io::*;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum StatementId {
    Sqlx(IdInner),
    GoCache([u8; 24]),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct PortalId(IdInner);

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct IdInner(Option<NonZeroU32>);

pub(crate) struct DisplayId {
    prefix: &'static str,
    id: Option<NonZeroU32>,
    digest: Option<[u8; 24]>,
}

impl StatementId {
    #[allow(dead_code)]
    pub const UNNAMED: Self = Self::Sqlx(IdInner::UNNAMED);

    pub const NAMED_START: Self = Self::Sqlx(IdInner::NAMED_START);

    #[cfg(test)]
    pub const TEST_VAL: Self = Self::Sqlx(IdInner::TEST_VAL);

    const NAME_PREFIX: &'static str = "sqlx_s_";
    const GO_CACHE_PREFIX: &'static str = "stmtcache_";

    pub fn go_cache(sql: &str) -> Self {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(sql.as_bytes());
        let mut name = [0; 24];
        name.copy_from_slice(&digest[..24]);
        Self::GoCache(name)
    }

    pub fn next(&self) -> Self {
        match self {
            Self::Sqlx(id) => Self::Sqlx(id.next()),
            Self::GoCache(_) => *self,
        }
    }

    pub fn name_len(&self) -> Saturating<usize> {
        match self {
            Self::Sqlx(id) => id.name_len(Self::NAME_PREFIX),
            Self::GoCache(_) => Saturating(Self::GO_CACHE_PREFIX.len() + 48 + 1),
        }
    }

    /// Get a type to format this statement ID with [`Display`].
    ///
    /// Returns `None` if this is the unnamed statement.
    #[inline(always)]
    pub fn display(&self) -> Option<DisplayId> {
        match self {
            Self::Sqlx(id) => id.display(Self::NAME_PREFIX),
            Self::GoCache(digest) => Some(DisplayId {
                prefix: Self::GO_CACHE_PREFIX,
                id: None,
                digest: Some(*digest),
            }),
        }
    }

    pub fn put_name_with_nul(&self, buf: &mut Vec<u8>) {
        match self {
            Self::Sqlx(id) => id.put_name_with_nul(Self::NAME_PREFIX, buf),
            Self::GoCache(digest) => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                buf.extend_from_slice(Self::GO_CACHE_PREFIX.as_bytes());
                for byte in digest {
                    buf.push(HEX[usize::from(*byte >> 4)]);
                    buf.push(HEX[usize::from(*byte & 0x0f)]);
                }
                buf.push(0);
            }
        }
    }
}

impl Display for DisplayId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix)?;
        if let Some(digest) = self.digest {
            for byte in digest {
                write!(f, "{byte:02x}")?;
            }
        } else if let Some(id) = self.id {
            write!(f, "{id}")?;
        }
        Ok(())
    }
}

#[allow(dead_code)]
impl PortalId {
    // None selects the unnamed portal
    pub const UNNAMED: Self = PortalId(IdInner::UNNAMED);

    pub const NAMED_START: Self = PortalId(IdInner::NAMED_START);

    #[cfg(test)]
    pub const TEST_VAL: Self = Self(IdInner::TEST_VAL);

    const NAME_PREFIX: &'static str = "sqlx_p_";

    /// If ID represents a named portal, return the next ID, wrapping on overflow.
    ///
    /// If this ID represents the unnamed portal, return the same.
    pub fn next(&self) -> Self {
        Self(self.0.next())
    }

    /// Calculate the number of bytes that will be written by [`Self::put_name_with_nul()`].
    pub fn name_len(&self) -> Saturating<usize> {
        self.0.name_len(Self::NAME_PREFIX)
    }

    pub fn put_name_with_nul(&self, buf: &mut Vec<u8>) {
        self.0.put_name_with_nul(Self::NAME_PREFIX, buf)
    }
}

impl IdInner {
    const UNNAMED: Self = Self(None);

    const NAMED_START: Self = Self(Some(NonZeroU32::MIN));

    #[cfg(test)]
    pub const TEST_VAL: Self = Self(NonZeroU32::new(1234567890));

    #[inline(always)]
    fn next(&self) -> Self {
        Self(
            self.0
                .map(|id| id.checked_add(1).unwrap_or(NonZeroU32::MIN)),
        )
    }

    #[inline(always)]
    fn display(&self, prefix: &'static str) -> Option<DisplayId> {
        self.0.map(|id| DisplayId {
            prefix,
            id: Some(id),
            digest: None,
        })
    }

    #[inline(always)]
    fn name_len(&self, name_prefix: &str) -> Saturating<usize> {
        let mut len = Saturating(0);

        if let Some(id) = self.0 {
            len += name_prefix.len();
            // estimate the length of the ID in decimal
            // `.ilog10()` can't panic since the value is never zero
            len += id.get().ilog10() as usize;
            // add one to compensate for `ilog10()` rounding down.
            len += 1;
        }

        // count the NUL terminator
        len += 1;

        len
    }

    #[inline(always)]
    fn put_name_with_nul(&self, name_prefix: &str, buf: &mut Vec<u8>) {
        if let Some(id) = self.0 {
            buf.extend_from_slice(name_prefix.as_bytes());
            buf.extend_from_slice(itoa::Buffer::new().format(id.get()).as_bytes());
        }

        buf.push(0);
    }
}

#[test]
fn statement_id_display_matches_encoding() {
    const EXPECTED_STR: &str = "sqlx_s_1234567890";
    const EXPECTED_BYTES: &[u8] = b"sqlx_s_1234567890\0";

    let mut bytes = Vec::new();

    StatementId::TEST_VAL.put_name_with_nul(&mut bytes);

    assert_eq!(bytes, EXPECTED_BYTES);

    let str = StatementId::TEST_VAL.display().unwrap().to_string();

    assert_eq!(str, EXPECTED_STR);
}
