// Copyright 2009, 2011, 2012 The Go Authors. All rights reserved.
// Finite EC key schemas from Go 1.26.9 crypto/x509/{sec1,pkcs8}.go and
// encoding/asn1/asn1.go; see LICENSE-GO and UPSTREAM.md.

//! Check the original EC key schema before deriving a key from its scalar.
//! This follows the selected Go ASN.1 field semantics, including ignored
//! sequence suffixes and explicit optional fields. It does not parse RSA keys
//! or replace the provider's scalar/curve validation.

use crate::Error;

use super::EC;

struct Header {
    class: u8,
    compound: bool,
    tag: u32,
    length: usize,
    end: usize,
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn value(&mut self, tag: u32, compound: bool) -> Result<&'a [u8], Error> {
        let header = header(self.bytes, self.at)?;
        if header.class != 0 || header.tag != tag || header.compound != compound {
            return Err(Error::KeyRejected);
        }
        self.consume(header)
    }

    fn consume(&mut self, header: Header) -> Result<&'a [u8], Error> {
        let end = header
            .end
            .checked_add(header.length)
            .ok_or(Error::KeyRejected)?;
        let bytes = self.bytes.get(header.end..end).ok_or(Error::KeyRejected)?;
        self.at = end;
        Ok(bytes)
    }

    fn explicit(&mut self, tag: u32, child: u32) -> Result<Option<&'a [u8]>, Error> {
        if self.at == self.bytes.len() {
            return Ok(None);
        }
        let outer = header(self.bytes, self.at)?;
        // Go reports this before even checking the optional wrapper's tag.
        if outer.end == self.bytes.len() {
            return Err(Error::KeyRejected);
        }
        if outer.class != 2 || outer.tag != tag || !(outer.length == 0 || outer.compound) {
            return Ok(None);
        }
        if outer.length == 0 {
            return Err(Error::KeyRejected);
        }
        // Selected asn1.parseField unwraps an explicit member in the enclosing
        // sequence, not a slice limited by the wrapper's advertised length.
        let inner = header(self.bytes, outer.end)?;
        if inner.class != 0 || inner.tag != child || inner.compound {
            return Ok(None);
        }
        self.consume(inner).map(Some)
    }
}

pub(super) fn sec1(raw: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    ec(raw, None)
}

pub(super) fn pkcs8(raw: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let mut outer = Reader::new(raw);
    let mut key = Reader::new(outer.value(16, true)?);
    integer(key.value(2, false)?)?; // Go decodes, but does not check this version.
    let mut algorithm = Reader::new(key.value(16, true)?);
    if algorithm.value(6, false)? != EC {
        return Err(Error::KeyRejected);
    }
    // AlgorithmIdentifier.Parameters is an optional RawValue. Validate its
    // framing even when it cannot be interpreted as an OID. Extra algorithm
    // fields and the rest returned by Unmarshal are intentionally ignored.
    let curve = if algorithm.at == algorithm.bytes.len() {
        None
    } else {
        let start = algorithm.at;
        let parameter = header(algorithm.bytes, start)?;
        algorithm.consume(parameter)?;
        let mut parameter = Reader::new(&algorithm.bytes[start..algorithm.at]);
        parameter.value(6, false).ok().filter(|oid| valid_oid(oid))
    };
    ec(key.value(4, false)?, curve)
}

fn ec<'a>(raw: &'a [u8], curve: Option<&'a [u8]>) -> Result<(&'a [u8], &'a [u8]), Error> {
    let mut outer = Reader::new(raw);
    let mut key = Reader::new(outer.value(16, true)?);
    if integer(key.value(2, false)?)? != 1 {
        return Err(Error::KeyRejected);
    }
    let scalar = key.value(4, false)?;
    let named_curve = key.explicit(0, 6)?;
    if named_curve.is_some_and(|oid| !valid_oid(oid)) {
        return Err(Error::KeyRejected);
    }
    if let Some(bits) = key.explicit(1, 3)? {
        let Some((&padding, bytes)) = bits.split_first() else {
            return Err(Error::KeyRejected);
        };
        if padding > 7
            || bytes.is_empty() && padding != 0
            || bytes
                .last()
                .is_some_and(|last| last & ((1u8 << padding) - 1) != 0)
        {
            return Err(Error::KeyRejected);
        }
    }
    Ok((scalar, curve.or(named_curve).ok_or(Error::KeyRejected)?))
}

fn integer(bytes: &[u8]) -> Result<i64, Error> {
    if bytes.is_empty()
        || bytes.len() > 8
        || bytes.len() > 1
            && (bytes[0] == 0 && bytes[1] & 0x80 == 0 || bytes[0] == 0xff && bytes[1] & 0x80 != 0)
    {
        return Err(Error::KeyRejected);
    }
    let mut value = if bytes[0] & 0x80 == 0 { 0i64 } else { -1i64 };
    for byte in bytes {
        value = (value << 8) | i64::from(*byte);
    }
    Ok(value)
}

fn base128(bytes: &[u8], at: &mut usize) -> Result<u32, Error> {
    let mut value = 0u64;
    for shifted in 0..5 {
        let byte = *bytes.get(*at).ok_or(Error::KeyRejected)?;
        if shifted == 0 && byte == 0x80 {
            return Err(Error::KeyRejected);
        }
        *at += 1;
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return if value <= i32::MAX as u64 {
                Ok(value as u32)
            } else {
                Err(Error::KeyRejected)
            };
        }
    }
    Err(Error::KeyRejected)
}

fn valid_oid(bytes: &[u8]) -> bool {
    let mut at = 0;
    if bytes.is_empty() {
        return false;
    }
    while at < bytes.len() {
        if base128(bytes, &mut at).is_err() {
            return false;
        }
    }
    true
}

fn header(bytes: &[u8], mut at: usize) -> Result<Header, Error> {
    let first = *bytes.get(at).ok_or(Error::KeyRejected)?;
    at += 1;
    let mut tag = u32::from(first & 0x1f);
    if tag == 0x1f {
        tag = base128(bytes, &mut at)?;
        if tag < 0x1f {
            return Err(Error::KeyRejected);
        }
    }
    let first_length = *bytes.get(at).ok_or(Error::KeyRejected)?;
    at += 1;
    let mut length = usize::from(first_length & 0x7f);
    if first_length & 0x80 != 0 {
        let count = length;
        if count == 0 {
            return Err(Error::KeyRejected);
        }
        length = 0;
        for _ in 0..count {
            let byte = *bytes.get(at).ok_or(Error::KeyRejected)?;
            at += 1;
            if length >= 1 << 23 {
                return Err(Error::KeyRejected);
            }
            length = (length << 8) | usize::from(byte);
            if length == 0 {
                return Err(Error::KeyRejected);
            }
        }
        if length < 128 {
            return Err(Error::KeyRejected);
        }
    }
    Ok(Header {
        class: first >> 6,
        compound: first & 0x20 != 0,
        tag,
        length,
        end: at,
    })
}
