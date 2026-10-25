// Copyright 2010 The Go Authors. All rights reserved.
// JSON grammar, nesting and string decoding adapt Go 1.26.9 encoding/json's
// scanner.go/decode.go. BSD terms are in headscale-api-acl/LICENSE-GO-STDLIB.

//! Byte-preserving JSON spans with an iterative 10,000-container depth limit.
//! Unknown/raw values never become a recursively allocated serde value tree.

mod scanner;

/// Validate with the pinned Go scanner's diagnostic text. This remains a
/// byte-oriented grammar check; invalid UTF-8 in strings is decoded later.
pub use scanner::{check_valid, first_raw_value};

/// Materialize JSON numbers without binary64 rounding while preserving ordinary
/// object names. Native policy parsing and raw-payload comparisons use this
/// instead of serde's Value visitor, whose private number sentinel is not an
/// object key. Number spelling can normalize; duplicate names keep the last
/// value. Grammar/depth and strict string encoding are checked before returning.
/// Parser-owned cleanup is iterative; returned Value operations remain recursive.
pub fn value(bytes: &[u8]) -> Result<serde_json::Value, String> {
    crate::go_policy_value::parse(bytes)
}

/// Materialize a generic value using go-jose's duplicate-name and binary64
/// rules. Every decoded object name must be unique; numbers round to finite
/// float64, including valid underflow to zero. Ordinary private-number member
/// names remain object data. Use only for generic decoded values, since typed
/// structs can ignore unknown subtrees without decoding their contents.
pub fn strict_any_value(bytes: &[u8]) -> Result<serde_json::Value, String> {
    crate::go_policy_value::strict_any(bytes)
}

/// Use legacy Go string decoding with value()'s arbitrary-precision numeric
/// projection and last-member-wins maps. Invalid UTF-8 bytes and unpaired UTF-16
/// surrogates become replacement characters in both names and string values.
pub fn legacy_value(bytes: &[u8]) -> Result<serde_json::Value, String> {
    crate::go_policy_value::legacy(bytes)
}

/// Use the pinned go-jose generic decoder's legacy string replacement, finite
/// binary64 numbers, and recursively unique decoded object names. Names that
/// become identical after replacement also count as duplicates.
pub fn legacy_strict_any_value(bytes: &[u8]) -> Result<serde_json::Value, String> {
    crate::go_policy_value::legacy_strict_any(bytes)
}

fn invalid() -> String {
    "invalid JSON".into()
}

const MAX_DEPTH: usize = 10_000;

#[derive(Clone, Copy)]
pub struct Raw<'a>(&'a [u8]);

impl<'a> Raw<'a> {
    pub fn get(self) -> &'a [u8] {
        self.0
    }
}

#[derive(Clone, Copy)]
enum Frame {
    ArrayFirst,
    ArrayComma,
    ObjectFirst,
    ObjectKey,
    ObjectColon,
    ObjectComma,
}

pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

pub fn trim(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(|byte| space(*byte)) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(|byte| space(*byte)) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r')
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    pub(crate) fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }
    /// Position relative to this cursor's input slice.
    pub(crate) fn position(&self) -> usize {
        self.at
    }
    pub(crate) fn space(&mut self) {
        while self.peek().is_some_and(space) {
            self.at += 1;
        }
    }
    pub(crate) fn take(&mut self, byte: u8) -> Result<(), String> {
        if self.peek() != Some(byte) {
            return Err(invalid());
        }
        self.at += 1;
        Ok(())
    }
    pub(crate) fn done(&mut self) -> Result<(), String> {
        self.space();
        if self.at == self.bytes.len() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
    pub(crate) fn quoted(&mut self) -> Result<Raw<'a>, String> {
        let start = self.at;
        self.take(b'"')?;
        loop {
            match self.peek().ok_or_else(invalid)? {
                b'"' => {
                    self.at += 1;
                    return Ok(Raw(&self.bytes[start..self.at]));
                }
                b'\\' => {
                    self.at += 1;
                    match self.peek().ok_or_else(invalid)? {
                        b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => self.at += 1,
                        b'u' => {
                            self.at += 1;
                            let end = self.at.checked_add(4).ok_or_else(invalid)?;
                            let digits = self.bytes.get(self.at..end).ok_or_else(invalid)?;
                            if !digits.iter().all(u8::is_ascii_hexdigit) {
                                return Err(invalid());
                            }
                            self.at = end;
                        }
                        _ => return Err(invalid()),
                    }
                }
                0..=0x1f => return Err(invalid()),
                _ => self.at += 1, // Go validates UTF-8 when unquoting, not scanning.
            }
        }
    }
    fn digits(&mut self) -> Result<(), String> {
        let start = self.at;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.at += 1;
        }
        if self.at == start {
            Err(invalid())
        } else {
            Ok(())
        }
    }
    fn number(&mut self) -> Result<(), String> {
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => self.digits()?,
            _ => return Err(invalid()),
        }
        if self.peek() == Some(b'.') {
            self.at += 1;
            self.digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.at += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.at += 1;
            }
            self.digits()?;
        }
        Ok(())
    }
    fn literal(&mut self, text: &[u8]) -> Result<(), String> {
        if !self.bytes[self.at..].starts_with(text) {
            return Err(invalid());
        }
        self.at += text.len();
        Ok(())
    }
    pub(crate) fn value(&mut self) -> Result<Raw<'a>, String> {
        self.value_with_depth(Some(MAX_DEPTH))
    }
    /// Extract a grammar-checked span without imposing this cursor's local
    /// depth limit. Native policy decoding enforces encounter-order JSON-v2
    /// depth with its actual outer decoder frames instead.
    pub(crate) fn value_unbounded(&mut self) -> Result<Raw<'a>, String> {
        self.value_with_depth(None)
    }
    fn value_with_depth(&mut self, max_depth: Option<usize>) -> Result<Raw<'a>, String> {
        self.space();
        let start = self.at;
        let mut frames = Vec::new();
        let mut value = true;
        loop {
            if value {
                self.space();
                match self.peek().ok_or_else(invalid)? {
                    b'[' | b'{' => {
                        if max_depth.is_some_and(|limit| frames.len() >= limit) {
                            return Err(invalid());
                        }
                        frames.push(if self.peek() == Some(b'[') {
                            Frame::ArrayFirst
                        } else {
                            Frame::ObjectFirst
                        });
                        self.at += 1;
                    }
                    b'"' => {
                        self.quoted()?;
                    }
                    b'-' | b'0'..=b'9' => self.number()?,
                    b't' => self.literal(b"true")?,
                    b'f' => self.literal(b"false")?,
                    b'n' => self.literal(b"null")?,
                    _ => return Err(invalid()),
                }
                value = false;
            }
            let Some(frame) = frames.last().copied() else {
                return Ok(Raw(&self.bytes[start..self.at]));
            };
            self.space();
            match frame {
                Frame::ArrayFirst if self.peek() == Some(b']') => {
                    self.at += 1;
                    let _ = frames.pop();
                }
                Frame::ArrayFirst => {
                    if let Some(frame) = frames.last_mut() {
                        *frame = Frame::ArrayComma;
                    }
                    value = true;
                }
                Frame::ArrayComma => match self.peek() {
                    Some(b',') => {
                        self.at += 1;
                        value = true;
                    }
                    Some(b']') => {
                        self.at += 1;
                        let _ = frames.pop();
                    }
                    _ => return Err(invalid()),
                },
                Frame::ObjectFirst if self.peek() == Some(b'}') => {
                    self.at += 1;
                    let _ = frames.pop();
                }
                Frame::ObjectFirst | Frame::ObjectKey => {
                    self.quoted()?;
                    if let Some(frame) = frames.last_mut() {
                        *frame = Frame::ObjectColon;
                    }
                }
                Frame::ObjectColon => {
                    self.take(b':')?;
                    if let Some(frame) = frames.last_mut() {
                        *frame = Frame::ObjectComma;
                    }
                    value = true;
                }
                Frame::ObjectComma => match self.peek() {
                    Some(b',') => {
                        self.at += 1;
                        if let Some(frame) = frames.last_mut() {
                            *frame = Frame::ObjectKey;
                        }
                    }
                    Some(b'}') => {
                        self.at += 1;
                        let _ = frames.pop();
                    }
                    _ => return Err(invalid()),
                },
            }
        }
    }
}

pub(crate) fn validate(bytes: &[u8]) -> Result<(), String> {
    validate_with_depth(bytes, MAX_DEPTH)
}

/// Validate with a caller-supplied container bound where a materialized
/// value is consumed recursively afterwards.
pub(crate) fn validate_with_depth(bytes: &[u8], max_depth: usize) -> Result<(), String> {
    let mut cursor = Cursor::new(bytes);
    cursor.value_with_depth(Some(max_depth))?;
    cursor.done()
}

pub fn array(bytes: &[u8]) -> Result<Vec<Raw<'_>>, String> {
    validate(bytes)?;
    let mut cursor = Cursor::new(trim(bytes));
    cursor.take(b'[')?;
    cursor.space();
    let mut result = Vec::new();
    if cursor.peek() == Some(b']') {
        return Ok(result);
    }
    loop {
        result.push(cursor.value()?);
        cursor.space();
        if cursor.peek() == Some(b']') {
            return Ok(result);
        }
        cursor.take(b',')?;
    }
}

pub fn object(bytes: &[u8]) -> Result<Vec<(String, Raw<'_>)>, String> {
    validate(bytes)?;
    let mut cursor = Cursor::new(trim(bytes));
    cursor.take(b'{')?;
    cursor.space();
    let mut result = Vec::new();
    if cursor.peek() == Some(b'}') {
        return Ok(result);
    }
    loop {
        cursor.space();
        let name = unquote(cursor.quoted()?.get())?;
        cursor.space();
        cursor.take(b':')?;
        let value = cursor.value()?;
        result.push((name, value));
        cursor.space();
        if cursor.peek() == Some(b'}') {
            return Ok(result);
        }
        cursor.take(b',')?;
    }
}

fn hex(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    bytes.iter().try_fold(0u16, |value, byte| {
        Some((value << 4) | (*byte as char).to_digit(16)? as u16)
    })
}

pub fn unquote(bytes: &[u8]) -> Result<String, String> {
    let mut cursor = Cursor::new(bytes);
    let raw = cursor.quoted()?.get();
    cursor.done()?;
    let bytes = &raw[1..raw.len() - 1];
    let mut at = 0;
    let mut result = String::new();
    while at < bytes.len() {
        match bytes[at] {
            b'\\' => {
                at += 1;
                let escaped = *bytes.get(at).ok_or_else(invalid)?;
                at += 1;
                let ch = match escaped {
                    b'"' => '"',
                    b'\\' => '\\',
                    b'/' => '/',
                    b'b' => '\u{0008}',
                    b'f' => '\u{000c}',
                    b'n' => '\n',
                    b'r' => '\r',
                    b't' => '\t',
                    b'u' => {
                        let unit =
                            hex(bytes.get(at..at + 4).ok_or_else(invalid)?).ok_or_else(invalid)?;
                        at += 4;
                        let mut code = u32::from(unit);
                        if (0xd800..=0xdbff).contains(&unit)
                            && bytes.get(at..at + 2) == Some(b"\\u")
                            && let Some(low) = bytes.get(at + 2..at + 6).and_then(hex)
                            && (0xdc00..=0xdfff).contains(&low)
                        {
                            code = 0x10000
                                + ((u32::from(unit) - 0xd800) << 10)
                                + (u32::from(low) - 0xdc00);
                            at += 6;
                        }
                        char::from_u32(code).unwrap_or('\u{fffd}')
                    }
                    _ => return Err(invalid()),
                };
                result.push(ch);
            }
            byte @ 0..=0x7f => {
                result.push(char::from(byte));
                at += 1;
            }
            byte => {
                let width = match byte {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf4 => 4,
                    _ => 1,
                };
                let valid = bytes
                    .get(at..at + width)
                    .and_then(|value| std::str::from_utf8(value).ok())
                    .and_then(|value| value.chars().next());
                if let Some(ch) = valid {
                    result.push(ch);
                    at += width;
                } else {
                    result.push('\u{fffd}');
                    at += 1;
                }
            }
        }
    }
    Ok(result)
}

/// Decode a fresh Gorm JSON-serialized Go `[]string` value.
///
/// An empty database string is not unmarshaled by Gorm. Root JSON null is a
/// nil slice, and null array elements leave their fresh string slots empty.
/// Other element types fail instead of becoming an empty authorization list.
pub fn gorm_string_list(source: &[u8]) -> Result<Vec<String>, String> {
    if source.is_empty() || trim(source) == b"null" {
        return Ok(Vec::new());
    }
    array(source)?
        .into_iter()
        .map(|value| {
            if value.get() == b"null" {
                Ok(String::new())
            } else {
                unquote(value.get())
            }
        })
        .collect()
}
