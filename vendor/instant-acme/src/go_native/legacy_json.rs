// Copyright 2010, 2013 The Go Authors. All rights reserved.
// Go 1.26.9 encoding/json scanner/decode/fold; see LICENSE-GO.

//! Ordered raw spans and legacy string decoding, without a recursive Value tree.

pub(super) mod scanner;

#[derive(Clone, Copy, Debug)]
pub(super) struct Raw<'a>(&'a [u8]);

impl<'a> Raw<'a> {
    pub(super) fn get(self) -> &'a [u8] {
        self.0
    }
}

fn space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

pub(super) fn trim(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(|byte| space(*byte)) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(|byte| space(*byte)) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

pub(super) fn first_value(bytes: &[u8]) -> Option<Raw<'_>> {
    let mut scanner = super::json_prefix::Scanner::new();
    let boundary = scanner.feed(bytes);
    if scanner.invalid() || scanner.depth_error_byte().is_some() {
        return None;
    }
    let length = match boundary {
        Some(length) => length,
        None if scanner.complete_at_eof() => bytes.len(),
        None => return None,
    };
    Some(Raw(trim(&bytes[..length])))
}

pub(super) fn check_valid(bytes: &[u8]) -> bool {
    scanner::check_valid(bytes).is_ok()
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl<'a> Cursor<'a> {
    fn space(&mut self) {
        while self.bytes.get(self.at).is_some_and(|byte| space(*byte)) {
            self.at += 1;
        }
    }
    fn take(&mut self, byte: u8) -> Option<()> {
        self.space();
        if self.bytes.get(self.at) != Some(&byte) {
            return None;
        }
        self.at += 1;
        Some(())
    }
    fn value(&mut self) -> Option<Raw<'a>> {
        self.space();
        let value = first_value(self.bytes.get(self.at..)?)?;
        self.at += value.get().len();
        Some(value)
    }
    fn done(&mut self) -> bool {
        self.space();
        self.at == self.bytes.len()
    }
}

pub(super) fn object(bytes: &[u8]) -> Option<Vec<(String, Raw<'_>)>> {
    let mut cursor = Cursor { bytes, at: 0 };
    cursor.take(b'{')?;
    cursor.space();
    let mut fields = Vec::new();
    if cursor.bytes.get(cursor.at) != Some(&b'}') {
        loop {
            let name = unquote(cursor.value()?.get())?;
            cursor.take(b':')?;
            let value = cursor.value()?;
            fields.push((name, value));
            cursor.space();
            if cursor.bytes.get(cursor.at) != Some(&b',') {
                break;
            }
            cursor.at += 1;
        }
    }
    cursor.take(b'}')?;
    cursor.done().then_some(fields)
}

pub(super) fn array(bytes: &[u8]) -> Option<Vec<Raw<'_>>> {
    let mut cursor = Cursor { bytes, at: 0 };
    cursor.take(b'[')?;
    cursor.space();
    let mut values = Vec::new();
    if cursor.bytes.get(cursor.at) != Some(&b']') {
        loop {
            values.push(cursor.value()?);
            cursor.space();
            if cursor.bytes.get(cursor.at) != Some(&b',') {
                break;
            }
            cursor.at += 1;
        }
    }
    cursor.take(b']')?;
    cursor.done().then_some(values)
}

fn hex(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    let mut value = 0;
    for byte in bytes {
        value = value * 16
            + match byte {
                b'0'..=b'9' => u16::from(byte - b'0'),
                b'a'..=b'f' => u16::from(byte - b'a' + 10),
                b'A'..=b'F' => u16::from(byte - b'A' + 10),
                _ => return None,
            };
    }
    Some(value)
}

/// Go DecodeRune replaces one malformed byte at a time, including a truncated
/// UTF8 suffix (String::from_utf8_lossy would combine some such suffixes).
pub(super) fn lossy(bytes: &[u8]) -> String {
    let mut output = String::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                output.push_str(text);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                // This prefix is guaranteed valid by Utf8Error.
                if let Ok(text) = std::str::from_utf8(&rest[..valid]) {
                    output.push_str(text);
                }
                output.push('\u{fffd}');
                rest = &rest[valid + 1..];
            }
        }
    }
    output
}

pub(super) fn unquote(bytes: &[u8]) -> Option<String> {
    let bytes = trim(bytes);
    if bytes.len() < 2 || bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') {
        return None;
    }
    let mut rest = &bytes[1..bytes.len() - 1];
    let mut output = String::new();
    while !rest.is_empty() {
        let plain = rest
            .iter()
            .position(|byte| *byte == b'\\' || *byte == b'"' || *byte < 0x20)
            .unwrap_or(rest.len());
        output.push_str(&lossy(&rest[..plain]));
        rest = &rest[plain..];
        if rest.is_empty() {
            break;
        }
        if rest.first() != Some(&b'\\') {
            return None;
        }
        let escaped = *rest.get(1)?;
        rest = &rest[2..];
        match escaped {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{8}'),
            b'f' => output.push('\u{c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => {
                let first = hex(rest.get(..4)?)?;
                rest = &rest[4..];
                let mut scalar = u32::from(first);
                if (0xd800..=0xdbff).contains(&first) {
                    let second = rest
                        .strip_prefix(b"\\u")
                        .and_then(|rest| hex(rest.get(..4)?));
                    if let Some(second) = second.filter(|second| (0xdc00..=0xdfff).contains(second))
                    {
                        scalar = 0x10000 + ((u32::from(first) - 0xd800) << 10) + u32::from(second)
                            - 0xdc00;
                        rest = &rest[6..];
                    } else {
                        scalar = 0xfffd;
                    }
                } else if (0xdc00..=0xdfff).contains(&first) {
                    scalar = 0xfffd;
                }
                output.push(char::from_u32(scalar)?);
            }
            _ => return None,
        }
    }
    Some(output)
}

/// All selected wire field names are ASCII. Only Kelvin-sign K and long-s S
/// join an ASCII letter's Unicode SimpleFold class in selected Go tables.
pub(super) fn field(name: &str, canonical: &str) -> bool {
    let mut name = name.chars();
    for expected in canonical.bytes() {
        let actual = match name.next() {
            Some('\u{212a}') => b'K',
            Some('\u{17f}') => b'S',
            Some(ch) if ch.is_ascii() => (ch as u8).to_ascii_uppercase(),
            _ => return false,
        };
        if actual != expected.to_ascii_uppercase() {
            return false;
        }
    }
    name.next().is_none()
}

pub(super) fn integer(raw: &[u8]) -> Option<i64> {
    let raw = trim(raw);
    // JSON grammar is validated independently; ParseInt rejects decimal and
    // exponent spellings even if their numeric value is an integer.
    if raw.is_empty()
        || raw
            .iter()
            .any(|byte| !byte.is_ascii_digit() && *byte != b'-')
    {
        return None;
    }
    std::str::from_utf8(raw).ok()?.parse().ok()
}
