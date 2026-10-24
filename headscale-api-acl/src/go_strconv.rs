// Copyright 2009 The Go Authors. All rights reserved.
// Go strconv.Quote/time.quote adaptations; BSD terms are in LICENSE-GO-STDLIB.

//! Go string quoting for UTF-8 Rust string boundaries. Invalid raw bytes
//! remain the responsibility of their byte-oriented decoder.

use std::fmt::Write as _;

// Verbatim tables from Go's strconv (isPrint/isNotPrint); grouping their hex
// digits would only make them harder to diff against upstream.
#[allow(clippy::unreadable_literal)]
mod unicode;

pub fn quote(value: &str) -> String {
    quote_with(value, '"')
}

pub fn quote_rune(value: char) -> String {
    quote_with(&value.to_string(), '\'')
}

/// Quote a Go string's bytes without replacing malformed UTF-8. Go's Quote
/// escapes each invalid byte as \xHH while retaining valid Unicode runes.
pub fn quote_bytes(value: &[u8]) -> String {
    let mut out = String::from("\"");
    let mut remaining = value;
    loop {
        match std::str::from_utf8(remaining) {
            Ok(text) => {
                let quoted = quote(text);
                out.push_str(&quoted[1..quoted.len() - 1]);
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if valid != 0 {
                    // valid_up_to marks a fully validated UTF-8 prefix.
                    if let Ok(text) = std::str::from_utf8(&remaining[..valid]) {
                        let quoted = quote(text);
                        out.push_str(&quoted[1..quoted.len() - 1]);
                    }
                }
                let invalid = error.error_len().unwrap_or(remaining.len() - valid);
                for byte in &remaining[valid..valid + invalid] {
                    let _ = write!(out, "\\x{byte:02x}");
                }
                remaining = &remaining[valid + invalid..];
            }
        }
    }
    out.push('"');
    out
}

pub(crate) fn is_print(value: char) -> bool {
    unicode::printable(value)
}

/// time.quote uses byte escapes for non-ASCII/control input, unlike
/// strconv.Quote. In particular, it retains DEL and writes LF as `\x0a`.
pub fn quote_time(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for byte in value.bytes() {
        if byte < b' ' || !byte.is_ascii() {
            let _ = write!(output, "\\x{byte:02x}");
        } else {
            if matches!(byte, b'"' | b'\\') {
                output.push('\\');
            }
            output.push(char::from(byte));
        }
    }
    output.push('"');
    output
}

fn quote_with(value: &str, delimiter: char) -> String {
    let mut out = String::new();
    out.push(delimiter);
    for ch in value.chars() {
        match ch {
            ch if ch == delimiter => {
                out.push('\\');
                out.push(ch);
            }
            '\\' => out.push_str("\\\\"),
            '\x07' => out.push_str("\\a"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x0b' => out.push_str("\\v"),
            ch if ch.is_ascii_control() => {
                let _ = write!(out, "\\x{:02x}", u32::from(ch));
            }
            ch if unicode::printable(ch) => out.push(ch),
            ch => {
                let code = u32::from(ch);
                if code <= 0xffff {
                    let _ = write!(out, "\\u{code:04x}");
                } else {
                    let _ = write!(out, "\\U{code:08x}");
                }
            }
        }
    }
    out.push(delimiter);
    out
}
