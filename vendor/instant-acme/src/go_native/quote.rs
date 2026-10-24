// Copyright 2009 The Go Authors. All rights reserved.
// Adapted Go strconv.Quote; see LICENSE-GO and LICENSE-GO-NOTICE.
// Private copy of the selected shared quoting implementation; no workspace
// dependency is added to the vendored SDK.

use std::fmt::Write as _;

mod unicode;

pub(super) fn quote(value: &str) -> String {
    quote_with(value, '"')
}

pub(super) fn quote_bytes(value: &[u8]) -> String {
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
