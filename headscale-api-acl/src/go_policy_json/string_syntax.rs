// Copyright 2023 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Adapted from go-json-experiment/json 00ed12fed2a6 internal/jsonwire
// decode.go/wire.go and jsontext/errors.go. See LICENSE-GO-JSON-EXPERIMENT.

//! Strict string diagnostics against the actual metadata-stripped HuJSON Pack
//! buffer. The HuJSON grammar pass already checked escapes and termination.

use std::fmt::Write as _;

use crate::go_strconv;

fn hex16(raw: &[u8]) -> Option<u16> {
    raw.get(..4)?.iter().try_fold(0_u16, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        };
        Some(value * 16 + u16::from(digit))
    })
}

fn invalid_surrogate(what: &[u8]) -> String {
    let label = if what.len() > 6 {
        "surrogate pair"
    } else {
        "escape sequence"
    };
    let text = std::str::from_utf8(what).ok();
    let need_escape = text.is_none_or(|text| {
        text.chars().any(|ch| {
            let rune = ch.to_string();
            ch == '`'
                || ch == '\u{fffd}'
                || crate::go_unicode::trim_space(&rune).is_empty()
                || !go_strconv::is_print(ch)
        })
    });
    let quoted = if need_escape {
        go_strconv::quote_bytes(what)
    } else {
        format!("`{}`", text.expect("valid printable text"))
    };
    format!("invalid {label} {quoted} in string")
}

pub(super) struct Failure {
    offset: usize,
    cause: String,
}

impl Failure {
    pub(super) fn render(self, pointer: &str) -> String {
        let mut text = format!("parsing policy from bytes: jsontext: {}", self.cause);
        if !pointer.is_empty() {
            text.push_str(" within ");
            text.push_str(&go_strconv::quote(&super::truncate_pointer(pointer, 100)));
        }
        if self.offset > 0 {
            let _ = write!(text, " after offset {}", self.offset);
        }
        text
    }
}

pub(super) fn depth_error(offset: usize, pointer: &str) -> String {
    Failure {
        offset,
        cause: "exceeded max depth".to_owned(),
    }
    .render(pointer)
}

pub(super) fn validate(
    source: &[u8],
    raw: &[u8],
    pointer: impl FnOnce() -> String,
) -> Result<(), String> {
    check(source, raw).map_err(|failure| failure.render(&pointer()))
}

pub(super) fn check(source: &[u8], raw: &[u8]) -> Result<(), Failure> {
    let start = (raw.as_ptr() as usize)
        .checked_sub(source.as_ptr() as usize)
        .filter(|&start| start <= source.len() && raw.len() <= source.len() - start)
        .expect("string span belongs to packed source");
    let remaining = &source[start..];
    let mut at = 1;
    while at + 1 < raw.len() {
        match raw[at] {
            b'\\' if raw.get(at + 1) == Some(&b'u') => {
                let first = hex16(&raw[at + 2..]).expect("HuJSON checked Unicode escape");
                if (0xd800..=0xdfff).contains(&first) {
                    let second = remaining
                        .get(at + 6..at + 12)
                        .filter(|bytes| bytes.starts_with(b"\\u"))
                        .and_then(|bytes| hex16(&bytes[2..]));
                    if !(0xd800..=0xdbff).contains(&first)
                        || !second.is_some_and(|value| (0xdc00..=0xdfff).contains(&value))
                    {
                        let end = remaining.len().min(at + 12);
                        return Err(Failure {
                            offset: start + at,
                            cause: invalid_surrogate(&remaining[at..end]),
                        });
                    }
                    at += 12;
                } else {
                    at += 6;
                }
            }
            b'\\' => at += 2,
            0..=0x7f => at += 1,
            first => {
                let width = match first {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf4 => 4,
                    _ => 0,
                };
                if width == 0
                    || raw
                        .get(at..at + width)
                        .is_none_or(|bytes| std::str::from_utf8(bytes).is_err())
                {
                    return Err(Failure {
                        offset: start + at,
                        cause: "invalid UTF-8".to_owned(),
                    });
                }
                at += width;
            }
        }
    }
    Ok(())
}
