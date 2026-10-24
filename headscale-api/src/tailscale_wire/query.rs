// Copyright 2009 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! URL.Query().Get semantics shared by public control endpoints.

const MAX_QUERY_PARAMETERS: usize = 10_000;

/// Match the default Go net/url parser: ignore malformed pairs, reject raw
/// semicolon pairs, decode '+' and percent escapes, and select the first value
/// even when empty. An over-limit query has no usable values at all.
pub(super) fn first_value(query: &str, name: &str) -> Option<Vec<u8>> {
    if query
        .bytes()
        .filter(|byte| *byte == b'&')
        .nth(MAX_QUERY_PARAMETERS - 1)
        .is_some()
    {
        return None;
    }
    for pair in query
        .split('&')
        .filter(|pair| !pair.is_empty() && !pair.contains(';'))
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let Some(key) = unescape(key) else { continue };
        if key != name.as_bytes() {
            continue;
        }
        // A bad value discards this whole pair, so a later valid pair can
        // become the first value for the key, as in Go ParseQuery.
        if let Some(value) = unescape(value) {
            return Some(value);
        }
    }
    None
}

fn unescape(value: &str) -> Option<Vec<u8>> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut offset = 0;
    while offset < bytes.len() {
        match bytes[offset] {
            b'+' => {
                out.push(b' ');
                offset += 1;
            }
            b'%' => {
                let hi = hex(*bytes.get(offset + 1)?)?;
                let lo = hex(*bytes.get(offset + 2)?)?;
                out.push((hi << 4) | lo);
                offset += 3;
            }
            byte => {
                out.push(byte);
                offset += 1;
            }
        }
    }
    Some(out)
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Go net/url.QueryEscape, including byte strings from percent decoding.
fn escape_bytes(value: &[u8]) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            b' ' => out.push('+'),
            _ => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(HEX[usize::from(byte >> 4)] as char);
                out.push(HEX[usize::from(byte & 15)] as char);
            }
        }
    }
    out
}

/// URL.Query keeps valid pairs despite parse errors. Values retain byte
/// strings and duplicate order; Encode sorts the decoded keys as Go does.
pub(super) fn values(query: &str) -> std::collections::BTreeMap<Vec<u8>, Vec<Vec<u8>>> {
    let mut values = std::collections::BTreeMap::<Vec<u8>, Vec<Vec<u8>>>::new();
    if query
        .bytes()
        .filter(|byte| *byte == b'&')
        .nth(MAX_QUERY_PARAMETERS - 1)
        .is_some()
    {
        return values;
    }
    for pair in query
        .split('&')
        .filter(|pair| !pair.is_empty() && !pair.contains(';'))
    {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if let (Some(key), Some(value)) = (unescape(key), unescape(value)) {
            values.entry(key).or_default().push(value);
        }
    }
    values
}

pub(super) fn encode_values(values: &std::collections::BTreeMap<Vec<u8>, Vec<Vec<u8>>>) -> String {
    let mut out = String::new();
    for (key, values) in values {
        let key = escape_bytes(key);
        for value in values {
            if !out.is_empty() {
                out.push('&');
            }
            out.push_str(&key);
            out.push('=');
            out.push_str(&escape_bytes(value));
        }
    }
    out
}
