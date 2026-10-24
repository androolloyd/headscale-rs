// Copyright 2009 The Go Authors. All rights reserved.
// Copyright 2010 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Form, MIME, and query semantics adapt Go 1.26.9 net/http/request.go,
// net/url/url.go, mime/mediatype.go, and mime/grammar.go.
// BSD terms and source attribution: LICENSE-GO-STDLIB, NOTICE-GO-STDLIB.

//! Confirmation POST's ParseForm boundary, before cookie/cache processing.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use axum::http::{HeaderMap, header};
use headscale_api_acl::{go_strconv, go_unicode};

const CSRF_FIELD: &[u8] = b"headscale_register_confirm";
#[cfg(feature = "full")]
const TOKEN_FIELDS: &[&str] = &[
    "access_token",
    "id_token",
    "token_type",
    "error",
    "error_description",
    "error_uri",
    "refresh_token",
    "expires_in",
];

/// Return the body's first CSRF value, using None for missing or empty.
/// The URL query is validated but never supplies PostFormValue's token.
/// A first empty duplicate value stays empty even if a later value is set.
pub(super) fn decode_confirmation_form(
    headers: &HeaderMap,
    raw: &[u8],
    query: Option<&str>,
) -> Result<Option<String>, String> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .map(http::HeaderValue::as_bytes)
        .filter(|value| !value.is_empty())
        .unwrap_or(b"application/octet-stream");
    let (media_type, mut error) = media_type_bytes(content_type);
    let mut csrf = None;
    // ParseMediaType can retain the recognized base alongside an invalid
    // parameter error. Go still reads that form body, preserving MIME error
    // precedence over MaxBytesReader or URL-decoding errors.
    if media_type == "application/x-www-form-urlencoded" {
        let body = if raw.len() > super::REGISTER_CONFIRM_BODY_LIMIT {
            Err("http: request body too large".to_owned())
        } else {
            parse_query(raw, Some(CSRF_FIELD))
        };
        match body {
            Ok(value) => csrf = value,
            Err(body_error) => {
                error.get_or_insert(body_error);
            }
        }
    }
    if let Err(query_error) = parse_query(query.unwrap_or_default().as_bytes(), None) {
        error.get_or_insert(query_error);
    }
    if let Some(error) = error {
        return Err(error);
    }
    // Go form strings can hold arbitrary bytes. Native Cookie values are
    // ASCII, so an invalid-UTF-8 token remains unable to match its cookie;
    // replacement here preserves the later mismatch rather than ParseForm
    // incorrectly rejecting it as a syntax error.
    Ok(csrf
        .filter(|value| !value.is_empty())
        .map(|value| String::from_utf8_lossy(&value).into_owned()))
}

/// oauth2's form response uses ParseQuery and Values.Get, selecting the first
/// value even when it is empty. Validate unknown fields too, then discard them.
/// Public token strings retain the existing lossy invalid-UTF-8 projection;
/// syntax errors, parameter limits, and duplicate selection stay byte-based.
#[cfg(feature = "full")]
pub(super) fn decode_token_form(raw: &[u8]) -> Result<BTreeMap<String, String>, String> {
    let mut values = BTreeMap::new();
    visit_query(raw, |key, value| {
        if let Some(field) = TOKEN_FIELDS
            .iter()
            .copied()
            .find(|field| field.as_bytes() == key.as_slice())
        {
            values
                .entry(field.to_owned())
                .or_insert_with(|| String::from_utf8_lossy(&value).into_owned());
        }
    })?;
    Ok(values)
}

/// Preserve ParseMediaType's base/error pair. Invalid parameters retain the
/// base; unequal duplicate parameters and invalid base grammar clear it.
/// RFC 2231 parameter stitching affects neither result used by native OIDC.
pub(super) fn media_type_bytes(value: &[u8]) -> (String, Option<String>) {
    let separator = value.iter().position(|&byte| byte == b';');
    let base = &value[..separator.unwrap_or(value.len())];
    let lower = go_unicode::to_lowercase(&String::from_utf8_lossy(base));
    let base = go_unicode::trim_space(&lower).to_owned();
    if let Err(error) = check_media_type(&base) {
        return (String::new(), Some(error.to_owned()));
    }
    let mut remaining = separator.map_or(&[][..], |index| &value[index..]);
    let mut parameters = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    loop {
        remaining = trim_start(remaining);
        if remaining.is_empty() {
            return (base, None);
        }
        let Some((name, value, rest)) = parameter(remaining) else {
            if remaining
                .strip_prefix(b";")
                .is_some_and(|rest| trim_start(rest).is_empty())
            {
                return (base, None);
            }
            return (base, Some("mime: invalid media parameter".to_owned()));
        };
        if let Some(previous) = parameters.get(&name)
            && previous != &value
        {
            return (
                String::new(),
                Some("mime: duplicate parameter name".to_owned()),
            );
        }
        let _ = parameters.insert(name, value);
        remaining = rest;
    }
}

fn check_media_type(value: &str) -> Result<(), &'static str> {
    let (first, rest) = token(value.as_bytes());
    if first.is_empty() {
        return Err("mime: no media type");
    }
    if rest.is_empty() {
        return Ok(());
    }
    let Some(rest) = rest.strip_prefix(b"/") else {
        return Err("mime: expected slash after first token");
    };
    let (subtype, rest) = token(rest);
    if subtype.is_empty() {
        return Err("mime: expected token after slash");
    }
    if !rest.is_empty() {
        return Err("mime: unexpected content after media subtype");
    }
    Ok(())
}

fn special(byte: u8) -> bool {
    b"()<>@,;:\\\"/[]?=".contains(&byte)
}

fn token(bytes: &[u8]) -> (&[u8], &[u8]) {
    let end = bytes
        .iter()
        .position(|&byte| !(0x21..0x7f).contains(&byte) || special(byte))
        .unwrap_or(bytes.len());
    bytes.split_at(end)
}

fn trim_start(mut bytes: &[u8]) -> &[u8] {
    while let Some(&first) = bytes.first() {
        let width = match first {
            0..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => break,
        };
        let Some(character) = bytes
            .get(..width)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|text| text.chars().next())
        else {
            break;
        };
        if !matches!(character, '\u{9}'..='\u{d}' | ' ' | '\u{85}' | '\u{a0}'
            | '\u{1680}' | '\u{2000}'..='\u{200a}' | '\u{2028}' | '\u{2029}'
            | '\u{202f}' | '\u{205f}' | '\u{3000}')
        {
            break;
        }
        bytes = &bytes[width..];
    }
    bytes
}

fn parameter(bytes: &[u8]) -> Option<(Vec<u8>, Vec<u8>, &[u8])> {
    let rest = trim_start(bytes).strip_prefix(b";")?;
    let (name, rest) = token(trim_start(rest));
    if name.is_empty() {
        return None;
    }
    let rest = trim_start(rest).strip_prefix(b"=")?;
    let (value, rest) = parameter_value(trim_start(rest))?;
    Some((name.to_ascii_lowercase(), value, rest))
}

fn parameter_value(bytes: &[u8]) -> Option<(Vec<u8>, &[u8])> {
    if bytes.first() != Some(&b'"') {
        let (value, rest) = token(bytes);
        return (!value.is_empty()).then(|| (value.to_vec(), rest));
    }
    let mut value = Vec::new();
    let mut index = 1;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'"' => return Some((value, &bytes[index + 1..])),
            b'\r' | b'\n' => return None,
            b'\\' if bytes.get(index + 1).copied().is_some_and(special) => {
                index += 1;
                value.push(bytes[index]);
            }
            _ => value.push(byte),
        }
        index += 1;
    }
    None
}

fn parse_query(bytes: &[u8], selected: Option<&[u8]>) -> Result<Option<Vec<u8>>, String> {
    let mut first = None;
    visit_query(bytes, |key, value| {
        if first.is_none() && selected == Some(key.as_slice()) {
            first = Some(value);
        }
    })?;
    Ok(first)
}

/// URL.Query discards ParseQuery's error, retaining all successfully decoded
/// pairs; Values.Get then selects the first value even when it is empty.
pub(super) fn query_first_value(bytes: &[u8], selected: &[u8]) -> Option<Vec<u8>> {
    let mut first = None;
    let _ = visit_query(bytes, |key, value| {
        if first.is_none() && key == selected {
            first = Some(value);
        }
    });
    first
}

fn visit_query(bytes: &[u8], mut visit: impl FnMut(Vec<u8>, Vec<u8>)) -> Result<(), String> {
    // N separators split the query into N + 1 entries.
    let count = bytes.split(|&byte| byte == b'&').count();
    if !crate::go_url::query_params_within_max(count) {
        return Err("number of URL query parameters exceeded limit".to_owned());
    }
    let mut error = None;
    for entry in bytes.split(|&byte| byte == b'&') {
        if entry.contains(&b';') {
            // A literal semicolon replaces even an earlier escaping error.
            error = Some("invalid semicolon separator in query".to_owned());
            continue;
        }
        if entry.is_empty() {
            continue;
        }
        let equals = entry.iter().position(|&byte| byte == b'=');
        let key = &entry[..equals.unwrap_or(entry.len())];
        let value = equals.map_or(&[][..], |index| &entry[index + 1..]);
        let key = match query_unescape(key) {
            Ok(value) => value,
            Err(unescape_error) => {
                error.get_or_insert(unescape_error);
                continue;
            }
        };
        let value = match query_unescape(value) {
            Ok(value) => value,
            Err(unescape_error) => {
                error.get_or_insert(unescape_error);
                continue;
            }
        };
        visit(key, value);
    }
    error.map_or(Ok(()), Err)
}

fn query_unescape(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut value = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'%' => {
                let pair = bytes
                    .get(index + 1..index + 3)
                    .filter(|pair| pair.iter().all(u8::is_ascii_hexdigit));
                let Some(pair) = pair else {
                    return Err(format!(
                        "invalid URL escape {}",
                        quote_bytes(&bytes[index..bytes.len().min(index + 3)])
                    ));
                };
                let digit = |byte| (byte as char).to_digit(16).unwrap_or_default() as u8;
                value.push(digit(pair[0]) * 16 + digit(pair[1]));
                index += 3;
            }
            b'+' => {
                value.push(b' ');
                index += 1;
            }
            _ => {
                value.push(byte);
                index += 1;
            }
        }
    }
    Ok(value)
}

pub(super) fn quote_bytes(mut bytes: &[u8]) -> String {
    let mut quoted = String::from("\"");
    while !bytes.is_empty() {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                let part = go_strconv::quote(text);
                quoted.push_str(&part[1..part.len() - 1]);
                break;
            }
            Err(error) if error.valid_up_to() > 0 => {
                let length = error.valid_up_to();
                let text = std::str::from_utf8(&bytes[..length]).expect("validated UTF-8 prefix");
                let part = go_strconv::quote(text);
                quoted.push_str(&part[1..part.len() - 1]);
                bytes = &bytes[length..];
            }
            Err(_) => {
                let _ = write!(quoted, "\\x{:02x}", bytes[0]);
                bytes = &bytes[1..];
            }
        }
    }
    quoted.push('"');
    quoted
}
