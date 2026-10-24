// OAuth/OIDC assignment adapts pinned Go, oauth2, go-oidc and Headscale sources;
// JOSE handling adapts go-jose v4.1.4. See UPSTREAM.md and retained
// LICENSE/NOTICE-GO-{STDLIB,OAUTH2,OIDC,JOSE,JOSE-JSON} and HEADSCALE-GO.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Native JSON boundaries keep objects separate from serde's numeric transport.
//! Standard OAuth/OIDC fields assign in input order; JOSE struct fields retain
//! exact names. Raw-valued fields preserve their original JSON kind.

use headscale_api_acl::{go_json, go_strconv, go_unicode};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use super::{OidcClaims, OidcIdTokenClaims, OidcJsonJws, OidcJsonSignature, OidcTokenResponse};

/// The go-jose JSON fork checks direct object names even for unknown
/// struct fields, but skips the contents of unknown struct-valued members.
pub(super) fn unique_object(bytes: &[u8]) -> Option<Vec<(String, go_json::Raw<'_>)>> {
    let fields = go_json::object(bytes).ok()?;
    let mut seen = BTreeSet::new();
    for (name, _) in &fields {
        if !seen.insert(name.clone()) {
            return None;
        }
    }
    Some(fields)
}

/// The remaining object bytes plus the selected `(canonical name, raw value)`
/// members, in input order.
type Projection<'a> = (Vec<u8>, Vec<(&'static str, go_json::Raw<'a>)>);

/// Remove selected fields without buffering the rest as generic serde Values.
/// Keep input member order, duplicate occurrences and typed decoding errors.
fn project<'a>(
    bytes: &'a [u8],
    names: &[(&'static str, bool)],
    unique: bool,
    typed_strings: Option<&[&str]>,
) -> Result<Projection<'a>, String> {
    let fields = if unique {
        unique_object(bytes).ok_or_else(|| "invalid JOSE JSON object".to_owned())?
    } else {
        go_json::object(bytes)?
    };
    let mut remaining = vec![b'{'];
    let mut selected = Vec::new();
    for (name, raw) in fields {
        if let Some(&(canonical, _)) = names.iter().find(|&&(canonical, fold)| {
            name == canonical || (fold && go_unicode::equal_fold(&name, canonical))
        }) {
            selected.push((canonical, raw));
        } else {
            if let Some(known) = typed_strings {
                if !known.contains(&name.as_str()) {
                    continue; // Typed JOSE structs skip unknown subtrees.
                }
                let token = go_json::trim(raw.get());
                if token != b"null" && token.first() != Some(&b'"') {
                    return Err("invalid JOSE string field".to_owned());
                }
            }
            if remaining.len() > 1 {
                remaining.push(b',');
            }
            remaining.extend(serde_json::to_vec(&name).map_err(|error| error.to_string())?);
            remaining.push(b':');
            if typed_strings.is_some() && go_json::trim(raw.get()).first() == Some(&b'"') {
                let text = go_json::unquote(raw.get())?;
                remaining.extend(serde_json::to_vec(&text).map_err(|error| error.to_string())?);
            } else {
                remaining.extend_from_slice(raw.get());
            }
        }
    }
    remaining.push(b'}');
    Ok((remaining, selected))
}

/// Ordinary Go string fields ignore JSON null rather than clearing it.
pub(super) fn assign_string(target: &mut String, raw: &[u8]) -> Result<(), String> {
    let raw = go_json::trim(raw);
    if raw == b"null" {
        return Ok(());
    }
    *target = go_json::unquote(raw)?;
    Ok(())
}

pub(super) fn flexible_strings(raw: &[u8]) -> Result<Vec<String>, String> {
    let raw = go_json::trim(raw);
    let decode = || {
        if raw == b"null" {
            return Ok(Vec::new());
        }
        if raw.first() == Some(&b'"') {
            return Ok(vec![go_json::unquote(raw)?]);
        }
        go_json::array(raw)?
            .into_iter()
            .map(|raw| {
                let mut value = String::new();
                assign_string(&mut value, raw.get())?;
                Ok(value)
            })
            .collect::<Result<Vec<_>, String>>()
    };
    decode().map_err(|_| {
        format!(
            "cannot parse value as string or []string: {}",
            String::from_utf8_lossy(raw)
        )
    })
}

pub(super) fn flexible_bool(raw: &[u8]) -> Result<bool, String> {
    let raw = go_json::trim(raw);
    go_json::check_valid(raw).map_err(|error| format!("unmarshalling data: {error}"))?;
    // FlexibleBoolean first calls std JSON's any decoder. It visits every
    // numeric occurrence, including an overwritten duplicate map member.
    check_any_numbers(raw).map_err(|error| format!("unmarshalling data: {error}"))?;
    let text = if raw.first() == Some(&b'"') {
        go_json::unquote(raw)?
    } else if raw == b"true" || raw == b"false" {
        String::from_utf8(raw.to_vec()).expect("ASCII boolean")
    } else if raw == b"null" {
        return Err("cannot parse value as boolean: <nil>".to_owned());
    } else {
        return Err(format!(
            "cannot parse value as boolean: {}",
            format_any(raw)?
        ));
    };
    match text.as_str() {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Ok(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Ok(false),
        _ => Err(format!(
            "parsing {text} as boolean: strconv.ParseBool: parsing {}: invalid syntax",
            go_strconv::quote(&text)
        )),
    }
}

fn check_any_numbers(raw: &[u8]) -> Result<(), String> {
    let mut pending = vec![raw];
    while let Some(raw) = pending.pop() {
        match raw.first() {
            Some(b'[') => {
                pending.extend(
                    go_json::array(raw)?
                        .into_iter()
                        .rev()
                        .map(headscale_api_acl::go_json::Raw::get),
                );
            }
            Some(b'{') => pending.extend(
                go_json::object(raw)?
                    .into_iter()
                    .rev()
                    .map(|(_, raw)| raw.get()),
            ),
            Some(b'-' | b'0'..=b'9') => {
                let text = std::str::from_utf8(raw).expect("validated JSON number is ASCII");
                if !text.parse::<f64>().is_ok_and(f64::is_finite) {
                    return Err(format!(
                        "json: cannot unmarshal number {text} into Go value of type float64"
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// fmt's %v visits slices/maps without JSON quoting and sorts string map keys.
// The raw traversal avoids a recursive generic Value tree at the depth limit.
fn format_any(raw: &[u8]) -> Result<String, String> {
    enum Part<'a> {
        Value(&'a [u8]),
        Text(String),
    }
    let mut pending = vec![Part::Value(raw)];
    let mut output = String::new();
    while let Some(part) = pending.pop() {
        let raw = match part {
            Part::Text(text) => {
                output.push_str(&text);
                continue;
            }
            Part::Value(raw) => raw,
        };
        match raw.first() {
            Some(b'[') => {
                output.push('[');
                pending.push(Part::Text("]".into()));
                for (index, value) in go_json::array(raw)?.into_iter().enumerate().rev() {
                    pending.push(Part::Value(value.get()));
                    if index != 0 {
                        pending.push(Part::Text(" ".into()));
                    }
                }
            }
            Some(b'{') => {
                output.push_str("map[");
                pending.push(Part::Text("]".into()));
                let entries = go_json::object(raw)?
                    .into_iter()
                    .collect::<std::collections::BTreeMap<_, _>>();
                for (index, (key, value)) in entries.into_iter().enumerate().rev() {
                    pending.push(Part::Value(value.get()));
                    pending.push(Part::Text(format!("{key}:")));
                    if index != 0 {
                        pending.push(Part::Text(" ".into()));
                    }
                }
            }
            Some(b'"') => output.push_str(&go_json::unquote(raw)?),
            Some(b'n') => output.push_str("<nil>"),
            Some(b't') => output.push_str("true"),
            Some(b'f') => output.push_str("false"),
            _ => {
                let value = std::str::from_utf8(raw)
                    .map_err(|error| error.to_string())?
                    .parse::<f64>()
                    .map_err(|error| error.to_string())?;
                // strconv.FormatFloat(value, 'g', -1, 64) uses shortest
                // digits, switching to exponent form outside [-4, 6).
                let scientific = format!("{value:e}");
                let (digits, exponent) = scientific
                    .split_once('e')
                    .expect("finite scientific float has an exponent");
                let exponent = exponent
                    .parse::<i32>()
                    .expect("float exponent is an integer");
                if (-4..6).contains(&exponent) {
                    output.push_str(&value.to_string());
                } else {
                    let _ = write!(output, "{digits}e{exponent:+03}");
                }
            }
        }
    }
    Ok(output)
}

fn matched<'a>(name: &str, fields: &[&'a str]) -> Option<&'a str> {
    fields
        .iter()
        .copied()
        .find(|field| name == *field)
        .or_else(|| {
            fields
                .iter()
                .copied()
                .find(|field| go_unicode::equal_fold(name, field))
        })
}

fn kind(raw: &[u8]) -> &'static str {
    match go_json::trim(raw).first() {
        Some(b'{') => "object",
        Some(b'[') => "array",
        Some(b'"') => "string",
        Some(b't' | b'f') => "bool",
        _ => "number",
    }
}

fn typed_string(
    target: &mut String,
    raw: &[u8],
    structure: &str,
    field: &str,
) -> Result<(), String> {
    let raw = go_json::trim(raw);
    if raw != b"null" && raw.first() != Some(&b'"') {
        return Err(format!(
            "json: cannot unmarshal {} into Go struct field {structure}.{field} of type string",
            kind(raw)
        ));
    }
    assign_string(target, raw)
}

fn expiry(raw: &[u8]) -> Result<Option<i64>, String> {
    let raw = go_json::trim(raw);
    if raw == b"null" {
        return Ok(None);
    }
    let number = if raw.first() == Some(&b'"') {
        let number = go_json::unquote(raw)?;
        if super::oidc_json_number(&number).is_none() {
            return Err(format!(
                "json: invalid number literal, trying to unmarshal {} into Number",
                quote_bytes(raw)
            ));
        }
        number
    } else if matches!(raw.first(), Some(b'-' | b'0'..=b'9')) {
        std::str::from_utf8(raw)
            .expect("validated JSON number is ASCII")
            .to_owned()
    } else {
        return Err(format!(
            "json: cannot unmarshal {} into Go struct field tokenJSON.expires_in of type json.Number",
            kind(raw)
        ));
    };
    // json.Number's Int64 rejects fractions and exponents even when integral.
    let seconds = decimal_i64(&number).map_err(|reason| {
        format!(
            "strconv.ParseInt: parsing {}: {reason}",
            go_strconv::quote(&number)
        )
    })?;
    // oauth2 expirationTime is int32 with an upper clamp, then narrowing.
    Ok(Some(i64::from(seconds.min(i64::from(i32::MAX)) as i32)))
}

// ParseInt(..., 10, 64) first parses the unsigned magnitude. Preserve its
// early uint64 overflow ordering before checking the final signed range.
fn decimal_i64(number: &str) -> Result<i64, &'static str> {
    let (negative, digits) = if let Some(digits) = number.strip_prefix('-') {
        (true, digits)
    } else {
        (false, number.strip_prefix('+').unwrap_or(number))
    };
    if digits.is_empty() {
        return Err("invalid syntax");
    }
    let mut magnitude = 0u64;
    for byte in digits.bytes() {
        if !byte.is_ascii_digit() {
            return Err("invalid syntax");
        }
        magnitude = magnitude
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or("value out of range")?;
    }
    if negative {
        if magnitude > (1u64 << 63) {
            Err("value out of range")
        } else {
            Ok((magnitude as i64).wrapping_neg())
        }
    } else {
        i64::try_from(magnitude).map_err(|_| "value out of range")
    }
}

// fmt %q on []byte preserves invalid UTF-8 as individual byte escapes.
fn quote_bytes(mut bytes: &[u8]) -> String {
    let mut output = String::from("\"");
    while !bytes.is_empty() {
        let (valid, remainder) = match std::str::from_utf8(bytes) {
            Ok(text) => (text, &[][..]),
            Err(error) => {
                let (valid, remainder) = bytes.split_at(error.valid_up_to());
                (
                    std::str::from_utf8(valid).expect("known valid prefix"),
                    remainder,
                )
            }
        };
        let quoted = go_strconv::quote(valid);
        output.push_str(&quoted[1..quoted.len() - 1]);
        bytes = remainder;
        if let Some((&byte, rest)) = bytes.split_first() {
            let _ = write!(output, "\\x{byte:02x}");
            bytes = rest;
        }
    }
    output.push('"');
    output
}

/// Token.Extra on url.Values returns an integer/float when its trimmed value
/// has zero/one dots and the corresponding conversion succeeds. An absent
/// form field is the empty string, which remains a string at this boundary.
pub(super) fn form_id_token_is_string(value: &str) -> bool {
    let value = go_unicode::trim_space(value);
    match value.bytes().filter(|byte| *byte == b'.').count() {
        0 => decimal_i64(value).is_err(),
        1 => !form_float(value),
        _ => true,
    }
}

fn form_float(value: &str) -> bool {
    if !float_underscores(value) {
        return false;
    }
    let value = value.replace('_', "");
    let unsigned = value
        .strip_prefix('-')
        .or_else(|| value.strip_prefix('+'))
        .unwrap_or(&value);
    if !unsigned.starts_with("0x") && !unsigned.starts_with("0X") {
        // Rust and Go decimal conversions both accept underflow to zero;
        // overflow returns a non-finite value and is not a successful Extra.
        return value.parse::<f64>().is_ok_and(f64::is_finite);
    }
    let Some((mantissa, exponent)) = unsigned[2..].split_once(['p', 'P']) else {
        return false;
    };
    let (negative, exponent) = if let Some(exponent) = exponent.strip_prefix('-') {
        (true, exponent)
    } else {
        (false, exponent.strip_prefix('+').unwrap_or(exponent))
    };
    if exponent.is_empty() || !exponent.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    // Match readFloat's large-exponent accumulation. Once e reaches 10000,
    // the remaining exponent digits do not change its overflow decision.
    let mut power = 0i64;
    for byte in exponent.bytes() {
        if power < 10000 {
            power = power * 10 + i64::from(byte - b'0');
        }
    }
    if negative {
        power = -power;
    }
    let Some((whole, fraction)) = mantissa.split_once('.') else {
        return false;
    };
    if !whole
        .bytes()
        .chain(fraction.bytes())
        .all(|byte| byte.is_ascii_hexdigit())
    {
        return false;
    }
    let digits = whole
        .bytes()
        .chain(fraction.bytes())
        .map(|byte| {
            char::from(byte)
                .to_digit(16)
                .expect("validated hexadecimal digit") as u8
        })
        .collect::<Vec<_>>();
    if digits.is_empty() {
        return false;
    }
    let Some(first) = digits.iter().position(|digit| *digit != 0) else {
        return true; // Zero is finite for every valid exponent.
    };
    let first_bit = digits[first].ilog2();
    let highest = (digits.len() - first - 1) as i64 * 4 + i64::from(first_bit) + power
        - fraction.len() as i64 * 4;
    if highest != 1023 {
        return highest < 1023;
    }
    // Round-to-nearest overflows at max-finite + 0.5 ULP. At exponent 1023,
    // that boundary has 54 leading one bits (1.fffffffffffff8 in hex).
    let mut bits = 0;
    for (index, digit) in digits[first..].iter().enumerate() {
        let top = if index == 0 { first_bit } else { 3 };
        for bit in (0..=top).rev() {
            if digit & (1u8 << bit) == 0 {
                return true;
            }
            bits += 1;
            if bits == 54 {
                return false;
            }
        }
    }
    true // The remaining implicit bits are zero, below the overflow boundary.
}

// strconv's underscoreOK accepts separators only between digits, with the
// hexadecimal base prefix also counting as a digit for the first separator.
fn float_underscores(value: &str) -> bool {
    let value = value
        .strip_prefix('-')
        .or_else(|| value.strip_prefix('+'))
        .unwrap_or(value);
    let (hex, mut previous_digit, rest) = if value.starts_with("0x") || value.starts_with("0X") {
        (true, true, &value[2..])
    } else {
        (false, false, value)
    };
    let mut underscore = false;
    for byte in rest.bytes() {
        let digit = byte.is_ascii_digit() || (hex && byte.is_ascii_hexdigit());
        if byte == b'_' {
            if !previous_digit {
                return false;
            }
            previous_digit = false;
            underscore = true;
        } else {
            if underscore && !digit {
                return false;
            }
            previous_digit = digit;
            underscore = false;
        }
    }
    !underscore
}

pub(super) fn token_response(bytes: &[u8]) -> Result<OidcTokenResponse, String> {
    go_json::check_valid(bytes)?;
    let mut token = OidcTokenResponse::default();
    if go_json::trim(bytes) == b"null" {
        return Ok(token);
    }
    if go_json::trim(bytes).first() != Some(&b'{') {
        return Err(format!(
            "json: cannot unmarshal {} into Go value of type internal.tokenJSON",
            kind(bytes)
        ));
    }
    let fields = go_json::object(bytes)?;
    // Typed fields that are validated but never read back are collected in
    // locals and assigned in the final struct literal.
    let mut refresh_token = String::new();
    let mut error_description = String::new();
    let mut error_uri = String::new();
    let mut expires_in = None;
    let mut saved_error = None;
    for (name, raw) in &fields {
        let Some(field) = matched(
            name,
            &[
                "access_token",
                "token_type",
                "refresh_token",
                "error",
                "error_description",
                "error_uri",
                "expires_in",
            ],
        ) else {
            continue;
        };
        if field == "expires_in" {
            // Custom decoder errors supersede earlier ordinary type errors.
            if let Some(value) = expiry(raw.get())? {
                expires_in = Some(value);
            }
            continue;
        }
        let target = match field {
            "access_token" => &mut token.access_token,
            "token_type" => &mut token.token_type,
            "refresh_token" => &mut refresh_token,
            "error" => &mut token.error_code,
            "error_description" => &mut error_description,
            "error_uri" => &mut error_uri,
            _ => unreachable!("known token string field"),
        };
        if let Err(error) = typed_string(target, raw.get(), "tokenJSON", field) {
            saved_error.get_or_insert(error);
        }
    }
    if let Some(error) = saved_error {
        return Err(error);
    }
    // oauth2 only decodes its generic Extra map after a successful typed
    // tokenJSON pass. Numeric overflow errors in this optional pass are saved
    // and ignored, and later entries still assign. Only the exact id_token
    // string assertion is observable here, so project it directly in order.
    for (name, raw) in fields {
        if name == "id_token" {
            token.id_token_is_string = raw.get().first() == Some(&b'"');
            token.id_token = if token.id_token_is_string {
                go_json::unquote(raw.get())?
            } else {
                String::new()
            };
        }
    }
    Ok(OidcTokenResponse {
        _error_description: error_description,
        _error_uri: error_uri,
        _refresh_token: refresh_token,
        _expires_in: expires_in,
        ..token
    })
}

pub(super) fn id_token_claims(bytes: &[u8]) -> Option<OidcIdTokenClaims> {
    go_json::check_valid(bytes).ok()?;
    let mut token = OidcIdTokenClaims {
        claims: OidcClaims::default(),
        nonce: String::new(),
        exp: Value::Null,
        aud: Value::Null,
        nbf: None,
        iat: None,
        _at_hash: String::new(),
        claim_names: BTreeMap::default(),
        claim_sources: BTreeMap::default(),
    };
    if go_json::trim(bytes) == b"null" {
        return Some(token);
    }
    // at_hash is validated as a string but never read back.
    let mut at_hash = String::new();
    let mut saved_error = None;
    for (name, raw) in go_json::object(bytes).ok()? {
        let Some(field) = matched(
            &name,
            &[
                "iss",
                "sub",
                "nonce",
                "at_hash",
                "exp",
                "aud",
                "nbf",
                "iat",
                "_claim_names",
                "_claim_sources",
            ],
        ) else {
            continue;
        };
        let bytes = go_json::trim(raw.get());
        match field {
            "exp" | "iat" | "nbf" => {
                if field == "nbf" && bytes == b"null" {
                    token.nbf = None;
                    continue;
                }
                if !matches!(bytes.first(), Some(b'"' | b'-' | b'0'..=b'9')) {
                    return None;
                }
                let value = go_json::legacy_value(bytes).ok()?;
                if field == "iat" {
                    if !super::oidc_valid_json_time(&value) {
                        return None;
                    }
                } else {
                    super::oidc_numeric_date(&value)?;
                }
                match field {
                    "exp" => token.exp = value,
                    "iat" => token.iat = Some(value),
                    _ => token.nbf = Some(value),
                }
            }
            "aud" => {
                token.aud = if bytes.first() == Some(&b'[') {
                    // audience's decoder creates a new local []string.
                    let mut values = Vec::new();
                    for raw in go_json::array(bytes).ok()? {
                        let mut value = String::new();
                        assign_string(&mut value, raw.get()).ok()?;
                        values.push(Value::String(value));
                    }
                    Value::Array(values)
                } else {
                    let mut value = String::new();
                    assign_string(&mut value, bytes).ok()?;
                    Value::String(value)
                };
            }
            "_claim_names" => {
                if let Err(error) = super::claim_maps::assign_names(&mut token.claim_names, bytes) {
                    saved_error.get_or_insert(error);
                }
            }
            "_claim_sources" => {
                if let Err(error) =
                    super::claim_maps::assign_sources(&mut token.claim_sources, bytes)
                {
                    saved_error.get_or_insert(error);
                }
            }
            _ => {
                let target = match field {
                    "iss" => &mut token.claims.iss,
                    "sub" => &mut token.claims.sub,
                    "nonce" => &mut token.nonce,
                    "at_hash" => &mut at_hash,
                    _ => unreachable!("known claim string field"),
                };
                if let Err(error) = assign_string(target, bytes) {
                    saved_error.get_or_insert(error);
                }
            }
        }
    }
    saved_error.is_none().then_some(OidcIdTokenClaims {
        _at_hash: at_hash,
        ..token
    })
}

/// Headscale's application claims decode follows successful core verification
/// and nonce matching. Unknown core-only fields are skipped in this pass.
pub(super) fn application_claims(bytes: &[u8]) -> Result<OidcClaims, String> {
    go_json::check_valid(bytes)?;
    let mut claims = OidcClaims::default();
    if go_json::trim(bytes) == b"null" {
        return Ok(claims);
    }
    if go_json::trim(bytes).first() != Some(&b'{') {
        return Err(format!(
            "json: cannot unmarshal {} into Go value of type types.OIDCClaims",
            kind(bytes)
        ));
    }
    let mut saved_error = None;
    for (name, raw) in go_json::object(bytes)? {
        let Some(field) = matched(
            &name,
            &[
                "iss",
                "sub",
                "name",
                "email",
                "picture",
                "preferred_username",
                "groups",
                "email_verified",
            ],
        ) else {
            continue;
        };
        match field {
            "groups" => claims.groups = flexible_strings(raw.get())?,
            "email_verified" => claims.email_verified = flexible_bool(raw.get())?,
            _ => {
                let target = match field {
                    "iss" => &mut claims.iss,
                    "sub" => &mut claims.sub,
                    "name" => &mut claims.name,
                    "email" => &mut claims.email,
                    "picture" => &mut claims.profile_picture_url,
                    "preferred_username" => &mut claims.username,
                    _ => unreachable!("known application string field"),
                };
                if let Err(error) = typed_string(target, raw.get(), "OIDCClaims", field) {
                    saved_error.get_or_insert(error);
                }
            }
        }
    }
    saved_error.map_or(Ok(claims), Err)
}

pub(super) fn header(bytes: &[u8]) -> Option<Map<String, Value>> {
    if go_json::trim(bytes) == b"null" {
        return Some(Map::new());
    }
    let mut header = Map::new();
    for (name, raw) in unique_object(bytes)? {
        let value = match name.as_str() {
            "jwk" => super::jwk::raw_value(raw.get()).ok()?,
            "kid" | "alg" | "nonce" => {
                let token = go_json::trim(raw.get());
                if token != b"null" && token.first() != Some(&b'"') {
                    return None;
                }
                go_json::legacy_value(token).ok()?
            }
            "x5c" if go_json::trim(raw.get()) == b"null" => Value::Null,
            "x5c" => Value::Array(
                go_json::array(raw.get())
                    .ok()?
                    .into_iter()
                    .map(|certificate| {
                        let token = go_json::trim(certificate.get());
                        if token != b"null" && token.first() != Some(&b'"') {
                            return None;
                        }
                        go_json::legacy_value(token).ok()
                    })
                    .collect::<Option<Vec<_>>>()?,
            ),
            // sanitized() decodes every extra header through the fork's any
            // decoder: float64 range and duplicate names apply recursively.
            _ => go_json::legacy_strict_any_value(raw.get()).ok()?,
        };
        header.insert(name, value);
    }
    Some(header)
}

fn merge_header(current: &mut Option<Map<String, Value>>, bytes: &[u8]) -> Option<()> {
    if go_json::trim(bytes) == b"null" {
        *current = None;
    } else {
        current.get_or_insert_with(Map::new).extend(header(bytes)?);
    }
    Some(())
}

fn signature(bytes: &[u8]) -> Option<OidcJsonSignature> {
    if go_json::trim(bytes) == b"null" {
        return Some(OidcJsonSignature::default());
    }
    let (remaining, fields) = project(
        bytes,
        &[("header", false)],
        true,
        Some(&["protected", "signature"]),
    )
    .ok()?;
    let mut signature: OidcJsonSignature = serde_json::from_slice(&remaining).ok()?;
    for (_, raw) in fields {
        merge_header(&mut signature.header, raw.get())?;
    }
    Some(signature)
}

pub(super) fn signed_json(bytes: &[u8]) -> Option<OidcJsonJws> {
    let (remaining, fields) = project(
        bytes,
        &[("header", false), ("signatures", false)],
        true,
        Some(&["payload", "protected", "signature"]),
    )
    .ok()?;
    let mut signed: OidcJsonJws = serde_json::from_slice(&remaining).ok()?;
    for (name, raw) in fields {
        if name == "header" {
            merge_header(&mut signed.flattened.header, raw.get())?;
        } else if go_json::trim(raw.get()) == b"null" {
            signed.signatures = None;
        } else {
            signed.signatures = Some(
                go_json::array(raw.get())
                    .ok()?
                    .into_iter()
                    .map(|raw| signature(raw.get()))
                    .collect::<Option<Vec<_>>>()?,
            );
        }
    }
    Some(signed)
}
