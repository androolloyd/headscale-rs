// UserInfo's two decoding passes follow coreos/go-oidc v3.18.0 oidc/oidc.go
// (Apache-2.0) and Headscale v0.29.5 hscontrol/types/users.go (BSD-3-Clause).
// Struct assignment follows Go 1.26.9 encoding/json/decode.go (BSD-3-Clause).
// See LICENSE-GO-OIDC, NOTICE-GO-OIDC, LICENSE-HEADSCALE-GO,
// NOTICE-HEADSCALE-GO, LICENSE-GO-STDLIB and NOTICE-GO-STDLIB.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Native UserInfo preserves the provider library's first decode before the
//! Headscale claims decode. Neither pass buffers unknown values as generic
//! numbers or discards duplicate fields.

use headscale_api_acl::{go_json, go_unicode};

use super::OidcUserInfo;

const PROVIDER_FIELDS: &[&str] = &["sub", "profile", "email", "email_verified"];
const CLAIM_FIELDS: &[&str] = &[
    "sub",
    "name",
    "given_name",
    "family_name",
    "preferred_username",
    "email",
    "email_verified",
    "groups",
    "picture",
];

pub(super) enum DecodeError {
    Provider(String),
    Claims,
}

pub(super) fn parse(bytes: &[u8]) -> Result<OidcUserInfo, DecodeError> {
    // encoding/json validates the whole input before invoking custom methods.
    go_json::check_valid(bytes).map_err(|error| provider_error(&error))?;
    let bytes = go_json::trim(bytes);
    if bytes == b"null" {
        return Ok(OidcUserInfo::default());
    }
    if bytes.first() != Some(&b'{') {
        return Err(provider_error(&type_error(
            bytes,
            None,
            "oidc.userInfoRaw",
            "userInfoRaw",
        )));
    }
    let fields = go_json::object(bytes).map_err(|error| provider_error(&error))?;

    // Provider.UserInfo first decodes userInfoRaw, including its profile field
    // which Headscale's second struct does not expose. Save ordinary type
    // errors, but let a later custom stringAsBool error return immediately.
    let mut saved_error = None;
    for (key, raw) in &fields {
        let Some(field) = field_name(key, PROVIDER_FIELDS) else {
            continue;
        };
        let raw = raw.get();
        if field == "email_verified" {
            provider_boolean(raw).map_err(|error| provider_error(&error))?;
        } else if let Err(error) = check_string(raw, field, "userInfoRaw") {
            saved_error.get_or_insert(error);
        }
    }
    if let Some(error) = saved_error {
        return Err(provider_error(&error));
    }

    // userInfo.Claims then decodes the original bytes into OIDCUserInfo.
    // Repeated plain null strings do not overwrite earlier assignments.
    let mut userinfo = OidcUserInfo::default();
    let mut saved_error = None;
    for (key, raw) in fields {
        let Some(field) = field_name(&key, CLAIM_FIELDS) else {
            continue;
        };
        let raw = raw.get();
        match field {
            "email_verified" => {
                // The first pass checked every occurrence against the four
                // raw spellings accepted by stringAsBool. All four also pass
                // Headscale's more permissive FlexibleBoolean decoder.
                userinfo.email_verified = provider_boolean(raw).map_err(|_| DecodeError::Claims)?;
            }
            "groups" => {
                userinfo.groups = if raw == b"null" {
                    None
                } else {
                    Some(super::json::flexible_strings(raw).map_err(|_| DecodeError::Claims)?)
                };
            }
            _ => {
                let target = match field {
                    "sub" => &mut userinfo.sub,
                    "name" => &mut userinfo.name,
                    "given_name" => &mut userinfo.given_name,
                    "family_name" => &mut userinfo.family_name,
                    "preferred_username" => &mut userinfo.preferred_username,
                    "email" => &mut userinfo.email,
                    "picture" => &mut userinfo.picture,
                    _ => unreachable!("known UserInfo field"),
                };
                match check_string(raw, field, "OIDCUserInfo") {
                    Ok(()) if raw != b"null" => {
                        *target = go_json::unquote(raw).map_err(|_| DecodeError::Claims)?;
                    }
                    Ok(()) => {}
                    Err(error) => {
                        saved_error.get_or_insert(error);
                    }
                }
            }
        }
    }
    if saved_error.is_some() {
        Err(DecodeError::Claims)
    } else {
        Ok(userinfo)
    }
}

fn field_name<'a>(key: &str, fields: &'a [&'a str]) -> Option<&'a str> {
    fields
        .iter()
        .copied()
        .find(|field| key == *field)
        .or_else(|| {
            fields
                .iter()
                .copied()
                .find(|field| go_unicode::equal_fold(key, field))
        })
}

fn provider_boolean(raw: &[u8]) -> Result<bool, String> {
    match raw {
        b"true" | b"\"true\"" => Ok(true),
        b"false" | b"\"false\"" => Ok(false),
        _ => Err("invalid value for boolean".into()),
    }
}

fn check_string(raw: &[u8], field: &str, structure: &str) -> Result<(), String> {
    if raw == b"null" || raw.first() == Some(&b'"') {
        Ok(())
    } else {
        Err(type_error(raw, Some(field), "string", structure))
    }
}

fn type_error(raw: &[u8], field: Option<&str>, target: &str, structure: &str) -> String {
    let kind = match raw.first() {
        Some(b'{') => "object",
        Some(b'[') => "array",
        Some(b'"') => "string",
        Some(b't' | b'f') => "bool",
        _ => "number",
    };
    match field {
        Some(field) => format!(
            "json: cannot unmarshal {kind} into Go struct field {structure}.{field} of type {target}"
        ),
        None => format!("json: cannot unmarshal {kind} into Go value of type {target}"),
    }
}

fn provider_error(error: &str) -> DecodeError {
    DecodeError::Provider(format!("oidc: failed to decode userinfo: {error}"))
}
