// The provider shape and response handling follow coreos/go-oidc v3.18.0
// oidc/oidc.go (Apache-2.0; see LICENSE-GO-OIDC and NOTICE-GO-OIDC).
// Copyright 2014 CoreOS, Inc
// JSON assignment and MIME parsing adapt Go 1.26.9 encoding/json/decode.go,
// mime/mediatype.go and mime/grammar.go, Copyright 2010 The Go Authors.
// BSD terms and source attribution: LICENSE-GO-STDLIB, NOTICE-GO-STDLIB.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Decode provider fields in document order, including Go's duplicate/null
//! assignment rules. The public metadata DTO remains source-compatible.

use headscale_api_acl::{go_json, go_unicode};

use super::OidcProviderMetadata;

pub(super) fn decode(body: &[u8]) -> Result<OidcProviderMetadata, String> {
    go_json::check_valid(body)?;
    let body = go_json::trim(body);
    if body == b"null" {
        return Ok(OidcProviderMetadata::default());
    }
    if body.first() != Some(&b'{') {
        return Err(type_error(body, None, "oidc.providerJSON"));
    }

    let mut metadata = OidcProviderMetadata::default();
    let mut device_auth_url = String::new();
    let mut userinfo_url = String::new();
    // Go reuses the slice's backing array across duplicate fields. Null array
    // elements leave old slots intact, even after an intervening shorter list.
    let mut algorithms = Vec::<String>::new();
    let mut algorithms_len = 0;
    for (key, raw) in go_json::object(body)? {
        let Some(field) = FIELDS
            .iter()
            .copied()
            .find(|name| go_unicode::equal_fold(&key, name))
        else {
            continue;
        };
        let value = raw.get();
        if field == "id_token_signing_alg_values_supported" {
            if value == b"null" {
                algorithms = Vec::new();
                algorithms_len = 0;
                continue;
            }
            if value.first() != Some(&b'[') {
                return Err(type_error(value, Some(field), "[]string"));
            }
            let elements = go_json::array(value)?;
            algorithms_len = elements.len();
            if algorithms_len == 0 {
                algorithms = Vec::new();
            } else if algorithms.len() < algorithms_len {
                algorithms.resize(algorithms_len, String::new());
            }
            for (index, raw) in elements.into_iter().enumerate() {
                assign_string(&mut algorithms[index], raw.get(), field)?;
            }
            continue;
        }
        let target = match field {
            "issuer" => &mut metadata.issuer,
            "authorization_endpoint" => &mut metadata.authorization_endpoint,
            "token_endpoint" => &mut metadata.token_endpoint,
            "device_authorization_endpoint" => &mut device_auth_url,
            "jwks_uri" => &mut metadata.jwks_uri,
            "userinfo_endpoint" => &mut userinfo_url,
            _ => unreachable!("known provider field"),
        };
        assign_string(target, value, field)?;
    }
    metadata.id_token_signing_alg_values_supported = algorithms[..algorithms_len].to_vec();
    if !userinfo_url.is_empty() {
        metadata.userinfo_endpoint = Some(userinfo_url);
    }
    Ok(metadata)
}

const FIELDS: &[&str] = &[
    "issuer",
    "authorization_endpoint",
    "token_endpoint",
    "device_authorization_endpoint",
    "jwks_uri",
    "userinfo_endpoint",
    "id_token_signing_alg_values_supported",
];

fn assign_string(target: &mut String, value: &[u8], field: &str) -> Result<(), String> {
    if value == b"null" {
        return Ok(());
    }
    if value.first() != Some(&b'"') {
        return Err(type_error(value, Some(field), "string"));
    }
    *target = go_json::unquote(value)?;
    Ok(())
}

fn type_error(value: &[u8], field: Option<&str>, target: &str) -> String {
    let kind = match value.first() {
        Some(b'{') => "object",
        Some(b'[') => "array",
        Some(b'"') => "string",
        Some(b't' | b'f') => "bool",
        _ => "number",
    };
    match field {
        Some(field) => format!(
            "json: cannot unmarshal {kind} into Go struct field providerJSON.{field} of type {target}"
        ),
        None => format!("json: cannot unmarshal {kind} into Go value of type {target}"),
    }
}

/// unmarshalResp only selects its JSON-specific diagnostic when the *whole*
/// MIME value parses successfully. A valid base with invalid/unequal duplicate
/// parameters must take the other diagnostic. RFC 2231 value stitching does
/// not affect this success predicate or the base media type.
pub(super) fn has_json_content_type(content_type: &[u8]) -> bool {
    let (base, error) = super::form::media_type_bytes(content_type);
    error.is_none() && base == "application/json"
}
