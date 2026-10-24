// Map/struct assignment adapts Go 1.26.9 encoding/json/decode.go (BSD-3-Clause)
// for coreos/go-oidc v3.18.0 oidc/oidc.go's idToken and claimSource shapes
// (Apache-2.0). See LICENSE/NOTICE-GO-STDLIB and LICENSE/NOTICE-GO-OIDC.
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause

//! Native distributed-claim maps retain Go's ordinary saved-error boundary:
//! malformed typed entries are assigned their zero/partial value while later
//! fields and entries continue decoding. Unknown subtrees stay raw.

use std::collections::BTreeMap;

use headscale_api_acl::{go_json, go_unicode};

use super::OidcClaimSource;

pub(super) fn assign_names(
    target: &mut BTreeMap<String, String>,
    raw: &[u8],
) -> Result<(), String> {
    go_json::check_valid(raw)?;
    let raw = go_json::trim(raw);
    if raw == b"null" {
        target.clear();
        return Ok(());
    }
    if raw.first() != Some(&b'{') {
        return Err(type_error(raw, "idToken._claim_names", "map[string]string"));
    }

    let mut saved_error = None;
    for (key, raw) in go_json::object(raw)? {
        // Go zeroes the map-element temporary for every occurrence, even for
        // a duplicate key and even when this occurrence cannot decode.
        let mut value = String::new();
        if let Err(error) = assign_string(&mut value, raw.get(), "idToken._claim_names") {
            saved_error.get_or_insert(error);
        }
        target.insert(key, value);
    }
    saved_error.map_or(Ok(()), Err)
}

pub(super) fn assign_sources(
    target: &mut BTreeMap<String, Option<OidcClaimSource>>,
    raw: &[u8],
) -> Result<(), String> {
    go_json::check_valid(raw)?;
    let raw = go_json::trim(raw);
    if raw == b"null" {
        target.clear();
        return Ok(());
    }
    if raw.first() != Some(&b'{') {
        return Err(type_error(
            raw,
            "idToken._claim_sources",
            "map[string]oidc.claimSource",
        ));
    }

    let mut saved_error = None;
    for (key, raw) in go_json::object(raw)? {
        let (source, error) = source(raw.get())?;
        if let Some(error) = error {
            saved_error.get_or_insert(error);
        }
        // The Go map element is a struct, not a pointer. JSON null therefore
        // assigns a present zero struct, represented by Some at this DTO edge.
        target.insert(key, Some(source));
    }
    saved_error.map_or(Ok(()), Err)
}

fn source(raw: &[u8]) -> Result<(OidcClaimSource, Option<String>), String> {
    if raw == b"null" {
        return Ok((OidcClaimSource::default(), None));
    }
    if raw.first() != Some(&b'{') {
        return Ok((
            OidcClaimSource::default(),
            Some(type_error(
                raw,
                "idToken._claim_sources",
                "oidc.claimSource",
            )),
        ));
    }

    let mut endpoint = String::new();
    let mut access_token = String::new();
    let mut saved_error = None;
    for (key, raw) in go_json::object(raw)? {
        let field = ["endpoint", "access_token"]
            .into_iter()
            .find(|field| key == *field)
            .or_else(|| {
                ["endpoint", "access_token"]
                    .into_iter()
                    .find(|field| go_unicode::equal_fold(&key, field))
            });
        let (target, context) = match field {
            Some("endpoint") => (&mut endpoint, "claimSource._claim_sources.endpoint"),
            Some("access_token") => (&mut access_token, "claimSource._claim_sources.access_token"),
            _ => continue,
        };
        if let Err(error) = assign_string(target, raw.get(), context) {
            saved_error.get_or_insert(error);
        }
    }
    Ok((
        OidcClaimSource {
            _endpoint: endpoint,
            _access_token: access_token,
        },
        saved_error,
    ))
}

fn assign_string(target: &mut String, raw: &[u8], context: &str) -> Result<(), String> {
    if raw == b"null" {
        return Ok(());
    }
    if raw.first() != Some(&b'"') {
        return Err(type_error(raw, context, "string"));
    }
    *target = go_json::unquote(raw)?;
    Ok(())
}

fn type_error(raw: &[u8], context: &str, target: &str) -> String {
    let kind = match raw.first() {
        Some(b'{') => "object",
        Some(b'[') => "array",
        Some(b'"') => "string",
        Some(b't' | b'f') => "bool",
        _ => "number",
    };
    format!("json: cannot unmarshal {kind} into Go struct field {context} of type {target}")
}
