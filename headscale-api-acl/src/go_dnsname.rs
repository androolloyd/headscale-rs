// Copyright (c) Tailscale Inc & contributors
// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause

//! Pinned Tailscale label checks and Headscale node FQDN bounds.

use crate::go_strconv::{quote, quote_rune};

pub const MAX_HOSTNAME_LENGTH: usize = 255;

pub fn valid_label(label: &str) -> Result<(), String> {
    let bytes = label.as_bytes();
    if bytes.is_empty() {
        return Err("empty DNS label".into());
    }
    if bytes.len() > 63 {
        return Err(format!(
            "{} is too long, max length is 63 bytes",
            quote(label)
        ));
    }
    if !bytes[0].is_ascii_alphanumeric() {
        return Err(format!(
            "{} is not a valid DNS label: must start with a letter or number",
            quote(label)
        ));
    }
    if !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(format!(
            "{} is not a valid DNS label: must end with a letter or number",
            quote(label)
        ));
    }
    for &byte in bytes.get(1..bytes.len() - 1).unwrap_or_default() {
        if !byte.is_ascii_alphanumeric() && byte != b'-' {
            return Err(format!(
                "{} is not a valid DNS label: contains invalid character {}",
                quote(label),
                quote_rune(char::from(byte))
            ));
        }
    }
    Ok(())
}

/// GetFQDN checks emptiness and the full byte length, not label syntax.
pub fn validate_fqdn(given_name: &str, base_domain: &str) -> Result<(), String> {
    if given_name.is_empty() {
        return Err("creating valid FQDN: node has no given name".into());
    }
    let suffix = if base_domain.is_empty() {
        0
    } else {
        base_domain.len().saturating_add(2)
    };
    if given_name.len().saturating_add(suffix) > MAX_HOSTNAME_LENGTH {
        let hostname = if base_domain.is_empty() {
            given_name.into()
        } else {
            format!("{given_name}.{base_domain}.")
        };
        return Err(format!(
            "creating valid FQDN ({hostname}): hostname too long, cannot accept more than 255 ASCII chars"
        ));
    }
    Ok(())
}

pub fn validate_given_name(given_name: &str, base_domain: &str) -> Result<(), String> {
    valid_label(given_name)
        .map_err(|error| format!("{} is not a valid DNS label: {error}", quote(given_name)))?;
    validate_fqdn(given_name, base_domain)
}
