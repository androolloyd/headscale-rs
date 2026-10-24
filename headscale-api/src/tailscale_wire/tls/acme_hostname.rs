// Copyright 2016 The Go Authors. All rights reserved.
// ACME hostname phases adapt x/crypto/acme/autocert; see LICENSE-GO-STDLIB.

//! The selected Go Lookup profile uses Unicode 15 nontransitional UTS #46,
//! STD3, hyphen/context-joiner/bidi checks, and no DNS-length check. Private
//! source-derived tables and algorithms keep its normalization and Punycode
//! phases independent of host/ICU Unicode versions. Opted native acceptors
//! preserve raw SNI; other rustls paths retain DNS validation before this layer.
//! Source implementation is unexecuted.

use super::WireError;

mod bidi;
// Generated conversion of Go's idna/norm/bidi tables; digit grouping would only
// obscure the diff against the pinned Go source.
#[allow(clippy::unreadable_literal)]
mod data;
mod nfc;
mod profile;
mod punycode;
mod trie;

#[derive(Debug)]
pub(super) struct HostPolicy {
    allowed: Option<String>,
}

impl HostPolicy {
    pub(super) fn new(configured: &str) -> Self {
        // HostWhitelist silently omits invalid configured names. Keep that
        // distinct from an unbound embedding resolver with no host policy.
        Self {
            allowed: lookup(configured),
        }
    }

    pub(super) fn allows(&self, normalized: &str) -> bool {
        self.allowed.as_deref() == Some(normalized)
    }
}

pub(super) fn lookup(name: &str) -> Option<String> {
    profile::lookup(name)
}

/// GetCertificate checks empty/component count before invoking IDNA. Work on
/// bytes first so malformed UTF-8 does not change that diagnostic precedence.
pub(super) fn server_name_bytes(name: Option<&[u8]>) -> Result<String, WireError> {
    let name = name
        .filter(|name| !name.is_empty())
        .ok_or_else(|| WireError::Internal("acme/autocert: missing server name".into()))?;
    let first = name
        .iter()
        .position(|byte| *byte != b'.')
        .unwrap_or(name.len());
    let trimmed = &name[first..];
    let end = trimmed
        .iter()
        .rposition(|byte| *byte != b'.')
        .map_or(0, |index| index + 1);
    if !trimmed[..end].contains(&b'.') {
        return Err(WireError::Internal(
            "acme/autocert: server name component count invalid".into(),
        ));
    }
    let name = std::str::from_utf8(name)
        .ok()
        .and_then(lookup)
        .ok_or_else(|| {
            WireError::Internal("acme/autocert: server name contains invalid character".into())
        })?;
    Ok(name)
}

pub(super) fn cache_hostname(name: &str) -> Option<String> {
    let normalized = lookup(name)?;
    let cache = normalized.strip_suffix('.').unwrap_or(&normalized);
    // Go never reaches its cert-cache lookup for an empty incoming name.
    // Rust's eager configured-host cache access needs a representable file.
    (!cache.is_empty()).then(|| cache.to_owned())
}
