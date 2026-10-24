// Copyright 2011, 2016 The Go Authors. All rights reserved.
// Cache eligibility adapts x/crypto/acme/autocert; hostname matching adapts
// Go 1.26.9 crypto/x509/verify.go (Go Authors); see LICENSE-GO-STDLIB.

//! Native ordinary ECDSA/RSA and TLS-ALPN token disk-cache eligibility. This does not
//! validate a trust chain, EKU, certificate signatures or network revocation:
//! selected autocert.validCert does not perform those checks. X.509/ASN.1,
//! distinguished-name and private-key parsing still use the selected Rust
//! libraries; provider SPKI equality is stricter than Go's EC coordinate/RSA
//! modulus comparison. This is not a complete Go crypto/x509 parser port.

use std::{collections::BTreeSet, net::IpAddr};

use chrono::{DateTime, Utc};
use rustls::{SignatureAlgorithm, pki_types::PrivateKeyDer};
use x509_parser::{certificate::X509Certificate, extensions::GeneralName, public_key::PublicKey};

use super::{AcmeCertificateKind, WireError, acme_hostname};

mod pem;

fn error(message: impl Into<String>) -> WireError {
    WireError::Internal(format!("acme/autocert: {}", message.into()))
}

fn private_der(block: pem::Block<'_>) -> Result<PrivateKeyDer<'static>, WireError> {
    if !block.label.windows(7).any(|part| part == b"PRIVATE") {
        return Err(error("certificate cache miss"));
    }
    PrivateKeyDer::try_from(block.bytes).map_err(|_| error("failed to parse private key"))
}

fn encode_private(key: &PrivateKeyDer<'_>) -> Result<String, WireError> {
    let label = match key {
        PrivateKeyDer::Pkcs1(_) => "RSA PRIVATE KEY",
        PrivateKeyDer::Pkcs8(_) => "PRIVATE KEY",
        PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
        _ => return Err(error("failed to parse private key")),
    };
    Ok(pem::encode(label, key.secret_der()))
}

pub(super) fn encode_entry(key_pem: &str, certificate_pem: &str) -> Result<String, WireError> {
    let (private, _) =
        pem::decode(key_pem.as_bytes()).ok_or_else(|| error("failed to parse private key"))?;
    let mut output = encode_private(&private_der(private)?)?;
    let mut rest = certificate_pem.as_bytes();
    let mut found = false;
    // Go fetchCertRFC extracts only CERTIFICATE blocks and ignores the final
    // undecodable suffix. cachePut then emits canonical PEM for each DER block.
    // This differs intentionally from the strict final-rest disk-cache reader.
    while let Some((block, next)) = pem::decode(rest) {
        if block.label != b"CERTIFICATE" {
            return Err(error("invalid PEM certificate type"));
        }
        output.push_str(&pem::encode("CERTIFICATE", &block.bytes));
        rest = next;
        found = true;
    }
    if !found {
        return Err(error("certificate chain is empty"));
    }
    Ok(output)
}

pub(super) fn load(
    combined: &[u8],
    hostname: &str,
) -> Result<(String, String, DateTime<Utc>), WireError> {
    load_normal(combined, hostname, AcmeCertificateKind::Ecdsa)
}

pub(super) fn load_normal(
    combined: &[u8],
    hostname: &str,
    kind: AcmeCertificateKind,
) -> Result<(String, String, DateTime<Utc>), WireError> {
    let domain = acme_hostname::cache_hostname(hostname)
        .ok_or_else(|| error("invalid certificate cache hostname"))?;
    let kind = match kind {
        AcmeCertificateKind::Ecdsa => Kind::NormalEcdsa,
        AcmeCertificateKind::Rsa => Kind::NormalRsa,
    };
    load_kind(combined, &domain, kind).map_err(LoadFailure::into_error)
}

pub(super) fn lookup_normal(
    combined: &[u8],
    hostname: &str,
    kind: AcmeCertificateKind,
) -> Result<Option<(String, String, DateTime<Utc>)>, WireError> {
    let domain = acme_hostname::cache_hostname(hostname)
        .ok_or_else(|| error("invalid certificate cache hostname"))?;
    let kind = match kind {
        AcmeCertificateKind::Ecdsa => Kind::NormalEcdsa,
        AcmeCertificateKind::Rsa => Kind::NormalRsa,
    };
    match load_kind(combined, &domain, kind) {
        Ok(certificate) => Ok(Some(certificate)),
        Err(LoadFailure::Miss(_)) => Ok(None),
        Err(LoadFailure::Fatal(error)) => Err(error),
    }
}

// GetCertificate's token key uses the Lookup-normalized name WITHOUT the
// ordinary certificate key's one-root-dot trim. It does not promote the result
// into the in-memory token map or create an ordinary certificate renewal.
pub(super) fn load_token(
    combined: &[u8],
    normalized_domain: &str,
) -> Result<(String, String, DateTime<Utc>), WireError> {
    load_kind(combined, normalized_domain, Kind::Token).map_err(LoadFailure::into_error)
}

#[derive(Clone, Copy)]
enum Kind {
    NormalEcdsa,
    NormalRsa,
    Token,
}

enum LoadFailure {
    Miss(WireError),
    Fatal(WireError),
}

impl LoadFailure {
    fn into_error(self) -> WireError {
        match self {
            Self::Miss(error) | Self::Fatal(error) => error,
        }
    }
}

fn load_kind(
    combined: &[u8],
    domain: &str,
    kind: Kind,
) -> Result<(String, String, DateTime<Utc>), LoadFailure> {
    let (private, mut rest) =
        pem::decode(combined).ok_or_else(|| LoadFailure::Miss(error("certificate cache miss")))?;
    if !private.label.windows(7).any(|part| part == b"PRIVATE") {
        return Err(LoadFailure::Miss(error("certificate cache miss")));
    }
    // Go ignores the PEM key label beyond Contains("PRIVATE") and attempts
    // PKCS#1, PKCS#8 and SEC1 DER. The selected Rust/provider decoder retains
    // its own supported-curve and ASN.1 acceptance boundary.
    let private_key = private_der(private).map_err(LoadFailure::Fatal)?;
    let key_pem = encode_private(&private_key).map_err(LoadFailure::Fatal)?;
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(private_key)
        .map_err(|_| LoadFailure::Fatal(error("failed to parse private key")))?;
    if !matches!(
        signing_key.algorithm(),
        SignatureAlgorithm::RSA | SignatureAlgorithm::ECDSA
    ) {
        return Err(LoadFailure::Fatal(error(
            "unknown private key type in PKCS#8 wrapping",
        )));
    }

    // cacheGet propagates private-key parsing failures, but converts all
    // public-chain/validCert failures into ErrCacheMiss before issuance.
    (|| {
        let mut public = Vec::new();
        let mut cert_pem = String::new();
        while !rest.is_empty() {
            let (block, next) = pem::decode(rest).ok_or_else(|| error("certificate cache miss"))?;
            // All subsequent PEM labels contribute DER in Go, including labels
            // other than CERTIFICATE. Inter-block skipped text is handled by Decode;
            // a final unconsumed suffix (even whitespace) is a cache miss.
            public.extend_from_slice(&block.bytes);
            // Keep Go's original DER block grouping on the TLS chain, while
            // canonicalizing labels/line wrapping for the Rust PEM decoder.
            cert_pem.push_str(&pem::encode("CERTIFICATE", &block.bytes));
            rest = next;
        }
        if public.is_empty() {
            return Err(error("no public key found"));
        }
        let mut remaining = public.as_slice();
        let mut leaf_der = None;
        while !remaining.is_empty() {
            let (next, cert) = x509_parser::parse_x509_certificate(remaining)
                .map_err(|_| error("no public key found"))?;
            validate_extensions(&cert)?;
            let consumed = remaining.len() - next.len();
            if consumed == 0 {
                return Err(error("no public key found"));
            }
            let der = &remaining[..consumed];
            if leaf_der.is_none() {
                leaf_der = Some(der);
            }
            remaining = next;
        }
        let (_, leaf) = x509_parser::parse_x509_certificate(
            leaf_der.ok_or_else(|| error("no public key found"))?,
        )
        .map_err(|_| error("no public key found"))?;
        let not_before = DateTime::from_timestamp(leaf.validity().not_before.timestamp(), 0)
            .ok_or_else(|| error("certificate notBefore is out of range"))?;
        let not_after = DateTime::from_timestamp(leaf.validity().not_after.timestamp(), 0)
            .ok_or_else(|| error("certificate notAfter is out of range"))?;
        let now = Utc::now();
        if now < not_before {
            return Err(error("certificate is not valid yet"));
        }
        if now > not_after {
            return Err(error("expired certificate"));
        }
        if !verify_hostname(&leaf, domain)? {
            return Err(error(format!("certificate is not valid for {domain}")));
        }
        let organizations = leaf.issuer().iter_organization().collect::<Vec<_>>();
        // 2022-01-26 00:48:00 UTC, the selected autocert one-time LE revocation rule.
        if organizations.len() == 1
            && organizations[0].as_str().ok() == Some("Let's Encrypt")
            && not_before.timestamp() < 1_643_158_080
        {
            return Err(error("certificate was probably revoked by Let's Encrypt"));
        }
        let expected_key = matches!(
            (leaf.public_key().parsed(), signing_key.algorithm(), kind),
            (
                Ok(PublicKey::EC(_)),
                SignatureAlgorithm::ECDSA,
                Kind::NormalEcdsa | Kind::Token
            ) | (
                Ok(PublicKey::RSA(_)),
                SignatureAlgorithm::RSA,
                Kind::NormalRsa | Kind::Token
            )
        );
        if !expected_key {
            return Err(error("key type does not match expected value"));
        }
        let key_spki = signing_key
            .public_key()
            .ok_or_else(|| error("private key public value is unavailable"))?;
        if key_spki.as_ref() != leaf.public_key().raw {
            return Err(error("private key does not match public key"));
        }
        Ok((key_pem, cert_pem, not_after))
    })()
    .map_err(LoadFailure::Miss)
}

fn validate_extensions(cert: &X509Certificate<'_>) -> Result<(), WireError> {
    let mut seen = BTreeSet::new();
    for extension in cert.extensions() {
        if !seen.insert(extension.oid.to_id_string()) {
            return Err(error("certificate contains duplicate extension"));
        }
    }
    if let Some(san) = cert
        .subject_alternative_name()
        .map_err(|_| error("malformed certificate subject alternative name"))?
    {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(name)
                | GeneralName::RFC822Name(name)
                | GeneralName::URI(name)
                    if !name.is_ascii() =>
                {
                    return Err(error("malformed certificate IA5 subject alternative name"));
                }
                GeneralName::IPAddress(bytes) if !matches!(bytes.len(), 4 | 16) => {
                    return Err(error("malformed certificate IP address"));
                }
                GeneralName::Invalid(tag, _) if matches!(tag.0, 1 | 2 | 6 | 7) => {
                    return Err(error("malformed certificate subject alternative name"));
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn normalized_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
        ip @ IpAddr::V4(_) => ip,
    }
}

fn verify_hostname(cert: &X509Certificate<'_>, hostname: &str) -> Result<bool, WireError> {
    let san = cert
        .subject_alternative_name()
        .map_err(|_| error("malformed certificate subject alternative name"))?;
    let Some(san) = san else {
        // Go explicitly ignores the legacy Common Name.
        return Ok(false);
    };
    let candidate_ip =
        if hostname.len() >= 3 && hostname.starts_with('[') && hostname.ends_with(']') {
            &hostname[1..hostname.len() - 1]
        } else {
            hostname
        };
    if let Ok(ip) = candidate_ip.parse::<IpAddr>() {
        let ip = normalized_ip(ip);
        return Ok(san.value.general_names.iter().any(|name| {
            let GeneralName::IPAddress(bytes) = name else {
                return false;
            };
            let candidate = match bytes.len() {
                4 => <[u8; 4]>::try_from(*bytes).ok().map(IpAddr::from),
                16 => <[u8; 16]>::try_from(*bytes).ok().map(IpAddr::from),
                _ => None,
            };
            candidate.is_some_and(|candidate| normalized_ip(candidate) == ip)
        }));
    }
    let candidate = hostname.to_ascii_lowercase();
    let valid_candidate = valid_hostname(&candidate, false);
    let parts = candidate
        .strip_suffix('.')
        .unwrap_or(&candidate)
        .split('.')
        .collect::<Vec<_>>();
    Ok(san.value.general_names.iter().any(|name| {
        let GeneralName::DNSName(pattern) = name else {
            return false;
        };
        if valid_candidate && valid_hostname(pattern, true) {
            let pattern = pattern.to_ascii_lowercase();
            let pattern_parts = pattern.split('.').collect::<Vec<_>>();
            pattern_parts.len() == parts.len()
                && pattern_parts.iter().zip(&parts).enumerate().all(
                    |(index, (pattern, candidate))| {
                        (index == 0 && *pattern == "*") || pattern == candidate
                    },
                )
        } else {
            !matches!(*pattern, "" | ".")
                && !matches!(candidate.as_str(), "" | ".")
                && pattern.eq_ignore_ascii_case(&candidate)
        }
    }))
}

fn valid_hostname(hostname: &str, pattern: bool) -> bool {
    let hostname = if pattern {
        hostname
    } else {
        hostname.strip_suffix('.').unwrap_or(hostname)
    };
    if hostname.is_empty() || hostname == "*" {
        return false;
    }
    hostname.split('.').enumerate().all(|(index, part)| {
        !part.is_empty()
            && ((pattern && index == 0 && part == "*")
                || part.bytes().enumerate().all(|(position, byte)| {
                    byte.is_ascii_alphanumeric() || byte == b'_' || (byte == b'-' && position != 0)
                }))
    })
}
