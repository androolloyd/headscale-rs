//! JWK import semantics from go-jose v4.1.4 and Go 1.26 RSA validation.
//! Private components are checked only for import compatibility, then dropped.

use aws_lc_rs::signature::{self, ParsedPublicKey, VerificationAlgorithm};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use num_bigint::BigUint;
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use super::{
    OidcJwk, OidcJwks, decode_oidc_base64, oidc_certificate_chain, oidc_ec_public_key,
    oidc_header_string, oidc_integer_bytes, oidc_rsa_exponent,
};

const INVALID: &str = "invalid OIDC JWK";

impl<'de> Deserialize<'de> for OidcJwks {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Default, Deserialize)]
        struct RawSet {
            keys: Option<Vec<Value>>,
        }
        // JSON null and a null/missing keys slice replace the cache with an
        // empty set. Any invalid key, including unknown kty, rejects the set.
        let raw = Option::<RawSet>::deserialize(deserializer)?.unwrap_or_default();
        let keys = raw
            .keys
            .unwrap_or_default()
            .iter()
            .map(parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(serde::de::Error::custom)?;
        Ok(Self { keys })
    }
}

/// Native key-set import preserves objects before checking typed JWK fields.
/// Generic Value deserialization can reinterpret an ordinary private-number
/// key; raw key records must keep that key as JSON data instead.
pub(super) fn decode(bytes: &[u8]) -> Result<OidcJwks, &'static str> {
    use headscale_api_acl::{go_json, go_unicode};
    if go_json::trim(bytes) == b"null" {
        return Ok(OidcJwks { keys: Vec::new() });
    }
    let mut keys = Vec::new();
    for (name, raw) in go_json::object(bytes).map_err(|_| INVALID)? {
        if !go_unicode::equal_fold(&name, "keys") {
            continue;
        }
        keys = if go_json::trim(raw.get()) == b"null" {
            Vec::new()
        } else {
            go_json::array(raw.get())
                .map_err(|_| INVALID)?
                .into_iter()
                .map(|raw| {
                    let value = raw_value(raw.get())?;
                    parse(&value)
                })
                .collect::<Result<Vec<_>, _>>()?
        };
    }
    Ok(OidcJwks { keys })
}

pub(super) fn raw_value(bytes: &[u8]) -> Result<Value, &'static str> {
    use headscale_api_acl::go_json;
    if go_json::trim(bytes) == b"null" {
        return Ok(Value::Null);
    }
    let mut known = Map::new();
    for (name, raw) in super::json::unique_object(bytes).ok_or(INVALID)? {
        let raw = go_json::trim(raw.get());
        let value = match name.as_str() {
            "use" | "kty" | "kid" | "crv" | "alg" | "x5u" | "k" | "x" | "y" | "n" | "e" | "d"
            | "p" | "q" | "dp" | "dq" | "qi" | "x5t" | "x5t#S256" => {
                if raw != b"null" && raw.first() != Some(&b'"') {
                    return Err(INVALID);
                }
                go_json::legacy_value(raw).map_err(|_| INVALID)?
            }
            "x5c" if raw == b"null" => Value::Null,
            "x5c" => Value::Array(
                go_json::array(raw)
                    .map_err(|_| INVALID)?
                    .into_iter()
                    .map(|certificate| {
                        let text = go_json::trim(certificate.get());
                        if text != b"null" && text.first() != Some(&b'"') {
                            return Err(INVALID);
                        }
                        go_json::legacy_value(text).map_err(|_| INVALID)
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            // The JOSE struct decoder checks direct duplicate names, then
            // skips unknown values without allocating/cloning their trees.
            _ => continue,
        };
        known.insert(name, value);
    }
    Ok(Value::Object(known))
}

fn bytes(fields: &Map<String, Value>, name: &str) -> Result<Option<Vec<u8>>, &'static str> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => decode_oidc_base64(value).map(Some).ok_or(INVALID),
        _ => Err(INVALID),
    }
}

fn required_bytes(fields: &Map<String, Value>, name: &str) -> Result<Vec<u8>, &'static str> {
    bytes(fields, name)?.ok_or(INVALID)
}

fn number(fields: &Map<String, Value>, name: &str) -> Result<Option<BigUint>, &'static str> {
    bytes(fields, name)?
        .map(|value| {
            let value = oidc_integer_bytes(&value);
            // Bound private-key import arithmetic as well as verification.
            // An embedded JWK is untrusted even when it cannot supply trust.
            if value.len() > super::rsa::MAX_MODULUS_BYTES {
                return Err(INVALID);
            }
            Ok(BigUint::from_bytes_be(value))
        })
        .transpose()
}

fn ed25519_public(value: &[u8]) -> [u8; 32] {
    // Pinned go-jose copies into a fixed 32-byte buffer, padding/truncating.
    let mut public = [0; 32];
    let len = value.len().min(public.len());
    public[..len].copy_from_slice(&value[..len]);
    public
}

fn valid_reference_url(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return false;
    }
    let (head, fragment) = value.split_once('#').map_or((value, ""), |parts| parts);
    let path = head.split_once('?').map_or(head, |(path, _)| path);
    for part in [path, fragment] {
        let part = part.as_bytes();
        let mut offset = 0;
        while offset < part.len() {
            if part[offset] == b'%' {
                if offset + 2 >= part.len()
                    || !part[offset + 1].is_ascii_hexdigit()
                    || !part[offset + 2].is_ascii_hexdigit()
                {
                    return false;
                }
                offset += 3;
            } else {
                offset += 1;
            }
        }
    }
    if let Some((scheme, _)) = path.split('/').next().unwrap_or_default().split_once(':')
        && (!scheme
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic)
            || !scheme
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')))
    {
        return false;
    }
    let Ok(base) = reqwest::Url::parse("https://oidc.invalid/") else {
        return false;
    };
    reqwest::Url::options()
        .base_url(Some(&base))
        .parse(value)
        .is_ok()
}

fn thumbprint(
    fields: &Map<String, Value>,
    name: &str,
    size: usize,
) -> Result<Vec<u8>, &'static str> {
    let value = oidc_header_string(fields, name).ok_or(INVALID)?;
    let decoded = decode_oidc_base64(&value).ok_or(INVALID)?;
    // go-jose also accepts a base64url-encoded hexadecimal digest.
    let decoded = if decoded.len() == size * 2 {
        hex::decode(decoded).map_err(|_| INVALID)?
    } else {
        decoded
    };
    if !decoded.is_empty() && decoded.len() != size {
        return Err(INVALID);
    }
    Ok(decoded)
}

fn metadata(fields: &Map<String, Value>) -> Result<Vec<Vec<u8>>, &'static str> {
    for name in ["use", "kty", "kid", "crv", "alg", "x5u", "x5t", "x5t#S256"] {
        oidc_header_string(fields, name).ok_or(INVALID)?;
    }
    for name in ["k", "x", "y", "n", "e", "d", "p", "q", "dp", "dq", "qi"] {
        bytes(fields, name)?;
    }
    let url = oidc_header_string(fields, "x5u").ok_or(INVALID)?;
    if !valid_reference_url(&url) {
        return Err(INVALID);
    }
    let certificates = oidc_certificate_chain(fields.get("x5c")).ok_or(INVALID)?;
    let sha1 = thumbprint(fields, "x5t", 20)?;
    let sha256 = thumbprint(fields, "x5t#S256", 32)?;
    if let Some(leaf) = certificates.first() {
        use aws_lc_rs::digest;
        if !sha1.is_empty()
            && sha1.as_slice() != digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, leaf).as_ref()
        {
            return Err(INVALID);
        }
        if !sha256.is_empty() && sha256.as_slice() != digest::digest(&digest::SHA256, leaf).as_ref()
        {
            return Err(INVALID);
        }
    }
    Ok(certificates)
}

fn valid_rsa_private(
    fields: &Map<String, Value>,
    modulus_bytes: &[u8],
    public_exponent: i64,
) -> bool {
    if oidc_integer_bytes(modulus_bytes).len() > super::rsa::MAX_MODULUS_BYTES {
        return false;
    }
    let (Ok(Some(private_exponent)), Ok(Some(prime_p)), Ok(Some(prime_q))) = (
        number(fields, "d"),
        number(fields, "p"),
        number(fields, "q"),
    ) else {
        return false;
    };
    let modulus = BigUint::from_bytes_be(modulus_bytes);
    let one = BigUint::from(1u8);
    let two = BigUint::from(2u8);
    if modulus <= one
        || !modulus.bit(0)
        || !(3..=i64::from(i32::MAX)).contains(&public_exponent)
        || public_exponent % 2 == 0
        || prime_p <= two
        || prime_q <= two
        || prime_p >= modulus
        || prime_q >= modulus
        || private_exponent >= modulus
    {
        return false;
    }
    let pm = &prime_p - &one;
    let qm = &prime_q - &one;
    let (Ok(dp), Ok(dq), Ok(qi)) = (
        number(fields, "dp"),
        number(fields, "dq"),
        number(fields, "qi"),
    ) else {
        return false;
    };
    let (dp, dq, qi) = if let (Some(dp), Some(dq), Some(qi)) = (dp, dq, qi) {
        (dp, dq, qi)
    } else {
        // Go ignores partial CRT values and reconstructs all three. Its
        // inversion uses Fermat's exponent, then validates the result below.
        if !prime_p.bit(0) {
            return false;
        }
        (
            &private_exponent % &pm,
            &private_exponent % &qm,
            prime_q.modpow(&(&prime_p - &two), &prime_p),
        )
    };
    let exponent = BigUint::from(public_exponent as u64);
    if dp >= pm
        || dq >= qm
        || qi >= prime_p
        || (&prime_p * &prime_q) % &modulus != BigUint::from(0u8)
        || (&dp * &exponent) % &pm != one
        || (&dq * &exponent) % &qm != one
        || (&qi * &prime_q) % &prime_p != one
        || &private_exponent % &pm != dp
        || &private_exponent % &qm != dq
    {
        return false;
    }
    let difference = if prime_p > prime_q {
        &prime_p - &prime_q
    } else {
        &prime_q - &prime_p
    };
    difference.bits() as i64 > (modulus.bits() / 2) as i64 - 100
        && private_exponent.bits() > modulus.bits() / 2
}

pub(super) fn parse(value: &Value) -> Result<OidcJwk, &'static str> {
    let fields = value.as_object().ok_or(INVALID)?;
    let certificates = metadata(fields)?;
    let leaf = certificates
        .first()
        .and_then(|der| x509_parser::parse_x509_certificate(der).ok())
        .map(|(_, certificate)| certificate);
    let mut key: OidcJwk = serde_json::from_value(value.clone()).map_err(|_| INVALID)?;
    key.private_key = fields.get("d").is_some_and(|value| !value.is_null());
    match key.kty.as_str() {
        "RSA" => {
            let n = required_bytes(fields, "n")?;
            let e = required_bytes(fields, "e")?;
            let exponent = oidc_rsa_exponent(&e);
            if key.private_key && !valid_rsa_private(fields, &n, exponent) {
                return Err(INVALID);
            }
            if let Some(certificate) = &leaf
                && !matches!(certificate.public_key().parsed(), Ok(x509_parser::public_key::PublicKey::RSA(rsa))
                    if oidc_integer_bytes(rsa.modulus) == oidc_integer_bytes(&n)
                        && oidc_rsa_exponent(rsa.exponent) == exponent)
            {
                return Err(INVALID);
            }
            key.n = Some(URL_SAFE_NO_PAD.encode(oidc_integer_bytes(&n)));
            key.e = Some(URL_SAFE_NO_PAD.encode(oidc_integer_bytes(&exponent.to_be_bytes())));
        }
        "EC" => {
            let (size, algorithm, curve): (usize, &'static dyn VerificationAlgorithm, &str) =
                match key.crv.as_str() {
                    "P-256" => (
                        32,
                        &signature::ECDSA_P256_SHA256_FIXED,
                        "1.2.840.10045.3.1.7",
                    ),
                    "P-384" => (48, &signature::ECDSA_P384_SHA384_FIXED, "1.3.132.0.34"),
                    "P-521" => (66, &signature::ECDSA_P521_SHA512_FIXED, "1.3.132.0.35"),
                    _ => return Err(INVALID),
                };
            let point = oidc_ec_public_key(&key, size).ok_or(INVALID)?;
            ParsedPublicKey::new(algorithm, &point).map_err(|_| INVALID)?;
            if key.private_key && required_bytes(fields, "d")?.len() != size {
                return Err(INVALID);
            }
            if let Some(certificate) = &leaf {
                let parameters = certificate
                    .public_key()
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|parameters| parameters.as_oid().ok())
                    .map(|oid| oid.to_id_string());
                if parameters.as_deref() != Some(curve)
                    || !matches!(
                        certificate.public_key().parsed(),
                        Ok(x509_parser::public_key::PublicKey::EC(_))
                    )
                    || certificate.public_key().subject_public_key.data.as_ref() != point.as_slice()
                {
                    return Err(INVALID);
                }
            }
        }
        "OKP" if key.crv == "Ed25519" => {
            let public = ed25519_public(&required_bytes(fields, "x")?);
            if let Some(certificate) = &leaf
                && (certificate.public_key().algorithm.algorithm.to_id_string() != "1.3.101.112"
                    || certificate.public_key().subject_public_key.data.as_ref()
                        != public.as_slice())
            {
                return Err(INVALID);
            }
            key.x = URL_SAFE_NO_PAD.encode(public);
        }
        "oct" => {
            required_bytes(fields, "k")?;
            if !certificates.is_empty() {
                return Err(INVALID);
            }
        }
        _ => return Err(INVALID),
    }
    Ok(key)
}
