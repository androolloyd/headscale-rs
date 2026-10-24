// Copyright 2015 The Go Authors. All rights reserved.
// ACME JWK/JWS representation follows x/crypto/acme/jws.go; see LICENSE-GO.

use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine};
use serde::Serialize;

use super::{native_error, pem};
use crate::{Error, crypto};
use crypto::{KeyPair, ring_like::signature};

mod ec_der;

const EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1];
const RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1];
const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7];
const P384: &[u8] = &[0x2b, 0x81, 4, 0, 0x22];
const P521: &[u8] = &[0x2b, 0x81, 4, 0, 0x23];

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum NativeJwk {
    Ec {
        crv: &'static str,
        kty: &'static str,
        x: String,
        y: String,
    },
    Rsa {
        e: String,
        kty: &'static str,
        n: String,
    },
}

enum Material {
    Ec(crypto::EcdsaKeyPair),
    Rsa(signature::RsaKeyPair),
}

/// Native account signing key. Secret material intentionally has no Debug.
pub struct NativeAccountKey {
    material: Material,
    jwk: NativeJwk,
    algorithm: crate::types::SigningAlgorithm,
    thumb: String,
    cache_pem: String,
}

impl crate::Signer for NativeAccountKey {
    type Signature = Vec<u8>;
    fn header<'n, 'u: 'n, 's: 'u>(
        &'s self,
        nonce: Option<&'n str>,
        url: &'u str,
    ) -> crate::types::Header<'n> {
        crate::types::Header {
            alg: self.algorithm,
            key: crate::types::KeyOrKeyId::NativeKey(self.jwk()),
            nonce,
            url,
        }
    }
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        NativeAccountKey::sign(self, payload)
    }
}

impl NativeAccountKey {
    /// Generate the P-256 account key selected by Go autocert.
    pub fn generate() -> Result<Self, Error> {
        let der = crypto::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &crypto::SystemRandom::new(),
        )
        .map_err(|_| Error::Crypto)?;
        Self::from_der(der.as_ref())
    }

    /// Parse the first PRIVATE PEM block as PKCS#1, PKCS#8 or SEC1.
    pub fn from_pem(raw: &[u8]) -> Result<Self, Error> {
        let (block, _) = pem::decode(raw)
            .ok_or_else(|| native_error("acme/autocert: invalid account key found in cache"))?;
        if !block.label.windows(7).any(|part| part == b"PRIVATE") {
            return Err(native_error(
                "acme/autocert: invalid account key found in cache",
            ));
        }
        Self::from_der(&block.bytes)
    }

    /// Canonical PEM encoding suitable for the Go account-key cache.
    pub fn cache_pem(&self) -> &str {
        &self.cache_pem
    }

    pub(crate) fn thumb(&self) -> &str {
        &self.thumb
    }
    pub(crate) fn jwk(&self) -> NativeJwk {
        self.jwk.clone()
    }
    pub(crate) fn algorithm(&self) -> crate::types::SigningAlgorithm {
        self.algorithm
    }

    pub(crate) fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let rng = crypto::SystemRandom::new();
        match &self.material {
            Material::Ec(key) => key
                .sign(&rng, payload)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| Error::Crypto),
            Material::Rsa(key) => {
                #[cfg(feature = "aws-lc-rs")]
                let length = key.public_modulus_len();
                #[cfg(not(feature = "aws-lc-rs"))]
                let length = key.public().modulus_len();
                let mut output = vec![0; length];
                key.sign(&signature::RSA_PKCS1_SHA256, &rng, payload, &mut output)
                    .map_err(|_| Error::Crypto)?;
                Ok(output)
            }
        }
    }

    fn from_der(raw: &[u8]) -> Result<Self, Error> {
        let mut outer = raw;
        let sequence = take(&mut outer, 0x30)?;
        let mut fields = sequence;
        let _version = take(&mut fields, 2)?;
        match fields.first() {
            Some(2) if outer.is_empty() => Self::rsa(raw, false),
            Some(4) => {
                let (scalar, curve) = ec_der::sec1(raw)?;
                Self::ec(scalar, curve)
            }
            Some(0x30) => {
                let mut algorithm = take(&mut fields, 0x30)?;
                let oid = take(&mut algorithm, 6)?;
                if oid == RSA {
                    return if outer.is_empty() {
                        Self::rsa(raw, true)
                    } else {
                        Err(Error::KeyRejected)
                    };
                }
                if oid != EC {
                    return Err(Error::Unsupported("native account signing key"));
                }
                let (scalar, curve) = ec_der::pkcs8(raw)?;
                Self::ec(scalar, curve)
            }
            _ => Err(Error::KeyRejected),
        }
    }

    fn rsa(raw: &[u8], pkcs8: bool) -> Result<Self, Error> {
        let key = if pkcs8 {
            signature::RsaKeyPair::from_pkcs8(raw)
        } else {
            signature::RsaKeyPair::from_der(raw)
        }
        .map_err(|_| Error::KeyRejected)?;
        let public = key.public_key().as_ref();
        let mut public = public;
        let mut fields = take(&mut public, 0x30)?;
        let n = positive(take(&mut fields, 2)?);
        let e = positive(take(&mut fields, 2)?);
        let jwk = NativeJwk::Rsa {
            e: BASE64_URL_SAFE_NO_PAD.encode(e),
            kty: "RSA",
            n: BASE64_URL_SAFE_NO_PAD.encode(n),
        };
        Self::finish(
            Material::Rsa(key),
            jwk,
            crate::types::SigningAlgorithm::Rs256,
            pem::encode(
                if pkcs8 {
                    "PRIVATE KEY"
                } else {
                    "RSA PRIVATE KEY"
                },
                raw,
            ),
        )
    }

    fn ec(mut scalar: &[u8], curve: &[u8]) -> Result<Self, Error> {
        let (algorithm, name, width, signing) = if curve == P256 {
            (
                crate::types::SigningAlgorithm::Es256,
                "P-256",
                32,
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            )
        } else if curve == P384 {
            (
                crate::types::SigningAlgorithm::Es384,
                "P-384",
                48,
                &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            )
        } else if curve == P521 {
            #[cfg(feature = "aws-lc-rs")]
            {
                (
                    crate::types::SigningAlgorithm::Es512,
                    "P-521",
                    66,
                    &signature::ECDSA_P521_SHA512_FIXED_SIGNING,
                )
            }
            #[cfg(not(feature = "aws-lc-rs"))]
            {
                return Err(Error::Unsupported(
                    "P-521 account key with selected crypto provider",
                ));
            }
        } else {
            return Err(Error::Unsupported("native account EC curve"));
        };
        // Go's SEC1 parser tolerates extra zero padding and short scalars,
        // then validates the normalized scalar and derives its public point.
        while scalar.len() > width {
            if scalar[0] != 0 {
                return Err(Error::KeyRejected);
            }
            scalar = &scalar[1..];
        }
        let mut normalized = vec![0; width];
        normalized[width - scalar.len()..].copy_from_slice(scalar);
        let scalar = normalized.as_slice();
        let sec1 = wrap(
            0x30,
            &[wrap(2, &[1]), wrap(4, scalar), wrap(0xa0, &wrap(6, curve))].concat(),
        );
        let pkcs8 = wrap(
            0x30,
            &[
                wrap(2, &[0]),
                wrap(0x30, &[wrap(6, EC), wrap(6, curve)].concat()),
                wrap(4, &sec1),
            ]
            .concat(),
        );
        #[cfg(feature = "aws-lc-rs")]
        let key = crypto::EcdsaKeyPair::from_pkcs8(signing, &pkcs8);
        #[cfg(not(feature = "aws-lc-rs"))]
        let key = crypto::EcdsaKeyPair::from_pkcs8(signing, &pkcs8, &crypto::SystemRandom::new());
        let key = key.map_err(|_| Error::KeyRejected)?;
        let point = key.public_key().as_ref();
        if point.len() != 1 + 2 * width || point[0] != 4 {
            return Err(Error::KeyRejected);
        }
        let jwk = NativeJwk::Ec {
            crv: name,
            kty: "EC",
            x: BASE64_URL_SAFE_NO_PAD.encode(&point[1..1 + width]),
            y: BASE64_URL_SAFE_NO_PAD.encode(&point[1 + width..]),
        };
        let cache_der = wrap(
            0x30,
            &[
                wrap(2, &[1]),
                wrap(4, scalar),
                wrap(0xa0, &wrap(6, curve)),
                wrap(0xa1, &wrap(3, &[&[0], point].concat())),
            ]
            .concat(),
        );
        // ec_der checked the original ASN.1 fields before reconstruction.
        // As in Go, a structurally valid embedded public bit string is ignored;
        // the provider validates the normalized scalar and derives the point.
        Self::finish(
            Material::Ec(key),
            jwk,
            algorithm,
            pem::encode("EC PRIVATE KEY", &cache_der),
        )
    }

    fn finish(
        material: Material,
        jwk: NativeJwk,
        algorithm: crate::types::SigningAlgorithm,
        cache_pem: String,
    ) -> Result<Self, Error> {
        let thumb = BASE64_URL_SAFE_NO_PAD
            .encode(crypto::digest(&crypto::SHA256, &serde_json::to_vec(&jwk)?).as_ref());
        Ok(Self {
            material,
            jwk,
            algorithm,
            thumb,
            cache_pem,
        })
    }
}

fn positive(mut raw: &[u8]) -> &[u8] {
    while raw.len() > 1 && raw[0] == 0 {
        raw = &raw[1..];
    }
    raw
}

fn take<'a>(raw: &mut &'a [u8], tag: u8) -> Result<&'a [u8], Error> {
    if raw.first() != Some(&tag) {
        return Err(Error::KeyRejected);
    }
    let first = *raw.get(1).ok_or(Error::KeyRejected)?;
    let (header, length) = if first < 128 {
        (2, usize::from(first))
    } else {
        let count = usize::from(first & 127);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err(Error::KeyRejected);
        }
        let digits = raw.get(2..2 + count).ok_or(Error::KeyRejected)?;
        if digits[0] == 0 {
            return Err(Error::KeyRejected);
        }
        let mut length = 0usize;
        for digit in digits {
            length = length
                .checked_mul(256)
                .and_then(|n| n.checked_add(usize::from(*digit)))
                .ok_or(Error::KeyRejected)?;
        }
        if length < 128 {
            return Err(Error::KeyRejected);
        }
        (2 + count, length)
    };
    let end = header.checked_add(length).ok_or(Error::KeyRejected)?;
    let value = raw.get(header..end).ok_or(Error::KeyRejected)?;
    *raw = &raw[end..];
    Ok(value)
}

fn wrap(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if value.len() < 128 {
        output.push(value.len() as u8);
    } else {
        let bytes = value.len().to_be_bytes();
        let start = bytes.iter().position(|b| *b != 0).unwrap();
        output.push(0x80 | (bytes.len() - start) as u8);
        output.extend_from_slice(&bytes[start..]);
    }
    output.extend_from_slice(value);
    output
}
