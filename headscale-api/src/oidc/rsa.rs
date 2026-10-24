//! Public RSA verification for pinned Go JOSE compatibility.
//!
//! aws-lc-rs' safe presets require >=2048 bits for most algorithms and a
//! digest-length PSS salt. Go 1.26/go-jose 4.1.4 accept >=1024 bits and detect
//! PSS salt length. Keep this FFI exception private, own every allocation,
//! and delegate all signature/padding checks to the existing AWS-LC backend.
//! No private key, signing, decryption, raw modular arithmetic, or pointer is
//! exposed. AWS-LC's 16384-bit maximum remains an explicit resource boundary.

#![allow(unsafe_code)]

use std::ptr::{self, NonNull};

use aws_lc_rs::digest;
use aws_lc_sys as ffi;

pub(super) const MAX_MODULUS_BYTES: usize = 16384 / 8;

struct BigNumber(NonNull<ffi::BIGNUM>);

impl BigNumber {
    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        // SAFETY: AWS-LC reads exactly this live slice and allocates a new BN
        // because the destination is null. NonNull rejects allocation failure.
        NonNull::new(unsafe { ffi::BN_bin2bn(bytes.as_ptr(), bytes.len(), ptr::null_mut()) })
            .map(Self)
    }
}

impl Drop for BigNumber {
    fn drop(&mut self) {
        // SAFETY: This wrapper uniquely owns the BN allocated above. PublicKey
        // construction copies the components rather than taking ownership.
        unsafe { ffi::BN_free(self.0.as_ptr()) };
    }
}

struct PublicKey(NonNull<ffi::RSA>);

impl PublicKey {
    fn new(n: &BigNumber, e: &BigNumber) -> Option<Self> {
        // SAFETY: Both BNs are live and immutable for this call. AWS-LC clones
        // them into a separately allocated RSA object; null signals failure.
        NonNull::new(unsafe { ffi::RSA_new_public_key(n.0.as_ptr(), e.0.as_ptr()) }).map(Self)
    }
}

impl Drop for PublicKey {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the sole reference to the RSA allocation.
        unsafe { ffi::RSA_free(self.0.as_ptr()) };
    }
}

pub(super) fn verify(alg: &str, n: &[u8], e: &[u8], input: &[u8], signature: &[u8]) -> bool {
    let n = super::oidc_integer_bytes(n);
    let Some(first) = n.first() else {
        return false;
    };
    let bits = n.len().saturating_mul(8) - first.leading_zeros() as usize;
    let exponent = super::oidc_rsa_exponent(e);
    // Go's default rsa1024min setting and public-key validation. The upper
    // bound is AWS-LC's own resource limit, not a claimed Go compatibility rule.
    if !(1024..=MAX_MODULUS_BYTES * 8).contains(&bits)
        || n.last().is_none_or(|last| last & 1 == 0)
        || !(3..=i64::from(i32::MAX)).contains(&exponent)
        || exponent & 1 == 0
        || signature.len() != n.len()
    {
        return false;
    }
    let (hash, nid, pss) = match alg {
        "RS256" => (&digest::SHA256, ffi::NID_sha256, false),
        "RS384" => (&digest::SHA384, ffi::NID_sha384, false),
        "RS512" => (&digest::SHA512, ffi::NID_sha512, false),
        "PS256" => (&digest::SHA256, ffi::NID_sha256, true),
        "PS384" => (&digest::SHA384, ffi::NID_sha384, true),
        "PS512" => (&digest::SHA512, ffi::NID_sha512, true),
        _ => return false,
    };
    let Some(n) = BigNumber::from_bytes(n) else {
        return false;
    };
    let Some(e) = BigNumber::from_bytes(super::oidc_integer_bytes(&exponent.to_be_bytes())) else {
        return false;
    };
    let Some(key) = PublicKey::new(&n, &e) else {
        return false;
    };
    let hashed = digest::digest(hash, input);
    let hashed = hashed.as_ref();
    // SAFETY: The exclusively owned key is live throughout verification.
    // Input and digest pointer/length pairs refer to live slices. The digest
    // was computed above with the selected hash; EVP_sha* return static
    // descriptors. Neither verifier retains any of these pointers.
    unsafe {
        if pss {
            let md = match nid {
                ffi::NID_sha256 => ffi::EVP_sha256(),
                ffi::NID_sha384 => ffi::EVP_sha384(),
                ffi::NID_sha512 => ffi::EVP_sha512(),
                _ => return false,
            };
            // -2 detects any valid salt length, matching VerifyPSS(..., nil).
            ffi::RSA_verify_pss_mgf1(
                key.0.as_ptr(),
                hashed.as_ptr(),
                hashed.len(),
                md,
                md,
                -2,
                signature.as_ptr(),
                signature.len(),
            ) == 1
        } else {
            ffi::RSA_verify(
                nid,
                hashed.as_ptr(),
                hashed.len(),
                signature.as_ptr(),
                signature.len(),
                key.0.as_ptr(),
            ) == 1
        }
    }
}
