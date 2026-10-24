// Copyright 2009, 2010, 2011 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// crypto/x509/pem_decrypt.go; see LICENSE-GO-STDLIB and UPSTREAM.md.

//! Legacy file decryption for the explicit native pgx configuration bridge.

use aws_lc_rs::cipher::{
    DecryptionContext, PaddedBlockDecryptingKey, UnboundCipherKey, AES_128, AES_192, AES_256,
};
use aws_lc_rs::iv::FixedLength;

use crate::error::Error;

mod des;

// The legacy algorithms are accepted solely for existing local PEM inputs,
// matching Go's RFC 1423 loader. They never enter TLS cipher negotiation.
pub(super) fn decrypt(
    algorithm: &str,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if algorithm == "DES-CBC" || algorithm == "DES-EDE3-CBC" {
        return des::decrypt(algorithm == "DES-EDE3-CBC", key, iv, ciphertext);
    }
    let (algorithm, key_size) = match algorithm {
        "AES-128-CBC" => (&AES_128, 16),
        "AES-192-CBC" => (&AES_192, 24),
        "AES-256-CBC" => (&AES_256, 32),
        _ => return Err(Error::tls("x509: unknown encryption mode")),
    };
    let context = match iv.len() {
        16 => DecryptionContext::Iv128(FixedLength::<16>::try_from(iv).map_err(Error::tls)?),
        _ => return Err(Error::tls("x509: incorrect IV size")),
    };
    if key.len() != key_size {
        return Err(Error::tls(format!(
            "crypto/aes: invalid key size {}",
            key.len()
        )));
    }
    if ciphertext.len() % 16 != 0 {
        return Err(Error::tls(
            "x509: encrypted PEM data is not a multiple of the block size",
        ));
    }
    if ciphertext.is_empty() {
        return Err(Error::tls("x509: invalid padding"));
    }
    let key = UnboundCipherKey::new(algorithm, key).map_err(Error::tls)?;
    let cipher = PaddedBlockDecryptingKey::cbc_pkcs7(key).map_err(Error::tls)?;
    let mut data = ciphertext.to_vec();
    let length = cipher
        .decrypt(&mut data, context)
        .map_err(|_| Error::tls("x509: decryption password incorrect"))?
        .len();
    data.truncate(length);
    Ok(data)
}

// RFC 1423 padding is unauthenticated. Preserve Go's padding decision and
// error; this operation is reachable only through configured local PEM data.
fn unpad(mut plaintext: Vec<u8>, block_size: usize) -> Result<Vec<u8>, Error> {
    let padding = usize::from(
        *plaintext
            .last()
            .ok_or_else(|| Error::tls("x509: invalid padding"))?,
    );
    if padding == 0
        || padding > block_size
        || padding > plaintext.len()
        || plaintext[plaintext.len() - padding..]
            .iter()
            .any(|&byte| usize::from(byte) != padding)
    {
        return Err(Error::tls("x509: decryption password incorrect"));
    }
    plaintext.truncate(plaintext.len() - padding);
    Ok(plaintext)
}
