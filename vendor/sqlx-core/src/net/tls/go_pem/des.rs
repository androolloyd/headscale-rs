// Copyright 2010, 2011 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// crypto/des and crypto/x509/pem_decrypt.go from Go 1.26.9.
// See LICENSE-GO-STDLIB and UPSTREAM.md.

//! DES/TDEA for the explicit local legacy PEM reader. Go accepts every
//! correctly sized key, including weak keys and equal TDEA subkeys. Keep
//! this private to PEM decryption; it is not a TLS or general cipher API.

use crate::error::Error;

mod tables;
use tables::{
    EXPANSION, FINAL, INITIAL, KEY_CHOICE_1, KEY_CHOICE_2, KEY_ROTATIONS, PERMUTATION, S_BOXES,
};

struct Des {
    subkeys: [u64; 16],
}

// Go's permutation tables name source bits from the least significant bit.
fn permute(input: u64, table: &[u8]) -> u64 {
    table
        .iter()
        .fold(0, |output, &bit| (output << 1) | ((input >> bit) & 1))
}

impl Des {
    fn new(key: &[u8]) -> Self {
        let selected = permute(
            u64::from_be_bytes(key.try_into().expect("DES key size")),
            &KEY_CHOICE_1,
        );
        let mut left = (selected >> 28) as u32;
        let mut right = (selected & 0x0fff_ffff) as u32;
        let mut subkeys = [0; 16];
        for (round, rotation) in KEY_ROTATIONS.into_iter().enumerate() {
            left = ((left << rotation) | (left >> (28 - rotation))) & 0x0fff_ffff;
            right = ((right << rotation) | (right >> (28 - rotation))) & 0x0fff_ffff;
            subkeys[round] = permute(((left as u64) << 28) | right as u64, &KEY_CHOICE_2);
        }
        Self { subkeys }
    }

    fn crypt(&self, block: u64, decrypt: bool) -> u64 {
        let initial = permute(block, &INITIAL);
        let mut left = (initial >> 32) as u32;
        let mut right = initial as u32;
        for round in 0..16 {
            let key = self.subkeys[if decrypt { 15 - round } else { round }];
            let expanded = permute(right as u64, &EXPANSION) ^ key;
            let mut substituted = 0_u32;
            for (index, s_box) in S_BOXES.iter().enumerate() {
                let six_bits = ((expanded >> (42 - 6 * index)) & 0x3f) as usize;
                let row = ((six_bits & 0x20) >> 4) | (six_bits & 1);
                let column = (six_bits >> 1) & 0x0f;
                substituted = (substituted << 4) | u32::from(s_box[row][column]);
            }
            let next = left ^ permute(substituted as u64, &PERMUTATION) as u32;
            left = right;
            right = next;
        }
        permute(((right as u64) << 32) | left as u64, &FINAL)
    }
}

pub(super) fn decrypt(
    triple: bool,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if key.len() != if triple { 24 } else { 8 } {
        return Err(Error::tls(format!(
            "crypto/des: invalid key size {}",
            key.len()
        )));
    }
    if iv.len() != 8 {
        return Err(Error::tls("x509: incorrect IV size"));
    }
    if ciphertext.len() % 8 != 0 {
        return Err(Error::tls(
            "x509: encrypted PEM data is not a multiple of the block size",
        ));
    }
    if ciphertext.is_empty() {
        return Err(Error::tls("x509: invalid padding"));
    }

    let first = Des::new(&key[..8]);
    let remaining = triple.then(|| (Des::new(&key[8..16]), Des::new(&key[16..])));
    let mut previous = u64::from_be_bytes(iv.try_into().expect("DES IV size"));
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for block in ciphertext.chunks_exact(8) {
        let block = u64::from_be_bytes(block.try_into().expect("DES block size"));
        // EDE encryption is E(K3, D(K2, E(K1, plaintext))).
        let decrypted = match &remaining {
            Some((second, third)) => {
                first.crypt(second.crypt(third.crypt(block, true), false), true)
            }
            None => first.crypt(block, true),
        };
        plaintext.extend_from_slice(&(decrypted ^ previous).to_be_bytes());
        previous = block;
    }
    super::unpad(plaintext, 8)
}
