// Copyright 2011 The Go Authors. All rights reserved.
// Copyright (c) 2020 Vincent Prouillet
// SPDX-License-Identifier: BSD-3-Clause AND MIT

//! Go bcrypt's byte input, parsing and comparison around the existing Rust
//! bcrypt/Blowfish backend. Raw SQL hashes need not be UTF-8 strings.

use subtle::ConstantTimeEq;

const ALPHABET: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const TOO_SHORT: &str = "crypto/bcrypt: hashedSecret too short to be a bcrypted password";

fn invalid_cost(cost: i32) -> String {
    format!("crypto/bcrypt: cost {cost} is outside allowed inclusive range 4..31")
}

fn quoted_cost(raw: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(raw) {
        return headscale_api_acl::go_strconv::quote(text);
    }
    // Atoi receives exactly two bytes. Any valid multi-byte rune would have
    // been handled above; otherwise quote each invalid byte as Go does.
    let mut output = String::from("\"");
    for byte in raw {
        if byte.is_ascii() {
            let quoted = headscale_api_acl::go_strconv::quote(&char::from(*byte).to_string());
            output.push_str(&quoted[1..quoted.len() - 1]);
        } else {
            use std::fmt::Write as _;
            let _ = write!(output, "\\x{byte:02x}");
        }
    }
    output.push('"');
    output
}

fn cost(raw: &[u8]) -> Result<u32, String> {
    let value = match raw {
        [left, right] if left.is_ascii_digit() && right.is_ascii_digit() => {
            i32::from(left - b'0') * 10 + i32::from(right - b'0')
        }
        [b'+', right] if right.is_ascii_digit() => i32::from(right - b'0'),
        [b'-', right] if right.is_ascii_digit() => -i32::from(right - b'0'),
        _ => {
            return Err(format!(
                "strconv.Atoi: parsing {}: invalid syntax",
                quoted_cost(raw)
            ));
        }
    };
    if !(4..=31).contains(&value) {
        return Err(invalid_cost(value));
    }
    Ok(value as u32)
}

fn base64_error(index: usize) -> String {
    format!("illegal base64 data at input byte {index}")
}

/// encoding/base64's padded, non-strict decodeQuantum. CR/LF count toward
/// error offsets; unused trailing bits are accepted, as in Go's NewEncoding.
fn decode_salt(raw: &[u8]) -> Result<Vec<u8>, String> {
    let mut source = raw.to_vec();
    source.resize(source.len() + 4 - raw.len() % 4, b'=');
    let mut index = 0;
    let mut output = Vec::with_capacity(16);
    loop {
        let mut digits = [0u8; 4];
        let mut count = 0;
        let mut padded = false;
        while count < 4 {
            if index == source.len() {
                return if count == 0 {
                    Ok(output)
                } else {
                    Err(base64_error(index - count))
                };
            }
            let byte = source[index];
            index += 1;
            if let Some(value) = ALPHABET.iter().position(|candidate| *candidate == byte) {
                digits[count] = value as u8;
                count += 1;
                continue;
            }
            if matches!(byte, b'\r' | b'\n') {
                continue;
            }
            if byte != b'=' || count < 2 {
                return Err(base64_error(index - 1));
            }
            if count == 2 {
                while index < source.len() && matches!(source[index], b'\r' | b'\n') {
                    index += 1;
                }
                if index == source.len() {
                    return Err(base64_error(source.len()));
                }
                if source[index] != b'=' {
                    return Err(base64_error(index - 1));
                }
                index += 1;
            }
            while index < source.len() && matches!(source[index], b'\r' | b'\n') {
                index += 1;
            }
            if index < source.len() {
                return Err(base64_error(index));
            }
            padded = true;
            break;
        }
        let value = (u32::from(digits[0]) << 18)
            | (u32::from(digits[1]) << 12)
            | (u32::from(digits[2]) << 6)
            | u32::from(digits[3]);
        output.push((value >> 16) as u8);
        if count >= 3 {
            output.push((value >> 8) as u8);
        }
        if count == 4 {
            output.push(value as u8);
        }
        if padded {
            return Ok(output);
        }
    }
}

fn encode_hash(raw: &[u8; 24]) -> [u8; 31] {
    let mut output = [0; 31];
    let mut at = 0;
    for chunk in raw[..23].chunks(3) {
        let value = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for shift in [18, 12, 6, 0].into_iter().take(chunk.len() + 1) {
            output[at] = ALPHABET[((value >> shift) & 63) as usize];
            at += 1;
        }
    }
    output
}

fn crypt(password: &[u8], salt: &[u8], cost: u32) -> [u8; 24] {
    let mut key = password[..password.len().min(72)].to_vec();
    if key.len() < 72 {
        key.push(0);
    }
    if let Ok(salt) = <[u8; 16]>::try_from(salt) {
        return bcrypt::bcrypt(cost, salt, &key);
    }
    // Go's newline-tolerant salt decoder can produce a shorter nonempty salt.
    // Use the same backend's bcrypt key-schedule primitives for that shape.
    let mut cipher = blowfish::Blowfish::bc_init_state();
    cipher.salted_expand_key(salt, &key);
    for _ in 0..(1u64 << cost) {
        cipher.bc_expand_key(&key);
        cipher.bc_expand_key(salt);
    }
    let mut output = *b"OrpheanBeholderScryDoubt";
    for block in output.as_chunks_mut::<8>().0 {
        let mut words = [
            u32::from_be_bytes(block[..4].try_into().expect("four-byte word")),
            u32::from_be_bytes(block[4..].try_into().expect("four-byte word")),
        ];
        for _ in 0..64 {
            words = cipher.bc_encrypt(words);
        }
        block[..4].copy_from_slice(&words[0].to_be_bytes());
        block[4..].copy_from_slice(&words[1].to_be_bytes());
    }
    output
}

pub(crate) fn verify(password: &[u8], encoded: &[u8]) -> Result<bool, String> {
    if encoded.len() < 59 {
        return Err(TOO_SHORT.into());
    }
    if encoded[0] != b'$' {
        return Err(format!(
            "crypto/bcrypt: bcrypt hashes must start with '$', but hashedSecret started with '{}'",
            char::from(encoded[0])
        ));
    }
    if encoded[1] > b'2' {
        return Err(format!(
            "crypto/bcrypt: bcrypt algorithm version '{}' requested is newer than current version '2'",
            char::from(encoded[1])
        ));
    }
    let version_len = if encoded[2] == b'$' { 3 } else { 4 };
    let cost = cost(&encoded[version_len..version_len + 2])?;
    let salt_at = version_len + 3;
    let salt = decode_salt(&encoded[salt_at..salt_at + 22])?;
    // A successful padded decode of this field always yields a nonempty salt.
    let actual = encode_hash(&crypt(password, &salt, cost));
    let mut expected = [0; 31];
    let hash = &encoded[salt_at + 22..];
    let count = hash.len().min(expected.len());
    expected[..count].copy_from_slice(&hash[..count]);
    // Go's Hash copies into a fixed-size buffer: extra suffix bytes are ignored
    // and a short final hash is zero-filled before constant-time comparison.
    Ok(bool::from(actual[..].ct_eq(&expected[..])))
}

pub(crate) fn hash(password: &[u8], requested_cost: u32) -> Result<String, String> {
    if password.len() > 72 {
        return Err("bcrypt: password length exceeds 72 bytes".into());
    }
    let cost = if requested_cost < 4 {
        10
    } else {
        requested_cost
    };
    if cost > 31 {
        return Err(format!(
            "crypto/bcrypt: cost {cost} is outside allowed inclusive range 4..31"
        ));
    }
    bcrypt::hash_with_result(password, cost)
        .map(|parts| parts.format_for_version(bcrypt::Version::TwoA))
        .map_err(|error| error.to_string())
}
