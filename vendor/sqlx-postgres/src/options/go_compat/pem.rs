//! PEM loading from Go 1.26 encoding/pem and crypto/x509, and pgx v5.10.0.
//! Copyright 2009, 2012 The Go Authors. All rights reserved.
//! BSD-3-Clause license: LICENSE-GO-STDLIB in this vendor directory.

use std::collections::BTreeMap;

use base64::Engine as _;
use md5::{Digest, Md5};

use super::config_error;
use sqlx_core::error::Error;

struct Block {
    label: Vec<u8>,
    headers: BTreeMap<Vec<u8>, Vec<u8>>,
    data: Vec<u8>,
}

fn line(input: &[u8]) -> (&[u8], usize) {
    let end = memchr::memchr(b'\n', input).unwrap_or(input.len());
    let consumed = if end < input.len() { end + 1 } else { end };
    let mut value = &input[..end];
    if end < input.len() && value.last() == Some(&b'\r') {
        value = &value[..value.len() - 1];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    (value, consumed)
}

fn trim_space(mut input: &[u8]) -> &[u8] {
    // Go bytes.TrimSpace still trims valid boundary runes when the interior
    // contains invalid UTF-8. Invalid boundary bytes themselves are retained.
    loop {
        let width = input.first().map_or(0, |byte| match *byte {
            0..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 0,
        });
        let whitespace = width > 0
            && input.get(..width).is_some_and(|bytes| {
                std::str::from_utf8(bytes)
                    .ok()
                    .and_then(|text| text.chars().next())
                    .is_some_and(char::is_whitespace)
            });
        if !whitespace {
            break;
        }
        input = &input[width..];
    }
    loop {
        let mut width = 0;
        for candidate in 1..=4.min(input.len()) {
            let bytes = &input[input.len() - candidate..];
            if let Ok(text) = std::str::from_utf8(bytes) {
                if text.chars().count() == 1 && text.chars().next().is_some_and(char::is_whitespace)
                {
                    width = candidate;
                    break;
                }
            }
        }
        if width == 0 {
            break;
        }
        input = &input[..input.len() - width];
    }
    input
}

fn decode(input: &[u8]) -> Option<(Block, &[u8])> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const END: &[u8] = b"\n-----END ";
    let engine = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    );
    let mut search = 0;
    loop {
        let end = search + memchr::memmem::find(input.get(search..)?, END)?;
        let end_label = end + END.len();
        let begin = search
            + match memchr::memmem::rfind(&input[search..end], BEGIN) {
                Some(begin) => begin,
                None => {
                    search = end_label;
                    continue;
                }
            };
        let previous_search = search;
        search = end_label;
        if begin > previous_search && input[begin - 1] != b'\n' {
            continue;
        }
        let (type_line, consumed) = line(&input[begin + BEGIN.len()..]);
        let Some(label) = type_line.strip_suffix(b"-----") else {
            continue;
        };
        let mut position = begin + BEGIN.len() + consumed;
        let mut headers = BTreeMap::new();
        loop {
            let remaining = input.get(position..)?;
            if remaining.is_empty() {
                return None;
            }
            let (header, consumed) = line(remaining);
            let Some(colon) = memchr::memchr(b':', header) else {
                break;
            };
            headers.insert(
                trim_space(&header[..colon]).to_vec(),
                trim_space(&header[colon + 1..]).to_vec(),
            );
            position += consumed;
        }
        if position > end_label {
            return None;
        }
        if !headers.is_empty() && position > end {
            continue;
        }
        let trailer_len = label.len().checked_add(5)?;
        let Some(trailer) = input.get(end_label..end_label.checked_add(trailer_len)?) else {
            continue;
        };
        if !trailer.starts_with(label) || !trailer.ends_with(b"-----") {
            continue;
        }
        let (tail, _) = line(&input[end_label + trailer_len..]);
        if !tail.is_empty() {
            continue;
        }
        let encoded: Vec<u8> = if position < end {
            input[position..end]
                .iter()
                .copied()
                .filter(|byte| !matches!(*byte, b' ' | b'\t' | b'\r' | b'\n'))
                .collect()
        } else {
            Vec::new()
        };
        let Ok(data) = engine.decode(encoded) else {
            continue;
        };
        let (_, end_consumed) = line(&input[end + 1..]);
        let remainder = &input[end + 1 + end_consumed..];
        return Some((
            Block {
                label: label.to_vec(),
                headers,
                data,
            },
            remainder,
        ));
    }
}

fn encode(label: &[u8], data: &[u8], output: &mut Vec<u8>) {
    output.extend_from_slice(b"-----BEGIN ");
    output.extend_from_slice(label);
    output.extend_from_slice(b"-----\n");
    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
    for line in encoded.as_bytes().chunks(64) {
        output.extend_from_slice(line);
        output.push(b'\n');
    }
    output.extend_from_slice(b"-----END ");
    output.extend_from_slice(label);
    output.extend_from_slice(b"-----\n");
}

pub(super) fn certificates(mut input: &[u8], allow_headers: bool) -> Vec<u8> {
    let mut output = Vec::new();
    while let Some((block, remainder)) = decode(input) {
        if block.label == b"CERTIFICATE" && (allow_headers || block.headers.is_empty()) {
            encode(b"CERTIFICATE", &block.data, &mut output);
        }
        input = remainder;
    }
    output
}

pub(super) struct Key {
    label: Vec<u8>,
    data: Vec<u8>,
}

impl Key {
    pub(super) fn into_der(self) -> Result<Vec<u8>, Error> {
        if self.label != b"PRIVATE KEY" && !self.label.ends_with(b" PRIVATE KEY") {
            return Err(config_error("Postgres key PEM block is not a private key"));
        }
        Ok(self.data)
    }
}

pub(super) fn key(input: &[u8], password: &str) -> Result<Key, Error> {
    let (mut block, _) = decode(input).ok_or_else(|| config_error("failed to decode sslkey"))?;
    if let Some(dek) = block.headers.get(b"DEK-Info".as_slice()) {
        if password.is_empty() {
            return Err(config_error("unable to find sslpassword"));
        }
        let comma = memchr::memchr(b',', dek)
            .ok_or_else(|| decrypt_error("x509: malformed DEK-Info header"))?;
        let mode = std::str::from_utf8(&dek[..comma])
            .map_err(|_| decrypt_error("x509: unknown encryption mode"))?;
        let (key_size, block_size) = match mode {
            "DES-CBC" => (8, 8),
            "DES-EDE3-CBC" => (24, 8),
            "AES-128-CBC" => (16, 16),
            "AES-192-CBC" => (24, 16),
            "AES-256-CBC" => (32, 16),
            _ => return Err(decrypt_error("x509: unknown encryption mode")),
        };
        let iv = decode_iv(&dek[comma + 1..])?;
        if iv.len() != block_size {
            return Err(decrypt_error("x509: incorrect IV size"));
        }
        let mut derived = Vec::with_capacity(key_size);
        let mut previous = Vec::new();
        while derived.len() < key_size {
            let mut digest = Md5::new();
            digest.update(&previous);
            digest.update(password.as_bytes());
            digest.update(&iv[..8]);
            previous = digest.finalize().to_vec();
            derived.extend_from_slice(&previous);
        }
        derived.truncate(key_size);
        block.data =
            sqlx_core::net::tls::decrypt_headscale_go_pem(mode, &derived, &iv, &block.data)
                .map_err(|error| match error {
                    Error::Tls(source) => decrypt_error(source),
                    error => decrypt_error(error),
                })?;
        // pgx relabels decrypted blocks; tls.X509KeyPair then detects the
        // actual DER key format independently of this label.
        block.label = b"RSA PRIVATE KEY".to_vec();
    }
    Ok(Key {
        label: block.label,
        data: block.data,
    })
}

fn decrypt_error(message: impl std::fmt::Display) -> Error {
    Error::Configuration(format!("unable to decrypt key: {message}").into())
}

fn iv_nibble(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => {
            // Go encoding/hex's %#U formats the offending byte as a rune.
            // fmt appends the literal printable rune, including quote/slash.
            let printable =
                (0x20..=0x7e).contains(&byte) || ((0xa1..=0xff).contains(&byte) && byte != 0xad);
            let suffix = if printable {
                format!(" '{}'", char::from(byte))
            } else {
                String::new()
            };
            Err(decrypt_error(format!(
                "encoding/hex: invalid byte: U+{byte:04X}{suffix}"
            )))
        }
    }
}

fn decode_iv(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut output = Vec::with_capacity(input.len() / 2);
    let mut pairs = input.chunks_exact(2);
    for pair in &mut pairs {
        // An invalid byte wins over the later odd-length error.
        let high = iv_nibble(pair[0])?;
        let low = iv_nibble(pair[1])?;
        output.push((high << 4) | low);
    }
    if let Some(&last) = pairs.remainder().first() {
        iv_nibble(last)?;
        return Err(decrypt_error("encoding/hex: odd length hex string"));
    }
    Ok(output)
}
