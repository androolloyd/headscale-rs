// Copyright 2011, 2016 The Go Authors. All rights reserved.
// Selected Go Unicode 15 IDNA Lookup profile; see LICENSE-GO and UPSTREAM.md.

mod bidi;
mod data;
mod nfc;
mod profile;
mod punycode;
mod trie;

pub(super) fn lookup(name: &str) -> Option<String> {
    profile::lookup(name)
}

/// Go's zero-option Punycode profile, used by HTTP/2 authorityAddr. This
/// deliberately performs no Lookup mapping, case folding or NFC validation.
pub(super) fn minimal_ascii(name: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::with_capacity(name.len());
    for (index, label) in name.split(|byte| *byte == b'.').enumerate() {
        if index != 0 {
            output.push(b'.');
        }
        let label = go_runes(label);
        let label = match label.strip_prefix("xn--") {
            Some(encoded) => {
                let decoded = punycode::decode_minimal(encoded)?;
                // A decoded nonempty all-ASCII ACE label is a Punycode error,
                // even though the zero-option profile otherwise validates little.
                if !decoded.is_empty() && decoded.is_ascii() {
                    return None;
                }
                decoded
            }
            None => label,
        };
        if label.is_ascii() {
            output.extend_from_slice(label.as_bytes());
        } else {
            output.extend_from_slice(punycode::encode(&label)?.as_bytes());
        }
    }
    Some(output)
}

// Go range/[]rune replaces one invalid UTF-8 byte at a time. Rust's lossy
// conversion can instead collapse an incomplete multi-byte sequence.
fn go_runes(mut bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len());
    loop {
        match std::str::from_utf8(bytes) {
            Ok(valid) => {
                output.push_str(valid);
                return output;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                output.push_str(std::str::from_utf8(&bytes[..valid]).expect("valid UTF-8 prefix"));
                output.push('\u{fffd}');
                bytes = &bytes[valid + 1..];
            }
        }
    }
}
