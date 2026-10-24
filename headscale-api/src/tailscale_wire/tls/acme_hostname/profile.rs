// Copyright 2016 The Go Authors. All rights reserved.
// Adapted from selected x/net/idna Lookup; see LICENSE-GO-STDLIB.

//! The Go 1.26.9 Lookup profile: Unicode 15, nontransitional, STD3,
//! hyphen/joiner/bidi checks, no leading-dot removal or DNS-length limits.
//! The public hostname boundary needs successful ASCII output only; Go's
//! partially sanitized output and structured error codes are not exposed.

use super::{bidi, data, nfc, punycode, trie};

const VALID: u16 = 0x08;
const MAPPED: u16 = 1;
const DISALLOWED: u16 = 0x40;
const IGNORED: u16 = 0xc0;

#[derive(Clone, Copy)]
struct Info(u16);

impl Info {
    fn mapped(self) -> bool {
        self.0 & 3 != 0
    }

    fn category(self) -> u16 {
        let category = if self.mapped() {
            self.0 & 3
        } else {
            self.0 & 0xf8
        };
        match category {
            // StrictDomainName and nontransitional options are fixed here.
            2 | 0x80 => DISALLOWED,
            3 | 0x18 | 0x28 => VALID,
            value => value,
        }
    }

    fn is_bidi(self, ch: char) -> bool {
        if self.mapped() {
            bidi::is_rtl(ch)
        } else {
            self.0 & 0x1800 == 0x0800
        }
    }

    fn modifier(self) -> bool {
        self.0 & 0x1003 == 0x1000
    }

    fn virama(self) -> bool {
        self.0 & 0x1803 == 0x1800
    }

    fn join_type(self) -> usize {
        if self.mapped() {
            0
        } else {
            usize::from((self.0 >> 8) & 7)
        }
    }

    fn append_mapping(self, ch: char, output: &mut Vec<u8>) {
        let mut index = usize::from(self.0 >> 3);
        if self.0 & 4 == 0 {
            let start = usize::from(data::MAPPING_INDEX[index]);
            let end = usize::from(data::MAPPING_INDEX[index + 1]);
            output.extend_from_slice(&data::MAPPINGS[start..end]);
        } else {
            let mut buf = [0; 4];
            let encoded = ch.encode_utf8(&mut buf).as_bytes();
            output.extend_from_slice(encoded);
            if self.0 & 0xe000 == 0xe000 {
                let last = output.len() - 1;
                output[last] ^= index as u8;
            } else {
                let start = output.len() - usize::from(data::XOR_DATA[index]);
                for byte in &mut output[start..] {
                    index += 1;
                    *byte ^= data::XOR_DATA[index];
                }
            }
        }
    }
}

fn map(input: &str) -> Option<(String, bool)> {
    let mut output = Vec::with_capacity(input.len());
    let mut combined = 0;
    let mut is_bidi = false;
    let mut changed = false;
    for ch in input.chars() {
        let info = Info(trie::idna(ch));
        combined |= info.0;
        is_bidi |= info.is_bidi(ch);
        match info.category() {
            VALID => {
                let mut buf = [0; 4];
                output.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
            DISALLOWED => return None,
            MAPPED => {
                changed = true;
                info.append_mapping(ch, &mut output);
            }
            IGNORED => changed = true,
            // Go's unknown category emits RuneError. Unlike disallowed,
            // this branch itself does not set an error in validateAndMap.
            0 => {
                changed = true;
                output.extend_from_slice("\u{fffd}".as_bytes());
            }
            _ => return None,
        }
    }
    let mapped = String::from_utf8(output).ok()?;
    let mapped = if changed || combined & 0x2000 != 0 {
        nfc::normalize(&mapped)
    } else {
        mapped
    };
    Some((mapped, is_bidi))
}

fn from_punycode(label: &str) -> bool {
    if nfc::normalize(label) != label {
        return false;
    }
    label
        .chars()
        .all(|ch| Info(trie::idna(ch)).category() == VALID)
}

// Start, Virama, Before, BeforeVirama, After, FAIL. Joining types are
// none/L/D/T/R/ZWJ/ZWNJ/Virama, exactly the selected Go table's indices.
const JOIN_STATES: [[usize; 8]; 6] = [
    [0, 2, 2, 0, 0, 5, 5, 1],
    [0, 2, 2, 0, 0, 0, 0, 0],
    [0, 2, 2, 2, 0, 5, 4, 3],
    [0, 2, 2, 2, 0, 0, 0, 0],
    [0, 5, 2, 4, 0, 5, 5, 4],
    [5; 8],
];

fn validate_label(label: &str) -> bool {
    if label.is_empty() {
        return true;
    }
    let bytes = label.as_bytes();
    if (bytes.len() > 4 && bytes[2] == b'-' && bytes[3] == b'-')
        || bytes[0] == b'-'
        || bytes[bytes.len() - 1] == b'-'
    {
        return false;
    }
    if label
        .chars()
        .next()
        .is_some_and(|ch| Info(trie::idna(ch)).modifier())
    {
        return false;
    }
    if !label.contains(['\u{200c}', '\u{200d}']) {
        return true;
    }
    let mut state = 0;
    for ch in label.chars() {
        let info = Info(trie::idna(ch));
        let kind = match ch {
            '\u{200d}' => 5,
            '\u{200c}' => 6,
            _ => info.join_type(),
        };
        state = JOIN_STATES[state][kind];
        if info.virama() {
            state = JOIN_STATES[state][7];
        }
    }
    !matches!(state, 4 | 5)
}

pub(super) fn lookup(input: &str) -> Option<String> {
    let (mapped, mut is_bidi) = map(input)?;
    let mut labels = Vec::new();
    // Empty labels/root dots are accepted because verifyDNSLength is false.
    // Mapping runs over the entire original domain BEFORE ACE recognition.
    for label in mapped.split('.') {
        let value = if let Some(encoded) = label.strip_prefix("xn--") {
            let decoded = punycode::decode(encoded)?;
            is_bidi |= decoded.chars().any(bidi::is_rtl);
            if !from_punycode(&decoded) {
                return None;
            }
            decoded
        } else {
            label.to_owned()
        };
        if !validate_label(&value) {
            return None;
        }
        labels.push(value);
    }
    if is_bidi && !labels.iter().all(|label| bidi::valid(label)) {
        return None;
    }
    for label in &mut labels {
        if !label.is_ascii() {
            *label = punycode::encode(label)?;
        }
    }
    Some(labels.join("."))
}
