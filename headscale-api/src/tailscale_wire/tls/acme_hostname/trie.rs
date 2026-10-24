// Copyright 2011, 2016 The Go Authors. All rights reserved.
// Adapted from selected x/net/idna and x/text Unicode tries; see LICENSE-GO-STDLIB.

use super::data;

fn sparse(offsets: &[u16], values: &[(u16, u8, u8)], block: usize, byte: u8) -> u16 {
    let offset = usize::from(offsets[block]);
    let (stride, count, _) = values[offset];
    let mut lo = offset + 1;
    let mut hi = lo + usize::from(count);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let (value, start, end) = values[mid];
        if start <= byte && byte <= end {
            return value + u16::from(byte - start) * stride;
        }
        if byte < start {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    0
}

// Inputs are Rust scalar values: Go's separate malformed UTF-8 trie paths
// cannot be reached through the existing hostname &str boundary.
pub(super) fn idna(ch: char) -> u16 {
    let mut buf = [0; 4];
    let bytes = ch.encode_utf8(&mut buf).as_bytes();
    if bytes.len() == 1 {
        return data::IDNA_VALUES[usize::from(bytes[0])];
    }
    let mut block = usize::from(data::IDNA_INDEX[usize::from(bytes[0])]);
    for byte in &bytes[1..bytes.len() - 1] {
        block = usize::from(data::IDNA_INDEX[(block << 6) + usize::from(*byte)]);
    }
    let byte = bytes[bytes.len() - 1];
    if block < 133 {
        data::IDNA_VALUES[(block << 6) + usize::from(byte)]
    } else {
        sparse(
            data::IDNA_SPARSE_OFFSET,
            data::IDNA_SPARSE_VALUES,
            block - 133,
            byte,
        )
    }
}

pub(super) fn nfc(ch: char) -> u16 {
    let mut buf = [0; 4];
    let bytes = ch.encode_utf8(&mut buf).as_bytes();
    if bytes.len() == 1 {
        return data::NFC_VALUES[usize::from(bytes[0])];
    }
    let mut block = usize::from(data::NFC_INDEX[usize::from(bytes[0])]);
    for byte in &bytes[1..bytes.len() - 1] {
        block = usize::from(data::NFC_INDEX[(block << 6) + usize::from(*byte)]);
    }
    let byte = bytes[bytes.len() - 1];
    if block < 46 {
        data::NFC_VALUES[(block << 6) + usize::from(byte)]
    } else {
        sparse(
            data::NFC_SPARSE_OFFSET,
            data::NFC_SPARSE_VALUES,
            block - 46,
            byte,
        )
    }
}

pub(super) fn bidi(ch: char) -> u8 {
    let mut buf = [0; 4];
    let bytes = ch.encode_utf8(&mut buf).as_bytes();
    let value = if bytes.len() == 1 {
        data::BIDI_VALUES[usize::from(bytes[0])]
    } else {
        let mut block = usize::from(data::BIDI_INDEX[usize::from(bytes[0])]);
        for byte in &bytes[1..bytes.len() - 1] {
            block = usize::from(data::BIDI_INDEX[(block << 6) + usize::from(*byte)]);
        }
        data::BIDI_VALUES[(block << 6) + usize::from(bytes[bytes.len() - 1])]
    } & 0x0f;
    if value == 14 {
        // bidi.Properties.Class expands the compact Control class using the
        // last UTF-8 byte. Unspecified entries default to bidi.L.
        match bytes[bytes.len() - 1] & 0x0f {
            0xd => 16,
            0xe => 17,
            0xa => 18,
            0xb => 19,
            0xc => 20,
            0x6 => 21,
            0x7 => 22,
            0x8 => 23,
            0x9 => 24,
            _ => 0,
        }
    } else {
        value
    }
}
