// Copyright 2009 The Go Authors. All rights reserved.
// Adapted from Go 1.26.9 encoding/pem.Decode; see LICENSE-GO and LICENSE-GO-NOTICE.

use base64::{
    Engine, alphabet,
    engine::{GeneralPurpose, GeneralPurposeConfig},
};

pub(super) struct Block<'a> {
    pub label: &'a [u8],
    pub bytes: Vec<u8>,
}

fn find(bytes: &[u8], needle: &[u8]) -> Option<usize> {
    bytes.windows(needle.len()).position(|part| part == needle)
}

fn line(bytes: &[u8]) -> (&[u8], &[u8], usize) {
    let (mut end, consumed) = match bytes.iter().position(|byte| *byte == b'\n') {
        Some(at) => (at, at + 1),
        None => (bytes.len(), bytes.len()),
    };
    if consumed > end && end > 0 && bytes[end - 1] == b'\r' {
        end -= 1;
    }
    while end > 0 && matches!(bytes[end - 1], b' ' | b'\t') {
        end -= 1;
    }
    (&bytes[..end], &bytes[consumed..], consumed)
}

pub(super) fn decode(data: &[u8]) -> Option<(Block<'_>, &[u8])> {
    const BEGIN: &[u8] = b"-----BEGIN ";
    const END: &[u8] = b"\n-----END ";
    const DASHES: &[u8] = b"-----";
    let mut rest = data;
    let mut trailer = 0_isize;
    loop {
        rest = rest.get(usize::try_from(trailer).ok()?..)?;
        let mut end = isize::try_from(find(rest, END)?).ok()?;
        trailer = end + END.len() as isize;
        let Some(begin) = rest[..end as usize]
            .windows(BEGIN.len())
            .rposition(|part| part == BEGIN)
        else {
            continue;
        };
        if begin > 0 && rest[begin - 1] != b'\n' {
            continue;
        }
        let skip = begin + BEGIN.len();
        rest = &rest[skip..];
        end -= skip as isize;
        trailer -= skip as isize;
        let (label_line, next, consumed) = line(rest);
        rest = next;
        end -= consumed as isize;
        trailer -= consumed as isize;
        let Some(label) = label_line.strip_suffix(DASHES) else {
            continue;
        };
        let mut headers = false;
        loop {
            if rest.is_empty() {
                return None;
            }
            let (header, next, consumed) = line(rest);
            if !header.contains(&b':') {
                break;
            }
            headers = true;
            rest = next;
            end -= consumed as isize;
            trailer -= consumed as isize;
        }
        if headers && end < 0 {
            continue;
        }
        let Some(end_trailer) = usize::try_from(trailer).ok().and_then(|at| rest.get(at..)) else {
            return None;
        };
        let trailer_len = label.len().checked_add(DASHES.len())?;
        if end_trailer.len() < trailer_len {
            continue;
        }
        if !end_trailer[..trailer_len].starts_with(label)
            || !end_trailer[..trailer_len].ends_with(DASHES)
            || !line(&end_trailer[trailer_len..]).0.is_empty()
        {
            continue;
        }
        let bytes = if end > 0 {
            let filtered = rest[..end as usize]
                .iter()
                .copied()
                .filter(|byte| !matches!(*byte, b' ' | b'\t' | b'\r' | b'\n'))
                .collect::<Vec<_>>();
            // Go StdEncoding accepts nonzero unused trailing bits, but still
            // requires the normal padded encoding. CR/LF are ignored by Go.
            let codec = GeneralPurpose::new(
                &alphabet::STANDARD,
                GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
            );
            let Ok(bytes) = codec.decode(filtered) else {
                continue;
            };
            bytes
        } else {
            Vec::new()
        };
        let after = usize::try_from(end + END.len() as isize - 1).ok()?;
        let (_, rest, _) = line(rest.get(after..)?);
        return Some((Block { label, bytes }, rest));
    }
}

pub(super) fn encode(label: &str, bytes: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    let mut output = format!("-----BEGIN {label}-----\n");
    for line in encoded.as_bytes().chunks(64) {
        // Base64 output is ASCII by construction.
        if let Ok(line) = std::str::from_utf8(line) {
            output.push_str(line);
            output.push('\n');
        }
    }
    output.push_str(&format!("-----END {label}-----\n"));
    output
}
