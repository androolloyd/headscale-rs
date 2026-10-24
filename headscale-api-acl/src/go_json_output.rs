// Copyright 2010 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Go encoding/json compact/HTML and indent behavior for retained raw JSON.

pub fn compact_html(source: &[u8]) -> Result<Vec<u8>, String> {
    crate::go_json::validate(source)?;
    let mut out = Vec::with_capacity(source.len());
    let mut at = 0;
    let mut string = false;
    let mut escaped = false;
    while at < source.len() {
        let byte = source[at];
        if matches!(byte, b'<' | b'>' | b'&') {
            const HEX: &[u8] = b"0123456789abcdef";
            out.extend_from_slice(b"\\u00");
            out.push(HEX[usize::from(byte >> 4)]);
            out.push(HEX[usize::from(byte & 15)]);
        } else if byte == 0xe2
            && source.get(at + 1) == Some(&0x80)
            && source
                .get(at + 2)
                .is_some_and(|byte| matches!(byte, 0xa8 | 0xa9))
        {
            out.extend_from_slice(if source[at + 2] == 0xa8 {
                b"\\u2028"
            } else {
                b"\\u2029"
            });
            at += 2;
        } else if string || !matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
            out.push(byte);
        }
        if string {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                string = false;
            }
        } else if byte == b'"' {
            string = true;
        }
        at += 1;
    }
    Ok(out)
}

pub fn indent(source: &[u8]) -> Result<Vec<u8>, String> {
    let compact = compact_html(source)?;
    let mut out = Vec::with_capacity(compact.len());
    let mut depth = 0;
    let mut string = false;
    let mut escaped = false;
    let newline = |out: &mut Vec<u8>, depth: usize| {
        out.push(b'\n');
        out.resize(out.len() + depth * 2, b' ');
    };
    for (index, &byte) in compact.iter().enumerate() {
        if string {
            out.push(byte);
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                string = false;
            }
            continue;
        }
        match byte {
            b'"' => {
                string = true;
                out.push(byte);
            }
            b'{' | b'[' => {
                out.push(byte);
                depth += 1;
                if !matches!(compact.get(index + 1), Some(b'}' | b']')) {
                    newline(&mut out, depth);
                }
            }
            b'}' | b']' => {
                depth -= 1;
                if !matches!(compact.get(index.wrapping_sub(1)), Some(b'{' | b'[')) {
                    newline(&mut out, depth);
                }
                out.push(byte);
            }
            b',' => {
                out.push(byte);
                newline(&mut out, depth);
            }
            b':' => out.extend_from_slice(b": "),
            _ => out.push(byte),
        }
    }
    Ok(out)
}
