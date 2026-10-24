// Copyright 2021, 2023 The Go Authors. All rights reserved.
// Adapted from Go 1.26.9 internal/godebug and internal/bisect. See LICENSE-GO-STDLIB.

//! Dynamic byte-valued environment settings for the selected native client.
//! Linked DefaultGODEBUG overrides, runtime counters and bisect reporting are
//! not reproduced. Stack-dependent matchers are explicit and callers retain
//! the Go 1.26 default, rather than assigning Rust stack PCs a Go identity.

pub(super) enum Resolution {
    Absent,
    Plain(Vec<u8>),
    StackConditioned,
}

pub(super) fn lookup(name: &[u8]) -> Resolution {
    let Some(environment) = std::env::var_os("GODEBUG") else {
        return Resolution::Absent;
    };
    let environment = environment_bytes(environment);
    // Go scans backwards, remembering the first '=' within each token. Empty
    // values override earlier values; a token without '=' does not shadow one.
    for entry in environment.rsplit(|byte| *byte == b',') {
        let Some(equal) = entry.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        if &entry[..equal] != name {
            continue;
        }
        let argument = &entry[equal + 1..];
        let Some(hash) = argument.iter().position(|byte| *byte == b'#') else {
            return Resolution::Plain(argument.to_vec());
        };
        let text = &argument[..hash];
        return match matcher(&argument[hash + 1..]) {
            // godebug deliberately ignores a bisect.New parse error, leaving
            // the shortened text active with a nil matcher.
            Matcher::None | Matcher::Constant(true) => Resolution::Plain(text.to_vec()),
            Matcher::Constant(false) => Resolution::Plain(Vec::new()),
            Matcher::StackDependent => Resolution::StackConditioned,
        };
    }
    Resolution::Absent
}

#[cfg(unix)]
fn environment_bytes(value: std::ffi::OsString) -> Vec<u8> {
    use std::os::unix::ffi::OsStringExt;
    value.into_vec()
}

#[cfg(not(unix))]
fn environment_bytes(value: std::ffi::OsString) -> Vec<u8> {
    value.to_string_lossy().into_owned().into_bytes()
}

enum Matcher {
    None,
    Constant(bool),
    StackDependent,
}

// Only classify a valid matcher as constant when its ordered conditions prove
// that result for every u64 stack hash. Other valid patterns remain explicit.
fn matcher(pattern: &[u8]) -> Matcher {
    if pattern.is_empty() {
        return Matcher::None;
    }
    let mut source = pattern;
    if source.first() == Some(&b'q') {
        source = &source[1..];
        if source.is_empty() {
            return Matcher::None;
        }
    }
    while source.first() == Some(&b'v') {
        source = &source[1..];
        if source.is_empty() {
            return Matcher::None;
        }
    }
    let mut enable = true;
    while source.first() == Some(&b'!') {
        enable = !enable;
        source = &source[1..];
        if source.is_empty() {
            return Matcher::None;
        }
    }
    if source == b"n" {
        enable = !enable;
        source = b"y";
    }
    let mut result = true;
    let mut bits = 0u64;
    let mut start = 0usize;
    let mut width = 1usize;
    let mut conditions = Vec::new();
    for index in 0..=source.len() {
        let byte = source.get(index).copied().unwrap_or(b'-');
        if index == start && width == 1 && byte == b'x' {
            start = index + 1;
            width = 4;
            continue;
        }
        match byte {
            b'0'..=b'9' if byte <= b'1' || width == 4 => {
                bits = bits.wrapping_shl(width as u32) | u64::from(byte - b'0');
            }
            b'a'..=b'f' | b'A'..=b'F' if width == 4 => {
                bits = bits.wrapping_shl(4) | u64::from((byte & !0x20) - b'A' + 10);
            }
            b'y' => {
                if matches!(source.get(index + 1), Some(b'0' | b'1')) {
                    return Matcher::None;
                }
                bits = 0;
            }
            b'+' | b'-' => {
                if byte == b'+' && !result {
                    return Matcher::None;
                }
                if index > 0 {
                    let count = (index - start).saturating_mul(width);
                    if count == 0 || count > 64 {
                        return Matcher::None;
                    }
                    let count = if source[start] == b'y' { 0 } else { count };
                    let mask = if count == 64 {
                        u64::MAX
                    } else {
                        (1u64 << count) - 1
                    };
                    conditions.push((mask, bits, result));
                } else if byte == b'-' {
                    conditions.push((0, 0, true));
                }
                bits = 0;
                result = byte == b'+';
                start = index + 1;
                width = 1;
            }
            _ => return Matcher::None,
        }
    }
    let mut selected = None;
    for (mask, bits, result) in conditions.into_iter().rev() {
        // Impossible conditions never match any ID.
        if bits & mask != bits {
            continue;
        }
        if selected.is_some_and(|previous| previous != result) {
            return Matcher::StackDependent;
        }
        selected = Some(result);
        if mask == 0 {
            return Matcher::Constant(result == enable);
        }
    }
    // Unmatched IDs return false. Only uniformly false conditions therefore
    // prove a constant here; complete nontrivial suffix coverage is left alone.
    match selected {
        None | Some(false) => Matcher::Constant(!enable),
        Some(true) => Matcher::StackDependent,
    }
}
