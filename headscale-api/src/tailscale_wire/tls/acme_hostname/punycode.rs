// Copyright 2016 The Go Authors. All rights reserved.
// Adapted from selected x/net/idna/punycode.go; see LICENSE-GO-STDLIB.

//! Go's RFC 3492 arithmetic and legacy delimiter behavior. The caller still
//! validates decoded labels; decoding alone does not make a label valid IDNA.

const BASE: i32 = 36;
const T_MIN: i32 = 1;
const T_MAX: i32 = 26;
const INITIAL_BIAS: i32 = 72;
const INITIAL_N: i32 = 128;

fn threshold(k: i32, bias: i32) -> i32 {
    if k <= bias {
        T_MIN
    } else if k >= bias + T_MAX {
        T_MAX
    } else {
        k - bias
    }
}

fn adapt(mut delta: i32, points: i32, first: bool) -> i32 {
    delta /= if first { 700 } else { 2 };
    delta += delta / points;
    let mut k = 0;
    while delta > ((BASE - T_MIN) * T_MAX) / 2 {
        delta /= BASE - T_MIN;
        k += BASE;
    }
    k + (BASE - T_MIN + 1) * delta / (delta + 38)
}

fn madd(a: i32, b: i32, c: i32) -> Option<i32> {
    i32::try_from(i64::from(a) + i64::from(b) * i64::from(c)).ok()
}

fn digit(byte: u8) -> Option<i32> {
    match byte {
        b'0'..=b'9' => Some(i32::from(byte - b'0') + 26),
        b'a'..=b'z' => Some(i32::from(byte - b'a')),
        b'A'..=b'Z' => Some(i32::from(byte - b'A')),
        _ => None,
    }
}

fn encode_digit(digit: i32) -> Option<char> {
    match digit {
        0..=25 => Some(char::from(b'a' + digit as u8)),
        26..=35 => Some(char::from(b'0' + (digit - 26) as u8)),
        _ => None,
    }
}

pub(super) fn decode(encoded: &str) -> Option<String> {
    if encoded.is_empty() {
        return Some(String::new());
    }
    let mut pos = encoded.rfind('-').map_or(0, |at| at + 1);
    if pos == 1 {
        return None;
    }
    if pos == encoded.len() {
        return Some(encoded[..pos - 1].to_owned());
    }
    let mut output = if pos == 0 {
        Vec::new()
    } else {
        encoded[..pos - 1].chars().collect::<Vec<_>>()
    };
    let mut index = 0_i32;
    let mut n = INITIAL_N;
    let mut bias = INITIAL_BIAS;
    while pos < encoded.len() {
        let old = index;
        let mut weight = 1;
        let mut k = BASE;
        loop {
            let next = digit(*encoded.as_bytes().get(pos)?)?;
            pos += 1;
            index = madd(index, next, weight)?;
            let t = threshold(k, bias);
            if next < t {
                break;
            }
            weight = madd(0, weight, BASE - t)?;
            k = k.checked_add(BASE)?;
        }
        // The selected Go decoder checks this before each insertion, but not
        // on its separate all-basic delimiter-ending return path.
        if output.len() >= 1024 {
            return None;
        }
        let points = i32::try_from(output.len() + 1).ok()?;
        bias = adapt(index - old, points, old == 0);
        n = n.checked_add(index / points)?;
        index %= points;
        // Go converts surrogate runes to U+FFFD, which its IDNA validation
        // then rejects. Reject them here with the same acceptance result.
        let ch = char::from_u32(u32::try_from(n).ok()?)?;
        output.insert(usize::try_from(index).ok()?, ch);
        index += 1;
    }
    Some(output.into_iter().collect())
}

pub(super) fn encode(label: &str) -> Option<String> {
    let mut output = String::from("xn--");
    let mut basic = 0_i32;
    let mut remaining = 0_i32;
    for ch in label.chars() {
        if ch.is_ascii() {
            basic = basic.checked_add(1)?;
            output.push(ch);
        } else {
            remaining = remaining.checked_add(1)?;
        }
    }
    let mut handled = basic;
    if basic > 0 {
        output.push('-');
    }
    let mut delta = 0;
    let mut code_point = INITIAL_N;
    let mut bias = INITIAL_BIAS;
    while remaining != 0 {
        let next_point = label
            .chars()
            .map(|ch| ch as i32)
            .filter(|&ch| ch >= code_point)
            .min()?;
        delta = madd(delta, next_point - code_point, handled.checked_add(1)?)?;
        code_point = next_point;
        for ch in label.chars().map(|ch| ch as i32) {
            if ch < code_point {
                delta = delta.checked_add(1)?;
                continue;
            }
            if ch > code_point {
                continue;
            }
            let mut quotient = delta;
            let mut position = BASE;
            loop {
                let limit = threshold(position, bias);
                if quotient < limit {
                    break;
                }
                output.push(encode_digit(limit + (quotient - limit) % (BASE - limit))?);
                quotient = (quotient - limit) / (BASE - limit);
                position = position.checked_add(BASE)?;
            }
            output.push(encode_digit(quotient)?);
            bias = adapt(delta, handled.checked_add(1)?, handled == basic);
            delta = 0;
            handled = handled.checked_add(1)?;
            remaining -= 1;
        }
        delta = delta.checked_add(1)?;
        code_point = code_point.checked_add(1)?;
    }
    Some(output)
}
