// Copyright 2009 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Adapted from Go 1.26.9 time/format.go. See LICENSE-GO-STDLIB.

//! Signed Go time.ParseDuration values and diagnostic text.

use crate::go_strconv::quote_time;

/// Parse a Go duration into signed nanoseconds. Policy's `always` sentinel
/// belongs to its SSHCheckPeriod decoder and is not a time duration here.
pub fn parse_nanos(input: &str) -> Result<i64, String> {
    const LIMIT: u64 = 1_u64 << 63;
    let invalid = || error("invalid duration", input);
    let bytes = input.as_bytes();
    let (negative, mut position) = match bytes.first() {
        Some(b'-') => (true, 1),
        Some(b'+') => (false, 1),
        _ => (false, 0),
    };
    if &input[position..] == "0" {
        return Ok(0);
    }
    if position == bytes.len() {
        return Err(invalid());
    }
    let mut total = 0_u64;
    while position < bytes.len() {
        if bytes[position] != b'.' && !bytes[position].is_ascii_digit() {
            return Err(invalid());
        }
        let integer_start = position;
        let mut whole = 0_u64;
        while position < bytes.len() && bytes[position].is_ascii_digit() {
            if whole > LIMIT / 10 {
                return Err(invalid());
            }
            whole = whole * 10 + u64::from(bytes[position] - b'0');
            if whole > LIMIT {
                return Err(invalid());
            }
            position += 1;
        }
        let pre = position != integer_start;
        let mut post = false;
        let mut fraction = 0_u64;
        let mut scale = 1_f64;
        if position < bytes.len() && bytes[position] == b'.' {
            position += 1;
            let fraction_start = position;
            let mut overflow = false;
            while position < bytes.len() && bytes[position].is_ascii_digit() {
                // leadingFraction consumes every digit after its precision
                // limit, but freezes both the mantissa and float64 scale.
                if !overflow {
                    if fraction > (LIMIT - 1) / 10 {
                        overflow = true;
                    } else {
                        let next = fraction * 10 + u64::from(bytes[position] - b'0');
                        if next > LIMIT {
                            overflow = true;
                        } else {
                            fraction = next;
                            scale *= 10.0;
                        }
                    }
                }
                position += 1;
            }
            post = position != fraction_start;
        }
        if !pre && !post {
            return Err(invalid());
        }
        let unit_start = position;
        while position < bytes.len() && bytes[position] != b'.' && !bytes[position].is_ascii_digit()
        {
            position += 1;
        }
        if unit_start == position {
            return Err(error("missing unit in duration", input));
        }
        // ASCII delimiters cannot occur inside a UTF-8 continuation byte.
        let unit_name = &input[unit_start..position];
        let unit = match unit_name {
            "ns" => 1_u64,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60_000_000_000,
            "h" => 3_600_000_000_000,
            _ => {
                return Err(error(
                    &format!("unknown unit {} in duration", quote_time(unit_name)),
                    input,
                ));
            }
        };
        if whole > LIMIT / unit {
            return Err(invalid());
        }
        let mut component = whole * unit;
        if fraction > 0 {
            // Preserve Go's evaluation order and truncating conversion. The
            // float64 rounding is Go's own, so it is the behaviour to match.
            #[allow(clippy::cast_precision_loss)]
            let scaled = (fraction as f64 * (unit as f64 / scale)) as u64;
            component = component.wrapping_add(scaled);
            if component > LIMIT {
                return Err(invalid());
            }
        }
        // Go adds into a uint64 before checking the signed magnitude bound.
        // In particular, two exact LIMIT components wrap to zero.
        total = total.wrapping_add(component);
        if total > LIMIT {
            return Err(invalid());
        }
    }
    if negative {
        Ok((total as i64).wrapping_neg())
    } else {
        i64::try_from(total).map_err(|_| invalid())
    }
}

fn error(message: &str, input: &str) -> String {
    format!("time: {message} {}", quote_time(input))
}
