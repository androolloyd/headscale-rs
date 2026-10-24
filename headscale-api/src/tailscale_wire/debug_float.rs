// Copyright 2010 The Go Authors. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
// Go encoding/json's float64 presentation rules, using Rust's shortest digits.
// See UPSTREAM.md and LICENSE-GO-STDLIB.

//! Typed float output for native debug schemas. Opaque JSON bypasses this.

use std::io;

use serde_json::Value;

use super::debug_filters::{field, json};

fn number(value: f64) -> io::Result<Vec<u8>> {
    if !value.is_finite() {
        return Err(io::Error::other("unsupported non-finite JSON number"));
    }
    let mut out = Vec::new();
    if value.is_sign_negative() {
        out.push(b'-');
    }
    if value == 0.0 {
        out.push(b'0');
        return Ok(out);
    }
    let shortest = value.abs().to_string();
    let (mantissa, power) = if let Some(at) = shortest.find(['e', 'E']) {
        (
            &shortest[..at],
            shortest[at + 1..]
                .parse::<i32>()
                .map_err(io::Error::other)?,
        )
    } else {
        (shortest.as_str(), 0)
    };
    let point = mantissa.find('.').unwrap_or(mantissa.len());
    let digits = mantissa
        .bytes()
        .filter(|byte| *byte != b'.')
        .collect::<Vec<_>>();
    let first = digits
        .iter()
        .position(|byte| *byte != b'0')
        .ok_or_else(|| io::Error::other("invalid shortest float"))?;
    let last = digits
        .iter()
        .rposition(|byte| *byte != b'0')
        .expect("nonzero digits");
    let exponent = power + i32::try_from(point).map_err(io::Error::other)?
        - i32::try_from(first).map_err(io::Error::other)?
        - 1;
    let digits = &digits[first..=last];
    // encoding/json uses decimal notation in [1e-6,1e21), unlike a generic
    // shortest formatter. Exponents carry a positive sign and no leading zero.
    if value.abs() < 1e-6 || value.abs() >= 1e21 {
        out.push(digits[0]);
        if digits.len() > 1 {
            out.push(b'.');
            out.extend_from_slice(&digits[1..]);
        }
        out.push(b'e');
        if exponent >= 0 {
            out.push(b'+');
        }
        out.extend_from_slice(exponent.to_string().as_bytes());
    } else {
        let point = exponent + 1;
        if point <= 0 {
            out.extend_from_slice(b"0.");
            out.resize(
                out.len() + usize::try_from(-point).map_err(io::Error::other)?,
                b'0',
            );
            out.extend_from_slice(digits);
        } else {
            let point = usize::try_from(point).map_err(io::Error::other)?;
            if point >= digits.len() {
                out.extend_from_slice(digits);
                out.resize(out.len() + point - digits.len(), b'0');
            } else {
                out.extend_from_slice(&digits[..point]);
                out.push(b'.');
                out.extend_from_slice(&digits[point..]);
            }
        }
    }
    Ok(out)
}

pub(super) fn value(input: &Value) -> io::Result<Vec<u8>> {
    match input {
        Value::Number(value) if value.is_f64() => number(value.as_f64().expect("float number")),
        Value::Array(values) => {
            let mut out = vec![b'['];
            for (index, input) in values.iter().enumerate() {
                if index != 0 {
                    out.push(b',');
                }
                out.extend(value(input)?);
            }
            out.push(b']');
            Ok(out)
        }
        Value::Object(values) => {
            let mut out = vec![b'{'];
            for (name, input) in values {
                field(&mut out, name, &value(input)?)?;
            }
            out.push(b'}');
            Ok(out)
        }
        _ => json(input),
    }
}
