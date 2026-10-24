// Copyright (c) 2020, Juan Font
// SPDX-License-Identifier: BSD-3-Clause
// headscale-go v0.29.5 util/string.go. See UPSTREAM.md and retained licenses.

//! Native key generation follows GenerateRandomStringURLSafe's read,
//! raw-URL-base64 encoding and truncation. The caller propagates RNG errors.

use crate::{DbError, Result};
use rand_core::RngCore;

const URLSAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub(crate) fn urlsafe(len: usize) -> Result<String> {
    let mut raw = vec![0u8; len];
    rand_core::OsRng
        .try_fill_bytes(&mut raw)
        .map_err(|error| DbError::General(error.to_string()))?;
    let mut output = String::with_capacity(len);
    let mut bits = 0;
    let mut accumulator = 0_u32;
    for byte in raw {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 6 && output.len() < len {
            bits -= 6;
            output.push(URLSAFE[((accumulator >> bits) & 63) as usize] as char);
        }
        if output.len() == len {
            break;
        }
    }
    Ok(output)
}
