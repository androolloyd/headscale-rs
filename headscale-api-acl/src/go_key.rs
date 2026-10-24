//! Typed Tailscale public-key text shared by wire and database adapters.
//! Acceptance/error order follows tailscale.com v1.98.3 types/key.parseHex.
// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

use std::sync::OnceLock;

use num_bigint::BigUint;
use thiserror::Error;

pub const ZERO_MACHINE_KEY: &str =
    "mkey:0000000000000000000000000000000000000000000000000000000000000000";
pub const ZERO_NODE_KEY: &str =
    "nodekey:0000000000000000000000000000000000000000000000000000000000000000";
pub const ZERO_DISCO_KEY: &str =
    "discokey:0000000000000000000000000000000000000000000000000000000000000000";
pub const ZERO_NODE_LOCK_KEY: &str =
    "nlpub:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublicKeyKind {
    Machine,
    Node,
    Disco,
    NodeLock,
    HardwareAttestation,
}

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PublicKeyTextError {
    #[error("key hex string doesn't have expected type prefix {0}")]
    Prefix(&'static str),
    #[error("key hex has the wrong size, got {0} want 64")]
    Length(usize),
    #[error("key hex has the wrong size, got {0} want 130")]
    HardwareLength(usize),
    #[error("invalid hex character in key")]
    Hex,
    #[error("ecdsa: invalid uncompressed public key")]
    UncompressedEncoding,
    #[error("invalid P256Element encoding")]
    CoordinateEncoding,
    #[error("P256 point not on curve")]
    OffCurve,
}

impl PublicKeyKind {
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Machine => "mkey:",
            Self::Node => "nodekey:",
            Self::Disco => "discokey:",
            Self::NodeLock => "nlpub:",
            Self::HardwareAttestation => "hwattestpub:",
        }
    }

    pub const fn zero_text(self) -> &'static str {
        match self {
            Self::Machine => ZERO_MACHINE_KEY,
            Self::Node => ZERO_NODE_KEY,
            Self::Disco => ZERO_DISCO_KEY,
            Self::NodeLock => ZERO_NODE_LOCK_KEY,
            // HardwareAttestationPublic.MarshalText emits empty for zero.
            Self::HardwareAttestation => "",
        }
    }

    /// Uppercase hex is valid and marshals lowercase. The 32-byte key types
    /// have no curve-point check. Hardware keys are empty/zero or a 65-byte
    /// uncompressed P-256 point with reduced coordinates, as in Go.
    pub fn parse_text(self, text: &str) -> Result<String, PublicKeyTextError> {
        let hardware = self == Self::HardwareAttestation;
        if hardware && text.is_empty() {
            return Ok(String::new());
        }
        // NLPublic accepts its CLI alias too and reports that expected alias
        // when input does not start with nlpub, matching its UnmarshalText.
        let input_prefix = if self == Self::NodeLock && !text.starts_with("nlpub:") {
            "tlpub:"
        } else {
            self.prefix()
        };
        let hex = text
            .strip_prefix(input_prefix)
            .ok_or(PublicKeyTextError::Prefix(input_prefix))?;
        if hex.len() != if hardware { 130 } else { 64 } {
            return Err(if hardware {
                PublicKeyTextError::HardwareLength(hex.len())
            } else {
                PublicKeyTextError::Length(hex.len())
            });
        }
        if !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(PublicKeyTextError::Hex);
        }
        if hardware {
            let mut point = [0u8; 65];
            for (index, byte) in point.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                    .map_err(|_| PublicKeyTextError::Hex)?;
            }
            validate_p256_public_point(&point)?;
        }
        Ok(format!("{}{}", self.prefix(), hex.to_ascii_lowercase()))
    }
}

fn validate_p256_public_point(point: &[u8; 65]) -> Result<(), PublicKeyTextError> {
    if point[0] != 4 {
        return Err(PublicKeyTextError::UncompressedEncoding);
    }
    // These operations inspect fixed-size public data, never a private key or
    // signing scalar. No secret-bearing crypto operation uses BigUint here.
    static CURVE: OnceLock<(BigUint, BigUint)> = OnceLock::new();
    let (prime, b) = CURVE.get_or_init(|| {
        // SP 800-186 P-256: p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
        let prime = BigUint::from_bytes_be(&[
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff,
        ]);
        let b = BigUint::from_bytes_be(&[
            0x5a, 0xc6, 0x35, 0xd8, 0xaa, 0x3a, 0x93, 0xe7, 0xb3, 0xeb, 0xbd, 0x55, 0x76, 0x98,
            0x86, 0xbc, 0x65, 0x1d, 0x06, 0xb0, 0xcc, 0x53, 0xb0, 0xf6, 0x3b, 0xce, 0x3c, 0x3e,
            0x27, 0xd2, 0x60, 0x4b,
        ]);
        (prime, b)
    });
    let x = BigUint::from_bytes_be(&point[1..33]);
    let y = BigUint::from_bytes_be(&point[33..]);
    if &x >= prime || &y >= prime {
        return Err(PublicKeyTextError::CoordinateEncoding);
    }
    let x_cubed = (((&x * &x) % prime) * &x) % prime;
    let three_x = (&x * 3u32) % prime;
    let rhs = (x_cubed + prime - three_x + b) % prime;
    let lhs = (&y * &y) % prime;
    if lhs != rhs {
        return Err(PublicKeyTextError::OffCurve);
    }
    Ok(())
}
