//! Decentralized Identifier (DID) implementation.

use serde::{Deserialize, Serialize};

/// A Decentralized Identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Did(String);

// Ed25519 public key multicodec prefix (0xed01)
const ED25519_MULTICODEC: &[u8] = &[0xed, 0x01];

impl Did {
    /// Create a DID from a public key using proper multibase/multicodec encoding.
    pub fn from_public_key(pubkey: &[u8; 32]) -> Self {
        let encoded = multibase_encode(pubkey);
        Self(format!("did:key:{}", encoded))
    }

    /// Parse a DID string.
    pub fn parse(s: &str) -> Result<Self, DidError> {
        if !s.starts_with("did:key:") {
            return Err(DidError::InvalidFormat);
        }
        Ok(Self(s.to_string()))
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> Result<[u8; 32], DidError> {
        let encoded = self
            .0
            .strip_prefix("did:key:")
            .ok_or(DidError::InvalidFormat)?;
        multibase_decode(encoded)
    }

    /// Get the full DID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DidError {
    #[error("Invalid DID format")]
    InvalidFormat,
    #[error("Invalid key encoding")]
    InvalidEncoding,
    #[error("Invalid multicodec prefix")]
    InvalidMulticodec,
}

/// Encode a public key with multibase (base58btc) and multicodec (ed25519).
///
/// Format: z (base58btc prefix) + base58(0xed01 + pubkey)
fn multibase_encode(pubkey: &[u8; 32]) -> String {
    // Prepend Ed25519 multicodec prefix to the public key
    let mut data = Vec::with_capacity(ED25519_MULTICODEC.len() + 32);
    data.extend_from_slice(ED25519_MULTICODEC);
    data.extend_from_slice(pubkey);

    // Encode with base58btc and prepend 'z' multibase prefix
    format!("z{}", bs58::encode(&data).into_string())
}

/// Decode a multibase-encoded public key.
fn multibase_decode(encoded: &str) -> Result<[u8; 32], DidError> {
    // Check for 'z' prefix (base58btc)
    let encoded = encoded.strip_prefix('z').ok_or(DidError::InvalidEncoding)?;

    // Decode base58
    let data = bs58::decode(encoded)
        .into_vec()
        .map_err(|_| DidError::InvalidEncoding)?;

    // Verify multicodec prefix
    if !data.starts_with(ED25519_MULTICODEC) {
        return Err(DidError::InvalidMulticodec);
    }

    // Extract public key (skip multicodec prefix)
    let pubkey_bytes = &data[ED25519_MULTICODEC.len()..];
    if pubkey_bytes.len() != 32 {
        return Err(DidError::InvalidEncoding);
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(pubkey_bytes);
    Ok(pubkey)
}
