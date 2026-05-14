//! WireGuard key management (x25519).
//!
//! WireGuard uses x25519 for key exchange, which is different from Ed25519
//! used for identity/signing. This module provides x25519 key generation
//! and conversion utilities.

use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

/// WireGuard key pair for tunnel encryption.
#[derive(Clone)]
pub struct WgKeyPair {
    secret: StaticSecret,
}

// Manual Debug impl to avoid printing the secret
impl std::fmt::Debug for WgKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WgKeyPair")
            .field("public_key", &self.public_key_base64())
            .finish()
    }
}

impl WgKeyPair {
    /// Generate a new random WireGuard key pair.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let mut secret_bytes = [0u8; 32];
        csprng.fill_bytes(&mut secret_bytes);
        let secret = StaticSecret::from(secret_bytes);
        Self { secret }
    }

    /// Create a WgKeyPair from a 32-byte secret.
    pub fn from_secret(secret_bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(secret_bytes);
        Self { secret }
    }

    /// Derive a WireGuard key pair from an Ed25519 secret key.
    ///
    /// This uses a one-way derivation to create a separate x25519 key
    /// from an Ed25519 identity key, keeping the WireGuard key deterministic
    /// but cryptographically separated.
    pub fn from_ed25519_secret(ed25519_secret: &[u8; 32]) -> Self {
        use blake2::{Blake2b512, Digest};

        // Hash the Ed25519 secret with a domain separator to derive x25519 key
        let mut hasher = Blake2b512::new();
        hasher.update(b"headscale-rs:ed25519-to-x25519:v1");
        hasher.update(ed25519_secret);
        let hash = hasher.finalize();

        // Take first 32 bytes as x25519 secret
        let mut secret_bytes = [0u8; 32];
        secret_bytes.copy_from_slice(&hash[..32]);

        // Apply x25519 clamping as per RFC 7748
        secret_bytes[0] &= 248;
        secret_bytes[31] &= 127;
        secret_bytes[31] |= 64;

        Self::from_secret(secret_bytes)
    }

    /// Get the secret key bytes.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Get the public key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    /// Get the public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key().to_bytes()
    }

    /// Get the secret as a StaticSecret reference (for boringtun).
    pub fn static_secret(&self) -> &StaticSecret {
        &self.secret
    }

    /// Get a clone of the secret (for boringtun which takes ownership).
    pub fn secret_key_x25519(&self) -> StaticSecret {
        StaticSecret::from(self.secret.to_bytes())
    }

    /// Get the public key as x25519 type.
    pub fn public_key_x25519(&self) -> PublicKey {
        self.public_key()
    }

    /// Encode public key as base64 (WireGuard standard format).
    pub fn public_key_base64(&self) -> String {
        use base64::prelude::*;
        BASE64_STANDARD.encode(self.public_key_bytes())
    }

    /// Perform Diffie-Hellman key exchange with a peer's public key.
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> [u8; 32] {
        self.secret.diffie_hellman(peer_public).to_bytes()
    }
}

/// Parse a WireGuard public key from base64.
pub fn parse_public_key(base64_key: &str) -> Result<PublicKey, KeyError> {
    use base64::prelude::*;

    let bytes = BASE64_STANDARD
        .decode(base64_key)
        .map_err(|e| KeyError::InvalidBase64(e.to_string()))?;

    if bytes.len() != 32 {
        return Err(KeyError::InvalidLength {
            expected: 32,
            got: bytes.len(),
        });
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);

    Ok(PublicKey::from(key_bytes))
}

/// Parse a WireGuard secret key from base64.
pub fn parse_secret_key(base64_key: &str) -> Result<WgKeyPair, KeyError> {
    use base64::prelude::*;

    let bytes = BASE64_STANDARD
        .decode(base64_key)
        .map_err(|e| KeyError::InvalidBase64(e.to_string()))?;

    if bytes.len() != 32 {
        return Err(KeyError::InvalidLength {
            expected: 32,
            got: bytes.len(),
        });
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes);

    Ok(WgKeyPair::from_secret(key_bytes))
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Invalid base64 encoding: {0}")]
    InvalidBase64(String),

    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let keypair = WgKeyPair::generate();
        let public = keypair.public_key_bytes();

        // Public key should not be all zeros
        assert_ne!(public, [0u8; 32]);

        // Should be deterministic from secret
        let keypair2 = WgKeyPair::from_secret(keypair.secret_bytes());
        assert_eq!(keypair.public_key_bytes(), keypair2.public_key_bytes());
    }

    #[test]
    fn test_ed25519_derivation() {
        let ed25519_secret = [42u8; 32];
        let wg_keypair = WgKeyPair::from_ed25519_secret(&ed25519_secret);

        // Should be deterministic
        let wg_keypair2 = WgKeyPair::from_ed25519_secret(&ed25519_secret);
        assert_eq!(wg_keypair.public_key_bytes(), wg_keypair2.public_key_bytes());

        // Different Ed25519 keys should produce different WG keys
        let ed25519_secret2 = [43u8; 32];
        let wg_keypair3 = WgKeyPair::from_ed25519_secret(&ed25519_secret2);
        assert_ne!(wg_keypair.public_key_bytes(), wg_keypair3.public_key_bytes());
    }

    #[test]
    fn test_base64_roundtrip() {
        let keypair = WgKeyPair::generate();
        let base64_pub = keypair.public_key_base64();

        let parsed = parse_public_key(&base64_pub).unwrap();
        assert_eq!(parsed.to_bytes(), keypair.public_key_bytes());
    }

    #[test]
    fn test_diffie_hellman() {
        let alice = WgKeyPair::generate();
        let bob = WgKeyPair::generate();

        // DH should produce the same shared secret on both sides
        let alice_shared = alice.diffie_hellman(&bob.public_key());
        let bob_shared = bob.diffie_hellman(&alice.public_key());

        assert_eq!(alice_shared, bob_shared);
    }

    #[test]
    fn test_invalid_base64() {
        let result = parse_public_key("not-valid-base64!!!");
        assert!(matches!(result, Err(KeyError::InvalidBase64(_))));
    }

    #[test]
    fn test_invalid_length() {
        use base64::prelude::*;
        let short_key = BASE64_STANDARD.encode([0u8; 16]);
        let result = parse_public_key(&short_key);
        assert!(matches!(
            result,
            Err(KeyError::InvalidLength {
                expected: 32,
                got: 16
            })
        ));
    }
}
