//! Key management for mesh nodes.

use crate::did::Did;
use ed25519_dalek::{
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH, Signature, Signer, SigningKey,
    Verifier, VerifyingKey,
};
use rand_core::{OsRng, RngCore};

/// Ed25519 key pair for node identity.
pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    /// Generate a new random key pair using cryptographically secure randomness.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let mut secret_bytes = [0u8; SECRET_KEY_LENGTH];
        csprng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        Self { signing_key }
    }

    /// Create a KeyPair from a secret key.
    pub fn from_secret(secret: &[u8; SECRET_KEY_LENGTH]) -> Self {
        let signing_key = SigningKey::from_bytes(secret);
        Self { signing_key }
    }

    /// Get the secret key bytes.
    pub fn secret_key(&self) -> [u8; SECRET_KEY_LENGTH] {
        self.signing_key.to_bytes()
    }

    /// Get the public key bytes.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the verifying key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Get the DID for this key pair.
    pub fn did(&self) -> Did {
        Did::from_public_key(&self.public_key())
    }

    /// Sign a message with Ed25519.
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LENGTH] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Verify a signature against a message using a public key.
    pub fn verify(
        public_key: &[u8; PUBLIC_KEY_LENGTH],
        message: &[u8],
        signature: &[u8; SIGNATURE_LENGTH],
    ) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };

        let sig = Signature::from_bytes(signature);

        verifying_key.verify(message, &sig).is_ok()
    }
}
