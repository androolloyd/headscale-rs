//! Session management for authenticated nodes.

use crate::did::Did;
use serde::{Deserialize, Serialize};

/// An authenticated session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// Node DID
    pub did: Did,
    /// Session token
    pub token: String,
    /// Created timestamp
    pub created_at: u64,
    /// Expires timestamp
    pub expires_at: u64,
    /// Session capabilities
    pub capabilities: Vec<String>,
}

impl Session {
    /// Create a new session.
    pub fn new(did: Did, duration_secs: u64) -> Self {
        let now = now();
        Self {
            did,
            token: generate_token(),
            created_at: now,
            expires_at: now + duration_secs,
            capabilities: Vec::new(),
        }
    }

    /// Check if session is expired.
    pub fn is_expired(&self) -> bool {
        now() > self.expires_at
    }

    /// Add a capability.
    pub fn with_capability(mut self, cap: &str) -> Self {
        self.capabilities.push(cap.to_string());
        self
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Generate a cryptographically secure random token.
///
/// Uses OsRng (CSPRNG) to generate 32 random bytes, encoded as base58.
fn generate_token() -> String {
    use rand_core::{OsRng, RngCore};

    let mut token_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut token_bytes);

    // Encode as base58 for URL-safe, compact representation
    bs58::encode(&token_bytes).into_string()
}
