//! Headscale-rs Identity
//!
//! DID authentication and key management for mesh nodes.
//!
//! This crate handles:
//! - DID generation and validation
//! - Ed25519 key management
//! - Challenge-response authentication
//! - Session tokens

pub mod did;
pub mod keys;
pub mod session;

pub use did::Did;
pub use keys::KeyPair;
pub use session::Session;
