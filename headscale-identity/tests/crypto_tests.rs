//! Integration tests for Ed25519 cryptography implementation

use headscale_identity::{Did, KeyPair, Session};

#[test]
fn test_key_generation_with_csprng() {
    // Generate two different keypairs
    let keypair1 = KeyPair::generate();
    let keypair2 = KeyPair::generate();

    let pubkey1 = keypair1.public_key();
    let pubkey2 = keypair2.public_key();

    // Keys should be different (astronomically unlikely to be same)
    assert_ne!(pubkey1, pubkey2, "Generated keys should be different");
}

#[test]
fn test_did_encoding_with_multibase_multicodec() {
    let keypair = KeyPair::generate();
    let did = keypair.did();

    // DID should use base58btc encoding (z prefix)
    assert!(
        did.as_str().starts_with("did:key:z"),
        "DID should start with did:key:z (base58btc multibase)"
    );

    // Should be able to recover the public key
    let recovered_pubkey = did.public_key().expect("Should decode DID");
    assert_eq!(
        recovered_pubkey,
        keypair.public_key(),
        "Recovered public key should match original"
    );
}

#[test]
fn test_ed25519_signing_and_verification() {
    let keypair = KeyPair::generate();
    let message = b"Test message for signing";

    // Sign the message
    let signature = keypair.sign(message);

    // Verify with correct key
    assert!(
        KeyPair::verify(&keypair.public_key(), message, &signature),
        "Valid signature should verify"
    );
}

#[test]
fn test_signature_verification_rejects_wrong_key() {
    let keypair1 = KeyPair::generate();
    let keypair2 = KeyPair::generate();
    let message = b"Test message";

    let signature = keypair1.sign(message);

    // Should fail with different public key
    assert!(
        !KeyPair::verify(&keypair2.public_key(), message, &signature),
        "Signature should not verify with different key"
    );
}

#[test]
fn test_signature_verification_rejects_tampered_message() {
    let keypair = KeyPair::generate();
    let message = b"Original message";
    let tampered = b"Tampered message";

    let signature = keypair.sign(message);

    // Should fail with tampered message
    assert!(
        !KeyPair::verify(&keypair.public_key(), tampered, &signature),
        "Signature should not verify with tampered message"
    );
}

#[test]
fn test_session_token_uses_csprng() {
    let keypair = KeyPair::generate();
    let did = keypair.did();

    // Generate multiple session tokens
    let session1 = Session::new(did.clone(), 3600);
    let session2 = Session::new(did.clone(), 3600);
    let session3 = Session::new(did, 3600);

    // All tokens should be different (using CSPRNG)
    assert_ne!(session1.token, session2.token, "Tokens should be unique");
    assert_ne!(session2.token, session3.token, "Tokens should be unique");
    assert_ne!(session1.token, session3.token, "Tokens should be unique");

    // Tokens should be base58 encoded (alphanumeric)
    assert!(
        session1.token.chars().all(|c| c.is_ascii_alphanumeric()),
        "Token should be base58 encoded"
    );
}

#[test]
fn test_keypair_from_secret() {
    let keypair1 = KeyPair::generate();
    let secret = keypair1.secret_key();

    // Create a new keypair from the same secret
    let keypair2 = KeyPair::from_secret(&secret);

    // Should have the same public key
    assert_eq!(
        keypair1.public_key(),
        keypair2.public_key(),
        "Same secret should produce same public key"
    );

    // Should produce the same signatures
    let message = b"Test message";
    let sig1 = keypair1.sign(message);
    let sig2 = keypair2.sign(message);
    assert_eq!(sig1, sig2, "Same secret should produce same signature");
}

#[test]
fn test_did_roundtrip() {
    let keypair = KeyPair::generate();
    let did1 = keypair.did();

    // Parse the DID string
    let did2 = Did::parse(did1.as_str()).expect("Should parse DID");

    assert_eq!(did1.as_str(), did2.as_str(), "DID should roundtrip");

    // Public keys should match
    let pubkey1 = did1.public_key().expect("Should decode");
    let pubkey2 = did2.public_key().expect("Should decode");
    assert_eq!(pubkey1, pubkey2, "Public keys should match after roundtrip");
}

#[test]
fn test_session_expiration() {
    let keypair = KeyPair::generate();
    let did = keypair.did();

    // Create a session with 1 second duration
    let session = Session::new(did, 1);

    // Should not be expired immediately
    assert!(!session.is_expired(), "Session should not be expired yet");

    // Wait for expiration
    std::thread::sleep(std::time::Duration::from_secs(2));

    assert!(session.is_expired(), "Session should be expired after waiting");
}
