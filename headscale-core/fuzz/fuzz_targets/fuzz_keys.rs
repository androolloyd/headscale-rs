#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use headscale_core::keys_wg::{parse_public_key, parse_secret_key, WgKeyPair};

#[derive(Arbitrary, Debug)]
struct KeyFuzzInput {
    base64_str: String,
    secret_bytes: [u8; 32],
}

fuzz_target!(|input: KeyFuzzInput| {
    // Fuzz key parsing and operations

    // Try to parse as base64 public key
    let _ = parse_public_key(&input.base64_str);

    // Try to parse as base64 secret key
    let _ = parse_secret_key(&input.base64_str);

    // Create key pair from arbitrary bytes
    let keypair = WgKeyPair::from_secret(input.secret_bytes);

    // Ensure key operations don't panic
    let _ = keypair.public_key();
    let _ = keypair.public_key_bytes();
    let _ = keypair.public_key_base64();
    let _ = keypair.secret_bytes();

    // Derive from Ed25519 secret (should never panic)
    let _ = WgKeyPair::from_ed25519_secret(&input.secret_bytes);
});
