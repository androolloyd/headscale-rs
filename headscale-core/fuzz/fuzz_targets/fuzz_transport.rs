#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use headscale_core::swarm_transport::{MeshMessage, MessageCategory};

/// Arbitrary message for fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzMessage {
    from: String,
    to: String,
    category: u8,
    payload: Vec<u8>,
    correlation_id: Option<String>,
}

/// Combined input for fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Raw bytes for parsing test
    raw_bytes: Vec<u8>,
    /// Structured message for creation test
    structured: FuzzMessage,
}

fuzz_target!(|input: FuzzInput| {
    // Test 1: Try parsing raw bytes as a serialized MeshMessage
    if let Ok(msg) = MeshMessage::from_bytes(&input.raw_bytes) {
        // If parsing succeeds, test serialization round-trip
        if let Ok(serialized) = msg.to_bytes() {
            // Should be able to parse again
            if let Ok(msg2) = MeshMessage::from_bytes(&serialized) {
                // Core fields should match
                assert_eq!(msg.from, msg2.from);
                assert_eq!(msg.to, msg2.to);
                assert_eq!(msg.payload, msg2.payload);
            }
        }

        // Test broadcast detection - should never panic
        let _ = msg.is_broadcast();
    }

    // Test 2: Create message from arbitrary structured input
    let category = match input.structured.category % 5 {
        0 => MessageCategory::Control,
        1 => MessageCategory::Task,
        2 => MessageCategory::Coordination,
        3 => MessageCategory::BulkData,
        _ => MessageCategory::Other,
    };

    let mut msg = MeshMessage::new(&input.structured.from, &input.structured.to, input.structured.payload.clone())
        .with_category(category);

    if let Some(cid) = &input.structured.correlation_id {
        msg = msg.with_correlation_id(cid.clone());
    }

    // Serialize and deserialize - should never panic
    if let Ok(bytes) = msg.to_bytes() {
        if let Ok(parsed) = MeshMessage::from_bytes(&bytes) {
            assert_eq!(parsed.from, input.structured.from);
            assert_eq!(parsed.to, input.structured.to);
            assert_eq!(parsed.payload, input.structured.payload);
            assert_eq!(parsed.category, category);
        }
    }

    // Test broadcast detection
    let is_broadcast = msg.is_broadcast();
    if input.structured.to.is_empty() || input.structured.to == "*" {
        assert!(is_broadcast, "Empty or '*' to should be broadcast");
    } else {
        assert!(!is_broadcast, "Non-empty to should not be broadcast");
    }
});
