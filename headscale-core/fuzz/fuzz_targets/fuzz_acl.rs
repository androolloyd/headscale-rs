#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use headscale_core::acl::{AclPolicy, AclEvaluator, AclContext, AclDestination, Action};
use std::net::{IpAddr, Ipv4Addr};

/// Arbitrary ACL context for fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzContext {
    src: String,
    src_ip_bytes: [u8; 4],
    tags: Vec<String>,
    groups: Vec<String>,
}

/// Arbitrary destination for fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzDestination {
    dst_ip_bytes: [u8; 4],
    port: Option<u16>,
}

/// Combined input for structured fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    /// Raw JSON-like data for parsing test
    json_like: Vec<u8>,
    /// Structured context
    ctx: FuzzContext,
    /// Structured destination
    dst: FuzzDestination,
}

fuzz_target!(|input: FuzzInput| {
    // Test 1: Try parsing as JSON ACL policy
    if let Ok(json_str) = std::str::from_utf8(&input.json_like) {
        if let Ok(policy) = AclPolicy::from_json(json_str) {
            // If parsing succeeds, test validation
            let _ = policy.validate();

            // Test serialization round-trip
            if let Ok(serialized) = policy.to_json() {
                // Should be able to parse again
                let _ = AclPolicy::from_json(&serialized);
            }

            // Test evaluation with the parsed policy
            let evaluator = AclEvaluator::new(policy);

            // Test with some basic contexts
            let ctx = AclContext::from_node("test-node", "100.64.0.1".parse().unwrap());
            let dst = AclDestination::new("100.64.0.2".parse().unwrap(), Some(443));
            let _ = evaluator.evaluate(&ctx, &dst);
        }
    }

    // Test 2: Structured fuzzing with default policy
    let evaluator = AclEvaluator::allow_fleet();

    // Build context
    let src_ip = IpAddr::V4(Ipv4Addr::from(input.ctx.src_ip_bytes));
    let mut ctx = AclContext::from_node(&input.ctx.src, src_ip);
    ctx = ctx.with_tags(input.ctx.tags.into_iter());
    for group in input.ctx.groups {
        ctx = ctx.with_group(&group);
    }

    // Build destination
    let dst_ip = IpAddr::V4(Ipv4Addr::from(input.dst.dst_ip_bytes));
    let dst = AclDestination::new(dst_ip, input.dst.port);

    // Evaluate - should never panic
    let result = evaluator.evaluate(&ctx, &dst);

    // Result should be one of the valid actions
    assert!(matches!(result, Action::Accept | Action::Deny));

    // With allow-fleet policy, everything should be accepted
    assert_eq!(result, Action::Accept, "Default allow-fleet should accept all");

    // Test 3: Deny-all policy
    let deny_evaluator = AclEvaluator::deny_all();
    let deny_result = deny_evaluator.evaluate(&ctx, &dst);
    assert_eq!(deny_result, Action::Deny, "Deny-all should deny all");

    // Test convenience methods
    let _ = evaluator.can_reach(&ctx, dst_ip);
    if let Some(port) = input.dst.port {
        let _ = evaluator.can_reach_port(&ctx, dst_ip, port);
    }
});
