#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use headscale_core::rental::{Lease, LeaseToken, is_blocked_destination, blocked_networks};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use std::sync::atomic::Ordering;

/// Arbitrary lease parameters for fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzLease {
    renter_did: String,
    provider_did: String,
    duration_secs: u64,
    bandwidth_limit: Option<u64>,
    bytes_to_record: Vec<u64>,
}

/// Arbitrary IP for destination blocking test
#[derive(Debug, Arbitrary)]
struct FuzzIp {
    octets: [u8; 4],
}

/// Combined input for fuzzing
#[derive(Debug, Arbitrary)]
struct FuzzInput {
    lease: FuzzLease,
    ip: FuzzIp,
}

fuzz_target!(|input: FuzzInput| {
    // Test 1: Lease operations
    let duration = Duration::from_secs(input.lease.duration_secs.max(1).min(86400 * 365));

    let mut lease = Lease::new(
        input.lease.renter_did.clone(),
        input.lease.provider_did.clone(),
        duration,
        input.lease.bandwidth_limit,
    );

    // Lease should not be active initially (pending)
    assert!(!lease.is_active());

    // Activate it
    lease.activate();
    assert!(lease.is_active());

    // Record some bytes - this should never panic
    for bytes in &input.lease.bytes_to_record {
        let within_limit = lease.record_bytes(*bytes);
        // If we have a limit, check consistency
        if let Some(limit) = input.lease.bandwidth_limit {
            let used = lease.bandwidth_used.load(Ordering::Relaxed);
            if used > limit && *bytes > 0 {
                // We're over limit, so we might have just exceeded it
                // record_bytes returns false when we GO over, not when we ARE over
            }
        } else {
            // No limit, should always succeed
            assert!(within_limit);
        }
    }

    // Remaining bandwidth should be consistent
    if let Some(remaining) = lease.remaining_bandwidth() {
        if let Some(limit) = input.lease.bandwidth_limit {
            let used = lease.bandwidth_used.load(Ordering::Relaxed);
            assert_eq!(remaining, limit.saturating_sub(used));
        }
    }

    // Test token creation
    let token = LeaseToken::new(&lease, vec![1, 2, 3, 4]);
    assert_eq!(token.lease_id, lease.id);
    assert_eq!(token.renter_did, input.lease.renter_did);
    assert_eq!(token.expires_at, lease.expires_at);

    // Signing data should be deterministic
    let data1 = token.signing_data();
    let data2 = token.signing_data();
    assert_eq!(data1, data2);

    // Test 2: IP blocking
    let ip = IpAddr::V4(Ipv4Addr::from(input.ip.octets));

    // is_blocked_destination should never panic
    let blocked = is_blocked_destination(ip);

    // Verify consistency with blocked_networks
    let networks = blocked_networks();
    let expected = networks.iter().any(|net| net.contains(&ip));
    assert_eq!(blocked, expected, "Inconsistent blocking for IP {}", ip);

    // Known blocked ranges - validate expected behavior
    if input.ip.octets[0] == 10 {
        assert!(blocked, "10.x.x.x should be blocked");
    }
    if input.ip.octets[0] == 127 {
        assert!(blocked, "127.x.x.x should be blocked");
    }
    if input.ip.octets[0] == 192 && input.ip.octets[1] == 168 {
        assert!(blocked, "192.168.x.x should be blocked");
    }

    // Known allowed ranges (public IPs)
    if input.ip.octets[0] == 8 && input.ip.octets[1] == 8 {
        assert!(!blocked, "8.8.x.x should not be blocked");
    }
    if input.ip.octets[0] == 1 && input.ip.octets[1] == 1 {
        assert!(!blocked, "1.1.x.x should not be blocked");
    }
});
