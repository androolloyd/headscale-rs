#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[derive(Arbitrary, Debug)]
struct EndpointFuzzInput {
    peer_id: String,
    ip_bytes: [u8; 4],
    port: u16,
    priority: u8,
}

fuzz_target!(|input: EndpointFuzzInput| {
    use headscale_core::endpoint::{Endpoint, EndpointType, EndpointTracker};

    // Create an endpoint tracker
    let tracker = EndpointTracker::new();

    // Create an endpoint from fuzzed data
    let ip = IpAddr::V4(Ipv4Addr::new(
        input.ip_bytes[0],
        input.ip_bytes[1],
        input.ip_bytes[2],
        input.ip_bytes[3],
    ));
    let addr = SocketAddr::new(ip, input.port);

    // Create endpoint (should never panic)
    let endpoint = Endpoint::new(addr, EndpointType::Direct, input.priority);

    // Verify endpoint properties
    assert_eq!(endpoint.addr, addr);
    assert_eq!(endpoint.priority, input.priority);
    assert!(endpoint.is_valid()); // Fresh endpoint should be valid

    // Use tokio runtime for async operations
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    rt.block_on(async {
        // Add peer endpoint
        tracker.update_peer_endpoint(
            &input.peer_id,
            addr,
            EndpointType::Direct,
            input.priority,
        ).await;

        // Get endpoints should work
        let _ = tracker.get_peer_endpoints(&input.peer_id).await;

        // Get best endpoint should work
        let _ = tracker.get_best_endpoint(&input.peer_id).await;

        // Mark success should work
        tracker.mark_endpoint_success(&input.peer_id, addr, None).await;

        // Remove peer should work
        tracker.remove_peer(&input.peer_id).await;
    });
});
