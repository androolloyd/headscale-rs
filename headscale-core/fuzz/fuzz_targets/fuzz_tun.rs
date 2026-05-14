#![no_main]

use libfuzzer_sys::fuzz_target;
use headscale_core::tun_device::{parse_ipv4_destination, parse_ipv4_source};

fuzz_target!(|data: &[u8]| {
    // Fuzz TUN device packet parsing
    // These functions should gracefully handle any malformed input

    // Parse destination from IP packet
    let _ = parse_ipv4_destination(data);

    // Parse source from IP packet
    let _ = parse_ipv4_source(data);

    // Verify parsing is consistent across multiple calls
    let dst1 = parse_ipv4_destination(data);
    let dst2 = parse_ipv4_destination(data);
    assert_eq!(dst1, dst2, "Parsing should be deterministic");

    let src1 = parse_ipv4_source(data);
    let src2 = parse_ipv4_source(data);
    assert_eq!(src1, src2, "Parsing should be deterministic");
});
