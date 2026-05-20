#![no_main]

use headscale_core::packet::{parse_destination, parse_source};
use headscale_core::tun_device::{parse_ipv4_destination, parse_ipv4_source};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz IP packet parsing functions
    // These should never panic on any input

    // Parse IPv4/IPv6 destination from packet
    let _ = parse_destination(data);

    // Parse IPv4/IPv6 source from packet
    let _ = parse_source(data);

    // Parse IPv4-specific functions
    let _ = parse_ipv4_destination(data);
    let _ = parse_ipv4_source(data);
});
