#![no_main]

use boringtun::noise::Tunn;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz WireGuard packet parsing
    // This tests boringtun's packet parsing with arbitrary data

    // Try to parse as an incoming WireGuard packet
    let _ = Tunn::parse_incoming_packet(data);

    // Also try to extract destination address (for IP packets inside WG)
    let _ = Tunn::dst_address(data);
});
