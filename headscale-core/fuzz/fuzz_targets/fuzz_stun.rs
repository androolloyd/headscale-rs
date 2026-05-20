#![no_main]

use headscale_core::stun::{
    parse_binding_response, parse_mapped_address, parse_xor_mapped_address,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz STUN parsing functions with arbitrary data

    // Try parsing as a binding response with a dummy transaction ID
    let txn_id = [0u8; 12];
    let _ = parse_binding_response(data, &txn_id);

    // Try parsing as mapped address
    let _ = parse_mapped_address(data);

    // Try parsing as XOR mapped address (requires transaction ID for IPv6)
    let _ = parse_xor_mapped_address(data, &txn_id);
});
