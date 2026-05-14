#![no_main]

use libfuzzer_sys::fuzz_target;
use headscale_core::derp::parse_derp_frame;

fuzz_target!(|data: &[u8]| {
    // Fuzz DERP frame parsing with arbitrary data
    // This should never panic, only return None for invalid data
    let _ = parse_derp_frame(data);
});
