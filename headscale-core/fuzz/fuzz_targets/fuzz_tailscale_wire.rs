#![no_main]

use headscale_api::tailscale_wire::wire::{
    stable_id_from_key, strip_key_prefix, HostInfo, MapRequest, MapResponse, RegisterRequest,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    round_trip_json::<RegisterRequest>(input);
    round_trip_json::<MapRequest>(input);
    round_trip_json::<MapResponse>(input);
    round_trip_json::<HostInfo>(input);

    let stable_id = stable_id_from_key(input);
    assert!(stable_id <= i64::MAX as u64);

    if let Some(stripped) = strip_key_prefix(input) {
        assert!(input.ends_with(stripped));
    }
});

fn round_trip_json<T>(input: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    if let Ok(value) = serde_json::from_str::<T>(input) {
        let encoded = serde_json::to_string(&value).expect("wire type serializes");
        let _ = serde_json::from_str::<T>(&encoded).expect("wire type round-trips");
    }
}
