#![no_main]

use headscale_api::tailscale_wire::wire::{
    stable_id_from_key, strip_key_prefix, DerpMap, DnsConfig, HostInfo, MapRequest, MapResponse,
    RegisterRequest, RegisterResponse,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let _ = round_trip_json::<RegisterRequest>(input);
    if let Some(response) = round_trip_json::<RegisterResponse>(input) {
        assert_register_response_wire_names(&response);
    }
    let _ = round_trip_json::<MapRequest>(input);
    if let Some(response) = round_trip_json::<MapResponse>(input) {
        assert_map_response_wire_names(&response);
    }
    let _ = round_trip_json::<HostInfo>(input);
    if let Some(derp_map) = round_trip_json::<DerpMap>(input) {
        assert_derp_map_wire_names(&derp_map);
    }
    let _ = round_trip_json::<DnsConfig>(input);

    let stable_id = stable_id_from_key(input);
    assert!(stable_id <= i64::MAX as u64);

    if let Some(stripped) = strip_key_prefix(input) {
        assert!(input.ends_with(stripped));
    }
});

fn round_trip_json<T>(input: &str) -> Option<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    if let Ok(value) = serde_json::from_str::<T>(input) {
        let encoded = serde_json::to_string(&value).expect("wire type serializes");
        let _ = serde_json::from_str::<T>(&encoded).expect("wire type round-trips");
        Some(value)
    } else {
        None
    }
}

fn assert_register_response_wire_names(response: &RegisterResponse) {
    let encoded = serde_json::to_value(response).expect("register response serializes");
    assert_object_field(&encoded, "User");
    assert_object_field(&encoded, "Login");
    assert_object_field(&encoded, "MachineAuthorized");
    assert_object_field(&encoded, "AuthURL");
    assert_no_object_field(&encoded, "AuthUrl");
}

fn assert_map_response_wire_names(response: &MapResponse) {
    let encoded = serde_json::to_value(response).expect("map response serializes");
    assert_no_object_field(&encoded, "DerpMap");
    assert_no_object_field(&encoded, "DnsConfig");
    assert_no_object_field(&encoded, "SshPolicy");

    if response.derp_map.is_some() {
        assert_object_field(&encoded, "DERPMap");
    }
    if response.dns_config.is_some() {
        assert_object_field(&encoded, "DNSConfig");
    }
    if response.ssh_policy.is_some() {
        assert_object_field(&encoded, "SSHPolicy");
    }
}

fn assert_derp_map_wire_names(derp_map: &DerpMap) {
    let encoded = serde_json::to_value(derp_map).expect("DERP map serializes");
    assert_object_field(&encoded, "omitDefaultRegions");
    assert_no_object_field(&encoded, "OmitDefaultRegions");
}

fn assert_object_field(value: &serde_json::Value, field: &str) {
    let Some(object) = value.as_object() else {
        return;
    };
    assert!(object.contains_key(field), "missing wire field {field}");
}

fn assert_no_object_field(value: &serde_json::Value, field: &str) {
    let Some(object) = value.as_object() else {
        return;
    };
    assert!(!object.contains_key(field), "unexpected wire field {field}");
}
