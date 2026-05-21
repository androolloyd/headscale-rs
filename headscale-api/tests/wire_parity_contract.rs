use headscale_api::tailscale_wire::wire::{
    DerpMap, DnsConfig, HostInfo, MapNode, MapResponse, RegisterAuth, RegisterRequest,
    RegisterResponse, SimpleLogin, SimpleUser,
};
use serde_json::{Value, json};

fn json_keys(value: &Value) -> Vec<String> {
    let mut keys: Vec<String> = value
        .as_object()
        .expect("object")
        .keys()
        .map(ToString::to_string)
        .collect();
    keys.sort();
    keys
}

#[test]
fn register_request_accepts_headscale_go_auth_key_shape() {
    let raw = json!({
        "NodeKey": "nodekey:012345",
        "Auth": { "AuthKey": "octrapreauth-deadbeef" },
        "Hostinfo": { "Hostname": "linux-a", "OS": "linux", "OSVersion": "6.8" },
        "Followup": "auth"
    });

    let req: RegisterRequest = serde_json::from_value(raw).unwrap();
    assert_eq!(req.node_key, "nodekey:012345");
    assert_eq!(req.auth.unwrap().auth_key, "octrapreauth-deadbeef");
    assert_eq!(req.hostinfo.unwrap().os, "linux");
}

#[test]
fn register_response_uses_auth_url_and_id_acronyms() {
    let response = RegisterResponse {
        user: SimpleUser {
            id: 42,
            login_name: "alice@example.com".into(),
            display_name: "Alice".into(),
        },
        login: SimpleLogin {
            id: 42,
            provider: "preauth".into(),
            login_name: "alice@example.com".into(),
            display_name: "Alice".into(),
        },
        node_key_expired: false,
        auth_url: String::new(),
        machine_authorized: true,
        error: String::new(),
    };

    let value = serde_json::to_value(response).unwrap();
    assert_eq!(value["AuthURL"], "");
    assert!(value.get("AuthUrl").is_none());
    assert_eq!(value["User"]["ID"], 42);
    assert!(value["User"].get("Id").is_none());
    assert_eq!(value["Login"]["ID"], 42);
}

#[test]
fn map_response_emits_required_stock_client_fields() {
    let response = MapResponse {
        key_expiry_extension: 0,
        node: MapNode {
            id: 7,
            stable_id: "n7".into(),
            name: "linux-a.octra.test".into(),
            user: 42,
            key: "nodekey:aa".into(),
            machine: Some("mkey:bb".into()),
            addresses: vec!["100.64.0.7/32".into()],
            allowed_ips: vec!["100.64.0.7/32".into()],
            hostinfo: HostInfo {
                hostname: "linux-a".into(),
                os: "linux".into(),
                os_version: "6.8".into(),
            },
            machine_authorized: true,
            disco_key: Some("discokey:cc".into()),
            endpoints: vec!["198.51.100.7:41641".into()],
        },
        peers: Vec::new(),
        dns_config: DnsConfig::default(),
        derp_map: DerpMap::default(),
        domain: "octra.test".into(),
        keep_alive: true,
        node_key_expired: false,
        packet_filter: Vec::new(),
    };

    let value = serde_json::to_value(response).unwrap();
    let keys = json_keys(&value);
    for required in [
        "DERPMap",
        "DNSConfig",
        "Domain",
        "KeepAlive",
        "Node",
        "Peers",
    ] {
        assert!(keys.iter().any(|k| k == required), "missing {required}");
    }
    assert!(value.get("DerpMap").is_none());
    assert!(value.get("DnsConfig").is_none());
    assert_eq!(value["Node"]["ID"], 7);
    assert_eq!(value["Node"]["AllowedIPs"], json!(["100.64.0.7/32"]));
    assert_eq!(value["Node"]["DiscoKey"], "discokey:cc");
}

#[test]
fn register_auth_empty_default_still_serializes_auth_key() {
    let value = serde_json::to_value(RegisterAuth::default()).unwrap();
    assert_eq!(value, json!({ "AuthKey": "" }));
}
