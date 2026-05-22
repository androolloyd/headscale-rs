//! Serde round-trip + JSON-shape coverage for the Tailscale wire
//! types declared in `headscale_api::tailscale_wire::wire`.
//!
//! The wire-format contract is byte-identical with upstream
//! `tailscale/tailcfg/tailcfg.go`; this file verifies the field
//! names, the `Option<...>`/`skip_serializing_if` shape, and the
//! all-caps acronym renames (`OS`/`IPv4`/`AuthURL`/`DNSConfig`/
//! `DERPMap`/`DiscoKey`) every existing #[serde(rename = …)] declares.
//!
//! Companion to the in-module unit tests in `src/tailscale_wire/wire.rs`
//! — we deliberately don't modify that file (in-flight ACL changes).

use std::collections::BTreeMap;

use headscale_api::tailscale_wire::MachineRecord;
use headscale_api::tailscale_wire::wire::{
    ClientVersion, ControlDialPlan, ControlIpCandidate, DebugConfig, DerpMap, DerpRegion,
    DerpRegionNode, DisplayMessage, DisplayMessageAction, DnsConfig, DnsResolver, FilterRule,
    HostInfo, MapNode, MapRequest, MapResponse, NetInfo, NetPortRange, PeerChange, PingRequest,
    PortRange, RegisterAuth, RegisterRequest, RegisterResponse, SimpleLogin, SimpleUser, SshAction,
    SshPolicy, SshPrincipal, SshRule, TkaInfo, UserProfile, stable_id_from_key, strip_key_prefix,
};
use serde_json::Value;

// ---------------------------------------------------------------------------
// strip_key_prefix
// ---------------------------------------------------------------------------

#[test]
fn strip_key_prefix_returns_body_for_each_prefix() {
    assert_eq!(strip_key_prefix("mkey:deadbeef"), Some("deadbeef"));
    assert_eq!(strip_key_prefix("nodekey:cafe"), Some("cafe"));
    assert_eq!(strip_key_prefix("discokey:0102"), Some("0102"));
}

#[test]
fn strip_key_prefix_none_on_unknown() {
    assert_eq!(strip_key_prefix("bogus:abcd"), None);
    assert_eq!(strip_key_prefix("just-hex"), None);
    assert_eq!(strip_key_prefix(""), None);
}

#[test]
fn strip_key_prefix_handles_empty_body() {
    // Prefix-only inputs are still recognised — body is the empty
    // string. Callers downstream typically reject empty hex.
    assert_eq!(strip_key_prefix("mkey:"), Some(""));
    assert_eq!(strip_key_prefix("nodekey:"), Some(""));
}

// ---------------------------------------------------------------------------
// stable_id_from_key
// ---------------------------------------------------------------------------

#[test]
fn stable_id_is_positive_signed_63_bit_safe() {
    // The upstream consumer treats the value as a Go `int64`; the top
    // bit must always be clear so the serialised number never trips
    // `cannot unmarshal number X into NodeID`.
    let max_signed = (1u64 << 63) - 1;
    for s in [
        "0",
        "a",
        "abcdef",
        "ffffffffffffffffffffffffffffffff",
        &"f".repeat(128),
    ] {
        let v = stable_id_from_key(s);
        assert!(v <= max_signed, "value {v} exceeds int64::MAX for {s:?}");
    }
}

#[test]
fn stable_id_distinct_for_distinct_inputs() {
    let a = stable_id_from_key("aaaa");
    let b = stable_id_from_key("aaab");
    let c = stable_id_from_key("aaba");
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
}

// ---------------------------------------------------------------------------
// HostInfo — all-caps OS / OSVersion renames
// ---------------------------------------------------------------------------

#[test]
fn hostinfo_emits_pascal_case_with_all_caps_os() {
    let h = HostInfo {
        hostname: "h1".into(),
        os: "linux".into(),
        os_version: "6.6".into(),
        routable_ips: vec!["10.0.0.0/24".into()],
        request_tags: vec!["tag:server".into()],
        net_info: Some(NetInfo { preferred_derp: 7 }),
    };
    let v: Value = serde_json::to_value(&h).unwrap();
    assert_eq!(v["Hostname"], "h1");
    // `OS` not `Os`.
    assert_eq!(v["OS"], "linux");
    assert!(v.get("Os").is_none(), "must NOT emit lowercase-Os variant");
    // `OSVersion` not `OsVersion`.
    assert_eq!(v["OSVersion"], "6.6");
    assert_eq!(v["RoutableIPs"], serde_json::json!(["10.0.0.0/24"]));
    assert_eq!(v["RequestTags"], serde_json::json!(["tag:server"]));
    assert_eq!(v["NetInfo"]["PreferredDERP"], 7);
    assert!(v.get("OsVersion").is_none());
}

#[test]
fn hostinfo_round_trip_preserves_unset_fields_as_empty_strings() {
    let j = r"{}";
    let h: HostInfo = serde_json::from_str(j).unwrap();
    assert_eq!(h.hostname, "");
    assert_eq!(h.os, "");
    assert_eq!(h.os_version, "");
    assert!(h.request_tags.is_empty());
    assert!(h.net_info.is_none());
}

#[test]
fn hostinfo_round_trips_request_tags() {
    let h: HostInfo = serde_json::from_str(r#"{"RequestTags":["tag:server","tag:db"]}"#).unwrap();
    assert_eq!(h.request_tags, vec!["tag:server", "tag:db"]);

    let v: Value = serde_json::to_value(&h).unwrap();
    assert_eq!(
        v["RequestTags"],
        serde_json::json!(["tag:server", "tag:db"])
    );
}

#[test]
fn hostinfo_round_trips_net_info_preferred_derp() {
    let h: HostInfo = serde_json::from_str(r#"{"NetInfo":{"PreferredDERP":901}}"#).unwrap();
    assert_eq!(
        h.net_info.as_ref().map(|net_info| net_info.preferred_derp),
        Some(901)
    );

    let v: Value = serde_json::to_value(&h).unwrap();
    assert_eq!(v["NetInfo"]["PreferredDERP"], 901);
}

// ---------------------------------------------------------------------------
// RegisterRequest / RegisterAuth / RegisterResponse
// ---------------------------------------------------------------------------

#[test]
fn register_request_optional_fields_default_to_none() {
    let j = r#"{"NodeKey":"nodekey:cafe"}"#;
    let r: RegisterRequest = serde_json::from_str(j).unwrap();
    assert_eq!(r.node_key, "nodekey:cafe");
    assert!(r.auth.is_none());
    assert!(r.hostinfo.is_none());
    assert!(r.followup.is_none());
    assert!(!r.ephemeral);
    assert!(r.expiry.is_none());
}

#[test]
fn register_request_accepts_ephemeral_and_expiry() {
    let j = r#"{
        "NodeKey":"nodekey:cafe",
        "Ephemeral": true,
        "Expiry": "2026-06-01T00:00:00Z"
    }"#;
    let r: RegisterRequest = serde_json::from_str(j).unwrap();
    assert!(r.ephemeral);
    assert!(r.expiry.is_some());
}

#[test]
fn register_auth_default_is_empty_string() {
    let a = RegisterAuth::default();
    assert_eq!(a.auth_key, "");
    let v = serde_json::to_value(&a).unwrap();
    assert_eq!(v["AuthKey"], "");
}

#[test]
fn register_response_emits_auth_url_all_caps() {
    let r = RegisterResponse {
        user: SimpleUser {
            id: 1,
            login_name: "alice".into(),
            display_name: "Alice".into(),
        },
        login: SimpleLogin {
            id: 1,
            provider: "preauth".into(),
            login_name: "alice".into(),
            display_name: "Alice".into(),
        },
        node_key_expired: false,
        auth_url: String::new(),
        machine_authorized: true,
        error: String::new(),
    };
    let v: Value = serde_json::to_value(&r).unwrap();
    // The all-caps rename is load-bearing — Go's decoder treats
    // `AuthUrl` as "extra unknown" and pushes the client into the
    // browser-auth branch.
    assert!(v.get("AuthURL").is_some());
    assert!(v.get("AuthUrl").is_none());
    // SimpleUser.ID — single-letter all-caps.
    assert_eq!(v["User"]["ID"], 1);
    assert!(v["User"].get("Id").is_none());
    assert_eq!(v["Login"]["ID"], 1);
    assert!(v.get("Error").is_none());
}

// ---------------------------------------------------------------------------
// MapRequest — DiscoKey / Endpoints Wall-7 fields
// ---------------------------------------------------------------------------

#[test]
fn map_request_disco_key_round_trip() {
    let r = MapRequest {
        version: 39,
        stream: true,
        compress: "zstd".into(),
        keep_alive: true,
        hostinfo: None,
        omit_peers: false,
        node_key: "nodekey:dead".into(),
        map_session_handle: "session-1".into(),
        map_session_seq: 7,
        disco_key: Some("discokey:beef".into()),
        hardware_attestation_key: None,
        hardware_attestation_key_signature: String::new(),
        hardware_attestation_key_signature_timestamp: None,
        endpoints: Some(vec!["198.51.100.1:41641".into()]),
        endpoint_types: vec![1],
        read_only: true,
        tka_head: String::new(),
        debug_flags: Vec::new(),
    };
    let j = serde_json::to_string(&r).unwrap();
    // PascalCase + explicit `DiscoKey` rename.
    assert!(j.contains("\"DiscoKey\":\"discokey:beef\""));
    assert!(j.contains("\"Endpoints\":[\"198.51.100.1:41641\"]"));
    assert!(j.contains("\"MapSessionHandle\":\"session-1\""));
    assert!(j.contains("\"EndpointTypes\":[1]"));
    let back: MapRequest = serde_json::from_str(&j).unwrap();
    assert_eq!(back.disco_key.as_deref(), Some("discokey:beef"));
    assert_eq!(back.endpoints.as_ref().unwrap().len(), 1);
    assert_eq!(back.endpoint_types, vec![1]);
    assert_eq!(back.map_session_seq, 7);
}

#[test]
fn map_request_disco_key_skipped_when_none() {
    let r = MapRequest {
        version: 39,
        stream: false,
        compress: String::new(),
        keep_alive: false,
        hostinfo: None,
        omit_peers: false,
        node_key: "nodekey:dead".into(),
        map_session_handle: String::new(),
        map_session_seq: 0,
        disco_key: None,
        hardware_attestation_key: None,
        hardware_attestation_key_signature: String::new(),
        hardware_attestation_key_signature_timestamp: None,
        endpoints: None,
        endpoint_types: Vec::new(),
        read_only: false,
        tka_head: String::new(),
        debug_flags: Vec::new(),
    };
    let j = serde_json::to_string(&r).unwrap();
    // `skip_serializing_if = "Option::is_none"` ⇒ no field emitted.
    assert!(
        !j.contains("DiscoKey"),
        "DiscoKey must be omitted when None"
    );
}

#[test]
fn map_request_endpoints_defaults_to_none_when_absent() {
    let j = r#"{"NodeKey":"nodekey:cafe"}"#;
    let r: MapRequest = serde_json::from_str(j).unwrap();
    assert!(r.endpoints.is_none());
    assert!(r.disco_key.is_none());
}

// ---------------------------------------------------------------------------
// MapNode — DiscoKey, Endpoints, MachineAuthorized
// ---------------------------------------------------------------------------

fn mk_node() -> MapNode {
    MapNode {
        id: 7,
        stable_id: "n7".into(),
        name: "h1.octra.test".into(),
        user: 42,
        key: "nodekey:aa".into(),
        machine: Some("mkey:bb".into()),
        addresses: vec!["100.64.0.5/32".into()],
        allowed_ips: vec!["100.64.0.5/32".into()],
        primary_routes: Vec::new(),
        hostinfo: HostInfo::default(),
        created: None,
        key_expiry: None,
        cap: 0,
        tags: Vec::new(),
        last_seen: None,
        online: None,
        machine_authorized: true,
        capabilities: Vec::new(),
        cap_map: BTreeMap::new(),
        expired: false,
        home_derp: 0,
        disco_key: Some("discokey:cc".into()),
        endpoints: vec!["198.51.100.1:41641".into()],
        ..MapNode::default()
    }
}

#[test]
fn map_node_emits_all_caps_renames() {
    let v: Value = serde_json::to_value(mk_node()).unwrap();
    assert!(v.get("ID").is_some());
    assert!(v.get("StableID").is_some());
    assert!(v.get("User").is_some());
    assert!(v.get("AllowedIPs").is_some());
    assert!(
        v.get("AllowedIps").is_none(),
        "lowercase-IPs variant must not appear"
    );
    assert!(v.get("DiscoKey").is_some());
    assert!(v.get("Endpoints").is_some());
}

#[test]
fn map_node_round_trips_route_tag_and_cap_metadata() {
    let mut n = mk_node();
    n.primary_routes = vec!["10.0.0.0/24".into()];
    n.tags = vec!["tag:web".into()];
    n.online = Some(true);
    n.cap = 74;
    n.capabilities = vec!["https://tailscale.com/cap/ssh".into()];
    n.cap_map.insert("funnel".into(), Vec::new());
    n.expired = true;
    n.home_derp = 900;
    n.sharer = 88;
    n.key_signature = "AQI=".into();
    n.legacy_derp_string = "127.3.3.40:900".into();
    n.unsigned_peer_api_only = true;
    n.computed_name = "h1".into();
    n.computed_name_with_host = "h1 (host-h1)".into();
    n.data_plane_audit_log_id = "node-log-id".into();
    n.self_node_v4_masq_addr_for_this_peer = Some("100.99.99.99".into());
    n.self_node_v6_masq_addr_for_this_peer = Some("fd7a:115c:a1e0::99".into());
    n.is_wire_guard_only = true;
    n.is_jailed = true;
    n.exit_node_dns_resolvers = vec![DnsResolver {
        addr: "1.1.1.1".into(),
        bootstrap_resolution: Vec::new(),
        use_with_exit_node: true,
    }];

    let v: Value = serde_json::to_value(&n).unwrap();
    assert_eq!(v["PrimaryRoutes"][0], "10.0.0.0/24");
    assert_eq!(v["Tags"][0], "tag:web");
    assert_eq!(v["Online"], true);
    assert_eq!(v["Cap"], 74);
    assert_eq!(v["Capabilities"][0], "https://tailscale.com/cap/ssh");
    assert!(v["CapMap"]["funnel"].as_array().unwrap().is_empty());
    assert_eq!(v["Expired"], true);
    assert_eq!(v["HomeDERP"], 900);
    assert_eq!(v["Sharer"], 88);
    assert_eq!(v["KeySignature"], "AQI=");
    assert_eq!(v["DERP"], "127.3.3.40:900");
    assert_eq!(v["UnsignedPeerAPIOnly"], true);
    assert_eq!(v["DataPlaneAuditLogID"], "node-log-id");
    assert_eq!(v["SelfNodeV4MasqAddrForThisPeer"], "100.99.99.99");
    assert_eq!(v["SelfNodeV6MasqAddrForThisPeer"], "fd7a:115c:a1e0::99");
    assert_eq!(v["IsWireGuardOnly"], true);
    assert_eq!(v["IsJailed"], true);
    assert_eq!(v["ExitNodeDNSResolvers"][0]["Addr"], "1.1.1.1");
    assert_eq!(v["ExitNodeDNSResolvers"][0]["UseWithExitNode"], true);

    let back: MapNode = serde_json::from_value(v).unwrap();
    assert_eq!(back.primary_routes, vec!["10.0.0.0/24"]);
    assert_eq!(back.tags, vec!["tag:web"]);
    assert_eq!(back.online, Some(true));
    assert!(back.cap_map.contains_key("funnel"));
    assert_eq!(back.legacy_derp_string, "127.3.3.40:900");
    assert_eq!(
        back.self_node_v6_masq_addr_for_this_peer.as_deref(),
        Some("fd7a:115c:a1e0::99")
    );
    assert_eq!(back.exit_node_dns_resolvers[0].addr, "1.1.1.1");
}

#[test]
fn map_node_empty_endpoints_skipped() {
    let mut n = mk_node();
    n.endpoints.clear();
    let j = serde_json::to_string(&n).unwrap();
    assert!(
        !j.contains("\"Endpoints\""),
        "empty Endpoints must be omitted"
    );
}

#[test]
fn map_node_none_machine_skipped() {
    let mut n = mk_node();
    n.machine = None;
    let j = serde_json::to_string(&n).unwrap();
    assert!(!j.contains("\"Machine\""), "None Machine must be omitted");
}

#[test]
fn map_node_disco_key_none_skipped() {
    let mut n = mk_node();
    n.disco_key = None;
    let j = serde_json::to_string(&n).unwrap();
    assert!(!j.contains("\"DiscoKey\""), "None DiscoKey must be omitted");
}

#[test]
fn map_node_round_trip_preserves_wall7_fields() {
    let original = mk_node();
    let j = serde_json::to_string(&original).unwrap();
    let back: MapNode = serde_json::from_str(&j).unwrap();
    assert_eq!(back.disco_key, original.disco_key);
    assert_eq!(back.endpoints, original.endpoints);
    assert_eq!(back.machine_authorized, original.machine_authorized);
}

#[test]
fn map_node_machine_authorized_false_skipped() {
    let mut n = mk_node();
    n.machine_authorized = false;
    let j = serde_json::to_string(&n).unwrap();
    assert!(
        !j.contains("\"MachineAuthorized\""),
        "false MachineAuthorized must be omitted"
    );
}

// ---------------------------------------------------------------------------
// MapResponse — DERPMap, DNSConfig, PacketFilter
// ---------------------------------------------------------------------------

#[test]
fn map_response_emits_all_caps_derp_and_dns() {
    let r = MapResponse {
        node: Some(mk_node()),
        peers: vec![],
        user_profiles: Vec::new(),
        dns_config: Some(DnsConfig::default()),
        derp_map: Some(DerpMap::default()),
        domain: "octra.test".into(),
        keep_alive: true,
        packet_filter: vec![],
        ssh_policy: None,
        node_key_expired: false,
        ..MapResponse::default()
    };
    let v: Value = serde_json::to_value(&r).unwrap();
    assert!(v.get("DNSConfig").is_some(), "DNSConfig (all-caps)");
    assert!(v.get("DnsConfig").is_none(), "must not emit DnsConfig");
    assert!(v.get("DERPMap").is_some());
    assert!(v.get("DerpMap").is_none());
    // PacketFilter skipped when empty (skip_serializing_if).
    assert!(
        v.get("PacketFilter").is_none(),
        "empty PacketFilter must be skipped"
    );
}

#[test]
fn map_response_packet_filter_populated_when_nonempty() {
    let r = MapResponse {
        node: Some(mk_node()),
        peers: vec![],
        user_profiles: Vec::new(),
        dns_config: Some(DnsConfig::default()),
        derp_map: Some(DerpMap::default()),
        domain: "octra.test".into(),
        keep_alive: true,
        packet_filter: vec![FilterRule {
            src_ips: vec!["*".into()],
            dst_ports: vec![NetPortRange {
                ip: "*".into(),
                ports: PortRange {
                    first: 0,
                    last: 65535,
                },
            }],
            ip_proto: vec![],
        }],
        ssh_policy: None,
        node_key_expired: false,
        ..MapResponse::default()
    };
    let v: Value = serde_json::to_value(&r).unwrap();
    let pf = v.get("PacketFilter").expect("PacketFilter present");
    assert!(pf.is_array());
    let first = &pf[0];
    // FilterRule.SrcIPs all-caps; IPProto omitted because empty.
    assert!(first.get("SrcIPs").is_some());
    assert!(first.get("SrcIps").is_none());
    assert!(first.get("IPProto").is_none(), "empty IPProto skipped");
    // NetPortRange.IP all-caps.
    let dp = &first["DstPorts"][0];
    assert!(dp.get("IP").is_some());
    assert!(dp.get("Ip").is_none());
}

#[test]
fn map_response_user_profiles_round_trip() {
    let mut r = MapResponse {
        node: Some(mk_node()),
        peers: vec![],
        user_profiles: vec![UserProfile {
            id: 42,
            login_name: "alice@example.com".into(),
            display_name: "Alice".into(),
            profile_pic_url: "https://example.com/alice.png".into(),
        }],
        dns_config: Some(DnsConfig::default()),
        derp_map: Some(DerpMap::default()),
        domain: "octra.test".into(),
        keep_alive: true,
        packet_filter: vec![],
        ssh_policy: None,
        node_key_expired: false,
        ..MapResponse::default()
    };
    let v: Value = serde_json::to_value(&r).unwrap();
    assert_eq!(v["UserProfiles"][0]["ID"], 42);
    assert_eq!(
        v["UserProfiles"][0]["ProfilePicURL"],
        "https://example.com/alice.png"
    );

    r.user_profiles.clear();
    let v: Value = serde_json::to_value(&r).unwrap();
    assert!(v.get("UserProfiles").is_none());
}

#[test]
fn ssh_policy_serialises_tailcfg_shape() {
    let mut ssh_users = BTreeMap::new();
    ssh_users.insert("*".to_string(), "=".to_string());
    ssh_users.insert("root".to_string(), String::new());
    let policy = SshPolicy {
        rules: vec![SshRule {
            principals: vec![SshPrincipal {
                node_ip: "100.64.0.3".into(),
                ..SshPrincipal::default()
            }],
            ssh_users,
            action: SshAction {
                accept: true,
                session_duration: 86_400_000_000_000,
                allow_agent_forwarding: true,
                allow_local_port_forwarding: true,
                allow_remote_port_forwarding: true,
                ..SshAction::default()
            },
            ..SshRule::default()
        }],
    };
    let v = serde_json::to_value(policy).unwrap();
    assert!(v.get("rules").is_some());
    let rule = &v["rules"][0];
    assert_eq!(rule["principals"][0]["nodeIP"], "100.64.0.3");
    assert!(rule["principals"][0].get("nodeIp").is_none());
    assert_eq!(rule["sshUsers"]["*"], "=");
    assert_eq!(rule["sshUsers"]["root"], "");
    assert_eq!(rule["action"]["accept"], true);
    assert_eq!(rule["action"]["sessionDuration"], 86_400_000_000_000_i64);
}

#[test]
fn map_response_emits_ssh_policy_all_caps_name() {
    let r = MapResponse {
        node: Some(mk_node()),
        peers: vec![],
        user_profiles: Vec::new(),
        dns_config: Some(DnsConfig::default()),
        derp_map: Some(DerpMap::default()),
        domain: "octra.test".into(),
        keep_alive: true,
        packet_filter: vec![],
        ssh_policy: Some(SshPolicy { rules: Vec::new() }),
        node_key_expired: false,
        ..MapResponse::default()
    };
    let v: Value = serde_json::to_value(&r).unwrap();
    assert!(v.get("SSHPolicy").is_some());
    assert!(v.get("SshPolicy").is_none());
}

#[test]
fn map_response_delta_debug_and_control_fields_round_trip() {
    let mut packet_filters = BTreeMap::new();
    packet_filters.insert(
        "base".to_string(),
        Some(vec![FilterRule {
            src_ips: vec!["100.64.0.1/32".into()],
            dst_ports: vec![NetPortRange {
                ip: "100.64.0.2/32".into(),
                ports: PortRange {
                    first: 22,
                    last: 22,
                },
            }],
            ip_proto: vec![6],
        }]),
    );
    packet_filters.insert("old".to_string(), None);

    let mut display_messages = BTreeMap::new();
    display_messages.insert(
        "router-unhealthy".to_string(),
        Some(DisplayMessage {
            title: "Router unhealthy".into(),
            text: "IP forwarding is disabled.".into(),
            severity: "medium".into(),
            impacts_connectivity: true,
            primary_action: Some(DisplayMessageAction {
                url: "https://example.com/fix".into(),
                label: "Open".into(),
            }),
        }),
    );
    display_messages.insert("old-warning".to_string(), None);

    let mut peer_seen_change = BTreeMap::new();
    peer_seen_change.insert(2, true);
    let mut online_change = BTreeMap::new();
    online_change.insert(2, false);

    let r = MapResponse {
        map_session_handle: "sess-1".into(),
        seq: 11,
        keep_alive: true,
        ping_request: Some(PingRequest {
            url: "https://control.example/ping/1".into(),
            url_is_noise: true,
            log: true,
            types: "TSMP".into(),
            ip: "100.64.0.2".into(),
            payload: "AQI=".into(),
        }),
        pop_browser_url: "https://control.example/login".into(),
        peers_changed: vec![mk_node()],
        peers_removed: vec![3],
        peers_changed_patch: vec![PeerChange {
            node_id: 2,
            derp_region: 1,
            cap: 99,
            endpoints: vec!["198.51.100.2:41641".into()],
            key: Some("nodekey:bb".into()),
            key_signature: "AQI=".into(),
            disco_key: Some("discokey:cc".into()),
            online: Some(false),
            ..PeerChange::default()
        }],
        peer_seen_change,
        online_change,
        packet_filters,
        health: Some(vec!["control-plane-warning".into()]),
        display_messages,
        control_time: Some(
            chrono::DateTime::parse_from_rfc3339("2026-05-21T12:34:56Z")
                .unwrap()
                .into(),
        ),
        tka_info: Some(TkaInfo {
            head: "aum-head".into(),
            disabled: false,
        }),
        domain_data_plane_audit_log_id: "tailnet-log-id".into(),
        debug: Some(DebugConfig {
            sleep_seconds: 1.5,
            disable_log_tail: true,
            exit: Some(5),
        }),
        control_dial_plan: Some(ControlDialPlan {
            candidates: vec![ControlIpCandidate {
                ip: "203.0.113.10".into(),
                ace_host: "ace.example.com".into(),
                dial_start_delay_sec: 0.25,
                dial_timeout_sec: 4.5,
                priority: 10,
            }],
        }),
        client_version: Some(ClientVersion {
            latest_version: "1.99.0".into(),
            notify: true,
            notify_url: "https://tailscale.com/download".into(),
            notify_text: "Update available".into(),
            ..ClientVersion::default()
        }),
        collect_services: Some(true),
        deprecated_default_auto_update: Some(true),
        ..MapResponse::default()
    };

    let v: Value = serde_json::to_value(&r).unwrap();
    assert_eq!(v["MapSessionHandle"], "sess-1");
    assert_eq!(v["PingRequest"]["URL"], "https://control.example/ping/1");
    assert_eq!(v["PingRequest"]["URLIsNoise"], true);
    assert_eq!(v["PopBrowserURL"], "https://control.example/login");
    assert_eq!(v["PeersChangedPatch"][0]["NodeID"], 2);
    assert_eq!(v["PeersChangedPatch"][0]["DiscoKey"], "discokey:cc");
    assert!(v["PacketFilters"]["old"].is_null());
    assert!(v["DisplayMessages"]["old-warning"].is_null());
    assert_eq!(v["TKAInfo"]["Head"], "aum-head");
    assert_eq!(v["ControlDialPlan"]["Candidates"][0]["IP"], "203.0.113.10");
    assert_eq!(
        v["ControlDialPlan"]["Candidates"][0]["ACEHost"],
        "ace.example.com"
    );
    assert_eq!(
        v["ClientVersion"]["NotifyURL"],
        "https://tailscale.com/download"
    );
    assert_eq!(v["DefaultAutoUpdate"], true);

    let back: MapResponse = serde_json::from_value(v).unwrap();
    assert_eq!(back.seq, 11);
    assert_eq!(back.peers_removed, vec![3]);
    assert_eq!(back.peer_seen_change.get(&2), Some(&true));
    assert_eq!(back.online_change.get(&2), Some(&false));
    assert!(back.packet_filters["old"].is_none());
    assert!(back.display_messages["old-warning"].is_none());
}

// ---------------------------------------------------------------------------
// DerpRegion / DerpRegionNode — all-caps DERP/STUN/IPv4/IPv6
// ---------------------------------------------------------------------------

#[test]
fn derp_region_round_trip_preserves_region_id_field_name() {
    let r = DerpRegion {
        region_id: 1,
        region_code: "oct-1".into(),
        region_name: "Octra Region 1".into(),
        avoid: false,
        nodes: vec![DerpRegionNode {
            name: "1a".into(),
            region_id: 1,
            host_name: "derp.octra.test".into(),
            ipv4: "198.51.100.10".into(),
            ipv6: String::new(),
            derp_port: 0,
            stun_port: 0,
            stun_only: false,
            insecure_for_tests: true,
        }],
    };
    let v: Value = serde_json::to_value(&r).unwrap();
    assert!(v.get("RegionID").is_some(), "RegionID (all-caps)");
    assert!(v.get("RegionId").is_none());
    let n0 = &v["Nodes"][0];
    assert!(n0.get("RegionID").is_some());
    assert!(n0.get("IPv4").is_some());
    assert!(
        n0.get("IPv6").is_none(),
        "empty IPv6 must be skipped (String::is_empty)"
    );
    // DERPPort / STUNPort zero ⇒ omitted.
    assert!(n0.get("DERPPort").is_none(), "DERPPort 0 must be skipped");
    assert!(n0.get("STUNPort").is_none(), "STUNPort 0 must be skipped");
    // STUNOnly false ⇒ omitted.
    assert!(n0.get("STUNOnly").is_none());
    // InsecureForTests true ⇒ present.
    assert_eq!(n0["InsecureForTests"], true);
}

#[test]
fn derp_region_node_emits_ports_when_nonzero() {
    let n = DerpRegionNode {
        name: "1a".into(),
        region_id: 1,
        host_name: "derp.octra.test".into(),
        ipv4: "198.51.100.10".into(),
        ipv6: String::new(),
        derp_port: 8443,
        stun_port: 3478,
        stun_only: true,
        insecure_for_tests: false,
    };
    let v: Value = serde_json::to_value(&n).unwrap();
    assert_eq!(v["DERPPort"], 8443);
    assert_eq!(v["STUNPort"], 3478);
    assert_eq!(v["STUNOnly"], true);
    // InsecureForTests false ⇒ omitted.
    assert!(v.get("InsecureForTests").is_none());
}

#[test]
fn derp_map_omit_default_regions_round_trip() {
    let j = r#"{"OmitDefaultRegions": true, "Regions": {}}"#;
    let m: DerpMap = serde_json::from_str(j).unwrap();
    assert!(m.omit_default_regions);
    let v = serde_json::to_value(&m).unwrap();
    assert_eq!(v["omitDefaultRegions"], true);
}

// ---------------------------------------------------------------------------
// MachineRecord (Wall 7 disco_key / endpoints) round-trip via clone
// ---------------------------------------------------------------------------

#[test]
fn machine_record_clone_preserves_wall7_fields() {
    let mut rec = MachineRecord::new_at(
        chrono::Utc::now(),
        "nk".into(),
        "mk".into(),
        "u".into(),
        "h".into(),
        std::net::Ipv4Addr::new(100, 64, 0, 5),
        false,
    );
    rec.disco_key = Some("dk".into());
    rec.endpoints = vec!["1.2.3.4:5".into(), "5.6.7.8:9".into()];
    rec.home_derp = 901;
    let cloned = rec.clone();
    assert_eq!(cloned.disco_key, rec.disco_key);
    assert_eq!(cloned.endpoints, rec.endpoints);
    assert_eq!(cloned.home_derp, rec.home_derp);
    assert_eq!(cloned.ipv4, rec.ipv4);
    assert_eq!(cloned.created_at, rec.created_at);
    assert_eq!(cloned.last_seen, rec.last_seen);
}

// ---------------------------------------------------------------------------
// FilterRule / PortRange shapes
// ---------------------------------------------------------------------------

#[test]
fn filter_rule_with_ip_proto_emits_field() {
    let f = FilterRule {
        src_ips: vec!["*".into()],
        dst_ports: vec![NetPortRange {
            ip: "*".into(),
            ports: PortRange {
                first: 22,
                last: 22,
            },
        }],
        ip_proto: vec![6, 17],
    };
    let v = serde_json::to_value(&f).unwrap();
    assert_eq!(v["IPProto"], serde_json::json!([6, 17]));
}

#[test]
fn port_range_defaults_are_zero() {
    let p = PortRange::default();
    assert_eq!(p.first, 0);
    assert_eq!(p.last, 0);
}
