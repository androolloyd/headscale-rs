//! Focused parity coverage for current headscale-go
//! `integration/route_test.go` and `integration/dns_test.go` names.
//!
//! These tests intentionally use the upstream normalized names so
//! `tools/parity/current_head_surface_inventory.py` can associate them
//! with the Go integration backlog while still staying cheap enough for
//! a focused metadata/test run.

#![allow(unknown_lints, clippy::duration_suboptimal_units)]

use std::net::Ipv4Addr;
use std::time::Duration;

use headscale_api::dns::{
    DnsConfigSpec, DnsStore, MachineDnsRecord, build_dns_config, spawn_extra_records_watcher,
};
use headscale_api::policy::{
    PeerMapNode, PolicyStore, build_peer_map_for_doc, parse_hujson_policy,
};
use headscale_api::tailscale_wire::routes::{
    PrimaryRouteState, active_approved_routes, active_exit_routes, active_primary_routes,
    normalize_routes,
};
use headscale_api::tailscale_wire::wire::DnsRecord;

fn routes(values: &[&str]) -> Vec<String> {
    values.iter().map(|route| (*route).to_string()).collect()
}

fn peer(id: u64, addr: &str, user: Option<&str>, tags: &[&str], routes: &[&str]) -> PeerMapNode {
    PeerMapNode {
        id,
        addr: addr.to_string(),
        addrs: Vec::new(),
        user: user.map(str::to_string),
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        routes: routes.iter().map(|route| (*route).to_string()).collect(),
    }
}

fn policy_store(raw: &str) -> PolicyStore {
    let store = PolicyStore::new();
    let doc = parse_hujson_policy(raw).unwrap();
    store.set(doc, raw.to_string());
    store
}

fn magic_spec() -> DnsConfigSpec {
    DnsConfigSpec {
        base_domain: "headscale.net".into(),
        override_local_dns: false,
        ..Default::default()
    }
}

fn write_records(path: &std::path::Path, records: &[(&str, &str, &str)]) {
    let payload = serde_json::to_string(
        &records
            .iter()
            .map(|(name, record_type, value)| {
                serde_json::json!({
                    "name": name,
                    "type": record_type,
                    "value": value,
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    std::fs::write(path, payload).unwrap();
}

#[test]
fn enablingroutes() {
    let available = routes(&["10.0.0.0/24"]);
    assert!(
        active_approved_routes(&available, &[]).is_empty(),
        "advertised routes are not active before approval"
    );

    let approved = routes(&["10.0.0.0/24"]);
    assert_eq!(active_primary_routes(&available, &approved), approved);

    let mut state = PrimaryRouteState::new();
    state.set_routes(1, routes(&["10.0.0.0/24"])).unwrap();
    state.set_routes(2, routes(&["10.0.1.0/24"])).unwrap();
    state.set_routes(3, routes(&["10.0.2.0/24"])).unwrap();
    assert_eq!(state.primary_routes(1), routes(&["10.0.0.0/24"]));
    assert_eq!(state.primary_routes(2), routes(&["10.0.1.0/24"]));
    assert_eq!(state.primary_routes(3), routes(&["10.0.2.0/24"]));

    state.set_routes(2, Vec::<String>::new()).unwrap();
    assert!(state.primary_routes(2).is_empty());
}

#[test]
fn enablingexitroutes() {
    let approved = normalize_routes(["0.0.0.0/0"]).unwrap();
    assert_eq!(approved, routes(&["0.0.0.0/0", "::/0"]));

    let available = routes(&["0.0.0.0/0", "::/0"]);
    assert_eq!(active_exit_routes(&available, &approved), approved);
    assert!(
        active_primary_routes(&available, &approved).is_empty(),
        "exit routes are served separately and never become PrimaryRoutes"
    );
}

#[test]
fn exitrouteswithautogroupinternetacl() {
    let raw = r#"{
        "tagOwners": {
            "tag:exit": ["alice@example.com"],
            "tag:router": ["alice@example.com"]
        },
        "autoApprovers": {
            "exitNode": ["tag:exit"],
            "routes": {"10.0.0.0/8": ["tag:router"]}
        },
        "acls": [
            {"action":"accept","src":["alice@example.com"],"dst":["autogroup:internet:*"]}
        ]
    }"#;
    let doc = parse_hujson_policy(raw).unwrap();
    let nodes = vec![
        peer(1, "100.64.0.1", Some("alice@example.com"), &[], &[]),
        peer(
            2,
            "100.64.0.2",
            Some("router-owner"),
            &["tag:exit"],
            &["0.0.0.0/0", "::/0"],
        ),
        peer(
            3,
            "100.64.0.3",
            Some("router-owner"),
            &["tag:router"],
            &["10.0.0.0/8"],
        ),
        peer(4, "100.64.0.4", Some("bob@example.com"), &[], &[]),
    ];

    let peers = build_peer_map_for_doc(&doc, &nodes);
    assert_eq!(peers.get(&1).cloned().unwrap_or_default(), vec![2]);
    assert_eq!(peers.get(&2).cloned().unwrap_or_default(), vec![1]);
    assert_eq!(
        peers.get(&3).cloned().unwrap_or_default(),
        Vec::<u64>::new()
    );
    assert_eq!(
        peers.get(&4).cloned().unwrap_or_default(),
        Vec::<u64>::new()
    );
}

#[test]
fn hasubnetrouterfailover() {
    let mut state = PrimaryRouteState::new();
    let route = "10.50.0.0/24";
    state.set_routes(1, routes(&[route])).unwrap();
    state.set_routes(2, routes(&[route])).unwrap();
    assert_eq!(state.primary_route_for(route), Some(1));

    assert!(state.set_node_health(1, false));
    assert_eq!(state.primary_route_for(route), Some(2));

    assert!(
        !state.set_node_health(1, true),
        "marking the recovered standby healthy must not move the sticky primary"
    );
    assert_eq!(
        state.primary_route_for(route),
        Some(2),
        "recovered lower-ID router must not steal a sticky primary"
    );
}

#[test]
fn hasubnetrouterfailoverbothoffline() {
    let mut state = PrimaryRouteState::new();
    let route = "10.51.0.0/24";
    state.set_routes(1, routes(&[route])).unwrap();
    state.set_routes(2, routes(&[route])).unwrap();
    assert_eq!(state.primary_route_for(route), Some(1));

    state.set_node_health(1, false);
    assert_eq!(state.primary_route_for(route), Some(2));
    state.set_node_health(2, false);
    assert_eq!(
        state.primary_route_for(route),
        Some(2),
        "when all HA candidates are unhealthy, keep the current last known primary"
    );
}

#[test]
fn hasubnetrouterfailoverbothofflinecablepull() {
    let mut state = PrimaryRouteState::new();
    let route = "10.52.0.0/24";
    state.set_routes(1, routes(&[route])).unwrap();
    state.set_routes(2, routes(&[route])).unwrap();
    assert_eq!(state.primary_route_for(route), Some(1));

    state.set_routes(1, Vec::<String>::new()).unwrap();
    assert_eq!(state.primary_route_for(route), Some(2));

    state.set_routes(2, Vec::<String>::new()).unwrap();
    assert_eq!(state.primary_route_for(route), None);
}

#[test]
fn hasubnetrouterfailoverdockerdisconnect() {
    let mut state = PrimaryRouteState::new();
    let route = "10.53.0.0/24";
    state.set_routes(1, routes(&[route])).unwrap();
    state.set_routes(2, routes(&[route])).unwrap();
    state.set_routes(3, routes(&[route])).unwrap();

    assert_eq!(state.primary_route_for(route), Some(1));
    state.set_routes(1, Vec::<String>::new()).unwrap();
    assert_eq!(state.primary_route_for(route), Some(2));
    state.set_routes(2, Vec::<String>::new()).unwrap();
    assert_eq!(state.primary_route_for(route), Some(3));
    state.set_routes(1, routes(&[route])).unwrap();
    assert_eq!(state.primary_route_for(route), Some(3));
}

#[test]
fn subnetrouteacl() {
    let raw = r#"{
        "acls": [
            {"action":"accept","src":["alice@"],"dst":["alice@:*"]},
            {"action":"accept","src":["alice@"],"dst":["10.33.0.0/16:*"]}
        ]
    }"#;
    let store = policy_store(raw);
    let nodes = vec![
        peer(1, "100.64.0.1", Some("alice"), &[], &[]),
        peer(2, "100.64.0.2", Some("router"), &[], &["10.33.10.0/24"]),
    ];

    assert_eq!(
        store.can_access_route_for_peer(&nodes, 1, 2, "10.33.10.0/24"),
        Some(true)
    );
    assert_eq!(
        store
            .build_peer_map(&nodes)
            .unwrap()
            .get(&1)
            .cloned()
            .unwrap_or_default(),
        vec![2]
    );
}

#[test]
fn subnetrouteaclfiltering() {
    let raw = r#"{
        "acls": [
            {"action":"accept","src":["alice@"],"dst":["10.33.0.0/16:*"]}
        ]
    }"#;
    let store = policy_store(raw);
    let nodes = vec![
        peer(1, "100.64.0.1", Some("alice"), &[], &[]),
        peer(
            2,
            "100.64.0.2",
            Some("router"),
            &[],
            &["10.33.10.0/24", "10.44.10.0/24"],
        ),
    ];

    assert_eq!(
        store.can_access_route_for_peer(&nodes, 1, 2, "10.33.10.0/24"),
        Some(true)
    );
    assert_eq!(
        store.can_access_route_for_peer(&nodes, 1, 2, "10.44.10.0/24"),
        Some(false)
    );
}

#[test]
fn subnetroutermultinetwork() {
    let raw = r#"{
        "acls": [
            {"action":"accept","src":["user2@"],"dst":["10.60.0.0/16:*"]}
        ]
    }"#;
    let store = policy_store(raw);
    let nodes = vec![
        peer(1, "100.64.0.1", Some("user1"), &[], &["10.60.4.0/24"]),
        peer(2, "100.64.0.2", Some("user2"), &[], &[]),
        peer(3, "100.64.0.3", Some("user3"), &[], &[]),
    ];

    let peers = store.build_peer_map(&nodes).unwrap();
    assert_eq!(peers.get(&2).cloned().unwrap_or_default(), vec![1]);
    assert_eq!(
        peers.get(&3).cloned().unwrap_or_default(),
        Vec::<u64>::new()
    );
    assert_eq!(
        store.can_access_route_for_peer(&nodes, 2, 1, "10.60.4.0/24"),
        Some(true)
    );
}

#[test]
fn subnetroutermultinetworkexitnode() {
    let available = routes(&["0.0.0.0/0", "::/0", "10.60.4.0/24"]);
    let approved = normalize_routes(["0.0.0.0/0", "10.60.4.0/24"]).unwrap();

    assert_eq!(
        active_exit_routes(&available, &approved),
        routes(&["0.0.0.0/0", "::/0"])
    );
    assert_eq!(
        active_primary_routes(&available, &approved),
        routes(&["10.60.4.0/24"])
    );
}

#[test]
fn grantviasubnetsteering() {
    let raw = r#"{
        "tagOwners": {
            "tag:router-a": ["router@"],
            "tag:router-b": ["router@"]
        },
        "grants": [
            {"src":["alice@"],"dst":["10.77.0.0/24"],"ip":["*"],"via":["tag:router-a"]},
            {"src":["bob@"],"dst":["10.77.0.0/24"],"ip":["*"],"via":["tag:router-b"]}
        ]
    }"#;
    let store = policy_store(raw);
    let nodes = vec![
        peer(
            1,
            "100.64.0.1",
            Some("router"),
            &["tag:router-a"],
            &["10.77.0.0/24"],
        ),
        peer(
            2,
            "100.64.0.2",
            Some("router"),
            &["tag:router-b"],
            &["10.77.0.0/24"],
        ),
        peer(3, "100.64.0.3", Some("alice"), &[], &[]),
        peer(4, "100.64.0.4", Some("bob"), &[], &[]),
    ];

    let alice_to_a = store.via_routes_for_peer(&nodes, 3, 1).unwrap();
    let alice_to_b = store.via_routes_for_peer(&nodes, 3, 2).unwrap();
    let bob_to_a = store.via_routes_for_peer(&nodes, 4, 1).unwrap();
    let bob_to_b = store.via_routes_for_peer(&nodes, 4, 2).unwrap();

    assert_eq!(alice_to_a.include, routes(&["10.77.0.0/24"]));
    assert_eq!(alice_to_b.exclude, routes(&["10.77.0.0/24"]));
    assert_eq!(bob_to_a.exclude, routes(&["10.77.0.0/24"]));
    assert_eq!(bob_to_b.include, routes(&["10.77.0.0/24"]));
}

#[test]
fn issue3233viainternetexitvisibility() {
    let raw = r#"{
        "tagOwners": {
            "tag:exit1": ["alice@headscale.net"],
            "tag:exit2": ["bob@headscale.net"]
        },
        "grants": [
            {
                "src": ["alice@headscale.net"],
                "dst": ["autogroup:internet"],
                "via": ["tag:exit1"],
                "ip": ["*"]
            }
        ]
    }"#;
    let store = policy_store(raw);
    let exit_routes = &["0.0.0.0/0", "::/0"];
    let nodes = vec![
        peer(1, "100.64.0.10", Some("alice@headscale.net"), &[], &[]),
        peer(
            2,
            "100.64.0.11",
            Some("alice@headscale.net"),
            &["tag:exit1"],
            exit_routes,
        ),
        peer(
            3,
            "100.64.0.21",
            Some("bob@headscale.net"),
            &["tag:exit2"],
            exit_routes,
        ),
    ];

    let peer_map = store.build_peer_map(&nodes).unwrap();
    assert_eq!(
        peer_map.get(&1).cloned().unwrap_or_default(),
        vec![2],
        "alice must see only the via-tagged exit node"
    );
    assert_eq!(
        peer_map.get(&2).cloned().unwrap_or_default(),
        vec![1],
        "matching exit node must see alice through the via grant"
    );
    assert!(
        peer_map.get(&3).cloned().unwrap_or_default().is_empty(),
        "non-matching exit node must stay hidden from alice"
    );

    let alice_to_exit1 = store.via_routes_for_peer(&nodes, 1, 2).unwrap();
    assert_eq!(
        alice_to_exit1.include,
        routes(exit_routes),
        "matching exit node defaults drive AllowedIPs"
    );
    assert!(alice_to_exit1.exclude.is_empty());

    let alice_to_exit2 = store.via_routes_for_peer(&nodes, 1, 3).unwrap();
    assert!(alice_to_exit2.include.is_empty());
    assert_eq!(
        alice_to_exit2.exclude,
        routes(exit_routes),
        "other exit-node defaults are stripped by the via grant"
    );
}

#[test]
fn resolvemagicdns() {
    let machines = [
        MachineDnsRecord {
            hostname: "peer-1".into(),
            ipv4: Some(Ipv4Addr::new(100, 64, 0, 11)),
            ipv6: None,
            node_id: 1,
        },
        MachineDnsRecord {
            hostname: "peer-2".into(),
            ipv4: Some(Ipv4Addr::new(100, 64, 0, 22)),
            ipv6: None,
            node_id: 2,
        },
    ];

    let cfg = build_dns_config(&magic_spec(), &machines, &[]);
    assert_eq!(cfg.domains, vec!["headscale.net"]);
    assert!(
        cfg.extra_records.is_empty(),
        "headscale-go resolves MagicDNS through its resolver, not DNSConfig.ExtraRecords"
    );
}

#[tokio::test]
async fn resolvemagicdnsextrarecordspath() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("extra-records.json");
    write_records(&path, &[("test.myvpn.example.com", "A", "6.6.6.6")]);

    let store = DnsStore::from_spec(magic_spec());
    let handle =
        spawn_extra_records_watcher(store.clone(), path.clone(), Some(Duration::from_millis(40)));

    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while std::time::Instant::now() < deadline {
        if store
            .extra_records()
            .iter()
            .any(|record| record.name == "test.myvpn.example.com")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        store.extra_records().as_slice(),
        &[DnsRecord {
            name: "test.myvpn.example.com".into(),
            record_type: "A".into(),
            value: "6.6.6.6".into(),
        }]
    );

    write_records(&path, &[("copy.myvpn.example.com", "A", "8.8.8.8")]);
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while std::time::Instant::now() < deadline {
        if store
            .extra_records()
            .iter()
            .any(|record| record.name == "copy.myvpn.example.com")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        store.extra_records().as_slice(),
        &[DnsRecord {
            name: "copy.myvpn.example.com".into(),
            record_type: "A".into(),
            value: "8.8.8.8".into(),
        }]
    );
    handle.abort();
}
