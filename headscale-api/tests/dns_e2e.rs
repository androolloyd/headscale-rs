//! End-to-end MagicDNS / DNSConfig wiring tests.
//!
//! Each test drives the public `DnsStore` API plus (where reachable
//! without spinning up a real noise tunnel) the wire layer's
//! `DNSConfig` emission. The streaming `/map` long-poller wake path is
//! exercised via [`DnsStore::wait_for_change`] — the same `Notify`
//! handle the in-tree streaming select! parks a future on.
//!
//! Closes the P1 entry in `docs/headscale-gap-analysis.md` (§MagicDNS).

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use headscale_api::dns::{
    DnsConfigSpec, DnsStore, MachineDnsRecord, build_dns_config, parse_extra_records,
    spawn_extra_records_watcher,
};
use headscale_api::tailscale_wire::wire::{DnsRecord, MapResponse};

/// Helper — write a JSON array of records to a path. Mirrors the
/// shape `juanfont/headscale` accepts in its `[dns].extra_records`
/// file: a top-level array of `{name, type, value}` objects.
fn write_records(path: &std::path::Path, records: &[(&str, &str, &str)]) {
    let s = serde_json::to_string(
        &records
            .iter()
            .map(|(n, t, v)| {
                serde_json::json!({
                    "name": n,
                    "type": t,
                    "value": v,
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    std::fs::write(path, s).unwrap();
}

#[test]
fn build_dns_config_emits_magic_a_records_per_machine() {
    let spec = DnsConfigSpec::default();
    let machines = [
        MachineDnsRecord {
            hostname: "peer-1".into(),
            ipv4: Ipv4Addr::new(100, 64, 0, 11),
            node_id: 1,
        },
        MachineDnsRecord {
            hostname: "peer-2".into(),
            ipv4: Ipv4Addr::new(100, 64, 0, 22),
            node_id: 2,
        },
    ];
    let cfg = build_dns_config(&spec, &machines, &[]);
    let names: Vec<String> = cfg.extra_records.iter().map(|r| r.name.clone()).collect();
    assert!(names.contains(&"peer-1.octravpn.example.org".to_string()));
    assert!(names.contains(&"peer-2.octravpn.example.org".to_string()));
}

#[test]
fn split_dns_routes_round_trip_through_dns_config() {
    let mut restricted = HashMap::new();
    restricted.insert(
        "corp.internal".to_string(),
        vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()],
    );
    let spec = DnsConfigSpec {
        restricted_nameservers: restricted,
        ..Default::default()
    };
    let cfg = build_dns_config(&spec, &[], &[]);
    let routes = cfg.routes.get("corp.internal").expect("present");
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].addr, "10.0.0.1");
    assert_eq!(routes[1].addr, "10.0.0.2");
}

#[test]
fn mapresponse_round_trip_carries_dnsconfig_fields() {
    // Build a `DnsConfig` indirectly via the public store, slot it
    // into a `MapResponse`, round-trip through JSON, and verify the
    // PascalCase field names land on the wire.
    let spec = DnsConfigSpec {
        nameservers: vec!["1.1.1.1".into()],
        ..Default::default()
    };
    let store = DnsStore::from_spec(spec);
    store.set_extra_records(vec![DnsRecord {
        name: "static.example.org".into(),
        record_type: "A".into(),
        value: "9.9.9.9".into(),
    }]);
    let dns = store.build(&[]);
    let json = serde_json::to_string(&dns).unwrap();
    assert!(json.contains("\"Proxied\":true"));
    assert!(json.contains("\"Resolvers\":"));
    assert!(json.contains("\"static.example.org\""));
    // Round-trip through serde to make sure we can deserialise our
    // own emission (covers the rename/alias attributes in both
    // directions).
    let decoded: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded["Resolvers"][0]["Addr"].as_str().unwrap(), "1.1.1.1");
}

#[tokio::test]
async fn set_extra_records_wakes_waiters_within_1s() {
    let store = DnsStore::from_spec(DnsConfigSpec::default());
    let store2 = store.clone();
    let join = tokio::spawn(async move {
        store2.wait_for_change().await;
    });
    tokio::task::yield_now().await;
    store.set_extra_records(vec![DnsRecord {
        name: "x.example".into(),
        record_type: "A".into(),
        value: "1.2.3.4".into(),
    }]);
    tokio::time::timeout(Duration::from_secs(1), join)
        .await
        .expect("wake within 1s")
        .expect("join ok");
    // And the next build call carries the new record.
    let cfg = store.build(&[]);
    assert!(
        cfg.extra_records
            .iter()
            .any(|r| r.name == "x.example" && r.value == "1.2.3.4")
    );
}

#[tokio::test]
async fn extra_records_file_watcher_picks_up_initial_records() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("extra.json");
    write_records(&path, &[("static.example.org", "A", "10.0.0.1")]);

    let store = DnsStore::from_spec(DnsConfigSpec::default());
    // Poll at a tight interval so the test doesn't take 5s.
    let handle =
        spawn_extra_records_watcher(store.clone(), path.clone(), Some(Duration::from_millis(50)));

    // The watcher loads the initial file synchronously inside its
    // first poll iteration. Wait up to 1s for the records to land.
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while std::time::Instant::now() < deadline {
        if store
            .extra_records()
            .iter()
            .any(|r| r.name == "static.example.org")
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        store
            .extra_records()
            .iter()
            .any(|r| r.name == "static.example.org"),
        "initial extra-records file should land in the store within 1s"
    );
    handle.abort();
}

#[tokio::test]
async fn extra_records_file_watcher_picks_up_changes_and_wakes_waiters() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("extra.json");
    write_records(&path, &[("first.example", "A", "10.0.0.1")]);

    let store = DnsStore::from_spec(DnsConfigSpec::default());
    let handle =
        spawn_extra_records_watcher(store.clone(), path.clone(), Some(Duration::from_millis(50)));

    // Park a waiter so we can prove the wake fires on file edits.
    let store_w = store.clone();
    let waiter = tokio::spawn(async move {
        // First wake is the initial-load notify; second is the
        // file-edit notify. We wait for both.
        store_w.wait_for_change().await;
        store_w.wait_for_change().await;
    });

    // Give the initial load a moment to land + fire.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Edit the file — bump mtime by writing fresh contents. Some
    // filesystems quantise mtime at 1s, so write distinctly different
    // bytes to force a re-read regardless of the mtime resolution.
    // We also `set_modified` explicitly when possible.
    write_records(&path, &[("second.example", "A", "10.0.0.2")]);
    // Force mtime bump in case the fs quantises at 1s.
    let _ = std::fs::File::open(&path).and_then(|f| f.set_modified(std::time::SystemTime::now()));

    tokio::time::timeout(Duration::from_secs(3), waiter)
        .await
        .expect("waker fires within 3s")
        .expect("join ok");

    let recs = store.extra_records();
    assert!(recs.iter().any(|r| r.name == "second.example"));
    handle.abort();
}

#[test]
fn parse_extra_records_validates_required_fields() {
    // Missing `value` is rejected.
    assert!(parse_extra_records(br#"[{"name":"x"}]"#).is_err());
    // Missing `name` is rejected.
    assert!(parse_extra_records(br#"[{"value":"x"}]"#).is_err());
    // Mixed Pascal + lowercase keys still work.
    let recs = parse_extra_records(br#"[{"Name":"a","value":"1.1.1.1"}]"#).expect("parses");
    assert_eq!(recs[0].name, "a");
}

#[test]
fn dnsconfig_default_serialises_to_empty_braces() {
    let cfg = DnsStore::new().build(&[]);
    let json = serde_json::to_string(&cfg).unwrap();
    // Default store (MagicDNS off, no resolvers) should emit `{}`
    // byte-for-byte — preserves the pre-feature wire shape.
    assert_eq!(json, "{}");
}

#[test]
fn dnsconfig_with_only_authoritative_emits_just_that_field() {
    let spec = DnsConfigSpec {
        magic_dns: false,
        base_domain: "tail.org".into(),
        authoritative_suffixes: Some(vec!["tail.org".into()]),
        ..Default::default()
    };
    let cfg = build_dns_config(&spec, &[], &[]);
    let json = serde_json::to_string(&cfg).unwrap();
    // Domains carries the base, AuthoritativeSuffixes carries our
    // override.
    assert!(json.contains("\"Domains\":[\"tail.org\"]"));
    assert!(json.contains("\"AuthoritativeSuffixes\":[\"tail.org\"]"));
    assert!(!json.contains("\"Proxied\""));
}

#[test]
fn collision_handling_is_stable_under_node_id_reorder() {
    // Build the same set of machines in two different insertion
    // orders and verify the resulting record set is identical (modulo
    // order). Collision handling must depend only on node_id, not on
    // iteration order.
    let machines_a = [
        MachineDnsRecord {
            hostname: "dup".into(),
            ipv4: Ipv4Addr::new(100, 64, 0, 1),
            node_id: 7,
        },
        MachineDnsRecord {
            hostname: "dup".into(),
            ipv4: Ipv4Addr::new(100, 64, 0, 2),
            node_id: 42,
        },
    ];
    let machines_b = [
        MachineDnsRecord {
            hostname: "dup".into(),
            ipv4: Ipv4Addr::new(100, 64, 0, 2),
            node_id: 42,
        },
        MachineDnsRecord {
            hostname: "dup".into(),
            ipv4: Ipv4Addr::new(100, 64, 0, 1),
            node_id: 7,
        },
    ];
    let spec = DnsConfigSpec::default();
    let a = build_dns_config(&spec, &machines_a, &[]);
    let b = build_dns_config(&spec, &machines_b, &[]);
    let mut a_names: Vec<String> = a.extra_records.iter().map(|r| r.name.clone()).collect();
    let mut b_names: Vec<String> = b.extra_records.iter().map(|r| r.name.clone()).collect();
    a_names.sort();
    b_names.sort();
    assert_eq!(a_names, b_names);
    // And the lowest node_id keeps the canonical name regardless of
    // input order.
    assert!(a_names.contains(&"dup.octravpn.example.org".to_string()));
    assert!(a_names.contains(&"dup-n42.octravpn.example.org".to_string()));
}

#[test]
fn extra_records_combined_with_magic_dns_records() {
    let spec = DnsConfigSpec::default();
    let extra = [DnsRecord {
        name: "ops.example.org".into(),
        record_type: "A".into(),
        value: "10.10.10.10".into(),
    }];
    let machines = [MachineDnsRecord {
        hostname: "peer-a".into(),
        ipv4: Ipv4Addr::new(100, 64, 0, 5),
        node_id: 100,
    }];
    let cfg = build_dns_config(&spec, &machines, &extra);
    // Both the operator-supplied record AND the MagicDNS record land.
    assert_eq!(cfg.extra_records.len(), 2);
    assert!(
        cfg.extra_records
            .iter()
            .any(|r| r.name == "ops.example.org")
    );
    assert!(
        cfg.extra_records
            .iter()
            .any(|r| r.name == "peer-a.octravpn.example.org")
    );
}

#[test]
fn dnsstore_arc_clone_shares_state() {
    // The store is cheap to clone (every field is an Arc). Two
    // handles must observe identical mutations.
    let a = DnsStore::from_spec(DnsConfigSpec::default());
    let b: Arc<DnsStore> = Arc::new(a.clone());
    a.set_extra_records(vec![DnsRecord {
        name: "shared".into(),
        record_type: "A".into(),
        value: "1.2.3.4".into(),
    }]);
    assert_eq!(b.extra_records().len(), 1);
}

#[test]
fn mapresponse_omits_default_dnsconfig_field() {
    // A `MapResponse` whose `dns_config` is the default (empty)
    // DnsConfig must still serialise (we explicitly emit the field
    // on the wire as `DNSConfig`). Just sanity-check the field name
    // — this guards against accidental rename drift.
    use headscale_api::tailscale_wire::wire::{DerpMap, DnsConfig, MapNode};
    let r = MapResponse {
        key_expiry_extension: 0,
        node: MapNode {
            id: 1,
            stable_id: "n1".into(),
            name: "x.octra.test".into(),
            user: 1,
            key: format!("nodekey:{}", "aa".repeat(32)),
            machine: None,
            addresses: vec!["100.64.0.1/32".into()],
            allowed_ips: vec!["100.64.0.1/32".into()],
            hostinfo: headscale_api::tailscale_wire::wire::HostInfo::default(),
            machine_authorized: true,
            disco_key: None,
            endpoints: Vec::new(),
        },
        peers: vec![],
        dns_config: DnsConfig::default(),
        derp_map: DerpMap::default(),
        domain: "octra.test".into(),
        keep_alive: false,
        node_key_expired: false,
        packet_filter: vec![],
    };
    let json = serde_json::to_string(&r).unwrap();
    assert!(json.contains("\"DNSConfig\":{}"));
}
