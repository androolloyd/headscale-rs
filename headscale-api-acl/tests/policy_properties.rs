use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use headscale_api_acl::{
    AclAction, AclDoc, AclRule, NodeView, PortRef, ViaRouteCandidate, parse_hujson_policy,
};

fn ip_string(bytes: [u8; 4]) -> String {
    Ipv4Addr::from(bytes).to_string()
}

fn sorted_flat_rule_ports(doc: &AclDoc) -> Vec<&str> {
    let mut ports = doc
        .rules
        .iter()
        .flat_map(|rule| rule.ports.iter().map(String::as_str))
        .collect::<Vec<_>>();
    ports.sort_unstable();
    ports
}

#[test]
fn empty_policy_is_default_deny_for_ipv4_matrix() {
    let doc = AclDoc::empty();
    for src in [
        [0, 0, 0, 0],
        [100, 64, 0, 1],
        [127, 0, 0, 1],
        [255, 255, 255, 255],
    ] {
        for dst in [
            [0, 0, 0, 0],
            [100, 64, 0, 2],
            [192, 0, 2, 1],
            [255, 255, 255, 255],
        ] {
            for port in [0, 1, 22, 443, 41641, u16::MAX] {
                let src = ip_string(src);
                let dst = ip_string(dst);
                assert_eq!(
                    doc.decide(&src, &dst, PortRef::new("tcp", port)),
                    AclAction::Deny
                );
            }
        }
    }
}

#[test]
fn wildcard_accept_rule_accepts_ipv4_matrix() {
    let doc = AclDoc {
        version: 1,
        rules: vec![AclRule {
            action: AclAction::Accept,
            src: vec!["*".into()],
            dst: vec!["*".into()],
            ports: vec!["*/*".into()],
        }],
        ..Default::default()
    };
    for src in [
        [0, 0, 0, 0],
        [100, 64, 0, 1],
        [127, 0, 0, 1],
        [255, 255, 255, 255],
    ] {
        for dst in [
            [0, 0, 0, 0],
            [100, 64, 0, 2],
            [192, 0, 2, 1],
            [255, 255, 255, 255],
        ] {
            for port in [0, 1, 22, 443, 41641, u16::MAX] {
                let src = ip_string(src);
                let dst = ip_string(dst);
                assert_eq!(
                    doc.decide(&src, &dst, PortRef::new("udp", port)),
                    AclAction::Accept
                );
            }
        }
    }
}

#[test]
fn canonical_hash_ignores_group_member_order() {
    for members in [
        Vec::<String>::new(),
        vec!["alice".into()],
        vec!["alice".into(), "bob".into(), "carol".into()],
        vec!["node_1".into(), "node_2".into(), "node_10".into()],
    ] {
        let mut sorted = members.clone();
        sorted.sort();
        sorted.dedup();
        let mut reversed = sorted.clone();
        reversed.reverse();

        let mut groups_a = BTreeMap::new();
        groups_a.insert("admins".to_string(), sorted);
        let mut groups_b = BTreeMap::new();
        groups_b.insert("admins".to_string(), reversed);

        let a = AclDoc {
            version: 1,
            groups: groups_a,
            ..Default::default()
        };
        let b = AclDoc {
            version: 1,
            groups: groups_b,
            ..Default::default()
        };

        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
        assert_eq!(a.policy_hash(), b.policy_hash());
    }
}

#[test]
fn first_match_deny_remains_authoritative() {
    let doc = AclDoc {
        version: 1,
        rules: vec![
            AclRule {
                action: AclAction::Deny,
                src: vec!["group:admins".into()],
                dst: vec!["tag:db".into()],
                ports: vec!["tcp/5432".into()],
            },
            AclRule {
                action: AclAction::Accept,
                src: vec!["*".into()],
                dst: vec!["*".into()],
                ports: vec!["*/*".into()],
            },
        ],
        groups: BTreeMap::from([("admins".into(), vec!["alice@example.com".into()])]),
        ..Default::default()
    };
    let db_tags = vec!["db".to_string()];
    let alice = NodeView::new("100.64.0.10").with_user("alice@example.com");
    let db = NodeView::new("100.64.0.20").with_tags(&db_tags);

    assert_eq!(
        doc.evaluate_with(&alice, &db, PortRef::new("tcp", 5432)),
        AclAction::Deny
    );
    assert_eq!(
        doc.evaluate_with(&alice, &db, PortRef::new("tcp", 443)),
        AclAction::Accept
    );
}

#[test]
fn via_routes_include_overlapping_advertised_prefixes() {
    let doc = parse_hujson_policy(
        r#"{
          "tagOwners": {
            "tag:router-broad": ["router@"],
            "tag:router-narrow": ["router@"],
            "tag:router-disjoint": ["router@"],
            "tag:router-v6": ["router@"],
            "tag:client-broad": ["client@"],
            "tag:client-narrow": ["client@"],
            "tag:client-disjoint": ["client@"],
            "tag:client-v6": ["client@"]
          },
          "hosts": {
            "office": "10.33.0.0/16",
            "office-narrow": "10.66.5.128/25",
            "office-disjoint": "10.77.0.0/24",
            "office-4via6": "fd7a:115c:a1e0:b1a::/64"
          },
          "grants": [
            {
              "src": ["tag:client-broad"],
              "dst": ["office"],
              "ip": ["*"],
              "via": ["tag:router-broad"]
            },
            {
              "src": ["tag:client-narrow"],
              "dst": ["office-narrow"],
              "ip": ["*"],
              "via": ["tag:router-narrow"]
            },
            {
              "src": ["tag:client-disjoint"],
              "dst": ["office-disjoint"],
              "ip": ["*"],
              "via": ["tag:router-disjoint"]
            },
            {
              "src": ["tag:client-v6"],
              "dst": ["office-4via6"],
              "ip": ["*"],
              "via": ["tag:router-v6"]
            }
          ]
        }"#,
    )
    .unwrap();

    for (client_tag, router_tag, route, expect_include) in [
        ("tag:client-broad", "tag:router-broad", "10.33.5.0/24", true),
        (
            "tag:client-narrow",
            "tag:router-narrow",
            "10.66.5.0/24",
            true,
        ),
        (
            "tag:client-disjoint",
            "tag:router-disjoint",
            "10.77.1.0/24",
            false,
        ),
        (
            "tag:client-v6",
            "tag:router-v6",
            "fd7a:115c:a1e0:b1a:0:13:ad2:7300/120",
            true,
        ),
    ] {
        let client_tags = vec![client_tag.to_string()];
        let router_tags = vec![router_tag.to_string()];
        let client = NodeView::new("100.64.0.10").with_tags(&client_tags);
        let router = NodeView::new("100.64.0.1").with_tags(&router_tags);
        let routes = vec![route.to_string()];

        let got = doc.via_routes_for_peer(&client, &router, &routes);

        if expect_include {
            assert_eq!(got.include, routes, "{client_tag} should include {route}");
        } else {
            assert!(
                got.include.is_empty(),
                "{client_tag} should not include disjoint {route}"
            );
        }
        assert!(got.exclude.is_empty());
        assert!(got.use_primary.is_empty());
    }
}

#[test]
fn via_routes_regular_overlap_clears_non_via_exclude() {
    let doc = parse_hujson_policy(
        r#"{
          "tagOwners": {
            "tag:client": ["client@"],
            "tag:primary": ["router@"],
            "tag:secondary": ["router@"]
          },
          "grants": [
            {
              "src": ["tag:client"],
              "dst": ["10.55.0.0/24"],
              "ip": ["*"],
              "via": ["tag:secondary"]
            },
            {
              "src": ["tag:client"],
              "dst": ["10.55.0.0/24"],
              "ip": ["*"]
            }
          ]
        }"#,
    )
    .unwrap();

    let client_tags = vec!["tag:client".to_string()];
    let primary_tags = vec!["tag:primary".to_string()];
    let secondary_tags = vec!["tag:secondary".to_string()];
    let client = NodeView::new("100.64.0.14").with_tags(&client_tags);
    let primary = NodeView::new("100.64.0.12").with_tags(&primary_tags);
    let route = "10.55.0.0/24".to_string();
    let routes = vec![route];
    let candidates = vec![
        ViaRouteCandidate {
            id: 12,
            tags: &primary_tags,
            routes: &routes,
        },
        ViaRouteCandidate {
            id: 13,
            tags: &secondary_tags,
            routes: &routes,
        },
    ];

    let got =
        doc.via_routes_for_peer_with_candidates(&client, 14, &primary, 12, &routes, &candidates);

    assert!(got.include.is_empty());
    assert!(got.exclude.is_empty());
    assert!(got.use_primary.is_empty());
}

#[test]
fn via_routes_autogroup_internet_matches_exit_defaults_only_for_via_tag() {
    let doc = parse_hujson_policy(
        r#"{
          "tagOwners": {
            "tag:client": ["client@"],
            "tag:exit-a": ["router@"],
            "tag:exit-b": ["router@"]
          },
          "grants": [{
            "src": ["tag:client"],
            "dst": ["autogroup:internet"],
            "ip": ["*"],
            "via": ["tag:exit-a"]
          }]
        }"#,
    )
    .unwrap();

    let client_tags = vec!["tag:client".to_string()];
    let exit_a_tags = vec!["tag:exit-a".to_string()];
    let exit_b_tags = vec!["tag:exit-b".to_string()];
    let client = NodeView::new("100.64.0.14").with_tags(&client_tags);
    let exit_a = NodeView::new("100.64.0.12").with_tags(&exit_a_tags);
    let exit_b = NodeView::new("100.64.0.13").with_tags(&exit_b_tags);
    let routes = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];

    let included = doc.via_routes_for_peer(&client, &exit_a, &routes);
    let excluded = doc.via_routes_for_peer(&client, &exit_b, &routes);

    assert_eq!(included.include, routes);
    assert!(included.exclude.is_empty());
    assert_eq!(excluded.exclude, routes);
    assert!(excluded.include.is_empty());
}

#[test]
fn via_routes_specific_subnet_does_not_match_exit_defaults() {
    let doc = parse_hujson_policy(
        r#"{
          "tagOwners": {
            "tag:client": ["client@"],
            "tag:exit": ["router@"]
          },
          "grants": [{
            "src": ["tag:client"],
            "dst": ["10.55.0.0/24"],
            "ip": ["*"],
            "via": ["tag:exit"]
          }]
        }"#,
    )
    .unwrap();

    let client_tags = vec!["tag:client".to_string()];
    let exit_tags = vec!["tag:exit".to_string()];
    let client = NodeView::new("100.64.0.14").with_tags(&client_tags);
    let exit = NodeView::new("100.64.0.12").with_tags(&exit_tags);
    let routes = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];

    let got = doc.via_routes_for_peer(&client, &exit, &routes);

    assert!(got.include.is_empty());
    assert!(got.exclude.is_empty());
    assert!(got.use_primary.is_empty());
}

#[test]
fn hujson_nested_member_names_match_go_case_insensitive_json() {
    let doc = parse_hujson_policy(
        r#"{
          "TAGOWNERS": {
            "tag:server": ["alice@"]
          },
          "AUTOAPPROVERS": {
            "EXITNODE": ["tag:server"],
            "ROUTES": {
              "10.0.0.0/8": ["tag:server"]
            }
          },
          "NODEATTRS": [{
            "TARGET": ["tag:server"],
            "ATTR": ["randomize-client-port"]
          }],
          "ACLS": [{
            "ACTION": "accept",
            "PROTO": "IPV6-ICMP",
            "SRC": ["tag:server"],
            "DST": ["*:*"]
          }],
          "GRANTS": [{
            "SRC": ["tag:server"],
            "DST": ["10.0.0.0/8"],
            "IP": ["TCP:443"]
          }]
        }"#,
    )
    .unwrap();

    assert_eq!(doc.auto_approvers.exit_node, vec!["tag:server"]);
    assert_eq!(doc.node_attrs[0].target, vec!["tag:server"]);
    assert_eq!(doc.node_attrs[0].attr, vec!["randomize-client-port"]);
    assert_eq!(sorted_flat_rule_ports(&doc), vec!["ipv6-icmp/*", "tcp/443"]);
}

#[test]
fn hujson_rejects_non_go_nested_policy_fields() {
    for (name, raw, want) in [
        (
            "autoapprovers-snake-exit-node",
            r#"{"autoApprovers":{"exit_node":["alice@"]}}"#,
            "unknown field \"exit_node\"",
        ),
        (
            "nodeattrs-snake-ip-pool",
            r#"{"nodeAttrs":[{"target":["*"],"ip_pool":[]}]}"#,
            "unknown field \"ip_pool\"",
        ),
        (
            "nodeattrs-app",
            r#"{"nodeAttrs":[{"target":["*"],"app":{"example.com/cap/use":[]}}]}"#,
            "unknown field \"app\"",
        ),
        (
            "top-level-postures",
            r#"{"postures":{"corp":["node:os == 'linux'"]}}"#,
            "unknown field \"postures\"",
        ),
    ] {
        let err = parse_hujson_policy(raw).expect_err(name).to_string();
        assert!(
            err.contains(want),
            "{name} should contain {want:?}, got {err:?}"
        );
    }
}

#[test]
fn hujson_validates_hosts_tag_owners_and_auto_approvers_eagerly() {
    for (name, raw, want) in [
        (
            "invalid-host-name",
            r#"{"hosts":{"host:server":"100.64.0.1"}}"#,
            "invalid hostname",
        ),
        (
            "invalid-host-ip",
            r#"{"hosts":{"server":"not-an-ip"}}"#,
            "contains invalid IP address",
        ),
        (
            "invalid-tag-owner",
            r#"{"tagOwners":{"tag:server":["100.64.0.1"]}}"#,
            "invalid owner format",
        ),
        (
            "invalid-autoapprover-route-prefix",
            r#"{"autoApprovers":{"routes":{"not-a-prefix":["alice@"]}}}"#,
            "invalid prefix",
        ),
        (
            "invalid-autoapprover-principal",
            r#"{"autoApprovers":{"exitNode":["100.64.0.1"]}}"#,
            "invalid auto approver format",
        ),
    ] {
        let err = parse_hujson_policy(raw).expect_err(name).to_string();
        assert!(
            err.contains(want),
            "{name} should contain {want:?}, got {err:?}"
        );
    }
}

#[test]
fn hujson_accepts_current_go_protocol_names_beyond_tcp_udp_icmp() {
    let doc = parse_hujson_policy(
        r#"{
          "acls": [
            {"action":"accept","proto":"ipv6-icmp","src":["*"],"dst":["*:*"]},
            {"action":"accept","proto":"fc","src":["*"],"dst":["*:*"]}
          ]
        }"#,
    )
    .unwrap();

    assert_eq!(doc.rules[0].ports, vec!["ipv6-icmp/*"]);
    assert_eq!(doc.rules[1].ports, vec!["fc/*"]);
}

#[test]
fn hujson_accepts_go_numeric_tcp_udp_sctp_protocols_with_specific_ports() {
    let doc = parse_hujson_policy(
        r#"{
          "acls": [
            {"action":"accept","proto":"6","src":["*"],"dst":["*:443"]},
            {"action":"accept","proto":"17","src":["*"],"dst":["*:53"]},
            {"action":"accept","proto":"132","src":["*"],"dst":["*:9899"]}
          ],
          "grants": [{
            "src": ["*"],
            "dst": ["*"],
            "ip": ["6:8443"]
          }]
        }"#,
    )
    .unwrap();

    assert_eq!(
        sorted_flat_rule_ports(&doc),
        vec!["sctp/9899", "tcp/443", "tcp/8443", "udp/53"]
    );
}
