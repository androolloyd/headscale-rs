use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use headscale_api_acl::{
    AclAction, AclDoc, AclRule, NodeView, PortRef, ViaRouteCandidate, parse_hujson_policy,
};

fn ip_string(bytes: [u8; 4]) -> String {
    Ipv4Addr::from(bytes).to_string()
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
