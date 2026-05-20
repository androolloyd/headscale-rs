use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use headscale_api_acl::{AclAction, AclDoc, AclRule, NodeView, PortRef};

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
