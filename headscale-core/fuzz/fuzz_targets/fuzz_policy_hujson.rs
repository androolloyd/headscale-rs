#![no_main]

use headscale_api::policy::{compile_ssh_policy, SshPolicyNode};
use headscale_api_acl::{parse_hujson_policy, strip_hujson, AclAction, AclDoc, NodeView, PortRef};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        return;
    };

    let stripped = strip_hujson(input);
    if let Ok(doc) = parse_hujson_policy(input) {
        exercise_doc(&doc);

        let canonical = doc.canonical_bytes();
        if let Ok(round_trip) = serde_json::from_slice::<AclDoc>(&canonical) {
            exercise_doc(&round_trip);
            assert_eq!(round_trip.policy_hash(), doc.policy_hash());
        }
    }

    if let Ok(doc) = AclDoc::from_toml(input) {
        exercise_doc(&doc);
    }

    if let Ok(doc) = parse_hujson_policy(&stripped) {
        exercise_doc(&doc);
    }
});

fn exercise_doc(doc: &AclDoc) {
    let src_tags = vec!["router".to_string(), "exit".to_string()];
    let dst_tags = vec!["db".to_string()];
    let src = NodeView::new("100.64.0.1")
        .with_user("alice@example.com")
        .with_tags(&src_tags);
    let dst = NodeView::new("100.64.0.2")
        .with_user("bob@example.com")
        .with_tags(&dst_tags);

    for port in [
        PortRef::any(),
        PortRef::new("tcp", 22),
        PortRef::new("tcp", 443),
        PortRef::new("udp", 41641),
    ] {
        let decision = doc.evaluate_with(&src, &dst, port);
        assert!(matches!(decision, AclAction::Accept | AclAction::Deny));
    }

    let attrs = doc.attrs_for(&src);
    assert!(attrs.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(attrs, doc.node_attrs_for(&src));
    assert_node_attrs_invariants(doc);

    assert!(!doc.auto_approves_route(&src, "0.0.0.0/0"));
    assert!(!doc.auto_approves_route(&src, "::/0"));
    for prefix in ["10.0.0.0/8", "10.1.2.0/24", "fd7a:115c:a1e0::/48"] {
        let _ = doc.auto_approves_route(&src, prefix);
    }
    let _ = doc.auto_approves_exit_node(&src);

    exercise_ssh_policy(doc);
}

fn assert_node_attrs_invariants(doc: &AclDoc) {
    let router_tags = vec!["router".to_string()];
    let prefixed_router_tags = vec!["tag:router".to_string()];
    let exit_tags = vec!["exit".to_string()];
    let empty_tags = Vec::new();

    for node in [
        NodeView::new("100.64.0.10")
            .with_user("alice@example.com")
            .with_tags(&router_tags),
        NodeView::new("100.64.0.11")
            .with_user("bob@example.com")
            .with_tags(&prefixed_router_tags),
        NodeView::new("100.64.0.12").with_tags(&exit_tags),
        NodeView::new("100.64.0.13").with_tags(&empty_tags),
    ] {
        let attrs = doc.node_attrs_for(&node);
        let mut sorted = attrs.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(attrs, sorted);
        assert_eq!(attrs, doc.attrs_for(&node));

        if doc.randomize_client_port {
            assert!(attrs.iter().any(|attr| attr == "randomize-client-port"));
        }
    }
}

fn exercise_ssh_policy(doc: &AclDoc) {
    let nodes = vec![
        SshPolicyNode {
            id: 1,
            user: Some("alice@example.com".to_string()),
            user_id: Some(1),
            addrs: vec!["100.64.0.10".to_string(), "fd7a:115c:a1e0::10".to_string()],
            tags: Vec::new(),
        },
        SshPolicyNode {
            id: 2,
            user: Some("bob@example.com".to_string()),
            user_id: Some(2),
            addrs: vec!["100.64.0.20".to_string()],
            tags: Vec::new(),
        },
        SshPolicyNode {
            id: 3,
            user: Some("admin@example.com".to_string()),
            user_id: Some(3),
            addrs: vec!["100.64.0.30".to_string(), "fd7a:115c:a1e0::30".to_string()],
            tags: vec!["tag:server".to_string(), "tag:router".to_string()],
        },
    ];

    for target in [1, 2, 3, 99] {
        if let Some(policy) = compile_ssh_policy(doc, &nodes, target) {
            for rule in policy.rules {
                assert!(!rule.principals.is_empty());
                assert!(!rule.ssh_users.is_empty());
                assert!(
                    rule.action.accept
                        || rule
                            .action
                            .hold_and_delegate
                            .starts_with("/machine/ssh/action/")
                        || rule.action.hold_and_delegate.is_empty()
                );
            }
        }
    }
}
