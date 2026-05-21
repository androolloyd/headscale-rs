#![no_main]

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

    for prefix in ["0.0.0.0/0", "10.0.0.0/8", "10.1.2.0/24", "::/0"] {
        let _ = doc.auto_approves_route(&src, prefix);
    }
    let _ = doc.auto_approves_exit_node(&src);
}
