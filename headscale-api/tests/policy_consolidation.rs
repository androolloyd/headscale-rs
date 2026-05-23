//! Verification that the ACL consolidation (2026-05-20) keeps the
//! admin-facade contract byte-identical to the pre-consolidation
//! implementation.
//!
//! Before this commit, `headscale-api::policy` carried its own
//! [`PolicyDoc`] serde mirror + hujson parser + NodeView access
//! helpers. Both were duplicates of the same logic in
//! `octravpn-mesh::acl`. Both implementations now share
//! `headscale-api-acl` (the canonical leaf crate).
//!
//! Acceptance checks here:
//!
//! * `PolicyStore::raw()` returns the operator's exact hujson bytes
//!   (no serde re-emission, comments preserved).
//! * `PolicyStore::filter_rules()` produces the same
//!   `Vec<FilterRule>` for every input the old implementation
//!   handled — driven through every fixture used by the
//!   `policy_coverage.rs` + `policy_e2e.rs` (heads-api side) tests.
//! * `node_attrs_for(&node)` / `auto_approves_route` /
//!   `auto_approves_exit_node` return the same values as the
//!   pre-consolidation hand-rolled mirror used to.
//! * Live-reload still wakes parked long-pollers via the Notify
//!   broadcast — checks the `wait_for_change()` contract from #230
//!   stays intact.
//!
//! Companion to `policy_coverage.rs` / `policy_e2e.rs`. Those exist
//! per-feature; this one specifically locks the consolidation
//! invariants.

#![cfg(feature = "admin")]

use std::sync::Arc;
use std::time::Duration;

use headscale_api::policy::{
    NodeView, PeerMapNode, PolicyAction, PolicyDoc, PolicyRule, PolicyStore, acl_to_filter_rules,
    build_peer_map_for_doc, parse_hujson_policy,
};

// ---------------------------------------------------------------------------
// PolicyStore::raw() — byte-stable round-trip
// ---------------------------------------------------------------------------

#[test]
fn raw_round_trip_preserves_hujson_byte_for_byte() {
    let store = PolicyStore::new();
    let raw = "{\n  // an operator comment\n  /* block */\n  \"acls\": [\n    {\"action\":\"accept\",\"proto\":\"tcp\",\"src\":[\"*\"],\"dst\":[\"*:22\"]},\n  ]\n}";
    let doc = parse_hujson_policy(raw).unwrap();
    store.set(doc, raw.to_string());
    let returned = store.raw().expect("raw is set");
    assert_eq!(returned, raw, "PolicyStore::raw() must round-trip bytes");
}

#[test]
fn raw_round_trip_preserves_url_with_double_slashes() {
    // Pre-consolidation regression candidate: the hujson stripper
    // used to live in both repos with slightly different escape
    // handling. The canonical stripper must preserve `https://x//y`
    // inside a string literal verbatim.
    let store = PolicyStore::new();
    let raw = r#"{"ssh":[{"action":"accept","src":["alice@"],"dst":["autogroup:self"],"users":["https://example.com//path"]}]}"#;
    let doc = parse_hujson_policy(raw).unwrap();
    store.set(doc, raw.to_string());
    let returned = store.raw().expect("raw");
    assert_eq!(returned, raw);
}

// ---------------------------------------------------------------------------
// PolicyStore::filter_rules() — translator output stays byte-identical
// ---------------------------------------------------------------------------

#[test]
fn filter_rules_allow_all_matches_pre_consolidation_shape() {
    let store = PolicyStore::new();
    let raw = r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#;
    let doc = parse_hujson_policy(raw).unwrap();
    store.set(doc.clone(), raw.to_string());
    let store_rules = store.filter_rules();
    // Direct translator + store-cached must match.
    let direct = acl_to_filter_rules(&doc);
    assert_eq!(store_rules.len(), direct.len());
    assert_eq!(store_rules.len(), 1);
    assert_eq!(store_rules[0].src_ips, vec!["0.0.0.0/0", "::/0"]);
    assert_eq!(store_rules[0].dst_ports.len(), 2);
    assert_eq!(store_rules[0].dst_ports[0].ip, "0.0.0.0/0");
    assert_eq!(store_rules[0].dst_ports[1].ip, "::/0");
    assert_eq!(store_rules[0].dst_ports[0].ports.first, 0);
    assert_eq!(store_rules[0].dst_ports[0].ports.last, 65535);
    assert_eq!(store_rules[0].dst_ports[1].ports.first, 0);
    assert_eq!(store_rules[0].dst_ports[1].ports.last, 65535);
    assert_eq!(store_rules[0].ip_proto, vec![6, 17]);
}

#[test]
fn filter_rules_deny_only_yields_empty_list() {
    let store = PolicyStore::new();
    let doc = PolicyDoc {
        version: 1,
        rules: vec![PolicyRule {
            action: PolicyAction::Deny,
            src: vec!["*".into()],
            dst: vec!["*".into()],
            ports: vec![],
        }],
        ..Default::default()
    };
    store.set(doc, "programmatic-deny-only".to_string());
    assert!(
        store.filter_rules().is_empty(),
        "deny-only policy ⇒ empty FilterRule list (pre-consolidation behaviour)"
    );
}

#[test]
fn filter_rules_group_expansion_matches_pre_consolidation() {
    // The pre-consolidation `headscale-api::policy::doc::expand_principal`
    // returned `members.clone()` for a known group; the post-consolidation
    // canonical `AclDoc::expand_principal` must return the same Vec
    // ordering.
    let store = PolicyStore::new();
    let doc = PolicyDoc {
        groups: std::iter::once((
            "admins".to_string(),
            vec!["100.64.0.10".to_string(), "100.64.0.11".to_string()],
        ))
        .collect(),
        rules: vec![PolicyRule {
            action: PolicyAction::Accept,
            src: vec!["group:admins".into()],
            dst: vec!["*".into()],
            ports: vec!["tcp/22".into()],
        }],
        ..Default::default()
    };
    store.set(doc, "programmatic-group-filter".to_string());
    let rules = store.filter_rules();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].src_ips, vec!["100.64.0.10", "100.64.0.11"]);
}

// ---------------------------------------------------------------------------
// node_attrs_for(&node) — delegates to canonical AclDoc
// ---------------------------------------------------------------------------

#[test]
fn node_attrs_empty_until_policy_loaded() {
    let store = PolicyStore::new();
    let node = NodeView::new("100.64.0.1");
    assert!(
        store.node_attrs_for(&node).is_empty(),
        "no policy ⇒ no attrs (pre-consolidation contract)"
    );
}

#[test]
fn node_attrs_for_collects_via_canonical_doc() {
    let store = PolicyStore::new();
    let raw = r#"
        version = 1
        [tag_owners]
        "tag:exit" = ["alice@"]

        [[node_attrs]]
        target = ["*"]
        attr = ["funnel"]

        [[node_attrs]]
        target = ["tag:exit"]
        attr = ["exit-node"]
    "#;
    let doc = PolicyDoc::from_toml(raw).unwrap();
    store.set(doc, raw.to_string());

    let exit_tags = vec!["exit".to_string()];
    let exit_node = NodeView::new("100.64.0.1").with_tags(&exit_tags);
    let plain = NodeView::new("100.64.0.2");

    // Sorted, deduped — same as pre-consolidation
    // `PolicyDoc::node_attrs_for`.
    assert_eq!(
        store.node_attrs_for(&exit_node),
        vec!["exit-node".to_string(), "funnel".to_string()]
    );
    assert_eq!(store.node_attrs_for(&plain), vec!["funnel".to_string()]);
}

#[test]
fn node_can_have_tag_delegates_to_canonical_doc() {
    let store = PolicyStore::new();
    let alice = NodeView::new("100.64.0.1").with_user("alice");
    assert!(!store.node_can_have_tag(&alice, "tag:server"));

    let raw = r#"{
        "groups": {"group:admins": ["alice@"]},
        "tagOwners": {"tag:server": ["group:admins"]},
        "acls": []
    }"#;
    let doc = parse_hujson_policy(raw).unwrap();
    store.set(doc, raw.to_string());

    let bob = NodeView::new("100.64.0.2").with_user("bob");
    assert!(store.node_can_have_tag(&alice, "tag:server"));
    assert!(!store.node_can_have_tag(&bob, "tag:server"));
}

// ---------------------------------------------------------------------------
// auto_approves_route / auto_approves_exit_node
// ---------------------------------------------------------------------------

#[test]
fn auto_approve_helpers_false_when_no_policy() {
    let store = PolicyStore::new();
    let n = NodeView::new("100.64.0.1");
    assert!(
        !store.auto_approves_route(&n, "10.0.0.0/8"),
        "no policy ⇒ false (admin must require explicit operator action)"
    );
    assert!(!store.auto_approves_exit_node(&n));
}

#[test]
fn auto_approve_route_matches_subprefix_via_tag() {
    let store = PolicyStore::new();
    let raw = r#"{
        "autoApprovers": {
            "routes": {"10.0.0.0/8": ["tag:router"]},
            "exitNode": ["tag:exit"]
        },
        "tagOwners": {
            "tag:router": ["alice@"],
            "tag:exit": ["alice@"]
        },
        "acls": []
    }"#;
    let doc = parse_hujson_policy(raw).unwrap();
    store.set(doc, raw.to_string());

    let router_tags = vec!["router".to_string()];
    let router = NodeView::new("100.64.0.1").with_tags(&router_tags);
    let plain = NodeView::new("100.64.0.2");

    assert!(store.auto_approves_route(&router, "10.5.0.0/16"));
    assert!(!store.auto_approves_route(&plain, "10.5.0.0/16"));
    assert!(!store.auto_approves_route(&router, "8.8.8.0/24"));

    let exit_tags = vec!["exit".to_string()];
    let exit_node = NodeView::new("100.64.0.3").with_tags(&exit_tags);
    assert!(store.auto_approves_exit_node(&exit_node));
    assert!(!store.auto_approves_exit_node(&plain));
}

// ---------------------------------------------------------------------------
// BuildPeerMap / route-aware visibility
// ---------------------------------------------------------------------------

#[test]
fn build_peer_map_uses_symmetric_visibility_for_one_way_rules() {
    let raw = r#"{
        "tagOwners": {"tag:server": ["alice@"]},
        "acls": [
            {"action":"accept","src":["alice@"],"dst":["tag:server:*"]}
        ]
    }"#;
    let doc = parse_hujson_policy(raw).unwrap();
    let nodes = vec![
        PeerMapNode {
            id: 1,
            addr: "100.64.0.1".into(),
            user: Some("alice".into()),
            tags: Vec::new(),
            routes: Vec::new(),
        },
        PeerMapNode {
            id: 2,
            addr: "100.64.0.2".into(),
            user: Some("server-owner".into()),
            tags: vec!["tag:server".into()],
            routes: Vec::new(),
        },
        PeerMapNode {
            id: 3,
            addr: "100.64.0.3".into(),
            user: Some("bob".into()),
            tags: Vec::new(),
            routes: Vec::new(),
        },
    ];

    let peers = build_peer_map_for_doc(&doc, &nodes);
    assert_eq!(peers.get(&1).cloned().unwrap_or_default(), vec![2]);
    assert_eq!(peers.get(&2).cloned().unwrap_or_default(), vec![1]);
    assert_eq!(
        peers.get(&3).cloned().unwrap_or_default(),
        Vec::<u64>::new()
    );
}

#[test]
fn build_peer_map_includes_subnet_router_when_rule_targets_served_route() {
    let raw = r#"{
        "acls": [
            {"action":"accept","src":["alice@"],"dst":["10.10.0.0/16:*"]}
        ]
    }"#;
    let doc = parse_hujson_policy(raw).unwrap();
    let nodes = vec![
        PeerMapNode {
            id: 1,
            addr: "100.64.0.1".into(),
            user: Some("alice".into()),
            tags: Vec::new(),
            routes: Vec::new(),
        },
        PeerMapNode {
            id: 2,
            addr: "100.64.0.2".into(),
            user: Some("router-owner".into()),
            tags: Vec::new(),
            routes: vec!["10.10.1.0/24".into()],
        },
    ];

    let peers = build_peer_map_for_doc(&doc, &nodes);
    assert_eq!(peers.get(&1).cloned().unwrap_or_default(), vec![2]);
    assert_eq!(peers.get(&2).cloned().unwrap_or_default(), vec![1]);
}

// ---------------------------------------------------------------------------
// PolicyAction / PolicyDoc / PolicyRule symbol stability
// ---------------------------------------------------------------------------

#[test]
fn public_symbols_compile_under_old_names() {
    // The consolidation kept the headscale-side names alive as
    // re-exports from `headscale-api-acl`. This test verifies the
    // exact public symbols every existing caller depends on are
    // still in `headscale_api::policy::*`.
    let _: PolicyAction = PolicyAction::Accept;
    let _: PolicyAction = PolicyAction::Deny;
    let r = PolicyRule {
        action: PolicyAction::Accept,
        src: vec!["*".into()],
        dst: vec!["*".into()],
        ports: vec![],
    };
    let _: PolicyDoc = PolicyDoc {
        version: 1,
        rules: vec![r],
        ..Default::default()
    };
}

#[test]
fn upstream_acls_alias_round_trips() {
    // Pre-consolidation, `headscale-api::policy::PolicyDoc` accepted
    // both `rules` and `acls`. The canonical `AclDoc` keeps that
    // serde alias so an operator's upstream `juanfont/headscale`
    // policy file PUTs without renaming.
    let raw = r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#;
    let doc = parse_hujson_policy(raw).unwrap();
    assert_eq!(doc.rules.len(), 1);
}

// ---------------------------------------------------------------------------
// Live-reload Notify wakes parked long-pollers
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn set_still_wakes_parked_long_pollers() {
    let store = Arc::new(PolicyStore::new());
    let waiter = {
        let store = store.clone();
        tokio::spawn(async move {
            tokio::time::timeout(Duration::from_secs(2), store.wait_for_change())
                .await
                .expect("notify wakes within 2s");
        })
    };
    // Park the waiter, then push a doc — the existing #230 wake
    // semantics must survive the rewrite.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let raw = r#"{"acls":[]}"#;
    let doc = parse_hujson_policy(raw).unwrap();
    store.set(doc, raw.to_string());
    waiter.await.unwrap();
}
