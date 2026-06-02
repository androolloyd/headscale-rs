//! End-to-end coverage for policy v2 surfaces. Headscale-go v0.28
//! HuJSON fixtures use the strict upstream schema; internal extension
//! surfaces such as `node_attrs` are exercised through the TOML/internal
//! parser instead of the public Go-shaped HuJSON parser.
//!
//! 1. The hujson parser accepts the upstream-shape document.
//! 2. The PolicyDoc fields land in the right places (no silent drop).
//! 3. `node_attrs_for` / `auto_approves_*` return the expected
//!    decisions for a small set of synthetic NodeViews.
//!
//! Tied to `docs/headscale-gap-analysis.md` §4 ACL/policy engine —
//! these were P1 gaps in the gap analysis.

#![cfg(feature = "admin")]

use headscale_api::policy::{NodeView, PolicyDoc, PolicyStore, parse_hujson_policy};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/policy");
const CURRENT_HEAD_FIXTURES: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../tools/parity/current-head");

fn load(name: &str) -> String {
    let path = format!("{FIXTURES}/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"))
}

fn load_current_head_policy(name: &str) -> String {
    let path = format!("{CURRENT_HEAD_FIXTURES}/{name}");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"));
    let scenario: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse fixture {path}: {e}"));
    serde_json::to_string(&scenario["policy"])
        .unwrap_or_else(|e| panic!("serialize fixture policy {path}: {e}"))
}

fn nodeattrs_doc() -> PolicyDoc {
    PolicyDoc::from_toml(
        r#"
            version = 1

            [[rules]]
            action = "accept"
            src = ["*"]
            dst = ["*"]
            ports = ["*/*"]

            [tag_owners]
            "tag:exit" = ["alice@example.com"]
            "tag:custom" = ["alice@example.com"]

            [[node_attrs]]
            target = ["*"]
            attr = ["mullvad-exit-node"]

            [[node_attrs]]
            target = ["tag:custom"]
            attr = ["custom-node-attr"]

            [[node_attrs]]
            target = ["tag:exit"]
            attr = ["exit-node"]
        "#,
    )
    .unwrap()
}

fn hosts_doc() -> PolicyDoc {
    PolicyDoc::from_toml(
        r#"
            version = 1

            [hosts]
            monitor = "10.1.2.3/32"
            router = "10.0.0.1/32"

            [[rules]]
            action = "accept"
            src = ["host:monitor"]
            dst = ["host:router"]
            ports = ["tcp/22"]
        "#,
    )
    .unwrap()
}

// ---------------------------------------------------------------------------
// upstream_acl_a01 — wide-shape policy (autogroups + hosts + groups +
// tagOwners + autoApprovers.routes) parses without losing fields
// ---------------------------------------------------------------------------

#[test]
fn parses_upstream_acl_a01_fixture() {
    let raw = load("upstream_acl_a01.hujson");
    let doc = parse_hujson_policy(&raw).expect("a01 must parse");
    assert_eq!(doc.version, 1);
    assert_eq!(doc.rules.len(), 1);
    assert!(doc.groups.contains_key("group:admins"));
    assert!(doc.groups.contains_key("group:developers"));
    assert_eq!(doc.hosts["internal"], "10.0.0.0/8");
    assert!(doc.tag_owners.contains_key("tag:router"));
    assert_eq!(doc.auto_approvers.routes.len(), 2);
    assert_eq!(doc.auto_approvers.exit_node, vec!["tag:exit"]);
}

// ---------------------------------------------------------------------------
// internal node_attrs — extension block round-trips and
// node_attrs_for returns the merged flag list per target
// ---------------------------------------------------------------------------

#[test]
fn parses_internal_nodeattrs_toml() {
    let doc = nodeattrs_doc();
    assert_eq!(doc.node_attrs.len(), 3);

    let exit_tags = vec!["exit".to_string()];
    let custom_tags = vec!["custom".to_string()];
    let exit_node = NodeView::new("100.64.0.1").with_tags(&exit_tags);
    let custom_node = NodeView::new("100.64.0.2").with_tags(&custom_tags);
    let plain_node = NodeView::new("100.64.0.3");

    // `*` target grants mullvad-exit-node to every node.
    assert!(
        doc.node_attrs_for(&exit_node)
            .contains(&"mullvad-exit-node".to_string()),
        "tag:exit node must still inherit the universal mullvad-exit-node grant"
    );
    assert!(
        doc.node_attrs_for(&plain_node)
            .contains(&"mullvad-exit-node".to_string())
    );
    // tag:exit also grants exit-node.
    assert!(
        doc.node_attrs_for(&exit_node)
            .contains(&"exit-node".to_string())
    );
    assert!(
        !doc.node_attrs_for(&plain_node)
            .contains(&"exit-node".to_string())
    );
    // tag:custom grants custom-node-attr.
    assert!(
        doc.node_attrs_for(&custom_node)
            .contains(&"custom-node-attr".to_string())
    );
}

#[test]
fn parses_current_head_taildrive_taildrop_caps_fixture() {
    let raw = load_current_head_policy("policy-v2-taildrive-taildrop-caps.json");
    let doc = parse_hujson_policy(&raw).expect("taildrive current-head fixture must parse");
    assert_eq!(doc.node_attrs.len(), 2);
    assert_eq!(doc.grants.len(), 1);
    assert!(doc.grants[0].app.contains_key("tailscale.com/cap/drive"));

    let client_tags = vec!["tag:client".to_string()];
    let server_tags = vec!["tag:server".to_string()];
    let client = NodeView::new("100.64.0.11").with_tags(&client_tags);
    let server = NodeView::new("100.64.0.12").with_tags(&server_tags);
    let plain = NodeView::new("100.64.0.13").with_user("carol@example.com");

    assert_eq!(doc.node_attrs_for(&client), vec!["drive:access"]);
    assert_eq!(
        doc.node_attrs_for(&server),
        vec![
            "drive:access".to_string(),
            "drive:share".to_string(),
            "https://tailscale.com/cap/file-sharing".to_string(),
        ]
    );
    assert_eq!(doc.node_attrs_for(&plain), vec!["drive:access"]);
}

// ---------------------------------------------------------------------------
// internal hosts — `hosts` expansion via `expand_principal`
// ---------------------------------------------------------------------------

#[test]
fn parses_internal_hosts_toml() {
    let doc = hosts_doc();
    assert_eq!(doc.hosts["monitor"], "10.1.2.3/32");

    let host = doc.expand_principal("host:router");
    assert_eq!(host, vec!["10.0.0.1/32"]);
}

// ---------------------------------------------------------------------------
// upstream_autoapprovers — camelCase parse + auto_approves_route /
// auto_approves_exit_node decisions
// ---------------------------------------------------------------------------

#[test]
fn parses_upstream_autoapprovers_fixture() {
    let raw = load("upstream_autoapprovers.hujson");
    let doc = parse_hujson_policy(&raw).expect("autoApprovers fixture must parse");
    assert_eq!(doc.auto_approvers.routes.len(), 3);
    assert_eq!(doc.auto_approvers.exit_node, vec!["tag:exit"]);

    let router_tags = vec!["router".to_string()];
    let router = NodeView::new("100.64.0.1").with_tags(&router_tags);
    let exit_tags = vec!["exit".to_string()];
    let exit = NodeView::new("100.64.0.2").with_tags(&exit_tags);
    let plain = NodeView::new("100.64.0.3");
    let alice = NodeView::new("100.64.0.4").with_user("alice@example.com");

    // tag:router can approve 10.0.0.0/8 routes (and sub-prefixes).
    assert!(doc.auto_approves_route(&router, "10.5.0.0/16"));
    assert!(!doc.auto_approves_route(&plain, "10.5.0.0/16"));

    // group:admins can approve 172.16.0.0/12 routes.
    assert!(doc.auto_approves_route(&alice, "172.16.0.0/12"));
    assert!(!doc.auto_approves_route(&router, "172.16.0.0/12"));

    // tag:exit auto-approves exit-node.
    assert!(doc.auto_approves_exit_node(&exit));
    assert!(!doc.auto_approves_exit_node(&router));
}

// ---------------------------------------------------------------------------
// upstream_ssh — `ssh` block round-trips
// ---------------------------------------------------------------------------

#[test]
fn parses_upstream_ssh_fixture() {
    let raw = load("upstream_ssh.hujson");
    let doc = parse_hujson_policy(&raw).expect("ssh fixture must parse");
    assert_eq!(doc.ssh.len(), 2);
    assert_eq!(doc.ssh[0].action, "accept");
    assert_eq!(doc.ssh[1].action, "check");
    assert_eq!(doc.ssh[0].users, vec!["root"]);
}

// ---------------------------------------------------------------------------
// PolicyStore — wires the new accessors
// ---------------------------------------------------------------------------

#[test]
fn store_node_attrs_for_returns_empty_when_unloaded() {
    let s = PolicyStore::new();
    let n = NodeView::new("100.64.0.1");
    assert!(s.node_attrs_for(&n).is_empty());
}

#[test]
fn store_node_attrs_for_forwards_to_doc() {
    let s = PolicyStore::new();
    let doc = nodeattrs_doc();
    s.set(doc, "internal-nodeattrs-toml".to_string());
    let exit_tags = vec!["exit".to_string()];
    let n = NodeView::new("100.64.0.1").with_tags(&exit_tags);
    let attrs = s.node_attrs_for(&n);
    assert!(attrs.contains(&"exit-node".to_string()));
    assert!(attrs.contains(&"mullvad-exit-node".to_string()));
}

#[test]
fn store_auto_approves_route_returns_false_when_unloaded() {
    let s = PolicyStore::new();
    let n = NodeView::new("100.64.0.1");
    assert!(!s.auto_approves_route(&n, "10.0.0.0/8"));
}

#[test]
fn store_auto_approves_route_forwards_to_doc() {
    let s = PolicyStore::new();
    let raw = load("upstream_autoapprovers.hujson");
    let doc = parse_hujson_policy(&raw).unwrap();
    s.set(doc, raw);
    let router_tags = vec!["router".to_string()];
    let router = NodeView::new("100.64.0.1").with_tags(&router_tags);
    assert!(s.auto_approves_route(&router, "10.0.0.0/16"));
}

#[test]
fn store_auto_approves_exit_node_forwards_to_doc() {
    let s = PolicyStore::new();
    let raw = load("upstream_autoapprovers.hujson");
    let doc = parse_hujson_policy(&raw).unwrap();
    s.set(doc, raw);
    let exit_tags = vec!["exit".to_string()];
    let exit = NodeView::new("100.64.0.1").with_tags(&exit_tags);
    let plain = NodeView::new("100.64.0.2");
    assert!(s.auto_approves_exit_node(&exit));
    assert!(!s.auto_approves_exit_node(&plain));
}

// ---------------------------------------------------------------------------
// expand_principal — coverage for the new token kinds
// ---------------------------------------------------------------------------

#[test]
fn expand_principal_handles_autogroup_internet() {
    let raw = load("upstream_acl_a01.hujson");
    let doc = parse_hujson_policy(&raw).unwrap();
    let exp = doc.expand_principal("autogroup:internet");
    assert_eq!(exp, headscale_api_acl::internet_filter_cidrs());
}

#[test]
fn expand_principal_handles_autogroup_member() {
    let raw = load("upstream_acl_a01.hujson");
    let doc = parse_hujson_policy(&raw).unwrap();
    let exp = doc.expand_principal("autogroup:member");
    assert_eq!(exp, vec!["0.0.0.0/0", "::/0"]);
}

#[test]
fn expand_principal_drops_non_flattenable_autogroups() {
    // `self`, `nonroot`, `tagged`, `tag:*` can't be expanded into a
    // static SrcIPs list — the doc layer emits an empty vec so the
    // filter translator drops the rule (default-deny on missing
    // SrcIPs).
    let raw = load("upstream_acl_a01.hujson");
    let doc = parse_hujson_policy(&raw).unwrap();
    assert!(doc.expand_principal("autogroup:self").is_empty());
    assert!(doc.expand_principal("autogroup:tagged").is_empty());
    assert!(doc.expand_principal("autogroup:nonroot").is_empty());
}

#[test]
fn expand_principal_handles_unknown_host() {
    let doc = hosts_doc();
    assert!(doc.expand_principal("host:does-not-exist").is_empty());
}
