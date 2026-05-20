//! End-to-end coverage for the extended policy v2 surface (autogroups,
//! NodeAttrs, autoApprovers, ipsets, hosts, tag_owners, ssh). Loads
//! representative hujson fixtures modelled on upstream
//! `juanfont/headscale@main:hscontrol/policy/v2/testdata/` and walks
//! each through the public PolicyDoc API to verify:
//!
//! 1. The hujson parser accepts the upstream-shape document.
//! 2. The PolicyDoc fields land in the right places (no silent drop).
//! 3. `node_attrs_for` / `auto_approves_*` return the expected
//!    decisions for a small set of synthetic NodeViews.
//!
//! Tied to `docs/headscale-gap-analysis.md` §4 ACL/policy engine —
//! these were P1 gaps in the gap analysis.

#![cfg(feature = "admin")]

use headscale_api::policy::{NodeView, PolicyStore, parse_hujson_policy};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/policy");

fn load(name: &str) -> String {
    let path = format!("{FIXTURES}/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"))
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
    assert!(doc.groups.contains_key("admins"));
    assert!(doc.groups.contains_key("developers"));
    assert_eq!(doc.hosts["internal"], "10.0.0.0/8");
    assert!(doc.tag_owners.contains_key("tag:router"));
    assert_eq!(doc.auto_approvers.routes.len(), 2);
    assert_eq!(doc.auto_approvers.exit_node, vec!["tag:exit"]);
}

// ---------------------------------------------------------------------------
// upstream_nodeattrs — `nodeAttrs` (camelCase) round-trips and
// node_attrs_for returns the merged flag list per target
// ---------------------------------------------------------------------------

#[test]
fn parses_upstream_nodeattrs_fixture() {
    let raw = load("upstream_nodeattrs.hujson");
    let doc = parse_hujson_policy(&raw).expect("nodeattrs fixture must parse");
    assert_eq!(doc.node_attrs.len(), 3);

    let exit_tags = vec!["exit".to_string()];
    let funnel_tags = vec!["funnel".to_string()];
    let exit_node = NodeView::new("100.64.0.1").with_tags(&exit_tags);
    let funnel_node = NodeView::new("100.64.0.2").with_tags(&funnel_tags);
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
    // tag:funnel grants funnel.
    assert!(
        doc.node_attrs_for(&funnel_node)
            .contains(&"funnel".to_string())
    );
}

// ---------------------------------------------------------------------------
// upstream_ipsets — `ipsets` + `hosts` expansion via `expand_principal`
// ---------------------------------------------------------------------------

#[test]
fn parses_upstream_ipsets_fixture() {
    let raw = load("upstream_ipsets.hujson");
    let doc = parse_hujson_policy(&raw).expect("ipsets fixture must parse");
    assert_eq!(doc.ipsets["office"].len(), 2);
    assert_eq!(doc.ipsets["lab"].len(), 1);
    assert_eq!(doc.hosts["monitor"], "10.1.2.3/32");

    // expand_principal flattens these for the FilterRule layer.
    let office = doc.expand_principal("ipset:office");
    assert_eq!(office.len(), 2);
    assert!(office.iter().any(|s| s == "10.0.0.0/8"));
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
    let raw = load("upstream_nodeattrs.hujson");
    let doc = parse_hujson_policy(&raw).unwrap();
    s.set(doc, raw);
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
    assert_eq!(exp, vec!["*"]);
}

#[test]
fn expand_principal_handles_autogroup_member() {
    let raw = load("upstream_acl_a01.hujson");
    let doc = parse_hujson_policy(&raw).unwrap();
    let exp = doc.expand_principal("autogroup:member");
    assert_eq!(exp, vec!["*"]);
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
fn expand_principal_handles_unknown_ipset() {
    let raw = load("upstream_ipsets.hujson");
    let doc = parse_hujson_policy(&raw).unwrap();
    assert!(doc.expand_principal("ipset:does-not-exist").is_empty());
}

#[test]
fn expand_principal_handles_unknown_host() {
    let raw = load("upstream_ipsets.hujson");
    let doc = parse_hujson_policy(&raw).unwrap();
    assert!(doc.expand_principal("host:does-not-exist").is_empty());
}
