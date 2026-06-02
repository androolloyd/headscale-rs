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

use headscale_api::policy::{
    NodeView, PacketFilterNode, PolicyAction, PolicyCheckNode, PolicyDoc, PolicyStore, PortRef,
    acl_to_filter_rules_for_node, check_policy_semantics, parse_hujson_policy,
};
use headscale_api::tailscale_wire::wire::FilterRule;

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/policy");
const PARITY_SCENARIOS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../tools/parity/scenarios");

fn load(name: &str) -> String {
    let path = format!("{FIXTURES}/{name}");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"))
}

fn load_parity_policy(name: &str) -> String {
    let path = format!("{PARITY_SCENARIOS}/{name}");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"));
    let scenario: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse fixture {path}: {e}"));
    serde_json::to_string(&scenario["policy"])
        .unwrap_or_else(|e| panic!("serialize fixture policy {path}: {e}"))
}

#[derive(Clone, Debug)]
struct ParityNode {
    id: u64,
    name: String,
    user: Option<String>,
    addr: String,
    addrs: Vec<String>,
    tags: Vec<String>,
    routes: Vec<String>,
}

impl ParityNode {
    fn user(id: u64, user: &str, addr: &str) -> Self {
        Self {
            id,
            name: format!("{user}-{id}"),
            user: Some(user.to_string()),
            addr: addr.to_string(),
            addrs: vec![addr.to_string()],
            tags: Vec::new(),
            routes: Vec::new(),
        }
    }

    fn tagged(id: u64, user: &str, addr: &str, tags: &[&str]) -> Self {
        Self {
            id,
            name: format!("{user}-{id}"),
            user: Some(user.to_string()),
            addr: addr.to_string(),
            addrs: vec![addr.to_string()],
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            routes: Vec::new(),
        }
    }

    fn view(&self) -> NodeView<'_> {
        let view = NodeView::new(&self.addr)
            .with_addrs(&self.addrs)
            .with_tags(&self.tags);
        if let Some(user) = self.user.as_deref() {
            view.with_user(user)
        } else {
            view
        }
    }

    fn packet_filter_node(&self) -> PacketFilterNode {
        PacketFilterNode {
            id: self.id,
            user_id: Some(self.id),
            user: self.user.clone(),
            addrs: self.addrs.clone(),
            tags: self.tags.clone(),
            routes: self.routes.clone(),
        }
    }

    fn policy_check_node(&self) -> PolicyCheckNode {
        PolicyCheckNode {
            id: self.id,
            user_id: Some(self.id),
            name: self.name.clone(),
            user: self.user.clone(),
            addrs: self.addrs.clone(),
            tags: self.tags.clone(),
        }
    }
}

fn assert_policy_accepts(
    doc: &PolicyDoc,
    src: &ParityNode,
    dst: &ParityNode,
    proto: &str,
    port: u16,
) {
    assert_eq!(
        doc.evaluate_with(&src.view(), &dst.view(), PortRef::new(proto, port)),
        PolicyAction::Accept,
        "{} should reach {} on {proto}/{port}",
        src.name,
        dst.name
    );
}

fn assert_policy_denies(
    doc: &PolicyDoc,
    src: &ParityNode,
    dst: &ParityNode,
    proto: &str,
    port: u16,
) {
    assert_eq!(
        doc.evaluate_with(&src.view(), &dst.view(), PortRef::new(proto, port)),
        PolicyAction::Deny,
        "{} should not reach {} on {proto}/{port}",
        src.name,
        dst.name
    );
}

fn visible_peer_count(doc: &PolicyDoc, viewer: &ParityNode, nodes: &[ParityNode]) -> usize {
    nodes
        .iter()
        .filter(|peer| peer.id != viewer.id)
        .filter(|peer| {
            doc.can_access_node(
                &viewer.view(),
                &viewer.routes,
                &peer.view(),
                &peer.routes,
                PortRef::any(),
            )
        })
        .count()
}

fn cap_grant_has_access(rules: &[FilterRule], cap: &str, dst_prefix: &str, access: &str) -> bool {
    rules.iter().flat_map(|rule| &rule.cap_grant).any(|grant| {
        grant.dsts.iter().any(|dst| dst == dst_prefix)
            && grant
                .cap_map
                .get(cap)
                .and_then(|values| values.as_ref())
                .is_some_and(|values| {
                    values.iter().any(|value| {
                        value.get("access").and_then(serde_json::Value::as_str) == Some(access)
                    })
                })
    })
}

fn cap_grant_present(rules: &[FilterRule], cap: &str, dst_prefix: &str) -> bool {
    rules.iter().flat_map(|rule| &rule.cap_grant).any(|grant| {
        grant.dsts.iter().any(|dst| dst == dst_prefix) && grant.cap_map.contains_key(cap)
    })
}

fn companion_cap_grant_present(rules: &[FilterRule], cap: &str, dst_prefix: &str) -> bool {
    rules.iter().flat_map(|rule| &rule.cap_grant).any(|grant| {
        grant.dsts.iter().any(|dst| dst == dst_prefix)
            && grant.cap_map.get(cap).is_some_and(Option::is_none)
    })
}

fn cap_grant_dsts(rules: &[FilterRule]) -> Vec<String> {
    let mut dsts = rules
        .iter()
        .flat_map(|rule| &rule.cap_grant)
        .flat_map(|grant| grant.dsts.clone())
        .collect::<Vec<_>>();
    dsts.sort();
    dsts.dedup();
    dsts
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
fn parses_taildrive_taildrop_caps_parity_fixture() {
    let raw = load_parity_policy("policy-v2-taildrive-taildrop-caps.json");
    let doc = parse_hujson_policy(&raw).expect("taildrive parity fixture must parse");
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

// ---------------------------------------------------------------------------
// Current upstream integration parity names from
// integration/{acl,cli_policy,grant_cap}_test.go.
// ---------------------------------------------------------------------------

#[test]
fn test_acl_allow_star_dst() {
    let doc = parse_hujson_policy(
        r#"{
          "acls": [
            {"action": "accept", "src": ["user1@"], "dst": ["*:*"]}
          ]
        }"#,
    )
    .unwrap();
    let user1 = ParityNode::user(1, "user1", "100.64.0.1");
    let user2 = ParityNode::user(2, "user2", "100.64.0.2");

    assert_policy_accepts(&doc, &user1, &user2, "tcp", 80);
    assert_policy_accepts(&doc, &user1, &user1, "udp", 41641);
    assert_policy_denies(&doc, &user2, &user1, "tcp", 80);
}

#[test]
fn test_acl_allow_user80_dst() {
    let doc = parse_hujson_policy(
        r#"{
          "acls": [
            {"action": "accept", "src": ["user1@"], "dst": ["user2@:80"]}
          ]
        }"#,
    )
    .unwrap();
    let user1 = ParityNode::user(1, "user1", "100.64.0.1");
    let user2 = ParityNode::user(2, "user2", "100.64.0.2");

    assert_policy_accepts(&doc, &user1, &user2, "tcp", 80);
    assert_policy_denies(&doc, &user1, &user2, "tcp", 22);
    assert_policy_denies(&doc, &user2, &user1, "tcp", 80);
}

#[test]
fn test_acl_allow_user_dst() {
    let doc = parse_hujson_policy(
        r#"{
          "acls": [
            {"action": "accept", "src": ["user1@"], "dst": ["user2@:*"]}
          ]
        }"#,
    )
    .unwrap();
    let user1 = ParityNode::user(1, "user1", "100.64.0.1");
    let user2 = ParityNode::user(2, "user2", "100.64.0.2");

    assert_policy_accepts(&doc, &user1, &user2, "tcp", 80);
    assert_policy_accepts(&doc, &user1, &user2, "udp", 41641);
    assert_policy_denies(&doc, &user2, &user1, "tcp", 80);
}

#[test]
fn test_acl_autogroup_member() {
    let doc = parse_hujson_policy(
        r#"{
          "acls": [
            {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}
          ]
        }"#,
    )
    .unwrap();
    let user1 = ParityNode::user(1, "user1", "100.64.0.1");
    let user2 = ParityNode::user(2, "user2", "100.64.0.2");
    let tagged = ParityNode::tagged(3, "user3", "100.64.0.3", &["tag:test"]);

    assert_policy_accepts(&doc, &user1, &user2, "tcp", 80);
    assert_policy_accepts(&doc, &user2, &user1, "tcp", 80);
    assert_policy_denies(&doc, &tagged, &user1, "tcp", 80);
}

#[test]
fn test_acl_autogroup_tagged() {
    let doc = parse_hujson_policy(
        r#"{
          "tagOwners": {"tag:test": ["user1@", "user2@"]},
          "acls": [
            {"action": "accept", "src": ["autogroup:tagged"], "dst": ["autogroup:tagged:*"]}
          ]
        }"#,
    )
    .unwrap();
    let tagged1 = ParityNode::tagged(1, "user1", "100.64.0.1", &["tag:test"]);
    let tagged2 = ParityNode::tagged(2, "user2", "100.64.0.2", &["tag:test"]);
    let untagged = ParityNode::user(3, "user1", "100.64.0.3");

    assert_policy_accepts(&doc, &tagged1, &tagged2, "tcp", 80);
    assert_policy_accepts(&doc, &tagged2, &tagged1, "tcp", 80);
    assert_policy_denies(&doc, &untagged, &tagged1, "tcp", 80);
}

#[test]
fn test_acl_deny_all_port80() {
    let doc = parse_hujson_policy(
        r#"{
          "groups": {"group:integration-acl-test": ["user1@", "user2@"]},
          "acls": [
            {"action": "accept", "src": ["group:integration-acl-test"], "dst": ["*:22"]}
          ]
        }"#,
    )
    .unwrap();
    let user1 = ParityNode::user(1, "user1", "100.64.0.1");
    let user2 = ParityNode::user(2, "user2", "100.64.0.2");

    assert_policy_accepts(&doc, &user1, &user2, "tcp", 22);
    assert_policy_denies(&doc, &user1, &user2, "tcp", 80);
    assert_policy_denies(&doc, &user2, &user1, "tcp", 80);
}

#[test]
fn test_acl_device1_can_access_device2() {
    let cases = [
        (
            "literal-ipv4",
            r#"{"acls":[{"action":"accept","src":["100.64.0.1"],"dst":["100.64.0.2:*"]}]}"#,
        ),
        (
            "host-alias",
            r#"{
              "hosts": {"test1": "100.64.0.1/32", "test2": "100.64.0.2/32"},
              "acls": [{"action":"accept","src":["test1"],"dst":["test2:*"]}]
            }"#,
        ),
        (
            "group-alias",
            r#"{
              "groups": {"group:one": ["user1@"], "group:two": ["user2@"]},
              "acls": [{"action":"accept","src":["group:one"],"dst":["group:two:*"]}]
            }"#,
        ),
    ];
    let user1 = ParityNode::user(1, "user1", "100.64.0.1");
    let user2 = ParityNode::user(2, "user2", "100.64.0.2");

    for (name, raw) in cases {
        let doc = parse_hujson_policy(raw).unwrap_or_else(|err| panic!("{name}: {err}"));
        assert_policy_accepts(&doc, &user1, &user2, "tcp", 80);
        assert_policy_denies(&doc, &user2, &user1, "tcp", 80);
    }
}

#[test]
fn test_acl_group_after_user_deletion() {
    let doc = parse_hujson_policy(
        r#"{
          "groups": {"group:all": ["user1@", "user2@", "user3@"]},
          "acls": [
            {"action": "accept", "src": ["group:all"], "dst": ["group:all:*"]}
          ]
        }"#,
    )
    .unwrap();
    let user1 = ParityNode::user(1, "user1", "100.64.0.1");
    let user2 = ParityNode::user(2, "user2", "100.64.0.2");
    let user4 = ParityNode::user(4, "user4", "100.64.0.4");

    assert_policy_accepts(&doc, &user1, &user2, "tcp", 80);
    assert_policy_accepts(&doc, &user2, &user1, "tcp", 80);
    assert_policy_denies(&doc, &user4, &user1, "tcp", 80);
}

#[test]
fn test_acl_group_deletion_exact_reproduction() {
    let doc = parse_hujson_policy(
        r#"{
          "groups": {
            "group:admin": ["user1@", "user3@", "deleteable@", "anotherinvaliduser@"]
          },
          "acls": [
            {"action": "accept", "src": ["group:admin"], "dst": ["*:*"]}
          ]
        }"#,
    )
    .unwrap();
    let user1 = ParityNode::user(1, "user1", "100.64.0.1");
    let user3 = ParityNode::user(3, "user3", "100.64.0.3");
    let outside = ParityNode::user(9, "outside", "100.64.0.9");

    assert_policy_accepts(&doc, &user1, &user3, "tcp", 80);
    assert_policy_accepts(&doc, &user3, &user1, "udp", 41641);
    assert_policy_denies(&doc, &outside, &user1, "tcp", 80);
}

#[test]
fn test_acl_hosts_in_net_map_table() {
    let allow_all =
        parse_hujson_policy(r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#).unwrap();
    let isolated = parse_hujson_policy(
        r#"{
          "acls": [
            {"action":"accept","src":["user1@"],"dst":["user1@:22"]},
            {"action":"accept","src":["user2@"],"dst":["user2@:22"]}
          ]
        }"#,
    )
    .unwrap();
    let nodes = vec![
        ParityNode::user(1, "user1", "100.64.0.1"),
        ParityNode::user(2, "user1", "100.64.0.2"),
        ParityNode::user(3, "user2", "100.64.0.3"),
        ParityNode::user(4, "user2", "100.64.0.4"),
    ];

    assert_eq!(visible_peer_count(&allow_all, &nodes[0], &nodes), 3);
    assert_eq!(visible_peer_count(&isolated, &nodes[0], &nodes), 1);
    assert_eq!(visible_peer_count(&isolated, &nodes[2], &nodes), 1);
}

#[test]
fn test_acl_named_hosts_can_reach() {
    let doc = parse_hujson_policy(
        r#"{
          "hosts": {
            "test1": "100.64.0.1/32",
            "test2": "100.64.0.2/32",
            "test3": "100.64.0.3/32"
          },
          "acls": [
            {"action": "accept", "src": ["*"], "dst": ["test3:*"]},
            {"action": "accept", "src": ["test1"], "dst": ["test2:*"]}
          ]
        }"#,
    )
    .unwrap();
    let test1 = ParityNode::user(1, "user1", "100.64.0.1");
    let test2 = ParityNode::user(2, "user2", "100.64.0.2");
    let test3 = ParityNode::user(3, "user2", "100.64.0.3");

    assert_policy_accepts(&doc, &test1, &test2, "tcp", 80);
    assert_policy_accepts(&doc, &test2, &test3, "tcp", 80);
    assert_policy_denies(&doc, &test2, &test1, "tcp", 80);
}

#[test]
fn test_acl_named_hosts_can_reach_by_subnet() {
    let doc = parse_hujson_policy(
        r#"{
          "hosts": {"all": "100.64.0.0/24"},
          "acls": [
            {"action": "accept", "src": ["*"], "dst": ["all:*"]}
          ]
        }"#,
    )
    .unwrap();
    let user1 = ParityNode::user(1, "user1", "100.64.0.1");
    let user2 = ParityNode::user(2, "user2", "100.64.0.2");
    let outside = ParityNode::user(3, "user2", "100.65.0.2");

    assert_policy_accepts(&doc, &user1, &user2, "tcp", 80);
    assert_policy_accepts(&doc, &user2, &user1, "tcp", 80);
    assert_policy_denies(&doc, &user1, &outside, "tcp", 80);
}

#[test]
fn test_acl_policy_propagation_over_time() {
    let store = PolicyStore::new();
    let user1 = ParityNode::user(1, "user1", "100.64.0.1");
    let user1_peer = ParityNode::user(2, "user1", "100.64.0.2");
    let user2 = ParityNode::user(3, "user2", "100.64.0.3");
    let policies = [
        (
            "allow-all",
            r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#,
            true,
            true,
        ),
        (
            "autogroup-self",
            r#"{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}"#,
            true,
            false,
        ),
        (
            "user1-to-user2",
            r#"{"acls":[{"action":"accept","src":["user1@"],"dst":["user2@:*"]}]}"#,
            false,
            true,
        ),
    ];

    for _ in 0..2 {
        for (name, raw, same_user_allowed, cross_user_allowed) in policies {
            let doc = parse_hujson_policy(raw).unwrap();
            store.set(doc, raw.to_string());
            let loaded = store.doc().unwrap_or_else(|| panic!("{name} not loaded"));
            let same =
                loaded.evaluate_with(&user1.view(), &user1_peer.view(), PortRef::new("tcp", 80));
            let cross = loaded.evaluate_with(&user1.view(), &user2.view(), PortRef::new("tcp", 80));
            assert_eq!(same == PolicyAction::Accept, same_user_allowed, "{name}");
            assert_eq!(cross == PolicyAction::Accept, cross_user_allowed, "{name}");
            assert_eq!(store.raw().as_deref(), Some(raw));
        }
    }
}

#[test]
fn test_acl_tag_propagation() {
    let doc = parse_hujson_policy(
        r#"{
          "tagOwners": {"tag:shared": ["user1@"]},
          "acls": [
            {"action":"accept","src":["user1@"],"dst":["user1@:*"]},
            {"action":"accept","src":["user2@"],"dst":["user2@:*"]},
            {"action":"accept","src":["user2@"],"dst":["tag:shared:*"]},
            {"action":"accept","src":["tag:shared"],"dst":["user2@:*"]}
          ]
        }"#,
    )
    .unwrap();
    let user2 = ParityNode::user(2, "user2", "100.64.0.2");
    let target_untagged = ParityNode::user(1, "user1", "100.64.0.1");
    let target_shared = ParityNode::tagged(1, "user1", "100.64.0.1", &["tag:shared"]);

    assert_policy_denies(&doc, &user2, &target_untagged, "tcp", 80);
    assert_policy_accepts(&doc, &user2, &target_shared, "tcp", 80);
    assert_policy_accepts(&doc, &target_shared, &user2, "tcp", 80);
}

#[test]
fn test_acl_tag_propagation_port_specific() {
    let doc = parse_hujson_policy(
        r#"{
          "tagOwners": {
            "tag:webserver": ["user1@"],
            "tag:sshonly": ["user1@"]
          },
          "acls": [
            {"action":"accept","src":["user2@"],"dst":["user2@:*"]},
            {"action":"accept","src":["user2@"],"dst":["tag:webserver:80"]},
            {"action":"accept","src":["user2@"],"dst":["tag:sshonly:22"]},
            {"action":"accept","proto":"icmp","src":["user2@"],"dst":["tag:webserver:*","tag:sshonly:*"]},
            {"action":"accept","src":["tag:webserver","tag:sshonly"],"dst":["user2@:*"]}
          ]
        }"#,
    )
    .unwrap();
    let user2 = ParityNode::user(2, "user2", "100.64.0.2");
    let web = ParityNode::tagged(1, "user1", "100.64.0.1", &["tag:webserver"]);
    let ssh = ParityNode::tagged(1, "user1", "100.64.0.1", &["tag:sshonly"]);

    assert_policy_accepts(&doc, &user2, &web, "tcp", 80);
    assert_policy_denies(&doc, &user2, &web, "tcp", 22);
    assert_policy_accepts(&doc, &user2, &web, "icmp", 0);
    assert_policy_denies(&doc, &user2, &ssh, "tcp", 80);
    assert_policy_accepts(&doc, &user2, &ssh, "tcp", 22);
    assert_policy_accepts(&doc, &user2, &ssh, "icmp", 0);
}

#[test]
fn test_policy_update_while_running_with_cli_in_database() {
    let store = PolicyStore::new();
    let allow_all = r#"{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}"#;
    let updated = r#"{"acls":[{"action":"accept","src":["user1@"],"dst":["user2@:*"]}]}"#;
    let user1 = ParityNode::user(1, "user1", "100.64.0.1");
    let user2 = ParityNode::user(2, "user2", "100.64.0.2");

    store.set(
        parse_hujson_policy(allow_all).unwrap(),
        allow_all.to_string(),
    );
    assert_policy_accepts(&store.doc().unwrap(), &user2, &user1, "tcp", 80);

    store.set(parse_hujson_policy(updated).unwrap(), updated.to_string());
    let doc = store.doc().unwrap();
    assert_eq!(store.raw().as_deref(), Some(updated));
    assert_policy_accepts(&doc, &user1, &user2, "tcp", 80);
    assert_policy_denies(&doc, &user2, &user1, "tcp", 80);
}

#[test]
fn test_policy_check_command() {
    let nodes = vec![
        ParityNode::user(1, "user1", "100.64.0.1").policy_check_node(),
        ParityNode::user(2, "user2", "100.64.0.2").policy_check_node(),
    ];
    let acl_only = parse_hujson_policy(
        r#"{"acls":[{"action":"accept","proto":"tcp","src":["user1@"],"dst":["user2@:22"]}]}"#,
    )
    .unwrap();
    let passing = parse_hujson_policy(
        r#"{
          "acls": [{"action":"accept","proto":"tcp","src":["user1@"],"dst":["user2@:22"]}],
          "tests": [{"src":"user1@","accept":["user2@:22"]}]
        }"#,
    )
    .unwrap();
    let failing = parse_hujson_policy(
        r#"{
          "acls": [{"action":"accept","proto":"tcp","src":["user1@"],"dst":["user2@:22"]}],
          "tests": [{"src":"user2@","accept":["user1@:22"]}]
        }"#,
    )
    .unwrap();

    check_policy_semantics(&acl_only, &nodes).unwrap();
    check_policy_semantics(&passing, &nodes).unwrap();
    let err = check_policy_semantics(&failing, &nodes).unwrap_err();
    assert!(err.contains("test(s) failed"));
}

#[test]
fn test_ssh_tests_reject_failing_policy() {
    let nodes = vec![ParityNode::user(1, "user1", "100.64.0.1").policy_check_node()];
    let good_raw = r#"{
      "ssh": [
        {"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"],"users":["root"]}
      ],
      "sshTests": [
        {"src":"user1@","dst":["autogroup:self"],"accept":["root"]}
      ]
    }"#;
    let bad_raw = r#"{
      "ssh": [
        {"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"],"users":["root"]}
      ],
      "sshTests": [
        {"src":"user1@","dst":["autogroup:self"],"accept":["ubuntu"]}
      ]
    }"#;
    let good = parse_hujson_policy(good_raw).unwrap();
    let bad = parse_hujson_policy(bad_raw).unwrap();
    let store = PolicyStore::new();

    check_policy_semantics(&good, &nodes).unwrap();
    store.set(good, good_raw.to_string());
    let err = check_policy_semantics(&bad, &nodes).unwrap_err();
    assert!(err.contains("test(s) failed"));
    assert!(err.contains("expected ALLOWED, got DENIED"));
    assert_eq!(store.raw().as_deref(), Some(good_raw));
}

#[test]
fn test_grant_cap_relay() {
    let doc = parse_hujson_policy(
        r#"{
          "tagOwners": {
            "tag:relay": ["relay@"],
            "tag:client-a": ["clienta@"],
            "tag:client-b": ["clientb@"]
          },
          "grants": [
            {
              "src": ["tag:relay", "tag:client-a", "tag:client-b"],
              "dst": ["tag:relay", "tag:client-a", "tag:client-b"],
              "ip": ["*"]
            },
            {
              "src": ["tag:client-a", "tag:client-b"],
              "dst": ["tag:relay"],
              "app": {"tailscale.com/cap/relay": [{}]}
            }
          ]
        }"#,
    )
    .unwrap();
    let relay = ParityNode::tagged(1, "relay", "100.64.0.10", &["tag:relay"]);
    let client_a = ParityNode::tagged(2, "clienta", "100.64.0.11", &["tag:client-a"]);
    let client_b = ParityNode::tagged(3, "clientb", "100.64.0.12", &["tag:client-b"]);
    let nodes = [relay.clone(), client_a.clone(), client_b]
        .iter()
        .map(ParityNode::packet_filter_node)
        .collect::<Vec<_>>();

    let relay_rules = acl_to_filter_rules_for_node(&doc, &nodes, relay.id);
    assert!(
        cap_grant_present(&relay_rules, "tailscale.com/cap/relay", "100.64.0.10/32"),
        "relay cap dsts: {:?}",
        cap_grant_dsts(&relay_rules)
    );

    let client_rules = acl_to_filter_rules_for_node(&doc, &nodes, client_a.id);
    assert!(
        companion_cap_grant_present(
            &client_rules,
            "tailscale.com/cap/relay-target",
            "100.64.0.11/32"
        ),
        "client companion cap dsts: {:?}",
        cap_grant_dsts(&client_rules)
    );
    assert!(!cap_grant_present(
        &client_rules,
        "tailscale.com/cap/relay",
        "100.64.0.11/32"
    ));
}

#[test]
fn test_grant_cap_drive() {
    let doc = parse_hujson_policy(
        r#"{
          "tagOwners": {
            "tag:sharer": ["sharer@"],
            "tag:rw-client": ["rwclient@"],
            "tag:ro-client": ["roclient@"],
            "tag:no-access": ["noaccess@"]
          },
          "nodeAttrs": [
            {"target": ["*"], "attr": ["drive:share", "drive:access"]}
          ],
          "grants": [
            {
              "src": ["tag:sharer", "tag:rw-client", "tag:ro-client", "tag:no-access"],
              "dst": ["tag:sharer", "tag:rw-client", "tag:ro-client", "tag:no-access"],
              "ip": ["*"]
            },
            {
              "src": ["tag:rw-client"],
              "dst": ["tag:sharer"],
              "app": {"tailscale.com/cap/drive": [{"shares":["*"],"access":"rw"}]}
            },
            {
              "src": ["tag:ro-client"],
              "dst": ["tag:sharer"],
              "app": {"tailscale.com/cap/drive": [{"shares":["*"],"access":"ro"}]}
            }
          ]
        }"#,
    )
    .unwrap();
    let sharer = ParityNode::tagged(1, "sharer", "100.64.0.10", &["tag:sharer"]);
    let rw = ParityNode::tagged(2, "rwclient", "100.64.0.11", &["tag:rw-client"]);
    let ro = ParityNode::tagged(3, "roclient", "100.64.0.12", &["tag:ro-client"]);
    let no_access = ParityNode::tagged(4, "noaccess", "100.64.0.13", &["tag:no-access"]);
    let nodes = [sharer.clone(), rw.clone(), ro, no_access.clone()]
        .iter()
        .map(ParityNode::packet_filter_node)
        .collect::<Vec<_>>();

    assert_eq!(
        doc.node_attrs_for(&sharer.view()),
        vec!["drive:access".to_string(), "drive:share".to_string()]
    );

    let sharer_rules = acl_to_filter_rules_for_node(&doc, &nodes, sharer.id);
    assert!(
        cap_grant_has_access(
            &sharer_rules,
            "tailscale.com/cap/drive",
            "100.64.0.10/32",
            "rw"
        ),
        "sharer cap dsts: {:?}",
        cap_grant_dsts(&sharer_rules)
    );
    assert!(
        cap_grant_has_access(
            &sharer_rules,
            "tailscale.com/cap/drive",
            "100.64.0.10/32",
            "ro"
        ),
        "sharer cap dsts: {:?}",
        cap_grant_dsts(&sharer_rules)
    );

    let rw_rules = acl_to_filter_rules_for_node(&doc, &nodes, rw.id);
    assert!(
        companion_cap_grant_present(
            &rw_rules,
            "tailscale.com/cap/drive-sharer",
            "100.64.0.11/32"
        ),
        "rw companion cap dsts: {:?}",
        cap_grant_dsts(&rw_rules)
    );

    let no_access_rules = acl_to_filter_rules_for_node(&doc, &nodes, no_access.id);
    assert!(!cap_grant_present(
        &no_access_rules,
        "tailscale.com/cap/drive",
        "100.64.0.13/32"
    ));
    assert!(!companion_cap_grant_present(
        &no_access_rules,
        "tailscale.com/cap/drive-sharer",
        "100.64.0.13/32"
    ));
}
