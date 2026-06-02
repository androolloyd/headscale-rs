#![allow(unknown_lints, clippy::duration_suboptimal_units)]

use std::{collections::BTreeMap, time::Duration};

use headscale_api::policy::{
    PacketFilterNode, PolicyDoc, SshPolicyNode, acl_to_filter_rules_for_node, compile_ssh_policy,
    compile_ssh_policy_with_base_url, parse_hujson_policy, ssh::ssh_check_period_for,
};
use headscale_api::tailscale_wire::wire::{SshPolicy, SshRule};
use headscale_api::tailscale_wire::{AuthWaitOutcome, RegistrationCache, SshCheckBinding};

const CURRENT_HEAD_FIXTURES: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../tools/parity/current-head");

fn user_node(id: u64, user: &str, ip: u8) -> SshPolicyNode {
    SshPolicyNode {
        id,
        user: Some(user.into()),
        user_id: Some(id_user(user)),
        addrs: vec![format!("100.64.0.{ip}")],
        tags: Vec::new(),
    }
}

fn tagged_node(id: u64, user: &str, ip: u8, tag: &str) -> SshPolicyNode {
    SshPolicyNode {
        id,
        user: Some(user.into()),
        user_id: Some(id_user(user)),
        addrs: vec![format!("100.64.0.{ip}")],
        tags: vec![tag.into()],
    }
}

fn id_user(user: &str) -> u64 {
    match user {
        "user1" => 1,
        "user2" => 2,
        _ => 99,
    }
}

fn packet_nodes(nodes: &[SshPolicyNode]) -> Vec<PacketFilterNode> {
    nodes
        .iter()
        .map(|node| PacketFilterNode {
            id: node.id,
            user_id: node.user_id,
            user: node.user.clone(),
            addrs: node.addrs.clone(),
            tags: node.tags.clone(),
            routes: Vec::new(),
        })
        .collect()
}

fn doc(raw: &str) -> PolicyDoc {
    parse_hujson_policy(raw).unwrap()
}

fn current_head_policy_doc(name: &str) -> PolicyDoc {
    let path = format!("{CURRENT_HEAD_FIXTURES}/{name}");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read fixture {path}: {e}"));
    let scenario: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse fixture {path}: {e}"));
    let policy_raw = serde_json::to_string(&scenario["policy"])
        .unwrap_or_else(|e| panic!("serialize fixture policy {path}: {e}"));
    parse_hujson_policy(&policy_raw).unwrap_or_else(|e| panic!("parse fixture policy {path}: {e}"))
}

fn base_nodes() -> Vec<SshPolicyNode> {
    vec![
        user_node(1, "user1", 1),
        user_node(2, "user1", 2),
        user_node(3, "user2", 3),
        user_node(4, "user2", 4),
    ]
}

fn check_nodes() -> Vec<SshPolicyNode> {
    vec![
        user_node(1, "user1", 1),
        tagged_node(2, "user1", 2, "tag:server"),
        user_node(3, "user2", 3),
    ]
}

fn policy_ips(policy: &SshPolicy) -> Vec<Vec<&str>> {
    policy
        .rules
        .iter()
        .map(rule_ips)
        .collect::<Vec<Vec<&str>>>()
}

fn rule_ips(rule: &SshRule) -> Vec<&str> {
    rule.principals
        .iter()
        .map(|principal| principal.node_ip.as_str())
        .collect()
}

fn ssh_users(policy: &SshPolicy) -> Vec<BTreeMap<String, String>> {
    policy
        .rules
        .iter()
        .map(|rule| rule.ssh_users.clone())
        .collect()
}

fn assert_accept(rule: &SshRule) {
    assert!(rule.action.accept);
    assert!(!rule.action.reject);
    assert!(rule.action.hold_and_delegate.is_empty());
    assert!(rule.action.allow_agent_forwarding);
    assert!(rule.action.allow_local_port_forwarding);
    assert!(rule.action.allow_remote_port_forwarding);
}

fn assert_check(rule: &SshRule) {
    assert!(!rule.action.accept);
    assert!(!rule.action.reject);
    assert!(
        rule.action
            .hold_and_delegate
            .contains("/machine/ssh/action/")
    );
    assert!(
        rule.action
            .hold_and_delegate
            .contains("local_user=$LOCAL_USER")
    );
}

#[test]
fn test_ssh_one_user_to_all() {
    let doc = doc(r#"{
          "groups": {"group:integration-test": ["user1@"]},
          "acls": [{"action":"accept","proto":"tcp","src":["*"],"dst":["*:0-65535"]}],
          "ssh": [{
            "action": "accept",
            "src": ["group:integration-test"],
            "dst": ["autogroup:member", "autogroup:tagged"],
            "users": ["ssh-it-user"]
          }]
        }"#);
    let nodes = base_nodes();

    for target in 1..=4 {
        let policy = compile_ssh_policy(&doc, &nodes, target).unwrap();
        assert_eq!(policy.rules.len(), 1, "target {target}");
        assert_eq!(rule_ips(&policy.rules[0]), vec!["100.64.0.1", "100.64.0.2"]);
        assert_eq!(policy.rules[0].ssh_users["ssh-it-user"], "ssh-it-user");
        assert_eq!(policy.rules[0].ssh_users["root"], "");
        assert_accept(&policy.rules[0]);
    }
}

#[test]
fn test_ssh_multiple_users_all_to_all() {
    let doc = doc(r#"{
          "groups": {"group:integration-test": ["user1@", "user2@"]},
          "acls": [{"action":"accept","proto":"tcp","src":["*"],"dst":["*:0-65535"]}],
          "ssh": [{
            "action": "accept",
            "src": ["group:integration-test"],
            "dst": ["autogroup:self"],
            "users": ["ssh-it-user"]
          }]
        }"#);
    let nodes = base_nodes();

    let user1_target = compile_ssh_policy(&doc, &nodes, 2).unwrap();
    let user2_target = compile_ssh_policy(&doc, &nodes, 4).unwrap();

    assert_eq!(
        rule_ips(&user1_target.rules[0]),
        vec!["100.64.0.1", "100.64.0.2"]
    );
    assert_eq!(
        rule_ips(&user2_target.rules[0]),
        vec!["100.64.0.3", "100.64.0.4"]
    );
    assert!(
        !policy_ips(&user1_target)
            .iter()
            .flatten()
            .any(|ip| ip.starts_with("100.64.0.3") || ip.starts_with("100.64.0.4")),
        "autogroup:self must not leak user2 principals into user1 targets"
    );
    assert_accept(&user1_target.rules[0]);
    assert_accept(&user2_target.rules[0]);
}

#[test]
fn test_ssh_no_ssh_configured() {
    let doc = doc(r#"{
          "groups": {"group:integration-test": ["user1@"]},
          "acls": [{"action":"accept","proto":"tcp","src":["*"],"dst":["*:0-65535"]}],
          "ssh": []
        }"#);

    assert!(compile_ssh_policy(&doc, &base_nodes(), 1).is_none());
}

#[test]
fn test_ssh_is_blocked_in_acl() {
    let doc = doc(r#"{
          "groups": {"group:integration-test": ["user1@"]},
          "acls": [{"action":"accept","proto":"tcp","src":["*"],"dst":["*:80"]}],
          "ssh": [{
            "action": "accept",
            "src": ["group:integration-test"],
            "dst": ["autogroup:self"],
            "users": ["ssh-it-user"]
          }]
        }"#);
    let nodes = base_nodes();
    let ssh_policy = compile_ssh_policy(&doc, &nodes, 2).unwrap();
    assert_eq!(ssh_policy.rules.len(), 1);
    assert_accept(&ssh_policy.rules[0]);

    let packet_rules = acl_to_filter_rules_for_node(&doc, &packet_nodes(&nodes), 2);
    assert!(
        packet_rules.iter().any(|rule| rule
            .dst_ports
            .iter()
            .any(|dst| dst.ports.first == 80 && dst.ports.last == 80)),
        "upstream scenario allows TCP/80 so packet filter is not empty"
    );
    assert!(
        packet_rules.iter().all(|rule| rule
            .dst_ports
            .iter()
            .all(|dst| !(dst.ports.first <= 22 && 22 <= dst.ports.last))),
        "SSH policy may allow the session, but the ACL packet filter must still block TCP/22"
    );
}

#[test]
fn current_head_multi_address_fixture_compiles_ssh_principals_and_accept_env() {
    let doc = current_head_policy_doc("multi-address-policy-ssh-dns-route-matrix.json");
    let nodes = vec![
        SshPolicyNode {
            id: 1,
            user: Some("alice@example.com".into()),
            user_id: Some(1),
            addrs: vec!["100.64.44.10".into(), "fd7a:115c:a1e0::10".into()],
            tags: Vec::new(),
        },
        SshPolicyNode {
            id: 2,
            user: Some("ops@example.com".into()),
            user_id: Some(2),
            addrs: vec!["100.64.44.20".into(), "fd7a:115c:a1e0::20".into()],
            tags: vec!["tag:server".into()],
        },
    ];

    let policy = compile_ssh_policy(&doc, &nodes, 2).unwrap();

    assert_eq!(policy.rules.len(), 1);
    assert_eq!(
        rule_ips(&policy.rules[0]),
        vec!["100.64.44.10", "fd7a:115c:a1e0::10"]
    );
    assert_eq!(
        policy.rules[0].ssh_users,
        BTreeMap::from([("root".to_string(), "root".to_string())])
    );
    assert_eq!(policy.rules[0].accept_env, vec!["LANG"]);
    assert_accept(&policy.rules[0]);
}

#[test]
fn test_ssh_user_only_isolation() {
    let doc = doc(r#"{
          "groups": {
            "group:ssh1": ["user1@"],
            "group:ssh2": ["user2@"]
          },
          "acls": [{"action":"accept","proto":"tcp","src":["*"],"dst":["*:0-65535"]}],
          "ssh": [
            {
              "action": "accept",
              "src": ["group:ssh1"],
              "dst": ["autogroup:self"],
              "users": ["ssh-it-user"]
            },
            {
              "action": "accept",
              "src": ["group:ssh2"],
              "dst": ["autogroup:self"],
              "users": ["ssh-it-user"]
            }
          ]
        }"#);
    let nodes = base_nodes();

    let user1_target = compile_ssh_policy(&doc, &nodes, 2).unwrap();
    let user2_target = compile_ssh_policy(&doc, &nodes, 4).unwrap();

    assert_eq!(user1_target.rules.len(), 1);
    assert_eq!(user2_target.rules.len(), 1);
    assert_eq!(
        rule_ips(&user1_target.rules[0]),
        vec!["100.64.0.1", "100.64.0.2"]
    );
    assert_eq!(
        rule_ips(&user2_target.rules[0]),
        vec!["100.64.0.3", "100.64.0.4"]
    );
    assert_eq!(ssh_users(&user1_target), ssh_users(&user2_target));
}

#[test]
fn test_ssh_autogroup_self() {
    let doc = doc(r#"{
          "acls": [{"action":"accept","proto":"tcp","src":["*"],"dst":["*:0-65535"]}],
          "ssh": [{
            "action": "accept",
            "src": ["autogroup:member"],
            "dst": ["autogroup:self"],
            "users": ["ssh-it-user"]
          }]
        }"#);
    let nodes = base_nodes();

    let user1_target = compile_ssh_policy(&doc, &nodes, 1).unwrap();
    let user2_target = compile_ssh_policy(&doc, &nodes, 3).unwrap();

    assert_eq!(
        rule_ips(&user1_target.rules[0]),
        vec!["100.64.0.1", "100.64.0.2"]
    );
    assert_eq!(
        rule_ips(&user2_target.rules[0]),
        vec!["100.64.0.3", "100.64.0.4"]
    );
}

#[test]
fn test_ssh_localpart_profile_variants_special_chars_and_no_match() {
    let mut nodes = vec![
        SshPolicyNode {
            id: 10,
            user: Some("dave+sshuser@example.com".into()),
            user_id: Some(10),
            addrs: vec!["100.64.0.10".into()],
            tags: Vec::new(),
        },
        SshPolicyNode {
            id: 11,
            user: Some("dave-cli".into()),
            user_id: Some(11),
            addrs: vec!["100.64.0.11".into()],
            tags: Vec::new(),
        },
        SshPolicyNode {
            id: 12,
            user: Some("server@example.com".into()),
            user_id: Some(12),
            addrs: vec!["100.64.0.12".into()],
            tags: vec!["tag:server".into()],
        },
    ];

    let special = doc(r#"{
          "tagOwners": {"tag:server": ["server@example.com"]},
          "acls": [{"action":"accept","proto":"tcp","src":["*"],"dst":["*:0-65535"]}],
          "ssh": [{
            "action": "accept",
            "src": ["autogroup:member"],
            "dst": ["tag:server"],
            "users": ["localpart:*@example.com"]
          }]
        }"#);

    let policy = compile_ssh_policy(&special, &nodes, 12).unwrap();
    assert_eq!(policy.rules.len(), 3);
    assert_eq!(rule_ips(&policy.rules[0]), vec!["100.64.0.10"]);
    assert_eq!(
        policy.rules[0].ssh_users,
        BTreeMap::from([("root".to_string(), String::new())])
    );
    assert_eq!(rule_ips(&policy.rules[1]), vec!["100.64.0.10"]);
    assert_eq!(
        policy.rules[1].ssh_users,
        BTreeMap::from([("dave+sshuser".to_string(), "dave+sshuser".to_string())])
    );
    assert_eq!(rule_ips(&policy.rules[2]), vec!["100.64.0.11"]);
    assert_eq!(
        policy.rules[2].ssh_users,
        BTreeMap::from([("root".to_string(), String::new())])
    );
    assert!(
        policy
            .rules
            .iter()
            .all(|rule| !rule.ssh_users.contains_key("localpart:*@example.com")),
        "client-facing sshUsers must contain concrete login users, not localpart patterns"
    );

    nodes[0].user = Some("dave+sshuser@other.example".into());
    let no_match = compile_ssh_policy(&special, &nodes, 12).unwrap();
    assert_eq!(no_match.rules.len(), 2);
    assert_eq!(rule_ips(&no_match.rules[0]), vec!["100.64.0.10"]);
    assert_eq!(
        no_match.rules[0].ssh_users,
        BTreeMap::from([("root".to_string(), String::new())])
    );
    assert_eq!(rule_ips(&no_match.rules[1]), vec!["100.64.0.11"]);
    assert_eq!(
        no_match.rules[1].ssh_users,
        BTreeMap::from([("root".to_string(), String::new())])
    );
}

#[test]
fn test_ssh_one_user_to_one_check_mode_cli() {
    let doc = doc(r#"{
          "groups": {"group:integration-test": ["user1@"]},
          "acls": [{"action":"accept","proto":"tcp","src":["*"],"dst":["*:0-65535"]}],
          "tagOwners": {"tag:server": ["user1@"]},
          "ssh": [{
            "action": "check",
            "src": ["group:integration-test"],
            "dst": ["autogroup:member", "autogroup:tagged"],
            "users": ["ssh-it-user"]
          }]
        }"#);
    let nodes = check_nodes();

    let user1_target =
        compile_ssh_policy_with_base_url(&doc, &nodes, 2, "https://headscale.example").unwrap();
    let user2_target =
        compile_ssh_policy_with_base_url(&doc, &nodes, 3, "https://headscale.example").unwrap();

    assert_eq!(user1_target.rules.len(), 1);
    assert_eq!(rule_ips(&user1_target.rules[0]), vec!["100.64.0.1"]);
    assert_eq!(
        user1_target.rules[0].ssh_users["ssh-it-user"],
        "ssh-it-user"
    );
    assert_check(&user1_target.rules[0]);
    assert_eq!(
        ssh_check_period_for(&doc, &nodes, 1, 2),
        Some(Duration::from_secs(12 * 60 * 60))
    );
    assert_eq!(user2_target.rules.len(), 1);
    assert_eq!(rule_ips(&user2_target.rules[0]), vec!["100.64.0.1"]);
    assert_check(&user2_target.rules[0]);
    assert_eq!(ssh_check_period_for(&doc, &nodes, 3, 1), None);
}

#[test]
fn test_ssh_one_user_to_one_check_mode_oidc() {
    let doc = doc(r#"{
          "groups": {"group:integration-test": ["user1@"]},
          "acls": [{"action":"accept","proto":"tcp","src":["*"],"dst":["*:0-65535"]}],
          "ssh": [{
            "action": "check",
            "src": ["group:integration-test"],
            "dst": ["autogroup:member", "autogroup:tagged"],
            "users": ["ssh-it-user"]
          }]
        }"#);
    let nodes = check_nodes();

    let policy =
        compile_ssh_policy_with_base_url(&doc, &nodes, 1, "https://headscale.example").unwrap();

    assert_eq!(policy.rules.len(), 1);
    assert_eq!(rule_ips(&policy.rules[0]), vec!["100.64.0.1"]);
    assert_check(&policy.rules[0]);
    assert!(
        policy.rules[0]
            .action
            .hold_and_delegate
            .starts_with("https://headscale.example/machine/ssh/action/"),
        "OIDC check approval uses the same delegated SSH action URL exposed to clients"
    );
}

#[test]
fn test_ssh_check_mode_check_period_cli() {
    let doc = doc(r#"{
          "groups": {"group:integration-test": ["user1@"]},
          "acls": [{"action":"accept","proto":"tcp","src":["*"],"dst":["*:0-65535"]}],
          "ssh": [{
            "action": "check",
            "checkPeriod": "1m",
            "src": ["group:integration-test"],
            "dst": ["autogroup:member", "autogroup:tagged"],
            "users": ["ssh-it-user"]
          }]
        }"#);
    let nodes = check_nodes();
    let policy =
        compile_ssh_policy_with_base_url(&doc, &nodes, 2, "https://headscale.example").unwrap();

    assert_check(&policy.rules[0]);
    assert_eq!(
        ssh_check_period_for(&doc, &nodes, 1, 2),
        Some(Duration::from_secs(60))
    );
    assert_eq!(ssh_check_period_for(&doc, &nodes, 3, 2), None);
}

#[tokio::test]
async fn test_ssh_check_mode_negative_cli() {
    let doc = doc(r#"{
          "groups": {"group:integration-test": ["user1@"]},
          "acls": [{"action":"accept","proto":"tcp","src":["*"],"dst":["*:0-65535"]}],
          "ssh": [{
            "action": "check",
            "src": ["group:integration-test"],
            "dst": ["autogroup:member", "autogroup:tagged"],
            "users": ["ssh-it-user"]
          }]
        }"#);
    let nodes = check_nodes();

    assert_eq!(
        ssh_check_period_for(&doc, &nodes, 1, 2),
        Some(Duration::from_secs(12 * 60 * 60))
    );
    assert_eq!(
        ssh_check_period_for(&doc, &nodes, 1, 3),
        Some(Duration::from_secs(12 * 60 * 60))
    );
    assert_eq!(ssh_check_period_for(&doc, &nodes, 3, 1), None);

    let binding = SshCheckBinding {
        src_node_id: 1,
        dst_node_id: 2,
        local_user: "ssh-it-user".into(),
    };
    let cache = RegistrationCache::new();
    cache.insert_ssh_check("abcdefghijklmnopqrstuvwx".into(), binding.clone());
    assert!(cache.reject("abcdefghijklmnopqrstuvwx", "denied"));
    assert_eq!(
        cache.wait_for_auth("abcdefghijklmnopqrstuvwx").await,
        AuthWaitOutcome::Rejected("denied".into())
    );
    assert!(
        cache.last_ssh_auth(&binding, Some(1)).is_none(),
        "rejected CLI checks must not seed check-period auto approval"
    );
}
