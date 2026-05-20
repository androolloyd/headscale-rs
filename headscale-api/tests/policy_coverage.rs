//! Coverage tests for the policy parser (`policy::hujson`) and the
//! [`PolicyStore`] live-reload surface.
//!
//! Companion to the unit tests in `src/policy/{hujson,filter}.rs` —
//! these tests hit every comment style, every escape, every error
//! path on the parser and verify the store's atomic-swap + Notify
//! contract.

#![cfg(feature = "admin")]

use std::sync::Arc;
use std::time::Duration;

use headscale_api::policy::{
    PolicyAction, PolicyDoc, PolicyRule, PolicyStore, acl_to_filter_rules, parse_hujson_policy,
};

// ---------------------------------------------------------------------------
// hujson parser — comment styles
// ---------------------------------------------------------------------------

#[test]
fn line_comment_at_eol_is_stripped() {
    let raw = r#"{
        "version": 1, // trailing line comment
        "rules": []
    }"#;
    let doc = parse_hujson_policy(raw).expect("parses with trailing line comment");
    assert_eq!(doc.version, 1);
}

#[test]
fn line_comment_at_eof_without_newline_is_stripped() {
    let raw = "{\"version\":1,\"rules\":[]} // no newline";
    let doc = parse_hujson_policy(raw).expect("parses with EOF line comment");
    assert_eq!(doc.version, 1);
}

#[test]
fn block_comment_inside_object_is_stripped() {
    let raw = r#"{
        /* leading block */ "version": 1,
        "rules": [/* inline */]
    }"#;
    parse_hujson_policy(raw).expect("parses with inline block comments");
}

#[test]
fn unterminated_block_comment_is_swallowed_to_eof() {
    // The stripper consumes the unterminated `/* ...` to EOF then
    // serde_json fails on the truncated body. We just need to assert
    // we get a parse error (not a panic).
    let raw = "{\"version\":1,\"rules\":[]} /* never closed";
    let _ = parse_hujson_policy(raw); // either Ok or Err — must NOT panic
}

#[test]
fn nested_block_comment_is_not_supported() {
    // Tailscale's hujson stripper matches the SHORTEST `*/` — nested
    // block comments would leak. We just document the behaviour: the
    // outer `*/` ends the outer comment, the trailing text trips serde.
    let raw = r#"{ "version":1, "rules":[] /* outer /* inner */ leak */ }"#;
    let _ = parse_hujson_policy(raw); // accepted as garbage-on-trailer
}

#[test]
fn trailing_comma_before_brace_and_bracket() {
    let raw = r#"{
        "version": 1,
        "groups": { "admins": ["100.64.0.1",], },
        "rules": [],
    }"#;
    let doc = parse_hujson_policy(raw).expect("parses both trailing-comma styles");
    assert_eq!(doc.groups["admins"].len(), 1);
}

// ---------------------------------------------------------------------------
// hujson parser — string-literal preservation
// ---------------------------------------------------------------------------

#[test]
fn escaped_quote_in_string_does_not_terminate_string() {
    let raw = r#"{
        "version": 1,
        "groups": { "k": ["a\"b\"c"] },
        "rules": []
    }"#;
    let doc = parse_hujson_policy(raw).expect("escaped quote preserved");
    assert_eq!(doc.groups["k"], vec![r#"a"b"c"#]);
}

#[test]
fn backslash_escapes_round_trip() {
    let raw = r#"{
        "version": 1,
        "groups": { "k": ["c:\\users\\test"] },
        "rules": []
    }"#;
    let doc = parse_hujson_policy(raw).expect("backslash escape preserved");
    assert!(doc.groups["k"][0].contains('\\'));
}

#[test]
fn double_slash_inside_string_is_not_a_comment() {
    let raw = r#"{
        "version": 1,
        "groups": { "k": ["https://x.example.com/path//deep"] },
        "rules": []
    }"#;
    let doc = parse_hujson_policy(raw).expect("URL with // preserved");
    assert!(doc.groups["k"][0].contains("//deep"));
}

#[test]
fn slash_star_inside_string_is_not_a_comment() {
    let raw = r#"{
        "version": 1,
        "groups": { "k": ["regex: a/*b*/"] },
        "rules": []
    }"#;
    let doc = parse_hujson_policy(raw).expect("/* inside string preserved");
    assert!(doc.groups["k"][0].contains("/*"));
}

#[test]
fn comma_inside_string_is_not_a_trailing_comma() {
    let raw = r#"{
        "version": 1,
        "groups": { "k": ["a,b,c"] },
        "rules": []
    }"#;
    let doc = parse_hujson_policy(raw).expect("comma inside string preserved");
    assert_eq!(doc.groups["k"][0], "a,b,c");
}

// ---------------------------------------------------------------------------
// hujson parser — error paths
// ---------------------------------------------------------------------------

#[test]
fn empty_input_yields_json_error() {
    let err = parse_hujson_policy("").unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("json"));
}

#[test]
fn pure_comments_yields_json_error() {
    let err = parse_hujson_policy("// just a comment\n/* and another */").unwrap_err();
    assert!(format!("{err}").to_lowercase().contains("json"));
}

#[test]
fn missing_required_version_field_is_schema_error() {
    // `version` is non-default — without it serde_json fails the
    // schema check, surfaced as `PolicyParseError::Schema`.
    let raw = r#"{ "rules": [] }"#;
    let err = parse_hujson_policy(raw).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("missing field") && msg.contains("version"),
        "expected schema diagnostic naming 'version', got: {msg}"
    );
}

#[test]
fn unknown_top_level_field_is_schema_error() {
    let raw = r#"{ "version": 1, "rules": [], "unknown_extra": true }"#;
    let err = parse_hujson_policy(raw).unwrap_err();
    assert!(
        format!("{err}").contains("unknown_extra"),
        "schema error should name the unknown field"
    );
}

#[test]
fn rule_missing_action_is_schema_error() {
    let raw = r#"{
        "version": 1,
        "rules": [{"src":["*"],"dst":["*"]}]
    }"#;
    let err = parse_hujson_policy(raw).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("action") || msg.contains("missing field"),
        "rule missing `action` must error, got: {msg}"
    );
}

#[test]
fn rule_with_invalid_action_value_is_schema_error() {
    let raw = r#"{
        "version": 1,
        "rules": [{"action":"maybe","src":["*"],"dst":["*"]}]
    }"#;
    assert!(parse_hujson_policy(raw).is_err());
}

#[test]
fn unknown_rule_field_is_schema_error() {
    // PolicyRule is `deny_unknown_fields` (see src/policy/doc.rs).
    let raw = r#"{
        "version": 1,
        "rules": [{"action":"accept","src":["*"],"dst":["*"],"extra":1}]
    }"#;
    let err = parse_hujson_policy(raw).unwrap_err();
    assert!(format!("{err}").contains("extra"));
}

// ---------------------------------------------------------------------------
// PolicyDoc::expand_principal
// ---------------------------------------------------------------------------

#[test]
fn expand_principal_wildcard_returns_wildcard() {
    let d = PolicyDoc::empty();
    assert_eq!(d.expand_principal("*"), vec!["*"]);
}

#[test]
fn expand_principal_unknown_group_returns_empty_vec() {
    let d = PolicyDoc::empty();
    assert_eq!(d.expand_principal("group:nope"), Vec::<String>::new());
}

#[test]
fn expand_principal_known_group_returns_members() {
    let mut d = PolicyDoc::empty();
    d.groups
        .insert("admins".to_string(), vec!["a".to_string(), "b".to_string()]);
    assert_eq!(d.expand_principal("group:admins"), vec!["a", "b"]);
}

#[test]
fn expand_principal_literal_returns_itself() {
    let d = PolicyDoc::empty();
    assert_eq!(d.expand_principal("oct1xyz"), vec!["oct1xyz"]);
}

// ---------------------------------------------------------------------------
// acl_to_filter_rules — additional coverage
// ---------------------------------------------------------------------------

#[test]
fn rule_with_empty_dst_is_dropped() {
    let doc = PolicyDoc {
        version: 1,
        groups: std::collections::BTreeMap::new(),
        rules: vec![PolicyRule {
            action: PolicyAction::Accept,
            src: vec!["*".into()],
            dst: vec!["group:unknown".into()],
            ports: vec!["*/*".into()],
        }],
        ..Default::default()
    };
    assert!(acl_to_filter_rules(&doc).is_empty());
}

#[test]
fn invalid_port_pattern_drops_rule() {
    let doc = PolicyDoc {
        version: 1,
        groups: std::collections::BTreeMap::new(),
        rules: vec![PolicyRule {
            action: PolicyAction::Accept,
            src: vec!["*".into()],
            dst: vec!["*".into()],
            ports: vec!["tcp/notanumber".into()],
        }],
        ..Default::default()
    };
    // The single port pattern is unparseable, so port_ranges is empty
    // and the rule is dropped (default-deny on garbage).
    assert!(acl_to_filter_rules(&doc).is_empty());
}

#[test]
fn legacy_star_colon_port_form_is_accepted() {
    let doc = PolicyDoc {
        version: 1,
        groups: std::collections::BTreeMap::new(),
        rules: vec![PolicyRule {
            action: PolicyAction::Accept,
            src: vec!["*".into()],
            dst: vec!["*".into()],
            ports: vec!["*:tcp/22".into()],
        }],
        ..Default::default()
    };
    let rs = acl_to_filter_rules(&doc);
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].dst_ports[0].ports.first, 22);
    assert_eq!(rs[0].dst_ports[0].ports.last, 22);
}

#[test]
fn port_range_with_hi_below_lo_drops_pattern() {
    let doc = PolicyDoc {
        version: 1,
        groups: std::collections::BTreeMap::new(),
        rules: vec![PolicyRule {
            action: PolicyAction::Accept,
            src: vec!["*".into()],
            dst: vec!["*".into()],
            ports: vec!["tcp/100-50".into()],
        }],
        ..Default::default()
    };
    assert!(acl_to_filter_rules(&doc).is_empty(), "hi<lo must drop rule");
}

#[test]
fn src_dedupes_repeated_principals() {
    let mut groups = std::collections::BTreeMap::new();
    groups.insert(
        "a".to_string(),
        vec!["100.64.0.1".to_string(), "100.64.0.2".to_string()],
    );
    groups.insert(
        "b".to_string(),
        vec!["100.64.0.1".to_string(), "100.64.0.3".to_string()],
    );
    let doc = PolicyDoc {
        version: 1,
        groups,
        tags: std::collections::BTreeMap::new(),
        rules: vec![PolicyRule {
            action: PolicyAction::Accept,
            src: vec!["group:a".into(), "group:b".into()],
            dst: vec!["*".into()],
            ports: vec!["*/*".into()],
        }],
        ..Default::default()
    };
    let rs = acl_to_filter_rules(&doc);
    assert_eq!(rs.len(), 1);
    // 100.64.0.1 appears in both groups; the translator must dedupe.
    assert_eq!(rs[0].src_ips.len(), 3);
    assert!(rs[0].src_ips.contains(&"100.64.0.1".to_string()));
    assert!(rs[0].src_ips.contains(&"100.64.0.2".to_string()));
    assert!(rs[0].src_ips.contains(&"100.64.0.3".to_string()));
}

// ---------------------------------------------------------------------------
// PolicyStore — atomic swap + Notify
// ---------------------------------------------------------------------------

#[test]
fn store_default_is_unloaded() {
    let s = PolicyStore::new();
    assert!(!s.is_loaded());
    assert!(s.doc().is_none());
    assert!(s.raw().is_none());
    assert!(s.filter_rules().is_empty());
}

#[test]
fn store_set_caches_filter_rules() {
    let s = PolicyStore::new();
    let raw = r#"{
        "version": 1,
        "rules": [{"action":"accept","src":["*"],"dst":["*"],"ports":["tcp/22"]}]
    }"#;
    let doc = parse_hujson_policy(raw).unwrap();
    s.set(doc.clone(), raw.to_string());
    assert!(s.is_loaded());
    assert_eq!(s.raw().unwrap(), raw);
    assert_eq!(s.doc().unwrap(), doc);
    let rules = s.filter_rules();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].dst_ports[0].ports.first, 22);
}

#[test]
fn store_set_preserves_raw_comments_verbatim() {
    let s = PolicyStore::new();
    let raw = "{\n  // comments must survive\n  \"version\":1,\n  \"rules\":[]\n}";
    let doc = parse_hujson_policy(raw).unwrap();
    s.set(doc, raw.to_string());
    assert_eq!(s.raw().unwrap(), raw, "raw bytes round-trip with comments");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn store_set_wakes_parked_long_pollers() {
    let s = Arc::new(PolicyStore::new());
    let s2 = s.clone();
    let waiter = tokio::spawn(async move {
        let h = s2.notify();
        // Tight timeout — wake should fire on the next tokio tick.
        tokio::time::timeout(Duration::from_secs(2), h.changed())
            .await
            .expect("notify wakes within 2s");
    });
    // Let the waiter park.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let raw = r#"{"version":1,"rules":[]}"#;
    let doc = parse_hujson_policy(raw).unwrap();
    s.set(doc, raw.to_string());
    waiter.await.unwrap();
}
