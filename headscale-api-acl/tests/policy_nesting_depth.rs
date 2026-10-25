//! Nesting-depth bound for policy sources.
//!
//! Go's JSON decoders accept up to 10,000 nested containers. The policy
//! parser here materializes a `serde_json::Value` that is consumed
//! recursively (metadata stripping, clone/eq/serialize, drop), which
//! overflows a 2 MiB thread stack well below that bound and aborts the
//! process. Policies nested that deeply are rejected instead.

use headscale_api_acl::{parse_hujson_policy, parse_hujson_policy_bytes};

/// `{"groups":{"group:a":[{"a":[{"a":...1...}]}]}}` with `pairs`
/// array/object pairs: 2 + 2 * pairs containers.
fn mixed_groups(pairs: usize) -> String {
    let open = "[{\"a\":".repeat(pairs);
    let close = "}]".repeat(pairs);
    format!("{{\"groups\":{{\"group:a\":{open}1{close}}}}}")
}

/// A valid grant whose opaque app payload nests `depth` arrays:
/// 5 + depth containers.
fn app_policy(depth: usize) -> String {
    let open = "[".repeat(depth);
    let close = "]".repeat(depth);
    format!(
        "{{\"grants\":[{{\"src\":[\"*\"],\"dst\":[\"*\"],\"app\":{{\"example.com/cap\":[{open}{close}]}}}}]}}"
    )
}

#[test]
fn rejects_policy_nested_beyond_the_rust_depth_bound() {
    // 9,982 containers sit inside Go's bound and used to overflow the stack
    // of a release build while the metadata stripper walked the value.
    let raw = mixed_groups(4_990);
    assert!(parse_hujson_policy(&raw).is_err());
    assert!(parse_hujson_policy_bytes(raw.as_bytes()).is_err());

    // A policy that is otherwise valid is rejected once its opaque app
    // payload crosses the bound, so no deep value reaches later consumers.
    let deep_app = app_policy(1_100);
    assert!(parse_hujson_policy(&deep_app).is_err());
    assert!(parse_hujson_policy_bytes(deep_app.as_bytes()).is_err());
}

#[test]
fn accepts_realistic_nesting_within_the_bound() {
    let app = app_policy(200);
    assert!(parse_hujson_policy(&app).is_ok());
    assert!(parse_hujson_policy_bytes(app.as_bytes()).is_ok());
}
