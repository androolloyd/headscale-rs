//! Thin facade over `headscale-api-acl`.
//!
//! Pre-2026-05-20 this module carried a copy of the hujson stripper
//! and most of the `parse_hujson_policy` entry-point. The shared parser
//! lives in `headscale-api-acl` so `octravpn-mesh` and `headscale-api`
//! parse identical bytes through the same state machine. This file keeps
//! the existing `headscale_api::policy::{parse_hujson_policy,
//! PolicyParseError}` symbols stable for admin callers + the
//! `headscale-cli` admin client, while preserving a few public
//! headscale-go compatibility shims that only affect admin policy input.

pub use headscale_api_acl::PolicyParseError;

/// Parse an upstream-shaped HuJSON policy.
pub fn parse_hujson_policy(raw: &str) -> Result<headscale_api_acl::AclDoc, PolicyParseError> {
    let normalized = normalize_ssh_action_fields(raw);
    let input = normalized.as_deref().unwrap_or(raw);
    headscale_api_acl::parse_hujson_policy(input).map_err(normalize_policy_error)
}

fn normalize_ssh_action_fields(raw: &str) -> Option<String> {
    let stripped = headscale_api_acl::strip_hujson(raw);
    let mut value = serde_json::from_str::<serde_json::Value>(&stripped).ok()?;
    let object = value.as_object_mut()?;
    let ssh_key = object
        .keys()
        .find(|key| key.eq_ignore_ascii_case("ssh"))?
        .clone();
    let ssh_rules = object.get_mut(&ssh_key)?.as_array_mut()?;

    let mut changed = false;
    for rule in ssh_rules {
        let Some(rule) = rule.as_object_mut() else {
            continue;
        };
        let action_key = rule
            .keys()
            .find(|key| key.eq_ignore_ascii_case("action"))
            .cloned();
        if let Some(key) = action_key {
            let Some(action) = rule.get(&key).and_then(serde_json::Value::as_str) else {
                continue;
            };
            let trimmed = action.trim().to_string();
            if trimmed != action {
                rule.insert(key, serde_json::Value::String(trimmed));
                changed = true;
            }
        } else {
            rule.insert(
                "action".to_string(),
                serde_json::Value::String(String::new()),
            );
            changed = true;
        }
    }

    changed
        .then(|| serde_json::to_string(&value).ok())
        .flatten()
}

fn normalize_policy_error(err: PolicyParseError) -> PolicyParseError {
    match err {
        PolicyParseError::Json(msg) => PolicyParseError::Json(msg),
        PolicyParseError::Schema(msg) => PolicyParseError::Schema(normalize_schema_message(&msg)),
    }
}

fn normalize_schema_message(msg: &str) -> String {
    let msg = replace_invalid_ssh_action_messages(msg);
    replace_invalid_alias_message(&msg)
}

fn replace_invalid_ssh_action_messages(msg: &str) -> String {
    const PREFIX: &str = "invalid SSH action ";
    const SUFFIX: &str = ", must be one of: accept, check";

    let mut rest = msg;
    let mut out = String::new();
    while let Some(start) = rest.find(PREFIX) {
        let value_start = start + PREFIX.len();
        let Some(end) = rest[value_start..].find(SUFFIX) else {
            break;
        };
        let value_end = value_start + end;
        let value = &rest[value_start..value_end];

        out.push_str(&rest[..start]);
        if value == "\"\"" {
            out.push_str("action must be specified");
        } else {
            out.push_str(value);
            out.push_str(" is not a valid action");
        }
        rest = &rest[value_end + SUFFIX.len()..];
    }

    if out.is_empty() {
        msg.to_string()
    } else {
        out.push_str(rest);
        out
    }
}

fn replace_invalid_alias_message(msg: &str) -> String {
    const PREFIX: &str = "Invalid alias ";
    const SUFFIX: &str = ". An alias must be one of the supported upstream policy alias types";

    let Some(start) = msg.find(PREFIX) else {
        return msg.to_string();
    };
    let value_start = start + PREFIX.len();
    let Some(end) = msg[value_start..].find(SUFFIX) else {
        return msg.to_string();
    };
    let value_end = value_start + end;

    let mut out = String::new();
    out.push_str(&msg[..start]);
    out.push_str("invalid alias format: ");
    out.push_str(&msg[value_start..value_end]);
    out.push_str(&msg[value_end + SUFFIX.len()..]);
    out
}

#[cfg(test)]
mod tests {
    use super::parse_hujson_policy;

    #[test]
    fn ssh_action_whitespace_is_trimmed_like_headscale_go() {
        let doc = parse_hujson_policy(
            r#"{
              "ssh": [{
                "action": " accept ",
                "src": ["alice@"],
                "dst": ["autogroup:self"],
                "users": ["root"]
              }]
            }"#,
        )
        .unwrap();

        assert_eq!(doc.ssh[0].action, "accept");
    }

    #[test]
    fn ssh_action_validation_uses_headscale_go_wording() {
        for (name, raw, want) in [
            (
                "missing",
                r#"{
                  "ssh": [{
                    "src": ["alice@"],
                    "dst": ["autogroup:self"],
                    "users": ["root"]
                  }]
                }"#,
                "action must be specified",
            ),
            (
                "blank",
                r#"{
                  "ssh": [{
                    "action": " \t\n ",
                    "src": ["alice@"],
                    "dst": ["autogroup:self"],
                    "users": ["root"]
                  }]
                }"#,
                "action must be specified",
            ),
            (
                "invalid",
                r#"{
                  "ssh": [{
                    "action": " invalid ",
                    "src": ["alice@"],
                    "dst": ["autogroup:self"],
                    "users": ["root"]
                  }]
                }"#,
                r#""invalid" is not a valid action"#,
            ),
        ] {
            let err = parse_hujson_policy(raw).expect_err(name).to_string();
            assert!(
                err.contains(want),
                "{name} should contain {want:?}, got {err}"
            );
        }
    }

    #[test]
    fn invalid_alias_validation_uses_headscale_go_wording() {
        let err = parse_hujson_policy(
            r#"{
              "acls": [{
                "action": "accept",
                "src": ["*"],
                "dst": ["fd7a:115c:a1e0::1"]
              }]
            }"#,
        )
        .unwrap_err()
        .to_string();

        assert!(err.contains(r#"invalid alias format: "fd7a:115c:a1e0:""#));
        assert!(!err.contains("Invalid alias"));
    }
}
