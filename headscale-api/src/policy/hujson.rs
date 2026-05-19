//! hujson → [`PolicyDoc`] parser.
//!
//! hujson is JSON with three extras: `//` line comments, `/* … */`
//! block comments, and trailing commas before `]`/`}`. Stock
//! `tailscale` accepts all three; our admin PUT route does too so
//! the operator's policy file round-trips byte-for-byte through the
//! existing `headscale policy set` CLI.
//!
//! The local stripper here matches `headscale-cli::admin::policy`'s
//! `strip_hujson` — same byte-level state machine, copied so this
//! crate doesn't take an admin-side dep. Tests verify the two stay in
//! sync.

use thiserror::Error;

use super::PolicyDoc;

#[derive(Debug, Error)]
pub enum PolicyParseError {
    /// The byte stream didn't even parse as JSON after stripping
    /// hujson decorations. The inner message carries the offset +
    /// expected-token diagnostic from `serde_json`.
    #[error("policy hujson did not parse as JSON: {0}")]
    Json(String),
    /// JSON-shape was valid but the document violated one of the
    /// schema constraints (`version`, unknown field, missing
    /// `action`, etc.).
    #[error("policy document failed schema validation: {0}")]
    Schema(String),
}

/// Strip hujson decorations + parse as a [`PolicyDoc`]. Tagged
/// `pub` so the admin `POST /api/v1/policy/validate` route can drive
/// it without going through `PolicyStore::set`.
pub fn parse_hujson_policy(raw: &str) -> Result<PolicyDoc, PolicyParseError> {
    let stripped = strip_hujson(raw);
    let value: serde_json::Value =
        serde_json::from_str(&stripped).map_err(|e| PolicyParseError::Json(e.to_string()))?;
    serde_json::from_value::<PolicyDoc>(value).map_err(|e| PolicyParseError::Schema(e.to_string()))
}

/// Strip `//` + `/* … */` comments and trailing commas. Preserves
/// every byte inside string literals (so a URL like `http://x/y//z`
/// survives intact). Copy of `headscale-cli`'s stripper — keep the
/// two in sync.
pub(crate) fn strip_hujson(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_str = false;
    let mut esc = false;
    while i < bytes.len() {
        let c = bytes[i];
        if in_str {
            out.push(c as char);
            if esc {
                esc = false;
            } else if c == b'\\' {
                esc = true;
            } else if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        if c == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
            continue;
        }
        if c == b',' {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b']' || bytes[j] == b'}') {
                i += 1;
                continue;
            }
        }
        out.push(c as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_doc() {
        let raw = r#"{
            // tiny allow-all
            "version": 1,
            "rules": [
                {"action":"accept","src":["*"],"dst":["*"],"ports":["*/*"]},
            ]
        }"#;
        let doc = parse_hujson_policy(raw).unwrap();
        assert_eq!(doc.version, 1);
        assert_eq!(doc.rules.len(), 1);
    }

    #[test]
    fn rejects_unknown_field() {
        let raw = r#"{"version":1,"policy_owner":"oct1","rules":[]}"#;
        let err = parse_hujson_policy(raw).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("policy_owner") || msg.contains("unknown field"),
            "error should name the field, got: {msg}"
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_hujson_policy("not json {").is_err());
    }

    #[test]
    fn block_comments_and_trailing_commas() {
        let raw = r#"{
            /* block comment */
            "version": 1,
            "rules": [
                {"action":"deny","src":["*"],"dst":["*"],},
            ],
        }"#;
        let doc = parse_hujson_policy(raw).unwrap();
        assert_eq!(doc.rules.len(), 1);
    }

    #[test]
    fn strings_with_slashes_are_preserved() {
        let raw = r#"{
            "version": 1,
            "groups": { "admins": ["oct://node1//net"] },
            "rules": []
        }"#;
        let doc = parse_hujson_policy(raw).unwrap();
        assert_eq!(doc.groups["admins"], vec!["oct://node1//net"]);
    }
}
