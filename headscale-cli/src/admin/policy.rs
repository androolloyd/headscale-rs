//! `headscale policy {get,set,check}`.
//!
//! `get` / `set` round-trip the policy document with the admin
//! surface. `check` runs locally — it parses + validates the file
//! without touching the server. The v0 admin endpoint (#216) is a stub
//! that returns `{loaded:false, policy:null}` and accepts any PUT
//! body; we still wire the CLI verbs so the operator-facing UX is in
//! place when #230 lands the real editor.

use std::path::Path;

use super::client::AdminClient;
use super::output::{print_json, OutputFormat};
use super::AdminError;

pub async fn get(client: &AdminClient, fmt: OutputFormat) -> Result<(), AdminError> {
    let value: serde_json::Value = client.get_json("/policy").await?;
    match fmt {
        OutputFormat::Json => print_json(&value)?,
        OutputFormat::Table => {
            let loaded = value
                .get("loaded")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            println!("Policy loaded: {loaded}");
            if let Some(p) = value.get("policy") {
                if !p.is_null() {
                    println!("---");
                    println!("{}", serde_json::to_string_pretty(p).unwrap_or_default());
                }
            }
        }
    }
    Ok(())
}

pub async fn set(
    client: &AdminClient,
    path: &Path,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let body = read_policy_file(path)?;
    // Local validation before sending — fail fast on garbage.
    check_policy_str(&body)?;
    let resp = client.put_text("/policy", body).await?;
    match fmt {
        OutputFormat::Json => print_json(&resp)?,
        OutputFormat::Table => {
            let applied = resp.get("applied").and_then(serde_json::Value::as_bool).unwrap_or(false);
            println!("Policy applied: {applied}");
            if let Some(note) = resp.get("note").and_then(serde_json::Value::as_str) {
                println!("Note: {note}");
            }
        }
    }
    Ok(())
}

/// Local-only validation. Reads the file, strips hujson `//` line
/// comments + trailing commas, then ensures the result parses as
/// `serde_json::Value`. The check is intentionally permissive — we
/// don't yet know the full policy schema (#230 lands that), so we
/// only catch byte-level / brace-level garbage.
pub fn check(path: &Path) -> Result<(), AdminError> {
    let raw = read_policy_file(path)?;
    check_policy_str(&raw)?;
    println!("Policy at {} parses OK.", path.display());
    Ok(())
}

fn read_policy_file(path: &Path) -> Result<String, AdminError> {
    std::fs::read_to_string(path).map_err(|e| {
        AdminError::Local(format!(
            "failed to read policy file '{}': {e}",
            path.display()
        ))
    })
}

/// Run the local-only parse. Exposed so the unit tests can exercise
/// the parser without a file on disk.
pub fn check_policy_str(raw: &str) -> Result<(), AdminError> {
    let stripped = strip_hujson(raw);
    serde_json::from_str::<serde_json::Value>(&stripped)
        .map(|_| ())
        .map_err(|e| AdminError::Local(format!("policy does not parse as (hu)json: {e}")))
}

/// Minimal hujson → JSON pre-processor. Strips `//` line comments,
/// `/* … */` block comments, and trailing commas before `]`/`}`. Good
/// enough for the local syntactic check; the server (or the real
/// editor in #230) owns the semantic validation.
fn strip_hujson(input: &str) -> String {
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
        // Line comment.
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            // Skip until newline.
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        // Block comment.
        if c == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'*' {
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            // Consume the closing `*/` (or EOF).
            i = (i + 2).min(bytes.len());
            continue;
        }
        if c == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
            continue;
        }
        // Trailing comma: `,` followed by whitespace then `]` or `}`.
        if c == b',' {
            let mut j = i + 1;
            while j < bytes.len() && (bytes[j] as char).is_whitespace() {
                j += 1;
            }
            if j < bytes.len() && (bytes[j] == b']' || bytes[j] == b'}') {
                // Drop this comma.
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
    fn strip_line_comment() {
        let s = strip_hujson("{\n  // hello\n  \"a\": 1\n}");
        assert!(!s.contains("hello"));
        assert!(s.contains("\"a\""));
    }

    #[test]
    fn strip_block_comment() {
        let s = strip_hujson("{/* x */\"a\":1}");
        assert!(serde_json::from_str::<serde_json::Value>(&s).is_ok());
    }

    #[test]
    fn strip_trailing_comma_in_array() {
        let s = strip_hujson("[1,2,3,]");
        assert!(serde_json::from_str::<serde_json::Value>(&s).is_ok());
    }

    #[test]
    fn strip_trailing_comma_in_object() {
        let s = strip_hujson("{\"a\":1,}");
        assert!(serde_json::from_str::<serde_json::Value>(&s).is_ok());
    }

    #[test]
    fn preserves_strings_containing_slashes() {
        // The slashes inside the URL string are not the start of a
        // comment — the stripper must not chop them.
        let s = strip_hujson("{\"url\":\"http://x/y//z\"}");
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["url"], "http://x/y//z");
    }

    #[test]
    fn check_policy_str_accepts_valid() {
        assert!(check_policy_str("{\"acls\":[]}").is_ok());
    }

    #[test]
    fn check_policy_str_rejects_garbage() {
        assert!(check_policy_str("not json {").is_err());
    }
}
