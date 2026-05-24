//! `headscale policy {get,set,check}`.
//!
//! The upstream-compatible path uses the gRPC `GetPolicy`, `SetPolicy`,
//! and `CheckPolicy` RPCs by default. Supplying explicit `--server` keeps
//! the legacy admin HTTP behavior, where `check` remains local-only.

use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use chrono::{DateTime, SecondsFormat, Utc};
use headscale_api::admin::{MachineAdmin, PersistentMachineAdmin, PersistentUserAdmin};
use headscale_api::generated::{GetPolicyResponse, SetPolicyResponse};
use headscale_api::policy::{PolicyCheckNode, check_policy_semantics, parse_hujson_policy};
use headscale_api::tailscale_wire::wire::stable_id_from_key;
use headscale_db::Database;
use serde::Serialize;

use super::AdminError;
use super::client::AdminClient;
use super::grpc_client::GrpcAdminClient;
use super::output::{OutputFormat, print_structured};

pub async fn get(client: &AdminClient, fmt: OutputFormat) -> Result<(), AdminError> {
    let value: serde_json::Value = client.get_json("/policy").await?;
    if fmt.is_structured() {
        print_structured(fmt, &value)?;
    } else {
        let loaded = value
            .get("loaded")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        println!("Policy loaded: {loaded}");
        if let Some(p) = value.get("policy")
            && !p.is_null()
        {
            println!("---");
            println!("{}", serde_json::to_string_pretty(p).unwrap_or_default());
        }
    }
    Ok(())
}

pub async fn get_grpc(client: &mut GrpcAdminClient, fmt: OutputFormat) -> Result<(), AdminError> {
    let response = PolicyOutput::from(client.get_policy().await?);
    if fmt.is_structured() {
        print_structured(fmt, &response)?;
    } else {
        print!("{}", response.policy);
        if !response.policy.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

pub async fn get_direct_db(db_path: &Path, fmt: OutputFormat) -> Result<(), AdminError> {
    let db = open_policy_database(db_path).await?;
    let policy = headscale_db::policies::get_latest(db.pool())
        .await
        .map_err(|e| AdminError::Local(format!("loading ACL from database: {e}")))?
        .ok_or_else(|| {
            AdminError::Local("loading ACL from database: acl policy not found".into())
        })?;
    let response = PolicyOutput {
        policy: policy.data,
        updated_at: Some(unix_timestamp_rfc3339(policy.updated_at)),
    };
    if fmt.is_structured() {
        print_structured(fmt, &response)?;
    } else {
        print!("{}", response.policy);
        if !response.policy.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

pub async fn set(client: &AdminClient, path: &Path, fmt: OutputFormat) -> Result<(), AdminError> {
    let body = read_policy_file(path)?;
    // Local validation before sending — fail fast on garbage.
    check_policy_str(&body)?;
    let resp = client.put_text("/policy", body).await?;
    if fmt.is_structured() {
        print_structured(fmt, &resp)?;
    } else {
        let applied = resp
            .get("applied")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        println!("Policy applied: {applied}");
        if let Some(note) = resp.get("note").and_then(serde_json::Value::as_str) {
            println!("Note: {note}");
        }
    }
    Ok(())
}

pub async fn set_grpc(
    client: &mut GrpcAdminClient,
    path: &Path,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let body = read_policy_file(path)?;
    let response = PolicySetOutput::from(client.set_policy(body).await?);
    if fmt.is_structured() {
        print_structured(fmt, &response)?;
    } else {
        println!("Policy applied: true");
    }
    Ok(())
}

pub async fn set_direct_db(
    db_path: &Path,
    path: &Path,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let body = read_policy_file(path)?;
    let db = open_policy_database(db_path).await?;
    validate_policy_with_database(db.pool(), &body, "setting policy").await?;
    let policy = headscale_db::policies::set(db.pool(), &body)
        .await
        .map_err(|e| AdminError::Local(format!("persisting policy to database: {e}")))?;
    let response = PolicySetOutput {
        applied: true,
        policy: policy.data,
        updated_at: Some(unix_timestamp_rfc3339(policy.updated_at)),
    };
    if fmt.is_structured() {
        print_structured(fmt, &response)?;
    } else {
        println!("Policy applied: true");
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

pub async fn check_grpc(client: &mut GrpcAdminClient, path: &Path) -> Result<(), AdminError> {
    let raw = read_policy_file(path)?;
    client.check_policy(raw).await?;
    println!("Policy at {} validates OK.", path.display());
    Ok(())
}

pub async fn check_direct_db(db_path: &Path, path: &Path) -> Result<(), AdminError> {
    let raw = read_policy_file(path)?;
    let db = open_policy_database(db_path).await?;
    validate_policy_with_database(db.pool(), &raw, "checking policy").await?;
    println!("Policy at {} validates OK.", path.display());
    Ok(())
}

pub fn confirm_direct_database_access(force: bool) -> Result<(), AdminError> {
    if force {
        return Ok(());
    }

    eprint!(
        "Bypassing gRPC accesses the headscale database directly and does not notify a running server. Continue? [y/n] "
    );
    std::io::stderr()
        .flush()
        .map_err(|e| AdminError::Local(format!("write confirmation prompt: {e}")))?;
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| AdminError::Local(format!("read confirmation response: {e}")))?;
    if matches!(answer.trim(), "y" | "Y" | "yes" | "YES" | "Yes") {
        Ok(())
    } else {
        Err(AdminError::Local(
            "direct database policy access aborted".into(),
        ))
    }
}

fn read_policy_file(path: &Path) -> Result<String, AdminError> {
    std::fs::read_to_string(path).map_err(|e| {
        AdminError::Local(format!(
            "failed to read policy file '{}': {e}",
            path.display()
        ))
    })
}

async fn validate_policy_with_database(
    pool: &sqlx::SqlitePool,
    raw: &str,
    context: &str,
) -> Result<(), AdminError> {
    let doc = parse_hujson_policy(raw).map_err(|e| AdminError::Local(format!("{context}: {e}")))?;
    let nodes = policy_check_nodes(pool).await;
    check_policy_semantics(&doc, &nodes)
        .map_err(|e| AdminError::Local(format!("{context}: {e}")))?;
    Ok(())
}

async fn policy_check_nodes(pool: &sqlx::SqlitePool) -> Vec<PolicyCheckNode> {
    let users = Arc::new(PersistentUserAdmin::new(pool.clone()));
    let machines = PersistentMachineAdmin::new(pool.clone()).with_user_admin(users);
    machines
        .list()
        .await
        .iter()
        .map(policy_check_node_from_machine)
        .collect()
}

fn policy_check_node_from_machine(
    machine: &headscale_api::admin::MachineAdminRecord,
) -> PolicyCheckNode {
    PolicyCheckNode {
        id: machine_numeric_id(machine),
        name: machine.name.clone(),
        user: (!machine.user.is_empty()).then(|| machine.user.clone()),
        addrs: node_ip_addresses(machine),
        tags: machine.tags.clone(),
    }
}

fn machine_numeric_id(machine: &headscale_api::admin::MachineAdminRecord) -> u64 {
    if machine.node_id == 0 {
        stable_id_from_key(&machine.id)
    } else {
        machine.node_id
    }
}

fn node_ip_addresses(machine: &headscale_api::admin::MachineAdminRecord) -> Vec<String> {
    let mut addresses = Vec::with_capacity(1 + usize::from(machine.ipv6.is_some()));
    if !machine.ipv4.is_empty() {
        addresses.push(machine.ipv4.clone());
    }
    if let Some(ipv6) = machine.ipv6.as_ref().filter(|ipv6| !ipv6.is_empty()) {
        addresses.push(ipv6.clone());
    }
    addresses
}

async fn open_policy_database(path: &Path) -> Result<Database, AdminError> {
    ensure_parent_dir(path)?;
    let url = sqlite_url_for_path(path);
    let db = Database::new(&url).await.map_err(|e| {
        AdminError::Local(format!("open SQLite database at {}: {e}", path.display()))
    })?;
    db.migrate().await.map_err(|e| {
        AdminError::Local(format!(
            "migrate SQLite database at {}: {e}",
            path.display()
        ))
    })?;
    Ok(db)
}

fn sqlite_url_for_path(path: &Path) -> String {
    format!("sqlite://{}?mode=rwc", path.display())
}

fn ensure_parent_dir(path: &Path) -> Result<(), AdminError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        std::fs::create_dir_all(parent).map_err(|e| {
            AdminError::Local(format!(
                "failed to create database directory {}: {e}",
                parent.display()
            ))
        })?;
    }
    Ok(())
}

fn timestamp_rfc3339(ts: Option<&prost_types::Timestamp>) -> Option<String> {
    let ts = ts?;
    let nanos = u32::try_from(ts.nanos).ok()?;
    DateTime::<Utc>::from_timestamp(ts.seconds, nanos)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn unix_timestamp_rfc3339(seconds: i64) -> String {
    DateTime::<Utc>::from_timestamp(seconds, 0).map_or_else(
        || "1970-01-01T00:00:00Z".to_string(),
        |time| time.to_rfc3339_opts(SecondsFormat::Secs, true),
    )
}

#[derive(Debug, Serialize)]
struct PolicyOutput {
    policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
}

impl From<GetPolicyResponse> for PolicyOutput {
    fn from(response: GetPolicyResponse) -> Self {
        Self {
            policy: response.policy,
            updated_at: timestamp_rfc3339(response.updated_at.as_ref()),
        }
    }
}

#[derive(Debug, Serialize)]
struct PolicySetOutput {
    applied: bool,
    policy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
}

impl From<SetPolicyResponse> for PolicySetOutput {
    fn from(response: SetPolicyResponse) -> Self {
        Self {
            applied: true,
            policy: response.policy,
            updated_at: timestamp_rfc3339(response.updated_at.as_ref()),
        }
    }
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

    #[test]
    fn policy_output_formats_timestamp_as_rfc3339() {
        let output = PolicyOutput::from(GetPolicyResponse {
            policy: "{\"acls\":[]}".into(),
            updated_at: Some(prost_types::Timestamp {
                seconds: 1_704_067_200,
                nanos: 0,
            }),
        });
        assert_eq!(output.updated_at.as_deref(), Some("2024-01-01T00:00:00Z"));
    }
}
