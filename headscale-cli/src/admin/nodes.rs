//! `headscale nodes {list,show,expire,delete}` — wraps the
//! `/api/v1/machines` admin surface. (Upstream `headscale` historically
//! called these "machines"; the v1 GUI exposes them under that name,
//! but the CLI verb is `nodes` to match upstream's modern naming.)

use headscale_api::admin::MachineAdminRecord;

use super::AdminError;
use super::client::AdminClient;
use super::output::{OutputFormat, print_json, print_table};

pub async fn list(
    client: &AdminClient,
    user_filter: Option<&str>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let mut nodes: Vec<MachineAdminRecord> = client.get_json("/machines").await?;
    if let Some(u) = user_filter {
        nodes.retain(|n| n.user == u);
    }
    match fmt {
        OutputFormat::Json => print_json(&nodes)?,
        OutputFormat::Table => render_nodes(&nodes),
    }
    Ok(())
}

pub async fn show(
    client: &AdminClient,
    id_or_name: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    // Admin's `GET /machines/:id` routes on `id` (the node_key hex).
    // If the operator typed a hostname instead, fall back to listing +
    // filtering — same UX as upstream `headscale nodes show`.
    let path = format!("/machines/{id_or_name}");
    let node = match client.get_json::<MachineAdminRecord>(&path).await {
        Ok(n) => n,
        Err(AdminError::NotFound(_)) => {
            // Try name match.
            let all: Vec<MachineAdminRecord> = client.get_json("/machines").await?;
            all.into_iter()
                .find(|n| n.name == id_or_name)
                .ok_or_else(|| AdminError::NotFound(format!("no node matching '{id_or_name}'")))?
        }
        Err(e) => return Err(e),
    };
    match fmt {
        OutputFormat::Json => print_json(&node)?,
        OutputFormat::Table => render_one(&node),
    }
    Ok(())
}

pub async fn expire(client: &AdminClient, id: &str, at: Option<&str>) -> Result<(), AdminError> {
    let path = format!("/machines/{id}/expire");
    // Body is `{}` for immediate expiry, `{"expiry": "<rfc3339>"}` for
    // a scheduled one. The admin route accepts an empty body too —
    // we always send `{}` so the wire is consistent across CLI runs.
    let body = match at {
        Some(t) => serde_json::json!({ "expiry": t }),
        None => serde_json::json!({}),
    };
    let _: serde_json::Value = post_json_no_content(client, &path, &body).await?;
    match at {
        Some(t) => println!("Scheduled expiry on node '{id}' at {t}"),
        None => println!("Expired node '{id}'"),
    }
    Ok(())
}

pub async fn logout(client: &AdminClient, id: &str) -> Result<(), AdminError> {
    let path = format!("/machines/{id}/logout");
    client.post_no_content(&path).await?;
    println!("Forced logout on node '{id}'");
    Ok(())
}

pub async fn rename(client: &AdminClient, id: &str, hostname: &str) -> Result<(), AdminError> {
    let path = format!("/machines/{id}/rename");
    let body = serde_json::json!({ "hostname": hostname });
    post_json_no_content(client, &path, &body).await?;
    println!("Renamed node '{id}' to '{hostname}'");
    Ok(())
}

pub async fn tags(client: &AdminClient, id: &str, tags: Vec<String>) -> Result<(), AdminError> {
    let path = format!("/machines/{id}/tags");
    let body = serde_json::json!({ "tags": tags });
    post_json_no_content(client, &path, &body).await?;
    if tags.is_empty() {
        println!("Cleared forced tags on node '{id}'");
    } else {
        println!("Set forced tags on node '{id}': {}", tags.join(", "));
    }
    Ok(())
}

pub async fn delete(client: &AdminClient, id: &str) -> Result<(), AdminError> {
    let path = format!("/machines/{id}");
    client.delete_no_content(&path).await?;
    println!("Deleted node '{id}'");
    Ok(())
}

/// Tiny helper: POST a JSON body and discard the (possibly empty)
/// response. The admin route returns `204 No Content` on success; on
/// `400`/`404` we want the error body surfaced through the standard
/// `AdminError` mapping. Adding a fully-typed `post_json` overload to
/// [`AdminClient`] would force callers to specify a phantom response
/// type even when there isn't one — this shim sidesteps that.
async fn post_json_no_content(
    client: &AdminClient,
    path: &str,
    body: &serde_json::Value,
) -> Result<serde_json::Value, AdminError> {
    // Reuse the existing `post_json` path; the admin server's
    // `204 No Content` arms still set Content-Length: 0 so reqwest's
    // `json::<Value>()` call would fail. We tolerate that by treating
    // an empty body as `Null`.
    match client
        .post_json::<serde_json::Value, serde_json::Value>(path, body)
        .await
    {
        Ok(v) => Ok(v),
        // `Decode` is reqwest's "couldn't json-parse the empty body"
        // failure — equivalent to a 204 success.
        Err(AdminError::Decode(_)) => Ok(serde_json::Value::Null),
        Err(e) => Err(e),
    }
}

fn render_nodes(nodes: &[MachineAdminRecord]) {
    if nodes.is_empty() {
        println!("No nodes registered.");
        return;
    }
    let rows: Vec<Vec<String>> = nodes
        .iter()
        .map(|n| {
            vec![
                short_id(&n.id),
                n.name.clone(),
                n.user.clone(),
                n.ipv4.clone(),
                if n.online {
                    "online".into()
                } else {
                    "offline".into()
                },
            ]
        })
        .collect();
    print_table(&["ID", "NAME", "USER", "IPV4", "STATUS"], &rows);
}

fn render_one(n: &MachineAdminRecord) {
    println!("Node:");
    println!("  ID:        {}", n.id);
    println!("  Name:      {}", n.name);
    println!("  User:      {}", n.user);
    println!("  IPv4:      {}", n.ipv4);
    println!("  Online:    {}", n.online);
    println!("  Expired:   {}", n.expired);
    println!("  Last seen: {}", n.last_seen);
    println!("  OS:        {}", n.os);
    println!("  Version:   {}", n.version);
    if !n.tags.is_empty() {
        println!("  Tags:      {}", n.tags.join(", "));
    }
    if !n.routes.is_empty() {
        println!("  Routes:    {}", n.routes.join(", "));
    }
}

/// Truncate the node_key-hex ID to its first 12 chars for the table
/// view — full ID is 64 chars and dominates the row otherwise. The
/// `show` view keeps the full string.
fn short_id(id: &str) -> String {
    if id.len() > 12 {
        format!("{}…", &id[..12])
    } else {
        id.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_truncates() {
        let s = "a".repeat(64);
        let out = short_id(&s);
        assert_eq!(out.chars().count(), 13); // 12 + ellipsis
        assert!(out.ends_with('…'));
    }

    #[test]
    fn short_id_leaves_short_strings_alone() {
        assert_eq!(short_id("abc"), "abc");
    }
}
