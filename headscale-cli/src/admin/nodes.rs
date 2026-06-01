//! `headscale nodes` over upstream-compatible gRPC.
//!
//! Supplying `--server` keeps the legacy `/api/v1/machines` transport
//! available for older admin HTTP deployments. Upstream historically called
//! these "machines"; the v1 GUI exposes them under that name, but the CLI verb
//! is `nodes` to match upstream's modern naming.

use std::collections::BTreeMap;
use std::io::{self, Write};

use chrono::{DateTime, SecondsFormat, Utc};
use headscale_api::admin::MachineAdminRecord;
use headscale_api::generated::{
    BackfillNodeIPsResponse, Node as GrpcNode, PreAuthKey as GrpcPreAuthKey, User as GrpcUser,
};
use headscale_api::tailscale_wire::routes::{active_exit_routes, primary_routes_by_node};
use headscale_api::tailscale_wire::wire::stable_id_from_key;
use serde::Serialize;

use super::AdminError;
use super::client::AdminClient;
use super::grpc_client::GrpcAdminClient;
use super::output::{OutputFormat, print_structured, print_table};

pub async fn list(
    client: &AdminClient,
    user_filter: Option<&str>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let mut nodes: Vec<MachineAdminRecord> = client.get_json("/machines").await?;
    if let Some(u) = user_filter {
        nodes.retain(|n| n.user == u);
    }
    if fmt.is_structured() {
        print_structured(fmt, &nodes)?;
    } else {
        render_nodes(&nodes);
    }
    Ok(())
}

pub async fn list_routes(
    client: &AdminClient,
    id: Option<&str>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let mut nodes = if let Some(id) = id {
        vec![
            client
                .get_json::<MachineAdminRecord>(&format!("/machines/{id}"))
                .await?,
        ]
    } else {
        client
            .get_json::<Vec<MachineAdminRecord>>("/machines")
            .await?
    };
    nodes.retain(|n| !n.routes.is_empty() || !n.approved_routes.is_empty());
    if fmt.is_structured() {
        print_structured(fmt, &nodes)?;
    } else {
        render_routes(&nodes);
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
    if fmt.is_structured() {
        print_structured(fmt, &node)?;
    } else {
        render_one(&node);
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

pub async fn approve_routes(
    client: &AdminClient,
    id: &str,
    routes: Vec<String>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let path = format!("/machines/{id}/routes");
    let body = serde_json::json!({ "routes": routes });
    let node: MachineAdminRecord = client.post_json(&path, &body).await?;
    if fmt.is_structured() {
        print_structured(fmt, &node)?;
    } else {
        println!("Node updated");
        render_routes(&[node]);
    }
    Ok(())
}

pub async fn delete(client: &AdminClient, id: &str) -> Result<(), AdminError> {
    let path = format!("/machines/{id}");
    client.delete_no_content(&path).await?;
    println!("Deleted node '{id}'");
    Ok(())
}

pub fn select_node_id<'a>(
    positional: Option<&'a str>,
    identifier: Option<&'a str>,
) -> Result<&'a str, AdminError> {
    match (positional, identifier) {
        (Some(_), Some(_)) => Err(AdminError::Local(
            "use either positional node ID or --identifier, not both".into(),
        )),
        (Some(id), None) | (None, Some(id)) if !id.trim().is_empty() => Ok(id),
        _ => Err(AdminError::Local(
            "node identifier is required; use --identifier".into(),
        )),
    }
}

pub fn select_rename_args<'a>(
    new_name: &'a str,
    identifier: Option<&'a str>,
) -> Result<(&'a str, &'a str), AdminError> {
    match identifier {
        Some(identifier) if !identifier.trim().is_empty() => Ok((identifier, new_name)),
        _ => Err(AdminError::Local(
            "rename requires --identifier ID NEW_NAME".into(),
        )),
    }
}

pub fn merged_tags(flags: &[String], positional: &[String]) -> Vec<String> {
    flags
        .iter()
        .chain(positional.iter())
        .filter(|tag| !tag.is_empty())
        .cloned()
        .collect()
}

pub async fn list_grpc(
    client: &mut GrpcAdminClient,
    user_filter: Option<&str>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let nodes: Vec<NodeOutput> = client
        .list_nodes(user_filter)
        .await?
        .into_iter()
        .map(NodeOutput::from)
        .collect();
    if fmt.is_structured() {
        print_structured(fmt, &nodes)?;
    } else {
        render_grpc_nodes(&nodes);
    }
    Ok(())
}

pub async fn list_routes_grpc(
    client: &mut GrpcAdminClient,
    id: Option<&str>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let requested_id = id.map(parse_node_id).transpose()?;
    let mut nodes: Vec<NodeOutput> = client
        .list_nodes(None)
        .await?
        .into_iter()
        .map(NodeOutput::from)
        .collect();
    nodes = route_nodes_for_display(nodes, requested_id);
    if fmt.is_structured() {
        print_structured(fmt, &nodes)?;
    } else {
        render_grpc_routes(&nodes);
    }
    Ok(())
}

pub async fn show_grpc(
    client: &mut GrpcAdminClient,
    id: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let node = NodeOutput::from(client.get_node(parse_node_id(id)?).await?);
    if fmt.is_structured() {
        print_structured(fmt, &node)?;
    } else {
        render_grpc_one(&node);
    }
    Ok(())
}

pub async fn register_grpc(
    client: &mut GrpcAdminClient,
    user: &str,
    key: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let node = NodeOutput::from(client.register_node(user, key).await?);
    if fmt.is_structured() {
        print_structured(fmt, &node)?;
    } else {
        let display_name = if node.given_name.is_empty() {
            &node.name
        } else {
            &node.given_name
        };
        println!("Node {display_name} registered");
    }
    Ok(())
}

pub async fn debug_create_node_grpc(
    client: &mut GrpcAdminClient,
    user: &str,
    key: &str,
    name: &str,
    routes: Vec<String>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let node = NodeOutput::from(client.debug_create_node(user, key, name, routes).await?);
    if fmt.is_structured() {
        print_structured(fmt, &node)?;
    } else {
        println!("Node created");
    }
    Ok(())
}

pub async fn expire_grpc(
    client: &mut GrpcAdminClient,
    id: &str,
    at: Option<&str>,
    disable_expiry: bool,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let node_id = parse_node_id(id)?;
    if disable_expiry {
        let node = NodeOutput::from(client.expire_node(node_id, None, true).await?);
        if fmt.is_structured() {
            print_structured(fmt, &node)?;
        } else {
            println!("Node expiry disabled");
        }
        return Ok(());
    }

    let now = current_unix_i64();
    let expiry = match at {
        Some(at) => parse_rfc3339_unix(at)?,
        None => now,
    };
    let node = NodeOutput::from(client.expire_node(node_id, Some(expiry), false).await?);
    if fmt.is_structured() {
        print_structured(fmt, &node)?;
    } else if expiry > now {
        println!("Node expiration updated");
    } else {
        println!("Node expired");
    }
    Ok(())
}

pub async fn logout_grpc(
    client: &mut GrpcAdminClient,
    id: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let node_id = parse_node_id(id)?;
    let node = NodeOutput::from(
        client
            .expire_node(node_id, Some(current_unix_i64()), false)
            .await?,
    );
    if fmt.is_structured() {
        print_structured(fmt, &node)?;
    } else {
        println!("Node expired");
    }
    Ok(())
}

pub async fn rename_grpc(
    client: &mut GrpcAdminClient,
    id: &str,
    hostname: &str,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let node_id = parse_node_id(id)?;
    let node = NodeOutput::from(client.rename_node(node_id, hostname).await?);
    if fmt.is_structured() {
        print_structured(fmt, &node)?;
    } else {
        println!("Node renamed");
    }
    Ok(())
}

pub async fn tags_grpc(
    client: &mut GrpcAdminClient,
    id: &str,
    tags: Vec<String>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let node_id = parse_node_id(id)?;
    let node = NodeOutput::from(client.set_tags(node_id, tags).await?);
    if fmt.is_structured() {
        print_structured(fmt, &node)?;
    } else {
        println!("Node updated");
    }
    Ok(())
}

pub async fn approve_routes_grpc(
    client: &mut GrpcAdminClient,
    id: &str,
    routes: Vec<String>,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let node_id = parse_node_id(id)?;
    let node = NodeOutput::from(client.set_approved_routes(node_id, routes).await?);
    if fmt.is_structured() {
        print_structured(fmt, &node)?;
    } else {
        println!("Node updated");
    }
    Ok(())
}

pub async fn delete_grpc(
    client: &mut GrpcAdminClient,
    id: &str,
    force: bool,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    let node_id = parse_node_id(id)?;
    let node = NodeOutput::from(client.get_node(node_id).await?);
    if !force && !confirm_action(&format!("Do you want to remove the node {}?", node.name))? {
        print_result(fmt, "Node not deleted")?;
        return Ok(());
    }

    client.delete_node(node_id).await?;
    print_result(fmt, "Node deleted")?;
    Ok(())
}

pub async fn backfillips_grpc(
    client: &mut GrpcAdminClient,
    confirmed: bool,
    force: bool,
    fmt: OutputFormat,
) -> Result<(), AdminError> {
    if !force
        && !confirmed
        && !confirm_action("Are you sure that you want to assign/remove IPs to/from nodes?")?
    {
        return Ok(());
    }

    let response = client.backfill_node_ips(true).await?;
    if fmt.is_structured() {
        let output = BackfillOutput {
            changes: response.changes,
        };
        print_structured(fmt, &output)?;
    } else {
        println!("Node IPs backfilled successfully");
    }
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
    if !n.approved_routes.is_empty() {
        println!("  Approved:  {}", n.approved_routes.join(", "));
    }
}

fn render_routes(nodes: &[MachineAdminRecord]) {
    if nodes.is_empty() {
        println!("No routes advertised or approved.");
        return;
    }
    let serving = serving_routes(nodes);
    let rows: Vec<Vec<String>> = nodes
        .iter()
        .map(|n| {
            vec![
                short_id(&n.id),
                n.name.clone(),
                n.approved_routes.join("\n"),
                n.routes.join("\n"),
                serving.get(&n.id).cloned().unwrap_or_default().join("\n"),
            ]
        })
        .collect();
    print_table(
        &[
            "ID",
            "HOSTNAME",
            "APPROVED",
            "AVAILABLE",
            "SERVING (PRIMARY)",
        ],
        &rows,
    );
}

fn serving_routes(nodes: &[MachineAdminRecord]) -> BTreeMap<String, Vec<String>> {
    let primary = primary_routes_by_node(nodes.iter().map(|n| {
        (
            n.id.as_str(),
            route_node_id(n),
            n.routes.as_slice(),
            n.approved_routes.as_slice(),
        )
    }));
    nodes
        .iter()
        .filter_map(|n| {
            let mut routes = primary.get(&n.id).cloned().unwrap_or_default();
            routes.extend(active_exit_routes(&n.routes, &n.approved_routes));
            routes.sort();
            routes.dedup();
            (!routes.is_empty()).then(|| (n.id.clone(), routes))
        })
        .collect()
}

fn route_node_id(n: &MachineAdminRecord) -> u64 {
    if n.node_id == 0 {
        stable_id_from_key(&n.id)
    } else {
        n.node_id
    }
}

fn render_grpc_nodes(nodes: &[NodeOutput]) {
    if nodes.is_empty() {
        println!("No nodes registered.");
        return;
    }
    let rows: Vec<Vec<String>> = nodes
        .iter()
        .map(|n| {
            vec![
                n.id.to_string(),
                n.name.clone(),
                n.given_name.clone(),
                short_key(&n.machine_key),
                short_key(&n.node_key),
                n.user_name.clone(),
                n.tags.join("\n"),
                n.ip_addresses.join("\n"),
                n.ephemeral().to_string(),
                n.last_seen_display.clone().unwrap_or_default(),
                n.expiry_display.clone().unwrap_or_else(|| "N/A".into()),
                if n.online {
                    "online".into()
                } else {
                    "offline".into()
                },
                if n.expired() {
                    "yes".into()
                } else {
                    "no".into()
                },
            ]
        })
        .collect();
    print_table(
        &[
            "ID",
            "HOSTNAME",
            "NAME",
            "MACHINEKEY",
            "NODEKEY",
            "USER",
            "TAGS",
            "IP ADDRESSES",
            "EPHEMERAL",
            "LAST SEEN",
            "EXPIRATION",
            "CONNECTED",
            "EXPIRED",
        ],
        &rows,
    );
}

fn render_grpc_one(n: &NodeOutput) {
    println!("Node:");
    println!("  ID:           {}", n.id);
    println!("  Name:         {}", n.name);
    if !n.given_name.is_empty() && n.given_name != n.name {
        println!("  Given name:   {}", n.given_name);
    }
    println!("  User:         {}", n.user_name);
    println!("  IP addresses: {}", n.ip_addresses.join(", "));
    println!("  Online:       {}", n.online);
    println!("  Expired:      {}", n.expired());
    println!("  Ephemeral:    {}", n.ephemeral());
    println!(
        "  Last seen:    {}",
        n.last_seen_display.as_deref().unwrap_or("-")
    );
    println!(
        "  Created:      {}",
        n.created_at_display.as_deref().unwrap_or("-")
    );
    println!(
        "  Expiry:       {}",
        n.expiry_display.as_deref().unwrap_or("-")
    );
    if !n.machine_key.is_empty() {
        println!("  Machine key:  {}", n.machine_key);
    }
    if !n.node_key.is_empty() {
        println!("  Node key:     {}", n.node_key);
    }
    if !n.tags.is_empty() {
        println!("  Tags:         {}", n.tags.join(", "));
    }
    if !n.available_routes.is_empty() {
        println!("  Available:    {}", n.available_routes.join(", "));
    }
    if !n.approved_routes.is_empty() {
        println!("  Approved:     {}", n.approved_routes.join(", "));
    }
}

fn render_grpc_routes(nodes: &[NodeOutput]) {
    if nodes.is_empty() {
        println!("No routes advertised or approved.");
        return;
    }
    let rows = grpc_route_rows(nodes);
    print_table(
        &[
            "ID",
            "HOSTNAME",
            "APPROVED",
            "AVAILABLE",
            "SERVING (PRIMARY)",
        ],
        &rows,
    );
}

fn grpc_route_rows(nodes: &[NodeOutput]) -> Vec<Vec<String>> {
    nodes
        .iter()
        .map(|n| {
            vec![
                n.id.to_string(),
                n.given_name.clone(),
                n.approved_routes.join("\n"),
                n.available_routes.join("\n"),
                n.subnet_routes.join("\n"),
            ]
        })
        .collect()
}

fn parse_node_id(id: &str) -> Result<u64, AdminError> {
    id.parse::<u64>().map_err(|_| {
        AdminError::Local(format!(
            "upstream gRPC node commands require a numeric node identifier, got '{id}'"
        ))
    })
}

fn parse_rfc3339_unix(value: &str) -> Result<i64, AdminError> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.timestamp())
        .map_err(|e| AdminError::Local(format!("invalid RFC3339 timestamp '{value}': {e}")))
}

fn timestamp_rfc3339(ts: Option<&prost_types::Timestamp>) -> Option<String> {
    let ts = ts?;
    let nanos = u32::try_from(ts.nanos).ok()?;
    DateTime::<Utc>::from_timestamp(ts.seconds, nanos)
        .map(|time| time.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn current_unix_i64() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    i64::try_from(now).unwrap_or(i64::MAX)
}

fn confirm_action(prompt: &str) -> Result<bool, AdminError> {
    eprint!("{prompt} [y/n] ");
    io::stderr()
        .flush()
        .map_err(|e| AdminError::Local(format!("write confirmation prompt: {e}")))?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|e| AdminError::Local(format!("read confirmation response: {e}")))?;
    Ok(matches!(
        response.trim().to_ascii_lowercase().as_str(),
        "y" | "yes" | "sure"
    ))
}

fn print_result(fmt: OutputFormat, message: &str) -> Result<(), AdminError> {
    #[derive(Serialize)]
    struct ResultOutput<'a> {
        #[serde(rename = "Result")]
        result: &'a str,
    }

    if fmt.is_structured() {
        print_structured(fmt, &ResultOutput { result: message })
    } else {
        println!("{message}");
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct NodeOutput {
    id: u64,
    machine_key: String,
    node_key: String,
    disco_key: String,
    ip_addresses: Vec<String>,
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<NodeUserOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen: Option<TimestampOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiry: Option<TimestampOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_auth_key: Option<NodePreAuthKeyOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<TimestampOutput>,
    register_method: i32,
    pub(crate) given_name: String,
    online: bool,
    approved_routes: Vec<String>,
    available_routes: Vec<String>,
    subnet_routes: Vec<String>,
    tags: Vec<String>,
    #[serde(skip)]
    user_name: String,
    #[serde(skip)]
    last_seen_display: Option<String>,
    #[serde(skip)]
    expiry_display: Option<String>,
    #[serde(skip)]
    created_at_display: Option<String>,
}

impl NodeOutput {
    fn ephemeral(&self) -> bool {
        self.pre_auth_key.as_ref().is_some_and(|key| key.ephemeral)
    }

    fn expired(&self) -> bool {
        self.expiry
            .as_ref()
            .is_some_and(|ts| ts.seconds <= current_unix_i64())
    }
}

#[derive(Clone, Debug, Serialize)]
struct NodeUserOutput {
    id: u64,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<TimestampOutput>,
    display_name: String,
    email: String,
    provider_id: String,
    provider: String,
    profile_pic_url: String,
}

#[derive(Clone, Debug, Serialize)]
struct NodePreAuthKeyOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    user: Option<NodeUserOutput>,
    id: u64,
    key: String,
    reusable: bool,
    ephemeral: bool,
    used: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiration: Option<TimestampOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<TimestampOutput>,
    acl_tags: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct TimestampOutput {
    #[serde(skip_serializing_if = "is_zero_i64")]
    seconds: i64,
    #[serde(skip_serializing_if = "is_zero_i32")]
    nanos: i32,
}

impl From<GrpcNode> for NodeOutput {
    fn from(node: GrpcNode) -> Self {
        let GrpcNode {
            id,
            machine_key,
            node_key,
            disco_key,
            ip_addresses,
            name,
            user,
            last_seen,
            expiry,
            pre_auth_key,
            created_at,
            register_method,
            given_name,
            online,
            approved_routes,
            available_routes,
            subnet_routes,
            tags,
        } = node;
        let user = user.map(NodeUserOutput::from);
        let user_name = user
            .as_ref()
            .map_or_else(String::new, |user| user.name.clone());
        let last_seen_display = timestamp_rfc3339(last_seen.as_ref());
        let expiry_display = timestamp_rfc3339(expiry.as_ref());
        let created_at_display = timestamp_rfc3339(created_at.as_ref());
        Self {
            id,
            machine_key,
            node_key,
            disco_key,
            ip_addresses,
            name,
            user,
            last_seen: last_seen.map(TimestampOutput::from),
            expiry: expiry.map(TimestampOutput::from),
            pre_auth_key: pre_auth_key.map(NodePreAuthKeyOutput::from),
            created_at: created_at.map(TimestampOutput::from),
            register_method,
            given_name,
            online,
            approved_routes,
            available_routes,
            subnet_routes,
            tags,
            user_name,
            last_seen_display,
            expiry_display,
            created_at_display,
        }
    }
}

impl From<GrpcUser> for NodeUserOutput {
    fn from(user: GrpcUser) -> Self {
        Self {
            id: user.id,
            name: user.name,
            created_at: user.created_at.map(TimestampOutput::from),
            display_name: user.display_name,
            email: user.email,
            provider_id: user.provider_id,
            provider: user.provider,
            profile_pic_url: user.profile_pic_url,
        }
    }
}

impl From<GrpcPreAuthKey> for NodePreAuthKeyOutput {
    fn from(key: GrpcPreAuthKey) -> Self {
        Self {
            user: key.user.map(NodeUserOutput::from),
            id: key.id,
            key: key.key,
            reusable: key.reusable,
            ephemeral: key.ephemeral,
            used: key.used,
            expiration: key.expiration.map(TimestampOutput::from),
            created_at: key.created_at.map(TimestampOutput::from),
            acl_tags: key.acl_tags,
        }
    }
}

impl From<prost_types::Timestamp> for TimestampOutput {
    fn from(ts: prost_types::Timestamp) -> Self {
        Self {
            seconds: ts.seconds,
            nanos: ts.nanos,
        }
    }
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

fn is_zero_i32(value: &i32) -> bool {
    *value == 0
}

#[derive(Debug, Serialize)]
struct BackfillOutput {
    changes: Vec<String>,
}

impl From<BackfillNodeIPsResponse> for BackfillOutput {
    fn from(response: BackfillNodeIPsResponse) -> Self {
        Self {
            changes: response.changes,
        }
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

fn short_key(key: &str) -> String {
    let Some((prefix, body)) = key.split_once(':') else {
        return short_id(key);
    };
    format!("{prefix}:{}", short_id(body))
}

fn route_nodes_for_display(
    mut nodes: Vec<NodeOutput>,
    requested_id: Option<u64>,
) -> Vec<NodeOutput> {
    if let Some(requested_id) = requested_id
        && let Some(position) = nodes.iter().position(|node| node.id == requested_id)
    {
        nodes = vec![nodes.remove(position)];
    }
    nodes.into_iter().filter(node_has_routes).collect()
}

fn node_has_routes(node: &NodeOutput) -> bool {
    !node.subnet_routes.is_empty()
        || !node.available_routes.is_empty()
        || !node.approved_routes.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route_node(id: u64, routes: &[&str]) -> NodeOutput {
        NodeOutput {
            id,
            machine_key: String::new(),
            node_key: String::new(),
            disco_key: String::new(),
            ip_addresses: Vec::new(),
            name: format!("node-{id}"),
            user: Some(NodeUserOutput {
                id: 1,
                name: "alice".into(),
                created_at: None,
                display_name: String::new(),
                email: String::new(),
                provider_id: String::new(),
                provider: String::new(),
                profile_pic_url: String::new(),
            }),
            last_seen: None,
            expiry: None,
            pre_auth_key: None,
            created_at: None,
            register_method: 0,
            given_name: String::new(),
            online: false,
            approved_routes: routes.iter().map(|route| (*route).to_string()).collect(),
            available_routes: Vec::new(),
            subnet_routes: Vec::new(),
            tags: Vec::new(),
            user_name: "alice".into(),
            last_seen_display: None,
            expiry_display: None,
            created_at_display: None,
        }
    }

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

    #[test]
    fn parse_node_id_accepts_numeric_identifier() {
        assert_eq!(parse_node_id("42").unwrap(), 42);
        assert!(matches!(
            parse_node_id("node-key"),
            Err(AdminError::Local(_))
        ));
    }

    #[test]
    fn route_list_identifier_only_narrows_on_match() {
        let nodes = vec![
            route_node(1, &["10.0.0.0/24"]),
            route_node(2, &[]),
            route_node(3, &["10.1.0.0/24"]),
        ];

        let matched = route_nodes_for_display(nodes.clone(), Some(3));
        assert_eq!(matched.iter().map(|node| node.id).collect::<Vec<_>>(), [3]);

        let missing = route_nodes_for_display(nodes, Some(99));
        assert_eq!(
            missing.iter().map(|node| node.id).collect::<Vec<_>>(),
            [1, 3]
        );
    }

    #[test]
    fn grpc_route_rows_use_given_name_hostname_like_upstream() {
        let mut node = route_node(7, &["10.0.0.0/24"]);
        node.name = "node.tail.example.com".into();
        node.given_name = "node".into();
        node.available_routes = vec!["10.0.0.0/24".into()];
        node.subnet_routes = vec!["10.0.0.0/24".into()];

        let rows = grpc_route_rows(&[node]);

        assert_eq!(rows[0][1], "node");
    }

    #[test]
    fn selector_helpers_accept_upstream_forms() {
        assert_eq!(select_node_id(None, Some("42")).unwrap(), "42");
        assert_eq!(select_node_id(Some("node-key"), None).unwrap(), "node-key");
        assert!(select_node_id(Some("1"), Some("2")).is_err());

        assert_eq!(
            select_rename_args("new-name", Some("42")).unwrap(),
            ("42", "new-name")
        );
        assert!(select_rename_args("legacy-name", None).is_err());

        assert_eq!(
            merged_tags(
                &["tag:prod".to_string()],
                &["tag:web".to_string(), String::new()]
            ),
            vec!["tag:prod".to_string(), "tag:web".to_string()]
        );
    }

    #[test]
    fn grpc_node_output_formats_timestamps_and_user() {
        let node = GrpcNode {
            id: 7,
            name: "node-one".into(),
            user: Some(headscale_api::generated::User {
                id: 1,
                name: "alice".into(),
                ..Default::default()
            }),
            ip_addresses: vec!["100.64.0.1".into()],
            created_at: Some(prost_types::Timestamp {
                seconds: 1_704_067_200,
                nanos: 0,
            }),
            expiry: Some(prost_types::Timestamp {
                seconds: 1,
                nanos: 0,
            }),
            pre_auth_key: Some(headscale_api::generated::PreAuthKey {
                ephemeral: true,
                ..Default::default()
            }),
            ..Default::default()
        };

        let output = NodeOutput::from(node);

        assert_eq!(output.id, 7);
        assert_eq!(output.user.as_ref().unwrap().name, "alice");
        assert_eq!(output.user_name, "alice");
        assert_eq!(
            output.created_at.as_ref().map(|ts| ts.seconds),
            Some(1_704_067_200)
        );
        assert_eq!(
            output.created_at_display.as_deref(),
            Some("2024-01-01T00:00:00Z")
        );
        assert!(output.ephemeral());
        assert!(output.expired());
    }

    #[test]
    fn grpc_node_output_serializes_proto_field_shape() {
        let output = NodeOutput::from(GrpcNode {
            id: 7,
            name: "node-one".into(),
            machine_key: "mkey:abc".into(),
            node_key: "nodekey:def".into(),
            user: Some(headscale_api::generated::User {
                id: 1,
                name: "alice".into(),
                created_at: Some(prost_types::Timestamp {
                    seconds: 1_704_067_100,
                    nanos: 0,
                }),
                ..Default::default()
            }),
            last_seen: Some(prost_types::Timestamp {
                seconds: 1_704_067_150,
                nanos: 0,
            }),
            created_at: Some(prost_types::Timestamp {
                seconds: 1_704_067_200,
                nanos: 0,
            }),
            pre_auth_key: Some(headscale_api::generated::PreAuthKey {
                id: 9,
                ephemeral: true,
                ..Default::default()
            }),
            ..Default::default()
        });

        let value = serde_json::to_value(&output).unwrap();

        assert_eq!(value["id"], 7);
        assert_eq!(value["machine_key"], "mkey:abc");
        assert_eq!(value["node_key"], "nodekey:def");
        assert_eq!(value["user"]["name"], "alice");
        assert_eq!(value["user"]["created_at"]["seconds"], 1_704_067_100);
        assert_eq!(value["last_seen"]["seconds"], 1_704_067_150);
        assert_eq!(value["created_at"]["seconds"], 1_704_067_200);
        assert_eq!(value["pre_auth_key"]["id"], 9);
        assert_eq!(value["pre_auth_key"]["ephemeral"], true);
        assert!(value.get("createdAt").is_none());
        assert!(value.get("lastSeen").is_none());
        assert!(value.get("machineKey").is_none());
        assert!(value.get("preAuthKey").is_none());
        assert!(value.get("ephemeral").is_none());
        assert!(value.get("expired").is_none());
    }

    fn route_record(id: &str, routes: &[&str], approved_routes: &[&str]) -> MachineAdminRecord {
        MachineAdminRecord {
            node_id: 0,
            id: id.to_string(),
            name: id.to_string(),
            user: "user".to_string(),
            ipv4: "100.64.0.1".to_string(),
            ipv6: None,
            online: true,
            last_seen: 0,
            created_at: 0,
            expiry: None,
            machine_key_hex: String::new(),
            os: "unknown".to_string(),
            version: "unknown".to_string(),
            tags: Vec::new(),
            routes: routes.iter().map(|route| (*route).to_string()).collect(),
            approved_routes: approved_routes
                .iter()
                .map(|route| (*route).to_string())
                .collect(),
            register_method: 0,
            expired: false,
        }
    }

    #[test]
    fn serving_routes_uses_stable_id_for_zero_node_id() {
        let route = "10.0.0.0/24";
        let nodes = vec![
            route_record("node-0", &[route], &[route]),
            route_record("node-10", &[route], &[route]),
        ];

        assert!(stable_id_from_key("node-10") < stable_id_from_key("node-0"));

        let serving = serving_routes(&nodes);

        assert_eq!(
            serving.get("node-10").cloned().unwrap_or_default(),
            vec![route]
        );
        assert!(!serving.contains_key("node-0"));
    }

    #[test]
    fn serving_routes_uses_persisted_node_id_when_present() {
        let route = "10.0.0.0/24";
        let mut higher = route_record("node-10", &[route], &[route]);
        higher.node_id = 2;
        let mut lower = route_record("node-0", &[route], &[route]);
        lower.node_id = 1;

        assert!(stable_id_from_key("node-10") < stable_id_from_key("node-0"));

        let serving = serving_routes(&[higher, lower]);

        assert_eq!(
            serving.get("node-0").cloned().unwrap_or_default(),
            vec![route]
        );
        assert!(!serving.contains_key("node-10"));
    }
}
