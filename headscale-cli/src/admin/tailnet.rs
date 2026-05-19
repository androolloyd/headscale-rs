//! `headscale tailnet status` — wraps `GET /api/v1/tailnet`.
//!
//! The admin endpoint returns a JSON object with `derp_regions`,
//! `dns`, and `policy_loaded`. We accept any object shape via
//! `serde_json::Value` so the CLI doesn't lock the server's response
//! shape — the field set is still in flux (#230) and tightening it
//! here would force a CLI release every time the GUI grew a field.

use super::client::AdminClient;
use super::output::{print_json, OutputFormat};
use super::AdminError;

pub async fn status(client: &AdminClient, fmt: OutputFormat) -> Result<(), AdminError> {
    let v: serde_json::Value = client.get_json("/tailnet").await?;
    match fmt {
        OutputFormat::Json => print_json(&v)?,
        OutputFormat::Table => render(&v),
    }
    Ok(())
}

fn render(v: &serde_json::Value) {
    let derp = v
        .get("derp_regions")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    let policy_loaded = v
        .get("policy_loaded")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    println!("Tailnet status:");
    println!("  DERP regions:  {derp}");
    println!("  Policy loaded: {policy_loaded}");
    if let Some(dns) = v.get("dns") {
        let magic = dns
            .get("magic_dns")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let enabled = dns
            .get("enabled")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        println!("  MagicDNS:      {magic}");
        println!("  DNS enabled:   {enabled}");
    }
}
