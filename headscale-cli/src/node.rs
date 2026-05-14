//! Node mode - connects to a control plane and joins the mesh.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Run as a mesh node.
pub async fn run_node(
    server_url: &str,
    name: Option<&str>,
    wg_interface: &str,
    wg_port: u16,
) -> Result<()> {
    tracing::info!("Starting headscale node");
    tracing::info!("  Server: {}", server_url);
    tracing::info!("  WireGuard interface: {}", wg_interface);
    tracing::info!("  WireGuard port: {}", wg_port);

    // Generate or load identity
    let node_id = generate_node_id();
    let node_name = name
        .map(String::from)
        .unwrap_or_else(|| hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| format!("node-{}", &node_id[..8])));

    tracing::info!("  Node ID: {}", node_id);
    tracing::info!("  Node name: {}", node_name);

    // Generate WireGuard keypair
    let wg_keypair = headscale_core::WgKeyPair::generate();
    tracing::info!("  WG Public Key: {}", wg_keypair.public_key_base64());

    // Discover local endpoints
    let endpoints = discover_endpoints(wg_port).await;
    tracing::info!("  Endpoints: {:?}", endpoints);

    // Register with control plane
    let client = reqwest::Client::new();
    let register_req = RegisterRequest {
        id: node_id.clone(),
        name: node_name.clone(),
        wg_pubkey: wg_keypair.public_key_base64(),
        endpoints: endpoints.clone(),
        capabilities: Capabilities::default(),
    };

    tracing::info!("Registering with control plane...");
    let resp = client
        .post(format!("{}/api/v1/register", server_url))
        .json(&register_req)
        .send()
        .await
        .context("Failed to connect to control plane")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Registration failed: {} - {}", status, body);
    }

    let register_resp: RegisterResponse = resp.json().await
        .context("Invalid registration response")?;

    tracing::info!("Registration successful!");
    tracing::info!("  Assigned IPs: {:?}", register_resp.addresses);
    tracing::info!("  Peers: {}", register_resp.peers.len());

    // Configure WireGuard interface
    configure_wireguard(wg_interface, &wg_keypair, wg_port, &register_resp).await?;

    // Start heartbeat loop
    let heartbeat_url = format!("{}/api/v1/nodes/{}/heartbeat", server_url, node_id);
    let heartbeat_client = client.clone();

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            match heartbeat_client.post(&heartbeat_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    tracing::debug!("Heartbeat sent");
                }
                Ok(resp) => {
                    tracing::warn!("Heartbeat failed: {}", resp.status());
                }
                Err(e) => {
                    tracing::warn!("Heartbeat error: {}", e);
                }
            }
        }
    });

    tracing::info!("Node is running. Press Ctrl+C to exit.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down...");

    Ok(())
}

/// Generate a unique node ID.
fn generate_node_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    // Simple hash-based ID
    format!("node-{:016x}", timestamp)
}

/// Discover local endpoints for NAT traversal.
async fn discover_endpoints(wg_port: u16) -> Vec<String> {
    let mut endpoints = Vec::new();

    // Try to get local IP addresses
    if let Ok(interfaces) = local_ip_address::list_afinet_netifas() {
        for (_, ip) in interfaces {
            // Skip loopback
            if ip.is_loopback() {
                continue;
            }

            // For now, only use IPv4
            if let std::net::IpAddr::V4(v4) = ip {
                // Skip link-local
                if v4.is_link_local() {
                    continue;
                }

                endpoints.push(format!("{}:{}", v4, wg_port));
            }
        }
    }

    // TODO: Add STUN-discovered endpoint

    endpoints
}

/// Configure WireGuard interface with assigned config.
async fn configure_wireguard(
    interface: &str,
    _keypair: &headscale_core::WgKeyPair,
    port: u16,
    config: &RegisterResponse,
) -> Result<()> {
    tracing::info!("Configuring WireGuard interface: {}", interface);

    // Note: This is a placeholder. Real implementation would:
    // 1. Create TUN device
    // 2. Configure with boringtun in userspace
    // 3. Set up routing for assigned IPs
    // 4. Add peers

    tracing::info!("  Private key: [redacted]");
    tracing::info!("  Listen port: {}", port);

    for addr in &config.addresses {
        tracing::info!("  Address: {}/32", addr);
    }

    for peer in &config.peers {
        tracing::info!("  Peer: {} ({})", peer.id, peer.wg_pubkey);
        for allowed in &peer.allowed_ips {
            tracing::info!("    AllowedIPs: {}", allowed);
        }
    }

    // In a full implementation, we would use:
    // - headscale_core::TunDevice for the TUN interface
    // - headscale_core::TunnelManager for WireGuard tunnels
    // - headscale_core::StunClient for NAT discovery
    // - headscale_core::DerpClient for relay fallback

    tracing::warn!("WireGuard configuration is in demo mode - no actual tunnel created");

    Ok(())
}

#[derive(Debug, Serialize)]
struct RegisterRequest {
    id: String,
    name: String,
    wg_pubkey: String,
    endpoints: Vec<String>,
    capabilities: Capabilities,
}

#[derive(Debug, Serialize, Default)]
struct Capabilities {
    relay: bool,
    inference: bool,
    storage: bool,
    compute: bool,
    seed: bool,
}

#[derive(Debug, Deserialize)]
struct RegisterResponse {
    addresses: Vec<String>,
    peers: Vec<PeerInfo>,
    #[allow(dead_code)]
    derp_map: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct PeerInfo {
    id: String,
    wg_pubkey: String,
    #[allow(dead_code)]
    addresses: Vec<String>,
    #[allow(dead_code)]
    endpoints: Vec<String>,
    allowed_ips: Vec<String>,
}
