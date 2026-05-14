//! Headscale-rs CLI
//!
//! Command-line interface for running headscale mesh nodes and control planes.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod node;
mod server;

use config::CliConfig;

/// Headscale-rs: WireGuard mesh networking with resource accounting
#[derive(Parser)]
#[command(name = "headscale")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to config file
    #[arg(short, long, env = "HEADSCALE_CONFIG")]
    config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info", env = "HEADSCALE_LOG")]
    log_level: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the control plane server
    Server {
        /// Listen address for the API
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        listen: String,

        /// Database path
        #[arg(short, long, default_value = "/var/lib/headscale/db.sqlite")]
        db_path: PathBuf,

        /// Mesh network CIDR
        #[arg(long, default_value = "100.64.0.0/10")]
        mesh_cidr: String,
    },

    /// Run as a mesh node (connects to a control plane)
    Node {
        /// Control plane URL
        #[arg(short, long, env = "HEADSCALE_SERVER")]
        server: String,

        /// Node name
        #[arg(short, long, env = "HEADSCALE_NODE_NAME")]
        name: Option<String>,

        /// WireGuard interface name
        #[arg(long, default_value = "wg0")]
        wg_interface: String,

        /// WireGuard listen port
        #[arg(long, default_value = "51820")]
        wg_port: u16,
    },

    /// Generate a new identity
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },

    /// Manage mesh nodes (control plane admin commands)
    Nodes {
        #[command(subcommand)]
        action: NodeAction,
    },

    /// Check control plane status
    Status {
        /// Control plane URL (uses config if not provided)
        #[arg(short, long)]
        server: Option<String>,
    },

    /// Generate example configuration file
    InitConfig {
        /// Output path for config file
        #[arg(short, long, default_value = "headscale.toml")]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a new identity keypair
    Generate {
        /// Output path for identity file
        #[arg(short, long, default_value = "identity.json")]
        output: PathBuf,
    },
    /// Show identity info from file
    Show {
        /// Path to identity file
        #[arg(short, long, default_value = "identity.json")]
        file: PathBuf,
    },
}

#[derive(Subcommand)]
enum NodeAction {
    /// List all registered nodes
    List {
        /// Control plane URL
        #[arg(short, long)]
        server: Option<String>,
    },
    /// Show details for a specific node
    Show {
        /// Node ID or name
        node: String,
        /// Control plane URL
        #[arg(short, long)]
        server: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = cli.log_level.parse().unwrap_or(tracing::Level::INFO);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("headscale={},headscale_core={}", log_level, log_level).into()),
        )
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .init();

    // Load config file if provided
    let config = if let Some(config_path) = &cli.config {
        Some(CliConfig::load(config_path).context("Failed to load config file")?)
    } else {
        None
    };

    match cli.command {
        Commands::Server {
            listen,
            db_path,
            mesh_cidr,
        } => {
            let listen = config
                .as_ref()
                .and_then(|c| c.server.as_ref())
                .map(|s| s.listen.clone())
                .unwrap_or(listen);
            let db_path = config
                .as_ref()
                .and_then(|c| c.server.as_ref())
                .map(|s| s.db_path.clone())
                .unwrap_or(db_path);
            let mesh_cidr = config
                .as_ref()
                .and_then(|c| c.server.as_ref())
                .map(|s| s.mesh_cidr.clone())
                .unwrap_or(mesh_cidr);

            server::run_server(&listen, &db_path, &mesh_cidr).await
        }

        Commands::Node {
            server: server_url,
            name,
            wg_interface,
            wg_port,
        } => {
            let server_url = config
                .as_ref()
                .and_then(|c| c.node.as_ref())
                .map(|n| n.server.clone())
                .unwrap_or(server_url);
            let name = name.or_else(|| {
                config
                    .as_ref()
                    .and_then(|c| c.node.as_ref())
                    .and_then(|n| n.name.clone())
            });

            node::run_node(&server_url, name.as_deref(), &wg_interface, wg_port).await
        }

        Commands::Identity { action } => match action {
            IdentityAction::Generate { output } => {
                identity_generate(&output).await
            }
            IdentityAction::Show { file } => {
                identity_show(&file).await
            }
        },

        Commands::Nodes { action } => match action {
            NodeAction::List { server } => {
                let server_url = server.or_else(|| {
                    config
                        .as_ref()
                        .and_then(|c| c.node.as_ref())
                        .map(|n| n.server.clone())
                });
                nodes_list(server_url.as_deref()).await
            }
            NodeAction::Show { node, server } => {
                let server_url = server.or_else(|| {
                    config
                        .as_ref()
                        .and_then(|c| c.node.as_ref())
                        .map(|n| n.server.clone())
                });
                nodes_show(&node, server_url.as_deref()).await
            }
        },

        Commands::Status { server } => {
            let server_url = server.or_else(|| {
                config
                    .as_ref()
                    .and_then(|c| c.node.as_ref())
                    .map(|n| n.server.clone())
            });
            check_status(server_url.as_deref()).await
        }

        Commands::InitConfig { output } => {
            init_config(&output).await
        }
    }
}

/// Serializable identity wrapper for CLI persistence.
#[derive(serde::Serialize, serde::Deserialize)]
struct StoredIdentity {
    /// Secret key bytes (base64 encoded)
    secret_key: String,
    /// DID string
    did: String,
}

impl StoredIdentity {
    fn from_keypair(keypair: &headscale_identity::KeyPair) -> Self {
        Self {
            secret_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                keypair.secret_key(),
            ),
            did: keypair.did().to_string(),
        }
    }

    #[allow(dead_code)]
    fn to_keypair(&self) -> Result<headscale_identity::KeyPair> {
        let secret_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &self.secret_key,
        )?;
        let secret_array: [u8; 32] = secret_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid secret key length"))?;
        Ok(headscale_identity::KeyPair::from_secret(&secret_array))
    }
}

async fn identity_generate(output: &PathBuf) -> Result<()> {
    tracing::info!("Generating new identity...");

    let keypair = headscale_identity::KeyPair::generate();
    let did = keypair.did();

    // Serialize identity
    let stored = StoredIdentity::from_keypair(&keypair);
    let json = serde_json::to_string_pretty(&stored)?;
    std::fs::write(output, &json)?;

    println!("Identity generated successfully!");
    println!("  DID: {}", did);
    println!("  Saved to: {}", output.display());
    println!();
    println!("Keep this file secure - it contains your private key!");

    Ok(())
}

async fn identity_show(file: &PathBuf) -> Result<()> {
    let contents = std::fs::read_to_string(file)
        .with_context(|| format!("Failed to read identity file: {}", file.display()))?;
    let stored: StoredIdentity = serde_json::from_str(&contents)?;

    println!("Identity Information:");
    println!("  DID: {}", stored.did);
    println!("  File: {}", file.display());

    Ok(())
}

async fn nodes_list(server: Option<&str>) -> Result<()> {
    let server = server.context("Server URL required. Use --server or set in config file.")?;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/nodes", server))
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("Failed to list nodes: {}", resp.status());
    }

    let nodes: Vec<serde_json::Value> = resp.json().await?;

    if nodes.is_empty() {
        println!("No nodes registered.");
        return Ok(());
    }

    println!("{:<40} {:<20} {:<15} {:<10}", "ID", "NAME", "IP", "STATUS");
    println!("{}", "-".repeat(85));

    for node in nodes {
        let id = node["id"].as_str().unwrap_or("-");
        let name = node["name"].as_str().unwrap_or("-");
        let ip = node["addresses"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_str())
            .unwrap_or("-");
        let online = node["online"].as_bool().unwrap_or(false);
        let status = if online { "online" } else { "offline" };

        println!("{:<40} {:<20} {:<15} {:<10}", id, name, ip, status);
    }

    Ok(())
}

async fn nodes_show(node_id: &str, server: Option<&str>) -> Result<()> {
    let server = server.context("Server URL required. Use --server or set in config file.")?;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/nodes/{}", server, node_id))
        .send()
        .await?;

    if !resp.status().is_success() {
        anyhow::bail!("Failed to get node: {}", resp.status());
    }

    let node: serde_json::Value = resp.json().await?;

    println!("Node Details:");
    println!("  ID:        {}", node["id"].as_str().unwrap_or("-"));
    println!("  Name:      {}", node["name"].as_str().unwrap_or("-"));
    println!("  WG Pubkey: {}", node["wg_pubkey"].as_str().unwrap_or("-"));
    println!("  Online:    {}", node["online"].as_bool().unwrap_or(false));
    println!("  Last Seen: {}", node["last_seen"].as_u64().unwrap_or(0));

    if let Some(addresses) = node["addresses"].as_array() {
        println!("  Addresses:");
        for addr in addresses {
            println!("    - {}", addr.as_str().unwrap_or("-"));
        }
    }

    if let Some(endpoints) = node["endpoints"].as_array() {
        println!("  Endpoints:");
        for ep in endpoints {
            println!("    - {}", ep.as_str().unwrap_or("-"));
        }
    }

    Ok(())
}

async fn check_status(server: Option<&str>) -> Result<()> {
    let server = server.context("Server URL required. Use --server or set in config file.")?;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/health", server))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            println!("Control plane at {} is healthy", server);
            Ok(())
        }
        Ok(r) => {
            println!("Control plane returned: {}", r.status());
            Ok(())
        }
        Err(e) => {
            println!("Failed to connect to control plane: {}", e);
            Ok(())
        }
    }
}

async fn init_config(output: &PathBuf) -> Result<()> {
    let example_config = r#"# Headscale-rs Configuration
# https://github.com/last-net/headscale-rs

# Server mode configuration (control plane)
[server]
listen = "0.0.0.0:8080"
db_path = "/var/lib/headscale/db.sqlite"
mesh_cidr = "100.64.0.0/10"

# DERP relay servers for NAT traversal
[[server.derp_servers]]
name = "us-west"
hostname = "derp.example.com"
region = "us-west"
stun_enabled = true

# Node mode configuration (mesh participant)
[node]
server = "http://localhost:8080"
name = "my-node"
wg_interface = "wg0"
wg_port = 51820
identity_file = "identity.json"

# Node capabilities (what resources this node can provide)
[node.capabilities]
relay = false
inference = false
storage = false
compute = false
seed = false

# Logging configuration
[logging]
level = "info"
format = "pretty"  # pretty, json, compact
"#;

    std::fs::write(output, example_config)?;
    println!("Example configuration written to: {}", output.display());
    println!("Edit the file to match your setup, then run with --config {}", output.display());

    Ok(())
}
