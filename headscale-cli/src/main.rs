//! Headscale-rs CLI
//!
//! Command-line interface for running headscale mesh nodes and control planes.
//! The admin subcommands (`users`, `nodes`, `preauthkeys`, `policy`,
//! `tailnet`) wrap the `/api/v1/*` surface exposed by the admin GUI
//! (#216 / commit `62b956d`).

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod node;
mod server;

use config::CliConfig;
use headscale_cli::admin::{
    self, AdminError, ConnectArgs, NodesCmd, PolicyCmd, PreauthKeysCmd, TailnetCmd, UsersCmd,
};

/// Headscale-rs: WireGuard mesh networking with resource accounting.
#[derive(Parser)]
#[command(name = "headscale")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to config file.
    #[arg(short, long, env = "HEADSCALE_CONFIG", global = true)]
    config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(
        short,
        long,
        default_value = "info",
        env = "HEADSCALE_LOG",
        global = true
    )]
    log_level: String,

    #[command(flatten)]
    connect: ConnectArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the control plane server.
    Server {
        /// Listen address for the API.
        #[arg(short, long, default_value = "0.0.0.0:8080")]
        listen: String,
        /// Database path.
        #[arg(short, long, default_value = "/var/lib/headscale/db.sqlite")]
        db_path: PathBuf,
        /// Mesh network CIDR.
        #[arg(long, default_value = "100.64.0.0/10")]
        mesh_cidr: String,
    },

    /// Run as a mesh node (connects to a control plane).
    Node {
        /// Control plane URL.
        #[arg(short, long, env = "HEADSCALE_SERVER")]
        server: String,
        /// Node name.
        #[arg(short, long, env = "HEADSCALE_NODE_NAME")]
        name: Option<String>,
        /// WireGuard interface name.
        #[arg(long, default_value = "wg0")]
        wg_interface: String,
        /// WireGuard listen port.
        #[arg(long, default_value = "51820")]
        wg_port: u16,
    },

    /// Generate a new identity.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },

    // ----- Admin surface (wraps `/api/v1/*`) -------------------------------
    /// Manage users on the admin surface.
    Users {
        #[command(subcommand)]
        action: UsersCmd,
    },
    /// Manage registered nodes.
    Nodes {
        #[command(subcommand)]
        action: NodesCmd,
    },
    /// Manage pre-auth keys.
    Preauthkeys {
        #[command(subcommand)]
        action: PreauthKeysCmd,
    },
    /// Inspect or update the network policy.
    Policy {
        #[command(subcommand)]
        action: PolicyCmd,
    },
    /// Inspect tailnet-wide state.
    Tailnet {
        #[command(subcommand)]
        action: TailnetCmd,
    },

    /// Check control plane status (legacy health probe — not the admin
    /// surface; uses the wire layer's `/health` endpoint).
    Status {
        /// Control plane URL (uses config if not provided).
        #[arg(long)]
        server: Option<String>,
    },

    /// Generate example configuration file.
    InitConfig {
        /// Output path for config file.
        #[arg(short, long, default_value = "headscale.toml")]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum IdentityAction {
    /// Generate a new identity keypair.
    Generate {
        /// Output path for identity file.
        #[arg(short, long, default_value = "identity.json")]
        output: PathBuf,
    },
    /// Show identity info from file.
    Show {
        /// Path to identity file.
        #[arg(short, long, default_value = "identity.json")]
        file: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = cli.log_level.parse().unwrap_or(tracing::Level::INFO);
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                format!("headscale={log_level},headscale_core={log_level}").into()
            }),
        )
        .with(tracing_subscriber::fmt::layer().with_target(true))
        .init();

    match dispatch(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(MainError::Admin(e)) => {
            eprintln!("error: {e}");
            ExitCode::from(e.exit_code() as u8)
        }
        Err(MainError::Other(e)) => {
            eprintln!("error: {e:#}");
            ExitCode::from(1)
        }
    }
}

/// Internal error envelope so the dispatcher can return both
/// admin-typed errors (with their exit codes) and the legacy
/// `anyhow::Error` paths from `server` / `node` / `identity`.
enum MainError {
    Admin(AdminError),
    Other(anyhow::Error),
}

impl From<AdminError> for MainError {
    fn from(e: AdminError) -> Self {
        Self::Admin(e)
    }
}

impl From<anyhow::Error> for MainError {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}

async fn dispatch(cli: Cli) -> Result<(), MainError> {
    // Load config file if provided (only the legacy `server`/`node`
    // commands consume it; admin commands take their URL via
    // `--server`/`HEADSCALE_URL`).
    let config = if let Some(config_path) = &cli.config {
        Some(
            CliConfig::load(config_path)
                .context("Failed to load config file")
                .map_err(MainError::Other)?,
        )
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
                .map_or(listen, |s| s.listen.clone());
            let db_path = config
                .as_ref()
                .and_then(|c| c.server.as_ref())
                .map_or(db_path, |s| s.db_path.clone());
            let mesh_cidr = config
                .as_ref()
                .and_then(|c| c.server.as_ref())
                .map_or(mesh_cidr, |s| s.mesh_cidr.clone());
            server::run_server(&listen, &db_path, &mesh_cidr)
                .await
                .map_err(MainError::Other)
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
                .map_or(server_url, |n| n.server.clone());
            let name = name.or_else(|| {
                config
                    .as_ref()
                    .and_then(|c| c.node.as_ref())
                    .and_then(|n| n.name.clone())
            });
            node::run_node(&server_url, name.as_deref(), &wg_interface, wg_port)
                .await
                .map_err(MainError::Other)
        }

        Commands::Identity { action } => match action {
            IdentityAction::Generate { output } => {
                identity_generate(&output).await.map_err(MainError::Other)
            }
            IdentityAction::Show { file } => identity_show(&file).await.map_err(MainError::Other),
        },

        Commands::Users { action } => admin::run_users(&cli.connect, &action)
            .await
            .map_err(Into::into),
        Commands::Nodes { action } => admin::run_nodes(&cli.connect, &action)
            .await
            .map_err(Into::into),
        Commands::Preauthkeys { action } => admin::run_preauthkeys(&cli.connect, &action)
            .await
            .map_err(Into::into),
        Commands::Policy { action } => admin::run_policy(&cli.connect, &action)
            .await
            .map_err(Into::into),
        Commands::Tailnet { action } => admin::run_tailnet(&cli.connect, &action)
            .await
            .map_err(Into::into),

        Commands::Status { server } => {
            let server_url = server.or_else(|| {
                config
                    .as_ref()
                    .and_then(|c| c.node.as_ref())
                    .map(|n| n.server.clone())
            });
            check_status(server_url.as_deref())
                .await
                .map_err(MainError::Other)
        }

        Commands::InitConfig { output } => init_config(&output).await.map_err(MainError::Other),
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
        let secret_bytes =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &self.secret_key)?;
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

    let stored = StoredIdentity::from_keypair(&keypair);
    let json = serde_json::to_string_pretty(&stored)?;
    std::fs::write(output, &json)?;

    println!("Identity generated successfully!");
    println!("  DID: {did}");
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

async fn check_status(server: Option<&str>) -> Result<()> {
    let server = server.context("Server URL required. Use --server or set in config file.")?;

    let client = reqwest::Client::new();
    let resp = client.get(format!("{server}/health")).send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            println!("Control plane at {server} is healthy");
            Ok(())
        }
        Ok(r) => {
            println!("Control plane returned: {}", r.status());
            Ok(())
        }
        Err(e) => {
            println!("Failed to connect to control plane: {e}");
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
    println!(
        "Edit the file to match your setup, then run with --config {}",
        output.display()
    );

    Ok(())
}
