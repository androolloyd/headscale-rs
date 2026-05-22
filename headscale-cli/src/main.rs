//! Headscale-rs CLI
//!
//! Command-line interface for running headscale mesh nodes and control planes.
//! The admin subcommands (`users`, `nodes`, `preauthkeys`, `policy`,
//! `apikeys`, `tailnet`) are being migrated to the upstream gRPC admin API.
//! Migrated groups default to the local Unix socket; unmigrated groups still
//! use the legacy `/api/v1/*` GUI surface.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod node;
mod server;

use config::{CliConfig, ServerConfig};
use headscale_cli::admin::{
    self, AdminError, ApiKeysCmd, ConnectArgs, NodesCmd, PolicyCmd, PreauthKeysCmd, TailnetCmd,
    UsersCmd,
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
    #[arg(long, default_value = "info", env = "HEADSCALE_LOG", global = true)]
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

    // ----- Admin surface ----------------------------------------------------
    /// Manage users on the admin surface.
    #[command(
        alias = "user",
        alias = "namespace",
        alias = "namespaces",
        alias = "ns"
    )]
    Users {
        #[command(subcommand)]
        action: UsersCmd,
    },
    /// Manage registered nodes.
    #[command(alias = "machine", alias = "machines")]
    Nodes {
        #[command(subcommand)]
        action: NodesCmd,
    },
    /// Manage pre-auth keys.
    #[command(alias = "preauthkey", alias = "authkey", alias = "pre")]
    Preauthkeys {
        #[command(subcommand)]
        action: PreauthKeysCmd,
    },
    /// Manage API keys.
    #[command(alias = "apikey", alias = "api")]
    Apikeys {
        #[command(subcommand)]
        action: ApiKeysCmd,
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
    // Load config file if provided. Server/node consume it today; admin
    // parity still uses flags/env until the upstream `cli` config section is
    // wired into ConnectArgs.
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
            let server_config = config.as_ref().and_then(|c| c.server.as_ref());
            let defaults = ServerConfig::default();
            let run_config = server::RunServerConfig {
                listen: server_config.map_or(listen, |s| s.listen.clone()),
                db_path: server_config.map_or(db_path, |s| s.db_path.clone()),
                mesh_cidr: server_config.map_or(mesh_cidr, |s| s.mesh_cidr.clone()),
                server_url: server_config.and_then(|s| s.server_url.clone()),
                state_dir: server_config.map_or(defaults.state_dir, |s| s.state_dir.clone()),
                https_listen: server_config.and_then(|s| s.https_listen.clone()),
                tls_hostname: server_config.and_then(|s| s.tls_hostname.clone()),
                unix_socket: server_config.map_or(defaults.unix_socket, |s| s.unix_socket.clone()),
                unix_socket_permission: server_config
                    .map_or(defaults.unix_socket_permission, |s| {
                        s.unix_socket_permission
                    }),
                grpc_listen_addr: server_config
                    .map_or(defaults.grpc_listen_addr, |s| s.grpc_listen_addr.clone()),
                grpc_allow_insecure: server_config.is_some_and(|s| s.grpc_allow_insecure),
                oidc: config
                    .as_ref()
                    .map_or_else(headscale_core::config::OidcConfig::default, |c| {
                        c.oidc.clone()
                    }),
                embedded_derp: server_config
                    .map_or(defaults.embedded_derp, |s| s.embedded_derp.clone()),
            };
            server::run_server(run_config)
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
        Commands::Apikeys { action } => admin::run_apikeys(&cli.connect, &action)
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
# Required when [oidc] is configured; used for /oidc/callback and helper URLs.
# server_url = "https://headscale.example"
# state_dir = "/var/lib/headscale"
# https_listen = "0.0.0.0:443"
# tls_hostname = "headscale.example"
# unix_socket = "/var/run/headscale/headscale.sock"
# unix_socket_permission = 504
# grpc_listen_addr = ":50443"
# grpc_allow_insecure = false

# Embedded DERP/STUN runtime. This starts a native STUN listener and can
# supervise an upstream tailscale derper binary for DERP relay traffic.
#[server.embedded_derp]
#enabled = false
#host_name = "derp.example.com"
#region_id = 900
#region_code = "embedded"
#region_name = "Embedded DERP"
#derp_port = 443
#stun_addr = "0.0.0.0:3478"
#stun_only = false
#derper_binary = "/usr/local/bin/derper"
#derper_listen_addr = "0.0.0.0:443"
#derper_cert_mode = "letsencrypt"
#omit_default_regions = false

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

# OpenID Connect registration. When oidc.issuer is set, `headscale server`
# starts the Tailscale wire-compatible public control surface and completes
# OIDC callbacks through the persistent users/nodes tables.
#[oidc]
#issuer = "https://issuer.example"
#client_id = "headscale"
#client_secret = "change-me"
"#;

    std::fs::write(output, example_config)?;
    println!("Example configuration written to: {}", output.display());
    println!(
        "Edit the file to match your setup, then run with --config {}",
        output.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn standalone_cli_accepts_user_aliases_from_upstream() {
        let parsed = Cli::try_parse_from(["headscale", "ns", "show"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Users {
                action: UsersCmd::List { .. }
            }
        ));
    }

    #[test]
    fn standalone_cli_accepts_machine_alias_without_conflicting_with_node_mode() {
        let parsed = Cli::try_parse_from(["headscale", "machine", "ls"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Nodes {
                action: NodesCmd::List { .. }
            }
        ));

        let parsed =
            Cli::try_parse_from(["headscale", "node", "--server", "http://127.0.0.1"]).unwrap();
        assert!(matches!(parsed.command, Commands::Node { .. }));
    }

    #[test]
    fn standalone_cli_accepts_preauthkey_aliases_from_upstream() {
        let parsed =
            Cli::try_parse_from(["headscale", "authkey", "new", "--user", "alice"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Preauthkeys {
                action: PreauthKeysCmd::Create { .. }
            }
        ));
    }

    #[test]
    fn standalone_cli_accepts_policy_aliases_from_upstream() {
        let parsed = Cli::try_parse_from(["headscale", "policy", "view"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Policy {
                action: PolicyCmd::Get
            }
        ));
    }

    #[test]
    fn standalone_cli_accepts_upstream_output_selector() {
        let parsed = Cli::try_parse_from(["headscale", "-o", "json-line", "users", "ls"]).unwrap();
        assert_eq!(parsed.connect.output.as_deref(), Some("json-line"));
        assert_eq!(
            parsed.connect.fmt().unwrap(),
            headscale_cli::admin::OutputFormat::JsonLine
        );
    }
}
