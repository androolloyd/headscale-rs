//! Headscale-rs CLI
//!
//! Command-line interface for running headscale mesh nodes and control planes.
//! The admin subcommands (`users`, `nodes`, `auth`, `preauthkeys`, `policy`,
//! `apikeys`, `tailnet`) are being migrated to the upstream gRPC admin API.
//! Migrated groups default to the local Unix socket; unmigrated groups still
//! use the legacy `/api/v1/*` GUI surface.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use rand_core::{OsRng, RngCore};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod config;
mod derp_config;
mod mockoidc;
mod node;
mod server;

use config::{CliConfig, ServerConfig};
use headscale_cli::admin::{
    self, AdminError, ApiKeysCmd, AuthCmd, ConnectArgs, DebugCmd, NodesCmd, PolicyCmd,
    PreauthKeysCmd, TailnetCmd, UsersCmd,
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
    #[command(alias = "serve")]
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
        /// Optional IPv6 mesh network CIDR.
        #[arg(long)]
        mesh_cidr_v6: Option<String>,
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
    /// Manage node authentication and approval.
    Auth {
        #[command(subcommand)]
        action: AuthCmd,
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
    /// Debug and testing commands.
    Debug {
        #[command(subcommand)]
        action: DebugCmd,
    },

    /// Generate commands.
    #[command(alias = "gen")]
    Generate {
        #[command(subcommand)]
        action: GenerateCmd,
    },

    /// Runs a mock OIDC server for testing.
    Mockoidc,

    /// Check the health of the Headscale server.
    Health,

    /// Print the version.
    Version,

    /// Generate the autocompletion script for the specified shell.
    Completion {
        #[command(subcommand)]
        shell: CompletionShell,
    },

    /// Test the configuration.
    Configtest,

    /// Dump the current config to `/etc/headscale/config.dump.yaml`.
    #[command(name = "dumpConfig", hide = true)]
    DumpConfig,

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

#[derive(Subcommand)]
enum GenerateCmd {
    /// Generate a private key for the headscale server.
    PrivateKey,
}

#[derive(Subcommand)]
enum CompletionShell {
    /// Generate the autocompletion script for bash.
    Bash {
        /// Disable completion descriptions.
        #[arg(long)]
        no_descriptions: bool,
    },
    /// Generate the autocompletion script for fish.
    Fish {
        /// Disable completion descriptions.
        #[arg(long)]
        no_descriptions: bool,
    },
    /// Generate the autocompletion script for powershell.
    Powershell {
        /// Disable completion descriptions.
        #[arg(long)]
        no_descriptions: bool,
    },
    /// Generate the autocompletion script for zsh.
    Zsh {
        /// Disable completion descriptions.
        #[arg(long)]
        no_descriptions: bool,
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
    let skip_config_load = matches!(
        cli.command,
        Commands::Version | Commands::Completion { .. } | Commands::Mockoidc
    );
    let config = if skip_config_load {
        None
    } else if let Some(config_path) = &cli.config {
        Some(
            CliConfig::load(config_path)
                .context("Failed to load config file")
                .map_err(MainError::Other)?,
        )
    } else {
        Some(
            CliConfig::load_default()
                .context("Failed to load config")
                .map_err(MainError::Other)?,
        )
    };
    let connect = merged_connect_args(&cli.connect, config.as_ref());

    match cli.command {
        Commands::Server {
            listen,
            db_path,
            mesh_cidr,
            mesh_cidr_v6,
        } => {
            let server_config = config.as_ref().and_then(|c| c.server.as_ref());
            let defaults = ServerConfig::default();
            let run_config = server::RunServerConfig {
                listen: server_config.map_or(listen, |s| s.listen.clone()),
                db_path: server_config.map_or(db_path, |s| s.db_path.clone()),
                mesh_cidr: server_config.map_or(mesh_cidr, |s| s.mesh_cidr.clone()),
                mesh_cidr_v6: server_config
                    .and_then(|s| s.mesh_cidr_v6.clone())
                    .or(mesh_cidr_v6),
                ip_allocation: server_config
                    .map_or(defaults.ip_allocation, |s| s.ip_allocation.clone()),
                server_url: server_config.and_then(|s| s.server_url.clone()),
                state_dir: server_config.map_or(defaults.state_dir, |s| s.state_dir.clone()),
                https_listen: server_config.and_then(|s| s.https_listen.clone()),
                metrics_listen_addr: server_config.map_or(defaults.metrics_listen_addr, |s| {
                    s.metrics_listen_addr.clone()
                }),
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
                derp: config.as_ref().and_then(|c| c.derp.clone()),
                dns: config.as_ref().and_then(|c| c.dns.clone()),
                ephemeral_node_inactivity_timeout: Duration::from_secs(
                    server_config.map_or(defaults.ephemeral_node_inactivity_timeout_secs, |s| {
                        s.ephemeral_node_inactivity_timeout_secs
                    }),
                ),
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

        Commands::Users { action } => admin::run_users(&connect, &action)
            .await
            .map_err(Into::into),
        Commands::Nodes { action } => admin::run_nodes(&connect, &action)
            .await
            .map_err(Into::into),
        Commands::Preauthkeys { action } => admin::run_preauthkeys(&connect, &action)
            .await
            .map_err(Into::into),
        Commands::Auth { action } => admin::run_auth(&connect, &action).await.map_err(Into::into),
        Commands::Apikeys { action } => admin::run_apikeys(&connect, &action)
            .await
            .map_err(Into::into),
        Commands::Policy { action } => admin::run_policy(&connect, &action)
            .await
            .map_err(Into::into),
        Commands::Tailnet { action } => admin::run_tailnet(&connect, &action)
            .await
            .map_err(Into::into),
        Commands::Debug { action } => admin::run_debug(&connect, &action)
            .await
            .map_err(Into::into),
        Commands::Generate { action } => match action {
            GenerateCmd::PrivateKey => print_private_key(connect.fmt().map_err(MainError::Admin)?)
                .map_err(MainError::Other),
        },
        Commands::Mockoidc => mockoidc::run().await.map_err(MainError::Other),
        Commands::Health => admin::run_health(&connect).await.map_err(Into::into),
        Commands::Version => {
            print_version(connect.fmt().map_err(MainError::Admin)?).map_err(MainError::Other)
        }
        Commands::Completion { shell } => {
            generate_completion(&shell);
            Ok(())
        }
        Commands::Configtest => configtest(config.as_ref()).map_err(MainError::Other),
        Commands::DumpConfig => dump_config(config.as_ref()).map_err(MainError::Other),

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

fn merged_connect_args(connect: &ConnectArgs, config: Option<&CliConfig>) -> ConnectArgs {
    let Some(config) = config else {
        return connect.clone();
    };

    let mut merged = connect.clone();
    let cli_config = config.cli.as_ref();

    if option_is_empty(merged.address.as_ref()) {
        merged.address = cli_config.and_then(|cli| non_empty_clone(cli.address.as_ref()));
    }
    if option_is_empty(merged.api_key.as_ref()) {
        merged.api_key = cli_config.and_then(|cli| non_empty_clone(cli.api_key.as_ref()));
    }
    if !merged.insecure {
        merged.insecure = cli_config.and_then(|cli| cli.insecure).unwrap_or(false);
    }
    if merged.unix_socket.is_none() {
        merged.unix_socket = config.unix_socket.clone().or_else(|| {
            config
                .server
                .as_ref()
                .map(|server| server.unix_socket.clone())
        });
    }

    merged
}

fn option_is_empty(value: Option<&String>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

fn non_empty_clone(value: Option<&String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty()).cloned()
}

fn configtest(config: Option<&CliConfig>) -> Result<()> {
    let config = config.context("configuration was not loaded")?;
    config.validate_for_configtest()?;
    Ok(())
}

fn generate_completion(shell: &CompletionShell) {
    let _no_descriptions = shell.no_descriptions();
    let mut command = Cli::command();
    clap_complete::generate(
        shell.clap_shell(),
        &mut command,
        "headscale",
        &mut std::io::stdout(),
    );
}

impl CompletionShell {
    fn clap_shell(&self) -> clap_complete::Shell {
        match self {
            Self::Bash { .. } => clap_complete::Shell::Bash,
            Self::Fish { .. } => clap_complete::Shell::Fish,
            Self::Powershell { .. } => clap_complete::Shell::PowerShell,
            Self::Zsh { .. } => clap_complete::Shell::Zsh,
        }
    }

    fn no_descriptions(&self) -> bool {
        match self {
            Self::Bash { no_descriptions }
            | Self::Fish { no_descriptions }
            | Self::Powershell { no_descriptions }
            | Self::Zsh { no_descriptions } => *no_descriptions,
        }
    }
}

fn print_version(fmt: headscale_cli::admin::OutputFormat) -> Result<()> {
    let version = VersionInfo::current();
    if fmt.is_structured() {
        print_structured_value(fmt, &version)?;
    } else {
        print!("{}", version.human());
    }
    Ok(())
}

fn print_private_key(fmt: headscale_cli::admin::OutputFormat) -> Result<()> {
    let private_key = MachinePrivateKeyOutput {
        private_key: generate_machine_private_key(),
    };
    if fmt.is_structured() {
        print_structured_value(fmt, &private_key)?;
    } else {
        println!("{}", private_key.private_key);
    }
    Ok(())
}

fn dump_config(config: Option<&CliConfig>) -> Result<()> {
    let config = config.context("configuration was not loaded")?;
    dump_config_to(config, &PathBuf::from("/etc/headscale/config.dump.yaml"))
}

fn dump_config_to(config: &CliConfig, path: &PathBuf) -> Result<()> {
    let contents = serde_yaml::to_string(config)?;
    if let Err(err) = std::fs::write(path, contents) {
        println!("Failed to dump config");
        return Err(err).with_context(|| format!("write config dump to {}", path.display()));
    }
    Ok(())
}

fn print_structured_value<T: serde::Serialize>(
    fmt: headscale_cli::admin::OutputFormat,
    value: &T,
) -> Result<()> {
    match fmt {
        headscale_cli::admin::OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(value)?);
        }
        headscale_cli::admin::OutputFormat::JsonLine => {
            println!("{}", serde_json::to_string(value)?);
        }
        headscale_cli::admin::OutputFormat::Yaml => {
            print!("{}", serde_yaml::to_string(value)?);
        }
        headscale_cli::admin::OutputFormat::Table => unreachable!(),
    }
    Ok(())
}

fn generate_machine_private_key() -> String {
    let mut key = [0_u8; 32];
    OsRng.fill_bytes(&mut key);
    key[0] &= 0xf8;
    key[31] &= 127;
    key[31] |= 64;
    format!("privkey:{}", hex::encode(key))
}

#[derive(serde::Serialize)]
struct MachinePrivateKeyOutput {
    private_key: String,
}

#[derive(serde::Serialize)]
struct VersionInfo {
    version: &'static str,
    commit: &'static str,
    #[serde(rename = "buildTime")]
    build_time: &'static str,
    rust: RustInfo,
    dirty: bool,
}

#[derive(serde::Serialize)]
struct RustInfo {
    version: &'static str,
    os: &'static str,
    arch: &'static str,
}

impl VersionInfo {
    fn current() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            commit: option_env!("HEADSCALE_RS_COMMIT").unwrap_or("unknown"),
            build_time: option_env!("HEADSCALE_RS_BUILD_TIME").unwrap_or("unknown"),
            rust: RustInfo {
                version: option_env!("RUSTC_VERSION").unwrap_or("unknown"),
                os: std::env::consts::OS,
                arch: std::env::consts::ARCH,
            },
            dirty: option_env!("HEADSCALE_RS_DIRTY").is_some_and(|value| value == "true"),
        }
    }

    fn human(&self) -> String {
        format!(
            "headscale-rs version {}\ncommit: {}\nbuild time: {}\nbuilt with: rust {} {}/{}\n",
            self.version,
            self.commit,
            self.build_time,
            self.rust.version,
            self.rust.os,
            self.rust.arch
        )
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
# mesh_cidr_v6 = "fd7a:115c:a1e0::/48"
# Required when [oidc] is configured; used for /oidc/callback and helper URLs.
# server_url = "https://headscale.example"
# state_dir = "/var/lib/headscale"
# https_listen = "0.0.0.0:443"
# metrics_listen_addr = "127.0.0.1:9090"
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
    fn standalone_cli_accepts_auth_commands_from_upstream() {
        let parsed = Cli::try_parse_from([
            "headscale",
            "auth",
            "register",
            "--user",
            "alice",
            "--auth-id",
            "hskey-authreq-abcdefghijklmnopqrstuvwx",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Auth {
                action: AuthCmd::Register { .. }
            }
        ));

        let parsed =
            Cli::try_parse_from(["headscale", "preauthkeys", "delete", "--id", "42"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Preauthkeys {
                action: PreauthKeysCmd::Delete { id: 42 }
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

    #[test]
    fn standalone_cli_accepts_upstream_serve_and_health_commands() {
        let parsed = Cli::try_parse_from(["headscale", "serve"]).unwrap();
        assert!(matches!(parsed.command, Commands::Server { .. }));

        let parsed = Cli::try_parse_from(["headscale", "health"]).unwrap();
        assert!(matches!(parsed.command, Commands::Health));
    }

    #[test]
    fn standalone_cli_accepts_upstream_mockoidc_command() {
        let parsed = Cli::try_parse_from(["headscale", "mockoidc"]).unwrap();
        assert!(matches!(parsed.command, Commands::Mockoidc));
    }

    #[test]
    fn standalone_cli_accepts_upstream_debug_create_node_command() {
        let parsed = Cli::try_parse_from([
            "headscale",
            "debug",
            "create-node",
            "--name",
            "node-one",
            "--user",
            "alice",
            "--key",
            "abcdefghijklmnopqrstuvwx",
        ])
        .unwrap();

        assert!(matches!(
            parsed.command,
            Commands::Debug {
                action: DebugCmd::CreateNode { .. }
            }
        ));
    }

    #[test]
    fn standalone_cli_accepts_upstream_generate_private_key_command() {
        let parsed = Cli::try_parse_from(["headscale", "generate", "private-key"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Generate {
                action: GenerateCmd::PrivateKey
            }
        ));

        let parsed = Cli::try_parse_from(["headscale", "gen", "private-key"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Generate {
                action: GenerateCmd::PrivateKey
            }
        ));
    }

    #[test]
    fn standalone_cli_accepts_upstream_version_and_configtest_commands() {
        let parsed = Cli::try_parse_from(["headscale", "version"]).unwrap();
        assert!(matches!(parsed.command, Commands::Version));

        let parsed = Cli::try_parse_from(["headscale", "configtest"]).unwrap();
        assert!(matches!(parsed.command, Commands::Configtest));

        let parsed = Cli::try_parse_from(["headscale", "dumpConfig"]).unwrap();
        assert!(matches!(parsed.command, Commands::DumpConfig));
    }

    #[test]
    fn standalone_cli_accepts_upstream_completion_commands() {
        let parsed = Cli::try_parse_from(["headscale", "completion", "bash"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Completion {
                shell: CompletionShell::Bash {
                    no_descriptions: false
                }
            }
        ));

        let parsed =
            Cli::try_parse_from(["headscale", "completion", "zsh", "--no-descriptions"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Completion {
                shell: CompletionShell::Zsh {
                    no_descriptions: true
                }
            }
        ));

        let parsed = Cli::try_parse_from(["headscale", "completion", "powershell"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Completion {
                shell: CompletionShell::Powershell { .. }
            }
        ));
    }

    #[test]
    fn version_output_matches_rust_runtime_shape() {
        let version = VersionInfo::current();

        assert_eq!(version.version, env!("CARGO_PKG_VERSION"));
        assert!(!version.commit.is_empty());
        assert!(!version.build_time.is_empty());
        assert_eq!(version.rust.os, std::env::consts::OS);
        assert!(version.human().contains("headscale-rs version"));
    }

    #[test]
    fn configtest_requires_loaded_config() {
        assert!(configtest(None).is_err());
        assert!(configtest(Some(&CliConfig::default())).is_err());

        let config = CliConfig {
            server: Some(ServerConfig {
                server_url: Some("https://headscale.example".into()),
                ..ServerConfig::default()
            }),
            dns: Some(headscale_api::dns::DnsConfigSpec {
                magic_dns: false,
                ..Default::default()
            }),
            ..CliConfig::default()
        };
        assert!(configtest(Some(&config)).is_ok());
    }

    #[test]
    fn generated_private_key_matches_tailscale_machine_key_shape() {
        let key = generate_machine_private_key();

        assert_eq!(key.len(), "privkey:".len() + 64);
        assert!(key.starts_with("privkey:"));
        let raw = hex::decode(&key["privkey:".len()..]).unwrap();
        assert_eq!(raw.len(), 32);
        assert_eq!(raw[0] & 7, 0);
        assert_eq!(raw[31] & 0x80, 0);
        assert_eq!(raw[31] & 0x40, 0x40);
    }

    #[test]
    fn dump_config_to_writes_yaml_config() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.dump.yaml");
        let config = CliConfig {
            server: Some(ServerConfig {
                server_url: Some("https://headscale.example".into()),
                ..ServerConfig::default()
            }),
            ..CliConfig::default()
        };

        dump_config_to(&config, &path).unwrap();

        let written = std::fs::read_to_string(path).unwrap();
        assert!(written.contains("server_url: https://headscale.example"));
    }

    #[test]
    fn admin_connect_args_merge_upstream_cli_config() {
        let connect = ConnectArgs {
            server: None,
            token: None,
            address: None,
            api_key: None,
            unix_socket: None,
            insecure: false,
            json: false,
            output: None,
            force: false,
        };
        let config = CliConfig {
            cli: Some(config::AdminCliConfig {
                address: Some("headscale.example:50443".into()),
                api_key: Some("hskey-api-abcdefghijkl-secret".into()),
                insecure: Some(true),
            }),
            unix_socket: Some(PathBuf::from("/run/headscale/admin.sock")),
            ..CliConfig::default()
        };

        let merged = merged_connect_args(&connect, Some(&config));

        assert_eq!(merged.address.as_deref(), Some("headscale.example:50443"));
        assert_eq!(
            merged.api_key.as_deref(),
            Some("hskey-api-abcdefghijkl-secret")
        );
        assert!(merged.insecure);
        assert_eq!(
            merged.unix_socket.as_deref(),
            Some(PathBuf::from("/run/headscale/admin.sock").as_path())
        );
    }

    #[test]
    fn explicit_cli_flags_override_config_connect_args() {
        let connect = ConnectArgs {
            server: None,
            token: None,
            address: Some("flag.example:50443".into()),
            api_key: Some("flag-key".into()),
            unix_socket: Some(PathBuf::from("/tmp/flag.sock")),
            insecure: true,
            json: false,
            output: None,
            force: false,
        };
        let config = CliConfig {
            cli: Some(config::AdminCliConfig {
                address: Some("config.example:50443".into()),
                api_key: Some("config-key".into()),
                insecure: Some(false),
            }),
            unix_socket: Some(PathBuf::from("/tmp/config.sock")),
            ..CliConfig::default()
        };

        let merged = merged_connect_args(&connect, Some(&config));

        assert_eq!(merged.address.as_deref(), Some("flag.example:50443"));
        assert_eq!(merged.api_key.as_deref(), Some("flag-key"));
        assert_eq!(
            merged.unix_socket.as_deref(),
            Some(PathBuf::from("/tmp/flag.sock").as_path())
        );
        assert!(merged.insecure);
    }
}
