//! Headscale-rs CLI
//!
//! Command-line interface for running headscale mesh nodes and control planes.
//! The admin subcommands (`users`, `nodes`, `auth`, `preauthkeys`, `policy`,
//! `apikeys`) are being migrated to the upstream gRPC admin API. Migrated
//! groups default to the local Unix socket; unmigrated groups still use the
//! legacy `/api/v1/*` GUI surface.

// Keep compatibility with downstream toolchains that predate
// Duration::from_mins/from_hours while newer clippy versions prefer them.
#![allow(unknown_lints, clippy::duration_suboptimal_units)]

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{CommandFactory, Parser, Subcommand};
use rand_core::{OsRng, RngCore};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod acme_issuer;
mod config;
mod derp_config;
mod mockoidc;
mod node;
mod server;

use config::{CliConfig, ServerConfig};
use headscale_cli::admin::{
    self, AdminError, ApiKeysCmd, AuthCmd, ConnectArgs, DebugCmd, DirectPolicyDatabase, NodesCmd,
    OutputFormat, PolicyCmd, PreauthKeysCmd, UsersCmd,
};
use headscale_db::DatabaseBackend;

#[derive(Parser)]
#[command(name = "headscale")]
#[command(author, version)]
#[command(about = "headscale - a Tailscale control server")]
#[command(
    long_about = "headscale is an open source implementation of the Tailscale control server\n\nhttps://github.com/juanfont/headscale"
)]
#[command(disable_version_flag = true)]
struct Cli {
    /// config file (default is /etc/headscale/config.yaml).
    #[arg(
        short,
        long,
        env = "HEADSCALE_CONFIG",
        global = true,
        allow_hyphen_values = true
    )]
    config: Option<PathBuf>,

    /// Log level (trace, debug, info, warn, error).
    #[arg(
        long,
        default_value = "info",
        env = "HEADSCALE_LOG",
        global = true,
        hide = true
    )]
    log_level: String,

    #[command(flatten)]
    connect: ConnectArgs,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Launches the headscale server.
    #[command(name = "serve")]
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
        #[arg(hide = true)]
        _ignored_args: Vec<String>,
    },

    /// Run as a mesh node (connects to a control plane).
    #[command(name = "mesh-node", hide = true)]
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
    #[command(hide = true)]
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },

    // ----- Admin surface ----------------------------------------------------
    /// Manage the users of Headscale.
    #[command(alias = "user")]
    Users {
        #[command(subcommand)]
        action: UsersCmd,
    },
    /// Manage the nodes of Headscale.
    #[command(alias = "node")]
    Nodes {
        #[command(subcommand)]
        action: NodesCmd,
    },
    /// Handle the preauthkeys in Headscale.
    #[command(alias = "preauthkey", alias = "authkey", alias = "pre")]
    Preauthkeys {
        /// User identifier (ID). Upstream accepts this before `create`.
        #[arg(short = 'u', long, hide = true)]
        user: Option<u64>,
        #[command(subcommand)]
        action: PreauthKeysCmd,
    },
    /// Manage node authentication and approval.
    Auth {
        #[command(subcommand)]
        action: AuthCmd,
    },
    /// Handle the Api keys in Headscale.
    #[command(alias = "apikey", alias = "api")]
    Apikeys {
        #[command(subcommand)]
        action: ApiKeysCmd,
    },
    /// Manage the Headscale ACL Policy.
    Policy {
        #[command(subcommand)]
        action: PolicyCmd,
    },
    /// debug and testing commands.
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
    #[command(hide = true)]
    Status {
        /// Control plane URL (uses config if not provided).
        #[arg(long)]
        server: Option<String>,
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
    PrivateKey {
        #[arg(hide = true)]
        _ignored_args: Vec<String>,
    },
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
    let raw_args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if let Some(help) = upstream_exact_help(&raw_args) {
        print!("{help}");
        if let Some(stderr) = upstream_exact_help_stderr(&raw_args) {
            eprint!("{stderr}");
        }
        return ExitCode::SUCCESS;
    }
    if let Some(error) = upstream_exact_success_stderr(&raw_args) {
        eprint!("{error}");
        return ExitCode::SUCCESS;
    }
    if let Some(error) = upstream_exact_error(&raw_args) {
        eprint!("{error}");
        return ExitCode::from(1);
    }
    if upstream_version_invocation(&raw_args) {
        let fmt = output_format_from_raw_args(&raw_args);
        return match print_version(fmt) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprint!("{error:#}");
                ExitCode::from(1)
            }
        };
    }

    let skip_config_load = raw_args_skip_config_load(&raw_args);
    let error_output_format = output_format_from_raw_args(&raw_args);
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

    match Box::pin(dispatch(cli, skip_config_load)).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(MainError::Admin(e)) => {
            eprint!(
                "{}",
                admin::output::format_error(error_output_format, &e.to_string())
            );
            ExitCode::from(e.exit_code() as u8)
        }
        Err(MainError::Other(e)) => {
            eprint!(
                "{}",
                admin::output::format_error(error_output_format, &format!("{e:#}"))
            );
            ExitCode::from(1)
        }
    }
}

fn output_format_from_raw_args<S: AsRef<OsStr>>(raw_args: &[S]) -> OutputFormat {
    let mut fmt = OutputFormat::Table;
    let mut args = raw_args.iter();
    while let Some(arg) = args.next() {
        if arg.as_ref() == OsStr::new("--") {
            break;
        }
        let Some(arg) = arg.as_ref().to_str() else {
            continue;
        };
        match arg {
            "-o" | "--output" => {
                if let Some(value) = args.next().and_then(|value| value.as_ref().to_str()) {
                    fmt = raw_output_format(value);
                }
            }
            _ => {
                if let Some(value) = arg.strip_prefix("--output=") {
                    fmt = raw_output_format(value);
                } else if let Some(value) = arg.strip_prefix("-o").filter(|value| !value.is_empty())
                {
                    fmt = raw_output_format(value);
                }
            }
        }
    }
    fmt
}

fn raw_output_format(value: &str) -> OutputFormat {
    match value {
        "json" => OutputFormat::Json,
        "json-line" => OutputFormat::JsonLine,
        "yaml" => OutputFormat::Yaml,
        _ => OutputFormat::Table,
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

async fn dispatch(cli: Cli, skip_config_load: bool) -> Result<(), MainError> {
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
            _ignored_args: _,
        } => {
            if let Some(config) = config.as_ref() {
                config.validate_for_configtest().map_err(MainError::Other)?;
                print_config_warnings(config);
            }
            let server_config = config.as_ref().and_then(|c| c.server.as_ref());
            let defaults = ServerConfig::default();
            let node_expiry = config
                .as_ref()
                .and_then(|c| c.node.as_ref())
                .and_then(|node| node.expiry)
                .map(Duration::from_secs)
                .unwrap_or_default();
            let node_routes_ha_probe_interval = config
                .as_ref()
                .and_then(|c| c.node.as_ref())
                .and_then(|node| node.routes.ha.probe_interval)
                .map_or_else(|| Duration::from_secs(10), Duration::from_secs);
            let node_routes_ha_probe_timeout = config
                .as_ref()
                .and_then(|c| c.node.as_ref())
                .and_then(|node| node.routes.ha.probe_timeout)
                .map_or_else(|| Duration::from_secs(5), Duration::from_secs);
            let mut oidc = config
                .as_ref()
                .map_or_else(headscale_core::config::OidcConfig::default, |c| {
                    c.oidc.clone()
                });
            oidc.expiry = Duration::ZERO;
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
                trusted_proxies: config
                    .as_ref()
                    .map_or_else(Vec::new, |c| c.trusted_proxies.clone()),
                disable_check_updates: config.as_ref().is_some_and(|c| c.disable_check_updates),
                tls: server::TlsRuntimeConfig {
                    acme_url: config.as_ref().and_then(|c| c.acme_url.clone()),
                    acme_email: config.as_ref().and_then(|c| c.acme_email.clone()),
                    acme_ca_root_path: None,
                    letsencrypt_hostname: config
                        .as_ref()
                        .and_then(|c| c.tls_letsencrypt_hostname.clone()),
                    letsencrypt_cache_dir: config
                        .as_ref()
                        .and_then(|c| c.tls_letsencrypt_cache_dir.clone()),
                    letsencrypt_listen: config
                        .as_ref()
                        .and_then(|c| c.tls_letsencrypt_listen.clone()),
                    letsencrypt_challenge_type: config
                        .as_ref()
                        .and_then(|c| c.tls_letsencrypt_challenge_type.clone()),
                    cert_path: config.as_ref().and_then(|c| c.tls_cert_path.clone()),
                    key_path: config.as_ref().and_then(|c| c.tls_key_path.clone()),
                },
                oidc,
                node_expiry,
                node_routes_ha_probe_interval,
                node_routes_ha_probe_timeout,
                embedded_derp: server_config
                    .map_or(defaults.embedded_derp, |s| s.embedded_derp.clone()),
                derp: config.as_ref().and_then(|c| c.derp.clone()),
                database: config.as_ref().and_then(|c| c.database.clone()),
                dns: config.as_ref().and_then(|c| c.dns.clone()),
                policy: config
                    .as_ref()
                    .map_or_else(config::PolicyConfig::default, |c| c.policy.clone()),
                taildrop_enabled: config.as_ref().map_or_else(
                    || config::TaildropConfig::default().enabled,
                    |c| c.taildrop.enabled,
                ),
                logtail_enabled: config.as_ref().is_some_and(|c| c.logtail.enabled),
                auto_update_enabled: config.as_ref().is_some_and(|c| c.auto_update.enabled),
                tuning: config
                    .as_ref()
                    .map_or_else(config::TuningConfig::default, |c| c.tuning.clone()),
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
                .and_then(|n| {
                    let server = n.server.trim();
                    if server.is_empty() {
                        None
                    } else {
                        Some(n.server.clone())
                    }
                })
                .unwrap_or(server_url);
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
        Commands::Preauthkeys { user, action } => admin::run_preauthkeys(&connect, user, &action)
            .await
            .map_err(Into::into),
        Commands::Auth { action } => admin::run_auth(&connect, &action).await.map_err(Into::into),
        Commands::Apikeys { action } => admin::run_apikeys(&connect, &action)
            .await
            .map_err(Into::into),
        Commands::Policy { action } => admin::run_policy(&connect, &action)
            .await
            .map_err(Into::into),
        Commands::Debug { action } => admin::run_debug(&connect, &action)
            .await
            .map_err(Into::into),
        Commands::Generate { action } => match action {
            GenerateCmd::PrivateKey { .. } => {
                print_private_key(connect.fmt().map_err(MainError::Admin)?)
                    .map_err(MainError::Other)
            }
        },
        Commands::Mockoidc => mockoidc::run()
            .await
            .context("running mock OIDC server")
            .map_err(MainError::Other),
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
                config.as_ref().and_then(|c| c.node.as_ref()).and_then(|n| {
                    let server = n.server.trim();
                    if server.is_empty() {
                        None
                    } else {
                        Some(n.server.clone())
                    }
                })
            });
            check_status(server_url.as_deref())
                .await
                .map_err(MainError::Other)
        }
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
    if merged.timeout_secs.is_none() {
        merged.timeout_secs = cli_config
            .and_then(|cli| cli.timeout)
            .or(Some(config::default_cli_timeout_secs()));
    }
    if merged.unix_socket.is_none() {
        merged.unix_socket = config.unix_socket.clone().or_else(|| {
            config
                .server
                .as_ref()
                .map(|server| server.unix_socket.clone())
        });
    }
    if merged.direct_database.is_none() {
        merged.direct_database = Some(direct_policy_database_from_config(config));
    }

    merged
}

fn direct_policy_database_from_config(config: &CliConfig) -> DirectPolicyDatabase {
    match config
        .database
        .as_ref()
        .and_then(config::UpstreamDatabaseConfig::runtime_backend)
    {
        Some(DatabaseBackend::Postgres) => {
            let Some(database) = config.database.as_ref() else {
                return DirectPolicyDatabase::Unavailable {
                    reason: "direct database policy access for Postgres requires a database block"
                        .into(),
                };
            };
            direct_postgres_policy_database(database)
        }
        Some(DatabaseBackend::Sqlite) | None => DirectPolicyDatabase::Sqlite {
            path: config.server.as_ref().map_or_else(
                || ServerConfig::default().db_path,
                |server| server.db_path.clone(),
            ),
        },
    }
}

#[cfg(feature = "postgres-sqlx")]
fn direct_postgres_policy_database(
    database: &config::UpstreamDatabaseConfig,
) -> DirectPolicyDatabase {
    match postgres_url_from_config(database.debug_postgres()) {
        Ok(url) => DirectPolicyDatabase::Postgres { url },
        Err(err) => DirectPolicyDatabase::Unavailable {
            reason: format!("direct database policy access for Postgres: {err:#}"),
        },
    }
}

#[cfg(not(feature = "postgres-sqlx"))]
fn direct_postgres_policy_database(
    _database: &config::UpstreamDatabaseConfig,
) -> DirectPolicyDatabase {
    DirectPolicyDatabase::Unavailable {
        reason: "direct database policy access for Postgres requires the postgres-sqlx feature"
            .into(),
    }
}

#[cfg(feature = "postgres-sqlx")]
fn postgres_url_from_config(postgres: &config::UpstreamPostgresConfig) -> Result<String> {
    let host = non_empty_str(Some(postgres.host())).unwrap_or("localhost");
    let port = postgres_config_port(postgres).context("database.postgres.port out of range")?;
    let name = non_empty_str(Some(postgres.name())).unwrap_or("headscale");
    let mut url = url::Url::parse("postgres://localhost/headscale")
        .context("build default Postgres database URL")?;
    url.set_host(Some(host))
        .map_err(|err| anyhow::anyhow!("database.postgres.host {host:?} is invalid: {err}"))?;
    url.set_port(Some(port))
        .map_err(|()| anyhow::anyhow!("database.postgres.port {port} is invalid"))?;
    url.set_path(name);
    if let Some(user) = non_empty_str(Some(postgres.user())) {
        url.set_username(user)
            .map_err(|()| anyhow::anyhow!("database.postgres.user is invalid"))?;
    }
    if let Some(pass) = non_empty_str(Some(postgres.pass())) {
        url.set_password(Some(pass))
            .map_err(|()| anyhow::anyhow!("database.postgres.pass is invalid"))?;
    }
    if let Some(sslmode) = postgres_sslmode(postgres.ssl()) {
        url.query_pairs_mut().append_pair("sslmode", sslmode);
    }
    Ok(url.to_string())
}

#[cfg(feature = "postgres-sqlx")]
fn postgres_config_port(postgres: &config::UpstreamPostgresConfig) -> Result<u16> {
    let port = postgres.port();
    if port <= 0 {
        return Ok(5432);
    }
    u16::try_from(port).context("database.postgres.port must be between 1 and 65535")
}

#[cfg(feature = "postgres-sqlx")]
fn postgres_sslmode(value: &str) -> Option<&str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" => None,
        "false" | "disable" => Some("disable"),
        "true" | "require" => Some("require"),
        "allow" => Some("allow"),
        "prefer" => Some("prefer"),
        "verify-ca" => Some("verify-ca"),
        "verify-full" => Some("verify-full"),
        _ => Some(value.trim()),
    }
}

fn option_is_empty(value: Option<&String>) -> bool {
    value.is_none_or(|value| value.trim().is_empty())
}

fn non_empty_clone(value: Option<&String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty()).cloned()
}

#[cfg(feature = "postgres-sqlx")]
fn non_empty_str(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn raw_args_skip_config_load<I, S>(args: I) -> bool
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let first = args.into_iter().next();
    matches!(
        first.as_ref().and_then(|arg| arg.as_ref().to_str()),
        Some("version" | "mockoidc" | "completion")
    )
}

fn upstream_exact_help<S: AsRef<OsStr>>(args: &[S]) -> Option<&'static str> {
    let mut parts = Vec::with_capacity(args.len());
    for arg in args {
        parts.push(arg.as_ref().to_str()?);
    }

    upstream_known_help(parts.as_slice())
        .or_else(|| {
            let command_parts = upstream_exact_command_parts(parts.as_slice());
            (command_parts != parts.as_slice())
                .then(|| upstream_known_help(command_parts))
                .flatten()
        })
        .or_else(|| upstream_extra_help_topic(parts.as_slice()))
}

fn upstream_known_help(parts: &[&str]) -> Option<&'static str> {
    match parts {
        ["-h" | "--help" | "help"] => Some(UPSTREAM_TOP_LEVEL_HELP),
        ["serve", "-h" | "--help"] | ["help", "serve"] => Some(UPSTREAM_SERVE_HELP),
        ["serve", tail @ ..] if utility_help_tail(tail, UtilityFlagScope::Serve) => {
            Some(UPSTREAM_SERVE_HELP)
        }
        ["version", "-h" | "--help"] | ["help", "version"] => Some(UPSTREAM_VERSION_HELP),
        ["version", tail @ ..] if utility_help_tail(tail, UtilityFlagScope::Version) => {
            Some(UPSTREAM_VERSION_HELP)
        }
        ["health", "-h" | "--help"] | ["help", "health"] => Some(UPSTREAM_HEALTH_HELP),
        ["health", tail @ ..] if utility_help_tail(tail, UtilityFlagScope::GlobalConfig) => {
            Some(UPSTREAM_HEALTH_HELP)
        }
        ["configtest", "-h" | "--help"] | ["help", "configtest"] => Some(UPSTREAM_CONFIGTEST_HELP),
        ["configtest", tail @ ..] if utility_help_tail(tail, UtilityFlagScope::GlobalConfig) => {
            Some(UPSTREAM_CONFIGTEST_HELP)
        }
        ["dumpConfig", "-h" | "--help"] | ["help", "dumpConfig"] => Some(UPSTREAM_DUMP_CONFIG_HELP),
        ["dumpConfig", tail @ ..] if utility_help_tail(tail, UtilityFlagScope::GlobalConfig) => {
            Some(UPSTREAM_DUMP_CONFIG_HELP)
        }
        ["mockoidc", "-h" | "--help"] | ["help", "mockoidc"] => Some(UPSTREAM_MOCKOIDC_HELP),
        ["mockoidc", tail @ ..] if mockoidc_help_tail(tail) => Some(UPSTREAM_MOCKOIDC_HELP),
        ["completion", "-h" | "--help"] | ["help", "completion"] | ["completion"] => {
            Some(UPSTREAM_COMPLETION_HELP)
        }
        ["completion", "bash", tail @ ..] if completion_shell_help_tail(tail) => {
            Some(UPSTREAM_COMPLETION_BASH_HELP)
        }
        ["completion", "fish", tail @ ..] if completion_shell_help_tail(tail) => {
            Some(UPSTREAM_COMPLETION_FISH_HELP)
        }
        ["completion", "powershell", tail @ ..] if completion_shell_help_tail(tail) => {
            Some(UPSTREAM_COMPLETION_POWERSHELL_HELP)
        }
        ["completion", "zsh", tail @ ..] if completion_shell_help_tail(tail) => {
            Some(UPSTREAM_COMPLETION_ZSH_HELP)
        }
        ["help", "completion", "bash"] => Some(UPSTREAM_COMPLETION_BASH_HELP),
        ["help", "completion", "fish"] => Some(UPSTREAM_COMPLETION_FISH_HELP),
        ["help", "completion", "powershell"] => Some(UPSTREAM_COMPLETION_POWERSHELL_HELP),
        ["help", "completion", "zsh"] => Some(UPSTREAM_COMPLETION_ZSH_HELP),
        ["completion", shell, tail @ ..] if completion_unknown_shell_help_tail(shell, tail) => {
            Some(UPSTREAM_COMPLETION_HELP)
        }
        ["generate" | "gen", "-h" | "--help"]
        | ["help", "generate" | "gen"]
        | ["generate" | "gen"] => Some(UPSTREAM_GENERATE_HELP),
        ["generate" | "gen", subcommand, tail @ ..]
            if generate_group_help_tail(subcommand, tail) =>
        {
            Some(UPSTREAM_GENERATE_HELP)
        }
        ["generate" | "gen", "private-key", tail @ ..] if private_key_help_tail(tail) => {
            Some(UPSTREAM_GENERATE_PRIVATE_KEY_HELP)
        }
        ["help", "generate" | "gen", "private-key"] => Some(UPSTREAM_GENERATE_PRIVATE_KEY_HELP),
        ["debug", "-h" | "--help"] | ["help", "debug"] => Some(UPSTREAM_DEBUG_HELP),
        ["debug", "create-node", "-h" | "--help"] | ["help", "debug", "create-node"] => {
            Some(UPSTREAM_DEBUG_CREATE_NODE_HELP)
        }
        ["auth", "-h" | "--help"] | ["help", "auth"] => Some(UPSTREAM_AUTH_HELP),
        ["auth", subcommand] if unknown_auth_subcommand(subcommand) => Some(UPSTREAM_AUTH_HELP),
        ["auth", "register", "-h" | "--help"] | ["help", "auth", "register"] => {
            Some(UPSTREAM_AUTH_REGISTER_HELP)
        }
        ["auth", "approve", "-h" | "--help"] | ["help", "auth", "approve"] => {
            Some(UPSTREAM_AUTH_APPROVE_HELP)
        }
        ["auth", "reject", "-h" | "--help"] | ["help", "auth", "reject"] => {
            Some(UPSTREAM_AUTH_REJECT_HELP)
        }
        ["users" | "user", "-h" | "--help"] | ["help", "users" | "user"] => {
            Some(UPSTREAM_USERS_HELP)
        }
        ["users" | "user", subcommand] if unknown_users_subcommand(subcommand) => {
            Some(UPSTREAM_USERS_HELP)
        }
        ["users" | "user", "create" | "c" | "new", "-h" | "--help"]
        | ["help", "users" | "user", "create" | "c" | "new"] => Some(UPSTREAM_USERS_CREATE_HELP),
        ["users" | "user", "list" | "ls" | "show", "-h" | "--help"]
        | ["help", "users" | "user", "list" | "ls" | "show"] => Some(UPSTREAM_USERS_LIST_HELP),
        ["users" | "user", "rename" | "mv", "-h" | "--help"]
        | ["help", "users" | "user", "rename" | "mv"] => Some(UPSTREAM_USERS_RENAME_HELP),
        ["users" | "user", "destroy" | "delete", "-h" | "--help"]
        | ["help", "users" | "user", "destroy" | "delete"] => Some(UPSTREAM_USERS_DESTROY_HELP),
        ["nodes" | "node", "-h" | "--help"] | ["help", "nodes" | "node"] => {
            Some(UPSTREAM_NODES_HELP)
        }
        ["nodes" | "node", "list" | "ls" | "show", "-h" | "--help"]
        | ["help", "nodes" | "node", "list" | "ls" | "show"] => Some(UPSTREAM_NODES_LIST_HELP),
        ["nodes" | "node", "register", "-h" | "--help"]
        | ["help", "nodes" | "node", "register"] => Some(UPSTREAM_NODES_REGISTER_HELP),
        [
            "nodes" | "node",
            "list-routes" | "lsr" | "routes",
            "-h" | "--help",
        ]
        | ["help", "nodes" | "node", "list-routes" | "lsr" | "routes"] => {
            Some(UPSTREAM_NODES_LIST_ROUTES_HELP)
        }
        [
            "nodes" | "node",
            "expire" | "logout" | "exp" | "e",
            "-h" | "--help",
        ]
        | ["help", "nodes" | "node", "expire" | "logout" | "exp" | "e"] => {
            Some(UPSTREAM_NODES_EXPIRE_HELP)
        }
        ["nodes" | "node", "rename", "-h" | "--help"] | ["help", "nodes" | "node", "rename"] => {
            Some(UPSTREAM_NODES_RENAME_HELP)
        }
        ["nodes" | "node", "tag" | "tags" | "t", "-h" | "--help"]
        | ["help", "nodes" | "node", "tag" | "tags" | "t"] => Some(UPSTREAM_NODES_TAG_HELP),
        ["nodes" | "node", "approve-routes", "-h" | "--help"]
        | ["help", "nodes" | "node", "approve-routes"] => Some(UPSTREAM_NODES_APPROVE_ROUTES_HELP),
        ["nodes" | "node", "delete" | "del", "-h" | "--help"]
        | ["help", "nodes" | "node", "delete" | "del"] => Some(UPSTREAM_NODES_DELETE_HELP),
        ["nodes" | "node", "backfillips", "-h" | "--help"]
        | ["help", "nodes" | "node", "backfillips"] => Some(UPSTREAM_NODES_BACKFILLIPS_HELP),
        [
            "preauthkeys" | "preauthkey" | "authkey" | "pre",
            "-h" | "--help",
        ]
        | ["help", "preauthkeys" | "preauthkey" | "authkey" | "pre"] => {
            Some(UPSTREAM_PREAUTHKEYS_HELP)
        }
        [
            "preauthkeys" | "preauthkey" | "authkey" | "pre",
            "create" | "c" | "new",
            "-h" | "--help",
        ]
        | [
            "help",
            "preauthkeys" | "preauthkey" | "authkey" | "pre",
            "create" | "c" | "new",
        ] => Some(UPSTREAM_PREAUTHKEYS_CREATE_HELP),
        [
            "preauthkeys" | "preauthkey" | "authkey" | "pre",
            "list" | "ls" | "show",
            "-h" | "--help",
        ]
        | [
            "help",
            "preauthkeys" | "preauthkey" | "authkey" | "pre",
            "list" | "ls" | "show",
        ] => Some(UPSTREAM_PREAUTHKEYS_LIST_HELP),
        [
            "preauthkeys" | "preauthkey" | "authkey" | "pre",
            "expire" | "revoke" | "exp" | "e",
            "-h" | "--help",
        ]
        | [
            "help",
            "preauthkeys" | "preauthkey" | "authkey" | "pre",
            "expire" | "revoke" | "exp" | "e",
        ] => Some(UPSTREAM_PREAUTHKEYS_EXPIRE_HELP),
        [
            "preauthkeys" | "preauthkey" | "authkey" | "pre",
            "delete" | "del" | "rm" | "d",
            "-h" | "--help",
        ]
        | [
            "help",
            "preauthkeys" | "preauthkey" | "authkey" | "pre",
            "delete" | "del" | "rm" | "d",
        ] => Some(UPSTREAM_PREAUTHKEYS_DELETE_HELP),
        ["apikeys" | "apikey" | "api", "-h" | "--help"]
        | ["help", "apikeys" | "apikey" | "api"] => Some(UPSTREAM_APIKEYS_HELP),
        [
            "apikeys" | "apikey" | "api",
            "create" | "c" | "new",
            "-h" | "--help",
        ]
        | ["help", "apikeys" | "apikey" | "api", "create" | "c" | "new"] => {
            Some(UPSTREAM_APIKEYS_CREATE_HELP)
        }
        [
            "apikeys" | "apikey" | "api",
            "list" | "ls" | "show",
            "-h" | "--help",
        ]
        | ["help", "apikeys" | "apikey" | "api", "list" | "ls" | "show"] => {
            Some(UPSTREAM_APIKEYS_LIST_HELP)
        }
        [
            "apikeys" | "apikey" | "api",
            "expire" | "revoke" | "exp" | "e",
            "-h" | "--help",
        ]
        | [
            "help",
            "apikeys" | "apikey" | "api",
            "expire" | "revoke" | "exp" | "e",
        ] => Some(UPSTREAM_APIKEYS_EXPIRE_HELP),
        [
            "apikeys" | "apikey" | "api",
            "delete" | "remove" | "del",
            "-h" | "--help",
        ]
        | [
            "help",
            "apikeys" | "apikey" | "api",
            "delete" | "remove" | "del",
        ] => Some(UPSTREAM_APIKEYS_DELETE_HELP),
        ["policy", "-h" | "--help"] | ["help", "policy"] => Some(UPSTREAM_POLICY_HELP),
        ["policy", subcommand] if unknown_policy_subcommand(subcommand) => {
            Some(UPSTREAM_POLICY_HELP)
        }
        ["policy", "get" | "show" | "view" | "fetch", "-h" | "--help"]
        | ["help", "policy", "get" | "show" | "view" | "fetch"] => Some(UPSTREAM_POLICY_GET_HELP),
        ["policy", "set" | "put" | "update", "-h" | "--help"]
        | ["help", "policy", "set" | "put" | "update"] => Some(UPSTREAM_POLICY_SET_HELP),
        ["policy", "check", "-h" | "--help"] | ["help", "policy", "check"] => {
            Some(UPSTREAM_POLICY_CHECK_HELP)
        }
        _ => None,
    }
}

fn upstream_extra_help_topic(parts: &[&str]) -> Option<&'static str> {
    let ["help", topic @ ..] = parts else {
        return None;
    };
    if topic.len() < 2 || topic.iter().any(|arg| matches!(*arg, "-h" | "--help")) {
        return None;
    }

    for end in (2..parts.len()).rev() {
        if let Some(help) = upstream_known_help(&parts[..end]) {
            return Some(help);
        }
    }
    None
}

fn upstream_exact_success_stderr<S: AsRef<OsStr>>(args: &[S]) -> Option<String> {
    let mut parts = Vec::with_capacity(args.len());
    for arg in args {
        parts.push(arg.as_ref().to_str()?);
    }

    match parts.as_slice() {
        ["help", topic] if !topic.starts_with('-') => Some(format!(
            "Unknown help topic [`{topic}`]\n{UPSTREAM_TOP_LEVEL_HELP_TOPIC_USAGE}"
        )),
        _ => None,
    }
}

fn upstream_exact_help_stderr<S: AsRef<OsStr>>(args: &[S]) -> Option<&'static str> {
    let mut parts = Vec::with_capacity(args.len());
    for arg in args {
        parts.push(arg.as_ref().to_str()?);
    }

    match parts.as_slice() {
        ["nodes" | "node", "register", "-h" | "--help"] => Some(UPSTREAM_NODES_REGISTER_DEPRECATED),
        _ => None,
    }
}

fn unknown_auth_subcommand(subcommand: &str) -> bool {
    !subcommand.starts_with('-') && !matches!(subcommand, "register" | "approve" | "reject")
}

fn unknown_users_subcommand(subcommand: &str) -> bool {
    !subcommand.starts_with('-')
        && !matches!(
            subcommand,
            "create"
                | "c"
                | "new"
                | "list"
                | "ls"
                | "show"
                | "rename"
                | "mv"
                | "destroy"
                | "delete"
        )
}

fn unknown_policy_subcommand(subcommand: &str) -> bool {
    !subcommand.starts_with('-')
        && !matches!(
            subcommand,
            "get" | "show" | "view" | "fetch" | "set" | "put" | "update" | "check"
        )
}

fn upstream_exact_error<S: AsRef<OsStr>>(args: &[S]) -> Option<String> {
    let mut parts = Vec::with_capacity(args.len());
    for arg in args {
        parts.push(arg.as_ref().to_str()?);
    }
    let output_format = output_format_from_raw_args(args);

    if parts
        .iter()
        .any(|part| *part == "--json" || part.starts_with("--json="))
    {
        if parts
            .first()
            .is_some_and(|part| *part == "--json" || part.starts_with("--json="))
        {
            return Some(format!(
                "{UPSTREAM_TOP_LEVEL_USAGE}\nError: unknown flag: --json\n"
            ));
        }
        return Some("Error: unknown flag: --json\n".into());
    }

    if let Some(error) = upstream_top_level_unknown_flag(parts.as_slice()) {
        return Some(format!("{UPSTREAM_TOP_LEVEL_USAGE}\nError: {error}\n"));
    }

    if let Some(error) = upstream_unknown_utility_flag(parts.as_slice()) {
        return Some(admin::output::format_error(output_format, &error));
    }

    if let Some(error) = completion_shell_unknown_command_error(parts.as_slice()) {
        return Some(format!("Error: {error}\n"));
    }

    if let Some(error) = upstream_hidden_compatibility_alias_error(parts.as_slice()) {
        return Some(format!("Error: {error}\n"));
    }

    if let Some(error) = upstream_top_level_unknown_command_error(parts.as_slice()) {
        return Some(format!("Error: {error}\n"));
    }

    if let Some(error) = debug_create_node_namespace_flag_error(parts.as_slice()) {
        return Some(format!("Error: {error}\n"));
    }

    let command_parts = upstream_exact_command_parts(parts.as_slice());
    if let Some(error) = debug_create_node_required_flag_error(command_parts) {
        return Some(admin::output::format_error(output_format, &error));
    }

    if let Some(error) = nodes_register_required_flag_error(command_parts) {
        return Some(format!(
            "{UPSTREAM_NODES_REGISTER_DEPRECATED}{}",
            admin::output::format_error(output_format, &error)
        ));
    }

    if let Some(error) = preauthkeys_create_user_value_error(parts.as_slice()) {
        return Some(error);
    }

    if let Some(error) = auth_required_flag_error(command_parts) {
        return Some(admin::output::format_error(output_format, &error));
    }

    if let Some(error) = users_rename_required_flag_error(command_parts) {
        return Some(admin::output::format_error(output_format, &error));
    }

    if users_create_missing_name_error(command_parts) {
        return Some(admin::output::format_error(
            output_format,
            "missing parameters",
        ));
    }

    if let Some(error) = nodes_list_missing_user_error(command_parts) {
        return Some(format!("Error: {error}\n"));
    }

    if matches!(parts.first(), Some(&"server")) {
        return Some(UPSTREAM_SERVER_UNKNOWN_COMMAND.into());
    }

    let command_is_unknown = match parts.as_slice() {
        ["version", tail @ ..] if !tail.is_empty() && !version_tail_is_supported(tail) => true,
        ["health" | "configtest" | "dumpConfig", tail @ ..]
            if !tail.is_empty() && !tail_is_help_or_global_config(tail) =>
        {
            true
        }
        ["mockoidc", tail @ ..] if !tail.is_empty() && !tail_is_help(tail) => true,
        [
            "completion",
            "bash" | "fish" | "powershell" | "zsh",
            tail @ ..,
        ] if !tail.is_empty() && !completion_tail_is_supported(tail) => true,
        ["help", _, _, ..] => true,
        _ => false,
    };

    command_is_unknown.then(|| {
        format!(
            "Error: unknown command \"{}\" for \"headscale\"\n",
            parts.join(" ")
        )
    })
}

fn upstream_exact_command_parts<'a>(parts: &'a [&'a str]) -> &'a [&'a str] {
    &parts[upstream_exact_command_start_index(parts)..]
}

fn upstream_exact_command_start_index(parts: &[&str]) -> usize {
    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "--" => return i + 1,
            "-c" | "--config" | "-o" | "--output" | "--server" | "--token" | "--address"
            | "--api-key" | "--unix-socket" | "--log-level"
                if i + 1 < parts.len() =>
            {
                i += 2;
            }
            "--force" | "--insecure" => i += 1,
            value if is_global_bool_assignment(value) => i += 1,
            value
                if value.starts_with("--config=")
                    || value.starts_with("--output=")
                    || value.starts_with("--server=")
                    || value.starts_with("--token=")
                    || value.starts_with("--address=")
                    || value.starts_with("--api-key=")
                    || value.starts_with("--unix-socket=")
                    || value.starts_with("--log-level=")
                    || value.starts_with("-c") && value.len() > 2
                    || value.starts_with("-o") && value.len() > 2 =>
            {
                i += 1;
            }
            _ => return i,
        }
    }
    i
}

fn upstream_version_invocation<S: AsRef<OsStr>>(args: &[S]) -> bool {
    let mut parts = Vec::with_capacity(args.len());
    for arg in args {
        let Some(arg) = arg.as_ref().to_str() else {
            return false;
        };
        parts.push(arg);
    }
    if parts.first() != Some(&"version") {
        return false;
    }
    matches!(
        parts.as_slice(),
        ["version", tail @ ..] if version_tail_is_supported(tail)
    )
}

fn auth_required_flag_error(parts: &[&str]) -> Option<String> {
    let [
        "auth",
        command @ ("register" | "approve" | "reject"),
        tail @ ..,
    ] = parts
    else {
        return None;
    };

    let mut saw_auth_id = false;
    let mut saw_user = *command != "register";
    let mut i = 0;
    while i < tail.len() {
        match tail[i] {
            "--auth-id" if i + 1 < tail.len() => {
                saw_auth_id = true;
                i += 2;
            }
            "-h" | "--help" | "--auth-id" => return None,
            value if value.starts_with("--auth-id=") => {
                saw_auth_id = true;
                i += 1;
            }
            "--user" if *command == "register" && i + 1 < tail.len() => {
                saw_user = true;
                i += 2;
            }
            "--user" if *command == "register" => return None,
            value if *command == "register" && value.starts_with("--user=") => {
                saw_user = true;
                i += 1;
            }
            "-u" if *command == "register" && i + 1 < tail.len() => {
                saw_user = true;
                i += 2;
            }
            value if *command == "register" && value.starts_with("-u") && value.len() > 2 => {
                saw_user = true;
                i += 1;
            }
            "--force" => i += 1,
            value if is_global_bool_assignment(value) => i += 1,
            "-c" | "--config" | "-o" | "--output" if i + 1 < tail.len() => i += 2,
            value
                if value.starts_with("--config=")
                    || value.starts_with("--output=")
                    || value.starts_with("-c") && value.len() > 2
                    || value.starts_with("-o") && value.len() > 2 =>
            {
                i += 1;
            }
            value if value.starts_with('-') => return None,
            _ => i += 1,
        }
    }

    let mut missing = Vec::new();
    if !saw_auth_id {
        missing.push(r#""auth-id""#);
    }
    if !saw_user {
        missing.push(r#""user""#);
    }

    (!missing.is_empty()).then(|| format!("required flag(s) {} not set", missing.join(", ")))
}

fn debug_create_node_required_flag_error(parts: &[&str]) -> Option<String> {
    let ["debug", "create-node", tail @ ..] = parts else {
        return None;
    };

    let mut saw_name = false;
    let mut saw_user = false;
    let mut saw_key = false;
    let mut i = 0;
    while i < tail.len() {
        match tail[i] {
            "-h" | "--help" => return None,
            "--name" => {
                if i + 1 >= tail.len() {
                    return None;
                }
                saw_name = true;
                i += 2;
            }
            value if value.starts_with("--name=") => {
                saw_name = true;
                i += 1;
            }
            "-u" | "--user" => {
                if i + 1 >= tail.len() {
                    return None;
                }
                saw_user = true;
                i += 2;
            }
            value if value.starts_with("--user=") => {
                saw_user = true;
                i += 1;
            }
            value if value.starts_with("-u") && value.len() > 2 => {
                saw_user = true;
                i += 1;
            }
            "-k" | "--key" => {
                if i + 1 >= tail.len() {
                    return None;
                }
                saw_key = true;
                i += 2;
            }
            value if value.starts_with("--key=") => {
                saw_key = true;
                i += 1;
            }
            value if value.starts_with("-k") && value.len() > 2 => {
                saw_key = true;
                i += 1;
            }
            "-r" | "--route" | "-c" | "--config" | "-o" | "--output" => {
                if i + 1 >= tail.len() {
                    return None;
                }
                i += 2;
            }
            "--force" | "--insecure" => i += 1,
            value if is_global_bool_assignment(value) => i += 1,
            value
                if value.starts_with("--route=")
                    || value.starts_with("--config=")
                    || value.starts_with("--output=")
                    || value.starts_with("-r") && value.len() > 2
                    || value.starts_with("-c") && value.len() > 2
                    || value.starts_with("-o") && value.len() > 2 =>
            {
                i += 1;
            }
            value if value.starts_with('-') => return None,
            _ => i += 1,
        }
    }

    let mut missing = Vec::new();
    if !saw_name {
        missing.push(r#""name""#);
    }
    if !saw_user {
        missing.push(r#""user""#);
    }
    if !saw_key {
        missing.push(r#""key""#);
    }

    (!missing.is_empty()).then(|| format!("required flag(s) {} not set", missing.join(", ")))
}

fn nodes_register_required_flag_error(parts: &[&str]) -> Option<String> {
    let ["nodes" | "node", "register", tail @ ..] = parts else {
        return None;
    };

    let mut saw_user = false;
    let mut saw_key = false;
    let mut i = 0;
    while i < tail.len() {
        match tail[i] {
            "-h" | "--help" => return None,
            "-u" | "--user" => {
                if i + 1 >= tail.len() {
                    return None;
                }
                saw_user = true;
                i += 2;
            }
            value if value.starts_with("--user=") => {
                saw_user = true;
                i += 1;
            }
            value if value.starts_with("-u") && value.len() > 2 => {
                saw_user = true;
                i += 1;
            }
            "-k" | "--key" => {
                if i + 1 >= tail.len() {
                    return None;
                }
                saw_key = true;
                i += 2;
            }
            value if value.starts_with("--key=") => {
                saw_key = true;
                i += 1;
            }
            value if value.starts_with("-k") && value.len() > 2 => {
                saw_key = true;
                i += 1;
            }
            "-c" | "--config" | "-o" | "--output" if i + 1 < tail.len() => i += 2,
            "-c" | "--config" | "-o" | "--output" => return None,
            "--force" | "--insecure" => i += 1,
            value if is_global_bool_assignment(value) => i += 1,
            value
                if value.starts_with("--config=")
                    || value.starts_with("--output=")
                    || value.starts_with("-c") && value.len() > 2
                    || value.starts_with("-o") && value.len() > 2 =>
            {
                i += 1;
            }
            value if value.starts_with('-') => return None,
            _ => i += 1,
        }
    }

    let mut missing = Vec::new();
    if !saw_key {
        missing.push(r#""key""#);
    }
    if !saw_user {
        missing.push(r#""user""#);
    }

    (!missing.is_empty()).then(|| format!("required flag(s) {} not set", missing.join(", ")))
}

fn users_rename_required_flag_error(parts: &[&str]) -> Option<String> {
    let ["users" | "user", "rename" | "mv", tail @ ..] = parts else {
        return None;
    };

    let mut saw_new_name = false;
    let mut i = 0;
    while i < tail.len() {
        match tail[i] {
            "-h" | "--help" => return None,
            "-r" | "--new-name" => {
                if i + 1 >= tail.len() {
                    return None;
                }
                saw_new_name = true;
                i += 2;
            }
            value if value.starts_with("--new-name=") => {
                saw_new_name = true;
                i += 1;
            }
            value if value.starts_with("-r") && value.len() > 2 => {
                saw_new_name = true;
                i += 1;
            }
            "-i" | "--identifier" | "-n" | "--name" | "-c" | "--config" | "-o" | "--output"
                if i + 1 < tail.len() =>
            {
                i += 2;
            }
            "-i" | "--identifier" | "-n" | "--name" | "-c" | "--config" | "-o" | "--output" => {
                return None;
            }
            "--force" | "--insecure" => i += 1,
            value if is_global_bool_assignment(value) => i += 1,
            value
                if value.starts_with("--identifier=")
                    || value.starts_with("--name=")
                    || value.starts_with("--config=")
                    || value.starts_with("--output=")
                    || value.starts_with("-i") && value.len() > 2
                    || value.starts_with("-n") && value.len() > 2
                    || value.starts_with("-c") && value.len() > 2
                    || value.starts_with("-o") && value.len() > 2 =>
            {
                i += 1;
            }
            value if value.starts_with('-') => return None,
            _ => i += 1,
        }
    }

    (!saw_new_name).then(|| r#"required flag(s) "new-name" not set"#.to_string())
}

fn users_create_missing_name_error(parts: &[&str]) -> bool {
    let ["users" | "user", "create" | "c" | "new", tail @ ..] = parts else {
        return false;
    };

    let mut i = 0;
    while i < tail.len() {
        match tail[i] {
            "--" => return i + 1 >= tail.len(),
            "-d" | "--display-name" | "-e" | "--email" | "-p" | "--picture-url"
                if i + 1 < tail.len() =>
            {
                i += 2;
            }
            "-h" | "--help" | "-d" | "--display-name" | "-e" | "--email" | "-p"
            | "--picture-url" => return false,
            value
                if value.starts_with("--display-name=")
                    || value.starts_with("--email=")
                    || value.starts_with("--picture-url=")
                    || value.starts_with("-d") && value.len() > 2
                    || value.starts_with("-e") && value.len() > 2
                    || value.starts_with("-p") && value.len() > 2 =>
            {
                i += 1;
            }
            "--force" => i += 1,
            value if is_global_bool_assignment(value) => i += 1,
            "-c" | "--config" | "-o" | "--output" if i + 1 < tail.len() => i += 2,
            value
                if value.starts_with("--config=")
                    || value.starts_with("--output=")
                    || value.starts_with("-c") && value.len() > 2
                    || value.starts_with("-o") && value.len() > 2 =>
            {
                i += 1;
            }
            value if value.starts_with('-') => return false,
            _ => return false,
        }
    }

    true
}

fn preauthkeys_create_user_value_error(parts: &[&str]) -> Option<String> {
    let command_start = upstream_exact_command_start_index(parts);
    let command_parts = &parts[command_start..];
    let ["preauthkeys" | "preauthkey" | "authkey" | "pre", tail @ ..] = command_parts else {
        return None;
    };

    let mut output_format = output_format_from_raw_args(&parts[..command_start]);
    let create_index = tail
        .iter()
        .position(|part| matches!(*part, "create" | "c" | "new"))?;

    if let Some(error) =
        preauthkeys_create_user_value_error_in_tail(&tail[..create_index], &mut output_format)
    {
        return Some(error);
    }
    preauthkeys_create_user_value_error_in_tail(&tail[create_index + 1..], &mut output_format)
}

fn preauthkeys_create_user_value_error_in_tail(
    tail: &[&str],
    output_format: &mut OutputFormat,
) -> Option<String> {
    let mut i = 0;
    while i < tail.len() {
        match tail[i] {
            "--" => return None,
            "-u" | "--user" if i + 1 < tail.len() => {
                if let Some(error) = cobra_parse_uint_error(tail[i + 1]) {
                    return Some(admin::output::format_error(*output_format, &error));
                }
                i += 2;
            }
            "-u" | "--user" => {
                let error = cobra_missing_flag_value_error(tail[i]);
                return Some(admin::output::format_error(*output_format, &error));
            }
            value if value.starts_with("--user=") => {
                let value = value.strip_prefix("--user=").unwrap_or_default();
                if let Some(error) = cobra_parse_uint_error(value) {
                    return Some(admin::output::format_error(*output_format, &error));
                }
                i += 1;
            }
            value if value.starts_with("-u") && value.len() > 2 => {
                if let Some(error) = cobra_parse_uint_error(&value[2..]) {
                    return Some(admin::output::format_error(*output_format, &error));
                }
                i += 1;
            }
            "-e" | "--expiration" | "--tags" if i + 1 < tail.len() => i += 2,
            "-h" | "--help" | "-e" | "--expiration" | "--tags" => return None,
            "--reusable" | "--ephemeral" | "--force" | "--insecure" => i += 1,
            value if is_global_bool_assignment(value) => i += 1,
            "-o" | "--output" if i + 1 < tail.len() => {
                *output_format = raw_output_format(tail[i + 1]);
                i += 2;
            }
            value if value.starts_with("--output=") => {
                *output_format = raw_output_format(value.strip_prefix("--output=").unwrap_or(""));
                i += 1;
            }
            value if value.starts_with("-o") && value.len() > 2 => {
                *output_format = raw_output_format(&value[2..]);
                i += 1;
            }
            "-c" | "--config" | "-o" | "--output" | "--server" | "--token" | "--address"
            | "--api-key" | "--unix-socket" | "--log-level"
                if i + 1 < tail.len() =>
            {
                i += 2;
            }
            value
                if value.starts_with("--expiration=")
                    || value.starts_with("--tags=")
                    || value.starts_with("--config=")
                    || value.starts_with("--output=")
                    || value.starts_with("-e") && value.len() > 2
                    || value.starts_with("-c") && value.len() > 2
                    || value.starts_with("-o") && value.len() > 2 =>
            {
                i += 1;
            }
            _ => i += 1,
        }
    }

    None
}

fn cobra_parse_uint_error(value: &str) -> Option<String> {
    if value.parse::<u64>().is_ok() {
        return None;
    }
    let detail = if !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit()) {
        "value out of range"
    } else {
        "invalid syntax"
    };
    Some(format!(
        "invalid argument \"{value}\" for \"-u, --user\" flag: \
         strconv.ParseUint: parsing \"{value}\": {detail}"
    ))
}

fn nodes_list_missing_user_error(parts: &[&str]) -> Option<String> {
    let ["nodes" | "node", "list" | "ls" | "show", tail @ ..] = parts else {
        return None;
    };

    let mut i = 0;
    while i < tail.len() {
        match tail[i] {
            "--" => return None,
            "-u" | "--user" if i + 1 < tail.len() => i += 2,
            "-u" | "--user" => return Some(cobra_missing_flag_value_error(tail[i])),
            value if value.starts_with("--user=") || value.starts_with("-u") && value.len() > 2 => {
                i += 1;
            }
            "-h" | "--help" | "--force" | "--insecure" => i += 1,
            value if is_global_bool_assignment(value) => i += 1,
            "-c" | "--config" | "-o" | "--output" | "--server" | "--token" | "--address"
            | "--api-key" | "--unix-socket" | "--log-level"
                if i + 1 < tail.len() =>
            {
                i += 2;
            }
            value
                if value.starts_with("--config=")
                    || value.starts_with("--output=")
                    || value.starts_with("--server=")
                    || value.starts_with("--token=")
                    || value.starts_with("--address=")
                    || value.starts_with("--api-key=")
                    || value.starts_with("--unix-socket=")
                    || value.starts_with("--log-level=")
                    || value.starts_with("-c") && value.len() > 2
                    || value.starts_with("-o") && value.len() > 2 =>
            {
                i += 1;
            }
            _ => i += 1,
        }
    }

    None
}

fn upstream_top_level_unknown_flag(parts: &[&str]) -> Option<String> {
    let mut i = 0;
    while i < parts.len() {
        let arg = parts[i];
        if arg == "--" || !arg.starts_with('-') {
            return None;
        }

        match arg {
            "-h" | "--help" | "--force" | "--insecure" => {
                i += 1;
            }
            value if is_global_bool_assignment(value) => i += 1,
            "-c" | "--config" | "-o" | "--output" | "--server" | "--token" | "--address"
            | "--api-key" | "--unix-socket" | "--log-level"
                if i + 1 < parts.len() =>
            {
                i += 2;
            }
            "-c" | "--config" | "-o" | "--output" => {
                return Some(cobra_missing_flag_value_error(arg));
            }
            value
                if value.starts_with("--config=")
                    || value.starts_with("--output=")
                    || value.starts_with("--server=")
                    || value.starts_with("--token=")
                    || value.starts_with("--address=")
                    || value.starts_with("--api-key=")
                    || value.starts_with("--unix-socket=")
                    || value.starts_with("--log-level=")
                    || value.starts_with("-c") && value.len() > 2
                    || value.starts_with("-o") && value.len() > 2 =>
            {
                i += 1;
            }
            _ => return cobra_unknown_flag_error(arg),
        }
    }
    None
}

fn upstream_top_level_unknown_command_error(parts: &[&str]) -> Option<String> {
    let ["userz", tail @ ..] = parts else {
        return None;
    };
    (tail.is_empty() || tail_is_help(tail)).then(|| {
        "unknown command \"userz\" for \"headscale\"\n\nDid you mean this?\n\tusers\n".into()
    })
}

fn is_global_bool_assignment(arg: &str) -> bool {
    let Some((flag, value)) = arg.split_once('=') else {
        return false;
    };
    matches!(flag, "--force" | "--insecure") && is_cobra_bool_value(value)
}

fn is_cobra_bool_value(value: &str) -> bool {
    matches!(
        value,
        "1" | "0" | "t" | "T" | "true" | "True" | "TRUE" | "f" | "F" | "false" | "False" | "FALSE"
    )
}

fn cobra_unknown_flag_error(arg: &str) -> Option<String> {
    if arg.starts_with("--") {
        let flag = arg.split_once('=').map_or(arg, |(flag, _)| flag);
        Some(format!("unknown flag: {flag}"))
    } else {
        arg.strip_prefix('-')
            .and_then(|shorthand| shorthand.chars().next())
            .map(|flag| format!("unknown shorthand flag: '{flag}' in {arg}"))
    }
}

fn cobra_missing_flag_value_error(arg: &str) -> String {
    if arg.starts_with("--") {
        format!("flag needs an argument: {arg}")
    } else {
        let flag = arg.strip_prefix('-').and_then(|value| value.chars().next());
        match flag {
            Some(flag) => format!("flag needs an argument: '{flag}' in {arg}"),
            None => format!("flag needs an argument: {arg}"),
        }
    }
}

fn upstream_unknown_utility_flag(parts: &[&str]) -> Option<String> {
    match parts {
        ["version", tail @ ..] if !tail.is_empty() && !version_tail_is_supported(tail) => {
            first_unknown_flag(tail, UtilityFlagScope::Version)
        }
        ["health" | "configtest" | "dumpConfig", tail @ ..]
            if !tail.is_empty() && !tail_is_help_or_global_config(tail) =>
        {
            first_unknown_flag(tail, UtilityFlagScope::GlobalConfig)
        }
        ["mockoidc", tail @ ..] if !tail.is_empty() && !tail_is_help(tail) => {
            first_unknown_flag(tail, UtilityFlagScope::HelpOnly)
        }
        ["serve", tail @ ..] if !tail.is_empty() && !tail_is_help_or_global_config(tail) => {
            first_unknown_flag(tail, UtilityFlagScope::Serve)
        }
        [
            "completion",
            "bash" | "fish" | "powershell" | "zsh",
            tail @ ..,
        ] if !tail.is_empty() && !completion_tail_is_supported(tail) => {
            first_unknown_flag(tail, UtilityFlagScope::CompletionShell)
        }
        ["completion", shell, ..]
            if !matches!(
                *shell,
                "bash" | "fish" | "powershell" | "zsh" | "-h" | "--help"
            ) =>
        {
            first_unknown_flag(&parts[1..], UtilityFlagScope::CompletionCommand)
        }
        ["generate" | "gen", tail @ ..] if !tail.is_empty() => {
            first_unknown_flag(tail, UtilityFlagScope::GenerateGroup)
        }
        _ => None,
    }
}

#[derive(Clone, Copy)]
enum UtilityFlagScope {
    Version,
    Serve,
    GenerateGroup,
    GlobalConfig,
    CompletionCommand,
    CompletionShell,
    HelpOnly,
}

fn first_unknown_flag(tail: &[&str], scope: UtilityFlagScope) -> Option<String> {
    let mut i = 0;
    while i < tail.len() {
        let arg = tail[i];
        match (scope, arg) {
            (UtilityFlagScope::GenerateGroup, "--") => return None,
            (_, "-h" | "--help")
            | (
                UtilityFlagScope::Serve
                | UtilityFlagScope::GenerateGroup
                | UtilityFlagScope::GlobalConfig,
                "--force",
            )
            | (UtilityFlagScope::CompletionShell, "--" | "--no-descriptions") => {
                i += 1;
                continue;
            }
            (
                UtilityFlagScope::Serve
                | UtilityFlagScope::GenerateGroup
                | UtilityFlagScope::GlobalConfig,
                value,
            ) if is_global_bool_assignment(value) => {
                i += 1;
                continue;
            }
            (
                UtilityFlagScope::Version
                | UtilityFlagScope::Serve
                | UtilityFlagScope::GenerateGroup
                | UtilityFlagScope::GlobalConfig,
                "-o" | "--output",
            ) if i + 1 < tail.len() => {
                i += 2;
                continue;
            }
            (
                UtilityFlagScope::Version
                | UtilityFlagScope::Serve
                | UtilityFlagScope::GenerateGroup
                | UtilityFlagScope::GlobalConfig,
                "-o" | "--output",
            ) => {
                return Some(cobra_missing_flag_value_error(arg));
            }
            (
                UtilityFlagScope::Version
                | UtilityFlagScope::Serve
                | UtilityFlagScope::GenerateGroup
                | UtilityFlagScope::GlobalConfig,
                value,
            ) if value.starts_with("--output=") => {
                i += 1;
                continue;
            }
            (
                UtilityFlagScope::Version
                | UtilityFlagScope::Serve
                | UtilityFlagScope::GenerateGroup
                | UtilityFlagScope::GlobalConfig,
                value,
            ) if value.starts_with("-o") && value.len() > 2 => {
                i += 1;
                continue;
            }
            (
                UtilityFlagScope::Serve
                | UtilityFlagScope::GenerateGroup
                | UtilityFlagScope::GlobalConfig,
                "-c" | "--config",
            ) if i + 1 < tail.len() => {
                i += 2;
                continue;
            }
            (
                UtilityFlagScope::Serve
                | UtilityFlagScope::GenerateGroup
                | UtilityFlagScope::GlobalConfig,
                "-c" | "--config",
            ) => {
                return Some(cobra_missing_flag_value_error(arg));
            }
            (
                UtilityFlagScope::Serve
                | UtilityFlagScope::GenerateGroup
                | UtilityFlagScope::GlobalConfig,
                value,
            ) if value.starts_with("--config=") => {
                i += 1;
                continue;
            }
            _ => {}
        }

        if arg.starts_with("--") {
            return Some(format!("unknown flag: {arg}"));
        } else if let Some(shorthand) = arg.strip_prefix('-') {
            return shorthand
                .chars()
                .next()
                .map(|flag| format!("unknown shorthand flag: '{flag}' in {arg}"));
        }
        i += 1;
    }
    None
}

fn tail_is_help(tail: &[&str]) -> bool {
    matches!(tail, ["-h" | "--help"])
}

fn completion_shell_help_tail(tail: &[&str]) -> bool {
    !tail.is_empty()
        && tail.iter().any(|arg| matches!(*arg, "-h" | "--help"))
        && first_unknown_flag(tail, UtilityFlagScope::CompletionShell).is_none()
}

fn completion_unknown_shell_help_tail(shell: &str, tail: &[&str]) -> bool {
    !matches!(
        shell,
        "bash" | "fish" | "powershell" | "zsh" | "-h" | "--help"
    ) && !shell.starts_with('-')
        && first_unknown_flag(tail, UtilityFlagScope::CompletionCommand).is_none()
}

fn generate_group_help_tail(subcommand: &str, tail: &[&str]) -> bool {
    !matches!(subcommand, "private-key" | "-h" | "--help")
        && first_unknown_flag(
            std::iter::once(subcommand)
                .chain(tail.iter().copied())
                .collect::<Vec<_>>()
                .as_slice(),
            UtilityFlagScope::GenerateGroup,
        )
        .is_none()
}

fn private_key_help_tail(tail: &[&str]) -> bool {
    !tail.is_empty()
        && tail_has_unconsumed_help(tail, UtilityFlagScope::GenerateGroup)
        && first_unknown_flag(tail, UtilityFlagScope::GenerateGroup).is_none()
}

fn utility_help_tail(tail: &[&str], scope: UtilityFlagScope) -> bool {
    !tail.is_empty()
        && tail_has_unconsumed_help(tail, scope)
        && first_unknown_flag(tail, scope).is_none()
}

fn tail_has_unconsumed_help(tail: &[&str], scope: UtilityFlagScope) -> bool {
    let mut i = 0;
    while i < tail.len() {
        match (scope, tail[i]) {
            (_, "--") => return false,
            (_, "-h" | "--help") => return true,
            (
                UtilityFlagScope::Serve
                | UtilityFlagScope::GenerateGroup
                | UtilityFlagScope::GlobalConfig,
                value,
            ) if is_global_bool_assignment(value) => i += 1,
            (
                UtilityFlagScope::Version
                | UtilityFlagScope::Serve
                | UtilityFlagScope::GenerateGroup
                | UtilityFlagScope::GlobalConfig,
                "-o" | "--output",
            )
            | (
                UtilityFlagScope::Serve
                | UtilityFlagScope::GenerateGroup
                | UtilityFlagScope::GlobalConfig,
                "-c" | "--config",
            ) if i + 1 < tail.len() => i += 2,
            _ => i += 1,
        }
    }
    false
}

fn mockoidc_help_tail(tail: &[&str]) -> bool {
    utility_help_tail(tail, UtilityFlagScope::HelpOnly)
}

fn tail_is_help_or_global_config(tail: &[&str]) -> bool {
    if tail.is_empty() {
        return false;
    }
    if tail_is_help(tail) {
        return true;
    }

    let mut i = 0;
    while i < tail.len() {
        match tail[i] {
            "--force" => i += 1,
            value if is_global_bool_assignment(value) => i += 1,
            "-c" | "--config" | "-o" | "--output" if i + 1 < tail.len() => i += 2,
            value
                if value.starts_with("--config=")
                    || value.starts_with("--output=")
                    || value.starts_with("-c") && value.len() > 2
                    || value.starts_with("-o") && value.len() > 2 =>
            {
                i += 1;
            }
            _ => return false,
        }
    }
    true
}

fn completion_tail_is_supported(tail: &[&str]) -> bool {
    tail_is_help(tail)
        || tail
            .iter()
            .all(|arg| matches!(*arg, "--" | "--no-descriptions"))
}

fn version_tail_is_supported(tail: &[&str]) -> bool {
    let mut i = 0;
    while i < tail.len() {
        match tail[i] {
            "--" => return true,
            "-h" | "--help" => i += 1,
            "-o" | "--output" if i + 1 < tail.len() => i += 2,
            "-o" | "--output" => return false,
            value if value.starts_with("--output=") => i += 1,
            value if value.starts_with("-o") && value.len() > 2 => i += 1,
            value if value.starts_with('-') => return false,
            _ => i += 1,
        }
    }
    true
}

fn completion_shell_unknown_command_error(parts: &[&str]) -> Option<String> {
    let [
        "completion",
        shell @ ("bash" | "fish" | "powershell" | "zsh"),
        tail @ ..,
    ] = parts
    else {
        return None;
    };
    if tail.is_empty() || completion_tail_is_supported(tail) {
        return None;
    }
    tail.iter()
        .find(|arg| !arg.starts_with('-'))
        .map(|command| {
            format!("unknown command \"{command}\" for \"headscale completion {shell}\"")
        })
}

fn upstream_hidden_compatibility_alias_error(parts: &[&str]) -> Option<String> {
    let command = *parts.first()?;
    matches!(
        command,
        "namespace" | "namespaces" | "ns" | "machine" | "machines" | "tailnet" | "init-config"
    )
    .then(|| format!("unknown command \"{command}\" for \"headscale\""))
}

fn debug_create_node_namespace_flag_error(parts: &[&str]) -> Option<String> {
    let ["debug", "create-node", tail @ ..] = parts else {
        return None;
    };
    let mut i = 0;
    while i < tail.len() {
        match tail[i] {
            "--" => return None,
            "--namespace" => return Some("unknown flag: --namespace".into()),
            value if value.starts_with("--namespace=") => {
                return Some("unknown flag: --namespace".into());
            }
            "-n" => return Some("unknown shorthand flag: 'n' in -n".into()),
            value if value.starts_with("-n") && value.len() > 2 => {
                return Some(format!("unknown shorthand flag: 'n' in {value}"));
            }
            "-u" | "--user" | "-k" | "--key" | "--name" | "-r" | "--route" | "-o" | "--output"
            | "-c" | "--config"
                if i + 1 < tail.len() =>
            {
                i += 2;
            }
            _ => {
                i += 1;
            }
        }
    }
    None
}

// Current upstream headscale main (4483fd0) Cobra help. Keep these explicit
// because Clap's formatter cannot reproduce Cobra output exactly.
const UPSTREAM_TOP_LEVEL_HELP: &str = r#"
headscale is an open source implementation of the Tailscale control server

https://github.com/juanfont/headscale

Usage:
  headscale [command]

Available Commands:
  apikeys     Handle the Api keys in Headscale
  auth        Manage node authentication and approval
  completion  Generate the autocompletion script for the specified shell
  configtest  Test the configuration.
  debug       debug and testing commands
  generate    Generate commands
  health      Check the health of the Headscale server
  help        Help about any command
  mockoidc    Runs a mock OIDC server for testing
  nodes       Manage the nodes of Headscale
  policy      Manage the Headscale ACL Policy
  preauthkeys Handle the preauthkeys in Headscale
  serve       Launches the headscale server
  users       Manage the users of Headscale
  version     Print the version.

Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -h, --help            help for headscale
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'

Use "headscale [command] --help" for more information about a command.
"#;

const UPSTREAM_TOP_LEVEL_USAGE: &str = r#"Usage:
  headscale [command]

Available Commands:
  apikeys     Handle the Api keys in Headscale
  auth        Manage node authentication and approval
  completion  Generate the autocompletion script for the specified shell
  configtest  Test the configuration.
  debug       debug and testing commands
  generate    Generate commands
  health      Check the health of the Headscale server
  help        Help about any command
  mockoidc    Runs a mock OIDC server for testing
  nodes       Manage the nodes of Headscale
  policy      Manage the Headscale ACL Policy
  preauthkeys Handle the preauthkeys in Headscale
  serve       Launches the headscale server
  users       Manage the users of Headscale
  version     Print the version.

Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -h, --help            help for headscale
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'

Use "headscale [command] --help" for more information about a command.
"#;

const UPSTREAM_TOP_LEVEL_HELP_TOPIC_USAGE: &str = r#"Usage:
  headscale [command]

Available Commands:
  apikeys     Handle the Api keys in Headscale
  auth        Manage node authentication and approval
  completion  Generate the autocompletion script for the specified shell
  configtest  Test the configuration.
  debug       debug and testing commands
  generate    Generate commands
  health      Check the health of the Headscale server
  help        Help about any command
  mockoidc    Runs a mock OIDC server for testing
  nodes       Manage the nodes of Headscale
  policy      Manage the Headscale ACL Policy
  preauthkeys Handle the preauthkeys in Headscale
  serve       Launches the headscale server
  users       Manage the users of Headscale
  version     Print the version.

Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'

Use "headscale [command] --help" for more information about a command.
"#;

const UPSTREAM_VERSION_HELP: &str = r"The version of headscale.

Usage:
  headscale version [flags]

Flags:
  -h, --help            help for version
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_SERVE_HELP: &str = r"Launches the headscale server

Usage:
  headscale serve [flags]

Flags:
  -h, --help   help for serve

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_SERVER_UNKNOWN_COMMAND: &str =
    "Error: unknown command \"server\" for \"headscale\"\n\nDid you mean this?\n\tserve\n\n";

const UPSTREAM_HEALTH_HELP: &str = r"Check the health of the Headscale server. This command will return an exit code of 0 if the server is healthy, or 1 if it is not.

Usage:
  headscale health [flags]

Flags:
  -h, --help   help for health

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_CONFIGTEST_HELP: &str = r"Run a test of the configuration and exit.

Usage:
  headscale configtest [flags]

Flags:
  -h, --help   help for configtest

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_DUMP_CONFIG_HELP: &str = r"dump current config to /etc/headscale/config.dump.yaml, integration test only

Usage:
  headscale dumpConfig [flags]

Flags:
  -h, --help   help for dumpConfig

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_MOCKOIDC_HELP: &str = r"This internal command runs a OpenID Connect for testing purposes

Usage:
  headscale mockoidc [flags]

Flags:
  -h, --help   help for mockoidc
";

const UPSTREAM_COMPLETION_HELP: &str = r#"Generate the autocompletion script for headscale for the specified shell.
See each sub-command's help for details on how to use the generated script.

Usage:
  headscale completion [command]

Available Commands:
  bash        Generate the autocompletion script for bash
  fish        Generate the autocompletion script for fish
  powershell  Generate the autocompletion script for powershell
  zsh         Generate the autocompletion script for zsh

Flags:
  -h, --help   help for completion

Use "headscale completion [command] --help" for more information about a command.
"#;

const UPSTREAM_COMPLETION_BASH_HELP: &str = r"Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(headscale completion bash)

To load completions for every new session, execute once:

#### Linux:

	headscale completion bash > /etc/bash_completion.d/headscale

#### macOS:

	headscale completion bash > $(brew --prefix)/etc/bash_completion.d/headscale

You will need to start a new shell for this setup to take effect.

Usage:
  headscale completion bash

Flags:
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
";

const UPSTREAM_COMPLETION_FISH_HELP: &str = r"Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	headscale completion fish | source

To load completions for every new session, execute once:

	headscale completion fish > ~/.config/fish/completions/headscale.fish

You will need to start a new shell for this setup to take effect.

Usage:
  headscale completion fish [flags]

Flags:
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
";

const UPSTREAM_COMPLETION_POWERSHELL_HELP: &str = r"Generate the autocompletion script for powershell.

To load completions in your current shell session:

	headscale completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.

Usage:
  headscale completion powershell [flags]

Flags:
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
";

const UPSTREAM_COMPLETION_ZSH_HELP: &str = r#"Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(headscale completion zsh)

To load completions for every new session, execute once:

#### Linux:

	headscale completion zsh > "${fpath[1]}/_headscale"

#### macOS:

	headscale completion zsh > $(brew --prefix)/share/zsh/site-functions/_headscale

You will need to start a new shell for this setup to take effect.

Usage:
  headscale completion zsh [flags]

Flags:
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
"#;

const UPSTREAM_GENERATE_HELP: &str = r#"Generate commands

Usage:
  headscale generate [command]

Aliases:
  generate, gen

Available Commands:
  private-key Generate a private key for the headscale server

Flags:
  -h, --help   help for generate

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'

Use "headscale generate [command] --help" for more information about a command.
"#;

const UPSTREAM_GENERATE_PRIVATE_KEY_HELP: &str = r"Generate a private key for the headscale server

Usage:
  headscale generate private-key [flags]

Flags:
  -h, --help   help for private-key

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_DEBUG_HELP: &str = r#"debug contains extra commands used for debugging and testing headscale

Usage:
  headscale debug [command]

Available Commands:
  create-node Create a node that can be registered with `auth register <>` command

Flags:
  -h, --help   help for debug

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'

Use "headscale debug [command] --help" for more information about a command.
"#;

const UPSTREAM_DEBUG_CREATE_NODE_HELP: &str = r"Create a node that can be registered with `auth register <>` command

Usage:
  headscale debug create-node [flags]

Flags:
  -h, --help            help for create-node
  -k, --key string      Key
      --name string     Name
  -r, --route strings   List (or repeated flags) of routes to advertise
  -u, --user string     User

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_AUTH_HELP: &str = r#"Manage node authentication and approval

Usage:
  headscale auth [command]

Available Commands:
  approve     Approve a pending authentication request
  register    Register a node to your network
  reject      Reject a pending authentication request

Flags:
  -h, --help   help for auth

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'

Use "headscale auth [command] --help" for more information about a command.
"#;

const UPSTREAM_AUTH_REGISTER_HELP: &str = r"Register a node to your network

Usage:
  headscale auth register [flags]

Flags:
      --auth-id string   Auth ID
  -h, --help             help for register
  -u, --user string      User

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_AUTH_APPROVE_HELP: &str = r"Approve a pending authentication request

Usage:
  headscale auth approve [flags]

Flags:
      --auth-id string   Auth ID
  -h, --help             help for approve

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_AUTH_REJECT_HELP: &str = r"Reject a pending authentication request

Usage:
  headscale auth reject [flags]

Flags:
      --auth-id string   Auth ID
  -h, --help             help for reject

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_USERS_HELP: &str = r#"Manage the users of Headscale

Usage:
  headscale users [command]

Aliases:
  users, user

Available Commands:
  create      Creates a new user
  destroy     Destroys a user
  list        List all the users
  rename      Renames a user

Flags:
  -h, --help   help for users

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'

Use "headscale users [command] --help" for more information about a command.
"#;

const UPSTREAM_USERS_CREATE_HELP: &str = r"Creates a new user

Usage:
  headscale users create NAME [flags]

Aliases:
  create, c, new

Flags:
  -d, --display-name string   Display name
  -e, --email string          Email
  -h, --help                  help for create
  -p, --picture-url string    Profile picture URL

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_USERS_LIST_HELP: &str = r"List all the users

Usage:
  headscale users list [flags]

Aliases:
  list, ls, show

Flags:
  -e, --email string     Email
  -h, --help             help for list
  -i, --identifier int   User identifier (ID) (default -1)
  -n, --name string      Username

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_USERS_RENAME_HELP: &str = r"Renames a user

Usage:
  headscale users rename [flags]

Aliases:
  rename, mv

Flags:
  -h, --help              help for rename
  -i, --identifier int    User identifier (ID) (default -1)
  -n, --name string       Username
  -r, --new-name string   New username

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_USERS_DESTROY_HELP: &str = r"Destroys a user

Usage:
  headscale users destroy --identifier ID or --name NAME [flags]

Aliases:
  destroy, delete

Flags:
  -h, --help             help for destroy
  -i, --identifier int   User identifier (ID) (default -1)
  -n, --name string      Username

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_NODES_HELP: &str = r#"Manage the nodes of Headscale

Usage:
  headscale nodes [command]

Aliases:
  nodes, node

Available Commands:
  approve-routes Manage the approved routes of a node
  backfillips    Backfill IPs missing from nodes
  delete         Delete a node
  expire         Expire (log out) a node in your network
  list           List nodes
  list-routes    List routes available on nodes
  rename         Renames a node in your network
  tag            Manage the tags of a node

Flags:
  -h, --help   help for nodes

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'

Use "headscale nodes [command] --help" for more information about a command.
"#;

const UPSTREAM_NODES_LIST_HELP: &str = r"List nodes

Usage:
  headscale nodes list [flags]

Aliases:
  list, ls, show

Flags:
  -h, --help          help for list
  -u, --user string   Filter by user

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_NODES_REGISTER_DEPRECATED: &str = "Command \"register\" is deprecated, use 'headscale auth register --auth-id <id> --user <user>' instead\n";

const UPSTREAM_NODES_REGISTER_HELP: &str = r"Registers a node to your network

Usage:
  headscale nodes register [flags]

Flags:
  -h, --help          help for register
  -k, --key string    Key
  -u, --user string   User

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_NODES_LIST_ROUTES_HELP: &str = r"List routes available on nodes

Usage:
  headscale nodes list-routes [flags]

Aliases:
  list-routes, lsr, routes

Flags:
  -h, --help              help for list-routes
  -i, --identifier uint   Node identifier (ID)

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_NODES_EXPIRE_HELP: &str = r"Expiring a node will keep the node in the database and force it to reauthenticate.

Use --disable to disable key expiry (node will never expire).

Usage:
  headscale nodes expire [flags]

Aliases:
  expire, logout, exp, e

Flags:
  -d, --disable           Disable key expiry (node will never expire)
  -e, --expiry string     Set expire to (RFC3339 format, e.g. 2025-08-27T10:00:00Z), or leave empty to expire immediately.
  -h, --help              help for expire
  -i, --identifier uint   Node identifier (ID)

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_NODES_RENAME_HELP: &str = r"Renames a node in your network

Usage:
  headscale nodes rename NEW_NAME [flags]

Flags:
  -h, --help              help for rename
  -i, --identifier uint   Node identifier (ID)

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_NODES_TAG_HELP: &str = r"Manage the tags of a node

Usage:
  headscale nodes tag [flags]

Aliases:
  tag, tags, t

Flags:
  -h, --help              help for tag
  -i, --identifier uint   Node identifier (ID)
  -t, --tags strings      List of tags to add to the node

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_NODES_APPROVE_ROUTES_HELP: &str = r#"Manage the approved routes of a node

Usage:
  headscale nodes approve-routes [flags]

Flags:
  -h, --help              help for approve-routes
  -i, --identifier uint   Node identifier (ID)
  -r, --routes strings    List of routes that will be approved (comma-separated, e.g. "10.0.0.0/8,192.168.0.0/24" or empty string to remove all approved routes)

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
"#;

const UPSTREAM_NODES_DELETE_HELP: &str = r"Delete a node

Usage:
  headscale nodes delete [flags]

Aliases:
  delete, del

Flags:
  -h, --help              help for delete
  -i, --identifier uint   Node identifier (ID)

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_NODES_BACKFILLIPS_HELP: &str = r"
Backfill IPs can be used to add/remove IPs from nodes
based on the current configuration of Headscale.

If there are nodes that does not have IPv4 or IPv6
even if prefixes for both are configured in the config,
this command can be used to assign IPs of the sort to
all nodes that are missing.

If you remove IPv4 or IPv6 prefixes from the config,
it can be run to remove the IPs that should no longer
be assigned to nodes.

Usage:
  headscale nodes backfillips [flags]

Flags:
  -h, --help   help for backfillips

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_PREAUTHKEYS_HELP: &str = r#"Handle the preauthkeys in Headscale

Usage:
  headscale preauthkeys [command]

Aliases:
  preauthkeys, preauthkey, authkey, pre

Available Commands:
  create      Creates a new preauthkey
  delete      Delete a preauthkey
  expire      Expire a preauthkey
  list        List all preauthkeys

Flags:
  -h, --help   help for preauthkeys

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'

Use "headscale preauthkeys [command] --help" for more information about a command.
"#;

const UPSTREAM_PREAUTHKEYS_CREATE_HELP: &str = r#"Creates a new preauthkey

Usage:
  headscale preauthkeys create [flags]

Aliases:
  create, c, new

Flags:
      --ephemeral           Preauthkey for ephemeral nodes
  -e, --expiration string   Human-readable expiration of the key (e.g. 30m, 24h) (default "1h")
  -h, --help                help for create
      --reusable            Make the preauthkey reusable
      --tags strings        Tags to automatically assign to node
  -u, --user uint           User identifier (ID)

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
"#;

const UPSTREAM_PREAUTHKEYS_LIST_HELP: &str = r"List all preauthkeys

Usage:
  headscale preauthkeys list [flags]

Aliases:
  list, ls, show

Flags:
  -h, --help   help for list

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_PREAUTHKEYS_EXPIRE_HELP: &str = r"Expire a preauthkey

Usage:
  headscale preauthkeys expire [flags]

Aliases:
  expire, revoke, exp, e

Flags:
  -h, --help      help for expire
  -i, --id uint   Authkey ID

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_PREAUTHKEYS_DELETE_HELP: &str = r"Delete a preauthkey

Usage:
  headscale preauthkeys delete [flags]

Aliases:
  delete, del, rm, d

Flags:
  -h, --help      help for delete
  -i, --id uint   Authkey ID

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_APIKEYS_HELP: &str = r#"Handle the Api keys in Headscale

Usage:
  headscale apikeys [command]

Aliases:
  apikeys, apikey, api

Available Commands:
  create      Creates a new Api key
  delete      Delete an ApiKey
  expire      Expire an ApiKey
  list        List the Api keys for headscale

Flags:
  -h, --help   help for apikeys

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'

Use "headscale apikeys [command] --help" for more information about a command.
"#;

const UPSTREAM_APIKEYS_CREATE_HELP: &str = r#"
Creates a new Api key, the Api key is only visible on creation
and cannot be retrieved again.
If you lose a key, create a new one and revoke (expire) the old one.

Usage:
  headscale apikeys create [flags]

Aliases:
  create, c, new

Flags:
  -e, --expiration string   Human-readable expiration of the key (e.g. 30m, 24h) (default "90d")
  -h, --help                help for create

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
"#;

const UPSTREAM_APIKEYS_LIST_HELP: &str = r"List the Api keys for headscale

Usage:
  headscale apikeys list [flags]

Aliases:
  list, ls, show

Flags:
  -h, --help   help for list

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_APIKEYS_EXPIRE_HELP: &str = r"Expire an ApiKey

Usage:
  headscale apikeys expire [flags]

Aliases:
  expire, revoke, exp, e

Flags:
  -h, --help            help for expire
  -i, --id uint         ApiKey ID
  -p, --prefix string   ApiKey prefix

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_APIKEYS_DELETE_HELP: &str = r"Delete an ApiKey

Usage:
  headscale apikeys delete [flags]

Aliases:
  delete, remove, del

Flags:
  -h, --help            help for delete
  -i, --id uint         ApiKey ID
  -p, --prefix string   ApiKey prefix

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_POLICY_HELP: &str = r#"Manage the Headscale ACL Policy

Usage:
  headscale policy [command]

Available Commands:
  check       Check the Policy file for errors
  get         Print the current ACL Policy
  set         Updates the ACL Policy

Flags:
  -h, --help   help for policy

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'

Use "headscale policy [command] --help" for more information about a command.
"#;

const UPSTREAM_POLICY_GET_HELP: &str = r"Print the current ACL Policy

Usage:
  headscale policy get [flags]

Aliases:
  get, show, view, fetch

Flags:
      --bypass-grpc-and-access-database-directly   Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running
  -h, --help                                       help for get

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_POLICY_SET_HELP: &str = "
\tUpdates the existing ACL Policy with the provided policy. The policy must be a valid HuJSON object.
\tThis command only works when the acl.policy_mode is set to \"db\", and the policy will be stored in the database.

Usage:
  headscale policy set [flags]

Aliases:
  set, put, update

Flags:
      --bypass-grpc-and-access-database-directly   Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running
  -f, --file string                                Path to a policy file in HuJSON format
  -h, --help                                       help for set

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

const UPSTREAM_POLICY_CHECK_HELP: &str = "
\tCheck validates the policy against the server's live users and nodes,
\trunning any \"tests\" or \"sshTests\" block. By default the command is a
\tthin frontend for a gRPC call to a running headscale; pass --bypass-grpc-and-access-database-directly to
\topen the database directly when headscale is not running.

Usage:
  headscale policy check [flags]

Flags:
      --bypass-grpc-and-access-database-directly   Open the database directly (no gRPC, no running server) to resolve user references and to evaluate the policy's tests and sshTests blocks. Required when those checks are needed.
  -f, --file string                                Path to a policy file in HuJSON format
  -h, --help                                       help for check

Global Flags:
  -c, --config string   config file (default is /etc/headscale/config.yaml)
      --force           Disable prompts and forces the execution
  -o, --output string   Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'
";

fn configtest(config: Option<&CliConfig>) -> Result<()> {
    let config = config.context("configuration was not loaded")?;
    config
        .validate_for_configtest()
        .context("configuration error: loading configuration")?;
    print_config_warnings(config);
    Ok(())
}

fn print_config_warnings(config: &CliConfig) {
    for warning in config.upstream_nonfatal_config_warnings() {
        eprintln!("{warning}");
    }
}

fn generate_completion(shell: &CompletionShell) {
    let mut command = Cli::command();
    command.build();
    if shell.no_descriptions() {
        command = strip_completion_descriptions(command);
    }
    clap_complete::generate(
        shell.clap_shell(),
        &mut command,
        "headscale",
        &mut std::io::stdout(),
    );
}

fn strip_completion_descriptions(command: clap::Command) -> clap::Command {
    command
        .about(None::<&'static str>)
        .long_about(None::<&'static str>)
        .before_help(None::<&'static str>)
        .before_long_help(None::<&'static str>)
        .after_help(None::<&'static str>)
        .after_long_help(None::<&'static str>)
        .mut_args(|arg| {
            arg.help(None::<&'static str>)
                .long_help(None::<&'static str>)
        })
        .mut_subcommands(strip_completion_descriptions)
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
    match fmt {
        headscale_cli::admin::OutputFormat::Json | headscale_cli::admin::OutputFormat::JsonLine => {
            print_structured_value(fmt, &version)?;
        }
        headscale_cli::admin::OutputFormat::Yaml => {
            print_structured_value(fmt, &version.yaml_view())?;
        }
        headscale_cli::admin::OutputFormat::Table => {
            print!("{}", version.human());
        }
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

fn dump_config_to(config: &CliConfig, path: &Path) -> Result<()> {
    let contents = serde_yaml::to_string(config)?;
    std::fs::write(path, contents)
        .map_err(|err| anyhow::anyhow!("{}", go_style_open_error("dumping config", path, &err)))?;
    Ok(())
}

fn go_style_open_error(context: &str, path: &Path, err: &std::io::Error) -> String {
    let message = match err.kind() {
        std::io::ErrorKind::NotFound => "no such file or directory".to_string(),
        std::io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        std::io::ErrorKind::AlreadyExists => "file exists".to_string(),
        _ => err.to_string(),
    };
    format!("{context}: open {}: {message}", path.display())
}

fn print_structured_value<T: serde::Serialize>(
    fmt: headscale_cli::admin::OutputFormat,
    value: &T,
) -> Result<()> {
    match fmt {
        headscale_cli::admin::OutputFormat::Json => {
            println!("{}", go_style_json_string(value)?);
        }
        headscale_cli::admin::OutputFormat::JsonLine => {
            println!("{}", serde_json::to_string(value)?);
        }
        headscale_cli::admin::OutputFormat::Yaml => {
            println!("{}", go_style_yaml_string(value)?);
        }
        headscale_cli::admin::OutputFormat::Table => unreachable!(),
    }
    Ok(())
}

fn go_style_json_string<T: serde::Serialize>(value: &T) -> Result<String> {
    let mut buf = Vec::new();
    let formatter = serde_json::ser::PrettyFormatter::with_indent(b"\t");
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, formatter);
    value.serialize(&mut ser)?;
    Ok(String::from_utf8(buf)?)
}

fn go_style_yaml_string<T: serde::Serialize>(value: &T) -> Result<String> {
    let yaml = serde_yaml::to_string(value)?;
    let mut formatted = String::with_capacity(yaml.len());
    for line in yaml.lines() {
        let leading_spaces = line.bytes().take_while(|byte| *byte == b' ').count();
        formatted.push_str(&" ".repeat(leading_spaces * 2));
        formatted.push_str(&line[leading_spaces..]);
        formatted.push('\n');
    }
    Ok(formatted)
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
    go: BuildRuntimeInfo,
    dirty: bool,
}

#[derive(serde::Serialize)]
struct VersionInfoYaml<'a> {
    version: &'static str,
    commit: &'static str,
    buildtime: &'static str,
    go: &'a BuildRuntimeInfo,
    dirty: bool,
}

#[derive(serde::Serialize)]
struct BuildRuntimeInfo {
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
            go: BuildRuntimeInfo {
                version: option_env!("RUSTC_VERSION").unwrap_or("unknown"),
                os: go_os_label(std::env::consts::OS),
                arch: go_arch_label(std::env::consts::ARCH),
            },
            dirty: option_env!("HEADSCALE_RS_DIRTY").is_some_and(|value| value == "true"),
        }
    }

    fn yaml_view(&self) -> VersionInfoYaml<'_> {
        VersionInfoYaml {
            version: self.version,
            commit: self.commit,
            buildtime: self.build_time,
            go: &self.go,
            dirty: self.dirty,
        }
    }

    fn human(&self) -> String {
        let mut version = self.version.to_string();
        if self.dirty && !version.contains("dirty") {
            version.push_str("-dirty");
        }

        format!(
            "headscale version {}\ncommit: {}\nbuild time: {}\nbuilt with: {} {}/{}\n",
            version, self.commit, self.build_time, self.go.version, self.go.os, self.go.arch
        )
    }
}

fn go_os_label(os: &'static str) -> &'static str {
    match os {
        "macos" => "darwin",
        other => other,
    }
}

fn go_arch_label(arch: &'static str) -> &'static str {
    match arch {
        "aarch64" => "arm64",
        "x86" => "386",
        "x86_64" => "amd64",
        other => other,
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
            anyhow::bail!("control plane returned: {}", r.status())
        }
        Err(e) => {
            anyhow::bail!("failed to connect to control plane: {e}")
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn standalone_cli_accepts_user_aliases_from_upstream() {
        let parsed = Cli::try_parse_from(["headscale", "user", "show"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Users {
                action: UsersCmd::List { .. }
            }
        ));
    }

    #[test]
    fn standalone_cli_rejects_removed_hidden_compatibility_aliases() {
        assert!(Cli::try_parse_from(["headscale", "namespace", "ls"]).is_err());
        assert!(Cli::try_parse_from(["headscale", "machine", "ls"]).is_err());
        assert!(Cli::try_parse_from(["headscale", "tailnet", "status"]).is_err());
        assert!(Cli::try_parse_from(["headscale", "init-config"]).is_err());
    }

    #[test]
    fn standalone_cli_accepts_node_alias_without_conflicting_with_node_mode() {
        let parsed = Cli::try_parse_from(["headscale", "node", "ls"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Nodes {
                action: NodesCmd::List { .. }
            }
        ));

        let parsed =
            Cli::try_parse_from(["headscale", "mesh-node", "--server", "http://127.0.0.1"])
                .unwrap();
        assert!(matches!(parsed.command, Commands::Node { .. }));
    }

    #[test]
    fn standalone_cli_accepts_preauthkey_aliases_from_upstream() {
        let parsed = Cli::try_parse_from(["headscale", "authkey", "new", "--user", "42"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Preauthkeys {
                user: None,
                action: PreauthKeysCmd::Create { user: Some(42), .. }
            }
        ));

        let parsed =
            Cli::try_parse_from(["headscale", "preauthkeys", "--user", "42", "create"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Preauthkeys {
                user: Some(42),
                action: PreauthKeysCmd::Create { user: None, .. }
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
                user: None,
                action: PreauthKeysCmd::Delete { id: Some(42) }
            }
        ));
    }

    #[test]
    fn standalone_cli_accepts_policy_aliases_from_upstream() {
        let parsed = Cli::try_parse_from(["headscale", "policy", "view"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Policy {
                action: PolicyCmd::Get { .. }
            }
        ));

        let parsed =
            Cli::try_parse_from(["headscale", "policy", "set", "--file", "policy.hujson"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Policy {
                action: PolicyCmd::Set { .. }
            }
        ));

        let parsed = Cli::try_parse_from([
            "headscale",
            "policy",
            "check",
            "-f",
            "policy.hujson",
            "--bypass-grpc-and-access-database-directly",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Policy {
                action: PolicyCmd::Check {
                    bypass_direct_db: true,
                    ..
                }
            }
        ));

        let Err(err) = Cli::try_parse_from(["headscale", "policy", "set", "policy.hujson"]) else {
            panic!("upstream policy set requires --file");
        };
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
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
                action: GenerateCmd::PrivateKey { .. }
            }
        ));

        let parsed = Cli::try_parse_from(["headscale", "gen", "private-key"]).unwrap();
        assert!(matches!(
            parsed.command,
            Commands::Generate {
                action: GenerateCmd::PrivateKey { .. }
            }
        ));
    }

    #[test]
    fn standalone_cli_accepts_upstream_version_and_configtest_commands() {
        let parsed = Cli::try_parse_from(["headscale", "version"]).unwrap();
        assert!(matches!(parsed.command, Commands::Version));

        let parsed = Cli::try_parse_from(["headscale", "--force=false", "health"]).unwrap();
        assert!(matches!(parsed.command, Commands::Health));
        assert!(!parsed.connect.force);

        let parsed = Cli::try_parse_from(["headscale", "--force=true", "health"]).unwrap();
        assert!(matches!(parsed.command, Commands::Health));
        assert!(parsed.connect.force);

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
    fn raw_first_arg_controls_config_skip_like_upstream_cobra() {
        assert!(raw_args_skip_config_load(["version"]));
        assert!(raw_args_skip_config_load(["mockoidc"]));
        assert!(raw_args_skip_config_load(["completion", "bash"]));
        assert!(!raw_args_skip_config_load([
            "--config",
            "missing.yaml",
            "version"
        ]));
        assert!(!raw_args_skip_config_load(["-o", "json", "version"]));
    }

    #[test]
    fn raw_version_shortcut_requires_version_as_first_arg() {
        assert!(upstream_version_invocation(&["version", "extra"]));
        assert!(!upstream_version_invocation(&[
            "--config",
            "missing.yaml",
            "version"
        ]));
        assert!(!upstream_version_invocation(&["-o", "json", "version"]));
    }

    #[test]
    fn raw_exact_help_matches_cobra_forms() {
        assert_eq!(
            upstream_exact_help(&["--help"]),
            Some(UPSTREAM_TOP_LEVEL_HELP)
        );
        assert_eq!(upstream_exact_help(&["-h"]), Some(UPSTREAM_TOP_LEVEL_HELP));
        assert_eq!(
            upstream_exact_help(&["help"]),
            Some(UPSTREAM_TOP_LEVEL_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["version", "-h"]),
            Some(UPSTREAM_VERSION_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "version", "bad"]),
            Some(UPSTREAM_VERSION_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["health", "--config", "missing.yaml", "--help"]),
            Some(UPSTREAM_HEALTH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["--force=false", "health", "--help"]),
            Some(UPSTREAM_HEALTH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["health", "--force=false", "--help"]),
            Some(UPSTREAM_HEALTH_HELP)
        );
        assert_eq!(upstream_exact_help(&["health", "--config", "--help"]), None);
        assert_eq!(
            upstream_exact_help(&["health", "-o", "json", "--help"]),
            Some(UPSTREAM_HEALTH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["configtest", "-c", "missing.yaml", "--help"]),
            Some(UPSTREAM_CONFIGTEST_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["configtest", "--output=json", "--help"]),
            Some(UPSTREAM_CONFIGTEST_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["configtest", "--output", "--help"]),
            None
        );
        assert_eq!(
            upstream_exact_help(&["dumpConfig", "--config=missing.yaml", "--help"]),
            Some(UPSTREAM_DUMP_CONFIG_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["dumpConfig", "--config", "--help"]),
            None
        );
        assert_eq!(
            upstream_exact_help(&["dumpConfig", "--force", "--help"]),
            Some(UPSTREAM_DUMP_CONFIG_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["serve", "ignored", "--help"]),
            Some(UPSTREAM_SERVE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["serve", "--config", "missing.yaml", "--help"]),
            Some(UPSTREAM_SERVE_HELP)
        );
        assert_eq!(
            upstream_exact_error(&["namespace", "--help"]),
            Some("Error: unknown command \"namespace\" for \"headscale\"\n".into())
        );
        assert_eq!(
            upstream_exact_error(&["machine", "--help"]),
            Some("Error: unknown command \"machine\" for \"headscale\"\n".into())
        );
        assert_eq!(
            upstream_exact_error(&[
                "debug",
                "create-node",
                "--namespace",
                "alice",
                "--key",
                "k",
                "--name",
                "n"
            ]),
            Some("Error: unknown flag: --namespace\n".into())
        );
        assert_eq!(
            upstream_exact_error(&["server", "--help"]),
            Some(UPSTREAM_SERVER_UNKNOWN_COMMAND.into())
        );
        assert_eq!(
            upstream_exact_error(&["userz"]),
            Some(
                "Error: unknown command \"userz\" for \"headscale\"\n\nDid you mean this?\n\tusers\n\n"
                    .into()
            )
        );
        assert_eq!(
            upstream_exact_error(&["completion", "bash", "--no-descriptions", "bad"]),
            Some("Error: unknown command \"bad\" for \"headscale completion bash\"\n".to_string())
        );
        assert_eq!(
            upstream_exact_error(&["auth", "register"]),
            Some("Error: required flag(s) \"auth-id\", \"user\" not set\n".to_string())
        );
        assert_eq!(
            upstream_exact_error(&["auth", "register", "--user", "alice"]),
            Some("Error: required flag(s) \"auth-id\" not set\n".to_string())
        );
        assert_eq!(
            upstream_exact_error(&["auth", "approve"]),
            Some("Error: required flag(s) \"auth-id\" not set\n".to_string())
        );
        assert_eq!(
            upstream_exact_error(&["nodes", "register", "--user", "alice"]),
            Some(
                "Command \"register\" is deprecated, use 'headscale auth register --auth-id <id> --user <user>' instead\nError: required flag(s) \"key\" not set\n"
                    .to_string()
            )
        );
        assert_eq!(
            upstream_exact_error(&["users", "create", "--display-name", "Alice"]),
            Some("Error: missing parameters\n".to_string())
        );
        assert_eq!(
            upstream_exact_error(&["nodes", "list", "--user"]),
            Some("Error: flag needs an argument: --user\n".to_string())
        );
        assert_eq!(
            upstream_exact_error(&["preauthkeys", "create", "--user"]),
            Some("Error: flag needs an argument: --user\n".to_string())
        );
        assert_eq!(
            upstream_exact_success_stderr(&["help", "server"]),
            Some(format!(
                "Unknown help topic [`server`]\n{UPSTREAM_TOP_LEVEL_HELP_TOPIC_USAGE}"
            ))
        );
        assert_eq!(
            upstream_exact_success_stderr(&["help", "status"]),
            Some(format!(
                "Unknown help topic [`status`]\n{UPSTREAM_TOP_LEVEL_HELP_TOPIC_USAGE}"
            ))
        );
        assert_eq!(
            upstream_exact_help(&["dumpConfig", "--help"]),
            Some(UPSTREAM_DUMP_CONFIG_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "dumpConfig"]),
            Some(UPSTREAM_DUMP_CONFIG_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["mockoidc", "--help"]),
            Some(UPSTREAM_MOCKOIDC_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["mockoidc", "ignored", "--help"]),
            Some(UPSTREAM_MOCKOIDC_HELP)
        );
        assert_eq!(
            upstream_exact_error(&["mockoidc", "--config", "missing.yaml", "--help"]),
            Some("Error: unknown flag: --config\n".into())
        );
        assert_eq!(
            upstream_exact_help(&["help", "mockoidc"]),
            Some(UPSTREAM_MOCKOIDC_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["gen", "--help"]),
            Some(UPSTREAM_GENERATE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "gen"]),
            Some(UPSTREAM_GENERATE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["gen", "private-key", "--help"]),
            Some(UPSTREAM_GENERATE_PRIVATE_KEY_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["generate", "private-key", "--force", "--help"]),
            Some(UPSTREAM_GENERATE_PRIVATE_KEY_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["generate", "private-key", "--output", "--help"]),
            None
        );
        assert_eq!(
            upstream_exact_help(&["generate", "bad", "--help"]),
            Some(UPSTREAM_GENERATE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["completion", "bash", "--help"]),
            Some(UPSTREAM_COMPLETION_BASH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["completion", "bash", "--no-descriptions", "--help"]),
            Some(UPSTREAM_COMPLETION_BASH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["completion", "bash", "extra", "--help"]),
            Some(UPSTREAM_COMPLETION_BASH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "completion", "bash"]),
            Some(UPSTREAM_COMPLETION_BASH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["completion", "fish", "--help"]),
            Some(UPSTREAM_COMPLETION_FISH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "completion", "fish"]),
            Some(UPSTREAM_COMPLETION_FISH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["completion", "powershell", "--help"]),
            Some(UPSTREAM_COMPLETION_POWERSHELL_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "completion", "powershell"]),
            Some(UPSTREAM_COMPLETION_POWERSHELL_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["completion", "zsh", "--help"]),
            Some(UPSTREAM_COMPLETION_ZSH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "completion", "zsh"]),
            Some(UPSTREAM_COMPLETION_ZSH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "auth", "register"]),
            Some(UPSTREAM_AUTH_REGISTER_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "auth", "register", "bad"]),
            Some(UPSTREAM_AUTH_REGISTER_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "auth", "bad"]),
            Some(UPSTREAM_AUTH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["auth", "bogus"]),
            Some(UPSTREAM_AUTH_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["users", "--help"]),
            Some(UPSTREAM_USERS_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["users", "bogus"]),
            Some(UPSTREAM_USERS_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "user"]),
            Some(UPSTREAM_USERS_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "users", "create"]),
            Some(UPSTREAM_USERS_CREATE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "users", "create", "bad"]),
            Some(UPSTREAM_USERS_CREATE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "users", "bad"]),
            Some(UPSTREAM_USERS_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["user", "new", "--help"]),
            Some(UPSTREAM_USERS_CREATE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "users", "c"]),
            Some(UPSTREAM_USERS_CREATE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["users", "ls", "-h"]),
            Some(UPSTREAM_USERS_LIST_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "user", "show"]),
            Some(UPSTREAM_USERS_LIST_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["user", "mv", "--help"]),
            Some(UPSTREAM_USERS_RENAME_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["users", "delete", "--help"]),
            Some(UPSTREAM_USERS_DESTROY_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["nodes", "--help"]),
            Some(UPSTREAM_NODES_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["node", "-h"]),
            Some(UPSTREAM_NODES_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["nodes", "register", "--help"]),
            Some(UPSTREAM_NODES_REGISTER_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["node", "register", "--help"]),
            Some(UPSTREAM_NODES_REGISTER_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "nodes", "register"]),
            Some(UPSTREAM_NODES_REGISTER_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "nodes", "routes"]),
            Some(UPSTREAM_NODES_LIST_ROUTES_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["nodes", "logout", "-h"]),
            Some(UPSTREAM_NODES_EXPIRE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "node", "t"]),
            Some(UPSTREAM_NODES_TAG_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["nodes", "del", "--help"]),
            Some(UPSTREAM_NODES_DELETE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["authkey", "new", "--help"]),
            Some(UPSTREAM_PREAUTHKEYS_CREATE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "pre", "rm"]),
            Some(UPSTREAM_PREAUTHKEYS_DELETE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["api", "revoke", "-h"]),
            Some(UPSTREAM_APIKEYS_EXPIRE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "apikey", "remove"]),
            Some(UPSTREAM_APIKEYS_DELETE_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["policy", "--help"]),
            Some(UPSTREAM_POLICY_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["policy", "bogus"]),
            Some(UPSTREAM_POLICY_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "policy", "fetch"]),
            Some(UPSTREAM_POLICY_GET_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["policy", "update", "-h"]),
            Some(UPSTREAM_POLICY_SET_HELP)
        );
        assert_eq!(
            upstream_exact_help(&["help", "policy", "check"]),
            Some(UPSTREAM_POLICY_CHECK_HELP)
        );
        assert_eq!(upstream_exact_help(&["--help", "nodes"]), None);
    }

    #[test]
    fn version_output_matches_upstream_runtime_shape() {
        let version = VersionInfo::current();

        assert_eq!(version.version, env!("CARGO_PKG_VERSION"));
        assert!(!version.commit.is_empty());
        assert!(!version.build_time.is_empty());
        assert_eq!(version.go.os, go_os_label(std::env::consts::OS));
        assert!(version.human().contains("headscale version"));
        assert!(!version.human().contains("headscale-rs version"));
    }

    #[test]
    fn configtest_requires_loaded_config() {
        assert!(configtest(None).is_err());
        assert!(configtest(Some(&CliConfig::default())).is_err());

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            r#"
server_url: "https://headscale.example"
noise:
  private_key_path: "noise_private.key"
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
"#,
        )
        .unwrap();
        let config = CliConfig::load(&config_path).unwrap();
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
            output: None,
            force: false,
            direct_database: None,
            timeout_secs: None,
        };
        let config = CliConfig {
            cli: Some(config::AdminCliConfig {
                address: Some("headscale.example:50443".into()),
                api_key: Some("hskey-api-abcdefghijkl-secret".into()),
                insecure: Some(true),
                timeout: Some(3),
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
        assert_eq!(merged.timeout_secs, Some(3));
        assert_eq!(
            merged.unix_socket.as_deref(),
            Some(PathBuf::from("/run/headscale/admin.sock").as_path())
        );
        assert_eq!(
            merged.direct_database,
            Some(DirectPolicyDatabase::Sqlite {
                path: ServerConfig::default().db_path
            })
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
            output: None,
            force: false,
            direct_database: None,
            timeout_secs: Some(11),
        };
        let config = CliConfig {
            cli: Some(config::AdminCliConfig {
                address: Some("config.example:50443".into()),
                api_key: Some("config-key".into()),
                insecure: Some(false),
                timeout: Some(3),
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
        assert_eq!(merged.timeout_secs, Some(11));
    }

    #[test]
    fn admin_connect_args_resolves_direct_policy_sqlite_database_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db.sqlite");
        let connect = ConnectArgs {
            server: None,
            token: None,
            address: None,
            api_key: None,
            unix_socket: None,
            insecure: false,
            output: None,
            force: false,
            direct_database: None,
            timeout_secs: None,
        };
        let config = CliConfig {
            server: Some(ServerConfig {
                db_path: db_path.clone(),
                ..ServerConfig::default()
            }),
            ..CliConfig::default()
        };

        let merged = merged_connect_args(&connect, Some(&config));

        assert_eq!(
            merged.direct_database,
            Some(DirectPolicyDatabase::Sqlite { path: db_path })
        );
    }

    #[test]
    fn admin_connect_args_reports_direct_policy_postgres_database_from_config() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            r"
database:
  type: postgres
  postgres:
    host: db.example
    port: 15432
    name: headscale
    user: hs
    pass: secret
    ssl: require
",
        )
        .unwrap();
        let config = CliConfig::load(&config_path).unwrap();

        let database = direct_policy_database_from_config(&config);

        #[cfg(feature = "postgres-sqlx")]
        assert_eq!(
            database,
            DirectPolicyDatabase::Postgres {
                url: "postgres://hs:secret@db.example:15432/headscale?sslmode=require".into()
            }
        );
        #[cfg(not(feature = "postgres-sqlx"))]
        assert_eq!(
            database,
            DirectPolicyDatabase::Unavailable {
                reason:
                    "direct database policy access for Postgres requires the postgres-sqlx feature"
                        .into()
            }
        );
    }
}
