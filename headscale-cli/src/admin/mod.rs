//! Operator CLI for the headscale admin surface.
//!
//! Upstream-compatible command groups use the local Unix-socket gRPC
//! service by default, matching `headscale`'s operator CLI model. Command
//! groups that have not been migrated yet still use the legacy admin HTTP
//! `/api/v1/*` surface exposed for the GUI (#216 / commit `62b956d`).
//!
//! ## Wire & auth
//!
//! gRPC commands use `--unix-socket` (`$HEADSCALE_UNIX_SOCKET`) locally
//! or `--address` + `--api-key` (`$HEADSCALE_CLI_ADDRESS` /
//! `$HEADSCALE_CLI_API_KEY`) remotely; `--insecure` only disables TLS
//! certificate verification. Legacy HTTP commands continue to take
//! `--server` (`$HEADSCALE_URL`) and `--token`
//! (`$HEADSCALE_ADMIN_TOKEN`). Errors are mapped onto the fixed exit-code
//! contract defined by [`ExitCode`]:
//!
//! | code | meaning                                     |
//! |------|---------------------------------------------|
//! | 0    | success                                     |
//! | 2    | bad usage (clap already exits 2 on its own) |
//! | 3    | connection failure (DNS / TCP / TLS)        |
//! | 4    | auth failure (401 / 403)                    |
//! | 5    | entity not found (404)                      |
//! | 6    | other server-side failure (4xx / 5xx / decode) |

pub mod apikeys;
pub mod client;
pub mod duration;
pub mod grpc_client;
pub mod nodes;
pub mod output;
pub mod policy;
pub mod preauthkeys;
pub mod tailnet;
pub mod users;

use std::path::PathBuf;

use clap::{Args, Subcommand};

pub use client::AdminClient;
pub use grpc_client::GrpcAdminClient;
pub use output::OutputFormat;

/// Errors surfaced by the admin client. Variants line up 1-to-1 with
/// the [`ExitCode`] table so the CLI can translate without inspecting
/// strings.
#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    /// DNS / TCP / TLS / handshake — anything that fails before the
    /// server returns a status code.
    #[error("connection failure: {0}")]
    Connection(String),
    /// HTTP 401 / 403 — wrong (or missing) bearer token.
    #[error("authentication failed: {0}")]
    Auth(String),
    /// HTTP 404 — entity (user / machine / preauth key) not found.
    #[error("not found: {0}")]
    NotFound(String),
    /// HTTP 4xx other than 401/403/404.
    #[error("bad request ({status}): {body}")]
    BadRequest { status: u16, body: String },
    /// HTTP 5xx.
    #[error("server error ({status}): {body}")]
    Server { status: u16, body: String },
    /// JSON / response-decoding failure.
    #[error("response decode failed: {0}")]
    Decode(String),
    /// Failure that doesn't involve the server at all (file IO, local
    /// validation, etc.). Mapped to the same exit code as `Server`
    /// because it's an unhandleable operator-side failure.
    #[error("{0}")]
    Local(String),
}

/// Stable exit codes the CLI honours. The `i32` values match the
/// process-exit contract documented in #216.
#[derive(Copy, Clone, Debug)]
pub enum ExitCode {
    Success = 0,
    Connection = 3,
    Auth = 4,
    NotFound = 5,
    Server = 6,
}

impl AdminError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Connection(_) => ExitCode::Connection,
            Self::Auth(_) => ExitCode::Auth,
            Self::NotFound(_) => ExitCode::NotFound,
            Self::BadRequest { .. } | Self::Server { .. } | Self::Decode(_) | Self::Local(_) => {
                ExitCode::Server
            }
        }
    }
}

/// Shared connection flags. Upstream parity commands prefer gRPC using
/// the local Unix socket by default; legacy HTTP commands continue to
/// consume `--server` / `--token` until their command group is ported.
#[derive(Args, Debug, Clone)]
pub struct ConnectArgs {
    /// Legacy admin HTTP URL. Falls back to `$HEADSCALE_URL`. Trailing `/` is OK.
    #[arg(long, env = "HEADSCALE_URL", global = true)]
    pub server: Option<String>,
    /// Legacy admin HTTP bearer token. Falls back to `$HEADSCALE_ADMIN_TOKEN`.
    #[arg(long, env = "HEADSCALE_ADMIN_TOKEN", global = true)]
    pub token: Option<String>,
    /// Upstream gRPC address. If unset, connect to the local Unix socket.
    #[arg(long = "address", env = "HEADSCALE_CLI_ADDRESS", global = true)]
    pub address: Option<String>,
    /// Upstream gRPC API key for remote addresses.
    #[arg(long = "api-key", env = "HEADSCALE_CLI_API_KEY", global = true)]
    pub api_key: Option<String>,
    /// Local upstream gRPC Unix socket used when `--address` is unset.
    #[arg(long = "unix-socket", env = "HEADSCALE_UNIX_SOCKET", global = true)]
    pub unix_socket: Option<PathBuf>,
    /// Disable TLS certificate verification for a remote gRPC address.
    #[arg(long = "insecure", env = "HEADSCALE_CLI_INSECURE", global = true)]
    pub insecure: bool,
    /// Emit raw JSON instead of the default table view.
    #[arg(long, global = true)]
    pub json: bool,
    /// Output format. Empty for human-readable, `json`, `json-line`, or `yaml`.
    #[arg(
        short = 'o',
        long = "output",
        global = true,
        value_parser = ["json", "json-line", "yaml"]
    )]
    pub output: Option<String>,
}

impl ConnectArgs {
    /// Build a client from the supplied flags. Empty `token` is
    /// allowed (some admin builds disable bearer auth in tests) — the
    /// server will reject it with 401 if it's required.
    pub fn build_client(&self) -> Result<AdminClient, AdminError> {
        let server = self
            .server
            .as_deref()
            .ok_or_else(|| AdminError::Local("--server (or $HEADSCALE_URL) is required".into()))?;
        let token = self.token.clone().unwrap_or_default();
        Ok(AdminClient::new(server, token))
    }

    pub async fn build_grpc_client(&self) -> Result<GrpcAdminClient, AdminError> {
        GrpcAdminClient::connect(
            self.address.as_deref(),
            self.api_key.as_deref(),
            self.unix_socket.as_deref(),
            self.insecure,
        )
        .await
    }

    pub fn should_use_legacy_http_for_migrated_commands(&self) -> bool {
        self.server.is_some() && !self.has_explicit_grpc_endpoint()
    }

    fn has_explicit_grpc_endpoint(&self) -> bool {
        self.address
            .as_deref()
            .is_some_and(|address| !address.trim().is_empty())
            || self.unix_socket.is_some()
    }

    pub fn fmt(&self) -> Result<OutputFormat, AdminError> {
        OutputFormat::from_flags(self.json, self.output.as_deref())
    }
}

// ---------------------------------------------------------------------------
// clap subcommand definitions
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum UsersCmd {
    /// Create a new user.
    #[command(alias = "c", alias = "new")]
    Create { name: String },
    /// List all users.
    #[command(alias = "ls", alias = "show")]
    List,
    /// Delete a user by name.
    #[command(alias = "destroy")]
    Delete { name: String },
}

#[derive(Subcommand, Debug)]
pub enum NodesCmd {
    /// List registered nodes (optionally filter by user).
    #[command(alias = "ls")]
    List {
        #[arg(long)]
        user: Option<String>,
    },
    /// List advertised, approved, and serving routes on nodes.
    #[command(name = "list-routes", alias = "routes", alias = "lsr")]
    ListRoutes {
        /// Restrict to one node ID.
        #[arg(short = 'i', long = "identifier", value_name = "ID")]
        id: Option<String>,
    },
    /// Show one node by node_key hex or hostname.
    Show {
        #[arg(value_name = "ID_OR_NAME")]
        id_or_name: String,
    },
    /// Mark a node expired. Without `--at`, expires immediately
    /// (forces re-register on the node's next /map). With `--at`,
    /// schedules expiry for the supplied ISO-8601 timestamp.
    Expire {
        #[arg(value_name = "ID")]
        id: String,
        /// ISO-8601 timestamp to schedule expiry at. Defaults to "now".
        #[arg(long, value_name = "ISO8601")]
        at: Option<String>,
    },
    /// Force-logout a node — clears Noise/disco keys + stamps
    /// expiry=now so the next /map round-trip returns a logout
    /// response. Mirrors upstream `headscale nodes logout`.
    Logout {
        #[arg(value_name = "ID")]
        id: String,
    },
    /// Rename a node (operator-driven hostname rewrite).
    Rename {
        #[arg(value_name = "ID")]
        id: String,
        #[arg(value_name = "HOSTNAME")]
        hostname: String,
    },
    /// Replace the node's forced-tags list. Empty list clears the
    /// override; tags are matched by exact string against the policy.
    #[command(alias = "tag", alias = "t")]
    Tags {
        #[arg(value_name = "ID")]
        id: String,
        /// Comma-separated tag list, e.g. `tag:prod,tag:web`.
        #[arg(value_name = "TAGS", value_delimiter = ',')]
        tags: Vec<String>,
    },
    /// Replace the approved routes for a node.
    #[command(name = "approve-routes")]
    ApproveRoutes {
        /// Node ID.
        #[arg(short = 'i', long = "identifier", value_name = "ID")]
        id: String,
        /// Comma-separated route list. Empty list removes approvals.
        #[arg(short = 'r', long = "routes", value_delimiter = ',')]
        routes: Vec<String>,
    },
    /// Delete a node.
    #[command(alias = "del")]
    Delete {
        #[arg(value_name = "ID")]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum PreauthKeysCmd {
    /// Mint a fresh preauth key.
    #[command(alias = "c", alias = "new")]
    Create {
        /// User the key belongs to.
        #[arg(long)]
        user: String,
        /// Allow more than one redemption.
        #[arg(long)]
        reusable: bool,
        /// Mark the resulting device ephemeral (auto-clean).
        #[arg(long)]
        ephemeral: bool,
        /// Comma-separated `tag:foo,tag:bar` tags.
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Duration the key is valid (e.g. `24h`, `7d`, `30m`).
        /// Defaults to `24h` — same as the admin GUI default.
        #[arg(long, default_value = "24h")]
        expires_in: String,
    },
    /// List all known preauth keys.
    #[command(alias = "ls", alias = "show")]
    List {
        /// Restrict to a single user.
        #[arg(long)]
        user: Option<String>,
    },
    /// Expire a key identified by its visible prefix.
    #[command(alias = "revoke", alias = "exp", alias = "e")]
    Expire {
        #[arg(value_name = "PREFIX")]
        prefix: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum ApiKeysCmd {
    /// Mint a fresh API key. The full secret is only shown once.
    #[command(alias = "c", alias = "new")]
    Create {
        /// Duration the key is valid (e.g. `30m`, `24h`, `90d`).
        #[arg(short = 'e', long = "expiration", default_value = "90d")]
        expiration: String,
    },
    /// List all known API keys.
    #[command(alias = "ls", alias = "show")]
    List,
    /// Expire an API key by visible prefix or numeric ID.
    #[command(alias = "revoke", alias = "exp", alias = "e")]
    Expire {
        /// API key display prefix, e.g. `hskey-api-abcdefghijkl-***`.
        #[arg(short, long)]
        prefix: Option<String>,
        /// API key numeric ID.
        #[arg(short, long)]
        id: Option<u64>,
    },
    /// Delete an API key by visible prefix or numeric ID.
    #[command(alias = "remove", alias = "del")]
    Delete {
        /// API key display prefix, e.g. `hskey-api-abcdefghijkl-***`.
        #[arg(short, long)]
        prefix: Option<String>,
        /// API key numeric ID.
        #[arg(short, long)]
        id: Option<u64>,
    },
}

#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// Fetch the policy currently loaded on the server.
    #[command(alias = "show", alias = "view", alias = "fetch")]
    Get,
    /// Push a policy file to the server.
    #[command(alias = "put", alias = "update")]
    Set {
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },
    /// Validate a policy file locally without touching the server.
    Check {
        #[arg(value_name = "FILE")]
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub enum TailnetCmd {
    /// Show tailnet-wide status (DERP regions, DNS, policy).
    Status,
}

// ---------------------------------------------------------------------------
// Dispatchers — invoked from `main.rs`
// ---------------------------------------------------------------------------

pub async fn run_users(conn: &ConnectArgs, cmd: &UsersCmd) -> Result<(), AdminError> {
    let fmt = conn.fmt()?;
    if conn.should_use_legacy_http_for_migrated_commands() {
        let client = conn.build_client()?;
        return match cmd {
            UsersCmd::Create { name } => users::create(&client, name, fmt).await,
            UsersCmd::List => users::list(&client, fmt).await,
            UsersCmd::Delete { name } => users::delete(&client, name).await,
        };
    }
    let mut client = conn.build_grpc_client().await?;
    match cmd {
        UsersCmd::Create { name } => users::create_grpc(&mut client, name, fmt).await,
        UsersCmd::List => users::list_grpc(&mut client, fmt).await,
        UsersCmd::Delete { name } => users::delete_grpc(&mut client, name).await,
    }
}

pub async fn run_nodes(conn: &ConnectArgs, cmd: &NodesCmd) -> Result<(), AdminError> {
    let client = conn.build_client()?;
    let fmt = conn.fmt()?;
    match cmd {
        NodesCmd::List { user } => nodes::list(&client, user.as_deref(), fmt).await,
        NodesCmd::ListRoutes { id } => nodes::list_routes(&client, id.as_deref(), fmt).await,
        NodesCmd::Show { id_or_name } => nodes::show(&client, id_or_name, fmt).await,
        NodesCmd::Expire { id, at } => nodes::expire(&client, id, at.as_deref()).await,
        NodesCmd::Logout { id } => nodes::logout(&client, id).await,
        NodesCmd::Rename { id, hostname } => nodes::rename(&client, id, hostname).await,
        NodesCmd::Tags { id, tags } => nodes::tags(&client, id, tags.clone()).await,
        NodesCmd::ApproveRoutes { id, routes } => {
            nodes::approve_routes(&client, id, routes.clone(), fmt).await
        }
        NodesCmd::Delete { id } => nodes::delete(&client, id).await,
    }
}

pub async fn run_preauthkeys(conn: &ConnectArgs, cmd: &PreauthKeysCmd) -> Result<(), AdminError> {
    let client = conn.build_client()?;
    let fmt = conn.fmt()?;
    match cmd {
        PreauthKeysCmd::Create {
            user,
            reusable,
            ephemeral,
            tags,
            expires_in,
        } => {
            let secs = duration::parse_duration_secs(expires_in).map_err(AdminError::Local)?;
            preauthkeys::create(
                &client,
                user,
                *reusable,
                *ephemeral,
                tags.clone(),
                secs,
                fmt,
            )
            .await
        }
        PreauthKeysCmd::List { user } => preauthkeys::list(&client, user.as_deref(), fmt).await,
        PreauthKeysCmd::Expire { prefix } => preauthkeys::expire(&client, prefix).await,
    }
}

pub async fn run_apikeys(conn: &ConnectArgs, cmd: &ApiKeysCmd) -> Result<(), AdminError> {
    let client = conn.build_client()?;
    let fmt = conn.fmt()?;
    match cmd {
        ApiKeysCmd::Create { expiration } => apikeys::create(&client, expiration, fmt).await,
        ApiKeysCmd::List => apikeys::list(&client, fmt).await,
        ApiKeysCmd::Expire { prefix, id } => apikeys::expire(&client, prefix.as_deref(), *id).await,
        ApiKeysCmd::Delete { prefix, id } => apikeys::delete(&client, prefix.as_deref(), *id).await,
    }
}

pub async fn run_policy(conn: &ConnectArgs, cmd: &PolicyCmd) -> Result<(), AdminError> {
    match cmd {
        PolicyCmd::Check { path } => policy::check(path),
        PolicyCmd::Get => {
            let client = conn.build_client()?;
            policy::get(&client, conn.fmt()?).await
        }
        PolicyCmd::Set { path } => {
            let client = conn.build_client()?;
            policy::set(&client, path, conn.fmt()?).await
        }
    }
}

pub async fn run_tailnet(conn: &ConnectArgs, cmd: &TailnetCmd) -> Result<(), AdminError> {
    let client = conn.build_client()?;
    let fmt = conn.fmt()?;
    match cmd {
        TailnetCmd::Status => tailnet::status(&client, fmt).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_mapping_covers_every_variant() {
        assert_eq!(
            AdminError::Connection("x".into()).exit_code() as i32,
            ExitCode::Connection as i32
        );
        assert_eq!(
            AdminError::Auth("x".into()).exit_code() as i32,
            ExitCode::Auth as i32
        );
        assert_eq!(
            AdminError::NotFound("x".into()).exit_code() as i32,
            ExitCode::NotFound as i32
        );
        assert_eq!(
            AdminError::BadRequest {
                status: 400,
                body: "x".into()
            }
            .exit_code() as i32,
            ExitCode::Server as i32
        );
        assert_eq!(
            AdminError::Server {
                status: 500,
                body: "x".into()
            }
            .exit_code() as i32,
            ExitCode::Server as i32
        );
        assert_eq!(
            AdminError::Decode("x".into()).exit_code() as i32,
            ExitCode::Server as i32
        );
        assert_eq!(
            AdminError::Local("x".into()).exit_code() as i32,
            ExitCode::Server as i32
        );
    }

    #[test]
    fn connect_args_require_server() {
        let conn = ConnectArgs {
            server: None,
            token: Some("t".into()),
            address: None,
            api_key: None,
            unix_socket: None,
            insecure: false,
            json: false,
            output: None,
        };
        let e = conn.build_client().unwrap_err();
        assert!(matches!(e, AdminError::Local(_)));
    }

    #[test]
    fn connect_args_accept_empty_token() {
        let conn = ConnectArgs {
            server: Some("http://localhost:51822".into()),
            token: None,
            address: None,
            api_key: None,
            unix_socket: None,
            insecure: false,
            json: false,
            output: None,
        };
        assert!(conn.build_client().is_ok());
    }

    #[test]
    fn connect_args_accept_upstream_output_formats() {
        let conn = ConnectArgs {
            server: Some("http://localhost:51822".into()),
            token: None,
            address: None,
            api_key: None,
            unix_socket: None,
            insecure: false,
            json: false,
            output: Some("json-line".into()),
        };
        assert_eq!(conn.fmt().unwrap(), OutputFormat::JsonLine);
    }

    #[test]
    fn migrated_commands_prefer_explicit_grpc_endpoint_over_legacy_server_env() {
        let conn = ConnectArgs {
            server: Some("http://localhost:51822".into()),
            token: Some("legacy-token".into()),
            address: Some("headscale.example:50443".into()),
            api_key: Some("grpc-token".into()),
            unix_socket: None,
            insecure: false,
            json: false,
            output: None,
        };
        assert!(!conn.should_use_legacy_http_for_migrated_commands());
    }
}
