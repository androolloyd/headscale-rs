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
//! | 1    | upstream command-handler usage/runtime error |
//! | 2    | bad usage (clap already exits 2 on its own) |
//! | 3    | connection failure (DNS / TCP / TLS)        |
//! | 4    | auth failure (401 / 403)                    |
//! | 5    | entity not found (404)                      |
//! | 6    | other server-side failure (4xx / 5xx / decode) |

pub mod apikeys;
pub mod auth;
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
use std::time::Duration;

use clap::{Args, Subcommand};
use serde::Serialize;

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
    /// Cobra-style runtime usage errors returned by upstream command handlers.
    #[error("{0}")]
    Usage(String),
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
    Usage = 1,
    Connection = 3,
    Auth = 4,
    NotFound = 5,
    Server = 6,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectPolicyDatabase {
    Sqlite { path: PathBuf },
    Postgres { url: String },
    Unavailable { reason: String },
}

impl AdminError {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            Self::Connection(_) => ExitCode::Connection,
            Self::Auth(_) => ExitCode::Auth,
            Self::NotFound(_) => ExitCode::NotFound,
            Self::Usage(_) => ExitCode::Usage,
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
    #[arg(long, env = "HEADSCALE_URL", global = true, hide = true)]
    pub server: Option<String>,
    /// Legacy admin HTTP bearer token. Falls back to `$HEADSCALE_ADMIN_TOKEN`.
    #[arg(long, env = "HEADSCALE_ADMIN_TOKEN", global = true, hide = true)]
    pub token: Option<String>,
    /// Upstream gRPC address. If unset, connect to the local Unix socket.
    #[arg(
        long = "address",
        env = "HEADSCALE_CLI_ADDRESS",
        global = true,
        hide = true
    )]
    pub address: Option<String>,
    /// Upstream gRPC API key for remote addresses.
    #[arg(
        long = "api-key",
        env = "HEADSCALE_CLI_API_KEY",
        global = true,
        hide = true
    )]
    pub api_key: Option<String>,
    /// Local upstream gRPC Unix socket used when `--address` is unset.
    #[arg(
        long = "unix-socket",
        env = "HEADSCALE_UNIX_SOCKET",
        global = true,
        hide = true
    )]
    pub unix_socket: Option<PathBuf>,
    /// Disable TLS certificate verification for a remote gRPC address.
    #[arg(
        long = "insecure",
        env = "HEADSCALE_CLI_INSECURE",
        global = true,
        hide = true
    )]
    pub insecure: bool,
    /// Output format. Empty for human-readable, 'json', 'json-line' or 'yaml'.
    #[arg(
        short = 'o',
        long = "output",
        global = true,
        allow_hyphen_values = true
    )]
    pub output: Option<String>,
    /// Disable prompts and forces the execution.
    #[arg(
        long,
        global = true,
        action = clap::ArgAction::Set,
        default_value_t = false,
        default_missing_value = "true",
        num_args = 0..=1,
        require_equals = true
    )]
    pub force: bool,
    /// Database descriptor from the loaded headscale config. This is not a CLI
    /// flag; it lets `policy --bypass-grpc-and-access-database-directly` match
    /// upstream's config-driven recovery path.
    #[arg(skip)]
    pub direct_database: Option<DirectPolicyDatabase>,
    /// Upstream `cli.timeout`, populated from config or
    /// `HEADSCALE_CLI_TIMEOUT`; this is not a Rust-only CLI flag.
    #[arg(skip)]
    pub timeout_secs: Option<u64>,
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
            self.timeout_secs.map(Duration::from_secs),
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
        OutputFormat::from_output(self.output.as_deref())
    }
}

// ---------------------------------------------------------------------------
// clap subcommand definitions
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum UsersCmd {
    /// Creates a new user.
    #[command(alias = "c", alias = "new")]
    Create {
        name: String,
        #[arg(hide = true)]
        extra_args: Vec<String>,
        /// Display name.
        #[arg(short = 'd', long = "display-name")]
        display_name: Option<String>,
        /// Email address.
        #[arg(short = 'e', long)]
        email: Option<String>,
        /// Profile picture URL.
        #[arg(short = 'p', long = "picture-url")]
        picture_url: Option<String>,
    },
    /// List all the users.
    #[command(alias = "ls", alias = "show")]
    List {
        /// User identifier (ID).
        #[arg(short = 'i', long = "identifier", allow_hyphen_values = true)]
        identifier: Option<i64>,
        /// Username.
        #[arg(short = 'n', long = "name")]
        name: Option<String>,
        /// Email address.
        #[arg(short = 'e', long)]
        email: Option<String>,
    },
    /// Destroys a user.
    #[command(name = "destroy", alias = "delete")]
    Destroy {
        /// User identifier (ID).
        #[arg(short = 'i', long = "identifier", allow_hyphen_values = true)]
        identifier: Option<i64>,
        /// Username.
        #[arg(short = 'n', long = "name")]
        name: Option<String>,
    },
    /// Renames a user.
    #[command(alias = "mv")]
    Rename {
        /// User identifier (ID).
        #[arg(short = 'i', long = "identifier", allow_hyphen_values = true)]
        identifier: Option<i64>,
        /// Username.
        #[arg(short = 'n', long = "name")]
        name: Option<String>,
        /// New username.
        #[arg(short = 'r', long = "new-name")]
        new_name: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum NodesCmd {
    /// List nodes.
    #[command(alias = "ls", alias = "show")]
    List {
        #[arg(short = 'u', long)]
        user: Option<String>,
    },
    /// List advertised, approved, and serving routes on nodes.
    #[command(name = "list-routes", alias = "routes", alias = "lsr")]
    ListRoutes {
        /// Restrict to one node ID. gRPC mode requires the numeric identifier.
        #[arg(
            short = 'i',
            long = "identifier",
            value_name = "ID",
            allow_hyphen_values = true
        )]
        id: Option<String>,
    },
    /// Show one node by numeric identifier. Legacy HTTP also accepts node_key hex or hostname.
    #[command(name = "get", hide = true)]
    Show {
        #[arg(value_name = "ID")]
        id_or_name: Option<String>,
    },
    /// Registers a node to your network.
    Register {
        #[arg(short = 'u', long)]
        user: String,
        #[arg(short = 'k', long)]
        key: String,
    },
    /// Mark a node expired. Without `--expiry`, expires immediately
    /// (forces re-register on the node's next /map). With `--expiry`,
    /// schedules expiry for the supplied ISO-8601 timestamp. With
    /// `--disable`, clears key expiry so the node never expires.
    #[command(alias = "logout", alias = "exp", alias = "e")]
    Expire {
        /// Node identifier (ID). Positional form is kept for legacy compatibility.
        #[arg(value_name = "ID")]
        id: Option<String>,
        /// Node identifier (ID).
        #[arg(
            short = 'i',
            long = "identifier",
            value_name = "ID",
            allow_hyphen_values = true
        )]
        identifier: Option<String>,
        /// ISO-8601 timestamp to schedule expiry at. Defaults to "now".
        #[arg(short = 'e', long = "expiry", value_name = "RFC3339")]
        expiry: Option<String>,
        /// Disable key expiry for this node.
        #[arg(short = 'd', long = "disable")]
        disable: bool,
    },
    /// Renames a node in your network.
    Rename {
        /// New hostname.
        #[arg(value_name = "NEW_NAME")]
        new_name: String,
        /// Node identifier (ID).
        #[arg(
            short = 'i',
            long = "identifier",
            value_name = "ID",
            allow_hyphen_values = true
        )]
        identifier: Option<String>,
    },
    /// Replace the node's forced-tags list. Empty list clears the
    /// override; tags are matched by exact string against the policy.
    #[command(name = "tag", alias = "tags", alias = "t")]
    Tags {
        /// Node identifier (ID). Positional form is kept for legacy compatibility.
        #[arg(value_name = "ID")]
        id: Option<String>,
        /// Node identifier (ID).
        #[arg(
            short = 'i',
            long = "identifier",
            value_name = "ID",
            allow_hyphen_values = true
        )]
        identifier: Option<String>,
        /// Comma-separated tag list, e.g. `tag:prod,tag:web`.
        #[arg(short = 't', long = "tags", value_delimiter = ',')]
        tags: Vec<String>,
        /// Legacy positional comma-separated tag list.
        #[arg(value_name = "TAGS", value_delimiter = ',')]
        legacy_tags: Vec<String>,
    },
    /// Replace the approved routes for a node.
    #[command(name = "approve-routes")]
    ApproveRoutes {
        /// Node ID. gRPC mode requires the numeric identifier.
        #[arg(
            short = 'i',
            long = "identifier",
            value_name = "ID",
            allow_hyphen_values = true
        )]
        id: Option<String>,
        /// Comma-separated route list. Empty list removes approvals.
        #[arg(short = 'r', long = "routes", value_delimiter = ',')]
        routes: Vec<String>,
    },
    /// Delete a node.
    #[command(alias = "del")]
    Delete {
        /// Node identifier (ID). Positional form is kept for legacy compatibility.
        #[arg(value_name = "ID")]
        id: Option<String>,
        /// Node identifier (ID).
        #[arg(
            short = 'i',
            long = "identifier",
            value_name = "ID",
            allow_hyphen_values = true
        )]
        identifier: Option<String>,
    },
    /// Backfill missing node IP addresses.
    #[command(name = "backfillips")]
    BackfillIps {
        /// Confirm the backfill operation. The global --force flag also confirms.
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum PreauthKeysCmd {
    /// Creates a new preauthkey.
    #[command(alias = "c", alias = "new")]
    Create {
        /// User identifier (ID).
        #[arg(short = 'u', long)]
        user: Option<u64>,
        /// Make the preauthkey reusable.
        #[arg(long)]
        reusable: bool,
        /// Preauthkey for ephemeral nodes.
        #[arg(long)]
        ephemeral: bool,
        /// Tags to automatically assign to node.
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
        /// Human-readable expiration of the key (e.g. 30m, 24h).
        #[arg(short = 'e', long = "expiration", default_value = "1h")]
        expires_in: String,
    },
    /// List all preauthkeys.
    #[command(alias = "ls", alias = "show")]
    List,
    /// Expire a preauthkey.
    #[command(alias = "revoke", alias = "exp", alias = "e")]
    Expire {
        /// Authkey ID.
        #[arg(short = 'i', long = "id")]
        id: Option<u64>,
    },
    /// Delete a preauth key by numeric ID.
    #[command(alias = "del", alias = "rm", alias = "d")]
    Delete {
        /// Authkey ID.
        #[arg(short = 'i', long = "id")]
        id: Option<u64>,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuthCmd {
    /// Register a node to your network.
    Register {
        /// User.
        #[arg(short = 'u', long = "user")]
        user: String,
        /// Auth ID.
        #[arg(long = "auth-id")]
        auth_id: String,
        #[arg(hide = true)]
        extra_args: Vec<String>,
    },
    /// Approve a pending authentication request.
    Approve {
        /// Auth ID.
        #[arg(long = "auth-id")]
        auth_id: String,
        #[arg(hide = true)]
        extra_args: Vec<String>,
    },
    /// Reject a pending authentication request.
    Reject {
        /// Auth ID.
        #[arg(long = "auth-id")]
        auth_id: String,
        #[arg(hide = true)]
        extra_args: Vec<String>,
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
    Get {
        /// Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running.
        #[arg(long = "bypass-grpc-and-access-database-directly")]
        bypass_direct_db: bool,
    },
    /// Push a policy file to the server.
    #[command(alias = "put", alias = "update")]
    Set {
        /// Path to a policy file in HuJSON format.
        #[arg(short = 'f', long = "file", value_name = "FILE", required = true)]
        path: PathBuf,
        /// Uses the headscale config to directly access the database, bypassing gRPC and does not require the server to be running.
        #[arg(long = "bypass-grpc-and-access-database-directly")]
        bypass_direct_db: bool,
    },
    /// Check the Policy file for errors.
    Check {
        /// Path to a policy file in HuJSON format.
        #[arg(short = 'f', long = "file", value_name = "FILE", required = true)]
        path: PathBuf,
        /// Open the database directly (no gRPC, no running server) to resolve user references and to evaluate the policy's tests and sshTests blocks. Required when those checks are needed.
        #[arg(long = "bypass-grpc-and-access-database-directly")]
        bypass_direct_db: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum TailnetCmd {
    /// Show tailnet-wide status (DERP regions, DNS, policy).
    Status,
}

#[derive(Subcommand, Debug)]
pub enum DebugCmd {
    /// Create a node that can be registered with `nodes register`.
    #[command(name = "create-node")]
    CreateNode {
        /// User.
        #[arg(short = 'u', long)]
        user: String,
        /// Registration key.
        #[arg(short = 'k', long)]
        key: String,
        /// Node name.
        #[arg(long)]
        name: String,
        /// List (or repeated flags) of routes to advertise.
        #[arg(short = 'r', long = "route", value_delimiter = ',')]
        routes: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// Dispatchers — invoked from `main.rs`
// ---------------------------------------------------------------------------

pub async fn run_users(conn: &ConnectArgs, cmd: &UsersCmd) -> Result<(), AdminError> {
    let fmt = conn.fmt()?;
    if conn.should_use_legacy_http_for_migrated_commands() {
        let client = conn.build_client()?;
        return match cmd {
            UsersCmd::Create { name, .. } => users::create(&client, name, fmt).await,
            UsersCmd::List { .. } => users::list(&client, fmt).await,
            UsersCmd::Destroy { name, .. } => {
                let name = name.as_deref().ok_or_else(|| {
                    AdminError::Local("--name is required for legacy HTTP user delete".into())
                })?;
                users::delete(&client, name).await
            }
            UsersCmd::Rename { .. } => Err(AdminError::Local(
                "user rename requires the upstream gRPC transport".into(),
            )),
        };
    }
    let mut client = conn.build_grpc_client().await?;
    match cmd {
        UsersCmd::Create {
            name,
            display_name,
            email,
            picture_url,
            ..
        } => {
            users::create_grpc(
                &mut client,
                name,
                display_name.as_deref().unwrap_or_default(),
                email.as_deref().unwrap_or_default(),
                picture_url.as_deref().unwrap_or_default(),
                fmt,
            )
            .await
        }
        UsersCmd::List {
            identifier,
            name,
            email,
        } => {
            users::list_grpc(
                &mut client,
                *identifier,
                name.as_deref(),
                email.as_deref(),
                fmt,
            )
            .await
        }
        UsersCmd::Destroy { identifier, name } => {
            users::destroy_grpc(&mut client, *identifier, name.as_deref(), conn.force, fmt).await
        }
        UsersCmd::Rename {
            identifier,
            name,
            new_name,
        } => users::rename_grpc(&mut client, *identifier, name.as_deref(), new_name, fmt).await,
    }
}

pub async fn run_nodes(conn: &ConnectArgs, cmd: &NodesCmd) -> Result<(), AdminError> {
    let fmt = conn.fmt()?;
    if matches!(cmd, NodesCmd::Register { .. }) {
        eprintln!("use 'headscale auth register --auth-id <id> --user <user>' instead");
    }
    if conn.should_use_legacy_http_for_migrated_commands() {
        let client = conn.build_client()?;
        return match cmd {
            NodesCmd::List { user } => nodes::list(&client, user.as_deref(), fmt).await,
            NodesCmd::ListRoutes { id } => nodes::list_routes(&client, id.as_deref(), fmt).await,
            NodesCmd::Show { id_or_name } => match id_or_name {
                Some(id_or_name) => nodes::show(&client, id_or_name, fmt).await,
                None => nodes::list(&client, None, fmt).await,
            },
            NodesCmd::Register { .. } => Err(AdminError::Local(
                "node register requires the upstream gRPC transport".into(),
            )),
            NodesCmd::Expire {
                id,
                identifier,
                expiry,
                disable,
            } => {
                if *disable {
                    return Err(AdminError::Local(
                        "node expiry disable requires the upstream gRPC transport".into(),
                    ));
                }
                let id = nodes::select_node_id(id.as_deref(), identifier.as_deref())?;
                nodes::expire(&client, id, expiry.as_deref()).await
            }
            NodesCmd::Rename {
                new_name,
                identifier,
            } => {
                let (id, hostname) = nodes::select_rename_args(new_name, identifier.as_deref())?;
                nodes::rename(&client, id, hostname).await
            }
            NodesCmd::Tags {
                id,
                identifier,
                tags,
                legacy_tags,
            } => {
                let id = nodes::select_node_id(id.as_deref(), identifier.as_deref())?;
                nodes::tags(&client, id, nodes::merged_tags(tags, legacy_tags)).await
            }
            NodesCmd::ApproveRoutes { id, routes } => {
                let id = id.as_deref().ok_or_else(|| {
                    AdminError::Local("node identifier is required; use --identifier".into())
                })?;
                nodes::approve_routes(&client, id, routes.clone(), fmt).await
            }
            NodesCmd::Delete { id, identifier } => {
                let id = nodes::select_node_id(id.as_deref(), identifier.as_deref())?;
                nodes::delete(&client, id).await
            }
            NodesCmd::BackfillIps { .. } => Err(AdminError::Local(
                "nodes backfillips requires the upstream gRPC transport".into(),
            )),
        };
    }

    validate_grpc_node_identifier(cmd)?;

    let mut client = conn.build_grpc_client().await?;
    match cmd {
        NodesCmd::List { user } => nodes::list_grpc(&mut client, user.as_deref(), fmt).await,
        NodesCmd::ListRoutes { id } => {
            nodes::list_routes_grpc(&mut client, id.as_deref(), fmt).await
        }
        NodesCmd::Show { id_or_name } => match id_or_name {
            Some(id_or_name) => nodes::show_grpc(&mut client, id_or_name, fmt).await,
            None => nodes::list_grpc(&mut client, None, fmt).await,
        },
        NodesCmd::Register { user, key } => nodes::register_grpc(&mut client, user, key, fmt).await,
        NodesCmd::Expire {
            id,
            identifier,
            expiry,
            disable,
        } => {
            let id = nodes::select_node_id(id.as_deref(), identifier.as_deref())?;
            nodes::expire_grpc(&mut client, id, expiry.as_deref(), *disable, fmt).await
        }
        NodesCmd::Rename {
            new_name,
            identifier,
        } => {
            let (id, hostname) = nodes::select_rename_args(new_name, identifier.as_deref())?;
            nodes::rename_grpc(&mut client, id, hostname, fmt).await
        }
        NodesCmd::Tags {
            id,
            identifier,
            tags,
            legacy_tags,
        } => {
            let id = nodes::select_node_id(id.as_deref(), identifier.as_deref())?;
            nodes::tags_grpc(&mut client, id, nodes::merged_tags(tags, legacy_tags), fmt).await
        }
        NodesCmd::ApproveRoutes { id, routes } => {
            let id = id
                .as_deref()
                .ok_or_else(upstream_required_identifier_error)?;
            nodes::approve_routes_grpc(&mut client, id, routes.clone(), fmt).await
        }
        NodesCmd::Delete { id, identifier } => {
            let id = nodes::select_node_id(id.as_deref(), identifier.as_deref())?;
            nodes::delete_grpc(&mut client, id, conn.force, fmt).await
        }
        NodesCmd::BackfillIps { confirm } => {
            nodes::backfillips_grpc(&mut client, *confirm, conn.force, fmt).await
        }
    }
}

fn validate_grpc_node_identifier(cmd: &NodesCmd) -> Result<(), AdminError> {
    let missing = match cmd {
        NodesCmd::Expire { identifier, .. }
        | NodesCmd::Tags { identifier, .. }
        | NodesCmd::Rename { identifier, .. }
        | NodesCmd::Delete { identifier, .. } => identifier.is_none(),
        NodesCmd::ApproveRoutes { id, .. } => id.is_none(),
        NodesCmd::List { .. }
        | NodesCmd::ListRoutes { .. }
        | NodesCmd::Show { .. }
        | NodesCmd::Register { .. }
        | NodesCmd::BackfillIps { .. } => false,
    };

    if missing {
        return Err(upstream_required_identifier_error());
    }

    validate_grpc_node_id_values(cmd)
}

fn validate_grpc_node_id_values(cmd: &NodesCmd) -> Result<(), AdminError> {
    match cmd {
        NodesCmd::ListRoutes { id: Some(id) }
        | NodesCmd::Rename {
            identifier: Some(id),
            ..
        }
        | NodesCmd::ApproveRoutes { id: Some(id), .. } => {
            nodes::parse_node_id(id)?;
        }
        NodesCmd::Expire {
            identifier: Some(id),
            ..
        }
        | NodesCmd::Tags {
            identifier: Some(id),
            ..
        }
        | NodesCmd::Delete {
            identifier: Some(id),
            ..
        } => {
            nodes::parse_node_id(id)?;
        }
        NodesCmd::List { .. }
        | NodesCmd::ListRoutes { id: None }
        | NodesCmd::Show { .. }
        | NodesCmd::Register { .. }
        | NodesCmd::BackfillIps { .. }
        | NodesCmd::Expire {
            identifier: None, ..
        }
        | NodesCmd::Tags {
            identifier: None, ..
        }
        | NodesCmd::Delete {
            identifier: None, ..
        }
        | NodesCmd::Rename {
            identifier: None, ..
        }
        | NodesCmd::ApproveRoutes { id: None, .. } => {}
    }
    Ok(())
}

fn upstream_required_identifier_error() -> AdminError {
    AdminError::Usage(r#"required flag(s) "identifier" not set"#.into())
}

pub async fn run_preauthkeys(conn: &ConnectArgs, cmd: &PreauthKeysCmd) -> Result<(), AdminError> {
    let fmt = conn.fmt()?;
    if conn.should_use_legacy_http_for_migrated_commands() {
        let client = conn.build_client()?;
        return match cmd {
            PreauthKeysCmd::Create {
                user,
                reusable,
                ephemeral,
                tags,
                expires_in,
            } => {
                let secs = duration::parse_duration_secs(expires_in).map_err(AdminError::Local)?;
                let user = user.unwrap_or_default().to_string();
                preauthkeys::create(
                    &client,
                    &user,
                    *reusable,
                    *ephemeral,
                    tags.clone(),
                    secs,
                    fmt,
                )
                .await
            }
            PreauthKeysCmd::List => preauthkeys::list(&client, fmt).await,
            PreauthKeysCmd::Expire { id } => {
                let id = id.unwrap_or_default();
                if id == 0 {
                    return Err(AdminError::Usage(
                        "missing --id parameter: missing parameters".into(),
                    ));
                }
                preauthkeys::expire(&client, &id.to_string()).await
            }
            PreauthKeysCmd::Delete { .. } => Err(AdminError::Local(
                "preauthkeys delete requires the upstream gRPC transport".into(),
            )),
        };
    }

    match cmd {
        PreauthKeysCmd::Expire { id } | PreauthKeysCmd::Delete { id }
            if id.unwrap_or_default() == 0 =>
        {
            return Err(AdminError::Usage(
                "missing --id parameter: missing parameters".into(),
            ));
        }
        _ => {}
    }

    let mut client = conn.build_grpc_client().await?;
    match cmd {
        PreauthKeysCmd::Create {
            user,
            reusable,
            ephemeral,
            tags,
            expires_in,
        } => {
            let secs = duration::parse_duration_secs(expires_in).map_err(AdminError::Local)?;
            let user = user.unwrap_or_default();
            preauthkeys::create_grpc(
                &mut client,
                user,
                *reusable,
                *ephemeral,
                tags.clone(),
                secs,
                fmt,
            )
            .await
        }
        PreauthKeysCmd::List => preauthkeys::list_grpc(&mut client, fmt).await,
        PreauthKeysCmd::Expire { id } => preauthkeys::expire_grpc(&mut client, *id, fmt).await,
        PreauthKeysCmd::Delete { id } => preauthkeys::delete_grpc(&mut client, *id, fmt).await,
    }
}

pub async fn run_auth(conn: &ConnectArgs, cmd: &AuthCmd) -> Result<(), AdminError> {
    let fmt = conn.fmt()?;
    if conn.should_use_legacy_http_for_migrated_commands() {
        return Err(AdminError::Local(
            "auth commands require the upstream gRPC transport".into(),
        ));
    }

    let mut client = conn.build_grpc_client().await?;
    match cmd {
        AuthCmd::Register { user, auth_id, .. } => {
            auth::register_grpc(&mut client, user, auth_id, fmt).await
        }
        AuthCmd::Approve { auth_id, .. } => auth::approve_grpc(&mut client, auth_id, fmt).await,
        AuthCmd::Reject { auth_id, .. } => auth::reject_grpc(&mut client, auth_id, fmt).await,
    }
}

pub async fn run_apikeys(conn: &ConnectArgs, cmd: &ApiKeysCmd) -> Result<(), AdminError> {
    let fmt = conn.fmt()?;
    if conn.should_use_legacy_http_for_migrated_commands() {
        let client = conn.build_client()?;
        return match cmd {
            ApiKeysCmd::Create { expiration } => apikeys::create(&client, expiration, fmt).await,
            ApiKeysCmd::List => apikeys::list(&client, fmt).await,
            ApiKeysCmd::Expire { prefix, id } => {
                apikeys::expire(&client, prefix.as_deref(), *id).await
            }
            ApiKeysCmd::Delete { prefix, id } => {
                apikeys::delete(&client, prefix.as_deref(), *id).await
            }
        };
    }

    match cmd {
        ApiKeysCmd::Expire { prefix, id } | ApiKeysCmd::Delete { prefix, id } => {
            apikeys::validate_selector(prefix.as_deref(), *id)?;
        }
        ApiKeysCmd::Create { .. } | ApiKeysCmd::List => {}
    }

    let mut client = conn.build_grpc_client().await?;
    match cmd {
        ApiKeysCmd::Create { expiration } => {
            apikeys::create_grpc(&mut client, expiration, fmt).await
        }
        ApiKeysCmd::List => apikeys::list_grpc(&mut client, fmt).await,
        ApiKeysCmd::Expire { prefix, id } => {
            apikeys::expire_grpc(&mut client, prefix.as_deref(), *id, fmt).await
        }
        ApiKeysCmd::Delete { prefix, id } => {
            apikeys::delete_grpc(&mut client, prefix.as_deref(), *id, fmt).await
        }
    }
}

pub async fn run_policy(conn: &ConnectArgs, cmd: &PolicyCmd) -> Result<(), AdminError> {
    let fmt = conn.fmt()?;
    if cmd.bypasses_direct_database() {
        policy::confirm_direct_database_access(conn.force)?;
        let database = conn.direct_database.as_ref().ok_or_else(|| {
            AdminError::Local(
                "direct database policy access requires a loaded headscale config".into(),
            )
        })?;
        return match cmd {
            PolicyCmd::Check { path, .. } => policy::check_direct_db(database, path).await,
            PolicyCmd::Get { .. } => policy::get_direct_db(database, fmt).await,
            PolicyCmd::Set { path, .. } => policy::set_direct_db(database, path, fmt).await,
        };
    }

    if conn.should_use_legacy_http_for_migrated_commands() {
        return match cmd {
            PolicyCmd::Check { path, .. } => policy::check(path),
            PolicyCmd::Get { .. } => {
                let client = conn.build_client()?;
                policy::get(&client, fmt).await
            }
            PolicyCmd::Set { path, .. } => {
                let client = conn.build_client()?;
                policy::set(&client, path, fmt).await
            }
        };
    }

    let mut client = conn.build_grpc_client().await?;
    match cmd {
        PolicyCmd::Check { path, .. } => policy::check_grpc(&mut client, path).await,
        PolicyCmd::Get { .. } => policy::get_grpc(&mut client, fmt).await,
        PolicyCmd::Set { path, .. } => policy::set_grpc(&mut client, path, fmt).await,
    }
}

impl PolicyCmd {
    fn bypasses_direct_database(&self) -> bool {
        match self {
            Self::Get { bypass_direct_db }
            | Self::Set {
                bypass_direct_db, ..
            }
            | Self::Check {
                bypass_direct_db, ..
            } => *bypass_direct_db,
        }
    }
}

pub async fn run_health(conn: &ConnectArgs) -> Result<(), AdminError> {
    let fmt = conn.fmt()?;
    let mut client = conn.build_grpc_client().await?;
    let response = client.health().await?;
    if fmt.is_structured() {
        output::print_structured(
            fmt,
            &HealthOutput {
                database_connectivity: response.database_connectivity,
            },
        )?;
    } else {
        println!();
    }
    Ok(())
}

pub async fn run_debug(conn: &ConnectArgs, cmd: &DebugCmd) -> Result<(), AdminError> {
    let fmt = conn.fmt()?;
    let mut client = conn.build_grpc_client().await?;
    match cmd {
        DebugCmd::CreateNode {
            user,
            key,
            name,
            routes,
        } => nodes::debug_create_node_grpc(&mut client, user, key, name, routes.clone(), fmt).await,
    }
}

pub async fn run_tailnet(conn: &ConnectArgs, cmd: &TailnetCmd) -> Result<(), AdminError> {
    let client = conn.build_client()?;
    let fmt = conn.fmt()?;
    match cmd {
        TailnetCmd::Status => tailnet::status(&client, fmt).await,
    }
}

#[derive(Debug, Serialize)]
struct HealthOutput {
    database_connectivity: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct UsersHarness {
        #[command(subcommand)]
        action: UsersCmd,
    }

    #[derive(Parser)]
    struct NodesHarness {
        #[arg(long, global = true)]
        server: Option<String>,
        #[arg(long, global = true)]
        address: Option<String>,
        #[arg(long, global = true)]
        force: bool,
        #[command(subcommand)]
        action: NodesCmd,
    }

    #[derive(Parser)]
    struct DebugHarness {
        #[command(subcommand)]
        action: DebugCmd,
    }

    #[derive(Parser)]
    struct PreauthKeysHarness {
        #[command(subcommand)]
        action: PreauthKeysCmd,
    }

    #[derive(Parser)]
    struct AuthHarness {
        #[command(subcommand)]
        action: AuthCmd,
    }

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
            AdminError::Usage("x".into()).exit_code() as i32,
            ExitCode::Usage as i32
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
            output: None,
            force: false,
            direct_database: None,
            timeout_secs: None,
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
            output: None,
            force: false,
            direct_database: None,
            timeout_secs: None,
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
            output: Some("json-line".into()),
            force: false,
            direct_database: None,
            timeout_secs: None,
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
            output: None,
            force: false,
            direct_database: None,
            timeout_secs: None,
        };
        assert!(!conn.should_use_legacy_http_for_migrated_commands());
    }

    #[test]
    fn nodes_accept_upstream_node_command_shapes() {
        assert!(matches!(
            NodesHarness::try_parse_from(["headscale", "list", "-u", "alice"])
                .unwrap()
                .action,
            NodesCmd::List { user } if user.as_deref() == Some("alice")
        ));
        assert!(matches!(
            NodesHarness::try_parse_from(["headscale", "show"])
                .unwrap()
                .action,
            NodesCmd::List { user: None }
        ));
        assert!(matches!(
            NodesHarness::try_parse_from(["headscale", "get", "42"])
                .unwrap()
                .action,
            NodesCmd::Show { id_or_name: Some(id_or_name) } if id_or_name == "42"
        ));
        assert!(matches!(
            NodesHarness::try_parse_from([
                "headscale",
                "register",
                "-u",
                "alice",
                "-k",
                "nodekey:abc",
            ])
            .unwrap()
            .action,
            NodesCmd::Register { user, key } if user == "alice" && key == "nodekey:abc"
        ));
        assert!(matches!(
            NodesHarness::try_parse_from([
                "headscale",
                "expire",
                "-i",
                "42",
                "-e",
                "2025-08-27T10:00:00Z",
            ])
            .unwrap()
            .action,
            NodesCmd::Expire {
                id: None,
                identifier: Some(identifier),
                expiry: Some(expiry),
                disable: false,
            } if identifier == "42" && expiry == "2025-08-27T10:00:00Z"
        ));
        assert!(matches!(
            NodesHarness::try_parse_from(["headscale", "logout", "-i", "42"])
                .unwrap()
                .action,
            NodesCmd::Expire {
                id: None,
                identifier: Some(identifier),
                expiry: None,
                disable: false,
            } if identifier == "42"
        ));
        assert!(matches!(
            NodesHarness::try_parse_from(["headscale", "expire", "-i", "42", "--disable"])
                .unwrap()
                .action,
            NodesCmd::Expire {
                id: None,
                identifier: Some(identifier),
                expiry: None,
                disable: true,
            } if identifier == "42"
        ));
        assert!(matches!(
            NodesHarness::try_parse_from(["headscale", "rename", "node-new", "-i", "42"])
                .unwrap()
                .action,
            NodesCmd::Rename {
                new_name,
                identifier: Some(identifier),
            } if new_name == "node-new" && identifier == "42"
        ));
        assert!(matches!(
            NodesHarness::try_parse_from([
                "headscale",
                "tag",
                "-i",
                "42",
                "-t",
                "tag:prod,tag:web",
            ])
            .unwrap()
            .action,
            NodesCmd::Tags {
                id: None,
                identifier: Some(identifier),
                tags,
                legacy_tags,
            } if identifier == "42"
                && tags == vec!["tag:prod".to_string(), "tag:web".to_string()]
                && legacy_tags.is_empty()
        ));
        assert!(matches!(
            NodesHarness::try_parse_from(["headscale", "delete", "-i", "42"])
                .unwrap()
                .action,
            NodesCmd::Delete {
                id: None,
                identifier: Some(identifier),
            } if identifier == "42"
        ));
        assert!(matches!(
            NodesHarness::try_parse_from([
                "headscale",
                "approve-routes",
                "--identifier",
                "42",
                "--routes",
                "10.0.0.0/24,192.168.0.0/24",
            ])
            .unwrap()
            .action,
            NodesCmd::ApproveRoutes { id, routes }
                if id.as_deref() == Some("42")
                    && routes == vec![
                        "10.0.0.0/24".to_string(),
                        "192.168.0.0/24".to_string()
                    ]
        ));
        assert!(matches!(
            NodesHarness::try_parse_from(["headscale", "--force", "backfillips"]).unwrap(),
            NodesHarness {
                force: true,
                action: NodesCmd::BackfillIps { confirm: false },
                ..
            }
        ));
        assert!(
            NodesHarness::try_parse_from([
                "headscale",
                "expire",
                "--identifier",
                "42",
                "--at",
                "2025-08-27T10:00:00Z",
            ])
            .is_err(),
            "current upstream only accepts --expiry"
        );
        assert!(
            NodesHarness::try_parse_from([
                "headscale",
                "approve-routes",
                "--identifier",
                "42",
                "--route",
                "10.0.0.0/24",
            ])
            .is_err(),
            "current upstream only accepts --routes"
        );
    }

    #[test]
    fn grpc_node_identifier_preflight_matches_upstream_required_flag_error() {
        for cmd in [
            NodesHarness::try_parse_from(["headscale", "expire"])
                .unwrap()
                .action,
            NodesHarness::try_parse_from(["headscale", "rename", "node-new"])
                .unwrap()
                .action,
            NodesHarness::try_parse_from(["headscale", "tag", "--tags", "tag:prod"])
                .unwrap()
                .action,
            NodesHarness::try_parse_from(["headscale", "delete"])
                .unwrap()
                .action,
            NodesHarness::try_parse_from([
                "headscale",
                "approve-routes",
                "--routes",
                "10.0.0.0/24",
            ])
            .unwrap()
            .action,
        ] {
            let err = validate_grpc_node_identifier(&cmd).unwrap_err();
            assert_eq!(err.to_string(), r#"required flag(s) "identifier" not set"#);
            assert!(matches!(err, AdminError::Usage(_)));
        }
    }

    #[test]
    fn nodes_parser_keeps_explicit_legacy_server_flag_available() {
        let parsed = NodesHarness::try_parse_from([
            "headscale",
            "--server",
            "http://127.0.0.1:51822",
            "get",
            "node-key-hex",
        ])
        .unwrap();

        assert_eq!(parsed.server.as_deref(), Some("http://127.0.0.1:51822"));
        assert!(matches!(
            parsed.action,
            NodesCmd::Show { id_or_name: Some(id_or_name) } if id_or_name == "node-key-hex"
        ));
    }

    #[test]
    fn users_accept_upstream_filter_and_profile_flags() {
        assert!(matches!(
            UsersHarness::try_parse_from([
                "headscale",
                "create",
                "alice",
                "--display-name",
                "Alice Example",
                "--email",
                "alice@example.com",
                "--picture-url",
                "https://example.com/alice.png",
            ])
            .unwrap()
            .action,
            UsersCmd::Create { name, display_name, email, picture_url, .. }
                if name == "alice"
                    && display_name.as_deref() == Some("Alice Example")
                    && email.as_deref() == Some("alice@example.com")
                    && picture_url.as_deref() == Some("https://example.com/alice.png")
        ));
        assert!(matches!(
            UsersHarness::try_parse_from(["headscale", "create", "alice", "ignored"])
                .unwrap()
                .action,
            UsersCmd::Create { name, .. } if name == "alice"
        ));
        assert!(matches!(
            UsersHarness::try_parse_from(["headscale", "list", "--identifier", "42"])
                .unwrap()
                .action,
            UsersCmd::List {
                identifier: Some(42),
                ..
            }
        ));
        assert!(matches!(
            UsersHarness::try_parse_from(["headscale", "list", "--identifier", "-1"])
                .unwrap()
                .action,
            UsersCmd::List {
                identifier: Some(-1),
                ..
            }
        ));
        assert!(matches!(
            UsersHarness::try_parse_from(["headscale", "destroy", "--name", "alice"])
                .unwrap()
                .action,
            UsersCmd::Destroy { name, .. } if name.as_deref() == Some("alice")
        ));
        assert!(matches!(
            UsersHarness::try_parse_from([
                "headscale",
                "rename",
                "--name",
                "alice",
                "--new-name",
                "bob",
            ])
            .unwrap()
            .action,
            UsersCmd::Rename { name, new_name, .. }
                if name.as_deref() == Some("alice") && new_name == "bob"
        ));
    }

    #[test]
    fn debug_accepts_upstream_create_node_shape() {
        let parsed = DebugHarness::try_parse_from([
            "headscale",
            "create-node",
            "--name",
            "node-one",
            "-u",
            "alice",
            "-k",
            "abcdefghijklmnopqrstuvwx",
            "-r",
            "10.0.0.0/24",
            "-r",
            "10.0.1.0/24,10.0.2.0/24",
        ])
        .unwrap();

        match parsed.action {
            DebugCmd::CreateNode {
                user,
                key,
                name,
                routes,
            } => {
                assert_eq!(user, "alice");
                assert_eq!(key, "abcdefghijklmnopqrstuvwx");
                assert_eq!(name, "node-one");
                assert_eq!(
                    routes,
                    vec![
                        "10.0.0.0/24".to_string(),
                        "10.0.1.0/24".to_string(),
                        "10.0.2.0/24".to_string()
                    ]
                );
            }
        }
    }

    #[test]
    fn preauthkeys_accepts_upstream_expire_and_delete_by_id() {
        assert!(matches!(
            PreauthKeysHarness::try_parse_from(["headscale", "expire", "--id", "41"])
                .unwrap()
                .action,
            PreauthKeysCmd::Expire { id: Some(41) }
        ));
        assert!(matches!(
            PreauthKeysHarness::try_parse_from(["headscale", "delete", "--id", "42"])
                .unwrap()
                .action,
            PreauthKeysCmd::Delete { id: Some(42) }
        ));
        assert!(matches!(
            PreauthKeysHarness::try_parse_from(["headscale", "del", "-i", "43"])
                .unwrap()
                .action,
            PreauthKeysCmd::Delete { id: Some(43) }
        ));
    }

    #[test]
    fn preauthkeys_create_uses_upstream_expiration_flag_and_default() {
        match PreauthKeysHarness::try_parse_from(["headscale", "create", "--user", "42"])
            .unwrap()
            .action
        {
            PreauthKeysCmd::Create {
                user, expires_in, ..
            } => {
                assert_eq!(user, Some(42));
                assert_eq!(expires_in, "1h");
            }
            other => panic!("unexpected command: {other:?}"),
        }

        match PreauthKeysHarness::try_parse_from([
            "headscale",
            "create",
            "--user",
            "42",
            "--expiration",
            "30m",
        ])
        .unwrap()
        .action
        {
            PreauthKeysCmd::Create { expires_in, .. } => assert_eq!(expires_in, "30m"),
            other => panic!("unexpected command: {other:?}"),
        }

        assert!(
            PreauthKeysHarness::try_parse_from([
                "headscale",
                "create",
                "--user",
                "42",
                "--expires-in",
                "24h",
            ])
            .is_err(),
            "current upstream only accepts --expiration"
        );
        assert!(
            PreauthKeysHarness::try_parse_from(["headscale", "list", "--user", "alice"]).is_err(),
            "current upstream preauthkeys list has no --user filter"
        );
    }

    #[test]
    fn auth_accepts_upstream_command_shapes() {
        assert!(matches!(
            AuthHarness::try_parse_from([
                "headscale",
                "register",
                "--user",
                "alice",
                "--auth-id",
                "hskey-authreq-abcdefghijklmnopqrstuvwx",
                "ignored",
            ])
            .unwrap()
            .action,
            AuthCmd::Register { user, auth_id, .. }
                if user == "alice" && auth_id == "hskey-authreq-abcdefghijklmnopqrstuvwx"
        ));
        assert!(matches!(
            AuthHarness::try_parse_from(["headscale", "approve", "--auth-id", "pending-id", "ignored"])
                .unwrap()
                .action,
            AuthCmd::Approve { auth_id, .. } if auth_id == "pending-id"
        ));
        assert!(matches!(
            AuthHarness::try_parse_from(["headscale", "reject", "--auth-id", "pending-id"])
                .unwrap()
                .action,
            AuthCmd::Reject { auth_id, .. } if auth_id == "pending-id"
        ));
    }
}
