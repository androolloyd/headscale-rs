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
    /// Disable confirmation prompts.
    #[arg(long, global = true)]
    pub force: bool,
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
    Create {
        name: String,
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
    /// List all users.
    #[command(alias = "ls", alias = "show")]
    List {
        /// User identifier (ID).
        #[arg(short = 'i', long = "identifier")]
        identifier: Option<u64>,
        /// Username.
        #[arg(short = 'n', long = "name")]
        name: Option<String>,
        /// Email address.
        #[arg(short = 'e', long)]
        email: Option<String>,
    },
    /// Destroy a user.
    #[command(name = "destroy", alias = "delete")]
    Destroy {
        /// User identifier (ID).
        #[arg(short = 'i', long = "identifier")]
        identifier: Option<u64>,
        /// Username.
        #[arg(short = 'n', long = "name")]
        name: Option<String>,
    },
    /// Rename a user.
    #[command(alias = "mv")]
    Rename {
        /// User identifier (ID).
        #[arg(short = 'i', long = "identifier")]
        identifier: Option<u64>,
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
    /// List registered nodes (optionally filter by user).
    #[command(alias = "ls")]
    List {
        #[arg(short = 'u', long)]
        user: Option<String>,
    },
    /// List advertised, approved, and serving routes on nodes.
    #[command(name = "list-routes", alias = "routes", alias = "lsr")]
    ListRoutes {
        /// Restrict to one node ID. gRPC mode requires the numeric identifier.
        #[arg(short = 'i', long = "identifier", value_name = "ID")]
        id: Option<String>,
    },
    /// Show one node by numeric identifier. Legacy HTTP also accepts node_key hex or hostname.
    #[command(alias = "get")]
    Show {
        #[arg(value_name = "ID")]
        id_or_name: Option<String>,
    },
    /// Register a pending node with a user and node key.
    Register {
        #[arg(short = 'u', long)]
        user: String,
        #[arg(short = 'k', long)]
        key: String,
    },
    /// Mark a node expired. Without `--at`, expires immediately
    /// (forces re-register on the node's next /map). With `--at`,
    /// schedules expiry for the supplied ISO-8601 timestamp.
    #[command(alias = "logout", alias = "exp", alias = "e")]
    Expire {
        /// Node identifier (ID). Positional form is kept for legacy compatibility.
        #[arg(value_name = "ID")]
        id: Option<String>,
        /// Node identifier (ID).
        #[arg(short = 'i', long = "identifier", value_name = "ID")]
        identifier: Option<String>,
        /// ISO-8601 timestamp to schedule expiry at. Defaults to "now".
        #[arg(short = 'e', long = "expiry", alias = "at", value_name = "RFC3339")]
        expiry: Option<String>,
    },
    /// Rename a node (operator-driven hostname rewrite).
    Rename {
        /// New hostname in upstream form, or node ID in legacy positional form.
        #[arg(value_name = "NEW_NAME_OR_ID")]
        value: String,
        /// New hostname when using the legacy `rename ID HOSTNAME` form.
        #[arg(value_name = "HOSTNAME")]
        legacy_hostname: Option<String>,
        /// Node identifier (ID).
        #[arg(short = 'i', long = "identifier", value_name = "ID")]
        identifier: Option<String>,
    },
    /// Replace the node's forced-tags list. Empty list clears the
    /// override; tags are matched by exact string against the policy.
    #[command(alias = "tag", alias = "t")]
    Tags {
        /// Node identifier (ID). Positional form is kept for legacy compatibility.
        #[arg(value_name = "ID")]
        id: Option<String>,
        /// Node identifier (ID).
        #[arg(short = 'i', long = "identifier", value_name = "ID")]
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
        #[arg(short = 'i', long = "identifier", value_name = "ID")]
        id: String,
        /// Comma-separated route list. Empty list removes approvals.
        #[arg(short = 'r', long = "routes", alias = "route", value_delimiter = ',')]
        routes: Vec<String>,
    },
    /// Delete a node.
    #[command(alias = "del")]
    Delete {
        /// Node identifier (ID). Positional form is kept for legacy compatibility.
        #[arg(value_name = "ID")]
        id: Option<String>,
        /// Node identifier (ID).
        #[arg(short = 'i', long = "identifier", value_name = "ID")]
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
            } => {
                let id = nodes::select_node_id(id.as_deref(), identifier.as_deref())?;
                nodes::expire(&client, id, expiry.as_deref()).await
            }
            NodesCmd::Rename {
                value,
                legacy_hostname,
                identifier,
            } => {
                let (id, hostname) = nodes::select_rename_args(
                    value,
                    legacy_hostname.as_deref(),
                    identifier.as_deref(),
                )?;
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
        } => {
            let id = nodes::select_node_id(id.as_deref(), identifier.as_deref())?;
            nodes::expire_grpc(&mut client, id, expiry.as_deref(), fmt).await
        }
        NodesCmd::Rename {
            value,
            legacy_hostname,
            identifier,
        } => {
            let (id, hostname) = nodes::select_rename_args(
                value,
                legacy_hostname.as_deref(),
                identifier.as_deref(),
            )?;
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
            nodes::approve_routes_grpc(&mut client, id, routes.clone(), fmt).await
        }
        NodesCmd::Delete { id, identifier } => {
            let id = nodes::select_node_id(id.as_deref(), identifier.as_deref())?;
            nodes::delete_grpc(&mut client, id).await
        }
        NodesCmd::BackfillIps { confirm } => {
            nodes::backfillips_grpc(&mut client, *confirm || conn.force, fmt).await
        }
    }
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
        };
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
        PreauthKeysCmd::List { user } => {
            preauthkeys::list_grpc(&mut client, user.as_deref(), fmt).await
        }
        PreauthKeysCmd::Expire { prefix } => preauthkeys::expire_grpc(&mut client, prefix).await,
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

    let mut client = conn.build_grpc_client().await?;
    match cmd {
        ApiKeysCmd::Create { expiration } => {
            apikeys::create_grpc(&mut client, expiration, fmt).await
        }
        ApiKeysCmd::List => apikeys::list_grpc(&mut client, fmt).await,
        ApiKeysCmd::Expire { prefix, id } => {
            apikeys::expire_grpc(&mut client, prefix.as_deref(), *id).await
        }
        ApiKeysCmd::Delete { prefix, id } => {
            apikeys::delete_grpc(&mut client, prefix.as_deref(), *id).await
        }
    }
}

pub async fn run_policy(conn: &ConnectArgs, cmd: &PolicyCmd) -> Result<(), AdminError> {
    let fmt = conn.fmt()?;
    if conn.should_use_legacy_http_for_migrated_commands() {
        return match cmd {
            PolicyCmd::Check { path } => policy::check(path),
            PolicyCmd::Get => {
                let client = conn.build_client()?;
                policy::get(&client, fmt).await
            }
            PolicyCmd::Set { path } => {
                let client = conn.build_client()?;
                policy::set(&client, path, fmt).await
            }
        };
    }

    let mut client = conn.build_grpc_client().await?;
    match cmd {
        PolicyCmd::Check { path } => policy::check_grpc(&mut client, path).await,
        PolicyCmd::Get => policy::get_grpc(&mut client, fmt).await,
        PolicyCmd::Set { path } => policy::set_grpc(&mut client, path, fmt).await,
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
            force: false,
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
            force: false,
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
            force: false,
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
            force: false,
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
            NodesCmd::Show { id_or_name: None }
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
            } if identifier == "42"
        ));
        assert!(matches!(
            NodesHarness::try_parse_from(["headscale", "rename", "node-new", "-i", "42"])
                .unwrap()
                .action,
            NodesCmd::Rename {
                value,
                legacy_hostname: None,
                identifier: Some(identifier),
            } if value == "node-new" && identifier == "42"
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
                "--route",
                "10.0.0.0/24,192.168.0.0/24",
            ])
            .unwrap()
            .action,
            NodesCmd::ApproveRoutes { id, routes }
                if id == "42"
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
    }

    #[test]
    fn nodes_parser_keeps_explicit_legacy_server_flag_available() {
        let parsed = NodesHarness::try_parse_from([
            "headscale",
            "--server",
            "http://127.0.0.1:51822",
            "show",
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
            UsersCmd::Create { name, display_name, email, picture_url }
                if name == "alice"
                    && display_name.as_deref() == Some("Alice Example")
                    && email.as_deref() == Some("alice@example.com")
                    && picture_url.as_deref() == Some("https://example.com/alice.png")
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
}
