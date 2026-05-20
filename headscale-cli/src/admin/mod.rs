//! Operator CLI for the headscale admin HTTP surface.
//!
//! The admin GUI (#216 / commit `62b956d`) exposes `/api/v1/*` on the
//! admin listener (default `127.0.0.1:51822`) with bearer-token auth.
//! This module wraps each of those endpoints in a clap subcommand so
//! the same actions are available from the shell — matching upstream
//! `juanfont/headscale`'s CLI surface for `users` / `nodes` /
//! `preauthkeys` / `policy` / `tailnet`.
//!
//! ## Wire & auth
//!
//! Every command takes a `--server` (`$HEADSCALE_URL`) and `--token`
//! (`$HEADSCALE_ADMIN_TOKEN`). Errors are mapped onto the fixed
//! exit-code contract defined by [`ExitCode`]:
//!
//! | code | meaning                                     |
//! |------|---------------------------------------------|
//! | 0    | success                                     |
//! | 2    | bad usage (clap already exits 2 on its own) |
//! | 3    | connection failure (DNS / TCP / TLS)        |
//! | 4    | auth failure (401 / 403)                    |
//! | 5    | entity not found (404)                      |
//! | 6    | other server-side failure (4xx / 5xx / decode) |

pub mod client;
pub mod duration;
pub mod nodes;
pub mod output;
pub mod policy;
pub mod preauthkeys;
pub mod tailnet;
pub mod users;

use std::path::PathBuf;

use clap::{Args, Subcommand};

pub use client::AdminClient;
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

/// Shared connection flags. Hoisted out of each subcommand so the same
/// `--server` / `--token` / `--json` triplet works everywhere.
#[derive(Args, Debug, Clone)]
pub struct ConnectArgs {
    /// Admin URL. Falls back to `$HEADSCALE_URL`. Trailing `/` is OK.
    #[arg(long, env = "HEADSCALE_URL", global = true)]
    pub server: Option<String>,
    /// Bearer token. Falls back to `$HEADSCALE_ADMIN_TOKEN`.
    #[arg(long, env = "HEADSCALE_ADMIN_TOKEN", global = true)]
    pub token: Option<String>,
    /// Emit raw JSON instead of the default table view.
    #[arg(long, global = true)]
    pub json: bool,
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

    pub fn fmt(&self) -> OutputFormat {
        OutputFormat::from_flag(self.json)
    }
}

// ---------------------------------------------------------------------------
// clap subcommand definitions
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum UsersCmd {
    /// Create a new user.
    Create { name: String },
    /// List all users.
    List,
    /// Delete a user by name.
    Delete { name: String },
}

#[derive(Subcommand, Debug)]
pub enum NodesCmd {
    /// List registered nodes (optionally filter by user).
    List {
        #[arg(long)]
        user: Option<String>,
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
    Tags {
        #[arg(value_name = "ID")]
        id: String,
        /// Comma-separated tag list, e.g. `tag:prod,tag:web`.
        #[arg(value_name = "TAGS", value_delimiter = ',')]
        tags: Vec<String>,
    },
    /// Delete a node.
    Delete {
        #[arg(value_name = "ID")]
        id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum PreauthKeysCmd {
    /// Mint a fresh preauth key.
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
    List {
        /// Restrict to a single user.
        #[arg(long)]
        user: Option<String>,
    },
    /// Expire a key identified by its visible prefix.
    Expire {
        #[arg(value_name = "PREFIX")]
        prefix: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// Fetch the policy currently loaded on the server.
    Get,
    /// Push a policy file to the server.
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
    let client = conn.build_client()?;
    match cmd {
        UsersCmd::Create { name } => users::create(&client, name, conn.fmt()).await,
        UsersCmd::List => users::list(&client, conn.fmt()).await,
        UsersCmd::Delete { name } => users::delete(&client, name).await,
    }
}

pub async fn run_nodes(conn: &ConnectArgs, cmd: &NodesCmd) -> Result<(), AdminError> {
    let client = conn.build_client()?;
    match cmd {
        NodesCmd::List { user } => nodes::list(&client, user.as_deref(), conn.fmt()).await,
        NodesCmd::Show { id_or_name } => nodes::show(&client, id_or_name, conn.fmt()).await,
        NodesCmd::Expire { id, at } => nodes::expire(&client, id, at.as_deref()).await,
        NodesCmd::Logout { id } => nodes::logout(&client, id).await,
        NodesCmd::Rename { id, hostname } => nodes::rename(&client, id, hostname).await,
        NodesCmd::Tags { id, tags } => nodes::tags(&client, id, tags.clone()).await,
        NodesCmd::Delete { id } => nodes::delete(&client, id).await,
    }
}

pub async fn run_preauthkeys(conn: &ConnectArgs, cmd: &PreauthKeysCmd) -> Result<(), AdminError> {
    let client = conn.build_client()?;
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
                conn.fmt(),
            )
            .await
        }
        PreauthKeysCmd::List { user } => {
            preauthkeys::list(&client, user.as_deref(), conn.fmt()).await
        }
        PreauthKeysCmd::Expire { prefix } => preauthkeys::expire(&client, prefix).await,
    }
}

pub async fn run_policy(conn: &ConnectArgs, cmd: &PolicyCmd) -> Result<(), AdminError> {
    match cmd {
        PolicyCmd::Check { path } => policy::check(path),
        PolicyCmd::Get => {
            let client = conn.build_client()?;
            policy::get(&client, conn.fmt()).await
        }
        PolicyCmd::Set { path } => {
            let client = conn.build_client()?;
            policy::set(&client, path, conn.fmt()).await
        }
    }
}

pub async fn run_tailnet(conn: &ConnectArgs, cmd: &TailnetCmd) -> Result<(), AdminError> {
    let client = conn.build_client()?;
    match cmd {
        TailnetCmd::Status => tailnet::status(&client, conn.fmt()).await,
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
            json: false,
        };
        let e = conn.build_client().unwrap_err();
        assert!(matches!(e, AdminError::Local(_)));
    }

    #[test]
    fn connect_args_accept_empty_token() {
        let conn = ConnectArgs {
            server: Some("http://localhost:51822".into()),
            token: None,
            json: false,
        };
        assert!(conn.build_client().is_ok());
    }
}
