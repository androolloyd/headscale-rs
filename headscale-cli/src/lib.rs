//! Library surface for the `headscale` binary.
//!
//! Most of the CLI is wired together in `src/main.rs`; this lib exists
//! so the integration tests under `tests/` can import the admin
//! client + per-subcommand helpers without going through the process
//! boundary. The bin re-uses the same modules via `mod admin;` (a
//! `path` directive) — there's no duplication of source.
//!
//! ## Embedding the admin surface in other crates
//!
//! Downstream binaries may embed the upstream-compatible admin CLI under
//! their own command tree. They build on the two public items below:
//!
//!   * [`AdminCmd`] — a clap `Subcommand` enum that bundles every
//!     admin verb (`users`, `nodes`, `preauthkeys`, `auth`, `apikeys`, `policy`,
//!     `debug`). Drop it into your top-level `clap::Parser` derive
//!     with `#[command(subcommand)]` and the same `users list /
//!     nodes show / preauthkeys create …` tree appears verbatim.
//!   * [`dispatch`] — the async entry-point. Takes the parsed
//!     [`admin::ConnectArgs`] + an [`AdminCmd`] and returns the same
//!     process exit code the standalone `headscale` binary would.
//!     Stable contract: 0 success / 3 connection / 4 auth / 5 not
//!     found / 6 server-side (see `admin::ExitCode`).
//!
//! The embedded contract is the same as the standalone `headscale`
//! admin surface. Downstream-specific commands and policy layers stay
//! outside this crate; this module only exposes the shared headscale-go
//! compatibility surface.

// Keep compatibility with downstream toolchains that predate
// Duration::from_mins/from_hours while newer clippy versions prefer them.
#![allow(unknown_lints, clippy::duration_suboptimal_units)]

pub mod admin;

use clap::Subcommand;

pub use admin::{
    AdminClient, AdminError, ApiKeysCmd, AuthCmd, ConnectArgs, DebugCmd, ExitCode, NodesCmd,
    OutputFormat, PolicyCmd, PreauthKeysCmd, UsersCmd,
};

/// The full set of admin verbs exposed by the standalone `headscale`
/// binary's admin surface. Used by external crates that want to embed
/// the surface verbatim (see [`dispatch`]).
///
/// Note: the standalone `headscale` binary's top-level `Commands` enum
/// also includes `server` / `node` / `identity` / `status`. Those touch
/// local on-disk state or legacy health probes and are intentionally not
/// re-exposed here — the embedded surface is the *operator-facing*
/// control-plane surface only.
#[derive(Subcommand, Debug)]
pub enum AdminCmd {
    /// Manage users on the admin surface.
    #[command(alias = "user")]
    Users {
        #[command(subcommand)]
        action: UsersCmd,
    },
    /// Manage registered nodes.
    #[command(alias = "node")]
    Nodes {
        #[command(subcommand)]
        action: NodesCmd,
    },
    /// Manage pre-auth keys.
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
    /// Debug and testing commands.
    Debug {
        #[command(subcommand)]
        action: DebugCmd,
    },
}

/// Dispatch an [`AdminCmd`] and return the process exit code matching
/// the standalone `headscale` binary's exit-code contract:
///
/// | code | meaning                                          |
/// |------|--------------------------------------------------|
/// | 0    | success                                          |
/// | 3    | connection failure (DNS / TCP / TLS)             |
/// | 4    | auth failure (401 / 403)                         |
/// | 5    | entity not found (404)                           |
/// | 6    | other server-side failure (4xx / 5xx / decode)   |
///
/// On error the function also writes the upstream-shaped diagnostic
/// envelope to stderr, matching the standalone binary's `main()` so
/// consumers of either binary see the same output.
///
/// This is the entry point embedders call. The standalone binary's
/// `main()` still routes its admin variants through the same
/// `admin::run_*` dispatchers, so output is byte-identical.
pub async fn dispatch(connect: ConnectArgs, cmd: AdminCmd) -> i32 {
    let result: Result<(), AdminError> = match cmd {
        AdminCmd::Users { action } => admin::run_users(&connect, &action).await,
        AdminCmd::Nodes { action } => admin::run_nodes(&connect, &action).await,
        AdminCmd::Preauthkeys { user, action } => {
            admin::run_preauthkeys(&connect, user, &action).await
        }
        AdminCmd::Auth { action } => admin::run_auth(&connect, &action).await,
        AdminCmd::Apikeys { action } => admin::run_apikeys(&connect, &action).await,
        AdminCmd::Policy { action } => admin::run_policy(&connect, &action).await,
        AdminCmd::Debug { action } => admin::run_debug(&connect, &action).await,
    };
    match result {
        Ok(()) => ExitCode::Success as i32,
        Err(e) => {
            let fmt = connect.fmt().unwrap_or(OutputFormat::Table);
            eprint!("{}", admin::output::format_error(fmt, &e.to_string()));
            e.exit_code() as i32
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser, Debug)]
    struct AdminHarness {
        #[command(flatten)]
        connect: ConnectArgs,
        #[command(subcommand)]
        cmd: AdminCmd,
    }

    #[test]
    fn embedded_admin_accepts_user_aliases_from_upstream() {
        let parsed = AdminHarness::try_parse_from(["headscale", "user", "ls"]).unwrap();
        assert!(matches!(
            parsed.cmd,
            AdminCmd::Users {
                action: UsersCmd::List { .. }
            }
        ));
    }

    #[test]
    fn embedded_admin_rejects_removed_hidden_compatibility_aliases() {
        assert!(AdminHarness::try_parse_from(["headscale", "namespace", "ls"]).is_err());
        assert!(AdminHarness::try_parse_from(["headscale", "machine", "ls"]).is_err());
        assert!(AdminHarness::try_parse_from(["headscale", "tailnet", "status"]).is_err());
    }

    #[test]
    fn embedded_admin_accepts_node_aliases_from_upstream() {
        let parsed =
            AdminHarness::try_parse_from(["headscale", "node", "tag", "abc123", "tag:web"])
                .unwrap();
        match parsed.cmd {
            AdminCmd::Nodes {
                action:
                    NodesCmd::Tags {
                        id,
                        identifier,
                        tags,
                        legacy_tags,
                    },
            } => {
                assert_eq!(id.as_deref(), Some("abc123"));
                assert_eq!(identifier, None);
                assert!(tags.is_empty());
                assert_eq!(legacy_tags, vec!["tag:web"]);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn embedded_admin_accepts_preauthkey_and_apikey_aliases_from_upstream() {
        let parsed =
            AdminHarness::try_parse_from(["headscale", "pre", "new", "--user", "42"]).unwrap();
        assert!(matches!(
            parsed.cmd,
            AdminCmd::Preauthkeys {
                user: None,
                action: PreauthKeysCmd::Create { user: Some(42), .. }
            }
        ));

        let parsed =
            AdminHarness::try_parse_from(["headscale", "preauthkeys", "--user", "42", "create"])
                .unwrap();
        assert!(matches!(
            parsed.cmd,
            AdminCmd::Preauthkeys {
                user: Some(42),
                action: PreauthKeysCmd::Create { user: None, .. }
            }
        ));

        let parsed = AdminHarness::try_parse_from(["headscale", "api", "new"]).unwrap();
        assert!(matches!(
            parsed.cmd,
            AdminCmd::Apikeys {
                action: ApiKeysCmd::Create { .. }
            }
        ));
    }

    #[test]
    fn embedded_admin_accepts_auth_from_upstream() {
        let parsed = AdminHarness::try_parse_from([
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
            parsed.cmd,
            AdminCmd::Auth {
                action: AuthCmd::Register { .. }
            }
        ));

        let parsed =
            AdminHarness::try_parse_from(["headscale", "auth", "approve", "--auth-id", "id"])
                .unwrap();
        assert!(matches!(
            parsed.cmd,
            AdminCmd::Auth {
                action: AuthCmd::Approve { .. }
            }
        ));
    }

    #[test]
    fn embedded_admin_accepts_policy_aliases_from_upstream() {
        let parsed = AdminHarness::try_parse_from(["headscale", "policy", "fetch"]).unwrap();
        assert!(matches!(
            parsed.cmd,
            AdminCmd::Policy {
                action: PolicyCmd::Get { .. }
            }
        ));

        let parsed = AdminHarness::try_parse_from([
            "headscale",
            "policy",
            "update",
            "--file",
            "policy.hujson",
        ])
        .unwrap();
        assert!(matches!(
            parsed.cmd,
            AdminCmd::Policy {
                action: PolicyCmd::Set { .. }
            }
        ));

        let parsed = AdminHarness::try_parse_from([
            "headscale",
            "policy",
            "check",
            "-f",
            "policy.hujson",
            "--bypass-grpc-and-access-database-directly",
        ])
        .unwrap();
        assert!(matches!(
            parsed.cmd,
            AdminCmd::Policy {
                action: PolicyCmd::Check {
                    bypass_direct_db: true,
                    ..
                }
            }
        ));
    }

    #[test]
    fn embedded_admin_accepts_debug_create_node_from_upstream() {
        let parsed = AdminHarness::try_parse_from([
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
            parsed.cmd,
            AdminCmd::Debug {
                action: DebugCmd::CreateNode { .. }
            }
        ));
    }

    #[test]
    fn embedded_admin_accepts_upstream_output_selector() {
        let parsed =
            AdminHarness::try_parse_from(["headscale", "-o", "yaml", "users", "list"]).unwrap();
        assert_eq!(parsed.connect.output.as_deref(), Some("yaml"));
        assert_eq!(parsed.connect.fmt().unwrap(), OutputFormat::Yaml);
    }
}
