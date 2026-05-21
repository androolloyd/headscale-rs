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
//! `octravpn-node` (sibling repo) re-exposes the entire admin CLI under
//! `octravpn-node headscale …` so operators only install one binary.
//! It builds on the two public items below:
//!
//!   * [`AdminCmd`] — a clap `Subcommand` enum that bundles every
//!     admin verb (`users`, `nodes`, `preauthkeys`, `policy`,
//!     `tailnet`). Drop it into your top-level `clap::Parser` derive
//!     with `#[command(subcommand)]` and the same `users list /
//!     nodes show / preauthkeys create …` tree appears verbatim.
//!   * [`dispatch`] — the async entry-point. Takes the parsed
//!     [`admin::ConnectArgs`] + an [`AdminCmd`] and returns the same
//!     process exit code the standalone `headscale` binary would.
//!     Stable contract: 0 success / 3 connection / 4 auth / 5 not
//!     found / 6 server-side (see `admin::ExitCode`).
//!
//! The contract is *byte-identical to the standalone binary*. Both
//! `headscale users list` and `octravpn-node headscale users list`
//! call the same `admin::run_users` dispatcher, so stdout, exit code,
//! and the stderr `error: …` envelope match.

pub mod admin;

use clap::Subcommand;

pub use admin::{
    AdminClient, AdminError, ConnectArgs, ExitCode, NodesCmd, OutputFormat, PolicyCmd,
    PreauthKeysCmd, TailnetCmd, UsersCmd,
};

/// The full set of admin verbs exposed by the standalone `headscale`
/// binary's admin surface. Used by external crates that want to embed
/// the surface verbatim (see [`dispatch`]).
///
/// Note: the standalone `headscale` binary's top-level `Commands` enum
/// also includes `server` / `node` / `identity` / `status` /
/// `init-config`. Those touch local on-disk state (config files,
/// keypair material) and are intentionally not re-exposed here — the
/// embedded surface is the *operator-facing* control-plane surface
/// only.
#[derive(Subcommand, Debug)]
pub enum AdminCmd {
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
/// On error the function also writes `error: <message>` to stderr,
/// matching the standalone binary's `main()` so consumers of either
/// binary see the same diagnostic prefix.
///
/// This is the entry-point [`octravpn-node`] (sibling repo) calls. The
/// standalone binary's `main()` still routes its admin variants through
/// the same `admin::run_*` dispatchers, so output is byte-identical.
pub async fn dispatch(connect: ConnectArgs, cmd: AdminCmd) -> i32 {
    let result: Result<(), AdminError> = match cmd {
        AdminCmd::Users { action } => admin::run_users(&connect, &action).await,
        AdminCmd::Nodes { action } => admin::run_nodes(&connect, &action).await,
        AdminCmd::Preauthkeys { action } => admin::run_preauthkeys(&connect, &action).await,
        AdminCmd::Policy { action } => admin::run_policy(&connect, &action).await,
        AdminCmd::Tailnet { action } => admin::run_tailnet(&connect, &action).await,
    };
    match result {
        Ok(()) => ExitCode::Success as i32,
        Err(e) => {
            eprintln!("error: {e}");
            e.exit_code() as i32
        }
    }
}
