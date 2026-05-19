//! Library surface for the `headscale` binary.
//!
//! Most of the CLI is wired together in `src/main.rs`; this lib exists
//! so the integration tests under `tests/` can import the admin
//! client + per-subcommand helpers without going through the process
//! boundary. The bin re-uses the same modules via `mod admin;` (a
//! `path` directive) — there's no duplication of source.

pub mod admin;
