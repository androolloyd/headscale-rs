# Headscale-Go Parity Pickup Notes

Updated: 2026-05-25 15:08 ADT

## Current State

- Main worktree: `/Users/androolloyd/Development/headscale-rs-fuzz-update`
- Branch: `main`
- Latest pushed commit: `cdd220a Add HTTP-01 ACME process parity smoke`
- Remote: `origin/main` is pushed through `cdd220a`
- Sibling checkout `/Users/androolloyd/Development/headscale-rs` branch `acl-consolidation` was fast-forwarded to `cdd220a`
- The sibling checkout still has its pre-existing untracked `worktrees/` directory; leave it alone unless explicitly cleaning worktrees

## Just Landed

`cdd220a` closes the HTTP-01 controlled-CA production-listener parity slice:

- Refactored the local ACME test helper in `headscale-cli/src/acme_issuer.rs` into `#[cfg(test)] pub(crate) mod test_support`
- Added a test-only/internal `TlsRuntimeConfig::acme_ca_root_path` hook so `run_server` tests can trust the controlled local CA without exposing a user-facing config key
- Added `server::tests::run_server_http01_acme_issues_through_production_challenge_listener`
- Updated `docs/headscale-go-parity.md` and `docs/HARDENING.md` so HTTP-01 process coverage is no longer listed as missing

Verified before commit:

```sh
cargo fmt --all -- --check
git diff --check
cargo test -p headscale-cli acme_issuer -- --nocapture
cargo test -p headscale-cli run_server_http01_acme_issues_through_production_challenge_listener -- --nocapture
CARGO_INCREMENTAL=0 cargo clippy -p headscale-cli --all-targets -- -D warnings
```

## Next Safe Slice

The narrow next lane is CLI structured-error snapshot parity. It has no edits yet after `cdd220a`.

Suggested additive tests from the helper agent:

- Add `serve_missing_noise_private_key_json.stderr` near `serve_rejects_supported_server_init_validation_before_state_startup`
- Add `serve_unsupported_postgres_json_line.stderr` beside `serve_rejects_unsupported_postgres_before_sqlite_startup`
- Add `grpc_live_health_failure_json_line.stderr` inside `live_local_grpc_health_failure_matches_process_stderr`
- Add `grpc_remote_auth_failure_json.stderr` beside `live_remote_grpc_config_success_and_auth_errors_match_process_output`

Expected test targets after that slice:

```sh
cargo test -p headscale-cli --test cli_process serve_rejects_supported_server_init_validation_before_state_startup -- --nocapture
cargo test -p headscale-cli --test cli_process serve_rejects_unsupported_postgres_before_sqlite_startup -- --nocapture
cargo test -p headscale-cli --test cli_process live_remote_grpc_config_success_and_auth_errors_match_process_output -- --nocapture
cargo test -p headscale-cli --test cli_process live_local_grpc_health_failure_matches_process_stderr -- --nocapture
```

## Remaining Larger Parity Tracks

- TLS-ALPN controlled-CA production-process smoke through the real public TLS listener
- Postgres runtime/import support, if full replacement parity includes Postgres rather than SQLite-only compatibility
- Broader paired route-via and route-health reload/restart stock-client matrices
- Broader Tailscale SSH current-head client status/stderr/profile variants
- Production restart and mutation smokes for web/CLI/OIDC policy and map churn
- Native Rust DERP relay decision; sidecar DERP parity is documented and covered, but native relay is not implemented or claimed

