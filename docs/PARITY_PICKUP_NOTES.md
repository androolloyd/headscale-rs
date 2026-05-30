# Headscale-Go Parity Pickup Notes

Updated: 2026-05-30 07:11 ADT

## Current State

- Main worktree: `/Users/androolloyd/Development/headscale-rs-fuzz-update`
- Branch: `main`
- Latest pushed commit before this pickup: `dc53bfb Broaden parity harness coverage`
- Remote: `origin/main` was pushed through `dc53bfb`
- Sibling checkout `/Users/androolloyd/Development/headscale-rs` branch `acl-consolidation` was fast-forwarded to `dc53bfb`
- The sibling checkout still has its pre-existing untracked `worktrees/` directory; leave it alone unless explicitly cleaning worktrees

## Just Landed

`dc53bfb` closes the latest accepted parity harness slice:

- Added TLS-ALPN controlled-CA process coverage through the production public TLS listener.
- Added the initial Postgres feature-gated foundation tests in `headscale-db`.
- Added paired route-via same-tag and SSH expired OIDC check-denial stock-client smokes.
- Updated the parity matrix and docs for those accepted coverage slices.

Verified before commit:

```sh
CARGO_TARGET_DIR=target/codex-verify-cli CARGO_INCREMENTAL=0 cargo test -p headscale-cli run_server_tls_alpn_acme_issues_through_production_tls_listener -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-cli CARGO_INCREMENTAL=0 cargo test -p headscale-cli acme -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-db CARGO_INCREMENTAL=0 cargo test -p headscale-db --all-targets -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-db-pg CARGO_INCREMENTAL=0 cargo test -p headscale-db --features postgres-sqlx --test postgres_foundation -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-clippy CARGO_INCREMENTAL=0 cargo clippy -p headscale-cli -p headscale-db --all-targets -- -D warnings
CARGO_TARGET_DIR=target/codex-verify-db-pg CARGO_INCREMENTAL=0 cargo clippy -p headscale-db --features postgres-sqlx --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
```

## Completed After Pickup

CLI structured-error snapshot parity was completed after `4d04612`:

- Add `serve_missing_noise_private_key_json.stderr` near `serve_rejects_supported_server_init_validation_before_state_startup`
- Add `serve_unsupported_postgres_json_line.stderr` beside `serve_rejects_unsupported_postgres_before_sqlite_startup`
- Add `grpc_live_health_failure_json_line.stderr` inside `live_local_grpc_health_failure_matches_process_stderr`
- Add `grpc_remote_auth_failure_json.stderr` beside `live_remote_grpc_config_success_and_auth_errors_match_process_output`

Verified test targets for that slice:

```sh
CARGO_INCREMENTAL=0 cargo test -p headscale-cli --test cli_process serve_rejects_supported_server_init_validation_before_state_startup -- --nocapture
CARGO_INCREMENTAL=0 cargo test -p headscale-cli --test cli_process serve_rejects_unsupported_postgres_before_sqlite_startup -- --nocapture
CARGO_INCREMENTAL=0 cargo test -p headscale-cli --test cli_process live_remote_grpc_config_success_and_auth_errors_match_process_output -- --nocapture
CARGO_INCREMENTAL=0 cargo test -p headscale-cli --test cli_process live_local_grpc_health_failure_matches_process_stderr -- --nocapture
```

## Next Safe Slice

The route-health policy-reload-then-production-restart stock-client smoke is the
current active slice. It adds paired Rust/headscale-go scripts that start with
one auto-approved tagged router, reload policy to add the second candidate,
restart the production server, and assert route-health failover still works.
After that lands, the next narrow lanes are current-upstream CLI output drift
snapshots, true Postgres runtime/import support, or the remaining route/SSH
stock-client edge rows.

## Remaining Larger Parity Tracks

- Postgres runtime/import support, if full replacement parity includes Postgres rather than SQLite-only compatibility
- Broader paired route-via and route-health stock-client edge matrices beyond the covered reload/restart basics
- Broader Tailscale SSH current-head client status/stderr/profile variants
- Production restart and mutation smokes for web/CLI/OIDC policy and map churn
- Native Rust DERP relay decision; sidecar DERP parity is documented and covered, but native relay is not implemented or claimed
