# Headscale-Go Parity Pickup Notes

Updated: 2026-05-30 08:01 ADT

## Current State

- Main worktree: `/Users/androolloyd/Development/headscale-rs-fuzz-update`
- Branch: `main`
- Latest pushed commit before the Postgres users pickup: `018b50a Expand parity coverage for CLI SSH and Postgres`
- Remote: `origin/main` was pushed through `018b50a`
- Sibling checkout `/Users/androolloyd/Development/headscale-rs` branch `acl-consolidation` was fast-forwarded to `018b50a`
- The sibling checkout still has its pre-existing untracked `worktrees/` directory; leave it alone unless explicitly cleaning worktrees

## Just Landed

`018b50a` closes the latest accepted multi-agent parity slice:

- Added exact CLI/OpenAPI drift fixes for `disableExpiry`, deprecated `nodes register`, completion shell help, `mockoidc`, and `dumpConfig`.
- Added paired stock-client SSH `check` smokes for CLI approval and wrong-user OIDC denial.
- Expanded the feature-gated Postgres foundation with `policies` migration/primitives and health checks.
- Updated the parity matrix and docs for those accepted coverage slices.

Verified before commit:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-cli raw_exact_help_matches_cobra_forms -- --nocapture
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-cli --test cli_process exact_help_aliases_match_current_upstream_snapshots -- --nocapture
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-cli --test cli_process operator_top_level_command_help_matches_snapshots -- --nocapture
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-cli --test cli_process mockoidc_help_and_missing_env_do_not_load_config -- --nocapture
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-api --lib swagger_api_v1_serves_upstream_openapi_document -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-db CARGO_INCREMENTAL=0 cargo test -p headscale-db --all-targets -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-db-pg CARGO_INCREMENTAL=0 cargo test -p headscale-db --features postgres-sqlx --all-targets -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-clippy CARGO_INCREMENTAL=0 cargo clippy -p headscale-cli -p headscale-api -p headscale-db --all-targets -- -D warnings
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

The current active slice is expanding the Postgres foundation from
`database_versions`/`policies` to Go-shaped `users` migration and user/OIDC
CRUD primitives. After that lands, the next narrow lanes are API-key/preauth
Postgres primitives, node/route Postgres primitives, current-upstream CLI output
drift snapshots, or the remaining route/SSH stock-client edge rows.

## Remaining Larger Parity Tracks

- Postgres runtime/import support, if full replacement parity includes Postgres rather than SQLite-only compatibility
- Broader paired route-via and route-health stock-client edge matrices beyond the covered reload/restart basics
- Broader Tailscale SSH current-head client status/stderr/profile variants
- Production restart and mutation smokes for web/CLI/OIDC policy and map churn
- Native Rust DERP relay decision; sidecar DERP parity is documented and covered, but native relay is not implemented or claimed
