# Headscale-Go Parity Pickup Notes

Updated: 2026-05-30 08:19 ADT

## Current State

- Main worktree: `/Users/androolloyd/Development/headscale-rs-fuzz-update`
- Branch: `main`
- Latest pushed commit before the Postgres preauth-key pickup: `e53c882 Refresh parity baseline documentation`
- Remote: `origin/main` was pushed through `e53c882`
- Sibling checkout `/Users/androolloyd/Development/headscale-rs` branch `acl-consolidation` was fast-forwarded to `e53c882`
- The sibling checkout still has its pre-existing untracked `worktrees/` directory; leave it alone unless explicitly cleaning worktrees

## Just Landed

Recent accepted slices:

- `b7380f6` added a headscale-go-shaped `api_keys` migration for
  feature-gated Postgres work.
- `b7380f6` added Postgres API-key foundation primitives for create, get/list,
  expire, delete, and modern/legacy key validation paths.
- `b7380f6` extended isolated Postgres foundation tests; they skip cleanly when
  `HEADSCALE_DB_POSTGRES_TEST_URL` is not set.
- `d9b8ec9` refreshed the fuzz lockfile and made `scripts/fuzz_ci.sh` run a
  locked fuzz manifest check before building fuzz targets.
- `e53c882` refreshed parity baseline docs so the pinned v0.29 differential
  harness is no longer described as a v0.28 harness.

Verified for the API-key slice:

```sh
cargo fmt --all -- --check
git diff --check
CARGO_TARGET_DIR=target/codex-verify-db CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-db --all-targets -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-db-pg CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-db --features postgres-sqlx --all-targets -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-db CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo clippy -p headscale-db --all-targets -- -D warnings
CARGO_TARGET_DIR=target/codex-verify-db-pg CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo clippy -p headscale-db --features postgres-sqlx --all-targets -- -D warnings
```

Verified for follow-up CI/docs slices:

```sh
cargo check --locked --manifest-path headscale-core/fuzz/Cargo.toml --bins
FUZZ_TARGET=fuzz_stun FUZZ_RUNS=1 ./scripts/fuzz_ci.sh
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
`database_versions`/`policies`/`users`/`api_keys` to Go-shaped preauth-key
migration and primitives. After that lands, the next narrow lanes are
node/route Postgres primitives, current-upstream CLI output drift snapshots, or
the remaining route/SSH stock-client edge rows.

## Remaining Larger Parity Tracks

- Postgres runtime/import support, if full replacement parity includes Postgres rather than SQLite-only compatibility
- Broader paired route-via and route-health stock-client edge matrices beyond the covered reload/restart basics
- Broader Tailscale SSH current-head client status/stderr/profile variants
- Production restart and mutation smokes for web/CLI/OIDC policy and map churn
- Native Rust DERP relay decision; sidecar DERP parity is documented and covered, but native relay is not implemented or claimed
