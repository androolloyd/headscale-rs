# Headscale-Go Parity Pickup Notes

Updated: 2026-05-30 10:43 ADT

## Current State

- Main worktree: `/Users/androolloyd/Development/headscale-rs-fuzz-update`
- Branch: `main`
- Latest pushed implementation commit:
  `00f72c1 Add Postgres OIDC registration handler`
- Remote: `origin/main` should be pushed through the current local `main`
- Sibling checkout `/Users/androolloyd/Development/headscale-rs` branch `acl-consolidation` should be fast-forwarded to the current local `main`
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
- `2bd5ef5` adds a headscale-go-shaped `pre_auth_keys` migration and Postgres
  preauth-key primitives for create, get by token, list, expire, delete, and
  try-use paths.
- The node slice adds a headscale-go-shaped `nodes` migration and Postgres node
  primitives for create/read/list/update/tag/rename/route/IP/logout/delete
  paths.
- `11cb90d` makes allocator seeding consume backend-loaded node IP rows rather
  than baking that logic directly into the SQLite pool path.
- `f4d98a2` adds feature-gated Postgres
  policy-persistence and database-health trait implementations for the gRPC
  admin service without removing the explicit Postgres `serve` guard.
- `3197a37` adds a feature-gated
  `PersistentPostgresApiKeyAdmin` over the existing Postgres API-key primitives
  while leaving the default SQLite adapter unchanged.
- `a46f9ad` adds feature-gated
  `PersistentPostgresUserAdmin` and `PersistentPostgresPreauthAdmin`
  adapters, and aligns Postgres user deletion with the SQLite/headscale-go
  non-empty-user and owned-preauth cleanup semantics.
- `96477a2` adds a feature-gated
  `PersistentPostgresMachineAdmin` over the existing Postgres node primitives,
  including admin node mutations, auth-key registration persistence, runtime
  state sync, wire-registry hydration, route/address mutation, and node delete.
- `cbbfe0d` adds `headscale-cli`'s
  `postgres-sqlx` feature, a server-local runtime database enum, a
  feature-gated Postgres open/migrate path, a Pg-backed wire/admin runtime
  builder for non-OIDC server configs, Postgres startup policy loading, and
  allocator seeding from Postgres `nodes` rows while preserving the default
  SQLite-only serve rejection in builds without `postgres-sqlx`.
- `00f72c1` adds the feature-gated Postgres OIDC registration and SSH-check
  handler, wires it into the Pg runtime store, and adds a lazy-Pg-pool smoke
  proving OIDC runtime configuration does not require a live database
  connection.

Current multi-agent split:

- Local critical path: Postgres runtime/import wiring. The shared
  server-local backend abstraction and Pg runtime builder now compile behind
  `headscale-cli/postgres-sqlx`, including OIDC registration and SSH-check
  approval. Remaining critical work is direct policy DB bypass, live Postgres
  serve smokes, and Postgres import/version-guard semantics.
- Explorer lane: Postgres runtime/import blocker inventory and safe file-by-file
  backend abstraction plan. Outcome before the runtime-abstraction slice:
  server startup opened SQLite unconditionally, `headscale-db::Database` was
  SQLite-only, and the remaining blockers were the Pg runtime builder,
  Postgres OIDC handler, direct DB bypass, live Pg smokes, and import/version
  guard semantics.
- Explorer lane: residual current-upstream CLI output/help drift inventory.
  Outcome: remaining CLI work is P2 byte-for-byte success/error/prompt snapshot
  hardening, not missing core transport wiring.
- Explorer lane: residual route/SSH paired real-client coverage inventory.
  Outcome: route/SSH are broadly paired, with remaining route-via edge smokes,
  richer route-health reload+restart combinations, and a new paired cancelled
  OIDC SSH-check denial smoke slice added for Rust and headscale-go.
- Explorer lane: Postgres machine admin next-slice inventory. Outcome:
  `headscale_db::headscale_nodes` already exposes the needed Postgres node
  primitives; the feature-gated `PersistentPostgresMachineAdmin` is the safe
  adapter slice before the full runtime backend abstraction.

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

Verified so far for the preauth-key slice:

```sh
cargo fmt --all -- --check
git diff --check
CARGO_TARGET_DIR=target/codex-verify-db-pg CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-db --features postgres-sqlx --test postgres_preauth_keys -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-db CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-db --all-targets -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-db-pg CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-db --features postgres-sqlx --all-targets -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-db CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo clippy -p headscale-db --all-targets -- -D warnings
CARGO_TARGET_DIR=target/codex-verify-db-pg CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo clippy -p headscale-db --features postgres-sqlx --all-targets -- -D warnings
```

Verified for the node slice:

```sh
cargo fmt --all -- --check
git diff --check
CARGO_TARGET_DIR=target/codex-verify-db-pg-node CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-db --features postgres-sqlx --test postgres_nodes -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-db-node CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-db --all-targets -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-db-pg-node CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo test -p headscale-db --features postgres-sqlx --all-targets -- --nocapture
CARGO_TARGET_DIR=target/codex-verify-db-node CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo clippy -p headscale-db --all-targets -- -D warnings
CARGO_TARGET_DIR=target/codex-verify-db-pg-node CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 cargo clippy -p headscale-db --features postgres-sqlx --all-targets -- -D warnings
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

The current active slice is now past the first shared backend/runtime path:
`headscale-cli/postgres-sqlx` compiles a Pg runtime builder with OIDC
registration and SSH-check approval wired. The next critical slices are direct
policy DB bypass, Postgres import/version-guard semantics, and live Postgres
serve smokes. The other narrow lanes remain current-upstream CLI output drift
snapshots or the remaining route/SSH stock-client edge rows.

## Remaining Larger Parity Tracks

- Postgres runtime/import support: feature-gated Pg runtime wiring with OIDC
  registration/SSH-check approval now compiles, but direct policy DB bypass,
  live Postgres serve smokes, and Postgres import/version-guard semantics
  remain
- Broader paired route-via and route-health stock-client edge matrices beyond the covered reload/restart basics
- Broader Tailscale SSH current-head client status/stderr/profile variants
- Production restart and mutation smokes for web/CLI/OIDC policy and map churn
- Native Rust DERP relay decision; sidecar DERP parity is documented and covered, but native relay is not implemented or claimed
