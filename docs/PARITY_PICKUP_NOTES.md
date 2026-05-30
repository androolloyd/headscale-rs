# Headscale-Go Parity Pickup Notes

Updated: 2026-05-30 11:24 ADT

## Current State

- Main worktree: `/Users/androolloyd/Development/headscale-rs-fuzz-update`
- Branch: `main`
- Latest pushed baseline before this pickup:
  `c57ff34 Refresh parity notes after Postgres policy bypass`
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
- `79a3121` guards Postgres foundation migration with the same
  headscale-go import/version compatibility checks as SQLite: Rust-managed
  schemas are accepted, supported v0.28/current migration histories are
  allowed, unsupported version rows or untracked Go-shaped tables are rejected
  before SQLx migrations run, and Pg foundation tests cover both rejection and
  supported-history acceptance paths.
- `e032c3f` makes `policy --bypass-grpc-and-access-database-directly`
  backend-aware: SQLite keeps the existing config-driven DB path, Postgres
  builds the same configured URL under `headscale-cli/postgres-sqlx`, and
  direct `get`/`set`/`check` use Postgres policy primitives plus Pg-backed
  machine/user admins for semantic policy validation.
- This slice adds a feature-gated live-Postgres runtime construction smoke that
  uses `HEADSCALE_DB_POSTGRES_TEST_URL` with an isolated temporary schema,
  migrates the Pg foundation tables, builds the production Pg wire/admin
  runtime, registers a preauth-key node through the wire router, persists policy
  state, and rebuilds the runtime to prove Postgres node hydration. The smoke
  skips cleanly when the env var is not set.
- This slice also fixes primary-route election when the old primary withdraws
  and every remaining candidate is unhealthy: the stale primary entry is now
  removed instead of kept, with a focused regression in
  `headscale-api/src/tailscale_wire/routes.rs`.

Current multi-agent split:

- Local critical path: Postgres runtime/import wiring. The shared
  server-local backend abstraction and Pg runtime builder now compile behind
  `headscale-cli/postgres-sqlx`, including OIDC registration and SSH-check
  approval, and Postgres foundation migration now has import/version guards.
  Backend-aware direct policy DB bypass is wired, and an env-gated live-Pg
  runtime construction/register/hydration smoke is covered. Remaining critical
  work is production `serve` smokes with Pg-backed listeners and local gRPC/CLI
  calls.
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
- Explorer lane: current route/SSH and map/admin churn audit. Outcome: stale
  primary-route removal after primary withdrawal plus all-unhealthy remaining
  candidates was fixed; remaining high-priority follow-ups are combined
  route-via plus route-health failover smokes, direct SSH action rejection pins,
  quiet last-seen map bookkeeping, MapSessionHandle/Seq runtime generation, and
  reason-field deltas.
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
registration and SSH-check approval wired, Postgres foundation migration now
rejects unsupported existing version state before running migrations, and an
env-gated live-Pg runtime smoke proves register/persist/hydrate behavior without
adding non-upstream config. The next critical slice is production Postgres
`serve` smokes. The other narrow lanes remain current-upstream CLI output drift
snapshots, map/session churn parity, and remaining route/SSH stock-client edge
rows.

## Remaining Larger Parity Tracks

- Postgres runtime/import support: feature-gated Pg runtime wiring with OIDC
  registration/SSH-check approval now compiles, foundation migration has
  import/version guards, backend-aware direct policy DB bypass is wired, and an
  env-gated live-Pg runtime register/hydrate smoke exists; production
  Postgres `serve` smokes remain
- Broader paired route-via and route-health stock-client edge matrices beyond the covered reload/restart basics
- Broader Tailscale SSH current-head client status/stderr/profile variants
- Production restart and mutation smokes for web/CLI/OIDC policy and map churn,
  including quiet last-seen bookkeeping plus MapSessionHandle/Seq and reason
  field deltas
- Native Rust DERP relay decision; sidecar DERP parity is documented and covered, but native relay is not implemented or claimed
