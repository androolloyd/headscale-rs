# Headscale-Go Parity Pickup Notes

Updated: 2026-05-30 12:22 ADT

## Current State

- Main worktree: `/Users/androolloyd/Development/headscale-rs-fuzz-update`
- Branch: `main`
- Latest pushed baseline before this pickup:
  `2824150 Add Postgres authkey real-client smoke`
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
- `b3eeb43` adds an env-gated production Postgres `serve` process smoke in
  `headscale-cli/tests/cli_process.rs`. It creates a temporary Postgres
  database from `HEADSCALE_DB_POSTGRES_TEST_URL`, starts the real
  `headscale serve` binary with Pg config, checks the public `/health` path,
  checks local Unix-socket gRPC health, and exercises users, preauth keys, and
  database-backed policy set/get through the CLI before dropping the temporary
  database. It skips cleanly when the env var is absent or the role cannot
  create a temporary database.
- This slice adds env-gated process coverage for Postgres direct policy DB
  bypass without a running server. The real `headscale` binary opens the
  configured Pg database through
  `policy --bypass-grpc-and-access-database-directly`, migrates the foundation
  tables, proves missing-policy error shape, and round-trips `set`, `get`, and
  `check` before dropping the temporary database.
- This slice adds an env-gated live-Postgres OIDC runtime smoke in
  `headscale-cli/src/server.rs`. It creates an OIDC user through the Pg user
  store, completes interactive wire registration through
  `PersistentPostgresOidcRegistrationHandler`, proves same-machine OIDC rekey
  replacement in the live registry, checks Go-shaped Pg node rows and route
  hostinfo preservation, runs a full map against the rekeyed node, and rebuilds
  the Pg runtime to prove restart hydration. The smoke skips cleanly when
  `HEADSCALE_DB_POSTGRES_TEST_URL` is absent.
- This slice adds paired env-gated production Postgres stock-client smoke
  scripts under `tools/real-client/postgres-authkey-*.sh` and a
  `postgres-authkey` row in `tools/real-client/smoke-matrix.sh`. The scripts
  reuse the production online/LastSeen harness with a temporary Pg database
  from `HEADSCALE_DB_POSTGRES_TEST_URL`, build Rust with `postgres-sqlx`, run
  real `headscale server`/headscale-go `serve`, mint an auth key, log in a
  stock Tailscale client, capture `tailscale debug netmap`, and assert the
  persisted node lifecycle. They skip cleanly when the Pg URL is absent.
- This slice wires the paired `postgres-authkey` stock-client row into
  `.github/workflows/real-client-parity.yml`: CI now runs on PRs and matching
  `main` pushes, starts a Postgres 16 service, installs `postgresql-client`,
  exports `HEADSCALE_DB_POSTGRES_TEST_URL`, and includes `postgres-authkey` in
  the bounded push/PR smoke set. The local environment here has no Docker
  daemon and no Pg URL, so the full stock-client/Pg execution is deferred to CI.
- This slice extends the same production Postgres stock-client harness to
  no-auth web/CLI registration with paired `postgres-web-register` Rust and
  headscale-go rows. The shared online/LastSeen harness can now run either
  auth-key or web registration against a temporary Pg database, and CI includes
  both Postgres rows in the bounded push/PR smoke set.
- This slice extends that production Postgres stock-client harness again for
  route advertisement and approval with paired `postgres-route-approve` Rust and
  headscale-go rows. The shared harness now passes `--advertise-routes`, approves
  the route through `headscale nodes approve-routes`, verifies CLI available,
  approved, and serving route state, checks the approved route in the stock
  client's netmap `AllowedIPs`, and keeps the online/LastSeen disconnect
  assertion. CI includes this Postgres route row in the bounded push/PR smoke
  set.
- This slice makes the production OIDC stock-client harness backend-aware and
  adds paired `postgres-oidc` Rust and headscale-go rows. The harness now creates
  a temporary Postgres database, builds Rust with `postgres-sqlx`, runs the mock
  OIDC confirmation flow, asserts the OIDC node/user profile rows through
  Postgres, verifies CLI node projection, and skips cleanly when
  `HEADSCALE_DB_POSTGRES_TEST_URL` is absent. CI includes this Postgres OIDC row
  in the bounded push/PR smoke set.

Current multi-agent split:

- Local critical path: Postgres runtime/import wiring. The shared
  server-local backend abstraction and Pg runtime builder now compile behind
  `headscale-cli/postgres-sqlx`, including OIDC registration and SSH-check
  approval, and Postgres foundation migration now has import/version guards.
  Backend-aware direct policy DB bypass is wired and process-covered against
  Postgres without a running server, an env-gated live-Pg runtime
  construction/register/hydration smoke is covered, and the first production
  Pg `serve` process smoke now covers listeners plus local gRPC/CLI
  health/user/preauth/API-key/policy/node admin operations. A live-Pg OIDC runtime smoke now
  covers OIDC registration, same-machine rekey, live-registry projection, full
  map output, and restart hydration. Paired env-gated production Pg
  stock-client auth-key, web-registration, route-approval, and OIDC smokes are
  now checked into the real-client matrix. CI now provisions Postgres and
  includes those rows in the push/PR real-client job.
  Remaining critical work is broader production Pg serve coverage beyond the
  auth-key, web-registration, route-approval, and OIDC map flows.
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
  candidates was fixed; quiet last-seen map bookkeeping now updates timestamps
  without waking long-poll streams; remaining high-priority follow-ups are
  combined route-via plus route-health failover smokes, direct SSH action
  rejection pins, canonical map-batcher reason/state deltas, and broader
  churn/restart map-stream tests. Runtime MapSessionHandle/Seq
  generation is not pursued for the pinned headscale-go baseline because
  upstream accepts those Tailcfg fields but leaves response
  `MapSessionHandle`/`Seq` empty.
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
adding non-upstream config. The first production Postgres `serve` process smoke
now starts the real binary and exercises public health plus local gRPC CLI
admin operations against Pg, including users, preauth keys, API keys, policy,
debug node creation, registration, node mutation, backfill, and deletion; direct
policy DB bypass now round-trips against configured Pg without a running server.
The next critical slice is broader production Pg serve coverage beyond the
auth-key, web-registration, route-approval, and OIDC map flows. The other
narrow lanes remain current-upstream CLI output drift snapshots, map/session
churn parity, and remaining route/SSH stock-client edge rows.

## Remaining Larger Parity Tracks

- Postgres runtime/import support: feature-gated Pg runtime wiring with OIDC
  registration/SSH-check approval now compiles, foundation migration has
  import/version guards, backend-aware direct policy DB bypass is wired and
  process-covered against Pg without a running server, and an env-gated live-Pg
  runtime register/hydrate smoke plus live-Pg OIDC rekey/projection/hydration
  smoke exist; the first production Pg `serve` process smoke covers public
  health plus local gRPC health/user/preauth/API-key/policy/node CLI paths, and
  paired env-gated Pg auth-key, web-registration, route-approval, and OIDC
  stock-client smokes are checked into the real-client matrix and push/PR CI now
  provisions Postgres for them; broader Pg stock-client serve smokes remain
- Broader paired route-via and route-health stock-client edge matrices beyond the covered reload/restart basics
- Broader Tailscale SSH current-head client status/stderr/profile variants
- Production restart and mutation smokes for web/CLI/OIDC policy and map churn,
  including canonical map-batcher reason/state deltas
- Native Rust DERP relay decision; sidecar DERP parity is documented and covered, but native relay is not implemented or claimed
