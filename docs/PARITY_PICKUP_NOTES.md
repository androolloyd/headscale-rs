# Headscale-Go Parity Pickup Notes

Updated: 2026-06-02 15:58 ADT

## Current State

- Main worktree: `/Users/androolloyd/Development/headscale-rs-fuzz-update`
- Branch: `main`
- Latest pushed baseline before this pickup:
  `d76ecc3`
- Remote: `origin/main` should be pushed through the current local `main`
- Sibling checkout `/Users/androolloyd/Development/headscale-rs` branch `acl-consolidation` should be fast-forwarded to the current local `main`
- The sibling checkout still has its pre-existing untracked `worktrees/` directory; leave it alone unless explicitly cleaning worktrees

## Just Landed

Recent accepted slices:

- This route/via pure Rust slice pins current-head
  `TestIssue3233ViaInternetExitVisibility`: an `autogroup:internet`
  `grants[].via` rule includes the matching tagged exit node's default routes
  and excludes non-matching exit nodes from the viewer's route effects.
- Current tag-expiry slice matches headscale-go's tagged-node restart guard:
  existing tagged nodes that send `Auth=nil` with Go zero `Expiry` return the
  current tagged register identity and keep nil node-key expiry instead of
  treating the zero timestamp as logout.
- Current auth/map-churn slice suppresses stale NodeStore worker rekey churn
  when an auth-completion rekey and same-batch delete remove the final node
  before the batch completes. Rekey-style map-change wakes now revalidate final
  node presence, and focused `Stream:true` coverage proves observers receive
  only the delayed `PeersRemoved` delta after the map-batcher tick.
- This route-edge slice adds paired `route-via-health-restart` and
  `postgres-route-via-health-restart` Rust/headscale-go rows for current-head
  same-tag `grants[].via` route ownership following route-health failover after
  a same-URL production restart. `restart-persistence-common.sh` now allows
  the combined route-via/route-health mode to cross the restart boundary while
  preserving the existing no-restart wrappers, and the push/PR smoke selector
  includes both new rows. The Postgres stock-client matrix now has ninety-six
  rows.
- This native DERP slice adds the Rust-only `postgres-derp-native-restart`
  stock-client row. It runs production Postgres with native Rust embedded DERP,
  proves STUN/map/forced-DERP relay before restart, restarts the same Rust
  server URL, waits for both stock clients to reconnect, and proves STUN,
  DERP-map, and forced-DERP relay again. The headscale-go matrix entry is an
  explicit no-equivalent skip because upstream embedded DERP does not exercise
  the Rust native relay shutdown health/restarting frames. The Postgres
  stock-client matrix now has ninety-seven rows.
- Current map-churn slice suppresses stale NodeStore worker upsert churn when a
  same-batch delete removes the node before the batch completes. Upsert-style
  map-change wakes now revalidate final node presence, and focused registry plus
  `Stream:true` tests prove observers receive only the delayed `PeersRemoved`
  delta after the map-batcher tick.
- Current map-churn slice aligns direct admin expiry/logout with
  headscale-go `SetNodeExpiry`: live observers receive `node added`
  full-peer updates, while scheduled expiry scanning remains the
  `key expiry` patch path.
- Current map-churn slice also aligns admin rename observer churn with
  headscale-go's persisted-node fallback: the renamed node receives a
  self-only `Node` update and connected observers receive a `node added`
  `PeersChanged` update containing the renamed peer.
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
- This slice extends that production Postgres `serve` smoke to prove the same
  temporary Pg-backed admin stores are reachable through the authenticated
  public grpc-gateway and the optional remote TCP gRPC listener. It checks
  unauthenticated grpc-gateway rejection, API-key-authenticated
  `/api/v1/health` and `/api/v1/user`, remote gRPC `health`/`users list`, and
  remote invalid-token error text before expiring/deleting the Pg-backed API
  key. The real-client CI workflow now runs this focused cargo test with its
  Postgres 16 service before the paired stock-client matrix.
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
- This slice broadens the same production Postgres OIDC stock-client harness
  with paired `postgres-oidc-restart` and
  `postgres-oidc-route-approve-restart` Rust/headscale-go rows. They prove OIDC
  reconnect, Pg-backed node/user/profile state, CLI projection, and OIDC
  route-approval state survive a real server restart, and they are included in
  the bounded push/PR real-client smoke set.
- This slice makes the production restart-persistence stock-client harness
  backend-aware and adds paired `postgres-web-register-restart` and
  `postgres-restart-persistence` Rust/headscale-go rows. They prove Postgres
  web/CLI registration reconnects across a real server restart and that
  Pg-backed route approval, tag mutation, peer map churn, and `/debug/batcher`
  connected-state recovery survive the same production restart boundary.
- This slice also adds paired `postgres-web-register-route-approve`
  Rust/headscale-go rows over the existing online/LastSeen harness, covering the
  cross-path where a web-registration pending cache carries advertised route
  metadata before Postgres-backed CLI route approval.
- This slice expands the backend-aware restart harness into current-head
  route-edge coverage with paired `postgres-route-via-restart`,
  `postgres-route-via-reload-restart`,
  `postgres-route-via-multiprefix-restart`,
  `postgres-route-via-multiprefix-reload-restart`,
  `postgres-route-health-restart`, and `postgres-route-health-reload-restart`
  rows. They cover Pg-backed persisted nodes/routes/policies across production
  restart while exercising `grants[].via`, route-via policy reload,
  route-health failover, and route-health policy reload behavior against Rust
  and headscale-go.
- This slice broadens those Postgres route-edge restart rows with paired
  `postgres-route-via-multiprefix-restart`,
  `postgres-route-health-primary-restart`,
  `postgres-route-health-all-unhealthy-restart`,
  `postgres-route-health-mixed-exit-restart`, and
  `postgres-route-health-mixed-exit-all-unhealthy-restart` rows. They cover
  multi-prefix `grants[].via`, route-health primary selection after restart,
  degraded all-unhealthy route-health retention, and mixed exit-node/subnet
  router separation across Rust/headscale-go production restart.
- This slice removes the restart harness restriction that kept route-health
  policy reload separate from mixed-exit/all-unhealthy restart modes and adds
  paired `postgres-route-health-mixed-exit-all-unhealthy-reload-restart` rows.
  They prove tagged exit-route auto-approval, route-health policy reload,
  Postgres restart hydration, mixed exit-node separation, failover, and
  all-unhealthy last-known subnet owner retention against Rust and headscale-go.
- This slice adds paired `postgres-route-exit-node` production Postgres
  stock-client rows. They exercise exit-node advertisement through stock
  `tailscaled`, Pg-backed CLI approval, netmap projection, and online/LastSeen
  assertions against Rust and headscale-go.
- This slice adds paired `postgres-web-register-policy-churn-restart` production
  Postgres stock-client rows. They reuse the two-client web-registration
  database-policy churn path, assert peer maps move from `0,0` to `1,1`, restart
  the same production server URL, and assert the post-reload peer visibility
  remains hydrated after reconnect. The checked-in Postgres stock-client matrix
  now has one hundred seven rows after the DERP WebSocket and prefix-family
  route-preservation restart rows.
- This slice also promotes the existing paired
  `postgres-oidc-policy-churn-restart` row into the bounded push/PR smoke set.
  It covers production Postgres OIDC registration, file-policy mutation via
  SIGHUP, stock-client peer/profile convergence, and server restart hydration
  against Rust and headscale-go.
- This slice also promotes the existing paired
  `postgres-web-register-custom-domain` row into the bounded push/PR smoke set.
  It covers no-auth web registration over production Postgres while projecting
  a custom MagicDNS base domain through stock-client DNS suffix assertions
  against Rust and headscale-go.
- This slice also promotes the existing paired
  `postgres-ssh-profile-subdomain-deny` row into the bounded push/PR smoke set.
  It carries the required SSH profile subdomain-deny edge into the production
  Postgres stock-client process path, with policy profile matching and
  Tailscale SSH denial assertions against Rust and headscale-go.

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
  stock-client auth-key, web-registration, route-approval, exit-node
  route-approval, web-registration route-approval, OIDC, OIDC restart, OIDC route-approval restart,
  web-registration restart, restart-persistence, route-via restart,
  route-via reload+restart, route-via multiprefix restart, route-via multiprefix reload+restart, route-health, route-health reload,
  route-health all-unhealthy, route-health restart, route-health primary-selection restart, route-health reload+restart, route-health
  all-unhealthy restart, route-health mixed-exit restart, and route-health
  mixed-exit all-unhealthy restart, plus route-health mixed-exit all-unhealthy
  reload+restart smokes are now checked into the real-client
  matrix. CI now provisions Postgres and includes those rows in the push/PR
  real-client job.
  Remaining critical work is broader production Pg serve coverage beyond the
  covered auth-key, web-registration, route-approval, OIDC map/restart, and
  route/tag/route-health restart-persistence flows.
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
  without waking long-poll streams; direct SSH action rejection pins now cover
  missing Noise identity, unknown destination, malformed/unknown auth IDs,
  binding mismatches, cancellation, and denied auth verdicts without seeding
  check-period auto-approval. A paired regular-overlap same-tag route-via plus
  route-health failover smoke now asserts stock-client route ownership follows
  HA primary failover and sticky recovery. A bounded canonical map-change
  reason/content history now owns upstream-shaped reasons, target/origin nodes,
  content flags, peer changed/removed/patch state, bounded response types, and
  merge semantics for node add/update/delete, online/offline transitions,
  endpoint/DERP updates, key expiry, policy/DNS/DERP config changes, pings,
  route updates, and route-health changes without adding free-form Prometheus
  labels. A pending per-node map-change batcher foundation now matches
  upstream add-to-batch behavior for full-update supersession,
  targeted/broadcast splits, deleted-node pending cleanup, and
  `BatchChangeDelay` tick-drained publishing; production `Stream:true`
  delivery now consumes those published batches while preserving the
  generation-watch fallback for non-batcher embedders/tests. Remaining
  high-priority follow-ups are actual NodeStore worker batching semantics
  and broader churn/restart map-stream tests. Runtime
  MapSessionHandle/Seq
  generation is not pursued for the pinned headscale-go baseline because
  upstream accepts those Tailcfg fields but leaves response
  `MapSessionHandle`/`Seq` empty.
  Persistent auth-key node hydration now derives the live ephemeral flag from
  the assigned preauth key, matching headscale-go's `Node.IsEphemeral` restart
  behavior.
  Operator `SetTags` calls now reject empty tag lists at the SQLite/Postgres
  node-store and in-memory registry boundaries, preserving existing tags like
  headscale-go's `ErrCannotRemoveAllTags` path.
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

- Added `serve_missing_noise_private_key_json.stderr` near `serve_rejects_supported_server_init_validation_before_state_startup`
- Added `serve_unsupported_postgres_json.stderr` and
  `serve_unsupported_postgres_json_line.stderr` beside
  `serve_rejects_unsupported_postgres_before_sqlite_startup`
- Added `grpc_live_health_failure_json.stderr` and
  `grpc_live_health_failure_json_line.stderr` inside
  `live_local_grpc_health_failure_matches_process_stderr`
- Added `grpc_remote_auth_failure_json.stderr` beside `live_remote_grpc_config_success_and_auth_errors_match_process_output`
- Unknown `-o/--output` selectors now match upstream by falling back to human
  output/error formatting instead of failing local validation.

API auth/error text follow-up:

- Direct authenticated gRPC health coverage now table-drives missing
  authorization metadata, opaque/non-UTF8 metadata, non-Bearer schemes, empty
  bearer tokens, invalid bearer tokens, and valid API-key success against the
  same upstream-style status messages.
- Remote CLI process snapshots now include json-line connection-failure output
  beside the existing human and JSON snapshots.

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
now starts the real binary and exercises public health, local gRPC CLI admin,
public grpc-gateway API-key auth, and remote TCP gRPC API-key auth against Pg,
including users, preauth keys, API keys, policy, debug node creation,
registration, node mutation, backfill, and deletion; direct policy DB bypass now
round-trips against configured Pg without a running server. The next critical
slice is broader production Pg stock-client/mutation coverage beyond the
already-paired auth-key, web-registration, route-approval, exit-node,
web-registration route-approval, OIDC, OIDC restart, route-via, route-health,
and restart-persistence rows listed below.
The other narrow lanes remain current-upstream CLI output drift snapshots,
map/session churn parity, and remaining route/SSH stock-client edge rows.

## Remaining Larger Parity Tracks

- Postgres runtime/import support: feature-gated Pg runtime wiring with OIDC
  registration/SSH-check approval now compiles, foundation migration has
  import/version guards, backend-aware direct policy DB bypass is wired and
  process-covered against Pg without a running server, and an env-gated live-Pg
  runtime register/hydrate smoke plus live-Pg OIDC rekey/projection/hydration
  smoke exist; the first production Pg `serve` process smoke covers public
  health plus local gRPC health/user/preauth/API-key/policy/node CLI paths, and
  paired env-gated Pg auth-key, one-time auth-key rejection, expired auth-key
  rejection, online/LastSeen, web-registration, route-approval, exit-node
  route-approval, web-registration route-approval, OIDC, OIDC restart, OIDC route-approval
  restart, web-registration restart, restart-persistence, route-via restart,
  route-via reload+restart, route-via multiprefix restart, route-via multiprefix reload+restart, route-health all-unhealthy, route-health restart, route-health
  primary-selection restart, route-health reload+restart, route-health
  all-unhealthy restart, route-health mixed-exit restart, route-health
  mixed-exit reload+restart, route-health mixed-exit all-unhealthy restart, and
  route-health mixed-exit all-unhealthy reload+restart stock-client smokes are
  checked into the real-client matrix.
  The production Pg stock-client harness also covers tagged preauth, post-login
  tag replacement, invalid tag-update rejection, and web reauth clearing forced
  tags through paired `postgres-tagged-preauth`, `postgres-tag-update`,
  `postgres-tag-update-invalid`, `postgres-tag-reauth-clear`,
  `postgres-acl-allow`, `postgres-acl-empty`, and
  `postgres-acl-autogroup-self` rows. Push/PR CI now provisions Postgres for
  all ninety-seven Pg rows, including
  `postgres-authkey-nonreusable`, `postgres-authkey-expired`,
  `postgres-authkey-relogin-same-user`,
  `postgres-authkey-relogin-expired`,
  `postgres-authkey-relogin-different-user`,
  `postgres-authkey-relogin-deleted`,
  `postgres-authkey-relogin-route-preserve`,
  `postgres-taildrop-capmap`, `postgres-randomize-client-port`,
  `postgres-derp-private`, `postgres-derp-native`,
  `postgres-derp-native-restart`,
  `postgres-online-lastseen`, `postgres-ping-lifecycle`,
  `postgres-policy-churn`, `postgres-magicdns`,
  `postgres-magicdns-custom-domain`,
  `postgres-extra-records`, `postgres-dns-disabled`, `postgres-dns-edge`,
  `postgres-dns-hot-reload`,
  `postgres-magicdns-ipv6-only`, `postgres-prefix-family-dual-stack`,
  `postgres-prefix-family-ipv4-only`, `postgres-prefix-family-ipv6-only`,
  `postgres-web-register-tags`, `postgres-web-register-unowned-tag`,
  `postgres-route-advertise`, `postgres-route-primary`,
  `postgres-route-primary-restart`,
  `postgres-route-primary-failover`, `postgres-route-primary-sticky`,
  `postgres-route-primary-withdraw`,
  `postgres-web-register-route-approve-restart`, `postgres-acl-allow`,
  `postgres-route-via`, `postgres-route-via-same-tag`, `postgres-route-via-health`,
  `postgres-route-via-health-restart`, `postgres-route-via-reload`,
  `postgres-route-via-multiprefix`, `postgres-route-via-multiprefix-reload`,
  `postgres-route-via-same-tag-restart`, `postgres-route-health`,
  `postgres-route-health-all-unhealthy`, `postgres-route-health-all-unhealthy-reload`,
  `postgres-route-health-mixed-exit`,
  `postgres-ssh`, `postgres-ssh-oidc-check`,
  `postgres-ssh-cli-check`, `postgres-ssh-oidc-check-period-cache`,
  `postgres-ssh-accept-env`, `postgres-ssh-localpart`,
  `postgres-ssh-profile-variants`, and the paired wrong-user, expired, and
  cancelled OIDC SSH-check denial rows plus private DERP sidecar/STUN/relay
  coverage; broader Pg process-level serve/mutation smokes remain for the
  remaining registration/config surfaces
- Broader paired route-via and route-health stock-client edge matrices for new
  upstream semantics beyond the now-symmetric default/Postgres reload/restart
  row set
- Broader Tailscale SSH current-head client status/stderr/profile variants;
  the policy-level `acceptEnv`, `check` hold-and-delegate, and host-destination
  rejection scenarios are now promoted into the default Go-vs-Rust differential
  gate
- Production restart and mutation smokes for web/CLI/OIDC policy and map churn,
  especially remaining NodeStore reason/state edge deltas
- Native Rust DERP relay runtime hardening beyond the focused stock-client
  restart row; sidecar DERP parity remains documented and covered, and
  headscale-go has no equivalent for Rust native DERP shutdown frames

## 2026-05-31 GivenName parity slice

- Registration now preserves raw client `Hostname` separately from DNS
  `GivenName`; SQLite/Postgres node writes auto-derive empty `given_name`
  from the raw hostname with Tailscale `dnsname.SanitizeHostname` semantics,
  `node` fallback, and current upstream's monotonic collision suffixes.
- Explicit rename and explicit update preservation now use
  `dnsname.ValidLabel`-style validation, so one-byte labels and uppercase are
  accepted, while dots/underscores/edge hyphens are rejected.
- Same-machine auth-key, web/CLI, OIDC, and runtime Hostinfo update paths now
  preserve admin-renamed GivenNames. Auto-derived names still recompute on
  Hostinfo hostname changes, including the `node` fallback case for empty
  sanitized labels.
- Verified locally with `headscale-db --lib` and `headscale-api --features
  admin --lib`; clippy/format gates should be rerun before the final commit if
  more edits land.

## 2026-05-31 Postgres tag-mutation smoke slice

- `tools/real-client/online-lastseen-common.sh` can now load a generated or
  caller-provided ACL policy through the production CLI, mint tagged preauth
  keys, force web reauth, set node tags, assert tag state, and run the same
  lifecycle checks against SQLite or Postgres.
- Added paired Rust/headscale-go Postgres rows for tagged preauth, tag update,
  invalid tag update, and web reauth tag clearing:
  `postgres-tagged-preauth`, `postgres-tag-update`,
  `postgres-tag-update-invalid`, and `postgres-tag-reauth-clear`.
- The real-client workflow includes those rows in `PR_SMOKES`; this slice moved
  the matrix to twenty-six Postgres stock-client rows.

## 2026-05-31 Postgres SSH OIDC-check smoke slice

- `tools/real-client/ssh-oidc-check-smoke.sh` can now run against either SQLite
  or a temporary Postgres database, builds Rust with `postgres-sqlx` for the Pg
  target, writes backend-specific config for Rust and headscale-go, loads the
  SSH policy into the database-backed policy store, and drops the temp database
  on cleanup.
- Added paired `postgres-ssh-oidc-check` Rust/headscale-go rows and included
  the row in `PR_SMOKES`; the matrix now has twenty-seven Postgres
  stock-client rows.

## 2026-05-31 Postgres SSH-check denial smoke slice

- Added paired Postgres rows for CLI-approved SSH checks plus wrong-user,
  expired, and cancelled OIDC SSH-check denials:
  `postgres-ssh-cli-check`, `postgres-ssh-oidc-check-wrong-user`,
  `postgres-ssh-oidc-check-deny`, and `postgres-ssh-oidc-check-cancel`.
- The real-client workflow includes these rows in `PR_SMOKES`; the matrix now
  has thirty-one Postgres stock-client rows.

## 2026-05-31 Postgres web-registration tag smoke slice

- Added paired `postgres-web-register-tags` Rust/headscale-go rows over the
  backend-aware online/LastSeen harness. The row proves web/CLI registration
  with an owned requested tag against a temporary Postgres database.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix moved
  to thirty-two Postgres stock-client rows.

## 2026-05-31 Node DB helper parity slice

- Added Go-shaped node read helpers for ID-filtered `ListNodes`, peer listing,
  assigned-preauth-key ephemeral listing, and user+raw-hostname lookup across
  SQLite and feature-gated Postgres.
- SQLite unit coverage and the Postgres `postgres_nodes` integration contract
  now lock the upstream empty-filter, partial-filter, self-excluded peer, and
  ephemeral-key semantics.

## 2026-05-31 Postgres route-advertise smoke slice

- Added paired `postgres-route-advertise` Rust/headscale-go rows over the
  backend-aware online/LastSeen harness. The row proves advertised-but-unapproved
  route projection against a temporary Postgres database.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  thirty-three Postgres stock-client rows.

## 2026-05-31 Postgres web-registration unowned-tag smoke slice

- Extended the backend-aware online/LastSeen harness with an expected
  web-registration failure path that asserts rejected registration does not
  create nodes.
- Added paired `postgres-web-register-unowned-tag` Rust/headscale-go rows over
  a temporary Postgres database. The row proves web/CLI registration rejects a
  requested tag that is not owned by the registering user.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  thirty-four Postgres stock-client rows.

## 2026-05-31 Postgres route-health mixed-exit reload+restart smoke slice

- Added paired `postgres-route-health-mixed-exit-reload-restart`
  Rust/headscale-go rows over the restart persistence harness. The row proves
  mixed subnet-router/exit-node route-health separation survives policy reload
  and production Postgres restart without requiring the all-unhealthy variant.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  thirty-five Postgres stock-client rows.

## 2026-05-31 Postgres route-via same-tag restart smoke slice

- Added paired `postgres-route-via-same-tag-restart` Rust/headscale-go rows over
  the restart persistence harness. The row proves same-tag multi-router
  `grants[].via` route ownership survives production Postgres restart.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  thirty-six Postgres stock-client rows.

## 2026-05-31 Postgres online/LastSeen smoke slice

- Added paired `postgres-online-lastseen` Rust/headscale-go rows over the
  backend-aware online/LastSeen harness. The row proves the standalone
  production Postgres lifecycle smoke records online state and LastSeen after
  disconnect, without relying only on the broader auth-key row.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  thirty-seven Postgres stock-client rows.

## 2026-05-31 Postgres DNS extra-record smoke slice

- Extended the backend-aware online/LastSeen harness with production DNS knobs:
  MagicDNS, `tailscale up --accept-dns`, config-backed `dns.extra_records`,
  stock-client status assertions for the MagicDNS suffix, and netmap assertions
  for `DNS.ExtraRecords`.
- Added paired `postgres-extra-records` Rust/headscale-go rows over a temporary
  Postgres database. The row proves the MagicDNS suffix and configured DNS
  extra records project through the production Postgres serving path.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  thirty-eight Postgres stock-client rows.

## 2026-05-31 Postgres MagicDNS custom-domain smoke slice

- Added paired `postgres-magicdns-custom-domain` Rust/headscale-go rows over
  the backend-aware online/LastSeen harness and temporary Postgres database.
- The row proves a non-default `dns.base_domain` projects into stock-client
  MagicDNS status through the production Postgres serving path.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  thirty-nine Postgres stock-client rows.

## 2026-05-31 Postgres DNS disabled smoke slice

- Extended the backend-aware online/LastSeen harness with
  `REAL_CLIENT_EXPECT_NO_MAGIC_DNS`, matching the existing two-client
  DNS-disabled assertions for the single-client production Postgres lifecycle
  path.
- Added paired `postgres-dns-disabled` Rust/headscale-go rows over a temporary
  Postgres database. The row proves disabled MagicDNS fallback names project
  through the production Postgres serving path.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  forty Postgres stock-client rows.

## 2026-05-31 Postgres DNS edge smoke slice

- Extended the backend-aware online/LastSeen harness with production DNS
  nameserver/split-route config knobs plus stock-client assertions for
  `DNS.FallbackResolvers`, `DNS.Routes`, and typed extra records.
- Added paired `postgres-dns-edge` Rust/headscale-go rows over a temporary
  Postgres database. The row proves split DNS routes, fallback resolver
  projection, MagicDNS status, and AAAA/CNAME extra records through the
  production Postgres serving path.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  forty-one Postgres stock-client rows.

## 2026-05-31 Postgres IPv6-only MagicDNS smoke slice

- Extended the backend-aware online/LastSeen harness with configurable
  `prefixes.v4`/`prefixes.v6` output and stock-client Tailscale IP family
  assertions.
- Added paired `postgres-magicdns-ipv6-only` Rust/headscale-go rows over a
  temporary Postgres database. The row proves IPv6-only prefix-family
  allocation plus MagicDNS status through the production Postgres serving path.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  forty-two Postgres stock-client rows.

## 2026-05-31 Postgres IPv4-only prefix-family smoke slice

- Added paired `postgres-prefix-family-ipv4-only` Rust/headscale-go rows over a
  temporary Postgres database. The row proves explicit IPv4-only prefix-family
  allocation through the production Postgres serving path.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  forty-three Postgres stock-client rows.

## 2026-05-31 Postgres dual-stack and IPv6-only prefix-family smoke slice

- Added paired `postgres-prefix-family-dual-stack` and
  `postgres-prefix-family-ipv6-only` Rust/headscale-go rows over temporary
  Postgres databases. The rows prove explicit dual-stack and IPv6-only
  prefix-family allocation through the production Postgres serving path.
- The real-client workflow includes both rows in `PR_SMOKES`; the matrix now
  has forty-five Postgres stock-client rows.

## 2026-05-31 Postgres default MagicDNS smoke slice

- Added paired `postgres-magicdns` Rust/headscale-go rows over a temporary
  Postgres database. The row proves the default MagicDNS suffix through the
  production Postgres serving path.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  forty-six Postgres stock-client rows.

## 2026-05-31 Postgres SSH checkPeriod cache smoke slice

- Added paired `postgres-ssh-oidc-check-period-cache` Rust/headscale-go rows
  over a temporary Postgres database. The row reuses the OIDC-backed Tailscale
  SSH `check` flow and asserts a second SSH attempt inside `checkPeriod` does
  not emit a new auth URL.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  forty-seven Postgres stock-client rows.

## 2026-05-31 Postgres DNS hot-reload smoke slice

- Added paired `postgres-dns-hot-reload` Rust/headscale-go rows over a
  temporary Postgres database. The row proves production `extra_records_path`
  file reloads by observing an initial A record and a later AAAA record in the
  stock-client netmap.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  forty-eight Postgres stock-client rows.

## 2026-05-31 Postgres ping lifecycle smoke slice

- Fixed production `/debug/ping` lookup to resolve persisted node IDs instead
  of deriving IDs only from node keys, so Postgres-hydrated connected streams
  can receive PingRequest callbacks.
- Added paired `postgres-ping-lifecycle` Rust/headscale-go rows over a
  temporary Postgres database. The row uses the current-head headscale-go audit
  baseline for exact executable `/debug/ping` lifecycle coverage.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  forty-nine Postgres stock-client rows.

## 2026-05-31 Postgres ACL allow smoke slice

- Added paired `postgres-acl-allow` Rust/headscale-go rows over a temporary
  Postgres database. The row runs two stock clients through the production
  lifecycle harness with a loaded allow policy and asserts each client sees one
  peer.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  fifty Postgres stock-client rows.

## 2026-05-31 Postgres route-via smoke slice

- Extended `tools/real-client/restart-persistence-common.sh` with an opt-in
  no-restart route-via mode so the production Postgres harness can assert
  current-head `grants[].via` route steering without also exercising restart
  persistence.
- Added paired `postgres-route-via` Rust/headscale-go rows over a temporary
  Postgres database using the current-head headscale-go audit baseline.
- The real-client workflow includes the row in `PR_SMOKES`; the matrix now has
  fifty-one Postgres stock-client rows.

## 2026-05-31 Postgres route-via reload/multiprefix smoke slice

- Added paired `postgres-route-via-same-tag`,
  `postgres-route-via-reload`, `postgres-route-via-multiprefix`, and
  `postgres-route-via-multiprefix-reload` Rust/headscale-go rows over a
  temporary Postgres database, reusing the no-restart production route-via
  harness.
- The new rows cover current-head same-tag `grants[].via` election,
  policy-reloaded `grants[].via` steering, and multi-prefix per-user route
  ownership before restart-specific assertions.
- The real-client workflow includes the rows in `PR_SMOKES`; the matrix now has
  fifty-five Postgres stock-client rows.

## 2026-05-31 Postgres route-health smoke slice

- Extended `tools/real-client/restart-persistence-common.sh` with an opt-in
  no-restart route-health mode so the production Postgres harness can assert
  current-head route-health failover without also exercising restart
  persistence.
- Added paired `postgres-route-health` and `postgres-route-health-reload`
  Rust/headscale-go rows over a temporary Postgres database using the
  current-head headscale-go audit baseline.
- The real-client workflow includes the rows in `PR_SMOKES`; the matrix now has
  fifty-seven Postgres stock-client rows.

## 2026-05-31 Multi-agent parity cleanup slice

- Adopted scoped worker fixes for current-head tag-name validation in ACL
  parsing, upstream tag whitespace error text on admin HTTP/gRPC paths, user
  command alias help routing, DB-level empty forced-tag persistence, and core
  route approval semantics that refuse phantom unadvertised routes.
- Focused local checks completed: `cargo fmt --all -- --check`,
  `git diff --check`, ACL/DB/core compile-only checks, feature-gated Pg node
  compile-only checks, and the core route-approval regression test. Local
  API/CLI compile-only checks were capped and deferred after the `headscale-api`
  build script stalled; CI should cover those surfaces with the normal gates.

## 2026-05-31 Ping lifecycle CI harness fix

- Fixed the production online/LastSeen harness to call Rust `/debug/ping` on
  the metrics/debug listener, matching where `metrics_debug_router` mounts the
  debug ping route and matching the older auth-key ping harness.
- The previous CI failure for `postgres-ping-lifecycle` returned the public
  listener fallback HTML instead of exercising the PingRequest callback path.

## 2026-05-31 Second-wave parity cleanup slice

- Added a map-stream regression for cancelled PingRequest callbacks and taught
  the ping tracker to remove queued outbound ping frames when a ping completes
  or is cancelled, preventing stale debug ping frames after timeout/cancel.
- Expanded CLI parity for the hidden `server` alias so help and unknown flag
  errors route through the same exact upstream-style snapshots as `serve`.
- Extended the env-gated production Postgres serve topology smoke with
  preauth-key expire/delete/list-empty coverage, and added one paired SSH
  profile-variant denial row for reverse `other.example` profile access.
- Focused local checks completed: `cargo fmt --all -- --check`,
  `git diff --check`, SSH wrapper `bash -n`, and the isolated API ping
  cancellation regression test. The broader Docker/Postgres matrix remains on
  CI.

## 2026-05-31 Ping lifecycle metrics listener follow-up

- Fixed the Rust production online/LastSeen config generated by
  `tools/real-client/online-lastseen-common.sh` to set
  `server.metrics_listen_addr`, so paired ping lifecycle rows bind the same
  dedicated metrics/debug listener that `/debug/ping` targets.
- Added a startup wait for the metrics/debug listener whenever the debug-ping
  assertion is enabled, making future failures point at listener readiness
  instead of the later PingRequest assertion.
- Loosened the ACL non-ASCII tag-name regression assertion to check the
  upstream validation invariant without depending on the HUJSON parser's
  rendered Unicode map key.
- Adopted the auth-cache lifecycle worker fix so non-SSH approval/rejection
  notifies waiters while preserving the auth cache entry until registration
  completion or expiry, matching current upstream Headscale behavior.

## 2026-05-31 Third-wave parity cleanup slice

- Adopted DB canonicalization parity fixes: preauth-key ACL tags now reject
  non-`tag:` values and persist sorted/deduplicated tag lists, and node
  approved routes now expand exit routes, sort by address family/address/prefix,
  and deduplicate before SQLite/Postgres persistence.
- Adopted DB lifecycle/import parity fixes: missing preauth-key expire/destroy
  IDs are no-op success like current upstream Go, and legacy `routes` table
  migration now copies enabled rows without synthesizing the opposite exit route.
- Adopted admin/gRPC parity fixes: `ListNodes` validates user filters, excludes
  tagged nodes from user-filtered ownership, renders tagged list rows with the
  upstream `tagged-devices` user, and `ListApiKeys` returns numeric ID order.
- Adopted core route parity fixes: equal-prefix/equal-priority routes now keep
  the incumbent primary while it remains eligible, and the route fuzz oracle was
  updated for the sticky primary behavior.
- Adopted a paired `postgres-route-health-reload` Rust/headscale-go real-client
  row and added it to the push/PR Postgres smoke set.

## 2026-06-01 Real-client CI matrix audit

- Audited `tools/real-client/smoke-matrix.sh --list` against the
  `.github/workflows/real-client-parity.yml` `PR_SMOKES` set after `aeef5d4`:
  current audit has 178 checked-in smoke IDs, and the push/PR set has 125 IDs
  with no unknown or duplicate row IDs while covering all 90 Postgres
  stock-client rows.
- Added the low-risk paired `ping-lifecycle` row to `PR_SMOKES` so the
  non-Postgres auth-key `/debug/ping` path runs on push/PR beside the existing
  Postgres ping lifecycle row.

## 2026-06-01 SSH profile-variant status audit

- Expanded the paired `ssh-profile-variants` real-client wrappers with a
  profile-matching `root` login-user denial. Both Rust and pinned headscale-go
  paths now assert exit status `255`, empty stdout through the shared SSH matrix
  harness, and the exact first stderr line for a disallowed login user.

## 2026-06-01 Route-via reload+restart SQLite smoke slice

- Added paired non-Postgres `route-via-reload-restart` Rust/headscale-go wrappers
  over the existing restart-persistence route-via reload mode. This closes the
  SQLite/runtime side of the route-via policy reload followed by production
  restart edge; the equivalent Postgres row already existed.
- Added the row to the real-client matrix and push/PR smoke set so it runs beside
  the existing route-via, route-via-health, and route-via-multiprefix rows.

## 2026-06-01 Route-via multiprefix reload+restart SQLite smoke slice

- Added paired non-Postgres `route-via-multiprefix-reload-restart`
  Rust/headscale-go wrappers over the existing restart-persistence route-via
  multiprefix reload mode. The row proves current-head multi-prefix
  `grants[].via` route ownership before reload, after policy reload, and after
  production restart; the equivalent Postgres row already existed.
- Added the row to the real-client matrix beside the existing route-via
  multiprefix, reload, and restart rows.

## 2026-06-01 OIDC/web registration map-churn audit

- Inspected the OIDC and web-registration real-client harnesses for the open
  production-process policy/map-churn parity gap. Existing web-registration
  restart coverage already asserts post-restart tag mutation through a stock
  client peer netmap; the OIDC route-approval restart row covers persistence
  and reconnect but not a focused policy-mutation stream assertion.
- Added a local OIDC callback handoff regression that keeps a registered
  viewer's streaming map open under deny-all policy, completes OIDC
  registration for a peer, then mutates policy to allow peers and asserts the
  stream emits the OIDC peer/profile through an incremental policy delta.

## 2026-06-01 Config/debug topology audit

- Added focused `/debug/config` coverage for the current merge model: static
  config fields remain sourced from the startup runtime snapshot, while
  public control URL, DNS, and DERP topology fields are refreshed from live
  runtime state before serialization.
- Filled the runtime snapshot's `DNSConfig.OverrideLocalDNS` field so direct
  snapshot assertions and debug projection start from the same config-backed
  DNS shape.
- Removed stale config comments that still described logtail and auto-update
  as projection-only; both now affect map-response runtime fields.

## 2026-06-01 Multi-address policy/SSH/route differential slice

- Added `multi-address-policy-ssh-route-matrix` to the pinned headscale-go
  differential scenarios. It covers dual-stack plus IPv6-only family-removal
  nodes through per-node filter reduction, symmetric peer visibility, SSH
  principals, and an approved IPv6 route.
- Kept DNS out of this slice because the pinned `wire.runtime_dns_config`
  differential is config-only and does not consume scenario nodes; node-family
  MagicDNS A/AAAA helpers remain covered by the existing API DNS tests.
- Refreshed `tools/parity/golden/headscale-go-v0.29.0-beta.2.json` after the
  full default differential run matched Rust and pinned headscale-go.

## 2026-06-01 CLI current-upstream utility audit

- Tightened the CLI upstream-output shim for utility command edges: `health`,
  `configtest`, and `dumpConfig` now return the pinned upstream help snapshots
  when `--config`/`-c` appears before `--help`, and completion-shell extra
  positionals now report the nested Cobra command path, for example
  `headscale completion bash`.
- Follow-up current-head comparison found the same utility help preemption for
  inherited `-o`/`--output` and `--force` flags, plus `mockoidc`'s narrower
  help/unknown-global-flag behavior. The process tests now lock those edges
  against the audited upstream Cobra output.
- Current-head process snapshots now also pin completion fish/powershell
  extra-positional errors, including their `--no-descriptions` variants, to the
  audited upstream nested Cobra command path.
- This slice adds the matching zsh `--no-descriptions` extra-positional stderr
  snapshot, audited against current upstream headscale-go `171fd7a`.

## 2026-06-01 Fourth-wave parity coverage

- Added direct gRPC bearer-auth edge coverage for no-space and lowercase bearer
  prefixes plus grpc-gateway opaque authorization and API-key not-found status
  JSON cases.
- Added Noise `/machine/*` endpoint tests that keep current inner-only routes
  public-404, enforce `HEAD`-only public ping callbacks, and lock wrong-method
  inner control routes to 405.
- Added `policy-v2-nodeattrs-grants-ssh-route-profile` to the default pinned
  differential suite for combined `nodeAttrs`, `grants`, route-via,
  localpart SSH, profile email, and dual-stack/IPv6-only policy behavior.
- Added `node_attr_checks` to the pinned differential harness and a
  `policy-v2-randomize-client-port-nodeattrs` scenario so
  `randomizeClientPort` plus per-node `nodeAttrs` CapMap output is compared
  directly against headscale-go.
- Added paired non-Postgres `route-health-all-unhealthy-reload-restart`
  real-client rows over the existing restart harness.
- Aligned broad real-client headscale-go wrapper defaults with the selected
  v0.29.0-beta.2 parity baseline via
  `tools/real-client/headscale-go-baseline.sh`; explicit
  `HEADSCALE_GO_VERSION` overrides and current-head wrappers still win.
- Added paired stock-client auth-key lifecycle rows for non-reusable key reuse
  rejection and expired-key rejection, wired into the real-client matrix and
  push/PR smoke set.

## 2026-06-01 Postgres auth-key lifecycle smoke slice

- Added paired `postgres-authkey-nonreusable` and `postgres-authkey-expired`
  Rust/headscale-go rows over the production Postgres stock-client harness.
- `tools/real-client/online-lastseen-common.sh` can now mint non-reusable or
  immediately expired preauth keys, mark selected 1-based clients as expected
  auth-key failures, and assert the resulting persisted machine count.
- The rows are included in the real-client matrix and `PR_SMOKES`; this brought
  the Postgres stock-client matrix to seventy-one rows before the later
  route-via-health addition.

## 2026-06-01 Postgres route-via-health smoke slice

- Added paired `postgres-route-via-health` Rust/headscale-go rows over the
  production Postgres restart harness.
- `tools/real-client/restart-persistence-common.sh` now permits the scoped
  same-tag, no-restart combination of route-via steering and route-health
  probes, then proves Alice and Bob both follow the route-health failover owner
  and keep that sticky owner after the paused router recovers.
- The row is included in the real-client matrix and `PR_SMOKES`, bringing the
  Postgres stock-client matrix to seventy-two rows.

## 2026-06-01 Postgres primary-route smoke slice

- Added paired `postgres-route-primary`, `postgres-route-primary-failover`,
  `postgres-route-primary-sticky`, and `postgres-route-primary-withdraw`
  Rust/headscale-go rows over the production Postgres restart harness.
- `tools/real-client/restart-persistence-common.sh` now has a route-primary
  mode that uses stock routers plus real `nodes approve-routes` calls to prove
  primary selection, unapproval failover, sticky owner retention when the old
  primary is reapproved, and advertised-route withdrawal while preserving
  approval state.
- The rows are included in the real-client matrix and `PR_SMOKES`, bringing the
  Postgres stock-client matrix to seventy-six rows.

## 2026-06-02 Postgres primary-route restart smoke slice

- Added paired `postgres-route-primary-restart` Rust/headscale-go rows over the
  production Postgres restart harness.
- The row uses the existing route-primary mode without the no-restart shortcut
  and now asserts the primary route owner before restart matches the owner after
  the real server process is restarted and both stock clients reconnect.
- The row is included in the real-client matrix and `PR_SMOKES`, bringing the
  Postgres stock-client matrix to ninety-five rows before the later route-via-health restart expansion.

## 2026-06-01 Postgres SSH smoke slice

- Added paired `postgres-ssh` Rust/headscale-go rows over the production
  Postgres stock-client harness.
- `tools/real-client/online-lastseen-common.sh` now supports per-client users
  and preauth keys, stock-client `--ssh`, OpenSSH client/user setup, and the
  shared allow/deny/timeout SSH matrix assertions used by the SQLite/current
  harness.
- The row is included in the real-client matrix and `PR_SMOKES`, bringing the
  Postgres stock-client matrix to seventy-seven rows.

## 2026-06-01 Postgres auth-key relogin smoke slice

- Added paired `postgres-authkey-relogin-same-user` and
  `postgres-authkey-relogin-route-preserve` Rust/headscale-go rows over the
  production Postgres stock-client harness.
- `tools/real-client/online-lastseen-common.sh` now supports auth-key logout
  followed by same-user relogin with fresh preauth keys, stable Tailscale IP
  assertions, and before/after node ID, user, address, available-route, and
  approved-route comparisons.
- The rows are included in the real-client matrix and `PR_SMOKES`, bringing the
  Postgres stock-client matrix to seventy-nine rows.

## 2026-06-01 Postgres Taildrop CapMap smoke slice

- Added paired `postgres-taildrop-capmap` Rust/headscale-go rows over the
  production Postgres stock-client harness.
- `tools/real-client/online-lastseen-common.sh` now accepts Taildrop config
  toggles, emits the production `taildrop.enabled` config, and asserts the
  stock-client self-node file-sharing CapMap state through `tailscale debug
  netmap`.
- The row is included in the real-client matrix and `PR_SMOKES`, bringing the
  Postgres stock-client matrix to eighty rows.

## 2026-06-01 Postgres SSH acceptEnv smoke slice

- Added paired `postgres-ssh-accept-env` Rust/headscale-go rows over the
  production Postgres stock-client harness.
- `tools/real-client/online-lastseen-common.sh` now supports per-client
  preauth-key tags, allowing one same-user client to register as an untagged
  source and another as the tagged SSH destination required by the upstream
  `acceptEnv` policy fixture.
- The row is included in the real-client matrix and `PR_SMOKES`, bringing the
  Postgres stock-client matrix to eighty-one rows.

## 2026-06-01 Postgres SSH profile/localpart smoke slice

- Added paired `postgres-ssh-localpart` and
  `postgres-ssh-profile-variants` Rust/headscale-go rows over the production
  Postgres stock-client harness.
- `tools/real-client/online-lastseen-common.sh` now supports per-client user
  profile emails for production smokes, matching the current-head headscale-go
  localpart/profile SSH policy cases while preserving username-based Rust
  compatibility.
- The rows are included in the real-client matrix and `PR_SMOKES`, bringing the
  Postgres stock-client matrix to eighty-three rows.

## 2026-06-01 Postgres private DERP smoke slice

- Added paired `postgres-derp-private` Rust/headscale-go rows over the
  production Postgres stock-client harness.
- `tools/real-client/online-lastseen-common.sh` now supports config-backed
  embedded DERP/STUN for Rust production serve and headscale-go embedded DERP,
  forces stock clients through DERP, and asserts STUN, DERP-map metadata, and a
  relay-path `tailscale ping`.
- The row is included in the real-client matrix and `PR_SMOKES`, bringing the
  Postgres stock-client matrix to eighty-four rows.

## 2026-06-01 DNS hot-reload resolver smoke slice

- Strengthened the paired `dns-hot-reload` Rust/headscale-go production smokes
  to run `tailscale debug resolve` inside the stock client after each
  `extra_records_path` netmap assertion. The row now proves the original A
  record and hot-reloaded AAAA record resolve through the client DNS path, not
  only through `tailscale debug netmap`.

## 2026-06-01 Real-client CI matrix hardening

- Added `tools/real-client/smoke-matrix.sh --check` to validate matrix length,
  duplicate smoke IDs, selected smoke/target names, and Rust/headscale-go
  script paths before the expensive Docker-backed stock-client matrix starts.
- Added `--list-selected` so the real-client workflow prints the exact
  push/PR/scheduled smoke rows it is about to run instead of the full catalog.
- Moved real-client smoke selection, validation, and selected-row listing to
  immediately after checkout in `.github/workflows/real-client-parity.yml`, so
  bad `PR_SMOKES` values fail before toolchain setup, dependency installation,
  the Postgres process smoke, or Docker image pulls.
- Added the paired `ssh-accept-env` row to `PR_SMOKES` so push/PR real-client
  parity now gates current-head Tailscale SSH `acceptEnv` forwarding for
  `LANG` and `LC_*` against Rust and headscale-go.

## 2026-06-01 CLI parser-error output slice

- Parser-level `auth register`/`auth approve`/`auth reject` missing-flag
  shims and `users create` missing-name shims now reuse the admin structured
  error formatter when `-o/--output` requests `json`, `json-line`, or `yaml`.
- Focused process coverage pins JSON, JSON-line, and YAML stderr envelopes for
  those current-upstream parser errors while preserving the existing human
  `Error:` snapshots for default output.

## 2026-06-01 Runtime route-approval reason slice

- Inspected current headscale-go `State.SetApprovedRoutes`: route-approval
  mutations fan out as `PolicyChange`, not a peer-only route delta.
- Updated the in-memory runtime registry's `set_approved_routes` map-change
  reason to `policy change` while preserving the stored approval and stale
  unhealthy-route cleanup behavior; a focused unit test now pins the bounded
  reason/type/content shape.
- Remaining runtime churn work: persistent wire-registry sync and broader
  NodeStore reason/state edge coverage.

## 2026-06-01 Postgres route-health mixed-exit no-restart slice

- Added paired `postgres-route-health-mixed-exit-all-unhealthy` Rust and
  headscale-go real-client wrappers over the existing route-health harness.
  The row covers mixed exit-node/subnet-router all-unhealthy last-known subnet
  primary retention on production Postgres without combining it with server
  restart.
- Added the row to the real-client matrix and PR smoke set; the Postgres
  stock-client matrix now covers fifty-nine rows.

## 2026-06-01 CLI late-global-flag parity slice

- Added current-upstream Cobra snapshots for skip-config utility commands that
  reject late global flags: `version --config`, `mockoidc --output`, and
  `completion zsh --config`.
- The expected stderr was audited against current upstream headscale-go
  `171fd7a`, where each exits with status 1 and an `unknown flag` error.

## 2026-06-01 Map-request auto-approval reason slice

- Map-time Hostinfo route auto-approval now records a `policy change` map
  reason, matching the route-approval policy-change reason instead of treating
  policy-driven approval as a plain route update.
- Added a streaming batcher regression proving the auto-approval waits for the
  batch tick, carries policy-derived DNS updates, and publishes the newly
  allowed route in the peer delta.

## 2026-06-01 Postgres prefix-family backfill slice

- Made the paired `prefix-family-v4-to-dual-backfill` harness backend-aware via
  `REAL_CLIENT_DATABASE_BACKEND=sqlite|postgres`, preserving the SQLite default
  and adding Postgres temp-database lifecycle, config emission, Rust
  `postgres-sqlx` build selection, and direct Postgres node-address assertion.
- Added paired `postgres-prefix-family-v4-to-dual-backfill` Rust/headscale-go
  wrappers and wired them into the real-client matrix and PR smoke set; the
  initial Postgres stock-client matrix covered fifty-nine rows.
- Added paired `postgres-prefix-family-dual-stack-to-ipv4-only-backfill` and
  `postgres-prefix-family-dual-stack-to-ipv6-only-backfill` Rust/headscale-go
  wrappers over the same backend-aware harness and wired them into the
  real-client matrix and PR smoke set. The Postgres stock-client matrix now
  covers sixty-two rows, including OIDC SSH policy-restart and configured family-removal backfill parity
  after production restart plus `nodes backfillips`.

## 2026-06-01 CLI and DERP patch churn slice

- Added current-upstream parser-edge stderr snapshots for residual utility
  command cases: `completion bash -- bad`, `completion bad --no-descriptions`,
  `completion bash --no-descriptions --bad`, and
  `generate private-key --force --bad`.
- Hostinfo updates that only move `NetInfo.PreferredDERP` now record
  `endpoint/DERP update` and emit a batched peer patch instead of a full
  self-update. The focused streaming test pins the reason, patch type, batch
  timing, and `PeerChange.DERPRegion` projection.

## 2026-06-01 No-DB preauth store unification slice

- `InMemoryPreauthAdmin` now also implements the wire `PreauthRedeemer`
  contract, so no-DB embedders can share one generic preauth store between
  upstream admin/gRPC mint/list/expire/delete paths and stock-client auth-key
  registration.
- Focused tests cover one-shot consumption, reusable redemptions, expired-key
  rejection, and same-key lookup metadata for used/expired keys.

## 2026-06-01 Embeddable control-router slice

- Added `ControlRouterOptions` plus `control_router_with_options` and
  `control_router_with_oidc_and_options` so embedders can mount the full
  public control listener while leaving selected host-owned routes, currently
  `/health`, outside the stock router.
- Defaults still mount the headscale-go-compatible `/health` endpoint. Focused
  router tests prove the default health shape is preserved and the no-health
  option can be merged with a host health route without losing `/version`,
  `/key`, or `/machine/ping-response`.

## 2026-06-01 Extra-records whitespace parity slice

- File-backed DNS `extra_records` parsing now matches headscale-go's
  zero-byte-only special case: an empty file maps to no records, while a
  whitespace-only file is invalid JSON and leaves the previous hot-reload
  record set in place.
- Focused DNS tests cover startup parsing, hot-reload preservation for
  zero-byte and whitespace-only edits, and existing extra-record e2e behavior.

## 2026-06-01 Postgres OIDC SSH policy-restart smoke slice

- Added paired `postgres-ssh-oidc-policy-restart` Rust/headscale-go stock-client
  smokes. They start production Postgres OIDC SSH registration with a database
  policy that has no SSH rules, prove ordinary peer connectivity, mutate the
  database policy to the OIDC SSH `check` policy, restart the server, and then
  complete the browser-approved stock-client SSH check.
- The real-client matrix and PR smoke set now include the row; the Postgres
  stock-client matrix covers sixty-two rows.

## 2026-06-01 DERP clear map-churn slice

- Hostinfo churn that clears `NetInfo.PreferredDERP` now records a peer
  `node updated` delta instead of a full self-update reason. This keeps
  non-patch peer state changes in the upstream-style peer-delta path while
  preserving PreferredDERP-only moves as endpoint/DERP patches.
- Focused streaming tests cover DERP-map refresh history, DERP patch updates,
  and batched DERP clears.

## 2026-06-01 CLI residual parser drift slice

- Current-upstream Cobra shims now cover `help <topic> <extra>` behavior,
  returning the matched topic help instead of an unknown-command error for the
  covered upstream topics.
- Added exact stderr snapshots for residual admin parser edges:
  `auth register` missing both required flags, `auth register --user alice`
  missing `--auth-id`, `auth approve` missing `--auth-id`, and
  `users create` without a name.

## 2026-06-01 Postgres route-health all-unhealthy smoke slice

- Upstream current HEAD remains `171fd7a3c54156965753a63639cdcafcd50c8d67`;
  the route/SSH coverage audit still shows route-health all-unhealthy fallback
  behavior in `integration/route_test.go` and `hscontrol/servertest`.
- Added paired `postgres-route-health-all-unhealthy` Rust/headscale-go rows over
  a temporary Postgres database, reusing the production route-health harness in
  no-restart mode.
- The row proves a stock client keeps the last-known subnet-route owner when
  both HA route candidates become unhealthy, closing the plain Postgres
  symmetry gap between `postgres-route-health-reload` and the restart-only
  all-unhealthy rows.

## 2026-06-01 Postgres route-health mixed-exit smoke slice

- Added paired `postgres-route-health-mixed-exit` Rust/headscale-go rows over a
  temporary Postgres database, reusing the stock-client mixed exit-node/subnet
  route-health harness without a production restart.
- The row proves the Postgres backend ignores exit-only routes while selecting
  the healthy subnet-route primary, matching the existing SQLite/default row and
  closing the plain Postgres symmetry gap before the restart-only mixed-exit
  rows.

## 2026-06-01 Postgres route-health all-unhealthy reload smoke slice

- Added paired `postgres-route-health-all-unhealthy-reload` Rust/headscale-go
  rows over a temporary Postgres database, reusing the stock-client policy
  reload route-health harness without a production restart.
- The row proves a policy reload preserves all-unhealthy last-known-primary
  retention on the Postgres backend, closing the plain Postgres symmetry gap
  between the no-restart all-unhealthy row and the restart-only
  all-unhealthy-reload row.

## 2026-06-01 Postgres mixed-exit route-health reload smoke slice

- Added paired `postgres-route-health-mixed-exit-reload` and
  `postgres-route-health-mixed-exit-all-unhealthy-reload` Rust/headscale-go
  rows over temporary Postgres databases, reusing the existing stock-client
  policy-reload route-health harnesses without a production restart.
- These rows prove policy reload preserves mixed exit-node separation and
  all-unhealthy last-known subnet-primary retention on the Postgres backend,
  closing the no-restart reload symmetry gap before the restart-only mixed-exit
  rows.

## 2026-06-01 gRPC preauth missing-owner parity slice

- `CreatePreAuthKey` now matches upstream when the request supplies neither a
  user nor ACL tags: gRPC returns `Unknown` with
  `auth-key must be either tagged or owned by user`.
- The grpc-gateway e2e matrix covers the corresponding HTTP 500/status JSON
  shape for `POST /api/v1/preauthkey` with an empty body.

## 2026-06-01 map batch ordered-delivery slice

- Streamed map responses now consume tick-published map batches through a
  bounded per-subscriber event queue instead of only observing the latest watch
  value.
- This matches headscale-go's buffered map-session semantics: if two batches
  publish before a slow stream polls again, the stream still processes the
  earlier self-targeted batch before skipping later batches that do not concern
  it. A lagged subscriber falls back to a full map response.

## 2026-06-01 DNS nodeAttrs/NextDNS parity scenario

- The Go/Rust parity harness now compares requester-specific runtime DNS
  outputs, not only the static loaded DNS config. The Go helper calls
  headscale-go's mapper DNS projection, while the Rust helper feeds matching
  `DnsRequester` metadata through `DnsStore::build_for_requester`.
- Added `wire-dns-nextdns-nodeattrs`, covering overlapping wildcard/user/tag
  nodeAttrs, profile sorting, requester metadata on global and split NextDNS
  resolvers, attacker-lookalike NextDNS host preservation, and
  `nextdns:no-device-info`.
- The refreshed v0.29.0-beta.2 golden now covers eighty-seven parity scenarios.

## 2026-06-01 policy v2 app-cap grant parity scenario

- `FilterRule`/`CapGrant` wire parity now preserves nullable upstream
  `PeerCapMap` values, which are required for generated companion capability
  grants.
- `grants[].app` now emits upstream companion `CapGrant` rules for
  `tailscale.com/cap/drive` and `tailscale.com/cap/relay`, producing
  `tailscale.com/cap/drive-sharer` and `tailscale.com/cap/relay-target` with
  null capability values after per-node packet-filter reduction.
- Added `policy-v2-app-cap-grants`, covering global and per-node `CapGrant`
  normalization plus cap-grant peer visibility against pinned headscale-go.
  The refreshed v0.29.0-beta.2 golden now covers eighty-eight parity scenarios.

## 2026-06-01 Postgres ACL stock-client smoke slice

- Added paired `postgres-acl-empty` and `postgres-acl-autogroup-self`
  Rust/headscale-go rows over a temporary Postgres database.
- The rows cover the empty ACL streaming visibility edge and
  `autogroup:self` same-user isolation through stock Tailscale clients, closing
  the remaining Postgres ACL smoke symmetry gap after `postgres-acl-allow`.
- The real-client matrix and PR smoke set now include the rows; the Postgres
  stock-client matrix covered sixty-nine rows before the later auth-key
  lifecycle additions.

## 2026-06-01 auth-key same-user relogin smoke slice

- Added paired `authkey-relogin-same-user` Rust/headscale-go rows.
- The shared auth-key harnesses can now opt into a logout plus fresh same-user
  auth-key relogin cycle, wait for the stock client to return to `NeedsLogin`,
  relogin with a newly minted key, and assert the node keeps its Tailscale IPs.
- This closes the first upstream auth-key lifecycle smoke gap and leaves
  deleted-key restart and different-user relogin cases as the next auth-key
  lifecycle rows.

## 2026-06-01 auth-key relogin route-preservation smoke slice

- Moved the shared same-user auth-key relogin flow to run after route approval,
  so wrappers can prove approved route state survives the relogin boundary.
- Added paired `authkey-relogin-route-preserve` Rust/headscale-go rows that
  advertise and approve a stock-client route, relogin the same user with a
  fresh auth key, and assert stable IPs plus stable logical node/user/route
  state.
- The bounded push/PR real-client smoke set now includes the new row.

## 2026-06-01 auth-key expired relogin rejection smoke slice

- Added paired `authkey-relogin-expired` Rust/headscale-go rows and paired
  `postgres-authkey-relogin-expired` Rust/headscale-go rows.
- The shared auth-key relogin flow can now expire the fresh same-user preauth
  key before `tailscale up`, assert the stock client does not reach a logged-in
  netmap, and assert the registered node count remains unchanged.
- This closes the expired-key relogin rejection gap; deleted-key restart and
  different-user relogin remain as the next auth-key lifecycle rows.

## 2026-06-01 Taildrop CapMap stock-client smoke slice

- Added `REAL_CLIENT_TAILDROP_ENABLED` and
  `REAL_CLIENT_EXPECT_FILE_SHARING_CAP` knobs to the paired auth-key stock-client
  harnesses.
- The Rust real-client harness now accepts `HSRS_HARNESS_TAILDROP_ENABLED` and
  projects it through `RuntimeConfigSnapshot.taildrop.enabled`.
- Added paired `taildrop-capmap` Rust/headscale-go rows that disable Taildrop
  and assert the stock-client self `CapMap` omits the file-sharing capability.

## 2026-06-01 NodeStore write worker batching slice

- Added an optional `MachineRegistry` NodeStore write worker for put/upsert,
  delete, bool-update, set-name, rekey, update-many, and legacy delete-many
  paths. Production `headscale server` now
  installs it using `tuning.node_store_batch_size` and
  `tuning.node_store_batch_timeout`.
- Concurrent writes now block until the worker commits their batch, clone and
  publish the COW registry snapshot once for the batch, and record
  `headscale_nodestore_batch_size` with the batch length.
- Set-name collision checks now run inside the writer batch, while unchanged
  bool updates still avoid publishing a fresh registry snapshot.
- Stream-offline `last_seen` writes, policy auto-approval fan-out, and the
  legacy ephemeral sweep now route through the worker instead of directly
  cloning/removing the registry snapshot.
- `headscale_nodestore_queue_depth` now reports the live write-worker queue
  depth instead of a hard-coded zero. Remaining NodeStore worker parity is now
  broader reason/churn coverage rather than missing core writer-op shapes.

## 2026-06-01 SQLite route-health mixed-exit reload+restart slice

- Added paired `route-health-mixed-exit-reload-restart` Rust/headscale-go rows
  over the existing production restart harness.
- Added paired `route-health-mixed-exit-all-unhealthy-reload-restart`
  Rust/headscale-go rows for the all-unhealthy mixed exit-node/subnet-router
  case.
- The default SQLite stock-client matrix now mirrors the Postgres mixed-exit
  reload+restart route-health combinations, and the bounded push/PR
  real-client smoke set includes both rows.

## 2026-06-01 SQLite route-via and SSH cache symmetry slice

- Added paired `route-via-same-tag-restart` Rust/headscale-go rows over the
  existing production restart harness.
- Added paired `ssh-oidc-check-period-cache` Rust/headscale-go rows over the
  existing OIDC SSH check harness.
- Generalized the OIDC SSH policy-mutation restart harness so SQLite/file
  policy mode starts with a no-SSH policy file, mutates that policy file, and
  restarts before approving the SSH check; added paired
  `ssh-oidc-policy-restart` Rust/headscale-go rows for that default path.
- Added paired `web-register-route-approve` Rust/headscale-go rows over the
  same stock-client online/LastSeen harness as the Postgres row, closing the
  last default-vs-Postgres matrix symmetry gap.
- The default SQLite stock-client matrix now matches the existing Postgres
  coverage for same-tag route-via restart, OIDC SSH checkPeriod cache, and OIDC
  SSH policy mutation across restart; it also mirrors the web-registration
  route-approval row. The bounded push/PR real-client smoke set includes all of
  those rows.

## 2026-06-01 auth-request and gateway exactness slice

- `RegistrationCache::wait_for_registration` now waits on any live auth request,
  including SSH-check auth IDs, so follow-up registration requests observe
  approve/reject/expiry before restarting the web-registration flow.
- OIDC registration callbacks and confirmation POSTs now classify auth request
  kind and reject SSH-check auth IDs as wrong-kind registration sessions instead
  of reporting expired/missing registration state.
- OIDC pending registration confirmations now stage on the shared auth request
  entry for the wire, SQLite, and Postgres registration handlers, so CSRF/user
  confirmation state follows the same auth-request TTL/LRU lifecycle as
  headscale-go. The runtime-local confirmation cache remains only as a fallback
  for handlers that do not implement the shared-auth storage hook.
- The grpc-gateway e2e suite now checks the checked-in swagger route/method set
  against mounted routes and pins `/api/v1/tailnet` as intentionally outside the
  upstream grpc-gateway surface.
- Direct gRPC tests now assert exact node/tag/auth-request error messages for
  the current upstream surfaces covered by the local admin service tests.
- DERP sidecar parity documentation now calls out that `verify_client_url` is
  the headscale-style registry admission boundary; `verify_clients` is local
  `tailscaled` verification in upstream `derper`, not a substitute.

## 2026-06-01 auth completion map-change reason slice

- Auth-key, web/CLI `RegisterNode`/`AuthRegister`, and OIDC registration
  completion now use auth-specific live-registry writes: successful same-key
  updates and rekeys emit upstream-style `node added` unless owner/tag/IP
  identity changes require a global `policy change`.
- Same-machine web/OIDC reauth that clears tags or changes route identity now
  records `policy change` rather than a targeted self-update, matching
  headscale-go's post-auth policy-manager promotion path.
- OIDC SSH-check approval remains verdict-only and now has an explicit negative
  assertion that it does not record MachineRegistry map changes.

## 2026-06-01 SQLite runtime defaults parity slice

- `SqliteOpenOptions::default()` now matches upstream file-backed SQLite
  runtime defaults for WAL, `wal_autocheckpoint=1000`, `busy_timeout=10000`,
  `auto_vacuum=INCREMENTAL`, `synchronous=NORMAL`, and foreign-key enforcement.
- The server path now applies those defaults even when no explicit
  `database.sqlite` block is present, while still honoring
  `wal_autocheckpoint: -1` as "do not set the checkpoint PRAGMA".
- SQLite write transactions that protect admin/user/preauth/payment mutations
  now use `BEGIN IMMEDIATE`, matching upstream's `_txlock=immediate` intent
  without changing Postgres transaction behavior.

## 2026-06-01 server transport env override parity slice

- `CliConfig::load` and default config discovery now apply current-upstream
  Viper-style server transport env overrides for `HEADSCALE_SERVER_URL`,
  `HEADSCALE_LISTEN_ADDR`, `HEADSCALE_METRICS_LISTEN_ADDR`,
  `HEADSCALE_GRPC_LISTEN_ADDR`, `HEADSCALE_GRPC_ALLOW_INSECURE`,
  `HEADSCALE_UNIX_SOCKET`, and `HEADSCALE_UNIX_SOCKET_PERMISSION`.
- `HEADSCALE_UNIX_SOCKET` updates both the server runtime socket and the
  top-level local CLI socket fallback so `headscale serve` and local admin
  commands resolve the same env-provided Unix socket.
- Focused coverage includes unit tests for the loaded runtime config and a
  process-level `configtest` snapshot proving env-provided invalid
  `grpc_listen_addr` fails like the same file-provided value.

## 2026-06-01 database env override parity slice

- `CliConfig::load` and default config discovery now apply current-upstream
  Viper-style database env overrides for `HEADSCALE_DATABASE_TYPE`,
  `HEADSCALE_DATABASE_DEBUG`, `HEADSCALE_DATABASE_GORM_*`,
  `HEADSCALE_DATABASE_SQLITE_*`, and `HEADSCALE_DATABASE_POSTGRES_*`.
- `HEADSCALE_DATABASE_SQLITE_PATH` participates in the same upstream alias
  normalization as file-provided `database.sqlite.path`, so it can feed the
  runtime SQLite path when no explicit Rust `server.db_path` overrides it.
- Focused coverage includes unit assertions for gorm/sqlite/postgres
  projection and a process-level `configtest` case proving env-only Postgres
  config is accepted while env-provided invalid pool sizing fails like the
  file-provided value.

## 2026-06-01 configtest default fatal parity slice

- `configtest` now wraps validation failures with upstream's
  `configuration error: loading configuration` context while keeping the shared
  validation snapshots reusable for `serve`.
- `validate_for_configtest` now uses upstream default `server` and `dns`
  values when those blocks are absent, so no-config and minimal configs
  accumulate the same missing noise key, bad/empty `server_url`, and default
  `dns.override_local_dns=true` nameserver fatal errors as pinned
  headscale-go.
- Unit and process fixtures now make `dns.override_local_dns=false` explicit
  when they are testing later validation paths such as TLS, listener parsing,
  DERP config, Postgres config, or policy loading.

## 2026-06-01 policy env override parity slice

- `CliConfig::load` and default config discovery now apply Viper-style
  `HEADSCALE_POLICY_MODE` and `HEADSCALE_POLICY_PATH` overrides after
  file-relative path resolution, matching current upstream.
- Process cleanup now scrubs those env vars so parity snapshots are stable.
- Focused coverage proves env `policy.mode=database` skips a configured
  missing policy file and env `policy.path` can replace the configured file
  path for `configtest`.

## 2026-06-01 gRPC node disco-key projection slice

- `MachineAdminRecord` now carries the upstream `discokey:` string through
  wire-registry, SQLite, and feature-gated Postgres projections.
- `RegisterNode`, `ListNodes`, and `GetNode` now emit `Node.disco_key` instead
  of dropping it during admin/gRPC conversion.
- The file-backed `RegisterNode` restart test now asserts the same
  `discokey:web-restart` value across registration, DB reopen, registry
  hydration, list, and get paths.
- The runtime config snapshot fixture now explicitly disables DNS override,
  fixing the CI failure introduced when configtest began applying upstream DNS
  defaults to absent DNS blocks.

## 2026-06-01 DNS env override parity slice

- `CliConfig::load` and default config discovery now apply Viper-style
  upstream DNS env overrides for `HEADSCALE_DNS_MAGIC_DNS`,
  `HEADSCALE_DNS_BASE_DOMAIN`, `HEADSCALE_DNS_OVERRIDE_LOCAL_DNS`,
  `HEADSCALE_DNS_NAMESERVERS_GLOBAL`, `HEADSCALE_DNS_NAMESERVERS_SPLIT`,
  `HEADSCALE_DNS_SEARCH_DOMAINS`, `HEADSCALE_DNS_EXTRA_RECORDS`, and
  `HEADSCALE_DNS_EXTRA_RECORDS_PATH`.
- DNS string-list env values follow Viper/cast whitespace splitting, while
  split-DNS and inline extra-record env values use the JSON shapes Viper accepts
  for map/slice config values.
- Process coverage proves `HEADSCALE_DNS_OVERRIDE_LOCAL_DNS=true` can override
  a file-provided `dns.override_local_dns=false` and trigger the upstream
  missing-global-nameserver fatal, while
  `HEADSCALE_DNS_NAMESERVERS_GLOBAL=1.1.1.1` satisfies that same validation.

## 2026-06-01 DERP and ephemeral env override parity slice

- `CliConfig::load` and default config discovery now apply current-upstream
  Viper-style DERP env overrides for `HEADSCALE_DERP_SERVER_*`,
  `HEADSCALE_DERP_URLS`, `HEADSCALE_DERP_PATHS`,
  `HEADSCALE_DERP_AUTO_UPDATE_ENABLED`, and
  `HEADSCALE_DERP_UPDATE_FREQUENCY`.
- Env-derived upstream `derp.server` settings project into Rust's
  `server.embedded_derp` after all env overlays, including
  `HEADSCALE_SERVER_URL`, so embedded-region host/port and private-key path use
  the final loaded config.
- Node ephemeral inactivity env overrides now cover both current
  `HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT` and deprecated
  `HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT`, with process tests for the
  upstream 65-second fatal boundary.

## 2026-06-01 NodeStore same-batch update/delete parity slice

- NodeStore bool-update outcomes now carry the affected stable node ID for
  node-targeted map changes.
- The write batcher revalidates those outcomes against the final post-batch
  snapshot, so an update followed by a delete for the same node returns `false`
  and suppresses the stale update wake.
- Regression coverage asserts the update/delete batch publishes only the
  `PeersRemoved` map change for the deleted node.

## 2026-06-01 hidden tailnet CLI removal slice

- The standalone `headscale` command and reusable embedded `AdminCmd` no longer
  expose the old hidden `tailnet` command.
- Process coverage now asserts `tailnet`, `tailnet --help`, and
  `tailnet status --help` return the current-upstream unknown-command error
  instead of rendering the removed local help page.

## 2026-06-01 NodeStore tuning env override parity slice

- `CliConfig::load` and default config discovery now apply current-upstream
  Viper-style NodeStore tuning env overrides for
  `HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE` and
  `HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT`.
- Process coverage proves env-provided zero values trigger the same
  `configtest` fatal validation as file-provided tuning values.

## 2026-06-01 hidden init-config CLI removal slice

- The standalone `headscale` command no longer exposes the old hidden
  `init-config` command or its local example-config writer.
- Process coverage now asserts `init-config`, `init-config --help`, and the old
  `init-config --output` form return the current-upstream unknown-command
  error.

## 2026-06-01 batched full map zero-peer removal parity slice

- Streamed full-map rebuilds now receive the previous per-stream peer snapshot
  so an empty rebuilt peer set can still report the removed stable peer IDs.
- The production map batcher now emits `PeersRemoved` when a tick-published
  full update removes the requester's final visible peer, instead of sending an
  empty full chunk that leaves clients with stale peers.
- Regression coverage pins the delayed batch behavior: the stream waits for the
  batch tick, then emits no peer/full patch payload and a single
  `PeersRemoved` entry for the deleted peer.

## 2026-06-01 CLI utility output/parser parity slice

- `headscale version -o yaml` now matches upstream Go's YAML field casing by
  emitting `buildtime` while retaining the JSON/json-line `buildTime` shape.
- Version runtime labels now use Go-compatible target names such as
  `darwin`/`arm64` and `amd64` instead of Rust target strings in structured and
  human output.
- `generate private-key -- <args>` now treats `--` as Cobra's end-of-options
  sentinel and ignores the remaining positional arguments, including values
  that look like flags or help requests.

## 2026-06-01 TLS and ACME env override parity slice

- `CliConfig::load` and default config discovery now apply upstream Viper-style
  TLS/ACME env overrides for `HEADSCALE_ACME_*` and
  `HEADSCALE_TLS_*` top-level settings.
- Covered env fields include ACME directory/email, Let's Encrypt hostname,
  cache dir, listen address, challenge type, and manual TLS cert/key paths.
- Process coverage proves an env-provided unsupported
  `tls_letsencrypt_challenge_type` fails the same `configtest` validation as a
  file-provided value.

## 2026-06-01 stream lifecycle policy companion parity slice

- Stream online/offline lifecycle changes now carry an in-batch `policy change`
  companion like headscale-go `State.Connect` and `State.Disconnect`.
- The companion is merged into the same pending map change rather than emitted
  as a second wake, preserving one generation/batch item while setting
  `include_policy` and runtime peer recomputation.
- Local history coverage now pins `node online`/`node offline` changes as
  policy-type batches that still retain the peer patch for the affected node.

## 2026-06-01 runtime feature env override parity slice

- `CliConfig::load` and default config discovery now apply current-upstream
  Viper-style env overrides for `HEADSCALE_DISABLE_CHECK_UPDATES`,
  `HEADSCALE_LOGTAIL_ENABLED`, and `HEADSCALE_AUTO_UPDATE_ENABLED`.
- Unit coverage proves those env values override the parsed/default runtime
  feature flags that project into `/debug/config` and map-response capability
  shaping.

## 2026-06-01 auth-key different-user relogin rejection smoke slice (superseded)

- Added paired `authkey-relogin-different-user` Rust/headscale-go rows and
  paired `postgres-authkey-relogin-different-user` Rust/headscale-go rows.
- The shared auth-key relogin flows can now mint the fresh relogin key for a
  deterministic alternate user, run `tailscale logout`, attempt `tailscale up`
  with the existing stock-client state, and require the client to remain logged
  out.
- The rejection assertion compares pre/post persisted node state so the
  rejected relogin cannot duplicate the node or silently transfer it to the
  different user.
- This was superseded by the 2026-06-02 current-head observation that
  different-user auth-key relogin creates a new node while preserving the old
  node.

## 2026-06-01 auth-key deleted relogin restart rejection smoke slice

- Added paired `authkey-relogin-deleted` Rust/headscale-go rows and paired
  `postgres-authkey-relogin-deleted` Rust/headscale-go rows.
- The production auth-key relogin helper can now mint a fresh same-user
  preauth key, delete it through `headscale preauthkeys delete`, restart the
  server, run `tailscale logout`, attempt `tailscale up` with the deleted key,
  and require the stock client to remain logged out.
- The rejection assertion compares pre/post persisted node state so the
  rejected deleted-key relogin cannot duplicate the node or silently change the
  node identity.
- This closes the deleted-key restart/relogin auth-key lifecycle gap.

## 2026-06-02 Postgres web-registration route-approval restart smoke slice

- Added paired `postgres-web-register-route-approve-restart`
  Rust/headscale-go rows over the production restart harness.
- The row uses web/CLI registration, advertises and approves a stock-client
  route, restarts the Postgres-backed server with the same control URL, and
  asserts the web-registered node identity plus approved route survive restart.
- This closes a small Postgres stock-client mutation symmetry gap between the
  existing web-registration restart row and the no-restart web-registration
  route-approval row; the Postgres stock-client matrix now has eighty-nine
  rows.

## 2026-06-02 Postgres randomize-client-port CapMap smoke slice

- Added paired `postgres-randomize-client-port` Rust/headscale-go rows over the
  production Postgres stock-client harness.
- The row loads an upstream-shaped policy with top-level
  `randomizeClientPort: true`, registers a stock client, reads
  `tailscale debug netmap`, and asserts the self `CapMap` contains
  `randomize-client-port`.
- This pins the current-head policy/runtime projection through the real client;
  the Postgres stock-client matrix now has ninety-one rows.

## 2026-06-02 CLI consumed-help value parity slice

- Global `--config` and `--output` now accept hyphen-prefixed values like
  current-upstream Cobra, so `--help` is consumed as the flag value for forms
  such as `health --config --help`, `serve --config --help`,
  `configtest --output --help`, `version --output --help`, and
  `generate private-key --output --help`.
- The raw help pre-parser now only emits static help when `-h`/`--help` is an
  unconsumed help flag, preserving the existing upstream help snapshots for
  forms such as `health --config missing.yaml --help`.
- Focused process snapshots cover the consumed-help config/configtest cases,
  while version and private-key coverage assert the upstream human fallback
  output.

## 2026-06-02 CLI residual Cobra parser parity slice

- Global `--force=<bool>` now follows the current-upstream Cobra shape for
  explicit bool values, including `--force=false health --help` and
  `health --force=false --help`.
- Unknown direct children for `users`, `auth`, and `policy` now return the
  parent command help with exit 0 for the audited `bogus` forms.
- The top-level `userz` typo now emits the upstream `users` suggestion, and
  `nodes list --user` now emits Cobra's `flag needs an argument` wording.
- gRPC node ID preflight now consumes hyphen-prefixed `--identifier` values and
  rejects invalid IDs such as `abc` and `-1` with the upstream
  `strconv.ParseUint` error before opening a socket.
- Validation: focused `headscale-cli` unit/process filters, `cargo fmt -p
  headscale-cli --check`, `cargo clippy -p headscale-cli --all-targets
  --features postgres-sqlx -- -D warnings`, and `git diff --check`.

## 2026-06-02 auth-key different-user relogin runtime fix

- Rust now mirrors current-head headscale-go for stock-client auth-key relogin:
  if the presented machine key is already attached to an untagged node owned by
  a different user, the fresh different-user key creates a new node instead of
  rejecting or transferring the old node.
- SQLite and Postgres persistent auth-key paths use the same behavior, so
  restart/hydration preserves the old-user node and stores the relogin as a
  separate node for the fresh key's user.
- The Rust and headscale-go real-client rows now assert the successful login,
  the additional node count, and preservation of the old-user node.

## 2026-06-02 policy danger-all source parity slice

- `autogroup:danger-all` now follows current headscale-go's source-only
  semantics in the Rust policy stack.
- HuJSON ACLs and non-via network grants accept `autogroup:danger-all` as a
  source, while ACL/grant destinations reject it with the upstream-shaped
  `cannot use autogroup:danger-all as a dst` error.
- Canonical route-overlap expansion treats it as the full IPv4/IPv6 default
  prefix pair, and per-node packet-filter compilation emits `SrcIPs: ["*"]`
  for both direct ACL rules and `grants[].via` route-steering rules.
- Validation: focused `headscale-api-acl` and `headscale-api`
  `danger_all`/`autogroup_danger_all` tests, `cargo fmt -p headscale-api -p
  headscale-api-acl --check`, `cargo clippy -p headscale-api-acl
  --all-targets -- -D warnings`, `cargo clippy -p headscale-api
  --all-targets -- -D warnings`, and `git diff --check`.

## 2026-06-02 subnet-router lifecycle map-stream parity slice

- Stream online/offline lifecycle changes now match current headscale-go's
  `NodeOnlineFor`/`NodeOfflineFor` branch for subnet routers: active approved
  non-exit subnet routers enqueue full map updates with upstream-style
  `subnet router online` and `subnet router offline` reason labels.
- Non-router online/offline lifecycle changes still use peer patches plus the
  policy companion update, preserving the previously covered lightweight
  lifecycle path.
- Added registry-level coverage for queued full updates and a streaming
  `Stream:true` regression proving observers receive full `Node`/`Peers` map
  responses instead of `PeersChanged` or `PeersChangedPatch` chunks when a
  subnet router connects and disconnects.

## 2026-06-02 user deletion map-stream parity slice

- User deletion now matches the current headscale-go fallback
  `change.UserRemoved()` behavior for policy-neutral deletes: successful
  gRPC/admin deletes enqueue a full map update with the upstream
  `user removed` reason when a live wire registry is available.
- Create and rename continue to use policy refresh wakes; delete falls back to
  that legacy policy refresh only for machine-admin backends with no live
  registry.
- Added registry, admin-route, and `Stream:true` gRPC lifecycle coverage so
  connected clients receive a full self/peer map response rather than a
  `PeersChanged` or `PeersChangedPatch` chunk after user deletion.
- Fixed the shared online/LastSeen real-client config writer to emit the
  explicit SQLite `database.type` block for Rust production-server rows, closing
  the CI failure observed in the `authkey-relogin-deleted` smoke after stricter
  config validation landed.

## 2026-06-02 route-health policy-delta parity slice

- Route-health primary-route changes now classify as upstream-style policy
  deltas instead of peer-only route deltas: `RouteHealthUpdate` sets
  `include_policy` plus `requires_runtime_peer_computation`, matching current
  headscale-go's HA prober dispatch of `change.PolicyChange()`.
- The existing `Stream:true` route-health failover regression now asserts the
  policy-delta wire shape while still proving old and new primary routers are
  emitted as peer changes with updated `AllowedIPs` and `PrimaryRoutes`.
- Added focused `Stream:true` route-health all-unhealthy coverage after a
  normal failover: the stale stream stays quiet when the second candidate
  becomes unhealthy, and a fresh `/map` retains the last-known primary route
  owner without letting the old unhealthy primary regain `AllowedIPs`.

## 2026-06-02 CLI version/preauth parser parity slice

- `headscale version` now mirrors Cobra's permissive positional handling:
  extra positionals are ignored, `-o/--output` still works before or after
  them, `--` stops output parsing, and help still wins when `-h/--help`
  appears in the tail.
- `headscale preauthkeys create --user/-u` now emits upstream
  `strconv.ParseUint` wording for invalid numeric owner values, including
  hyphen-prefixed values that Cobra consumes as the `--user` value rather than
  treating as a later flag. Output-format wrapping follows Cobra's parse order.

## 2026-06-02 gRPC auth registration error parity slice

- `RegisterNode`, `DebugCreateNode`, and `AuthRegister` now preserve
  headscale-go's raw auth-ID validation failures as gRPC `Unknown` errors.
  Through grpc-gateway these map to HTTP 500/code 2 with the raw
  `auth ID has invalid ...` message.
- `AuthApprove` and `AuthReject` intentionally keep the upstream
  `InvalidArgument` wrapper (`invalid auth_id: ...`), matching the distinct
  status-wrapped branch in headscale-go.

## 2026-06-02 gRPC raw lookup error parity slice

- `ListNodes` with a missing user filter now matches headscale-go's raw
  `GetUserByName` failure: gRPC `Unknown` with `user not found`, and
  grpc-gateway HTTP 500/code 2.
- `ExpireApiKey` and `DeleteApiKey` still return `InvalidArgument` for missing
  or conflicting selectors, but ID/prefix lookup failures now preserve
  headscale-go's raw API-key lookup errors as gRPC `Unknown` instead of
  wrapping them as `NotFound`.

## 2026-06-02 SSH autogroup self numeric-owner parity slice

- SSH policy compilation and SSH policy checks now preserve upstream numeric
  owner IDs through `MachineAdminRecord`, policy-check nodes, and wire snapshot
  SSH policy nodes.
- `autogroup:self` owner matching now prefers numeric user IDs, matching
  headscale-go's `node.User().ID()` behavior when login names are stale,
  missing, or reused. Legacy login-name matching remains only as a fallback for
  volatile records with no numeric owner ID.
- Added regressions proving same numeric-owner nodes match without equal user
  labels, equal labels with different numeric owners do not match, tagged nodes
  remain excluded from `autogroup:self`, and map snapshot SSH policy nodes keep
  the numeric owner ID.

## 2026-06-02 gRPC preauth response parity slice

- `CreatePreAuthKey` still returns the one-time full `hskey-auth-*` token, but
  `ListPreAuthKeys` now matches headscale-go by rendering stored modern keys as
  `hskey-auth-<prefix>-***` instead of leaking cached plaintext.
- `CreatePreAuthKey` missing-owner lookup failures now preserve headscale-go's
  raw lookup shape: gRPC `Unknown` with `user not found`, and grpc-gateway HTTP
  500/code 2.
- Added gRPC and gateway regressions for create/full-token versus list/masked
  token behavior and the missing-user status mapping.

## 2026-06-02 SSH check auth pair-binding parity slice

- SSH check-mode auth sessions and check-period auto-approval now match
  headscale-go's `(src_node_id, dst_node_id)` binding. `local_user` remains in
  the client callback URL but is no longer part of the server-side auth binding
  or last-auth cache key.
- Server-side check-period lookup now mirrors headscale-go's
  `SSHCheckParams`: first matching `check` rule by source node and destination
  node wins, without trusting or evaluating the callback `local_user` parameter.
- Added regressions for changed-local-user follow-up acceptance, pair-scoped
  check-period cache reuse, unchanged rejection for different src/dst pairs,
  and the existing policy-generation invalidation path.

## 2026-06-02 CLI policy set output parity slice

- `headscale policy set` over gRPC and direct database bypass now ignores
  structured output formats and always prints `Policy updated.`, matching
  headscale-go's CLI success output.
- Updated direct SQLite/Postgres bypass expectations and live gRPC coverage so
  `policy set -o json` preserves the text success shape while `policy get`
  remains raw policy text output.

## 2026-06-02 key expiration zero-time parity slice

- `CreateApiKey` and `CreatePreAuthKey` now mirror headscale-go's omitted
  expiration handling: absent request timestamps are stored as Go's non-nil
  zero `time.Time`, so create/list responses carry protobuf timestamp
  `0001-01-01T00:00:00Z` instead of `null` or an infinite sentinel.
- Gateway key JSON now omits genuinely absent optional timestamps like
  `lastSeen`, but preserves present zero-time expiration fields for upstream
  protojson parity.

## 2026-06-02 preauth CLI parent-user parity slice

- `headscale preauthkeys --user <id> create` is now accepted in addition to
  `headscale preauthkeys create --user <id>`, matching upstream's persistent
  flag placement.
- Legacy HTTP `preauthkeys list` output now masks listed keys with
  `hskey-auth-<prefix>-***` so list output does not reveal the one-time full
  token returned by create.

## 2026-06-02 health failure wording parity slice

- gRPC and gateway health checks now wrap database ping failures as
  `pinging database: <err>`, matching headscale-go's `Health` RPC error text.

## 2026-06-02 initial route auto-approval churn proof

- Initial `Stream:true` map requests that introduce auto-approved
  `Hostinfo.RoutableIPs` now have focused batcher-path coverage proving the
  upstream-shaped churn sequence: subnet-router lifecycle full update first,
  followed by the deferred `policy change` route auto-approval.
- The observer's pending batch and resulting route-aware map response are pinned
  in `stream_true_initial_routable_ips_wake_peer_with_allowed_ips`.

## 2026-06-02 auth completion route auto-approval churn

- Web/CLI `RegisterNode`/`AuthRegister` and OIDC registration completion now
  preserve the upstream `Change(nodeChange, routeChange)` shape when completed
  nodes carry auto-approved advertised routes: the auth lifecycle change remains
  `node added`, followed by a separate route-derived `policy change`.
- The live registry can now wake one auth-completion event with an ordered list
  of bounded map changes while preserving one stream generation, including the
  NodeStore rekey worker path.
- Focused registry tests pin new-node and same-key route approval churn, a
  persistent gRPC `RegisterNode` test pins stored/live approved routes plus map
  history, and the OIDC callback handoff test still passes through the same
  completion helper.

## 2026-06-02 CLI YAML and TLS-ALPN warning parity

- CLI process snapshots now cover YAML stderr envelopes for remote gRPC
  connection failure, remote API-key authentication failure, and live local
  gRPC health failure.
- Remote gRPC missing-API-key stderr now has process snapshots for human,
  JSON, json-line, and YAML output modes, keeping the local pre-connection
  error envelope aligned with the rest of the CLI transport failures.
- `configtest` and `server` now print headscale-go's non-fatal TLS-ALPN ACME
  warning when `tls_letsencrypt_hostname` uses `TLS-ALPN-01` while
  `listen_addr` does not end in `:443`.

## 2026-06-02 DNS CertDomains parity boundary

- Current headscale-go DNS config does not expose a `cert_domains` field in
  `hscontrol/types.DNSConfig`, and `dnsToTailcfgDNS` leaves
  `DNSConfig.CertDomains` empty for normal configured DNS.
- The paired `dns-hot-reload` Rust/headscale-go production smokes already pin
  the upstream-compatible HTTPS boundary by asserting that control-plane TLS
  hostnames are not synthesized into stock-client `DNS.CertDomains`.
- Rust's explicit `dns.cert_domains` pass-through remains covered by focused
  Rust runtime/unit tests and older wire golden coverage, but it is not a
  current headscale-go configuration parity requirement.

## 2026-06-02 Postgres grpc-gateway node lifecycle smoke

- Added a feature-gated production `headscale serve` smoke that drives the
  public grpc-gateway node lifecycle against a temporary Postgres database:
  user create, API-key auth, debug node create, register, list/get, policy/tag,
  route approval, rename, expire, backfill, and delete.
- The smoke compiles and uses the existing local skip path when
  `HEADSCALE_DB_POSTGRES_TEST_URL` is absent; CI provides the live Postgres URL.

## 2026-06-02 Postgres grpc-gateway API-key lifecycle smoke

- Added the sibling feature-gated production `headscale serve` smoke for public
  grpc-gateway API-key lifecycle over Postgres: a CLI bootstrap key authenticates
  gateway create, list, expire, delete, and post-delete list checks.
- The test asserts protojson `apiKey`/`apiKeys` field names, display-prefix
  deletion, `{}` mutation responses, and timestamp field projection on the real
  public gateway path.

## 2026-06-02 OIDC policy-churn stock-client smoke

- Added paired `oidc-policy-churn` Rust/headscale-go real-client wrappers over
  the production SQLite/file-policy OIDC topology. The smoke starts a
  CLI/auth-key viewer under a policy that hides the OIDC peer, completes OIDC
  registration for a second stock client, reloads policy with `SIGHUP`, and
  waits for the viewer to see the OIDC peer/profile.
- Added the row to `tools/real-client/smoke-matrix.sh`, the real-client README,
  and the PR real-client parity smoke list. Local Docker execution reached the
  Rust production server and viewer preauth-key minting, then stopped because
  the local OrbStack Docker socket was unavailable; CI should run the paired
  stock-client row.

## 2026-06-02 NodeStore timeout flush regression

- Added a focused NodeStore write-worker regression for `batch_size=2` and a
  partial batch that flushes on `recv_timeout`. The test proves the queued write
  does not publish immediately, then the timeout commits one `put`, clears queue
  depth, records batch-size bucket `1`, and publishes exactly one new snapshot.

## 2026-06-02 grpc-gateway base-0 path literal expansion

- Expanded the grpc-gateway path `uint64` e2e to cover the Go base-0 literal
  forms that the parser already supports: hex, binary, explicit octal,
  legacy leading-zero octal, and underscore-separated digits. The route-level
  test now matches the documented parser claim instead of only exercising hex.

## 2026-06-02 web-registration route-approval restart row

- Added paired default SQLite `web-register-route-approve-restart` real-client
  wrappers by reusing the existing restart-persistence harness route-approval
  mode. This mirrors the existing Postgres row and closes the default-vs-Pg
  matrix symmetry gap for web/CLI registration route approval across restart.

## 2026-06-02 randomizeClientPort default row

- Added paired default SQLite `randomize-client-port` real-client wrappers over
  the existing online/LastSeen harness. The row mirrors the existing Postgres
  coverage by applying `randomizeClientPort: true` and asserting the stock
  client self CapMap contains `randomize-client-port`.

## 2026-06-02 policy-reload route auto-approval batching

- Policy reload stream wakes now recompute route auto-approvals from the current
  machine snapshot before queuing the policy map batch. This matches
  headscale-go's reload ordering where auto-approvals are applied before mapper
  batching, so `Stream:true` observers do not receive a stale no-route map
  before the first post-reload batch tick.

## 2026-06-02 grpc-gateway admin error-shape pins

- Added grpc-gateway coverage for raw user rename errors, non-empty user
  deletion, preauth missing-ID no-op success, and malformed API-key display
  prefixes. API-key display-prefix parse errors now surface the headscale-go
  shaped `failed to parse ApiKey: ...` message instead of the generic
  `Database operation failed: ...` wrapper.

## 2026-06-02 Postgres OIDC policy-churn row

- Added paired `postgres-oidc-policy-churn` real-client wrappers and allowed
  the OIDC policy-churn harness to run with Postgres. File-policy churn now
  suppresses the default Postgres database-policy mode in both Rust TOML and
  headscale-go YAML configs, closing the remaining default-vs-Postgres smoke
  matrix asymmetry.

## 2026-06-02 grpc-gateway Octra boundary guard

- Added grpc-gateway e2e coverage proving replacement-mode `/api/v1` only
  exposes upstream headscale routes: Octra-only legacy node/register/status,
  balance, and transfer aliases return the standard HTTP 404/code 5 `Not Found`
  status JSON instead of being accepted by the headscale replacement gateway.

## 2026-06-02 Octra consumer boundary closure

- Added `docs/octra-consumer-boundary.md` as the replacement-parity boundary
  contract for Octra consumers: Octra-only admin mounting, preauth account
  policy, embedded CLI documentation, and settlement/billing behavior stay
  downstream unless they expose a reusable headscale-go contract.
- Added a swagger absence regression for the same Octra-only `/api/v1` routes
  covered by the runtime grpc-gateway 404 test, then removed
  `p2-octra-consumer-boundary` from the machine-readable open backlog. The
  backlog checker now requires the boundary doc, parity ledger row, and route
  tests whenever that row is absent.

## 2026-06-02 grpc-gateway raw semicolon query parser

- Matched current headscale-go/grpc-gateway query parsing for raw semicolon
  separators: authenticated URL query parameters and POST form fallback bodies
  now return HTTP 400/code 3 with `invalid semicolon separator in query`
  instead of letting `serde_urlencoded` treat the semicolon as ordinary text.

## 2026-06-02 dumpConfig v0.29 error-shape pin

- Updated hidden `dumpConfig` execution to match the pinned headscale-go
  v0.29 error prefix for an unwritable/missing `/etc/headscale` dump target:
  no legacy `Failed to dump config` stdout, and `dumping config: open ...` in
  the formatted error path.
- Added guarded process snapshots for human, JSON, json-line, and YAML
  `dumpConfig` failures when `/etc/headscale` is absent.

## 2026-06-02 dumpConfig default-warning parity slice

- Hidden `dumpConfig` now preserves headscale-go's timestamped
  `WRN no config file found, using defaults` stderr line when default config
  discovery finds no file before formatting the missing `/etc/headscale`
  dump-target error.
- Process snapshots normalize only the timestamp prefix and pin the warning
  before the human, JSON, json-line, and YAML error envelopes.
- Explicit `--config missing.yaml` remains a file-load fatal path rather than
  a default-backed warning path, matching the upstream boundary.

## 2026-06-02 native DERP protocol foundation

- Added clean-room DERP wire-frame helpers in `headscale-core`: current
  frame IDs, 5-byte big-endian headers, server-key magic, encrypted
  client/server-info envelope shape, packet frame layouts, peer
  present/gone metadata, ping/pong, health, restarting, unknown-frame
  preservation, and protocol packet/info caps.
- This is protocol foundation only. Runtime relay parity still requires a
  native session registry plus `/derp` upgrade handler; the supported
  production relay path remains the upstream `derper` sidecar until those
  pieces pass stock-client smokes.

## 2026-06-02 native DERP stream decoder foundation

- Added an incremental DERP frame decoder for native relay work so split TCP
  headers, split payloads, coalesced frames, unknown frame preservation, and
  oversized-frame rejection are handled before wiring a `/derp` upgrade route.

## 2026-06-02 native DERP relay registry foundation

- Added an in-process native DERP relay registry foundation in
  `headscale-core`: sessions register by node public key, `SendPacket` routes
  to connected peers as `RecvPacket`, unknown destinations return
  `PeerGone(NotHere)`, disconnects notify reverse-path peers with
  `PeerGone(Disconnected)`, and pings receive matching pongs.
- This still sits below the HTTP `/derp` upgrade and encrypted client-info
  handshake; production relay parity remains sidecar-backed until those layers
  and stock-client native DERP smokes are wired.

## 2026-06-02 native DERP auth/fuzz foundation

- Added NaCl-box-compatible DERP node-key helpers in `headscale-core` using
  the RustCrypto `crypto_box` crate: clamped X25519 node keys, server-key
  frame emission, encrypted `ClientInfo` and `ServerInfo` frame builders, and
  open/decode helpers for the DERP login sequence.
- `ClientInfo` and `ServerInfo` now pin the current Tailscale JSON field
  shapes, including lower/upper-case version aliases, optional 64-hex DERP mesh
  keys, `CanAckPings`, `IsProber`, and token-bucket server limits.
- Expanded `fuzz_derp` from legacy parser-only coverage to structured
  coverage for arbitrary raw bytes, raw frame encode/decode, typed frame
  round trips, split-stream decoding, and coalesced frames.
- This closes the native DERP crypto/auth payload foundation. The remaining
  native DERP gap is the public `/derp` HTTP upgrade/runtime loop, including
  `Upgrade: DERP`/websocket boundaries, server-key header behavior,
  verify-client admission, keepalive/ping runtime, and stock-client native DERP
  smokes.

## 2026-06-02 native DERP HTTP upgrade foundation

- Added an optional `WireState::native_derp` runtime and conditional `/derp`
  route in `headscale-api`. The route remains unmounted when the runtime is
  absent, preserving sidecar-owned deployments.
- The native route now handles the normal `Upgrade: DERP` path through Hyper
  upgrade, emits upstream-shaped `101` response headers (`Upgrade: DERP`,
  `Derp-Version`, `Derp-Public-Key`), sends the DERP server-key frame, opens
  encrypted `ClientInfo`, sends encrypted `ServerInfo`, registers the client in
  the native relay registry, and relays ping/pong plus packet frames through the
  core registry.
- Tests cover missing-upgrade `426` body parity, websocket-without-DERP-protocol
  rejection, and an in-memory native DERP login plus ping/pong stream.
- Remaining native DERP runtime gaps: keepalive/restarting/health runtime
  scheduling and stock-client native DERP smokes.

## 2026-06-02 native DERP config/runtime enablement

- Added explicit embedded DERP relay modes: sidecar remains the default for
  hand-authored Rust `server.embedded_derp` blocks, while upstream-shaped
  `derp.server.enabled` projects to native relay mode with `stun_only = false`.
- The CLI server now mounts the native `/derp` runtime when embedded native
  relay is enabled, persists the DERP private key as Tailscale's
  `privkey:<64 lowercase hex chars>` format, creates missing key directories,
  writes generated keys with `0600` on Unix, and rejects reuse of the server
  Noise key.
- Focused tests cover native relay configtest acceptance without a sidecar
  binary, sidecar validation preservation, native runtime attachment, Noise-key
  collision rejection, native relay startup without spawning a sidecar, and
  DERP key create/reload/malformed-key paths.

## 2026-06-02 native DERP WebSocket transport

- Added true DERP-over-WebSocket handling for native `/derp`: `Upgrade:
  websocket` is accepted only when the client offers the `derp` subprotocol,
  the 101 response negotiates `Sec-WebSocket-Protocol: derp`, and DERP frames
  are carried as a binary-message byte stream like Tailscale's `wsconn`.
- WebSocket text messages now fail closed with an unsupported-data close frame,
  while ping/pong/close control messages are handled separately from DERP frame
  bytes. `Derp-Fast-Start` remains raw-DERP-only and outside the WebSocket path.
- Focused tests cover WebSocket login, encrypted server info, ping/pong relay,
  and unsupported text-frame rejection.

## 2026-06-02 native DERP verify-client admission

- Added an optional native DERP client verifier hook that runs after encrypted
  `ClientInfo` login and before the client is registered in the native relay.
  When configured, failed admissions close the connection before any relay
  session is created.
- `headscale server` now wires `derp.server.verify_clients`/embedded
  `verify_clients` to the live `MachineRegistry`, matching headscale-go's
  fail-closed registry admission behavior for native DERP mode.
- Focused tests cover raw DERP and DERP-over-WebSocket allow/deny paths plus
  CLI runtime wiring against a registered and unknown node key.

## 2026-06-02 native DERP fast-start over raw TLS

- Added production raw-TLS dispatch for `GET /derp` with `Upgrade: DERP` and
  `Derp-Fast-Start: 1`. The raw listener now suppresses the HTTP `101` response
  exactly like upstream and passes post-header bytes directly into the native
  DERP stream driver.
- This closes the stock-client fast-start blocker for native embedded DERP,
  because Tailscale only enables this optimization after learning the DERP
  server key from the TLS meta certificate path.
- Focused tests cover fast-start request detection, WebSocket rejection, query
  strings, and preserving an already-pipelined encrypted `ClientInfo` frame
  across the raw-TLS peek buffer.

## 2026-06-02 native DERP real-client smoke row

- Added `REAL_CLIENT_RUST_DERP_RELAY_MODE=sidecar|native` to
  `tools/real-client/online-lastseen-common.sh`; sidecar remains the default,
  while native mode advertises the Rust HTTPS listener as the DERP port and omits
  sidecar-only `derper` config fields.
- Added the paired `postgres-derp-native` row over the production Postgres
  stock-client harness. The Rust side uses native embedded DERP relay mode, and
  the headscale-go side reuses its embedded-DERP wrapper for the same STUN,
  DERP-map, and forced-DERP ping assertions.
- The row is included in the real-client matrix and `PR_SMOKES`, bringing the
  Postgres stock-client matrix to ninety-two rows.

## 2026-06-02 Postgres policy-churn stock-client row

- Extended `tools/real-client/online-lastseen-common.sh` with an optional
  `REAL_CLIENT_RELOAD_POLICY_JSON` path plus post-reload peer-count assertions.
- Added paired `postgres-policy-churn` Rust/headscale-go rows. They register two
  stock clients through production Postgres auth keys, load a self-only database
  policy, prove no cross-user peers are visible, mutate the stored policy with
  `policy set`, and prove both live clients see the peer-map wake.
- The row is included in the real-client matrix and `PR_SMOKES`, bringing the
  Postgres stock-client matrix to ninety-three rows.

## 2026-06-02 DNS live resolver evidence slice

- Extended the authkey and online/LastSeen real-client harnesses with
  `tailscale debug resolve` assertions for peer MagicDNS names and explicit DNS
  record expectations.
- The paired MagicDNS rows now accept DNS and resolve each visible peer's
  MagicDNS name to the peer Tailscale IP from `tailscale status --json`,
  including the custom-domain and IPv6-only variants.
- The extra-record and DNS-edge rows now prove configured A/AAAA/CNAME records
  through the stock-client resolver in addition to the existing netmap checks;
  split DNS remains asserted at the tailcfg route/fallback resolver layer
  because these smoke rows intentionally configure synthetic split resolvers.

## 2026-06-02 Postgres runtime convergence evidence

- Extended the env-gated production Postgres `serve` restart process smoke in
  `headscale-cli/tests/cli_process.rs` to mutate user, database-backed policy,
  route, and tag state through local gRPC/CLI before restarting the real server.
- After restart, the smoke now checks CLI node/route/policy output plus
  `/debug/nodestore`, `/debug/routes`, `/debug/policy-manager`, and
  `/debug/filter` on the metrics/debug listener, proving the Pg rows hydrate
  into the live registry, route selection, policy manager, and map-response
  input state. The test remains
  `postgres-sqlx` feature-gated and skips cleanly when
  `HEADSCALE_DB_POSTGRES_TEST_URL` is absent.

## 2026-06-02 native DERP runtime-frame evidence

- Added DERP-over-WebSocket runtime evidence alongside the existing raw DERP
  path: native sessions now have focused tests for initial health-state replay,
  health-clear broadcasts, restart advisories, and scheduled keepalives on both
  transports.
- This narrows the remaining native DERP runtime gap to production lifecycle
  sources that decide when to set DERP health problems or announce server
  restart, not the native `/derp` frame loop or sidecar-preserving route mount.

## 2026-06-02 native DERP duplicate-health lifecycle slice

- Native DERP relay sessions now keep multiple same-node-key connections rather
  than silently replacing the older session in the relay registry.
- When a node key connects more than once, all same-key raw DERP and
  DERP-over-WebSocket sessions receive a server-originated duplicate-connection
  `Health` problem; when the duplicate clears, the remaining session receives an
  empty `Health` clear frame.
- Focused core, raw DERP, and DERP-over-WebSocket tests pin duplicate health
  emission and session-specific disconnect. This closed the first production
  health lifecycle source for native DERP and left server-restart announcements
  plus broader stock-client runtime assertions for follow-on slices.

## 2026-06-02 native DERP server-restart lifecycle slice

- Native DERP now has a production shutdown lifecycle helper that emits the
  upstream-shaped `Health("server restarting")` problem followed by a
  `Restarting` advisory with 1s reconnect delay and 5s retry window to active
  sessions.
- `headscale serve` now listens for SIGINT/SIGTERM, announces that native DERP
  shutdown lifecycle before returning from the serve waiter, and gives queued
  lifecycle frames a short flush grace when any active native DERP session
  accepted frames.
- Focused tests prove raw DERP and DERP-over-WebSocket sessions receive the
  shutdown lifecycle frames, and a server-waiter test proves the frames are
  emitted from the production shutdown path rather than only direct test API
  calls. The follow-on stock-client row below covers reconnect behavior after a
  production restart.

## 2026-06-02 native DERP stock-client restart slice

- Added `REAL_CLIENT_DERP_RESTART_AFTER_ASSERTIONS` to
  `tools/real-client/online-lastseen-common.sh`. When enabled, the harness
  restarts the same production server URL after the initial DERP assertions,
  waits for each stock client to return to a valid logged-in netmap, and reruns
  the requested STUN, DERP-map, and forced-DERP ping checks.
- Added the Rust `postgres-derp-native-restart` row. It uses native embedded
  DERP relay mode with production Postgres, so the restart crosses the same
  Rust HTTPS listener used as the advertised DERP port and exercises the
  shutdown health/restarting lifecycle that was wired in the preceding slice.
- The headscale-go side is intentionally a no-equivalent skip. Upstream
  headscale-go embedded DERP can be smoke-tested for its own restart behavior,
  but it does not exercise headscale-rs native DERP relay shutdown frames, so
  this row is not claimed as paired parity.
- The row is included in the real-client matrix and `PR_SMOKES`, bringing the
  Postgres stock-client matrix to ninety-seven rows.

## 2026-06-02 NodeStore update-many/delete churn slice

- The NodeStore write worker now revalidates update-many outcomes that require
  final node presence, so `set_approved_routes_many` followed by a delete for
  the same node in one worker batch returns zero applied changes and does not
  emit a stale `policy change` map wake.
- Focused worker and streaming map tests pin the observer-visible shape: the
  active `/map` stream waits for the map-batcher tick and then receives only the
  `PeersRemoved` delta for the deleted router.

## 2026-06-02 CLI nodes list user output parity

- `headscale nodes list --user` missing-value preflight now uses the shared
  upstream-style error formatter, so `-o json`, `-ojson-line`, and
  `--output=yaml` produce the same structured stderr envelopes as current
  upstream headscale-go `171fd7a3`.
- Added focused process snapshots for the three structured forms while
  preserving the existing human `Error: flag needs an argument: --user` output.

## 2026-06-02 Multi-address DNS map coverage slice

- Added focused map-response coverage for a MagicDNS-enabled tailnet with a
  dual-stack requester, a dual-stack peer, and an IPv6-only peer.
- The regression pins the address-family projection through `MapNode.Addresses`
  and `AllowedIPs`, while proving peer MagicDNS A/AAAA context does not leak
  into operator-owned `DNSConfig.ExtraRecords`, matching the headscale-go
  `MapNode.Name`/`Domain` separation.

## 2026-06-02 SQLite listener separation process smoke

- Added a default SQLite production `headscale serve` process smoke for the
  current headscale-go `171fd7a3` listener topology: public control,
  metrics/debug, and remote gRPC bind to separate sockets.
- The smoke creates a user and API key over local Unix gRPC, proves remote
  insecure gRPC admin traffic works through `grpc_listen_addr` with that API
  key, and asserts `/metrics` plus `/debug/config` are available on
  `metrics_listen_addr` while the public `listen_addr` fallback does not expose
  those diagnostic payloads.
- At the time, adjacent gaps included public-CA-shaped ACME failure-mode
  snapshots and config/map-stream churn; this slice only closed the default
  SQLite process-level listener-separation proof. Later no-network ACME
  coverage is recorded below.

## 2026-06-02 ACME HTTP-01 bind failure snapshot

- Added a focused `headscale serve` process snapshot for an HTTP-01 ACME
  challenge-listener bind collision. This exercises the same upstream
  `autocert` startup boundary without making public-CA network requests.
- The snapshot normalizes the dynamic loopback port and platform errno while
  asserting no ACME certificate cache entry is written after the listener bind
  failure.

## 2026-06-02 Multi-agent parity breadth slice

- Added `scripts/check_headscale_go_refs.py` and wired it into CI plus the
  real-client parity workflow so checked-in `headscale-go-current.sh` must match
  upstream `juanfont/headscale` `main`, while
  `headscale-go-baseline.sh` stays aligned with the pinned Go module version.
- Added paired `postgres-web-register-policy-churn` Rust/headscale-go
  stock-client rows. The shared online/LastSeen harness now honors
  per-client users during web registration, so the row registers Alice and Bob
  via web auth under isolating DB policy, mutates DB policy to allow both
  users, and asserts live maps converge from `0,0` to `1,1` peers. The row is
  selected in push/PR real-client CI, bringing the matrix to 100 Postgres rows
  and 153 deterministic PR rows.
- Added focused current-head dual-stack Taildrive/Taildrop cap-grant coverage:
  `policy-v2-taildrive-taildrop-caps` now asserts both IPv4 and IPv6 `SrcIPs`
  and `CapGrant.Dsts` for direct `drive` and reverse `drive-sharer` grants.
- Added current-upstream CLI parser coverage for
  `completion fish --no-descriptions -- bad`, pinning the exact Cobra stderr
  against `171fd7a3`.
- Added a TLS-ALPN public-CA-shaped `serve` runtime test with DERP map/source
  settings that forces a metrics listener bind collision before ACME issuance
  and asserts no Let's Encrypt cache entry is written.
- Added native DERP duplicate-reconnect coverage: after duplicate health is
  cleared when one same-key session disconnects, a later same-key reconnect
  reissues duplicate health to both live sessions.
- Added map-stream lifecycle/route batching coverage where a peer online event
  and route approval before the batch tick emit one incremental policy-style
  delta with peer online patch, route-bearing peer change, DNS config, and no
  extra observer frame.

## 2026-06-02 Pending parity authorization and delegated backlog slice

- Generated `headscale-api/tests/current_head_go_parity_pending.rs` from the
  current-head surface inventory, first authorizing the 111 audited backlog
  rows as ignored Rust stubs plus one active authorization-count test. After
  worker adoption and inventory refresh, the file now has zero ignored pending
  tests and one active zero-count guard.
- CI now checks the generated backlog stubs before real-client metadata. The
  refreshed current-head inventory reports all 142 upstream integration tests as
  `present`, with backlog count 0, and the inventory scanner explicitly ignores
  the generated file and `go_parity_pending_` prefix so pending stubs never
  count as parity evidence.
- Six worker agents were dispatched across all current backlog clusters:
  tags, ACL/policy/grant-cap, route/DNS, CLI/API auth, SSH, and the combined
  auth/OIDC/general/DERP slice.
- Adopted completed worker coverage/fixes: same-machine auth-key and web/OIDC
  reauth now preserve stable node/user IDs, native DERP replays current health
  before keepalive, `auth reject --output=yaml` missing `--auth-id` matches
  current upstream stderr, and TLS-ALPN explicit `server.https_listen` startup
  failure avoids public-CA cache writes before listener bind failure.
- Adopted the six backlog slices: exact-name focused evidence for tags,
  ACL/policy/grant-cap, route/DNS, CLI/API auth, SSH, and
  auth/OIDC/general/DERP. The ACL/grant-cap slice also fixes companion cap
  grants for range-style source IP sets by expanding ranges to CIDRs.
- Added paired `ssh-profile-subdomain-deny` and
  `postgres-policy-rename-restart` real-client rows; the Postgres row is now in
  PR real-client CI, bringing deterministic PR selection to 155 rows.

## 2026-06-02 Postgres SSH profile subdomain denial

- Added paired `postgres-ssh-profile-subdomain-deny` real-client rows. They run
  the current-head `localpart:*@example.com` profile policy against clients with
  `ssh-it-user@sub.example.com` profile emails and assert the denied stock-client
  status `255`, empty stdout, and stable first stderr line against both
  headscale-rs and current headscale-go.

## 2026-06-02 duplicate NodeKey and preauth display parity

- Removed Rust's live `node_key` uniqueness index and updated SQLite/Postgres
  node helpers so duplicate live NodeKeys are stored like headscale-go while
  `get_by_node_key` keeps deterministic earliest-row lookup semantics.
- Persistent auth-key reauth paths now allow the current upstream case where
  the same machine and NodeKey register as a different user, and the
  registration-store return path fetches by numeric node ID so duplicate
  NodeKeys do not hydrate the wrong row. The in-memory wire registry still
  rejects occupied rekeys because that registry cannot represent duplicate live
  NodeKeys without overwriting an entry.
- Fixed gRPC/REST preauth-key list display masking for URL-safe prefixes that
  contain `-`: list responses now slice the fixed 12-character prefix and
  return `hskey-auth-<prefix>-***`, while create responses still return the
  one-time full token.

## 2026-06-02 SSH localpart profile variant regression

- Added a focused Rust parity regression for current-head SSH localpart profile
  variants. It proves `localpart:*@example.com` compiles a special-character
  profile email such as `dave+sshuser@example.com` into the concrete client
  login user `dave+sshuser`, and that a domain/profile mismatch emits only
  root-deny `sshUsers` rather than leaking the localpart pattern.

## 2026-06-02 Postgres web-registration custom-domain row

- Added paired `postgres-web-register-custom-domain` real-client rows. They run
  the production Postgres no-auth web/CLI registration flow while enabling
  MagicDNS with a non-default base domain, then assert the stock-client netmap
  carries that configured suffix for both headscale-rs and current headscale-go.

## 2026-06-02 headscale-go auth-key relogin TLS harness

- Fixed the shared headscale-go auth-key smoke harness so every auth-key
  relogin variant defaults to HTTPS when `REAL_CLIENT_HEADSCALE_GO_TLS` is not
  explicitly set. This covers the current-head different-user relogin row that
  was previously still advertising an HTTP `server_url`; Tailscale v1.94.1 can
  force the follow-up register request toward HTTPS/443 after Noise dialing and
  fail before reaching the configured random port.

## 2026-06-02 subagent parity edge adoption

- Added gateway auth-ID parser coverage for overlong `hskey-authreq-` values
  on `/api/v1/auth/register`, `/api/v1/auth/approve`, and
  `/api/v1/auth/reject`, preserving the upstream split where register remains
  an `Unknown`/HTTP 500 envelope while approve/reject are
  `InvalidArgument`/HTTP 400 envelopes.
- Added `/verify` DERP admission denial coverage for an unknown node key,
  complementing the existing registered-node allow case with the upstream
  `{"Allow":false}` response body.
- Added map-stream batching coverage where an `endpoint/DERP update` patch is
  queued before the same peer is deleted; the batch tick now proves only
  `PeersRemoved` is emitted and stale `PeersChangedPatch` entries are
  suppressed.
- Matched config-backed remote gRPC CLI connection setup errors by prefixing
  `cli.address`-derived missing API-key failures with
  `connecting to headscale:` while preserving direct flag/env behavior.

## 2026-06-02 second subagent parity edge adoption

- Added current-upstream CLI snapshots for default and
  `HEADSCALE_UNIX_SOCKET` local gRPC connection failures. Default-loaded local
  admin commands now emit the upstream no-config warning and wrap setup
  failures as `connecting to headscale: connecting to <socket>: context
  deadline exceeded`.
- Added a `serve` early-fatal snapshot for invalid HTTP-01
  `tls_letsencrypt_listen`, extending the configtest-equivalent server-init
  matrix before state startup.
- Added `DNSConfig.ExtraRecords` serde coverage for lower-case
  headscale-style `name`/`type`/`value` input while continuing to emit
  canonical tailcfg PascalCase JSON.
- Added primitive-level node persistence coverage proving stale `user_id`
  values hit FK enforcement on create/update, while tagged nodes clear
  ownership before FK enforcement like upstream.
- The `22ec6ed` real-client workflow failure was infrastructure-only: Docker
  timed out pulling `postgres:16` before checkout. The same push's CI failure
  was a clippy `collapsible_if` in `merged_connect_args`; this batch collapses
  that branch and passes the exact workspace clippy command locally.

## 2026-06-02 third subagent parity edge adoption

- Added config-file `unix_socket` CLI coverage. Top-level config-provided
  sockets now wrap connection setup failures as `connecting to headscale:`,
  matching current upstream behavior for config-derived local gRPC dialing.
- Added a direct tonic transport test for auth gRPC error envelopes, proving
  malformed `AuthRegister`, missing-session `AuthApprove`, and malformed
  `AuthReject` status codes/messages survive the real server/client boundary.
- Added current-head SSH fixture coverage for the multi-address
  SSH/DNS/route-policy matrix, proving dual-stack source principals and
  `acceptEnv` survive `tag:server` target compilation.
- Added native DERP raw runtime relay coverage: two admitted sessions now
  prove `SendPacket` routes as `RecvPacket`, and the destination observes
  `PeerGone(Disconnected)` when the source session drops.

## 2026-06-02 fourth subagent parity edge adoption

- Added wire-level tag/expiry parity coverage for tagged auth-key
  registration. A tagged node now proves the `/map` self node uses the
  synthetic Tagged Devices identity, carries the forced tag, and omits
  `KeyExpiry`/false `Expired` even when the registration body carried a client
  expiry.
- Added native DERP mixed-transport relay coverage in both directions:
  WebSocket-to-raw and raw-to-WebSocket sessions now prove `SendPacket`
  becomes `RecvPacket`, and the destination receives
  `PeerGone(Disconnected)` when the source drops.
- Added remote TLS gRPC CLI snapshots for `auth approve` missing-session
  server errors in human and JSON-line output, extending local Unix-socket
  auth error coverage to the remote config path.
- Added a real `headscale serve` runtime projection test for upstream-shaped
  `derp.server` config and explicit self-signed `server.https_listen`; it
  asserts `/debug/config` DERP fields/DERPMap and HTTPS `/health` without ACME,
  public CA traffic, or Docker.
- Added `postgres-web-register-policy-churn-restart` to the deterministic
  PR/push real-client set and CI metadata guard. The checked PR matrix now
  reports 156 deterministic rows.

## 2026-06-02 fifth subagent parity edge adoption

- Adopted native DERP verify-client admission counters split by raw DERP and
  DERP-over-WebSocket, plus restart-row `Peer[].Relay` status assertions for
  `postgres-derp-native-restart`. The native DERP stock-client row remains
  open for broader runtime and transport-forcing coverage.
- Added live stock-client native DERP admission assertions to the Rust-only
  Postgres native DERP rows. They read `/debug/derp` and require native
  verify-client mode, at least two raw allowed admissions, and zero raw or
  WebSocket denials. The row remains open because stock-client
  DERP-over-WebSocket forcing is not yet proven.
- Added an opt-in WebSocket-forced native DERP harness path:
  `REAL_CLIENT_FORCE_DERP_WEBSOCKET=true` injects `TS_DEBUG_DERP_WS_CLIENT=1`
  into the client `tailscaled` process, and
  `test-derp-server-websocket-scenario-smoke.sh` now requires at least two
  native `websocket_allowed` admissions. This stays outside the mandatory
  matrix until the selected stock Tailscale image is proven to carry the
  `ts_debug_websockets` build tag.
- Adopted exact successful Tailscale SSH stderr assertions for the paired
  `ssh-accept-env` and `postgres-ssh-accept-env` rows. Broader SSH
  status/stdout/stderr coverage remains open.
- Adopted live local-gRPC `health` stdout snapshots for JSON, JSON-line, and
  YAML and matched upstream YAML success output trailing-blank-line behavior.
  The lower-priority CLI residual row remains open for remaining utility and
  process-level output drift.
- Closed `p0-change-merge-filter-semantics`: map-change content flags now pin
  targeted/full/self updates, PingRequest preservation, policy/runtime peer
  computation, DNS/DERP/domain inclusion, and scoped peer-patch filtering.
  Filtered peer deltas no longer advance unrelated peer baseline state.
- Adopted the DNS-edge live split-resolver fixture and paired DNS-edge smoke
  assertions for a real split-suffix A lookup. The DNS row remains open until
  the paired Docker stock-client rows are run successfully.

## 2026-06-02 Postgres auth terminal-session coverage

- `AuthRegister` now refuses pending auth IDs that already have a terminal
  cache outcome, so a CLI/gateway register cannot complete a previously
  approved or rejected session from the registration cache.
- Added a focused upstream gRPC regression for approved and rejected terminal
  auth sessions, plus a feature-gated production Postgres `headscale serve`
  smoke covering CLI `auth approve`, grpc-gateway `auth reject`, failed
  register-after-terminal-auth, restart, and empty node persistence.
- The `p0-production-postgres-process-mutations` row remains open until the
  new Postgres process smoke runs against a live `HEADSCALE_DB_POSTGRES_TEST_URL`
  and broader mutation/restart coverage is complete.

## 2026-06-02 policy compat fixture adoption

- Added `policy-v2-tailscale-compat-fixtures` to the pinned Go/Rust
  differential suite, raising the pinned golden to 93 scenarios. The fixture
  covers representative ACL, app grant, route, auto-approver, via-route, and
  SSH accept/check compatibility slices.
- Matched Go's grant-before-ACL packet-filter order, fixed wildcard app-cap
  destination reduction for per-node `CapGrant` output, and kept broad
  wildcard ACL destinations from counting as route-prefix overlap for
  `grants[].via` `UsePrimary`.
- The `p1-policy-v2-compat-fixtures` backlog row remains open because this is
  a representative pinned slice, not an exhaustive audit of the upstream
  ACL/grants/routes/SSH compatibility corpus.

## 2026-06-02 SSH stock-client exactness closure

- Broadened paired stock-client SSH success assertions across the shared
  auth-key, Postgres/common, and OIDC check-period harnesses. Default
  `hostname` allow paths now require status `0`, stdout exactly equal to the
  target stock-client hostname, and empty stderr unless an explicit exact
  stderr override is configured.
- OIDC SSH `checkPeriod` cache replay now records and asserts status `0`,
  exact target-hostname stdout, empty stderr, and no second dynamic auth URL.
  The initial browser-approved check still keeps the pre-approval auth URL
  stderr non-exact because the URL is intentionally dynamic.
- Removed `p0-broader-ssh-client-status` from the open backlog. Remaining
  non-exact SSH paths are dynamic auth URL and bounded timeout cases rather
  than stable deterministic status/stdout/stderr gaps.

## 2026-06-02 route-via-health reload restart edge

- Added paired `route-via-health-reload-restart` and
  `postgres-route-via-health-reload-restart` Rust/headscale-go rows. The
  shared restart harness now combines a shared same-tag `grants[].via` target
  with distinct route-health approval tags, reloads policy to add the standby
  router, restarts the same server URL, and asserts stock-client observed route
  ownership failover.
- Extended the route-edge audit and real-client matrix to include the new
  default/Postgres mirrors. The `p1-route-via-health-edge-coverage` row remains
  open because broader route-via/route-health edge matrices remain before full
  route parity closure.

## 2026-06-02 ACME public-CA no-network drift closure

- HTTP-01 ACME startup now bootstraps public/remote TLS from in-memory
  self-signed material when the Go/autocert cache is missing, binds configured
  listeners before online issuance, then reloads public HTTPS and remote gRPC
  TLS after issuance writes the cache.
- The raw public HTTPS listener bind now happens synchronously in `serve`, so
  HTTP-01 and TLS-ALPN fail on deterministic HTTPS bind collisions before
  either issuer can contact the configured public CA.
- `headscale-cli/tests/acme_https_runtime_breadth.rs` now covers
  public-CA-shaped no-network startup failures for HTTP-01 metrics,
  remote-gRPC, and public-HTTPS collisions plus TLS-ALPN public-HTTPS collision,
  while preserving the existing TLS-ALPN metrics/HTTP/remote-gRPC/ignored
  HTTP-01-listen cases. These tests assert no ACME cache or account entries are
  written.
- Removed `p1-config-tls-acme-public-ca-drift` from the open backlog. Actual
  live public-CA smoke coverage remains an externally-networked release concern,
  not an open deterministic parity gate.

## 2026-06-02 CLI Unix-socket structured failure snapshots

- Added exact process-level structured output snapshots for local Unix-socket
  gRPC connection failures across default config JSON, `HEADSCALE_UNIX_SOCKET`
  JSON-line, and configured-socket YAML paths.
- The `p2-cli-output-error-residuals` row remains open because broader
  current-upstream CLI output/error parity still has residual utility and
  process-level surfaces to pin.

## 2026-06-02 Postgres preauth restart process smoke

- Added `serve_postgres_runtime_gateway_preauth_key_restart_smoke`, a
  feature-gated live-Postgres production `headscale serve` process test. It
  creates a user and tagged reusable/ephemeral preauth key through the
  authenticated public grpc-gateway, restarts the same server config against
  the same temporary Postgres database, asserts the hydrated preauth-key
  owner/tag/reusable/ephemeral/unused metadata, then expires and deletes the
  key after restart.
- The `p0-production-postgres-process-mutations` row remains open. This slice
  complements the API-key revocation restart smoke but does not close the
  remaining user/node/policy/route/auth-session/config and map-churn breadth.
