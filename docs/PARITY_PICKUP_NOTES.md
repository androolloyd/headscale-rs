# Headscale-Go Parity Pickup Notes

Updated: 2026-05-31 16:23 ADT

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
  route-health restart, route-health primary-selection restart, route-health reload+restart, route-health
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
  paired env-gated Pg auth-key, online/LastSeen, web-registration, route-approval, exit-node
  route-approval, web-registration route-approval, OIDC, OIDC restart, OIDC route-approval
  restart, web-registration restart, restart-persistence, route-via restart,
  route-via reload+restart, route-via multiprefix restart, route-via multiprefix reload+restart, route-health restart, route-health
  primary-selection restart, route-health reload+restart, route-health
  all-unhealthy restart, route-health mixed-exit restart, route-health
  mixed-exit reload+restart, route-health mixed-exit all-unhealthy restart, and
  route-health mixed-exit all-unhealthy reload+restart stock-client smokes are
  checked into the real-client matrix.
  The production Pg stock-client harness also covers tagged preauth, post-login
  tag replacement, invalid tag-update rejection, and web reauth clearing forced
  tags through paired `postgres-tagged-preauth`, `postgres-tag-update`,
  `postgres-tag-update-invalid`, `postgres-tag-reauth-clear`, and `postgres-acl-allow` rows. Push/PR
  CI now provisions Postgres for all fifty-seven Pg rows, including
  `postgres-online-lastseen`, `postgres-ping-lifecycle`, `postgres-magicdns`,
  `postgres-magicdns-custom-domain`,
  `postgres-extra-records`, `postgres-dns-disabled`, `postgres-dns-edge`,
  `postgres-dns-hot-reload`,
  `postgres-magicdns-ipv6-only`, `postgres-prefix-family-dual-stack`,
  `postgres-prefix-family-ipv4-only`, `postgres-prefix-family-ipv6-only`,
  `postgres-web-register-tags`, `postgres-web-register-unowned-tag`,
  `postgres-route-advertise`, `postgres-acl-allow`, `postgres-route-via`, `postgres-route-via-same-tag`, `postgres-route-via-reload`, `postgres-route-via-multiprefix`, `postgres-route-via-multiprefix-reload`, `postgres-route-via-same-tag-restart`, `postgres-route-health`,
  `postgres-ssh-oidc-check`,
  `postgres-ssh-cli-check`, `postgres-ssh-oidc-check-period-cache`, and the paired
  wrong-user, expired, and cancelled OIDC SSH-check denial rows; broader Pg
  stock-client serve smokes remain for the remaining registration/config
  surfaces
- Broader paired route-via and route-health stock-client edge matrices beyond the covered reload/restart basics
- Broader Tailscale SSH current-head client status/stderr/profile variants;
  the policy-level `acceptEnv`, `check` hold-and-delegate, and host-destination
  rejection scenarios are now promoted into the default Go-vs-Rust differential
  gate
- Production restart and mutation smokes for web/CLI/OIDC policy and map churn,
  especially NodeStore worker batching semantics and remaining reason/state edge
  deltas
- Native Rust DERP relay decision; sidecar DERP parity is documented and covered, but native relay is not implemented or claimed

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
  baseline because pinned v0.28.0 predates executable `/debug/ping`.
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
