# Headscale-Go Parity Pickup Notes

Updated: 2026-06-01 21:33 ADT

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
  all eighty-nine Pg rows, including
  `postgres-authkey-nonreusable`, `postgres-authkey-expired`,
  `postgres-authkey-relogin-same-user`,
  `postgres-authkey-relogin-expired`,
  `postgres-authkey-relogin-different-user`,
  `postgres-authkey-relogin-deleted`,
  `postgres-authkey-relogin-route-preserve`,
  `postgres-taildrop-capmap`, `postgres-derp-private`,
  `postgres-online-lastseen`, `postgres-ping-lifecycle`, `postgres-magicdns`,
  `postgres-magicdns-custom-domain`,
  `postgres-extra-records`, `postgres-dns-disabled`, `postgres-dns-edge`,
  `postgres-dns-hot-reload`,
  `postgres-magicdns-ipv6-only`, `postgres-prefix-family-dual-stack`,
  `postgres-prefix-family-ipv4-only`, `postgres-prefix-family-ipv6-only`,
  `postgres-web-register-tags`, `postgres-web-register-unowned-tag`,
  `postgres-route-advertise`, `postgres-route-primary`,
  `postgres-route-primary-failover`, `postgres-route-primary-sticky`,
  `postgres-route-primary-withdraw`,
  `postgres-web-register-route-approve-restart`, `postgres-acl-allow`,
  `postgres-route-via`, `postgres-route-via-same-tag`, `postgres-route-via-health`, `postgres-route-via-reload`, `postgres-route-via-multiprefix`, `postgres-route-via-multiprefix-reload`, `postgres-route-via-same-tag-restart`, `postgres-route-health`, `postgres-route-health-all-unhealthy`, `postgres-route-health-all-unhealthy-reload`, `postgres-route-health-mixed-exit`,
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
  the checked-in matrix has 127 paired rows, and the push/PR set had no unknown
  or duplicate row IDs while covering all 57 Postgres stock-client rows.
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
- Remaining runtime churn work: persistent wire-registry sync, map-request
  auto-approval reasons, and the broader NodeStore worker batching semantics.

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
  updates and rekeys emit upstream-style `node added` unless owner/tag/IP/active
  approved-route identity changes require a global `policy change`.
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

## 2026-06-01 auth-key different-user relogin rejection smoke slice

- Added paired `authkey-relogin-different-user` Rust/headscale-go rows and
  paired `postgres-authkey-relogin-different-user` Rust/headscale-go rows.
- The shared auth-key relogin flows can now mint the fresh relogin key for a
  deterministic alternate user, run `tailscale logout`, attempt `tailscale up`
  with the existing stock-client state, and require the client to remain logged
  out.
- The rejection assertion compares pre/post persisted node state so the
  rejected relogin cannot duplicate the node or silently transfer it to the
  different user.
- This closes the different-user relogin rejection gap.

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

## 2026-06-02 CLI consumed-help value parity slice

- Global `--config` and `--output` now accept hyphen-prefixed values like
  current-upstream Cobra, so `--help` is consumed as the flag value for forms
  such as `health --config --help`, `serve --config --help`,
  `configtest --output --help`, and `version --output --help`.
- The raw help pre-parser now only emits static help when `-h`/`--help` is an
  unconsumed help flag, preserving the existing upstream help snapshots for
  forms such as `health --config missing.yaml --help`.
- Focused process snapshots cover the consumed-help config/configtest cases,
  while version coverage asserts the upstream human fallback output.
