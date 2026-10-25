# Changes

## 2026-10-25 — origin/main reconciled into the verified parity branch

- Merged the six `origin/main` commits (2026-10-15 to 2026-10-17: YAML backend,
  a parallel v0.29.5 compatibility pass, DERP client authorization, mesh-policy
  persistence, registry handoff) into the branch verified against the real
  headscale-go v0.29.5 binary. Every hunk was classified; where both sides
  implemented the same behaviour the verified side was kept unless Go's source
  or binary showed otherwise.
- Ported: the vendored SQLite 3.46 WAL-reset backport (`vendor/libsqlite3-sys`,
  under the vendor provenance and test gates); live native DERP client and peer
  authorization; embedded mesh policy persistence (the policy persistence trait
  now lives in `policy::persistence` and returns `chrono` timestamps); peers
  removed while a node was offline are sent on reconnect; a second stream of an
  already-online peer gets the forced `Online` patch; WebSocket control streams
  omit the EarlyNoise payload as Go does; a self node with an invalid FQDN is
  refused; a default route overlaps a `*` grant like `autogroup:internet`; an
  empty SSH policy compiles to an explicit empty rule list; an SSH follow-up
  with a changed local user is refused; two new parity scenarios
  (`release-0295-empty-ssh`, `release-0295-policy-metadata`).
- Not taken: main's two repair migrations (they have no Go migration ID, so
  they would re-run on every Go-imported or already-migrated database and
  re-clear tagged-node expiry that Go leaves alone); main's `runtime_only`
  persistence flag and per-method persist mutex (the verified side already
  persists runtime state with Go's `persistNode` column mask); main's single
  deletion response split (Go sends one response).
- Compatibility: a database that an `origin/main` build already migrated
  records migration `20261015000018` (PostgreSQL `20261015000011`), which this
  tree does not have, and import stops with a missing-version error. Delete that
  one row from `_sqlx_migrations` to continue; no repository fixture contains it.
- Verification on the merged tree (pinned Rust 1.99.0): 2262 workspace tests
  passed, 0 failed; clippy `-D warnings` and fmt clean in every CI configuration
  and for the excluded crates; the Go differential matches on all 106
  scenarios; every vendored crate's own suite passes; stock-client rows
  authkey, relogin, web-register, OIDC, ping, private DERP, restart persistence,
  online/last-seen, route advertise and approve, tagged pre-auth and ACL allow
  pass.

## 2026-10-25 — Concurrent registration and `/map` no longer queue behind the NodeStore writer

- Registrations were effectively serial (about 1 per second with the 500 ms
  default batch period; CLI `nodes register` bursts timed out). A handler
  blocked its runtime worker on the NodeStore write batch, which also stranded
  sqlx's connection-return task in that worker's local queue, so with a small
  pool (one connection under the headscale-go pool settings) each registration
  held the whole database pool for its two writer round trips.
- NodeStore writes from the registration, auth-completion and `/map` paths now
  await a tokio oneshot instead of blocking a worker, and the remaining
  blocking callers hand their worker off with `block_in_place`. A burst shares
  one batch per period however large it is.
- The writer batches like `NodeStore.processWrite`: it applies at the next tick
  of a free-running period or when `node_store_batch_size` is reached, and an
  arriving write no longer extends the window. Stopping applies the open batch
  at once.
- Existing-node re-registration performs its NodeStore edit before taking the
  native save lock, which now covers only the SQL write (as `persistNode` does
  in headscale-go).

## 2026-10-25 — Quality gates that gate

- Pin the compiler in `rust-toolchain.toml` and use it everywhere: all
  workflows (via `.github/actions/setup-rust`), both Dockerfiles (they built on
  an unqualified 1.99) and the fuzz jobs (a dated nightly).
  `scripts/check_toolchain_pin.py` fails on drift. Floating `stable`/`nightly`
  had turned `main` red from 2026-10-16 (new 1.99 clippy lint; nightly rustfmt).
- Clear RUSTSEC-2026-0382/0381/0383 (`rustls-webpki` 0.103.16, `webpki-roots` and
  `webpki-root-certs` 1.0.11; the vendored `sqlx-core` pinned `webpki-roots`
  exactly to 1.0.9) and RUSTSEC-2026-0386 (`tokio` 1.54.1 in the fuzz lockfile).
  Resync the fuzz lockfile with its manifests, bump the two tool crates'
  lockfiles, and audit all four committed lockfiles in the supply-chain job.
- Vendored crates: `scripts/check_vendor_provenance.py` checks every `vendor/*`
  crate against its pristine crates.io archive plus the recorded patch set
  (`vendor/PATCHES.json`); `vendor-tests.yml` runs each crate's own upstream
  suite against the patch; `headscale-vendor-conformance` asserts the h2, rustls
  and pgx Go-exactness behaviour. See `docs/ci-quality-gates.md`.
- Clear the clippy 1.99.0 findings across the workspace (assertion forms,
  `as_chunks`, two needlessly async functions) so the tree lints clean on both the
  previously qualified 1.96.0 and 1.99.0. The qualified toolchain is 1.99.0
  (was 1.96.0): `rust-toolchain.toml`, both Dockerfiles and the CI jobs use it.
- `check_headscale_go_refs.py --remote` warns, instead of failing every run,
  when headscale-go `main` has moved; a nightly `pin-freshness` job fails on it.

## 2026-10-25 — Resource-limit hardening from a public assessment

- Registration cache: per-source quota for unauthenticated pending
  registrations and a per-registration cap on pending OIDC states, so one
  source cannot evict other users' pending approvals or sign-ins.
- Stream the `derp.urls` and ACME response reads with a hard limit (OIDC reads
  were already bounded) and truncate remote bodies embedded in errors and logs.
- Embedded DERP: cap same-key sessions, make duplicate-health transition-only,
  drop instead of blocking on full queues, bound frame and WebSocket sizes, add
  a write timeout, and reject mesh-only frames from regular clients.
- Add `policy.ssh.allow_{agent,local_port,remote_port}_forwarding` (default
  true, matching headscale-go) to stop authorising SSH forwarding.

## 2026-10-25 — Evidence gaps: /health, packet-filter parity, Postgres

- `GET /health` now pings the database like headscale-go's `HealthHandler`
  (`State.PingDB`, one-second bound): 200 `{"status":"pass"}` or 500
  `{"status":"fail"}`, both with Go's trailing newline. The ping goes through
  `MachineRegistrationStore::ping_database` (overridden by the SQLite and
  Postgres persistent stores); a wire surface without a database-backed store
  still always passes. The gRPC `Health` RPC shares the same one-second bound.
  Verified against the real v0.29.5 binary with its Postgres database dropped
  (`tools/parity/health_db_down_diff.sh`).
- The differential harness no longer carries its own filter compiler: its Rust
  side builds a `MachineRegistry` + `PolicyStore` and reads the production
  global and per-node `PacketFilters["base"]` output
  (`tools/parity/headscale-rs/src/production_filter.rs`). It now compares the
  filter of every node, not only named ones, and `PARITY_FILTER_ORDER=emitted`
  disables the intra-rule sorting on both sides. A golden test
  (`headscale-api/tests/packet_filter_golden.rs`) runs the production compiler
  against `golden/headscale-go-v0.29.5.json` under plain `cargo test`. No
  production difference was found: all 104 scenarios match in both modes.
- Postgres: the production server could not start (SQLSTATE 08P01 `invalid
  message format` on the first multi-column query). The vendored
  sqlx-postgres `Bind` encoder wrote the result-format count from the
  parameter-format slice (an upstream 0.8.6 bug that per-column result formats
  exposed). Fixed, with a live-database test of the production pool.
  A new registration whose hostname collides with an existing node's name now
  gets Go's `-1`, `-2` suffix instead of failing on the unique `given_name`
  index (hit by a different user logging in from the same host).
- Other Rust-only failures from the Postgres stock-client rows (Go passes
  them): `nodes approve-routes --routes ""` sent `[""]` instead of the empty
  list cobra produces, so clearing approvals failed; the sidecar `derper` was
  started with `-verify-clients` even when the control `/verify` URL was set,
  which made it demand a local tailscaled and reject every client.
- Row scripts: `psql`/`pg_dump` got `PGSSLMODE=false` (libpq rejects it) when
  the Postgres URL had no `sslmode`; the user-rename row now pins Go's
  "owner name updates after restart" boundary for headscale-rs too.
- Stale live-Postgres test expectations (never run before, 11 of them) now
  follow Go.

## 2026-10-24 — First build and test of the v0.29.5 parity tree

- Fix the vendored-crate and workspace build breaks that kept the tree from
  compiling, then reconcile roughly 196 test failures against the real
  headscale-go v0.29.5 binary: stale expectations were updated, real defects
  fixed (unix-socket gRPC clients, gateway 401, native policy parser on the
  admin paths, post-registration route auto-approval on the auth-key, OIDC,
  web and gRPC registration paths, offline exit routes in `ListNodes`,
  `/debug/routes` ordering, `derp.urls` crypto-provider panic, and several
  message and path details).
- Clear the pedantic/nursery clippy backlog (no blanket allows) and format the
  workspace. Workspace tests: 2114 passed, 0 failed, 1 ignored.

## 2026-10-17 — dynamic native DERP authorization (from the `main` line)

- Add a directional peer-verification hook. Raw and WebSocket sessions reread
  configured client authorization for each frame and both packet endpoints,
  including queued delivery; peer policy is checked before forwarding and
  before writing received packets.
- Refuse mesh-only and server-only frames from ordinary client connections.
  A client login does not authorize forwarded-source spoofing or peer teardown.
- Unconfigured verification retains the library's compatibility defaults.
  Embedders must supply current membership and peer policy. These checks see
  endpoint keys and opaque packets, not IP destinations, ports or payment.
  Revocation applies on the next frame/keepalive; completed IO is not recalled.

## 2026-10-17 — durable embedded mesh control (from the `main` line)

- Share SQLite/PostgreSQL policy persistence between HTTP admin and gRPC;
  commit HTTP policy writes before publishing them and hydrate policy explicitly
  before an embedder opens its listeners. Serialize database writes and cache
  publication, preserve HuJSON and timestamps, and reject HTTP replacement of
  externally managed policy. This is a library feature for embedders:
  `headscale-cli` does not wire the HTTP admin persistence.
- Return bound HTTP/HTTPS addresses to embedding hosts. Raw TLS connections
  were already tracked by this branch's HTTP shutdown group and are cancelled
  when it closes, so main's separate connection set is not carried.

## 2026-10-16 — headscale-go v0.29.5 compatibility update (from the `main` line)

- The official v0.29.5 release is this branch's pinned baseline. The `main`
  line's two extra differential scenarios (`release-0295-empty-ssh`,
  `release-0295-policy-metadata`) are checked in and match Go, which makes 106
  scenarios in the Go/Rust differential and its golden (the 104 existing golden
  entries are unchanged).
- The release semantics that line implemented (capability checks,
  authenticated registration and single-use SSH approval, OIDC confirmation and
  cookies, split map removal frames, peer metadata/key classification,
  connection lifecycle, durable node IDs/expiry/deleted-key handling in runtime
  persistence) were reconciled hunk by hunk with the verified implementation;
  where both lines implemented a behaviour, this branch's code is kept. What
  landed from that line: an explicit empty SSH policy for a document without
  `ssh` rules, `"*"` counting as reaching the internet for exit-route election,
  removal of peers that disappeared while a client was offline right after its
  initial map, a forced online patch for each new connection, no early-noise
  write on the WebSocket control stream, and the OIDC/policy `release_0295`
  regression tests. Its separate append-only repair migration is not carried:
  this branch already replays Go's two v0.29.5 repairs once, under Go's
  migration IDs.
- Vendor the minimal upstream SQLite WAL-reset race backport for the standalone
  bundled SQLite graph. See `vendor/libsqlite3-sys/OCTRA-PATCHES.md`. The patch
  is hash-pinned in `vendor/PATCHES.json` and the crate is built and run by the
  vendored-crate test gate (`docs/ci-quality-gates.md`); the race fix itself has
  no executable regression in this repository.
- `docs/qualification/` holds that line's qualification records. They are bound
  to its tree; see `docs/qualification/README.md`. This update does not claim
  full 1:1 parity.

## 2026-10-15 — YAML maintenance and isolated protobuf generation

- Replace the retired `serde_yaml`/`unsafe-libyaml` backend with pinned
  `serde-saphyr` 2.0.0. Configuration, DERP YAML maps, config dumps and
  `-o yaml` remain supported. Optional file inclusion, property interpolation,
  robotics and comment-retention extensions are disabled.
- Preserve YAML 1.2 boolean spelling, duplicate-key rejection, anchors and
  unexpanded merge keys, and removed-key detection through nested mappings.
  Existing CLI output snapshots remain unchanged. Quoted canonical
  `true`/`false` can additionally deserialize as booleans; YAML 1.1 `yes`/`on`
  shorthand remains rejected. Unicode U+2028/U+2029 strings now use escaped
  double-quoted presentation with identical decoded values. Parser diagnostic
  details come from the maintained backend; outer error contexts are preserved.
- Generate protobuf modules and descriptors under Cargo `OUT_DIR`, preserving
  source checkouts during builds. Identical generator versions produce identical
  generated Rust/API output.
- The new YAML backend requires Rust 1.89; the qualified toolchain is 1.96.0.

## 2026-05-20 — workspace member trim

Four crates were demoted from `[workspace.members]` to `[workspace.exclude]`:

| Crate                | Disposition | Reason |
| -------------------- | ----------- | ------ |
| `headscale-core`     | kept on disk, excluded from members | required by `headscale-api`, `headscale-db`, `headscale-cli` via path dep |
| `headscale-identity` | kept on disk, excluded from members | DID/Ed25519 infra OctraVPN doesn't use directly but kept for embedders |
| `headscale-resources`| kept on disk, excluded from members | metering surface kept for the open question on a future provider registry |
| `headscale-payments` | kept on disk, excluded from members; deletion candidate | OctraVPN uses the Octra chain; `headscale-db::payments` still depends on it and pins it alive |

### What this changes

- `cargo build --workspace`, `cargo test --workspace`, and
  `cargo clippy --workspace` no longer cover the four demoted crates
  on their own. Their tests and lint surface are only exercised when
  one of the active crates (`headscale-api`, `headscale-db`,
  `headscale-cli`) pulls them through.
- Each demoted crate has `package.publish = false` set so it cannot
  be accidentally pushed to crates.io.
- Each demoted crate has a top-level README explaining how to build
  it in isolation if needed.

### What this doesn't change

- The path-dependency graph is unchanged. `headscale-db` and friends
  still depend on `headscale-core`, `headscale-identity`,
  `headscale-resources`, and `headscale-payments` via
  `[workspace.dependencies]` path entries. Those entries don't need a
  crate to be in `[workspace.members]` to resolve, so production
  builds are byte-identical.
- No code in the active crates was modified. No cargo dependency
  versions were changed. Only `members`/`exclude` lists and the
  `publish` keys.

### Build-time impact

Cold `cargo build --workspace` does *not* meaningfully change: the
demoted crates are still in the dep tree of the active crates and
still get compiled on the way to building `headscale-cli`. The win
is structural — clippy / test scope is now restricted to the three
crates we actually maintain, and the demoted crates are flagged for
embedders as second-class.

### Why not delete `headscale-payments` outright

The original plan was to `git rm -r headscale-payments` as "option
(A)". That's blocked by `headscale-db/src/payments.rs` and
`headscale-db/src/models.rs::PaymentRow::to_transaction` referencing
`headscale_payments::ledger::*` directly. Deleting it would require
touching code in a kept crate (`headscale-db`), which was explicitly
out-of-scope for the workspace-trim commit. The crate is on the
short-list for deletion once the kept crates are decoupled.

### Why not delete `headscale-core::authorization`

The original plan suggested removing the `authorization.rs` stub
that was added during an earlier build-break fix. The current
`authorization.rs` is not dead — `headscale-core::packet` and the
forward-decision contract tests at the bottom of `packet.rs` consume
`ForwardDecision` + `authorize_forward{,_ip}`. Leaving it alone.
