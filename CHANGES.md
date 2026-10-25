# Changes

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
