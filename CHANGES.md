# Changes

## 2026-10-17 — dynamic native DERP authorization

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

## 2026-10-17 — durable embedded mesh control

- Share SQLite/PostgreSQL policy persistence between HTTP admin and gRPC;
  commit HTTP policy writes before publishing them and hydrate policy explicitly
  before an embedder opens its listeners. Serialize database writes and cache
  publication, preserve HuJSON and timestamps, and reject HTTP replacement of
  externally managed policy.
- Return bound HTTP/HTTPS addresses to embedding hosts. Supervise raw TLS
  connection tasks with the listener so cancelling it closes pending clients.


## 2026-10-16 — headscale-go v0.29.5 compatibility update

- Pin the official v0.29.5 release and refresh its Go/Rust differential golden
  to 100 executed scenarios. Preserve the explicit four-item replacement-parity
  backlog and the observed upstream rename-projection limitation.
- Match release capability checks, authenticated registration and single-use SSH
  approval, OIDC confirmation/cookies, empty SSH policy revocation, split map
  removal frames, peer metadata/key classification and connection lifecycle.
- Preserve canonical node IDs, expiry and preauth-key deletion during runtime
  persistence; add append-only SQLite/PostgreSQL repair migrations and native
  import guards. Keep active route indexes separate from durable approvals.
- Vendor the minimal upstream SQLite WAL-reset race backport for the standalone
  bundled SQLite graph. See `vendor/libsqlite3-sys/OCTRA-PATCHES.md`.
- See `docs/qualification/headscale-v0.29.5.json` for executed gates, exact hashes,
  preserved failures and exclusions. This update does not claim full 1:1 parity.

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
