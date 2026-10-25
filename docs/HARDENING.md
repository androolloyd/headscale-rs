# Hardening and parity gates

This repo has four quality gates:

- Pull-request CI: formatting, clippy, tests, a 10k-input fuzz smoke run across
  every checked-in fuzz target, pinned headscale-go differential scenarios, and
  current-head Rust golden scenarios.
- Coverage CI: `cargo llvm-cov` over the active workspace plus the excluded
  support crates, with `target/coverage/lcov.info` and a text summary uploaded
  as artifacts.
- Supply-chain CI: RustSec advisories, license/source policy, and the fuzz
  lockfile audited separately from the root dependency graph.
- Real-client parity CI: selected paired Rust/headscale-go stock-client rows on
  matching pull requests, plus a scheduled full paired matrix.

## Admin user text boundary

The v0.29.5-compatible CreateUser/RenameUser state RPCs accept name text without
the legacy username validation. Admin authentication still gates these methods.
Names and profile strings may contain terminal controls; upstream-compatible
CLI table rendering preserves their printed bytes. Treat the admin text source
and the operator terminal as part of this boundary. These source changes have
not received new protocol, terminal or security qualification, and imply no
fresh dependency/advisory audit.

## Local encrypted database key files

The explicit native pgx bridge accepts Go's existing RFC 1423 encrypted key
files, including weak DES keys and equal TripleDES subkeys. That compatibility
is isolated to configured local PEM input; it does not enable TLS cipher
suites. RFC 1423 encryption is unauthenticated, and this acceptance does not
establish a secure key-storage format. The private DES adaptation, AES backend,
padding/diagnostics and feature/package/container boundaries have not received
new execution or security qualification. No fresh advisory check covers them.

## SSH forwarding permissions

Every `tailcfg.SSHAction` the control server sends carries three permissions
that Tailscale's embedded SSH server (`tailscaled`) applies to the session:
`allowAgentForwarding`, `allowLocalPortForwarding` and
`allowRemotePortForwarding`. headscale-go v0.29.5 sets all three to true on
every accepted SSH rule (`hscontrol/policy/v2/filter.go`) and on every dynamic
check-mode answer from `/machine/ssh/action` (`hscontrol/noise.go`: the
hold-and-delegate action, the accepted action and both rejects), and offers no
setting to change that. headscale-rs matches this by default so the
differential, golden and real-client SSH rows are unchanged.

A public assessment (tailworm.com, October 2026) treats any SSH grant as
high-impact because of how `tailscaled`'s SSH server handles forwarding; the
vulnerable component it names is that client-side forwarding path handling. We
have not independently verified the report. Whatever its merit, the bug is in
the client. The setting below does not fix or patch `tailscaled`: it only lets
an operator stop this control server from authorising forwarding, so clients
that honour the flags no longer receive forwarding permission from it. A client
that ignores the flags, a client that has not yet fetched the new SSHPolicy, and
SSH sessions that are already established are not affected. Keep clients
updated regardless.

To turn forwarding off, add a `policy.ssh` block to the server config. Each
key is a boolean and defaults to true (the headscale-go behaviour):

```yaml
policy:
  mode: file
  path: /etc/headscale/policy.hujson
  ssh:
    allow_agent_forwarding: false
    allow_local_port_forwarding: false
    allow_remote_port_forwarding: false
```

The same keys exist in TOML (`[policy.ssh]`) and JSON, and as the environment
variables `HEADSCALE_POLICY_SSH_ALLOW_AGENT_FORWARDING`,
`HEADSCALE_POLICY_SSH_ALLOW_LOCAL_PORT_FORWARDING` and
`HEADSCALE_POLICY_SSH_ALLOW_REMOTE_PORT_FORWARDING` (`true`/`false`, `1`/`0`,
`yes`/`no`, `on`/`off`).

- A flag set to false is emitted as false on every accept rule in the SSHPolicy
  served in map responses and on every dynamic check-mode action, including
  hold-and-delegate, the post-approval accept, the cached auto-approval and the
  rejects. Flags can only be cleared: check rules were already all-false in the
  static policy, and everything else in the output is byte-identical to the
  default.
- Values must be booleans and unknown keys under `policy.ssh` are a startup
  error naming the key, so a misspelt `allow_*` cannot silently leave
  forwarding enabled. An unparseable environment value fails startup the same
  way.
- headscale-go has no `policy.ssh` block and ignores it, so a Go-valid config
  loads unchanged. With the keys unset, the config dump and `/debug/config`
  output are unchanged, and only an explicitly set `policy.ssh` appears in the
  `dumpConfig` output.
- The setting is read at startup and, like headscale-go, a SIGHUP reloads only
  the ACL policy, not the server config; change it and restart. It is applied
  when a compiled SSH policy is read, so policy reloads, node changes and the
  per-node compile cache cannot bring a cleared flag back.
- When any flag is false this intentionally diverges from headscale-go's
  output; the differential scenarios run with the defaults.

## Resource limits against unauthenticated and peer-driven growth

A public assessment of Tailscale v1.104.2 and headscale v0.29.5 (tailworm.com,
October 2026) reports memory-exhaustion and onboarding-denial paths in a
self-hosted control server. We have not independently verified its numbers; the
paths below were each reproduced against this tree before being limited. Every
limit is a named constant with a comment, and none is reachable by a stock
client in normal use. These are deliberate deviations from headscale-go, which
has no equivalent.

- **Pending registrations.** Anyone who can complete the Noise handshake can
  create a pending registration with a tiny `Register` request, and 1024 of
  them evict pending approvals from the 1024-entry LRU. Unauthenticated
  interactive registrations are now counted per source (IPv4 address, or IPv6
  /64; the resolved peer address) and, while any other party holds a pending
  entry, a source holding more than 64 loses only its own oldest pending
  entries. Behind a reverse proxy without `trusted_proxies` every client shares
  one source, the quota cannot tell attacker from users and stands down, so
  that deployment keeps Go's plain 1024-entry LRU and gets no protection from
  this change: set `trusted_proxies`. When the cache is full, entries
  that already have a verdict are evicted first, then the least recently used
  entry of the heaviest source, then plain LRU. A source over quota still
  receives the normal pending response. Entries created by internal callers
  (gRPC `debug create-node`, SSH check) are exempt.
- **OIDC sign-in states.** A registration holds at most 16 pending OIDC states;
  repeating the redirect drops that registration's own oldest states instead of
  the global LRU dropping other users' in-flight sign-ins.
- **Remote response bodies.** Bodies read from remote servers are streamed with
  a hard limit and abandoned past it (the `derp.urls` and ACME reads had none;
  the OIDC reads were already bounded): the `derp.urls` map (10 MiB; Go does an
  unbounded `io.ReadAll`), OIDC discovery, JWKS and userinfo (1 MiB), the token
  endpoint (1 MiB, as `oauth2` does), and ACME responses (8 MiB, bounding the
  decompressed size). Error and log text embeds at most a short prefix of a
  remote body (256 bytes for OIDC, 1 to 2 KiB for ACME) where Go embeds the
  whole body.
- **Embedded DERP relay.** At most 4 simultaneous sessions per key (a new
  connection closes the oldest, so the newest still wins as in Go), duplicate
  connection health is sent on transitions only, remembered reverse paths are
  indexed and capped per source, and no relay operation waits on a session's
  queue (packets to a full queue are dropped, as Go does). Frames from a client
  are limited to Go's maximum packet size after login and to a bounded
  handshake before it, WebSocket messages to 1 MiB, and every client write has
  a 30 second timeout. `ClosePeer` and `ForwardPacket` are mesh-only frames and
  from a regular client now end the connection (Go: `canMesh`); before, any
  client could close another client's connection by key.

Residual risk: an attacker with many source addresses can still fill the
registration cache with one entry per source; the per-session DERP queue stays
at 256 frames (up to 16 MiB for a stuck reader receiving maximum-size packets;
Go uses 32 with head drop); and `route_packet` still takes the relay's write
lock per packet.

## Local commands

```sh
cargo fmt --all -- --check
cargo fmt --manifest-path headscale-core/fuzz/Cargo.toml --all -- --check
cargo fmt --manifest-path tools/parity/headscale-rs/Cargo.toml --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo clippy -p headscale-api --features admin,full --tests -- -D warnings
cargo test -p headscale-api --features admin,full --test grpc_gateway_e2e
for manifest in \
  headscale-core/Cargo.toml \
  headscale-identity/Cargo.toml \
  headscale-resources/Cargo.toml \
  headscale-payments/Cargo.toml; do
  cargo fmt --manifest-path "$manifest" --all -- --check
  cargo clippy --manifest-path "$manifest" --all-targets -- -D warnings
  cargo test --manifest-path "$manifest"
done
./scripts/coverage.sh
cargo deny check advisories licenses sources
cargo audit --deny warnings --ignore RUSTSEC-2023-0071
cargo audit --file headscale-core/fuzz/Cargo.lock --deny warnings
./scripts/headscale_go_diff.sh
./scripts/headscale_rs_current_head_golden.sh
REAL_CLIENT_SMOKES=authkey,web-register,oidc,online-lastseen,restart-persistence,magicdns,extra-records,acl-allow,route-approve \
  REAL_CLIENT_TARGETS='rust headscale-go' \
  tools/real-client/smoke-matrix.sh
```

The application lockfile is committed and used by release builds. The
lockfile-only audit still reports `RUSTSEC-2023-0071` through the disabled
`sqlx-mysql` backend; RustSec has no patched version. The feature-aware
`cargo deny check advisories` gate verifies that the active server graph does
not include it. Keep the exception scoped to the lockfile audit and revisit
it if MySQL support is enabled.

## Fuzzing

Pull-request CI runs each fuzz target with `-runs=10000`; cargo-fuzz replays
any checked-in `headscale-core/fuzz/corpus/<target>/` seeds before generated
inputs. The scheduled nightly workflow runs the same target list with
`-max_total_time`, uploads logs, and keeps any crash artifacts from
`headscale-core/fuzz/artifacts/<target>/`. Both workflows derive the target list
from `headscale-core/fuzz/Cargo.toml` via `scripts/fuzz_targets.py`, and
`scripts/check_fuzz_corpus.sh` fails stale checked-in corpus directories before
running libFuzzer.

Current target surfaces:

- `fuzz_acl`: legacy `headscale-core::acl` policy parsing/evaluation.
- `fuzz_policy_hujson`: shared `headscale-api-acl` HuJSON parsing,
  canonicalisation, hashing, node attrs, auto-approvers, and evaluation.
- `fuzz_tailscale_wire`: Tailscale wire JSON shapes for register/map structs.
- `fuzz_derp`, `fuzz_stun`, `fuzz_ip_packet`, `fuzz_tun`, `fuzz_wireguard`:
  network packet/frame parsers.
- `fuzz_endpoint`, `fuzz_routing`, `fuzz_metering`, `fuzz_transport`: stateful
  control-plane helpers and invariants.

Crash handling contract:

1. Minimize the artifact with `cargo fuzz tmin`.
2. Add the minimized input to the target corpus only if it exercises a useful
   durable edge. Corpus directories are ignored for local fuzz output, so use
   `git add -f headscale-core/fuzz/corpus/<target>/<seed>` for seeds that CI
   should replay.
3. Add a normal regression test when the crash maps to a named invariant.
4. Fix the implementation.
5. Re-run the target and the affected crate tests.

## Parity

Parity work should be proven with fixtures, differential tests, or paired
stock-client smokes, not comments. The current fixtures cover:

- preauth persistence semantics against upstream headscale-go test names;
- `tools/parity/scenarios/*.json` differential cases against pinned
  `github.com/juanfont/headscale v0.29.5`
  policy, peer-map, route auto-approval, SSH-policy, and `tailcfg` JSON output;
- `tools/parity/golden/headscale-go-v0.29.5.json`,
  which snapshots the normalized pinned differential output after Rust and Go
  agree;
- `tools/parity/current-head/*.json` plus
  `tools/parity/current-head/golden/headscale-rs.json`, which keep
  current-upstream-only policy surfaces runnable until the Go harness baseline is
  intentionally rebased;
- Tailscale wire acronym fields such as `AuthURL`, `DNSConfig`, `DERPMap`,
  `AllowedIPs`, `DiscoKey`, and `ID`;
- ACL default-deny, first-match-wins, group ordering canonicalisation, hosts,
  auto-approvers, and HuJSON compatibility. Headscale-go-compatible policy
  rejects `ipsets`; Octra-specific multi-CIDR aliases should be expanded before
  policy submission.
- real Tailscale client auth-key, web registration, OIDC, lifecycle, tag, ACL
  visibility, MagicDNS enabled/custom/disabled, address-family, route
  primary/failover/withdrawal, DERP, and SSH smokes against both headscale-rs
  and pinned headscale-go.

The next parity layer should close the remaining paired stock-client and
serving-topology gaps: TLS-ALPN controlled-CA ACME process coverage beyond the
local issuer tests and HTTP-01 process smoke, API auth exactness, CLI over
upstream gRPC exact snapshots, config-driven process wiring, and the remaining
DNS/ACL/route edge matrices tracked in `docs/headscale-go-parity.md`.

## Optional admin JSON session CSRF boundary — 2026-10-18

The separately mounted optional admin GUI JSON API now requires the existing
session-bound HMAC CSRF token in `x-csrf-token` for cookie-authenticated unsafe
methods. Missing/invalid tokens return 403. Bearer authentication and safe
methods preserve their existing contract. HTML forms keep their existing CSRF
handling. Native serve uses the upstream-shaped gateway; the GUI router is an
optional embedding surface. This is a source-reviewed hardening change, with no
new executable or advisory/security qualification. The three replacement parity
acceptance gates remain open.
