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
