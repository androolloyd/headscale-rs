# Hardening and parity gates

This repo has three quality gates:

- Pull-request CI: formatting, clippy, tests, a 10k-input fuzz smoke run across
  every checked-in fuzz target, headscale-go policy differential scenarios, and
  selected paired stock-client parity smokes for changes touching the control
  plane.
- Coverage CI: `cargo llvm-cov` over the active workspace plus the excluded
  support crates, with `target/coverage/lcov.info` and a text summary uploaded
  as artifacts.
- Supply-chain CI: RustSec advisories, license/source policy, and the fuzz
  lockfile audited separately from the root dependency graph.
- Real-client parity CI: selected paired Rust/headscale-go stock-client rows on
  matching pull requests, plus a scheduled full paired matrix.

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
cargo generate-lockfile && cargo audit --deny warnings --ignore RUSTSEC-2023-0071 --ignore RUSTSEC-2026-0097
cargo audit --file headscale-core/fuzz/Cargo.lock --deny warnings
./scripts/headscale_go_diff.sh
./scripts/headscale_rs_current_head_golden.sh
REAL_CLIENT_SMOKES=authkey,web-register,oidc,online-lastseen,restart-persistence,magicdns,extra-records,acl-allow,route-approve \
  REAL_CLIENT_TARGETS='rust headscale-go' \
  tools/real-client/smoke-matrix.sh
```

`cargo audit` is lockfile-only and currently reports `RUSTSEC-2023-0071`
and `RUSTSEC-2026-0097` through optional `sqlx` MySQL/Postgres and
`reqwest` QUIC packages. The workspace enables sqlite and HTTP over Rustls,
not those optional backends, and the feature-aware
`cargo deny check advisories` gate is clean.

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
  `github.com/juanfont/headscale v0.29.0-beta.1.0.20260522122924-4483fd0cad38`
  policy, peer-map, route auto-approval, SSH-policy, and `tailcfg` JSON output;
- `tools/parity/golden/headscale-go-v0.29.0-beta.1.0.20260522122924-4483fd0cad38.json`,
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
