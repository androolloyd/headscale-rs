# Hardening and parity gates

This repo has three quality gates:

- Pull-request CI: formatting, clippy, tests, a 10k-input fuzz smoke run across
  every checked-in fuzz target, and headscale-go policy differential scenarios.
- Coverage CI: `cargo llvm-cov` over the active workspace plus the excluded
  support crates, with `target/coverage/lcov.info` and a text summary uploaded
  as artifacts.
- Supply-chain CI: RustSec advisories, license/source policy, and the fuzz
  lockfile audited separately from the root dependency graph.

## Local commands

```sh
cargo fmt --all -- --check
cargo fmt --manifest-path headscale-core/fuzz/Cargo.toml --all -- --check
cargo fmt --manifest-path tools/parity/headscale-rs/Cargo.toml --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
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
cargo generate-lockfile && cargo audit --deny warnings --ignore RUSTSEC-2023-0071
cargo audit --file headscale-core/fuzz/Cargo.lock --deny warnings
./scripts/headscale_go_diff.sh
```

`cargo audit` is lockfile-only and currently reports `RUSTSEC-2023-0071`
through `sqlx`'s optional MySQL backend. The workspace enables sqlite, not
MySQL, and the feature-aware `cargo deny check advisories` gate is clean.

## Fuzzing

Pull-request CI runs each fuzz target with `-runs=10000`. The scheduled nightly
workflow runs the same target list with `-max_total_time`, uploads logs, and
keeps any crash artifacts from `headscale-core/fuzz/artifacts/<target>/`.

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
   durable edge.
3. Add a normal regression test when the crash maps to a named invariant.
4. Fix the implementation.
5. Re-run the target and the affected crate tests.

## Parity

Parity work should be proven with fixtures, differential tests, or paired
stock-client smokes, not comments. The current fixtures cover:

- preauth persistence semantics against upstream headscale-go test names;
- `tools/parity/scenarios/*.json` differential cases against pinned
  `github.com/juanfont/headscale v0.28.0` policy, peer-map, route
  auto-approval, SSH-policy, and `tailcfg` JSON output;
- Tailscale wire acronym fields such as `AuthURL`, `DNSConfig`, `DERPMap`,
  `AllowedIPs`, `DiscoKey`, and `ID`;
- ACL default-deny, first-match-wins, group ordering canonicalisation, hosts,
  auto-approvers, and HuJSON compatibility; Rust-extension node attrs/ipsets
  are fuzzed but intentionally outside pinned v0.28 differential parity.
- real Tailscale client auth-key, web registration, tag, ACL visibility,
  MagicDNS enabled/custom/disabled, and route primary/failover/withdrawal
  smokes against both headscale-rs and pinned headscale-go.

The next parity layer should close the remaining paired stock-client and
serving-topology gaps: OIDC callback completion, Tailscale SSH, DERP/STUN,
private DERP, API auth, CLI over upstream gRPC, config-driven process wiring,
and the remaining DNS/ACL/route edge matrices tracked in
`docs/headscale-go-parity.md`.
