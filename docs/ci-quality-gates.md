# CI quality gates

What each gate enforces, how to run it locally, and how to change what it pins.
Written 2026-10-25 after an independent review found the gates were not gating:
`main` had been red since 2026-10-16, the scheduled jobs had not run since August,
and nothing pinned the compiler or checked the ~12k lines of patched crates in
`vendor/`.

## One compiler: `rust-toolchain.toml`

The tree is edition 2024 with let-chains, so it needs a recent compiler, and the
workspace lints are `clippy::pedantic` + `nursery` under `-D warnings`. A
floating `stable` therefore turns the build red whenever a release adds a lint:
that is exactly what happened on 2026-10-16 when the runner's `stable` became
1.99.0 (new `clippy::assert_is_empty`, 22 hits in `headscale-api-acl`) and the
unpinned nightly `rustfmt` reformatted `tools/parity`.

`rust-toolchain.toml` pins `1.96.0` (the release `CHANGES.md` records as
qualified) with the `clippy` and `rustfmt` components. Everything follows it:

| consumer | how |
| --- | --- |
| local `cargo` / `rustup` | picks the file up automatically |
| `.github/workflows/*` | `uses: ./.github/actions/setup-rust` reads the file and installs exactly that toolchain |
| `deploy/docker/Dockerfile*` | `FROM rust:1.96.0-bookworm` |
| fuzz jobs | need a nightly for libFuzzer sanitizers: `FUZZ_NIGHTLY_TOOLCHAIN: nightly-2026-08-21` in `ci.yml` and `fuzz-nightly.yml` (a dated nightly, via the same action) |
| `cargo audit` / `cargo deny` / `cargo llvm-cov` | installed with a current `stable` (`cargo +stable install --locked …`) because their own MSRV moves faster than the pin |

`scripts/check_toolchain_pin.py` (run in the CI `harness` job) fails when a
Dockerfile, a workflow or `CHANGES.md` drifts from the pin, or when a workflow
uses a floating `stable`/`nightly` or `dtolnay/rust-toolchain`.

**Bumping the pin** is its own commit: change `channel`, the Dockerfile tags and
`CHANGES.md`, then run `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace --all-targets`, `scripts/test_vendored_crates.sh` and
`python3 scripts/check_toolchain_pin.py` on the new release.

The tree is also clippy-clean (`-D warnings`, workspace, the three `headscale-api`
feature variants and the excluded crates) on Rust 1.99.0, the release CI's floating
`stable` had reached when `main` went red. Moving the pin to 1.99.0 therefore only
needs the steps above; it has not been done because `CHANGES.md` records 1.96.0 as
the qualified release. The 1.99 pass rewrote test assertions that clippy flags
(`assert!(x.is_empty())` is now `assert_eq!(x, [] as [T; 0])`, `assert_eq!(x, "")`
or `assert_eq!(x.len(), 0)` where the element type cannot be named from the test),
replaced `chunks_exact(N)` with `as_chunks::<N>()` in the DERP YAML and RNG-table
parsers, and made two functions that never awaited non-async
(`InMemoryPreauthAdmin::mint_inner`, and the `go-pool-compat`-off stub of
`Database::new_with_go_sqlite_options`, which returns a ready future).

## Gates

| gate | workflow / job | local command |
| --- | --- | --- |
| format | `ci.yml` / `cargo fmt` | `cargo fmt --all -- --check` (plus the excluded crates, fuzz and tool crates, see the job) |
| clippy, workspace + feature variants + excluded crates | `ci.yml` / `cargo clippy` | `cargo clippy --workspace --all-targets -- -D warnings` |
| tests | `ci.yml` / `cargo test` | `cargo test --workspace --all-targets` |
| harness metadata, pins | `ci.yml` / `parity harness metadata` | the `python3 scripts/check_*.py` steps in the job |
| fuzz (10k runs) | `ci.yml` / `cargo fuzz 10k`, nightly: `fuzz-nightly.yml` | `scripts/fuzz_ci.sh` |
| RustSec advisories, **all four committed lockfiles** | `supply-chain.yml` / `cargo audit` | `cargo audit --deny warnings --ignore RUSTSEC-2023-0071` and `cargo audit --file <lock> --deny warnings` for `headscale-core/fuzz`, `tools/parity/headscale-rs`, `tools/real-client/headscale-rs-harness` |
| licences, sources, bans | `supply-chain.yml` / `cargo deny` | `cargo deny check advisories licenses sources` |
| vendored crates == pristine crates.io source + recorded patches | `supply-chain.yml` / `vendor provenance` | `python3 scripts/check_vendor_provenance.py -v` |
| vendored crates pass their own upstream suites | `vendor-tests.yml` (matrix per crate) | `scripts/test_vendored_crates.sh [crate…]` |
| Go-exactness behaviour of the patches | `cargo test --workspace` (crate `headscale-vendor-conformance`) | `cargo test -p headscale-vendor-conformance` |
| real-client parity | `real-client-parity.yml` | `tools/real-client/smoke-matrix.sh` |

### Vendored crates (`vendor/`)

`deny.toml` only allows crates.io sources, and path patches bypass it, so three
layers cover `vendor/`:

1. **Provenance** (`scripts/check_vendor_provenance.py`, manifest
   `vendor/PATCHES.json`). Downloads each pristine `.crate`, checks its SHA-256
   against the crates.io index and `UPSTREAM.md`, and fails on any vendored file
   that differs from upstream without being recorded in the manifest (modified,
   added or removed), on a recorded change that disappeared, and on a path patch
   in `Cargo.toml` / `Cargo.lock` that is not a vendored crate. After an
   *intended* change to a vendored crate: `git add` new files, run
   `python3 scripts/check_vendor_provenance.py --update`, review
   `git diff vendor/PATCHES.json`, commit it with the change.
2. **Upstream suites** (`scripts/test_vendored_crates.sh`, see
   `tools/vendor-tests/README.md`). Runs each crate's own tests (including those
   that only exist in the upstream git repository, fetched at the commit in
   `.cargo_vcs_info.json`) against the patched source, with default features and
   with the Go-native feature set the workspace enables. Six upstream tests (http
   2, hyper 1, h2 2, sqlx-postgres 1) fail *because* the patches change that
   behaviour on purpose; they are explicit expected failures that must keep
   failing. Refresh
   `tools/vendor-tests/locks/*.Cargo.lock` with `--update-locks` whenever a
   vendored manifest changes.
3. **Behaviour** (`headscale-vendor-conformance/`). One test per Go-exactness
   feature, each asserting stock and native behaviour on the same input:
   h2 SETTINGS validation, refusal accounting, Content-Length normalisation,
   `:authority` handling, rustls raw SNI, pgx passfile handling, `http` header
   capacity. `headscale-vendor-conformance/README.md` maps feature → test → Go
   reference.

### The headscale-go current-head pin

`scripts/check_headscale_go_refs.py --remote` used to fail whenever headscale-go
`main` moved past `tools/real-client/headscale-go-current.sh`. That killed every
push, pull request and nightly real-client run before any smoke test executed.
Now `--remote` still fails if the baseline tag `v0.29.5` stops resolving, but
reports a moved `main` as a warning annotation. The nightly `pin-freshness` job in
`real-client-parity.yml` runs it with `--fail-on-stale`, so a stale pin shows up as
one failing scheduled job without blocking the rest. Moving the pin is a parity
decision (re-run the golden and capture audits), not a CI fix.

## Scheduled workflows

GitHub disables scheduled workflows in a repository without activity for 60 days;
`Supply chain`, `Real-client parity` and `Nightly fuzz` show
`disabled_inactivity`. A push is not enough; they have to be re-enabled (see the
owner checklist in the hand-over). Re-enabling and then ignoring the failure
emails will repeat the August outcome: the audit job fails on purpose whenever a
new advisory lands on any committed lockfile.
