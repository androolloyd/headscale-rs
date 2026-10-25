# Vendored-crate test gate

`vendor/` holds eleven crates that carry Go-exactness (or, for `libsqlite3-sys`,
storage-safety) patches on top of a pinned crates.io release: `aws-lc-rs`, `h2`,
`http`, `hyper`, `hyper-rustls`, `hyper-util`, `instant-acme`, `libsqlite3-sys`,
`rustls`, `sqlx-core` and `sqlx-postgres`. Their
`UPSTREAM.md` files state that no tests were authored for the patches, and the
workspace's own tests only reach them indirectly. This gate runs **each crate's
own upstream test suite against the patched source**, so a patch that breaks
documented upstream behaviour fails CI.

```sh
scripts/test_vendored_crates.sh                  # every crate
scripts/test_vendored_crates.sh h2 rustls        # selected crates
scripts/test_vendored_crates.sh --list           # crates and their runs
scripts/test_vendored_crates.sh --run native h2  # only the "native" run
scripts/test_vendored_crates.sh --update-locks   # refresh locks/, then commit
```

CI runs one matrix row per crate in `.github/workflows/vendor-tests.yml`
(pull requests and pushes touching `vendor/**`, weekly, and on demand).

## How a crate is tested

For each crate the runner (`run.py`) builds a scratch workspace under
`target/vendor-tests/work/<group>/`; `vendor/` is never written to.

1. **The vendored directory is copied in** as the crate under test, with the
   manifest the real build uses (`vendor/<crate>/Cargo.toml`). Tests that ship in
   the crates.io archive (`http`, `hyper-util`, `instant-acme`) come with it.
2. **Upstream-only tests are fetched at the pinned commit.** The commit is read
   from the vendored `.cargo_vcs_info.json` (so it cannot drift from the vendored
   version) and fetched with a shallow `git fetch` of that SHA:

   | crate | taken from the upstream repository |
   | --- | --- |
   | `h2` | `fixtures/` (HPACK stories), `tests/h2-support`, `tests/h2-tests` |
   | `hyper` | `tests/` plus its `[[test]]` targets |
   | `hyper-rustls` | `tests/` and `examples/` (the tests spawn the example binaries) |
   | `rustls` | `rustls/tests/`, `rustls-test`, `test-ca` plus the `[[test]]` runners |
   | `aws-lc-rs` | `aws-lc-rs/tests/` (auto-discovered) |
   | `libsqlite3-sys` | nothing: the crate's own unit test ships in the archive; it is run with the `bundled` feature the workspace enables |
   | `sqlx-core`, `sqlx-postgres` | the whole workspace: the patched crates replace `sqlx-core/` and `sqlx-postgres/`, the root `sqlx` crate's `tests/` run on top |

   The published manifests omit targets whose files are not in the archive, so
   the runner appends upstream's `[[test]]`/`[[example]]` tables and the
   path-only dev-dependencies (`rustls-test`).
3. **Every other vendored crate is patched in** through the scratch workspace's
   `.cargo/config.toml` (`[patch.crates-io]`), exactly as the root `Cargo.toml`
   does, so the crates are tested together as they are built.
4. **Two feature sets per crate**: the defaults (what upstream tests) and the
   Go-native set the workspace actually enables (`go-server-lifecycle`,
   `go-server-client-hello`, `go-native-client`, `go-pem-compat`, ...). The
   native set is read off `cargo metadata` of the root workspace; update the
   plans in `run.py` when `headscale-*/Cargo.toml` changes it.
5. **Test-binary results are checked, not just the exit code**: a run that
   executes zero tests fails (doc-test runs of crates without doctests opt out),
   and counts are printed per run.

## Intended divergences (expected failures)

A test that fails *because the patch deliberately changes the behaviour it
asserts* is listed in a run's `xfail`. It is skipped in the main run and then run
on its own: the run only passes while every listed test **still fails**, so a
stale exemption is itself an error. Currently:

| crate / run | tests | why |
| --- | --- | --- |
| `http` / `native` | `reserve_over_capacity`, `with_capacity_overflow` | `go-native-header-capacity` raises the `HeaderMap` capacity ceiling from `1<<15` to `1<<22`; upstream asserts the old ceiling with `#[should_panic]` |
| `hyper` / `native` | `body::incoming::tests::test_size_of` | `go-client-idle` (with `client`) adds per-body idle-tracking state to `hyper::body::Incoming` (248 bytes); upstream's accident detector asserts <= 40 bytes |
| `h2` / `integration-native` | `recv_invalid_authority`, `recv_next_stream_id_updated_by_malformed_headers` | `go-server-lifecycle` keeps a request whose `:authority` is not a valid URI authority (exposed as `Host`, like Go's `net/http`; see the comment in `vendor/h2/src/server.rs`); both upstream tests send `"not:a/good authority"` and assert the stream is rejected |

## `libsqlite3-sys`: what the gate does and does not prove

The patch is a C-source backport (the SQLite WAL-reset guard, see
`vendor/libsqlite3-sys/OCTRA-PATCHES.md`) inside the bundled amalgamations; no
Rust API changed. The `libsqlite3-sys` group runs the crate's own unit test with
`--features bundled`, so a patched amalgamation that no longer builds or links
fails CI. Because every vendored crate that is not a plan member is patched into
the other scratch workspaces, the `sqlx-core` group's `integration-sqlite` run
(sqlx's SQLite integration suite) also executes against the patched library. The
WAL-reset race itself has **no executable regression** in this repository (the
upstream fault-injection hook is intentionally absent from the production
backport); the two patched amalgamations are pinned by SHA-256 in
`vendor/PATCHES.json`, which `scripts/check_vendor_provenance.py` enforces.

## Compiler-drift allowance

The `http` runs set `RUSTFLAGS=--cap-lints=warn`. Upstream `http` 1.5.0 has
`#![deny(warnings)]` and its own unit tests use `::std::usize::MAX` /
`::std::isize::MAX` (`src/header/value.rs`, byte-identical in the pristine archive),
which Rust 1.99 deprecates, so the crate's test build fails on 1.99.0 with no
connection to the patch. The library itself compiles without the cap. Drop the
allowance once an `http` release fixes it.

## Lockfiles

`locks/<group>.Cargo.lock` pin the resolution of each scratch workspace. They are
seeded from the repository's audited root `Cargo.lock` (so the tests build the
same dependency versions as the shipped binary) with every vendored crate pinned
to its vendored version; only dev-dependencies and the upstream-only workspace
members add new entries. Runs use `--locked`. After changing a vendored manifest
or the plans in `run.py`, refresh them with
`scripts/test_vendored_crates.sh --update-locks` (resolution only, no tests) and
commit the result. `VENDOR_TESTS_UNLOCKED=1` resolves without `--locked`.

These lockfiles belong to test builds only and nothing shipped is built from
them. They are **not** audited by the supply-chain job: the test-only dependency
trees (for example sqlx's workspace for the integration suite) carry some
unmaintained/unsound dev crates that upstream's own tests need.

## Not run, and why

See the table printed at the end of every run (`SKIP`). At the time of writing:

* `sqlx-postgres` / `integration-postgres` needs a live Postgres
  (`VENDOR_TESTS_POSTGRES_URL`) and `psql`; CI provides a service container. The
  runner resets the `public` schema and loads sqlx's `tests/postgres/setup.sql`
  before the run. It runs against a stock `postgres:16` (SCRAM auth, no TLS): upstream's
  TLS-verification variants and the `pg_stat_statements` preload need a custom
  server image and are not run.
* `instant-acme` / `pebble*` need the `pebble` ACME server; the runner builds a
  pinned release with `go install` when Go is available (always, in CI).
* Out of scope: rustls' BoGo and OpenSSL interop suites, aws-lc-rs' FIPS builds,
  hyper's FFI (`capi`) tests, sqlx's MySQL/MSSQL suites and UI (trybuild) tests.
