#!/usr/bin/env python3
"""Run each vendored crate's own upstream test suite against its local patch.

`vendor/` holds ten crates (rustls, h2, hyper, ...) that carry Go-exactness
patches on top of a pinned crates.io release. Nothing else in CI exercises
those crates' *own* tests, so a patch could silently break upstream behaviour.
This runner closes that gap:

* The crate under test is the vendored directory itself (copied into a scratch
  workspace; `vendor/` is never written to).
* Tests that ship in the crates.io archive come with the copy. Tests that only
  exist in the upstream git repository (h2's `tests/h2-tests`, hyper's
  `tests/`, rustls' `rustls/tests` + `rustls-test`, aws-lc-rs' `tests/`, hyper-
  rustls' `tests/` + examples, sqlx's `tests/`) are fetched from the exact commit
  recorded in the vendored `.cargo_vcs_info.json` and copied alongside.
* Every *other* vendored crate is patched in via `.cargo/config.toml`, exactly
  as the root `Cargo.toml` does, so the crates are tested as they are built.
* Each crate is run with its default features (what upstream tests) and with
  the Go-native feature set the headscale workspace really enables.

Usage: see `scripts/test_vendored_crates.sh --help`.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time
import tomllib

REPO = pathlib.Path(__file__).resolve().parents[2]
VENDOR = REPO / "vendor"
LOCKS = REPO / "tools" / "vendor-tests" / "locks"

ALL_VENDORED = [
    "aws-lc-rs",
    "h2",
    "http",
    "hyper",
    "hyper-rustls",
    "hyper-util",
    "instant-acme",
    "rustls",
    "sqlx-core",
    "sqlx-postgres",
]

UPSTREAM_URLS = {
    "aws-lc-rs": "https://github.com/aws/aws-lc-rs",
    "h2": "https://github.com/hyperium/h2",
    "hyper": "https://github.com/hyperium/hyper",
    "hyper-rustls": "https://github.com/rustls/hyper-rustls",
    "rustls": "https://github.com/rustls/rustls",
    "sqlx": "https://github.com/launchbadge/sqlx",
}


# --------------------------------------------------------------------------
# Test plans
# --------------------------------------------------------------------------


@dataclasses.dataclass
class Run:
    """One `cargo test` invocation (plus an optional expected-failure check)."""

    name: str
    args: list[str]
    # Harness arguments after `--` (e.g. ["--test-threads=1"]).
    harness: list[str] = dataclasses.field(default_factory=list)
    env: dict[str, str] = dataclasses.field(default_factory=dict)
    # Upstream tests that fail *because of an intended divergence*. They are
    # skipped in the main run and then run on their own: the run only passes
    # if every one of them still fails (a stale entry is an error).
    xfail: list[str] = dataclasses.field(default_factory=list)
    xfail_reason: str = ""
    # Environment variable that must be set for the run to apply; otherwise the
    # run is reported as SKIPPED with `skip_reason`.
    requires_env: str = ""
    skip_reason: str = ""
    # External tool the run needs; currently only "pebble" (ACME test server).
    requires_tool: str = ""
    # Doc-test runs of crates without any doctests legitimately run zero tests.
    allow_empty: bool = False
    # SQL file (relative to the scratch workspace) loaded with psql into the
    # database named by `requires_env` after resetting the public schema.
    setup_sql: str = ""


@dataclasses.dataclass
class Plan:
    group: str
    # Upstream directories whose *non-Rust* files are added to the workspace copy
    # when the vendored crate lacks them (include_str!/include_bytes! test data
    # that the crates.io archive omits). Rust sources always come from vendor/.
    fill_missing: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    # Directories/files copied from the upstream checkout: (repo path, workspace
    # path). Paths are relative to the upstream repository root.
    copy: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    # Upstream support crates added as workspace members: (repo path, workspace
    # path). Their `path = ".."` dependencies on the crate are rewritten.
    members: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    # (workspace file, old, new) text replacements applied after copying.
    rewrite: list[tuple[str, str, str]] = dataclasses.field(default_factory=list)
    # Vendored crates that are workspace members of this plan.
    vendored: list[str] = dataclasses.field(default_factory=list)
    # (workspace file, text) appended after copying (e.g. feature pass-throughs).
    append: list[tuple[str, str]] = dataclasses.field(default_factory=list)
    # Append upstream's `[[test]]`/`[[example]]` tables (published manifests
    # omit targets whose files are not in the crates.io archive).
    upstream_targets: dict[str, list[str]] = dataclasses.field(default_factory=dict)
    # Flip `autotests = false` for crates that rely on tests/ auto-discovery.
    autotests: list[str] = dataclasses.field(default_factory=list)
    # Extra `[dev-dependencies]` tables per vendored crate.
    dev_deps: dict[str, dict[str, dict]] = dataclasses.field(default_factory=dict)
    runs: list[Run] = dataclasses.field(default_factory=list)
    # "scratch" builds a small workspace from vendored copies; "overlay" uses the
    # whole upstream repository as the workspace.
    mode: str = "scratch"
    upstream: str = ""
    notes: list[str] = dataclasses.field(default_factory=list)


H2_NATIVE = [
    "h2/go-client-idle",
    "h2/go-server-first-settings",
    "h2/go-server-graceful-current-id",
    "h2/go-server-lifecycle",
]

HTTP_NATIVE_XFAIL = ["reserve_over_capacity", "with_capacity_overflow"]

# http 1.5.0 declares `#![deny(warnings)]` and its own unit tests spell
# `::std::usize::MAX` / `::std::isize::MAX` (src/header/value.rs, byte-identical in
# the pristine archive). Since Rust 1.99 those module constants are deprecated, so
# the crate's `cfg(test)` build fails with `deprecated` errors that have nothing to
# do with the local patch. Capping lints to warnings keeps the upstream behaviour
# tests runnable on the pinned compiler; the library itself builds clean without it.
HTTP_ENV = {"RUSTFLAGS": "--cap-lints=warn"}

PLANS: dict[str, Plan] = {
    "http": Plan(
        group="http",
        vendored=["http"],
        runs=[
            Run("default", ["-p", "http"], env=HTTP_ENV),
            Run(
                "native",
                ["-p", "http", "--features", "go-native-header-capacity"],
                env=HTTP_ENV,
                xfail=HTTP_NATIVE_XFAIL,
                xfail_reason=(
                    "go-native-header-capacity widens the HeaderMap index to u32 and the "
                    "maximum table capacity from 1<<15 to 1<<22, so upstream's "
                    "should_panic tests for the old 1<<15 ceiling (reserve(50_000) and "
                    "with_capacity(24_577)) legitimately no longer panic"
                ),
            ),
        ],
    ),
    "hyper-util": Plan(
        group="hyper-util",
        vendored=["hyper-util"],
        runs=[
            Run("default", ["-p", "hyper-util", "--features", "full", "--lib", "--tests"]),
            Run("default-doc", ["-p", "hyper-util", "--features", "full", "--doc"]),
            Run(
                "native",
                ["-p", "hyper-util", "--features", "full,go-native-client", "--lib", "--tests"],
            ),
            Run(
                "native-doc",
                ["-p", "hyper-util", "--features", "full,go-native-client", "--doc"],
            ),
        ],
    ),
    "instant-acme": Plan(
        group="instant-acme",
        vendored=["instant-acme"],
        runs=[
            Run("default", ["-p", "instant-acme", "--lib", "--tests"]),
            Run("default-doc", ["-p", "instant-acme", "--doc"], allow_empty=True),
            Run(
                "native",
                ["-p", "instant-acme", "--features", "go-native-client", "--lib", "--tests"],
            ),
            Run(
                "native-doc",
                ["-p", "instant-acme", "--features", "go-native-client", "--doc"],
                allow_empty=True,
            ),
            # Upstream's integration suite drives a real ACME server (pebble).
            Run(
                "pebble",
                ["-p", "instant-acme", "--features", "x509-parser,time", "--test", "pebble"],
                harness=["--ignored"],
                requires_tool="pebble",
            ),
            Run(
                "pebble-native",
                [
                    "-p",
                    "instant-acme",
                    "--features",
                    "x509-parser,time,go-native-client",
                    "--test",
                    "pebble",
                ],
                harness=["--ignored"],
                requires_tool="pebble",
            ),
        ],
    ),
    "h2": Plan(
        group="h2",
        upstream="h2",
        vendored=["h2"],
        copy=[("fixtures", "h2/fixtures")],
        members=[("tests/h2-support", "h2-support"), ("tests/h2-tests", "h2-tests")],
        rewrite=[("h2-support/Cargo.toml", 'path = "../.."', 'path = "../h2"')],
        # h2-tests only sees h2 through h2-support (which enables `stream` and
        # `unstable`), so the native features are passed down the same chain.
        append=[
            (
                "h2-support/Cargo.toml",
                "\n[features]\ngo-native = [" + ", ".join(f'"{f}"' for f in H2_NATIVE) + "]\n",
            ),
            ("h2-tests/Cargo.toml", '\n[features]\ngo-native = ["h2-support/go-native"]\n'),
        ],
        runs=[
            Run("lib-default", ["-p", "h2", "--lib"]),
            Run("doc-default", ["-p", "h2", "--doc"]),
            Run("integration-default", ["-p", "h2-tests"]),
            Run("lib-native", ["-p", "h2", "--lib", "--features", ",".join(H2_NATIVE)]),
            Run("doc-native", ["-p", "h2", "--doc", "--features", ",".join(H2_NATIVE)]),
            Run(
                "integration-native",
                ["-p", "h2-tests", "--features", "go-native"],
                xfail=["recv_invalid_authority", "recv_next_stream_id_updated_by_malformed_headers"],
                xfail_reason=(
                    "go-server-lifecycle keeps a request whose :authority is not a valid URI "
                    "authority (exposed as the Host header, like Go's net/http, so grpc-go's "
                    "percent-encoded unix-socket authority works); both tests send the malformed "
                    "authority \"not:a/good authority\" and assert the stream is rejected. See the "
                    "comment in vendor/h2/src/server.rs"
                ),
            ),
        ],
    ),
    "hyper": Plan(
        group="hyper",
        upstream="hyper",
        vendored=["hyper"],
        copy=[("tests", "hyper/tests")],
        upstream_targets={"hyper": ["test"]},
        runs=[
            Run("default", ["-p", "hyper", "--features", "full"]),
            Run(
                "native",
                ["-p", "hyper", "--features", "full,go-client-idle,go-server-lifecycle"],
                xfail=["body::incoming::tests::test_size_of"],
                xfail_reason=(
                    "go-client-idle (with client) adds Go-style per-body idle-tracking state "
                    "to hyper::body::Incoming, growing it past the 40-byte accident-detector "
                    "ceiling that upstream's test_size_of asserts (248 bytes with the feature)"
                ),
            ),
        ],
    ),
    "hyper-rustls": Plan(
        group="hyper-rustls",
        upstream="hyper-rustls",
        vendored=["hyper-rustls"],
        copy=[("tests", "hyper-rustls/tests"), ("examples", "hyper-rustls/examples")],
        upstream_targets={"hyper-rustls": ["example"]},
        runs=[
            Run("default", ["-p", "hyper-rustls"]),
            Run(
                "native",
                ["-p", "hyper-rustls", "--features", "go-native-http-proxy,http2,webpki-tokio"],
            ),
        ],
    ),
    "rustls": Plan(
        group="rustls",
        upstream="rustls",
        vendored=["rustls"],
        copy=[
            ("rustls/tests", "rustls/tests"),
            # include_bytes! fixtures of the in-crate unit tests (not in the archive)
            ("rustls/src/testdata", "rustls/src/testdata"),
            ("test-ca", "test-ca"),
            ("fuzz/corpus", "fuzz/corpus"),
            (
                "rustls-provider-test/tests/rfc-9180-test-vectors.json",
                "rustls-provider-test/tests/rfc-9180-test-vectors.json",
            ),
        ],
        members=[("rustls-test", "rustls-test")],
        upstream_targets={"rustls": ["test"]},
        dev_deps={"rustls": {"rustls-test": {"path": "../rustls-test"}}},
        runs=[
            Run("default", ["-p", "rustls", "--lib", "--tests"]),
            Run("default-doc", ["-p", "rustls", "--doc"]),
            Run(
                "native",
                [
                    "-p",
                    "rustls",
                    "--features",
                    "go-server-client-hello,go-client-record-eof",
                    "--lib",
                    "--tests",
                ],
            ),
            Run(
                "native-doc",
                [
                    "-p",
                    "rustls",
                    "--features",
                    "go-server-client-hello,go-client-record-eof",
                    "--doc",
                ],
            ),
        ],
    ),
    "aws-lc-rs": Plan(
        group="aws-lc-rs",
        upstream="aws-lc-rs",
        vendored=["aws-lc-rs"],
        copy=[
            ("aws-lc-rs/tests", "aws-lc-rs/tests"),
            # NIST CAVP vectors the digest/hmac/... tests read via ../third_party
            ("aws-lc-rs/third_party", "aws-lc-rs/third_party"),
        ],
        fill_missing=[("aws-lc-rs/src", "aws-lc-rs/src")],
        autotests=["aws-lc-rs"],
        runs=[
            Run("default", ["-p", "aws-lc-rs", "--lib", "--tests"]),
            Run("default-doc", ["-p", "aws-lc-rs", "--doc"]),
            Run(
                "native",
                ["-p", "aws-lc-rs", "--features", "go-native-tls12-ecdsa", "--lib", "--tests"],
            ),
        ],
    ),
}

# sqlx-core and sqlx-postgres are tested together: the upstream integration
# tests live in the root `sqlx` crate of the upstream workspace, which is
# overlaid with both patched crates.
SQLX_CORE_NATIVE = (
    "_rt-tokio,_tls-rustls-aws-lc-rs,any,json,migrate,offline,go-pem-compat,webpki-roots"
)
SQLX_ROOT_FEATURES = "any,macros,migrate,_unstable-all-types,runtime-tokio"
SQLX_SQLITE_ENV = {
    "DATABASE_URL": "sqlite:tests/sqlite/sqlite.db",
    "SQLX_OFFLINE_DIR": ".sqlx",
}
PLANS["sqlx-core"] = Plan(
    group="sqlx",
    mode="overlay",
    upstream="sqlx",
    vendored=["sqlx-core", "sqlx-postgres"],
    runs=[
        Run("unit-default", ["-p", "sqlx-core", "--lib"]),
        Run("unit-native", ["-p", "sqlx-core", "--lib", "--features", SQLX_CORE_NATIVE]),
        Run(
            "integration-sqlite",
            [
                "-p",
                "sqlx",
                "--no-default-features",
                "--features",
                f"{SQLX_ROOT_FEATURES},sqlite",
            ],
            harness=["--test-threads=1"],
            env=SQLX_SQLITE_ENV,
        ),
    ],
)
PLANS["sqlx-postgres"] = Plan(
    group="sqlx",
    mode="overlay",
    upstream="sqlx",
    vendored=["sqlx-core", "sqlx-postgres"],
    runs=[
        Run(
            "unit-default",
            ["-p", "sqlx-postgres", "--lib"],
            xfail=["types::geometry::path::path_tests::cannot_deserialise_path_type_uneven_point_bytes"],
            xfail_reason=(
                "the patch adds a point-count bounds check to PgPath decoding, so the malformed "
                "input is still rejected but with the new message \"PATH point count exceeds its "
                "buffer\" instead of the \"expected 32 bytes after header, got 28\" the "
                "upstream test pins"
            ),
        ),
        Run(
            "integration-postgres",
            [
                "-p",
                "sqlx",
                "--no-default-features",
                "--features",
                f"{SQLX_ROOT_FEATURES},postgres,tls-rustls-aws-lc-rs",
            ],
            env={"SQLX_OFFLINE_DIR": ".sqlx"},
            setup_sql="tests/postgres/setup.sql",
            requires_env="VENDOR_TESTS_POSTGRES_URL",
            skip_reason=(
                "needs a live Postgres: set VENDOR_TESTS_POSTGRES_URL "
                "(e.g. postgres://postgres:password@localhost:5432/sqlx)"
            ),
        ),
    ],
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def log(msg: str) -> None:
    print(msg, flush=True)


def group_cache_dir(vt_dir: pathlib.Path) -> pathlib.Path:
    return vt_dir / "upstream"


def vcs_info(crate: str) -> dict:
    with open(VENDOR / crate / ".cargo_vcs_info.json", encoding="utf-8") as handle:
        return json.load(handle)


def fetch_upstream(vt_dir: pathlib.Path, repo_key: str, sha: str) -> pathlib.Path:
    dest = group_cache_dir(vt_dir) / f"{repo_key}-{sha[:12]}"
    if (dest / ".fetched").exists():
        return dest
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    url = UPSTREAM_URLS[repo_key]
    log(f"fetching {url} @ {sha}")
    for cmd in (
        ["git", "init", "-q"],
        ["git", "fetch", "-q", "--depth", "1", url, sha],
        ["git", "checkout", "-q", "FETCH_HEAD"],
    ):
        subprocess.run(cmd, cwd=dest, check=True)
    (dest / ".fetched").write_text(sha + "\n", encoding="utf-8")
    return dest


def upstream_sha(plan: Plan) -> tuple[str, str]:
    """Commit and in-repo path of the first vendored crate of the plan."""
    shas = {vcs_info(c)["git"]["sha1"] for c in plan.vendored}
    if len(shas) != 1:
        raise SystemExit(f"vendored crates of group {plan.group} pin different commits: {shas}")
    return shas.pop(), vcs_info(plan.vendored[0]).get("path_in_vcs", "")


def copy_vendored(crate: str, dest: pathlib.Path) -> None:
    ignore = shutil.ignore_patterns("target", "Cargo.lock", ".cargo-ok")
    shutil.copytree(VENDOR / crate, dest, ignore=ignore, dirs_exist_ok=True)


def copy_path(src: pathlib.Path, dest: pathlib.Path) -> None:
    if not src.exists():
        raise SystemExit(f"upstream checkout is missing {src}")
    if src.is_dir():
        shutil.copytree(src, dest, dirs_exist_ok=True)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)


def fill_missing_data(src: pathlib.Path, dest: pathlib.Path) -> int:
    if not src.is_dir():
        raise SystemExit(f"upstream checkout is missing {src}")
    added = 0
    for path in sorted(src.rglob("*")):
        if not path.is_file() or path.suffix == ".rs":
            continue
        target = dest / path.relative_to(src)
        if target.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        added += 1
    return added


def toml_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(toml_value(v) for v in value) + "]"
    raise TypeError(f"unsupported TOML value {value!r}")


def append_upstream_targets(
    manifest: pathlib.Path, upstream_manifest: pathlib.Path, kinds: list[str]
) -> None:
    with open(upstream_manifest, "rb") as handle:
        upstream = tomllib.load(handle)
    with open(manifest, "rb") as handle:
        have = tomllib.load(handle)
    out: list[str] = []
    for kind in kinds:
        existing = {t.get("name") for t in have.get(kind, [])}
        for table in upstream.get(kind, []):
            if table.get("name") in existing:
                continue
            out.append(f"\n[[{kind}]]")
            for key, value in table.items():
                out.append(f"{key} = {toml_value(value)}")
    if out:
        with open(manifest, "a", encoding="utf-8") as handle:
            handle.write("\n".join(out) + "\n")


def append_dev_deps(manifest: pathlib.Path, deps: dict[str, dict]) -> None:
    out = []
    for name, spec in deps.items():
        out.append(f"\n[dev-dependencies.{name}]")
        for key, value in spec.items():
            out.append(f"{key} = {toml_value(value)}")
    with open(manifest, "a", encoding="utf-8") as handle:
        handle.write("\n".join(out) + "\n")


# --------------------------------------------------------------------------
# Workspace preparation
# --------------------------------------------------------------------------


def prepare_scratch(plan: Plan, work: pathlib.Path, upstream: pathlib.Path | None) -> None:
    for crate in plan.vendored:
        copy_vendored(crate, work / crate)
    for repo_path, ws_path in plan.fill_missing:
        assert upstream is not None
        log(f"  added {fill_missing_data(upstream / repo_path, work / ws_path)} test-data file(s) from {repo_path}")
    for repo_path, ws_path in plan.copy:
        assert upstream is not None
        copy_path(upstream / repo_path, work / ws_path)
    for repo_path, ws_path in plan.members:
        assert upstream is not None
        copy_path(upstream / repo_path, work / ws_path)
    for rel, old, new in plan.rewrite:
        path = work / rel
        text = path.read_text(encoding="utf-8")
        if old not in text:
            raise SystemExit(f"rewrite target {old!r} not found in {rel}")
        path.write_text(text.replace(old, new), encoding="utf-8")
    for rel, text in plan.append:
        with open(work / rel, "a", encoding="utf-8") as handle:
            handle.write(text)
    for crate, kinds in plan.upstream_targets.items():
        assert upstream is not None
        _, in_repo = upstream_sha(plan)
        manifest_src = upstream / in_repo / "Cargo.toml"
        append_upstream_targets(work / crate / "Cargo.toml", manifest_src, kinds)
    for crate in plan.autotests:
        path = work / crate / "Cargo.toml"
        text = path.read_text(encoding="utf-8")
        new = re.sub(r"(?m)^autotests\s*=\s*false", "autotests = true", text)
        if new == text:
            raise SystemExit(f"{crate}: no `autotests = false` to flip")
        path.write_text(new, encoding="utf-8")
    for crate, deps in plan.dev_deps.items():
        append_dev_deps(work / crate / "Cargo.toml", deps)
    members = plan.vendored + [ws for _, ws in plan.members]
    manifest = ["[workspace]", 'resolver = "2"', "members = ["]
    manifest += [f'    "{m}",' for m in members]
    manifest += ["]", ""]
    (work / "Cargo.toml").write_text("\n".join(manifest), encoding="utf-8")


def prepare_overlay(plan: Plan, work: pathlib.Path, upstream: pathlib.Path) -> None:
    """Use the whole upstream repository as the workspace; swap in the patches."""
    shutil.copytree(
        upstream, work, ignore=shutil.ignore_patterns(".git", ".fetched"), dirs_exist_ok=True
    )
    for crate in plan.vendored:
        dest = work / crate
        if not dest.is_dir():
            raise SystemExit(f"upstream workspace has no {crate}/ directory")
        for sub in ("src", "benches", "examples"):
            shutil.rmtree(dest / sub, ignore_errors=True)
        copy_vendored(crate, dest)
        orig = dest / "Cargo.toml.orig"
        if not orig.exists():
            raise SystemExit(f"{crate}: vendored Cargo.toml.orig missing")
        # Upstream workspace members inherit from the workspace manifest, so the
        # source-form manifest (workspace = true keys intact) is what fits here.
        shutil.copyfile(orig, dest / "Cargo.toml")


def write_cargo_config(plan: Plan, work: pathlib.Path) -> None:
    member_names = set(plan.vendored)
    lines = ["[patch.crates-io]"]
    for crate in ALL_VENDORED:
        if crate in member_names:
            continue
        lines.append(f'{crate} = {{ path = "{(VENDOR / crate).as_posix()}" }}')
    (work / ".cargo").mkdir(exist_ok=True)
    (work / ".cargo" / "config.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")


def seed_lock(plan: Plan, work: pathlib.Path, use_committed: bool) -> bool:
    committed = LOCKS / f"{plan.group}.Cargo.lock"
    if use_committed and committed.exists():
        shutil.copyfile(committed, work / "Cargo.lock")
        return True
    # Seed from the repository's audited lock, not the (older) upstream one, so the
    # test builds resolve the same dependency versions as the shipped binary.
    shutil.copyfile(REPO / "Cargo.lock", work / "Cargo.lock")
    return False


def semver_compat_key(version: str) -> tuple:
    major, minor, patch = (int(part) for part in version.split("-")[0].split(".")[:3])
    if major:
        return (major,)
    if minor:
        return (0, minor)
    return (0, 0, patch)


def pin_patched_in_lock(plan: Plan, work: pathlib.Path) -> None:
    """Make a seeded lockfile use the vendored crates instead of registry copies.

    Cargo keeps an already-locked registry version over a `[patch]` candidate, so a
    seed that predates the patch (the upstream sqlx lock pins rustls 0.23.21) must
    be moved to the vendored version explicitly.
    """
    with open(work / "Cargo.lock", "rb") as handle:
        packages = tomllib.load(handle).get("package", [])
    for crate in ALL_VENDORED:
        if crate in plan.vendored:
            continue
        with open(VENDOR / crate / "Cargo.toml", "rb") as handle:
            patched = tomllib.load(handle)["package"]["version"]
        for package in packages:
            if package["name"] != crate or not package.get("source", "").startswith("registry+"):
                continue
            if package["version"] == patched:
                continue
            if semver_compat_key(package["version"]) != semver_compat_key(patched):
                continue
            log(f"  pinning {crate} {package['version']} -> vendored {patched} in the seed lock")
            subprocess.run(
                ["cargo", "update", "-p", f"{crate}@{package['version']}", "--precise", patched],
                cwd=work,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )


def prepare(
    plan: Plan, vt_dir: pathlib.Path, use_committed_lock: bool = True
) -> tuple[pathlib.Path, bool]:
    work = vt_dir / "work" / plan.group
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    upstream = None
    if plan.upstream:
        sha, _ = upstream_sha(plan)
        upstream = fetch_upstream(vt_dir, plan.upstream, sha)
    if plan.mode == "overlay":
        assert upstream is not None
        prepare_overlay(plan, work, upstream)
    else:
        prepare_scratch(plan, work, upstream)
    write_cargo_config(plan, work)
    shutil.copyfile(REPO / "rust-toolchain.toml", work / "rust-toolchain.toml")
    (work / ".sqlx").mkdir(exist_ok=True)
    locked = seed_lock(plan, work, use_committed_lock)
    if not locked and (work / "Cargo.lock").exists():
        pin_patched_in_lock(plan, work)
    return work, locked


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------

RESULT_RE = re.compile(
    r"^test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored", re.M
)


@dataclasses.dataclass
class Outcome:
    crate: str
    run: str
    status: str  # PASS | FAIL | SKIP
    passed: int = 0
    failed: int = 0
    ignored: int = 0
    seconds: float = 0.0
    detail: str = ""


def cargo_test(
    work: pathlib.Path,
    args: list[str],
    harness: list[str],
    env: dict[str, str],
    logfile: pathlib.Path,
    locked: bool,
) -> tuple[int, str, float]:
    # --no-fail-fast: report every failing test binary, not just the first.
    cmd = ["cargo", "test", "--no-fail-fast"]
    if locked:
        cmd.append("--locked")
    cmd += args
    if harness:
        cmd += ["--"] + harness
    full_env = os.environ.copy()
    full_env.update(env)
    full_env.setdefault("CARGO_TERM_COLOR", "never")
    full_env.setdefault("RUST_BACKTRACE", "1")
    log(f"$ {' '.join(cmd)}")
    start = time.monotonic()
    with open(logfile, "w", encoding="utf-8") as handle:
        handle.write("$ " + " ".join(cmd) + "\n")
        handle.flush()
        proc = subprocess.run(
            cmd, cwd=work, env=full_env, stdout=handle, stderr=subprocess.STDOUT, check=False
        )
    elapsed = time.monotonic() - start
    return proc.returncode, logfile.read_text(encoding="utf-8", errors="replace"), elapsed


def failing_tests(output: str) -> list[str]:
    return sorted(
        set(re.findall(r"^test (\S+)(?: - should panic)? \.\.\. FAILED", output, re.M))
    )


def tally(output: str) -> tuple[int, int, int]:
    p = f = i = 0
    for match in RESULT_RE.finditer(output):
        p += int(match.group(1))
        f += int(match.group(2))
        i += int(match.group(3))
    return p, f, i


def load_setup_sql(work: pathlib.Path, url: str, sql_file: str) -> str:
    """Reset the test database and load sqlx's schema; returns a problem or ''."""
    psql = shutil.which("psql")
    if not psql:
        return "needs psql to load the upstream test schema"
    reset = (
        "DROP SCHEMA IF EXISTS public CASCADE; DROP SCHEMA IF EXISTS foo CASCADE; "
        "CREATE SCHEMA public;"
    )
    proc = subprocess.run(
        [psql, url, "-v", "ON_ERROR_STOP=1", "-q", "-c", reset, "-f", str(work / sql_file)],
        check=False,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        return f"loading {sql_file} failed: {proc.stderr.strip()[:300]}"
    return ""


PEBBLE_VERSION = "v2.10.1"


def ensure_pebble(vt_dir: pathlib.Path) -> dict[str, str] | str:
    """Env vars locating pebble and pebble-challtestsrv, or a reason to skip.

    Honours PEBBLE/CHALLTESTSRV; otherwise builds the pinned release with `go
    install` (checksum-verified through the Go module proxy / sumdb).
    """
    if os.environ.get("PEBBLE") and os.environ.get("CHALLTESTSRV"):
        return {"PEBBLE": os.environ["PEBBLE"], "CHALLTESTSRV": os.environ["CHALLTESTSRV"]}
    if not shutil.which("go"):
        return "needs pebble: set PEBBLE and CHALLTESTSRV, or install Go to build it"
    bindir = vt_dir / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["GOBIN"] = str(bindir)
    for tool in ("pebble", "pebble-challtestsrv"):
        if (bindir / tool).exists():
            continue
        log(f"building {tool} {PEBBLE_VERSION}")
        proc = subprocess.run(
            ["go", "install", f"github.com/letsencrypt/pebble/v2/cmd/{tool}@{PEBBLE_VERSION}"],
            env=env,
            check=False,
        )
        if proc.returncode != 0:
            return f"go install of {tool} {PEBBLE_VERSION} failed"
    return {
        "PEBBLE": str(bindir / "pebble"),
        "CHALLTESTSRV": str(bindir / "pebble-challtestsrv"),
    }


def execute_run(
    crate: str, run: Run, work: pathlib.Path, vt_dir: pathlib.Path, locked: bool
) -> Outcome:
    if run.requires_env and not os.environ.get(run.requires_env):
        return Outcome(crate, run.name, "SKIP", detail=run.skip_reason)
    env = dict(run.env)
    if run.requires_env:
        env["DATABASE_URL"] = os.environ[run.requires_env]
    if run.setup_sql:
        problem = load_setup_sql(work, os.environ[run.requires_env], run.setup_sql)
        if problem:
            return Outcome(crate, run.name, "SKIP" if problem.startswith("needs") else "FAIL", detail=problem)
    if run.requires_tool == "pebble":
        found = ensure_pebble(vt_dir)
        if isinstance(found, str):
            return Outcome(crate, run.name, "SKIP", detail=found)
        env.update(found)
    logs = vt_dir / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    harness = list(run.harness)
    for name in run.xfail:
        harness += ["--skip", name]
    rc, output, seconds = cargo_test(
        work, run.args, harness, env, logs / f"{crate}-{run.name}.log", locked
    )
    passed, failed, ignored = tally(output)
    outcome = Outcome(crate, run.name, "PASS", passed, failed, ignored, seconds)
    if rc != 0:
        outcome.status = "FAIL"
        names = failing_tests(output)
        outcome.detail = (
            "failing tests: " + ", ".join(names[:12]) + (" ..." if len(names) > 12 else "")
            if names
            else "cargo test failed before/while running tests (see log)"
        )
        return outcome
    if passed == 0 and not run.allow_empty:
        outcome.status = "FAIL"
        outcome.detail = "no tests ran"
        return outcome
    if run.xfail:
        # The diverging tests must still fail: otherwise the exemption is stale.
        rc2, out2, secs2 = cargo_test(
            work,
            run.args,
            run.harness + ["--exact"] + run.xfail,
            env,
            logs / f"{crate}-{run.name}-xfail.log",
            locked,
        )
        outcome.seconds += secs2
        failed_names = set(failing_tests(out2))
        missing = [n for n in run.xfail if not any(f.endswith(n) for f in failed_names)]
        if rc2 == 0 or missing:
            outcome.status = "FAIL"
            outcome.detail = (
                "expected-to-fail tests no longer fail (remove from xfail): " + ", ".join(missing or run.xfail)
            )
        else:
            outcome.detail = f"{len(run.xfail)} expected failure(s) confirmed: {run.xfail_reason}"
    return outcome


def update_lock(crate: str, vt_dir: pathlib.Path) -> None:
    """Re-resolve the group's scratch workspace from its seed; no tests are run."""
    plan = PLANS[crate]
    log(f"\n===== {crate} (group {plan.group}): refreshing lockfile =====")
    work, _ = prepare(plan, vt_dir, use_committed_lock=False)
    subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        cwd=work,
        stdout=subprocess.DEVNULL,
        check=True,
    )
    LOCKS.mkdir(parents=True, exist_ok=True)
    target = LOCKS / f"{plan.group}.Cargo.lock"
    shutil.copyfile(work / "Cargo.lock", target)
    log(f"  wrote {target.relative_to(REPO)}")


def run_crate(crate: str, vt_dir: pathlib.Path, selected: list[str] | None) -> list[Outcome]:
    plan = PLANS[crate]
    log(f"\n===== {crate} (group {plan.group}) =====")
    work, have_lock = prepare(plan, vt_dir)
    # Without a committed lock the first resolution cannot use --locked.
    locked = have_lock and not os.environ.get("VENDOR_TESTS_UNLOCKED")
    if not have_lock:
        log(
            f"  note: no committed lockfile for group {plan.group}; resolving from the "
            "seed. Run with --update-locks and commit tools/vendor-tests/locks/."
        )
    outcomes: list[Outcome] = []
    for run in plan.runs:
        if selected and run.name not in selected:
            continue
        outcomes.append(execute_run(crate, run, work, vt_dir, locked))
        last = outcomes[-1]
        log(
            f"  -> {last.run}: {last.status} ({last.passed} passed, {last.failed} failed, "
            f"{last.ignored} ignored) {last.detail}"
        )
    return outcomes


def summarize(outcomes: list[Outcome]) -> int:
    log("\n===== vendored crate test summary =====")
    width = max((len(f"{o.crate}/{o.run}") for o in outcomes), default=10)
    bad = 0
    for o in outcomes:
        label = f"{o.crate}/{o.run}".ljust(width)
        log(
            f"{o.status:<5} {label}  {o.passed:>5} passed {o.failed:>3} failed "
            f"{o.ignored:>3} ignored  {o.seconds:6.0f}s  {o.detail}"
        )
        if o.status == "FAIL":
            bad += 1
    skipped = [o for o in outcomes if o.status == "SKIP"]
    if skipped:
        log(f"{len(skipped)} run(s) skipped (see reasons above)")
    log("RESULT: " + ("FAILED" if bad else "ok"))
    return 1 if bad else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("crates", nargs="*", help="crates to test (default: all)")
    parser.add_argument("--list", action="store_true", help="list crates and their runs")
    parser.add_argument("--run", action="append", default=[], help="only the named run(s)")
    parser.add_argument(
        "--update-locks",
        action="store_true",
        help="re-resolve (no tests) and rewrite tools/vendor-tests/locks/*.Cargo.lock",
    )
    args = parser.parse_args()

    if args.list:
        for name, plan in PLANS.items():
            log(f"{name}: " + ", ".join(r.name for r in plan.runs))
        return 0

    crates = args.crates or list(PLANS)
    unknown = [c for c in crates if c not in PLANS]
    if unknown:
        raise SystemExit(f"unknown crate(s): {', '.join(unknown)}; known: {', '.join(PLANS)}")

    vt_dir = pathlib.Path(os.environ.get("VENDOR_TESTS_DIR", REPO / "target" / "vendor-tests")).resolve()
    vt_dir.mkdir(parents=True, exist_ok=True)
    os.environ.setdefault("CARGO_TARGET_DIR", str(vt_dir / "target"))
    log(f"scratch dir: {vt_dir}")
    log(f"target dir : {os.environ['CARGO_TARGET_DIR']}")

    if args.update_locks:
        done_groups: set[str] = set()
        for crate in crates:
            if PLANS[crate].group not in done_groups:
                update_lock(crate, vt_dir)
                done_groups.add(PLANS[crate].group)
        return 0

    outcomes: list[Outcome] = []
    for crate in crates:
        outcomes += run_crate(crate, vt_dir, args.run or None)
    return summarize(outcomes)


if __name__ == "__main__":
    sys.exit(main())
