#!/usr/bin/env python3
"""Fail when CI, the container images or the docs drift from rust-toolchain.toml.

The compiler this tree is built, linted and tested with is pinned once, in
`rust-toolchain.toml`. Everything else must follow it:

* the channel is an exact `X.Y.Z` release (never `stable`/`beta`/`nightly`) and
  the pin lists the `clippy` and `rustfmt` components;
* every `deploy/docker/Dockerfile*` builder stage uses `rust:<channel>-<variant>`;
* workflows install Rust through `./.github/actions/setup-rust` only. A
  `toolchain:` override must be a dated nightly (`nightly-YYYY-MM-DD`), which is
  what the fuzz jobs need for the libFuzzer sanitizers, and the floating
  installers (`dtolnay/rust-toolchain`, `actions-rs/toolchain`) are forbidden;
* CHANGES.md, when it names a qualified toolchain, names the pinned one (its
  newest mention counts; older entries are history).

Floating `stable`/`nightly` in CI is how main went red on 2026-10-16: the runner's
`stable` moved to 1.99, whose new `clippy::assert_is_empty` lint failed the
workspace, and the unpinned nightly rustfmt reformatted a tool crate.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
import tomllib


DEFAULT_ROOT = pathlib.Path(__file__).resolve().parents[1]
EXACT_VERSION = re.compile(r"\d+\.\d+\.\d+")
DATED_NIGHTLY = re.compile(r"nightly-\d{4}-\d{2}-\d{2}")
FLOATING_INSTALLERS = ("dtolnay/rust-toolchain", "actions-rs/toolchain")
SETUP_ACTION = "./.github/actions/setup-rust"
REQUIRED_COMPONENTS = {"clippy", "rustfmt"}


class CheckError(Exception):
    pass


def pinned_channel(root: pathlib.Path) -> str:
    path = root / "rust-toolchain.toml"
    if not path.is_file():
        raise CheckError("rust-toolchain.toml is missing")
    table = tomllib.loads(path.read_text(encoding="utf-8")).get("toolchain", {})
    channel = table.get("channel")
    if not isinstance(channel, str) or not EXACT_VERSION.fullmatch(channel):
        raise CheckError(
            f"rust-toolchain.toml channel must be an exact X.Y.Z release, got {channel!r}"
        )
    missing = REQUIRED_COMPONENTS - set(table.get("components", []))
    if missing:
        raise CheckError(
            "rust-toolchain.toml must list components " + ", ".join(sorted(missing))
        )
    return channel


def check_dockerfiles(root: pathlib.Path, channel: str) -> list[str]:
    problems: list[str] = []
    dockerfiles = sorted((root / "deploy" / "docker").glob("Dockerfile*"))
    if not dockerfiles:
        problems.append("deploy/docker has no Dockerfile*")
    for path in dockerfiles:
        rel = path.relative_to(root).as_posix()
        images = re.findall(
            r"^FROM\s+(rust:\S+)", path.read_text(encoding="utf-8"), re.MULTILINE
        )
        if not images:
            problems.append(f"{rel}: no `FROM rust:<version>-<variant>` builder stage")
        for image in images:
            tag = image.split(":", 1)[1]
            if tag.split("-", 1)[0] != channel:
                problems.append(
                    f"{rel}: builder image {image} does not match rust-toolchain.toml ({channel})"
                )
    return problems


def check_workflows(root: pathlib.Path) -> list[str]:
    problems: list[str] = []
    for path in sorted((root / ".github" / "workflows").glob("*.y*ml")):
        rel = path.relative_to(root).as_posix()
        text = path.read_text(encoding="utf-8")
        for installer in FLOATING_INSTALLERS:
            if installer in text:
                problems.append(
                    f"{rel}: uses {installer}; use {SETUP_ACTION} so rust-toolchain.toml applies"
                )
        if re.search(r"^\s*toolchain:\s*(stable|beta|nightly)\s*$", text, re.MULTILINE):
            problems.append(f"{rel}: floating `toolchain:` value; pin it")
        uses_cargo = re.search(r"\bcargo\b", text) is not None
        if uses_cargo and SETUP_ACTION not in text:
            problems.append(f"{rel}: runs cargo but never uses {SETUP_ACTION}")
        for match in re.finditer(r"^\s*toolchain:\s*(\S+)\s*$", text, re.MULTILINE):
            value = match.group(1).strip("\"'")
            if value.startswith("${{"):
                continue  # resolved from a job-level env value, checked below
            if not DATED_NIGHTLY.fullmatch(value):
                problems.append(
                    f"{rel}: `toolchain: {value}` must be a dated nightly (nightly-YYYY-MM-DD)"
                )
        for match in re.finditer(r"^\s*FUZZ_NIGHTLY_TOOLCHAIN:\s*(\S+)\s*$", text, re.MULTILINE):
            if not DATED_NIGHTLY.fullmatch(match.group(1).strip("\"'")):
                problems.append(f"{rel}: FUZZ_NIGHTLY_TOOLCHAIN must be nightly-YYYY-MM-DD")
    return problems


def check_changes(root: pathlib.Path, channel: str) -> list[str]:
    """CHANGES.md is newest-first; its latest statement of the qualified toolchain wins."""
    path = root / "CHANGES.md"
    if not path.is_file():
        return []
    found = re.search(
        r"qualified toolchain is (\d+\.\d+\.\d+)", path.read_text(encoding="utf-8")
    )
    if found and found.group(1) != channel:
        return [
            f"CHANGES.md names qualified toolchain {found.group(1)}, "
            f"rust-toolchain.toml pins {channel}"
        ]
    return []


def check(root: pathlib.Path) -> list[str]:
    channel = pinned_channel(root)
    return [
        *check_dockerfiles(root, channel),
        *check_workflows(root),
        *check_changes(root, channel),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=pathlib.Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    try:
        problems = check(args.root)
    except CheckError as err:
        print(err, file=sys.stderr)
        return 1
    if problems:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1
    print(f"toolchain pin {pinned_channel(args.root)} is used consistently")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
