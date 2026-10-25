#!/usr/bin/env python3
"""Validate checked-in headscale-go parity reference pins."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
GO_MOD = REPO_ROOT / "tools" / "parity" / "headscale-go" / "go.mod"
BASELINE_SH = REPO_ROOT / "tools" / "real-client" / "headscale-go-baseline.sh"
CURRENT_SH = REPO_ROOT / "tools" / "real-client" / "headscale-go-current.sh"
UPSTREAM_URL = "https://github.com/juanfont/headscale.git"


class CheckError(Exception):
    pass


def relative(path: pathlib.Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def shell_default(path: pathlib.Path, name: str) -> str:
    pattern = re.compile(
        rf"^{re.escape(name)}=\"\$\{{{re.escape(name)}:-(?P<value>[^\"]+)}}\"$"
    )
    for line in path.read_text(encoding="utf-8").splitlines():
        match = pattern.match(line.strip())
        if match:
            return match.group("value")
    raise CheckError(f"{relative(path)} does not define default {name}")


def headscale_go_version() -> str:
    for line in GO_MOD.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "github.com/juanfont/headscale":
            return parts[1]
    raise CheckError(f"{relative(GO_MOD)} does not pin github.com/juanfont/headscale")


def git_ls_remote(refs: list[str]) -> dict[str, str]:
    output = subprocess.check_output(
        ["git", "ls-remote", UPSTREAM_URL, *refs],
        cwd=REPO_ROOT,
        text=True,
    )
    found: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 2:
            raise CheckError(f"unexpected git ls-remote output for {UPSTREAM_URL}: {output!r}")
        found[parts[1]] = parts[0]
    return found


def upstream_main_sha() -> str:
    found = git_ls_remote(["refs/heads/main"])
    try:
        return found["refs/heads/main"]
    except KeyError as err:
        raise CheckError(f"{UPSTREAM_URL} is missing refs/heads/main") from err


def upstream_tag_sha(version: str) -> str:
    ref = f"refs/tags/{version}"
    peeled_ref = f"{ref}^{{}}"
    found = git_ls_remote([ref, peeled_ref])
    if peeled_ref in found:
        return found[peeled_ref]
    try:
        return found[ref]
    except KeyError as err:
        raise CheckError(f"{UPSTREAM_URL} is missing pinned tag {version}") from err


def warn(message: str) -> None:
    """Report a non-fatal finding (a workflow annotation under GitHub Actions)."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::warning title=headscale-go pin::{message}")
    else:
        print(f"warning: {message}", file=sys.stderr)


def check(remote: bool, fail_on_stale: bool = False) -> None:
    go_mod_version = headscale_go_version()
    baseline = shell_default(BASELINE_SH, "HEADSCALE_GO_BASELINE_VERSION")
    current = shell_default(CURRENT_SH, "HEADSCALE_GO_CURRENT_VERSION")

    if baseline != go_mod_version:
        raise CheckError(
            "pinned headscale-go baseline mismatch: "
            f"{relative(BASELINE_SH)} defaults to {baseline}, "
            f"but {relative(GO_MOD)} pins {go_mod_version}"
        )

    if not re.fullmatch(r"[0-9a-f]{40}", current):
        raise CheckError(
            f"{relative(CURRENT_SH)} must pin a full 40-character upstream main SHA"
        )

    if remote:
        # The pinned baseline tag is an immutable reference: it must keep
        # resolving, and a missing tag is always an error.
        tag_sha = upstream_tag_sha(baseline)
        print(f"checked upstream headscale-go baseline tag: {baseline} -> {tag_sha}")

        # Upstream main moves whenever headscale-go merges anything, so a
        # differing SHA is drift to schedule a re-qualification for, not a
        # reason to fail every push, pull request and nightly smoke run (that
        # is how this gate kept the whole real-client job red). It is reported
        # as a warning; `--fail-on-stale` turns it into an error for the
        # dedicated freshness job.
        upstream = upstream_main_sha()
        if current != upstream:
            message = (
                "checked-in current-head headscale-go pin is stale: "
                f"{relative(CURRENT_SH)} has {current}, upstream main is {upstream}"
            )
            if fail_on_stale:
                raise CheckError(message)
            warn(message)
        else:
            print(f"checked upstream headscale-go main pin: {current}")

    print(f"checked headscale-go baseline pin: {baseline}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--remote",
        action="store_true",
        help=(
            "also verify the baseline tag exists upstream and report (as a "
            "warning) when HEADSCALE_GO_CURRENT_VERSION differs from upstream main"
        ),
    )
    parser.add_argument(
        "--fail-on-stale",
        action="store_true",
        help="with --remote, fail instead of warning when the current-head pin is stale",
    )
    args = parser.parse_args()
    if args.fail_on_stale and not args.remote:
        parser.error("--fail-on-stale requires --remote")

    try:
        check(remote=args.remote, fail_on_stale=args.fail_on_stale)
    except (CheckError, subprocess.CalledProcessError) as err:
        print(err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
