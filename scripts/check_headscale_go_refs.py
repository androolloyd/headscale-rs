#!/usr/bin/env python3
"""Validate checked-in headscale-go parity reference pins."""

from __future__ import annotations

import argparse
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


def check(remote: bool) -> None:
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
        upstream = upstream_main_sha()
        if current != upstream:
            raise CheckError(
                "checked-in current-head headscale-go pin is stale: "
                f"{relative(CURRENT_SH)} has {current}, upstream main is {upstream}"
            )
        tag_sha = upstream_tag_sha(baseline)
        print(f"checked upstream headscale-go main pin: {current}")
        print(f"checked upstream headscale-go baseline tag: {baseline} -> {tag_sha}")

    print(f"checked headscale-go baseline pin: {baseline}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--remote",
        action="store_true",
        help="also compare HEADSCALE_GO_CURRENT_VERSION with upstream main",
    )
    args = parser.parse_args()

    try:
        check(remote=args.remote)
    except (CheckError, subprocess.CalledProcessError) as err:
        print(err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
