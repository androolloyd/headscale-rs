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


def upstream_main_sha() -> str:
    output = subprocess.check_output(
        ["git", "ls-remote", UPSTREAM_URL, "refs/heads/main"],
        cwd=REPO_ROOT,
        text=True,
    )
    parts = output.split()
    if len(parts) < 2 or parts[1] != "refs/heads/main":
        raise CheckError(f"unexpected git ls-remote output for {UPSTREAM_URL}: {output!r}")
    return parts[0]


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
        print(f"checked upstream headscale-go main pin: {current}")

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
