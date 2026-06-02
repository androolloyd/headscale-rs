#!/usr/bin/env python3
"""Validate real-client parity CI selection metadata."""

from __future__ import annotations

from collections import Counter
import os
import pathlib
import re
import subprocess
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "real-client-parity.yml"
MIN_PR_SMOKE_COUNT = 150
REQUIRED_PR_SMOKES = {
    "authkey",
    "taildrop-capmap",
    "web-register-tags",
    "web-register-unowned-tag",
    "oidc-policy-churn-restart",
    "ssh-oidc-check",
    "ssh-cli-check",
    "ssh-localpart",
    "ssh-profile-variants",
    "ssh-profile-subdomain-deny",
    "magicdns-custom-domain",
    "dns-edge",
    "dns-hot-reload",
    "magicdns-ipv6-only",
    "acl-empty",
    "acl-autogroup-self",
    "derp-private",
    "postgres-web-register-policy-churn",
    "postgres-web-register-policy-churn-restart",
    "postgres-policy-rename-restart",
    "route-via-multiprefix-reload-restart",
    "route-health-reload-restart",
    "route-edge-current-upstream-audit",
    "tag-update-invalid",
}


class CheckError(Exception):
    pass


def extract_scalar(text: str, key: str) -> str:
    lines = text.splitlines()
    pattern = re.compile(rf"^(?P<indent>\s*){re.escape(key)}:\s*(?P<value>.*)$")
    for index, line in enumerate(lines):
        match = pattern.match(line)
        if not match:
            continue

        value = match.group("value").strip()
        if value not in {">", ">-", "|", "|-"}:
            return value.strip("\"'")

        parent_indent = len(match.group("indent"))
        chunks: list[str] = []
        for child in lines[index + 1 :]:
            if not child.strip():
                continue
            child_indent = len(child) - len(child.lstrip(" "))
            if child_indent <= parent_indent:
                break
            chunks.append(child.strip())
        if not chunks:
            raise CheckError(f"{key} block scalar is empty")
        return " ".join(chunks)

    raise CheckError(f"{WORKFLOW.relative_to(REPO_ROOT)} is missing {key}")


def split_words(value: str) -> list[str]:
    return [part for part in value.replace(",", " ").split() if part]


def require_snippet(text: str, snippet: str, label: str) -> None:
    if snippet not in text:
        raise CheckError(f"real-client workflow no longer contains {label}")


def run_smoke_matrix_check(smokes: list[str]) -> None:
    env = os.environ.copy()
    env["REAL_CLIENT_SMOKES"] = " ".join(smokes)
    env["REAL_CLIENT_TARGETS"] = "rust headscale-go"
    subprocess.run(
        ["tools/real-client/smoke-matrix.sh", "--check"],
        cwd=REPO_ROOT,
        env=env,
        check=True,
    )


def main() -> int:
    try:
        text = WORKFLOW.read_text(encoding="utf-8")

        if "secrets." in text:
            raise CheckError("real-client workflow must not require repository secrets")

        require_snippet(text, "pull_request:", "pull_request trigger")
        require_snippet(text, "schedule:", "scheduled trigger")
        require_snippet(
            text,
            "python3 scripts/check_headscale_go_refs.py --remote",
            "headscale-go current-head pin check",
        )
        require_snippet(text, 'smokes="${PR_SMOKES}"', "PR/push smoke selection")
        require_snippet(text, 'smokes="all"', "scheduled full matrix selection")
        require_snippet(text, 'default: "all"', "workflow_dispatch full-matrix default")

        targets = extract_scalar(text, "REAL_CLIENT_TARGETS")
        if "rust" not in targets or "headscale-go" not in targets:
            raise CheckError("REAL_CLIENT_TARGETS must default to both rust and headscale-go")

        smokes = split_words(extract_scalar(text, "PR_SMOKES"))
        if "all" in smokes:
            raise CheckError("PR_SMOKES must list deterministic rows, not all")
        if len(smokes) < MIN_PR_SMOKE_COUNT:
            raise CheckError(
                f"PR_SMOKES selects {len(smokes)} rows; expected at least "
                f"{MIN_PR_SMOKE_COUNT}"
            )

        duplicates = sorted(name for name, count in Counter(smokes).items() if count > 1)
        if duplicates:
            raise CheckError(f"PR_SMOKES contains duplicate rows: {', '.join(duplicates)}")

        missing = sorted(REQUIRED_PR_SMOKES - set(smokes))
        if missing:
            raise CheckError(f"PR_SMOKES is missing required rows: {', '.join(missing)}")

        run_smoke_matrix_check(smokes)
    except (CheckError, subprocess.CalledProcessError) as err:
        print(err, file=sys.stderr)
        return 1

    print(
        "checked real-client parity workflow: "
        f"{len(smokes)} deterministic PR rows, scheduled all-row matrix"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
