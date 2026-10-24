#!/usr/bin/env python3
"""Compare pinned-Go and Rust CLI help and unknown-flag envelopes."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from collections import deque


ROOT = Path(__file__).resolve().parents[2]
GO_BIN = Path(os.environ.get("HEADSCALE_GO_BIN", ""))
RUST_BIN = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale"))
WORKDIR = Path(os.environ.get(
    "REAL_CLIENT_WORKDIR",
    f"target/real-client/cli-parser-tree-diff-{int(time.time())}-{os.getpid()}",
))
if not WORKDIR.is_absolute():
    WORKDIR = ROOT / WORKDIR
WORKDIR.mkdir(parents=True, exist_ok=True)
ENV = {key: value for key, value in os.environ.items() if not key.startswith("HEADSCALE_")}


def run(binary, args):
    result = subprocess.run([str(binary), *args], cwd=ROOT, env=ENV,
                            text=True, capture_output=True)
    return {"status": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def children_from_help(output):
    in_commands = False
    for line in output.splitlines():
        if line == "Available Commands:":
            in_commands = True
            continue
        if in_commands and not line.strip():
            break
        if in_commands:
            found = re.match(r"^  ([a-z][a-z0-9-]*)\s+\S", line)
            if found and found.group(1) != "help":
                yield found.group(1)


def main():
    if not GO_BIN.is_file():
        raise FileNotFoundError("set HEADSCALE_GO_BIN to pinned v0.29.5 executable")
    version = run(GO_BIN, ["version"])
    if version["status"] or "v0.29.5" not in version["stdout"]:
        raise RuntimeError(f"expected pinned headscale-go v0.29.5: {version}")
    if "RUST_HEADSCALE_BIN" not in os.environ:
        subprocess.run(["cargo", "build", "-p", "headscale-cli", "--bin", "headscale"],
                       cwd=ROOT, check=True)
    if not RUST_BIN.is_file():
        raise FileNotFoundError(f"Rust executable missing: {RUST_BIN}")
    queue = deque([()])
    seen = set()
    comparisons = 0
    mismatches = []
    while queue:
        path = queue.popleft()
        if path in seen:
            continue
        seen.add(path)
        help_args = [*path, "--help"]
        go_help = run(GO_BIN, help_args)
        rust_help = run(RUST_BIN, help_args)
        comparisons += 1
        if go_help != rust_help:
            mismatches.append({"path": path, "args": help_args,
                               "go": go_help, "rust": rust_help})
        if path:
            topic_args = ["help", *path]
            go_topic = run(GO_BIN, topic_args)
            rust_topic = run(RUST_BIN, topic_args)
            comparisons += 1
            if go_topic != rust_topic:
                mismatches.append({"path": path, "args": topic_args,
                                   "go": go_topic, "rust": rust_topic})
        for child in children_from_help(go_help["stdout"]):
            queue.append((*path, child))
        for fmt in ("human", "json", "json-line", "yaml"):
            args = ([] if fmt == "human" else ["-o", fmt]) + [*path, "--parity-unknown-flag"]
            go_result = run(GO_BIN, args)
            rust_result = run(RUST_BIN, args)
            comparisons += 1
            if go_result != rust_result:
                mismatches.append({"path": path, "args": args,
                                   "go": go_result, "rust": rust_result})
            if fmt != "human":
                trailing_args = [*path, "--parity-unknown-flag", "-o", fmt]
                go_trailing = run(GO_BIN, trailing_args)
                rust_trailing = run(RUST_BIN, trailing_args)
                comparisons += 1
                if go_trailing != rust_trailing:
                    mismatches.append({"path": path, "args": trailing_args,
                                       "go": go_trailing, "rust": rust_trailing})
    report = {"go_version": version["stdout"].strip(), "paths": len(seen),
              "comparisons": comparisons, "mismatches": mismatches}
    (WORKDIR / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(seen)} command paths, {comparisons} comparisons, "
          f"{len(mismatches)} mismatches: {WORKDIR / 'report.json'}")
    for mismatch in mismatches[:12]:
        print("mismatch:", " ".join(mismatch["args"]), file=sys.stderr)
    if mismatches:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"CLI parser tree diff failed: {error}", file=sys.stderr)
        sys.exit(1)
