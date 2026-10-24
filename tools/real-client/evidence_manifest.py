#!/usr/bin/env python3
"""Record source/binary/toolchain identity beside a parity qualification packet.

This records provenance, not test results. It never dumps the environment,
configuration files, source diffs, database contents, or report contents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOTS = (
    "headscale-api", "headscale-api-acl", "headscale-db", "headscale-cli",
    "headscale-core", "headscale-identity", "headscale-resources", "headscale-payments",
    "vendor", "scripts", "tools/parity", "tools/real-client", ".github/workflows",
)
# Build/package inputs outside crate trees are part of the same source identity.
# Keep deployment configuration/state out of the inventory; these are source
# recipes and Cargo settings, never runtime configuration or credentials.
SOURCE_FILES = (
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rust-toolchain",
    "deny.toml", ".cargo/config.toml", ".cargo/config", ".dockerignore",
    "deploy/docker/Dockerfile", "deploy/docker/Dockerfile.node",
)


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def source_identity() -> dict:
    paths = {ROOT / name for name in SOURCE_FILES
             if (ROOT / name).is_file()}
    for relative in SOURCE_ROOTS:
        base = ROOT / relative
        if not base.exists():
            continue
        for path in base.rglob("*"):
            parts = path.relative_to(base).parts
            if any(part in {"target", ".git", "__pycache__", "node_modules", "artifacts", "corpus"}
                   for part in parts):
                continue
            if path.is_file() and not path.is_symlink():
                paths.add(path)
    files = {str(path.relative_to(ROOT)): digest(path) for path in sorted(paths)}
    aggregate = hashlib.sha256()
    for relative, checksum in files.items():
        aggregate.update((relative + "\0" + checksum + "\n").encode())
    return {"sha256": aggregate.hexdigest(), "files": files,
            "algorithm": "sorted relative-path NUL per-file-SHA256 newline"}


def command(args: list[str]) -> dict:
    try:
        result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, check=False)
        return {"command": args, "status": result.returncode, "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip()}
    except OSError as error:
        return {"command": args, "status": None, "error": str(error)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--binary", action="append", default=[], metavar="LABEL=PATH")
    parser.add_argument("--features", default="unspecified")
    parser.add_argument("--backends", default="unspecified")
    parser.add_argument("--reports", type=Path)
    parser.add_argument("--compare-source", type=Path)
    parser.add_argument("--allow-missing-binary", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    errors = []
    source = source_identity()
    binaries = {}
    for specification in args.binary:
        label, separator, raw_path = specification.partition("=")
        if not separator or not label or not raw_path:
            parser.error("--binary must be LABEL=PATH")
        path = Path(raw_path).resolve()
        if path.is_file():
            binaries[label] = {"path": str(path), "sha256": digest(path), "bytes": path.stat().st_size}
        else:
            binaries[label] = {"path": str(path), "missing": True}
            if not args.allow_missing_binary:
                errors.append(f"missing {label} binary")
    if args.compare_source:
        try:
            before = json.loads(args.compare_source.read_text())
            if before["source"]["sha256"] != source["sha256"]:
                errors.append("qualification source changed between provenance captures")
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(f"initial source identity unavailable: {error}")
    reports = {}
    if args.reports and args.reports.exists():
        for path in sorted(args.reports.rglob("report.json")):
            if path.resolve() != output:
                reports[str(path.resolve().relative_to(args.reports.resolve()))] = digest(path)
        # Several stock-client rows build their own pinned Go binary. Retain
        # their identities as an inventory, separately from the named CLI pair.
        for path in sorted(args.reports.rglob("headscale")):
            if path.is_file() and not path.is_symlink() and os.access(path, os.X_OK):
                label = "report-tree:" + str(path.relative_to(args.reports))
                binaries[label] = {"path": str(path.resolve()), "sha256": digest(path),
                                   "bytes": path.stat().st_size}
    tools = {label: command(argv) for label, argv in {
        "rustc": ["rustc", "-Vv"], "cargo": ["cargo", "-V"], "go": ["go", "version"],
    }.items()}
    for label, result in tools.items():
        if result["status"] != 0:
            errors.append(f"{label} identity unavailable")
    record = {
        "schema_version": 1, "captured_at": datetime.now(timezone.utc).isoformat(),
        "purpose": "provenance only; test outcomes remain in the referenced reports",
        "binding_scope": "packet inventory captured at this time; not a per-row execution receipt",
        "source": source, "git_head": command(["git", "rev-parse", "HEAD"]),
        "git_status": command(["git", "status", "--porcelain=v1", "--untracked-files=normal"]),
        "binaries": binaries, "toolchains": tools,
        "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
        "configured_scope": {"features": args.features, "backends": args.backends},
        "ci": {name: os.environ[name] for name in ("GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")
               if name in os.environ},
        "report_sha256": reports, "metadata_errors": errors,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"wrote provenance {output}: {source['sha256']}")
    for error in errors:
        print(error, file=sys.stderr)
    return int(bool(errors))


if __name__ == "__main__":
    raise SystemExit(main())
