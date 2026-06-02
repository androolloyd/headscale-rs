#!/usr/bin/env python3
"""Emit the fuzz target matrix from the cargo-fuzz manifest."""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FUZZ_MANIFEST = REPO_ROOT / "headscale-core" / "fuzz" / "Cargo.toml"
FUZZ_TARGETS_DIR = FUZZ_MANIFEST.parent / "fuzz_targets"


def main() -> int:
    manifest = tomllib.loads(FUZZ_MANIFEST.read_text(encoding="utf-8"))
    targets: list[str] = []
    manifest_paths: set[str] = set()
    for bin_target in manifest.get("bin", []):
        name = bin_target.get("name")
        path = bin_target.get("path")
        if not isinstance(name, str) or not name:
            raise SystemExit("fuzz bin entry is missing a non-empty name")
        if not isinstance(path, str) or not path.startswith("fuzz_targets/"):
            continue
        if not (FUZZ_MANIFEST.parent / path).is_file():
            raise SystemExit(f"fuzz target path does not exist: {path}")
        manifest_paths.add(path)
        targets.append(name)

    if not targets:
        raise SystemExit("no fuzz targets found")

    unlisted_sources = sorted(
        source.relative_to(FUZZ_MANIFEST.parent).as_posix()
        for source in FUZZ_TARGETS_DIR.glob("*.rs")
        if source.relative_to(FUZZ_MANIFEST.parent).as_posix() not in manifest_paths
    )
    if unlisted_sources:
        details = "\n  ".join(unlisted_sources)
        raise SystemExit(f"fuzz target source files missing from manifest:\n  {details}")

    targets.sort()

    if sys.argv[1:] == ["--matrix"]:
        print(json.dumps({"target": targets}, separators=(",", ":")))
    elif not sys.argv[1:]:
        print("\n".join(targets))
    else:
        raise SystemExit("usage: fuzz_targets.py [--matrix]")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
