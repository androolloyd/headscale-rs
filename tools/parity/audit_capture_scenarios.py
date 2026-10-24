#!/usr/bin/env python3
"""Run every converted upstream capture against the pinned Go and Rust engines."""

from __future__ import annotations

import argparse
import fnmatch
import json
import pathlib
import subprocess
import sys
from collections import Counter


def run_engine(binary: pathlib.Path, scenario: pathlib.Path) -> tuple[object | None, str]:
    try:
        result = subprocess.run(
            [str(binary), str(scenario)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, "engine timed out after 30 seconds"
    if result.returncode:
        return None, result.stderr.strip()[:1000]
    try:
        output = json.loads(result.stdout)
        assert isinstance(output, list) and len(output) == 1
        output[0]["engine"] = "headscale"
        return output[0], ""
    except (AssertionError, ValueError, KeyError, TypeError) as error:
        return None, f"invalid engine JSON output: {error}: {result.stdout[:500]}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=pathlib.Path, required=True)
    parser.add_argument("--go", type=pathlib.Path, required=True)
    parser.add_argument("--rust", type=pathlib.Path, required=True)
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--pattern", default="capture-*.json")
    args = parser.parse_args()

    manifest = json.loads(args.manifest.read_text())
    results: list[dict[str, object]] = []
    for entry in manifest["entries"]:
        output = entry.get("output")
        if not output or not fnmatch.fnmatchcase(output, args.pattern):
            continue
        scenario = args.manifest.parent / output
        go, go_error = run_engine(args.go, scenario)
        rust, rust_error = run_engine(args.rust, scenario)
        if go is not None and rust is not None:
            status = "matched" if go == rust else "output_mismatch"
        elif go is None and rust is None:
            status = "both_rejected"
        elif go is None:
            status = "go_rejected"
        else:
            status = "rust_rejected"
        row = {
            "source": entry["source"],
            "sha256": entry["sha256"],
            "source_api_response_code": entry["source_api_response_code"],
            "scenario": output,
            "status": status,
        }
        if go_error:
            row["go_error"] = go_error
        if rust_error:
            row["rust_error"] = rust_error
        results.append(row)
        if status == "output_mismatch":
            mismatch_dir = args.out.parent / "capture-mismatches"
            mismatch_dir.mkdir(parents=True, exist_ok=True)
            stem = pathlib.Path(output).stem
            (mismatch_dir / f"{stem}-go.json").write_text(
                json.dumps(go, indent=2, sort_keys=True) + "\n"
            )
            (mismatch_dir / f"{stem}-rust.json").write_text(
                json.dumps(rust, indent=2, sort_keys=True) + "\n"
            )

    counts = dict(sorted(Counter(row["status"] for row in results).items()))
    report = {
        "upstream_version": manifest["upstream_version"],
        "pattern": args.pattern,
        "counts": counts,
        "counts_by_api_response_code": {
            str(code): dict(sorted(Counter(
                row["status"] for row in results
                if row["source_api_response_code"] == code
            ).items()))
            for code in sorted({row["source_api_response_code"] for row in results})
        },
        "results": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(f"capture audit: {counts}; report {args.out}")
    if any(counts.get(status, 0) for status in ("output_mismatch", "go_rejected", "rust_rejected")):
        sys.exit(1)


if __name__ == "__main__":
    main()
