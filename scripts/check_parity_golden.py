#!/usr/bin/env python3
"""Validate parity scenario and golden metadata used by CI."""

from __future__ import annotations

import json
import pathlib
import sys


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
GO_MOD = REPO_ROOT / "tools" / "parity" / "headscale-go" / "go.mod"
PINNED_SCENARIOS = REPO_ROOT / "tools" / "parity" / "scenarios"
PINNED_GOLDENS = REPO_ROOT / "tools" / "parity" / "golden"
CURRENT_HEAD_SCENARIOS = REPO_ROOT / "tools" / "parity" / "current-head"
CURRENT_HEAD_GOLDEN = CURRENT_HEAD_SCENARIOS / "golden" / "headscale-rs.json"


class CheckError(Exception):
    pass


def load_json(path: pathlib.Path) -> object:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except json.JSONDecodeError as err:
        raise CheckError(f"{relative(path)} is not valid JSON: {err}") from err


def relative(path: pathlib.Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def headscale_go_version() -> str:
    for line in GO_MOD.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "github.com/juanfont/headscale":
            return parts[1]
    raise CheckError(f"{relative(GO_MOD)} does not pin github.com/juanfont/headscale")


def scenario_names(
    scenario_dir: pathlib.Path, label: str, *, allow_empty: bool = False
) -> list[str]:
    paths = sorted(scenario_dir.glob("*.json"))
    if not paths and not allow_empty:
        raise CheckError(f"{label} has no scenario files in {relative(scenario_dir)}")

    names: list[str] = []
    seen: dict[str, pathlib.Path] = {}
    for path in paths:
        document = load_json(path)
        if not isinstance(document, dict):
            raise CheckError(f"{relative(path)} must contain a JSON object")

        name = document.get("name")
        if not isinstance(name, str) or not name:
            raise CheckError(f"{relative(path)} is missing a non-empty name")
        if name != path.stem:
            raise CheckError(
                f"{relative(path)} name {name!r} must match filename stem {path.stem!r}"
            )
        if name in seen:
            raise CheckError(
                f"duplicate {label} scenario name {name!r}: "
                f"{relative(seen[name])} and {relative(path)}"
            )

        seen[name] = path
        names.append(name)

    return names


def golden_names(
    golden_path: pathlib.Path,
    label: str,
    expected_engine: str,
    *,
    allow_empty: bool = False,
) -> list[str]:
    if not golden_path.is_file():
        raise CheckError(f"{label} golden is missing: {relative(golden_path)}")

    document = load_json(golden_path)
    if not isinstance(document, list):
        raise CheckError(f"{relative(golden_path)} must contain a JSON array")
    if not document and not allow_empty:
        raise CheckError(f"{relative(golden_path)} must not be empty")

    names: list[str] = []
    seen: set[str] = set()
    for index, entry in enumerate(document):
        if not isinstance(entry, dict):
            raise CheckError(f"{relative(golden_path)}[{index}] must be a JSON object")

        name = entry.get("name")
        if not isinstance(name, str) or not name:
            raise CheckError(f"{relative(golden_path)}[{index}] is missing a non-empty name")
        if name in seen:
            raise CheckError(f"{relative(golden_path)} contains duplicate scenario {name!r}")

        engine = entry.get("engine")
        if engine != expected_engine:
            raise CheckError(
                f"{relative(golden_path)} scenario {name!r} has engine {engine!r}; "
                f"expected {expected_engine!r}"
            )

        seen.add(name)
        names.append(name)

    return names


def compare_names(label: str, scenarios: list[str], golden: list[str]) -> None:
    if scenarios == golden:
        return

    scenario_set = set(scenarios)
    golden_set = set(golden)
    missing = sorted(scenario_set - golden_set)
    extra = sorted(golden_set - scenario_set)
    details: list[str] = [f"{label} scenario/golden coverage mismatch"]
    if missing:
        details.append(f"missing from golden: {', '.join(missing)}")
    if extra:
        details.append(f"extra in golden: {', '.join(extra)}")
    if not missing and not extra:
        details.append("scenario and golden names match as sets but not in sorted file order")
    raise CheckError("; ".join(details))


def check_pinned() -> None:
    version = headscale_go_version()
    golden_path = PINNED_GOLDENS / f"headscale-go-{version}.json"
    scenarios = scenario_names(PINNED_SCENARIOS, "pinned")
    golden = golden_names(golden_path, "pinned", "headscale")
    compare_names("pinned", scenarios, golden)
    print(f"checked pinned parity golden {relative(golden_path)} for {len(scenarios)} scenarios")


def check_current_head() -> None:
    scenarios = scenario_names(CURRENT_HEAD_SCENARIOS, "current-head", allow_empty=True)
    golden = golden_names(
        CURRENT_HEAD_GOLDEN,
        "current-head",
        "headscale-rs",
        allow_empty=True,
    )
    compare_names("current-head", scenarios, golden)
    print(
        f"checked current-head parity golden {relative(CURRENT_HEAD_GOLDEN)} "
        f"for {len(scenarios)} scenarios"
    )


def main() -> int:
    try:
        check_pinned()
        check_current_head()
    except CheckError as err:
        print(err, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
