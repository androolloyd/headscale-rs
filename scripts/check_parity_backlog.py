#!/usr/bin/env python3
"""Validate the machine-readable full-parity backlog."""

from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter
from typing import Any


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
BACKLOG = REPO_ROOT / "docs" / "headscale-go-parity-backlog.json"
PRIORITIES = {"P0", "P1", "P2"}
STATUSES = {"open", "in_progress", "blocked"}
COMPLETION_STATUSES = {"complete", "completed", "full_parity_complete"}


class BacklogError(Exception):
    pass


def relative(path: pathlib.Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def expect_str(item: dict[str, Any], key: str, label: str) -> str:
    value = item.get(key)
    if not isinstance(value, str) or not value.strip():
        raise BacklogError(f"{label} is missing non-empty string field {key!r}")
    return value


def expect_str_list(item: dict[str, Any], key: str, label: str) -> list[str]:
    value = item.get(key)
    if (
        not isinstance(value, list)
        or not value
        or any(not isinstance(entry, str) or not entry.strip() for entry in value)
    ):
        raise BacklogError(f"{label} is missing non-empty string list field {key!r}")
    return value


def load_document() -> dict[str, Any]:
    try:
        with BACKLOG.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except json.JSONDecodeError as err:
        raise BacklogError(f"{relative(BACKLOG)} is not valid JSON: {err}") from err

    if not isinstance(document, dict):
        raise BacklogError(f"{relative(BACKLOG)} must contain a JSON object")
    return document


def validate() -> tuple[int, Counter[str]]:
    document = load_document()
    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        raise BacklogError("metadata must be an object")

    project_status = expect_str(metadata, "status", "metadata")
    if project_status in COMPLETION_STATUSES:
        raise BacklogError(
            "metadata.status cannot claim completion while this backlog gate exists"
        )

    source = expect_str(metadata, "source", "metadata")
    if not (REPO_ROOT / source).exists():
        raise BacklogError(f"metadata.source does not exist: {source}")

    open_items = document.get("open_items")
    if not isinstance(open_items, list) or not open_items:
        raise BacklogError("open_items must be a non-empty list until parity is complete")

    seen_ids: set[str] = set()
    counts: Counter[str] = Counter()
    for index, item in enumerate(open_items):
        if not isinstance(item, dict):
            raise BacklogError(f"open_items[{index}] must be an object")

        label = f"open_items[{index}]"
        item_id = expect_str(item, "id", label)
        if item_id in seen_ids:
            raise BacklogError(f"duplicate backlog id: {item_id}")
        seen_ids.add(item_id)

        priority = expect_str(item, "priority", item_id)
        if priority not in PRIORITIES:
            raise BacklogError(f"{item_id} has invalid priority {priority!r}")
        counts[priority] += 1

        status = expect_str(item, "status", item_id)
        if status not in STATUSES:
            raise BacklogError(f"{item_id} has invalid status {status!r}")

        for key in ("lane", "type", "exit_criteria"):
            expect_str(item, key, item_id)
        for key in ("owner_scope", "upstream_evidence"):
            expect_str_list(item, key, item_id)

    summary = document.get("summary")
    if not isinstance(summary, dict):
        raise BacklogError("summary must be an object")

    expected_summary = {
        "open_p0": counts["P0"],
        "open_p1": counts["P1"],
        "open_p2": counts["P2"],
        "total_open": len(open_items),
    }
    for key, expected in expected_summary.items():
        if summary.get(key) != expected:
            raise BacklogError(
                f"summary.{key}={summary.get(key)!r}; expected {expected}"
            )

    return len(open_items), counts


def main() -> int:
    try:
        total, counts = validate()
    except BacklogError as err:
        print(err, file=sys.stderr)
        return 1

    print(
        "checked full-parity backlog: "
        f"{total} open items ({counts['P0']} P0, {counts['P1']} P1, {counts['P2']} P2)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
