#!/usr/bin/env python3
"""Export a Rust-managed SQLite database into pinned headscale-go v0.29.5 shape.

This produces a separate rollback artifact. It never edits the source database.
The pinned schema fixture is copied from hscontrol/db/schema.sql at
github.com/juanfont/headscale v0.29.5 (commit 0f7d1e536bed9f01dd7161f7637af19bb0908335).
"""

import argparse
import hashlib
import json
import os
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = Path(__file__).resolve().parents[2] / "headscale-db/schema/headscale-go-v0295.sql"
SCHEMA_SHA256 = "7db8001facc5a0508748e0470504c7df06e2c9e66f7facf11bc202b88d78e70b"
TABLES = ("users", "pre_auth_keys", "api_keys", "nodes", "policies")
SOURCE_VERSIONS = ("v0.29.0-beta.2", "v0.29.5")
MIGRATIONS = (
    "SCHEMA_INIT",
    "202501221827",
    "202501311657",
    "202502070949",
    "202502131714",
    "202502171819",
    "202505091439",
    "202505141324",
    "202507021200",
    "202510311551",
    "202511011637-preauthkey-bcrypt",
    "202511101554-drop-old-idx",
    "202511122344-remove-newline-index",
    "202511131445-node-forced-tags-to-tags",
    "202601121700-migrate-hostinfo-request-tags",
    "202602201200-clear-tagged-node-user-id",
    "202605221435-clear-zero-time-node-expiry",
    "202606181200-recover-null-tags-node-user-id",
    "202607241200-clear-tagged-node-expiry",
)


def columns(db: sqlite3.Connection, table: str) -> tuple[str, ...]:
    return tuple(row[1] for row in db.execute(f"PRAGMA table_info({table})"))


def reject_populated_sidecar(source_path: Path) -> None:
    sidecar = Path(str(source_path.resolve()) + ".rust-aux.sqlite")
    if not sidecar.exists():
        return
    with closing(sqlite3.connect(f"{sidecar.as_uri()}?mode=ro", uri=True)) as db:
        for (table,) in db.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        ):
            quoted = '"' + table.replace('"', '""') + '"'
            if db.execute(f"SELECT 1 FROM {quoted} LIMIT 1").fetchone():
                raise ValueError(
                    f"cannot export populated Rust sidecar table {table}; "
                    "the Go schema cannot preserve its rows"
                )


def export(source_path: Path, output_path: Path) -> dict[str, int]:
    if source_path.resolve() == output_path.resolve():
        raise ValueError("source and output paths must differ")
    if output_path.exists():
        raise FileExistsError(f"refusing to replace existing output: {output_path}")
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if not output_path.parent.is_dir():
        raise FileNotFoundError(output_path.parent)
    reject_populated_sidecar(source_path)
    schema = SCHEMA.read_bytes()
    if hashlib.sha256(schema).hexdigest() != SCHEMA_SHA256:
        raise ValueError("pinned headscale-go v0.29.5 schema fixture changed")

    source_uri = f"{source_path.resolve().as_uri()}?mode=ro"
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_path.parent
    )
    os.close(fd)
    temporary = Path(temporary_name)
    try:
        with closing(sqlite3.connect(source_uri, uri=True)) as source, closing(sqlite3.connect(temporary)) as target:
            source.execute("BEGIN")
            version = source.execute(
                "SELECT version FROM database_versions WHERE id = 1"
            ).fetchone()
            if version is None or version[0] not in SOURCE_VERSIONS:
                raise ValueError(
                    f"expected Rust-managed source stamped {SOURCE_VERSIONS}, got {version}"
                )
            reserved = {*TABLES, "database_versions", "migrations", "_sqlx_migrations"}
            for (table,) in source.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            ):
                if table in reserved:
                    continue
                quoted = '"' + table.replace('"', '""') + '"'
                if source.execute(f"SELECT 1 FROM {quoted} LIMIT 1").fetchone():
                    raise ValueError(
                        f"cannot export populated Rust-only table {table}; "
                        "the Go schema cannot preserve its rows"
                    )
            target.executescript(schema.decode("utf-8"))
            target.execute("PRAGMA foreign_keys = ON")
            counts: dict[str, int] = {}
            for table in TABLES:
                source_columns = set(columns(source, table))
                target_columns = columns(target, table)
                if not target_columns or not set(target_columns).issubset(source_columns):
                    missing = sorted(set(target_columns) - source_columns)
                    raise ValueError(f"source {table} is missing Go columns: {missing}")
                field_list = ", ".join(f'"{field}"' for field in target_columns)
                placeholders = ", ".join("?" for _ in target_columns)
                query = f'SELECT {field_list} FROM "{table}" ORDER BY id'
                insert = f'INSERT INTO "{table}" ({field_list}) VALUES ({placeholders})'
                cursor = source.execute(query)
                count = 0
                while rows := cursor.fetchmany(500):
                    target.executemany(insert, rows)
                    count += len(rows)
                counts[table] = count

            target.executemany(
                "INSERT INTO migrations(id) VALUES (?)", ((item,) for item in MIGRATIONS)
            )
            target.execute(
                "INSERT INTO database_versions(id, version, updated_at) VALUES (1, ?, ?)",
                ("v0.29.5", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
            )
            violations = target.execute("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise ValueError(f"export has foreign-key violations: {violations[:5]}")
            integrity = target.execute("PRAGMA integrity_check").fetchone()
            if integrity != ("ok",):
                raise ValueError(f"export failed integrity check: {integrity}")
            target.commit()
            source.rollback()
        os.link(temporary, output_path)
        return counts
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="existing Rust-managed SQLite database")
    parser.add_argument("output", type=Path, help="new Go-compatible SQLite copy")
    args = parser.parse_args()
    counts = export(args.source, args.output)
    print(json.dumps({"output": str(args.output), "version": "v0.29.5", "rows": counts}))


if __name__ == "__main__":
    main()
