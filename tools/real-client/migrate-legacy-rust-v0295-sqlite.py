#!/usr/bin/env python3
"""Migrate a current legacy Rust SQLite database into a Go-exact primary/sidecar pair.

The source is read under one SQLite snapshot and never modified. The output is
a new directory containing headscale.sqlite and headscale.sqlite.rust-aux.sqlite.
The directory is published only after both databases pass integrity checks.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timezone


SCHEMA_DIR = Path(__file__).resolve().parents[2] / "headscale-db/schema"
GO_SCHEMA = SCHEMA_DIR / "headscale-go-v0295.sql"
AUX_SCHEMA = SCHEMA_DIR / "rust-aux.sql"
GO_SCHEMA_SHA256 = "7db8001facc5a0508748e0470504c7df06e2c9e66f7facf11bc202b88d78e70b"
GO_MIGRATIONS = (
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
SHARED = ("users", "pre_auth_keys", "api_keys", "nodes", "policies")
AUXILIARY = (
    "octra_nodes", "transactions", "account_balances", "resources",
    "resource_usage", "sessions",
)
SOURCE_METADATA = {"database_versions", "migrations", "_sqlx_migrations"}
KNOWN_LEGACY_INDEXES = {
    "idx_api_keys_expiration", "idx_api_keys_prefix",
    "idx_name_no_provider_identifier", "idx_name_provider_identifier",
    "idx_nodes_auth_key_id", "idx_nodes_deleted_at", "idx_nodes_given_name",
    "idx_nodes_ipv4", "idx_nodes_ipv6", "idx_nodes_user_id",
    "idx_octra_nodes_capabilities", "idx_octra_nodes_online",
    "idx_octra_nodes_wg_pubkey", "idx_policies_deleted_at",
    "idx_pre_auth_keys_expiration", "idx_pre_auth_keys_prefix",
    "idx_pre_auth_keys_user_id", "idx_provider_identifier",
    "idx_resources_provider", "idx_resources_type", "idx_sessions_did",
    "idx_sessions_expiry", "idx_transactions_from", "idx_transactions_timestamp",
    "idx_transactions_to", "idx_transactions_type", "idx_usage_active",
    "idx_usage_consumer", "idx_usage_provider", "idx_users_deleted_at",
}
LATEST_RUST_MIGRATION = 20261016000019


def columns(db: sqlite3.Connection, table: str, schema: str = "main") -> tuple[str, ...]:
    return tuple(row[1] for row in db.execute(f"PRAGMA {schema}.table_info({table})"))


def copy_table(source: sqlite3.Connection, target: sqlite3.Connection,
               table: str, target_schema: str) -> int:
    source_columns = set(columns(source, table))
    destination_columns = columns(target, table, target_schema)
    missing = sorted(set(destination_columns) - source_columns)
    extra = sorted(source_columns - set(destination_columns))
    if not destination_columns or missing or extra:
        raise ValueError(
            f"legacy {table} column mismatch: missing={missing}, extra={extra}"
        )
    names = ", ".join(f'"{field}"' for field in destination_columns)
    placeholders = ", ".join("?" for _ in destination_columns)
    selection = source.execute(f'SELECT {names} FROM "{table}" ORDER BY rowid')
    insertion = f'INSERT INTO {target_schema}."{table}" ({names}) VALUES ({placeholders})'
    count = 0
    while rows := selection.fetchmany(500):
        target.executemany(insertion, rows)
        count += len(rows)
    return count


def validate_source(source: sqlite3.Connection) -> None:
    version = source.execute(
        "SELECT version FROM database_versions WHERE id = 1"
    ).fetchone()
    if version != ("v0.29.0-beta.2",):
        raise ValueError(f"expected legacy Rust v0.29.0-beta.2 database, got {version}")
    latest = source.execute(
        "SELECT MAX(version) FROM _sqlx_migrations WHERE success = 1"
    ).fetchone()[0]
    if latest != LATEST_RUST_MIGRATION:
        raise ValueError(
            f"legacy Rust database must finish migration {LATEST_RUST_MIGRATION}; got {latest}"
        )
    failed = source.execute(
        "SELECT COUNT(*) FROM _sqlx_migrations WHERE success != 1"
    ).fetchone()[0]
    if failed:
        raise ValueError(f"legacy Rust database has {failed} failed SQLx migrations")
    tables = {
        row[0] for row in source.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    missing = (set(SHARED) | set(AUXILIARY)) - tables
    unknown = tables - set(SHARED) - set(AUXILIARY) - SOURCE_METADATA
    if missing or unknown:
        raise ValueError(f"unsupported legacy tables: missing={sorted(missing)}, extra={sorted(unknown)}")
    schema_objects = {
        (kind, name) for kind, name in source.execute(
            "SELECT type, name FROM sqlite_master WHERE type IN ('view', 'trigger')"
        )
    }
    unknown_objects = schema_objects - {("trigger", "cleanup_expired_sessions")}
    if unknown_objects:
        raise ValueError(f"unsupported legacy views/triggers: {sorted(unknown_objects)}")
    indexes = {
        row[0] for row in source.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"
        )
    }
    unknown_indexes = indexes - KNOWN_LEGACY_INDEXES
    if unknown_indexes:
        raise ValueError(f"unsupported legacy indexes: {sorted(unknown_indexes)}")
    violations = source.execute("PRAGMA foreign_key_check").fetchall()
    if violations:
        raise ValueError(f"legacy source has foreign-key violations: {violations[:5]}")


def migrate(source_path: Path, output_dir: Path) -> dict[str, int]:
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if output_dir.exists():
        raise FileExistsError(f"refusing to replace existing output: {output_dir}")
    if not output_dir.parent.is_dir():
        raise FileNotFoundError(output_dir.parent)
    go_schema = GO_SCHEMA.read_bytes()
    if hashlib.sha256(go_schema).hexdigest() != GO_SCHEMA_SHA256:
        raise ValueError("pinned headscale-go v0.29.5 schema fixture changed")
    stage = Path(tempfile.mkdtemp(prefix=f".{output_dir.name}.", dir=output_dir.parent))
    try:
        primary = stage / "headscale.sqlite"
        auxiliary = stage / "headscale.sqlite.rust-aux.sqlite"
        source_uri = f"{source_path.resolve().as_uri()}?mode=ro"
        with closing(sqlite3.connect(source_uri, uri=True)) as source, closing(sqlite3.connect(primary)) as target:
            source.execute("BEGIN")
            validate_source(source)
            target.execute("ATTACH DATABASE ? AS rust_aux", (str(auxiliary),))
            target.executescript(go_schema.decode("utf-8"))
            target.executescript(AUX_SCHEMA.read_text())
            # Copy every legacy session, including expired rows. Recreate the
            # trigger only after data transfer so migration is lossless.
            target.execute("DROP TRIGGER rust_aux.cleanup_expired_sessions")
            target.execute("PRAGMA foreign_keys = ON")

            counts = {}
            for table in (*SHARED, *AUXILIARY):
                schema = "main" if table in SHARED else "rust_aux"
                counts[table] = copy_table(source, target, table, schema)

            # AUTOINCREMENT must never reuse an ID that was allocated and
            # subsequently deleted in the legacy database.
            for table, sequence in source.execute(
                "SELECT name, seq FROM sqlite_sequence"
            ):
                if table not in counts:
                    continue
                schema = "main" if table in SHARED else "rust_aux"
                updated = target.execute(
                    f"UPDATE {schema}.sqlite_sequence SET seq = MAX(seq, ?) WHERE name = ?",
                    (sequence, table),
                ).rowcount
                if updated == 0:
                    target.execute(
                        f"INSERT INTO {schema}.sqlite_sequence(name, seq) VALUES (?, ?)",
                        (table, sequence),
                    )

            target.executemany(
                "INSERT INTO migrations(id) VALUES (?)",
                ((migration,) for migration in GO_MIGRATIONS),
            )
            target.execute(
                "INSERT INTO database_versions(id, version, updated_at) VALUES (1, ?, ?)",
                ("v0.29.5", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")),
            )
            target.execute("""
                CREATE TRIGGER rust_aux.cleanup_expired_sessions
                AFTER INSERT ON sessions
                BEGIN
                    DELETE FROM sessions WHERE expires_at < unixepoch();
                END
            """)
            violations = target.execute("PRAGMA foreign_key_check").fetchall()
            if violations:
                raise ValueError(f"migrated primary has foreign-key violations: {violations[:5]}")
            for schema in ("main", "rust_aux"):
                integrity = target.execute(f"PRAGMA {schema}.integrity_check").fetchone()
                if integrity != ("ok",):
                    raise ValueError(f"{schema} integrity check failed: {integrity}")
            target.commit()
            source.rollback()
        os.chmod(stage, 0o700)
        os.rename(stage, output_dir)
        return counts
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="fully migrated legacy Rust SQLite file")
    parser.add_argument("output_dir", type=Path, help="new directory for primary and sidecar")
    args = parser.parse_args()
    counts = migrate(args.source, args.output_dir)
    print(json.dumps({
        "primary": str(args.output_dir / "headscale.sqlite"),
        "sidecar": str(args.output_dir / "headscale.sqlite.rust-aux.sqlite"),
        "rows": counts,
    }))


if __name__ == "__main__":
    main()
