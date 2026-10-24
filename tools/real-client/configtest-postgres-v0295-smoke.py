#!/usr/bin/env python3
"""Pair default-build Rust and pinned Go v0.29.5 Postgres configtest effects."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote, urlparse, urlunparse


ROOT = Path(__file__).resolve().parents[2]
GO_BIN = Path(os.environ.get("HEADSCALE_GO_BIN", "")).resolve()
RUST_BIN = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale")).resolve()
POSTGRES_URL = os.environ.get("HEADSCALE_DB_POSTGRES_TEST_URL", "")
WORKDIR = Path(os.environ.get(
    "REAL_CLIENT_WORKDIR",
    f"target/real-client/configtest-postgres-v0295-{int(time.time())}-{os.getpid()}",
))
if not WORKDIR.is_absolute():
    WORKDIR = ROOT / WORKDIR
ENV = {key: value for key, value in os.environ.items() if not key.startswith("HEADSCALE_")}


def command(*args, cwd=ROOT, env=None):
    result = subprocess.run(args, cwd=cwd, env=env, text=True,
                            capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} exited {result.returncode}: {result.stderr[-3000:]}")
    return result.stdout


def db_url(name):
    parsed = urlparse(POSTGRES_URL)
    return urlunparse(parsed._replace(path=f"/{name}"))


def query(name, sql):
    return command("psql", "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1",
                   db_url(name), "-c", sql).strip().splitlines()


def config(name, parsed):
    directory = WORKDIR / name
    directory.mkdir(parents=True)
    database_name = f"hs_cfgtest_{os.getpid()}_{name}"
    path = directory / "config.json"
    path.write_text(json.dumps({
        "server_url": "http://127.0.0.1:8080",
        "listen_addr": "127.0.0.1:8080",
        "noise": {"private_key_path": str(directory / "noise_private.key")},
        "prefixes": {"v4": "100.64.0.0/10"},
        "dns": {"magic_dns": False, "override_local_dns": False},
        "database": {"type": "postgres", "postgres": {
            "host": parsed.hostname, "port": parsed.port or 5432,
            "name": database_name, "user": unquote(parsed.username),
            "pass": unquote(parsed.password or ""),
            "ssl": parse_qs(parsed.query).get("sslmode", ["false"])[0],
        }},
        "log": {"level": "error"},
        "derp": {"server": {"enabled": False}, "urls": [], "paths": [],
                 "auto_update_enabled": False},
    }, indent=2) + "\n")
    command("psql", "-X", "-v", "ON_ERROR_STOP=1", POSTGRES_URL,
            "-c", f'CREATE DATABASE "{database_name}"')
    return database_name, path


def inspect(name, path):
    key = (path.parent / "noise_private.key").read_text().strip()
    if not key.startswith("privkey:") or len(key) != 72:
        raise AssertionError(f"invalid Go-format Noise key for {name}")
    tables = query(name, "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")
    core_tables = sorted(set(tables) - {"migrations", "_sqlx_migrations"})
    if not {"users", "nodes", "pre_auth_keys", "api_keys", "database_versions"} <= set(tables):
        raise AssertionError(f"missing Go primary tables for {name}: {tables}")
    versions = query(name, "SELECT version FROM database_versions ORDER BY id")
    if "v0.29.5" not in versions:
        raise AssertionError(f"missing v0.29.5 marker for {name}: {versions}")
    application_tables = "'users','nodes','pre_auth_keys','api_keys','policies','database_versions'"
    columns = query(name, f"""
        SELECT table_name || '.' || column_name || '|' || data_type || '|' ||
               is_nullable || '|' || COALESCE(column_default, '')
        FROM information_schema.columns
        WHERE table_schema='public' AND table_name IN ({application_tables})
        ORDER BY table_name, ordinal_position
    """)
    indexes = query(name, f"""
        SELECT tablename || '.' || indexname || '|' || indexdef
        FROM pg_indexes WHERE schemaname='public' AND tablename IN ({application_tables})
        ORDER BY tablename, indexname
    """)
    constraints = query(name, f"""
        SELECT conrelid::regclass::text || '.' || conname || '|' || pg_get_constraintdef(oid)
        FROM pg_constraint WHERE conrelid::regclass::text IN ({application_tables})
        ORDER BY conrelid::regclass::text, conname
    """)
    migration_ids = query(name, "SELECT id FROM migrations ORDER BY id") if "migrations" in tables else []
    return {"key_format": "privkey", "tables": tables,
            "core_tables": core_tables, "versions": versions,
            "columns": columns, "indexes": indexes, "constraints": constraints,
            "migration_ids": migration_ids}


def main():
    parsed = urlparse(POSTGRES_URL)
    if not parsed.hostname or not parsed.username:
        raise ValueError("set HEADSCALE_DB_POSTGRES_TEST_URL to a local TCP Postgres URL")
    if not GO_BIN.is_file() or not RUST_BIN.is_file():
        raise FileNotFoundError("set HEADSCALE_GO_BIN and build default RUST_HEADSCALE_BIN")
    go_version = command(str(GO_BIN), "version")
    if "v0.29.5" not in go_version:
        raise RuntimeError(f"expected pinned headscale-go v0.29.5, got {go_version!r}")
    WORKDIR.mkdir(parents=True, exist_ok=True)
    cases = {}
    try:
        for name, binary in (("go", GO_BIN), ("rust", RUST_BIN)):
            database_name, path = config(name, parsed)
            cases[name] = {"database": database_name, "config": path}
            command(str(binary), "--config", str(path), "configtest", cwd=path.parent, env=ENV)
            cases[name]["storage"] = inspect(database_name, path)
        if cases["go"]["storage"]["core_tables"] != cases["rust"]["storage"]["core_tables"]:
            raise AssertionError(
                "Go/Rust Postgres application tables differ: "
                f"Go={cases['go']['storage']['core_tables']}, "
                f"Rust={cases['rust']['storage']['core_tables']}"
            )
        for field in ("columns", "migration_ids"):
            go_values = set(cases["go"]["storage"][field])
            rust_values = set(cases["rust"]["storage"][field])
            if go_values != rust_values:
                raise AssertionError(
                    f"fresh Go/Rust Postgres {field} differ: "
                    f"Go only={sorted(go_values - rust_values)}, "
                    f"Rust only={sorted(rust_values - go_values)}"
                )
        rust_name = cases["rust"]["database"]
        rust_path = cases["rust"]["config"]
        before = cases["rust"]["storage"]
        rust_key_before = (rust_path.parent / "noise_private.key").read_bytes()
        command(str(GO_BIN), "--config", str(rust_path), "configtest",
                cwd=rust_path.parent, env=ENV)
        after = inspect(rust_name, rust_path)
        if (before["core_tables"] != after["core_tables"]
                or before["versions"] != after["versions"]
                or any(set(before[field]) != set(after[field])
                       for field in ("columns", "indexes", "constraints", "migration_ids"))
                or (rust_path.parent / "noise_private.key").read_bytes() != rust_key_before):
            raise AssertionError("pinned Go changed Rust's Noise key or application schema")
        if "migrations" not in after["tables"]:
            raise AssertionError("pinned Go did not establish its migration ledger")
        report = {"go_version": go_version.strip(), "go": cases["go"]["storage"],
                  "rust": before, "go_reopen_rust": after}
        report["schema_differences_before_go_reopen"] = {
            field: {"go_only": sorted(set(report["go"][field]) - set(before[field])),
                    "rust_only": sorted(set(before[field]) - set(report["go"][field]))}
            for field in ("columns", "indexes", "constraints")
        }
        report["schema_differences_after_go_reopen"] = {
            field: {"go_only": sorted(set(report["go"][field]) - set(after[field])),
                    "rust_only": sorted(set(after[field]) - set(report["go"][field]))}
            for field in ("columns", "indexes", "constraints", "migration_ids")
        }
        report_path = WORKDIR / "report.json"
        report_path.write_text(json.dumps(report, indent=2) + "\n")
        print(f"paired default-build Postgres configtest and Go reopen passed: {report_path}")
    finally:
        for case in cases.values():
            command("psql", "-X", "-v", "ON_ERROR_STOP=1", POSTGRES_URL,
                    "-c", f'DROP DATABASE IF EXISTS "{case["database"]}" WITH (FORCE)')


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Postgres configtest smoke failed: {error}", file=sys.stderr)
        sys.exit(1)
