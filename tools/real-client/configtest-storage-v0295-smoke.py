#!/usr/bin/env python3
"""Check pinned Go and Rust configtest storage effects and Go reopening Rust files."""

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
GO_BIN = Path(os.environ.get("HEADSCALE_GO_BIN", "")).resolve()
RUST_BIN = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale")).resolve()
WORKDIR = Path(os.environ.get(
    "REAL_CLIENT_WORKDIR",
    f"target/real-client/configtest-storage-v0295-{int(time.time())}-{os.getpid()}",
))
if not WORKDIR.is_absolute():
    WORKDIR = ROOT / WORKDIR
ENV = {key: value for key, value in os.environ.items() if not key.startswith("HEADSCALE_")}


def run(binary, config_path, command):
    result = subprocess.run(
        [str(binary), "--config", str(config_path), command],
        cwd=config_path.parent, env=ENV, text=True, capture_output=True, timeout=20,
    )
    if result.returncode:
        raise RuntimeError(f"{binary.name} {command}: {result.returncode}\n{result.stderr}")
    return {"status": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def prepare(name):
    directory = WORKDIR / name
    directory.mkdir(parents=True)
    config_path = directory / "config.json"
    config_path.write_text(json.dumps({
        "server_url": "http://127.0.0.1:8080",
        "listen_addr": "127.0.0.1:8080",
        "noise": {"private_key_path": "noise_private.key"},
        "prefixes": {"v4": "100.64.0.0/10"},
        "dns": {"magic_dns": False, "override_local_dns": False},
        "database": {"type": "sqlite", "sqlite": {"path": "db.sqlite"}},
        "log": {"level": "error"},
        "derp": {"server": {"enabled": False}, "urls": [], "paths": [],
                 "auto_update_enabled": False},
    }, indent=2) + "\n")
    return config_path


def inspect(directory):
    key = (directory / "noise_private.key").read_text().strip()
    if not key.startswith("privkey:") or len(key) != 72:
        raise AssertionError("Noise key is not in Go MachinePrivate format")
    with sqlite3.connect(f"file:{directory / 'db.sqlite'}?mode=ro", uri=True) as db:
        tables = sorted(row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ))
        versions = list(db.execute("SELECT version FROM database_versions ORDER BY id"))
    if not {"users", "nodes", "pre_auth_keys", "api_keys", "database_versions"} <= set(tables):
        raise AssertionError(f"missing Go primary tables: {tables}")
    return {"key_format": "privkey", "tables": tables, "versions": versions}


def main():
    if not GO_BIN.is_file() or not RUST_BIN.is_file():
        raise FileNotFoundError("set HEADSCALE_GO_BIN and build RUST_HEADSCALE_BIN")
    version = subprocess.run([str(GO_BIN), "version"], capture_output=True, text=True,
                             timeout=10, check=True).stdout
    if "v0.29.5" not in version:
        raise RuntimeError(f"expected pinned Go v0.29.5, got {version!r}")
    WORKDIR.mkdir(parents=True, exist_ok=True)
    go_config = prepare("go")
    rust_config = prepare("rust")
    go_result = run(GO_BIN, go_config, "configtest")
    rust_result = run(RUST_BIN, rust_config, "configtest")
    go_storage = inspect(go_config.parent)
    rust_storage = inspect(rust_config.parent)
    if go_storage["tables"] != rust_storage["tables"]:
        raise AssertionError("Go primary table names differ")
    key_before = (rust_config.parent / "noise_private.key").read_bytes()
    rust_db_before = rust_storage["versions"]
    go_reopen = run(GO_BIN, rust_config, "configtest")
    if (rust_config.parent / "noise_private.key").read_bytes() != key_before:
        raise AssertionError("Go changed Rust's Noise key")
    if inspect(rust_config.parent)["versions"] != rust_db_before:
        raise AssertionError("Go changed Rust's migration versions")
    report = {"go_version": version.strip(), "go": go_result, "rust": rust_result,
              "go_storage": go_storage, "rust_storage": rust_storage,
              "go_reopen_rust": go_reopen}
    report_path = WORKDIR / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"paired configtest storage and Go reopen passed: {report_path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"configtest storage smoke failed: {exc}", file=sys.stderr)
        sys.exit(1)
