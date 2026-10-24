#!/usr/bin/env python3
"""Compare pinned headscale-go v0.29.5 and Rust configtest process results."""

import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
GO_BIN = Path(os.environ.get("HEADSCALE_GO_BIN", "")).resolve()
RUST_BIN = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale")).resolve()
WORKDIR = Path(os.environ.get(
    "REAL_CLIENT_WORKDIR",
    f"target/real-client/configtest-v0295-diff-{int(time.time())}-{os.getpid()}",
))
if not WORKDIR.is_absolute():
    WORKDIR = ROOT / WORKDIR
ENV = {key: value for key, value in os.environ.items() if not key.startswith("HEADSCALE_")}
LOG_TIMESTAMP = re.compile(r"\b\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[+-]\d\d:\d\d\b")


def run(binary, args, cwd):
    result = subprocess.run([str(binary), *args], cwd=cwd, env=ENV,
                            text=True, capture_output=True, timeout=15)
    return {"status": result.returncode, "stdout": result.stdout, "stderr": result.stderr}


def comparable(result):
    return {**result, "stderr": LOG_TIMESTAMP.sub("<timestamp>", result["stderr"])}


def cases(baseline):
    yield "baseline", baseline
    edits = (
        ("no-prefixes", "prefixes", None),
        ("empty-prefixes", "prefixes", {}),
        ("empty-v4", "prefixes", {"v4": ""}),
        ("v6-only", "prefixes", {"v6": "fd7a:115c:a1e0::/48"}),
        ("both-prefixes", "prefixes", {"v4": "100.64.0.0/10", "v6": "fd7a:115c:a1e0::/48"}),
        ("bad-v4", "prefixes", {"v4": "not-a-prefix"}),
        ("bad-v6", "prefixes", {"v6": "not-a-prefix"}),
        ("bad-v4-address", "prefixes", {"v4": "bad/24"}),
        ("bad-v4-bits", "prefixes", {"v4": "100.64.0.0/abc"}),
        ("out-of-range-v4", "prefixes", {"v4": "100.64.0.0/40"}),
        ("empty-server-url", "server_url", ""),
        ("bad-server-url", "server_url", "not-a-url"),
        ("bad-listen", "listen_addr", "not-a-socket"),
        ("bad-grpc-listen", "grpc_listen_addr", "not-a-socket"),
        ("bad-metrics-listen", "metrics_listen_addr", "not-a-socket"),
        ("missing-noise", "noise", None),
        ("empty-noise", "noise", {"private_key_path": ""}),
        ("no-dns", "dns", None),
        ("magic-dns-no-domain", "dns", {"magic_dns": True, "override_local_dns": False}),
        ("override-no-nameservers", "dns", {"magic_dns": False, "override_local_dns": True}),
        ("bad-db-type", "database", {"type": "mysql"}),
        ("bad-policy-mode", "policy", {"mode": "consul"}),
        ("bad-tls-challenge", "tls_letsencrypt_challenge_type", "DNS-01"),
        ("bad-log-level", "log", {"level": "verbose"}),
        ("unsafe-proxy", "trusted_proxies", ["0.0.0.0/0"]),
        ("bad-ephemeral-timeout", "ephemeral_node_inactivity_timeout", "1s"),
        ("bad-node-ephemeral-timeout", "node", {"ephemeral": {"inactivity_timeout": "1s"}}),
        ("bad-oidc-issuer", "oidc", {"issuer": "invalid", "client_id": "test", "client_secret": "secret"}),
        ("bad-derp-url", "derp", {"urls": ["not-a-url"], "paths": [], "auto_update_enabled": False}),
    )
    for name, key, value in edits:
        config = copy.deepcopy(baseline)
        if value is None:
            config.pop(key, None)
        else:
            config[key] = value
        yield name, config


def main():
    if not GO_BIN.is_file():
        raise FileNotFoundError("set HEADSCALE_GO_BIN to pinned v0.29.5 executable")
    if not RUST_BIN.is_file():
        raise FileNotFoundError(f"Rust executable missing: {RUST_BIN}")
    version = run(GO_BIN, ["version"], ROOT)
    if version["status"] or "v0.29.5" not in version["stdout"]:
        raise RuntimeError(f"expected pinned headscale-go v0.29.5: {version}")
    WORKDIR.mkdir(parents=True, exist_ok=True)
    baseline = {
        "server_url": "http://127.0.0.1:8080",
        "listen_addr": "127.0.0.1:8080",
        "noise": {"private_key_path": "noise_private.key"},
        "prefixes": {"v4": "100.64.0.0/10"},
        "dns": {"magic_dns": False, "override_local_dns": False},
        "database": {"type": "sqlite", "sqlite": {"path": "db.sqlite"}},
        "log": {"level": "error"},
        "derp": {"server": {"enabled": False}, "urls": [], "paths": [],
                 "auto_update_enabled": False},
    }
    rows = []
    for name, config in cases(baseline):
        case_dir = WORKDIR / name
        case_dir.mkdir()
        config_path = case_dir / "config.json"
        config_path.write_text(json.dumps(config, indent=2) + "\n")
        args = ["--config", str(config_path), "configtest"]
        go = run(GO_BIN, args, case_dir)
        rust = run(RUST_BIN, args, case_dir)
        rows.append({"case": name, "match": comparable(go) == comparable(rust),
                     "go": go, "rust": rust})
    report = {"go_version": version["stdout"].strip(), "normalization": "log timestamps",
              "comparisons": len(rows),
              "mismatches": sum(not row["match"] for row in rows), "rows": rows}
    report_path = WORKDIR / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(rows)} configtest comparisons, {report['mismatches']} mismatches: {report_path}")
    for row in rows:
        if not row["match"]:
            print(f"mismatch: {row['case']}", file=sys.stderr)
    if report["mismatches"]:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"configtest diff failed: {error}", file=sys.stderr)
        sys.exit(1)
