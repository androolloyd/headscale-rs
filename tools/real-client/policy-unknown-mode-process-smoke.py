#!/usr/bin/env python3
"""Paired v0.29.5/Rust startup and admin behavior for unknown policy.mode."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import URLError
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[2]
GO_BIN = Path(os.environ.get("HEADSCALE_GO_BIN", "")).resolve()
RUST_BIN = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale")).resolve()
WORKDIR = Path(os.environ.get(
    "REAL_CLIENT_WORKDIR",
    f"target/real-client/policy-unknown-mode-{int(time.time())}-{os.getpid()}",
))
if not WORKDIR.is_absolute():
    WORKDIR = ROOT / WORKDIR
ENV = {key: value for key, value in os.environ.items() if not key.startswith("HEADSCALE_")}
DERP = """regions:
  900:
    regionid: 900
    regioncode: smoke
    regionname: Smoke Test
    nodes:
      - name: 900a
        regionid: 900
        hostname: derp.invalid
        ipv4: 198.51.100.1
        stunport: 0
        stunonly: false
        derpport: 443
"""


def reserve_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def run(binary, args, cwd):
    completed = subprocess.run([str(binary), *args], cwd=cwd, env=ENV,
                               text=True, capture_output=True, timeout=8)
    return {"status": completed.returncode, "stdout": completed.stdout,
            "stderr": completed.stderr}


def run_server(name, binary):
    directory = WORKDIR / name
    directory.mkdir(parents=True)
    (directory / "derp.yaml").write_text(DERP)
    http_port, metrics_port, grpc_port = (reserve_port() for _ in range(3))
    socket_path = Path("/tmp") / f"hs-pol-{os.getpid()}-{name}.sock"
    config = {
        "server_url": f"http://127.0.0.1:{http_port}",
        "listen_addr": f"127.0.0.1:{http_port}",
        "metrics_listen_addr": f"127.0.0.1:{metrics_port}",
        "grpc_listen_addr": f"127.0.0.1:{grpc_port}",
        "grpc_allow_insecure": True,
        "unix_socket": str(socket_path),
        "noise": {"private_key_path": str(directory / "noise.key")},
        "prefixes": {"v4": "100.64.0.0/10"},
        "dns": {"magic_dns": False, "override_local_dns": False},
        "database": {"type": "sqlite", "sqlite": {"path": str(directory / "db.sqlite")}},
        "policy": {"mode": "consul"},
        "derp": {"server": {"enabled": False}, "urls": [],
                 "paths": [str(directory / "derp.yaml")], "auto_update_enabled": False},
        "log": {"level": "error"},
    }
    config_path = directory / "config.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    stdout_path, stderr_path = directory / "serve.stdout", directory / "serve.stderr"
    with stdout_path.open("w") as stdout, stderr_path.open("w") as stderr:
        process = subprocess.Popen([str(binary), "--config", str(config_path), "serve"],
                                   cwd=directory, env=ENV, stdout=stdout, stderr=stderr)
        healthy = False
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with urlopen(f"http://127.0.0.1:{http_port}/health", timeout=.2) as response:
                        healthy = response.status == 200
                        if healthy:
                            break
                except (OSError, URLError):
                    time.sleep(.05)
            if not healthy:
                raise RuntimeError(f"{name} never served /health; see {stderr_path}")
            get = run(binary, ["--config", str(config_path), "policy", "get"], directory)
            set_result = run(binary, ["--config", str(config_path), "policy", "set",
                                      "--file", str(config_path)], directory)
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            socket_path.unlink(missing_ok=True)
    return {"healthy": healthy, "serve_exit": process.returncode,
            "noise_key_created": (directory / "noise.key").is_file(),
            "database_created": (directory / "db.sqlite").is_file(),
            "get_policy": get, "set_policy": set_result,
            "serve_stderr": stderr_path.read_text()}


def main():
    if not GO_BIN.is_file() or not RUST_BIN.is_file():
        raise FileNotFoundError("set HEADSCALE_GO_BIN and build target/debug/headscale")
    version = run(GO_BIN, ["version"], ROOT)
    if version["status"] or "v0.29.5" not in version["stdout"]:
        raise RuntimeError(f"expected pinned v0.29.5: {version}")
    WORKDIR.mkdir(parents=True)
    rows = {name: run_server(name, binary) for name, binary in
            (("go", GO_BIN), ("rust", RUST_BIN))}
    report = {"go_version": version["stdout"].strip(), "rows": rows}
    report_path = WORKDIR / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(report_path)
    for name, row in rows.items():
        if not (row["healthy"] and row["serve_exit"] == 0
                and row["noise_key_created"] and row["database_created"]
                and row["get_policy"]["status"] == 1
                and 'policy.mode: "consul"' in row["get_policy"]["stderr"]
                and row["set_policy"]["status"] == 1
                and "update is disabled" in row["set_policy"]["stderr"]):
            raise AssertionError(f"{name} failed unknown policy-mode behavior: {row}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, AssertionError, subprocess.TimeoutExpired) as error:
        print(f"unknown policy-mode smoke failed: {error}", file=sys.stderr)
        sys.exit(1)
