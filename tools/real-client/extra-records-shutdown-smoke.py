#!/usr/bin/env python3
"""Compare pinned Go and Rust shutdown after a watched DNS file disappears."""

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[2]
WORKDIR = Path(os.environ.get(
    "REAL_CLIENT_WORKDIR",
    f"target/real-client/extra-records-shutdown-{int(time.time())}-{os.getpid()}",
))
if not WORKDIR.is_absolute():
    WORKDIR = ROOT / WORKDIR
WORKDIR.mkdir(parents=True, exist_ok=True)
GO_BIN = Path(os.environ.get("HEADSCALE_GO_BIN", ""))
RUST_BIN = ROOT / "target/debug/headscale"
DATABASE_MODE = os.environ.get("EXTRA_RECORDS_DATABASE", "sqlite")
POSTGRES_URL = os.environ.get("HEADSCALE_DB_POSTGRES_TEST_URL", "")


def run(*args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"{args} failed: {result.stderr[-4000:]}")
    return result.stdout


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_health(port, process):
    url = f"http://127.0.0.1:{port}/health"
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited {process.returncode} before {url}")
        try:
            with urlopen(url, timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError(url)


def wait_for_deleted_file_watcher(implementation, stdout_path, process):
    """Ensure the Rust poller has actually taken its removed-file branch."""
    if implementation == "go":
        # Go's fsnotify manager has no default-level event log. Give its
        # delete event and retry loop time to run before shutdown.
        time.sleep(2)
        return
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited {process.returncode} after file deletion")
        if "extra-records file disappeared; keeping previous set" in stdout_path.read_text():
            return
        time.sleep(0.1)
    raise TimeoutError("Rust watcher did not observe deleted extra-records file")


def database_config(case, name):
    if DATABASE_MODE == "sqlite":
        return f"database:\n  type: sqlite\n  sqlite:\n    path: {json.dumps(str(case / 'db.sqlite'))}\n"
    parsed = urlparse(POSTGRES_URL)
    if not parsed.hostname or not parsed.username:
        raise ValueError("Postgres mode needs HEADSCALE_DB_POSTGRES_TEST_URL")
    return f"""database:
  type: postgres
  postgres:
    host: {json.dumps(parsed.hostname)}
    port: {parsed.port or 5432}
    name: {json.dumps(name)}
    user: {json.dumps(unquote(parsed.username))}
    pass: {json.dumps(unquote(parsed.password or ''))}
    ssl: {json.dumps(parse_qs(parsed.query).get('sslmode', ['false'])[0])}
"""


def write_config(case, implementation, name):
    q = json.dumps
    port = free_port()
    socket_path = f"/tmp/hs-extra-shutdown-{os.getpid()}-{implementation}.sock"
    records = case / "extra-records.json"
    records.write_text(q([{"Name": "MiXeD.Tail.Test", "Type": "A", "Value": "100.64.0.50"}]))
    (case / "policy.hujson").write_text(q({
        "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
    }))
    (case / "derp.yaml").write_text("""regions:
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
""")
    (case / "config.yaml").write_text(f"""
server_url: {q(f'http://127.0.0.1:{port}')}
listen_addr: {q(f'127.0.0.1:{port}')}
unix_socket: {q(socket_path)}
private_key_path: {q(str(case / 'private.key'))}
noise:
  private_key_path: {q(str(case / 'noise.key'))}
prefixes:
  allocation: sequential
  v4: 100.64.0.0/10
dns:
  magic_dns: true
  base_domain: tail.test
  override_local_dns: false
  extra_records_path: {q(str(records))}
logtail:
  enabled: false
derp:
  server:
    enabled: false
  urls: []
  paths:
    - {q(str(case / 'derp.yaml'))}
  auto_update_enabled: false
policy:
  mode: file
  path: {q(str(case / 'policy.hujson'))}
{database_config(case, name)}
""")
    return port, socket_path, records


def case_run(implementation, name):
    case = WORKDIR / implementation
    case.mkdir(exist_ok=True)
    port, socket_path, records = write_config(case, implementation, name)
    binary = GO_BIN if implementation == "go" else RUST_BIN
    with (case / "serve.stdout").open("w") as stdout, (case / "serve.stderr").open("w") as stderr:
        process = subprocess.Popen(
            [str(binary), "--config", str(case / "config.yaml"), "serve"],
            cwd=ROOT, stdout=stdout, stderr=stderr,
        )
        try:
            wait_health(port, process)
            records.unlink()
            wait_for_deleted_file_watcher(implementation, case / "serve.stdout", process)
            wait_health(port, process)
            began = time.monotonic()
            process.terminate()
            try:
                exit_code = process.wait(timeout=8)
            except subprocess.TimeoutExpired as error:
                raise TimeoutError(f"{implementation} hung after watched file removal") from error
            result = {
                "implementation": implementation,
                "exit_code": exit_code,
                "shutdown_seconds": round(time.monotonic() - began, 3),
                "file_deleted": not records.exists(),
            }
            (case / "result.json").write_text(json.dumps(result, indent=2) + "\n")
            return result
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            Path(socket_path).unlink(missing_ok=True)


def main():
    if DATABASE_MODE not in ("sqlite", "postgres"):
        raise ValueError("EXTRA_RECORDS_DATABASE must be sqlite or postgres")
    if not GO_BIN.is_file():
        raise FileNotFoundError(f"set HEADSCALE_GO_BIN to pinned v0.29.5 binary: {GO_BIN}")
    go_version = run(str(GO_BIN), "version").strip()
    if "v0.29.5" not in go_version:
        raise RuntimeError(f"expected pinned Go v0.29.5: {go_version}")
    build = ["cargo", "build", "-p", "headscale-cli", "--bin", "headscale"]
    if DATABASE_MODE == "postgres":
        build.extend(["--features", "postgres-sqlx"])
    run(*build)
    results = []
    for implementation in ("go", "rust"):
        name = None
        if DATABASE_MODE == "postgres":
            name = f"hs_extra_shutdown_{os.getpid()}_{implementation}"
            run("psql", POSTGRES_URL, "-X", "-c", f'CREATE DATABASE "{name}"')
        try:
            results.append(case_run(implementation, name))
        finally:
            if name:
                run("psql", POSTGRES_URL, "-X", "-c", f'DROP DATABASE "{name}"')
    summary = {"go_version": go_version, "database": DATABASE_MODE, "results": results}
    (WORKDIR / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(WORKDIR)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"extra-records shutdown smoke failed: {error}", file=sys.stderr)
        sys.exit(1)
