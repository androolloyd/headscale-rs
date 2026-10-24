#!/usr/bin/env python3
"""Pair Go/Rust production Postgres API-key authorization and restart behavior."""

import json
import os
from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
WORKDIR = Path(os.environ.get(
    "REAL_CLIENT_WORKDIR",
    f"target/real-client/postgres-api-key-session-{int(time.time())}-{os.getpid()}",
))
if not WORKDIR.is_absolute():
    WORKDIR = ROOT / WORKDIR
GO_BIN = Path(os.environ.get("HEADSCALE_GO_BIN", ""))
RUST_BIN = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale"))
POSTGRES_URL = os.environ.get("HEADSCALE_DB_POSTGRES_TEST_URL", "")


def command(*args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"{args} exited {result.returncode}: {result.stderr[-2000:]}")
    return result.stdout


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(port, route, secret=None, method="GET", body=None):
    headers = {}
    if secret:
        headers["Authorization"] = f"Bearer {secret}"
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = Request(f"http://127.0.0.1:{port}{route}",
                  data=json.dumps(body).encode() if body is not None else None,
                  headers=headers, method=method)
    try:
        with urlopen(req, timeout=5) as response:
            return response.status, response.read().decode()
    except HTTPError as error:
        return error.code, error.read().decode()


def wait_health(port, process):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited {process.returncode} before health")
        try:
            if request(port, "/health")[0] == 200:
                return
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError("server health")


@contextmanager
def serve(case, binary, port, phase):
    with (case / f"{phase}.stdout").open("w") as stdout, \
         (case / f"{phase}.stderr").open("w") as stderr:
        process = subprocess.Popen(
            [str(binary), "--config", str(case / "config.yaml"), "serve"],
            cwd=ROOT, stdout=stdout, stderr=stderr,
        )
        try:
            wait_health(port, process)
            yield
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def config(case, name, port):
    parsed = urlparse(POSTGRES_URL)
    if not parsed.hostname or not parsed.username:
        raise ValueError("HEADSCALE_DB_POSTGRES_TEST_URL needs TCP host and user")
    q = json.dumps
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
unix_socket: {q(f'/tmp/hs-apikey-session-{os.getpid()}-{name}.sock')}
noise:
  private_key_path: {q(str(case / 'noise.key'))}
prefixes:
  v4: 100.64.0.0/10
dns:
  magic_dns: false
  base_domain: tail.test
  override_local_dns: false
log:
  level: error
derp:
  server:
    enabled: false
  urls: []
  paths: [{q(str(case / 'derp.yaml'))}]
  auto_update_enabled: false
policy:
  mode: database
database:
  type: postgres
  postgres:
    host: {q(parsed.hostname)}
    port: {parsed.port or 5432}
    name: {q(name)}
    user: {q(unquote(parsed.username))}
    pass: {q(unquote(parsed.password or ''))}
    ssl: {q(parse_qs(parsed.query).get('sslmode', ['false'])[0])}
""")


def assert_status(port, secret, expected):
    status, body = request(port, "/api/v1/health", secret)
    if status != expected:
        raise AssertionError(f"API key health: expected {expected}, got {status}: {body}")
    if expected == 200 and json.loads(body).get("databaseConnectivity") is not True:
        raise AssertionError(f"API key did not reach database: {body}")
    if expected == 401 and body != "Unauthorized":
        raise AssertionError(f"unexpected unauthorized body: {body!r}")
    return {"status": status, "body": body}


def run_case(implementation, binary):
    case = WORKDIR / implementation
    case.mkdir(parents=True)
    name = f"hs_apikey_sess_{os.getpid()}_{implementation}"
    command("psql", POSTGRES_URL, "-X", "-c", f'CREATE DATABASE "{name}"')
    port = free_port()
    config(case, name, port)
    cli = [str(binary), "--config", str(case / "config.yaml")]
    result = {"implementation": implementation}
    try:
        with serve(case, binary, port, "first"):
            bootstrap = json.loads(command(*cli, "-o", "json", "apikeys", "create",
                                           "--expiration", "1h"))
            if not bootstrap.startswith("hskey-api-"):
                raise AssertionError("unexpected bootstrap key")
            status, body = request(port, "/api/v1/apikey", bootstrap, "POST",
                                   {"expiration": "2030-01-02T03:04:05Z"})
            if status != 200:
                raise AssertionError(f"create via gateway: {status} {body}")
            secondary = json.loads(body)["apiKey"]
            if not secondary.startswith("hskey-api-"):
                raise AssertionError("unexpected secondary key")
            result["secondary_before_expire"] = assert_status(port, secondary, 200)
            status, body = request(port, "/api/v1/apikey", bootstrap)
            if status != 200:
                raise AssertionError(f"list via gateway: {status} {body}")
            keys = json.loads(body)["apiKeys"]
            secondary_id = next((row["id"] for row in keys if row["id"] != "1"), None)
            if secondary_id is None:
                raise AssertionError(f"secondary key missing: {body}")
            status, body = request(port, "/api/v1/apikey/expire", bootstrap, "POST",
                                   {"id": secondary_id})
            if status != 200 or json.loads(body) != {}:
                raise AssertionError(f"expire via gateway: {status} {body}")
            result["secondary_after_expire"] = assert_status(port, secondary, 401)
            result["bootstrap_before_restart"] = assert_status(port, bootstrap, 200)
        with serve(case, binary, port, "restart"):
            result["secondary_after_restart"] = assert_status(port, secondary, 401)
            result["bootstrap_after_restart"] = assert_status(port, bootstrap, 200)
        (case / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        command("psql", POSTGRES_URL, "-X", "-c", f'DROP DATABASE "{name}"')
        Path(f"/tmp/hs-apikey-session-{os.getpid()}-{name}.sock").unlink(missing_ok=True)


def main():
    if not GO_BIN.is_file() or not RUST_BIN.is_file() or not POSTGRES_URL:
        raise ValueError("set HEADSCALE_GO_BIN, RUST_HEADSCALE_BIN, and HEADSCALE_DB_POSTGRES_TEST_URL")
    version = command(str(GO_BIN), "version").strip()
    if "v0.29.5" not in version:
        raise RuntimeError(f"expected pinned Go v0.29.5: {version}")
    WORKDIR.mkdir(parents=True, exist_ok=True)
    results = [run_case("go", GO_BIN), run_case("rust", RUST_BIN)]
    # The key bytes differ, but every observable authorization transition must agree.
    for field in ("secondary_before_expire", "secondary_after_expire",
                  "secondary_after_restart", "bootstrap_before_restart",
                  "bootstrap_after_restart"):
        if results[0][field] != results[1][field]:
            raise AssertionError(f"Go/Rust gateway response differs for {field}")
    report = {"go_version": version, "database": "postgres", "results": results}
    path = WORKDIR / "report.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"paired Postgres API-key session/restart passed: {path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"Postgres API-key session smoke failed: {error}", file=sys.stderr)
        sys.exit(1)
