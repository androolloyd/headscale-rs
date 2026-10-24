#!/usr/bin/env python3
"""Paired production policy metadata load, validation, and restart check."""

import json
import os
from contextlib import contextmanager
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
    f"target/real-client/policy-metadata-{int(time.time())}-{os.getpid()}",
))
if not WORKDIR.is_absolute():
    WORKDIR = ROOT / WORKDIR
WORKDIR.mkdir(parents=True, exist_ok=True)
GO_BIN = Path(os.environ.get("HEADSCALE_GO_BIN", ""))
RUST_BIN = ROOT / "target/debug/headscale"
DATABASE_MODE = os.environ.get("POLICY_METADATA_DATABASE", "sqlite")
POSTGRES_URL = os.environ.get("HEADSCALE_DB_POSTGRES_TEST_URL", "")
SCENARIO = ROOT / "tools/parity/scenarios/policy-v0294-metadata-fields.json"


def command(*args, expect_success=True):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if expect_success and result.returncode:
        raise RuntimeError(f"{args} exited {result.returncode}: {result.stdout[-2000:]} {result.stderr[-2000:]}")
    return result


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_health(port, process):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited {process.returncode} before health")
        try:
            with urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError("server health")


def database_config(case, name):
    q = json.dumps
    if DATABASE_MODE == "sqlite":
        return f"database:\n  type: sqlite\n  sqlite:\n    path: {q(str(case / 'db.sqlite'))}\n"
    parsed = urlparse(POSTGRES_URL)
    if not parsed.hostname or not parsed.username:
        raise ValueError("Postgres mode needs HEADSCALE_DB_POSTGRES_TEST_URL")
    return f"""database:
  type: postgres
  postgres:
    host: {q(parsed.hostname)}
    port: {parsed.port or 5432}
    name: {q(name)}
    user: {q(unquote(parsed.username))}
    pass: {q(unquote(parsed.password or ''))}
    ssl: {q(parse_qs(parsed.query).get('sslmode', ['false'])[0])}
"""


def make_config(case, implementation, name):
    q = json.dumps
    port = free_port()
    socket_path = f"/tmp/hs-policy-metadata-{os.getpid()}-{implementation}.sock"
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
  magic_dns: false
  base_domain: tail.test
  override_local_dns: false
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
  mode: database
{database_config(case, name)}
""")
    scenario = json.loads(SCENARIO.read_text())
    policy = scenario["policy"]
    (case / "policy.hujson").write_text(q(policy, indent=2) + "\n")
    bad_policy = dict(policy)
    bad_policy["unknown_metadata_without_hash"] = True
    (case / "invalid-policy.hujson").write_text(q(bad_policy, indent=2) + "\n")
    return port, socket_path


@contextmanager
def serve(case, binary, port, phase):
    with (case / f"{phase}.stdout").open("w") as stdout, (case / f"{phase}.stderr").open("w") as stderr:
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


def case_run(implementation, name):
    case = WORKDIR / implementation
    case.mkdir(exist_ok=True)
    port, socket_path = make_config(case, implementation, name)
    binary = GO_BIN if implementation == "go" else RUST_BIN
    cli = [str(binary), "--config", str(case / "config.yaml")]
    try:
        with serve(case, binary, port, "first"):
            command(*cli, "users", "create", "alice")
            checked = command(*cli, "policy", "check", "--file", str(case / "policy.hujson"))
            (case / "policy-check.stdout").write_text(checked.stdout)
            command(*cli, "policy", "set", "--file", str(case / "policy.hujson"))
            got = command(*cli, "policy", "get").stdout
            (case / "policy-get.stdout").write_text(got)
            if "#ha-meta" not in got or "#note" not in got:
                raise AssertionError(f"{implementation} lost stored policy metadata")
            bad = command(*cli, "policy", "check", "--file", str(case / "invalid-policy.hujson"), expect_success=False)
            (case / "invalid-policy.stderr").write_text(bad.stderr)
            if bad.returncode == 0 or "unknown" not in (bad.stdout + bad.stderr).lower():
                raise AssertionError(f"{implementation} accepted an unprefixed unknown field: {bad}")
        with serve(case, binary, port, "restart"):
            got_after = command(*cli, "policy", "get").stdout
            (case / "policy-get-after-restart.stdout").write_text(got_after)
            if got_after != got:
                raise AssertionError(f"{implementation} changed policy bytes across restart")
        result = {"implementation": implementation, "valid_metadata": True,
                  "unknown_field_rejected": True, "policy_persisted": True}
        (case / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        Path(socket_path).unlink(missing_ok=True)


def main():
    if DATABASE_MODE not in ("sqlite", "postgres"):
        raise ValueError("POLICY_METADATA_DATABASE must be sqlite or postgres")
    if not GO_BIN.is_file():
        raise FileNotFoundError("set HEADSCALE_GO_BIN to pinned v0.29.5 binary")
    version = command(str(GO_BIN), "version").stdout
    if "v0.29.5" not in version:
        raise RuntimeError(f"expected pinned Go v0.29.5: {version}")
    build = ["cargo", "build", "-p", "headscale-cli", "--bin", "headscale"]
    if DATABASE_MODE == "postgres":
        build.extend(["--features", "postgres-sqlx"])
    command(*build)
    results = []
    for implementation in ("go", "rust"):
        name = None
        if DATABASE_MODE == "postgres":
            name = f"hs_policy_meta_{os.getpid()}_{implementation}"
            command("psql", POSTGRES_URL, "-X", "-c", f'CREATE DATABASE "{name}"')
        try:
            results.append(case_run(implementation, name))
        finally:
            if name:
                command("psql", POSTGRES_URL, "-X", "-c", f'DROP DATABASE "{name}"')
    summary = {"go_version": version.strip(), "database": DATABASE_MODE, "results": results}
    (WORKDIR / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(WORKDIR)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"policy metadata process smoke failed: {error}", file=sys.stderr)
        sys.exit(1)
