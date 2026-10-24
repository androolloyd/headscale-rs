#!/usr/bin/env python3
"""Upgrade a real Go v0.28 Postgres schema with zero-time expiry under Go/Rust."""

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
    f"target/real-client/postgres-v028-zero-time-{int(time.time())}-{os.getpid()}",
))
if not WORKDIR.is_absolute():
    WORKDIR = ROOT / WORKDIR
GO_V028 = Path(os.environ.get("HEADSCALE_GO_V028_BIN", ""))
GO_V0295 = Path(os.environ.get("HEADSCALE_GO_BIN", ""))
RUST = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale"))
ADMIN_URL = os.environ.get("HEADSCALE_DB_POSTGRES_TEST_URL", "")


def command(*args):
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f"{args} exited {result.returncode}: {result.stderr[-2000:]}")
    return result.stdout


def psql(database, sql):
    parsed = urlparse(ADMIN_URL)
    url = parsed._replace(path=f"/{database}").geturl()
    return command("psql", url, "-X", "-At", "-v", "ON_ERROR_STOP=1", "-c", sql)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def config(directory, name, port, socket_path):
    parsed = urlparse(ADMIN_URL)
    q = json.dumps
    (directory / "config.yaml").write_text(f"""
server_url: {q(f'http://127.0.0.1:{port}')}
listen_addr: {q(f'127.0.0.1:{port}')}
unix_socket: {q(socket_path)}
noise:
  private_key_path: {q(str(WORKDIR / 'noise.key'))}
prefixes:
  allocation: sequential
  v4: 100.64.0.0/10
dns:
  magic_dns: false
  base_domain: tail.test
  override_local_dns: false
log:
  level: info
derp:
  server:
    enabled: false
  urls: []
  paths: [{q(str(WORKDIR / 'derp.yaml'))}]
  auto_update_enabled: false
policy:
  mode: database
database:
  type: postgres
  postgres:
    host: {q(parsed.hostname)}
    port: {parsed.port or 5432}
    name: {q(name)}
    user: {q(unquote(parsed.username or ''))}
    pass: {q(unquote(parsed.password or ''))}
    ssl: {q(parse_qs(parsed.query).get('sslmode', ['false'])[0])}
""")


def wait_health(port, process):
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited {process.returncode}")
        try:
            with urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError("server health")


@contextmanager
def serve(binary, label, config_path, port):
    with (WORKDIR / f"{label}.stdout").open("w") as stdout, \
         (WORKDIR / f"{label}.stderr").open("w") as stderr:
        process = subprocess.Popen([str(binary), "--config", str(config_path), "serve"],
                                   cwd=ROOT, stdout=stdout, stderr=stderr)
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


def seed_nodes(database):
    psql(database, "INSERT INTO users (id,name,display_name,created_at,updated_at) "
         "VALUES (10,'alice','Alice',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
    columns = set(psql(database, "SELECT column_name FROM information_schema.columns "
                       "WHERE table_name='nodes'").splitlines())
    tag_column = "tags" if "tags" in columns else "forced_tags"
    assert tag_column in columns and "expiry" in columns, columns
    for node_id, expiry in ((1, "0001-01-01 00:00:00+00"),
                            (2, "2099-01-01 00:00:00+00"),
                            (3, "2020-01-01 00:00:00+00")):
        psql(database, f"""INSERT INTO nodes
          (id,machine_key,node_key,disco_key,endpoints,host_info,ipv4,ipv6,
           hostname,given_name,user_id,register_method,{tag_column},expiry,
           approved_routes,created_at,updated_at)
          VALUES ({node_id},
            'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e0{node_id}',
            'nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c160550{node_id}',
            'discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf5770{node_id}',
            '[]','{{}}','100.64.0.{node_id}','fd7a:115c:a1e0::{node_id}',
            'node{node_id}','node{node_id}',10,'cli','[]','{expiry}',
            '[]',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)""")


def snapshot(database):
    has_versions = psql(database, "SELECT COUNT(*) FROM information_schema.tables "
                        "WHERE table_schema='public' AND table_name='database_versions'").strip() == "1"
    version = psql(database, "SELECT version FROM database_versions WHERE id=1").strip() if has_versions else None
    marker = psql(database, "SELECT COUNT(*) FROM migrations WHERE "
                  "id='202605221435-clear-zero-time-node-expiry'").strip()
    raw_values = psql(database, "SELECT json_agg(row_to_json(n)) FROM "
                      "(SELECT id,user_id,EXTRACT(YEAR FROM expiry AT TIME ZONE 'UTC')::int AS expiry_year "
                      "FROM nodes ORDER BY id) n").strip()
    values = json.loads(raw_values) if raw_values else []
    return {"version": version, "zero_time_marker_count": int(marker), "nodes": values}


def main():
    if not all(path.is_file() for path in (GO_V028, GO_V0295, RUST)) or not ADMIN_URL:
        raise ValueError("set HEADSCALE_GO_V028_BIN, HEADSCALE_GO_BIN, RUST_HEADSCALE_BIN, and HEADSCALE_DB_POSTGRES_TEST_URL")
    if "v0.28.0" not in command(str(GO_V028), "version"):
        raise RuntimeError("expected pinned Go v0.28.0")
    if "v0.29.5" not in command(str(GO_V0295), "version"):
        raise RuntimeError("expected pinned Go v0.29.5")
    WORKDIR.mkdir(parents=True, exist_ok=True)
    (WORKDIR / "derp.yaml").write_text("""regions:
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
    base = f"hs_zero28_{os.getpid()}"
    names = [f"{base}_template", f"{base}_go", f"{base}_rust"]
    created = []
    port = free_port()
    socket_path = f"/tmp/hs-zero28-{os.getpid()}.sock"
    configs = {}
    try:
        for name in names[:1]:
            psql("postgres", f'CREATE DATABASE "{name}"')
            created.append(name)
        template_config = WORKDIR / "template"
        template_config.mkdir()
        config(template_config, names[0], port, socket_path)
        with serve(GO_V028, "go-v028-template", template_config / "config.yaml", port):
            pass
        before = snapshot(names[0])
        if before["version"] is not None or before["zero_time_marker_count"]:
            raise AssertionError(f"not an unmigrated v0.28.0 database: {before}")
        seed_nodes(names[0])
        source = snapshot(names[0])
        if source != {"version": None, "zero_time_marker_count": 0,
                      "nodes": [{"id": node_id, "user_id": 10, "expiry_year": year}
                                for node_id, year in ((1, 1), (2, 2099), (3, 2020))]}:
            raise AssertionError(f"unexpected Go v0.28 source rows: {source}")
        for name in names[1:]:
            psql("postgres", f'CREATE DATABASE "{name}" TEMPLATE "{names[0]}"')
            created.append(name)
            directory = WORKDIR / name
            directory.mkdir()
            config(directory, name, port, socket_path)
            configs[name] = directory / "config.yaml"
        phases = (("go-upgrade", GO_V0295, names[1]),
                  ("rust-upgrade", RUST, names[2]),
                  ("go-on-rust", GO_V0295, names[2]),
                  ("rust-on-go", RUST, names[1]))
        for label, binary, name in phases:
            with serve(binary, label, configs[name], port):
                command(str(binary), "--config", str(configs[name]), "-o", "json", "nodes", "list")
            state = snapshot(name)
            (WORKDIR / f"{label}-state.json").write_text(json.dumps(state, indent=2) + "\n")
            if state != {"version": "v0.29.5", "zero_time_marker_count": 1,
                          "nodes": [{"id": node_id, "user_id": 10, "expiry_year": year}
                                    for node_id, year in ((1, None), (2, 2099), (3, 2020))]}:
                raise AssertionError(f"{label} historical expiry mismatch: {state}")
        report = {"source": source, "phases": [label for label, _, _ in phases],
                  "upgraded": snapshot(names[1]), "cross_started": snapshot(names[2])}
        path = WORKDIR / "report.json"
        path.write_text(json.dumps(report, indent=2) + "\n")
        print(f"Go v0.28 zero-time Postgres upgrade and cross-start passed: {path}")
    finally:
        for name in reversed(created):
            psql("postgres", f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        Path(socket_path).unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        import traceback
        traceback.print_exc()
        print(f"Postgres v0.28 zero-time upgrade failed: {error}", file=sys.stderr)
        sys.exit(1)
