#!/usr/bin/env python3
"""Compare pinned-Go and Rust tagged preauth reauthentication over TS2021."""

import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[2]
WORKDIR = Path(os.environ.get(
    "REAL_CLIENT_WORKDIR", f"target/real-client/noise-tagged-retag-{int(time.time())}-{os.getpid()}"
))
if not WORKDIR.is_absolute():
    WORKDIR = ROOT / WORKDIR
WORKDIR.mkdir(parents=True, exist_ok=True)
RUST_BIN = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale"))
GO_BIN = Path(os.environ.get("HEADSCALE_GO_BIN", ""))
HELPER = WORKDIR / "noise-tagged-retag-helper"
DATABASE_MODE = os.environ.get("NOISE_TAGGED_DATABASE", "sqlite")
POSTGRES_TEST_URL = os.environ.get("HEADSCALE_DB_POSTGRES_TEST_URL", "")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(*args, cwd=ROOT):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(f"{' '.join(map(str, args))} failed: {result.stderr[-4000:]}")
    return result.stdout


def wait_http(url, process):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"server exited {process.returncode} before {url}")
        try:
            with urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return
        except OSError:
            pass
        time.sleep(0.1)
    raise TimeoutError(url)


def postgres_config(name):
    parsed = urlparse(POSTGRES_TEST_URL)
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


def make_config(case, port, database_name):
    q = json.dumps
    socket_path = f"/tmp/hs-noise-retag-{os.getpid()}-{case.name}.sock"
    database = (postgres_config(database_name) if database_name else f"""database:
  type: sqlite
  sqlite:
    path: {q(str(case / 'db.sqlite'))}
""")
    (case / "policy.hujson").write_text(json.dumps({
        "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
        "tagOwners": {
            "tag:server": ["alice@"], "tag:database": ["alice@"], "tag:manual": ["alice@"]
        },
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
  mode: file
  path: {q(str(case / 'policy.hujson'))}
{database}
""")
    return socket_path


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def leaf_paths(value, prefix=""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from leaf_paths(item, f"{prefix}.{key}")
    elif isinstance(value, list):
        if not value:
            yield prefix
        for index, item in enumerate(value):
            yield from leaf_paths(item, f"{prefix}[{index}]")
    else:
        yield prefix


def database_node(case, database_name):
    if database_name:
        database_url = urlparse(POSTGRES_TEST_URL)._replace(path=f"/{database_name}").geturl()
        raw = run("psql", database_url, "-X", "-A", "-t", "-F", "\t",
                  "-c", "SELECT id, COALESCE(user_id::text, 'NULL'), auth_key_id, tags, disco_key FROM nodes")
        fields = raw.strip().split("\t")
        assert len(fields) == 5, raw
        return {"id": int(fields[0]), "user_id": None if fields[1] == "NULL" else int(fields[1]),
                "auth_key_id": None if fields[2] == "" else int(fields[2]),
                "tags": json.loads(fields[3]), "disco_key": fields[4]}
    with sqlite3.connect(case / "db.sqlite") as connection:
        rows = connection.execute(
            "SELECT id, user_id, auth_key_id, tags, disco_key FROM nodes"
        ).fetchall()
    assert len(rows) == 1, rows
    node_id, user_id, auth_key_id, tags, disco_key = rows[0]
    return {"id": node_id, "user_id": user_id, "auth_key_id": auth_key_id,
            "tags": json.loads(tags), "disco_key": disco_key}


def case_run(implementation, database_name):
    case = WORKDIR / implementation
    case.mkdir(exist_ok=True)
    port = free_port()
    socket_path = make_config(case, port, database_name)
    binary = RUST_BIN if implementation == "rust" else GO_BIN
    with (case / "serve.stdout").open("w") as stdout, (case / "serve.stderr").open("w") as stderr:
        server = subprocess.Popen(
            [str(binary), "--config", str(case / "config.yaml"), "serve"],
            cwd=ROOT, stdout=stdout, stderr=stderr,
        )
        try:
            base = f"http://127.0.0.1:{port}"
            wait_http(f"{base}/health", server)
            config_args = [str(binary), "--config", str(case / "config.yaml"), "-o", "json"]
            user = json.loads(run(*config_args, "users", "create", "alice"))
            user_id = user["id"]
            keys = []
            for tag in ("tag:server", "tag:database"):
                key = json.loads(run(*config_args, "preauthkeys", "create", "--user",
                                     str(user_id), "--reusable", "--tags", tag))
                keys.append(key["key"])
            state = case / "state.json"
            responses = []
            snapshots = []
            database_snapshots = []
            for stage, mode, key in (
                ("initial", "authkey-initial", keys[0]),
                ("same-key", "authkey-retag", keys[0]),
                ("new-key", "authkey-retag", keys[1]),
            ):
                output = case / f"{stage}.json"
                run(str(HELPER), "-mode", mode, "-url", base, "-state", str(state),
                    "-output", str(output), "-authkey", key)
                responses.append(json.loads(output.read_text()))
                nodes = json.loads(run(*config_args, "nodes", "list"))
                snapshots.append(nodes)
                (case / f"{stage}-nodes.json").write_text(json.dumps(nodes, indent=2))
                database_snapshots.append(database_node(case, database_name))
                if stage == "initial":
                    run(*config_args, "nodes", "tag", "--identifier", str(nodes[0]["id"]),
                        "--tags", "tag:manual")
                    manual = json.loads(run(*config_args, "nodes", "list"))
                    assert manual[0]["tags"] == ["tag:manual"], manual
            for stage, request_tags in (("interactive-readvertise", "tag:database"),
                                        ("interactive-untag", "")):
                output = case / f"{stage}.json"
                run(str(HELPER), "-mode", "interactive-reauth", "-url", base,
                    "-state", str(state), "-output", str(output),
                    "-request-tags", request_tags)
                auth_url = json.loads(state.read_text())["auth_url"]
                auth_id = urlparse(auth_url).path.rsplit("/", 1)[-1]
                assert auth_id.startswith("hskey-authreq-"), auth_url
                with (case / f"{stage}-followup.stdout").open("w") as stdout, \
                     (case / f"{stage}-followup.stderr").open("w") as stderr:
                    followup = subprocess.Popen(
                        [str(HELPER), "-mode", "followup", "-url", base,
                         "-state", str(state), "-output", str(output)],
                        cwd=ROOT, stdout=stdout, stderr=stderr,
                    )
                    try:
                        time.sleep(0.2)
                        run(*config_args, "auth", "register", "--user", "alice",
                            "--auth-id", auth_id)
                        if followup.wait(timeout=15):
                            raise RuntimeError(f"{stage} followup failed: {stderr.name}")
                    finally:
                        stop_process(followup)
                responses.append(json.loads(output.read_text()))
                nodes = json.loads(run(*config_args, "nodes", "list"))
                snapshots.append(nodes)
                (case / f"{stage}-nodes.json").write_text(json.dumps(nodes, indent=2))
                database_snapshots.append(database_node(case, database_name))
            expiry = "2100-01-01T00:00:00.123456789Z"
            node_id = str(snapshots[-1][0]["id"])
            run(*config_args, "nodes", "expire", "--identifier", node_id, "--expiry", expiry)
            expired_nodes = json.loads(run(*config_args, "nodes", "list"))
            (case / "scheduled-expiry-nodes.json").write_text(
                json.dumps(expired_nodes, indent=2))
            stop_process(server)
            with (case / "restart.stdout").open("w") as restart_stdout, \
                 (case / "restart.stderr").open("w") as restart_stderr:
                server = subprocess.Popen(
                    [str(binary), "--config", str(case / "config.yaml"), "serve"],
                    cwd=ROOT, stdout=restart_stdout, stderr=restart_stderr,
                )
                wait_http(f"{base}/health", server)
                restarted_nodes = json.loads(run(*config_args, "nodes", "list"))
                (case / "restart-nodes.json").write_text(
                    json.dumps(restarted_nodes, indent=2))
            return (responses, snapshots, database_snapshots, int(user_id),
                    expired_nodes, restarted_nodes)
        finally:
            stop_process(server)
            Path(socket_path).unlink(missing_ok=True)


def main():
    if DATABASE_MODE not in ("sqlite", "postgres"):
        raise ValueError(f"unsupported NOISE_TAGGED_DATABASE: {DATABASE_MODE}")
    if not GO_BIN.is_file() or "v0.29.5" not in run(str(GO_BIN), "version"):
        raise ValueError("HEADSCALE_GO_BIN must point to a pinned v0.29.5 executable")
    build = ["cargo", "build", "-p", "headscale-cli", "--bin", "headscale"]
    if DATABASE_MODE == "postgres":
        build.extend(["--features", "postgres-sqlx"])
    run(*build)
    run("go", "build", "-o", str(HELPER), "./noise-followup",
        cwd=ROOT / "tools/parity/headscale-go")

    results = {}
    for implementation in ("rust", "go"):
        database_name = None
        try:
            if DATABASE_MODE == "postgres":
                database_name = f"hs_retag_{int(time.time())}_{os.getpid()}_{implementation}"
                run("psql", POSTGRES_TEST_URL, "-X", "-v", "ON_ERROR_STOP=1",
                    "-c", f"CREATE DATABASE {database_name}")
            results[implementation] = case_run(implementation, database_name)
        finally:
            if database_name:
                run("psql", POSTGRES_TEST_URL, "-X", "-v", "ON_ERROR_STOP=1",
                    "-c", f"DROP DATABASE {database_name} WITH (FORCE)")

    for implementation, (responses, snapshots, database_snapshots, user_id,
                         expired_nodes, restarted_nodes) in results.items():
        assert all(result["status"] == 200 and json.loads(result["body"])["MachineAuthorized"]
                   for result in responses), responses
        assert all(len(snapshot) == 1 for snapshot in snapshots), snapshots
        zero_disco_key = "discokey:" + "0" * 64
        assert all(snapshot[0].get("disco_key") == zero_disco_key
                   for snapshot in snapshots), snapshots
        assert all(row["disco_key"] == zero_disco_key
                   for row in database_snapshots), database_snapshots
        assert all(snapshot[0]["user"]["created_at"]["seconds"] == -62135596800
                   for snapshot in snapshots[:4]), snapshots
        before, same_key, after, readvertised, personal = (snapshot[0] for snapshot in snapshots)
        assert before["id"] == same_key["id"] == after["id"], snapshots
        assert before["ip_addresses"] == same_key["ip_addresses"] == after["ip_addresses"], snapshots
        assert before["tags"] == ["tag:server"], before
        assert same_key["tags"] == ["tag:manual"], same_key
        assert after["tags"] == ["tag:database"], after
        assert len({before["node_key"], same_key["node_key"], after["node_key"]}) == 3, snapshots
        assert all(row["id"] == before["id"] and row["user_id"] is None
                   for row in database_snapshots[:3]), database_snapshots
        assert [row["tags"] for row in database_snapshots[:3]] == [
            ["tag:server"], ["tag:manual"], ["tag:database"]
        ], database_snapshots
        assert database_snapshots[0]["auth_key_id"] == database_snapshots[1]["auth_key_id"], database_snapshots
        assert database_snapshots[1]["auth_key_id"] != database_snapshots[2]["auth_key_id"], database_snapshots
        assert before["id"] == readvertised["id"] == personal["id"], snapshots
        assert before["ip_addresses"] == readvertised["ip_addresses"] == personal["ip_addresses"], snapshots
        assert len({node["node_key"] for node in (before, same_key, after, readvertised, personal)}) == 5, snapshots
        assert readvertised["tags"] == ["tag:database"], readvertised
        assert readvertised["user"]["name"] == "tagged-devices", readvertised
        assert personal.get("tags", []) == [], personal
        assert personal["user"]["name"] == "alice", personal
        assert database_snapshots[3]["id"] == database_snapshots[4]["id"] == before["id"]
        assert database_snapshots[3]["user_id"] is None, database_snapshots
        assert database_snapshots[3]["auth_key_id"] == database_snapshots[2]["auth_key_id"], database_snapshots
        assert database_snapshots[4]["user_id"] == user_id, database_snapshots
        assert database_snapshots[4]["auth_key_id"] is None, database_snapshots
        immediate_expiry = {"seconds": 4_102_444_800, "nanos": 123_456_789}
        persisted_nanos = 123_456_789 if DATABASE_MODE == "sqlite" else 123_456_000
        persisted_expiry = {"seconds": 4_102_444_800, "nanos": persisted_nanos}
        assert expired_nodes[0]["expiry"] == immediate_expiry, (implementation, expired_nodes)
        assert restarted_nodes[0]["expiry"] == persisted_expiry, (
            implementation, restarted_nodes)
        assert restarted_nodes[0]["id"] == personal["id"]
        assert restarted_nodes[0]["ip_addresses"] == personal["ip_addresses"]
    stages = ("initial", "same-key", "new-key", "interactive-readvertise", "interactive-untag",
              "scheduled-expiry", "restart-expiry")
    shape_report = {}
    for index, stage in enumerate(stages):
        if index < 5:
            go_node = results["go"][1][index][0]
            rust_node = results["rust"][1][index][0]
        else:
            position = 4 if index == 5 else 5
            go_node = results["go"][position][0]
            rust_node = results["rust"][position][0]
        go_paths = set(leaf_paths(go_node))
        rust_paths = set(leaf_paths(rust_node))
        go_only = sorted(go_paths - rust_paths)
        rust_only = sorted(rust_paths - go_paths)
        assert not go_only and not rust_only, (stage, go_only, rust_only)
        shape_report[stage] = {"go_only": go_only, "rust_only": rust_only}
    (WORKDIR / "cli-node-json-shape-diff.json").write_text(json.dumps(shape_report, indent=2))
    print(f"paired Rust and pinned-Go tagged reauth passed ({DATABASE_MODE}): {WORKDIR}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"tagged reauth smoke failed: {error}", file=sys.stderr)
        sys.exit(1)
