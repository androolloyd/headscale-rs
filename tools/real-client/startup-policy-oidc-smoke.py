#!/usr/bin/env python3
"""Pair production Go/Rust startup, ambiguous user aliases, and OIDC discovery.

Policy errors are compared exactly. OIDC rows compare discovery, required vs
optional availability, and listener startup; provider error wording is retained
in the report but is not claimed to match.
"""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse, urlunparse
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
GO = Path(os.environ.get("HEADSCALE_GO_BIN", "")).resolve()
RUST = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale")).resolve()
PG = os.environ.get("HEADSCALE_DB_POSTGRES_TEST_URL", "")
BACKENDS = os.environ.get("STARTUP_DATABASES", "sqlite postgres").split()
WORK = Path(os.environ.get("REAL_CLIENT_WORKDIR", f"target/real-client/startup-policy-oidc-{int(time.time())}-{os.getpid()}")).resolve()
ENV = {k: v for k, v in os.environ.items() if not k.startswith("HEADSCALE_") and k != "RUST_LOG"}
BASE = '{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}'
AMBIGUOUS = '{"groups":{"group:admins":["yala@"]},"acls":[{"action":"accept","src":["group:admins"],"dst":["*:*"]}]}'
MISSING = AMBIGUOUS.replace("yala@", "missing@")
AMBIGUOUS_POLICIES = {
    "group": AMBIGUOUS,
    "tag-owner": '{"tagOwners":{"tag:test":["yala@"]}}',
    "auto-route": '{"autoApprovers":{"routes":{"10.0.0.0/24":["yala@"]}}}',
    "auto-exit": '{"autoApprovers":{"exitNode":["yala@"]}}',
    "acl-source": '{"acls":[{"action":"accept","src":["yala@"],"dst":["*:80"]}]}',
    "acl-destination": '{"acls":[{"action":"accept","src":["*"],"dst":["yala@:80"]}]}',
    "ssh-source": '{"ssh":[{"action":"accept","src":["yala@"],"dst":["autogroup:self"],"users":["root"]}]}',
    "ssh-destination": '{"ssh":[{"action":"accept","src":["yala@"],"dst":["yala@"],"users":["root"]}]}',
}


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def pg_command(url, sql):
    result = subprocess.run(["psql", url, "-X", "-A", "-t", "-v", "ON_ERROR_STOP=1"],
                            input=sql, text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError(f"Postgres fixture SQL failed: {result.stderr}")
    return result.stdout.strip()


def quote(value):
    return "'" + value.replace("'", "''") + "'"


@contextmanager
def storage(case, backend, name):
    if backend == "sqlite":
        path = case / "db.sqlite"
        def sql(query):
            with sqlite3.connect(path) as connection:
                cursor = connection.execute(query)
                value = cursor.fetchone() if cursor.description else None
                return value[0] if value else None
        yield {"type": "sqlite", "sqlite": {"path": str(path)}}, sql
        return
    if backend != "postgres" or not PG:
        raise ValueError("set HEADSCALE_DB_POSTGRES_TEST_URL for the postgres backend")
    parsed = urlparse(PG)
    pg_command(PG, f'CREATE DATABASE "{name}";')
    url = urlunparse(parsed._replace(path=f"/{name}"))
    try:
        yield {"type": "postgres", "postgres": {
            "host": parsed.hostname, "port": parsed.port or 5432, "name": name,
            "user": parsed.username, "pass": parsed.password or "", "ssl": False,
        }}, lambda query: pg_command(url, query)
    finally:
        pg_command(PG, f'DROP DATABASE "{name}" WITH (FORCE);')


def run(binary, config, args):
    result = subprocess.run([str(binary), "--config", str(config), *args], cwd=ROOT, env=ENV,
                            capture_output=True, timeout=15)
    return {"status": result.returncode, "stdout": result.stdout.decode(), "stderr": result.stderr.decode()}


def success(result):
    if result["status"]:
        raise AssertionError(result)


@contextmanager
def serve(binary, config, port, case, phase):
    with (case / f"{phase}.stdout").open("w") as out, (case / f"{phase}.stderr").open("w") as err:
        process = subprocess.Popen([str(binary), "--config", str(config), "serve"],
                                   cwd=ROOT, env=ENV, stdout=out, stderr=err)
        try:
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise AssertionError(f"server exited before health: {(case / f'{phase}.stderr').read_text()}")
                try:
                    with urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as response:
                        if response.status == 200:
                            break
                except OSError:
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError("control listener health")
                time.sleep(.05)
            yield
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    raise AssertionError("server did not shut down cleanly")


class Provider(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *_):
        pass

    def do_GET(self):
        Provider.requests.append(self.path)
        if self.path.startswith("/unavailable/"):
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b"provider unavailable")
            return
        issuer = f"http://127.0.0.1:{self.server.server_port}" + self.path.split("/.well-known/")[0]
        body = json.dumps({
            "issuer": issuer + ("/wrong" if self.path.startswith("/mismatch/") else ""),
            "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
            "jwks_uri": issuer + "/jwks", "response_types_supported": ["code"],
            "subject_types_supported": ["public"], "id_token_signing_alg_values_supported": ["RS256"],
            "code_challenge_methods_supported": ["S256"],
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


def run_case(implementation, binary, backend, provider_port):
    case = WORK / f"{backend}-{implementation}"
    case.mkdir()
    (case / "derp.yaml").write_text("""regions:
  900:
    regionid: 900
    regioncode: fixture
    regionname: Fixture
    nodes:
      - name: 900a
        regionid: 900
        hostname: derp.invalid
        ipv4: 198.51.100.1
        stunport: 0
        derpport: 443
""")
    port = free_port()
    config_path = case / "config.json"
    policy_path = case / "candidate.hujson"
    policy_path.write_text(AMBIGUOUS)
    outputs, oidc_rows, malformed_outputs = {}, [], {}
    with storage(case, backend, f"hs_startup_{os.getpid()}_{implementation}") as (database, sql):
        config = {
            "server_url": f"http://127.0.0.1:{port}", "listen_addr": f"127.0.0.1:{port}",
            "unix_socket": f"/tmp/hs-startup-{os.getpid()}-{backend}-{implementation}.sock",
            "noise": {"private_key_path": str(case / "noise.key")},
            "prefixes": {"v4": "100.64.0.0/10"},
            "dns": {"magic_dns": False, "override_local_dns": False},
            "log": {"level": "error"}, "policy": {"mode": "database"},
            "derp": {"server": {"enabled": False}, "urls": [], "paths": [str(case / "derp.yaml")], "auto_update_enabled": False},
            "database": database,
        }
        config_path.write_text(json.dumps(config))
        success(run(binary, config_path, ["configtest"]))
        sql("INSERT INTO users (id,name,email,provider_identifier,provider,created_at,updated_at) VALUES "
            "(2,'yala','',NULL,'','2025-01-02T03:04:05Z','2025-01-02T03:04:05Z'),"
            "(7,'yala','yala@yala.yala','https://idp.test/subject','oidc','2025-01-02T03:04:05Z','2025-01-02T03:04:05Z')")
        sql("INSERT INTO policies(data,created_at,updated_at) VALUES (" + quote(BASE) + ",'2025-01-02T03:04:05Z','2025-01-02T03:04:05Z')")
        with serve(binary, config_path, port, case, "policy-live"):
            for alias, text in AMBIGUOUS_POLICIES.items():
                policy_path.write_text(text)
                for command in ("check", "set"):
                    for fmt in ("human", "json", "json-line", "yaml"):
                        args = ([] if fmt == "human" else ["-o", fmt]) + ["policy", command, "--file", str(policy_path)]
                        result = run(binary, config_path, args)
                        assert result["status"] != 0 and "multiple users found" in result["stderr"], result
                        outputs[f"live-{alias}-{command}-{fmt}"] = result
                        assert sql("SELECT data FROM policies ORDER BY id DESC LIMIT 1") == BASE

        policy_path.write_text(AMBIGUOUS)
        sql("UPDATE policies SET data=" + quote(AMBIGUOUS))
        for command in ("configtest", "serve"):
            for fmt in ("human", "json", "json-line", "yaml"):
                args = ([] if fmt == "human" else ["-o", fmt]) + [command]
                result = run(binary, config_path, args)
                assert result["status"] != 0 and "multiple users found" in result["stderr"], result
                outputs[f"startup-{command}-{fmt}"] = result
        config["policy"] = {"mode": "file", "path": str(policy_path)}
        config_path.write_text(json.dumps(config))
        for command in ("configtest", "serve"):
            for fmt in ("human", "json", "json-line", "yaml"):
                args = ([] if fmt == "human" else ["-o", fmt]) + [command]
                result = run(binary, config_path, args)
                assert result["status"] != 0 and "multiple users found" in result["stderr"], result
                outputs[f"startup-file-{command}-{fmt}"] = result
        config["policy"] = {"mode": "database"}
        config_path.write_text(json.dumps(config))
        for command in ("check", "set"):
            for fmt in ("human", "json", "json-line", "yaml"):
                args = ([] if fmt == "human" else ["-o", fmt]) + ["--force", "policy", command, "--file", str(policy_path), "--bypass-grpc-and-access-database-directly"]
                result = run(binary, config_path, args)
                assert result["status"] != 0 and "multiple users found" in result["stderr"], result
                outputs[f"direct-{command}-{fmt}"] = result

        sql("UPDATE policies SET data='{broken'")
        for command in ("configtest", "serve"):
            result = run(binary, config_path, [command])
            assert result["status"] != 0 and "policy" in result["stderr"], result
            malformed_outputs[command] = result
        sql("UPDATE policies SET data=" + quote(AMBIGUOUS))

        # A provider identifier match takes precedence over both duplicate names.
        sql("UPDATE users SET provider_identifier='yala' WHERE id=7")
        success(run(binary, config_path, ["configtest"]))
        with serve(binary, config_path, port, case, "provider-priority"):
            for text, label in ((AMBIGUOUS, "provider-priority"), (MISSING, "missing-user")):
                policy_path.write_text(text)
                for command in ("check", "set"):
                    result = run(binary, config_path, ["policy", command, "--file", str(policy_path)])
                    success(result)
                    outputs[f"{label}-{command}"] = result

        # Admin display fallbacks must not turn an unnamed stored account into
        # a second policy match for another account's numeric login name.
        sql("UPDATE users SET name='',email='',provider_identifier=NULL,provider='' WHERE id=2")
        sql("UPDATE users SET name='2',email='',provider_identifier='https://idp.test/subject-2' WHERE id=7")
        policy_path.write_text(AMBIGUOUS.replace("yala@", "2@"))
        with serve(binary, config_path, port, case, "raw-policy-name"):
            for command in ("check", "set"):
                result = run(binary, config_path, ["policy", command, "--file", str(policy_path)])
                success(result)
                outputs[f"raw-policy-name-{command}"] = result

        # Empty stored policies have the upstream default-policy meaning.
        sql("UPDATE policies SET data=''")
        outputs["empty-policy-configtest"] = run(binary, config_path, ["configtest"])
        success(outputs["empty-policy-configtest"])
        policy_path.write_text("")
        config["policy"] = {"mode": "file", "path": str(policy_path)}
        config_path.write_text(json.dumps(config))
        outputs["empty-file-configtest"] = run(binary, config_path, ["configtest"])
        success(outputs["empty-file-configtest"])
        with serve(binary, config_path, port, case, "empty-file"):
            pass
        config["policy"] = {"mode": "database"}
        for mode, required in (("valid", True), ("unavailable", True), ("unavailable", False), ("mismatch", True)):
            config["oidc"] = {"issuer": f"http://127.0.0.1:{provider_port}/{mode}",
                              "client_id": "fixture", "client_secret": "fixture-secret",
                              "only_start_if_oidc_is_available": required}
            config_path.write_text(json.dumps(config))
            expected = mode == "valid" or not required
            before = len(Provider.requests)
            result = run(binary, config_path, ["configtest"])
            attempted = len(Provider.requests) > before
            assert attempted and (result["status"] == 0) == expected, result
            if expected:
                with serve(binary, config_path, port, case, f"oidc-{mode}-{required}"):
                    served = True
            else:
                failed_serve = run(binary, config_path, ["serve"])
                assert failed_serve["status"] != 0, failed_serve
                served = False
            oidc_rows.append({"mode": mode, "required": required, "discovery_attempted": attempted,
                              "configtest_success": result["status"] == 0, "serve_success": served,
                              "configtest_output": result})
    return {"policy_outputs": outputs, "oidc": oidc_rows, "malformed_policy_outputs": malformed_outputs}


def main():
    os.umask(0o077)
    if not GO.is_file() or not RUST.is_file():
        raise FileNotFoundError("set HEADSCALE_GO_BIN and build the Rust CLI")
    version = subprocess.check_output([str(GO), "version"], env=ENV).decode()
    assert "v0.29.5" in version, version
    WORK.mkdir(parents=True)
    provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=provider.serve_forever, daemon=True)
    thread.start()
    report = {"go_version": version.strip(), "backends": {}, "policy_mismatches": []}
    try:
        for backend in BACKENDS:
            go = run_case("go", GO, backend, provider.server_port)
            rust = run_case("rust", RUST, backend, provider.server_port)
            for label in go["policy_outputs"]:
                if go["policy_outputs"][label] != rust["policy_outputs"][label]:
                    report["policy_mismatches"].append({"backend": backend, "case": label,
                        "go": go["policy_outputs"][label], "rust": rust["policy_outputs"][label]})
            for g, r in zip(go["oidc"], rust["oidc"]):
                assert {k:v for k,v in g.items() if k != "configtest_output"} == {k:v for k,v in r.items() if k != "configtest_output"}
            assert all(result["status"] != 0 for output in (go, rust) for result in output["malformed_policy_outputs"].values())
            report["backends"][backend] = {"go": go, "rust": rust}
    finally:
        provider.shutdown()
        provider.server_close()
        (WORK / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(report['backends'])} paired backends, {len(report['policy_mismatches'])} policy output mismatches: {WORK / 'report.json'}")
    if report["policy_mismatches"]:
        for row in report["policy_mismatches"]:
            print(f"mismatch: {row['backend']} {row['case']}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
