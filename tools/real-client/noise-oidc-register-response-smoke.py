#!/usr/bin/env python3
"""Compare pinned-Go and Rust OIDC register responses over TS2021/Noise."""

from datetime import datetime
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from urllib.error import HTTPError
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import parse_qs, unquote, urlencode, urlparse
from urllib.request import HTTPSHandler, HTTPCookieProcessor, Request, build_opener, urlopen


ROOT = Path(__file__).resolve().parents[2]
WORKDIR = Path(os.environ.get(
    "REAL_CLIENT_WORKDIR",
    f"target/real-client/noise-oidc-register-response-{int(time.time())}-{os.getpid()}",
))
if not WORKDIR.is_absolute():
    WORKDIR = ROOT / WORKDIR
WORKDIR.mkdir(parents=True, exist_ok=True)
RUST_BIN = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale"))
GO_BIN = Path(os.environ.get("HEADSCALE_GO_BIN", WORKDIR / "bin/headscale"))
HELPER = WORKDIR / "noise-followup"
DATABASE_MODE = os.environ.get("NOISE_OIDC_DATABASE", "sqlite")
WEBSOCKET_MODE = os.environ.get("NOISE_OIDC_WEBSOCKET", "") == "1"
TLS_MODE = os.environ.get("NOISE_OIDC_TLS", "") == "1"
DELETE_STREAM_MODE = os.environ.get("NOISE_OIDC_DELETE_STREAM", "") == "1"
POSTGRES_TEST_URL = os.environ.get("HEADSCALE_DB_POSTGRES_TEST_URL", "")


def assert_regular_http_metrics(body):
    counters = []
    for line in body.splitlines():
        match = re.fullmatch(r'http_requests_total\{([^}]*)\} ([0-9.]+)', line)
        if match:
            labels = dict(re.findall(r'(\w+)="([^"]*)"', match.group(1)))
            counters.append((labels, float(match.group(2))))
    health = [(labels, count) for labels, count in counters
              if labels.get("endpoint") == "GET /health" and labels.get("status") == "200"]
    ts2021 = [(labels, count) for labels, count in counters
              if labels.get("endpoint", "").endswith(" /ts2021") and count > 0]
    machine_register = [(labels, count) for labels, count in counters
                        if labels.get("endpoint") == "POST /machine/register"
                        and labels.get("status") == "200"
                        and labels.get("proto") == "HTTP/2.0" and count > 0]
    assert health and sum(count for _, count in health) > 0, "GET /health missing from HTTP metrics"
    assert ts2021, "/ts2021 missing from HTTP metrics"
    assert machine_register, "inner Noise /machine/register missing from HTTP metrics"
    assert all(not labels.get("endpoint", "").startswith("OPTIONS ") for labels, _ in counters), (
        "preflight OPTIONS requests should not be counted"
    )
    assert "http_request_duration_seconds_count{" in body, "HTTP duration histogram missing"
    return {"health": sum(count for _, count in health),
            "ts2021": sum(count for _, count in ts2021),
            "machine_register": sum(count for _, count in machine_register)}


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(*args, cwd=ROOT, env=None, output=None):
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)
    if output:
        Path(output).write_text(result.stdout)
    if result.returncode:
        raise RuntimeError(f"{' '.join(map(str, args))} failed: {result.stderr[-4000:]}")
    return result.stdout


def wait_http(url, process, timeout=30, ssl_context=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"process exited before {url} became ready")
        try:
            with urlopen(url, timeout=1, context=ssl_context) as response:
                return response.read()
        except Exception:
            time.sleep(0.2)
    raise TimeoutError(f"timed out waiting for {url}")


def wait_file(path, process, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError(f"process exited before writing {path}")
        time.sleep(0.1)
    raise TimeoutError(f"timed out waiting for {path}")


class ConfirmationToken(HTMLParser):
    def __init__(self):
        super().__init__()
        self.value = ""

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "input" and fields.get("name") == "headscale_register_confirm":
            self.value = fields.get("value", "")


def postgres_settings(database_name):
    parsed = urlparse(POSTGRES_TEST_URL)
    if not parsed.hostname or not parsed.username:
        raise ValueError("Postgres mode requires HEADSCALE_DB_POSTGRES_TEST_URL with host and user")
    return f"""database:
  type: postgres
  postgres:
    host: {json.dumps(parsed.hostname)}
    port: {parsed.port or 5432}
    name: {json.dumps(database_name)}
    user: {json.dumps(unquote(parsed.username))}
    pass: {json.dumps(unquote(parsed.password or ""))}
    ssl: {json.dumps(parse_qs(parsed.query).get("sslmode", ["false"])[0])}
policy:
  mode: database
"""


def make_config(case, port, metrics, grpc, oidc_port, database_name=None):
    q = json.dumps
    socket_path = f"/tmp/hs-noise-oidc-{os.getpid()}-{case.name}.sock"
    scheme = "https" if TLS_MODE else "http"
    tls_config = ""
    if TLS_MODE:
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
            "-days", "1", "-nodes", "-keyout", str(case / "tls.key"),
            "-out", str(case / "tls.crt"), "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
        tls_config = (f"tls_cert_path: {q(str(case / 'tls.crt'))}\n"
                      f"tls_key_path: {q(str(case / 'tls.key'))}\n")
    database_config = (postgres_settings(database_name) if database_name else
                       f"""database:
  type: sqlite
  sqlite:
    path: {q(str(case / 'db.sqlite'))}
policy:
  mode: database
""")
    config = f"""
server_url: {q(f'{scheme}://127.0.0.1:{port}')}
listen_addr: {q(f'127.0.0.1:{port}')}
metrics_listen_addr: {q(f'127.0.0.1:{metrics}')}
grpc_listen_addr: {q(f'127.0.0.1:{grpc}')}
grpc_allow_insecure: true
unix_socket: {q(socket_path)}
private_key_path: {q(str(case / 'private.key'))}
{tls_config}
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
{database_config}
oidc:
  only_start_if_oidc_is_available: true
  issuer: {q(f'http://127.0.0.1:{oidc_port}/oidc')}
  client_id: headscale-rs
  client_secret: secret
  allowed_domains:
    - example.com
  email_verified_required: true
"""
    (case / "config.yaml").write_text(config)
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
    return socket_path


def start_process(args, stdout_path, stderr_path, env=None):
    stdout = Path(stdout_path).open("w")
    stderr = Path(stderr_path).open("w") if stderr_path is not None else subprocess.DEVNULL
    process = subprocess.Popen(args, cwd=ROOT, env=env, stdout=stdout, stderr=stderr)
    stdout.close()
    if stderr_path is not None:
        stderr.close()
    return process


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def case_run(implementation, oidc_port, database_name=None):
    case = WORKDIR / implementation
    case.mkdir(exist_ok=True)
    port, metrics, grpc = free_port(), free_port(), free_port()
    socket_path = make_config(case, port, metrics, grpc, oidc_port, database_name)
    binary = RUST_BIN if implementation == "rust" else GO_BIN
    transport_args = ["-websocket"] if WEBSOCKET_MODE else []
    ssl_context = None
    if TLS_MODE:
        transport_args.extend(["-ca-cert", str(case / "tls.crt")])
        ssl_context = ssl.create_default_context(cafile=case / "tls.crt")
    server = start_process(
        [str(binary), "--config", str(case / "config.yaml"), "serve"],
        case / "serve.stdout", case / "serve.stderr",
    )
    try:
        scheme = "https" if TLS_MODE else "http"
        base = f"{scheme}://127.0.0.1:{port}"
        wait_http(f"{base}/health", server, ssl_context=ssl_context)
        state = case / "initial.json"
        run(str(HELPER), *transport_args, "-mode", "initial", "-url", base,
            "-state", str(state), "-output", str(case / "initial-response.json"))
        auth_url = json.loads(state.read_text())["auth_url"]
        auth_id = urlparse(auth_url).path.rsplit("/", 1)[-1]
        assert auth_id.startswith("hskey-authreq-") and len(auth_id) == 38, auth_id
        followup = start_process(
            [str(HELPER), *transport_args, "-mode", "followup", "-url", base,
             "-state", str(state), "-output", str(case / "followup.json")],
            case / "followup.stdout", case / "followup.stderr",
        )
        handlers = [HTTPCookieProcessor(CookieJar())]
        if ssl_context is not None:
            handlers.append(HTTPSHandler(context=ssl_context))
        opener = build_opener(*handlers)
        try:
            callback_response = opener.open(auth_url, timeout=20)
            confirmation_url = callback_response.geturl()
            assert urlparse(confirmation_url).path.endswith(
                f"/register/confirm/{auth_id}"), confirmation_url
            callback = callback_response.read().decode()
            (case / "callback.html").write_text(callback)
            parser = ConfirmationToken()
            parser.feed(callback)
            if parser.value:
                reload_response = opener.open(confirmation_url, timeout=20)
                assert reload_response.status == 200, reload_response.status
                reload_body = reload_response.read().decode()
                reload_parser = ConfirmationToken()
                reload_parser.feed(reload_body)
                assert reload_parser.value == parser.value, "confirmation reload changed CSRF token"
                (case / "confirm-reload.html").write_text(reload_body)
                no_cookie_handlers = [HTTPSHandler(context=ssl_context)] if ssl_context else []
                no_cookie_opener = build_opener(*no_cookie_handlers)
                try:
                    no_cookie_opener.open(confirmation_url, timeout=20)
                except HTTPError as error:
                    assert error.code == 403, error.code
                else:
                    raise AssertionError("confirmation GET disclosed without CSRF cookie")
                request = Request(
                    f"{base}/register/confirm/{auth_id}",
                    data=urlencode({"headscale_register_confirm": parser.value}).encode(),
                )
                confirmation = opener.open(request, timeout=20).read().decode()
                (case / "confirm.html").write_text(confirmation)
            elif not any(text in callback for text in
                         ("Authenticated", "Signed in successfully", "Node registered", "Node reauthenticated")):
                raise AssertionError("OIDC callback returned neither confirmation nor success")
            followup.wait(timeout=50)
            if followup.returncode:
                raise RuntimeError((case / "followup.stderr").read_text())
        finally:
            stop_process(followup)
        nodes = run(str(binary), "--config", str(case / "config.yaml"),
                    "-o", "json", "nodes", "list", output=case / "nodes.json")
        nodes = json.loads(nodes)
        metrics_text = urlopen(f"http://127.0.0.1:{metrics}/metrics", timeout=10).read().decode()
        (case / "metrics.txt").write_text(metrics_text)
        lifecycle = {"http_metrics": assert_regular_http_metrics(metrics_text)}
        if DELETE_STREAM_MODE:
            stream_output = case / "deleted-stream.json"
            stream = start_process(
                [str(HELPER), *transport_args, "-mode", "stream", "-url", base,
                 "-state", str(state), "-output", str(stream_output)],
                case / "deleted-stream.stdout", case / "deleted-stream.stderr",
            )
            try:
                wait_file(Path(str(stream_output) + ".ready"), stream)
                assert stream.poll() is None, "map stream closed before node deletion"
                run(str(binary), "--config", str(case / "config.yaml"),
                    "--force", "-o", "json", "nodes", "delete",
                    "--identifier", str(nodes[0]["id"]),
                    output=case / "delete-node.json")
                stream.wait(timeout=10)
                if stream.returncode:
                    raise RuntimeError((case / "deleted-stream.stderr").read_text())
                lifecycle["stream"] = json.loads(stream_output.read_text())
            finally:
                stop_process(stream)
            expired_output = case / "expired-map.json"
            run(str(HELPER), *transport_args, "-mode", "expired", "-url", base,
                "-state", str(state), "-output", str(expired_output))
            lifecycle["expired"] = json.loads(expired_output.read_text())
        return json.loads((case / "followup.json").read_text()), nodes, lifecycle
    finally:
        stop_process(server)
        Path(socket_path).unlink(missing_ok=True)


def main():
    if DATABASE_MODE not in ("sqlite", "postgres"):
        raise ValueError(f"unsupported NOISE_OIDC_DATABASE: {DATABASE_MODE}")
    if DATABASE_MODE == "postgres":
        postgres_settings("validation")
    if not GO_BIN.exists():
        if GO_BIN.name != "headscale":
            raise ValueError("HEADSCALE_GO_BIN must end in /headscale")
        bin_dir = GO_BIN.parent
        bin_dir.mkdir(exist_ok=True)
        run("go", "install", "github.com/juanfont/headscale/cmd/headscale@v0.29.5",
            env={**os.environ, "GOBIN": str(bin_dir)})
    version = run(str(GO_BIN), "version")
    assert "v0.29.5" in version, version
    (WORKDIR / "go-version.txt").write_text(version)
    build = ["cargo", "build", "-p", "headscale-cli", "--bin", "headscale"]
    if DATABASE_MODE == "postgres":
        build.extend(["--features", "postgres-sqlx"])
    run(*build)
    run("go", "build", "-o", str(HELPER), "./noise-followup",
        cwd=ROOT / "tools/parity/headscale-go")

    results = {}
    for implementation in ("rust", "go"):
        oidc_port = free_port()
        mock_env = {**os.environ,
            "MOCKOIDC_CLIENT_ID": "headscale-rs",
            "MOCKOIDC_CLIENT_SECRET": "secret",
            "MOCKOIDC_ADDR": "127.0.0.1",
            "MOCKOIDC_PORT": str(oidc_port),
            "MOCKOIDC_USERS": json.dumps([{
                "Subject": "alice-subject", "Email": "alice@example.com",
                "EmailVerified": True, "PreferredUsername": "alice", "Groups": ["engineering"]}]),
            "MOCKOIDC_ACCESS_TTL": "10m"}
        mock = start_process([str(GO_BIN), "mockoidc"],
                             WORKDIR / f"mockoidc-{implementation}.stdout", None, mock_env)
        database_name = None
        try:
            if DATABASE_MODE == "postgres":
                pending_database = f"hs_oidc_response_{int(time.time())}_{os.getpid()}_{implementation}"
                run("psql", POSTGRES_TEST_URL, "-X", "-v", "ON_ERROR_STOP=1",
                    "-c", f"CREATE DATABASE {pending_database}")
                database_name = pending_database
            wait_http(f"http://127.0.0.1:{oidc_port}/oidc/.well-known/openid-configuration", mock)
            results[implementation] = case_run(implementation, oidc_port, database_name)
        finally:
            stop_process(mock)
            if database_name:
                run("psql", POSTGRES_TEST_URL, "-X", "-v", "ON_ERROR_STOP=1",
                    "-c", f"DROP DATABASE {database_name} WITH (FORCE)")

    bodies = {}
    for implementation, (response, nodes, lifecycle) in results.items():
        body = json.loads(response["body"])
        assert response["status"] == 200 and body["MachineAuthorized"] is True, response
        assert len(nodes) == 1 and nodes[0]["user"]["email"] == "alice@example.com", nodes
        assert body["User"]["ID"] == nodes[0]["user"]["id"], body
        assert body["Login"]["LoginName"] == "alice@example.com", body
        assert body["Login"]["Provider"] == "oidc", body
        assert body["NodeKeySignature"] is None, body
        assert body["NodeKeyExpired"] is False and body["AuthURL"] == "" and body["Error"] == "", body
        created = datetime.fromisoformat(body["User"]["Created"].replace("Z", "+00:00"))
        assert created.microsecond != 0, body
        if DELETE_STREAM_MODE:
            assert lifecycle["stream"]["status"] == 200, lifecycle
            stream_close = json.loads(lifecycle["stream"]["body"])
            assert stream_close["closed"] is True, lifecycle
            assert not stream_close["close_error"] or "INTERNAL_ERROR" in stream_close["close_error"], lifecycle
            assert lifecycle["expired"]["status"] == 200, lifecycle
            expired = json.loads(lifecycle["expired"]["body"])
            assert expired["Node"]["Key"] == json.loads(
                (WORKDIR / implementation / "initial.json").read_text()
            )["node_key"], expired
            assert expired["Node"]["Expired"] is True, expired
            assert expired["Node"]["KeyExpiry"] == "1970-01-01T00:00:01Z", expired
            assert "Peers" not in expired, expired
        bodies[implementation] = body
    rust_user = {key: value for key, value in bodies["rust"]["User"].items()
                 if key != "Created"}
    go_user = {key: value for key, value in bodies["go"]["User"].items()
               if key != "Created"}
    assert rust_user == go_user, bodies
    assert bodies["rust"]["Login"] == bodies["go"]["Login"], bodies
    assert bodies["rust"].keys() == bodies["go"].keys(), bodies
    assert results["rust"][2]["http_metrics"] == results["go"][2]["http_metrics"], (
        results["rust"][2]["http_metrics"], results["go"][2]["http_metrics"]
    )
    if DELETE_STREAM_MODE:
        rust_expired = json.loads(results["rust"][2]["expired"]["body"])
        go_expired = json.loads(results["go"][2]["expired"]["body"])
        rust_expired["Node"].pop("Key")
        go_expired["Node"].pop("Key")
        assert rust_expired == go_expired, (rust_expired, go_expired)
    transport = "websocket" if WEBSOCKET_MODE else "native"
    if TLS_MODE:
        transport = f"tls-{transport}"
    print(f"paired Rust and pinned-Go TS2021 OIDC register responses passed "
          f"({DATABASE_MODE}, {transport}): {WORKDIR}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"OIDC register-response smoke failed: {exc}", file=sys.stderr)
        sys.exit(1)
