#!/usr/bin/env python3
"""Compare the production Go/Rust 30-second OIDC discovery deadline.

Each process has its own SQLite database, keys and listener. A local provider
stalls either before headers or after a partial JSON body. The eight paired
rows cover configtest/serve and required/optional provider availability.
Only elapsed time and failure/fallback behavior are compared, not diagnostics.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
GO = Path(os.environ.get("HEADSCALE_GO_BIN", "")).resolve()
RUST = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale")).resolve()
WORK = Path(os.environ.get("REAL_CLIENT_WORKDIR", f"target/real-client/oidc-startup-deadline-{int(time.time())}-{os.getpid()}")).resolve()
ENV = {k: v for k, v in os.environ.items() if not k.startswith("HEADSCALE_") and k != "RUST_LOG"}
STOP = threading.Event()
REQUESTS = {}
LOCK = threading.Lock()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        label = self.path.split("/")[1]
        with LOCK:
            REQUESTS[label] = time.monotonic()
        if label.startswith("body-"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "1000")
            self.end_headers()
            self.wfile.write(b'{"issuer":')
            self.wfile.flush()
        STOP.wait(50)
        self.close_connection = True


def run_case(binary, implementation, mode, command, required, provider_port):
    label = f"{mode}-{command}-{required}-{implementation}"
    case = WORK / label
    case.mkdir()
    port = free_port()
    derp_path = case / "derp.yaml"
    derp_path.write_text("""regions:
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
    config_path = case / "config.json"
    config = {
        "server_url": f"http://127.0.0.1:{port}", "listen_addr": f"127.0.0.1:{port}",
        "metrics_listen_addr": "127.0.0.1:0",
        "unix_socket": f"/tmp/hs-oidc-deadline-{os.getpid()}-{label}.sock",
        "noise": {"private_key_path": str(case / "noise.key")},
        "prefixes": {"v4": "100.64.0.0/10"},
        "dns": {"magic_dns": False, "override_local_dns": False},
        "log": {"level": "error"}, "policy": {"mode": "database"},
        "derp": {"server": {"enabled": False}, "urls": [], "paths": [str(derp_path)], "auto_update_enabled": False},
        "database": {"type": "sqlite", "sqlite": {"path": str(case / "db.sqlite")}},
    }
    config_path.write_text(json.dumps(config))
    initialized = subprocess.run([str(binary), "--config", str(config_path), "configtest"],
                                 cwd=ROOT, env=ENV, capture_output=True, timeout=15)
    assert initialized.returncode == 0, initialized.stderr.decode()
    config["oidc"] = {
        "issuer": f"http://127.0.0.1:{provider_port}/{label}",
        "client_id": "fixture", "client_secret": "fixture-secret",
        "only_start_if_oidc_is_available": required,
    }
    config_path.write_text(json.dumps(config))
    with (case / "stdout").open("w") as out, (case / "stderr").open("w") as err:
        process = subprocess.Popen([str(binary), "--config", str(config_path), command],
                                   cwd=ROOT, env=ENV, stdout=out, stderr=err)
        healthy = False
        try:
            deadline = time.monotonic() + 43
            while process.poll() is None:
                if command == "serve":
                    try:
                        with urlopen(f"http://127.0.0.1:{port}/health", timeout=.2) as response:
                            healthy = response.status == 200
                        if healthy:
                            break
                    except OSError:
                        pass
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"{label} did not finish discovery within 43 seconds")
                time.sleep(.05)
            with LOCK:
                requested = REQUESTS.get(label)
            assert requested is not None, f"{label} never attempted discovery"
            elapsed = time.monotonic() - requested
            assert 28.5 <= elapsed <= 39, (label, elapsed)
            succeeded = healthy if command == "serve" else process.returncode == 0
            assert succeeded == (not required), (label, process.poll(), healthy)
            if required:
                assert process.returncode not in (0, None), label
            return {"implementation": implementation, "mode": mode, "command": command,
                    "required": required, "discovery_seconds": round(elapsed, 3),
                    "startup_success": succeeded, "status": process.poll()}
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    raise AssertionError(f"{label} did not shut down cleanly")


def main():
    os.umask(0o077)
    if not GO.is_file() or not RUST.is_file():
        raise FileNotFoundError("set HEADSCALE_GO_BIN and build the Rust CLI")
    version = subprocess.check_output([str(GO), "version"], env=ENV).decode().strip()
    assert "v0.29.5" in version, version
    WORK.mkdir(parents=True)
    provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    threading.Thread(target=provider.serve_forever, daemon=True).start()
    report = {"go_version": version, "rows": [], "failures": []}
    try:
        with ThreadPoolExecutor(max_workers=16) as executor:
            futures = {}
            for mode in ("headers", "body"):
                for command in ("configtest", "serve"):
                    for required in (True, False):
                        for implementation, binary in (("go", GO), ("rust", RUST)):
                            future = executor.submit(run_case, binary, implementation, mode,
                                                     command, required, provider.server_port)
                            futures[future] = f"{mode}-{command}-{required}-{implementation}"
            for future in as_completed(futures):
                try:
                    report["rows"].append(future.result())
                except Exception as error:
                    report["failures"].append({"case": futures[future], "error": str(error)})
    finally:
        STOP.set()
        provider.shutdown()
        provider.server_close()
        (WORK / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(report['rows'])} process rows, {len(report['failures'])} failures: {WORK / 'report.json'}")
    if report["failures"]:
        raise AssertionError(report["failures"])


if __name__ == "__main__":
    main()
