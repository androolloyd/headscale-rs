#!/usr/bin/env python3
"""Pair Go/Rust production full-map logtail and audit node-attribute behavior."""

import json
import os
from contextlib import contextmanager
from pathlib import Path
import socket
import subprocess
import sys
import time
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[2]
WORKDIR = Path(os.environ.get(
    "REAL_CLIENT_WORKDIR",
    f"target/real-client/noise-logtail-v0295-{int(time.time())}-{os.getpid()}",
))
if not WORKDIR.is_absolute():
    WORKDIR = ROOT / WORKDIR
GO_BIN = Path(os.environ.get("HEADSCALE_GO_BIN", ""))
RUST_BIN = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale"))
HELPER = WORKDIR / "noise-followup"
AUDIT_ATTR = "data-plane-audit-logs"


def command(*args, cwd=ROOT):
    result = subprocess.run(args, cwd=cwd, text=True, capture_output=True, timeout=35)
    if result.returncode:
        raise RuntimeError(f"{args} exited {result.returncode}: {result.stderr[-2000:]}")
    return result.stdout


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def config(case, port, enabled):
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
unix_socket: {q(f'/tmp/hs-logtail-{os.getpid()}-{case.name}.sock')}
noise:
  private_key_path: {q(str(case / 'noise.key'))}
prefixes:
  allocation: sequential
  v4: 100.64.0.0/10
dns:
  magic_dns: false
  base_domain: tail.test
  override_local_dns: false
log:
  level: error
logtail:
  enabled: {str(enabled).lower()}
derp:
  server:
    enabled: false
  urls: []
  paths: [{q(str(case / 'derp.yaml'))}]
  auto_update_enabled: false
policy:
  mode: database
database:
  type: sqlite
  sqlite:
    path: {q(str(case / 'db.sqlite'))}
""")


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


def map_once(case, port, label, expected_debug, expect_attr):
    output = case / f"{label}.json"
    command(str(HELPER), "-mode", "map-once", "-url", f"http://127.0.0.1:{port}",
            "-state", str(case / "state.json"), "-output", str(output))
    response = json.loads(output.read_text())
    if response["status"] != 200:
        raise AssertionError(f"map status: {response}")
    frame = json.loads(response["body"])
    debug = frame.get("Debug")
    attrs = frame["Node"].get("CapMap") or {}
    if debug != expected_debug:
        raise AssertionError(f"{label} Debug: expected {expected_debug}, got {debug}")
    if (AUDIT_ATTR in attrs) != expect_attr:
        raise AssertionError(f"{label} audit CapMap: {attrs}")
    return {"debug": debug, "audit_node_attr": AUDIT_ATTR in attrs,
            "node_id": frame["Node"]["ID"]}


def run_case(implementation, enabled, audit):
    name = f"{implementation}-logtail-{int(enabled)}-audit-{int(audit)}"
    case = WORKDIR / name
    case.mkdir()
    port = free_port()
    config(case, port, enabled)
    binary = GO_BIN if implementation == "go" else RUST_BIN
    cli = [str(binary), "--config", str(case / "config.yaml"), "-o", "json"]
    expected_debug = None if enabled else {"DisableLogTail": True}
    try:
        with serve(case, binary, port, "first"):
            user = json.loads(command(*cli, "users", "create", "alice"))
            key = json.loads(command(*cli, "preauthkeys", "create", "--user",
                                     str(user["id"]), "--reusable"))["key"]
            policy = {"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}
            if audit:
                policy["nodeAttrs"] = [{"target": ["alice@"], "attr": [AUDIT_ATTR]}]
            (case / "policy.hujson").write_text(json.dumps(policy, indent=2) + "\n")
            command(*cli, "policy", "set", "--file", str(case / "policy.hujson"))
            command(str(HELPER), "-mode", "authkey-initial", "-url",
                    f"http://127.0.0.1:{port}", "-state", str(case / "state.json"),
                    "-output", str(case / "register.json"), "-authkey", key)
            first = map_once(case, port, "first-map", expected_debug, audit)
            second = map_once(case, port, "second-map", expected_debug, audit)
            if first != second:
                raise AssertionError(f"map stream open changed response: {first} {second}")
        with serve(case, binary, port, "restart"):
            restarted = map_once(case, port, "restart-map", expected_debug, audit)
            if first != restarted:
                raise AssertionError(f"restart changed map response: {first} {restarted}")
        result = {"implementation": implementation, "logtail_enabled": enabled,
                  "audit_attr": audit, "first": first, "second": second,
                  "restarted": restarted}
        (case / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        Path(f"/tmp/hs-logtail-{os.getpid()}-{case.name}.sock").unlink(missing_ok=True)


def main():
    if not GO_BIN.is_file() or not RUST_BIN.is_file():
        raise ValueError("set HEADSCALE_GO_BIN and build RUST_HEADSCALE_BIN")
    version = command(str(GO_BIN), "version").strip()
    if "v0.29.5" not in version:
        raise RuntimeError(f"expected pinned Go v0.29.5: {version}")
    WORKDIR.mkdir(parents=True, exist_ok=True)
    command("go", "build", "-o", str(HELPER), "./noise-followup",
            cwd=ROOT / "tools/parity/headscale-go")
    results = []
    for enabled in (False, True):
        for audit in (False, True):
            go = run_case("go", enabled, audit)
            rust = run_case("rust", enabled, audit)
            for phase in ("first", "second", "restarted"):
                if go[phase] != rust[phase]:
                    raise AssertionError(f"Go/Rust {phase} full map differs for {enabled}/{audit}")
            results.extend((go, rust))
    report = {"go_version": version, "cases": results}
    path = WORKDIR / "report.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"paired v0.29.5 full-map logtail/nodeAttrs passed: {path}")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"full-map logtail/nodeAttrs smoke failed: {error}", file=sys.stderr)
        sys.exit(1)
