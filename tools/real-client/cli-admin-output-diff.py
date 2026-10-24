#!/usr/bin/env python3
"""Compare Go/Rust admin CLI bytes and requests using fixed upstream RPC replies.

This qualifies client output and request construction, independently of server
parity. No output normalization is applied. Only minted request expiry instants
may differ, and their timing is bounded relative to each command invocation.
"""

from contextlib import contextmanager
from datetime import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
GO_BIN = Path(os.environ.get("HEADSCALE_GO_BIN", "")).resolve()
RUST_BIN = Path(os.environ.get("RUST_HEADSCALE_BIN", ROOT / "target/debug/headscale")).resolve()
WORKDIR = Path(os.environ.get(
    "REAL_CLIENT_WORKDIR",
    f"target/real-client/cli-admin-output-diff-{int(time.time())}-{os.getpid()}",
)).resolve()
ENV = {k: v for k, v in os.environ.items()
       if not k.startswith("HEADSCALE_") and k != "RUST_LOG"}
AUTH_ID = "hskey-authreq-" + "a" * 24
CREATED = "2025-01-02T03:04:05.123456789Z"
FUTURE = "2099-01-02T03:04:05.123456789Z"
POLICY = '{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}\n'


def fixture(empty=False):
    user = {"id": "1", "name": "alice", "createdAt": CREATED,
            "displayName": "Alice 東京", "email": "alice@example.com",
            "providerId": "https://idp.example/subject-1", "provider": "oidc",
            "profilePicUrl": "https://example.com/alice.png"}
    other = {"id": "2", "name": "bob", "createdAt": CREATED}
    key = {"user": user, "id": "7", "key": "fixture-key-prefix.secret",
           "reusable": True, "ephemeral": True, "used": True,
           "expiration": FUTURE, "createdAt": CREATED}
    tagged_key = {"id": "8", "key": "tagged-prefix", "createdAt": CREATED,
                  "aclTags": ["tag:router", "tag:production"]}
    node = {"id": "3", "machineKey": "mkey:" + "01" * 32,
            "nodeKey": "nodekey:" + "02" * 32, "discoKey": "discokey:" + "03" * 32,
            "ipAddresses": ["100.64.0.3", "fd7a:115c:a1e0::3"],
            "name": "router.example", "givenName": "router", "user": user,
            "createdAt": CREATED, "lastSeen": CREATED, "expiry": FUTURE,
            "preAuthKey": key, "registerMethod": "REGISTER_METHOD_AUTH_KEY",
            "online": True, "approvedRoutes": ["10.0.0.0/24", "0.0.0.0/0", "::/0"],
            "availableRoutes": ["10.0.0.0/24", "0.0.0.0/0", "::/0"],
            "subnetRoutes": ["10.0.0.0/24"]}
    tagged = {"id": "4", "machineKey": "mkey:" + "04" * 32,
              "nodeKey": "nodekey:" + "05" * 32, "discoKey": "discokey:" + "00" * 32,
              "ipAddresses": ["100.64.0.4"], "name": "tagged", "givenName": "tagged",
              "user": {"name": "tagged-devices", "displayName": "Tagged Devices",
                       "createdAt": "0001-01-01T00:00:00Z"},
              "createdAt": CREATED, "tags": ["tag:router", "tag:production"],
              "registerMethod": "REGISTER_METHOD_CLI"}
    return {
        "CreateUser": {"user": user}, "RenameUser": {"user": user}, "DeleteUser": {},
        "ListUsers": {"users": [] if empty else [user, other]},
        "CreatePreAuthKey": {"preAuthKey": key},
        "ListPreAuthKeys": {"preAuthKeys": [] if empty else [key, tagged_key]},
        "ExpirePreAuthKey": {}, "DeletePreAuthKey": {},
        "CreateApiKey": {"apiKey": "fixture-api-prefix.secret"},
        "ListApiKeys": {"apiKeys": [] if empty else [
            {"id": "9", "prefix": "fixture-api", "createdAt": CREATED,
             "expiration": FUTURE, "lastSeen": CREATED},
            {"id": "10", "prefix": "no-expiry", "createdAt": CREATED}]},
        "ExpireApiKey": {}, "DeleteApiKey": {},
        "ListNodes": {"nodes": [] if empty else [node, tagged]},
        **{name: {"node": node} for name in (
            "GetNode", "DebugCreateNode", "SetTags", "SetApprovedRoutes",
            "RegisterNode", "ExpireNode", "RenameNode", "AuthRegister")},
        "DeleteNode": {}, "AuthApprove": {}, "AuthReject": {},
        "BackfillNodeIPs": {"changes": ["node 3: allocated fd7a:115c:a1e0::3", "node 4: unchanged"]},
        "GetPolicy": {"policy": POLICY, "updatedAt": CREATED},
        "SetPolicy": {"policy": POLICY, "updatedAt": CREATED}, "CheckPolicy": {},
        "Health": {"databaseConnectivity": True},
    }


def cases(policy_path, empty=False):
    lists = [
        ["users", "list"], ["users", "list", "--name", "alice"],
        ["users", "list", "--identifier", "1"],
        ["users", "list", "--email", "alice@example.com"],
        ["nodes", "list"], ["nodes", "list", "--user", "alice"],
        ["nodes", "list-routes"], ["nodes", "list-routes", "-i", "3"],
        ["preauthkeys", "list"], ["apikeys", "list"], ["health"], ["policy", "get"],
    ]
    if empty:
        return lists
    return lists + [
        ["users", "create", "alice", "--display-name", "Alice Example", "--email", "alice@example.com",
         "--picture-url", "https://example.com/alice.png"],
        ["users", "rename", "--name", "alice", "--new-name", "renamed"],
        ["users", "rename", "-i", "1", "--new-name", "renamed"],
        ["users", "destroy", "--name", "alice", "--force"],
        ["preauthkeys", "create", "--user", "1", "--reusable", "--ephemeral", "--expiration", "24h"],
        ["preauthkeys", "create", "--tags", "tag:router,tag:production", "--expiration", "24h"],
        ["preauthkeys", "expire", "--id", "7"], ["preauthkeys", "delete", "--id", "7", "--force"],
        ["apikeys", "create", "--expiration", "24h"],
        ["apikeys", "expire", "--prefix", "fixture-api"],
        ["apikeys", "delete", "--prefix", "fixture-api", "--force"],
        ["nodes", "rename", "renamed", "--identifier", "3"],
        ["nodes", "expire", "--identifier", "3", "--expiry", FUTURE],
        ["nodes", "expire", "--identifier", "3", "--disable"],
        ["nodes", "tag", "--identifier", "3", "--tags", "tag:router,tag:production"],
        ["nodes", "approve-routes", "--identifier", "3", "--routes", "10.0.0.0/24,::/0"],
        ["nodes", "delete", "--identifier", "3", "--force"],
        ["nodes", "backfillips", "--force"],
        ["nodes", "register", "--user", "alice", "--key", AUTH_ID],
        ["auth", "register", "--user", "alice", "--auth-id", AUTH_ID],
        ["auth", "approve", "--auth-id", AUTH_ID], ["auth", "reject", "--auth-id", AUTH_ID],
        ["debug", "create-node", "--name", "router", "--user", "alice", "--key", AUTH_ID,
         "--route", "10.0.0.0/24,::/0"],
        ["policy", "set", "--file", str(policy_path)],
        ["policy", "check", "--file", str(policy_path)],
    ]


@contextmanager
def server(helper, case_dir, empty):
    fixture_path = case_dir / "fixture.json"
    fixture_path.write_text(json.dumps(fixture(empty), indent=2) + "\n")
    audit_path = case_dir / "requests.jsonl"
    with tempfile.TemporaryDirectory(prefix="hs-cli-") as socket_dir:
        socket_path = Path(socket_dir) / "s.sock"
        config_path = case_dir / "config.json"
        config_path.write_text(json.dumps({"unix_socket": str(socket_path), "log": {"level": "error"}}))
        with (case_dir / "fixture.stderr").open("w") as stderr:
            process = subprocess.Popen([str(helper), "-socket", str(socket_path),
                                        "-fixture", str(fixture_path), "-audit", str(audit_path)],
                                       stderr=stderr)
            try:
                deadline = time.monotonic() + 10
                while not socket_path.exists():
                    if process.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError("gRPC fixture failed to start")
                    time.sleep(.02)
                yield config_path, audit_path
            finally:
                process.terminate()
                process.wait(timeout=5)


def run(binary, config_path, args, audit_path):
    before = len(audit_path.read_text().splitlines())
    started = time.time()
    result = subprocess.run([str(binary), "--config", str(config_path), *args],
                            cwd=ROOT, env=ENV, capture_output=True, timeout=20)
    finished = time.time()
    requests = [json.loads(line) for line in audit_path.read_text().splitlines()[before:]]
    # Duration-based flags legitimately mint different expiration instants.
    # Validate their actual values before replacing just that request field.
    for request in requests:
        if request["method"] in ("CreateApiKey", "CreatePreAuthKey"):
            expiry = request["request"].get("expiration")
            if expiry is not None:
                expiry_time = datetime.fromisoformat(expiry.replace("Z", "+00:00")).timestamp()
                if not started + 86400 - 1 <= expiry_time <= finished + 86400 + 1:
                    raise AssertionError(f"incorrect minted request expiry: {request}")
                request["request"]["expiration"] = "<invocation + 24h>"
    return {"status": result.returncode, "stdout": result.stdout.decode(), "stderr": result.stderr.decode(),
            "requests": requests}


def main():
    if not GO_BIN.is_file() or not RUST_BIN.is_file():
        raise FileNotFoundError("set HEADSCALE_GO_BIN and build target/debug/headscale")
    version = subprocess.run([str(GO_BIN), "version"], text=True, capture_output=True, check=True).stdout
    if "v0.29.5" not in version:
        raise RuntimeError(f"expected pinned headscale-go v0.29.5: {version}")
    WORKDIR.mkdir(parents=True)
    helper = WORKDIR / "cli-fixture"
    subprocess.run(["go", "build", "-o", str(helper), "./cli-fixture"],
                   cwd=ROOT / "tools/parity/headscale-go", check=True)
    policy_path = WORKDIR / "policy.hujson"
    policy_path.write_text(POLICY)
    rows = []
    for empty in (False, True):
        case_dir = WORKDIR / ("empty" if empty else "populated")
        case_dir.mkdir()
        with server(helper, case_dir, empty) as (config_path, audit_path):
            for command in cases(policy_path, empty):
                for fmt in ("human", "json", "json-line", "yaml"):
                    args = ([] if fmt == "human" else ["-o", fmt]) + command
                    go = run(GO_BIN, config_path, args, audit_path)
                    rust = run(RUST_BIN, config_path, args, audit_path)
                    rows.append({"empty": empty, "args": args,
                                 "match": go["status"] == 0 and go == rust, "go": go, "rust": rust})
    methods = sorted({request["method"] for row in rows for request in row["go"]["requests"]})
    if set(methods) != set(fixture()):
        raise AssertionError(f"uncovered RPC fixtures: {set(fixture()) - set(methods)}")
    report = {"go_version": version.strip(), "output_normalization": "none", "rpc_methods": methods,
              "request_normalization": "24h expiry validated against invocation time",
              "comparisons": len(rows), "mismatches": sum(not row["match"] for row in rows), "rows": rows}
    report_path = WORKDIR / "report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(f"{len(rows)} admin comparisons, {report['mismatches']} mismatches: {report_path}")
    for row in rows:
        if not row["match"]:
            print(f"mismatch ({'empty' if row['empty'] else 'populated'}): {' '.join(row['args'])}", file=sys.stderr)
    if report["mismatches"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
