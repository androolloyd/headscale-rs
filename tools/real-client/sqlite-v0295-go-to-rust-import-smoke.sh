#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

run_dir="${REAL_CLIENT_WORKDIR:-target/real-client/sqlite-v0295-go-to-rust-import-$(date +%s)-$$}"
mkdir -p "${run_dir}"
run_dir="$(cd "${run_dir}" && pwd)"
go_work_dir="${run_dir}/go"
rust_db="${run_dir}/imported.sqlite"
rust_config="${run_dir}/rust.yaml"
rust_socket="/tmp/hsrs-v0295-${$}.sock"
rust_bin="${RUST_HEADSCALE_BIN:-${repo_root}/target/debug/headscale}"
go_bin=""
rust_pid=""

stop_rust() {
  if [[ -n "${rust_pid}" ]]; then
    kill "${rust_pid}" >/dev/null 2>&1 || true
    wait "${rust_pid}" >/dev/null 2>&1 || true
    rust_pid=""
    rm -f "${rust_socket}"
  fi
}
trap stop_rust EXIT

echo "::group::create pinned v0.29.5 database with a stock Tailscale client"
HEADSCALE_GO_VERSION=v0.29.5 \
REAL_CLIENT_WORKDIR="${go_work_dir}" \
REAL_CLIENT_CLIENT_COUNT=2 \
REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT='10.77.0.0/24;-' \
REAL_CLIENT_EXPECT_AVAILABLE_ROUTES_BY_CLIENT='10.77.0.0/24;-' \
REAL_CLIENT_APPROVE_ROUTES_BY_CLIENT='10.77.0.0/24;-' \
REAL_CLIENT_EXPECT_APPROVED_ROUTES_BY_CLIENT='10.77.0.0/24;-' \
REAL_CLIENT_EXPECT_PEER_COUNT=1 \
  tools/real-client/authkey-headscale-go-smoke.sh
echo "::endgroup::"

go_db="$(find "${go_work_dir}" -mindepth 2 -maxdepth 2 -name db.sqlite -type f -print -quit)"
if [[ -z "${go_db}" ]]; then
  echo "headscale-go stock-client smoke did not leave a SQLite database" >&2
  exit 1
fi
go_bin="$(find "${go_work_dir}" -mindepth 3 -maxdepth 3 -path '*/bin/headscale' -type f -print -quit)"
if [[ -z "${go_bin}" ]]; then
  echo "headscale-go stock-client smoke did not leave a pinned Go binary" >&2
  exit 1
fi
python3 - "${go_db}" "${rust_db}" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as source, sqlite3.connect(sys.argv[2]) as target:
    source.backup(target)
    version = target.execute("SELECT version FROM database_versions WHERE id = 1").fetchone()
    assert version == ("v0.29.5",), version
    migrations = {row[0] for row in target.execute("SELECT id FROM migrations")}
    assert "SCHEMA_INIT" in migrations, migrations
    assert target.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
    assert target.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] == 2
    assert target.execute("SELECT COUNT(*) FROM nodes WHERE approved_routes LIKE '%10.77.0.0/24%'").fetchone()[0] == 1
PY

read -r listen_port metrics_port grpc_port < <(python3 - <<'PY'
import socket
sockets = []
for _ in range(3):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sockets.append(sock)
print(*(sock.getsockname()[1] for sock in sockets))
for sock in sockets:
    sock.close()
PY
)

python3 - "${rust_config}" "${rust_db}" "${run_dir}" "${rust_socket}" \
  "${listen_port}" "${metrics_port}" "${grpc_port}" <<'PY'
import json
import pathlib
import sys

config, db, root, socket = sys.argv[1:5]
listen, metrics, grpc = sys.argv[5:8]
q = json.dumps
pathlib.Path(config).write_text(f"""
server_url: {q('http://127.0.0.1:' + listen)}
listen_addr: {q('127.0.0.1:' + listen)}
metrics_listen_addr: {q('127.0.0.1:' + metrics)}
grpc_listen_addr: {q('127.0.0.1:' + grpc)}
grpc_allow_insecure: true
unix_socket: {q(socket)}
noise:
  private_key_path: {q(str(pathlib.Path(root) / 'rust-noise.key'))}
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: sqlite
  sqlite:
    path: {q(db)}
policy:
  mode: database
""")
PY

cargo build -p headscale-cli --bin headscale

start_rust() {
  local attempt="$1"
  "${rust_bin}" --config "${rust_config}" serve \
    >"${run_dir}/rust-${attempt}.stdout" \
    2>"${run_dir}/rust-${attempt}.stderr" &
  rust_pid="$!"
  local deadline=$((SECONDS + 20))
  until curl --silent --show-error --fail \
    "http://127.0.0.1:${listen_port}/health" >"${run_dir}/health-${attempt}.json" 2>/dev/null; do
    if ! kill -0 "${rust_pid}" >/dev/null 2>&1 || ((SECONDS >= deadline)); then
      cat "${run_dir}/rust-${attempt}.stderr" >&2
      echo "headscale-rs did not start on the v0.29.5 Go database" >&2
      return 1
    fi
    sleep 0.2
  done
}

assert_imported_rows() {
  local attempt="$1"
  "${rust_bin}" --config "${rust_config}" -o json users list \
    >"${run_dir}/users-${attempt}.json"
  "${rust_bin}" --config "${rust_config}" -o json nodes list \
    >"${run_dir}/nodes-${attempt}.json"
  python3 - "${run_dir}/users-${attempt}.json" "${run_dir}/nodes-${attempt}.json" "${attempt}" <<'PY'
import json
import sys

users = json.load(open(sys.argv[1]))
nodes = json.load(open(sys.argv[2]))
attempt = int(sys.argv[3])
names = {user["name"] for user in users}
assert "alice" in names, users
if attempt == 2:
    assert "imported-after-switch" in names, users
assert len(nodes) == 2, nodes
assert all(node["user"]["name"] == "alice" for node in nodes), nodes
assert all(node["pre_auth_key"]["id"] > 0 for node in nodes), nodes
assert sum("10.77.0.0/24" in node["approved_routes"] for node in nodes) == 1, nodes
assert sum("10.77.0.0/24" in node["available_routes"] for node in nodes) == 1, nodes
PY
}

echo "::group::import and mutate through headscale-rs production process"
start_rust 1
assert_imported_rows 1
"${rust_bin}" --config "${rust_config}" users create imported-after-switch \
  >"${run_dir}/users-create.stdout"
user_id="$(python3 - "${run_dir}/users-1.json" <<'PY'
import json
import sys
print(next(user['id'] for user in json.load(open(sys.argv[1])) if user['name'] == 'alice'))
PY
)"
"${rust_bin}" --config "${rust_config}" -o json preauthkeys --user "${user_id}" create --reusable --expiration 1h \
  >"${run_dir}/preauth-create.json"
"${rust_bin}" --config "${rust_config}" -o json apikeys create --expiration 1h \
  >"${run_dir}/api-create.json"
api_secret="$(python3 - "${run_dir}/api-create.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1])))
PY
)"
curl --silent --show-error --fail -H "Authorization: Bearer ${api_secret}" \
  "http://127.0.0.1:${listen_port}/api/v1/health" >"${run_dir}/api-health-1.json"
stop_rust
start_rust 2
assert_imported_rows 2
"${rust_bin}" --config "${rust_config}" -o json preauthkeys list \
  >"${run_dir}/preauth-list-2.json"
"${rust_bin}" --config "${rust_config}" -o json apikeys list \
  >"${run_dir}/api-list-2.json"
python3 - "${run_dir}/preauth-create.json" "${run_dir}/preauth-list-2.json" "${run_dir}/api-list-2.json" <<'PY'
import json
import sys

created = json.load(open(sys.argv[1]))
preauth = json.load(open(sys.argv[2]))
api_keys = json.load(open(sys.argv[3]))
assert created['user']['name'] == 'alice', created
assert any(key['id'] == created['id'] and key['user']['name'] == 'alice' for key in preauth), preauth
assert len(api_keys) == 1, api_keys
PY
curl --silent --show-error --fail -H "Authorization: Bearer ${api_secret}" \
  "http://127.0.0.1:${listen_port}/api/v1/health" >"${run_dir}/api-health-2.json"
stop_rust
echo "::endgroup::"

HEADSCALE_GO_BIN="${go_bin}" \
REAL_CLIENT_WORKDIR="${run_dir}/direct-restart" \
  tools/real-client/sqlite-v0295-rust-to-go-export-smoke.sh --direct "${rust_db}"
HEADSCALE_GO_BIN="${go_bin}" \
REAL_CLIENT_WORKDIR="${run_dir}/reverse-export" \
  tools/real-client/sqlite-v0295-rust-to-go-export-smoke.sh "${rust_db}"

echo "pinned v0.29.5 Go to Rust to Go direct SQLite restart and reverse-export smoke passed"
