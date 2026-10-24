#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"
if [[ $# -gt 1 ]]; then
  echo "usage: $0 [EXISTING_GO_SCHEMA_SQLITE_DATABASE]" >&2
  exit 2
fi

run_dir="${REAL_CLIENT_WORKDIR:-target/real-client/sqlite-v0295-fresh-rust-to-go-$(date +%s)-$$}"
mkdir -p "${run_dir}"
run_dir="$(cd "${run_dir}" && pwd)"
db="${run_dir}/fresh.sqlite"
mode="fresh"
if [[ $# -eq 1 ]]; then
  db="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
  mode="existing"
fi
config="${run_dir}/rust.yaml"
socket="/tmp/hsrs-fresh-go-${$}.sock"
rust_bin="${RUST_HEADSCALE_BIN:-${repo_root}/target/debug/headscale}"
rust_pid=""

stop_rust() {
  if [[ -n "${rust_pid}" ]]; then
    kill "${rust_pid}" >/dev/null 2>&1 || true
    wait "${rust_pid}" >/dev/null 2>&1 || true
    rust_pid=""
  fi
  rm -f "${socket}"
}
trap stop_rust EXIT

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

python3 - "${config}" "${db}" "${run_dir}" "${socket}" \
  "${listen_port}" "${metrics_port}" "${grpc_port}" <<'PY'
import json
from pathlib import Path
import sys

config, db, root, socket = sys.argv[1:5]
listen, metrics, grpc = sys.argv[5:8]
q = json.dumps
Path(config).write_text(f"""
server_url: {q('http://127.0.0.1:' + listen)}
listen_addr: {q('127.0.0.1:' + listen)}
metrics_listen_addr: {q('127.0.0.1:' + metrics)}
grpc_listen_addr: {q('127.0.0.1:' + grpc)}
grpc_allow_insecure: true
unix_socket: {q(socket)}
noise:
  private_key_path: {q(str(Path(root) / 'rust-noise.key'))}
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
"${rust_bin}" --config "${config}" serve \
  >"${run_dir}/rust.stdout" 2>"${run_dir}/rust.stderr" &
rust_pid="$!"
deadline=$((SECONDS + 20))
until curl --silent --show-error --fail \
  "http://127.0.0.1:${listen_port}/health" >"${run_dir}/health.json" 2>/dev/null; do
  if ! kill -0 "${rust_pid}" >/dev/null 2>&1 || ((SECONDS >= deadline)); then
    tail -n 60 "${run_dir}/rust.stderr" >&2
    echo "fresh Rust server did not start" >&2
    exit 1
  fi
  sleep 0.2
done
curl --silent --show-error --fail "http://127.0.0.1:${listen_port}/key?v=138" \
  >"${run_dir}/rust-key.json"

if [[ "${mode}" == fresh ]]; then
  "${rust_bin}" --config "${config}" users create alice >"${run_dir}/user-create.stdout"
  "${rust_bin}" --config "${config}" -o json users list >"${run_dir}/users.json"
  user_id="$(python3 - "${run_dir}/users.json" <<'PY'
import json
import sys
print(next(user['id'] for user in json.load(open(sys.argv[1])) if user['name'] == 'alice'))
PY
  )"
  "${rust_bin}" --config "${config}" -o json preauthkeys --user "${user_id}" create --reusable --expiration 1h \
    >"${run_dir}/preauth-create.json"
  "${rust_bin}" --config "${config}" -o json apikeys create --expiration 1h \
    >"${run_dir}/api-create.json"
else
  "${rust_bin}" --config "${config}" -o json users list >"${run_dir}/users.json"
  "${rust_bin}" --config "${config}" -o json nodes list >"${run_dir}/nodes.json"
  python3 - "${db}" "${run_dir}/users.json" "${run_dir}/nodes.json" <<'PY'
import json
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as db:
    users = json.load(open(sys.argv[2])) or []
    nodes = json.load(open(sys.argv[3])) or []
    assert len(users) == db.execute("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL").fetchone()[0]
    assert len(nodes) == db.execute("SELECT COUNT(*) FROM nodes WHERE deleted_at IS NULL").fetchone()[0]
PY
fi
stop_rust

python3 - "${db}" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as db:
    tables = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert '_sqlx_migrations' not in tables, tables
    assert 'sessions' not in tables, tables
    assert db.execute("SELECT version FROM database_versions WHERE id=1").fetchone() == ('v0.29.5',)
PY
test -f "${db}.rust-aux.sqlite"

HEADSCALE_GO_NOISE_PRIVATE_KEY_PATH="${run_dir}/rust-noise.key" \
HEADSCALE_GO_EXPECT_NOISE_KEY_FILE="${run_dir}/rust-key.json" \
REAL_CLIENT_WORKDIR="${run_dir}/direct-restart" \
  tools/real-client/sqlite-v0295-rust-to-go-export-smoke.sh --direct "${db}"

echo "${mode} Rust SQLite primary file passed pinned v0.29.5 Go direct restart: ${run_dir}"
