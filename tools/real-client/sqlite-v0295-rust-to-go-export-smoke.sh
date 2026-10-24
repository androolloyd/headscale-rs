#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

mode="export"
if [[ "${1:-}" == "--direct" ]]; then
  mode="direct"
  shift
fi
if [[ $# -ne 1 ]]; then
  echo "usage: $0 [--direct] RUST_SQLITE_DATABASE" >&2
  exit 2
fi
source_db="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
run_dir="${REAL_CLIENT_WORKDIR:-target/real-client/sqlite-v0295-rust-to-go-export-$(date +%s)-$$}"
mkdir -p "${run_dir}"
run_dir="$(cd "${run_dir}" && pwd)"
go_db="${run_dir}/go-compatible.sqlite"
go_bin="${HEADSCALE_GO_BIN:-${run_dir}/bin/headscale}"
go_socket="/tmp/hsgo-export-${$}.sock"
go_pid=""

stop_go() {
  if [[ -n "${go_pid}" ]]; then
    kill "${go_pid}" >/dev/null 2>&1 || true
    wait "${go_pid}" >/dev/null 2>&1 || true
    go_pid=""
  fi
  rm -f "${go_socket}"
}
trap stop_go EXIT

if [[ "${mode}" == export ]]; then
  python3 tools/real-client/export-go-v0295-sqlite.py "${source_db}" "${go_db}" \
    >"${run_dir}/export.json"
else
  go_db="${source_db}"
fi

python3 - "${source_db}" "${go_db}" "${mode}" <<'PY'
import sqlite3
import sys

source, target = (sqlite3.connect(path) for path in sys.argv[1:3])
if sys.argv[3] == 'direct':
    assert target.execute("SELECT version FROM database_versions WHERE id = 1").fetchone() == ('v0.29.5',)
    assert target.execute("SELECT COUNT(*) FROM sqlite_master WHERE name = '_sqlx_migrations'").fetchone()[0] == 0
else:
    for table in ("users", "pre_auth_keys", "api_keys", "nodes", "policies"):
        columns = [row[1] for row in target.execute(f"PRAGMA table_info({table})")]
        fields = ", ".join('"' + column + '"' for column in columns)
        before = source.execute(f"SELECT {fields} FROM {table} ORDER BY id").fetchall()
        after = target.execute(f"SELECT {fields} FROM {table} ORDER BY id").fetchall()
        assert before == after, f"{table} rows changed in export"
assert target.execute("PRAGMA foreign_key_check").fetchall() == []
assert target.execute("PRAGMA integrity_check").fetchone() == ("ok",)
PY

if [[ -z "${HEADSCALE_GO_BIN:-}" ]]; then
  GOBIN="${run_dir}/bin" go install github.com/juanfont/headscale/cmd/headscale@v0.29.5
fi
"${go_bin}" version >"${run_dir}/go-version.txt"
if ! rg -q 'v0\.29\.5' "${run_dir}/go-version.txt"; then
  echo "expected pinned headscale-go v0.29.5 binary" >&2
  exit 1
fi

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

python3 - "${run_dir}" "${go_db}" "${go_socket}" "${listen_port}" "${metrics_port}" "${grpc_port}" <<'PY'
import json
import os
from pathlib import Path
import sys

root = Path(sys.argv[1])
db = Path(sys.argv[2])
socket = sys.argv[3]
listen, metrics, grpc = sys.argv[4:]
q = json.dumps
noise_key_path = os.environ.get('HEADSCALE_GO_NOISE_PRIVATE_KEY_PATH', str(root / 'noise.key'))
(root / "derp.yaml").write_text("""regions:
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
(root / "go.yaml").write_text(f"""
server_url: {q('http://127.0.0.1:' + listen)}
listen_addr: {q('127.0.0.1:' + listen)}
metrics_listen_addr: {q('127.0.0.1:' + metrics)}
grpc_listen_addr: {q('127.0.0.1:' + grpc)}
grpc_allow_insecure: true
unix_socket: {q(socket)}
private_key_path: {q(str(root / 'private.key'))}
noise:
  private_key_path: {q(noise_key_path)}
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
    - {q(str(root / 'derp.yaml'))}
  auto_update_enabled: false
database:
  type: sqlite
  sqlite:
    path: {q(str(db))}
""")
PY

"${go_bin}" --config "${run_dir}/go.yaml" serve \
  >"${run_dir}/go.stdout" 2>"${run_dir}/go.stderr" &
go_pid="$!"
deadline=$((SECONDS + 20))
until curl --silent --show-error --fail "http://127.0.0.1:${listen_port}/health" \
  >"${run_dir}/health.json" 2>/dev/null; do
  if ! kill -0 "${go_pid}" >/dev/null 2>&1 || ((SECONDS >= deadline)); then
    tail -n 60 "${run_dir}/go.stderr" >&2
    echo "headscale-go v0.29.5 failed to start on exported Rust database" >&2
    exit 1
  fi
  sleep 0.2
done

if [[ -n "${HEADSCALE_GO_EXPECT_NOISE_KEY_FILE:-}" ]]; then
  curl --silent --show-error --fail "http://127.0.0.1:${listen_port}/key?v=138" \
    >"${run_dir}/go-key.json"
  python3 - "${HEADSCALE_GO_EXPECT_NOISE_KEY_FILE}" "${run_dir}/go-key.json" <<'PY'
import json
import sys
before, after = [json.load(open(path)) for path in sys.argv[1:]]
assert before == after, (before, after)
PY
fi

"${go_bin}" --config "${run_dir}/go.yaml" -o json users list >"${run_dir}/users.json"
"${go_bin}" --config "${run_dir}/go.yaml" -o json nodes list >"${run_dir}/nodes.json"
"${go_bin}" --config "${run_dir}/go.yaml" -o json nodes list-routes >"${run_dir}/routes.json"
"${go_bin}" --config "${run_dir}/go.yaml" -o json preauthkeys list >"${run_dir}/preauthkeys.json"
"${go_bin}" --config "${run_dir}/go.yaml" -o json apikeys list >"${run_dir}/apikeys.json"

python3 - "${go_db}" "${run_dir}" <<'PY'
import json
from pathlib import Path
import sqlite3
import sys

db = sqlite3.connect(sys.argv[1])
root = Path(sys.argv[2])
users = json.loads((root / "users.json").read_text()) or []
nodes = json.loads((root / "nodes.json").read_text()) or []
routes = json.loads((root / "routes.json").read_text()) or []
preauthkeys = json.loads((root / "preauthkeys.json").read_text()) or []
apikeys = json.loads((root / "apikeys.json").read_text()) or []
assert len(users) == db.execute("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL").fetchone()[0]
assert len(nodes) == db.execute("SELECT COUNT(*) FROM nodes WHERE deleted_at IS NULL").fetchone()[0]
assert len(preauthkeys) == db.execute("SELECT COUNT(*) FROM pre_auth_keys").fetchone()[0]
assert len(apikeys) == db.execute("SELECT COUNT(*) FROM api_keys").fetchone()[0]
approved = db.execute("SELECT COUNT(*) FROM nodes WHERE approved_routes LIKE '%10.77.0.0/24%'").fetchone()[0]
if approved:
    assert sum("10.77.0.0/24" in row.get("approved_routes", []) for row in routes) == approved, routes
PY

stop_go
echo "pinned v0.29.5 Rust-to-Go SQLite ${mode}/start smoke passed: ${run_dir}"
