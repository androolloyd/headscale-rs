#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

if [[ -z "${HEADSCALE_DB_POSTGRES_TEST_URL:-}" ]]; then
  echo "HEADSCALE_DB_POSTGRES_TEST_URL is required for this import smoke" >&2
  exit 2
fi

run_dir="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-v0295-go-to-rust-import-$(date +%s)-$$}"
mkdir -p "${run_dir}"
run_dir="$(cd "${run_dir}" && pwd)"
archive="${run_dir}/headscale-go-v0.29.5.dump"
rust_config="${run_dir}/rust.yaml"
rust_socket="/tmp/hsrs-v0295-pg-${$}.sock"
rust_bin="${RUST_HEADSCALE_BIN:-${repo_root}/target/debug/headscale}"
database_name="hsrs_v0295_import_$(date +%s)_$$"
rust_pid=""
go_pid=""
go_socket="/tmp/hsgo-v0295-pg-${$}.sock"
database_created=false

admin_url="$(python3 - <<'PY'
import os
from urllib.parse import urlsplit, urlunsplit
url = urlsplit(os.environ['HEADSCALE_DB_POSTGRES_TEST_URL'])
print(urlunsplit((url.scheme, url.netloc, '/postgres', url.query, url.fragment)))
PY
)"
import_url="$(python3 - "${database_name}" <<'PY'
import os
import sys
from urllib.parse import urlsplit, urlunsplit
url = urlsplit(os.environ['HEADSCALE_DB_POSTGRES_TEST_URL'])
print(urlunsplit((url.scheme, url.netloc, '/' + sys.argv[1], url.query, url.fragment)))
PY
)"

stop_rust() {
  if [[ -n "${rust_pid}" ]]; then
    kill "${rust_pid}" >/dev/null 2>&1 || true
    wait "${rust_pid}" >/dev/null 2>&1 || true
    rust_pid=""
  fi
  rm -f "${rust_socket}"
}

cleanup() {
  stop_rust
  if [[ -n "${go_pid}" ]]; then
    kill "${go_pid}" >/dev/null 2>&1 || true
    wait "${go_pid}" >/dev/null 2>&1 || true
  fi
  rm -f "${go_socket}"
  if [[ "${database_created}" == true ]]; then
    psql "${admin_url}" -v ON_ERROR_STOP=1 \
      -c "DROP DATABASE IF EXISTS ${database_name} WITH (FORCE)" \
      >"${run_dir}/postgres-drop.stdout" \
      2>"${run_dir}/postgres-drop.stderr" || true
  fi
}
trap cleanup EXIT

echo "::group::create pinned Go v0.29.5 Postgres state with a stock client"
HEADSCALE_GO_VERSION=v0.29.5 \
REAL_CLIENT_WORKDIR="${run_dir}/go" \
REAL_CLIENT_POSTGRES_EXPORT_PATH="${archive}" \
REAL_CLIENT_IMPORT_SNAPSHOT_AFTER_LOGIN=true \
REAL_CLIENT_CLIENT_COUNT=2 \
REAL_CLIENT_ADVERTISE_ROUTES=10.77.0.0/24 \
REAL_CLIENT_APPROVE_ROUTES=10.77.0.0/24 \
REAL_CLIENT_EXPECT_PEER_COUNT=1 \
  tools/real-client/postgres-authkey-headscale-go-smoke.sh
test -s "${archive}"
go_bin="$(find "${run_dir}/go" -path '*/bin/headscale' -type f -print -quit)"
if [[ -z "${go_bin}" ]]; then
  echo "pinned Go stock-client smoke did not leave a Go binary" >&2
  exit 1
fi
echo "::endgroup::"

echo "::group::restore isolated Postgres import database"
psql "${admin_url}" -v ON_ERROR_STOP=1 \
  -c "CREATE DATABASE ${database_name}" \
  >"${run_dir}/postgres-create.stdout"
database_created=true
pg_restore --no-owner --no-acl --dbname="${import_url}" "${archive}"
test "$(psql "${import_url}" -At -c 'SELECT version FROM database_versions WHERE id = 1')" = v0.29.5
test "$(psql "${import_url}" -At -c 'SELECT COUNT(*) FROM users')" = 1
test "$(psql "${import_url}" -At -c 'SELECT COUNT(*) FROM nodes')" = 2
test "$(psql "${import_url}" -At -c "SELECT COUNT(*) FROM nodes WHERE approved_routes LIKE '%10.77.0.0/24%'")" = 1
echo "::endgroup::"

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

python3 - "${rust_config}" "${run_dir}" "${rust_socket}" "${import_url}" \
  "${listen_port}" "${metrics_port}" "${grpc_port}" <<'PY'
import json
import pathlib
import sys
from urllib.parse import parse_qs, unquote, urlsplit

config, root, socket, database_url = sys.argv[1:5]
listen, metrics, grpc = sys.argv[5:8]
url = urlsplit(database_url)
ssl = parse_qs(url.query).get('sslmode', ['disable'])[0]
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
  type: postgres
  postgres:
    host: {q(url.hostname or '')}
    port: {url.port or 5432}
    name: {q(url.path.lstrip('/'))}
    user: {q(unquote(url.username or ''))}
    pass: {q(unquote(url.password or ''))}
    ssl: {q(ssl)}
policy:
  mode: database
""")
pathlib.Path(config).chmod(0o600)
PY

cargo build -p headscale-cli --features postgres-sqlx --bin headscale

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
      echo "headscale-rs did not start on the v0.29.5 Go Postgres database" >&2
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
names = {user['name'] for user in users}
if attempt == 1:
    assert 'alice' in names, users
else:
    assert 'imported-alice' in names, users
    assert 'imported-after-switch' in names, users
assert len(nodes) == 2, nodes
assert all(node['user']['name'] == ('alice' if attempt == 1 else 'imported-alice') for node in nodes), nodes
assert all(node['pre_auth_key']['id'] > 0 for node in nodes), nodes
assert sum('10.77.0.0/24' in node['approved_routes'] for node in nodes) == 1, nodes
assert all('10.77.0.0/24' in node['available_routes'] for node in nodes), nodes
if attempt == 2:
    assert nodes[0]['given_name'] == 'imported-node', nodes
PY
}

echo "::group::import and mutate through headscale-rs production Postgres process"
start_rust 1
assert_imported_rows 1
"${rust_bin}" --config "${rust_config}" users create imported-after-switch \
  >"${run_dir}/users-create.stdout"
"${rust_bin}" --config "${rust_config}" users rename --name alice --new-name imported-alice \
  >"${run_dir}/users-rename.stdout"
node_id="$(python3 - "${run_dir}/nodes-1.json" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1]))[0]['id'])
PY
)"
"${rust_bin}" --config "${rust_config}" nodes rename imported-node --identifier "${node_id}" \
  >"${run_dir}/nodes-rename.stdout"
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
assert created['user']['name'] == 'imported-alice', created
assert any(key['id'] == created['id'] and key['user']['name'] == 'imported-alice' for key in preauth), preauth
assert len(api_keys) == 1, api_keys
PY
curl --silent --show-error --fail -H "Authorization: Bearer ${api_secret}" \
  "http://127.0.0.1:${listen_port}/api/v1/health" >"${run_dir}/api-health-2.json"
stop_rust
echo "::endgroup::"

echo "::group::restart pinned Go on Rust-mutated Postgres database"
python3 - "${run_dir}" "${go_socket}" "${import_url}" \
  "${listen_port}" "${metrics_port}" "${grpc_port}" <<'PY'
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, unquote, urlsplit

root = Path(sys.argv[1])
socket = sys.argv[2]
url = urlsplit(sys.argv[3])
listen, metrics, grpc = sys.argv[4:]
ssl = parse_qs(url.query).get('sslmode', ['disable'])[0]
q = json.dumps
(root / 'derp-go.yaml').write_text('''regions:
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
''')
(root / 'go-restart.yaml').write_text(f'''
server_url: {q('http://127.0.0.1:' + listen)}
listen_addr: {q('127.0.0.1:' + listen)}
metrics_listen_addr: {q('127.0.0.1:' + metrics)}
grpc_listen_addr: {q('127.0.0.1:' + grpc)}
grpc_allow_insecure: true
unix_socket: {q(socket)}
private_key_path: {q(str(root / 'go-restart-private.key'))}
noise:
  private_key_path: {q(str(root / 'go-restart-noise.key'))}
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
    - {q(str(root / 'derp-go.yaml'))}
  auto_update_enabled: false
database:
  type: postgres
  postgres:
    host: {q(url.hostname or '')}
    port: {url.port or 5432}
    name: {q(url.path.lstrip('/'))}
    user: {q(unquote(url.username or ''))}
    pass: {q(unquote(url.password or ''))}
    ssl: {q(ssl)}
''')
(root / 'go-restart.yaml').chmod(0o600)
PY

"${go_bin}" --config "${run_dir}/go-restart.yaml" serve \
  >"${run_dir}/go-restart.stdout" 2>"${run_dir}/go-restart.stderr" &
go_pid="$!"
deadline=$((SECONDS + 20))
until curl --silent --show-error --fail \
  "http://127.0.0.1:${listen_port}/health" >"${run_dir}/go-restart-health.json" 2>/dev/null; do
  if ! kill -0 "${go_pid}" >/dev/null 2>&1 || ((SECONDS >= deadline)); then
    tail -n 60 "${run_dir}/go-restart.stderr" >&2
    echo "pinned Go did not restart on the Rust-mutated Postgres database" >&2
    exit 1
  fi
  sleep 0.2
done

for command in users nodes preauthkeys apikeys; do
  "${go_bin}" --config "${run_dir}/go-restart.yaml" -o json "${command}" list \
    >"${run_dir}/go-restart-${command}.json"
done
"${go_bin}" --config "${run_dir}/go-restart.yaml" -o json nodes list-routes \
  >"${run_dir}/go-restart-routes.json"
python3 - "${run_dir}" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
def read(name):
    return json.loads((root / f'go-restart-{name}.json').read_text())

users, nodes, preauthkeys, apikeys, routes = (
    read(name) for name in ('users', 'nodes', 'preauthkeys', 'apikeys', 'routes')
)
assert {user['name'] for user in users} == {'imported-alice', 'imported-after-switch'}, users
assert len(nodes) == 2 and all(node['user']['name'] == 'imported-alice' for node in nodes), nodes
assert any(node['given_name'] == 'imported-node' for node in nodes), nodes
assert len(preauthkeys) == 2, preauthkeys
assert len(apikeys) == 1, apikeys
assert sum('10.77.0.0/24' in row.get('approved_routes', []) for row in routes) == 1, routes
PY
echo "::endgroup::"

echo "pinned v0.29.5 Go to Rust to Go Postgres process restart smoke passed"
