#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"
: "${HEADSCALE_DB_POSTGRES_TEST_URL:?set a local Postgres admin URL}"

run_dir="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-v0295-release-upgrade-$(date +%s)-$$}"
mkdir -p "${run_dir}"
run_dir="$(cd "${run_dir}" && pwd)"
rust_bin="${RUST_HEADSCALE_BIN:-${repo_root}/target/debug/headscale}"
go_bin="${HEADSCALE_GO_BIN:-${run_dir}/bin/headscale}"
name_prefix="hsrs_rel_${$}"
template_name="${name_prefix}_template"
go_name="${name_prefix}_go"
rust_name="${name_prefix}_rust"
server_pid=""
server_socket="/tmp/hsrs-rel-${$}.sock"
created_names=()

admin_url="$(python3 - <<'PY'
import os
from urllib.parse import urlsplit, urlunsplit
url = urlsplit(os.environ['HEADSCALE_DB_POSTGRES_TEST_URL'])
if url.scheme not in ('postgres', 'postgresql') or not url.hostname:
    raise SystemExit('HEADSCALE_DB_POSTGRES_TEST_URL must be a Postgres URL')
print(urlunsplit((url.scheme, url.netloc, '/postgres', url.query, url.fragment)))
PY
)"
db_url() {
  python3 - "$1" <<'PY'
import os
import sys
from urllib.parse import urlsplit, urlunsplit
url = urlsplit(os.environ['HEADSCALE_DB_POSTGRES_TEST_URL'])
print(urlunsplit((url.scheme, url.netloc, '/' + sys.argv[1], url.query, url.fragment)))
PY
}

stop_server() {
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
    server_pid=""
  fi
  rm -f "${server_socket}"
}
cleanup() {
  stop_server
  local name
  for name in "${created_names[@]}"; do
    psql "${admin_url}" -v ON_ERROR_STOP=1 \
      -c "DROP DATABASE IF EXISTS ${name} WITH (FORCE)" \
      >>"${run_dir}/postgres-drop.stdout" 2>>"${run_dir}/postgres-drop.stderr" || true
  done
}
trap cleanup EXIT

if [[ -z "${HEADSCALE_GO_BIN:-}" ]]; then
  GOBIN="${run_dir}/bin" go install github.com/juanfont/headscale/cmd/headscale@v0.29.5
fi
"${go_bin}" version >"${run_dir}/go-version.txt"
rg -q 'v0\.29\.5' "${run_dir}/go-version.txt"
cargo build -p headscale-cli --features postgres-sqlx --bin headscale

read -r listen_port metrics_port grpc_port < <(python3 - <<'PY'
import socket
sockets = []
for _ in range(3):
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    sockets.append(sock)
print(*(sock.getsockname()[1] for sock in sockets))
for sock in sockets:
    sock.close()
PY
)

cat >"${run_dir}/derp.yaml" <<'YAML'
regions:
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
YAML

make_config() {
  local label="$1" implementation="$2" name="$3"
  python3 - "${run_dir}" "${label}" "${implementation}" "$(db_url "${name}")" \
    "${server_socket}" "${listen_port}" "${metrics_port}" "${grpc_port}" <<'PY'
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, unquote, urlsplit

root = Path(sys.argv[1])
label, implementation, database_url, socket, listen, metrics, grpc = sys.argv[2:]
url = urlsplit(database_url)
q = json.dumps
common = f'''server_url: {q('http://127.0.0.1:' + listen)}
listen_addr: {q('127.0.0.1:' + listen)}
metrics_listen_addr: {q('127.0.0.1:' + metrics)}
grpc_listen_addr: {q('127.0.0.1:' + grpc)}
grpc_allow_insecure: true
unix_socket: {q(socket)}
noise:
  private_key_path: {q(str(root / 'noise.key'))}
prefixes:
  allocation: sequential
  v4: 100.64.0.0/10
dns:
  magic_dns: false
  base_domain: tail.test
  override_local_dns: false
'''
go = f'''private_key_path: {q(str(root / 'private.key'))}
logtail:
  enabled: false
derp:
  server:
    enabled: false
  urls: []
  paths:
    - {q(str(root / 'derp.yaml'))}
  auto_update_enabled: false
'''
rust = '''policy:
  mode: database
'''
database = f'''database:
  type: postgres
  postgres:
    host: {q(url.hostname or '')}
    port: {url.port or 5432}
    name: {q(url.path.lstrip('/'))}
    user: {q(unquote(url.username or ''))}
    pass: {q(unquote(url.password or ''))}
    ssl: {q(parse_qs(url.query).get('sslmode', ['disable'])[0])}
'''
path = root / f'{label}.yaml'
path.write_text(common + (go if implementation == 'go' else rust) + database)
path.chmod(0o600)
PY
}

start_server() {
  local label="$1" implementation="$2" bin="$3" name="$4"
  make_config "${label}" "${implementation}" "${name}"
  "${bin}" --config "${run_dir}/${label}.yaml" serve \
    >"${run_dir}/${label}.stdout" 2>"${run_dir}/${label}.stderr" &
  server_pid="$!"
  local deadline=$((SECONDS + 30))
  until curl --silent --show-error --fail "http://127.0.0.1:${listen_port}/health" \
    >"${run_dir}/${label}-health.json" 2>/dev/null; do
    if ! kill -0 "${server_pid}" >/dev/null 2>&1 || ((SECONDS >= deadline)); then
      cat "${run_dir}/${label}.stderr" >&2
      echo "${label} failed to start" >&2
      exit 1
    fi
    sleep 0.2
  done
  "${bin}" --config "${run_dir}/${label}.yaml" -o json nodes list \
    >"${run_dir}/${label}-nodes.json"
}

psql "${admin_url}" -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${template_name}" \
  >"${run_dir}/postgres-create-template.stdout"
created_names+=("${template_name}")
start_server go-template go "${go_bin}" "${template_name}"
stop_server

# Start from the exact schema and migration ledger produced by pinned Go.
# Recreate the two historical release faults in rows and rewind only the
# release migration markers and version stamp before cloning the database.
psql "$(db_url "${template_name}")" -v ON_ERROR_STOP=1 <<'SQL'
INSERT INTO users (id, name, display_name, created_at, updated_at)
VALUES (10, 'alice', 'Alice', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);
INSERT INTO pre_auth_keys (id, user_id, tags, reusable, used, created_at)
VALUES (20, 10, '[]', TRUE, TRUE, CURRENT_TIMESTAMP);
INSERT INTO nodes
    (id, machine_key, node_key, disco_key, endpoints, host_info, ipv4, ipv6,
     hostname, given_name, user_id, register_method, tags, auth_key_id,
     expiry, approved_routes, created_at, updated_at)
SELECT n,
       'mkey:a0ab77456320823945ae0331823e3c0d516fae9585bd42698dfa1ac3d7679e0' || n,
       'nodekey:7c84167ab68f494942de14deb83587fd841843de2bac105b6c670048c160550' || n,
       'discokey:53075b3c6cad3b62a2a29caea61beeb93f66b8c75cb89dac465236a5bbf5770' || n,
       '[]', '{}', '100.64.0.' || n, 'fd7a:115c:a1e0::' || n,
       'node' || n, 'node' || n,
       CASE WHEN n = 3 THEN 10 ELSE NULL END,
       CASE WHEN n = 4 THEN 'cli' ELSE 'authkey' END,
       CASE WHEN n = 2 THEN '["tag:server"]' ELSE 'null' END,
       CASE WHEN n IN (1, 2) THEN 20 ELSE NULL END,
       CASE WHEN n IN (2, 3) THEN '2020-06-01 00:00:00+00'::timestamptz ELSE NULL END,
       '[]', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
FROM generate_series(1, 4) AS n;
DELETE FROM migrations WHERE id IN
    ('202606181200-recover-null-tags-node-user-id',
     '202607241200-clear-tagged-node-expiry');
UPDATE database_versions SET version = 'v0.29.0' WHERE id = 1;
SQL

for name in "${go_name}" "${rust_name}"; do
  psql "${admin_url}" -v ON_ERROR_STOP=1 \
    -c "CREATE DATABASE ${name} TEMPLATE ${template_name}" \
    >"${run_dir}/postgres-create-${name}.stdout"
  created_names+=("${name}")
done

snapshot() {
  local label="$1" name="$2"
  psql "$(db_url "${name}")" -At -v ON_ERROR_STOP=1 -c \
    "SELECT json_build_object(
      'version', (SELECT version FROM database_versions WHERE id = 1),
      'migrations', (SELECT array_agg(id) FROM migrations),
      'nodes', (SELECT json_agg(row_to_json(n)) FROM
        (SELECT id, user_id, tags, expiry IS NOT NULL AS has_expiry
         FROM nodes ORDER BY id) n))" >"${run_dir}/${label}-state.json"
}

compare_states() {
  local label="$1"
  snapshot "${label}-go" "${go_name}"
  snapshot "${label}-rust" "${rust_name}"
  python3 - "${run_dir}/${label}-go-state.json" "${run_dir}/${label}-rust-state.json" <<'PY'
import json
import sys

states = [json.load(open(path)) for path in sys.argv[1:]]
for state in states:
    assert state['version'] == 'v0.29.5', state
    migrations = set(state['migrations'])
    assert '202606181200-recover-null-tags-node-user-id' in migrations, state
    assert '202607241200-clear-tagged-node-expiry' in migrations, state
    for node in state['nodes']:
        node['tags'] = json.loads(node['tags'] or '[]') or []
    assert [(n['id'], n['user_id'], n['has_expiry']) for n in state['nodes']] == [
        (1, 10, False), (2, None, False), (3, 10, True), (4, None, False)
    ], state
assert states[0]['nodes'] == states[1]['nodes'], states
PY
}

start_server go-upgrade go "${go_bin}" "${go_name}"
stop_server
start_server rust-upgrade rust "${rust_bin}" "${rust_name}"
stop_server
compare_states upgraded

start_server go-on-rust go "${go_bin}" "${rust_name}"
stop_server
start_server rust-on-go rust "${rust_bin}" "${go_name}"
stop_server
compare_states cross-started

python3 - "${run_dir}" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
for label in ('go-upgrade', 'rust-upgrade', 'go-on-rust', 'rust-on-go'):
    nodes = json.loads((root / f'{label}-nodes.json').read_text()) or []
    assert [node['id'] for node in nodes] == [1, 2, 3, 4], (label, nodes)
    assert [node.get('user', {}).get('id') if node.get('user') else None for node in nodes] == [
        10, 2147455555, 10, None
    ], (label, nodes)
    assert [node.get('tags') or [] for node in nodes] == [
        [], ['tag:server'], [], []
    ], (label, nodes)
PY

echo "pinned v0.29.5 Postgres release upgrade and bidirectional direct restarts passed: ${run_dir}"
