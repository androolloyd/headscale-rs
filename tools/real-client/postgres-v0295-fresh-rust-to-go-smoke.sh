#!/usr/bin/env bash
# Fresh production Postgres: Rust writes rows, pinned Go and Rust reopen them.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"
: "${HEADSCALE_DB_POSTGRES_TEST_URL:?set a local Postgres admin URL}"

run_dir="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-v0295-fresh-rust-to-go-$(date +%s)-$$}"
mkdir -p "${run_dir}"
run_dir="$(cd "${run_dir}" && pwd)"
rust_bin="${RUST_HEADSCALE_BIN:-${repo_root}/target/debug/headscale}"
go_bin="${HEADSCALE_GO_BIN:-${run_dir}/bin/headscale}"
database_name="hsrs_v0295_fresh_${$}"
rust_config="${run_dir}/rust.yaml"
go_config="${run_dir}/go.yaml"
rust_socket="/tmp/hsrs-v0295-fresh-${$}.sock"
go_socket="/tmp/hsgo-v0295-fresh-${$}.sock"
server_pid=""
database_created=false

database_urls=()
while IFS= read -r database_url_part; do
  database_urls+=("${database_url_part}")
done < <(python3 - "${database_name}" <<'PY'
import os
import sys
from urllib.parse import urlsplit, urlunsplit
url = urlsplit(os.environ['HEADSCALE_DB_POSTGRES_TEST_URL'])
if url.scheme not in ('postgres', 'postgresql') or not url.hostname:
    raise SystemExit('HEADSCALE_DB_POSTGRES_TEST_URL must be a Postgres URL')
print(urlunsplit((url.scheme, url.netloc, '/postgres', url.query, url.fragment)))
print(urlunsplit((url.scheme, url.netloc, '/' + sys.argv[1], url.query, url.fragment)))
PY
)
admin_url="${database_urls[0]}"
database_url="${database_urls[1]}"

stop_server() {
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
    server_pid=""
  fi
}
cleanup() {
  stop_server
  rm -f "${rust_socket}" "${go_socket}"
  if [[ "${database_created}" == true ]]; then
    psql "${admin_url}" -v ON_ERROR_STOP=1 \
      -c "DROP DATABASE IF EXISTS ${database_name} WITH (FORCE)" \
      >"${run_dir}/postgres-drop.stdout" 2>"${run_dir}/postgres-drop.stderr" || true
  fi
}
trap cleanup EXIT

if [[ -z "${HEADSCALE_GO_BIN:-}" ]]; then
  GOBIN="${run_dir}/bin" go install github.com/juanfont/headscale/cmd/headscale@v0.29.5
fi
"${go_bin}" version >"${run_dir}/go-version.txt"
rg -q 'v0\.29\.5' "${run_dir}/go-version.txt"
cargo build -p headscale-cli --features postgres-sqlx --bin headscale

psql "${admin_url}" -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${database_name}" \
  >"${run_dir}/postgres-create.stdout"
database_created=true

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

python3 - "${run_dir}" "${database_url}" "${rust_socket}" "${go_socket}" \
  "${listen_port}" "${metrics_port}" "${grpc_port}" <<'PY'
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, unquote, urlsplit

root = Path(sys.argv[1])
url = urlsplit(sys.argv[2])
rust_socket, go_socket = sys.argv[3:5]
listen, metrics, grpc = sys.argv[5:]
ssl = parse_qs(url.query).get('sslmode', ['disable'])[0]
q = json.dumps
database = f'''database:
  type: postgres
  postgres:
    host: {q(url.hostname or '')}
    port: {url.port or 5432}
    name: {q(url.path.lstrip('/'))}
    user: {q(unquote(url.username or ''))}
    pass: {q(unquote(url.password or ''))}
    ssl: {q(ssl)}
'''
common = f'''server_url: {q('http://127.0.0.1:' + listen)}
listen_addr: {q('127.0.0.1:' + listen)}
metrics_listen_addr: {q('127.0.0.1:' + metrics)}
grpc_listen_addr: {q('127.0.0.1:' + grpc)}
grpc_allow_insecure: true
dns:
  magic_dns: false
  base_domain: tail.test
  override_local_dns: false
'''
noise = q(str(root / 'noise.key'))
(root / 'rust.yaml').write_text(common + f'''unix_socket: {q(rust_socket)}
noise:
  private_key_path: {noise}
policy:
  mode: database
''' + database)
(root / 'derp.yaml').write_text('''regions:
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
(root / 'go.yaml').write_text(common + f'''unix_socket: {q(go_socket)}
private_key_path: {q(str(root / 'go-private.key'))}
noise:
  private_key_path: {noise}
prefixes:
  allocation: sequential
  v4: 100.64.0.0/10
logtail:
  enabled: false
derp:
  server:
    enabled: false
  urls: []
  paths:
    - {q(str(root / 'derp.yaml'))}
  auto_update_enabled: false
''' + database)
for path in (root / 'rust.yaml', root / 'go.yaml'):
    path.chmod(0o600)
PY

start_server() {
  local label="$1" bin="$2" config="$3" deadline=$((SECONDS + 25))
  "${bin}" --config "${config}" serve \
    >"${run_dir}/${label}.stdout" 2>"${run_dir}/${label}.stderr" &
  server_pid="$!"
  until curl --silent --show-error --fail \
    "http://127.0.0.1:${listen_port}/health" >"${run_dir}/${label}-health.json" 2>/dev/null; do
    if ! kill -0 "${server_pid}" >/dev/null 2>&1 || ((SECONDS >= deadline)); then
      tail -n 80 "${run_dir}/${label}.stderr" >&2
      echo "${label} did not start" >&2
      return 1
    fi
    sleep 0.2
  done
  curl --silent --show-error --fail "http://127.0.0.1:${listen_port}/key?v=138" \
    >"${run_dir}/${label}-key.json"
}

assert_gateway_api_key() {
  local label="$1" key="$2" expected_user="$3"
  curl --silent --show-error --fail \
    --header "Authorization: Bearer ${key}" \
    "http://127.0.0.1:${listen_port}/api/v1/user" \
    >"${run_dir}/${label}-api-auth.json"
  python3 - "${run_dir}/${label}-api-auth.json" "${expected_user}" <<'PY'
import json
import sys
response = json.load(open(sys.argv[1]))
assert any(user.get('name') == sys.argv[2] for user in response.get('users', [])), response
PY
}

start_server rust-first "${rust_bin}" "${rust_config}"
"${rust_bin}" --config "${rust_config}" users create alice \
  >"${run_dir}/rust-user-create.stdout"
"${rust_bin}" --config "${rust_config}" -o json users list \
  >"${run_dir}/rust-users.json"
user_id="$(python3 - "${run_dir}/rust-users.json" <<'PY'
import json
import sys
print(next(user['id'] for user in json.load(open(sys.argv[1])) if user['name'] == 'alice'))
PY
)"
"${rust_bin}" --config "${rust_config}" -o json preauthkeys --user "${user_id}" \
  create --reusable --expiration 1h >"${run_dir}/rust-preauth-create.json"
"${rust_bin}" --config "${rust_config}" -o json apikeys create --expiration 1h \
  >"${run_dir}/rust-api-create.json"
rust_api_secret="$(python3 - "${run_dir}/rust-api-create.json" <<'PY'
import json
import sys
key = json.load(open(sys.argv[1]))
assert isinstance(key, str) and key.startswith('hskey-api-'), key
print(key)
PY
)"
assert_gateway_api_key rust-first "${rust_api_secret}" alice
auth_id=hskey-authreq-abcdefghijklmnopqrstuvwx
"${rust_bin}" --config "${rust_config}" debug create-node \
  --user alice --key "${auth_id}" --name fresh-router --route 10.77.0.0/24 \
  >"${run_dir}/rust-debug-create.stdout"
"${rust_bin}" --config "${rust_config}" auth register \
  --user alice --auth-id "${auth_id}" >"${run_dir}/rust-register.stdout"
"${rust_bin}" --config "${rust_config}" -o json nodes list \
  >"${run_dir}/rust-nodes.json"
node_id="$(python3 - "${run_dir}/rust-nodes.json" <<'PY'
import json
import sys
nodes = json.load(open(sys.argv[1]))
assert len(nodes) == 1 and nodes[0]['name'] == 'fresh-router', nodes
print(nodes[0]['id'])
PY
)"
"${rust_bin}" --config "${rust_config}" nodes approve-routes \
  --identifier "${node_id}" --routes 10.77.0.0/24 \
  >"${run_dir}/rust-approve-routes.stdout"
"${rust_bin}" --config "${rust_config}" -o json nodes expire \
  --identifier "${node_id}" --expiry 2100-01-01T00:00:00.123456789Z \
  >"${run_dir}/rust-scheduled-expiry.json"
stop_server

test "$(psql "${database_url}" -At -c 'SELECT version FROM database_versions WHERE id=1')" = v0.29.5
start_server go "${go_bin}" "${go_config}"
assert_gateway_api_key go-rust-key "${rust_api_secret}" alice
for command in users nodes preauthkeys apikeys; do
  "${go_bin}" --config "${go_config}" -o json "${command}" list \
    >"${run_dir}/go-${command}.json"
done
"${go_bin}" --config "${go_config}" -o json nodes list-routes \
  >"${run_dir}/go-routes.json"
"${go_bin}" --config "${go_config}" users rename --name alice --new-name go-alice \
  >"${run_dir}/go-user-rename.stdout"
"${go_bin}" --config "${go_config}" nodes rename go-router --identifier "${node_id}" \
  >"${run_dir}/go-node-rename.stdout"
"${go_bin}" --config "${go_config}" -o json apikeys create --expiration 1h \
  >"${run_dir}/go-api-create.json"
go_api_secret="$(python3 - "${run_dir}/go-api-create.json" <<'PY'
import json
import sys
key = json.load(open(sys.argv[1]))
assert isinstance(key, str) and key.startswith('hskey-api-'), key
print(key)
PY
)"
assert_gateway_api_key go-go-key "${go_api_secret}" go-alice
"${go_bin}" --config "${go_config}" -o json preauthkeys create \
  --user "${user_id}" --reusable --expiration 1h \
  >"${run_dir}/go-preauth-create.json"
go_preauth_id="$(python3 - "${run_dir}/go-preauth-create.json" <<'PY'
import json
import sys
key = json.load(open(sys.argv[1]))
assert isinstance(key.get('id'), int) and key.get('key', '').startswith('hskey-auth-'), key
print(key['id'])
PY
)"
"${go_bin}" --config "${go_config}" nodes approve-routes \
  --identifier "${node_id}" --routes '' \
  >"${run_dir}/go-withdraw-routes.stdout"
go_auth_id=hskey-authreq-zyxwvutsrqponmlkjihgfedc
"${go_bin}" --config "${go_config}" debug create-node \
  --user go-alice --key "${go_auth_id}" --name go-second-router --route 10.78.0.0/24 \
  >"${run_dir}/go-debug-create.stdout"
"${go_bin}" --config "${go_config}" auth register \
  --user go-alice --auth-id "${go_auth_id}" \
  >"${run_dir}/go-register.stdout"
"${go_bin}" --config "${go_config}" -o json nodes list \
  >"${run_dir}/go-after-mutations-nodes.json"
go_node_id="$(python3 - "${run_dir}/go-after-mutations-nodes.json" <<'PY'
import json
import sys
nodes = json.load(open(sys.argv[1]))
assert len(nodes) == 2, nodes
node = next(node for node in nodes if node['name'] == 'go-second-router')
assert node['user']['name'] == 'go-alice', node
print(node['id'])
PY
)"
"${go_bin}" --config "${go_config}" nodes approve-routes \
  --identifier "${go_node_id}" --routes 10.78.0.0/24 \
  >"${run_dir}/go-approve-routes.stdout"
stop_server

python3 - "${run_dir}" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
assert json.loads((root / 'rust-first-key.json').read_text()) == json.loads((root / 'go-key.json').read_text())
users = json.loads((root / 'go-users.json').read_text()) or []
nodes = json.loads((root / 'go-nodes.json').read_text()) or []
preauthkeys = json.loads((root / 'go-preauthkeys.json').read_text()) or []
apikeys = json.loads((root / 'go-apikeys.json').read_text()) or []
routes = json.loads((root / 'go-routes.json').read_text()) or []
assert len(users) == 1 and users[0]['name'] == 'alice', users
assert len(nodes) == 1 and nodes[0]['name'] == 'fresh-router', nodes
assert nodes[0]['user']['name'] == 'alice', nodes
assert nodes[0]['approved_routes'] == ['10.77.0.0/24'], nodes
assert nodes[0]['expiry'] == {'seconds': 4102444800, 'nanos': 123456000}, nodes
assert len(preauthkeys) == 1 and preauthkeys[0]['user']['name'] == 'alice', preauthkeys
assert len(apikeys) == 1, apikeys
assert len(routes) == 1 and routes[0]['approved_routes'] == ['10.77.0.0/24'], routes
PY

start_server rust-again "${rust_bin}" "${rust_config}"
"${rust_bin}" --config "${rust_config}" -o json users list \
  >"${run_dir}/rust-again-users.json"
"${rust_bin}" --config "${rust_config}" -o json nodes list \
  >"${run_dir}/rust-again-nodes.json"
"${rust_bin}" --config "${rust_config}" -o json apikeys list \
  >"${run_dir}/rust-again-apikeys.json"
"${rust_bin}" --config "${rust_config}" -o json preauthkeys list \
  >"${run_dir}/rust-again-preauthkeys.json"
"${rust_bin}" --config "${rust_config}" -o json nodes list-routes \
  >"${run_dir}/rust-again-routes.json"
assert_gateway_api_key rust-again-rust-key "${rust_api_secret}" go-alice
assert_gateway_api_key rust-again-go-key "${go_api_secret}" go-alice
python3 - "${run_dir}" <<'PY'
import json
from pathlib import Path
import sys
root = Path(sys.argv[1])
assert json.loads((root / 'rust-first-key.json').read_text()) == json.loads((root / 'rust-again-key.json').read_text())
assert json.loads((root / 'rust-again-users.json').read_text())[0]['name'] == 'go-alice'
nodes = json.loads((root / 'rust-again-nodes.json').read_text())
assert len(nodes) == 2, nodes
original = next(node for node in nodes if node['given_name'] == 'go-router')
added = next(node for node in nodes if node['name'] == 'go-second-router')
assert original['given_name'] == 'go-router', original
assert original['user']['name'] == 'go-alice' and added['user']['name'] == 'go-alice', nodes
assert not original.get('approved_routes'), original
assert added['approved_routes'] == ['10.78.0.0/24'], added
assert original['expiry'] == {'seconds': 4102444800, 'nanos': 123456000}, original
api_keys = json.loads((root / 'rust-again-apikeys.json').read_text())
assert len(api_keys) == 2, api_keys
keys = json.loads((root / 'rust-again-preauthkeys.json').read_text())
assert len(keys) == 2 and all(key['user']['name'] == 'go-alice' for key in keys), keys
routes = json.loads((root / 'rust-again-routes.json').read_text())
assert len(routes) == 2, routes
assert sorted(route.get('approved_routes') or [] for route in routes) == [[], ['10.78.0.0/24']], routes
PY
"${rust_bin}" --config "${rust_config}" preauthkeys expire --id "${go_preauth_id}" \
  >"${run_dir}/rust-expire-go-preauth.stdout"
"${rust_bin}" --config "${rust_config}" nodes approve-routes \
  --identifier "${node_id}" --routes 10.77.0.0/24 \
  >"${run_dir}/rust-reapprove-routes.stdout"
stop_server

start_server go-final "${go_bin}" "${go_config}"
"${go_bin}" --config "${go_config}" -o json preauthkeys list \
  >"${run_dir}/go-final-preauthkeys.json"
"${go_bin}" --config "${go_config}" -o json nodes list \
  >"${run_dir}/go-final-nodes.json"
assert_gateway_api_key go-final-rust-key "${rust_api_secret}" go-alice
assert_gateway_api_key go-final-go-key "${go_api_secret}" go-alice
stop_server
python3 - "${run_dir}" "${go_preauth_id}" <<'PY'
import json
from pathlib import Path
import sys
import time
root = Path(sys.argv[1])
keys = json.loads((root / 'go-final-preauthkeys.json').read_text())
assert len(keys) == 2, keys
expired = next(key for key in keys if key['id'] == int(sys.argv[2]))
assert expired['expiration']['seconds'] <= time.time() and not expired.get('used', False), expired
nodes = json.loads((root / 'go-final-nodes.json').read_text())
assert len(nodes) == 2, nodes
original = next(node for node in nodes if node['given_name'] == 'go-router')
added = next(node for node in nodes if node['name'] == 'go-second-router')
assert original['approved_routes'] == ['10.77.0.0/24'], original
assert added['approved_routes'] == ['10.78.0.0/24'], added
assert json.loads((root / 'rust-first-key.json').read_text()) == json.loads((root / 'go-final-key.json').read_text())
PY
echo "fresh Rust Postgres → pinned Go v0.29.5 registration/route/key mutations → Rust → Go direct restarts passed: ${run_dir}"
