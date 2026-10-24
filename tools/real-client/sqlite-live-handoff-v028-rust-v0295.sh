#!/usr/bin/env bash
# Hook invoked by authkey-headscale-go-smoke.sh while its stock clients run.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

: "${REAL_CLIENT_HANDOFF_WORK_DIR:?}"
: "${REAL_CLIENT_HANDOFF_GO_CONFIG:?}"
: "${REAL_CLIENT_HANDOFF_GO_BIN:?}"
: "${REAL_CLIENT_HANDOFF_GO_PID:?}"
: "${REAL_CLIENT_HANDOFF_CLIENTS:?}"
: "${REAL_CLIENT_HANDOFF_HTTP_PORT:?}"
: "${REAL_CLIENT_HANDOFF_CONTROL_SCHEME:?}"
: "${REAL_CLIENT_HANDOFF_METRICS_PORT:?}"
: "${REAL_CLIENT_HANDOFF_GRPC_PORT:?}"
: "${REAL_CLIENT_HANDOFF_SOCKET:?}"

work_dir="${REAL_CLIENT_HANDOFF_WORK_DIR}"
go_config="${REAL_CLIENT_HANDOFF_GO_CONFIG}"
go_v028_bin="${REAL_CLIENT_HANDOFF_GO_BIN}"
go_pid="${REAL_CLIENT_HANDOFF_GO_PID}"
http_port="${REAL_CLIENT_HANDOFF_HTTP_PORT}"
scheme="${REAL_CLIENT_HANDOFF_CONTROL_SCHEME}"
metrics_port="${REAL_CLIENT_HANDOFF_METRICS_PORT}"
grpc_port="${REAL_CLIENT_HANDOFF_GRPC_PORT}"
rust_socket="/tmp/hsrs-live-handoff-${$}.sock"
rust_config="${work_dir}/rust-handoff.yaml"
rust_bin="${RUST_HEADSCALE_BIN:-${repo_root}/target/debug/headscale}"
go_v0295_bin="${HEADSCALE_GO_V0295_BIN:-${work_dir}/bin-v0295/headscale}"
rust_pid=""
go_v0295_pid=""
IFS=',' read -r -a clients <<<"${REAL_CLIENT_HANDOFF_CLIENTS}"
if [[ ${#clients[@]} -ne 2 ]]; then
  echo "live handoff requires exactly two logged-in stock clients" >&2
  exit 2
fi

cleanup() {
  if [[ -n "${rust_pid}" ]]; then
    kill "${rust_pid}" >/dev/null 2>&1 || true
    wait "${rust_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${go_v0295_pid}" ]]; then
    kill "${go_v0295_pid}" >/dev/null 2>&1 || true
    wait "${go_v0295_pid}" >/dev/null 2>&1 || true
  fi
  rm -f "${rust_socket}"
}
trap cleanup EXIT

if [[ -z "${HEADSCALE_GO_V0295_BIN:-}" ]]; then
  GOBIN="${work_dir}/bin-v0295" go install github.com/juanfont/headscale/cmd/headscale@v0.29.5
fi
if [[ "${scheme}" != "https" ]]; then
  echo "live handoff requires REAL_CLIENT_HEADSCALE_GO_TLS=true for client retries" >&2
  exit 2
fi
local_control_url="${scheme}://127.0.0.1:${http_port}"
"${go_v0295_bin}" version >"${work_dir}/go-v0295-version.txt"
rg -q 'v0\.29\.5' "${work_dir}/go-v0295-version.txt"
cargo build -p headscale-cli --bin headscale

python3 - "${rust_config}" "${work_dir}" "${rust_socket}" \
  "${http_port}" "${metrics_port}" "${grpc_port}" "${scheme}" <<'PY'
import json
from pathlib import Path
import sys

config, root, socket = sys.argv[1:4]
http, metrics, grpc = sys.argv[4:7]
scheme = sys.argv[7]
root = Path(root)
q = json.dumps
Path(config).write_text(f"""
server_url: {q(scheme + '://host.docker.internal:' + http)}
listen_addr: {q('0.0.0.0:' + http)}
tls_cert_path: {q(str(root / 'tls.crt'))}
tls_key_path: {q(str(root / 'tls.key'))}
metrics_listen_addr: {q('127.0.0.1:' + metrics)}
grpc_listen_addr: {q('127.0.0.1:' + grpc)}
grpc_allow_insecure: true
unix_socket: {q(socket)}
noise:
  private_key_path: {q(str(root / 'noise_private.key'))}
prefixes:
  allocation: sequential
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
dns:
  magic_dns: true
  base_domain: tail.test
  override_local_dns: false
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
    path: {q(str(root / 'db.sqlite'))}
policy:
  mode: database
""")
PY

for index in 0 1; do
  docker inspect --format '{{.Id}}' "${clients[$index]}" >"${work_dir}/handoff-client-$((index + 1)).container-id"
  docker exec "${clients[$index]}" tailscale status --json \
    >"${work_dir}/handoff-before-$((index + 1)).json"
done
"${go_v028_bin}" --config "${go_config}" -o json nodes list \
  >"${work_dir}/handoff-go-before-nodes.json"
"${go_v028_bin}" --config "${go_config}" -o json apikeys create --expiration 24h \
  >"${work_dir}/handoff-go-created-api-key.json"
"${go_v028_bin}" --config "${go_config}" -o json apikeys list \
  >"${work_dir}/handoff-go-before-api-keys.json"
api_key="$(python3 - "${work_dir}/handoff-go-created-api-key.json" <<'PY'
import json
import sys
key = json.load(open(sys.argv[1]))
assert isinstance(key, str) and key.startswith('hskey-api-'), key
print(key)
PY
)"
assert_api_key_auth() {
  local label="$1"
  curl --silent --show-error --fail --insecure \
    --header "Authorization: Bearer ${api_key}" \
    "${local_control_url}/api/v1/user" \
    >"${work_dir}/handoff-${label}-api-auth.json"
  python3 - "${work_dir}/handoff-${label}-api-auth.json" <<'PY'
import json
import sys
response = json.load(open(sys.argv[1]))
assert any(user.get('name') == 'alice' for user in response.get('users', [])), response
PY
}
assert_api_key_auth go-before
python3 - "${work_dir}/handoff-go-created-api-key.json" \
  "${work_dir}/handoff-go-before-api-keys.json" \
  "${work_dir}/db.sqlite" "${work_dir}/handoff-api-key-before.json" <<'PY'
import json
import sqlite3
import sys

created, listed = [json.load(open(path)) for path in sys.argv[1:3]]
assert len(listed) == 1, listed
assert listed[0]['prefix'].startswith('hskey-api-'), listed
assert created, created
with sqlite3.connect(sys.argv[3]) as db:
    rows = [
        (row[0], row[1], row[2].hex() if isinstance(row[2], bytes) else row[2])
        for row in db.execute('SELECT id, prefix, hash FROM api_keys ORDER BY id')
    ]
assert len(rows) == 1 and rows[0][1] in listed[0]['prefix'], (rows, listed)
with open(sys.argv[4], 'w') as output:
    json.dump(rows, output)
PY
curl --silent --show-error --fail --insecure "${local_control_url}/key?v=138" \
  >"${work_dir}/handoff-go-before-key.json"
node_id="$(python3 - "${work_dir}/handoff-go-before-nodes.json" "${clients[0]}" <<'PY'
import json
import sys
nodes = json.load(open(sys.argv[1]))
print(next(node['id'] for node in nodes if node['given_name'] == sys.argv[2]))
PY
)"

wait_health() {
  local pid="$1" label="$2" deadline=$((SECONDS + 25))
  until curl --silent --show-error --fail --insecure \
    "${local_control_url}/health" >"${work_dir}/handoff-${label}-health.json" 2>/dev/null; do
    if ! kill -0 "${pid}" >/dev/null 2>&1 || ((SECONDS >= deadline)); then
      tail -n 70 "${work_dir}/handoff-${label}.stderr" >&2
      echo "${label} did not start during live handoff" >&2
      return 1
    fi
    sleep 0.2
  done
}

wait_port_closed() {
  local deadline=$((SECONDS + 15))
  while curl --silent --fail --insecure "${local_control_url}/health" >/dev/null 2>&1; do
    if ((SECONDS >= deadline)); then
      echo "previous server still owns HTTP port ${http_port}" >&2
      return 1
    fi
    sleep 0.2
  done
}

assert_noise_key_equal() {
  python3 - "${work_dir}/handoff-go-before-key.json" "$1" <<'PY'
import json
import sys
before, after = [json.load(open(path)) for path in sys.argv[1:]]
assert after == before, (before, after)
PY
}

wait_peer_name() {
  local client="$1" expected="$2" label="$3" deadline=$((SECONDS + 90))
  while true; do
    if docker exec "${client}" tailscale status --json \
      >"${work_dir}/handoff-${label}.json" 2>/dev/null && \
      python3 - "${work_dir}/handoff-${label}.json" "${expected}" 2>/dev/null <<'PY'
import json
import sys
status = json.load(open(sys.argv[1]))
peers = list((status.get('Peer') or {}).values())
assert status.get('BackendState') == 'Running', status.get('BackendState')
assert len(peers) == 1, peers
assert peers[0].get('DNSName', '').startswith(sys.argv[2] + '.'), peers[0]
PY
    then
      return 0
    fi
    if ((SECONDS >= deadline)); then
      echo "observer did not receive ${expected} peer map under ${label}" >&2
      return 1
    fi
    sleep 1
  done
}

echo "::group::live handoff Go v0.28.0 to Rust"
kill "${go_pid}"
wait_port_closed
rm -f "${REAL_CLIENT_HANDOFF_SOCKET}"
"${rust_bin}" --config "${rust_config}" serve \
  >"${work_dir}/handoff-rust.stdout" 2>"${work_dir}/handoff-rust.stderr" &
rust_pid="$!"
wait_health "${rust_pid}" rust
assert_api_key_auth rust
curl --silent --show-error --fail --insecure "${local_control_url}/key?v=138" \
  >"${work_dir}/handoff-rust-key.json"
assert_noise_key_equal "${work_dir}/handoff-rust-key.json"
"${rust_bin}" --config "${rust_config}" -o json nodes list \
  >"${work_dir}/handoff-rust-nodes.json"
"${rust_bin}" --config "${rust_config}" -o json apikeys list \
  >"${work_dir}/handoff-rust-api-keys.json"
"${rust_bin}" --config "${rust_config}" nodes rename handoff-rust-node --identifier "${node_id}" \
  >"${work_dir}/handoff-rust-rename.stdout"
wait_peer_name "${clients[1]}" handoff-rust-node rust-map
echo "::endgroup::"

echo "::group::live handoff Rust to Go v0.29.5"
kill "${rust_pid}"
wait "${rust_pid}" >/dev/null 2>&1 || true
rust_pid=""
wait_port_closed
"${go_v0295_bin}" --config "${go_config}" serve \
  >"${work_dir}/handoff-go-v0295.stdout" 2>"${work_dir}/handoff-go-v0295.stderr" &
go_v0295_pid="$!"
wait_health "${go_v0295_pid}" go-v0295
assert_api_key_auth go-v0295
curl --silent --show-error --fail --insecure "${local_control_url}/key?v=138" \
  >"${work_dir}/handoff-go-v0295-key.json"
assert_noise_key_equal "${work_dir}/handoff-go-v0295-key.json"
"${go_v0295_bin}" --config "${go_config}" nodes rename handoff-go-node --identifier "${node_id}" \
  >"${work_dir}/handoff-go-v0295-rename.stdout"
wait_peer_name "${clients[1]}" handoff-go-node go-map
"${go_v0295_bin}" --config "${go_config}" -o json nodes list-routes \
  >"${work_dir}/handoff-go-v0295-routes.json"
"${go_v0295_bin}" --config "${go_config}" -o json apikeys list \
  >"${work_dir}/handoff-go-v0295-api-keys.json"
echo "::endgroup::"

for index in 0 1; do
  local_id="$(docker inspect --format '{{.Id}}' "${clients[$index]}")"
  test "${local_id}" = "$(cat "${work_dir}/handoff-client-$((index + 1)).container-id")"
  docker exec "${clients[$index]}" tailscale status --json \
    >"${work_dir}/handoff-after-$((index + 1)).json"
done
python3 - "${work_dir}" <<'PY'
import json
import sqlite3
from pathlib import Path
import sys

root = Path(sys.argv[1])
for index in (1, 2):
    before = json.loads((root / f'handoff-before-{index}.json').read_text())
    after = json.loads((root / f'handoff-after-{index}.json').read_text())
    assert before['BackendState'] == after['BackendState'] == 'Running'
    for field in ('ID', 'PublicKey', 'TailscaleIPs'):
        assert before['Self'][field] == after['Self'][field], field
routes = json.loads((root / 'handoff-go-v0295-routes.json').read_text())
assert sum('10.77.0.0/24' in row.get('approved_routes', []) for row in routes) == 1, routes
before_keys = json.loads((root / 'handoff-go-before-api-keys.json').read_text())
for stage in ('rust', 'go-v0295'):
    listed = json.loads((root / f'handoff-{stage}-api-keys.json').read_text())
    assert [(row['id'], row['prefix']) for row in listed] == [
        (row['id'], row['prefix']) for row in before_keys
    ], (stage, listed, before_keys)
with sqlite3.connect(root / 'db.sqlite') as db:
    after_keys = [
        [row[0], row[1], row[2].hex() if isinstance(row[2], bytes) else row[2]]
        for row in db.execute('SELECT id, prefix, hash FROM api_keys ORDER BY id')
    ]
assert after_keys == json.loads((root / 'handoff-api-key-before.json').read_text()), after_keys
PY

echo "live Go v0.28.0 → Rust → Go v0.29.5 client map handoff passed"
