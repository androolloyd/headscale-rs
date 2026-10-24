#!/usr/bin/env bash
# Paired production TS2021 register follow-up under two Noise machine keys.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"
run_dir="${REAL_CLIENT_WORKDIR:-target/real-client/noise-followup-binding-$(date +%s)-$$}"
mkdir -p "${run_dir}"
run_dir="$(cd "${run_dir}" && pwd)"
rust_bin="${RUST_HEADSCALE_BIN:-${repo_root}/target/debug/headscale}"
go_bin="${HEADSCALE_GO_BIN:-${run_dir}/bin/headscale}"
helper="${run_dir}/noise-followup"
server_pid=""

stop_server() {
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
    server_pid=""
  fi
}
trap stop_server EXIT

if [[ -z "${HEADSCALE_GO_BIN:-}" ]]; then
  GOBIN="${run_dir}/bin" go install github.com/juanfont/headscale/cmd/headscale@v0.29.5
fi
"${go_bin}" version >"${run_dir}/go-version.txt"
rg -q 'v0\.29\.5' "${run_dir}/go-version.txt"
cargo build -p headscale-cli --bin headscale
(cd tools/parity/headscale-go && go build -o "${helper}" ./noise-followup)

make_config() {
  local case_dir="$1" port="$2" metrics="$3" grpc="$4" socket="$5"
  python3 - "${case_dir}" "${port}" "${metrics}" "${grpc}" "${socket}" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
port, metrics, grpc, socket = sys.argv[2:]
q = json.dumps
(root / 'config.yaml').write_text(f'''
server_url: {q('http://127.0.0.1:' + port)}
listen_addr: {q('127.0.0.1:' + port)}
metrics_listen_addr: {q('127.0.0.1:' + metrics)}
grpc_listen_addr: {q('127.0.0.1:' + grpc)}
grpc_allow_insecure: true
unix_socket: {q(socket)}
private_key_path: {q(str(root / 'private.key'))}
noise:
  private_key_path: {q(str(root / 'noise.key'))}
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
    path: {q(str(root / 'db.sqlite'))}
policy:
  mode: database
''')
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
PY
}

start_server() {
  local label="$1" bin="$2" config="$3" port="$4" case_dir="$5"
  "${bin}" --config "${config}" serve >"${case_dir}/serve.stdout" 2>"${case_dir}/serve.stderr" &
  server_pid="$!"
  local deadline=$((SECONDS + 25))
  until curl --silent --show-error --fail "http://127.0.0.1:${port}/health" \
    >"${case_dir}/health.json" 2>/dev/null; do
    if ! kill -0 "${server_pid}" >/dev/null 2>&1 || ((SECONDS >= deadline)); then
      tail -n 80 "${case_dir}/serve.stderr" >&2
      echo "${label} failed to start" >&2
      exit 1
    fi
    sleep 0.2
  done
}

for implementation in rust go; do
  for actor in rightful attacker; do
  case_dir="${run_dir}/${implementation}-${actor}"
  mkdir -p "${case_dir}"
  read -r port metrics grpc < <(python3 - <<'PY'
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
  socket="/tmp/hs-followup-${$}-${implementation:0:1}-${actor:0:1}.sock"
  make_config "${case_dir}" "${port}" "${metrics}" "${grpc}" "${socket}"
  if [[ "${implementation}" == rust ]]; then
    bin="${rust_bin}"
  else
    bin="${go_bin}"
  fi
  start_server "${implementation}" "${bin}" "${case_dir}/config.yaml" "${port}" "${case_dir}"
  "${bin}" --config "${case_dir}/config.yaml" users create alice >"${case_dir}/user-create.stdout"
  "${helper}" -mode initial -url "http://127.0.0.1:${port}" \
    -state "${case_dir}/initial.json" -output "${case_dir}/initial-response.json" \
    >"${case_dir}/initial.stdout" 2>"${case_dir}/initial.stderr"
  auth_id="$(python3 - "${case_dir}/initial.json" <<'PY'
import json
import sys
from urllib.parse import urlparse
url = json.load(open(sys.argv[1]))['auth_url']
auth_id = urlparse(url).path.rsplit('/', 1)[-1]
assert auth_id.startswith('hskey-authreq-') and len(auth_id) == len('hskey-authreq-') + 24, auth_id
print(auth_id)
PY
)"
  actor_args=()
  if [[ "${actor}" == attacker ]]; then
    actor_args=(-attacker)
  fi
  "${helper}" -mode followup "${actor_args[@]}" -url "http://127.0.0.1:${port}" \
    -state "${case_dir}/initial.json" -output "${case_dir}/followup.json" \
    >"${case_dir}/followup.stdout" 2>"${case_dir}/followup.stderr" &
  followup_pid="$!"
  sleep 0.5
  "${bin}" --config "${case_dir}/config.yaml" auth register \
    --user alice --auth-id "${auth_id}" >"${case_dir}/approve.stdout"
  wait "${followup_pid}" || { cat "${case_dir}/followup.stderr" >&2; exit 1; }
  "${bin}" --config "${case_dir}/config.yaml" -o json nodes list >"${case_dir}/nodes.json"
  stop_server
  rm -f "${socket}"
  done
done

python3 - "${run_dir}" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
for implementation in ('rust', 'go'):
    rightful_case = root / f'{implementation}-rightful'
    attacker_case = root / f'{implementation}-attacker'
    rightful = json.loads((rightful_case / 'followup.json').read_text())
    attacker = json.loads((attacker_case / 'followup.json').read_text())
    right_nodes = json.loads((rightful_case / 'nodes.json').read_text())
    attack_nodes = json.loads((attacker_case / 'nodes.json').read_text())
    right_body = json.loads(rightful['body'])
    attack_body = json.loads(attacker['body'])
    assert rightful['status'] == 200 and right_body.get('MachineAuthorized') is True, rightful
    assert right_body.get('Login', {}).get('LoginName') == 'alice', rightful
    assert right_body.get('Login', {}).get('Provider') == '', rightful
    assert right_body.get('User', {}).get('Created'), rightful
    assert 'NodeKeySignature' in right_body and right_body['NodeKeySignature'] is None, rightful
    assert attacker['status'] == 200 and attack_body.get('MachineAuthorized') is False, attacker
    assert 'machine key' in attack_body.get('Error', '').lower(), attacker
    assert attack_body.get('Login', {}).get('LoginName', '') == '', attacker
    assert attack_body.get('User', {}).get('DisplayName', '') == '', attacker
    assert 'NodeKeySignature' in attack_body and attack_body['NodeKeySignature'] is None, attacker
    for nodes in (right_nodes, attack_nodes):
        assert len(nodes) == 1 and nodes[0]['user']['name'] == 'alice', nodes
print('paired Rust and pinned-Go TS2021 follow-up machine binding passed')
PY

echo "paired production Noise register follow-up passed: ${run_dir}"
