#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

run_dir="${REAL_CLIENT_WORKDIR:-target/real-client/sqlite-v0295-release-upgrade-$(date +%s)-$$}"
mkdir -p "${run_dir}"
run_dir="$(cd "${run_dir}" && pwd)"
rust_bin="${RUST_HEADSCALE_BIN:-${repo_root}/target/debug/headscale}"
go_bin="${HEADSCALE_GO_BIN:-${run_dir}/bin/headscale}"
server_pid=""
server_socket=""

stop_server() {
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
    server_pid=""
  fi
  if [[ -n "${server_socket}" ]]; then
    rm -f "${server_socket}"
    server_socket=""
  fi
}
trap stop_server EXIT

if [[ -z "${HEADSCALE_GO_BIN:-}" ]]; then
  GOBIN="${run_dir}/bin" go install github.com/juanfont/headscale/cmd/headscale@v0.29.5
fi
"${go_bin}" version >"${run_dir}/go-version.txt"
rg -q 'v0\.29\.5' "${run_dir}/go-version.txt"
cargo build -p headscale-cli --bin headscale

make_config() {
  local implementation="$1" case_dir="$2" database="$3" port="$4" metrics="$5" grpc="$6" socket="$7"
  python3 - "${implementation}" "${case_dir}" "${database}" "${port}" "${metrics}" "${grpc}" "${socket}" <<'PY'
import json
from pathlib import Path
import sys

implementation, root, db, port, metrics, grpc, socket = sys.argv[1:]
root = Path(root)
q = json.dumps
(root / f"{implementation}.yaml").write_text(f"""
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
    path: {q(db)}
policy:
  mode: database
""")
(root / 'derp.yaml').write_text("""regions:
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
PY
}

start_server() {
  local label="$1" bin="$2" config="$3" port="$4" socket="$5" case_dir="$6"
  server_socket="${socket}"
  "${bin}" --config "${config}" serve >"${case_dir}/${label}.stdout" 2>"${case_dir}/${label}.stderr" &
  server_pid="$!"
  local deadline=$((SECONDS + 25))
  until curl --silent --show-error --fail "http://127.0.0.1:${port}/health" \
    >"${case_dir}/${label}-health.json" 2>/dev/null; do
    if ! kill -0 "${server_pid}" >/dev/null 2>&1 || ((SECONDS >= deadline)); then
      cat "${case_dir}/${label}.stderr" >&2
      echo "${label} failed to start on release migration fixture" >&2
      exit 1
    fi
    sleep 0.2
  done
}

assert_upgraded_state() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sqlite3
import sys

scenario = sys.argv[1]
states = []
for path in sys.argv[2:]:
    with sqlite3.connect(path) as db:
        assert db.execute('PRAGMA integrity_check').fetchone() == ('ok',), path
        assert db.execute('PRAGMA foreign_key_check').fetchall() == [], path
        assert db.execute('SELECT version FROM database_versions WHERE id=1').fetchone() == ('v0.29.5',), path
        migrations = {row[0] for row in db.execute('SELECT id FROM migrations')}
        assert '202606181200-recover-null-tags-node-user-id' in migrations, path
        assert '202607241200-clear-tagged-node-expiry' in migrations, path
        states.append({
            'expiry_years': [
                int(str(row[0])[:4]) if row[0] is not None else None
                for row in db.execute('SELECT expiry FROM nodes ORDER BY id')
            ],
            'nodes': [
                (row[0], row[1], json.loads(row[2] or '[]') or [], row[3] is not None,
                 row[4], row[5], row[6])
                for row in db.execute(
                    'SELECT id, user_id, tags, expiry, auth_key_id, register_method, approved_routes '
                    'FROM nodes ORDER BY id'
                )
            ],
            'preauth': list(db.execute(
                'SELECT id, key, prefix, hash, user_id, reusable, ephemeral, used, tags '
                'FROM pre_auth_keys ORDER BY id'
            )),
            'api': list(db.execute(
                'SELECT id, prefix, hash, expiration FROM api_keys ORDER BY id'
            )),
        })
assert states[0] == states[1], states
nodes = states[0]['nodes']
if scenario == 'recover_null_tags_user_id':
    assert [(row[0], row[1]) for row in nodes] == [(1, 2), (2, None), (3, None), (4, 1)], states
elif scenario == 'clear_tagged_node_expiry':
    assert [row[3] for row in nodes] == [False, False, False, True, True], states
elif scenario == 'zero_time_expiry':
    assert states[0]['expiry_years'] == [None, None, 2099, 2020, None], states
elif scenario == 'v028_auth_rows':
    assert [(row[0], row[1], row[2], row[3], row[4], row[5]) for row in nodes] == [
        (1, None, ['tag:server'], False, 1, 'authkey')
    ], states
    assert len(states[0]['preauth']) == len(states[0]['api']) == 1, states
    assert states[0]['preauth'][0][2] == 'AuthPrefix01', states
    assert states[0]['api'][0][1] == 'ApiPrefix001', states
elif scenario == 'v028_request_tags_rows':
    assert [(row[0], row[1], row[2], row[3], row[4]) for row in nodes] == [
        (1, None, ['tag:server'], False, 1),
        (2, 1, [], False, 1),
    ], states
    assert len(states[0]['preauth']) == len(states[0]['api']) == 1, states
else:
    raise AssertionError(f'unknown scenario: {scenario}')
PY
}

for scenario in recover_null_tags_user_id clear_tagged_node_expiry zero_time_expiry v028_auth_rows v028_request_tags_rows; do
  case_dir="${run_dir}/${scenario}"
  mkdir -p "${case_dir}"
  case "${scenario}" in
    v028_auth_rows) fixture="headscale-db/tests/fixtures/headscale_go/v0_28_0_sqlite_auth_rows.sql" ;;
    v028_request_tags_rows) fixture="headscale-db/tests/fixtures/headscale_go/v0_28_0_sqlite_request_tags_rows.sql" ;;
    *) fixture="headscale-db/tests/fixtures/headscale_go/v0_29_5_${scenario}.sql" ;;
  esac
  python3 - "${fixture}" "${case_dir}/rust.sqlite" "${case_dir}/go.sqlite" <<'PY'
import sqlite3
import sys

script = open(sys.argv[1]).read()
for path in sys.argv[2:]:
    with sqlite3.connect(path) as db:
        db.executescript(script)
PY

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
  socket="/tmp/hs-upgrade-${$}-${scenario:0:5}.sock"
  make_config rust "${case_dir}" "${case_dir}/rust.sqlite" "${port}" "${metrics}" "${grpc}" "${socket}"
  make_config go "${case_dir}" "${case_dir}/go.sqlite" "${port}" "${metrics}" "${grpc}" "${socket}"

  start_server rust "${rust_bin}" "${case_dir}/rust.yaml" "${port}" "${socket}" "${case_dir}"
  stop_server
  start_server go "${go_bin}" "${case_dir}/go.yaml" "${port}" "${socket}" "${case_dir}"
  stop_server

  assert_upgraded_state "${scenario}" "${case_dir}/rust.sqlite" "${case_dir}/go.sqlite"

  # Each implementation must accept the other's upgraded primary file.
  python3 - "${case_dir}/go.yaml" "${case_dir}/go.sqlite" "${case_dir}/rust.sqlite" "${case_dir}/go-on-rust.yaml" \
    "${case_dir}/rust.yaml" "${case_dir}/rust-on-go.yaml" <<'PY'
import json
from pathlib import Path
import sys
config = Path(sys.argv[1]).read_text()
old, new = map(json.dumps, sys.argv[2:4])
assert old in config
Path(sys.argv[4]).write_text(config.replace(old, new))
config = Path(sys.argv[5]).read_text()
assert new in config
Path(sys.argv[6]).write_text(config.replace(new, old))
PY
  start_server go-on-rust "${go_bin}" "${case_dir}/go-on-rust.yaml" "${port}" "${socket}" "${case_dir}"
  stop_server
  start_server rust-on-go "${rust_bin}" "${case_dir}/rust-on-go.yaml" "${port}" "${socket}" "${case_dir}"
  stop_server

  assert_upgraded_state "${scenario}" "${case_dir}/rust.sqlite" "${case_dir}/go.sqlite"
done

echo "pinned v0.28.0 and v0.29.5 fixture process upgrades and bidirectional direct restarts passed: ${run_dir}"
