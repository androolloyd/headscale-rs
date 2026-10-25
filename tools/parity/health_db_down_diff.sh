#!/usr/bin/env bash
# Differential check of GET /health against the pinned headscale-go binary.
#
# Starts headscale-go v0.29.5 and headscale-rs on their own temporary Postgres
# databases, records the raw /health response while the database is up, then
# removes the database out from under the running server (DROP DATABASE ...
# WITH (FORCE) terminates the pool's connections and refuses new ones) and
# records /health again. Status line, header set/values (names case-folded,
# Date dropped) and body must be identical between the two engines, and the
# expected values are asserted so a server that never fails also fails here:
#
#   database up:   200  {"status":"pass"}\n
#   database gone: 500  {"status":"fail"}\n
#
# Needs: HEADSCALE_DB_POSTGRES_TEST_URL (an admin-capable Postgres URL, e.g.
# postgres://postgres@127.0.0.1:5432/postgres), psql, curl, python3, go (module
# cache populated; the Go binary is built offline from a scratch copy so the
# checked-in go.mod is not touched), and a headscale-rs binary
# (RUST_HEADSCALE_BIN, default target/debug/headscale built with the default
# features).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

if [[ -z "${HEADSCALE_DB_POSTGRES_TEST_URL:-}" ]]; then
  echo "HEADSCALE_DB_POSTGRES_TEST_URL is required" >&2
  exit 2
fi
rust_bin="${RUST_HEADSCALE_BIN:-${repo_root}/target/debug/headscale}"
work="$(mktemp -d "${TMPDIR:-/tmp}/hs-health.XXXXXX")"
pids=()
databases=()

eval "$(python3 - "${HEADSCALE_DB_POSTGRES_TEST_URL}" <<'PY'
import shlex, sys
from urllib.parse import urlparse, unquote
u = urlparse(sys.argv[1])
for key, value in {
    "pg_host": u.hostname or "127.0.0.1",
    "pg_port": str(u.port or 5432),
    "pg_user": unquote(u.username or "postgres"),
    "pg_pass": unquote(u.password or ""),
}.items():
    print(f"{key}={shlex.quote(value)}")
PY
)"
export PGPASSWORD="${pg_pass}"
psql_admin() { psql -X -q -h "${pg_host}" -p "${pg_port}" -U "${pg_user}" -d postgres -v ON_ERROR_STOP=1 "$@"; }

cleanup() {
  for pid in "${pids[@]:-}"; do
    [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null || true
  done
  for db in "${databases[@]:-}"; do
    [[ -n "${db}" ]] && psql_admin -c "DROP DATABASE IF EXISTS ${db} WITH (FORCE)" >/dev/null 2>&1 || true
  done
  rm -rf "${work}"
}
trap cleanup EXIT

go_bin="${GO_HEADSCALE_BIN:-}"
if [[ -z "${go_bin}" ]]; then
  cp -R tools/parity/headscale-go "${work}/go-src"
  (cd "${work}/go-src" &&
    GOFLAGS=-mod=mod GOPROXY=off go build -o "${work}/headscale-go" github.com/juanfont/headscale/cmd/headscale)
  go_bin="${work}/headscale-go"
fi

free_ports() {
  python3 - <<'PY'
import socket
socks = [socket.socket() for _ in range(3)]
for s in socks:
    s.bind(("127.0.0.1", 0))
print(*(s.getsockname()[1] for s in socks))
PY
}

# start <engine> <binary>: sets $http_port and appends the server pid.
start() {
  local engine="$1" bin="$2" dir="${work}/$1"
  local db="hs_health_${engine}_$$"
  mkdir -p "${dir}"
  psql_admin -c "CREATE DATABASE ${db}" >/dev/null
  databases+=("${db}")
  read -r http_port metrics_port grpc_port < <(free_ports)
  local sock
  sock="$(mktemp -d /tmp/hshl.XXXXXX)/hs.sock"
  cat >"${dir}/derp.yaml" <<YAML
regions:
  900:
    regionid: 900
    regioncode: test
    regionname: Test
    nodes:
      - name: 900a
        regionid: 900
        hostname: derp.invalid
        stunport: -1
        stunonly: false
        derpport: 443
YAML
  cat >"${dir}/config.yaml" <<YAML
server_url: http://127.0.0.1:${http_port}
listen_addr: 127.0.0.1:${http_port}
metrics_listen_addr: 127.0.0.1:${metrics_port}
grpc_listen_addr: 127.0.0.1:${grpc_port}
grpc_allow_insecure: true
unix_socket: ${sock}
noise:
  private_key_path: ${dir}/noise.key
prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
derp:
  server:
    enabled: false
  urls: []
  paths:
    - ${dir}/derp.yaml
  auto_update_enabled: false
dns:
  magic_dns: false
  override_local_dns: false
database:
  type: postgres
  postgres:
    host: ${pg_host}
    port: ${pg_port}
    name: ${db}
    user: ${pg_user}
    pass: '${pg_pass}'
    ssl: false
policy:
  mode: database
YAML
  "${bin}" --config "${dir}/config.yaml" serve >"${dir}/stdout.log" 2>&1 &
  pids+=("$!")
  for _ in $(seq 1 150); do
    curl -fsS "http://127.0.0.1:${http_port}/health" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  echo "${engine} did not become healthy" >&2
  tail -20 "${dir}/stdout.log" >&2
  return 1
}

# capture <engine> <phase>: normalised raw response (status, sorted lower-case
# headers without Date, body).
capture() {
  curl -sS -i --max-time 10 "http://127.0.0.1:${http_port}/health" |
    python3 -c '
import sys
raw = sys.stdin.buffer.read().replace(b"\r\n", b"\n")
head, _, body = raw.partition(b"\n\n")
lines = head.decode().split("\n")
headers = sorted(
    l.split(":", 1)[0].lower() + ":" + l.split(":", 1)[1].strip()
    for l in lines[1:] if not l.lower().startswith("date:")
)
print("\n".join([lines[0].strip(), *headers, "", repr(body.decode())]))
' >"${work}/$1.$2"
}

declare -a engines=("go:${go_bin}" "rs:${rust_bin}")
for entry in "${engines[@]}"; do
  engine="${entry%%:*}"
  bin="${entry#*:}"
  start "${engine}" "${bin}"
  capture "${engine}" up
  psql_admin -c "DROP DATABASE hs_health_${engine}_$$ WITH (FORCE)" >/dev/null
  databases=("${databases[@]/hs_health_${engine}_$$/}")
  sleep 0.5
  capture "${engine}" down
done

status=0
for phase in up down; do
  if diff -u "${work}/go.${phase}" "${work}/rs.${phase}"; then
    echo "health ${phase}: headscale-rs matches headscale-go"
  else
    echo "health ${phase}: headscale-rs differs from headscale-go" >&2
    status=1
  fi
done
head -1 "${work}/go.up" | grep -q '200' || { echo "go did not answer 200 with the database up" >&2; status=1; }
head -1 "${work}/go.down" | grep -q '500' || { echo "go did not answer 500 with the database gone" >&2; status=1; }
grep -q '{"status":"pass"}' "${work}/go.up" || { echo "unexpected go body (up)" >&2; status=1; }
grep -q '{"status":"fail"}' "${work}/go.down" || { echo "unexpected go body (down)" >&2; status=1; }
exit "${status}"
