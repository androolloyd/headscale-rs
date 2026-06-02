#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

target="${REAL_CLIENT_OIDC_TARGET:-}"
case "${target}" in
  rust | headscale-go) ;;
  *)
    echo "REAL_CLIENT_OIDC_TARGET must be rust or headscale-go" >&2
    exit 2
    ;;
esac

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
# shellcheck source=tools/real-client/headscale-go-baseline.sh
source tools/real-client/headscale-go-baseline.sh
headscale_go_version="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_BASELINE_VERSION}}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-150}"
oidc_client_id="${REAL_CLIENT_OIDC_CLIENT_ID:-headscale-rs}"
oidc_client_secret="${REAL_CLIENT_OIDC_CLIENT_SECRET:-secret}"
oidc_subject="${REAL_CLIENT_OIDC_SUBJECT:-alice-subject}"
oidc_email="${REAL_CLIENT_OIDC_EMAIL:-alice@example.com}"
oidc_username="${REAL_CLIENT_OIDC_USERNAME:-alice}"
oidc_groups="${REAL_CLIENT_OIDC_GROUPS:-engineering}"
oidc_restart="${REAL_CLIENT_OIDC_RESTART:-false}"
oidc_policy_churn="${REAL_CLIENT_OIDC_POLICY_CHURN:-false}"
oidc_advertise_routes="${REAL_CLIENT_OIDC_ADVERTISE_ROUTES:-}"
oidc_approve_routes="${REAL_CLIENT_OIDC_APPROVE_ROUTES:-}"
database_backend="${REAL_CLIENT_DATABASE_BACKEND:-sqlite}"
base_domain="${REAL_CLIENT_BASE_DOMAIN-tail.test}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/oidc-${target}-smoke}"
run_id="hs-oidc-${target}-${database_backend}-$(date +%s)-$$"
client_name="${REAL_CLIENT_CLIENT_NAME:-${run_id}-client}"
policy_churn_viewer_user="${REAL_CLIENT_OIDC_POLICY_CHURN_VIEWER_USER:-viewer}"
policy_churn_viewer_name="${REAL_CLIENT_OIDC_POLICY_CHURN_VIEWER_NAME:-${run_id}-viewer}"
policy_churn_peer_name="${REAL_CLIENT_OIDC_POLICY_CHURN_PEER_NAME:-${run_id}-oidc-peer}"
docker_client_names=("${client_name}")

case "${database_backend}" in
  sqlite | postgres) ;;
  *)
    echo "REAL_CLIENT_DATABASE_BACKEND must be sqlite or postgres" >&2
    exit 2
    ;;
esac

case "${oidc_restart}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    oidc_restart_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    oidc_restart_flag=0
    ;;
  *)
    echo "REAL_CLIENT_OIDC_RESTART must be true or false, got ${oidc_restart}" >&2
    exit 2
    ;;
esac
case "${oidc_policy_churn}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    oidc_policy_churn_flag=1
    docker_client_names=("${policy_churn_viewer_name}" "${policy_churn_peer_name}")
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    oidc_policy_churn_flag=0
    ;;
  *)
    echo "REAL_CLIENT_OIDC_POLICY_CHURN must be true or false, got ${oidc_policy_churn}" >&2
    exit 2
    ;;
esac
if ((oidc_policy_churn_flag)) && [[ -n "${oidc_advertise_routes}${oidc_approve_routes}" ]]; then
  echo "REAL_CLIENT_OIDC_POLICY_CHURN cannot be combined with OIDC route advertisement/approval flags" >&2
  exit 2
fi
if [[ -n "${oidc_approve_routes}" && -z "${oidc_advertise_routes}" ]]; then
  echo "REAL_CLIENT_OIDC_APPROVE_ROUTES requires REAL_CLIENT_OIDC_ADVERTISE_ROUTES" >&2
  exit 2
fi

case "${work_root}" in
  /*) work_dir="${work_root}/${run_id}" ;;
  *) work_dir="${repo_root}/${work_root}/${run_id}" ;;
esac
mkdir -p "${work_dir}"

http_port=""
https_port=""
grpc_port=""
metrics_port=""
oidc_port=""
server_pid=""
mock_oidc_pid=""
control_url=""
local_health_url=""
control_port=""
config_path="${work_dir}/headscale-config"
db_path="${work_dir}/db.sqlite"
policy_path="${work_dir}/policy.hujson"
tls_cert_path=""
headscale_bin="${HEADSCALE_GO_BIN:-${work_dir}/bin/headscale}"
headscale_rs_socket_path="${REAL_CLIENT_HEADSCALE_RS_SOCKET:-/tmp/hsrs-${run_id}.sock}"
headscale_go_socket_path=""
postgres_admin_url=""
postgres_runtime_url=""
postgres_database_name=""
postgres_host=""
postgres_port=""
postgres_user=""
postgres_pass=""
postgres_sslmode=""
postgres_database_created=0

cleanup() {
  local docker_client_name
  for docker_client_name in "${docker_client_names[@]}"; do
    docker rm -f "${docker_client_name}" >/dev/null 2>&1 || true
  done
  rm -f "${headscale_rs_socket_path}"
  if [[ -n "${headscale_go_socket_path}" ]]; then
    rm -f "${headscale_go_socket_path}"
  fi
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${mock_oidc_pid}" ]]; then
    kill "${mock_oidc_pid}" >/dev/null 2>&1 || true
    wait "${mock_oidc_pid}" >/dev/null 2>&1 || true
  fi
  drop_postgres_database || true
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

free_port() {
  ruby -rsocket -e 's=TCPServer.new("127.0.0.1",0); puts s.addr[1]; s.close'
}

quoted_string() {
  ruby -rjson -e 'puts ARGV.fetch(0).to_json' "$1"
}

parse_postgres_test_url() {
  eval "$(
    ruby -ruri -rshellwords -e '
      url = URI.parse(ARGV.fetch(0))
      database_name = ARGV.fetch(1)
      abort("HEADSCALE_DB_POSTGRES_TEST_URL must include a TCP host") if url.host.to_s.empty?
      query = URI.decode_www_form(url.query.to_s).to_h
      sslmode = query.fetch("sslmode", "false")
      admin_db = url.path.to_s.sub(%r{\A/}, "")
      admin_db = "postgres" if admin_db.empty?
      admin = url.dup
      admin.path = "/#{admin_db}"
      runtime = url.dup
      runtime.path = "/#{database_name}"
      {
        postgres_admin_url: admin.to_s,
        postgres_runtime_url: runtime.to_s,
        postgres_database_name: database_name,
        postgres_host: url.host.to_s,
        postgres_port: (url.port || 5432).to_s,
        postgres_user: URI.decode_www_form_component(url.user.to_s),
        postgres_pass: URI.decode_www_form_component(url.password.to_s),
        postgres_sslmode: sslmode,
      }.each do |key, value|
        puts "#{key}=#{Shellwords.escape(value)}"
      end
    ' "${HEADSCALE_DB_POSTGRES_TEST_URL:-}" "${postgres_database_name}"
  )"
}

prepare_postgres_database() {
  [[ "${database_backend}" == "postgres" ]] || return 0
  if [[ -z "${HEADSCALE_DB_POSTGRES_TEST_URL:-}" ]]; then
    echo "skipping Postgres OIDC real-client smoke: HEADSCALE_DB_POSTGRES_TEST_URL is not set" >&2
    exit 0
  fi
  need psql
  postgres_database_name="headscale_rs_pg_oidc_${target//[^a-zA-Z0-9]/_}_$(date +%s)_$$"
  parse_postgres_test_url
  if ! [[ "${postgres_database_name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "internal temporary Postgres database name is invalid: ${postgres_database_name}" >&2
    exit 2
  fi
  echo "::group::create temporary Postgres database"
  if ! psql "${postgres_admin_url}" -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${postgres_database_name}" >"${work_dir}/postgres-create.stdout" 2>"${work_dir}/postgres-create.stderr"; then
    echo "skipping Postgres OIDC real-client smoke: cannot create temporary database ${postgres_database_name}" >&2
    cat "${work_dir}/postgres-create.stderr" >&2 || true
    echo "::endgroup::"
    exit 0
  fi
  postgres_database_created=1
  echo "created ${postgres_database_name}"
  echo "::endgroup::"
}

drop_postgres_database() {
  [[ "${database_backend}" == "postgres" ]] || return 0
  ((postgres_database_created)) || return 0
  echo "::group::drop temporary Postgres database"
  psql "${postgres_admin_url}" -v ON_ERROR_STOP=1 \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${postgres_database_name}' AND pid <> pg_backend_pid()" \
    >"${work_dir}/postgres-terminate.stdout" \
    2>"${work_dir}/postgres-terminate.stderr" || true
  if ! psql "${postgres_admin_url}" -v ON_ERROR_STOP=1 \
    -c "DROP DATABASE IF EXISTS ${postgres_database_name} WITH (FORCE)" \
    >"${work_dir}/postgres-drop.stdout" \
    2>"${work_dir}/postgres-drop.stderr"; then
    psql "${postgres_admin_url}" -v ON_ERROR_STOP=1 \
      -c "DROP DATABASE IF EXISTS ${postgres_database_name}" \
      >>"${work_dir}/postgres-drop.stdout" \
      2>>"${work_dir}/postgres-drop.stderr"
  fi
  postgres_database_created=0
  echo "::endgroup::"
}

wait_for() {
  local label="$1"
  local cmd="$2"
  local deadline=$((SECONDS + timeout_secs))
  until eval "${cmd}"; do
    if [[ -n "${mock_oidc_pid}" ]] && ! kill -0 "${mock_oidc_pid}" >/dev/null 2>&1; then
      wait "${mock_oidc_pid}" >/dev/null 2>&1 || true
      mock_oidc_pid=""
      echo "mock OIDC exited while waiting for ${label}" >&2
      dump_startup_logs "mock OIDC exited before ${label}"
      return 1
    fi
    if [[ -n "${server_pid}" ]] && ! kill -0 "${server_pid}" >/dev/null 2>&1; then
      wait "${server_pid}" >/dev/null 2>&1 || true
      server_pid=""
      echo "${target} server exited while waiting for ${label}" >&2
      dump_startup_logs "server exited before ${label}"
      return 1
    fi
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for ${label}" >&2
      dump_startup_logs "timed out waiting for ${label}"
      return 1
    fi
    sleep 1
  done
}

wait_pid_with_timeout() {
  local label="$1"
  local pid="$2"
  local deadline=$((SECONDS + timeout_secs))
  while kill -0 "${pid}" >/dev/null 2>&1; do
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for ${label}" >&2
      kill "${pid}" >/dev/null 2>&1 || true
      wait "${pid}" >/dev/null 2>&1 || true
      return 1
    fi
    sleep 1
  done
  wait "${pid}"
}

dump_startup_logs() {
  local reason="$1"
  local path
  if [[ -n "${local_health_url}" ]]; then
    server_health_probe >/dev/null 2>&1 || true
  fi
  if [[ -s "${config_path}" ]]; then
    server_grpc_health_probe >/dev/null 2>&1 || true
  fi
  echo "::group::OIDC startup debug (${reason})"
  for path in \
    "${work_dir}/mockoidc.stderr" \
    "${work_dir}/mockoidc.stdout" \
    "${work_dir}/mockoidc-discovery.stderr" \
    "${work_dir}/mockoidc-discovery.stdout" \
    "${work_dir}/headscale-rs.stderr" \
    "${work_dir}/headscale-rs.stdout" \
    "${work_dir}/headscale-rs-health.stderr" \
    "${work_dir}/headscale-rs-health.stdout" \
    "${work_dir}/headscale-rs-grpc-health.stderr" \
    "${work_dir}/headscale-rs-grpc-health.stdout" \
    "${work_dir}/headscale-rs-version.txt" \
    "${work_dir}/headscale-go.stderr" \
    "${work_dir}/headscale-go.stdout" \
    "${work_dir}/headscale-go-health.stderr" \
    "${work_dir}/headscale-go-health.stdout" \
    "${work_dir}/headscale-go-grpc-health.stderr" \
    "${work_dir}/headscale-go-grpc-health.stdout" \
    "${work_dir}/headscale-go-version.txt" \
    "${work_dir}/openssl.stderr" \
    "${work_dir}/openssl.stdout"; do
    if [[ -s "${path}" ]]; then
      echo "--- ${path} ---" >&2
      tail -200 "${path}" >&2 || true
    fi
  done
  echo "--- sockets ---" >&2
  ls -l "${headscale_rs_socket_path}" "${headscale_go_socket_path}" 2>/dev/null >&2 || true
  echo "::endgroup::"
}

stop_server() {
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
    server_pid=""
  fi
}

tailscale_logged_in() {
  local active_client_name="${1:-${client_name}}"
  local status_json
  status_json="$(docker exec "${active_client_name}" tailscale status --json 2>/dev/null || true)"
  ruby -rjson -e '
    status = JSON.parse(STDIN.read)
    self_node = status["Self"] || {}
    ips = Array(status["TailscaleIPs"])
    ok = status["HaveNodeKey"] &&
      status["AuthURL"].to_s.empty? &&
      self_node["InNetworkMap"] &&
      ips.any? { |ip| ip.start_with?("100.") }
    exit(ok ? 0 : 1)
  ' <<<"${status_json}"
}

write_registration_id() {
  local output_path="$1"
  local active_client_name="${2:-${client_name}}"
  local status_json
  status_json="$(docker exec "${active_client_name}" tailscale status --json 2>/dev/null || true)"
  ruby -rjson -e '
    status = JSON.parse(STDIN.read)
    url = status["AuthURL"].to_s
    match = url.match(%r{/register/((?:hskey-authreq-)?[A-Za-z0-9_-]{24})(?:\z|[?#])})
    exit 1 unless match
    File.write(ARGV.fetch(0), match[1])
  ' "${output_path}" <<<"${status_json}"
}

dump_client_debug() {
  local active_client_name="${1:-${client_name}}"
  docker exec "${active_client_name}" tailscale status 2>&1 || true
  docker exec "${active_client_name}" sh -c 'tail -180 /tmp/tailscaled.log 2>/dev/null || true' >&2
}

headscale_cmd() {
  if [[ "${target}" == "rust" ]]; then
    env -u HEADSCALE_CLI_ADDRESS -u HEADSCALE_CLI_API_KEY -u HEADSCALE_CLI_INSECURE \
      target/debug/headscale --config "${config_path}" --unix-socket "${headscale_rs_socket_path}" "$@"
  else
    "${headscale_bin}" -c "${config_path}" "$@"
  fi
}

server_log_prefix() {
  case "${target}" in
    rust) echo "headscale-rs" ;;
    headscale-go) echo "headscale-go" ;;
  esac
}

server_health_probe() {
  local prefix
  prefix="$(server_log_prefix)"
  case "${target}" in
    rust) curl -fsS "${local_health_url}" >"${work_dir}/${prefix}-health.stdout" 2>"${work_dir}/${prefix}-health.stderr" ;;
    headscale-go) curl -kfsS "${local_health_url}" >"${work_dir}/${prefix}-health.stdout" 2>"${work_dir}/${prefix}-health.stderr" ;;
  esac
}

server_grpc_health_probe() {
  local prefix
  prefix="$(server_log_prefix)"
  headscale_cmd health >"${work_dir}/${prefix}-grpc-health.stdout" 2>"${work_dir}/${prefix}-grpc-health.stderr"
}

mock_oidc_discovery_probe() {
  curl -fsS "http://127.0.0.1:${oidc_port}/oidc/.well-known/openid-configuration" \
    >"${work_dir}/mockoidc-discovery.stdout" \
    2>"${work_dir}/mockoidc-discovery.stderr"
}

install_headscale_go() {
  if [[ -n "${HEADSCALE_GO_BIN:-}" ]]; then
    return
  fi
  mkdir -p "${work_dir}/bin"
  GOBIN="${work_dir}/bin" go install "github.com/juanfont/headscale/cmd/headscale@${headscale_go_version}"
}

start_mock_oidc() {
  oidc_port="$(free_port)"
  local users_json
  users_json="$(
    ruby -rjson -e '
      groups = ARGV.fetch(3).split(",").reject(&:empty?)
      puts JSON.generate([{
        Subject: ARGV.fetch(0),
        Email: ARGV.fetch(1),
        EmailVerified: true,
        PreferredUsername: ARGV.fetch(2),
        Groups: groups,
      }])
    ' "${oidc_subject}" "${oidc_email}" "${oidc_username}" "${oidc_groups}"
  )"

  echo "::group::start mock OIDC"
  MOCKOIDC_CLIENT_ID="${oidc_client_id}" \
    MOCKOIDC_CLIENT_SECRET="${oidc_client_secret}" \
    MOCKOIDC_ADDR=127.0.0.1 \
    MOCKOIDC_PORT="${oidc_port}" \
    MOCKOIDC_USERS="${users_json}" \
    MOCKOIDC_ACCESS_TTL=10m \
    "${headscale_bin}" mockoidc \
    >"${work_dir}/mockoidc.stdout" \
    2>"${work_dir}/mockoidc.stderr" &
  mock_oidc_pid="$!"
  wait_for "mock OIDC discovery" \
    "mock_oidc_discovery_probe"
  echo "mock_oidc=http://127.0.0.1:${oidc_port}/oidc"
  echo "::endgroup::"
}

start_rust_server() {
  if [[ -z "${http_port}" ]]; then
    http_port="$(free_port)"
  fi
  if [[ -z "${https_port}" ]]; then
    https_port="$(free_port)"
  fi
  if [[ -z "${grpc_port}" ]]; then
    grpc_port="$(free_port)"
  fi
  control_port="${https_port}"
  control_url="https://host.docker.internal:${https_port}"
  local_health_url="http://127.0.0.1:${http_port}/health"
  config_path="${work_dir}/headscale-rs.toml"
  db_path="${work_dir}/db.sqlite"
  mkdir -p "${work_dir}/state"
  tls_cert_path="${work_dir}/state/tls.crt"
  rm -f "${headscale_rs_socket_path}"

  echo "::group::build headscale-rs CLI"
  if [[ "${database_backend}" == "postgres" ]]; then
    cargo build --quiet -p headscale-cli --features postgres-sqlx --bin headscale
  else
    cargo build --quiet -p headscale-cli --bin headscale
  fi
  target/debug/headscale version >"${work_dir}/headscale-rs-version.txt" 2>&1 || true
  echo "::endgroup::"

  cat >"${config_path}" <<EOF
[server]
listen = "127.0.0.1:${http_port}"
https_listen = "0.0.0.0:${https_port}"
grpc_listen_addr = "127.0.0.1:${grpc_port}"
server_url = "${control_url}"
state_dir = "${work_dir}/state"
db_path = "${db_path}"
tls_hostname = "host.docker.internal"
unix_socket = "${headscale_rs_socket_path}"
unix_socket_permission = 448

[noise]
private_key_path = "${work_dir}/state/noise_private.key"

[node]
expiry = "180d"

[dns]
magic_dns = true
base_domain = "${base_domain}"
override_local_dns = false
search_domains = []

[dns.nameservers]
global = []

[oidc]
issuer = "http://127.0.0.1:${oidc_port}/oidc"
client_id = "${oidc_client_id}"
client_secret = "${oidc_client_secret}"
allowed_domains = ["example.com"]
email_verified_required = true
EOF
  if [[ "${database_backend}" == "postgres" ]]; then
    cat >>"${config_path}" <<EOF

[database]
type = "postgres"

[database.postgres]
host = $(quoted_string "${postgres_host}")
port = ${postgres_port}
name = $(quoted_string "${postgres_database_name}")
user = $(quoted_string "${postgres_user}")
pass = $(quoted_string "${postgres_pass}")
ssl = $(quoted_string "${postgres_sslmode}")
EOF
    if ! ((oidc_policy_churn_flag)); then
      cat >>"${config_path}" <<EOF

[policy]
mode = "database"
EOF
    fi
  else
    cat >>"${config_path}" <<EOF

[database]
type = "sqlite"
EOF
  fi
  if ((oidc_policy_churn_flag)); then
    cat >>"${config_path}" <<EOF

[policy]
mode = "file"
path = "${policy_path}"
EOF
  fi

  echo "::group::start headscale-rs OIDC server"
  printf '\n--- headscale-rs start %s ---\n' "$(date -u +%FT%TZ)" >>"${work_dir}/headscale-rs.stdout"
  printf '\n--- headscale-rs start %s ---\n' "$(date -u +%FT%TZ)" >>"${work_dir}/headscale-rs.stderr"
  target/debug/headscale --config "${config_path}" serve \
    >>"${work_dir}/headscale-rs.stdout" \
    2>>"${work_dir}/headscale-rs.stderr" &
  server_pid="$!"
  wait_for "headscale-rs health" "server_health_probe"
  wait_for "headscale-rs TLS certificate" "test -s '${tls_cert_path}'"
  wait_for "headscale-rs gRPC" "server_grpc_health_probe"
  echo "headscale-rs control=http://127.0.0.1:${http_port}"
  echo "headscale-rs login=${control_url}"
  echo "::endgroup::"
}

write_headscale_go_database_config() {
  case "${database_backend}" in
    sqlite)
      cat <<EOF

database:
  type: sqlite
  sqlite:
    path: ${db_path}
EOF
      ;;
    postgres)
      cat <<EOF

database:
  type: postgres
  postgres:
    host: $(quoted_string "${postgres_host}")
    port: ${postgres_port}
    name: $(quoted_string "${postgres_database_name}")
    user: $(quoted_string "${postgres_user}")
    pass: $(quoted_string "${postgres_pass}")
    ssl: $(quoted_string "${postgres_sslmode}")
EOF
      if ! ((oidc_policy_churn_flag)); then
        cat <<EOF

policy:
  mode: database
EOF
      fi
      ;;
  esac
}

start_headscale_go_server() {
  if [[ -z "${http_port}" ]]; then
    http_port="$(free_port)"
  fi
  if [[ -z "${metrics_port}" ]]; then
    metrics_port="$(free_port)"
  fi
  if [[ -z "${grpc_port}" ]]; then
    grpc_port="$(free_port)"
  fi
  control_port="${http_port}"
  control_url="https://host.docker.internal:${http_port}"
  local_health_url="https://127.0.0.1:${http_port}/health"
  config_path="${work_dir}/headscale-go.yaml"
  db_path="${work_dir}/db.sqlite"
  tls_cert_path="${work_dir}/tls.crt"
  if [[ -z "${headscale_go_socket_path}" ]]; then
    headscale_go_socket_path="/tmp/hs-oidc-${run_id}.sock"
  fi
  rm -f "${headscale_go_socket_path}"

  if [[ ! -s "${tls_cert_path}" || ! -s "${work_dir}/tls.key" ]]; then
    echo "::group::generate headscale-go TLS certificate"
    openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
      -keyout "${work_dir}/tls.key" \
      -out "${tls_cert_path}" \
      -subj "/CN=host.docker.internal" \
      -addext "subjectAltName=DNS:host.docker.internal,IP:127.0.0.1" \
      >"${work_dir}/openssl.stdout" \
      2>"${work_dir}/openssl.stderr"
    echo "::endgroup::"
  fi

  cat >"${work_dir}/derp.yaml" <<EOF
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
EOF

  cat >"${config_path}" <<EOF
server_url: ${control_url}
listen_addr: 0.0.0.0:${http_port}
metrics_listen_addr: 127.0.0.1:${metrics_port}
grpc_listen_addr: 127.0.0.1:${grpc_port}
grpc_allow_insecure: true
unix_socket: ${headscale_go_socket_path}
unix_socket_permission: "0700"

private_key_path: ${work_dir}/private.key
noise:
  private_key_path: ${work_dir}/noise_private.key

prefixes:
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential

dns:
  magic_dns: true
  base_domain: "${base_domain}"
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []

logtail:
  enabled: false

cli:
  timeout: 5s

log:
  level: info
  format: text

tls_cert_path: ${tls_cert_path}
tls_key_path: ${work_dir}/tls.key

derp:
  server:
    enabled: false
  urls: []
  paths:
    - ${work_dir}/derp.yaml
  auto_update_enabled: false

oidc:
  only_start_if_oidc_is_available: true
  issuer: "http://127.0.0.1:${oidc_port}/oidc"
  client_id: "${oidc_client_id}"
  client_secret: "${oidc_client_secret}"
  allowed_domains:
    - example.com
  email_verified_required: true
EOF
  write_headscale_go_database_config >>"${config_path}"
  if ((oidc_policy_churn_flag)); then
    cat >>"${config_path}" <<EOF

policy:
  mode: file
  path: ${policy_path}
EOF
  fi

  echo "::group::start headscale-go OIDC server"
  printf '\n--- headscale-go start %s ---\n' "$(date -u +%FT%TZ)" >>"${work_dir}/headscale-go.stdout"
  printf '\n--- headscale-go start %s ---\n' "$(date -u +%FT%TZ)" >>"${work_dir}/headscale-go.stderr"
  "${headscale_bin}" -c "${config_path}" serve \
    >>"${work_dir}/headscale-go.stdout" \
    2>>"${work_dir}/headscale-go.stderr" &
  server_pid="$!"
  wait_for "headscale-go health" "server_health_probe"
  wait_for "headscale-go gRPC" "server_grpc_health_probe"
  echo "headscale-go login=${control_url}"
  echo "::endgroup::"
}

start_client() {
  local active_client_name="${1:-${client_name}}"
  echo "::group::start stock tailscale client ${active_client_name}"
  docker run -d \
    --name "${active_client_name}" \
    --hostname "${active_client_name}" \
    --add-host host.docker.internal:host-gateway \
    --entrypoint /bin/sh \
    -v "${tls_cert_path}:/usr/local/share/ca-certificates/headscale-oidc.crt:ro" \
    "${image}" \
    -ceu 'update-ca-certificates >/tmp/update-ca-certificates.log 2>&1; tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity' \
    >/dev/null

  wait_for "tailscaled local socket" \
    "docker exec '${active_client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
  echo "::endgroup::"
}

drive_oidc_login() {
  local active_client_name="${1:-${client_name}}"
  echo "::group::tailscale OIDC login ${active_client_name}"
  local oidc_registration_success_pattern="Authenticated|Signed in successfully|Node registered|Node reauthenticated"
  local tailscale_up_args=(
    "--login-server=${control_url}" \
    "--hostname=${active_client_name}" \
    "--timeout=60s" \
    --accept-routes=false \
    --accept-dns=false
  )
  if [[ -n "${oidc_advertise_routes}" ]]; then
    tailscale_up_args+=("--advertise-routes=${oidc_advertise_routes}")
  fi
  docker exec "${active_client_name}" tailscale up "${tailscale_up_args[@]}" \
    >"${work_dir}/${active_client_name}.tailscale-up.stdout" \
    2>"${work_dir}/${active_client_name}.tailscale-up.stderr" &
  local up_pid="$!"

  local registration_id_path="${work_dir}/${active_client_name}.registration-id"
  if ! wait_for "OIDC registration URL" \
    "write_registration_id '${registration_id_path}' '${active_client_name}'"; then
    dump_client_debug "${active_client_name}"
    exit 1
  fi
  local registration_id
  registration_id="$(cat "${registration_id_path}")"
  local callback_headers="${work_dir}/${active_client_name}.oidc-callback.headers"
  local callback_html="${work_dir}/${active_client_name}.oidc-callback.html"
  local confirm_html="${work_dir}/${active_client_name}.oidc-confirm.html"
  local cookie_jar="${work_dir}/${active_client_name}.oidc.cookies"
  curl -fsSL \
    -D "${callback_headers}" \
    --cacert "${tls_cert_path}" \
    --resolve "host.docker.internal:${control_port}:127.0.0.1" \
    -c "${cookie_jar}" \
    -b "${cookie_jar}" \
    "${control_url}/register/${registration_id}" \
    >"${callback_html}"
  grep -Eiq "Location: .*host\.docker\.internal:${control_port}/oidc/callback\\?" "${callback_headers}"
  if grep -Eq "Confirm node registration" "${callback_html}"; then
    local confirm_csrf
    confirm_csrf="$(sed -n 's/.*name="headscale_register_confirm" value="\([^"]*\)".*/\1/p' "${callback_html}" | head -n 1)"
    if [[ -z "${confirm_csrf}" ]]; then
      echo "OIDC confirmation page did not contain CSRF token" >&2
      exit 1
    fi
    curl -fsSL \
      --cacert "${tls_cert_path}" \
      --resolve "host.docker.internal:${control_port}:127.0.0.1" \
      -c "${cookie_jar}" \
      -b "${cookie_jar}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      --data "headscale_register_confirm=${confirm_csrf}" \
      "${control_url}/register/confirm/${registration_id}" \
      >"${confirm_html}"
    grep -Eq "${oidc_registration_success_pattern}" "${confirm_html}"
  elif grep -Eq "${oidc_registration_success_pattern}" "${callback_html}"; then
    cp "${callback_html}" "${confirm_html}"
    echo "OIDC callback completed registration without explicit confirm form"
  else
    echo "OIDC callback contained neither confirmation form nor success page" >&2
    exit 1
  fi

  if ! wait_pid_with_timeout "tailscale up OIDC" "${up_pid}"; then
    echo "tailscale up returned non-zero; verifying logged-in netmap" >&2
  fi
  if ! wait_for "tailscale logged-in netmap" "tailscale_logged_in '${active_client_name}'"; then
    dump_client_debug "${active_client_name}"
    exit 1
  fi
  docker exec "${active_client_name}" tailscale status --json >"${work_dir}/${active_client_name}.tailscale-status.json"
  echo "::endgroup::"
}

write_oidc_policy_churn_initial_policy() {
  cat >"${policy_path}" <<EOF
{
  "acls": [
    {
      "action": "accept",
      "src": ["${policy_churn_viewer_user}@"],
      "dst": ["${policy_churn_viewer_user}@:*"]
    }
  ]
}
EOF
}

write_oidc_policy_churn_allow_policy() {
  cat >"${policy_path}" <<EOF
{
  "acls": [
    {
      "action": "accept",
      "src": ["*"],
      "dst": ["*:*"]
    }
  ]
}
EOF
}

create_policy_churn_viewer_authkey() {
  echo "::group::create policy-churn viewer preauth key"
  headscale_cmd -o json users create "${policy_churn_viewer_user}" >"${work_dir}/policy-churn-viewer-user.json"
  local user_id
  user_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("id")' "${work_dir}/policy-churn-viewer-user.json")"
  headscale_cmd -o json preauthkeys create \
    --user "${user_id}" \
    --reusable \
    --expiration 1h \
    >"${work_dir}/policy-churn-viewer-preauth.json"
  policy_churn_viewer_authkey="$(
    ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("key")' \
      "${work_dir}/policy-churn-viewer-preauth.json"
  )"
  echo "minted ${policy_churn_viewer_authkey%%-*}-..."
  echo "::endgroup::"
}

drive_authkey_login() {
  local active_client_name="$1"
  local authkey="$2"
  echo "::group::tailscale auth-key login ${active_client_name}"
  docker exec "${active_client_name}" tailscale up \
    "--login-server=${control_url}" \
    "--hostname=${active_client_name}" \
    "--timeout=60s" \
    --accept-routes=false \
    --accept-dns=false \
    "--authkey=${authkey}" \
    >"${work_dir}/${active_client_name}.tailscale-up.stdout" \
    2>"${work_dir}/${active_client_name}.tailscale-up.stderr" ||
    echo "tailscale up returned non-zero for ${active_client_name}; verifying logged-in netmap" >&2
  if ! wait_for "tailscale logged-in netmap ${active_client_name}" "tailscale_logged_in '${active_client_name}'"; then
    dump_client_debug "${active_client_name}"
    exit 1
  fi
  docker exec "${active_client_name}" tailscale status --json >"${work_dir}/${active_client_name}.tailscale-status.json"
  echo "::endgroup::"
}

tailscale_peer_count_matches() {
  local active_client_name="$1"
  local expected_count="$2"
  docker exec "${active_client_name}" tailscale status --json 2>/dev/null | ruby -rjson -e '
    status = JSON.parse(STDIN.read)
    peers = status["Peer"] || {}
    exit(peers.length == Integer(ARGV.fetch(0)) ? 0 : 1)
  ' "${expected_count}"
}

assert_tailscale_peer_count() {
  local active_client_name="$1"
  local expected_count="$2"
  local output_path="$3"
  if ! wait_for "tailscale peer count ${expected_count} for ${active_client_name}" \
    "tailscale_peer_count_matches '${active_client_name}' '${expected_count}'"; then
    dump_client_debug "${active_client_name}"
    exit 1
  fi
  docker exec "${active_client_name}" tailscale status --json >"${output_path}"
  ruby -rjson -e '
    status = JSON.parse(File.read(ARGV.fetch(0)))
    peers = status["Peer"] || {}
    puts JSON.pretty_generate({
      self: status.fetch("Self").fetch("HostName"),
      peer_count: peers.length,
      peers: peers.each_value.map { |peer| peer.fetch("HostName") }.sort,
    })
  ' "${output_path}"
}

tailscale_peer_visible_with_profile() {
  local source_name="$1"
  local peer_name="$2"
  local output_path="$3"
  docker exec "${source_name}" tailscale status --json >"${output_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      status = JSON.parse(File.read(ARGV.fetch(0)))
      peer_name = ARGV.fetch(1)
      expected_logins = [ARGV.fetch(2), ARGV.fetch(3)]
      peer = (status["Peer"] || {}).each_value.find { |candidate| candidate["HostName"] == peer_name }
      abort("missing peer #{peer_name}") unless peer

      profiles = status["User"] || status["Users"] || status["UserProfiles"] || {}
      user_id = peer["UserID"] || peer["UserId"] || peer["userID"] || peer["userId"]
      profile = nil
      if profiles.is_a?(Hash)
        profile = profiles[user_id.to_s] if user_id
        profile ||= profiles.each_value.find do |candidate|
          candidate.is_a?(Hash) &&
            [candidate["ID"], candidate["Id"], candidate["id"]].compact.map(&:to_s).include?(user_id.to_s)
        end
      elsif profiles.is_a?(Array)
        profile = profiles.find do |candidate|
          candidate.is_a?(Hash) &&
            [candidate["ID"], candidate["Id"], candidate["id"]].compact.map(&:to_s).include?(user_id.to_s)
        end
      end
      login = nil
      if profile.is_a?(Hash)
        login = profile["LoginName"] || profile["loginName"] || profile["login_name"] ||
          profile["DisplayName"] || profile["displayName"] || profile["display_name"] ||
          profile["Name"] || profile["name"]
      end
      abort("missing user profile for #{peer_name}: #{JSON.pretty_generate(status)}") if login.to_s.empty?
      abort("expected #{peer_name} profile #{expected_logins.inspect}, got #{login.inspect}") unless expected_logins.include?(login.to_s)

      puts JSON.pretty_generate({
        source: status.fetch("Self").fetch("HostName"),
        peer: peer.fetch("HostName"),
        profile: login,
        peer_ips: peer["TailscaleIPs"] || peer["TailscaleIP"],
      })
    ' "${output_path}" "${peer_name}" "${oidc_email}" "${oidc_username}"
}

assert_policy_churn_cli_state() {
  echo "::group::assert policy-churn admin node state"
  local nodes_path="${work_dir}/policy-churn-nodes.json"
  headscale_cmd -o json nodes list >"${nodes_path}"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    viewer_name = ARGV.fetch(1)
    viewer_user = ARGV.fetch(2)
    peer_name = ARGV.fetch(3)
    oidc_email = ARGV.fetch(4)
    oidc_username = ARGV.fetch(5)
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    abort("expected 2 nodes, got #{nodes.length}") unless nodes.length == 2
    by_name = nodes.to_h do |node|
      name = node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
      [name.to_s, node]
    end
    viewer = by_name.fetch(viewer_name)
    peer = by_name.fetch(peer_name)
    user_name = lambda do |node|
      user = node["user"] || node["User"]
      user.is_a?(Hash) ? (user["name"] || user["loginName"] || user["login_name"]) : user.to_s
    end
    viewer_actual_user = user_name.call(viewer)
    peer_actual_user = user_name.call(peer)
    abort("expected viewer user #{viewer_user}, got #{viewer_actual_user.inspect}") unless viewer_actual_user == viewer_user
    abort("expected OIDC user #{oidc_email} or #{oidc_username}, got #{peer_actual_user.inspect}") unless [oidc_email, oidc_username].include?(peer_actual_user)
    register_method = peer["registerMethod"] || peer["register_method"]
    abort("expected OIDC register method, got #{register_method.inspect}") unless register_method.to_s.match?(/oidc/i) || register_method.to_s == "3"
    puts JSON.pretty_generate({viewer: viewer_name, oidc_peer: peer_name, oidc_user: peer_actual_user})
  ' "${nodes_path}" "${policy_churn_viewer_name}" "${policy_churn_viewer_user}" "${policy_churn_peer_name}" "${oidc_email}" "${oidc_username}"
  echo "::endgroup::"
}

reload_oidc_policy_churn_policy() {
  echo "::group::reload OIDC policy-churn policy"
  write_oidc_policy_churn_allow_policy
  kill -HUP "${server_pid}"
  wait_for "${target} health after OIDC policy reload" "server_health_probe"
  wait_for "OIDC peer visible to viewer after policy reload" \
    "tailscale_peer_visible_with_profile '${policy_churn_viewer_name}' '${policy_churn_peer_name}' '${work_dir}/policy-churn-viewer-after-reload-status.json'" || {
      dump_client_debug "${policy_churn_viewer_name}"
      exit 1
    }
  cat "${work_dir}/policy-churn-viewer-after-reload-status.json"
  echo "::endgroup::"
}

restart_oidc_policy_churn_server_and_assert_maps() {
  ((oidc_restart_flag)) || return 0

  echo "::group::restart OIDC policy-churn server"
  stop_server
  if [[ "${target}" == "rust" ]]; then
    start_rust_server
  else
    start_headscale_go_server
  fi
  wait_for "policy-churn viewer logged-in netmap after OIDC policy restart" \
    "tailscale_logged_in '${policy_churn_viewer_name}'"
  wait_for "policy-churn OIDC peer logged-in netmap after OIDC policy restart" \
    "tailscale_logged_in '${policy_churn_peer_name}'"
  wait_for "OIDC peer visible to viewer after policy restart" \
    "tailscale_peer_visible_with_profile '${policy_churn_viewer_name}' '${policy_churn_peer_name}' '${work_dir}/policy-churn-viewer-after-restart-status.json'" || {
      dump_client_debug "${policy_churn_viewer_name}"
      exit 1
    }
  cat "${work_dir}/policy-churn-viewer-after-restart-status.json"
  assert_policy_churn_cli_state
  echo "::endgroup::"
}

run_oidc_policy_churn_smoke() {
  create_policy_churn_viewer_authkey
  start_client "${policy_churn_viewer_name}"
  drive_authkey_login "${policy_churn_viewer_name}" "${policy_churn_viewer_authkey}"
  echo "::group::assert policy-churn initial viewer map"
  assert_tailscale_peer_count "${policy_churn_viewer_name}" 0 "${work_dir}/policy-churn-viewer-initial-status.json"
  echo "::endgroup::"

  start_client "${policy_churn_peer_name}"
  drive_oidc_login "${policy_churn_peer_name}"
  assert_policy_churn_cli_state
  reload_oidc_policy_churn_policy
}

assert_sqlite_oidc_state() {
  echo "::group::assert OIDC SQLite state"
  local node_count
  node_count="$(sqlite3 "${db_path}" "SELECT COUNT(*) FROM nodes WHERE deleted_at IS NULL;")"
  if [[ "${node_count}" != "1" ]]; then
    echo "expected 1 node row, got ${node_count}" >&2
    exit 1
  fi
  local user_count
  user_count="$(sqlite3 "${db_path}" "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL;")"
  if [[ "${user_count}" != "1" ]]; then
    echo "expected 1 user row, got ${user_count}" >&2
    exit 1
  fi

  local node_row sqlite_sep
  sqlite_sep="|"
  node_row="$(
    sqlite3 -separator "${sqlite_sep}" "${db_path}" \
      "SELECT COALESCE(n.register_method,''), COALESCE(n.machine_key,''), COALESCE(n.node_key,''), COALESCE(n.hostname,''), COALESCE(n.given_name,''), COALESCE(n.ipv4,''), COALESCE(n.expiry,''), COALESCE(n.user_id,''), COALESCE(u.name,''), COALESCE(u.email,''), COALESCE(u.provider,''), COALESCE(u.provider_identifier,'') FROM nodes n JOIN users u ON u.id = n.user_id AND u.deleted_at IS NULL WHERE n.deleted_at IS NULL LIMIT 1;"
  )"
  local register_method machine_key node_key hostname given_name ipv4 expiry user_id user_name email provider provider_identifier
  IFS="${sqlite_sep}" read -r register_method machine_key node_key hostname given_name ipv4 expiry user_id user_name email provider provider_identifier <<<"${node_row}"
  [[ "${register_method}" == "oidc" ]] || { echo "expected node register_method oidc, got ${register_method}" >&2; exit 1; }
  [[ -n "${machine_key}" ]] || { echo "expected non-empty machine_key" >&2; exit 1; }
  [[ -n "${node_key}" ]] || { echo "expected non-empty node_key" >&2; exit 1; }
  [[ "${hostname}" == "${client_name}" || "${given_name}" == "${client_name}" ]] || {
    echo "expected hostname/given_name ${client_name}, got hostname=${hostname} given_name=${given_name}" >&2
    exit 1
  }
  [[ "${ipv4}" == 100.* ]] || { echo "expected CGNAT IPv4, got ${ipv4}" >&2; exit 1; }
  [[ -n "${expiry}" ]] || { echo "expected non-empty OIDC node expiry" >&2; exit 1; }
  [[ -n "${user_id}" ]] || { echo "expected node user_id" >&2; exit 1; }
  [[ "${user_name}" == "${oidc_username}" ]] || { echo "expected OIDC user name ${oidc_username}, got ${user_name}" >&2; exit 1; }
  [[ "${email}" == "${oidc_email}" ]] || { echo "expected OIDC email ${oidc_email}, got ${email}" >&2; exit 1; }
  [[ "${provider}" == "oidc" ]] || { echo "expected OIDC provider oidc, got ${provider}" >&2; exit 1; }
  local expected_provider_identifier="http://127.0.0.1:${oidc_port}/oidc/${oidc_subject}"
  [[ "${provider_identifier}" == "${expected_provider_identifier}" ]] || {
    echo "expected provider_identifier ${expected_provider_identifier}, got ${provider_identifier}" >&2
    exit 1
  }

  ruby -rjson -e '
    status = JSON.parse(File.read(ARGV.fetch(0)))
    self_node = status.fetch("Self")
    abort("expected self hostname #{ARGV.fetch(1)}, got #{self_node["HostName"].inspect}") unless self_node["HostName"] == ARGV.fetch(1)
    puts JSON.pretty_generate({
      host: self_node["HostName"],
      ips: status.fetch("TailscaleIPs"),
      user: ARGV.fetch(2),
    })
  ' "${work_dir}/${client_name}.tailscale-status.json" "${client_name}" "${oidc_email}"
  echo "::endgroup::"
}

assert_postgres_oidc_state() {
  echo "::group::assert OIDC Postgres state"
  local node_count
  node_count="$(psql "${postgres_runtime_url}" -v ON_ERROR_STOP=1 -At -c "SELECT COUNT(*) FROM nodes WHERE deleted_at IS NULL;")"
  if [[ "${node_count}" != "1" ]]; then
    echo "expected 1 node row, got ${node_count}" >&2
    exit 1
  fi
  local user_count
  user_count="$(psql "${postgres_runtime_url}" -v ON_ERROR_STOP=1 -At -c "SELECT COUNT(*) FROM users WHERE deleted_at IS NULL;")"
  if [[ "${user_count}" != "1" ]]; then
    echo "expected 1 user row, got ${user_count}" >&2
    exit 1
  fi

  local node_row
  node_row="$(
    psql "${postgres_runtime_url}" -v ON_ERROR_STOP=1 -At -F '|' -c \
      "SELECT COALESCE(n.register_method,''), COALESCE(n.machine_key,''), COALESCE(n.node_key,''), COALESCE(n.hostname,''), COALESCE(n.given_name,''), COALESCE(n.ipv4,''), COALESCE(n.expiry::text,''), COALESCE(n.user_id::text,''), COALESCE(u.name,''), COALESCE(u.email,''), COALESCE(u.provider,''), COALESCE(u.provider_identifier,'') FROM nodes n JOIN users u ON u.id = n.user_id AND u.deleted_at IS NULL WHERE n.deleted_at IS NULL LIMIT 1;"
  )"
  assert_oidc_node_row "${node_row}"
  echo "::endgroup::"
}

assert_oidc_node_row() {
  local node_row="$1"
  local register_method machine_key node_key hostname given_name ipv4 expiry user_id user_name email provider provider_identifier
  IFS="|" read -r register_method machine_key node_key hostname given_name ipv4 expiry user_id user_name email provider provider_identifier <<<"${node_row}"
  [[ "${register_method}" == "oidc" ]] || { echo "expected node register_method oidc, got ${register_method}" >&2; exit 1; }
  [[ -n "${machine_key}" ]] || { echo "expected non-empty machine_key" >&2; exit 1; }
  [[ -n "${node_key}" ]] || { echo "expected non-empty node_key" >&2; exit 1; }
  [[ "${hostname}" == "${client_name}" || "${given_name}" == "${client_name}" ]] || {
    echo "expected hostname/given_name ${client_name}, got hostname=${hostname} given_name=${given_name}" >&2
    exit 1
  }
  [[ "${ipv4}" == 100.* ]] || { echo "expected CGNAT IPv4, got ${ipv4}" >&2; exit 1; }
  [[ -n "${expiry}" ]] || { echo "expected non-empty OIDC node expiry" >&2; exit 1; }
  [[ -n "${user_id}" ]] || { echo "expected node user_id" >&2; exit 1; }
  [[ "${user_name}" == "${oidc_username}" ]] || { echo "expected OIDC user name ${oidc_username}, got ${user_name}" >&2; exit 1; }
  [[ "${email}" == "${oidc_email}" ]] || { echo "expected OIDC email ${oidc_email}, got ${email}" >&2; exit 1; }
  [[ "${provider}" == "oidc" ]] || { echo "expected OIDC provider oidc, got ${provider}" >&2; exit 1; }
  local expected_provider_identifier="http://127.0.0.1:${oidc_port}/oidc/${oidc_subject}"
  [[ "${provider_identifier}" == "${expected_provider_identifier}" ]] || {
    echo "expected provider_identifier ${expected_provider_identifier}, got ${provider_identifier}" >&2
    exit 1
  }
}

assert_oidc_database_state() {
  case "${database_backend}" in
    sqlite) assert_sqlite_oidc_state ;;
    postgres) assert_postgres_oidc_state ;;
  esac
}

assert_headscale_go_cli_state() {
  [[ "${target}" == "headscale-go" ]] || return 0
  local expected_approved_routes
  if (($# > 0)); then
    expected_approved_routes="$1"
  else
    expected_approved_routes="${oidc_approve_routes}"
  fi
  echo "::group::assert headscale-go node CLI state"
  headscale_cmd -o json nodes list >"${work_dir}/nodes.json"
  assert_cli_nodes_json "${work_dir}/nodes.json" "${oidc_advertise_routes}" "${expected_approved_routes}"
  echo "::endgroup::"
}

assert_rust_cli_state() {
  [[ "${target}" == "rust" ]] || return 0
  local expected_approved_routes
  if (($# > 0)); then
    expected_approved_routes="$1"
  else
    expected_approved_routes="${oidc_approve_routes}"
  fi
  echo "::group::assert headscale-rs node CLI state"
  headscale_cmd -o json nodes list >"${work_dir}/nodes.json"
  assert_cli_nodes_json "${work_dir}/nodes.json" "${oidc_advertise_routes}" "${expected_approved_routes}"
  echo "::endgroup::"
}

assert_cli_nodes_json() {
  local nodes_json_path="$1"
  local expected_available_routes="$2"
  local expected_approved_routes="$3"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    abort("expected 1 node, got #{nodes.length}") unless nodes.length == 1
    node = nodes.fetch(0)
    user = node["user"] || node["User"]
    user_name = user.is_a?(Hash) ? (user["name"] || user["loginName"] || user["login_name"]) : user.to_s
    given_name = node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
    addresses = Array(node["ipAddresses"] || node["ip_addresses"] || node["addresses"])
    register_method = node["registerMethod"] || node["register_method"]
    expiry = node["expiry"] || node["Expiry"] || node["expiresAt"] || node["expires_at"]
    available_routes = Array(node["availableRoutes"] || node["available_routes"]).map(&:to_s).sort
    approved_routes = Array(node["approvedRoutes"] || node["approved_routes"]).map(&:to_s).sort
    expected_available = ARGV.fetch(4).split(",").reject(&:empty?).sort
    expected_approved = ARGV.fetch(5).split(",").reject(&:empty?).sort
    abort("expected hostname #{ARGV.fetch(1)}, got #{given_name.inspect}") unless given_name.to_s == ARGV.fetch(1)
    abort("expected user #{ARGV.fetch(2)} or #{ARGV.fetch(3)}, got #{user.inspect}") unless [ARGV.fetch(2), ARGV.fetch(3)].include?(user_name)
    abort("expected CGNAT IPv4, got #{addresses.inspect}") unless addresses.any? { |ip| ip.to_s.start_with?("100.") }
    abort("expected OIDC register method, got #{register_method.inspect}") unless register_method.to_s.match?(/oidc/i) || register_method.to_s == "3"
    abort("expected node expiry in CLI output") if expiry.to_s.empty?
    expected_available.each do |route|
      abort("expected available route #{route.inspect}, got #{available_routes.inspect}") unless available_routes.include?(route)
    end
    expected_approved.each do |route|
      abort("expected approved route #{route.inspect}, got #{approved_routes.inspect}") unless approved_routes.include?(route)
    end
    puts JSON.pretty_generate(node)
  ' "${nodes_json_path}" "${client_name}" "${oidc_email}" "${oidc_username}" "${expected_available_routes}" "${expected_approved_routes}"
}

load_oidc_node_id() {
  local nodes_path="${work_dir}/nodes-for-oidc-route-approval.json"
  headscale_cmd -o json nodes list >"${nodes_path}"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    expected_name = ARGV.fetch(1)
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    node = nodes.find do |candidate|
      names = [
        candidate["givenName"],
        candidate["given_name"],
        candidate["name"],
        candidate["hostname"],
      ].compact.map(&:to_s)
      names.include?(expected_name)
    end
    abort("missing node #{expected_name.inspect} in #{nodes.inspect}") unless node
    node_id = node["id"] || node["ID"] || node["nodeId"] || node["node_id"]
    abort("expected non-empty node ID for #{expected_name}") if node_id.to_s.empty?
    puts node_id
  ' "${nodes_path}" "${client_name}"
}

approve_oidc_routes() {
  [[ -n "${oidc_approve_routes}" ]] || return 0

  echo "::group::approve OIDC advertised routes"
  local node_id
  node_id="$(load_oidc_node_id)"
  headscale_cmd -o json nodes approve-routes --identifier "${node_id}" --routes "${oidc_approve_routes}" \
    >"${work_dir}/approved-oidc-routes-${node_id}.json"
  echo "::endgroup::"

  assert_rust_cli_state
  assert_headscale_go_cli_state
  assert_oidc_self_route_netmap "after-approval"
}

oidc_self_netmap_routes_match() {
  local active_client_name="$1"
  local expected_routes="$2"
  local output_path="$3"
  local netmap_path="${output_path}.netmap"
  docker exec "${active_client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      netmap = JSON.parse(File.read(ARGV.fetch(0)))
      client_name = ARGV.fetch(1)
      expected_routes = ARGV.fetch(2).split(",").reject(&:empty?).sort
      self_node = netmap["SelfNode"] || netmap["selfNode"] || netmap["Self"] || netmap["self"]
      abort("missing self node in netmap") unless self_node.is_a?(Hash)

      def route_values(node, keys)
        keys.flat_map { |key| Array(node[key]) }.compact.flatten.map(&:to_s).sort.uniq
      end

      allowed_routes = route_values(self_node, [
        "AllowedIPs",
        "AllowedIps",
        "allowedIPs",
        "allowed_ips",
      ])
      primary_routes = route_values(self_node, [
        "PrimaryRoutes",
        "primaryRoutes",
        "primary_routes",
        "SubnetRoutes",
        "subnetRoutes",
        "subnet_routes",
      ])
      expected_routes.each do |route|
        abort("expected self AllowedIPs to include #{route.inspect}, got #{allowed_routes.inspect}") unless allowed_routes.include?(route)
        abort("expected self PrimaryRoutes to include #{route.inspect}, got #{primary_routes.inspect}") unless primary_routes.include?(route)
      end

      puts JSON.pretty_generate({
        client: client_name,
        expected_routes: expected_routes,
        allowed_routes: allowed_routes,
        primary_routes: primary_routes,
      })
    ' "${netmap_path}" "${active_client_name}" "${expected_routes}" >"${output_path}"
}

assert_oidc_self_route_netmap() {
  [[ -n "${oidc_approve_routes}" ]] || return 0

  local label="$1"
  local safe_label="${label//[^a-zA-Z0-9_.-]/-}"
  local output_path="${work_dir}/oidc-self-route-netmap-${safe_label}.json"
  echo "::group::assert OIDC approved route in self netmap ${label}"
  if ! wait_for "OIDC approved route in self netmap ${label}" \
    "oidc_self_netmap_routes_match '${client_name}' '${oidc_approve_routes}' '${output_path}'"; then
    cat "${output_path}.err" >&2 || true
    dump_client_debug "${client_name}"
    exit 1
  fi
  cat "${output_path}"
  echo "::endgroup::"
}

restart_oidc_server_and_assert_client() {
  ((oidc_restart_flag)) || return 0

  echo "::group::restart OIDC server"
  stop_server
  if [[ "${target}" == "rust" ]]; then
    start_rust_server
  else
    start_headscale_go_server
  fi
  if ! wait_for "tailscale logged-in netmap after OIDC restart" "tailscale_logged_in"; then
    dump_client_debug
    exit 1
  fi
  docker exec "${client_name}" tailscale status --json >"${work_dir}/${client_name}.tailscale-status.json"
  echo "::endgroup::"

  assert_oidc_database_state
  assert_rust_cli_state
  assert_headscale_go_cli_state
  assert_oidc_self_route_netmap "after-restart"
}

need ruby
prepare_postgres_database
need cargo
need curl
need docker
case "${database_backend}" in
  sqlite) need sqlite3 ;;
  postgres) need psql ;;
esac
if [[ -z "${HEADSCALE_GO_BIN:-}" ]]; then
  need go
fi
if [[ "${target}" == "headscale-go" ]]; then
  need openssl
fi

echo "::group::build headscale-go ${headscale_go_version} for mock OIDC"
install_headscale_go
"${headscale_bin}" version >"${work_dir}/headscale-go-version.txt"
cat "${work_dir}/headscale-go-version.txt"
echo "::endgroup::"

start_mock_oidc
if ((oidc_policy_churn_flag)); then
  write_oidc_policy_churn_initial_policy
fi
if [[ "${target}" == "rust" ]]; then
  start_rust_server
else
  start_headscale_go_server
fi
if ((oidc_policy_churn_flag)); then
  run_oidc_policy_churn_smoke
  restart_oidc_policy_churn_server_and_assert_maps
  if ((oidc_restart_flag)); then
    echo "${target} OIDC policy-churn restart real-client smoke passed"
  else
    echo "${target} OIDC policy-churn real-client smoke passed"
  fi
  exit 0
fi
start_client
drive_oidc_login
assert_oidc_database_state
assert_rust_cli_state ""
assert_headscale_go_cli_state ""
approve_oidc_routes
restart_oidc_server_and_assert_client

echo "${target} OIDC real-client smoke passed"
