#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

target="${REAL_CLIENT_OIDC_SSH_TARGET:-rust}"
case "${target}" in
  rust | headscale-go) ;;
  *)
    echo "REAL_CLIENT_OIDC_SSH_TARGET must be rust or headscale-go" >&2
    exit 2
    ;;
esac

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
headscale_go_version="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-180}"
ssh_user="${REAL_CLIENT_SSH_USER:-ssh-it-user}"
attempt_timeout="${REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS:-120}"
cancel_timeout="${REAL_CLIENT_OIDC_SSH_CANCEL_TIMEOUT_SECS:-15}"
oidc_client_id="${REAL_CLIENT_OIDC_CLIENT_ID:-headscale-rs}"
oidc_client_secret="${REAL_CLIENT_OIDC_CLIENT_SECRET:-secret}"
oidc_flow_count="${REAL_CLIENT_OIDC_FLOW_COUNT:-3}"
check_period_cache="${REAL_CLIENT_OIDC_SSH_CHECK_PERIOD_CACHE:-false}"
policy_mutation_restart="${REAL_CLIENT_OIDC_SSH_POLICY_MUTATION_RESTART:-false}"
check_result="${REAL_CLIENT_OIDC_SSH_CHECK_RESULT:-approve}"
check_approval="${REAL_CLIENT_OIDC_SSH_CHECK_APPROVAL:-oidc}"
register_cache_expiration="${REAL_CLIENT_REGISTER_CACHE_EXPIRATION:-}"
database_backend="${REAL_CLIENT_DATABASE_BACKEND:-sqlite}"
ssh_deny_status="${REAL_CLIENT_OIDC_SSH_DENY_STATUS:-255}"
ssh_deny_stderr_first_line="${REAL_CLIENT_OIDC_SSH_DENY_STDERR_FIRST_LINE:-}"
ssh_deny_stderr_regex="${REAL_CLIENT_OIDC_SSH_DENY_STDERR_REGEX:-tailscale: access denied|Permission denied \(tailscale\)}"
wrong_user_auth_status="${REAL_CLIENT_OIDC_SSH_WRONG_USER_AUTH_STATUS:-403}"
base_domain="${REAL_CLIENT_BASE_DOMAIN-tail.test}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/ssh-oidc-check-smoke}"
run_id="hs-ssh-oidc-${target}-${database_backend}-$(date +%s)-$$"
client_one="${REAL_CLIENT_CLIENT_ONE:-${run_id}-one}"
client_two="${REAL_CLIENT_CLIENT_TWO:-${run_id}-two}"

case "${check_period_cache}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    check_period_cache_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    check_period_cache_flag=0
    ;;
  *)
    echo "REAL_CLIENT_OIDC_SSH_CHECK_PERIOD_CACHE must be true or false, got ${check_period_cache}" >&2
    exit 2
    ;;
esac

case "${policy_mutation_restart}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    policy_mutation_restart_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    policy_mutation_restart_flag=0
    ;;
  *)
    echo "REAL_CLIENT_OIDC_SSH_POLICY_MUTATION_RESTART must be true or false, got ${policy_mutation_restart}" >&2
    exit 2
    ;;
esac

case "${check_result}" in
  approve | expire | wrong-user | cancel) ;;
  *)
    echo "REAL_CLIENT_OIDC_SSH_CHECK_RESULT must be approve, expire, wrong-user, or cancel, got ${check_result}" >&2
    exit 2
    ;;
esac

case "${check_approval}" in
  oidc | cli) ;;
  *)
    echo "REAL_CLIENT_OIDC_SSH_CHECK_APPROVAL must be oidc or cli, got ${check_approval}" >&2
    exit 2
    ;;
esac

if [[ "${check_result}" != "approve" && "${check_approval}" != "oidc" ]]; then
  echo "REAL_CLIENT_OIDC_SSH_CHECK_APPROVAL=cli is only valid with REAL_CLIENT_OIDC_SSH_CHECK_RESULT=approve" >&2
  exit 2
fi

if ((policy_mutation_restart_flag)); then
  if [[ "${database_backend}" != "postgres" ]]; then
    echo "REAL_CLIENT_OIDC_SSH_POLICY_MUTATION_RESTART requires REAL_CLIENT_DATABASE_BACKEND=postgres" >&2
    exit 2
  fi
  if [[ "${check_result}" != "approve" || "${check_approval}" != "oidc" ]]; then
    echo "REAL_CLIENT_OIDC_SSH_POLICY_MUTATION_RESTART requires OIDC-approved SSH checks" >&2
    exit 2
  fi
fi

case "${database_backend}" in
  sqlite | postgres) ;;
  *)
    echo "REAL_CLIENT_DATABASE_BACKEND must be sqlite or postgres" >&2
    exit 2
    ;;
esac

if [[ "${check_result}" == "cancel" ]]; then
  ssh_deny_status="${REAL_CLIENT_OIDC_SSH_DENY_STATUS:-124}"
  ssh_deny_stderr_first_line="${REAL_CLIENT_OIDC_SSH_DENY_STDERR_FIRST_LINE:-# Headscale SSH requires an additional check.}"
  ssh_deny_stderr_regex="${REAL_CLIENT_OIDC_SSH_DENY_STDERR_REGEX:-Headscale SSH requires an additional check}"
  if [[ ! "${cancel_timeout}" =~ ^[0-9]+$ ]] || ((cancel_timeout <= 0)); then
    echo "REAL_CLIENT_OIDC_SSH_CANCEL_TIMEOUT_SECS must be a positive integer, got ${cancel_timeout}" >&2
    exit 2
  fi
  attempt_timeout="${REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS:-${cancel_timeout}}"
fi

if [[ "${check_result}" == "expire" || "${check_result}" == "wrong-user" ]]; then
  register_cache_expiration="${register_cache_expiration:-10s}"
fi

if [[ "${check_result}" == "expire" || "${check_result}" == "wrong-user" || "${check_result}" == "cancel" ]]; then
  if ((check_period_cache_flag)); then
    echo "REAL_CLIENT_OIDC_SSH_CHECK_PERIOD_CACHE cannot be true when REAL_CLIENT_OIDC_SSH_CHECK_RESULT=${check_result}" >&2
    exit 2
  fi
fi

if [[ -n "${ssh_deny_status}" && "${ssh_deny_status}" != "any" && ! "${ssh_deny_status}" =~ ^[0-9]+$ ]]; then
  echo "REAL_CLIENT_OIDC_SSH_DENY_STATUS must be empty, any, or a non-negative integer, got ${ssh_deny_status}" >&2
  exit 2
fi

if [[ "${check_result}" == "wrong-user" && ! "${wrong_user_auth_status}" =~ ^[0-9]{3}$ ]]; then
  echo "REAL_CLIENT_OIDC_SSH_WRONG_USER_AUTH_STATUS must be a three-digit HTTP status, got ${wrong_user_auth_status}" >&2
  exit 2
fi

if ((check_period_cache_flag)); then
  default_policy_path="tools/real-client/fixtures/ssh-check-period.hujson"
  default_oidc_subject="user1-subject"
  default_oidc_email="user1"
  default_oidc_username="user1"
  default_oidc_allowed_domains=""
else
  default_policy_path="tools/real-client/fixtures/ssh-oidc-check.hujson"
  default_oidc_subject="alice-subject"
  default_oidc_email="alice@example.com"
  default_oidc_username="alice"
  default_oidc_allowed_domains="example.com"
fi

oidc_subject="${REAL_CLIENT_OIDC_SUBJECT:-${default_oidc_subject}}"
oidc_email="${REAL_CLIENT_OIDC_EMAIL:-${default_oidc_email}}"
oidc_username="${REAL_CLIENT_OIDC_USERNAME:-${default_oidc_username}}"
oidc_groups="${REAL_CLIENT_OIDC_GROUPS:-engineering}"
oidc_allowed_domains="${REAL_CLIENT_OIDC_ALLOWED_DOMAINS:-${default_oidc_allowed_domains}}"
wrong_user_oidc_subject="${REAL_CLIENT_OIDC_SSH_WRONG_USER_SUBJECT:-mallory-subject}"
wrong_user_oidc_email="${REAL_CLIENT_OIDC_SSH_WRONG_USER_EMAIL:-mallory@example.com}"
wrong_user_oidc_username="${REAL_CLIENT_OIDC_SSH_WRONG_USER_USERNAME:-mallory}"
wrong_user_oidc_groups="${REAL_CLIENT_OIDC_SSH_WRONG_USER_GROUPS:-engineering}"
policy_json="${REAL_CLIENT_POLICY_JSON:-$(cat "${default_policy_path}")}"
policy_mutation_initial_json="${REAL_CLIENT_OIDC_SSH_INITIAL_POLICY_JSON:-$(cat tools/real-client/fixtures/ssh-no-ssh.hujson)}"
policy_mutation_final_json="${REAL_CLIENT_OIDC_SSH_FINAL_POLICY_JSON:-${policy_json}}"

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
ssh_pid=""
control_url=""
local_health_url=""
control_port=""
config_path="${work_dir}/headscale-config"
db_path="${work_dir}/db.sqlite"
tls_cert_path=""
headscale_bin="${HEADSCALE_GO_BIN:-${work_dir}/bin/headscale}"
headscale_rs_socket_path="${REAL_CLIENT_HEADSCALE_RS_SOCKET:-/tmp/hsrs-${run_id}.sock}"
headscale_go_socket_path="/tmp/hs-ssh-oidc-${run_id}.sock"
postgres_admin_url=""
postgres_database_name=""
postgres_host=""
postgres_port=""
postgres_user=""
postgres_pass=""
postgres_sslmode=""
postgres_database_created=0

cleanup() {
  docker rm -f "${client_one}" "${client_two}" >/dev/null 2>&1 || true
  rm -f "${headscale_rs_socket_path}" "${headscale_go_socket_path}"
  if [[ -n "${ssh_pid}" ]]; then
    kill "${ssh_pid}" >/dev/null 2>&1 || true
    wait "${ssh_pid}" >/dev/null 2>&1 || true
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
      {
        postgres_admin_url: admin.to_s,
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
    echo "skipping Postgres OIDC SSH real-client smoke: HEADSCALE_DB_POSTGRES_TEST_URL is not set" >&2
    exit 0
  fi
  need psql
  postgres_database_name="headscale_rs_pg_ssh_oidc_${target//[^a-zA-Z0-9]/_}_$(date +%s)_$$"
  parse_postgres_test_url
  if ! [[ "${postgres_database_name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "internal temporary Postgres database name is invalid: ${postgres_database_name}" >&2
    exit 2
  fi
  echo "::group::create temporary Postgres database"
  if ! psql "${postgres_admin_url}" -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${postgres_database_name}" >"${work_dir}/postgres-create.stdout" 2>"${work_dir}/postgres-create.stderr"; then
    echo "skipping Postgres OIDC SSH real-client smoke: cannot create temporary database ${postgres_database_name}" >&2
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
  echo "::group::OIDC SSH startup debug (${reason})"
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

html_input_value() {
  local path="$1"
  local name="$2"
  ruby -e '
    html = File.read(ARGV.fetch(0))
    wanted = ARGV.fetch(1)
    html.scan(/<input\b[^>]*>/i) do |tag|
      attrs = {}
      tag.scan(/([[:alnum:]_-]+)\s*=\s*"([^"]*)"/) { |key, value| attrs[key.downcase] = value }
      next unless attrs["name"] == wanted
      puts attrs.fetch("value", "")
      exit 0
    end
    exit 1
  ' "${path}" "${name}"
}

oidc_allowed_domains_toml_items() {
  ruby -rjson -e '
    domains = ARGV.fetch(0).split(/[,\s]+/).reject(&:empty?)
    puts domains.map { |domain| JSON.generate(domain) }.join(", ")
  ' "${oidc_allowed_domains}"
}

oidc_allowed_domains_yaml() {
  ruby -rjson -e '
    domains = ARGV.fetch(0).split(/[,\s]+/).reject(&:empty?)
    if domains.empty?
      puts "  allowed_domains: []"
    else
      puts "  allowed_domains:"
      domains.each { |domain| puts "    - #{JSON.generate(domain)}" }
    end
  ' "${oidc_allowed_domains}"
}

register_cache_toml() {
  [[ -z "${register_cache_expiration}" ]] && return 0
  ruby -rjson -e 'puts "[tuning]\nregister_cache_expiration = #{JSON.generate(ARGV.fetch(0))}"' "${register_cache_expiration}"
}

register_cache_yaml() {
  [[ -z "${register_cache_expiration}" ]] && return 0
  ruby -rjson -e 'puts "tuning:\n  register_cache_expiration: #{JSON.generate(ARGV.fetch(0))}"' "${register_cache_expiration}"
}

install_headscale_go() {
  if [[ -n "${HEADSCALE_GO_BIN:-}" ]]; then
    return
  fi
  mkdir -p "${work_dir}/bin"
  GOBIN="${work_dir}/bin" go install "github.com/juanfont/headscale/cmd/headscale@${headscale_go_version}"
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

start_mock_oidc() {
  oidc_port="$(free_port)"
  local users_json
  users_json="$(
    ruby -rjson -e '
      count = Integer(ARGV.fetch(4))
      abort("REAL_CLIENT_OIDC_FLOW_COUNT must be positive") unless count.positive?
      check_result = ARGV.fetch(5)
      groups = ARGV.fetch(3).split(",").reject(&:empty?)
      user = {
        Subject: ARGV.fetch(0),
        Email: ARGV.fetch(1),
        EmailVerified: true,
        PreferredUsername: ARGV.fetch(2),
        Groups: groups,
      }
      users = Array.new(count) { user }
      if check_result == "wrong-user"
        abort("REAL_CLIENT_OIDC_FLOW_COUNT must be at least 3 for wrong-user SSH checks") if count < 3
        users[2] = {
          Subject: ARGV.fetch(6),
          Email: ARGV.fetch(7),
          EmailVerified: true,
          PreferredUsername: ARGV.fetch(8),
          Groups: ARGV.fetch(9).split(",").reject(&:empty?),
        }
      end
      puts JSON.generate(users)
    ' \
      "${oidc_subject}" \
      "${oidc_email}" \
      "${oidc_username}" \
      "${oidc_groups}" \
      "${oidc_flow_count}" \
      "${check_result}" \
      "${wrong_user_oidc_subject}" \
      "${wrong_user_oidc_email}" \
      "${wrong_user_oidc_username}" \
      "${wrong_user_oidc_groups}"
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

write_policy_file() {
  local policy_body="${1:-${policy_json}}"
  printf '%s\n' "${policy_body}" >"${work_dir}/ssh-oidc-check.hujson"
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

$(register_cache_toml)

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
allowed_domains = [$(oidc_allowed_domains_toml_items)]
email_verified_required = true
EOF
  case "${database_backend}" in
    sqlite)
      cat >>"${config_path}" <<EOF

[policy]
mode = "file"
path = "${work_dir}/ssh-oidc-check.hujson"
EOF
      ;;
    postgres)
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

[policy]
mode = "database"
EOF
      ;;
  esac

  echo "::group::start headscale-rs OIDC SSH server"
  printf '\n--- headscale-rs start %s ---\n' "$(date -u +%FT%TZ)" >>"${work_dir}/headscale-rs.stdout"
  printf '\n--- headscale-rs start %s ---\n' "$(date -u +%FT%TZ)" >>"${work_dir}/headscale-rs.stderr"
  target/debug/headscale --config "${config_path}" serve \
    >>"${work_dir}/headscale-rs.stdout" \
    2>>"${work_dir}/headscale-rs.stderr" &
  server_pid="$!"
  wait_for "headscale-rs health" "server_health_probe"
  wait_for "headscale-rs TLS certificate" "test -s '${tls_cert_path}'"
  wait_for "headscale-rs gRPC" "server_grpc_health_probe"
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

policy:
  mode: file
  path: ${work_dir}/ssh-oidc-check.hujson
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

policy:
  mode: database
EOF
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

$(register_cache_yaml)

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
$(oidc_allowed_domains_yaml)
  email_verified_required: true
EOF
  write_headscale_go_database_config >>"${config_path}"

  echo "::group::start headscale-go OIDC SSH server"
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
  local client_name="$1"
  echo "::group::start stock tailscale client ${client_name}"
  docker run -d \
    --name "${client_name}" \
    --hostname "${client_name}" \
    --add-host host.docker.internal:host-gateway \
    --entrypoint /bin/sh \
    -v "${tls_cert_path}:/usr/local/share/ca-certificates/headscale-oidc.crt:ro" \
    "${image}" \
    -ceu "apk add --no-cache openssh-client >/tmp/apk-openssh-client.log 2>&1; id '${ssh_user}' >/dev/null 2>&1 || adduser -D -h '/home/${ssh_user}' -s /bin/sh '${ssh_user}' >/tmp/adduser-${ssh_user}.log 2>&1; update-ca-certificates >/tmp/update-ca-certificates.log 2>&1; tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity" \
    >/dev/null

  wait_for "tailscaled local socket ${client_name}" \
    "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
  echo "::endgroup::"
}

write_registration_id() {
  local client_name="$1"
  local output_path="$2"
  local status_json
  status_json="$(docker exec "${client_name}" tailscale status --json 2>/dev/null || true)"
  ruby -rjson -e '
    status = JSON.parse(STDIN.read)
    url = status["AuthURL"].to_s
    match = url.match(%r{/register/((?:hskey-authreq-)?[A-Za-z0-9_-]{24})(?:\z|[?#])})
    exit 1 unless match
    File.write(ARGV.fetch(0), match[1])
  ' "${output_path}" <<<"${status_json}"
}

tailscale_logged_in() {
  local client_name="$1"
  local status_json
  status_json="$(docker exec "${client_name}" tailscale status --json 2>/dev/null || true)"
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

drive_oidc_login() {
  local client_name="$1"
  echo "::group::tailscale OIDC login ${client_name}"
  docker exec "${client_name}" tailscale up \
    "--login-server=${control_url}" \
    "--hostname=${client_name}" \
    "--timeout=60s" \
    --accept-routes=false \
    --accept-dns=false \
    --ssh \
    >"${work_dir}/${client_name}.tailscale-up.stdout" \
    2>"${work_dir}/${client_name}.tailscale-up.stderr" &
  local up_pid="$!"

  local registration_id_path="${work_dir}/${client_name}.registration-id"
  if ! wait_for "OIDC registration URL ${client_name}" \
    "write_registration_id '${client_name}' '${registration_id_path}'"; then
    docker exec "${client_name}" tailscale status >&2 || true
    exit 1
  fi
  local registration_id
  registration_id="$(cat "${registration_id_path}")"
  curl -fsSL \
    -D "${work_dir}/${client_name}.oidc-callback.headers" \
    --cacert "${tls_cert_path}" \
    --resolve "host.docker.internal:${control_port}:127.0.0.1" \
    -c "${work_dir}/${client_name}.oidc.cookies" \
    -b "${work_dir}/${client_name}.oidc.cookies" \
    "${control_url}/register/${registration_id}" \
    >"${work_dir}/${client_name}.oidc-callback.html"
  local confirm_csrf
  confirm_csrf="$(html_input_value "${work_dir}/${client_name}.oidc-callback.html" headscale_register_confirm || true)"
  if [[ -z "${confirm_csrf}" ]]; then
    echo "OIDC confirmation page for ${client_name} did not contain CSRF token" >&2
    exit 1
  fi
  curl -fsSL \
    --cacert "${tls_cert_path}" \
    --resolve "host.docker.internal:${control_port}:127.0.0.1" \
    -c "${work_dir}/${client_name}.oidc.cookies" \
    -b "${work_dir}/${client_name}.oidc.cookies" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "headscale_register_confirm=${confirm_csrf}" \
    "${control_url}/register/confirm/${registration_id}" \
    >"${work_dir}/${client_name}.oidc-confirm.html"
  grep -Eq "Authenticated|Signed in successfully|Node registered" "${work_dir}/${client_name}.oidc-confirm.html"

  if ! wait_pid_with_timeout "tailscale up OIDC ${client_name}" "${up_pid}"; then
    echo "tailscale up returned non-zero for ${client_name}; verifying logged-in netmap" >&2
  fi
  wait_for "tailscale logged-in netmap ${client_name}" "tailscale_logged_in '${client_name}'"
  docker exec "${client_name}" tailscale status --json >"${work_dir}/${client_name}.tailscale-status.json"
  echo "::endgroup::"
}

wait_for_ssh_host_keys() {
  local source_name="$1"
  local target_name="$2"
  wait_for "SSH host keys ${source_name} to ${target_name}" \
    "docker exec '${source_name}' tailscale status --json | ruby -rjson -e 'status = JSON.parse(STDIN.read); peer = (status[\"Peer\"] || {}).each_value.find { |p| p[\"HostName\"] == ARGV.fetch(0) }; keys = Array(peer && (peer[\"SSH_HostKeys\"] || peer[\"SSHHostKeys\"] || peer[\"sshHostKeys\"])); exit(keys.empty? ? 1 : 0)' '${target_name}'"
}

peer_tailscale_ip() {
  local source_name="$1"
  local target_name="$2"
  docker exec "${source_name}" tailscale status --json 2>/dev/null | ruby -rjson -e '
    status = JSON.parse(STDIN.read)
    target = ARGV.fetch(0)
    peer = (status["Peer"] || {}).each_value.find { |p| p["HostName"] == target }
    exit 1 unless peer
    ips = Array(peer["TailscaleIPs"])
    ips << peer["TailscaleIP"] if ips.empty? && peer["TailscaleIP"]
    exit 1 if ips.empty?
    puts ips.first
  ' "${target_name}"
}

tailscale_ping_succeeded() {
  local source_name="$1"
  local target_name="$2"
  local output_path="$3"
  local target_ip
  target_ip="$(peer_tailscale_ip "${source_name}" "${target_name}")" || return 1
  docker exec "${source_name}" tailscale ping --timeout=5s --c=1 "${target_ip}" \
    >"${output_path}" \
    2>"${output_path}.err"
}

dump_client_debug() {
  local client_name="$1"
  local prefix="$2"
  docker exec "${client_name}" tailscale status --json >"${work_dir}/${prefix}.status.json" 2>"${work_dir}/${prefix}.status.err" || true
  docker exec "${client_name}" tailscale debug netmap >"${work_dir}/${prefix}.netmap.json" 2>"${work_dir}/${prefix}.netmap.err" || true
  docker exec "${client_name}" sh -ceu 'cat /tmp/tailscaled.log' >"${work_dir}/${prefix}.tailscaled.log" 2>"${work_dir}/${prefix}.tailscaled-log.err" || true
}

headscale_cmd() {
  case "${target}" in
    rust)
      env -u HEADSCALE_CLI_ADDRESS -u HEADSCALE_CLI_API_KEY -u HEADSCALE_CLI_INSECURE \
        target/debug/headscale --config "${config_path}" --unix-socket "${headscale_rs_socket_path}" "$@"
      ;;
    headscale-go) "${headscale_bin}" -c "${config_path}" "$@" ;;
  esac
}

stop_server() {
  if [[ -n "${server_pid}" ]]; then
    echo "::group::stop ${target} OIDC SSH server"
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
    server_pid=""
    echo "::endgroup::"
  fi
}

load_database_policy() {
  [[ "${database_backend}" == "postgres" ]] || return 0
  local label="$1"
  local policy_body="$2"
  write_policy_file "${policy_body}"
  echo "::group::load ${label}"
  headscale_cmd --force -o json policy set --file "${work_dir}/ssh-oidc-check.hujson" \
    >"${work_dir}/policy-set.json"
  echo "::endgroup::"
}

load_database_policy_if_requested() {
  load_database_policy "database policy" "${policy_json}"
}

restart_ssh_oidc_server_and_wait() {
  echo "::group::restart OIDC SSH server after policy mutation"
  stop_server
  if [[ "${target}" == "rust" ]]; then
    start_rust_server
  else
    start_headscale_go_server
  fi
  wait_for "tailscale logged-in netmap after policy restart ${client_one}" "tailscale_logged_in '${client_one}'"
  wait_for "tailscale logged-in netmap after policy restart ${client_two}" "tailscale_logged_in '${client_two}'"
  docker exec "${client_one}" tailscale status --json >"${work_dir}/${client_one}.after-policy-restart-status.json"
  docker exec "${client_two}" tailscale status --json >"${work_dir}/${client_two}.after-policy-restart-status.json"
  echo "::endgroup::"
}

mutate_database_policy_and_restart_if_requested() {
  ((policy_mutation_restart_flag)) || return 0

  load_database_policy "initial no-SSH database policy" "${policy_mutation_initial_json}"
  wait_for "pre-mutation Tailscale peer path ${client_one} to ${client_two}" \
    "tailscale_ping_succeeded '${client_one}' '${client_two}' '${work_dir}/pre-policy-mutation-ping.txt'"
  load_database_policy "mutated OIDC SSH database policy" "${policy_mutation_final_json}"
  restart_ssh_oidc_server_and_wait
}

extract_ssh_auth_id() {
  ruby -e '
    text = ARGV.map { |path| File.exist?(path) ? File.read(path) : "" }.join("\n")
    match = text.match(%r{/auth/(hskey-authreq-[A-Za-z0-9_-]{24})})
    exit 1 unless match
    puts match[1]
  ' "${work_dir}/ssh-check.stdout" "${work_dir}/ssh-check.stderr"
}

approve_ssh_check_with_oidc() {
  local auth_id="$1"
  curl -fsSL \
    --cacert "${tls_cert_path}" \
    --resolve "host.docker.internal:${control_port}:127.0.0.1" \
    -c "${work_dir}/ssh-check-oidc.cookies" \
    -b "${work_dir}/ssh-check-oidc.cookies" \
    "${control_url}/auth/${auth_id}" \
    >"${work_dir}/ssh-check-oidc.html"
  grep -Eq "SSH session authorized|Signed in successfully|Authenticated" "${work_dir}/ssh-check-oidc.html"
}

approve_ssh_check_with_cli() {
  local auth_id="$1"
  headscale_cmd -o json auth approve "--auth-id=${auth_id}" \
    >"${work_dir}/ssh-check-cli-approve.stdout" \
    2>"${work_dir}/ssh-check-cli-approve.stderr"
}

deny_ssh_check_with_wrong_user() {
  local auth_id="$1"
  local http_status
  http_status="$(
    curl -sSL \
      --cacert "${tls_cert_path}" \
      --resolve "host.docker.internal:${control_port}:127.0.0.1" \
      -c "${work_dir}/ssh-check-wrong-user-oidc.cookies" \
      -b "${work_dir}/ssh-check-wrong-user-oidc.cookies" \
      -D "${work_dir}/ssh-check-wrong-user-oidc.headers" \
      -o "${work_dir}/ssh-check-wrong-user-oidc.body" \
      -w "%{http_code}" \
      "${control_url}/auth/${auth_id}"
  )"
  printf '%s\n' "${http_status}" >"${work_dir}/ssh-check-wrong-user-oidc.status"
  if [[ "${http_status}" != "${wrong_user_auth_status}" ]]; then
    echo "expected wrong-user OIDC SSH auth status ${wrong_user_auth_status}, got ${http_status}" >&2
    cat "${work_dir}/ssh-check-wrong-user-oidc.body" >&2 || true
    exit 1
  fi
}

ssh_auth_url_present() {
  local prefix="$1"
  grep -Eq '/auth/hskey-authreq-[A-Za-z0-9_-]{24}' \
    "${work_dir}/${prefix}.stdout" \
    "${work_dir}/${prefix}.stderr"
}

run_cached_ssh_check() {
  local target_addr="$1"
  echo "::group::verify cached Tailscale SSH checkPeriod"
  if ! docker exec "${client_one}" sh -ceu \
    'timeout "$1" tailscale ssh "$2@$3" hostname' \
    sh "${attempt_timeout}" "${ssh_user}" "${target_addr}" \
    >"${work_dir}/ssh-check-cache.stdout" \
    2>"${work_dir}/ssh-check-cache.stderr"; then
    echo "cached SSH checkPeriod attempt failed" >&2
    cat "${work_dir}/ssh-check-cache.stdout" >&2 || true
    cat "${work_dir}/ssh-check-cache.stderr" >&2 || true
    exit 1
  fi
  grep -Fxq "${client_two}" "${work_dir}/ssh-check-cache.stdout"
  if ssh_auth_url_present "ssh-check-cache"; then
    echo "cached SSH checkPeriod attempt unexpectedly emitted a new auth URL" >&2
    cat "${work_dir}/ssh-check-cache.stdout" >&2 || true
    cat "${work_dir}/ssh-check-cache.stderr" >&2 || true
    exit 1
  fi
  echo "::endgroup::"
}

assert_denied_ssh_check() {
  local status="$1"
  printf '%s\n' "${status}" >"${work_dir}/ssh-check.status"
  if ((status == 0)); then
    echo "expected Tailscale SSH check to be denied" >&2
    cat "${work_dir}/ssh-check.stdout" >&2 || true
    cat "${work_dir}/ssh-check.stderr" >&2 || true
    exit 1
  fi
  if [[ -n "${ssh_deny_status}" && "${ssh_deny_status}" != "any" ]] &&
    ((status != ssh_deny_status)); then
    echo "expected denied Tailscale SSH check status ${ssh_deny_status}, got ${status}" >&2
    cat "${work_dir}/ssh-check.stderr" >&2 || true
    exit 1
  fi
  if [[ -s "${work_dir}/ssh-check.stdout" ]]; then
    echo "expected denied Tailscale SSH check stdout to be empty, got:" >&2
    cat "${work_dir}/ssh-check.stdout" >&2 || true
    exit 1
  fi
  if [[ -n "${ssh_deny_stderr_first_line}" ]]; then
    local first_line
    first_line="$(sed -n '1p' "${work_dir}/ssh-check.stderr")"
    if [[ "${first_line}" != "${ssh_deny_stderr_first_line}" ]]; then
      echo "expected denied Tailscale SSH check first stderr line '${ssh_deny_stderr_first_line}', got '${first_line}':" >&2
      cat "${work_dir}/ssh-check.stderr" >&2 || true
      exit 1
    fi
  fi
  if [[ -n "${ssh_deny_stderr_regex}" ]] && ! grep -Eq "${ssh_deny_stderr_regex}" "${work_dir}/ssh-check.stderr"; then
    echo "expected denied Tailscale SSH check stderr to match ${ssh_deny_stderr_regex}, got:" >&2
    cat "${work_dir}/ssh-check.stderr" >&2 || true
    exit 1
  fi
}

run_ssh_check() {
  if [[ "${check_result}" == "expire" ]]; then
    echo "::group::assert expired Tailscale SSH check denial"
  elif [[ "${check_result}" == "wrong-user" ]]; then
    echo "::group::assert wrong-user Tailscale SSH check denial"
  elif [[ "${check_result}" == "cancel" ]]; then
    echo "::group::assert cancelled Tailscale SSH check denial"
  elif [[ "${check_approval}" == "cli" ]]; then
    echo "::group::approve Tailscale SSH check with CLI"
  else
    echo "::group::approve Tailscale SSH check with OIDC"
  fi
  wait_for_ssh_host_keys "${client_one}" "${client_two}"
  docker exec "${client_one}" tailscale status --json >"${work_dir}/${client_one}.pre-ssh-status.json"
  docker exec "${client_one}" tailscale debug netmap >"${work_dir}/${client_one}.pre-ssh-netmap.json" 2>"${work_dir}/${client_one}.pre-ssh-netmap.err" || true
  wait_for "Tailscale peer path ${client_one} to ${client_two}" \
    "tailscale_ping_succeeded '${client_one}' '${client_two}' '${work_dir}/ssh-check-ping.txt'"
  local target_addr
  target_addr="$(peer_tailscale_ip "${client_one}" "${client_two}")"
  docker exec "${client_one}" sh -ceu \
    'timeout "$1" tailscale ssh "$2@$3" hostname' \
    sh "${attempt_timeout}" "${ssh_user}" "${target_addr}" \
    >"${work_dir}/ssh-check.stdout" \
    2>"${work_dir}/ssh-check.stderr" &
  ssh_pid="$!"

  if ! wait_for "SSH OIDC auth URL" "extract_ssh_auth_id >'${work_dir}/ssh-check.auth-id'"; then
    dump_client_debug "${client_one}" "${client_one}.ssh-timeout"
    dump_client_debug "${client_two}" "${client_two}.ssh-timeout"
    cat "${work_dir}/ssh-check.stdout" >&2 || true
    cat "${work_dir}/ssh-check.stderr" >&2 || true
    cat "${work_dir}/ssh-check-ping.txt" >&2 || true
    exit 1
  fi
  local auth_id
  auth_id="$(cat "${work_dir}/ssh-check.auth-id")"
  case "${check_result}" in
    expire)
      local ssh_status=0
      wait_pid_with_timeout "tailscale ssh check denial" "${ssh_pid}" || ssh_status="$?"
      ssh_pid=""
      assert_denied_ssh_check "${ssh_status}"
      echo "expired_auth_id=${auth_id}"
      echo "::endgroup::"
      return
      ;;
    wrong-user)
      deny_ssh_check_with_wrong_user "${auth_id}"
      local ssh_status=0
      wait_pid_with_timeout "tailscale ssh wrong-user denial" "${ssh_pid}" || ssh_status="$?"
      ssh_pid=""
      assert_denied_ssh_check "${ssh_status}"
      echo "wrong_user_auth_id=${auth_id}"
      echo "::endgroup::"
      return
      ;;
    cancel)
      local ssh_status=0
      wait_pid_with_timeout "tailscale ssh cancelled check" "${ssh_pid}" || ssh_status="$?"
      ssh_pid=""
      assert_denied_ssh_check "${ssh_status}"
      echo "cancelled_auth_id=${auth_id}"
      echo "::endgroup::"
      return
      ;;
  esac
  if [[ "${check_approval}" == "cli" ]]; then
    approve_ssh_check_with_cli "${auth_id}"
  else
    approve_ssh_check_with_oidc "${auth_id}"
  fi
  wait_pid_with_timeout "tailscale ssh check completion" "${ssh_pid}"
  ssh_pid=""
  grep -Fxq "${client_two}" "${work_dir}/ssh-check.stdout"
  echo "approved_auth_id=${auth_id}"
  echo "::endgroup::"
  if ((check_period_cache_flag)); then
    run_cached_ssh_check "${target_addr}"
  fi
}

need cargo
need curl
need docker
need ruby
if [[ -z "${HEADSCALE_GO_BIN:-}" ]]; then
  need go
fi
if [[ "${target}" == "headscale-go" ]]; then
  need openssl
fi
prepare_postgres_database

echo "::group::build headscale-go ${headscale_go_version} for mock OIDC"
install_headscale_go
"${headscale_bin}" version >"${work_dir}/headscale-go-version.txt"
cat "${work_dir}/headscale-go-version.txt"
echo "::endgroup::"

write_policy_file
start_mock_oidc
if [[ "${target}" == "rust" ]]; then
  start_rust_server
else
  start_headscale_go_server
fi
start_client "${client_one}"
start_client "${client_two}"
drive_oidc_login "${client_one}"
drive_oidc_login "${client_two}"
if ((policy_mutation_restart_flag)); then
  mutate_database_policy_and_restart_if_requested
else
  load_database_policy_if_requested
fi
run_ssh_check

if ((check_period_cache_flag)); then
  echo "${target} OIDC SSH checkPeriod cache real-client smoke passed"
elif [[ "${check_result}" == "expire" ]]; then
  echo "${target} expired OIDC SSH check denial real-client smoke passed"
elif [[ "${check_result}" == "wrong-user" ]]; then
  echo "${target} wrong-user OIDC SSH check denial real-client smoke passed"
elif [[ "${check_result}" == "cancel" ]]; then
  echo "${target} cancelled OIDC SSH check denial real-client smoke passed"
elif [[ "${check_approval}" == "cli" ]]; then
  echo "${target} CLI-approved SSH check real-client smoke passed"
else
  echo "${target} OIDC SSH check real-client smoke passed"
fi
