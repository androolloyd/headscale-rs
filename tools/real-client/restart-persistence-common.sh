#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

target="${REAL_CLIENT_RESTART_TARGET:-}"
case "${target}" in
  rust | headscale-go) ;;
  *)
    echo "REAL_CLIENT_RESTART_TARGET must be rust or headscale-go" >&2
    exit 2
    ;;
esac

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
headscale_go_version="${HEADSCALE_GO_VERSION:-v0.28.0}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-180}"
database_backend="${REAL_CLIENT_DATABASE_BACKEND:-sqlite}"
route="${REAL_CLIENT_RESTART_ROUTE:-10.88.0.0/24}"
route_b="${REAL_CLIENT_RESTART_ROUTE_B:-${REAL_CLIENT_ROUTE_B:-10.88.0.0/24}}"
exit_routes="${REAL_CLIENT_RESTART_EXIT_ROUTES:-${REAL_CLIENT_EXIT_ROUTES:-0.0.0.0/0,::/0}}"
initial_tag="${REAL_CLIENT_RESTART_INITIAL_TAG:-tag:server}"
mutated_tag="${REAL_CLIENT_RESTART_MUTATED_TAG:-tag:db}"
route_via_restart="${REAL_CLIENT_RESTART_ROUTE_VIA:-false}"
route_via_multiprefix_restart="${REAL_CLIENT_RESTART_ROUTE_VIA_MULTIPREFIX:-false}"
route_via_reload_restart="${REAL_CLIENT_RESTART_ROUTE_VIA_RELOAD:-false}"
route_health_restart="${REAL_CLIENT_RESTART_ROUTE_HEALTH:-false}"
route_health_reload_restart="${REAL_CLIENT_RESTART_ROUTE_HEALTH_RELOAD:-false}"
route_health_mixed_exit_restart="${REAL_CLIENT_RESTART_ROUTE_HEALTH_MIXED_EXIT:-false}"
route_health_all_unhealthy_restart="${REAL_CLIENT_RESTART_ROUTE_HEALTH_ALL_UNHEALTHY:-false}"
web_register_restart="${REAL_CLIENT_RESTART_WEB_REGISTER:-false}"
route_health_probe_interval_secs="${REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS:-2}"
route_health_probe_timeout_secs="${REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS:-1}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/restart-persistence-${target}}"
run_id="hs-restart-${target}-${database_backend}-$(date +%s)-$$"
case "${database_backend}" in
  sqlite | postgres) ;;
  *)
    echo "REAL_CLIENT_DATABASE_BACKEND must be sqlite or postgres" >&2
    exit 2
    ;;
esac
case "${route_via_restart}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    route_via_restart_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    route_via_restart_flag=0
    ;;
  *)
    echo "REAL_CLIENT_RESTART_ROUTE_VIA must be true or false, got ${route_via_restart}" >&2
    exit 2
    ;;
esac
case "${route_via_multiprefix_restart}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    route_via_multiprefix_restart_flag=1
    route_via_restart_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    route_via_multiprefix_restart_flag=0
    ;;
  *)
    echo "REAL_CLIENT_RESTART_ROUTE_VIA_MULTIPREFIX must be true or false, got ${route_via_multiprefix_restart}" >&2
    exit 2
    ;;
esac
case "${route_via_reload_restart}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    route_via_reload_restart_flag=1
    route_via_restart_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    route_via_reload_restart_flag=0
    ;;
  *)
    echo "REAL_CLIENT_RESTART_ROUTE_VIA_RELOAD must be true or false, got ${route_via_reload_restart}" >&2
    exit 2
    ;;
esac
case "${route_health_restart}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    route_health_restart_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    route_health_restart_flag=0
    ;;
  *)
    echo "REAL_CLIENT_RESTART_ROUTE_HEALTH must be true or false, got ${route_health_restart}" >&2
    exit 2
    ;;
esac
case "${route_health_reload_restart}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    route_health_reload_restart_flag=1
    route_health_restart_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    route_health_reload_restart_flag=0
    ;;
  *)
    echo "REAL_CLIENT_RESTART_ROUTE_HEALTH_RELOAD must be true or false, got ${route_health_reload_restart}" >&2
    exit 2
    ;;
esac
case "${route_health_mixed_exit_restart}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    route_health_mixed_exit_restart_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    route_health_mixed_exit_restart_flag=0
    ;;
  *)
    echo "REAL_CLIENT_RESTART_ROUTE_HEALTH_MIXED_EXIT must be true or false, got ${route_health_mixed_exit_restart}" >&2
    exit 2
    ;;
esac
case "${route_health_all_unhealthy_restart}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    route_health_all_unhealthy_restart_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    route_health_all_unhealthy_restart_flag=0
    ;;
  *)
    echo "REAL_CLIENT_RESTART_ROUTE_HEALTH_ALL_UNHEALTHY must be true or false, got ${route_health_all_unhealthy_restart}" >&2
    exit 2
    ;;
esac
case "${web_register_restart}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    web_register_restart_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    web_register_restart_flag=0
    ;;
  *)
    echo "REAL_CLIENT_RESTART_WEB_REGISTER must be true or false, got ${web_register_restart}" >&2
    exit 2
    ;;
esac
if ((web_register_restart_flag && (route_via_restart_flag || route_health_restart_flag))); then
  echo "REAL_CLIENT_RESTART_WEB_REGISTER cannot be combined with route-via or route-health restart modes" >&2
  exit 2
fi
if ((route_via_restart_flag && route_health_restart_flag)); then
  echo "REAL_CLIENT_RESTART_ROUTE_VIA and REAL_CLIENT_RESTART_ROUTE_HEALTH are mutually exclusive" >&2
  exit 2
fi
if ((route_health_mixed_exit_restart_flag && ! route_health_restart_flag)); then
  echo "REAL_CLIENT_RESTART_ROUTE_HEALTH_MIXED_EXIT requires REAL_CLIENT_RESTART_ROUTE_HEALTH=true" >&2
  exit 2
fi
if ((route_health_all_unhealthy_restart_flag && ! route_health_restart_flag)); then
  echo "REAL_CLIENT_RESTART_ROUTE_HEALTH_ALL_UNHEALTHY requires REAL_CLIENT_RESTART_ROUTE_HEALTH=true" >&2
  exit 2
fi
if ((route_health_reload_restart_flag && (route_health_mixed_exit_restart_flag || route_health_all_unhealthy_restart_flag))); then
  echo "REAL_CLIENT_RESTART_ROUTE_HEALTH_RELOAD cannot be combined with mixed-exit or all-unhealthy restart modes" >&2
  exit 2
fi
if ((route_health_restart_flag)); then
  if ! [[ "${route_health_probe_interval_secs}" =~ ^[0-9]+$ ]] || ((route_health_probe_interval_secs < 2)); then
    echo "REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS must be an integer >= 2, got ${route_health_probe_interval_secs}" >&2
    exit 2
  fi
  if ! [[ "${route_health_probe_timeout_secs}" =~ ^[0-9]+$ ]] || ((route_health_probe_timeout_secs < 1)); then
    echo "REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS must be a positive integer, got ${route_health_probe_timeout_secs}" >&2
    exit 2
  fi
  if ((route_health_probe_timeout_secs >= route_health_probe_interval_secs)); then
    echo "REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS must be less than REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS" >&2
    exit 2
  fi
fi
if ((route_via_multiprefix_restart_flag)); then
  advertised_routes="${route},${route_b}"
else
  advertised_routes="${route}"
fi
if ((route_via_restart_flag || route_health_restart_flag)); then
  router_name="${REAL_CLIENT_ROUTER_NAME:-${run_id}-router-a}"
else
  router_name="${REAL_CLIENT_ROUTER_NAME:-${run_id}-router}"
fi
if ((route_via_restart_flag)); then
  observer_name="${REAL_CLIENT_OBSERVER_NAME:-${run_id}-alice}"
else
  observer_name="${REAL_CLIENT_OBSERVER_NAME:-${run_id}-observer}"
fi
router_b_name="${REAL_CLIENT_ROUTER_B_NAME:-${run_id}-router-b}"
bob_name="${REAL_CLIENT_BOB_NAME:-${run_id}-bob}"
exit_name="${REAL_CLIENT_EXIT_NAME:-${run_id}-exit}"
base_domain="${REAL_CLIENT_BASE_DOMAIN-tail.test}"

case "${work_root}" in
  /*) work_dir="${work_root}/${run_id}" ;;
  *) work_dir="${repo_root}/${work_root}/${run_id}" ;;
esac
mkdir -p "${work_dir}"

http_port=""
https_port=""
metrics_port=""
grpc_port=""
server_pid=""
config_path="${work_dir}/config.yaml"
db_path="${work_dir}/db.sqlite"
socket_path="/tmp/${run_id}.sock"
control_url=""
local_control_url=""
tls_cert_path=""
tls_key_path=""
health_curl_opts="-fsS"
headscale_bin=""
authkey=""
router_a_authkey=""
router_b_authkey=""
postgres_admin_url=""
postgres_database_name=""
postgres_host=""
postgres_port=""
postgres_user=""
postgres_pass=""
postgres_sslmode=""
postgres_database_created=0

cleanup() {
  docker rm -f "${router_name}" "${router_b_name}" "${observer_name}" "${bob_name}" "${exit_name}" >/dev/null 2>&1 || true
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
  fi
  drop_postgres_database || true
  rm -f "${socket_path}"
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

yaml_string() {
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
    echo "skipping Postgres restart real-client smoke: HEADSCALE_DB_POSTGRES_TEST_URL is not set" >&2
    exit 0
  fi
  need psql
  postgres_database_name="headscale_rs_pg_restart_${target//[^a-zA-Z0-9]/_}_$(date +%s)_$$"
  parse_postgres_test_url
  if ! [[ "${postgres_database_name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "internal temporary Postgres database name is invalid: ${postgres_database_name}" >&2
    exit 2
  fi
  echo "::group::create temporary Postgres database"
  if ! psql "${postgres_admin_url}" -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${postgres_database_name}" >"${work_dir}/postgres-create.stdout" 2>"${work_dir}/postgres-create.stderr"; then
    echo "skipping Postgres restart real-client smoke: cannot create temporary database ${postgres_database_name}" >&2
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
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for ${label}" >&2
      return 1
    fi
    sleep 1
  done
}

wait_for_server() {
  local label="$1"
  local cmd="$2"
  local deadline=$((SECONDS + timeout_secs))
  until eval "${cmd}"; do
    if [[ -n "${server_pid}" ]] && ! kill -0 "${server_pid}" >/dev/null 2>&1; then
      echo "${target} server exited while waiting for ${label}" >&2
      sed -n '1,220p' "${work_dir}/${target}.stderr" >&2 || true
      return 1
    fi
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for ${label}" >&2
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

dump_debug() {
  headscale_cmd -o json nodes list 2>&1 || true
  for client_name in "${router_name}" "${router_b_name}" "${observer_name}" "${bob_name}" "${exit_name}"; do
    docker exec "${client_name}" tailscale status 2>&1 || true
    docker exec "${client_name}" sh -c 'tail -180 /tmp/tailscaled.log 2>/dev/null || true' >&2 || true
  done
}

install_or_build_headscale() {
  case "${target}" in
    rust)
      echo "::group::build headscale-rs CLI"
      if [[ "${database_backend}" == "postgres" ]]; then
        cargo build --quiet -p headscale-cli --features postgres-sqlx --bin headscale
      else
        cargo build --quiet -p headscale-cli --bin headscale
      fi
      headscale_bin="${repo_root}/target/debug/headscale"
      echo "::endgroup::"
      ;;
    headscale-go)
      headscale_bin="${HEADSCALE_GO_BIN:-${work_dir}/bin/headscale}"
      echo "::group::build headscale-go ${headscale_go_version}"
      if [[ -z "${HEADSCALE_GO_BIN:-}" ]]; then
        mkdir -p "${work_dir}/bin"
        GOBIN="${work_dir}/bin" go install "github.com/juanfont/headscale/cmd/headscale@${headscale_go_version}"
      fi
      "${headscale_bin}" version >"${work_dir}/headscale-go-version.txt"
      cat "${work_dir}/headscale-go-version.txt"
      echo "::endgroup::"
      ;;
  esac
}

generate_headscale_go_tls() {
  tls_cert_path="${work_dir}/tls.crt"
  tls_key_path="${work_dir}/tls.key"
  echo "::group::generate headscale-go TLS certificate"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
    -keyout "${tls_key_path}" \
    -out "${tls_cert_path}" \
    -subj "/CN=host.docker.internal" \
    -addext "subjectAltName=DNS:host.docker.internal,IP:127.0.0.1" \
    >"${work_dir}/openssl.stdout" \
    2>"${work_dir}/openssl.stderr"
  echo "::endgroup::"
}

write_derp_map() {
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
}

write_policy() {
  if ((route_via_restart_flag)); then
    if ((route_via_multiprefix_restart_flag)); then
      cat >"${work_dir}/policy.hujson" <<EOF
{
  "tagOwners": {
    "tag:router-a": ["router@"],
    "tag:router-b": ["router@"]
  },
  "autoApprovers": {
    "routes": {
      "${route}": ["tag:router-a", "tag:router-b"],
      "${route_b}": ["tag:router-a", "tag:router-b"]
    }
  },
  "grants": [
    {
      "src": ["*"],
      "dst": ["tag:router-a", "tag:router-b"],
      "ip": ["*"]
    },
    {
      "src": ["alice@"],
      "dst": ["${route}"],
      "ip": ["*"],
      "via": ["tag:router-a"]
    },
    {
      "src": ["alice@"],
      "dst": ["${route_b}"],
      "ip": ["*"],
      "via": ["tag:router-b"]
    },
    {
      "src": ["bob@"],
      "dst": ["${route}"],
      "ip": ["*"],
      "via": ["tag:router-b"]
    },
    {
      "src": ["bob@"],
      "dst": ["${route_b}"],
      "ip": ["*"],
      "via": ["tag:router-a"]
    }
  ]
}
EOF
      return
    fi
    cat >"${work_dir}/policy.hujson" <<EOF
{
  "tagOwners": {
    "tag:router-a": ["router@"],
    "tag:router-b": ["router@"]
  },
  "autoApprovers": {
    "routes": {
      "${route}": ["tag:router-a", "tag:router-b"]
    }
  },
  "grants": [
    {
      "src": ["*"],
      "dst": ["tag:router-a", "tag:router-b"],
      "ip": ["*"]
    },
    {
      "src": ["alice@"],
      "dst": ["${route}"],
      "ip": ["*"],
      "via": ["tag:router-a"]
    },
    {
      "src": ["bob@"],
      "dst": ["${route}"],
      "ip": ["*"],
      "via": ["tag:router-b"]
    }
  ]
}
EOF
    return
  fi
  if ((route_health_restart_flag)); then
    if ((route_health_reload_restart_flag)); then
      write_route_health_reload_policy tag:router-a
      return
    fi
    cat >"${work_dir}/policy.hujson" <<EOF
{
  "grants": [
    {
      "src": ["*"],
      "dst": ["*"],
      "ip": ["*"]
    },
    {
      "src": ["*"],
      "dst": ["${route}"],
      "ip": ["*"]
    }
  ]
}
EOF
    return
  fi
  cat >"${work_dir}/policy.hujson" <<EOF
{
  "tagOwners": {
    "${initial_tag}": ["alice@"],
    "${mutated_tag}": ["alice@"]
  },
  "acls": [
    {"action": "accept", "src": ["*"], "dst": ["*:*"]}
  ]
}
EOF
}

write_route_health_reload_policy() {
  local auto_tags=("$@")
  ruby -rjson -e '
    route = ARGV.fetch(0)
    auto_tags = ARGV.drop(1)
    puts JSON.pretty_generate({
      tagOwners: {
        "tag:router-a" => ["router@"],
        "tag:router-b" => ["router@"],
      },
      autoApprovers: {
        routes: {
          route => auto_tags,
        },
      },
      grants: [
        {
          src: ["*"],
          dst: ["*"],
          ip: ["*"],
        },
        {
          src: ["*"],
          dst: [route],
          ip: ["*"],
        },
      ],
    })
  ' "${route}" "${auto_tags[@]}" >"${work_dir}/policy.hujson"
}

write_route_via_reload_policy() {
  if ((route_via_multiprefix_restart_flag)); then
    cat >"${work_dir}/policy.hujson" <<EOF
{
  "tagOwners": {
    "tag:router-a": ["router@"],
    "tag:router-b": ["router@"]
  },
  "autoApprovers": {
    "routes": {
      "${route}": ["tag:router-a", "tag:router-b"],
      "${route_b}": ["tag:router-a", "tag:router-b"]
    }
  },
  "grants": [
    {
      "src": ["*"],
      "dst": ["tag:router-a", "tag:router-b"],
      "ip": ["*"]
    },
    {
      "src": ["alice@"],
      "dst": ["${route}"],
      "ip": ["*"],
      "via": ["tag:router-b"]
    },
    {
      "src": ["alice@"],
      "dst": ["${route_b}"],
      "ip": ["*"],
      "via": ["tag:router-a"]
    },
    {
      "src": ["bob@"],
      "dst": ["${route}"],
      "ip": ["*"],
      "via": ["tag:router-a"]
    },
    {
      "src": ["bob@"],
      "dst": ["${route_b}"],
      "ip": ["*"],
      "via": ["tag:router-b"]
    }
  ]
}
EOF
    return
  fi
  cat >"${work_dir}/policy.hujson" <<EOF
{
  "tagOwners": {
    "tag:router-a": ["router@"],
    "tag:router-b": ["router@"]
  },
  "autoApprovers": {
    "routes": {
      "${route}": ["tag:router-a", "tag:router-b"]
    }
  },
  "grants": [
    {
      "src": ["*"],
      "dst": ["tag:router-a", "tag:router-b"],
      "ip": ["*"]
    },
    {
      "src": ["alice@"],
      "dst": ["${route}"],
      "ip": ["*"],
      "via": ["tag:router-b"]
    },
    {
      "src": ["bob@"],
      "dst": ["${route}"],
      "ip": ["*"],
      "via": ["tag:router-b"]
    }
  ]
}
EOF
}

write_database_config() {
  case "${database_backend}" in
    sqlite)
      if [[ "${target}" == "headscale-go" ]]; then
        cat <<EOF

database:
  type: sqlite
  sqlite:
    path: ${db_path}
EOF
      fi
      ;;
    postgres)
      cat <<EOF

database:
  type: postgres
  postgres:
    host: $(yaml_string "${postgres_host}")
    port: ${postgres_port}
    name: $(yaml_string "${postgres_database_name}")
    user: $(yaml_string "${postgres_user}")
    pass: $(yaml_string "${postgres_pass}")
    ssl: $(yaml_string "${postgres_sslmode}")
EOF
      ;;
  esac
}

write_config() {
  case "${target}" in
    rust)
      tls_cert_path="${work_dir}/state/tls.crt"
      cat >"${config_path}" <<EOF
server:
  server_url: ${control_url}
  listen: 0.0.0.0:${http_port}
  https_listen: 0.0.0.0:${https_port}
  grpc_listen_addr: 127.0.0.1:${grpc_port}
  db_path: ${db_path}
  state_dir: ${work_dir}/state
  metrics_listen_addr: 127.0.0.1:${metrics_port}
  unix_socket: ${socket_path}
  unix_socket_permission: "0700"
  tls_hostname: host.docker.internal

noise:
  private_key_path: ${work_dir}/state/noise_private.key

prefixes:
  allocation: sequential
  v4: 100.64.0.0/10

dns:
  magic_dns: false
  base_domain: "${base_domain}"
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []

policy:
  mode: file
  path: ${work_dir}/policy.hujson
EOF
      ;;
    headscale-go)
      cat >"${config_path}" <<EOF
server_url: ${control_url}
listen_addr: 0.0.0.0:${http_port}
metrics_listen_addr: 127.0.0.1:${metrics_port}
grpc_listen_addr: 127.0.0.1:${grpc_port}
grpc_allow_insecure: true
unix_socket: ${socket_path}
unix_socket_permission: "0700"

private_key_path: ${work_dir}/private.key
noise:
  private_key_path: ${work_dir}/noise_private.key

prefixes:
  allocation: sequential
  v4: 100.64.0.0/10

dns:
  magic_dns: false
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

derp:
  server:
    enabled: false
  urls: []
  paths:
    - ${work_dir}/derp.yaml
  auto_update_enabled: false

tls_cert_path: ${tls_cert_path}
tls_key_path: ${tls_key_path}

policy:
  mode: file
  path: ${work_dir}/policy.hujson
EOF
      ;;
  esac
  write_database_config >>"${config_path}"
  if ((route_health_restart_flag)); then
    cat >>"${config_path}" <<EOF

node:
  routes:
    ha:
      probe_interval: ${route_health_probe_interval_secs}s
      probe_timeout: ${route_health_probe_timeout_secs}s
EOF
  fi
}

headscale_cmd() {
  case "${target}" in
    rust)
      env -u HEADSCALE_CLI_ADDRESS -u HEADSCALE_CLI_API_KEY -u HEADSCALE_CLI_INSECURE \
        "${headscale_bin}" --config "${config_path}" --unix-socket "${socket_path}" "$@"
      ;;
    headscale-go) "${headscale_bin}" -c "${config_path}" "$@" ;;
  esac
}

register_web_node() {
  local registration_id="$1"
  local user="$2"
  local output_path="$3"
  local error_path="$4"
  local auth_id="${registration_id}"
  case "${auth_id}" in
    hskey-authreq-*) ;;
    *) auth_id="hskey-authreq-${auth_id}" ;;
  esac

  case "${target}" in
    rust)
      headscale_cmd -o json auth register "--auth-id=${auth_id}" "--user=${user}" \
        >"${output_path}"
      ;;
    headscale-go)
      local register_status=0
      headscale_cmd -o json auth register "--auth-id=${auth_id}" "--user=${user}" \
        >"${output_path}" \
        2>"${error_path}" ||
        register_status="$?"
      if ((register_status == 0)); then
        return 0
      fi
      if ! grep -Eq 'unknown command|unknown flag|unknown shorthand' "${error_path}"; then
        cat "${error_path}" >&2 || true
        return "${register_status}"
      fi
      headscale_cmd -o json nodes register "--user=${user}" "--key=${registration_id}" \
        >"${output_path}"
      ;;
  esac
}

start_server() {
  write_config
  rm -f "${socket_path}"
  echo "::group::start ${target} server"
  case "${target}" in
    rust)
      mkdir -p "${work_dir}/state"
      "${headscale_bin}" --config "${config_path}" server \
        >"${work_dir}/${target}.stdout" \
        2>"${work_dir}/${target}.stderr" &
      ;;
    headscale-go)
      "${headscale_bin}" -c "${config_path}" serve \
        >"${work_dir}/${target}.stdout" \
        2>"${work_dir}/${target}.stderr" &
      ;;
  esac
  server_pid="$!"
  wait_for_server "${target} health" "curl ${health_curl_opts} '${local_control_url}/health' >/dev/null"
  if [[ "${target}" == "rust" ]]; then
    wait_for_server "${target} TLS certificate" "test -s '${tls_cert_path}'"
  fi
  wait_for_server "${target} gRPC" "headscale_cmd health >/dev/null 2>&1"
  echo "${target} control=${local_control_url}"
  echo "${target} login=${control_url}"
  echo "::endgroup::"
}

stop_server() {
  echo "::group::stop ${target} server"
  kill "${server_pid}" >/dev/null 2>&1 || true
  wait "${server_pid}" >/dev/null 2>&1 || true
  server_pid=""
  echo "::endgroup::"
}

create_user_and_key() {
  echo "::group::create user and preauth key"
  case "${target}" in
    rust)
      headscale_cmd -o json users create alice >"${work_dir}/user.json"
      local user_id
      user_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("id")' "${work_dir}/user.json")"
      headscale_cmd -o json preauthkeys create --user "${user_id}" --reusable --expires-in 1h >"${work_dir}/preauth.json"
      ;;
    headscale-go)
      headscale_cmd -o json users create alice >"${work_dir}/user.json"
      local user_id
      user_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("id")' "${work_dir}/user.json")"
      headscale_cmd -o json preauthkeys create --user "${user_id}" --reusable --expiration 1h >"${work_dir}/preauth.json"
      ;;
  esac
  authkey="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("key")' "${work_dir}/preauth.json")"
  echo "minted ${authkey%%-*}-..."
  echo "::endgroup::"
}

create_user_json() {
  local user="$1"
  local output_path="$2"
  headscale_cmd -o json users create "${user}" >"${output_path}"
  ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("id")' "${output_path}"
}

create_tagged_preauth_key() {
  local user_id="$1"
  local tag="$2"
  local output_path="$3"
  case "${target}" in
    rust)
      headscale_cmd -o json preauthkeys create \
        --user "${user_id}" \
        --reusable \
        --expires-in 1h \
        --tags "${tag}" \
        >"${output_path}"
      ;;
    headscale-go)
      headscale_cmd -o json preauthkeys create \
        --user "${user_id}" \
        --reusable \
        --expiration 1h \
        --tags "${tag}" \
        >"${output_path}"
      ;;
  esac
  ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("key")' "${output_path}"
}

create_route_via_users_and_keys() {
  echo "::group::create route-via users and preauth keys"
  local router_user_id alice_user_id bob_user_id
  router_user_id="$(create_user_json router "${work_dir}/user-router.json")"
  alice_user_id="$(create_user_json alice "${work_dir}/user-alice.json")"
  bob_user_id="$(create_user_json bob "${work_dir}/user-bob.json")"
  router_a_authkey="$(create_tagged_preauth_key "${router_user_id}" tag:router-a "${work_dir}/preauth-router-a.json")"
  router_b_authkey="$(create_tagged_preauth_key "${router_user_id}" tag:router-b "${work_dir}/preauth-router-b.json")"
  echo "created router user ${router_user_id}, alice user ${alice_user_id}, and bob user ${bob_user_id}"
  echo "minted tagged router keys"
  echo "::endgroup::"
}

create_route_health_reload_users_and_keys() {
  echo "::group::create route-health reload users and tagged preauth keys"
  local router_user_id alice_user_id
  router_user_id="$(create_user_json router "${work_dir}/user-router.json")"
  alice_user_id="$(create_user_json alice "${work_dir}/user-alice.json")"
  router_a_authkey="$(create_tagged_preauth_key "${router_user_id}" tag:router-a "${work_dir}/preauth-router-a.json")"
  router_b_authkey="$(create_tagged_preauth_key "${router_user_id}" tag:router-b "${work_dir}/preauth-router-b.json")"
  echo "created router user ${router_user_id} and alice user ${alice_user_id}"
  echo "minted route-health tagged router keys"
  echo "::endgroup::"
}

start_client() {
  local client_name="$1"
  echo "::group::start stock tailscale client ${client_name}"
  docker run -d \
    --name "${client_name}" \
    --hostname "${client_name}" \
    --add-host host.docker.internal:host-gateway \
    -v "${tls_cert_path}:/usr/local/share/ca-certificates/headscale-control.crt:ro" \
    --entrypoint /bin/sh \
    "${image}" \
    -ceu 'update-ca-certificates >/tmp/update-ca-certificates.log 2>&1; tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity' \
    >/dev/null

  wait_for "tailscaled local socket ${client_name}" \
    "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
  echo "::endgroup::"
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
      ips.any? { |ip| ip.to_s.include?(".") }
    exit(ok ? 0 : 1)
  ' <<<"${status_json}"
}

write_registration_id() {
  local client_name="$1"
  local output_path="$2"
  local status_json
  status_json="$(docker exec "${client_name}" tailscale status --json 2>/dev/null || true)"
  ruby -rjson -e '
    status = JSON.parse(STDIN.read)
    url = status["AuthURL"].to_s
    match = url.match(%r{/register/(?:hskey-authreq-)?([A-Za-z0-9_-]{24})(?:\z|[?#])})
    exit 1 unless match
    File.write(ARGV.fetch(0), match[1])
  ' "${output_path}" <<<"${status_json}"
}

login_router_with_authkey() {
  local client_name="${1:-${router_name}}"
  local key="${2:-${authkey}}"
  echo "::group::tailscale up auth-key router ${client_name}"
  up_status=0
  docker exec "${client_name}" tailscale up \
    "--login-server=${control_url}" \
    "--hostname=${client_name}" \
    --timeout=60s \
    --accept-routes=false \
    --accept-dns=false \
    "--advertise-routes=${advertised_routes}" \
    "--authkey=${key}" \
    >"${work_dir}/${client_name}.tailscale-up.stdout" \
    2>"${work_dir}/${client_name}.tailscale-up.stderr" ||
    up_status="$?"
  if ((up_status != 0)); then
    echo "tailscale up ${client_name} returned ${up_status}; verifying logged-in netmap"
  fi
  wait_for "logged-in router netmap ${client_name}" "tailscale_logged_in '${client_name}'" || {
    dump_debug
    return 1
  }
  echo "::endgroup::"
}

login_exit_with_authkey() {
  local client_name="${1:-${exit_name}}"
  local key="${2:-${authkey}}"
  echo "::group::tailscale up auth-key exit node ${client_name}"
  up_status=0
  docker exec "${client_name}" tailscale up \
    "--login-server=${control_url}" \
    "--hostname=${client_name}" \
    --timeout=60s \
    --accept-routes=false \
    --accept-dns=false \
    --advertise-exit-node \
    "--authkey=${key}" \
    >"${work_dir}/${client_name}.tailscale-up.stdout" \
    2>"${work_dir}/${client_name}.tailscale-up.stderr" ||
    up_status="$?"
  if ((up_status != 0)); then
    echo "tailscale up ${client_name} returned ${up_status}; verifying logged-in netmap"
  fi
  wait_for "logged-in exit-node netmap ${client_name}" "tailscale_logged_in '${client_name}'" || {
    dump_debug
    return 1
  }
  echo "::endgroup::"
}

login_observer_with_web_registration() {
  local client_name="${1:-${observer_name}}"
  local user="${2:-alice}"
  echo "::group::tailscale up web observer ${client_name}"
  docker exec "${client_name}" tailscale up \
    "--login-server=${control_url}" \
    "--hostname=${client_name}" \
    --timeout=60s \
    --accept-routes=true \
    --accept-dns=false \
    >"${work_dir}/${client_name}.tailscale-up.stdout" \
    2>"${work_dir}/${client_name}.tailscale-up.stderr" &
  local up_pid="$!"

  local registration_id_path="${work_dir}/${client_name}.registration-id"
  if ! wait_for "web registration URL ${client_name}" \
    "write_registration_id '${client_name}' '${registration_id_path}'"; then
    dump_debug
    return 1
  fi
  local registration_id
  registration_id="$(cat "${registration_id_path}")"
  register_web_node \
    "${registration_id}" \
    "${user}" \
    "${work_dir}/${client_name}.registered.json" \
    "${work_dir}/${client_name}.registered.err"

  if ! wait_pid_with_timeout "tailscale up ${client_name}" "${up_pid}"; then
    echo "tailscale up ${client_name} returned non-zero; verifying logged-in netmap"
  fi
  wait_for "logged-in observer netmap ${client_name}" "tailscale_logged_in '${client_name}'" || {
    dump_debug
    return 1
  }
  echo "::endgroup::"
}

node_id_for_host() {
  local nodes_path="$1"
  local hostname="$2"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    hostname = ARGV.fetch(1)
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    node = nodes.find do |candidate|
      names = [
        candidate["givenName"],
        candidate["given_name"],
        candidate["name"],
        candidate["hostname"],
      ].compact.map(&:to_s)
      names.include?(hostname)
    end
    abort("missing node #{hostname.inspect} in #{nodes.inspect}") unless node
    puts node.fetch("id")
  ' "${nodes_path}" "${hostname}"
}

load_node_id() {
  local hostname="$1"
  local safe_hostname="${hostname//[^a-zA-Z0-9_.-]/-}"
  local nodes_path="${work_dir}/nodes-for-${safe_hostname}-id.json"
  headscale_cmd -o json nodes list >"${nodes_path}"
  node_id_for_host "${nodes_path}" "${hostname}"
}

load_router_id() {
  load_node_id "${router_name}"
}

approve_router_routes() {
  local hostname="$1"
  local router_id
  router_id="$(load_node_id "${hostname}")"
  echo "::group::approve router routes ${hostname}"
  headscale_cmd -o json nodes approve-routes --identifier "${router_id}" --routes "${advertised_routes}" \
    >"${work_dir}/approved-routes-${router_id}.json"
  echo "::endgroup::"
}

approve_exit_routes() {
  local hostname="$1"
  local router_id
  router_id="$(load_node_id "${hostname}")"
  echo "::group::approve exit routes ${hostname}"
  headscale_cmd -o json nodes approve-routes --identifier "${router_id}" --routes "${exit_routes}" \
    >"${work_dir}/approved-exit-routes-${router_id}.json"
  echo "::endgroup::"
}

set_router_routes_and_tag() {
  local tag="$1"
  local router_id
  router_id="$(load_router_id)"
  echo "::group::set router routes and tag ${tag}"
  headscale_cmd -o json nodes approve-routes --identifier "${router_id}" --routes "${route}" \
    >"${work_dir}/approved-routes-${router_id}.json"
  headscale_cmd -o json nodes tag --identifier "${router_id}" --tags "${tag}" \
    >"${work_dir}/set-tags-${router_id}-${tag#tag:}.json"
  echo "::endgroup::"
}

assert_persisted_nodes() {
  local expected_tag="$1"
  local label="$2"
  local nodes_path="${work_dir}/nodes-${label}.json"
  headscale_cmd -o json nodes list >"${nodes_path}"
  ruby -rjson -e '
    route = ARGV.fetch(1)
    expected_tag = ARGV.fetch(2)
    router_name = ARGV.fetch(3)
    observer_name = ARGV.fetch(4)
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")

    def node_name(node)
      node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
    end

    router = nodes.find { |node| node_name(node).to_s == router_name }
    observer = nodes.find { |node| node_name(node).to_s == observer_name }
    abort("missing router #{router_name.inspect} in #{nodes.inspect}") unless router
    abort("missing observer #{observer_name.inspect} in #{nodes.inspect}") unless observer

    available = Array(router["availableRoutes"] || router["available_routes"]).map(&:to_s).sort
    approved = Array(router["approvedRoutes"] || router["approved_routes"]).map(&:to_s).sort
    tags = Array(router["tags"] || router["Tags"]).map(&:to_s).sort
    abort("expected router available route #{route.inspect}, got #{available.inspect}") unless available.include?(route)
    abort("expected router approved route #{route.inspect}, got #{approved.inspect}") unless approved.include?(route)
    abort("expected router tag #{expected_tag.inspect}, got #{tags.inspect}") unless tags.include?(expected_tag)

    puts JSON.pretty_generate({
      router: router,
      observer: observer,
      route: route,
      tag: expected_tag,
    })
  ' "${nodes_path}" "${route}" "${expected_tag}" "${router_name}" "${observer_name}"
}

assert_route_via_persisted_nodes() {
  local label="$1"
  local nodes_path="${work_dir}/nodes-${label}.json"
  headscale_cmd -o json nodes list >"${nodes_path}"
  ruby -rjson -e '
    routes = ARGV.fetch(1).split(",").map(&:to_s)
    router_a_name = ARGV.fetch(2)
    router_b_name = ARGV.fetch(3)
    alice_name = ARGV.fetch(4)
    bob_name = ARGV.fetch(5)
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")

    def node_name(node)
      node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
    end

    def find_node(nodes, name)
      nodes.find { |node| node_name(node).to_s == name } ||
        abort("missing node #{name.inspect} in #{nodes.inspect}")
    end

    def assert_router(node, routes, tag)
      available = Array(node["availableRoutes"] || node["available_routes"]).map(&:to_s).sort
      approved = Array(node["approvedRoutes"] || node["approved_routes"]).map(&:to_s).sort
      tags = Array(node["tags"] || node["Tags"]).map(&:to_s).sort
      routes.each do |route|
        abort("expected router available route #{route.inspect}, got #{available.inspect}") unless available.include?(route)
        abort("expected router approved route #{route.inspect}, got #{approved.inspect}") unless approved.include?(route)
      end
      abort("expected router tag #{tag.inspect}, got #{tags.inspect}") unless tags.include?(tag)
    end

    router_a = find_node(nodes, router_a_name)
    router_b = find_node(nodes, router_b_name)
    alice = find_node(nodes, alice_name)
    bob = find_node(nodes, bob_name)
    assert_router(router_a, routes, "tag:router-a")
    assert_router(router_b, routes, "tag:router-b")

    puts JSON.pretty_generate({
      router_a: router_a,
      router_b: router_b,
      alice: alice,
      bob: bob,
      routes: routes,
    })
  ' "${nodes_path}" "${advertised_routes}" "${router_name}" "${router_b_name}" "${observer_name}" "${bob_name}"
}

assert_web_registered_node() {
  local label="$1"
  local nodes_path="${work_dir}/nodes-${label}.json"
  local summary_path="${work_dir}/web-registered-node-${label}.json"
  headscale_cmd -o json nodes list >"${nodes_path}"
  ruby -rjson -e '
    expected_name = ARGV.fetch(1)
    expected_user = ARGV.fetch(2)
    summary_path = ARGV.fetch(3)
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    abort("expected 1 web-registered node, got #{nodes.length}: #{nodes.inspect}") unless nodes.length == 1
    node = nodes.fetch(0)

    def node_name(node)
      node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
    end

    user = node["user"] || node["User"]
    user_name = user.is_a?(Hash) ? (user["name"] || user["loginName"] || user["login_name"]) : user.to_s
    register_method = node["registerMethod"] || node["register_method"]
    addresses = Array(node["ipAddresses"] || node["ip_addresses"] || node["addresses"])
    machine_key = node["machineKey"] || node["machine_key"]
    node_key = node["nodeKey"] || node["node_key"]
    node_id = node["id"] || node["ID"] || node["nodeId"] || node["node_id"]

    abort("expected node #{expected_name.inspect}, got #{node_name(node).inspect}") unless node_name(node).to_s == expected_name
    abort("expected user #{expected_user.inspect}, got #{user.inspect}") unless user_name == expected_user
    abort("expected at least one IPv4 address, got #{addresses.inspect}") unless addresses.any? { |ip| ip.to_s.include?(".") }
    abort("expected non-empty machine key") if machine_key.to_s.empty?
    abort("expected non-empty node key") if node_key.to_s.empty?
    abort("expected non-empty node ID") if node_id.to_s.empty?

    File.write(summary_path, JSON.pretty_generate({
      node_id: node_id,
      node_name: node_name(node),
      user: user,
      register_method: register_method,
      ip_addresses: addresses,
    }))
    puts node_id
  ' "${nodes_path}" "${observer_name}" "alice" "${summary_path}"
}

assert_route_health_persisted_nodes() {
  local label="$1"
  local nodes_path="${work_dir}/nodes-${label}.json"
  headscale_cmd -o json nodes list >"${nodes_path}"
  ruby -rjson -e '
    route = ARGV.fetch(1)
    router_a_name = ARGV.fetch(2)
    router_b_name = ARGV.fetch(3)
    mixed_exit = ARGV.fetch(4) == "1"
    exit_name = ARGV.fetch(5)
    exit_routes = ARGV.fetch(6).split(",").map(&:to_s)
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")

    def node_name(node)
      node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
    end

    def find_node(nodes, name)
      nodes.find { |node| node_name(node).to_s == name } ||
        abort("missing node #{name.inspect} in #{nodes.inspect}")
    end

    def assert_router(node, route)
      available = Array(node["availableRoutes"] || node["available_routes"]).map(&:to_s).sort
      approved = Array(node["approvedRoutes"] || node["approved_routes"]).map(&:to_s).sort
      abort("expected router available route #{route.inspect}, got #{available.inspect}") unless available.include?(route)
      abort("expected router approved route #{route.inspect}, got #{approved.inspect}") unless approved.include?(route)
      online = node.key?("online") ? node["online"] : node["Online"]
      abort("expected router #{node_name(node).inspect} to be online, got #{online.inspect}") unless online == true
    end

    def assert_exit_node(node, exit_routes, subnet_route)
      available = Array(node["availableRoutes"] || node["available_routes"]).map(&:to_s).sort
      approved = Array(node["approvedRoutes"] || node["approved_routes"]).map(&:to_s).sort
      exit_routes.each do |exit_route|
        abort("expected exit node available route #{exit_route.inspect}, got #{available.inspect}") unless available.include?(exit_route)
        abort("expected exit node approved route #{exit_route.inspect}, got #{approved.inspect}") unless approved.include?(exit_route)
      end
      abort("exit node unexpectedly advertises subnet route #{subnet_route.inspect}") if available.include?(subnet_route)
      online = node.key?("online") ? node["online"] : node["Online"]
      abort("expected exit node #{node_name(node).inspect} to be online, got #{online.inspect}") unless online == true
    end

    def primary_routes(node)
      Array(
        node["subnetRoutes"] ||
        node["subnet_routes"] ||
        node["primaryRoutes"] ||
        node["primary_routes"]
      ).map(&:to_s)
    end

    router_a = find_node(nodes, router_a_name)
    router_b = find_node(nodes, router_b_name)
    assert_router(router_a, route)
    assert_router(router_b, route)
    exit_node = nil
    if mixed_exit
      exit_node = find_node(nodes, exit_name)
      assert_exit_node(exit_node, exit_routes, route)
    end

    primary_nodes = nodes.select { |node| primary_routes(node).include?(route) }
    abort("expected exactly one primary route owner for #{route}, got #{primary_nodes.length} in #{nodes.inspect}") unless primary_nodes.length == 1
    primary_name = node_name(primary_nodes.fetch(0)).to_s
    unless [router_a_name, router_b_name].include?(primary_name)
      abort("expected primary route owner for #{route} to be one of #{[router_a_name, router_b_name].inspect}, got #{primary_name.inspect}")
    end

    puts JSON.pretty_generate({
      route: route,
      primary: primary_nodes.fetch(0),
      router_a: router_a,
      router_b: router_b,
      exit_node: exit_node,
    })
  ' "${nodes_path}" "${route}" "${router_name}" "${router_b_name}" "${route_health_mixed_exit_restart_flag}" "${exit_name}" "${exit_routes}"
}

wait_for_route_health_primary() {
  local label="$1"
  local safe_label="${label//[^a-zA-Z0-9_-]/-}"
  wait_for "${label} route-health primary" \
    "assert_route_health_persisted_nodes '${safe_label}' > '${work_dir}/route-health-primary-${safe_label}.json'" || {
      dump_debug
      return 1
    }
  cat "${work_dir}/route-health-primary-${safe_label}.json"
}

assert_route_health_approved_candidates() {
  local label="$1"
  local expected_csv="$2"
  local nodes_path="${work_dir}/nodes-${label}.json"
  headscale_cmd -o json nodes list >"${nodes_path}"
  ruby -rjson -e '
    route = ARGV.fetch(1)
    router_a_name = ARGV.fetch(2)
    router_b_name = ARGV.fetch(3)
    expected = ARGV.fetch(4).split(",").reject(&:empty?).sort
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")

    def node_name(node)
      node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
    end

    def find_node(nodes, name)
      nodes.find { |node| node_name(node).to_s == name } ||
        abort("missing node #{name.inspect} in #{nodes.inspect}")
    end

    def routes(node, camel, snake)
      Array(node[camel] || node[snake]).map(&:to_s).sort
    end

    def primary_routes(node)
      Array(
        node["subnetRoutes"] ||
        node["subnet_routes"] ||
        node["primaryRoutes"] ||
        node["primary_routes"]
      ).map(&:to_s)
    end

    routers = [find_node(nodes, router_a_name), find_node(nodes, router_b_name)]
    routers.each do |router|
      available = routes(router, "availableRoutes", "available_routes")
      abort("expected #{node_name(router).inspect} to advertise #{route.inspect}, got #{available.inspect}") unless available.include?(route)
    end

    approved = routers.select do |router|
      routes(router, "approvedRoutes", "approved_routes").include?(route)
    end.map { |router| node_name(router).to_s }.sort
    abort("expected approved route-health candidates #{expected.inspect}, got #{approved.inspect}") unless approved == expected

    primary = nodes.select { |node| primary_routes(node).include?(route) }
    abort("expected exactly one primary owner for #{route.inspect}, got #{primary.length}") unless primary.length == 1
    primary_name = node_name(primary.fetch(0)).to_s
    abort("expected primary #{primary_name.inspect} to be one of approved candidates #{expected.inspect}") unless expected.include?(primary_name)

    puts JSON.pretty_generate({
      route: route,
      approved_candidates: approved,
      primary: primary_name,
    })
  ' "${nodes_path}" "${route}" "${router_name}" "${router_b_name}" "${expected_csv}"
}

wait_for_route_health_approved_candidates() {
  local label="$1"
  local expected_csv="$2"
  local safe_label="${label//[^a-zA-Z0-9_-]/-}"
  wait_for "${label} route-health approved candidates ${expected_csv}" \
    "assert_route_health_approved_candidates '${safe_label}' '${expected_csv}' > '${work_dir}/route-health-candidates-${safe_label}.json'" || {
      cat "${work_dir}/route-health-candidates-${safe_label}.json" >&2 || true
      dump_debug
      return 1
    }
  cat "${work_dir}/route-health-candidates-${safe_label}.json"
}

reload_route_health_policy() {
  echo "::group::reload route-health policy"
  write_route_health_reload_policy tag:router-a tag:router-b
  kill -HUP "${server_pid}"
  wait_for_server "${target} health after policy reload" "curl ${health_curl_opts} '${local_control_url}/health' >/dev/null"
  wait_for_route_health_approved_candidates "after-policy-reload" "${router_name},${router_b_name}"
  echo "::endgroup::"
}

route_health_primary_name_from_nodes() {
  local snapshot_path="$1"
  headscale_cmd -o json nodes list >"${snapshot_path}"
  ruby -rjson -e '
    route = ARGV.fetch(1)
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")

    def node_name(node)
      node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
    end

    def primary_routes(node)
      Array(
        node["subnetRoutes"] ||
        node["subnet_routes"] ||
        node["primaryRoutes"] ||
        node["primary_routes"]
      ).map(&:to_s)
    end

    primary_nodes = nodes.select { |node| primary_routes(node).include?(route) }
    abort("expected exactly one current primary route owner for #{route}, got #{primary_nodes.length}") unless primary_nodes.length == 1
    puts node_name(primary_nodes.fetch(0))
  ' "${snapshot_path}" "${route}"
}

wait_for_route_health_peer_owner_from_admin() {
  local label="$1"
  local safe_label="${label//[^a-zA-Z0-9_-]/-}"
  local snapshot_path="${work_dir}/route-health-primary-${safe_label}-peer-gate.json"
  local output_path="${work_dir}/route-health-peer-${safe_label}.json"
  local primary_name
  primary_name="$(route_health_primary_name_from_nodes "${snapshot_path}")"
  wait_for "${label} observer sees route-health owner" \
    "peer_netmap_route_owner_matches '${observer_name}' '${primary_name}' '${route}' '${output_path}'" || {
      cat "${output_path}.err" >&2 || true
      dump_debug
      return 1
    }
  cat "${output_path}"
}

route_health_peer_owner_from_netmap() {
  local source_name="$1"
  local expected_route="$2"
  local output_path="$3"
  local owner_path="$4"
  local netmap_path="${output_path}.netmap"
  docker exec "${source_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      netmap = JSON.parse(File.read(ARGV.fetch(0)))
      expected_route = ARGV.fetch(1)
      router_a_name = ARGV.fetch(2)
      router_b_name = ARGV.fetch(3)
      owner_path = ARGV.fetch(4)
      peers = Array(netmap["Peers"] || netmap["peers"])

      def names_for(peer)
        [
          peer["HostName"],
          peer["Name"],
          peer["DNSName"],
          peer["ComputedName"],
          peer["Hostinfo"] && peer["Hostinfo"]["Hostname"],
          peer["HostInfo"] && peer["HostInfo"]["Hostname"],
        ].compact.map(&:to_s)
      end

      def route_fields(peer)
        [
          peer["AllowedIPs"],
          peer["AllowedIps"],
          peer["allowedIPs"],
          peer["allowed_ips"],
          peer["PrimaryRoutes"],
          peer["primaryRoutes"],
          peer["primary_routes"],
          peer["SubnetRoutes"],
          peer["subnetRoutes"],
          peer["subnet_routes"],
        ].compact.flatten.map(&:to_s)
      end

      def peer_matches_name?(peer, expected)
        names_for(peer).any? do |name|
          name == expected || name.split(".").first == expected || name.include?(expected)
        end
      end

      candidate_peers = [router_a_name, router_b_name].map do |name|
        peer = peers.find { |candidate| peer_matches_name?(candidate, name) }
        peer && [name, peer]
      end.compact
      abort("expected both route-health routers in netmap, got #{candidate_peers.map(&:first).inspect} from #{peers.inspect}") unless candidate_peers.length == 2

      owners = candidate_peers.select { |(_name, peer)| route_fields(peer).include?(expected_route) }
      abort("expected one route-health router to own #{expected_route.inspect}, got #{owners.length} in #{candidate_peers.map { |name, peer| {name: name, names: names_for(peer), routes: route_fields(peer)} }.inspect}") unless owners.length == 1

      owner_name, owner_peer = owners.fetch(0)
      unexpected_owners = peers.reject { |peer| peer.equal?(owner_peer) }.select do |peer|
        route_fields(peer).include?(expected_route)
      end
      unless unexpected_owners.empty?
        details = unexpected_owners.map { |peer| {names: names_for(peer), routes: route_fields(peer)} }
        abort("expected only #{owner_name.inspect} to own #{expected_route.inspect}, but found #{details.inspect}")
      end

      File.write(owner_path, "#{owner_name}\n")
      puts JSON.pretty_generate({
        source: netmap.dig("SelfNode", "HostName") || netmap.dig("SelfNode", "Name"),
        owner: owner_name,
        route: expected_route,
        owner_names: names_for(owner_peer),
        owner_routes: route_fields(owner_peer),
      })
    ' "${netmap_path}" "${expected_route}" "${router_name}" "${router_b_name}" "${owner_path}" >"${output_path}"
}

assert_route_health_peer_failover_after_restart() {
  local before_path="${work_dir}/route-health-peer-before-failover.json"
  local after_path="${work_dir}/route-health-peer-after-failover.json"
  local recovery_path="${work_dir}/route-health-peer-after-recovery.json"
  local primary_snapshot_path="${work_dir}/route-health-primary-before-peer-failover.json"
  local owner_path="${work_dir}/route-health-peer-before-failover.owner"
  local route_health_primary_name route_health_standby_name

  echo "::group::assert route-health peer failover after restart"
  headscale_cmd -o json nodes list >"${primary_snapshot_path}"
  wait_for "observer sees initial route-health owner" \
    "route_health_peer_owner_from_netmap '${observer_name}' '${route}' '${before_path}' '${owner_path}'" || {
      cat "${before_path}.err" >&2 || true
      dump_debug
      return 1
    }
  cat "${before_path}"
  route_health_primary_name="$(cat "${owner_path}")"
  case "${route_health_primary_name}" in
    "${router_name}") route_health_standby_name="${router_b_name}" ;;
    "${router_b_name}") route_health_standby_name="${router_name}" ;;
    *)
      echo "route-health primary ${route_health_primary_name} is not ${router_name} or ${router_b_name}" >&2
      dump_debug
      return 1
      ;;
  esac

  docker pause "${route_health_primary_name}" >/dev/null
  if ! wait_for "observer sees route-health failover owner" \
    "peer_netmap_route_owner_matches '${observer_name}' '${route_health_standby_name}' '${route}' '${after_path}'"; then
    docker unpause "${route_health_primary_name}" >/dev/null 2>&1 || true
    cat "${after_path}.err" >&2 || true
    dump_debug
    return 1
  fi
  cat "${after_path}"

  docker unpause "${route_health_primary_name}" >/dev/null
  if ! wait_for "tailscale logged-in netmap after route-health recovery ${route_health_primary_name}" "tailscale_logged_in '${route_health_primary_name}'"; then
    dump_debug
    return 1
  fi
  sleep $((route_health_probe_interval_secs + route_health_probe_timeout_secs + 2))
  wait_for "observer keeps sticky route-health owner after recovery" \
    "peer_netmap_route_owner_matches '${observer_name}' '${route_health_standby_name}' '${route}' '${recovery_path}'" || {
      cat "${recovery_path}.err" >&2 || true
      dump_debug
      return 1
    }
  cat "${recovery_path}"
  echo "::endgroup::"
}

assert_route_health_failover_after_restart() {
  local before_path="${work_dir}/nodes-before-route-health-failover.json"
  local after_path="${work_dir}/nodes-after-route-health-failover.json"
  local recovery_path="${work_dir}/nodes-after-route-health-recovery.json"
  local route_health_client_name

  echo "::group::assert route-health primary failover after restart"
  headscale_cmd -o json nodes list >"${before_path}"
  route_health_client_name="$(
    ruby -rjson -e '
      route = ARGV.fetch(1)
      payload = JSON.parse(File.read(ARGV.fetch(0)))
      nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")

      def node_name(node)
        node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
      end

      def primary_routes(node)
        Array(
          node["subnetRoutes"] ||
          node["subnet_routes"] ||
          node["primaryRoutes"] ||
          node["primary_routes"]
        ).map(&:to_s)
      end

      primary_nodes = nodes.select { |node| primary_routes(node).include?(route) }
      abort("expected exactly one primary node before route-health, got #{primary_nodes.length}") unless primary_nodes.length == 1
      puts node_name(primary_nodes.fetch(0))
    ' "${before_path}" "${route}"
  )"

  docker pause "${route_health_client_name}" >/dev/null
  deadline=$((SECONDS + timeout_secs))
  until
    headscale_cmd -o json nodes list >"${after_path}" &&
      ruby -rjson -e '
        route = ARGV.fetch(2)
        paused_client = ARGV.fetch(3)
        router_a_name = ARGV.fetch(4)
        router_b_name = ARGV.fetch(5)

        def node_name(node)
          node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
        end

        def primary_routes(node)
          Array(
            node["subnetRoutes"] ||
            node["subnet_routes"] ||
            node["primaryRoutes"] ||
            node["primary_routes"]
          ).map(&:to_s)
        end

        before_payload = JSON.parse(File.read(ARGV.fetch(0)))
        before_nodes = before_payload.is_a?(Array) ? before_payload : before_payload.fetch("nodes")
        after_payload = JSON.parse(File.read(ARGV.fetch(1)))
        after_nodes = after_payload.is_a?(Array) ? after_payload : after_payload.fetch("nodes")

        before_primary = before_nodes.select { |node| primary_routes(node).include?(route) }
        after_primary = after_nodes.select { |node| primary_routes(node).include?(route) }
        abort("expected exactly one primary node before route-health, got #{before_primary.length}") unless before_primary.length == 1
        abort("expected exactly one primary node after route-health, got #{after_primary.length}") unless after_primary.length == 1

        before_owner = before_primary.fetch(0)
        after_owner = after_primary.fetch(0)
        before_id = Integer(before_owner.fetch("id"))
        after_id = Integer(after_owner.fetch("id"))
        abort("expected route-health primary owner to change, still #{after_id}") if after_id == before_id

        remaining_ids = after_nodes
          .select { |node| [router_a_name, router_b_name].include?(node_name(node).to_s) }
          .reject { |node| node_name(node).to_s == paused_client }
          .select do |node|
            Array(node["availableRoutes"] || node["available_routes"]).include?(route) &&
              Array(node["approvedRoutes"] || node["approved_routes"]).include?(route)
          end
          .map { |node| Integer(node.fetch("id")) }
        abort("new primary owner #{after_id} not among remaining active routers #{remaining_ids.inspect}") unless remaining_ids.include?(after_id)

        puts JSON.pretty_generate({
          paused_client: paused_client,
          before_owner: before_id,
          after_owner: after_id,
          nodes: after_nodes,
        })
      ' "${before_path}" "${after_path}" "${route}" "${route_health_client_name}" "${router_name}" "${router_b_name}" >"${work_dir}/route-health-failover.json"
  do
    if ((SECONDS >= deadline)); then
      docker unpause "${route_health_client_name}" >/dev/null 2>&1 || true
      echo "timed out waiting for route-health failover" >&2
      dump_debug
      return 1
    fi
    sleep 1
  done
  cat "${work_dir}/route-health-failover.json"

  docker unpause "${route_health_client_name}" >/dev/null
  if ! wait_for "tailscale logged-in netmap after route-health recovery ${route_health_client_name}" "tailscale_logged_in '${route_health_client_name}'"; then
    dump_debug
    return 1
  fi
  sleep $((route_health_probe_interval_secs + route_health_probe_timeout_secs + 2))
  headscale_cmd -o json nodes list >"${recovery_path}"
  ruby -rjson -e '
    route = ARGV.fetch(2)

    def primary_owner(path, route)
      payload = JSON.parse(File.read(path))
      nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
      primary = nodes.select do |node|
        Array(
          node["subnetRoutes"] ||
          node["subnet_routes"] ||
          node["primaryRoutes"] ||
          node["primary_routes"]
        ).map(&:to_s).include?(route)
      end
      abort("expected exactly one primary node for #{route}, got #{primary.length}") unless primary.length == 1
      Integer(primary.fetch(0).fetch("id"))
    end

    failed_over_owner = primary_owner(ARGV.fetch(0), route)
    recovered_owner = primary_owner(ARGV.fetch(1), route)
    abort("route-health recovery stole #{route}: #{recovered_owner.inspect}, expected sticky #{failed_over_owner.inspect}") unless recovered_owner == failed_over_owner
    puts JSON.pretty_generate({route: route, sticky_owner: recovered_owner})
  ' "${after_path}" "${recovery_path}" "${route}" >"${work_dir}/route-health-recovery.json"
  cat "${work_dir}/route-health-recovery.json"
  echo "::endgroup::"
}

assert_route_health_all_unhealthy_after_restart() {
  local before_path="${work_dir}/route-health-peer-before-all-unhealthy.json"
  local first_unhealthy_path="${work_dir}/route-health-peer-after-first-unhealthy.json"
  local all_unhealthy_path="${work_dir}/route-health-peer-after-all-unhealthy.json"
  local owner_path="${work_dir}/route-health-peer-before-all-unhealthy.owner"
  local route_health_primary_name
  local route_health_standby_name
  local paused=()

  echo "::group::assert route-health all-unhealthy fallback after restart"
  wait_for "observer sees initial route-health owner before all-unhealthy" \
    "route_health_peer_owner_from_netmap '${observer_name}' '${route}' '${before_path}' '${owner_path}'" || {
      cat "${before_path}.err" >&2 || true
      dump_debug
      return 1
    }
  cat "${before_path}"
  route_health_primary_name="$(cat "${owner_path}")"
  case "${route_health_primary_name}" in
    "${router_name}") route_health_standby_name="${router_b_name}" ;;
    "${router_b_name}") route_health_standby_name="${router_name}" ;;
    *)
      echo "route-health primary ${route_health_primary_name} is not ${router_name} or ${router_b_name}" >&2
      dump_debug
      return 1
      ;;
  esac

  docker pause "${route_health_primary_name}" >/dev/null
  paused+=("${route_health_primary_name}")
  if ! wait_for "observer sees route-health first-unhealthy failover owner" \
    "peer_netmap_route_owner_matches '${observer_name}' '${route_health_standby_name}' '${route}' '${first_unhealthy_path}'"; then
    for client_name in "${paused[@]}"; do
      docker unpause "${client_name}" >/dev/null 2>&1 || true
    done
    cat "${first_unhealthy_path}.err" >&2 || true
    dump_debug
    return 1
  fi
  cat "${first_unhealthy_path}"

  docker pause "${route_health_standby_name}" >/dev/null
  paused+=("${route_health_standby_name}")
  sleep $((route_health_probe_interval_secs + route_health_probe_timeout_secs + 2))
  if ! wait_for "observer keeps last-known route-health owner when all candidates unhealthy" \
    "peer_netmap_route_owner_matches '${observer_name}' '${route_health_standby_name}' '${route}' '${all_unhealthy_path}'"; then
    for client_name in "${paused[@]}"; do
      docker unpause "${client_name}" >/dev/null 2>&1 || true
    done
    cat "${all_unhealthy_path}.err" >&2 || true
    dump_debug
    return 1
  fi
  cat "${all_unhealthy_path}"

  for client_name in "${paused[@]}"; do
    docker unpause "${client_name}" >/dev/null
  done
  for client_name in "${paused[@]}"; do
    if ! wait_for "tailscale logged-in netmap after all-unhealthy route-health ${client_name}" "tailscale_logged_in '${client_name}'"; then
      dump_debug
      return 1
    fi
  done
  echo "::endgroup::"
}

peer_netmap_route_owner_matches() {
  local source_name="$1"
  local peer_name="$2"
  local expected_route="$3"
  local output_path="$4"
  local netmap_path="${output_path}.netmap"
  docker exec "${source_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      netmap = JSON.parse(File.read(ARGV.fetch(0)))
      expected_peer = ARGV.fetch(1)
      expected_route = ARGV.fetch(2)
      peers = Array(netmap["Peers"] || netmap["peers"])

      def names_for(peer)
        [
          peer["HostName"],
          peer["Name"],
          peer["DNSName"],
          peer["ComputedName"],
          peer["Hostinfo"] && peer["Hostinfo"]["Hostname"],
          peer["HostInfo"] && peer["HostInfo"]["Hostname"],
        ].compact.map(&:to_s)
      end

      def route_fields(peer)
        [
          peer["AllowedIPs"],
          peer["AllowedIps"],
          peer["allowedIPs"],
          peer["allowed_ips"],
          peer["PrimaryRoutes"],
          peer["primaryRoutes"],
          peer["primary_routes"],
          peer["SubnetRoutes"],
          peer["subnetRoutes"],
          peer["subnet_routes"],
        ].compact.flatten.map(&:to_s)
      end

      peer = peers.find do |candidate|
        names_for(candidate).any? do |name|
          name == expected_peer || name.split(".").first == expected_peer || name.include?(expected_peer)
        end
      end
      abort("missing peer #{expected_peer.inspect} in netmap peers #{peers.inspect}") unless peer

      owner_routes = route_fields(peer)
      unless owner_routes.include?(expected_route)
        abort("expected #{expected_peer.inspect} to own route #{expected_route.inspect}, got #{owner_routes.inspect} in #{peer.inspect}")
      end

      other_owners = peers.reject { |candidate| candidate.equal?(peer) }.select do |candidate|
        route_fields(candidate).include?(expected_route)
      end
      unless other_owners.empty?
        details = other_owners.map { |candidate| {names: names_for(candidate), routes: route_fields(candidate)} }
        abort("expected only #{expected_peer.inspect} to own #{expected_route.inspect}, but found #{details.inspect}")
      end

      puts JSON.pretty_generate({
        source: netmap.dig("SelfNode", "HostName") || netmap.dig("SelfNode", "Name"),
        peer: expected_peer,
        route: expected_route,
        peer_names: names_for(peer),
        peer_routes: owner_routes,
      })
    ' "${netmap_path}" "${peer_name}" "${expected_route}" >"${output_path}"
}

wait_for_route_via_owner() {
  local label="$1"
  local client_name="$2"
  local peer_name="$3"
  local expected_route="$4"
  local output_path="$5"
  wait_for "${label}" \
    "peer_netmap_route_owner_matches '${client_name}' '${peer_name}' '${expected_route}' '${output_path}'" || {
      cat "${output_path}.err" >&2 || true
      dump_debug
      return 1
    }
}

wait_for_route_via_peer_maps() {
  local label="$1"
  local safe_label="${label//[^a-zA-Z0-9_-]/-}"
  if ((route_via_multiprefix_restart_flag)); then
    wait_for_route_via_owner "${label} alice route ${route} via router-a" \
      "${observer_name}" "${router_name}" "${route}" "${work_dir}/route-via-${safe_label}-alice-a.json"
    wait_for_route_via_owner "${label} alice route ${route_b} via router-b" \
      "${observer_name}" "${router_b_name}" "${route_b}" "${work_dir}/route-via-${safe_label}-alice-b.json"
    wait_for_route_via_owner "${label} bob route ${route} via router-b" \
      "${bob_name}" "${router_b_name}" "${route}" "${work_dir}/route-via-${safe_label}-bob-a.json"
    wait_for_route_via_owner "${label} bob route ${route_b} via router-a" \
      "${bob_name}" "${router_name}" "${route_b}" "${work_dir}/route-via-${safe_label}-bob-b.json"
    cat "${work_dir}/route-via-${safe_label}-alice-a.json"
    cat "${work_dir}/route-via-${safe_label}-alice-b.json"
    cat "${work_dir}/route-via-${safe_label}-bob-a.json"
    cat "${work_dir}/route-via-${safe_label}-bob-b.json"
    return
  fi

  wait_for_route_via_owner "${label} alice route via router-a" \
    "${observer_name}" "${router_name}" "${route}" "${work_dir}/route-via-${safe_label}-alice.json"
  wait_for_route_via_owner "${label} bob route via router-b" \
    "${bob_name}" "${router_b_name}" "${route}" "${work_dir}/route-via-${safe_label}-bob.json"
  cat "${work_dir}/route-via-${safe_label}-alice.json"
  cat "${work_dir}/route-via-${safe_label}-bob.json"
}

wait_for_route_via_reloaded_peer_maps() {
  local label="$1"
  local safe_label="${label//[^a-zA-Z0-9_-]/-}"
  if ((route_via_multiprefix_restart_flag)); then
    wait_for_route_via_owner "${label} alice route ${route} via router-b" \
      "${observer_name}" "${router_b_name}" "${route}" "${work_dir}/route-via-${safe_label}-alice-a-reloaded.json"
    wait_for_route_via_owner "${label} alice route ${route_b} via router-a" \
      "${observer_name}" "${router_name}" "${route_b}" "${work_dir}/route-via-${safe_label}-alice-b-reloaded.json"
    wait_for_route_via_owner "${label} bob route ${route} via router-a" \
      "${bob_name}" "${router_name}" "${route}" "${work_dir}/route-via-${safe_label}-bob-a-reloaded.json"
    wait_for_route_via_owner "${label} bob route ${route_b} via router-b" \
      "${bob_name}" "${router_b_name}" "${route_b}" "${work_dir}/route-via-${safe_label}-bob-b-reloaded.json"
    cat "${work_dir}/route-via-${safe_label}-alice-a-reloaded.json"
    cat "${work_dir}/route-via-${safe_label}-alice-b-reloaded.json"
    cat "${work_dir}/route-via-${safe_label}-bob-a-reloaded.json"
    cat "${work_dir}/route-via-${safe_label}-bob-b-reloaded.json"
    return
  fi

  wait_for_route_via_owner "${label} alice route via router-b" \
    "${observer_name}" "${router_b_name}" "${route}" "${work_dir}/route-via-${safe_label}-alice-reloaded.json"
  wait_for_route_via_owner "${label} bob route via router-b" \
    "${bob_name}" "${router_b_name}" "${route}" "${work_dir}/route-via-${safe_label}-bob-reloaded.json"
  cat "${work_dir}/route-via-${safe_label}-alice-reloaded.json"
  cat "${work_dir}/route-via-${safe_label}-bob-reloaded.json"
}

reload_route_via_policy() {
  echo "::group::reload route-via policy"
  write_route_via_reload_policy
  kill -HUP "${server_pid}"
  wait_for_server "${target} health after route-via policy reload" "curl ${health_curl_opts} '${local_control_url}/health' >/dev/null"
  wait_for_route_via_reloaded_peer_maps "after policy reload"
  echo "::endgroup::"
}

peer_map_has_route_and_tag() {
  local observer="$1"
  local peer="$2"
  local expected_route="$3"
  local expected_tag="$4"
  local output_path="$5"
  local netmap_path="${output_path}.netmap"
  docker exec "${observer}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      netmap = JSON.parse(File.read(ARGV.fetch(0)))
      peer_name = ARGV.fetch(1)
      expected_route = ARGV.fetch(2)
      expected_tag = ARGV.fetch(3)
      peers = Array(netmap["Peers"] || netmap["peers"])

      def names_for(peer)
        [
          peer["HostName"],
          peer["Hostinfo"] && peer["Hostinfo"]["Hostname"],
          peer["HostInfo"] && peer["HostInfo"]["Hostname"],
          peer["Name"],
          peer["DNSName"],
          peer["ComputedName"],
        ].compact.map(&:to_s)
      end

      peer = peers.find do |candidate|
        names_for(candidate).any? do |name|
          name == peer_name || name.split(".").first == peer_name || name.include?(peer_name)
        end
      end
      abort("missing peer #{peer_name.inspect} in netmap peers #{peers.inspect}") unless peer

      tags = Array(peer["Tags"] || peer["tags"] || peer["ForcedTags"] || peer["forcedTags"]).map(&:to_s)
      routes = [
        peer["AllowedIPs"], peer["AllowedIps"], peer["allowedIPs"], peer["allowed_ips"],
        peer["PrimaryRoutes"], peer["primaryRoutes"], peer["primary_routes"],
        peer["SubnetRoutes"], peer["subnetRoutes"], peer["subnet_routes"],
        peer.dig("Hostinfo", "RoutableIPs"), peer.dig("HostInfo", "RoutableIPs")
      ].compact.flatten.map(&:to_s)

      unless tags.include?(expected_tag)
        abort("expected peer tag #{expected_tag.inspect}, got #{tags.inspect} in #{peer.inspect}")
      end
      unless routes.any? { |route| route == expected_route || route.include?(expected_route) }
        abort("expected peer route #{expected_route.inspect}, got #{routes.inspect} in #{peer.inspect}")
      end

      puts JSON.pretty_generate({
        peer: peer_name,
        route: expected_route,
        tag: expected_tag,
        names: names_for(peer),
      })
    ' "${netmap_path}" "${peer}" "${expected_route}" "${expected_tag}" >"${output_path}"
}

wait_for_peer_map() {
  local expected_tag="$1"
  local label="$2"
  local safe_label="${label//[^a-zA-Z0-9_-]/-}"
  wait_for "${label}" \
    "peer_map_has_route_and_tag '${observer_name}' '${router_name}' '${route}' '${expected_tag}' '${work_dir}/peer-map-${safe_label}.json'" || {
      dump_debug
      return 1
    }
}

debug_batcher_url() {
  case "${target}" in
    rust) printf "http://127.0.0.1:%s/debug/batcher\n" "${metrics_port}" ;;
    headscale-go) printf "http://127.0.0.1:%s/debug/batcher\n" "${metrics_port}" ;;
  esac
}

fetch_debug_batcher() {
  local output_path="$1"
  local url
  url="$(debug_batcher_url)"
  curl -fsS -H "Accept: application/json" "${url}" >"${output_path}"
}

batcher_nodes_connected() {
  local router_id="$1"
  local observer_id="$2"
  local router_host="$3"
  local observer_host="$4"
  local output_path="$5"

  fetch_debug_batcher "${output_path}" &&
    ruby -rjson -e '
      payload = JSON.parse(File.read(ARGV.fetch(0)))
      expected = [
        [ARGV.fetch(1), ARGV.fetch(3)],
        [ARGV.fetch(2), ARGV.fetch(4)],
      ]
      nodes = payload["connected_nodes"] || payload["ConnectedNodes"]
      abort("missing connected_nodes in debug batcher payload #{payload.inspect}") unless nodes.is_a?(Hash)

      observed = expected.map do |node_id, host|
        node = nodes[node_id.to_s]
        abort("missing debug batcher node #{node_id.inspect} for #{host.inspect}; got #{nodes.keys.sort.inspect}") unless node
        connected = node.key?("connected") ? node["connected"] : node["Connected"]
        active_connections = node.key?("active_connections") ? node["active_connections"] : node["ActiveConnections"]
        abort("expected debug batcher node #{node_id.inspect} for #{host.inspect} connected=true, got #{connected.inspect} in #{node.inspect}") unless connected == true
        {
          node_id: node_id,
          host: host,
          connected: connected,
          active_connections: active_connections,
        }
      end

      puts JSON.pretty_generate({
        total_nodes: payload["total_nodes"] || payload["TotalNodes"],
        observed: observed,
      })
    ' "${output_path}" "${router_id}" "${observer_id}" "${router_host}" "${observer_host}"
}

wait_for_debug_batcher_nodes() {
  local label="$1"
  local safe_label="${label//[^a-zA-Z0-9_-]/-}"
  local router_id observer_id snapshot_path summary_path

  router_id="$(load_node_id "${router_name}")"
  observer_id="$(load_node_id "${observer_name}")"
  snapshot_path="${work_dir}/debug-batcher-${safe_label}.json"
  summary_path="${work_dir}/debug-batcher-${safe_label}.summary.json"

  echo "::group::assert debug batcher state ${label}"
  wait_for "${label} debug batcher router and observer connected" \
    "batcher_nodes_connected '${router_id}' '${observer_id}' '${router_name}' '${observer_name}' '${snapshot_path}' > '${summary_path}'" || {
      cat "${snapshot_path}" >&2 || true
      dump_debug
      return 1
    }
  cat "${summary_path}"
  echo "::endgroup::"
}

need curl
need docker
need ruby
prepare_postgres_database
case "${target}" in
  rust) need cargo ;;
  headscale-go)
    [[ -n "${HEADSCALE_GO_BIN:-}" ]] || need go
    need openssl
    ;;
esac

http_port="$(free_port)"
metrics_port="$(free_port)"
grpc_port="$(free_port)"
case "${target}" in
  rust)
    https_port="$(free_port)"
    control_url="https://host.docker.internal:${https_port}"
    local_control_url="http://127.0.0.1:${http_port}"
    ;;
  headscale-go)
    control_url="https://host.docker.internal:${http_port}"
    local_control_url="https://127.0.0.1:${http_port}"
    health_curl_opts="-fsSk"
    ;;
esac

write_derp_map
write_policy
install_or_build_headscale
if [[ "${target}" == "headscale-go" ]]; then
  generate_headscale_go_tls
fi
start_server

if ((web_register_restart_flag)); then
  web_node_id_before=""
  web_node_id_after=""
  create_user_json alice "${work_dir}/user-alice.json" >/dev/null
  start_client "${observer_name}"
  login_observer_with_web_registration "${observer_name}" alice
  web_node_id_before="$(assert_web_registered_node "before-restart")"

  stop_server
  start_server
  wait_for "web-registered node reconnected after restart" "tailscale_logged_in '${observer_name}'"
  docker exec "${observer_name}" tailscale status --json >"${work_dir}/${observer_name}.after-restart-status.json"
  web_node_id_after="$(assert_web_registered_node "after-restart")"
  if [[ "${web_node_id_before}" != "${web_node_id_after}" ]]; then
    echo "expected web-registered node ID to survive restart, before=${web_node_id_before}, after=${web_node_id_after}" >&2
    exit 1
  fi
elif ((route_via_restart_flag)); then
  create_route_via_users_and_keys
  start_client "${router_name}"
  start_client "${router_b_name}"
  start_client "${observer_name}"
  start_client "${bob_name}"
  login_router_with_authkey "${router_name}" "${router_a_authkey}"
  login_router_with_authkey "${router_b_name}" "${router_b_authkey}"
  approve_router_routes "${router_name}"
  approve_router_routes "${router_b_name}"
  login_observer_with_web_registration "${observer_name}" alice
  login_observer_with_web_registration "${bob_name}" bob
  assert_route_via_persisted_nodes "before-restart"
  wait_for_route_via_peer_maps "before restart"
  if ((route_via_reload_restart_flag)); then
    reload_route_via_policy
  fi

  stop_server
  start_server
  wait_for "router-a reconnected after restart" "tailscale_logged_in '${router_name}'"
  wait_for "router-b reconnected after restart" "tailscale_logged_in '${router_b_name}'"
  wait_for "alice reconnected after restart" "tailscale_logged_in '${observer_name}'"
  wait_for "bob reconnected after restart" "tailscale_logged_in '${bob_name}'"
  assert_route_via_persisted_nodes "after-restart"
  if ((route_via_reload_restart_flag)); then
    wait_for_route_via_reloaded_peer_maps "after restart"
  else
    wait_for_route_via_peer_maps "after restart"
  fi
elif ((route_health_restart_flag)); then
  if ((route_health_reload_restart_flag)); then
    create_route_health_reload_users_and_keys
  else
    create_user_and_key
  fi
  start_client "${router_name}"
  start_client "${router_b_name}"
  if ((route_health_mixed_exit_restart_flag)); then
    start_client "${exit_name}"
  fi
  start_client "${observer_name}"
  if ((route_health_reload_restart_flag)); then
    login_router_with_authkey "${router_name}" "${router_a_authkey}"
    login_router_with_authkey "${router_b_name}" "${router_b_authkey}"
  else
    login_router_with_authkey "${router_name}" "${authkey}"
    login_router_with_authkey "${router_b_name}" "${authkey}"
    approve_router_routes "${router_name}"
    approve_router_routes "${router_b_name}"
  fi
  if ((route_health_mixed_exit_restart_flag)); then
    login_exit_with_authkey "${exit_name}" "${authkey}"
    approve_exit_routes "${exit_name}"
  fi
  login_observer_with_web_registration "${observer_name}" alice
  if ((route_health_reload_restart_flag)); then
    wait_for_route_health_approved_candidates "before-policy-reload" "${router_name}"
    wait_for_route_via_owner "before policy reload observer sees router-a" \
      "${observer_name}" "${router_name}" "${route}" "${work_dir}/route-health-before-policy-reload-owner.json"
    reload_route_health_policy
    wait_for_route_health_peer_owner_from_admin "after-policy-reload"
  else
    wait_for_route_health_primary "before-restart"
    wait_for_route_health_peer_owner_from_admin "before-restart"
  fi

  stop_server
  start_server
  wait_for "router-a reconnected after restart" "tailscale_logged_in '${router_name}'"
  wait_for "router-b reconnected after restart" "tailscale_logged_in '${router_b_name}'"
  if ((route_health_mixed_exit_restart_flag)); then
    wait_for "exit node reconnected after restart" "tailscale_logged_in '${exit_name}'"
  fi
  wait_for "observer reconnected after restart" "tailscale_logged_in '${observer_name}'"
  if ((route_health_reload_restart_flag)); then
    wait_for_route_health_approved_candidates "after-restart" "${router_name},${router_b_name}"
  else
    wait_for_route_health_primary "after-restart"
  fi
  if ((route_health_all_unhealthy_restart_flag)); then
    assert_route_health_all_unhealthy_after_restart
  else
    assert_route_health_peer_failover_after_restart
  fi
  if ((route_health_mixed_exit_restart_flag && ! route_health_all_unhealthy_restart_flag)); then
    wait_for_route_health_primary "after-failover"
  fi
else
  create_user_and_key
  start_client "${router_name}"
  start_client "${observer_name}"
  login_router_with_authkey
  set_router_routes_and_tag "${initial_tag}"
  login_observer_with_web_registration
  assert_persisted_nodes "${initial_tag}" "before-restart"
  wait_for_debug_batcher_nodes "before-restart"

  stop_server
  start_server
  wait_for "router reconnected after restart" "tailscale_logged_in '${router_name}'"
  wait_for "observer reconnected after restart" "tailscale_logged_in '${observer_name}'"
  assert_persisted_nodes "${initial_tag}" "after-restart"
  wait_for_peer_map "${initial_tag}" "observer sees restarted route and tag"
  wait_for_debug_batcher_nodes "after-restart"

  set_router_routes_and_tag "${mutated_tag}"
  assert_persisted_nodes "${mutated_tag}" "after-post-restart-tag-mutation"
  wait_for_peer_map "${mutated_tag}" "observer sees post-restart tag mutation"
  wait_for_debug_batcher_nodes "after-post-restart-tag-mutation"
fi

echo "${target} restart persistence real-client smoke passed"
