#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

target="${REAL_CLIENT_ONLINE_LASTSEEN_TARGET:-}"
case "${target}" in
  rust | headscale-go) ;;
  *)
    echo "REAL_CLIENT_ONLINE_LASTSEEN_TARGET must be rust or headscale-go" >&2
    exit 2
    ;;
esac

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
headscale_go_version="${HEADSCALE_GO_VERSION:-v0.28.0}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-180}"
database_backend="${REAL_CLIENT_DATABASE_BACKEND:-sqlite}"
login_mode="${REAL_CLIENT_LOGIN_MODE:-authkey}"
advertise_routes="${REAL_CLIENT_ADVERTISE_ROUTES:-}"
approve_routes="${REAL_CLIENT_APPROVE_ROUTES:-}"
expected_available_routes="${REAL_CLIENT_EXPECT_AVAILABLE_ROUTES:-${advertise_routes}}"
expected_approved_routes="${REAL_CLIENT_EXPECT_APPROVED_ROUTES:-${approve_routes}}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/online-lastseen-${target}}"
run_id="hs-online-lastseen-${target}-${database_backend}-${login_mode}-$(date +%s)-$$"
case "${target}" in
  rust) client_target="rs" ;;
  headscale-go) client_target="go" ;;
esac
client_name="${REAL_CLIENT_CLIENT_NAME:-hs-ol-${client_target}-${database_backend}-${login_mode}-$$}"
base_domain="${REAL_CLIENT_BASE_DOMAIN-tail.test}"

case "${database_backend}" in
  sqlite | postgres) ;;
  *)
    echo "REAL_CLIENT_DATABASE_BACKEND must be sqlite or postgres" >&2
    exit 2
    ;;
esac

case "${login_mode}" in
  authkey | web) ;;
  *)
    echo "REAL_CLIENT_LOGIN_MODE must be authkey or web, got ${login_mode}" >&2
    exit 2
    ;;
esac

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
postgres_admin_url=""
postgres_database_name=""
postgres_host=""
postgres_port=""
postgres_user=""
postgres_pass=""
postgres_sslmode=""
postgres_database_created=0

cleanup() {
  docker rm -f "${client_name}" >/dev/null 2>&1 || true
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
    echo "skipping Postgres real-client smoke: HEADSCALE_DB_POSTGRES_TEST_URL is not set" >&2
    exit 0
  fi
  need psql
  postgres_database_name="headscale_rs_pg_real_${target//[^a-zA-Z0-9]/_}_$(date +%s)_$$"
  parse_postgres_test_url
  if ! [[ "${postgres_database_name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "internal temporary Postgres database name is invalid: ${postgres_database_name}" >&2
    exit 2
  fi
  echo "::group::create temporary Postgres database"
  if ! psql "${postgres_admin_url}" -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${postgres_database_name}" >"${work_dir}/postgres-create.stdout" 2>"${work_dir}/postgres-create.stderr"; then
    echo "skipping Postgres real-client smoke: cannot create temporary database ${postgres_database_name}" >&2
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

run_with_timeout() {
  local label="$1"
  shift
  local deadline=$((SECONDS + timeout_secs))
  "$@" &
  local pid="$!"
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

write_registration_id() {
  local output_path="$1"
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

dump_debug() {
  headscale_cmd -o json nodes list 2>&1 || true
  docker exec "${client_name}" tailscale status 2>&1 || true
  docker exec "${client_name}" sh -c 'tail -180 /tmp/tailscaled.log 2>/dev/null || true' >&2 || true
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

policy:
  mode: database
EOF
      ;;
  esac
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

write_config() {
  case "${target}" in
    rust)
      tls_cert_path="${work_dir}/tls.crt"
      tls_key_path="${work_dir}/tls.key"
      cat >"${config_path}" <<EOF
server:
  server_url: ${control_url}
  listen: 0.0.0.0:${http_port}
  https_listen: 0.0.0.0:${https_port}
  grpc_listen_addr: 127.0.0.1:${grpc_port}
  grpc_allow_insecure: true
  db_path: ${db_path}
  state_dir: ${work_dir}/state
  unix_socket: ${socket_path}
  unix_socket_permission: "0700"
  tls_hostname: host.docker.internal

unix_socket: ${socket_path}
unix_socket_permission: "0700"

cli:
  timeout: 5s

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
EOF
      ;;
  esac
  write_database_config >>"${config_path}"
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

headscale_health_probe() {
  headscale_cmd -o json health >"${work_dir}/${target}-grpc-health.stdout" 2>"${work_dir}/${target}-grpc-health.stderr"
}

dump_grpc_health_debug() {
  echo "::group::${target} gRPC health debug"
  ls -l "${socket_path}" >&2 || true
  if [[ -s "${work_dir}/${target}-grpc-health.stdout" ]]; then
    echo "--- last health stdout ---" >&2
    cat "${work_dir}/${target}-grpc-health.stdout" >&2 || true
  fi
  if [[ -s "${work_dir}/${target}-grpc-health.stderr" ]]; then
    echo "--- last health stderr ---" >&2
    cat "${work_dir}/${target}-grpc-health.stderr" >&2 || true
  fi
  echo "--- direct health retry ---" >&2
  headscale_cmd -o json health >&2 || true
  echo "::endgroup::"
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
  wait_for "${target} health" "curl ${health_curl_opts} '${local_control_url}/health' >/dev/null"
  if [[ "${target}" == "rust" ]]; then
    wait_for "${target} TLS certificate" "test -s '${tls_cert_path}'"
  fi
  wait_for "${target} gRPC" "headscale_health_probe" || {
    dump_grpc_health_debug
    return 1
  }
  echo "${target} control=${local_control_url}"
  echo "${target} login=${control_url}"
  echo "::endgroup::"
}

create_user_and_key() {
  echo "::group::create user"
  case "${target}" in
    rust)
      headscale_cmd -o json users create alice >"${work_dir}/user.json"
      ;;
    headscale-go)
      headscale_cmd -o json users create alice >"${work_dir}/user.json"
      ;;
  esac
  local user_id
  user_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("id")' "${work_dir}/user.json")"
  echo "created user alice ${user_id}"
  echo "::endgroup::"

  if [[ "${login_mode}" == "authkey" ]]; then
    echo "::group::mint preauth key"
    case "${target}" in
      rust)
        headscale_cmd -o json preauthkeys create --user "${user_id}" --reusable --expires-in 1h >"${work_dir}/preauth.json"
        ;;
      headscale-go)
        headscale_cmd -o json preauthkeys create --user "${user_id}" --reusable --expiration 1h >"${work_dir}/preauth.json"
        ;;
    esac
    authkey="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("key")' "${work_dir}/preauth.json")"
    echo "minted ${authkey%%-*}-..."
    echo "::endgroup::"
  fi
}

start_client() {
  echo "::group::start stock tailscale client"
  docker_args=(
    docker run -d
    --name "${client_name}" \
    --hostname "${client_name}" \
    --add-host host.docker.internal:host-gateway \
    --entrypoint /bin/sh
  )
  docker_args+=(-v "${tls_cert_path}:/usr/local/share/ca-certificates/headscale-control.crt:ro")
  docker_args+=("${image}")
  "${docker_args[@]}" \
    -ceu 'update-ca-certificates >/tmp/update-ca-certificates.log 2>&1; tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity' \
    >/dev/null

  wait_for "tailscaled local socket" \
    "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
  echo "::endgroup::"
}

login_client() {
  echo "::group::tailscale up"
  up_args=(
    tailscale up
    "--login-server=${control_url}"
    "--hostname=${client_name}"
    --timeout=60s
    --accept-routes=false
    --accept-dns=false
  )
  if [[ "${login_mode}" == "authkey" ]]; then
    up_args+=("--authkey=${authkey}")
  fi
  if [[ -n "${advertise_routes}" ]]; then
    up_args+=("--advertise-routes=${advertise_routes}")
  fi

  up_status=0
  if [[ "${login_mode}" == "web" ]]; then
    docker exec "${client_name}" "${up_args[@]}" \
      >"${work_dir}/${client_name}.tailscale-up.stdout" \
      2>"${work_dir}/${client_name}.tailscale-up.stderr" &
    up_pid="$!"
    registration_id_path="${work_dir}/${client_name}.registration-id"
    if ! wait_for "web registration URL" "write_registration_id '${registration_id_path}'"; then
      dump_debug
      return 1
    fi
    registration_id="$(cat "${registration_id_path}")"
    case "${target}" in
      rust)
        auth_id="${registration_id}"
        case "${auth_id}" in
          hskey-authreq-*) ;;
          *) auth_id="hskey-authreq-${auth_id}" ;;
        esac
        headscale_cmd -o json auth register "--auth-id=${auth_id}" --user alice \
          >"${work_dir}/${client_name}.registered.json"
        ;;
      headscale-go)
        headscale_cmd -o json nodes register --user alice "--key=${registration_id}" \
          >"${work_dir}/${client_name}.registered.json"
        ;;
    esac
    wait_pid_with_timeout "tailscale up ${client_name}" "${up_pid}" ||
      up_status="$?"
  else
    run_with_timeout "tailscale up ${client_name}" docker exec "${client_name}" "${up_args[@]}" ||
      up_status="$?"
  fi
  if ((up_status != 0)); then
    echo "tailscale up returned ${up_status}; verifying logged-in netmap"
  fi
  wait_for "logged-in client netmap" \
    "docker exec '${client_name}' tailscale status --json >'${work_dir}/${client_name}.status.json' 2>/dev/null && ruby -rjson -e 's=JSON.parse(File.read(ARGV.fetch(0))); ips=Array(s[\"TailscaleIPs\"]); ok=s[\"HaveNodeKey\"] && s[\"AuthURL\"].to_s.empty? && (s[\"Self\"]||{})[\"InNetworkMap\"] && ips.any? { |ip| ip.to_s.include?(\".\") }; exit(ok ? 0 : 1)' '${work_dir}/${client_name}.status.json'"
  echo "::endgroup::"
}

assert_client_netmap() {
  local netmap_path="${work_dir}/${client_name}.netmap.json"
  docker exec "${client_name}" tailscale debug netmap >"${netmap_path}" 2>"${netmap_path}.err"
  ruby -rjson -e '
    netmap = JSON.parse(File.read(ARGV.fetch(0)))
    client_name = ARGV.fetch(1)
    expected_allowed = ARGV.fetch(2).split(",").reject(&:empty?)
    self_node = netmap["SelfNode"] || netmap["Node"] || {}
    hostname = self_node["HostName"] || self_node["Name"] || self_node["DNSName"]
    ips = Array(self_node["Addresses"] || self_node["AllowedIPs"] || self_node["AllowedIps"])
    allowed_ips = Array(
      self_node["AllowedIPs"] ||
      self_node["AllowedIps"] ||
      self_node["allowedIPs"] ||
      self_node["allowed_ips"]
    ).map(&:to_s)
    abort("expected self node in netmap, got #{netmap.inspect}") if self_node.empty?
    abort("expected self hostname to include #{client_name.inspect}, got #{hostname.inspect}") unless hostname.to_s.include?(client_name)
    abort("expected self node addresses/AllowedIPs in #{self_node.inspect}") if ips.empty?
    expected_allowed.each do |route|
      abort("expected self AllowedIPs to include approved route #{route.inspect}, got #{allowed_ips.inspect}") unless allowed_ips.include?(route)
    end
    puts JSON.pretty_generate({
      hostname: hostname,
      ips: ips,
      allowed_ips: allowed_ips,
      peers: Array(netmap["Peers"] || netmap["peers"]).length,
    })
  ' "${netmap_path}" "${client_name}" "${expected_approved_routes}" >"${work_dir}/${client_name}.netmap-summary.json"
  cat "${work_dir}/${client_name}.netmap-summary.json"
}

wait_for_client_netmap() {
  wait_for "client netmap" "assert_client_netmap" || {
    dump_debug
    return 1
  }
}

node_id_for_client() {
  local path="$1"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    client_name = ARGV.fetch(1)
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    node = nodes.find do |candidate|
      [
        candidate["givenName"],
        candidate["given_name"],
        candidate["name"],
        candidate["hostname"],
      ].compact.map(&:to_s).any? { |name| name == client_name || name.include?(client_name) }
    end
    abort("expected one node named #{client_name.inspect}, got #{nodes.inspect}") unless node
    id = node["id"] || node["ID"]
    abort("expected node id in #{node.inspect}") if id.nil? || id.to_s.empty?
    puts id
  ' "${path}" "${client_name}"
}

assert_node_routes_file() {
  local path="$1"
  local expected_available="$2"
  local expected_approved="$3"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    client_name = ARGV.fetch(1)
    expected_available = ARGV.fetch(2).split(",").reject(&:empty?).sort
    expected_approved = ARGV.fetch(3).split(",").reject(&:empty?).sort
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    node = nodes.find do |candidate|
      [
        candidate["givenName"],
        candidate["given_name"],
        candidate["name"],
        candidate["hostname"],
      ].compact.map(&:to_s).any? { |name| name == client_name || name.include?(client_name) }
    end
    abort("expected one node named #{client_name.inspect}, got #{nodes.inspect}") unless node
    available = Array(
      node["availableRoutes"] ||
      node["available_routes"] ||
      node["routes"]
    ).map(&:to_s).sort
    approved = Array(node["approvedRoutes"] || node["approved_routes"]).map(&:to_s).sort
    subnet = Array(node["subnetRoutes"] || node["subnet_routes"]).map(&:to_s).sort
    abort("expected available routes #{expected_available.inspect}, got #{available.inspect} in #{node.inspect}") unless available == expected_available
    abort("expected approved routes #{expected_approved.inspect}, got #{approved.inspect} in #{node.inspect}") unless approved == expected_approved
    expected_approved.each do |route|
      abort("expected subnet routes to include #{route.inspect}, got #{subnet.inspect}") unless subnet.include?(route)
    end
    puts JSON.pretty_generate({name: client_name, available_routes: available, approved_routes: approved, subnet_routes: subnet, node: node})
  ' "${path}" "${client_name}" "${expected_available}" "${expected_approved}"
}

wait_for_node_routes() {
  local expected_available="$1"
  local expected_approved="$2"
  local label="$3"
  local path="${work_dir}/nodes-${label//[^a-zA-Z0-9_-]/-}.json"
  wait_for "${label}" "headscale_cmd -o json nodes list >'${path}' && assert_node_routes_file '${path}' '${expected_available}' '${expected_approved}'" || {
    dump_debug
    return 1
  }
}

approve_routes_if_requested() {
  [[ -n "${advertise_routes}" || -n "${approve_routes}" ]] || return 0
  wait_for_node_routes "${expected_available_routes}" "" "advertised routes"
  [[ -n "${approve_routes}" ]] || return 0

  echo "::group::approve routes"
  local nodes_path="${work_dir}/nodes-before-approve.json"
  headscale_cmd -o json nodes list >"${nodes_path}"
  local node_id
  node_id="$(node_id_for_client "${nodes_path}")"
  headscale_cmd -o json nodes approve-routes --identifier "${node_id}" --routes "${approve_routes}" \
    >"${work_dir}/approved-routes.json"
  echo "::endgroup::"

  wait_for_node_routes "${expected_available_routes}" "${expected_approved_routes}" "approved routes"
}

assert_node_lifecycle_file() {
  local path="$1"
  local expected_online="$2"
  local min_last_seen="${3:-0}"
  ruby -rjson -rtime -e '
    def last_seen_epoch(value)
      case value
      when String
        Time.parse(value).to_f
      when Hash
        seconds = value["seconds"] || value[:seconds]
        nanos = value["nanos"] || value[:nanos] || 0
        seconds.nil? ? nil : seconds.to_f + nanos.to_f / 1_000_000_000.0
      else
        nil
      end
    end

    payload = JSON.parse(File.read(ARGV.fetch(0)))
    expected_online = ARGV.fetch(1) == "true"
    min_last_seen = ARGV.fetch(2).to_f
    client_name = ARGV.fetch(3)
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    node = nodes.find do |candidate|
      [candidate["givenName"], candidate["given_name"], candidate["name"], candidate["hostname"]].compact.map(&:to_s).include?(client_name)
    end
    abort("expected one node named #{client_name.inspect}, got #{nodes.inspect}") unless node
    online = node.key?("online") ? !!node["online"] : false
    abort("expected online=#{expected_online}, got #{online} in #{node.inspect}") unless online == expected_online
    last_seen = last_seen_epoch(node["lastSeen"] || node["last_seen"])
    abort("expected parseable lastSeen/last_seen in #{node.inspect}") unless last_seen
    if min_last_seen.positive? && last_seen <= min_last_seen
      abort("expected lastSeen #{last_seen} to be later than #{min_last_seen} in #{node.inspect}")
    end
    File.write(ARGV.fetch(4), last_seen.to_s)
    puts JSON.pretty_generate({name: client_name, online: online, last_seen_epoch: last_seen, node: node})
  ' "${path}" "${expected_online}" "${min_last_seen}" "${client_name}" "${work_dir}/last-seen.epoch"
}

wait_for_node_lifecycle() {
  local expected_online="$1"
  local label="$2"
  local min_last_seen="${3:-0}"
  local path="${work_dir}/nodes-${label//[^a-zA-Z0-9_-]/-}.json"
  wait_for "${label}" "headscale_cmd -o json nodes list >'${path}' && assert_node_lifecycle_file '${path}' '${expected_online}' '${min_last_seen}'" || {
    dump_debug
    return 1
  }
}

stop_tailscaled() {
  echo "::group::stop tailscaled"
  docker exec "${client_name}" sh -ceu 'pids="$(pidof tailscaled 2>/dev/null || true)"; if [ -n "$pids" ]; then kill -TERM $pids; fi'
  echo "::endgroup::"
}

need ruby
prepare_postgres_database
need curl
need docker
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
install_or_build_headscale
if [[ "${target}" == "headscale-go" ]]; then
  generate_headscale_go_tls
fi
start_server
create_user_and_key
start_client
login_client
approve_routes_if_requested
wait_for_client_netmap
wait_for_node_lifecycle true "connected online node"
connected_last_seen="$(cat "${work_dir}/last-seen.epoch")"
stop_tailscaled
wait_for_node_lifecycle false "offline node after disconnect grace" "${connected_last_seen}"

echo "${target} online/lastSeen real-client smoke passed"
