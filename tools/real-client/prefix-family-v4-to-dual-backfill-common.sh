#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

target="${REAL_CLIENT_PREFIX_MIGRATION_TARGET:-}"
case "${target}" in
  rust | headscale-go) ;;
  *)
    echo "REAL_CLIENT_PREFIX_MIGRATION_TARGET must be rust or headscale-go" >&2
    exit 2
    ;;
esac
migration_case="${REAL_CLIENT_PREFIX_MIGRATION_CASE:-v4-to-dual}"
case "${migration_case}" in
  v4-to-dual)
    initial_family="ipv4-only"
    final_family="dual-stack"
    backfill_label="enabling IPv6"
    expected_change_fragment="assigned IPv6"
    ;;
  dual-to-v4)
    initial_family="dual-stack"
    final_family="ipv4-only"
    backfill_label="disabling IPv6"
    expected_change_fragment="removing IPv6"
    ;;
  dual-to-v6)
    initial_family="dual-stack"
    final_family="ipv6-only"
    backfill_label="disabling IPv4"
    expected_change_fragment="removing IPv4"
    ;;
  *)
    echo "REAL_CLIENT_PREFIX_MIGRATION_CASE must be v4-to-dual, dual-to-v4, or dual-to-v6" >&2
    exit 2
    ;;
esac

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
# shellcheck source=tools/real-client/headscale-go-baseline.sh
source tools/real-client/headscale-go-baseline.sh
headscale_go_version="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_BASELINE_VERSION}}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-180}"
database_backend="${REAL_CLIENT_DATABASE_BACKEND:-sqlite}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/prefix-family-${migration_case}-backfill-${target}}"
run_id="hspf-${migration_case}-${target}-$(date +%s)-$$"
client_name="${REAL_CLIENT_CLIENT_NAME:-${run_id}-client}"
peer_name="${REAL_CLIENT_PEER_NAME:-${run_id}-peer}"
base_domain="${REAL_CLIENT_BASE_DOMAIN-tail.test}"
edge="${REAL_CLIENT_PREFIX_MIGRATION_EDGE:-addresses}"
route="${REAL_CLIENT_PREFIX_BACKFILL_ROUTE:-10.94.0.0/24}"

case "${database_backend}" in
  sqlite | postgres) ;;
  *)
    echo "REAL_CLIENT_DATABASE_BACKEND must be sqlite or postgres" >&2
    exit 2
    ;;
esac
case "${edge}" in
  addresses | route-approval-restart | magicdns-peer-restart) ;;
  *)
    echo "REAL_CLIENT_PREFIX_MIGRATION_EDGE must be addresses, route-approval-restart, or magicdns-peer-restart" >&2
    exit 2
    ;;
esac
magic_dns_enabled=false
accept_dns_arg=false
client_names=("${client_name}")
if [[ "${edge}" == "magicdns-peer-restart" ]]; then
  if [[ "${migration_case}" != "v4-to-dual" ]]; then
    echo "magicdns-peer-restart edge currently requires REAL_CLIENT_PREFIX_MIGRATION_CASE=v4-to-dual" >&2
    exit 2
  fi
  magic_dns_enabled=true
  accept_dns_arg=true
  client_names+=("${peer_name}")
fi

# shellcheck source=tools/real-client/postgres-test-db-common.sh
source tools/real-client/postgres-test-db-common.sh

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
active_server_label=""

cleanup() {
  docker rm -f "${client_names[@]}" >/dev/null 2>&1 || true
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
  fi
  if [[ "${database_backend}" == "postgres" ]]; then
    real_client_drop_postgres_database || true
  fi
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

wait_for() {
  local label="$1"
  local cmd="$2"
  local deadline=$((SECONDS + timeout_secs))
  until eval "${cmd}"; do
    if [[ -n "${server_pid}" ]] && ! kill -0 "${server_pid}" >/dev/null 2>&1; then
      wait "${server_pid}" >/dev/null 2>&1 || true
      server_pid=""
      echo "${target} server exited while waiting for ${label}" >&2
      dump_server_logs "server exited before ${label}"
      return 1
    fi
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for ${label}" >&2
      dump_server_logs "timed out waiting for ${label}"
      return 1
    fi
    sleep 1
  done
}

dump_client_debug() {
  dump_server_logs "client debug snapshot"
  local name
  for name in "${client_names[@]}"; do
    echo "--- client ${name} status ---" >&2
    docker exec "${name}" tailscale status 2>&1 || true
    echo "--- client ${name} tailscaled log ---" >&2
    docker exec "${name}" sh -c 'tail -180 /tmp/tailscaled.log 2>/dev/null || true' >&2
  done
}

dump_server_logs() {
  local reason="$1"
  local prefix="${active_server_label:-${target}}"
  local path
  if [[ -n "${local_control_url}" ]]; then
    server_health_probe >/dev/null 2>&1 || true
  fi
  if [[ -s "${config_path}" ]]; then
    server_grpc_health_probe >/dev/null 2>&1 || true
  fi
  echo "::group::${target} server debug (${reason})"
  for path in \
    "${work_dir}/${prefix}.stderr" \
    "${work_dir}/${prefix}.stdout" \
    "${work_dir}/${prefix}-health.stderr" \
    "${work_dir}/${prefix}-health.stdout" \
    "${work_dir}/${prefix}-grpc-health.stderr" \
    "${work_dir}/${prefix}-grpc-health.stdout" \
    "${work_dir}/headscale-rs-version.txt" \
    "${work_dir}/headscale-go-version.txt" \
    "${work_dir}/openssl.stderr" \
    "${work_dir}/openssl.stdout"; do
    if [[ -s "${path}" ]]; then
      echo "--- ${path} ---" >&2
      tail -200 "${path}" >&2 || true
    fi
  done
  echo "--- socket ${socket_path} ---" >&2
  ls -l "${socket_path}" >&2 || true
  echo "::endgroup::"
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
      "${headscale_bin}" version >"${work_dir}/headscale-rs-version.txt" 2>&1 || true
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

append_database_config() {
  case "${database_backend}" in
    sqlite)
      if [[ "${target}" == "headscale-go" ]]; then
        cat >>"${config_path}" <<EOF

database:
  type: sqlite
  sqlite:
    path: ${db_path}
EOF
      fi
      ;;
    postgres)
      printf '\n' >>"${config_path}"
      real_client_write_postgres_database_config >>"${config_path}"
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
  local family="$1"
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
  unix_socket: ${socket_path}
  unix_socket_permission: "0700"
  tls_hostname: host.docker.internal

noise:
  private_key_path: ${work_dir}/state/noise_private.key

prefixes:
  allocation: sequential
EOF
      if [[ "${family}" != "ipv6-only" ]]; then
        printf '  v4: 100.64.0.0/10\n' >>"${config_path}"
      fi
      if [[ "${family}" != "ipv4-only" ]]; then
        printf '  v6: fd7a:115c:a1e0::/48\n' >>"${config_path}"
      fi
      append_database_config
      if [[ "${database_backend}" == "postgres" ]]; then
        printf '\n' >>"${config_path}"
      fi
      cat >>"${config_path}" <<EOF
dns:
  magic_dns: ${magic_dns_enabled}
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
EOF
      if [[ "${family}" != "ipv6-only" ]]; then
        printf '  v4: 100.64.0.0/10\n' >>"${config_path}"
      fi
      if [[ "${family}" != "ipv4-only" ]]; then
        printf '  v6: fd7a:115c:a1e0::/48\n' >>"${config_path}"
      fi
      append_database_config
      cat >>"${config_path}" <<EOF

dns:
  magic_dns: ${magic_dns_enabled}
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

server_health_probe() {
  local prefix="${active_server_label:-${target}}"
  curl ${health_curl_opts} "${local_control_url}/health" \
    >"${work_dir}/${prefix}-health.stdout" \
    2>"${work_dir}/${prefix}-health.stderr"
}

server_grpc_health_probe() {
  local prefix="${active_server_label:-${target}}"
  headscale_cmd health \
    >"${work_dir}/${prefix}-grpc-health.stdout" \
    2>"${work_dir}/${prefix}-grpc-health.stderr"
}

start_server() {
  local family="$1"
  active_server_label="${target}-${family}"
  write_config "${family}"
  rm -f "${socket_path}"
  echo "::group::start ${target} server (${family})"
  printf '\n--- %s start %s ---\n' "${target} ${family}" "$(date -u +%FT%TZ)" >>"${work_dir}/${active_server_label}.stdout"
  printf '\n--- %s start %s ---\n' "${target} ${family}" "$(date -u +%FT%TZ)" >>"${work_dir}/${active_server_label}.stderr"
  case "${target}" in
    rust)
      mkdir -p "${work_dir}/state"
      "${headscale_bin}" --config "${config_path}" serve \
        >>"${work_dir}/${active_server_label}.stdout" \
        2>>"${work_dir}/${active_server_label}.stderr" &
      ;;
    headscale-go)
      "${headscale_bin}" -c "${config_path}" serve \
        >>"${work_dir}/${active_server_label}.stdout" \
        2>>"${work_dir}/${active_server_label}.stderr" &
      ;;
  esac
  server_pid="$!"
  wait_for "${target} health (${family})" "server_health_probe"
  if [[ "${target}" == "rust" ]]; then
    wait_for "${target} TLS certificate (${family})" "test -s '${tls_cert_path}'"
  fi
  wait_for "${target} gRPC (${family})" "server_grpc_health_probe"
  echo "${target} control=${local_control_url}"
  echo "${target} login=${control_url}"
  echo "::endgroup::"
}

stop_server() {
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
    server_pid=""
  fi
}

create_user_and_key() {
  echo "::group::create user and preauth key"
  case "${target}" in
    rust)
      headscale_cmd -o json users create alice >"${work_dir}/user.json"
      local user_id
      user_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("id")' "${work_dir}/user.json")"
      headscale_cmd -o json preauthkeys create --user "${user_id}" --reusable --expiration 1h >"${work_dir}/preauth.json"
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

start_named_client() {
  local name="$1"
  echo "::group::start stock tailscale client ${name}"
  docker_args=(
    docker run -d
    --name "${name}" \
    --hostname "${name}" \
    --add-host host.docker.internal:host-gateway \
    --entrypoint /bin/sh
  )
  client_entry='tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity'
  if [[ -n "${tls_cert_path}" ]]; then
    docker_args+=(-v "${tls_cert_path}:/usr/local/share/ca-certificates/headscale-control.crt:ro")
    client_entry='update-ca-certificates >/tmp/update-ca-certificates.log 2>&1; tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity'
  fi
  docker_args+=("${image}")
  "${docker_args[@]}" \
    -ceu "${client_entry}" \
    >/dev/null

  wait_for "tailscaled local socket" \
    "docker exec '${name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
  echo "::endgroup::"
}

start_clients() {
  local name
  for name in "${client_names[@]}"; do
    start_named_client "${name}"
  done
}

assert_status_family_file() {
  local path="$1"
  local expected="$2"
  ruby -rjson -e '
    status = JSON.parse(File.read(ARGV.fetch(0)))
    expected = ARGV.fetch(1)
    self_node = status["Self"] || {}
    ips = Array(status["TailscaleIPs"])
    has_v4 = ips.any? { |ip| ip.to_s.include?(".") }
    has_v6 = ips.any? { |ip| ip.to_s.include?(":") }
    ok = status["HaveNodeKey"] && status["AuthURL"].to_s.empty? && self_node["InNetworkMap"]
    case expected
    when "ipv4-only"
      ok &&= has_v4 && !has_v6
    when "ipv6-only"
      ok &&= !has_v4 && has_v6
    when "dual-stack"
      ok &&= has_v4 && has_v6
    else
      abort("unsupported expected family #{expected.inspect}")
    end
    exit(ok ? 0 : 1)
  ' "${path}" "${expected}"
}

wait_for_named_client_family() {
  local name="$1"
  local expected="$2"
  local label="$3"
  local slug="${label//[^[:alnum:]_.-]/-}"
  local path="${work_dir}/${name}.${slug}.${expected}.status.json"
  wait_for "${label}" "docker exec '${name}' tailscale status --json >'${path}' 2>/dev/null && assert_status_family_file '${path}' '${expected}'" || {
    dump_client_debug
    return 1
  }
  ruby -rjson -e '
    status = JSON.parse(File.read(ARGV.fetch(0)))
    puts JSON.pretty_generate({host: status.dig("Self", "HostName"), tailscale_ips: status.fetch("TailscaleIPs")})
  ' "${path}"
}

wait_for_client_family() {
  wait_for_named_client_family "${client_name}" "$@"
}

wait_for_all_clients_family() {
  local expected="$1"
  local label="$2"
  local name
  for name in "${client_names[@]}"; do
    wait_for_named_client_family "${name}" "${expected}" "${label} (${name})"
  done
}

login_named_client_initial_family() {
  local name="$1"
  local advertise_route="$2"
  echo "::group::tailscale up ${name} against ${initial_family} config"
  up_status=0
  up_args=(
    tailscale up
    "--login-server=${control_url}" \
    "--hostname=${name}" \
    --timeout=60s \
    --accept-routes=false \
    "--accept-dns=${accept_dns_arg}" \
    "--authkey=${authkey}"
  )
  if [[ "${advertise_route}" == "true" ]]; then
    up_args+=("--advertise-routes=${route}")
  fi
  docker exec "${name}" "${up_args[@]}" \
    >"${work_dir}/${name}.tailscale-up.stdout" \
    2>"${work_dir}/${name}.tailscale-up.stderr" ||
    up_status="$?"
  if ((up_status != 0)); then
    echo "tailscale up returned ${up_status}; verifying logged-in netmap"
  fi
  wait_for_named_client_family "${name}" "${initial_family}" "${initial_family} client netmap (${name})"
  echo "::endgroup::"
}

login_clients_initial_family() {
  local advertise_route=false
  [[ "${edge}" == "route-approval-restart" ]] && advertise_route=true
  login_named_client_initial_family "${client_name}" "${advertise_route}"
  if [[ "${edge}" == "magicdns-peer-restart" ]]; then
    login_named_client_initial_family "${peer_name}" false
  fi
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
      ].compact.map(&:to_s).include?(client_name)
    end
    abort("expected one node named #{client_name.inspect}, got #{nodes.inspect}") unless node
    available = Array(node["availableRoutes"] || node["available_routes"] || node["routes"]).map(&:to_s).sort
    approved = Array(node["approvedRoutes"] || node["approved_routes"]).map(&:to_s).sort
    subnet = Array(node["subnetRoutes"] || node["subnet_routes"]).map(&:to_s).sort
    abort("expected available routes #{expected_available.inspect}, got #{available.inspect} in #{node.inspect}") unless available == expected_available
    abort("expected approved routes #{expected_approved.inspect}, got #{approved.inspect} in #{node.inspect}") unless approved == expected_approved
    expected_approved.each do |candidate_route|
      abort("expected subnet routes to include #{candidate_route.inspect}, got #{subnet.inspect}") unless subnet.include?(candidate_route)
    end
    puts JSON.pretty_generate({name: client_name, available_routes: available, approved_routes: approved, subnet_routes: subnet})
  ' "${path}" "${client_name}" "${expected_available}" "${expected_approved}"
}

wait_for_node_routes() {
  local expected_available="$1"
  local expected_approved="$2"
  local label="$3"
  local path="${work_dir}/nodes-${label//[^a-zA-Z0-9_-]/-}.json"
  wait_for "${label}" "headscale_cmd -o json nodes list >'${path}' && assert_node_routes_file '${path}' '${expected_available}' '${expected_approved}'" || {
    dump_client_debug
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
      ].compact.map(&:to_s).include?(client_name)
    end
    abort("expected one node named #{client_name.inspect}, got #{nodes.inspect}") unless node
    id = node["id"] || node["ID"]
    abort("expected node id in #{node.inspect}") if id.nil? || id.to_s.empty?
    puts id
  ' "${path}" "${client_name}"
}

approve_route_edge_if_requested() {
  [[ "${edge}" == "route-approval-restart" ]] || return 0

  wait_for_node_routes "${route}" "" "advertised route before prefix restart"

  echo "::group::approve advertised route before prefix restart"
  local nodes_path="${work_dir}/nodes-before-route-approve.json"
  local node_id
  headscale_cmd -o json nodes list >"${nodes_path}"
  node_id="$(node_id_for_client "${nodes_path}")"
  headscale_cmd -o json nodes approve-routes --identifier "${node_id}" --routes "${route}" \
    >"${work_dir}/approved-routes-${node_id}.json"
  echo "::endgroup::"

  wait_for_node_routes "${route}" "${route}" "approved route before prefix restart"
}

assert_route_edge_if_requested() {
  local label="$1"
  [[ "${edge}" == "route-approval-restart" ]] || return 0
  wait_for_node_routes "${route}" "${route}" "${label}"
}

assert_dns_debug_resolve() {
  local resolver_client="$1"
  local expected_name="$2"
  local network="$3"
  local expected_value="$4"
  local output_path="$5"
  local raw_path="${output_path}.raw"
  docker exec "${resolver_client}" tailscale debug resolve "--net=${network}" "${expected_name}" \
    >"${raw_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      raw_path = ARGV.fetch(0)
      expected_name = ARGV.fetch(1)
      network = ARGV.fetch(2)
      expected_value = ARGV.fetch(3)
      values = File.read(raw_path).lines.map(&:strip).reject(&:empty?)
      abort("expected #{expected_name} #{network} resolution #{expected_value.inspect}, got #{values.inspect}") unless values == [expected_value]
      puts JSON.pretty_generate({"Name" => expected_name, "Network" => network, "Resolved" => values})
    ' "${raw_path}" "${expected_name}" "${network}" "${expected_value}" >"${output_path}"
}

assert_magicdns_peer_resolves_both_families() {
  local resolver_client="$1"
  local target_client="$2"
  local output_path="$3"
  local status_path="${output_path}.status.json"
  local expectation_path="${output_path}.expectation.tsv"
  docker exec "${resolver_client}" tailscale status --json >"${status_path}" 2>"${output_path}.status.err" &&
    ruby -rjson -e '
      status = JSON.parse(File.read(ARGV.fetch(0)))
      target = ARGV.fetch(1)
      peers = status["Peer"] || {}
      peer = peers.each_value.find do |candidate|
        [
          candidate["HostName"],
          candidate["DNSName"].to_s.sub(/\.\z/, "").split(".").first,
          candidate.dig("Hostinfo", "Hostname"),
          candidate.dig("HostInfo", "Hostname"),
        ].compact.map(&:to_s).include?(target)
      end
      abort("expected peer #{target.inspect} in MagicDNS resolver status, got #{peers.inspect}") unless peer
      name = peer.fetch("DNSName").to_s.sub(/\.\z/, "")
      abort("expected peer DNSName for #{target.inspect}, got #{peer.inspect}") if name.empty?
      ips = Array(peer["TailscaleIPs"])
      ip4 = ips.find { |value| value.to_s.include?(".") }
      ip6 = ips.find { |value| value.to_s.include?(":") }
      abort("expected peer #{target.inspect} to have IPv4 and IPv6 for MagicDNS A/AAAA resolution, got #{ips.inspect}") if ip4.to_s.empty? || ip6.to_s.empty?
      puts [name, ip4, ip6].join("\t")
    ' "${status_path}" "${target_client}" >"${expectation_path}" || return

  local name ip4 ip6
  IFS=$'\t' read -r name ip4 ip6 <"${expectation_path}"
  local safe_name="${name//[^a-zA-Z0-9_.-]/-}"
  wait_for "peer MagicDNS ${resolver_client} resolves ${name} A" \
    "assert_dns_debug_resolve '${resolver_client}' '${name}' ip4 '${ip4}' '${output_path}.${safe_name}.ip4.json'" || return 1
  wait_for "peer MagicDNS ${resolver_client} resolves ${name} AAAA" \
    "assert_dns_debug_resolve '${resolver_client}' '${name}' ip6 '${ip6}' '${output_path}.${safe_name}.ip6.json'" || return 1
  ruby -rjson -e '
    resolver = ARGV.fetch(0)
    target = ARGV.fetch(1)
    name, ip4, ip6 = File.read(ARGV.fetch(2)).strip.split("\t")
    puts JSON.pretty_generate({resolver: resolver, target: target, dns_name: name, a: ip4, aaaa: ip6})
  ' "${resolver_client}" "${target_client}" "${expectation_path}" >"${output_path}"
}

assert_magicdns_edge_if_requested() {
  local label="$1"
  [[ "${edge}" == "magicdns-peer-restart" ]] || return 0
  echo "::group::assert MagicDNS peer A/AAAA resolution ${label}"
  wait_for "MagicDNS ${client_name} resolves ${peer_name} ${label}" \
    "assert_magicdns_peer_resolves_both_families '${client_name}' '${peer_name}' '${work_dir}/${client_name}.magicdns-${label//[^a-zA-Z0-9_-]/-}.json'" || {
      dump_client_debug
      echo "::endgroup::"
      return 1
    }
  cat "${work_dir}/${client_name}.magicdns-${label//[^a-zA-Z0-9_-]/-}.json"
  wait_for "MagicDNS ${peer_name} resolves ${client_name} ${label}" \
    "assert_magicdns_peer_resolves_both_families '${peer_name}' '${client_name}' '${work_dir}/${peer_name}.magicdns-${label//[^a-zA-Z0-9_-]/-}.json'" || {
      dump_client_debug
      echo "::endgroup::"
      return 1
    }
  cat "${work_dir}/${peer_name}.magicdns-${label//[^a-zA-Z0-9_-]/-}.json"
  echo "::endgroup::"
}

run_backfill() {
  echo "::group::run ${target} backfill after ${backfill_label}"
  headscale_cmd --force -o json nodes backfillips >"${work_dir}/backfill.json"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    changes = Array(payload["changes"] || payload["Changes"])
    expected = ARGV.fetch(1)
    abort("expected #{expected.inspect} change, got #{changes.inspect}") unless changes.any? { |c| c.to_s.include?(expected) }
    puts JSON.pretty_generate({changes: changes})
  ' "${work_dir}/backfill.json" "${expected_change_fragment}"
  echo "::endgroup::"
}

assert_node_state_family() {
  local expected_family="$1"
  local label="${2:-after-backfill}"
  local nodes_path="${work_dir}/nodes-${label}.json"
  local expected_names="${client_name}"
  if [[ "${edge}" == "magicdns-peer-restart" ]]; then
    expected_names="${client_name},${peer_name}"
  fi
  echo "::group::assert ${target} node state ${label}"
  headscale_cmd -o json nodes list >"${nodes_path}"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    expected_names = ARGV.fetch(1).split(",").reject(&:empty?)
    expected_family = ARGV.fetch(2)
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    abort("expected #{expected_names.length} node(s), got #{nodes.length}") unless nodes.length == expected_names.length
    matched = expected_names.map do |expected_name|
      node = nodes.find do |candidate|
        [
          candidate["givenName"],
          candidate["given_name"],
          candidate["name"],
          candidate["hostname"],
        ].compact.map(&:to_s).include?(expected_name)
      end
      abort("expected node #{expected_name.inspect}, got #{nodes.inspect}") unless node
      addresses = Array(node["ipAddresses"] || node["ip_addresses"] || node["addresses"])
      has_v4 = addresses.any? { |ip| ip.to_s.include?(".") }
      has_v6 = addresses.any? { |ip| ip.to_s.include?(":") }
      case expected_family
      when "ipv4-only"
        abort("expected IPv4-only node addresses for #{expected_name}, got #{addresses.inspect}") unless has_v4 && !has_v6
      when "ipv6-only"
        abort("expected IPv6-only node addresses for #{expected_name}, got #{addresses.inspect}") unless !has_v4 && has_v6
      when "dual-stack"
        abort("expected dual-stack node addresses for #{expected_name}, got #{addresses.inspect}") unless has_v4 && has_v6
      else
        abort("unsupported expected family #{expected_family.inspect}")
      end
      node
    end
    puts JSON.pretty_generate({"expected_family" => expected_family, "nodes" => matched})
  ' "${nodes_path}" "${expected_names}" "${expected_family}"

  local db_rows
  case "${database_backend}" in
    sqlite)
      db_rows="$(sqlite3 -separator $'\t' "${db_path}" "SELECT COALESCE(NULLIF(ipv4,''),'<empty>'), COALESCE(NULLIF(ipv6,''),'<empty>') FROM nodes WHERE deleted_at IS NULL ORDER BY id;")"
      ;;
    postgres)
      db_rows="$(psql "${postgres_runtime_url}" -v ON_ERROR_STOP=1 -At -F $'\t' -c "SELECT COALESCE(NULLIF(ipv4,''),'<empty>'), COALESCE(NULLIF(ipv6,''),'<empty>') FROM nodes WHERE deleted_at IS NULL ORDER BY id;")"
      ;;
  esac
  local expected_count=1
  [[ "${edge}" == "magicdns-peer-restart" ]] && expected_count=2
  local db_ipv4 db_ipv6
  local db_row_count=0
  while IFS=$'\t' read -r db_ipv4 db_ipv6; do
    [[ -n "${db_ipv4}${db_ipv6}" ]] || continue
    db_row_count=$((db_row_count + 1))
    case "${expected_family}" in
      ipv4-only)
        [[ "${db_ipv4}" == 100.* ]] || { echo "expected DB IPv4 after backfill, got ${db_ipv4}" >&2; exit 1; }
        [[ "${db_ipv6}" == "<empty>" ]] || { echo "expected empty DB IPv6 after backfill, got ${db_ipv6}" >&2; exit 1; }
        ;;
      ipv6-only)
        [[ "${db_ipv4}" == "<empty>" ]] || { echo "expected empty DB IPv4 after backfill, got ${db_ipv4}" >&2; exit 1; }
        [[ "${db_ipv6}" == fd7a:115c:a1e0* ]] || { echo "expected DB IPv6 after backfill, got ${db_ipv6}" >&2; exit 1; }
        ;;
      dual-stack)
        [[ "${db_ipv4}" == 100.* ]] || { echo "expected DB IPv4 after backfill, got ${db_ipv4}" >&2; exit 1; }
        [[ "${db_ipv6}" == fd7a:115c:a1e0* ]] || { echo "expected DB IPv6 after backfill, got ${db_ipv6}" >&2; exit 1; }
        ;;
    esac
  done <<<"${db_rows}"
  [[ "${db_row_count}" -eq "${expected_count}" ]] || { echo "expected ${expected_count} DB node rows, got ${db_row_count}" >&2; exit 1; }
  echo "::endgroup::"
}

need ruby
if [[ "${database_backend}" == "postgres" ]]; then
  real_client_prepare_postgres_database \
    "Postgres prefix-family ${migration_case} backfill real-client smoke" \
    "headscale_rs_pg_prefix_family_${migration_case//[^a-zA-Z0-9]/_}_${target//[^a-zA-Z0-9]/_}"
else
  need sqlite3
fi
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
start_server "${initial_family}"
create_user_and_key
start_clients
login_clients_initial_family
approve_route_edge_if_requested

echo "::group::restart ${target} server from ${initial_family} to ${final_family}"
stop_server
start_server "${final_family}"
echo "::endgroup::"

run_backfill
wait_for_all_clients_family "${final_family}" "${final_family} client netmap after backfill"
assert_node_state_family "${final_family}" "after-backfill"
assert_route_edge_if_requested "approved route after backfill"
assert_magicdns_edge_if_requested "after-backfill"

echo "::group::restart ${target} server after ${backfill_label} backfill"
stop_server
start_server "${final_family}"
echo "::endgroup::"

wait_for_all_clients_family "${final_family}" "${final_family} client netmap after post-backfill restart"
assert_node_state_family "${final_family}" "after-backfill-restart"
assert_route_edge_if_requested "approved route after post-backfill restart"
assert_magicdns_edge_if_requested "after-backfill-restart"

echo "${target} prefix-family ${migration_case} backfill real-client smoke passed"
