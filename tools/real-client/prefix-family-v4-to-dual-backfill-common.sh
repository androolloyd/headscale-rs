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
headscale_go_version="${HEADSCALE_GO_VERSION:-v0.28.0}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-180}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/prefix-family-${migration_case}-backfill-${target}}"
run_id="hspf-${migration_case}-${target}-$(date +%s)-$$"
client_name="${REAL_CLIENT_CLIENT_NAME:-${run_id}-client}"
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

cleanup() {
  docker rm -f "${client_name}" >/dev/null 2>&1 || true
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
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
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for ${label}" >&2
      return 1
    fi
    sleep 1
  done
}

dump_client_debug() {
  docker exec "${client_name}" tailscale status 2>&1 || true
  docker exec "${client_name}" sh -c 'tail -180 /tmp/tailscaled.log 2>/dev/null || true' >&2
}

install_or_build_headscale() {
  case "${target}" in
    rust)
      echo "::group::build headscale-rs CLI"
      cargo build --quiet -p headscale-cli --bin headscale
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
      cat >>"${config_path}" <<EOF
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
EOF
      if [[ "${family}" != "ipv6-only" ]]; then
        printf '  v4: 100.64.0.0/10\n' >>"${config_path}"
      fi
      if [[ "${family}" != "ipv4-only" ]]; then
        printf '  v6: fd7a:115c:a1e0::/48\n' >>"${config_path}"
      fi
      cat >>"${config_path}" <<EOF

database:
  type: sqlite
  sqlite:
    path: ${db_path}

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
}

headscale_cmd() {
  case "${target}" in
    rust) "${headscale_bin}" --config "${config_path}" "$@" ;;
    headscale-go) "${headscale_bin}" -c "${config_path}" "$@" ;;
  esac
}

start_server() {
  local family="$1"
  write_config "${family}"
  rm -f "${socket_path}"
  echo "::group::start ${target} server (${family})"
  case "${target}" in
    rust)
      mkdir -p "${work_dir}/state"
      "${headscale_bin}" --config "${config_path}" server \
        >"${work_dir}/${target}-${family}.stdout" \
        2>"${work_dir}/${target}-${family}.stderr" &
      ;;
    headscale-go)
      "${headscale_bin}" -c "${config_path}" serve \
        >"${work_dir}/${target}-${family}.stdout" \
        2>"${work_dir}/${target}-${family}.stderr" &
      ;;
  esac
  server_pid="$!"
  wait_for "${target} health (${family})" "curl ${health_curl_opts} '${local_control_url}/health' >/dev/null"
  if [[ "${target}" == "rust" ]]; then
    wait_for "${target} TLS certificate (${family})" "test -s '${tls_cert_path}'"
  fi
  wait_for "${target} gRPC (${family})" "headscale_cmd health >/dev/null 2>&1"
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
      headscale_cmd -o json preauthkeys create --user alice --reusable --expires-in 1h >"${work_dir}/preauth.json"
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

start_client() {
  echo "::group::start stock tailscale client"
  docker_args=(
    docker run -d
    --name "${client_name}" \
    --hostname "${client_name}" \
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
    "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
  echo "::endgroup::"
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

wait_for_client_family() {
  local expected="$1"
  local label="$2"
  local path="${work_dir}/${client_name}.${expected}.status.json"
  wait_for "${label}" "docker exec '${client_name}' tailscale status --json >'${path}' 2>/dev/null && assert_status_family_file '${path}' '${expected}'" || {
    dump_client_debug
    return 1
  }
  ruby -rjson -e '
    status = JSON.parse(File.read(ARGV.fetch(0)))
    puts JSON.pretty_generate({host: status.dig("Self", "HostName"), tailscale_ips: status.fetch("TailscaleIPs")})
  ' "${path}"
}

login_client_initial_family() {
  echo "::group::tailscale up against ${initial_family} config"
  up_status=0
  docker exec "${client_name}" tailscale up \
    "--login-server=${control_url}" \
    "--hostname=${client_name}" \
    --timeout=60s \
    --accept-routes=false \
    --accept-dns=false \
    "--authkey=${authkey}" \
    >"${work_dir}/${client_name}.tailscale-up.stdout" \
    2>"${work_dir}/${client_name}.tailscale-up.stderr" ||
    up_status="$?"
  if ((up_status != 0)); then
    echo "tailscale up returned ${up_status}; verifying logged-in netmap"
  fi
  wait_for_client_family "${initial_family}" "${initial_family} client netmap"
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
  echo "::group::assert ${target} node state after backfill"
  headscale_cmd -o json nodes list >"${work_dir}/nodes-after-backfill.json"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    expected_family = ARGV.fetch(2)
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    abort("expected one node, got #{nodes.length}") unless nodes.length == 1
    node = nodes.fetch(0)
    name = node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
    addresses = Array(node["ipAddresses"] || node["ip_addresses"] || node["addresses"])
    has_v4 = addresses.any? { |ip| ip.to_s.include?(".") }
    has_v6 = addresses.any? { |ip| ip.to_s.include?(":") }
    abort("expected #{ARGV.fetch(1)}, got #{name.inspect}") unless name.to_s == ARGV.fetch(1)
    case expected_family
    when "ipv4-only"
      abort("expected IPv4-only node addresses, got #{addresses.inspect}") unless has_v4 && !has_v6
    when "ipv6-only"
      abort("expected IPv6-only node addresses, got #{addresses.inspect}") unless !has_v4 && has_v6
    when "dual-stack"
      abort("expected dual-stack node addresses, got #{addresses.inspect}") unless has_v4 && has_v6
    else
      abort("unsupported expected family #{expected_family.inspect}")
    end
    puts JSON.pretty_generate(node)
  ' "${work_dir}/nodes-after-backfill.json" "${client_name}" "${expected_family}"

  local db_row
  db_row="$(sqlite3 -separator $'\t' "${db_path}" "SELECT COALESCE(NULLIF(ipv4,''),'<empty>'), COALESCE(NULLIF(ipv6,''),'<empty>') FROM nodes WHERE deleted_at IS NULL LIMIT 1;")"
  local db_ipv4 db_ipv6
  IFS=$'\t' read -r db_ipv4 db_ipv6 <<<"${db_row}"
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
  echo "::endgroup::"
}

need curl
need docker
need ruby
need sqlite3
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
start_client
login_client_initial_family

echo "::group::restart ${target} server from ${initial_family} to ${final_family}"
stop_server
start_server "${final_family}"
echo "::endgroup::"

run_backfill
wait_for_client_family "${final_family}" "${final_family} client netmap after backfill"
assert_node_state_family "${final_family}"

echo "${target} prefix-family ${migration_case} backfill real-client smoke passed"
