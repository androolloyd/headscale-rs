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
route="${REAL_CLIENT_RESTART_ROUTE:-10.88.0.0/24}"
initial_tag="${REAL_CLIENT_RESTART_INITIAL_TAG:-tag:server}"
mutated_tag="${REAL_CLIENT_RESTART_MUTATED_TAG:-tag:db}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/restart-persistence-${target}}"
run_id="hs-restart-${target}-$(date +%s)-$$"
router_name="${REAL_CLIENT_ROUTER_NAME:-${run_id}-router}"
observer_name="${REAL_CLIENT_OBSERVER_NAME:-${run_id}-observer}"
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

cleanup() {
  docker rm -f "${router_name}" "${observer_name}" >/dev/null 2>&1 || true
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
  for client_name in "${router_name}" "${observer_name}"; do
    docker exec "${client_name}" tailscale status 2>&1 || true
    docker exec "${client_name}" sh -c 'tail -180 /tmp/tailscaled.log 2>/dev/null || true' >&2 || true
  done
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

write_policy() {
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

write_config() {
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

prefixes:
  allocation: sequential
  v4: 100.64.0.0/10

dns:
  magic_dns: false
  base_domain: "${base_domain}"

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

policy:
  mode: file
  path: ${work_dir}/policy.hujson
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
  wait_for "${target} gRPC" "headscale_cmd health >/dev/null 2>&1"
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
    match = url.match(%r{/register/([A-Za-z0-9_-]{24})(?:\z|[?#])})
    exit 1 unless match
    File.write(ARGV.fetch(0), match[1])
  ' "${output_path}" <<<"${status_json}"
}

login_router_with_authkey() {
  echo "::group::tailscale up auth-key router"
  up_status=0
  docker exec "${router_name}" tailscale up \
    "--login-server=${control_url}" \
    "--hostname=${router_name}" \
    --timeout=60s \
    --accept-routes=false \
    --accept-dns=false \
    "--advertise-routes=${route}" \
    "--authkey=${authkey}" \
    >"${work_dir}/${router_name}.tailscale-up.stdout" \
    2>"${work_dir}/${router_name}.tailscale-up.stderr" ||
    up_status="$?"
  if ((up_status != 0)); then
    echo "tailscale up ${router_name} returned ${up_status}; verifying logged-in netmap"
  fi
  wait_for "logged-in router netmap" "tailscale_logged_in '${router_name}'" || {
    dump_debug
    return 1
  }
  echo "::endgroup::"
}

login_observer_with_web_registration() {
  echo "::group::tailscale up web observer"
  docker exec "${observer_name}" tailscale up \
    "--login-server=${control_url}" \
    "--hostname=${observer_name}" \
    --timeout=60s \
    --accept-routes=true \
    --accept-dns=false \
    >"${work_dir}/${observer_name}.tailscale-up.stdout" \
    2>"${work_dir}/${observer_name}.tailscale-up.stderr" &
  local up_pid="$!"

  local registration_id_path="${work_dir}/${observer_name}.registration-id"
  if ! wait_for "web registration URL ${observer_name}" \
    "write_registration_id '${observer_name}' '${registration_id_path}'"; then
    dump_debug
    return 1
  fi
  local registration_id
  registration_id="$(cat "${registration_id_path}")"
  headscale_cmd -o json nodes register --user alice --key "${registration_id}" \
    >"${work_dir}/${observer_name}.registered.json"

  if ! wait_pid_with_timeout "tailscale up ${observer_name}" "${up_pid}"; then
    echo "tailscale up ${observer_name} returned non-zero; verifying logged-in netmap"
  fi
  wait_for "logged-in observer netmap" "tailscale_logged_in '${observer_name}'" || {
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

load_router_id() {
  headscale_cmd -o json nodes list >"${work_dir}/nodes-for-router-id.json"
  node_id_for_host "${work_dir}/nodes-for-router-id.json" "${router_name}"
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

need curl
need docker
need ruby
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
create_user_and_key
start_client "${router_name}"
start_client "${observer_name}"
login_router_with_authkey
set_router_routes_and_tag "${initial_tag}"
login_observer_with_web_registration
assert_persisted_nodes "${initial_tag}" "before-restart"

stop_server
start_server
wait_for "router reconnected after restart" "tailscale_logged_in '${router_name}'"
wait_for "observer reconnected after restart" "tailscale_logged_in '${observer_name}'"
assert_persisted_nodes "${initial_tag}" "after-restart"
wait_for_peer_map "${initial_tag}" "observer sees restarted route and tag"

set_router_routes_and_tag "${mutated_tag}"
assert_persisted_nodes "${mutated_tag}" "after-post-restart-tag-mutation"
wait_for_peer_map "${mutated_tag}" "observer sees post-restart tag mutation"

echo "${target} restart persistence real-client smoke passed"
