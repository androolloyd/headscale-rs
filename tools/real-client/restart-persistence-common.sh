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
route_via_restart="${REAL_CLIENT_RESTART_ROUTE_VIA:-false}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/restart-persistence-${target}}"
run_id="hs-restart-${target}-$(date +%s)-$$"
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
if ((route_via_restart_flag)); then
  router_name="${REAL_CLIENT_ROUTER_NAME:-${run_id}-router-a}"
  observer_name="${REAL_CLIENT_OBSERVER_NAME:-${run_id}-alice}"
else
  router_name="${REAL_CLIENT_ROUTER_NAME:-${run_id}-router}"
  observer_name="${REAL_CLIENT_OBSERVER_NAME:-${run_id}-observer}"
fi
router_b_name="${REAL_CLIENT_ROUTER_B_NAME:-${run_id}-router-b}"
bob_name="${REAL_CLIENT_BOB_NAME:-${run_id}-bob}"
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

cleanup() {
  docker rm -f "${router_name}" "${router_b_name}" "${observer_name}" "${bob_name}" >/dev/null 2>&1 || true
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
  for client_name in "${router_name}" "${router_b_name}" "${observer_name}" "${bob_name}"; do
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
  if ((route_via_restart_flag)); then
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
    match = url.match(%r{/register/([^/?#]+)(?:\z|[?#])})
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
    "--advertise-routes=${route}" \
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
  headscale_cmd -o json nodes register --user "${user}" --key "${registration_id}" \
    >"${work_dir}/${client_name}.registered.json"

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
  headscale_cmd -o json nodes approve-routes --identifier "${router_id}" --routes "${route}" \
    >"${work_dir}/approved-routes-${router_id}.json"
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
    route = ARGV.fetch(1)
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

    def assert_router(node, route, tag)
      available = Array(node["availableRoutes"] || node["available_routes"]).map(&:to_s).sort
      approved = Array(node["approvedRoutes"] || node["approved_routes"]).map(&:to_s).sort
      tags = Array(node["tags"] || node["Tags"]).map(&:to_s).sort
      abort("expected router available route #{route.inspect}, got #{available.inspect}") unless available.include?(route)
      abort("expected router approved route #{route.inspect}, got #{approved.inspect}") unless approved.include?(route)
      abort("expected router tag #{tag.inspect}, got #{tags.inspect}") unless tags.include?(tag)
    end

    router_a = find_node(nodes, router_a_name)
    router_b = find_node(nodes, router_b_name)
    alice = find_node(nodes, alice_name)
    bob = find_node(nodes, bob_name)
    assert_router(router_a, route, "tag:router-a")
    assert_router(router_b, route, "tag:router-b")

    puts JSON.pretty_generate({
      router_a: router_a,
      router_b: router_b,
      alice: alice,
      bob: bob,
      route: route,
    })
  ' "${nodes_path}" "${route}" "${router_name}" "${router_b_name}" "${observer_name}" "${bob_name}"
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

wait_for_route_via_peer_maps() {
  local label="$1"
  local safe_label="${label//[^a-zA-Z0-9_-]/-}"
  wait_for "${label} alice route via router-a" \
    "peer_netmap_route_owner_matches '${observer_name}' '${router_name}' '${route}' '${work_dir}/route-via-${safe_label}-alice.json'" || {
      cat "${work_dir}/route-via-${safe_label}-alice.json.err" >&2 || true
      dump_debug
      return 1
    }
  wait_for "${label} bob route via router-b" \
    "peer_netmap_route_owner_matches '${bob_name}' '${router_b_name}' '${route}' '${work_dir}/route-via-${safe_label}-bob.json'" || {
      cat "${work_dir}/route-via-${safe_label}-bob.json.err" >&2 || true
      dump_debug
      return 1
    }
  cat "${work_dir}/route-via-${safe_label}-alice.json"
  cat "${work_dir}/route-via-${safe_label}-bob.json"
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

if ((route_via_restart_flag)); then
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

  stop_server
  start_server
  wait_for "router-a reconnected after restart" "tailscale_logged_in '${router_name}'"
  wait_for "router-b reconnected after restart" "tailscale_logged_in '${router_b_name}'"
  wait_for "alice reconnected after restart" "tailscale_logged_in '${observer_name}'"
  wait_for "bob reconnected after restart" "tailscale_logged_in '${bob_name}'"
  assert_route_via_persisted_nodes "after-restart"
  wait_for_route_via_peer_maps "after restart"
else
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
fi

echo "${target} restart persistence real-client smoke passed"
