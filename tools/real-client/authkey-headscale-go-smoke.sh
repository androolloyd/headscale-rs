#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
headscale_go_version="${HEADSCALE_GO_VERSION:-v0.28.0}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/authkey-headscale-go-smoke}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-120}"
client_count="${REAL_CLIENT_CLIENT_COUNT:-1}"
login_mode="${REAL_CLIENT_LOGIN_MODE:-authkey}"
expected_register_failure="${REAL_CLIENT_EXPECT_REGISTER_FAILURE:-false}"
advertise_routes="${REAL_CLIENT_ADVERTISE_ROUTES:-}"
advertise_exit_node="${REAL_CLIENT_ADVERTISE_EXIT_NODE:-false}"
expected_available_routes="${REAL_CLIENT_EXPECT_AVAILABLE_ROUTES:-${advertise_routes}}"
approve_routes="${REAL_CLIENT_APPROVE_ROUTES:-}"
expected_approved_routes="${REAL_CLIENT_EXPECT_APPROVED_ROUTES:-${approve_routes}}"
expected_machine_count="${REAL_CLIENT_EXPECT_MACHINE_COUNT:-${client_count}}"
expected_primary_route="${REAL_CLIENT_EXPECT_PRIMARY_ROUTE:-}"
expected_primary_failover_route="${REAL_CLIENT_EXPECT_PRIMARY_FAILOVER_ROUTE:-}"
expected_primary_withdraw_route="${REAL_CLIENT_EXPECT_PRIMARY_WITHDRAW_ROUTE:-}"
preauth_tags="${REAL_CLIENT_PREAUTH_TAGS:-}"
expected_tags="${REAL_CLIENT_EXPECT_TAGS:-${preauth_tags}}"
policy_json="${REAL_CLIENT_POLICY_JSON:-}"
expected_magic_dns_suffix="${REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX:-}"
expected_peer_count="${REAL_CLIENT_EXPECT_PEER_COUNT:-}"
expected_peer_counts="${REAL_CLIENT_EXPECT_PEER_COUNTS:-}"
case "${login_mode}" in
  authkey | web) ;;
  *)
    echo "REAL_CLIENT_LOGIN_MODE must be authkey or web, got ${login_mode}" >&2
    exit 2
    ;;
esac
case "${expected_register_failure}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    expect_register_failure=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    expect_register_failure=0
    ;;
  *)
    echo "REAL_CLIENT_EXPECT_REGISTER_FAILURE must be true or false, got ${expected_register_failure}" >&2
    exit 2
    ;;
esac
if ((expect_register_failure)) && [[ "${login_mode}" != "web" ]]; then
  echo "REAL_CLIENT_EXPECT_REGISTER_FAILURE is only supported with REAL_CLIENT_LOGIN_MODE=web" >&2
  exit 2
fi
up_timeout="${REAL_CLIENT_TAILSCALE_UP_TIMEOUT:-}"
if [[ -z "${up_timeout}" ]]; then
  if [[ "${login_mode}" == "web" ]]; then
    up_timeout="45s"
  else
    up_timeout="15s"
  fi
fi
run_id="hsgo-${login_mode}-$(date +%s)-$$"
case "${work_root}" in
  /*) work_dir="${work_root}/${run_id}" ;;
  *) work_dir="${repo_root}/${work_root}/${run_id}" ;;
esac
mkdir -p "${work_dir}/bin"

if ! [[ "${client_count}" =~ ^[0-9]+$ ]] || ((client_count < 1)); then
  echo "REAL_CLIENT_CLIENT_COUNT must be a positive integer, got ${client_count}" >&2
  exit 2
fi

if [[ -n "${expected_peer_count}" ]] && ! [[ "${expected_peer_count}" =~ ^[0-9]+$ ]]; then
  echo "REAL_CLIENT_EXPECT_PEER_COUNT must be a non-negative integer, got ${expected_peer_count}" >&2
  exit 2
fi

expected_peer_counts_values=()
if [[ -n "${expected_peer_counts}" ]]; then
  IFS=',' read -r -a expected_peer_counts_values <<<"${expected_peer_counts}"
  if ((${#expected_peer_counts_values[@]} != client_count)); then
    echo "REAL_CLIENT_EXPECT_PEER_COUNTS must contain ${client_count} comma-separated counts, got ${expected_peer_counts}" >&2
    exit 2
  fi
  for count in "${expected_peer_counts_values[@]}"; do
    if ! [[ "${count}" =~ ^[0-9]+$ ]]; then
      echo "REAL_CLIENT_EXPECT_PEER_COUNTS must contain non-negative integers, got ${expected_peer_counts}" >&2
      exit 2
    fi
  done
fi

if [[ -n "${preauth_tags}" && -z "${policy_json}" ]]; then
  policy_json="$(
    ruby -rjson -e '
      tags = ARGV.fetch(0).split(",").reject(&:empty?).sort.uniq
      owners = tags.to_h { |tag| [tag, ["alice@"]] }
      puts JSON.pretty_generate({
        tagOwners: owners,
        acls: [{action: "accept", src: ["*"], dst: ["*:*"]}],
      })
    ' "${preauth_tags}"
  )"
fi

http_port=""
grpc_port=""
metrics_port=""
server_pid=""
client_names=()
for ((idx = 1; idx <= client_count; idx++)); do
  if ((client_count == 1)); then
    client_names+=("${run_id}-client")
  else
    client_names+=("${run_id}-client-${idx}")
  fi
done
config_path="${work_dir}/config.yaml"
headscale_bin="${HEADSCALE_GO_BIN:-${work_dir}/bin/headscale}"
socket_path="/tmp/${run_id}.sock"

cleanup() {
  for client_name in "${client_names[@]}"; do
    docker rm -f "${client_name}" >/dev/null 2>&1 || true
  done
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

tailscale_peer_count_matches() {
  local client_name="$1"
  local count="$2"
  local status_json
  status_json="$(docker exec "${client_name}" tailscale status --json 2>/dev/null || true)"
  ruby -rjson -e '
    status = JSON.parse(STDIN.read)
    peers = status["Peer"] || {}
    exit(peers.length == Integer(ARGV.fetch(0)) ? 0 : 1)
  ' "${count}" <<<"${status_json}"
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

dump_client_debug() {
  local client_name="$1"
  docker exec "${client_name}" tailscale status 2>&1 || true
  docker exec "${client_name}" sh -c 'tail -160 /tmp/tailscaled.log 2>/dev/null || true' >&2
}

need curl
need docker
need go
need ruby

http_port="$(free_port)"
grpc_port="$(free_port)"
metrics_port="$(free_port)"

echo "::group::build headscale-go ${headscale_go_version}"
if [[ -z "${HEADSCALE_GO_BIN:-}" ]]; then
  GOBIN="${work_dir}/bin" go install "github.com/juanfont/headscale/cmd/headscale@${headscale_go_version}"
fi
"${headscale_bin}" version >"${work_dir}/headscale-version.txt"
cat "${work_dir}/headscale-version.txt"
echo "::endgroup::"

cat >"${config_path}" <<EOF
server_url: http://host.docker.internal:${http_port}
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
  v4: 100.64.0.0/10
  v6: fd7a:115c:a1e0::/48
  allocation: sequential

database:
  type: sqlite
  sqlite:
    path: ${work_dir}/db.sqlite

dns:
  magic_dns: true
  base_domain: tail.test
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
EOF

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

cat >>"${config_path}" <<EOF
derp:
  server:
    enabled: false
  urls: []
  paths:
    - ${work_dir}/derp.yaml
  auto_update_enabled: false
EOF

if [[ -n "${policy_json}" ]]; then
  printf '%s\n' "${policy_json}" >"${work_dir}/policy.hujson"
  cat >>"${config_path}" <<EOF
policy:
  mode: file
  path: ${work_dir}/policy.hujson
EOF
fi

echo "::group::start headscale-go"
"${headscale_bin}" -c "${config_path}" serve \
  >"${work_dir}/headscale.stdout" \
  2>"${work_dir}/headscale.stderr" &
server_pid="$!"

wait_for "headscale-go health" \
  "curl -fsS 'http://127.0.0.1:${http_port}/health' >/dev/null"
wait_for "headscale-go gRPC" \
  "'${headscale_bin}' -c '${config_path}' health >/dev/null 2>&1"
echo "headscale-go http=http://127.0.0.1:${http_port}"
echo "headscale-go login=http://host.docker.internal:${http_port}"
echo "::endgroup::"

echo "::group::create user"
"${headscale_bin}" -c "${config_path}" -o json users create alice >"${work_dir}/user.json"
user_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("id")' "${work_dir}/user.json")"
echo "created user ${user_id}"
echo "::endgroup::"

authkey=""
if [[ "${login_mode}" == "authkey" ]]; then
  echo "::group::mint preauth key"
  preauth_args=(
    "${headscale_bin}" -c "${config_path}" -o json preauthkeys create
    --user "${user_id}" \
    --reusable \
    --expiration 1h
  )
  if [[ -n "${preauth_tags}" ]]; then
    preauth_args+=(--tags "${preauth_tags}")
  fi
  "${preauth_args[@]}" >"${work_dir}/preauth.json"
  authkey="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("key")' "${work_dir}/preauth.json")"
  echo "minted ${authkey%%-*}-..."
  echo "::endgroup::"
fi

echo "::group::start stock tailscale client"
for client_name in "${client_names[@]}"; do
  docker run -d \
    --name "${client_name}" \
    --hostname "${client_name}" \
    --add-host host.docker.internal:host-gateway \
    --entrypoint /bin/sh \
    "${image}" \
    -ceu 'tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity' \
    >/dev/null

  wait_for "tailscaled local socket ${client_name}" \
    "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
done
echo "::endgroup::"

echo "::group::tailscale up"
for client_name in "${client_names[@]}"; do
  up_args=(
    tailscale up
    "--login-server=http://host.docker.internal:${http_port}"
    "--hostname=${client_name}"
    "--timeout=${up_timeout}"
    --accept-routes=false
    --accept-dns=false
  )
  if [[ "${login_mode}" == "authkey" ]]; then
    up_args+=("--authkey=${authkey}")
  fi
  if [[ -n "${advertise_routes}" ]]; then
    up_args+=("--advertise-routes=${advertise_routes}")
  fi
  if [[ "${login_mode}" == "web" && -n "${preauth_tags}" ]]; then
    up_args+=("--advertise-tags=${preauth_tags}")
  fi
  case "${advertise_exit_node}" in
    1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
      up_args+=(--advertise-exit-node)
      ;;
  esac
  up_status=0
  if [[ "${login_mode}" == "web" ]]; then
    docker exec "${client_name}" "${up_args[@]}" \
      >"${work_dir}/${client_name}.tailscale-up.stdout" \
      2>"${work_dir}/${client_name}.tailscale-up.stderr" &
    up_pid="$!"
    registration_id_path="${work_dir}/${client_name}.registration-id"
    if ! wait_for "web registration URL ${client_name}" \
      "write_registration_id '${client_name}' '${registration_id_path}'"; then
      dump_client_debug "${client_name}"
      exit 1
    fi
    registration_id="$(cat "${registration_id_path}")"
    register_status=0
    "${headscale_bin}" -c "${config_path}" -o json nodes register \
      --user alice \
      --key "${registration_id}" \
      >"${work_dir}/${client_name}.registered.json" \
      2>"${work_dir}/${client_name}.registered.err" ||
      register_status="$?"
    if ((expect_register_failure)); then
      if ((register_status == 0)); then
        echo "expected web registration to fail for ${client_name}" >&2
        kill "${up_pid}" >/dev/null 2>&1 || true
        wait "${up_pid}" >/dev/null 2>&1 || true
        exit 1
      fi
      kill "${up_pid}" >/dev/null 2>&1 || true
      wait "${up_pid}" >/dev/null 2>&1 || true
      continue
    fi
    if ((register_status != 0)); then
      cat "${work_dir}/${client_name}.registered.err" >&2 || true
      kill "${up_pid}" >/dev/null 2>&1 || true
      wait "${up_pid}" >/dev/null 2>&1 || true
      exit "${register_status}"
    fi
    wait_pid_with_timeout "tailscale up ${client_name}" "${up_pid}" ||
      up_status="$?"
  else
    run_with_timeout "tailscale up ${client_name}" docker exec "${client_name}" "${up_args[@]}" ||
      up_status="$?"
  fi
  if ((up_status != 0)); then
    echo "tailscale up ${client_name} returned ${up_status}; verifying logged-in netmap"
  fi

  if ! wait_for "tailscale logged-in netmap ${client_name}" "tailscale_logged_in '${client_name}'"; then
    dump_client_debug "${client_name}"
    exit 1
  fi
  docker exec "${client_name}" tailscale status --json >"${work_dir}/${client_name}.tailscale-status.json"
done
echo "::endgroup::"

if ((expect_register_failure)); then
  echo "::group::assert rejected headscale-go web registration"
  "${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes.json"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    nodes = payload.nil? ? [] : (payload.is_a?(Array) ? payload : payload.fetch("nodes"))
    expected_count = Integer(ARGV.fetch(1))
    abort("expected #{expected_count} registered nodes after rejected registration, got #{nodes.length}") unless nodes.length == expected_count
    puts JSON.pretty_generate({nodes: nodes.length})
  ' "${work_dir}/nodes.json" "${expected_machine_count}"
  echo "::endgroup::"
  echo "headscale-go ${login_mode} rejected-registration real-client smoke passed"
  exit 0
fi

if [[ -n "${approve_routes}" ]]; then
  echo "::group::approve routes"
  "${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes-before-approve.json"
  node_id="$(
    ruby -rjson -e '
      payload = JSON.parse(File.read(ARGV.fetch(0)))
      nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
      expected = Integer(ARGV.fetch(1))
      abort("expected #{expected} registered nodes, got #{nodes.length}") unless nodes.length == expected
      puts nodes.map { |node| node.fetch("id") }
    ' "${work_dir}/nodes-before-approve.json" "${expected_machine_count}"
  )"
  while IFS= read -r node_id; do
    "${headscale_bin}" -c "${config_path}" -o json nodes approve-routes \
      --identifier "${node_id}" \
      --routes "${approve_routes}" \
      >"${work_dir}/approved-routes-${node_id}.json"
  done <<<"${node_id}"
  echo "::endgroup::"
fi

echo "::group::assert headscale-go node state"
"${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes.json"
ruby -rjson -e '
  expected_routes = ARGV.fetch(1).split(",").reject(&:empty?).sort
  expected_approved = ARGV.fetch(2).split(",").reject(&:empty?).sort
  expected_count = Integer(ARGV.fetch(3))
  expected_primary_route = ARGV.fetch(4)
  expected_tags = ARGV.fetch(5).split(",").reject(&:empty?).sort
  expected_hostname_prefix = ARGV.fetch(6)
  payload = JSON.parse(File.read(ARGV.fetch(0)))
  nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
  abort("expected #{expected_count} registered nodes, got #{nodes.length}") unless nodes.length == expected_count
  nodes.each do |node|
    user = node["user"] || node["User"]
    user_name = user.is_a?(Hash) ? (user["name"] || user["loginName"] || user["login_name"]) : user.to_s
    given_name = node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
    addresses = Array(node["ipAddresses"] || node["ip_addresses"] || node["addresses"])
    available_routes = Array(node["availableRoutes"] || node["available_routes"]).sort
    approved_routes = Array(node["approvedRoutes"] || node["approved_routes"]).sort
    expected_user = expected_tags.empty? ? "alice" : "tagged-devices"
    abort("expected user #{expected_user}, got #{user.inspect}") unless user_name == expected_user
    abort("expected hostname prefix #{expected_hostname_prefix.inspect}, got #{given_name.inspect}") unless given_name.to_s.start_with?(expected_hostname_prefix)
    abort("expected CGNAT IPv4, got #{addresses.inspect}") unless addresses.any? { |ip| ip.to_s.start_with?("100.") }
    unless expected_routes.empty? || available_routes == expected_routes
      abort("expected available routes #{expected_routes.inspect}, got #{available_routes.inspect}")
    end
    unless expected_approved.empty? || approved_routes == expected_approved
      abort("expected approved routes #{expected_approved.inspect}, got #{approved_routes.inspect}")
    end
    tags = Array(node["tags"] || node["Tags"]).sort
    unless expected_tags.empty? || tags == expected_tags
      abort("expected tags #{expected_tags.inspect}, got #{tags.inspect}")
    end
  end

  primary_nodes = []
  unless expected_primary_route.empty?
    primary_nodes = nodes.select do |node|
      Array(node["subnetRoutes"] || node["subnet_routes"]).include?(expected_primary_route)
    end
    abort("expected exactly one primary node for #{expected_primary_route}, got #{primary_nodes.length}") unless primary_nodes.length == 1
  end

  if expected_count == 1
    puts JSON.pretty_generate(nodes.fetch(0))
  else
    puts JSON.pretty_generate({nodes: nodes, primary_nodes: primary_nodes})
  end
' "${work_dir}/nodes.json" "${expected_available_routes}" "${expected_approved_routes}" "${expected_machine_count}" "${expected_primary_route}" "${expected_tags}" "${run_id}"
echo "::endgroup::"

if [[ -n "${expected_magic_dns_suffix}" ]]; then
  echo "::group::assert MagicDNS client status"
  magicdns_status_paths=()
  for client_name in "${client_names[@]}"; do
    status_path="${work_dir}/${client_name}.magicdns-status.json"
    docker exec "${client_name}" tailscale status --json >"${status_path}"
    magicdns_status_paths+=("${status_path}")
  done
  ruby -rjson -e '
    expected_suffix = ARGV.fetch(0).sub(/\.\z/, "")
    status_paths = ARGV.drop(1)
    expected_peers = status_paths.length - 1

    status_paths.each do |path|
      status = JSON.parse(File.read(path))
      self_node = status.fetch("Self")
      suffix = status.fetch("MagicDNSSuffix").to_s.sub(/\.\z/, "")
      abort("#{path}: expected MagicDNSSuffix #{expected_suffix.inspect}, got #{suffix.inspect}") unless suffix == expected_suffix

      self_dns = self_node.fetch("DNSName").to_s.sub(/\.\z/, "")
      expected_self_dns = "#{self_node.fetch("HostName")}.#{expected_suffix}"
      abort("#{path}: expected self DNSName #{expected_self_dns.inspect}, got #{self_dns.inspect}") unless self_dns == expected_self_dns

      peers = status["Peer"] || {}
      abort("#{path}: expected #{expected_peers} peers, got #{peers.length}") unless peers.length == expected_peers
      peers.each_value do |peer|
        peer_dns = peer.fetch("DNSName").to_s.sub(/\.\z/, "")
        expected_peer_dns = "#{peer.fetch("HostName")}.#{expected_suffix}"
        abort("#{path}: expected peer DNSName #{expected_peer_dns.inspect}, got #{peer_dns.inspect}") unless peer_dns == expected_peer_dns
      end
    end
    puts JSON.pretty_generate({magic_dns_suffix: expected_suffix, clients: status_paths.length})
  ' "${expected_magic_dns_suffix}" "${magicdns_status_paths[@]}"
  echo "::endgroup::"
fi

if [[ -n "${expected_peer_count}" || -n "${expected_peer_counts}" ]]; then
  echo "::group::assert client peer visibility"
  peer_status_paths=()
  peer_expected_counts=()
  for idx in "${!client_names[@]}"; do
    client_name="${client_names[$idx]}"
    expected_count="${expected_peer_count}"
    if [[ -n "${expected_peer_counts}" ]]; then
      expected_count="${expected_peer_counts_values[$idx]}"
    fi
    if ! wait_for "tailscale peer count ${expected_count} for ${client_name}" \
      "tailscale_peer_count_matches '${client_name}' '${expected_count}'"; then
      dump_client_debug "${client_name}"
      exit 1
    fi
    status_path="${work_dir}/${client_name}.peer-status.json"
    docker exec "${client_name}" tailscale status --json >"${status_path}" || true
    peer_status_paths+=("${status_path}")
    peer_expected_counts+=("${expected_count}")
  done
  peer_expected_counts_csv="$(IFS=,; echo "${peer_expected_counts[*]}")"
  ruby -rjson -e '
    expected_counts = ARGV.fetch(0).split(",").map { |value| Integer(value) }
    status_paths = ARGV.drop(1)
    status_paths.each_with_index do |path, idx|
      expected_count = expected_counts.fetch(idx)
      status = JSON.parse(File.read(path))
      self_host = status.fetch("Self").fetch("HostName")
      peers = status["Peer"] || {}
      abort("#{path}: expected #{expected_count} peers, got #{peers.length}") unless peers.length == expected_count
      peer_hosts = peers.each_value.map { |peer| peer.fetch("HostName") }.sort
      puts JSON.pretty_generate({self: self_host, peer_count: peers.length, peers: peer_hosts})
    end
  ' "${peer_expected_counts_csv}" "${peer_status_paths[@]}"
  echo "::endgroup::"
fi

if [[ -n "${expected_primary_failover_route}" ]]; then
  echo "::group::assert primary route failover"
  cp "${work_dir}/nodes.json" "${work_dir}/nodes-before-failover.json"
  failover_node_id="$(
    ruby -rjson -e '
      route = ARGV.fetch(1)
      payload = JSON.parse(File.read(ARGV.fetch(0)))
      nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
      primary_nodes = nodes.select do |node|
        Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route)
      end
      abort("expected exactly one primary node before failover, got #{primary_nodes.length}") unless primary_nodes.length == 1
      puts primary_nodes.fetch(0).fetch("id")
    ' "${work_dir}/nodes-before-failover.json" "${expected_primary_failover_route}"
  )"
  "${headscale_bin}" -c "${config_path}" -o json nodes approve-routes \
    --identifier "${failover_node_id}" \
    --routes "" \
    >"${work_dir}/failover-clear-primary.json"
  "${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes-after-failover.json"
  ruby -rjson -e '
    route = ARGV.fetch(2)
    cleared_node_id = Integer(ARGV.fetch(3))
    expected_count = Integer(ARGV.fetch(4))

    before_payload = JSON.parse(File.read(ARGV.fetch(0)))
    before_nodes = before_payload.is_a?(Array) ? before_payload : before_payload.fetch("nodes")
    after_payload = JSON.parse(File.read(ARGV.fetch(1)))
    after_nodes = after_payload.is_a?(Array) ? after_payload : after_payload.fetch("nodes")
    abort("expected #{expected_count} nodes before failover, got #{before_nodes.length}") unless before_nodes.length == expected_count
    abort("expected #{expected_count} nodes after failover, got #{after_nodes.length}") unless after_nodes.length == expected_count

    before_primary = before_nodes.select do |node|
      Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route)
    end
    after_primary = after_nodes.select do |node|
      Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route)
    end
    abort("expected exactly one primary node before failover, got #{before_primary.length}") unless before_primary.length == 1
    abort("expected exactly one primary node after failover, got #{after_primary.length}") unless after_primary.length == 1
    before_owner = Integer(before_primary.fetch(0).fetch("id"))
    after_owner = Integer(after_primary.fetch(0).fetch("id"))
    abort("cleared node #{cleared_node_id} was not the initial primary #{before_owner}") unless before_owner == cleared_node_id
    abort("expected primary owner to change, still #{after_owner}") if after_owner == before_owner

    cleared = after_nodes.find { |node| Integer(node.fetch("id")) == cleared_node_id }
    abort("missing cleared node #{cleared_node_id}") unless cleared
    abort("cleared node still has approved route #{route}") if Array(cleared["approvedRoutes"] || cleared["approved_routes"]).include?(route)

    remaining_ids = after_nodes
      .reject { |node| Integer(node.fetch("id")) == cleared_node_id }
      .select { |node| Array(node["approvedRoutes"] || node["approved_routes"]).include?(route) }
      .map { |node| Integer(node.fetch("id")) }
    abort("new primary owner #{after_owner} not among remaining approved routers #{remaining_ids.inspect}") unless remaining_ids.include?(after_owner)

    puts JSON.pretty_generate({
      cleared_node_id: cleared_node_id,
      before_owner: before_owner,
      after_owner: after_owner,
      nodes: after_nodes,
    })
  ' "${work_dir}/nodes-before-failover.json" "${work_dir}/nodes-after-failover.json" "${expected_primary_failover_route}" "${failover_node_id}" "${expected_machine_count}"
  echo "::endgroup::"
fi

if [[ -n "${expected_primary_withdraw_route}" ]]; then
  echo "::group::assert primary route withdrawal"
  cp "${work_dir}/nodes.json" "${work_dir}/nodes-before-withdraw.json"
  withdraw_client_name="$(
    ruby -rjson -e '
      route = ARGV.fetch(1)
      payload = JSON.parse(File.read(ARGV.fetch(0)))
      nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
      primary_nodes = nodes.select do |node|
        Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route)
      end
      abort("expected exactly one primary node before withdrawal, got #{primary_nodes.length}") unless primary_nodes.length == 1
      node = primary_nodes.fetch(0)
      puts node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
    ' "${work_dir}/nodes-before-withdraw.json" "${expected_primary_withdraw_route}"
  )"
  withdraw_status=0
  run_with_timeout "tailscale withdraw route ${withdraw_client_name}" \
    docker exec "${withdraw_client_name}" tailscale set --advertise-routes= ||
    withdraw_status="$?"
  if ((withdraw_status != 0)); then
    echo "tailscale route withdrawal ${withdraw_client_name} returned ${withdraw_status}; verifying route state"
  fi
  if ! wait_for "tailscale logged-in netmap after withdrawal ${withdraw_client_name}" "tailscale_logged_in '${withdraw_client_name}'"; then
    dump_client_debug "${withdraw_client_name}"
    exit 1
  fi

  deadline=$((SECONDS + timeout_secs))
  until
    "${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes-after-withdraw.json" &&
      ruby -rjson -e '
        route = ARGV.fetch(2)
        withdrawn_client = ARGV.fetch(3)
        expected_count = Integer(ARGV.fetch(4))

        before_payload = JSON.parse(File.read(ARGV.fetch(0)))
        before_nodes = before_payload.is_a?(Array) ? before_payload : before_payload.fetch("nodes")
        after_payload = JSON.parse(File.read(ARGV.fetch(1)))
        after_nodes = after_payload.is_a?(Array) ? after_payload : after_payload.fetch("nodes")
        abort("expected #{expected_count} nodes before withdrawal, got #{before_nodes.length}") unless before_nodes.length == expected_count
        abort("expected #{expected_count} nodes after withdrawal, got #{after_nodes.length}") unless after_nodes.length == expected_count

        before_primary = before_nodes.select do |node|
          Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route)
        end
        after_primary = after_nodes.select do |node|
          Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route)
        end
        abort("expected exactly one primary node before withdrawal, got #{before_primary.length}") unless before_primary.length == 1
        abort("expected exactly one primary node after withdrawal, got #{after_primary.length}") unless after_primary.length == 1
        before_owner = Integer(before_primary.fetch(0).fetch("id"))
        after_owner = Integer(after_primary.fetch(0).fetch("id"))
        abort("expected primary owner to change, still #{after_owner}") if after_owner == before_owner

        withdrawn = after_nodes.find do |node|
          name = node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
          name == withdrawn_client
        end
        abort("missing withdrawn client #{withdrawn_client}") unless withdrawn
        abort("withdrawn client still advertises #{route}") if Array(withdrawn["availableRoutes"] || withdrawn["available_routes"]).include?(route)

        remaining_ids = after_nodes
          .reject do |node|
            name = node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
            name == withdrawn_client
          end
          .select { |node| Array(node["availableRoutes"] || node["available_routes"]).include?(route) }
          .map { |node| Integer(node.fetch("id")) }
        abort("new primary owner #{after_owner} not among remaining advertising routers #{remaining_ids.inspect}") unless remaining_ids.include?(after_owner)

        puts JSON.pretty_generate({
          withdrawn_client: withdrawn_client,
          before_owner: before_owner,
          after_owner: after_owner,
          nodes: after_nodes,
        })
      ' "${work_dir}/nodes-before-withdraw.json" "${work_dir}/nodes-after-withdraw.json" "${expected_primary_withdraw_route}" "${withdraw_client_name}" "${expected_machine_count}"
  do
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for primary route withdrawal" >&2
      exit 1
    fi
    sleep 1
  done
  echo "::endgroup::"
fi

echo "headscale-go ${login_mode} real-client smoke passed"
