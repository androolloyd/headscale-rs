#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
headscale_go_version="${HEADSCALE_GO_VERSION:-v0.28.0}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/authkey-headscale-go-smoke}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-120}"
advertise_routes="${REAL_CLIENT_ADVERTISE_ROUTES:-}"
expected_available_routes="${REAL_CLIENT_EXPECT_AVAILABLE_ROUTES:-${advertise_routes}}"
approve_routes="${REAL_CLIENT_APPROVE_ROUTES:-}"
expected_approved_routes="${REAL_CLIENT_EXPECT_APPROVED_ROUTES:-${approve_routes}}"
run_id="hsgo-authkey-$(date +%s)-$$"
case "${work_root}" in
  /*) work_dir="${work_root}/${run_id}" ;;
  *) work_dir="${repo_root}/${work_root}/${run_id}" ;;
esac
mkdir -p "${work_dir}/bin"

http_port=""
grpc_port=""
metrics_port=""
server_pid=""
client_name="${run_id}-client"
config_path="${work_dir}/config.yaml"
headscale_bin="${HEADSCALE_GO_BIN:-${work_dir}/bin/headscale}"
socket_path="/tmp/${run_id}.sock"

cleanup() {
  if [[ -n "${client_name}" ]]; then
    docker rm -f "${client_name}" >/dev/null 2>&1 || true
  fi
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

tailscale_logged_in() {
  docker exec "${client_name}" tailscale status --json 2>/dev/null |
    ruby -rjson -e '
      status = JSON.parse(STDIN.read)
      self_node = status["Self"] || {}
      ips = Array(status["TailscaleIPs"])
      ok = status["HaveNodeKey"] &&
        status["AuthURL"].to_s.empty? &&
        self_node["InNetworkMap"] &&
        ips.any? { |ip| ip.start_with?("100.") }
      exit(ok ? 0 : 1)
    '
}

dump_client_debug() {
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

echo "::group::mint preauth key"
"${headscale_bin}" -c "${config_path}" -o json users create alice >"${work_dir}/user.json"
user_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("id")' "${work_dir}/user.json")"
"${headscale_bin}" -c "${config_path}" -o json preauthkeys create \
  --user "${user_id}" \
  --reusable \
  --expiration 1h \
  >"${work_dir}/preauth.json"
authkey="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("key")' "${work_dir}/preauth.json")"
echo "minted ${authkey%%-*}-..."
echo "::endgroup::"

echo "::group::start stock tailscale client"
docker run -d \
  --name "${client_name}" \
  --hostname "${client_name}" \
  --add-host host.docker.internal:host-gateway \
  --entrypoint /bin/sh \
  "${image}" \
  -ceu 'tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity' \
  >/dev/null

wait_for "tailscaled local socket" \
  "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
echo "::endgroup::"

echo "::group::tailscale up"
up_args=(
  tailscale up
  "--login-server=http://host.docker.internal:${http_port}"
  "--hostname=${client_name}"
  "--authkey=${authkey}"
  --timeout=15s
  --accept-routes=false
  --accept-dns=false
)
if [[ -n "${advertise_routes}" ]]; then
  up_args+=("--advertise-routes=${advertise_routes}")
fi
up_status=0
run_with_timeout "tailscale up" docker exec "${client_name}" "${up_args[@]}" ||
  up_status="$?"
if ((up_status != 0)); then
  echo "tailscale up returned ${up_status}; verifying logged-in netmap"
fi

if ! wait_for "tailscale logged-in netmap" tailscale_logged_in; then
  dump_client_debug
  exit 1
fi
docker exec "${client_name}" tailscale status --json >"${work_dir}/tailscale-status.json"
echo "::endgroup::"

if [[ -n "${approve_routes}" ]]; then
  echo "::group::approve routes"
  "${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes-before-approve.json"
  node_id="$(
    ruby -rjson -e '
      payload = JSON.parse(File.read(ARGV.fetch(0)))
      nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
      abort("expected one registered node, got #{nodes.length}") unless nodes.length == 1
      puts nodes.fetch(0).fetch("id")
    ' "${work_dir}/nodes-before-approve.json"
  )"
  "${headscale_bin}" -c "${config_path}" -o json nodes approve-routes \
    --identifier "${node_id}" \
    --routes "${approve_routes}" \
    >"${work_dir}/approved-routes.json"
  echo "::endgroup::"
fi

echo "::group::assert headscale-go node state"
"${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes.json"
ruby -rjson -e '
  expected_routes = ARGV.fetch(1).split(",").reject(&:empty?).sort
  expected_approved = ARGV.fetch(2).split(",").reject(&:empty?).sort
  payload = JSON.parse(File.read(ARGV.fetch(0)))
  nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
  abort("expected one registered node, got #{nodes.length}") unless nodes.length == 1
  node = nodes.fetch(0)
  user = node["user"] || node["User"]
  user_name = user.is_a?(Hash) ? (user["name"] || user["loginName"] || user["login_name"]) : user.to_s
  given_name = node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
  addresses = Array(node["ipAddresses"] || node["ip_addresses"] || node["addresses"])
  available_routes = Array(node["availableRoutes"] || node["available_routes"]).sort
  approved_routes = Array(node["approvedRoutes"] || node["approved_routes"]).sort
  abort("expected user alice, got #{user.inspect}") unless user_name == "alice"
  abort("expected hostname prefix, got #{given_name.inspect}") unless given_name.to_s.start_with?("hsgo-authkey-")
  abort("expected CGNAT IPv4, got #{addresses.inspect}") unless addresses.any? { |ip| ip.to_s.start_with?("100.") }
  unless expected_routes.empty? || available_routes == expected_routes
    abort("expected available routes #{expected_routes.inspect}, got #{available_routes.inspect}")
  end
  unless expected_approved.empty? || approved_routes == expected_approved
    abort("expected approved routes #{expected_approved.inspect}, got #{approved_routes.inspect}")
  end
  puts JSON.pretty_generate(node)
' "${work_dir}/nodes.json" "${expected_available_routes}" "${expected_approved_routes}"
echo "::endgroup::"

echo "headscale-go auth-key real-client smoke passed"
