#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

target="${REAL_CLIENT_OIDC_SSH_TARGET:-rust}"
case "${target}" in
  rust | headscale-go) ;;
  *)
    echo "REAL_CLIENT_OIDC_SSH_TARGET must be rust or headscale-go" >&2
    exit 2
    ;;
esac

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
headscale_go_version="${HEADSCALE_GO_VERSION:-4483fd0cad38717913e7509fc50f9d48c691b02b}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-180}"
ssh_user="${REAL_CLIENT_SSH_USER:-ssh-it-user}"
attempt_timeout="${REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS:-120}"
oidc_client_id="${REAL_CLIENT_OIDC_CLIENT_ID:-headscale-rs}"
oidc_client_secret="${REAL_CLIENT_OIDC_CLIENT_SECRET:-secret}"
oidc_subject="${REAL_CLIENT_OIDC_SUBJECT:-alice-subject}"
oidc_email="${REAL_CLIENT_OIDC_EMAIL:-alice@example.com}"
oidc_username="${REAL_CLIENT_OIDC_USERNAME:-alice}"
oidc_groups="${REAL_CLIENT_OIDC_GROUPS:-engineering}"
oidc_flow_count="${REAL_CLIENT_OIDC_FLOW_COUNT:-3}"
base_domain="${REAL_CLIENT_BASE_DOMAIN-tail.test}"
policy_json="${REAL_CLIENT_POLICY_JSON:-$(cat tools/real-client/fixtures/ssh-oidc-check.hujson)}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/ssh-oidc-check-smoke}"
run_id="hs-ssh-oidc-${target}-$(date +%s)-$$"
client_one="${REAL_CLIENT_CLIENT_ONE:-${run_id}-one}"
client_two="${REAL_CLIENT_CLIENT_TWO:-${run_id}-two}"

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
      count = Integer(ARGV.fetch(4))
      abort("REAL_CLIENT_OIDC_FLOW_COUNT must be positive") unless count.positive?
      groups = ARGV.fetch(3).split(",").reject(&:empty?)
      user = {
        Subject: ARGV.fetch(0),
        Email: ARGV.fetch(1),
        EmailVerified: true,
        PreferredUsername: ARGV.fetch(2),
        Groups: groups,
      }
      puts JSON.generate(Array.new(count) { user })
    ' "${oidc_subject}" "${oidc_email}" "${oidc_username}" "${oidc_groups}" "${oidc_flow_count}"
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
    "curl -fsS 'http://127.0.0.1:${oidc_port}/oidc/.well-known/openid-configuration' >/dev/null"
  echo "mock_oidc=http://127.0.0.1:${oidc_port}/oidc"
  echo "::endgroup::"
}

write_policy_file() {
  printf '%s\n' "${policy_json}" >"${work_dir}/ssh-oidc-check.hujson"
}

start_rust_server() {
  http_port="$(free_port)"
  https_port="$(free_port)"
  control_port="${https_port}"
  control_url="https://host.docker.internal:${https_port}"
  local_health_url="http://127.0.0.1:${http_port}/health"
  config_path="${work_dir}/headscale-rs.toml"
  db_path="${work_dir}/db.sqlite"
  mkdir -p "${work_dir}/state"
  tls_cert_path="${work_dir}/state/tls.crt"
  rm -f "${headscale_rs_socket_path}"

  echo "::group::build headscale-rs CLI"
  cargo build --quiet -p headscale-cli --bin headscale
  echo "::endgroup::"

  cat >"${config_path}" <<EOF
[server]
listen = "127.0.0.1:${http_port}"
https_listen = "0.0.0.0:${https_port}"
server_url = "${control_url}"
state_dir = "${work_dir}/state"
db_path = "${db_path}"
tls_hostname = "host.docker.internal"
unix_socket = "${headscale_rs_socket_path}"
unix_socket_permission = 448

[node]
expiry = "180d"

[policy]
mode = "file"
path = "${work_dir}/ssh-oidc-check.hujson"

[oidc]
issuer = "http://127.0.0.1:${oidc_port}/oidc"
client_id = "${oidc_client_id}"
client_secret = "${oidc_client_secret}"
allowed_domains = ["example.com"]
email_verified_required = true
EOF

  echo "::group::start headscale-rs OIDC SSH server"
  target/debug/headscale --config "${config_path}" server \
    >"${work_dir}/headscale-rs.stdout" \
    2>"${work_dir}/headscale-rs.stderr" &
  server_pid="$!"
  wait_for "headscale-rs health" "curl -fsS '${local_health_url}' >/dev/null"
  wait_for "headscale-rs TLS certificate" "test -s '${tls_cert_path}'"
  echo "headscale-rs login=${control_url}"
  echo "::endgroup::"
}

start_headscale_go_server() {
  http_port="$(free_port)"
  metrics_port="$(free_port)"
  grpc_port="$(free_port)"
  control_port="${http_port}"
  control_url="https://host.docker.internal:${http_port}"
  local_health_url="https://127.0.0.1:${http_port}/health"
  config_path="${work_dir}/headscale-go.yaml"
  db_path="${work_dir}/db.sqlite"
  tls_cert_path="${work_dir}/tls.crt"
  rm -f "${headscale_go_socket_path}"

  echo "::group::generate headscale-go TLS certificate"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
    -keyout "${work_dir}/tls.key" \
    -out "${tls_cert_path}" \
    -subj "/CN=host.docker.internal" \
    -addext "subjectAltName=DNS:host.docker.internal,IP:127.0.0.1" \
    >"${work_dir}/openssl.stdout" \
    2>"${work_dir}/openssl.stderr"
  echo "::endgroup::"

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

database:
  type: sqlite
  sqlite:
    path: ${db_path}

dns:
  magic_dns: true
  base_domain: "${base_domain}"
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []

policy:
  mode: file
  path: ${work_dir}/ssh-oidc-check.hujson

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

  echo "::group::start headscale-go OIDC SSH server"
  "${headscale_bin}" -c "${config_path}" serve \
    >"${work_dir}/headscale-go.stdout" \
    2>"${work_dir}/headscale-go.stderr" &
  server_pid="$!"
  wait_for "headscale-go health" "curl -kfsS '${local_health_url}' >/dev/null"
  wait_for "headscale-go gRPC" "'${headscale_bin}' -c '${config_path}' health >/dev/null 2>&1"
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

run_ssh_check() {
  echo "::group::approve Tailscale SSH check with OIDC"
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
  approve_ssh_check_with_oidc "${auth_id}"
  wait_pid_with_timeout "tailscale ssh check completion" "${ssh_pid}"
  ssh_pid=""
  grep -Fxq "${client_two}" "${work_dir}/ssh-check.stdout"
  echo "approved_auth_id=${auth_id}"
  echo "::endgroup::"
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
run_ssh_check

echo "${target} OIDC SSH check real-client smoke passed"
