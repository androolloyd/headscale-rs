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
expected_primary_sticky_route="${REAL_CLIENT_EXPECT_PRIMARY_STICKY_ROUTE:-}"
expected_primary_withdraw_route="${REAL_CLIENT_EXPECT_PRIMARY_WITHDRAW_ROUTE:-}"
preauth_tags="${REAL_CLIENT_PREAUTH_TAGS:-}"
set_tags_after_login="${REAL_CLIENT_SET_TAGS_AFTER_LOGIN:-}"
expected_set_tags_failure="${REAL_CLIENT_EXPECT_SET_TAGS_FAILURE:-false}"
reauth_after_login="${REAL_CLIENT_REAUTH_AFTER_LOGIN:-false}"
reauth_tags="${REAL_CLIENT_REAUTH_TAGS:-}"
expected_tags_exact="${REAL_CLIENT_EXPECT_TAGS_EXACT:-}"
headscale_go_tls="${REAL_CLIENT_HEADSCALE_GO_TLS:-}"
policy_json="${REAL_CLIENT_POLICY_JSON:-}"
base_domain="${REAL_CLIENT_BASE_DOMAIN-tail.test}"
magic_dns="${REAL_CLIENT_MAGIC_DNS:-}"
prefix_v4="${REAL_CLIENT_PREFIX_V4-100.64.0.0/10}"
prefix_v6="${REAL_CLIENT_PREFIX_V6-fd7a:115c:a1e0::/48}"
prefix_allocation="${REAL_CLIENT_PREFIX_ALLOCATION:-sequential}"
expected_magic_dns_suffix="${REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX:-}"
expected_no_magic_dns="${REAL_CLIENT_EXPECT_NO_MAGIC_DNS:-false}"
expected_peer_count="${REAL_CLIENT_EXPECT_PEER_COUNT:-}"
expected_peer_counts="${REAL_CLIENT_EXPECT_PEER_COUNTS:-}"
expected_tailscale_ip_families="${REAL_CLIENT_EXPECT_TAILSCALE_IP_FAMILIES:-}"
client_users_csv="${REAL_CLIENT_CLIENT_USERS:-}"
enable_tailscale_ssh="${REAL_CLIENT_ENABLE_TAILSCALE_SSH:-false}"
install_openssh="${REAL_CLIENT_INSTALL_OPENSSH:-false}"
ssh_user="${REAL_CLIENT_SSH_USER:-}"
expected_ssh_matrix="${REAL_CLIENT_EXPECT_SSH_MATRIX:-}"
ssh_attempt_timeout_secs="${REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS:-12}"
ssh_host_key_timeout_secs="${REAL_CLIENT_SSH_HOST_KEY_TIMEOUT_SECS:-30}"
if [[ -n "${expected_ssh_matrix}" ]]; then
  enable_tailscale_ssh="${REAL_CLIENT_ENABLE_TAILSCALE_SSH:-true}"
  install_openssh="${REAL_CLIENT_INSTALL_OPENSSH:-true}"
  ssh_user="${ssh_user:-ssh-it-user}"
fi
case "${login_mode}" in
  authkey | web) ;;
  *)
    echo "REAL_CLIENT_LOGIN_MODE must be authkey or web, got ${login_mode}" >&2
    exit 2
    ;;
esac
case "${enable_tailscale_ssh}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    enable_tailscale_ssh_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    enable_tailscale_ssh_flag=0
    ;;
  *)
    echo "REAL_CLIENT_ENABLE_TAILSCALE_SSH must be true or false, got ${enable_tailscale_ssh}" >&2
    exit 2
    ;;
esac
case "${install_openssh}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    install_openssh_client=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    install_openssh_client=0
    ;;
  *)
    echo "REAL_CLIENT_INSTALL_OPENSSH must be true or false, got ${install_openssh}" >&2
    exit 2
    ;;
esac
if [[ -n "${expected_ssh_matrix}" && -z "${ssh_user}" ]]; then
  echo "REAL_CLIENT_EXPECT_SSH_MATRIX requires REAL_CLIENT_SSH_USER" >&2
  exit 2
fi
if [[ -n "${ssh_user}" && ! "${ssh_user}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  echo "REAL_CLIENT_SSH_USER must be a simple Linux username, got ${ssh_user}" >&2
  exit 2
fi
if ! [[ "${ssh_attempt_timeout_secs}" =~ ^[0-9]+$ ]] || ((ssh_attempt_timeout_secs < 1)); then
  echo "REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS must be a positive integer, got ${ssh_attempt_timeout_secs}" >&2
  exit 2
fi
if ! [[ "${ssh_host_key_timeout_secs}" =~ ^[0-9]+$ ]] || ((ssh_host_key_timeout_secs < 1)); then
  echo "REAL_CLIENT_SSH_HOST_KEY_TIMEOUT_SECS must be a positive integer, got ${ssh_host_key_timeout_secs}" >&2
  exit 2
fi
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
if [[ -n "${expected_primary_sticky_route}" ]]; then
  if [[ -z "${expected_primary_failover_route}" ]]; then
    echo "REAL_CLIENT_EXPECT_PRIMARY_STICKY_ROUTE requires REAL_CLIENT_EXPECT_PRIMARY_FAILOVER_ROUTE" >&2
    exit 2
  fi
  if [[ "${expected_primary_sticky_route}" != "${expected_primary_failover_route}" ]]; then
    echo "REAL_CLIENT_EXPECT_PRIMARY_STICKY_ROUTE must match REAL_CLIENT_EXPECT_PRIMARY_FAILOVER_ROUTE" >&2
    exit 2
  fi
fi
case "${expected_set_tags_failure}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    expect_set_tags_failure=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    expect_set_tags_failure=0
    ;;
  *)
    echo "REAL_CLIENT_EXPECT_SET_TAGS_FAILURE must be true or false, got ${expected_set_tags_failure}" >&2
    exit 2
    ;;
esac
if ((expect_set_tags_failure)) && [[ -z "${set_tags_after_login}" ]]; then
  echo "REAL_CLIENT_EXPECT_SET_TAGS_FAILURE requires REAL_CLIENT_SET_TAGS_AFTER_LOGIN" >&2
  exit 2
fi
case "${reauth_after_login}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    do_reauth_after_login=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    do_reauth_after_login=0
    ;;
  *)
    echo "REAL_CLIENT_REAUTH_AFTER_LOGIN must be true or false, got ${reauth_after_login}" >&2
    exit 2
    ;;
esac
expected_tags_default="${preauth_tags}"
if ((do_reauth_after_login)); then
  expected_tags_default="${reauth_tags}"
fi
if [[ -n "${set_tags_after_login}" ]] && ((expect_set_tags_failure == 0)); then
  expected_tags_default="${set_tags_after_login}"
fi
expected_tags="${REAL_CLIENT_EXPECT_TAGS:-${expected_tags_default}}"
if [[ -z "${expected_tags_exact}" ]]; then
  if ((do_reauth_after_login)); then
    expected_tags_exact=true
  else
    expected_tags_exact=false
  fi
fi
case "${expected_tags_exact}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    expect_tags_exact=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    expect_tags_exact=0
    ;;
  *)
    echo "REAL_CLIENT_EXPECT_TAGS_EXACT must be true or false, got ${expected_tags_exact}" >&2
    exit 2
    ;;
esac
if [[ -z "${headscale_go_tls}" ]]; then
  if ((do_reauth_after_login)); then
    headscale_go_tls=true
  else
    headscale_go_tls=false
  fi
fi
case "${headscale_go_tls}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    use_headscale_go_tls=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    use_headscale_go_tls=0
    ;;
  *)
    echo "REAL_CLIENT_HEADSCALE_GO_TLS must be true or false, got ${headscale_go_tls}" >&2
    exit 2
    ;;
esac
if [[ -z "${magic_dns}" ]]; then
  if [[ -n "${base_domain}" ]]; then
    magic_dns=true
  else
    magic_dns=false
  fi
fi
case "${magic_dns}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    use_magic_dns=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    use_magic_dns=0
    ;;
  *)
    echo "REAL_CLIENT_MAGIC_DNS must be true or false, got ${magic_dns}" >&2
    exit 2
    ;;
esac
case "${expected_no_magic_dns}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    expect_no_magic_dns=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    expect_no_magic_dns=0
    ;;
  *)
    echo "REAL_CLIENT_EXPECT_NO_MAGIC_DNS must be true or false, got ${expected_no_magic_dns}" >&2
    exit 2
    ;;
esac
if ((expect_no_magic_dns)) && [[ -n "${expected_magic_dns_suffix}" ]]; then
  echo "REAL_CLIENT_EXPECT_NO_MAGIC_DNS conflicts with REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX" >&2
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
case "${expected_tailscale_ip_families}" in
  "" | ipv4 | ipv4-only | ipv6 | ipv6-only | dual | dual-stack) ;;
  *)
    echo "REAL_CLIENT_EXPECT_TAILSCALE_IP_FAMILIES must be empty, ipv4-only, ipv6-only, or dual-stack; got ${expected_tailscale_ip_families}" >&2
    exit 2
    ;;
esac
if [[ -z "${prefix_v4}" && -z "${prefix_v6}" ]]; then
  echo "at least one of REAL_CLIENT_PREFIX_V4 or REAL_CLIENT_PREFIX_V6 must be non-empty" >&2
  exit 2
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

client_users=()
if [[ -n "${client_users_csv}" ]]; then
  IFS=',' read -r -a client_users <<<"${client_users_csv}"
  if ((${#client_users[@]} != client_count)); then
    echo "REAL_CLIENT_CLIENT_USERS must contain ${client_count} comma-separated users, got ${client_users_csv}" >&2
    exit 2
  fi
  for user in "${client_users[@]}"; do
    if [[ -z "${user}" ]]; then
      echo "REAL_CLIENT_CLIENT_USERS must not contain empty users, got ${client_users_csv}" >&2
      exit 2
    fi
  done
else
  for ((idx = 0; idx < client_count; idx++)); do
    client_users+=("alice")
  done
fi
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
      !ips.empty?
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

tailscale_ssh_attempt() {
  local source_name="$1"
  local target_name="$2"
  local stdout_path="$3"
  local stderr_path="$4"
  docker exec "${source_name}" sh -ceu \
    'timeout "$1" tailscale ssh "$2@$3" hostname' \
    sh "${ssh_attempt_timeout_secs}" "${ssh_user}" "${target_name}" \
    >"${stdout_path}" \
    2>"${stderr_path}"
}

tailscale_ssh_succeeded() {
  local source_name="$1"
  local target_name="$2"
  local stdout_path="${work_dir}/ssh-${source_name}-to-${target_name}.stdout"
  local stderr_path="${work_dir}/ssh-${source_name}-to-${target_name}.stderr"
  tailscale_ssh_attempt "${source_name}" "${target_name}" "${stdout_path}" "${stderr_path}" || return 1
  grep -Fxq "${target_name}" "${stdout_path}"
}

tailscale_peer_has_ssh_host_keys() {
  local source_name="$1"
  local target_name="$2"
  local status_json
  status_json="$(docker exec "${source_name}" tailscale status --json 2>/dev/null || true)"
  ruby -rjson -e '
    status = JSON.parse(STDIN.read)
    peer = (status["Peer"] || {}).each_value.find { |p| p["HostName"] == ARGV.fetch(0) }
    keys = Array(peer && (peer["SSH_HostKeys"] || peer["SSHHostKeys"] || peer["sshHostKeys"]))
    exit(keys.empty? ? 1 : 0)
  ' "${target_name}" <<<"${status_json}"
}

wait_for_ssh_host_keys() {
  local source_name="$1"
  local target_name="$2"
  local deadline=$((SECONDS + ssh_host_key_timeout_secs))
  until tailscale_peer_has_ssh_host_keys "${source_name}" "${target_name}"; do
    if ((SECONDS >= deadline)); then
      return 1
    fi
    sleep 1
  done
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
if ((use_headscale_go_tls)); then
  need openssl
fi

http_port="$(free_port)"
grpc_port="$(free_port)"
metrics_port="$(free_port)"
control_scheme="http"
health_curl_opts="-fsS"
if ((use_headscale_go_tls)); then
  control_scheme="https"
  health_curl_opts="-fsSk"
  echo "::group::generate headscale-go TLS certificate"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
    -keyout "${work_dir}/tls.key" \
    -out "${work_dir}/tls.crt" \
    -subj "/CN=host.docker.internal" \
    -addext "subjectAltName=DNS:host.docker.internal,IP:127.0.0.1" \
    >"${work_dir}/openssl.stdout" \
    2>"${work_dir}/openssl.stderr"
  echo "::endgroup::"
fi
control_url="${control_scheme}://host.docker.internal:${http_port}"
local_control_url="${control_scheme}://127.0.0.1:${http_port}"

echo "::group::build headscale-go ${headscale_go_version}"
if [[ -z "${HEADSCALE_GO_BIN:-}" ]]; then
  GOBIN="${work_dir}/bin" go install "github.com/juanfont/headscale/cmd/headscale@${headscale_go_version}"
fi
"${headscale_bin}" version >"${work_dir}/headscale-version.txt"
cat "${work_dir}/headscale-version.txt"
echo "::endgroup::"

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
  allocation: ${prefix_allocation}
EOF
if [[ -n "${prefix_v4}" ]]; then
  printf '  v4: %s\n' "${prefix_v4}" >>"${config_path}"
fi
if [[ -n "${prefix_v6}" ]]; then
  printf '  v6: %s\n' "${prefix_v6}" >>"${config_path}"
fi
cat >>"${config_path}" <<EOF

database:
  type: sqlite
  sqlite:
    path: ${work_dir}/db.sqlite

dns:
  magic_dns: $([[ "${use_magic_dns}" -eq 1 ]] && printf true || printf false)
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
EOF

if ((use_headscale_go_tls)); then
  cat >>"${config_path}" <<EOF

tls_cert_path: ${work_dir}/tls.crt
tls_key_path: ${work_dir}/tls.key
EOF
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
  "curl ${health_curl_opts} '${local_control_url}/health' >/dev/null"
wait_for "headscale-go gRPC" \
  "'${headscale_bin}' -c '${config_path}' health >/dev/null 2>&1"
echo "headscale-go control=${local_control_url}"
echo "headscale-go login=${control_url}"
echo "::endgroup::"

user_names=()
user_ids=()

lookup_user_id() {
  local target="$1"
  local idx
  for idx in "${!user_names[@]}"; do
    if [[ "${user_names[$idx]}" == "${target}" ]]; then
      printf '%s\n' "${user_ids[$idx]}"
      return 0
    fi
  done
  return 1
}

echo "::group::create users"
for user in "${client_users[@]}"; do
  already_created=0
  for existing in "${user_names[@]}"; do
    if [[ "${existing}" == "${user}" ]]; then
      already_created=1
      break
    fi
  done
  if ((already_created)); then
    continue
  fi
  user_path="${work_dir}/user-${user}.json"
  "${headscale_bin}" -c "${config_path}" -o json users create "${user}" >"${user_path}"
  user_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("id")' "${user_path}")"
  user_names+=("${user}")
  user_ids+=("${user_id}")
  echo "created user ${user} ${user_id}"
done
echo "::endgroup::"

authkey=""
authkeys=()
if [[ "${login_mode}" == "authkey" ]]; then
  echo "::group::mint preauth key"
  if [[ -n "${client_users_csv}" ]]; then
    for idx in "${!client_names[@]}"; do
      user_id="$(lookup_user_id "${client_users[$idx]}")"
      preauth_args=(
        "${headscale_bin}" -c "${config_path}" -o json preauthkeys create
        --user "${user_id}" \
        --reusable \
        --expiration 1h
      )
      if [[ -n "${preauth_tags}" ]]; then
        preauth_args+=(--tags "${preauth_tags}")
      fi
      "${preauth_args[@]}" >"${work_dir}/preauth-${idx}.json"
      authkey="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("key")' "${work_dir}/preauth-${idx}.json")"
      authkeys+=("${authkey}")
    done
    echo "minted ${#authkeys[@]} per-client keys"
  else
    user_id="$(lookup_user_id alice)"
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
    for _client_name in "${client_names[@]}"; do
      authkeys+=("${authkey}")
    done
    echo "minted ${authkey%%-*}-..."
  fi
  echo "::endgroup::"
fi

echo "::group::start stock tailscale client"
for client_name in "${client_names[@]}"; do
  docker_args=(
    docker run -d
    --name "${client_name}" \
    --hostname "${client_name}" \
    --add-host host.docker.internal:host-gateway \
    --entrypoint /bin/sh
  )
  client_entry='tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity'
  if ((use_headscale_go_tls)); then
    docker_args+=(-v "${work_dir}/tls.crt:/usr/local/share/ca-certificates/headscale-go.crt:ro")
    client_entry='update-ca-certificates >/tmp/update-ca-certificates.log 2>&1; tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity'
  fi
  if ((install_openssh_client)); then
    client_entry="apk add --no-cache openssh-client >/tmp/apk-openssh-client.log 2>&1; ${client_entry}"
  fi
  if [[ -n "${ssh_user}" ]]; then
    client_entry="id '${ssh_user}' >/dev/null 2>&1 || adduser -D -h '/home/${ssh_user}' -s /bin/sh '${ssh_user}' >/tmp/adduser-${ssh_user}.log 2>&1; ${client_entry}"
  fi
  docker_args+=("${image}")
  "${docker_args[@]}" \
    -ceu "${client_entry}" \
    >/dev/null

  wait_for "tailscaled local socket ${client_name}" \
    "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
done
echo "::endgroup::"

echo "::group::tailscale up"
for idx in "${!client_names[@]}"; do
  client_name="${client_names[$idx]}"
  up_args=(
    tailscale up
    "--login-server=${control_url}"
    "--hostname=${client_name}"
    "--timeout=${up_timeout}"
    --accept-routes=false
    --accept-dns=false
  )
  if [[ "${login_mode}" == "authkey" ]]; then
    up_args+=("--authkey=${authkeys[$idx]}")
  fi
  if [[ -n "${advertise_routes}" ]]; then
    up_args+=("--advertise-routes=${advertise_routes}")
  fi
  if ((enable_tailscale_ssh_flag)); then
    up_args+=(--ssh)
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
    register_user="${client_users[$idx]}"
    "${headscale_bin}" -c "${config_path}" -o json nodes register \
      --user "${register_user}" \
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

if ((do_reauth_after_login)); then
  echo "::group::force headscale-go web reauth"
  for idx in "${!client_names[@]}"; do
    client_name="${client_names[$idx]}"
    reauth_args=(
      tailscale up
      "--login-server=${control_url}"
      "--hostname=${client_name}"
      "--timeout=${up_timeout}"
      --accept-routes=false
      --accept-dns=false
      --force-reauth
      --reset
    )
    if [[ -n "${reauth_tags}" ]]; then
      reauth_args+=("--advertise-tags=${reauth_tags}")
    fi
    if ((enable_tailscale_ssh_flag)); then
      reauth_args+=(--ssh)
    fi
    up_status=0
    docker exec "${client_name}" "${reauth_args[@]}" \
      >"${work_dir}/${client_name}.reauth-up.stdout" \
      2>"${work_dir}/${client_name}.reauth-up.stderr" &
    up_pid="$!"
    registration_id_path="${work_dir}/${client_name}.reauth-registration-id"
    if ! wait_for "reauth web registration URL ${client_name}" \
      "write_registration_id '${client_name}' '${registration_id_path}'"; then
      dump_client_debug "${client_name}"
      exit 1
    fi
    registration_id="$(cat "${registration_id_path}")"
    register_status=0
    register_user="${client_users[$idx]}"
    "${headscale_bin}" -c "${config_path}" -o json nodes register \
      --user "${register_user}" \
      --key "${registration_id}" \
      >"${work_dir}/${client_name}.reauth-registered.json" \
      2>"${work_dir}/${client_name}.reauth-registered.err" ||
      register_status="$?"
    if ((register_status != 0)); then
      cat "${work_dir}/${client_name}.reauth-registered.err" >&2 || true
      kill "${up_pid}" >/dev/null 2>&1 || true
      wait "${up_pid}" >/dev/null 2>&1 || true
      exit "${register_status}"
    fi
    wait_pid_with_timeout "tailscale reauth ${client_name}" "${up_pid}" ||
      up_status="$?"
    if ((up_status != 0)); then
      echo "tailscale reauth ${client_name} returned ${up_status}; verifying logged-in netmap"
    fi
    if ! wait_for "tailscale logged-in netmap after reauth ${client_name}" "tailscale_logged_in '${client_name}'"; then
      dump_client_debug "${client_name}"
      exit 1
    fi
    docker exec "${client_name}" tailscale status --json >"${work_dir}/${client_name}.reauth-tailscale-status.json"
  done
  echo "::endgroup::"
fi

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

if [[ -n "${set_tags_after_login}" ]]; then
  echo "::group::set headscale-go tags"
  "${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes-before-tags.json"
  node_id="$(
    ruby -rjson -e '
      payload = JSON.parse(File.read(ARGV.fetch(0)))
      nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
      expected = Integer(ARGV.fetch(1))
      abort("expected #{expected} registered nodes, got #{nodes.length}") unless nodes.length == expected
      puts nodes.map { |node| node.fetch("id") }
    ' "${work_dir}/nodes-before-tags.json" "${expected_machine_count}"
  )"
  while IFS= read -r node_id; do
    tag_status=0
    "${headscale_bin}" -c "${config_path}" -o json nodes tag \
      --identifier "${node_id}" \
      --tags "${set_tags_after_login}" \
      >"${work_dir}/set-tags-${node_id}.json" \
      2>"${work_dir}/set-tags-${node_id}.err" ||
      tag_status="$?"
    if ((expect_set_tags_failure)); then
      if ((tag_status == 0)); then
        echo "expected tag update to fail for node ${node_id}" >&2
        exit 1
      fi
      continue
    fi
    if ((tag_status != 0)); then
      cat "${work_dir}/set-tags-${node_id}.err" >&2 || true
      exit "${tag_status}"
    fi
  done <<<"${node_id}"
  echo "::endgroup::"
fi

echo "::group::assert headscale-go node state"
"${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes.json"
expected_client_names_csv="$(IFS=,; echo "${client_names[*]}")"
expected_client_users_csv="$(IFS=,; echo "${client_users[*]}")"
ruby -rjson -e '
  expected_routes = ARGV.fetch(1).split(",").reject(&:empty?).sort
  expected_approved = ARGV.fetch(2).split(",").reject(&:empty?).sort
  expected_count = Integer(ARGV.fetch(3))
  expected_primary_route = ARGV.fetch(4)
  expected_tags = ARGV.fetch(5).split(",").reject(&:empty?).sort
  expected_hostname_prefix = ARGV.fetch(6)
  expect_tags_exact = ARGV.fetch(7) == "true"
  expected_names = ARGV.fetch(8).split(",")
  expected_users = ARGV.fetch(9).split(",")
  expected_families = ARGV.fetch(10)
  expected_user_by_host = expected_names.zip(expected_users).to_h

  def assert_ip_families(label, ips, expected)
    has_v4 = ips.any? { |ip| ip.to_s.include?(".") }
    has_v6 = ips.any? { |ip| ip.to_s.include?(":") }
    case expected
    when ""
      abort("#{label}: expected at least one IPv4 address, got #{ips.inspect}") unless has_v4
    when "ipv4", "ipv4-only"
      abort("#{label}: expected IPv4-only addresses, got #{ips.inspect}") unless has_v4 && !has_v6
    when "ipv6", "ipv6-only"
      abort("#{label}: expected IPv6-only addresses, got #{ips.inspect}") unless !has_v4 && has_v6
    when "dual", "dual-stack"
      abort("#{label}: expected dual-stack addresses, got #{ips.inspect}") unless has_v4 && has_v6
    else
      abort("unsupported expected IP family #{expected.inspect}")
    end
  end

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
    expected_user = if expected_tags.empty?
      expected_user_by_host.fetch(given_name.to_s) {
        abort("unexpected node hostname #{given_name.inspect}; expected one of #{expected_names.inspect}")
      }
    else
      "tagged-devices"
    end
    abort("expected user #{expected_user}, got #{user.inspect}") unless user_name == expected_user
    abort("expected hostname prefix #{expected_hostname_prefix.inspect}, got #{given_name.inspect}") unless given_name.to_s.start_with?(expected_hostname_prefix)
    assert_ip_families("node #{given_name}", addresses, expected_families)
    unless expected_routes.empty? || available_routes == expected_routes
      abort("expected available routes #{expected_routes.inspect}, got #{available_routes.inspect}")
    end
    unless expected_approved.empty? || approved_routes == expected_approved
      abort("expected approved routes #{expected_approved.inspect}, got #{approved_routes.inspect}")
    end
    tags = Array(node["tags"] || node["Tags"]).sort
    unless (!expect_tags_exact && expected_tags.empty?) || tags == expected_tags
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
  ' "${work_dir}/nodes.json" "${expected_available_routes}" "${expected_approved_routes}" "${expected_machine_count}" "${expected_primary_route}" "${expected_tags}" "${run_id}" "$([[ "${expect_tags_exact}" -eq 1 ]] && printf true || printf false)" "${expected_client_names_csv}" "${expected_client_users_csv}" "${expected_tailscale_ip_families}"
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

if ((expect_no_magic_dns)); then
  echo "::group::assert MagicDNS disabled client status"
  no_magicdns_status_paths=()
  for client_name in "${client_names[@]}"; do
    status_path="${work_dir}/${client_name}.no-magicdns-status.json"
    docker exec "${client_name}" tailscale status --json >"${status_path}"
    no_magicdns_status_paths+=("${status_path}")
  done
  ruby -rjson -e '
    status_paths = ARGV
    expected_peers = status_paths.length - 1

    status_paths.each do |path|
      status = JSON.parse(File.read(path))
      self_node = status.fetch("Self")
      self_host = self_node.fetch("HostName").to_s
      suffix = status["MagicDNSSuffix"].to_s.sub(/\.\z/, "")
      abort("#{path}: expected MagicDNSSuffix to fall back to self hostname #{self_host.inspect}, got #{suffix.inspect}") unless suffix == self_host

      self_dns = self_node["DNSName"].to_s.sub(/\.\z/, "")
      abort("#{path}: expected bare self DNSName #{self_host.inspect}, got #{self_dns.inspect}") unless self_dns == self_host

      peers = status["Peer"] || {}
      abort("#{path}: expected #{expected_peers} peers, got #{peers.length}") unless peers.length == expected_peers
      peers.each_value do |peer|
        peer_host = peer.fetch("HostName").to_s
        peer_dns = peer["DNSName"].to_s.sub(/\.\z/, "")
        abort("#{path}: expected bare peer DNSName #{peer_host.inspect}, got #{peer_dns.inspect}") unless peer_dns == peer_host
      end
    end
    puts JSON.pretty_generate({magic_dns: false, clients: status_paths.length})
  ' "${no_magicdns_status_paths[@]}"
  echo "::endgroup::"
fi

if [[ -n "${expected_tailscale_ip_families}" ]]; then
  echo "::group::assert Tailscale IP families"
  family_status_paths=()
  for client_name in "${client_names[@]}"; do
    status_path="${work_dir}/${client_name}.ip-family-status.json"
    docker exec "${client_name}" tailscale status --json >"${status_path}"
    family_status_paths+=("${status_path}")
  done
  ruby -rjson -e '
    expected = ARGV.fetch(0)
    ARGV.drop(1).each do |path|
      status = JSON.parse(File.read(path))
      ips = Array(status["TailscaleIPs"])
      has_v4 = ips.any? { |ip| ip.to_s.include?(".") }
      has_v6 = ips.any? { |ip| ip.to_s.include?(":") }
      case expected
      when "ipv4", "ipv4-only"
        abort("#{path}: expected IPv4-only TailscaleIPs, got #{ips.inspect}") unless has_v4 && !has_v6
      when "ipv6", "ipv6-only"
        abort("#{path}: expected IPv6-only TailscaleIPs, got #{ips.inspect}") unless !has_v4 && has_v6
      when "dual", "dual-stack"
        abort("#{path}: expected dual-stack TailscaleIPs, got #{ips.inspect}") unless has_v4 && has_v6
      else
        abort("unsupported expected IP family #{expected.inspect}")
      end
      puts JSON.pretty_generate({path: path, tailscale_ips: ips})
    end
  ' "${expected_tailscale_ip_families}" "${family_status_paths[@]}"
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

if [[ -n "${expected_ssh_matrix}" ]]; then
  echo "::group::assert tailscale ssh matrix"
  IFS=',' read -r -a ssh_checks <<<"${expected_ssh_matrix}"
  ssh_results=()
  for raw_check in "${ssh_checks[@]}"; do
    check="${raw_check//[[:space:]]/}"
    if [[ ! "${check}" =~ ^([0-9]+):([0-9]+):(allow|deny|timeout)$ ]]; then
      echo "REAL_CLIENT_EXPECT_SSH_MATRIX entries must be source_index:target_index:allow|deny|timeout, got ${raw_check}" >&2
      exit 2
    fi
    source_idx="${BASH_REMATCH[1]}"
    target_idx="${BASH_REMATCH[2]}"
    expected_ssh="${BASH_REMATCH[3]}"
    if ((source_idx < 1 || source_idx > client_count || target_idx < 1 || target_idx > client_count)); then
      echo "SSH matrix index out of range for ${client_count} clients: ${check}" >&2
      exit 2
    fi
    source_name="${client_names[$((source_idx - 1))]}"
    target_name="${client_names[$((target_idx - 1))]}"
    stdout_path="${work_dir}/ssh-${source_name}-to-${target_name}-${expected_ssh}.stdout"
    stderr_path="${work_dir}/ssh-${source_name}-to-${target_name}-${expected_ssh}.stderr"

    # TODO(real-client SSH): when this fails, the control plane is not
    # re-emitting peer sshHostKeys in MapNode.HostInfo;
    # `tailscale ssh` fails strict host-key checking before policy
    # allow/deny evaluation can run.
    if ! wait_for_ssh_host_keys "${source_name}" "${target_name}"; then
      docker exec "${source_name}" tailscale status --json >"${work_dir}/ssh-${source_name}-status-missing-hostkeys.json" || true
      echo "timed out waiting for ${source_name} to learn ${target_name} SSH host keys; tailscale ssh cannot run strict host-key checks without peer sshHostKeys" >&2
      exit 1
    fi

    case "${expected_ssh}" in
      allow)
        if ! wait_for "tailscale ssh ${source_name} to ${target_name}" \
          "tailscale_ssh_succeeded '${source_name}' '${target_name}'"; then
          cat "${work_dir}/ssh-${source_name}-to-${target_name}.stderr" >&2 || true
          dump_client_debug "${source_name}"
          dump_client_debug "${target_name}"
          exit 1
        fi
        cp "${work_dir}/ssh-${source_name}-to-${target_name}.stdout" "${stdout_path}"
        cp "${work_dir}/ssh-${source_name}-to-${target_name}.stderr" "${stderr_path}"
        ;;
      deny)
        ssh_status=0
        tailscale_ssh_attempt "${source_name}" "${target_name}" "${stdout_path}" "${stderr_path}" ||
          ssh_status="$?"
        if ((ssh_status == 0)); then
          echo "expected tailscale ssh ${source_name} to ${target_name} to be denied" >&2
          exit 1
        fi
        if [[ -s "${stdout_path}" ]]; then
          echo "expected denied tailscale ssh stdout to be empty, got:" >&2
          cat "${stdout_path}" >&2
          exit 1
        fi
        if ! grep -Eq 'Permission denied \(tailscale\)|failed to evaluate SSH policy|tailnet policy does not permit you to SSH to this node' "${stderr_path}"; then
          echo "expected tailscale ssh denial stderr, got:" >&2
          cat "${stderr_path}" >&2 || true
          exit 1
        fi
        ;;
      timeout)
        ssh_status=0
        tailscale_ssh_attempt "${source_name}" "${target_name}" "${stdout_path}" "${stderr_path}" ||
          ssh_status="$?"
        if ((ssh_status == 0)); then
          echo "expected tailscale ssh ${source_name} to ${target_name} to time out" >&2
          exit 1
        fi
        if [[ -s "${stdout_path}" ]]; then
          echo "expected timed-out tailscale ssh stdout to be empty, got:" >&2
          cat "${stdout_path}" >&2
          exit 1
        fi
        if grep -Eq 'Permission denied \(tailscale\)|failed to evaluate SSH policy|tailnet policy does not permit you to SSH to this node' "${stderr_path}"; then
          echo "expected packet-filter timeout, got SSH policy denial:" >&2
          cat "${stderr_path}" >&2 || true
          exit 1
        fi
        if ! grep -Eq 'Connection timed out|Operation timed out' "${stderr_path}" &&
          ((ssh_status != 124 && ssh_status != 137 && ssh_status != 143)); then
          echo "expected tailscale ssh timeout status/stderr, got status ${ssh_status}:" >&2
          cat "${stderr_path}" >&2 || true
          exit 1
        fi
        ;;
    esac
    ssh_results+=("${source_name}->${target_name}:${expected_ssh}")
  done
  ruby -rjson -e 'puts JSON.pretty_generate({ssh_checks: ARGV})' "${ssh_results[@]}"
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

  if [[ -n "${expected_primary_sticky_route}" ]]; then
    echo "::group::assert primary route sticky return"
    "${headscale_bin}" -c "${config_path}" -o json nodes approve-routes \
      --identifier "${failover_node_id}" \
      --routes "${expected_primary_sticky_route}" \
      >"${work_dir}/sticky-reapprove-old-primary.json"
    "${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes-after-sticky.json"
    ruby -rjson -e '
      route = ARGV.fetch(2)
      returned_node_id = Integer(ARGV.fetch(3))
      expected_count = Integer(ARGV.fetch(4))

      after_failover_payload = JSON.parse(File.read(ARGV.fetch(0)))
      after_failover_nodes = after_failover_payload.is_a?(Array) ? after_failover_payload : after_failover_payload.fetch("nodes")
      after_sticky_payload = JSON.parse(File.read(ARGV.fetch(1)))
      after_sticky_nodes = after_sticky_payload.is_a?(Array) ? after_sticky_payload : after_sticky_payload.fetch("nodes")
      abort("expected #{expected_count} nodes after sticky return, got #{after_sticky_nodes.length}") unless after_sticky_nodes.length == expected_count

      failover_primary = after_failover_nodes.select do |node|
        Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route)
      end
      sticky_primary = after_sticky_nodes.select do |node|
        Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route)
      end
      abort("expected exactly one primary node after failover, got #{failover_primary.length}") unless failover_primary.length == 1
      abort("expected exactly one primary node after sticky return, got #{sticky_primary.length}") unless sticky_primary.length == 1
      failover_owner = Integer(failover_primary.fetch(0).fetch("id"))
      sticky_owner = Integer(sticky_primary.fetch(0).fetch("id"))
      abort("returned node unexpectedly stole #{route}: #{sticky_owner}") if sticky_owner == returned_node_id
      abort("expected sticky owner #{failover_owner}, got #{sticky_owner}") unless sticky_owner == failover_owner

      returned = after_sticky_nodes.find { |node| Integer(node.fetch("id")) == returned_node_id }
      abort("missing returned node #{returned_node_id}") unless returned
      abort("returned node missing approved route #{route}") unless Array(returned["approvedRoutes"] || returned["approved_routes"]).include?(route)
      abort("returned node missing available route #{route}") unless Array(returned["availableRoutes"] || returned["available_routes"]).include?(route)

      active_candidates = after_sticky_nodes.select do |node|
        Array(node["availableRoutes"] || node["available_routes"]).include?(route) &&
          Array(node["approvedRoutes"] || node["approved_routes"]).include?(route)
      end
      abort("expected #{expected_count} active candidates after sticky return, got #{active_candidates.length}") unless active_candidates.length == expected_count

      puts JSON.pretty_generate({
        returned_node_id: returned_node_id,
        sticky_owner: sticky_owner,
        nodes: after_sticky_nodes,
      })
    ' "${work_dir}/nodes-after-failover.json" "${work_dir}/nodes-after-sticky.json" "${expected_primary_sticky_route}" "${failover_node_id}" "${expected_machine_count}"
    echo "::endgroup::"
  fi
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
