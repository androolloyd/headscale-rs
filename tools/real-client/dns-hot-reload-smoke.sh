#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-180}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/dns-hot-reload-smoke}"
run_id="hs-dns-hot-reload-$(date +%s)-$$"
client_name="${REAL_CLIENT_CLIENT_NAME:-${run_id}-client}"
base_domain="${REAL_CLIENT_BASE_DOMAIN:-tail.test}"

case "${work_root}" in
  /*) work_dir="${work_root}/${run_id}" ;;
  *) work_dir="${repo_root}/${work_root}/${run_id}" ;;
esac
mkdir -p "${work_dir}"

http_port=""
https_port=""
grpc_port=""
server_pid=""
config_path="${work_dir}/config.yaml"
db_path="${work_dir}/db.sqlite"
socket_path="/tmp/${run_id}.sock"
extra_records_path="${work_dir}/extra-records.json"
control_url=""
local_control_url=""
tls_cert_path="${work_dir}/state/tls.crt"
headscale_bin="${repo_root}/target/debug/headscale"
authkey=""

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

headscale_cmd() {
  env -u HEADSCALE_CLI_ADDRESS -u HEADSCALE_CLI_API_KEY -u HEADSCALE_CLI_INSECURE \
    "${headscale_bin}" --config "${config_path}" --unix-socket "${socket_path}" "$@"
}

dump_debug() {
  headscale_cmd -o json nodes list 2>&1 || true
  docker exec "${client_name}" tailscale status 2>&1 || true
  docker exec "${client_name}" sh -c 'tail -180 /tmp/tailscaled.log 2>/dev/null || true' >&2 || true
}

write_records() {
  local record_name="$1"
  local record_type="$2"
  local record_value="$3"
  ruby -rjson -e 'puts JSON.generate([{"Name" => ARGV[0], "Type" => ARGV[1], "Value" => ARGV[2]}])' \
    "${record_name}" "${record_type}" "${record_value}" >"${extra_records_path}"
}

write_config() {
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
  v4: 100.64.0.0/10

dns:
  magic_dns: true
  base_domain: ${base_domain}
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  extra_records_path: ${extra_records_path}
EOF
}

start_server() {
  write_config
  rm -f "${socket_path}"
  mkdir -p "${work_dir}/state"
  echo "::group::build headscale-rs CLI"
  cargo build --quiet -p headscale-cli --bin headscale
  echo "::endgroup::"

  echo "::group::start headscale-rs server"
  "${headscale_bin}" --config "${config_path}" server \
    >"${work_dir}/headscale-rs.stdout" \
    2>"${work_dir}/headscale-rs.stderr" &
  server_pid="$!"
  wait_for "headscale-rs health" "curl -fsS '${local_control_url}/health' >/dev/null"
  wait_for "headscale-rs TLS certificate" "test -s '${tls_cert_path}'"
  wait_for "headscale-rs gRPC" "headscale_cmd health >/dev/null 2>&1"
  echo "headscale-rs control=${local_control_url}"
  echo "headscale-rs login=${control_url}"
  echo "::endgroup::"
}

create_user_and_key() {
  echo "::group::create user and preauth key"
  headscale_cmd -o json users create alice >"${work_dir}/user.json"
  user_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("id")' "${work_dir}/user.json")"
  headscale_cmd -o json preauthkeys create \
    --user "${user_id}" \
    --reusable \
    --expires-in 1h \
    >"${work_dir}/preauth.json"
  authkey="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("key")' "${work_dir}/preauth.json")"
  echo "minted ${authkey%%-*}-..."
  echo "::endgroup::"
}

start_client() {
  echo "::group::start stock tailscale client"
  docker run -d \
    --name "${client_name}" \
    --hostname "${client_name}" \
    --add-host host.docker.internal:host-gateway \
    --entrypoint /bin/sh \
    -v "${tls_cert_path}:/usr/local/share/ca-certificates/headscale-control.crt:ro" \
    "${image}" \
    -ceu 'update-ca-certificates >/tmp/update-ca-certificates.log 2>&1; tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity' \
    >/dev/null

  wait_for "tailscaled local socket" \
    "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
  echo "::endgroup::"
}

login_client() {
  echo "::group::tailscale up"
  up_status=0
  docker exec "${client_name}" tailscale up \
    "--login-server=${control_url}" \
    "--hostname=${client_name}" \
    --timeout=60s \
    --accept-routes=false \
    --accept-dns=true \
    "--authkey=${authkey}" \
    >"${work_dir}/${client_name}.tailscale-up.stdout" \
    2>"${work_dir}/${client_name}.tailscale-up.stderr" ||
    up_status="$?"
  if ((up_status != 0)); then
    echo "tailscale up returned ${up_status}; verifying logged-in netmap"
  fi
  wait_for "logged-in client netmap" \
    "docker exec '${client_name}' tailscale status --json >'${work_dir}/${client_name}.status.json' 2>/dev/null && ruby -rjson -e 's=JSON.parse(File.read(ARGV.fetch(0))); ips=Array(s[\"TailscaleIPs\"]); ok=s[\"HaveNodeKey\"] && s[\"AuthURL\"].to_s.empty? && (s[\"Self\"]||{})[\"InNetworkMap\"] && ips.any? { |ip| ip.to_s.include?(\".\") }; exit(ok ? 0 : 1)' '${work_dir}/${client_name}.status.json'"
  echo "::endgroup::"
}

assert_dns_netmap() {
  local expected_name="$1"
  local expected_type="$2"
  local expected_value="$3"
  local output_path="$4"
  local netmap_path="${output_path}.netmap"
  docker exec "${client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      netmap = JSON.parse(File.read(ARGV.fetch(0)))
      expected_name = ARGV.fetch(1).sub(/\.\z/, "")
      expected_type = ARGV.fetch(2)
      expected_value = ARGV.fetch(3)
      dns = netmap.fetch("DNS")
      cert_domains = Array(dns["CertDomains"])
      abort("expected no CertDomains from control-plane HTTPS, got #{cert_domains.inspect}") unless cert_domains.empty?
      records = Array(dns["ExtraRecords"])
      abort("expected exactly one ExtraRecord, got #{records.inspect}") unless records.length == 1
      record = records.fetch(0)
      name = (record["Name"] || record["name"]).to_s.sub(/\.\z/, "")
      type = (record["Type"] || record["type"]).to_s
      value = (record["Value"] || record["value"]).to_s
      unless name == expected_name && type == expected_type && value == expected_value
        abort("expected #{expected_name}=#{expected_type}:#{expected_value}, got #{records.inspect}")
      end
      puts JSON.pretty_generate({"CertDomains" => cert_domains, "ExtraRecords" => records})
    ' "${netmap_path}" "${expected_name}" "${expected_type}" "${expected_value}" >"${output_path}"
}

need cargo
need curl
need docker
need ruby

http_port="$(free_port)"
https_port="$(free_port)"
grpc_port="$(free_port)"
control_url="https://host.docker.internal:${https_port}"
local_control_url="http://127.0.0.1:${http_port}"

write_records "before.${base_domain}" "A" "100.64.0.50"
start_server
create_user_and_key
start_client
login_client

echo "::group::assert initial DNS extra records"
wait_for "initial DNS extra record" \
  "assert_dns_netmap 'before.${base_domain}' 'A' '100.64.0.50' '${work_dir}/dns-before.json'" || {
    dump_debug
    exit 1
  }
cat "${work_dir}/dns-before.json"
echo "::endgroup::"

echo "::group::edit extra-records file"
write_records "after.${base_domain}" "AAAA" "fd7a:115c:a1e0::53"
echo "::endgroup::"

echo "::group::assert hot-reloaded DNS extra records"
wait_for "hot-reloaded DNS extra record" \
  "assert_dns_netmap 'after.${base_domain}' 'AAAA' 'fd7a:115c:a1e0::53' '${work_dir}/dns-after.json'" || {
    dump_debug
    exit 1
  }
cat "${work_dir}/dns-after.json"
echo "::endgroup::"

echo "headscale-rs production DNS hot-reload real-client smoke passed"
