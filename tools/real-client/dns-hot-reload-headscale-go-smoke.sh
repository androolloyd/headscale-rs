#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-baseline.sh
source tools/real-client/headscale-go-baseline.sh

headscale_go_version="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_BASELINE_VERSION}}"
image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-180}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/dns-hot-reload-headscale-go-smoke}"
run_id="hs-dns-hot-reload-go-$(date +%s)-$$"
client_name="${REAL_CLIENT_CLIENT_NAME:-${run_id}-client}"
base_domain="${REAL_CLIENT_BASE_DOMAIN:-tail.test}"
database_backend="${REAL_CLIENT_DATABASE_BACKEND:-sqlite}"

case "${database_backend}" in
  sqlite | postgres) ;;
  *)
    echo "REAL_CLIENT_DATABASE_BACKEND must be sqlite or postgres" >&2
    exit 2
    ;;
esac

# shellcheck source=tools/real-client/postgres-test-db-common.sh
source tools/real-client/postgres-test-db-common.sh

case "${work_root}" in
  /*) work_dir="${work_root}/${run_id}" ;;
  *) work_dir="${repo_root}/${work_root}/${run_id}" ;;
esac
mkdir -p "${work_dir}"

http_port=""
grpc_port=""
metrics_port=""
server_pid=""
config_path="${work_dir}/config.yaml"
socket_path="/tmp/${run_id}.sock"
extra_records_path="${work_dir}/extra-records.json"
control_url=""
local_control_url=""
headscale_bin="${HEADSCALE_GO_BIN:-${work_dir}/bin/headscale}"
authkey=""

cleanup() {
  docker rm -f "${client_name}" >/dev/null 2>&1 || true
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
      echo "headscale-go server exited while waiting for ${label}" >&2
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

headscale_cmd() {
  "${headscale_bin}" -c "${config_path}" "$@"
}

dump_debug() {
  dump_server_logs "debug snapshot"
  headscale_cmd -o json nodes list 2>&1 || true
  docker exec "${client_name}" tailscale status 2>&1 || true
  docker exec "${client_name}" sh -c 'tail -180 /tmp/tailscaled.log 2>/dev/null || true' >&2 || true
}

dump_server_logs() {
  local reason="$1"
  local path
  if [[ -n "${local_control_url}" ]]; then
    server_health_probe >/dev/null 2>&1 || true
  fi
  if [[ -s "${config_path}" ]]; then
    server_grpc_health_probe >/dev/null 2>&1 || true
  fi
  echo "::group::headscale-go server debug (${reason})"
  for path in \
    "${work_dir}/headscale-go.stderr" \
    "${work_dir}/headscale-go.stdout" \
    "${work_dir}/headscale-go-health.stderr" \
    "${work_dir}/headscale-go-health.stdout" \
    "${work_dir}/headscale-go-grpc-health.stderr" \
    "${work_dir}/headscale-go-grpc-health.stdout" \
    "${work_dir}/headscale-version.txt"; do
    if [[ -s "${path}" ]]; then
      echo "--- ${path} ---" >&2
      tail -200 "${path}" >&2 || true
    fi
  done
  echo "--- socket ${socket_path} ---" >&2
  ls -l "${socket_path}" >&2 || true
  echo "::endgroup::"
}

server_health_probe() {
  curl -fsS "${local_control_url}/health" \
    >"${work_dir}/headscale-go-health.stdout" \
    2>"${work_dir}/headscale-go-health.stderr"
}

server_grpc_health_probe() {
  headscale_cmd health \
    >"${work_dir}/headscale-go-grpc-health.stdout" \
    2>"${work_dir}/headscale-go-grpc-health.stderr"
}

write_records() {
  local record_name="$1"
  local record_type="$2"
  local record_value="$3"
  ruby -rjson -e 'puts JSON.generate([{"Name" => ARGV[0], "Type" => ARGV[1], "Value" => ARGV[2]}])' \
    "${record_name}" "${record_type}" "${record_value}" >"${extra_records_path}"
}

write_database_config() {
  case "${database_backend}" in
    sqlite)
      cat <<EOF
database:
  type: sqlite
  sqlite:
    path: ${work_dir}/db.sqlite
EOF
      ;;
    postgres) real_client_write_postgres_database_config ;;
  esac
}

write_config() {
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
unix_socket: ${socket_path}
unix_socket_permission: "0700"

private_key_path: ${work_dir}/private.key
noise:
  private_key_path: ${work_dir}/noise_private.key

prefixes:
  allocation: sequential
  v4: 100.64.0.0/10

EOF
  write_database_config >>"${config_path}"
  cat >>"${config_path}" <<EOF

dns:
  magic_dns: true
  base_domain: "${base_domain}"
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []
  extra_records_path: ${extra_records_path}

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
EOF
}

install_headscale_go() {
  echo "::group::build headscale-go ${headscale_go_version}"
  if [[ -z "${HEADSCALE_GO_BIN:-}" ]]; then
    GOBIN="${work_dir}/bin" go install "github.com/juanfont/headscale/cmd/headscale@${headscale_go_version}"
  fi
  "${headscale_bin}" version >"${work_dir}/headscale-version.txt"
  cat "${work_dir}/headscale-version.txt"
  echo "::endgroup::"
}

start_server() {
  write_config
  rm -f "${socket_path}"

  echo "::group::start headscale-go"
  printf '\n--- headscale-go start %s ---\n' "$(date -u +%FT%TZ)" >>"${work_dir}/headscale-go.stdout"
  printf '\n--- headscale-go start %s ---\n' "$(date -u +%FT%TZ)" >>"${work_dir}/headscale-go.stderr"
  "${headscale_bin}" -c "${config_path}" serve \
    >>"${work_dir}/headscale-go.stdout" \
    2>>"${work_dir}/headscale-go.stderr" &
  server_pid="$!"
  wait_for "headscale-go health" "server_health_probe"
  wait_for "headscale-go gRPC" "server_grpc_health_probe"
  echo "headscale-go control=${local_control_url}"
  echo "headscale-go login=${control_url}"
  echo "::endgroup::"
}

create_user_and_key() {
  echo "::group::create user and preauth key"
  headscale_cmd -o json users create alice >"${work_dir}/user.json"
  user_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("id")' "${work_dir}/user.json")"
  headscale_cmd -o json preauthkeys create \
    --user "${user_id}" \
    --reusable \
    --expiration 1h \
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
    "${image}" \
    -ceu 'tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity' \
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
      abort("expected no CertDomains, got #{cert_domains.inspect}") unless cert_domains.empty?
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

assert_dns_resolution() {
  local expected_name="$1"
  local network="$2"
  local expected_value="$3"
  local output_path="$4"
  local raw_path="${output_path}.raw"
  docker exec "${client_name}" tailscale debug resolve "--net=${network}" "${expected_name}" \
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

need ruby
if [[ "${database_backend}" == "postgres" ]]; then
  real_client_prepare_postgres_database \
    "Postgres headscale-go DNS hot-reload real-client smoke" \
    "headscale_rs_pg_dns_hot_reload_go"
fi
need curl
need docker
[[ -n "${HEADSCALE_GO_BIN:-}" ]] || need go

http_port="$(free_port)"
grpc_port="$(free_port)"
metrics_port="$(free_port)"
control_url="http://host.docker.internal:${http_port}"
local_control_url="http://127.0.0.1:${http_port}"

write_records "before.${base_domain}" "A" "100.64.0.50"
install_headscale_go
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

echo "::group::assert initial DNS client resolution"
wait_for "initial DNS client resolution" \
  "assert_dns_resolution 'before.${base_domain}' 'ip4' '100.64.0.50' '${work_dir}/dns-before-resolution.json'" || {
    dump_debug
    exit 1
  }
cat "${work_dir}/dns-before-resolution.json"
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

echo "::group::assert hot-reloaded DNS client resolution"
wait_for "hot-reloaded DNS client resolution" \
  "assert_dns_resolution 'after.${base_domain}' 'ip6' 'fd7a:115c:a1e0::53' '${work_dir}/dns-after-resolution.json'" || {
    dump_debug
    exit 1
  }
cat "${work_dir}/dns-after-resolution.json"
echo "::endgroup::"

echo "headscale-go production ${database_backend} DNS hot-reload real-client smoke passed"
