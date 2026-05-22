#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/authkey-smoke}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-120}"
advertise_routes="${REAL_CLIENT_ADVERTISE_ROUTES:-}"
expected_available_routes="${REAL_CLIENT_EXPECT_AVAILABLE_ROUTES:-${advertise_routes}}"
approve_routes="${REAL_CLIENT_APPROVE_ROUTES:-}"
expected_approved_routes="${REAL_CLIENT_EXPECT_APPROVED_ROUTES:-${approve_routes}}"
run_id="hsrs-authkey-$(date +%s)-$$"
case "${work_root}" in
  /*) work_dir="${work_root}/${run_id}" ;;
  *) work_dir="${repo_root}/${work_root}/${run_id}" ;;
esac
mkdir -p "${work_dir}"

http_port=""
https_port=""
harness_pid=""
client_name="${run_id}-client"

cleanup() {
  if [[ -n "${client_name}" ]]; then
    docker rm -f "${client_name}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${harness_pid}" ]]; then
    kill "${harness_pid}" >/dev/null 2>&1 || true
    wait "${harness_pid}" >/dev/null 2>&1 || true
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

need cargo
need curl
need docker
need ruby

http_port="$(free_port)"
https_port="$(free_port)"

echo "::group::build headscale-rs real-client harness"
cargo build --quiet --manifest-path tools/real-client/headscale-rs-harness/Cargo.toml
echo "::endgroup::"

echo "::group::start headscale-rs harness"
tools/real-client/headscale-rs-harness/target/debug/headscale-rs-real-client-harness \
  --http "127.0.0.1:${http_port}" \
  --https "0.0.0.0:${https_port}" \
  --hostname host.docker.internal \
  --public-url "https://host.docker.internal:${https_port}" \
  --base-domain tail.test \
  --state-dir "${work_dir}/state" \
  >"${work_dir}/harness.stdout" \
  2>"${work_dir}/harness.stderr" &
harness_pid="$!"

wait_for "harness health" \
  "curl -fsS 'http://127.0.0.1:${http_port}/harness/health' >/dev/null"
test -s "${work_dir}/state/tls.crt"
echo "harness http=http://127.0.0.1:${http_port}"
echo "harness login=https://host.docker.internal:${https_port}"
echo "::endgroup::"

echo "::group::mint preauth key"
preauth_json="$(
  curl -fsS -X POST "http://127.0.0.1:${http_port}/harness/preauth" \
    -H 'content-type: application/json' \
    -d '{"user":"alice","reusable":true}'
)"
authkey="$(ruby -rjson -e 'puts JSON.parse(STDIN.read).fetch("key")' <<<"${preauth_json}")"
echo "minted ${authkey%%-*}-..."
echo "::endgroup::"

echo "::group::start stock tailscale client"
docker run -d \
  --name "${client_name}" \
  --hostname "${client_name}" \
  --add-host host.docker.internal:host-gateway \
  -v "${work_dir}/state/tls.crt:/usr/local/share/ca-certificates/headscale-rs.crt:ro" \
  --entrypoint /bin/sh \
  "${image}" \
  -ceu 'update-ca-certificates >/tmp/update-ca-certificates.log 2>&1; tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity' \
  >/dev/null

wait_for "tailscaled local socket" \
  "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
echo "::endgroup::"

echo "::group::tailscale up"
up_args=(
  tailscale up
  "--login-server=https://host.docker.internal:${https_port}"
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
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-before-approve.json"
  node_key="$(
    ruby -rjson -e '
      machines = JSON.parse(File.read(ARGV.fetch(0)))
      abort("expected one registered machine, got #{machines.length}") unless machines.length == 1
      puts machines.fetch(0).fetch("node_key")
    ' "${work_dir}/machines-before-approve.json"
  )"
  routes_json="$(ruby -rjson -e 'puts JSON.generate({routes: ARGV.fetch(0).split(",").reject(&:empty?)})' "${approve_routes}")"
  curl -fsS -X PUT "http://127.0.0.1:${http_port}/harness/machines/${node_key}/routes" \
    -H 'content-type: application/json' \
    -d "${routes_json}" \
    >"${work_dir}/approved-routes.json"
  echo "::endgroup::"
fi

echo "::group::assert harness machine state"
curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines.json"
ruby -rjson -e '
  expected_routes = ARGV.fetch(1).split(",").reject(&:empty?).sort
  expected_approved = ARGV.fetch(2).split(",").reject(&:empty?).sort
  machines = JSON.parse(File.read(ARGV.fetch(0)))
  abort("expected one registered machine, got #{machines.length}") unless machines.length == 1
  machine = machines.fetch(0)
  abort("expected user alice, got #{machine["user"].inspect}") unless machine["user"] == "alice"
  abort("expected hostname prefix, got #{machine["hostname"].inspect}") unless machine["hostname"].start_with?("hsrs-authkey-")
  abort("expected CGNAT IPv4, got #{machine["ipv4"].inspect}") unless machine["ipv4"].start_with?("100.")
  available_routes = Array(machine["available_routes"]).sort
  unless expected_routes.empty? || available_routes == expected_routes
    abort("expected available routes #{expected_routes.inspect}, got #{available_routes.inspect}")
  end
  approved_routes = Array(machine["approved_routes"]).sort
  unless expected_approved.empty? || approved_routes == expected_approved
    abort("expected approved routes #{expected_approved.inspect}, got #{approved_routes.inspect}")
  end
  puts JSON.pretty_generate(machine)
' "${work_dir}/machines.json" "${expected_available_routes}" "${expected_approved_routes}"
echo "::endgroup::"

echo "auth-key real-client smoke passed"
