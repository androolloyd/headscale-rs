#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/authkey-smoke}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-120}"
client_count="${REAL_CLIENT_CLIENT_COUNT:-1}"
login_mode="${REAL_CLIENT_LOGIN_MODE:-authkey}"
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
up_timeout="${REAL_CLIENT_TAILSCALE_UP_TIMEOUT:-}"
if [[ -z "${up_timeout}" ]]; then
  if [[ "${login_mode}" == "web" ]]; then
    up_timeout="45s"
  else
    up_timeout="15s"
  fi
fi
run_id="hsrs-${login_mode}-$(date +%s)-$$"
case "${work_root}" in
  /*) work_dir="${work_root}/${run_id}" ;;
  *) work_dir="${repo_root}/${work_root}/${run_id}" ;;
esac
mkdir -p "${work_dir}"

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
https_port=""
harness_pid=""
client_names=()
for ((idx = 1; idx <= client_count; idx++)); do
  if ((client_count == 1)); then
    client_names+=("${run_id}-client")
  else
    client_names+=("${run_id}-client-${idx}")
  fi
done

cleanup() {
  for client_name in "${client_names[@]}"; do
    docker rm -f "${client_name}" >/dev/null 2>&1 || true
  done
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

if [[ -n "${policy_json}" ]]; then
  echo "::group::load policy"
  curl -fsS -X PUT "http://127.0.0.1:${http_port}/harness/policy" \
    -H 'content-type: application/json' \
    --data-binary "${policy_json}" \
    >"${work_dir}/policy-load.txt"
  echo "::endgroup::"
fi

authkey=""
if [[ "${login_mode}" == "authkey" ]]; then
  echo "::group::mint preauth key"
  preauth_body="$(
    ruby -rjson -e '
      tags = ARGV.fetch(0).split(",").reject(&:empty?)
      puts JSON.generate({user: "alice", reusable: true, tags: tags})
    ' "${preauth_tags}"
  )"
  preauth_json="$(
    curl -fsS -X POST "http://127.0.0.1:${http_port}/harness/preauth" \
      -H 'content-type: application/json' \
      -d "${preauth_body}"
  )"
  authkey="$(ruby -rjson -e 'puts JSON.parse(STDIN.read).fetch("key")' <<<"${preauth_json}")"
  echo "minted ${authkey%%-*}-..."
  echo "::endgroup::"
fi

echo "::group::start stock tailscale client"
for client_name in "${client_names[@]}"; do
  docker run -d \
    --name "${client_name}" \
    --hostname "${client_name}" \
    --add-host host.docker.internal:host-gateway \
    -v "${work_dir}/state/tls.crt:/usr/local/share/ca-certificates/headscale-rs.crt:ro" \
    --entrypoint /bin/sh \
    "${image}" \
    -ceu 'update-ca-certificates >/tmp/update-ca-certificates.log 2>&1; tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity' \
    >/dev/null

  wait_for "tailscaled local socket ${client_name}" \
    "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
done
echo "::endgroup::"

echo "::group::tailscale up"
for client_name in "${client_names[@]}"; do
  up_args=(
    tailscale up
    "--login-server=https://host.docker.internal:${https_port}"
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
    curl -fsS -X POST "http://127.0.0.1:${http_port}/harness/register/${registration_id}" \
      -H 'content-type: application/json' \
      -d '{"user":"alice"}' \
      >"${work_dir}/${client_name}.registered.json"
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

if [[ -n "${approve_routes}" ]]; then
  echo "::group::approve routes"
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-before-approve.json"
  node_key="$(
    ruby -rjson -e '
      machines = JSON.parse(File.read(ARGV.fetch(0)))
      expected = Integer(ARGV.fetch(1))
      abort("expected #{expected} registered machines, got #{machines.length}") unless machines.length == expected
      puts machines.map { |machine| machine.fetch("node_key") }
    ' "${work_dir}/machines-before-approve.json" "${expected_machine_count}"
  )"
  routes_json="$(ruby -rjson -e 'puts JSON.generate({routes: ARGV.fetch(0).split(",").reject(&:empty?)})' "${approve_routes}")"
  while IFS= read -r node_key; do
    curl -fsS -X PUT "http://127.0.0.1:${http_port}/harness/machines/${node_key}/routes" \
      -H 'content-type: application/json' \
      -d "${routes_json}" \
      >"${work_dir}/approved-routes-${node_key#nodekey:}.json"
  done <<<"${node_key}"
  echo "::endgroup::"
fi

echo "::group::assert harness machine state"
curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines.json"
if [[ -n "${expected_primary_route}" ]]; then
  curl -fsS -H 'accept: application/json' \
    "http://127.0.0.1:${http_port}/debug/routes" \
    >"${work_dir}/debug-routes.json"
else
  printf '{}\n' >"${work_dir}/debug-routes.json"
fi
ruby -rjson -e '
  expected_routes = ARGV.fetch(1).split(",").reject(&:empty?).sort
  expected_approved = ARGV.fetch(2).split(",").reject(&:empty?).sort
  expected_count = Integer(ARGV.fetch(3))
  expected_primary_route = ARGV.fetch(4)
  debug_routes_path = ARGV.fetch(5)
  expected_tags = ARGV.fetch(6).split(",").reject(&:empty?).sort
  expected_hostname_prefix = ARGV.fetch(7)

  def stable_id_from_key(hex)
    h = 0xcbf29ce484222325
    hex.each_byte do |byte|
      h ^= byte
      h = (h * 0x100000001b3) & 0xffffffffffffffff
    end
    h & 0x7fffffffffffffff
  end

  machines = JSON.parse(File.read(ARGV.fetch(0)))
  abort("expected #{expected_count} registered machines, got #{machines.length}") unless machines.length == expected_count
  machines.each do |machine|
    abort("expected user alice, got #{machine["user"].inspect}") unless machine["user"] == "alice"
    abort("expected hostname prefix #{expected_hostname_prefix.inspect}, got #{machine["hostname"].inspect}") unless machine["hostname"].start_with?(expected_hostname_prefix)
    abort("expected CGNAT IPv4, got #{machine["ipv4"].inspect}") unless machine["ipv4"].start_with?("100.")
    available_routes = Array(machine["available_routes"]).sort
    unless expected_routes.empty? || available_routes == expected_routes
      abort("expected available routes #{expected_routes.inspect}, got #{available_routes.inspect}")
    end
    approved_routes = Array(machine["approved_routes"]).sort
    unless expected_approved.empty? || approved_routes == expected_approved
      abort("expected approved routes #{expected_approved.inspect}, got #{approved_routes.inspect}")
    end
    forced_tags = Array(machine["forced_tags"]).sort
    unless expected_tags.empty? || forced_tags == expected_tags
      abort("expected forced tags #{expected_tags.inspect}, got #{forced_tags.inspect}")
    end
  end

  debug_routes = nil
  unless expected_primary_route.empty?
    debug_routes = JSON.parse(File.read(debug_routes_path))
    primary_owner = debug_routes.fetch("primary_routes").fetch(expected_primary_route) {
      abort("missing primary route #{expected_primary_route.inspect} in #{debug_routes.inspect}")
    }
    node_ids = machines.map { |machine| stable_id_from_key(machine.fetch("node_key").sub(/\Anodekey:/, "")) }
    abort("primary route owner #{primary_owner.inspect} not in registered node IDs #{node_ids.inspect}") unless node_ids.include?(primary_owner)
    available_entries = debug_routes.fetch("available_routes").select do |_node_id, routes|
      Array(routes).include?(expected_primary_route)
    end
    abort("expected #{expected_count} available primary-route candidates, got #{available_entries.length}") unless available_entries.length == expected_count
  end

  if expected_count == 1
    puts JSON.pretty_generate(machines.fetch(0))
  else
    puts JSON.pretty_generate({machines: machines, debug_routes: debug_routes})
  end
' "${work_dir}/machines.json" "${expected_available_routes}" "${expected_approved_routes}" "${expected_machine_count}" "${expected_primary_route}" "${work_dir}/debug-routes.json" "${expected_tags}" "${run_id}"
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
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-before-failover.json"
  curl -fsS -H 'accept: application/json' \
    "http://127.0.0.1:${http_port}/debug/routes" \
    >"${work_dir}/debug-routes-before-failover.json"
  failover_node_key="$(
    ruby -rjson -e '
      route = ARGV.fetch(2)

      def stable_id_from_key(hex)
        h = 0xcbf29ce484222325
        hex.each_byte do |byte|
          h ^= byte
          h = (h * 0x100000001b3) & 0xffffffffffffffff
        end
        h & 0x7fffffffffffffff
      end

      machines = JSON.parse(File.read(ARGV.fetch(0)))
      debug_routes = JSON.parse(File.read(ARGV.fetch(1)))
      primary_owner = debug_routes.fetch("primary_routes").fetch(route) {
        abort("missing primary route #{route.inspect} before failover")
      }
      machine = machines.find do |candidate|
        stable_id_from_key(candidate.fetch("node_key").sub(/\Anodekey:/, "")) == primary_owner
      end
      abort("primary owner #{primary_owner.inspect} did not match a registered machine") unless machine
      puts machine.fetch("node_key")
    ' "${work_dir}/machines-before-failover.json" "${work_dir}/debug-routes-before-failover.json" "${expected_primary_failover_route}"
  )"
  curl -fsS -X PUT "http://127.0.0.1:${http_port}/harness/machines/${failover_node_key}/routes" \
    -H 'content-type: application/json' \
    -d '{"routes":[]}' \
    >"${work_dir}/failover-clear-primary.json"
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-after-failover.json"
  curl -fsS -H 'accept: application/json' \
    "http://127.0.0.1:${http_port}/debug/routes" \
    >"${work_dir}/debug-routes-after-failover.json"
  ruby -rjson -e '
    route = ARGV.fetch(4)
    cleared_node_key = ARGV.fetch(5)
    expected_count = Integer(ARGV.fetch(6))

    def stable_id_from_key(hex)
      h = 0xcbf29ce484222325
      hex.each_byte do |byte|
        h ^= byte
        h = (h * 0x100000001b3) & 0xffffffffffffffff
      end
      h & 0x7fffffffffffffff
    end

    before_machines = JSON.parse(File.read(ARGV.fetch(0)))
    before_debug = JSON.parse(File.read(ARGV.fetch(1)))
    after_machines = JSON.parse(File.read(ARGV.fetch(2)))
    after_debug = JSON.parse(File.read(ARGV.fetch(3)))
    abort("expected #{expected_count} machines before failover, got #{before_machines.length}") unless before_machines.length == expected_count
    abort("expected #{expected_count} machines after failover, got #{after_machines.length}") unless after_machines.length == expected_count

    before_owner = before_debug.fetch("primary_routes").fetch(route)
    after_owner = after_debug.fetch("primary_routes").fetch(route) {
      abort("missing primary route #{route.inspect} after failover")
    }
    abort("expected primary owner to change, still #{after_owner.inspect}") if after_owner == before_owner

    cleared = after_machines.find { |machine| machine.fetch("node_key") == cleared_node_key }
    abort("missing cleared machine #{cleared_node_key}") unless cleared
    abort("cleared machine still has approved route #{route}") if Array(cleared["approved_routes"]).include?(route)

    remaining_ids = after_machines
      .reject { |machine| machine.fetch("node_key") == cleared_node_key }
      .select { |machine| Array(machine["approved_routes"]).include?(route) }
      .map { |machine| stable_id_from_key(machine.fetch("node_key").sub(/\Anodekey:/, "")) }
    abort("new primary owner #{after_owner.inspect} not among remaining approved routers #{remaining_ids.inspect}") unless remaining_ids.include?(after_owner)

    active_candidates = after_debug.fetch("available_routes").select do |_node_id, routes|
      Array(routes).include?(route)
    end
    abort("expected #{expected_count - 1} active candidates after failover, got #{active_candidates.length}") unless active_candidates.length == expected_count - 1

    puts JSON.pretty_generate({
      cleared_node_key: cleared_node_key,
      before_owner: before_owner,
      after_owner: after_owner,
      debug_routes: after_debug,
    })
  ' "${work_dir}/machines-before-failover.json" "${work_dir}/debug-routes-before-failover.json" "${work_dir}/machines-after-failover.json" "${work_dir}/debug-routes-after-failover.json" "${expected_primary_failover_route}" "${failover_node_key}" "${expected_machine_count}"
  echo "::endgroup::"
fi

if [[ -n "${expected_primary_withdraw_route}" ]]; then
  echo "::group::assert primary route withdrawal"
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-before-withdraw.json"
  curl -fsS -H 'accept: application/json' \
    "http://127.0.0.1:${http_port}/debug/routes" \
    >"${work_dir}/debug-routes-before-withdraw.json"
  withdraw_client_name="$(
    ruby -rjson -e '
      route = ARGV.fetch(2)

      def stable_id_from_key(hex)
        h = 0xcbf29ce484222325
        hex.each_byte do |byte|
          h ^= byte
          h = (h * 0x100000001b3) & 0xffffffffffffffff
        end
        h & 0x7fffffffffffffff
      end

      machines = JSON.parse(File.read(ARGV.fetch(0)))
      debug_routes = JSON.parse(File.read(ARGV.fetch(1)))
      primary_owner = debug_routes.fetch("primary_routes").fetch(route) {
        abort("missing primary route #{route.inspect} before withdrawal")
      }
      machine = machines.find do |candidate|
        stable_id_from_key(candidate.fetch("node_key").sub(/\Anodekey:/, "")) == primary_owner
      end
      abort("primary owner #{primary_owner.inspect} did not match a registered machine") unless machine
      puts machine.fetch("hostname")
    ' "${work_dir}/machines-before-withdraw.json" "${work_dir}/debug-routes-before-withdraw.json" "${expected_primary_withdraw_route}"
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
    curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-after-withdraw.json" &&
      curl -fsS -H 'accept: application/json' \
        "http://127.0.0.1:${http_port}/debug/routes" \
        >"${work_dir}/debug-routes-after-withdraw.json" &&
      ruby -rjson -e '
        route = ARGV.fetch(4)
        withdrawn_client = ARGV.fetch(5)
        expected_count = Integer(ARGV.fetch(6))

        def stable_id_from_key(hex)
          h = 0xcbf29ce484222325
          hex.each_byte do |byte|
            h ^= byte
            h = (h * 0x100000001b3) & 0xffffffffffffffff
          end
          h & 0x7fffffffffffffff
        end

        before_machines = JSON.parse(File.read(ARGV.fetch(0)))
        before_debug = JSON.parse(File.read(ARGV.fetch(1)))
        after_machines = JSON.parse(File.read(ARGV.fetch(2)))
        after_debug = JSON.parse(File.read(ARGV.fetch(3)))
        abort("expected #{expected_count} machines before withdrawal, got #{before_machines.length}") unless before_machines.length == expected_count
        abort("expected #{expected_count} machines after withdrawal, got #{after_machines.length}") unless after_machines.length == expected_count

        before_owner = before_debug.fetch("primary_routes").fetch(route)
        after_owner = after_debug.fetch("primary_routes").fetch(route) {
          abort("missing primary route #{route.inspect} after withdrawal")
        }
        abort("expected primary owner to change, still #{after_owner.inspect}") if after_owner == before_owner

        withdrawn = after_machines.find { |machine| machine.fetch("hostname") == withdrawn_client }
        abort("missing withdrawn client #{withdrawn_client}") unless withdrawn
        abort("withdrawn client still advertises #{route}") if Array(withdrawn["available_routes"]).include?(route)

        remaining_ids = after_machines
          .reject { |machine| machine.fetch("hostname") == withdrawn_client }
          .select { |machine| Array(machine["available_routes"]).include?(route) && Array(machine["approved_routes"]).include?(route) }
          .map { |machine| stable_id_from_key(machine.fetch("node_key").sub(/\Anodekey:/, "")) }
        abort("new primary owner #{after_owner.inspect} not among remaining active routers #{remaining_ids.inspect}") unless remaining_ids.include?(after_owner)

        active_candidates = after_debug.fetch("available_routes").select do |_node_id, routes|
          Array(routes).include?(route)
        end
        abort("expected #{expected_count - 1} active candidates after withdrawal, got #{active_candidates.length}") unless active_candidates.length == expected_count - 1

        puts JSON.pretty_generate({
          withdrawn_client: withdrawn_client,
          before_owner: before_owner,
          after_owner: after_owner,
          debug_routes: after_debug,
        })
      ' "${work_dir}/machines-before-withdraw.json" "${work_dir}/debug-routes-before-withdraw.json" "${work_dir}/machines-after-withdraw.json" "${work_dir}/debug-routes-after-withdraw.json" "${expected_primary_withdraw_route}" "${withdraw_client_name}" "${expected_machine_count}"
  do
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for primary route withdrawal" >&2
      exit 1
    fi
    sleep 1
  done
  echo "::endgroup::"
fi

echo "${login_mode} real-client smoke passed"
