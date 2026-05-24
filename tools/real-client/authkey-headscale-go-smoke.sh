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
advertise_routes_by_client="${REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT:-}"
advertise_exit_node="${REAL_CLIENT_ADVERTISE_EXIT_NODE:-false}"
advertise_exit_node_by_client="${REAL_CLIENT_ADVERTISE_EXIT_NODE_BY_CLIENT:-}"
expected_available_routes="${REAL_CLIENT_EXPECT_AVAILABLE_ROUTES:-${advertise_routes}}"
expected_available_routes_by_client="${REAL_CLIENT_EXPECT_AVAILABLE_ROUTES_BY_CLIENT:-}"
approve_routes="${REAL_CLIENT_APPROVE_ROUTES:-}"
approve_routes_by_client="${REAL_CLIENT_APPROVE_ROUTES_BY_CLIENT:-}"
expected_approved_routes="${REAL_CLIENT_EXPECT_APPROVED_ROUTES:-${approve_routes}}"
expected_approved_routes_by_client="${REAL_CLIENT_EXPECT_APPROVED_ROUTES_BY_CLIENT:-${approve_routes_by_client}}"
expected_machine_count="${REAL_CLIENT_EXPECT_MACHINE_COUNT:-${client_count}}"
expected_primary_route="${REAL_CLIENT_EXPECT_PRIMARY_ROUTE:-}"
expected_primary_route_candidates="${REAL_CLIENT_EXPECT_PRIMARY_ROUTE_CANDIDATES:-${expected_machine_count}}"
expected_primary_failover_route="${REAL_CLIENT_EXPECT_PRIMARY_FAILOVER_ROUTE:-}"
expected_primary_sticky_route="${REAL_CLIENT_EXPECT_PRIMARY_STICKY_ROUTE:-}"
expected_primary_withdraw_route="${REAL_CLIENT_EXPECT_PRIMARY_WITHDRAW_ROUTE:-}"
expected_withdraw_approval_preserved="${REAL_CLIENT_EXPECT_WITHDRAW_APPROVAL_PRESERVED:-false}"
expected_peer_route_owners="${REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS:-}"
expected_route_health_failover_route="${REAL_CLIENT_EXPECT_ROUTE_HEALTH_FAILOVER_ROUTE:-}"
expected_route_health_all_unhealthy_route="${REAL_CLIENT_EXPECT_ROUTE_HEALTH_ALL_UNHEALTHY_ROUTE:-}"
route_health_probe_interval_secs="${REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS:-}"
route_health_probe_timeout_secs="${REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS:-}"
preauth_tags="${REAL_CLIENT_PREAUTH_TAGS:-}"
preauth_tags_by_client="${REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT:-}"
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
accept_dns="${REAL_CLIENT_ACCEPT_DNS:-false}"
dns_extra_records_json="${REAL_CLIENT_DNS_EXTRA_RECORDS_JSON:-}"
dns_nameservers_json="${REAL_CLIENT_DNS_NAMESERVERS_JSON:-}"
dns_split_nameservers_json="${REAL_CLIENT_DNS_SPLIT_NAMESERVERS_JSON:-}"
dns_fallback_nameservers_json="${REAL_CLIENT_DNS_FALLBACK_NAMESERVERS_JSON:-}"
dns_override_local="${REAL_CLIENT_DNS_OVERRIDE_LOCAL:-}"
expected_dns_extra_records="${REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS:-${REAL_CLIENT_EXPECT_DNS_RESOLUTIONS:-}}"
expected_dns_extra_records_exact="${REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS_EXACT:-false}"
expected_dns_routes="${REAL_CLIENT_EXPECT_DNS_ROUTES:-}"
expected_dns_resolvers="${REAL_CLIENT_EXPECT_DNS_RESOLVERS:-}"
expected_dns_fallback_resolvers="${REAL_CLIENT_EXPECT_DNS_FALLBACK_RESOLVERS:-}"
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
ssh_deny_status="${REAL_CLIENT_EXPECT_SSH_DENY_STATUS:-}"
ssh_deny_stderr_regex="${REAL_CLIENT_EXPECT_SSH_DENY_STDERR_REGEX:-Permission denied \(tailscale\)|failed to evaluate SSH policy|tailnet policy does not permit you to SSH to this node}"
ssh_deny_stderr_first_line="${REAL_CLIENT_EXPECT_SSH_DENY_STDERR_FIRST_LINE:-}"
force_derp="${REAL_CLIENT_FORCE_DERP:-false}"
headscale_go_embedded_derp="${REAL_CLIENT_HEADSCALE_GO_EMBEDDED_DERP:-false}"
headscale_go_derp_region_id="${REAL_CLIENT_HEADSCALE_GO_DERP_REGION_ID:-${REAL_CLIENT_EXPECT_DERP_REGION_ID:-900}}"
headscale_go_derp_region_code="${REAL_CLIENT_HEADSCALE_GO_DERP_REGION_CODE:-${REAL_CLIENT_EXPECT_DERP_REGION_CODE:-headscale}}"
headscale_go_derp_region_name="${REAL_CLIENT_HEADSCALE_GO_DERP_REGION_NAME:-${REAL_CLIENT_EXPECT_DERP_REGION_NAME:-Headscale Embedded DERP}}"
headscale_go_derp_stun_addr="${REAL_CLIENT_HEADSCALE_GO_DERP_STUN_ADDR:-}"
headscale_go_derp_verify_clients="${REAL_CLIENT_HEADSCALE_GO_DERP_VERIFY_CLIENTS:-true}"
expected_derp_region_id="${REAL_CLIENT_EXPECT_DERP_REGION_ID:-}"
expected_derp_region_code="${REAL_CLIENT_EXPECT_DERP_REGION_CODE:-}"
expected_derp_region_name="${REAL_CLIENT_EXPECT_DERP_REGION_NAME:-}"
expected_derp_host="${REAL_CLIENT_EXPECT_DERP_HOST:-}"
expected_derp_port="${REAL_CLIENT_EXPECT_DERP_PORT:-}"
expected_derp_stun_port="${REAL_CLIENT_EXPECT_DERP_STUN_PORT:-}"
expected_derp_insecure_for_tests="${REAL_CLIENT_EXPECT_DERP_INSECURE_FOR_TESTS:-}"
expected_derp_omit_default_regions="${REAL_CLIENT_EXPECT_DERP_OMIT_DEFAULT_REGIONS:-}"
expected_derp_ping="${REAL_CLIENT_EXPECT_DERP_PING:-false}"
assert_derp_stun="${REAL_CLIENT_ASSERT_DERP_STUN:-false}"
derp_stun_probe_host="${REAL_CLIENT_DERP_STUN_PROBE_HOST:-127.0.0.1}"
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
case "${force_derp}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    force_derp_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    force_derp_flag=0
    ;;
  *)
    echo "REAL_CLIENT_FORCE_DERP must be true or false, got ${force_derp}" >&2
    exit 2
    ;;
esac
case "${headscale_go_embedded_derp}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    use_headscale_go_embedded_derp=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    use_headscale_go_embedded_derp=0
    ;;
  *)
    echo "REAL_CLIENT_HEADSCALE_GO_EMBEDDED_DERP must be true or false, got ${headscale_go_embedded_derp}" >&2
    exit 2
    ;;
esac
case "${headscale_go_derp_verify_clients}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    use_headscale_go_derp_verify_clients=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    use_headscale_go_derp_verify_clients=0
    ;;
  *)
    echo "REAL_CLIENT_HEADSCALE_GO_DERP_VERIFY_CLIENTS must be true or false, got ${headscale_go_derp_verify_clients}" >&2
    exit 2
    ;;
esac
case "${expected_derp_ping}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    expect_derp_ping_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    expect_derp_ping_flag=0
    ;;
  *)
    echo "REAL_CLIENT_EXPECT_DERP_PING must be true or false, got ${expected_derp_ping}" >&2
    exit 2
    ;;
esac
case "${assert_derp_stun}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    assert_derp_stun_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    assert_derp_stun_flag=0
    ;;
  *)
    echo "REAL_CLIENT_ASSERT_DERP_STUN must be true or false, got ${assert_derp_stun}" >&2
    exit 2
    ;;
esac
if ((expect_derp_ping_flag)) && [[ "${client_count}" =~ ^[0-9]+$ ]] && ((client_count < 2)); then
  echo "REAL_CLIENT_EXPECT_DERP_PING requires at least two clients" >&2
  exit 2
fi
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
if [[ -n "${ssh_deny_status}" && "${ssh_deny_status}" != "any" && ! "${ssh_deny_status}" =~ ^[0-9]+$ ]]; then
  echo "REAL_CLIENT_EXPECT_SSH_DENY_STATUS must be empty, any, or a non-negative integer, got ${ssh_deny_status}" >&2
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
case "${expected_withdraw_approval_preserved}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    expect_withdraw_approval_preserved=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    expect_withdraw_approval_preserved=0
    ;;
  *)
    echo "REAL_CLIENT_EXPECT_WITHDRAW_APPROVAL_PRESERVED must be true or false, got ${expected_withdraw_approval_preserved}" >&2
    exit 2
    ;;
esac
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
if ((use_headscale_go_embedded_derp)) && ((use_headscale_go_tls == 0)); then
  echo "REAL_CLIENT_HEADSCALE_GO_EMBEDDED_DERP requires REAL_CLIENT_HEADSCALE_GO_TLS=true so DERP clients can use HTTPS on server_url" >&2
  exit 2
fi
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
case "${accept_dns}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    accept_dns_arg=true
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    accept_dns_arg=false
    ;;
  *)
    echo "REAL_CLIENT_ACCEPT_DNS must be true or false, got ${accept_dns}" >&2
    exit 2
    ;;
esac
if [[ -z "${dns_override_local}" ]]; then
  dns_override_local=false
fi
case "${dns_override_local}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    dns_override_local_yaml=true
    ;;
  0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    dns_override_local_yaml=false
    ;;
  *)
    echo "REAL_CLIENT_DNS_OVERRIDE_LOCAL must be true or false, got ${dns_override_local}" >&2
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
split_client_values() {
  local spec="$1"
  local label="$2"
  split_values=()
  [[ -z "${spec}" ]] && return 0
  IFS=';' read -r -a split_values <<<"${spec}"
  if ((${#split_values[@]} != client_count)); then
    echo "${label} must contain ${client_count} semicolon-separated values, got ${spec}" >&2
    exit 2
  fi
  local idx
  for idx in "${!split_values[@]}"; do
    if [[ "${split_values[$idx]}" == "-" ]]; then
      split_values[$idx]=""
    fi
  done
}

advertise_routes_values=()
for ((idx = 0; idx < client_count; idx++)); do
  advertise_routes_values+=("${advertise_routes}")
done
split_client_values "${advertise_routes_by_client}" "REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT"
if [[ -n "${advertise_routes_by_client}" ]]; then
  advertise_routes_values=("${split_values[@]}")
fi

advertise_exit_node_values=()
for ((idx = 0; idx < client_count; idx++)); do
  advertise_exit_node_values+=("${advertise_exit_node}")
done
split_client_values "${advertise_exit_node_by_client}" "REAL_CLIENT_ADVERTISE_EXIT_NODE_BY_CLIENT"
if [[ -n "${advertise_exit_node_by_client}" ]]; then
  advertise_exit_node_values=("${split_values[@]}")
fi
for value in "${advertise_exit_node_values[@]}"; do
  case "${value}" in
    1 | true | TRUE | True | yes | YES | Yes | on | ON | On | "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off) ;;
    *)
      echo "REAL_CLIENT_ADVERTISE_EXIT_NODE_BY_CLIENT values must be true or false, got ${value}" >&2
      exit 2
      ;;
  esac
done

expected_available_routes_values=()
for ((idx = 0; idx < client_count; idx++)); do
  expected_available_routes_values+=("${expected_available_routes}")
done
split_client_values "${expected_available_routes_by_client}" "REAL_CLIENT_EXPECT_AVAILABLE_ROUTES_BY_CLIENT"
if [[ -n "${expected_available_routes_by_client}" ]]; then
  expected_available_routes_values=("${split_values[@]}")
fi
expected_available_routes_spec="$(IFS=';'; echo "${expected_available_routes_values[*]}")"
expect_available_by_client=false
if [[ -n "${expected_available_routes_by_client}" ]]; then
  expect_available_by_client=true
fi

approve_routes_values=()
for ((idx = 0; idx < client_count; idx++)); do
  approve_routes_values+=("${approve_routes}")
done
split_client_values "${approve_routes_by_client}" "REAL_CLIENT_APPROVE_ROUTES_BY_CLIENT"
if [[ -n "${approve_routes_by_client}" ]]; then
  approve_routes_values=("${split_values[@]}")
fi

expected_approved_routes_values=()
for ((idx = 0; idx < client_count; idx++)); do
  expected_approved_routes_values+=("${expected_approved_routes}")
done
split_client_values "${expected_approved_routes_by_client}" "REAL_CLIENT_EXPECT_APPROVED_ROUTES_BY_CLIENT"
if [[ -n "${expected_approved_routes_by_client}" ]]; then
  expected_approved_routes_values=("${split_values[@]}")
fi
expected_approved_routes_spec="$(IFS=';'; echo "${expected_approved_routes_values[*]}")"
expect_approved_by_client=false
if [[ -n "${expected_approved_routes_by_client}" ]]; then
  expect_approved_by_client=true
fi

if ! [[ "${expected_primary_route_candidates}" =~ ^[0-9]+$ ]] || ((expected_primary_route_candidates < 1)); then
  echo "REAL_CLIENT_EXPECT_PRIMARY_ROUTE_CANDIDATES must be a positive integer, got ${expected_primary_route_candidates}" >&2
  exit 2
fi

preauth_tags_values=()
for ((idx = 0; idx < client_count; idx++)); do
  preauth_tags_values+=("${preauth_tags}")
done
split_client_values "${preauth_tags_by_client}" "REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT"
if [[ -n "${preauth_tags_by_client}" ]]; then
  preauth_tags_values=("${split_values[@]}")
fi

if [[ -n "${route_health_probe_interval_secs}" ]] &&
  (! [[ "${route_health_probe_interval_secs}" =~ ^[0-9]+$ ]] || ((route_health_probe_interval_secs < 1))); then
  echo "REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS must be a positive integer, got ${route_health_probe_interval_secs}" >&2
  exit 2
fi
if [[ -n "${route_health_probe_timeout_secs}" ]] &&
  (! [[ "${route_health_probe_timeout_secs}" =~ ^[0-9]+$ ]] || ((route_health_probe_timeout_secs < 1))); then
  echo "REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS must be a positive integer, got ${route_health_probe_timeout_secs}" >&2
  exit 2
fi
if { [[ -n "${expected_route_health_failover_route}" ]] || [[ -n "${expected_route_health_all_unhealthy_route}" ]]; } &&
  [[ -z "${route_health_probe_interval_secs}" || -z "${route_health_probe_timeout_secs}" ]]; then
  echo "route-health assertions require REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS and REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS" >&2
  exit 2
fi
if ((expect_derp_ping_flag)) && ((client_count < 2)); then
  echo "REAL_CLIENT_EXPECT_DERP_PING requires at least two clients" >&2
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
expected_client_names_csv="$(IFS=,; echo "${client_names[*]}")"
expected_client_users_csv="$(IFS=,; echo "${client_users[*]}")"
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

peer_netmap_route_owner_matches() {
  local source_name="$1"
  local peer_name="$2"
  local route="$3"
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
    ' "${netmap_path}" "${peer_name}" "${route}" >"${output_path}"
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

assert_dns_extra_record() {
  local client_name="$1"
  local host="$2"
  local expected="$3"
  local expected_type="$4"
  local output_path="$5"
  local netmap_path="${output_path}.netmap"
  docker exec "${client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      netmap = JSON.parse(File.read(ARGV.fetch(0)))
      host = ARGV.fetch(1).sub(/\.\z/, "")
      expected = ARGV.fetch(2)
      expected_type = ARGV.fetch(3)
      records = Array(netmap.dig("DNS", "ExtraRecords"))
      match = records.any? do |record|
        name = (record["Name"] || record["name"]).to_s.sub(/\.\z/, "")
        type = (record["Type"] || record["type"]).to_s
        value = (record["Value"] || record["value"]).to_s
        name == host && value == expected && (expected_type.empty? || type == expected_type)
      end
      want = expected_type.empty? ? "#{host}=#{expected}" : "#{host}=#{expected_type}:#{expected}"
      abort("expected DNS extra record #{want}, got #{records.inspect}") unless match
      puts JSON.pretty_generate(records)
    ' "${netmap_path}" "${host}" "${expected}" "${expected_type}" >"${output_path}"
}

assert_dns_extra_records_exact() {
  local client_name="$1"
  local expected_spec="$2"
  local output_path="$3"
  local netmap_path="${output_path}.netmap"
  docker exec "${client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      def parse_expectations(spec)
        spec.split(",").reject(&:empty?).map do |entry|
          host, expected = entry.split("=", 2)
          abort("expected DNS extra record entry host=value, got #{entry.inspect}") if host.to_s.empty? || expected.to_s.empty?
          type = ""
          if expected =~ /\A(A|AAAA|CNAME):(.*)\z/
            type = Regexp.last_match(1)
            expected = Regexp.last_match(2)
          end
          [host.sub(/\.\z/, ""), type, expected]
        end
      end

      netmap = JSON.parse(File.read(ARGV.fetch(0)))
      expected = parse_expectations(ARGV.fetch(1))
      records = Array(netmap.dig("DNS", "ExtraRecords")).map do |record|
        [
          (record["Name"] || record["name"]).to_s.sub(/\.\z/, ""),
          (record["Type"] || record["type"]).to_s,
          (record["Value"] || record["value"]).to_s,
          record,
        ]
      end
      unmatched = records.dup
      expected.each do |host, type, value|
        idx = unmatched.index do |name, record_type, record_value, _|
          name == host && record_value == value && (type.empty? || record_type == type)
        end
        abort("expected DNS extra record #{host}=#{type.empty? ? value : "#{type}:#{value}"}, got #{records.map(&:last).inspect}") unless idx
        unmatched.delete_at(idx)
      end
      abort("unexpected DNS extra records #{unmatched.map(&:last).inspect}; expected #{expected.inspect}") unless unmatched.empty?
      puts JSON.pretty_generate(records.map(&:last))
    ' "${netmap_path}" "${expected_spec}" >"${output_path}"
}

assert_dns_resolver_list() {
  local client_name="$1"
  local field="$2"
  local expected_csv="$3"
  local output_path="$4"
  local netmap_path="${output_path}.netmap"
  docker exec "${client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      netmap = JSON.parse(File.read(ARGV.fetch(0)))
      field = ARGV.fetch(1)
      expected = ARGV.fetch(2).split(",").reject(&:empty?)
      resolvers = Array(netmap.dig("DNS", field))
      got = resolvers.map do |resolver|
        if resolver.is_a?(Hash)
          (resolver["Addr"] || resolver["addr"]).to_s
        else
          resolver.to_s
        end
      end
      abort("expected DNS #{field} #{expected.inspect}, got #{got.inspect}") unless got == expected
      puts JSON.pretty_generate({field => got})
    ' "${netmap_path}" "${field}" "${expected_csv}" >"${output_path}"
}

assert_dns_route() {
  local client_name="$1"
  local suffix="$2"
  local expected_csv="$3"
  local output_path="$4"
  local netmap_path="${output_path}.netmap"
  docker exec "${client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      netmap = JSON.parse(File.read(ARGV.fetch(0)))
      suffix = ARGV.fetch(1).sub(/\.\z/, "")
      expected = ARGV.fetch(2).split(",").reject(&:empty?)
      routes = netmap.dig("DNS", "Routes") || {}
      route = routes[suffix] || routes["#{suffix}."]
      abort("expected DNS route #{suffix}, got #{routes.inspect}") if route.nil?
      got = Array(route).map do |resolver|
        if resolver.is_a?(Hash)
          (resolver["Addr"] || resolver["addr"]).to_s
        else
          resolver.to_s
        end
      end
      abort("expected DNS route #{suffix}=#{expected.inspect}, got #{got.inspect}") unless got == expected
      puts JSON.pretty_generate({suffix => got})
    ' "${netmap_path}" "${suffix}" "${expected_csv}" >"${output_path}"
}

assert_stun_round_trip() {
  local host="$1"
  local port="$2"
  local output_path="$3"
  ruby -rjson -rsocket -rzlib -e '
    host = ARGV.fetch(0)
    port = Integer(ARGV.fetch(1))
    txid = "derpstun1234".bytes.take(12).pack("C*")
    software = "tailnode"
    body = [0x8022, software.bytesize].pack("nn") + software
    req = [0x0001, body.bytesize + 8, 0x2112a442].pack("nnN") + txid + body
    fingerprint = (Zlib.crc32(req) ^ 0x5354554e) & 0xffffffff
    req += [0x8028, 4, fingerprint].pack("nnN")
    ipv6 = host.include?(":")
    sock = UDPSocket.new(ipv6 ? Socket::AF_INET6 : Socket::AF_INET)
    sock.bind(ipv6 ? "::1" : "127.0.0.1", 0)
    local = sock.addr
    sock.send(req, 0, host, port)
    ready = IO.select([sock], nil, nil, 3)
    abort("timed out waiting for STUN response from #{host}:#{port}") unless ready
    data, = sock.recvfrom(1500)
    abort("short STUN response: #{data.bytesize}") if data.bytesize < 32
    type, len, cookie = data.byteslice(0, 8).unpack("nnN")
    abort("unexpected STUN type 0x#{type.to_s(16)}") unless type == 0x0101
    abort("unexpected STUN cookie 0x#{cookie.to_s(16)}") unless cookie == 0x2112a442
    abort("transaction id mismatch") unless data.byteslice(8, 12) == txid
    attr_type, attr_len = data.byteslice(20, 4).unpack("nn")
    abort("expected XOR-MAPPED-ADDRESS, got 0x#{attr_type.to_s(16)}") unless attr_type == 0x0020
    abort("truncated XOR-MAPPED-ADDRESS") if data.bytesize < 24 + attr_len
    family = data.getbyte(25)
    abort("unexpected XOR-MAPPED-ADDRESS length #{attr_len}") unless (family == 0x01 && attr_len == 8) || (family == 0x02 && attr_len == 20)
    xport = data.byteslice(26, 2).unpack1("n")
    decoded_port = xport ^ (0x2112a442 >> 16)
    expected_port = local[1]
    abort("expected reflected port #{expected_port}, got #{decoded_port}") unless decoded_port == expected_port
    File.write(ARGV.fetch(2), JSON.pretty_generate({stun: "#{host}:#{port}", family: family == 0x02 ? "ipv6" : "ipv4", reflected_port: decoded_port}))
  ' "${host}" "${port}" "${output_path}"
}

assert_derp_map() {
  local client_name="$1"
  local output_path="$2"
  local netmap_path="${output_path}.netmap"
  docker exec "${client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      path = ARGV.fetch(0)
      expected_region = ARGV.fetch(1)
      expected_code = ARGV.fetch(2)
      expected_name = ARGV.fetch(3)
      expected_host = ARGV.fetch(4)
      expected_port = ARGV.fetch(5)
      expected_stun = ARGV.fetch(6)
      expected_insecure = ARGV.fetch(7)
      expected_omit_default = ARGV.fetch(8)
      netmap = JSON.parse(File.read(path))
      derp_map = netmap.fetch("DERPMap")
      regions = derp_map.fetch("Regions")
      region = regions.fetch(expected_region) {
        abort("missing DERP region #{expected_region}; got #{regions.keys.inspect}")
      }
      abort("expected RegionCode #{expected_code.inspect}, got #{region["RegionCode"].inspect}") unless expected_code.empty? || region["RegionCode"] == expected_code
      abort("expected RegionName #{expected_name.inspect}, got #{region["RegionName"].inspect}") unless expected_name.empty? || region["RegionName"] == expected_name
      node = Array(region["Nodes"]).first || abort("region #{expected_region} has no nodes")
      abort("expected HostName #{expected_host.inspect}, got #{node["HostName"].inspect}") unless expected_host.empty? || node["HostName"] == expected_host
      unless expected_port.empty?
        port = node.fetch("DERPPort", 0).to_i
        abort("expected DERPPort #{expected_port}, got #{port}") unless port == Integer(expected_port)
      end
      unless expected_stun.empty?
        stun = node.fetch("STUNPort", 0).to_i
        abort("expected STUNPort #{expected_stun}, got #{stun}") unless stun == Integer(expected_stun)
      end
      unless expected_insecure.empty?
        insecure = !!node["InsecureForTests"]
        want = %w[1 true TRUE True yes YES Yes on ON On].include?(expected_insecure)
        abort("expected InsecureForTests #{want}, got #{insecure}") unless insecure == want
      end
      unless expected_omit_default.empty?
        omit = !!derp_map["omitDefaultRegions"]
        want = %w[1 true TRUE True yes YES Yes on ON On].include?(expected_omit_default)
        abort("expected omitDefaultRegions #{want}, got #{omit}") unless omit == want
      end
      puts JSON.pretty_generate({region: region, node: node, omitDefaultRegions: !!derp_map["omitDefaultRegions"]})
    ' "${netmap_path}" "${expected_derp_region_id}" "${expected_derp_region_code}" "${expected_derp_region_name}" "${expected_derp_host}" "${expected_derp_port}" "${expected_derp_stun_port}" "${expected_derp_insecure_for_tests}" "${expected_derp_omit_default_regions}" >"${output_path}"
}

tailscale_derp_ping_succeeded() {
  local source_name="$1"
  local target_name="$2"
  local output_path="$3"
  local target_ip
  target_ip="$(
    docker exec "${source_name}" tailscale status --json 2>/dev/null | ruby -rjson -e '
      status = JSON.parse(STDIN.read)
      target = ARGV.fetch(0)
      peer = (status["Peer"] || {}).each_value.find { |p| p["HostName"] == target }
      exit 1 unless peer
      ips = Array(peer["TailscaleIPs"])
      ips << peer["TailscaleIP"] if ips.empty? && peer["TailscaleIP"]
      puts ips.first
    ' "${target_name}"
  )" || return 1
  docker exec "${source_name}" tailscale ping --timeout=5s --c=1 --until-direct=false "${target_ip}" \
    >"${output_path}" \
    2>"${output_path}.err" || return 1
  if [[ -n "${expected_derp_region_code}" ]]; then
    grep -Eq "via DERP\\(${expected_derp_region_code}\\)" "${output_path}"
  else
    grep -Eq "via DERP\\(" "${output_path}"
  fi
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
if ((use_headscale_go_embedded_derp)); then
  if [[ -z "${headscale_go_derp_stun_addr}" ]]; then
    headscale_go_derp_stun_addr="0.0.0.0:3478"
  fi
  expected_derp_region_id="${expected_derp_region_id:-${headscale_go_derp_region_id}}"
  expected_derp_region_code="${expected_derp_region_code:-${headscale_go_derp_region_code}}"
  expected_derp_region_name="${expected_derp_region_name:-${headscale_go_derp_region_name}}"
  expected_derp_host="${expected_derp_host:-host.docker.internal}"
  expected_derp_port="${expected_derp_port:-${http_port}}"
  if [[ -z "${expected_derp_stun_port}" && "${headscale_go_derp_stun_addr}" =~ :([0-9]+)$ ]]; then
    expected_derp_stun_port="${BASH_REMATCH[1]}"
  fi
fi
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
  override_local_dns: ${dns_override_local_yaml}
  nameservers:
EOF
if [[ -n "${dns_nameservers_json}" ]]; then
  ruby -rjson -e '
    puts "    global:"
    JSON.parse(ARGV.fetch(0)).each do |resolver|
      addr = resolver.is_a?(Hash) ? (resolver["Addr"] || resolver["addr"]) : resolver
      abort("DNS resolver needs addr/Addr: #{resolver.inspect}") if addr.to_s.empty?
      puts "      - #{addr.to_s.to_json}"
    end
  ' "${dns_nameservers_json}" >>"${config_path}"
else
  printf '    global: []\n' >>"${config_path}"
fi
if [[ -n "${dns_split_nameservers_json}" ]]; then
  ruby -rjson -e '
    puts "    split:"
    JSON.parse(ARGV.fetch(0)).sort.each do |suffix, resolvers|
      puts "      #{suffix.to_s.to_json}:"
      Array(resolvers).each do |resolver|
        addr = resolver.is_a?(Hash) ? (resolver["Addr"] || resolver["addr"]) : resolver
        abort("DNS split resolver needs addr/Addr: #{resolver.inspect}") if addr.to_s.empty?
        puts "        - #{addr.to_s.to_json}"
      end
    end
  ' "${dns_split_nameservers_json}" >>"${config_path}"
else
  printf '    split: {}\n' >>"${config_path}"
fi
cat >>"${config_path}" <<EOF
  search_domains: []
EOF
if [[ -n "${dns_extra_records_json}" ]]; then
  printf '  extra_records:\n' >>"${config_path}"
  ruby -rjson -e '
    JSON.parse(ARGV.fetch(0)).each do |record|
      name = record["Name"] || record["name"]
      type = record["Type"] || record["type"] || ""
      value = record["Value"] || record["value"]
      abort("extra DNS records need Name/name and Value/value: #{record.inspect}") if name.to_s.empty? || value.to_s.empty?
      puts "    - name: #{name.to_s.to_json}"
      puts "      type: #{type.to_s.to_json}" unless type.to_s.empty?
      puts "      value: #{value.to_s.to_json}"
    end
  ' "${dns_extra_records_json}" >>"${config_path}"
else
  printf '  extra_records: []\n' >>"${config_path}"
fi
cat >>"${config_path}" <<EOF

logtail:
  enabled: false

cli:
  timeout: 5s

log:
  level: info
  format: text
EOF

if [[ -n "${route_health_probe_interval_secs}" || -n "${route_health_probe_timeout_secs}" ]]; then
  cat >>"${config_path}" <<EOF

node:
  routes:
    ha:
      probe_interval: ${route_health_probe_interval_secs}s
      probe_timeout: ${route_health_probe_timeout_secs}s
EOF
fi

if ((use_headscale_go_tls)); then
  cat >>"${config_path}" <<EOF

tls_cert_path: ${work_dir}/tls.crt
tls_key_path: ${work_dir}/tls.key
EOF
fi

if ((use_headscale_go_embedded_derp)); then
  cat >>"${config_path}" <<EOF
derp:
  server:
    enabled: true
    region_id: ${headscale_go_derp_region_id}
    region_code: ${headscale_go_derp_region_code}
    region_name: ${headscale_go_derp_region_name}
    verify_clients: $([[ "${use_headscale_go_derp_verify_clients}" -eq 1 ]] && printf true || printf false)
    stun_listen_addr: ${headscale_go_derp_stun_addr}
    private_key_path: ${work_dir}/derp_server_private.key
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
EOF
else
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
fi

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

if ((assert_derp_stun_flag)); then
  echo "::group::assert embedded DERP STUN"
  if [[ -z "${expected_derp_stun_port}" ]]; then
    echo "REAL_CLIENT_ASSERT_DERP_STUN requires REAL_CLIENT_EXPECT_DERP_STUN_PORT" >&2
    exit 2
  fi
  wait_for "embedded DERP STUN" \
    "assert_stun_round_trip '${derp_stun_probe_host}' '${expected_derp_stun_port}' '${work_dir}/embedded-derp-stun.json'"
  cat "${work_dir}/embedded-derp-stun.json"
  echo "::endgroup::"
fi

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
  if [[ -n "${client_users_csv}" || -n "${preauth_tags_by_client}" ]]; then
    for idx in "${!client_names[@]}"; do
      user_id="$(lookup_user_id "${client_users[$idx]}")"
      preauth_args=(
        "${headscale_bin}" -c "${config_path}" -o json preauthkeys create
        --user "${user_id}" \
        --reusable \
        --expiration 1h
      )
      if [[ -n "${preauth_tags_values[$idx]}" ]]; then
        preauth_args+=(--tags "${preauth_tags_values[$idx]}")
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
  tailscaled_prefix=""
  if ((force_derp_flag)); then
    tailscaled_prefix="TS_DEBUG_ALWAYS_USE_DERP=1 "
  fi
  client_entry="${tailscaled_prefix}tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity"
  if ((use_headscale_go_tls)); then
    docker_args+=(-v "${work_dir}/tls.crt:/usr/local/share/ca-certificates/headscale-go.crt:ro")
    client_entry="update-ca-certificates >/tmp/update-ca-certificates.log 2>&1; ${tailscaled_prefix}tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity"
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
    "--accept-dns=${accept_dns_arg}"
  )
  if [[ "${login_mode}" == "authkey" ]]; then
    up_args+=("--authkey=${authkeys[$idx]}")
  fi
  if [[ -n "${advertise_routes_values[$idx]}" ]]; then
    up_args+=("--advertise-routes=${advertise_routes_values[$idx]}")
  fi
  if ((enable_tailscale_ssh_flag)); then
    up_args+=(--ssh)
  fi
  if [[ "${login_mode}" == "web" && -n "${preauth_tags}" ]]; then
    up_args+=("--advertise-tags=${preauth_tags}")
  fi
  case "${advertise_exit_node_values[$idx]}" in
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
      "--accept-dns=${accept_dns_arg}"
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

if [[ -n "${approve_routes}" || -n "${approve_routes_by_client}" ]]; then
  echo "::group::approve routes"
  "${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes-before-approve.json"
  approval_rows="$(
    ruby -rjson -e '
      payload = JSON.parse(File.read(ARGV.fetch(0)))
      nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
      expected = Integer(ARGV.fetch(1))
      expected_names = ARGV.fetch(2).split(",")
      routes_by_client = ARGV.fetch(3).split(";", -1)
      abort("expected #{expected} registered nodes, got #{nodes.length}") unless nodes.length == expected
      expected_names.each_with_index do |name, idx|
        node = nodes.find do |candidate|
          given_name = candidate["givenName"] || candidate["given_name"] || candidate["name"] || candidate["hostname"]
          given_name.to_s == name
        end
        abort("missing node #{name.inspect} in #{nodes.inspect}") unless node
        routes = routes_by_client.fetch(idx, "")
        next if routes.empty?
        puts [node.fetch("id"), routes].join("\t")
      end
    ' "${work_dir}/nodes-before-approve.json" "${expected_machine_count}" "${expected_client_names_csv}" "$(IFS=';'; echo "${approve_routes_values[*]}")"
  )"
  while IFS=$'\t' read -r node_id routes; do
    [[ -z "${node_id}" ]] && continue
    "${headscale_bin}" -c "${config_path}" -o json nodes approve-routes \
      --identifier "${node_id}" \
      --routes "${routes}" \
      >"${work_dir}/approved-routes-${node_id}.json"
  done <<<"${approval_rows}"
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
ruby -rjson -e '
  expected_routes_by_client = ARGV.fetch(1).split(";", -1).map { |routes| routes.split(",").reject(&:empty?).sort }
  expected_approved_by_client = ARGV.fetch(2).split(";", -1).map { |routes| routes.split(",").reject(&:empty?).sort }
  expected_count = Integer(ARGV.fetch(3))
  expected_primary_route = ARGV.fetch(4)
  expected_tags = ARGV.fetch(5).split(",").reject(&:empty?).sort
  expected_hostname_prefix = ARGV.fetch(6)
  expect_tags_exact = ARGV.fetch(7) == "true"
  expected_names = ARGV.fetch(8).split(",")
  expected_users = ARGV.fetch(9).split(",")
  expected_families = ARGV.fetch(10)
  assert_available = ARGV.fetch(11) == "true"
  assert_approved = ARGV.fetch(12) == "true"
  expected_user_by_host = expected_names.zip(expected_users).to_h
  expected_routes_by_host = expected_names.zip(expected_routes_by_client).to_h
  expected_approved_by_host = expected_names.zip(expected_approved_by_client).to_h

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
    tags = Array(node["tags"] || node["Tags"]).sort
    expected_user = if tags.empty?
      expected_user_by_host.fetch(given_name.to_s) {
        abort("unexpected node hostname #{given_name.inspect}; expected one of #{expected_names.inspect}")
      }
    else
      "tagged-devices"
    end
    abort("expected user #{expected_user}, got #{user.inspect}") unless user_name == expected_user
    abort("expected hostname prefix #{expected_hostname_prefix.inspect}, got #{given_name.inspect}") unless given_name.to_s.start_with?(expected_hostname_prefix)
    expected_routes = expected_routes_by_host.fetch(given_name.to_s, [])
    expected_approved = expected_approved_by_host.fetch(given_name.to_s, [])
    assert_ip_families("node #{given_name}", addresses, expected_families)
    unless (!assert_available && expected_routes.empty?) || available_routes == expected_routes
      abort("expected available routes #{expected_routes.inspect}, got #{available_routes.inspect}")
    end
    unless (!assert_approved && expected_approved.empty?) || approved_routes == expected_approved
      abort("expected approved routes #{expected_approved.inspect}, got #{approved_routes.inspect}")
    end
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
  ' "${work_dir}/nodes.json" "${expected_available_routes_spec}" "${expected_approved_routes_spec}" "${expected_machine_count}" "${expected_primary_route}" "${expected_tags}" "${run_id}" "$([[ "${expect_tags_exact}" -eq 1 ]] && printf true || printf false)" "${expected_client_names_csv}" "${expected_client_users_csv}" "${expected_tailscale_ip_families}" "${expect_available_by_client}" "${expect_approved_by_client}"
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

if [[ -n "${expected_dns_extra_records}" ]]; then
  echo "::group::assert DNS extra records"
  resolver_client="${client_names[0]}"
  IFS=',' read -r -a dns_expectations <<<"${expected_dns_extra_records}"
  for expectation in "${dns_expectations[@]}"; do
    host="${expectation%%=*}"
    expected="${expectation#*=}"
    if [[ -z "${host}" || -z "${expected}" || "${host}" == "${expectation}" ]]; then
      echo "REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS entries must be host=value, got ${expectation}" >&2
      exit 2
    fi
    expected_type=""
    if [[ "${expected}" =~ ^(A|AAAA|CNAME):(.*)$ ]]; then
      expected_type="${BASH_REMATCH[1]}"
      expected="${BASH_REMATCH[2]}"
    fi
    safe_host="${host//[^a-zA-Z0-9_.-]/-}"
    wait_for "DNS extra record ${host}" \
      "assert_dns_extra_record '${resolver_client}' '${host}' '${expected}' '${expected_type}' '${work_dir}/dns-${safe_host}.json'" || {
        dump_client_debug "${resolver_client}"
        exit 1
      }
    cat "${work_dir}/dns-${safe_host}.json"
  done
  case "${expected_dns_extra_records_exact}" in
    true)
      wait_for "exact DNS extra records" \
        "assert_dns_extra_records_exact '${resolver_client}' '${expected_dns_extra_records}' '${work_dir}/dns-extra-records-exact.json'" || {
          dump_client_debug "${resolver_client}"
          exit 1
        }
      cat "${work_dir}/dns-extra-records-exact.json"
      ;;
    false | "") ;;
    *)
      echo "REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS_EXACT must be true or false, got ${expected_dns_extra_records_exact}" >&2
      exit 2
      ;;
  esac
  echo "::endgroup::"
fi

if [[ -n "${expected_dns_resolvers}" ]]; then
  echo "::group::assert DNS resolvers"
  resolver_client="${client_names[0]}"
  wait_for "DNS resolvers ${expected_dns_resolvers}" \
    "assert_dns_resolver_list '${resolver_client}' 'Resolvers' '${expected_dns_resolvers}' '${work_dir}/dns-resolvers.json'" || {
      dump_client_debug "${resolver_client}"
      exit 1
    }
  cat "${work_dir}/dns-resolvers.json"
  echo "::endgroup::"
fi

if [[ -n "${expected_dns_fallback_resolvers}" ]]; then
  echo "::group::assert DNS fallback resolvers"
  resolver_client="${client_names[0]}"
  wait_for "DNS fallback resolvers ${expected_dns_fallback_resolvers}" \
    "assert_dns_resolver_list '${resolver_client}' 'FallbackResolvers' '${expected_dns_fallback_resolvers}' '${work_dir}/dns-fallback-resolvers.json'" || {
      dump_client_debug "${resolver_client}"
      exit 1
    }
  cat "${work_dir}/dns-fallback-resolvers.json"
  echo "::endgroup::"
fi

if [[ -n "${expected_dns_routes}" ]]; then
  echo "::group::assert DNS split routes"
  resolver_client="${client_names[0]}"
  IFS=',' read -r -a dns_route_expectations <<<"${expected_dns_routes}"
  for expectation in "${dns_route_expectations[@]}"; do
    suffix="${expectation%%=*}"
    expected="${expectation#*=}"
    if [[ -z "${suffix}" || -z "${expected}" || "${suffix}" == "${expectation}" ]]; then
      echo "REAL_CLIENT_EXPECT_DNS_ROUTES entries must be suffix=resolver|resolver, got ${expectation}" >&2
      exit 2
    fi
    expected_csv="${expected//|/,}"
    safe_suffix="${suffix//[^a-zA-Z0-9_.-]/-}"
    wait_for "DNS route ${suffix}" \
      "assert_dns_route '${resolver_client}' '${suffix}' '${expected_csv}' '${work_dir}/dns-route-${safe_suffix}.json'" || {
        dump_client_debug "${resolver_client}"
        exit 1
      }
    cat "${work_dir}/dns-route-${safe_suffix}.json"
  done
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

if [[ -n "${expected_peer_route_owners}" ]]; then
  echo "::group::assert route-via peer route owners"
  IFS=';' read -r -a peer_route_owner_checks <<<"${expected_peer_route_owners}"
  for raw_check in "${peer_route_owner_checks[@]}"; do
    IFS=':' read -r source_idx peer_idx route extra <<<"${raw_check}"
    if [[ -n "${extra:-}" ||
      ! "${source_idx}" =~ ^[0-9]+$ ||
      ! "${peer_idx}" =~ ^[0-9]+$ ||
      -z "${route}" ||
      "${source_idx}" -lt 1 ||
      "${peer_idx}" -lt 1 ||
      "${source_idx}" -gt "${client_count}" ||
      "${peer_idx}" -gt "${client_count}" ]]; then
      echo "REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS entries must be source_index:peer_index:route, got ${raw_check}" >&2
      exit 2
    fi
    source_name="${client_names[$((source_idx - 1))]}"
    peer_name="${client_names[$((peer_idx - 1))]}"
    safe_check="${source_idx}-${peer_idx}-${route//[^a-zA-Z0-9_.-]/-}"
    if ! wait_for "route ${route} from ${source_name} via ${peer_name}" \
      "peer_netmap_route_owner_matches '${source_name}' '${peer_name}' '${route}' '${work_dir}/route-owner-${safe_check}.json'"; then
      cat "${work_dir}/route-owner-${safe_check}.json.err" >&2 || true
      dump_client_debug "${source_name}"
      dump_client_debug "${peer_name}"
      exit 1
    fi
    cat "${work_dir}/route-owner-${safe_check}.json"
  done
  echo "::endgroup::"
fi

if [[ -n "${expected_derp_region_id}" ]]; then
  echo "::group::assert DERP map metadata"
  for client_name in "${client_names[@]}"; do
    assert_derp_map "${client_name}" "${work_dir}/${client_name}.derp-map.json" || {
      dump_client_debug "${client_name}"
      exit 1
    }
    cat "${work_dir}/${client_name}.derp-map.json"
  done
  echo "::endgroup::"
fi

if ((expect_derp_ping_flag)); then
  echo "::group::assert DERP relay path"
  source_name="${client_names[0]}"
  target_name="${client_names[1]}"
  if ! wait_for "tailscale ping ${source_name} to ${target_name} via DERP" \
    "tailscale_derp_ping_succeeded '${source_name}' '${target_name}' '${work_dir}/derp-ping-${source_name}-to-${target_name}.txt'"; then
    cat "${work_dir}/derp-ping-${source_name}-to-${target_name}.err" >&2 || true
    dump_client_debug "${source_name}"
    dump_client_debug "${target_name}"
    exit 1
  fi
  cat "${work_dir}/derp-ping-${source_name}-to-${target_name}.txt"
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
    status_path="${work_dir}/ssh-${source_name}-to-${target_name}-${expected_ssh}.status"

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
        printf '0\n' >"${status_path}"
        ;;
      deny)
        ssh_status=0
        tailscale_ssh_attempt "${source_name}" "${target_name}" "${stdout_path}" "${stderr_path}" ||
          ssh_status="$?"
        printf '%s\n' "${ssh_status}" >"${status_path}"
        if ((ssh_status == 0)); then
          echo "expected tailscale ssh ${source_name} to ${target_name} to be denied" >&2
          exit 1
        fi
        if [[ -n "${ssh_deny_status}" && "${ssh_deny_status}" != "any" ]] &&
          ((ssh_status != ssh_deny_status)); then
          echo "expected denied tailscale ssh status ${ssh_deny_status}, got ${ssh_status}" >&2
          cat "${stderr_path}" >&2 || true
          exit 1
        fi
        if [[ -s "${stdout_path}" ]]; then
          echo "expected denied tailscale ssh stdout to be empty, got:" >&2
          cat "${stdout_path}" >&2
          exit 1
        fi
        if [[ -n "${ssh_deny_stderr_first_line}" ]]; then
          first_line="$(sed -n '1{s/\r$//;p;q;}' "${stderr_path}")"
          if [[ "${first_line}" != "${ssh_deny_stderr_first_line}" ]]; then
            echo "expected denied tailscale ssh first stderr line '${ssh_deny_stderr_first_line}', got '${first_line}':" >&2
            cat "${stderr_path}" >&2 || true
            exit 1
          fi
        fi
        if [[ -n "${ssh_deny_stderr_regex}" ]] && ! grep -Eq "${ssh_deny_stderr_regex}" "${stderr_path}"; then
          echo "expected tailscale ssh denial stderr, got:" >&2
          cat "${stderr_path}" >&2 || true
          exit 1
        fi
        ;;
      timeout)
        ssh_status=0
        tailscale_ssh_attempt "${source_name}" "${target_name}" "${stdout_path}" "${stderr_path}" ||
          ssh_status="$?"
        printf '%s\n' "${ssh_status}" >"${status_path}"
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
        preserve_approval = ARGV.fetch(5) == "true"

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
        if preserve_approval
          approved_routes = Array(withdrawn["approvedRoutes"] || withdrawn["approved_routes"])
          abort("withdrawn client lost approved route #{route}") unless approved_routes.include?(route)
        end

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
          withdrawn_approved_routes: Array(withdrawn["approvedRoutes"] || withdrawn["approved_routes"]).sort,
          before_owner: before_owner,
          after_owner: after_owner,
          nodes: after_nodes,
        })
      ' "${work_dir}/nodes-before-withdraw.json" "${work_dir}/nodes-after-withdraw.json" "${expected_primary_withdraw_route}" "${withdraw_client_name}" "${expected_machine_count}" "$([[ "${expect_withdraw_approval_preserved}" -eq 1 ]] && printf true || printf false)"
  do
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for primary route withdrawal" >&2
      exit 1
    fi
    sleep 1
  done
  echo "::endgroup::"
fi

if [[ -n "${expected_route_health_failover_route}" ]]; then
  echo "::group::assert route-health primary failover"
  cp "${work_dir}/nodes.json" "${work_dir}/nodes-before-route-health.json"
  route_health_client_name="$(
    ruby -rjson -e '
      route = ARGV.fetch(1)
      payload = JSON.parse(File.read(ARGV.fetch(0)))
      nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
      primary_nodes = nodes.select do |node|
        Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route)
      end
      abort("expected exactly one primary node before route-health, got #{primary_nodes.length}") unless primary_nodes.length == 1
      node = primary_nodes.fetch(0)
      puts node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
    ' "${work_dir}/nodes-before-route-health.json" "${expected_route_health_failover_route}"
  )"

  docker pause "${route_health_client_name}" >/dev/null
  deadline=$((SECONDS + timeout_secs))
  until
    "${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes-after-route-health.json" &&
      ruby -rjson -e '
        route = ARGV.fetch(2)
        paused_client = ARGV.fetch(3)
        expected_count = Integer(ARGV.fetch(4))

        def node_name(node)
          node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
        end

        before_payload = JSON.parse(File.read(ARGV.fetch(0)))
        before_nodes = before_payload.is_a?(Array) ? before_payload : before_payload.fetch("nodes")
        after_payload = JSON.parse(File.read(ARGV.fetch(1)))
        after_nodes = after_payload.is_a?(Array) ? after_payload : after_payload.fetch("nodes")
        abort("expected #{expected_count} nodes before route-health, got #{before_nodes.length}") unless before_nodes.length == expected_count
        abort("expected #{expected_count} nodes after route-health, got #{after_nodes.length}") unless after_nodes.length == expected_count

        before_primary = before_nodes.select do |node|
          Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route)
        end
        after_primary = after_nodes.select do |node|
          Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route)
        end
        abort("expected exactly one primary node before route-health, got #{before_primary.length}") unless before_primary.length == 1
        abort("expected exactly one primary node after route-health, got #{after_primary.length}") unless after_primary.length == 1
        before_owner = Integer(before_primary.fetch(0).fetch("id"))
        after_owner = Integer(after_primary.fetch(0).fetch("id"))
        abort("expected route-health primary owner to change, still #{after_owner}") if after_owner == before_owner

        remaining_ids = after_nodes
          .reject { |node| node_name(node) == paused_client }
          .select do |node|
            Array(node["availableRoutes"] || node["available_routes"]).include?(route) &&
              Array(node["approvedRoutes"] || node["approved_routes"]).include?(route)
          end
          .map { |node| Integer(node.fetch("id")) }
        abort("new primary owner #{after_owner} not among remaining active routers #{remaining_ids.inspect}") unless remaining_ids.include?(after_owner)

        puts JSON.pretty_generate({
          paused_client: paused_client,
          before_owner: before_owner,
          after_owner: after_owner,
          nodes: after_nodes,
        })
      ' "${work_dir}/nodes-before-route-health.json" "${work_dir}/nodes-after-route-health.json" "${expected_route_health_failover_route}" "${route_health_client_name}" "${expected_machine_count}"
  do
    if ((SECONDS >= deadline)); then
      docker unpause "${route_health_client_name}" >/dev/null 2>&1 || true
      echo "timed out waiting for route-health failover" >&2
      exit 1
    fi
    sleep 1
  done

  docker unpause "${route_health_client_name}" >/dev/null
  if ! wait_for "tailscale logged-in netmap after route-health recovery ${route_health_client_name}" "tailscale_logged_in '${route_health_client_name}'"; then
    dump_client_debug "${route_health_client_name}"
    exit 1
  fi
  sleep $((route_health_probe_interval_secs + route_health_probe_timeout_secs + 2))
  "${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes-after-route-health-recovery.json"
  ruby -rjson -e '
    route = ARGV.fetch(2)
    def primary_owner(path, route)
      payload = JSON.parse(File.read(path))
      nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
      primary = nodes.select { |node| Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route) }
      abort("expected exactly one primary node for #{route}, got #{primary.length}") unless primary.length == 1
      Integer(primary.fetch(0).fetch("id"))
    end
    failed_over_owner = primary_owner(ARGV.fetch(0), route)
    recovered_owner = primary_owner(ARGV.fetch(1), route)
    abort("route-health recovery stole #{route}: #{recovered_owner.inspect}, expected sticky #{failed_over_owner.inspect}") unless recovered_owner == failed_over_owner
    puts JSON.pretty_generate({route: route, sticky_owner: recovered_owner})
  ' "${work_dir}/nodes-after-route-health.json" "${work_dir}/nodes-after-route-health-recovery.json" "${expected_route_health_failover_route}"
  echo "::endgroup::"
fi

if [[ -n "${expected_route_health_all_unhealthy_route}" ]]; then
  echo "::group::assert route-health all-unhealthy fallback"
  cp "${work_dir}/nodes.json" "${work_dir}/nodes-before-route-health-all-unhealthy.json"
  route_health_all_selection="$(
    ruby -rjson -e '
      route = ARGV.fetch(1)

      def node_name(node)
        node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
      end

      payload = JSON.parse(File.read(ARGV.fetch(0)))
      nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
      primary_nodes = nodes.select do |node|
        Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route)
      end
      abort("expected exactly one primary node before all-unhealthy route-health, got #{primary_nodes.length}") unless primary_nodes.length == 1
      candidates = nodes
        .select do |node|
          Array(node["availableRoutes"] || node["available_routes"]).include?(route) &&
            Array(node["approvedRoutes"] || node["approved_routes"]).include?(route)
        end
        .map { |node| [Integer(node.fetch("id")), node_name(node)] }
        .sort_by(&:first)
      abort("expected at least two route-health candidates for #{route}, got #{candidates.inspect}") if candidates.length < 2
      primary_id = Integer(primary_nodes.fetch(0).fetch("id"))
      primary = candidates.find { |id, _hostname| id == primary_id }
      abort("primary owner #{primary_id.inspect} did not match active candidates #{candidates.inspect}") unless primary
      puts primary.fetch(1)
      candidates.each { |_id, hostname| puts hostname }
    ' "${work_dir}/nodes-before-route-health-all-unhealthy.json" "${expected_route_health_all_unhealthy_route}"
  )"
  mapfile -t route_health_all_lines <<<"${route_health_all_selection}"
  route_health_all_primary_name="${route_health_all_lines[0]}"
  route_health_all_candidates=("${route_health_all_lines[@]:1}")
  route_health_all_paused=()

  docker pause "${route_health_all_primary_name}" >/dev/null
  route_health_all_paused+=("${route_health_all_primary_name}")
  deadline=$((SECONDS + timeout_secs))
  until
    "${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes-after-route-health-first-unhealthy.json" &&
      ruby -rjson -e '
        route = ARGV.fetch(2)
        paused_client = ARGV.fetch(3)
        expected_count = Integer(ARGV.fetch(4))

        def node_name(node)
          node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
        end

        before_payload = JSON.parse(File.read(ARGV.fetch(0)))
        before_nodes = before_payload.is_a?(Array) ? before_payload : before_payload.fetch("nodes")
        after_payload = JSON.parse(File.read(ARGV.fetch(1)))
        after_nodes = after_payload.is_a?(Array) ? after_payload : after_payload.fetch("nodes")
        abort("expected #{expected_count} nodes before first route-health timeout, got #{before_nodes.length}") unless before_nodes.length == expected_count
        abort("expected #{expected_count} nodes after first route-health timeout, got #{after_nodes.length}") unless after_nodes.length == expected_count

        before_primary = before_nodes.select { |node| Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route) }
        after_primary = after_nodes.select { |node| Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route) }
        abort("expected exactly one primary node before first route-health timeout, got #{before_primary.length}") unless before_primary.length == 1
        abort("expected exactly one primary node after first route-health timeout, got #{after_primary.length}") unless after_primary.length == 1
        before_owner = Integer(before_primary.fetch(0).fetch("id"))
        after_owner = Integer(after_primary.fetch(0).fetch("id"))
        abort("expected first route-health timeout to fail over, still #{after_owner}") if after_owner == before_owner

        remaining_ids = after_nodes
          .reject { |node| node_name(node) == paused_client }
          .select do |node|
            Array(node["availableRoutes"] || node["available_routes"]).include?(route) &&
              Array(node["approvedRoutes"] || node["approved_routes"]).include?(route)
          end
          .map { |node| Integer(node.fetch("id")) }
        abort("first failover owner #{after_owner} not among remaining active routers #{remaining_ids.inspect}") unless remaining_ids.include?(after_owner)

        puts JSON.pretty_generate({
          paused_client: paused_client,
          before_owner: before_owner,
          after_owner: after_owner,
          nodes: after_nodes,
        })
      ' "${work_dir}/nodes-before-route-health-all-unhealthy.json" "${work_dir}/nodes-after-route-health-first-unhealthy.json" "${expected_route_health_all_unhealthy_route}" "${route_health_all_primary_name}" "${expected_machine_count}"
  do
    if ((SECONDS >= deadline)); then
      for paused in "${route_health_all_paused[@]}"; do
        docker unpause "${paused}" >/dev/null 2>&1 || true
      done
      echo "timed out waiting for first route-health timeout" >&2
      exit 1
    fi
    sleep 1
  done

  for candidate in "${route_health_all_candidates[@]}"; do
    if [[ "${candidate}" != "${route_health_all_primary_name}" ]]; then
      docker pause "${candidate}" >/dev/null
      route_health_all_paused+=("${candidate}")
    fi
  done

  sleep $((route_health_probe_interval_secs + route_health_probe_timeout_secs + 2))
  if ! (
    "${headscale_bin}" -c "${config_path}" -o json nodes list >"${work_dir}/nodes-after-route-health-all-unhealthy.json" &&
      ruby -rjson -e '
        route = ARGV.fetch(3)
        expected_count = Integer(ARGV.fetch(4))

        before_payload = JSON.parse(File.read(ARGV.fetch(0)))
        before_nodes = before_payload.is_a?(Array) ? before_payload : before_payload.fetch("nodes")
        first_payload = JSON.parse(File.read(ARGV.fetch(1)))
        first_nodes = first_payload.is_a?(Array) ? first_payload : first_payload.fetch("nodes")
        after_payload = JSON.parse(File.read(ARGV.fetch(2)))
        after_nodes = after_payload.is_a?(Array) ? after_payload : after_payload.fetch("nodes")
        abort("expected #{expected_count} nodes before all-unhealthy route-health, got #{before_nodes.length}") unless before_nodes.length == expected_count
        abort("expected #{expected_count} nodes after all-unhealthy route-health, got #{after_nodes.length}") unless after_nodes.length == expected_count

        first_primary = first_nodes.select { |node| Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route) }
        after_primary = after_nodes.select { |node| Array(node["subnetRoutes"] || node["subnet_routes"]).include?(route) }
        abort("expected exactly one primary node after first route-health timeout, got #{first_primary.length}") unless first_primary.length == 1
        abort("expected exactly one primary node after all route-health candidates are unhealthy, got #{after_primary.length}") unless after_primary.length == 1
        first_owner = Integer(first_primary.fetch(0).fetch("id"))
        after_owner = Integer(after_primary.fetch(0).fetch("id"))

        candidate_ids = before_nodes
          .select do |node|
            Array(node["availableRoutes"] || node["available_routes"]).include?(route) &&
              Array(node["approvedRoutes"] || node["approved_routes"]).include?(route)
          end
          .map { |node| Integer(node.fetch("id")) }
          .sort
        abort("all-unhealthy fallback owner #{after_owner} not among candidates #{candidate_ids.inspect}") unless candidate_ids.include?(after_owner)

        puts JSON.pretty_generate({
          route: route,
          first_unhealthy_owner: first_owner,
          all_unhealthy_owner: after_owner,
          retained_last_known_primary: after_owner == first_owner,
          candidate_ids: candidate_ids,
          nodes: after_nodes,
        })
      ' "${work_dir}/nodes-before-route-health-all-unhealthy.json" "${work_dir}/nodes-after-route-health-first-unhealthy.json" "${work_dir}/nodes-after-route-health-all-unhealthy.json" "${expected_route_health_all_unhealthy_route}" "${expected_machine_count}"
  ); then
    for paused in "${route_health_all_paused[@]}"; do
      docker unpause "${paused}" >/dev/null 2>&1 || true
    done
    echo "route-health all-unhealthy fallback assertion failed" >&2
    exit 1
  fi

  for paused in "${route_health_all_paused[@]}"; do
    docker unpause "${paused}" >/dev/null
  done
  for paused in "${route_health_all_paused[@]}"; do
    if ! wait_for "tailscale logged-in netmap after all-unhealthy route-health ${paused}" "tailscale_logged_in '${paused}'"; then
      dump_client_debug "${paused}"
      exit 1
    fi
  done
  echo "::endgroup::"
fi

echo "headscale-go ${login_mode} real-client smoke passed"
