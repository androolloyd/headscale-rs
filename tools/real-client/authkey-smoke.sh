#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/authkey-smoke}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-120}"
client_count="${REAL_CLIENT_CLIENT_COUNT:-1}"
login_mode="${REAL_CLIENT_LOGIN_MODE:-authkey}"
expected_register_failure="${REAL_CLIENT_EXPECT_REGISTER_FAILURE:-false}"
preauth_reusable="${REAL_CLIENT_PREAUTH_REUSABLE:-true}"
preauth_ephemeral="${REAL_CLIENT_PREAUTH_EPHEMERAL:-false}"
preauth_expired="${REAL_CLIENT_PREAUTH_EXPIRED:-false}"
expected_authkey_failure_indexes="${REAL_CLIENT_EXPECT_AUTHKEY_FAILURE_INDEXES:-}"
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
expected_peer_route_owners_after_policy_reload="${REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS_AFTER_POLICY_RELOAD:-}"
expected_peer_route_owners_after_route_health="${REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS_AFTER_ROUTE_HEALTH:-}"
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
authkey_relogin_same_user="${REAL_CLIENT_AUTHKEY_RELOGIN_SAME_USER:-false}"
authkey_relogin_expired="${REAL_CLIENT_AUTHKEY_RELOGIN_EXPIRED:-false}"
authkey_relogin_different_user="${REAL_CLIENT_AUTHKEY_RELOGIN_DIFFERENT_USER:-false}"
expected_tags_exact="${REAL_CLIENT_EXPECT_TAGS_EXACT:-}"
policy_json="${REAL_CLIENT_POLICY_JSON:-}"
policy_reload_json="${REAL_CLIENT_POLICY_RELOAD_JSON:-}"
base_domain="${REAL_CLIENT_BASE_DOMAIN-tail.test}"
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
expected_dns_resolver_objects="${REAL_CLIENT_EXPECT_DNS_RESOLVER_OBJECTS:-false}"
expected_dns_debug_resolves="${REAL_CLIENT_EXPECT_DNS_DEBUG_RESOLVES:-}"
expected_peer_magic_dns_resolve="${REAL_CLIENT_EXPECT_PEER_MAGIC_DNS_RESOLVE:-false}"
expected_peer_count="${REAL_CLIENT_EXPECT_PEER_COUNT:-}"
expected_peer_counts="${REAL_CLIENT_EXPECT_PEER_COUNTS:-}"
expected_tailscale_ip_families="${REAL_CLIENT_EXPECT_TAILSCALE_IP_FAMILIES:-}"
harness_ip_families="${HSRS_HARNESS_IP_FAMILIES:-ipv4-only}"
client_users_csv="${REAL_CLIENT_CLIENT_USERS:-}"
enable_tailscale_ssh="${REAL_CLIENT_ENABLE_TAILSCALE_SSH:-false}"
install_openssh="${REAL_CLIENT_INSTALL_OPENSSH:-false}"
ssh_user="${REAL_CLIENT_SSH_USER:-}"
expected_ssh_matrix="${REAL_CLIENT_EXPECT_SSH_MATRIX:-}"
ssh_command="${REAL_CLIENT_SSH_COMMAND:-hostname}"
ssh_expected_stdout="${REAL_CLIENT_EXPECT_SSH_STDOUT:-}"
ssh_send_env="${REAL_CLIENT_SSH_SEND_ENV:-}"
ssh_attempt_timeout_secs="${REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS:-12}"
ssh_host_key_timeout_secs="${REAL_CLIENT_SSH_HOST_KEY_TIMEOUT_SECS:-30}"
ssh_deny_status="${REAL_CLIENT_EXPECT_SSH_DENY_STATUS:-}"
ssh_timeout_status="${REAL_CLIENT_EXPECT_SSH_TIMEOUT_STATUS:-}"
ssh_deny_stderr_regex="${REAL_CLIENT_EXPECT_SSH_DENY_STDERR_REGEX:-Permission denied \(tailscale\)|failed to evaluate SSH policy|tailnet policy does not permit you to SSH to this node}"
ssh_deny_stderr_first_line="${REAL_CLIENT_EXPECT_SSH_DENY_STDERR_FIRST_LINE:-}"
force_derp="${REAL_CLIENT_FORCE_DERP:-false}"
expected_derp_region_id="${REAL_CLIENT_EXPECT_DERP_REGION_ID:-}"
expected_derp_region_code="${REAL_CLIENT_EXPECT_DERP_REGION_CODE:-}"
expected_derp_region_name="${REAL_CLIENT_EXPECT_DERP_REGION_NAME:-}"
expected_derp_host="${REAL_CLIENT_EXPECT_DERP_HOST:-}"
expected_derp_port="${REAL_CLIENT_EXPECT_DERP_PORT:-}"
expected_derp_stun_port="${REAL_CLIENT_EXPECT_DERP_STUN_PORT:-}"
expected_derp_insecure_for_tests="${REAL_CLIENT_EXPECT_DERP_INSECURE_FOR_TESTS:-}"
expected_derp_omit_default_regions="${REAL_CLIENT_EXPECT_DERP_OMIT_DEFAULT_REGIONS:-}"
expected_derp_ping="${REAL_CLIENT_EXPECT_DERP_PING:-false}"
expected_derp_verify_requests_min="${REAL_CLIENT_EXPECT_DERP_VERIFY_REQUESTS_MIN:-}"
assert_derp_stun="${REAL_CLIENT_ASSERT_DERP_STUN:-false}"
expected_debug_ping="${REAL_CLIENT_EXPECT_DEBUG_PING:-false}"
taildrop_enabled="${REAL_CLIENT_TAILDROP_ENABLED:-}"
expected_file_sharing_cap="${REAL_CLIENT_EXPECT_FILE_SHARING_CAP:-}"
derp_stun_probe_host="${REAL_CLIENT_DERP_STUN_PROBE_HOST:-127.0.0.1}"
harness_derp_map="${HSRS_HARNESS_DERP_MAP:-${REAL_CLIENT_DERP_MAP:-}}"
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
case "${expected_debug_ping}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    expect_debug_ping=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    expect_debug_ping=0
    ;;
  *)
    echo "REAL_CLIENT_EXPECT_DEBUG_PING must be true or false, got ${expected_debug_ping}" >&2
    exit 2
    ;;
esac
taildrop_enabled_bool=""
if [[ -n "${taildrop_enabled}" ]]; then
  case "${taildrop_enabled}" in
    1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
      taildrop_enabled_bool=true
      ;;
    0 | false | FALSE | False | no | NO | No | off | OFF | Off)
      taildrop_enabled_bool=false
      ;;
    *)
      echo "REAL_CLIENT_TAILDROP_ENABLED must be true or false, got ${taildrop_enabled}" >&2
      exit 2
      ;;
  esac
fi
expected_file_sharing_cap_bool=""
if [[ -n "${expected_file_sharing_cap}" ]]; then
  case "${expected_file_sharing_cap}" in
    1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
      expected_file_sharing_cap_bool=true
      ;;
    0 | false | FALSE | False | no | NO | No | off | OFF | Off)
      expected_file_sharing_cap_bool=false
      ;;
    *)
      echo "REAL_CLIENT_EXPECT_FILE_SHARING_CAP must be true or false, got ${expected_file_sharing_cap}" >&2
      exit 2
      ;;
  esac
fi
case "${authkey_relogin_same_user}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    authkey_relogin_same_user_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    authkey_relogin_same_user_flag=0
    ;;
  *)
    echo "REAL_CLIENT_AUTHKEY_RELOGIN_SAME_USER must be true or false, got ${authkey_relogin_same_user}" >&2
    exit 2
    ;;
esac
case "${authkey_relogin_expired}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    authkey_relogin_expired_flag=1
    authkey_relogin_expired_json=true
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    authkey_relogin_expired_flag=0
    authkey_relogin_expired_json=false
    ;;
  *)
    echo "REAL_CLIENT_AUTHKEY_RELOGIN_EXPIRED must be true or false, got ${authkey_relogin_expired}" >&2
    exit 2
    ;;
esac
case "${authkey_relogin_different_user}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    authkey_relogin_different_user_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    authkey_relogin_different_user_flag=0
    ;;
  *)
    echo "REAL_CLIENT_AUTHKEY_RELOGIN_DIFFERENT_USER must be true or false, got ${authkey_relogin_different_user}" >&2
    exit 2
    ;;
esac
authkey_relogin_requested_flag=0
if ((authkey_relogin_same_user_flag || authkey_relogin_different_user_flag)); then
  authkey_relogin_requested_flag=1
fi
if ((authkey_relogin_requested_flag)) && [[ "${login_mode}" != "authkey" ]]; then
  echo "auth-key relogin requires REAL_CLIENT_LOGIN_MODE=authkey" >&2
  exit 2
fi
if ((authkey_relogin_expired_flag && ! authkey_relogin_requested_flag)); then
  echo "REAL_CLIENT_AUTHKEY_RELOGIN_EXPIRED requires auth-key relogin" >&2
  exit 2
fi
if ((authkey_relogin_different_user_flag && authkey_relogin_same_user_flag)); then
  echo "REAL_CLIENT_AUTHKEY_RELOGIN_DIFFERENT_USER cannot be combined with REAL_CLIENT_AUTHKEY_RELOGIN_SAME_USER" >&2
  exit 2
fi
if ((authkey_relogin_different_user_flag && authkey_relogin_expired_flag)); then
  echo "REAL_CLIENT_AUTHKEY_RELOGIN_DIFFERENT_USER cannot be combined with REAL_CLIENT_AUTHKEY_RELOGIN_EXPIRED" >&2
  exit 2
fi
if ((authkey_relogin_requested_flag)) && [[ -n "${expected_authkey_failure_indexes}" ]]; then
  echo "auth-key relogin cannot be combined with REAL_CLIENT_EXPECT_AUTHKEY_FAILURE_INDEXES" >&2
  exit 2
fi
if ((expect_derp_ping_flag)) && [[ "${client_count}" =~ ^[0-9]+$ ]] && ((client_count < 2)); then
  echo "REAL_CLIENT_EXPECT_DERP_PING requires at least two clients" >&2
  exit 2
fi
if [[ -n "${expected_derp_verify_requests_min}" ]] && ! [[ "${expected_derp_verify_requests_min}" =~ ^[0-9]+$ ]]; then
  echo "REAL_CLIENT_EXPECT_DERP_VERIFY_REQUESTS_MIN must be a non-negative integer, got ${expected_derp_verify_requests_min}" >&2
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
if [[ -n "${ssh_timeout_status}" && "${ssh_timeout_status}" != "any" && ! "${ssh_timeout_status}" =~ ^[0-9]+$ ]]; then
  echo "REAL_CLIENT_EXPECT_SSH_TIMEOUT_STATUS must be empty, any, or a non-negative integer, got ${ssh_timeout_status}" >&2
  exit 2
fi
ssh_env_args=()
if [[ -n "${ssh_send_env}" ]]; then
  IFS=',' read -r -a ssh_send_env_entries <<<"${ssh_send_env}"
  for ssh_send_env_entry in "${ssh_send_env_entries[@]}"; do
    if [[ ! "${ssh_send_env_entry}" =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then
      echo "REAL_CLIENT_SSH_SEND_ENV entries must be comma-separated NAME=value pairs, got ${ssh_send_env_entry}" >&2
      exit 2
    fi
    ssh_env_args+=(--env "${ssh_send_env_entry}")
  done
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
case "${preauth_reusable}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    preauth_reusable_json=true
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    preauth_reusable_json=false
    ;;
  *)
    echo "REAL_CLIENT_PREAUTH_REUSABLE must be true or false, got ${preauth_reusable}" >&2
    exit 2
    ;;
esac
case "${preauth_ephemeral}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    preauth_ephemeral_json=true
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    preauth_ephemeral_json=false
    ;;
  *)
    echo "REAL_CLIENT_PREAUTH_EPHEMERAL must be true or false, got ${preauth_ephemeral}" >&2
    exit 2
    ;;
esac
case "${preauth_expired}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    preauth_expired_json=true
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    preauth_expired_json=false
    ;;
  *)
    echo "REAL_CLIENT_PREAUTH_EXPIRED must be true or false, got ${preauth_expired}" >&2
    exit 2
    ;;
esac
if [[ -n "${expected_authkey_failure_indexes}" && "${login_mode}" != "authkey" ]]; then
  echo "REAL_CLIENT_EXPECT_AUTHKEY_FAILURE_INDEXES is only supported with REAL_CLIENT_LOGIN_MODE=authkey" >&2
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
case "${expected_peer_magic_dns_resolve}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    expect_peer_magic_dns_resolve=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    expect_peer_magic_dns_resolve=0
    ;;
  *)
    echo "REAL_CLIENT_EXPECT_PEER_MAGIC_DNS_RESOLVE must be true or false, got ${expected_peer_magic_dns_resolve}" >&2
    exit 2
    ;;
esac
case "${expected_dns_resolver_objects}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    expect_dns_resolver_objects=true
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    expect_dns_resolver_objects=false
    ;;
  *)
    echo "REAL_CLIENT_EXPECT_DNS_RESOLVER_OBJECTS must be true or false, got ${expected_dns_resolver_objects}" >&2
    exit 2
    ;;
esac
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

if ! [[ "${expected_primary_route_candidates}" =~ ^[0-9]+$ ]]; then
  echo "REAL_CLIENT_EXPECT_PRIMARY_ROUTE_CANDIDATES must be a non-negative integer, got ${expected_primary_route_candidates}" >&2
  exit 2
fi
if [[ -n "${expected_primary_route}" ]] && ((expected_primary_route_candidates < 1)); then
  echo "REAL_CLIENT_EXPECT_PRIMARY_ROUTE_CANDIDATES must be positive when REAL_CLIENT_EXPECT_PRIMARY_ROUTE is set, got ${expected_primary_route_candidates}" >&2
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
if [[ -n "${expected_peer_route_owners_after_route_health}" && -z "${expected_route_health_failover_route}" ]]; then
  echo "REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS_AFTER_ROUTE_HEALTH requires REAL_CLIENT_EXPECT_ROUTE_HEALTH_FAILOVER_ROUTE" >&2
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
metrics_port=""
harness_pid=""
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

authkey_failure_flags=()
for ((idx = 0; idx < client_count; idx++)); do
  authkey_failure_flags+=(0)
done
if [[ -n "${expected_authkey_failure_indexes}" ]]; then
  IFS=',' read -r -a authkey_failure_indexes <<<"${expected_authkey_failure_indexes}"
  for authkey_failure_index in "${authkey_failure_indexes[@]}"; do
    if ! [[ "${authkey_failure_index}" =~ ^[0-9]+$ ]] ||
      ((authkey_failure_index < 1 || authkey_failure_index > client_count)); then
      echo "REAL_CLIENT_EXPECT_AUTHKEY_FAILURE_INDEXES values must be 1..${client_count}, got ${authkey_failure_index}" >&2
      exit 2
    fi
    authkey_failure_flags[$((authkey_failure_index - 1))]=1
  done
fi

expected_client_names=()
expected_client_users=()
for idx in "${!client_names[@]}"; do
  if ((authkey_failure_flags[$idx] == 0)); then
    expected_client_names+=("${client_names[$idx]}")
    expected_client_users+=("${client_users[$idx]}")
  fi
done
expected_client_names_csv="$(IFS=,; echo "${expected_client_names[*]}")"
expected_client_users_csv="$(IFS=,; echo "${expected_client_users[*]}")"

cleanup() {
  for client_name in "${client_names[@]}"; do
    docker rm -f "${client_name}" >/dev/null 2>&1 || true
  done
  stop_harness
}
trap cleanup EXIT

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

free_port() {
  local host="${1:-127.0.0.1}"
  ruby -rsocket -e 'host=ARGV.fetch(0); s=TCPServer.new(host,0); puts s.addr[1]; s.close' "${host}"
}

wait_for() {
  local label="$1"
  local cmd="$2"
  wait_for_with_timeout "${label}" "${timeout_secs}" "${cmd}"
}

wait_for_with_timeout() {
  local label="$1"
  local wait_secs="$2"
  local cmd="$3"
  local deadline=$((SECONDS + wait_secs))
  until eval "${cmd}"; do
    if [[ -n "${harness_pid}" ]] && ! kill -0 "${harness_pid}" >/dev/null 2>&1; then
      wait "${harness_pid}" >/dev/null 2>&1 || true
      harness_pid=""
      echo "headscale-rs harness exited while waiting for ${label}" >&2
      dump_harness_logs "harness exited before ${label}"
      return 1
    fi
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for ${label}" >&2
      dump_harness_logs "timed out waiting for ${label}"
      return 1
    fi
    sleep 1
  done
}

dump_harness_logs() {
  local label="${1:-harness}"
  local path
  echo "::group::${label}"
  for path in \
    "${work_dir}/harness.stderr" \
    "${work_dir}/harness.stdout" \
    "${work_dir}/harness-health.stderr" \
    "${work_dir}/harness-health.stdout" \
    "${work_dir}/harness-metrics.stderr" \
    "${work_dir}/harness-metrics.stdout"; do
    if [[ -s "${path}" ]]; then
      echo "--- ${path} ---" >&2
      tail -200 "${path}" >&2 || true
    fi
  done
  echo "::endgroup::"
}

stop_harness() {
  if [[ -n "${harness_pid}" ]]; then
    kill "${harness_pid}" >/dev/null 2>&1 || true
    wait "${harness_pid}" >/dev/null 2>&1 || true
    harness_pid=""
  fi
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

tailscale_status_ips() {
  local status_path="$1"
  ruby -rjson -e '
    status = JSON.parse(File.read(ARGV.fetch(0)))
    puts Array(status["TailscaleIPs"]).sort.join(",")
  ' "${status_path}"
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
  docker exec "${ssh_env_args[@]}" "${source_name}" sh -ceu \
    'timeout "$1" tailscale ssh "$2@$3" "$4"' \
    sh "${ssh_attempt_timeout_secs}" "${ssh_user}" "${target_name}" "${ssh_command}" \
    >"${stdout_path}" \
    2>"${stderr_path}"
}

tailscale_ssh_succeeded() {
  local source_name="$1"
  local target_name="$2"
  local stdout_path="${work_dir}/ssh-${source_name}-to-${target_name}.stdout"
  local stderr_path="${work_dir}/ssh-${source_name}-to-${target_name}.stderr"
  tailscale_ssh_attempt "${source_name}" "${target_name}" "${stdout_path}" "${stderr_path}" || return 1
  if [[ -n "${ssh_expected_stdout}" ]]; then
    local actual_stdout
    actual_stdout="$(sed 's/\r$//' "${stdout_path}")"
    [[ "${actual_stdout}" == "${ssh_expected_stdout}" ]]
    return
  fi
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
    match = url.match(%r{/register/(?:hskey-authreq-)?([A-Za-z0-9_-]{24})(?:\z|[?#])})
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
  local expect_objects="${5:-false}"
  local netmap_path="${output_path}.netmap"
  docker exec "${client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      def normalize_resolver(resolver, expect_object)
        unless resolver.is_a?(Hash)
          abort("expected DNS resolver object, got #{resolver.inspect}") if expect_object
          return {
            "Addr" => resolver.to_s,
            "BootstrapResolution" => [],
            "UseWithExitNode" => false,
          }
        end
        {
          "Addr" => (resolver["Addr"] || resolver["addr"]).to_s,
          "BootstrapResolution" => Array(resolver["BootstrapResolution"] || resolver["bootstrap_resolution"]).map(&:to_s),
          "UseWithExitNode" => !!(resolver["UseWithExitNode"] || resolver["use_with_exit_node"]),
        }
      end

      netmap = JSON.parse(File.read(ARGV.fetch(0)))
      field = ARGV.fetch(1)
      expected = ARGV.fetch(2).split(",").reject(&:empty?)
      expect_objects = ARGV.fetch(3) == "true"
      resolvers = Array(netmap.dig("DNS", field))
      normalized = resolvers.map { |resolver| normalize_resolver(resolver, expect_objects) }
      got = normalized.map { |resolver| resolver.fetch("Addr") }
      abort("expected DNS #{field} #{expected.inspect}, got #{got.inspect}") unless got == expected
      puts JSON.pretty_generate({field => normalized})
    ' "${netmap_path}" "${field}" "${expected_csv}" "${expect_objects}" >"${output_path}"
}

assert_dns_route() {
  local client_name="$1"
  local suffix="$2"
  local expected_csv="$3"
  local output_path="$4"
  local expect_objects="${5:-false}"
  local netmap_path="${output_path}.netmap"
  docker exec "${client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      def normalize_resolver(resolver, expect_object)
        unless resolver.is_a?(Hash)
          abort("expected DNS route resolver object, got #{resolver.inspect}") if expect_object
          return {
            "Addr" => resolver.to_s,
            "BootstrapResolution" => [],
            "UseWithExitNode" => false,
          }
        end
        {
          "Addr" => (resolver["Addr"] || resolver["addr"]).to_s,
          "BootstrapResolution" => Array(resolver["BootstrapResolution"] || resolver["bootstrap_resolution"]).map(&:to_s),
          "UseWithExitNode" => !!(resolver["UseWithExitNode"] || resolver["use_with_exit_node"]),
        }
      end

      netmap = JSON.parse(File.read(ARGV.fetch(0)))
      suffix = ARGV.fetch(1).sub(/\.\z/, "")
      expected = ARGV.fetch(2).split(",").reject(&:empty?)
      expect_objects = ARGV.fetch(3) == "true"
      routes = netmap.dig("DNS", "Routes") || {}
      route = routes[suffix] || routes["#{suffix}."]
      abort("expected DNS route #{suffix}, got #{routes.inspect}") if route.nil?
      normalized = Array(route).map { |resolver| normalize_resolver(resolver, expect_objects) }
      got = normalized.map { |resolver| resolver.fetch("Addr") }
      abort("expected DNS route #{suffix}=#{expected.inspect}, got #{got.inspect}") unless got == expected
      puts JSON.pretty_generate({suffix => normalized})
    ' "${netmap_path}" "${suffix}" "${expected_csv}" "${expect_objects}" >"${output_path}"
}

assert_dns_debug_resolve() {
  local resolver_client="$1"
  local expected_name="$2"
  local network="$3"
  local expected_value="$4"
  local output_path="$5"
  local raw_path="${output_path}.raw"
  docker exec "${resolver_client}" tailscale debug resolve "--net=${network}" "${expected_name}" \
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

assert_peer_magic_dns_debug_resolve() {
  local resolver_client="$1"
  local output_path="$2"
  local status_path="${output_path}.status.json"
  local expectations_path="${output_path}.expectations.tsv"
  docker exec "${resolver_client}" tailscale status --json >"${status_path}" 2>"${output_path}.status.err" &&
    ruby -rjson -e '
      status = JSON.parse(File.read(ARGV.fetch(0)))
      peers = status["Peer"] || {}
      abort("expected peers for MagicDNS resolver evidence, got none") if peers.empty?
      peers.each_value do |peer|
        name = peer.fetch("DNSName").to_s.sub(/\.\z/, "")
        abort("expected peer DNSName in #{peer.inspect}") if name.empty?
        ips = Array(peer["TailscaleIPs"])
        ip = ips.find { |value| value.to_s.include?(".") }
        network = "ip4"
        unless ip
          ip = ips.find { |value| value.to_s.include?(":") }
          network = "ip6"
        end
        abort("expected peer TailscaleIPs in #{peer.inspect}") if ip.to_s.empty?
        puts [name, network, ip].join("\t")
      end
    ' "${status_path}" >"${expectations_path}" || return

  local idx=0
  local name
  local network
  local expected_value
  while IFS=$'\t' read -r name network expected_value; do
    [[ -n "${name}" ]] || continue
    safe_name="${name//[^a-zA-Z0-9_.-]/-}"
    wait_for "peer MagicDNS ${resolver_client} resolves ${name}" \
      "assert_dns_debug_resolve '${resolver_client}' '${name}' '${network}' '${expected_value}' '${output_path}.${idx}.${safe_name}.${network}.json'" || {
        return 1
      }
    idx=$((idx + 1))
  done <"${expectations_path}"

  ruby -rjson -e '
    client = ARGV.fetch(0)
    rows = File.readlines(ARGV.fetch(1), chomp: true).reject(&:empty?).map do |line|
      name, network, resolved = line.split("\t", 3)
      {name: name, network: network, resolved: resolved}
    end
    puts JSON.pretty_generate({client: client, peer_magicdns_resolves: rows})
  ' "${resolver_client}" "${expectations_path}" >"${output_path}"
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

assert_self_file_sharing_cap() {
  local client_name="$1"
  local output_path="$2"
  local expected="$3"
  local netmap_path="${output_path}.netmap"
  docker exec "${client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      path = ARGV.fetch(0)
      expected = ARGV.fetch(1) == "true"
      cap = "https://tailscale.com/cap/file-sharing"
      netmap = JSON.parse(File.read(path))
      self_node = netmap["SelfNode"] || netmap["selfNode"] || {}
      cap_map = self_node["CapMap"] || self_node["capMap"] || {}
      has_cap = cap_map.key?(cap)
      abort("expected file-sharing CapMap presence #{expected}, got #{has_cap}; CapMap keys=#{cap_map.keys.inspect}") unless has_cap == expected
      puts JSON.pretty_generate({file_sharing_cap: has_cap, cap_map_keys: cap_map.keys.sort})
    ' "${netmap_path}" "${expected}" >"${output_path}"
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

assert_peer_route_owners() {
  local checks="$1"
  local group_label="$2"
  local raw_check source_idx peer_idx route extra source_name peer_name safe_check
  echo "::group::${group_label}"
  IFS=';' read -r -a peer_route_owner_checks <<<"${checks}"
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
}

need cargo
need curl
need docker
need ruby

harness_start_timeout_secs="${REAL_CLIENT_HARNESS_START_TIMEOUT_SECS:-60}"

echo "::group::build headscale-rs real-client harness"
cargo build --quiet --manifest-path tools/real-client/headscale-rs-harness/Cargo.toml
echo "::endgroup::"

if [[ -n "${dns_extra_records_json}" ]]; then
  export HSRS_HARNESS_DNS_EXTRA_RECORDS_JSON="${dns_extra_records_json}"
fi
if [[ -n "${dns_nameservers_json}" ]]; then
  export HSRS_HARNESS_DNS_NAMESERVERS_JSON="${dns_nameservers_json}"
fi
if [[ -n "${dns_split_nameservers_json}" ]]; then
  export HSRS_HARNESS_DNS_SPLIT_NAMESERVERS_JSON="${dns_split_nameservers_json}"
fi
if [[ -n "${dns_fallback_nameservers_json}" ]]; then
  export HSRS_HARNESS_DNS_FALLBACK_NAMESERVERS_JSON="${dns_fallback_nameservers_json}"
fi
if [[ -n "${dns_override_local}" ]]; then
  export HSRS_HARNESS_DNS_OVERRIDE_LOCAL="${dns_override_local}"
fi
if [[ -n "${route_health_probe_interval_secs}" ]]; then
  export HSRS_HARNESS_ROUTE_HEALTH_PROBE_INTERVAL_SECS="${route_health_probe_interval_secs}"
fi
if [[ -n "${route_health_probe_timeout_secs}" ]]; then
  export HSRS_HARNESS_ROUTE_HEALTH_PROBE_TIMEOUT_SECS="${route_health_probe_timeout_secs}"
fi
if [[ -n "${taildrop_enabled_bool}" ]]; then
  export HSRS_HARNESS_TAILDROP_ENABLED="${taildrop_enabled_bool}"
fi

harness_started=0
for harness_attempt in 1 2 3; do
  http_port="$(free_port 127.0.0.1)"
  https_port="$(free_port 0.0.0.0)"
  metrics_port="$(free_port 127.0.0.1)"

  echo "::group::start headscale-rs harness attempt ${harness_attempt}"
  harness_args=(
    tools/real-client/headscale-rs-harness/target/debug/headscale-rs-real-client-harness
    --http "127.0.0.1:${http_port}"
    --https "0.0.0.0:${https_port}"
    --metrics "127.0.0.1:${metrics_port}"
    --hostname host.docker.internal
    --public-url "https://host.docker.internal:${https_port}"
    --state-dir "${work_dir}/state"
    --ip-families "${harness_ip_families}"
  )
  if [[ -n "${harness_derp_map}" ]]; then
    harness_args+=(--derp-map "${harness_derp_map}")
  fi
  if [[ -n "${base_domain}" ]]; then
    harness_args+=(--base-domain "${base_domain}")
  fi
  "${harness_args[@]}" \
    >"${work_dir}/harness.stdout" \
    2>"${work_dir}/harness.stderr" &
  harness_pid="$!"

  if wait_for_with_timeout "harness health" "${harness_start_timeout_secs}" \
    "curl -fsS 'http://127.0.0.1:${http_port}/harness/health' >'${work_dir}/harness-health.stdout' 2>'${work_dir}/harness-health.stderr'" &&
    wait_for_with_timeout "harness metrics" "${harness_start_timeout_secs}" \
      "curl -fsS 'http://127.0.0.1:${metrics_port}/metrics' >'${work_dir}/harness-metrics.stdout' 2>'${work_dir}/harness-metrics.stderr'" &&
    wait_for_with_timeout "harness TLS certificate" "${harness_start_timeout_secs}" \
      "test -s '${work_dir}/state/tls.crt'"; then
    echo "harness http=http://127.0.0.1:${http_port}"
    echo "harness login=https://host.docker.internal:${https_port}"
    echo "harness metrics=http://127.0.0.1:${metrics_port}"
    echo "::endgroup::"
    harness_started=1
    break
  fi

  echo "harness startup attempt ${harness_attempt} failed" >&2
  if [[ -n "${harness_pid}" ]] && ! kill -0 "${harness_pid}" >/dev/null 2>&1; then
    wait "${harness_pid}" >/dev/null 2>&1 || true
    harness_pid=""
  fi
  stop_harness
  echo "::endgroup::"
done

if ((harness_started == 0)); then
  echo "failed to start headscale-rs harness after 3 attempts" >&2
  exit 1
fi

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

if [[ -n "${policy_json}" ]]; then
  echo "::group::load policy"
  curl -fsS -X PUT "http://127.0.0.1:${http_port}/harness/policy" \
    -H 'content-type: application/json' \
    --data-binary "${policy_json}" \
    >"${work_dir}/policy-load.txt"
  echo "::endgroup::"
fi

authkey=""
authkeys=()
if [[ "${login_mode}" == "authkey" ]]; then
  echo "::group::mint preauth key"
  if [[ -n "${client_users_csv}" || -n "${preauth_tags_by_client}" ]]; then
    for idx in "${!client_names[@]}"; do
      preauth_body="$(
        ruby -rjson -e '
          tags = ARGV.fetch(1).split(",").reject(&:empty?)
          puts JSON.generate({
            user: ARGV.fetch(0),
            reusable: ARGV.fetch(2) == "true",
            ephemeral: ARGV.fetch(3) == "true",
            expired: ARGV.fetch(4) == "true",
            tags: tags,
          })
        ' "${client_users[$idx]}" "${preauth_tags_values[$idx]}" "${preauth_reusable_json}" "${preauth_ephemeral_json}" "${preauth_expired_json}"
      )"
      preauth_json="$(
        curl -fsS -X POST "http://127.0.0.1:${http_port}/harness/preauth" \
          -H 'content-type: application/json' \
          -d "${preauth_body}"
      )"
      authkey="$(ruby -rjson -e 'puts JSON.parse(STDIN.read).fetch("key")' <<<"${preauth_json}")"
      authkeys+=("${authkey}")
    done
    echo "minted ${#authkeys[@]} per-client keys"
  else
    preauth_body="$(
      ruby -rjson -e '
        tags = ARGV.fetch(0).split(",").reject(&:empty?)
        puts JSON.generate({
          user: "alice",
          reusable: ARGV.fetch(1) == "true",
          ephemeral: ARGV.fetch(2) == "true",
          expired: ARGV.fetch(3) == "true",
          tags: tags,
        })
      ' "${preauth_tags}" "${preauth_reusable_json}" "${preauth_ephemeral_json}" "${preauth_expired_json}"
    )"
    preauth_json="$(
      curl -fsS -X POST "http://127.0.0.1:${http_port}/harness/preauth" \
        -H 'content-type: application/json' \
        -d "${preauth_body}"
    )"
    authkey="$(ruby -rjson -e 'puts JSON.parse(STDIN.read).fetch("key")' <<<"${preauth_json}")"
    for _client_name in "${client_names[@]}"; do
      authkeys+=("${authkey}")
    done
    echo "minted ${authkey%%-*}-..."
  fi
  echo "::endgroup::"
fi

echo "::group::start stock tailscale client"
for client_name in "${client_names[@]}"; do
  tailscaled_prefix=""
  if ((force_derp_flag)); then
    tailscaled_prefix="TS_DEBUG_ALWAYS_USE_DERP=1 "
  fi
  client_entry="update-ca-certificates >/tmp/update-ca-certificates.log 2>&1; ${tailscaled_prefix}tailscaled --tun=userspace-networking --verbose=10 --statedir=/tmp/tailscale-state >/tmp/tailscaled.log 2>&1 & sleep infinity"
  if ((install_openssh_client)); then
    client_entry="apk add --no-cache openssh-client >/tmp/apk-openssh-client.log 2>&1; ${client_entry}"
  fi
  if [[ -n "${ssh_user}" ]]; then
    client_entry="id '${ssh_user}' >/dev/null 2>&1 || adduser -D -h '/home/${ssh_user}' -s /bin/sh '${ssh_user}' >/tmp/adduser-${ssh_user}.log 2>&1; ${client_entry}"
  fi
  docker run -d \
    --name "${client_name}" \
    --hostname "${client_name}" \
    --add-host host.docker.internal:host-gateway \
    -v "${work_dir}/state/tls.crt:/usr/local/share/ca-certificates/headscale-rs.crt:ro" \
    --entrypoint /bin/sh \
    "${image}" \
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
    "--login-server=https://host.docker.internal:${https_port}"
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
    register_body="$(ruby -rjson -e 'puts JSON.generate({user: ARGV.fetch(0)})' "${register_user}")"
    curl -fsS -X POST "http://127.0.0.1:${http_port}/harness/register/${registration_id}" \
      -H 'content-type: application/json' \
      -d "${register_body}" \
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
  if ((authkey_failure_flags[$idx])); then
    if tailscale_logged_in "${client_name}"; then
      echo "expected auth-key login to fail for ${client_name}, but it reached a logged-in netmap" >&2
      docker exec "${client_name}" tailscale status --json >"${work_dir}/${client_name}.unexpected-tailscale-status.json" 2>/dev/null || true
      exit 1
    fi
    echo "auth-key login failed as expected for ${client_name}"
    docker exec "${client_name}" tailscale status --json >"${work_dir}/${client_name}.tailscale-status.json" 2>/dev/null || true
    continue
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
  echo "::group::force web reauth"
  for idx in "${!client_names[@]}"; do
    client_name="${client_names[$idx]}"
    reauth_args=(
      tailscale up
      "--login-server=https://host.docker.internal:${https_port}"
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
    register_body="$(ruby -rjson -e 'puts JSON.generate({user: ARGV.fetch(0)})' "${register_user}")"
    curl -fsS -X POST "http://127.0.0.1:${http_port}/harness/register/${registration_id}" \
      -H 'content-type: application/json' \
      -d "${register_body}" \
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
  echo "::group::assert rejected web registration"
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines.json"
  ruby -rjson -e '
    machines = JSON.parse(File.read(ARGV.fetch(0)))
    expected_count = Integer(ARGV.fetch(1))
    abort("expected #{expected_count} registered machines after rejected registration, got #{machines.length}") unless machines.length == expected_count
    puts JSON.pretty_generate({machines: machines.length})
  ' "${work_dir}/machines.json" "${expected_machine_count}"
  echo "::endgroup::"
  echo "${login_mode} rejected-registration real-client smoke passed"
  exit 0
fi

if [[ -n "${approve_routes}" || -n "${approve_routes_by_client}" ]]; then
  echo "::group::approve routes"
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-before-approve.json"
  approval_rows="$(
    ruby -rjson -e '
      machines = JSON.parse(File.read(ARGV.fetch(0)))
      expected = Integer(ARGV.fetch(1))
      expected_names = ARGV.fetch(2).split(",")
      routes_by_client = ARGV.fetch(3).split(";", -1)
      abort("expected #{expected} registered machines, got #{machines.length}") unless machines.length == expected
      expected_names.each_with_index do |name, idx|
        machine = machines.find { |candidate| candidate.fetch("hostname") == name }
        abort("missing machine #{name.inspect} in #{machines.inspect}") unless machine
        routes = routes_by_client.fetch(idx, "")
        next if routes.empty?
        puts [machine.fetch("node_key"), routes].join("\t")
      end
    ' "${work_dir}/machines-before-approve.json" "${expected_machine_count}" "${expected_client_names_csv}" "$(IFS=';'; echo "${approve_routes_values[*]}")"
  )"
  while IFS=$'\t' read -r node_key routes; do
    [[ -z "${node_key}" ]] && continue
    routes_json="$(ruby -rjson -e 'puts JSON.generate({routes: ARGV.fetch(0).split(",").reject(&:empty?)})' "${routes}")"
    curl -fsS -X PUT "http://127.0.0.1:${http_port}/harness/machines/${node_key}/routes" \
      -H 'content-type: application/json' \
      -d "${routes_json}" \
      >"${work_dir}/approved-routes-${node_key#nodekey:}.json"
  done <<<"${approval_rows}"
  echo "::endgroup::"
fi

if ((authkey_relogin_requested_flag)); then
  if ((authkey_relogin_different_user_flag)); then
    echo "::group::auth-key logout and different-user relogin rejection"
  elif ((authkey_relogin_expired_flag)); then
    echo "::group::auth-key logout and expired-key relogin rejection"
  else
    echo "::group::auth-key logout and same-user relogin"
  fi
  relogin_authkeys=()
  relogin_before_ips=()
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-before-relogin.json"
  for idx in "${!client_names[@]}"; do
    client_name="${client_names[$idx]}"
    relogin_before_ips+=("$(tailscale_status_ips "${work_dir}/${client_name}.tailscale-status.json")")
    relogin_user="${client_users[$idx]}"
    if ((authkey_relogin_different_user_flag)); then
      relogin_user="relogin-user-$((idx + 1))"
      if [[ "${relogin_user}" == "${client_users[$idx]}" ]]; then
        relogin_user="relogin-other-user-$((idx + 1))"
      fi
    fi
    preauth_body="$(
      ruby -rjson -e '
        tags = ARGV.fetch(1).split(",").reject(&:empty?)
        puts JSON.generate({
          user: ARGV.fetch(0),
          reusable: true,
          ephemeral: false,
          expired: ARGV.fetch(2) == "true",
          tags: tags,
        })
      ' "${relogin_user}" "${preauth_tags_values[$idx]}" "${authkey_relogin_expired_json}"
    )"
    preauth_json="$(
      curl -fsS -X POST "http://127.0.0.1:${http_port}/harness/preauth" \
        -H 'content-type: application/json' \
        -d "${preauth_body}"
    )"
    relogin_authkeys+=("$(ruby -rjson -e 'puts JSON.parse(STDIN.read).fetch("key")' <<<"${preauth_json}")")
  done

  for idx in "${!client_names[@]}"; do
    client_name="${client_names[$idx]}"
    docker exec "${client_name}" tailscale logout \
      >"${work_dir}/${client_name}.logout.stdout" \
      2>"${work_dir}/${client_name}.logout.stderr"
    wait_for "tailscale logged out ${client_name}" \
      "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"

    up_args=(
      tailscale up
      "--login-server=https://host.docker.internal:${https_port}"
      "--hostname=${client_name}"
      "--timeout=${up_timeout}"
      --accept-routes=false
      "--accept-dns=${accept_dns_arg}"
      "--authkey=${relogin_authkeys[$idx]}"
    )
    if [[ -n "${advertise_routes_values[$idx]}" ]]; then
      up_args+=("--advertise-routes=${advertise_routes_values[$idx]}")
    fi
    if ((enable_tailscale_ssh_flag)); then
      up_args+=(--ssh)
    fi
    case "${advertise_exit_node_values[$idx]}" in
      1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
        up_args+=(--advertise-exit-node)
        ;;
    esac
    relogin_status=0
    run_with_timeout "tailscale auth-key relogin ${client_name}" docker exec "${client_name}" "${up_args[@]}" ||
      relogin_status="$?"
    if ((authkey_relogin_expired_flag || authkey_relogin_different_user_flag)); then
      if tailscale_logged_in "${client_name}"; then
        if ((authkey_relogin_different_user_flag)); then
          echo "expected different-user auth-key relogin to fail for ${client_name}, but it reached a logged-in netmap" >&2
        else
          echo "expected expired auth-key relogin to fail for ${client_name}, but it reached a logged-in netmap" >&2
        fi
        docker exec "${client_name}" tailscale status --json >"${work_dir}/${client_name}.unexpected-relogin-status.json" 2>/dev/null || true
        exit 1
      fi
      docker exec "${client_name}" tailscale status --json >"${work_dir}/${client_name}.expected-relogin-failure-status.json" 2>/dev/null || true
      if ((authkey_relogin_different_user_flag)); then
        echo "different-user auth-key relogin failed as expected for ${client_name}"
      else
        echo "expired auth-key relogin failed as expected for ${client_name}"
      fi
      continue
    fi
    if ((relogin_status != 0)); then
      echo "tailscale same-user relogin ${client_name} returned ${relogin_status}; verifying logged-in netmap"
    fi
    if ! wait_for "tailscale logged-in netmap after same-user relogin ${client_name}" "tailscale_logged_in '${client_name}'"; then
      dump_client_debug "${client_name}"
      exit 1
    fi
    docker exec "${client_name}" tailscale status --json >"${work_dir}/${client_name}.relogin-tailscale-status.json"
    relogin_after_ips="$(tailscale_status_ips "${work_dir}/${client_name}.relogin-tailscale-status.json")"
    if [[ "${relogin_after_ips}" != "${relogin_before_ips[$idx]}" ]]; then
      echo "expected stable Tailscale IPs for ${client_name}: ${relogin_before_ips[$idx]}, got ${relogin_after_ips}" >&2
      exit 1
    fi
    cp "${work_dir}/${client_name}.relogin-tailscale-status.json" "${work_dir}/${client_name}.tailscale-status.json"
  done
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-after-relogin.json"
  if ((authkey_relogin_expired_flag || authkey_relogin_different_user_flag)); then
    ruby -rjson -e '
      before = JSON.parse(File.read(ARGV.fetch(0)))
      after = JSON.parse(File.read(ARGV.fetch(1)))
      expected_count = Integer(ARGV.fetch(2))
      mode = ARGV.fetch(3)
      expected_names = ARGV.fetch(4).split(",").reject(&:empty?)
      abort("expected #{expected_count} machines before #{mode} relogin, got #{before.length}") unless before.length == expected_count
      abort("expected #{expected_count} machines after #{mode} relogin rejection, got #{after.length}") unless after.length == expected_count

      if mode == "different-user"
        comparable = %w[machine_key user hostname addresses available_routes approved_routes]
        expected_names.each do |name|
          old = before.find { |machine| machine.fetch("hostname") == name }
          new = after.find { |machine| machine.fetch("hostname") == name }
          abort("missing before-relogin machine #{name.inspect}") unless old
          abort("missing after-relogin machine #{name.inspect}") unless new
          comparable.each do |field|
            old_value = old.fetch(field)
            new_value = new.fetch(field)
            old_value = old_value.sort if old_value.is_a?(Array)
            new_value = new_value.sort if new_value.is_a?(Array)
            abort("different-user relogin changed #{name} #{field}: #{old_value.inspect} -> #{new_value.inspect}") unless old_value == new_value
          end
        end
      end
      puts JSON.pretty_generate({"#{mode.tr("-", "_")}_relogin_rejected_machines": after.length})
    ' "${work_dir}/machines-before-relogin.json" "${work_dir}/machines-after-relogin.json" "${expected_machine_count}" "$([[ "${authkey_relogin_different_user_flag}" -eq 1 ]] && printf different-user || printf expired)" "${expected_client_names_csv}"
    echo "::endgroup::"
    if ((authkey_relogin_different_user_flag)); then
      echo "authkey different-user-relogin real-client smoke passed"
    else
      echo "authkey expired-relogin real-client smoke passed"
    fi
    exit 0
  fi
  ruby -rjson -e '
    before = JSON.parse(File.read(ARGV.fetch(0)))
    after = JSON.parse(File.read(ARGV.fetch(1)))
    expected_count = Integer(ARGV.fetch(2))
    expected_names = ARGV.fetch(3).split(",")
    abort("expected #{expected_count} machines before relogin, got #{before.length}") unless before.length == expected_count
    abort("expected #{expected_count} machines after relogin, got #{after.length}") unless after.length == expected_count

    comparable = %w[machine_key user hostname addresses available_routes approved_routes]
    expected_names.each do |name|
      old = before.find { |machine| machine.fetch("hostname") == name }
      new = after.find { |machine| machine.fetch("hostname") == name }
      abort("missing before-relogin machine #{name.inspect}") unless old
      abort("missing after-relogin machine #{name.inspect}") unless new
      comparable.each do |field|
        old_value = old.fetch(field)
        new_value = new.fetch(field)
        old_value = old_value.sort if old_value.is_a?(Array)
        new_value = new_value.sort if new_value.is_a?(Array)
        abort("relogin changed #{name} #{field}: #{old_value.inspect} -> #{new_value.inspect}") unless old_value == new_value
      end
    end
    puts JSON.pretty_generate({relogin_preserved_machines: expected_names})
  ' "${work_dir}/machines-before-relogin.json" "${work_dir}/machines-after-relogin.json" "${expected_machine_count}" "${expected_client_names_csv}"
  echo "::endgroup::"
fi

if [[ -n "${set_tags_after_login}" ]]; then
  echo "::group::set forced tags"
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-before-tags.json"
  node_key="$(
    ruby -rjson -e '
      machines = JSON.parse(File.read(ARGV.fetch(0)))
      expected = Integer(ARGV.fetch(1))
      abort("expected #{expected} registered machines, got #{machines.length}") unless machines.length == expected
      puts machines.map { |machine| machine.fetch("node_key") }
    ' "${work_dir}/machines-before-tags.json" "${expected_machine_count}"
  )"
  tags_json="$(ruby -rjson -e 'puts JSON.generate({tags: ARGV.fetch(0).split(",").reject(&:empty?)})' "${set_tags_after_login}")"
  while IFS= read -r node_key; do
    tag_status=0
    curl -fsS -X PUT "http://127.0.0.1:${http_port}/harness/machines/${node_key}/tags" \
      -H 'content-type: application/json' \
      -d "${tags_json}" \
      >"${work_dir}/set-tags-${node_key#nodekey:}.json" \
      2>"${work_dir}/set-tags-${node_key#nodekey:}.err" ||
      tag_status="$?"
    if ((expect_set_tags_failure)); then
      if ((tag_status == 0)); then
        echo "expected tag update to fail for ${node_key}" >&2
        exit 1
      fi
      continue
    fi
    if ((tag_status != 0)); then
      cat "${work_dir}/set-tags-${node_key#nodekey:}.err" >&2 || true
      exit "${tag_status}"
    fi
  done <<<"${node_key}"
  echo "::endgroup::"
fi

echo "::group::assert harness machine state"
curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines.json"
if [[ -n "${expected_primary_route}" ]]; then
  curl -fsS -H 'accept: application/json' \
    "http://127.0.0.1:${http_port}/harness/routes" \
    >"${work_dir}/debug-routes.json"
else
  printf '{}\n' >"${work_dir}/debug-routes.json"
fi
ruby -rjson -e '
  expected_routes_by_client = ARGV.fetch(1).split(";", -1).map { |routes| routes.split(",").reject(&:empty?).sort }
  expected_approved_by_client = ARGV.fetch(2).split(";", -1).map { |routes| routes.split(",").reject(&:empty?).sort }
  expected_count = Integer(ARGV.fetch(3))
  expected_primary_route = ARGV.fetch(4)
  debug_routes_path = ARGV.fetch(5)
  expected_tags = ARGV.fetch(6).split(",").reject(&:empty?).sort
  expected_hostname_prefix = ARGV.fetch(7)
  expect_tags_exact = ARGV.fetch(8) == "true"
  expected_names = ARGV.fetch(9).split(",")
  expected_users = ARGV.fetch(10).split(",")
  expected_families = ARGV.fetch(11)
  expected_primary_candidates = Integer(ARGV.fetch(12))
  assert_available = ARGV.fetch(13) == "true"
  assert_approved = ARGV.fetch(14) == "true"
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
    expected_user = expected_user_by_host.fetch(machine["hostname"]) {
      abort("unexpected machine hostname #{machine["hostname"].inspect}; expected one of #{expected_names.inspect}")
    }
    abort("expected user #{expected_user.inspect}, got #{machine["user"].inspect}") unless machine["user"] == expected_user
    abort("expected hostname prefix #{expected_hostname_prefix.inspect}, got #{machine["hostname"].inspect}") unless machine["hostname"].start_with?(expected_hostname_prefix)
    expected_routes = expected_routes_by_host.fetch(machine["hostname"], []) || []
    expected_approved = expected_approved_by_host.fetch(machine["hostname"], []) || []
    ips = Array(machine["addresses"])
    ips << machine["ipv4"] if ips.empty? && machine["ipv4"].to_s != ""
    ips << machine["ipv6"] if ips.empty? && machine["ipv6"].to_s != ""
    assert_ip_families("machine #{machine["hostname"]}", ips, expected_families)
    available_routes = Array(machine["available_routes"]).sort
    unless (!assert_available && expected_routes.empty?) || available_routes == expected_routes
      abort("expected available routes #{expected_routes.inspect}, got #{available_routes.inspect}")
    end
    approved_routes = Array(machine["approved_routes"]).sort
    unless (!assert_approved && expected_approved.empty?) || approved_routes == expected_approved
      abort("expected approved routes #{expected_approved.inspect}, got #{approved_routes.inspect}")
    end
    forced_tags = Array(machine["forced_tags"]).sort
    unless (!expect_tags_exact && expected_tags.empty?) || forced_tags == expected_tags
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
    abort("expected #{expected_primary_candidates} available primary-route candidates, got #{available_entries.length}") unless available_entries.length == expected_primary_candidates
  end

  if expected_count == 1
    puts JSON.pretty_generate(machines.fetch(0))
  else
    puts JSON.pretty_generate({machines: machines, debug_routes: debug_routes})
  end
  ' "${work_dir}/machines.json" "${expected_available_routes_spec}" "${expected_approved_routes_spec}" "${expected_machine_count}" "${expected_primary_route}" "${work_dir}/debug-routes.json" "${expected_tags}" "${run_id}" "$([[ "${expect_tags_exact}" -eq 1 ]] && printf true || printf false)" "${expected_client_names_csv}" "${expected_client_users_csv}" "${expected_tailscale_ip_families}" "${expected_primary_route_candidates}" "${expect_available_by_client}" "${expect_approved_by_client}"
echo "::endgroup::"

if ((expect_debug_ping)); then
  echo "::group::assert debug PingRequest lifecycle"
  ping_target="${client_names[0]}"
  curl -fsS --max-time "${timeout_secs}" \
    "http://127.0.0.1:${metrics_port}/debug/ping?node=${ping_target}" \
    >"${work_dir}/debug-ping.html"
  if ! grep -Eq 'Ping OK|Pong|responded' "${work_dir}/debug-ping.html"; then
    echo "expected /debug/ping to report a successful PingRequest callback" >&2
    cat "${work_dir}/debug-ping.html" >&2 || true
    dump_client_debug "${ping_target}"
    exit 1
  fi
  ruby -rjson -e 'puts JSON.pretty_generate({debug_ping: "ok", node: ARGV.fetch(0)})' "${ping_target}"
  echo "::endgroup::"
fi

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

if ((expect_peer_magic_dns_resolve)); then
  echo "::group::assert peer MagicDNS client resolution"
  for client_name in "${client_names[@]}"; do
    safe_client="${client_name//[^a-zA-Z0-9_.-]/-}"
    wait_for "peer MagicDNS resolver ${client_name}" \
      "assert_peer_magic_dns_debug_resolve '${client_name}' '${work_dir}/${safe_client}.peer-magicdns-resolve.json'" || {
        dump_client_debug "${client_name}"
        exit 1
      }
    cat "${work_dir}/${safe_client}.peer-magicdns-resolve.json"
  done
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

if [[ -n "${expected_dns_debug_resolves}" ]]; then
  echo "::group::assert DNS client resolution"
  resolver_client="${client_names[0]}"
  IFS=',' read -r -a dns_resolution_expectations <<<"${expected_dns_debug_resolves}"
  for expectation in "${dns_resolution_expectations[@]}"; do
    host="${expectation%%=*}"
    expected="${expectation#*=}"
    if [[ -z "${host}" || -z "${expected}" || "${host}" == "${expectation}" ]]; then
      echo "REAL_CLIENT_EXPECT_DNS_DEBUG_RESOLVES entries must be host=value or host=network:value, got ${expectation}" >&2
      exit 2
    fi
    network=""
    if [[ "${expected}" =~ ^(ip4|ip6):(.*)$ ]]; then
      network="${BASH_REMATCH[1]}"
      expected="${BASH_REMATCH[2]}"
    elif [[ "${expected}" == *:* ]]; then
      network=ip6
    else
      network=ip4
    fi
    safe_host="${host//[^a-zA-Z0-9_.-]/-}"
    wait_for "DNS debug resolve ${host}" \
      "assert_dns_debug_resolve '${resolver_client}' '${host}' '${network}' '${expected}' '${work_dir}/dns-resolve-${safe_host}-${network}.json'" || {
        dump_client_debug "${resolver_client}"
        exit 1
      }
    cat "${work_dir}/dns-resolve-${safe_host}-${network}.json"
  done
  echo "::endgroup::"
fi

if [[ -n "${expected_dns_resolvers}" ]]; then
  echo "::group::assert DNS resolvers"
  resolver_client="${client_names[0]}"
  wait_for "DNS resolvers ${expected_dns_resolvers}" \
    "assert_dns_resolver_list '${resolver_client}' 'Resolvers' '${expected_dns_resolvers}' '${work_dir}/dns-resolvers.json' '${expect_dns_resolver_objects}'" || {
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
    "assert_dns_resolver_list '${resolver_client}' 'FallbackResolvers' '${expected_dns_fallback_resolvers}' '${work_dir}/dns-fallback-resolvers.json' '${expect_dns_resolver_objects}'" || {
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
      "assert_dns_route '${resolver_client}' '${suffix}' '${expected_csv}' '${work_dir}/dns-route-${safe_suffix}.json' '${expect_dns_resolver_objects}'" || {
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
  assert_peer_route_owners "${expected_peer_route_owners}" "assert route-via peer route owners"
fi

if [[ -n "${policy_reload_json}" ]]; then
  echo "::group::reload policy"
  curl -fsS -X PUT "http://127.0.0.1:${http_port}/harness/policy" \
    -H 'content-type: application/json' \
    --data-binary "${policy_reload_json}" \
    >"${work_dir}/policy-reload.txt"
  echo "::endgroup::"
fi

if [[ -n "${expected_file_sharing_cap_bool}" ]]; then
  echo "::group::assert file-sharing CapMap"
  for client_name in "${client_names[@]}"; do
    if ! wait_for "file-sharing CapMap ${client_name}" \
      "assert_self_file_sharing_cap '${client_name}' '${work_dir}/file-sharing-cap-${client_name}.json' '${expected_file_sharing_cap_bool}'"; then
      cat "${work_dir}/file-sharing-cap-${client_name}.json.err" >&2 || true
      dump_client_debug "${client_name}"
      exit 1
    fi
    cat "${work_dir}/file-sharing-cap-${client_name}.json"
  done
  echo "::endgroup::"
fi

if [[ -n "${expected_peer_route_owners_after_policy_reload}" ]]; then
  if [[ -z "${policy_reload_json}" ]]; then
    echo "REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS_AFTER_POLICY_RELOAD requires REAL_CLIENT_POLICY_RELOAD_JSON" >&2
    exit 2
  fi
  assert_peer_route_owners "${expected_peer_route_owners_after_policy_reload}" \
    "assert route-via peer route owners after policy reload"
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

if [[ -n "${expected_derp_verify_requests_min}" ]]; then
  echo "::group::assert DERP verify-client admission"
  curl -fsS "http://127.0.0.1:${http_port}/harness/derp/verify-log" >"${work_dir}/derp-verify-log.json"
  ruby -rjson -e '
    log = JSON.parse(File.read(ARGV.fetch(0)))
    expected = Integer(ARGV.fetch(1))
    abort("expected at least #{expected} DERP verify requests, got #{log.inspect}") unless log.fetch("requests") >= expected
    abort("expected at least #{expected} allowed DERP verify requests, got #{log.inspect}") unless log.fetch("allowed") >= expected
    abort("expected zero denied DERP verify requests, got #{log.inspect}") unless log.fetch("denied") == 0
    puts JSON.pretty_generate(log)
  ' "${work_dir}/derp-verify-log.json" "${expected_derp_verify_requests_min}"
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
          cat "${work_dir}/ssh-${source_name}-to-${target_name}.stdout" >&2 || true
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
        if [[ -n "${ssh_timeout_status}" && "${ssh_timeout_status}" != "any" ]] &&
          ((ssh_status != ssh_timeout_status)); then
          echo "expected timed-out tailscale ssh status ${ssh_timeout_status}, got ${ssh_status}" >&2
          cat "${stderr_path}" >&2 || true
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
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-before-failover.json"
  curl -fsS -H 'accept: application/json' \
    "http://127.0.0.1:${http_port}/harness/routes" \
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
    "http://127.0.0.1:${http_port}/harness/routes" \
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

  if [[ -n "${expected_primary_sticky_route}" ]]; then
    echo "::group::assert primary route sticky return"
    routes_json="$(ruby -rjson -e 'puts JSON.generate({routes: [ARGV.fetch(0)]})' "${expected_primary_sticky_route}")"
    curl -fsS -X PUT "http://127.0.0.1:${http_port}/harness/machines/${failover_node_key}/routes" \
      -H 'content-type: application/json' \
      -d "${routes_json}" \
      >"${work_dir}/sticky-reapprove-old-primary.json"
    curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-after-sticky.json"
    curl -fsS -H 'accept: application/json' \
      "http://127.0.0.1:${http_port}/harness/routes" \
      >"${work_dir}/debug-routes-after-sticky.json"
    ruby -rjson -e '
      route = ARGV.fetch(3)
      returned_node_key = ARGV.fetch(4)
      expected_count = Integer(ARGV.fetch(5))

      def stable_id_from_key(hex)
        h = 0xcbf29ce484222325
        hex.each_byte do |byte|
          h ^= byte
          h = (h * 0x100000001b3) & 0xffffffffffffffff
        end
        h & 0x7fffffffffffffff
      end

      after_failover = JSON.parse(File.read(ARGV.fetch(0)))
      after_sticky = JSON.parse(File.read(ARGV.fetch(1)))
      machines = JSON.parse(File.read(ARGV.fetch(2)))
      failover_owner = after_failover.fetch("primary_routes").fetch(route)
      sticky_owner = after_sticky.fetch("primary_routes").fetch(route) {
        abort("missing primary route #{route.inspect} after sticky return")
      }
      returned_id = stable_id_from_key(returned_node_key.sub(/\Anodekey:/, ""))
      abort("returned node unexpectedly stole #{route}: #{sticky_owner.inspect}") if sticky_owner == returned_id
      abort("expected sticky owner #{failover_owner.inspect}, got #{sticky_owner.inspect}") unless sticky_owner == failover_owner

      returned = machines.find { |machine| machine.fetch("node_key") == returned_node_key }
      abort("missing returned machine #{returned_node_key}") unless returned
      abort("returned machine missing approved route #{route}") unless Array(returned["approved_routes"]).include?(route)
      abort("returned machine missing available route #{route}") unless Array(returned["available_routes"]).include?(route)

      active_candidates = after_sticky.fetch("available_routes").select do |_node_id, routes|
        Array(routes).include?(route)
      end
      abort("expected #{expected_count} active candidates after sticky return, got #{active_candidates.length}") unless active_candidates.length == expected_count

      puts JSON.pretty_generate({
        returned_node_key: returned_node_key,
        returned_id: returned_id,
        sticky_owner: sticky_owner,
        debug_routes: after_sticky,
      })
    ' "${work_dir}/debug-routes-after-failover.json" "${work_dir}/debug-routes-after-sticky.json" "${work_dir}/machines-after-sticky.json" "${expected_primary_sticky_route}" "${failover_node_key}" "${expected_machine_count}"
    echo "::endgroup::"
  fi
fi

if [[ -n "${expected_primary_withdraw_route}" ]]; then
  echo "::group::assert primary route withdrawal"
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-before-withdraw.json"
  curl -fsS -H 'accept: application/json' \
    "http://127.0.0.1:${http_port}/harness/routes" \
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
        "http://127.0.0.1:${http_port}/harness/routes" \
        >"${work_dir}/debug-routes-after-withdraw.json" &&
      ruby -rjson -e '
        route = ARGV.fetch(4)
        withdrawn_client = ARGV.fetch(5)
        expected_count = Integer(ARGV.fetch(6))
        preserve_approval = ARGV.fetch(7) == "true"

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
        if preserve_approval
          abort("withdrawn client lost approved route #{route}") unless Array(withdrawn["approved_routes"]).include?(route)
        end

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
          withdrawn_approved_routes: Array(withdrawn["approved_routes"]).sort,
          before_owner: before_owner,
          after_owner: after_owner,
          debug_routes: after_debug,
        })
      ' "${work_dir}/machines-before-withdraw.json" "${work_dir}/debug-routes-before-withdraw.json" "${work_dir}/machines-after-withdraw.json" "${work_dir}/debug-routes-after-withdraw.json" "${expected_primary_withdraw_route}" "${withdraw_client_name}" "${expected_machine_count}" "$([[ "${expect_withdraw_approval_preserved}" -eq 1 ]] && printf true || printf false)"
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
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-before-route-health.json"
  curl -fsS -H 'accept: application/json' \
    "http://127.0.0.1:${http_port}/harness/routes" \
    >"${work_dir}/debug-routes-before-route-health.json"
  route_health_client_name="$(
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
        abort("missing primary route #{route.inspect} before route-health failover")
      }
      machine = machines.find do |candidate|
        stable_id_from_key(candidate.fetch("node_key").sub(/\Anodekey:/, "")) == primary_owner
      end
      abort("primary owner #{primary_owner.inspect} did not match a registered machine") unless machine
      puts machine.fetch("hostname")
    ' "${work_dir}/machines-before-route-health.json" "${work_dir}/debug-routes-before-route-health.json" "${expected_route_health_failover_route}"
  )"

  docker pause "${route_health_client_name}" >/dev/null
  deadline=$((SECONDS + timeout_secs))
  until
    curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-after-route-health.json" &&
      curl -fsS -H 'accept: application/json' \
        "http://127.0.0.1:${http_port}/harness/routes" \
        >"${work_dir}/debug-routes-after-route-health.json" &&
      ruby -rjson -e '
        route = ARGV.fetch(4)
        paused_client = ARGV.fetch(5)
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
        abort("expected #{expected_count} machines before route-health, got #{before_machines.length}") unless before_machines.length == expected_count
        abort("expected #{expected_count} machines after route-health, got #{after_machines.length}") unless after_machines.length == expected_count

        before_owner = before_debug.fetch("primary_routes").fetch(route)
        after_owner = after_debug.fetch("primary_routes").fetch(route) {
          abort("missing primary route #{route.inspect} after route-health failover")
        }
        abort("expected route-health primary owner to change, still #{after_owner.inspect}") if after_owner == before_owner

        remaining_ids = after_machines
          .reject { |machine| machine.fetch("hostname") == paused_client }
          .select { |machine| Array(machine["available_routes"]).include?(route) && Array(machine["approved_routes"]).include?(route) }
          .map { |machine| stable_id_from_key(machine.fetch("node_key").sub(/\Anodekey:/, "")) }
        abort("new primary owner #{after_owner.inspect} not among remaining active routers #{remaining_ids.inspect}") unless remaining_ids.include?(after_owner)

        puts JSON.pretty_generate({
          paused_client: paused_client,
          before_owner: before_owner,
          after_owner: after_owner,
          debug_routes: after_debug,
        })
      ' "${work_dir}/machines-before-route-health.json" "${work_dir}/debug-routes-before-route-health.json" "${work_dir}/machines-after-route-health.json" "${work_dir}/debug-routes-after-route-health.json" "${expected_route_health_failover_route}" "${route_health_client_name}" "${expected_machine_count}"
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
  curl -fsS -H 'accept: application/json' \
    "http://127.0.0.1:${http_port}/harness/routes" \
    >"${work_dir}/debug-routes-after-route-health-recovery.json"
  ruby -rjson -e '
    route = ARGV.fetch(2)
    failed_over_owner = JSON.parse(File.read(ARGV.fetch(0))).fetch("primary_routes").fetch(route)
    recovered_owner = JSON.parse(File.read(ARGV.fetch(1))).fetch("primary_routes").fetch(route)
    abort("route-health recovery stole #{route}: #{recovered_owner.inspect}, expected sticky #{failed_over_owner.inspect}") unless recovered_owner == failed_over_owner
    puts JSON.pretty_generate({route: route, sticky_owner: recovered_owner})
  ' "${work_dir}/debug-routes-after-route-health.json" "${work_dir}/debug-routes-after-route-health-recovery.json" "${expected_route_health_failover_route}"
  if [[ -n "${expected_peer_route_owners_after_route_health}" ]]; then
    assert_peer_route_owners "${expected_peer_route_owners_after_route_health}" \
      "assert route-via peer route owners after route-health failover"
  fi
  echo "::endgroup::"
fi

if [[ -n "${expected_route_health_all_unhealthy_route}" ]]; then
  echo "::group::assert route-health all-unhealthy fallback"
  curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-before-route-health-all-unhealthy.json"
  curl -fsS -H 'accept: application/json' \
    "http://127.0.0.1:${http_port}/harness/routes" \
    >"${work_dir}/debug-routes-before-route-health-all-unhealthy.json"
  route_health_all_selection="$(
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
        abort("missing primary route #{route.inspect} before all-unhealthy route-health check")
      }
      candidates = machines
        .select { |machine| Array(machine["available_routes"]).include?(route) && Array(machine["approved_routes"]).include?(route) }
        .map { |machine| [stable_id_from_key(machine.fetch("node_key").sub(/\Anodekey:/, "")), machine.fetch("hostname")] }
        .sort_by(&:first)
      abort("expected at least two route-health candidates for #{route}, got #{candidates.inspect}") if candidates.length < 2
      primary = candidates.find { |id, _hostname| id == primary_owner }
      abort("primary owner #{primary_owner.inspect} did not match active candidates #{candidates.inspect}") unless primary
      puts primary.fetch(1)
      candidates.each { |_id, hostname| puts hostname }
    ' "${work_dir}/machines-before-route-health-all-unhealthy.json" "${work_dir}/debug-routes-before-route-health-all-unhealthy.json" "${expected_route_health_all_unhealthy_route}"
  )"
  mapfile -t route_health_all_lines <<<"${route_health_all_selection}"
  route_health_all_primary_name="${route_health_all_lines[0]}"
  route_health_all_candidates=("${route_health_all_lines[@]:1}")
  route_health_all_paused=()

  docker pause "${route_health_all_primary_name}" >/dev/null
  route_health_all_paused+=("${route_health_all_primary_name}")
  deadline=$((SECONDS + timeout_secs))
  until
    curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-after-route-health-first-unhealthy.json" &&
      curl -fsS -H 'accept: application/json' \
        "http://127.0.0.1:${http_port}/harness/routes" \
        >"${work_dir}/debug-routes-after-route-health-first-unhealthy.json" &&
      ruby -rjson -e '
        route = ARGV.fetch(4)
        paused_client = ARGV.fetch(5)
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
        abort("expected #{expected_count} machines before first route-health timeout, got #{before_machines.length}") unless before_machines.length == expected_count
        abort("expected #{expected_count} machines after first route-health timeout, got #{after_machines.length}") unless after_machines.length == expected_count

        before_owner = before_debug.fetch("primary_routes").fetch(route)
        after_owner = after_debug.fetch("primary_routes").fetch(route) {
          abort("missing primary route #{route.inspect} after first route-health timeout")
        }
        abort("expected first route-health timeout to fail over, still #{after_owner.inspect}") if after_owner == before_owner

        remaining_ids = after_machines
          .reject { |machine| machine.fetch("hostname") == paused_client }
          .select { |machine| Array(machine["available_routes"]).include?(route) && Array(machine["approved_routes"]).include?(route) }
          .map { |machine| stable_id_from_key(machine.fetch("node_key").sub(/\Anodekey:/, "")) }
        abort("first failover owner #{after_owner.inspect} not among remaining active routers #{remaining_ids.inspect}") unless remaining_ids.include?(after_owner)

        puts JSON.pretty_generate({
          paused_client: paused_client,
          before_owner: before_owner,
          after_owner: after_owner,
          debug_routes: after_debug,
        })
      ' "${work_dir}/machines-before-route-health-all-unhealthy.json" "${work_dir}/debug-routes-before-route-health-all-unhealthy.json" "${work_dir}/machines-after-route-health-first-unhealthy.json" "${work_dir}/debug-routes-after-route-health-first-unhealthy.json" "${expected_route_health_all_unhealthy_route}" "${route_health_all_primary_name}" "${expected_machine_count}"
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
    curl -fsS "http://127.0.0.1:${http_port}/harness/machines" >"${work_dir}/machines-after-route-health-all-unhealthy.json" &&
      curl -fsS -H 'accept: application/json' \
        "http://127.0.0.1:${http_port}/harness/routes" \
        >"${work_dir}/debug-routes-after-route-health-all-unhealthy.json" &&
      ruby -rjson -e '
        route = ARGV.fetch(4)
        expected_count = Integer(ARGV.fetch(5))

        def stable_id_from_key(hex)
          h = 0xcbf29ce484222325
          hex.each_byte do |byte|
            h ^= byte
            h = (h * 0x100000001b3) & 0xffffffffffffffff
          end
          h & 0x7fffffffffffffff
        end

        before_machines = JSON.parse(File.read(ARGV.fetch(0)))
        first_debug = JSON.parse(File.read(ARGV.fetch(1)))
        after_machines = JSON.parse(File.read(ARGV.fetch(2)))
        after_debug = JSON.parse(File.read(ARGV.fetch(3)))
        abort("expected #{expected_count} machines before all-unhealthy route-health, got #{before_machines.length}") unless before_machines.length == expected_count
        abort("expected #{expected_count} machines after all-unhealthy route-health, got #{after_machines.length}") unless after_machines.length == expected_count

        first_owner = first_debug.fetch("primary_routes").fetch(route)
        after_owner = after_debug.fetch("primary_routes").fetch(route) {
          abort("missing primary route #{route.inspect} after all route-health candidates are unhealthy")
        }

        candidate_ids = before_machines
          .select { |machine| Array(machine["available_routes"]).include?(route) && Array(machine["approved_routes"]).include?(route) }
          .map { |machine| stable_id_from_key(machine.fetch("node_key").sub(/\Anodekey:/, "")) }
          .sort
        abort("all-unhealthy fallback owner #{after_owner.inspect} not among candidates #{candidate_ids.inspect}") unless candidate_ids.include?(after_owner)
        abort("all-unhealthy fallback did not retain last known primary for #{route}: got #{after_owner.inspect}, expected #{first_owner.inspect}") unless after_owner == first_owner

        puts JSON.pretty_generate({
          route: route,
          first_unhealthy_owner: first_owner,
          all_unhealthy_owner: after_owner,
          retained_last_known_primary: after_owner == first_owner,
          candidate_ids: candidate_ids,
          debug_routes: after_debug,
        })
      ' "${work_dir}/machines-before-route-health-all-unhealthy.json" "${work_dir}/debug-routes-after-route-health-first-unhealthy.json" "${work_dir}/machines-after-route-health-all-unhealthy.json" "${work_dir}/debug-routes-after-route-health-all-unhealthy.json" "${expected_route_health_all_unhealthy_route}" "${expected_machine_count}"
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

echo "${login_mode} real-client smoke passed"
