#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

target="${REAL_CLIENT_ONLINE_LASTSEEN_TARGET:-}"
case "${target}" in
  rust | headscale-go) ;;
  *)
    echo "REAL_CLIENT_ONLINE_LASTSEEN_TARGET must be rust or headscale-go" >&2
    exit 2
    ;;
esac

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
# shellcheck source=tools/real-client/headscale-go-baseline.sh
source tools/real-client/headscale-go-baseline.sh
headscale_go_version="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_BASELINE_VERSION}}"
timeout_secs="${REAL_CLIENT_TIMEOUT_SECS:-180}"
server_start_retries="${REAL_CLIENT_SERVER_START_RETRIES:-3}"
client_count="${REAL_CLIENT_CLIENT_COUNT:-1}"
database_backend="${REAL_CLIENT_DATABASE_BACKEND:-sqlite}"
login_mode="${REAL_CLIENT_LOGIN_MODE:-authkey}"
preauth_reusable="${REAL_CLIENT_PREAUTH_REUSABLE:-true}"
preauth_expired="${REAL_CLIENT_PREAUTH_EXPIRED:-false}"
expected_authkey_failure_indexes="${REAL_CLIENT_EXPECT_AUTHKEY_FAILURE_INDEXES:-}"
expected_machine_count="${REAL_CLIENT_EXPECT_MACHINE_COUNT:-}"
advertise_routes="${REAL_CLIENT_ADVERTISE_ROUTES:-}"
advertise_exit_node="${REAL_CLIENT_ADVERTISE_EXIT_NODE:-false}"
approve_routes="${REAL_CLIENT_APPROVE_ROUTES:-}"
expected_available_routes="${REAL_CLIENT_EXPECT_AVAILABLE_ROUTES:-${advertise_routes}}"
expected_approved_routes="${REAL_CLIENT_EXPECT_APPROVED_ROUTES:-${approve_routes}}"
preauth_tags="${REAL_CLIENT_PREAUTH_TAGS:-}"
preauth_tags_by_client="${REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT:-}"
set_tags_after_login="${REAL_CLIENT_SET_TAGS_AFTER_LOGIN:-}"
expected_set_tags_failure="${REAL_CLIENT_EXPECT_SET_TAGS_FAILURE:-false}"
expected_register_failure="${REAL_CLIENT_EXPECT_REGISTER_FAILURE:-false}"
reauth_after_login="${REAL_CLIENT_REAUTH_AFTER_LOGIN:-false}"
reauth_tags="${REAL_CLIENT_REAUTH_TAGS:-}"
authkey_relogin_same_user="${REAL_CLIENT_AUTHKEY_RELOGIN_SAME_USER:-false}"
authkey_relogin_expired="${REAL_CLIENT_AUTHKEY_RELOGIN_EXPIRED:-false}"
authkey_relogin_different_user="${REAL_CLIENT_AUTHKEY_RELOGIN_DIFFERENT_USER:-false}"
authkey_relogin_deleted="${REAL_CLIENT_AUTHKEY_RELOGIN_DELETED:-false}"
expected_tags_exact="${REAL_CLIENT_EXPECT_TAGS_EXACT:-}"
policy_json="${REAL_CLIENT_POLICY_JSON:-}"
policy_reload_json="${REAL_CLIENT_RELOAD_POLICY_JSON:-}"
prefix_v4="${REAL_CLIENT_PREFIX_V4-100.64.0.0/10}"
prefix_v6="${REAL_CLIENT_PREFIX_V6:-}"
expected_tailscale_ip_families="${REAL_CLIENT_EXPECT_TAILSCALE_IP_FAMILIES:-}"
expected_peer_count="${REAL_CLIENT_EXPECT_PEER_COUNT:-}"
expected_peer_counts="${REAL_CLIENT_EXPECT_PEER_COUNTS:-}"
expected_peer_count_after_policy_reload="${REAL_CLIENT_EXPECT_PEER_COUNT_AFTER_POLICY_RELOAD:-}"
expected_peer_counts_after_policy_reload="${REAL_CLIENT_EXPECT_PEER_COUNTS_AFTER_POLICY_RELOAD:-}"
rename_node_after_login="${REAL_CLIENT_RENAME_NODE_AFTER_LOGIN:-}"
client_users_csv="${REAL_CLIENT_CLIENT_USERS:-}"
client_user_emails_csv="${REAL_CLIENT_CLIENT_USER_EMAILS:-}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/online-lastseen-${target}}"
up_timeout="${REAL_CLIENT_TAILSCALE_UP_TIMEOUT:-60s}"
run_id="hs-online-lastseen-${target}-${database_backend}-${login_mode}-$(date +%s)-$$"
case "${target}" in
  rust) client_target="rs" ;;
  headscale-go) client_target="go" ;;
esac
client_name_override="${REAL_CLIENT_CLIENT_NAME:-}"
base_domain="${REAL_CLIENT_BASE_DOMAIN-tail.test}"
magic_dns="${REAL_CLIENT_MAGIC_DNS:-false}"
accept_dns="${REAL_CLIENT_ACCEPT_DNS:-false}"
expected_magic_dns_suffix="${REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX:-}"
expected_no_magic_dns="${REAL_CLIENT_EXPECT_NO_MAGIC_DNS:-false}"
dns_extra_records_json="${REAL_CLIENT_DNS_EXTRA_RECORDS_JSON:-}"
dns_nameservers_json="${REAL_CLIENT_DNS_NAMESERVERS_JSON:-}"
dns_split_nameservers_json="${REAL_CLIENT_DNS_SPLIT_NAMESERVERS_JSON:-}"
dns_override_local="${REAL_CLIENT_DNS_OVERRIDE_LOCAL:-false}"
expected_dns_extra_records="${REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS:-${REAL_CLIENT_EXPECT_DNS_RESOLUTIONS:-}}"
expected_dns_extra_records_exact="${REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS_EXACT:-false}"
expected_dns_routes="${REAL_CLIENT_EXPECT_DNS_ROUTES:-}"
expected_dns_resolvers="${REAL_CLIENT_EXPECT_DNS_RESOLVERS:-}"
expected_dns_fallback_resolvers="${REAL_CLIENT_EXPECT_DNS_FALLBACK_RESOLVERS:-}"
expected_dns_debug_resolves="${REAL_CLIENT_EXPECT_DNS_DEBUG_RESOLVES:-}"
expected_peer_magic_dns_resolve="${REAL_CLIENT_EXPECT_PEER_MAGIC_DNS_RESOLVE:-false}"
expected_debug_ping="${REAL_CLIENT_EXPECT_DEBUG_PING:-false}"
taildrop_enabled="${REAL_CLIENT_TAILDROP_ENABLED:-}"
expected_file_sharing_cap="${REAL_CLIENT_EXPECT_FILE_SHARING_CAP:-}"
expected_self_capmap_keys="${REAL_CLIENT_EXPECT_SELF_CAPMAP_KEYS:-}"
force_derp="${REAL_CLIENT_FORCE_DERP:-false}"
rust_embedded_derp="${REAL_CLIENT_RUST_EMBEDDED_DERP:-${HSRS_HARNESS_EMBEDDED_DERP:-false}}"
rust_derp_region_id="${REAL_CLIENT_RUST_DERP_REGION_ID:-${REAL_CLIENT_DERP_REGION_ID:-${HSRS_HARNESS_EMBEDDED_DERP_REGION_ID:-900}}}"
rust_derp_region_code="${REAL_CLIENT_RUST_DERP_REGION_CODE:-${REAL_CLIENT_DERP_REGION_CODE:-${HSRS_HARNESS_EMBEDDED_DERP_REGION_CODE:-headscale}}}"
rust_derp_region_name="${REAL_CLIENT_RUST_DERP_REGION_NAME:-${REAL_CLIENT_DERP_REGION_NAME:-${HSRS_HARNESS_EMBEDDED_DERP_REGION_NAME:-Headscale Embedded DERP}}}"
rust_derp_host="${REAL_CLIENT_RUST_DERP_HOST:-${REAL_CLIENT_DERP_HOST:-${HSRS_HARNESS_EMBEDDED_DERP_HOSTNAME:-host.docker.internal}}}"
rust_derp_port="${REAL_CLIENT_RUST_DERP_PORT:-${REAL_CLIENT_DERP_PORT:-${HSRS_HARNESS_EMBEDDED_DERP_DERP_PORT:-}}}"
rust_derp_stun_addr="${REAL_CLIENT_RUST_DERP_STUN_ADDR:-${HSRS_HARNESS_EMBEDDED_DERP_STUN_ADDR:-}}"
rust_derp_omit_default_regions="${REAL_CLIENT_RUST_DERP_OMIT_DEFAULT_REGIONS:-${REAL_CLIENT_DERP_OMIT_DEFAULT_REGIONS:-${HSRS_HARNESS_EMBEDDED_DERP_OMIT_DEFAULT_REGIONS:-true}}}"
rust_derp_insecure_for_tests="${REAL_CLIENT_RUST_DERP_INSECURE_FOR_TESTS:-${REAL_CLIENT_DERP_INSECURE_FOR_TESTS:-${HSRS_HARNESS_EMBEDDED_DERP_INSECURE_FOR_TESTS:-true}}}"
rust_derp_verify_clients="${REAL_CLIENT_RUST_DERP_VERIFY_CLIENTS:-${HSRS_HARNESS_EMBEDDED_DERP_VERIFY_CLIENTS:-true}}"
rust_derp_relay_mode="${REAL_CLIENT_RUST_DERP_RELAY_MODE:-${HSRS_HARNESS_EMBEDDED_DERP_RELAY_MODE:-sidecar}}"
rust_derper_binary="${REAL_CLIENT_RUST_DERPER_BINARY:-${REAL_CLIENT_DERPER_BIN:-${HSRS_HARNESS_EMBEDDED_DERP_DERPER_BINARY:-}}}"
rust_derper_listen_addr="${REAL_CLIENT_RUST_DERPER_LISTEN_ADDR:-${HSRS_HARNESS_EMBEDDED_DERP_DERPER_LISTEN_ADDR:-}}"
rust_derper_cert_mode="${REAL_CLIENT_RUST_DERPER_CERT_MODE:-${HSRS_HARNESS_EMBEDDED_DERP_DERPER_CERT_MODE:-manual}}"
rust_derper_cert_dir="${REAL_CLIENT_RUST_DERPER_CERT_DIR:-${HSRS_HARNESS_EMBEDDED_DERP_DERPER_CERT_DIR:-}}"
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
assert_derp_status_health_clear="${REAL_CLIENT_ASSERT_DERP_STATUS_HEALTH_CLEAR:-false}"
assert_derp_reload_stability="${REAL_CLIENT_ASSERT_DERP_RELOAD_STABILITY:-false}"
derp_restart_after_assertions="${REAL_CLIENT_DERP_RESTART_AFTER_ASSERTIONS:-false}"
derp_stun_probe_host="${REAL_CLIENT_DERP_STUN_PROBE_HOST:-127.0.0.1}"
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
if [[ -n "${expected_ssh_matrix}" ]]; then
  enable_tailscale_ssh="${REAL_CLIENT_ENABLE_TAILSCALE_SSH:-true}"
  install_openssh="${REAL_CLIENT_INSTALL_OPENSSH:-true}"
  ssh_user="${ssh_user:-ssh-it-user}"
fi

case "${database_backend}" in
  sqlite | postgres) ;;
  *)
    echo "REAL_CLIENT_DATABASE_BACKEND must be sqlite or postgres" >&2
    exit 2
    ;;
esac

case "${login_mode}" in
  authkey | web) ;;
  *)
    echo "REAL_CLIENT_LOGIN_MODE must be authkey or web, got ${login_mode}" >&2
    exit 2
    ;;
esac
case "${preauth_reusable}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    preauth_reusable_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    preauth_reusable_flag=0
    ;;
  *)
    echo "REAL_CLIENT_PREAUTH_REUSABLE must be true or false, got ${preauth_reusable}" >&2
    exit 2
    ;;
esac
case "${preauth_expired}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    preauth_expired_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    preauth_expired_flag=0
    ;;
  *)
    echo "REAL_CLIENT_PREAUTH_EXPIRED must be true or false, got ${preauth_expired}" >&2
    exit 2
    ;;
esac

if ! [[ "${client_count}" =~ ^[0-9]+$ ]] || ((client_count < 1)); then
  echo "REAL_CLIENT_CLIENT_COUNT must be a positive integer, got ${client_count}" >&2
  exit 2
fi
if [[ -n "${expected_machine_count}" ]] && ! [[ "${expected_machine_count}" =~ ^[0-9]+$ ]]; then
  echo "REAL_CLIENT_EXPECT_MACHINE_COUNT must be a non-negative integer, got ${expected_machine_count}" >&2
  exit 2
fi
if ! [[ "${server_start_retries}" =~ ^[0-9]+$ ]] || ((server_start_retries < 1)); then
  echo "REAL_CLIENT_SERVER_START_RETRIES must be a positive integer, got ${server_start_retries}" >&2
  exit 2
fi
if [[ -n "${expected_authkey_failure_indexes}" && "${login_mode}" != "authkey" ]]; then
  echo "REAL_CLIENT_EXPECT_AUTHKEY_FAILURE_INDEXES is only supported with REAL_CLIENT_LOGIN_MODE=authkey" >&2
  exit 2
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
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    authkey_relogin_expired_flag=0
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
case "${authkey_relogin_deleted}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    authkey_relogin_deleted_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    authkey_relogin_deleted_flag=0
    ;;
  *)
    echo "REAL_CLIENT_AUTHKEY_RELOGIN_DELETED must be true or false, got ${authkey_relogin_deleted}" >&2
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
if ((authkey_relogin_deleted_flag && ! authkey_relogin_requested_flag)); then
  echo "REAL_CLIENT_AUTHKEY_RELOGIN_DELETED requires auth-key relogin" >&2
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
if ((authkey_relogin_different_user_flag && authkey_relogin_deleted_flag)); then
  echo "REAL_CLIENT_AUTHKEY_RELOGIN_DIFFERENT_USER cannot be combined with REAL_CLIENT_AUTHKEY_RELOGIN_DELETED" >&2
  exit 2
fi
if ((authkey_relogin_expired_flag && authkey_relogin_deleted_flag)); then
  echo "REAL_CLIENT_AUTHKEY_RELOGIN_EXPIRED cannot be combined with REAL_CLIENT_AUTHKEY_RELOGIN_DELETED" >&2
  exit 2
fi
if ((authkey_relogin_requested_flag)) && [[ -n "${expected_authkey_failure_indexes}" ]]; then
  echo "auth-key relogin cannot be combined with REAL_CLIENT_EXPECT_AUTHKEY_FAILURE_INDEXES" >&2
  exit 2
fi

case "${advertise_exit_node}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    advertise_exit_node_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    advertise_exit_node_flag=0
    ;;
  *)
    echo "REAL_CLIENT_ADVERTISE_EXIT_NODE must be true or false, got ${advertise_exit_node}" >&2
    exit 2
    ;;
esac

case "${magic_dns}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    magic_dns_yaml=true
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    magic_dns_yaml=false
    ;;
  *)
    echo "REAL_CLIENT_MAGIC_DNS must be true or false, got ${magic_dns}" >&2
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

case "${dns_override_local}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    dns_override_local_yaml=true
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    dns_override_local_yaml=false
    ;;
  *)
    echo "REAL_CLIENT_DNS_OVERRIDE_LOCAL must be true or false, got ${dns_override_local}" >&2
    exit 2
    ;;
esac

case "${expected_dns_extra_records_exact}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    expect_dns_extra_records_exact=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    expect_dns_extra_records_exact=0
    ;;
  *)
    echo "REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS_EXACT must be true or false, got ${expected_dns_extra_records_exact}" >&2
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
if [[ -n "${rename_node_after_login}" && "${client_count}" -lt 2 ]]; then
  echo "REAL_CLIENT_RENAME_NODE_AFTER_LOGIN requires at least two clients so a peer map can observe the rename" >&2
  exit 2
fi

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
case "${rust_embedded_derp}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    use_rust_embedded_derp=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    use_rust_embedded_derp=0
    ;;
  *)
    echo "REAL_CLIENT_RUST_EMBEDDED_DERP must be true or false, got ${rust_embedded_derp}" >&2
    exit 2
    ;;
esac
case "${rust_derp_omit_default_regions}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    rust_derp_omit_default_regions_bool=true
    ;;
  0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    rust_derp_omit_default_regions_bool=false
    ;;
  *)
    echo "REAL_CLIENT_RUST_DERP_OMIT_DEFAULT_REGIONS must be true or false, got ${rust_derp_omit_default_regions}" >&2
    exit 2
    ;;
esac
case "${rust_derp_insecure_for_tests}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    rust_derp_insecure_for_tests_bool=true
    ;;
  0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    rust_derp_insecure_for_tests_bool=false
    ;;
  *)
    echo "REAL_CLIENT_RUST_DERP_INSECURE_FOR_TESTS must be true or false, got ${rust_derp_insecure_for_tests}" >&2
    exit 2
    ;;
esac
case "${rust_derp_verify_clients}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    rust_derp_verify_clients_bool=true
    ;;
  0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    rust_derp_verify_clients_bool=false
    ;;
  *)
    echo "REAL_CLIENT_RUST_DERP_VERIFY_CLIENTS must be true or false, got ${rust_derp_verify_clients}" >&2
    exit 2
    ;;
esac
case "${rust_derp_relay_mode}" in
  sidecar | native) ;;
  *)
    echo "REAL_CLIENT_RUST_DERP_RELAY_MODE must be sidecar or native, got ${rust_derp_relay_mode}" >&2
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
case "${assert_derp_status_health_clear}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    assert_derp_status_health_clear_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    assert_derp_status_health_clear_flag=0
    ;;
  *)
    echo "REAL_CLIENT_ASSERT_DERP_STATUS_HEALTH_CLEAR must be true or false, got ${assert_derp_status_health_clear}" >&2
    exit 2
    ;;
esac
case "${assert_derp_reload_stability}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    assert_derp_reload_stability_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    assert_derp_reload_stability_flag=0
    ;;
  *)
    echo "REAL_CLIENT_ASSERT_DERP_RELOAD_STABILITY must be true or false, got ${assert_derp_reload_stability}" >&2
    exit 2
    ;;
esac
case "${derp_restart_after_assertions}" in
  1 | true | TRUE | True | yes | YES | Yes | on | ON | On)
    derp_restart_after_assertions_flag=1
    ;;
  "" | 0 | false | FALSE | False | no | NO | No | off | OFF | Off)
    derp_restart_after_assertions_flag=0
    ;;
  *)
    echo "REAL_CLIENT_DERP_RESTART_AFTER_ASSERTIONS must be true or false, got ${derp_restart_after_assertions}" >&2
    exit 2
    ;;
esac
if ((expect_derp_ping_flag)) && ((client_count < 2)); then
  echo "REAL_CLIENT_EXPECT_DERP_PING requires at least two clients" >&2
  exit 2
fi
if ((use_rust_embedded_derp)) && [[ -z "${rust_derp_stun_addr}" ]]; then
  echo "REAL_CLIENT_RUST_EMBEDDED_DERP requires REAL_CLIENT_RUST_DERP_STUN_ADDR or HSRS_HARNESS_EMBEDDED_DERP_STUN_ADDR" >&2
  exit 2
fi
if ((use_rust_embedded_derp)) && [[ "${rust_derp_relay_mode}" == "sidecar" && -z "${rust_derp_port}" ]]; then
  echo "REAL_CLIENT_RUST_EMBEDDED_DERP requires REAL_CLIENT_RUST_DERP_PORT or REAL_CLIENT_DERP_PORT" >&2
  exit 2
fi
if ((use_rust_embedded_derp)) && [[ "${rust_derp_relay_mode}" == "sidecar" && -z "${rust_derper_binary}" ]]; then
  echo "REAL_CLIENT_RUST_EMBEDDED_DERP requires REAL_CLIENT_RUST_DERPER_BINARY or REAL_CLIENT_DERPER_BIN" >&2
  exit 2
fi
if ((use_rust_embedded_derp)) && [[ "${rust_derp_relay_mode}" == "sidecar" && -z "${rust_derper_listen_addr}" ]]; then
  echo "REAL_CLIENT_RUST_EMBEDDED_DERP requires REAL_CLIENT_RUST_DERPER_LISTEN_ADDR" >&2
  exit 2
fi
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
if [[ -n "${ssh_user}" && ! "${ssh_user}" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
  echo "REAL_CLIENT_SSH_USER must be a simple Linux username, got ${ssh_user}" >&2
  exit 2
fi
if [[ -n "${expected_ssh_matrix}" && -z "${ssh_user}" ]]; then
  echo "REAL_CLIENT_EXPECT_SSH_MATRIX requires REAL_CLIENT_SSH_USER" >&2
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
  echo "REAL_CLIENT_EXPECT_REGISTER_FAILURE requires REAL_CLIENT_LOGIN_MODE=web" >&2
  exit 2
fi
registration_failed_as_expected=0

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
if [[ -n "${expected_peer_count_after_policy_reload}" ]] &&
  ! [[ "${expected_peer_count_after_policy_reload}" =~ ^[0-9]+$ ]]; then
  echo "REAL_CLIENT_EXPECT_PEER_COUNT_AFTER_POLICY_RELOAD must be a non-negative integer, got ${expected_peer_count_after_policy_reload}" >&2
  exit 2
fi
if [[ -n "${expected_peer_counts_after_policy_reload}" ]]; then
  IFS=',' read -r -a expected_peer_counts_after_policy_reload_values <<<"${expected_peer_counts_after_policy_reload}"
  if ((${#expected_peer_counts_after_policy_reload_values[@]} != client_count)); then
    echo "REAL_CLIENT_EXPECT_PEER_COUNTS_AFTER_POLICY_RELOAD must contain ${client_count} comma-separated counts, got ${expected_peer_counts_after_policy_reload}" >&2
    exit 2
  fi
  for count in "${expected_peer_counts_after_policy_reload_values[@]}"; do
    if ! [[ "${count}" =~ ^[0-9]+$ ]]; then
      echo "REAL_CLIENT_EXPECT_PEER_COUNTS_AFTER_POLICY_RELOAD must contain non-negative integers, got ${expected_peer_counts_after_policy_reload}" >&2
      exit 2
    fi
  done
fi
if [[ -n "${policy_reload_json}" &&
  -z "${expected_peer_count_after_policy_reload}${expected_peer_counts_after_policy_reload}" ]]; then
  echo "REAL_CLIENT_RELOAD_POLICY_JSON requires REAL_CLIENT_EXPECT_PEER_COUNT_AFTER_POLICY_RELOAD or REAL_CLIENT_EXPECT_PEER_COUNTS_AFTER_POLICY_RELOAD" >&2
  exit 2
fi
if [[ -z "${policy_reload_json}" &&
  -n "${expected_peer_count_after_policy_reload}${expected_peer_counts_after_policy_reload}" ]]; then
  echo "post-reload peer expectations require REAL_CLIENT_RELOAD_POLICY_JSON" >&2
  exit 2
fi
if ((assert_derp_reload_stability_flag)); then
  if [[ -z "${policy_reload_json}" ]]; then
    echo "REAL_CLIENT_ASSERT_DERP_RELOAD_STABILITY requires REAL_CLIENT_RELOAD_POLICY_JSON" >&2
    exit 2
  fi
  if [[ -z "${expected_derp_region_id}" && "${use_rust_embedded_derp}${use_headscale_go_embedded_derp}" == "00" ]]; then
    echo "REAL_CLIENT_ASSERT_DERP_RELOAD_STABILITY requires DERP map expectations" >&2
    exit 2
  fi
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

client_names=()
for ((idx = 1; idx <= client_count; idx++)); do
  if ((client_count == 1)); then
    client_names+=("${client_name_override:-hs-ol-${client_target}-${database_backend}-${login_mode}-$$}")
  else
    client_prefix="${client_name_override:-hs-ol-${client_target}-${database_backend}-${login_mode}-$$}"
    client_names+=("${client_prefix}-${idx}")
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

client_user_emails=()
for ((idx = 0; idx < client_count; idx++)); do
  client_user_emails+=("")
done
if [[ -n "${client_user_emails_csv}" ]]; then
  IFS=',' read -r -a client_user_emails <<<"${client_user_emails_csv}"
  if ((${#client_user_emails[@]} != client_count)); then
    echo "REAL_CLIENT_CLIENT_USER_EMAILS must contain ${client_count} comma-separated values, got ${client_user_emails_csv}" >&2
    exit 2
  fi
  for idx in "${!client_user_emails[@]}"; do
    if [[ "${client_user_emails[$idx]}" == "-" ]]; then
      client_user_emails[$idx]=""
    fi
  done
fi

preauth_tags_values=()
for ((idx = 0; idx < client_count; idx++)); do
  preauth_tags_values+=("${preauth_tags}")
done
if [[ -n "${preauth_tags_by_client}" ]]; then
  IFS=';' read -r -a preauth_tags_values <<<"${preauth_tags_by_client}"
  if ((${#preauth_tags_values[@]} != client_count)); then
    echo "REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT must contain ${client_count} semicolon-separated values, got ${preauth_tags_by_client}" >&2
    exit 2
  fi
  for idx in "${!preauth_tags_values[@]}"; do
    if [[ "${preauth_tags_values[$idx]}" == "-" ]]; then
      preauth_tags_values[$idx]=""
    fi
  done
fi
client_name="${client_names[0]}"

if [[ -z "${policy_json}" ]]; then
  policy_json="$(
    ruby -rjson -e '
      tags = []
      tags.concat(ARGV.fetch(0).split(","))
      tags.concat(ARGV.fetch(1).split(","))
      tags.concat(ARGV.fetch(2).split(",")) unless ARGV.fetch(3) == "true"
      ARGV.fetch(4).split(";").each { |value| tags.concat(value.split(",")) unless value == "-" }
      tags = tags.reject(&:empty?).sort.uniq
      exit if tags.empty?
      owners = tags.to_h { |tag| [tag, ["alice@"]] }
      puts JSON.generate({
        tagOwners: owners,
        acls: [{action: "accept", src: ["*"], dst: ["*:*"]}],
      })
    ' "${preauth_tags}" "${reauth_tags}" "${set_tags_after_login}" "$([[ "${expect_set_tags_failure}" -eq 1 ]] && printf true || printf false)" "${preauth_tags_by_client:-}"
  )"
fi

case "${work_root}" in
  /*) work_dir="${work_root}/${run_id}" ;;
  *) work_dir="${repo_root}/${work_root}/${run_id}" ;;
esac
mkdir -p "${work_dir}"

http_port=""
https_port=""
metrics_port=""
grpc_port=""
server_pid=""
config_path="${work_dir}/config.yaml"
policy_path="${work_dir}/policy.hujson"
policy_reload_path="${work_dir}/policy-reload.hujson"
db_path="${work_dir}/db.sqlite"
socket_path="/tmp/${run_id}.sock"
control_url=""
local_control_url=""
tls_cert_path=""
tls_key_path=""
health_curl_opts="-fsS"
headscale_bin=""
authkey=""
authkeys=()
current_client_index=0
created_user_names=()
created_user_ids=()
created_user_emails=()
postgres_admin_url=""
postgres_database_name=""
postgres_host=""
postgres_port=""
postgres_user=""
postgres_pass=""
postgres_sslmode=""
postgres_database_created=0
rust_derp_effective_port="${rust_derp_port}"

cleanup() {
  local cleanup_client_name
  for cleanup_client_name in "${client_names[@]}"; do
    docker rm -f "${cleanup_client_name}" >/dev/null 2>&1 || true
  done
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
  fi
  drop_postgres_database || true
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

assign_server_ports() {
  http_port="$(free_port)"
  metrics_port="$(free_port)"
  grpc_port="$(free_port)"
  case "${target}" in
    rust)
      https_port="$(free_port)"
      control_url="https://host.docker.internal:${https_port}"
      local_control_url="http://127.0.0.1:${http_port}"
      ;;
    headscale-go)
      https_port=""
      control_url="https://host.docker.internal:${http_port}"
      local_control_url="https://127.0.0.1:${http_port}"
      health_curl_opts="-fsSk"
      ;;
  esac
  configure_derp_expectations
}

yaml_string() {
  ruby -rjson -e 'puts ARGV.fetch(0).to_json' "$1"
}

derp_port_from_addr() {
  local addr="$1"
  if [[ "${addr}" =~ :([0-9]+)$ ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

parse_postgres_test_url() {
  eval "$(
    ruby -ruri -rshellwords -e '
      url = URI.parse(ARGV.fetch(0))
      database_name = ARGV.fetch(1)
      abort("HEADSCALE_DB_POSTGRES_TEST_URL must include a TCP host") if url.host.to_s.empty?
      query = URI.decode_www_form(url.query.to_s).to_h
      sslmode = query.fetch("sslmode", "false")
      admin_db = url.path.to_s.sub(%r{\A/}, "")
      admin_db = "postgres" if admin_db.empty?
      admin = url.dup
      admin.path = "/#{admin_db}"
      {
        postgres_admin_url: admin.to_s,
        postgres_database_name: database_name,
        postgres_host: url.host.to_s,
        postgres_port: (url.port || 5432).to_s,
        postgres_user: URI.decode_www_form_component(url.user.to_s),
        postgres_pass: URI.decode_www_form_component(url.password.to_s),
        postgres_sslmode: sslmode,
      }.each do |key, value|
        puts "#{key}=#{Shellwords.escape(value)}"
      end
    ' "${HEADSCALE_DB_POSTGRES_TEST_URL:-}" "${postgres_database_name}"
  )"
}

prepare_postgres_database() {
  [[ "${database_backend}" == "postgres" ]] || return 0
  if [[ -z "${HEADSCALE_DB_POSTGRES_TEST_URL:-}" ]]; then
    echo "skipping Postgres real-client smoke: HEADSCALE_DB_POSTGRES_TEST_URL is not set" >&2
    exit 0
  fi
  need psql
  postgres_database_name="headscale_rs_pg_real_${target//[^a-zA-Z0-9]/_}_$(date +%s)_$$"
  parse_postgres_test_url
  if ! [[ "${postgres_database_name}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
    echo "internal temporary Postgres database name is invalid: ${postgres_database_name}" >&2
    exit 2
  fi
  echo "::group::create temporary Postgres database"
  if ! psql "${postgres_admin_url}" -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${postgres_database_name}" >"${work_dir}/postgres-create.stdout" 2>"${work_dir}/postgres-create.stderr"; then
    echo "skipping Postgres real-client smoke: cannot create temporary database ${postgres_database_name}" >&2
    cat "${work_dir}/postgres-create.stderr" >&2 || true
    echo "::endgroup::"
    exit 0
  fi
  postgres_database_created=1
  echo "created ${postgres_database_name}"
  echo "::endgroup::"
}

drop_postgres_database() {
  [[ "${database_backend}" == "postgres" ]] || return 0
  ((postgres_database_created)) || return 0
  echo "::group::drop temporary Postgres database"
  psql "${postgres_admin_url}" -v ON_ERROR_STOP=1 \
    -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '${postgres_database_name}' AND pid <> pg_backend_pid()" \
    >"${work_dir}/postgres-terminate.stdout" \
    2>"${work_dir}/postgres-terminate.stderr" || true
  if ! psql "${postgres_admin_url}" -v ON_ERROR_STOP=1 \
    -c "DROP DATABASE IF EXISTS ${postgres_database_name} WITH (FORCE)" \
    >"${work_dir}/postgres-drop.stdout" \
    2>"${work_dir}/postgres-drop.stderr"; then
    psql "${postgres_admin_url}" -v ON_ERROR_STOP=1 \
      -c "DROP DATABASE IF EXISTS ${postgres_database_name}" \
      >>"${work_dir}/postgres-drop.stdout" \
      2>>"${work_dir}/postgres-drop.stderr"
  fi
  postgres_database_created=0
  echo "::endgroup::"
}

stop_server() {
  if [[ -n "${server_pid}" ]]; then
    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
    server_pid=""
  fi
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

dump_server_startup_logs() {
  local reason="$1"
  local path
  echo "::group::${target} server startup debug (${reason})"
  for path in \
    "${work_dir}/${target}.stderr" \
    "${work_dir}/${target}.stdout" \
    "${work_dir}/${target}-health.stderr" \
    "${work_dir}/${target}-metrics-debug.stderr" \
    "${work_dir}/${target}-grpc-health.stderr" \
    "${work_dir}/${target}-grpc-health.stdout"; do
    if [[ -s "${path}" ]]; then
      echo "--- ${path} ---" >&2
      sed -n '1,220p' "${path}" >&2 || true
    fi
  done
  echo "::endgroup::"
}

wait_for_server() {
  local label="$1"
  local cmd="$2"
  local deadline=$((SECONDS + timeout_secs))
  until eval "${cmd}"; do
    if [[ -n "${server_pid}" ]] && ! kill -0 "${server_pid}" >/dev/null 2>&1; then
      echo "${target} server exited while waiting for ${label}" >&2
      dump_server_startup_logs "server exited before ${label}"
      return 1
    fi
    if ((SECONDS >= deadline)); then
      echo "timed out waiting for ${label}" >&2
      dump_server_startup_logs "timed out waiting for ${label}"
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

write_registration_id() {
  local output_path="$1"
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

client_logged_in() {
  local check_client_name="$1"
  local status_path="$2"
  docker exec "${check_client_name}" tailscale status --json >"${status_path}" 2>/dev/null &&
    ruby -rjson -e '
      status = JSON.parse(File.read(ARGV.fetch(0)))
      ips = Array(status["TailscaleIPs"])
      ok = status["HaveNodeKey"] &&
        status["AuthURL"].to_s.empty? &&
        (status["Self"] || {})["InNetworkMap"] &&
        !ips.empty?
      exit(ok ? 0 : 1)
    ' "${status_path}"
}

dump_debug() {
  headscale_cmd -o json nodes list 2>&1 || true
  docker exec "${client_name}" tailscale status 2>&1 || true
  docker exec "${client_name}" sh -c 'tail -180 /tmp/tailscaled.log 2>/dev/null || true' >&2 || true
}

dump_client_debug() {
  local debug_client_name="$1"
  docker exec "${debug_client_name}" tailscale status 2>&1 || true
  docker exec "${debug_client_name}" sh -c 'tail -180 /tmp/tailscaled.log 2>/dev/null || true' >&2 || true
}

tailscale_peer_count_matches() {
  local peer_client_name="$1"
  local count="$2"
  local status_json
  status_json="$(docker exec "${peer_client_name}" tailscale status --json 2>/dev/null || true)"
  ruby -rjson -e '
    status = JSON.parse(STDIN.read)
    peers = status["Peer"] || {}
    exit(peers.length == Integer(ARGV.fetch(0)) ? 0 : 1)
  ' "${count}" <<<"${status_json}"
}

assert_peer_visibility_counts() {
  local label="$1"
  local expected_count_all="$2"
  local expected_counts_csv="$3"
  [[ -n "${expected_count_all}" || -n "${expected_counts_csv}" ]] || return 0
  echo "::group::assert client peer visibility${label:+ (${label})}"
  local peer_status_paths=()
  local peer_expected_counts=()
  local expected_count_values=()
  local idx peer_client_name expected_count status_path peer_expected_counts_joined safe_label
  safe_label="${label:-initial}"
  safe_label="${safe_label//[^a-zA-Z0-9_-]/-}"
  if [[ -n "${expected_counts_csv}" ]]; then
    IFS=',' read -r -a expected_count_values <<<"${expected_counts_csv}"
  fi
  for idx in "${!client_names[@]}"; do
    peer_client_name="${client_names[$idx]}"
    expected_count="${expected_count_all}"
    if [[ -n "${expected_counts_csv}" ]]; then
      expected_count="${expected_count_values[$idx]}"
    fi
    if ! wait_for "tailscale peer count ${expected_count} for ${peer_client_name}" \
      "tailscale_peer_count_matches '${peer_client_name}' '${expected_count}'"; then
      dump_client_debug "${peer_client_name}"
      echo "::endgroup::"
      return 1
    fi
    status_path="${work_dir}/${peer_client_name}.${safe_label}-peer-status.json"
    docker exec "${peer_client_name}" tailscale status --json >"${status_path}" || true
    peer_status_paths+=("${status_path}")
    peer_expected_counts+=("${expected_count}")
  done
  peer_expected_counts_joined="$(IFS=,; echo "${peer_expected_counts[*]}")"
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
  ' "${peer_expected_counts_joined}" "${peer_status_paths[@]}"
  echo "::endgroup::"
}

assert_peer_visibility_if_requested() {
  assert_peer_visibility_counts "" "${expected_peer_count}" "${expected_peer_counts}"
}

assert_post_reload_peer_visibility_if_requested() {
  assert_peer_visibility_counts \
    "after policy reload" \
    "${expected_peer_count_after_policy_reload}" \
    "${expected_peer_counts_after_policy_reload}"
}

assert_node_renamed_file() {
  local path="$1"
  local old_name="$2"
  local new_name="$3"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    old_name = ARGV.fetch(1)
    new_name = ARGV.fetch(2)
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")

    def display_names(node)
      [
        node["givenName"],
        node["given_name"],
        node["name"],
      ].compact.map(&:to_s)
    end

    node = nodes.find { |candidate| display_names(candidate).include?(new_name) }
    abort("missing renamed node #{new_name.inspect} in #{nodes.inspect}") unless node
    stale = display_names(node).select { |name| name == old_name }
    abort("renamed node still exposes old display name #{old_name.inspect}: #{node.inspect}") unless stale.empty?
    puts JSON.pretty_generate({renamed_node: new_name, old_name: old_name, display_names: display_names(node), node: node})
  ' "${path}" "${old_name}" "${new_name}"
}

peer_netmap_has_renamed_node() {
  local observer_name="$1"
  local old_name="$2"
  local new_name="$3"
  local output_path="$4"
  local netmap_path="${output_path}.netmap"
  docker exec "${observer_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      netmap = JSON.parse(File.read(ARGV.fetch(0)))
      old_name = ARGV.fetch(1)
      new_name = ARGV.fetch(2)
      peers = Array(netmap["Peers"] || netmap["peers"])

      def display_names(peer)
        [
          peer["HostName"],
          peer["Name"],
          peer["DNSName"],
          peer["ComputedName"],
        ].compact.map(&:to_s)
      end

      peer = peers.find do |candidate|
        display_names(candidate).any? do |name|
          name == new_name || name.split(".").first == new_name || name.include?(new_name)
        end
      end
      abort("missing renamed peer #{new_name.inspect} in peers #{peers.inspect}") unless peer

      puts JSON.pretty_generate({
        observer: netmap.dig("SelfNode", "HostName") || netmap.dig("SelfNode", "Name"),
        renamed_peer: new_name,
        old_name: old_name,
        display_names: display_names(peer),
      })
    ' "${netmap_path}" "${old_name}" "${new_name}" >"${output_path}"
}

rename_node_if_requested() {
  [[ -n "${rename_node_after_login}" ]] || return 0
  echo "::group::rename node"
  local old_name="${successful_client_names[0]}"
  local new_name="${rename_node_after_login}"
  local nodes_path="${work_dir}/nodes-before-rename.json"
  headscale_cmd -o json nodes list >"${nodes_path}"
  local node_id
  node_id="$(node_id_for_client "${nodes_path}")"
  headscale_cmd nodes rename "${new_name}" --identifier "${node_id}" \
    >"${work_dir}/rename-node-${node_id}.stdout" \
    2>"${work_dir}/rename-node-${node_id}.stderr"

  local renamed_path="${work_dir}/nodes-after-rename.json"
  wait_for "renamed node admin row" \
    "headscale_cmd -o json nodes list >'${renamed_path}' && assert_node_renamed_file '${renamed_path}' '${old_name}' '${new_name}'" || {
      dump_debug
      echo "::endgroup::"
      return 1
    }

  local observer_name output_path safe_observer
  for observer_name in "${successful_client_names[@]:1}"; do
    safe_observer="${observer_name//[^a-zA-Z0-9_.-]/-}"
    output_path="${work_dir}/renamed-peer-${safe_observer}.json"
    wait_for "renamed peer ${new_name} visible to ${observer_name}" \
      "peer_netmap_has_renamed_node '${observer_name}' '${old_name}' '${new_name}' '${output_path}'" || {
        cat "${output_path}.err" >&2 || true
        dump_client_debug "${observer_name}"
        echo "::endgroup::"
        return 1
      }
    cat "${output_path}"
  done
  echo "::endgroup::"
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

assert_derp_stun_if_requested() {
  ((assert_derp_stun_flag)) || return 0
  echo "::group::assert embedded DERP STUN"
  if [[ -z "${expected_derp_stun_port}" ]]; then
    echo "REAL_CLIENT_ASSERT_DERP_STUN requires REAL_CLIENT_EXPECT_DERP_STUN_PORT" >&2
    echo "::endgroup::"
    return 1
  fi
  wait_for "embedded DERP STUN" \
    "assert_stun_round_trip '${derp_stun_probe_host}' '${expected_derp_stun_port}' '${work_dir}/embedded-derp-stun.json'"
  cat "${work_dir}/embedded-derp-stun.json"
  echo "::endgroup::"
}

assert_derp_map() {
  local derp_client_name="$1"
  local output_path="$2"
  local netmap_path="${output_path}.netmap"
  docker exec "${derp_client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
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

assert_derp_map_if_requested() {
  [[ -n "${expected_derp_region_id}" ]] || return 0
  echo "::group::assert DERP map metadata"
  local derp_client_name
  for derp_client_name in "${successful_client_names[@]}"; do
    if ! wait_for "DERP map metadata ${derp_client_name}" \
      "assert_derp_map '${derp_client_name}' '${work_dir}/${derp_client_name}.derp-map.json'"; then
      cat "${work_dir}/${derp_client_name}.derp-map.json.err" >&2 || true
      dump_client_debug "${derp_client_name}"
      echo "::endgroup::"
      return 1
    fi
    cat "${work_dir}/${derp_client_name}.derp-map.json"
  done
  echo "::endgroup::"
}

snapshot_derp_map_before_restart_if_available() {
  [[ -n "${expected_derp_region_id}" ]] || return 0
  local derp_client_name current_path snapshot_path
  for derp_client_name in "${successful_client_names[@]}"; do
    current_path="${work_dir}/${derp_client_name}.derp-map.json"
    snapshot_path="${work_dir}/${derp_client_name}.pre-derp-restart-derp-map.json"
    if [[ -f "${current_path}" ]]; then
      cp "${current_path}" "${snapshot_path}"
    fi
  done
}

assert_derp_map_stable_after_restart_if_available() {
  [[ -n "${expected_derp_region_id}" ]] || return 0
  echo "::group::assert DERP map stable after restart"
  local derp_client_name pre_path post_path output_path
  for derp_client_name in "${successful_client_names[@]}"; do
    pre_path="${work_dir}/${derp_client_name}.pre-derp-restart-derp-map.json"
    post_path="${work_dir}/${derp_client_name}.derp-map.json"
    output_path="${work_dir}/${derp_client_name}.derp-map-restart-stability.json"
    if [[ ! -f "${pre_path}" ]]; then
      echo "missing pre-restart DERP map snapshot for ${derp_client_name}: ${pre_path}" >&2
      echo "::endgroup::"
      return 1
    fi
    if ! ruby -rjson -e '
      pre = JSON.parse(File.read(ARGV.fetch(0)))
      post = JSON.parse(File.read(ARGV.fetch(1)))
      client = ARGV.fetch(2)
      unless pre == post
        abort("DERP map changed after restart for #{client}: before=#{JSON.generate(pre)} after=#{JSON.generate(post)}")
      end
      node = post.fetch("node", {})
      puts JSON.pretty_generate({
        client: client,
        stable_derp_map_after_restart: true,
        host: node["HostName"],
        derp_port: node["DERPPort"],
        stun_port: node["STUNPort"],
        omitDefaultRegions: post["omitDefaultRegions"],
      })
    ' "${pre_path}" "${post_path}" "${derp_client_name}" >"${output_path}" 2>"${output_path}.err"; then
      cat "${output_path}.err" >&2 || true
      dump_client_debug "${derp_client_name}"
      echo "::endgroup::"
      return 1
    fi
    cat "${output_path}"
  done
  echo "::endgroup::"
}

snapshot_derp_map_before_policy_reload_if_requested() {
  ((assert_derp_reload_stability_flag)) || return 0
  echo "::group::snapshot DERP map before policy reload"
  local derp_client_name safe_derp_client_name output_path
  for derp_client_name in "${successful_client_names[@]}"; do
    safe_derp_client_name="${derp_client_name//[^a-zA-Z0-9_.-]/-}"
    output_path="${work_dir}/${safe_derp_client_name}.pre-policy-reload-derp-map.json"
    if ! wait_for "DERP map before policy reload ${derp_client_name}" \
      "assert_derp_map '${derp_client_name}' '${output_path}'"; then
      cat "${output_path}.err" >&2 || true
      dump_client_debug "${derp_client_name}"
      echo "::endgroup::"
      return 1
    fi
    cat "${output_path}"
  done
  echo "::endgroup::"
}

assert_derp_map_stable_after_policy_reload() {
  local derp_client_name="$1"
  local pre_path="$2"
  local post_path="$3"
  local output_path="$4"
  : >"${output_path}.err"
  if [[ ! -f "${pre_path}" ]]; then
    echo "missing pre-policy-reload DERP map snapshot for ${derp_client_name}: ${pre_path}" >&2
    return 1
  fi
  assert_derp_map "${derp_client_name}" "${post_path}" &&
    ruby -rjson -e '
      pre = JSON.parse(File.read(ARGV.fetch(0)))
      post = JSON.parse(File.read(ARGV.fetch(1)))
      client = ARGV.fetch(2)
      unless pre == post
        abort("DERP map changed after policy reload for #{client}: before=#{JSON.generate(pre)} after=#{JSON.generate(post)}")
      end
      node = post.fetch("node", {})
      puts JSON.pretty_generate({
        client: client,
        stable_derp_map_after_policy_reload: true,
        host: node["HostName"],
        derp_port: node["DERPPort"],
        stun_port: node["STUNPort"],
        omitDefaultRegions: post["omitDefaultRegions"],
      })
    ' "${pre_path}" "${post_path}" "${derp_client_name}" >"${output_path}" 2>>"${output_path}.err"
}

assert_derp_map_stable_after_policy_reload_if_requested() {
  ((assert_derp_reload_stability_flag)) || return 0
  echo "::group::assert DERP map stable after policy reload"
  local derp_client_name safe_derp_client_name pre_path post_path output_path
  for derp_client_name in "${successful_client_names[@]}"; do
    safe_derp_client_name="${derp_client_name//[^a-zA-Z0-9_.-]/-}"
    pre_path="${work_dir}/${safe_derp_client_name}.pre-policy-reload-derp-map.json"
    post_path="${work_dir}/${safe_derp_client_name}.post-policy-reload-derp-map.json"
    output_path="${work_dir}/${safe_derp_client_name}.policy-reload-derp-map-stability.json"
    if ! wait_for "DERP map stable after policy reload ${derp_client_name}" \
      "assert_derp_map_stable_after_policy_reload '${derp_client_name}' '${pre_path}' '${post_path}' '${output_path}'"; then
      cat "${post_path}.err" >&2 || true
      cat "${output_path}.err" >&2 || true
      dump_client_debug "${derp_client_name}"
      echo "::endgroup::"
      return 1
    fi
    cat "${output_path}"
  done
  echo "::endgroup::"
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

assert_derp_ping_if_requested() {
  ((expect_derp_ping_flag)) || return 0
  echo "::group::assert DERP relay path"
  if ((${#successful_client_names[@]} < 2)); then
    echo "REAL_CLIENT_EXPECT_DERP_PING requires at least two successful clients" >&2
    echo "::endgroup::"
    return 1
  fi
  local source_name="${successful_client_names[0]}"
  local target_name="${successful_client_names[1]}"
  if ! wait_for "tailscale ping ${source_name} to ${target_name} via DERP" \
    "tailscale_derp_ping_succeeded '${source_name}' '${target_name}' '${work_dir}/derp-ping-${source_name}-to-${target_name}.txt'"; then
    cat "${work_dir}/derp-ping-${source_name}-to-${target_name}.err" >&2 || true
    dump_client_debug "${source_name}"
    dump_client_debug "${target_name}"
    echo "::endgroup::"
    return 1
  fi
  cat "${work_dir}/derp-ping-${source_name}-to-${target_name}.txt"
  echo "::endgroup::"
}

assert_derp_status_health_clear() {
  local derp_client_name="$1"
  local output_path="$2"
  local status_path="${output_path}.status.json"
  : >"${output_path}.err"
  docker exec "${derp_client_name}" tailscale status --json >"${status_path}" 2>>"${output_path}.err" &&
    ruby -rjson -e '
      def collect_strings(value)
        case value
        when nil
          []
        when String
          [value]
        when Array
          value.flat_map { |item| collect_strings(item) }
        when Hash
          value.flat_map { |key, item| collect_strings(key) + collect_strings(item) }
        else
          [value.to_s]
        end
      end

      status = JSON.parse(File.read(ARGV.fetch(0)))
      client = ARGV.fetch(1)
      health_text = %w[Health health Warnings warnings].flat_map { |key| collect_strings(status[key]) }
        .map(&:strip)
        .reject(&:empty?)
        .uniq
      lingering_derp_health = health_text.select do |entry|
        entry.match?(/duplicate DERP connection/i) || entry.match?(/server restarting/i)
      end
      unless lingering_derp_health.empty?
        abort("expected #{client} DERP health to clear, got #{lingering_derp_health.inspect}; all health=#{health_text.inspect}")
      end
      peers = status["Peer"] || status["peer"] || {}
      peer_relays = peers.each_value.map { |peer| peer["Relay"] || peer["relay"] }.compact.sort
      puts JSON.pretty_generate({
        client: client,
        derp_status_health_clear: true,
        health: health_text,
        peer_relays: peer_relays,
        backend_state: status["BackendState"] || status["backendState"],
      })
    ' "${status_path}" "${derp_client_name}" >"${output_path}" 2>>"${output_path}.err"
}

assert_derp_status_health_clear_if_requested() {
  ((assert_derp_status_health_clear_flag)) || return 0
  echo "::group::assert stock-client DERP status health clear"
  local derp_client_name safe_derp_client_name output_path
  for derp_client_name in "${successful_client_names[@]}"; do
    safe_derp_client_name="${derp_client_name//[^a-zA-Z0-9_.-]/-}"
    output_path="${work_dir}/${safe_derp_client_name}.derp-status-health-clear.json"
    if ! wait_for "DERP status health clear ${derp_client_name}" \
      "assert_derp_status_health_clear '${derp_client_name}' '${output_path}'"; then
      cat "${output_path}.err" >&2 || true
      dump_client_debug "${derp_client_name}"
      echo "::endgroup::"
      return 1
    fi
    cat "${output_path}"
  done
  echo "::endgroup::"
}

assert_derp_restart_if_requested() {
  ((derp_restart_after_assertions_flag)) || return 0
  echo "::group::restart ${target} server and assert DERP recovery"
  snapshot_derp_map_before_restart_if_available
  stop_server
  if ! start_server; then
    echo "::endgroup::"
    return 1
  fi

  local reconnect_name safe_reconnect_name status_path
  for reconnect_name in "${successful_client_names[@]}"; do
    safe_reconnect_name="${reconnect_name//[^a-zA-Z0-9_.-]/-}"
    status_path="${work_dir}/${safe_reconnect_name}.post-derp-restart-status.json"
    if ! wait_for "${reconnect_name} reconnected after DERP restart" \
      "client_logged_in '${reconnect_name}' '${status_path}'"; then
      dump_client_debug "${reconnect_name}"
      echo "::endgroup::"
      return 1
    fi
  done

  assert_derp_stun_if_requested
  assert_derp_map_if_requested
  assert_derp_map_stable_after_restart_if_available
  assert_derp_ping_if_requested
  assert_derp_status_health_clear_if_requested
  echo "::endgroup::"
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

assert_ssh_matrix_if_requested() {
  [[ -n "${expected_ssh_matrix}" ]] || return 0
  echo "::group::assert tailscale ssh matrix"
  local ssh_checks=()
  local ssh_results=()
  local raw_check check source_idx target_idx expected_ssh
  local source_name target_name stdout_path stderr_path status_path first_line ssh_status
  IFS=',' read -r -a ssh_checks <<<"${expected_ssh_matrix}"
  for raw_check in "${ssh_checks[@]}"; do
    check="${raw_check//[[:space:]]/}"
    if [[ ! "${check}" =~ ^([0-9]+):([0-9]+):(allow|deny|timeout)$ ]]; then
      echo "REAL_CLIENT_EXPECT_SSH_MATRIX entries must be source_index:target_index:allow|deny|timeout, got ${raw_check}" >&2
      echo "::endgroup::"
      return 2
    fi
    source_idx="${BASH_REMATCH[1]}"
    target_idx="${BASH_REMATCH[2]}"
    expected_ssh="${BASH_REMATCH[3]}"
    if ((source_idx < 1 || source_idx > client_count || target_idx < 1 || target_idx > client_count)); then
      echo "SSH matrix index out of range for ${client_count} clients: ${check}" >&2
      echo "::endgroup::"
      return 2
    fi
    source_name="${client_names[$((source_idx - 1))]}"
    target_name="${client_names[$((target_idx - 1))]}"
    stdout_path="${work_dir}/ssh-${source_name}-to-${target_name}-${expected_ssh}.stdout"
    stderr_path="${work_dir}/ssh-${source_name}-to-${target_name}-${expected_ssh}.stderr"
    status_path="${work_dir}/ssh-${source_name}-to-${target_name}-${expected_ssh}.status"

    if ! wait_for_ssh_host_keys "${source_name}" "${target_name}"; then
      docker exec "${source_name}" tailscale status --json >"${work_dir}/ssh-${source_name}-status-missing-hostkeys.json" || true
      echo "timed out waiting for ${source_name} to learn ${target_name} SSH host keys; tailscale ssh cannot run strict host-key checks without peer sshHostKeys" >&2
      echo "::endgroup::"
      return 1
    fi

    case "${expected_ssh}" in
      allow)
        if ! wait_for "tailscale ssh ${source_name} to ${target_name}" \
          "tailscale_ssh_succeeded '${source_name}' '${target_name}'"; then
          cat "${work_dir}/ssh-${source_name}-to-${target_name}.stdout" >&2 || true
          cat "${work_dir}/ssh-${source_name}-to-${target_name}.stderr" >&2 || true
          dump_client_debug "${source_name}"
          dump_client_debug "${target_name}"
          echo "::endgroup::"
          return 1
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
          echo "::endgroup::"
          return 1
        fi
        if [[ -n "${ssh_deny_status}" && "${ssh_deny_status}" != "any" ]] &&
          ((ssh_status != ssh_deny_status)); then
          echo "expected denied tailscale ssh status ${ssh_deny_status}, got ${ssh_status}" >&2
          cat "${stderr_path}" >&2 || true
          echo "::endgroup::"
          return 1
        fi
        if [[ -s "${stdout_path}" ]]; then
          echo "expected denied tailscale ssh stdout to be empty, got:" >&2
          cat "${stdout_path}" >&2
          echo "::endgroup::"
          return 1
        fi
        if [[ -n "${ssh_deny_stderr_first_line}" ]]; then
          first_line="$(sed -n '1{s/\r$//;p;q;}' "${stderr_path}")"
          if [[ "${first_line}" != "${ssh_deny_stderr_first_line}" ]]; then
            echo "expected denied tailscale ssh first stderr line '${ssh_deny_stderr_first_line}', got '${first_line}':" >&2
            cat "${stderr_path}" >&2 || true
            echo "::endgroup::"
            return 1
          fi
        fi
        if [[ -n "${ssh_deny_stderr_regex}" ]] && ! grep -Eq "${ssh_deny_stderr_regex}" "${stderr_path}"; then
          echo "expected tailscale ssh denial stderr, got:" >&2
          cat "${stderr_path}" >&2 || true
          echo "::endgroup::"
          return 1
        fi
        ;;
      timeout)
        ssh_status=0
        tailscale_ssh_attempt "${source_name}" "${target_name}" "${stdout_path}" "${stderr_path}" ||
          ssh_status="$?"
        printf '%s\n' "${ssh_status}" >"${status_path}"
        if ((ssh_status == 0)); then
          echo "expected tailscale ssh ${source_name} to ${target_name} to time out" >&2
          echo "::endgroup::"
          return 1
        fi
        if [[ -n "${ssh_timeout_status}" && "${ssh_timeout_status}" != "any" ]] &&
          ((ssh_status != ssh_timeout_status)); then
          echo "expected timed-out tailscale ssh status ${ssh_timeout_status}, got ${ssh_status}" >&2
          cat "${stderr_path}" >&2 || true
          echo "::endgroup::"
          return 1
        fi
        if [[ -s "${stdout_path}" ]]; then
          echo "expected timed-out tailscale ssh stdout to be empty, got:" >&2
          cat "${stdout_path}" >&2
          echo "::endgroup::"
          return 1
        fi
        if grep -Eq 'Permission denied \(tailscale\)|failed to evaluate SSH policy|tailnet policy does not permit you to SSH to this node' "${stderr_path}"; then
          echo "expected packet-filter timeout, got SSH policy denial:" >&2
          cat "${stderr_path}" >&2 || true
          echo "::endgroup::"
          return 1
        fi
        if ! grep -Eq 'Connection timed out|Operation timed out' "${stderr_path}" &&
          ((ssh_status != 124 && ssh_status != 137 && ssh_status != 143)); then
          echo "expected tailscale ssh timeout status/stderr, got status ${ssh_status}:" >&2
          cat "${stderr_path}" >&2 || true
          echo "::endgroup::"
          return 1
        fi
        ;;
    esac
    ssh_results+=("${source_name}->${target_name}:${expected_ssh}")
  done
  ruby -rjson -e 'puts JSON.pretty_generate({ssh_checks: ARGV})' "${ssh_results[@]}"
  echo "::endgroup::"
}

assert_self_file_sharing_cap() {
  local cap_client_name="$1"
  local output_path="$2"
  local expected="$3"
  local netmap_path="${output_path}.netmap"
  docker exec "${cap_client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
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

assert_file_sharing_cap_if_requested() {
  [[ -n "${expected_file_sharing_cap_bool}" ]] || return 0
  echo "::group::assert file-sharing CapMap"
  local cap_client_name
  for cap_client_name in "${successful_client_names[@]}"; do
    if ! wait_for "file-sharing CapMap ${cap_client_name}" \
      "assert_self_file_sharing_cap '${cap_client_name}' '${work_dir}/file-sharing-cap-${cap_client_name}.json' '${expected_file_sharing_cap_bool}'"; then
      cat "${work_dir}/file-sharing-cap-${cap_client_name}.json.err" >&2 || true
      echo "::endgroup::"
      return 1
    fi
    cat "${work_dir}/file-sharing-cap-${cap_client_name}.json"
  done
  echo "::endgroup::"
}

assert_self_capmap_keys() {
  local cap_client_name="$1"
  local output_path="$2"
  local expected_keys="$3"
  local netmap_path="${output_path}.netmap"
  docker exec "${cap_client_name}" tailscale debug netmap >"${netmap_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      path = ARGV.fetch(0)
      expected = ARGV.fetch(1).split(/[,\s]+/).reject(&:empty?)
      netmap = JSON.parse(File.read(path))
      self_node = netmap["SelfNode"] || netmap["selfNode"] || {}
      cap_map = self_node["CapMap"] || self_node["capMap"] || {}
      missing = expected.reject { |key| cap_map.key?(key) }
      abort("missing expected self CapMap keys #{missing.inspect}; CapMap keys=#{cap_map.keys.inspect}") unless missing.empty?
      puts JSON.pretty_generate({expected_self_capmap_keys: expected.sort, cap_map_keys: cap_map.keys.sort})
    ' "${netmap_path}" "${expected_keys}" >"${output_path}"
}

assert_self_capmap_keys_if_requested() {
  [[ -n "${expected_self_capmap_keys}" ]] || return 0
  echo "::group::assert self CapMap keys"
  local cap_client_name
  for cap_client_name in "${successful_client_names[@]}"; do
    if ! wait_for "self CapMap keys ${cap_client_name}" \
      "assert_self_capmap_keys '${cap_client_name}' '${work_dir}/self-capmap-${cap_client_name}.json' '${expected_self_capmap_keys}'"; then
      cat "${work_dir}/self-capmap-${cap_client_name}.json.err" >&2 || true
      echo "::endgroup::"
      return 1
    fi
    cat "${work_dir}/self-capmap-${cap_client_name}.json"
  done
  echo "::endgroup::"
}

install_or_build_headscale() {
  case "${target}" in
    rust)
      echo "::group::build headscale-rs CLI"
      if [[ "${database_backend}" == "postgres" ]]; then
        cargo build --quiet -p headscale-cli --features postgres-sqlx --bin headscale
      else
        cargo build --quiet -p headscale-cli --bin headscale
      fi
      headscale_bin="${repo_root}/target/debug/headscale"
      echo "::endgroup::"
      ;;
    headscale-go)
      headscale_bin="${HEADSCALE_GO_BIN:-${work_dir}/bin/headscale}"
      echo "::group::build headscale-go ${headscale_go_version}"
      if [[ -z "${HEADSCALE_GO_BIN:-}" ]]; then
        mkdir -p "${work_dir}/bin"
        GOBIN="${work_dir}/bin" go install "github.com/juanfont/headscale/cmd/headscale@${headscale_go_version}"
      fi
      "${headscale_bin}" version >"${work_dir}/headscale-go-version.txt"
      cat "${work_dir}/headscale-go-version.txt"
      echo "::endgroup::"
      ;;
  esac
}

generate_headscale_go_tls() {
  tls_cert_path="${work_dir}/tls.crt"
  tls_key_path="${work_dir}/tls.key"
  echo "::group::generate headscale-go TLS certificate"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
    -keyout "${tls_key_path}" \
    -out "${tls_cert_path}" \
    -subj "/CN=host.docker.internal" \
    -addext "subjectAltName=DNS:host.docker.internal,IP:127.0.0.1" \
    >"${work_dir}/openssl.stdout" \
    2>"${work_dir}/openssl.stderr"
  echo "::endgroup::"
}

write_database_config() {
  case "${database_backend}" in
    sqlite)
      cat <<EOF

database:
  type: sqlite
  sqlite:
    path: ${db_path}
EOF
      ;;
    postgres)
      cat <<EOF

database:
  type: postgres
  postgres:
    host: $(yaml_string "${postgres_host}")
    port: ${postgres_port}
    name: $(yaml_string "${postgres_database_name}")
    user: $(yaml_string "${postgres_user}")
    pass: $(yaml_string "${postgres_pass}")
    ssl: $(yaml_string "${postgres_sslmode}")

policy:
  mode: database
EOF
      ;;
  esac
}

write_derp_map() {
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
}

write_policy_file() {
  [[ -n "${policy_json}${policy_reload_json}" ]] || return 0
  if [[ -n "${policy_json}" ]]; then
    printf '%s\n' "${policy_json}" >"${policy_path}"
  fi
  if [[ -n "${policy_reload_json}" ]]; then
    printf '%s\n' "${policy_reload_json}" >"${policy_reload_path}"
  fi
}

append_dns_extra_records_config() {
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
}

append_dns_nameservers_config() {
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
}

configure_derp_expectations() {
  if ((use_rust_embedded_derp)); then
    if [[ "${rust_derp_relay_mode}" == "native" ]]; then
      rust_derp_effective_port="${https_port}"
    else
      rust_derp_effective_port="${rust_derp_port}"
    fi
    expected_derp_region_id="${REAL_CLIENT_EXPECT_DERP_REGION_ID:-${rust_derp_region_id}}"
    expected_derp_region_code="${REAL_CLIENT_EXPECT_DERP_REGION_CODE:-${rust_derp_region_code}}"
    expected_derp_region_name="${REAL_CLIENT_EXPECT_DERP_REGION_NAME:-${rust_derp_region_name}}"
    expected_derp_host="${REAL_CLIENT_EXPECT_DERP_HOST:-${rust_derp_host}}"
    expected_derp_port="${REAL_CLIENT_EXPECT_DERP_PORT:-${rust_derp_effective_port}}"
    if [[ -n "${REAL_CLIENT_EXPECT_DERP_STUN_PORT:-}" ]]; then
      expected_derp_stun_port="${REAL_CLIENT_EXPECT_DERP_STUN_PORT}"
    else
      expected_derp_stun_port="$(derp_port_from_addr "${rust_derp_stun_addr}")"
    fi
    expected_derp_insecure_for_tests="${REAL_CLIENT_EXPECT_DERP_INSECURE_FOR_TESTS:-${rust_derp_insecure_for_tests_bool}}"
    expected_derp_omit_default_regions="${REAL_CLIENT_EXPECT_DERP_OMIT_DEFAULT_REGIONS:-${rust_derp_omit_default_regions_bool}}"
  fi

  if ((use_headscale_go_embedded_derp)); then
    if [[ -z "${headscale_go_derp_stun_addr}" ]]; then
      headscale_go_derp_stun_addr="0.0.0.0:3478"
    fi
    expected_derp_region_id="${REAL_CLIENT_EXPECT_DERP_REGION_ID:-${headscale_go_derp_region_id}}"
    expected_derp_region_code="${REAL_CLIENT_EXPECT_DERP_REGION_CODE:-${headscale_go_derp_region_code}}"
    expected_derp_region_name="${REAL_CLIENT_EXPECT_DERP_REGION_NAME:-${headscale_go_derp_region_name}}"
    expected_derp_host="${REAL_CLIENT_EXPECT_DERP_HOST:-host.docker.internal}"
    expected_derp_port="${REAL_CLIENT_EXPECT_DERP_PORT:-${http_port}}"
    if [[ -n "${REAL_CLIENT_EXPECT_DERP_STUN_PORT:-}" ]]; then
      expected_derp_stun_port="${REAL_CLIENT_EXPECT_DERP_STUN_PORT}"
    else
      expected_derp_stun_port="$(derp_port_from_addr "${headscale_go_derp_stun_addr}")"
    fi
  fi
}

append_rust_embedded_derp_config() {
  ((use_rust_embedded_derp)) || return 0
  cat >>"${config_path}" <<EOF
  embedded_derp:
    enabled: true
    host_name: $(yaml_string "${rust_derp_host}")
    derp_port: ${rust_derp_effective_port}
    stun_addr: $(yaml_string "${rust_derp_stun_addr}")
    stun_only: false
    relay_mode: $(yaml_string "${rust_derp_relay_mode}")
    region_id: ${rust_derp_region_id}
    region_code: $(yaml_string "${rust_derp_region_code}")
    region_name: $(yaml_string "${rust_derp_region_name}")
    omit_default_regions: ${rust_derp_omit_default_regions_bool}
    insecure_for_tests: ${rust_derp_insecure_for_tests_bool}
    derper_config_path: $(yaml_string "${work_dir}/derper.key")
    verify_client_url: $(yaml_string "${local_control_url}/verify")
    verify_clients: ${rust_derp_verify_clients_bool}
EOF
  if [[ "${rust_derp_relay_mode}" == "sidecar" ]]; then
    cat >>"${config_path}" <<EOF
    derper_binary: $(yaml_string "${rust_derper_binary}")
    derper_listen_addr: $(yaml_string "${rust_derper_listen_addr}")
    derper_cert_mode: $(yaml_string "${rust_derper_cert_mode}")
EOF
    if [[ -n "${rust_derper_cert_dir}" ]]; then
      printf '    derper_cert_dir: %s\n' "$(yaml_string "${rust_derper_cert_dir}")" >>"${config_path}"
    fi
  fi
}

write_config() {
  case "${target}" in
    rust)
      tls_cert_path="${work_dir}/tls.crt"
      tls_key_path="${work_dir}/tls.key"
      cat >"${config_path}" <<EOF
server:
  server_url: ${control_url}
  listen: 0.0.0.0:${http_port}
  https_listen: 0.0.0.0:${https_port}
  metrics_listen_addr: 127.0.0.1:${metrics_port}
  grpc_listen_addr: 127.0.0.1:${grpc_port}
  grpc_allow_insecure: true
  db_path: ${db_path}
  state_dir: ${work_dir}/state
  unix_socket: ${socket_path}
  unix_socket_permission: "0700"
  tls_hostname: host.docker.internal
EOF
      append_rust_embedded_derp_config
      cat >>"${config_path}" <<EOF
unix_socket: ${socket_path}
unix_socket_permission: "0700"

cli:
  timeout: 5s

noise:
  private_key_path: ${work_dir}/noise_private.key

prefixes:
  allocation: sequential
EOF
      if [[ -n "${prefix_v4}" ]]; then
        printf '  v4: %s\n' "${prefix_v4}" >>"${config_path}"
      fi
      if [[ -n "${prefix_v6}" ]]; then
        printf '  v6: %s\n' "${prefix_v6}" >>"${config_path}"
      fi
      cat >>"${config_path}" <<EOF
dns:
  magic_dns: ${magic_dns_yaml}
  base_domain: "${base_domain}"
  override_local_dns: ${dns_override_local_yaml}
  nameservers:
EOF
      append_dns_nameservers_config
      printf '  search_domains: []\n' >>"${config_path}"
      append_dns_extra_records_config
      ;;
    headscale-go)
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
EOF
      if [[ -n "${prefix_v4}" ]]; then
        printf '  v4: %s\n' "${prefix_v4}" >>"${config_path}"
      fi
      if [[ -n "${prefix_v6}" ]]; then
        printf '  v6: %s\n' "${prefix_v6}" >>"${config_path}"
      fi
      cat >>"${config_path}" <<EOF
dns:
  magic_dns: ${magic_dns_yaml}
  base_domain: "${base_domain}"
  override_local_dns: ${dns_override_local_yaml}
  nameservers:
EOF
      append_dns_nameservers_config
      printf '  search_domains: []\n' >>"${config_path}"
      append_dns_extra_records_config
      cat >>"${config_path}" <<EOF

logtail:
  enabled: false

cli:
  timeout: 5s

log:
  level: info
  format: text
EOF
      if ((use_headscale_go_embedded_derp)); then
        cat >>"${config_path}" <<EOF
derp:
  server:
    enabled: true
    region_id: ${headscale_go_derp_region_id}
    region_code: $(yaml_string "${headscale_go_derp_region_code}")
    region_name: $(yaml_string "${headscale_go_derp_region_name}")
    verify_clients: $([[ "${use_headscale_go_derp_verify_clients}" -eq 1 ]] && printf true || printf false)
    stun_listen_addr: $(yaml_string "${headscale_go_derp_stun_addr}")
    private_key_path: $(yaml_string "${work_dir}/derp_server_private.key")
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
EOF
      else
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
      cat >>"${config_path}" <<EOF

tls_cert_path: ${tls_cert_path}
tls_key_path: ${tls_key_path}
EOF
      ;;
  esac
  write_database_config >>"${config_path}"
  if [[ -n "${taildrop_enabled_bool}" ]]; then
    cat >>"${config_path}" <<EOF

taildrop:
  enabled: ${taildrop_enabled_bool}
EOF
  fi
}

headscale_cmd() {
  case "${target}" in
    rust)
      env -u HEADSCALE_CLI_ADDRESS -u HEADSCALE_CLI_API_KEY -u HEADSCALE_CLI_INSECURE \
        "${headscale_bin}" --config "${config_path}" --unix-socket "${socket_path}" "$@"
      ;;
    headscale-go) "${headscale_bin}" -c "${config_path}" "$@" ;;
  esac
}

headscale_health_probe() {
  headscale_cmd -o json health >"${work_dir}/${target}-grpc-health.stdout" 2>"${work_dir}/${target}-grpc-health.stderr"
}

dump_grpc_health_debug() {
  echo "::group::${target} gRPC health debug"
  ls -l "${socket_path}" >&2 || true
  if [[ -s "${work_dir}/${target}-grpc-health.stdout" ]]; then
    echo "--- last health stdout ---" >&2
    cat "${work_dir}/${target}-grpc-health.stdout" >&2 || true
  fi
  if [[ -s "${work_dir}/${target}-grpc-health.stderr" ]]; then
    echo "--- last health stderr ---" >&2
    cat "${work_dir}/${target}-grpc-health.stderr" >&2 || true
  fi
  echo "--- direct health retry ---" >&2
  headscale_cmd -o json health >&2 || true
  echo "::endgroup::"
}

start_server() {
  write_config
  rm -f "${socket_path}"
  echo "::group::start ${target} server"
  case "${target}" in
    rust)
      mkdir -p "${work_dir}/state"
      "${headscale_bin}" --config "${config_path}" serve \
        >"${work_dir}/${target}.stdout" \
        2>"${work_dir}/${target}.stderr" &
      ;;
    headscale-go)
      "${headscale_bin}" -c "${config_path}" serve \
        >"${work_dir}/${target}.stdout" \
        2>"${work_dir}/${target}.stderr" &
      ;;
  esac
  server_pid="$!"
  if ! wait_for_server "${target} health" \
    "curl ${health_curl_opts} '${local_control_url}/health' >/dev/null 2>'${work_dir}/${target}-health.stderr'"; then
    echo "::endgroup::"
    return 1
  fi
  if [[ "${target}" == "rust" ]]; then
    if ! wait_for_server "${target} TLS certificate" "test -s '${tls_cert_path}'"; then
      echo "::endgroup::"
      return 1
    fi
  fi
  if ((expect_debug_ping)); then
    if ! wait_for_server "${target} metrics debug" \
      "curl ${health_curl_opts} '$(debug_ping_url)' >/dev/null 2>'${work_dir}/${target}-metrics-debug.stderr'"; then
      echo "::endgroup::"
      return 1
    fi
  fi
  wait_for_server "${target} gRPC" "headscale_health_probe" || {
    dump_grpc_health_debug
    echo "::endgroup::"
    return 1
  }
  echo "${target} control=${local_control_url}"
  echo "${target} login=${control_url}"
  echo "::endgroup::"
}

server_startup_retryable() {
  local path
  for path in \
    "${work_dir}/${target}.stderr" \
    "${work_dir}/${target}.stdout" \
    "${work_dir}/${target}-health.stderr" \
    "${work_dir}/${target}-metrics-debug.stderr" \
    "${work_dir}/${target}-grpc-health.stderr" \
    "${work_dir}/${target}-grpc-health.stdout"; do
    if [[ -s "${path}" ]] && grep -Eiq 'address already in use|addrinuse|os error 48|os error 98' "${path}"; then
      return 0
    fi
  done
  return 1
}

start_server_with_retries() {
  local attempt status
  for ((attempt = 1; attempt <= server_start_retries; attempt++)); do
    assign_server_ports
    if ((server_start_retries > 1)); then
      echo "${target} server startup attempt ${attempt}/${server_start_retries}" >&2
    fi
    if start_server; then
      return 0
    fi
    status="$?"
    if ((attempt >= server_start_retries)) || ! server_startup_retryable; then
      stop_server
      return "${status}"
    fi
    echo "${target} server listener was already in use; retrying with fresh ports" >&2
    stop_server
    sleep 1
  done
  return 1
}

load_policy_if_requested() {
  [[ -n "${policy_json}" ]] || return 0
  echo "::group::load policy"
  headscale_cmd --force -o json policy set --file "${policy_path}" \
    >"${work_dir}/policy-set.json"
  echo "::endgroup::"
}

reload_policy_if_requested() {
  [[ -n "${policy_reload_json}" ]] || return 0
  echo "::group::reload policy"
  headscale_cmd --force -o json policy set --file "${policy_reload_path}" \
    >"${work_dir}/policy-reload-set.json"
  echo "::endgroup::"
}

user_id_for_name() {
  local wanted="$1"
  local idx
  for idx in "${!created_user_names[@]}"; do
    if [[ "${created_user_names[$idx]}" == "${wanted}" ]]; then
      printf '%s\n' "${created_user_ids[$idx]}"
      return 0
    fi
  done
  return 1
}

relogin_user_name_for_idx() {
  local idx="$1"
  local candidate="relogin-user-$((idx + 1))"
  if [[ "${candidate}" == "${client_users[$idx]}" ]]; then
    candidate="relogin-other-user-$((idx + 1))"
  fi
  printf '%s\n' "${candidate}"
}

mint_preauth_key_for_user() {
  local key_user_id="$1"
  local output_name="$2"
  local key_tags="${preauth_tags}"
  local key_expired_flag="${preauth_expired_flag}"
  local key_deleted_flag=0
  if (($# >= 3)); then
    key_tags="$3"
  fi
  if (($# >= 4)); then
    key_expired_flag="$4"
  fi
  if (($# >= 5)); then
    key_deleted_flag="$5"
  fi
  local preauth_args=(
    -o json preauthkeys create
    --user "${key_user_id}"
    --expiration 1h
  )
  if ((preauth_reusable_flag)); then
    preauth_args+=(--reusable)
  fi
  if [[ -n "${key_tags}" ]]; then
    preauth_args+=(--tags "${key_tags}")
  fi
  headscale_cmd "${preauth_args[@]}" >"${work_dir}/${output_name}.json"
  if ((key_expired_flag)); then
    local authkey_id
    authkey_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); id = j["id"] || j["ID"]; abort("missing preauth key ID") unless id; puts id' "${work_dir}/${output_name}.json")"
    headscale_cmd -o json preauthkeys expire --id "${authkey_id}" \
      >"${work_dir}/${output_name}-expired.json"
  fi
  if ((key_deleted_flag)); then
    local authkey_id
    authkey_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); id = j["id"] || j["ID"]; abort("missing preauth key ID") unless id; puts id' "${work_dir}/${output_name}.json")"
    headscale_cmd -o json preauthkeys delete --id "${authkey_id}" \
      >"${work_dir}/${output_name}-deleted.json"
  fi
  ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("key")' "${work_dir}/${output_name}.json"
}

create_user_and_key() {
  echo "::group::create users"
  local user user_email idx created_idx user_id exists safe_user existing_email create_args
  local users_to_create=("${client_users[@]}")
  if ((authkey_relogin_different_user_flag)); then
    for idx in "${!client_users[@]}"; do
      users_to_create+=("$(relogin_user_name_for_idx "${idx}")")
    done
  fi
  for idx in "${!users_to_create[@]}"; do
    user="${users_to_create[$idx]}"
    user_email=""
    if ((idx < ${#client_users[@]})); then
      user_email="${client_user_emails[$idx]}"
    fi
    exists=0
    for created_idx in "${!created_user_names[@]}"; do
      if [[ "${created_user_names[$created_idx]}" == "${user}" ]]; then
        existing_email="${created_user_emails[$created_idx]}"
        if [[ "${user_email}" != "${existing_email}" ]]; then
          echo "REAL_CLIENT_CLIENT_USER_EMAILS has conflicting emails for user ${user}: ${existing_email} and ${user_email}" >&2
          exit 2
        fi
        exists=1
        break
      fi
    done
    ((exists == 0)) || continue
    safe_user="${user//[^a-zA-Z0-9_.-]/-}"
    create_args=(-o json users create "${user}")
    if [[ -n "${user_email}" ]]; then
      create_args+=(--email "${user_email}")
    fi
    headscale_cmd "${create_args[@]}" >"${work_dir}/user-${safe_user}.json"
    user_id="$(ruby -rjson -e 'j=JSON.parse(File.read(ARGV.fetch(0))); puts j.fetch("id")' "${work_dir}/user-${safe_user}.json")"
    created_user_names+=("${user}")
    created_user_ids+=("${user_id}")
    created_user_emails+=("${user_email}")
    echo "created user ${user} ${user_id}"
  done
  echo "::endgroup::"

  load_policy_if_requested

  if [[ "${login_mode}" == "authkey" ]]; then
    echo "::group::mint preauth keys"
    authkeys=()
    if [[ -n "${client_users_csv}" || -n "${preauth_tags_by_client}" ]]; then
      for idx in "${!client_users[@]}"; do
        user_id="$(user_id_for_name "${client_users[$idx]}")"
        authkey="$(mint_preauth_key_for_user "${user_id}" "preauth-${idx}" "${preauth_tags_values[$idx]}")"
        authkeys+=("${authkey}")
      done
      echo "minted ${#authkeys[@]} per-client keys"
    else
      user_id="$(user_id_for_name "${client_users[0]}")"
      authkey="$(mint_preauth_key_for_user "${user_id}" "preauth")"
      for idx in "${!client_names[@]}"; do
        authkeys+=("${authkey}")
      done
      echo "minted ${authkey%%-*}-..."
    fi
    echo "::endgroup::"
  fi
}

start_client() {
  echo "::group::start stock tailscale client"
  local client_entry tailscaled_prefix
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
  docker_args=(
    docker run -d
    --name "${client_name}" \
    --hostname "${client_name}" \
    --add-host host.docker.internal:host-gateway \
    --entrypoint /bin/sh
  )
  docker_args+=(-v "${tls_cert_path}:/usr/local/share/ca-certificates/headscale-control.crt:ro")
  docker_args+=("${image}")
  "${docker_args[@]}" \
    -ceu "${client_entry}" \
    >/dev/null

  wait_for "tailscaled local socket" \
    "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"
  echo "::endgroup::"
}

login_client() {
  local expect_login_failure="${1:-0}"
  echo "::group::tailscale up"
  up_args=(
    tailscale up
    "--login-server=${control_url}"
    "--hostname=${client_name}"
    "--timeout=${up_timeout}"
    --accept-routes=false
    "--accept-dns=${accept_dns_arg}"
  )
  if [[ "${login_mode}" == "authkey" ]]; then
    up_args+=("--authkey=${authkeys[$current_client_index]}")
  fi
  if [[ -n "${advertise_routes}" ]]; then
    up_args+=("--advertise-routes=${advertise_routes}")
  fi
  if ((advertise_exit_node_flag)); then
    up_args+=(--advertise-exit-node)
  fi
  if [[ "${login_mode}" == "web" && -n "${preauth_tags}" ]]; then
    up_args+=("--advertise-tags=${preauth_tags}")
  fi
  if ((enable_tailscale_ssh_flag)); then
    up_args+=(--ssh)
  fi

  up_status=0
  if [[ "${login_mode}" == "web" ]]; then
    docker exec "${client_name}" "${up_args[@]}" \
      >"${work_dir}/${client_name}.tailscale-up.stdout" \
      2>"${work_dir}/${client_name}.tailscale-up.stderr" &
    up_pid="$!"
    registration_id_path="${work_dir}/${client_name}.registration-id"
    if ! wait_for "web registration URL" "write_registration_id '${registration_id_path}'"; then
      dump_debug
      return 1
    fi
    registration_id="$(cat "${registration_id_path}")"
    register_status=0
    case "${target}" in
      rust)
        auth_id="${registration_id}"
        case "${auth_id}" in
          hskey-authreq-*) ;;
          *) auth_id="hskey-authreq-${auth_id}" ;;
        esac
        headscale_cmd -o json auth register "--auth-id=${auth_id}" --user alice \
          >"${work_dir}/${client_name}.registered.json" \
          2>"${work_dir}/${client_name}.registered.stderr" ||
          register_status="$?"
        ;;
      headscale-go)
        headscale_cmd -o json nodes register --user alice "--key=${registration_id}" \
          >"${work_dir}/${client_name}.registered.json" \
          2>"${work_dir}/${client_name}.registered.stderr" ||
          register_status="$?"
        ;;
    esac
    if ((expect_register_failure)); then
      if ((register_status == 0)); then
        echo "expected web registration to fail for requested tags ${preauth_tags}" >&2
        kill "${up_pid}" >/dev/null 2>&1 || true
        wait "${up_pid}" >/dev/null 2>&1 || true
        echo "::endgroup::"
        return 1
      fi
      registration_failed_as_expected=1
      kill "${up_pid}" >/dev/null 2>&1 || true
      wait "${up_pid}" >/dev/null 2>&1 || true
      echo "::endgroup::"
      return 0
    fi
    if ((register_status != 0)); then
      cat "${work_dir}/${client_name}.registered.stderr" >&2 || true
      kill "${up_pid}" >/dev/null 2>&1 || true
      wait "${up_pid}" >/dev/null 2>&1 || true
      echo "::endgroup::"
      return "${register_status}"
    fi
    wait_pid_with_timeout "tailscale up ${client_name}" "${up_pid}" ||
      up_status="$?"
  else
    run_with_timeout "tailscale up ${client_name}" docker exec "${client_name}" "${up_args[@]}" ||
      up_status="$?"
  fi
  if ((up_status != 0)); then
    echo "tailscale up returned ${up_status}; verifying logged-in netmap"
  fi
  if ((expect_login_failure)); then
    if client_logged_in "${client_name}" "${work_dir}/${client_name}.unexpected-login-status.json"; then
      echo "expected auth-key login failure for ${client_name}, but it logged in" >&2
      echo "::endgroup::"
      return 1
    fi
    docker exec "${client_name}" tailscale status --json \
      >"${work_dir}/${client_name}.expected-authkey-failure-status.json" 2>/dev/null || true
    echo "auth-key login failed as expected for ${client_name}"
    echo "::endgroup::"
    return 0
  fi
  wait_for "logged-in client netmap" \
    "client_logged_in '${client_name}' '${work_dir}/${client_name}.status.json'"
  echo "::endgroup::"
}

reauth_client_if_requested() {
  ((do_reauth_after_login)) || return 0
  echo "::group::force web reauth"
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
  if ! wait_for "reauth web registration URL" "write_registration_id '${registration_id_path}'"; then
    dump_debug
    return 1
  fi
  registration_id="$(cat "${registration_id_path}")"
  case "${target}" in
    rust)
      auth_id="${registration_id}"
      case "${auth_id}" in
        hskey-authreq-*) ;;
        *) auth_id="hskey-authreq-${auth_id}" ;;
      esac
      headscale_cmd -o json auth register "--auth-id=${auth_id}" --user alice \
        >"${work_dir}/${client_name}.reauth-registered.json"
      ;;
    headscale-go)
      headscale_cmd -o json nodes register --user alice "--key=${registration_id}" \
        >"${work_dir}/${client_name}.reauth-registered.json"
      ;;
  esac
  wait_pid_with_timeout "tailscale reauth ${client_name}" "${up_pid}" ||
    up_status="$?"
  if ((up_status != 0)); then
    echo "tailscale reauth returned ${up_status}; verifying logged-in netmap"
  fi
  wait_for "logged-in client netmap after reauth" \
    "docker exec '${client_name}' tailscale status --json >'${work_dir}/${client_name}.reauth-status.json' 2>/dev/null && ruby -rjson -e 's=JSON.parse(File.read(ARGV.fetch(0))); ips=Array(s[\"TailscaleIPs\"]); ok=s[\"HaveNodeKey\"] && s[\"AuthURL\"].to_s.empty? && (s[\"Self\"]||{})[\"InNetworkMap\"] && !ips.empty?; exit(ok ? 0 : 1)' '${work_dir}/${client_name}.reauth-status.json'"
  echo "::endgroup::"
}

tailscale_status_ips() {
  local status_path="$1"
  ruby -rjson -e '
    status = JSON.parse(File.read(ARGV.fetch(0)))
    puts Array(status["TailscaleIPs"]).sort.join(",")
  ' "${status_path}"
}

relogin_with_authkey_if_requested() {
  ((authkey_relogin_requested_flag)) || return 0
  local rejection_mode=""
  if ((authkey_relogin_different_user_flag)); then
    rejection_mode="different-user"
    echo "::group::auth-key logout and different-user relogin rejection"
  elif ((authkey_relogin_deleted_flag)); then
    rejection_mode="deleted-key"
    echo "::group::auth-key logout and deleted-key relogin rejection"
  elif ((authkey_relogin_expired_flag)); then
    rejection_mode="expired"
    echo "::group::auth-key logout and expired-key relogin rejection"
  else
    echo "::group::auth-key logout and same-user relogin"
  fi
  local expected_count="${expected_machine_count:-${#successful_client_names[@]}}"
  local before_nodes_path="${work_dir}/nodes-before-relogin.json"
  local after_nodes_path="${work_dir}/nodes-after-relogin.json"
  local relogin_authkeys=()
  local relogin_before_ips=()
  local idx client_name relogin_user user_id relogin_status relogin_after_ips
  local up_args=()

  headscale_cmd -o json nodes list >"${before_nodes_path}"
  for idx in "${!client_names[@]}"; do
    client_name="${client_names[$idx]}"
    docker exec "${client_name}" tailscale status --json >"${work_dir}/${client_name}.relogin-before-status.json"
    relogin_before_ips+=("$(tailscale_status_ips "${work_dir}/${client_name}.relogin-before-status.json")")
    relogin_user="${client_users[$idx]}"
    if ((authkey_relogin_different_user_flag)); then
      relogin_user="$(relogin_user_name_for_idx "${idx}")"
    fi
    user_id="$(user_id_for_name "${relogin_user}")"
    relogin_authkeys+=("$(mint_preauth_key_for_user "${user_id}" "preauth-relogin-${idx}" "${preauth_tags_values[$idx]}" "${authkey_relogin_expired_flag}" "${authkey_relogin_deleted_flag}")")
  done

  if ((authkey_relogin_deleted_flag)); then
    echo "restarting ${target} server after deleting relogin preauth key"
    stop_server
    if ! start_server; then
      echo "::endgroup::"
      return 1
    fi
  fi

  for idx in "${!client_names[@]}"; do
    client_name="${client_names[$idx]}"
    docker exec "${client_name}" tailscale logout \
      >"${work_dir}/${client_name}.logout.stdout" \
      2>"${work_dir}/${client_name}.logout.stderr"
    wait_for "tailscale logged out ${client_name}" \
      "docker exec '${client_name}' sh -ceu 'tailscale status >/tmp/ts.status 2>&1 || true; grep -Eq \"Logged out|NeedsLogin|Needs login\" /tmp/ts.status'"

    up_args=(
      tailscale up
      "--login-server=${control_url}"
      "--hostname=${client_name}"
      "--timeout=${up_timeout}"
      --accept-routes=false
      "--accept-dns=${accept_dns_arg}"
      "--authkey=${relogin_authkeys[$idx]}"
    )
    if [[ -n "${advertise_routes}" ]]; then
      up_args+=("--advertise-routes=${advertise_routes}")
    fi
    if ((advertise_exit_node_flag)); then
      up_args+=(--advertise-exit-node)
    fi
    if ((enable_tailscale_ssh_flag)); then
      up_args+=(--ssh)
    fi

    relogin_status=0
    run_with_timeout "tailscale auth-key relogin ${client_name}" docker exec "${client_name}" "${up_args[@]}" ||
      relogin_status="$?"
    if ((authkey_relogin_expired_flag || authkey_relogin_different_user_flag || authkey_relogin_deleted_flag)); then
      if client_logged_in "${client_name}" "${work_dir}/${client_name}.unexpected-relogin-status.json"; then
        if ((authkey_relogin_different_user_flag)); then
          echo "expected different-user auth-key relogin to fail for ${client_name}, but it logged in" >&2
        elif ((authkey_relogin_deleted_flag)); then
          echo "expected deleted-key auth-key relogin to fail for ${client_name}, but it logged in" >&2
        else
          echo "expected expired auth-key relogin to fail for ${client_name}, but it logged in" >&2
        fi
        echo "::endgroup::"
        return 1
      fi
      docker exec "${client_name}" tailscale status --json \
        >"${work_dir}/${client_name}.expected-relogin-failure-status.json" 2>/dev/null || true
      if ((authkey_relogin_different_user_flag)); then
        echo "different-user auth-key relogin failed as expected for ${client_name}"
      elif ((authkey_relogin_deleted_flag)); then
        echo "deleted-key auth-key relogin failed as expected for ${client_name}"
      else
        echo "expired auth-key relogin failed as expected for ${client_name}"
      fi
      continue
    fi
    if ((relogin_status != 0)); then
      echo "tailscale same-user relogin ${client_name} returned ${relogin_status}; verifying logged-in netmap"
    fi
    if ! wait_for "tailscale logged-in netmap after same-user relogin ${client_name}" \
      "client_logged_in '${client_name}' '${work_dir}/${client_name}.relogin-status.json'"; then
      dump_client_debug "${client_name}"
      echo "::endgroup::"
      return 1
    fi
    relogin_after_ips="$(tailscale_status_ips "${work_dir}/${client_name}.relogin-status.json")"
    if [[ "${relogin_after_ips}" != "${relogin_before_ips[$idx]}" ]]; then
      echo "expected stable Tailscale IPs for ${client_name}: ${relogin_before_ips[$idx]}, got ${relogin_after_ips}" >&2
      echo "::endgroup::"
      return 1
    fi
    cp "${work_dir}/${client_name}.relogin-status.json" "${work_dir}/${client_name}.status.json"
  done

  headscale_cmd -o json nodes list >"${after_nodes_path}"
  if ((authkey_relogin_expired_flag || authkey_relogin_different_user_flag || authkey_relogin_deleted_flag)); then
    ruby -rjson -e '
      def nodes(path)
        payload = JSON.parse(File.read(path))
        payload.nil? ? [] : (payload.is_a?(Array) ? payload : payload.fetch("nodes"))
      end

      before = nodes(ARGV.fetch(0))
      after = nodes(ARGV.fetch(1))
      expected_count = Integer(ARGV.fetch(2))
      mode = ARGV.fetch(3)
      expected_names = ARGV.fetch(4).split(",").reject(&:empty?)
      abort("expected #{expected_count} nodes before #{mode} relogin, got #{before.length}") unless before.length == expected_count
      abort("expected #{expected_count} nodes after #{mode} relogin rejection, got #{after.length}") unless after.length == expected_count

      if ["different-user", "deleted-key"].include?(mode)
        def node_name(node)
          node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
        end

        def user_name(node)
          user = node["user"] || node["User"]
          user.is_a?(Hash) ? (user["name"] || user["loginName"] || user["login_name"]) : user.to_s
        end

        def node_id(node)
          node["id"] || node["ID"] || node["nodeId"] || node["node_id"]
        end

        expected_names.each do |name|
          old = before.find { |node| node_name(node).to_s == name }
          new = after.find { |node| node_name(node).to_s == name }
          abort("missing before-relogin node #{name.inspect}") unless old
          abort("missing after-relogin node #{name.inspect}") unless new

          checks = {
            "id" => [node_id(old), node_id(new)],
            "user" => [user_name(old), user_name(new)],
            "ipAddresses" => [
              Array(old["ipAddresses"] || old["ip_addresses"] || old["addresses"]).map(&:to_s).sort,
              Array(new["ipAddresses"] || new["ip_addresses"] || new["addresses"]).map(&:to_s).sort,
            ],
            "availableRoutes" => [
              Array(old["availableRoutes"] || old["available_routes"]).map(&:to_s).sort,
              Array(new["availableRoutes"] || new["available_routes"]).map(&:to_s).sort,
            ],
            "approvedRoutes" => [
              Array(old["approvedRoutes"] || old["approved_routes"]).map(&:to_s).sort,
              Array(new["approvedRoutes"] || new["approved_routes"]).map(&:to_s).sort,
            ],
          }
          checks.each do |field, values|
            old_value, new_value = values
            abort("#{mode} relogin changed #{name} #{field}: #{old_value.inspect} -> #{new_value.inspect}") unless old_value == new_value
          end
        end
      end
      puts JSON.pretty_generate({"#{mode.tr("-", "_")}_relogin_rejected_nodes": after.length})
    ' "${before_nodes_path}" "${after_nodes_path}" "${expected_count}" "${rejection_mode}" "$(IFS=,; echo "${successful_client_names[*]}")"
    echo "::endgroup::"
    if ((authkey_relogin_different_user_flag)); then
      echo "${target} different-user auth-key relogin real-client smoke passed"
    elif ((authkey_relogin_deleted_flag)); then
      echo "${target} deleted-key auth-key relogin real-client smoke passed"
    else
      echo "${target} expired auth-key relogin real-client smoke passed"
    fi
    exit 0
  fi
  ruby -rjson -e '
    def nodes(path)
      payload = JSON.parse(File.read(path))
      payload.nil? ? [] : (payload.is_a?(Array) ? payload : payload.fetch("nodes"))
    end

    def node_name(node)
      node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
    end

    def user_name(node)
      user = node["user"] || node["User"]
      user.is_a?(Hash) ? (user["name"] || user["loginName"] || user["login_name"]) : user.to_s
    end

    def node_id(node)
      node["id"] || node["ID"] || node["nodeId"] || node["node_id"]
    end

    before = nodes(ARGV.fetch(0))
    after = nodes(ARGV.fetch(1))
    expected_count = Integer(ARGV.fetch(2))
    expected_names = ARGV.fetch(3).split(",").reject(&:empty?)
    abort("expected #{expected_count} nodes before relogin, got #{before.length}") unless before.length == expected_count
    abort("expected #{expected_count} nodes after relogin, got #{after.length}") unless after.length == expected_count

    expected_names.each do |name|
      old = before.find { |node| node_name(node).to_s == name }
      new = after.find { |node| node_name(node).to_s == name }
      abort("missing before-relogin node #{name.inspect}") unless old
      abort("missing after-relogin node #{name.inspect}") unless new

      checks = {
        "id" => [node_id(old), node_id(new)],
        "user" => [user_name(old), user_name(new)],
        "ipAddresses" => [
          Array(old["ipAddresses"] || old["ip_addresses"] || old["addresses"]).map(&:to_s).sort,
          Array(new["ipAddresses"] || new["ip_addresses"] || new["addresses"]).map(&:to_s).sort,
        ],
        "availableRoutes" => [
          Array(old["availableRoutes"] || old["available_routes"]).map(&:to_s).sort,
          Array(new["availableRoutes"] || new["available_routes"]).map(&:to_s).sort,
        ],
        "approvedRoutes" => [
          Array(old["approvedRoutes"] || old["approved_routes"]).map(&:to_s).sort,
          Array(new["approvedRoutes"] || new["approved_routes"]).map(&:to_s).sort,
        ],
      }
      checks.each do |field, values|
        old_value, new_value = values
        abort("relogin changed #{name} #{field}: #{old_value.inspect} -> #{new_value.inspect}") unless old_value == new_value
      end
    end
    puts JSON.pretty_generate({relogin_preserved_nodes: expected_names})
  ' "${before_nodes_path}" "${after_nodes_path}" "${expected_count}" "$(IFS=,; echo "${successful_client_names[*]}")"
  echo "::endgroup::"
}

assert_client_netmap() {
  local netmap_path="${work_dir}/${client_name}.netmap.json"
  docker exec "${client_name}" tailscale debug netmap >"${netmap_path}" 2>"${netmap_path}.err"
  ruby -rjson -e '
    netmap = JSON.parse(File.read(ARGV.fetch(0)))
    client_name = ARGV.fetch(1)
    expected_allowed = ARGV.fetch(2).split(",").reject(&:empty?)
    self_node = netmap["SelfNode"] || netmap["Node"] || {}
    hostname = self_node["HostName"] || self_node["Name"] || self_node["DNSName"]
    ips = Array(self_node["Addresses"] || self_node["AllowedIPs"] || self_node["AllowedIps"])
    allowed_ips = Array(
      self_node["AllowedIPs"] ||
      self_node["AllowedIps"] ||
      self_node["allowedIPs"] ||
      self_node["allowed_ips"]
    ).map(&:to_s)
    abort("expected self node in netmap, got #{netmap.inspect}") if self_node.empty?
    abort("expected self hostname to include #{client_name.inspect}, got #{hostname.inspect}") unless hostname.to_s.include?(client_name)
    abort("expected self node addresses/AllowedIPs in #{self_node.inspect}") if ips.empty?
    expected_allowed.each do |route|
      abort("expected self AllowedIPs to include approved route #{route.inspect}, got #{allowed_ips.inspect}") unless allowed_ips.include?(route)
    end
    puts JSON.pretty_generate({
      hostname: hostname,
      ips: ips,
      allowed_ips: allowed_ips,
      peers: Array(netmap["Peers"] || netmap["peers"]).length,
    })
  ' "${netmap_path}" "${client_name}" "${expected_approved_routes}" >"${work_dir}/${client_name}.netmap-summary.json"
  cat "${work_dir}/${client_name}.netmap-summary.json"
}

wait_for_client_netmap() {
  wait_for "client netmap" "assert_client_netmap" || {
    dump_debug
    return 1
  }
}

debug_ping_url() {
  case "${target}" in
    rust) printf 'http://127.0.0.1:%s/debug/ping' "${metrics_port}" ;;
    headscale-go) printf 'http://127.0.0.1:%s/debug/ping' "${metrics_port}" ;;
  esac
}

assert_debug_ping_if_requested() {
  ((expect_debug_ping)) || return 0
  echo "::group::assert debug PingRequest lifecycle"
  local ping_url
  ping_url="$(debug_ping_url)"
  curl -fsS --max-time "${timeout_secs}" \
    --get \
    --data-urlencode "node=${client_name}" \
    "${ping_url}" \
    >"${work_dir}/debug-ping.html"
  if ! grep -Eq 'Ping OK|Pong|responded' "${work_dir}/debug-ping.html"; then
    echo "expected /debug/ping to report a successful PingRequest callback" >&2
    cat "${work_dir}/debug-ping.html" >&2 || true
    dump_debug
    echo "::endgroup::"
    return 1
  fi
  ruby -rjson -e 'puts JSON.pretty_generate({debug_ping: "ok", node: ARGV.fetch(0)})' "${client_name}"
  echo "::endgroup::"
}

assert_magic_dns_status() {
  local output_path="${work_dir}/${client_name}.magicdns-status.json"
  docker exec "${client_name}" tailscale status --json >"${output_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      status = JSON.parse(File.read(ARGV.fetch(0)))
      expected_suffix = ARGV.fetch(1).sub(/\.\z/, "")
      self_node = status.fetch("Self")
      self_host = self_node.fetch("HostName").to_s
      suffix = status.fetch("MagicDNSSuffix").to_s.sub(/\.\z/, "")
      abort("expected MagicDNSSuffix #{expected_suffix.inspect}, got #{suffix.inspect}") unless suffix == expected_suffix
      self_dns = self_node.fetch("DNSName").to_s.sub(/\.\z/, "")
      expected_self_dns = "#{self_host}.#{expected_suffix}"
      abort("expected self DNSName #{expected_self_dns.inspect}, got #{self_dns.inspect}") unless self_dns == expected_self_dns
      puts JSON.pretty_generate({
        magic_dns_suffix: suffix,
        self_host: self_host,
        self_dns: self_dns,
      })
    ' "${output_path}" "${expected_magic_dns_suffix}" >"${work_dir}/${client_name}.magicdns-summary.json"
  cat "${work_dir}/${client_name}.magicdns-summary.json"
}

assert_magic_dns_if_requested() {
  [[ -n "${expected_magic_dns_suffix}" ]] || return 0
  echo "::group::assert MagicDNS client status"
  wait_for "MagicDNS suffix ${expected_magic_dns_suffix}" "assert_magic_dns_status" || {
    dump_debug
    echo "::endgroup::"
    return 1
  }
  echo "::endgroup::"
}

assert_no_magic_dns_status() {
  local output_path="${work_dir}/${client_name}.no-magicdns-status.json"
  docker exec "${client_name}" tailscale status --json >"${output_path}" 2>"${output_path}.err" &&
    ruby -rjson -e '
      status = JSON.parse(File.read(ARGV.fetch(0)))
      self_node = status.fetch("Self")
      self_host = self_node.fetch("HostName").to_s
      suffix = status["MagicDNSSuffix"].to_s.sub(/\.\z/, "")
      abort("expected MagicDNSSuffix to fall back to self hostname #{self_host.inspect}, got #{suffix.inspect}") unless suffix == self_host
      self_dns = self_node["DNSName"].to_s.sub(/\.\z/, "")
      abort("expected bare self DNSName #{self_host.inspect}, got #{self_dns.inspect}") unless self_dns == self_host
      puts JSON.pretty_generate({
        magic_dns: false,
        self_host: self_host,
        self_dns: self_dns,
      })
    ' "${output_path}" >"${work_dir}/${client_name}.no-magicdns-summary.json"
  cat "${work_dir}/${client_name}.no-magicdns-summary.json"
}

assert_no_magic_dns_if_requested() {
  ((expect_no_magic_dns)) || return 0
  echo "::group::assert MagicDNS disabled client status"
  wait_for "MagicDNS disabled fallback names" "assert_no_magic_dns_status" || {
    dump_debug
    echo "::endgroup::"
    return 1
  }
  echo "::endgroup::"
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

assert_peer_magic_dns_debug_resolve_if_requested() {
  ((expect_peer_magic_dns_resolve)) || return 0
  echo "::group::assert peer MagicDNS client resolution"
  local resolver_client
  for resolver_client in "${successful_client_names[@]}"; do
    safe_client="${resolver_client//[^a-zA-Z0-9_.-]/-}"
    wait_for "peer MagicDNS resolver ${resolver_client}" \
      "assert_peer_magic_dns_debug_resolve '${resolver_client}' '${work_dir}/${safe_client}.peer-magicdns-resolve.json'" || {
        dump_debug
        echo "::endgroup::"
        return 1
      }
    cat "${work_dir}/${safe_client}.peer-magicdns-resolve.json"
  done
  echo "::endgroup::"
}

assert_dns_extra_record() {
  local host="$1"
  local expected="$2"
  local expected_type="$3"
  local output_path="$4"
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
  local expected_spec="$1"
  local output_path="$2"
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

assert_dns_extra_records_if_requested() {
  [[ -n "${expected_dns_extra_records}" ]] || return 0
  echo "::group::assert DNS extra records"
  IFS=',' read -r -a dns_expectations <<<"${expected_dns_extra_records}"
  for expectation in "${dns_expectations[@]}"; do
    host="${expectation%%=*}"
    expected="${expectation#*=}"
    if [[ -z "${host}" || -z "${expected}" || "${host}" == "${expectation}" ]]; then
      echo "REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS entries must be host=value, got ${expectation}" >&2
      echo "::endgroup::"
      return 2
    fi
    expected_type=""
    if [[ "${expected}" =~ ^(A|AAAA|CNAME):(.*)$ ]]; then
      expected_type="${BASH_REMATCH[1]}"
      expected="${BASH_REMATCH[2]}"
    fi
    safe_host="${host//[^a-zA-Z0-9_.-]/-}"
    wait_for "DNS extra record ${host}" \
      "assert_dns_extra_record '${host}' '${expected}' '${expected_type}' '${work_dir}/dns-${safe_host}.json'" || {
        dump_debug
        echo "::endgroup::"
        return 1
      }
    cat "${work_dir}/dns-${safe_host}.json"
  done
  if ((expect_dns_extra_records_exact)); then
    wait_for "exact DNS extra records" \
      "assert_dns_extra_records_exact '${expected_dns_extra_records}' '${work_dir}/dns-extra-records-exact.json'" || {
        dump_debug
        echo "::endgroup::"
        return 1
      }
    cat "${work_dir}/dns-extra-records-exact.json"
  fi
  echo "::endgroup::"
}

assert_dns_debug_resolves_if_requested() {
  [[ -n "${expected_dns_debug_resolves}" ]] || return 0
  echo "::group::assert DNS client resolution"
  local resolver_client="${client_name}"
  IFS=',' read -r -a dns_resolution_expectations <<<"${expected_dns_debug_resolves}"
  for expectation in "${dns_resolution_expectations[@]}"; do
    host="${expectation%%=*}"
    expected="${expectation#*=}"
    if [[ -z "${host}" || -z "${expected}" || "${host}" == "${expectation}" ]]; then
      echo "REAL_CLIENT_EXPECT_DNS_DEBUG_RESOLVES entries must be host=value or host=network:value, got ${expectation}" >&2
      echo "::endgroup::"
      return 2
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
        dump_debug
        echo "::endgroup::"
        return 1
      }
    cat "${work_dir}/dns-resolve-${safe_host}-${network}.json"
  done
  echo "::endgroup::"
}

assert_dns_resolver_list() {
  local field="$1"
  local expected_csv="$2"
  local output_path="$3"
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
  local suffix="$1"
  local expected_csv="$2"
  local output_path="$3"
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

assert_dns_resolvers_if_requested() {
  [[ -n "${expected_dns_resolvers}" ]] || return 0
  echo "::group::assert DNS resolvers"
  wait_for "DNS resolvers ${expected_dns_resolvers}" \
    "assert_dns_resolver_list 'Resolvers' '${expected_dns_resolvers}' '${work_dir}/dns-resolvers.json'" || {
      dump_debug
      echo "::endgroup::"
      return 1
    }
  cat "${work_dir}/dns-resolvers.json"
  echo "::endgroup::"
}

assert_dns_fallback_resolvers_if_requested() {
  [[ -n "${expected_dns_fallback_resolvers}" ]] || return 0
  echo "::group::assert DNS fallback resolvers"
  wait_for "DNS fallback resolvers ${expected_dns_fallback_resolvers}" \
    "assert_dns_resolver_list 'FallbackResolvers' '${expected_dns_fallback_resolvers}' '${work_dir}/dns-fallback-resolvers.json'" || {
      dump_debug
      echo "::endgroup::"
      return 1
    }
  cat "${work_dir}/dns-fallback-resolvers.json"
  echo "::endgroup::"
}

assert_dns_routes_if_requested() {
  [[ -n "${expected_dns_routes}" ]] || return 0
  echo "::group::assert DNS split routes"
  IFS=',' read -r -a dns_route_expectations <<<"${expected_dns_routes}"
  for expectation in "${dns_route_expectations[@]}"; do
    suffix="${expectation%%=*}"
    expected="${expectation#*=}"
    if [[ -z "${suffix}" || -z "${expected}" || "${suffix}" == "${expectation}" ]]; then
      echo "REAL_CLIENT_EXPECT_DNS_ROUTES entries must be suffix=resolver|resolver, got ${expectation}" >&2
      echo "::endgroup::"
      return 2
    fi
    expected_csv="${expected//|/,}"
    safe_suffix="${suffix//[^a-zA-Z0-9_.-]/-}"
    wait_for "DNS route ${suffix}" \
      "assert_dns_route '${suffix}' '${expected_csv}' '${work_dir}/dns-route-${safe_suffix}.json'" || {
        dump_debug
        echo "::endgroup::"
        return 1
      }
    cat "${work_dir}/dns-route-${safe_suffix}.json"
  done
  echo "::endgroup::"
}

assert_tailscale_ip_family_if_requested() {
  [[ -n "${expected_tailscale_ip_families}" ]] || return 0
  echo "::group::assert Tailscale IP families"
  local status_path="${work_dir}/${client_name}.ip-family-status.json"
  docker exec "${client_name}" tailscale status --json >"${status_path}"
  ruby -rjson -e '
    expected = ARGV.fetch(0)
    path = ARGV.fetch(1)
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
  ' "${expected_tailscale_ip_families}" "${status_path}"
  echo "::endgroup::"
}

node_id_for_client() {
  local path="$1"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    client_name = ARGV.fetch(1)
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    node = nodes.find do |candidate|
      [
        candidate["givenName"],
        candidate["given_name"],
        candidate["name"],
        candidate["hostname"],
      ].compact.map(&:to_s).any? { |name| name == client_name || name.include?(client_name) }
    end
    abort("expected one node named #{client_name.inspect}, got #{nodes.inspect}") unless node
    id = node["id"] || node["ID"]
    abort("expected node id in #{node.inspect}") if id.nil? || id.to_s.empty?
    puts id
  ' "${path}" "${client_name}"
}

assert_node_routes_file() {
  local path="$1"
  local expected_available="$2"
  local expected_approved="$3"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    client_name = ARGV.fetch(1)
    expected_available = ARGV.fetch(2).split(",").reject(&:empty?).sort
    expected_approved = ARGV.fetch(3).split(",").reject(&:empty?).sort
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    node = nodes.find do |candidate|
      [
        candidate["givenName"],
        candidate["given_name"],
        candidate["name"],
        candidate["hostname"],
      ].compact.map(&:to_s).any? { |name| name == client_name || name.include?(client_name) }
    end
    abort("expected one node named #{client_name.inspect}, got #{nodes.inspect}") unless node
    available = Array(
      node["availableRoutes"] ||
      node["available_routes"] ||
      node["routes"]
    ).map(&:to_s).sort
    approved = Array(node["approvedRoutes"] || node["approved_routes"]).map(&:to_s).sort
    subnet = Array(node["subnetRoutes"] || node["subnet_routes"]).map(&:to_s).sort
    abort("expected available routes #{expected_available.inspect}, got #{available.inspect} in #{node.inspect}") unless available == expected_available
    abort("expected approved routes #{expected_approved.inspect}, got #{approved.inspect} in #{node.inspect}") unless approved == expected_approved
    expected_approved.each do |route|
      abort("expected subnet routes to include #{route.inspect}, got #{subnet.inspect}") unless subnet.include?(route)
    end
    puts JSON.pretty_generate({name: client_name, available_routes: available, approved_routes: approved, subnet_routes: subnet, node: node})
  ' "${path}" "${client_name}" "${expected_available}" "${expected_approved}"
}

wait_for_node_routes() {
  local expected_available="$1"
  local expected_approved="$2"
  local label="$3"
  local path="${work_dir}/nodes-${label//[^a-zA-Z0-9_-]/-}.json"
  wait_for "${label}" "headscale_cmd -o json nodes list >'${path}' && assert_node_routes_file '${path}' '${expected_available}' '${expected_approved}'" || {
    dump_debug
    return 1
  }
}

assert_node_tags_file() {
  local path="$1"
  local expected="$2"
  local exact="$3"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    client_name = ARGV.fetch(1)
    expected = ARGV.fetch(2).split(",").reject(&:empty?).sort
    exact = ARGV.fetch(3) == "true"
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    node = nodes.find do |candidate|
      [
        candidate["givenName"],
        candidate["given_name"],
        candidate["name"],
        candidate["hostname"],
      ].compact.map(&:to_s).any? { |name| name == client_name || name.include?(client_name) }
    end
    abort("expected one node named #{client_name.inspect}, got #{nodes.inspect}") unless node
    tags = Array(node["tags"] || node["Tags"] || node["forced_tags"] || node["forcedTags"]).map(&:to_s).sort
    unless (!exact && expected.empty?) || tags == expected
      abort("expected tags #{expected.inspect}, got #{tags.inspect} in #{node.inspect}")
    end
    puts JSON.pretty_generate({name: client_name, tags: tags, node: node})
  ' "${path}" "${client_name}" "${expected}" "${exact}"
}

wait_for_node_tags_if_requested() {
  if [[ -z "${expected_tags}" && "${expect_tags_exact}" -eq 0 ]]; then
    return 0
  fi
  local path="${work_dir}/nodes-final-tags.json"
  local exact=false
  if [[ "${expect_tags_exact}" -eq 1 ]]; then
    exact=true
  fi
  wait_for "node tags" "headscale_cmd -o json nodes list >'${path}' && assert_node_tags_file '${path}' '${expected_tags}' '${exact}'" || {
    dump_debug
    return 1
  }
}

assert_no_nodes_file() {
  local path="$1"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    nodes =
      if payload.nil?
        []
      elsif payload.is_a?(Array)
        payload
      else
        payload.fetch("nodes")
      end
    abort("expected rejected web registration to create no nodes, got #{nodes.inspect}") unless nodes.empty?
    puts JSON.pretty_generate({nodes: nodes.length})
  ' "${path}"
}

wait_for_no_nodes_after_expected_registration_failure() {
  local path="${work_dir}/nodes-after-rejected-registration.json"
  wait_for "no nodes after rejected web registration" "headscale_cmd -o json nodes list >'${path}' && assert_no_nodes_file '${path}'" || {
    dump_debug
    return 1
  }
}

assert_node_count_file() {
  local path="$1"
  local expected="$2"
  ruby -rjson -e '
    payload = JSON.parse(File.read(ARGV.fetch(0)))
    expected = Integer(ARGV.fetch(1))
    nodes = payload.nil? ? [] : (payload.is_a?(Array) ? payload : payload.fetch("nodes"))
    abort("expected #{expected} nodes, got #{nodes.length}: #{nodes.inspect}") unless nodes.length == expected
    puts JSON.pretty_generate({nodes: nodes.length})
  ' "${path}" "${expected}"
}

wait_for_expected_node_count_if_requested() {
  [[ -n "${expected_machine_count}" ]] || return 0
  local path="${work_dir}/nodes-expected-count.json"
  wait_for "expected node count ${expected_machine_count}" "headscale_cmd -o json nodes list >'${path}' && assert_node_count_file '${path}' '${expected_machine_count}'" || {
    dump_debug
    return 1
  }
}

approve_routes_if_requested() {
  [[ -n "${advertise_routes}" || -n "${approve_routes}" ]] || return 0
  wait_for_node_routes "${expected_available_routes}" "" "advertised routes"
  [[ -n "${approve_routes}" ]] || return 0

  echo "::group::approve routes"
  local nodes_path="${work_dir}/nodes-before-approve.json"
  headscale_cmd -o json nodes list >"${nodes_path}"
  local node_id
  node_id="$(node_id_for_client "${nodes_path}")"
  headscale_cmd -o json nodes approve-routes --identifier "${node_id}" --routes "${approve_routes}" \
    >"${work_dir}/approved-routes.json"
  echo "::endgroup::"

  wait_for_node_routes "${expected_available_routes}" "${expected_approved_routes}" "approved routes"
}

set_tags_if_requested() {
  [[ -n "${set_tags_after_login}" ]] || return 0
  echo "::group::set forced tags"
  local nodes_path="${work_dir}/nodes-before-tags.json"
  headscale_cmd -o json nodes list >"${nodes_path}"
  local node_id tag_status
  node_id="$(node_id_for_client "${nodes_path}")"
  tag_status=0
  headscale_cmd -o json nodes tag --identifier "${node_id}" --tags "${set_tags_after_login}" \
    >"${work_dir}/set-tags-${node_id}.json" \
    2>"${work_dir}/set-tags-${node_id}.err" ||
    tag_status="$?"
  if ((expect_set_tags_failure)); then
    if ((tag_status == 0)); then
      echo "expected tag update to fail for node ${node_id}" >&2
      exit 1
    fi
    echo "::endgroup::"
    return 0
  fi
  if ((tag_status != 0)); then
    cat "${work_dir}/set-tags-${node_id}.err" >&2 || true
    exit "${tag_status}"
  fi
  echo "::endgroup::"
}

assert_node_lifecycle_file() {
  local path="$1"
  local expected_online="$2"
  local min_last_seen="${3:-0}"
  local lookup_name="${4:-${client_name}}"
  ruby -rjson -rtime -e '
    def last_seen_epoch(value)
      case value
      when String
        Time.parse(value).to_f
      when Hash
        seconds = value["seconds"] || value[:seconds]
        nanos = value["nanos"] || value[:nanos] || 0
        seconds.nil? ? nil : seconds.to_f + nanos.to_f / 1_000_000_000.0
      else
        nil
      end
    end

    payload = JSON.parse(File.read(ARGV.fetch(0)))
    expected_online = ARGV.fetch(1) == "true"
    min_last_seen = ARGV.fetch(2).to_f
    client_name = ARGV.fetch(3)
    nodes = payload.is_a?(Array) ? payload : payload.fetch("nodes")
    node = nodes.find do |candidate|
      [candidate["givenName"], candidate["given_name"], candidate["name"], candidate["hostname"]].compact.map(&:to_s).include?(client_name)
    end
    abort("expected one node named #{client_name.inspect}, got #{nodes.inspect}") unless node
    online = node.key?("online") ? !!node["online"] : false
    abort("expected online=#{expected_online}, got #{online} in #{node.inspect}") unless online == expected_online
    last_seen = last_seen_epoch(node["lastSeen"] || node["last_seen"])
    abort("expected parseable lastSeen/last_seen in #{node.inspect}") unless last_seen
    if min_last_seen.positive? && last_seen <= min_last_seen
      abort("expected lastSeen #{last_seen} to be later than #{min_last_seen} in #{node.inspect}")
    end
    File.write(ARGV.fetch(4), last_seen.to_s)
    puts JSON.pretty_generate({name: client_name, online: online, last_seen_epoch: last_seen, node: node})
  ' "${path}" "${expected_online}" "${min_last_seen}" "${lookup_name}" "${work_dir}/last-seen.epoch"
}

wait_for_node_lifecycle() {
  local expected_online="$1"
  local label="$2"
  local min_last_seen="${3:-0}"
  local lookup_name="${rename_node_after_login:-${client_name}}"
  local path="${work_dir}/nodes-${label//[^a-zA-Z0-9_-]/-}.json"
  wait_for "${label}" "headscale_cmd -o json nodes list >'${path}' && assert_node_lifecycle_file '${path}' '${expected_online}' '${min_last_seen}' '${lookup_name}'" || {
    dump_debug
    return 1
  }
}

stop_tailscaled() {
  echo "::group::stop tailscaled"
  docker exec "${client_name}" sh -ceu 'pids="$(pidof tailscaled 2>/dev/null || true)"; if [ -n "$pids" ]; then kill -TERM $pids; fi'
  echo "::endgroup::"
}

need ruby
prepare_postgres_database
need curl
need docker
case "${target}" in
  rust) need cargo ;;
  headscale-go)
    [[ -n "${HEADSCALE_GO_BIN:-}" ]] || need go
    need openssl
    ;;
esac

write_derp_map
write_policy_file
install_or_build_headscale
if [[ "${target}" == "headscale-go" ]]; then
  generate_headscale_go_tls
fi
start_server_with_retries
assert_derp_stun_if_requested
create_user_and_key
successful_client_names=()
for idx in "${!client_names[@]}"; do
  client_name="${client_names[$idx]}"
  current_client_index="${idx}"
  start_client
  login_client "${authkey_failure_flags[$idx]}"
  if ((authkey_failure_flags[$idx] == 0)); then
    successful_client_names+=("${client_name}")
  fi
done
wait_for_expected_node_count_if_requested
if ((${#successful_client_names[@]} == 0)); then
  echo "${target} rejected auth-key login real-client smoke passed"
  exit 0
fi
client_name="${successful_client_names[0]}"
if ((expect_register_failure)); then
  if ((registration_failed_as_expected == 0)); then
    echo "expected web registration failure path was not observed" >&2
    exit 1
  fi
  wait_for_no_nodes_after_expected_registration_failure
  echo "${target} rejected web registration real-client smoke passed"
  exit 0
fi
reauth_client_if_requested
approve_routes_if_requested
relogin_with_authkey_if_requested
set_tags_if_requested
wait_for_node_tags_if_requested
wait_for_client_netmap
assert_peer_visibility_if_requested
snapshot_derp_map_before_policy_reload_if_requested
reload_policy_if_requested
assert_post_reload_peer_visibility_if_requested
rename_node_if_requested
assert_derp_map_if_requested
assert_derp_map_stable_after_policy_reload_if_requested
assert_derp_ping_if_requested
assert_derp_status_health_clear_if_requested
assert_derp_restart_if_requested
assert_ssh_matrix_if_requested
assert_file_sharing_cap_if_requested
assert_self_capmap_keys_if_requested
assert_debug_ping_if_requested
assert_magic_dns_if_requested
assert_peer_magic_dns_debug_resolve_if_requested
assert_no_magic_dns_if_requested
assert_dns_extra_records_if_requested
assert_dns_debug_resolves_if_requested
assert_dns_resolvers_if_requested
assert_dns_fallback_resolvers_if_requested
assert_dns_routes_if_requested
assert_tailscale_ip_family_if_requested
wait_for_node_lifecycle true "connected online node"
connected_last_seen="$(cat "${work_dir}/last-seen.epoch")"
stop_tailscaled
wait_for_node_lifecycle false "offline node after disconnect grace" "${connected_last_seen}"

echo "${target} online/lastSeen real-client smoke passed"
