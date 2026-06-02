#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/dns-live-resolver-common.sh
source tools/real-client/dns-live-resolver-common.sh

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
base_domain="${REAL_CLIENT_BASE_DOMAIN:-tail.test}"
split_suffix="${REAL_CLIENT_DNS_LIVE_MULTI_SUFFIX:-fallback.${base_domain}}"
record_name="${REAL_CLIENT_DNS_LIVE_MULTI_NAME:-answer.${split_suffix}}"
fixture_work_root="${REAL_CLIENT_DNS_LIVE_RESOLVER_WORKDIR:-target/real-client/dns-multi-resolver-fallback-fixture}"
case "${fixture_work_root}" in
  /*) fixture_work_dir="${fixture_work_root}" ;;
  *) fixture_work_dir="${repo_root}/${fixture_work_root}" ;;
esac

export REAL_CLIENT_DNS_LIVE_SPLIT_SUFFIX="${split_suffix}"
export REAL_CLIENT_DNS_LIVE_SPLIT_NAME="${record_name}"
export REAL_CLIENT_DNS_LIVE_SPLIT_IPV4="${REAL_CLIENT_DNS_LIVE_SPLIT_IPV4:-203.0.113.72}"

start_dns_live_failure_resolver "${image}" "${fixture_work_dir}/failure" "${record_name}"
failure_resolver_addr="${DNS_LIVE_FAILURE_RESOLVER_ADDR}"
start_dns_live_split_resolver "${image}" "${fixture_work_dir}/answer" "${base_domain}"
trap stop_dns_live_resolver EXIT

split_json="$(ruby -rjson -e 'puts JSON.generate({ARGV.fetch(0) => [ARGV.fetch(1), ARGV.fetch(2)]})' \
  "${DNS_LIVE_SPLIT_SUFFIX}" "${failure_resolver_addr}" "${DNS_LIVE_SPLIT_RESOLVER_ADDR}")"
expected_route="${DNS_LIVE_SPLIT_SUFFIX}=${failure_resolver_addr}|${DNS_LIVE_SPLIT_RESOLVER_ADDR}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/dns-multi-resolver-fallback-smoke}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-1}" \
REAL_CLIENT_BASE_DOMAIN="${base_domain}" \
REAL_CLIENT_MAGIC_DNS=true \
REAL_CLIENT_ACCEPT_DNS=true \
REAL_CLIENT_DNS_OVERRIDE_LOCAL=false \
REAL_CLIENT_DNS_SPLIT_NAMESERVERS_JSON="${REAL_CLIENT_DNS_SPLIT_NAMESERVERS_JSON:-${split_json}}" \
REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX="${REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX:-${base_domain}}" \
REAL_CLIENT_EXPECT_DNS_ROUTES="${REAL_CLIENT_EXPECT_DNS_ROUTES:-${expected_route}}" \
REAL_CLIENT_EXPECT_DNS_RESOLVER_OBJECTS="${REAL_CLIENT_EXPECT_DNS_RESOLVER_OBJECTS:-true}" \
REAL_CLIENT_EXPECT_DNS_DEBUG_RESOLVES="${REAL_CLIENT_EXPECT_DNS_DEBUG_RESOLVES:-${DNS_LIVE_SPLIT_RESOLVE_EXPECTATION}}" \
  tools/real-client/authkey-smoke.sh
