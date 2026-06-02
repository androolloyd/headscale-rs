#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/dns-live-resolver-common.sh
source tools/real-client/dns-live-resolver-common.sh

image="${TAILSCALE_IMAGE:-tailscale/tailscale:v1.94.1}"
base_domain="${REAL_CLIENT_BASE_DOMAIN:-tail.test}"
search_suffix="${REAL_CLIENT_DNS_LIVE_SEARCH_SUFFIX:-search.live.test}"
search_label="${REAL_CLIENT_DNS_LIVE_SEARCH_LABEL:-lookup}"
fixture_work_root="${REAL_CLIENT_DNS_LIVE_RESOLVER_WORKDIR:-target/real-client/dns-search-live-resolver-fixture}"
case "${fixture_work_root}" in
  /*) fixture_work_dir="${fixture_work_root}" ;;
  *) fixture_work_dir="${repo_root}/${fixture_work_root}" ;;
esac

export REAL_CLIENT_DNS_LIVE_SPLIT_SUFFIX="${search_suffix}"
export REAL_CLIENT_DNS_LIVE_SPLIT_NAME="${REAL_CLIENT_DNS_LIVE_SPLIT_NAME:-${search_label}.${search_suffix}}"
export REAL_CLIENT_DNS_LIVE_SPLIT_IPV4="${REAL_CLIENT_DNS_LIVE_SPLIT_IPV4:-203.0.113.71}"

start_dns_live_split_resolver "${image}" "${fixture_work_dir}" "${base_domain}"
trap stop_dns_live_resolver EXIT

split_json="$(ruby -rjson -e 'puts JSON.generate({ARGV.fetch(0) => [ARGV.fetch(1)]})' \
  "${DNS_LIVE_SPLIT_SUFFIX}" "${DNS_LIVE_SPLIT_RESOLVER_ADDR}")"
search_domains_json="$(ruby -rjson -e 'puts JSON.generate([ARGV.fetch(0)])' "${search_suffix}")"
expected_domains="${base_domain},${search_suffix}"
expected_resolves="${DNS_LIVE_SPLIT_RESOLVE_EXPECTATION}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/dns-search-live-resolver-smoke}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-1}" \
REAL_CLIENT_BASE_DOMAIN="${base_domain}" \
REAL_CLIENT_MAGIC_DNS=true \
REAL_CLIENT_ACCEPT_DNS=true \
REAL_CLIENT_DNS_OVERRIDE_LOCAL=false \
REAL_CLIENT_DNS_SPLIT_NAMESERVERS_JSON="${REAL_CLIENT_DNS_SPLIT_NAMESERVERS_JSON:-${split_json}}" \
REAL_CLIENT_DNS_SEARCH_DOMAINS_JSON="${REAL_CLIENT_DNS_SEARCH_DOMAINS_JSON:-${search_domains_json}}" \
REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX="${REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX:-${base_domain}}" \
REAL_CLIENT_EXPECT_DNS_DOMAINS="${REAL_CLIENT_EXPECT_DNS_DOMAINS:-${expected_domains}}" \
REAL_CLIENT_EXPECT_DNS_ROUTES="${REAL_CLIENT_EXPECT_DNS_ROUTES:-${DNS_LIVE_SPLIT_ROUTE_EXPECTATION}}" \
REAL_CLIENT_EXPECT_DNS_RESOLVER_OBJECTS="${REAL_CLIENT_EXPECT_DNS_RESOLVER_OBJECTS:-true}" \
REAL_CLIENT_EXPECT_DNS_DEBUG_RESOLVES="${REAL_CLIENT_EXPECT_DNS_DEBUG_RESOLVES:-${expected_resolves}}" \
  tools/real-client/authkey-smoke.sh
