#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

base_domain="${REAL_CLIENT_BASE_DOMAIN:-tail.test}"
record_name="${REAL_CLIENT_EXTRA_RECORD_NAME:-app.${base_domain}}"
record_value="${REAL_CLIENT_EXTRA_RECORD_VALUE:-100.64.0.50}"
record_type="${REAL_CLIENT_EXTRA_RECORD_TYPE:-A}"
case "${record_type}" in
  A) record_network=ip4 ;;
  AAAA) record_network=ip6 ;;
  *) record_network="" ;;
esac
default_dns_debug_resolves=""
if [[ -n "${record_network}" ]]; then
  default_dns_debug_resolves="${record_name}=${record_network}:${record_value}"
fi
default_dns_extra_records_json="$(
  ruby -rjson -e 'puts [{"Name" => ARGV[0], "Type" => ARGV[1], "Value" => ARGV[2]}].to_json' \
    "${record_name}" "${record_type}" "${record_value}"
)"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/extra-records-headscale-go-smoke}" \
REAL_CLIENT_BASE_DOMAIN="${base_domain}" \
REAL_CLIENT_MAGIC_DNS=true \
REAL_CLIENT_ACCEPT_DNS=true \
REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX="${base_domain}" \
REAL_CLIENT_DNS_EXTRA_RECORDS_JSON="${REAL_CLIENT_DNS_EXTRA_RECORDS_JSON:-${default_dns_extra_records_json}}" \
REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS="${REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS:-${record_name}=${record_value}}" \
REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS_EXACT="${REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS_EXACT:-true}" \
REAL_CLIENT_EXPECT_DNS_DEBUG_RESOLVES="${REAL_CLIENT_EXPECT_DNS_DEBUG_RESOLVES:-${default_dns_debug_resolves}}" \
  tools/real-client/authkey-headscale-go-smoke.sh
