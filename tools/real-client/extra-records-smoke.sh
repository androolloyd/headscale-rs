#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

base_domain="${REAL_CLIENT_BASE_DOMAIN:-tail.test}"
record_name="${REAL_CLIENT_EXTRA_RECORD_NAME:-app.${base_domain}}"
record_value="${REAL_CLIENT_EXTRA_RECORD_VALUE:-100.64.0.50}"
record_type="${REAL_CLIENT_EXTRA_RECORD_TYPE:-A}"
default_dns_extra_records_json="$(
  ruby -rjson -e 'puts [{"Name" => ARGV[0], "Type" => ARGV[1], "Value" => ARGV[2]}].to_json' \
    "${record_name}" "${record_type}" "${record_value}"
)"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/extra-records-smoke}" \
REAL_CLIENT_BASE_DOMAIN="${base_domain}" \
REAL_CLIENT_MAGIC_DNS=true \
REAL_CLIENT_ACCEPT_DNS=true \
REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX="${base_domain}" \
REAL_CLIENT_DNS_EXTRA_RECORDS_JSON="${REAL_CLIENT_DNS_EXTRA_RECORDS_JSON:-${default_dns_extra_records_json}}" \
REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS="${REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS:-${record_name}=${record_value}}" \
REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS_EXACT="${REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS_EXACT:-true}" \
  tools/real-client/authkey-smoke.sh
