#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

base_domain="${REAL_CLIENT_BASE_DOMAIN:-tail.test}"
records_json="$(ruby -rjson -e '
  base = ARGV.fetch(1)
  records = JSON.parse(File.read(ARGV.fetch(0)))
  records.each do |record|
    record["Name"] = record.fetch("Name").sub("tail.test", base)
    record["Value"] = record.fetch("Value").sub("tail.test", base)
  end
  puts JSON.generate(records)
' "tools/real-client/fixtures/dns-edge-extra-records.json" "${base_domain}")"
split_json="$(ruby -rjson -e 'puts JSON.generate({ARGV.fetch(0) => ["10.0.0.53", "10.0.0.54"]})' \
  "corp.${base_domain}")"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/dns-edge-smoke}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-2}" \
REAL_CLIENT_BASE_DOMAIN="${base_domain}" \
REAL_CLIENT_MAGIC_DNS=true \
REAL_CLIENT_ACCEPT_DNS=true \
REAL_CLIENT_DNS_OVERRIDE_LOCAL=false \
REAL_CLIENT_DNS_NAMESERVERS_JSON="${REAL_CLIENT_DNS_NAMESERVERS_JSON:-[\"1.1.1.1\"]}" \
REAL_CLIENT_DNS_SPLIT_NAMESERVERS_JSON="${REAL_CLIENT_DNS_SPLIT_NAMESERVERS_JSON:-${split_json}}" \
REAL_CLIENT_DNS_EXTRA_RECORDS_JSON="${REAL_CLIENT_DNS_EXTRA_RECORDS_JSON:-${records_json}}" \
REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX="${REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX:-${base_domain}}" \
REAL_CLIENT_EXPECT_DNS_FALLBACK_RESOLVERS="${REAL_CLIENT_EXPECT_DNS_FALLBACK_RESOLVERS:-1.1.1.1}" \
REAL_CLIENT_EXPECT_DNS_ROUTES="${REAL_CLIENT_EXPECT_DNS_ROUTES:-corp.${base_domain}=10.0.0.53|10.0.0.54}" \
REAL_CLIENT_EXPECT_DNS_RESOLVER_OBJECTS="${REAL_CLIENT_EXPECT_DNS_RESOLVER_OBJECTS:-true}" \
REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS="${REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS:-v6.${base_domain}=AAAA:fd7a:115c:a1e0::53,alias.${base_domain}=CNAME:v6.${base_domain}}" \
REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS_EXACT="${REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS_EXACT:-true}" \
REAL_CLIENT_EXPECT_DNS_DEBUG_RESOLVES="${REAL_CLIENT_EXPECT_DNS_DEBUG_RESOLVES:-v6.${base_domain}=ip6:fd7a:115c:a1e0::53,alias.${base_domain}=ip6:fd7a:115c:a1e0::53}" \
REAL_CLIENT_EXPECT_PEER_MAGIC_DNS_RESOLVE="${REAL_CLIENT_EXPECT_PEER_MAGIC_DNS_RESOLVE:-true}" \
  tools/real-client/authkey-smoke.sh
