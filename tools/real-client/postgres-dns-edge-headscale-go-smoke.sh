#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

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

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-dns-edge-headscale-go-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
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
REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS="${REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS:-v6.${base_domain}=AAAA:fd7a:115c:a1e0::53,alias.${base_domain}=CNAME:v6.${base_domain}}" \
REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS_EXACT="${REAL_CLIENT_EXPECT_DNS_EXTRA_RECORDS_EXACT:-true}" \
  tools/real-client/online-lastseen-common.sh
