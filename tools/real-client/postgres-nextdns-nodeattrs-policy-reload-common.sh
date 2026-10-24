#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

target="${REAL_CLIENT_ONLINE_LASTSEEN_TARGET:?set rust or headscale-go}"
policy_json="$(ruby -rjson -e 'puts JSON.generate({acls: [{action: "accept", src: ["*"], dst: ["*:*"]}], nodeAttrs: [{target: ["alice@"], attr: ["nextdns:base", "nextdns:no-device-info"]}]})')"
policy_unrelated_reload_json="$(ruby -rjson -e 'puts JSON.generate({acls: [{action: "accept", src: ["alice@"], dst: ["*:*"]}], nodeAttrs: [{target: ["alice@"], attr: ["nextdns:base", "nextdns:no-device-info"]}]})')"
policy_reload_json="$(ruby -rjson -e 'puts JSON.generate({acls: [{action: "accept", src: ["alice@"], dst: ["*:*"]}], nodeAttrs: [{target: ["alice@"], attr: ["nextdns:profile", "nextdns:no-device-info"]}]})')"

REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_CLIENT_COUNT=1 \
REAL_CLIENT_POLICY_JSON="${policy_json}" \
REAL_CLIENT_RELOAD_POLICY_UNRELATED_JSON="${policy_unrelated_reload_json}" \
REAL_CLIENT_RELOAD_POLICY_JSON="${policy_reload_json}" \
REAL_CLIENT_ASSERT_MAPRESPONSE_DNS_POLICY_RELOAD=true \
REAL_CLIENT_EXPECT_PEER_COUNT=0 \
REAL_CLIENT_EXPECT_PEER_COUNT_AFTER_POLICY_RELOAD=0 \
REAL_CLIENT_DNS_OVERRIDE_LOCAL=true \
REAL_CLIENT_ACCEPT_DNS=true \
REAL_CLIENT_DNS_NAMESERVERS_JSON='["https://dns.nextdns.io/base"]' \
REAL_CLIENT_EXPECT_DNS_RESOLVERS_BEFORE_POLICY_RELOAD='https://dns.nextdns.io/base' \
REAL_CLIENT_EXPECT_DNS_RESOLVERS='https://dns.nextdns.io/profile' \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-180}" \
REAL_CLIENT_TAILSCALE_UP_TIMEOUT="${REAL_CLIENT_TAILSCALE_UP_TIMEOUT:-30s}" \
  tools/real-client/online-lastseen-common.sh
