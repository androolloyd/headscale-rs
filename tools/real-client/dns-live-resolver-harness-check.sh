#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/dns-live-resolver-common.sh
source tools/real-client/dns-live-resolver-common.sh

assert_equal() {
  local label="$1"
  local expected="$2"
  local actual="$3"

  if [[ "${actual}" != "${expected}" ]]; then
    echo "${label}: expected ${expected}, got ${actual}" >&2
    exit 1
  fi
}

assert_json_equal() {
  local label="$1"
  local expected="$2"
  local actual="$3"

  ruby -rjson -e '
    label = ARGV.fetch(0)
    expected = JSON.parse(ARGV.fetch(1))
    actual = JSON.parse(ARGV.fetch(2))
    abort("#{label}: expected #{expected.inspect}, got #{actual.inspect}") unless actual == expected
  ' "${label}" "${expected}" "${actual}"
}

search_resolver="host.docker.internal:53001"
dns_live_resolver_plan_search_row \
  "tail.test." \
  "search.live.test." \
  "${search_resolver}" \
  "lookup.search.live.test=ip4:203.0.113.71"

assert_json_equal \
  "search split nameserver JSON" \
  '{"search.live.test":["host.docker.internal:53001"]}' \
  "${DNS_LIVE_SEARCH_SPLIT_NAMESERVERS_JSON}"
assert_json_equal \
  "search domains JSON" \
  '["search.live.test"]' \
  "${DNS_LIVE_SEARCH_DOMAINS_JSON}"
assert_equal \
  "search DNS domains expectation" \
  "tail.test,search.live.test" \
  "${DNS_LIVE_SEARCH_EXPECT_DNS_DOMAINS}"
assert_equal \
  "search DNS route expectation" \
  "search.live.test=${search_resolver}" \
  "${DNS_LIVE_SEARCH_EXPECT_DNS_ROUTES}"
assert_equal \
  "search DNS resolve expectation" \
  "lookup.search.live.test=ip4:203.0.113.71" \
  "${DNS_LIVE_SEARCH_EXPECT_DNS_DEBUG_RESOLVES}"

failure_resolver="192.0.2.10:5353"
answer_resolver="192.0.2.11:5354"
dns_live_resolver_plan_multi_fallback_row \
  "fallback.tail.test." \
  "${failure_resolver}" \
  "${answer_resolver}" \
  "answer.fallback.tail.test=ip4:203.0.113.72"

assert_json_equal \
  "multi fallback split nameserver JSON" \
  '{"fallback.tail.test":["192.0.2.10:5353","192.0.2.11:5354"]}' \
  "${DNS_LIVE_MULTI_SPLIT_NAMESERVERS_JSON}"
assert_equal \
  "multi fallback DNS route expectation" \
  "fallback.tail.test=${failure_resolver}|${answer_resolver}" \
  "${DNS_LIVE_MULTI_EXPECT_DNS_ROUTES}"
assert_equal \
  "multi fallback DNS resolve expectation" \
  "answer.fallback.tail.test=ip4:203.0.113.72" \
  "${DNS_LIVE_MULTI_EXPECT_DNS_DEBUG_RESOLVES}"

if dns_live_resolver_plan_multi_fallback_row \
  "fallback.tail.test" \
  "${failure_resolver}" \
  "${failure_resolver}" \
  "answer.fallback.tail.test=ip4:203.0.113.72" \
  2>/dev/null; then
  echo "multi fallback helper accepted identical failure and answer resolvers" >&2
  exit 1
fi

echo "dns-live-resolver harness check passed"
