#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/magicdns-ipv6-only-headscale-go-smoke}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-2}" \
REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX="${REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX:-tail.test}" \
REAL_CLIENT_EXPECT_TAILSCALE_IP_FAMILIES=ipv6-only \
REAL_CLIENT_ACCEPT_DNS=true \
REAL_CLIENT_EXPECT_PEER_MAGIC_DNS_RESOLVE="${REAL_CLIENT_EXPECT_PEER_MAGIC_DNS_RESOLVE:-true}" \
REAL_CLIENT_PREFIX_V4="" \
REAL_CLIENT_PREFIX_V6="${REAL_CLIENT_PREFIX_V6:-fd7a:115c:a1e0::/48}" \
  tools/real-client/authkey-headscale-go-smoke.sh
