#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

base_domain="${REAL_CLIENT_BASE_DOMAIN:-tail.test}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-magicdns-ipv6-only-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=rust \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_BASE_DOMAIN="${base_domain}" \
REAL_CLIENT_MAGIC_DNS=true \
REAL_CLIENT_ACCEPT_DNS=true \
REAL_CLIENT_PREFIX_V4="" \
REAL_CLIENT_PREFIX_V6="${REAL_CLIENT_PREFIX_V6:-fd7a:115c:a1e0::/48}" \
REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX="${REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX:-${base_domain}}" \
REAL_CLIENT_EXPECT_TAILSCALE_IP_FAMILIES=ipv6-only \
  tools/real-client/online-lastseen-common.sh
