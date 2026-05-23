#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/prefix-family-dual-stack-headscale-go-smoke}" \
REAL_CLIENT_PREFIX_V4="${REAL_CLIENT_PREFIX_V4:-100.64.0.0/10}" \
REAL_CLIENT_PREFIX_V6="${REAL_CLIENT_PREFIX_V6:-fd7a:115c:a1e0::/48}" \
REAL_CLIENT_EXPECT_TAILSCALE_IP_FAMILIES="${REAL_CLIENT_EXPECT_TAILSCALE_IP_FAMILIES:-dual-stack}" \
  tools/real-client/authkey-headscale-go-smoke.sh
