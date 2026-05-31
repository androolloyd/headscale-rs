#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-prefix-family-ipv4-only-headscale-go-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_PREFIX_V4="${REAL_CLIENT_PREFIX_V4:-100.64.0.0/10}" \
REAL_CLIENT_PREFIX_V6="" \
REAL_CLIENT_EXPECT_TAILSCALE_IP_FAMILIES="${REAL_CLIENT_EXPECT_TAILSCALE_IP_FAMILIES:-ipv4-only}" \
  tools/real-client/online-lastseen-common.sh
