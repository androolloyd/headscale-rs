#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/prefix-family-dual-stack-smoke}" \
HSRS_HARNESS_IP_FAMILIES="${HSRS_HARNESS_IP_FAMILIES:-dual-stack}" \
REAL_CLIENT_EXPECT_TAILSCALE_IP_FAMILIES="${REAL_CLIENT_EXPECT_TAILSCALE_IP_FAMILIES:-dual-stack}" \
  tools/real-client/authkey-smoke.sh
