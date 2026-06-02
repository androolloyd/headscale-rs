#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/authkey-relogin-different-user-headscale-go-smoke}" \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-180}" \
REAL_CLIENT_TAILSCALE_UP_TIMEOUT="${REAL_CLIENT_TAILSCALE_UP_TIMEOUT:-45s}" \
REAL_CLIENT_AUTHKEY_RELOGIN_DIFFERENT_USER=true \
REAL_CLIENT_EXPECT_MACHINE_COUNT="${REAL_CLIENT_EXPECT_MACHINE_COUNT:-1}" \
  tools/real-client/authkey-headscale-go-smoke.sh
