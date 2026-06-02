#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/authkey-relogin-different-user-smoke}" \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-180}" \
REAL_CLIENT_TAILSCALE_UP_TIMEOUT="${REAL_CLIENT_TAILSCALE_UP_TIMEOUT:-45s}" \
REAL_CLIENT_AUTHKEY_RELOGIN_DIFFERENT_USER=true \
REAL_CLIENT_EXPECT_MACHINE_COUNT="${REAL_CLIENT_EXPECT_MACHINE_COUNT:-1}" \
  tools/real-client/authkey-smoke.sh
