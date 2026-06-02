#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/test-auth-key-logout-and-relogin-same-user-smoke}" \
  tools/real-client/authkey-relogin-same-user-smoke.sh
