#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/web-register-smoke}" \
REAL_CLIENT_LOGIN_MODE=web \
  tools/real-client/authkey-smoke.sh
