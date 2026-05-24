#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/web-register-restart-headscale-go-smoke}" \
REAL_CLIENT_RESTART_TARGET=headscale-go \
REAL_CLIENT_RESTART_WEB_REGISTER=true \
  tools/real-client/restart-persistence-common.sh
