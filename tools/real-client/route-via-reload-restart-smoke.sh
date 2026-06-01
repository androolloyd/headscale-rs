#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/route-via-reload-restart-smoke}" \
REAL_CLIENT_RESTART_TARGET=rust \
REAL_CLIENT_RESTART_ROUTE_VIA_RELOAD=true \
REAL_CLIENT_RESTART_ROUTE="${REAL_CLIENT_RESTART_ROUTE:-10.77.0.0/24}" \
  tools/real-client/restart-persistence-common.sh
