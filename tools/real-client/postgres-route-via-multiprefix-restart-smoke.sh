#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-route-via-multiprefix-restart-smoke}" \
REAL_CLIENT_RESTART_TARGET=rust \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_RESTART_ROUTE_VIA_MULTIPREFIX=true \
REAL_CLIENT_RESTART_ROUTE="${REAL_CLIENT_RESTART_ROUTE:-10.77.0.0/24}" \
REAL_CLIENT_RESTART_ROUTE_B="${REAL_CLIENT_RESTART_ROUTE_B:-10.88.0.0/24}" \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-280}" \
  tools/real-client/restart-persistence-common.sh
