#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

route="${REAL_CLIENT_ROUTE:-10.77.0.0/24}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/route-approve-smoke}" \
REAL_CLIENT_ADVERTISE_ROUTES="${REAL_CLIENT_ADVERTISE_ROUTES:-${route}}" \
REAL_CLIENT_APPROVE_ROUTES="${REAL_CLIENT_APPROVE_ROUTES:-${route}}" \
  tools/real-client/authkey-smoke.sh
