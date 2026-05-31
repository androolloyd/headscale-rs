#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

exit_routes="${REAL_CLIENT_EXIT_ROUTES:-0.0.0.0/0,::/0}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-route-exit-node-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=rust \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_ADVERTISE_EXIT_NODE="${REAL_CLIENT_ADVERTISE_EXIT_NODE:-true}" \
REAL_CLIENT_EXPECT_AVAILABLE_ROUTES="${REAL_CLIENT_EXPECT_AVAILABLE_ROUTES:-${exit_routes}}" \
REAL_CLIENT_APPROVE_ROUTES="${REAL_CLIENT_APPROVE_ROUTES:-${exit_routes}}" \
REAL_CLIENT_EXPECT_APPROVED_ROUTES="${REAL_CLIENT_EXPECT_APPROVED_ROUTES:-${exit_routes}}" \
  tools/real-client/online-lastseen-common.sh
