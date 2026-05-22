#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

exit_routes="${REAL_CLIENT_EXIT_ROUTES:-0.0.0.0/0,::/0}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/route-exit-node-headscale-go-smoke}" \
REAL_CLIENT_ADVERTISE_EXIT_NODE="${REAL_CLIENT_ADVERTISE_EXIT_NODE:-true}" \
REAL_CLIENT_EXPECT_AVAILABLE_ROUTES="${REAL_CLIENT_EXPECT_AVAILABLE_ROUTES:-${exit_routes}}" \
REAL_CLIENT_APPROVE_ROUTES="${REAL_CLIENT_APPROVE_ROUTES:-${exit_routes}}" \
REAL_CLIENT_EXPECT_APPROVED_ROUTES="${REAL_CLIENT_EXPECT_APPROVED_ROUTES:-${exit_routes}}" \
  tools/real-client/authkey-headscale-go-smoke.sh
