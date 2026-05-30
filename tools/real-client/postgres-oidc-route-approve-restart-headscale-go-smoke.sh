#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

route="${REAL_CLIENT_ROUTE:-10.77.0.0/24}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-oidc-route-approve-restart-headscale-go-smoke}" \
REAL_CLIENT_OIDC_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_OIDC_RESTART=true \
REAL_CLIENT_OIDC_ADVERTISE_ROUTES="${REAL_CLIENT_OIDC_ADVERTISE_ROUTES:-${route}}" \
REAL_CLIENT_OIDC_APPROVE_ROUTES="${REAL_CLIENT_OIDC_APPROVE_ROUTES:-${route}}" \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-240}" \
  tools/real-client/oidc-common.sh
