#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}" \
REAL_CLIENT_RESTART_TARGET=headscale-go \
REAL_CLIENT_RESTART_ROUTE_HEALTH=true \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/route-health-restart-headscale-go-smoke}" \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-240}" \
REAL_CLIENT_RESTART_ROUTE="${REAL_CLIENT_RESTART_ROUTE:-10.89.0.0/24}" \
REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS="${REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS:-2}" \
REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS="${REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS:-1}" \
  tools/real-client/restart-persistence-common.sh
