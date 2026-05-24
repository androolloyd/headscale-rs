#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-4483fd0cad38717913e7509fc50f9d48c691b02b}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/route-via-multiprefix-restart-headscale-go-smoke}" \
REAL_CLIENT_RESTART_TARGET=headscale-go \
REAL_CLIENT_RESTART_ROUTE_VIA_MULTIPREFIX=true \
REAL_CLIENT_RESTART_ROUTE="${REAL_CLIENT_RESTART_ROUTE:-10.77.0.0/24}" \
REAL_CLIENT_RESTART_ROUTE_B="${REAL_CLIENT_RESTART_ROUTE_B:-10.88.0.0/24}" \
  tools/real-client/restart-persistence-common.sh
