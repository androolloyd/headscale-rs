#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_ROUTE_EDGE_AUDIT_TARGET=headscale-go \
  tools/real-client/route-edge-current-upstream-audit-smoke.sh
