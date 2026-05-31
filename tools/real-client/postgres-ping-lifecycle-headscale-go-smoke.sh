#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

# The pinned headscale-go v0.28.0 matrix predates /debug/ping and the
# executable PingRequest callback lifecycle, so this row tracks audited HEAD.
HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-ping-lifecycle-headscale-go-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_EXPECT_DEBUG_PING="${REAL_CLIENT_EXPECT_DEBUG_PING:-true}" \
  tools/real-client/online-lastseen-common.sh
