#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-v0.29.5}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-invalid-fqdn-peer-restart-headscale-go-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_CLIENT_COUNT=2 \
REAL_CLIENT_EXPECT_PEER_COUNT=1 \
REAL_CLIENT_CORRUPT_PEER_NAME_AFTER_LOGIN=true \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-300}" \
  tools/real-client/online-lastseen-common.sh
