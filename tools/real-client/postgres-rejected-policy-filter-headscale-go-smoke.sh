#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

visible_policy='{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}'
rejected_policy='{"acls":[],"tests":[{"src":"alice@","accept":["bob@:22"]}]}'

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-v0.29.5}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-rejected-policy-filter-headscale-go-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_CLIENT_COUNT=2 \
REAL_CLIENT_CLIENT_USERS=alice,bob \
REAL_CLIENT_POLICY_JSON="${visible_policy}" \
REAL_CLIENT_REJECT_POLICY_JSON="${rejected_policy}" \
REAL_CLIENT_EXPECT_PEER_COUNTS=1,1 \
REAL_CLIENT_RESTART_AFTER_ASSERTIONS=true \
REAL_CLIENT_EXPECT_MACHINE_COUNT=2 \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-300}" \
  tools/real-client/online-lastseen-common.sh
