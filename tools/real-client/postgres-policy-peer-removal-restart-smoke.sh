#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

visible_policy='{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}'
hidden_policy='{"acls":[{"action":"accept","src":["alice@"],"dst":["alice@:*"]},{"action":"accept","src":["bob@"],"dst":["bob@:*"]}]}'

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-policy-peer-removal-restart-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=rust \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_CLIENT_COUNT=2 \
REAL_CLIENT_CLIENT_USERS=alice,bob \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_POLICY_JSON:-${visible_policy}}" \
REAL_CLIENT_RELOAD_POLICY_JSON="${REAL_CLIENT_RELOAD_POLICY_JSON:-${hidden_policy}}" \
REAL_CLIENT_EXPECT_PEER_COUNTS=1,1 \
REAL_CLIENT_EXPECT_PEER_COUNTS_AFTER_POLICY_RELOAD=0,0 \
REAL_CLIENT_EXPECT_POLICY_PEER_REMOVAL=true \
REAL_CLIENT_RESTART_AFTER_ASSERTIONS=true \
REAL_CLIENT_EXPECT_MACHINE_COUNT=2 \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-300}" \
  tools/real-client/online-lastseen-common.sh
