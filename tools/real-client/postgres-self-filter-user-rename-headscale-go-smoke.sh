#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

self_policy='{"groups":{"group:a":["u1@","u3@"]},"acls":[{"action":"accept","src":["group:a"],"dst":["autogroup:self:*"]}]}'

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-v0.29.5}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-self-filter-user-rename-headscale-go-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_CLIENT_COUNT=2 \
REAL_CLIENT_CLIENT_USERS=u1,x3 \
REAL_CLIENT_POLICY_JSON="${self_policy}" \
REAL_CLIENT_SELF_FILTER_RENAME_USER=x3:u3 \
REAL_CLIENT_RESTART_AFTER_ASSERTIONS=true \
REAL_CLIENT_EXPECT_MACHINE_COUNT=2 \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-180}" \
  tools/real-client/online-lastseen-common.sh
