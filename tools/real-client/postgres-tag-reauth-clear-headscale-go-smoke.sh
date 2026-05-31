#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

initial_tags="${REAL_CLIENT_PREAUTH_TAGS:-tag:server}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-tag-reauth-clear-headscale-go-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_LOGIN_MODE=web \
REAL_CLIENT_PREAUTH_TAGS="${initial_tags}" \
REAL_CLIENT_REAUTH_AFTER_LOGIN=true \
REAL_CLIENT_EXPECT_TAGS_EXACT=true \
REAL_CLIENT_EXPECT_TAGS="${REAL_CLIENT_EXPECT_TAGS:-}" \
  tools/real-client/online-lastseen-common.sh
