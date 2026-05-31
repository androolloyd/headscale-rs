#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

initial_tags="${REAL_CLIENT_PREAUTH_TAGS:-tag:server}"
updated_tags="${REAL_CLIENT_SET_TAGS_AFTER_LOGIN:-tag:prod}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-tag-update-headscale-go-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_PREAUTH_TAGS="${initial_tags}" \
REAL_CLIENT_SET_TAGS_AFTER_LOGIN="${updated_tags}" \
REAL_CLIENT_EXPECT_TAGS="${REAL_CLIENT_EXPECT_TAGS:-${updated_tags}}" \
  tools/real-client/online-lastseen-common.sh
