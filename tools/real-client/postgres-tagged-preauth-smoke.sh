#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

tags="${REAL_CLIENT_PREAUTH_TAGS:-tag:server}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-tagged-preauth-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=rust \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_PREAUTH_TAGS="${tags}" \
REAL_CLIENT_EXPECT_TAGS="${REAL_CLIENT_EXPECT_TAGS:-${tags}}" \
  tools/real-client/online-lastseen-common.sh
