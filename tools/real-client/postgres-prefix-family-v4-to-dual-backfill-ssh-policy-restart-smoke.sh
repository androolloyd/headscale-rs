#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-prefix-family-v4-to-dual-backfill-ssh-policy-restart-smoke}" \
REAL_CLIENT_PREFIX_MIGRATION_TARGET=rust \
REAL_CLIENT_PREFIX_MIGRATION_CASE=v4-to-dual \
REAL_CLIENT_PREFIX_MIGRATION_EDGE=ssh-policy-restart \
REAL_CLIENT_DATABASE_BACKEND=postgres \
  tools/real-client/prefix-family-v4-to-dual-backfill-common.sh
