#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/prefix-family-dual-stack-to-ipv4-only-backfill-smoke}" \
REAL_CLIENT_PREFIX_MIGRATION_TARGET=rust \
REAL_CLIENT_PREFIX_MIGRATION_CASE=dual-to-v4 \
  tools/real-client/prefix-family-v4-to-dual-backfill-common.sh
