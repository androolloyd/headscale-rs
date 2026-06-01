#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-prefix-family-v4-to-dual-backfill-headscale-go-smoke}" \
REAL_CLIENT_PREFIX_MIGRATION_TARGET=headscale-go \
REAL_CLIENT_PREFIX_MIGRATION_CASE=v4-to-dual \
REAL_CLIENT_DATABASE_BACKEND=postgres \
  tools/real-client/prefix-family-v4-to-dual-backfill-common.sh
