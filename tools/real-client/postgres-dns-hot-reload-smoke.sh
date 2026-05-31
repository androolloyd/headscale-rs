#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-dns-hot-reload-smoke}" \
REAL_CLIENT_DATABASE_BACKEND=postgres \
  tools/real-client/dns-hot-reload-smoke.sh
