#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/restart-persistence-smoke}" \
REAL_CLIENT_RESTART_TARGET=rust \
  tools/real-client/restart-persistence-common.sh
