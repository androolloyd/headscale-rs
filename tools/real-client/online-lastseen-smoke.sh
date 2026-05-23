#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/online-lastseen-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=rust \
  tools/real-client/online-lastseen-common.sh
