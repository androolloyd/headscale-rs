#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/taildrop-capmap-smoke}" \
REAL_CLIENT_TAILDROP_ENABLED=false \
REAL_CLIENT_EXPECT_FILE_SHARING_CAP=false \
REAL_CLIENT_EXPECT_MACHINE_COUNT="${REAL_CLIENT_EXPECT_MACHINE_COUNT:-1}" \
  tools/real-client/authkey-smoke.sh
