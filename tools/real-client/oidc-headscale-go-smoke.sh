#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/oidc-headscale-go-smoke}" \
REAL_CLIENT_OIDC_TARGET=headscale-go \
  tools/real-client/oidc-common.sh
