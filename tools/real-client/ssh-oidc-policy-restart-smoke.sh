#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_OIDC_SSH_TARGET=rust \
REAL_CLIENT_OIDC_SSH_POLICY_MUTATION_RESTART=true \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-240}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/ssh-oidc-policy-restart-smoke}" \
  tools/real-client/ssh-oidc-check-smoke.sh
