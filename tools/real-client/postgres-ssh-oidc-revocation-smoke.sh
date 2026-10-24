#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_OIDC_SSH_TARGET=rust \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_OIDC_SSH_CHECK_PERIOD_CACHE=true \
REAL_CLIENT_OIDC_SSH_REVOKE_AFTER_CACHE=true \
REAL_CLIENT_OIDC_SSH_CALLBACK_REPLAY_AFTER_CHECK=true \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-ssh-oidc-revocation-smoke}" \
  tools/real-client/ssh-oidc-check-smoke.sh
