#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_OIDC_SSH_TARGET=rust \
REAL_CLIENT_OIDC_SSH_CHECK_RESULT=wrong-user \
REAL_CLIENT_REGISTER_CACHE_EXPIRATION="${REAL_CLIENT_REGISTER_CACHE_EXPIRATION:-10s}" \
REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS="${REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS:-45}" \
REAL_CLIENT_OIDC_SSH_DENY_STATUS="${REAL_CLIENT_OIDC_SSH_DENY_STATUS:-255}" \
REAL_CLIENT_OIDC_SSH_DENY_STDERR_FIRST_LINE="${REAL_CLIENT_OIDC_SSH_DENY_STDERR_FIRST_LINE:-# Headscale SSH requires an additional check.}" \
REAL_CLIENT_OIDC_SSH_DENY_STDERR_REGEX="${REAL_CLIENT_OIDC_SSH_DENY_STDERR_REGEX:-tailscale: access denied|Permission denied \(tailscale\)}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/ssh-oidc-check-wrong-user-smoke}" \
  tools/real-client/ssh-oidc-check-smoke.sh
