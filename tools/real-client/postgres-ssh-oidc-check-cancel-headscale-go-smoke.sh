#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_OIDC_SSH_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_OIDC_SSH_CHECK_RESULT=cancel \
REAL_CLIENT_OIDC_SSH_CANCEL_TIMEOUT_SECS="${REAL_CLIENT_OIDC_SSH_CANCEL_TIMEOUT_SECS:-15}" \
REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS="${REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS:-${REAL_CLIENT_OIDC_SSH_CANCEL_TIMEOUT_SECS:-15}}" \
REAL_CLIENT_OIDC_SSH_DENY_STATUS="${REAL_CLIENT_OIDC_SSH_DENY_STATUS:-143}" \
REAL_CLIENT_OIDC_SSH_DENY_STDERR_FIRST_LINE="${REAL_CLIENT_OIDC_SSH_DENY_STDERR_FIRST_LINE:-# Headscale SSH requires an additional check.}" \
REAL_CLIENT_OIDC_SSH_DENY_STDERR_REGEX="${REAL_CLIENT_OIDC_SSH_DENY_STDERR_REGEX:-Headscale SSH requires an additional check}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-ssh-oidc-check-cancel-headscale-go-smoke}" \
  tools/real-client/ssh-oidc-check-smoke.sh
