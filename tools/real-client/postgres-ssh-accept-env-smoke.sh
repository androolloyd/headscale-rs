#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

policy_json="$(cat tools/real-client/fixtures/ssh-accept-env.hujson)"
preauth_tags_by_client="${REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT:-}"
if [[ -z "${preauth_tags_by_client}" ]]; then
  preauth_tags_by_client="-;tag:server"
fi
accept_env_lang="${REAL_CLIENT_ACCEPT_ENV_LANG:-C.UTF-8}"
accept_env_lc="${REAL_CLIENT_ACCEPT_ENV_LC:-real-client-accept-env}"
accept_env_command='printf "%s:%s\n" "$LANG" "$LC_ACCEPT_ENV_SMOKE"'
accept_env_stdout="${accept_env_lang}:${accept_env_lc}"
accept_env_send_env="LANG=${accept_env_lang},LC_ACCEPT_ENV_SMOKE=${accept_env_lc}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-ssh-accept-env-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=rust \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-2}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-alice,alice}" \
REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT="${preauth_tags_by_client}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_POLICY_JSON:-${policy_json}}" \
REAL_CLIENT_EXPECT_PEER_COUNT="${REAL_CLIENT_EXPECT_PEER_COUNT:-1}" \
REAL_CLIENT_ENABLE_TAILSCALE_SSH=true \
REAL_CLIENT_INSTALL_OPENSSH=true \
REAL_CLIENT_SSH_USER="${REAL_CLIENT_SSH_USER:-root}" \
REAL_CLIENT_EXPECT_SSH_MATRIX="${REAL_CLIENT_EXPECT_SSH_MATRIX:-1:2:allow}" \
REAL_CLIENT_SSH_COMMAND="${REAL_CLIENT_SSH_COMMAND:-${accept_env_command}}" \
REAL_CLIENT_EXPECT_SSH_STDOUT="${REAL_CLIENT_EXPECT_SSH_STDOUT:-${accept_env_stdout}}" \
REAL_CLIENT_EXPECT_SSH_ALLOW_STDERR="${REAL_CLIENT_EXPECT_SSH_ALLOW_STDERR-}" \
REAL_CLIENT_SSH_SEND_ENV="${REAL_CLIENT_SSH_SEND_ENV:-${accept_env_send_env}}" \
  tools/real-client/online-lastseen-common.sh
