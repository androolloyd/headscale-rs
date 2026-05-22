#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

work_root="${REAL_CLIENT_WORKDIR:-target/real-client/ssh-smoke}"
ssh_user="${REAL_CLIENT_SSH_USER:-ssh-it-user}"
attempt_timeout="${REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS:-12}"
autogroup_policy="$(cat tools/real-client/fixtures/ssh-autogroup-self.hujson)"
blocked_policy="$(cat tools/real-client/fixtures/ssh-acl-blocked.hujson)"

REAL_CLIENT_WORKDIR="${work_root}/autogroup-self" \
REAL_CLIENT_CLIENT_COUNT=3 \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-user1,user1,user2}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_SSH_AUTOGROUP_POLICY:-${autogroup_policy}}" \
REAL_CLIENT_EXPECT_PEER_COUNT="${REAL_CLIENT_EXPECT_PEER_COUNT:-2}" \
REAL_CLIENT_ENABLE_TAILSCALE_SSH=true \
REAL_CLIENT_INSTALL_OPENSSH=true \
REAL_CLIENT_SSH_USER="${ssh_user}" \
REAL_CLIENT_EXPECT_SSH_MATRIX="${REAL_CLIENT_EXPECT_SSH_MATRIX:-1:2:allow,2:1:allow,1:3:deny,3:1:deny}" \
REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS="${attempt_timeout}" \
  tools/real-client/authkey-smoke.sh

REAL_CLIENT_WORKDIR="${work_root}/acl-blocked" \
REAL_CLIENT_CLIENT_COUNT=2 \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_TIMEOUT_CLIENT_USERS:-user1,user1}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_SSH_BLOCKED_POLICY:-${blocked_policy}}" \
REAL_CLIENT_EXPECT_PEER_COUNT="${REAL_CLIENT_TIMEOUT_EXPECT_PEER_COUNT:-1}" \
REAL_CLIENT_ENABLE_TAILSCALE_SSH=true \
REAL_CLIENT_INSTALL_OPENSSH=true \
REAL_CLIENT_SSH_USER="${ssh_user}" \
REAL_CLIENT_EXPECT_SSH_MATRIX="${REAL_CLIENT_TIMEOUT_EXPECT_SSH_MATRIX:-1:2:timeout}" \
REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS="${attempt_timeout}" \
  tools/real-client/authkey-smoke.sh
