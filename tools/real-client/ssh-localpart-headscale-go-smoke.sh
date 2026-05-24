#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

policy_json="$(cat tools/real-client/fixtures/ssh-localpart.hujson)"
localpart_ssh_user="${REAL_CLIENT_SSH_USER:-ssh-it-user}"
deny_first_line="tailscale: tailnet policy does not permit you to SSH as user \"${localpart_ssh_user}\""
deny_first_line="${REAL_CLIENT_SSH_DENY_STDERR_FIRST_LINE:-${deny_first_line}}"

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-4483fd0cad38717913e7509fc50f9d48c691b02b}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/ssh-localpart-headscale-go-smoke}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-4}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-ssh-it-user,ssh-it-user,eve,eve}" \
REAL_CLIENT_CLIENT_USER_EMAILS="${REAL_CLIENT_CLIENT_USER_EMAILS:-ssh-it-user@example.com,ssh-it-user@example.com,eve@other.example,eve@other.example}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_POLICY_JSON:-${policy_json}}" \
REAL_CLIENT_EXPECT_PEER_COUNT="${REAL_CLIENT_EXPECT_PEER_COUNT:-3}" \
REAL_CLIENT_ENABLE_TAILSCALE_SSH=true \
REAL_CLIENT_INSTALL_OPENSSH=true \
REAL_CLIENT_SSH_USER="${localpart_ssh_user}" \
REAL_CLIENT_EXPECT_SSH_MATRIX="${REAL_CLIENT_EXPECT_SSH_MATRIX:-1:2:allow,3:4:deny}" \
REAL_CLIENT_EXPECT_SSH_DENY_STATUS="${REAL_CLIENT_EXPECT_SSH_DENY_STATUS:-255}" \
REAL_CLIENT_EXPECT_SSH_DENY_STDERR_REGEX="${REAL_CLIENT_EXPECT_SSH_DENY_STDERR_REGEX:-tailnet policy does not permit you to SSH as user}" \
REAL_CLIENT_EXPECT_SSH_DENY_STDERR_FIRST_LINE="${REAL_CLIENT_EXPECT_SSH_DENY_STDERR_FIRST_LINE:-${deny_first_line}}" \
  tools/real-client/authkey-headscale-go-smoke.sh
