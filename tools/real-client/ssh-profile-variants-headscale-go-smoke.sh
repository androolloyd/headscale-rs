#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

policy_json="$(cat tools/real-client/fixtures/ssh-profile-variants.hujson)"
ssh_user="${REAL_CLIENT_SSH_USER:-ssh-it-user}"
deny_first_line="tailscale: tailnet policy does not permit you to SSH as user \"${ssh_user}\""
deny_first_line="${REAL_CLIENT_SSH_DENY_STDERR_FIRST_LINE:-${deny_first_line}}"
profile_root_deny_first_line="${REAL_CLIENT_PROFILE_ROOT_DENY_STDERR_FIRST_LINE:-tailscale: tailnet policy does not permit you to SSH as user \"root\"}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/ssh-profile-variants-headscale-go-smoke}"

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}" \
REAL_CLIENT_WORKDIR="${work_root}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-6}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-profile-owner,profile-owner,other-owner,other-owner,ssh-it-user,ssh-it-user}" \
REAL_CLIENT_CLIENT_USER_EMAILS="${REAL_CLIENT_CLIENT_USER_EMAILS:-ssh-it-user@example.com,ssh-it-user@example.com,ssh-it-user@other.example,ssh-it-user@other.example,-,-}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_POLICY_JSON:-${policy_json}}" \
REAL_CLIENT_EXPECT_PEER_COUNT="${REAL_CLIENT_EXPECT_PEER_COUNT:-5}" \
REAL_CLIENT_ENABLE_TAILSCALE_SSH=true \
REAL_CLIENT_INSTALL_OPENSSH=true \
REAL_CLIENT_SSH_USER="${ssh_user}" \
REAL_CLIENT_EXPECT_SSH_MATRIX="${REAL_CLIENT_EXPECT_SSH_MATRIX:-1:2:allow,2:1:allow,3:4:deny,4:3:deny,5:6:deny}" \
REAL_CLIENT_EXPECT_SSH_DENY_STATUS="${REAL_CLIENT_EXPECT_SSH_DENY_STATUS:-255}" \
REAL_CLIENT_EXPECT_SSH_DENY_STDERR_REGEX="${REAL_CLIENT_EXPECT_SSH_DENY_STDERR_REGEX:-tailnet policy does not permit you to SSH as user}" \
REAL_CLIENT_EXPECT_SSH_DENY_STDERR_FIRST_LINE="${REAL_CLIENT_EXPECT_SSH_DENY_STDERR_FIRST_LINE:-${deny_first_line}}" \
  tools/real-client/authkey-headscale-go-smoke.sh

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_PROFILE_ROOT_DENY_WORKDIR:-${work_root}/root-login-user-deny}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_PROFILE_ROOT_DENY_CLIENT_COUNT:-2}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_PROFILE_ROOT_DENY_CLIENT_USERS:-profile-owner,profile-owner}" \
REAL_CLIENT_CLIENT_USER_EMAILS="${REAL_CLIENT_PROFILE_ROOT_DENY_CLIENT_USER_EMAILS:-ssh-it-user@example.com,ssh-it-user@example.com}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_PROFILE_ROOT_DENY_POLICY_JSON:-${policy_json}}" \
REAL_CLIENT_EXPECT_PEER_COUNT="${REAL_CLIENT_PROFILE_ROOT_DENY_EXPECT_PEER_COUNT:-1}" \
REAL_CLIENT_ENABLE_TAILSCALE_SSH=true \
REAL_CLIENT_INSTALL_OPENSSH=true \
REAL_CLIENT_SSH_USER=root \
REAL_CLIENT_EXPECT_SSH_MATRIX="${REAL_CLIENT_PROFILE_ROOT_DENY_MATRIX:-1:2:deny,2:1:deny}" \
REAL_CLIENT_EXPECT_SSH_DENY_STATUS="${REAL_CLIENT_PROFILE_ROOT_DENY_STATUS:-255}" \
REAL_CLIENT_EXPECT_SSH_DENY_STDERR_REGEX="${REAL_CLIENT_PROFILE_ROOT_DENY_STDERR_REGEX:-tailnet policy does not permit you to SSH as user}" \
REAL_CLIENT_EXPECT_SSH_DENY_STDERR_FIRST_LINE="${profile_root_deny_first_line}" \
  tools/real-client/authkey-headscale-go-smoke.sh
