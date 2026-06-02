#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

policy_json="$(cat tools/real-client/fixtures/ssh-profile-variants.hujson)"
ssh_user="${REAL_CLIENT_SSH_USER:-ssh-it-user}"
profile_email="${REAL_CLIENT_PROFILE_SUBDOMAIN_EMAIL:-${ssh_user}@sub.example.com}"
deny_first_line="tailscale: tailnet policy does not permit you to SSH as user \"${ssh_user}\""
deny_first_line="${REAL_CLIENT_SSH_DENY_STDERR_FIRST_LINE:-${deny_first_line}}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/ssh-profile-subdomain-deny-headscale-go-smoke}"

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}" \
REAL_CLIENT_WORKDIR="${work_root}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-2}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-profile-subdomain,profile-subdomain}" \
REAL_CLIENT_CLIENT_USER_EMAILS="${REAL_CLIENT_CLIENT_USER_EMAILS:-${profile_email},${profile_email}}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_POLICY_JSON:-${policy_json}}" \
REAL_CLIENT_EXPECT_PEER_COUNT="${REAL_CLIENT_EXPECT_PEER_COUNT:-1}" \
REAL_CLIENT_ENABLE_TAILSCALE_SSH=true \
REAL_CLIENT_INSTALL_OPENSSH=true \
REAL_CLIENT_SSH_USER="${ssh_user}" \
REAL_CLIENT_EXPECT_SSH_MATRIX="${REAL_CLIENT_EXPECT_SSH_MATRIX:-1:2:deny,2:1:deny}" \
REAL_CLIENT_EXPECT_SSH_DENY_STATUS="${REAL_CLIENT_EXPECT_SSH_DENY_STATUS:-255}" \
REAL_CLIENT_EXPECT_SSH_DENY_STDERR_REGEX="${REAL_CLIENT_EXPECT_SSH_DENY_STDERR_REGEX:-tailnet policy does not permit you to SSH as user}" \
REAL_CLIENT_EXPECT_SSH_DENY_STDERR_FIRST_LINE="${deny_first_line}" \
  tools/real-client/authkey-headscale-go-smoke.sh
