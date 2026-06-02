#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

policy_json="$(cat tools/real-client/fixtures/ssh-profile-variants.hujson)"
ssh_user="${REAL_CLIENT_SSH_USER:-ssh-it-user}"
profile_email="${REAL_CLIENT_PROFILE_SUBDOMAIN_EMAIL:-${ssh_user}@sub.example.com}"
deny_first_line="tailscale: tailnet policy does not permit you to SSH as user \"${ssh_user}\""
deny_first_line="${REAL_CLIENT_SSH_DENY_STDERR_FIRST_LINE:-${deny_first_line}}"
work_root="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-ssh-profile-subdomain-deny-smoke}"

REAL_CLIENT_WORKDIR="${work_root}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=rust \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-2}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-${profile_email},${profile_email}}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_POLICY_JSON:-${policy_json}}" \
REAL_CLIENT_EXPECT_PEER_COUNT="${REAL_CLIENT_EXPECT_PEER_COUNT:-1}" \
REAL_CLIENT_ENABLE_TAILSCALE_SSH=true \
REAL_CLIENT_INSTALL_OPENSSH=true \
REAL_CLIENT_SSH_USER="${ssh_user}" \
REAL_CLIENT_EXPECT_SSH_MATRIX="${REAL_CLIENT_EXPECT_SSH_MATRIX:-1:2:deny,2:1:deny}" \
REAL_CLIENT_EXPECT_SSH_DENY_STATUS="${REAL_CLIENT_EXPECT_SSH_DENY_STATUS:-255}" \
REAL_CLIENT_EXPECT_SSH_DENY_STDERR_REGEX="${REAL_CLIENT_EXPECT_SSH_DENY_STDERR_REGEX:-tailnet policy does not permit you to SSH as user}" \
REAL_CLIENT_EXPECT_SSH_DENY_STDERR_FIRST_LINE="${deny_first_line}" \
  tools/real-client/online-lastseen-common.sh
