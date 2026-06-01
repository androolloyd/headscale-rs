#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

policy_json="${REAL_CLIENT_POLICY_JSON:-$(ruby -rjson -e 'puts JSON.pretty_generate({acls: [{action: "accept", src: ["autogroup:member"], dst: ["autogroup:self:*"]}]})')}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-acl-autogroup-self-headscale-go-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-3}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-alice,bob,alice}" \
REAL_CLIENT_POLICY_JSON="${policy_json}" \
REAL_CLIENT_EXPECT_PEER_COUNTS="${REAL_CLIENT_EXPECT_PEER_COUNTS:-1,0,1}" \
  tools/real-client/online-lastseen-common.sh
