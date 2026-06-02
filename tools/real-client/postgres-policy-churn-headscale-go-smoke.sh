#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

policy_json="${REAL_CLIENT_POLICY_JSON:-$(ruby -rjson -e 'puts JSON.pretty_generate({acls: [{action: "accept", src: ["alice@"], dst: ["alice@:*"]}, {action: "accept", src: ["bob@"], dst: ["bob@:*"]}]})')}"
policy_reload_json="${REAL_CLIENT_RELOAD_POLICY_JSON:-$(ruby -rjson -e 'puts JSON.pretty_generate({acls: [{action: "accept", src: ["*"], dst: ["*:*"]}]})')}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-policy-churn-headscale-go-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-2}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-alice,bob}" \
REAL_CLIENT_POLICY_JSON="${policy_json}" \
REAL_CLIENT_RELOAD_POLICY_JSON="${policy_reload_json}" \
REAL_CLIENT_EXPECT_PEER_COUNTS="${REAL_CLIENT_EXPECT_PEER_COUNTS:-0,0}" \
REAL_CLIENT_EXPECT_PEER_COUNT_AFTER_POLICY_RELOAD="${REAL_CLIENT_EXPECT_PEER_COUNT_AFTER_POLICY_RELOAD:-1}" \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-240}" \
  tools/real-client/online-lastseen-common.sh
