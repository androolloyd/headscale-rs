#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

policy_json="${REAL_CLIENT_POLICY_JSON:-$(ruby -rjson -e 'puts JSON.pretty_generate({acls: [{action: "accept", src: ["*"], dst: ["*:*"]}]})')}"
renamed_node="${REAL_CLIENT_RENAME_NODE_AFTER_LOGIN:-pg-renamed-node}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-node-rename-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=rust \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-2}" \
REAL_CLIENT_POLICY_JSON="${policy_json}" \
REAL_CLIENT_EXPECT_PEER_COUNT="${REAL_CLIENT_EXPECT_PEER_COUNT:-1}" \
REAL_CLIENT_RENAME_NODE_AFTER_LOGIN="${renamed_node}" \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-240}" \
  tools/real-client/online-lastseen-common.sh
