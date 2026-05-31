#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

tag="${REAL_CLIENT_UNOWNED_TAG:-tag:blocked}"
policy_json="${REAL_CLIENT_POLICY_JSON:-}"
if [[ -z "${policy_json}" ]]; then
  policy_json="$(
    ruby -rjson -e '
      puts JSON.generate({
        tagOwners: {"tag:server" => ["alice@"]},
        acls: [{action: "accept", src: ["*"], dst: ["*:*"]}],
      })
    '
  )"
fi

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-web-register-unowned-tag-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=rust \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_LOGIN_MODE=web \
REAL_CLIENT_PREAUTH_TAGS="${tag}" \
REAL_CLIENT_POLICY_JSON="${policy_json}" \
REAL_CLIENT_EXPECT_REGISTER_FAILURE=true \
  tools/real-client/online-lastseen-common.sh
