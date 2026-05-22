#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

initial_tags="${REAL_CLIENT_PREAUTH_TAGS:-tag:server}"
invalid_tags="${REAL_CLIENT_SET_TAGS_AFTER_LOGIN:-tag:blocked}"
policy_json="${REAL_CLIENT_POLICY_JSON:-}"
if [[ -z "${policy_json}" ]]; then
  policy_json="$(
    ruby -rjson -e '
      tags = ARGV.fetch(0).split(",").reject(&:empty?).sort.uniq
      owners = tags.to_h { |tag| [tag, ["alice@"]] }
      puts JSON.generate({
        tagOwners: owners,
        acls: [{action: "accept", src: ["*"], dst: ["*:*"]}],
      })
    ' "${initial_tags}"
  )"
fi

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/tag-update-invalid-headscale-go-smoke}" \
REAL_CLIENT_PREAUTH_TAGS="${initial_tags}" \
REAL_CLIENT_SET_TAGS_AFTER_LOGIN="${invalid_tags}" \
REAL_CLIENT_EXPECT_SET_TAGS_FAILURE=true \
REAL_CLIENT_EXPECT_TAGS="${REAL_CLIENT_EXPECT_TAGS:-${initial_tags}}" \
REAL_CLIENT_POLICY_JSON="${policy_json}" \
  tools/real-client/authkey-headscale-go-smoke.sh
