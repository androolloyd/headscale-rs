#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

route="${REAL_CLIENT_ROUTE:-10.77.0.0/24}"
policy_json="$(
  ruby -rjson -e '
    route = ARGV.fetch(0)
    puts JSON.pretty_generate({
      tagOwners: {
        "tag:router-a" => ["router@"],
        "tag:router-b" => ["router@"],
      },
      autoApprovers: {
        routes: {
          route => ["tag:router-a", "tag:router-b"],
        },
      },
      grants: [
        {
          src: ["*"],
          dst: ["tag:router-a", "tag:router-b"],
          ip: ["*"],
        },
        {
          src: ["alice@"],
          dst: [route],
          ip: ["*"],
          via: ["tag:router-a"],
        },
        {
          src: ["bob@"],
          dst: [route],
          ip: ["*"],
          via: ["tag:router-b"],
        },
      ],
    })
  ' "${route}"
)"

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-4483fd0cad38717913e7509fc50f9d48c691b02b}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/route-via-headscale-go-smoke}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-4}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-router,router,alice,bob}" \
REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT="${REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT:-tag:router-a;tag:router-b;-;-}" \
REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT="${REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT:-${route};${route};-;-}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_POLICY_JSON:-${policy_json}}" \
REAL_CLIENT_EXPECT_MACHINE_COUNT="${REAL_CLIENT_EXPECT_MACHINE_COUNT:-4}" \
REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS="${REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS:-3:1:${route};4:2:${route}}" \
  tools/real-client/authkey-headscale-go-smoke.sh
