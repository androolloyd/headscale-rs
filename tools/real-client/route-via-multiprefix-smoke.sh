#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

route_a="${REAL_CLIENT_ROUTE_A:-10.77.0.0/24}"
route_b="${REAL_CLIENT_ROUTE_B:-10.88.0.0/24}"
routes="${route_a},${route_b}"
policy_json="$(
  ruby -rjson -e '
    route_a = ARGV.fetch(0)
    route_b = ARGV.fetch(1)
    puts JSON.pretty_generate({
      tagOwners: {
        "tag:router-a" => ["router@"],
        "tag:router-b" => ["router@"],
      },
      autoApprovers: {
        routes: {
          route_a => ["tag:router-a", "tag:router-b"],
          route_b => ["tag:router-a", "tag:router-b"],
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
          dst: [route_a],
          ip: ["*"],
          via: ["tag:router-a"],
        },
        {
          src: ["alice@"],
          dst: [route_b],
          ip: ["*"],
          via: ["tag:router-b"],
        },
        {
          src: ["bob@"],
          dst: [route_a],
          ip: ["*"],
          via: ["tag:router-b"],
        },
        {
          src: ["bob@"],
          dst: [route_b],
          ip: ["*"],
          via: ["tag:router-a"],
        },
      ],
    })
  ' "${route_a}" "${route_b}"
)"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/route-via-multiprefix-smoke}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-4}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-router,router,alice,bob}" \
REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT="${REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT:-tag:router-a;tag:router-b;-;-}" \
REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT="${REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT:-${routes};${routes};-;-}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_POLICY_JSON:-${policy_json}}" \
REAL_CLIENT_EXPECT_MACHINE_COUNT="${REAL_CLIENT_EXPECT_MACHINE_COUNT:-4}" \
REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS="${REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS:-3:1:${route_a};3:2:${route_b};4:2:${route_a};4:1:${route_b}}" \
  tools/real-client/authkey-smoke.sh
