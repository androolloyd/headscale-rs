#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

route="${REAL_CLIENT_ROUTE:-10.77.0.0/24}"
policy_json="$(
  ruby -rjson -e '
    route = ARGV.fetch(0)
    puts JSON.pretty_generate({
      tagOwners: {
        "tag:router-ha" => ["router@"],
      },
      autoApprovers: {
        routes: {
          route => ["tag:router-ha"],
        },
      },
      grants: [
        {
          src: ["*"],
          dst: ["tag:router-ha"],
          ip: ["*"],
        },
        {
          src: ["alice@", "bob@"],
          dst: [route],
          ip: ["*"],
        },
        {
          src: ["alice@"],
          dst: [route],
          ip: ["*"],
          via: ["tag:router-ha"],
        },
        {
          src: ["bob@"],
          dst: [route],
          ip: ["*"],
          via: ["tag:router-ha"],
        },
      ],
    })
  ' "${route}"
)"

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/route-via-health-headscale-go-smoke}" \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-120}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-4}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-router,router,alice,bob}" \
REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT="${REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT:-tag:router-ha;tag:router-ha;-;-}" \
REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT="${REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT:-${route};${route};-;-}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_POLICY_JSON:-${policy_json}}" \
REAL_CLIENT_EXPECT_MACHINE_COUNT="${REAL_CLIENT_EXPECT_MACHINE_COUNT:-4}" \
REAL_CLIENT_EXPECT_PRIMARY_ROUTE="${REAL_CLIENT_EXPECT_PRIMARY_ROUTE:-${route}}" \
REAL_CLIENT_EXPECT_PRIMARY_ROUTE_CANDIDATES="${REAL_CLIENT_EXPECT_PRIMARY_ROUTE_CANDIDATES:-2}" \
REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS="${REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS:-3:1:${route};4:1:${route}}" \
REAL_CLIENT_EXPECT_ROUTE_HEALTH_FAILOVER_ROUTE="${REAL_CLIENT_EXPECT_ROUTE_HEALTH_FAILOVER_ROUTE:-${route}}" \
REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS_AFTER_ROUTE_HEALTH="${REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS_AFTER_ROUTE_HEALTH:-3:2:${route};4:2:${route}}" \
REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS="${REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS:-2}" \
REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS="${REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS:-1}" \
  tools/real-client/authkey-headscale-go-smoke.sh
