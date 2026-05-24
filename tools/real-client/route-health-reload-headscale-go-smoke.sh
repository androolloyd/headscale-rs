#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

route="${REAL_CLIENT_ROUTE:-10.90.0.0/24}"

route_health_reload_policy() {
  ruby -rjson -e '
    route = ARGV.fetch(0)
    auto_tags = ARGV.drop(1)
    puts JSON.pretty_generate({
      tagOwners: {
        "tag:router-a" => ["router@"],
        "tag:router-b" => ["router@"],
      },
      autoApprovers: {
        routes: {
          route => auto_tags,
        },
      },
      grants: [
        {
          src: ["*"],
          dst: ["*"],
          ip: ["*"],
        },
        {
          src: ["*"],
          dst: [route],
          ip: ["*"],
        },
      ],
    })
  ' "${route}" "$@"
}

initial_policy="$(route_health_reload_policy tag:router-a)"
reload_policy="$(route_health_reload_policy tag:router-a tag:router-b)"

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-4483fd0cad38717913e7509fc50f9d48c691b02b}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/route-health-reload-headscale-go-smoke}" \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-180}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-2}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-router,router}" \
REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT="${REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT:-tag:router-a;tag:router-b}" \
REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT="${REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT:-${route};${route}}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_POLICY_JSON:-${initial_policy}}" \
REAL_CLIENT_POLICY_RELOAD_JSON="${REAL_CLIENT_POLICY_RELOAD_JSON:-${reload_policy}}" \
REAL_CLIENT_EXPECT_MACHINE_COUNT="${REAL_CLIENT_EXPECT_MACHINE_COUNT:-2}" \
REAL_CLIENT_EXPECT_AVAILABLE_ROUTES_BY_CLIENT="${REAL_CLIENT_EXPECT_AVAILABLE_ROUTES_BY_CLIENT:-${route};${route}}" \
REAL_CLIENT_EXPECT_APPROVED_ROUTES_BY_CLIENT="${REAL_CLIENT_EXPECT_APPROVED_ROUTES_BY_CLIENT:-${route};-}" \
REAL_CLIENT_EXPECT_PRIMARY_ROUTE="${REAL_CLIENT_EXPECT_PRIMARY_ROUTE:-${route}}" \
REAL_CLIENT_EXPECT_PRIMARY_ROUTE_CANDIDATES="${REAL_CLIENT_EXPECT_PRIMARY_ROUTE_CANDIDATES:-1}" \
REAL_CLIENT_EXPECT_ROUTE_HEALTH_FAILOVER_ROUTE="${REAL_CLIENT_EXPECT_ROUTE_HEALTH_FAILOVER_ROUTE:-${route}}" \
REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS="${REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS:-2}" \
REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS="${REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS:-1}" \
  tools/real-client/authkey-headscale-go-smoke.sh
