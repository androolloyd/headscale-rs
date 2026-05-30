#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

route="${REAL_CLIENT_ROUTE:-10.96.0.0/24}"
exit_routes="${REAL_CLIENT_EXIT_ROUTES:-0.0.0.0/0,::/0}"

route_health_mixed_exit_all_unhealthy_reload_policy() {
  ruby -rjson -e '
    route = ARGV.fetch(0)
    exit_routes = ARGV.fetch(1).split(",")
    subnet_auto_tags = ARGV.drop(2)
    auto_routes = {route => subnet_auto_tags}
    exit_routes.each { |exit_route| auto_routes[exit_route] = ["tag:exit"] }
    puts JSON.pretty_generate({
      tagOwners: {
        "tag:router-a" => ["router@"],
        "tag:router-b" => ["router@"],
        "tag:exit" => ["router@"],
      },
      autoApprovers: {
        routes: auto_routes,
      },
      acls: [
        {action: "accept", src: ["*"], dst: ["*:*"]},
      ],
    })
  ' "${route}" "${exit_routes}" "$@"
}

initial_policy="$(route_health_mixed_exit_all_unhealthy_reload_policy tag:router-a)"
reload_policy="$(route_health_mixed_exit_all_unhealthy_reload_policy tag:router-a tag:router-b)"

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/route-health-mixed-exit-all-unhealthy-reload-headscale-go-smoke}" \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-240}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-3}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-router,router,router}" \
REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT="${REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT:-tag:router-a;tag:router-b;tag:exit}" \
REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT="${REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT:-${route};${route};-}" \
REAL_CLIENT_ADVERTISE_EXIT_NODE_BY_CLIENT="${REAL_CLIENT_ADVERTISE_EXIT_NODE_BY_CLIENT:-false;false;true}" \
REAL_CLIENT_POLICY_JSON="${REAL_CLIENT_POLICY_JSON:-${initial_policy}}" \
REAL_CLIENT_POLICY_RELOAD_JSON="${REAL_CLIENT_POLICY_RELOAD_JSON:-${reload_policy}}" \
REAL_CLIENT_EXPECT_MACHINE_COUNT="${REAL_CLIENT_EXPECT_MACHINE_COUNT:-3}" \
REAL_CLIENT_EXPECT_AVAILABLE_ROUTES_BY_CLIENT="${REAL_CLIENT_EXPECT_AVAILABLE_ROUTES_BY_CLIENT:-${route};${route};${exit_routes}}" \
REAL_CLIENT_EXPECT_APPROVED_ROUTES_BY_CLIENT="${REAL_CLIENT_EXPECT_APPROVED_ROUTES_BY_CLIENT:-${route};-;${exit_routes}}" \
REAL_CLIENT_EXPECT_PRIMARY_ROUTE="${REAL_CLIENT_EXPECT_PRIMARY_ROUTE:-${route}}" \
REAL_CLIENT_EXPECT_PRIMARY_ROUTE_CANDIDATES="${REAL_CLIENT_EXPECT_PRIMARY_ROUTE_CANDIDATES:-1}" \
REAL_CLIENT_EXPECT_ROUTE_HEALTH_FAILOVER_ROUTE="${REAL_CLIENT_EXPECT_ROUTE_HEALTH_FAILOVER_ROUTE:-${route}}" \
REAL_CLIENT_EXPECT_ROUTE_HEALTH_ALL_UNHEALTHY_ROUTE="${REAL_CLIENT_EXPECT_ROUTE_HEALTH_ALL_UNHEALTHY_ROUTE:-${route}}" \
REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS="${REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS:-2}" \
REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS="${REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS:-1}" \
  tools/real-client/authkey-headscale-go-smoke.sh
