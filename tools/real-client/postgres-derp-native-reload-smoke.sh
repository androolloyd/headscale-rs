#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

if [[ -z "${HEADSCALE_DB_POSTGRES_TEST_URL:-}" ]]; then
  echo "skipping Postgres real-client smoke: HEADSCALE_DB_POSTGRES_TEST_URL is not set"
  exit 0
fi

region_id="${REAL_CLIENT_DERP_REGION_ID:-943}"
region_code="${REAL_CLIENT_DERP_REGION_CODE:-native-reload}"
region_name="${REAL_CLIENT_DERP_REGION_NAME:-headscale-rs native DERP reload}"
host_name="${REAL_CLIENT_DERP_HOST:-host.docker.internal}"

policy_json="${REAL_CLIENT_POLICY_JSON:-$(ruby -rjson -e 'puts JSON.pretty_generate({acls: [{action: "accept", src: ["alice@"], dst: ["alice@:*"]}, {action: "accept", src: ["bob@"], dst: ["bob@:*"]}]})')}"
policy_reload_json="${REAL_CLIENT_RELOAD_POLICY_JSON:-$(ruby -rjson -e 'puts JSON.pretty_generate({acls: [{action: "accept", src: ["*"], dst: ["*:*"]}]})')}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

free_udp_port() {
  ruby -rsocket -e 's=UDPSocket.new; s.bind("127.0.0.1",0); puts s.addr[1]; s.close'
}

need ruby

stun_port="${REAL_CLIENT_DERP_STUN_PORT:-$(free_udp_port)}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-derp-native-reload-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=rust \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-2}" \
REAL_CLIENT_CLIENT_USERS="${REAL_CLIENT_CLIENT_USERS:-alice,bob}" \
REAL_CLIENT_POLICY_JSON="${policy_json}" \
REAL_CLIENT_RELOAD_POLICY_JSON="${policy_reload_json}" \
REAL_CLIENT_EXPECT_PEER_COUNTS="${REAL_CLIENT_EXPECT_PEER_COUNTS:-0,0}" \
REAL_CLIENT_EXPECT_PEER_COUNT_AFTER_POLICY_RELOAD="${REAL_CLIENT_EXPECT_PEER_COUNT_AFTER_POLICY_RELOAD:-1}" \
REAL_CLIENT_FORCE_DERP="${REAL_CLIENT_FORCE_DERP:-true}" \
REAL_CLIENT_EXPECT_DERP_PING="${REAL_CLIENT_EXPECT_DERP_PING:-true}" \
REAL_CLIENT_ASSERT_DERP_STUN="${REAL_CLIENT_ASSERT_DERP_STUN:-true}" \
REAL_CLIENT_ASSERT_DERP_STATUS_HEALTH_CLEAR="${REAL_CLIENT_ASSERT_DERP_STATUS_HEALTH_CLEAR:-true}" \
REAL_CLIENT_ASSERT_DERP_RELOAD_STABILITY="${REAL_CLIENT_ASSERT_DERP_RELOAD_STABILITY:-true}" \
REAL_CLIENT_EXPECT_DERP_REGION_ID="${REAL_CLIENT_EXPECT_DERP_REGION_ID:-${region_id}}" \
REAL_CLIENT_EXPECT_DERP_REGION_CODE="${REAL_CLIENT_EXPECT_DERP_REGION_CODE:-${region_code}}" \
REAL_CLIENT_EXPECT_DERP_REGION_NAME="${REAL_CLIENT_EXPECT_DERP_REGION_NAME:-${region_name}}" \
REAL_CLIENT_EXPECT_DERP_HOST="${REAL_CLIENT_EXPECT_DERP_HOST:-${host_name}}" \
REAL_CLIENT_EXPECT_DERP_STUN_PORT="${REAL_CLIENT_EXPECT_DERP_STUN_PORT:-${stun_port}}" \
REAL_CLIENT_EXPECT_DERP_INSECURE_FOR_TESTS="${REAL_CLIENT_EXPECT_DERP_INSECURE_FOR_TESTS:-true}" \
REAL_CLIENT_EXPECT_DERP_OMIT_DEFAULT_REGIONS="${REAL_CLIENT_EXPECT_DERP_OMIT_DEFAULT_REGIONS:-true}" \
REAL_CLIENT_RUST_EMBEDDED_DERP=true \
REAL_CLIENT_RUST_DERP_RELAY_MODE=native \
REAL_CLIENT_RUST_DERP_HOST="${host_name}" \
REAL_CLIENT_RUST_DERP_STUN_ADDR="0.0.0.0:${stun_port}" \
REAL_CLIENT_RUST_DERP_REGION_ID="${region_id}" \
REAL_CLIENT_RUST_DERP_REGION_CODE="${region_code}" \
REAL_CLIENT_RUST_DERP_REGION_NAME="${region_name}" \
REAL_CLIENT_RUST_DERP_OMIT_DEFAULT_REGIONS=true \
REAL_CLIENT_RUST_DERP_INSECURE_FOR_TESTS=true \
REAL_CLIENT_RUST_DERP_VERIFY_CLIENTS=true \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-240}" \
  tools/real-client/online-lastseen-common.sh
