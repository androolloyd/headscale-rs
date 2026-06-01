#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

if [[ -z "${HEADSCALE_DB_POSTGRES_TEST_URL:-}" ]]; then
  echo "skipping Postgres real-client smoke: HEADSCALE_DB_POSTGRES_TEST_URL is not set"
  exit 0
fi

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

region_id="${REAL_CLIENT_DERP_REGION_ID:-940}"
region_code="${REAL_CLIENT_DERP_REGION_CODE:-sidecar}"
region_name="${REAL_CLIENT_DERP_REGION_NAME:-headscale private DERP}"

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

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-derp-private-headscale-go-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
REAL_CLIENT_DATABASE_BACKEND=postgres \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-2}" \
REAL_CLIENT_EXPECT_PEER_COUNT="${REAL_CLIENT_EXPECT_PEER_COUNT:-1}" \
REAL_CLIENT_FORCE_DERP="${REAL_CLIENT_FORCE_DERP:-true}" \
REAL_CLIENT_EXPECT_DERP_PING="${REAL_CLIENT_EXPECT_DERP_PING:-true}" \
REAL_CLIENT_ASSERT_DERP_STUN="${REAL_CLIENT_ASSERT_DERP_STUN:-true}" \
REAL_CLIENT_DERP_STUN_PROBE_HOST="${REAL_CLIENT_DERP_STUN_PROBE_HOST:-::1}" \
REAL_CLIENT_HEADSCALE_GO_EMBEDDED_DERP=true \
REAL_CLIENT_HEADSCALE_GO_DERP_REGION_ID="${region_id}" \
REAL_CLIENT_HEADSCALE_GO_DERP_REGION_CODE="${region_code}" \
REAL_CLIENT_HEADSCALE_GO_DERP_REGION_NAME="${region_name}" \
REAL_CLIENT_HEADSCALE_GO_DERP_STUN_ADDR="0.0.0.0:${stun_port}" \
REAL_CLIENT_HEADSCALE_GO_DERP_VERIFY_CLIENTS=true \
REAL_CLIENT_EXPECT_DERP_REGION_ID="${REAL_CLIENT_EXPECT_DERP_REGION_ID:-${region_id}}" \
REAL_CLIENT_EXPECT_DERP_REGION_CODE="${REAL_CLIENT_EXPECT_DERP_REGION_CODE:-${region_code}}" \
REAL_CLIENT_EXPECT_DERP_REGION_NAME="${REAL_CLIENT_EXPECT_DERP_REGION_NAME:-${region_name}}" \
REAL_CLIENT_EXPECT_DERP_HOST="${REAL_CLIENT_EXPECT_DERP_HOST:-host.docker.internal}" \
REAL_CLIENT_EXPECT_DERP_STUN_PORT="${REAL_CLIENT_EXPECT_DERP_STUN_PORT:-${stun_port}}" \
  tools/real-client/online-lastseen-common.sh
