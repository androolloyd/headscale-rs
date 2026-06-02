#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# This parity row intentionally proves the supported sidecar compatibility
# boundary: headscale-rs owns DERP map generation, STUN, and verify-client
# admission while relay bytes flow through the upstream derper sidecar. Native
# relay stock-client coverage is wired by postgres-derp-native.

tailscale_version="${TAILSCALE_DERPER_VERSION:-v1.94.1}"
bin_dir="${repo_root}/target/real-client/bin"
derper_bin="${REAL_CLIENT_DERPER_BIN:-${bin_dir}/derper}"
region_id="${REAL_CLIENT_DERP_REGION_ID:-940}"
region_code="${REAL_CLIENT_DERP_REGION_CODE:-sidecar}"
region_name="${REAL_CLIENT_DERP_REGION_NAME:-headscale-rs sidecar DERP}"
host_name="${REAL_CLIENT_DERP_HOST:-host.docker.internal}"
work_tmp=""

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 2
  }
}

free_port() {
  ruby -rsocket -e 's=TCPServer.new("127.0.0.1",0); puts s.addr[1]; s.close'
}

free_udp_port() {
  ruby -rsocket -e 's=UDPSocket.new; s.bind("127.0.0.1",0); puts s.addr[1]; s.close'
}

cleanup() {
  if [[ -n "${work_tmp}" ]]; then
    rm -rf "${work_tmp}"
  fi
}
trap cleanup EXIT

need go
need openssl
need ruby

mkdir -p "${bin_dir}"
if [[ ! -x "${derper_bin}" ]]; then
  echo "::group::build derper ${tailscale_version}"
  GOBIN="${bin_dir}" go install "tailscale.com/cmd/derper@${tailscale_version}"
  echo "::endgroup::"
fi

derp_port="${REAL_CLIENT_DERP_PORT:-$(free_port)}"
stun_port="${REAL_CLIENT_DERP_STUN_PORT:-$(free_udp_port)}"
work_tmp="$(mktemp -d "${TMPDIR:-/tmp}/headscale-rs-derp-private.XXXXXX")"
cert_dir="${work_tmp}/certs"
mkdir -p "${cert_dir}"

echo "::group::generate derper manual TLS certificate"
openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
  -keyout "${cert_dir}/${host_name}.key" \
  -out "${cert_dir}/${host_name}.crt" \
  -subj "/CN=${host_name}" \
  -addext "subjectAltName=DNS:${host_name}" \
  >"${work_tmp}/openssl.stdout" \
  2>"${work_tmp}/openssl.stderr"
echo "::endgroup::"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/derp-private-smoke}" \
REAL_CLIENT_CLIENT_COUNT="${REAL_CLIENT_CLIENT_COUNT:-2}" \
REAL_CLIENT_EXPECT_PEER_COUNT="${REAL_CLIENT_EXPECT_PEER_COUNT:-1}" \
REAL_CLIENT_FORCE_DERP="${REAL_CLIENT_FORCE_DERP:-true}" \
REAL_CLIENT_EXPECT_DERP_PING="${REAL_CLIENT_EXPECT_DERP_PING:-true}" \
REAL_CLIENT_ASSERT_DERP_STUN="${REAL_CLIENT_ASSERT_DERP_STUN:-true}" \
REAL_CLIENT_EXPECT_DERP_VERIFY_REQUESTS_MIN="${REAL_CLIENT_EXPECT_DERP_VERIFY_REQUESTS_MIN:-2}" \
REAL_CLIENT_EXPECT_DERP_REGION_ID="${REAL_CLIENT_EXPECT_DERP_REGION_ID:-${region_id}}" \
REAL_CLIENT_EXPECT_DERP_REGION_CODE="${REAL_CLIENT_EXPECT_DERP_REGION_CODE:-${region_code}}" \
REAL_CLIENT_EXPECT_DERP_REGION_NAME="${REAL_CLIENT_EXPECT_DERP_REGION_NAME:-${region_name}}" \
REAL_CLIENT_EXPECT_DERP_HOST="${REAL_CLIENT_EXPECT_DERP_HOST:-${host_name}}" \
REAL_CLIENT_EXPECT_DERP_PORT="${REAL_CLIENT_EXPECT_DERP_PORT:-${derp_port}}" \
REAL_CLIENT_EXPECT_DERP_STUN_PORT="${REAL_CLIENT_EXPECT_DERP_STUN_PORT:-${stun_port}}" \
REAL_CLIENT_EXPECT_DERP_INSECURE_FOR_TESTS="${REAL_CLIENT_EXPECT_DERP_INSECURE_FOR_TESTS:-true}" \
REAL_CLIENT_EXPECT_DERP_OMIT_DEFAULT_REGIONS="${REAL_CLIENT_EXPECT_DERP_OMIT_DEFAULT_REGIONS:-true}" \
HSRS_HARNESS_EMBEDDED_DERP=true \
HSRS_HARNESS_EMBEDDED_DERP_HOSTNAME="${host_name}" \
HSRS_HARNESS_EMBEDDED_DERP_DERP_PORT="${derp_port}" \
HSRS_HARNESS_EMBEDDED_DERP_STUN_ADDR="0.0.0.0:${stun_port}" \
HSRS_HARNESS_EMBEDDED_DERP_REGION_ID="${region_id}" \
HSRS_HARNESS_EMBEDDED_DERP_REGION_CODE="${region_code}" \
HSRS_HARNESS_EMBEDDED_DERP_REGION_NAME="${region_name}" \
HSRS_HARNESS_EMBEDDED_DERP_OMIT_DEFAULT_REGIONS=true \
HSRS_HARNESS_EMBEDDED_DERP_INSECURE_FOR_TESTS=true \
HSRS_HARNESS_EMBEDDED_DERP_DERPER_BINARY="${derper_bin}" \
HSRS_HARNESS_EMBEDDED_DERP_DERPER_LISTEN_ADDR="0.0.0.0:${derp_port}" \
HSRS_HARNESS_EMBEDDED_DERP_DERPER_CERT_MODE=manual \
HSRS_HARNESS_EMBEDDED_DERP_DERPER_CERT_DIR="${cert_dir}" \
  tools/real-client/authkey-smoke.sh
