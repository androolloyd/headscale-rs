#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/route-advertise-headscale-go-smoke}" \
REAL_CLIENT_ADVERTISE_ROUTES="${REAL_CLIENT_ADVERTISE_ROUTES:-10.77.0.0/24}" \
  tools/real-client/authkey-headscale-go-smoke.sh
