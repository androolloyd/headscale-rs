#!/usr/bin/env bash
# Keep stock Tailscale clients running through the v0.28 Go -> Rust -> v0.29.5 Go SQLite handoff.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

HEADSCALE_GO_VERSION=v0.28.0 \
REAL_CLIENT_HEADSCALE_GO_TLS=true \
REAL_CLIENT_HANDOFF_SCRIPT=tools/real-client/sqlite-live-handoff-v028-rust-v0295.sh \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/sqlite-live-handoff-v028-rust-v0295-$(date +%s)-$$}" \
REAL_CLIENT_CLIENT_COUNT=2 \
REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT='10.77.0.0/24;-' \
REAL_CLIENT_EXPECT_AVAILABLE_ROUTES_BY_CLIENT='10.77.0.0/24;-' \
REAL_CLIENT_APPROVE_ROUTES_BY_CLIENT='10.77.0.0/24;-' \
REAL_CLIENT_EXPECT_APPROVED_ROUTES_BY_CLIENT='10.77.0.0/24;-' \
REAL_CLIENT_EXPECT_PEER_COUNT=1 \
  tools/real-client/authkey-headscale-go-smoke.sh
