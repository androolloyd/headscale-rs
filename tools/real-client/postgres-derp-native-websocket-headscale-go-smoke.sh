#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
skipping postgres-derp-native-websocket headscale-go smoke:
headscale-go embedded DERP coverage is tracked by the private DERP rows. This
row asserts headscale-rs native DERP-over-WebSocket transport and native
/debug/derp verify-client admission counters, so it is Rust-only and is
intentionally not a sidecar-vs-native parity claim.
EOF
