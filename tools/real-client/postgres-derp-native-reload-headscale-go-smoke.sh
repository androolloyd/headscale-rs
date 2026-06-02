#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
skipping postgres-derp-native-reload headscale-go smoke:
headscale-go embedded DERP coverage is tracked by the private DERP rows. This
row asserts headscale-rs native DERP relay map stability, post-reload relay
traffic, and stock-client status-health clear after a live policy reload, so it
is Rust-only and is intentionally not a sidecar-vs-native parity claim.
EOF
