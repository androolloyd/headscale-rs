#!/usr/bin/env bash
set -euo pipefail

cat <<'EOF'
skipping postgres-derp-native-restart headscale-go smoke:
headscale-go has embedded DERP restart behavior, but it does not exercise
headscale-rs native DERP relay shutdown health/restarting frames or the
post-restart status-health clear check for those frames. This matrix entry is
Rust-only and is intentionally not a sidecar-vs-native parity claim.
EOF
