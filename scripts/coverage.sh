#!/usr/bin/env bash
set -euo pipefail

mkdir -p target/coverage
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/llvm-cov}"

ignore_regex='(headscale-api/src/generated/.*|.*/target/.*)'
standalone_manifests=(
  headscale-core/Cargo.toml
  headscale-identity/Cargo.toml
  headscale-resources/Cargo.toml
  headscale-payments/Cargo.toml
)

cargo llvm-cov clean --workspace

cargo llvm-cov \
  --workspace \
  --all-features \
  --no-report

for manifest in "${standalone_manifests[@]}"; do
  cargo llvm-cov \
    --manifest-path "${manifest}" \
    --all-features \
    --no-report \
    --no-clean
done

cargo llvm-cov report \
  --lcov \
  --output-path target/coverage/lcov.info \
  --ignore-filename-regex "${ignore_regex}"

cargo llvm-cov report \
  --text \
  --output-path target/coverage/summary.txt \
  --ignore-filename-regex "${ignore_regex}"

cat target/coverage/summary.txt
