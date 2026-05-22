#!/usr/bin/env bash
set -euo pipefail

mkdir -p target/coverage
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target/llvm-cov}"
coverage_fail_under="${HEADSCALE_COVERAGE_FAIL_UNDER_LINES:-20}"

ignore_regex='(headscale-api/src/generated/.*|.*/target/.*)'
standalone_manifests=(
  headscale-core/Cargo.toml
  headscale-identity/Cargo.toml
  headscale-resources/Cargo.toml
  headscale-payments/Cargo.toml
)

cargo llvm-cov clean --workspace

eval "$(cargo llvm-cov show-env --sh)"

cargo test \
  --workspace \
  --all-targets \
  --all-features

for manifest in "${standalone_manifests[@]}"; do
  cargo test \
    --manifest-path "${manifest}" \
    --all-targets \
    --all-features
done

cargo llvm-cov report \
  --lcov \
  --output-path target/coverage/lcov.info \
  --ignore-filename-regex "${ignore_regex}"

cargo llvm-cov report \
  --fail-under-lines "${coverage_fail_under}" \
  --ignore-filename-regex "${ignore_regex}" \
  | tee target/coverage/summary.txt
