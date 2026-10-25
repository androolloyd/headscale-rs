#!/usr/bin/env bash
# Run the upstream test suites of the crates vendored under vendor/ against
# their local patches. See tools/vendor-tests/run.py for how the scratch
# workspaces are built and tools/vendor-tests/README.md for the design.
#
#   scripts/test_vendored_crates.sh                 # every crate
#   scripts/test_vendored_crates.sh h2 rustls       # selected crates
#   scripts/test_vendored_crates.sh --list          # crates and their runs
#   scripts/test_vendored_crates.sh --run native h2 # only runs named "native"
#   scripts/test_vendored_crates.sh --update-locks  # refresh tools/vendor-tests/locks
#
# Environment:
#   VENDOR_TESTS_DIR            scratch directory (default: target/vendor-tests)
#   CARGO_TARGET_DIR            cargo target dir (default: $VENDOR_TESTS_DIR/target)
#   VENDOR_TESTS_POSTGRES_URL   live Postgres for sqlx-postgres' integration suite
#   VENDOR_TESTS_UNLOCKED=1     resolve without --locked
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "${repo_root}/tools/vendor-tests/run.py" "$@"
