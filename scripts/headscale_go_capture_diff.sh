#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
export GOCACHE="${GOCACHE:-${repo_root}/target/parity/go-build}"
mkdir -p "${GOCACHE}"

capture_dir="${CAPTURE_OUT_DIR:-target/parity/captures-v0.29.5}"
case "${capture_dir}" in
  /*) capture_dir_abs="${capture_dir}" ;;
  *) capture_dir_abs="${repo_root}/${capture_dir}" ;;
esac
module_version="$(cd tools/parity/headscale-go && go list -m -f '{{.Version}}' github.com/juanfont/headscale)"
if [[ "${module_version}" != v0.29.5 ]]; then
  echo "expected pinned headscale-go v0.29.5, found ${module_version}" >&2
  exit 1
fi
module_dir="$(cd tools/parity/headscale-go && go list -m -f '{{.Dir}}' github.com/juanfont/headscale)"

(
  cd tools/parity/headscale-go
  go run ./cmd/capture-scenarios \
    --upstream-root "${module_dir}" \
    --out "${capture_dir_abs}"
)

scenarios=()
capture_pattern="${CAPTURE_PATTERN:-capture-*.json}"
while IFS= read -r scenario; do
  scenarios+=("${scenario}")
done < <(python3 - "${capture_dir_abs}/manifest.json" "${capture_pattern}" "${capture_dir_abs}" <<'PY'
import fnmatch
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
for entry in manifest['entries']:
    output = entry.get('output')
    if output and fnmatch.fnmatchcase(output, sys.argv[2]):
        print(pathlib.Path(sys.argv[3]) / output)
PY
)
if ((${#scenarios[@]} == 0)); then
  echo "no converted captures match ${capture_pattern}" >&2
  exit 2
fi

if [[ "${CAPTURE_AUDIT:-0}" == 1 ]]; then
  go_binary="${repo_root}/target/parity/headscale-go-capture"
  (
    cd tools/parity/headscale-go
    go build -o "${go_binary}" .
  )
  cargo build --quiet --manifest-path tools/parity/headscale-rs/Cargo.toml
  python3 tools/parity/audit_capture_scenarios.py \
    --manifest "${capture_dir_abs}/manifest.json" \
    --go "${go_binary}" \
    --rust "${repo_root}/tools/parity/headscale-rs/target/debug/headscale-rs-parity" \
    --out "${CAPTURE_AUDIT_OUT:-${repo_root}/target/parity/capture-audit.json}" \
    --pattern "${capture_pattern}"
  exit 0
fi

PARITY_GOLDEN= OUT_DIR="${CAPTURE_DIFF_OUT_DIR:-target/parity/capture-diff}" \
  ./scripts/headscale_go_diff.sh "${scenarios[@]}"
