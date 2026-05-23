#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

scenario_dir="${CURRENT_HEAD_SCENARIO_DIR:-tools/parity/current-head}"
golden_path="${CURRENT_HEAD_GOLDEN:-}"
out_dir="${OUT_DIR:-target/parity-current-head}"
case "${out_dir}" in
  /*) out_dir_abs="${out_dir}" ;;
  *) out_dir_abs="${repo_root}/${out_dir}" ;;
esac
mkdir -p "${out_dir_abs}"

default_scenarios=0
if (($# == 0)); then
  default_scenarios=1
  scenarios=()
  if [[ -d "${scenario_dir}" ]]; then
    while IFS= read -r scenario; do
      scenarios+=("${scenario}")
    done < <(find "${scenario_dir}" -maxdepth 1 -name '*.json' -type f | sort)
  fi
else
  scenarios=("$@")
fi

if ((default_scenarios == 1)) && [[ -z "${CURRENT_HEAD_GOLDEN+x}" ]]; then
  golden_path="tools/parity/current-head/golden/headscale-rs.json"
fi

if ((${#scenarios[@]} == 0)); then
  echo "no current-head parity scenarios found" >&2
  exit 2
fi

cargo run \
  --quiet \
  --manifest-path tools/parity/headscale-rs/Cargo.toml \
  -- "${scenarios[@]}" \
  > "${out_dir_abs}/headscale-rs-current-head.json"

OUT_DIR_FOR_RUBY="${out_dir_abs}" CURRENT_HEAD_GOLDEN_PATH="${golden_path}" ruby <<'RUBY'
require "json"
require "fileutils"

out_dir = ENV.fetch("OUT_DIR_FOR_RUBY")
actual_path = File.join(out_dir, "headscale-rs-current-head.json")
actual = JSON.parse(File.read(actual_path))

golden_path = ENV["CURRENT_HEAD_GOLDEN_PATH"]
if golden_path.nil? || golden_path.empty?
  puts "current-head parity scenarios matched: #{actual.map { |s| s["name"] }.join(", ")}"
  exit 0
end

golden_abs = File.absolute_path(golden_path, Dir.pwd)
if ENV["CURRENT_HEAD_UPDATE_GOLDEN"] == "1"
  FileUtils.mkdir_p(File.dirname(golden_abs))
  File.write(golden_abs, JSON.pretty_generate(actual) + "\n")
  puts "updated current-head parity golden: #{golden_abs}"
elsif File.exist?(golden_abs)
  golden = JSON.parse(File.read(golden_abs))
  if actual != golden
    warn "current-head parity golden mismatch"
    warn "Golden: #{golden_abs}"
    warn "Actual: #{actual_path}"
    warn "Refresh intentionally with CURRENT_HEAD_UPDATE_GOLDEN=1 ./scripts/headscale_rs_current_head_golden.sh"
    exit 1
  end
  puts "current-head parity golden matched: #{golden_abs}"
else
  warn "current-head parity golden not found: #{golden_abs}"
  warn "Create it intentionally with CURRENT_HEAD_UPDATE_GOLDEN=1 ./scripts/headscale_rs_current_head_golden.sh"
  exit 1
end

puts "current-head parity scenarios matched: #{actual.map { |s| s["name"] }.join(", ")}"
RUBY
