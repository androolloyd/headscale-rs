#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

# tools/parity/headscale-go/go.mod pins github.com/juanfont/headscale to
# upstream commit 4483fd0cad38717913e7509fc50f9d48c691b02b through this
# Go pseudo-version.
go_baseline_version="v0.29.0-beta.1.0.20260522122924-4483fd0cad38"
default_golden_path="tools/parity/golden/headscale-go-${go_baseline_version}.json"

out_dir="${OUT_DIR:-target/parity}"
golden_path="${PARITY_GOLDEN:-}"
case "${out_dir}" in
  /*) out_dir_abs="${out_dir}" ;;
  *) out_dir_abs="${repo_root}/${out_dir}" ;;
esac
mkdir -p "${out_dir_abs}"

default_scenarios=0
if (($# == 0)); then
  default_scenarios=1
  scenarios=()
  while IFS= read -r scenario; do
    scenarios+=("${scenario}")
  done < <(find tools/parity/scenarios -name '*.json' -type f | sort)
else
  scenarios=("$@")
fi

if ((default_scenarios == 1)) && [[ -z "${PARITY_GOLDEN+x}" ]]; then
  golden_path="${default_golden_path}"
fi

if ((${#scenarios[@]} == 0)); then
  echo "no parity scenarios found" >&2
  exit 2
fi

go_scenarios=()
for scenario in "${scenarios[@]}"; do
  case "${scenario}" in
    /*) go_scenarios+=("${scenario}") ;;
    *) go_scenarios+=("${repo_root}/${scenario}") ;;
  esac
done

cargo run \
  --quiet \
  --manifest-path tools/parity/headscale-rs/Cargo.toml \
  -- "${scenarios[@]}" \
  > "${out_dir_abs}/headscale-rs.json"

(
  cd tools/parity/headscale-go
  go run . "${go_scenarios[@]}" \
    > "${out_dir_abs}/headscale-go.json"
)

OUT_DIR_FOR_RUBY="${out_dir_abs}" PARITY_GOLDEN_PATH="${golden_path}" ruby <<'RUBY'
require "json"
require "fileutils"

out_dir = ENV.fetch("OUT_DIR_FOR_RUBY")
rs_path = File.join(out_dir, "headscale-rs.json")
go_path = File.join(out_dir, "headscale-go.json")
rs = JSON.parse(File.read(rs_path))
go = JSON.parse(File.read(go_path))

rs.each { |s| s["engine"] = "headscale" }
go.each { |s| s["engine"] = "headscale" }

if rs != go
  warn "headscale-go differential mismatch"
  warn "Rust output: #{rs_path}"
  warn "Go output:   #{go_path}"
  exit 1
end

golden_path = ENV["PARITY_GOLDEN_PATH"]
update_golden = ENV["PARITY_UPDATE_GOLDEN"] == "1"
if golden_path && !golden_path.empty?
  golden_abs = File.absolute_path(golden_path, Dir.pwd)
  if update_golden
    FileUtils.mkdir_p(File.dirname(golden_abs))
    File.write(golden_abs, JSON.pretty_generate(go) + "\n")
    puts "updated parity golden: #{golden_abs}"
  elsif File.exist?(golden_abs)
    golden = JSON.parse(File.read(golden_abs))
    if go != golden
      warn "headscale-go golden mismatch"
      warn "Golden: #{golden_abs}"
      warn "Actual: #{go_path}"
      warn "Refresh intentionally with PARITY_UPDATE_GOLDEN=1 ./scripts/headscale_go_diff.sh"
      exit 1
    end
    puts "headscale-go golden matched: #{golden_abs}"
  else
    warn "parity golden not found: #{golden_abs}"
    warn "Create it intentionally with PARITY_UPDATE_GOLDEN=1 ./scripts/headscale_go_diff.sh"
    exit 1
  end
end

puts "headscale-go parity scenarios matched: #{rs.map { |s| s["name"] }.join(", ")}"
RUBY
