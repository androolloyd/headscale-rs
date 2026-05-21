#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

out_dir="${OUT_DIR:-target/parity}"
case "${out_dir}" in
  /*) out_dir_abs="${out_dir}" ;;
  *) out_dir_abs="${repo_root}/${out_dir}" ;;
esac
mkdir -p "${out_dir_abs}"

if (($# == 0)); then
  scenarios=()
  while IFS= read -r scenario; do
    scenarios+=("${scenario}")
  done < <(find tools/parity/scenarios -name '*.json' -type f | sort)
else
  scenarios=("$@")
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

OUT_DIR_FOR_RUBY="${out_dir_abs}" ruby <<'RUBY'
require "json"

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

puts "headscale-go parity scenarios matched: #{rs.map { |s| s["name"] }.join(", ")}"
RUBY
