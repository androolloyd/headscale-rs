#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

# shellcheck source=tools/real-client/headscale-go-current.sh
source tools/real-client/headscale-go-current.sh

audit_target="${REAL_CLIENT_ROUTE_EDGE_AUDIT_TARGET:-rust}"
case "${audit_target}" in
  rust | headscale-go) ;;
  *)
    echo "REAL_CLIENT_ROUTE_EDGE_AUDIT_TARGET must be rust or headscale-go, got ${audit_target}" >&2
    exit 2
    ;;
esac

if [[ ! "${HEADSCALE_GO_CURRENT_VERSION}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "HEADSCALE_GO_CURRENT_VERSION must be a 40-character commit SHA, got ${HEADSCALE_GO_CURRENT_VERSION}" >&2
  exit 2
fi

matrix_output="$(tools/real-client/smoke-matrix.sh --list)"
failed=0

route_via_ids=(
  route-via
  route-via-same-tag
  route-via-health
  route-via-health-restart
  route-via-health-reload-restart
  route-via-reload
  route-via-restart
  route-via-same-tag-restart
  route-via-reload-restart
  route-via-multiprefix
  route-via-multiprefix-reload
  route-via-multiprefix-restart
  route-via-multiprefix-reload-restart
)

route_health_ids=(
  route-health
  route-health-reload
  route-health-reload-restart
  route-health-restart
  route-health-primary-restart
  route-health-all-unhealthy
  route-health-all-unhealthy-reload
  route-health-all-unhealthy-restart
  route-health-all-unhealthy-reload-restart
  route-health-mixed-exit
  route-health-mixed-exit-reload
  route-health-mixed-exit-restart
  route-health-mixed-exit-reload-restart
  route-health-mixed-exit-all-unhealthy
  route-health-mixed-exit-all-unhealthy-reload
  route-health-mixed-exit-all-unhealthy-restart
  route-health-mixed-exit-all-unhealthy-reload-restart
)

fail() {
  echo "route edge audit: $*" >&2
  failed=1
}

expected_route_edge() {
  local candidate="$1"
  local id
  for id in "${route_via_ids[@]}" "${route_health_ids[@]}"; do
    [[ "${candidate}" == "${id}" ]] && return 0
  done
  return 1
}

require_matrix_row() {
  local id="$1"
  local expected_area="$2"
  local expected_rust="$3"
  local expected_go="$4"
  local row
  local actual_area
  local actual_rust
  local actual_go

  if ! row="$(
    awk -v wanted="${id}" '
      NR > 1 && $1 == wanted {
        print $2 "\t" $3 "\t" $4
        found = 1
        exit
      }
      END {
        if (!found) {
          exit 1
        }
      }
    ' <<<"${matrix_output}"
  )"; then
    fail "missing matrix row ${id}"
    return
  fi

  IFS=$'\t' read -r actual_area actual_rust actual_go <<<"${row}"
  [[ "${actual_area}" == "${expected_area}" ]] ||
    fail "${id} area is ${actual_area}, expected ${expected_area}"
  [[ "${actual_rust}" == "${expected_rust}" ]] ||
    fail "${id} Rust script is ${actual_rust}, expected ${expected_rust}"
  [[ "${actual_go}" == "${expected_go}" ]] ||
    fail "${id} headscale-go script is ${actual_go}, expected ${expected_go}"

  for script in "${actual_rust}" "${actual_go}"; do
    [[ -f "${script}" ]] || fail "${id} script is missing: ${script}"
    [[ -x "${script}" ]] || fail "${id} script is not executable: ${script}"
  done
}

require_current_head_go_script() {
  local id="$1"
  local script="$2"

  grep -Fq 'source tools/real-client/headscale-go-current.sh' "${script}" ||
    fail "${id} headscale-go script does not source headscale-go-current.sh: ${script}"
  grep -Fq 'HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-${HEADSCALE_GO_CURRENT_VERSION}}"' "${script}" ||
    fail "${id} headscale-go script does not default to HEADSCALE_GO_CURRENT_VERSION: ${script}"
}

require_default_and_postgres_rows() {
  local id="$1"

  require_matrix_row \
    "${id}" \
    routes \
    "tools/real-client/${id}-smoke.sh" \
    "tools/real-client/${id}-headscale-go-smoke.sh"

  require_matrix_row \
    "postgres-${id}" \
    database \
    "tools/real-client/postgres-${id}-smoke.sh" \
    "tools/real-client/postgres-${id}-headscale-go-smoke.sh"

  require_current_head_go_script \
    "${id}" \
    "tools/real-client/${id}-headscale-go-smoke.sh"
  require_current_head_go_script \
    "postgres-${id}" \
    "tools/real-client/postgres-${id}-headscale-go-smoke.sh"
}

for id in "${route_via_ids[@]}" "${route_health_ids[@]}"; do
  require_default_and_postgres_rows "${id}"
done

expected_edge_count=$((${#route_via_ids[@]} + ${#route_health_ids[@]}))
actual_default_count="$(
  awk '
    NR > 1 && $2 == "routes" && ($1 ~ /^route-via/ || $1 ~ /^route-health/) {
      count++
    }
    END {
      print count + 0
    }
  ' <<<"${matrix_output}"
)"
actual_postgres_count="$(
  awk '
    NR > 1 && $2 == "database" && ($1 ~ /^postgres-route-via/ || $1 ~ /^postgres-route-health/) {
      count++
    }
    END {
      print count + 0
    }
  ' <<<"${matrix_output}"
)"

[[ "${actual_default_count}" == "${expected_edge_count}" ]] ||
  fail "default route-via/route-health row count is ${actual_default_count}, expected ${expected_edge_count}"
[[ "${actual_postgres_count}" == "${expected_edge_count}" ]] ||
  fail "Postgres route-via/route-health row count is ${actual_postgres_count}, expected ${expected_edge_count}"

while read -r id; do
  [[ -n "${id}" ]] || continue
  expected_route_edge "${id}" ||
    fail "unexpected default route-via/route-health row ${id}; update the audit expected set"
done < <(
  awk '
    NR > 1 && $2 == "routes" && ($1 ~ /^route-via/ || $1 ~ /^route-health/) {
      print $1
    }
  ' <<<"${matrix_output}"
)

while read -r postgres_id; do
  [[ -n "${postgres_id}" ]] || continue
  id="${postgres_id#postgres-}"
  expected_route_edge "${id}" ||
    fail "unexpected Postgres route-via/route-health row ${postgres_id}; update the audit expected set"
done < <(
  awk '
    NR > 1 && $2 == "database" && ($1 ~ /^postgres-route-via/ || $1 ~ /^postgres-route-health/) {
      print $1
    }
  ' <<<"${matrix_output}"
)

if ((failed != 0)); then
  exit 2
fi

echo "route edge current-head audit passed for ${audit_target}: ${expected_edge_count} default route-via/route-health rows, ${expected_edge_count} Postgres mirrors, and current-head headscale-go pinning are present"
echo "headscale-go current-head pin: ${HEADSCALE_GO_CURRENT_VERSION}"
