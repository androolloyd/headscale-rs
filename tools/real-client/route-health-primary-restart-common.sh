#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

target="${REAL_CLIENT_RESTART_TARGET:-}"
case "${target}" in
  rust | headscale-go) ;;
  *)
    echo "REAL_CLIENT_RESTART_TARGET must be rust or headscale-go" >&2
    exit 2
    ;;
esac

database_backend="${REAL_CLIENT_DATABASE_BACKEND:-sqlite}"
route="${REAL_CLIENT_RESTART_ROUTE:-10.91.0.0/24}"
base_work_root="${REAL_CLIENT_WORKDIR:-target/real-client/route-health-primary-restart-${target}}"
unique_root_suffix="primary-owner-$(date +%s)-$$"
case "${base_work_root}" in
  /*) run_root="${base_work_root}/${unique_root_suffix}" ;;
  *) run_root="${repo_root}/${base_work_root}/${unique_root_suffix}" ;;
esac

if [[ "${database_backend}" == "postgres" && -z "${HEADSCALE_DB_POSTGRES_TEST_URL:-}" ]]; then
  echo "skipping Postgres route-health primary restart smoke: HEADSCALE_DB_POSTGRES_TEST_URL is not set" >&2
  exit 0
fi

REAL_CLIENT_RESTART_TARGET="${target}" \
REAL_CLIENT_DATABASE_BACKEND="${database_backend}" \
REAL_CLIENT_RESTART_ROUTE_HEALTH=true \
REAL_CLIENT_WORKDIR="${run_root}" \
REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-240}" \
REAL_CLIENT_RESTART_ROUTE="${route}" \
REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS="${REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS:-2}" \
REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS="${REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS:-1}" \
  tools/real-client/restart-persistence-common.sh

shopt -s nullglob
restart_runs=("${run_root}"/hs-restart-"${target}"-*)
shopt -u nullglob
if ((${#restart_runs[@]} != 1)); then
  echo "expected one restart smoke run under ${run_root}, got ${#restart_runs[@]}" >&2
  exit 1
fi

run_dir="${restart_runs[0]}"
before_path="${run_dir}/route-health-primary-before-restart.json"
after_path="${run_dir}/route-health-primary-after-restart.json"

if [[ ! -s "${before_path}" || ! -s "${after_path}" ]]; then
  if [[ "${database_backend}" == "postgres" && -s "${run_dir}/postgres-create.stderr" ]]; then
    echo "skipping Postgres route-health primary restart owner assertion: restart smoke did not produce snapshots" >&2
    exit 0
  fi
  echo "missing route-health primary restart snapshots under ${run_dir}" >&2
  exit 1
fi

ruby -rjson -e '
  route = ARGV.fetch(2)
  before = JSON.parse(File.read(ARGV.fetch(0)))
  after = JSON.parse(File.read(ARGV.fetch(1)))

  def node_id(node)
    node["id"] || node["ID"] || node["nodeId"] || node["node_id"]
  end

  def node_name(node)
    node["givenName"] || node["given_name"] || node["name"] || node["hostname"]
  end

  before_primary = before.fetch("primary")
  after_primary = after.fetch("primary")
  before_id = node_id(before_primary)
  after_id = node_id(after_primary)
  before_name = node_name(before_primary)
  after_name = node_name(after_primary)

  if before_id && after_id
    abort("expected route-health primary for #{route} to survive restart, got #{before_id.inspect} before and #{after_id.inspect} after") unless before_id.to_s == after_id.to_s
  elsif before_name && after_name
    abort("expected route-health primary for #{route} to survive restart, got #{before_name.inspect} before and #{after_name.inspect} after") unless before_name.to_s == after_name.to_s
  else
    abort("could not compare route-health primary snapshots: before=#{before_primary.inspect} after=#{after_primary.inspect}")
  end

  puts JSON.pretty_generate({
    route: route,
    primary_owner: {
      id: before_id,
      name: before_name,
    },
    before_restart: before_primary,
    after_restart: after_primary,
  })
' "${before_path}" "${after_path}" "${route}" >"${run_dir}/route-health-primary-restart-preserved.json"

cat "${run_dir}/route-health-primary-restart-preserved.json"
