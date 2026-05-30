#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_dir="${FUZZ_DIR:-${repo_root}/headscale-core/fuzz}"
runs="${FUZZ_RUNS:-10000}"
max_total_time="${FUZZ_MAX_TOTAL_TIME:-}"
timeout_secs="${FUZZ_TIMEOUT_SECS:-30}"
rss_limit_mb="${FUZZ_RSS_LIMIT_MB:-4096}"
seed="${FUZZ_SEED:-}"

cd "${fuzz_dir}"

declare -A valid_targets=()
while IFS= read -r target; do
  [[ -n "${target}" ]] && valid_targets["${target}"]=1
done < <(python3 "${repo_root}/scripts/fuzz_targets.py")

if ((${#valid_targets[@]} == 0)); then
  echo "no fuzz targets found" >&2
  exit 2
fi

targets=()
if [[ -n "${FUZZ_TARGETS:-}" ]]; then
  read -r -a targets <<< "${FUZZ_TARGETS}"
elif [[ -n "${FUZZ_TARGET:-}" ]]; then
  targets=("${FUZZ_TARGET}")
else
  while IFS= read -r target; do
    [[ -n "${target}" ]] && targets+=("${target}")
  done < <(printf '%s\n' "${!valid_targets[@]}" | sort)
fi

if ((${#targets[@]} == 0)); then
  echo "no fuzz targets found" >&2
  exit 2
fi

for target in "${targets[@]}"; do
  if [[ -z "${valid_targets[${target}]:-}" ]]; then
    echo "unknown fuzz target: ${target}" >&2
    echo "known fuzz targets:" >&2
    printf '  %s\n' "${!valid_targets[@]}" | sort >&2
    exit 2
  fi
done

group_start() {
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "::group::$*"
  else
    echo "==> $*"
  fi
}

group_end() {
  if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    echo "::endgroup::"
  fi
}

group_start "check locked fuzz manifest"
cargo check --locked --bins
group_end

for target in "${targets[@]}"; do
  group_start "build ${target}"
  set +e
  cargo fuzz build "${target}"
  status="$?"
  set -e
  group_end

  if ((status != 0)); then
    exit "${status}"
  fi
done

mkdir -p logs
for target in "${targets[@]}"; do
  mkdir -p "logs/${target}" "artifacts/${target}"

  fuzz_args=(
    "-timeout=${timeout_secs}"
    "-rss_limit_mb=${rss_limit_mb}"
    "-print_final_stats=1"
  )
  if [[ -n "${seed}" ]]; then
    fuzz_args+=("-seed=${seed}")
  fi
  if [[ -n "${max_total_time}" ]]; then
    fuzz_args+=("-max_total_time=${max_total_time}")
    log_name="max-${max_total_time}.log"
    run_label="${max_total_time}s"
  else
    fuzz_args+=("-runs=${runs}")
    log_name="runs-${runs}.log"
    run_label="${runs} inputs"
  fi

  group_start "run ${target} (${run_label})"
  set +e
  cargo fuzz run "${target}" -- "${fuzz_args[@]}" 2>&1 | tee "logs/${target}/${log_name}"
  status="${PIPESTATUS[0]}"
  set -e
  group_end

  if ((status != 0)); then
    exit "${status}"
  fi
done
