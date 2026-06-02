#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fuzz_dir="${FUZZ_DIR:-${repo_root}/headscale-core/fuzz}"
corpus_dir="${fuzz_dir}/corpus"

cd "${fuzz_dir}"

declare -A targets=()
while IFS= read -r target; do
  [[ -n "${target}" ]] && targets["${target}"]=1
done < <(python3 "${repo_root}/scripts/fuzz_targets.py")

if ((${#targets[@]} == 0)); then
  echo "no fuzz targets found" >&2
  exit 2
fi

declare -A checked_in_corpus_dirs=()
while IFS= read -r path; do
  rel="${path#headscale-core/fuzz/corpus/}"
  target="${rel%%/*}"
  [[ -n "${target}" && "${target}" != "${rel}" ]] && checked_in_corpus_dirs["${target}"]=1
done < <(git -C "${repo_root}" ls-files 'headscale-core/fuzz/corpus/*')

stale=()
for target in "${!checked_in_corpus_dirs[@]}"; do
  if [[ -z "${targets[${target}]:-}" ]]; then
    stale+=("${target}")
  fi
done

if ((${#stale[@]} > 0)); then
  printf 'stale checked-in fuzz corpus directories not present in fuzz manifest:\n' >&2
  printf '  %s\n' "${stale[@]}" | sort >&2
  exit 1
fi

missing=()
for target in "${!targets[@]}"; do
  if [[ -z "${checked_in_corpus_dirs[${target}]:-}" ]]; then
    missing+=("${target}")
  fi
done

if ((${#missing[@]} > 0)); then
  printf 'fuzz targets missing checked-in corpus seeds:\n' >&2
  printf '  %s\n' "${missing[@]}" | sort >&2
  exit 1
fi

echo "checked ${#checked_in_corpus_dirs[@]} checked-in fuzz corpus directories covering ${#targets[@]} fuzz targets"
