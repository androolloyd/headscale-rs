#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workspace="${LEAN_WORKSPACE:-${repo_root}/proofs/lean}"
status_file="${FORMAL_STATUS_FILE:-${repo_root}/target/formal-verification-status.json}"

case "${workspace}" in
  /*) workspace_abs="${workspace}" ;;
  *) workspace_abs="${repo_root}/${workspace}" ;;
esac

case "${status_file}" in
  /*) status_file_abs="${status_file}" ;;
  *) status_file_abs="${repo_root}/${status_file}" ;;
esac

mkdir -p "$(dirname "${status_file_abs}")"

relative_to_repo() {
  local path="$1"
  case "${path}" in
    "${repo_root}") printf '.' ;;
    "${repo_root}"/*) printf '%s' "${path#"${repo_root}/"}" ;;
    *) printf '%s' "${path}" ;;
  esac
}

commit="$(git -C "${repo_root}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')"
workspace_rel="$(relative_to_repo "${workspace_abs}")"
status_rel="$(relative_to_repo "${status_file_abs}")"

emit_status() {
  local status="$1"
  local detail="$2"
  python3 - "$status" "$detail" "$workspace_rel" "$status_rel" "$commit" > "${status_file_abs}" <<'PY'
import json
import sys

status, detail, workspace, status_file, commit = sys.argv[1:]
print(
    json.dumps(
        {
            "status": status,
            "detail": detail,
            "workspace": workspace,
            "status_file": status_file,
            "commit": commit,
        },
        sort_keys=True,
    )
)
PY
  cat "${status_file_abs}"

  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
      echo "### Formal verification status"
      echo
      echo "- status: ${status}"
      echo "- workspace: ${workspace_rel}"
      echo "- detail: ${detail}"
      echo "- status file: ${status_rel}"
    } >> "${GITHUB_STEP_SUMMARY}"
  fi
}

if [[ ! -d "${workspace_abs}" ]]; then
  emit_status "absent" "Lean workspace directory is not present; no formal proof gate to run"
  exit 0
fi

if [[ ! -f "${workspace_abs}/lakefile.lean" && ! -f "${workspace_abs}/lakefile.toml" ]]; then
  emit_status "present-unconfigured" "Lean workspace directory exists but no lakefile.lean or lakefile.toml is present"
  exit 1
fi

if ! find "${workspace_abs}" -name '*.lean' -type f -print -quit | grep -q .; then
  emit_status "present-empty" "Lean workspace is configured but contains no .lean files"
  exit 1
fi

incomplete_matches="$(
  grep -R -n -E '(^|[^[:alnum:]_])(sorry|admit)([^[:alnum:]_]|$)' \
    --include='*.lean' \
    "${workspace_abs}" || true
)"
if [[ -n "${incomplete_matches}" ]]; then
  printf '%s\n' "${incomplete_matches}" >&2
  emit_status "present-incomplete" "Lean workspace contains sorry/admit placeholders"
  exit 1
fi

if ! command -v lake >/dev/null 2>&1; then
  emit_status "present-missing-lake" "Lean workspace is present but lake is not installed"
  exit 1
fi

if (cd "${workspace_abs}" && lake build); then
  emit_status "verified" "Lean workspace built successfully"
else
  emit_status "build-failed" "Lean workspace lake build failed"
  exit 1
fi
