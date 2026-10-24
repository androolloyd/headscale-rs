#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

: "${REAL_CLIENT_ONLINE_LASTSEEN_TARGET:?set rust or headscale-go}"
base_policy='{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}'
audit_policy='{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"nodeAttrs":[{"target":["alice@"],"attr":["https://tailscale.com/cap/data-plane-audit-logs"]}]}'

for logtail_enabled in false true; do
  if [[ "${logtail_enabled}" == false ]]; then
    expected_state=Stopped
    recover_policy="${base_policy}"
  else
    expected_state=Running
    recover_policy=""
  fi
  echo "audit-log nodeAttrs: ${REAL_CLIENT_ONLINE_LASTSEEN_TARGET}, logtail=${logtail_enabled}, expected=${expected_state}"
  REAL_CLIENT_CLIENT_COUNT=1 \
  REAL_CLIENT_POLICY_JSON="${base_policy}" \
  REAL_CLIENT_RELOAD_POLICY_JSON="${audit_policy}" \
  REAL_CLIENT_AUDIT_RECOVER_POLICY_JSON="${recover_policy}" \
  REAL_CLIENT_EXPECT_PEER_COUNT=0 \
  REAL_CLIENT_EXPECT_PEER_COUNT_AFTER_POLICY_RELOAD=0 \
  REAL_CLIENT_LOGTAIL_ENABLED="${logtail_enabled}" \
  REAL_CLIENT_EXPECT_AUDIT_LOG_STATE="${expected_state}" \
  REAL_CLIENT_TIMEOUT_SECS="${REAL_CLIENT_TIMEOUT_SECS:-180}" \
  REAL_CLIENT_TAILSCALE_UP_TIMEOUT="${REAL_CLIENT_TAILSCALE_UP_TIMEOUT:-30s}" \
    tools/real-client/online-lastseen-common.sh
done
