#!/usr/bin/env bash
set -euo pipefail
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
  "$(dirname "$0")/audit-log-nodeattrs-common.sh"
