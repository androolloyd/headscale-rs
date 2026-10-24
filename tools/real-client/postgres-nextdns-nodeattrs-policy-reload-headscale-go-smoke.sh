#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

HEADSCALE_GO_VERSION="${HEADSCALE_GO_VERSION:-v0.29.5}" \
REAL_CLIENT_WORKDIR="${REAL_CLIENT_WORKDIR:-target/real-client/postgres-nextdns-nodeattrs-policy-reload-headscale-go-smoke}" \
REAL_CLIENT_ONLINE_LASTSEEN_TARGET=headscale-go \
  tools/real-client/postgres-nextdns-nodeattrs-policy-reload-common.sh
