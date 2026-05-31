#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${repo_root}"

smoke_spec="${REAL_CLIENT_SMOKES:-authkey}"
target_spec="${REAL_CLIENT_TARGETS:-rust headscale-go}"
list_only=0
arg_smokes=()

usage() {
  cat <<'EOF'
Usage: tools/real-client/smoke-matrix.sh [--list] [--rust|--headscale-go|--both] [--all] [SMOKE...]

Run paired stock-client smoke scripts against headscale-rs and/or pinned
headscale-go. SMOKE values are the IDs printed by --list.

Environment:
  REAL_CLIENT_SMOKES    Space- or comma-separated smoke IDs, or all.
                       Defaults to authkey.
  REAL_CLIENT_TARGETS   Space- or comma-separated targets: rust, headscale-go.
                       Defaults to both targets.

Examples:
  tools/real-client/smoke-matrix.sh --list
  REAL_CLIENT_SMOKES=authkey,magicdns REAL_CLIENT_TARGETS=rust tools/real-client/smoke-matrix.sh
  REAL_CLIENT_SMOKES=all REAL_CLIENT_TARGETS='rust headscale-go' tools/real-client/smoke-matrix.sh
EOF
}

while (($# > 0)); do
  case "$1" in
    --list)
      list_only=1
      ;;
    --rust)
      target_spec="rust"
      ;;
    --headscale-go)
      target_spec="headscale-go"
      ;;
    --both)
      target_spec="rust headscale-go"
      ;;
    --all)
      smoke_spec="all"
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    -*)
      echo "unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
    *)
      arg_smokes+=("$1")
      ;;
  esac
  shift
done

if ((${#arg_smokes[@]} > 0)); then
  smoke_spec="${arg_smokes[*]}"
fi

smoke_ids=(
  authkey
  postgres-authkey
  postgres-online-lastseen
  postgres-magicdns-custom-domain
  postgres-extra-records
  postgres-dns-disabled
  postgres-web-register
  postgres-web-register-tags
  postgres-web-register-unowned-tag
  postgres-route-advertise
  postgres-route-approve
  postgres-route-exit-node
  postgres-web-register-route-approve
  postgres-oidc
  postgres-oidc-restart
  postgres-oidc-route-approve-restart
  postgres-ssh-oidc-check
  postgres-ssh-cli-check
  postgres-ssh-oidc-check-wrong-user
  postgres-ssh-oidc-check-deny
  postgres-ssh-oidc-check-cancel
  postgres-web-register-restart
  postgres-restart-persistence
  postgres-tagged-preauth
  postgres-tag-update
  postgres-tag-update-invalid
  postgres-tag-reauth-clear
  postgres-route-via-restart
  postgres-route-via-same-tag-restart
  postgres-route-via-reload-restart
  postgres-route-via-multiprefix-restart
  postgres-route-via-multiprefix-reload-restart
  postgres-route-health-restart
  postgres-route-health-primary-restart
  postgres-route-health-reload-restart
  postgres-route-health-all-unhealthy-restart
  postgres-route-health-all-unhealthy-reload-restart
  postgres-route-health-mixed-exit-restart
  postgres-route-health-mixed-exit-reload-restart
  postgres-route-health-mixed-exit-all-unhealthy-restart
  postgres-route-health-mixed-exit-all-unhealthy-reload-restart
  ping-lifecycle
  web-register
  web-register-tags
  web-register-unowned-tag
  oidc
  ssh-oidc-check
  ssh-cli-check
  ssh-oidc-check-wrong-user
  ssh-oidc-check-deny
  ssh-oidc-check-cancel
  oidc-restart
  oidc-route-approve-restart
  web-register-restart
  online-lastseen
  restart-persistence
  tagged-preauth
  tag-update
  tag-update-invalid
  tag-reauth-clear
  magicdns
  magicdns-custom-domain
  extra-records
  dns-edge
  dns-hot-reload
  magicdns-ipv6-only
  dns-disabled
  prefix-family-dual-stack
  prefix-family-v4-to-dual-backfill
  prefix-family-dual-stack-to-ipv4-only-backfill
  prefix-family-dual-stack-to-ipv6-only-backfill
  prefix-family-ipv4-only
  prefix-family-ipv6-only
  acl-allow
  acl-empty
  acl-autogroup-self
  route-advertise
  route-approve
  route-primary
  route-primary-failover
  route-primary-sticky
  route-primary-withdraw
  route-exit-node
  route-via
  route-via-same-tag
  route-via-health
  route-via-reload
  route-via-restart
  route-via-multiprefix
  route-via-multiprefix-reload
  route-via-multiprefix-restart
  route-health
  route-health-reload
  route-health-reload-restart
  route-health-restart
  route-health-primary-restart
  route-health-all-unhealthy
  route-health-all-unhealthy-reload
  route-health-all-unhealthy-restart
  route-health-mixed-exit
  route-health-mixed-exit-reload
  route-health-mixed-exit-restart
  route-health-mixed-exit-all-unhealthy
  route-health-mixed-exit-all-unhealthy-reload
  route-health-mixed-exit-all-unhealthy-restart
  derp-private
  ssh
  ssh-localpart
  ssh-profile-variants
  ssh-accept-env
)

smoke_areas=(
  registration
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  database
  registration
  registration
  registration
  registration
  registration
  ssh
  ssh
  ssh
  ssh
  ssh
  lifecycle
  lifecycle
  lifecycle
  lifecycle
  lifecycle
  tags
  tags
  tags
  tags
  dns
  dns
  dns
  dns
  dns
  dns
  dns
  addresses
  addresses
  addresses
  addresses
  addresses
  addresses
  acl
  acl
  acl
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  routes
  derp
  ssh
  ssh
  ssh
  ssh
)

smoke_rust_scripts=(
  tools/real-client/authkey-smoke.sh
  tools/real-client/postgres-authkey-smoke.sh
  tools/real-client/postgres-online-lastseen-smoke.sh
  tools/real-client/postgres-magicdns-custom-domain-smoke.sh
  tools/real-client/postgres-extra-records-smoke.sh
  tools/real-client/postgres-dns-disabled-smoke.sh
  tools/real-client/postgres-web-register-smoke.sh
  tools/real-client/postgres-web-register-tags-smoke.sh
  tools/real-client/postgres-web-register-unowned-tag-smoke.sh
  tools/real-client/postgres-route-advertise-smoke.sh
  tools/real-client/postgres-route-approve-smoke.sh
  tools/real-client/postgres-route-exit-node-smoke.sh
  tools/real-client/postgres-web-register-route-approve-smoke.sh
  tools/real-client/postgres-oidc-smoke.sh
  tools/real-client/postgres-oidc-restart-smoke.sh
  tools/real-client/postgres-oidc-route-approve-restart-smoke.sh
  tools/real-client/postgres-ssh-oidc-check-smoke.sh
  tools/real-client/postgres-ssh-cli-check-smoke.sh
  tools/real-client/postgres-ssh-oidc-check-wrong-user-smoke.sh
  tools/real-client/postgres-ssh-oidc-check-deny-smoke.sh
  tools/real-client/postgres-ssh-oidc-check-cancel-smoke.sh
  tools/real-client/postgres-web-register-restart-smoke.sh
  tools/real-client/postgres-restart-persistence-smoke.sh
  tools/real-client/postgres-tagged-preauth-smoke.sh
  tools/real-client/postgres-tag-update-smoke.sh
  tools/real-client/postgres-tag-update-invalid-smoke.sh
  tools/real-client/postgres-tag-reauth-clear-smoke.sh
  tools/real-client/postgres-route-via-restart-smoke.sh
  tools/real-client/postgres-route-via-same-tag-restart-smoke.sh
  tools/real-client/postgres-route-via-reload-restart-smoke.sh
  tools/real-client/postgres-route-via-multiprefix-restart-smoke.sh
  tools/real-client/postgres-route-via-multiprefix-reload-restart-smoke.sh
  tools/real-client/postgres-route-health-restart-smoke.sh
  tools/real-client/postgres-route-health-primary-restart-smoke.sh
  tools/real-client/postgres-route-health-reload-restart-smoke.sh
  tools/real-client/postgres-route-health-all-unhealthy-restart-smoke.sh
  tools/real-client/postgres-route-health-all-unhealthy-reload-restart-smoke.sh
  tools/real-client/postgres-route-health-mixed-exit-restart-smoke.sh
  tools/real-client/postgres-route-health-mixed-exit-reload-restart-smoke.sh
  tools/real-client/postgres-route-health-mixed-exit-all-unhealthy-restart-smoke.sh
  tools/real-client/postgres-route-health-mixed-exit-all-unhealthy-reload-restart-smoke.sh
  tools/real-client/ping-lifecycle-smoke.sh
  tools/real-client/web-register-smoke.sh
  tools/real-client/web-register-tags-smoke.sh
  tools/real-client/web-register-unowned-tag-smoke.sh
  tools/real-client/oidc-smoke.sh
  tools/real-client/ssh-oidc-check-smoke.sh
  tools/real-client/ssh-cli-check-smoke.sh
  tools/real-client/ssh-oidc-check-wrong-user-smoke.sh
  tools/real-client/ssh-oidc-check-deny-smoke.sh
  tools/real-client/ssh-oidc-check-cancel-smoke.sh
  tools/real-client/oidc-restart-smoke.sh
  tools/real-client/oidc-route-approve-restart-smoke.sh
  tools/real-client/web-register-restart-smoke.sh
  tools/real-client/online-lastseen-smoke.sh
  tools/real-client/restart-persistence-smoke.sh
  tools/real-client/tagged-preauth-smoke.sh
  tools/real-client/tag-update-smoke.sh
  tools/real-client/tag-update-invalid-smoke.sh
  tools/real-client/tag-reauth-clear-smoke.sh
  tools/real-client/magicdns-smoke.sh
  tools/real-client/magicdns-custom-domain-smoke.sh
  tools/real-client/extra-records-smoke.sh
  tools/real-client/dns-edge-smoke.sh
  tools/real-client/dns-hot-reload-smoke.sh
  tools/real-client/magicdns-ipv6-only-smoke.sh
  tools/real-client/dns-disabled-smoke.sh
  tools/real-client/prefix-family-dual-stack-smoke.sh
  tools/real-client/prefix-family-v4-to-dual-backfill-smoke.sh
  tools/real-client/prefix-family-dual-stack-to-ipv4-only-backfill-smoke.sh
  tools/real-client/prefix-family-dual-stack-to-ipv6-only-backfill-smoke.sh
  tools/real-client/prefix-family-ipv4-only-smoke.sh
  tools/real-client/prefix-family-ipv6-only-smoke.sh
  tools/real-client/acl-allow-smoke.sh
  tools/real-client/acl-empty-smoke.sh
  tools/real-client/acl-autogroup-self-smoke.sh
  tools/real-client/route-advertise-smoke.sh
  tools/real-client/route-approve-smoke.sh
  tools/real-client/route-primary-smoke.sh
  tools/real-client/route-primary-failover-smoke.sh
  tools/real-client/route-primary-sticky-smoke.sh
  tools/real-client/route-primary-withdraw-smoke.sh
  tools/real-client/route-exit-node-smoke.sh
  tools/real-client/route-via-smoke.sh
  tools/real-client/route-via-same-tag-smoke.sh
  tools/real-client/route-via-health-smoke.sh
  tools/real-client/route-via-reload-smoke.sh
  tools/real-client/route-via-restart-smoke.sh
  tools/real-client/route-via-multiprefix-smoke.sh
  tools/real-client/route-via-multiprefix-reload-smoke.sh
  tools/real-client/route-via-multiprefix-restart-smoke.sh
  tools/real-client/route-health-smoke.sh
  tools/real-client/route-health-reload-smoke.sh
  tools/real-client/route-health-reload-restart-smoke.sh
  tools/real-client/route-health-restart-smoke.sh
  tools/real-client/route-health-primary-restart-smoke.sh
  tools/real-client/route-health-all-unhealthy-smoke.sh
  tools/real-client/route-health-all-unhealthy-reload-smoke.sh
  tools/real-client/route-health-all-unhealthy-restart-smoke.sh
  tools/real-client/route-health-mixed-exit-smoke.sh
  tools/real-client/route-health-mixed-exit-reload-smoke.sh
  tools/real-client/route-health-mixed-exit-restart-smoke.sh
  tools/real-client/route-health-mixed-exit-all-unhealthy-smoke.sh
  tools/real-client/route-health-mixed-exit-all-unhealthy-reload-smoke.sh
  tools/real-client/route-health-mixed-exit-all-unhealthy-restart-smoke.sh
  tools/real-client/derp-private-smoke.sh
  tools/real-client/ssh-smoke.sh
  tools/real-client/ssh-localpart-smoke.sh
  tools/real-client/ssh-profile-variants-smoke.sh
  tools/real-client/ssh-accept-env-smoke.sh
)

smoke_go_scripts=(
  tools/real-client/authkey-headscale-go-smoke.sh
  tools/real-client/postgres-authkey-headscale-go-smoke.sh
  tools/real-client/postgres-online-lastseen-headscale-go-smoke.sh
  tools/real-client/postgres-magicdns-custom-domain-headscale-go-smoke.sh
  tools/real-client/postgres-extra-records-headscale-go-smoke.sh
  tools/real-client/postgres-dns-disabled-headscale-go-smoke.sh
  tools/real-client/postgres-web-register-headscale-go-smoke.sh
  tools/real-client/postgres-web-register-tags-headscale-go-smoke.sh
  tools/real-client/postgres-web-register-unowned-tag-headscale-go-smoke.sh
  tools/real-client/postgres-route-advertise-headscale-go-smoke.sh
  tools/real-client/postgres-route-approve-headscale-go-smoke.sh
  tools/real-client/postgres-route-exit-node-headscale-go-smoke.sh
  tools/real-client/postgres-web-register-route-approve-headscale-go-smoke.sh
  tools/real-client/postgres-oidc-headscale-go-smoke.sh
  tools/real-client/postgres-oidc-restart-headscale-go-smoke.sh
  tools/real-client/postgres-oidc-route-approve-restart-headscale-go-smoke.sh
  tools/real-client/postgres-ssh-oidc-check-headscale-go-smoke.sh
  tools/real-client/postgres-ssh-cli-check-headscale-go-smoke.sh
  tools/real-client/postgres-ssh-oidc-check-wrong-user-headscale-go-smoke.sh
  tools/real-client/postgres-ssh-oidc-check-deny-headscale-go-smoke.sh
  tools/real-client/postgres-ssh-oidc-check-cancel-headscale-go-smoke.sh
  tools/real-client/postgres-web-register-restart-headscale-go-smoke.sh
  tools/real-client/postgres-restart-persistence-headscale-go-smoke.sh
  tools/real-client/postgres-tagged-preauth-headscale-go-smoke.sh
  tools/real-client/postgres-tag-update-headscale-go-smoke.sh
  tools/real-client/postgres-tag-update-invalid-headscale-go-smoke.sh
  tools/real-client/postgres-tag-reauth-clear-headscale-go-smoke.sh
  tools/real-client/postgres-route-via-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-via-same-tag-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-via-reload-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-via-multiprefix-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-via-multiprefix-reload-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-health-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-health-primary-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-health-reload-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-health-all-unhealthy-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-health-all-unhealthy-reload-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-health-mixed-exit-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-health-mixed-exit-reload-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-health-mixed-exit-all-unhealthy-restart-headscale-go-smoke.sh
  tools/real-client/postgres-route-health-mixed-exit-all-unhealthy-reload-restart-headscale-go-smoke.sh
  tools/real-client/ping-lifecycle-headscale-go-smoke.sh
  tools/real-client/web-register-headscale-go-smoke.sh
  tools/real-client/web-register-tags-headscale-go-smoke.sh
  tools/real-client/web-register-unowned-tag-headscale-go-smoke.sh
  tools/real-client/oidc-headscale-go-smoke.sh
  tools/real-client/ssh-oidc-check-headscale-go-smoke.sh
  tools/real-client/ssh-cli-check-headscale-go-smoke.sh
  tools/real-client/ssh-oidc-check-wrong-user-headscale-go-smoke.sh
  tools/real-client/ssh-oidc-check-deny-headscale-go-smoke.sh
  tools/real-client/ssh-oidc-check-cancel-headscale-go-smoke.sh
  tools/real-client/oidc-restart-headscale-go-smoke.sh
  tools/real-client/oidc-route-approve-restart-headscale-go-smoke.sh
  tools/real-client/web-register-restart-headscale-go-smoke.sh
  tools/real-client/online-lastseen-headscale-go-smoke.sh
  tools/real-client/restart-persistence-headscale-go-smoke.sh
  tools/real-client/tagged-preauth-headscale-go-smoke.sh
  tools/real-client/tag-update-headscale-go-smoke.sh
  tools/real-client/tag-update-invalid-headscale-go-smoke.sh
  tools/real-client/tag-reauth-clear-headscale-go-smoke.sh
  tools/real-client/magicdns-headscale-go-smoke.sh
  tools/real-client/magicdns-custom-domain-headscale-go-smoke.sh
  tools/real-client/extra-records-headscale-go-smoke.sh
  tools/real-client/dns-edge-headscale-go-smoke.sh
  tools/real-client/dns-hot-reload-headscale-go-smoke.sh
  tools/real-client/magicdns-ipv6-only-headscale-go-smoke.sh
  tools/real-client/dns-disabled-headscale-go-smoke.sh
  tools/real-client/prefix-family-dual-stack-headscale-go-smoke.sh
  tools/real-client/prefix-family-v4-to-dual-backfill-headscale-go-smoke.sh
  tools/real-client/prefix-family-dual-stack-to-ipv4-only-backfill-headscale-go-smoke.sh
  tools/real-client/prefix-family-dual-stack-to-ipv6-only-backfill-headscale-go-smoke.sh
  tools/real-client/prefix-family-ipv4-only-headscale-go-smoke.sh
  tools/real-client/prefix-family-ipv6-only-headscale-go-smoke.sh
  tools/real-client/acl-allow-headscale-go-smoke.sh
  tools/real-client/acl-empty-headscale-go-smoke.sh
  tools/real-client/acl-autogroup-self-headscale-go-smoke.sh
  tools/real-client/route-advertise-headscale-go-smoke.sh
  tools/real-client/route-approve-headscale-go-smoke.sh
  tools/real-client/route-primary-headscale-go-smoke.sh
  tools/real-client/route-primary-failover-headscale-go-smoke.sh
  tools/real-client/route-primary-sticky-headscale-go-smoke.sh
  tools/real-client/route-primary-withdraw-headscale-go-smoke.sh
  tools/real-client/route-exit-node-headscale-go-smoke.sh
  tools/real-client/route-via-headscale-go-smoke.sh
  tools/real-client/route-via-same-tag-headscale-go-smoke.sh
  tools/real-client/route-via-health-headscale-go-smoke.sh
  tools/real-client/route-via-reload-headscale-go-smoke.sh
  tools/real-client/route-via-restart-headscale-go-smoke.sh
  tools/real-client/route-via-multiprefix-headscale-go-smoke.sh
  tools/real-client/route-via-multiprefix-reload-headscale-go-smoke.sh
  tools/real-client/route-via-multiprefix-restart-headscale-go-smoke.sh
  tools/real-client/route-health-headscale-go-smoke.sh
  tools/real-client/route-health-reload-headscale-go-smoke.sh
  tools/real-client/route-health-reload-restart-headscale-go-smoke.sh
  tools/real-client/route-health-restart-headscale-go-smoke.sh
  tools/real-client/route-health-primary-restart-headscale-go-smoke.sh
  tools/real-client/route-health-all-unhealthy-headscale-go-smoke.sh
  tools/real-client/route-health-all-unhealthy-reload-headscale-go-smoke.sh
  tools/real-client/route-health-all-unhealthy-restart-headscale-go-smoke.sh
  tools/real-client/route-health-mixed-exit-headscale-go-smoke.sh
  tools/real-client/route-health-mixed-exit-reload-headscale-go-smoke.sh
  tools/real-client/route-health-mixed-exit-restart-headscale-go-smoke.sh
  tools/real-client/route-health-mixed-exit-all-unhealthy-headscale-go-smoke.sh
  tools/real-client/route-health-mixed-exit-all-unhealthy-reload-headscale-go-smoke.sh
  tools/real-client/route-health-mixed-exit-all-unhealthy-restart-headscale-go-smoke.sh
  tools/real-client/derp-private-headscale-go-smoke.sh
  tools/real-client/ssh-headscale-go-smoke.sh
  tools/real-client/ssh-localpart-headscale-go-smoke.sh
  tools/real-client/ssh-profile-variants-headscale-go-smoke.sh
  tools/real-client/ssh-accept-env-headscale-go-smoke.sh
)

smoke_assertions=(
  "auth-key login and one alice node"
  "production Postgres auth-key login, stock-client netmap, and online/LastSeen"
  "production Postgres online transition and LastSeen after disconnect"
  "production Postgres custom MagicDNS base domain"
  "production Postgres MagicDNS suffix and DNS extra record projection"
  "production Postgres MagicDNS disabled fallback names"
  "production Postgres web registration, stock-client netmap, and online/LastSeen"
  "production Postgres web registration with owned requested tag"
  "production Postgres web registration rejects unowned requested tag"
  "production Postgres route advertisement without approval"
  "production Postgres route advertisement/approval, stock-client netmap, and online/LastSeen"
  "production Postgres exit-node route advertisement/approval"
  "production Postgres web registration with route advertisement/approval"
  "production Postgres OIDC registration, user profile rows, stock-client netmap, and node state"
  "production Postgres OIDC registration survives server restart"
  "production Postgres OIDC route approval survives server restart"
  "production Postgres OIDC-backed Tailscale SSH check approval"
  "production Postgres CLI-approved Tailscale SSH check approval"
  "production Postgres wrong-user OIDC-backed Tailscale SSH check denial status/stdout/stderr"
  "production Postgres expired OIDC-backed Tailscale SSH check denial status/stdout/stderr"
  "production Postgres cancelled OIDC-backed Tailscale SSH check denial status/stdout/stderr"
  "production Postgres web registration survives server restart"
  "production Postgres restart persistence and route/tag map churn"
  "production Postgres preauth key with ACL tag owners"
  "production Postgres post-login tag replacement"
  "production Postgres invalid tag update rejection"
  "production Postgres web reauth clears forced tags"
  "production Postgres current-head grants via survives server restart"
  "production Postgres current-head same-tag grants via survives server restart"
  "production Postgres current-head grants via policy reload survives server restart"
  "production Postgres current-head multi-prefix grants via survives server restart"
  "production Postgres current-head multi-prefix grants via policy reload survives server restart"
  "production Postgres current-head route-health survives server restart"
  "production Postgres route-health primary selection survives server restart"
  "production Postgres route-health policy reload survives server restart"
  "production Postgres route-health all-unhealthy retention survives server restart"
  "production Postgres route-health all-unhealthy policy reload survives server restart"
  "production Postgres route-health mixed exit-node separation survives server restart"
  "production Postgres route-health mixed exit-node policy reload survives server restart"
  "production Postgres route-health mixed exit-node all-unhealthy retention survives server restart"
  "production Postgres route-health mixed exit-node all-unhealthy policy reload survives server restart"
  "debug PingRequest dispatch and public HEAD callback correlation"
  "no-auth pending registration and CLI approval"
  "web registration with owned requested tag"
  "web registration rejects unowned requested tag"
  "OIDC callback, node row, and user profile"
  "OIDC-backed Tailscale SSH check approval; opt-in checkPeriod cache variant"
  "CLI-approved Tailscale SSH check approval"
  "wrong-user OIDC-backed Tailscale SSH check denial status/stdout/stderr"
  "expired OIDC-backed Tailscale SSH check denial status/stdout/stderr"
  "cancelled OIDC-backed Tailscale SSH check denial status/stdout/stderr"
  "Production OIDC registration survives server restart"
  "Production OIDC route approval survives server restart"
  "Production web/CLI registration survives server restart"
  "production online transition and LastSeen after disconnect"
  "production restart persistence and route/tag netmap churn"
  "preauth key with ACL tag owners"
  "post-login tag replacement"
  "invalid tag update rejection"
  "web reauth clears forced tags"
  "MagicDNS suffix and peer DNS names"
  "custom DNS base domain"
  "extra DNS A record in client netmap"
  "split DNS routes plus AAAA/CNAME extra records"
  "production extra-records file hot reload in client netmap"
  "MagicDNS with IPv6-only prefix-family allocation"
  "MagicDNS disabled fallback names"
  "Dual-stack prefix-family allocation"
  "IPv4-to-dual-stack backfill after prefix migration"
  "Dual-stack-to-IPv4-only backfill after prefix-family removal"
  "Dual-stack-to-IPv6-only backfill after prefix-family removal"
  "IPv4-only prefix-family allocation"
  "IPv6-only prefix-family allocation"
  "allowed peers visible"
  "empty ACL peer visibility edge"
  "autogroup:self peer isolation"
  "advertised route recorded"
  "route approval recorded"
  "single primary route owner"
  "primary route failover"
  "sticky primary route ownership"
  "withdrawn primary route failover"
  "exit-node route advertisement and approval"
  "current-head route steering with grants via"
  "current-head same-tag multi-router grants via election"
  "current-head regular-overlap same-tag grants via follows route-health failover"
  "current-head route steering policy reload moves grants via ownership"
  "current-head route steering with grants via survives server restart"
  "current-head multi-prefix route steering with grants via"
  "current-head multi-prefix route steering policy reload moves grants via ownership"
  "current-head multi-prefix route steering with grants via survives server restart"
  "current-head route-health failover and sticky recovery"
  "current-head route-health policy reload expands HA failover"
  "current-head route-health policy reload expansion survives production restart"
  "current-head route-health production restart failover"
  "current-head route-health primary selection survives server restart"
  "current-head route-health all-unavailable last-known-primary retention"
  "current-head route-health policy reload preserves all-unavailable last-known-primary retention"
  "current-head route-health production restart preserves all-unavailable last-known-primary retention"
  "current-head route-health ignores exit-only routes during HA failover"
  "current-head route-health policy reload preserves exit-node separation during HA failover"
  "current-head route-health mixed exit-node separation survives server restart"
  "current-head route-health mixed exit-node all-unavailable last-known subnet primary retention"
  "current-head route-health policy reload preserves mixed exit-node all-unavailable subnet primary retention"
  "current-head route-health mixed exit-node all-unavailable subnet primary retention survives server restart"
  "private DERP relay, STUN, verify-client admission, and DERP map metadata"
  "Tailscale SSH allow, deny, and ACL timeout"
  "current-head Tailscale SSH localpart login users from profile emails"
  "current-head Tailscale SSH profile email variants and exact denial status/stderr"
  "current-head Tailscale SSH acceptEnv forwards accepted LANG and LC_* env"
)

assert_matrix_lengths() {
  local expected="${#smoke_ids[@]}"
  if ((
    ${#smoke_areas[@]} != expected ||
      ${#smoke_rust_scripts[@]} != expected ||
      ${#smoke_go_scripts[@]} != expected ||
      ${#smoke_assertions[@]} != expected
  )); then
    echo "internal real-client smoke matrix length mismatch" >&2
    exit 2
  fi
}

split_words() {
  local value="$1"
  value="${value//,/ }"
  read -r -a split_result <<<"${value}"
}

known_smoke() {
  local candidate="$1"
  local id
  for id in "${smoke_ids[@]}"; do
    [[ "${candidate}" == "${id}" ]] && return 0
  done
  return 1
}

known_target() {
  case "$1" in
    rust | headscale-go) return 0 ;;
    *) return 1 ;;
  esac
}

selected_smoke() {
  local candidate="$1"
  local wanted
  for wanted in "${selected_smokes[@]}"; do
    [[ "${wanted}" == "all" || "${wanted}" == "${candidate}" ]] && return 0
  done
  return 1
}

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

print_matrix() {
  printf '%-28s %-14s %-52s %-62s %s\n' \
    "smoke" "area" "headscale-rs script" "headscale-go script" "assertion"
  local i
  for i in "${!smoke_ids[@]}"; do
    printf '%-28s %-14s %-52s %-62s %s\n' \
      "${smoke_ids[$i]}" \
      "${smoke_areas[$i]}" \
      "${smoke_rust_scripts[$i]}" \
      "${smoke_go_scripts[$i]}" \
      "${smoke_assertions[$i]}"
  done
}

assert_matrix_lengths

if ((list_only)); then
  print_matrix
  exit 0
fi

split_words "${smoke_spec}"
selected_smokes=("${split_result[@]}")
split_words "${target_spec}"
selected_targets=("${split_result[@]}")

if ((${#selected_smokes[@]} == 0)); then
  echo "no real-client smokes selected" >&2
  exit 2
fi
if ((${#selected_targets[@]} == 0)); then
  echo "no real-client targets selected" >&2
  exit 2
fi

for smoke in "${selected_smokes[@]}"; do
  if [[ "${smoke}" != "all" ]] && ! known_smoke "${smoke}"; then
    echo "unknown real-client smoke: ${smoke}" >&2
    echo "run tools/real-client/smoke-matrix.sh --list for valid smoke IDs" >&2
    exit 2
  fi
done

for target in "${selected_targets[@]}"; do
  if ! known_target "${target}"; then
    echo "unknown real-client target: ${target}" >&2
    echo "valid targets: rust, headscale-go" >&2
    exit 2
  fi
done

ran=0
for i in "${!smoke_ids[@]}"; do
  selected_smoke "${smoke_ids[$i]}" || continue
  for target in "${selected_targets[@]}"; do
    if [[ "${target}" == "rust" ]]; then
      script="${smoke_rust_scripts[$i]}"
    else
      script="${smoke_go_scripts[$i]}"
    fi

    group_start "real-client ${target} ${smoke_ids[$i]}"
    set +e
    "${repo_root}/${script}"
    status="$?"
    set -e
    group_end

    if ((status != 0)); then
      exit "${status}"
    fi
    ran=$((ran + 1))
  done
done

echo "real-client smoke matrix passed (${ran} script runs)"
