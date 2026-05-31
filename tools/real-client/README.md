# Real-Client Parity Harness

This directory is for end-to-end parity tests that run stock `tailscaled`
clients against both headscale-go and headscale-rs.

The first checked-in piece is a Rust wire-control harness:

```sh
cargo run --manifest-path tools/real-client/headscale-rs-harness/Cargo.toml -- \
  --http 0.0.0.0:51821 \
  --https 0.0.0.0:443 \
  --hostname headscale-rs.test \
  --public-url https://headscale-rs.test \
  --base-domain tail.test
```

It starts the headscale-rs Tailscale wire surface and adds harness-only routes:

- `GET /harness/health`
- `POST /harness/preauth`
- `PUT /harness/policy`
- `POST /harness/register/{registration_id}`
- `GET /harness/machines`
- `GET /harness/routes`
- `PUT /harness/machines/{node_key}/routes`

Mint an auth key for a stock client:

```sh
curl -sS -X POST http://127.0.0.1:51821/harness/preauth \
  -H 'content-type: application/json' \
  -d '{"user":"alice","reusable":true}'
```

Then run a client with that key:

```sh
tailscale up --login-server https://headscale-rs.test --authkey <key>
```

The harness prints the generated TLS certificate path on startup. Real client
jobs must install that certificate into the client trust store or terminate TLS
in front of the harness with a trusted certificate.

## Parity Plan

Use the upstream headscale-go v0.28 integration tests as the scenario inventory:

- auth key registration
- web registration
- OIDC registration
- ACL and tag behavior
- DNS and MagicDNS
- routes and exit nodes
- SSH policy
- embedded DERP and `/verify`
- API auth and CLI behavior

Each scenario should run the same stock `tailscaled` image against:

1. headscale-go v0.28.0, pinned by `tools/parity/headscale-go/go.mod`
2. this headscale-rs harness

Keep scenario assertions outside Octra-specific code. Octra can adapt by wiring
its own preauth, persistence, billing, and deployment concerns around the shared
headscale-rs wire surface.

## Smoke Coverage Matrix

Use `tools/real-client/smoke-matrix.sh --list` as the executable source of
truth for the checked-in real-client matrix. Each row has a Rust harness script
and a matching headscale-go script so parity work can compare behavior with the
same stock `tailscaled` image. Most headscale-go rows use the pinned v0.28.0
baseline; `ping-lifecycle` targets the current-head audit commit because v0.28.0
predates the executable PingRequest lifecycle.

| Area | Smoke ID | headscale-rs | headscale-go | Assertion focus |
| --- | --- | --- | --- | --- |
| Registration | `authkey` | `authkey-smoke.sh` | `authkey-headscale-go-smoke.sh` | Auth-key login and one `alice` node |
| Database | `postgres-authkey` | `postgres-authkey-smoke.sh` | `postgres-authkey-headscale-go-smoke.sh` | Production Postgres auth-key login, stock-client netmap, and online/LastSeen |
| Database | `postgres-online-lastseen` | `postgres-online-lastseen-smoke.sh` | `postgres-online-lastseen-headscale-go-smoke.sh` | Production Postgres online transition and LastSeen after client disconnect |
| Database | `postgres-ping-lifecycle` | `postgres-ping-lifecycle-smoke.sh` | `postgres-ping-lifecycle-headscale-go-smoke.sh` | Production Postgres debug PingRequest lifecycle and online/LastSeen |
| Database | `postgres-magicdns` | `postgres-magicdns-smoke.sh` | `postgres-magicdns-headscale-go-smoke.sh` | Production Postgres default MagicDNS suffix |
| Database | `postgres-magicdns-custom-domain` | `postgres-magicdns-custom-domain-smoke.sh` | `postgres-magicdns-custom-domain-headscale-go-smoke.sh` | Production Postgres custom MagicDNS base domain |
| Database | `postgres-extra-records` | `postgres-extra-records-smoke.sh` | `postgres-extra-records-headscale-go-smoke.sh` | Production Postgres MagicDNS suffix and DNS extra record projection |
| Database | `postgres-dns-disabled` | `postgres-dns-disabled-smoke.sh` | `postgres-dns-disabled-headscale-go-smoke.sh` | Production Postgres MagicDNS disabled fallback names |
| Database | `postgres-dns-edge` | `postgres-dns-edge-smoke.sh` | `postgres-dns-edge-headscale-go-smoke.sh` | Production Postgres split DNS routes, fallback resolver, and DNS edge records |
| Database | `postgres-dns-hot-reload` | `postgres-dns-hot-reload-smoke.sh` | `postgres-dns-hot-reload-headscale-go-smoke.sh` | Production Postgres DNS `extra_records` hot reload |
| Database | `postgres-magicdns-ipv6-only` | `postgres-magicdns-ipv6-only-smoke.sh` | `postgres-magicdns-ipv6-only-headscale-go-smoke.sh` | Production Postgres MagicDNS with IPv6-only prefix-family allocation |
| Database | `postgres-prefix-family-dual-stack` | `postgres-prefix-family-dual-stack-smoke.sh` | `postgres-prefix-family-dual-stack-headscale-go-smoke.sh` | Production Postgres dual-stack prefix-family allocation |
| Database | `postgres-prefix-family-ipv4-only` | `postgres-prefix-family-ipv4-only-smoke.sh` | `postgres-prefix-family-ipv4-only-headscale-go-smoke.sh` | Production Postgres IPv4-only prefix-family allocation |
| Database | `postgres-prefix-family-ipv6-only` | `postgres-prefix-family-ipv6-only-smoke.sh` | `postgres-prefix-family-ipv6-only-headscale-go-smoke.sh` | Production Postgres IPv6-only prefix-family allocation |
| Database | `postgres-web-register` | `postgres-web-register-smoke.sh` | `postgres-web-register-headscale-go-smoke.sh` | Production Postgres web registration, stock-client netmap, and online/LastSeen |
| Database | `postgres-web-register-tags` | `postgres-web-register-tags-smoke.sh` | `postgres-web-register-tags-headscale-go-smoke.sh` | Production Postgres web registration with owned requested tag |
| Database | `postgres-web-register-unowned-tag` | `postgres-web-register-unowned-tag-smoke.sh` | `postgres-web-register-unowned-tag-headscale-go-smoke.sh` | Production Postgres web registration rejects unowned requested tag |
| Database | `postgres-route-advertise` | `postgres-route-advertise-smoke.sh` | `postgres-route-advertise-headscale-go-smoke.sh` | Production Postgres route advertisement without approval |
| Database | `postgres-route-approve` | `postgres-route-approve-smoke.sh` | `postgres-route-approve-headscale-go-smoke.sh` | Production Postgres route advertisement/approval, stock-client netmap, and online/LastSeen |
| Database | `postgres-route-exit-node` | `postgres-route-exit-node-smoke.sh` | `postgres-route-exit-node-headscale-go-smoke.sh` | Production Postgres exit-node route advertisement/approval |
| Database | `postgres-web-register-route-approve` | `postgres-web-register-route-approve-smoke.sh` | `postgres-web-register-route-approve-headscale-go-smoke.sh` | Production Postgres web registration with route advertisement/approval |
| Database | `postgres-oidc` | `postgres-oidc-smoke.sh` | `postgres-oidc-headscale-go-smoke.sh` | Production Postgres OIDC registration, user profile rows, stock-client netmap, and node state |
| Database | `postgres-oidc-restart` | `postgres-oidc-restart-smoke.sh` | `postgres-oidc-restart-headscale-go-smoke.sh` | Production Postgres OIDC registration survives server restart |
| Database | `postgres-oidc-route-approve-restart` | `postgres-oidc-route-approve-restart-smoke.sh` | `postgres-oidc-route-approve-restart-headscale-go-smoke.sh` | Production Postgres OIDC route approval survives server restart |
| Database | `postgres-ssh-oidc-check` | `postgres-ssh-oidc-check-smoke.sh` | `postgres-ssh-oidc-check-headscale-go-smoke.sh` | Production Postgres OIDC-backed Tailscale SSH `check` approval |
| Database | `postgres-ssh-cli-check` | `postgres-ssh-cli-check-smoke.sh` | `postgres-ssh-cli-check-headscale-go-smoke.sh` | Production Postgres CLI-approved Tailscale SSH `check` approval |
| Database | `postgres-ssh-oidc-check-period-cache` | `postgres-ssh-oidc-check-period-cache-smoke.sh` | `postgres-ssh-oidc-check-period-cache-headscale-go-smoke.sh` | Production Postgres OIDC-backed Tailscale SSH `checkPeriod` cache |
| Database | `postgres-ssh-oidc-check-wrong-user` | `postgres-ssh-oidc-check-wrong-user-smoke.sh` | `postgres-ssh-oidc-check-wrong-user-headscale-go-smoke.sh` | Production Postgres wrong-user OIDC-backed Tailscale SSH `check` denial |
| Database | `postgres-ssh-oidc-check-deny` | `postgres-ssh-oidc-check-deny-smoke.sh` | `postgres-ssh-oidc-check-deny-headscale-go-smoke.sh` | Production Postgres expired OIDC-backed Tailscale SSH `check` denial |
| Database | `postgres-ssh-oidc-check-cancel` | `postgres-ssh-oidc-check-cancel-smoke.sh` | `postgres-ssh-oidc-check-cancel-headscale-go-smoke.sh` | Production Postgres cancelled OIDC-backed Tailscale SSH `check` denial |
| Database | `postgres-web-register-restart` | `postgres-web-register-restart-smoke.sh` | `postgres-web-register-restart-headscale-go-smoke.sh` | Production Postgres web registration survives server restart |
| Database | `postgres-restart-persistence` | `postgres-restart-persistence-smoke.sh` | `postgres-restart-persistence-headscale-go-smoke.sh` | Production Postgres restart persistence and route/tag map churn |
| Database | `postgres-tagged-preauth` | `postgres-tagged-preauth-smoke.sh` | `postgres-tagged-preauth-headscale-go-smoke.sh` | Production Postgres preauth key with ACL tag owners |
| Database | `postgres-tag-update` | `postgres-tag-update-smoke.sh` | `postgres-tag-update-headscale-go-smoke.sh` | Production Postgres post-login forced tag replacement |
| Database | `postgres-tag-update-invalid` | `postgres-tag-update-invalid-smoke.sh` | `postgres-tag-update-invalid-headscale-go-smoke.sh` | Production Postgres invalid forced tag rejection |
| Database | `postgres-tag-reauth-clear` | `postgres-tag-reauth-clear-smoke.sh` | `postgres-tag-reauth-clear-headscale-go-smoke.sh` | Production Postgres web reauth clears forced tags |
| Database | `postgres-route-via-restart` | `postgres-route-via-restart-smoke.sh` | `postgres-route-via-restart-headscale-go-smoke.sh` | Production Postgres current-head `grants[].via` survives server restart |
| Database | `postgres-route-via-same-tag-restart` | `postgres-route-via-same-tag-restart-smoke.sh` | `postgres-route-via-same-tag-restart-headscale-go-smoke.sh` | Production Postgres current-head same-tag `grants[].via` survives server restart |
| Database | `postgres-route-via-reload-restart` | `postgres-route-via-reload-restart-smoke.sh` | `postgres-route-via-reload-restart-headscale-go-smoke.sh` | Production Postgres current-head `grants[].via` policy reload survives server restart |
| Database | `postgres-route-via-multiprefix-restart` | `postgres-route-via-multiprefix-restart-smoke.sh` | `postgres-route-via-multiprefix-restart-headscale-go-smoke.sh` | Production Postgres current-head multi-prefix `grants[].via` survives server restart |
| Database | `postgres-route-via-multiprefix-reload-restart` | `postgres-route-via-multiprefix-reload-restart-smoke.sh` | `postgres-route-via-multiprefix-reload-restart-headscale-go-smoke.sh` | Production Postgres current-head multi-prefix `grants[].via` policy reload survives server restart |
| Database | `postgres-route-health-restart` | `postgres-route-health-restart-smoke.sh` | `postgres-route-health-restart-headscale-go-smoke.sh` | Production Postgres current-head route-health survives server restart |
| Database | `postgres-route-health-primary-restart` | `postgres-route-health-primary-restart-smoke.sh` | `postgres-route-health-primary-restart-headscale-go-smoke.sh` | Production Postgres route-health primary selection survives server restart |
| Database | `postgres-route-health-reload-restart` | `postgres-route-health-reload-restart-smoke.sh` | `postgres-route-health-reload-restart-headscale-go-smoke.sh` | Production Postgres route-health policy reload survives server restart |
| Database | `postgres-route-health-all-unhealthy-restart` | `postgres-route-health-all-unhealthy-restart-smoke.sh` | `postgres-route-health-all-unhealthy-restart-headscale-go-smoke.sh` | Production Postgres route-health all-unhealthy retention survives server restart |
| Database | `postgres-route-health-all-unhealthy-reload-restart` | `postgres-route-health-all-unhealthy-reload-restart-smoke.sh` | `postgres-route-health-all-unhealthy-reload-restart-headscale-go-smoke.sh` | Production Postgres route-health all-unhealthy policy reload survives server restart |
| Database | `postgres-route-health-mixed-exit-restart` | `postgres-route-health-mixed-exit-restart-smoke.sh` | `postgres-route-health-mixed-exit-restart-headscale-go-smoke.sh` | Production Postgres route-health mixed exit-node separation survives server restart |
| Database | `postgres-route-health-mixed-exit-reload-restart` | `postgres-route-health-mixed-exit-reload-restart-smoke.sh` | `postgres-route-health-mixed-exit-reload-restart-headscale-go-smoke.sh` | Production Postgres route-health mixed exit-node policy reload survives server restart |
| Database | `postgres-route-health-mixed-exit-all-unhealthy-restart` | `postgres-route-health-mixed-exit-all-unhealthy-restart-smoke.sh` | `postgres-route-health-mixed-exit-all-unhealthy-restart-headscale-go-smoke.sh` | Production Postgres route-health mixed exit-node all-unhealthy retention survives server restart |
| Database | `postgres-route-health-mixed-exit-all-unhealthy-reload-restart` | `postgres-route-health-mixed-exit-all-unhealthy-reload-restart-smoke.sh` | `postgres-route-health-mixed-exit-all-unhealthy-reload-restart-headscale-go-smoke.sh` | Production Postgres route-health mixed exit-node all-unhealthy policy reload survives server restart |
| Registration | `ping-lifecycle` | `ping-lifecycle-smoke.sh` | `ping-lifecycle-headscale-go-smoke.sh` | Debug PingRequest dispatch and public HEAD callback correlation |
| Registration | `web-register` | `web-register-smoke.sh` | `web-register-headscale-go-smoke.sh` | No-auth pending registration and CLI approval |
| Registration | `web-register-tags` | `web-register-tags-smoke.sh` | `web-register-tags-headscale-go-smoke.sh` | Web registration with owned requested tag |
| Registration | `web-register-unowned-tag` | `web-register-unowned-tag-smoke.sh` | `web-register-unowned-tag-headscale-go-smoke.sh` | Rejection for unowned requested tag |
| Registration | `oidc` | `oidc-smoke.sh` | `oidc-headscale-go-smoke.sh` | OIDC callback, node row, and user profile |
| SSH | `ssh-oidc-check` | `ssh-oidc-check-smoke.sh` | `ssh-oidc-check-headscale-go-smoke.sh` | OIDC-backed Tailscale SSH `check` approval |
| SSH | `ssh-cli-check` | `ssh-cli-check-smoke.sh` | `ssh-cli-check-headscale-go-smoke.sh` | CLI-approved Tailscale SSH `check` approval |
| SSH | `ssh-oidc-check-wrong-user` | `ssh-oidc-check-wrong-user-smoke.sh` | `ssh-oidc-check-wrong-user-headscale-go-smoke.sh` | Wrong-user OIDC-backed Tailscale SSH `check` denial status/stdout/stderr |
| SSH | `ssh-oidc-check-deny` | `ssh-oidc-check-deny-smoke.sh` | `ssh-oidc-check-deny-headscale-go-smoke.sh` | Expired OIDC-backed Tailscale SSH `check` denial status/stdout/stderr |
| SSH | `ssh-oidc-check-cancel` | `ssh-oidc-check-cancel-smoke.sh` | `ssh-oidc-check-cancel-headscale-go-smoke.sh` | Cancelled OIDC-backed Tailscale SSH `check` denial status/stdout/stderr |
| Lifecycle | `oidc-restart` | `oidc-restart-smoke.sh` | `oidc-restart-headscale-go-smoke.sh` | Production OIDC registration survives server restart |
| Lifecycle | `oidc-route-approve-restart` | `oidc-route-approve-restart-smoke.sh` | `oidc-route-approve-restart-headscale-go-smoke.sh` | Production OIDC route approval survives server restart |
| Lifecycle | `web-register-restart` | `web-register-restart-smoke.sh` | `web-register-restart-headscale-go-smoke.sh` | Production web/CLI registration survives server restart |
| Lifecycle | `online-lastseen` | `online-lastseen-smoke.sh` | `online-lastseen-headscale-go-smoke.sh` | Production online transition and LastSeen after client disconnect |
| Lifecycle | `restart-persistence` | `restart-persistence-smoke.sh` | `restart-persistence-headscale-go-smoke.sh` | Production restart persistence, debug batcher state, and route/tag netmap churn |
| Tags | `tagged-preauth` | `tagged-preauth-smoke.sh` | `tagged-preauth-headscale-go-smoke.sh` | Tagged preauth key with `tagOwners` policy |
| Tags | `tag-update` | `tag-update-smoke.sh` | `tag-update-headscale-go-smoke.sh` | Post-login forced tag replacement |
| Tags | `tag-update-invalid` | `tag-update-invalid-smoke.sh` | `tag-update-invalid-headscale-go-smoke.sh` | Invalid tag update rejection |
| Tags | `tag-reauth-clear` | `tag-reauth-clear-smoke.sh` | `tag-reauth-clear-headscale-go-smoke.sh` | Web reauth clears forced tags |
| DNS | `magicdns` | `magicdns-smoke.sh` | `magicdns-headscale-go-smoke.sh` | MagicDNS suffix and peer DNS names |
| DNS | `magicdns-custom-domain` | `magicdns-custom-domain-smoke.sh` | `magicdns-custom-domain-headscale-go-smoke.sh` | Custom DNS base domain |
| DNS | `extra-records` | `extra-records-smoke.sh` | `extra-records-headscale-go-smoke.sh` | Extra DNS A record in client netmap |
| DNS | `dns-edge` | `dns-edge-smoke.sh` | `dns-edge-headscale-go-smoke.sh` | Split DNS routes plus AAAA/CNAME extra records |
| DNS | `dns-hot-reload` | `dns-hot-reload-smoke.sh` | `dns-hot-reload-headscale-go-smoke.sh` | Production `extra_records_path` hot reload in client netmap |
| DNS | `magicdns-ipv6-only` | `magicdns-ipv6-only-smoke.sh` | `magicdns-ipv6-only-headscale-go-smoke.sh` | MagicDNS with IPv6-only prefix-family allocation |
| DNS | `dns-disabled` | `dns-disabled-smoke.sh` | `dns-disabled-headscale-go-smoke.sh` | MagicDNS disabled fallback names |
| Addresses | `prefix-family-dual-stack` | `prefix-family-dual-stack-smoke.sh` | `prefix-family-dual-stack-headscale-go-smoke.sh` | Dual-stack prefix-family allocation |
| Addresses | `prefix-family-v4-to-dual-backfill` | `prefix-family-v4-to-dual-backfill-smoke.sh` | `prefix-family-v4-to-dual-backfill-headscale-go-smoke.sh` | IPv4-to-dual-stack backfill after prefix migration |
| Addresses | `prefix-family-dual-stack-to-ipv4-only-backfill` | `prefix-family-dual-stack-to-ipv4-only-backfill-smoke.sh` | `prefix-family-dual-stack-to-ipv4-only-backfill-headscale-go-smoke.sh` | Dual-stack-to-IPv4-only backfill after prefix-family removal |
| Addresses | `prefix-family-dual-stack-to-ipv6-only-backfill` | `prefix-family-dual-stack-to-ipv6-only-backfill-smoke.sh` | `prefix-family-dual-stack-to-ipv6-only-backfill-headscale-go-smoke.sh` | Dual-stack-to-IPv6-only backfill after prefix-family removal |
| Addresses | `prefix-family-ipv4-only` | `prefix-family-ipv4-only-smoke.sh` | `prefix-family-ipv4-only-headscale-go-smoke.sh` | IPv4-only prefix-family allocation |
| Addresses | `prefix-family-ipv6-only` | `prefix-family-ipv6-only-smoke.sh` | `prefix-family-ipv6-only-headscale-go-smoke.sh` | IPv6-only prefix-family allocation |
| ACL | `acl-allow` | `acl-allow-smoke.sh` | `acl-allow-headscale-go-smoke.sh` | Allowed peers visible |
| ACL | `acl-empty` | `acl-empty-smoke.sh` | `acl-empty-headscale-go-smoke.sh` | Empty ACL streaming visibility edge |
| ACL | `acl-autogroup-self` | `acl-autogroup-self-smoke.sh` | `acl-autogroup-self-headscale-go-smoke.sh` | `autogroup:self` peer isolation |
| Routes | `route-advertise` | `route-advertise-smoke.sh` | `route-advertise-headscale-go-smoke.sh` | Advertised route recorded |
| Routes | `route-approve` | `route-approve-smoke.sh` | `route-approve-headscale-go-smoke.sh` | Route approval recorded |
| Routes | `route-primary` | `route-primary-smoke.sh` | `route-primary-headscale-go-smoke.sh` | Single primary route owner |
| Routes | `route-primary-failover` | `route-primary-failover-smoke.sh` | `route-primary-failover-headscale-go-smoke.sh` | Primary route failover |
| Routes | `route-primary-sticky` | `route-primary-sticky-smoke.sh` | `route-primary-sticky-headscale-go-smoke.sh` | Sticky primary route ownership |
| Routes | `route-primary-withdraw` | `route-primary-withdraw-smoke.sh` | `route-primary-withdraw-headscale-go-smoke.sh` | Withdrawn primary route failover and approval preservation |
| Routes | `route-exit-node` | `route-exit-node-smoke.sh` | `route-exit-node-headscale-go-smoke.sh` | Exit-node route advertisement and approval |
| Routes | `route-via` | `route-via-smoke.sh` | `route-via-headscale-go-smoke.sh` | Current-head `grants[].via` route steering |
| Routes | `route-via-same-tag` | `route-via-same-tag-smoke.sh` | `route-via-same-tag-headscale-go-smoke.sh` | Current-head same-tag multi-router `grants[].via` election |
| Routes | `route-via-health` | `route-via-health-smoke.sh` | `route-via-health-headscale-go-smoke.sh` | Current-head regular-overlap same-tag `grants[].via` route owner follows route-health failover |
| Routes | `route-via-reload` | `route-via-reload-smoke.sh` | `route-via-reload-headscale-go-smoke.sh` | Current-head `grants[].via` policy reload steering |
| Routes | `route-via-restart` | `route-via-restart-smoke.sh` | `route-via-restart-headscale-go-smoke.sh` | Current-head `grants[].via` restart persistence |
| Routes | `route-via-multiprefix` | `route-via-multiprefix-smoke.sh` | `route-via-multiprefix-headscale-go-smoke.sh` | Current-head multi-prefix `grants[].via` route steering |
| Routes | `route-via-multiprefix-reload` | `route-via-multiprefix-reload-smoke.sh` | `route-via-multiprefix-reload-headscale-go-smoke.sh` | Current-head multi-prefix `grants[].via` policy reload steering |
| Routes | `route-via-multiprefix-restart` | `route-via-multiprefix-restart-smoke.sh` | `route-via-multiprefix-restart-headscale-go-smoke.sh` | Current-head multi-prefix `grants[].via` restart persistence |
| Routes | `route-health` | `route-health-smoke.sh` | `route-health-headscale-go-smoke.sh` | Current-head route-health failover and sticky recovery |
| Routes | `route-health-reload` | `route-health-reload-smoke.sh` | `route-health-reload-headscale-go-smoke.sh` | Current-head route-health policy reload expands HA failover |
| Routes | `route-health-reload-restart` | `route-health-reload-restart-smoke.sh` | `route-health-reload-restart-headscale-go-smoke.sh` | Current-head route-health policy reload expansion survives production restart |
| Routes | `route-health-restart` | `route-health-restart-smoke.sh` | `route-health-restart-headscale-go-smoke.sh` | Production route-health failover after server restart |
| Routes | `route-health-primary-restart` | `route-health-primary-restart-smoke.sh` | `route-health-primary-restart-headscale-go-smoke.sh` | Current-head route-health primary selection survives server restart |
| Routes | `route-health-all-unhealthy` | `route-health-all-unhealthy-smoke.sh` | `route-health-all-unhealthy-headscale-go-smoke.sh` | Current-head route-health last-known-primary retention when all candidates are unavailable |
| Routes | `route-health-all-unhealthy-reload` | `route-health-all-unhealthy-reload-smoke.sh` | `route-health-all-unhealthy-reload-headscale-go-smoke.sh` | Current-head route-health policy reload preserves all-unavailable last-known-primary retention |
| Routes | `route-health-all-unhealthy-restart` | `route-health-all-unhealthy-restart-smoke.sh` | `route-health-all-unhealthy-restart-headscale-go-smoke.sh` | Current-head route-health production restart preserves all-unavailable last-known-primary retention |
| Routes | `route-health-mixed-exit` | `route-health-mixed-exit-smoke.sh` | `route-health-mixed-exit-headscale-go-smoke.sh` | Current-head route-health ignores exit-only routes during HA failover |
| Routes | `route-health-mixed-exit-reload` | `route-health-mixed-exit-reload-smoke.sh` | `route-health-mixed-exit-reload-headscale-go-smoke.sh` | Current-head route-health policy reload preserves exit-node separation |
| Routes | `route-health-mixed-exit-restart` | `route-health-mixed-exit-restart-smoke.sh` | `route-health-mixed-exit-restart-headscale-go-smoke.sh` | Current-head route-health mixed exit-node separation survives server restart |
| Routes | `route-health-mixed-exit-all-unhealthy` | `route-health-mixed-exit-all-unhealthy-smoke.sh` | `route-health-mixed-exit-all-unhealthy-headscale-go-smoke.sh` | Current-head route-health mixed exit-node all-unavailable subnet primary retention |
| Routes | `route-health-mixed-exit-all-unhealthy-reload` | `route-health-mixed-exit-all-unhealthy-reload-smoke.sh` | `route-health-mixed-exit-all-unhealthy-reload-headscale-go-smoke.sh` | Current-head route-health policy reload preserves mixed exit-node all-unavailable subnet primary retention |
| Routes | `route-health-mixed-exit-all-unhealthy-restart` | `route-health-mixed-exit-all-unhealthy-restart-smoke.sh` | `route-health-mixed-exit-all-unhealthy-restart-headscale-go-smoke.sh` | Current-head route-health mixed exit-node all-unavailable subnet primary retention survives server restart |
| DERP | `derp-private` | `derp-private-smoke.sh` | `derp-private-headscale-go-smoke.sh` | Private DERP relay, STUN, verify-client admission, and DERP map metadata |
| SSH | `ssh` | `ssh-smoke.sh` | `ssh-headscale-go-smoke.sh` | Tailscale SSH allow, deny, and ACL timeout |
| SSH | `ssh-localpart` | `ssh-localpart-smoke.sh` | `ssh-localpart-headscale-go-smoke.sh` | Current-head Tailscale SSH localpart login users from profile emails |
| SSH | `ssh-profile-variants` | `ssh-profile-variants-smoke.sh` | `ssh-profile-variants-headscale-go-smoke.sh` | Current-head Tailscale SSH profile email variants and exact denial status/stderr |
| SSH | `ssh-accept-env` | `ssh-accept-env-smoke.sh` | `ssh-accept-env-headscale-go-smoke.sh` | Current-head Tailscale SSH `acceptEnv` forwards accepted `LANG` and `LC_*` environment variables |

## Local and CI Execution

The real-client smokes require a Docker daemon that supports
`--add-host host.docker.internal:host-gateway`, plus `cargo`, `curl`, and
`ruby`. The headscale-go target also needs either `go` or `HEADSCALE_GO_BIN`;
TLS-backed headscale-go runs need `openssl`. The OIDC and prefix-family
backfill rows also use `sqlite3`. Postgres rows also need `psql` and
`HEADSCALE_DB_POSTGRES_TEST_URL`; they create and drop a temporary database for
each run and skip cleanly when that URL is absent.

Run a quick paired gate:

```sh
tools/real-client/smoke-matrix.sh
```

Run selected rows against only the Rust harness while iterating:

```sh
REAL_CLIENT_SMOKES=authkey,web-register,magicdns,acl-allow,route-advertise \
REAL_CLIENT_TARGETS=rust \
tools/real-client/smoke-matrix.sh
```

Run the full paired matrix in a parity branch or scheduled CI job:

```sh
REAL_CLIENT_SMOKES=all \
REAL_CLIENT_TARGETS='rust headscale-go' \
REAL_CLIENT_TIMEOUT_SECS=180 \
tools/real-client/smoke-matrix.sh
```

The default repository CI already runs `./scripts/fuzz_ci.sh` for the 10k-input
fuzz smoke and compiles the real-client Rust harness. The dedicated
`Real-client parity` workflow runs selected paired rows on pull requests that
touch the control-plane surface, runs `REAL_CLIENT_SMOKES=all` on a nightly
schedule, and supports manual dispatch for arbitrary smoke/target selections.
For local parity branches, run the fuzz gate first and then the real-client
matrix so a crash-only protocol failure is separated from a stock-client
behavior mismatch:

```sh
FUZZ_RUNS=10000 FUZZ_TIMEOUT_SECS=30 ./scripts/fuzz_ci.sh
REAL_CLIENT_SMOKES=authkey,web-register,oidc,online-lastseen,restart-persistence,magicdns,extra-records,acl-allow,route-approve,prefix-family-v4-to-dual-backfill,prefix-family-dual-stack-to-ipv4-only-backfill,prefix-family-dual-stack-to-ipv6-only-backfill \
REAL_CLIENT_TARGETS='rust headscale-go' \
tools/real-client/smoke-matrix.sh
```

Use `REAL_CLIENT_SMOKES=all` for scheduled or release parity runs. For pull
requests, keep the selected rows close to the changed surface because the full
matrix builds headscale-go, pulls the Tailscale image, and starts multiple
stock clients serially.

## Auth-Key Smoke

The first runnable stock-client scenario runs against headscale-rs:

```sh
tools/real-client/authkey-smoke.sh
```

It builds the Rust harness, starts it on loopback plus a Docker-reachable HTTPS
port, runs a stock `tailscale/tailscale:v1.94.1` client container, logs in with
a minted reusable auth key, waits for the client to have a logged-in self node
in its netmap, and asserts that the harness registered exactly one `alice`
machine. The smoke disables client DNS acceptance because the minimal harness
does not start a local DERP/DNS environment.

Useful knobs:

- `TAILSCALE_IMAGE` defaults to `tailscale/tailscale:v1.94.1`.
- `REAL_CLIENT_WORKDIR` defaults to `target/real-client/authkey-smoke`.
- `REAL_CLIENT_TIMEOUT_SECS` defaults to `120`.
- `REAL_CLIENT_LOGIN_MODE` defaults to `authkey`; `web` runs the same script
  through the pending web-registration flow.
- `REAL_CLIENT_CLIENT_USERS` can assign comma-separated per-client users. By
  default every client registers as `alice`; when set in auth-key mode, each
  client gets a user-specific key.

The matching headscale-go v0.28.0 smoke is:

```sh
tools/real-client/authkey-headscale-go-smoke.sh
```

It installs the pinned upstream headscale-go binary into the per-run work
directory, starts a local SQLite-backed server with a local DERP map fixture,
mints the same reusable auth-key shape through the upstream CLI, runs the same
stock Tailscale client image, and asserts that headscale-go registered one
`alice` node.

Additional knobs:

- `HEADSCALE_GO_VERSION` defaults to `v0.28.0`.
- `HEADSCALE_GO_BIN` can point at an existing `headscale` binary.

## Web Registration Smoke

The web-registration scenario starts a stock client without an auth key, waits
for the `/register/{auth_id}` AuthURL, extracts the raw 24-byte registration
key needed by the Rust harness or pinned-v0.28 `headscale nodes register`, and
waits for the same client to complete login:

```sh
tools/real-client/web-register-smoke.sh
tools/real-client/web-register-headscale-go-smoke.sh
```

The tagged web-registration variant runs the same no-auth login flow with
`tailscale up --advertise-tags=tag:server` and asserts that the approved node
carries the requested ACL tag:

```sh
tools/real-client/web-register-tags-smoke.sh
tools/real-client/web-register-tags-headscale-go-smoke.sh
```

The unowned-tag variant asks for `tag:blocked` while the loaded policy only
permits `tag:server`, then asserts that the CLI/web approval is rejected and no
node is registered:

```sh
tools/real-client/web-register-unowned-tag-smoke.sh
tools/real-client/web-register-unowned-tag-headscale-go-smoke.sh
```

The restart variant uses the production `headscale server` path on both sides,
approves the same no-auth pending registration through the CLI/gRPC API,
restarts the server with the same SQLite DB and control URL, then asserts that
the stock client reconnects and the web/CLI-registered node is still listed:

```sh
tools/real-client/web-register-restart-smoke.sh
tools/real-client/web-register-restart-headscale-go-smoke.sh
```

Useful knobs:

- `REAL_CLIENT_LOGIN_MODE=web` can be passed directly to the auth-key smoke
  scripts for custom scenarios.
- `REAL_CLIENT_RESTART_WEB_REGISTER=true` enables the focused production
  restart path in `restart-persistence-common.sh`.
- `REAL_CLIENT_PREAUTH_TAGS` defaults to `tag:server` in the tagged variant.
- `REAL_CLIENT_UNOWNED_TAG` defaults to `tag:blocked` in the unowned-tag
  variant.
- `REAL_CLIENT_EXPECT_REGISTER_FAILURE=true` asserts rejection for custom
  negative web-registration cases.
- `REAL_CLIENT_TAILSCALE_UP_TIMEOUT` defaults to `45s` for web registration.

## OIDC Smoke

The OIDC scenario starts the production `headscale server` path with `[oidc]`
configured, runs upstream `headscale mockoidc` as the identity provider, starts a
stock client without an auth key, and drives the browser callback with a cookie
jar:

```sh
tools/real-client/oidc-smoke.sh
tools/real-client/oidc-headscale-go-smoke.sh
tools/real-client/oidc-restart-smoke.sh
tools/real-client/oidc-restart-headscale-go-smoke.sh
tools/real-client/oidc-route-approve-restart-smoke.sh
tools/real-client/oidc-route-approve-restart-headscale-go-smoke.sh
```

All OIDC scripts assert that the client reaches a logged-in netmap and that SQLite
records one OIDC-registered node plus the expected OIDC user profile. The
Rust scripts also check the production local gRPC CLI node view over a short
`/tmp/hsrs-*.sock` path, overrideable with `REAL_CLIENT_HEADSCALE_RS_SOCKET`;
the headscale-go scripts check the upstream
`headscale nodes list` JSON output. The restart variants keep the same control
URL and SQLite DB, restart the production server after OIDC login, then assert
that the stock client reconnects and the OIDC node/user state still matches.
The route-approval restart variant also advertises `10.77.0.0/24`, approves it
through the production CLI/gRPC path, and asserts available/approved route state
before and after the restart.
The Rust OIDC config sets `node.expiry = "180d"` to mirror the pinned
headscale-go OIDC default through the current `node.expiry` surface.

Useful knobs:

- `TAILSCALE_IMAGE` defaults to `tailscale/tailscale:v1.94.1`.
- `REAL_CLIENT_WORKDIR` defaults to `target/real-client/oidc-smoke` or
  `target/real-client/oidc-headscale-go-smoke`.
- `REAL_CLIENT_TIMEOUT_SECS` defaults to `150`.
- `REAL_CLIENT_OIDC_RESTART=true` enables the restart assertion; the
  `oidc-restart` and `oidc-route-approve-restart` wrappers set it.
- `REAL_CLIENT_OIDC_ADVERTISE_ROUTES` and `REAL_CLIENT_OIDC_APPROVE_ROUTES`
  enable advertised-route persistence assertions for OIDC clients.
- `HEADSCALE_GO_VERSION` defaults to `v0.28.0`.
- `HEADSCALE_GO_BIN` can point at an existing `headscale` binary.
- `REAL_CLIENT_OIDC_EMAIL`, `REAL_CLIENT_OIDC_USERNAME`,
  `REAL_CLIENT_OIDC_SUBJECT`, and `REAL_CLIENT_OIDC_GROUPS` control the mock
  identity.

## Online / LastSeen Smoke

The lifecycle scenario starts the production `headscale server` path, logs in a
stock client with a reusable auth key, checks that `nodes list -o json` reports
the node online with a parseable `LastSeen`, then stops `tailscaled` and waits
for the production admin view to report the node offline with an advanced
`LastSeen`:

```sh
tools/real-client/online-lastseen-smoke.sh
tools/real-client/online-lastseen-headscale-go-smoke.sh
```

The helper accepts headscale-go protobuf JSON that omits the default `online:
false` field after disconnect, while still requiring an explicit connected
online state.

## Tagged Preauth Smoke

The tagged-preauth scenario mints a reusable auth key with ACL tags, logs in a
stock client, and asserts that the registered node carries those tags:

```sh
tools/real-client/tagged-preauth-smoke.sh
tools/real-client/tagged-preauth-headscale-go-smoke.sh
```

Both scripts load a minimal tag-owner policy when tags are requested. The
headscale-go smoke uses the upstream `headscale preauthkeys create --tags`
command; the Rust smoke uses the harness-only preauth mint route.

Useful knobs:

- `REAL_CLIENT_PREAUTH_TAGS` defaults to `tag:server`.
- `REAL_CLIENT_EXPECT_TAGS` defaults to the requested preauth tags.
- `REAL_CLIENT_POLICY_JSON` can override the generated tag-owner policy.

## Tag Update Smoke

The tag-update scenario logs in a stock client with `tag:server`, replaces the
node's forced tags with `tag:prod` through the Rust harness or upstream
`headscale nodes tag`, and asserts that the final node state carries only the
updated tag. The invalid-tag variant requests `tag:blocked` while the loaded
policy only defines `tag:server`, then asserts that the update is rejected and
the original tag remains:

```sh
tools/real-client/tag-update-smoke.sh
tools/real-client/tag-update-headscale-go-smoke.sh
tools/real-client/tag-update-invalid-smoke.sh
tools/real-client/tag-update-invalid-headscale-go-smoke.sh
```

The reauth-clear variant logs in with `tag:server`, forces a web reauth with
no advertised tags, and asserts that the existing same-machine node is rekeyed
back to user-owned state with an empty tag set instead of duplicated:

```sh
tools/real-client/tag-reauth-clear-smoke.sh
tools/real-client/tag-reauth-clear-headscale-go-smoke.sh
```

Useful knobs:

- `REAL_CLIENT_PREAUTH_TAGS` defaults to `tag:server`.
- `REAL_CLIENT_SET_TAGS_AFTER_LOGIN` defaults to `tag:prod`.
- `REAL_CLIENT_EXPECT_TAGS` defaults to the post-update tags.
- `REAL_CLIENT_REAUTH_AFTER_LOGIN=true` forces a second web registration after
  the initial login.
- `REAL_CLIENT_REAUTH_TAGS` sets the advertised tags for that reauth; empty
  means the final node is expected to have no forced tags.
- `REAL_CLIENT_EXPECT_TAGS_EXACT=true` asserts the tag set exactly, including
  an empty set.
- `REAL_CLIENT_EXPECT_SET_TAGS_FAILURE=true` asserts rejection for custom
  negative tag-update cases.
- `REAL_CLIENT_POLICY_JSON` can override the generated tag-owner policy.

## MagicDNS Smoke

The MagicDNS scenario starts two stock clients and asserts that each client
reports the configured tailnet suffix plus peer DNS names in
`tailscale status --json`:

```sh
tools/real-client/magicdns-smoke.sh
tools/real-client/magicdns-headscale-go-smoke.sh
```

The custom-domain variant runs the same stock-client assertions with a
non-default DNS base domain:

```sh
tools/real-client/magicdns-custom-domain-smoke.sh
tools/real-client/magicdns-custom-domain-headscale-go-smoke.sh
```

The extra-records variant configures an operator-supplied A record, runs the
stock client with DNS acceptance enabled, and asserts the record is present in
the client-observed netmap:

```sh
tools/real-client/extra-records-smoke.sh
tools/real-client/extra-records-headscale-go-smoke.sh
```

The DNS hot-reload variant starts the production server with
`dns.extra_records_path`, logs in a stock client, edits the JSON records file,
and asserts that the client-observed netmap switches from the original A
record to the updated AAAA record without restarting the server:

```sh
tools/real-client/dns-hot-reload-smoke.sh
tools/real-client/dns-hot-reload-headscale-go-smoke.sh
```

The disabled-DNS scenario starts two stock clients with MagicDNS off and
asserts that client DNS names fall back to bare hostnames while peer visibility
is unchanged:

```sh
tools/real-client/dns-disabled-smoke.sh
tools/real-client/dns-disabled-headscale-go-smoke.sh
```

Useful knobs:

- `REAL_CLIENT_CLIENT_COUNT` defaults to `2`.
- `REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX` defaults to `tail.test`.
- `REAL_CLIENT_BASE_DOMAIN` defaults to `tail.test`; set it to an empty string
  to disable MagicDNS in the Rust harness.
- `tools/real-client/magicdns-custom-domain-*.sh` default
  `REAL_CLIENT_BASE_DOMAIN` and `REAL_CLIENT_EXPECT_MAGIC_DNS_SUFFIX` to
  `tail.custom.test`.
- `REAL_CLIENT_MAGIC_DNS=false` disables MagicDNS in the headscale-go smoke.
- `REAL_CLIENT_EXPECT_NO_MAGIC_DNS=true` asserts the disabled-DNS client
  status shape.

## ACL Peer Visibility Smoke

The ACL allow scenario starts two stock clients with a loaded policy that allows
`alice@` devices to reach other `alice@` devices, then asserts each client sees
exactly one peer:

```sh
tools/real-client/acl-allow-smoke.sh
tools/real-client/acl-allow-headscale-go-smoke.sh
```

Useful knobs:

- `REAL_CLIENT_POLICY_JSON` can override the generated allow policy.
- `REAL_CLIENT_EXPECT_PEER_COUNT` defaults to `1`.
- `REAL_CLIENT_EXPECT_PEER_COUNTS` can assert comma-separated per-client counts.

The empty-ACL scenario covers the headscale-go streaming edge where the first
client receives the later node through an incremental peer delta while the
second client's initial full map remains empty:

```sh
tools/real-client/acl-empty-smoke.sh
tools/real-client/acl-empty-headscale-go-smoke.sh
```

Useful knobs:

- `REAL_CLIENT_EXPECT_PEER_COUNTS` defaults to `1,0`.

The `autogroup:self` scenario starts three clients as `alice`, `bob`, and
`alice`, then asserts that only same-user peers are visible:

```sh
tools/real-client/acl-autogroup-self-smoke.sh
tools/real-client/acl-autogroup-self-headscale-go-smoke.sh
```

Useful knobs:

- `REAL_CLIENT_CLIENT_USERS` defaults to `alice,bob,alice`.
- `REAL_CLIENT_EXPECT_PEER_COUNTS` defaults to `1,0,1`.

## Advertised Route Smoke

The route-advertisement scenario reuses the auth-key setup and adds
`tailscale up --advertise-routes=10.77.0.0/24`.

```sh
tools/real-client/route-advertise-smoke.sh
tools/real-client/route-advertise-headscale-go-smoke.sh
```

Both scripts assert that the control server records the advertised route as an
available route for the registered node. The route is intentionally not
approved in this smoke; approval and primary-route behavior are covered by
separate smokes plus Rust unit/differential tests.

Useful knobs:

- `REAL_CLIENT_ADVERTISE_ROUTES` defaults to `10.77.0.0/24`.
- `REAL_CLIENT_EXPECT_AVAILABLE_ROUTES` defaults to the advertised routes.

The route-approval scenario advertises the same route, approves it through the
control server, and asserts that the route is present in both available and
approved route state:

```sh
tools/real-client/route-approve-smoke.sh
tools/real-client/route-approve-headscale-go-smoke.sh
```

For headscale-rs the approval call uses a harness-only route that updates the
shared wire `MachineRegistry`; for headscale-go it uses the upstream
`headscale nodes approve-routes` CLI.

Additional knobs:

- `REAL_CLIENT_ROUTE` defaults to `10.77.0.0/24` for the wrapper scripts.
- `REAL_CLIENT_APPROVE_ROUTES` defaults to `REAL_CLIENT_ROUTE` in the approval
  wrappers.
- `REAL_CLIENT_EXPECT_APPROVED_ROUTES` defaults to the approved routes.

The Postgres online/LastSeen scenario runs the single-node lifecycle flow
through production `headscale server`/headscale-go `serve` processes backed by
a temporary Postgres database. The `postgres-magicdns` variant asserts the
default MagicDNS suffix over that production Postgres path, the
`postgres-magicdns-custom-domain` variant asserts a non-default suffix, the
`postgres-extra-records` variant asserts configured DNS `extra_records` in the
stock-client netmap, the `postgres-dns-disabled` variant asserts disabled
MagicDNS fallback names, the `postgres-dns-edge` variant asserts split DNS
routes, fallback resolvers, and AAAA/CNAME records, the
`postgres-dns-hot-reload` variant asserts production `extra_records_path`
file reloads, and the
`postgres-magicdns-ipv6-only` variant asserts IPv6-only MagicDNS allocation.
The `postgres-prefix-family-dual-stack`, `postgres-prefix-family-ipv4-only`,
and `postgres-prefix-family-ipv6-only` variants assert explicit prefix-family
allocation through the same path:

```sh
tools/real-client/postgres-online-lastseen-smoke.sh
tools/real-client/postgres-online-lastseen-headscale-go-smoke.sh
tools/real-client/postgres-magicdns-smoke.sh
tools/real-client/postgres-magicdns-headscale-go-smoke.sh
tools/real-client/postgres-magicdns-custom-domain-smoke.sh
tools/real-client/postgres-magicdns-custom-domain-headscale-go-smoke.sh
tools/real-client/postgres-extra-records-smoke.sh
tools/real-client/postgres-extra-records-headscale-go-smoke.sh
tools/real-client/postgres-dns-disabled-smoke.sh
tools/real-client/postgres-dns-disabled-headscale-go-smoke.sh
tools/real-client/postgres-dns-edge-smoke.sh
tools/real-client/postgres-dns-edge-headscale-go-smoke.sh
tools/real-client/postgres-dns-hot-reload-smoke.sh
tools/real-client/postgres-dns-hot-reload-headscale-go-smoke.sh
tools/real-client/postgres-magicdns-ipv6-only-smoke.sh
tools/real-client/postgres-magicdns-ipv6-only-headscale-go-smoke.sh
tools/real-client/postgres-prefix-family-dual-stack-smoke.sh
tools/real-client/postgres-prefix-family-dual-stack-headscale-go-smoke.sh
tools/real-client/postgres-prefix-family-ipv4-only-smoke.sh
tools/real-client/postgres-prefix-family-ipv4-only-headscale-go-smoke.sh
tools/real-client/postgres-prefix-family-ipv6-only-smoke.sh
tools/real-client/postgres-prefix-family-ipv6-only-headscale-go-smoke.sh
```

The Postgres route-approval scenario adds route advertisement and approval on
top of the same production Postgres lifecycle harness:

```sh
tools/real-client/postgres-route-approve-smoke.sh
tools/real-client/postgres-route-approve-headscale-go-smoke.sh
```

Both use `HEADSCALE_DB_POSTGRES_TEST_URL` and skip cleanly when that URL is not
set. The route row additionally asserts CLI route state and approved-route
netmap projection.

The Postgres OIDC scenario runs the production OIDC confirmation flow against
Rust and headscale-go with a temporary Postgres database:

```sh
tools/real-client/postgres-oidc-smoke.sh
tools/real-client/postgres-oidc-headscale-go-smoke.sh
```

It uses the same mock OIDC provider and stock Tailscale client as `oidc`, skips
cleanly when `HEADSCALE_DB_POSTGRES_TEST_URL` is not set, and asserts the OIDC
node row, user profile/provider fields, CLI node projection, and client netmap.

The Postgres route-edge restart rows reuse the restart harness with a temporary
Postgres database to prove persisted route-via and route-health state across a
production server restart:

```sh
tools/real-client/postgres-route-via-restart-smoke.sh
tools/real-client/postgres-route-via-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-via-same-tag-restart-smoke.sh
tools/real-client/postgres-route-via-same-tag-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-via-reload-restart-smoke.sh
tools/real-client/postgres-route-via-reload-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-via-multiprefix-restart-smoke.sh
tools/real-client/postgres-route-via-multiprefix-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-via-multiprefix-reload-restart-smoke.sh
tools/real-client/postgres-route-via-multiprefix-reload-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-health-restart-smoke.sh
tools/real-client/postgres-route-health-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-health-primary-restart-smoke.sh
tools/real-client/postgres-route-health-primary-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-health-reload-restart-smoke.sh
tools/real-client/postgres-route-health-reload-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-health-all-unhealthy-restart-smoke.sh
tools/real-client/postgres-route-health-all-unhealthy-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-health-all-unhealthy-reload-restart-smoke.sh
tools/real-client/postgres-route-health-all-unhealthy-reload-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-health-mixed-exit-restart-smoke.sh
tools/real-client/postgres-route-health-mixed-exit-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-health-mixed-exit-reload-restart-smoke.sh
tools/real-client/postgres-route-health-mixed-exit-reload-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-health-mixed-exit-all-unhealthy-restart-smoke.sh
tools/real-client/postgres-route-health-mixed-exit-all-unhealthy-restart-headscale-go-smoke.sh
tools/real-client/postgres-route-health-mixed-exit-all-unhealthy-reload-restart-smoke.sh
tools/real-client/postgres-route-health-mixed-exit-all-unhealthy-reload-restart-headscale-go-smoke.sh
```

The primary-route scenario starts two stock clients, advertises and approves
the same subnet route on both, and asserts that exactly one node is selected as
the primary route owner:

```sh
tools/real-client/route-primary-smoke.sh
tools/real-client/route-primary-headscale-go-smoke.sh
```

The primary-route failover scenario then removes approval from the current
primary owner and asserts that another approved router takes over:

```sh
tools/real-client/route-primary-failover-smoke.sh
tools/real-client/route-primary-failover-headscale-go-smoke.sh
```

The sticky primary-route scenario performs that failover, then re-approves the
old primary owner and asserts that the current primary remains sticky instead
of being stolen back:

```sh
tools/real-client/route-primary-sticky-smoke.sh
tools/real-client/route-primary-sticky-headscale-go-smoke.sh
```

The primary-route withdrawal scenario instead asks the current primary client
to stop advertising the route with `tailscale set --advertise-routes=` and
asserts that another advertising router takes over while the withdrawn router's
operator approval remains recorded:

```sh
tools/real-client/route-primary-withdraw-smoke.sh
tools/real-client/route-primary-withdraw-headscale-go-smoke.sh
```

Additional knobs:

- `REAL_CLIENT_CLIENT_COUNT` defaults to `2` in the primary-route wrappers.
- `REAL_CLIENT_EXPECT_PRIMARY_ROUTE` defaults to `REAL_CLIENT_ROUTE`.
- `REAL_CLIENT_EXPECT_PRIMARY_FAILOVER_ROUTE` defaults to `REAL_CLIENT_ROUTE`
  in the failover wrappers.
- `REAL_CLIENT_EXPECT_PRIMARY_STICKY_ROUTE` defaults to `REAL_CLIENT_ROUTE`
  in the sticky wrapper and must match the failover route.
- `REAL_CLIENT_EXPECT_PRIMARY_WITHDRAW_ROUTE` defaults to `REAL_CLIENT_ROUTE`
  in the withdrawal wrappers.
- `REAL_CLIENT_EXPECT_WITHDRAW_APPROVAL_PRESERVED` defaults to `true` in the
  withdrawal wrappers.

The exit-node scenario advertises the default-route pair with
`tailscale up --advertise-exit-node`, approves both routes, and checks that
the control server reports them as available and approved:

```sh
tools/real-client/route-exit-node-smoke.sh
tools/real-client/route-exit-node-headscale-go-smoke.sh
```

Additional knobs:

- `REAL_CLIENT_EXIT_ROUTES` defaults to `0.0.0.0/0,::/0`.
- `REAL_CLIENT_ADVERTISE_EXIT_NODE` defaults to `true` in the exit-node
  wrappers.

The route-via scenario uses current-head `grants[].via` policy semantics. It
starts two tagged routers and two user nodes, has both routers advertise the
same subnet, and asserts from each user node's stock-client netmap that the
route is owned only by the router selected by that user's `via` grant:

```sh
tools/real-client/route-via-smoke.sh
tools/real-client/route-via-headscale-go-smoke.sh
```

The same-tag route-via variant has two routers with `tag:router-ha` advertise
the same subnet, then asserts Alice and Bob both see only the first registered
router as the stock-client route owner for that shared `via` tag:

```sh
tools/real-client/route-via-same-tag-smoke.sh
tools/real-client/route-via-same-tag-headscale-go-smoke.sh
```

The route-via plus route-health variant uses the same two-router `via` tag with
a regular overlapping route grant, enables HA route-health probes, pauses the
current primary router, and asserts Alice and Bob's stock-client netmaps move
the route owner to the surviving router. After the old primary recovers, it also
asserts sticky route-health ownership does not steal the route back:

```sh
tools/real-client/route-via-health-smoke.sh
tools/real-client/route-via-health-headscale-go-smoke.sh
```

The route-via reload variant starts from the same two-router state, reloads the
policy so Alice's `via` grant moves from `tag:router-a` to `tag:router-b`, and
asserts the stock-client netmap moves that route owner after reload:

```sh
tools/real-client/route-via-reload-smoke.sh
tools/real-client/route-via-reload-headscale-go-smoke.sh
```

The route-via restart variant runs the same current-head steering semantics
through the production server, persistent SQLite state, and stock clients on
both implementations, then restarts the server and asserts Alice and Bob still
see only their policy-selected route owner:

```sh
tools/real-client/route-via-restart-smoke.sh
tools/real-client/route-via-restart-headscale-go-smoke.sh
```

The multi-prefix route-via variant has both routers advertise two subnets and
asserts opposite per-prefix steering for two users. The reload variant swaps
both users' per-prefix owners through a policy reload, and the restart variant
proves the same ownership survives a production-server restart:

```sh
tools/real-client/route-via-multiprefix-smoke.sh
tools/real-client/route-via-multiprefix-headscale-go-smoke.sh
tools/real-client/route-via-multiprefix-reload-smoke.sh
tools/real-client/route-via-multiprefix-reload-headscale-go-smoke.sh
tools/real-client/route-via-multiprefix-restart-smoke.sh
tools/real-client/route-via-multiprefix-restart-headscale-go-smoke.sh
```

The headscale-go wrapper defaults `HEADSCALE_GO_VERSION` to the audited
current-head commit because pinned v0.28 does not implement `grants[].via`.

The route-health scenario enables HA route probes, pauses the current primary
router container without removing route approval, and asserts that the route
fails over to the other router. After unpausing the old primary, it waits for a
recovery probe and asserts sticky ownership remains with the failover router:

```sh
tools/real-client/route-health-smoke.sh
tools/real-client/route-health-headscale-go-smoke.sh
```

The route-health reload variant starts with one tagged router auto-approved,
reloads policy so the second tagged router is also auto-approved, and then
asserts route-health HA failover across the newly expanded candidate set:

```sh
tools/real-client/route-health-reload-smoke.sh
tools/real-client/route-health-reload-headscale-go-smoke.sh
```

The route-health reload-restart variant runs the production server, starts with
only `tag:router-a` auto-approved, reloads policy to add `tag:router-b`,
verifies the expanded HA candidate set, restarts the server, and then asserts
post-restart failover:

```sh
tools/real-client/route-health-reload-restart-smoke.sh
tools/real-client/route-health-reload-restart-headscale-go-smoke.sh
```

The route-health restart variant runs the production server with persistent
SQLite and config-backed HA route probes, restarts the server, then pauses the
current primary router and asserts post-restart route-health failover plus
sticky recovery:

```sh
tools/real-client/route-health-restart-smoke.sh
tools/real-client/route-health-restart-headscale-go-smoke.sh
```

The all-unhealthy route-health variant pauses the current primary, waits for
failover, then pauses every remaining route candidate and asserts the route
keeps the last known primary as a degraded primary instead of disappearing.
Current headscale-go retains the last known primary in this stock-client
unavailable-candidate case:

```sh
tools/real-client/route-health-all-unhealthy-smoke.sh
tools/real-client/route-health-all-unhealthy-headscale-go-smoke.sh
tools/real-client/route-health-all-unhealthy-reload-smoke.sh
tools/real-client/route-health-all-unhealthy-reload-headscale-go-smoke.sh
tools/real-client/route-health-all-unhealthy-restart-smoke.sh
tools/real-client/route-health-all-unhealthy-restart-headscale-go-smoke.sh
```

The mixed-exit route-health variants add an exit-only router next to the two
subnet router candidates and assert HA primary/failover behavior continues to
use only the subnet routers. The reload variant proves the same separation
after policy expansion; the restart variant runs through a production server
restart before asserting the exit-only routes remain separate from subnet HA:

```sh
tools/real-client/route-health-mixed-exit-smoke.sh
tools/real-client/route-health-mixed-exit-headscale-go-smoke.sh
tools/real-client/route-health-mixed-exit-reload-smoke.sh
tools/real-client/route-health-mixed-exit-reload-headscale-go-smoke.sh
tools/real-client/route-health-mixed-exit-restart-smoke.sh
tools/real-client/route-health-mixed-exit-restart-headscale-go-smoke.sh
```

The mixed-exit all-unhealthy variants combine the exit-only separation case
with the degraded-primary fallback case: after proving failover between the
two subnet routers, every subnet route candidate is paused while the exit-only
node remains available, and the route must retain the last known subnet primary
instead of moving to the exit node or disappearing:

```sh
tools/real-client/route-health-mixed-exit-all-unhealthy-smoke.sh
tools/real-client/route-health-mixed-exit-all-unhealthy-headscale-go-smoke.sh
tools/real-client/route-health-mixed-exit-all-unhealthy-reload-smoke.sh
tools/real-client/route-health-mixed-exit-all-unhealthy-reload-headscale-go-smoke.sh
tools/real-client/route-health-mixed-exit-all-unhealthy-restart-smoke.sh
tools/real-client/route-health-mixed-exit-all-unhealthy-restart-headscale-go-smoke.sh
```

The headscale-go wrapper also defaults to the audited current-head commit
because pinned v0.28 does not expose `node.routes.ha`.

Additional knobs:

- `REAL_CLIENT_ADVERTISE_ROUTES_BY_CLIENT` accepts semicolon-separated
  per-client route advertisements; use `-` for no routes.
- `REAL_CLIENT_PREAUTH_TAGS_BY_CLIENT` accepts semicolon-separated per-client
  preauth-key tags; use `-` for no tags.
- `REAL_CLIENT_EXPECT_PEER_ROUTE_OWNERS` entries are
  `source_index:peer_index:route` and assert route ownership in
  `tailscale debug netmap`.
- `REAL_CLIENT_EXPECT_ROUTE_HEALTH_ALL_UNHEALTHY_ROUTE` enables the degraded
  primary fallback assertion after all route candidates have timed out.
- `REAL_CLIENT_ROUTE_HEALTH_PROBE_INTERVAL_SECS` and
  `REAL_CLIENT_ROUTE_HEALTH_PROBE_TIMEOUT_SECS` default to `2` and `1` in the
  route-health wrappers.

## Tailscale SSH Smoke

The SSH scenario enables Tailscale SSH on stock clients, installs the
OpenSSH client package inside the client containers, creates the local
`ssh-it-user`, and runs actual `tailscale ssh` commands. The first pass checks
same-user `autogroup:self` success plus cross-user policy denial; the second
pass keeps the SSH policy but blocks port 22 in ACLs and expects the SSH
attempt to time out.

```sh
tools/real-client/ssh-smoke.sh
tools/real-client/ssh-headscale-go-smoke.sh
```

The OIDC and CLI `check` wrappers drive the stock client through the Headscale
SSH `HoldAndDelegate` path. The OIDC approval row follows the browser
`/auth/{auth_id}` flow and expects hostname output. The CLI approval row uses
`headscale auth approve --auth-id ...` against the same pending check request.
The wrong-user row authenticates the `/auth/{auth_id}` flow as a different OIDC
user, expects the auth callback to be denied, then asserts the nonzero SSH
exit, empty stdout, first stderr line, and access-denied stderr regex. The
expired-denial row sets a short `tuning.register_cache_expiration`, lets the
check auth request expire, and asserts the same denied SSH output shape. The
cancelled-denial row lets the stock client enter the SSH `check` flow and
emit the auth URL, then relies on the inner `timeout` to cancel the parked SSH
attempt and asserts the nonzero exit, empty stdout, and auth-prompt stderr
shape.

```sh
tools/real-client/ssh-oidc-check-smoke.sh
tools/real-client/ssh-oidc-check-headscale-go-smoke.sh
tools/real-client/ssh-cli-check-smoke.sh
tools/real-client/ssh-cli-check-headscale-go-smoke.sh
tools/real-client/postgres-ssh-oidc-check-period-cache-smoke.sh
tools/real-client/postgres-ssh-oidc-check-period-cache-headscale-go-smoke.sh
tools/real-client/ssh-oidc-check-wrong-user-smoke.sh
tools/real-client/ssh-oidc-check-wrong-user-headscale-go-smoke.sh
tools/real-client/ssh-oidc-check-deny-smoke.sh
tools/real-client/ssh-oidc-check-deny-headscale-go-smoke.sh
tools/real-client/ssh-oidc-check-cancel-smoke.sh
tools/real-client/ssh-oidc-check-cancel-headscale-go-smoke.sh
```

The current-head localpart wrappers exercise `localpart:*@domain` login users
with profile emails. The profile-variant row also checks split username/email
profiles against headscale-go, wrong-domain profile emails, bare usernames with
no profile email, exact denied status `255`, empty denied stdout, and the
stable first denial stderr line. The `ssh-accept-env` row runs a tagged target
with policy `acceptEnv: ["LANG", "LC_*"]`, passes `LANG` and `LC_ACCEPT_ENV_SMOKE`
through the stock client command environment, and asserts the remote command
prints those accepted values:

```sh
tools/real-client/ssh-localpart-smoke.sh
tools/real-client/ssh-localpart-headscale-go-smoke.sh
tools/real-client/ssh-profile-variants-smoke.sh
tools/real-client/ssh-profile-variants-headscale-go-smoke.sh
tools/real-client/ssh-accept-env-smoke.sh
tools/real-client/ssh-accept-env-headscale-go-smoke.sh
```

Useful knobs:

- `REAL_CLIENT_SSH_USER` defaults to `ssh-it-user`.
- `REAL_CLIENT_EXPECT_SSH_MATRIX` defaults to
  `1:2:allow,2:1:allow,1:3:deny,3:1:deny` for the first pass.
- `REAL_CLIENT_TIMEOUT_EXPECT_SSH_MATRIX` defaults to `1:2:timeout` for the
  ACL-blocked pass.
- `REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS` defaults to `12`.
- `REAL_CLIENT_SSH_HOST_KEY_TIMEOUT_SECS` defaults to `30`; this fails fast
  when a control server does not re-emit peer `sshHostKeys`, which the
  `tailscale ssh` wrapper needs for strict host-key checking.
- `REAL_CLIENT_SSH_COMMAND`, `REAL_CLIENT_EXPECT_SSH_STDOUT`, and
  `REAL_CLIENT_SSH_SEND_ENV` let wrappers run a non-`hostname` SSH command and
  assert exact stdout; `REAL_CLIENT_SSH_SEND_ENV` is a comma-separated list of
  `NAME=value` pairs passed into the client-side `tailscale ssh` process.
- `REAL_CLIENT_OIDC_SSH_CHECK_RESULT=expire` reuses
  `ssh-oidc-check-smoke.sh` for the denied check path; the wrapper defaults
  `REAL_CLIENT_REGISTER_CACHE_EXPIRATION=10s`,
  `REAL_CLIENT_SSH_ATTEMPT_TIMEOUT_SECS=45`, status `255`, first stderr line
  `# Headscale SSH requires an additional check.`, and an access-denied regex.
- `REAL_CLIENT_OIDC_SSH_CHECK_APPROVAL=cli` approves the pending SSH check with
  `headscale auth approve --auth-id ...` instead of the browser flow.
- `REAL_CLIENT_OIDC_SSH_CHECK_PERIOD_CACHE=true` reruns the approved SSH
  command inside the policy `checkPeriod` window and asserts no second auth URL
  is emitted.
- `REAL_CLIENT_OIDC_SSH_CHECK_RESULT=wrong-user` uses a third mock OIDC login
  as `mallory@example.com` by default, expects HTTP `403` from the auth flow,
  and then asserts the denied SSH output shape.
- `REAL_CLIENT_OIDC_SSH_CHECK_RESULT=cancel` uses
  `REAL_CLIENT_OIDC_SSH_CANCEL_TIMEOUT_SECS` as the default SSH attempt timeout
  so the parked `tailscale ssh` exits nonzero after the auth URL is emitted;
  the wrapper defaults to status `124`, empty stdout, the stable first auth
  prompt line, and an auth-prompt stderr regex.
