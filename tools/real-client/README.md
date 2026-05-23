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
and a matching pinned headscale-go script so parity work can compare behavior
with the same stock `tailscaled` image.

| Area | Smoke ID | headscale-rs | headscale-go | Assertion focus |
| --- | --- | --- | --- | --- |
| Registration | `authkey` | `authkey-smoke.sh` | `authkey-headscale-go-smoke.sh` | Auth-key login and one `alice` node |
| Registration | `web-register` | `web-register-smoke.sh` | `web-register-headscale-go-smoke.sh` | No-auth pending registration and CLI approval |
| Registration | `web-register-tags` | `web-register-tags-smoke.sh` | `web-register-tags-headscale-go-smoke.sh` | Web registration with owned requested tag |
| Registration | `web-register-unowned-tag` | `web-register-unowned-tag-smoke.sh` | `web-register-unowned-tag-headscale-go-smoke.sh` | Rejection for unowned requested tag |
| Registration | `oidc` | `oidc-smoke.sh` | `oidc-headscale-go-smoke.sh` | OIDC callback, node row, and user profile |
| Lifecycle | `online-lastseen` | `online-lastseen-smoke.sh` | `online-lastseen-headscale-go-smoke.sh` | Production online transition and LastSeen after client disconnect |
| Lifecycle | `restart-persistence` | `restart-persistence-smoke.sh` | `restart-persistence-headscale-go-smoke.sh` | Production restart persistence and route/tag netmap churn |
| Tags | `tagged-preauth` | `tagged-preauth-smoke.sh` | `tagged-preauth-headscale-go-smoke.sh` | Tagged preauth key with `tagOwners` policy |
| Tags | `tag-update` | `tag-update-smoke.sh` | `tag-update-headscale-go-smoke.sh` | Post-login forced tag replacement |
| Tags | `tag-update-invalid` | `tag-update-invalid-smoke.sh` | `tag-update-invalid-headscale-go-smoke.sh` | Invalid tag update rejection |
| Tags | `tag-reauth-clear` | `tag-reauth-clear-smoke.sh` | `tag-reauth-clear-headscale-go-smoke.sh` | Web reauth clears forced tags |
| DNS | `magicdns` | `magicdns-smoke.sh` | `magicdns-headscale-go-smoke.sh` | MagicDNS suffix and peer DNS names |
| DNS | `magicdns-custom-domain` | `magicdns-custom-domain-smoke.sh` | `magicdns-custom-domain-headscale-go-smoke.sh` | Custom DNS base domain |
| DNS | `extra-records` | `extra-records-smoke.sh` | `extra-records-headscale-go-smoke.sh` | Extra DNS A record in client netmap |
| DNS | `dns-edge` | `dns-edge-smoke.sh` | `dns-edge-headscale-go-smoke.sh` | Split DNS routes plus AAAA/CNAME extra records |
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
| Routes | `route-health` | `route-health-smoke.sh` | `route-health-headscale-go-smoke.sh` | Current-head route-health failover and sticky recovery |
| DERP | `derp-private` | `derp-private-smoke.sh` | `derp-private-headscale-go-smoke.sh` | Private DERP relay, STUN, verify-client admission, and DERP map metadata |
| SSH | `ssh` | `ssh-smoke.sh` | `ssh-headscale-go-smoke.sh` | Tailscale SSH allow, deny, and ACL timeout |

## Local and CI Execution

The real-client smokes require a Docker daemon that supports
`--add-host host.docker.internal:host-gateway`, plus `cargo`, `curl`, and
`ruby`. The headscale-go target also needs either `go` or `HEADSCALE_GO_BIN`;
TLS-backed headscale-go runs need `openssl`. The OIDC and prefix-family
backfill rows also use `sqlite3`.

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
for the `/register/{registration_id}` AuthURL, approves the pending registration
through the Rust harness or upstream `headscale nodes register`, and waits for
the same client to complete login:

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

Useful knobs:

- `REAL_CLIENT_LOGIN_MODE=web` can be passed directly to the auth-key smoke
  scripts for custom scenarios.
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
```

Both scripts assert that the client reaches a logged-in netmap and that SQLite
records one OIDC-registered node plus the expected OIDC user profile. The
Rust script also configures the production local gRPC Unix socket at a short
`/tmp/hsrs-*.sock` path, overrideable with `REAL_CLIENT_HEADSCALE_RS_SOCKET`;
the headscale-go script checks the upstream
`headscale nodes list` JSON output.

Useful knobs:

- `TAILSCALE_IMAGE` defaults to `tailscale/tailscale:v1.94.1`.
- `REAL_CLIENT_WORKDIR` defaults to `target/real-client/oidc-smoke` or
  `target/real-client/oidc-headscale-go-smoke`.
- `REAL_CLIENT_TIMEOUT_SECS` defaults to `150`.
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
