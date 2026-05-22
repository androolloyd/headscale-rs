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
asserts that another advertising router takes over:

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
