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

Additional knobs:

- `REAL_CLIENT_CLIENT_COUNT` defaults to `2` in the primary-route wrappers.
- `REAL_CLIENT_EXPECT_PRIMARY_ROUTE` defaults to `REAL_CLIENT_ROUTE`.

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
