# Headscale-go differential harness

This harness compares observable policy and wire output between:

- `headscale-rs`, via `tools/parity/headscale-rs`
- `headscale-go` current head, via `tools/parity/headscale-go`

The checked-in Go harness pins `github.com/juanfont/headscale` to
`v0.29.0-beta.2`, which resolves to upstream commit
`171fd7a3c54156965753a63639cdcafcd50c8d67`.

Run it from the repository root:

```sh
./scripts/headscale_go_diff.sh
```

CI also runs a Docker-free metadata check before the differential harness:

```sh
python3 scripts/check_parity_golden.py
python3 scripts/check_headscale_go_refs.py --remote
```

These checks verify that the pinned headscale-go version in
`tools/parity/headscale-go/go.mod` has a matching active golden, that scenario
file names and `name` fields line up, that pinned/current-head goldens cover
the checked-in scenario sets exactly, that the real-client current-head SHA
still matches upstream `main`, and that the pinned release tag exists upstream.

Scenario files for the pinned differential gate live in
`tools/parity/scenarios/*.json`. Each scenario carries an upstream-shaped HuJSON
policy object. The checked-in scenarios use headscale-go's native ACL syntax,
where policy files omit `version`, `proto` is per ACL rule, and ports are
embedded in `dst` entries such as `100.64.0.2/32:22`.
Current policy-v2 surfaces such as `grants` and `nodeAttrs` should be covered
here when the pinned headscale-go baseline and Rust implementation agree; stage
known divergences under `tools/parity/current-head/` until they can be promoted.

Scenarios may also include:

- `route_checks`: node route auto-approval checks compared against
  `headscale-go`'s `ApproveRoutesWithPolicy`.
- `via_route_checks`: viewer/peer `grants[].via` route-steering checks
  compared against `headscale-go`'s `PolicyManager.ViaRoutesForPeer`,
  including include, exclude, and `UsePrimary` route decisions.
- `filter_node_checks`: per-node `FilterForNode` checks, including
  `autogroup:self` reduction.
- `peer_map_checks`: per-node peer visibility checks compared against
  `headscale-go`'s `PolicyManager.BuildPeerMap`, including symmetric
  one-way ACL visibility and route-backed subnet-router visibility.
- `tag_checks`: `NodeCanHaveTag` checks for `tagOwners` behavior.
- `node_attr_checks`: per-node policy `NodeCapMap`/`nodeAttrs` checks,
  including top-level `randomizeClientPort`.
- `ssh_checks`: per-node `SSHPolicy` checks, including SSH user maps,
  `autogroup:self`, tagged destinations, and host destinations.
- `expect_policy_error`: a substring that both engines must reject during
  policy load; used for negative parser/validator parity scenarios.
- `wire`: typed `tailcfg` JSON fragments for DNS, DERP, register, and map
  response summaries. The Go side round-trips these through
  `tailscale.com/tailcfg`; the Rust side round-trips through
  `headscale-api::tailscale_wire::wire`.
- `wire.runtime_dns_config`: upstream-shaped DNS config input that both
  harnesses render through their runtime DNS builders. Use this for behavior
  that comes from config loading and map-time DNS construction, such as keeping
  MagicDNS peer names out of `DNSConfig.ExtraRecords`.

Add scenarios here when closing parity gaps. Keep the default scenario set green;
put known divergences in separate local files until the implementation catches up.
Headscale-go does not expose public `ipsets`; keep only negative rejection
coverage for that field, and do not add positive `ipset:` alias scenarios unless
a future upstream baseline adds the same surface.

The default differential run also checks
`tools/parity/golden/headscale-go-v0.29.0-beta.2.json`
after confirming the Rust and Go outputs match. Refresh it with
`PARITY_UPDATE_GOLDEN=1 ./scripts/headscale_go_diff.sh` only after reviewing the
semantic change.

Current-head-only scenarios live in `tools/parity/current-head/*.json` while
they are being staged. They use Rust golden verification through
`./scripts/headscale_rs_current_head_golden.sh` until they are promoted into the
default differential scenario set. The current default v0.29 gate now directly
compares formerly staged route-via steering, SSH `acceptEnv`,
hold-and-delegate SSH checks, SSH host-destination rejection, and
autogroup-internet exit-node route visibility against headscale-go.
