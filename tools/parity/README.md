# Headscale-go differential harness

This harness compares observable policy and wire output between:

- `headscale-rs`, via `tools/parity/headscale-rs`
- `headscale-go` current head, via `tools/parity/headscale-go`

The checked-in Go harness pins `github.com/juanfont/headscale` to
`v0.29.0-beta.1.0.20260522122924-4483fd0cad38`, the Go pseudo-version for
upstream commit `4483fd0cad38717913e7509fc50f9d48c691b02b`.

Run it from the repository root:

```sh
./scripts/headscale_go_diff.sh
```

Scenario files for the pinned differential gate live in
`tools/parity/scenarios/*.json`. Each scenario carries an upstream-shaped HuJSON
policy object. The checked-in scenarios use headscale-go's native ACL syntax,
where policy files omit `version`, `proto` is per ACL rule, and ports are
embedded in `dst` entries such as `100.64.0.2/32:22`.

Scenarios may also include:

- `route_checks`: node route auto-approval checks compared against
  `headscale-go`'s `ApproveRoutesWithPolicy`.
- `filter_node_checks`: per-node `FilterForNode` checks, including
  `autogroup:self` reduction.
- `peer_map_checks`: per-node peer visibility checks compared against
  `headscale-go`'s `PolicyManager.BuildPeerMap`, including symmetric
  one-way ACL visibility and route-backed subnet-router visibility.
- `tag_checks`: `NodeCanHaveTag` checks for `tagOwners` behavior.
- `ssh_checks`: per-node `SSHPolicy` checks, including SSH user maps,
  `autogroup:self`, tagged destinations, and host destinations.
- `expect_policy_error`: a substring that both engines must reject during
  policy load; used for negative parser/validator parity scenarios.
- `wire`: typed `tailcfg` JSON fragments for DNS, DERP, register, and map
  response summaries. The Go side round-trips these through
  `tailscale.com/tailcfg`; the Rust side round-trips through
  `headscale-api::tailscale_wire::wire`.

Add scenarios here when closing parity gaps. Keep the default scenario set green;
put known divergences in separate local files until the implementation catches up.
Headscale-go does not expose public `ipsets`; keep only negative rejection
coverage for that field, and do not add positive `ipset:` alias scenarios unless
a future upstream baseline adds the same surface.

The default differential run also checks
`tools/parity/golden/headscale-go-v0.29.0-beta.1.0.20260522122924-4483fd0cad38.json`
after confirming the Rust and Go outputs match. Refresh it with
`PARITY_UPDATE_GOLDEN=1 ./scripts/headscale_go_diff.sh` only after reviewing the
semantic change.

Current-head-only scenarios live in `tools/parity/current-head/*.json`. They use
Rust golden verification through `./scripts/headscale_rs_current_head_golden.sh`
until they are promoted into the default differential scenario set. Current-head
SSH scenarios cover fields such as `acceptEnv`, and behavior such as
hold-and-delegate SSH checks, that were introduced after the old v0.28 baseline.
