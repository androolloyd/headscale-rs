# Headscale-go differential harness

This harness compares observable policy and wire output between:

- `headscale-rs`, via `tools/parity/headscale-rs`
- `headscale-go` v0.28.0, via `tools/parity/headscale-go`

Run it from the repository root:

```sh
./scripts/headscale_go_diff.sh
```

Scenario files for the pinned differential gate live in
`tools/parity/scenarios/*.json`. Each scenario carries an upstream-shaped HuJSON
policy object. The checked-in scenarios intentionally use headscale-go v0.28's
native ACL syntax, where policy files omit `version`, `proto` is per ACL rule,
and ports are embedded in `dst` entries such as `100.64.0.2/32:22`.

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
The pinned headscale-go v0.28 policy surface does not expose `ipsets`; do not add
`ipset:` scenarios to this harness until the Go side supports them.

The default differential run also checks
`tools/parity/golden/headscale-go-v0.28.0.json` after confirming the Rust and Go
outputs match. Refresh it with `PARITY_UPDATE_GOLDEN=1
./scripts/headscale_go_diff.sh` only after reviewing the semantic change.

Current-head-only scenarios live in `tools/parity/current-head/*.json`. They use
Rust golden verification through `./scripts/headscale_rs_current_head_golden.sh`
until `tools/parity/headscale-go` is deliberately rebased to an upstream version
that can execute the same policy surface. Current-head-only SSH scenarios cover
fields such as `acceptEnv`, and behavior such as hold-and-delegate SSH checks,
that the pinned v0.28 policy parser or compiler does not expose.
