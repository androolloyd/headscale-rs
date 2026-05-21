# Headscale-go differential harness

This harness compares observable policy and wire output between:

- `headscale-rs`, via `tools/parity/headscale-rs`
- `headscale-go` v0.28.0, via `tools/parity/headscale-go`

Run it from the repository root:

```sh
./scripts/headscale_go_diff.sh
```

Scenario files live in `tools/parity/scenarios/*.json`. Each scenario carries an
upstream-shaped HuJSON policy object. The checked-in scenarios intentionally use
headscale-go's native ACL syntax, where policy files omit `version`, `proto` is
per ACL rule, and ports are embedded in `dst` entries such as
`100.64.0.2/32:22`.

Scenarios may also include:

- `route_checks`: node route auto-approval checks compared against
  `headscale-go`'s `ApproveRoutesWithPolicy`.
- `filter_node_checks`: per-node `FilterForNode` checks, including
  `autogroup:self` reduction.
- `tag_checks`: `NodeCanHaveTag` checks for `tagOwners` behavior.
- `ssh_checks`: per-node `SSHPolicy` checks, including SSH user maps,
  `autogroup:self`, tagged destinations, host destinations, and `checkPeriod`.
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
