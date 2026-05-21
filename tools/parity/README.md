# Headscale-go differential harness

This harness compares observable policy-to-`tailcfg.FilterRule` output between:

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
- `wire`: typed `tailcfg` JSON fragments for DNS, DERP, register, and map
  response summaries. The Go side round-trips these through
  `tailscale.com/tailcfg`; the Rust side round-trips through
  `headscale-api::tailscale_wire::wire`.

Add scenarios here when closing parity gaps. Keep the default scenario set green;
put known divergences in separate local files until the implementation catches up.
