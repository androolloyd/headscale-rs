# Headscale-go differential harness

This harness compares observable policy and wire output between:

- `headscale-rs`, via `tools/parity/headscale-rs`
- `headscale-go` pinned release, via `tools/parity/headscale-go`

The checked-in Go harness pins `github.com/juanfont/headscale` to
`v0.29.5`, which resolves to upstream commit
`0f7d1e536bed9f01dd7161f7637af19bb0908335`.

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
the checked-in scenario sets exactly, that the pinned release tag exists
upstream, and that the real-client current-head SHA
(`tools/real-client/headscale-go-current.sh`) is a full commit hash. A current-head
SHA that no longer matches upstream `main` is reported as a warning
(`--fail-on-stale` makes it an error; see `docs/ci-quality-gates.md`).

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

The pinned v0.29.5 Tailscale compatibility captures can be converted into
temporary scenarios and compared with both engines using
`./scripts/headscale_go_capture_diff.sh`. The converter writes a manifest with
each upstream capture's SHA-256, API response code, and generated scenario.
`CAPTURE_PATTERN='capture-acl-c05.json'` narrows a run to one generated case.
`CAPTURE_AUDIT=1` checks each converted case independently and writes a JSON
report under `target/parity/capture-audit.json`, classifying output mismatches
and Go or Rust policy rejections without stopping at the first case. The audit
exits nonzero on output mismatches or one-sided rejections.
Generated files stay under `target/parity/captures-v0.29.5`; promote confirmed
cases into `tools/parity/scenarios` only after reviewing their semantic output.
All 875 pinned captures, including upstream API 400/500 cases, are converted.
The audit checks policy load, differential output, and pass/fail verdicts for
policy and SSH tests against the pinned Go policy manager. Upstream SaaS API
verdicts and exact rejection text are recorded as context, not asserted as
equivalent to headscale-go.

## Packet filters: what runs, what is compared

The `filter`, `filter_for_nodes` and `node_filters` outputs of the Rust side are
produced by production code, not by a harness copy of the compiler.
`tools/parity/headscale-rs/src/production_filter.rs` builds the inputs the
server has at startup (a `MachineRegistry` holding the scenario nodes, plus the
user list), loads the scenario policy through `PolicyStore::from_initial_registry_bytes`
and reads:

- `filter`: `PolicyStore::filter_rules`, compared with Go's `PolicyManager.Filter()`;
- `node_filters` (every node of every scenario) and `filter_for_nodes` (the
  named checks): `tailscale_wire::map::base_packet_filter_for_node` over the
  node projection of `packet_filter_nodes_for_registry`, i.e. the
  `PacketFilters["base"]` a `/machine/map` response carries, compared with
  Go's `FilterForNode`.

`headscale-api/tests/packet_filter_golden.rs` runs the same code against
`tools/parity/golden/headscale-go-v0.29.5.json` under plain `cargo test`
(no Go toolchain needed); the differential script keeps that golden honest by
refusing to pass when the pinned Go module no longer produces it.

Compared exactly: the number and order of the rules, and every field of every
rule after sorting. Not compared by default: the order *inside* a rule. The Go
harness sorts `SrcIPs`, `DstPorts` (by IP string, then ports), `IPProto`, the
caps of a `CapGrant` and the `CapGrant` list before printing, and the Rust side
applies the same sorts without de-duplicating, so a duplicate entry still shows.
Run `PARITY_FILTER_ORDER=emitted ./scripts/headscale_go_diff.sh` to switch the
sorts off on both sides (`CapGrant.Dsts` is always sorted by the Go harness's
`prefixStrings`). On 2026-10-25 both modes match for all 104 scenarios.
Scenarios Go rejects (`expect_policy_error`) are compared on the error class
only and are not compiled into filters.

The default differential run also checks
`tools/parity/golden/headscale-go-v0.29.5.json`
after confirming the Rust and Go outputs match. Refresh it with
`PARITY_UPDATE_GOLDEN=1 ./scripts/headscale_go_diff.sh` only after reviewing the
semantic change.

Current-head-only scenarios live in `tools/parity/current-head/*.json` while
they are being staged. They use Rust golden verification through
`./scripts/headscale_rs_current_head_golden.sh` until they are promoted into the
default differential scenario set. The current default v0.29 gate now directly
compares formerly staged route-via steering, SSH `acceptEnv`,
hold-and-delegate SSH checks, SSH host-destination rejection,
autogroup-internet exit-node route visibility, the multi-address
SSH/DNS/route policy matrix, and Taildrive/Taildrop capability grants against
headscale-go.
