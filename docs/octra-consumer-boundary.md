# Octra Consumer Boundary

`headscale-rs` replacement parity means generic headscale-go replacement
behavior: stock Tailscale control-plane, admin gRPC/grpc-gateway, CLI, config,
database, policy, DNS, DERP, and debug surfaces that can be compared to
headscale-go. Octra-only product behavior is downstream unless it exposes a
reusable headscale-go contract missing from this repository.

## Downstream-Only Surfaces

| Surface | Boundary |
| --- | --- |
| admin mounting | `headscale-rs` owns upstream `/api/v1` grpc-gateway routes and stock public control routes. Octra full-Hub/admin routes mount downstream. |
| preauth store unification | The reusable contract is `PreauthAdmin` plus `PreauthRedeemer`. `InMemoryPreauthAdmin` now implements both traits for no-DB embedders; Octra account/key policy remains downstream. |
| embedded CLI documentation | `headscale-cli` parity docs and snapshots cover upstream `headscale` commands. `octravpn` wrapper commands and embedded operator docs live in the Octra repo. |
| settlement and billing policy | `headscale-rs` policy parity tracks headscale-go ACL, grants, nodeAttrs, and SSH behavior. Octra chain settlement, billing, resource quotas, and payment policy are downstream adapters. |

## Executable Evidence

`headscale-api/tests/grpc_gateway_e2e.rs` pins the replacement API boundary:

- `grpc_gateway_rejects_non_upstream_octra_api_routes` proves Octra-only legacy
  routes return the standard grpc-gateway 404 status JSON instead of being
  accepted by the replacement gateway.
- `grpc_gateway_swagger_excludes_non_upstream_octra_api_routes` proves the
  checked-in swagger does not advertise those downstream routes.

The excluded route set is:

- `/api/v1/nodes`
- `/api/v1/register`
- `/api/v1/status`
- `/api/v1/balance/{account}`
- `/api/v1/transfer`

Run the focused boundary evidence with:

```sh
cargo test -p headscale-api --features admin,full --test grpc_gateway_e2e grpc_gateway_rejects_non_upstream_octra_api_routes
cargo test -p headscale-api --features admin,full --test grpc_gateway_e2e grpc_gateway_swagger_excludes_non_upstream_octra_api_routes
python3 scripts/check_parity_backlog.py
```

## Removal Rule

The `p2-octra-consumer-boundary` backlog row is removable when the row is no
longer needed to block replacement parity claims and the generic contracts above
are covered in this repository. Future Octra-only route, CLI, billing, or
deployment requirements should be tracked in Octra unless they identify a
generic headscale-go contract that headscale-rs should expose.
