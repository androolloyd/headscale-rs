# headscale-rs

A Rust implementation of Tailscale-style mesh coordination: node
registration, WireGuard control plane, mesh topology, DERP relay,
and per-session bandwidth metering.

This crate is the **transport layer**. It deliberately does not own
escrow, payments, or settlement — those belong in an integration
layer that consumes the `MeteringSnapshot` events surfaced by
`headscale-core::metering::MeteringService`.

## Workspace layout

```
headscale-core      mesh, WireGuard keys, DERP, metering, routing
headscale-identity  node identity + auth
headscale-resources resource discovery / advertisement
headscale-payments  reference ledger / channel / x402 — replace with your own
headscale-api       gRPC + HTTP control plane
headscale-db        sqlite-backed persistence
headscale-cli       headscale-rs daemon + CLI
```

## Build

```
cargo build --workspace
```

## Origin

Extracted from a private last-net swarm experiment (Radicle Heartwood
fork). The Radicle-coupled business-logic modules (`accounting`,
`rental`, `rental_service`, `foreman_bridge`) have been removed; this
repo is now standalone and runs on its own metering primitives.
