# headscale-rs

A Rust implementation of Tailscale-style mesh coordination: node
registration, WireGuard control plane, mesh topology, DERP relay,
and per-session bandwidth metering.

This crate is the **transport layer**. It deliberately does not own
escrow, payments, or settlement — those belong in an integration
layer that consumes the `MeteringSnapshot` events surfaced by
`headscale-core::metering::MeteringService`.

## Workspace layout

Three crates are first-class workspace members and participate in
`cargo build --workspace` / `cargo test --workspace` / `cargo clippy
--workspace`:

```
headscale-api       gRPC + HTTP control plane, Tailscale wire, admin GUI
headscale-db        sqlite-backed persistence (preauth keys, nodes, ...)
headscale-cli       headscale-rs daemon + operator CLI
```

Four crates are **on disk but not workspace members** as of
2026-05-20 (see [`CHANGES.md`](./CHANGES.md)). They are still
compiled when the active crates above pull them in via path
dependencies, so production builds are byte-identical; they just no
longer get their own per-crate test/clippy scope at the workspace
level.

```
headscale-core      mesh, WireGuard, DERP, metering, routing, authorization
headscale-identity  Ed25519 + DID + session primitives
headscale-resources resource registry + metering
headscale-payments  reference ledger / x402 / escrow / channels (deletion candidate)
```

To work on one of the demoted crates directly:

```
cd headscale-<name> && cargo build --release
cd headscale-<name> && cargo test
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
