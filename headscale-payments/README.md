# headscale-payments

> **Kept on disk but excluded from workspace cargo** as of 2026-05-20.
> Marked for deletion once the active crates can be refactored off of
> it. See [`../CHANGES.md`](../CHANGES.md) for the deprecation
> contract.

This crate is no longer listed in `[workspace.members]` at the
workspace root. `headscale-db`, `headscale-cli`, and
`headscale-api[full]` still consume it via path dependencies
declared in `[workspace.dependencies]`, so it continues to compile as
part of a normal `cargo build --workspace` from the repo root.

OctraVPN deployments use the Octra chain for payments and metering;
this crate is dead weight in production. The path-dep entanglement in
`headscale-db::payments` and `headscale-db::models::to_transaction`
is what is keeping it alive — once those modules are extracted or
deleted, this crate can be `git rm`'d cleanly.

To build or test this crate in isolation:

```sh
cd headscale-payments && cargo build --release
cd headscale-payments && cargo test
```

## Contents

Reference ledger / x402 micropayments / escrow / channels. None of it
is on the OctraVPN hot path.
