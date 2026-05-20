# headscale-identity

> **Kept on disk but excluded from workspace cargo** as of 2026-05-20.
> See [`../CHANGES.md`](../CHANGES.md) for the deprecation contract.

This crate is no longer listed in `[workspace.members]` at the
workspace root. The three active crates (`headscale-api`,
`headscale-db`, `headscale-cli`) still consume it via path
dependencies declared in `[workspace.dependencies]`, so it continues
to compile as part of a normal `cargo build --workspace` from the
repo root.

To build or test this crate in isolation:

```sh
cd headscale-identity && cargo build --release
cd headscale-identity && cargo test
```

`cargo build --workspace` / `cargo test --workspace` / `cargo clippy
--workspace` no longer cover this crate's own tests or lints — only
what the active crates pull through.

## Contents

DID + Ed25519 keypair + session primitives. OctraVPN deployments
prefer their own wallet / signature stack and route around this crate
where possible; it survives here for embedders that want the DID
helpers.
