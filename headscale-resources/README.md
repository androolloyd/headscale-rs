# headscale-resources

> **Kept on disk but excluded from workspace cargo** as of 2026-05-20.
> See [`../CHANGES.md`](../CHANGES.md) for the deprecation contract.

This crate is no longer listed in `[workspace.members]` at the
workspace root. `headscale-db`, `headscale-cli`, and
`headscale-api[full]` still consume it via path dependencies
declared in `[workspace.dependencies]`, so it continues to compile as
part of a normal `cargo build --workspace` from the repo root.

`octravpn-node` has reimplemented metering on its own primitives; the
registry / metering surfaces here may be revisited later when we
formalise the provider-capability registry, per the headscale gap
analysis.

To build or test this crate in isolation:

```sh
cd headscale-resources && cargo build --release
cd headscale-resources && cargo test
```

## Contents

Resource registry, resource type / pricing definitions, allocation
helper, metering primitives, and prometheus metrics for the same.
