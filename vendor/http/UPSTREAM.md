# Selected http source and native header capacity

This directory starts from the exact crates.io `http` 1.5.0 archive selected
by the authorized dependency upgrade. Its archive SHA-256 is
`918d3568bebf352712bc2ef3d46a8bcf1a75b373be6539de198e9105cbbf9ce0`.
Registry `.cargo_vcs_info.json` is retained verbatim: commit
`e559023f67e3fad6ecc3ee91307be178e0f13626`, with upstream's `dirty: true`.
The registry cache marker `.cargo-ok` is excluded. Upstream source, fixtures,
tests, manifests, changelog and dual MIT/Apache-2.0 licenses are retained.
No tests or fixtures were authored for this adaptation.

Original selected source SHA-256 values:

- `src/header/map.rs`: `fff2c8490382c7e739e0b2d0ac344c2acc33e8d47f80643c85742b57950da648`
- `Cargo.toml`: `a949b1afc8b7fe334e9f6038b88d987e6a83b41b10cc852ad11dad1ead3c296d`
- `Cargo.toml.orig`: `d746fe0ed51dfd2a4e92c9a8c2348278adea73671187bbb711f231cd3c19669b`

`LOCAL.patch` records the complete local source/manifest delta against that
archive. It adapts the previously prepared 1.4.0 native capacity patch onto
1.5.0, preserving the intervening upstream fixes, including HeaderMap
iterator safety and Extend capacity clamping and the URI parsing fixes.

The new `go-native-header-capacity` feature is off by default. Without it,
the original private `u16` index/hash representation and `1 << 15` raw table
capacity are unchanged. With it, the private index and hash types both use
`u32` and the maximum raw table capacity is `1 << 22`. The hash mask derives
from that same capacity. This avoids both index truncation and a hash bucket
range restricted to the original width. The all-ones empty-index sentinel is
still outside every supported table/index range. The selected maximum times
the existing load-factor threshold also fits 32-bit usize arithmetic.

Cargo feature unification selects this representation for every user of this
package in the build; it is not a per-map runtime flag. Public APIs and public
field types are unchanged, but maps using the feature allocate wider private
index entries. Native admission retains separate byte limits; the larger
map ceiling does not replace those limits or imply bounded total memory use.

Only source comparison and direct rustfmt were used. No tests, builds,
benchmarks, runtime probes or validators were run for this adaptation.
