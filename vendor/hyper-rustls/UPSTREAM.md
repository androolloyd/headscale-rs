# hyper-rustls 0.27.10 native adaptation rebase

This directory now starts from the exact authorized crates.io `hyper-rustls` 0.27.10 archive, SHA-256 `dfa8e654703247911e29c23fbeaa261834bd9bb74efba2f9acddc37bfb127f53`. Upstream `.cargo_vcs_info.json` is retained verbatim and identifies commit `ce45b6b0dfdf238f9058b89feb1e3b8eaebbc5b0`. Upstream source, manifests, archive-supplied tests/examples and original licenses are retained; the registry cache marker is excluded. No tests or fixtures were authored for this rebase.

`LOCAL.patch` records the complete local source/manifest delta against this archive. Go-derived code retains LICENSE-GO and LICENSE-GO-NOTICE and the combined package license metadata.

All prior default-off native lower-connector mapping, handshake timeout, record EOF observation and actual close_notify mapping remain. Upstream 0.27.10's public HttpsConnector::new constructor initializes the private native timeout to None and EOF selection to false, just like the builder and From constructors. Upstream ServerName imports now use rustls::pki_types, and its MSRV/dependency changes are retained. Ordinary/default connectors retain the upstream TLS path and native hooks remain explicit runtime choices.

`SOURCE_SHA256SUMS` records the final vendored files, local patch and provenance hashes (excluding itself). The initial implementation records below are historical; their former package pins and statements that no version changed describe those earlier edits. This section and the current archive/inventory supersede those package pin statements. Existing qualification limits remain in force.

Only source comparison, three-way source merging, independent source review and direct rustfmt were used. No tests, builds, Cargo commands, probes, validators, benchmarks or executable parity qualification were run in this rebase lane.

## Current upstream source SHA-256 for adapted files

- `Cargo.toml`: `ea73618088153351ec214a8bf7f5fa26a358f636a7cbe79b99a91961dc95a8fe`
- `Cargo.toml.orig`: `e5c2d451b9398887233bfafce4eff4e32bea450081f03945191664b388f14e78`
- `src/connector/builder.rs`: `79f98460fa32642fa7d07db59e419d13bdcd0c913ede1168bf087a541d134909`
- `src/connector.rs`: `3f2d7eb6967d2d9750ed0542a241f59b192b4ba830f5ef3e45f2d078eabe16df`

## Historical adaptation record

# Local exact-version connector adaptation

Upstream hyper-rustls 0.27.7, VCS commit
`aff7441ec40be7c334886f8807f32cccecb5adbe`.

This is the already-selected package, copied without a version/resolution update.
Root Cargo.toml patches/excludes this checkout; Cargo.lock removes only this
package's registry source/checksum and preserves its version/dependencies.
The default-off go-native-http-proxy feature adds Tokio's existing time feature
and forwards Rustls's default-off go-client-record-eof feature.
Original LICENSE, LICENSE-APACHE, LICENSE-ISC and LICENSE-MIT remain intact;
both native container recipes copy this package's LICENSE* files.
Both package manifests also record BSD-3-Clause for the selected Go EOF adaptation.

The additive hidden go_map_http_connector method replaces only the owned lower
connector while retaining TLS configuration, SNI resolver, HTTPS policy and
optional timeout. go_with_tls_handshake_timeout enables a deadline that starts
after lower connection completion, before TLS handshake. Every constructor
initializes the optional timeout to None. Feature-off and default None paths
retain the existing handshake and error wrapping. The native instant-acme client
explicitly selects these hooks for its own pool; ordinary SDK calls retain their
original HTTPS-only path. Downstream builds need equivalent patch configuration.

Independent source review/direct rustfmt only. No builds/tests, feature/backend,
package/container/client/process, security/advisory or parity qualification.

## Native client TLS EOF selection — 2026-10-18

The hidden go_with_record_boundary_eof method selects the native Rustls policy
only for this connector. Both constructors initialize the private selection to
false; go_map_http_connector preserves it. connect_with selects the connection
policy and captures its observer synchronously before handshake I/O.

Only selected handshake UnexpectedEof errors with a real transport observation
are remapped: record boundary becomes `EOF`, partial record becomes
`unexpected EOF`. An actual close_notify during an unfinished native handshake
is mapped to EOF only with its independent observer bit, InvalidData kind and
the exact inner Rustls AlertReceived(CloseNotify). Timeout, other protocol/I/O
and unobserved errors retain their existing handling. Application reads use the connection's selected Reader policy.
Native instant-acme selects both origin and HTTPS proxy TLS; its original SDK
connector clone retains the default selection.

Rustls UPSTREAM.md records Go source pins, the read-only TokioRustls adapter
trace, parsed close_notify handling and nested-transport behavior.
ErrorKind versus exact Go error identity, full TLS error/alert/decoder phases,
physical I/O and all runtime/feature/client qualification remain open.
Independent source reviews/direct rustfmt only; no executable evidence.
Go BSD terms and attribution are retained in LICENSE-GO and LICENSE-GO-NOTICE.

## Original package source SHA-256

- Cargo.toml: d835791214e048ded7c6deddc663b628e7e077daa67ce24fc9843e7999938fd0
- Cargo.toml.orig: 4a0120f81c4207801e29e7be002c91d98dc2eaba7c98ac0f98bf1c292df29a51
- src/connector.rs: d796974eecf557428a0f0dbceaea28b437d91bbfda2d3bf6c89f77157dfc50af
- src/connector/builder.rs: 1b5c3424dee4a0fe8d5ae0a1c882b732c209df4892e6756191a06d825e2647c7

## Local adaptation SHA-256 — 2026-10-18

- Cargo.toml: a9b022566dceabf829da7b6bfc536a28941e2c775c0e9c900a2f9ea022b36ba1
- Cargo.toml.orig: 4bac7b4903225b398286e0ec7a17e3232a1d38ac67cc28d87d2cc9bc8b83d7fe
- src/connector/builder.rs: 22ca93b5c593744589fba92a538294d11686bb15f266d4fe07589d1c5f41387b
- src/connector.rs: c18d5493821877bc6cdbc3db014ca5d1c5ae71868357ab60d3cf3e0f26fc6620

