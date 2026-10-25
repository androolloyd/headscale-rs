# SQLx-core provenance and local changes

This is SQLx-core **0.8.6**, copied from the Cargo registry source used by this
workspace. Its original crates.io archive checksum is
`ee6798b1838b6a0f69c007c133b8df5866302197e404e8b6ee8ed3e3a5e68dc6`.
The retained `.cargo_vcs_info.json` identifies upstream Git commit
`bab1b022bd56a64f9a08b46b36b97c5cff19d77e`, path `sqlx-core`.
The upstream MIT and Apache-2.0 license files are retained.

The workspace patches crates.io SQLx-core to this directory. It adds an
optional retained-idle connection cap to support headscale-go v0.29.5's
`database/sql.SetMaxIdleConns` setting:

- `src/pool/options.rs`: optional cap, direct connector/timeout controls,
  opt-in release-ping control, reuse-clock metadata, cloning and diagnostics.
- `src/pool/idle_queue.rs`: bounded, lazily allocated idle queue for explicitly
  capped pools, most-recently-returned reuse and expired-entry removal without
  rotating survivors; omitted caps retain the upstream `ArrayQueue` behavior.
- `src/pool/inner.rs`: clamp the minimum pool size to the idle cap and close
  excess returned connections while retaining their size/connection permits
  until close or cancellation. Capped maintenance removes expired entries
  without refreshing healthy idle timestamps or changing their reuse order.
  Direct mode uses one connector attempt, leaves acquisition deadlines to the
  caller and records the start of each successful reuse.
- `src/pool/connection.rs`: retain the reuse clock across pool moves and expose
  elapsed reuse time to callbacks; optionally omit the extra release ping
  after the caller's release callback drains and validates the connection.
- `src/pool/mod.rs`: register the private queue module.
- `src/common/statement_cache.rs`: an additive key-removal method lets the
  native driver invalidate a failed query without rotating other cache entries.
- `src/net/mod.rs` and `src/net/socket/mod.rs`: resolve candidates separately
  and dial an exact socket address, retaining IPv6 scope IDs. Native TCP uses
  Go's no-delay and 15-second idle/interval, nine-probe keepalive defaults where
  supported, ignoring socket-option errors as Go does.
  The Socket trait has optional borrowed access to the negotiated TLS leaf
  certificate; boxed sockets and `src/net/socket/buffered.rs` forward it.
  Rustls exposes its completed-handshake certificate for native SCRAM channel
  binding. Plain sockets and other backends keep the default absent result.
- `src/net/tls/mod.rs`: exclusive CA-file, shared PEM snapshots and OS-root
  inputs for pgx's trust policy; ordinary file inputs retain SQLx's policy.
  Inline material is redacted in Debug/Display. Native preflight validates CA
  material and client key/certificate consistency before connection attempts.
  An additive DER-key preflight infers PKCS#1/PKCS#8/SEC1 format independently
  of the PEM label, after the native Go loader selects a private-key block.
- `src/net/tls/go_pem.rs`: opt-in local RFC 1423 PEM decryption. AES-128/192/
  256-CBC uses locked AWS-LC 1.18.2. Private `go_pem/des.rs` uses the pinned Go
  DES permutations, key schedule and S-boxes for DES-CBC and DES-EDE3-CBC,
  accepting weak/semi-weak keys and equal effective subkeys as Go does. CBC
  chaining and RFC 1423 padding retain Go's decisions. This removes the prior
  source restriction imposed by AWS-LC's checked legacy DES constructors;
  the unused `legacy-des` feature is removed. It does not select TLS cipher
  suites or add a public DES API. Cipher/key/padding behavior has no execution
  qualification. Go's BSD notice is retained in `LICENSE-GO-STDLIB`, included
  by the existing container license copies; package metadata includes BSD.
- `src/net/tls/tls_rustls.rs` and `tls_native_tls.rs`: exclusive inputs replace
  built-in roots. OS inputs use a process-cached native store with Rustls.
  The native bridge selects Rustls explicitly even with native-tls features
  present, so preflight and handshake use the same backend. It adds direct
  PostgreSQL ALPN and independent SNI suppression. CA-only verification accepts
  both Rustls hostname-error variants after the chain has been verified and
  uses an explicit verifier provider to avoid ambiguous global provider
  selection when dependencies enable both Rustls crypto providers.
  Preflight canonicalizes retained PEM material; unsupported client keys fail
  before fallback. Go certificate-parser/algorithm equivalence is unqualified.
  The optional native-tls backend uses its documented
  [built-in-root control](https://docs.rs/native-tls/0.2.18/native_tls/struct.TlsConnectorBuilder.html#method.disable_built_in_roots).
- `Cargo.toml` and `Cargo.toml.orig`: reuse the workspace's already-locked
  webpki-roots 1.0.5 for the newly activated AWS-LC TLS feature instead of
  resolving a separate 0.26 package. Its trust-anchor API is used unchanged.
  Native-cert loading is a required dependency, reusing locked
  rustls-native-certs 0.8.3; the old implicit feature name remains an explicit
  compatibility feature. OS roots can therefore be selected with AWS-LC
  without activating SQLx's Ring provider feature.
  Native socket options use already-locked socket2 0.6.1 with its `all` feature
  on Unix/Windows; no new package version was resolved.
  The new `go-pem-compat` feature selects an optional direct AWS-LC 1.18.2
  dependency with `non-fips`. The private Go DES adaptation no longer needs
  AWS-LC's `legacy-des` feature. Headscale-db forwards it only from its explicit Go bridge feature;
  ordinary SQLx configurations do not activate it. No build, binding/feature
  graph, FIPS, advisory or license check qualifies this new activation.

An explicit zero cap retains no returned connections. The lazy queue avoids
allocating storage proportional to SQLx's `u32::MAX` open-connection ceiling
when representing Go's unlimited-open setting. Capped pools use Go's most
recently returned connection first; uncapped pools retain FIFO reuse.
Default acquisition, connector retry and release-ping behavior remain SQLx's.
The headscale runtime opts into direct connector mode, so its acquisition
deadline belongs to the caller. The native Postgres driver owns its resolved
per-address-group connector deadlines. Postgres callbacks use the reuse clock for pgx's conditional
`-- ping` and drain pending protocol work before return. Idle retirement
scheduling still needs database/sql qualification.

This local patch reuses existing resolved crate versions and changes feature
and dependency requirements as listed above. It has not been built, tested,
audited or process-qualified
in this implementation batch. Future SQLx updates must review and rebase these
changes. The CLI enables headscale-db's `go-pool-compat` feature. External
workspaces opting into that feature must carry this root `[patch.crates-io]`
entry and, for Postgres, the companion SQLx-postgres patch. Generic database
embeddings do not enable it. The known wire-only API consumer is unaffected.

## Legacy PEM source pins — 2026-10-18

The private DES/TDEA path uses Go 1.26.9's standard tables and the same key
selection, half rotations and Feistel substitution/permutation operations.
Its straightforward permutations retain the standard block layout rather
than Go's optimized packed-round layout. TripleDES decryption is D(K1,
E(K2, D(K3, ciphertext))); CBC preserves the preceding ciphertext block.
Correctly sized keys are accepted without parity/weakness/degeneracy rejection.
RFC 1423 padding follows crypto/x509. This local compatibility does not add
TLS suites or a general cipher API. It does not establish cryptographic,
constant-time, side-channel, FIPS, resource or security qualification.

Go source SHA-256:
- crypto/des/const.go: fb1b9ff9539a17a3cffd374e75bfcedbebbaf23732365af56003f04697c6c3b9
- crypto/des/block.go: b2db89bff122de6f8ad47510522c297c5e7adbbb8527543a9beb50c303985c92
- crypto/des/cipher.go: 0dfa5c8ef6e6043f5031b412cb66f58b8ce197a7a3494c0effc475a7663a0335
- crypto/x509/pem_decrypt.go: 062b4025a467daf8eb1955f4afa4ce8ed19d7234274a28edf724062eae944b6f

tools/generate-go-des-tables.py checks and translates only the pinned constants
source. The original BSD license is retained in LICENSE-GO-STDLIB and package
metadata; existing container license copies include it. No dependency release
changed. Only source reads/hashes/translation/edits and direct rustfmt ran.
Cipher execution, tests, builds, validators, probes and fresh advisory checks
were not run. Full key/cipher/PEM/DER/provider/driver/error/feature/package/
container/native/client/process/import/restart qualification remains open.


## Delegate pool execute to the acquired connection — 2026-10-18

The pool Executor now overrides execute by acquiring one connection and calling
its execute method. This preserves driver overrides rather than forcing every
pool through the trait's default execute_many aggregate. The native Postgres
adapter requires this distinction for pgx last-CommandTag and Exec mode behavior.
Connections using the default method retain aggregation. No public trait method
or type changed. Source/direct rustfmt only; generic/native driver lifetimes,
error ordering, cancellation, pooling and feature behavior have not been built
or executed. All runtime and replacement-parity qualification remains open.


## Any backend command delegation — 2026-10-18

AnyConnectionBackend has an additive default execute method retaining aggregate
fetch-many behavior. The Any Executor delegates to it, and native Postgres
provides its concrete command-intent override. Generic Postgres Any preserves
its former row conversion/error/aggregation path; other backends keep the new
default. Existing optional arguments/persistence and initial Encode errors stay
at their prior boundary. Source/direct rustfmt only; no compilation, lifetimes,
feature/generic-driver or native runtime qualification was performed.

## Authorized compatible socket dependency upgrade — 2026-10-18

The native socket2 exact pin moves from0.6.1 to0.6.5 with features=all retained
in both manifests. Its unchanged SockRef/TcpKeepalive builder/setter APIs cover
current native keepalive calls. This removes the old pin's resolver conflict
with Tokio1.51+ (which requires socket2^0.6.3), allowing current compatible
Tokio selection. This is source/resolution work only, not keepalive execution
or platform qualification. Original SQLx local source adaptations are retained.

The same authorized upgrade advances the explicit webpki-roots1.0.5 pin to
1.0.9 in both manifests. The trust-anchor API remains unchanged; CA/trust and
platform behavior need final qualification.

## Security advisory pin bump — 2026-10-25

The exact webpki-roots pin moves from 1.0.9 to 1.0.11 in both manifests to
clear RUSTSEC-2026-0381 (bundled roots allow trust in distrusted emSign
intermediates; fixed in >=1.0.10). Only the pin changed: the trust-anchor API is
the same, and Cargo.lock moves webpki-roots, webpki-root-certs and rustls-webpki
(RUSTSEC-2026-0383, RUSTSEC-2026-0382) within their semver-compatible ranges.

Current manifest SHA-256:

- Cargo.toml: 793f3029745ddb104e0e23e347c08fa6ffd04b4a23bd27e7f4c879d54414cf5a
- Cargo.toml.orig: a704eecee74928e96d1118b943aa86ec084168fe5a2590900b304ed2d1f7e4e4
