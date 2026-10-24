# Local exact-version source adaptation

This checkout uses the already-selected crates.io package, with no version or
resolution update. Root Cargo.toml patches the package and excludes its copied
checkout from workspace membership; Cargo.lock keeps the selected version and
existing dependency list while removing only its registry source/checksum.
Downstream embedders need equivalent patch configuration to use these additive
APIs. Cargo package/container/feature behavior has not been executed.

Upstream `rustls 0.23.46`, VCS commit `f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb`.

## Native raw SNI scope

The default-off `go-server-client-hello` feature adds explicit per-Acceptor
`go_server_client_hello()` and borrowed `ClientHello::raw_server_name()` APIs.
Only the API full native provider acceptor opts in. Compiling the feature does
not opt default/Tonic/client/unbound connections in.

A private Reader mode follows subreaders and subsequent messages. Native SNI
requires complete nonempty U16 list/item framing, skips unknown name types,
rejects duplicate hostname entries and a final ASCII dot, and retains arbitrary
nonempty hostname bytes. The exact encoded extension is retained for transcript
re-encoding; copies are bounded by TLS U16 framing. HRR compares exact raw name
bytes; typed DNS accessors remain strict convenience projections. Native
Unicode/IP host names receive the ordinary SNI acknowledgement.

A private session-prefix tag retains optional U16 raw identity for native TLS
1.2/1.3 sessions; resumption requires matching native/default mode and raw name.
Default session encoding is unchanged. This intentionally preserves Rustls's
cross-name protection; Go's server tickets do not themselves bind serverName.
This is not Go TLS/session-format equivalence. Native certificate preparation
now has the version/PSK-aware phase implementation below; broader version,
cipher/extension validation, alerts, provider and resources remain separate
source or qualification boundaries.

Independent source reviews and direct rustfmt only. No build/test/feature,
handshake/PSK/HRR/resumption/package/container execution or release gate closure.

## Selected Go source SHA-256

Go toolchain 1.26.9 src/crypto/tls:

- handshake_messages.go: b3a61247d78d93e196debfb6d6202e9f771d732de94bd4c30d7dbbebad4ac2b3
- handshake_server.go: 371e52320f1011df2b23f1ee942f0ef0e6130cb53c8e7b2f83b7aff69cae21cb
- handshake_server_tls13.go: 54cce7be02c286d397b9af1ded5a24ad356962ad5fbfb37bf8f93ded9c32aee0
- ticket.go: 61b0247979c73930db8bac363c5c6a5cf7b38906fd4be67f5a9967c8818fb1df

## Original package source SHA-256

- src/common_state.rs: f47f795cd2f8b393971e9896dfbf69c38d78aef9610797cc4534d61b0c16491f
- src/conn.rs: 60b4bf4186776efe7df71c43be3aef44027cfde06f393e1238efbb9d1cfdfcf9
- src/msgs/codec.rs: fa53201ef4387a453c626c37138a6a2de2d2ff13d85c0ec34f8b13ee20daeeaf
- src/msgs/message/mod.rs: f1bdfa1ee08e31e54c85dd1c47d090afee672bd50bb6074aaa9c51d08feae3bf
- src/msgs/handshake.rs: 9f9d9d4686e4a3f4433edf5fcc17c224155fa3eef747363bfa53802fd67dda7d
- src/msgs/persist.rs: 2d88c8855a11c6ced38f4688da8cc772c2c41f84a165ba77c9f8bde30ff96891
- src/server/server_conn.rs: 603cddb8a3a415737b7e047deedd32a2a6e4f918c2372af0bfb50ebb04de2163
- src/server/hs.rs: b1ed14e5e36ee46bfb843b86af58efda01cdaa71a7f25a2f647da21f52529f91
- src/server/tls12.rs: b7d083644d3be9bb6bf6cca4c654537cd22d3bc545f932ab2c9354503ebd7056
- src/server/tls13.rs: bd2482dad0811a179ea55af468f59d567e520a533a021a0e2f99c3b2afdbf18c

- src/crypto/signer.rs: b097775c0b30d507255824a8ac65d8d7440e723b16a9e91036e0d096a3d7b071
- src/crypto/aws_lc_rs/sign.rs: 8163d1a10e5ce0d729af920ba8b5ad9096a0553a3b2b7798fb400bfc422f23b9

## Licensing

Original upstream license files remain intact. Adapted Go source retains
Go Authors attribution and BSD terms in LICENSE-GO and LICENSE-GO-NOTICE.
Both package manifests include the additional BSD-3-Clause requirement; both
native container recipes copy this package's LICENSE* files.

## Native certificate-provider phase — implemented, unvalidated

Native Acceptor parsing retains absent original signature_algorithms without
synthesizing offers. Normal into_connection still rejects that absence; only
explicit go_into_connection enters the native deferred state machine.

TLS1.2 negotiates ALPN and pauses for a certificate before certificate-dependent
suite selection and resumption. TLS1.3 rejects TCP early_data, completes HRR
handling and computes/validates key exchange once, negotiates ALPN, and checks
PSK/session identity and the original binder before any provider call. A valid
PSK skips certificate preparation. A full handshake rejects a missing signature
extension before suspending for preparation. Native ALPN retains Go's h2-server/
http1.1-client fallback to no negotiated ALPN. Later extension processing reuses
that result. Default paths retain their previous ordering.

The pause owns decoded ClientHello, original transcript encoding, continuation
and completed TLS1.3 key exchange. Pending state stops packet deframing and read
admission. Completion resolves only the selected certificate/key from prepared
material; baseline configuration retains session/ticket, crypto, ALPN and
verification policy. Original optional, unfiltered signatures reach the API's
nil-aware ECDSA selection. No binder, ticket lookup or key exchange is replayed.

API raw_tls/acme_handshake.rs drives this original connection through HRR and
suspension, awaits the provider only on certificate demand, writes errors via
the original record writer, and completes flush/buffered-record processing
before tokio-rustls accept_with replaces its fresh state before I/O. There is
no temporary ordinary certificate or synthetic handshake.

Source locations: Go handshake_server.go69–75/278 and negotiateALPN,
handshake_server_tls13.go67–76/processClientHello/checkForResumption/
pickCertificate, auth.go252–259, key_agreement.go195. Selected Go1.26.9 pins:

- crypto/tls/auth.go: 7bdcfa1d4d1b53fb8e1306bcf8712037ac870cc793685d243cab508ebe654bef
- crypto/tls/key_agreement.go: 3874cd45e07283547ae3ab6ba4a10893323210ba153906fe586ce0158ba45862
- internal/godebugs/table.go: c8d5b6e7358fd39befe8df0cb31bb859804ced8182b85f0b01355e3a845f7fa9

Headscale go.mod declares1.26.8 and the selected default does not enable legacy
SHA1 fallback. Existing handshake_server hashes apply. Broader TLS decoders,
version/cipher/group choices, HRR validation of other fields, signature-failure
edge diagnostics, X.509/provider/session formats and resources remain source
or qualification boundaries. Independent source reviews/direct rustfmt only;
no builds/tests, handshake/HRR/PSK/client/feature/package/process qualification
or acceptance gate closure.

## Native signing selection and failure flights — 2026-10-18

TLS 1.3 selects and owns the native signer before transcript/ServerHello
publication and reuses it at CertificateVerify. Native selection traverses the
actual client offers in order through singleton provider calls. TLS 1.2 defers
missing/no-common selection to ServerKeyExchange after buffering the preceding
flight. Native key-exchange/sign failures publish the partial flight before
HandshakeFailure; TLS 1.3 actual signing failures publish their encrypted
partial flight before InternalError. Default runtime paths retain their order.

The additive default SigningKey::go_choose_scheme delegates to existing
provider policy. The AWS native TLS 1.2 ECDSA override permits SHA-256/384/512
independently of EC curve via the optional exact-version aws-lc-rs adaptation.
TLS 1.3/default signing retains the existing scheme/curve relation. Native AWS
RSA filters offered schemes using Go byte-size minima: PSS256/384/512 need
66/98/130 bytes; PKCS1 SHA256/384/512 need62/78/94. Public modulus byte length
uses the selected provider's ceiling bit-to-byte conversion, matching Go Size.
A non-byte-aligned PSS modulus can pass that filter then fail actual signing.
The native AWS signer now exposes its actual modulus bits through an additive
provider hook. Only on an actual TLS1.3 PSS signing failure, floor(bits/8) below
2*hashsize+2 selects HandshakeFailure after the partial flight; other failures
select InternalError. The hook defaults false for other providers and is only
consulted in explicit native mode. Runtime alert/signature behavior remains
unqualified.

The rustls native feature weakly forwards aws-lc-rs/go-native-tls12-ecdsa;
no backend is forced by the feature alone. Root patches the already-locked
aws-lc-rs1.18.2 source, without a version/sys dependency update. Both dependency
patches are needed by downstream consumers of these native APIs. Original
upstream behavior remains the fallback for ring/custom providers. AWS provenance,
Go terms and build/FIPS/backend limitations are in ../aws-lc-rs/UPSTREAM.md.

Existing Go auth.go/key_agreement.go/handshake_server hashes apply. Source
review/direct rustfmt only; all signing, alert/record ordering, HRR/resumption,
feature/backend/package/container/client/process qualification remains open.

## Native server record-boundary EOF — 2026-10-18

The existing per-connection go-server-client-hello selection now also selects
Go's application Reader EOF rule. A private Reader marker records whether the
unconsumed TLS record deframer is empty. After plaintext drains and transport EOF
is observed, native servers return EOF without close_notify only at that boundary;
a partial record retains UnexpectedEof with Go's `unexpected EOF` text. A real
close_notify remains clean. The Reader reborrow retains this marker.

Default/Tonic/client readers keep Rustls's original truncation handling and error
text. This does not change IoState's peer-close notification, TLS alert handling,
handshake complete_io EOF handling or client selection. No public field/signature,
manifest, version or dependency resolution changed. Source review/direct rustfmt
only; no handshake/client/server/resource/feature/package/runtime qualification.

Selected Go1.26.9 crypto/tls/conn.go readRecordOrCCS accepts missing close_notify
only when readFromUntil returns UnexpectedEOF with empty rawInput. SHA-256:

- crypto/tls/conn.go: c5267d4cc54fef91f4346e82865bee81224599c080dd2c559b21e09dd1d7e7d6

## Client EOF follow-up original source SHA-256 — 2026-10-18

- Cargo.toml: ef983ace35d7ad699e22682ee0ee45211f805b074fc9e84190b62f200259070f
- Cargo.toml.orig: 279a804f483d7e4ac77a56dcb58cef9832b71e48af4280d5473945a81e93b2e8
- src/client/client_conn.rs: 7cf3803f3b95e078743d687ab08b8c1d183c0c27a502a2a3d4403a512874b92d
- src/lib.rs: 7bd4855fe9628a0d596e89edf8130a6c099a14a0b7f7bbb28953b53c01810502

## Native client record-boundary EOF — 2026-10-18

The default-off go-client-record-eof feature requires std and adds hidden
per-connection selection plus a GoClientEof observer. Selection is independent
of the server flag; ordinary clients retain Rustls's original EOF policy.
The native ACME connector explicitly selects this policy for origin and HTTPS
proxy TLS. The observer is allocated only when explicitly requested.

For both native selections, the raw record boundary is the filled deframer extent
equal to the processed record extent. This supersedes the earlier empty-deframer
description: complete records can remain buffered for fragmented handshake
messages. Plaintext drains before application EOF. A real underlying zero read
records the boundary; an underlying UnexpectedEof from a nested TLS transport is
normalized using this layer's own boundary. Boundary EOF becomes Ok(0), while a
partial record retains UnexpectedEof with `unexpected EOF`. Other errors and
positive reads retain their existing handling.

The optional observer preserves the first real transport EOF classification for
the selected HyperRustls handshake adapter. An actual unfinished-handshake
close_notify uses an independent observer bit and an immediate existing
AlertReceived(CloseNotify) error, without fabricating handshake success or a
read_tls zero result. This selected client branch checks the parsed close_notify
description before alert-level/version dispatch, as Go does. The connector maps
only the exact inner Rustls alert plus observer marker. Rust ErrorKind matching
cannot distinguish Go's exact UnexpectedEOF sentinel from a custom or wrapped
error with the same kind. Default complete_io behavior and full alert/decoder/
handshake diagnostic equivalence, physical I/O and runtime/resource qualification
remain open.

Selected source: Go1.26.9 crypto/tls/conn.go readRecordOrCCS,
readHandshakeBytes and handshakeContext; its SHA-256 is recorded above.
TokioRustls 0.26.4 was inspected without modification: connect_with invokes its
configuration callback before I/O, application reads use Reader, and unfinished
handshake EOF takes a separate error path. Adapter source SHA-256:

- tokio-rustls/src/common/mod.rs: 56453fb0a2f704e9387eb83567804e0517fd79ca9376fd73dd3514a3c8385a52
- tokio-rustls/src/client.rs: 9fac71d97f0f66604b8fa77927978fff23dc1e7a5ec695044f2599439654ff62

Independent source reviews/direct rustfmt only. No builds/tests/probes, dependency
resolution, feature/backend/client/process/security or parity qualification.
Original Rustls terms and retained Go BSD attribution apply.

## Local implementation source SHA-256 — 2026-10-18

- Cargo.toml: cdd700e0ca1ed06f90d3b6d668823b10edef752a305c45497e64a422039f2788
- Cargo.toml.orig: d8303c1e6d58b1eb2b642f8740dc176d8dc2d3cd04a075068df78b5039ed24e7
- src/client/client_conn.rs: 8fa75d99ddfbaf2484b93c82c20a417439aca8a2657ba99ee105d106d29cca05
- src/common_state.rs: 44f0be41e75ad8281c9e455ce63d9762d9b1e057e76b537934ef59012e4d1c94
- src/conn.rs: da26eeb7ff657148dc37c034550cb5458e5f806bfd0b30592c857c64916a6f68
- src/crypto/aws_lc_rs/sign.rs: f25c7cd7c8333e0ab0b45a50cc1d9c63acb50e0ef0d06bb93aa09a81357d510b
- src/crypto/signer.rs: c6339182ab9f20b68a7f947b0d257f2bc84031d41d6721333a3d81947604f0b4
- src/lib.rs: 20f36bcd617195655cdcbdbc2d1c58f2bc600e84a611117649953befada98681
- src/msgs/codec.rs: abb53b83125318920ddcb15697448add7c47dc81f9ec1046be07964b3b956e28
- src/msgs/handshake.rs: 22e619ab1f0ec57b414bc00669a821811007c15a94413685c6208c320774cf9e
- src/msgs/message/mod.rs: 0443e46be548b3208c1e061813195ff5157e33dd34ec9fb203c79d1666e56ee1
- src/msgs/persist.rs: a4106916f7c4c1625c57c0c0c30f6ae8f2a16b0e70c78a484e65eecaa22e6299
- src/server/handy.rs: ddd7de113c20ea375aeac8185a6014999098c258a4dd25bdefe8f0934b702c68
- src/server/hs.rs: b21554213f79d96a5c6e3d6861186628b8ab2fda162b376b754fd25b5bd9a0e3
- src/server/server_conn.rs: 464c209b6cf313c34b2d353f255dd4335217375eced46bf3eec7297d474f423f
- src/server/tls12.rs: 7f397b5a93b330791379ade029aa062485b78ec4650475ac8e5dd3ad69cdc0d4
- src/server/tls13.rs: af474cdf0b1249840ed3da16f69319b2c3eecbc91f0fee1c83e9b017d5b16ccc

