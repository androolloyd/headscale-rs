# Local exact-version source adaptation

Upstream: `aws-lc-rs 1.18.2`, VCS commit
`9df497501436596d4da77109217806b3af7f56cb`.
The source was copied from the already-selected registry package. Root
Cargo.toml excludes this directory from workspace membership and patches
crates.io to it. Cargo.lock retains the selected version and dependency list;
only this package's registry source/checksum were removed. No dependency
resolution, version update, Cargo command or executable qualification ran.
Downstream embedders using the Rustls adaptation need equivalent patches.

## Optional native TLS signing adapters

Default-off `go-native-tls12-ecdsa` adds the hidden additive method
`EcdsaKeyPair::go_tls12_sign_asn1`. It accepts only SHA-256, SHA-384 or SHA-512
and delegates message hashing/signing to the existing validated key and EVP
signing implementation, returning ASN.1 signatures. This permits the selected
native Rustls TLS 1.2 server to use the peer's selected hash independently of
the EC curve. Existing constructors, `sign`, `sign_digest`, signatures and
default behavior are unchanged. No cryptographic primitive, raw-digest
shortcut, unsafe block or new sys dependency was added.

Rustls's default-off `go-server-client-hello` weakly forwards this feature only
when the AWS backend is selected. Its explicit native server mode selects
the new method only for TLS 1.2 ECDSA; ordinary Rustls and TLS 1.3 signing retain
their existing methods. Ring and custom providers retain their own supported
algorithms. API full enables the Rustls feature; the wire-only API boundary
does not introduce a crypto/database/core backedge through this adaptation.

The same optional feature also exposes hidden additive
`RsaKeyPair::go_public_modulus_bits`, delegating to the existing validated
EVP_PKEY bit-count wrapper. The native Rustls RSA signer uses its floor-byte
value only after an actual TLS1.3 PSS signing failure, matching Go's special
HandshakeFailure classification; ordinary modulus/signature length remains
unchanged. This adds no unsafe code or sys/dependency edge.

Original source SHA-256:

- src/ec/key_pair.rs: df9bf4959faab94350384af43df3f62accb4ea7179c99f47013612d20260c4c9

- src/rsa/key.rs: 10570549ffe69dcc9924b1a3335fda0b93da00d2da0b74b654c0ce687895f8c9

Selected Go 1.26.9 source SHA-256:

- crypto/tls/auth.go: 7bdcfa1d4d1b53fb8e1306bcf8712037ac870cc793685d243cab508ebe654bef
- crypto/tls/key_agreement.go: 3874cd45e07283547ae3ab6ba4a10893323210ba153906fe586ce0158ba45862

## Licensing and qualification

Original LICENSE is preserved. LICENSE-GO and NOTICE-GO retain Go attribution
and BSD terms for the behavioral adaptation; both package manifests append
BSD-3-Clause to the original license expression. Both native Docker recipes
copy LICENSE* and NOTICE*. Those recipes have not been built.

Independent source review and direct rustfmt only. No build, test, feature,
FIPS, backend, signing/verification, handshake, package or container execution
has qualified this change. This is not a fresh dependency/advisory/security or
FIPS certification claim. All three replacement-parity gates remain open.

## Local implementation source SHA-256 — 2026-10-18

- src/ec/key_pair.rs: 58cc0980d2400baafceca00654e4c278283cbcd35a5e85d0a9ac4558bf8fd03c
- src/rsa/key.rs: 71b316c1fcc325cca9cfd454dfc3ccab00238314da7acee8b322b8ef494588ec
- Cargo.toml: 56263795822a724a6700ab0b281f882717321c358bc17bb538cde3490913bf17
- Cargo.toml.orig: 959ea18459f45b36eb32d417b8e3baba23e041ce2165f9afc6ac33821e525fb1
