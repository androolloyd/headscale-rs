# Go and Tailscale compatibility source

## Tag authorization behavior

The tag owner methods in `src/lib.rs` follow headscale-go v0.29.5
`hscontrol/policy/v2/policy.go` (`NodeCanHaveTag`, `UserCanHaveTag`,
`resolveTagOwners`) and `hscontrol/state/state.go` (reauth request tags), at
the repository parity baseline commit
`0f7d1e536bed9f01dd7161f7637af19bb0908335`.
The snapshotless method implements the direct user/group fallback. Nested
owners require `node_can_have_tag_with_nodes` and registered-node addresses;
tagged nodes are excluded from user owner sets. The API supplies native or
volatile node snapshots, and the parity adapter supplies its scenario nodes.
This behavior and the source-adjusted nested-owner assertion have not been
built, run or qualified for this implementation batch.
The original Headscale copyright/BSD terms are retained separately in
NOTICE-HEADSCALE-GO and LICENSE-HEADSCALE-GO and copied by both container recipes.

## Network text and string quoting

`src/go_netip.rs` adapts pinned Go 1.26.9 IPv4/IPv6 parsing, address/zone and
prefix grammar, error ordering, host-bit preservation and Prefix.Compare.
Request prefix parsing rejects empty text; stored Prefix text preserves Go's
empty zero representation. AddrPort handles brackets, unsigned decimal ports,
zones, mapped IPv6 display and empty text zero values. Canonical ordinary
IPv4/IPv6 rendering uses Rust address Display, with mapped IPv6 explicit.
Scalar Addr text retains an empty zero value; ParseAddr rejects empty input
and exposes the parsed family/zone for allocator seeding.

Native stored network columns, map endpoint strings, wire route normalization,
route approvals/debug echo and configured prefixes/trusted proxies share this
leaf. Primary-route vectors/debug text and auto-approvals use Prefix.Compare.
The wider route emission and Hostinfo/JSON boundaries remain unqualified.

`src/go_strconv.rs` and `src/go_strconv/unicode.rs` share UTF-8 Go Quote and
its pinned Unicode printability tables with CLI logging and network diagnostic
formatting. The source/table implementation was extracted from CLI logging;
no new dependency release or public wire field type was introduced. Raw
invalid UTF-8 coercion remains the responsibility of the byte-oriented decoder.

Go 1.26.9 source SHA-256:

- `src/net/netip/netip.go`: `dbebdcbfd55f9619d57f55910b2af6240adb84dcd58bc76b9b396e479b91815e`.
- `src/strconv/quote.go`: `6602960ec8777de9926c1d02fbf5cb0828d4aefa38083865f4af17b6892c09a2`.
- `src/strconv/isprint.go`: `24114557c2b3cad7b80c8e71683831bfbe1c72eb99e8fd28a3a48eaf77705fb4`.

The Go copyright and BSD license are retained in NOTICE-GO-STDLIB and
LICENSE-GO-STDLIB, package metadata records BSD-3-Clause and both container
recipes copy the notices. No external dependency version changed.

This is unbuilt source implementation. No parser/Unicode/zone/error corpus,
malformed-row/map/config request, resource, feature/license/container, CLI,
process or restart qualification covers it. The existing config error assertion
was source-adjusted only. No new executable evidence closes a parity gate.
## Public-key text

`src/go_key.rs` shares Tailscale v1.98.3 public-key text acceptance between
wire requests and native persistence. Prefixes are case-sensitive; 32-byte
hex payloads accept either case and marshal lowercase. Prefix, size and hex
errors retain the pinned order without echoing key material. SQL NULL zero
semantics remain in the database adapter. NLPublic accepts both nlpub and
tlpub input and emits nlpub; it reports the CLI prefix when appropriate.
No curve-point validation is added to Go's text format.

Tailscale v1.98.3 source SHA-256:

- `types/key/util.go`: `f635c220a4b75e16e01269994c92c8defc0ea1ad9b09ba71826b65ac86da80f9`.
- `types/key/nl.go`: `b893f4c53b5eb016d75972dc1254c559623f27eb4984071dc97c4fda7cd554c0`.

The original copyright and BSD terms are retained in NOTICE-TAILSCALE and
LICENSE-TAILSCALE, included by both runtime container recipes. This extraction,
NL alias support and the consuming SQLx adapters are unbuilt and unexecuted.


## Shared control JSON decoding

`src/go_json.rs` is the maintained Go 1.26.9 byte scanner extracted from the
DB adapter. Its public DB re-export preserves CLI/database call sites. The
iterative 10,000-container scan avoids serde's lower unknown-value depth limit;
unknown values are scanned and discarded. Existing scanner source hashes above
in headscale-db/UPSTREAM.md still identify the pin.

`src/go_tailcfg_json.rs` shares the pinned tailcfg Hostinfo schema and a bounded
Go struct decoder with native storage and wire requests. Nested object state
retains array backing slots across repeated Hostinfo objects, case aliases,
shorter duplicate arrays and scalar nulls. Slice null and [] reset that state.
Standard field errors are saved while decoding continues; custom key, opt.Bool,
time and network-text unmarshal errors stop immediately. Errors retain the root
Version reached by that decoder for the registration capability-error branch.
Diagnostic text is redacted and is not qualified as exact Go driver/JSON text.

Byte slices accept JSON uint8 arrays and StdEncoding base64 strings, including
CR/LF and non-zero unused bits; padding is required for incomplete quanta.
Arrays reuse prior byte slots, and successful values project to canonical base64.
The ACL package now directly uses the already locked base64 0.22.1 and
num-bigint 0.4.6 releases; only its lock dependency list was edited. No external
version/checksum changed or resolver/build/license gate ran.

Hardware attestation keys now share `go_key`: empty is zero, otherwise the exact
hwattestpub prefix and 130 hex characters are checked before uncompressed P-256
encoding, coordinate bounds and y² = x³ - 3x + b mod p. BigUint arithmetic is
bounded to public coordinates; constants are initialized once. No private-key,
signature or secret-bearing operation uses this arithmetic.

Additional source SHA-256:

- Tailscale v1.98.3 `types/key/hardware_attestation.go`: `94d2974b070c113fc31edbfd7cb64432c76ad6bf9982e97db2cbf18bfa2cfbd0`.
- Tailscale v1.98.3 `types/tkatype/tkatype.go`: `77e46f6b695a47e1b2178a43294131c1f2614325c55b87db5fea8a49d84aeb69`.
- Go 1.26.9 `crypto/ecdsa/ecdsa.go`: `61d06e6707ef461f7e77fcff654430dea46970edd446ac49dc3692dd5b43ac55`.
- Go 1.26.9 `crypto/elliptic/nistec.go`: `19452fe2c70d7b0136868829fc6466fe6ee8394c996d78bc1e7a4d27964a594b`.
- Go 1.26.9 `crypto/internal/fips140/nistec/p256.go`: `aefa1a76543721e8e4d0b38cb07dfc71bfda7b005500864c7a69457fe216d660`.
- Go 1.26.9 `crypto/internal/fips140/nistec/fiat/p256.go`: `b5e874ddd907466916c93ed1bca988d7264ee2cadcc4892bcf72c8d3ea50fa68`.

Go/Tailscale notices and BSD terms remain in this package and both runtime
container copy patterns. The extraction, field/error/array handling, byte codec,
public-point check and downstream feature surface are unbuilt/unexecuted. Wider
public wire integer widths, nil/explicit-unset representation, custom metadata
canonicalization, exact diagnostics, resource/concurrency and paired process/
restart behavior remain incomplete or unqualified. No parity gate is closed.

## SignatureType text

`go_tailcfg_json::signature_type_text` follows Tailscale v1.98.3
SignatureType.UnmarshalText followed by String on the pinned 64-bit Go host.
Named none/v1/v2 values are direct. Other input follows fmt.Sscanf with
signature-unknown(%d): a successful scan selects SignatureUnknown, while a
failed closing literal retains an already assigned signed value. Prefix,
missing-digit, overflow and newline scan failures leave the zero value.
The fmt whitespace table and decimal scan rules follow Go 1.26.9 fmt/scan.go,
SHA-256 `ac416ad4fba7f9901c737a203950d5d57220d1401e4bc7f0a2420389b88a86cd`.
This conversion is non-idempotent; the API applies it once during projection.
No tests/builds or byte/Unicode/overflow/process corpus qualify the adapter.

## Hostinfo typed JSON emission

marshal_hostinfo_value uses the pinned Hostinfo schema for Go JSON emission.
Ordinary scalar zero fields omit, non-nil nested pointers retain empty objects,
opt.Bool ExplicitlyUnset retains null, empty slices/maps omit, and Service Proto
and Port remain present at zero. The native DB writer shares this adapter.
The references are the same Tailscale v1.98.3 tailcfg.go/opt.Bool and Go 1.26.9
encoding/json sources above, with existing BSD notices retained. Public wire
field types are unchanged. This is unbuilt/unexecuted semantic JSON emission;
exact key order, float spelling, escaping, malformed/custom values and runtime/
SQLx/feature/license/container/resource equivalence remain unqualified.

## DNS labels and node FQDN bounds

src/go_dnsname.rs adapts Tailscale v1.98.3 util/dnsname.ValidLabel: byte-length,
start/end/interior checks and diagnostic order. Go string/rune quoting uses the
existing Go 1.26.9 strconv adapter; invalid interior bytes are rendered as Go
byte/rune values. The same module follows Headscale v0.29.5 Node.GetFQDN and
ValidateGivenName, including the final dot and the 255-byte full-name bound.
It validates UTF-8 Rust strings; raw invalid UTF-8 remains an outer boundary.
Native/wire rename, DB label validation and map FQDN checks share this leaf.

Source SHA-256:

- Tailscale util/dnsname/dnsname.go: c6d9c12cb8820bf756cb6425eee81a294efce9adace8b95fa4672e3ac73e7f0d.
- Headscale hscontrol/types/node.go: b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab.

Existing Tailscale/Headscale/Go BSD terms and notices are retained and copied by
both container recipes. No dependency version changed. Shared validation and
quote refactoring are unbuilt/unexecuted. Length, Unicode/byte/rune/escaping,
error ordering, configured-domain/feature/wire-only/package/container/resource
and process behavior remain unqualified. No parity gate is closed.

## Typed map Hostinfo comparisons

`go_tailcfg_json::map_hostinfo_equal` and `peer_hostinfo_equal` consume the
already decoded schema value. Missing scalars compare as their Go zero values;
missing pointers stay nil and opt.Bool's omitted zero and explicit unset differ.
Storage comparison preserves nil/empty slices and omits NetInfo DERP/latency.
Peer comparison ignores slice nilness and reads only the pinned peer field set.
These follow Headscale v0.29.5 state/maprequest.go hostinfoEqual/
peerHostinfoEqual and Tailscale v1.98.3 tailcfg/tailcfg.go Hostinfo.Equal/
NetInfo.BasicallyEqual at the existing pins. Source SHA-256 for maprequest.go is
77cd7b1a2e90a199bdab3ef7eecd96cc490dab0174ded3823348f1db5519c8d0;
tailcfg.go is 13bde37c19d7f841e494a49ee3bad60b92e242ba8361f3ed4965b801f757ebf2.
Both BSD notices/licenses remain packaged. Public wire projection/emission,
registration raw shapes and integer widths remain narrower. Direct rustfmt only;
no build, execution, feature/package/license/container or parity evidence ran.

## Unicode simple folding — 2026-10-18

src/go_unicode.rs adapts Go 1.26.9 unicode/letter.go SimpleFold with the
Unicode 15.0.0 CaseRanges, asciiFold and caseOrbit tables from unicode/tables.go.
It compares the simple-fold equivalence classes of valid UTF-8 strings without
multi-character full case folding or depending on the Rust toolchain's Unicode
version. SSH localpart email-domain matching and go_tailcfg_json field-name
equality call this helper. Raw invalid UTF-8 remains the decoder's boundary.

Go 1.26.9 SHA-256:

- src/unicode/letter.go: b35a6d259313cef88d07e9e4027b8bd72c60ae140418f5be2c41a2ecea6074fe.
- src/unicode/tables.go: 6a88d48746c4b2c471cc04ae40559694b734770212e6f5ea5f1962adb0c0bdb1.

Original Go Authors copyright/BSD notices remain in NOTICE-GO-STDLIB and
LICENSE-GO-STDLIB. No dependency version or public wire field changed. Direct
rustfmt only; no build, execution, Unicode boundary/resource qualification or
native/wire-only/package/container/client/process/restart evidence ran.

## Grant App null and raw shape — 2026-10-18

GrantRule's public CapabilityMap type remains a map of value vectors. Its serde
decoder now accepts a null App map and null capability value slices, projecting
them to the existing empty map/vector representation. go_policy_shape.rs keeps
raw map nilness and nil capability keys separately. It leaves opaque payload
values uninterpreted and follows the existing pinned Headscale v0.29.5
types.go Grant.App/validation and compiled.go compileOtherDests boundaries.
Empty App alone still fails ip-or-app validation. Case-folded App fields also
preserve their opaque metadata payloads in strip_metadata_members.

The API policy store uses this metadata for empty App versus nil admission and
null versus [] CapMap emission. Direct typed consumers/canonical_bytes/policy_hash
retain their public projection; that hash does not capture the private raw App
shape. No public wire/policy field type or dependency release changed. Existing
Headscale BSD notices/licenses cover this adaptation at the previously recorded
types.go/compiled.go hashes. Full nil/duplicate/backing-array and opaque raw-byte
decoding, feature/package/license/container and paired process/client/restart
qualification remain open. Direct rustfmt only; no tests/builds/validators/probes
or fresh advisory evidence ran.

## Strict policy JSON v2 — 2026-10-18

Headscale v0.29.5 types.go policyJSONOpts uses DefaultOptionsV2,
MatchCaseInsensitiveNames(true) and RejectUnknownMembers(true). The policy
entry therefore rejects duplicate names; JSON v1 repeated-field/reused-slot
semantics apply at separate wire/storage boundaries.

go_policy_json.rs now walks retained raw members iteratively before Serde maps
discard duplicates. It strips metadata using the pinned literal app exemption,
rejects duplicate retained names and known-field aliases (including nested App
payload duplicates), and reports JSON pointers with the pinned truncation
algorithm. It validates retained UTF-8 strings/surrogates separately from the
shared Go JSON v1 grammar scanner. Schema matching now ignores dashes/underscores
and follows the Unicode folds entering ASCII schema names; actual map keys
remain exact. This corrects the prior case-folded metadata exemption: only the
literal app stops metadata recursion, even though App aliases match the struct.
App raw shape and typed decoding now use the same preparation.

Supported null containers, group/tag-owner/approver member slices and null or
empty nodeAttrs entries now project to existing typed containers. Missing
nodeAttrs target defaults to empty. Raw packet-filter default detection preserves
nil ACL/grant slices versus explicit []. Custom scalar null rules remain
separate, including Protocol.UnmarshalJSON's rejection of null. Comment stripping
retains token separation/newlines, handles trailing commas before comments and
retains unterminated block comments as invalid syntax.

Additional pinned github.com/go-json-experiment/json
v0.0.0-20260601182631-00ed12fed2a6 SHA-256:

- fold.go: 14f299eb612fc4ed42d5c25601f4dd85dbcf0edbc3b1696e839fa6048a6ddf03.
- jsontext/errors.go: b4cdd1094446c2078c0f360e96c353b5d45f97ef03afdd3212621f9eac4c7ee5.
- arshal_methods.go: d8dbd07a61abf827febfee9b991b7a0f3096307f734fc0ae2fc65f9ad51386ba.
- arshal_default.go: 2a57a7251a74e31d44c40bd2ab752a89ce7a6195dcdc8f7085ec5d5ba595f728.
- internal/jsonwire/wire.go: 0ad06ea1461edd3a0672e209b007e68c8f76c1f53fe0a8f7d799f01dd25c79df.

NOTICE-GO-JSON-EXPERIMENT/LICENSE-GO-JSON-EXPERIMENT retain original Go Authors
BSD terms in ACL/API/CLI packages. Existing Headscale and Go standard-library
notices cover their respective metadata/scanner behavior. No dependency release
or public wire/policy field type changed. Direct rustfmt only; no build/test/
validator/probe/advisory refresh. Opaque raw payload byte/numeric/depth fidelity,
remaining scalar/custom null cases, full nil representation/hashing and error
precedence, resources and feature/package/container/client/process/restart
qualification remain incomplete or unqualified.

## Opaque App text and JSON output — 2026-10-18

GrantAppShape now retains raw App array values alongside nil capability keys.
Literal app payloads retain standardized source whitespace; variant-field
payloads use the prepared metadata-stripped input. The API's private opaque
filter representation consumes these strings while public PolicyDoc/Value and
wire field types remain unchanged. Input value comparison guards trusted manual
doc/raw mismatches. Typed input range/depth and full raw-policy hashing remain
separate incomplete boundaries.

src/go_json_output.rs follows Go 1.26.9 encoding/json/indent.go compact,
HTML escaping (including U+2028/U+2029) and two-space indentation. It emits
validated raw payloads without reparsing their numbers/strings/object order into
serde values. Map framing and raw debug dump writes use this shared helper.

Additional SHA-256:

- Go 1.26.9 src/encoding/json/indent.go: 9ef9eac29fc4cc9d94bf305976891eb5e78a2644acd4f07ed7a0c186991ac908.
- Tailscale v1.98.3 tailcfg/tailcfg.go: 13bde37c19d7f841e494a49ee3bad60b92e242ba8361f3ed4965b801f757ebf2.

Original Go Authors BSD terms remain in LICENSE-GO-STDLIB/NOTICE-GO-STDLIB;
Tailscale and Headscale notices cover their respective RawMessage/App boundaries.
No dependency release or public field type changed. Direct rustfmt only; no
build/test/validator/probe/advisory refresh. Go-range/depth input, full hash/
whitespace and debug readback, resources and native/wire-only/package/container/
client/process/restart qualification remain open.

## Native tag validation casing — 2026-10-18

src/go_unicode.rs now exposes strings.ToLower using the existing pinned
Unicode 15.0.0 CaseRanges, including alternating upper/lower ranges. Native
RPC tag format validation uses this simple mapping rather than the Rust
version's full/contextual case conversion. The letter.go/tables.go hashes in
the Unicode section above apply. Existing BSD notices/licenses remain. No
dependency update or public wire-field change. Source/direct rustfmt only;
no build/test/validator/probe, Unicode/resource or release qualification.

## time.quote — 2026-10-18

src/go_strconv.rs exposes Go time.quote separately from strconv.Quote for
CLI duration diagnostics. It emits byte escapes for non-ASCII/control input,
retains DEL, and escapes quote/backslash. Source: Go 1.26.9 src/time/format.go;
SHA-256 f288c56858ab25828551681778f006b591ed140fc12e60122b6a9a7e35b07eb7.
Existing Go Authors BSD terms are retained in LICENSE-GO-STDLIB. Source and
direct rustfmt only; no tests/builds/validators/probes ran.

## JSON scanner diagnostics — 2026-10-18

src/go_json/scanner.rs ports Go 1.26.9 encoding/json/scanner.go's iterative
grammar, 10,000-container depth bound, numeric/literal/string contexts, byte
quoting and EOF-space transition into go_json::check_valid. Existing span
helpers retain their generic error API; the discovery decoder uses the new
detailed entrypoint. Invalid UTF-8 in quoted bytes is accepted by the scanner
and belongs to subsequent Go unquoting. Source SHA-256:
2b16dd215274dfa8e0806b53cca144684d5b9c8a02319cf5ce10120c50e6eef2.

## Native policy tag-chain and schema error aggregation — 2026-10-18

HuJSON validation appends the first undefined tag-chain error after direct owner
reference errors, following pinned Policy.validate/flattenTagOwners. Iterative
heap traversal tracks the active path, drops cycle edges and keeps undefined
references fatal at parse time. Go's zero/single/multiple aggregation is rendered
at schema boundaries; ACL/SSH test-shape child groups remain opaque under their
test(s) failed wrapper. Selected empty-assertion/protocol messages use pinned
wording and Go Quote. The public TOML extension retains its prior diagnostic and
validation contract. No runtime publication/cache boundary changed.

Go iterates tag maps nondeterministically; Rust's BTree maps select a lexical
root. Competing invalid chains, broader validation order/wording, resource
behavior and exact public/native error envelopes remain unqualified.

Pinned source SHA-256:
- Headscale v0.29.5 hscontrol/policy/v2/policy.go:
  1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e
- hscontrol/policy/v2/types.go:
  57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4
- hscontrol/policy/v2/test.go:
  7d90bc875a3c8209ebaae369bf48bbbcd376647a1dd8eade551b53863d19619d
- tailscale.com v1.101.0-pre util/multierr/multierr.go:
  67413ab1031194eac91a5d7dd7ec28976d4989dc711b21b23015ca32c8ba898f
Existing Headscale/Tailscale BSD notices/licenses apply. Independent source
review/direct rustfmt only; no tests/builds/Cargo/validators/probes/recapture or
parity gate closure.
Copyright 2010 The Go Authors; original BSD terms are in LICENSE-GO-STDLIB.
Source/direct rustfmt only; no tests/builds/validators/probes or runtime,
resource, wire-only or release qualification. No dependency/version change.

## Full Hostinfo equality for map connection state — 2026-10-18

`go_tailcfg_json::node_hostinfo_equal` reuses the existing typed HOST_INFO
schema with full reflect-style Hostinfo equality for tailcfg.Node.Equal.
Incoming map-update and peer Hostinfo comparisons keep their separate field
selection. Pinned tailscale v1.101.0-pre tailcfg/tailcfg.go SHA-256:
83d0f9f69326e7da231eb6f5b2ea54257d87362e2718dad28f7e26d7c0167cf3.
Existing Tailscale BSD notices/license apply. Source-only implementation;
no tests/builds/validators or parity qualification were run.

## Native address host prefixes — 2026-10-18

`go_netip::addr_host_prefix_text` follows PrefixFrom(addr, addr.BitLen())
and Prefix.MarshalText: typed zero Addr becomes the zero prefix's empty text,
IPv6 zones are removed and the actual family determines /32 or /128, including
IPv4-mapped IPv6 /128. Existing Go 1.26.9 net/netip source pin/notices/license
apply. Source reads/edits and direct rustfmt only; no executable qualification.

## SSH acceptEnv source shape — 2026-10-18

`go_policy_shape::ssh_accept_env_nil` retains missing/null versus explicit []
from prepared policy source. It shares the existing HuJSON/JSON-v2 validation
and field folding pass. hscontrol/policy/v2/filter.go assigns AcceptEnv directly
to expanded tailcfg.SSHRule objects, while mapper/node_conn.go compares SSH
policies with reflect.DeepEqual. The pinned v0.29.5 source hashes are recorded
in headscale-api/UPSTREAM.md. Existing Headscale/Go BSD notices/licenses apply.
Source-only implementation; no tests/builds/lint/validators or qualification.

## Via route result ordering — 2026-10-18

Via route matching now walks expanded destinations before announced subnet
routes, appends approved exit matches for autogroup:internet and retains
Include/Exclude order/multiplicity instead of sorting/deduplicating the result.
State.RoutesForPeer owns subsequent membership checks; TailNode derives the
non-exit PrimaryRoutes list before separately sorting AllowedIPs. The pinned
v0.29.5 policy.go/compiled.go/types/node.go provenance is recorded in the API
UPSTREAM.md. Existing Headscale BSD notices/license apply. Full resolution and
UsePrimary order remain unqualified; no tests/builds/validators were run.

## Original ACL source rows — 2026-10-18

`go_policy_shape::original_acl_rules` shares the existing prepared-source,
metadata removal, Go-field normalization and typed document decoder. It
returns original ACLs only if source grants and the complete synthetic-plus-
original rule sequence match the supplied public document. Callers can keep
all explicit typed rules on mismatch rather than guess a synthetic prefix.
Existing parser/Headscale provenance and notices/licenses apply. Source-only
implementation; no tests/builds/validators or parity qualification were run.

## Packet-filter document projection — 2026-10-18

go_policy_shape::packet_filter_document derives a compilation-only copy using
the existing acl_rules_from_grants normalization and explicit source ACL rows.
It preserves the supplied public document and reports malformed network-grant
IP specifications before PolicyStore publishes a candidate. Native compilation
can share the parser's grant-prefix representation for typed input as well as
parsed policies. Existing parser and pinned Headscale grants-before-ACL source
provenance/notices/licenses apply. Source/direct rustfmt only; no executable
qualification or release gate closure.

## Original ACL validation shape — 2026-10-18

go_policy_shape::original_acl_shape retains the original ACL source/destination
alias sequence before destination splitting/reordering, alongside expanded
compilation rows. It uses the existing prepared JSON, metadata stripping and
Go field/null normalization, and binds the capture to a complete matching
source grant/rule projection. original_acl_rules remains available as a
wrapper returning the compilation rows. Public policy model fields remain
unchanged. Pinned policy.go validateUserReferences and existing parser source
provenance/notices/licenses apply. Source/direct rustfmt only; no executable
qualification, fixture recapture or release gate closure.

## Original ACL identity and Go zero fields — 2026-10-18

original_acl_details captures original ACL list/group/order and nil slice
shape, per-destination normalized ports, canonical protocol and original
Action independently of expanded rows and user-validation aliases. Existing
original_acl_shape/original_acl_rules signatures delegate to this capture.
Source grant/rule projection must match the supplied public model.

The Go HuJSON object normalizer materializes omitted ACL Action as effective
accept (aclToGrants ignores the zero Action) and missing Src/Dst as empty.
Null ACL entries become zero-field objects before projection. Generic/TOML
serde's required fields and explicit-action validation remain unchanged.
Private identity retains omitted Action's actual empty value and slice
nilness. Public AclDoc/AclRule field types remain unchanged.

Pinned Headscale v0.29.5 types.go ACL/aclToGrants/validate/unmarshalPolicy and
policy.go filterAndPolicy/updateLocked provenance is recorded in API
UPSTREAM.md. Selected github.com/go-json-experiment/json version
v0.0.0-20260601182631-00ed12fed2a6 arshal_default.go makeStructArshaler resets a
struct on JSON null under DefaultOptionsV2; SHA-256:
2a57a7251a74e31d44c40bd2ab752a89ce7a6195dcdc8f7085ec5d5ba595f728.
Existing Headscale/Go notices/licenses remain. Source/direct rustfmt only;
no tests/builds/validators or fixture recapture. Other policy identity and
explicit-null scalar cases, exact errors/resource/cache/rollback/concurrency
behavior and full package/client/process/import/restart qualification remain
open. No release gate closes.

## Raw scalar custom UnmarshalJSON behavior — 2026-10-18

go_policy_json now recognizes ACL/Test Protocol, ACL Action, SSH Action and
SSH CheckPeriod scalar contexts before serde. It follows the selected custom
UnmarshalJSON raw-token quote trimming instead of decoding escape spellings
into accepted names. Numeric protocol tokens canonicalize before validation;
null protocols fail. SSH Action uses the Go TrimSpace rune set. CheckPeriod
null bypasses its pointer custom method; other scalar tokens are parsed as raw
durations before per-rule action/duration validation, including numeric zero.
Protocol canonicalization uses the existing Go Unicode simple lowercase table
and signed 64-bit parsing/name mapping; errors use pinned Go wording/quoting.
Generic/TOML protocol normalization retains its trim. Public field types and
methods remain unchanged; opaque App and ordinary alias paths retain their
existing schema contexts.

Pinned Headscale v0.29.5 policy/v2/types.go Action.UnmarshalJSON,
Protocol.UnmarshalJSON/validate, SSHAction.UnmarshalJSON and
SSHCheckPeriod.UnmarshalJSON SHA-256:
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
The selected policy/v2/test.go PolicyTest.Proto is a nonpointer Protocol;
SHA-256 7d90bc875a3c8209ebaae369bf48bbbcd376647a1dd8eade551b53863d19619d. Existing Go
Unicode/strconv/time and Go JSON source pins/notices/licenses apply.

Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification. Duration diagnostic taxonomy, non-scalar error phases/envelopes,
ProtocolPort validation, all-policy identity, raw/model ambiguity and full
error/cache/rollback/resource/concurrency/shutdown/native/wire-only/package/
container/client/process/import/restart evidence remain unqualified. Existing
fixtures were not recaptured/run; no release gate closes.

## ProtocolPort literal protocols and canonical port ranges — 2026-10-18

go_policy_json now gives grant IP array elements a ProtocolPort context.
Its decoder unquotes JSON strings before literal protocol validation, without
ACL Protocol.UnmarshalJSON casing/number-name canonicalization, and rejects
non-string entries before projection even for via grants. Grant normalization
uses the same parser and does not apply ACL protocol/port compatibility.

The shared range parser follows utils.go parsePortRange/parsePort exactly in
its value grammar: no native entry trimming, empty-hyphen-part removal, source
order/multiplicity, positive singletons, valid zero range endpoints, complete
wildcard ranges and signed 64-bit parsing. Canonical patterns prevent accepted
range spellings from being dropped later. ACL destination normalization shares
this conversion; ACL compatibility checks numeric wildcard endpoints rather
than the original spelling. Explicit legacy port-pattern passthrough and
per-entry trimming retain their separate normalization branch. Public field
types and existing methods remain intact; grant_ip_patterns is additive.

Pinned Headscale v0.29.5 policy/v2/types.go ProtocolPort.UnmarshalJSON,
Protocol.validate, grant validation and ACL protocol/port compatibility:
SHA-256 57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
policy/v2/utils.go parsePortRange/parsePort:
SHA-256 264a06019ea2c9e2aa37ad2bad7040433e2c6baf32f7abaf18dcdff3b2b21b52.
Existing Headscale/Go JSON/strconv notices/licenses remain.

Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification. Numeric-to-any overflow and nested malformed value diagnostic
phases/envelopes, duration error taxonomy, complete policy identity, raw/model
ambiguity and full error/cache/rollback/resource/concurrency/shutdown/native/
wire-only/package/container/client/process/import/restart evidence remain
unqualified. Existing fixtures were not recaptured/run; no gate closes.

## Shared Go time.ParseDuration translation — 2026-10-18

go_duration::parse_nanos translates pinned Go time.ParseDuration, leadingInt,
leadingFraction and parseDurationError into a shared signed nanosecond parser.
It preserves byte cursor order, integer and fractional precision bounds,
float64 multiplication/division order, uint64 accumulation and wrap before the
magnitude check, signed final conversion, units and time.quote diagnostics.
Policy's always sentinel is handled by its separate check-period wrapper.
Raw custom CheckPeriod parsing and per-rule validation use the same Result
path rather than dropping specific diagnostics or using integer-decimal
fractions. Public policy fields/methods remain unchanged; the module is an
additive leaf utility without backend dependencies.

Pinned Go 1.26.9 time/format.go SHA-256:
f288c56858ab25828551681778f006b591ed140fc12e60122b6a9a7e35b07eb7.
Original Go notice is retained in the new module; BSD terms remain in
LICENSE-GO-STDLIB. The existing quote_time translation is reused.
Source/direct rustfmt only; no tests/builds/lint/validators/probes/advisory
qualification. Floating-point/platform/error/resource behavior, surrounding
JSON error envelopes and full cache/rollback/concurrency/shutdown/native/
wire-only/package/container/client/process/import/restart evidence remain
unqualified. Existing fixtures were not recaptured/run; no gate closes.

## AliasEnc contexts and group decode phases — 2026-10-18

go_policy_json maps ACL Sources, Grant Sources/Destinations, NodeAttrs Targets
and SSH Sources/Destinations to the AliasEnc string decoder plus Go TrimSpace.
Explicit null elements clear the intermediate plain string before later alias
validation. Group usernames, owners, auto-approvers and ACL AliasWithPorts
retain their separate decoding paths. The added go_unicode::trim_space helper
uses the selected IsSpace/White_Space set and also serves SSH Action trimming.
Generic/TOML serde behavior and public model fields remain unchanged.

Groups validation now follows name phase, value/member type phase, reverse-
sorted nested group phase and username validation phase. Errors use selected
Go constants/quoting and the dynamic JSON-any type names. Original ACL identity
now records explicit null Sources as non-nil [] because Aliases.UnmarshalJSON
always constructs make([]Alias, len(aliases)); omitted Sources remains nil.
Existing public methods remain; helper additions use no backend dependencies.

Pinned Headscale v0.29.5 policy/v2/types.go AliasEnc/unmarshalPointer/Aliases,
Groups.UnmarshalJSON and Group/Username validation SHA-256:
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
Pinned Go 1.26.9 unicode/graphic.go IsSpace SHA-256:
46a43107a87c88cf17a05a557e00dbf6b0f4bb53ebcd7d3035e02f1e67c428be.
The existing Unicode tables.go and go-json-experiment arshal_default.go pins
apply; makeStringArshaler clears a Go string on null under DefaultOptionsV2.
Original Go/Headscale notices and retained licenses remain.

Source/direct rustfmt only; no tests/builds/lint/validators/probes/advisory
qualification. Cross-map error winners, numeric-to-any/nested value error
phases/envelopes, typed-map keys, full policy identity, raw/model ambiguity and
complete cache/failure/resource/concurrency/shutdown/native/wire-only/package/
container/client/process/import/restart evidence remain unqualified. Existing
fixtures were not recaptured/run and no release gate closes.

## Hosts and typed TagOwners map-key decoding — 2026-10-18

The Go boundary no longer coerces null group values into empty lists; the
phased Groups decoder now sees and rejects their actual dynamic type.
TagOwners lists keep their distinct Owners slice decoder normalization.

Hosts normalization decodes the full map[string]string first, including null
string zeroing, then checks host names and Prefix.parseString behavior through
shared Go netip helpers. Bare/scoped addresses become host prefixes with zones
removed; slash prefixes retain host bits and canonical text. Selected hostname/
address diagnostic wording and quote helpers apply. Generic/TOML inputs keep
their existing path; no public model fields change.

The prepared TagOwners context now unmarshals each Tag key from its raw JSON
string token using literal quote trimming and Tag.Validate. Escaped names
retain the selected custom Tag value rather than a serde-unquoted value.
JSON-name duplicates are checked before custom decoding, with resulting typed
Tag map keys checked separately. Metadata is stripped first. Original Go/
Headscale notices and retained licenses remain.

Pinned Headscale v0.29.5 policy/v2/types.go Hosts.UnmarshalJSON, Tag.Validate/
UnmarshalJSON, Groups and TagOwners SHA-256:
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
Selected go-json-experiment arshal_default.go typed-map and plain-string null
paths retain their existing source pins. arshal_methods.go custom map-key
UnmarshalJSON SHA-256:
d8dbd07a61abf827febfee9b991b7a0f3096307f734fc0ae2fc65f9ad51386ba. Shared Go netip provenance remains unchanged.

Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification. Cross-map error winners, remaining typed map/owner/approver
paths, numeric/nested/custom error phases/envelopes, full policy identity,
raw/model ambiguity and complete cache/failure/resource/concurrency/shutdown/
native/wire-only/package/container/client/process/import/restart evidence
remain unqualified. Existing fixtures were not recaptured/run; no gate closes.

## Owner/auto-approver decoders and typed route map keys — 2026-10-18

The native prepared-policy walker now distinguishes Owners, AutoApprovers
and their element decoders. unmarshalPointer string unquoting/null zeroing is
shared with AliasEnc; only AliasEnc trims. Owner/approver kind admission
selects Username before Group and Tag. Invalid kinds are rejected during
preparation rather than solely by late generic reference validation.

AutoApproverPolicy.Routes keys use decoded Prefix text, including the empty
zero value, host-bit preservation and canonical address text. Raw JSON-name
and typed-key duplicate checks are separate. Generic route validation shares
the Go text grammar and leaves the zero key inert. Owner/approver reference
validation, leaf ownership/auto-approval and tag recursion preserve Username
precedence; no public model field or method signature changes.

Pinned Headscale v0.29.5 policy/v2/types.go unmarshalPointer, parseOwner,
parseAutoApprover, Owners/AutoApprovers and Policy.validate SHA-256:
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
Pinned Go 1.26.9 net/netip/netip.go Prefix.UnmarshalText/ParsePrefix SHA-256:
dbebdcbfd55f9619d57f55910b2af6240adb84dcd58bc76b9b396e479b91815e.
Selected go-json-experiment arshal_default.go typed-map duplicate checking:
2a57a7251a74e31d44c40bd2ab752a89ce7a6195dcdc8f7085ec5d5ba595f728.
Existing JSON method source pins/notices and retained licenses apply.

Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification, fixture recapture or release gate closure. Nested custom
error envelopes/order, other Alias/Prefix precedence, numeric overflow,
complete policy identity and all accumulated failure/cache/resource/
concurrency/shutdown/native/wire-only/package/container/client/process/
import/restart evidence remain incomplete or unqualified.

## General aliases, typed SSH alias domains and policy-test shape — 2026-10-18

Additive go_policy_shape AliasKind/alias_prefix/canonical_alias helpers follow
parseAlias/Prefix.parseString precedence and text. Native AliasEnc decoding
uses Go TrimSpace, then canonical typed prefix text; owner/approver decoding
retains its separate semantics. The native ACL destination projection also
canonicalizes Prefix text without trimming, preserving host bits and making
zero-ending IPv6 aliases unambiguous for public rule splitting. Bracketed
IPv6 validation uses shared Go netip, including valid zones.

Reference/autogroup/SSH combination checks, conditional ACL destination
ordering and leaf expansion/evaluation use parsed alias kinds. SSH list
element admission follows the source/destination type switch, and Host SSH
destinations are rejected during validation even when undefined. SSH test
source/default/null handling, destination alias classification and test
shape checks retain their distinct typed domains. AliasWithPorts additionally
validates the Tag/AutoGroup value. Policy-test shape checks use parsed port
bounds instead of syntactic hyphen/comma checks and consult the hosts table
only for Host aliases. Public field types/methods remain; no backend dependency
is added. Existing TOML representation remains available.

Pinned Headscale v0.29.5 policy/v2/types.go parseAlias, Prefix.parseString,
AliasWithPorts, SSHSrcAliases/SSHDstAliases and policy/test validation SHA-256:
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
policy/v2/test.go SSHPolicyTest/SSHTestDestinations and parseDestinationAlias:
7d90bc875a3c8209ebaae369bf48bbbcd376647a1dd8eade551b53863d19619d.
policy/v2/utils.go splitDestinationAndPort/parsePortRange:
264a06019ea2c9e2aa37ad2bad7040433e2c6baf32f7abaf18dcdff3b2b21b52.
Existing Go netip/Unicode pins, notices and retained licenses apply.

Source/direct rustfmt only; no tests/builds/lint/validators/probes/advisory
qualification or fixture recapture. Whole-field/custom error phases/envelopes,
manually quoted test destinations, remaining typed raw JSON fields, complete
policy identity and all accumulated cache/failure/resource/concurrency/shutdown/
native/wire-only/package/container/client/process/import/restart evidence
remain incomplete or unqualified. No release gate closes.

## Typed via tags, netip IP pools and scalar null values — 2026-10-18

The native prepared-policy walker now routes grants[].via through raw
Tag.UnmarshalJSON quote trimming/validation rather than ordinary unquoted
String decoding. NodeAttrs ipPool uses netip.Prefix's text decoder, including
null-to-zero, empty text, canonical address text and retained host bits. Zero
IP pools reach selected CGNAT validation as "invalid Prefix"; allocator support
is still rejected. Error prefix text/quoting follows the selected typed values.

SSHUser arrays (SSH users and SSH-test assertions) use Go string null zeroing
then Go TrimSpace. Plain nodeAttr capability/SSH acceptEnv/policy-test strings
use null zeroing without trimming. These contexts do not touch opaque app
payloads or group-map dynamic decoding. Generic trimming helpers use shared Go
Unicode whitespace. All native policy struct-array contexts now convert null
elements to zero structs before semantic validation; public fields/methods and
wire-only dependencies stay unchanged.

Pinned Headscale v0.29.5 policy/v2/types.go Tag, Grant.Via, NodeAttrGrant.IPPool,
SSHUser and SSH/nodeAttrs validation SHA-256:
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
Pinned Go 1.26.9 net/netip/netip.go Prefix.UnmarshalText/String SHA-256:
dbebdcbfd55f9619d57f55910b2af6240adb84dcd58bc76b9b396e479b91815e.
Selected go-json-experiment arshal_methods.go text null/value dispatch:
d8dbd07a61abf827febfee9b991b7a0f3096307f734fc0ae2fc65f9ad51386ba.
Existing arshal_default.go makeStringArshaler/makeStructArshaler and shared Go
Unicode source pins/notices/licenses remain applicable.

Source/direct rustfmt only; no tests/builds/lint/validators/probes/advisory
qualification or fixture recapture. Whole-field/custom error phases/envelopes,
numeric-to-any overflow, manually quoted test destinations, complete policy
identity and all accumulated failure/cache/rollback/resources/concurrency/
shutdown/native/wire-only/package/container/client/process/import/restart
qualification remain incomplete or unqualified. No release gate closes.

## Policy container shape and canonical duration identity — 2026-10-18

The additive PolicyContainerShape/policy_container_shape helper retains
selected Go map/slice nilness only when the complete native parsed source
matches the supplied public document, excluding the attached user directory.
It uses canonical field/map-entry paths and distinguishes ordinary map/slice
null handling from Groups/Hosts map allocation and custom alias/owner/approver
slice allocation. Groups' empty Usernames values remain nil because that
custom decoder appends to an initially nil slice. Grant capability slice
values, auto-approver map/list fields and all policy struct-list contexts are
included. Opaque payload bytes retain their existing metadata path.

Native SSHCheckPeriod numeric values now project canonical duration text;
literal always retains its separate Always bool identity. Existing numeric
zero rendering was already 0s; other numeric spellings now canonicalize too.
No public field type/method or backend dependency changes. This shape augments
existing typed/original ACL/app identity; it is not a Go deephash implementation.

Pinned Headscale v0.29.5 policy/v2/types.go Groups/Hosts/Owners/AutoApprovers/
Aliases/SSH alias decoders, policy fields and SSHCheckPeriod SHA-256:
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
policy/v2/policy.go filterAndPolicy/updateLocked SHA-256:
1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e.
Pinned Tailscale v1.101.0-pre util/deephash/deephash.go makeSliceHasher/
makeMapHasher nil-versus-empty and interface/pointer hashing SHA-256:
cc886c8db2085886058d59aa21532123ff45d8b3a12920c905d15ac1d9bbc2d2.
Existing Go JSON default struct/map/slice/null and time/format.go pins and
original notices/licenses apply. No Go hash implementation is copied.

Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification or fixture recapture. Full filter/typed-policy/deephash equality,
legacy raw/model ambiguity, error phases/envelopes and all cache/failure/
rollback/resources/concurrency/shutdown/native/wire-only/package/container/
client/process/import/restart qualification remain incomplete or unqualified.
No release gate closes.

## Policy-test second JSON boundary and shared destination parser — 2026-10-18

The additive TestDestination/parse_test_destination helper follows selected
parseDestinationAlias: surround the already decoded destination with literal
quote bytes, decode a JSON string again, then apply AliasWithPorts splitting,
port ranges, Alias.Validate and canonical typed alias text. Escapes therefore
undergo a second decode, while unescaped quotes/control bytes fail. Policy-
test shape validation uses this helper and keeps the original outer string
for the Prefix/raw-slash test; native ACL destinations keep their own decoder.
Public field types/methods and backend dependencies remain unchanged.

Pinned Headscale v0.29.5 policy/v2/test.go parseDestinationAlias SHA-256:
7d90bc875a3c8209ebaae369bf48bbbcd376647a1dd8eade551b53863d19619d.
policy/v2/types.go AliasWithPorts/validateTestDestination SHA-256:
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
Existing utils.go/Go JSON/netip/port source pins and notices/licenses apply.
Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification, fixture recapture or release gate closure. Exact JSON/custom
error envelopes, numeric-to-any overflow, complete typed/filter/deephash
identity and all failure/cache/resource/concurrency/shutdown/native/wire-only/
package/container/client/process/import/restart evidence remain unqualified.

## Recursive any-number decoding — 2026-10-18

The schema walker scopes recursive float64 decoding to Groups' map[string]any
and ProtocolPort's any payload. Out-of-range numbers fail before custom semantic
validation; underflow succeeds. Whole-subtree name/string checks precede deferred
numeric errors, and ProtocolPort containers reject only after that decode.
Typed fields and opaque app contexts keep their existing behavior. Diagnostics
retain number/type/pointer/range cause with the selected cannot wording; Go may
randomly choose unable to instead. Whole-policy serde_json::Value materialization
may still reject enormous numbers in app RawMessage payloads. Public APIs and
dependencies remain unchanged. No builds/tests/Cargo/validators/probes run.

Pinned Headscale v0.29.5 policy/v2/types.go SHA-256:
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
JSON experiment v0.0.0-20260601182631-00ed12fed2a6 SHA-256:
arshal_any.go 3e1f8ecf0166f1a7ebeb866a86f90186952d1d086f15d912430e0cc7a1b835af;
arshal_methods.go d8dbd07a61abf827febfee9b991b7a0f3096307f734fc0ae2fc65f9ad51386ba;
errors.go 457ff930caa50f15b0c60adfdec9764c54ab7c0d6c05e52ce1da7d9cf698344a;
jsontext/decode.go 504864242a3712977778ec3b5831ce8f7667000c13e75c35b63e82ee5a4b8637.
Go 1.26.9 src/internal/strconv/atof.go SHA-256:
2c2205ccab8626b623a188144a7dcaf202ece77002a27a2cd6b0aaf5a61669a5.
Existing notices/licenses apply. Source/direct rustfmt only; all general decoder,
error-envelope, typed-equality and native/wire-only/package/client/process
qualification remains unqualified; no release or security gate closes.

## Lossless numeric capability projection — 2026-10-18

Native policy and source-shape Value materialization now uses a token builder
that assembles arrays/maps iteratively and constructs Number separately from
object names. serde_json arbitrary_precision is enabled at the leaf, retaining
public CapabilityMap/Value types. Valid grants/nodeAttrs app maps are moved past
typed AclDoc deserialization and restored without a second ValueVisitor pass.
Literal $serde_json::private::Number keys remain ordinary app objects; huge
numbers survive public projection. Number spelling may normalize, so retained
raw shapes remain authoritative for exact wire payload encoding. Invalid app
map/list shapes still enter typed rejection. Public additive go_json.value is
also used by the API's opaque-payload comparison. Package version/lock unchanged.

Source audit used locally locked serde_json 1.0.149, crate checksum
83fc039473c5595ace860d8c4fafa220ff474b3fc6bfdb4293327f1a37e94d86:
src/de.rs SHA-256 2364aaa767bb40eeedd4aa24e3bf917be5e007a00bd3d911b61f9de74aa5f074;
src/number.rs 327e30a5542e169df2bbea59e4a7a4861c5a6994876f74cadab49f8133cbae34;
src/value/de.rs ceda1bf415aafde89caa83bf275811b70d393717d4e1038e0c61822d2da02993;
src/value/ser.rs 11f2b7daa1eba826d4086d5497f73729478dd7647bff77deccde5e47b0f126f2.
Pinned Headscale types.go/grant RawMessage and JSON experiment pins/notices above
apply to upstream policy semantics; no dependency/advisory freshness claim.

Source/direct rustfmt only; no tests/builds/Cargo/validators/probes. Features
unify for this serde_json version, so generic Value readers, direct Deserialize/
TOML users, numeric equality/canonical bytes and downstream consumers still need
qualification. Iterative construction does not make Value clone/equality/encode/
drop iterative. Deep/large payload resources, malformed diagnostics, native/
wire-only/feature/package/client/process/import/restart and prior qualification
remain incomplete or unqualified. All three release gates remain open.

## Parser cleanup and explicit strict-any mode — 2026-10-18

Parser-owned partial/completed/replaced Values drain iteratively using owning
array/map iterators, including late string/number/cursor errors and ordinary
last-member replacement. The Go grammar scanner supplies prepass diagnostics.
Returned Value operations remain recursive. The additive go_json.strict_any_value
uses the same assembly/cleanup but rejects decoded duplicate names recursively
and converts numbers through finite float64, accepting underflow. It is used for
generic JOSE extra headers; typed unknown subtrees must use their own decoder's
skip behavior. Existing go_json.value keeps exact-number/last-member semantics.

Pinned go-jose v4.1.4 json/decode.go default UnmarshalFloat/duplicate-key handling
SHA-256 2b8768b473ecf66b8e2319e912a9370d433ecc01c75c33aeaaf532d6912b1fc4.
Existing Go scanner, serde Number source pins and retained licenses apply.
Source/direct rustfmt only; no tests/builds/Cargo/lint/validators/probes. Allocator
failure/panic recovery, returned-value resource behavior, strict Unicode versus
legacy replacements, full diagnostics and accumulated native/wire-only/package/
client/process/import/restart qualification remain incomplete. No gate closes.

## Explicit legacy JSON string modes — 2026-10-18

Additive go_json.legacy_value and legacy_strict_any_value reuse iterative
assembly/cleanup with Go v1 unquote replacement of invalid UTF-8 and unpaired
UTF-16 in names/strings. Exact legacy mode preserves arbitrary Number projection
and last-member maps; strict-any legacy mode applies finite binary64 rounding
and recursive duplicate rejection after repaired-name comparison. Existing strict
value/strict_any_value used by policy-v2 retain their contracts. No dependency
or public model field changes.

Go 1.26.9 encoding/json/decode.go SHA-256:
a91535f18f9a2c8380448b1c84c4c2017dbe3d530a10faf8babf03494042da48.
Pinned go-jose v4.1.4 json/decode.go:
2b8768b473ecf66b8e2319e912a9370d433ecc01c75c33aeaaf532d6912b1fc4.
The fork's original BSD terms are retained in LICENSE-GO-JOSE-JSON with
NOTICE-GO-JOSE-JSON, alongside existing Go licenses/notices.
Source/direct rustfmt only; no tests/builds/Cargo/lint/validators/probes. Returned
Value resources, exact original numeric spelling, decoder diagnostics and all
native/wire-only/feature/package/client/process/import/restart qualification
remain unqualified. No release or security/advisory gate closes.


## First streaming raw JSON value — 2026-10-18

Additive go_json::first_raw_value adapts Go 1.26.9 encoding/json.Decoder.readValue
and the existing scanner for the grpc-gateway RawMessage boundary. It omits
leading whitespace, returns None for clean whitespace-only EOF, scans strict
syntax/depth without materializing values, and leaves trailing data for the next
Decode call. Truncated first values return unexpected EOF. The API gateway feeds
only this raw slice to protobuf decoding; its generated upstream handler drains
remaining bytes. Existing Go BSD license/notice and scanner source pins apply.
Source/direct rustfmt only; no tests/builds/Cargo/validators/probes or resource/
feature/process qualification. No parity gate closes.

Additional Go scanner source pins for the first-value adapter:
encoding/json/stream.go (readValue):
bb26b2442db6a686fc7f823ea9cc89babe26ac988ec7d8caf4a157aeb60d92f2;
encoding/json/scanner.go:
2b16dd215274dfa8e0806b53cca144684d5b9c8a02319cf5ce10120c50e6eef2.
# Native byte HuJSON — 2026-10-18

src/go_hujson.rs adapts the byte grammar, literal validity, comment UTF-8 and
standardization phases from github.com/tailscale/hujson
v0.0.0-20260302212456-ecc657c15afd, selected by Headscale v0.29.5. An explicit
task stack replaces the recursive upstream AST. Metadata-only reconstruction
preserves kept token spelling; # names use legacy JSON string decoding before
strict retained-field decoding. Additive parse_hujson_policy_bytes returns the
typed document and valid compilation source, never a substitute original source.

Pinned source SHA-256:
- parse.go: 4a907eda39d7b64f800ba3c61f76bd1d8b5961c15ac33e6f8df0e72544476f0e
- standard.go: 4eda30fd6c71ac233dd17b156d2dc4b90e7c7554b088aa556ad8bf833820937b
- types.go: c093574beaf5462fbe5fc74a898f6d709adcbd2f5575643fe1941c5ed052b7c8
- LICENSE: a125b6c2721809b6c2a8761771932611833008ed8697d752b3e35d36e4bbd83e

Original BSD conditions retained in LICENSE-HUJSON and NOTICE-HUJSON. Existing
package license expression and container LICENSE*/NOTICE* copies cover these
files. No dependency version changed. Exact JSONv2 UTF-8 offset/pointer and raw
malformed diagnostic-byte transport remain incomplete. Source/direct rustfmt
only; no execution, qualification or fresh security/advisory conclusion. Three
parity gates stay open.

# Custom policy receiver decoding order — 2026-10-18

Native byte parsing performs the complete JSONv2 syntax/string/duplicate-name
ReadValue pass before custom JSON receiver element semantics. An explicit stack
and saved parent Cursor avoid recursive AST allocation and preserve raw numeric
tokens. Ordinary policy/ACL/grant/SSH structs retain encounter-order unknown-name
handling. SSHsrc/dst list kind errors follow all AliasEnc parsing. SSHPolicyTest
first decodes all raw fields, then reports its Src alias semantic error.

Sources: Headscale v0.29.5 policy/v2/types.go Aliases, Owners, AutoApprovers,
SSHSrcAliases and SSHDstAliases; policy/v2/test.go SSHPolicyTest.UnmarshalJSON;
selected go-json-experiment/json arshal_methods.go Unmarshaler ReadValue wrapper.
Existing Headscale/Go JSON experiment BSD licenses/notices apply.

SHA-256:
- types.go: 57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4
- test.go: 7d90bc875a3c8209ebaae369bf48bbbcd376647a1dd8eade551b53863d19619d
- arshal_methods.go at v0.0.0-20260601182631-00ed12fed2a6:
  d8dbd07a61abf827febfee9b991b7a0f3096307f734fc0ae2fc65f9ad51386ba

Exact JSONv2 pointer/offset decoration and broader decoder type-wrapper text
remain unqualified. Source/direct rustfmt only; no tests/builds/Cargo/validators,
probes/recapture or runtime/feature/process qualification. Three gates stay open.

# Raw-container method dispatch — 2026-10-18

Native byte decoding dispatches all JSON kinds to raw-text Protocol, ACL Action,
SSH Action and SSHCheckPeriod methods after full ReadValue syntax validation.
This follows Headscale v0.29.5 types.go1685/1710/1849/2894; container method
rejection occurs before subsequent fields. ProtocolPort keeps any-value numeric
decoding, and public String parsing keeps its existing behavior. Existing pinned
types.go/arshal_methods.go hashes and Headscale/Go JSON experiment BSD notices
apply. Source/direct rustfmt only; no execution/runtime/feature qualification.
Exact diagnostic decoration remains unqualified; three parity gates stay open.

# Packed native metadata and strict string diagnostics — 2026-10-18

go_hujson::prepare_metadata validates HuJSON before metadata deletion, retains
original Name/Value extras and composite tails in an indexed flat arena, and
iteratively emits stripMetadataMembers/Standardize/Pack output. Non-nil empty
last-value extras preserve trailing-comma semantics, including a newly last
retained member after metadata removal. Exact app values skip metadata removal.
Native parser glue uses this packed buffer; obsolete compact reconstruction was
removed. Original bytes are separately retained by the policy store.

go_policy_json/string_syntax.rs follows strict JSONv2 ConsumeString and
SyntacticError for malformed UTF-8/surrogates: first offending byte/backslash,
up-to-twelve-byte surrogate fragment from remaining packed input, Go quoting,
parent pointer for invalid names and full pointer suffixes for value errors.
Custom ReadValue subcursors retain absolute packed-buffer offsets. Byte quoting
in go_strconv follows strconv.Quote's invalid-byte hexadecimal escapes. Existing
public String parser and semantic policy rules remain unchanged.

Additional pinned SHA-256:
- HuJSON v0.0.0-20260302212456-ecc657c15afd pack.go:
  0edaa18a5ff8f3f156533ddc62177fbc65574ed728ba3b5f12447b505d1a7f75
- go-json-experiment/json v0.0.0-20260601182631-00ed12fed2a6
  internal/jsonwire/decode.go:
  54b3cbdf6a557cfe056a2d5d469a7e8a1ce1f861f89d93d5d505678d9dff8f4c
- internal/jsonwire/wire.go:
  0ad06ea1461edd3a0672e209b007e68c8f76c1f53fe0a8f7d799f01dd25c79df
- jsontext/decode.go:
  504864242a3712977778ec3b5831ce8f7667000c13e75c35b63e82ee5a4b8637
- jsontext/errors.go:
  b4cdd1094446c2078c0f360e96c353b5d45f97ef03afdd3212621f9eac4c7ee5
- jsontext/state.go:
  66c40efe4bdb5f958ff8167a7e22b8a80151efce4ca3cc89f661f49f23d93632

Existing HuJSON parse/standard/types and Go strconv/printability hashes apply.
LICENSE-HUJSON/NOTICE-HUJSON and Go JSON experiment/stdlib BSD notices retained.
This supersedes the specific native Unicode position/compaction source gap;
broader semantic type wrappers/modal wording, malformed HuJSON diagnostic-byte
transport, memory/resources and runtime/feature/process parity stay unqualified.
Independent bounded source review/direct rustfmt only; no tests/builds/Cargo,
validators/probes/recapture or gate closure. Three parity gates remain open.

# Native Tag semantic-error remapping — 2026-10-18

Native Tag errors after full ReadValue now follow unmarshalPolicy's selected
SemanticError remap order: case-sensitive actual JSONPointer contains '/via/'
first, then first-letter Tag failure becomes tagOwners[last-token]. Syntax
errors bypass remapping; String parser and whole-via-container handling retain
their existing behavior. Source: pinned Headscale v0.29.5 types.go3275–3293,
existing types.go SHA-25657006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4
and Headscale BSD license/notice apply. Bounded peer source review/direct
rustfmt only; no tests/builds/Cargo/validators/probes/recapture or broader
semantic-wrapper qualification. Three parity gates stay open.

# Native JSONv2 depth encounter order — 2026-10-18

Native preparation skips the old whole-buffer v1 depth check after HuJSON has
validated grammar. Typed container entry and strict custom ReadValue enforce
10,000 containers with outer depth and packed-source positions/pointers.
Private unbounded raw-span extraction is iterative; nonnative value scanning
retains its existing depth limit. This preserves earlier typed unknown-field
and custom string errors ahead of a later excessive-depth value.

Selected go-json-experiment/json v0.0.0-20260601182631-00ed12fed2a6
jsontext/state.go maxNestingDepth/pushObject/pushArray, jsontext/decode.go
consumeObject/consumeArray and jsontext/errors.go provide the source behavior.
Their SHA-256 and BSD license/notice are recorded above. General semantic
container errors, temporary raw-span stack growth, returned deep values and
runtime/resource equality remain unqualified. Independent source review/direct
rustfmt only; no tests/builds/Cargo/validators/probes/recapture or gate closure.

# Native typed JSON kind ordering — 2026-10-18

Native policy preprocessing now records ordinary struct/map/slice/boolean
shapes and rejects a wrong kind after its opening ReadToken, before visiting
rejected container children or later fields. The opening-token depth gate and
string-token syntax check still precede kind rejection. Custom JSON receiver
prepasses remain complete ReadValue passes. Default strings and Prefix text
decoding now also validate the full ReadValue before type rejection, correcting
the earlier token-only assumption for those decoders.

Native shape mappings include hosts' internal map[string]string, ACL destination
lists and custom any-decoded elements, capability map/raw-message lists,
randomizeClientPort, NodeCapability strings and SSHUsers versus []SSHUser.
Arbitrary capability payloads remain raw JSON. Kind errors use the innermost Go
type, packed source position and pointer-or-offset envelope; syntax errors keep
their separate envelope. Native tag/via remapping applies after semantic
failure. Existing nonnative parsing and public APIs are retained.

Selected go-json-experiment/json v0.0.0-20260601182631-00ed12fed2a6
source SHA-256:
- arshal_default.go:
  2a57a7251a74e31d44c40bd2ab752a89ce7a6195dcdc8f7085ec5d5ba595f728
- arshal_methods.go:
  d8dbd07a61abf827febfee9b991b7a0f3096307f734fc0ae2fc65f9ad51386ba
- errors.go (SemanticError, distinct from jsontext/errors.go above):
  457ff930caa50f15b0c60adfdec9764c54ab7c0d6c05e52ce1da7d9cf698344a

Existing Headscale types.go pin and Go JSON experiment BSD license apply;
2023 source attribution and NOTICE are retained. This implementation chooses
the "cannot" spelling; Go randomizes "cannot"/"unable to" once per process.
Broader custom semantic phase/order behavior (including Hosts prefix parsing),
general wrapped causes, allocation/deep-value resources and actual diagnostics
remain unqualified. Source review/direct rustfmt only; no execution or release
gate closure. Three gates remain open.

# Native Hosts/Groups receiver completion — 2026-10-18

Native frames retain the original packed Hosts/Groups receiver span. After the
complete strict syntax pass, inner typed-map/any decoding and number errors,
receiver close invokes the existing shared semantic helpers before the next
policy field. Groups retains all-key name checks, array/string-member checks,
reverse-sorted nested-group rejection and Username validation. Hosts retains
full map[string]string decoding (null values clear to empty), then per-entry
Host validation and Prefix parsing. Whole null receivers complete successfully.

Semantic failures carry outer JSON kind, v2.Hosts/v2.Groups, original receiver
offset/pointer and the shared cause. Raw span extraction builds only a shallow
semantic projection of strings and runtime-type placeholders, so rejected
nested group values do not become recursively owned Value trees. Original
source and prepared output are retained; public/nonnative paths are unchanged.

Pinned Headscale v0.29.5 types.go Groups.UnmarshalJSON (1381–1465),
Hosts.UnmarshalJSON (1471–1500) and unmarshalPolicy (3267–3300), SHA-256
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
The selected JSON experiment arshal_methods.go (291–302) and errors.go pins
above cover method error wrapping and position/rendering. Existing Headscale
and Go JSON experiment BSD licenses/notices apply.

Go's unordered map loops can select another offender when multiple entries
fail; only the explicit reverse-sorted recursion phase has fixed ordering.
The renderer retains the deterministic "cannot" modal. Receiver rescanning,
temporary allocations, broader custom methods, cancellation and actual error/
runtime/process/feature parity remain unqualified. Independent source review/
direct rustfmt only; no tests/builds/Cargo/validators/probes/recapture or release
gate closure. Three parity gates remain open.

# Native custom semantic-error context — 2026-10-18

Native scalar/custom receiver and typed map-key failures now wrap the selected
Go type, JSON kind, packed source offset/pointer and cause. Deferred SSH list
kind failures wrap v2.SSHSrcAliases/v2.SSHDstAliases at the array; deferred test
source parse failures wrap v2.SSHPolicyTest at its object. Inner string and
float64 errors retain their inner type/location under SemanticError collapse.
Headscale's case-sensitive via and first-letter-tag rewrites run before the
envelope. Numeric range errors also apply the actual-pointer via remap while
retaining their delayed decode phase. Native duplicates receive the parse
prefix once and remain syntactic errors outside those semantic rewrites.

Pinned sources: selected JSON experiment arshal_methods.go text249–277 and
JSON291–305; errors.go newUnmarshalErrorAfter160, collapse300 and rendering331+;
arshal_default.go inner string269 and pointer1745+; Headscale types.go custom
methods/unmarshalPolicy and test.go SSHPolicyTest. Their hashes and BSD licenses
are recorded above. No new dependency or public/nonnative API change.

Independent source reviews/direct rustfmt only; no tests/builds/Cargo/validators,
probes or recapture. Go's randomized modal spelling, unordered-map multi-error
selection, broader runtime/resource and paired process qualification remain
unproven. All three parity gates remain open.

