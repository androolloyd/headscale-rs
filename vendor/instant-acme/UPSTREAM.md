# Local exact-version source adaptation

This checkout uses the already-selected crates.io package, with no version or
resolution update. Root Cargo.toml patches the package and excludes its copied
checkout from workspace membership; Cargo.lock keeps the selected version and
existing versions while removing its registry source/checksum. The native proxy
adapter additionally uses the already-locked tower-service 0.3.3 package; no
package version or resolution update was performed.
Downstream embedders need equivalent patch configuration to use these additive
APIs. Cargo package/container/feature behavior has not been executed.

Upstream `instant-acme 0.8.5`, VCS commit `c8c16a2110d01bee3586c2639da00dcd96e70dcd2`.

## Native client scope

The default-off `go-native-client` feature adds explicitly named Account/Order
APIs; only the native CLI dependency enables/calls them. Existing SDK APIs and
Client.post remain unchanged when this feature is built or disabled.

Native POST status classification follows selected Go retryable HTTP codes
(<=399, >=500 and 429), badNonce cache invalidation and header-aware bounded
exponential backoff/jitter. Signing/transport failures remain outside HTTP
retry. Raw first Retry-After bytes survive body/JSON decode failures; signed
64-bit seconds use wrapping duration multiplication. Polling zero/invalid
means one second; negative delays are immediately due. Polling decodes the
first JSON value, separates outer HTTP/transport failures from inner body/JSON
errors and leaves same-URL retry decisions to native CLI loops.

Direct authorization URLs avoid an extra Account.order request. Native pending
cleanup fetches each URL and deactivates only Pending. Finalization exposes its
actual order status and polling follows it before certificate retrieval.
Native account discovery/registration and nonce HEAD/pool now have explicit
Go-phase implementations described below. The selected native HTTP redirect
path now has its own implementation; TLS, lower connection reuse and other
transport behavior remain separately qualified. Native JSON uses the private Go
scanner/typed assignment helpers; exact typed diagnostic wording and resources
remain unqualified. These helpers do not claim complete Go ACME equivalence.

Independent source reviews and direct rustfmt only; no build/test/feature,
CA/client/process/package/container execution or release gate closure.

## Bounded remote reads

Go's x/crypto/acme reads directory, order/authorization and error bodies
without a bound (`io.ReadAll`, `json.NewDecoder`); only the certificate chain
has one. This copy bounds every response read from the remote server
(`src/limits.rs`): `MAX_RESPONSE_BODY` (8 MiB) for the SDK whole-body reads and
the native first-JSON-value, error-prefix and whole-body reads, applied to the
DECODED bytes of a gzip body and enforced while streaming; the certificate
download keeps Go's exact bound. `go_http_get` takes the bound from its caller
(headscale uses 10 MiB for `derp.urls`). `Display` of `NativeResponseError` and
`Problem` renders at most `ERROR_DISPLAY_LIMIT` (2 KiB) of server text; the
fields keep the whole (bounded) response. Exceeding a bound is an error
(`http: response body too large (limit N bytes)`) except for error-status
bodies, which keep their first `MAX_RESPONSE_BODY` bytes. These are deliberate
differences from Go, added for the tailworm.com F-READ finding.

## Selected Go source SHA-256

Golang.org/x/crypto v0.53.0:

- acme/http.go: 1f3f948126b5cc90c113bea6affcfce15c3c265d29b8c26cd7954f137e6dcb5e
- acme/acme.go: 12fb0fd00c443f796879f033f920ea0b739d3822697d3c1108f46991a713a9cd
- acme/rfc8555.go: e898ab7e77ae19c5b28ec5abff60b876a07791cf6a87e1bd93263cf660e7727e
- acme/autocert/autocert.go: 175d3d5b0dd6278291bb924b55f1c9e6647b24f8e595394e2848dc6f50e07aea

## Original package source SHA-256

- src/lib.rs: e344a537df48b372eae21c804c3200fcfd5b8670baf91c370d88fc3d74369410
- src/account.rs: d53f4b10b21f20ff07c938096713e1635005a6d433da66beff1b77a0b7cf991c
- src/order.rs: d23e49a02af011717147b54e4f04d694ed1a71010939a5c41267f2debff77800

## Licensing

Original upstream license files remain intact. Adapted Go source retains
Go Authors attribution and BSD terms in LICENSE-GO and LICENSE-GO-NOTICE.
Both package manifests include the additional BSD-3-Clause requirement; both
native container recipes copy this package's LICENSE* files.

## Native certificate download limits and finalization URL

Native finalization takes the polling URI from its own response Location,
including an absent header becoming empty, as selected Go responseOrder does.
The selected Hyper streaming body retains/reads at most MAX+1 bytes, where
MAX = 5*(1<<20) + [5*(1<<20)]/33. It stops before later stream errors once the
limit prefix is read, rejects oversized bodies and more than five PEM blocks,
requires exact CERTIFICATE block labels and a nonempty chain, and ignores the
final undecodable suffix. It does not add X.509 validation at this layer.
Private Go PEM decoding and canonical ASCII encoding preserve the public String
return while tolerating an ignored non-UTF8 suffix. Cap/stream errors avoid the
SDK Str variant's extra missing-data prefix; invalid-type labels now use the
selected Go byte-quoting helper. Other diagnostics remain a boundary.

The feature-gated BytesBody limited-read method has a default implementation
for compatibility. Custom external bodies may still collect before truncation;
the selected streaming BodyWrapper and Bytes implementations bound the prefix.
Native selected streaming JSON and raw resource status handling are described
below. Typed diagnostic text, provider/transport representations and runtime
equivalence remain unqualified.

Additional original source SHA-256:
- Go1.26.9 encoding/pem/pem.go: 536954f803f79d8972e8f86b792b25d4ac83167fbe4c3117954a4378e60521da

Source reviews/direct rustfmt only; no execution or acceptance gate closure.

## Native resource metadata and streaming JSON

NativeNewOrder retains raw status, Location and all authorization URLs before
SDK enum interpretation. The CLI registers cleanup before rejecting an unknown
new-order status. Initial authorization and pending cleanup use raw statuses;
unknown challenge strings do not prevent a non-pending skip or pending cleanup.
Raw authorization polling also avoids SDK identifier-enum projection failures.

Selected streaming bodies incrementally scan the complete first-value grammar
once, returning root composites at the closer and scalar roots after lookahead
or EOF. Later suffix body errors/hangs do not delay a completed composite. HTTP
error response bodies still follow the separate full-read path. Compatibility
fallback methods for custom external bodies can collect before framing/limits.
Native decode uses the private selected Go syntax scanner with the 10000
nesting gate, followed by finite ordered raw-field assignment without Serde
Value/Content or typed deserialization. Default SDK deserializers retain their
existing behavior. The native feature adds no Serde feature forwarding or
package/version/resolution change. Native order raw resource/problem metadata retains arbitrary status strings,
authorization/finalize/certificate URLs, Location, identifier type/value and
signed64 status through private sidecars/additive getters. Unknown finalize
status successfully decodes and continues polling the finalize response URI;
unknown poll status retries the same URL, and raw Valid/latest certificate URL
controls download. The typed SDK state retains its last representable view.
Best-effort projection does not invent enum values or block operational state.

Native field matching, duplicates, legacy Unicode and saved-error assignment
now have source implementations described below. Exact diagnostics and all
unexecuted runtime/resource behavior remain unqualified; this is not complete
encoding/json equivalence.

## Native Retry-After HTTP dates

Private http_date.rs follows the ordered Go TimeFormat/RFC850/ANSIC layouts,
fixed69 year pivot, token-only weekday checks, exact literal/space phases,
fractional seconds and pre-epoch civil dates. RFC850 named-zone lookup uses a
private once-initialized Unix Local snapshot: TZ bytes, selected system paths,
TZif v1/2/3 transitions/first-zone rules, abbreviation lookup and POSIX tails.
Explicit nonempty GOROOT selects its archive; otherwise the copied selected Go
archive represents default build-root fallback. No new timezone dependency was
added. LICENSE-TZDATA-NOTICE retains the Go README's IANA public-domain statement.

The Go binary may initialize Local/GOROOT earlier than this helper; environment
mutation and file changes before first named-zone parsing remain initialization
qualification. Non-Unix paths use a fallback projection and are not claimed as
Go Windows/Plan9 behavior. System files can differ by host; malformed I/O/ZIP,
allocation and exact initialization/resource effects have not been executed.

Original Go1.26.9 source SHA-256:
- encoding/json/scanner.go: 2b16dd215274dfa8e0806b53cca144684d5b9c8a02319cf5ce10120c50e6eef2
- encoding/json/stream.go: bb26b2442db6a686fc7f823ea9cc89babe26ac988ec7d8caf4a157aeb60d92f2
- strconv/quote.go: 6602960ec8777de9926c1d02fbf5cb0828d4aefa38083865f4af17b6892c09a2
- strconv/isprint.go: 24114557c2b3cad7b80c8e71683831bfbe1c72eb99e8fd28a3a48eaf77705fb4
- net/http/header.go: b4fa959c3db03d4ca67a487b3cbb25dcefecea45ca3dd10fef13cfc32fa6d80d
- time/format.go: f288c56858ab25828551681778f006b591ed140fc12e60122b6a9a7e35b07eb7
- time/zoneinfo.go: 03bc9ba0ed7f4657121992620a83621f2ac7c5a6eb8b559d46600829e618211c
- time/zoneinfo_unix.go: d2001a2351a080f1a47ebb3999be74f99caceb4a8f1ea6369a3c843fa0442f08
- time/zoneinfo_read.go: 47e6cc315fbf5ba3eea95043fe7ec5e982d14b98574e60da22ac9b4f774f254b
- time/zoneinfo_goroot.go: 984267b22b58101becfd3612f836c3e32a6f4190e149e257315a4179ec279992
- lib/time/zoneinfo.zip: 8f55634d05f8bca1f7bc7c69c5933428c69357e0bdf565e5ba224e3f88ff12e8 (408125 bytes)

Independent source reviews/direct rustfmt only; no builds/tests, CA/client,
feature/package/container/process or acceptance gate qualification.

## Native account keys, nonce phases and Go assignment — 2026-10-18

The explicit native builder accepts an opaque NativeAccountKey. Canonical
PKCS#1 RSA, SEC1 EC and PKCS#8 EC/RSA account keys use the selected provider;
EC supports P-256/P-384/P-521 on AWS, with ring-only P-521 explicitly unsupported.
New account keys use P-256 and SEC1 cache PEM. Canonical JWK order/thumbprints,
fixed-width ECDSA JWS signatures and RSA RS256 are private native behavior.
The public SDK Key constructors/shape remain unchanged. Native JWS applies
Go HTML and U+2028/U+2029 escaping before base64/signing; default JoseJson uses
its original implementation.

Native directory GET, registration status/TOS/contact, account lookup/KID cache,
raw-byte nonce set (max100), serialized nonce HEAD and badNonce invalidation
follow selected x/crypto/acme phases. Nonce HEAD accepts a nonempty nonce
regardless of status. Account-ID lookup errors are suppressed, retried before
each HTTP retry, and fall back to JWK signing. Explicit-key lookup avoids
recursive account-ID lookup. Native response nonces enter the pool before body
decoding. Arbitrary nonce bytes retain identity until Go-style JSON replacement.
SDK clients without native state retain their original nonce and POST paths.

Successful discovery is published once behind a native async serialization lock.
Manager-style account construction accepts an assigned ACME409 from discovery
without caching an empty directory. The next native operation retries discovery
before capturing endpoint URLs or preparing account-ID signing; recovery does
not repeat registration/TOS. Failed discovery/decoding never publishes a cache.
Nonce endpoints are resolved before the nonce mutex to avoid lock inversion.

Native HTTP failures retain HTTP status/headers, exact original body bytes,
partially assigned problem fields and signed64 status in NativeResponseError.
Selected streaming partial ReadAll retains bytes before a read error. A saved
JSON syntax/type failure replaces Detail with the original body while retaining
assigned problem type/status for classification. Custom external BytesBody
fallbacks cannot reconstruct prefixes discarded by their own whole-body API.

Private legacy_json/scanner.rs supplies selected Go first-value syntax/EOF
phases. resource_decode.rs assigns all pinned order/auth/challenge fields using
ordered duplicates, folded names, legacy malformed-UTF8/surrogate replacement,
null value/pointer distinctions, saved scalar errors and slice backing reuse.
Nested problem assignment shares response_error.rs. json_time.rs validates
raw quoted RFC3339 bytes without JSON-unescaping and preserves time.Time's
immediate custom-decoder error priority. It retains strings as DTO views.
Directory/account finite wire decoders use the same raw field helpers.

Remaining qualifications include runtime diagnostic equivalence and typed
Offset/downcast metadata, raw HTTP Location/header/URI representations, transport/redirect/
TLS/cancellation taxonomy, provider RSA/key-range acceptance and parse-error taxonomy, non-selected
backends, custom bodies, allocation/scheduling and all runtime equivalence.
Independent source reviews and direct rustfmt only; no tests/builds, CA/client,
feature/package/container/process execution or acceptance gate closure.

Additional selected source SHA-256:
- Go1.26.9 encoding/json/decode.go: a91535f18f9a2c8380448b1c84c4c2017dbe3d530a10faf8babf03494042da48
- Go1.26.9 encoding/json/fold.go: 5b3c91bfbf6943e04d9aeb934031331a3f08a83b10079a0a7f0def3466b2f39e
- x/crypto0.53.0 acme/types.go: 97f9ad0f5049091d129a8da24510606ddcaea8da6ff371e41f6ed9731f285f49
- x/crypto0.53.0 acme/jws.go: 107829803eb9cdcd0469421d58464c6fbe7528f7066ef8870291d2b5007d0467


## Native diagnostic and EC key follow-up — 2026-10-18

Finite success-resource UnmarshalTypeError rendering now retains the nearest Go
struct name separately from the complete canonical field path, preserves root
value-of-type wording, omits slice indices and includes numeric literals only
for integer-conversion failures. Existing assignment/null/slice behavior remains
unchanged. Nested wireError assignment shares the existing decoder; a finite
known-field diagnostic walk reconstructs its first type-error context.
Time parsing now consumes the entire six-byte numeric-zone token and follows
Go's minute/hour/lexical error precedence and held remainder. Actual call sites
add the responseOrder, GetAuthorization/Accept and responseAccount wrappers;
WaitAuthorization retains raw decode errors for same-URL retry. Exact typed
Offset/downcast metadata is not exposed as Go concrete error types.

Private account_key/ec_der.rs now checks the selected SEC1/EC PKCS#8 schemas
before canonical key reconstruction. It validates DER tag/length/integer/OID/
BIT STRING fields, requires SEC1 version1, handles optional explicit fields,
PKCS#8 outer-curve override/fallback and Go's ignored trailing-field semantics.
It mirrors the selected explicit-wrapper parsing phase rather than imposing a
new wrapper-length boundary. EC scalars tolerate extra zero padding and short
encodings, then normalize to curve width before provider key validation/public
point derivation. A structurally valid embedded public point is ignored as in
Go. No unchecked scalar is admitted and no cryptographic primitive was added.
RSA still uses the original provider parser; nonselected backends/key ranges,
RSA DER/CRT acceptance, error taxonomy and all actual key/signature execution
remain qualification boundaries.

Source peers and direct rustfmt only; no tests/builds, malformed-input or
sign/verify execution, CA/client/process/feature/package/container qualification.
All three release gates remain open. Additional selected Go1.26.9 pins:
- encoding/asn1/asn1.go: 325e3acb01e6ca0083bfe78cdd720aeca0d766c8561c4125e8e1711358d25740
- crypto/x509/sec1.go: 624dbfcfa0eb07b5860bfdff475fbc38a65dea2df8da3f0ba259aaf1a4c37dd4
- crypto/x509/pkcs8.go: 6b62c951d4fc9ce980f3f47f58c5408c265d56e82f5ded3fa9e61911baf64b20
- time/time.go: e8b6ea9e6e7cb890aeed1d24ee7163a2237b6fa78ffc564efb8688dba717f02a
- time/format_rfc3339.go: 14b2a58fa295cca1a4f99467f5a5059418ed266a2298316124af97ffa014f271

Directory/account finite diagnostics now share the resource type-error formatter.
Anonymous root type names retain Go declaration order and quoted JSON tags;
field errors retain canonical tags, .Meta paths and untagged .Status/.Contact/
.Orders names. This removes the earlier generic/doubled account error text.
The source peer review covered shared saved-first error ordering; Go concrete
error/downcast metadata and runtime equivalence remain unqualified.

- Go1.26.9 cmd/compile/internal/types/fmt.go: b33c77a55f1ad00801149a117c549ad15a1fcabc60661a5d20db7b1c1ccc1a2d


## Native HTTP redirects and URL preparation — 2026-10-18

The additive HttpClient::go_request hook defaults to an external client's
existing request policy. The selected built-in DefaultClient overrides it for
explicit native requests, with a separate HTTP/HTTPS Hyper pool. Its original
SDK pool still enforces HTTPS. Both derive the same selected connector/TLS/ALPN
configuration; enabling native code alone does not route ordinary SDK methods
through the redirect implementation. No dependency version or edge changed.

Native requests retain their original Go URL in request extensions before the
backend URI projection removes credentials/fragments. JWS protected URLs remain
the original strings. Private transport/url.rs adapts selected net/url parsing,
raw percent-escape/path/query/fragment state, reference resolution and dot-path
processing. Credentials remain bytes for Basic authentication; request errors
use password redaction. Parsed metadata has no Debug implementation. Known
unsupported-scheme/no-host errors retain the original method/URL context.
Initial backend preflight occurs before invoking a custom client's go_request;
external custom-protocol/hooks and exact transport phase taxonomy remain outside
the selected built-in policy qualification.

Native no-Jar redirects follow 301/302/303 method/body changes, sticky body-drop,
307/308 replay of the original in-memory body without re-signing, missing-Location
returns, ten-request limit, original-header snapshots, sticky sensitive-header
stripping, relative custom Host handling and Go Referer construction. URL-derived
Basic auth is injected after the original snapshot and only when Authorization
is empty. Explicit Referer copying and generated secure-to-insecure omission
follow their separate Go phases. Only the final response reaches the ACME nonce
pool/classifier. Intermediate response-body draining follows the selected slurp
threshold, with Hyper frame granularity and lower connection reuse/read effects
remaining a concrete qualification boundary.

The URL helper uses the existing maintained Go Unicode15 Lookup port copied
from headscale-api/src/tailscale_wire/tls/acme_hostname into private url/idna
modules. Only license-comment paths changed. Static mapping/trie/NFC/bidi/
Punycode data and algorithms retain the same pinned Go source; no newer ICU
fallback or API/core/database dependency backedge was introduced. Go's ASCII
fast path and IDNA-error hostname fallback remain separate from successful
Lookup output. The source conversion script was not rerun.

Automatic gzip negotiation/stream decoding and environment HTTP/HTTPS/SOCKS proxy
selection now have native source implementations, as recorded below. Remaining
source and qualification boundaries include
non-UTF8 Location/host projection, selected Rust IPv6/backend URI/DNS/zone and
TLS diagnostics, IDNA partial output/error representations, optional Go URL
GODEBUG overrides, custom clients/body streams, cancellation, pooling, resource
and HTTP-version/wire framing behavior. These remain source or qualification
work; this is not complete Go HTTP transport equivalence.

Independent source reviews/direct rustfmt only; no tests/builds, network/CA/client,
feature/package/container/process or security/advisory qualification. Three
replacement gates remain open. Selected Go1.26.9 original source SHA-256:
- net/http/client.go: 908d9d964cd157899b60e7ba839befa4bfd398b4fb8f7ff5a1aa389eae75f652
- net/http/request.go: 4a34a9e157a606a046d5b9f8f761c571c4762668fa351d92048515a595939c38
- net/http/transport.go: 643bce4b4fb016ed57c18e9d087e6c298faf3263d83728107c6b5cdaa398fe87
- net/url/url.go: 7bec001746c2cd512275c7269bc293f3d36cb004ddb193d736e02e361a3778aa

- net/url/gen_encoding_table.go: cd0f5020e4a5aa9741411afb4ab1bf73b9e9f40cd950e2bb9b369a773fdd9033

Selected IDNA source pins retained from the shared API port:
Source SHA-256:
- x/net0.56 idna/idna.go:
  c5aeb4b73731634a6f88502afd61d6fc30c391ab3cdfc170596375f039f6b06c
- x/net0.56 idna/tables15.0.0.go:
  79fb7af83a29255478a5e56fdc8d176276ccdb4d1ff1b1459646cbf8d52cc5f3
- x/net0.56 idna/punycode.go:
  3e65858245f1a7d32e225aba714a305d3ef34496acb839956a7b15d1c7a34eb7
- x/text0.38 unicode/norm/tables15.0.0.go:
  49dda94f9429bac8c29efe11e09558d46abfaa3c8e1de59816f2910b99cade04
- x/text0.38 unicode/norm/forminfo.go:
  fceb28bef5efec8347536a89018e906f607a70a91051d9360b3656867efe2d9e
- x/text0.38 unicode/norm/composition.go:
  3d1be52960f2693926472819b747646e7d2371d2bb5f53097cf9d46c913052df
- x/text0.38 unicode/norm/normalize.go:
  b9e7aeff51e6cb036ff4e8c6255410e7068c112e329a137d333e639f63c4a8ab
- x/text0.38 unicode/bidi/tables15.0.0.go:
  98c2d6d57e116667e73a4f5c89ee20ead7b27b50d561b5c5d23d8ebf0e3f3310
- x/text0.38 secure/bidirule/bidirule.go:
  714b5baaa1ec84a50e03504a7100d54d37e6ea7551d57d28265576c57de94ba9

## Native gzip and environment proxy transport — 2026-10-18

The selected native client adds automatic gzip request negotiation and a private
incremental gzip/raw-DEFLATE reader. Stored/fixed/dynamic blocks, 32 KiB history,
header options/CRC, trailer checksum/size, concatenated members and deferred
read errors follow the selected Go source phases. Fixed Huffman tables initialize
once. Native JSON reads follow the caller's logical decoder capacity, initially
512 bytes, so a completed value need not await a later gzip trailer/member.
Certificate limits and redirect slurping use decoded caller-sized reads and
retain data returned with an error. Backend frame buffering remains separate.
The selected connection now applies the HTTP/1 versus HTTP/2 gzip guards
after checkout/ALPN through the exact-version Hyper-util adaptation below.

Native proxy selection snapshots HTTP_PROXY/HTTPS_PROXY/NO_PROXY with uppercase
precedence, CGI rejection and Go Unicode simple lowercase/space rules. Domain,
port, IP, loopback and CIDR bypass rules include mask-before-family normalization
for mapped IPv6 networks; ::/0 does not bypass IPv4. HTTP forward proxies,
HTTPS proxies, CONNECT, proxy Basic authentication and SOCKS5/5h remote DNS and
authentication have source implementations. CONNECT retains selected ALPN,
finite response validation, 60-second deadline and header bound. The lower native
dialer bounds DNS plus TCP at 30 seconds and configures selected keepalive values.
An additive exact-version hyper-rustls connector hook retains TLS policy while
mapping the lower connector, with a separate 10-second TLS handshake timeout.
The native pool sets two idle connections per host and a 90-second idle timeout
with an explicit timer. Native global 100-entry idle eviction and cross-origin
HTTP proxy pool identity now have source implementations, recorded below.

Both SDK manifests add only the exact already-locked tower-service 0.3.3 edge and
existing Tokio net/io-util features. The default-off native feature forwards the
new default-off hyper-rustls feature; ordinary SDK calls retain their HTTPS-only
pool and no native timeout setting. No dependency versions were changed or
resolved. Private Go code retains LICENSE-GO and LICENSE-GO-NOTICE; the connector
keeps its upstream license files, copied by both native container recipes.

Remaining boundaries include physical HTTP/CONNECT parser/I/O error phases,
non-Unix environment projection, Rust backend header/URI/IP/DNS/zone and OS
errors, optional Go GODEBUG overrides, shared-environment snapshot timing,
compressed/input frame buffering, pool keys/eviction, cancellation/scheduling,
platform socket behavior and resource/performance equivalence. Independent
source reviews and direct rustfmt only; no builds/tests, feature/package/container,
CA/client/process, security/advisory or replacement-gate qualification.

Selected Go1.26.9 original source SHA-256:
- compress/gzip/gunzip.go: 5886344b7fd61358d430872ab735653b16a314c87dab1f0bde4d8d9db0381ec4
- compress/flate/inflate.go: 28b241ba6b66cc14ac93cc17a49756cd78daaade60afb47d7cd6aed2489dc5cb
- compress/flate/dict_decoder.go: 26ce1ac6f0a735d8e7fffab3f1052d2e2c6929e9fe740ce7c514a7f46552b28a
- net/http/transport.go: 643bce4b4fb016ed57c18e9d087e6c298faf3263d83728107c6b5cdaa398fe87
- vendor/golang.org/x/net/http/httpproxy/proxy.go: e1cde07b566be558b32a4a54cd1e8d9c36ce7d0579706c9495537154f8c1041e
- net/http/socks_bundle.go: ec71ed06e8a41851c7ae52a59373586960e519d69e416abad890d1ff8a5b9b99
- net/http/response.go: 43833d3f5b76380a6ba2ac6972d024f9efc599fbd17ceebda34e3e79b03483ec
- net/http/transfer.go: 3e04744176d3cf5bef2827ab158b10aaeec3981ac5f4e7fb86e3dbf5f592eed7
- net/ip.go: 7e26071410dd7265f58c27e9a13820b9e42b13187529db3f4a43eb48f94d1436
- net/dial.go: 9963e94645bb8620e61bf219236a5d859b17de161344d433b93bedd6f3ad1e1e
- unicode/letter.go: b35a6d259313cef88d07e9e4027b8bd72c60ae140418f5be2c41a2ecea6074fe
- unicode/tables.go: 6a88d48746c4b2c471cc04ae40559694b734770212e6f5ea5f1962adb0c0bdb1

## Native byte URL, CONNECT and connection policy follow-up — 2026-10-18

Unix HTTP/HTTPS proxy environment values now retain raw bytes through URL.Parse
and fallback-prefix parsing. NO_PROXY first trims Go Unicode whitespace without
altering invalid bytes, then applies strings.ToLower's one-invalid-byte-per-
RuneError mapping. Whole domain tokens go directly through IDNA, avoiding a
second URL parse that could split slash/query delimiters.

Private URLs now parse raw bytes and retain opaque/query bytes separately from
escaped path/fragment hints. Redirect Location parsing, Referer and password
redaction preserve bytes; invalid raw UTF-8 paths/fragments use the canonical
escaped representation. Host validation precedes userinfo checks, and username
escape errors precede password errors. The selected URI/TLS/DNS backend still
has its own representation/error boundaries; this does not claim Go network
handling of arbitrary invalid host bytes.

CONNECT parsing now retains Go-quoted status/header/TE/CL/trailer diagnostic
values, accepts noncanonical space-containing header keys without recognizing
them as transfer metadata, unfolds continuations before key/value validation,
and preserves missing-colon and finite status-validation order. Physical buffer
fragment/partial-I/O error timing, non-UTF8 rejection-reason display, optional
GODEBUG overrides and lower Hyper error envelopes remain unqualified.

Independent source reviews and direct rustfmt only. No builds/tests, feature,
CA/client/process, package/container, security/advisory or parity gate closure.

Additional selected Go1.26.9 source SHA-256:
- strings/strings.go: ba9478be775d11b6956c828ebf870a8f8e7b7318ee382834f1e741f02d1336ef
- unicode/utf8/utf8.go: 3c145ee25fd7631ebbc670fd1236e8c163ca30ae8913c796489efbf3f267ad54
- net/textproto/reader.go: fe649123b4df42a4aeb7713aa3f8028de61897072874f37c67c497bd6bbf734f
- bufio/bufio.go: 0393162eb1732d74ec5efe88760df58186f6847c525e577b297e8649c679580b
- net/http/internal/httpcommon/httpcommon.go: 20aedc8a3cde20f3cab6f392d33f9eb4e2fb9f663c7298fcbf0f9462c721c26a

## Connection-selected gzip and native pooling — 2026-10-18

Exact selected Hyper-util0.1.19 is locally adapted with a default-off native
feature. A per-request marker defers automatic gzip negotiation until connection
checkout knows HTTP/1 versus HTTP/2. HTTP/1 uses the first header value's emptiness
and appends the extra gzip field after caller fields; HTTP/2 requires absent
Accept-Encoding and Range values. Original Accept-Encoding values survive an
internal canceled-request retry, including a change of protocol. A response
marker records actual injection and controls native transparent decoding.
The SDK no longer predicts the protocol before sending.

Native pool identity now follows equality of the selected Go connectMethodKey:
full proxy URL bytes, target scheme, canonical target address and onlyH1=false.
HTTP forward proxies omit the target address; CONNECT/SOCKS retain it. The
length-prefixed opaque key preserves equality without delimiter ambiguity and
keeps the dial destination separate. Debug output redacts identity bytes, which
can contain proxy credentials. An explicit native builder setting selects global
100-entry insertion-LRU idle eviction; default clients remain unlimited globally.
The public pool Config struct retains its original fields. Shared HTTP/2 entries
keep insertion rank. The stream-aware native client-idle follow-up supersedes
shared HTTP/2 checkout timestamp/periodic-expiry behavior. Default native clients
now share their pool within the production runtime, with separate pools across
concurrent runtimes instead of Go's shared process-wide DefaultTransport. Physical HTTP/2 socket lifetime, backend sharing,
cancellation and scheduling remain incomplete or unqualified.

Both SDK manifests forward only the existing optional Hyper-util dependency's
new native feature. Root patch/exclude and lock source conversion preserve exact
versions/dependencies. Hyper-util's original MIT license and added Go BSD notices
are included in both container license-copy recipes. No resolution/build/package
or container execution was performed. Source peers/direct rustfmt only; all three
replacement gates remain open and this batch remains unvalidated.

## Native default-pool and plain GODEBUG follow-up — 2026-10-18

Default native accounts now select a registry-shared client on the first poll of
go_request, after a Tokio runtime exists. Accounts in the production runtime
share idle limits/connections; explicit roots and custom HTTP clients retain
isolation. The SDK HTTPS-only pool retains its per-builder behavior. Runtime IDs
partition the registry so live, undriven current-thread runtimes cannot hand each
other sockets. A generation-checked guard is captured before its cleanup task is
spawned and removes the entry on runtime shutdown, including tasks never polled.
No runtime Handle is retained and no lock spans an await/spawn/client drop.
Cross-runtime sharing remains different from Go process-wide DefaultTransport.

Private dynamic GODEBUG lookup retains Unix bytes, scans last matching key first,
uses the first equals sign within a token and preserves empty overrides. Selected
Go bisect syntax distinguishes invalid patterns (shortened value still applies)
and proven hash-independent constant matchers from unsupported stack-dependent
matchers. Native urlstrictcolons=0 and httplaxcontentlength=1 now follow the
selected URL/CONNECT phases for plain or supported constant values. Valid stack-
dependent settings retain Go1.26 strict defaults without inventing Go stack IDs.
Linked DefaultGODEBUG, stack reporting/counters and non-Unix raw environment
semantics remain outside this implementation. These limitations remain source
gaps, not evidence of complete GODEBUG equivalence.

Independent source reviews/direct rustfmt only. No builds/tests, feature/default/
backend/wire-only/package/container/client/process or parity-gate qualification.
Additional selected Go1.26.9 source SHA-256:
- internal/godebug/godebug.go: cd492e76ae63872ac4310fc09b2e097229588dbf114d14d713be3f027b0233c8
- internal/bisect/bisect.go: 978d518986ba6867f5f96356531f35bfa59b865fbb363b98eb9052e862a2160c
- internal/godebugs/table.go: c8d5b6e7358fd39befe8df0cb31bb859804ced8182b85f0b01355e3a845f7fa9
- net/http/h2_bundle.go: a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e

## Explicit native client idle selection — 2026-10-18

The native client factory explicitly selects go_native_idle_timeout(90s), which
configures exact pool-managed HTTP/1 deadlines and separate HTTP/2 connection-
owned idle state. Queued reservations protect checked-out connections; admission
and expiry linearize under the same stream mutex. Pending-open streams count as
active. The last stream retires only after its dirty terminal output reaches a
successful native flush checkpoint. Clean, fully written GET completion does not
wait for unrelated output. Native idle closure sends no GOAWAY. Wall-clock reuse
expiry starts with no timestamp, records final completion and rechecks after a
reservation before clearing last-idle state. Early request failures rearm idle;
wall-expired rejection keeps its old timestamp and unsent request ownership.

Independent source reviews repaired timer rearming after failed admission,
shared-closed readiness, terminal output timing, client-only Duration imports and
an extra default flush lock. The new default-off h2/Hyper features forward only
existing dependency/time features. Default SDK/Tonic/server policies remain
unselected, and public configuration literals remain compatible.

Remaining source gaps include conservative flush checkpoints after internal codec
writes, independent client reader/writer backpressure, complete H2 saturation/
pending-reset connection selection, stale closed senders until checkout/eviction,
Go's separate H2 ownership and cross-runtime process-wide transport sharing.
Root/client/profile/backend/OS timing, cancellation, resource/performance and all
accumulated executable/package/container/process/security qualification remain
open. This batch remains implemented_unvalidated and all three gates stay open.

## Native HTTP/2 authority identity and reset entropy — 2026-10-18

Native requests now supply separate authorityAddr metadata for the H2 connection
cache on every request and redirect. This follows net.SplitHostPort fallback,
HTTP/HTTPS default ports and bracket reconstruction before backend normalization.
Its zero-option IDNA Punycode profile is distinct from the Lookup profile used for
dialing: it preserves case, performs no NFC/STD3/DNS-length mapping, retains the
whole original host on conversion failure and preserves Go's per-invalid-byte
RuneError conversion. The selected toolchain-vendored idna10.0.0.go unconditionally
rejects a nonempty all-ASCII decoded ACE label; the newer external module's
conditional Unicode-version rule is not used for this stdlib call path. The
Lookup decoder retains its prior strict behavior, while the minimal decoder
preserves Go surrogate-to-RuneError acceptance before re-encoding.

The SDK explicitly supplies reset-PING bytes using its already initialized TLS
provider's secure_random implementation, forwarding through Hyper-util/Hyper/h2.
No package versions, resolution or public SDK signatures changed. Source review
and direct rustfmt only; this does not qualify native H2 wire, timing or runtime
parity. The vendor transport provenance describes the cache/control changes and
remaining per-request flight, cross-runtime and backend/error boundaries.

## Native H2 authority helper original source SHA-256 — 2026-10-18

- Go1.26.9 net/ipsock.go: 1d5cc127665695ab1351a96b015ceeddcc5adcbed91f35af0a6c6cd1552d846b
- Go1.26.9 vendor/golang.org/x/net/idna/idna10.0.0.go: f2232848beb271df6b3d05f6df16e10cb8c9f94ecff709a5e32dd1f2bf1e64cf
- Go1.26.9 vendor/golang.org/x/net/idna/punycode.go: 4e7adef5c3c4ff789ad439094738b5829896814e3fcd8a9a2c2c2ba40fa12a28

## Native caller-sized body consumption and deferred close — 2026-10-18

Native Raw/gzip consumers now call Incoming.go_poll_read with selected Go logical
read demand: encoding/json Decoder refill, Go1.26.9 io.ReadAll intermediate chunk
sizes for unbounded/limited certificate reads, and io.CopyN demand for redirect
slurp. The private gzip/read_size.rs retains selected noscan byte-allocation size
rounding; the actual Rust allocation strategy remains separate. Gzip input demand
models the Go bufio4096 fill and direct large extra/stored-block reads when empty.
The finite inflater algorithm is unchanged apart from a private demand accessor.

Additive default BytesBody.discard_bytes_limited/close_native methods preserve
existing implementors; native implementations await ignored deferred close on
consuming reads and explicitly close nonce-only/status-only responses. Native body
kind is checked before creating gzip or removing Content-Encoding/Content-Length,
so HEAD/NoBody/MissingBody retain Go's early-return behavior. Redirect draining
closes both known-long skipped bodies and consumed small/unknown bodies.

Go source: io/io.go ReadAll/CopyN, encoding/json/stream.go, bufio/bufio.go,
compress/gzip/gunzip.go, runtime/msize.go, internal/runtime/gc/sizeclasses.go and
net/http/h2_bundle.go response-body kinds/read/close. Go BSD attribution remains
in LICENSE-GO/NOTICE alongside original SDK terms. Existing package/container
LICENSE* inclusion covers the new helper. No version/resolution update.

Source reviews/direct rustfmt only. HTTP/1 lower transport framing/draining,
allocator/resource/scheduling behavior, custom BytesBody default fallback phases,
malformed/body/decoder/transport/TLS-close representations and all accumulated
native/default/feature/backend/wire-only/package/container/CA/client/process/
database/security qualification remain incomplete or unqualified.

## Caller-sized body source SHA-256 — 2026-10-18

Selected Go1.26.9 toolchain sources:

- io/io.go: 3945d328a9072e4f5970b7d4bc0eb834eec29fd22889a1ed9f3fb76ad41c3274
- bufio/bufio.go: 0393162eb1732d74ec5efe88760df58186f6847c525e577b297e8649c679580b
- runtime/msize.go: 0164d15295726608812842b429e241f553a314985a7c6aa48cb1ad24346a52dd
- internal/runtime/gc/sizeclasses.go: 7626b00bbb416c25c5279b29aa73a072d74ace3444e58b178a6ff855a2deec2c
- compress/gzip/gunzip.go: 5886344b7fd61358d430872ab735653b16a314c87dab1f0bde4d8d9db0381ec4
- encoding/json/stream.go: bb26b2442db6a686fc7f823ea9cc89babe26ac988ec7d8caf4a157aeb60d92f2
- net/http/h2_bundle.go: a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e

## Admission and body follow-up original source SHA-256 — 2026-10-18

- src/lib.rs: e344a537df48b372eae21c804c3200fcfd5b8670baf91c370d88fc3d74369410

## Native client TLS EOF integration — 2026-10-18

The explicitly native default client selects the new HyperRustls record-boundary
EOF policy on its origin connector and HTTPS proxy connector. The ordinary SDK
HTTPS-only connector is cloned before native selection and retains its original
policy. Existing handshake deadlines still begin after lower connection setup.

Rustls/HyperRustls UPSTREAM.md record source pins, processed-record boundary
classification, nested TLS EOF normalization, handshake error mapping and source
reviews, including exact observed close_notify mapping during handshake. Backend/custom error identity,
full TLS parser/alert diagnostics and runtime/feature/client qualification remain
open. No package version, resolution or public field/signature change; retained
Go attribution and container LICENSE* inclusion cover this adaptation.
Source review/direct rustfmt only; no builds/tests/probes or executable evidence.

## Local implementation source SHA-256 — 2026-10-18

- Cargo.toml: 183b4b7bdf0428002173a9759d167a8c5fa4b45b368e3577251e6f7926461f5d
- Cargo.toml.orig: 01d88fd2c91f25a0adc3b50c893e0959bea9d936b117a6b1e2b9426eee6d679c
- src/account.rs: ec6bc21ce9aa5acadcbfc97592bc3795e589f5842e4cf2d339a2da86c9cd4f5e
- src/go_native.rs: 3bab12ca5e4df68014ecb02e615d116d8c9a0edfb369cbcc1a676f05401cff0c
- src/go_native/account_client.rs: 70d84e750d02d55a67fd7d3ade36ab230e77f7694f41ed8b2def06e6ea43525c
- src/go_native/account_key.rs: c0af67835737d39170124fdaa5757870e3e7fe607555f3dbb5b26624dc9afd2b
- src/go_native/account_key/ec_der.rs: ba4a855c22283ec20d9179b510f3497081fe0127c5bd3dc159ec4e13cdcf08c2
- src/go_native/godebug.rs: b383fcadfba4047f6c370273ffe92fafaae76e524b88b16009ba3b7cc24d5f5b
- src/go_native/http_date.rs: f38602cf8433120a65ed1658ad72f6624d50a05e7d583e4b707ca26b3acdb741
- src/go_native/http_date/local.rs: ccd2f6c57fc5f29e910e718d2c06fba80a505d2870956b997ec2f1dd6e981752
- src/go_native/http_date/local/tzset.rs: beccb293e85c810e373318bfe71e638ce3c574905eea5ffc852d85d831a94ed1
- src/go_native/http_date/zoneinfo.zip: 8f55634d05f8bca1f7bc7c69c5933428c69357e0bdf565e5ba224e3f88ff12e8
- src/go_native/json_prefix.rs: 8607cf05244ec9efb7e063e17cfa60096ec19a4aa39f5a7f967502f5f4b0a55a
- src/go_native/json_time.rs: aadbcf635e734808328b438e656a30eff7766208f2b5712fc157ff92b26dd0b6
- src/go_native/legacy_json.rs: b71503dbcf2cc7fbc489745cbe663cd28af0dcce5964325df68b7ec419b0d20c
- src/go_native/legacy_json/scanner.rs: 8777b54dbd9d5f3401c54b05fcf35c824a8fa4bf56a67e1ed9b2cee804213a3a
- src/go_native/pem.rs: 655f0629865cba78d13647f68e9952691092f6fe71908f6bd7d39799957debd6
- src/go_native/quote.rs: 96fc4f0b6ce2b01f3ff24fd9fe33138ecc4715c8c9b1a2622b26ef49ad8eb804
- src/go_native/quote/unicode.rs: 27fa9712788f1774d89f2010df9fc09f1b00536743b1c5f2fd603ce341746cbd
- src/go_native/resource.rs: c6850822359f60303ed1cc6814a3f642d5b06921f3f564974809eec5baffca52
- src/go_native/resource_decode.rs: 01d0af25ab95b4c8f69d283b8d670e2ca59ea84c8f21996ebb0e76b315cf54cb
- src/go_native/response_error.rs: 2879fff5d86abfe45923a2a1c3e7577540b375c5dd49d8aa44ceaf87fcea6fc1
- src/go_native/transport.rs: 3e7ed868ff9810cc6a4edb84c7cfec62e2912ae3ea8cf8e8e75381d1b1ee34e7
- src/go_native/transport/gzip.rs: f68f30f312811c8d4ecb418e594d8fe79f34655c685d4a735923273f8bc2606f
- src/go_native/transport/gzip/inflate.rs: 101f94855e67a9b86cc63cf8ec57f04bbd3682e5ed593ace147664584cf3f785
- src/go_native/transport/gzip/read_size.rs: 505c8d8d514ca30775649804e55cdc52913b27c2b4cd1a07b61f31cacaa1e83e
- src/go_native/transport/proxy.rs: bfc586ecf22d3c5db79dd1a7079594eb3fad2dca9fe2449b0494289c974a288d
- src/go_native/transport/proxy/environment.rs: c1dffc9e08455c017ab15baba75d6e16769c9c22eb00016896ddfe2aff61ecc1
- src/go_native/transport/proxy/socks.rs: d773f9ae6e17667819b3271368594f99cf3d807ba178b46ffcb25b2faecf7d60
- src/go_native/transport/proxy/unicode.rs: aa5b7cff549f0fdd655b87e2df446e9b83afda44c182a155035071a953fd7318
- src/go_native/transport/url.rs: 68be748c54fc5425009e8c337f3f257610a94853d38f0307351bd089f60dd765
- src/go_native/transport/url/idna.rs: 4e8eb2c9ea736c9a21a69125564d7a3fb2a53fc2a1fa99e1fedba8f86b31b792
- src/go_native/transport/url/idna/bidi.rs: f76100914478aff0d3f730616cfc0d91ca9ad41019774f6d1d081eeff039f15b
- src/go_native/transport/url/idna/data.rs: 3f666c52ccc7f75e3abc1dc873e6d8dccedd9a56d739e318a4008e4a20be83e0
- src/go_native/transport/url/idna/nfc.rs: 7f11b0af4d3bcd7011507777391658c4dbe7600c6c0e2687d6f2d3878243421e
- src/go_native/transport/url/idna/profile.rs: 6c968c039b2ca1a07edd66a4883af4afffacea6e540a5e90219c8228bbbd9cc4
- src/go_native/transport/url/idna/punycode.rs: 3e61c4153daf68821b4d2a5962dc84f916ac0310c5fcf707447ccd97cdbdb879
- src/go_native/transport/url/idna/trie.rs: 29da58b8e053f200c5e1fbb42c7cc96c524ed33221c282e076d7b848b0564b9f
- src/lib.rs: fc7a805c004a939cc08963094e2a06a35aa10628f52a7c41aa9862559c2e56e7
- src/order.rs: 52fc75344d8b012861fe05271d8fe5273cb2c992e3ec592cc60d5febf9fc77d4
- src/types.rs: 186979267edf04d99e04edbc837b287cb7b74c3a90715c697640c86c57d30cce

## Grouped audit native response, URL and observation boundary — 2026-10-18

The native factory selects a 10-MiB H1 response buffer/H2 header-list budget,
allows H1 folded response headers and raises the field cap within Hyper's safe
parser allocation behavior. Ordinary SDK clients retain their prior profile.
Hyper's UPSTREAM.md documents the remaining HeaderMap domain ceiling (F14).
Hidden additive go_parse_url/go_is_oidc_issuer_url expose selected Go parse and
String/scheme/host phases to CLI validation without WHATWG trimming (F13).

Hidden additive AccountBuilder::go_request_observer and NativeHttpObserver let
the CLI record actual native transport failures and status>=400 body events
(F17). Private request extensions preserve observation across redirects/retries.
A status body is read using the selected partial ReadAll/Close behavior and
restored as a buffered reader before the caller consumes it. No observer retains
the prior streaming path. Ordinary requests are forwarded unchanged. External
custom HttpClient implementations can ignore extensions; that generic surface
is unqualified. Invalid-byte log rendering and physical request/body/close timing
remain backend/runtime qualifications. Public fields/signatures and dependency
versions/resolution are unchanged. Independent source peer/direct rustfmt only;
no execution or security/advisory qualification was added.

The new selected Headscale app.go adaptation retains its BSD notice and full
LICENSE-HEADSCALE-GO here, alongside existing SDK/Go terms. Both container
recipes already include vendor/instant-acme/LICENSE*.

Selected pinned source SHA-256:

- Headscale v0.29.5 hscontrol/app.go: 381958868e878b30c1f43138808b7cb3daf27c05a3db762ed3d672bf9f779a85
- Go1.26.9 net/url/url.go: 7bec001746c2cd512275c7269bc293f3d36cb004ddb193d736e02e361a3778aa
- Go1.26.9 net/http/transport.go: 643bce4b4fb016ed57c18e9d087e6c298faf3263d83728107c6b5cdaa398fe87

Observer follow-up: native loop URI/proxy identity/proxy authorization failures
now notify before preserving their existing returned error wrappers. Initial
account prepare_url rejection is earlier than observer dispatch and remains an
explicit diagnostic coverage boundary. Bounded independent source peer passed;
no execution.

## Remaining-audit native GET and early observation follow-up — 2026-10-18

This supersedes the named initial parsed-URI observation and selected native DERP
Reqwest boundaries. An additive default-noop HttpClient::go_transport_error hook
lets selected observed clients log parsed backend URI failures before retaining
the existing Go URL wrapper. Invalid URL Parse remains before RoundTripper and
unobserved. The same wire-cause ordering is used in redirect attempts. Existing
observer extensions survive wrapper nesting, so the outer selection wins once.

Hidden additive go_http_get uses the existing native default shared transport for
GET, response ReadAll and ignored Close under a full operation timeout, without
rejecting HTTP error status bodies. A selected marker survives redirects and lets
HyperUtil choose default UA on the actual protocol, with retry restoration. The
helper is used by the native CLI DERP loader. Ordinary SDK/ACME explicit-UA paths
remain unmarked. Provider/platform/error identity, timeout-versus-cancellation
races, physical body/close/write behavior and full feature/package/default/client
qualification remain open. Independent source peers/direct rustfmt only; no
execution, dependency version/resolution or security/advisory conclusion.

Selected pinned source SHA-256:

- Go1.26.9 net/http/request.go: 4a34a9e157a606a046d5b9f8f761c571c4762668fa351d92048515a595939c38
- Go1.26.9 net/http/client.go: 908d9d964cd157899b60e7ba839befa4bfd398b4fb8f7ff5a1aa389eae75f652
- Go1.26.9 net/http/h2_bundle.go: a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e
- Headscale0.29.5 hscontrol/derp/derp.go: baaa75ae8aaa504ace47003b1f792c7af9d610eda6ae5b5b2079dabe9000b4d5

## Authorized native header capacity integration — 2026-10-18

The native go-native-client feature now selects http/go-native-header-capacity
from the local http1.5.0 package. Its default-off private index/hash widening is
shared by Cargo feature unification, while ordinary builds retain the upstream
capacity. The native byte limits remain separate. Source/version integration
follows the user-authorized dependency upgrade; no builds/tests ran.
