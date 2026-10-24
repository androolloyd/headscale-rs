# CLI compatibility source provenance

## Native resource framing, metadata and HTTP dates — 2026-10-18

Native raw order/authorization/challenge statuses preserve pending cleanup
before interpretation and let non-pending resources skip unknown challenge
strings. Actual auth polling uses raw status, avoiding SDK identifier projection
failures. A feature-gated raw order problem sidecar preserves arbitrary identifier
types/values and signed64 status while known SDK error projection remains a
convenience view. Native streaming first-value grammar framing, finite resource
DTOs and Go10000 depth gating replace full JSON-body collection/Serde128 limits
on the selected path; default SDK deserializers remain unchanged. Custom bodies
retain compatibility fallbacks. Typed field/duplicate/Unicode/partial-error
assignment now has the private Go source implementation described below; exact
diagnostics and runtime equivalence remain unqualified.

Private Go HTTP-date parsing includes all three layouts, fixed year pivot,
fractional/pre-epoch values and Unix Local/TZif/POSIX lookup. Its once-init timing,
explicit GOROOT/system files, non-Unix projection and resources remain qualified.
The default archive is copied from selected Go and attributed inside the vendor.
TLS certificate phase ordering now has the native continuation/bridge source
implementation in API/rustls; broader TLS/cipher/decoder/alert behavior remains
unqualified. Vendor UPSTREAM.md files record source pins/local hashes and terms.

Independent source reviews/direct rustfmt only; no builds/tests, executable
feature/client/CA/package/container/process evidence or release gate closure.
This supersedes earlier missing raw-status/framing/date/provider-phase notes.

## Native ACME retry and pending cleanup — 2026-10-18

The exact selected instant-acme0.8.5 source is now vendored. Its default-off
`go-native-client` feature exposes explicit native Account/Order APIs; only the
CLI dependency calls them. Default SDK methods/Client.post remain unchanged.
Native POSTs classify selected Go retryable statuses and badNonce, retaining
first raw Retry-After metadata with signed64/wrapping seconds and bounded
exponential backoff/jitter. HTTP status/transport errors stay separate from
body/JSON decode errors. Auth/order polling retries body/JSON failures at the
same URL; zero/invalid poll delay means1s, negative means immediately due.
Finalization polls its own response Location and waits on actual order state
before direct certificate retrieval. Selected Hyper downloads now enforce Go
5MiB-plus-overhead/max-five-CERTIFICATE/nonempty PEM limits and canonicalize
only decoded blocks; unknown suffix bytes are ignored. Custom external bodies
retain a default collect-before-prefix fallback. Source detail is in the vendor
UPSTREAM.md.

Native verifyRFC captures all authorization URLs immediately after successful
new-order decoding, before status checks. On success, failure or cancellation,
Drop starts an independent five-minute cleanup per order, in reverse order;
it fetches each URL directly and deactivates only Pending. Fulfillment cleanup
still ends before finalization. Runtime shutdown/task scheduling/resource
behavior has not been executed.

Source pins, SDK adaptation scope, original licenses/retained Go BSD terms are
in vendor/instant-acme/UPSTREAM.md and LICENSE-GO*. Both manifests add BSD terms;
both image recipes copy them. Root patch/exclude and exact lock source change
reuse selected versions/dependency lists. Native account discovery/registration,
nonce pool/HEAD, first-value/typed JSON assignment and HTTP dates now have source
implementations described in the later update. Transport redirects/TLS/reuse,
exact diagnostics and runtime behavior remain unqualified. Raw SNI and missing
signature phases have native source implementations; broader TLS/provider
acceptance remains an open boundary.
Independent source reviews/direct rustfmt only; no tests/builds/CA/client/process,
feature/package/container qualification or release gate closure. This supersedes
the pending-cleanup/selected retry gaps recorded below.

## Native lazy ACME, RSA and authorization lifecycle — 2026-10-18

Native startup constructs an empty bound provider before public/remote TLS
acceptance. It does not read the certificate cache, generate a certificate key
or contact the CA. Hostname activation/HostWhitelist input retain the configured
nonempty string without trimming. Native server paths no longer call eager
ensure/renewal startup helpers. The shared provider captures ordinary ECDSA/RSA
kind before rustls suite filtering; token requests use its initial shared
resolver without ordinary issuance. API/transport provenance is in
headscale-api/UPSTREAM.md.

src/acme_issuer/lazy.rs coalesces owned tasks per kind and keeps clients from
cancelling issuance. Five-minute initial and ten-minute renewal owners use
typed cache lookup, preserving fatal read/private-key errors versus misses.
P-256/RSA2048 keys and CN plus explicit DNS SAN CSRs are prepared before lazy
account/network work. A manager-local account mutex is released before orders.
The already-selected CLI rcgen0.13.2 edge moved from dev to production without
version/resolution changes; its selected AWS-LC generator supports RSA2048.
Existing public APIs and the API wire-only dependency boundary are preserved.

Fresh ready state, follower publication and renewal start precede first
best-effort cache write; the initiating caller waits for cache completion.
Created-state failure followers receive missing-certificate during the one-minute
retry interval; pre-state errors are not retained. Ordinary memory state is
served without expiry revalidation. Renewal adopts newer eligible cache state
or reuses its existing key, and only replaces memory after successful cache
write. Timing uses lifetime/3 capped30d with jitter, and 30–60min failure retry.
Weak timer ownership and the maintenance stop guard bound lifecycle work.
An immediately-due renewal still coalesces with the initial pending owner;
exact blocked-filesystem concurrency/scheduling remains unqualified.

src/acme_issuer/native_order.rs follows selected verifyRFC preference and
retry phases: TLS-ALPN first, then HTTP-01 when configured, with one next-type
cursor across orders/authorizations and unchanged account/key/CSR. New-order,
GetAuthorization, initial status and exhausted challenge failures remain fatal;
fulfillment/accept/auth-wait/order-wait failures retry with a new order. The
fulfillment cleanup scope ends before CSR finalization. The outer owner bounds
native polling; old per-type 90s fixture paths are test-only. Pending
authorization deactivation, Retry-After/invalid-JSON and library transport
diagnostics remain incomplete or unqualified.

Provider remote gRPC handshakes use src/server/acme_grpc_incoming.rs: a bounded
1024-task JoinSet, completion-first polling and explicit wake registration.
Dropping it requests cancellation of connection futures; provider-owned issuance
has its own stop condition. Static remote TLS retains its previous incoming
path and deadline policy. This is not exact Go quota/resource equivalence.
Cache/account files now use exclusive 0600 creation, 0700 directories, atomic
rename and error cleanup before exposing private bytes.
Two existing native ACME fixtures now initiate ordinary TLS before expecting
issuance. They were source-adjusted only and remain unexecuted.

Selected source SHA-256:

- x/crypto v0.53.0 autocert/autocert.go: 175d3d5b0dd6278291bb924b55f1c9e6647b24f8e595394e2848dc6f50e07aea
- autocert/renewal.go: c441235ad4e46eab701b533df00827f45b8a21060a3b59d9d1eca2165989d6f4
- rcgen0.13.2 src/key_pair.rs: 21ae7731f051be2999bedf14cea1717849195c1802c4e8e799190fab9c7ed8a9
- rcgen0.13.2 src/certificate.rs: 6b6fe40cee537c91a61d7e222815c35588fc5024cd2b055f0f1b69909ef50f4c
- instant-acme0.8.5 src/order.rs: d23e49a02af011717147b54e4f04d694ed1a71010939a5c41267f2debff77800

The new lifecycle/order helpers retain Go Authors2016 attribution and BSD terms
in NOTICE-GO-STDLIB/LICENSE-GO-STDLIB. Source reviews/direct rustfmt only; no
tests/builds/probes, CA/client/feature/package/process/restart qualification or
gate closure. Raw SNI/missing-signature TLS acceptance, X.509/provider/session
state, context/synchronous filesystem/resource behavior remain unqualified.

`src/server.rs` now follows headscale-go v0.29.5 `hscontrol/db/ip.go` for raw
address seeding, actual-family/zone handling, one-start finite random scans,
exclusive-bound random selection, tiny-prefix exhaustion and paired allocation
locking. The source hash is
`190e8a05be4b16fe24dfaa0c758c59ae595f02b7501fa9f50b565b4b87786071` at commit
`0f7d1e536bed9f01dd7161f7637af19bb0908335`. The original Juan Font BSD notice
and terms are retained in NOTICE-HEADSCALE-GO and LICENSE-HEADSCALE-GO, alongside
the existing Go/gRPC notices. Both container recipes copy them. Random draws
use the existing OS randomness dependency with rejection sampling; no release
changed. An existing tiny-pool assertion was source-adjusted only. No build,
entropy/distribution/exhaustion/concurrency, malformed database, feature, CLI,
process, license/container or restart evidence qualifies these changes.

The private `src/admin/grpc_client/upstream_*.rs` modules follow the
headscale-go v0.29.5 client and its pinned grpc-go v1.81.1 implementation.
The DNS service-configuration selection, method paths, validation and signed
duration handling in `upstream_service_config.rs` adapt grpc-go's
`internal/resolver/dns/dns_resolver.go`, `service_config.go`,
`internal/serviceconfig/duration.go` and balancer parsing. The Apache-2.0
license and gRPC copyright/attribution notices are retained in
`LICENSE-GRPC-GO` and `NOTICE-GRPC-GO`.

CLI logging now delegates Go string quoting to the maintained shared leaf
`headscale-api-acl::go_strconv`. Its Unicode tables were moved from
`src/logging/unicode.rs`; the source hash and Go Authors' BSD notice remain
in the shared source, with quote.go/isprint.go provenance in that crate's
UPSTREAM.md. Configured prefixes and trusted proxies likewise use the shared
Go netip parser. Go-derived resolver/NSS/RFC6724 behavior follows the
cached Go 1.26.9 source. `LICENSE-GO-STDLIB` retains the Go BSD notice for
binary distributions. Package metadata accounts for the Apache/BSD additions,
and both runtime container recipes copy these license and notice files.

The service-config path currently implements TXT framing/search/selection,
the Go environment defaults, initial invalid-config rejection, retention of a
previous valid config, method/service/default precedence, signed/clamped
durations, per-call deadlines and request/response limits, plus pick-first
address shuffling. All 29 admin request types select their method by the wire
RPC name. The RPC budget preserves the command deadline and checks negative
message limits too. A direct Prost dependency reuses the already locked
workspace release for encoded-size checks; no release was upgraded/resolved.

`upstream_retry.rs` adapts grpc-go v1.81.1 `stream.go` and `clientconn.go`
(Copyright 2014 gRPC authors, covered by the retained gRPC notices). It keeps
encoded unary requests replayable up to Go's 256 KiB retry-buffer threshold,
commits larger bodies, stops replay after initial response headers, handles
trailers-only/configured pre-header failures, and transparently replays a
first explicit remote REFUSED_STREAM. Configured attempts cap at five and
honor status sets, 0.8-1.2 jittered exponential backoff, server pushback,
previous-attempt headers and the original RPC deadline. Throttle buckets reset
on applied config, decrement only at Go's failure checks, and gain tokens after
successful unary decoding. Exhaustion retains its Go CLI error wrapper.
Replay bodies retain the encoder's unspecified size hint so Hyper does not
introduce a Content-Length header from the buffered payload.

All CLI client responses now guard binary status details in initial headers
and trailers before the pinned Tonic 0.14.6 parser's base64 expectation. These
are source guards without malformed-server execution or advisory evidence.
Direct h2 0.4.19/http-body 1.0.1 and the promoted http-body-util dependency reuse
locked releases; only dependency edges were edited, with no Cargo resolution.

`upstream_service_config/json.rs` adapts Go encoding/json's ordered typed
decoding and grpc-go's service-config/canary/code types. Every known duplicate
occurrence is validated before selection; incoming names fold case, including
long-s and Kelvin-sign ASCII fold cycles. Repeated struct pointers merge, null
pointers reset, and scalar nulls retain earlier values. Reused array slots keep
their state across duplicate fields and shrink/regrow; empty arrays and null
reset it. Custom duration nulls retain Go's error boundary. Integer fields parse
tokens directly, including -0, while retry codes use Go's raw-name spelling.
Outer choice arrays and balancer map element types decode fully before early
selection. Raw service configs and load-balancing configs stay opaque until
their selected/final occurrence is interpreted; selected source bytes are kept
for config identity. This removes map reduction before duplicate validation.
`json/scan.rs` adapts the shared `headscale_db::go_json` scanner to this
path's error envelope. The scanner follows Go 1.26.9 scanner.go/decode.go and enforces
the 10,000-container limit, JSON's four whitespace bytes and token/escape
grammar without recursing through unknown/raw payloads. Typed strings and
keys combine valid UTF-16 surrogate pairs, replace lone surrogates, and replace
each malformed UTF-8 byte as Go does. DNS TXT strings/records stay as bytes
through concatenation and selection, and raw config identity retains those
bytes. This also preserves UTF-8 sequences spanning DNS character/record
boundaries. The existing Go BSD notice covers the adapted scanner.
No dependency release changed. Exact errors, hostname/platform bytes, Unicode,
depth boundaries, parser CPU/memory and runtime config/retry effects remain
unqualified. No build, malformed-input execution, depth/load or process result
covers this scanner and byte-path change.
The scanner was moved into headscale-db for reuse by Go/Gorm database tag
decoding. headscale-db/UPSTREAM.md records the source hashes and retained BSD notices;
both container recipes copy them. The extraction and SQLx adapter are unbuilt
and untested; no runtime or feature/license qualification is implied.
The API policy manager now emits the missing hash-change event family and
counts/flags from private compiled snapshots. Fingerprints use Rust SHA-256
projections rather than Go deephash. Native startup now loads allocator, nodes,
users and raw source before one real full-input policy construction. Failed
constructors keep partial events without empty-policy rollback logs; boot
warnings follow success. Exact policy mode matching no longer trims whitespace;
unknown modes load no policy, exact-empty source is nil and whitespace is parsed.
Native loading/constructor phase prefixes and direct node/user list error
payloads were source-aligned. Public deferred APIs remain optional legacy paths;
native startup does not use their diagnostic replay. Retained shape/hash,
underlying association/driver/parser/rare OS/UTF8 and exact output/lifecycle
differences remain unresolved or unqualified.
The earlier proposed native tag-validation reordering was unwarranted: pinned
Go validates tag chains while parsing too. See the API UPSTREAM diagnostic
section. No process snapshots were recaptured.

Startup source references (Headscale v0.29.5 SHA-256):
- hscontrol/state/state.go:
  7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01
- hscontrol/db/policy.go:
  59aca2ef1a9d8a0187ffd37df1c40ad12ed2a5b63c8f4c7825118a5809950746
- hscontrol/policy/v2/policy.go:
  1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e
- hscontrol/util/file.go:
  180c2e8955423f12b9b33f01caef1599d72cdaac9f98a4907f790a8dbd6a294b
- hscontrol/types/config.go:
  d27177817d7477525f78cd71fd98574aeb631bd6df39503858015c95768ea788
Existing BSD notices/license apply. Independent source review/direct rustfmt
only; no tests/builds/Cargo/validators/probes/recapture or gate closure.

`upstream_connection.rs` now supervises native transports after initial dial.
EOF, shutdown, errors and complete GOAWAY frames retire a transport for new
picks. Pick-first reconnects on demand through a one-shot idle picker;
round-robin children automatically exit Idle. Connecting picks wait, transient
failure picks fail fast unless waitForReady is set, and every wait/dispatch
checks the original RPC deadline. A request is only repicked before dispatch;
subsequent replay belongs to the retry controller. Each HTTP/2 Channel owns
one transport; its connector cannot silently redial a stale endpoint. Known
connector failures before any new stream carry a private unprocessed marker
for transparent retry without consuming configured attempts.

Active dispatch/response bodies retain transport leases, allowing an old
GOAWAY connection to finish existing calls while the supervisor dials anew.
Last-owner Drop cancels all registered current/retiring transports and aborts
the supervisor. Connection budgets grow with backoff, with a 20-second minimum
for initial and later attempts. Initial blocking dial verifies current readiness.
This owned lifecycle applies only to the standalone constructor; direct
library channels retain their static transport path.

Ordinary hostname TCP dialing now follows Go 1.26.9 net/dial.go's two-family
race: the alternate family starts after 300ms or primary exhaustion, addresses
within each family dial serially with the remaining-deadline split/2-second
floor, and a double failure reports the primary's first error. Losing futures
own/drop their sockets. This TCP selection precedes the single TLS handshake.
The Go Authors' BSD notice is retained in the source and package license file.

`upstream_balancer.rs` adapts grpc-go's pickfirst/roundrobin (Copyright 2017),
endpointsharding (Copyright 2024) and gracefulswitch (Copyright 2022) lifecycle.
Modern and legacy service configs select pick-first or round-robin. DNS policy
selection precedes dialing; round-robin creates a reconnecting child per unique
endpoint, rotates child startup order and cycles ready children from a random
counter seed. Aggregate readiness prefers ready over connecting over failure.
DNS updates retain matching children and retire removed ones; generation checks
discard stale dial events without replacing the picker. Pick-first retains
matching per-address subchannels and backoff clocks across DNS changes. It
starts full TCP/TLS/ALPN/H2 attempts 250ms apart, immediately advances on current
failure, waits for all first-pass failures before reporting failure, then retries
independently while effective failure stays sticky until Ready. Backoff-expired
idle children wait for the first pass to finish. A ready winner retires all
others; a still-present winner is retained. After Ready closes, the picker
enters Idle and starts a new first-address pass on demand. An atomic one-shot
wake token matches Go's sync.OnceFunc and prevents concurrent callers from
leaving a later idle permit. Round-robin children auto-connect on Idle. Literal
IP DNS targets become direct sockets; mapped IPv6 uses the IPv4 family for
interleaving/fallback. Each subchannel owns its actual Tonic transport; the
superseded duplex preface replay and address-snapshot retry helper was removed.
Temporary DNS errors keep the last good address state without applying a config
or resetting retry throttles. Only connection failures/closure request refresh;
reading a cached snapshot does not. Policy changes use active/pending pools and
Go's handoff rule: swap when the candidate leaves Connecting or the old pool
loses Ready. Removed and superseded transports retain in-flight body leases.

Health configuration is type-checked but does not start Watch RPCs, matching
the inspected standalone Go baseline's import boundary. The cached production
v0.29.5 Mach-O at `target/real-client/postgres-v0295-go-to-rust-import-1792209186-73018/go/hs-online-lastseen-headscale-go-postgres-authkey-1792209186-73035/bin/headscale`
contains roundrobin init and health/grpc_health_v1 init symbols but no
grpc/health package symbols. Pinned headscale/grpc-gateway production sources
import the protocol package, while grpc-go clientconn.go requires the parent
health package to register internal.HealthCheckFunc before starting Watch.
This is bounded source/binary inspection, not executed health-check evidence;
other Go builds with extra imports are outside this baseline.

Complete GOAWAY/new-stream transparent retry equivalence, oversized-request startup
failures, transport status classification and cancellation/order edges also
remain incomplete or unqualified. Full raw
JSON/null/case-collision behavior, diagnostics, compressed/unknown-field payload
handling, platform DNS, resolver Close and reconnect/draining behavior remain
incomplete or unqualified. Pick-first per-address backoff/reuse, first-pass and
idle/one-shot wakeup behavior, mapped-address family ordering, endpoint/config
churn, ready-only distribution, health nonactivation, resource use and graceful
policy handoff have no execution evidence. No build, test, network probe, container, dependency
or license validation qualifies this implementation batch.

## SIGHUP policy events

The signal handler emits signal=hangup with Received SIGHUP, reloading ACL
policy, and logs reload errors as their payload under reloading policy. It
no longer adds unconditional reloaded/skipped info messages. The API owns the
successful reload's SSH invalidation, auto-approval and notification sequence.
The reference is Headscale v0.29.5 hscontrol/app.go, SHA-256
`381958868e878b30c1f43138808b7cb3daf27c05a3db762ed3d672bf9f779a85`.
Policy-manager seeded deephash and conditional change-count logging remain
incomplete; no text/JSON/process or signal run qualifies this source work.

## Deleted-address release and rename configuration

Production runtime preparation configures the registry's given-name base domain
and weak allocator binding before serving control/admin paths. CidrIpAllocator
implements the default-compatible release_addresses hook by removing typed IPv4/
IPv6 reservations under its existing address-pair lock. It does not rewind prev,
matching Headscale v0.29.5 hscontrol/db/ip.go FreeIPs. Shared DNS-name validation
and registry delete/notification ordering are documented in the API/ACL packages.
Existing Headscale BSD terms/notices remain retained; no dependency version
changed. Release/reuse/exhaustion, domain/error limits, weak ownership/custom
configuration, concurrency/cancellation/features/wire-only/package/container and
stock-client/process/restart behavior are unbuilt and unqualified. No build,
test, probe or executable validator ran.

## CLI duration quoting and pterm width escapes — 2026-10-18

The shared go_strconv module now exposes time.quote separately from
strconv.Quote. CLI time.ParseDuration diagnostics use byte escaping for
non-ASCII/control input while Prometheus model.ParseDuration errors use Go
string quoting. DEL behavior and invalid/missing/unknown-unit envelopes follow
the pinned sources; legacy duration grammar is unchanged.

CLI upstream table padding measures OSC 8 visible text and gookit color-cleared
lines, preserving the literal reset-suffix precondition, ASCII SGR pattern and
multiline maximum. Printed bytes are unchanged. The existing unicode-width
backend remains; full Go runewidth grapheme/Unicode/locale behavior is a separate
source/qualification boundary. No terminal-control sanitization is claimed.
The CLI now declares the ACL dependency already used by logging and directly
reuses locked regex 1.12.2 for fixed linear-time patterns; no version updates.
Pterm/gookit MIT terms are retained in LICENSE-PTERM/LICENSE-GOOKIT-COLOR and
NOTICE-PTERM; CLI metadata includes MIT. Go terms remain in LICENSE-GO-STDLIB.

Source SHA-256:

- Go 1.26.9 src/time/format.go: f288c56858ab25828551681778f006b591ed140fc12e60122b6a9a7e35b07eb7
- prometheus/common v0.68.1 model/time.go: 2eaa3a4820fed568a8ffa74b51d09afe6d127ff90a5caf2f3175eb1ccc12d05d
- pterm v0.12.83 table_printer.go: 8675715851f7d8c8fac6ee79aa9164b4ed371918f212e59cabc179fbed38940b
- pterm v0.12.83 internal/utils.go: 8337705f6f1c7976e88f08f1ade3267c9450c1df41545543593a6f002d3af0e7
- pterm v0.12.83 internal/max_text_width.go: eba65a5524cfc370b8e3ac5122426b83934f31c2dde6bcaf9f95dd3d0ce7b653
- gookit/color v1.6.1 color.go: 6b76711772025ffb3531033c4a6e40ecc920baef9faa0faae0b606c8155594c3

Source reads/hashes and direct rustfmt only; no tests/builds/validators/probes or
fresh dependency/advisory checks. No compile, parser/output/process or security
qualification follows from this batch. Startup/provider/config/transport/TTY/
color/Unicode/grapheme/locale/invalid-byte/IO combinations and all broader
native/wire-only/package/container/client/process/import/restart gates remain
incomplete or unqualified. All three replacement-parity gates remain open.

## Pinned Unicode table width — 2026-10-18

The upstream renderer now uses private src/admin/output/runewidth.rs and
runewidth/tables.rs ports of go-runewidth v0.0.24 with clipperhouse/uax29/v2
v2.7.0, as selected by headscale-go v0.29.5. This supersedes the generic
unicode-width boundary described above. The direct unicode-width dependency
and CLI lockfile edge were removed; other packages retain their own edges.
No dependency version changed.

The default StrictEmojiNeutral=true condition uses pinned zero/double/ambiguous
width ranges, Unicode 17 grapheme properties and the first-positive-rune rule,
including Indic linker and pictographic-ZWJ/RI lookbacks. POSIX locale selection
honors RUNEWIDTH_EASTASIAN, LC_ALL/LC_CTYPE/LANG, C/POSIX overrides and
@cjk_narrow. The port measures valid UTF-8; non-POSIX console code-page discovery
is not implemented. The locale condition initializes on first measurement.

tools/generate-cli-runewidth-tables.py reads hash-pinned Go source data and emits
scalar intervals without using the host Unicode database. It is source
generation, not runtime validation. MIT licenses/copyrights/source hashes are
retained in NOTICE-PTERM, LICENSE-GO-RUNEWIDTH and LICENSE-UAX29; existing runtime
container license globs include them. No feature/package/container qualification
was executed. Source generation/reads/hashes/direct rustfmt only; no tests,
builds, validators, probes or fresh dependency/advisory checks.

The standalone serve path also gives OIDC startup failures the upstream
initializing/creating-new-headscale context rather than the Rust-only
build-OIDC-runtime label. Provider decoding changes are recorded in
headscale-api/UPSTREAM.md. Startup output and all three release gates remain
unqualified.

## Source-aware policy user validation — 2026-10-18

Startup and direct policy commands now pass original raw source into the
shared source-aware API user validator. Each original ACL source is checked
once before destination expansion; original destination order is retained.
The new helper binds raw source to the public grant/rule projection and keeps
programmatic explicit rows on mismatch. Pinned Headscale v0.29.5 policy.go
validateUserReferences provenance is recorded in headscale-api/UPSTREAM.md.
Public command/error envelopes and dependency boundaries remain unchanged.
Source/direct rustfmt only; no tests/builds/validators/process comparisons or
fresh advisory qualification. Exact diagnostics and full CLI parity remain
unqualified; no release gate closes.

## Shared Go duration utility — 2026-10-18

The existing parse_go_duration_nanos entrypoint delegates to the ACL leaf's
shared Go 1.26.9 duration translation, keeping its public signature and quoted
diagnostic classes. The parser now preserves uint64 accumulation wrap before
the signed bound check, matching pinned time/format.go rather than using
checked addition. Whole/fraction precision and float64 evaluation order are
shared with policy validation and live SSH checks. The Prometheus expiration
parser retains its separate existing path. Source hash/notices/BSD license
provenance is recorded in headscale-api-acl/UPSTREAM.md.
Source/direct rustfmt only; no builds/tests/validators/process comparisons or
fresh advisory qualification. Platform/error/resource and full CLI/restart
qualification remain open; existing fixtures were not recaptured/run and no
release gate closes.

## Source-aware policy-test sandbox wiring — 2026-10-18

Direct policy check/init validation and server startup warnings now pass their
original source to the API's additive source-aware semantic check/warning
entrypoints. This keeps selected nil-default filtering, source ACL rows and
app shapes available to the fresh global ACL-test sandbox. Existing public
fields/methods and wire-only dependencies remain unchanged. The API and leaf
UPSTREAM.md files record the pinned Headscale v0.29.5 test.go/types.go parser,
compiled filter test semantics and source notices/licenses.
Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification or fixture recapture. Routed node inputs, source-less projection,
SSH-test/combined error behavior and all package/container/client/process/
import/restart/concurrency/resource qualification remain incomplete or
unqualified. No release gate closes.

## Direct/startup policy-test route snapshots — 2026-10-18

Direct SQLite/Postgres policy checks now construct additive route-bearing
PolicyCheckNodeSnapshot entries using fallible tags/Hostinfo/approval decoding
from each loaded row. Source-aware check and boot-warning calls use the new
snapshot entrypoints. Server startup warnings capture loaded identity/address
metadata and routes through the API's retained registry constructor, rather
than a metadata-free record projection; construction errors propagate while
policy-test failures remain warn-and-continue. Public existing field/method
and wire-only feature/dependency contracts remain unchanged. The API's
UPSTREAM.md records pinned Headscale v0.29.5 Node route getters and policy-test
compiler source provenance/notices/licenses.

Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification or fixture recapture. Typed/canonical route and orphan/association
edges, database snapshot consistency, legacy/custom inputs and all package/
container/client/process/import/restart/error/concurrency/resource/shutdown
qualification remain incomplete or unqualified. No release gate closes.

## Direct policy snapshot identity/address edges — 2026-10-18

Direct SQLite/Postgres policy snapshots use only loaded user associations for
policy ownership; orphan foreign keys provide no owner. Tagged creator metadata
is retained for downstream classification. Username fallback follows Go's email,
name, provider identifier, then numeric ID. Present zero addresses and scoped/
mapped family are retained through the shared Go address-text projection.
Invalid/duplicate Rust node IDs and negative user IDs fail explicitly; both stores
share fallible user-directory conversion. Existing route decoding is retained.
Public signatures/fields remain unchanged. Users/nodes remain separate reads as
in the pinned CLI; malformed-row diagnostics and zero-node-ID behavior are not
qualified (Go uint itself can express zero, Rust native identity rejects it).

Pinned Headscale v0.29.5 SHA-256:
cmd/headscale/cli/policy.go 17cf00ad32b18ad9cfb90aba1804fff855112d70afe1904b9c3091b52c1fa1a8;
hscontrol/types/node.go b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab;
hscontrol/types/users.go 36bc0f562c507336d3a2a309c94718ec3baa2db2c3432180596556ab512d69dd;
hscontrol/policy/v2/types.go 57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4;
hscontrol/db/node.go 9b1badd1eba80662eccb1eb5e2d0f039967b6469a30fab6fb3904466de234bb4.
Existing notices/licenses apply. Source/direct rustfmt only; no tests/builds/
Cargo/validators/probes or gate closure. Full offline snapshot, malformed-row,
CLI/process/import/restart and prior qualification remain pending.

## Direct policy constructor and database diagnostics — 2026-10-18

Direct Set/Check now use the additive isolated compile_policy_for_snapshot
before constructor boot warnings, carrying Check's loaded node/route inputs.
Static tag topology and node-dependent compiler errors abort with parsing policy
file wrapping. Set retains its pinned empty-node constructor and warning-only
semantic checks; Check follows construction/warnings with the hard semantic
boundary. Existing public signatures and field types remain. Direct Get now uses
backend-neutral loading policy from database text including missing-policy errors.
Get/Set and user/node-load errors use DbError.headscale_go_message. Dispatch exit
normalization and database open/migration wrappers remain unchanged.

Pinned Headscale v0.29.5 SHA-256:
hscontrol/db/policy.go 59aca2ef1a9d8a0187ffd37df1c40ad12ed2a5b63c8f4c7825118a5809950746;
hscontrol/types/policy.go ae45869c30684f8a08388db3f0c97b9aab7c386abfe35137269a9b8119ec0ac9;
cmd/headscale/cli/policy.go 17cf00ad32b18ad9cfb90aba1804fff855112d70afe1904b9c3091b52c1fa1a8;
hscontrol/policy/v2/policy.go 1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e.
Existing notices/licenses apply. Source/direct rustfmt only; no tests/builds/
Cargo/validators/probes or gate closure. Source/row consistency, malformed/app/
DB/driver diagnostics, all constructor/runtime combinations and accumulated
native/wire-only/feature/package/client/process/import/restart qualification
remain unqualified.

## Direct database startup boundary — 2026-10-18

SQLite/Postgres connection failures use opening database plus the existing native
DB error renderer. Explicit unsupported-version and Migration variants retain
version check and migration failed phase labels; ambiguous combined migration
errors do not acquire an invented phase. SQLite parent creation follows Go
EnsureDir stat handling and recursive Unix0700 mode, with nested source-derived
permission wording. Public signatures and existing confirmation behavior remain.

Pinned Headscale v0.29.5 hscontrol/db/db.go SHA-256
141d70c4fb38ebfdfdbb072de70d56b1620a15d25357a5b012685a8df7bfc024;
hscontrol/util/file.go
180c2e8955423f12b9b33f01caef1599d72cdaac9f98a4907f790a8dbd6a294b.
Existing licenses/notices apply. Source/direct rustfmt only; no tests/builds/
Cargo/lint/validators/probes. Combined migration-stage loss, SQLx versus gormigrate
messages, nonpermission failing ancestor paths, platform/locale/driver errors
and accumulated CLI/package/client/process/import/restart qualification remain
unqualified. All three release gates stay open.


## Unicode configured log levels — 2026-10-18

configured_level uses shared Go Unicode EqualFold over zerolog's canonical level
names before its existing numeric/fallback path. A long-s spelling of disabled
therefore suppresses output rather than falling back to Debug. Pinned zerolog
v1.35.1 log.go SHA-256:
ff745ccc500d61dd3c8ce64c00aa9ec0bd7b3f30796eca4f8be6c854ce14d7f2.
Source/direct rustfmt only; broader CLI/startup/provider diagnostics and all
three release gates remain unqualified. Existing upstream notices apply.


## OIDC secret-file startup errors — 2026-10-18

Empty client_secret_path is unset, matching Viper's raw-string activation check.
The CLI resolver maps common file errors to Go-style open/read PathError text
and removes Rust-only resolution context; mutual-exclusion text remains pinned.
Core public types/resolver remain unchanged. Source: Headscale v0.29.5
hscontrol/types/config.go lines1213–1226, SHA-256
d27177817d7477525f78cd71fd98574aeb631bd6df39503858015c95768ea788.
Environment expansion, invalidUTF8 paths/secret bytes, rare read-operation
classification and OS/locale diagnostics remain unqualified. Source/direct
rustfmt only; no tests/builds/Cargo/validators/probes or gate closure. Existing
notices/licenses apply.


## Native secret-file expansion — 2026-10-18

Native config/secret_file.rs resolves the OIDC secret without delegating to the
legacy core. It follows Go os.ExpandEnv's one-pass grammar, including special
and single-digit variables, empty braced names and unterminated braces. Shared
Go TrimSpace handles the resulting text. Existing conflict/path/read ordering
remains; public APIs and core code are unchanged.

Go 1.26.9 source SHA-256:
- os/env.go: e7eb15de93fccf8c0706285c350f32eab6c4a1f752bb8594ce7da3a0215ee92b
- strings/strings.go: ba9478be775d11b6956c828ebf870a8f8e7b7318ee382834f1e741f02d1336ef
Headscale config.go pin from the preceding batch applies. Go BSD license and
NOTICE-GO-STDLIB apply. NonUTF8 path/secret projection, nonUTF8 environment
values and uncommon IO/locale text remain incomplete or unqualified.
Source/direct rustfmt only; no tests/builds/Cargo/validators/probes or gate closure.
# Native policy file bytes — 2026-10-18

Native SQLite/Postgres startup reads policy files as bytes and uses the additive
full-input byte constructor. Boot warnings inspect valid compilation source;
the original file bytes stay separately retained. This permits malformed UTF-8
inside metadata discarded by pinned Go while rejecting malformed comments and
retained strings at their respective parse phases. Existing public String APIs
and dependency versions remain unchanged. HuJSON source/license pins live in
headscale-api-acl/UPSTREAM.md. Source/direct rustfmt only; no tests/builds/Cargo,
validators/probes/recapture or runtime/feature/process qualification. Three
parity gates stay open.

# Native shutdown orchestration — 2026-10-18

Production CLI retains losing listener JoinHandles across selection, aborts
maintenance tasks on signal before the DERP notice and on every exit before
listener teardown, then awaits native map drain while the batcher and database
remain available. Early ACME failures use the same stop/drain ordering for
already-started work. Private test helper signatures remain compatible.

Adapted shutdown phases follow pinned Headscale v0.29.5 hscontrol/app.go,
SHA-256381958868e878b30c1f43138808b7cb3daf27c05a3db762ed3d672bf9f779a85.
Existing Headscale BSD license/notice applies; API UPSTREAM.md records the native
drain scope, source pins and limitations. This is not a global drain of detached
non-map mutations. Independent source reviews/direct rustfmt only; no tests,
builds/Cargo/validators/probes/recapture or runtime/process/feature qualification.
Three parity gates remain open.

## Graceful production gRPC shutdown — 2026-10-18

Private shutdown-aware local/external gRPC spawn helpers use Tonic's selected
serve_with_incoming_shutdown path; original private test wrappers remain.
Production retains separate one-shot signals. HTTP listeners stop first,
native maps drain while gRPC remains live, then local and external RPC servers
stop/wait in that order without a timeout before state teardown. Existing
listener errors remain primary if cleanup also fails. No public field or API
changed; no dependency version changed.

Pinned source SHA-256:
- tonic v0.14.6 src/transport/server/mod.rs (graceful connection watcher wait):
  fc341cf57114ac9a527694028f9f27dcc8c86156475fb3f40ce7b19d899189f4
- google.golang.org/grpc v1.81.1 server.go (GracefulStop and handler wait):
  af57f92e3ecf2adf8e832afd074a267a5bb370ab4b4241842dbe9155e33f3b8a
- Headscale v0.29.5 hscontrol/types/const.go (HTTPShutdownTimeout = 3s):
  693c0328a3dc226eae42411a908cc6abb1c7d63f41e9e7444be41c5d0c8d88ce
- Go 1.26.9 net/http/server.go (Shutdown excludes hijacked connections):
  6f344ca40661ce5d31ce7f237dc23c53d4d34fe3043bd5e76bac50e6c97d91cb
Existing app.go/noise.go pins apply. This uses existing Tonic APIs; no Tonic
source was copied. Existing Headscale BSD provenance covers adapted ordering.

Previously detached mutation workers remain outside the active RPC guarantee.
The newer ordinary HTTP implementation below supplies the shared3s phase;
upstream's HTTP wait excludes hijacked Noise and does not imply a universal
Noise worker drain.
Independent source review/direct rustfmt only; no tests/builds/Cargo/validators,
probes or active-RPC/TLS/cancellation/shutdown/process qualification. All three
parity gates remain open.

## Native ordinary HTTP shutdown — 2026-10-18

Production now calls the additive API serve_with_shutdown and retains its
opaque HTTP control. Scheduled maintenance and ephemeral GC stop before one
shared3s debug-then-main shutdown phase. Timeout is logged and nonfatal; active
ordinary connection tasks continue. Native maps then drain, followed by local
and external RPC graceful stops before state teardown. Early ACME startup
failures use the HTTP phase during cleanup while preserving the original error.
Challenge-only listeners retain their separate stop behavior. Existing private
test wrappers and public APIs are unchanged.

Headscale app.go and Go net/http/server.go pins above apply. API UPSTREAM.md
records the managed H1/StateNew/admission/hijack source and license details,
plus the separate confirmed ACME ordinary TLS H2 gap. Exact logs/caller paths,
finer reused-request parse/write races, detached workers, scheduling/resources
and active-handler/shutdown/process/native/wire-only/package qualification
remain unproven. Independent source reviews/direct rustfmt only; no tests,
builds/Cargo/validators/probes or gate closure. Three gates remain open.


Native ACME order-finalization status follow-up — 2026-10-18:
The latest raw NativeOrderResource sidecar retains status, operational URLs,
Location and raw error metadata. An unknown finalize status does not fail SDK
enum projection before polling; the CLI waits on the returned Location and
checks raw Valid before downloading the latest certificate URL. Unknown poll
statuses retain raw state and retry the same URL; typed state remains its last
representable compatibility view. This avoids fabricated enum variants.
Combined independent source review found no actionable blocker in the bounded
resource/framing/depth/finalization path. No executable qualification followed.

Local source SHA-256:
- src/acme_issuer/native_order.rs: e144a090b0796c0d3852d2fb6cdd953693ec52c59df24410289ce426502595b2
- src/acme_issuer.rs: f2355cc5e6d147291020176d37a7cb3d9f8548172e68425ed2637ba92778ebb8

## Native account/cache and typed resource assignment — 2026-10-18

Production lazy issuance now calls load_or_create_native_account. It reads the
shared Go `acme_account+key` file, tries `acme_account.key` only on NotFound,
and treats other read/malformed-key errors as fatal. A new P-256 SEC1 key is
persisted before discovery/registration; the old hostname/directory-hashed SDK
credential helper remains only for existing test fixtures. The selected SDK
native builder owns its opaque key and Go directory/registration/nonce/KID/JWS
phases; ordinary SDK defaults and public Key remain unchanged.
A discovery-origin account409 retains the manager client with an unset native
directory; its next operation rediscovers before capturing the endpoint. Only
successful discovery is cached and recovery does not repeat registration/TOS.

Native resource success decoding now uses ordered Go raw spans, folded field
names, duplicate/null/slice reuse semantics, legacy Unicode replacement and
raw time.Time JSON grammar. Native HTTP failure metadata preserves status,
headers, partial-body bytes and assigned problem fields. Vendor provenance
contains source pins, licensing and provider/diagnostic/transport boundaries.
The API and Rustls native signer phase changes retain separate provenance,
including the optional exact-version AWS adapter. No versions were updated.

All source reviews/direct rustfmt only. No fresh build/test/client/CA/feature/
package/container/process/security/advisory evidence; all three parity gates
remain open and this implementation remains unvalidated.

- src/acme_issuer/lazy.rs: 8dea6f37b2b3653dd30ac3f6ad6e3946031893e8f2324a5aae71c2df36d665e4

## Native diagnostic/key follow-up — 2026-10-18

Finite ACME resource/directory/account type errors now retain Go root/field
wording, anonymous type names, canonical nested paths and saved-first error
ordering. Numeric-zone time failures use the whole token and selected Go error
precedence. Native caller sites apply responseOrder, initial GetAuthorization/
Accept and responseAccount prefixes while authorization polling keeps its raw
retryable decode failure. Concrete Go error/Offset metadata is not exposed.

The opaque account key now validates selected SEC1/EC PKCS#8 ASN.1 schemas,
normalizes padded/short scalars and derives the public point instead of rejecting
Go-accepted contradictory embedded points. Original RSA parsing and provider
scalar validation remain. Full source pins, notices and backend/key/error
qualifications are in vendor/instant-acme/UPSTREAM.md. The API native AWS PSS
signing-failure alert follow-up is recorded in both crypto vendor UPSTREAM.md.
Independent source peers/direct rustfmt only; no tests/builds or fresh runtime,
feature/package/container/client/security/advisory qualification. Three gates
remain open.

## Native ACME HTTP redirect integration — 2026-10-18

All production native ACME POST, nonce HEAD and directory GET requests now retain
Go URL metadata before backend URI conversion and call the additive SDK native
HTTP hook. Its selected built-in client owns a separate HTTP/HTTPS pool and Go
no-Jar redirect state machine. The existing SDK pool remains HTTPS-only. Signed
JWS URL strings are not rewritten/re-signed during redirect replay. The private
URL/IDNA source is scoped to the native SDK with no API/core/database backedge or
new dependency/resolution. Full source pins/terms and phase boundaries are in
vendor/instant-acme/UPSTREAM.md.

Source peers/direct rustfmt only. Automatic gzip negotiation/stream decode and
environment proxy/CONNECT/auth now have native source implementations, described
in the follow-up below.
Raw-byte/URI/TLS/DNS/header and lower transport/framing/pool/cancellation effects,
custom-client policies and all feature/package/container/CA/client/process
qualification remain pending. No tests/builds/probes or gate closure.

## Native ACME gzip/proxy integration — 2026-10-18

The selected native SDK transport now implements streaming gzip/DEFLATE reads,
environment HTTP/HTTPS/NO_PROXY selection, CONNECT/HTTPS proxy/SOCKS5/5h and
proxy authentication. Caller-sized JSON and certificate reads retain native
first-value/limit phases. Exact selected hyper-rustls0.27.7 is locally patched
for additive lower-connector mapping and native TLS timeout; the native pool
sets its idle timer explicitly. Existing locked tower-service0.3.3 and Tokio
features are the only added edges, with no dependency version/resolution update.
Vendor UPSTREAM.md and license notices record source hashes and boundaries.

The following connection-policy batch implements the named HTTP/2 gzip guards
and global idle/proxy key policies. Physical parser/I/O phases and backend
transport/OS diagnostics remain separate source or qualification boundaries.
Buffering, cancellation, OS/socket/resource behavior and all runtime/feature/
package/container/CA/client/process/security/advisory qualification remain open.
Source peers/direct rustfmt only; no tests/builds/probes or gate closure.

## Native byte URL and connection-policy integration — 2026-10-18

The SDK now preserves Unix proxy environment, raw Location/query/opaque URL,
Referer and password-redaction bytes with Go URL validation/error order. NO_PROXY
uses byte-preserving trimming followed by Go lowercase replacement semantics and
direct whole-domain IDNA. CONNECT finite status/header/transfer diagnostic and
folding phases were refined. The exact-version Hyper-util0.1.19 adaptation moves
gzip decisions after protocol negotiation, restores caller headers on retries,
records actual gzip injection and separates pool equality from dial destination.
HTTP forward proxies share target-independent connections; CONNECT/SOCKS keys
retain targets. Native global idle eviction selects 100 with opaque credential-
redacted identity. Default clients retain their prior pool/header behavior.

No dependency versions/resolution changed; default-off additive hooks and license
notices/source pins are in vendor/hyper-util and vendor/instant-acme UPSTREAM.md.
Source peers/direct rustfmt only. All accumulated runtime/feature/package/client/
process/import/restart/security qualification remains open; three gates unchanged.

## Native default-pool, deadline and GODEBUG integration — 2026-10-18

Default native account clients now share connections/idle limits within the
production Tokio runtime. First-poll registry selection preserves construction
outside Tokio; generation-checked cleanup removes entries on runtime shutdown.
Explicit roots/custom clients keep separate pools, and the normal SDK retains
its HTTPS-only pool. Multiple concurrent runtimes remain separate from Go's
process-wide default transport.

Native HTTP/1 expiry selects the earliest retained deadline (zero disables it).
The default-off client-idle adapters in exact selected Hyper/h2 connect native
HTTP/2 initial-flush, request reservations, atomic admission, final stream/output
completion, silent idle close and wall-clock reuse checks. The SDK explicitly
selects 90 seconds. Failed admission rearms idle state; retries preserve unsent
request ownership. Source review also repaired feature-only imports and default
flush locking. No dependency versions/resolution or public config fields changed.

Plain urlstrictcolons=0 and httplaxcontentlength=1 now follow dynamic raw-byte
GODEBUG lookup and selected parse phases. Stack-dependent bisect settings, linked
defaults, counters and reporting remain source gaps. H2 flush checkpoints, read/
write scheduling, full capacity/reset/pool ownership, cross-runtime sharing and
all accumulated runtime/default/feature/package/container/client/process/import/
restart/security qualification remain incomplete or unqualified.
Source peers/direct rustfmt only; no builds/tests/probes and three gates open.

## Native H2 capacity/cache and receive-control integration — 2026-10-18

The SDK native transport now supplies separate authorityAddr metadata and reset-PING
entropy from its already installed TLS provider. Exact selected h2/Hyper/Hyper-util
source adapters implement atomic capacity reservation, ordered multi-H2 selection,
separate physical cache ownership, closure observation, unused-failure handling,
pending-reset accounting and client-specific SETTINGS/PONG/refund write barriers.
The native-client flag also applies with zero idle TTL. General HTTP/1/default SDK
selection and wire-only API dependency boundaries remain intact.

Selected Go stdlib H2 uses the toolchain-vendored zero-option Punycode profile for
cache authority; it does not use the external x/net module's newer Unicode guard.
Source peers and direct rustfmt only. Per-request codec flight receipts, SETTINGS
ACK write-error lifetime, cross-runtime sharing and accumulated runtime/feature/
package/container/client/process/import/restart/security qualification remain
incomplete or unqualified. No dependency versions/resolution or parity gate changed.

## Native H2 writer flight integration — 2026-10-18

The selected native h2 adapter now tracks sealed request output flights and captured
cancellation reset/PING flights separately from later output. Native handshake
preface/SETTINGS/window output shares its initial flush. Cached writer failures
follow client SETTINGS/refund ignored-error and PONG fatal-error phases while
remaining visible to subsequent request/reset writers and cleanup. Native global
error/EOF cleanup preserves a received response EOS independently of the send half.

Default/server runtime selection and wire-only dependency boundaries stay intact.
Source changes/reviews and direct rustfmt only; no builds/tests/probes or dependency
resolution. Body per-read credit/flush grouping, pending-ID phases and accumulated
runtime/feature/package/client/process/import/restart/security qualification remain
incomplete or unqualified. All three replacement acceptance gates remain open.

## Native caller-sized body and admission integration — 2026-10-18

The selected native ACME client now forwards JSON/ReadAll/limited-certificate/
redirect-CopyN read demand through hidden Hyper/h2 adapters. H2 body reads capture
per-read credit/flush ownership and Close waits for unread credit and request
cleanup. Native HEAD/NoBody/MissingBody retain distinct close and gzip phases.
Nonce/status-only ACME responses close explicitly; consuming body methods await
ignored deferred close. Native initial-header admission holds no stream ID while
queued, rechecks selected non-strict capacity, and independently releases canceled
queued requests and reservations. Existing public/wire-only integration boundaries
remain preserved by selection; execution has not established them for this batch.

Source changes/reviews/direct rustfmt only; no build/test/probe or dependency
resolution update. See h2/Hyper/instant-acme UPSTREAM.md for source pins, hashes,
licenses and remaining source/runtime boundaries. Two P0 and one P2 replacement
acceptance gates remain open; this is implemented_unvalidated.

## Native TLS/server-URL startup warnings — 2026-10-18

A private server.rs warning helper restores the three selected v0.29.5
getTLSSettings scheme warnings: ACME uses the capitalized `Listening`, while
static TLS/plaintext use lowercase `listening`. Exact case-sensitive scheme
prefix checks are retained. The selected listener plan also describes Rust's
explicit dual-listener extension as TLS. The call precedes ACME HTTP01/TLS
material setup within the existing Rust startup order.

Source: pinned v0.29.5 hscontrol/app.go1043–1108, SHA-256
381958868e878b30c1f43138808b7cb3daf27c05a3db762ed3d672bf9f779a85.
Source reviews/direct rustfmt only; no startup log snapshot or process evidence.
Exact local-socket/provider/TLS failure ordering and wider logging/output
qualification remain open. No public API or dependency changes.

## Native protocol-reset and upload integration — 2026-10-18

The selected native ACME transport now uses captured exact protocol resets,
separate pipe/final-cleanup completion phases, initial-header upload gating and
Go-shaped early responses. Status above 299 stops unfinished request uploads;
2xx retains full duplex behavior. Empty-request NoBody headers wait for request
cleanup, while callback cancellation and failed delivery cancel pending uploads.
Native server application TLS EOF handling now accepts missing close_notify only
between records. Defaults and wire-only selection remain separate.

Source details, error/body representation limits, exact hashes and retained Go
licenses are recorded in h2/Hyper/rustls UPSTREAM.md. Source changes/reviews/direct
rustfmt only; no tests/builds/probes or dependency resolution. All three replacement
acceptance gates remain open and the batch is implemented_unvalidated.

## Native ACME client TLS EOF integration — 2026-10-18

The selected SDK client now opts origin and HTTPS proxy TLS into native
record-boundary EOF handling. Partial records retain `unexpected EOF`; selected
handshake EOF uses the same underlying transport classification. The direct SDK
default retains its previous policy. Rustls and HyperRustls provenance records
the default-off features, hidden connection APIs and nested TLS normalization.

Independent source reviews/direct rustfmt only; no runtime/feature/client/process
qualification. Parsed close_notify during native client handshake now maps to
EOF through an exact alert check. Full parser/alert/error representations and all
three replacement acceptance gates remain open.

## Native TLS warning implementation SHA-256 — 2026-10-18

- src/server.rs: c50c372475bad35a3e562d0674f2516aea293be0250673ab61b74a0eeb055290

## Grouped DERP, issuer and diagnostic audit changes — 2026-10-18

F12 skips/logs invalid native Go URLs before loading, parses JSON bodies even on
error HTTP statuses, uses ordered/folded/null/duplicate Go JSON assignments
(including retained Nodes slice backing), and applies selected lowercase YAML
keys/default-zero semantics. It removes invented region-ID defaults and the
upstream-absent map-key/RegionID mismatch rejection. Public narrow integers/nil
node projection, reqwest lower transport and broader YAML diagnostics remain
partial; no wide-ID sidecar or public struct change is introduced.

F13 validates activated native issuer scheme/host using the vendored SDK's Go
URL helper, preserving selected PKCE/client-ID/secret validation order without
WHATWG trimming. Deprecated core source remains unchanged. F17 adds selected
startup/minimum-version/insecure-gRPC/listener events, reporting the actual Rust
build identity, and attaches per-attempt native ACME transport/status observers.
The SDK restores observed error bodies before caller parsing. Initial account
prepare_url failures precede that observer; lower byte/error/physical lifecycle
logging equivalence remains incomplete or unqualified. API/SDK provenance records
request logger coverage and remaining timing/representation limits.

Independent source peers/direct rustfmt only; one existing DERP assertion was
source-adjusted to the accepted mismatch behavior. No tests/builds/probes or
new security/advisory evidence. All three gates remain open; original Go and
Headscale attribution/terms remain in existing notices/licenses.

Selected pinned source SHA-256:

- Headscale0.29.5 hscontrol/types/config.go: d27177817d7477525f78cd71fd98574aeb631bd6df39503858015c95768ea788
- Headscale0.29.5 hscontrol/derp/derp.go: baaa75ae8aaa504ace47003b1f792c7af9d610eda6ae5b5b2079dabe9000b4d5
- Headscale0.29.5 hscontrol/app.go: 381958868e878b30c1f43138808b7cb3daf27c05a3db762ed3d672bf9f779a85

Local grouped source SHA-256:

- headscale-cli/src/config.rs: 0b39602442cc851af06289b0ed880bb224076c03f96b4f62371e8d06ac9a51e4
- headscale-cli/src/derp_config.rs: bc35931c33a733955abb7b16effe841688da7606efb1bd07bad7fad896bf6785
- headscale-cli/src/derp_config/native_json.rs: 993d05a68e8be0c58d70b0ecffd8267e23bad1e8696864e08c8c73f6d43bafff
- headscale-cli/src/server.rs: 56293501be3e220dc9b42ade1cc434cb294a1ebafacdbc58e586e853a76398c3
- headscale-cli/src/acme_issuer.rs: 0a942caa1bc01a0b5954e976ac0809f5bfbfb49688264eb473a02d39b05e53f0

## Remaining-audit canonical DERP configuration follow-up — 2026-10-18

This supersedes the preceding native wide-ID/nil-node and lower Reqwest fetch
source limits. CLI JSON/YAML receivers build the complete new native signed
64-bit DERP model, preserving node null/slice states and selected duplicate
assignment/backing behavior. Native startup installs it before listeners; refresh
atomically replaces its owner and compatibility projection. Bootstrap/map/config
output follows that owner. The private upstream embedded-server region ID and
environment receiver are signed64; the unchanged core/runtime u16 field is only
a checked compatibility projection, not native advertised identity. Config JSON
retains the canonical ID via owner metadata without changing public debug fields.

Native URL fetches call instant_acme::go_http_get, using the existing native
proxy/redirect/gzip/TLS transport, full-body timeout/Close and actual-protocol Go
User-Agent. Status bodies are still parsed regardless of status. Unsupported raw
byte/backend/error identities and broader YAML diagnostic corners remain; null
nodes are kept on the wire and yield the selected recovered 500 status on
bootstrap/debug without a Rust panic. Nonfinite YAML floats fail
at native encode rather than startup; diagnostic snapshots may show null before
that failure without changing typed ownership. Original public compatibility
helpers retain their signatures and narrow returned views.

Selected chi logging source is v5.4.0 (as pinned by Headscale0.29.5), superseding
an earlier source-anchor message naming5.2.5; selected handler/byte/hijack semantics
are unchanged. Source peers/direct rustfmt only, no execution or gate closure.

Selected pinned source SHA-256:

- Headscale0.29.5 hscontrol/derp/derp.go: baaa75ae8aaa504ace47003b1f792c7af9d610eda6ae5b5b2079dabe9000b4d5
- chi5.4.0 middleware/logger.go: 40e7b7b01eb0363aad9930d3764880e3cf6f1f8aed6ad3fd918866ec34602729
- chi5.4.0 middleware/wrap_writer.go: 7b6ed24d3d5bfd362e00851d117e74273b02597a1d9e9eb243cbf7aae22597c8

Final parallel follow-up local source SHA-256 — 2026-10-18:

- headscale-cli/src/config.rs: 0c467c7940c74318dff38c8e00b2729a83ecef7ecf17402dd19fe6b6dfe6cadf
- headscale-cli/src/derp_config.rs: 372a9c2cc6f5a0f5b848beeccf40fee210aa1f3ad73c5e19a77a2557094210d8
- headscale-cli/src/derp_config/native_json.rs: c7c6539128bbc62415432ae085d69abd45a99f90b94b25fbe66803b4a3f95ffe
- headscale-cli/src/server.rs: 4661e7e42c38a5f15c50d4d9107be5b1379efdc6b3c8e394be6c41f238146249

## Finite native DERP YAML and JSON diagnostics — 2026-10-18

The private DERP loader now uses an index-only arena over the existing granit
parser, retaining tags/styles/aliases and mapping order until finite typed
assignment. It handles selected yaml.v3 scalar/bool/integer/float assignment,
null keys/pointers/slices, duplicate fields, merges, UTF16/BOM input, YAML1.1
directives and typed alias-expansion accounting before canonical allocation.
The shared CLI YAML facade and dependency versions are unchanged.
JSON errors retain selected Go target/field/literal text and value-before-map-key
first-error order. Original Canonical yaml.v3 terms are retained in
LICENSE-YAML-V3 and NOTICE-YAML-V3; original Go JSON terms remain retained.

This finite adaptation does not replace Go libyaml syntax/scanning. Detailed
YAML type-error aggregation/line wording, invalid binary-string projection,
non-x86/AArch64 float-to-int behavior and backend errors remain narrower or
unqualified. Source peers/direct rustfmt only; no tests/builds/Cargo/validators/
probes, fixture capture or fresh advisory/security qualification.

Selected upstream SHA-256:

- gopkg.in/yaml.v3 v3.0.1 decode.go: a66a783addb0f9cdb45f9e87deb0e51c2aca6bf81e46d4e822136993ba81505d
- gopkg.in/yaml.v3 v3.0.1 resolve.go: 69b6069012fef0a518e379222007f6ea7622cb1c235a35b1355bb5641ab16d26
- gopkg.in/yaml.v3 v3.0.1 parserc.go: 4ca0ff93c79c32592106e3c44a7a6dedd41f6d55d88809aaa3b28fd675b0aa82
- gopkg.in/yaml.v3 v3.0.1 LICENSE: d18f6323b71b0b768bb5e9616e36da390fbd39369a81807cca352de4e4e6aa0b
- granit-parser2.0 parser.rs: 61fc97384585ded36ccd18c7af775c7ba0bffd2b388337d992b3751a2b4ead2b
- Go1.26.9 encoding/json/decode.go: a91535f18f9a2c8380448b1c84c4c2017dbe3d530a10faf8babf03494042da48

Local source SHA-256 for this follow-up:

- headscale-cli/src/derp_config.rs: 670fe809718617379aee844c49db566b709bce3a373dd77cde1c6c7e693ce115
- headscale-cli/src/derp_config/native_json.rs: bc1ca15dbfd1bf029d7b91250b2d816b764cc497f2e72f0f80dacd85a7b93a43
- headscale-cli/src/derp_config/native_yaml.rs: 583ee599fd8695a1f24ac82d59ecff41f45a44b3150eb48ba988072bd04a9135
- headscale-cli/LICENSE-YAML-V3: d18f6323b71b0b768bb5e9616e36da390fbd39369a81807cca352de4e4e6aa0b
- headscale-cli/NOTICE-YAML-V3: a9a7354f3dffefb89aecd773d1c89ee81535a03e19952d43542cc31e2857504f

Final bounded source peer passed the private YAML typed assignments, merge-key
identity and alias-budget traversal on the recorded source hash. No actionable
source issue was found in that review; parser/platform/diagnostic and runtime
qualification boundaries above remain. No execution was performed.

## Finite DERP YAML diagnostic continuation — 2026-10-18

The existing iterative typed alias-budget traversal now accumulates selected
yaml.v3 TypeError messages with source lines, tags, finite reflect type names,
raw duplicate-pair ordering and converted known-field duplicates. It continues
siblings and merge members in decoder order; later fatal tag/binary/alias/merge
errors supersede saved errors. Canonical assignment and Regions-only merge
remain unchanged. Final source peer corrected explicit-tag << resolve wording.

This supersedes the named missing finite type-error aggregation. Granit versus
Go scanner/parser syntax/property-span diagnostics, Go's mid-rune byte-preview
text, binary-invalid-UTF8 model normalization, complex generic merge-key fatal
formatting and other-platform casts remain qualified. Source pins remain
gopkg.in/yaml.v3 v3.0.1 decode.go/resolve.go as above. Direct rustfmt and source
reviews only; no tests/builds/validators.

Local source SHA-256:

- headscale-cli/src/derp_config/native_yaml.rs: cf0ea11880ad1d5a4dd2dcba921acd4ceab5699ad2d766756d2721cf99eae7aa

## Authorized compatible dependency upgrades — 2026-10-18

The user authorized dependency versions/resolution with upgrade deps. Root
Cargo.lock now binds the locally patched http1.5.0, h2 0.4.20, Hyper1.12.0,
Hyper-util0.1.21 and Hyper-rustls0.27.10, preserving native profile features.
The explicit CLI pins advance h2/http-body/regex/libc/native-cert dependencies
within their compatible series. Socket2 0.6.5 permits Tokio1.53.3. No public
CLI signatures, deprecated core source or migration SQL/checksum changed.

The two standalone wire-only harness lockfiles are refreshed separately; their
registry transports are not the root native CLI vendor graph. Exact before/after
lock hashes/deltas, source rebases and changed dependency behavior are recorded
in docs/headscale-dependency-upgrade-2026-10-18.json. Existing native private Go
source pins remain selected. Cargo update/fetch/source review/direct rustfmt
only; no builds/tests/lints/process/database/CA/advisory qualification.

Current manifest SHA-256: c9c356a57ea58737e0eca8cc3e430997d8e8d7e693ce5a61dd3f6a0f63f83528
