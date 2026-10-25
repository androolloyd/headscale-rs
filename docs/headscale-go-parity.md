# Headscale-go Parity Ledger

## Evidence gaps closed — 2026-10-25

`/health` now fails with the database as headscale-go's does, the differential
harness reads the production packet-filter compiler (104 scenarios match, every
node compared), and the Postgres stock-client rows were run for the first time:
the production server could not start on Postgres until a vendored-driver
defect was fixed; 105 of 121 rows now pass and the 16 failures are classified
(15 fail identically against Go). See "Evidence-gap pass — 2026-10-25" in
[the remaining-work audit](headscale-v0295-remaining-audit-2026-10-18.md).

## First build and test of the frozen tree — 2026-10-24

The frozen tree was built, tested and compared against the real headscale-go
v0.29.5 binary for the first time. Workspace tests, clippy (nightly and stable),
fmt, the 104-scenario differential harness and 33 stock-client rows pass; the
seven defects that were real regressions or pre-existing gaps are fixed, and the
residual differences are listed. Details and the evidence boundary are in the
"Execution pass — 2026-10-24" section of
[the remaining-work audit](headscale-v0295-remaining-audit-2026-10-18.md). The
"no tests/builds ran" statements in the entries below describe their own dates.

## Comprehensive remaining-work audit — 2026-10-18

Implementation is frozen for the requested audit before further fixes.
[The audit](headscale-v0295-remaining-audit-2026-10-18.md) inventories 17
source-confirmed production differences in 10 implementation batches, two
CI/evidence changes and one conditional optional-admin security issue. Its
machine-readable companion includes source anchors, scope decisions, remaining
qualification and a frozen source fingerprint. Findings are distinct from patch
counts and from the three existing acceptance gates. No gate was closed and no
tests/builds/probes/validators/advisory scans ran. Use this inventory to batch the
next work instead of rediscovering append-only historical residuals one at a time.

## Native client TLS EOF update — 2026-10-18

Selected native ACME origin and HTTPS proxy TLS now accept transport EOF between
records after plaintext drains. Partial records retain `unexpected EOF`.
Record-boundary detection accounts for retained complete records containing a
partial handshake message. A nested transport UnexpectedEof is classified using
the current TLS layer's own record boundary. This also corrects the native server
boundary calculation described below.

A connection observer lets the selected HyperRustls adapter distinguish boundary
and partial transport EOF during an unfinished TokioRustls handshake. The adapter
maps observed UnexpectedEof errors and an actual close_notify carrying the exact
inner Rustls alert and its observer marker. Other protocol/I/O errors and timeout
retain their existing handling. The new Rustls feature is default-off and
forwarded through the existing native connector feature; ordinary SDK selection
remains unchanged.

Independent source reviews/direct rustfmt only. No tests/builds/probes or new
executable evidence. Rust ErrorKind versus Go sentinel identity, full TLS
decoder/alert/error phases, physical I/O and accumulated runtime/feature/backend/
client/process/database/security
qualification remain open. All three acceptance gates remain open and this
batch remains implemented_unvalidated.

## Native reset and early-response update — 2026-10-18

Selected native clients now retain exact local protocol reset flights without
cancellation PING accounting, ignore codec stream errors for unknown streams, and
remove the generic local-error reset budget. Ordinary request-body errors use
CANCEL/PING; typed local reset errors preserve their code, and peer-origin errors
abort the current request without a reset echo. Pipe errors wait for the reset
flush; response errors and Close wait for final cleanup. Buffered positive data,
received EOF and sticky read errors remain separate from that error gating.

Responses above 299 stop unfinished uploads and use NO_ERROR cleanup after peer
EOS. 2xx keeps full duplex behavior. Native body polling waits for the initial
header flush while response polling proceeds independently. Empty-request NoBody
responses await cleanup before callback delivery; MissingBody remains distinct.
Pending response cancellation and rejected callback handoff cancel the upload.
Source review also repaired an admission mutex re-entry and native abort wakeups.

The native server TLS EOF and CLI warning changes are recorded in the next
section. These are source implementations with independent source reviews and
direct rustfmt only. No build, test, runtime, fixture or parity evidence was added.
Broader parser/error classification, arbitrary custom-body error objects and Drop
versus Go Close, request-context/callback timing, queued/unstarted EOS, physical
buffering/scheduling/resources and accumulated feature/client/process/database/
security qualification remain incomplete or unqualified. Two P0 and one P2 gates
remain open; this batch is implemented_unvalidated.

## Native server EOF and startup warning update — 2026-10-18

Explicit native server Rustls readers now accept a missing close_notify only at
a TLS record boundary after buffered plaintext drains. Partial-record EOF remains
UnexpectedEof with the native Go text. Default/client readers and handshake
complete_io handling retain their previous policy; this is an application-reader
source change, not full TLS-close qualification.

Native CLI startup now emits the three pinned getTLSSettings server-URL scheme
warnings with exact prefix checks and capitalization. Rust's explicit dual-listener
extension is described using its selected TLS listener. Broader provider/socket/TLS
startup failure order and rendered logging remain unqualified.

Independent source reviews/direct rustfmt only. No builds, tests, process probes,
fixture capture, dependency resolution or new executable evidence. The two P0 and
one P2 replacement gates remain open; the batch is implemented_unvalidated.

## Native caller-sized bodies and delayed admission — 2026-10-18

Selected native HTTP/2 requests now wait for initial-header ownership without a
stream ID. Admission consumes the request's reservation and rechecks capacity
before allocating the real ID. The selected Go default uses non-strict concurrency:
a capacity race returns the original unsent request for retry. Header ownership
continues through the initial header flush; response handles are available earlier.
Queued Hyper requests register cancellation independently, including while another
request's header writer is blocked.

Native response reads use the caller's requested byte count, drain only currently
available data, and capture each connection/stream credit pair in one writer flight.
Read completion waits for that flight; refund write errors are ignored. Declared
length overflow is truncated at read time with a sticky error and no credit refund
for the consumed bytes. Short EOF is sticky UnexpectedEOF. Close discards unread
bytes, returns connection credit and waits for request cleanup. HEAD, initial-EOS
NoBody and MissingBody preserve their separate read/close behavior, including no
implicit cancellation when their public response handle is dropped.

The SDK uses separate read demand for JSON decoding, Go1.26.9 ReadAll/certificate
limits and redirect CopyN draining. Gzip compressed reads follow the selected
bufio demand; special empty/missing bodies skip gzip decoding and header removal.
Nonce-only and status-only responses explicitly close their native body. Hidden
additive adapters preserve existing public signatures and default method bodies.

Source changes/reviews and direct rustfmt only. The earlier named per-read credit
and early stream-ID source gaps are superseded by these implementations. Actual
Rust allocation, lower HTTP/1 framing/draining, general malformed/protocol-reset/
decoder/transport/TLS-close representations and phases, cross-runtime default-pool
sharing, physical I/O, scheduling, cancellation/resource behavior and accumulated
feature/default/wire-only/package/container/CA/client/process/database/security
qualification remain incomplete or unqualified. No executable evidence was added;
all three gates remain open and the batch remains `implemented_unvalidated`.

## Native H2 writer ownership update — 2026-10-18

Native H2 now uses sealed writer flights with independent pending/flushed/failed
receipts. A completed request flight remains observable when later output blocks.
Captured cancellation reset/PING pairs retain their own writer ownership through
generic stream queue cleanup. Header-start visibility is recorded before writing,
and cancellation before header start suppresses the unsent header/reset output.
Native startup buffers the preface, initial SETTINGS and window update together.

The first writer I/O failure is cached. SETTINGS ACK and receive-refund failures
allow the reader to continue; PONG failures remain fatal. Later real request/reset
writes and request cleanup still observe the cached failure. Native connection
cleanup preserves response EOS already received while failing an unfinished sender.
Default/server paths retain their previous selection and batching.

Remaining source boundaries include synchronous per-read body credit/refund groups,
pending-open stream-ID allocation phases and broader malformed/body/reset/decoder/
transport/TLS behavior. Runtime, feature, stock-client, Postgres/restart and upgrade
qualification remain open. No builds/tests/probes or dependency resolution ran;
all three acceptance gates remain open and this is `implemented_unvalidated`.

## Native H2 connection and receive-control update — 2026-10-18

Native HTTP/2 now has an ordered connection cache separate from the general idle
wrapper limit. Atomic reservations select the first available sender, keep healthy
saturated connections and permit another connection to the same authority. Dial
ownership handles cancellation, and stable closure observers remove dead entries
while retaining Go's bounded unused failure. Native client selection is independent
of a nonzero idle timeout. Source review repaired closure notification, reset races
and non-reusable final-request cleanup; no acceptance gates close from this work.

An independent native client guard requires SETTINGS as the first decoded frame,
including unknown-frame handling, without selecting server-only validation.
Client SETTINGS, PONG and DATA-refund handling now waits for the prior writer,
flushes the required control before further reads, and defers terminal DATA EOF
until its required refund is flushed. Ordinary read progress can continue behind
blocked ordinary output. Reset/PING capacity accounting and the SDK's existing TLS
random provider are connected through the selected h2/Hyper/Hyper-util adapters.
H2 authority identity uses the selected toolchain's zero-option Punycode profile,
separately from the Lookup profile used for dialing.

Independent reset-flight ownership, per-request output-flight receipts/internal
codec batching, SETTINGS ACK write-error
lifetime, process-wide sharing across runtimes, malformed/body/decoder/transport/TLS
phases and broader runtime qualification remain incomplete or unqualified. Builds,
tests, probes, fixture recapture and dependency resolution remain paused. All three
replacement gates stay open and the batch remains `implemented_unvalidated`.

## Native ACME/TLS implementation update — 2026-10-18

Three replacement gates remain open: v0.29.1–v0.29.5 production release
qualification (P0), broader Postgres process mutation/restart qualification
(P0), and CLI output/error residuals (P2). This batch remains
`implemented_unvalidated`; source reviews do not close these gates.

Native TLS now retains the selected signer through TLS 1.3 CertificateVerify,
selects actual peer offers in order, and preserves partial flights before native
signing failures. AWS TLS 1.2 ECDSA supports the selected SHA-256/384/512
independently of curve through an optional exact-version aws-lc-rs1.18.2 source
adapter. RSA offer filtering follows Go's modulus-byte minima. Default runtime
paths retain existing provider policy; wire-only APIs gain no dependency backedge.

Native ACME uses the Go shared `acme_account+key` cache with legacy-key fallback
only on a cache miss, fatal cached-key/read/write failures, and new-key persistence
before network registration. Private account signing supports canonical RSA and
P-256/P-384/P-521 EC keys on the selected AWS backend. Directory/registration,
account-ID lookup, nonce HEAD/pool, retry signing and JSON escaping have native
source implementations, including discovery-origin409 recovery with success-only
directory caching. Response failures retain partial bodies and problem
fields. Finite successful-resource decoding follows Go field folding, duplicates,
nulls, slice backing reuse, malformed Unicode and raw quoted time assignment.

Remaining source boundaries include exact JSON/type/time diagnostic wording,
provider accepted-DER/key ranges, raw header/URI/transport representations,
TLS decoder/version/group/HRR/session differences and uncommon signing alerts.
All accumulated runtime, feature/backend, package/container, stock-client,
CA/process, migration/import/restart/rollback/cancellation/concurrency and
security/dependency/advisory qualification remains pending. No builds, tests,
validators, probes, fixture recapture or dependency resolution ran in this batch.
Vendor UPSTREAM.md files retain exact source pins and licensing scope.

A source follow-up implements finite resource/directory/account type-error text,
RFC3339 numeric-zone diagnostic precedence and the actual Go caller prefixes.
EC account keys now follow Go's SEC1/PKCS#8 schema, curve override/fallback and
scalar normalization before provider validation, including ignoring a valid
embedded public point. Native AWS TLS1.3 RSA-PSS actual signing failures use
Go's exact floor-modulus-bit alert classification. These changes have source
peer reviews, with no executable qualification or acceptance-gate closure.

Native ACME now has a separate HTTP/HTTPS transport with Go redirect method/body,
header/auth/Referer and URL-resolution source behavior. SDK requests retain their
HTTPS-only path. The private URL helper reuses the pinned Go Unicode15 profile
without an API/core/database backedge. Automatic gzip negotiation and incremental
DEFLATE/gzip decoding now have source implementations, with caller-sized JSON,
certificate and redirect reads. Environment proxy selection, NO_PROXY rules,
CONNECT, HTTPS proxy and SOCKS5/5h authentication are also implemented in source.
An exact-version hyper-rustls0.27.7 patch adds native lower-connector mapping and
TLS timeout hooks; the native pool now has an explicit idle timer. Only existing
locked packages/features were added; no dependency version/resolution update ran.
Independent source peers reviewed these changes, including CIDR family matching.

A further source batch fixes negotiated HTTP/2 explicit-empty gzip guards through
an exact-version Hyper-util0.1.19 adapter. Native requests retain original headers
across internal retries and decode only when the actual attempt requested gzip.
Go-shaped connection keys support cross-origin HTTP forward-proxy reuse while
keeping CONNECT/SOCKS targets separate; native global idle eviction selects 100.
Opaque pool identities redact proxy credentials in debug output. Unix proxy env,
Location, Referer and password-redaction paths now retain bytes through parsing;
NO_PROXY uses Go whitespace/lowercase phases and direct whole-domain IDNA.
CONNECT finite parsing/error order and quoted diagnostic values were refined.

Known source boundaries still include physical HTTP parser/I/O error phases,
backend URI/IP/DNS/TLS/OS representations, non-Unix environment behavior and
optional Go GODEBUG overrides. Lower buffering, physical HTTP/2 socket lifetimes,
cancellation, platform behavior and all accumulated runtime qualification remain
open. This batch has not been built
or tested; source review establishes no new runtime or replacement-parity claim.

Native default accounts now share connections and the idle cap within the
production Tokio runtime, with a generation-checked shutdown guard. Explicit
root/custom clients stay isolated; simultaneous runtimes remain separate from
Go's process-wide default transport. Plain urlstrictcolons/httplaxcontentlength
GODEBUG settings now have source implementations with byte-preserving dynamic
lookup. Stack-selective bisect settings, linked defaults and debug reporting
remain source gaps. Native HTTP/1 pool expiry now uses the earliest retained
connection deadline instead of periodic scans, with zero disabling expiry.
These changes passed bounded source reviews; no executable evidence was added.
Native HTTP/2 idle timers now track queued reservations, admitted streams and
terminal output pending a successful flush. A separate wall-clock reuse check
matches the selected Go last-idle phases. Source reviews repaired failed-admission
timer rearming, closed-connection readiness, a client-only import guard and an
extra default-path flush mutex. Remaining source gaps include conservative flush
checkpoints, blocked-write/read scheduling, complete H2 capacity/pending-reset
pool selection, closed-entry cleanup and process-wide cross-runtime ownership.
No replacement gate is closed by these source changes.

Differential baseline: `github.com/juanfont/headscale` at `v0.29.5`, pinned by
`tools/parity/headscale-go/go.mod` at commit
`0f7d1e536bed9f01dd7161f7637af19bb0908335`. The 106 checked-in
policy/wire scenarios compare against this release, including its unknown-user
group via-route behavior and exit steering under an unrelated ACL. This is a
bounded differential slice, not complete release or stock-client parity.

Fresh file-backed Rust SQLite databases and imported current v0.29.5 Go
databases now keep the exact pinned Go schema, 19 migration IDs, and v0.29.5
version row in the primary file. Rust-only accounting, resource, mesh, and
session tables live in a separate `.rust-aux.sqlite` file attached to every
Rust connection. The primary file has Go's seven non-internal tables, seven
named indexes, and no triggers. A two-stock-client Go→Rust→Go process smoke
directly restarted pinned Go on the Rust-mutated primary SQLite database and
read Rust-created users, preauth/API keys, nodes, and an approved subnet route.
The sidecar must be backed up with the primary file to preserve Rust-only data.

The v0.29.4 OIDC confirmation path now uses Go's 303 callback redirect to a
separate, reloadable `GET /register/confirm/{auth_id}` page. The callback sets
a path-scoped, `SameSite=Lax` CSRF cookie; GET and POST require the cookie, and
the page cannot be read after confirmation. The redirect and cookie path keep
a reverse proxy's URL prefix. The v0.29.4 regular-traffic metrics fix now
records public and inner Noise HTTP/2 requests in Go-compatible
`http_requests_total` and `http_request_duration_seconds` families, while
skipping `OPTIONS`. Paired pinned-Go/Rust OIDC process runs verified the
redirect, safe reload, cookie-less 403, and `/health`, `/ts2021`, and
`/machine/register` metrics in SQLite native Noise and Postgres WSS modes:
`target/real-client/noise-oidc-confirm-reload-metrics-sqlite-1792261000` and
`target/real-client/noise-oidc-confirm-reload-metrics-pg-wss-1792261300`.
Those runs cover the named flows; exact response timing and all HTTP route
metrics remain outside this paired check.
The local ACME directory fixture now returns `badNonce` once during order
creation and then a fresh replay nonce. The HTTP-01 issuer completes issuance
and caches a valid certificate through the configured `instant-acme` retry
path, covering the v0.29.4 renewal regression without an external CA.
The v0.29.4 policy metadata fix now strips `#`-prefixed members throughout
the policy schema while preserving opaque grant `app` payloads. The
`policy-v0294-metadata-fields` differential scenario matches pinned Go, and
paired production CLI `policy check`/`set`/`get` plus restart runs passed on
SQLite and Postgres in `target/real-client/policy-metadata-1792230453-44368`
and `target/real-client/policy-metadata-1792230479-44502`. Both implementations
also reject a same-document unprefixed unknown field. These rows cover the
named metadata behavior and stored-policy restart; live stock-client map
churn from this policy remains outside the check.

The v0.29.3 tagged-device reauthentication fix now distinguishes a repeat
registration with the same tagged preauth key from one using a new key.
The same key preserves an admin tag override; a different tagged key applies
its new tags without changing the node ID or IP. Tagged nodes retain an
operator-scheduled future expiry and clear only an already-expired timestamp.
Tagged registration also stores null user ownership in the Go-shaped
`nodes` row and safely resolves the existing machine across node-key
rotation. Paired pinned-Go/Rust TS2021 process runs on SQLite and Postgres
assert the three tag states, rotated node keys, stable row identity,
null ownership, and auth-key ID transition:
`target/real-client/noise-tagged-retag-db-sqlite-1792265900` and
`target/real-client/noise-tagged-retag-db-postgres-1792266000`.
Stock Tailscale tagged-preauth registration also passed on Rust SQLite and
Postgres after this change. The Postgres run at
`target/real-client/postgres-tagged-preauth-retag-current-1792225685`
observed the synthetic tagged-device identity in CLI output, a live self
netmap, and offline `lastSeen` lifecycle after disconnect. The paired TS2021
run above is the evidence for same-machine key rotation and retagging.
The paired TS2021 harness now also rotates that same machine through two
interactive CLI approvals: first it re-advertises its tag while preserving
null user ownership, then it requests no tags and returns to Alice. Both
implementations retain the node ID and IP, and the final database row clears
the tagged preauth-key reference. SQLite and Postgres runs passed at
`target/real-client/noise-tagged-shape-sqlite-1792227292` and
`target/real-client/noise-tagged-shape-postgres-1792227312`.
The same comparison exposed empty repeated fields in Rust CLI JSON that Go
omits; Rust's node output now follows the Go omission shape for empty node,
user, and preauth-key fields. A missing client DiscoKey now stores and emits
Go's zero DiscoKey on both databases, and tagged-device CLI users carry Go's
zero creation timestamp. The paired harness checks these fields in its
database rows and CLI JSON. Rust now preserves fractional node, user, and
preauth-key timestamps through the database and admin projection. The later
seven-stage SQLite and Postgres corpus has no Go-only or Rust-only CLI node
JSON paths, including scheduled fractional expiry before and after restart.
Postgres rounds the stored expiry to microseconds under both implementations.
Broader CLI output parity remains open.

At startup, an existing Rust-managed file first completes any pending SQLx
migrations, then receives a timestamped `.pre-v0295-*.sqlite` backup. Rust
copies the six auxiliary tables into the sidecar in one transaction and
rebuilds the primary file in another, preserving shared rows and allocated
SQLite IDs. A seeded beta.2 database with rows in all six auxiliary tables
passed production Rust startup and direct pinned-Go restart on the same file.
The original primary backup remains available for recovery. This conversion
also runs on the first Rust startup for supported older Go imports. A real
v0.28.0 Go database with two stock-client nodes and one approved subnet route
passed that single-start Rust upgrade and a direct pinned v0.29.5 Go restart;
both Rust and Go read the route approval. Wider historical upgrade
states remain to be qualified. A TLS stock-client handoff now keeps two
Tailscale clients running while the server changes from Go v0.28.0 to Rust
and then to pinned Go v0.29.5 on the same SQLite file, control URL, certificate,
and Noise private key. Rust and Go each rename a peer and the observer receives
both live map changes; client container identities and Tailscale IPs are stable,
and the approved subnet route remains present after the Go restart. The same
handoff now creates an API key under Go v0.28.0, authenticates a live gateway
request with it under all three servers, and checks that its CLI prefix and
stored hash survive both switches. Run the
reproducible row with:

```bash
tools/real-client/sqlite-live-handoff-v028-rust-v0295-smoke.sh
```

The handoff also compares
the `/key?v=138` response at each phase. Rust now reads the configured Go
`privkey:` Noise key, preserves an existing raw Rust key when the configured
file is absent, and emits Go's `legacyPublicKey`/`publicKey` response fields.
The reverse fresh-database check in
`tools/real-client/sqlite-v0295-fresh-rust-to-go-smoke.sh` directly starts
pinned Go v0.29.5 on a Rust-created SQLite primary file using the
Rust-generated Noise private key. Both servers return the same `/key?v=138`
JSON, and Go reads the Rust-created user, preauth key, and API key rows.
The production Postgres process suite also passes all 16 mutation and restart
cases with a local database. Debug node IDs now use persisted database IDs;
the gateway's synthetic debug-create response uses ID zero until registration,
matching pinned Go. These checks do not cover every historical upgrade state
or all stock-client Postgres churn combinations.
Fresh Postgres databases now receive the pinned `v0.29.5` version stamp. The
`tools/real-client/postgres-v0295-fresh-rust-to-go-smoke.sh` process row creates
the user, preauth/API keys, a node, and an approved subnet route under Rust,
then directly starts pinned Go v0.29.5 on that database and returns to Rust.
Both implementations read the rows and serve the same Noise public key. Pinned
Go now also renames the user and node and creates an API key before Rust
reopens the database. Rust sees both renames and the approved route, while
gateway requests authenticate with the original Rust key and the new Go key
across the process switches. The
legacy SQLite migration path keeps its beta.2 intermediate stamp until the
file is rebuilt into the exact v0.29.5 Go primary schema.
The paired Postgres `postgres-user-node-lifecycle-restart` stock-client row now
pins Go v0.29.5 and checks the surviving observer's live peer map. Before the
mutations it sees two peers. After one peer expires and another is deleted,
both Go and Rust retain the expired peer as offline and remove the deleted
peer; the observer's ID and Tailscale IP remain fixed before and after server
restart. The Rust row supplies the same DERP map fixture as the Go row so the
clients reach their normal Running state.
The paired production Postgres `postgres-authkey-relogin-same-user` row now
registers two stock Tailscale clients against pinned Go v0.29.5 and Rust. After
same-user auth-key logout/relogin, it checks the target's node key rotated,
its node ID and IP stayed fixed, and the other client's live netmap received
the new key. Both implementations passed this observer-map rekey check.
The Rust row uses the same static DERP map fixture as the Go row.
The paired Postgres `postgres-ssh-oidc-revocation` row now approves an OIDC
Tailscale SSH check, proves a cached `checkPeriod` replay succeeds, removes
the SSH rule through live database policy, waits for the target client to
receive an empty SSH policy in its netmap, and proves another SSH attempt is
denied without a new auth URL. Pinned Go v0.29.5 and Rust both returned SSH
status 255 after revocation.
That row also reopens the original mock IdP authorization URL to obtain a
fresh code with the consumed callback state and original state/nonce cookies.
Both pinned Go and Rust return HTTP 410, which exercises the single-use
state check independently of authorization-code reuse.
The paired production Postgres `postgres-policy-peer-removal-restart` row
starts with two cross-user peers visible, then changes the live database
policy to self-only ACLs. Each stock client loses its previously visible peer
without changing its own node ID or Tailscale IP, and the peer remains absent
after server restart. Pinned Go v0.29.5 and Rust both passed.
The historical current-head audit below records the earlier beta.2 baseline
and is not an audit of every intervening release change.
The CLI now defers OIDC issuer/client credential validation until `configtest`
or `serve`, matching pinned Go v0.29.5 command timing: `version` still works
with those invalid startup settings. Process snapshots pin the exact
human/JSON/JSON-line/YAML `configtest` errors and `serve` errors for an invalid
issuer, missing client ID, and missing client secret. Environment value parsing
and secret-file resolution remain load-time operations.

`tools/real-client/migrate-legacy-rust-v0295-sqlite.py SOURCE.sqlite NEW_DIR`
provides a guarded offline migration for a fully migrated beta.2 Rust file.
It preserves all five Go tables and six Rust-only tables in a new primary and
sidecar pair, including row values and SQLite AUTOINCREMENT positions. It
rejects unknown tables/views/triggers/indexes, incomplete SQLx history, and
existing output paths. A seeded legacy snapshot with rows in each Rust-only table
passed the converter, production Rust reopening, and direct pinned-Go startup
on the new primary file. The original source remains intact; operators must
switch their database path to `NEW_DIR/headscale.sqlite` and keep its
`.rust-aux.sqlite` companion. This offline path remains available separately
from the automatic in-place conversion and does not qualify every historical
upgrade state.

The replacement-direction cross-start on a copy of a live v0.29.5 Go SQLite
database (one user, one stock-client node) found the upstream `SCHEMA_INIT`
migration marker missing from the Rust allowlist. After accepting that marker,
the Rust server started, passed `/health`, returned the imported user through
the CLI, and retained both user and node rows. This is one process-level import
case, not complete upgrade or drop-in qualification.
`tools/real-client/sqlite-v0295-go-to-rust-import-smoke.sh` makes this
replacement-direction case reproducible: it creates a pinned Go database with
two stock clients and an approved subnet route, imports it in the production
Rust server, reads user/node/preauth-key ownership and route state through the
CLI, creates a user plus preauth/API keys, checks the rows and API-key
authentication after Rust restart, then directly starts pinned Go on the same
primary SQLite file. It also verifies a separately exported Go-schema copy.
The matching
`tools/real-client/postgres-v0295-go-to-rust-import-smoke.sh` now passes on a
temporary Postgres cluster. It exports the pinned Go stock-client database,
restores an isolated copy, and runs the same production Rust import, admin
mutation, and restart checks. The Postgres row also renames the imported user
and node, creates a preauth key and an API key, then verifies their ownership
and API-key authentication after restart. The imported Postgres state now
includes two stock-client nodes advertising a subnet route, with one node
approved; Rust preserves those route fields across restart. After Rust stops,
the smoke directly starts pinned Go on the same Postgres database and reads
the two users, two nodes, keys, and approved route through Go's CLI. This is a
bounded bidirectional Postgres process case; it does not establish a general
Postgres migration or the full release behavior matrix.

For an operator rollback artifact from a legacy Rust database,
`tools/real-client/export-go-v0295-sqlite.py SOURCE.sqlite NEW.sqlite`
copies the five shared data tables into the exact pinned v0.29.5 Go SQLite
schema, records its migration history, and leaves the Rust source untouched.
It rejects an unsupported source version, an existing output, a changed schema fixture,
or populated Rust-only tables that Go cannot represent. Run
`tools/real-client/sqlite-v0295-rust-to-go-export-smoke.sh SOURCE.sqlite`
to compare all shared rows and start pinned Go on the exported copy, then
read users, nodes, keys, and approved routes through Go's CLI. The roundtrip
smoke passed with two stock-client nodes, one approved subnet route, and
Rust-created user/preauth/API-key rows. This is a guarded
one-way SQLite export for legacy databases. The Postgres smoke above demonstrates a selected direct
reverse restart, but does not qualify arbitrary Postgres state.

The paired `node-key-expiry-clear` and `postgres-node-key-expiry-clear`
stock-client rows now set a future node key expiry and then disable it through
the production CLI. A connected peer's netmap first contains the timestamp
and then clears it against both Rust and pinned Go v0.29.5. Rust emits a full
peer node when clearing `KeyExpiry`, since an incremental `PeerChange` omits
an absent timestamp and cannot clear the client's value. This qualifies one
map-stream lifecycle edge; the wider release and database upgrade gates remain
open.

The v0.29.5 release work in this branch adds the upstream null-tags owner
recovery and tagged-node expiry migrations to SQLite and Postgres, preserves
untagged owners before the older Rust migration runs, rejects v0.29.5 stamps
without the two release migration IDs, and imports the two upstream SQLite
migration fixtures. It also resolves `users rename --name` through the matched
user ID, lowercases operator DNS record names on the client wire, and consumes
OIDC callback state once while deriving state/nonce cookie security from the
configured URL or direct TLS. Config validation also rejects invalid issuers
and missing OIDC credentials when an issuer activates OIDC. These are bounded
fixes. SSH check actions now match a rule for the requested login user,
deny a stale check after rule removal, recheck policy after an auth verdict,
and consume each verdict once. Map responses send an explicit empty SSH
policy when rules disappear so clients discard previous SSH access. The P0 release and
production Postgres qualification rows remain open.
The register follow-up now verifies the completed node's machine key against
the Noise machine key before returning its owner identity. A regression uses
two pending pollers on the same auth ID: the matching machine receives the
owner, while a different machine receives only the upstream mismatch error.
When authorization and cancellation become ready together, the completed
registration takes precedence. Pinned Go's two corresponding `hscontrol`
tests and the Rust regression pass. The paired production
`tools/real-client/noise-followup-machine-binding-smoke.sh` row now opens real
TS2021/Noise sessions against Rust and pinned Go v0.29.5, approves separate
pending registrations through each CLI, and checks that the original machine
receives the owner while a foreign Noise machine using the same node key and
follow-up URL receives only the machine-key mismatch error. The row exposed a
Rust plain-HTTP `/ts2021` path that waited for a pipelined initiation even
when current clients sent it in `X-Tailscale-Handshake`; that path now decodes
the header as the raw TLS listener already did. The process row uses separate
registrations so it does not claim a deterministic winner among concurrent
pollers sharing one Go auth verdict.
The same paired process row now checks the successful register response's
owner creation time, owner login provider, and explicit null
`NodeKeySignature`. Rust obtains provider and creation time from the user row
through persistent node hydration and through the gRPC CLI approval path;
the registration method no longer masquerades as the login provider. The
paired row passed in
`target/real-client/noise-followup-owner-metadata-1792224300`.
OIDC completion now also refreshes the cached and live wire record from the
persisted owner in SQLite and Postgres, so the first successful follow-up can
include the owner's creation time and provider without waiting for a server
restart. A SQLite regression checks the immediate cached and live records.
The paired SQLite OIDC row exposed a lifetime mismatch: pinned Go v0.29.5
keeps a new OIDC node's expiry unset when token expiry is disabled and the
client did not request one, while Rust had applied its `node.expiry` default
while caching the pending web registration. The pending record now retains
only an explicit client expiry; the OIDC callback can still override it with
a configured token expiry. The stock-client process row checks the resulting
unset expiry in SQLite and CLI node output.
The paired stock-client rows passed under
`target/real-client/oidc-no-expiry-go-1792227000` and
`target/real-client/oidc-no-expiry-rust-1792227000`. The common OIDC smoke
now parses the confirmation form's HTML attributes by name, since pinned Go
can insert `type="hidden"` between the input's name and value.
A paired production Postgres stock-client policy rejection case passed. The
`postgres-rejected-policy-filter-smoke.sh` and
`postgres-rejected-policy-filter-headscale-go-smoke.sh` rows register Alice and
Bob under a visible ACL, then submit a policy whose `tests` block requires
reachability that its empty ACL denies. Both production servers reject the
write with a test failure, keep each stock client's nonempty `PacketFilter`
and `PacketFilterRules` and visible peer unchanged, and preserve that state
after restart. Both clients entered `Running` with one configured DERP region before the
rejection. The fixture DERP host is intentionally unreachable, so a transient
relay health warning is outside this policy-filter assertion. The Rust row passed in
`target/real-client/postgres-rejected-policy-filter-smoke/hs-online-lastseen-rust-postgres-authkey-1792236945-35331`;
the pinned-Go row passed in
`target/real-client/postgres-rejected-policy-filter-headscale-go-smoke/hs-online-lastseen-headscale-go-postgres-authkey-1792236973-35689`.
This qualifies the v0.29.5 rejected-policy filter regression for one
two-client Postgres state; other release and mutation combinations remain open.

The matching production Postgres stock-client rows also passed against an
isolated local PostgreSQL 14 cluster, both at initial login and after server
restart: `target/real-client/postgres-oidc-no-expiry-go-1792229000`,
`target/real-client/postgres-oidc-no-expiry-rust-1792229000`,
`target/real-client/postgres-oidc-no-expiry-restart-go-1792229300`, and
`target/real-client/postgres-oidc-no-expiry-restart-rust-1792229300`. Each
implementation kept the OIDC node's expiry unset in stored and CLI state.
`tools/real-client/noise-oidc-register-response-smoke.py` now completes
separate mock OIDC callbacks over real TS2021/Noise sessions against Rust and
pinned Go v0.29.5, then compares their successful register response bodies.
The paired row passed in
`target/real-client/noise-oidc-register-response-1792230900`: owner and login
fields, authorization, expiry state, auth URL, error, and null node-key
signature agree. A follow-up run in
`target/real-client/noise-oidc-created-precise-1792239000` now checks that
both implementations emit fractional `User.Created` values. Rust retains
microseconds in new SQLite and Postgres user writes and projects imported Go
SQLite timestamps with offsets through the register response. The paired
process row passed for SQLite. The two independently created users have
different creation instants and Go emits its local offset, so literal
timestamp-string equality is not a parity assertion.
The focused live Postgres user test also confirms the projected microsecond
value equals the stored `TIMESTAMPTZ` value. The same paired TS2021/Noise
OIDC row passed on independent Postgres databases in
`target/real-client/noise-oidc-postgres-created-precise-1792245000`.
Rust and pinned Go both returned fractional `User.Created`, matching owner
and login fields, authorization and expiry state, auth URL, error, and null
node-key signature.
Rust now accepts the v0.29.2 browser/WASM `GET /ts2021` WebSocket upgrade,
reads the deferred Noise initiation from its query string, and carries the
encrypted HTTP/2 control stream over binary WebSocket messages. The paired
OIDC register row passed against pinned Go in SQLite
(`target/real-client/noise-oidc-websocket-sqlite-1792246600`) and Postgres
(`target/real-client/noise-oidc-websocket-postgres-1792246900`) modes. Both
rows complete real Noise handshakes, mock IdP callbacks, and follow-up
registration over plain loopback WebSocket, then compare the same response
fields. The paired WSS/TLS row also passed with a trusted local certificate
on SQLite (`target/real-client/noise-oidc-wss-sqlite-1792249200`) and
Postgres (`target/real-client/noise-oidc-wss-postgres-1792249500`).
The test client reproduces the browser/WASM WebSocket Noise transport;
a browser runtime was not used. The real-client parity workflow now gates
native, plain WebSocket, and WSS transport in both database modes.
The v0.29.4 deleted-node map fix now has a paired production Noise/OIDC row:
after deleting a registered node, its active map stream ends promptly and
its next streaming map request gets an expired self node with the fixed
1970 key expiry. The SQLite and Postgres runs passed in
`target/real-client/noise-oidc-delete-stream-shape-sqlite-1792252100`
and `target/real-client/noise-oidc-delete-stream-shape-postgres-1792252400`.
The expired response JSON shape matches pinned Go after removing the
independently generated node key. Rust closes the old HTTP/2 stream with EOF;
pinned Go resets it with `INTERNAL_ERROR`. Both end the stream before the
test's ten-second bound. The real-client workflow now gates both databases.
Ephemeral deletion timers now carry a generation, so a callback queued before
reconnect or reschedule cannot consume a newer timer or delete that node.
The active map stream is published before its GC timer is cancelled. A Rust
regression covers cancellation and rescheduling against a queued callback;
the pinned Go `TestEphemeralGarbageCollectorCancelBeatsQueuedDeletion` is the
corresponding v0.29.5 case. The paired production Postgres
`postgres-ephemeral-reconnect` row now registers two ephemeral-key stock
clients, restarts the target three times, and checks both persisted identities,
the target's Tailscale IP, and its online peer entry in the observer netmap
after every reconnect. Rust and pinned Go both passed. The exact queued
callback race is covered by the deterministic regressions; a production
timing test at that boundary remains unqualified.
When a full map batch and a targeted ping are queued together, Rust now sends
the full response before the ping-only frame and does not send that ping to
other nodes. The Rust two-stream regression mirrors pinned Go
`TestBatcherPingSurvivesFullUpdate` and `TestPingSurvivesFullUpdate`;
the paired production Postgres `postgres-full-map-ping-churn` row now overlaps
four debug pings with unrelated user removals, checks each callback and new
full-map dump, and preserves the stock client's ID and IP on both Rust and
pinned Go. The process row does not force both events into the same batch;
the deterministic regressions establish that ordering.
Map construction now omits peers with an empty stored given name or an FQDN
longer than 255 bytes while preserving valid peers, and returns an explicit
500 for an invalid self name on the initial map request. The matching pinned
Go mapper and long-poll regressions pass alongside Rust's map regressions.
`postgres-invalid-fqdn-peer-restart` now runs the same production Postgres
stock-client sequence against Rust and pinned Go v0.29.5. It empties a stored
peer `given_name`, restarts the server, and verifies the observer drops that
peer while retaining its node ID and Tailscale IP. Both implementations pass.
The row exposed a Rust database reload fallback that had replaced the invalid
given name with the raw hostname; wire hydration now preserves the stored name
for map validation. Both startup scans log the affected node ID and an
actionable `headscale nodes rename ID <name>` hint, which the paired row checks.
`tools/real-client/sqlite-v0295-release-upgrade-smoke.sh` starts pinned Go
and Rust independently on copies of the historical release fixtures and
populated v0.28.0 auth-key and RequestTags fixtures. Both processes reach
v0.29.5, compare key rows, owner and tag semantics, and expiry presence, and
each implementation directly starts on the other's upgraded primary file.
The row rechecks database integrity and state after both cross-starts.
The comparison normalizes Go's JSON `null` and Rust's `[]` as the same
untagged value; the raw tag storage differs.
`postgres_foundation_applies_v0295_release_repairs_to_older_go_rows` also
upgrades seeded v0.29.0 Postgres rows through the Rust migrations, checking
owner recovery, tagged expiry removal, untagged expiry preservation, and a
second idempotent migration run. The paired
`tools/real-client/postgres-v0295-release-upgrade-smoke.sh` starts from a
pinned-Go-created Postgres schema seeded with those pre-fix rows, clones it,
upgrades one copy under Go and the other under Rust, compares stored and CLI
node state, and cross-starts each server on the other's copy. Rust now records
the four equivalent Go migration IDs in an imported Go ledger before stamping
`v0.29.5`, so the upgraded Postgres database advertises consistent release
history. This qualifies the seeded release-fix state; other historical
Postgres database shapes and mutation paths remain open.
The SQLite release-upgrade process gate now also imports pinned Go's zero-time
expiry fixture. Both Go and Rust clear year-1 expiry values while preserving
future and legitimately past dates, then directly restart on each other's
upgraded file. A separate Postgres gate starts from a schema made by a real Go
v0.28.0 process, seeds those three expiry states, upgrades cloned databases
under Go v0.29.5 and Rust, and cross-starts both. The UTC expiry years and
v0.29.5 migration marker agree at all four stages. This covers the historical
zero-time data repair on both backends; other historical shapes remain open.
Full map responses now omit `Debug` when `logtail.enabled` is true, matching
the v0.29.5 Go builder; disabled logtail still sends `DisableLogTail: true`.
A paired production Noise process row now checks both logtail settings with
and without the `data-plane-audit-logs` node attribute. For every combination,
Go v0.29.5 and Rust return the same `Debug` instruction and self `CapMap`
attribute on two fresh full-map streams and a stream after server restart.
The paired SQLite stock-client policy reload now also grants that attribute
while the client is running. Go v0.29.5 and Rust both make Tailscale v1.94.1
persist `WantRunning=false` and emit the same audit-log health warning when
logtail is disabled; with logtail enabled, the client receives the capability
and remains running. The client's `BackendState` can lag the persisted stop
preference, so the process row checks preferences, health, and netmap together.
After the policy removes the attribute, `tailscale up` restores the running
preference and the same node ID and IP under both servers. Tailscale v1.94.1
can retain the old audit-log health warning after this recovery, so the row
checks the recovered preference, backend state, identity, and absence of the
attribute rather than requiring that warning to clear.
Successful `configtest` now creates or reuses the configured Noise key and
opens/migrates the SQLite database through the production storage path, as
pinned Go does. A paired fresh-process check verifies both create Go-format
Noise keys and the same primary SQLite tables, then pinned Go reopens Rust's
files without changing the key or migration version. The CLI's default feature
set now includes `postgres-sqlx`, so its default binary opens and migrates
Postgres during `configtest` as it does SQLite. Explicit
`--no-default-features` builds still omit that backend.
A paired default-build Postgres `configtest` row created separate fresh Go and
Rust databases with the same six application tables and v0.29.5 version, then
directly reopened Rust's database under Go without changing its Noise key,
application tables, or version. Go's `migrations` ledger and Rust's
`_sqlx_migrations` ledger differ on fresh creation; Go adds its ledger on the
cross-start. The report is in
`target/real-client/configtest-postgres-v0295-1792234921-2931/report.json`.
A paired production Postgres API-key session row now creates a secondary key
through the authenticated public gateway, uses it to read health, expires it
through the same gateway, and restarts each server. Pinned Go v0.29.5 and Rust
both returned the same 200/401 health responses before and after restart while
the bootstrap key remained valid. This covers API-key authorization state;
other live auth-session and config/route combinations remain open.

The stock Tailscale v1.94.1 search-domain live DNS row now passes against both
Rust and pinned headscale-go v0.29.5. Its resolver runs on Docker bridge UDP/TCP
port 53, and the client queries Tailscale's internal DNS forwarder. This avoids
Docker Desktop's synthetic host-gateway address and exercises actual split-DNS
forwarding. The paired two-resolver failure/fallback row also passes against both
servers, with one resolver returning SERVFAIL and the second returning the
expected A record. These two live rows close the DNS resolver backlog item.

Standalone `main` line, release qualification (2026-10-16): a parallel
v0.29.5 update that was developed on `origin/main` and later reconciled into
this branch. Its checkpoint recorded 2,061 workspace tests across 35 targets
with actual PostgreSQL, 786 wire-only tests, strict lint gates, an actual Rust
1.89 check and 100 paired Go/Rust policy/wire scenarios, plus selected
stock-Tailscale PostgreSQL rows. Those numbers and the hashes in
[`qualification/headscale-v0.29.5.json`](qualification/headscale-v0.29.5.json)
describe that line's tree, not this one; see
[`qualification/README.md`](qualification/README.md) for how the records relate
to the merged tree and which of their statements this branch's later results
supersede (the paired user-rename lifecycle row and the open-backlog count).
Historical notes and registered matrix counts below do not mean that every row
ran for any one release.

The same line's follow-up added three v0.29.5 release regressions for unknown-user
groups in `via` subnet/exit grants and unrelated-ACL exit steering
(`v0295-unknown-group-exit`, `v0295-unknown-group-via`,
`v0295-via-exit-unrelated-acl`); all three scenarios are in the checked-in set
here. See
[`qualification/headscale-v0.29.5-via-followup.json`](qualification/headscale-v0.29.5-via-followup.json).
That line also added the `release-0295-empty-ssh` (a policy without an `ssh`
section yields an explicit, empty SSH policy for the node) and
`release-0295-policy-metadata` (unknown `#`-prefixed metadata fields beside
`groups`, `tagOwners` and `ssh`, and the resulting SSH user maps) scenarios;
both are part of the checked-in set (106 scenarios). The golden gained their
two entries by regeneration with the real Go harness (`PARITY_UPDATE_GOLDEN=1
./scripts/headscale_go_diff.sh`); the other 104 entries are unchanged, and the
Rust side, which reads the production policy and filter code, matches Go on all
106 in both the sorted and `PARITY_FILTER_ORDER=emitted` modes.

Release baseline audit, refreshed 2026-10-15:

- Pinned upstream `juanfont/headscale` release used for the parity
  audit is `0f7d1e536bed9f01dd7161f7637af19bb0908335`.
- The checked-in differential harness now targets the current-head baseline
  above. Treat rows below as executable default-scenario coverage plus explicit
  current-head deltas; no current-head-only parity scenario is currently staged
  outside the default set.
- Integrated current-head fixes: `/key?v=` capability-version behavior
  and Noise placeholder route/body-limit parity in `c002804`, `/verify`
  4 KiB request-body limit in `72bb5f8`, and DB user/preauth delete
  semantics in `d076c8e`; CLI `auth` plus `preauthkeys delete`
  command parity in `56d4de6`, and current-upstream top-level
  `auth` visibility plus auth help snapshots; unsupported client capability
  rejection and Noise register error-envelope parity in `004098d`;
  map stream compression/framing negotiation in `97e8bbd`; removed
  upstream config-key rejection in `222f80a`; persistent IPv6
  projection plus IPv4 `BackfillNodeIPs` in `118a03c`; public
  `/machine/*` hard-gating in `cfa44f1`; semantic ACL policy tests
  for `CheckPolicy`/`SetPolicy` in `c546f5b`; rich
  `Hostinfo`/`NetInfo` runtime preservation in `db7ff65`; public
  `HEAD /machine/ping-response` callback routing in `47b9fad`;
  non-empty `sshTests` semantic evaluation and grants-only omitted-proto
  `tests` reachability in the current policy checker; and
  `PingRequest` map-stream dispatch/callback correlation
  plus optional dual-stack live wire address projection, DB-seeded
  production address allocation, configured prefix-family backfill
  add/remove coverage, IPv4-disabled wire/admin/DNS projection, and register-time
  debug/CLI address allocation plus duplicate admin address rejection,
  upstream IPv6-only prefix config, paired dual-stack/IPv4-only/
  IPv6-only stock-client coverage, and paired production-process
  IPv4-to-dual-stack, dual-stack-to-IPv4-only, and
  dual-stack-to-IPv6-only backfill plus post-backfill restart hydration
  stock-client coverage, and
  production online/LastSeen lifecycle projection, upstream DNS
  `override_local_dns` resolver/fallback behavior plus initial
  `extra_records_path` validation in `8031754`, upstream
  `taildrop.enabled` capability gating in `e625727`, upstream
  default log format `text` in `c6c583b`, and current-upstream
  `node.expiry` parsing/env/debug projection plus non-tagged
  registration default expiry plus tagged zero-expiry restart
  preservation, public `grants`/`nodeAttrs`
  parsing, public `ipsets` rejection, user CRUD policy/map refresh wakes, per-viewer
  `grants[].via` route steering, current-upstream config-schema
  parsing/debug projection, SQLite import fixture matrix coverage,
  DNS edge resolver/MagicDNS live stock-client coverage, production DNS
  `extra_records_path` hot-reload stock-client resolver coverage, production
  restart-persistence smoke wiring with debug batcher state assertions,
  route-withdraw approval
  preservation, paired route-via policy reload/restart and multi-prefix
  restart stock-client coverage, viewer-specific route-prefix reduction
  before peer `AllowedIPs`/`PrimaryRoutes` emission, route-health policy reload stock-client coverage,
  production route-health restart stock-client coverage,
  expanded SSH real-client coverage, current-upstream SSH
  `localpart:*@domain` login-user compiler and `sshTests` semantics,
  paired current-head SSH localpart/profile real-client coverage,
  route-health probe fresh-session/reconnect deferral with batched
  health application,
  scoped grpc-gateway fallback routing, upstream-shaped grpc-gateway
  timestamp query/range parser errors plus duplicate scalar/timestamp
  query edge coverage, strict protojson-style grpc-gateway body field,
  grpc-gateway status-code/envelope matrix coverage including plain 401 auth,
  timestamp range, timestamp scalar-subfield query-path rejection, and
  scalar-query-path rejection, private-DERP/STUN sidecar real-client parity,
  operator `/debug/ping`, tsweb-style `/debug/gc` method handling,
  paired ping-lifecycle stock-client coverage,
  enabled `/debug/mapresponses` dump/readback parity,
  current-upstream top-level CLI help text/order parity, and
  current-upstream Cobra help snapshots for stable
  operator/auth/user/node/preauthkey/API-key/policy subcommands,
  deprecated `nodes register`, completion shell helpers, `mockoidc`,
  hidden `dumpConfig`, and residual top-level/help-command parser
  snapshots, plus
  upstream policy direct-database bypass over configured SQLite,
  process-level local stderr snapshots for migrated CLI command
  boundary errors, exact gRPC node mutation stdout for expire,
  scheduled expiry, rename, tag, backfillips, and
  list/list-routes/approve-routes tables, and process-level
  remote TLS gRPC config coverage, plus keyed map compatibility route
  body-`NodeKey` precedence matching upstream Noise `/machine/map`,
  upstream-shaped human user/API-key/preauth-key create/list output,
  user JSON/json-line/YAML create/list/rename/destroy success output,
  API-key JSON/json-line/YAML create/list/expire/delete success output
  with proto JSON field names,
  default-gRPC API-key selector validation before connection setup, and
  preauth-key JSON/json-line/YAML create/list/expire/delete success output in
  the current branch; output-aware CLI error envelopes now match
  upstream `Error:`/JSON/json-line/YAML formatting plus
  `missing parameters` usage exits for selector and
  remote transport failures including structured connection/auth envelopes
  and remote health/server failure envelopes, structured live auth
  no-pending-session envelopes,
  live local-gRPC domain failures now have exact text/JSON/json-line/YAML
  snapshots, gRPC API-key auth now matches upstream missing-token,
  missing-`Bearer`, and invalid-token text, and current-upstream auth
  request IDs now enforce the `hskey-authreq-` prefix and 38-character
  shape across the auth RPC/gateway shim while the web registration page
  renders `headscale auth register --auth-id hskey-authreq-... --user USERNAME`
  and the public `/auth/{auth_id}` page renders
  `headscale auth approve --auth-id hskey-authreq-...`; the checked-in
  OpenAPI JSON advertises `/api/v1/auth/{register,approve,reject}` and `/api/v1/policy/check`
  while pinning the `disableExpiry` query description.
  SSH `check` rules now fail closed into upstream `HoldAndDelegate`
  instead of direct accept, with a Noise-inner
  `/machine/ssh/action/{src}/to/{dst}` route that binds auth IDs to
  the source/destination pair and resolves CLI/web approve/reject
  verdicts. When OIDC is configured, `/auth/{auth_id}` now starts the
  OIDC flow and the callback approves SSH-check auth only for the
  authenticated user that owns the source node across both in-memory
  and persistent production handlers, rejecting tagged, ownerless,
  missing, or wrong-owner source nodes before releasing the waiting
  SSH follow-up. Long-offline `/debug/batcher` state now
  follows headscale-go's rapid-reconnect retention plus stale cleanup:
  disconnected entries are retained, then zero-count entries older than
  15 minutes are evicted by the production cleanup task without deleting
  node records. OIDC registration now mirrors current upstream's
  confirmation interstitial: the callback stages a pending confirmation,
  `POST /register/confirm/{auth_id}` validates the URL-encoded CSRF
  form value, CSRF cookie, and cached pending confirmation before
  completing registration, and TLS-served confirmation cookies carry
  `Secure` like headscale-go. The differential parity harness now renders
  loaded runtime DNS config through both headscale-go and headscale-rs and
  proves MagicDNS peer names are not synthesized into operator
  `DNSConfig.ExtraRecords`; live local-gRPC CLI tests now snapshot exact
  normalized API-key and preauth-key human list table output,
  `serve` now runs the same startup validation gate as `configtest`
  before opening SQLite state with broader server-init failure snapshots,
  utility-command unknown shorthand flag and checked-in OpenAPI
  `disableExpiry` parity are closed in
  `bd73e18`, public gRPC reflection filename/dependency parity is
  closed in `0f0b943`, and `debug create-node` plus `users rename`
  local required-flag errors now match current upstream. Node `GivenName` handling now mirrors current
  upstream's Tailscale DNS-name path: registration preserves the raw
  client `Hostname`, auto-derives DNS labels with
  `dnsname.SanitizeHostname`-style rules plus `node` fallback and
  monotonic `-N` collisions, explicit rename validates with
  `dnsname.ValidLabel`-style rules without auto-bumping, and Hostinfo
  updates recompute auto-derived labels while preserving admin renames.
  Server transport `HEADSCALE_*` env overrides now feed the same runtime
  config fields as current upstream Viper for server URL/listeners, remote
  gRPC security, and local Unix-socket path/permission. `configtest` now wraps
  validation failures with the upstream `configuration error: loading
  configuration` context, rejects missing `database.type`, and validates absent `server`/`dns` blocks against
  current-upstream defaults, including the empty `server_url`, missing noise
  private key, and default `dns.override_local_dns=true` nameserver fatal.
  Policy env overrides now match Viper for `HEADSCALE_POLICY_MODE` and
  `HEADSCALE_POLICY_PATH`. DNS env overrides now match Viper for the
  current-upstream DNS scalar/list keys, including `HEADSCALE_DNS_MAGIC_DNS`,
  `HEADSCALE_DNS_BASE_DOMAIN`, `HEADSCALE_DNS_OVERRIDE_LOCAL_DNS`,
  `HEADSCALE_DNS_NAMESERVERS_GLOBAL`, `HEADSCALE_DNS_NAMESERVERS_SPLIT`,
  `HEADSCALE_DNS_SEARCH_DOMAINS`, `HEADSCALE_DNS_EXTRA_RECORDS`, and
  `HEADSCALE_DNS_EXTRA_RECORDS_PATH`. User deletion now emits an
  upstream-style `user removed` full map update when a live wire registry is
  available. DERP, route-health HA, and ephemeral lifecycle env
  overrides now match Viper for the upstream `HEADSCALE_DERP_*` DERP source
  and embedded-region keys, `HEADSCALE_NODE_ROUTES_HA_PROBE_INTERVAL`,
  `HEADSCALE_NODE_ROUTES_HA_PROBE_TIMEOUT`,
  `HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT`, and
  deprecated `HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT`. NodeStore tuning
  env overrides now match Viper for
  `HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE` and
  `HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT`. NodeStore worker batches now
  suppress stale auth-completion rekey map-change reasons when a same-batch
  delete removes the final node, leaving observers with only delayed peer
  removal churn. Persistent auth-key reauth now matches headscale-go's
  duplicate live NodeKey storage behavior when the same machine registers as a
  different user; NodeKey lookups intentionally return the earliest live row.
  Database env overrides now
  match Viper for `HEADSCALE_DATABASE_TYPE`, `HEADSCALE_DATABASE_DEBUG`,
  `HEADSCALE_DATABASE_GORM_*`, `HEADSCALE_DATABASE_SQLITE_*`, and
  `HEADSCALE_DATABASE_POSTGRES_*`. Batched policy reloads that narrow
  peer visibility now prove they emit a single policy delta with
  `PeersRemoved`, updated user profiles, and no stale full-map churn.
  Unchanged DNS configuration is omitted from policy deltas. Paired Postgres web-registration policy churn restart smokes
  now carry the no-auth registration plus database-policy map convergence path
  across a same-URL production server restart. Paired
  `postgres-web-register-custom-domain` smokes now pin no-auth registration
  against the custom MagicDNS base-domain config surface over production
  Postgres for Rust and current headscale-go. Remote gRPC duplicate-user server
  errors now have text, JSON, json-line, and YAML CLI output snapshots.
  gRPC/REST preauth-key list responses now mask fixed-width URL-safe prefixes
  even when the prefix itself contains `-`, while create responses still return
  the one-time full key.
- Active P0 default-scenario regressions against the current-head executable
  baseline: none known from the 2026-05-23 audit. Full replacement parity still
  has P0 backlog led by broader production Postgres process-level
  serve/mutation coverage beyond the CI-backed paired stock-client matrix.
  Current-upstream
  route-via/route-health row mirroring is guarded by the checked-in
  `route-edge-current-upstream-audit` row; remaining route work is new upstream
  semantics rather than another default/Postgres mirror row.
- Remaining P1 current-head gaps from the audit: remaining broader production
  Postgres process-level serve/mutation coverage and remaining multi-address
  policy/DNS/SSH/route edges beyond the covered restart-persistence and
  prefix-family post-backfill hydration rows.
- Remaining P2 current-head gaps from the audit: broader CLI output/error
  snapshots for residual serve/output drift, passing live proof for the wired
  DNS search-domain and multi-resolver fallback rows, and Octra-side adaptation to consume the generic no-health
  control router instead of hand-picking stock public control routes.
- Recent Rust-only SSH parity pins current-head localpart profile variants
  beyond the stock-client rows: special-character email localparts now compile
  into concrete client-facing `sshUsers`, while domain/profile mismatches still
  emit only the upstream root-deny rule.
- Recent coverage adds `postgres-derp-native-reload` as Rust-only native DERP
  stock-client coverage: two Postgres-backed clients start under isolated
  policy, snapshot the native DERP map, reload policy to expose the peer, and
  then assert stable region metadata, relay ping through the native region, and
  clear DERP status health. The headscale-go matrix script is an explicit
  no-equivalent skip so private/sidecar DERP coverage stays separate from
  headscale-rs native DERP claims.
- Native DERP stock-client runtime assertions now also pin the client's own
  `tailscale status --json` peer relay projection: the base and policy-reload
  Rust-only native DERP rows require `Peer[].Relay` to include the advertised
  native DERP region code after forced relay traffic succeeds.
- Rust-only `postgres-derp-native-websocket` coverage now opts stock clients
  into DERP-over-WebSocket, requires forced relay traffic through the native
  region, and asserts `/debug/derp` WebSocket verify-client admissions while
  keeping raw/WebSocket denials at zero. This closes the P0 native DERP
  stock-client runtime breadth row; future DERP work should be scoped to new
  drift or release-specific live-network evidence.
- NodeStore hostname/GivenName collision handling now retries auto-derived
  names after concurrent unique-index races on create and auth-path update,
  with SQLite concurrency tests and feature-gated Postgres helper coverage.
- Route primary parity now pins the Go property-test sequence for sticky
  primary ownership, unhealthy failover, non-stealing recovery, withdrawal
  failback, stale-primary clearing, and reverse primary-route lookup.
- Ephemeral lifecycle race coverage now pins pending-GC timer behavior across
  in-memory and persistent paths: connected streams cancel startup deletion,
  persistent reauth survives stale timers, explicit delete cancels pending
  store deletion, and persistent rows are removed before live records.
- Recent coverage closes the hidden `dumpConfig` no-config default-warning
  slice: process snapshots now pin headscale-go's timestamped
  `WRN no config file found, using defaults` line before the human,
  JSON, json-line, and YAML missing-target error envelopes.
- Recent coverage closes one residual current-upstream help-topic warning slice:
  headscale-go `171fd7a3` emits the timestamped `WRN no config file found,
  using defaults` stderr line when `headscale help <topic>` falls through to
  default config discovery with no config file, including extra-topic and
  unknown-topic help lookups; process snapshots now normalize that timestamp
  via `no_config_default_warning.stderr` while direct `subcommand --help`
  remains clean.
- Recent coverage adds process snapshots for API-key delete selector errors in
  JSON, json-line, and YAML, pinning the current-upstream missing
  `--id`/`--prefix` envelope before any gRPC connection attempt.
- Recent coverage adds process snapshots for remote gRPC duplicate-user server
  failures in text, JSON, json-line, and YAML, pinning the upstream-shaped
  server error envelope after a config-backed remote gRPC success path creates
  the first user.

This ledger tracks observable behavior that must match before
`headscale-rs` can claim full parity with headscale-go. Rows marked
`Done` have differential tests or direct Rust tests in this repo.
Rows marked `Partial` have some implementation or tests but do not
cover the whole upstream surface. Rows marked `Missing` need product
implementation and parity tests.

## Current remaining work — 2026-10-18

The backlog has three open acceptance gates: v0.29.5 release behavior,
production Postgres mutation/restart coverage, and CLI output/errors. These are
acceptance areas, not a count of patches. Historical results do not qualify the
accumulated implementation batch, which remains unbuilt and unexecuted under
the user's testing pause.

Raw SNI, pending authorization cleanup, version/PSK-aware certificate
preparation, raw ACME resource status, streaming first-JSON-value framing,
finite native wire decoding and selected Go HTTP-date processing now have
source implementations and independent source reviews. Those reviews are not
executable evidence.

Remaining source boundaries include broader TLS parser/cipher/group/HRR and
signature-failure alert behavior; ACME typed JSON field matching, duplicate and
partial-error assignment behavior; default account/discovery/nonce and HTTP
transport semantics; and platform/environment/raw-byte representation edges.
The native TLS session-name binding intentionally retains stronger Rustls
protection than Go tickets. The current review does not give an exhaustive
remaining patch count. No complete Go TLS/JSON/client engine claim follows from
these selected source repairs.

Normal ECDSA/RSA cache eligibility, selected Go15 hostname processing, persistent
TLS-ALPN tokens, native HTTP/2 blocked-output input/SETTINGS validation, and
lazy ordinary issuance/renewal also have source implementations. Full
X.509/provider and protocol error equivalence need qualification. Generic
caveats and superseded historical notes are not additional confirmed fixes.
The bounded CLI review found no additional missing routine Unix admin command.
Non-UTF8 secret/path/environment bytes and non-Unix console width remain
separate representation/platform boundaries.

## Implementation pending validation

### Native TLS certificate phases and ACME resource decoding — 2026-10-18

Native TLS1.2 pauses for certificate preparation before resumption. TLS1.3
handles HRR, computes/validates key exchange once, negotiates ALPN and validates
PSK/binder before a full-handshake-only pause; valid resumption skips preparation.
Missing signatures fail before the full TLS1.3 provider call and remain absent,
without synthetic SHA1 offers. Native TCP early_data rejection and h2/http1.1
ALPN fallback follow selected Go phases. Owned continuations retain original
ClientHello/transcript/KX; baseline configuration retains protocol/session policy,
while provider material supplies the selected key. Pending state blocks further
input. The API completes queued output and buffered-record processing before
handing the same connection to tokio-rustls. Static/default paths stay isolated.

Native ACME raw status/authorization APIs register pending cleanup before
unknown-status rejection and avoid identifier-enum failures in actual auth
polling. Raw order resource/error sidecars preserve unknown status strings, operational
URLs, arbitrary identifiers and signed64 status without blocking progress.
Unknown finalize status continues polling its returned Location; raw Valid and
latest certificate URL control download, while typed state remains a documented
compatibility projection. Incremental grammar framing stops after the
first value; native finite wire DTOs permit Go10000 nesting without Serde's
recursive adjacent-tagged Content buffer. Custom external bodies retain their
compatibility collect-before-frame fallback. Private Go byte quoting supplies
PEM diagnostics. Go HTTP-date layouts, fixed year pivot, fractional/pre-epoch
values, Unix Local/TZif/POSIX lookup and a pinned default archive have source
implementations, with initialization/platform/resource qualification retained.

Vendor UPSTREAM.md files record original/local hashes, licenses and remaining
boundaries. Feature forwarding reuses selected serde_json; no dependency
version/resolution changed. Independent source reviews/direct rustfmt only;
no builds/tests, CA/HRR/PSK/session/client/feature/package/container/process
qualification or closure of any of the three parity gates. This supersedes
earlier missing provider-phase/raw-status/framing/date implementation notes.


### Native raw SNI and ACME retry/cleanup — 2026-10-18

The exact selected Rustls0.23.46 and instant-acme0.8.5 sources are vendored with
default-off features and explicit per-acceptor/API selection. Default/Tonic/
client/unbound behavior remains opt-in only. Native raw SNI keeps original
hostname/extension bytes through HRR/transcript processing, validates Go's
selected structural framing and reaches byte-based hostname checks before
UTF-8/IDNA. Unicode/IP names receive SNI acknowledgement. Native TLS1.2/1.3
sessions bind exact raw name and mode, preserving Rustls cross-name protection;
this does not adopt Go's unbound ticket behavior or ticket format.

Native ACME auth/order polling retains raw Retry-After metadata through
body/JSON failure and retries the same URL; signing/transport/status errors
remain separate. Native POSTs apply selected retryable-status/badNonce/backoff
phases. Every decoded new order registers all auth URLs before status checks;
Drop starts independent five-minute direct pending-only deactivation cleanup,
including on cancellation. Finalization polls its own response Location and uses actual state before
download. Selected Hyper certificate download now bounds the read to Go
5MiB-plus-overhead+1, requires at most five CERTIFICATE blocks/nonempty chain,
ignores the final undecodable suffix and returns canonical decoded PEM.
Custom external bodies can still collect before the default prefix limit.

Workspace patches/excludes, exact lock source entries, features, embedded
original/Go licenses and container license copies are integrated without
package version/resolution changes. Source provenance/remaining boundaries
are in vendor/{rustls,instant-acme}/UPSTREAM.md. Missing signature-extension,
broader TLS/X.509/provider, ACME JSON/date/default account/nonce/
transport and resource behavior remain separate source or qualification
boundaries. Independent source review/direct rustfmt only; no tests/builds,
CA/client/HRR/PSK/session/package/container/process or gate qualification.


### Native lazy ACME, RSA issuance and renewal — 2026-10-18

Native startup now installs an empty certificate resolver before listener
acceptance. It neither reads the ordinary cache nor generates a certificate
key or contacts the CA. The requesting TLS handshake supplies an owned
ClientHello snapshot before rustls filters signature schemes; selected Go
signature/group/cipher rules choose ECDSA or RSA. Sole TLS-ALPN token requests
use the shared challenge resolver and never start ordinary issuance. The same
provider serves public TLS and remote gRPC while preserving each listener's
ALPN policy. Preparation errors end that connection with a fatal internal_error
alert; they no longer abort server startup or expose a temporary self-signed
ordinary certificate.

Each ordinary kind has one owned, coalesced preparation task. A disconnected
waiter cannot cancel issuance. Classified cache lookup separates misses from
fatal read/private-key failures; only misses issue. P-256/RSA2048 keys and
CN/DNS-SAN CSRs are prepared before account/network work. Account initialization
is shared lazily, with its mutex released before orders. RSA uses the separate
`+rsa` cache identity. Issued material is validated before publication. Fresh
ready state and renewal start precede best-effort cache write; pending followers
can receive the certificate then, while the initiating caller waits for cache
completion. Failed created-state followers receive the missing-certificate
error during the one-minute retry interval; pre-state failures are not retained.

Renewal reuses the private key, adopts newer eligible cache material, applies
the lifetime/3 threshold capped at 30 days with jitter, and retries failures
after 30–60 minutes while keeping the old state. Ordinary memory hits do not
revalidate expiry; renewal owns replacement. Cache write failure prevents a
renewal replacement. Initial/renewal owners have five/ten-minute budgets and
native shutdown signals their stop condition. Provider-only remote gRPC
handshakes progress concurrently with a 1024-task admission bound.

Native authorization prefers TLS-ALPN, then HTTP-01 when configured, sharing
the next challenge type across orders/authorizations. The same account/key/CSR
survive retries. New-order/GetAuthorization failures remain fatal; fulfillment,
challenge acceptance and authorization/order wait failures advance to a new
order. Accumulated challenge cleanup occurs before CSR finalization. Existing
per-type fixture helpers remain separate. Production CSR generation promotes
the already-locked CLI rcgen 0.13.2 dependency; no package version/resolution
changed. Cache/account temporary files now use 0600 at creation and 0700
directories, with atomic rename and failure cleanup.
Configured nonempty hostname identity is retained without trimming in runtime,
snapshot and listener validation. Two existing native ACME fixtures now trigger
an ordinary TLS handshake before expecting issuance; they remain unexecuted.

This supersedes the missing normal-RSA and eager-only lifecycle branches.
Pending authorization deactivation, Retry-After/invalid-JSON/library transport
behavior, raw SNI/missing-signature acceptance, X.509/provider/session state,
synchronous filesystem/context/scheduling/resource and immediately-due renewal
overlap remain incomplete or unqualified. Independent source reviews and direct
rustfmt only; no tests/builds/probes, CA/client/process/restart/feature/package
qualification or release gate closure.

### Native raw SETTINGS validation — 2026-10-18

Opted native server codecs now validate SETTINGS before identifier collapse.
More than 100 parameters or any repeated raw identifier, including unknown
IDs, produces PROTOCOL_ERROR. The private loader follows selected Go phases:
nonempty ACK gives FRAME_SIZE_ERROR before the stream-ID check; nonzero stream
gives PROTOCOL_ERROR; non-six-byte payload size gives FRAME_SIZE_ERROR; the
first INITIAL_WINDOW_SIZE overflow gives FLOW_CONTROL_ERROR before count and
duplicate checks. Remaining unique known values use the existing typed loader.

A fixed 100-element stack array bounds duplicate detection without allocation.
Runtime selection is armed only after the opted server's client preface;
default/Tonic/client and feature-off codecs retain the prior loader. Go BSD
terms and adaptation notice now ship within the h2 package alongside its MIT
license; package metadata records both licenses and existing container globs
include them.

This supersedes the missing raw count/duplicate validation below. General
decoder/error-dispatch phases, including already-failing GOAWAY drains, full
control scheduling, timers/resources and runtime equivalence remain
unqualified. Source reviews/direct rustfmt only; no builds/tests/probes,
package/process qualification or gate closure.

### Native persistent TLS-ALPN token cache — 2026-10-18

Full/native bound ACME resolvers now retain the configured cache directory.
Sole TLS-ALPN challenge requests read the in-memory token first, then fall back
to the normalized, untrimmed `hostname+token` disk entry. Disk hits are not
promoted to the map. Token entries reuse PEM/DER/date/hostname/private-key
eligibility checks, permitting either RSA or ECDSA; normal ECDSA entries keep
their existing key-type requirement. Critical challenge extensions do not
invoke ordinary WebPKI verification.

Installing/removing a challenge holds the map write lock across memory change
and best-effort cache publication/deletion, following Go's challenge mutex.
Publication uses a private directory, random exclusive 0600 temporary file and
atomic rename; failed publication preserves the memory token. Paths remain
inside the configured cache directory. HTTP-01's private bound resolver also
supports token fallback. Public unbound constructors and non-full builds keep
disk access disabled; renewal retains the same resolver.

This supersedes the missing durable token branch. Synchronous filesystem work,
Go context/cancellation/worker scheduling, exact private-key bytes, X.509/provider
acceptance and runtime handoff/restart/resource behavior remain unqualified.
Source reviews/direct rustfmt only; no tests/builds/probes or gate closure.

### Native H2 frame progress under blocked control output — 2026-10-18

Native server connections now poll pending GOAWAY and control writes without
gating frame input on a pending write. Peer SETTINGS apply on receipt with a
coalesced pending ACK, matching Go's processSettings ordering. Private FIFO
queues retain PONG payloads and refused stream IDs instead of overwriting the
old single pending slots. Default/Tonic/client and feature-off paths retain
their previous readiness and single-slot behavior.

The aggregate newly decoupled control queues are checked after each received
frame. More than 10000 pending replies closes through the terminal I/O path,
without waiting for blocked output. A 32-frame cooperative budget yields
through the existing stream-output/flush path and registers another wake, so
continuously ready input cannot monopolize one driver poll. Existing flow and
stream concurrency limits still apply.

This repairs the known steady-state write-before-read gate. It does not prove
Go's complete control scheduler/counting or timing equivalence. The newer raw
SETTINGS loader above supplies count/duplicate rejection; general
decoder/error phases remain separate.
Source reviews/direct rustfmt only; no builds/tests/probes, transport/process/
feature/resource qualification or parity gate closure.

### Native H2 preface progress under blocked output — 2026-10-18

Selected native server handshakes now poll the initial SETTINGS flush and
client-preface read independently. A pending write no longer prevents the
24-byte preface from being consumed and validated. The same codec, including
any unwritten SETTINGS bytes, passes into the protocol connection. Terminal
write errors still terminate the handshake. Default/Tonic and feature-off
handshakes retain their prior flush-before-read path.

The newer frame-progress implementation above supplies the separate native
SETTINGS/coalesced ACK and bounded PONG/refusal handling. No unconditional
readiness bypass was introduced. Independent source review and direct rustfmt
only; no builds, tests, probes or wire/process qualification. All three parity
gates remain open.

### Native H2 stream read/write deadlines — 2026-10-18

Tracked ordinary H2 now selects Go's 30-second per-stream read and write
timeouts through additive Hyper/h2 builder forwarding. Noise, default/Tonic,
client and untracked ordinary builders keep these timeouts disabled. Write time
starts at server stream creation; read time starts after request conversion.
Completed request bodies retain EOF. Read expiry preserves already-buffered
DATA, then returns a sticky timeout without resetting the stream; later body
DATA is discarded with connection credit returned. Write expiry queues an
INTERNAL_ERROR reset without consuming the protocol-abuse reset budget.

One connection timer tracks the earliest stream deadline. A private generation
cache avoids per-frame store scans; rescan occurs when deadlines change or the
cached deadline expires. Scans include active and retained reset entries. No
per-stream tasks or timer allocations were added. Existing public signatures
remain; the default-off lifecycle feature contains the implementation.

Writer-completion/buffering boundaries, detailed error causes, response-controller
deadline overrides, resource and scheduling behavior remain unqualified. Source
correction: Go may close a stream after encoding into its writer buffer, before
the eventual socket flush; an unconditional all-wire-flush rule would also differ.
Independent source/peer reviews and direct rustfmt only; no tests/builds/Cargo,
deadline/frame/client/process/feature qualification or gate closure.

### Native ACME cache eligibility and publication — 2026-10-18

Full/native cache loading now reads bytes and follows selected Go PEM block
ordering, first-private-key requirements and strict final-remainder handling.
All subsequent block DER contributes to certificate parsing regardless of PEM
label; original DER grouping is retained. Normal ECDSA entries require inclusive
validity dates, matching SAN hostname/IP, the selected 2022 Let's Encrypt rule
and a matching private key. Hostname matching follows Go's wildcard/exact-name
rules and mapped-IP equality; legacy Common Name is ignored. Static/non-full
loading and unbound resolver defaults retain their existing paths.

CLI issuance canonicalizes PEM before writing and validates the issued entry
before atomic replacement. A rejected response therefore preserves the existing
cache. The private expiry predicate now accepts exact NotAfter equality. Existing
layout/equality assertions were source-updated and remain unexecuted.

This supplies default normal-cache eligibility, not a full Go X.509 parser.
Selected ASN.1/DN/time/extension/key-curve/provider parsing still differs; SPKI
equality can be stronger than Go's coordinate/modulus comparison. Unusual DER
grouping may fail in Rust before the Go handshake. RSA/token variants, eager
issuance, runtime certificate selection, diagnostics and failure/resource phases
remain separate boundaries. Independent source reviews/direct rustfmt only;
no tests/builds/Cargo, certificate/renewal/process qualification or gate closure.

### Selected Go Unicode 15 hostname profile — 2026-10-18

Native hostname Lookup now uses private source-derived Go Unicode 15 tables
and algorithms throughout. Whole-domain mapping precedes ACE decoding, including
compatibility-mapped prefixes. Selected status/STD3/nontransitional rules,
ContextJ, stream-safe NFC with 30-nonstarter CGJ insertion, Hangul/recomposition,
bidi and signed-32-bit Punycode now share the selected profile. The ICU fallback
and its separate input limit have been removed from this serving path. The
earlier direct optional idna dependency/feature/lock edge was removed; unrelated
transitive dependencies retain their existing versions.

A committed converter reads three exact SHA-pinned Go table artifacts and
writes static Rust implementation data. It runs no Go, build script, runtime
source parser or behavior probe. Public hostname/policy/cache APIs are unchanged.
This supersedes the earlier newer-Unicode/NFC/bidi/mapped-ACE/adapter-limit
implementation gaps. Compilation, data equivalence, hostname behavior, resource
and failure behavior remain unqualified. The Option boundary exposes success
only; Go's sanitized partial output and structured IDNA errors are not returned.
rustls raw SNI/alerts, eager invalid-config handling, RSA/token cache variants
and certificate verification remain separate boundaries. Independent source
reviews, implementation data conversion and direct rustfmt only; no tests,
builds/Cargo, handshake/process/feature qualification or gate closure.

### Per-server HTTP/2 lifecycle — 2026-10-18

Native H2 lifecycle is now selected per builder. A narrow vendored Hyper 1.8.1
forwarder enables it for tracked ordinary HTTP with a 30-second idle timeout;
native Noise enables it with no idle timeout. Default/Tonic builders retain
upstream MAX-ID/PING shutdown even when the feature is compiled. The erroneous
outer 30-second quiet-Noise close was removed for all feature profiles. Existing
untracked ordinary embedding does not opt into the new lifecycle. Public types
and existing signatures are retained through additive setters; both vendor
versions and their MIT licenses are preserved.

Protocol idle starts after the preface, stops on new HEADERS and restarts after
the final counted stream closes. A separate one-second close clock starts only
after GOAWAY reaches the transport; NO_ERROR also requires drained protocol
streams and queued output. Error GOAWAY does not wait for streams. Timers are
polled independently of write gates and expiry does not wait for a later blocked
flush. Native peer GOAWAY receives a current-ID reply; the pending path yields
to its registered close timer instead of spinning. Native error-drain input
discards frames while retaining DATA connection-credit accounting.

Source correction: Go's H2 ConnState notifications are optional callbacks and
do not change core net/http accounting. Headscale supplies no callback; ALPN H2
stays core-active until connection close. Existing native HTTP work tracking
already retains that lifetime. Remaining gaps include count-close versus actual
END_STREAM write timing, the h2 write-before-read gate, general decoder/error
phases, per-stream deadlines and the separate Noise outer shutdown's best-effort
flush/drop. Independent source/peer reviews and direct rustfmt only; no tests,
builds/Cargo or lifecycle/client/process/feature/package qualification. All three
parity gates remain open.

### Legacy ACME ACE labels — 2026-10-18

The hostname helper now handles raw ASCII ACE labels using the selected Go
Punycode arithmetic before the newer IDNA adapter. Go's pre-Unicode-16 profile
accepts decoded ASCII and empty labels, including delimiter-ending forms that
the adapter rejects. The private decoder/encoder retains signed-32-bit checked
arithmetic and Go's 1024-rune insertion bound. Decoded values pass adapter
validation plus an exact Unicode identity comparison, preventing case, width or
NFC repair from accepting decoded values Go rejects. Whole-domain validation
retains bidi checks and empty/root-dot placement.

This repairs those legacy ACE branches. Full Go Unicode-15 mapping/status,
stream-safe NFC and bidi data, compatibility-mapped ACE prefixes and adapter
input/output limits remain separate gaps. Raw Unicode SNI, eager issuance and
RSA/token cache boundaries remain as recorded below. No dependency/public API
change. Independent source/peer review and direct rustfmt only; no tests/builds,
hostname/handshake/process or feature qualification. Three gates stay open.

### HTTP/2 GOAWAY stream identity and graceful selection — 2026-10-18

The native h2 first-SETTINGS guard now carries the successfully decoded
offending frame's stream ID through private error metadata into its error
GOAWAY. Decoder failures do not acquire invented frame metadata. The new
default-off graceful-current-ID feature, enabled only by API full, sends the
current highest decoded client HEADERS ID without the MAX-ID/PING phase.
Tracking precedes stream-concurrency refusal. Existing accepted streams retain
their lifetime; higher new stream frames are discarded and discarded DATA uses
the existing connection-credit return path. Final idle close retains the
advertised ID rather than sending a lower second GOAWAY after a refused stream.

Client and feature-off behavior retain the selected upstream paths. First-frame
error IDs are clamped after a prior GOAWAY to preserve h2's nonincreasing-ID
invariant. General decoder-stage errors and HEADERS rejected before dispatch
still have Go phase/maximum-ID differences. Go's 30-second idle accounting and
one-second close delay after GOAWAY output/drain remain source work, along with
preface read/write ordering and per-stream deadlines. Independent source/peer
reviews and direct rustfmt only; no tests/builds/Cargo, frame/client/process,
embedding or package qualification. All three gates remain open.

### HTTP/2 server limits — 2026-10-18

Ordinary ACME H2 now sets the pinned Go server defaults explicitly: 250
concurrent streams, a 1 MiB maximum frame, 1 MiB stream/connection receive
windows and a 1 MiB + 320-byte header-list limit. Hyper previously supplied
200 streams and 16 KiB frame/header limits. Noise now also sets the selected
x/net server's 1 MiB frame and receive windows, and explicitly advertises its
4096-byte header table alongside the existing matching stream/header limits.

These are configured limit values, not a claim of identical SETTINGS bytes,
flow-control replenishment, decoder behavior or resource use. No public API or
dependency version changed. Source review/direct rustfmt only; no tests/builds,
frame/process/client/wire-only or memory qualification. Three gates stay open.

### ACME hostname policy and cache identity — 2026-10-18

Native ACME cache/bootstrap configurations now bind an immutable hostname
policy. Ordinary certificate selection requires a nonempty, multi-component
SNI name, Lookup normalization and an exact normalized whitelist match before
returning the cached certificate. Sole TLS-ALPN challenge requests normalize
their token key and bypass the ordinary whitelist, as in autocert. Renewals
retain the bound policy. Public unbound resolver constructors, non-ACME TLS and
non-full embedding defaults retain their behavior.

API and CLI share an additive full-feature cache-name helper: normalize using
nontransitional UTS #46 with STD3/hyphen/joiner/bidi checks and no DNS-length
check, then remove one final root dot for the cache key. Whitelist comparison
retains that dot. Certificate reads/writes, order identifiers and TLS-ALPN
challenge SANs/keys/cleanup use the normalized identity; account filenames stay
unchanged. The direct optional idna 1.1.0 edge reuses the locked package and is
activated only by full. No dependency version was updated.

This is a bounded hostname repair. Selected Go uses Unicode 15 tables while
the locked Rust adapter uses newer ICU data. rustls validates/lowercases SNI
before the resolver, so raw Unicode SNI and TLS alert/error fidelity remain
different. Invalid configured names can fail the eager CLI cache/issuance path;
Go silently omits invalid whitelist entries and issues lazily. The API loader
retains its prior invalid-name fallback while its bound policy denies ordinary
selection. RSA/token disk-cache variants and cached-certificate/name validation
remain unqualified. Independent source review/direct rustfmt only; no tests,
builds/Cargo, handshake/renewal/process or wire-only qualification. Three gates
remain open.

### Ordinary HTTP/2 initial-frame deadline — 2026-10-18

The private H2 input observer now starts a separate two-second budget when it
observes the complete client preface. It tracks the first nine-byte frame header
and its declared payload without allocating or reading ahead of Hyper, including
partial input, zero-length frames and preface/frame bytes in one read. Completion
of a SETTINGS frame disables that initial-frame budget; active requests retain
their existing lifetime. The independent ten-second preface budget remains.

The selected h2 0.4.19 source is now vendored with a default-off server-only
first-SETTINGS guard, activated by API full. It rejects decoded non-SETTINGS
frames, including unknown/PRIORITY frames, through the existing PROTOCOL_ERROR
GOAWAY path before request dispatch. SETTINGS ACK passes the type guard and
retains ordinary validation. Decoder errors retain precedence; partial HEADERS
awaiting CONTINUATION keep the two-second budget live. Client and feature-off
codecs retain their behavior. The workspace patch and lock use the same package
version; MIT/BSD notices are retained and both images include the h2 license.

The newer GOAWAY section above supplies offending-frame identity and native
current-ID graceful selection, with remaining decoder/race boundaries recorded
there. Receipt versus processed-frame timing, SETTINGS-before-preface-read
ordering, idle and per-stream differences remain. Full consumers outside this workspace need the vendor patch;
the custom feature is not activated by the known wire-only embedding profile.
Independent peer/source review and direct rustfmt only; no tests/builds/Cargo,
validators/probes or frame/process/package/embedding qualification. All three
parity gates remain open.

### ACME ordinary TLS HTTP/2 — 2026-10-18

ACME cached, bootstrap and renewed configurations now advertise the selected
Go order h2/http1/acme-tls. Challenge certificates are selected only for a sole
acme-tls/1 offer; mixed offers retain normal certificate selection. HTTP-01
keeps an empty challenge resolver internally, so a sole challenge offer cannot
fall back to the ordinary certificate, while its public resolver field remains
None. Static/self-signed and remote gRPC profiles remain separate.

Raw TLS dispatches negotiated h2 before HTTP/1 header sniffing into a private
Hyper HTTP/2 Router driver, retaining TLS and peer extensions. H2 becomes active
before its preface, avoids HTTP/1's late-header gate and retains active tasks
after the shared HTTP shutdown wait expires. An independent ten-second budget
observes the first 24 input bytes without consuming ahead of Hyper; it also
expires if initial SETTINGS output is blocked and is disabled after the preface
is observed. The existing Hyper http2 feature is explicitly enabled for the
wire-only build. No dependency version or public field/signature changed.

This repairs negotiated serving/ALPN source gaps, not complete Go H2 behavior.
Confirmed remaining source gaps include Hyper's SETTINGS-before-preface-read
phase, two-stage MAX-ID/PING GOAWAY versus Go's immediate current-ID GOAWAY,
idle ConnState/post-drain handling and idle/per-stream deadlines. The later
initial-frame timeout section above supplies that budget and records the
first-frame SETTINGS source repair and its remaining wire differences. The newer
hostname section above supplies the bounded ACME SNI/HostPolicy/cache repair and
records its remaining IDNA/TLS boundaries.
Existing two ALPN expectation vectors were updated without executing them.
Independent bounded source reviews/direct rustfmt only; no tests/builds/Cargo,
validators/probes or handshake/frame/renewal/client/process/feature qualification.
All three parity gates remain open.

### Native ordinary HTTP shutdown — 2026-10-18

Production now uses an additive serving entrypoint with an opaque HTTP shutdown
control. Existing public ServeHandle/ServeConfig fields and serving signatures
remain compatible; the original embedding path retains its behavior. Native
plaintext/debug serving uses HTTP/1 as pinned Go does. Debug and main listeners
share one three-second deadline, in that order. Listener admission stops before
waiting; timeout logs an error and continues shutdown without aborting active
connection tasks. GC and maintenance stop before this phase, followed by native
map draining and sequential graceful local/external RPC shutdown.

New connections retain Go's strict integer Unix-second age rule instead of
being closed immediately by stock framework shutdown. Fresh/partial-header
connections survive an expired shutdown context; late valid requests are
rejected before routing. A first-nonempty-write gate covers parser-generated
error responses, while empty flushes do not change connection state. Raw Noise
admission becomes active before writing 101 and leaves HTTP accounting only
after its successful flush; upgraded protocol lifetimes are separate. Weak
tracking entries are removed at completion/drop without holding the registry
lock while upgrading or dropping connection references.

Bounded independent source reviews/direct rustfmt only; no tests/builds/Cargo,
validators/probes or process/client/feature qualification. Finer reused-request
malformed-header/write races, exact polling/RNG/scheduling, body/read/write
deadlines and resources remain unqualified. The newer ACME HTTP/2 section above
supplies negotiated serving and records remaining H2 source gaps. Previously
detached durable workers remain outside existing drain
accounting. All three parity gates stay open.

### Native custom-decoder error context — 2026-10-18

Native custom scalar, typed map-key and deferred SSH receiver failures now
carry their Go receiver type, JSON kind, original packed position/pointer and
cause. Delayed SSH source/destination kind errors point to the entire list;
delayed SSH test-source parse errors point to the entire test. Inner string
and float64 errors retain their inner type and location without an additional
method wrapper. Headscale's via/first-letter-tag rewrites precede rendering,
including numeric errors whose actual pointer contains `/via/`.

Native duplicate-name and numeric-range diagnostics now include the Headscale
parse prefix exactly once. Duplicate syntax failures retain priority and bypass
semantic rewrites. Nonnative errors/public APIs are unchanged. Independent
bounded source reviews/direct rustfmt only; no tests/builds/Cargo/validators,
probes or recapture. Randomized Go modal wording, unordered-map offender choice
and runtime/resource behavior remain unqualified. Three parity gates stay open.

### Native gRPC graceful shutdown — 2026-10-18

Production local and external gRPC listeners now receive private shutdown
signals through Tonic's graceful server path. They stay available through
native map draining, then stop and await local RPC completion followed by
external RPC completion before state teardown, without a timeout as in Go.
The existing private compatibility test wrappers retain their signatures.

This does not establish a global drain of mutation workers detached by earlier
RPC cancellation. The newer ordinary HTTP implementation above supplies the
shared three-second phase; Go excludes hijacked Noise from that HTTP wait.
No universal Noise registration drain is inferred. Source review/direct
rustfmt only; no tests/builds/Cargo/validators/probes or active-RPC/TLS/
cancellation/shutdown/process qualification. Three gates remain open.

### Native hosts/groups receiver completion — 2026-10-18

Native Hosts and Groups now complete their semantic validation when their own
JSON receiver closes, before the next policy field is decoded. Complete strict
syntax validation, Hosts' typed string-map decoding and Groups' generic-number
checks retain precedence. Shared existing helpers preserve Groups' name/type/
recursive-reference/username phases and Hosts' name/address checks. Semantic
failures carry the outer v2.Hosts/v2.Groups type, original packed position and
field pointer. Whole-receiver null remains accepted.

The completion pass reads the retained receiver span into a shallow projection
of strings and runtime-type placeholders; it does not construct a recursively
owned tree for rejected nested group values. Original source/prepared bytes,
public APIs and nonnative behavior remain unchanged. Go's unordered map loops
can select a different offender when several entries fail; randomized modal
wording, broader custom decoders and runtime/resource behavior remain
unqualified. Bounded source reviews/direct rustfmt only; no tests/builds/Cargo,
validators/probes or recapture. All three parity gates stay open.

### Native typed JSON kind ordering — 2026-10-18

Native policy decoding now rejects wrong struct/map/list/boolean kinds after
the opening token, before walking a rejected container or reaching later
fields. Opening-token depth and string syntax checks retain their priority.
String and Prefix text decoders instead validate the complete value before
reporting the wrong kind, matching their selected ReadValue behavior. Custom
JSON receiver prepasses remain intact.

Native shape mappings now include hosts, ACL destinations, capability maps and
raw-message lists, randomizeClientPort and named SSH/capability list elements.
Kind errors retain the inner Go type and packed-source pointer-or-offset
envelope. Public/nonnative behavior is preserved. Go's randomized modal wording,
broader custom semantic phase/order and resource behavior remain unqualified.
Source review/direct rustfmt only; no tests/builds/Cargo/validators/probes or
recapture. Three parity gates remain open.

### Native shutdown before response headers — 2026-10-18

Shutdown while a Noise request awaits its router response now explicitly
resets the stream with INTERNAL_ERROR. Previously that branch only marked
cancellation and dropped the unanswered SendResponse, whose h2 fallback uses
CANCEL. The selected Go HTTP/2 server uses INTERNAL_ERROR for the map-stop
write deadline. The reset-wait borrow ends before sending the explicit reset;
successful responses, peer resets and native drain tickets are unchanged.
Independent bounded source review/direct rustfmt only; actual frame delivery,
cancellation and shutdown/process behavior remain unqualified. Three parity
gates remain open; no tests or builds ran.

### Native shutdown cancellation and drain — 2026-10-18

Native shutdown now retains listener handles, stops maintenance and ephemeral
GC, rejects new native map work, and interrupts direct Noise HTTP/2 body and
flow-control waits. Owned native map mutations and stream guards retain drain
tickets through reconnect grace, disconnect persistence and publication before
the batcher and database are torn down. A closed-state recheck under the GC
timer lock prevents a scheduler from installing a timer after shutdown drains
the timer map. No synchronous state guard crosses an await.

This covers native flat map work and direct Noise transports. Separately
detached registration/OIDC/admin mutations, custom adapters and keyed/public
tracking helpers do not gain a global drain. Final control-frame flushing has
one nonblocking opportunity; delivery is not guaranteed. Persistence draining
has no timeout. Independent source reviews/direct rustfmt only; no execution,
shutdown/cancellation/resource/process or feature qualification. Three parity
gates remain open.

### Native JSON depth encounter order — 2026-10-18

Native policy parsing now enforces the selected JSONv2 10,000-container limit
at typed/container and custom ReadValue encounters, with outer depth, actual
packed-source offsets and JSON pointers. It no longer applies the v1-style
whole-buffer depth check before typed decoding, so a later deep value does not
preempt an earlier unknown-field or custom string error. Initial full HuJSON
grammar validation remains; existing nonnative scanner behavior is retained.

Raw span extraction is iterative but its temporary stack can grow before the
custom ReadValue depth gate. General wrong-container semantic errors, returned
deep-value operations and runtime memory/resource behavior remain unqualified.
Independent source review/direct rustfmt only; no tests/builds/Cargo/validators,
probes or recapture. Three parity gates remain open.

### SQLite allocation high-water preservation — 2026-10-18

Native legacy SQLite migrations now preserve AUTOINCREMENT floors while
rebuilding nodes (migration 9) and nodes/pre-auth keys (migration 12). Renaming
and dropping the old tables otherwise discards sequence entries for previously
allocated, subsequently deleted IDs. Runtime wrappers snapshot the affected
floors in TEMP tables and restore the maximum of the original floor, current
sequence and surviving IDs before each migration's original ledger transaction
commits. This includes all-rows-deleted states and protects the floor across a
failure between migrations. Original SQL files, descriptions and checksums are
unchanged. The converter subsequently sees the preserved floors.
Floors already lost by a previously completed migration cannot be inferred
from surviving rows; recovery requires the original database backup.

File-backed migration sessions close on drop; memory databases retain their
connection and ordinary SQLx transaction rollback behavior. Bounded independent
source review found no defect. Direct rustfmt only; no tests/builds/Cargo/
validators/probes/recapture or allocation/import/restart/cancellation/feature
qualification. All three parity gates stay open.

### Native grant-via error remapping — 2026-10-18

After strict ReadValue succeeds, native Tag semantic failures now follow Go's
case-sensitive JSON-pointer `/via/` remap before its first-letter-tag fallback.
This preserves the selected `via can only be a tag` message and the pinned
fallback `tagOwners[last-token]` behavior for differently spelled input fields.
Syntax errors keep priority. Public String parsing and whole-via container type
handling are unchanged. Bounded source review/direct rustfmt only; no execution
or general semantic-wrapper qualification. Three parity gates remain open.

### Native packed-source Unicode diagnostics — 2026-10-18

The native byte parser now reproduces HuJSON metadata removal followed by
Standardize/Pack with a flat arena and explicit task stacks. It retains kept
Name/Value extras, original composite tails, literal spellings and the non-nil
last-AfterExtra marker that can produce a synthetic blank comma after deletion.
Removed metadata owns and removes its own extras; exact `app` subtrees remain
opaque to metadata removal. The previous whitespace-compacting helper is gone.

Strict retained-string parsing now reports invalid UTF-8 and surrogate failures
in encounter order with Go-shaped causes, escaped diagnostic fragments, JSON
pointers and byte offsets into that actual packed buffer. Custom ReadValue
subcursors retain outer positions and nested pointer suffixes. Invalid names use
the containing-object pointer. A byte quoting helper preserves malformed bytes
as hexadecimal escapes while keeping pinned Go Unicode printability rules.
Original operator bytes remain separately retained; public String parsing and
semantic policy rules are unchanged.

This supplies source implementations for the earlier native Unicode position
and metadata-compaction residuals. Broader JSONv2 semantic type wrappers, modal
wording, malformed HuJSON diagnostic-byte transport and resource/runtime parity
remain unqualified. Independent bounded source reviews found no further defect.
Direct rustfmt only; no tests/builds/Cargo/validators/probes/recapture or feature/
process/reload/rollback qualification. All three parity gates stay open.

### Native initial-map session ordering — 2026-10-18

Native flat streaming requests now acquire their session and cancel ephemeral
GC before validating/building the initial map, matching Go Connect followed by
batcher AddNode. Private quiet acquisition retains the existing counters,
generation and ownership epoch. Request and connection changes remain deferred
until the complete initial MapResponse is constructed, then publish in that
order while the node incarnation is still current. Failed generation suppresses
both changes and releases the acquired guard through existing reconnect-grace,
disconnect and GC handling. It also avoids introducing an ended metric before
the serving loop starts. Public tracking helpers and keyed compatibility retain
their immediate-publication behavior.

This supersedes the earlier native validation-before-Connect approximation.
Independent bounded source review found no further actionable defect.
No synchronous state guard crosses an await. Source/direct rustfmt only; no
tests/builds/Cargo/validators/probes/recapture or cancellation/concurrency/GC/
process/client qualification. All three parity gates remain open.

### SQLite backup precedes migration writes — 2026-10-18

Native file-backed legacy/import startup now completes a logical main-database
backup before ledger adoption, repair updates, foundation DDL or version stamps.
The earlier backup only captured the already-migrated intermediate state.
Standalone conversion retains its own backup, now taken before auxiliary schema
initialization. Successful native conversion therefore retains two snapshots.

Backup destinations are reserved with exclusive creation and Unix 0600 mode;
VACUUM INTO otherwise accepts an existing empty file. The copy runs outside an
explicit transaction, and its session closes before later pool-based work to
support a single-connection pool. Failure prevents later migration writes on
that path. Failed/cancelled destinations are retained because unlinking can
race the SQLite worker; only successful copies are usable backups.

These are logical primary snapshots after connection setup PRAGMAs/ATTACH, not
pre-open byte copies. Sidecars are not backed up, and independent external
writers are not serialized across the full upgrade. Bounded peer source review
found no introduced defect. Direct rustfmt only; no tests/builds/Cargo/validators,
probes/recapture or recovery/import/restart qualification. Three gates stay open.

### Pending owner repairs preserve nil tags — 2026-10-18

For supported SQLite/Postgres node schemas that still need tagged-owner cleanup,
Rust now executes Go's exact predicate excluding `tags='null'`, then records the
original SQLx completion metadata in the same preparation transaction. Both
the SQLx version and exact Go migration ID must be absent. This preserves valid
nil-tag storage instead of rewriting it to `[]` to accommodate historical SQL.
Column checks keep the correction scoped to the expected node schema. Existing
or adopted repairs remain untouched; fresh no-nodes startup retains its ordinary
empty-table migration path. The existing normalizer consequently does not run
for the corrected supported import state. No migration SQL/checksum changed.
Bounded independent source review found no further actionable defect in these
pending repairs, SQLite adoption or raw-container method dispatch.

Source/direct rustfmt only; no tests/builds/Cargo/validators/probes/recapture or
runtime/import/restart/feature qualification. All three parity gates stay open.

### Pending Postgres zero-expiry repair timezone — 2026-10-18

When a supported existing Postgres database still needs the zero-expiry repair,
Rust now executes Go's exact unqualified `expiry < '1900-01-01'` predicate. The
immutable SQLx migration hardcodes UTC, which differs under a non-UTC native
session. This execution and its original SQLx completion record are committed
together under the foundation lock. It runs only when neither the SQLx version
nor exact Go repair ID exists and the nodes table is present. Already-applied
repairs remain untouched; fresh databases retain the ordinary empty-table path.
This is execution of a pending compatible repair, distinct from Go-ID adoption.
No migration SQL/checksum or global timezone setting changed.

Source/direct rustfmt only; no tests/builds/Cargo/validators/probes/recapture or
timezone/import/restart/feature qualification. All three parity gates stay open.

### SQLite one-time repair adoption — 2026-10-18

The SQLite path outside the file-backed current-schema shortcut now adopts
four repairs only when their exact Go migration IDs exist. This covers supported
older Go imports, ledger-only imports and in-memory schemas without replaying
already-completed repairs over subsequent administrator changes. Pending repairs
still run normally. Original SQLx metadata/checksums are retained; dirty, unknown
or mismatched records reject before adoption. A writer transaction atomically
installs the obsolete node-key index pair's final dropped-index state and ledger
rows. Null-tag normalization is skipped once its owner repair is applied/adopted.
The same embedded migrator supplies both ledger metadata and later migration
execution. No migration SQL/checksum or converter behavior changed.

Source/direct rustfmt only; no tests/builds/Cargo/validators/probes/recapture or
runtime/import/restart/feature qualification. All three parity gates stay open.

### Raw-container policy methods — 2026-10-18

Native byte policy decoding now sends object/array input directly to the custom
Protocol, ACL Action, SSH Action and SSHCheckPeriod methods after the complete
ReadValue syntax pass. These methods inspect raw text for every JSON kind, so
their rejection must occur before decoding subsequent policy fields. The prior
generic-container walk could defer rejection until later schema conversion.
ProtocolPort retains its separate any-decoding and numeric-overflow precedence.
Existing public String-parser behavior remains unchanged.

Source/direct rustfmt only; no tests/builds/Cargo/validators/probes/recapture or
runtime/feature/process qualification. All three parity gates remain open.

### Custom policy decoder error ordering — 2026-10-18

Native byte policy decoding now performs a complete syntax/string/name pass at
custom JSON receiver boundaries before running element semantics. This follows
Go JSONv2 ReadValue: a later invalid UTF-8 string, unpaired surrogate or duplicate
name inside the receiver can precede an earlier alias/owner semantic error.
The iterative pass retains numeric tokens and restores the parent cursor after
the receiver. Ordinary policy/ACL/grant/SSH struct fields keep encounter-order
unknown-name handling.

SSH source/destination lists parse all aliases before rejecting their supported
kinds. SSH policy-test entries validate the complete custom receiver, decode all
raw fields, then report a source-alias semantic error. String/type errors retain
their decoding phase. These changes supersede the corresponding custom-container
and SSH test source-order residuals. Exact JSONv2 pointer/offset decoration and
broader decoder type-wrapper diagnostics remain unqualified.

Source/direct rustfmt only; no tests/builds/Cargo/validators/probes/recapture or
runtime/feature/process qualification. All three parity gates stay open.

### Fresh debug policy source reads — 2026-10-18

Native debug policy requests now read the configured source on every request.
File mode returns current file bytes, including malformed UTF-8 or a newly
edited policy not yet accepted by the manager. An empty configured path returns
an empty HTTP 200. Database mode fetches the latest stored row, returning an
error for no row but allowing an empty existing row. Unsupported modes return an
error. Private asynchronous source adapters are registered by the existing
admin-service builders; WireState fields and public signatures are unchanged.
Adapter locks are released before I/O, and source reads do not replace compiled
policy. Embedders without a configured adapter retain the stored-source fallback.

Source/direct rustfmt only; no tests/builds/Cargo/validators/probes/recapture or
runtime/process/feature qualification. All three parity gates remain open.

### Byte-preserving native policy files — 2026-10-18

Native file startup and reload now read bytes. A byte-oriented HuJSON pass
validates the complete grammar and UTF-8 in comments before removing metadata.
Legacy-decoded metadata names beginning with # are removed before strict typed
decoding, allowing malformed string bytes only where Go discards that metadata.
Retained strings still require valid UTF-8. The parser uses an explicit task
stack rather than a recursive AST.

PolicyStore retains original bytes separately from valid compilation source.
Existing String APIs remain stable; raw() returns None when the original source
cannot be represented. Additive raw_bytes() and source_for_compilation() expose
their respective meanings. Successful String replacement clears the byte
sidecar; rejected replacement retains prior source. Native gRPC policy retrieval
rejects unrepresentable strings at its marshaling boundary. Debug policy output
uses the original bytes; configured native source reads are described above.

HuJSON module version, source hashes, BSD license and notice are retained in
headscale-api-acl. No dependency version changed. Exact retained-string JSONv2
offset/pointer diagnostics, broader decoder type-wrapper behavior, imported
database text boundaries and arbitrary malformed diagnostic-byte transport
remain incomplete or unqualified. Source/direct rustfmt only; no tests, builds, Cargo commands,
validators, probes, recapture or runtime/reload/rollback/feature qualification.
All three parity gates remain open.

Independent bounded source review found no further actionable regression in
the byte-policy changes. This is source review, not runtime qualification.

### Native non-streaming maps and Postgres repair adoption — 2026-10-18

The native flat map route now returns an empty HTTP 200 after committing and
dispatching every non-streaming request, including requests without OmitPeers.
It no longer waits for another peer or builds a full map in that branch. The
public keyed compatibility route retains its existing response contract. The
existing flat-route assertion was source-adjusted to check both the empty body
and committed endpoint update; it was not executed.

Postgres foundation import now adopts four one-time data repairs only when
their exact Go migration IDs prove they already ran. This preserves later
administrator expiry changes instead of clearing them again. Adoption retains
the original SQLx checksums/descriptions and rejects dirty, unknown or mismatched
records. When both obsolete node-key uniqueness migrations are pending, their
final dropped-index state and ledger rows are installed transactionally, avoiding
a transient unique index that rejects valid Go rows. Null-tag normalization runs
only when its historical owner repair remains pending. An absent or empty Go
ledger receives the complete fresh ledger in the final version transaction.
Migration SQL and checksums are unchanged.

Source review and direct rustfmt only. No tests, builds, Cargo commands,
validators, probes, fixture recapture or runtime/import/restart qualification ran.
The two P0 gates and CLI P2 gate remain open. Directly borrowed Postgres
connections retain caller-owned cancellation cleanup; pooled migration sessions
already close on drop.

### Full-input policy construction and retained rekey sessions — 2026-10-18

Native SQLite/Postgres startup now loads the allocator, nodes, users and raw
policy before constructing the manager. Initial installation seeds final users
and retained node inputs without a provisional compile, then compiles once,
including nodeAttrs. Failed construction returns its first error with partial
diagnostic events and no empty-policy rollback logs. Ordinary replacement keeps
its prior restore/recompile behavior. Boot warnings follow successful initial
compilation. Offline candidate compilation shares initial-install semantics.
This replaces the native deferred-diagnostic workaround and its constructor
failure-event source gap. The optional public deferred APIs remain available.

Native policy modes now compare exact text, including whitespace; unknown modes
load no policy. Exact-empty source means no policy, while nonempty whitespace is
parsed. Raw source and persisted update times are retained. Startup error phases
use initializing IP allocator, loading nodes/users/policy, and initializing policy
manager with parse/reference subcontexts. Direct node-list and policy-user-list
errors use the native database renderer. Row association/helper, malformed-byte,
rare OS/driver/parser error text and SHA-256/Go-deephash/nil/type projection
boundaries remain unqualified.

Native CheckPolicy and its admin-validation mirror now emit constructor policy
test warnings after successful candidate compilation and before the subsequent
hard assertion rejection. The public compile helper remains warning-free; direct
CLI validation retains its existing explicit warning boundary. Also corrected a
preexisting bare return in the Result-returning auth-completion publication path
to return Ok on lost presence, matching that path's no-longer-current outcome.

Open map sessions now resolve their current node key by the guard's stable node
ID after every relevant wake. A same-ID rekey preserves session counters and
generations. Private ownership epochs protect active-count drops, queued/deferred
state releases and post-save offline dispatch from retiring a replacement node.
Retirement occurs inside every record writer and after each queued batch item,
including same-key/different-ID replacement and delete/reinsert in one batch;
notification follows lock release. Captured disconnect views still select peer
recomputation. GC timers carry node/machine/epoch identity, including nodes that
have never connected, and revalidate after the machine guard and before local
post-persistence deletion. No synchronous lock crosses an await. Already-started
external custom-store persistence/deletion effects cannot be revoked through the
unchanged trait; this ownership guarantee covers local state/dispatch/GC.

Keepalive timing now uses Go's 50-second base plus one uniform 0..8999ms session
jitter. One absolute idle deadline survives wakes that emit no frame; an elapsed
deadline cannot be starved by irrelevant ready wakes. A subsequent native Noise
body pull follows the preceding DATA handoff, anchoring reset after that write.
Initial frames remain immediate and nonstreaming behavior is unchanged. Two
existing paused-time advances were source-adjusted to cover the jitter bound.
OS entropy differs from Go's PRNG; no random-sequence equality is claimed. Outer
Hyper/body-consumer write completion, initial setup stalls and actual timer/
flow-control/cancellation/backpressure behavior remain unqualified.

Source/direct-rustfmt and independent source review only. No tests/builds/Cargo,
validators/probes/fixture recapture or paired behavioral evidence ran. All three
parity gates remain open.

### Constructor diagnostics, Noise cancellation and parser aggregation — 2026-10-18

Successful native SQLite/Postgres preparation now defers policy diagnostic
events until policy, users and hydrated nodes are available. It emits one final
snapshot before boot policy-test warnings. The subsequent first retained-input
bind suppresses only an identical no-change trace; changed snapshots and later
runtime no-change traces remain observable. A diagnostic-only final nodeAttrs
compilation gates aggregate/no-change output; a failure retains stage events
without propagating a new error or installing serving attrs/caches.
Offline candidate construction also defers its provisional nil-policy
compilation. Both paths reuse the serving
registry's exact node-input projection. Serving validation/cache/publication
order is unchanged. Failures before diagnostic completion still do not replay
Go's possible partial constructor events; SHA-256 versus Go deephash and retained
nil/type distinctions remain diagnostic boundaries. This supersedes the prior
successful-constructor provisional-event source residual only.

**Transport correction:** production Noise uses h2::server directly, so the
preceding Hyper-only explanation did not establish its reset behavior. A private
map response extension now carries the existing exact-session sticky cancellation
flag and an already-subscribed generation watch. The Noise sender selects this
signal during response-body polling and outbound DATA capacity waits, explicitly
sending RST_STREAM(INTERNAL_ERROR) on deletion. Body errors also explicitly reset.
The sticky flag preserves cancellation through rapid delete/reinsert without
treating ordinary rekey/shutdown as deletion. No background task or extra frame
buffer was added. The existing direct-body deletion assertion was source-updated
from clean EOF to body failure, without execution. This supplies the previously
missing Noise blocked-capacity reset implementation; actual socket delivery,
flow-control, client cancellation, reconnect and shutdown remain unqualified.

Native HuJSON schema validation now appends the undefined tag-chain error after
direct owner-reference errors, matching pinned parse-time validation. An iterative
heap traversal drops cycle edges and retains the missing-reference failure. Error
aggregation follows Go's zero/single/multiple boundary, including opaque wrapped
ACL/SSH test-shape groups. Empty-assertion and disallowed-protocol messages were
source-aligned. These changes are scoped to HuJSON; the public TOML extension
retains its prior validation/diagnostic contract. Go's randomized map iteration
and other existing validation wording/order remain unqualified. Earlier claims
that native tag flattening must move into runtime are superseded: pinned Go
already validates those chains before compilation.

Independent source reviews and direct rustfmt only. No tests, builds, Cargo,
validators, probes, fixture recapture or paired process evidence ran. All three
parity gates remain open; historical reports do not qualify this source batch.

### Bounded completion audit and process-suite wiring — 2026-10-18

Three independent source audits revisited the remaining release, Postgres and
CLI gates. They established three concrete production changes in this pass:
empty-peer policy-frame profiles, policy-manager diagnostic events and deleted
map-stream termination. This is a bounded finding, not a count of every patch
that qualification may expose.

Policy recompilation now emits the four filter/tag/route/exit change events,
old/new rule or map counts, aggregate change flags and a no-change trace. Private
snapshots use the compiled projections and retained policy/source shapes;
diagnostic comparisons do not control serving changes or cache invalidation.
Stage snapshots advance before fallible nodeAttrs, with aggregate output only
after successful refresh, including the pre-registry no-node path.

Fingerprints are computed SHA-256 values of Rust snapshots, not Go's seeded
deephash algorithm; exact digest equality is not claimed. Missing Go nil/type
distinctions, Rust's staged constructor emitting provisional events and existing
tag prevalidation/error ordering remain diagnostic source boundaries. Therefore
the missing-event family has implementation, while complete startup diagnostic
lifecycle/output parity remains unresolved and unqualified.

Policy frames now omit UserProfiles when their current visible peer set is
empty, following pinned mapper.policyChangeResponse. Frames with visible peers
and other update kinds retain their existing profile behavior. This supersedes
the recorded empty-peer policy-profile source residual; the earlier paired
report remains historical evidence of the discrepancy, not a new pass.

The real-client CI job now selects all 16 existing serve_postgres_runtime_
process cases rather than one admin smoke. It keeps the explicit Postgres URL
and feature, runs serially, and fails on the helper's skip marker, including
database-creation skips. No process case was executed during this change.

Deleted-node map streams now return a body error instead of clean EOF. Locked
Hyper maps that error to HTTP/2 INTERNAL_ERROR, matching pinned Go's immediate
write-deadline reset for an actively polled stream. This is source reasoning,
not a recaptured paired result. Hyper can wait for outbound flow-control
capacity before polling the body, so this does not reproduce Go's out-of-band
reset when an unread peer blocks writes; that transport boundary remains open.

The release audit found no additional missing core release fix within its
bounded source/evidence review. Existing paired reports predate the accumulated
implementation batch. Wider historical upgrade/reopen, wire SSH omission,
mutation/restart/churn and current startup output remain unqualified. Deleted
map streams' prior EOF discrepancy now has the narrow source repair above;
blocked-write reset behavior remains unresolved. All three backlog gates remain
open; tests/builds stay paused at the user's request.

### Measured timestamp scan-error columns — 2026-10-18

SQLite expiry projections now carry the table's measured pragma_table_info cid
and physical expiration/expiry name alongside private type/value metadata.
Typed scan errors use that context to render Go's database/sql column envelope,
including different fresh and imported table order. Missing/unsupported context
retains the conversion cause. No ordinal is hardcoded.

Independent source audit confirms ordinary pinned API-key, preauth-key and node
model reads use SELECT *; association preloads run separate queries. That makes
the measured cid appropriate for supported plain Headscale tables. Joined or
reordered projections, generated/hidden/virtual columns, custom/case-altered DDL,
earlier malformed fields and repeated scan-error aggregation remain unqualified.
Postgres's existing timestamp projection and generic error boundary still need
qualification. This supersedes the ordinary SQLite missing-column-envelope
source residual without establishing process output equality.

A separate source audit followed numeric-ID preauth expire/delete from gRPC
through persistent stores to both database adapters. Those paths already mutate
without loading timestamp fields, matching pinned Go; no fix was warranted.
Source/direct-rustfmt and independent source review only; no tests/builds/Cargo,
validators/probes/fixtures or gate closure. All three parity gates remain open.

### SQL scan-phase correction and legacy timestamp conversion — 2026-10-18

**This corrects the preceding timestamp implementation notes.** Gorm's normal
model reads call Rows.Scan into pooled `**time.Time` before the model setter.
Unrecognized driver strings and scalar numeric/blob values fail there; the
now.Parse string setter is not reached. Removed the incorrectly added Gorm
fallback/default/local-time corpus, timezone loader/archive work and now-specific
notices. Native row reads now accept only the pinned SQLite driver's ordered
time.String and nine timestamp layouts. Their UTC instant projection does not
need a timezone archive. Earlier missing-Gorm-fallback/TZ fallback claims are
superseded, not completed by the removed code.

Typed timestamp errors preserve the native unsupported-Scan cause for strings,
int64, float64 and byte slices. The native renderer avoids Rust's synthetic
column envelope but does not guess Go's SELECT * column ordinal/name, which
varies by schema history. Native Go primary rows reject integer timestamps;
Rust-managed schemas retain explicit legacy integer compatibility while their
_sqlx_migrations marker remains.

Before primary publication, legacy SQLite conversion now normalizes integer
time cells on TEMP copies inside the rebuild transaction. It covers creation,
update, deletion, expiry and last-seen columns across the five primary tables.
Integer seconds become Go-driver-readable four-digit UTC TEXT; out-of-range
years reject. Existing valid TEXT and fractional precision remain unchanged;
malformed TEXT/REAL/BLOB reject before schema/Go ledger/version publication.
Indexed256-row batches bound row-count storage. Backup, rollback and migration
session isolation remain; the earlier committed sidecar copy is unchanged.

Source/direct-rustfmt and independent source audit only. No tests/builds/Cargo,
validators/probes or fixture recapture. Native error envelopes, imported/large/
malformed data, custom declarations, rollback/cancellation/sidecar recovery and
actual Rust-to-Go reopen remain unqualified. All three parity gates remain open.

### Ordered persisted timestamp parsing and node expiry — 2026-10-18

**Superseded where it assumes a Gorm SQL-read fallback; see the scan-phase correction above.**

Persisted timestamp parsing now follows the pinned SQLite driver's ordered
layouts before Gorm's ordered now.Parse fallback. The parser implements the
layout tokens, strict literals, independent weekday parsing, fraction rules,
current-date defaults and normalized calendar assembly used by that corpus.
Driver dates retain UTC behavior; fallback dates use one Go-style Unix local
zone snapshot. Current/local-dependent results freeze at row decoding so later
expiry checks cannot reinterpret them on a different day or year.

The private timezone helper loads bounded system TZif v1/v2/v3 data, retaining
historical transitions, ordered abbreviation lookup and POSIX footer rules.
Current-field defaults, local wall-clock correction and explicit-offset/name
matching all use that same snapshot. No dependency/features or unsafe code were
added. Go embedded/GOROOT archive fallback, non-Unix initialization, byte and
Chrono-range boundaries remain incomplete or unqualified.

Node expiry now uses the typed SQLite storage projection and a canonical row
adapter for both backends, so accepted Go text reaches existing hydration as a
fixed instant. NULL and exact Go zero time remain distinct; malformed non-NULL
expiry fails row decoding. API/preauth is_expired(now_unix) convenience methods
also prefer the parsed deadline before falling back to legacy integer seconds,
including when SQLite cannot project a numeric timestamp.

This supersedes the earlier missing ordered-layout/current-local/default corpus
residual with source implementation. It does not establish runtime equivalence.
Source/direct-rustfmt and peer source review only; no tests/builds/Cargo,
validators/probes/fixture recapture or import/restart/client/process/security
qualification. Exact scan errors and platform/package feature behavior remain
unqualified. All three parity gates stay open.

### Provider requests and SQLite upgrade-session isolation — 2026-10-18

API-key and preauth-key expiration now validates during SQL row decoding rather
than letting a malformed non-NULL value become an absent deadline. SQLite's
private projection carries storage type plus raw text, keeping NULL, legacy
integer seconds and numeric calendar text distinct. Out-of-range integers and
unsupported storage types reject. Representable legacy integer deadlines expose
an equivalent timestamp in the existing public text field. Accepted numeric
calendar text also canonicalizes before the legacy integer fallback. PostgreSQL keeps
its original projection and uses the same validated row boundary.

The shared parser covers canonical RFC/SQLite, date-only/minute/hour defaults,
compact calendar dates, comma/long fractions and common Go time.String forms.
This is not full Go/Gorm date parsing: exotic partial/time-only/RFC/zone-name or
host-local forms may still read-error where Go accepts them. Exact scan-error
text and all runtime authentication/import/list/restart behavior remain
unqualified. Public row types/signatures and strict expiry boundaries remain.
A second agent reviewed the SQLx adapter bounds and numeric fail-open fixes in
source; no compile or behavioral check ran.

Native CLI secret-file loading now uses a private Go-style one-pass environment
expander and pinned whitespace trimming rather than the legacy core resolver.
Single-digit/special variables, empty braced names and unterminated braces follow
Go os.ExpandEnv grammar; replacements are not rescanned. Conflict and path/read
error ordering remain intact. Existing lossy non-UTF-8 path/secret projection and
unavailable non-UTF-8 environment values remain explicit limitations. Public
APIs and the legacy core are unchanged.

UserInfo reads the bounded response body before checking status, preserving
body-read error precedence and including status/reason plus body in non-200
provider errors. HTTP/1 reason phrases are retained when available. Transport
errors keep native cause chains and Get/quoted password-redacted URL context.
The private empty-access-token shortcut is removed to follow Provider.UserInfo;
production token exchange still rejects missing access tokens. All helpers stay
behind the full feature. Underlying Rust/Go transport text, raw byte projection,
status normalization and the existing 1 MiB/30-second limits remain distinct or
unqualified; those bounds are retained.

Legacy SQLite conversion now marks its acquired migration connection
close-on-drop before validation or rebuild work. Rebuild temporarily disables
foreign keys; cancellation can skip the explicit restoration. The connection
therefore cannot return to the application pool carrying altered connection-local
state. Backup/copy/rebuild SQL and migration checksums are unchanged. Actual
cancellation, worker shutdown, failure recovery and restart behavior remain
unqualified. Source/direct-rustfmt only; no tests/builds/Cargo/validators/probes
or fixture recapture. All three parity gates remain open.

### Migration serialization, persisted expiry and OIDC startup — 2026-10-18

OIDC runtime events now include pinned redirect, missing callback state,
expired registration, wrong auth-request kind and SSH-owner rejection messages
and fields. UserInfo provider failures log the pinned ERROR event twice;
second-pass claims failure or subject mismatch logs it once without an error
field. A private decoder error enum preserves that phase distinction without
changing acceptance or merge decisions. Missing UserInfo endpoints emit the
provider's unsupported-endpoint diagnostic. Provider transport/signature text,
non-200 response-body diagnostics, caller paths and rendered bytes remain
unqualified.

Postgres migration now acquires SQLx's database advisory lock before import
compatibility checks and retains it through normalization, foundation migrations
and transactional Go ledger/version publication. The nested foundation migrator
has locking disabled to avoid a second acquisition. Ordinary errors attempt
unlock while retaining their original error; the pooled entry point still
closes its session on drop for cancellation cleanup. This closes the source race
between foundation completion and final ledger creation among cooperating Rust
startups. Borrowed-session cancellation, Go/Rust mixed concurrent migration,
commit ambiguity and restart behavior remain unqualified.

SQLite node reads no longer turn every text expiry beginning 0001-01-01 into
NULL. SQL NULL, an explicit Go zero-time pointer and nonzero instants on that
date remain distinct in the stored row projection. Existing precise timestamp
hydration and exact-zero expiry checks retain Go's zero-time semantics while a
nonzero year-one expiry stays expired. Postgres already retained that distinction.
No migration SQL/checksum or public API changed.

OIDC secret-file startup treats an explicitly empty path as unset and preserves
the mutual-exclusion sentinel. Common file failures now expose Go-style open/read
PathError text without Rust-only resolution wrappers. Secret-byte/path encoding,
environment-expansion details, rare read errors and OS/locale behavior remain
unqualified. Source/direct-rustfmt only; no tests/builds/Cargo/validators/probes
or fixture recapture. All three parity gates stay open.

### Native backend framing and startup cleanup — 2026-10-18

Native Postgres ingress now checks signed frame lengths and pgx's default
0x3ffffffe-byte body limit before reserving the body. Allocation-free structural
checks cover represented backend packet kinds even when their bodies would be
discarded. Native Error/Notice decoding consumes the full field list, requires
its final marker and retains the last duplicate field; the final S severity
controls pgx-style FATAL handling independently of V. Notice and ParameterStatus
bytes project lossily into existing Rust string fields. Generic SQLx decoding
keeps its existing path. Query argument-count errors now use pgx Query wording;
commands retain ExtendedQueryBuilder wording.

CLI log levels now use Go Unicode simple folding before numeric fallback, so
values such as diſabled suppress logs as pinned zerolog does. The pooled
Postgres migration entry point marks its acquired session close-on-drop before
starting work: failure or cancellation cannot return a session holding SQLx's
migration advisory lock to the reusable pool. The borrowed-connection entry
point still leaves session cleanup to its owner. Final ledger/version publication
remains transactional; concurrent startup and interrupted imports are unqualified.

Source/direct-rustfmt only. Explicit prepared-statement lifecycle differences
remain adapter residuals, with no production Headscale Postgres callsite found.
SQLx-only execute_many semantics, absent FunctionCallResponse/CopyBoth variants,
ReadyForQuery status handling, invalid-UTF8 column names, COPY count projection,
SASL mechanism parsing, transport cancellation, startup/provider diagnostic
breadth and accumulated native/generic/feature/package/client/process/import/
restart/security/dependency qualification remain open. No tests, builds, Cargo,
validators, probes or fixture recapture ran. All three parity gates remain open.

### Postgres result draining, protocol failure and migration publication — 2026-10-18

Native row queries expose the first simple-query result and continue decoding
and draining later results through ReadyForQuery, retaining late database
errors. Native commands still return the last tag. Cached command result formats
now follow pgx's default registered type-map preferences, including arrays/ranges
and text fallback for unknown types; row queries keep the distinct stdlib
format map. Any backend execution now delegates through an additive backend
method to the concrete native command path. Generic Any aggregation and row
conversion keep their existing path.

Native malformed-backend protocol errors and FATAL responses now leave sticky
unusable connection state. Receive/decode/invariant paths mark it, while client
validation/encoding failures and ordinary SQL errors do not. Pool flush/drain
rejects that state, and close drops the poisoned socket without sending queued
statements. Drain paths validate discarded command tags, data rows and row
descriptions. Buffer-only Sync/rollback encoding stays non-failing so transaction
Drop cannot panic after a protocol error. This remains source implementation,
with transport termination and cancellation behavior unqualified.

Postgres Go migration-ledger stamping and the current-version marker now commit
together after the foundation migrations. Cancellation before commit cannot
publish only a prefix of a newly created fresh-Go ledger. Earlier partial ledgers,
concurrent startup, failed commit/rollback, foundation-step cancellation and
direct Go handoff after interrupted startup still need qualification.

Source/direct-rustfmt only; no tests/builds/Cargo/lint/validators/probes. Generic
and native/Any lifetimes, custom codec maps, execute_many API semantics, skipped
backend-message decoders, CancelRequest/asynchronous cleanup, I/O timeouts and
all accumulated pool/cache/mutation/restart/import/feature/package/container/
client/process/security/dependency/advisory qualification remain open. All three
release gates stay open; no drop-in or production-readiness claim is made.

### Native Postgres execution and text codec corrections — 2026-10-18

Native connection execute now retains the final CommandTag for multi-statement
simple SQL while draining through ReadyForQuery. Pool execute delegates to the
acquired connection so production pool calls reach that native override;
ordinary SQLx connections retain their existing aggregate behavior. Native
Exec's no-argument simple-protocol rule is separated from Query's configured
mode and empty-SQL rule. Retired statement Close frames wait while the backend
reports a failed transaction. Native command-tag row counts use pgx's trailing
digit/wrapping arithmetic through the existing SQLx u64 result boundary, after
requiring one terminal NUL and rejecting interior NULs. Native described queries
request pgx stdlib's binary formats for its 13 built-in OIDs and text for other
columns. Private per-column row metadata preserves the actual returned formats;
generic SQLx rows keep their existing uniform decoding path.

Text argument conversion now emits an empty array immediately for any validated
zero-cardinality shape. This prevents a tiny shape such as [large,0] expanding
into a huge number of empty braces. Array quoting, TIME fractional digits,
interval month/day/clock formatting, float infinities and numeric header/zero
handling follow the pinned codecs more closely. Generic SQLx paths are separate.

A bounded source review of native user create/rename/query/delete-preload code
found no warranted mutation change in the inspected paths. Rust deliberately
continues to propagate failed database reads where pinned GetUserByID discards
errors other than record-not-found and can return a partial model. Signed Rust
ID boundaries and that fail-closed behavior remain explicit differences.

Source/direct-rustfmt only; no tests/builds/Cargo/lint/validators/probes. Native
mode/command/query/pool/cache/transaction/error/row-decoding equivalence, generic
SQLx regressions, malformed codec resources and text/binary conversion remain
unqualified. Native fetch_many still exposes all simple-query results, cached
Conn.Exec result preferences retain a uniform-binary approximation, and Any
backend execution has its own dispatch boundary. Broader mutation/restart,
feature/package/container/client/process/
import/security/dependency/advisory qualification remains open. All three release
gates stay open; this batch does not qualify production or replacement readiness.

### Native timestamp, form and OAuth decoding — 2026-10-18

Gateway request timestamps now use a private source-derived Go RFC3339Nano
parser instead of Chrono. It handles fallback one-digit hours, comma fractions,
nanosecond truncation, timezone hour/minute boundaries of 24/60, calendar/leap
checks, year zero, UTC conversion and Go ParseError context. Protobuf bodies add
their own UTC range and dot-only fractional-precision check; query timestamps
retain gateway range/error wrapping. Response timestamp formatting is unchanged.

Confirmation POST uses a shared native ParseForm boundary: MIME base/error
handling, recognized-form-only 4 KiB enforcement, body-before-query errors,
body-only first-value CSRF lookup, percent escapes, semicolon errors and Go query
parameter limits. Ordinary unpatterned GODEBUG urlmaxqueryparams overrides retain
the pinned custom strict comparison. MIME decisions are shared with discovery,
OAuth and UserInfo; raw response-header bytes retain parameter comparisons.
OAuth ignores MIME parameter errors but retains a valid base, while signed
UserInfo requires a successful whole MIME parse. OAuth form token responses
reuse the same strict query decoder and parameter-count limits. Discovery
decode-error selection/quoting also retains raw header bytes, and UserInfo
normalizes bearer/basic/mac token types using Go Unicode folding.

OAuth authorization options now replace earlier values, including configured
overrides followed by the native nonce. Authorization/token requests encode keys
in sorted order with Go QueryEscape; optional empty redirect/client-secret fields
follow oauth2 construction rules. The token endpoint reads at most the first
1 MiB as io.LimitReader does, rather than rejecting oversized Content-Length.
Typed token JSON completes before optional Extra projection. A private type flag
distinguishes empty-string ID tokens from absent/non-string JSON values; form
Extra applies Go's signed-integer/decimal-or-hex-float coercion rules. Expiration
syntax/type/range diagnostics and int32 clamp/narrowing follow pinned source.

Source/direct-rustfmt only; no tests/builds/Cargo/lint/validators/probes or fixture
recapture. Timestamp/parser/error equivalence, numeric conversion, MIME/query
edge cases, arbitrary-byte form DTO limitations, buffered-body versus reader
errors/connection effects, Go stack-bisect patterns/runtime counters and all
accumulated callback/resource/native/wire-only/feature/package/container/client/
process/import/restart/security/dependency/advisory qualification remain open.
All three release gates remain open; no replacement-readiness claim is made.

### Streaming gateway validation and confirmation lifecycle — 2026-10-18

Every current gateway request body declares private scalar/list/timestamp field
schemas. Known fields and repeated elements validate as tokens arrive, using
input order, actual line/column, JSON field names and raw token spellings. Wrong
containers and elements fail before later fields once the outer gateway JSON
decoder has validated the first whole value. The outer encoding/json RawMessage
boundary must precede protobuf field decoding; invalid first-value syntax takes
priority over typed-field errors. Whitespace-only bodies mean empty DTOs, and
data after the first complete value is ignored by the generated gateway.
Timestamp diagnostics follow protobuf and reject over-nine-digit dot fractions;
leap seconds cannot produce invalid protobuf nanoseconds. Go-versus-Chrono
parsing remains unqualified.

OIDC confirmation GET now sends Cache-Control: no-store. The production route
uses an additive async entry point that reloads the user by ID after CSRF
validation; POST also reloads before completing registration. Native SQLite and
Postgres adapters reject missing users, and the policy wrapper delegates the
refresh. Legacy synchronous/custom stores retain their previous cached behavior
unless they implement the additive refresh method. The branded confirmation,
registration/reauthentication and SSH-success pages now follow pinned templates,
including absolute form URLs, empty-OS fallback, user numeric-ID fallback and
the dedicated spent-registration-link message. HTML attributes remain escaped:
pinned elem-go writes them raw, while AuthID validation only checks prefix/length.
This intentional hardening can differ in bytes for unusual attribute values.
Native confirmation fingerprints now use five standard-base64 characters from
the decoded machine key, with an empty all-zero-key fingerprint. Confirmation
POST also rejects malformed query escapes and raw semicolons, while query values
cannot supply the POST-only CSRF token.

Callback cache lookup now fails early with 404 only when PKCE requires a cached
verifier. Without PKCE, code/core/nonce/application validation precedes atomic
state consumption, preserving provider failures and post-nonce cookie clearing.
Confirmation cookies use Go attribute order, decoded paths and cookie-path
sanitization. Ordinary GODEBUG httpcookiemaxnum overrides now honor rightmost
assignment, signed platform-int parsing, zero-unlimited and invalid-value
fallback. Go stack-bisect #patterns and Go runtime counters are not projected.

Native claim strings now retain typed error context and exact-before-fold field
lookup. FlexibleBoolean follows the standard-any float64 overflow phase across
nested/overwritten entries, ParseBool string errors and Go-style invalid-value
formatting through iterative raw traversal. Numeric shortest-format equivalence
and repeated subtree scanning costs remain unqualified.

Source/direct-rustfmt only; no tests/builds/Cargo/lint/validators/probes or fixture
recapture. Account deletion/rename races, refresh-to-commit timing, custom stores,
cookie/runtime-environment edges, browser rendering and unusual attributes,
timestamp grammar, malformed UTF-8 diagnostics, numeric conversion/formatting,
generic Value resources and all accumulated feature/process/import/restart/
security/dependency/advisory qualification remain open. All three release gates
remain open; these source changes do not establish replacement readiness.

### OIDC callback staging, browser errors and protobuf body tokens — 2026-10-18

Native ID-token verification now decodes core claims before nonce binding;
Headscale application claims decode after nonce validation and expiry selection.
Every response after successful nonce binding clears the state and nonce cookies,
including malformed application claims, authorization and persistence failures.
Earlier failures preserve the cookies. Nested distributed-claim maps now retain
ordinary saved errors while assigning later entries and zeroing each map element.
Cookie parsing follows byte-level name/value admission, first valid matching
cookie selection and the default 3000-candidate limit. Callback paths preserve
the configured prefix, percent decoding and Go cookie-path sanitization.

OIDC browser errors now use the pinned Headscale AuthError page and generic
status messages; technical details are logged. The pinned CSS/SVG assets are
retained. The protobuf gateway now uses a private iterative body lexer that
preserves raw numeric/string tokens, protobuf delimiter/escape rules, known-field
alias duplicates (including null), and skips retaining deeper unknown subtrees.
Response serialization and public method/field/wire-only boundaries are preserved.

Source/direct-rustfmt only; no tests/builds/Cargo/lint/validators/probes or fixture
recapture. Full-body validation still precedes typed gateway field extraction,
so competing syntax/type error precedence and many scalar source positions remain
incomplete. Invalid UTF-8 outside strings has lossy diagnostic transport. Go
GODEBUG cookie-limit overrides and HTTPError custom UserMsg overrides are not
implemented here. Browser rendering, cookie/callback lifecycle, nested-map errors,
Chrono expiry/nbf bounds, numeric overflow conversion, generic Value resources and
all accumulated native/wire-only/feature/package/container/client/process/import/
restart/security/dependency/advisory qualification remain unqualified. All three
release gates stay open; their count is not a count of remaining code fixes.

### Standard OIDC assignment, legacy Unicode and protobuf integers — 2026-10-18

Native OAuth and ID-token claims now assign recognized standard Go JSON fields
in input order with Unicode-folded tagged names. Plain null strings preserve
previous values; custom groups/bools/dates process each occurrence, and ordinary
saved type errors remain failures. Claim-name/source maps merge across duplicate
map fields, clear on null and create zeroed map elements per assignment. Unknown
subtrees skip allocation. UserInfo now runs coreos's first decode (including
profile and strict literal email_verified) before Headscale's claims pass. Fresh
custom group slices retain nil-versus-empty behavior where the public DTO permits
it. Existing public structs/signatures and the wire-only boundary remain.

New explicit legacy Value modes replace malformed UTF-8/unpaired UTF-16 in names
and strings, with exact-number or duplicate-rejecting binary64 variants. Native
OIDC/JWS/JWK paths use them; policy-v2 keeps strict string encoding. A numeric-
grammar guard prevents serde's private-number object transport inside quoted
numeric dates/expiry. Int64 precedes Float64 for dates. IssuedAt validates numeric
syntax/conversion without requiring Chrono materialization, following go-oidc's
parse-only treatment; expiry/nbf range limitations remain.

Gateway uint64 body decoding now uses protobuf decimal digit shifting for
integral fraction/exponent forms with checked range and exponent width, preserving
its actual quoted-first-token behavior without floating rounding or exponent-
sized allocation. Query/path integer rules remain distinct. Null-valued aliases
count toward duplicate protobuf field numbers. The top-level duplicate pass
ignores values instead of rebuilding generic serde trees. Adapted protobuf,
OAuth, JOSE and JOSE JSON licenses/notices are retained with source pins.

Source/direct-rustfmt only; no tests/builds/Cargo/lint/validators/probes or fixture
recapture. Remaining diagnostic byte/field/order details, combined core-verifier
versus Headscale claims staging, saved-error ordering within nested claim maps,
Chrono expiry/nbf bounds and architecture-dependent overflow conversion, malformed
protobuf-body number lexing versus the stricter initial scanner, generic direct
Deserialize consumers and public Value resource behavior remain incomplete or
unqualified. Full native/wire-only/feature/package/container/client/process/import/
restart/cache/rollback/cancellation/concurrency/shutdown/security/dependency/
advisory qualification remains pending. All three release gates stay open.


### Native JSON kinds, constructor errors and retained users — 2026-10-18

The arbitrary-number source review found concrete object-to-number confusion
paths beyond policy apps. Native OIDC token/claim/date/header/key-set imports and
the protobuf HTTP gateway now keep literal private-number objects distinct from
numeric values. OAuth selected raw fields and ID-token date/audience fields are
projected without a generic Value decode, retaining every selected occurrence
before replacement. Expiry null duplicates retain the previous value; quoted
expiry syntax, upper clamp and int32 narrowing follow pinned oauth2. JWS/header/
JWK struct fields use go-jose's exact names and direct duplicate rejection.
Extra headers use the separate strict-any decoder: recursive unique names and
finite binary64 numbers, including underflow. Unknown JWS/JWK struct subtrees are
skipped before Value construction; known wrong kinds fail before allocation of
nested trees. Original protected/signing bytes remain the authentication input.

Parser-owned partial/replaced JSON Values now drain iteratively on error or
ordinary duplicate replacement. Cleanup keeps owning iterators with scratch
proportional to nesting. The existing exact-number parser remains last-member-
wins; the new strict-any entrypoint is scoped to generic JOSE header decoding.
Returned public Values still have recursive clone/equality/encode/drop behavior.

CheckPolicy now captures users/nodes before parsing and runs constructor
compilation before semantic assertions. Go Check/Set status/context wrapping
removes only local PolicyParseError display prefixes. Set/reload now use the
live manager's retained directory rather than a fresh user database read; REST
candidate validation follows the same constructor/write distinction. Direct CLI
database failures retain opening/version/migration phase wording where the Rust
error type identifies the phase. SQLite missing directories use recursive 0700
creation and source-derived permission wording.

All changes remain source/direct-rustfmt only. No tests/builds/Cargo/lint/
validators/probes, fixture recapture, fresh dependency/advisory or security
qualification. Remaining standard OAuth/claim field case folding and duplicate
semantics, strict Unicode versus legacy replacement, Chrono date ranges,
malformed error text, generic Deserialize/Value consumers, deep/wide payload
resources and exact database migration/driver/platform diagnostics remain
incomplete or unqualified. Full typed/deephash/cache/rollback/cancellation/
concurrency/shutdown/native/wire-only/feature/package/container/client/process/
import/restart qualification remains pending. All three release gates stay open.


### Opaque numeric payloads and native constructor paths — 2026-10-18

Native policy parsing now preserves numeric capability values outside binary64
range. The leaf enables serde_json arbitrary_precision without changing the
locked package version or adding dependencies. A token-based Value builder
assembles objects/arrays iteratively, decodes strings strictly and parses numbers
separately. Literal $serde_json::private::Number object keys remain ordinary
payload members. Valid app maps are moved around typed AclDoc deserialization
and restored without a second generic Value decode, for grants and nodeAttrs.
Policy shape/original-ACL projection and opaque raw-payload comparisons use the
same builder. Existing raw capture still supplies exact wire payload spelling;
public Number spelling can normalize exponent syntax.

The API facade now passes original policy bytes directly to the shared decoder.
Its obsolete SSH-action Value round-trip could collapse duplicate names, rewrite
opaque payloads and unquote action escapes before Go's raw-token custom decoder.
That shim is removed; existing public/error translation symbols remain. The
existing escaped-whitespace expectation was corrected from source, without
running it. Tagged SSH principals now retain input node order and repeated tags
rather than acquiring a private node-ID sort.

The additive compile_policy_for_snapshot creates an isolated policy store with
identity/address/tag/announced/approved facts from the supplied snapshots before
constructor compilation. Direct CLI Set uses its existing empty snapshot; Check
uses loaded nodes/routes. Static topology and node-dependent constructor errors
surface before boot warnings/semantic assertions. Direct Get uses backend-neutral
loading policy from database wording; direct Get/Set and user/node-load failures
use the existing native DB diagnostic renderer. Warning-only Set tests and hard
Check tests retain their pinned sequence.

This is source/direct-rustfmt work only. No tests/builds/Cargo/lint/validators/
probes or fixture recapture ran. arbitrary_precision unifies across consumers of
the locked serde_json version: other generic Value deserializers, numeric equality,
canonical bytes and downstream signed-policy integrations need qualification.
The builder is iterative; Value clone/equality/serialization/drop and other
public policy traversals remain recursive, so deep/large payload resource behavior
is unqualified. Generic direct Deserialize/TOML consumers are not the native
protected parsing path. Malformed app/DB diagnostics, general error envelopes,
programmatic invalid-action compiler channels and all accumulated native/wire-only/
feature/package/container/client/process/import/restart/concurrency/rollback/cache/
shutdown/security/dependency/advisory qualification remain incomplete. No release
gate closes; the backlog still has two P0s and one P2.


### Compiled SSH-test sandbox and decoder/snapshot edges — 2026-10-18

SSH tests now resolve their source through the checked native alias path and
consume the actual per-destination compiled SSH policy, cached by node ID for
one evaluation pass. Reachability uses exact unzoned NodeIP principals and
compiled SSHUsers maps, including explicit empty-user overrides and non-root
wildcard fallback. Accept/check require all source addresses; deny fails on any
accepted source. Interval coverage/intersection preserves the first uncovered
address without enumerating CIDR hosts.

Destination selection retains alias/node order, deduplicates node IDs and scopes
native autogroup:self to a nonzero source username owner. Source/destination
resolution failures abort at the pinned boundary; no-assertion entries return
immediately. Failure usernames are sorted, destination duplicates remain, and
check reasons consult the final AcceptOK set. Combined ACL/SSH failures retain
two test(s) failed wrappers inside the Tailscale multierr envelope. Strict source
user ambiguity now fails before inspecting a zero-user node's address errors.

Groups and ProtocolPort custom JSON decoders now apply recursive float64 number
range checks only in their any-decoded subtrees. Nested name/string validation
precedes deferred numeric overflow, which precedes custom semantic/type checks.
Underflow remains accepted; opaque app contexts and typed fields are unchanged.
Direct CLI snapshots retain loaded associations, typed zero/scoped/mapped
addresses and Go username fallback, reject invalid/duplicate Rust node IDs and
negative user IDs, and share fallible directory projection across both stores.

Three subagents supplied the interval, decoder and CLI changes in disjoint files;
the parent integrated the SSH evaluator and error envelope. Source/direct rustfmt
only: no tests/builds/Cargo/lint/validators/probes, fixture recapture, dependency
or advisory qualification. Whole-policy serde_json::Value materialization may
still reject enormous numbers in opaque app payloads. General error envelopes,
Go's randomized cannot/unable-to wording, compiler error channels for manually
constructed invalid policies, legacy/source-less/custom projections, malformed
row/zero-ID diagnostics, and independent offline reads remain incomplete or
unqualified. Full typed/deephash/cache/failure/rollback/resources/concurrency/
shutdown/native/wire-only/package/container/client/process/import/restart
qualification remains pending. All three release gates remain open.


### Route-bearing native policy-test snapshots — 2026-10-18

The additive PolicyCheckNodeSnapshot pairs an unchanged PolicyCheckNode with
advertised and approved route lists. The fresh ACL-test compiler receives the
intersection in announcement order, preserving duplicates. Route facts stay
paired with each entry through the private check pipeline; there is no separate
ID-keyed route map that can overwrite another entry's facts. Existing source-
only and legacy public check/warning methods retain their previous contracts.

PolicyCheckNodeSnapshot.from_registry captures node IDs, loaded user association
identity, typed/zero-address metadata, advertised routes and approvals from one
retained registry snapshot. It preserves the duplicate-ID rejection and sorted
native order. Registration's legacy node projection now reuses that capture and
discards only the added route fields.

MachineAdmin has an additive fallible policy_nodes_for_check method. Registry,
SQLite and Postgres implementations retain their native snapshot/row decoding
and association paths while supplying routes from the same record or database
row. Native gRPC/REST policy validation now invokes the route-bearing sandbox.
Custom stores have a fallible record-list default and can override it without
changing their existing registration/list methods.

Direct CLI SQLite/Postgres policy checks decode tags, Hostinfo and approvals
fallibly into route-bearing entries. Startup warnings use the retained registry
helper instead of rebuilding identity/addresses from a metadata-free record
snapshot; snapshot-construction errors propagate through startup. Policy test
failures remain warnings at boot. Public field types/methods and the wire-only
dependency boundary remain unchanged.

This supplies the native route input omitted by the previous ACL-test sandbox
batch. It remains a source-only implementation: no builds/tests/lint/validators/
probes, fixture recapture, security/dependency qualification or release gate
closure. Typed/canonical route edge cases, legacy/source-less/custom projections,
offline database/association read consistency, SSH tests, combined/JSON error
behavior, filter/deephash equality and full error/partial/cache/rollback/resource/
concurrency/shutdown behavior remain incomplete or unqualified. All accumulated
native/wire-only/package/container/client/process/import/restart qualification
and all three backlog gates remain open.


### Policy-test destination parsing and compiled global checks — 2026-10-18

A shared additive TestDestination/parse_test_destination helper now follows
policy/v2.parseDestinationAlias's literal quote wrapping before AliasWithPorts
decoding. An already decoded policy-test string undergoes the selected second
JSON-string parse: escapes are decoded again and unescaped quote/control bytes
are rejected. Destination aliases and port ranges then use the shared Go
parsers and typed validation. Shape validation retains the original destination
string for Go's raw slash test, rather than applying that test to canonical
Prefix text. Native ACL destination parsing keeps its own one-decode boundary.

ACL policy-test execution now compiles a fresh global packet filter and
resolves test aliases through the shared address-set resolver. Every merged
source prefix must overlap an allowing global source entry; protocol matching
uses the IANA values including the four default protocols, and destination/
requested port ranges are checked against DstPorts. CapGrant destinations do
not independently admit packet traffic. Equal-end ranges and Go-supported
port spellings no longer pass parsing only to fail a separate runtime numeric
parser. No live PolicyStore or map-cache state is mutated by the sandbox.

New additive source-aware check and boot-warning entrypoints retain nil-versus-
empty default filtering, original ACL rows and app shapes only when the source
matches the public document. Native gRPC, REST, direct CLI policy checks and
server startup warning paths now pass that source. Existing public entrypoints,
fields and wire-only dependencies remain available. Source-less callers keep
their legacy projection/default boundary and remain unqualified.

Test source aliases are not AliasEnc: their plain string text is no longer
trimmed again by the check resolver. Explicit source usernames must exist in
the attached user directory; provider precedence and ambiguity errors remain
in the shared resolver. Checked resolution rejects partial/error results as Go
policy tests do. ACL-test errors now retain Go-style source/protocol labels,
errors-before-accept-failures-before-deny-failures ordering and selected quoted
resolution diagnostics. SSH test logic retains its separate path.

Source/direct rustfmt only; no builds/tests/lint/validators/probes, fixture
recapture, security/dependency qualification or release gate closure. The
existing public PolicyCheckNode lacks approved-route facts, so the fresh ACL
sandbox currently supplies no routes; routed/wildcard-source test inputs need
a further native snapshot boundary. Full source-less/mismatched projection,
SSH-test behavior, combined multi-error/JSON envelopes, numeric-to-any overflow,
filter/typed-policy/deephash equality and complete error/partial/cache/rollback/
resource/concurrency/shutdown behavior remain incomplete or unqualified. All
accumulated native/wire-only/package/container/client/process/import/restart
qualification and all three backlog gates remain open.


### Retained policy container identity and duration values — 2026-10-18

PolicyState now retains a private PolicyContainerShape beside the supplied
public document. The additive leaf helper captures it only when the full
parsed native source matches the supplied document after excluding the
independently attached user directory. Paths use canonical typed field names
and map-entry tokens; JSON spelling, member order and metadata do not define
the container identity.

The shape distinguishes omitted/nil ordinary maps and slices from allocated
empty containers across root policy fields, original ACL fields, grants,
nodeAttrs, SSH rules, policy tests and SSH tests. Custom decoders are distinct:
explicit null Groups/Hosts allocate maps; explicit null Aliases, Owners,
AutoApprovers, SSH alias lists and SSH-test destination lists allocate slices;
empty Groups member values remain nil because that decoder builds them by
appending to a nil slice. Auto-approver routes/exit lists and grant capability
slice values retain their selected shape. Opaque payload bytes remain handled
by the existing separate app metadata.

The retained shape participates in policy cache invalidation and is installed
and restored with the rest of the candidate policy state on a rejected write.
It supplements public values, original ACL identity and app/SSH-env metadata;
it does not replace or prove full Go filterAndPolicy deephash equivalence.
Mismatched/programmatic sources receive no new container-shape metadata.

Native numeric SSH check periods now retain canonical time.Duration.String
text, so equivalent spellings do not differ solely by input text. The literal
always retains its distinct Always identity from a numeric zero duration;
the renderer already preserved that zero-versus-always distinction and now
canonicalizes other numeric periods as well. Public field types/methods and
the wire-only dependency boundary remain unchanged.

Source/direct rustfmt only; no builds/tests/lint/validators/probes, fixture
recapture, security/dependency qualification or release gate closure. Full
filter/typed-policy/deephash equality and hash-triggered update behavior,
legacy source metadata/raw-model ambiguity, whole-field/custom error phases/
envelopes, numeric-to-any overflow, manually quoted test destinations and
complete error/partial/cache/rollback/resource/concurrency/shutdown behavior
remain incomplete or unqualified. All accumulated native/wire-only/package/
container/client/process/import/restart qualification and all three backlog
gates remain open.


### Typed via tags, IP-pool prefixes and string zero values — 2026-10-18

The native prepared-policy walker now gives grants[].via the selected []Tag
decoder. Each Tag uses literal raw quote trimming and validation, preserving
JSON escape spellings instead of silently replacing them with decoded text.
It applies no AliasEnc whitespace trimming or Username classification.

NodeAttrs ipPool entries use netip.Prefix text decoding: decoded JSON strings,
canonical address text, preserved host bits, strict Go prefix grammar, and
null/empty text as the zero Prefix. A zero Prefix reaches the CGNAT validation
as the Go String value "invalid Prefix"; valid prefix errors retain canonical
host-bit-preserving text and Go quoting. The allocator-unsupported validation
remains in place.

SSH users and SSH-test accept/deny/check entries now use SSHUser's Go string
null zeroing and Unicode TrimSpace at the native boundary. Ordinary nodeAttr
capability strings, SSH acceptEnv values and policy-test source/assertion
strings use Go string null zeroing without trimming. Null list elements no
longer fail solely because Rust String deserialization rejects null; empty
values reach each field's own validation. Opaque app payloads keep their
existing separate path. Existing generic trimming helpers share Go whitespace.

Null entries in grants, SSH rules and policy tests now reach their zero struct
values and semantic validation, alongside the previously handled ACL,
nodeAttrs and SSH-test struct entries. Public model fields/methods and the
wire-only dependency boundary are unchanged.

Source/direct rustfmt only; no builds/tests/lint/validators/probes, fixture
recapture, security/dependency qualification or release gate closure. Exact
whole-field/custom decoder error phases/envelopes, numeric-to-any overflow,
manually quoted test destinations, complete policy nil/empty/deephash identity,
raw/model ambiguity and full error/partial/cache/rollback/resource/concurrency/
shutdown behavior remain incomplete or unqualified. All accumulated native,
wire-only/package/container/client/process/import/restart qualification and all
three backlog gates remain open.


### General alias classification and SSH typed aliases — 2026-10-18

A shared additive AliasKind/alias_prefix/canonical_alias helper now follows
policy/v2.parseAlias: parse an address/prefix first, then wildcard, Username,
Group, Tag, AutoGroup and Host. Native AliasEnc values are trimmed using Go
Unicode whitespace and retain canonical typed prefix text. Bare addresses
become host prefixes, address zones disappear, slash prefixes preserve host
bits, and invalid alias syntax is rejected at the decoder boundary. Owners
and auto-approvers keep their distinct untrimmed, Username-first decoder.

Native ACL destination prefix projection now canonicalizes Prefix text before
public rule splitting, including IPv6 aliases ending in :: and bracketed
scoped IPv6 accepted by Go netip. It retains destination port text and applies
no AliasEnc whitespace trimming. AliasWithPorts syntax validation also calls
its selected Tag/AutoGroup validation, distinct from AliasEnc admission.

Reference/autogroup/SSH source-destination validation, general address
resolution, leaf evaluation/expansion, user-ambiguity checks and conditional
ACL/self/via ordering now use parsed alias kinds. A group/tag/autogroup-looking
username containing @ is not reclassified as that namespace. Literal IPs
cannot be replaced by a same-named hosts-table value; scoped addresses whose
zone contains @ still take the Prefix branch before Username.

SSH source/destination decoding now checks the selected typed alias domains:
sources reject Prefix/Host/wildcard; destinations reject Prefix/Group/wildcard,
with Host rejection during policy validation even when that host is undefined.
SSH source/destination combinations distinguish usernames before tag/group
prefixes. SSH policy-test aliases use the general decoder; missing/null/empty
sources and null test structs reach shape validation as Go zero values.
SSH test destination checks dispatch on the parsed kind, including tag names
containing a colon, without guessing that every colon denotes a port.

Policy-test destination shape uses parsed Go port ranges, admitting equal-end
ranges such as 22-22 and 0-0, rejecting multiple/range ports by their resulting
bounds, applying CIDR syntax checks only to Prefix values and consulting hosts
only for Host values. Policy-check resolution uses Prefix-before-Username/
Host precedence and Go whitespace trimming. Existing public field types and
methods, generic TOML representation and wire-only dependencies remain intact.

Source/direct rustfmt only; no builds/tests/lint/validators/probes, fixture
recapture, security/dependency qualification or release gate closure. Exact
whole-field/custom error phases and envelopes, manually quoted test destination
edge cases, other typed-field raw JSON decoding, complete policy nil/empty/
deephash identity, raw/model ambiguity and full failure/cache/rollback/resource/
concurrency/shutdown behavior remain incomplete or unqualified. All accumulated
native/wire-only/package/container/client/process/import/restart qualification
and all three backlog gates remain open.


### Owner/auto-approver decoding and typed route keys — 2026-10-18

The native policy preparer now dispatches TagOwners list elements through
OwnerEnc semantics and both auto-approver lists through AutoApproverEnc
semantics. JSON strings are unquoted; whitespace is retained; null becomes
an empty string and is rejected by the selected owner/approver parser.
Unsupported alias kinds are rejected at this decoding boundary. Username
selection precedes group/tag prefixes, including names such as group:name@.

Auto-approver route map keys now follow netip.Prefix.UnmarshalText. Empty
text retains the zero-prefix key, which cannot cover an advertised route.
Valid keys retain host bits and canonicalize address text without masking.
JSON-name duplicates and duplicate resulting typed prefixes are checked
separately, before decoding the second entry's approvers. The generic route
validator uses the shared Go prefix text grammar and accepts the inert zero
key instead of rejecting it through Rust IpNet parsing.

Owner/approver reference validation, tag-chain flattening, direct-user tag
ownership, leaf route/exit approval, compiled approver/tag-owner address
resolution and user-ambiguity checks now preserve Username precedence.
The resolver has an owner-specific entrypoint; group member Username values
also bypass alias prefix reclassification. Existing public field types and
methods and the wire-only dependency boundary remain unchanged.

Source/direct rustfmt only; no tests/builds/lint/validators/probes, fixture
recapture, security/dependency qualification or release gate closure. Exact
nested custom decoder envelopes/error ordering, other Alias/Prefix precedence
contexts, numeric overflow, complete policy nil/empty/deephash identity,
raw/model ambiguity and full failure/cache/rollback/resource/concurrency/
shutdown behavior remain incomplete or unqualified. All accumulated native,
wire-only, package/container/client/process/import/restart qualification and
all three open backlog gates remain outstanding.


### Hosts, typed tag keys and null group values — 2026-10-18

Null group member lists now reach the phased group decoder unchanged and are
rejected as non-array values. The prior shared groups/tagOwners null-list
coercion had prevented that validation; tag-owner lists retain their own
selected Owners decoder behavior.

Native Hosts decoding first checks all map value types as strings (null
clears the intermediate string), then validates each host name and parses its
address through the shared Go netip helpers. Bare addresses become host
prefixes, scoped IPv6 addresses lose their zone, slash prefixes retain host
bits and canonical address text, and errors use selected Go host/IP wording.
Generic/TOML host handling retains its existing path.

TagOwners map keys now follow Tag.UnmarshalJSON raw quote trimming before
validation and map insertion. JSON escape spellings no longer silently become
different decoded tag names. JSON-name duplicate checks precede the custom
key decoder, with a separate check for duplicate resulting typed Tag values.
Metadata removal still precedes both, and normalized prepared keys retain the
actual Go Tag value. Public policy fields/methods and wire-only dependencies
remain unchanged.

Source/direct rustfmt only; no tests/builds/lint/validators/probes or fresh
security/dependency qualification. Cross-map error winners, remaining typed
map/owner/approver decoding, numeric overflow/nested value/custom error
envelopes, full policy nil/empty/deephash identity, raw/model ambiguity and
complete error/partial/cache/rollback/resource/concurrency/shutdown behavior
plus all native/wire-only/package/container/client/process/import/restart
qualification remain incomplete or unqualified. Existing fixtures were not
recaptured/run; all three release gates remain open.

### AliasEnc trimming and phased group decoding — 2026-10-18

The prepared policy path now applies the selected AliasEnc decoder to ACL
sources, grant sources/destinations, nodeAttrs targets and SSH sources/
destinations. Each value is decoded as a Go string and trimmed with the shared
Go Unicode 15 White_Space set. Explicit null alias elements become zero
strings before alias/reference validation. Ordinary group members, tag owners,
auto-approvers and ACL destinations retain their own decoder paths. Generic/
TOML serde fields remain unchanged.

Group validation now checks all group names before value/member types, then
checks nested groups in reverse lexicographic parent order before validating
username syntax. Diagnostics use the selected Go wording, quoting and dynamic
JSON-any type names. This removes interleaving that could report a username
or recursion error before a more fundamental name/type failure.

Private original ACL identity now distinguishes omitted Sources (nil) from
explicit null Sources: Aliases.UnmarshalJSON constructs a non-nil empty slice
for the latter. Explicit [] has the same source-slice identity as null. The
ordinary ACL destination slice retains its own nil/empty treatment. Public
policy/wire fields, methods and dependency boundaries remain unchanged.

Source/direct rustfmt only; no tests/builds/lint/validators/probes or fresh
security/dependency qualification. Cross-map error winners, numeric-to-any
overflow and nested invalid-value envelopes, typed-map key decoding, full
policy nil/empty/deephash identity, raw/model ambiguity and complete error/
partial/cache/rollback/resource/concurrency/shutdown behavior plus all native/
wire-only/package/container/client/process/import/restart qualification remain
incomplete or unqualified. Existing fixtures were not recaptured/run; all three
release gates remain open.

### Shared Go duration values and diagnostics — 2026-10-18

The ACL leaf now exposes a shared Go 1.26.9 time.ParseDuration translation.
Policy custom CheckPeriod decoding, per-rule validation, SSH approval/check
period calculation and the existing CLI Go-duration entrypoint use it. This
removes separate integer-decimal implementations from the policy and live SSH
paths. The parser preserves leading integer/fraction limits, float64 fraction
evaluation order and truncation, both microsecond spellings, signs/zero,
component and total bounds, and Go's unsigned accumulation before its bound
check. In particular, exact unsigned accumulation wrap is retained rather
than replaced by checked or wider-integer addition.

Errors retain Go's invalid-duration, missing-unit and unknown-unit classes,
including time.quote byte escaping. SSH's always sentinel remains in its
policy wrapper; it is not accepted by the standard duration parser. The CLI
public function keeps its signature and delegates to the shared leaf. The
separate Prometheus key-expiration grammar retains its existing path. Public
policy/wire field types and wire-only dependency boundaries remain unchanged.

Source/direct rustfmt only; no tests/builds/lint/validators/probes or fresh
security/dependency qualification. Existing fixtures were not recaptured or
executed. Cross-platform floating-point/error/resource behavior, surrounding
JSON custom-method error envelopes, complete policy nil/empty/deephash
identity, raw/model ambiguity, cache/rollback/concurrency/shutdown and all
native/wire-only/package/container/client/process/import/restart qualification
remain incomplete or unqualified. All three release gates remain open.

### Grant ProtocolPort and shared port-range parsing — 2026-10-18

Grant IP entries now follow their own ProtocolPort decoder: JSON strings are
unquoted before literal protocol validation, without ACL-style lowercasing or
numeric-name canonicalization. Whitespace inside native port entries is not
trimmed. Non-string entries are rejected through the ProtocolPort context,
including via grants whose IP entries previously escaped projection-time
validation. Grant IP entries no longer inherit ACL-specific protocol/port
compatibility checks that the pinned Go grant path does not perform.

A shared Go-derived range parser retains numeric ports and ranges in source
order. It follows the selected empty-hyphen-part handling, positive singleton
rule, zero-valued range endpoints, full-range wildcard and signed integer
parsing. The leaf grant projection, grant evaluator and API filter compiler
consume the same canonical patterns; valid forms such as repeated-hyphen
ranges can no longer validate and then disappear in the filter encoder.
ACL destinations use the same canonical range conversion. Their compatibility
check treats numeric 0-65535 as wildcard ports and uses pinned wording/quotes.
Legacy explicit port-pattern passthrough and per-entry trimming remain at
that separate input path. Public field/method/dependency boundaries remain
unchanged.

Source/direct rustfmt only; no tests/builds/lint/validators/probes or fresh
security/dependency qualification. Numeric-to-any overflow and nested invalid
value error phases/envelopes, duration diagnostic taxonomy, all-policy nil/
empty/deephash identity, raw/model ambiguity and complete error/partial/cache/
rollback/resource/concurrency/shutdown behavior remain incomplete or
unqualified, along with all native/wire-only/package/container/client/process/
import/restart evidence. Existing fixtures were not recaptured/run; all three
release gates remain open.

### Raw custom policy scalars — 2026-10-18

The prepared Go policy path now recognizes custom scalar fields before serde:
ACL and policy-test Protocol, ACL Action, SSH Action and SSH CheckPeriod. The
selected Go methods trim literal quote bytes from the raw JSON token rather
than unquoting JSON escapes. Numeric protocol tokens now reach Go numeric-name
canonicalization; explicit null protocol and escaped spellings are rejected
instead of becoming absent fields or decoded accepted names. SSH actions use
Go TrimSpace's rune set after raw quote trimming. CheckPeriod null preserves
the nil pointer; other scalar tokens pass raw duration parsing before per-rule
validation, including numeric zero.

Protocol canonicalization uses the shared Go simple Unicode lowercase table
and 64-bit signed integer parsing before known-number name mapping. Protocol
validation errors use pinned wording/Go quoting, and the packet-filter protocol
encoder retains protocol number zero for the signed-zero spellings accepted
by Go. Generic/TOML protocol normalization retains its existing whitespace
trim at that entrypoint. Ordinary aliases and opaque capability payloads stay
on their existing context-specific decoding paths.

Source/direct rustfmt only; no tests/builds/lint/validators/probes or fresh
security/dependency qualification. Exact duration error taxonomy, non-scalar
custom-field error phases/envelopes, ProtocolPort raw validation, all-policy
nil/empty/deephash identity, raw/model ambiguity, complete error/partial/cache/
rollback/resource/concurrency/shutdown behavior and all native/wire-only/
package/container/client/process/import/restart qualification remain incomplete
or unqualified. Existing fixtures were not recaptured/run; all three release
gates remain open.

### Original ACL identity and zero-value fields — 2026-10-18

PolicyStore now retains original ACL content identity beside the expanded
compilation model: ACL-list nilness, original ACL grouping, source/destination
slice nilness, original destination order and individual port lists, canonical
protocol and the original action string. This identity participates in cache
invalidation and rejected-update restoration. A grouped ACL and its separately
expanded equivalents can no longer suppress policy-content invalidation just
because their compiled rows compare equal. Whitespace, metadata and field-name
aliases are removed before capturing this identity; user-directory changes do
not rewrite it.

The source-shape helper captures compilation rows, validation aliases and ACL
identity in one pass, bound to the complete supplied grant/rule projection.
Existing helper signatures remain available. The Go HuJSON boundary now
materializes omitted source/destination fields as empty and omitted action as
the effective accept projection used by aclToGrants. Null ACL entries follow
the selected JSON-v2 struct decoder's zero-value behavior. The original absent
action stays distinct from explicit accept in private identity. Generic/TOML
serde keeps its required fields and explicit-action validation.

Source/direct rustfmt only; no tests/builds/lint/validators/probes or fresh
security/dependency qualification. Existing fixtures were not recaptured or
executed. Other policy fields' nil/empty identity and full deephash equivalence,
explicit-null scalar cases, legacy source-less callers, raw/model ambiguity,
map-order diagnostics, complete error/partial/cache/rollback/resource/
concurrency/shutdown behavior and all native/wire-only/package/container/
client/process/import/restart qualification remain incomplete or unqualified.
All three gates remain open.

### Original ACL aliases at user-validation boundaries — 2026-10-18

The shared source-shape capture now retains two representations: expanded
ACL rows for compilation, and the original source-then-destination alias
sequence for user-reference validation. Each source occurs once per original
ACL, before destination splitting or conditional self-destination reordering.
The shape is accepted only when source grants and the complete synthetic-plus-
explicit rule projection match the supplied document.

PolicyStore validates those captured aliases before publishing a candidate.
Programmatic/raw-mismatched policies validate all explicitly supplied ACL
rows rather than skipping a counted grant prefix. Native gRPC set/reload/check,
HTTP admin set/check, startup user validation and direct CLI policy validation
now pass their raw source to the additive source-aware validator. The existing
public validator signature and public policy/wire field types remain intact;
its legacy parsed-projection contract remains available for callers without
source. Grant-only aliases stay outside this explicit ACL validation phase,
as in pinned validateUserReferences.

Source/direct rustfmt only; no tests/builds/lint/validators/probes or fresh
security/dependency qualification. Existing fixtures were not recaptured or
executed. Legacy source-less callers, raw/model ambiguity, nil/empty and
original ACL grouping in policy-content invalidation, map-order diagnostics,
complete error/partial/cache/rollback/resource/concurrency/shutdown behavior
and all native/wire-only/package/container/client/process/import/restart
qualification remain incomplete or unqualified. All three gates stay open.

### Strict filter-string matching and recipient reduction — 2026-10-18

Peer matchers and ordinary packet-filter reduction now share a dedicated
util.ParseIPSet(value, nil) translation. It follows Go's wildcard, slash,
exactly-one-hyphen range and scalar-address branch order, rejects non-network
CIDRs, keeps range endpoints untrimmed, validates family/order and strips
endpoint zones while constructing IP sets. Invalid filter strings contribute
no matcher span and are dropped during reduction. Node address membership
uses the shared Go parser and rejects zoned query addresses.

Policy alias/typed-prefix construction stays separate: AddPrefix masks valid
host-bit prefixes, while filter-string parsing rejects those same prefixes.
CapGrant matcher destinations use the typed-prefix path. Its recipient
reducer requires typed prefix text, retains canonical original prefixes for
subnet overlaps, and emits Dsts/CapMap with the pinned reduced-rule shape.
Policy-side address/prefix/range helpers now use shared Go parsing as well.

Ordinary reduction now checks the same parsed set against node addresses and
all approved routes, including exits. Wildcard no longer survives solely by
being wildcard when a recipient has no matching addresses or approved routes;
IP ranges can overlap route prefixes without being coerced into one CIDR.

Source/direct rustfmt only; no tests/builds/lint/validators/probes or fresh
security/dependency qualification. Existing fixtures were not recaptured or
executed. Nil/empty encoding, raw/model ambiguity, standalone typed compiler
projection assumptions, complete typed-invalid/error/partial/cache/rollback/
resource/concurrency/shutdown behavior and all accumulated native/wire-only/
package/container/client/process/import/restart evidence remain incomplete or
unqualified. All three release gates remain open.

### Original grant protocol groups and self capabilities — 2026-10-18

The native packet-filter compiler now constructs an ordered internal grant
sequence from original grants followed by explicit ACL destination conversions.
Synthetic network-grant rows remain a private/public model projection and are
not mistaken for independently compiled policy grants. Admission and per-node
category detection share that sequence, including empty-source/destination and
autogroup:self-source rejection. ACL conversions retain the pinned conditional
non-self-before-self ordering.

Each original grant IP entry keeps its ProtocolPort boundary and duplicate
ports. TCP/UDP entries are no longer collapsed by equal port ranges. Regular
network rules, regular capability rules/companions and deferred self rules
follow compileOneGrant order. Self network destinations follow node, port,
address order. Source membership for self rules uses the original resolved
source sets, excluding wildcard approved-route additions; a matched node's
invalid address suppresses the self expansion as Go's IPSet builder does.

Self capabilities retain one CapGrant per same-user node rather than merging
all nodes into one entry. Exit-node extras use that same helper for every
other user in numeric ID order, including app-only self grants and companion
capabilities; those extras append after the merged recipient batch without
another merge. Via grants retain srcIPsWithRoutes source construction, numeric
prefixes in alias order with duplicates, a single trailing internet expansion,
and explicit host-prefix bits in DstPorts.

Source/direct rustfmt only; no tests/builds/lint/validators/probes or fresh
security/dependency qualification. Existing fixtures were not recaptured or
executed. Nil/empty encoding, raw/model ambiguity, standalone typed compiler
projection assumptions, complete malformed/zero/zone and exact error/partial/
cache/rollback/resource/concurrency/shutdown behavior and all accumulated
native/wire-only/package/container/client/process/import/restart evidence
remain incomplete or unqualified. All three release gates remain open.

### Packet-filter address order and merge phases — 2026-10-18

Native source compilation now resolves aliases independently, merges the
usable IP sets into numeric ranges, then follows buildSrcIPStrings: wildcard
approved-route entries retain first-occurrence node/announcement order, and
non-wildcard source aliases append their own range strings in alias order.
This preserves explicit identities beside wildcard ranges, including the
wildcard plus danger-all branch. Empty or errored aliases retain the existing
usable-partial-set behavior. Destination aliases retain policy order, with
minimal numeric prefixes inside each alias rather than a global text sort.

Filter merging now keys ordered SrcIPs/IPProto slices, appends DstPorts
without sorting or deduplication, and passes CapGrant entries through without
reordering them. Capability destinations use each alias's minimal prefixes;
companion sources retain per-alias prefix order/multiplicity and companion
rules are no longer suppressed solely for empty sources/destinations. Only
recipient CapGrant narrowing sorts and compacts its destination prefixes,
using Go numeric Prefix.Compare. Global/per-node native and opaque packet
filters no longer run an additional merge after recipient reduction.

Source/direct rustfmt only; no tests/builds/lint/validators/probes or fresh
security/dependency qualification. ProtocolPort grouping boundaries, self
CapGrant per-node grouping and exit-node self capabilities remain concrete
source residuals. Nil/empty encoding, invalid/zero/zone cases, exact error/
partial/cache/rollback behavior, resources/concurrency/shutdown and all
accumulated native/wire-only/package/container/client/process/import/restart
qualification remain open. Historical fixtures were not recaptured or run;
all three release gates remain open.

### Private packet-filter grant projection — 2026-10-18

PolicyStore now builds a private filter document with generated network-grant
rows followed by the retained original ACL rows. Global filters, per-recipient
filters, opaque filter payloads and per-node category detection consume that
representation. Typed policies no longer depend on their caller reproducing
the parser's generated prefix. The public doc() snapshot and raw source keep
their existing representations.

Grant projection errors return before candidate state is published. Rejected
SetPolicy restores the prior private document, and SetUsers updates/restores
its directory beside the public document while retaining the existing partial
compiled-state failure behavior. Raw omitted/null filter fields select the
allow-all default only when the typed document also has no ACLs or grants;
explicit programmatic policy rules cannot be bypassed by a raw {} source.

Source reads/edits and direct rustfmt only; no tests/builds/lint/validators/
probes or fresh dependency/security qualification. Ambiguous source/model
mismatches, direct standalone compiler calls on nonparsed documents, exact
error/partial/cache/rollback behavior, resources/concurrency/shutdown and the
complete native/wire-only/package/container/client/process/import/restart
qualification remain open. All three release gates stay open.

### Original ACL rows beside grant projections — 2026-10-18

Native via fallback no longer skips a counted prefix of PolicyDoc.rules.
The shared source-shape helper recovers original ACL rows through the same
prepared JSON, metadata removal, normalization and typed decoding boundary.
It uses them only when source grants and the complete generated-plus-original
rule projection equal the supplied document. Otherwise every explicit rule
in the supplied document remains an ACL row for this native boundary.

PolicyState retains those rows independently of public synthetic grant rules.
They participate in cache invalidation and are restored with the prior policy
on a rejected write. ViaRoutesForPeer receives the retained ACL rows directly,
so programmatic documents are not subject to a guessed generated-rule count.
Public policy/wire field types and dependency boundaries remain unchanged.

Source reads/edits and direct rustfmt only; no tests/builds/lint/validators/
probes or fresh advisory review. Broader programmatic/raw-document consistency,
other compiler projection boundaries, exact errors/resources/cache/rollback/
concurrency and all native/wire-only/package/container/client/process/import/
restart qualification remain incomplete or unqualified. All three release
gates remain open.

### Native via alias resolution and ordered HA fallback — 2026-10-18

PolicyStore via selection now follows a private three-pass implementation of
PolicyManager.ViaRoutesForPeer under its policy read lock. Each source alias
resolves independently against retained policy nodes; an errored alias is
skipped without hiding a later usable alias. Each destination alias contributes
its merged minimal IP-set prefixes in numeric order, while autogroup:internet
is retained as a separate exit-route flag. Current viewer/peer identities are
kept distinct from retained alias/election candidates. The pre-expanded
CompiledRuntime via-document copy has been removed.

The native path preserves original grants followed by ACL-to-grant destination
order, Include/Exclude multiplicity, per-tag lowest-ID election with Go's zero
sentinel, and grant/destination/included-route order for UsePrimary. Exit-route
exclusions relax only for explicit regular wildcard/internet aliases. Exit
routes do not acquire subnet-only election behavior from an internet flag.
The shared public AclDoc via helper remains available to downstream callers;
native map route selection uses the retained-node implementation.

Retained policy-node route values now preserve announcement order and
multiplicity. Policy/network cache invalidation still compares unordered
multisets with duplicate counts, rather than treating reordering as a policy
change. Numeric IP-set prefix emission reuses the existing interval encoder.
No public wire fields, public method signatures or dependency versions changed.

Source reads/edits and direct rustfmt only; no tests/builds/lint/validators/
probes or fresh advisory review. Programmatic documents without parser grant
projections, alias/partial/error diagnostics, malformed/zero/native pointer
states, full policy/cache/HA/co-router churn, performance/resource/concurrency/
shutdown and all native/wire-only/package/container/client/process/import/
restart qualification remain incomplete or unqualified. All three release
gates remain open.

### Self/peer route reduction and via PrimaryRoutes — 2026-10-18

Self map construction now reduces global primary subnet routes with global
State.Filter-style matchers before appending the node's approved exits.
It uses captured native identity/addresses and active subnet source identities;
compiled runtimes reuse their global matchers, including for per-node policies.
Peer route selection removes the unconditional exit bypass: pinned
State.RoutesForPeer reduces the global-primary-plus-exit list with the viewer's
matchers, then applies via and co-router rules. Self exits remain appended
without that peer-view reduction. Older upstream comments describing
unconditional peer exits do not match the pinned function body used here.

Peer PrimaryRoutes now derives from every returned non-exit route, including
via-only routes, exactly where TailNode derives it. Route reduction retains
its input order. Via matching walks destinations before announced subnet
routes, appends exit matches for autogroup:internet, and retains Include/Exclude
order/multiplicity. Final AllowedIPs still sorts with Prefix.Compare and keeps
duplicates; PrimaryRoutes is not separately sorted back into global ownership.
This supersedes the earlier selected-route sorting source description.

Approved/announced intersections now walk announcements in order and preserve
announcement duplicates rather than approval ordering or set deduplication.
Primary election continues to normalize its own set. Snapshot served routes
no longer append exit routes a second time or sort away announced shape.
Public normalization helpers and wire field types remain unchanged.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/lint/
validators/probes or fresh advisory qualification. Full via alias-resolution/
UsePrimary ordering, typed zero/malformed route states, cache/error/phase/
policy/co-router/HA churn, packet behavior/resource/concurrency/shutdown and
all native/wire-only/package/container/client/process/import/restart evidence
remain incomplete or unqualified. All three release gates remain open.

### SSH query bytes and encoded node IDs — 2026-10-18

SSH action query extraction now retains raw decoded auth_id/local_user bytes
in skipped private metadata alongside the existing public String projections.
Native check-user evaluation compares literals, root and resolved localparts
by bytes; nonempty invalid UTF-8 can match nonroot without being confused with
a valid replacement-character literal. The same bytes remain authoritative
through follow-up policy revalidation and concrete hold-URL query encoding.
Public string policy methods delegate to the same byte-oriented checker.

Auth IDs are validated by prefix and byte length after the current policy
check, following AuthID.Validate. A valid-shaped non-UTF-8 ID necessarily misses
the UTF-8 String-key cache and re-delegates; malformed shape returns Invalid
auth_id. The public binding's local_user remains a compatibility projection
(empty for invalid UTF-8); native authorization never reads that projection,
and approval/cache binding remains the src/dst pair as in Go.

The handler reads node IDs from the raw matched URI instead of Axum's
percent-decoding UTF-8 Path extractor. Pinned Chi routes RawPath where present,
so encoded digits are not silently accepted as decoded numeric IDs. Invalid
source/destination bytes reach the pinned error envelope. Unmatched route,
percent-encoded static prefix, HTTP request-target validation and unusual
mount/rewrite behavior remain unqualified.

Source reads/edits and direct rustfmt only; no tests/builds/lint/validators/
probes or fresh advisory qualification. Raw byte/route/alias corpora, direct
public binding/query projection behavior, request-target/HTTP2 rejection,
URL/GODEBUG/error/entropy/cache/resource/concurrency/shutdown and all native/
wire-only/package/container/client/process/import/restart evidence remain
incomplete or unqualified. All three release gates stay open.

### SSH delegation URL parse and reassembly — 2026-10-18

The private delegation URL path now applies Go-style Parse to the configured
base plus SSH suffix before auth-ID entropy or cache insertion. It retains
scheme case normalization, opaque/rootless forms, relative paths, OmitHost,
userinfo and password escaping, raw host spelling, strict HTTP colon/port
checks, IPv6 literal/zone validation, escaped path hints and fragment hints.
It reassembles those components after replacing the query, rather than
assuming the suffix became a URL path. Base queries and fragments therefore
retain the same placement and suffix interpretation as pinned Go.

Shared query values now retain decoded byte keys/values and duplicate value
order, discard malformed/semicolon pairs, follow the default 10,000-parameter
limit and sort decoded keys before encoding. Auth ID and concrete local_user
replace their existing slices while unrelated valid query pairs survive.
Encoded non-UTF-8 bytes in unrelated query data round-trip without a String
projection. Failed URL parsing returns Internal error before randomness and
before creating an auth session. This supersedes the handler's earlier simple
string-only URL concatenation source gap.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/lint/
validators/probes or fresh advisory review. URL corpora, exact diagnostics,
nondefault Go GODEBUG URL modes, raw invalid-UTF-8 configuration/request paths,
request local_user byte semantics, allocation/resource/entropy/cache/error/
concurrency/shutdown and all native/wire-only/package/container/client/process/
import/restart qualification remain incomplete or unqualified. All three
release gates remain open.

### SSH action HTTP and hold delegation — 2026-10-18

SSH action requests now use URL.Query().Get-style first-value parsing instead
of serde duplicate-field rejection. Empty auth_id takes the initial-request
path; malformed escape/semicolon pairs use the shared Go query parser.
Unsigned decimal node IDs return pinned invalid source/destination text.
Destination lookup and Noise machine-key validation precede query use.
Invalid UTF-8 path/query behavior remains narrower than Go and unqualified.

HoldAndDelegate now includes the concrete local_user escaped with Go query
rules and sorted auth_id/local_user parameters. The compiled policy retains
the literal $LOCAL_USER template. Compiled and handler URL concatenation
preserve base trailing slashes; provider /auth URLs trim only one slash.
Hold and follow-up reject responses retain initial forwarding flags.

SSH action JSON uses the shared tailcfg action schema, Go HTML escaping and
Encoder.Encode newline. Encode failure retains the committed 200 boundary
with an empty body/log. Text errors add nosniff. Auth-ID entropy reads 24
bytes and truncates URL-safe unpadded base64 to 24 characters; failure returns
Internal error before cache insertion instead of panicking.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/lint/
validators/probes/advisory checks. Full Go URL parsing/query/fragment/invalid-
base phases, invalid UTF-8/path extraction, header/flush/IO/RNG failures,
approval/replay/concurrency/resource/shutdown and all native/wire-only/package/
container/client/process/import/restart qualification remain incomplete or
unqualified. Existing fixtures are unrecaptured and unexecuted. All three
release gates remain open.

### SSH principal construction and check alias failures — 2026-10-18

User principal IP sets and tagged-node localpart self-access now parse addresses
through the Go-compatible leaf, removing IPv6 zones as IPRangeFrom does.
An invalid address still prevents emission from that account/self-access
builder, matching the compiler's explicit builder-error check. Tagged ordinary
principals instead use canonical Addr.String-style text, retaining zones,
typed zero display ("invalid IP") and per-tag multiplicity. The source alias
resolver still retains valid partial IP sets together with errors; this batch
does not discard those sets from map policy compilation.

SSH check authorization now distinguishes that compilation behavior from its
own boundary: any source resolution error skips that check rule, and each
non-self destination with an error is skipped. Successful later rules and
localpart self-access follow the existing source-selected flow. This prevents
using a usable-but-errored alias set to authorize a check where pinned Go would
skip it. Check-user authorization now follows sshRuleAllowsUser directly:
explicit root, nonroot and literal users are checked independently of compiled
principal grouping, while localpart still requires an untagged hydrated owner.
An unowned source selected by a valid source alias can therefore follow Go's
literal-user check path even though groupSourcesByUser emits no map principal.
The public resolver/compiler signatures and field types remain.

Localpart resolution now iterates entries before directory users with last
match winning, retaining entry order and multiplicity. Domain matching still
uses Go EqualFold. This aligns ordering for repeated user identities without
rewriting source domains or changing ordinary unique-user results.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/lint/
validators/probes/advisory checks. Full alias/partial/error diagnostics,
malformed/wide/custom imports and duplicate identities, zoned/mapped/zero
addresses, all SSH authorization/revocation/replay/race boundaries and all
native/wire-only/package/container/client/process/import/restart qualification
remain incomplete or unqualified. All three release gates remain open.

### SSH policy native acceptEnv equality — 2026-10-18

The private SSH policy snapshot now retains acceptEnv nilness for each emitted
rule. The policy source shape pass distinguishes missing/null from explicit
empty arrays using the existing prepared HuJSON/JSON field-folding boundary.
A single source rule can emit multiple self, ordinary and localpart rules;
its nilness follows those rules through stable check-before-accept sorting.
Public PolicyDoc and wire SSH field types remain unchanged.

PolicyState includes this shape in cache invalidation and restores it with the
previous document after a rejected write. CompiledRuntime retains the shape
with its SSH document and lazy per-node cache. Native map construction captures
the policy and comparison metadata together, including its initial cache;
per-connection SSH equality now sees nil-versus-empty acceptEnv even when both
serialize away. Explicit empty revocation policies and the last-non-nil cache
behavior remain. Successful whole-batch encoding is still the cache update
boundary, and debug dumps keep the pre-deduplication SSH policy.

Pinned Go startup and fresh registration explicitly initialize IsOnline=false;
this source pass found no new standard production online-pointer repair.
Custom/direct node pointer and SSH fields, time/location metadata, complete
policy compilation/failure/cache phases, raw-shape mismatch with programmatic
documents, concurrent policy/node edits, queue/network delivery, and all
native/wire-only/package/container/client/process/import/restart qualification
remain incomplete or unqualified. Source reads/hashes/edits and direct rustfmt
only; no tests/builds/lint/validators/probes or fresh advisory review. All three
release gates remain open.

### Native map slice, address and LastSeen projection — 2026-10-18

Native map snapshots now consume retained nullable endpoints/tags when
remembering self and peer equality. A hidden nil/empty change prevents an
otherwise-equal comparison or a partial patch from suppressing the native
state change. Offline LastSeen uses the retained nullable value while its
saved projection matches; a later live timestamp supersedes it. Public wire
field types remain unchanged and wire-only builds acquire no admin/database
imports.

Map identity prefixes now derive from captured native address pointers,
including typed zero addresses, actual families independent of SQL column
name, and IPv6 zones removed by PrefixFrom. No address pointers yield
Addresses:null; filtering all IPv4 identities from a non-nil source retains
Addresses:[]. Empty AllowedIPs is omitted because slices.Concat produces nil
for a zero-length result. The existing one-policy-read attribute snapshot and
fallback now use captured native policy addresses and owner identity.

Identity-only disable-ipv4 filtering now precedes route concatenation so an
advertised route equal to an identity prefix survives. AllowedIPs concatenation
sorts with Go Prefix.Compare and preserves duplicates. Selected route vectors
also use Prefix.Compare. Peer Node.ID sorting uses signed int64 order after
the bit-preserving public ID conversion. These are source implementations;
ordinary and unusual imports, route collisions, dual-stack/mapped/zoned/zero
addresses, policy churn and all affected fixtures remain unexecuted.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/lint/
validators/probes or fresh advisory review. Native online-pointer presence,
time/location and raw capabilities/SSH reflection metadata, direct public
serde/custom adapter nil shapes, malformed values, concurrent mutation/queue/
network delivery and all native/wire-only/feature/package/container/client/
process/import/restart qualification remain incomplete or unqualified.
All three release gates remain open.

### Per-connection self state and stream failure/change handoff — 2026-10-18

Map connection state now retains native Hostinfo alongside the public node
projection. Self-node equality uses the full typed Hostinfo schema, including
NetInfo fields ignored by incoming map-update comparisons. It normalizes Go
zero scalar creation/expiry times and optional zero machine/disco keys, and
excludes ExitNodeDNSResolvers and DataPlaneAuditLogID as pinned Node.Equal
does. Capability argument slices keep nil/empty equality through the public
projection. Other lost native slice/pointer/raw payload distinctions remain
outside this repair. A changed self/DNS prelude advances a preview cache
before the subsequent policy frame is deduplicated; full rebuilds use the
same per-connection comparison. Debug dumps retain pre-deduplication nodes.
The preview becomes carried state only after the complete batch encodes.

Incremental/full map and ping encoding failures now propagate through try_unfold and
end the body, following poll.go's writeMap error return. They no longer emit
a successful keepalive after consuming the change. This supersedes the
keepalive-on-encoding-failure behavior described in the preceding batch.
SSH cache updates still happen only after successful complete encoding.
Network delivery acknowledgement, partial-frame delivery and separate
frame boundaries within an encoded batch remain unqualified.

Registry generation, batch, DERP and DNS subscriptions now precede the
initial map snapshot. Published batches remain queued after that first full
frame. DNS uses a retained watch receiver so config, extra-record and reverse
prefix edits during frame encoding/yielding are observed on the next wait.
The existing one-shot DNS notify APIs remain available to callers. DNS inputs
and node/policy/filter/config snapshots still lack cross-component atomicity.

Source reads/edits and direct rustfmt only; no tests, builds, lint, validators,
process/client probes or advisory checks. SSH native nil/empty/reflection and
time-location distinctions, wider node metadata, encoding/writing failures,
initial-map concurrency, watch coalescing, queue/backpressure/reconnect/rekey,
shutdown, native/wire-only/package/container/client/import/restart behavior
remain incomplete or unqualified. All three release gates remain open.

### Leading removals and captured map rebuild state — 2026-10-18

Runtime policy/full-view removals now use a dedicated PeersRemoved-only frame
before the accompanying policy/full map, following pinned Go withRemovals.
It carries no Node, DNSConfig, SSHPolicy, ControlTime or packet filters.
Full rebuilds compute previous-minus-current peers even when some peers
remain visible. Runtime policy updates resend all remaining visible peers as
PeersChanged, including otherwise unchanged nodes. Explicit registry deletion
responses keep their existing ordinary delta path. An existing separate
self/DNS prelude remains ahead of the runtime policy removal/policy pair.
Computed removal-only frames do not add mapper debug dumps or builder counts.

Full rebuilds now return encoded bytes and their remembered peer/self state
together from the snapshot used to construct the response. Callers no longer
take separate fresh snapshots to remember what was emitted. Incremental and
full batches finish encoding all component frames before returning new state;
encoding failure returns a keepalive with prior peer/self state. SSH policy
deduplication previews without mutating its cache and records only a non-nil
policy after successful encoding, retaining the last non-nil policy when the
new response has none. Mapper debug output keeps the pre-deduplication policy.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/validators/
probes or fresh advisory review. Existing frame/peer/SSH assertions remain
unrecaptured and unexecuted. Exact removal ordering, projected versus native
self/SSH equality, generation-cursor retry behavior after failures, queue/
network delivery, frame metrics, reconnect/rekey/policy churn, cancellation/
backpressure/load/shutdown and broader cross-component snapshot coherence
remain incomplete or unqualified. Native/wire-only/feature/package/container/
client/process/import/restart qualification and all three gates remain open.

### Native registration JSON encoding — 2026-10-18

Registration success, follow-up, expiry and error envelopes now pass through
a private encoder matching pinned RegisterResponse/User/Login field order.
User and login IDs use Go's uint-to-int64 conversion without changing public
u64 fields. Empty optional profile pictures and Go-zero creation times omit;
other typed creation times use canonical fractional digits. Required false
booleans, empty strings and NodeKeySignature remain present, with nil signature
encoded as null and non-nil empty signature as the empty base64 string.
Go compact/HTML processing escapes string contents before the existing HTTP
wrapper appends Encoder.Encode's newline. Header/status and encoding-failure
handling retain their established paths.

SimpleUser/SimpleLogin ID deserialization accepts signed wire IDs into the
existing u64 bit-pattern projection, preserving legacy unsigned inputs and
direct public serialization. Timestamp formatting consumes the producer's
existing UTC projection; this change does not restore discarded storage
timezone/location metadata or complete user/owner association semantics.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/validators/
probes or fresh advisory review. Existing registration assertions remain
unrecaptured and unexecuted. Full producer/DB timestamp and wide-ID metadata,
strict direct public serde, malformed key/signature/Unicode inputs, exact
errors/logging, flush/cancellation/resource/concurrency and native/wire-only/
feature/package/container/client/process/import/restart qualification remain
incomplete or unqualified. All three release gates remain open.

### Live signed IDs and zero-field encoding — 2026-10-18

Native map encoding now applies Go's unsigned-storage-to-int64 conversion to
node/user/profile/patch IDs, removed-ID slices and integer map keys. Decimal
map keys sort after conversion; StableID remains the original unsigned decimal
string, matching headscale NodeID.StableID. Other typed integer fields follow
the same pinned 64-bit representation. Public u64 field types remain intact.

Private public-wire deserializers accept signed map IDs by retaining their
64-bit pattern in those u64 fields. Removal slices and ID boolean maps accept
signed IDs, nil containers and fresh null elements/values. Map entries are
converted in input order so aliases retain the latest value. The existing
unsigned input range and direct unsigned serialization remain available;
these public adapters are not a strict substitute for Go's signed decoder.

The live encoder now applies the pinned schema's omitempty/omitzero rules,
including non-nil zero key/time pointers in peer patches. Ordinary pointer
bool/int/address zero values remain present, and non-nil zero LastSeen times
remain present where tagged omitempty. Explicit-unset opt.Bool remains null.
Required fields hidden by the public projection receive their zero value,
including nil SSH fields and dial candidates. Empty root health and false
omitDefaultRegions now omit. Named packet-filter empty/deletion updates,
required explicit arrays and existing extension fields remain distinct. This
supersedes the earlier ordering-only encoder's selected-field omission gap.

Source reads/edits and direct rustfmt only; no tests/builds/validators/probes
or fresh advisory review. Existing assertions remain unrecaptured and
unexecuted. Full producer nil/empty origin metadata, registration/admin/SQL
wide-ID handling, strict direct public serde, malformed numeric/key/time/
network/Unicode inputs, error/resource/concurrency and all native/wire-only/
feature/package/container/client/process/import/restart qualification remain
incomplete or unqualified. All three release gates remain open.

### Live map encoding and capability overlays — 2026-10-18

Native full/delta/ping/expired map output and native debug dumps now use a
shared declaration-order encoder. Root, node, patch, Hostinfo, DNS/DERP/SSH
and other nested records follow the pinned schema order; known timestamps
and floats use the private Go-shaped formatters. Captured opaque base filters
remain raw and now occupy PacketFilters' declared root position. Other named
filters use ordered rule/grant/port fields. The encoder preserves the fields
selected by construction, explicit empty updates, named-filter deletion
markers and existing extension fields; it does not apply debug readback's
decode/omission rules to live updates. Existing framing/compression remains.

Approved exit peers now receive suggest-exit-node even without a corresponding
policy attribute. Peer no-argument capability slices emit null. Self baseline
capabilities retain explicit [] unless policy overrides them: policy attrs
now replace baseline/runtime values after configuration defaults, matching
Go maps.Copy, and emit nil argument slices even when the name overlaps a
baseline or default-auto-update capability. Taildrop policy overlays follow
the same order. Public capability-map vector types remain unchanged.
MapNode/PeerChange deserialization accepts null maps and argument slices,
projecting nil values into the existing empty vectors; direct reserialization
through those public vectors still cannot retain their nilness.

Map construction now captures node attributes for the node snapshot under one
policy read and retains that immutable sidecar through encoding. Address
shape, capability overlays and requester DNS attributes consume this capture;
the encoder uses it to retain exact policy nil slices without a second policy
lookup. These attribute captures do not make the broader policy/filter/config/
node publication sequence atomic. Public store read/record and direct serde
interfaces retain their existing narrower shape representation.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/validators/
probes or fresh advisory review. Existing wire/debug/golden assertions remain
unrecaptured and unexecuted. Complete producer nil/empty/selected-field
omission, signed-ID casts, wide/private shapes, fallback/custom adapters,
float/time/key/network/error fidelity, snapshot/reload/cancellation/load/
shutdown behavior and native/wire-only/feature/package/container/client/
process/import/restart qualification remain incomplete or unqualified.
All three release gates remain open.

### Nested native debug response schemas — 2026-10-18

Native map-response readback now decodes the remaining pinned response records
through private schemas: DNS/resolvers/extra records, user profiles, ping,
display messages/actions, client version, control dial plan/candidates, debug,
TKA info, DERP home/region/node data and SSH policy/rules/principals/actions/
recording failure actions. The public MapResponse projection and its debug
Hostinfo conversion are no longer part of this readback path. Public wire
types, live Hostinfo operations and dependency features remain unchanged.

The private record containers retain repeated pointer/object merges, nil
pointer resets, reused struct/pointer arrays and truncated tail slots. Map
objects merge keys while each entry decodes a fresh value; integer keys retain
the signed 64-bit Go range and emit sorted decimal strings. Required nil
maps/slices/pointers remain null, including DERP Regions, dial Candidates and
SSH rules/principals/sshUsers/action. DNS route values preserve null, [] and
nullable resolver elements. Profile/extra-record null struct elements retain
their zero or reused fields. All schemas emit their declared field order and
omitempty/omitzero rules; SSH duration remains an int64 nanosecond value.

Typed float output now applies Go encoding/json's decimal range [1e-6,1e21),
signed-zero handling and unpadded signed exponent presentation to Rust's
shortest decimal digits. This covers typed DERP/dial/debug and Hostinfo float
values/maps; opaque capability JSON still bypasses numeric materialization.
Full shortest-digit/rounding equality remains unqualified.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/validators/
probes or fresh advisory review. Existing assertions remain unrecaptured and
unexecuted. Exact float parser/rounding/formatting, typed decoder error text/
ordering, invalid UTF-8/Unicode/key/network/time edges, IO/resource/concurrency
behavior, direct public read/serde and live wire output remain incomplete or
unqualified. Native/wire-only/feature/package/container/client/process/import/
restart qualification and all three release gates remain open.

### Native debug node and response state — 2026-10-18

The native debug directory reader now keeps Node, Peers, PeersChanged and
PeersChangedPatch in private typed state through final response encoding.
Repeated node objects merge; nonempty peer arrays reuse pointer slots and
truncated tail slots, while null pointer entries clear them. Required node
fields use Go zero values, Addresses retains nil/empty, and AllowedIPs omits
only nil. IDs and int fields retain signed 64-bit values. Key, prefix,
endpoint, address, signature-byte and resolver fields use typed normalization
and Go declaration/omission order. Capability maps retain their opaque raw
payloads and merge across repeated objects and reused nodes.

HostinfoView now follows its generated one-time initialization contract:
null initializes an empty valid view, and a second initialization rejects the
dump. Hostinfo and its nested struct/service fields emit in declaration order.
Private timestamps retain numeric offsets, canonicalize fractional digits,
distinguish pointer/scalar nulls and apply IsZero to the fields tagged
omitzero, including non-nil zero key/time pointers in peer patches. Timestamp
decode and marshal phases are separate: a decoded unencodable offset fails
the final HTTP body rather than being treated as an invalid dump to skip.
The established live UTC projection keeps its existing function signature.

Response field names now canonicalize with Go case folding, unknown root
subtrees are scanned without Value allocation, and root fields emit in Go
declaration order. Simple scalar fields, health/removal slices, signed-ID
boolean maps, control time and both opt.Bool fields retain repeated-field,
null, omission and map-merge behavior. Explicit-unset opt.Bool emits null.
Native filters now emit directly from their private state, without projection
presence markers. Public wire fields and wire-only dependencies are unchanged.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/validators/
probes or fresh advisory review. Existing debug assertions remain unrecaptured
and unexecuted. Remaining nested response fields (including DERP/DNS, SSH,
profiles, display/debug/dial/client-version data), full float formatting,
typed decoder/error/log/IO/resource/concurrency fidelity, direct public
read/serde, live wire emission and native/wire-only/feature/package/container/
client/process/import/restart qualification remain incomplete or unqualified.
All three release gates remain open.

### Stateful native debug filter decoding — 2026-10-18

Native debug readback now decodes PacketFilter and PacketFilters through a
private filter model before the stable public response projection. Repeated
nonempty slice fields reuse their prior elements, including slots retained
after a shorter array. Null and empty arrays reset that state; required
SrcIPs/Dsts retain null versus [] when emitted. Null struct/scalar elements
leave reused values intact. Nested NetPortRange/PortRange fields merge with
Go's null/pointer behavior, required zero fields, case folds and declaration
order. SrcBits, IPProto and Bits use the pinned 64-bit Go int range without
changing the public i32 fields. Dsts uses the existing Go netip prefix parser
and preserves zero prefixes. Unknown filter fields are scanned and discarded.

Repeated CapMap objects merge keys; a repeated map key decodes a fresh raw
value slice, and null clears the map. Named filter objects merge names while
each repeated name gets a fresh rule slice. This retains named null deletion
markers and non-nil empty rule arrays. Node/PeerChange CapMap fields also merge
within each decoded object. Private presence markers carry these fields
through the public projection; final encoding restores their complete native
JSON. Opaque payload spelling/order/duplicates remain byte-preserved, with no
per-payload dummy Value allocation for node capability maps.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/validators/
probes or fresh advisory review. Existing debug assertions remain unrecaptured
and unexecuted. Surrounding MapResponse/Node/Hostinfo field order, full typed
schema/aliases/nulls/repeated node objects and node-slice backing reuse, direct
public read/serde, exact error/log/resource/concurrency behavior and native/
wire-only/feature/package/container/client/process/import/restart qualification
remain incomplete or unqualified. All three release gates remain open.

### Required capability destinations and filter JSON order — 2026-10-18

CapGrant.Dsts now remains present for empty vectors. Pinned Go's destination
IP-set Prefixes method returns a non-nil empty slice, whose required Dsts field
emits []. The private opaque-filter encoder writes declared FilterRule fields
in SrcIPs/SrcBits/DstPorts/IPProto/CapGrant order and CapGrant fields in
Dsts/Caps/CapMap order, with their respective omission rules. Raw capability
payloads still bypass Value encoding, while capability map keys sort normally.

Native debug readback retains missing/null SrcIPs and Dsts as nil separately
from explicit empty arrays, accepts fresh null rule/grant struct elements,
normalizes the covered nil optional filter slices, and restores Go filter/
grant field order when emitting the typed response. Public Vec field types
remain unchanged; their direct nil representation is still narrower.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/validators/
probes or fresh advisory qualification. Existing filter/debug/golden assertions
remain unrecaptured and unexecuted. Full surrounding response/node/Hostinfo
field order, aliases/null/duplicates/backing slots, direct public read/serde,
wide values, opaque typed-input limits, errors/resources/concurrency and all
native/wire-only/feature/package/container/client/process/import/restart
qualification remain open. No release gate closes.

### Opaque capability JSON in debug readback — 2026-10-18

Native `/debug/mapresponses` readback now captures Node/PeerChange CapMap and
legacy/named packet-filter capability payloads before the typed Value decode.
The surrounding response and Hostinfo still pass through the existing typed
projection. Re-encoding restores the captured raw payloads, preserving numeric
and string spellings, payload object order and duplicates, and nil map-value
slices. Capability names use sorted Go map-key order. Opaque values no longer
depend on Serde Value's numeric/depth representation. The final response uses
shared Go compact/HTML/indent processing, with decimal node keys sorted as
strings. Root directories are read in name order; signed node directory names
are rejected, and a partial node-directory enumeration error skips that node.

Source reads/edits/hashes and direct rustfmt only; no tests/builds/validators/
probes or fresh advisory review. Existing debug assertions remain unrecaptured
and unexecuted. Full Go surrounding-response field order, aliases/nulls/
duplicates/backing slots, required empty fields, wide scalar/date/key/address
values, direct public read/serde APIs, IO/log/resource/concurrency behavior and
all native/wire-only/package/container/client/process/import/restart
qualification remain open. No dependency release/public wire-field type or
release gate changed.

### API-key state operations and native mint phases — 2026-10-18

API-key expiry/deletion now load the typed key before writing, retain the
loaded primary ID and zero-ID WHERE guard, use write transactions, and accept
a successful zero-row write after lookup. Prefix and credential lookups use
Go First's primary-ID ordering. Creation prepares entropy/bcrypt before pooled
acquisition, assigns CreatedAt after beginning the save, and returns its
original model without rereading trigger/driver values. Empty RETURNING scans
leave ID zero as Gorm create does. Save errors keep the upstream operation
context. Postgres binds micros while the returned model retains nanos; expiry
captures its clock before pool wait.

Checked native list/validation methods preserve errors through additive trait
defaults. gRPC list propagates failures; key creation/mutation errors use raw
Go-facing Unknown statuses, including record-not-found lookup text. gRPC auth
returns Internal validating-token for validation errors and Unauthenticated
invalid-token for a correctly authenticated expired key. Existing bool/list
adapter methods retain their compatibility contracts. API/preauth mutation
RPCs own completion after acceptance independently of caller cancellation.

Native API/preauth mints share Go's raw-URL-base64 encoding/truncation and
propagate entropy errors; public convenience generator signatures stay intact.
Native preauth nil-owner/empty-tags rejection now occurs after BEGIN. Other
adapters keep preliminary validation. The RPC's initial user lookup retains
stored model identity; native preauth errors use the shared Go-facing envelope.

Source reads/edits/hashes and direct rustfmt only; no tests/builds/validators/
probes or fresh dependency/advisory qualification. Existing key/auth/status/
gateway/CLI assertions remain unrecaptured and unexecuted. Full Go scalar/
date/unsigned-ID/byte/scan-error semantics, detailed credential diagnostics,
external transaction nesting, trigger/driver/failure/resource/clock/race/
cancellation/shutdown/custom and all native/wire-only/feature/package/container/
client/process/import/restart qualification remain open. Historical reports
predate this batch; no release gate closes.

### Legacy encrypted Postgres key compatibility — 2026-10-18

The native PEM bridge no longer relies on AWS-LC's rejection of weak/semi-weak
DES or degenerate TripleDES keys. A private Go-derived DES/TDEA implementation
uses pinned constants, key selection/rotations, permutations, substitution,
CBC chaining and RFC 1423 unpadding. AES retains locked AWS-LC. The unused
AWS-LC legacy-DES feature is removed; no dependency release was changed.
The pgx loader retains its unable-to-decrypt-key context and Go's header/mode/
IV/block/padding/password decisions. Hex errors retain first-invalid-byte
precedence, odd-length diagnostics and byte-rune formatting. Empty encrypted
blocks reach x509's invalid-padding path. Go notices and package metadata are
retained, and existing container license globs include the new BSD license.

This is local operator PEM compatibility; TLS negotiation is unchanged.
Source translation/hashes/edits and direct rustfmt only; no cipher execution,
tests, builds, validators, probes or fresh dependency/advisory review. Primitive
correctness, AES/DES/backend/PEM/DER/provider/driver/error/resource/FIPS/callback/
cancellation and all feature/package/container/native/client/process/import/
restart qualification remain open. Historical reports predate this batch;
none of the three release gates closes.

### State user create, rename and deletion authority — 2026-10-18

Upstream user RPCs now select the state write path. Go's state create/rename
does not invoke the legacy name validator or forbid OIDC rename. Native writes
preserve original create clocks and apply nonzero struct-update columns with
fractional UpdatedAt. Empty rename is omitted in SQL; the RPC refreshes policy,
dispatches and then performs its by-name lookup, including zero-name/all-user
semantics. A lookup error after that point does not undo the write. UserRegistry
implements the corresponding state path; custom adapters keep provided defaults.

Native deletion checks durable node ownership in DestroyUser's transaction,
without the earlier live-node rejection. Its initial user read loads the model,
then typed node/AuthKey/AuthKey.User/User preloads complete before deciding
whether the user owns nodes. Typed key/User preloads precede key destruction.
Missing users stay nil; non-nil zero FK pointers are included. The final loaded
zero-primary-key guard follows key cleanup and rolls back the transaction;
successful final zero-row deletes remain accepted. Node.DeletedAt stays an
ordinary timestamp, so those rows still participate in ownership checks.
Nested key deletion keeps native driver errors and its Go operation context;
Postgres UpdatedAt binds retain microseconds without server rounding of nanos.

ListUsers now filters in native SQL and returns all matching stored models,
including users sharing a name. It preserves stored empty names instead of
substituting a fallback in the adapter; User.Proto's display-name fallback is
still applied at response projection. Name/email/nonzero-ID priority and
final response sorting follow the RPC. The in-memory/default adapter filters
its user snapshot; native drivers return their Go-facing diagnostics.
Legacy interfaces remain separate; cached Node.User profiles retain Go's
existing update boundary. The admin text trust boundary is documented in
HARDENING.md.

Source reads/edits/hashes/direct rustfmt only; no tests, builds, validators,
probes, dependency/advisory or sibling runtime checks. Earlier name/OIDC/status/
gateway/list/delete assertions are unrecaptured and unexecuted. Full Go scalar/
time/wide scan behavior, malformed imports, memory/custom behavior, DB/driver/trigger/
transaction/clock/error/resource/race and native/wire-only/package/container/
client/process/import/restart qualification remain open. No release gate closes.

### Logout expiry and guarded deletion phases — 2026-10-18

Logout now applies expiry/online state once, before saving, and retains that
view and online transition for the later policy refresh/notification. Native
SQLite/Postgres save callbacks no longer repeat the live edit. Database failure
keeps the quiet edit; policy failure is propagated instead of being logged by a
bool setter followed by success. The response retains the accepted view and
diagnostics use the pinned logout/expiry/deletion operation context. Tagged
persistent logout remains unchanged, and admin tag assignment still retains an
existing expiry as upstream does.

Native admin, guarded ephemeral logout and guarded GC now share SQL/cache
deletion under the save mutex. Writer completion carries the actual removed
node's addresses; their allocator release runs after unlocking that mutex and
before policy refresh/dispatch. Direct and batched writers use this same phase
boundary, with release on failed batch-completion delivery. Policy dispatch
runs after release,
and committed removal is still published before a late policy error returns.
Volatile/default/custom/headless callback boundaries remain separate.

Source reads/edits/hashes/direct rustfmt only; no tests, builds, validators,
probes or fresh dependency/advisory checks ran. The callback contract clarifies
that expiry logout has already applied its quiet cache edit. All accumulated
backend/feature/client/process/import/restart and failure/clock/cancellation/
resource/phase/race qualification remains open, including the three gates.

### State session ownership and disconnect persistence — 2026-10-18

The registry now keeps attached map channels separate from state sessions,
which remain counted during reconnect grace. Acquire/online/epoch/flag selection
runs in the NodeStore writer and a missing node acquires nothing. Every guard
releases its own session, including an older epoch after reconnect. Replacement
channels, expired keys and missing nodes skip grace. The last state release
updates LastSeen/offline state even when the key was already expired; another
state session keeps the node online. Expiry restoration and GC use state-session
counts. Batcher cleanup retains the registered node's epoch and online facts.

Attached SQLite/Postgres disconnect persistence now re-reads the stable node ID
under the save mutex and writes current selected columns without Expiry. Its
owned completion attempts that save before offline dispatch and ephemeral
scheduling, including the failure path. Store binding is independent of GC
timers; detached/custom compatibility boundaries remain separate. The legacy
GC sweep reads session/online state within its writer operation.

This supersedes the earlier batcher-count/generation-based grace implementation
and timestamp-only native disconnect save claims. Existing fixtures/assertions
were source-adjusted only. No tests, builds, validators, probes or fresh
dependency/advisory checks ran. No source-only edit qualifies cancellation,
runtime shutdown, grace/clock/race/failure/GC behavior or cross-feature, backend,
stock-client, process and restart parity. All three gates remain open.

### Role-gated lifecycle and expiry refresh — 2026-10-18

Source now follows v0.29.5's distinction between ordinary nodes and subnet,
relay or via targets. Ordinary online/offline events carry patches; only active
approved non-exit routers and policy-compiled relay/via targets add runtime peer
recomputation. The old unconditional PolicyChange and subnet full-config update
paths were replaced. Policy roles are retained with compiled inputs, including
via-source eligibility. No online/offline origin is invented, and role-driven
policy updates also reach the originating stream. Each overlapping Connect
emits its lightweight update; expired control streams remain offline.

Scheduled expiry now revalidates stable-ID candidates in one writer batch,
clears their online flags together and sends NodeAdded, adding recomputation for
formerly online targets/routers. Quiet native and volatile admin expiry changes
also recompute online state before saving, retaining Go's live state on a later
DB failure and restoring online status when an active client's expiry is
extended. Stale restored/deleted candidates, Go zero expiry and strict expiry
comparisons are handled in source.

Existing assertions for the older full-map, overlapping-session and exact-time
assumptions were source-adjusted, not executed. No tests, builds, validators,
probes, fresh dependency/advisory checks or runtime resource measurements ran.
Sources/hashes/licenses are recorded in headscale-api/UPSTREAM.md. Cross-feature,
stock-client/process/restart, role/compiler parity, concurrent grace/session/
mutation/failure/shutdown and accumulated release qualification remain open.
This supersedes the corresponding lifecycle source claims, and closes no gate.

### Shared fresh SQLite/Postgres registration — 2026-10-18

Fresh built-in registration now uses the native insertion path with or without
an attached wire registry. This covers web/CLI/OIDC and atomic auth-key saves.
The detached path no longer uses legacy SQL name reservation or fresh-create
nil encoding. It saves the original sanitized GivenName seed, retains native
nil tags/endpoints/routes and captured association results, and projects the
accepted model through the same helper. Empty returned names fall back to node;
the seed stored in SQL remains empty, matching Go's database-before-NodeStore
ordering. Atomic creation keeps save and strict key-use claim together.

Detached SQL selection/preload and absent process name-collision authority
remain separate boundaries. Public shapes already flattened before this helper,
custom/legacy adapters and all accumulated runtime/feature/backend/restart
qualification remain open. Source edits/reads/direct rustfmt only; no tests,
builds, validators, probes or fresh advisory/dependency checks ran. No gate closes.

### Pinned Unicode width and provider discovery decoding — 2026-10-18

CLI table measurement now ports the v0.29.5-selected go-runewidth v0.0.24 and
uax29 v2.7.0 source: pinned Unicode 17 grapheme/width tables, first-positive-rune
cluster width, Indic/emoji/RI rules and POSIX locale overrides. This supersedes
the generic Rust width source gap recorded in the preceding batch. A source
generator emits scalar intervals from hash-pinned Go data; the direct generic
unicode-width dependency was removed without changing any dependency version.
MIT licenses and source hashes accompany the port. Non-POSIX console discovery,
invalid-byte interfaces, terminal behavior and runtime parity remain unqualified.

OIDC discovery now assigns metadata fields in Go document order, with folded
names, duplicate/null semantics and reused string-slice slots. Root/field type
errors name providerJSON; shared Go JSON scanner logic supplies syntax/depth/EOF
diagnostics. MIME parameters must parse successfully before choosing the
JSON-specific Content-Type error. Quoting, exactly-empty issuer disablement,
fallback warning/context, serve initialization context and single-terminal-slash
callback construction follow pinned source. The metadata DTO remains compatible
and the implementation stays inside existing feature boundaries. CoreOS Apache
NOTICE/license and Go BSD attribution/source hashes are retained.

The existing 1 MiB provider-body limit remains a resource difference from Go's
unbounded discovery read. Network/URL/TLS/IO/raw-status errors and complete
startup/provider/CLI combinations still need qualification. Only source reads,
source generation, hashes, edits and direct rustfmt ran. No tests, builds,
validators, probes or fresh dependency/advisory checks ran. All three replacement
gates remain open; no historical report qualifies this accumulated source batch.

### CLI duration diagnostics and escaped table cells — 2026-10-18

CLI Go-duration diagnostics now use time.quote semantics, including byte-wise
hex escapes for non-ASCII/control input and the upstream DEL behavior. Prometheus
key-expiration diagnostics use strconv.Quote semantics instead. This replaces
Rust Debug quoting in invalid/missing/unknown-unit errors without changing the
two duration grammars or the separate legacy duration interface.

Upstream CLI table width now measures OSC 8 hyperlink text and applies pinned
pterm/gookit color removal before padding, including multiline headers/cells.
The color remover retains its literal `[0m` reset-suffix precondition and ASCII
color-code grammar. Rendering still writes the original text bytes. This is
width compatibility, not terminal-control sanitization; display strings can
still carry escape sequences, as in the upstream renderer. General Go runewidth
Unicode/grapheme/locale behavior was a separate source gap at this point; the
newer pinned-width implementation above supersedes that gap, without runtime
qualification.

The CLI now declares its already-used shared ACL crate directly (logging already
referenced go_strconv). It also directly reuses locked regex 1.12.2 for fixed,
linear-time escape patterns. No dependency version changed. Source-derived MIT
pterm/gookit notices/licenses are retained and CLI package metadata includes MIT.

Only source reads/hashes and direct rustfmt ran. No tests, builds, validators,
probes or fresh advisory/dependency checks ran; declaring the missing dependency
is not a compilation result. Remaining startup/provider/config/transport errors,
TTY/color/Unicode/locale/invalid-byte/IO behavior and full CLI/process snapshots
remain unqualified. The broader native/wire-only/package/container/client/
process/import/restart gaps and all three replacement-parity gates remain open.

### Shared cached registration saves and native user preloads — 2026-10-18

The built-in headless SQLite/Postgres cached registration paths now use the
same typed mutation builder and selected-column persistence as attached native
registration. Web/CLI/OIDC reauth preserves a retained non-null AuthKeyID, writes
NULL when the flow clears it, and auth-key reauth explicitly sets the presented
key ID. Expiry is intentionally included. CreatedAt/DeletedAt stay outside the
write mask. Existing GivenName, IPs and approved routes are retained; auth-key
reauth preserves its original endpoints/disco values, while web reauth uses the
request's disco value and retains endpoints when none were supplied. Nil tags,
Hostinfo and address shape pass through the existing native snapshot builder.

Headless atomic cached completion now uses the selected save followed by the
captured key's strict claim in one transaction. The returned typed record is
retained through response publication, without SQL name reservation, affected-row
rejection, row recreation or a post-save SQL node reread. A missing SQL row is
a valid no-op save, following the captured-view contract. The old full-update
function is no longer used by built-in API registration for existing nodes.

Headless auth planning no longer auto-approves routes during registration or
performs extra duplicate-address queries. Fresh registrations start without
approved routes; existing approvals remain. This matches Go's registration
flow: route auto-approval belongs to map processing or policy replacement.
Native SQL node User and AuthKey.User projections now read from their own pool,
independently of an optional UserAdmin. Missing users are known nil associations;
raw foreign keys remain distinct. Native registration planning without an
already supplied state snapshot now captures its raw User model from the same
pool instead of silently omitting association material when UserAdmin is absent.

These changes supersede the missing built-in headless cached-mask and early
route-approval source findings. Headless selection and preload still use SQL
rather than a retained process NodeStore. Legacy low-level DB update/commit
interfaces retain compatibility behavior, and headless fresh naming/nil shapes,
custom selectors/adapters, non-atomic/cancellation/shutdown/failure/resource/
clock/error/trigger/rounding/race behavior, malformed/nil/wide imports and policy
phase/resource equality remain incomplete or unqualified. Direct source reads
and rustfmt only; no tests, builds, validators, probes or fresh dependency/
advisory checks ran. All native/wire-only/package/container/client/process/
import/restart qualification and all three release gates remain open.

### State user lookup boundary correction — 2026-10-18

Direct inspection of State.HandleNodeFromAuthPath corrects the earlier
original-CLI/OIDC-user snapshot claim below. Go first finds the pending auth
entry, then loads User by numeric ID, then acquires the per-machine lock. The
initial CLI GetUserByName and the OIDC callback/confirmation profile select that
ID; their user models are not the later registration-save authority.

The native CLI path now performs both reads in that order. SQLite/Postgres OIDC
completion now loads the state user by ID from its own database after retaining
the pending entry and before lock waits. The state-level snapshot supplies
registration identity and fresh association-write material. Thus account/profile
changes committed before that read appear in registration, and a user deleted
before confirmation/state lookup fails with the contextual finding-user error.
After that read, fresh saves retain their captured-model association behavior.
Auth-key registration continues to retain its verified key/User preload.

The unnecessary raw OIDC user/confirmation wrapper types and forwarding methods
added by the earlier batch are removed. Confirmation retains the existing
callback profile DTO and CSRF state; OIDC persistence still preserves Go's
claim-return model versus struct-Updates SQL distinction. Native registration
lookup errors use Go-facing driver text and CLI looking-up/finding-user context.
Accepted pending completions now own the state user read and registration/key
lock waits through publication after request cancellation. Public pre-existing
user, confirmation and wire/policy field shapes remain unchanged; no wire-only
DB edge is introduced.

Source review also confirms that registration intentionally includes Expiry in
nodeUpdateColumns. Headless AuthKeyID selection, name/route and full cached-update
behavior still require source work; removing expiry from registration saves
would be incorrect. Native selected-column registration behavior is unchanged.

Source/direct rustfmt only. No tests, builds, validators, probes, dependency or
advisory refresh ran. Cancellation/shutdown/race/clock/resource/error ordering,
headless/custom/non-atomic boundaries, malformed/nil/wide imports, policy phases/
resources and all native/wire-only/package/container/client/process/import/
restart qualification remain incomplete or unqualified. All three release gates
remain open; this correction supersedes the earlier snapshot-authority wording.

### Raw hash columns and Go bcrypt inputs — 2026-10-18

Preauth and API-key hash columns now load without SQL UTF-8 conversion on both
SQLite and Postgres. Native registration, connection-based preauth getters and
all API-key bearer validators retain a separate nullable raw-byte hash projection
through verification. This also permits legacy plaintext preauth rows whose
unused Hash contains arbitrary bytes. Existing public String hash fields remain
representable convenience projections; their lossy text is not authentication
or captured-association authority. Captured raw hashes remain transient and
neither new raw credential wrapper implements Debug/Serialize.

The bounded credential worker now uses a source adaptation of pinned Go bcrypt
input behavior around the existing Rust bcrypt/Blowfish backend. This includes
minimum hash length and error order, accepted version/minor forms, two-byte cost
parsing/diagnostics, unchecked historical separators, CR/LF-tolerant non-strict
salt decoding and byte offsets, and Go's fixed-buffer hash/suffix comparison.
Ordinary 16-byte salts use bcrypt's raw primitive; shorter accepted decoded
salts use the same locked Blowfish bcrypt key-schedule primitives. Comparison
uses subtle constant-time equality. Generation rejects passwords over 72 bytes,
uses default cost 10 below the minimum and emits Go's `$2a$` version. No bcrypt,
Blowfish or subtle version changed: headscale-db adds direct edges to already
locked blowfish 0.9.1 and subtle 2.6.1, with the existing bcrypt feature enabled.
Go/Rust notices and licenses are retained.

This changes credential parsing and generated hash representation. It has only
source-derived implementation, not executable cryptographic/authentication or
replacement qualification. The existing worker budget and cancellation-held
permit remain; Go-accepted high stored costs still request expensive work, so
this does not establish resource/DoS equality or a new cost cap. Public UTF-8
plaintext/prefix/key interfaces, malformed ordinary strings/scalars, wider SQL
coercions and byte-for-byte public row convenience projections remain separate
boundaries, as do headless update masks/SQL authority, policy phases/resources,
wide times/IDs, exact errors/resources/failures/races/cancellation/shutdown and
all native/wire-only/package/container/client/process/import/restart gates.
No tests, builds, validators, probes or fresh advisory/dependency checks ran.
All three release gates remain open; historical results predate this batch.

### Headless and candidate-only captured saves — 2026-10-18

The built-in headless SQLite/Postgres registration adapters now run captured
belongs-to saves in the same transaction as fresh node insertion. A shared
association writer rebinds returned user/key IDs for both native and compatibility
node shapes. Headless CLI/OIDC completion passes its original User write model;
headless atomic auth-key completion passes its original verified key/User model,
saves the node, then claims `used = false`. Selected existing-node saves still
skip association inserts. Returned user/key response projections use the retained
sanitized association models instead of another association lookup.

Candidate-only API and database registration entry points now capture one
verified key/User snapshot before planning/writing. They validate that snapshot
and carry it through the save/claim transaction, replacing the previous second
credential read and current-hash/flag comparison under the write transaction.
Fresh candidate-only nodes also execute the captured association inserts.
Serving requests with an already validated lookup continue to use that original
lookup without write-time revalidation. Accepted-operation deletion/revocation
semantics therefore follow the same captured-model boundary as native saves.
The strict SQL `used = false` claim remains; NULL Used does not match false.

Nullable Reusable/Ephemeral key columns now load as ordinary Go bool zero values
(false), including direct ephemeral lookups. Node row projections preserve NULL
CreatedAt as Go's year-one zero, retain representable pre-epoch timestamps and
recognize zero node expiry as non-expiring. Non-optional MachineRecord LastSeen
still needs a representable sentinel in headless projections; native metadata
retains the separate nil state.

These changes supersede the prior missing headless association-save and
candidate-only credential-reread source findings for the built-in adapters.
Headless SQL-selected node/concurrency/name resolution and its legacy full
cached-update mask still differ from attached NodeStore authority. Low-level
metadata-only/custom/non-atomic adapters cannot reconstruct an earlier missing
snapshot. Imported malformed binary/text/scalar and Go-wide date/ID shapes,
policy phase/resource equality, exact SQL/driver/trigger/rounding/failure/race/
cancellation/shutdown behavior and all native/wire-only/package/container/client/
process/import/restart qualification remain incomplete or unqualified. Direct
source reads/hashes and rustfmt only: no tests, builds, validators, probes or
fresh dependency/advisory checks ran. All three release gates remain open.

### Captured fresh-save associations and OIDC users — 2026-10-18

Fresh attached SQLite/Postgres registration now saves the originally captured
User/AuthKey belongs-to models with `ON CONFLICT DO NOTHING` before inserting
the node, following unrestricted Gorm Save. Selected cached-node updates still
skip association writes. Credential lookup retains exact user update/deletion
timestamps, nullable raw hash bytes and nil-tag state before bcrypt. This
material is transient, is not Debug/Serialize, and is excluded from NodeStore;
only sanitized loaded associations reach the cache. Returned association IDs
are rebound into the node/key models. User zero CreatedAt/UpdatedAt and nil key
CreatedAt receive the Gorm auto clocks, including when an insert conflicts;
non-nil zero key CreatedAt stays zero. Native key mint saves its captured user
in the same transaction and stores the ordinary Go string Key as `''`.

The original source batch's CLI/OIDC snapshot authority is superseded by the
State user lookup boundary correction above. CLI GetUserByName (including its
omitted empty-name selector) and the OIDC callback profile select a numeric ID.
Registration loads its own state User after finding the pending entry and before
lock waits, then carries that snapshot through save. Confirmation retains the
existing profile/CSRF DTO. Public UserRecord, OidcStoredUser, confirmation and
wire/policy field types stay unchanged. Native OIDC persistence performs
the initial provider lookup and separate create/update phases rather than an
atomic profile upsert. On updates, SQL skips zero string fields and uses a new
UpdatedAt clock, while the returned callback model retains its original
UpdatedAt and claim-assigned empty display/picture fields. New users retain
their pre-bind timestamp precision. Accepted OIDC user writes finish in owned
work after caller cancellation. SQL JSON list/Hostinfo writes now use Go's
HTML-safe JSON envelope.

Compatibility/security consequence: an accepted fresh save can attempt to
reinsert a user/key deleted after its state User read or verified auth-key
preload. Conflict/FK constraints still apply. This follows upstream captured-model semantics; deletion is not
an immediate revocation fence for an already accepted request. The code does
not retain raw credential material in permanent cache or response DTOs.

These changes supersede the missing fresh-association implementation described
in the next section. Headless/candidate-only/custom fallback paths still lack
complete native captured-save semantics. Imported malformed binary/text,
nullable scalar and Go-wide date/ID shapes, full policy phase/resource equality,
exact failure/driver/trigger/rounding behavior, concurrency/cancellation/shutdown
and all native/wire-only/package/container/client/process/import/restart
qualification remain incomplete or unqualified. Direct rustfmt and source reads
only; no tests, builds, validators, probes or dependency/advisory refresh ran.
Historical passing reports predate this batch; all three release gates remain
open. This is implementation progress, not full replacement parity evidence.

### Native mutation failures and removal dispatch — 2026-10-18

Native saves/expiry writes now retain Go's operation context and actual driver
errors. A separate DbError.headscale_go_message formatter preserves the existing
Rust Display contract while exposing SQLite result-code and pgx-style severity/
SQLSTATE envelopes on native saves and captured-key commits. Native node save/
registration entry points no longer replace unique-constraint driver errors
with a generic node-exists sentinel. Ordinary missing records, name collisions
and policy-after-save/expiry failures retain their state-phase messages.

Native RPC selectors enter rename/expiry/route state methods directly instead
of forcing an earlier DTO read, preserving validation order. SetTags format
failures use Unknown while its state failures use InvalidArgument; route state
failures use InvalidArgument, expiry/rename/deletion state failures use Unknown.
Preauth format validation keeps its InvalidArgument contract. Tag lowercase
checks use the pinned Go Unicode simple mapping. Accepted native mutation and
deletion work now owns lock waits through completion after caller disconnect.

Deletion dispatches its explicit removal even if the subsequent policy refresh
fails, then returns the contextual error. Durable deletion, cache removal and
address/session cleanup remain effective on that late error. Earlier save
failures retain the existing live/durable ordering.

Source inspection also identified required fresh-registration work: Go's
unrestricted Gorm Save runs User/AuthKey belongs-to inserts with ON CONFLICT DO
NOTHING before inserting the node. The native fresh-save implementation omits
those association writes. Existing selected-column updates skip associations
in Go. Fresh-save association material, default timestamps, conflict/trigger/FK
behavior and concurrent deletion semantics therefore remain source work; the
captured node/key claim implementation does not close that boundary.

Direct rustfmt/source reads/hashes only; no build/test/validator/probe/dependency
or advisory refresh. Driver versions/locales, connection/pool/encoding errors,
mutation races, clocks/online/policy boundaries, headless/custom behavior and
all native/wire-only/package/container/client/process/import/restart gates
remain incomplete or unqualified. All three release gates remain open.

### Retained native admin response views — 2026-10-18

MachineAdmin now offers checked get/list response views and mutation results
that carry the record, raw client hostname and loaded user/key associations
together. Attached SQLite/Postgres and Wire adapters capture these from one
retained NodeStore view. gRPC GetNode, ListNodes, SetTags, SetApprovedRoutes,
ExpireNode and RenameNode convert that view without rereading live associations
or raw hostname after async user/key conversion. Registration's guarded response
projection also uses a complete view. Custom adapters retain default fallbacks;
existing MachineAdminRecord and wire field types remain unchanged.

Attached native expiry responses retain the original writer-update view and
persist its requested expiry; rename/tag/route responses retain the fresh view
read under the save lock, matching Go's operation boundaries. Ordinary SQL
failure still retains the quiet live edit and suppresses success dispatch. Pure
volatile adapters skip SQL-shape/ID conversion and only update native nil-shape
metadata when a native baseline already exists. Native cached NULL LastSeen is
retained as an absent proto field. Headless get/list views keep each row's loaded
associations through conversion; their NULL non-pointer CreatedAt projects Go's
zero time. Headless/custom mutation fallback still rereads after the legacy
operation and is not the attached native mutation-view guarantee.

ListNodes resolves the requested current username to its numeric ID and filters
untagged nodes by that ID, so cached profile labels do not hide nodes after a
user rename. Label-only custom adapters retain their previous fallback. Expiry
and API-key deadline timestamp conversion now normalizes supported protobuf
nanoseconds like AsTime; expiry responses emit the normalized applied instant
instead of echoing unnormalized request fields.

This supersedes the attached native admin record/association envelope source
gap. Headless/custom mutation snapshots and batch preloads, policy/route/online/
clock boundaries, same-projection staged/raw writers, wide/invalid imports and
exact errors/resources/cancellation/shutdown/failure behavior remain source work
or unqualified. Direct rustfmt only: no tests, builds, validators, probes,
dependency updates or advisory refresh. All three release gates remain open;
historical passing reports do not validate this accumulated source batch.

### Retained node metadata snapshots — 2026-10-18

Map builds/rebuilds, peer deltas, raw-Hostinfo response/debug encoding, user
profiles, packet-filter/SSH/peer-map inputs, policy refresh/check/approval inputs
and registration planning now retain a private MachineSnapshot. It captures
the record map plus copy-on-write raw Hostinfo and native association tables
while excluding the NodeStore writer. Later metadata changes cannot alter that
view. The public record fields and public Arc<HashMap> snapshot API remain;
MachineRecord additionally implements PartialEq for exact staged-publication
matching. Native-only fields remain behind the admin feature.

Native tag/route edits now record explicit nil-owner/nil-route intent in the
same writer operation as the record. The quiet live edit remains when later
encoding/SQL fails. IP backfill installs refreshed records and loaded metadata
in one writer operation. SQL row conversion stages metadata rather than
replacing active pointers before publication; matching direct/queued/auth
writers install the staged values with the record. Registration scope cleanup
and node removal discard unused staged values. Standalone persistence metadata
replacement checks that the captured record, Hostinfo and association map
versions are still current, so a completed older save cannot replace newer
metadata. Runtime/policy persistence reads record/native/Hostinfo from one view.
Native gRPC conversion retains its loaded-association view across async work.

This implements the main retained-record/metadata read and common native-write
source gaps. Native admin result records still need a single view shared with
their association envelope across get/list/mutation responses; policy/route/
online/clock boundaries, same-projection staged-row races, raw/custom/headless
writers and error/cancellation/shutdown/resource/import behavior remain source
work or unqualified. The accumulated batch is unbuilt/unexecuted. Only direct
rustfmt ran; no tests, builds, validators, probes, dependency or advisory refresh.
All three release gates remain open; earlier passing reports predate the batch.

### Captured-key commit and node deletion timestamps — 2026-10-18

Native SQLite/Postgres registration now commits the originally fetched key
snapshot. It saves the cache-selected node columns or inserts the new node,
then claims a one-shot key with `id = ? AND used = false`. It does not reread,
reverify or rebind the key's current hash, flags, tags, owner or expiry during
that write. An existing registration skips consumption for a captured Used key;
a fresh node always claims a non-reusable key. SQL NULL does not match false.
The shared captured Used flag changes after a successful claim, before commit,
as Go mutates its key pointer. Failed writes retain transaction rollback and
restore the earlier live node; storage errors retain the save/use and existing/
new-node operation context. Legacy callers without a captured native lookup
retain their prior candidate-verification fallback.

Accepted auth-key requests own their work from registration-lock acquisition
through lookup, validation, planning and publication, even if the HTTP caller
disconnects. Interactive followup cancellation retains its existing behavior.

Existing native registrations now prepare their selected SQL projection inside
the serialized NodeStore writer, using its current record and loaded metadata.
They preserve concurrent map fields and evaluate captured-key retagging against
the current AuthKeyID/tags instead of overwriting same-key admin overrides from
an earlier plan. New-node publication, existing-node update and rollback move
the record, raw Hostinfo and native associations in the same writer operation.
This narrows the registration mutation gap; arbitrary multi-step snapshot reads
and other lifecycle metadata writes remain source work.

This batch corrects an earlier source-model mistake: Go's Node.DeletedAt is
`*time.Time`, **not** `gorm.DeletedAt`. Gorm does not add a node soft-delete
predicate. Native node lookup/list/ownership/name/runtime/update queries now
include timestamp-marked rows. Those rows still reserve identities and names,
block deletion of their owner, and participate in key-reference cleanup.
Key deletion clears every matching node reference and advances UpdatedAt;
user-key cleanup uses the same transactional/savepoint helper. User and Policy
embed gorm.Model and retain their own soft-delete scopes. Node deletion markers
remain stored and cached saves omit their column.

These are unbuilt and unexecuted source changes. Native snapshot reads and other lifecycle metadata writes remain source work. Headless/non-atomic/custom adapters,
concurrent credential/account/raw-SQL changes, cancellation/runtime shutdown,
nil/zero/wide/invalid imports, exact SQL/encoding/driver/resource diagnostics,
rollback/publication and all native/wire-only/package/container/client/process/
import/restart behavior still need qualification. Historical passing reports
predate this batch. No tests, builds, validators, probes, dependency updates or
advisory refresh ran; all three release gates remain open.

### Credential preload and captured lookup — 2026-10-18

SQLite/Postgres token lookup now reads the key's loaded user before bcrypt.
Missing users remain nil; user-preload/identity decoding failures map to the
same record-not-found sentinel as Go's findAuthKey query errors. Modern and
legacy lookup select the first primary ID explicitly. Pool lookups release the
SQL connection before CPU verification; connection-scoped calls retain the
caller's context. These lookups do not start a new transaction, matching the
pinned GetPreAuthKey path rather than the separate transactional list path.

A new optional lookup envelope retains existing RedeemOk metadata plus a private
native key/user snapshot. Its modern form carries no bearer secret or bcrypt
hash. Native metadata uses the loaded user's Username and ID, with no numeric
login invented for a missing association. Captured expiration/reusable/used
state supplies serving validation after existing-node selection; selection errors
are now returned before that validation. A still-valid same-node refresh skips
validation as Go does. The built-in serving path avoids a second redeemer lookup
and bcrypt check between fetch and serving validation.

An optional registration-store method passes that captured lookup to SQLite and
Postgres planning. The planner verifies the key ID and retains its user/key
associations without substituting later directory/key reads. Fresh node identity
uses the captured key user; existing auth-key re-registration retains its earlier
node user independently. Existing redeemer/store methods and public record/wire
field types are unchanged; custom and wire-only adapters have default fallbacks.
Credential read work uses owned completion.


Captured loaded key users also scope existing-node selection for tagged keys:
their matching user node takes precedence, followed by an existing tagged node;
a different sole user is not converted. Only a tagged key without a loaded user
uses the unambiguous user-node conversion fallback. Native planning uses the
captured owner directly, keeps tag-node storage ownership nil, and excludes raw
zero-owner rows from that anonymous conversion set. Label-only custom fallback
remains available. A key with neither a loaded user nor tags does not match an
existing tagged node. This additional selection implementation is unvalidated.

The newer captured-key commit batch above supersedes this section's native
write-time reread and pre-write cancellation gaps. Candidate-only/headless/
non-atomic/custom fallbacks, coherent snapshot reads and other lifecycle
metadata writes, exact SQL/encoding/resource diagnostics, invalid/zero/wide/
byte-valued imports and failure/rollback/native/wire-only/package/container/
client/process/import/restart behavior remain incomplete or unqualified. Direct rustfmt only; no builds, tests, validators, probes or advisory
refresh ran. No dependency version or wire-only DB/core edge changed. All three
release gates remain open.

### Preauth transactions and owned completion — 2026-10-18

Key creation now begins a database transaction before resolving its user and
retains that loaded row through hashing, insert and commit. SQLite uses the
pinned BEGIN IMMEDIATE default; Postgres uses its normal transaction settings
and nested savepoints for connection-scoped callers. Existing public create
methods still return Created; native methods additionally return the captured
user. Native API projection uses that row, including its raw stored name,
without a later user-directory read. Alias/UI minting also retains this snapshot
and uses strict IDs after a configured user resolver selects an account.

Native key listing reads keys and batch-preloads active referenced users on the
same connection inside Go's read transaction, then rolls it back. SQLite read
transactions also use BEGIN IMMEDIATE as pinned sqliteconfig.Default requires.
Missing users remain nil. Empty reference sets skip the user query, and duplicate
references share one batched preload. Postgres retains its normal per-statement
visibility within the transaction; this does not introduce stronger isolation.

Persistent adapter list, mint, prefix/ID expiry and deletion now use owned async
completion. The authorized CreatePreAuthKey RPC owns the initial user lookup
through response projection as well. Dropping a requesting stream detaches the
worker; it does not abort an operation already started. This can leave a committed
key when the caller receives no response, as in the pinned context-independent
Go handler. Modern plaintext is still returned once and is not retained in an
adapter cache. Expiry now uses an explicit commit boundary and captures its clock
after the transaction begins.

This supersedes the corresponding mint/list transaction and request-cancellation
source gaps. Credential lookup/preload/hash ordering, credential/account/cache
races, coherent node/side-metadata views, exact begin/savepoint/commit/rollback
errors, deadlocks/pool/bind limits, imported nil/zero/wide/invalid data, custom/
headless/direct-DB callers and runtime shutdown/process failure remain incomplete
or unqualified. Public wire/policy fields and the wire-only DB/core graph are
unchanged. Direct rustfmt only; no build, test, validator, probe, advisory refresh,
package/container/client/process/import/restart evidence ran. All three release
gates remain open.

### Direct preauth-key admin projection and expiry — 2026-10-18

The preauth admin trait now provides checked listing plus optional native
list/mint projections with loaded users and nullable timestamps. Native SQLite
and Postgres adapters implement those paths; existing custom adapters retain
default fallback methods and unchanged stable key fields. gRPC list/mint uses
the native projection directly, preserving missing/soft-deleted user
associations, nil CreatedAt/Expiration, exact legacy display values (including
legacy strings that resemble modern keys), sorted/deduplicated tags and Used.
It no longer invents a numeric-name user or re-resolves a projected account name
for those native RPCs. Headless node RPC fallback also uses native key views
and numeric user associations when available. A numeric mint path stays bound to that ID and cannot
fall back to a different account whose name is the requested decimal ID.

Storage/association/encoding failures now propagate through checked list and
native mint as ordinary RPC errors. REST/HTML list paths surface errors instead
of silently displaying an empty key list; REST storage mutation failures are
server errors. CreatePreAuthKey normalizes supported timestamp nanoseconds like
Go AsTime. Native create returns the original insert projection with its assigned
ID and pre-insert timestamp precision, including after a Postgres write; it no
longer substitutes a reread rounded/trigger-modified SQL row. The creation clock
is captured before random generation and bcrypt.

SQLite/Postgres key expiration writes retain fractional precision. Key deletion
clears all matching node references (Node.DeletedAt is a plain timestamp;
see the correction above) and propagates the
node-table clearing error; a missing Postgres nodes table is no longer silently
bypassed. In-memory ID expiry/deletion treats missing/zero IDs as no-op success,
updates the precise expiry field and leaves reusable keys' Used bit unchanged.

Auth-key and node expiry no longer share zero-time disable semantics. A non-nil
zero-time key deadline is expired; NULL alone disables key expiry. Node expiry
still disables at exact Go zero time, with fractional instants in that second
remaining real deadlines. Key comparisons use strict Before and in-memory
redemption retains the precise deadline. Two existing expectations for zero-time
key expiry and reusable Used state were source-updated without execution.

This supersedes the corresponding direct native preauth list/mint/expiry source
gaps. Full transactional user/key snapshot and cancellation ordering, raw SQL/
encoding/driver diagnostics, unsupported Go-wide timestamps/IDs/byte strings,
malformed imported scalar/null values, custom/headless/legacy behavior, database
rounding/triggers/soft-delete FK failures, cached-node races and all native/wire-
only/package/container/client/process/import/restart qualification remain
incomplete or unqualified. Public wire/policy field types and the wire-only
DB/core graph are unchanged; no dependency/advisory update. Direct rustfmt only;
no tests, builds, validators or probes ran. All three release gates remain open.

### Native cached preauth-key associations — 2026-10-18

Native node snapshots now retain the loaded preauth key and its own loaded user
separately from AuthKeyID and the node's user association. SQLite and Postgres
hydration load those snapshots with checked lookups. Dangling key IDs retain the
raw ID with a nil association and Ephemeral=false; other lookup/decoding failures
stop publication. Key tags, nullable timestamps, display key and the independent
Reusable/Ephemeral/Used flags survive normal node saves. Modern bearer secrets
and bcrypt hashes are not copied into the snapshot; legacy plaintext display
continues to follow the pinned Go behavior.

Node gRPC projection uses one captured native association bundle, so ordinary
key expiry/deletion and user renames do not substitute current database values
for a node's cached key/user. Registration replaces the key association; normal
web reauth preserves it unless ownership conversion clears it. Backfill reloads
it. One-shot Used state is shared by clones of the same loaded key and flips
after successful commit; failed auth-key completion restores prior metadata.
Fresh node/user projection shares the loaded key's user snapshot. Existing
same-user auth-key re-registration preserves the node's earlier user snapshot,
matching Go's distinct Node.User and Node.AuthKey.User pointers.

The native key display fallback is empty when both prefix and legacy key are
absent. Persistent admin key projections now retain Used independently of
Reusable. No public policy/wire field type, dependency version or wire-only
DB/core boundary changed. This supersedes the earlier missing cached
AuthKey.User source representation.

Coherent concurrent node/side-metadata snapshots, credential/account/cache/SQL
snapshot races, malformed/nil/zero/wide imported timestamp/key/user values,
legacy and custom/headless adapters, direct key-list/mint error/projection
semantics and failure/rollback/resource behavior remain incomplete or
unqualified. Direct rustfmt only; no builds, tests, validators, probes, advisory
refresh or client/process/restart qualification ran. All three release gates
remain open.

### Native loaded user associations — 2026-10-18

Native snapshots now retain the loaded user separately from the raw nodes.user_id
foreign key. A known missing association remains distinct from an adapter without
native association metadata. SQLite and Postgres hydration use checked user
lookups; a missing row retains the raw FK and no loaded identity, while lookup
errors stop publication. Native user reads retain the stored name rather than
an admin display fallback.

Registration plans capture the loaded user before live/SQL completion. Normal
native saves retain that association, auth-key rollback restores it, and IP
backfill reloads it with the full database node snapshot. OIDC publication uses
the captured association instead of replacing it with a late directory read.
An ordinary account rename does not rewrite cached node user snapshots.

Policy input equality keeps raw ownership and loaded association validity/ID
separate. Peer/filter/SSH inputs, SSH action checks, tag authorization, policy
validation and route auto-approval use the loaded association and native address
text. Known orphan rows cannot gain a policy identity merely because a matching
user ID is later created. Wire MapNode.User retains the raw FK (zero for a native
nil FK); user profiles, registration User/Login and gRPC node users use the
loaded snapshot. A native self node without an owner emits no user profiles;
profile deduplication follows self then ascending peer IDs. Unnamed loaded users
retain the pinned Username/Proto fallback behavior.

This supersedes the earlier missing source representation for independent native
user associations. Public policy/wire fields and the wire-only DB/core boundary
are unchanged. This is source implementation only: coherent concurrent node/
side-metadata snapshots, credential/account/cache races, soft-deleted/orphan/zero/
wide imported values, cached AuthKey.User, custom/headless adapters, failure and
rollback paths, and process/restart behavior remain incomplete or unqualified.
No build, test, validator, probe or advisory refresh ran. All three release gates
remain open.

### Opaque filter snapshots and JSON output — 2026-10-18

Grant App metadata now retains raw payload values alongside nil flags. Literal
app sources also retain their standardized internal whitespace for comparison.
A private opaque compilation form keeps payload JSON text separate from public
typed values through filter generation/reduction. Source payloads are used only
when they project to the supplied typed values; trusted manual doc/raw mismatches
fall back to encoding the supplied typed value. Public wire/policy field types
are unchanged.

The policy runtime retains opaque global filters and atomic per-node typed/raw
cache entries, including raw global change comparison and the same invalidation
and partial-failure phases. Each miss computes both forms from one recipient
view; concurrent misses cannot mix results from different quiet views. Immutable
raw filters use Arc ownership across frame snapshots. Filter wire types now
provide structural equality for cache/snapshot comparison. A map filter snapshot owns
both forms under one policy read lock. Full, non-stream, incremental and rebuilt map responses use
that owned snapshot, so later policy changes cannot substitute payload text in
an already-built filter. Opaque payload object order, numeric spelling and
string escapes survive serialization, subject to Go compact/HTML escaping.

The same captured snapshot drives native debug dump writes with Go-style JSON
indentation. Map framing/compression uses a shared encoded-byte path; compact
keepalive bytes retain their separate path. The raw JSON formatter follows the
pinned Go encoding/json compact/HTML/indent boundary without introducing a new
dependency release or changing the wire-only DB/core graph.

This supersedes the corresponding serving payload-serialization source gap for
currently accepted typed policy values. It does not widen the typed input stage:
Go-range/depth opaque input remains incomplete. Debug readback still has a typed
projection; direct public serializers have no retained source snapshot. Complete
raw-policy hashing/variant-field whitespace, remaining nil/scalar/error ordering,
root-field byte order, eager compilation/resource behavior, native association/
zero/zoned/wide values and native/wire-only/package/container/client/process/
restart qualification remain open. Direct rustfmt only; no build, test, validator,
probe or advisory refresh ran. All three release gates remain open.

### Policy JSON v2 decoding — 2026-10-18

Policy parsing now checks ordered raw members before Serde can discard repeated
names. The new iterative pass follows Headscale's metadata stripping, then
rejects duplicate retained object members and duplicate known-field aliases,
including opaque App payload members. Removed # metadata does not contribute
duplicates. Duplicate diagnostics carry JSON-pointer context with the pinned
JSON v2 pointer truncation behavior. The later typed/value stages still need
full error-order and resource qualification.

Policy struct names now use JSON v2's delimiter-insensitive case matching,
including ASCII schema aliases through long-s/Kelvin folds. Actual map keys
remain case/delimiter sensitive. Metadata stripping exempts only the exact
literal key app, matching the pinned source; the preceding case-folded App
metadata exemption has been corrected. App shape extraction uses the same
prepared input as the typed parser.

Supported nil policy containers now project to their existing empty typed
maps/vectors, including null policy, groups/tag-owner member lists, route-
approver lists, schema slice fields and empty/null nodeAttrs entries. Missing
nodeAttrs target defaults to an empty slice. The no-filter default separately
retains nil ACL/grant slices versus explicit [], so null uses allow-all while
explicit empty filter slices deny. Custom scalar unmarshaler rules remain
separate; protocol null is not accepted as an empty protocol.

HuJSON comment standardization retains whitespace and line breaks so comments
cannot join adjacent tokens. Trailing commas followed by comments standardize
correctly; unterminated block comments remain errors instead of disappearing.
These are source changes, with Go JSON experiment BSD notices/source hashes.
No dependency release or public field type changed; the wire-only boundary is
unchanged. The policy entry uses strict JSON v2 duplicate rejection; JSON v1
reused-slot concerns belong to the separate wire/storage decoders.

This supersedes the corresponding duplicate-name/field-fold/container/comment
gaps and earlier policy JSON v1 reuse wording. Opaque payload byte/numeric/depth
fidelity, remaining scalar/custom null cases and unknown/custom-error ordering,
full typed nil hashing, native association/zero/zoned/wide state, eager compiler
resources and paired native/wire-only/package/container/client/process/import/
restart evidence remain incomplete or unqualified. Direct rustfmt only; no
tests, builds, validators, probes or advisory refresh ran. All three gates remain open.

### Volatile refresh errors and raw App shape — 2026-10-18

Built-in volatile create/rename/tag/approved-route/advertised-route/batch and
interactive/auth-key registration paths now use checked policy refresh. A
RegistryMutationError distinguishes rejected input from a late policy failure;
HTTP/admin adapters preserve the latter as server errors. Failed refresh returns
before success dispatch or registration completion. The ephemeral sweep uses
its checked refresh path and completes address/connection cleanup before
returning a late error. Existing bool/static-error methods remain compatibility
wrappers; checked variants expose the actual error to embedders. The common
volatile finish helper no longer discards refresh errors. Legacy raw refresh
logging remains available separately.

The shared ACL leaf now accepts Go's null grant App map and null per-capability
value slices while preserving the public CapabilityMap type. A private raw-shape
snapshot records map nilness and nil capability keys. PolicyStore retains that
shape through policy/user/node refresh and global/per-node/unreduced compilation,
including unbound recipient compilation. An explicit empty App on an IP grant
produces its capability rule, while a nil App does not. Capability values retain
null versus [] on the wire. Empty App alone still fails Go's nonempty ip-or-app
validation. Self-source grants are also suppressed in the capability path.
Case-folded App fields preserve their opaque metadata payload during stripping.

Public wire/policy field types and the wire-only DB/core boundary are unchanged.
The public canonical hash still describes the typed policy projection; raw App
nilness is separate metadata for the Go adapter. This does not qualify raw
opaque JSON bytes, all duplicate/backing-array/nil policy shapes, native loaded
association/zero/zoned/wide state, exact errors/logs/hash/change counts, eager
compiler resources or raw/custom/misbound/external-writer paths. Source only,
direct rustfmt; no build/test/validator/probe/advisory or native/wire-only/package/
container/client/process/import/restart evidence ran. All three gates remain open.

### Partial alias results and refresh failures — 2026-10-18

The policy adapter now retains each alias's optional IP set and resolution errors
separately. Missing accounts/groups produce usable empty sets; ambiguous users
and invalid native addresses can produce partial sets with errors. Identity
sets retain valid addresses, strip IPv6 zones during insertion and reject zoned
membership queries. Packet-filter/SSH/tag/approver resolution keeps usable
partial sets, capability and via destinations skip errored aliases, and
nodeAttrs fails on target errors. Capability destinations preserve empty non-nil
sets. Self-grant admission now distinguishes an unresolved alias from a resolved
empty set; source autogroup:self rejects the whole grant.

SetUsers no longer prevalidates every user reference. Go performs that broad
check during policy installation, while user refresh resolves each consumer.
User refresh clears its caches before compiling; on failure it restores the
directory while retaining already installed global filters and approver maps.
SSH/direct-user tag fallback then sees the restored directory, while compiled
filter inputs retain their candidate directory. Failed policy replacement
restores and recompiles the previous document. Node refresh keeps its new node
inputs on error. Node-attribute state/diffs remain unchanged when its compile
fails. Global and per-node cache invalidation now happens before node refresh,
including affected raw owner IDs and Go's tagged-entry zero-owner behavior.

Checked refresh APIs now propagate errors through native startup, SQLite/
Postgres admin mutations and saved-row publication, registration/auth-key/OIDC
completion, auto-approval fan-out, map updates, expiry and deletion. These paths
return before success notification when a late policy refresh fails; preceding
SQL/cache changes retain their existing ownership semantics. The admin error
adapter maps policy failures to gRPC Unknown/HTTP 500. Legacy public bool/logging
wrappers remain available; remaining volatile/static-error/custom call paths
still need complete fallible propagation.

This supersedes the corresponding partial-result and selected native-failure
gaps in earlier entries. Rust currently emits base IP-builder errors rather than
Go4 stack traces. Exact typed nil/duplicate/backing-array and empty App/CapMap
representation, eager compiled-grant resources and all phase/error ordering,
native association/zero/zoned/wide values and remaining lifecycle paths remain
incomplete or unqualified. Go4 source hashes/notices accompany the adaptation.
No external dependency release or public wire field changed. Direct rustfmt
only; no tests, builds, validators, probes, advisory refresh or process evidence
ran. All three release gates remain open.

### User refresh results and eager tag owners — 2026-10-18

PolicyStore now exposes independent policy-change and peer-map-change results
for user-directory refresh. Equality sorts by ID and reads only ID, stored name,
email and provider identity. Bound refresh compares the global filter and
canonical resolved tag-owner/route/exit IP sets; a changed directory still forces
a policy event for SSH or per-node filtering. Node-attribute differences retain
their separate accumulated self-refresh drain. Native user creation always
dispatches PolicyChange; rename and OIDC updates use the reported result, and
deletion falls back to UserRemoved only when no policy event was returned.
Native updates no longer overwrite every cached node profile, matching the
pinned State.UpdateUser boundary. The current wire peer graph reads fresh
compiled matchers rather than storing a separate policy-filtered graph.

Tag owners now flatten nested references before replacement, preserving other
owners around cyclic edges, sorting and deduplicating resolved aliases, and
rejecting undefined nested tags with Go quoting. Bound queries use an eager
canonical IP-set map plus the direct-user fallback. Approver maps use the same
canonical sets, including nil versus configured-empty exit sets. New fallible
setters propagate rejection through native startup, policy RPC/load/reload and
the admin policy route. Legacy infallible setters log rejection and retain the
active source. Rejected static topology or ambiguous directory inputs leave
the active source and directory intact.

SSH localpart email-domain comparison and JSON field-name equality now share
Go 1.26.9 Unicode 15.0.0 simple folding, including its orbit table and pinned
upper/lower mappings. These helpers accept Rust UTF-8 strings; raw-byte decoding
remains a separate boundary. No external dependency release or public wire
field changed, and the wire-only API still has no DB/core dependency backedge.

These source changes supersede the user-change-result, eager-tag-map and
ASCII-only localpart gaps in earlier entries. Dynamic resolver errors, partial
runtime state and rollback ordering, eager-grant versus lazy-miss resources,
parsed nil/duplicate policy representation, exact hash/log/change counts and
native association/zero/zoned/wide values remain incomplete or unqualified.
Go deephash includes a process seed and runtime type hash, so literal digest
comparison across independent processes needs a defined qualification boundary.
All three release gates remain open. Direct rustfmt only; no tests, builds,
validators, probes, package/container checks or fresh advisory evidence ran.

### Retained policy evaluation and caches — 2026-10-18

A bound PolicyStore now retains global filters and resolver inputs and owns
per-node reduced-filter, SSH-policy and unreduced-matcher caches. Cache misses
resolve aliases from the retained inputs while reducing against the requesting
node, following the Go separation between compiled grants and live node views.
Policy-affecting node changes and changed user facts recompile and invalidate;
unchanged global-policy node sets selectively invalidate network-changed filter/
matcher entries without clearing SSH. Equivalent typed policy content retains
those caches, while successful policy publication still invalidates SSH check
auth independently. Exact Go deephashes, all typed nil distinctions and resolver
error/rollback behavior are not implemented by this cache comparison.

Bound SSH source/destination aliases now resolve through retained IP sets rather
than the current target's user/tag labels. Sources group by numeric account, with
per-account IP ordering and tagged per-tag duplication. Local-part rules use the
policy account's email instead of cached login text; equal login strings no longer
merge distinct numeric owners. Source nodes without an ownership association or
tags do not gain a Unix-user rule. Public wire fields remain unchanged.

Node attributes compile by resolving each target to an IP set and stamping every
matching stable node ID, including shared-address cases. Map/DNS projection reads
those cached IDs. Changed attribute IDs accumulate across policy/user/node
recompilations, including loss of the last attribute, and dispatch drains their
sorted union with pending DNS self-refreshes. Cached route/exit approvers and
retained tag-owner resolution now drive production checks. Single-node and batch
approval plans carry one owned approval snapshot instead of cloning the live doc
and matching against current user/tag labels.

Peer visibility now derives source/destination IP sets from filter rules,
including CapGrant destinations. Matchers implement direct-IP and approved-subnet
source identities, destination subnet overlap, exit-node internet coverage and
four-direction self/via peer checks. Peer-map builds use fresh unreduced matchers;
route authorization uses the per-ID matcher cache, excluding exit-node self-rule
augmentation. Via source/destination aliases are retained as resolved prefixes,
with the internet marker preserved, while candidate routing remains live.

A weak policy-to-registry binding now sends bound notifications through the
registry's global policy event and attribute drain. This repairs batched streams
that previously observed a watch update without a registry event when no routes
changed. Volatile route approvals complete a quiet stable-ID batch first. Native
SQLite/Postgres adapters mark that their route fan-out requires persistence, so
map watchers/notification cannot invent a second cache-only approval. User-list
refreshes do not run the policy-reload route fan-out. Legacy public Notify
observers still wake; the private watch fallback serves unbound stores. The weak
back-reference avoids adding a strong ownership cycle.

Volatile admin create/rename/tags/routes/batches and explicit durable admin-row
publication now refresh retained inputs before dispatch. Logout delegates to the
same expiry completion. Raw upsert/backfill retains its separate store-only
contract; refresh_policy_nodes exposes an explicit refresh hook for trusted
embedders. Public control routers and production adapters bind the store after
hydration. No DB/core dependency or external release was added to wire-only.

Source only, unbuilt/unexecuted; direct rustfmt only. Complete Go policy parsing/
nil/duplicate/backing-array semantics, resolved-map error and rollback ordering,
exact hash/log/change-count results, SetUsers result reporting, Unicode/localpart
edges, loaded-association and zero/zoned/wide shapes, and remaining raw/custom/
external-writer lifecycle boundaries remain incomplete or unqualified. Per-node
alias work on cache misses still uses retained Rust resolver adapters, and exact
Go eager-compilation resource behavior is unqualified. A storage error can leave
quiet live data distinct from both SQL and retained policy results, as in the
pinned ordering; no failure-injection evidence covers this batch. Cache memory,
concurrency, weak ownership/cancellation, feature/wire-only/package/container and
paired client/process/import/restart gates remain open. No tests, builds,
validators, probes or fresh advisory refresh ran. All three release gates remain
open.

### Retained policy node inputs — 2026-10-18

PolicyStore now retains a private node-input snapshot separately from the latest
quiet live registry edit. The v0.29.5 SetNodes comparison checks cardinality and
stable IDs, raw numeric owner, loaded numeric association, ordered tags and IPs,
and sorted active-route multisets retaining announcement duplicates. Announced
route changes additionally matter when the previously compiled policy has self
or via grants requiring per-node filters. Clocks, endpoints and profile-only
changes do not enter this comparison. Native nullable/zero/zoned address text
and raw ownership are retained for equality when hidden by the public projection.
Association validity still shares the narrower public representation.

The per-node category is derived using the existing source resolver and pinned
compileOneGrant/compileOneViaGrant admission rules. Unresolved source aliases do
not activate an inert self/via grant. Private raw grant-App presence distinguishes
nil from an explicit empty map. Successful policy/user replacement recompiles
that category; identical sorted user input skips the replacement. This does not
supply the complete Go compiled-grant/alias caches, resolver errors or deephashes.

Production native runtime, gRPC registry attachment and control-router creation
bind the serving PolicyStore after initial hydration. Reusing that store for
another listener does not reset its earlier inputs. Native/volatile auth
completion, successful native admin saves, substantive map saves at the pinned
Hostinfo/route refresh boundary, non-empty auto-approval batches, expiry and
single/batched deletion now advance the tracked snapshot. Failed saves leave it
unchanged, allowing a later successful refresh to detect earlier quiet edits.
Backfill keeps its pinned no-policy-refresh behavior.

Auth notification classification uses the retained comparison when bound. Quiet
rekey publication retains queued identity checks and defers notification until that
comparison completes. Empty direct/queued rekey changes no longer drain pending
self-refreshes before the owning operation dispatches its result. Map
policy events are global; native tag policy changes retain their origin, ordinary
rename/route policy changes do not invent one. Route approval still forces the
pinned global change even when SetNodes reports no input difference. Expiry
merges an explicit node-add/its origin into a preceding policy change. A startup
policy warning helper's invalid MachineRecord.tags references were corrected to
forced_tags. No public wire fields or dependency versions changed.

This is source implementation, unbuilt/unexecuted; direct rustfmt only. Full
compiled-filter/alias/SSH/CapMap snapshot authority, user-change result reporting,
policy hash/log/change-count equality, failure/error ordering, remaining volatile
admin/raw/custom refresh boundaries and native association/nil/zero/wide shapes
remain source work. Current map/SSH/capability evaluators still accept live node
snapshots; this tracker does not qualify their behavior after failed persistence.
Concurrency, ownership/resource/cancellation, feature/wire-only/package/container
and paired client/process/import/restart evidence remain absent for this batch.
No tests, builds, validators, probes or advisory refresh ran. All three release
gates remain open.

### Registration completion lifetime and change classification — 2026-10-18

Built-in auth-key, CLI and SQLite/Postgres OIDC completion workers now own a
private publication cleanup scope after acquiring their registration guards.
The scope removes only newer pending publication/Hostinfo entries for its
machine/node-key binding, before releasing those guards. Return, failure and
worker destruction discard bookkeeping without reverting committed SQL, quiet
live changes, or connection state, and without dispatching a success event.
Direct/manual adapter calls outside these workers still require ownership.

CLI, SQLite/Postgres OIDC and volatile web completion now capture the original
pending auth entry, record and Hostinfo together before waiting for machine/node
locks. They retain that entry across the owned mutation instead of re-looking up
an auth ID after the save. First verdict wins: an eviction can already have
expired the waiter while the admitted mutation still succeeds, matching the Go
completion lifetime. Conditional pointer-identity removal protects a replacement
entry under the same ID; unlike Go's unconditional Remove, it does not remove a
new request. A completion admitted before another callback finishes may proceed
after it under the machine lock; callbacks admitted after completion still fail.
Existing public cache signatures and wire field types are unchanged.

Fresh auth publication now reports one global policy change, following SetNodes
and reauthChange. Existing completion uses numeric ownership and ordered tag
slices, and compares active route multisets without dropping duplicate announced
prefixes. An active route change selects that same single global policy event.
Exact policy-manager prior-input snapshots, resolved hashes, per-node-filter
route invalidation, association validity and accumulated change counts remain
incomplete; these local comparisons do not implement that entire lifecycle.

Source only, unbuilt/unexecuted. Direct rustfmt was the only formatting action;
no tests, builds, validators, probes, dependency upgrades or advisory refresh ran.
Expiry/eviction/replacement and duplicate callbacks, failure/rollback/publication
ordering, lock/resource/cancellation behavior, zero/native/custom representations,
wire-only/native/package/container and paired client/process/restart gates remain
unqualified. The backlog remains open with two P0s and one P2.

### Fresh registration source additions — 2026-10-18

Gorm v1.31.1 JSONSerializer compatibility now has its MIT license/notice in both
API and DB packages, and their package license expressions include MIT. Existing
container wildcard copies include the notices; package/container/license tools
were not executed. No dependency version changed.

Attached native fresh-node creation now inserts the original node fields in
SQLite/Postgres before publishing the database-assigned ID. The dedicated adapter
preserves nil endpoints/tags/approvals, writes raw empty scalar text, seeds
GivenName from the sanitized raw hostname, and does not query/reserve/retry a DNS
name in SQL. Its returned initial projection retains pre-marshal Hostinfo and
original time precision instead of re-reading the row. Auth-key consumption and
node insertion share one transaction, committed before the cache publication.

The NodeStore writer resolves the initial GivenName against current live names,
including the empty-name fallback and suffix collisions. The resolved live name
can differ from the initial SQL seed, as in Go; a later cached-node save persists
it. Private native publication now distinguishes created and updated nodes,
retains the original Hostinfo/nil shape metadata, and delivers the creation event
without reapplying a SQL snapshot. Already verified wire identity/profile data is
retained when constructing the initial cached record.

Fresh registration no longer auto-approves routes. Attached and volatile auth
paths keep approvals empty initially, and reauth preserves the existing approval
vector and GivenName. The map/policy lifecycle owns subsequent approvals. The
recent existing-node helper's AuthKeyID assignment was also corrected to the
existing signed field type. Public wire field types and the wire-only dependency
boundary are unchanged; no external dependency release changed.

These changes are unbuilt/unexecuted. Direct rustfmt only; no tests, builds,
probes, advisory refresh or executable validators ran. Exact policy lifecycle
input hashes/change counts, deferred/failed publication cleanup, credential/cache
and account-clock races, duplicate-key representation, malformed/zero/wide values,
non-Hostinfo JSON/codec/transport residuals and resources/cancellation remain
incomplete or unqualified. Fresh creation's SQL/nil/name/time/failure behavior,
legacy/headless/custom contracts, wire-only/native/package/container features and
paired stock-client/process/import/restart behavior still require qualification.
All three release gates remain open.

Existing attached native registrations now select node identity/ownership,
addresses, routes and nullable field shapes from a live registry projection.
Address preparation uses the same authority, avoiding a new allocation merely
because an existing node's SQL row is missing. Node SQL rows are not re-read for
authorization or optimistic conflict checks on this path; credential rows remain
verified and locked in the combined auth-key transaction.

The NodeStore writer now applies existing-node auth quietly before SQL, preserving
GivenName, addresses, CreatedAt, approvals and stable-ID connection tracking.
Auth-key reauth preserves disco/endpoints, writes the newly presented AuthKeyID,
and uses that key's ephemeral property. Web/CLI/OIDC reauth preserves AuthKeyID
unless it clears the reference, so a deleted stale key cannot cause a new FK
check. User-to-tag conversion clears expiry. Nil tag/owner intent and raw
Hostinfo advance with the live state before the save.

Auth-key transaction failure restores the prior key binding, cached record,
Hostinfo and native shape metadata without releasing addresses or dispatching a
success event. Web/CLI/OIDC save failure retains the quiet live mutation, matching
the different Go path. The cached save writes Expiry with Go's selected node
columns, conditionally includes AuthKeyID, excludes CreatedAt/DeletedAt, accepts
zero affected rows and never inserts a missing row or reserves a name in SQL.
One-shot key consumption is still atomic; an unused key is also consumed on a
skip-validation refresh, while an already used key is not consumed twice.

Successful existing-node completion retains its prior raw peer state until the
caller publishes. Publication reads the already-updated live record, merges only
canonical account profile metadata and classifies hidden Hostinfo changes as a
whole-node add rather than a key patch. It skips SQL projection reapplication and
retains stable-ID online/session state. Deletion discards pending completion data.

This is source-only and unbuilt/unexecuted. Fresh-node creation's name/nil/approval and database-first publication now have
source implementation above; exact policy lifecycle input hashing/change counts
and deferred/failed completion cleanup remain open.
Prior/default expiry and account clocks, zero/wide/native values, credential/cache
races, delayed/failed completion cleanup, SQL/encoding/rollback failures, raw or
external writers, duplicate/missing/soft-deleted rows, route/HA/session changes,
resources/cancellation and feature/package/container/client/process/restart need
paired qualification. No test, build, probe, dependency/advisory refresh or
executable parity validator ran. All three release gates remain open.

Registration request decoding now carries the Go-typed Hostinfo companion
through auth-key persistence and immutable pending CLI/OIDC/web auth entries.
The pending record and companion are read together under the same entry and
retained by the owned completion worker after its machine/node guards. Built-in
SQLite/Postgres and wire admin hooks accept the optional companion; existing
custom backends keep their default projection contract. Auth completion uses a
non-nil empty Hostinfo for a nil request, carries only omitted NetInfo (including
its explicit-unset values), and applies fresh web tag compaction to the native
value. Route slices preserve canonical item order, duplicates and typed zeros.

Native registration stages the pre-marshal Hostinfo only after its SQL commit.
Publication consumes it by stable ID, node key and matching projection, so SQL
omitempty does not turn an in-memory empty slice into nil. Metadata remembers
and deletion discard clear pending shapes. Volatile completion installs native
shapes inside its NodeStore writer and upgrades a raw peer-field change from a
key patch to a whole-node add. Native registration's wider cache/SQL authority,
existing-node live-first update/rollback and prior raw notification classification
now have source implementation above. Fresh-node creation now has source implementation above; staging/failure
coherence remains incomplete or unqualified; no runtime correctness is claimed.

Debug dumps now write the private Hostinfo representation for Node, Peers and
PeersChanged. The operator readback decodes supported MapResponse fields and
re-emits typed Hostinfo without losing nil/explicit-unset values; it does not
return arbitrary unknown JSON from files. The legacy typed read API stays
available. File filtering follows the .json byte suffix (including .json itself
and non-UTF-8 prefixes), filename fractions trim trailing nanosecond zeros in
local time, and 0755 creation modes respect the process umask while preserving
existing file/directory modes. Full non-Hostinfo Go JSON grammar/widths/case/
duplicate/error behavior and direct public serde remain narrower or unqualified.

These are unbuilt/unexecuted source changes. Direct rustfmt only; no build,
test, probe, dependency/advisory refresh or executable parity validator ran.
The three qualification gates remain open.

Each stream now retains private typed Hostinfo with its previous peer state.
Incremental comparisons check peer-visible raw values as well as the public
MapNode. A changed nil root or AppConnector explicit-unset value forces a whole
node instead of disappearing in equality or an unrelated endpoint/key patch,
including policy-driven and fallback comparisons. Public wire types remain
unchanged. Debug Hostinfo readback and registration companions now have source
implementation above. Wider registration/cache authority, non-Hostinfo debug JSON,
direct public serde and exact lifecycle logging remain incomplete or unqualified. These changes are unbuilt and unexecuted.

Control responses now serialize private Hostinfo snapshots for self Node,
Peers and PeersChanged in initial/full/incremental frames and non-streaming JSON.
The typed marshaler preserves explicit-unset opt.Bool, applies pinned scalar/
slice omission, omits a nil Hostinfo view and emits {} for a non-nil empty view.
The public MapNode Hostinfo field accepts omission on decode without changing
its type. Ping/keepalive framing stays on the compact path. This source change
has not been built or executed. Private stream comparison and debug Hostinfo
readback now have source implementation; direct public serde remains narrower.

Map request decoding now retains a private Go-typed Hostinfo value before the
public projection. Registry snapshots preserve nil roots, nil/empty slices and
explicit-unset opt.Bool. Structural comparisons use Go zero defaults and retain
slice nilness; peer comparisons use the pinned field set and slice rules. A
present Hostinfo replaces the complete native value, carrying only omitted
NetInfo. Native selected-column saves use that live replacement even when the
public projection is unchanged; individual admin edits still merge only their
changed fields. Public wire struct fields and dependency versions are unchanged.

DNS metadata self-refreshes are retained after the live map mutation, before
persistence. Successful change dispatch drains sorted unique IDs, including an
otherwise empty successful map result. A failed save leaves them queued for the
next dispatch, matching State.DrainSelfRefreshes and Headscale.Change. This is
unbuilt and unexecuted source work; no earlier result qualifies these changes.

Attached native map persistence now re-reads the current registry node by
stable ID under the shared save mutex and writes Go's selected cached-node
columns. It no longer re-reads SQL ownership/names/routes or applies optimistic
partial runtime SQL, and it skips post-SQL cache reapplication through a default-
compatible store hook. Live nullable-shape metadata advances before SQL so a
failed save does not restore an older nil shape on a later substantive write.
Headless/custom stores retain their existing persistence/publication contracts.

All map requests now apply client fields quietly and defer peer notifications
until persistence succeeds; streaming requests also wait for Connect. Failed
saves retain live state without a successful delta. Hostinfo route slices keep
canonical item text, order, duplicates and typed zero prefixes. Automatic name
reservation moved entirely into the NodeStore writer. A stable-ID primary-route
assignment comparison detects announcement-driven advertiser changes before
persistence and defers the resulting policy event through the same success path.

Native user-owned logout now applies expiry quietly before an expiry/UpdatedAt-
only save, with a fresh ID-based read under the shared mutex and no SQL row
projection. Failure retains the live expiry; the caller notifies only after
success. Tagged and ephemeral branches retain their separate behavior. No
public wire field type or dependency version changed.

This remains unbuilt/unexecuted source work. Remaining implementation boundaries
include wider registration planning/cache authority and exact policy lifecycle behavior and deferred publication cleanup,
non-Hostinfo debug JSON/direct public serde, public
integer widths and exact policy lifecycle hash/change-count logging. Client/route/key/HA/owner changes,
missing/soft-deleted rows, save failure/retry/restart, clock/notify/connect timing,
custom hooks, cancellation/resources, feature/wire-only/package/container and
stock-client/process behavior require paired qualification. All three gates stay
open; no builds, tests, probes or executable validators ran.

Rename now shares pinned Tailscale label diagnostics and Headscale's full
FQDN byte-length check through the pure go_dnsname leaf. The 255-byte bound
includes `name.base_domain.` and its final dot. Production preparation and
control-router setup configure the registry's domain; native/wire renames reject
before mutation and map-name checks use the same FQDN rule. DB label validation
shares the label adapter. Go string/rune quoting preserves diagnostic ordering.

Attached native deletion now selects the live stable ID, holds machine guards
and the persistence mutex through SQL/cache removal, and treats an absent SQL
row as a successful DELETE. A failed SQL delete retains the cache, sessions and
IP reservations. Native ephemeral deletion also uses its authoritative cached
ID and accepts zero affected rows; legacy no-ID fallback keeps its row lookup.
A default-compatible allocator release hook is configured through weak ownership
at production preparation/router/service setup. Direct and batched registry
deletions capture the actually removed addresses, drop the writer lock, release
them, then dispatch removal; the legacy ephemeral sweep does the same. Cidr
release holds the address-pair lock, removes used addresses and leaves sequential
cursors unchanged, as Go FreeIPs does. Rekey paths do not release addresses.

No builds, tests, probes or executable validators ran. FQDN boundary/error cases,
SQL failure/absence, timed cleanup, allocator release/reuse, callback lifetime,
raw/external writers, duplicate/unusual addresses, queue/cancellation/locking,
features/wire-only/packages/containers and client/process/restart behavior need
paired qualification. Stateless/custom allocators keep the default no-op unless
they implement release; manual registry users must configure the allocator and
domain. Attached map/logout persistence now has source implementation above;
wider registration/cache authority, exact policy lifecycle behavior, deferred publication cleanup and non-Hostinfo debug JSON/direct public serde remain source work.
All three parity gates remain open.

Attached native node admin mutations now use the live registry as their
source. Tags, approvals, advertised-route edits and rename apply one quiet
stable-ID writer update, then re-read under the shared persistence mutex and
save Go's cached-node column mask. Expiry/disable-expiry use the same live-first
boundary with a separate expiry/UpdatedAt-only SQL update. Missing SQL rows are
not recreated and zero affected expiry updates succeed. Failed saves retain
the live edit without a success notification; successful saves notify after SQL.
Machine guards survive cancellation through the owned completion worker. Name
collision checks and assignment share the NodeStore writer with create/rekey.

Attached get/raw-hostname/ordinary wire and registration-policy reads now use
the registry; explicit committed-row publication remains separate. Setting tags
sorts/compacts and clears ownership, including same-vector writes; the wire
setter now does the same and names the origin node for self refresh. Explicit
empty approval writes retain Go nil intent, and native snapshots retain that
intent across SQL failures. Route health clearing uses the full active approved
set, including exit routes, rather than only primary subnet routes. The generic
noop fixture now uses the unchanged advertised-route operation, and one existing
tag-order expectation was source-adjusted; neither was executed.

These changes are unbuilt/unexecuted. Configured-domain FQDN validation,
registry-only/missing-SQL-row deletion and allocator release have since received
source implementation described above. Attached native map/logout save ordering
has since received source implementation too; wider registration/cache authority
and deferred publication cleanup and non-Hostinfo debug JSON still need source work. Headless/custom adapters retain their
own behavior. Failure/retry/restart, stale/raw/external writers, owner/route/HA
state, notification/online timing, locks/cancellation/resources, native feature
and wire-only/package/container behavior need paired qualification. All three
parity gates remain open.

Database SetPolicy now follows the pinned live-install/append/reload sequence.
A valid candidate becomes live and invalidates SSH approvals before the database
append; a later append or reload failure retains that live state without a
success notification. After an append, the service re-reads the actual latest
policy rather than reusing the request or insert result, so external appends,
read failures and route failures follow the reload boundary. Empty SetPolicy
bytes retain the current document while still appending/reloading and clearing
SSH approvals; empty CheckPolicy bytes use a valid no-policy sandbox.

Native policy writes retain fractional timestamps (SQLite nanoseconds, Postgres
microseconds) and return the inserted row directly using INSERT RETURNING,
removing a separate post-insert lookup. GetPolicy/SetPolicy carry the precise
UpdatedAt through native persistence to protobuf. A separate TimedPolicyRow and
default trait methods preserve existing PolicyRow/PersistedPolicy field shapes
and custom backends' whole-second contracts. SQL NULL UpdatedAt projects Go's
year-one zero time; wider stored datetime/driver behavior remains unqualified.
No build, test or executable validator covers these source changes. Failed-write
live state, concurrent/external policy changes, empty/malformed policies, clocks,
RETURNING/type/trigger behavior, SQLx/native features, resource/cancellation,
stock clients and process/restart behavior require paired qualification. Exact
policy-manager seeded hashes/change-count logging remain a source residual.
All three parity gates remain open.

Policy route auto-approval now computes one full plan and publishes one quiet
NodeStore batch by stable ID. Native/wire implementations lock selected machine
keys in sorted order, re-read live nodes after waiting and keep guards through
owned publication/persistence. Deleted IDs skip; duplicate live IDs fail. The
plan sees one policy document and both node address families. Native checked
listing uses the live registry when attached and propagates query errors in
headless mode. Candidate policy validation uses that checked snapshot.

Typed zero prefixes are removed from approval results; current duplicates remain
part of Go's changed-vector comparison. An order-only difference leaves live
state unchanged. Policy route persistence and create/auth/runtime vectors no
longer receive the admin API's exit-default pair expansion. The dedicated native
policy setters preserve their computed route vector and subsecond UpdatedAt.
One live batch precedes per-node SQL writes, retaining Go's partial durable
failure behavior. Attached native stores now save each freshly re-read cached
node under a registry-wide persistence mutex with Go's selected-column mask.
The mask includes keys, endpoints, Hostinfo, addresses, raw/given names, owner,
registration method, tags, LastSeen, approvals and UpdatedAt. It excludes expiry,
auth-key references, CreatedAt and DeletedAt. The SQL update never inserts an
absent row and does not treat zero affected rows as an error.

Private admin-only native baselines preserve nullable addresses, owner/method,
Hostinfo root, slices and LastSeen while their wire projections are unchanged.
Nested Hostinfo fields merge against the original typed value, retaining explicit
opt.Bool unset values when unrelated fields change. A successful snapshot save
refreshes the baseline; deletion/ephemeral GC removes absent native state.
Hydration, committed native registration/runtime/admin publication, CLI/OIDC
completion and the full backfill refresh capture native values. Ordinary
wire_record reads do not. The public wire field types and wire-only dependency
boundary are unchanged. Headless stores still use approvals-only writes because
they have no NodeStore; custom same-value updates cannot express every nil or
explicit-unset transition through the public wire model.

The shared Hostinfo writer now follows pinned scalar omission, nested pointer
retention, opt.Bool unset and mandatory Service Proto/Port emission. This is
semantic JSON emission; exact key order/float/escaping bytes are unqualified.
Native auth-path/runtime CreateParams now propagate Hostinfo encoding errors.
Non-finite floats fail before JSON null coercion; a reduced fallback object and
alias-based deletion of canonical Hostinfo fields have been removed.

PolicyStore now has a retained watch notification alongside legacy Notify.
Stream receivers subscribe before baseline processing and survive chunk yields,
so policy changes between polls remain observable. User refresh uses the same
watch signal; gRPC/HTTP policy notification follows successful auto-approval.
No test/build or executable validation covers these changes. Cached/DB field
parity, failures/restarts, cross-process/raw writers, cancellation, watch timing,
feature combinations, client behavior and broader diagnostics remain unqualified.
All three gates stay open; helper fixture changes are source edits only.

SSH check-period approvals now bind to a live policy identity, independent of
persisted updated_at seconds. Every policy publication changes that identity;
retained Arc tokens prevent reuse while old approvals exist. Rule evaluation,
cache lookup and successful follow-up stamping hold one policy read snapshot.
Native policy writes/reloads clear cached approvals. A successful configured
reload with empty file bytes or a missing/empty database policy still invalidates
SSH approvals and rechecks auto-approved routes while retaining the current
policy. Unsupported Go modes receive the nil-policy reload side effects too;
an empty configured file path remains a skipped source. Map notification follows
successful route auto-approval.

Legacy timestamp cache helpers remain callable for observation/seeding, but the
production handler requires a policy stamp. Embedders can seed against a live
PolicyStore with record_ssh_auth_for_policy. The existing positive SSH fixture
calls were migrated in source only. Same-second, unchanged-time, failed/empty
reload, concurrent approval/cache/route and restart behavior remains unqualified.

SignatureType now follows the pinned Go text conversion, including its unusual
fmt.Sscanf success/error branches, partial signed decimal assignments, Unicode
whitespace and zero omission. It is applied once because the conversion is not
idempotent. SIGHUP emits the Go signal field/message and error payload without
unconditional success/skip output. Seeded policy hash/change-count logging and
broader diagnostic equality remain open. No tests, builds or executable
validators cover these changes; all three parity gates remain open.

The maintained JSON scanner and tailcfg schema decoder now live in the pure
ACL leaf. Database adapters/re-exports preserve existing native and CLI callers.
Register/map raw bodies apply pinned schemas before projecting into existing
wire types: field folding, scalar/null defaults, repeated objects and pointer
merges, reused slice slots across duplicate Hostinfo objects, and unknown-value
scanning now share one implementation. Ordinary type errors are saved while
Go-style custom unmarshaler failures stop immediately and supersede them. The
root capability Version reached by decoding travels with an error rather than
being reconstructed by a separate, out-of-order serde pass.

Request byte slices accept base64 and uint8 arrays, including CR/LF, nonzero
unused bits and reused null slots. Timestamp parsing follows pinned Go's JSON
and RFC3339 fallback grammar, including one-digit hours, comma fractions,
nanosecond truncation and timezone bounds of 24/60, while rejecting escapes and
leap seconds. Accepted instants project to UTC through existing chrono. Hardware
attestation keys validate their 65-byte uncompressed P-256 encoding, reduced
coordinates and curve equation; only bounded public data uses BigUint. Service
Proto/Port zero fields now emit as in Go. The ACL package reuses locked base64
0.22.1 and num-bigint 0.4.6; no external version/checksum changed.

This request integration, shared extraction, crypto text check and time grammar
have not been built or executed. Public wire integer widths, nil/explicit-unset
projection, direct serde consumers, SignatureType canonicalization, exact error
and log bytes, uncommon time ranges, feature/downstream/lock/license/container
and resource/client/process/restart behavior remain incomplete or unqualified.
Go/Tailscale notices and source hashes are retained. All three parity gates stay
open; the accumulated batch remains implemented_unvalidated.

Stored machine, node and disco keys now decode through shared Tailscale text
rules. SQL NULL yields a full zero key; present empty stored text fails. Key
writes validate before mutation and canonicalize hex case. Auth-key transactions
compare fallible canonical identities, runtime optimistic writes and ownership
lookups normalize imported case/nullable zeroes, and known native node-key reads
prefer the registry's stable primary ID. Wire NLPublic accepts the tlpub alias.
Existing positive SQLite/Postgres fixtures now contain real 32-byte key text;
these source edits were not executed. Original Tailscale BSD notices are retained.

Stored Hostinfo now has schema-aware decoding over the shared Go JSON scanner.
It applies pinned tailcfg types, Go null and field-folding rules, nested/map
merges and duplicate slice backing-array reuse, including retained null slots.
Unknown subtrees are scanned without constructing recursive Value trees. Known
prefixes validate; nil Hostinfo writes bind SQL NULL. Native registration, wire
projection and route updates propagate decode/planning errors. The current
public wire model still has narrower integer fields and cannot retain every
nil Hostinfo or explicit-unset distinction; projection now fails explicitly
instead of erasing the snapshot. Wider wire request JSON remains a separate gap.

After an IP change, backfill now reloads every live database node, decodes all
records, and publishes one quiet NodeStore writer batch. Live Hostinfo merges by
stable node ID inside the writer, prefers stored NetInfo and retains independent
online state. Stale key slots for those IDs are replaced; database-absent nodes
are not pruned. This follows Go's PutNode refresh without a map/policy event and
avoids cloning the entire map once per node. Concurrent newly added nodes,
external writers, malformed/duplicate rows, SQLx/custom type behavior, numeric
and JSON edge cases, resource use, cancellation, rollback and restart remain
unqualified. No builds, tests or executable validators were run. All three
parity gates remain open and this batch remains implemented_unvalidated.

Stored IPv4/IPv6 columns now decode through typed scalar address adapters on
SQLite and Postgres. SQL NULL remains absent; present empty text remains a zero
Addr at the row boundary. Non-null network text validates and canonicalizes
through the shared Go parser without restricting family by column name.
Create, reauth and IP-only write paths validate before mutation. SQLite blobs
and text are supported; Postgres text/bytea use the appropriate SQLx codec.
The row and public wire field types remain unchanged.

Production allocator startup now plucks both raw address columns before parsing
them, including rows outside the live-node list, and parses all IPv4-column
values before IPv6-column values. ParseAddr rejects present empty text here,
unlike Addr.UnmarshalText at the row boundary. Seeding uses the actual address
family and strips zones as netipx does. Random allocation uses unbiased rejection
sampling for Go's exclusive upper bound, picks one starting point, then scans
with prefix wrap until success/exhaustion. Tiny valid pools construct and fail
when allocation is requested. The production allocator serializes single-family
and dual-family allocation with one common lock; built-in registration paths
use the new default-compatible pair method. Auth-key allocation failures use
the pinned RegisterResponse context and the Go exhaustion text.

Native SQLite/Postgres backfill now prepares NULL-based changes under sorted
machine guards, re-reads identity after waiting, then commits every IP update
in one transaction. A failed batch explicitly rolls back. Address allocation
starts only after awaitable snapshot reads; an owned worker holds the guards
through database commit and live publication. Changed-row decoding completes
before publication. Backfill preserves live Hostinfo, preferring stored NetInfo
when present, and keeps stored Hostname separate. Change messages use Go Quote,
assignment-before-removal ordering and Go error statuses; UpdatedAt retains
subsecond storage precision. The existing tiny-prefix assertion was adjusted,
not run. Headscale BSD notices and package/container source provenance were added.

This remains unbuilt source work. Malformed/null/zero/blob/zone/mapped/cross-family
address comparisons, SQLx type/feature behavior, entropy errors/distribution,
pair locking, random exhaustion and reservation behavior, backfill rollback,
cancellation/concurrency, CLI/process/restart and container/license gates need
qualification. Raw invalid-UTF-8 zones cannot be retained by the String model;
wire projection of unusual zero/zoned/cross-family addresses and the wider
Hostinfo/wire JSON boundary remain incomplete or unqualified. Typed key/Hostinfo
decoding and full post-backfill reload now have source implementation above. All three parity gates stay open.

The tag-registration source pass now separates Go's direct user/group owner
fallback from the nested-tag owner IP set. A new node without registered IP
membership cannot claim a tag merely through a nested owner reference.
Reauthentication checks the existing stored node OR the authenticating user,
using both address families and excluding tagged nodes from user owner sets.
Native SQLite/Postgres adapters expose a fallible node snapshot; selection and
snapshot failures stop approval before fresh allocation. The persistent planners
and volatile admin completion recheck the same rule before mutation.

Register requests now retain RequestTags order and duplicates through the cache.
Rejected tags retain that order; successful node tags sort/compact. Fresh web
registration also reproduces Go's shared Hostinfo RequestTags backing-array
behavior: it retains the original array length with cleared duplicate tail
slots. Reauthentication retains its original RequestTags array. Each validation
uses one policy read snapshot and reuses decisions for duplicate tags.

`tailscale_wire/web_registration.rs` extracts the authenticated volatile cache
completion path used by wire OIDC and the standalone harness. It owns machine
and node-key guards through an owned publication worker, rechecks the pending
binding, validates tags before allocating fresh addresses and completes the
cache with the captured committed record. Persistent runtimes retain their
backend completion handlers. Public wire field types remain unchanged. The
parity adapter now supplies registered-node views for tag checks, and the
existing nested-owner assertion was source-adjusted only.

These changes are unbuilt and unexecuted. Direct/nested/group/missing/ambiguous
owners, tagged/personal reauthentication, duplicate rejection and Hostinfo
round trips, policy/node snapshot timing, custom embedding contracts, resource
cost, cancellation/cache expiry, database failures, feature combinations,
process/restart and stock-client behavior still require paired qualification.
They do not close any of the three open parity gates.

Registration completion now applies `node.expiry` to untagged nodes whose
expiry is absent or Go zero time, using the configured signed nanoseconds.
Explicit epoch/past/future values and nonpositive configuration retain their
meaning. Persistent auth planners stamp LastSeen at completion; volatile
fresh web nodes also stamp CreatedAt and clear client ephemeral/preauth
metadata. Native runtime setup configures the registry before installing
CLI/OIDC handlers. Unattached custom stores retain their configuration contract.

`DebugCreateNode` now follows the pinned synthetic echo/cache split: exact
stored-name lookup, zero ID/timestamps/GivenName/IPs, route order and duplicates
in the response, but no TestOS/routes or placeholder IPs in the registration
cache. The existing Snow implementation generates X25519 public keys for both
debug identities. The two affected route assertions were edited, not executed.
Ordinary interactive registration likewise caches no allocated IPs. CLI and
SQLite/Postgres OIDC completion select existing nodes through a fallible lookup,
reuse their addresses, validate tags, then allocate for a fresh node. Native
selection/ownership/key-binding errors stop before allocation. Production OIDC
handlers receive the configured allocator, and wire-only OIDC follows the same
order. Embeddings without an allocator retain the legacy approval-time fallback;
third-party completion handlers must allocate fresh pending nodes themselves.

Stored approvals and wire route-set normalization now share Go `Prefix.Compare`
ordering in the maintained ACL leaf. `SetApprovedRoutes` parses before looking
up the node and uses the pinned outer parser/missing-node status envelopes.
Request prefix grammar and inner errors now use the pinned Go parser and
shared Go string quoting. Primary-route vectors/debug text and auto-approval
results use Prefix.Compare too. Configured prefixes and trusted proxies use
the same parser, replacing permissive length parsing and approximate errors.
IPv4/IPv6 parsing follows pinned Go source; ordinary address rendering retains
Rust Display with explicit mapped IPv6 handling. CLI logging now shares the
existing Go Unicode table/Quote through the ACL leaf. These changes add no
external release or public wire field type. Other route emission and broader
Hostinfo/JSON boundaries remain incomplete or unqualified.

These are unbuilt source changes. Default/zero expiry persistence, auth/reauth
transitions, debug fixtures, custom embeddings, partial allocation and cleanup
after later policy/database/cache errors, concurrency, resource exhaustion,
features, process/restart and stock-client behavior need qualification. No new
test, build, lint or process evidence closes any of the three parity gates.

The 2026-10-17 implementation-only pass adds the remaining identified OIDC
algorithm/claim/key-refresh behavior, bounds provider and transport startup
work, serializes same-machine auth-key registration, corrects preauth-key
refresh consumption, and bounds the optional DID replay cache. Core/runtime
OIDC configuration Debug output redacts the client secret.

Persistent auth-key registration additionally commits its node mutation and
single-use key consumption together on SQLite and Postgres. The transaction
rechecks credential liveness and the prepared node's owner/key/tag/expiry
state before writing; failed node writes roll back key consumption. Postgres
name-collision retries run under savepoints. Node admin mutations use the
same registration mutex and refresh their stable ID lookup after waiting.
Credential owner IDs now propagate directly rather than being re-resolved by
a possibly ambiguous OIDC display name. Production expiry validation keeps
fractional-second deadlines. These paths are source changes pending execution.

Map request updates now hold the same per-machine guard through persistence,
then release it before long polling or streaming. The live merge preserves
server-managed authorization/identity fields and cannot recreate a deleted or
rekeyed record. Dedicated SQLite/Postgres updates write client map fields,
conditionally retain concurrent admin names/approvals, and skip no-op or
LastSeen-only writes. Explicit endpoint clears, order-independent comparison,
STUN/shrink notification suppression, replacement Hostinfo snapshots with
NetInfo carry-over, latency-jitter suppression and targeted self/DNS refresh
follow the pinned map-request source. Key-only relogins use incremental key
patches with an explicit Go zero expiry when needed; peer-visible Hostinfo or
expiry-status changes retain whole-node updates.

Persistent wire hydration preserves raw client OS/version values. Admin node
status keeps fractional expiry precision and treats absent live presence as
offline. Atomic registration also rechecks credential owner/tag properties
and binds the proposed tags to the locked credential/node state.

Noise HTTP/2 now advertises the pinned Go defaults of 250 concurrent streams
and 1 MiB plus header accounting, bounds outstanding request tasks, releases
stream state promptly on resets and waits for receive-window capacity before
sending response data. These map/transport paths also remain unbuilt and
unexecuted.

The next source pass separates `MachineRecord.raw_hostname` (the database's
`Hostname`) from `hostname` (`GivenName`) and the latest Hostinfo snapshot.
Map updates can clear Hostinfo.Hostname without losing the stored raw node
name; registration replaces the raw name even when empty. Admin RPCs now
project Name/GivenName independently, including empty stored GivenName.
Wire-only embedders using struct literals must initialize `raw_hostname`;
the constructors and `replace_host_info` maintain it automatically.

Auth-key reauth replaces OS/version/SSH-host-key fields, preserving only
omitted NetInfo. Persistent web/CLI/OIDC auth planning retains saved endpoints
when registration provides none, preserves the prior register method on plain
reauth and publishes the committed canonical wire row. CLI approval and all
built-in OIDC completion handlers share the per-machine guard and re-read the
pending entry after waiting. Tagged completions clear owner/profile/provider
metadata. Expiry follows Go's strict-after and zero-time behavior, and tagged
future expiries keep fractional precision. These paths have no build or
executable evidence for the new snapshot.

The wire logout path now persists precise expiry or ephemeral deletion before
publishing the live change, with a dedicated SQLite/Postgres store hook under
the shared machine guard. It rechecks node identity after waiting, leaves a
non-ephemeral tagged node's expiry intact and clamps old client logout
sentinels to now. An explicit non-zero expiry on a fresh auth-key registration
is retained even when already past; configured defaults are calculated after
credential work. Whole-node map serialization omits Go zero expiry. Custom
persistence adapters can implement `persist_wire_logout`; its default retains
the previous volatile behavior. Paired logout/restart evidence for the new
implementation remains pending.

A cancellation follow-up now keeps database/live publication work owned through
completion after it starts. This covers auth-key registration, wire logout,
CLI approval, persistent OIDC completion, map persistence/session attachment
and persistent node admin expiry/disable/logout/rename/tag/route/delete writes.
The worker retains the machine guard even when the requesting handler is
cancelled; if an abandoned map result contains a connection guard, dropping
that result runs normal disconnect cleanup. This does not establish graceful
runtime shutdown or process-crash behavior.

Ephemeral GC now waits for the machine guard before claiming the matching
timer generation and rechecking node identity/session count. SQLite/Postgres
opt into guarded deletion without recursive admin locking. Custom stores keep
their existing deletion hook unless they explicitly opt into the guarded
interface. Streaming maps attach while holding the same guard, and invalid
self names fail before attachment so a failed reconnect does not cancel its
existing cleanup timer. These are source changes without cancellation,
failure-injection, reconnect or restart qualification for the new snapshot.

The diagnostic pass adds registration-specific error messages alongside the
existing redeemer error kind, preserving the original redeem/validate API.
Persistent lookup retains named parse/bcrypt errors, and missing/expired/used
keys use pinned Go wording. RegisterResponse encoding now uses the Go field
order, JSON charset header and trailing newline; future-expiry rejection and
storage failures use its Error envelope. New auth-key nodes reject RequestTags
through that envelope, while re-registration ignores client tags and retains
the key/admin tag state, following the pinned existing-node path.

Request public keys now validate prefixes/64 hexadecimal digits and normalize
case; null keys retain zero-key semantics. The new key helpers and shared zero
disco value remain available to wire-only consumers. NextDNS device_name uses
the raw database hostname, independently of GivenName. These paths remain
unbuilt, and general malformed-JSON diagnostics and other error combinations
are not established as byte-identical.

Persistent SQLite/Postgres preauth adapters no longer cache minted bearer
secrets. Mint returns a modern key once, and subsequent reads use its public
prefix plus `***`, matching Go. The optional prefix-expiry API accepts a
verified full token or one unique public display prefix; partial secret
prefixes are unsupported and ambiguous matches are rejected. Imported legacy
plaintext rows retain Go's legacy display behavior. Source fixtures were
updated for the named behavior, but none were executed for this batch.

API-key source reconciliation also corrects the non-null Go zero-time expiry:
pinned `ValidateAPIKey` rejects it as expired; only SQL NULL is unlimited.
Authentication compares the stored fractional timestamp with the current time.
API-key mint/expire writes and gRPC list projection now retain SQLite
nanoseconds or Postgres microseconds. The additive `mint_precise` adapter method
defaults to the existing method for custom stores; built-in stores preserve
the supplied fraction. `ApiKeyRow` and `ApiKeyAdminKey` carry additional timestamp
metadata; external struct-literal consumers need to initialize those fields.

API-key bearer/display parsing validates byte slices before converting to
UTF-8, avoiding a panic when a multibyte character crosses the fixed prefix
boundary. Modern bearer parsing follows pinned Go's string-cut behavior.
Both credential types share a bounded blocking-worker budget for bcrypt
(available CPUs, at most eight). The permit stays with submitted work after
request cancellation. Pooled verification releases its SQL connection before
waiting for hash capacity; explicitly connection-scoped operations retain it.
This bounds submitted bcrypt work, not total incoming requests, and has no
load or cancellation evidence for this snapshot.

Policy/admin publication now uses a shared async mutation guard in
`PolicyStore`. gRPC writes, persisted loads and SIGHUP reloads serialize their
validation, persistence, live projection, route reconciliation and notification.
Once started, their owned worker retains the guard and finishes if its request
future is dropped. Reload calls the internal loader under the existing guard.
gRPC user create/rename/delete and legacy HTML/JSON create/delete hold the same
guard through identity projection and map refresh. The deletion precheck uses
numeric owner IDs before falling back to legacy name-only records.

Legacy admin policy PUT also checks live user references and policy/SSH tests
before mutation, and its read-only validate endpoint runs the same checks.
Both surfaces share the gRPC live-node projection. Its policy update retains
completion ownership through auto-approval and notification. The legacy policy
store remains volatile by its existing contract. These changes do not serialize
custom/direct database writers or qualify runtime/process shutdown recovery;
no cancellation or concurrent-update behavior was executed for this snapshot.

Live identity matching now uses an authoritative runtime account snapshot.
Pinned Go resolves provider identifiers first, then one unique stored name or
email, and matches the resulting account ID to the node owner. The previous
live matchers often compared only the displayed login label, despite checking
the database aliases at policy load. The shared ACL engine, packet-filter and
SSH/check compilers now use the account snapshot and numeric owner across
peer visibility, route grants, tag ownership, auto-approval, node attributes
and DNS requester attributes. Provider aliases containing URL slashes are
resolved before CIDR handling. Numeric `autogroup:self` ownership distinguishes
separate accounts with equal labels.

Startup binds users even without a loaded policy, and candidates bind them
before semantic checks. gRPC and legacy user mutations refresh the snapshot
under the policy guard. An ambiguous update retains the prior policy account
snapshot and returns an error after its database write, following pinned
`SetUsers`. The production SQLite/Postgres OIDC adapters now finish user/profile
and policy publication in an owned worker before registration or SSH completion.

Runtime `PolicyDoc.users` is excluded from serialization and canonical policy
hashing. An absent snapshot retains label-only embedding behavior; an empty
snapshot is authoritative and resolves no user alias. `NodeView` has a new
optional `user_id` field, so external struct literals need to initialize it.
`PeerMapNode` retains its public shape: production uses additive methods that
accept numeric ownership maps. The known Octra sibling was inspected for these
literals, without building it. Go/Rust scenario adapters now support provider
identifiers and authoritative user matching; their changed source fixtures
remain unexecuted.

OIDC provider reconciliation now requires HTTP 200 for discovery, JWKS and
UserInfo. Discovery retains a bounded provider error body and the pinned issuer
mismatch/provider-construction framing. Missing auth/token/JWKS endpoints are
deferred until use, matching `NewProvider`; URL construction removes one
trailing slash without normalizing issuer identity. Named nullable metadata
fields retain Go zero values. Transport and general JSON decoder text, MIME
edge cases and complete startup logs remain unqualified.

Token exchange supports JSON and form/text responses, requires `access_token`,
rejects OAuth error codes even with HTTP 200, and validates JSON `expires_in`
syntax. Initial failures probe the other client-auth style; a shared runtime
cache retains a successful style for later callbacks. A missing/non-string ID
token preserves the separate `no id_token` path after a valid access-token
response. UserInfo authorization uses the returned token type with Go's
Bearer/Basic/MAC spelling. Compact `application/jwt` UserInfo is verified through
the JWKS cache using go-oidc's asymmetric algorithm set, separately from the
ID-token discovery allowlist. Its subject still must match the ID token before
merging. Null strings/group elements, Go boolean string spellings and explicit
null boolean rejection now follow the pinned claim types. These are source
changes without provider-process evidence; general JOSE serialization and
remaining diagnostic combinations are not qualified.

The next JOSE pass adds flattened and single-signature general JSON JWS to the
ID-token and signed UserInfo paths. It follows pinned protected-header
precedence, general-form key-ID selection and reconstructed signing input;
multiple signatures, unprotected nonce and unprotected critical fields are
rejected. Embedded keys are checked as public metadata and selected
certificate/key pairs must match, but signing trust always comes from provider
JWKS. EC coordinates now require exact curve width. Base64 handling also follows
Go's trailing-bit and CR/LF behavior. Ordinary compact/JSON paths share the
verification/cache flow; malformed metadata, certificate/key-set combinations
and decoder/serialization edge cases remain unqualified without execution.

The JWKS import pass now rejects a whole set when any key has malformed or
unsupported key material, following pinned go-jose. Null/missing key lists
replace the cache with an empty set. Private keys may be parsed as metadata
but cannot verify a signature. EC points, certificate/key matches, thumbprint
sizes and digests, RSA private import consistency, and Go's fixed-buffer
Ed25519 import behavior are handled by the shared header/JWKS parser.
Parsing and verification run on blocking workers behind a process-wide CPU
budget capped at eight; cancellation retains the worker's permit until its
work finishes. Cached key sets are shared through immutable `Arc` snapshots.

RSA verification now uses the existing pinned AWS-LC backend for RS256/384/512
and PS256/384/512. This covers Go's default 1024-bit minimum and automatic PSS
salt detection, which the former JWT verifier's presets did not support.
The small private FFI module owns every allocation and exposes public-key
verification only. AWS-LC's 16,384-bit maximum and the same bound on private
JWK import arithmetic are explicit resource limits: keys above that size and
Go's non-default `rsa1024min=0` override are not supported. These changes,
including the FFI ownership and worker cancellation paths, are unbuilt and
untested; malformed-key and signature acceptance equivalence remains open.

The same source pass distinguishes a missing `iat` from invalid explicit
null, checks the otherwise unused `at_hash` string type, accepts Go's null
audience-array entries and nullable distributed-claim maps/source fields,
and restricts quoted numeric dates to JSON number syntax. These decoder
branches have no execution evidence yet.

The CLI source pass replaces the gRPC key-expiration parser with the pinned
Prometheus v0.68.1 grammar: ordered integer `y/w/d/h/m/s/ms` components, zero,
signed-64-bit nanosecond range, and matching ordinary parse-error context.
API-key creation preserves nanoseconds; preauth creation carries an explicit
timestamp even for zero duration. Existing whole-second client helpers remain
available through additive precise methods. The legacy duration helper also
avoids splitting a UTF-8 code point. API-key selectors use Cobra's zero values
for empty prefixes/ID zero. Node-expiry human output compares seconds and
nanoseconds against one captured instant and treats an empty expiry as now.

Standalone gRPC commands now retain Go's operation context, status-code names
and runtime exit 1, including explicit endpoints. Direct client callers retain
their typed errors unless they opt into the CLI mode. The CLI has one absolute
deadline spanning bounded connection retries and all 29 unary RPCs, including
response-body decoding; each RPC also carries the remaining `grpc-timeout`.
Local Tonic timer errors become `DeadlineExceeded` without rewriting a
server-supplied cancellation. Structured JSON and JSON-line output use Go's
HTML and U+2028/U+2029 escaping. Existing error fixtures were updated from
source expectations, with separate node/preauth tag contexts; they were not
recaptured or executed. Connection backoff/permission diagnostics, remaining
provider/startup/decoder text and the broader CLI error matrix are unqualified.

The startup/logging source pass adds zerolog-style text events on stderr and
typed JSON events on stdout for `log.format: json`, with RFC3339 console
timestamps, Unix JSON timestamps, level abbreviations, console field sorting,
error-first fields, quoting and terminal/NO_COLOR handling. The binary owns
this formatter; library embedders retain their subscriber. Actual Noise-key
creation and SQLite/Postgres opening now emit the pinned event names, and the
Postgres log path contains host/database/user without the password. Rust span
context and other Rust-specific events remain; pinned policy-manager hash
events and all startup-log bytes are still unqualified. The earlier
invalid-log-level mismatch report is not a pass for this changed source.

Existing manual database/MagicDNS fatal logs and the ephemeral-timeout
deprecation warning now use the same text/JSON renderer. JSON records go to
stdout with Unix timestamps and proper fatal/warn levels. Fatal exit status is
retained when the configured zerolog threshold suppresses its output; early
deprecation warnings retain Go's literal machine-output-argument suppression
and pre-logConfig level boundary. Missing-config warnings keep the initial
text writer. Console output now uses last-value semantics for duplicate fields,
excludes reserved time/level fields, and places relative caller paths before
messages with Go-style coloring. Unix terminal selection follows pinned
termcolor flags, FORCE_COLOR, TERM/COLORTERM, CI and terminal-program rules,
with headscale's presence-based NO_COLOR override.

Float log fields retain their type instead of losing NaN/infinity or reformatting
through serde's generic number representation. Non-finite values use Go's
quoted spellings; finite values use fixed/scientific thresholds and normalized
signed exponents, preserving negative zero. The CLI enables `serde_json`'s
existing `raw_value` feature to retain numeric spelling without adding a
package release. These rendering, filtering and terminal branches have no
build/process evidence. Go policy hash events, invalid-format diagnostics,
pre-load fatal/caller diagnostics, Unicode printability and combined startup
error ordering remain incomplete or unqualified.

Admin commands now use a separate configuration projection matching Go's
`LoadCLIConfig` boundary. Users, nodes, auth, keys, health, debug and gRPC policy
commands read CLI connection, socket and logging settings without decoding
server-only values, checking removed server keys, applying server environment
validation or reading OIDC secret files. Direct database policy commands and
server startup retain the full loader. Logging setup also uses the projection,
so an unrelated server error cannot hide the configured log format or level.
The projection handles case-insensitive and dotted keys, empty configuration
documents and Viper-style scalar casts. Empty environment values preserve file
settings; invalid CLI booleans become false. Standalone argument parsing leaves
these environment settings to the loader, while the public library argument
parser keeps its environment support. Empty config paths use nonempty
`HEADSCALE_CONFIG` or default search paths. CLI timeout and local-socket debug
events now use the pinned messages and duration units; the timeout event keeps
the sign of an expired context. The command deadline begins before credentials
and permission checks. These source changes have no build or process evidence;
full server config cast/error ordering and exact diagnostic output remain open.

Console field quoting now uses the pinned Go `strconv.IsPrint` range and
exclusion tables instead of Rust's toolchain-dependent `escape_debug`
classification. The private generated module records its source SHA-256 and
retains Go's license; the Go 1.26.0 and 1.26.9 source tables are identical.
Printable Unicode remains literal inside quoted fields, and nonprintable
characters use Go's lowercase `\u`/`\U` escapes. No dependency or public API
was added. This closes the identified source-table gap, but quoting output and
the changed source have no new execution evidence.

The binary now owns one initial config-file snapshot. Logging setup reads its
CLI projection and full server parsing consumes the same contents, avoiding a
second file read. Missing-config warnings use the initial text writer before
command setup for remote and local commands alike; the later admin/dump paths
do not duplicate them. Initial file failures emit a fatal record with error and
actual Rust caller fields, rather than a Cobra runtime-error envelope. Version,
completion, mock OIDC and key generation use the projection when global flags
cause config loading; they do not open OIDC secret files or validate server
settings. Empty/null documents pass through to normal server validation.

Invalid log formats now emit the pinned error message and `GetLogConfig`
field on admin setup and otherwise successful server/configtest validation.
This initial text diagnostic is independent of the configured threshold and
honors root's literal machine-output suppression. Caller fields retain actual
Rust locations. Error wording from parsers, caller paths and combined startup
ordering are still not byte-for-byte qualified.

Removed-key handling now collects warnings and fatals, including nonempty
environment settings, instead of rejecting the first file key. Old ACL/DNS
keys with an available replacement are warnings; Go's DNS replacement defaults
count as set even when empty. `oidc.expiry` remains fatal with a new node expiry
present. Unsupported keys retain their remediation text. Explicit null is
unset, and presence checks accept case-insensitive/dotted paths. Warnings emit
once during full config loading before secret reads, including direct database
policy commands; fatal reports use one log record and exit 1 even when root
machine output suppresses the record. Messages retain warning/fatal groups in
declaration order; Go's sets do not guarantee multi-message order. Activated
OIDC configuration is checked before deprecations. Empty OIDC environment
values retain file values, and an empty client-secret path no longer satisfies
the secret requirement. One existing DNS deprecation expectation was updated
from source; none of these changes were built or executed. Full server casts,
typed-decoder/error precedence and broader startup equivalence remain open.

Production server configuration now has an explicit completion stage shared
by serve, configtest and direct database policy commands. Initial full parsing
does not read OIDC secret files. Completion checks DNS-source conflicts, emits
early TLS warnings and aggregate errors, reports invalid log formats, then
checks prefixes, trusted proxies, allocation and DERP configuration before
reading the secret. Domain safety follows, then database-type and MagicDNS
projection fatals. Database type no longer wins before prefix errors or secret
file failures; an absent/empty type uses Go's fatal message too. Configuration
errors receive the appropriate serve/configtest/direct-policy context. Fatal
database and allocation values use the pinned Go string-quoting helper.

The private CLI DNS decoder defers conflicting inline/file record sources to
that early fatal stage, retaining file/environment presence separately. Empty
inline arrays still count as set, null does not, and conflicting environment
record payloads are not decoded. This preserves OIDC/deprecation priority and
the full pinned remediation text. The public API DNS decoder remains strict.
Early DNS conflicts honor the initial machine-output threshold; later fatal
projections honor the configured level. One existing DNS expectation now calls
the production completion stage in source, without execution.

Policy files are no longer read by a duplicate pre-constructor validation pass;
the prepared persistent-state stage loads them after the Noise identity and
database. Configtest does not run the serving-only TLS/listener checks. Existing
legacy in-module validation helpers are retained for their unit callers but
are not the production startup path. Explicit empty allocation strategies and
whitespace in prefix/server-URL input no longer become defaults or pass via
trimming. Aggregate errors retain Go duration spelling and its missing newline
after the ephemeral-timeout error when another error follows. TLS warning
records now use the shared text/JSON writer at their early threshold.

These staging, filesystem and error paths have no new build or process
evidence. Full typed-decoder/Viper cast compatibility, malformed mixed-source
inputs, nonstandard-prefix warning banners, direct-database confirmation
timing, library constructor/listener ordering and diagnostic equivalence remain
incomplete or unqualified. Database option edge cases still need production
qualification; no broad release or Postgres gate is closed by this source pass.

Policy command input is now prepared once after initial config loading. Set
and check read their files before any gRPC connection; direct database commands
confirm before full server-config validation, secret reads or database opening.
The prepared input carries confirmation through dispatch without changing the
user's force flag or rereading the file. Path-based library helpers remain
available. Missing-file/permission/directory failures use Go's outer read
context. Direct policy aborts use `command aborted by user` and standalone
runtime exit 1. User, node and policy prompts share the pinned first-token,
case-insensitive `y`/`yes`/`sure` behavior and ignored prompt/scan I/O failures.

Nonstandard prefixes now emit the pinned banner after prefix/proxy validation
and before allocation validation, using the configured warning threshold and
text/JSON writer. The private module records the source SHA-256 and retains the
upstream license. CGNAT/ULA containment follows native address families and
prefix lengths; empty families do not trigger the banner.

Direct database set and check now use distinct validation boundaries on both
backends. Set loads users, validates structure and ambiguous user references,
warns about tests against an empty node list, and stores the policy without
rejecting those test failures. Check loads users and nodes with fallible
database reads, binds the authoritative user snapshot and owner IDs, emits
boot-style test warnings and then rejects failing ACL/SSH tests. Empty input
follows Go's no-policy parse boundary. Tagged nodes do not acquire user
ownership, and failed node queries cannot become an empty successful input.
The regular live API write boundary still enforces tests.

SQLite/Postgres persistent-state preparation now emits the same two boot
warning event names after node hydration, evaluating stored policy against the
hydrated nodes and user snapshot without blocking startup on test failures.
The shared evaluator still returns the same combined hard-check result; the
new reporting helper changes no wire fields or dependencies. All of these
command, prompt, database and warning paths are unbuilt and unexecuted. Prompt
I/O, non-UTF-8 policy input, native error strings, inner policy diagnostics,
stored-row decoder edges and process/restart behavior remain unqualified.

Production `serve` now loads/generates the Noise key before opening the
database and passes that same `Arc` into SQLite/Postgres state preparation.
Preparation validates policy and hydrates nodes once, before OIDC discovery,
embedded DERP/STUN startup, remote DERP loading and DNS-file loading. A prepared
state object owns the same registry, stores, policy, allocator and registration
cache until final wire-runtime construction. Registration-cache tuning uses
the same limits for production and internal fixtures; no placeholder DNS/DERP
snapshot is used for preparation. These ordering changes have no failure-process
or handoff evidence.

`configtest` now uses the same SQLite/Postgres state preparation, including IP
allocation setup and persisted-node hydration before OIDC discovery. It also
shares the native DERP constructor with `serve`, so configured relay-key
creation/loading and the existing Noise-key reuse guard apply there. Both paths
resolve default key paths identically; serving constructs the native relay
before starting STUN/relay listeners. Configtest does
not start control, admin, STUN or relay listeners. Constructor error combinations
and these additional filesystem/state paths have no new process evidence.

Public control query decoding now follows default Go `URL.Query().Get`
behavior: strict percent/plus decoding, discarded malformed/raw-semicolon
pairs, the first duplicate value even when empty, and a 10,000-parameter
limit. `/key` uses platform-sized signed integer parsing, the supported-client
floor, a JSON-encoder newline, and `http.Error`'s `nosniff` response header.
WebSocket Noise initiation and debug-key lookup share the query parser;
debug lookup no longer skips an empty first value to accept a later duplicate.
These paths remain source-only, including their wire-only embedding surface.

Existing-node in-memory admin mutations now share registration's per-machine
locks for expiry, disabling expiry, logout, rename, tagging, advertised/approved
routes and deletion. Multi-node route updates order and deduplicate machine
locks, then re-resolve each stable node ID/machine/creation identity after
waiting. The registry owns expiry/deletion; obsolete sidecar flags no longer
expire a future schedule immediately or hide a fresh registration. LastSeen is
retained when expired, and wire creation retains precise expiry timestamps.
Rekeys and web/auth-key completion preserve the old effective numeric ID when
the original volatile record had no explicit ID.

Native gRPC node mutations use stable numeric selectors and re-fetch their
response by numeric ID. SQLite/Postgres and in-memory selectors accept only
canonical positive decimal numeric forms; a stale all-digit hex key with
leading zeroes no longer aliases a database row. Generic MachineAdmin adapters
retain their key selector by default. The failed-key registration path still
returns its error directly; no stale-node authorization fallback was added.
The existing future-expiry assertion was changed in source, without execution.
These changes have no build, concurrent registration/admin/rekey/deletion/batch,
cancellation, process or restart evidence. Trusted direct registry writes remain
outside the adapter lock boundary; the three parity gates remain open.

Volatile auth-key and web/CLI/OIDC registration now check node-key binding in
the same NodeStore write as publication. A source rekey must still match its
machine, creation identity and numeric ID; an occupied target must be that same
node, and a fresh registration cannot overwrite an occupied key. Committed
records supply the auth response directly, replacing the post-insert expect
which could panic after concurrent deletion. General rekeys keep the record's
key field and registry index aligned. These source changes have no competing
machine, collision, delete/recreate, batch, credential-consumption or process
evidence. Legacy eager/custom redeemers do not gain a credential transaction;
database registration retains its existing atomic credential/node path.

Volatile admin creation checks key, effective numeric ID, IPv4, IPv6 and
GivenName uniqueness inside its NodeStore insertion, replacing the earlier
snapshot-check/upsert race. Its fallible DTO conversion retains numeric owner
and auth-key IDs, disco key, Hostinfo and precise timestamps; tagged creation
clears user identity. Generated registration names are resolved under the same
writer while preserving an explicit admin name during reauthentication.
Web/CLI/OIDC existing-node selection uses the supplied numeric owner ID rather
than a shared display name, with name lookup retained for legacy callers that
supply no owner ID. Canonical auth projection copies the selected owner ID and
auth-key lookup rejects duplicate same-owner matches. These creation, identity
and name-reservation changes are source-only: no build, account-collision,
concurrency, batch, process or restart result qualifies them.

SQLite/Postgres auth planning now reads every live node for a machine and
applies one ownership decision instead of first-row and cached-wire-ID
fallbacks. It selects the numeric owner, permits the relevant tagged
conversion, rejects ambiguous ownership and retains unscoped matching only
without an attached user store. Supplied owner IDs are looked up by ID, and
OIDC IDs use checked signed conversion. These are source repairs without an
account-boundary or historical-database comparison.
New different-account nodes on the same machine retain omitted NetInfo from a
prior user-owned node in both persistent and volatile web auth, as Go does;
that fallback does not transfer ownership, addresses, routes or node identity.
Multiple prior-user selection and client connectivity remain unqualified.

Built-in auth-key, CLI/OIDC completion and native admin creation now acquire
machine then node-key guards, retaining both through persistence and live
publication. The live node-key binding check rejects claims by a different
machine with the pinned error; pending auth records are re-read for both keys
after waiting. Persistent creates also own their write/publication through
caller cancellation. This addresses the source path where a foreign node key
could reach a database-backed auth upsert. The guards are local to one shared
registry: raw embedding writes, custom backends without the guard and other
processes do not gain distributed coordination or a new database constraint.
No build, collision/ownership/concurrency/cancellation, process or restart
result qualifies these changes, and all three parity gates remain open.

Native SQLx node/preauth-key tag columns now decode fallibly during FromRow,
including the ephemeral-key metadata lookup. Registration transactions and
ownership/hydration decisions also use explicit fallible tag decoding. Malformed
tag JSON cannot silently become an empty ownership list on those paths. The
decoder retains pinned Gorm's empty/null behavior and fresh string slots for
null array elements; invalid JSON and non-string elements fail. SQLite text/blob
and Postgres text bytes use Go's surrogate and UTF-8 replacement semantics;
unrepresentable source bytes are re-encoded as decoded JSON strings for the
existing String row fields. Manually constructed rows still have the legacy
convenience getter and must use try_tag_list for authorization decisions.

The iterative byte scanner is shared through headscale_db::go_json; the CLI
keeps its original service-config error adapter. headscale-db/UPSTREAM.md records
pinned Go/Gorm source hashes, BSD notices and package/container license changes.
No dependency version changed. This extraction and the row adapter have no
build, malformed-data/depth/resource, feature/license/container, transaction,
process or restart evidence. Exact diagnostic text, other stored fields and
custom database types remain incomplete or unqualified.

Stored endpoints and approved routes now use typed, fallible SQLx column
decoders and hydration accessors. Endpoint/route write paths validate before
SQL mutation. Shared Go netip text handling lives in the existing pure ACL
leaf crate: it retains zero values, IPv6 zones, mapped IPv6 text, Go numeric
port and prefix-length spelling, and prefix host bits. Database route ordering
now compares masked addresses, prefix lengths and original addresses, with
zero prefixes first; admin proto output uses `invalid Prefix` for a zero
approval. Map endpoint strings share this parser and fresh null array elements
become zero AddrPorts. Omitted/root-null marker behavior is unchanged.

The direct leaf dependency and lock edge reuse an existing workspace package;
Go source hashes, BSD package/notices and container copies are recorded in
headscale-api-acl/UPSTREAM.md. No build, malformed-data/map/zone/port/prefix,
resource, feature/license/container, client or restart comparison qualifies the
batch. A later source pass replaces delegated Rust IP parsing with the pinned
Go grammar/error order and shared Quote. Other route request/emission sites,
Hostinfo, wider wire JSON/coercion and exact errors remain incomplete or
unqualified. No parity gate was closed.

Pinned Tailscale `deephash` seeds policy diagnostic hashes with process startup
time and reflected Go type addresses. Literal hash values cannot be compared
across independent Go processes either. Future logging qualification must
normalize only those volatile values while retaining event names, field names,
change flags and rule counts; the policy lifecycle events themselves remain a
source residual. The existing report has not been changed or rerun.

Preauth-key ID checks and API-key selector checks now run after gRPC connection
setup, matching the handler boundary in Go's `grpcRunE`. Parser/required-flag
errors retain their earlier boundary. Existing runtime-error cases now use a
reachable gRPC fixture in source; they have not been executed. Local standalone
gRPC setup also probes socket write permission before dialing, with the pinned
permission-error framing. The probe creates/truncates no file and transfers no
file data. It uses nonblocking mode for malformed FIFO paths, with platform
constants from the already-locked Unix-only `libc` 0.2.186 package. Connection
attempts now follow grpc-go v1.81.1's one-second initial backoff, 1.6 multiplier,
120-second cap and subsequent +/-20% jitter. Each attempt gets at least a
20-second budget, increasing with its backoff, while the command deadline
still bounds the complete operation. The transport remains Tonic; Go resolver
state transitions, unusual path/error text and permission-process behavior
remain unqualified.

The CLI timeout now retains signed nanoseconds from config and environment
through the runtime snapshot and command context. Its parser follows Go
`time.ParseDuration` (signed/composite/fractional values and ns/us/µs/μs/ms/s/m/h),
separately from Prometheus key-expiration syntax. Pinned Viper/cast numeric
nanosecond conversion and invalid-value fallback to zero are applied; zero or
negative timeouts expire immediately. `ConnectArgs.timeout_secs` remains the
embedding override, with an added `timeout_nanos` field for precision. Existing
Rust struct literals need to initialize that additional field; the API
wire-only surface used by the known Octra sibling is unaffected.

Standalone remote gRPC now uses TLS for every accepted target, including
`--insecure`: that flag skips certificate trust/name checks while preserving
TLS handshake-signature verification and required `h2` ALPN negotiation. The
TLS configuration strips IPv6 address brackets before server-name parsing in
both secure and insecure modes. HTTP-looking target strings cannot select a
plaintext bearer-token transport. A dedicated grpc-go target parser now handles
hierarchical and opaque `dns`/`passthrough` forms, case-insensitive schemes,
query/fragment removal, hierarchical path escapes, literal opaque paths and
exactly-one-leading-slash endpoint extraction. Unknown schemes fall back to
passthrough rather than selecting an HTTP transport. Resolver host decoding
checks percent-escape, bracket and port constraints separately from paths.

Remote `unix` and `unix-abstract` targets retain TLS, use `localhost` as the
TLS/HTTP authority, preserve absolute/relative filesystem paths and decode
hierarchical path bytes without UTF-8 loss. Linux/Android abstract addresses
use Tokio's NUL-prefixed address support; other Unix platforms retain Go's
filesystem interpretation. Nonempty Unix resolver authorities fail at setup.
TCP target parsing supports DNS's implicit port 443, bare-target explicit
ports, empty-host localhost semantics, signed numeric ports and TCP service
names from a once-loaded `/etc/services` map with Go's built-in fallback names.
System service mappings override fallbacks and lookups use ASCII lowercase.
TLS and ALPN setup share the owned standalone transport for TCP and Unix
connectors, including handshake signature checks in insecure mode. Direct
library connections retain Tonic's explicit TLS configuration.

Custom DNS authorities now resolve hostname targets through a dedicated UDP/TCP
transport, with literal IPs retaining Go's direct-resolution bypass. The
implementation follows system hosts/search/ndots settings and relevant resolver
timeout/attempt/single-request/TCP/trust-ad settings. It sends parallel A/AAAA
queries by default, advertises Go's 1232-byte EDNS0 payload size, validates the
connected peer, transaction ID, question, QR/opcode and record boundaries, and
falls back to TCP for truncated UDP replies. TCP DNS frames are bounded by
their 16-bit length; name decoding permits at most ten compression pointers
and 253 presentation bytes. The pinned recursive-resolver assumption is
preserved: CNAME prefixes accompany final address records, with no additional
alias-chasing queries. Invalid/numeric-only hostnames follow Go validation.

Explicit and system DNS targets now share an owned background watcher started
at first lookup. It retries failed lookups independently of connection calls,
coalesces ResolveNow requests and enforces the 30-second success refresh floor
and resolution deadline. Last addresses survive temporary lookup errors;
permanent/no-address results remove them. SERVFAIL is classified as temporary.
System results retain full socket addresses, including IPv6 scope IDs; only
the configured port is replaced when using a resolver snapshot.
The last resolver owner aborts its watcher; no task retains the owning state.
Invalid names are checked before retry loops and immediate failures yield.

DNS pick-first now owns a subchannel and backoff clock per address. Complete
TCP/TLS/ALPN/HTTP2-preface attempts start 250 ms apart, with first-family
interleaving and immediate advance on current-address failure. DNS updates
retain matching subchannels, including in-progress attempts and backoff. A
ready winner retires all other subchannels; a still-present winner survives
later updates. First-pass failure is published only after every address has
failed; subsequent retries proceed independently while failure stays sticky
until Ready. Backoff-expired idle subchannels wait for first-pass completion.
A lost ready transport enters Idle and a one-shot picker starts a new pass
from the first address on demand. The single-target native supervisor also
uses one-shot idle demand. Round-robin children automatically exit Idle.
Each subchannel owns its own Tonic HTTP/2 transport, so the earlier duplex
preface replay/forwarding helper and shared-list retry loop were removed.
Literal IP DNS targets convert directly to socket endpoints without TXT/DNS.
IPv4-mapped IPv6 addresses use the IPv4 family for interleaving/TCP fallback.
Initial/reconnect budgets grow with backoff, with a 20-second minimum;
command/RPC deadlines bound caller waiting and the supervisor owns later IO.

Standalone remote TCP/Unix and local Unix setup now wait for the complete
initial server SETTINGS frame before returning a usable channel. A bounded
stream observer validates the initial frame type/stream ID, 16 KiB frame
limit, ACK/payload shape and defined setting-value ranges, preserving Tonic's
normal frame processing. Writes permit the client preface and initial SETTINGS
before holding subsequent traffic until the peer preface arrives, including
automatic channel reconnects. Permitted TLS bytes are flushed before waiting.
Removed/losing subchannels abort their owned tasks and I/O guards; selected
attempts retain cancellation wakers until their transport lease ends.

The standalone TLS factory caches secure/insecure configurations, uses the
existing AWS-LC verifier/signature policy and native trust roots, and requires
`h2` ALPN. Its direct `rustls-native-certs` dependency pins the existing locked
0.8.3 package; no package release was updated and the API wire-only dependency
surface is unaffected. RPC origin authority/scheme remain the original target
even though the already-encrypted I/O enters Tonic through an HTTP transport
connector. TCP connections enable nodelay.

Custom-authority DNS answers now use Go's implemented RFC6724 ordering before
gRPC family interleaving. Source addresses come from UDP connect/local-address
selection without sending datagrams. Sorting preserves Go's usable-source,
matching scope/label, precedence, smaller-scope and IPv6-prefix preferences,
with stable input order for ties and unavailable sources. The prefix comparison
stops at 64 bits and excludes IPv4/mapped destinations; policy attributes and
scope classification follow the pinned Go table. Source checks periodically
yield to the enclosing deadline. Go's omitted deprecated/home/native-transport
preferences are omitted here too.

Custom-authority resolution now selects files-only, DNS-only, files-then-DNS
or DNS-then-files through the pinned PreferGo NSS rules. It parses NSS source
criteria while following Go's forced-native treatment of actions and unknown
sources, falls back for unreadable/malformed NSS configuration, and honors
OpenBSD's `lookup` order and missing-resolv.conf files-only rule. File-first
LookupHost results retain file order, while a successful DNS-first hosts-file
fallback receives Go's RFC6724 sort. DNS-only resolution skips hosts entries;
files-only resolution never queries the configured DNS authority.

DNS TXT service configuration now looks up `_grpc_config.<host>` through the
configured authority or system nameservers. TXT character strings and records
are concatenated before Go's `grpc_config=` selection by GO language,
percentage and hostname. Environment flags retain grpc-go's true defaults
(only case-insensitive `false` disables them). Address and TXT I/O share one
30-second resolution budget. Ignored TXT timeouts retain already resolved
addresses. Initial invalid configuration prevents connection; later invalid or
missing config retains the previous valid one and parse failures trigger
resolver backoff. Pick-first address shuffling is applied before the race.

All 29 admin requests now select exact method, service default or global
settings by the wire RPC name. Service-config timeouts share the command
deadline; request/response message limits configure the codec and include
negative-limit checks. An expired deadline stops before a new RPC is polled.
Direct library clients retain their separate configuration path. Config parsing
validates method paths/duplicates, durations, retry/throttling fields and
supported balancer shapes. The direct Prost size-check dependency reuses the
locked workspace release. Go/gRPC notices, CLI package metadata and runtime
container license copies are updated; provenance is in `headscale-cli/UPSTREAM.md`.

Service-config JSON now decodes known typed fields in source order, preserving
invalid earlier duplicates as errors rather than losing them in a JSON map.
Incoming case variants, long-s/Kelvin folds, struct-pointer merges, pointer-null
resets and scalar-null retention follow the inspected Go decoder. Duplicate
array fields reuse element state, including hidden slots after shrink/regrow;
empty arrays and null reset them. Integer tokens retain Go's -0 behavior, and
custom retry durations/status codes keep their null/raw-spelling boundaries.
Canary arrays and balancer map element types decode fully before selection.
Raw configs are interpreted only at their selected/final occurrence, and the
selected original JSON bytes now identify a config instead of a reserialized
map. These changes affect which retry/limit settings are accepted; they have no
build, duplicate/null/merge/array/case/code fixture or process evidence.

The config path now scans bytes with an iterative Go-shaped JSON scanner and
10,000-container limit. Unknown/raw values do not become recursive serde trees.
Only JSON's four whitespace bytes are skipped, token/escape grammar is checked,
valid surrogate pairs combine, and lone surrogates/malformed UTF-8 bytes use
Go replacement behavior in strings and keys. TXT character strings and records
remain bytes through concatenation and selection; original config identity
retains them, including invalid bytes and UTF-8 sequences spanning record
boundaries. No dependency release changed. These scanner/byte-path changes have
no build, malformed-input, Unicode, depth, resource or process evidence. Exact
diagnostics, platform hostname bytes and parser/config/retry behavior remain
incomplete or unqualified. Policy-manager hash lifecycle logging remains a
source residual.

Configured retry policies now reach unary execution. Encoded requests at or
below Go's 256 KiB replay threshold can retry trailers-only and pre-header
failures matching the policy's status set; initial response headers commit the
call. Larger bodies are committed instead of retained for replay. A first
explicit remote REFUSED_STREAM can retry transparently without increasing the
configured attempt count. Configured attempts cap at five, use Go's 0.8-1.2
jittered exponential backoff, process abort/delay/duplicate server pushback,
reset backoff after pushback and send grpc-previous-rpc-attempts. Retries and
backoff retain the original RPC deadline and update grpc-timeout per attempt.

Applied service config resets the shared retry throttle. Matching failures and
invalid pushback decrement tokens in Go's order; successfully decoded RPCs add
tokens, and exhausted retries retain the Go CLI wrapper. Each call snapshots
its method policy and throttle. Both initial/trailing binary status-detail
headers are checked before Tonic's base64 expectation can panic. The direct
h2/http-body and promoted http-body-util edges reuse locked releases; no Cargo
resolution or dependency update was run.

Native transports now have an owned background connection supervisor. EOF,
shutdown/errors and complete GOAWAY frames remove a transport from new picks.
Pick-first reconnects on idle demand; round-robin children exit Idle
automatically. Connecting picks wait; failed picks return immediately
unless the selected method has waitForReady, which waits for a ready transport
within the same RPC deadline. Current readiness is also checked before initial
blocking dial returns. Safe repicking happens only before request dispatch.
Each underlying Channel is limited to one transport; a rejected local redial
before a new stream carries a private unprocessed marker for transparent retry.

Dispatch and response-body leases preserve old in-flight calls during GOAWAY
while new calls select the replacement. Last-owner Drop cancels registered
current/retiring transports and aborts the supervisor. Ordinary hostname TCP
dialing also now uses Go's 300ms alternate-family fallback (or immediate start
when primaries fail), serial per-family attempts, remaining-deadline slices
with a 2-second floor, first-primary-error preference and owned socket cleanup.
TLS starts after that TCP selection; DNS resolver endpoint racing retains its
separate 250ms whole-handshake behavior.

Native DNS connections now choose modern or legacy pick-first/round-robin
policy before dialing. Round-robin owns one reconnecting child per unique DNS
endpoint, rotates startup order and cycles through ready children with a random
counter seed. Aggregation prefers ready children, then connecting, then failure.
DNS updates retain matching children, retire removed endpoints for new calls and
discard stale completions using pool/child generations. Pick-first retains a
still-present ready endpoint and matching per-address workers/backoff clocks
across DNS updates. Its first pass and demand-driven Idle handling follow the
pinned source, retaining connectivity failures until Ready. Temporary DNS errors retain
the last good address state without config application or retry-throttle reset;
snapshot reads no longer request refresh. Active/pending policy pools follow
Go's graceful handoff when the candidate leaves Connecting or the old pool loses
Ready, with in-flight leases retained during removal/handoff.

Health configuration remains type-checked without health Watch traffic. Pinned
Go source requires the grpc/health parent package to register its health-client
function; the inspected cached production v0.29.5 binary contains protocol and
round-robin init symbols but no parent health-package symbols. Provenance and
the exact cached binary path are recorded in `headscale-cli/UPSTREAM.md`.
This source/binary inspection does not qualify runtime health behavior or other
Go builds with extra imports.

Complete GOAWAY/new-stream transparent retry equivalence, large-request startup failures,
transport status classification, cancellation/order and diagnostic equivalence
remain incomplete or unqualified. Full raw JSON/null/case-collision behavior,
compressed/unknown-field payload and error fidelity, default/system-resolver
platform differences, waiting Close semantics and reconnect backoff/fail-fast/
draining remain incomplete or unqualified. Background resolution, subchannels,
TXT selection, method budgets, retries, throttle, readiness/supervision, TCP
fallback, endpoint pools, policy handoff, sticky failure, health nonactivation
and binary-status guards have no lifecycle, malformed-server or process evidence.
Pick-first per-address reuse/backoff, first-pass completion, idle wakeups,
IPv4-mapped family order and endpoint/resource churn remain unqualified.
No build, fixture, network probe or process evidence was produced
for the new DNS codec/cache, ordering/NSS selection, TLS factory, preface/write
gate or connection selection/cancellation code.
Address/key whitespace is retained for Go's nonempty-value boundary. Direct
library clients retain their explicit HTTP extension. Existing SQLite/Postgres
remote CLI process fixtures now configure TLS in source; no fixture was run.

Production and offline-policy database openers now share the pinned Go pool
settings. SQLite uses one open/idle connection, a one-hour idle timeout and
no connection-age limit. Disabling the WAL configuration override retains
the pinned SQLite driver's WAL/1000 defaults; it no longer requests DELETE
journaling. Enabled overrides retain the custom checkpoint and `-1` omission
semantics, with invalid negative values rejected at database-open time.

Postgres now applies configured maximum-open, maximum-idle and idle-timeout
values, including zero retained-idle connections and disabled idle expiry.
Nonpositive open limits map to SQLx's `u32::MAX` representational ceiling,
with no eager allocation proportional to that ceiling; idle limits clamp to
the open limit. The ceiling also respects Tokio's smaller semaphore capacity
on 32-bit targets. Production pools disable SQLx's default connection-age limit.
Prepared offline policy input carries these settings through the existing
confirmation and config-loading boundaries.

The root workspace vendors and patches SQLx-core 0.8.6 to add an optional
idle cap, closing excess returned connections while retaining their pool
permits through close/cancellation. Pools without an explicit cap retain the
upstream queue. Version, original archive checksum, Git revision, licenses
and the five changed pool source files are recorded in
`vendor/sqlx-core/UPSTREAM.md`. Container recipes already copy this directory;
the parity workflow now watches changes to it. The CLI enables the opt-in
`go-pool-compat` database feature; external workspaces selecting it must carry
the root Cargo patches. Generic database embeddings and the known wire-only
API consumer do not enable that bridge.

Postgres SSL projection now shares Go's exact boolean spellings: true omits
the mode, false disables TLS and other values enter the raw keyword/value
string without trimming or case folding. This corrects the previous mapping
of true to `require`; default `prefer` can permit a plaintext fallback.
Explicit verification modes remain available.

Explicitly capped pools now reuse the most recently returned connection,
matching Go's free-connection selection. Their maintenance path removes
expired entries without rotating healthy survivors or refreshing their idle
timestamps. Uncapped SQLx pools retain upstream behavior. This code is still
unbuilt and has no concurrency, cancellation or idle-retirement evidence.

The server and offline CLI now share a keyword/value connection builder.
It constructs the raw DSN in pinned Go order and scans it using pgx v5.10.0's
ASCII whitespace, quoting, backslash, last-duplicate and empty-user rules.
The pgx MIT notice is retained in `headscale-cli/src/config/postgres.rs`.
Parsed values use URL query-pair encoding, preserving literal percent escapes,
reserved characters, Unicode and quoted whitespace instead of trimming or
reinterpreting credentials. Explicit ports reject zero, negatives and overflow;
zero configured ports omit the DSN override. TCP SSL modes use pgx's exact
case-sensitive names, while Unix socket targets ignore the mode. Empty modes
are scanned in their raw DSN position before projection. Parser errors exclude
raw connection values. Unsupported pgx keyword extensions fail explicitly;
service-file, multi-host, environment/default-user/database, startup-parameter
and native transport behavior remain incomplete or unqualified. An existing
internal URL expectation was updated in source and was not executed.

The native pool bridge now has a direct connector mode for SQLite and
Postgres: acquisition uses the caller's deadline, and refused/transient
connector errors return directly instead of SQLx's 30-second acquisition
budget and retry loop. Postgres also projects nonempty `PGCONNECT_TIMEOUT`
through signed Go seconds/nanosecond multiplication into an individual
connector deadline; invalid/negative values fail without printing their
contents. With no caller or connector deadline, waiting can be indefinite,
as in Go. Generic SQLx defaults remain in effect unless direct mode is enabled.

Postgres callbacks now drain pending protocol work and queued rollbacks on
return and before reuse, and reject connections with managed transaction
depth or a non-idle wire transaction status. The companion vendored
SQLx-postgres 0.8.6 patch exposes that latest ReadyForQuery status through one
additive method; its original archive checksum, Git revision, licenses and
changed source file are in `vendor/sqlx-postgres/UPSTREAM.md`. The parity
workflow watches this patch too. The callback issues pgx's simple `-- ping`
on first reuse or when more than one second has elapsed since the previous
reuse began, including checked-out time. An optional core release-ping flag
avoids an additional SQLx Sync ping after the drain/validation callback.
Healthy uncapped/default pools retain SQLx's original ping behavior.

Fresh-primary creation and both legacy auxiliary-copy/primary-rebuild SQLite
transactions now use `BEGIN IMMEDIATE`, matching pinned sqliteconfig's
transaction lock setting. Existing production mutation transactions already
use it. These schema and upgrade changes have no fresh process evidence.

The native database feature isolates the patched APIs; generic SQLite and
legacy Postgres factories use standard SQLx APIs without selecting it. Calling
the new Go pool factories without the feature returns an explicit feature error.
No build verifies this feature boundary. Reuse clocks, raw/failed transaction
discard, stalled connection cancellation, capacity waiters, timeout/overflow
edges and direct connector errors have no execution or paired evidence.

The native Postgres constructor now merges pinned pgx defaults, nonempty
environment variables, the selected service section and explicit connection
settings in that order. Service selection/path use the preliminary merged
settings; duplicate service sections replace earlier sections. The entire
file is parsed, with Go's Unicode trimming, comments, key/value splitting and
64 KiB scanner-line limit. The native Unix real-UID account/home lookup uses
the already-locked `nix` 0.31.3 user feature through safe APIs. Default socket,
service/password-file and client/root certificate paths follow the pinned
platform layout. Unsupported non-UTF-8 inputs fail without lossy credential
replacement or printing their contents.

Password files follow pinned pgpassfile first-match, wildcard and ordered
escape handling, including empty passwords, Unix-host `localhost` matching
and ignored load/scan errors. Files are fully read before selection and are
not rejected based on permission bits, as in Go. Whole-file size and local
file I/O time are not bounded by the line limit or connector timeout.

The CLI now encodes explicit parsed settings without resolving local files;
the native constructor resolves them at database-open time. Connector timeout
therefore follows the final merged value, including service/explicit overrides
of `PGCONNECT_TIMEOUT`. Native startup parameters carry configured GUCs,
application name, options and timezone without SQLx's extra implicit
DateStyle/client-encoding/UTC/float settings. Empty database names omit the
startup field, and the native statement cache default is 512, matching pgx.
Generic SQLx constructors retain their existing startup and environment paths.

Source inspection found that SQLx TLS was not enabled in the workspace:
`prefer` could only select plaintext and mandatory TLS modes failed. The native
database feature now enables the existing AWS-LC Rustls provider. It reuses
locked Rustls 0.23.46 and webpki-roots 1.0.5; the vendored core dependency
requirement reuses that root package rather than resolving a separate 0.26
package. Native configured CA files replace built-in trust anchors through an
exclusive-file input. `require` with a configured CA uses CA verification
without hostname verification, following pgx's policy. Generic file inputs
retain SQLx's trust behavior. Native verified modes without a CA file use OS
roots, and `sslrootcert=system` forces full endpoint verification even if the
configured mode was disable/allow/require. The Rustls OS store is cached for
the process. The core reuses locked rustls-native-certs 0.8.3 as a required
dependency so this does not select SQLx's Ring-provider feature. No handshake
or certificate fixture qualifies the new feature graph, exclusive/system
stores, cache behavior or mode mapping.

The native connector now expands comma-separated hosts and URI authorities,
maps corresponding ports with first-port reuse, and resolves each TLS variant
before dialing. Prefer/allow try fresh TLS/plain sockets in pgx order; mandatory
modes have no plaintext candidate. Adjacent candidates for the same resolved
endpoint share their connector deadline, while a new endpoint gets a fresh
deadline. DNS resolution remains under the caller's deadline. Authentication,
database and permission failures with SQLSTATE 28P01, 3D000 or 42501 stop the
chain. Original TLS names and resolved IPv6 scope IDs are retained. Unix socket
paths are cleaned lexically before dialing.

All six `target_session_attrs` modes now use the pinned simple SQL/text checks.
Prefer-standby retries the last nonpreferred candidate once with a fresh
deadline after ordinary attempts fail. Rejected connections have bounded owned
cleanup, preserving the known validation verdict and SQLSTATE. Native TCP
applies Go's no-delay and supported 15-second idle/interval, nine-probe
keepalive defaults through already-locked socket2 0.6.1. Socket-option errors
are ignored as in Go. The native pool factory performs Gorm's initial simple
`-- ping`, then eagerly returns the connection for the first schema query;
the later first-reuse ping remains separate.

Local CA material is now read and parsed before mode validation/dialing, even
when TCP TLS is disabled. Enabled client certificate/key pairs are parsed and
matched before any connection candidate; immutable canonical PEM snapshots
prevent rereading changed files during fallback. Local TLS material failures
cannot become plaintext fallback. Unencrypted keys ignore `sslpassword`;
the explicit encrypted-PEM loader below handles legacy encrypted inputs.
Inline material, passwords and arbitrary runtime options are redacted from
connection-option diagnostics. The explicit system-root override also replaces
an invalid SSL mode, as pgx does.

Native direct TLS negotiation now uses PostgreSQL ALPN and promotes prefer to
require. SNI follows pinned pgx: non-verify-full modes honor suppression;
verify-full keeps its verification hostname and DNS SNI. Native handshakes
select the same Rustls backend as preflight even if another dependency also
enables native-tls. CA-only verification handles both hostname-error variants
in locked Rustls 0.23.46 after chain verification.

Native authentication now implements pgx's require_auth positive/negative
method lists, all seven method names, duplicate/mixed-list rejection and the
unauthenticated-Ok check. Forbidden methods fail before sending credentials.
Kerberos settings no longer reject unrelated authentication methods; requested
GSS fails with the no-provider error after policy checks, matching pinned
headscale/Gorm, which register no GSS provider or OAuth token callback.

SCRAM now supports channel_binding prefer/disable/require and PLUS using the
actual TLS leaf certificate. It follows Go's certificate-signature hash rules,
PSS parameter constraints, GS2 headers and base-mechanism requirement. It sends
an 18-byte random nonce with an empty SCRAM username, checks that the server
extends the nonce, enforces pgx's ten-million-iteration ceiling and verifies
the server proof in constant time. Binding=require is checked during SCRAM;
require_auth separately controls whether SCRAM must occur, following pgx.

Password preparation now uses the pinned x/text v0.38.0 OpaqueString profile:
Unicode-space mapping, stream-safe NFC, Unicode 15.0.0 property/context rules
selected by Go 1.26, and raw-password fallback on profile failure. Its imported
range table records the Go source hash and retains the BSD license. The
importer generates source without running Go or Rust. Existing locked
x509-parser 0.18.1 and unicode-normalization 0.1.25 provide certificate parsing
and NFC; no package version was newly resolved. Vendor package metadata now
records the added MIT/BSD license requirements, original Go MIT/BSD notices
are retained, and both container recipes copy the vendor licenses into their
runtime image. The container recipes were not built.

The vendored generic SCRAM path also gains nonce-extension and iteration
checks and a fallible username path. Short auth/ReadyForQuery/backend-key
bodies, malformed SCRAM attributes and invalid frame lengths now fail rather
than indexing short buffers. These source fixes have no adversarial execution
evidence. Unicode/context/import equivalence, certificate/PSS parsing,
malformed-byte inputs, auth error/fallback order and PBKDF2 resource/deadline
behavior still need paired qualification.

Native protocol options now accept pgx's exact 3.0/3.2/latest spellings, retain
the 3.0 default and auto-raise an omitted maximum when the minimum is higher.
An explicit minimum/maximum conflict fails before dialing. Startup sends the
selected maximum, and `NegotiateProtocolVersion` applies Go's minimum check.
Unsupported option names are scanned without count-based allocation and then
ignored as in Go. Full variable-length backend cancellation keys are retained
and redacted in diagnostics. SQLx has no cancellation API using those keys.
Existing 3.0 startup/key source assertions were adjusted for the new fields;
they were not executed.

Local client-key loading now ports Go 1.26.9 PEM block selection, malformed
block scanning, header/whitespace and base64 handling. It selects the first
usable key-file block and checks the private-key label, then infers the actual
PKCS#1/PKCS#8/SEC1 format from DER independently of label spelling. Client
certificate blocks may carry headers; CA blocks with headers are skipped,
following Go's distinct loaders. Key decoding/decryption happens before the
client certificate file is read, and key/certificate validation still precedes
all dialing and fallback.

RFC 1423 encrypted PEM inputs now use sslpassword, Go's MD5/first-eight-IV-byte
derivation and the five named AES-128/192/256, DES and 3DES CBC formats through
already-locked AWS-LC 1.18.2. Missing passwords, invalid IVs/ciphertext/padding
and invalid or mismatched keys fail during preflight. The dedicated
SQLx-core `go-pem-compat` feature is forwarded only by headscale-db's explicit
Go bridge through an optional direct core dependency. It selects AWS-LC's
non-FIPS/legacy-DES feature and sys all-bindings without resolving new versions.
These are local file ciphers; TLS cipher-suite selection is unchanged.
The port retains the Go standard-library BSD notice, already included by the
container vendor-license copies. No build, cipher/key fixture, image, feature,
binding, FIPS, advisory or license gate qualifies this activation.

Native default_query_exec_mode now accepts all five pinned names and dispatches
cache_statement, cache_describe, describe_exec, exec and simple_protocol through
their respective preparation/description/text/simple paths. Statement and
description capacities use Go's signed-32-bit parser; nonpositive values disable
the cache. Argument-free queries always use simple protocol, including initial
and reuse pings, and parameterized cache modes reject disabled caches with the
pinned errors. Description caching has its own LRU and result-format count.
Failed queries invalidate their cached metadata/names; named-statement closure
is deferred until the next operation. Explicit cache clearing also drains
retired names and clears descriptions.

Native automatically cached statements now use pgx's `stmtcache_` plus the
first 24 SHA-256 bytes of SQL as lowercase hex. Native prepare/close batches
are staged before transport append. A preparation drop guard retires a name
on failure or cancellation, and close IDs stay queued until the full close
and ReadyForQuery cycle succeeds. Explicit cache clearing uses that queue;
ReadyForQuery accounting rejects underflow. Explicit SQLx preparation without
a cache retains numeric IDs. `describe_exec` reparses the original query in
its execution frame after SQLx custom-type lookups can replace the unnamed
statement. No cancellation, deallocation or stable-name process comparison
qualifies these changes.

Native arguments are converted from SQLx binary buffers into text, with
null/scalar/text/byte/JSON/UUID/numeric/date/time/timestamp/interval/network,
array and selected enum/domain support. Described results retain SQLx binary
decoding; exec/simple results use text. The generic SQLx execution path stays
separate. Complete Query/Parse/Bind/Execute/Sync frames are encoded before
appending to the transport, so a conversion or encoding error leaves no partial
native execution frame queued.

The pinned pgx sanitizer lexer is ported for simple queries. It preserves
ordinary/E strings, quoted identifiers, tagged dollar strings, line comments
and nested block comments, checks placeholder overflow/missing/unused arguments,
quotes converted values and retains leading/trailing argument-boundary spaces.
Parameterized simple queries enforce the reported UTF8 and
standard_conforming_strings=on prerequisites. Query logs keep the original SQL
template rather than interpolated parameter values.

Received rows, descriptions, notifications, COPY headers and nested values
now check their counts and byte bounds before allocation or indexing. Only
-1 is NULL, native parameter descriptions infer complete OIDs from the body
like pgx, and mismatched native row/metadata counts invalidate the query cache.
Primitive binary widths, JSONB versions, numeric digits, array/record/bit-string
and geometry bounds, and date/timestamp arithmetic are checked. Text arrays
preserve quoted `"NULL"`, text records preserve Unicode and trailing NULL
fields, and text ranges check quoting, bounds and field count. These shared
SQLx decoder fixes have no adversarial or codec execution evidence. SQLx's
signed COPY count API, one-dimensional/one-based array limits, auxiliary/custom
codecs and full Go row-conversion/error fidelity remain incomplete or unqualified.

No mode, codec, lexer, cache, malformed-input, cancellation, resource, schema-drift
or process comparison qualifies this code. Auxiliary/custom text codecs,
per-type Go encoding plans and client/server cast-failure timing, explicit
prepare/persistence behavior, explicit statement naming/lifetimes, text row decoding and
multi-result behavior remain incomplete or unqualified. Weak/degenerate DES
compatibility also remains incomplete: AWS-LC rejects keys accepted by Go.
Protocol negotiation, full-key framing, PEM layouts/algorithms and failure ordering,
malformed/alias-colliding URI inputs, resolver/platform differences, disabled
caches, system-root cache timing, identity/home behavior, diagnostics and
timestamp codecs remain unqualified. Source provenance/notices for these
changes are in both vendor `UPSTREAM.md` files.

These database and vendored-driver changes have no build or execution
evidence. Native acquisition/session checks and idle retirement scheduling
remain unqualified against Go's
database/sql. Driver SSL fallback, invalid-mode diagnostics, environment
overrides, wider typed casts/DSN inputs, stored-row decoding, concurrent
mutations and restart behavior also remain unqualified. No fresh advisory
audit covers this source patch or the newly activated TLS feature graph.

The user requested no further testing. No build, lint, unit, process, or
stock-client validation was run for this batch. Earlier reports below remain
evidence for their earlier source snapshot; they do not qualify these new
changes. The two P0 and one P2 backlog items stay open. Their remaining
requirements are broader production release/upgrade qualification, Postgres
mutation/restart qualification, and CLI/config error/output coverage.

## Executable Parity

The paired production startup/policy corpus in
`target/real-client/startup-policy-oidc-1792243430-49963/report.json` now has
192 matching CLI policy results across SQLite and Postgres. It covers
ambiguous user references in groups, tag owners, route/exit auto-approvers,
ACLs, and SSH rules, rejected-write persistence, file/database startup,
direct database commands, provider-ID priority, missing-user tolerance,
empty policies, and raw-name versus admin display fallback behavior. Rust
now shares that validation across startup, check/set, and reload. `configtest`
also loads stored policy and performs OIDC discovery. Eight paired OIDC
availability rows and four malformed stored-policy rejection rows pass;
those rows compare behavior and preserve diagnostic output without claiming
identical provider/JSON error wording. The real-client CI workflow requires
`tools/real-client/startup-policy-oidc-smoke.py`. These are additional named
qualification rows; the broader P0 gates and CLI diagnostic residuals remain
open.

The separate discovery-deadline report
`target/real-client/oidc-startup-deadline-1792244012-57734/report.json` has
16 passing production processes (eight paired cases). Both implementations
stop discovery after approximately 30 seconds when the provider stalls before
headers or partway through its response body. Required providers reject
`configtest`/`serve`; optional providers allow configtest and serve fallback.
The request deadline includes JSON decoding. The real-client CI workflow
requires `tools/real-client/oidc-startup-deadline-smoke.py`. These rows do not
qualify OIDC callback HTTP deadlines or provider diagnostic wording.

The Rust regression
`upstream_policy_reload_rejects_ambiguous_users_without_replacing_live_policy`
separately checks that a rejected database or file reload leaves the active
policy unchanged. That internal preservation check is distinct from the
paired process corpus's rejected-write persistence checks.

The v0.29.5 admin CLI success corpus now compares 196 populated/empty cases
across human, JSON, JSON-line, and YAML output using deterministic upstream
protobuf responses. All 29 admin RPCs are exercised. Exit status, stdout,
stderr, and RPC requests match the pinned Go CLI in
`target/real-client/cli-admin-output-diff-1792241585-14078/report.json`.
Output is not normalized; only duration-minted request expiry instants are
validated against their invocation time before comparison. This found and
fixed table layout/Unicode widths/multiline rows, short key rendering, human
node timestamps, protobuf YAML names/defaults/indentation, empty-list JSON,
policy-get trailing newlines, and the node-registration deprecation message.
The checked-in fixture and driver are
`tools/parity/headscale-go/cli-fixture/main.go` and
`tools/real-client/cli-admin-output-diff.py`, and the real-client workflow runs
the comparison. The fixture proves the CLI contract independently of the
production server. Config/startup logging and remaining error combinations
keep the P2 CLI backlog open.

The default differential gate is:

```sh
./scripts/headscale_go_diff.sh
```

It compares `tools/parity/headscale-rs` with headscale-go at commit
`0f7d1e536bed9f01dd7161f7637af19bb0908335` over every checked-in
`tools/parity/scenarios/*.json` scenario, then checks the normalized pinned Go
golden at
`tools/parity/golden/headscale-go-v0.29.5.json`.
Former current-head-only route-via steering, SSH `acceptEnv`,
hold-and-delegate SSH checks, SSH host-destination rejection, and
autogroup-internet exit-node route visibility, plus Taildrive/Taildrop
capability grants, now live in the default Go-vs-Rust differential scenario
set. New current-head-only scenarios can still stage under
`tools/parity/current-head/` and run through the Rust golden gate until they are
promoted:

```sh
./scripts/headscale_rs_current_head_golden.sh
```

The full-replacement backlog gate is:

```sh
python3 scripts/check_parity_backlog.py
```

It validates `docs/headscale-go-parity-backlog.json`, the machine-readable list
of known open replacement-parity blockers. The checker intentionally fails if
the backlog file claims completion while any open blocker remains.

The stock-client parity matrix is:

```sh
tools/real-client/smoke-matrix.sh --list
```

Run the full paired matrix when Docker-backed real-client jobs are
available:

```sh
REAL_CLIENT_SMOKES=all REAL_CLIENT_TARGETS='rust headscale-go' tools/real-client/smoke-matrix.sh
```

Current executable coverage:

| Surface | Status | Evidence |
| --- | --- | --- |
| ACL literal prefixes and ports | Done | `literal-prefix-*` scenarios |
| ACL protocol names and numbers | Done | `acl-comment-fields-and-protocols`, `literal-prefix-proto-number-tcp` |
| ACL users, groups, tags, hosts, autogroups | Done | `acl-principal-resolution-matrix`, `host-alias-tcp22` |
| ACL parser and validator errors | Done | `acl-validation-*` scenarios for autogroups, unknown fields, missing references, protocols, and ports |
| Policy missing-reference validation | Done | `acl-validation-undefined-*`, `ssh-validation-undefined-*`, `tagowners-validation-undefined-group`, `tagowners-validation-undefined-tag-owner`, `autoapprovers-validation-undefined-tag-route` |
| Per-node `autogroup:self` filter reduction | Done | `acl-autogroup-self-per-node` |
| Peer map / matcher visibility | Done | `peer-map-symmetric-one-way`, `peer-map-route-visibility`, and `acl-autogroup-self-per-node` `peer_map_checks` cover `PolicyManager.BuildPeerMap` symmetric one-way ACL visibility, active approved route visibility, unapproved route exclusion, and per-node `autogroup:self` peer maps |
| `tagOwners` authorization | Done | `tag-owners-matrix`, `tagowners-nested-tag-owner`, `tagowners-validation-circular-tag-owner` |
| `autoApprovers` route and exit-node checks | Done | `route-autoapprove*` scenarios, including default-route, IP-family, prefix-containment, current-approved preservation, and tagged-node identity edge cases |
| `grants[].via` policy effects | Done | `route-via-grant-effects` `via_route_checks` compare Rust against `PolicyManager.ViaRoutesForPeer` for broader/narrower/disjoint host-alias destinations, IPv6 4via6 advertised-prefix inclusion, same-tag multi-router election, regular-grant overlap `UsePrimary`, and non-via exclusion clearing |
| SSH policy compilation and validation | Done | `ssh-policy-matrix`, `ssh-validation-*` scenarios, and `policy::check` unit coverage for `sshTests` accept/deny/check semantics, all-destination failure handling, localpart users, nonroot wildcards, and SSH/ACL packet-filter independence |
| Tailcfg DNS, DERP, register, map, SSHPolicy JSON summaries | Partial | `wire-*` scenarios, including `RegisterRequest` capability version, old-node-key rotation, network-lock key, tailnet/follow-up/ephemeral/expiry fields, register node-key/device signature fields, `RegisterResponse.NodeKeySignature`, upstream `RegisterResponse.User`/`Login` profile fields, extended `Hostinfo`/`NetInfo` client metadata including routable IPs, services, Tailscale SSH host keys, location, TPM metadata, and DERP latency, `MapRequest` session/debug/connection-handle/hardware-attestation fields, broad `MapNode` metadata/CapMap/Cap/lifecycle timestamps including key-expiry/expired state, `MapResponse` peer/filter deltas, health/display/debug/control fields, `UserProfiles`, `SSHPolicy`, extended `DNSConfig` fields (`Nameservers`, `CertDomains`, resolver bootstrap addresses, `TempCorpIssue13969`), and extended `DERPMap` fields (`HomeParams`, region coordinates/selection flags, node cert/STUN/port-80 metadata); runtime map node names/domains now derive from the configured DNS base domain instead of an Octra-specific core default, streaming `/map` registry wakes now emit incremental `PeersChanged`/`PeersRemoved` updates, self key-expiry wakes now emit an updated self `Node`, route, disco-key, and SSH host-key updates that change full peer state emit full `PeersChanged` entries, endpoint/DERP-only updates emit `PeersChangedPatch` entries, policy-refresh wakes after user-profile registry churn now carry updated `UserProfiles` without forcing unchanged peer-node deltas, `/map` emits headscale-go-style `PacketFilters["base"]` reduced for the receiving node, `/map` stamps requester capability version into self and peer `MapNode.Cap`, self/peer `MapNode.CapMap` now seeds upstream default admin, SSH, and file-sharing capabilities before applying policy node attrs, and full map responses stamp upstream builder fields such as `ControlTime`, `CollectServices=false`, and `Debug.DisableLogTail=true` |
| Public control HTTP basics | Partial | `tailscale_wire::basic_handlers::tests::*` covers headscale-go-compatible `/robots.txt`, `/health`, `/version`, `/windows`, `/apple`, `/apple/{platform}`, `/swagger`, `/swagger/v1/openapiv2.json`, `/verify`, `/register/{auth_id}`, `/auth/{auth_id}`, `/favicon.ico`, and blank fallback response shapes on the unauthenticated control listener; `/register` and `/auth` require the current-upstream prefixed `hskey-authreq-<24 byte id>` auth ID shape. Apple/Windows profile URLs prefer `WireState.public_control_url` to mirror headscale-go `cfg.ServerURL`, with request-derived fallback until full config loading supplies it. `tailscale_wire::acme::tests::*`, `serve::tests::public_router_serves_acme_http01_before_control_fallback`, and `serve::tests::serve_binds_dedicated_acme_http01_listener_without_control_routes` cover the default-off `ServeConfig::acme_http01` path plus the host-policy-protected dedicated listener for `/.well-known/acme-challenge/{token}`; production `headscale server` now starts that listener before TLS material loading and lets the CLI-owned HTTP-01 issuer populate the Go/autocert-compatible cert cache when no usable cache entry exists. `acme_issuer::test_support::*_issues_against_local_acme_directory` drives the real instant-acme client over a controlled HTTPS ACME directory, proves HTTP-01 key-authorization installation, TLS-ALPN challenge-certificate installation/cleanup, CSR finalization, and Go/autocert-compatible cache loading for both challenge types. `server::tests::run_server_http01_acme_issues_through_production_challenge_listener` proves `headscale server` wires the configured HTTP-01 listener into controlled-CA issuance through an exact Host-policy fetch before loading the issued cache, and `server::tests::run_server_tls_alpn_acme_issues_through_production_tls_listener` proves the production public TLS listener serves the RFC 8737 challenge certificate over real SNI/ALPN during controlled-CA TLS-ALPN issuance |
| API-key persistence, admin REST auth, CLI, and gRPC slice | Partial | `headscale-db::api_keys` unit tests, `headscale-api/tests/api_keys_e2e.rs`, `headscale-cli/tests/admin_client.rs`, `grpc::upstream_tests::*`, and `headscale-api/tests/grpc_gateway_e2e.rs` cover headscale-go key shape, Go-compatible `api_keys.hash`/datetime row layout, bcrypt-secret storage, legacy rows, prefix parsing, validate/expire/delete/list, bearer auth, CLI HTTP wiring, the four upstream `HeadscaleService` API-key RPCs, opt-in gRPC bearer API-key auth, grpc-gateway `/api/v1/apikey` create/list/expire/delete paths, and a tonic service mount helper. Production `headscale server` now mounts the authenticated grpc-gateway plus unauthenticated local Unix-socket gRPC, protected by filesystem permissions, over the same persistent admin stores as the wire runtime. The SQLite admin adapter and feature-gated Postgres admin adapter both implement the same API-key admin trait over Go-shaped rows. The gRPC CLI now mirrors upstream human create/list table columns, empty-list table rendering, JSON/json-line/YAML create-as-string output, list timestamp-object output with Go struct field names, `{}` mutation success output, and output-aware `Error:`/JSON/json-line/YAML selector errors with upstream `missing parameters` text and usage exit codes; feature-gated Postgres `serve` process coverage now drives public grpc-gateway API-key create/list/expire/delete against the same persistent store. Remaining API-key gaps are broader stock-client/upgrade integration beyond the local and process harnesses |
| Pre-auth-key persistence, admin REST/CLI, and gRPC slice | Partial | `headscale-db::preauth_keys` unit tests, `headscale-api/tests/preauth_e2e.rs`, `headscale-cli/tests/admin_client.rs`, `grpc::upstream_tests::*`, and `headscale-api/tests/grpc_gateway_e2e.rs` cover create/list/expire/delete, headscale-go `hskey-auth-<12>-<64>` token shape, Go-compatible `pre_auth_keys.prefix/hash/used` row layout, `pre_auth_keys.user_id` FK enforcement with upstream `ON DELETE SET NULL` semantics, reusable/ephemeral/used/tags, tags-only keys, assigned-key delete FK rejection, orphaned `nodes.auth_key_id` cleanup during migration, ID-based upstream gRPC RPCs, OIDC user-id preauth minting through synthesized usernames, grpc-gateway `/api/v1/preauthkey` create/list/expire/delete paths, tag/user validation, `headscale preauthkeys create/list/expire` over upstream gRPC connection modes with prefix-to-ID resolution, and persistent wire auth-key registration preserving `nodes.auth_key_id`. SQLite and feature-gated Postgres admin/preauth-redeemer adapters now implement the same admin trait over Go-shaped rows. The gRPC CLI now mirrors upstream human create output, list columns, owner/tag display, empty-list table rendering, protobuf-shaped JSON/json-line/YAML create/list output with nested `User`, `acl_tags`, timestamp objects, Go-style omitted zero fields, `{}` structured mutation success output, and output-aware `Error:`/JSON/json-line/YAML selector errors with upstream `missing parameters` text and usage exit codes; remaining preauth-key gaps are broader upstream integration coverage beyond the local process harness |
| Node gRPC slice | Partial | `proto/node.proto` now matches the upstream `headscale.v1.Node` message/RPC schema instead of the previous Octra mesh schema, and `grpc::upstream_tests::*` covers `ListNodes`, `GetNode`, `SetTags`, `SetApprovedRoutes`, `BackfillNodeIPs`, `DebugCreateNode`, `RegisterNode` from the debug registration cache, `RegisterNode` consuming the same pending web-registration cache populated by wire register, blocking follow-up wire registration until CLI approval, `RenameNode`, `ExpireNode`, `ExpireNode.disable_expiry`, and `DeleteNode`; `headscale-api/tests/grpc_gateway_e2e.rs` covers the matching grpc-gateway `/api/v1/debug/node`, `/api/v1/node`, `/api/v1/node/register`, `/api/v1/node/backfillips`, and node ID subpaths with protojson-style node bodies, including `disableExpiry`/`disable_expiry` query handling and the upstream mutual-exclusion error when expiry and disable-expiry are both set. `SetTags` now rejects empty lists, malformed tags, and tags missing from the loaded policy like upstream. `headscale-db::headscale_nodes` covers the Go-shaped `nodes` row layout/core node mutations, upstream-shaped ID-filtered list, peer-list, ephemeral-list, and user-hostname read helpers, Tailscale DNS `GivenName` auto-derivation from raw `Hostname`, monotonic collision suffixes, explicit `RenameNode` label validation, and auth-path rekey/update by machine key and user. SQLite and feature-gated Postgres machine admin adapters now expose numeric `nodes.id` values and implement admin node mutations, auth-key registration persistence, runtime state sync, wire-registry hydration, route/address mutation, and node delete over Go-shaped rows. Runtime registration and map Hostinfo updates preserve raw client hostnames separately from DNS `GivenName`, recomputing auto-derived labels only when the existing label was not admin-renamed. `MachineAdmin::complete_registration` now gives `RegisterNode` the same persistent web/CLI approval path as auth-key creation/update: the persistent admin writes or rekeys Go-shaped `nodes`, `WireMachineAdmin` mirrors the in-memory rekey behavior, and `HeadscaleAdminService::with_wire_registry` can project approved nodes into a live `MachineRegistry`. File-backed `RegisterNode` restart coverage now proves numeric node/user IDs, tags, routes, `disco_key`, and pending wire metadata survive DB reopen and registry hydration, with `RegisterNode`, `ListNodes`, and `GetNode` projecting upstream `Node.disco_key`. Route responses preserve headscale-go sticky primary-route ownership, keep exit routes out of `PrimaryRoutes` while surfacing them as serving routes where upstream does, persist approved routes through Go-shaped SQLite rows, and ignore expired/offline nodes when calculating serving route state. Auth-key registration can now write through persistent `nodes` and project the saved row back into the live wire registry; public grpc-gateway, local Unix-socket gRPC, optional remote TCP gRPC, and default `headscale nodes` CLI-over-gRPC are wired, while broader interactive stock-client smokes, CLI output/error snapshots, CLI config-file merging, debug/health top-level CLI wiring, and restart/runtime mutation coverage remain open |
| Policy and health gRPC slice | Partial | `grpc::upstream_tests::*`, `headscale-api/tests/grpc_gateway_e2e.rs`, `headscale-cli/tests/cli_process.rs`, and `headscale-db::policies` cover upstream `GetPolicy`, `SetPolicy`, `CheckPolicy`, and `Health` RPCs backed by `PolicyStore`, preserving raw HUJSON and update timestamps across both tonic and grpc-gateway `/api/v1/policy`, `/api/v1/policy/check`, and `/api/v1/health`; `CheckPolicy` validates candidate policy text without mutating the live store and now evaluates upstream `tests` accept/deny assertions plus `sshTests` accept/deny/check assertions against live nodes before success, including current-upstream `localpart:*@domain` SSH login-user semantics, with `SetPolicy` using the same semantic gate before persistence. `headscale policy get/set/check` now uses the upstream gRPC connection modes by default, with explicit `--server` preserving the legacy HTTP/local-check behavior, `set/check` require upstream `--file/-f` instead of a positional path, and `--bypass-grpc-and-access-database-directly --force` opens the configured DB directly to get/set/check policies without a running server across SQLite and feature-gated Postgres. Health now pings a wired database health probe/SQLite pool and surfaces headscale-go-style ping failures through gRPC and grpc-gateway; the same health and policy-persistence trait boundary now has feature-gated `PgPool` implementations for the Postgres runtime path. Production `headscale server` mounts bearer-auth `/api/v1/health` on the public listener and unauthenticated local Unix-socket `Health` protected by filesystem permissions with the same SQLite health probe as the wire runtime. Config-driven DB-mode policy persistence now appends Go-shaped `policies` rows, reads the latest non-deleted row, and errors on missing policy rows like upstream; config-driven file mode loads raw policy files at startup and rejects `SetPolicy` before parsing. Broader SSH runtime/client parity remains open |
| User admin and gRPC slice | Partial | Admin REST/CLI user CRUD plus `grpc::upstream_tests::*` cover upstream `CreateUser`, `RenameUser`, `DeleteUser`, and `ListUsers` RPCs with numeric IDs and profile fields; `headscale-api/tests/grpc_gateway_e2e.rs` covers the upstream grpc-gateway singular `/api/v1/user` create/list/rename/delete paths with bearer API-key auth and protojson-style uint64/status response shapes. `headscale users create/list/rename/destroy` now defaults to the upstream local Unix-socket gRPC service, supports remote TLS `--address` + `--api-key`, implements `--insecure` as TLS certificate-verification skip instead of plaintext downgrade, supports upstream user profile/filter/rename/destroy flags plus `--force`, keeps `delete` as the upstream destroy alias, and keeps the legacy HTTP transport only when `--server` is supplied without an explicit gRPC endpoint. The gRPC CLI now mirrors upstream human create/list output plus JSON/json-line/YAML create/list/rename/destroy success output with Go struct field names, timestamp objects, and `{}` structured mutation success output. `headscale-db::users` now covers the headscale-go `users` row shape, provider/profile fields, uniqueness indexes, OIDC rename rejection, DNS-hostname validation, and aligned Postgres non-empty-user/preauth cleanup delete semantics. `UserAdmin` now has in-memory, SQLite-backed, and feature-gated Postgres-backed adapters; name-based persistent lookups resolve headscale-go `Username()` fallbacks for OIDC users, and admin/gRPC tests exercise the persistent Go-shaped user store; remaining user gaps are exact upstream error text, user/node FK enforcement, and broader web/OIDC user lifecycle coverage |
| OIDC config and runtime foundation | Partial | `headscale-core::config` and `headscale-cli::config` tests cover upstream OIDC fields/defaults, TOML/YAML parsing, `HEADSCALE_OIDC_*` overrides, `client_secret_path` resolution, upstream-fatal removed keys such as `oidc.expiry`/`oidc.strip_email_domain`/`oidc.map_legacy_users`, PKCE validation, and server `server_url`/state/TLS/local Unix/remote TCP gRPC socket fields needed by the wire runtime; `headscale-api::oidc` tests cover allowed domain/user/group checks, email verification, issuer/subject identifier cleanup, UserInfo merge, profile field mapping, flexible `email_verified` and single-string `groups` decoding, optional/no node expiry, OIDC provider discovery metadata validation, config-to-runtime construction, state/nonce auth-start cookies, PKCE challenge generation, extra auth params, auth-code redirect construction, callback token exchange with PKCE verifier, JWKS-backed ID-token validation, nonce-cookie validation, callback UserInfo fetch/merge, callback claim authorization after final claims are assembled, an optional `OidcUserStore` create/update hook for merged profile claims, callback success/expired-session responses, prefixed auth-ID normalization, registration confirmation cache/CSRF validation, and a generic `OidcRegistrationHandler` hook. `tailscale_wire::router_with_oidc` and `tailscale_wire::serve::ServeConfig::oidc` can mount the OIDC provider so `/register/{auth_id}` starts the auth-code flow, `/oidc/callback` renders the upstream confirmation interstitial, and `POST /register/confirm/{auth_id}` completes the in-memory wire registration cache with OIDC expiry/register method after form/cookie/cache CSRF validation; confirmed OIDC registration now preserves pending client/default expiry when no provider expiry is supplied, lets token expiry override pending/default expiry when `use_expiry_from_token` is enabled, and clears expiry for tagged OIDC registrations. `PersistentOidcRegistrationHandler` and feature-gated `PersistentPostgresOidcRegistrationHandler` can also write/rekey Go-shaped `nodes` rows, validate pending requested tags through shared `tagOwners` policy rules, replace the old live-registry node key on same-machine reauth, preserve disabled OIDC node expiry, complete the same pending cache when configured, and approve SSH-check auth requests only when the persisted source node is owned by the authenticated OIDC user. `headscale server` now uses the headscale-compatible Tailscale wire serve path for both web and OIDC registration, opens/migrates the Go-shaped SQLite DB, loads the latest persisted ACL policy, strictly hydrates existing persisted `nodes` into the live wire registry, mounts the authenticated public grpc-gateway plus local Unix-socket and optional remote TCP gRPC services from the same persistent stores, wires persistent users/preauth/nodes plus the persistent OIDC handler into the shared registration cache/live registry, and requires `server.server_url` so clients receive absolute registration and callback URLs. Paired `tools/real-client/oidc-smoke.sh` and `tools/real-client/oidc-headscale-go-smoke.sh` now prove the production OIDC confirmation flow against Rust and pinned headscale-go with stock Tailscale clients; an env-gated live-Pg OIDC runtime smoke creates an OIDC user through the Pg store, completes interactive registration, proves same-machine rekey/live-registry projection, full map output, Pg row preservation, and restart hydration. Broader persisted policy/route mutation and CLI-over-gRPC serving coverage remain open |

Public `ipsets` are intentionally rejected like headscale-go. The Rust
`AclDoc` has no local `ipset:` alias surface; HuJSON policy parsing treats
top-level `ipsets` as an unknown field. Octra-specific multi-CIDR aliases
belong in an Octra-side preprocessor before submitting upstream-shaped policy
to headscale-rs.

## Full Parity Matrix

| Area | Status | Required work |
| --- | --- | --- |
| Config loading | Partial | Match `config.yaml` search paths, env overrides, validation, TLS/ACME, metrics, DNS, DERP, OIDC, database, gRPC, and CLI config fields. Rust now covers the major v0.28 config/runtime surfaces: DNS defaults and validation, Taildrop, log format, OIDC, top-level server/listener/gRPC/noise/prefix/database/TLS/DERP/policy/CLI aliases, `cli.timeout` parsing, `HEADSCALE_CLI_*` overrides, current-upstream policy env overrides for `HEADSCALE_POLICY_MODE`/`HEADSCALE_POLICY_PATH`, current-upstream runtime feature env overrides for `HEADSCALE_DISABLE_CHECK_UPDATES`, `HEADSCALE_LOGTAIL_ENABLED`, and `HEADSCALE_AUTO_UPDATE_ENABLED`, current-upstream DNS env overrides for `HEADSCALE_DNS_MAGIC_DNS`, `HEADSCALE_DNS_BASE_DOMAIN`, `HEADSCALE_DNS_OVERRIDE_LOCAL_DNS`, `HEADSCALE_DNS_NAMESERVERS_GLOBAL`, `HEADSCALE_DNS_NAMESERVERS_SPLIT`, `HEADSCALE_DNS_SEARCH_DOMAINS`, `HEADSCALE_DNS_EXTRA_RECORDS`, and `HEADSCALE_DNS_EXTRA_RECORDS_PATH`, current-upstream DERP env overrides for `HEADSCALE_DERP_SERVER_*`, `HEADSCALE_DERP_URLS`, `HEADSCALE_DERP_PATHS`, `HEADSCALE_DERP_AUTO_UPDATE_ENABLED`, and `HEADSCALE_DERP_UPDATE_FREQUENCY`, current-upstream ephemeral env overrides for `HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT` and `HEADSCALE_EPHEMERAL_NODE_INACTIVITY_TIMEOUT`, current-upstream tuning env overrides for `HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE` and `HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT`, current-upstream database env overrides for `HEADSCALE_DATABASE_TYPE`, `HEADSCALE_DATABASE_DEBUG`, `HEADSCALE_DATABASE_GORM_*`, `HEADSCALE_DATABASE_SQLITE_*`, and `HEADSCALE_DATABASE_POSTGRES_*`, current-upstream TLS/ACME env overrides for `HEADSCALE_ACME_URL`, `HEADSCALE_ACME_EMAIL`, `HEADSCALE_TLS_LETSENCRYPT_HOSTNAME`, `HEADSCALE_TLS_LETSENCRYPT_CACHE_DIR`, `HEADSCALE_TLS_LETSENCRYPT_LISTEN`, `HEADSCALE_TLS_LETSENCRYPT_CHALLENGE_TYPE`, `HEADSCALE_TLS_CERT_PATH`, and `HEADSCALE_TLS_KEY_PATH`, and current-upstream server transport env overrides for `HEADSCALE_SERVER_URL`, `HEADSCALE_LISTEN_ADDR`, `HEADSCALE_METRICS_LISTEN_ADDR`, `HEADSCALE_GRPC_LISTEN_ADDR`, `HEADSCALE_GRPC_ALLOW_INSECURE`, `HEADSCALE_UNIX_SOCKET`, and `HEADSCALE_UNIX_SOCKET_PERMISSION`, default config discovery, current-upstream `configtest` error context/default fatal accumulation for absent `server`/`dns` blocks, pinned v0.28 config-example-derived fixture parsing, loaded `/debug/config`, manual TLS on the public and remote gRPC listeners, config-backed route HA probe timing including default-filled timeout/interval validation, trusted-proxy forwarding-header gating, SIGHUP ACL policy reload with auto-approval fan-out, and current-upstream parse/projection for update-check, logtail, auto-update, tuning, and database subfields where runtime supports them. HTTP-01 ACME config now passes `configtest`, resolves the upstream `tls_letsencrypt_listen` listener, loads or writes Go/autocert-style cert material in `tls_letsencrypt_cache_dir`, shares that TLS material with remote gRPC, starts a host-policy challenge listener before TLS material loading, performs startup-time online HTTP-01 issuance when the cert cache is missing/invalid/expired, runs live renewal/reload for the public HTTPS and remote gRPC TLS configs, has controlled local-CA issuance coverage through the real ACME client, and has a process snapshot for challenge-listener bind failure before public-CA network issuance. TLS-ALPN-01 now passes `configtest`, bootstraps the public TLS listener when the cache is missing, installs RFC 8737 challenge certificates through the rustls SNI/ALPN resolver, writes Go/autocert cache entries, reloads public HTTPS plus remote gRPC TLS for startup issuance and renewal, and has controlled local-CA issuance coverage through the real ACME client and production public TLS listener. Valid `database.type = "postgres"` now passes `configtest` like upstream, maps to a typed backend foundation, drives backend-aware direct policy DB bypass, and `headscale-cli/postgres-sqlx` is enabled in the default CLI build; explicit `--no-default-features` builds retain the unsupported-Postgres `serve` rejection. Broader supported config/runtime fatal matrices remain open. |
| Database models | Partial | Match users, nodes, preauth keys, API keys, routes, policies, migrations, soft-delete behavior, timestamps, expiry, and uniqueness constraints; API-key, pre-auth-key, user, policy history, and canonical node row shapes now track headscale-go, legacy Octra mesh nodes are isolated in `octra_nodes`, admin/gRPC users and nodes can use Go-compatible SQLite stores, preauth rows enforce the upstream `users(id)` FK while migrating matching legacy username labels to numeric IDs, tagged nodes now clear `nodes.user_id` on import and write paths like current headscale-go, Rust-managed SQLite now stamps the upstream-shaped `database_versions` row with the pinned current headscale-go version while preserving imported rows, approved routes persist in `nodes.approved_routes`, advertised-route updates can mutate `host_info.RoutableIPs` without clearing approvals, map-time runtime state can persist `disco_key`, `endpoints`, `Hostinfo` identity/routes/SSH keys/PreferredDERP, legacy Go `routes` rows migrate enabled approvals into `nodes.approved_routes`, and SQLite import tests now cover modern bcrypt-prefixed preauth/API-key rows plus linked auth-key node metadata across v0.26.0, v0.27.1, v0.28.0-beta.1, v0.28.0-beta.2, and v0.28.0 fixture histories. The DB guard accepts the pinned v0.28-compatible SQLite window and current v0.29 rows only when Go migration history includes `202602201200-clear-tagged-node-user-id`, rejects unsupported older/future Go migration markers, and the feature-gated Postgres foundation can migrate `database_versions`, `policies`, `users`, `api_keys`, `pre_auth_keys`, and `nodes`, ping the database, append/read policy rows, exercise user/OIDC create/read/list/rename/touch/delete primitives, exercise API-key create/list/expire/delete plus modern and legacy validation, exercise preauth-key create/list/expire/delete/try-use plus modern and legacy validation, exercise node create/read/list/update/tag/rename/route/IP/logout/delete primitives in isolated smoke tests, guard existing Pg version state before SQLx migrations, compile a Pg-backed `headscale server` runtime path with OIDC registration/SSH-check approval, run backend-aware direct policy DB bypass through Pg policy primitives, process-cover that bypass without a running server, process-cover Pg serve local/public grpc-gateway/remote gRPC admin lifecycle operations, and run paired production Postgres stock-client auth-key, admin node rename live map churn, online/LastSeen, web-registration, web-registration policy churn, web-registration policy churn restart, IPv4-to-dual-stack prefix backfill, route-approval, exit-node route-approval, web-registration route-approval, OIDC, OIDC restart, OIDC route-approval restart, web-registration restart, restart-persistence, ACL allowed peers, empty ACL streaming edge, autogroup:self peer isolation, route-via steering, route-via same-tag, route-via-health restart failover, route-via reload, route-via multiprefix, route-via multiprefix reload, route-via restart, route-via same-tag restart, route-via reload+restart, route-via multiprefix restart, route-via multiprefix reload+restart, route-health, route-health all-unhealthy, route-health all-unhealthy reload, route-health both-offline secondary reconnect, route-health restart, route-health primary-selection restart, route-health reload+restart, route-health all-unhealthy restart, route-health all-unhealthy reload+restart, route-health mixed-exit, route-health mixed-exit reload, route-health mixed-exit restart, route-health mixed-exit reload+restart, route-health mixed-exit all-unhealthy, route-health mixed-exit all-unhealthy reload, route-health mixed-exit all-unhealthy restart, and route-health mixed-exit all-unhealthy reload+restart smokes through Rust and headscale-go. Broader live Pg stock-client/mutation smokes remain open before claiming full database parity. The live wire runtime is still not fully DB-backed. |
| Node registration | Partial | Match preauth-key registration, reusable/ephemeral/expired keys, CLI debug registration, web registration, OIDC registration, machine-key reuse, node-key expiry, forced tags, and duplicate handling; pre-auth key token/storage format plus user/node storage shapes now match upstream, CLI debug registration can persist through the Go-shaped node adapter, unauthenticated wire registration now creates a Go-shaped 24-byte web registration ID in a shared pending cache and returns current-upstream `hskey-authreq-<id>` AuthURLs, the public web registration page validates the auth ID and renders `headscale auth register --auth-id hskey-authreq-... --user USERNAME`, gRPC `RegisterNode` and `DebugCreateNode` require current-upstream prefixed auth IDs while consuming the same pending entry, wire follow-up requests block until approval, expired or rejected follow-ups restart with a fresh AuthURL, and the cache reports headscale-go's 15m expiry and 1024-entry default LRU cap while honoring configured `tuning.register_cache_max_entries`. Existing registered nodes now handle no-auth restart registration without re-entering web registration, reject client-side expiry extension, process past-expiry logout for both persistent and ephemeral nodes, persist the TS2021 Noise machine key into auth-key and pending web registrations, reject mismatched Noise machine keys on no-auth existing-node requests, auth-key same-user reauth/node-key rotation updates the existing machine-key identity instead of duplicating the node while preserving its address, created timestamp, endpoints, and still-advertised approved routes, and web/CLI same-user reauth now rekeys the existing machine-key identity and clears tags when the client no longer requests any. Used/expired preauth-key re-registration is accepted only for the exact same machine/user/node-key identity, tagged preauth-key registration disables requested/default node-key expiry while untagged preauth preserves future client expiry or falls back to configured `node.expiry`, Go zero-time client expiry falls back to the default, `node.expiry = 0` disables the default, and same-machine re-registration refreshes the default expiry. Client-requested `Hostinfo.RequestTags` are rejected on preauth-key registration, pending web/CLI registrations carry request tags into gRPC approval with `tagOwners` validation, carry configured default expiry when no future client expiry is supplied and no tags are requested, and disable node-key expiry for tagged approvals, and assigned preauth-key deletion is blocked like upstream after orphaned node FK cleanup. Auth-key wire registration also normalizes advertised routes, persists policy auto-approved routes, and can write through to Go-shaped `nodes.auth_key_id` when the persistent server runtime is active. Persistent auth-key, OIDC handler, and web/CLI approval paths now preserve pending wire metadata such as disco key, endpoints, PreferredDERP, SSH host keys, routes, tags, and auth/user FKs through Go-shaped `nodes` and fresh registry hydration. Persistent web/CLI approval now uses the shared `MachineAdmin::complete_registration` path so `RegisterNode` can create or rekey Go-shaped `nodes` and, when configured, project the approval into the live wire registry. Public grpc-gateway plus local Unix-socket and optional remote TCP gRPC production mounting are wired; broader interactive restart/runtime mutation coverage remains open. |
| Poll/map runtime | Partial | Match `/machine/{key}/map`, streaming updates, keep-alives, full vs incremental map responses, peer changes, endpoint updates, disco key updates, hostinfo updates, logout, and expiry behavior; map node FQDNs now follow the configured DNS base domain, loaded policies now reduce visible peers using symmetric node/route access checks, full map responses now carry upstream builder control/debug/service fields and de-duplicated `UserProfiles`, `/map` self and peer nodes now carry the requester `MapRequest.Version` in `MapNode.Cap`, expired self nodes now use upstream `Node.KeyExpiry`/`Expired`/`MachineAuthorized` state instead of a non-upstream map-level expiry bit, streaming registry wakes now use `PeersChanged`/`PeersRemoved` deltas for peer add/remove/update events, policy wakes now use incremental deltas with `PeersRemoved` even when visibility collapses to zero while carrying refreshed `DNSConfig`/packet filters/SSH policy, self key-expiry updates emit the updated self `Node`, full `PeersChanged` deltas for route updates that change peer visibility/route `AllowedIPs` and disco-key-only updates, full map responses with upstream `subnet router online`/`subnet router offline` reasons for approved advertised non-exit subnet-router lifecycle transitions, and `PeersChangedPatch` for endpoint-only, preferred-DERP, and non-router online/offline peer updates. Online state is now volatile stream-session state with a 10-second disconnect grace, and full `MapNode.LastSeen` is suppressed while a node is online like headscale-go. Timestamp-only `/map` `last_seen` bookkeeping now updates quietly without waking long-poll streams; peer-visible HostInfo, route, endpoint, disco, policy, DNS, DERP, and lifecycle changes still wake streams. Map/register HostInfo updates now preserve the full client `Hostinfo`/`NetInfo` snapshot while maintaining hostname/OS/route/SSH-key/DERP projections, omitted `NetInfo` preserves the previous value, map HostInfo route updates now persist newly policy auto-approved routes while preserving existing approvals, DB-backed runtime sync now writes map-time last-seen, disco key, endpoints, full `Hostinfo` identity/routes/SSH keys/NetInfo into Go-shaped `nodes` and hydrates those fields back into the live registry after restart, register-time logout requests with past expiry expire persistent nodes or remove ephemeral nodes like headscale-go, and stream `MapSessionHandle`/`MapSessionSeq` resume requests are accepted but not reflected in `MapResponse.MapSessionHandle`/`Seq`, matching pinned headscale-go's current behavior. Non-streaming `OmitPeers` endpoint-update requests now match headscale-go's lite 200-empty response while still updating node state, leaving downstream Octra domains to Octra-side wiring. |
| Tailcfg wire model | Partial | `RegisterRequest` version/old-node-key/NLKey/tailnet/follow-up/ephemeral/expiry/signature fields, `RegisterResponse.NodeKeySignature` and upstream User/Login/Error shape, expanded `HostInfo` client metadata including legacy services, geolocation, TPM, and `NetInfo` preferred-DERP/link/firewall/DERP-latency fields, `DNSConfig` legacy/temp/cert/resolver fields, `DERPMap` home-parameter/region/node metadata fields, `MapRequest` session/keepalive/debug/connection-handle/hardware-attestation fields, broad `MapNode` metadata including tags/routes/HomeDERP/Cap/capabilities/CapMap, default admin/SSH/file-sharing CapMap entries, lifecycle timestamps, key-expiry/expired state, and WireGuard-only metadata, nodeAttrs-to-CapMap emission, top-level `randomizeClientPort` emission as `randomize-client-port`, policy-driven `MapResponse.Peers` reduction for node IPs and served routes, per-node `PacketFilters["base"]` emission for node IPs and served routes, `MapResponse.UserProfiles`, tagged-node `TaggedDevices` user identity, peer deltas, packet-filter deltas, health/display/debug/control messages, and `SSHPolicy` are covered at the JSON/runtime-test layer; upstream-shaped `taildrop.enabled` now gates the file-sharing CapMap entry and policy node attributes cannot re-enable it while disabled. Still wire remaining route state and client capability negotiation edges. |
| Policy parsing and validation | Partial | SSH parser/error parity plus ACL autogroup placement, unknown fields, missing group/tag/host references, protocol/port errors, nodeAttrs-to-CapMap, top-level `randomizeClientPort`, upstream-shaped `tests`/`sshTests` parsing, ACL `tests` shape validation, `sshTests` semantic evaluation, current-upstream `localpart:*@domain` SSH login-user semantics, and policy update cache invalidation are covered. The public HuJSON parser now accepts and validates upstream-main `grants` and `nodeAttrs`, rejects public top-level `ipsets` like headscale-go, accepts source-only `autogroup:danger-all` while rejecting it as a destination, projects network `grants[].ip` into ACL/filter behavior, keeps empty ACL/grants policies deny-all, validates app capability and `via` tag constraints, serializes `grants[].app` `CapGrant` entries including nullable upstream companion caps for `tailscale.com/cap/drive` and `tailscale.com/cap/relay`, and uses `grants[].via` to steer route `AllowedIPs` per viewer. Keep broadening differential policy v2 fixtures, Taildrive/Taildrop stock-client behavior, and SSH profile/error variants against the pinned baseline. |
| Peer map/matchers | Partial | Exact differential `peer_map_checks` now compare Rust against headscale-go `PolicyManager.BuildPeerMap` for symmetric one-way ACL visibility, active approved route visibility, unapproved route exclusion, and per-node `autogroup:self` peer maps; `headscale-api/tests/policy_consolidation.rs` covers the Rust helper directly, including per-node packet-filter recomputation across tag-context changes after an initial empty lookup, and `tailscale_wire::map::tests::map_response_*policy*` verifies loaded policies reduce `/map` peers while preserving route-visible routers. Runtime `/map` now emits per-node reduced `PacketFilters["base"]` for node IPs and served routes, including source-side `autogroup:danger-all` as `SrcIPs: ["*"]` for direct ACLs and `grants[].via`, plus the headscale-go empty-ACL streaming edge where full maps remain empty but later registry deltas can surface newly joined peers without loosening packet filters. `tools/real-client/acl-allow-smoke.sh` / `tools/real-client/acl-allow-headscale-go-smoke.sh`, `tools/real-client/acl-empty-smoke.sh` / `tools/real-client/acl-empty-headscale-go-smoke.sh`, and `tools/real-client/acl-autogroup-self-smoke.sh` / `tools/real-client/acl-autogroup-self-headscale-go-smoke.sh` now run matching stock-client loaded-ACL, empty-ACL, and multi-user `autogroup:self` peer visibility checks against Rust and pinned headscale-go. Remaining `MatchersForNode` cache edges still need broader route/user integration coverage. |
| Tailscale SSH | Partial | Differential compiler and validation coverage exists, `MapResponse.SSHPolicy` is emitted, `Hostinfo.sshHostKeys` round-trips into peer `MapNode` entries, current-upstream `localpart:*@domain` login-user compiler and `sshTests` semantics are covered, SSH `check` now emits upstream `HoldAndDelegate` instead of direct accept, server-side check-period resolution accepts `always` and rejects `checkPeriod` on non-check actions, and the Noise-inner `/machine/ssh/action/{src}/to/{dst}` route validates the destination node's machine key, binds auth IDs to the `(src,dst)` pair, rejects missing Noise identity, unknown destinations, malformed/unknown auth IDs, and binding mismatches, waits for CLI/web/OIDC auth verdicts, returns upstream-style cancellation when a parked follow-up request is reset without consuming the auth session, rejects denied verdicts without seeding check-period auto-approval, rejects OIDC approval unless the authenticated user owns the SSH source node, and records successful checks for check-period auto-approval. Paired `tools/real-client/ssh-smoke.sh` / `ssh-headscale-go-smoke.sh` stock-client scripts cover same-user `autogroup:self` allow, cross-user policy denial, ACL-blocked packet-filter timeout, flat multi-group source matrices, no-policy denial, and `check`/check-period behavior, paired `tools/real-client/ssh-localpart-smoke.sh` / `ssh-localpart-headscale-go-smoke.sh` cover current-head localpart login users from profile emails, paired `tools/real-client/ssh-profile-variants-smoke.sh` / `ssh-profile-variants-headscale-go-smoke.sh` cover split username/profile-email allow, case-insensitive localpart domain allow, wrong-domain email denial, bare-user denial, exact denied exit status, empty denied stdout, and the stable first denial stderr line, and paired `ssh-profile-subdomain-deny` plus `postgres-ssh-profile-subdomain-deny` rows cover the profile subdomain denial status/stderr shape against current headscale-go. Remaining upstream SSH edges are broader exact client-facing status/stderr snapshots outside these covered denial cases. |
| DNS/MagicDNS | Partial | Match MagicDNS names, search domains, split DNS, resolvers, extra records, collisions, machine records, IPv4/IPv6, disabled DNS, and hot reload behavior; default/base-domain/override-local-DNS validation now follows headscale-go while downstream domains remain embedder-supplied, production `headscale server` now injects configured DNS into the live map runtime, including MagicDNS/base domain, configured IPv4/IPv6 MagicDNS reverse-DNS route roots, search domains, global and split nameservers, `override_local_dns` resolver-vs-fallback behavior, inline extra records, and the extra-records file watcher with upstream-style initial file validation plus empty-hot-reload preservation while valid `[]` clears records, and `wire-dns-derp-extended` differentially covers legacy `Nameservers`, `CertDomains`, resolver bootstrap addresses, empty split-DNS routes, `TempCorpIssue13969`, and additional A/AAAA/CNAME-style extra records. `tools/real-client/magicdns-smoke.sh` / `tools/real-client/magicdns-headscale-go-smoke.sh` now run matching two-client stock-client logins against Rust and pinned headscale-go and assert the client-observed MagicDNS suffix plus self/peer DNS names. `tools/real-client/magicdns-custom-domain-smoke.sh` / `tools/real-client/magicdns-custom-domain-headscale-go-smoke.sh` run the same stock-client assertions with a non-default `base_domain`. `tools/real-client/dns-disabled-smoke.sh` / `tools/real-client/dns-disabled-headscale-go-smoke.sh` run the same stock-client pair with MagicDNS disabled and assert the headscale-go-compatible bare-hostname DNS status fallback. `tools/real-client/dns-edge-*`, `tools/real-client/dns-split-live-records-*`, and `tools/real-client/magicdns-ipv6-only-*` now add paired coverage for split resolver routes, structured global/fallback resolver metadata, live split-resolver A/AAAA stock-client lookups, AAAA/CNAME extra records, MagicDNS normalization/collision caps, IPv6-only prefix MagicDNS records, and map-stream DNS hot-reload behavior at the Rust layer. `tools/real-client/dns-search-live-resolver-*` and `tools/real-client/dns-multi-resolver-fallback-*` now pass against Rust and pinned v0.29.5 with stock clients querying Tailscale internal DNS through Docker bridge resolver sidecars. `tools/real-client/dns-hot-reload-smoke.sh` / `tools/real-client/dns-hot-reload-headscale-go-smoke.sh` now add paired production-process `extra_records_path` reload coverage observed by a stock client and pin that control-plane HTTPS does not synthesize `DNSConfig.CertDomains`. The paired live search-domain and multi-resolver/failure-fallback rows have passed. |
| Routes | Partial | Advertised and approved route storage now feeds node gRPC responses and map response `AllowedIPs`/primary routes, with stateful headscale-go-style sticky primary promotion/failover, exit routes separated from subnet `PrimaryRoutes`, expired/offline nodes excluded from serving-route calculations, registration/map paths applying policy `autoApprovers`, admin/gRPC policy updates re-running auto-approval across existing nodes without removing existing approvals, admin REST/CLI route listing plus approval updates writing the same approved-route state, persistent gRPC/grpc-gateway approval coverage through Go-shaped SQLite rows, legacy `routes` table approvals migrated into node approval state, and streaming map clients receiving full `PeersChanged` deltas when a peer's advertised route update changes visibility or route-derived `AllowedIPs`; `route-autoapprove-edge-matrix` differentially covers upstream default-route, IP-family, prefix-containment, current-approved preservation, and tagged-node identity auto-approval edge cases. `tools/real-client/route-advertise-smoke.sh` / `tools/real-client/route-advertise-headscale-go-smoke.sh`, `tools/real-client/route-approve-smoke.sh` / `tools/real-client/route-approve-headscale-go-smoke.sh`, `tools/real-client/route-primary-smoke.sh` / `tools/real-client/route-primary-headscale-go-smoke.sh`, `tools/real-client/route-primary-failover-smoke.sh` / `tools/real-client/route-primary-failover-headscale-go-smoke.sh`, `tools/real-client/route-primary-sticky-smoke.sh` / `tools/real-client/route-primary-sticky-headscale-go-smoke.sh`, `tools/real-client/route-primary-withdraw-smoke.sh` / `tools/real-client/route-primary-withdraw-headscale-go-smoke.sh`, `tools/real-client/route-exit-node-smoke.sh` / `tools/real-client/route-exit-node-headscale-go-smoke.sh`, `tools/real-client/route-via-smoke.sh` / `tools/real-client/route-via-headscale-go-smoke.sh`, `tools/real-client/route-via-same-tag-smoke.sh` / `tools/real-client/route-via-same-tag-headscale-go-smoke.sh`, `tools/real-client/route-via-health-smoke.sh` / `tools/real-client/route-via-health-headscale-go-smoke.sh`, `tools/real-client/route-via-health-restart-smoke.sh` / `tools/real-client/route-via-health-restart-headscale-go-smoke.sh`, `tools/real-client/route-via-reload-smoke.sh` / `tools/real-client/route-via-reload-headscale-go-smoke.sh`, `tools/real-client/route-via-restart-smoke.sh` / `tools/real-client/route-via-restart-headscale-go-smoke.sh`, `tools/real-client/route-via-multiprefix-smoke.sh` / `tools/real-client/route-via-multiprefix-headscale-go-smoke.sh`, `tools/real-client/route-via-multiprefix-reload-smoke.sh` / `tools/real-client/route-via-multiprefix-reload-headscale-go-smoke.sh`, `tools/real-client/route-via-multiprefix-restart-smoke.sh` / `tools/real-client/route-via-multiprefix-restart-headscale-go-smoke.sh`, `tools/real-client/route-via-multiprefix-reload-restart-smoke.sh` / `tools/real-client/route-via-multiprefix-reload-restart-headscale-go-smoke.sh`, `tools/real-client/route-health-smoke.sh` / `tools/real-client/route-health-headscale-go-smoke.sh`, `tools/real-client/route-health-reload-smoke.sh` / `tools/real-client/route-health-reload-headscale-go-smoke.sh`, `tools/real-client/route-health-reload-restart-smoke.sh` / `tools/real-client/route-health-reload-restart-headscale-go-smoke.sh`, `tools/real-client/route-health-restart-smoke.sh` / `tools/real-client/route-health-restart-headscale-go-smoke.sh`, `tools/real-client/route-health-primary-restart-smoke.sh` / `tools/real-client/route-health-primary-restart-headscale-go-smoke.sh`, `tools/real-client/route-health-all-unhealthy-smoke.sh` / `tools/real-client/route-health-all-unhealthy-headscale-go-smoke.sh`, `tools/real-client/route-health-all-unhealthy-reload-smoke.sh` / `tools/real-client/route-health-all-unhealthy-reload-headscale-go-smoke.sh`, `tools/real-client/route-health-both-offline-reconnect-smoke.sh` / `tools/real-client/route-health-both-offline-reconnect-headscale-go-smoke.sh`, `tools/real-client/route-health-all-unhealthy-restart-smoke.sh` / `tools/real-client/route-health-all-unhealthy-restart-headscale-go-smoke.sh`, `tools/real-client/route-health-mixed-exit-smoke.sh` / `tools/real-client/route-health-mixed-exit-headscale-go-smoke.sh`, `tools/real-client/route-health-mixed-exit-reload-smoke.sh` / `tools/real-client/route-health-mixed-exit-reload-headscale-go-smoke.sh`, `tools/real-client/route-health-mixed-exit-restart-smoke.sh` / `tools/real-client/route-health-mixed-exit-restart-headscale-go-smoke.sh`, `tools/real-client/route-health-mixed-exit-all-unhealthy-smoke.sh` / `tools/real-client/route-health-mixed-exit-all-unhealthy-headscale-go-smoke.sh`, `tools/real-client/route-health-mixed-exit-all-unhealthy-reload-smoke.sh` / `tools/real-client/route-health-mixed-exit-all-unhealthy-reload-headscale-go-smoke.sh`, and `tools/real-client/route-health-mixed-exit-all-unhealthy-restart-smoke.sh` / `tools/real-client/route-health-mixed-exit-all-unhealthy-restart-headscale-go-smoke.sh` now run matching stock-client advertised-route, approved-route, primary-route, primary failover, sticky primary return, primary withdrawal, exit-node, current-head `grants[].via`, current-head same-tag multi-router `grants[].via`, current-head regular-overlap `grants[].via` plus route-health failover, current-head same-tag `grants[].via` route-health failover after production restart, current-head policy-reloaded `grants[].via`, current-head production-restarted `grants[].via`, current-head multi-prefix `grants[].via`, current-head policy-reloaded multi-prefix `grants[].via`, current-head production-restarted multi-prefix `grants[].via`, current-head policy-reloaded plus production-restarted multi-prefix `grants[].via`, current-head route-health failover, current-head policy-reloaded route-health failover, current-head policy-reloaded route-health production restart, current-head production-restarted route-health failover, current-head route-health primary selection across restart, current-head all-unavailable route-health last-known-primary retention, current-head policy-reloaded all-unavailable route-health last-known-primary retention, current-head both-offline route-health secondary reconnect primary promotion, current-head production-restarted all-unavailable route-health last-known-primary retention, current-head mixed exit-node/subnet-router route-health logins, current-head policy-reloaded mixed exit-node/subnet-router route-health logins, current-head production-restarted mixed exit-node/subnet-router route-health logins, current-head mixed exit-node all-unavailable route-health last-known subnet-primary retention, current-head policy-reloaded mixed exit-node all-unavailable route-health retention, and current-head production-restarted mixed exit-node all-unavailable route-health retention against Rust and headscale-go and assert route state. Recent route-edge coverage preserves approvals when routes are temporarily unadvertised, supports explicit unapproval, preserves approvals across policy reload, handles simultaneous/offline/expired/ephemeral router candidates, avoids electing a new primary for a newly introduced all-unhealthy prefix while preserving prior-primary retention, defers route-health timeouts for fresh or reconnected sessions, applies route-health probe results as one batch, asserts policy-file reload recomputes `grants[].via` route ownership, and asserts withdraw map-delta shape. Remaining route gaps are lower-priority route transition breadth rather than the current-head both-offline HA case. |
| Tags | Partial | Match tag ownership, forced tags, invalid tag handling, registration tags, tag removal, and tagged-node user semantics across policy, API, CLI, and map/register responses; nested tagOwners now flatten tag-owner chains, allow circular tag-owner references like current headscale-go, reject undefined tag-owner references, and deny unbacked cycles at runtime through the ownership recursion guard. Preauth-key tags now stamp initial wire registrations, client-advertised `Hostinfo.RequestTags` round-trip on the tailcfg wire model, preauth-key registration rejects request tags, web/CLI registration validates request tags against shared `tagOwners` ownership before applying them, web/CLI same-machine reauth with no requested tags clears the forced tag set and returns the node to the registering user, map/register JSON uses headscale-go's synthetic `TaggedDevices` identity for tagged nodes, tagged node-key expiry stays disabled on registration/reauth, and gRPC, REST, SQLite/Postgres node stores, and the in-memory registry reject empty operator `SetTags` updates while preserving existing tags. `tools/real-client/tagged-preauth-smoke.sh` / `tools/real-client/tagged-preauth-headscale-go-smoke.sh`, `tools/real-client/tag-update-smoke.sh` / `tools/real-client/tag-update-headscale-go-smoke.sh`, `tools/real-client/tag-update-invalid-smoke.sh` / `tools/real-client/tag-update-invalid-headscale-go-smoke.sh`, `tools/real-client/tag-reauth-clear-smoke.sh` / `tools/real-client/tag-reauth-clear-headscale-go-smoke.sh`, `tools/real-client/web-register-tags-smoke.sh` / `tools/real-client/web-register-tags-headscale-go-smoke.sh`, and `tools/real-client/web-register-unowned-tag-smoke.sh` / `tools/real-client/web-register-unowned-tag-headscale-go-smoke.sh` now run matching stock-client tagged auth-key, accepted/rejected operator tag replacement, reauth-based tag clearing, accepted tagged web/CLI registration, and rejected unowned-tag web/CLI registration against Rust and pinned headscale-go. Remaining tag edges need broader API/CLI and map expiry coverage. |
| API keys | Partial | DB-backed create/list/expire/delete, headscale-go `hskey-api-<12>-<64>` shape, Go-compatible `api_keys.hash`/datetime row layout, bcrypt secret hashing, legacy `prefix.secret` validation, REST bearer-auth middleware, upstream `HeadscaleService` API-key RPCs, grpc-gateway API-key paths, opt-in gRPC bearer API-key auth, and `headscale apikeys create/list/expire/delete` over the upstream gRPC connection modes are covered, with legacy HTTP retained only for explicit `--server` use. CLI structured list output now uses upstream proto JSON names (`createdAt`, `lastSeen`) and selector errors validate before default gRPC connection setup; still add broader upstream integration coverage beyond the local process harness. |
| Upstream gRPC API | Partial | The `User`, `Node`, `ApiKey`, `PreAuthKey`, `Policy`, and `Health` proto messages plus their implemented `headscale.v1.HeadscaleService` RPCs are generated and backed by admin state, with users/nodes/API keys/preauth keys able to use Go-compatible SQLite adapters; debug-created CLI registration, web-registration cache approval via `RegisterNode`, node route operations, numeric SQLite node IDs, auth-required service mode, tonic mount helpers, a standard gRPC reflection descriptor/service builder for the v0.28-shaped `HeadscaleService`, and grpc-gateway-backed `Health`/`User`/`PreAuthKey`/`ApiKey`/`Node`/`Policy`/`DebugCreateNode` HTTP annotation slices are covered. The upstream-main auth approval surface now has generated `auth.proto` messages and compatibility `AuthRegister`/`AuthApprove`/`AuthReject` gRPC plus gateway routes backed by the v0.28 registration cache, with `hskey-authreq-` auth ID validation for auth/register/debug paths and empty structured approve/reject responses like upstream. Production `headscale server` mounts the authenticated grpc-gateway on the public listener, unauthenticated local Unix-socket gRPC with reflection, and optional remote TCP gRPC with API-key-authenticated admin RPCs plus reflection using the same persistent users/API-key/preauth/node/policy stores as the wire runtime. The admin CLI now has a reusable gRPC client path and exercises user create/list/rename/destroy, nodes list/show/register/expire/logout/rename/tag/approve-routes/delete/backfillips, API-key create/list/expire/delete, preauth-key create/list/expire, policy get/set/check, top-level health, current-upstream auth register/approve/reject, removed hidden `tailnet` alias rejection, and `debug create-node` over local Unix gRPC by default, including user profile fields, user filter selectors, node numeric identifier flags, API-key prefix/ID selectors, preauth user-name lookup, preauth prefix-to-ID resolution, policy raw-document round-trips, upstream `[cli]` config merging, and remote TLS `--insecure` coverage. grpc-gateway path `uint64` parameters now parse Go base-0 integer literals (`0x`, `0b`, `0o`, leading-zero octal, and underscores) with Go-style `strconv.ParseUint` error text, and implemented v0.28 grpc-gateway parser/auth/status ordering now has exact table coverage. Remaining upstream-main auth-request gaps are broader model/lifecycle semantics beyond the v0.28 registration-cache shim, non-v0.28/current-head grpc-gateway shim edges, and broader integration tests; v0.28 exposes version via public HTTP `/version`, not a `HeadscaleService` RPC. |
| REST/swagger API | Partial | Match `/api/v1`, `/swagger`, `/version`, auth, request/response shapes, status codes, and error bodies; the public wire router now covers `/robots.txt`, `/health`, `/version`, `/windows`, `/apple`, `/apple/{platform}`, `/swagger`, `/swagger/v1/openapiv2.json`, `/verify`, `/register/{auth_id}`, `/auth/{auth_id}`, `/derp/probe`, `/derp/latency-check`, `/bootstrap-dns`, `/metrics`, `/debug`, `/debug/`, `/debug/vars`, `/debug/varz`, `/debug/gc`, `/debug/pprof`, `/debug/pprof/`, `/debug/pprof/cmdline`, `/debug/pprof/profile`, `/debug/pprof/symbol`, `/debug/pprof/trace`, `/debug/pprof/{profile}`, `/debug/statsviz`, `/debug/statsviz/`, `/debug/statsviz/ws`, `/debug/overview`, `/debug/config`, `/debug/routes`, `/debug/derp`, `/debug/registration-cache`, `/debug/filter`, `/debug/policy`, `/debug/ssh`, `/debug/nodestore`, `/debug/mapresponses`, `/debug/batcher`, `/debug/policy-manager`, `/favicon.ico`, and blank fallback with config-backed helper URLs where upstream uses `server_url`. `grpc_gateway::router` now covers the v0.28-shaped `headscale.v1.HeadscaleService` HTTP annotations for `/api/v1/health`, singular `/api/v1/user`, `/api/v1/preauthkey`, `/api/v1/apikey`, `/api/v1/node`, `/api/v1/debug/node`, and `/api/v1/policy` plus the upstream-main auth shim paths `/api/v1/auth/register`, `/api/v1/auth/approve`, and `/api/v1/auth/reject` with upstream-style HTTP-edge bearer auth returning plain `Unauthorized`, protojson-style success/status bodies, Go-style base-0 `uint64` path parsing, body-before-path parser ordering for body routes, and persistent route approval through the Go-shaped node table; the checked-in swagger/OpenAPI JSON advertises those auth paths plus `/api/v1/policy/check`, `v1AuthRegisterRequest`/`Response`, `v1AuthApproveRequest`/`Response`, `v1AuthRejectRequest`/`Response`, and `v1CheckPolicyRequest`/`Response`, and production `headscale server` mounts those `/api/v1` routes on the public listener. Remaining exact grpc-gateway work is broader differential coverage and current-head shim paths outside the implemented v0.28-shaped service. |
| CLI parity | Partial | `headscale users`, `nodes`, `apikeys`, `preauthkeys`, `auth`, `policy`, `health`, and `debug create-node` now use upstream-compatible gRPC by default through the local Unix socket, with remote TLS/API-key config, config-file connection merging, upstream aliases, current-upstream Cobra help snapshots, direct-DB policy bypass, and exact output/error snapshots across text/JSON/json-line/YAML. Recent coverage closes upstream rejection of legacy hidden `--json`, unknown `-o/--output` selector fallback to human output/error formatting, node selector conflicts, missing user selectors, invalid user profile URLs, invalid API-key/preauth-key durations, duplicate users, missing preauth/API keys, structured live auth missing-session errors, missing nodes, invalid tags, and policy parser failures. Still add upstream byte-for-byte help/output/error snapshots for remaining utility command surfaces plus any current-upstream output drift not yet covered. |
| OIDC | Partial | Config/helper parity is in progress: upstream config fields/defaults, CLI TOML/YAML parsing, `HEADSCALE_OIDC_*` overrides, `client_secret_path` handling, removed-key validation for the current `oidc.expiry` to `node.expiry` move and older legacy OIDC keys, PKCE validation, provider discovery/startup metadata validation, config-to-runtime construction, claims authorization, UserInfo merging, profile field mapping, issuer/subject provider identifiers, flexible `email_verified` decoding, helper-level node-expiry selection, auth-code start routing with state/nonce cookies, PKCE, scopes, extra params, callback token exchange with PKCE verifier, JWKS-backed ID-token validation, nonce-cookie validation, UserInfo retrieval/merge, post-merge allowed domain/user/group decisions, optional callback user create/update via `OidcUserStore`, callback registration confirmation/CSRF flow, success/expired-session responses, opt-in serve-level OIDC route mounting into the in-memory wire registration cache, an opt-in persistent OIDC registration handler that writes/rekeys `nodes`, validates requested tags through the same shared `tagOwners` helper used by web/CLI approval, replaces the old live-registry node key, and completes the pending cache, a router-level mock OIDC callback-to-confirm handoff regression, and an OIDC-configured `headscale server` path that builds the wire runtime from the live SQLite/user/preauth/node stores, loads persisted ACL policy, and strictly hydrates persisted nodes into the live registry now have local coverage. Paired stock-client OIDC, OIDC policy-churn, OIDC restart, and OIDC route-approval restart smokes prove the production confirmation flow, file-policy reload visibility, CLI-approved route persistence, and same-URL/SQLite restart reconnection against Rust and pinned headscale-go; paired `postgres-oidc`, `postgres-oidc-restart`, and `postgres-oidc-route-approve-restart` now run the same production OIDC stock-client login, restart, and route-approval restart flows through Postgres and assert persisted user/profile/node rows. Broader Postgres persisted policy mutation coverage remains open. |
| Web registration | Partial | Public `/register/{auth_id}` now accepts current-upstream `hskey-authreq-<24 byte id>` URLs, rejects raw 24-byte IDs like current upstream, returns the `invalid registration id` error body for malformed IDs, serves HTML content type, and renders the current-upstream `headscale auth register --auth-id hskey-authreq-... --user USERNAME` instruction without double-prefixing; unauthenticated wire register creates a 24-character URL-safe registration ID, returns a prefixed AuthURL, and stores pending machine state, including requested ACL tags and configured default expiry when no future client expiry is supplied and no tags are requested, in a shared registration cache. gRPC `RegisterNode` validates those tags against `tagOwners`, requires the prefixed auth ID form, and approves that same pending entry for follow-up wire registration; OIDC callback now stages the upstream confirmation interstitial, `POST /register/confirm/{auth_id}` completes the same in-memory registration cache with OIDC expiry/register method after CSRF validation, pending follow-up requests wait for approval, and expired, rejected, or missing follow-ups restart the web-registration flow with a fresh AuthURL. Persistent `RegisterNode` approval now calls `MachineAdmin::complete_registration`, so web/CLI approval can create or update Go-shaped `nodes`, mirror in-memory rekey behavior through `WireMachineAdmin`, and project approvals into a live `MachineRegistry` when the admin service is built with `with_wire_registry`. `tools/real-client/web-register-smoke.sh` / `tools/real-client/web-register-headscale-go-smoke.sh`, `tools/real-client/web-register-tags-smoke.sh` / `tools/real-client/web-register-tags-headscale-go-smoke.sh`, `tools/real-client/web-register-unowned-tag-smoke.sh` / `tools/real-client/web-register-unowned-tag-headscale-go-smoke.sh`, and `tools/real-client/web-register-restart-smoke.sh` / `tools/real-client/web-register-restart-headscale-go-smoke.sh` now run matching stock-client no-auth, accepted requested-tag, rejected unowned-tag, and production restart web/CLI registrations against Rust and pinned headscale-go. Public grpc-gateway production mounting is wired; broader web/CLI map-churn mutation coverage remains open. |
| Embedded DERP | Partial | Match DERP server, DERP map loading/defaults, STUN behavior, private DERP config, TLS behavior, and integration coverage; `/verify` now accepts headscale-go DERP admission requests and checks the runtime machine registry, `/derp/probe` and `/derp/latency-check` match the upstream browser latency probe responses, `/bootstrap-dns` resolves configured DERP node hostnames into the upstream JSON map shape, `/debug/derp` exposes the configured DERP map in headscale-go text/JSON shapes, `wire-dns-derp-extended` differentially covers `DERPMap.HomeParams`, region latitude/longitude/selection flags, and node cert/STUN/port-80 metadata, and `headscale server` can now build a config-backed embedded DERP map, run a native UDP STUN responder, derive private-DERP host/port metadata from `server_url`, supervise an upstream `derper` sidecar, and mount native `/derp` relay traffic. Paired `tools/real-client/derp-private-*` and `tools/real-client/postgres-derp-private-*` smokes cover private DERP relay through the sidecar, while `tools/real-client/postgres-derp-native-smoke.sh` wires stock-client coverage for Rust native relay mode over production Postgres with the same STUN, DERP-map, forced-DERP ping, status-health, and raw verify-client admission assertions. Rust-only `tools/real-client/postgres-derp-native-websocket-smoke.sh`, `postgres-derp-native-reload-smoke.sh`, and `postgres-derp-native-restart-smoke.sh` cover opt-in DERP-over-WebSocket admissions, policy-reload stability, and restart reconnect/map-stability respectively; headscale-go has no equivalent for the Rust native relay shutdown frames or native `/debug/derp` admission counters. |
| Noise/control protocol | Partial | Match Noise handshake, controlbase transport, TS2021 behavior, error paths, early noise response, key rotation, and client compatibility; TS2021 h2 dispatch now carries the initiator static machine key through request extensions so registration can persist and validate it. |
| State manager | Partial | Registry generation watches, bounded canonical map-change reason/content history with upstream-style content flags, target/origin nodes, peer changed/removed/patch state, bounded response type classification, merge semantics, and pending per-node batcher add-to-batch behavior for full-update supersession, targeted/broadcast splits, deleted-node cleanup, batched full updates that remove the final visible peer, and `BatchChangeDelay` tick-drained publishing, policy/DNS/DERP wake-ups, streaming peer add/remove deltas, endpoint/preferred-DERP peer patches, volatile online/offline state with delayed disconnect, disco-key and route update propagation via full peer deltas, upstream-shaped per-node ephemeral GC timers, production startup scheduling for hydrated ephemeral nodes, persistent-node deletion on GC, 5-second scheduled node-expiry wakeups, live-registry write-through for persistent admin node mutations, config-backed NodeStore put/upsert/delete/bool-update/set-name/rekey/update-many write-worker batching with one COW snapshot publish per concurrent/full or timeout-flushed partial batch and live queue-depth metrics, same-batch update/delete and update-many/delete revalidation that suppresses stale update/policy wakes after final node deletion, worker-routed stream-offline `last_seen` writes, worker-routed legacy ephemeral multi-delete sweeps, long-offline batcher entry cleanup without node deletion, route primary-state updates that ignore offline nodes, route-debug snapshots, and policy-update route auto-approval fan-out via one live-registry update-many operation have local coverage; production DERP URL/path auto-update now replaces the live map on successful refresh, keeps the previous map on failure, merges embedded DERP after external sources, wakes existing `/map` streams, and updates `/debug/derp` plus `/debug/config`; production SIGHUP now reloads the configured ACL policy source and re-runs route auto-approvals, matching the v0.28 policy-reload boundary rather than full config reload. Targeted/full/self update content flags, PingRequest preservation, policy/runtime peer computation, DNS/DERP/domain inclusion, and scoped peer-patch filtering are now pinned by focused map-change and stream regressions. Still match remaining map/debug state. |
| Metrics/debug | Partial | `/metrics`, `/debug`, `/debug/`, `/debug/vars`, `/debug/varz`, `/debug/gc`, `/debug/pprof`, `/debug/pprof/`, `/debug/pprof/cmdline`, `/debug/pprof/profile`, `/debug/pprof/symbol`, `/debug/pprof/trace`, `/debug/pprof/{profile}`, `/debug/statsviz`, `/debug/statsviz/`, `/debug/statsviz/ws`, `/debug/overview`, `/debug/config`, `/debug/routes`, `/debug/derp`, `/debug/registration-cache`, `/debug/filter`, `/debug/policy`, `/debug/ssh`, `/debug/nodestore`, `/debug/mapresponses`, `/debug/batcher`, and `/debug/policy-manager` now cover the headscale-go debug surface for Prometheus-compatible runtime counters, debug index navigation, the tsweb Go-metrics and Prometheus aliases, pprof and statsviz route compatibility, upstream map-response metric names (`headscale_mapresponse_endpoint_updates_total`, `headscale_mapresponse_generated_total`, `headscale_mapresponse_sent_total`, `headscale_mapresponse_ended_total`, and opt-in `headscale_mapresponse_last_sent_seconds`), upstream HTTP metric names (`headscale_http_requests_total` and `headscale_http_duration_seconds`), upstream NodeStore metric names (`headscale_nodestore_operations_total`, `headscale_nodestore_operation_duration_seconds`, `headscale_nodestore_batch_size`, `headscale_nodestore_batch_duration_seconds`, `headscale_nodestore_snapshot_build_duration_seconds`, `headscale_nodestore_nodes_total`, `headscale_nodestore_peers_calculation_duration_seconds`, and `headscale_nodestore_queue_depth`), state overview, runtime config snapshots, primary routes, DERP map inspection, registration-cache metadata, current packet filters, raw policy output, per-node SSH policy output, NodeStore summaries, disabled and enabled map-response dump/readback behavior under `HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH`, active and recently disconnected streaming map connections with headscale-go stale-entry cleanup, and policy-manager inspection; a default SQLite production `headscale serve` process smoke now proves `metrics_listen_addr` serves `/metrics` and `/debug/config` while public `listen_addr` does not expose those diagnostic payloads, with authenticated remote gRPC admin traffic isolated on `grpc_listen_addr`; `/debug/gc` is a Rust no-op compatibility endpoint because there is no GC to force, Rust runtime JSON snapshots are still not a byte-for-byte persisted `types.Node`/`types.Config` dump, and pprof/statsviz return Rust runtime metadata instead of Go pprof protobuf/websocket samples. Still match operational logs that tests depend on. |
| Integration test parity | Partial | `tools/real-client/headscale-rs-harness` now starts the headscale-rs Tailscale wire surface as a standalone stock-client target with harness-only preauth minting, pending web-registration approval/rejection, policy injection, DNS base-domain config, DERP-map loading, machine-state inspection, harness-only route approval, harness-only tag replacement/rejection, and opt-in per-client auth-key users/routes/exit-node flags plus route-health probe timing for route smokes. `tools/real-client/smoke-matrix.sh --list` is the executable source of truth for paired stock-client rows. `tools/real-client/authkey-smoke.sh` runs stock `tailscale/tailscale:v1.94.1` client containers through reusable, non-reusable reuse-rejection, expired-key rejection, and same-user logout/relogin auth-key lifecycle scenarios against that harness, waits for expected logged-in self nodes or expected login failures, and asserts registration state. `tools/real-client/authkey-headscale-go-smoke.sh` runs the matching stock-client auth-key lifecycle scenarios, including same-user logout/relogin against the pinned headscale-go v0.29.5 baseline by default, while current-head wrappers can still target the audited current-head commit for upgrade-track route/SSH smokes. `tools/real-client/web-register-*`, `tools/real-client/web-register-tags-*`, `tools/real-client/web-register-unowned-tag-*`, `tools/real-client/tagged-preauth-*`, `tools/real-client/tag-update-*`, `tools/real-client/tag-reauth-clear-*`, `tools/real-client/acl-allow-*`, `tools/real-client/acl-empty-*`, `tools/real-client/acl-autogroup-self-*`, `tools/real-client/magicdns-*`, `tools/real-client/dns-disabled-*`, `tools/real-client/prefix-family-dual-stack-*`, `tools/real-client/prefix-family-v4-to-dual-backfill-*`, `tools/real-client/postgres-prefix-family-v4-to-dual-backfill-*`, `tools/real-client/postgres-prefix-family-dual-stack-to-ipv4-only-backfill-*`, `tools/real-client/postgres-prefix-family-dual-stack-to-ipv6-only-backfill-*`, `tools/real-client/prefix-family-dual-stack-to-ipv4-only-backfill-*`, `tools/real-client/prefix-family-dual-stack-to-ipv6-only-backfill-*`, `tools/real-client/prefix-family-ipv4-only-*`, `tools/real-client/prefix-family-ipv6-only-*`, `tools/real-client/route-advertise-*`, `tools/real-client/route-approve-*`, `tools/real-client/route-primary-*`, `tools/real-client/route-primary-failover-*`, `tools/real-client/route-primary-sticky-*`, `tools/real-client/route-primary-withdraw-*`, `tools/real-client/route-exit-node-*`, `tools/real-client/route-via-*`, `tools/real-client/route-health-*`, `tools/real-client/oidc-*`, including the `oidc-policy-churn` file-policy reload row, `tools/real-client/restart-persistence-*`, `tools/real-client/dns-edge-*`, `tools/real-client/magicdns-ipv6-only-*`, `tools/real-client/derp-private-*`, `tools/real-client/postgres-derp-private-*`, `tools/real-client/ssh-*`, and `tools/real-client/ssh-localpart-*` now exercise the same stock-client web registration, accepted/rejected tagged web registration, tagged-preauth, accepted/rejected operator tag replacement, reauth-based tag clearing, loaded-ACL peer visibility, empty-ACL streaming peer visibility, multi-user `autogroup:self` peer visibility, MagicDNS enabled/default-domain/custom-domain/disabled behavior, dual-stack/IPv4-only/IPv6-only prefix-family allocation, production-process IPv4-to-dual-stack prefix backfill after restart, dual-stack-to-IPv4-only and dual-stack-to-IPv6-only prefix-family removal backfill after restart, advertised-route, approved-route, primary-route, primary-failover, sticky primary return, primary-withdrawal, exit-node, current-head route-via/reload/restart/multiprefix/multiprefix-reload/multiprefix-restart/multiprefix-reload-restart, current-head route-health failover/recovery/policy-reload/restart/all-unavailable/mixed-exit/mixed-exit-reload cases, production OIDC, OIDC restart, OIDC route-approval restart, production web/CLI restart, restart persistence, DNS edge/IPv6-only MagicDNS, private DERP sidecar/STUN, Tailscale SSH allow/deny/timeout/group/no-policy/check-period, and current-head SSH localpart/profile scenarios against both implementations. Still port upstream stock-client scenarios for API auth, CLI over gRPC, exact SSH status/stderr snapshots, and the remaining ACL/DNS/route edge matrices. |

## Remaining Gap Backlog

Recent coverage note: key-expiry-only peer stream deltas now use
`PeersChangedPatch.KeyExpiry`, matching headscale-go's lightweight peer patch
shape while preserving the existing self-node expiry update path.

Recent coverage note: SSH policy parity now includes `acceptEnv` parsing,
tailcfg emission, and differential harness normalization, plus current-upstream
validation for missing users, invalid literal `*`/empty users, empty
`acceptEnv` entries, host-alias SSH destinations, and the 168h `checkPeriod`
maximum. Current-head-only SSH parity scenarios now cover `acceptEnv` and
hold-and-delegate `check` behavior while the default differential matrix carries
only scenarios that have been promoted to the Go-vs-Rust gate.

Use this backlog to turn each `Partial` row into implementation and parity-test
work. Upstream references are from the pinned current-head module under
`tools/parity/headscale-go`; rows marked `upstream-main` come from the
2026-05-22 sweep against `headscale/headscale` main
`171fd7a3c54156965753a63639cdcafcd50c8d67`. Local references are current repo
evidence, not claims about uninspected code.

| Priority | Gap | Upstream evidence | Local status | Actionable next step |
| --- | --- | --- | --- | --- |
| P0 | upstream-main gRPC/auth API drift | `proto/headscale/v1/headscale.proto` on upstream main adds the auth approval flow beyond the v0.28-shaped RPC set | Rust currently implements the v0.28-shaped `HeadscaleService` slices for users, nodes, preauth keys, API keys, policy, and health plus upstream-main `CheckPolicy`, `ExpireNode.disable_expiry`, and a compatibility `auth.proto` surface for `AuthRegister`/`AuthApprove`/`AuthReject` over the existing v0.28 registration cache, including prefixed auth ID validation, current-upstream web-register and web-auth instructions, checked-in auth OpenAPI entries, empty structured approve/reject CLI output, CLI/web/OIDC-backed SSH check auth verdicts through the Noise-inner SSH action route, and cancellation release for parked SSH and registration follow-up requests without consuming pending auth sessions. The persistent production OIDC handler now applies the same source-node ownership gate before approving SSH-check auth | Finish the full upstream auth-request model, deeper grpc-gateway error matrices, OIDC confirmation/CSRF, and real client approval coverage before claiming current-upstream auth parity |
| P0 | upstream-main policy model drift | Upstream main policy v2 includes grants, policy tests, SSH tests, nodeAttrs, randomize-client-port behavior, and SSH `localpart:*@domain` login users | Rust now parses top-level `randomizeClientPort` and emits `randomize-client-port` in `MapNode.CapMap`, parses/validates upstream-shaped `tests` and `sshTests`, semantically evaluates ACL `tests` plus `sshTests` for `CheckPolicy`/`SetPolicy`, accepts public `grants`/`nodeAttrs`, rejects public `ipsets` like headscale-go, projects network grants into ACL/filter behavior, validates capability/via/ipPool constraints, applies `grants[].via` to per-viewer route selection, covers canonical SSH `localpart:*@domain` login-user semantics through compiler/checker and paired current-head stock-client smokes, pins combined nodeAttrs/grants/via/SSH/profile dual-stack behavior in `policy-v2-nodeattrs-grants-ssh-route-profile`, and now differentially compares per-node policy `NodeCapMap` output through `node_attr_checks`, including top-level `randomizeClientPort` | Keep policy v2 differential fixtures growing as the executable baseline moves beyond v0.28, and broaden SSH profile/error variants |
| P0 | upstream-main CLI command drift | Upstream main exposes additional top-level commands including `serve`, `health`, `version`, `configtest`, `debug`, `generate private-key`, `mockoidc`, and `auth` | Rust has server/node/identity plus admin wrappers; user, node, API-key, preauth-key, policy, health, auth register/approve/reject, and debug-create-node paths use upstream gRPC connection modes, and `serve`, `version`, `completion`, `configtest`, hidden `dumpConfig`, `generate private-key`, and `mockoidc` are wired. Current-upstream utility coverage now includes completion shell help, config/output/force-before-help utility forms, nested completion-shell unknown-command errors, and `mockoidc` positional-help/global-flag behavior; broader residual CLI output drift remains open | Add command/help snapshots against the selected upstream baseline, then implement missing top-level command aliases/behavior while keeping Octra-only commands out of parity claims |
| P0 | drop-in database import and migration parity | Upstream uses its own database versioning/import expectations and supports existing headscale-go deployments beyond SQLite row-shape compatibility | Rust row shapes cover users, nodes, policies, preauth keys, API keys, and route migration slices; `headscale-db` now gates SQLite imports to the pinned v0.28-compatible window by accepting v0.28 `database_versions` rows or v0.28-complete Go migration history, accepting current v0.29 SQLite only when migration history reaches `202602201200-clear-tagged-node-user-id`, preserving existing Go-shaped fixture rows, clearing tagged-node `user_id`, validating modern bcrypt-prefixed auth/API-key imports, preserving auth-key node metadata while letting tagged nodes be tag-owned, stamping fresh Rust-managed SQLite with the pinned current `database_versions` row, preserving imported version rows, classifying SQLite/Postgres URL schemes through a shared typed backend enum, adding feature-gated Postgres `database_versions`/`policies`/`users`/`api_keys`/`pre_auth_keys`/`nodes` migrations plus policy/user/API-key/preauth-key/node primitives, adding feature-gated gRPC policy/health plus user/API-key/preauth/machine admin `PgPool` trait adapters, adding a `headscale-cli/postgres-sqlx` runtime DB enum/open path and Pg-backed wire/admin runtime builder with OIDC, rejecting older/future Go markers before running Rust migrations, making direct policy DB bypass backend-aware plus process-covered for Postgres, adding Pg serve local/public grpc-gateway/remote gRPC admin topology coverage plus local Unix-socket gRPC mutation hydration across process restart, and adding paired production Postgres stock-client auth-key, online/LastSeen, default MagicDNS suffix, custom MagicDNS base-domain, DNS extra-record projection, disabled MagicDNS fallback, split-DNS resolver routes, IPv6-only MagicDNS, dual-stack/IPv4-only/IPv6-only prefix allocation, web-registration, route-approval, exit-node route-approval, web-registration route-approval, OIDC, OIDC restart, OIDC route-approval restart, web-registration restart, restart-persistence, ACL allowed peers, empty ACL streaming edge, autogroup:self peer isolation, route-via steering, route-via same-tag, route-via-health restart failover, route-via reload, route-via multiprefix, route-via multiprefix reload, route-via restart, route-via same-tag restart, route-via reload+restart, route-via multiprefix restart, route-via multiprefix reload+restart, route-health, route-health all-unhealthy, route-health all-unhealthy reload, route-health both-offline secondary reconnect, route-health restart, route-health primary-selection restart, route-health reload+restart, route-health all-unhealthy restart, route-health all-unhealthy reload+restart, route-health mixed-exit, route-health mixed-exit reload, route-health mixed-exit restart, route-health mixed-exit reload+restart, route-health mixed-exit all-unhealthy, route-health mixed-exit all-unhealthy reload, route-health mixed-exit all-unhealthy restart, and route-health mixed-exit all-unhealthy reload+restart smokes. Full Postgres runtime/import remains open until broader live stock-client/mutation smokes pass | Add broader live Postgres stock-client/mutation smokes before claiming drop-in database parity |
| P0 | Noise-protected `/machine/*` endpoints | headscale-go serves map/register inside the TS2021/Noise path, validates the Noise machine key before map/register handling, and exposes only selected public exceptions such as `HEAD /machine/ping-response` | Rust now hard-gates public outer-router `/machine/*` fallback paths to empty 404, explicitly allows only public `HEAD /machine/ping-response` while non-HEAD requests leave ping waiters pending, keeps current Noise-inner control-only `/machine/*` routes public-404, requires the Noise peer machine key for inner map/register routes, returns 405 for wrong verbs on inner control routes instead of hitting placeholders, wraps existing-node register machine-key mismatches in HTTP 200 `RegisterResponse.Error`, and matches upstream `/map` 404 plain-text bodies for missing nodes and machine-key mismatches; keyed and flat missing-key cases are covered | Add paired real-client replay/mismatch tests against the upstream v0.28 auth table |
| P0 | Node address allocation parity | headscale-go allocates IPv4 and IPv6 addresses from DB-aware used-address sets and supports prefix change/backfill semantics | Rust keeps the embeddable `IpAllocator` contract while production `headscale server` now uses a stateful CIDR allocator seeded from persisted `nodes.ipv4`/`nodes.ipv6`, skips network/end and Tailscale-reserved service ranges, supports upstream `prefixes.allocation` values (`sequential`/`random`), carries optional IPv4/IPv6 through live `MachineRecord`, register, map `Addresses`/base `AllowedIPs`, policy/SSH node inputs, MagicDNS A/AAAA records, persistent SQLite hydration/write-through, CLI `prefixes.v6` parsing, upstream IPv6-only `prefixes.v6` config that disables the default IPv4 prefix, missing-family backfill assignment, configured family-removal backfill for IPv4 and IPv6, live-registry sync after backfill mutations, upstream-style `DebugCreateNode` pending nodes with no preallocated addresses, register-time address allocation for new CLI/web approvals including IPv6-only allocator coverage, reauth preservation before allocation, app-level duplicate IPv4/IPv6 rejection for direct admin-created nodes, and DB-level partial unique indexes for non-empty `nodes.ipv4`/`nodes.ipv6`. `tools/real-client/prefix-family-dual-stack-smoke.sh` / `tools/real-client/prefix-family-dual-stack-headscale-go-smoke.sh`, `tools/real-client/prefix-family-ipv4-only-smoke.sh` / `tools/real-client/prefix-family-ipv4-only-headscale-go-smoke.sh`, `tools/real-client/prefix-family-ipv6-only-smoke.sh` / `tools/real-client/prefix-family-ipv6-only-headscale-go-smoke.sh`, `tools/real-client/prefix-family-v4-to-dual-backfill-smoke.sh` / `tools/real-client/prefix-family-v4-to-dual-backfill-headscale-go-smoke.sh`, `tools/real-client/prefix-family-dual-stack-to-ipv4-only-backfill-smoke.sh` / `tools/real-client/prefix-family-dual-stack-to-ipv4-only-backfill-headscale-go-smoke.sh`, and `tools/real-client/prefix-family-dual-stack-to-ipv6-only-backfill-smoke.sh` / `tools/real-client/prefix-family-dual-stack-to-ipv6-only-backfill-headscale-go-smoke.sh` now provide paired stock-client coverage for dual-stack, IPv4-only, IPv6-only, production-process IPv4-to-dual-stack add backfill, and production-process family-removal backfill client-observed addresses against both implementations. Focused persistent-admin and gRPC tests cover family-change backfill for existing IPv4-to-dual, IPv4+IPv6-to-IPv6-only, and IPv6-to-dual cases. Focused map coverage now pins dual-stack and IPv6-only allocation shapes through requester `DNSConfig`/MagicDNS context without leaking peer A/AAAA records into operator `ExtraRecords`. The paired `postgres-prefix-family-v4-to-dual-backfill-ssh-policy-restart` row covers dual-stack peer-map addresses and `tailscale ssh` allow behavior after IPv4-to-dual-stack backfill and post-backfill production restart | Keep Octra-facing structured allocation context cleanup on the consumer side |
| P0 | Persisted OIDC callback completion and node handoff | `hscontrol/oidc.go` validates state/nonce, merges UserInfo, creates/updates the user, renders a registration confirmation interstitial, then completes registration through `POST /register/confirm/{auth_id}` after form/cookie/cache CSRF validation | `headscale-api/src/oidc.rs::handle_callback` validates tokens/claims, can call `OidcUserStore`, renders success/expired-session responses, stages pending OIDC registration confirmations, and validates the current-upstream confirmation POST before completing registration. `tailscale_wire::router_with_oidc` mounts `/oidc/callback`, `/register/confirm/{auth_id}`, and OIDC-backed `/auth/{auth_id}` SSH-check approval into the in-memory registration cache, `PersistentOidcRegistrationHandler` can write/rekey Go-shaped `nodes` rows, validate requested tags, replace the old live-registry node key, and approve persisted SSH-check auth requests only for the OIDC-owned source node, and the OIDC-configured CLI server path opens/migrates SQLite, loads persisted ACL policy, and wires persistent users/preauth/nodes plus that handler into `ServeConfig::oidc`. `headscale-api/tests/oidc_callback_handoff.rs` proves mocked token/JWKS/UserInfo callback waits for confirmation before waking the blocked wire follow-up, paired `tools/real-client/oidc-smoke.sh`/`oidc-headscale-go-smoke.sh`, `tools/real-client/oidc-restart-smoke.sh`/`oidc-restart-headscale-go-smoke.sh`, and `tools/real-client/oidc-route-approve-restart-smoke.sh`/`oidc-route-approve-restart-headscale-go-smoke.sh` prove the production confirmation flow, CLI route approval, and same-URL/SQLite restart reconnection with stock Tailscale clients, `tools/real-client/ssh-oidc-check-smoke.sh`/`tools/real-client/ssh-oidc-check-headscale-go-smoke.sh` exercise OIDC-backed Tailscale SSH `check` approval with stock clients against both implementations, `tools/real-client/ssh-oidc-check-deny-smoke.sh`/`tools/real-client/ssh-oidc-check-deny-headscale-go-smoke.sh` cover the expired check-auth denial status/stdout/stderr path, and `tools/real-client/ssh-oidc-check-cancel-smoke.sh`/`tools/real-client/ssh-oidc-check-cancel-headscale-go-smoke.sh` cover the cancelled check-auth denial status/stdout/stderr path | Extend paired OIDC smokes into broader persisted policy mutation and map-churn coverage |
| P0 | Persisted-node wire runtime | headscale-go auth, map, routes, and gRPC all operate on persisted users/nodes/preauth keys and the state NodeStore | Rust admin/gRPC can use Go-shaped SQLite rows, and the OIDC-configured wire runtime now loads persisted ACL policy, strictly hydrates persisted `nodes` into the live registry on startup, writes auth-key registrations through persistent `nodes` while preserving `auth_key_id`, derives hydrated ephemeral-node state from the assigned preauth key like headscale-go, syncs map-time node runtime state back into `nodes` for restart hydration, can complete persistent web/CLI `RegisterNode` approvals through `MachineAdmin::complete_registration` with optional live-registry projection via `with_wire_registry`, and mounts the public grpc-gateway plus local Unix-socket and optional remote TCP gRPC from the same persistent stores in production `headscale server`. File-backed restart tests now cover auth-key, OIDC-handler, and web/CLI registration preserving node ID, user/auth-key FKs, routes/tags, disco key, endpoints, PreferredDERP, SSH host keys, and ephemeral preauth-key state through DB reopen and registry hydration, paired restart-persistence stock-client smokes prove production Rust/headscale-go restart behavior for auth-key flows plus route/tag netmap churn and `/debug/batcher` connected-state recovery, paired OIDC restart smokes prove OIDC-registered nodes reconnect after same-URL/SQLite server restart, paired OIDC route-approval restart smokes prove CLI-approved OIDC route state survives the same restart boundary, and paired web-register-restart smokes prove CLI-approved web-registration nodes reconnect after same-URL/SQLite server restart; broader web/CLI map-churn and OIDC policy churn smokes are still partial | Broaden persistent web/CLI and OIDC registration stock-client smokes in the production serving topology; add broader restart/reload tests for map visibility and runtime mutations after auth-key and interactive registrations |
| P0 | Runtime task and NodeStore parity | headscale-go has a canonical State/NodeStore, map batcher, scheduled expiry, ephemeral cleanup, DERP refresh, extra-record watchers, SIGHUP policy reload tasks, and route-health probes | Rust has a live `MachineRegistry` projection plus persistent hydration/write-through slices, upstream-shaped ephemeral timers, scheduled node-expiry wakeups, config-backed DERP URL/path refresh, trusted-proxy forwarding-header gating on public listeners, production SIGHUP policy reload with route auto-approval fan-out, policy-change map deltas that remove stale peers/routes even for zero-visible-peer policies, stream online/offline lifecycle changes that carry the upstream policy-change companion while retaining peer-patch churn, registry-change stream wakes that suppress empty peer-delta frames like upstream's map batcher, a pending per-node map-change batcher foundation that covers full-update supersession, targeted/broadcast splits, deleted-node pending cleanup, zero-visible-peer full-update removals, `BatchChangeDelay` tick-drained publishing in production, and production stream consumption of those tick-published batches while preserving immediate generation-watch delivery only for non-batcher embedders/tests. HA-only route-health probes are driven by `node.routes.ha` timing and update primary-route election with upstream-style fresh-session/reconnect deferral and batched health application. Production now installs a `tuning.node_store_batch_size`/`node_store_batch_timeout` NodeStore put/upsert/delete/bool-update/set-name/rekey/update-many worker that blocks callers until their batch is committed, publishes one COW snapshot per batch, performs set-name collision checks inside the writer batch, revalidates same-batch update/delete outcomes against the final snapshot to avoid stale peer-change wakes, routes stream-offline `last_seen` writes and legacy ephemeral multi-delete sweeps through the worker, applies policy auto-approval fan-out as one live-registry update-many operation, and reports live queue depth through `headscale_nodestore_queue_depth`. Persistent admin/gRPC node listing projects live online state and `LastSeen`, paired online/restart stock-client smokes cover disconnect and auth-key restart behavior, the restart-persistence row now waits for Rust/headscale-go `/debug/batcher` JSON to report router and observer `connected=true` before restart, after restart, and after post-restart tag mutation, and local `/debug/batcher` text coverage now locks two-stream churn, partial disconnect, final disconnect, and `mapresponse_ended{reason="done"}` counts. Remaining runtime gaps are broader churn/restart map-stream tests and canonical persistence convergence | Make the persistent NodeStore/runtime state canonical and add churn/restart map-stream tests for each state-change reason |
| P1 | Current-upstream config schema and node-expiry config | Current upstream config includes additional blocks and defaults introduced after the old v0.28 executable baseline, including trusted proxies, update checks, logtail, auto-update, node expiry, route HA timing, tuning, and database subfields | Rust now matches major v0.28 serving/DNS/OIDC/DERP/TLS/CLI fields, rejects removed keys, matches `log.format = "text"` by default, parses a pinned v0.28 config-example-derived fixture including `randomize_client_port` and octal Unix-socket permissions, parses and validates `trusted_proxies` and uses it to gate forwarding headers, rejects upstream-unsafe `server_url`/`dns.base_domain` combinations with current-head fatal text, parses `node.expiry` plus `HEADSCALE_NODE_EXPIRY`, accepts and validates `node.routes.ha` probe timing against explicit and default-filled interval/timeout values, projects node lifecycle fields into `/debug/config`, and drives non-tagged auth-key, interactive/web, and OIDC pending expiry from the same node-default semantics while keeping tagged registrations non-expiring. It also parses/projects update-check, logtail, auto-update, tuning, database subfields, loaded `log`, loaded `cli`, and policy snapshot surfaces where runtime supports them, including valid `database.type = "postgres"` acceptance at `configtest` time and a default CLI Pg runtime path through `headscale-cli/postgres-sqlx` | Add configtest rows for remaining config blocks and finish live Postgres serve smokes before claiming real DB support |
| P1 | Current-upstream route steering and route health | Current upstream policy grants can steer a route through a selected router via `via`, and route health participates in primary-route election | Rust derives served peer routes from each node's active approved routes, applies per-viewer `grants[].via` route selection so two routers advertising the same prefix can be steered to different viewers, applies `grants[].via` over `autogroup:internet` default routes so matching via-tagged exit nodes retain `0.0.0.0/0` and `::/0` while non-matching exit nodes lose those defaults, rebuilds streams on policy changes and route-health failovers that move route `AllowedIPs`, covers v0.28-era primary route behavior, limits route-health ping scheduling to HA prefixes with 2+ active online subnet routers, runs probe-driven route-health transitions that fail over unhealthy primary candidates while preserving sticky recovery semantics, leaves newly introduced all-unhealthy prefixes unmapped unless a previous primary exists, defers timeout-driven unhealthy decisions for fresh or reconnected sessions, applies probe health results in one batch, has unit coverage that policy-file reload recomputes `grants[].via` route ownership, adds regular-overlap `grants[].via` coverage that follows route-health primary failover, and now has paired stock-client current-head smokes for two-viewer, same-tag multi-router, regular-overlap route-health failover, same-tag route-health failover after production restart, policy-reloaded, production-restarted, production-restarted same-tag, multi-prefix, policy-reloaded multi-prefix, production-restarted multi-prefix, and policy-reloaded plus production-restarted multi-prefix `grants[].via` route ownership, pause-driven route-health failover/recovery, policy-reloaded route-health failover, policy-reloaded route-health production restart, production-restarted route-health failover, all-unavailable route-health last-known-primary retention, mixed exit-node/subnet-router route-health separation, production-restarted mixed exit-node/subnet-router route-health separation, and both-offline secondary reconnect primary promotion | Keep tracking new current-upstream route-via/route-health semantics; remaining route-edge breadth is tracked as P2 reload/restart transition coverage |
| P1 | User CRUD policy/map refresh effects | Current upstream refreshes policy manager state around user lifecycle changes so maps and packet filters see user reference changes promptly | Rust gRPC and admin user create/delete/rename now call `PolicyStore::refresh()` after successful mutations so connected `/map` streams rebuild policy-derived state. Tests cover gRPC user CRUD and admin API user create/delete refreshing connected map streams with loaded policies | Broaden OIDC/web user lifecycle coverage and exact upstream error text around FK and rename edge cases |
| P1 | Config-driven serving topology | `hscontrol/app.go` starts public HTTP, grpc-gateway over a Unix gRPC socket, optional external gRPC with auth/TLS or insecure mode, reflection, metrics/debug, DNS, and DERP/STUN from one loaded config | Rust has individual routers/services and helper mount tests, and `headscale server` now starts the headscale-compatible wire path with or without OIDC, public `/api/v1` grpc-gateway routes, local Unix-socket gRPC/reflection, optional remote TCP gRPC/reflection, config-backed DNS injection into map responses, config-backed metrics/debug listener separation through `metrics_listen_addr`, startup DERP URL fetching, static local DERP path-map loading from upstream `derp:`, periodic DERP URL/path auto-update with live map-stream wakeups, config-backed embedded DERP/STUN backed by the same persistent stores, loaded-config `/debug/config` snapshots, trusted-proxy forwarding-header gating, SIGHUP ACL policy reload, and manual TLS cert/key material for remote gRPC plus the raw TLS control listener on upstream `listen_addr` when `https_listen` is absent. HTTP-01 ACME now has production configtest/runtime acceptance, Go/autocert cache reuse/write, startup-time online issuance for missing/invalid/expired cache entries, live renewal/reload for public HTTPS and remote gRPC TLS, a supervised exact-Host-policy validation listener, and controlled local-CA `headscale server` process coverage that fetches the challenge through that production listener. TLS-ALPN now has configtest/runtime acceptance, temporary bootstrap TLS material for missing caches, rustls SNI/ALPN challenge-certificate selection, RFC 8737 challenge certificate generation, Go/autocert cache writes, startup/renewal reload for public HTTPS and remote gRPC TLS, and controlled local-CA `headscale server` process coverage that validates the production public TLS listener over real SNI/ALPN. Native DERP relay is wired with raw, WebSocket, reload, and restart stock-client coverage while sidecar mode remains documented | live public-CA ACME smoke coverage is treated as an externally networked release concern rather than a deterministic parity blocker |
| P1 | gRPC/gateway exactness | `proto/headscale/v1/headscale.proto` exposes User, PreAuthKey, Node, ApiKey, Policy, and Health RPCs only; route approval is `SetApprovedRoutes` and version is public HTTP `/version` | Rust proto/service/gateway cover these slices; grpc-gateway tests now cover bearer auth ordering across normal and auth-shim routes, exact status JSON envelopes for fallback routing, method mismatch, database health failure, missing DB policy rows, implemented-route handler failures, Go base-0 path parsing, malformed JSON, scalar/repeated body type failures, duplicate query values, raw semicolon query/form rejection, timestamp query parse/range errors, timestamp scalar-subfield invalid paths such as `expiry.seconds.foo`, unknown JSON body fields, duplicate protojson body fields including json/proto-name alias conflicts, invalid nested scalar query paths like `id.foo`, and table-driven remaining parser/status envelopes across implemented v0.28 gateway routes. Public reflection now advertises upstream-style `headscale/v1/*.proto` filenames and rewritten public dependencies while filtering internal Octra descriptors. Remaining doc/code comments about route/debug/version RPC expansion are stale for v0.28 | Do not add non-v0.28 RPCs for parity; instead finish narrower gRPC/CLI-visible error text comparisons and stale route/debug/version RPC comments |
| P1 | Tailscale SSH real-client behavior | `integration/ssh_test.go` runs actual `tailscale ssh` allow/deny checks for groups, `autogroup:self`, no-policy, check-period, and cross-user denial; current-upstream policy handling also supports login-user patterns such as `localpart:*@domain` and OIDC-backed `check` approval | Rust compiles/validates SSH policy, rejects circular SSH source-group references, expands nested source groups with recursion guards, emits `MapResponse.SSHPolicy`, fans out peer `sshHostKeys`, covers canonical `localpart:*@domain` login-user behavior in the compiler/checker, and paired OpenSSH-enabled stock-client scripts now assert successful hostname output, permission-denied, packet-filter timeout, flat group matrices, no-policy denial, `check`/check-period, OIDC-backed `check` approval, CLI-approved `check` approval via `headscale auth approve --auth-id ...`, policy mutation across server restart, expired OIDC `check` denial status/empty stdout/first-line stderr/access-denied regex, wrong-user OIDC `check` denial HTTP status plus nonzero SSH exit/empty stdout/headscale-go-matched stderr, opt-in OIDC checkPeriod cache reuse without a second auth URL, cancelled OIDC `check` denial status/empty stdout/auth-prompt stderr, current-head localpart/profile cases, profile email variants including case-insensitive localpart domain matching, and exact denial status/first-line stderr snapshots against headscale-go | Add broader profile-variant coverage and exact client-facing stderr/status text outside the currently covered denial cases |
| P1 | Embedded DERP/STUN/private DERP | headscale-go mounts `/derp`, `/derp/probe`, `/derp/latency-check`, `/bootstrap-dns`, optional client verification, embedded-region generation, and STUN serving | Rust covers verify/probe/latency/bootstrap/debug DERP-map shapes, DERPMap JSON fields, top-level `derp:` parsing, startup JSON URL map fetching, static local YAML path-map loading with merge/remove semantics, periodic URL/path auto-update, config-backed embedded-region generation, a native UDP STUN responder, and supervised upstream `derper` sidecar startup; top-level upstream `derp.server.enabled` now projects to native relay mode with config-backed key persistence, while sidecar mode remains available for supported `derper`-backed relay deployments. Paired private-DERP client coverage now passes through the supported upstream `derper` sidecar, including relay connectivity, STUN, verify-client admission, generated metadata, IPv6/userinfo-safe server URL derivation, and TLS interactions. Clean-room native DERP frame helpers now pin current frame IDs, headers, server-key magic, info-envelope shapes, packet/peer/ping/health/restart frames, unknown-frame preservation, and packet/info caps, an in-process native relay registry can register sessions, route `SendPacket` as `RecvPacket`, return `PeerGone(NotHere)`, notify reverse-path disconnects, and answer ping/pong, and the native `/derp` runtime now covers normal raw DERP, websocket handshakes, raw-TLS `Derp-Fast-Start` no-response dispatch, registry-backed verify-client admission when configured, the `postgres-derp-native` stock-client smoke row, Rust-only `postgres-derp-native-websocket` WebSocket admission coverage, and Rust-only `postgres-derp-native-reload`/`postgres-derp-native-restart` map-stability and reconnect coverage | No active native DERP stock-client runtime blocker remains; keep future work scoped to drift/release-specific evidence or broader release hardening rather than current replacement parity |
| P2 | DNS/MagicDNS edge behavior | upstream DNS integration covers split DNS, resolver routes, extra records, base-domain validation, disabled DNS, and client-observed names | Rust has JSON coverage, production config-to-map DNS wiring, configured MagicDNS reverse-DNS route roots, `override_local_dns` resolver placement, initial `extra_records_path` load/failure behavior, headscale-go-compatible zero-byte-only hot-reload preservation for file-backed extra records while whitespace-only files fail JSON parsing and preserve the previous set, explicit Rust runtime `cert_domains`/`CertDomains` pass-through into `DNSConfig.CertDomains` while paired production smokes prove current headscale-go-compatible HTTPS config does not synthesize CertDomains, paired default/custom/disabled MagicDNS smokes, paired `tools/real-client/extra-records-smoke.sh` / `tools/real-client/extra-records-headscale-go-smoke.sh` coverage for client-observed operator A records, paired `dns-hot-reload` production smokes for `extra_records_path` mtime reload into stock-client netmaps plus stock-client resolver lookups, paired DNS-edge/split-live-records/IPv6-only smokes for split resolver routes, fallback/split resolver object shape with normalized metadata fields, live split-resolver A and AAAA stock-client lookups, AAAA/CNAME records, and IPv6-only MagicDNS, and `wire-dns-runtime-magic-extra-records` differential coverage proving loaded MagicDNS peer records stay out of operator `DNSConfig.ExtraRecords`; paired `dns-search-live-resolver` and `dns-multi-resolver-fallback` scripts now share deterministic expectation builders covered by `tools/real-client/dns-live-resolver-harness-check.sh`, and now pass paired live stock-client DNS queries against Rust and pinned v0.29.5 | Closed for the deterministic v0.29.5 DNS resolver matrix; live public-CA ACME smoke coverage is treated as an externally networked release concern |
| P2 | Route edge transitions | upstream route tests cover auto-approval preservation, primary owner selection, failover, withdrawals, exit routes, offline/expired nodes, policy-triggered updates, and route-health session churn | Rust covers major real-client route flows, differential auto-approval matrices, approval preservation across withdrawal/reauth, explicit unapproval, policy reload preserving approvals, simultaneous candidates, offline/expired/ephemeral router removal, withdraw map-delta shape, route-health failover map-stream deltas, route-health fresh-session timeout deferral, reconnect-during-probe suppression, batched health-result application, `grants[].via` map selection excluding a duplicate non-via subnet while preserving that same peer's allowed exit routes, `grants[].via` exit-node selection over `autogroup:internet` defaults, regular-overlap `grants[].via` route ownership following route-health failover, and paired stock-client current-head route-via/route-health basics including same-tag and multi-prefix route-via steering, same-tag route-via route-health failover after production restart, multi-prefix route-via policy reload plus production restart, policy-reloaded route-health failover, policy-reloaded route-health production restart, production-restarted primary selection, all-unavailable degraded-primary retention, policy-reloaded all-unavailable retention, production-restarted all-unavailable retention, policy-reloaded plus production-restarted all-unavailable retention, mixed exit-node/subnet-router HA separation, policy-reloaded mixed-exit HA separation, production-restarted mixed-exit HA separation, policy-reloaded plus production-restarted mixed-exit HA separation, mixed-exit all-unavailable degraded-primary retention, policy-reloaded mixed-exit all-unavailable retention, production-restarted mixed-exit all-unavailable retention, and policy-reloaded plus production-restarted mixed-exit all-unavailable retention | Add broader paired stock-client route edge coverage for remaining reload and restart interactions |
| P2 | Ping lifecycle | Upstream main mounts public `HEAD /machine/ping-response`, wires `PingRequest` callbacks through the state ping tracker, and exposes `/debug/ping` so operators can initiate a URL-callback ping against a connected node; the old v0.28 baseline did not carry this executable slice | Rust now exposes the public HEAD callback, keeps adjacent public `/machine/*` paths 404, registers unguessable ping IDs, dispatches URL callback `PingRequest` chunks on active map streams, correlates successful callbacks back to the pending ping waiter, lists connected nodes on `/debug/ping`, resolves persisted node IDs for Postgres-hydrated streams, lets GET/POST `/debug/ping` enqueue a `PingRequest` and render success/error/timeout results, and has paired stock-client coverage through `tools/real-client/ping-lifecycle-smoke.sh`, `tools/real-client/ping-lifecycle-headscale-go-smoke.sh`, `tools/real-client/postgres-ping-lifecycle-smoke.sh`, and `tools/real-client/postgres-ping-lifecycle-headscale-go-smoke.sh` against the current-head audit commit | Broaden later only if replacement parity finds current clients require non-HEAD PingRequest types (`TSMP`/`disco`/`c2n`) |
| P2 | CLI over upstream gRPC | headscale-go CLI connects via config, Unix socket by default, remote gRPC with API key/TLS, and exposes `serve`, `version`, `completion`, `configtest`, `dumpConfig`, `debug create-node`, users, nodes, preauthkeys, apikeys, and policy commands | Rust CLI has HTTP-admin wrappers, aliases, and output formats for several groups, plus extra Octra-era commands; user create/list/rename/destroy, API-key create/list/expire/delete, preauth-key create/list/expire/delete, policy get/set/check, top-level health, `debug create-node`, `version`, `completion`, hidden `dumpConfig`, `generate private-key`, `mockoidc`, and `configtest` now run with upstream config discovery, upstream top-level server/config aliases for the production SQLite path and core listeners, `cli.address`/`cli.api_key`/`cli.insecure` config merging plus process-level remote TLS/API-key success and invalid-token coverage, upstream `--insecure` TLS semantics, selectors, migrated-admin help snapshots, current-upstream byte-for-byte Cobra help output for root plus stable operator/auth/user/node/preauthkey/API-key/policy commands, deprecated `nodes register`/`node register`/`help nodes register`, completion shell helper help, `mockoidc --help` including positional-help preemption, `dumpConfig --help`, current-upstream `dumpConfig` missing-target process failures in human/JSON/json-line/YAML formats, config/output/force-before-help `health`/`configtest`/`dumpConfig`, nested completion-shell unknown-command errors including fish/powershell/zsh `--no-descriptions` process snapshots, `mockoidc` inherited-global unknown-flag behavior, and late global-flag rejection for skip-config utility commands, upstream policy `--file/-f` and direct-database bypass behavior for configured SQLite, upstream-style raw first-arg config-load exceptions for `version`/`mockoidc`/`completion`, `completion --no-descriptions`, `completion` missing/unknown-shell help fallbacks, `generate`/`gen` missing/unknown-subcommand help fallbacks, utility-command extra-argument and unknown-flag Cobra error text, `version` JSON/json-line/YAML field shapes including Go-style YAML `buildtime` and target labels, unknown output selectors falling back to human output/error text, legacy `--server` fallback only when explicitly requested, local stderr snapshots for preauthkey/API-key selector validation plus migrated auth/user/node command-boundary errors, default-gRPC API-key selector validation before connection setup, API-key proto JSON field names, exact human stdout for direct-DB policy set/get/check, normalized exact human API-key/preauth-key list table snapshots, gRPC node expire/scheduled-expire/rename/tag/backfillips success strings, and gRPC node list/list-routes/approve-routes tables, remote gRPC missing-API-key/connection-failure/auth-failure errors plus output-aware JSON/json-line/YAML envelopes including auth-failure JSON and connection-failure json-line output, live local-gRPC process coverage for config-provided `unix_socket`, `health`, users, preauthkeys, API keys, auth approve/reject/register, debug create-node, node delete, healthy/unhealthy health output, exact live local-gRPC domain-error snapshots for duplicate users, missing users/API keys/auth sessions/nodes, invalid tags, policy parser failures, and health-failure json-line output, serve-time server-init validation now includes JSON missing-noise-key output plus Postgres-runtime json-line output, and hidden legacy `status` now exits nonzero on missing, unhealthy, or refused `/health` probes. Exact remaining broad current-upstream CLI output/error parity remains open | Add remaining CLI output/error snapshots against current headscale-go, especially residual current-upstream output drift not yet covered; keep Octra-only commands out of parity claims |
| P2 | API auth and error text | upstream grpc-gateway and gRPC auth return specific unauthenticated/status bodies and parser errors before handlers run | Rust covers gRPC bearer auth text for missing tokens, opaque/non-UTF8 metadata, missing `Bearer` prefixes including no-space and lowercase-prefix forms, empty bearer tokens, and invalid tokens, direct gRPC AuthRegister/AuthApprove/AuthReject invalid/no-pending status text, grpc-gateway plain `Unauthorized` auth failures including opaque authorization headers, auth preemption before body/path parsing on normal and auth-shim routes, Go base-0 uint64 parsing, malformed JSON, strict body unknown/duplicate field rejection, invalid nested scalar query paths, duplicate query values, raw semicolon query/form rejection, timestamp parse/range/subfield-path errors, API-key selector not-found status JSON, and protojson-style parser/status JSON envelopes across the implemented gateway routes, including table-driven health and missing-policy server-error envelopes. The exposed proto surface has no non-timestamp well-known query fields left to mirror, and remote CLI missing-API-key, connection-failure, auth-failure, duplicate-user, and health-failure errors now cover human plus structured JSON/json-line/YAML envelopes. Residual API error-text drift is tracked through broader CLI output/error parity rather than a dedicated gRPC backlog row. | Keep future upstream error-text drift under CLI/API snapshot review |

Recent coverage notes (2026-05-25): runtime DNS `CertDomains`
coverage is now explicit config pass-through only; the remaining
DNS/certificate lane now has HTTP-01 and TLS-ALPN cache-backed HTTPS
serving, startup-time online issuance, controlled local-CA issuance
through the real ACME client, exact Host policy for HTTP-01, RFC 8737
challenge-certificate selection for TLS-ALPN, remote gRPC TLS reuse,
live renewal/reload, and challenge listener/resolver coverage at
runtime; runtime DNS
golden coverage now proves MagicDNS peers are not serialized as operator
extra records; SSH OIDC checkPeriod cache reuse has opt-in Rust/headscale-go
smoke coverage; normalized exact API-key/preauth-key list snapshots now guard
human CLI table shape; `version` now uses the upstream `headscale version`
human label and `go` structured runtime object shape; `serve` now reuses the
`configtest` validation gate before opening SQLite and has process snapshots
for invalid policy mode and unsafe trusted proxies; `grants[].via` plus
exit-route interaction is
covered at the map integration layer; direct Go-vs-Rust
`ViaRoutesForPeer` checks cover broader, narrower, disjoint, and IPv6
4via6 host-alias route destinations, upstream `UsePrimary` fallback,
and lowest-ID multi-router via-tag election; paired stock-client
same-tag route-via smokes now prove co-router primary visibility before
broader route-health/restart expansion. Public gRPC reflection now preserves the upstream
`google.api.http` annotations for every implemented `HeadscaleService`
RPC while still filtering internal Octra services out of the advertised
descriptor set; `configtest` now accumulates current-upstream fatal
server-init validation errors for TLS conflict, missing
`noise.private_key_path`, invalid challenge type, unsafe `server_url`,
DNS override, route HA timing, and NodeStore tuning instead of stopping
at the first one; `serve --help` and utility-command unknown shorthand
flag errors now match current-upstream Cobra output, `serve` tolerates
ignored positional args before startup validation like upstream, and
the checked-in OpenAPI JSON now advertises the implemented
`disableExpiry` node-expiry query parameter. Public gRPC reflection now also
serves upstream-style `headscale/v1/*.proto` filenames and rewrites public
descriptor dependencies to those names while keeping internal Octra descriptors
hidden; these `bd73e18`/`0f0b943` slices are closed on current `main`.

Recent coverage notes (2026-06-02): current v0.29.0-beta.2
`database_versions` drop-in coverage now pins Go-shaped tagged/user preauth
rows, tagged/user-owned nodes, null and real expiry values, approved routes,
policy rows, and rejection before SQLx migrations when required Go migration
history is missing. Map-session replacement churn is now covered by executable
tests for disconnect grace, multi-connection drops, rapid reconnect cleanup,
same-batch pending delete/rekey suppression, and lost-wake race behavior.

## Parallel Workstreams

These streams are independent enough to run in separate worktrees. Keep
file ownership narrow when splitting them across agents.

### Active Task Board

| Lane | Status | Owner scope | Next handoff |
| --- | --- | --- | --- |
| CLI node/debug/health gRPC client plumbing | Done | `headscale-cli/src/admin/grpc_client.rs` | Client helpers exist for node, debug-create-node, backfill, and health RPCs |
| CI/fuzz/coverage gates | Done | `.github/workflows/**`, `scripts/**` | CI now runs all-target workspace/standalone tests, checks checked-in fuzz corpus directories, keeps the 10k fuzz lane live, validates selected real-client matrix rows immediately after checkout before toolchain/dependency/Postgres/Docker work, gates the paired current-head `ssh-accept-env`, `postgres-derp-private`, `postgres-derp-native`, Rust-only `postgres-derp-native-websocket`, Rust-only `postgres-derp-native-restart`, `postgres-ssh-accept-env`, `postgres-ssh-localpart`, and `postgres-ssh-profile-variants` stock-client rows on push/PR, and enforces the coverage floor before heavier real-client gates |
| CLI nodes command migration | Done | `headscale-cli/src/admin/nodes.rs`, `headscale-cli/src/admin/mod.rs`, focused CLI tests | `headscale nodes` defaults to upstream gRPC with explicit `--server` legacy HTTP fallback where supported |
| CLI config and snapshots | In flight | `headscale-cli/src/main.rs`, `headscale-cli/src/config.rs`, CLI snapshot tests | `cli.address`/`cli.api_key`/`cli.insecure`/`cli.timeout` plus top-level `unix_socket`, upstream default config discovery, upstream top-level server/config alias mapping, JSON config parsing, top-level current-upstream command/help surfaces including `help <topic> <extra>` topic resolution and the current-upstream no-config warning on `headscale help <topic>` default-config fallback, utility-command extra-argument and unknown-flag Cobra error text including completion fish/powershell/zsh `--no-descriptions` nested-command snapshots, residual completion/generate parser-edge snapshots, auth/users required-flag and missing-parameter snapshots, and rejected `--json`, current-upstream root/operator/auth/user/node/preauthkey/API-key/policy Cobra help snapshots, policy direct-DB bypass coverage, HTTP-01 and TLS-ALPN ACME configtest acceptance plus the non-fatal TLS-ALPN/non-443 warning, valid Postgres `configtest` acceptance, explicit unsupported Postgres `serve`/runtime stderr before SQLite/runtime startup, expanded `serve` pre-state-startup snapshots for configtest-equivalent server-init validation, process-level stderr snapshots for local selector/transport-boundary errors including node selector conflicts, remote gRPC missing-API-key/connection-failure/auth-failure errors plus structured JSON/json-line/YAML envelopes, remote gRPC duplicate-user server-error text/JSON/json-line/YAML snapshots, live local-gRPC success/failure output coverage for health/users/preauthkeys/API keys/auth/node commands via config-provided `unix_socket`, live local-gRPC exact domain-error snapshots for selector, URL, duration, and server-side failures including YAML health failure, upstream-shaped structured outputs, and hidden `status` success/failure exit coverage are wired and covered; broaden remaining output drift snapshots next |
| Wire auth boundary | Done | `headscale-api/src/tailscale_wire/**`, `headscale-cli/src/server.rs`, paired wire tests | Public routers gate `/machine/*`, map/register require Noise peer machine-key context, mismatched Noise machine-key requests are rejected, and the compatibility keyed map route pins upstream Noise `/machine/map` body-`NodeKey` precedence |
| Address allocation | In flight | `headscale-api/src/tailscale_wire/**`, `headscale-db/**`, Octra adapter tests | Production allocation is now DB-seeded and config-aware for v4/v6, debug/CLI registration allocates at approval time like upstream, direct admin creation rejects duplicate addresses, DB partial unique indexes protect non-empty manual node addresses, `MachineRecord` tolerates IPv4-disabled nodes, upstream IPv6-only prefix config disables the default IPv4 prefix, paired dual-stack/IPv4-only/IPv6-only prefix-family stock-client smokes cover initial configured family allocation cases, paired production-process IPv4-to-dual-stack and dual-stack-to-single-family stock-client smokes cover initial restart, `nodes backfillips`, and post-backfill restart hydration, the Postgres IPv4-to-dual-stack route-preservation row covers an already-approved subnet route across backfill and post-backfill restart, the Postgres IPv4-to-dual-stack MagicDNS row covers peer A/AAAA resolution across backfill and post-backfill restart, the Postgres IPv4-to-dual-stack SSH policy row covers dual-stack peer-map addresses plus Tailscale SSH allow behavior across backfill and post-backfill restart, and persistent-admin/gRPC tests cover prefix-family add/remove backfill semantics; keep Octra-facing structured allocation context cleanup |
| Runtime/auth parity | In flight | `headscale-api/proto/auth.proto`, `headscale-api/src/grpc.rs`, `headscale-api/src/grpc_gateway.rs`, `headscale-api/src/tailscale_wire/register.rs`, `headscale-api/src/tailscale_wire/ssh.rs`, wire registration tests, `tools/real-client/ssh-oidc-check-smoke.sh`, `tools/real-client/ssh-oidc-check-deny-smoke.sh`, `tools/real-client/ssh-oidc-check-cancel-smoke.sh` | Prefixed auth IDs, prefixed-ID `RegisterNode`/`DebugCreateNode`, rejected web-registration follow-up refresh, web-register AuthURLs/instructions, the `/auth/{auth_id}` approval page, OIDC `/auth/{auth_id}` redirects, OIDC registration confirmation/CSRF, auth OpenAPI entries, CLI structured approve/reject output, CLI/web/OIDC SSH-check approval over `/machine/ssh/action/{src}/to/{dst}` including persistent production OIDC source-owner checks, paired stock-client OIDC SSH `check` approval plus expired-denial and cancel-denial status/stderr against Rust and headscale-go, cancelled SSH plus web-registration follow-up request release without consuming auth sessions, policy-refresh map churn carrying updated `UserProfiles` without unchanged peer deltas, Hostinfo `NetInfo.PreferredDERP`-only churn recording `endpoint/DERP update` peer patches, PreferredDERP clears using batched `node updated` peer deltas instead of full self-update reasons, and in-memory route-approval mutations plus map-time Hostinfo route auto-approval recording upstream `policy change` map reasons instead of peer `route update` reasons are covered, including the initial `Stream:true` subnet-router lifecycle plus deferred policy-change batch sequence and web/CLI/OIDC auth-completion lifecycle plus route policy-change projection; next split is broader current-upstream auth-request lifecycle beyond the v0.28 registration-cache shim, especially remaining map/NodeStore churn and reason propagation |
| Persistent runtime smokes | In flight | `tools/real-client/**`, server/runtime tests | Online/LastSeen, restart-persistence with debug batcher state, OIDC restart, OIDC route-approval restart, and web/CLI registration restart stock-client lifecycles are covered; feature-gated Postgres runtime construction now wires OIDC registration and SSH-check approval, an env-gated live-Pg runtime smoke covers migration plus preauth-key wire registration, policy persistence, and restart hydration, an env-gated live-Pg OIDC smoke covers OIDC user creation, interactive registration completion, same-machine rekey/live-registry projection, full map output, Pg row preservation, and restart hydration, an env-gated production Pg `serve` process smoke starts the real binary to cover public health, local gRPC health/users/preauth/API-key/policy/node admin CLI paths, authenticated public grpc-gateway health/user/API-key access plus node lifecycle mutations and a preauth-key restart mutation path, and optional remote TCP gRPC API-key auth against the same Pg stores, an env-gated Pg direct-policy process smoke proves `policy --bypass-grpc-and-access-database-directly` can migrate and round-trip get/set/check without a running server, and paired env-gated `postgres-authkey`, `postgres-authkey-nonreusable`, `postgres-authkey-expired`, `postgres-authkey-relogin-same-user`, `postgres-authkey-relogin-route-preserve`, `postgres-taildrop-capmap`, `postgres-randomize-client-port`, `postgres-derp-private`, `postgres-derp-native`, `postgres-derp-native-websocket`, `postgres-derp-native-reload`, `postgres-derp-native-restart`, `postgres-online-lastseen`, `postgres-ping-lifecycle`, `postgres-policy-churn`, `postgres-web-register-policy-churn`, `postgres-web-register-policy-churn-restart`, `postgres-web-register-policy-config-map-churn-restart`, `postgres-node-rename`, `postgres-user-node-lifecycle-restart`, `postgres-magicdns`, `postgres-magicdns-custom-domain`, `postgres-extra-records`, `postgres-dns-disabled`, `postgres-dns-edge`, `postgres-dns-hot-reload`, `postgres-magicdns-ipv6-only`, `postgres-prefix-family-dual-stack`, `postgres-prefix-family-v4-to-dual-backfill`, `postgres-prefix-family-v4-to-dual-backfill-route-restart`, `postgres-prefix-family-v4-to-dual-backfill-magicdns-restart`, `postgres-prefix-family-v4-to-dual-backfill-ssh-policy-restart`, `postgres-prefix-family-dual-stack-to-ipv4-only-backfill`, `postgres-prefix-family-dual-stack-to-ipv6-only-backfill`, `postgres-prefix-family-ipv4-only`, `postgres-prefix-family-ipv6-only`, `postgres-web-register`, `postgres-web-register-tags`, `postgres-web-register-unowned-tag`, `postgres-route-advertise`, `postgres-route-approve`, `postgres-route-primary`, `postgres-route-primary-restart`, `postgres-route-primary-failover`, `postgres-route-primary-sticky`, `postgres-route-primary-withdraw`, `postgres-route-exit-node`, `postgres-web-register-route-approve`, `postgres-oidc`, `postgres-oidc-restart`, `postgres-oidc-route-approve-restart`, `postgres-ssh`, `postgres-ssh-oidc-check`, `postgres-ssh-cli-check`, `postgres-ssh-oidc-check-period-cache`, `postgres-ssh-oidc-policy-restart`, `postgres-ssh-oidc-check-wrong-user`, `postgres-ssh-oidc-check-deny`, `postgres-ssh-oidc-check-cancel`, `postgres-ssh-accept-env`, `postgres-ssh-localpart`, `postgres-ssh-profile-variants`, `postgres-web-register-restart`, `postgres-restart-persistence`, `postgres-tagged-preauth`, `postgres-tag-update`, `postgres-tag-update-invalid`, `postgres-tag-reauth-clear`, `postgres-acl-allow`, `postgres-acl-empty`, `postgres-acl-autogroup-self`, `postgres-route-via`, `postgres-route-via-same-tag`, `postgres-route-via-health`, `postgres-route-via-health-restart`, `postgres-route-via-reload`, `postgres-route-via-multiprefix`, `postgres-route-via-multiprefix-reload`, `postgres-route-via-restart`, `postgres-route-via-same-tag-restart`, `postgres-route-via-reload-restart`, `postgres-route-via-multiprefix-restart`, `postgres-route-via-multiprefix-reload-restart`, `postgres-route-health`, `postgres-route-health-reload`, `postgres-route-health-all-unhealthy`, `postgres-route-health-all-unhealthy-reload`, `postgres-route-health-both-offline-reconnect`, `postgres-route-health-restart`, `postgres-route-health-primary-restart`, `postgres-route-health-reload-restart`, `postgres-route-health-all-unhealthy-restart`, `postgres-route-health-all-unhealthy-reload-restart`, `postgres-route-health-mixed-exit`, `postgres-route-health-mixed-exit-reload`, `postgres-route-health-mixed-exit-restart`, `postgres-route-health-mixed-exit-reload-restart`, `postgres-route-health-mixed-exit-all-unhealthy`, `postgres-route-health-mixed-exit-all-unhealthy-reload`, `postgres-route-health-mixed-exit-all-unhealthy-restart`, and `postgres-route-health-mixed-exit-all-unhealthy-reload-restart` stock-client scripts run Rust/headscale-go production Postgres auth-key, one-time and expired auth-key rejection, same-user auth-key relogin, auth-key relogin route preservation, Taildrop CapMap disablement, randomize-client-port CapMap projection, private DERP sidecar/STUN/relay, native DERP relay/STUN, native DERP WebSocket admissions, native DERP policy-reload map stability, native DERP restart reconnect, online/LastSeen lifecycle, Postgres debug PingRequest lifecycle, Postgres auth-key policy mutation peer-map churn, Postgres web-registration policy mutation peer-map churn plus restart hydration, Postgres web-registration policy/config map churn plus MagicDNS peer resolution across restart, admin node rename live peer-map churn, user rename/node expire/delete/user destroy restart persistence, default/custom MagicDNS base-domain, DNS extra-record projection and hot reload, disabled MagicDNS fallback, split DNS resolver routes, IPv6-only MagicDNS allocation, explicit dual-stack, IPv4-to-dual-stack, IPv4-to-dual-stack route preservation across post-backfill restart, IPv4-to-dual-stack peer MagicDNS A/AAAA resolution across post-backfill restart, IPv4-to-dual-stack SSH policy allow with dual-stack peer addresses across post-backfill restart, and family-removal backfill, IPv4-only, and IPv6-only allocation, no-auth web/CLI registration, web-registration tag ownership/rejection, route advertisement, route approval, primary-route restart-owner preservation, primary-route failover/sticky/withdrawal, exit-node approval, web-registration route metadata/approval, OIDC confirmation, OIDC reconnect, Tailscale SSH allow/deny/timeout, OIDC-backed SSH-check approval, checkPeriod cache, OIDC SSH policy mutation across server restart, and denial/CLI variants, SSH acceptEnv forwarding, SSH localpart/profile variants, restart reconnect, tagged preauth, tag mutation/rejection, web reauth tag clearing, ACL peer visibility, empty ACL streaming visibility, autogroup:self peer isolation, route-via steering, route-via-health failover steering, route-via-health restart failover steering, `tailscale debug netmap`, node lifecycle/profile/route assertions, peer map churn, and `/debug/batcher` connected-state recovery. The real-client push/PR workflow now provisions Postgres 16, runs the focused Pg `serve` topology cargo test with a live Pg URL, and the checked-in matrix contains one hundred nineteen Postgres stock-client rows; broader production Postgres stock-client serve smokes remain open; broaden production-process restart/mutation smokes for more registration/config map-stream churn cases |
| Octra boundary checks | Done | `docs/octra-consumer-boundary.md`, `headscale-api/tests/grpc_gateway_e2e.rs`, `scripts/check_parity_backlog.py` | Octra-only admin mounting, embedded CLI documentation, preauth account policy, and settlement/billing policy are documented as downstream-only unless they expose a generic headscale-go contract. The replacement grpc-gateway test rejects Octra-only `/api/v1/nodes`, `/api/v1/register`, `/api/v1/status`, `/api/v1/balance/{account}`, and `/api/v1/transfer` routes with standard 404/code 5 status JSON, and the swagger absence test proves those routes are not advertised. The generic no-DB preauth split is closed: `InMemoryPreauthAdmin` implements `PreauthRedeemer`, matching persistent-store sharing for embedders that want one admin/wire key store. The generic public control-router embedding gap is closed by `ControlRouterOptions::without_health_route()`, `control_router_with_options`, and `control_router_with_oidc_and_options`, so downstreams can mount full stock public control routes while keeping host-owned `/health`. |
| DB import matrix | Done for SQLite window | `headscale-db/tests/**`, fixture DBs, migration guard | SQLite import fixtures now cover v0.26.0, v0.27.1, v0.28.0-beta.1, v0.28.0-beta.2, and v0.28.0 with explicit accepted/rejected windows; Postgres has feature-gated foundation migrations/primitives for version, policy, user, API-key, preauth-key, and node rows plus matching node read-helper parity and admin trait adapters for policy/health/users/API keys/preauth keys/machines, Pg foundation migration now rejects unsupported existing version state, malformed database_versions rows, and unknown Go migration histories before SQLx migrations run, a Pg runtime path with OIDC registration/SSH-check approval is wired, direct policy DB bypass is backend-aware and covered by an env-gated no-server process smoke, env-gated live-Pg runtime register/hydrate and OIDC rekey/project/hydrate smokes cover the runtime builder, an env-gated production Pg `serve` smoke covers public health, local gRPC health/users/preauth/API-key/policy/node admin CLI paths, authenticated public grpc-gateway health/user/API-key access plus node lifecycle mutations and a preauth-key restart mutation path, and optional remote TCP gRPC API-key auth against the same Pg stores, paired env-gated Pg auth-key, one-time and expired auth-key rejection, online/LastSeen, debug PingRequest lifecycle, auth-key policy mutation peer-map churn, web-registration policy mutation peer-map churn plus restart hydration, web-registration policy/config map churn plus MagicDNS peer resolution across restart, admin node rename live peer-map churn, user rename/node expire/delete/user destroy restart persistence, default MagicDNS suffix, custom MagicDNS base-domain, DNS extra-record projection and hot reload, disabled MagicDNS fallback, split DNS resolver routes, IPv6-only MagicDNS, explicit dual-stack/IPv4-to-dual-stack backfill/IPv4-to-dual-stack route-preservation restart/IPv4-to-dual-stack MagicDNS restart/IPv4-to-dual-stack SSH policy restart/family-removal backfill/IPv4-only/IPv6-only allocation, web-registration, web-registration tag ownership/rejection, route-advertisement, route-approval, primary-route selection/restart-owner preservation/failover/sticky/withdrawal, exit-node route-approval, web-registration route-approval, OIDC, OIDC restart, OIDC route-approval restart, same-user auth-key relogin, auth-key relogin route preservation, Taildrop CapMap disablement, randomize-client-port CapMap projection, private/native DERP relay, Rust-only native DERP WebSocket admissions, Rust-only native DERP policy-reload map stability, Rust-only native DERP restart reconnect, Tailscale SSH allow/deny/timeout, OIDC-backed SSH-check approval, checkPeriod cache, OIDC SSH policy mutation across server restart, plus CLI/wrong-user/expired/cancelled variants, SSH acceptEnv forwarding, SSH localpart/profile variants, web-registration restart, restart-persistence, tagged preauth, tag update/rejection, web reauth tag clearing, ACL peer visibility, empty ACL streaming visibility, autogroup:self peer isolation, route-via steering, route-via same-tag, route-via-health failover, route-via-health restart failover, route-via reload, route-via multiprefix, route-via multiprefix reload, route-via restart, route-via same-tag restart, route-via reload+restart, route-via multiprefix restart, route-via multiprefix reload+restart, route-health, route-health reload, route-health all-unhealthy, route-health all-unhealthy reload, route-health both-offline secondary reconnect, route-health restart, route-health primary-selection restart, route-health reload+restart, route-health all-unhealthy restart, route-health all-unhealthy reload+restart, route-health mixed-exit, route-health mixed-exit reload, route-health mixed-exit restart, route-health mixed-exit reload+restart, route-health mixed-exit all-unhealthy, route-health mixed-exit all-unhealthy reload, route-health mixed-exit all-unhealthy restart, and route-health mixed-exit all-unhealthy reload+restart stock-client scripts are checked into the real-client matrix, and the checked-in matrix now contains one hundred nineteen Postgres stock-client rows while push/PR CI provisions Postgres 16 for the process smoke and selected rows; broader stock-client/mutation smokes remain before full database parity |

| Stream | Scope | Primary files | Exit criteria |
| --- | --- | --- | --- |
| Control-plane topology | Add optional remote TCP gRPC serving with API-key auth, TLS/insecure config, reflection, and metrics/debug listener separation; keep the local Unix socket unauthenticated and permission-protected like upstream. | `headscale-cli/src/server.rs`, `headscale-cli/src/config.rs`, `headscale-cli/src/main.rs`, `headscale-api/src/grpc.rs`, `headscale-api/src/tailscale_wire/serve.rs` | Remote helper tests prove API-key-authenticated `Health` plus reflection, config parses upstream-shaped gRPC and metrics fields, local Unix health remains bearerless, production serving no longer mounts metrics/debug on the public control router, and migrated admin commands exercise upstream gRPC connection modes; still add broader production-process smokes. |
| CLI transport parity | Move admin commands from legacy HTTP wrappers toward upstream gRPC connection modes: Unix socket by default, remote address with API key/TLS/insecure, and upstream output/error snapshots. | `headscale-cli/src/admin/**`, `headscale-cli/tests/**`, `headscale-cli/src/config.rs` | CLI tests prove Unix-socket gRPC users, nodes, API-key, preauth-key, policy, health, debug-create-node, and mock OIDC commands against production-style services, remote TLS/API-key config success/auth-failure behavior, exact upstream node mutation success strings for expire, scheduled expiry, rename, tag, and backfillips, node route table snapshots, API-key proto JSON names, structured remote error envelopes, structured default/env/config Unix-socket failure snapshots, completion fish/powershell/zsh nested unknown-command snapshots, skip-config utility late-global-flag snapshots, rejected legacy `--json`, help-topic default-config warning snapshots, node selector conflicts, user selector failures including structured `nodes list --user` missing-value envelopes, invalid user profile URLs, invalid API-key/preauth-key durations, and expanded `serve` server-init validation snapshots before state startup. Remaining exit criteria are lower-priority utility stderr snapshots and broader process-level config/output tests while preserving Octra-only commands outside parity claims. |
| Runtime DNS and DERP config | Harden the loaded-config DNS/DERP runtime now that production maps use configured `DnsStore` and embedded DERP/STUN settings. | `headscale-cli/src/server.rs`, `headscale-cli/src/config.rs`, `headscale-api/src/dns.rs`, `headscale-api/src/tailscale_wire/**`, `tools/real-client/**` | Full map responses from production include configured DERP and MagicDNS, `override_local_dns` is honored in the tailcfg DNS shape, invalid initial `extra_records_path` files fail before serving, paired rows now cover split DNS, DNS resolver metadata, IPv6-only MagicDNS, production `extra_records_path` hot reload, current headscale-go-compatible empty CertDomains under HTTPS, and private DERP sidecar/STUN, including the production Postgres row, and route-health HA env overrides feed the validated runtime probe durations. No ACME public-CA drift exit criteria remain for this stream; live public-CA smoke coverage is treated as an externally networked release concern. |
| Embedded DERP/STUN | Harden the config-backed embedded DERP/STUN runtime: native STUN, DERP map generation, `derper` sidecar lifecycle, verify-client admission, TLS/server-url behavior, and native `/derp` relay parity. | `headscale-core/src/derp.rs`, `headscale-core/src/stun.rs`, `headscale-cli/src/server.rs`, `headscale-cli/src/config.rs`, `headscale-api/src/tailscale_wire/**`, `tools/real-client/**` | Paired `derp-private` and `postgres-derp-private` real-client rows pass against Rust and pinned headscale-go through the supported upstream `derper` sidecar with STUN and verify-client admission; clean-room native frame helpers, stream decoder, relay registry, NaCl-box client/server-info auth helpers, optional normal `Upgrade: DERP` route/runtime, persisted `privkey:<hex>` DERP key loading/generation, upstream-shaped `derp.server.enabled` projection to native relay mode, CLI `serve` native runtime mounting, true binary-message DERP-over-WebSocket transport, registry-backed native verify-client admission, raw-TLS `Derp-Fast-Start` no-response dispatch, scheduled keepalive frames, health/restarting control-frame broadcasts across raw DERP and WebSocket native transports, mixed raw/WebSocket multi-session shutdown broadcast counts and frame order, paired `postgres-derp-native` stock-client coverage, production duplicate-connection health announcements with clear frames, production server-shutdown health/restarting lifecycle announcements, Rust-only `postgres-derp-native-websocket` WebSocket admission coverage, and Rust-only `postgres-derp-native-reload`/`postgres-derp-native-restart` map-stability and reconnect coverage now exist. No active native DERP stock-client runtime blocker remains; headscale-go has no equivalent for Rust native relay shutdown health/restarting frames or native admission counters. |
| Lifecycle and route correctness | Preserve route approvals across reauth even when not currently advertised and tighten map-change batching/reason coverage. | `headscale-api/src/tailscale_wire/register.rs`, `headscale-api/src/tailscale_wire/routes.rs`, `headscale-api/src/tailscale_wire/map.rs`, `headscale-api/src/tailscale_wire/mod.rs`, `headscale-cli/src/server.rs` | Tests prove absent-route reauth keeps DB approvals, stale primary-route entries are removed when the old primary withdraws and all remaining candidates are unhealthy, expired/ephemeral nodes disappear from peers, stream-session online/offline state uses headscale-go's disconnect grace, production ephemeral GC uses per-node timers with persistent deletion, scheduled expiry wakeups preserve node rows while waking streams, canonical map-change reasons are bounded and target node churn, batched full-map rebuilds emit `PeersRemoved` when the final visible peer disappears, batched policy reloads that hide one of several visible peers emit only the removed peer plus updated policy/profile state, omitting unchanged DNS configuration, and streaming deltas match upstream-visible behavior. |
| CI, fuzz, and coverage gates | Enforce stronger parity in CI: `--all-targets` tests, selected real-client rows, stale-corpus checks, coverage thresholds, and an explicit formal-verification status. | `.github/workflows/**`, `scripts/**`, `headscale-core/fuzz/**`, `tools/real-client/**` | PR CI runs all-target tests, 10k fuzz plus stale-corpus check, pinned headscale-go differential/golden checks, the coverage floor, `scripts/check_real_client_ci.py`, and `scripts/check_formal_status.sh`. The DERP fuzz target now covers arbitrary parser input, raw frame encode/decode, typed frame round trips, split stream decoding, and coalesced frames. The separate real-client parity workflow validates selected smoke IDs and script paths immediately after checkout before toolchain/dependency/Postgres/Docker work, includes the current-head `ssh-accept-env`, `oidc-policy-churn`, `postgres-derp-private`, `postgres-derp-native`, `postgres-derp-native-websocket`, `postgres-derp-native-reload`, `postgres-derp-native-restart`, `postgres-ssh-accept-env`, `postgres-ssh-localpart`, `postgres-ssh-profile-variants`, `web-register-route-approve`, `web-register-tags`, `web-register-unowned-tag`, `ssh-oidc-check`, `ssh-cli-check`, `ssh-localpart`, `ssh-profile-variants`, `magicdns-custom-domain`, `dns-edge`, `dns-hot-reload`, `magicdns-ipv6-only`, `acl-empty`, `acl-autogroup-self`, `derp-private`, `tag-update-invalid`, `ssh-oidc-check-period-cache`, `ssh-oidc-policy-restart`, `route-via-same-tag-restart`, `route-via-multiprefix-reload-restart`, `route-health-reload-restart`, `route-health-mixed-exit-reload-restart`, and `route-health-mixed-exit-all-unhealthy-reload-restart` rows in push/PR smokes, runs selected Docker smokes on matching PRs, and runs the full paired matrix on schedule. Formal status is recorded as `target/formal-verification-status.json`; it passes with `status=absent` while `proofs/lean` is missing and becomes a `lake build`/no-`sorry` gate if the Lean workspace is restored. |

Recent coverage note (2026-06-02): the shared prefix-family backfill
real-client path now restarts the production server again after
`nodes backfillips`, then reasserts stock-client netmap family and database
node address family. This pins post-backfill persistent hydration for
IPv4-to-dual-stack and dual-stack-to-single-family migrations across the
paired SQLite and Postgres Rust/headscale-go wrappers. The paired `postgres-prefix-family-v4-to-dual-backfill-route-restart` row additionally keeps a pre-existing approved subnet route through the IPv4-to-dual-stack backfill and post-backfill production restart. The paired `postgres-prefix-family-v4-to-dual-backfill-magicdns-restart` row adds two MagicDNS-enabled peers and reasserts peer A/AAAA resolution after backfill and after the final production restart. The paired `postgres-prefix-family-v4-to-dual-backfill-ssh-policy-restart` row loads an SSH allow policy, verifies dual-stack peer-map addresses, and reasserts `tailscale ssh` allow behavior after backfill and after the final production restart; this closes `p1-production-backfill-restart-edges`.

Recent coverage note (2026-06-01): paired `postgres-route-health-all-unhealthy`
stock-client rows now cover the plain Postgres route-health all-unhealthy
fallback without a production restart. This closes the Postgres symmetry gap
between the no-restart `postgres-route-health`/`postgres-route-health-reload`
rows and the existing restart-only all-unhealthy rows, bringing the Postgres
stock-client matrix from sixty-two to sixty-three rows.

Recent coverage note (2026-06-02): focused `Stream:true` route-health coverage
now proves the all-unhealthy transition after a normal failover emits no stale
removal frame while fresh `/map` output retains the last-known primary route
owner and keeps the old unhealthy primary route-free.

Recent coverage note (2026-06-01): paired `postgres-route-health-mixed-exit`
stock-client rows now cover the plain Postgres mixed exit-node/subnet-router
route-health selection path without a production restart. This closes the
Postgres symmetry gap before the restart-only mixed-exit rows, bringing the
Postgres stock-client matrix to sixty-four rows.

Recent coverage note (2026-06-01): paired
`postgres-route-health-all-unhealthy-reload` stock-client rows now cover the
plain Postgres policy-reloaded all-unhealthy route-health retention path
without a production restart. This closes the no-restart reload symmetry gap
before the restart-only all-unhealthy reload row, bringing the Postgres
stock-client matrix to sixty-five rows.

Recent coverage note (2026-06-01): paired
`postgres-route-health-mixed-exit-reload` and
`postgres-route-health-mixed-exit-all-unhealthy-reload` stock-client rows now
cover the plain Postgres policy-reloaded mixed-exit route-health paths without
a production restart. This closes the no-restart reload symmetry gaps before
the restart-only mixed-exit reload rows, bringing the Postgres stock-client
matrix to sixty-seven rows.

Recent coverage note (2026-06-01): paired `postgres-acl-empty` and
`postgres-acl-autogroup-self` stock-client rows now cover the remaining
Postgres ACL empty-policy streaming edge and `autogroup:self` same-user
isolation cases, bringing the Postgres stock-client matrix to sixty-nine rows.

Recent coverage note (2026-06-01): paired `postgres-authkey-nonreusable` and
`postgres-authkey-expired` stock-client rows now cover production Postgres
one-time auth-key reuse rejection and expired auth-key registration rejection,
bringing the Postgres stock-client matrix to seventy-one rows.

Recent coverage note (2026-06-01): paired `postgres-route-via-health`
stock-client rows now cover production Postgres same-tag `grants[].via`
ownership following route-health failover for two observers, bringing the
Postgres stock-client matrix to seventy-two rows.

Recent coverage note (2026-06-02): paired `route-via-health-restart` and
`postgres-route-via-health-restart` stock-client rows now cover same-tag
`grants[].via` ownership following route-health failover after a same-URL
production restart, bringing the Postgres stock-client matrix to ninety-six
rows.

Recent coverage note (2026-06-02): paired
`route-via-health-reload-restart` and
`postgres-route-via-health-reload-restart` stock-client rows now cover same-tag
`grants[].via` ownership after route-health policy reload expands the approved
HA candidate set, the server restarts on the same URL, and stock clients
observe route ownership failover. The Postgres stock-client matrix now has one
hundred eight rows.

Recent coverage note (2026-06-02): paired
`route-edge-current-upstream-audit` matrix scripts now check the audited
current-head upstream pin and assert all thirty-one default
route-via/route-health rows have matching thirty-one Postgres mirrors with
checked-in Rust/headscale-go scripts. This is evidence-only because every
reload, restart, all-unhealthy, mixed-exit, same-tag, multiprefix, and
route-via-health symmetry row is already covered by live stock-client scripts;
future route work should add new upstream semantics rather than another mirror
row.

Recent coverage note (2026-06-02): `route-edge-current-upstream-audit` now also
asserts every default and Postgres route-via/route-health headscale-go mirror
sources `headscale-go-current.sh` and defaults `HEADSCALE_GO_VERSION` to the
audited current-head SHA, preventing current-head route rows from silently
falling back to the older pinned baseline.

Recent coverage note (2026-06-02): paired
`route-health-both-offline-reconnect` and
`postgres-route-health-both-offline-reconnect` stock-client rows now cover
`integration/route_test.go` `TestHASubnetRouterFailoverBothOffline` plus the
servertest `ha_secondary_recovers_after_all_offline` case. The scripts drive
both HA subnet routers offline, assert no primary route remains while both are
offline, reconnect only the secondary router, and assert the observer sees that
secondary router online with the route in `PrimaryRoutes`. This satisfies the
`p1-route-via-health-edge-coverage` backlog exit criteria.

Recent coverage note (2026-06-02): `policy-route-autogroup-internet-exit-visibility`
now lives in the default Go-vs-Rust differential scenario set. The promoted row
pins `autogroup:internet:*` ACL peer visibility for default-route exit nodes
alongside private subnet route auto-approval.

Recent coverage note (2026-06-01): paired `postgres-route-primary`,
`postgres-route-primary-failover`, `postgres-route-primary-sticky`, and
`postgres-route-primary-withdraw` stock-client rows now cover production
Postgres primary route owner selection, failover, sticky return, and withdrawal,
bringing the Postgres stock-client matrix to seventy-six rows.

Recent coverage note (2026-06-02): paired
`postgres-route-primary-restart` stock-client rows now cover production
Postgres primary route owner preservation across a real server restart,
bringing the Postgres stock-client matrix to ninety-five rows before the later route-via-health restart expansion.

Recent coverage note (2026-06-01): paired `postgres-ssh` stock-client rows now
cover production Postgres Tailscale SSH allow, policy denial, and packet-filter
timeout behavior over per-client users and database-backed policies, bringing
the Postgres stock-client matrix to seventy-seven rows.

Recent coverage note (2026-06-01): paired
`postgres-authkey-relogin-same-user` and
`postgres-authkey-relogin-route-preserve` stock-client rows now cover production
Postgres logout followed by same-user auth-key relogin, stable Tailscale IPs,
and approved-route preservation, bringing the Postgres stock-client matrix to
seventy-nine rows.

Recent coverage note (2026-06-01): paired `postgres-taildrop-capmap`
stock-client rows now cover production Postgres Taildrop disablement removing
the file-sharing capability from the stock-client self-node CapMap, bringing the
Postgres stock-client matrix to eighty rows.

Recent coverage note (2026-06-01): paired `postgres-ssh-accept-env`
stock-client rows now cover production Postgres Tailscale SSH `acceptEnv`
forwarding for accepted `LANG` and `LC_*` environment variables, bringing the
Postgres stock-client matrix to eighty-one rows.

Recent coverage note (2026-06-01): paired `postgres-ssh-localpart` and
`postgres-ssh-profile-variants` stock-client rows now cover production Postgres
current-head Tailscale SSH localpart login users from profile emails, profile
email variants, root-login denial, and denial status/stderr assertions, bringing
the Postgres stock-client matrix to eighty-three rows.

Recent coverage note (2026-06-02): paired `ssh-profile-variants` and
`postgres-ssh-profile-variants` stock-client rows now also cover
case-insensitive `localpart:*@EXAMPLE.COM` profile email domain matching
against both headscale-rs and headscale-go.

Recent coverage note (2026-06-02): paired
`postgres-ssh-profile-subdomain-deny` stock-client rows now cover production
Postgres current-head Tailscale SSH localpart profile email subdomain denial,
including denied status `255`, empty stdout, and the stable first stderr line.

Recent coverage note (2026-06-01): paired `postgres-derp-private` stock-client
rows now cover production Postgres private DERP through the supported upstream
`derper` sidecar, including configured DERP map metadata, STUN, and forced DERP
relay pings, bringing the Postgres stock-client matrix to eighty-four rows.
For Rust sidecar admission, `verify_client_url` is the headscale-style registry
verification path; `derper -verify-clients`/`verify_clients` verifies against a
local `tailscaled` and is not a registry-admission substitute.

Recent coverage note (2026-06-01): generic auth-request lifecycle handling now
waits on live non-registration auth IDs instead of treating them as missing
registrations, and OIDC registration callback/confirmation paths now reject
wrong-kind SSH-check auth IDs as bad registration sessions. The grpc-gateway
suite now pins advertised swagger route/method drift, and direct gRPC tests pin
exact node/tag/auth-request error messages.

Recent coverage note (2026-06-01): OIDC pending registration confirmations now
stage on the shared auth request entry for the wire, SQLite, and Postgres
registration handlers, so confirmation CSRF/user/device state follows the same
TTL/LRU lifecycle as the auth request instead of an independent runtime cache.

Recent coverage note (2026-06-01): auth-key, web/CLI `RegisterNode` /
`AuthRegister`, and OIDC registration completion now use auth-specific
live-registry map-change reasons. Same-key updates and rekeys emit
upstream-style `node added` unless owner/tag/IP/active approved-route identity
changes require a global `policy change`; SSH-check approval remains
verdict-only and explicitly map-change-free.

Recent coverage note (2026-06-01): SQLite runtime opening now applies
headscale-go's file-backed defaults for WAL, checkpointing, busy timeout,
incremental auto-vacuum, synchronous NORMAL, and foreign keys even when no
explicit `database.sqlite` block is configured. SQLite write transactions now
use `BEGIN IMMEDIATE`, matching upstream's `_txlock=immediate` write-lock
intent for the local DB mutation paths.

Recent coverage note (2026-06-01): paired `authkey-relogin-same-user`
stock-client rows now cover logout followed by fresh auth-key relogin as the
same user, asserting the existing node identity keeps its Tailscale IPs after
relogin against Rust and pinned headscale-go. The paired
`authkey-relogin-route-preserve` row extends the same lifecycle through
pre-relogin route advertisement/approval and asserts the logical node keeps its
approved route state after relogin.

Recent coverage note (2026-06-01): paired `taildrop-capmap` stock-client rows
now disable `taildrop.enabled` in Rust/headscale-go and assert the stock-client
self `CapMap` omits `https://tailscale.com/cap/file-sharing` through
`tailscale debug netmap`.

Recent coverage note (2026-06-01): production now configures a NodeStore
put/upsert/delete/bool-update/set-name/rekey/update-many write worker from
`tuning.node_store_batch_size` and `tuning.node_store_batch_timeout`;
concurrent writes block until their batch is committed, publish one COW snapshot
for the batch, perform set-name collision checks inside the writer batch, and
drive live `headscale_nodestore_queue_depth` metrics. Stream-offline
`last_seen`, policy auto-approval fan-out, and legacy ephemeral multi-delete
sweeps also run through the worker.

Recent coverage note (2026-06-01): `CreatePreAuthKey` now rejects requests with
neither an owner user nor ACL tags using the upstream `Unknown` gRPC status and
message, with grpc-gateway HTTP/status JSON coverage for the same edge.

Recent coverage note (2026-06-02): `grpc_gateway::parser_tests` now pins the
grpc-gateway status-to-HTTP mapping and response envelope for every tonic
status code, including the authenticated gateway's plain `401 Unauthorized`
body without `WWW-Authenticate`.

Recent coverage note (2026-06-01): parser-level CLI `auth register` /
`auth approve` / `auth reject` missing-flag errors and `users create`
missing-name errors now honor `-o/--output` structured stderr formatting for
JSON, JSON-line, and YAML while preserving current-upstream human `Error:`
output by default.

Recent coverage note (2026-06-01): streamed map responses now use a bounded
per-subscriber batch event queue for tick-published map changes, preserving
headscale-go-style ordered delivery when multiple batches publish before a
stream polls again while retaining full-map fallback on lag.

Recent coverage note (2026-06-01): tick-published full-map rebuilds now use the
previous stream peer snapshot to emit `PeersRemoved` when the rebuilt peer set
is empty, so clients drop the final stale peer after batch-delayed deletes.

Recent coverage note (2026-10-17): v0.29.5 policy map deltas now omit
unchanged `DNSConfig`; a node receives it when its own CapMap, hostname, OS,
address, or explicit targeted self refresh changes DNS inputs. Rust stream
regressions cover an unrelated policy edit followed by a NextDNS nodeAttrs
edit and a targeted self refresh carrying self plus DNS without a full peer
list. Pinned Go `TestDNSConfigOnlyWithSelfRefresh` and `TestNodeAttrsNextDNS`
pass. A per-stream SSH policy snapshot omits unchanged `SSHPolicy` on ACL-only
edits and sends an explicit empty policy on revocation; the Rust stream
regression and pinned Go `TestSSHPolicySentOnlyWhenChanged` pass. The paired
`postgres-nextdns-nodeattrs-policy-reload` production Postgres stock-client row
checks a live resolver switch from `base` to `profile`. Its MapResponse debug
dumps now also show the same frame sequence on Rust and pinned Go: an unrelated
policy response omits `DNSConfig`, then a self/DNS `change` response carries
the profile resolver before a policy response without `DNSConfig`. Rust now
splits these frames. Both paired runs passed in
`target/real-client/nextdns-policy-mapresponse-paired-matrix-final/`.
The pinned Go debug dump records `SSHPolicy` before its per-connection wire
deduplication, so paired production evidence for the wire-level SSH omission
remains open. Rust still sends `UserProfiles` on policy responses that pinned
Go's dump omits in this row; other Rust regressions need these profiles when
peer visibility or profile data changes. Full byte-for-byte stream
equivalence remains unqualified.

Recent coverage note (2026-06-01): the parity harness now compares
requester-specific runtime DNS projection for NextDNS/nodeAttrs. The
`wire-dns-nextdns-nodeattrs` scenario covers overlapping wildcard/user/tag
nodeAttrs, NextDNS profile selection, requester metadata, split DNS resolvers,
attacker-lookalike host preservation, and `nextdns:no-device-info`.

Recent coverage note (2026-06-01): `policy-v2-app-cap-grants` now
differentially covers `grants[].app` `CapGrant` output for
`tailscale.com/cap/drive` and `tailscale.com/cap/relay`, including upstream
nullable companion caps `drive-sharer` and `relay-target` after per-node packet
filter reduction. The checked golden now covers eighty-eight scenarios.

Recent coverage note (2026-06-02): process-level `serve` startup validation
snapshots now cover YAML output in addition to human, JSON, and JSON-line for
missing Noise private-key config and the SQLite-only unsupported-Postgres
runtime guard. This closes another residual server/output formatter edge in the
CLI parity stream. A follow-up process snapshot now covers current-upstream
`serve` unknown-flag stderr with `json`, `json-line`, `yaml`, and unknown-output
fallback formatting before server startup.

The v0.29.5 CLI sweep also found a Cobra help-topic distinction: `help
mockoidc`, `help completion`, and `help completion {bash,fish,powershell,zsh}`
include inherited Global Flags, while the corresponding direct `--help`
forms omit them. Rust now uses six pinned-Go output snapshots for those topic
forms, with process assertions for their stdout and config-warning stderr.

Recent coverage note (2026-06-02): map-stream churn coverage now proves
same-key auth completion records the upstream `node added` reason and wakes an
active observer `/map` stream with an incremental `PeersChanged` delta for the
reauthenticated node, without emitting DNS/config, peer-removal, or patch
payloads. Admin rename churn now mirrors headscale-go's self-map response path:
the renamed node receives a self `Node` update without peer, DNS, DERP,
user-profile, packet-filter, or SSH-policy payloads, while connected observers
receive the upstream `node added`/`PeersChanged` update with the renamed peer.
Direct admin expiry/logout churn now also follows upstream `SetNodeExpiry` by
emitting `node added` full peer updates; scheduled expiry scanning remains the
`key expiry` patch path.

Recent coverage note (2026-06-02): tagged existing-node register requests with
`Auth=nil` and Go zero `Expiry` now follow upstream's tailscaled restart path:
Rust returns the current tagged `RegisterResponse` identity and preserves nil
node-key expiry instead of treating the zero timestamp as logout. Focused
register coverage pins the edge against headscale-go
`TestTaggedNodeRestartPreservesNilExpiry`.

Recent coverage note (2026-06-02): runtime debug/config parity now covers the
upstream-shaped `derp:` projection, including embedded-region precedence,
operator URLs/paths, auto-update frequency, STUN/private-key/client-verification
settings, IPv4/IPv6 hints, and the serialized `DERPMap` exposed through the
runtime snapshot.

Recent coverage note (2026-06-02): route and STUN parity expanded again.
`set_approved_routes_many` now has map-stream coverage proving one batched
policy delta fans out to existing observers with all newly approved routes and
without a stale full-map follow-up. The STUN parser now matches Tailscale client
edge behavior for declared message lengths, padded unknown attributes before
`XOR-MAPPED-ADDRESS`, `MAPPED-ADDRESS` fallback, alternate XOR attribute
`0x8020`, and truncated binding-request drops.

Recent coverage note (2026-06-02): NodeStore update-many/delete same-batch
revalidation now suppresses stale policy-change churn when the only nodes
changed by `set_approved_routes_many` are deleted later in that worker batch.
Focused map-stream coverage proves observers receive only the delayed
`PeersRemoved` delta after the map-batcher tick.

Recent coverage note (2026-06-02): NodeStore upsert/delete same-batch
revalidation now suppresses stale node-added/node-updated churn when an
upsert-style write is followed by a delete for that same final-absent node in
the worker batch. Focused registry and `Stream:true` tests prove observers see
only the delayed `PeersRemoved` delta after the map-batcher tick.

Recent coverage note (2026-06-02): NodeStore auth-completion rekey/delete
coverage now also pins the opposite stale-delete ordering: when a reauth rekey
is batched with a delete of the old node-key index, the stale delete produces no
removal churn and observers receive only the delayed upstream `node added` /
`PeersChanged` delta for the reauthenticated node, without policy, config, patch,
or peer-removal payloads.

Recent coverage note (2026-06-02): `sshTests` unit coverage now pins the
current upstream empty-login-user edge: `accept: [""]` fails closed and renders
the attempted login user as `""` in the failed assertion body.

Recent coverage note (2026-06-02): CLI/debug parity tightened around two
upstream-only edges. gRPC `nodes expire`, `nodes tag`, and `nodes delete` now
reject positional node IDs before any connection attempt and require
`--identifier`, while `/debug/ping` lists connected nodes from the map-batcher
view even if their node expiry timestamp has passed.

Recent coverage note (2026-06-02): residual utility parser stderr coverage now
pins current-upstream `completion --no-descriptions`, `completion bash
--no-descriptions -- bad`, and `generate private-key --force -x` one-line
Cobra errors without adding any Octra-only CLI behavior to the parity ledger.
Follow-up snapshots now cover the same `--no-descriptions -- bad` separator
shape for `completion powershell` and `completion zsh`, completing that current
upstream shell-helper residual matrix beside the existing bash/fish cases. The
no-space unknown-flag form `--no-descriptions --bad` is now pinned for
`completion fish`, `completion powershell`, and `completion zsh` against the
same current-upstream CLI behavior.

Recent coverage note (2026-06-02): utility-command output-format parser
coverage now pins current-upstream headscale-go `171fd7a3` for
`health -o json --bad`, `health --output weird --bad`, `configtest -o json-line --bad`,
and `dumpConfig -oyaml --bad`, including structured JSON/JSON-line/YAML errors
and unknown-output fallback to human stderr.

Recent coverage note (2026-06-02): CLI process snapshots now pin
current-upstream headscale-go `171fd7a3` default-config warning stderr for
`headscale help <topic>` dispatch. The focused `help <topic> <extra>` and
unknown-topic tests normalize the timestamped `WRN no config file found, using
defaults` line, while direct `subcommand --help` aliases remain no-stderr like
upstream.

Recent coverage note (2026-06-02): remote gRPC health failure process snapshots
now pin current-upstream-style human, JSON, JSON-line, and YAML server-error
envelopes after successful TLS/API-key transport setup.

Recent coverage note (2026-06-02): live local-gRPC `auth approve` missing-session
process snapshots now pin current-upstream-style human, JSON, JSON-line, and YAML
not-found envelopes for valid-but-absent `hskey-authreq-` IDs.

Recent coverage note (2026-06-02): the `/debug/` index now mirrors tsweb's
runtime key/value rows more closely by including `Uptime`, `Version`, and
`Machine` before the headscale debug endpoint links.

Recent coverage note (2026-06-02): policy v2 `autogroup:danger-all` now matches
current headscale-go source-only semantics. HuJSON ACLs and non-via network
grants accept it as a source, ACL/grant destinations reject it with the
upstream-shaped destination error, canonical route overlap expands it to the
full IPv4/IPv6 default prefixes, and per-node packet-filter compilation emits
`SrcIPs: ["*"]` for direct ACLs and `grants[].via`.

Recent coverage note (2026-06-02): paired
`postgres-randomize-client-port` stock-client smokes now load
top-level `randomizeClientPort: true` against Rust and current headscale-go,
read `tailscale debug netmap`, and require the self `CapMap` to contain
`randomize-client-port`. The Postgres stock-client matrix now has ninety-one
rows.

Recent coverage note (2026-06-02): paired `postgres-derp-native` stock-client
smokes now run Rust production Postgres with native `server.embedded_derp`
relay mode through the shared real-client DERP assertions. The row proves
stock-client DERP-map metadata, STUN, forced-DERP relay pings, and clear
stock-client DERP status health without a Rust `derper` sidecar. The live row
also asserts `/debug/derp` native runtime counters: verify-client mode must be
enabled, raw admissions must include both stock clients, and raw/WebSocket
denials must remain zero. This brings the Postgres stock-client matrix to
ninety-two rows.

Recent coverage note (2026-06-02): Rust-only
`postgres-derp-native-restart` stock-client coverage now proves native Rust
embedded DERP survives a production Postgres server restart. The row asserts
STUN, DERP-map metadata, and forced-DERP relay pings before restart, restarts
the same Rust server URL, waits for both stock clients to reconnect, and reruns
the DERP assertions. The restart path now also snapshots each stock client's
DERP-map summary before shutdown and requires the post-reconnect summary to
match exactly, pinning native relay host, DERP/STUN ports, omitDefaultRegions,
and node metadata stability across reconnect. It also reads `tailscale status
--json` before and after restart and requires native duplicate/restart DERP
health to be cleared after relayed traffic settles. The headscale-go matrix
entry is an explicit no-equivalent skip because upstream embedded DERP does not
exercise headscale-rs native DERP shutdown health/restarting frames. The
Postgres stock-client matrix reached ninety-seven rows at this point; later
OIDC policy-churn restart coverage brought the matrix to ninety-eight rows,
subsequent native DERP reload coverage brought it to ninety-nine rows, and
web-registration policy-churn coverage brought it to one hundred rows, and
web-registration policy-churn restart coverage now brings it to one hundred one
rows.

Recent coverage note (2026-06-02): Rust-only
`postgres-derp-native-websocket` stock-client coverage now forces
DERP-over-WebSocket through the native Rust relay, asserts relayed traffic and
status health, and requires `/debug/derp` WebSocket verify-client admissions
with zero raw/WebSocket denials. This brings the Postgres stock-client matrix
to one hundred two rows and closes the native DERP stock-client runtime
breadth blocker.

Recent coverage note (2026-06-02): focused native DERP wire tests now run one
raw DERP session and one DERP-over-WebSocket session on a shared Rust runtime,
announce the server-shutdown lifecycle once, and assert two-session delivery
counts plus `Health` before `Restarting` frame order on both transports. This
broadens Rust-only native relay runtime coverage without changing production
behavior.

Recent coverage note (2026-06-02): paired `postgres-policy-churn` stock-client
smokes now run Rust/headscale-go production Postgres with two auth-key
registered clients, load a self-only database policy, assert zero visible
cross-user peers, mutate the stored policy with `policy set`, and assert live
peer maps converge to one visible peer per client. This brings the Postgres
stock-client matrix to ninety-three rows.

Recent coverage note (2026-06-02): paired `postgres-node-rename` stock-client
smokes now run Rust/headscale-go production Postgres with two auth-key
registered clients, rename the first node through the production admin CLI,
assert the renamed row through `nodes list`, require the observer's live
`tailscale debug netmap` to show the renamed peer, and keep the renamed node's
online/offline lifecycle assertions. This brings the Postgres stock-client
matrix to ninety-four rows.

Recent coverage note (2026-06-02): paired
`postgres-user-node-lifecycle-restart` stock-client smokes now run
Rust/headscale-go production Postgres with three auth-key clients, rename one
user, expire one node, delete another node, destroy the deleted node's user,
restart the server against the same Postgres database, and reassert the durable
user/node lifecycle state. The P0 production Postgres process-mutation backlog
remains open for policy, route, auth-session, config, and map-stream churn
breadth.

Recent coverage note (2026-06-02): subnet-router stream lifecycle now follows
current headscale-go's `NodeOnlineFor`/`NodeOfflineFor` branch. Approved
advertised non-exit subnet routers enqueue full map responses with
`subnet router online`/`subnet router offline` reasons, while ordinary peers
keep the patch-plus-policy lifecycle path. Focused registry and `Stream:true`
tests pin the queued full update and the emitted full `Node`/`Peers` response.

Recent coverage note (2026-06-02): the env-gated production Postgres `serve`
restart process smoke now mutates user, database-backed policy, node route, and
tag state through local gRPC/CLI, restarts the real server, and asserts the
same route/tag state through CLI output, `/debug/nodestore`,
`/debug/routes`, `/debug/policy-manager`, and `/debug/filter`. This gives one
focused process-level convergence check across the Pg DB rows, hydrated live
registry, loaded policy manager, and map-response inputs after restart.

Recent coverage note (2026-06-02):
`serve_postgres_runtime_live_admin_rename_updates_nodestore_smoke` now starts
the real env-gated production Postgres `serve` binary, creates and registers a
node through local gRPC/CLI against persistent Pg state, renames it while the
server stays live, and asserts both Pg-backed CLI JSON and `/debug/nodestore`
show the renamed node. This adds a focused live admin/map mutation row distinct
from the existing grpc-gateway/remote-gRPC topology and policy-file SIGHUP
smokes.

Recent coverage note (2026-06-02):
`serve_postgres_runtime_live_cli_policy_tag_updates_nodestore_smoke` now covers
a second live production Postgres registration/mutation path: local gRPC/CLI
registers a pending node, mutates database-backed policy to allow a tag, applies
that node tag while `serve` remains running, and polls `/debug/nodestore` until
the live registry exposes the new `forced_tags` state.

Recent coverage note (2026-06-02):
`serve_postgres_runtime_gateway_api_key_revocation_restart_smoke` now
starts the real env-gated production Postgres `serve` binary, creates a
secondary API key through the authenticated public grpc-gateway, proves that key
can authenticate public health, expires it through the bootstrap key, and asserts
the expired key is rejected immediately and after a production server restart.

Recent coverage note (2026-06-02):
`serve_postgres_runtime_gateway_preauth_key_restart_smoke` now covers a
different public grpc-gateway restart mutation path: the real env-gated
production Postgres `serve` process creates a user and tagged reusable/ephemeral
preauth key, restarts on the same Postgres database, verifies the hydrated
preauth-key owner/tag/reusable/ephemeral/unused metadata, and then expires and
deletes that key after restart.

Recent coverage note (2026-06-02):
`serve_postgres_runtime_gateway_user_rename_restart_smoke` now covers public
grpc-gateway user/node owner mutation across a production Postgres restart. The
real `serve` process creates and registers a node under Alice, renames Alice to
Bob through grpc-gateway, restarts on the same Postgres database, and verifies
CLI node listing plus `/debug/nodestore` hydrate the registered node with the
renamed owner.

Recent coverage note (2026-06-02): `configtest` now snapshots invalid
`server.https_listen` parsing, matching the already-covered `serve` startup
guard so explicit HTTPS listener mistakes are caught before runtime state is
opened.

Recent coverage note (2026-06-02): `configtest` now snapshots the upstream
top-level `derp.server.enabled=true` + `derp.server.stun_listen_addr=null`
fatal edge. Evidence: headscale-go `hscontrol/types/config.go` requires
`derp.server.stun_listen_addr` when the embedded DERP server is enabled at
lines 697-710, and Rust now pins the same process stderr in
`headscale-cli/tests/snapshots/configtest_derp_missing_stun_listen.stderr`.

Recent coverage note (2026-06-02): the pinned current-upstream v0.28
config-example fixture now carries the lower-frequency DERP server map/source
settings (`verify_clients`, `stun_listen_addr`, `private_key_path`, IPv4/IPv6
hints, DERP URL source, `auto_update_enabled`, and `update_frequency`) alongside
the existing HTTP-01 ACME fields. `headscale-cli/tests/cli_process.rs` now runs
that fixture through the real `headscale configtest` process to prove those
HTTPS/DERP runtime settings are accepted without public-CA issuance or
stock-client traffic.

Recent coverage note (2026-06-02): an env-gated production Postgres `serve`
process smoke now runs file-backed policy mode, registers a route-advertising
node, mutates `policy.path`, sends SIGHUP, and asserts the policy reload
auto-approves the advertised route through CLI node state and `/debug/routes`.
This adds a focused process-level config-mutation check without duplicating the
existing database-policy restart or grpc-gateway CRUD smokes.

Recent coverage note (2026-06-02): paired
`postgres-oidc-policy-churn-restart` stock-client smokes now run the production
Rust/headscale-go OIDC confirmation flow on temporary Postgres, register an
auth-key viewer plus OIDC peer under a file policy, reload the policy with
`SIGHUP` to expose the peer/profile, restart the production server, and assert
both clients reconnect with the viewer still seeing the OIDC peer/profile. The
row is wired through `tools/real-client/smoke-matrix.sh --check
postgres-oidc-policy-churn-restart --both` and selected by the bounded PR/push
real-client CI smoke set.

Recent coverage note (2026-06-02): the existing paired
`postgres-web-register-custom-domain` stock-client row is now selected by the
bounded PR/push real-client CI smoke set. It covers production Postgres no-auth
web registration with a custom MagicDNS base domain and validates the projected
DNS suffix against Rust and headscale-go.

Recent coverage note (2026-06-02): the existing paired
`postgres-ssh-profile-subdomain-deny` stock-client row is now selected by the
bounded PR/push real-client CI smoke set. It extends the required SSH profile
subdomain-deny edge into the production Postgres process path and asserts the
same policy-profile denial behavior against Rust and headscale-go.

Recent coverage note (2026-06-02): CI harness metadata now records formal
verification status through `scripts/check_formal_status.sh`. When
`proofs/lean` is absent the gate writes
`target/formal-verification-status.json` with `status=absent`; if the Lean
workspace is restored it fails on missing `lake`, missing `.lean` sources,
`sorry`/`admit` placeholders, or `lake build` failure instead of silently
skipping formal proof status.

Recent coverage note (2026-06-02): grpc-gateway auth approve/reject malformed
auth ID handling now has exact HTTP status JSON envelope coverage for missing,
bare, and short `hskey-authreq-` IDs. This pins the current-upstream split where
auth register reports malformed IDs as gRPC `Unknown` while approve/reject
return `InvalidArgument`.

Recent coverage note (2026-06-02): CI now checks that
`tools/real-client/headscale-go-current.sh` still matches upstream
`juanfont/headscale` `main`, and that the baseline script stays aligned with
`tools/parity/headscale-go/go.mod`. The real-client workflow now selects 153
deterministic PR rows, including the new paired
`postgres-web-register-policy-churn` row.

Recent coverage note (2026-06-02): paired
`postgres-web-register-policy-churn` stock-client smokes now run Rust and
headscale-go production Postgres web registration for Alice and Bob under
database-backed policy, mutate policy live, and assert maps converge from
isolated `0,0` peer visibility to `1,1`. The shared harness no longer hardcodes
web registration to `alice`, so multi-user web-auth rows can exercise the
configured per-client user.

Recent coverage note (2026-06-02): `policy-v2-taildrive-taildrop-caps`
coverage is now dual-stack and promoted into the default differential set. The
Go-vs-Rust golden asserts IPv4 and IPv6 source/destination preservation for
both direct `tailscale.com/cap/drive` grants and reverse
`tailscale.com/cap/drive-sharer` companion grants.

Recent coverage note (2026-06-02): lower-frequency runtime/config coverage now
includes a public-CA-shaped TLS-ALPN `serve` path with configured DERP
map/source settings. The deterministic process test forces a metrics bind
collision before ACME issuance and asserts no Let's Encrypt cache entry is
written.

Recent coverage note (2026-06-02): HTTP-01 now bootstraps public and remote
TLS listeners with in-memory material before ACME issuance, binds configured
listeners before contacting the issuer, and reloads public HTTPS plus remote
gRPC TLS after issuance writes the Go/autocert cache. Public-CA-shaped
no-network process coverage now proves HTTP-01 metrics, remote-gRPC, and
public-HTTPS bind failures plus TLS-ALPN public-HTTPS bind failure stop before
ACME cache/account writes. Actual live public-CA smoke remains an
externally-networked release concern rather than an open deterministic parity
gate.

Recent coverage note (2026-06-02): native DERP duplicate-health coverage now
pins reconnect behavior after a duplicate clear: when a same-node-key session
disconnect clears health for the remaining session, a later same-key reconnect
reissues duplicate health to both live sessions.

Recent coverage note (2026-06-02): native DERP post-admission cleanup now
unregisters raw and WebSocket relay sessions even when the server-info or
health replay write fails before entering the steady relay loop. A focused raw
DERP regression scripts that early write failure and asserts the relay session
registry is empty afterward.

Recent coverage note (2026-06-02): map-stream lifecycle/route batching now
covers an ordinary peer online event plus route approval before the batch tick.
The observer receives one incremental policy-style delta with the online peer
patch, route-bearing peer change, DNS config, and no full self map or extra
frame.

Recent coverage note (2026-06-02): the audited current-head integration backlog
is now represented end-to-end. Six worker agents covered the tags,
ACL/policy/grant-cap, route/DNS, CLI/API auth, SSH, and
auth/OIDC/general/DERP clusters; the refreshed current-head inventory reports
all 142 upstream integration tests as `present` with backlog count 0.
`current_head_go_parity_pending.rs` remains generated as a zero-pending
authorization guard, and the source inventory ignores that generated
file/prefix so pending stubs cannot falsely close backlog.

Recent coverage note (2026-06-02): same-machine reauth now preserves stable
node/user IDs for auth-key and web/OIDC completion paths, preventing map peer
ID churn relative to headscale-go. Additional breadth coverage pins native DERP
health replay before keepalive, `auth reject --output=yaml` missing
`--auth-id`, and TLS-ALPN explicit `server.https_listen` pre-issuance bind
failure. The real-client PR matrix now selects 166 deterministic rows,
including `postgres-policy-rename-restart`,
`postgres-web-register-policy-churn-restart`, and
`postgres-web-register-policy-config-map-churn-restart`.

Recent coverage note (2026-06-02): focused exact-name Rust evidence was added
for the former tags, ACL, route/DNS, CLI/API auth, SSH, auth/OIDC/lifecycle,
network retry, DERP verify, and native DERP backlog rows. Companion cap grants
now expand range-style source IP sets to CIDRs so current-head cap-grant
companions are not dropped when upstream policies aggregate source ranges.

Recent coverage note (2026-06-02): additional subagent edge coverage now pins
config-file `unix_socket` CLI connection wrapping, real tonic transport auth
gRPC status/message envelopes, the current-head multi-address
SSH/DNS/route-policy fixture's SSH principals plus `acceptEnv`, and raw native
DERP packet relay followed by `PeerGone(Disconnected)` on source drop.

Recent coverage note (2026-06-02): the next parity edge batch now pins tagged
auth-key `/map` identity/expiry shape, native DERP mixed WebSocket/raw packet
relay plus source-disconnect `PeerGone`, remote TLS gRPC `auth approve`
missing-session CLI errors, and real `headscale serve` projection for
upstream-shaped `derp.server` config with explicit self-signed HTTPS. The PR
real-client set now includes `postgres-web-register-policy-churn-restart` and
`postgres-web-register-policy-config-map-churn-restart`.

Recent coverage note (2026-06-02): paired
`postgres-web-register-policy-config-map-churn-restart` stock-client smokes now
run Rust/headscale-go production Postgres web-registration through an
auth-session registration flow, an isolating file policy, a policy reload that
opens Alice/Bob peer visibility, custom MagicDNS suffix assertions, peer
MagicDNS `tailscale debug resolve` assertions, and same-URL server restart.
This extends P0 policy/auth-session/config map-churn evidence but leaves the
P0 backlog row open for live execution and broader production-process
route/API-auth/session/lifecycle mutation breadth.

Recent coverage note (2026-06-02): `policy-v2-tailscale-compat-fixtures`
adds a representative pinned Tailscale compatibility slice for ACLs, wildcard
app grants, subnet routes, auto-approvers, `grants[].via`, and SSH
accept/check rules. `policy-v2-current-compat-fixture-batch` adds a second
upstream-current slice for `autogroup:tagged`, TCP/UDP/ICMP policy rules,
accepted `tests` host/IP-literal/bracketed-IPv6 destinations, `nodeAttrs`
targeting wildcard/tags/groups, app-only grants, app+IP grants, `grants[].via`,
and `sshTests` tag/host-alias/self/localpart/nonroot variants. The pinned golden
now covers 94 scenarios.

Recent coverage note (2026-06-02): `policy-v2-compat-fixture-batch-2`
adds a third pinned compatibility slice covering nodeAttrs host-alias targets,
operator capability strings with query parameters, merged NextDNS attrs,
`autogroup:tagged` attrs, grouped tag owners, policy tests with protocol/port
denials, `autoApprovers.exitNode`, broader-CIDR `grants[].via`, app+IP grants,
app-only grants, SSH accept/check overlap ordering, SSH host-alias tests, and
nonroot SSH users. `policy-v2-nodeattrs-ippool-unsupported` pins the current
headscale-go rejection for parsed-but-unimplemented `nodeAttrs[].ipPool`. The
pinned golden now covers 96 scenarios; broader upstream ACL/grants/nodeAttrs/
routes/policyTest/sshTest fixture auditing remains open before closing the
policy v2 backlog row.

Recent coverage note (2026-06-02): `policy-v2-compat-fixture-batch-3`
adds a fourth pinned compatibility slice after auditing upstream
`hscontrol/policy/v2/*compat*` at `171fd7a3c54156965753a63639cdcafcd50c8d67`
(215 ACL, 266 grant, 56 nodeAttrs, 125 route, 108 SSH, 57 policyTest, and 37
sshTest captures). The batch covers policy tester mixed ACL/grant tests,
duplicate accepted test entries, bracketed IPv6 literal grant destinations,
numeric TCP `tests[].proto`, SSH tester accept/check/deny/localpart assertions,
wildcard/unknown/suggest-exit `nodeAttrs`, and `autogroup:member` excluding
tagged nodes. Rust now accepts and canonicalizes numeric TCP `tests[].proto`
like headscale-go. The pinned golden now covers 97 scenarios; the P1 row
remains open because the full 864-capture upstream corpus is not exhausted.

Recent coverage note (2026-06-02): `policy-v2-compat-fixture-batch-4`
adds another upstream-backed nodeAttrs compatibility slice for CIDR-prefix
targets, host-alias targets, group targets, and duplicate capability
deduplication. The pinned golden now covers 98 scenarios; the P1 row remains
open for broader ACL/grants/nodeAttrs/routes/policyTest/sshTest capture
coverage.

Recent coverage note (2026-10-17): the pinned v0.29.5 capture converter now
records SHA-256 and API response code for all 875 ACL, grant, nodeAttrs, route,
SSH, policy-test, and SSH-test captures. The independent Go/Rust policy-load and
differential-output audit has 766 matching outputs and 109 policies rejected by
both engines, with no output mismatch or one-sided rejection. Of the 733
upstream API-accepted captures, 725 match and eight unsupported nodeAttrs
policies are rejected by both headscale-go and Rust. Of 141 upstream API-400
captures, 41 load and match under both engines while 100 are rejected by both;
the one API-500 capture is rejected by both. This measures parity with the
pinned headscale-go implementation, not agreement with every SaaS verdict.
The differential audit also compares Go and Rust policy/SSH test pass/fail
verdicts for the 59 policies containing `tests` and 37 containing `sshTests`.
This closes the pinned-Go P1 fixture-audit row. Exact rejection text and SaaS
API verdicts are separate from the headscale-go replacement claim. Run `CAPTURE_AUDIT=1
./scripts/headscale_go_capture_diff.sh` to reproduce the report under
`target/parity/capture-audit.json`.

Recent coverage note (2026-10-17): the paired pinned-Go v0.29.5/Rust
five-stage TS2021 tagged registration row now has exact CLI node JSON field
shape on both SQLite and Postgres. Its audit compares initial tagged auth,
same-key reauth, new-key retag, interactive tag re-advertisement, and
interactive untagging; both `go_only` and `rust_only` are empty at every stage
in `target/real-client/noise-tagged-retag-1792228600-31959` and
`target/real-client/noise-tagged-retag-1792228654-32180`. Rust now keeps
fractional node and preauth-key timestamps through database reads/writes and
gRPC, uses the precise user creation time already stored, and transmits
fractional preauth expiry from its CLI. Full timestamp value equality is not
asserted because the separate processes mint at different instants. Fresh
Rust SQLite and Postgres direct restarts under pinned Go also passed in
`target/real-client/sqlite-v0295-fresh-rust-to-go-1792228674-32322` and
`target/real-client/postgres-v0295-fresh-rust-to-go-1792228684-32436`.
Pinned Go also restarted directly on the Rust SQLite database from the
five-stage tagged-client run, with its registered node and fractional
timestamps, in `target/real-client/sqlite-v0295-rust-to-go-export-1792228732-33006`.
The selected output-shape row does not close broader CLI or release/database
qualification.

Recent coverage note (2026-10-17): the same paired pinned-Go/Rust TS2021
row now schedules a node expiry at `2100-01-01T00:00:00.123456789Z`,
checks the production CLI projection, restarts each server, and checks the
stored value again. Both SQLite runs retain 123456789 nanoseconds before and
after restart. Both Postgres runs expose 123456789 while the live node store is
active and 123456000 after restart, reflecting Postgres microsecond storage.
All seven CLI node JSON shape stages have empty `go_only` and `rust_only`
sets in `target/real-client/noise-tagged-retag-1792229363-38755` (SQLite)
and `target/real-client/noise-tagged-retag-1792229326-37754` (Postgres).
Pinned Go directly reopened the Rust SQLite database from that row and read
the exact fractional expiry in
`target/real-client/sqlite-v0295-rust-to-go-export-1792229394-38909`.
A separate Rust → Go v0.29.5 → Rust Postgres process switch kept the
microsecond-stored expiry, approved route, API keys, and Go-side rename
mutations in
`target/real-client/postgres-v0295-fresh-rust-to-go-1792229419-39025`.
That process row now also covers bidirectional registration, routes, and key
mutations through a final Go restart. Go creates a second CLI-registered node
with an approved subnet route and a preauth key, and withdraws the original
node's route. Rust reopens the same database, verifies both nodes and keys,
expires the Go-created preauth key, and reapproves the original route. Pinned
Go then reopens it again, sees the expired key and both approved routes, and
authenticates API keys minted on each side. The passing artifact is
`target/real-client/postgres-v0295-fresh-rust-to-go-1792230211-42731`.
The synthetic CLI registration and selected rows do not qualify all live
registration, auth-session, route, or historical upgrade combinations.
The two P0 breadth gates and broader CLI output gate remain open.

Recent coverage note (2026-10-17): `tools/real-client/extra-records-shutdown-smoke.py`
starts pinned Go v0.29.5 and Rust production servers with a file-backed DNS
extra record, deletes the watched file after `/health` succeeds, checks health
again, and sends SIGTERM. Both implementations exited with code 0 within the
eight-second bound on SQLite and Postgres. The paired process artifacts are
`target/real-client/extra-records-shutdown-1792229841-41233` (SQLite) and
`target/real-client/extra-records-shutdown-1792229860-41288` (Postgres).
The Rust cases wait for the watcher to log that it observed the missing file
before shutdown; the Go cases allow its fsnotify removal handler to run.
This covers the v0.29.4 watched-file removal shutdown path; live client DNS
behavior after file deletion and the remaining release breadth are unqualified.

Recent CLI coverage note (2026-10-17):
`tools/real-client/cli-parser-tree-diff.py` enumerates the pinned Go CLI
command tree and compares each direct `--help` page, each `help` topic, and
unknown-flag errors in human, JSON, JSON-line, and YAML forms with output
flags both before and after the error. All 47 command paths and 422 paired
process comparisons matched in
`target/real-client/cli-parser-tree-diff-1792230998-51907/report.json`.
Rust now uses the output format already parsed when an unknown flag occurs,
matches the top-level Cobra path when a later value is treated as an unknown
command, and distinguishes `help version` from `version --help`. Pinned-Go
snapshots pin the root and mock-OIDC error envelopes. This covers help and
parser errors; successful admin command values and the remaining config/error
matrix still need their own qualification.

Recent config coverage note (2026-10-17):
`tools/real-client/configtest-v0295-diff.py` compares 30 pinned-Go v0.29.5
and Rust `configtest` exit codes, stdout, and stderr with isolated fixture
directories, normalizing only log timestamps. A top-level upstream config without either node prefix now fails
at both `configtest` and `serve` with Go's exact error. Malformed prefixes now
use Go's `netip.ParsePrefix` error text for absent slashes, malformed addresses
and bit lengths, and out-of-range lengths. The process snapshots cover the
missing-prefix and malformed-prefix errors. The latest run is
`target/real-client/configtest-v0295-diff-1792232690-74510/report.json`:
29 outputs match and one differs. Rust now lets `configtest` accept invalid
HTTP, metrics, and gRPC listener syntax like Go, while `serve` still validates
it before opening runtime state. Rust now matches Go's acceptance of an
unknown policy mode and of the deprecated top-level ephemeral timeout, with
the same warning and the exact lower-bound error for the new timeout key.
Invalid database type and missing MagicDNS base domain now exit through Go's
fatal log envelope. A paired live process row for the unknown policy mode
starts both servers, checks health, key/database creation, admin get/set
errors, and clean shutdown in
`target/real-client/policy-unknown-mode-1792232773-75263/report.json`.
The remaining output difference is invalid log-level startup logging. Go's
successful `configtest` also creates a Noise key and opens the database;
Rust now does both for SQLite and default-build Postgres. This corpus does not
qualify full configtest process equivalence or all configuration fields.

A fresh pinned-Go v0.29.5/Rust Postgres schema audit found that Rust had no Go
`migrations` ledger and used different defaults for `database_versions.id` and
`pre_auth_keys.reusable`. Rust now writes the 19 IDs in the fresh Go ledger
after its SQLx foundation, adds the ID sequence, and aligns the reusable
default. Imported Go ledgers retain their history. The paired
`tools/real-client/configtest-postgres-v0295-smoke.py` gate confirms matching
application column and migration-ID sets before direct Go reopen and no schema
changes after it; see
`target/real-client/configtest-postgres-v0295-1792235510-13248/report.json`.
The Postgres foundation integration suite passed all 14 cases, including an
older imported schema without a `reusable` column. Extra Rust indexes remain
in its schema; wider mutation/restart qualification remains open.

A paired production Postgres stock-client row now covers the v0.29.5
`autogroup:self` filter update after a user rename. Under a group policy
containing `u1@` and `u3@`, the second client starts as `x3` with no packet
filter, then receives the exact self-only rule after `users rename x3 u3` and
retains it across server restart. Pinned Go and Rust produced the same
`PacketFilterRules` at all three checkpoints in
`target/real-client/postgres-self-filter-user-rename-headscale-go-smoke/hs-online-lastseen-headscale-go-postgres-authkey-1792237973-51856`
and
`target/real-client/postgres-self-filter-user-rename-smoke/hs-online-lastseen-rust-postgres-authkey-1792237935-51113`.
Rust refreshes live node identities and publishes a policy map change when the
admin rename commits. Broader release and Postgres mutation coverage remains
open.

## Next Implementation Order

1. Broaden production Postgres process-level serve/mutation smokes beyond the
   CI-backed paired stock-client matrix and the grpc-gateway/remote-gRPC admin
   topology smoke, especially additional registration/config mutation rows
   beyond the now-PR-gated web-registration policy/config map-churn restart,
   custom-domain web-registration, focused API-key/preauth-key process restart,
   gateway user-rename/node-owner restart, and stock-client user/node lifecycle
   restart cases, especially route, API-auth/session, and wider lifecycle
   mutations, before
   claiming full database parity.
2. Continue CLI transport parity on top of the users/nodes/API-key/preauth/policy
   gRPC slice: add current-upstream byte-for-byte output/error snapshots for
   the remaining live-server cases and residual output drift; table-driven
   direct gRPC, grpc-gateway, and remote CLI auth/server error-text coverage is
   now pinned.
3. Keep paired stock-client route coverage tracking current upstream route-via
   and route-health behavior; `route-edge-current-upstream-audit` now guards
   the checked-in default/Postgres reload, restart, mixed-exit, all-unhealthy,
   and route-via symmetry set plus current-head headscale-go script pinning, so
   remaining work is new edge semantics rather than row mirroring.
4. Finish config-runtime gaps: HTTP-01/TLS-ALPN now have production-listener
   controlled-CA process coverage plus public-CA-shaped no-network bind-failure
   coverage before ACME cache/account writes. Runtime `derp.server` projection
   plus explicit self-signed HTTPS serve health are pinned; continue with
   remaining non-ACME config combinations.
5. Broaden production-process restart smokes for web/CLI/OIDC policy and
   map churn beyond the auth-key restart-persistence, OIDC route-approval,
   web/CLI restart, default web-registration route-approval, Postgres web
   registration policy-churn, and Postgres OIDC policy-churn restart rows.
6. Finish native Rust DERP relay parity beyond the supported upstream
   `derper` sidecar boundary: broader stock-client restart/runtime assertions
   after keepalive, WebSocket-forced stock-client traffic, mixed-transport
   packet relay, duplicate reconnect, and source-disconnect `PeerGone` cases
   beyond the focused status-health, raw admission counter, duplicate-health
   reconnect, and restart map-stability pins are wired.
7. Extend CI/fuzz/golden enforcement: broaden selected real-client rows on PRs,
   scheduled full matrix, current-head pin checks, and parity golden diffs. The
   formal-verification status gate is now explicit and records the current
   Lean-workspace absence until proofs are restored.

### 2026-10-17 paired route approval and LastSeen evidence

`tools/real-client/smoke-matrix.sh postgres-route-approve` passed both Rust
and pinned headscale-go v0.29.5 process rows (exit 0 for each; see
`target/real-client/smoke-matrix-summary.tsv`). The stock router's own netmap
omits the route from `AllowedIPs`/`PrimaryRoutes` before approval, includes it
after approval, and retains it after server restart. Both rows also assert
admin approved/available routes and online/LastSeen transitions. The Rust
Postgres admin projection now reads the live registry's precise LastSeen when
available, and stream disconnect persists that timestamp at database precision
without a policy refresh; both rows check it remains stable after a second
server restart while the client is offline. This result qualifies
that named row; it does not close the broader production Postgres P0 gate.

## 2026-10-18 grouped remaining-work audit implementation

All ten audit batches now have source changes from parallel file ownership.
**13 findings have selected source implementations; four remain partial**:

| Finding | Source work remaining or narrower boundary |
|---|---|
| F07 | Non-Linux filesystem-event latency; Linux events and all-platform content recovery are implemented. |
| F12 | Wide DERP integers/nil node representation, lower fetch transport and YAML diagnostic corners. |
| F14 | HeaderMap distinct-name ceiling below Go's byte-budget domain. |
| F17 | Gateway/HTTP01 request events, ordinary spawned upgrade completion, physical-write counts, initial account pre-request URI failures and raw diagnostic rendering. |

Registration precedence/Followup, OIDC identity/mailbox/username/callback query,
DNS receivers/resolvers/NextDNS, strict issuer validation and both H1 ownership
findings have source implementations. DERP loading, request/startup/ACME events
and the native header profile have the bounded improvements above. CI filters
cover all vendors; a new provenance script records source, binary, toolchain
and report inventory. Per-row execution receipts remain a separate evidence
requirement. Optional admin cookie-authenticated JSON mutations now require the
existing session-bound CSRF token in `x-csrf-token`.

Independent source reviews corrected DERP duplicate-slice retention, a missing
Noise middleware argument and Unicode zones in log-only proxy addresses.
Public signatures/fields remain compatible; the API wire-only dependency
boundary and deprecated core source are unchanged. Original licenses/notices
and local source hashes are retained in package provenance.

**No tests, builds, Cargo commands, validators, probes or fresh advisory scans
ran. All three acceptance gates remain open.** The audit's six scope decisions and
Q1–Q6 qualification matrix still apply. Historical evidence predates these
changes. The original findings and source snapshot below describe the audit
baseline; they are retained for traceability, not current unresolved-code counts.

## Parallel follow-up to the partial findings — 2026-10-18

The native DERP path now owns a complete signed64/null model independently of
public compatibility structs. JSON/YAML and embedded configuration, startup,
refresh, map frames, bootstrap DNS, debug maps/config and counts retain that
owner. Bootstrap/debug null dereferences return the selected Go recoverer status
without a Rust panic. Native URL fetches now use the existing Go-profile
transport with total body timeout/Close and actual-protocol User-Agent.

DNS event wakeups now cover Linux and nix-supported BSD/Apple targets; remaining
platforms retain content polling. Merged main-listener request logging and
spawned Noise/DERP upgrade lifetimes now share one event owner. ACME observation
also covers parsed URI rejection before backend construction. Independent
source peers reviewed these changes; no execution was performed.

The remaining header-capacity fix is prepared as an exact http1.4.0 source patch
at `tools/parity/patches/http-1.4.0-native-header-capacity.patch`. Applying it needs
a local dependency source override and Cargo.lock source change. That action is
pending the existing user question about the no-resolution-change constraint;
**the patch is not applied and the current HeaderMap limit remains**.

Other residuals include unsupported event platforms, YAML/backend/error text,
successful-write versus body-poll byte counts, physical I/O and cancellation
phases, and S01–S06/Q1–Q6. Public narrow projection helpers are compatibility
views, not native identity storage. Tests/builds remain paused, no dependency
version/resolution changes were made, and all three acceptance gates stay open.

