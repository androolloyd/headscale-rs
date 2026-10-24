# Security and deployment audit — 2026-10-17

This is a source and dependency review of the current checkout, not a
penetration test or a production readiness certificate. The replacement
parity backlog still has two P0 items and one P2 item open.

## Implementation after the last validated snapshot

A subsequent implementation-only pass was requested with **no further testing**.
No builds, lint checks or executable tests were run for this batch. The earlier
passing reports later in this document predate these changes.

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
Unicode/grapheme/locale behavior remains separate from the existing Rust width
library and still requires implementation/qualification where it differs.

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

The serving policy runtime now owns an opaque filter form alongside public typed
rules. Prepared App payload JSON and literal-app whitespace survive private
compilation/reduction, raw global comparison and per-node caching. Retained
payloads must project to the supplied typed values; mismatched trusted doc/raw
inputs fall back to typed encoding. The private raw strings are never published
as public policy/wire values.

Owned filter snapshots bind typed rules and raw payloads under one policy read
lock. Per-node cache entries publish an atomic typed/raw pair from one recipient
view; concurrent misses cannot combine different quiet views. Immutable raw
filters use Arc ownership across snapshots. Full, non-stream, incremental and rebuilt responses serialize that snapshot
through framing/compression, preserving payload numeric/string spelling and
object order with Go compact/HTML escaping. Debug dump writes use the same
snapshot and Go-style indentation. Cache invalidation and partial-failure phases
include the opaque form. No dependency release, public field type or wire-only
DB/core boundary changed; existing Go/Tailscale/Headscale notices were extended.

Typed input number-range/depth limits remain incomplete, and debug readback and
direct public serializers still use their typed projection. Full raw-policy hash/
variant whitespace, nil/scalar/error ordering, root byte order, eager resources,
native association/zero/zoned/wide values and concurrency remain unqualified.
Direct rustfmt only; no build/test/validator/probe/advisory refresh or package/
container/client/process/restart evidence ran. All three gates remain open.

### Policy JSON v2 decoding — 2026-10-18

An ordered iterative policy pass now rejects duplicate retained members before
Serde maps lose them, including known schema aliases and opaque App payloads.
Metadata stripping precedes those checks; removed # members do not contribute
duplicates. JSON-pointer context and pointer truncation follow the pinned JSON
experiment source. Struct-name matching ignores dashes/underscores and handles
the Unicode folds entering ASCII schema names. Actual map keys remain exact.

The preceding case-folded App metadata exemption was corrected: pinned Go
exempts the literal key app only. Typed parsing and App-shape extraction now use
the same prepared input. Supported null containers, null/missing nodeAttrs
targets and empty/null nodeAttrs entries use existing empty typed containers.
Nil ACL/grant slices retain the allow-all default, distinct from explicit []
deny-all slices. Custom scalar null rules remain separate.

Comment standardization now preserves token separation and newlines, handles
trailing commas followed by comments and retains unterminated block comments
as errors. Original Go JSON experiment BSD terms/notices accompany the shared
decoder in ACL/API/CLI packages. No dependency release, public wire/policy field
type or wire-only DB/core boundary changed.

This supersedes corresponding decoder gaps and earlier policy JSON v1 reuse
wording. Raw opaque payload bytes/numbers/depth, remaining scalar/custom null
rules, error precedence, full nil hashing, native association/zero/zoned/wide
state, eager resources and concurrency remain incomplete or unqualified. Direct
rustfmt only; no build, test, validator, probe, advisory refresh or native/wire-
only/package/container/client/process/restart evidence ran. All gates remain open.

### Volatile refresh errors and raw App shape — 2026-10-18

Checked policy refresh now reaches built-in volatile admin create/rename/tags/
routes/batches and interactive/auth-key registration. Late policy failure is
distinct from rejected input and returns before success dispatch or cached auth
completion. The ephemeral sweep reports refresh failure after retaining its
deletion/address/connection cleanup. Legacy bool/static-error entry points keep
their signatures and log errors; serving adapters use checked variants.

Grant App decoding now accepts null maps and null capability slices. Private
shape metadata records map nilness and nil keys independently of the public
map-of-vectors type. Global/per-node/unreduced filters, bound caches and unbound
recipient compilation retain this metadata. Explicit empty App on an IP grant
can emit a capability rule; nil App cannot. Per-capability null and [] remain
distinct wire values. Empty App alone still fails Go's nonempty ip-or-app check.
Case-folded App metadata stripping preserves its opaque payload. No dependency
release or public wire/policy field type changed; wire-only remains free of a
DB/core backedge. The public canonical hash remains a typed projection and
does not encode this private raw-shape metadata.

This supersedes the corresponding built-in volatile/empty-App/nil-capability
source gaps. Opaque JSON byte fidelity, complete typed nil/duplicate/backing-array
representation, native loaded associations/zero/zoned/wide values, raw/custom/
misbound/external writers, exact errors/logs/hash/change counts, eager resources
and concurrency/cancellation remain incomplete or unqualified. Direct rustfmt
only; no build, test, validator, probe, advisory refresh or package/container/
client/process/restart evidence ran. All three release gates remain open.

### Partial alias results and refresh failures — 2026-10-18

A shared private resolver now separates an optional usable IP set from its
errors. Empty non-nil aliases, partial identity sets, ambiguous accounts and
invalid native addresses retain different outcomes. Packet filters/SSH/tag/
approvers retain partial sets; capability/via destinations skip errored aliases;
nodeAttrs rejects target errors. Zoned addresses are stripped during set
insertion and rejected at membership lookup. Self-grant admission preserves
resolved-empty aliases, and capability destinations retain empty non-nil sets.

SetUsers' overly broad prevalidation was removed: the global user-reference
check belongs to policy installation. User refresh now clears caches before
compiling and restores its directory on failure without reverting prior global
filter/approver phases. SSH/direct-user tag fallback sees that restored directory.
Rejected policy replacement recompiles its previous document; failed SetNodes
retains its new input list. Pre-refresh cache invalidation follows the global
network versus affected raw-owner branches, including zero-owner tagged entries.
NodeAttrs errors retain its prior CapMap and pending-diff union.

Checked native startup, saved-row/admin changes, registration/OIDC/auth-key,
auto-approval, map, expiry and deletion paths propagate refresh errors before
success dispatch. Policy errors have gRPC Unknown/HTTP 500 adapters; earlier
SQL/live changes retain their existing failure contract. Legacy public bool/log
wrappers and remaining volatile/static-error/custom boundaries still need full
propagation. Go4 notices, original BSD terms and pinned source hashes were added
to API/CLI packaging; no dependency version or public wire field changed.

These are source-only additions. Exact Go4 error stack traces, all partial-phase
order, empty App/CapMap/nil/duplicate policy shapes, eager-compiler resources,
native association/zero/zoned/wide values, cancellation/concurrency and native/
wire-only/package/container/client/process/restart behavior remain incomplete
or unqualified. Direct rustfmt only; no build/test/validator/probe or fresh
advisory evidence ran. All three parity gates remain open.

### User refresh results and eager tag owners — 2026-10-18

Policy refresh now reports policy and peer-map changes separately from sorted
account facts. Native rename/OIDC skip broad broadcasts when those facts and
resolved effects did not change; SSH/per-node policies still force refresh for
changed facts. Creation forces PolicyChange, and deletion chooses PolicyChange
or UserRemoved. Cached live node profiles retain Go UpdateUser's prior projection.
Node-attribute self-refreshes retain a separate drain even without a broad event.

Nested tag topology is preflighted before replacement. Cyclic back edges drop
without losing the other owners, and undefined tags return quoted errors through
fallible native startup/RPC/reload/admin paths. Eager tag/route/exit IP maps now
use canonical span equality, and bound tag checks retain the direct-user fallback.
Configured-empty versus nil exit sets stay distinct. Legacy infallible setters
log rejection without replacing the active source. Static topology/directory
rejection preserves that source and directory; this does not qualify all dynamic
resolver failures or Go's partially updated runtime/error restoration ordering.

The shared ACL leaf now carries pinned Go 1.26.9 Unicode 15.0.0 simple-fold
tables. SSH localpart domains and JSON field-name equality use them at UTF-8
boundaries. No dependency version, public wire field or wire-only DB/core
boundary changed. Go/BSD notices accompany the new source.

This supersedes the preceding user-result/eager-tag/ASCII-localpart source gaps.
Dynamic failures, parsed nil/duplicate policy shapes, eager compilation resources,
native association/zero/zoned/wide values, hash/log/change counts, concurrency and
native/wire-only/package/container/client/process/restart behavior remain
incomplete or unqualified. Direct rustfmt only; no build, test, validator, probe
or new advisory evidence ran. All three release gates remain open.

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

The route mutation source pass found native auto-approval using an infallible
list and sequential per-node updates. A failed node query could appear empty,
and live readers could observe only part of a policy's approval fan-out. The
new backend path uses checked snapshots, sorted machine guards, stable-ID
re-resolution, one policy view and one live batch. Native attached stores use
the runtime registry; headless stores propagate query failures. Candidate policy
validation now uses the checked snapshot. This is source review/repair without
a demonstrated fault injection, race or runtime result.

Both node address families now reach auto-approver matching. Typed zero prefixes
clean up correctly, duplicate comparison is preserved and sort-only input avoids
an extra mutation. Policy-derived default routes are serialized directly instead
of gaining the admin API's exit pair. Live publication intentionally precedes
per-node durable writes, as Go does; failures can leave full live approvals with
partial durable progress. Attached SQLite/Postgres policy saves now re-read
one current cached node under a shared persistence mutex and write Go's explicit
column mask. Expiry, auth-key references, CreatedAt and DeletedAt are excluded;
missing rows are never recreated and zero affected rows are not save errors.
This removes the approvals-only implementation gap for attached native stores.

A private admin-only native baseline preserves nullable fields hidden by the
public wire model. Native hydration and durable publication capture the source;
ordinary wire reads do not refresh it. Hostinfo merges retain unchanged explicit
unset fields across unrelated edits, and successful saves advance the baseline.
Deletion/ephemeral GC drops absent native state. The DB Hostinfo writer applies
pinned omission/pointer/Service rules. Non-finite projected floats fail before
serde can turn them into null. Native auth-path/runtime CreateParams also
propagate encoding failures, with no reduced-object fallback or alias-based
removal of canonical Hostinfo fields. No public wire field type or dependency
version changed. Headless stores remain approvals-only, and raw custom same-value writes
cannot identify all nil/unset transitions. The additional cached copies, global
save serialization, nullable/timestamp/JSON equivalence, external/raw writers,
missing/soft-deleted rows, owner/key changes, cancellation, feature isolation and
restart/resource behavior remain unbuilt and unqualified.

Policy streams previously waited on a newly created Notify future after each
chunk. PolicyStore now exposes a retained watch receiver subscribed before the
baseline and carried through stream state, so changes between polls survive.
Legacy Notify clients keep their interface. Policy/user refreshes signal the
watch channel; successful policy mutation notifications follow auto-approval
persistence. No load, cancellation, coalescing, malformed-row, feature, client,
process, restart, advisory or build evidence verifies this batch.

The SSH source review found cached check approvals bound only to a persisted
one-second policy timestamp. A successful policy write in that same second
could retain a prior src/dst approval even when Go would require a fresh check.
The handler now binds approvals to a live policy identity and holds one policy
snapshot through rule evaluation and cache lookup/publication. Native successful
writes/reloads also clear the cache. No exploit or runtime regression was run;
this is a source finding and repair.

Configured reloads with empty policy bytes or a missing database row previously
skipped SSH invalidation and route re-evaluation. They now preserve the current
policy while performing those successful-reload side effects. Rejected policy
loads do not reach that success boundary. Legacy timestamp-only seeding cannot
grant production cache approval; embedders have a live-policy seeding helper.
Same-second changes, queued/OIDC approval races, failed/noop/empty reloads,
concurrent cache access, cancellation, resource retention and restart remain
unqualified. Existing SSH fixture calls were adapted in source, not executed.

SignatureType text now follows the pinned signed-decimal/partial-scan behavior
and omits zero on output. SIGHUP uses the Go signal field and error payload;
unconditional success/skip messages were removed. Policy-manager seeded hash
and change-count events remain incomplete, and no build, client/process,
feature, advisory or license/container qualification covers the batch.

Register/map body decoding now uses the shared pure Go scanner/tailcfg schema
rather than recursively materializing every unknown JSON subtree with serde.
Known field names, nulls, duplicate pointers/objects and reused array slots now
share native persistence semantics. Standard type errors are saved; custom key,
opt.Bool, network and time unmarshal failures halt and retain the capability
Version reached. Rejection errors avoid echoing auth/token field values. This is
source hardening without malformed-request, depth, memory or process evidence.

Hardware attestation strings previously had no public-point validation in these
paths. Typed prefix/size/hex checks now precede uncompressed P-256 and reduced-
coordinate/curve checks. Arithmetic is bounded to fixed-size public coordinates
and never handles a secret scalar or signature. Byte signatures/certificates
also validate Go base64/uint8 forms before use. Timestamp parsing follows pinned
Go JSON/RFC3339 grammar rather than accepting chrono's broader date syntax.
These are source findings/repairs, not demonstrated authentication exploits.

The ACL leaf now directly uses the existing locked base64/num-bigint releases;
no external version was updated. Source hashes and retained Go/Tailscale BSD
notices are recorded across ACL/API/database packages and covered by existing
image notice copies. Numeric/option projection, direct serde callers, custom
metadata canonicalization, exact error bytes, public-key/time edge cases and
feature/downstream/lock/license/container/resource/client/restart behavior still
require qualification. No new build, test, advisory audit or image run covers
this implementation.

The key persistence pass rejects malformed machine/node/disco text during row
decoding and before writes. Nullable zero keys and upper/lower hex now share
canonical identities for auth-key conflict checks and optimistic map writes.
Errors do not echo key bytes. Known-key native lookups use the primary node ID;
normalized cold and complete ownership lookups still need query-cost evidence.
NLPublic's tlpub alias now shares the wire/database parser. Existing positive
SQLite/Postgres fixture literals were source-adjusted, not run.

Persisted Hostinfo previously used permissive parsing/defaults in native paths.
A schema decoder now validates known tailcfg fields, Go null/duplicate/slice
rules and prefix text before SQL use. Nil writes bind SQL NULL. Unknown JSON
subtrees are scanned without recursively materializing them. Native completion,
route updates and wire projection propagate errors; the auth planner no longer
falls back to a reduced record when canonical conversion fails. This is a source
finding and repair, not an executed exploit result. The existing wire integer
widths and nil/explicit-unset representation remain narrower than Go; native
projection now rejects unsupported values. Wider request JSON and diagnostics
remain incomplete or unqualified.

Backfill now reloads all live database nodes after IP changes, then merges and
publishes one quiet NodeStore writer batch. Hostinfo is preserved by stable ID
at publication, persisted NetInfo takes precedence and online tracking stays
separate. The batch avoids per-node COW cloning. Rows added while initial guards
are held, cross-process writers, key/index corruption, cancellation, memory/query
cost and restart remain unqualified. Tailscale BSD notices and exact source
hashes are retained in the ACL/database packages and included by both image
recipes. No fresh build, test, license/container or dependency audit was run.

The stored-address source pass adds typed nullable scalar decoding for both
node IP columns and validation before create/reauth/IP-only mutations. Invalid
text no longer reaches a native SQL row as an unchecked address String. SQL
NULL and present empty zero text remain distinct; generic row-decode errors
do not include the stored bytes. Allocator startup separately uses ParseAddr,
so present empty values reject there, and seeds according to actual address
family with zones removed. Typed public-key/Hostinfo adapters have since been
added above; broader wire JSON, unusual zero/zoned/cross-family projection and
raw invalid UTF-8 zone preservation remain incomplete or unqualified.

The allocator previously redrew random candidates up to 1,024 times, used modulo
sampling and could reject based on a used-set count containing out-of-prefix
addresses. It now follows the pinned one-start/finite-wrap scan with unbiased
exclusive-bound rejection sampling. Tiny prefixes report exhaustion on demand.
Single-family and dual-family allocation share one production lock. Auth-key
allocation errors use the pinned registration envelope. These are source changes
without distribution, entropy-failure, exhaustion, load or concurrency execution.

Backfill previously committed one node at a time. Native backends now prepare
under sorted machine guards and apply the IP batch in one SQLite/Postgres
transaction with explicit rollback on failure. Owned publication retains guards;
all awaitable reads finish before allocation starts. Live Hostinfo is preserved
for publication and Go-quoted messages prevent raw client hostnames from
inserting diagnostic lines. The full-node reload now appears above. No exploit, rollback, cancellation, resource,
process or restart run verifies this repair. Full NodeStore refresh behavior,
cross-process writers and post-allocation/cache failures remain unqualified.
New Headscale BSD source notices are retained in affected packages and copied by
both container recipes; package/license/container validation was not run.

The tag authorization source review found that the shared helper recursively
treated nested tag owners as a direct user grant. Go's direct user fallback
accepts user/group owners; nested owner references instead resolve registered
user-owned node IPs. These are now separate operations. CLI and native
SQLite/Postgres/OIDC completion validate the stored node OR the authenticating
user, with fallible native node snapshots and final planner rechecks. Tagged
nodes do not contribute addresses to user owner sets. This is a source finding
and repair without an exploit or behavior run; missing/ambiguous users, owner
chains/cycles, cross-account transitions and concurrent policy/node snapshots
remain unqualified.

Raw requested-tag order and duplicates now survive caching and rejection.
Successful tags compact only after validation; fresh Hostinfo retains Go's
cleared duplicate tail while reauth retains the input array. Validation uses
one policy read snapshot and caches per-tag decisions so duplicate input does
not repeat a complete owner-node scan. The extracted volatile completion helper
is shared by wire OIDC and the harness and retains both registration guards
through owned publication/cache completion. Custom persistent runtimes still
require their backend handlers. No build, authorization corpus, adversarial
load, cancellation/cache-expiry, malformed Hostinfo, feature, process or restart
evidence covers these changes. The earlier policy reports are historical.

The registration source review found that interactive requests reserved prefix
addresses before authentication. They now cache identity/Hostinfo without IPs;
CLI and SQLite/Postgres OIDC approval reuse an existing node's addresses or
validate tags and allocate for a fresh node. Native selection is fallible, so
database errors, ambiguous ownership and node-key binding failures stop before
reservation. Production OIDC providers receive the configured allocator, and
wire-only OIDC follows the same order. This is a source finding and repair;
no exhaustion or adversarial run was performed. Partial dual-family allocation,
failures after reservation, cleanup/retry behavior, custom completion providers,
concurrency and restart remain unqualified.

Registration completion now applies the configured default lifetime to untagged
nodes with absent or Go-zero expiry while preserving explicit timestamps and
nonpositive lifetime configuration. Completion clocks and volatile fresh-node
ephemeral/key metadata follow the pinned source. Debug registration now caches
only registration data, generates actual X25519 public keys through existing
Snow, and keeps TestOS/routes/zero timestamps in its synthetic echo. Stored
route and wire normalization sorting share Go Prefix.Compare; approval parsing
precedes lookup and uses pinned outer error statuses. Request/config prefixes
and trusted proxies now share Go IPv4/IPv6/prefix grammar and inner diagnostics,
including the existing Go Quote/Unicode implementation moved to the ACL leaf.
Primary-route vectors/debug text and auto-approvals use Prefix.Compare too.
Canonical ordinary address rendering still uses Rust Display. No build, source-adjusted fixture
execution, process, feature, crypto or lifecycle evidence qualifies these changes.
All three parity gates remain open.

The standalone gRPC client's latest source changes use grpc-go v1.81.1's
default retry delays (one second initially, multiplier 1.6, cap 120 seconds,
then +/-20% jitter). Per-attempt connection budgets are at least 20 seconds
and increase with backoff; the absolute command deadline still bounds both
attempts and unary response decoding. Jitter uses the existing OS randomness
dependency. Resolver/backoff/close equivalence remains unqualified, with no
new execution evidence.

Standalone remote CLI connections now require TLS for accepted targets;
HTTP-looking strings cannot send an API-key bearer over a plaintext channel.
`--insecure` skips trust/name validation but now retains TLS 1.2/1.3 handshake
signature verification using the AWS-LC provider's supported algorithms and
requires negotiated `h2` ALPN. The standalone owned transport now applies these
checks for both TCP and remote Unix connectors; secure and insecure server-name
conversion strips IPv6 brackets. Remote Unix/abstract targets retain TLS with
localhost authority. Target parsing separates scheme/host/path/opaque decoding
and validates resolver-host escapes before choosing a connector. Service-name
ports use a cached system services map. Direct library callers retain their explicit HTTP
extension. The CLI's source-only timeout path now preserves signed nanoseconds,
including fractional, zero and negative durations, instead of rejecting or
rounding fractional values. No new builds or execution evidence cover these
transport/decoder changes. Custom DNS-authority hostname resolution now has an
owned UDP/TCP implementation: connected UDP peers, randomized IDs, matched
questions/headers, bounded frame/name/compression parsing and TCP fallback for
truncated replies. It uses the pinned recursive-answer assumption, system
hosts/search settings and relevant resolver options. Owned background watchers
now share resolution for explicit/system DNS, use 30-second resolution and
positive-refresh bounds, coalesce refresh requests and retry failures with
resolver backoff. Temporary failures retain addresses; permanent/no-address
updates remove them. SERVFAIL is classified as temporary. DNS
TLS/ALPN/HTTP2-preface address attempts are staggered by 250 ms, interleave
families and advance immediately on current-address failure. A channel becomes
usable only after a complete validated server SETTINGS frame. The bounded
observer also holds post-handshake traffic until the peer preface on reconnect,
flushes permitted TLS bytes, and validates initial SETTINGS shape/value bounds.
Owned subchannel tasks and I/O abort guards cancel losing attempts; selected channels
retain cancellation wakers until their transport lease ends. Native TLS roots reuse the existing locked
`rustls-native-certs` 0.8.3 package through a new direct CLI dependency, with no
release or API wire-only dependency change. Literal IP targets retain Go's
bypass. These codec/cache/TLS/preface/cancellation paths remain unbuilt and
untested. Custom-authority DNS sorting now follows Go's implemented RFC6724
preferences, using route/source selection through UDP connect without sending
datagrams, stable ties and the pinned policy/scope table. The resolver also
implements forced-native NSS files/DNS ordering, criteria/unknown-source
handling and OpenBSD lookup defaults. Files-only resolution does not query the
DNS authority, DNS-only resolution skips hosts entries, and file-first order
is preserved. Pick-first now keeps independently owned subchannels and backoff
clocks per address. DNS updates reuse matching workers; a ready winner retires
others, and lost readiness enters Idle until demand starts a new first-address
pass. First-pass failure requires every address to fail, with independent
retries thereafter and sticky failure until Ready. Backoff-expired idle
subchannels wait for the first pass to finish. One-shot idle wake tokens prevent
concurrent calls from leaving a future wake permit. Round-robin children
reconnect automatically. The superseded shared-list duplex preface replay and
forwarding helper was removed; each child owns its actual Tonic transport.
Removed endpoints stop new picks while in-flight leases drain. Native literal
IP DNS targets become direct sockets, and mapped IPv6 uses the IPv4 family in
interleaving/TCP fallback. Last resolver owner Drop aborts its watcher.
TXT lookup now uses the explicit authority or system nameservers, bounded TXT
character-string framing and the same 30-second address/TXT resolution budget.
Go's language/percentage/hostname selection and environment defaults are
implemented. Ignored TXT errors retain resolved addresses, initial invalid
config blocks connection, and an existing valid config survives later invalid
updates. Method timeouts and request/response limits now apply to all 29 admin
RPCs, alongside the command deadline; pick-first shuffling is implemented.
Configured limits may raise the default receive limit, following Go.
Configured unary retries now retain bounded replay eligibility, commit on
initial response headers, cap configured attempts at five, honor status sets,
server pushback, 0.8-1.2 jittered backoff and the same RPC deadline. An explicit
first remote REFUSED_STREAM permits a transparent retry. Larger requests commit
instead of remaining retryable; configured retries of failures before response
headers follow the service policy. Shared throttle tokens follow Go's failure/
success checks and config resets. This changes retry behavior for mutations
when DNS explicitly supplies a retry policy; no retry/commit/cancellation or
paired process evidence qualifies it.

The service-config decoder no longer reduces JSON objects to maps before typed
validation. A bad typed duplicate could previously disappear behind a later
valid value, allowing retry/limit settings which the pinned Go parser rejects.
The source now checks every occurrence, folds incoming names in order, merges
repeated struct pointers, resets null pointers and retains scalar null values.
Duplicate arrays retain prior element state, including hidden slots across
shrink/regrow, with empty-array/null resets. Custom durations and raw retry-code
spellings retain their distinct error boundaries. Choice arrays and balancer
element types decode before early selection; RawMessages remain opaque until
selected, and config identity keeps original JSON bytes. This is a source
finding and implementation, without an exploit, malformed-config execution,
retry/mutation process, load or build result.

The service-config path now has an iterative byte scanner with Go's
10,000-container limit, JSON whitespace and token/escape grammar. Unknown/raw
payloads stay byte spans rather than recursively allocated serde trees. String
and key decoding combines valid surrogate pairs and replaces lone surrogates
and each malformed UTF-8 byte. TXT data remains bytes across character-string
and record concatenation, selection and config identity, avoiding early lossy
conversion and preserving cross-record UTF-8 sequences. This is new parser
code without a build, malformed-input run, depth/load or resource result. Exact
diagnostics, hostname/platform bytes and parser/config/retry behavior remain
incomplete or unqualified; source inspection is not adversarial qualification.
Policy-manager hash lifecycle logging remains a separate source residual.

Source inspection found an `expect` while Tonic 0.14.6 decodes binary status
details. The CLI client wrapper now validates base64 in initial headers and
trailers before that parser. A malicious configured server or intercepted
insecure connection can supply those values. The guards have no malformed-peer
execution or advisory evidence and do not claim to audit all Tonic parsing or
other callers of generated clients. Newly direct h2 0.4.19/http-body 1.0.1 and
the promoted http-body-util dependency reuse locked releases without resolution.

Native connections now have a background supervisor with connecting/ready/
failed picks. Wait-for-ready queues before dispatch within the same RPC deadline;
fail-fast calls stop on transient failure. EOF/errors/shutdown and complete
GOAWAY frames retire IO; pick-first reconnects on idle demand and round-robin
children automatically reconnect with growing backoff/20-second minimum budgets. An old transport cannot silently redial itself; locally known
pre-stream rejections permit transparent retry. Dispatch/body leases preserve
old in-flight calls during GOAWAY, and final-owner Drop cancels registered
transports and aborts the supervisor. Initial blocking dial checks current
readiness before returning.

Ordinary hostname dialing now starts the alternate TCP family after 300ms or
primary exhaustion, splits remaining deadline across serial addresses with
Go's 2-second floor, and owns cancellation of losing sockets. TCP selection
precedes TLS. These readiness/lease/drain/backoff/fallback changes have no build,
execution, cancellation, load or paired process evidence.

Native DNS connections now select pick-first/round-robin before dialing.
Round-robin maintains independently reconnecting children per unique endpoint
and picks ready children; DNS removal and policy replacement stop new picks
while active response bodies retain their transport leases. Pool/child
generations reject stale completions. Active/pending pools apply Go's graceful
handoff rule. Pick-first preserves a still-present ready endpoint and retains
matching per-address subchannels, backoff clocks and sticky connectivity failure.
Temporary DNS errors retain the last good address state without config
application or retry-throttle reset. Refresh requests come from connection
failure/close rather than snapshot reads.

The inspected cached Go v0.29.5 production binary has round-robin and health
protocol symbols but no grpc/health package symbols. Pinned gRPC requires that
parent package's registration to activate health Watch, so this native CLI also
validates health config without starting Watch. This is bounded source/binary
inspection; other builds with extra imports and runtime nonactivation remain
unqualified. No health traffic was sent. Provenance records the cached path.

Endpoint fanout, DNS/config churn, fairness, sticky failure, stale completion,
draining, shutdown and resource behavior have no build or execution evidence.
Pick-first per-address reconnect/backoff/reuse, first-pass completion, idle
wakeups and mapped-address family ordering remain unqualified, alongside complete
GOAWAY/new-stream transparent retry equivalence and large-request startup
failures. Transport status classification, full JSON/null/case-collision,
payload/diagnostic and system-resolver
equivalence, Go's waiting Close
semantics, reconnect backoff/fail-fast/draining and exact diagnostics remain
incomplete or unqualified. No build, fixture, network probe, load or lifecycle
execution qualifies this resolver/subchannel/service-config implementation.
The new Prost dependency edge reuses the locked workspace release. Go/gRPC
license notices, CLI metadata and both runtime image notice copies are updated;
no dependency, license or image gate was executed. Provenance and limitations
are recorded in `headscale-cli/UPSTREAM.md`.

- OIDC now carries discovery's signing-algorithm allowlist into verification,
  supports RSA/PSS, EC P-256/P-384/P-521 and Ed25519, tries all matching keys,
  caches JWKS and coalesces refreshes (including failed refreshes). Issuer,
  audience, expiry and `nbf` handling follow the pinned go-oidc source.
- Provider requests share a client and have 30-second request deadlines,
  including response bodies. Discovery/token/JWKS/UserInfo JSON is limited to
  1 MiB; at most 128 callbacks perform provider work concurrently. Config
  Debug output redacts the client secret.
- TLS, both Noise drivers and native DERP authentication now have absolute
  30-second deadlines. Pending control and DERP handshakes each have a 1024
  permit budget. Established sessions release their handshake permits.
  Noise also closes idle HTTP/2 sessions and bounds request-body reads;
  active map streams have no lifetime timeout.
- Same-machine auth-key registration is serialized. A valid existing node
  can refresh using its current node key without spending another PAK.
  Expired untagged nodes, rekeys, ownership conversion and retagging require
  fresh validation, following the v0.29.5 state handler.
- The optional DID replay cache now expires globally using the server clock,
  has a configurable capacity (default 65,536), and rejects new requests at
  capacity instead of evicting a live nonce. Routers can share a cache;
  transactional persistence across durable-ledger restarts remains unqualified.

The same implementation-only work also repairs registration persistence:

Source review of the current failed-key path found an immediate error return,
without an authorization fallback using a previously captured node. Persistent
registration also compares authorization state under its SQLite/Postgres
transaction. This is source evidence; the concurrent failed-key adversarial
case remains unexecuted.

The in-memory `WireMachineAdmin` adapter now serializes existing-node expiry,
disable-expiry, logout, rename, tagging, route changes and deletion with the
same per-machine locks as registration. Route batches deduplicate and order
machine locks, then resolve stable node ID, machine identity and creation time
again after waiting. Registry expiry/deletion are authoritative; removed
sidecar flags can no longer mark a future expiry immediately expired or hide
a later registration with the same key. Expiry preserves LastSeen history,
and wire creation retains precise expiry. Missing numeric IDs on rekey inherit
the old effective ID before map changes and auth responses are prepared.

Native admin adapters now select gRPC mutations by stable numeric ID, and
mutation responses resolve that ID again instead of looking up the old key.
Numeric selectors must be canonical positive decimal strings; stale hex keys
with leading zeroes cannot fall back to an unrelated database row. Generic
MachineAdmin implementations retain their existing key selector by default.
One existing future-expiry assertion was source-updated, without execution.
No build, rekey/admin/expiry/deletion/batch/cancellation race, process or restart
result qualifies these changes. Direct registry writes by a trusted embedding
host remain outside the adapter lock boundary.

The review also found that fresh volatile auth-key registration could reach
an unconditional registry upsert when the requested node key was occupied.
The existing precheck covered a rekeying node and could not make check/write
atomic across different machines. Volatile auth-key and web/CLI/OIDC completion
now use a checked NodeStore write: an existing source must retain its machine,
creation identity and numeric ID; an occupied target must belong to that same
source node; a fresh registration cannot overwrite any occupied target. The
same operation performs insertion/rekey, captures its committed record and
computes map changes. The auth-key response no longer assumes a subsequent
registry lookup must succeed, avoiding a panic if deletion follows publication.
General rekey writes also align the record's node-key field with its index.

Volatile admin creation also checked a snapshot before an unconditional upsert.
It now checks node-key, effective numeric ID, IPv4, IPv6 and DNS-name uniqueness
inside the insertion's NodeStore write and returns its captured committed row.
The adapter uses the existing fallible DTO-to-wire conversion, preserving
numeric owner/auth-key IDs, disco key, Hostinfo and precise timestamps; tagged
creation clears user identity. Generated registration DNS labels are resolved
inside the same writer, retaining an explicit admin name on reauthentication,
so competing machine registrations cannot select the same generated label.

Volatile web/CLI/OIDC node selection now uses the authenticated numeric user ID
when available, matching the pinned Go user index rather than reusing a node
based on a shared display name. Legacy callers without a supplied numeric owner
retain name lookup. Auth-key lookup rejects duplicate same-owner matches instead
of selecting an arbitrary entry, and the canonical auth projection carries the
selected numeric owner from its admin DTO. These are source repairs; duplicate
name/account, concurrent creation and label-reservation behavior were not run.

The persistent auth planner also selected an arbitrary first machine row and
accepted a cached wire node ID without an owner check. Both SQLite and Postgres
now fetch the complete live ownership set for the machine. A shared decision
selects the numeric owner, handles a tagged-node conversion, and rejects
duplicate-owner or ambiguous tagged/user combinations. Web/CLI/OIDC completion
does not treat a cached node ID as permission to replace a different account's
row. Legacy unscoped matching is limited to adapters without a user store.
Numeric owners are resolved by ID when supplied, with existence checked through
the attached user store; a display name cannot redirect that lookup. OIDC owner
conversion no longer wraps an overflowing u64 into a signed database ID.
When web auth creates a different account's new node on the same machine, the
SQLite/Postgres and volatile plans retain only omitted NetInfo from a prior
user-owned node, following Go's connectivity metadata carry-over. Ownership,
addresses, approvals and node identity are not inherited through that fallback.

Source review found a separate persistent node-key binding gap. Database node
key lookups deliberately retain Go's first-row behavior and do not establish
uniqueness. The previous volatile-only precheck did not protect the production
auth-key store/publication path. An authenticated different machine claiming a
peer's public node key could therefore reach persistence and an unchecked live
upsert, a potential netmap denial of service. This is a source finding without
an exploit run. Built-in auth-key, CLI and OIDC completions now acquire a
separate node-key registration mutex after the machine mutex and retain both
through owned persistence/publication. Namespaced lock identities cannot alias
machine and node scopes. The live binding check rejects a foreign machine with
the pinned v0.29.5 error, including fresh and rotating auth-key registrations.
Pending completions re-read both machine and node keys after waiting. Native
admin creates also use these guards, and persistent creates own the database
write/live projection through caller cancellation.

These locks coordinate built-in writers in one shared live registry. Raw
embedding writes, unattached custom backends and independent processes do not
gain a distributed lock or a new database uniqueness constraint. Credential
rollback remains limited to the atomic store path. No build, malformed-state,
account/ownership/key-collision race, cancellation, process or restart evidence
qualifies this implementation batch.

Stored tag JSON previously decoded with an empty-list fallback on parse errors.
Native SQLx node and preauth-key rows now validate tag columns during FromRow,
so a malformed value cannot silently change tag ownership to user ownership in
registration or hydration. The narrow auth-key ephemeral lookup validates the
referenced key's tags too. Transaction authorization snapshots, key binding,
freshness decisions, proposed tags, ownership selection and wire hydration use
fallible decoding explicitly. Public row String fields remain in place; the
convenience tag_list method still defaults malformed manually built values,
and such callers must use try_tag_list for authorization decisions.

The shared decoder follows pinned Gorm/Go semantics: an empty serializer
value, SQL null and root JSON null are empty slices; null array elements retain
fresh empty string slots. Whitespace-only input, invalid JSON and non-string
elements fail. Go surrogate and per-byte UTF-8 replacement use the existing
iterative scanner, now shared through headscale_db::go_json. SQLite text/blob
and Postgres text tag values reach it as bytes; representable raw JSON is kept,
while invalid UTF-8 inside valid string values is re-encoded with Go's decoded
replacement characters to retain ownership in the Rust String row field.
Native SQLx row-decode errors contain a field/context description without the
stored JSON or credential. No tag-name policy validation was added here.

The CLI scanner adapter retains its service-config error envelope. headscale-db/UPSTREAM.md records Go/Gorm source hashes, retained BSD notices, package license
metadata and container notice copies. There is no new dependency release. No
build, malformed-row/Unicode/depth/resource execution, credential transaction,
feature/license/container, paired process or restart result qualifies this
source batch. Other stored fields, custom database types, driver diagnostics
and the wider production parity gates remain open.

Stored endpoints and approved routes had the same empty-list JSON fallback,
and nonempty strings were not validated as Go netip values. Node SQLx row
conversion now validates these columns, hydration uses fallible accessors and
the database endpoint/route write paths validate before mutation. The shared
pure leaf `headscale-api-acl::go_netip` handles numeric ports, IPv6 brackets and
zone names, IPv4-mapped IPv6 text, prefix length spelling and empty text zero
values. Prefix host bits are retained. Root-null/empty serializer values and
null array slots follow the same Gorm/Go rules as the typed endpoint/prefix
slices. Invalid network text rejects the row instead of silently removing
endpoints or approvals. The storage route comparator now uses Go's masked
address/length/original-address order, with zero prefixes first, and native
admin proto output renders a zero approved prefix as `invalid Prefix`.

Map endpoint strings use the same parser, replacing the narrower SocketAddr
and last-percent zone fallback. Fresh null endpoint array elements decode to
zero AddrPorts, while omitted/root-null marker behavior remains as before.
The public wire field types are unchanged. The leaf parser adds no external
release; its source hash, Go BSD notices, package metadata, existing-package
lock edge and container notice copies are recorded in its UPSTREAM.md.

No build, malformed row/write/map, zone/port/prefix/Unicode comparison,
concurrency/resource, feature/license/container, client or restart result
qualifies this source batch. A subsequent source pass replaces Rust IP parsing
delegates with Go grammar/error ordering and shares the existing Quote/Unicode
table with CLI logging. Parser/rendering/diagnostic equivalence still needs
paired evidence. Other route request/emission sites, stored Hostinfo,
broader wire JSON/null/duplicate/coercion handling and exact diagnostics remain
incomplete or unqualified; all three parity gates remain open.

This is a source finding and repair, without an exploit or adversarial run.
Node-key collision, competing-machine publication, source deletion/recreation,
batch ordering and credential-consumption behavior remain unqualified. Legacy
eager/custom redeemers may consume a key before a later publication failure;
the database transaction path remains responsible for atomic credential/node
persistence. No build or test covered these changes.

- Persistent SQLite/Postgres adapters opt into deferred credential consumption.
  The database transaction rechecks the credential, compares current node
  authorization state with the prepared snapshot, saves the node, and marks a
  single-use key used before committing. A failed write rolls both changes back.
  Legacy `used=NULL` rows are handled as unused. Custom redeemers/stores retain
  their existing path unless both explicitly opt into the atomic interface.
- Postgres name retries use savepoints. Node admin mutation methods share the
  per-machine registration lock, then resolve the stable row again before
  changing it. This coordinates their database write and live-state projection
  with the auth-key handler's persistence/publication step.
- Numeric owner IDs are carried from the authenticated preauth row through the
  wire record and persistence plan, eliminating ambiguous display-name lookup.
  Production credential/node expiry checks retain fractional-second deadlines.

The map/stream implementation-only follow-up adds:

- Same-machine serialization across map mutation/persistence and registration/
  admin writes, with the guard released before any long poll or live stream.
  The COW merge preserves current authorization, owner, IP and admin-name state
  and refuses to insert a node that disappeared during persistence.
- Dedicated SQLite/Postgres map UPDATE statements omit ownership, tags, expiry,
  auth-key references, IP assignments and registration identity. Unchanged and
  LastSeen-only requests avoid full row writes.
- Endpoint validation/canonicalization, explicit endpoint clearing, independent
  storage/notification decisions, complete Hostinfo replacement with NetInfo
  carry-over, and incremental key patches following the pinned Go source.
- HTTP/2 stream/header limits matching pinned Go, an outstanding-request task
  bound, prompt stream reset cleanup, and receive-window backpressure so a
  stalled client does not accumulate an unbounded queue of map response data.
- Raw client OS/version values remain intact on wire hydration; admin node
  expiry uses fractional timestamps and absent live presence is offline.
  Atomic registration rechecks credential owner/tag properties and the
  proposed node tags before committing.

Registration source review found further state-projection differences:

- Raw database Hostname, server-managed GivenName and client Hostinfo are now
  separate. Empty client snapshots do not get filled with an admin DNS label;
  admin RPCs preserve both names independently across database hydration.
- Auth-key reauth clears retired client OS/version/SSH-host-key fields instead
  of keeping them. Web/OIDC/CLI reauth preserves omitted NetInfo and endpoint
  reachability, then publishes the committed row. Ordinary reauth preserves
  the registration method; tagged expiry preservation keeps full precision.
- CLI and built-in OIDC completion paths share the same machine mutation lock
  and re-read pending auth state after waiting. Tagged node publication clears
  numeric user ownership and profile/provider metadata.
- Node expiry uses Go's strict-after boundary and treats a pointer to Go zero
  time as no expiry. The wire record has a new `raw_hostname` field; external
  struct-literal consumers need to initialize it, while constructors do so.

The wire logout handler previously changed only the live registry. It now
persists expiry or ephemeral deletion before publishing, using dedicated
SQLite/Postgres hooks under the shared machine guard. Revalidation after lock
acquisition binds the write to the same node/machine; tagged logout keeps its
expiry semantics, and old client timestamps are clamped to now. This addresses
the source-level path that could restore a logged-out row after restart, but
its durable restart behavior has not been executed for this snapshot. Custom
store adapters must override `persist_wire_logout` to make that operation
durable; the default preserves their prior volatile behavior.

The Noise dispatcher intentionally cancels handler futures on stream reset.
Source review found that this could interrupt live publication after a database
commit. Critical registration/logout/map and persistent node admin mutation
steps now own their worker and machine guard through publication, so dropping
the requesting future does not abort that step. CLI and persistent OIDC
registration also finish the pending-auth handoff. This addresses request
cancellation; graceful runtime shutdown, worker failure and process-crash
recovery still require execution evidence.

A related GC race is also changed in source: cleanup claims its timer only
after acquiring the machine guard, rechecks node identity/active sessions and
uses an explicitly opted-in SQLite/Postgres deletion hook under that guard.
Map streams attach under the guard and reject invalid self names first. Custom
stores retain their old hook contract unless they implement guarded deletion;
the new production behavior does not qualify that legacy embedding path.

The next source pass validates/canonicalizes node, old-node, network-lock and
disco public keys before they can enter stored state. It retains the pinned
Go key-parse diagnostics and prevents malformed key strings from being
published to peers. Registration error messages/encoding and the named tag
rejection paths now follow the pinned wrapper behavior; other JSON/provider
error combinations still require paired qualification.

The persistent preauth adapters previously kept all minted bearer tokens in
an unbounded process cache, even though gRPC list output was already masked.
That cache is removed: modern mint responses return the bearer once and later
adapter reads expose only the public prefix/mask. Prefix expiry now requires
a complete verified token or a unique public prefix, rather than cached
secret fragments. Imported legacy rows keep Go's plaintext display behavior
for compatibility; this change does not erase those legacy database secrets.
NextDNS device_name now follows the raw node hostname rather than its admin
DNS label.

The API-key validator previously exempted a non-null Go zero-time expiry and
discarded fractional expiry. Pinned Go exempts only SQL NULL. The source now
rejects the year-one timestamp and checks the precise stored deadline; mint,
expire and gRPC timestamp projection also retain database precision. A key
created through the gRPC API without an expiry therefore has the pinned Go
zero-time behavior. This is distinct from a SQL NULL key and from node or
preauth zero-time semantics. The former local zero-time fixture is corrected
but has not been run.

API-key parsing also sliced untrusted UTF-8 strings at fixed byte offsets.
Malformed prefixes could panic before validation. Byte-level validation now
precedes UTF-8 conversion in bearer and display-prefix parsing. Modern bearer
recognition uses pinned Go's string-cut behavior.

API-key and preauth bcrypt calls previously ran synchronously on async runtime
threads. They now share a blocking-worker budget, sized to available CPUs and
capped at eight, acquired before submission. The worker retains its permit if
the requesting future is cancelled. Pooled verification releases database
connections before waiting for bcrypt; explicitly connection-scoped operations
retain their connection. This bounds submitted hashing work; it does not add
a global request-rate limit or establish overload resistance without execution.

Policy writes and user CRUD had the same commit/publication cancellation gap
as node mutations. The source now shares an async mutation guard across cloned
admin services and the legacy UI/API, and the worker owns that guard through
publication. Policy writes/reloads retain it through route reconciliation and
notification, avoiding out-of-order publication by these handlers. User
create/rename/delete retain it through identity/map refresh. Numeric ownership
now takes precedence over display-name matching in user deletion checks.

The legacy policy PUT endpoint previously parsed the document without checking
live user-reference ambiguity or the document's policy/SSH tests. It now checks
those conditions before publication; its validate endpoint performs the same
read-only checks. This closes a source-level route around candidate validation
that gRPC already performed. These changes have no cancellation/concurrency
execution evidence. Direct/custom database writers and runtime/process shutdown
are outside the new completion guarantee.

Identity source review found that policy-load ambiguity checks used database
accounts, while several live matchers compared only the displayed login.
That could misresolve an ACL/tag/route/SSH principal when stored names, email
and provider identifiers differ or labels collide. Matching now resolves the
pinned provider-ID/name/email precedence through a runtime account snapshot
and compares numeric node ownership. Provider URL aliases are resolved before
CIDRs; peer visibility, route grants, node attributes and DNS metadata use the
same identity path. Numeric self matching separates equal display labels.

Production startup, policy candidates, user CRUD and OIDC profile writes now
bind or refresh that snapshot. Ambiguous account updates preserve the prior
policy snapshot and report failure, following pinned Go. OIDC user publication
uses the shared guard and completes after request cancellation. This does not
add a persistent user store to wire-only embedders: without an authoritative
snapshot they retain the existing label-based behavior. Runtime account facts
are excluded from policy JSON and canonical hashing. The new paths, including
their public type changes, have no build or behavioral evidence yet.

The OIDC provider source pass aligns discovery status/issuer handling and
missing-endpoint timing with pinned go-oidc. Token exchange now supports form
responses, requires an access token, rejects OAuth error payloads and caches
the working client-auth style. UserInfo uses the returned token type and can
verify compact signed responses through the bounded JWKS path before merging
subject-matched claims. Nullable claim handling and flexible boolean spellings
also follow the pinned types; explicit null booleans are rejected. The existing
body/deadline limits remain. No provider-process or new signature-path execution
supports this snapshot, and general JOSE serialization/transport/decoder error
parity remains unqualified.

JOSE parsing now also handles flattened and single-signature general JSON
serialization for ID tokens and UserInfo. Protected-header precedence, critical
header rules, nonce placement, signing-input reconstruction and numeric curve
width checks follow the pinned source. Embedded public keys/certificates are
metadata checks only: they cannot supply a verification key, which still comes
from the provider's JWKS. Multiple signatures and private selected embedded
keys are rejected. These parsing and certificate checks are also unbuilt and
untested; malformed metadata/key-set/certificate combinations remain outside
the current evidence.

JWKS import now uses the same typed parser as embedded JOSE metadata. An
invalid or unsupported key rejects its whole set; null/missing key lists
replace the cache with an empty set. Valid private metadata is excluded from
verification. The parser checks recognized key material, certificate matches
and thumbprints, preserves Go's Ed25519 fixed-buffer import behavior, and
discards private components after import validation. RSA private arithmetic
is limited to 16,384-bit components. Parsing and signature work are admitted
before entering the blocking pool, share a CPU budget capped at eight, and
retain permits after caller cancellation until work finishes. Key-set
snapshots are immutable and shared rather than cloned for each signature.

RS/PS verification now delegates to the already pinned AWS-LC backend through
`headscale-api/src/oidc/rsa.rs`. This is a private, documented exception to the
workspace unsafe-code lint: its safe entry point owns all C allocations,
returns only a verification result, and uses no private-key operations. It
supports the default Go 1024-bit minimum and automatic PSS salt detection,
closing two differences in the prior JWT presets. AWS-LC's 16,384-bit maximum
and Go's unsupported `rsa1024min=0` override remain explicit compatibility
limits. The direct `aws-lc-sys` edge is pinned to the existing 0.46.0 lockfile
package; the advisory-bearing `rsa` crate remains inactive. This new FFI and
its signature/ownership/error paths have not been built or executed and
must be included in the eventual qualification gate.

ID-token decoding also distinguishes absent `iat` from explicit null,
validates `at_hash` as a nullable Go string, permits nullable distributed
claim maps/source fields and null audience-array entries, and restricts
quoted numeric dates to JSON number syntax. Source references still must
exist and be nonempty. These branches are also unexecuted.

The CLI source pass adds one absolute timeout across connection attempts and
all 29 unary RPCs, including response-body decoding. It also sends the remaining
budget to the server. This prevents stalled dialing/response bodies and
multi-RPC commands from renewing their runtime indefinitely. Direct client
construction keeps its existing error/timeout behavior; the standalone binary
selects Go command-context behavior. Local timer expiry is distinguished from
a server cancellation. The new connection retry/deadline paths remain unbuilt
and unexecuted; permission diagnostics and backoff timing remain unqualified.

Key commands now use pinned Prometheus duration syntax and bounds, preserve
API-key request nanoseconds, and send a concrete preauth expiry for zero
duration. The legacy parser no longer slices through a UTF-8 character.
API-key selector zero values, fractional node-expiry output and Go structured
JSON escaping are also repaired in source. Existing error expectations were
source-updated for operation/status text and standalone runtime exit 1; they
are not new behavioral evidence.

The standalone logger now emits zerolog-style text on stderr or typed JSON on
stdout according to `log.format`. It keeps console field quoting/error order,
timestamps and terminal/NO_COLOR handling, and preserves Rust span context.
Noise-key creation and database opening emit real lifecycle events. The
Postgres event contains host/database/user rather than a password-bearing URL.
Existing manual database/MagicDNS fatal and ephemeral deprecation logs now
share the renderer, including JSON stdout, configured fatal thresholds and
the early deprecation machine-output boundary. Console duplicate fields retain
their last values and caller paths precede messages. Unix color selection now
follows pinned termcolor flags, FORCE_COLOR, terminal and CI rules plus
headscale's NO_COLOR override. Float fields preserve Go non-finite spellings,
negative zero, notation thresholds and normalized signed exponents through
the existing serde_json raw_value feature; no package release was added.
These paths remain unbuilt and untested. Policy hash events, invalid-format
diagnostics, pre-load fatal/caller diagnostics, Unicode printability, combined
startup-error ordering and the broader log matrix remain incomplete or
unqualified; the earlier log mismatch report was not rerun.

Admin gRPC commands now load a private projection of CLI, socket and logging
settings. Unrelated server fields and environment values cannot trigger server
validation or OIDC secret-file reads during those commands or logging setup.
Direct database policy operations and server startup retain full config loading.
The binary defers CLI environment parsing to this loader so empty values retain
file settings and invalid booleans follow Go's false fallback; library argument
parsing remains available. Case-insensitive/dotted fields, empty documents,
scalar casts and empty config-path fallback are handled in source. Timeout and
local-socket debug events are emitted without API-key or secret fields. The
command deadline now starts before credential/permission setup. These changes
are unbuilt and untested; server config casting, combined error order and exact
diagnostic equivalence remain unqualified.

Console field quoting now uses a private copy of Go's pinned Unicode
printability ranges/exclusions, with source SHA-256 and retained license.
This removes dependence on Rust's Unicode-version/debug-escape decisions for
log fields without adding a package or public API. The Go 1.26.0/1.26.9 source
tables are identical; output behavior is still unbuilt and untested.

Initial configuration now owns one file snapshot for logging and command
parsing; the raw source has no Debug implementation. Missing-config warnings
emit once before command setup, and initial file failures use a fatal record
with actual Rust caller/error fields. Root-only utility commands avoid full
server loading even when global flags precede the command. Invalid log format
messages now appear during admin and successful server/configtest setup, using
the initial text threshold and root machine-output suppression.

Deprecations now collect warning/fatal messages across file keys and nonempty
environment settings. Available replacements, including Go DNS defaults, make
the relevant old keys warnings; unsupported keys and oidc.expiry remain fatal.
Null is unset and presence checks support case-insensitive/dotted paths. The
full loader emits warnings once before secret reads, including direct policy
database access. Fatal reports preserve exit 1 when output is suppressed.
Activated OIDC validation precedes deprecations; empty OIDC environment values
retain file values, and an empty client-secret path cannot satisfy required
secret validation. No new execution evidence covers these changes. Parser and
caller wording, multi-message ordering, full server casts and combined startup
error precedence remain unqualified.

The production server loader now separates typed parsing from completion.
Serve, configtest and direct database policy access share the ordered static
completion stage; OIDC secret-file reads follow aggregate/prefix/trusted-proxy/
allocation/DERP checks. Domain safety, database-type and MagicDNS projection
checks follow the read. This removes the former database-fatal shortcut and
duplicate policy-file precheck. Persistent state loads policy after Noise-key
and database initialization. Configtest does not perform serving-only TLS or
listener checks. Existing in-module legacy validation helpers are not the
production path.

Private CLI DNS buffering now retains source presence and rejects conflicting
inline/file sources at Go's early fatal boundary, including explicit empty
arrays and nonempty environment sources. The public DNS decoder is unchanged.
Early conflicts use the initial threshold; later fatal projections use the
configured threshold. Quoted values, aggregate duration/error framing and TLS
warning records use pinned formatting. No builds or tests cover these changes.
Typed decoder/cast behavior, malformed mixed-source inputs, nonstandard-prefix
banners, direct database confirmation timing, database option edges and
constructor/listener failure order remain incomplete or unqualified.

Policy input is now read once before gRPC dialing; direct database confirmation
precedes full server-config validation, OIDC secret reads and database opening.
Prepared input retains that confirmation without changing the force flag or
reopening the file. Shared user/node/policy prompts follow pinned first-token
yes/no handling and ignore prompt/scan I/O failures. Nonstandard prefixes now
emit the pinned warning banner at its configured threshold; its private source
copy records the pin hash and retains the upstream license.

Offline direct policy set now matches Go's boot validation boundary: structure
and ambiguous-user errors reject the write, while failing ACL/SSH tests warn
against an empty node set and do not block storage. Direct check binds numeric
owners and the authoritative user snapshot, propagates node-list database
errors and rejects test failures. Regular live API writes keep their hard test
boundary. Both persistent backend startup paths now warn about stored-policy
test failures after node hydration and continue startup, matching Go's boot
behavior. These are implementation changes, not fresh deployment evidence.
No builds/tests were run; non-UTF-8 policy files, native error wording, prompt
I/O, stored-row decode edges and production/restart behavior remain unqualified.

Production startup now reads the Noise identity before opening the database
and reuses that key for the runtime. A prepared state stage validates policy
and hydrates nodes before OIDC discovery, DERP/STUN listener startup, remote
DERP loading and DNS-file loading. The same persistent stores, registry,
allocator, policy/account guard and tuned registration cache are retained for
final runtime construction. These sequencing changes have no process evidence.

`configtest` now shares allocator/policy/node preparation and the native DERP
constructor with `serve`. Relay-key loading/creation and the existing rejection
of Noise-key reuse therefore run during this preflight too. Default key paths
are resolved consistently, and serve performs native key construction before
STUN/relay listener startup. No configtest listener stage
is invoked. These constructor, hydration and filesystem branches remain unbuilt
and unexecuted.

The public control query parser now rejects malformed escape pairs and raw
semicolon pairs, handles encoded names/values, retains an empty first duplicate
value and matches Go's default 10,000-parameter limit. Key discovery, WebSocket
initiation and debug-key lookup share it. Debug authorization no longer skips
an empty first `debugkey` value in favor of a later duplicate. Key discovery
also uses Go-sized signed integers and Go-shaped JSON/error headers. These
wire-only parser/authorization branches are unbuilt and unexecuted.

CLI handler-side key ID/selector checks now follow connection setup, preserving
the Go credential/connection failure boundary. The local gRPC connector also
checks socket write permissions with Go-shaped error framing. Its open does
not create/truncate a file or transfer file data, and uses nonblocking mode to
avoid a FIFO open waiting for a reader. Unix constants come from the existing
locked `libc` 0.2.186 package; this adds no direct unsafe Rust. The permission
probe, unusual-path diagnostics and connection ordering remain unexecuted.
Existing runtime-error cases were adjusted to use a reachable fixture in source.

These transaction and concurrency changes are also unbuilt and untested. They
have no paired process or failure-injection evidence yet; earlier passing
reports do not establish their rollback, concurrency or restart behavior.

These resource limits are explicit hardening choices. Provider responses over
1 MiB and excess pending callbacks/handshakes are rejected; those boundaries
and the new signature paths still need behavioral and load qualification.

Production and offline-policy database openers now apply the configured Go
pool limits. SQLite uses a single connection, one-hour idle expiry, no maximum
connection age and the pinned driver's WAL/1000 defaults when the WAL override
is false. Postgres applies open/idle limits and idle expiry, including zero
idle retention, and disables SQLx's default maximum connection age.

This introduces a local SQLx-core 0.8.6 source patch for a native idle cap.
Excess returns close while retaining pool permits through close/cancellation;
the capped idle queue grows with actual retained connections. Unconfigured
pools keep the upstream queue. `vendor/sqlx-core/UPSTREAM.md` records provenance,
licenses and the changed pool files. Maintaining and rebasing this patch is
now part of dependency maintenance; outside workspaces enabling the Postgres
factory with `go-pool-compat` must carry the root Cargo patches. Generic
database embeddings do not select that feature. This batch has no build, audit,
load, cancellation or restart evidence for the patched driver.

The server and offline CLI now share pinned Go Postgres SSL boolean parsing.
True omits the mode (`prefer` by default); false disables TLS. Other
modes retain their configured spelling/whitespace in Go's raw DSN, including
empty values. The previous true-to-`require` mapping was stricter than Go.
Default preference permits plaintext fallback; deployments requiring transport
verification need an explicit verification mode. SQLx/pgx fallback details,
environment interactions and error behavior remain unqualified.

The capped SQLx pool now reuses the most recently returned connection and
removes expired idle entries without rotating healthy survivors or refreshing
their idle timestamps. Acquisition deadlines, connection checks and cleanup
scheduling still need driver qualification. No concurrency, cancellation or
resource-limit evidence was produced for these new maintenance paths.

Both production and offline policy now use one Postgres DSN scanner based on
pinned pgx v5.10.0. It retains Go append order, ASCII whitespace, quoting,
backslashes and duplicate handling, then encodes parsed values as URL query
pairs. This removes credential trimming and literal-percent reinterpretation.
The source retains the pgx MIT notice. Parser errors exclude raw DSN values;
unsupported pgx extensions fail explicitly rather than being ignored and
logged with their values. TCP SSL modes and explicit ports get case/range
checks, while Unix socket targets ignore SSL mode. Service files, multi-host
fallback, environment/default database handling, startup parameters and
transport behavior remain incomplete or unqualified. No build or execution
evidence covers the new scanner or its source-updated URL expectation.

The native SQLite/Postgres bridge now uses one connector attempt and leaves
pool acquisition deadlines to the caller. It no longer retries refused or
transient connection errors under SQLx's default 30-second budget. Postgres
also projects `PGCONNECT_TIMEOUT` into its connector deadline, retaining Go
signed parsing and wrapping nanosecond multiplication. Invalid/negative
settings fail without printing their contents. When no caller or connector
deadline exists, a database stall or capacity wait can be indefinite, as in
Go; caller cancellation remains part of the ownership contract.

Postgres return/reuse callbacks drain pending work and queued rollbacks,
then reject managed transactions and non-idle ReadyForQuery transaction
status. One additive accessor in a vendored SQLx-postgres 0.8.6 patch exposes
the wire status, including raw SQL and failed transaction blocks. Its pin,
checksum, retained licenses and changed file are recorded in
`vendor/sqlx-postgres/UPSTREAM.md`; parity CI watches it. Reuse timing now
follows pgx's first-reuse or greater-than-one-second conditional simple
`-- ping`, including time checked out. The extra SQLx release ping is disabled
only after installing the drain/status callback. Default pools retain it.

Fresh schema creation and both legacy SQLite copy/rebuild transactions now
request `BEGIN IMMEDIATE`. The CLI selects the `go-pool-compat` feature for
the native pool APIs; generic database users do not need the patched APIs.
These connection, cancellation, raw-transaction, feature-boundary and schema
changes have no new build, advisory, process, load or restart qualification.

The native Postgres constructor now resolves pgx defaults/environment,
selected service-file settings and explicit values in pinned precedence.
It uses real-UID user/home lookup through the already-locked nix 0.31.3 user
feature, then follows Go service/passfile parsing and empty-password lookup.
Individual scanner lines are bounded at 64 KiB. Whole files and local file I/O
remain unbounded; connector deadlines apply after configuration resolution.
Go's ignored passfile errors and lack of permission-bit rejection are retained.
These files and environment settings are trusted operator inputs and can
contain credentials. Non-UTF-8 inputs are rejected rather than silently
replaced or ignored; parser errors omit raw values.

Native startup now sends configured runtime parameters without SQLx's extra
implicit timezone/encoding/float settings and omits an empty database field.
Connector timeout uses the final merged setting, including service/explicit
overrides. The source paths are separate from ordinary SQLx constructors.

Source inspection also found that SQLx TLS was not enabled: `prefer` selected
plaintext even when a server could offer TLS, and mandatory modes failed.
The native database feature now selects the existing AWS-LC Rustls provider,
reusing locked Rustls 0.23.46 and webpki-roots 1.0.5. The vendor core dependency
requirement was changed to reuse that root package. Native CA files now replace
built-in roots, and `require` with a CA maps to CA verification without hostname
verification, as in pgx. Generic certificate-file inputs retain their existing
policy. Prefer/allow modes still permit plaintext; operators requiring endpoint
verification need an explicit verification mode. These new TLS paths have no
handshake, certificate, process or advisory qualification.

Native verified modes without an explicit CA use OS roots, and the explicit
system-root setting forces full endpoint verification as in pgx. Rustls uses
a process-cached OS store. The core now reuses locked rustls-native-certs
0.8.3 as a required dependency, preserving its old feature name for callers
and avoiding a switch to SQLx's Ring-provider feature. Root-loader failures,
OS/platform trust differences and cache timing remain unqualified.

Native multi-host and TLS/plain preference chains are now implemented with
fresh sockets, original TLS hostnames and per-adjacent-address-group deadlines.
The native connector expands candidates before dialing, stops on the three
pinned authentication/database/permission SQLSTATEs, supports all six session
targets and retries the last nonpreferred standby candidate once. Rejected
connections have bounded owned cleanup. DNS uses the caller's deadline.
Native TCP uses Go's supported keepalive defaults through already-locked
socket2 0.6.1, ignoring socket-option errors. The pool factory performs Gorm's
initial simple ping separately from later reuse checks.

CA files are now read and parsed before mode validation or dialing, including
TCP TLS-disable configurations. Enabled client cert/key pairs are parsed and
matched before connection attempts. Shared canonical PEM snapshots prevent
later file changes from altering fallback trust or identity. Local material
failures cannot select plaintext fallback. Inline TLS material, passwords and
arbitrary runtime settings are redacted in connection-option diagnostics.
The system-root override also replaces invalid SSL modes. Whole files/local
file reads remain unbounded, and Go passfile permission semantics are retained.

Native direct TLS uses PostgreSQL ALPN and promotes prefer to require. SNI
suppression follows pgx's verify-full exception, retaining the verification
hostname and DNS SNI in that mode. The native handshake explicitly selects the
preflight Rustls backend even if another dependency enables native-tls.
CA-only verification now handles both Rustls hostname-error variants after
chain verification. Prefer/allow still intentionally permit plaintext.

Native authentication now parses/enforces require_auth method policies before
sending credentials and checks whether authentication completed when required.
It supports channel_binding prefer/disable/require and SCRAM-PLUS using the
actual negotiated TLS certificate, with Go's supported signature-hash rules
and RSA-PSS constraints. Required binding is checked during SCRAM, as in pgx;
require_auth controls whether that exchange must occur. Kerberos settings are
inert for other methods; GSS fails with the pinned no-provider error after
policy checks. Pinned headscale/Gorm register no GSS or OAuth provider callback.

The native SCRAM path now checks server nonce extension, bounds PBKDF2 at the
pinned ten-million-iteration ceiling and verifies the server proof in constant
time. Password normalization follows x/text v0.38.0 OpaqueString space/NFC and
context rules with Unicode 15.0.0 property ranges imported from pinned source.
Invalid profiles retain the original password bytes. The Go BSD license and
source hash are recorded. Authentication directly reuses locked x509-parser
0.18.1 and unicode-normalization 0.1.25; this changes dependency edges without
resolving new versions. Vendor license metadata records the adapted Go MIT/BSD
components. Original notices are retained in `LICENSE-GO-PGX` and
`LICENSE-GO-TEXT`, and both container recipes now include the vendor license
files in their runtime images. No image build or fresh license/advisory check
qualifies those changes.

Source inspection also found unchecked indexing of malformed auth/SCRAM,
ReadyForQuery and backend-key bodies, an invalid-username panic, and missing
generic SCRAM nonce/iteration checks. The patch makes these paths fallible.
No adversarial execution qualifies these repairs. PBKDF2 remains synchronous
up to the ceiling, and Unicode/import/normalization, certificate/PSS parsing,
malformed-frame handling, auth fallback/error ordering and cancellation/load
behavior remain unqualified.

Native protocol selection now accepts Go's 3.0/3.2/latest settings and implicit
maximum promotion, sends the chosen version, validates negotiated minimums and
retains complete variable-length backend cancellation keys. Key diagnostics are
redacted; negotiation-option counts cannot allocate beyond the received body.
SQLx has no cancellation API using those keys. No negotiated-version, malformed
frame, resource or cancellation execution qualifies this code.

The native local-key loader now ports Go 1.26.9 PEM selection, whitespace,
headers and base64 behavior. It honors the first usable key block and detects
the DER format independently of label spelling. Client certificates accept
headers while CA blocks with headers are skipped. Encrypted RFC 1423 PEM uses
sslpassword, MD5/IV-salt derivation and AES-128/192/256, DES or 3DES CBC through
locked AWS-LC 1.18.2. Decoding/decryption and key-pair validation occur before
connection attempts; invalid inputs cannot select plaintext fallback.

The optional SQLx-core go-pem-compat feature selects AWS-LC non-FIPS/legacy-DES
and sys all-bindings through the explicit database Go bridge. Ordinary SQLx
configurations do not enable it. It decrypts existing operator-supplied local
files and does not change TLS cipher suites. The legacy file format retains
Go's unauthenticated MD5/CBC design. Go standard-library BSD notices are kept
in LICENSE-GO-STDLIB and included by the container vendor-license copies.
No build, crypto fixture, FIPS, bindings, feature, image, advisory or license
evidence qualifies this new activation.

All five native query modes now dispatch to cached statements, cached
descriptions, per-query descriptions, text extended execution or simple SQL.
Nonpositive signed-32-bit cache capacities disable caches, and argument-free
queries always use simple protocol. Failed queries invalidate metadata and
defer named-statement cleanup until the next operation. Complete execution
frames are encoded off-transport before append, avoiding partial protocol work
on client conversion/encoding failure.

Native automatic cache names now follow pgx's truncated SHA-256 scheme.
Preparation/close frames are staged before append; a preparation drop guard
retires names on failure/cancellation, and close IDs remain queued until the
whole close cycle succeeds. Explicit cache clearing follows that queue.
`describe_exec` reparses after custom-type metadata lookups can replace the
unnamed statement, and ReadyForQuery counts reject underflow. Cancellation,
resource cleanup and failure ordering remain unqualified.

The source pass found unchecked inbound value ranges, primitive reads, JSONB
assertions and date arithmetic in vendored result decoding. Row/description/
notification/COPY counts and nested value bounds are now checked before
allocation or indexing; native row counts must match cached metadata. Primitive
widths, numeric digits, array/record/bit-string/geometry bounds, JSONB versions
and date/timestamp overflows now return errors. Text arrays preserve quoted
NULL strings, and record decoding preserves Unicode and trailing NULL fields.
Text ranges reject malformed bounds, quoting and field counts. A malicious
or compromised database endpoint could reach the affected decoder paths;
this review has not executed an exploit or measured availability impact.
These guards also apply to generic SQLx callers sharing the decoders. This is
not a complete malformed-server or custom-codec audit.

Parameterized simple SQL uses a lexer ported from pinned pgx with quote,
identifier, E-string, dollar-string and nested-comment handling, placeholder
usage/overflow checks and argument-boundary spaces. It requires the server to
report UTF8 and standard_conforming_strings=on. Values are text-converted then
quoted/escaped; logging keeps the original query template. The conversion path
supports common scalar/JSON/date/network/array/enum/domain values and rejects
unsupported codecs without logging raw values. Ordinary SQLx execution stays
on its separate existing path.

No build, lexer/SQL-injection fixture, query-mode, codec, cache/schema drift,
load, cancellation, malformed-input or paired process evidence qualifies this
source. Auxiliary/custom codecs, Go encoding-plan/cast-error ordering, explicit
prepare/persistence behavior, explicit statement names/lifetimes, text row decoding and
multi-result semantics remain incomplete or unqualified. Weak/degenerate DES
compatibility remains incomplete: the backend rejects keys Go accepts. Native
unencrypted keys ignore sslpassword as in pgx. PEM layouts/algorithms and file
error ordering, malformed inputs, resolver/platform trust and identity,
disabled caches, timestamp codecs, fallback diagnostics and the dependency
features remain unqualified. Both vendor provenance files list these changes.
No build, test, handshake, process, network probe or advisory validation was
run for this source batch.

## Risk summary

The control plane is a network trust authority. Administrative compromise can
enroll peers and change ACLs, SSH policy, routes and DNS. The database exposes
user identities and network topology; the Noise private key identifies the
server to clients. A control-plane or DERP operator does not thereby obtain
clients' WireGuard private keys or automatically decrypt existing peer traffic.
The impact of changing peer and routing policy is still substantial.

The source review covered production listener routing, admin authentication,
OIDC state/nonce/token checks, policy mutation/reload, key-file persistence,
database queries/migrations, optional gateway/HTTP surfaces, dependency features,
container defaults and CI coverage. It did not exercise an external production
deployment, prove absence of authentication bugs, or measure a resource
exhaustion attack. Findings below distinguish source observations from paired
process evidence.

## Security fixes in this change set

- **Private key creation:** Noise and self-signed TLS writers previously
  created predictable temporary paths using the process umask, wrote secrets,
  then changed permissions to `0600`. With a permissive umask, a local account
  able to traverse the directory could read a key during that interval; an
  account able to write there could pre-create a temporary symlink. Both paths
  now use random temporary filenames, exclusive creation and permissions set
  at file creation, followed by sync and rename. The regression
  `generated_keys_ignore_legacy_temp_symlinks_and_are_private` checks both key
  writers leave a symlink target unchanged and persist private files. Existing
  operator-supplied key permissions remain an operator responsibility.
- **OIDC startup availability:** provider discovery had no explicit request
  timeout. It now uses the pinned Go 30-second deadline, including body reads.
  Eight paired cases (16 production processes) cover stalled headers and body,
  required/optional availability, and configtest/serve. All passed in
  `target/real-client/oidc-startup-deadline-1792244012-57734/report.json`.
- **Policy validation:** startup, check/set and reload now reject ambiguous
  user references before replacing a policy. Failed reload preserves the
  live policy. The separate paired policy/startup corpus has 192 exact policy
  output comparisons across SQLite/Postgres, eight OIDC availability pairs,
  and four malformed-policy rejection pairs. These fixtures establish their
  named behaviors, not general production qualification.

## Open findings and conditional exposure

| Priority | Finding and evidence | Exposure / required work |
| --- | --- | --- |
| P1, validation pending | Native TLS/Noise/DERP handshake deadlines and pending-handshake budgets are implemented, along with Noise idle/body deadlines. | Paired transport behavior, cancellation and burst/load qualification have not run for this implementation batch. |
| P1, validation pending | OIDC provider deadlines, bounded JSON reads, shared client, callback concurrency limits and JWKS caching are implemented. | Verify stalled providers, oversized bodies, refresh failure/coalescing, cancellation and normal login against pinned Go before claiming the finding closed. |
| P2, validation pending | OIDC EC/EdDSA/P-521 verification and discovery algorithm restrictions are implemented alongside the RSA/PSS path. | The previous mock-provider reports used RSA and predate this implementation; additional algorithm/claim/rotation qualification remains open. |
| Configuration dependent, validation pending | Vendored Postgres result decoders now check identified short bodies, counts, widths and date overflows; statement cleanup also retains interrupted preparation/close work. | The affected paths accept database-endpoint input. Malformed-server, codec and cancellation qualification remains open, including custom types and SQLx's signed COPY/array-shape limits. |
| Configuration dependent, validation pending | The CLI wrapper now checks malformed base64 status details before the pinned Tonic parser's expectation, in both initial headers and trailers. | A configured malicious server or intercepted insecure connection controls these response fields. The source guards have no malformed-peer execution evidence; other generated-client users and parser paths remain outside this fix. |
| P2, library only | The DID replay cache is now bounded, expires by server clock, and can be reused across router rebuilds. It is still volatile. Optional HTTP reads and self-signed registration remain public by design. | These routes are not mounted by production CLI `serve`. Embedders using a durable ledger must persist replay/idempotency state transactionally with transfers and qualify their admission/data-visibility policy. |
| Configuration dependent | Native embedded DERP admits arbitrary client keys when `derp.server.verify_clients=false`, the core config default. `attach_native_derp_runtime` installs the registry verifier only when enabled. | Enabling the native relay with verification disabled exposes relay bandwidth to unregistered clients. Set `verify_clients=true` for a private tailnet and qualify the admission configuration. This does not reveal WireGuard plaintext. |

P1 here identifies an availability concern to resolve before an unrestricted
Internet deployment; it is not a measured CVSS score. P2 items are narrower
compatibility or optional-embedding limitations. The separate two P0 parity
items continue to block a full Go replacement claim.

## Dependency findings and changes

| Finding | Exposure in this repository | Action |
| --- | --- | --- |
| `h2` 0.4.13, [RUSTSEC-2026-0258](https://rustsec.org/advisories/RUSTSEC-2026-0258.html) | Active in the Noise `/ts2021` HTTP/2 server, Hyper and tonic. Crafted empty DATA frames could exhaust memory. | Raise the direct minimum to 0.4.19 and add a tracked lockfile resolving 0.4.19. |
| `rustls` 0.23.36, [RUSTSEC-2026-0285](https://rustsec.org/advisories/RUSTSEC-2026-0285.html), [0346](https://rustsec.org/advisories/RUSTSEC-2026-0346.html), [0348](https://rustsec.org/advisories/RUSTSEC-2026-0348.html), [0349](https://rustsec.org/advisories/RUSTSEC-2026-0349.html) | Active for public TLS, remote gRPC TLS, ACME and outbound HTTPS. The Brotli issue requires the nondefault Brotli feature, so the advisory is not uniformly exploitable in this build; the ServerHello issue concerns outbound TLS session reuse, not authentication bypass. | Raise the direct minimum to 0.23.46 and add a tracked lockfile resolving 0.23.46. |
| `quinn-proto` 0.11.14, five 2026 RustSec advisories | Pulled into the lockfile by reqwest's optional HTTP/3 support; this workspace enables HTTP over Rustls, not HTTP/3. It becomes relevant if that feature is enabled later. | Resolve the lockfile to 0.11.19. |
| `rsa` 0.9.10, [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) | Pulled into the lockfile by disabled `sqlx-mysql`. RustSec reports no patched version; the active feature graph excludes it. | Keep the existing lockfile-only audit exception scoped to this advisory. Revisit before enabling MySQL. |
| `proc-macro-error2` unmaintained and `spin` 0.9.8 yanked | The former came through `local-ip-address` in CLI node mode; the latter through SQLx SQLite. | Replace interface enumeration with `if-addrs` and resolve `spin` 0.9.9. Feature-aware `cargo deny check advisories` passes. |

The root `Cargo.lock` is now included in the change set, and the container builds use
`cargo build --locked`. Supply-chain CI audits that same lockfile rather than
generating a new dependency graph for every run. A fresh advisory feed can
still discover new issues after this review.

The fuzz harness has its own lockfile. Its audit independently found stale
`h2` 0.4.14 and `rustls` 0.23.40 plus the `anyhow` 1.0.102 and `event-listener`
5.4.1 unsoundness warnings. That lockfile now resolves `h2` 0.4.20, `rustls`
0.23.46, `anyhow` 1.0.104 and `event-listener` 5.4.2, and its independent audit
passes without an advisory exception; the application audit alone does not
cover it. The latter two warnings concern fuzz/build or platform-specific dependencies and are not
evidence of an exposed production endpoint.

The Docker recipes used Rust 1.82 despite the workspace's 2024 edition,
expected an ignored lockfile and omitted current workspace sources. Both now
use the official Rust 1.99 Bookworm image, copy the filtered repository
context and build with `--locked`; the server runtime image includes `curl`
for its configured health check. The bundled Docker server config also lacked
the required Noise key path, server URL, DNS settings, and database type; it
now passes `configtest` and serves `/health` with a writable data volume.
Both Docker default commands now name CLI subcommands that exist (`serve`
and `mesh-node`). The real-client CI checker also found seven
paired Postgres rows present in the matrix but absent from the PR selection;
those rows are now included.

## Exposed interfaces and deployment boundaries

- The example container publishes plain HTTP on `0.0.0.0:8080`. Put a trusted
  TLS terminator in front of public control/OIDC traffic or configure native
  TLS, and set `server_url`/OIDC redirect URLs to the external HTTPS origin.
  The container example is a development topology, not an Internet-facing
  secure deployment recipe. OIDC uses state/nonce cookies, one-time callback
  state, and `Secure` cookies when its configured redirect URL is HTTPS.
- The optional node container runs as root with `NET_ADMIN`, `NET_RAW`, and
  `/dev/net/tun`; it is a privileged test topology and should not be treated
  as a hardened control-plane image.
- Remote admin gRPC is disabled without TLS unless
  `grpc_allow_insecure=true`; enabled TCP gRPC requires an API key. The local
  Unix gRPC socket is unauthenticated and defaults to mode `0770`, so socket
  group membership is administrative access. Do not publish it as a volume to
  untrusted workloads.
- Metrics are disabled by default. When `metrics_listen_addr` is configured,
  `/metrics` is unauthenticated; `/debug/*` has peer-IP/key access checks.
  Bind this listener to a private interface or protect it at the network
  layer. Diagnostic output can expose topology and runtime metadata.
- Pre-auth and API key secrets are bcrypt-hashed in the database. Protect
  server Noise keys, OIDC client secrets, API-key configuration, DB backups and
  the admin socket; possession of live credentials or the admin socket gives
  control-plane authority.
- Public control uses custom Noise and DERP protocol handling. Fuzz and
  paired stock-client coverage exist, but the two open P0 parity gates include
  production release behavior and broader Postgres mutation/restart cases.
  Until those pass, treat ACL/SSH revocation, route changes and identity
  transitions as unqualified for replacement deployment.
- A disconnect now writes LastSeen to SQLite/Postgres at stored timestamp
  precision as well as updating the live registry. The write is best-effort,
  matching upstream; a crash before it completes can still leave the prior
  persisted value.

## Upstream watch

At review time [headscale-go v0.29.5](https://github.com/juanfont/headscale/releases)
is the latest release and remains the pinned comparison baseline. Its October
13 release includes route steering, logtail, map ping, self-route refresh,
SSH verdict replay and policy invalidation fixes. The paired
`postgres-route-approve` run now asserts the router's own `AllowedIPs` and
`PrimaryRoutes` before approval, after approval and after restart against both
servers. The [Tailscale release stream](https://github.com/tailscale/tailscale/releases)
has v1.104.1 as latest at this review; continue stock-client checks as client
capabilities move beyond the current test binary.

The [unreleased 0.30 changelog](https://github.com/juanfont/headscale/blob/fc97593bcea76c92fb3ad41a5b95076684ddc85a/CHANGELOG.md)
also matters: it removes gRPC, adds scoped OAuth credentials, and merges
credential tables through an irreversible migration. Treat adopting that
database/API as a separate migration target. Security backport candidates
include rejecting old clients before registration side effects and rechecking
node state when a failed pre-auth key request races with expiry/rekey. The
Rust entry point already checks capability before `register_inner`; the
current failed-key branch returns its error directly and persistent transactions
recheck authorization state. The related in-memory admin/rekey mutation gaps
described above are repaired in source; the concurrent failed-key case still
needs a targeted adversarial fixture.
These are observations from unreleased upstream code, not an announced 0.30
release or proof the Rust race is exploitable.

## Audit commands

```sh
cargo audit --deny warnings --ignore RUSTSEC-2023-0071
cargo audit --file headscale-core/fuzz/Cargo.lock --deny warnings
cargo deny check advisories licenses sources
cargo fmt --all -- --check
HEADSCALE_DB_POSTGRES_TEST_URL=postgresql://headscale@127.0.0.1:5432/postgres cargo test --workspace --quiet
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p headscale-api --no-default-features --tests -- -D warnings
cargo check --locked --manifest-path headscale-core/fuzz/Cargo.toml --bins
tools/real-client/smoke-matrix.sh --check --all --both
```

The last validated snapshot, before the implementation-only batch above,
passed both advisory audits, feature-aware advisory/license/source policy,
strict workspace and wire-only Clippy, formatting, and the full workspace
test suite with Postgres enabled. The API unit suite reports
944 passing tests and one ignored test; a separate doctest is also ignored.
The four excluded path crates were tested explicitly using
`cargo test --manifest-path <crate>/Cargo.toml --all-targets --quiet`; all passed.
All fuzz targets pass a locked compile check; that check is not a fuzz campaign.
The temporary Postgres cluster was stopped after the full test run.

The paired startup corpus has 192 exact policy comparisons without a mismatch,
eight OIDC availability pairs and four malformed-policy rejection pairs. The
16 additional stalled-discovery processes passed with measured discovery times
of 30.009–30.056 seconds. CI requires both startup harnesses. The earlier paired
Postgres route-approval row also passed, including router self-map changes and
durable offline `LastSeen`. The two P0 parity gates and the open findings above
remain unqualified by these bounded tests.
