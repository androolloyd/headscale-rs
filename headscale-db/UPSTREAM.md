# Upstream source provenance

## Scalar addresses and backfill

`src/stored_text.rs` follows headscale-go v0.29.5
`hscontrol/db/text_serialiser.go`: SQL NULL differs from a present empty Addr;
non-null text/blob values use typed text decoding. Node address fields retain
Option<String> while validating/canonicalizing through the shared netip leaf.
Create, auth-path and IP-only updates validate before SQL mutation. Allocator
startup uses a raw nullable text adapter before applying ParseAddr, where empty
text rejects. Postgres bytea goes through SQLx's bytea codec when present.

Transactional IP batch setters roll back all row writes on failure. Reservations
remain the allocator's responsibility, matching the pinned backfill ownership.
IP update timestamps retain subsecond precision. Backfill ordering, quoting,
guards and live refresh are in the API adapter. After an IP change it reloads
all live database nodes and publishes one quiet NodeStore batch, merging live
Hostinfo by stable ID inside the writer. This is unqualified source behavior.

Baseline: `github.com/juanfont/headscale` v0.29.5, commit
`0f7d1e536bed9f01dd7161f7637af19bb0908335`.

- `hscontrol/db/text_serialiser.go` SHA-256: `f5dd1cec4c69bdd2e36005065613d057ce6f2b6a05ff75096b4cd7449d4a1297`.
- `hscontrol/db/ip.go` SHA-256: `190e8a05be4b16fe24dfaa0c758c59ae595f02b7501fa9f50b565b4b87786071`.

Headscale copyright/BSD terms are retained in NOTICE-HEADSCALE-GO and
LICENSE-HEADSCALE-GO and copied by both container recipes. No external release
changed. This source batch is unbuilt/unexecuted. Null/zero/UTF-8/blob/bytea/zone/
cross-family values, type compatibility, rollback, resource use and process/
restart require qualification. Raw invalid-UTF-8 zone strings, native unusual
address projection, wider wire JSON/projection and exact errors remain open.

## Public keys and Hostinfo

Machine, node and disco keys use strict typed text column adapters. SQL NULL
produces the full prefixed zero key; present empty stored text fails. Writers
interpret omitted constructor Strings as typed zero defaults, reject malformed
keys before mutation and store canonical lowercase text. Identity lookup and
optimistic runtime comparisons normalize imported hex case and nullable zeros.
Auth-key transactions compare fallible canonical identities. Native known-key
lookups resolve the registry's stable ID before reading SQL. Normalized cold
lookups and complete ownership candidate scans still need resource evaluation.
The shared Tailscale parser/provenance is in headscale-api-acl/UPSTREAM.md.

`src/stored_hostinfo.rs` delegates to the maintained pure decoder in
headscale-api-acl/src/go_tailcfg_json.rs for the pinned tailcfg Hostinfo, NetInfo,
Service, Location and TPMInfo schema using the shared Go JSON scanner. It preserves
ordered duplicate fields, nested object/map merges, slice backing-array reuse,
scalar/null defaults, opt.Bool explicit unset and Unicode-aware field folding.
Known numeric widths follow 64-bit Go; prefixes validate through shared netip.
Unknown subtrees are scanned without materializing them. Nil/empty database
values remain nil Hostinfo; nil writes bind SQL NULL per Gorm JSONSerializer.
Writes validate before SQL mutation, and native registration/route updates use
fallible accessors. Diagnostic errors do not include client field values.

Tailscale v1.98.3 source SHA-256:

- `tailcfg/tailcfg.go`: `13bde37c19d7f841e494a49ee3bad60b92e242ba8361f3ed4965b801f757ebf2`.
- `types/opt/bool.go`: `c2a3278ee70ce84d24eab7c4d54a8c37804a280dce718b3a8b222b138b798718`.

NOTICE-TAILSCALE and LICENSE-TAILSCALE retain the original copyright/BSD terms
and are included by both runtime container recipes. No dependency version was
changed. Existing positive SQLite/Postgres node fixtures were source-adjusted
to real 32-byte key text; no test or build was run. SQLx custom types, malformed
rows, slice/merge/numeric/UTF-8 behavior, resource use, identity lookup cost,
concurrent writers, cancellation, process and restart behavior remain unqualified.
The public wire model still cannot preserve every Go int-width, nil Hostinfo or
explicit-unset distinction. Native wire projection now rejects unrepresentable
values instead of silently replacing the whole snapshot with defaults.

## Go JSON scanning and Gorm string-list decoding

`src/go_json.rs` now re-exports headscale-api-acl::go_json. This is the shared
byte scanner previously kept in the standalone CLI service-config path. It adapts the Go 1.26.9 `encoding/json` scanner, depth
limit and string unquoting. The CLI keeps its own error-envelope adapter.
Database string-list decoding also follows Gorm JSONSerializer.Scan: an empty
database value is not unmarshaled; JSON null is a nil slice; null elements of
a fresh string slice retain empty strings. Other element types fail.

- Go 1.26.9 `src/encoding/json/scanner.go` SHA-256: `2b16dd215274dfa8e0806b53cca144684d5b9c8a02319cf5ce10120c50e6eef2`.
- Go 1.26.9 `src/encoding/json/decode.go` SHA-256: `a91535f18f9a2c8380448b1c84c4c2017dbe3d530a10faf8babf03494042da48`.

Gorm reference: `gorm.io/gorm@v1.31.1/schema/serializer.go`,
JSONSerializer.Scan, as pinned by headscale-go v0.29.5.
SHA-256: `9dadcf607eccadd1f6cab29f72a95d8ff7c683e20dd412f585a5b5d15797a1a8`.
The original Go copyright and BSD license are retained in
`NOTICE-GO-STDLIB` and `LICENSE-GO-STDLIB`; package metadata records BSD-3-Clause.
Both container recipes copy those notices. No dependency release changed.

This is source-only work. No build, malformed-input/depth/resource execution,
SQLx feature, package/license, container or Go/Rust process qualification covers
the extraction or the database row adapter. Exact parser/driver diagnostic text
and SQL transport encodings remain unqualified.

## Stored endpoints and route prefixes

Node endpoints and approved routes now pass typed netip text decoding during
SQLx FromRow conversion, using `headscale-api-acl::go_netip`. The same source
handles map endpoint strings. Empty/null array slots retain Go zero values;
nonempty endpoint/prefix text is validated and canonicalized without masking
prefix host bits. Endpoint and route write paths validate before SQL mutation.
The native approved-route comparison follows Go 1.26.9 Prefix.Compare: masked
address, length, then original address, with invalid zero prefixes first.
The admin proto projection renders a zero approved prefix as `invalid Prefix`.

The Go netip source hash and license are recorded in
`../headscale-api-acl/UPSTREAM.md`. The direct leaf-crate dependency reuses the
existing locked workspace package; no external version was resolved. No build,
row/write/map/zone/prefix/Unicode comparison, resource, feature/license/container
or process evidence qualifies these changes. Other route normalization sites,
Hostinfo decoding, broader wire JSON and exact errors remain open.

## Policy-derived approval persistence

Create, auth-path and runtime CreateParams now serialize typed approved prefix
vectors directly, preserving order/duplicates/zero text and a single default.
The explicit admin SetApprovedRoutes normalization remains its own operation.
The policy-specific SQLite/Postgres approval-only helpers remain for headless
adapters without a NodeStore. Attached native stores now use
save_cached_node_snapshot/save_postgres_cached_node_snapshot. CachedNodeSnapshot
implements the explicit Go State.persistNode column mask, excluding expiry,
auth-key references, CreatedAt and DeletedAt. Typed zero/nil values bind directly;
there is no NULLIF scalar rewriting, upsert, missing-row insertion, deleted_at
filter or affected-row rejection. UpdatedAt uses a fresh clock, following Gorm's
update hook. Per-node failure retains partial durable progress after the live
batch, without a full-batch database transaction.

The shared Hostinfo writer now applies pinned zero-field omission, opt.Bool
explicit unset, non-nil nested pointers and required Service Proto/Port fields.
Nil root values bind SQL NULL. This provides semantic typed JSON emission, not
qualified exact key-order/float/escaping bytes.

Reference: Headscale v0.29.5 state/state.go (persistNode/nodeUpdateColumns),
SHA-256 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01;
Gorm v1.31.1 callbacks/update.go (auto update clock). Tailscale Hostinfo source
hashes and retained BSD notices remain above and in the shared ACL package.
Full cache/row equivalence, nullability, timestamps, failed/missing/soft-deleted
rows, restart and SQLx/feature behavior are unqualified. No tests, builds or
runtime validators ran. No external dependency version changed.

## Policy history clocks and inserted-row returns

src/policies.rs now stores a fresh subsecond policy clock, using one timestamp
for CreatedAt/UpdatedAt (SQLite nanoseconds; Postgres microseconds). All setters
return the inserted row in the INSERT RETURNING statement, as pinned Gorm
Create with clause.Returning does. They no longer perform a separate get_by_id
that can observe a subsequent deletion or external edit. New timestamp-aware
get/set helpers expose TimedPolicyRow without changing PolicyRow's existing
fields. SQL NULL UpdatedAt retains Go's year-one time.Time zero in that precise
projection; ordinary stored RFC3339/Gorm timestamp text retains its fraction.
Older helpers still return whole-second PolicyRow data.

References: Headscale v0.29.5 hscontrol/db/policy.go (SetPolicy/GetPolicy),
SHA-256 59aca2ef1a9d8a0187ffd37df1c40ad12ed2a5b63c8f4c7825118a5809950746;
hscontrol/types/policy.go (gorm.Model), SHA-256
ae45869c30684f8a08388db3f0c97b9aab7c386abfe35137269a9b8119ec0ac9.
The retained Headscale BSD notices cover these adapters. No external dependency
version changed. Native fractional clocks, NULL/zero/unusual/malformed dates,
driver conversions, SQLx FromRow/flatten/RETURNING behavior, external writers,
triggers, cancellation/resource use, feature/client/process/restart and package/
container behavior are unbuilt and unqualified. No tests or validators ran.

## Native expiry-only updates

save_cached_node_expiry/save_postgres_cached_node_expiry implement the selected
expiry and automatic UpdatedAt update used by Go DB.NodeSetExpiry. They bind
nullable expiry directly and preserve subsecond clock precision. WHERE id alone
matches Go Node's plain *time.Time DeletedAt field; no new soft-delete filter,
missing-row insertion, affected-row rejection or post-write node lookup occurs.
Attached native admin callers update the live registry before this save; headless
legacy setters retain their existing contracts.

Reference: Headscale v0.29.5 hscontrol/db/node.go NodeSetExpiry, SHA-256
9b1badd1eba80662eccb1eb5e2d0f039967b6469a30fab6fb3904466de234bb4.
Existing BSD notices/terms remain retained. No external version changed.
Clock/NULL/zero/missing/soft-deleted row behavior, driver/type/feature semantics,
SQL failure/retry, lock/cancellation/resource and client/process/restart remain
unbuilt/unexecuted and unqualified. No parity gate is closed.

## Cached-ID deletion and shared DNS labels

New destroy_cached_node/destroy_postgres_cached_node helpers mirror pinned
DB.DeleteNode: DELETE by the authoritative cached ID with no affected-row error
or pre-delete row lookup. Native attached admin/ephemeral callers use these;
legacy headless destroy methods retain their existing lookup/error contract.
DB label validation now delegates to the shared pinned dnsname leaf, whose
source hashes/Go diagnostic quoting provenance are recorded in the ACL package.
References remain Headscale v0.29.5 hscontrol/db/node.go and types/node.go,
with existing BSD notices retained. No dependency version changed. Missing/failed
SQL deletion, identity/external writers, transaction/trigger/type behavior, label
errors, native features and client/process/restart remain unbuilt/unqualified.
No test or executable validator ran and no parity gate is closed.

Attached native map callers now use CachedNodeSnapshot's full selected-column
save and no longer use update_runtime_state/update_postgres_runtime_state to
re-read or optimistically merge SQL runtime rows. Those older helpers retain
their headless/custom contract. Attached user logout uses the narrow cached-node
expiry update after a quiet live mutation; it does not re-read unrelated SQL
columns. These call-path changes are unbuilt/unexecuted and do not close any
native process/restart, row/error/feature or replacement qualification gate.

## Cached existing-node registration saves

`headscale_nodes/cached_registration.rs` adds Go's existing-node auth column mask
on a live CachedNodeSnapshot: precise Expiry is included; AuthKeyID is either
omitted or explicitly set/cleared. CreatedAt/DeletedAt stay outside the mask,
WHERE selects the stable ID without a soft-delete condition, zero affected rows
are success, and no name lookup/insert occurs. SQLite/Postgres connection helpers
allow credential consumption in the same transaction. `auth_key_registration`
cached entry points retain credential verification/row locking but use the
caller's live node projection for tags/expiry/binding validation, without an SQL
node re-read. An unused one-shot key is consumed even on a validation-skipping
refresh; an already used key is not consumed again.

This follows pinned Headscale v0.29.5 state/state.go applyAuthNodeUpdate and
RegisterNodeWithPreAuthKey, using the source hash and BSD terms already recorded.
Existing fresh/headless entry points keep their own contracts. Direct rustfmt
only; no builds, tests, process/restart, failure/rollback, concurrency/resource,
feature/package/container or advisory/license evidence qualifies these changes.

## Fresh registration inserts — 2026-10-18

headscale_nodes/new_registration.rs follows pinned State.createAndSaveNewNode:
native fresh inserts retain nullable slices, empty scalar text and the initial
sanitized name without SQL name selection/retries. The insert returns its ID and
an initial typed projection with original pre-marshal Hostinfo and timestamp
precision, not an SQL row reread. The NodeStore name bump happens after commit
and can remain live-only until a later save. Dedicated auth_key_registration
fresh entry points validate/lock the key and consume one-shot credentials in the
same insert transaction. Legacy/headless create helpers retain their contracts.

The source references are the existing Headscale v0.29.5 state.go/node_store.go
pins, text serialiser and Gorm v1.31.1 JSONSerializer.Value; its nil JSON value
becomes SQL NULL. Gorm schema/serializer.go SHA-256 is
9dadcf607eccadd1f6cab29f72a95d8ff7c683e20dd412f585a5b5d15797a1a8.
The existing notices/terms apply. Direct rustfmt only; no build/test, key-failure,
SQL/cache/name/time/nil/cancellation/resource, feature/package/container, advisory
or paired process/import/restart evidence qualifies this source batch.

The Gorm JSONSerializer compatibility reference now carries LICENSE-GORM and
NOTICE-GORM in API and DB packages, and their SPDX expressions include MIT.
Existing container wildcard copies include these files. No package/image/license
validator ran, and no Gorm runtime dependency or release upgrade was added.

## Empty preauth-key display — 2026-10-18

PreauthKeyRow::display_key now returns an empty string when both the prefix
and legacy key are absent, following hscontrol/types/preauth_key.go Proto at
headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335.
SHA-256: 75f5ec4e1e0d73c2ea4bd3760f006b7b0587db3ade380c43bf839e7daf22a130.
Modern prefix masking and legacy plaintext display retain the same source
boundary. Direct rustfmt only; no build/test/process qualification ran.

## Direct preauth-key admin projection and expiry — 2026-10-18

Checked listing and optional native list/mint views retain loaded user and nullable
timestamps without changing stable public key or wire/policy fields. Native gRPC
projection avoids name re-resolution, preserves legacy display provenance and
uses strict numeric-owner minting. Storage failures propagate; REST/HTML lists
surface them. Creation captures time before RNG/bcrypt and retains the original
insert projection, including pre-SQL timestamp precision. Supported binary RPC
nanoseconds normalize like protobuf AsTime. Custom adapters retain default
fallbacks; no wire-only DB/core edge or external dependency was added.

Fractional key expiry, key-deletion cleanup (node scope corrected below) and
clearing-error propagation follow pinned DB behavior. In-memory missing-ID expiry/
delete and Used projection follow the same ordinary behavior. A non-nil auth-key
zero timestamp is expired; only NULL disables key expiry. Nodes separately disable
at exact Go zero time. Two obsolete assertions were source-adjusted, not executed.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. SHA-256:

- hscontrol/grpcv1.go: 1bb435c674a64b3a7d1382eddfc9b33d7fb8f646c414709d011508d0a2e883c3
- hscontrol/db/preauth_keys.go: 732667bea9f0f766aeeea919d894f0761bfe88b3e5babcdb4d4d3cd6d19ed4a6
- hscontrol/types/preauth_key.go: 75f5ec4e1e0d73c2ea4bd3760f006b7b0587db3ade380c43bf839e7daf22a130
- hscontrol/types/node.go: b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab

The original BSD notices/license remain retained. Transaction/cancellation and
snapshot coherence, exact raw SQL/driver/encoding diagnostics, Go-wide dates/IDs/
bytes, malformed native values, custom/headless/legacy flows, SQL rounding/
trigger/FK failures and concurrent cached-node/raw-writer behavior remain
incomplete or unqualified. Direct rustfmt only; no build/test/validator/probe,
package/container/client/process/import/restart or dependency/advisory refresh.
All three release gates remain open.

Headless node RPC fallback also uses native preauth views and numeric node user
association lookup when available, retaining label-only custom fallback behavior.
These additional projections are source-only and share the same unqualified gates.

## Preauth transactions and owned completion — 2026-10-18

Key minting now reads its user and performs hash/insert/commit in one transaction,
returning the captured UserRow for native RPC/UI projection. Original public
Created methods retain their type. Raw-name conversion is shared with existing
native node association reads. Alias/UI mints switch to strict numeric binding
after a configured user resolver selects the account. No late user-directory
read substitutes for the captured association.

Native listing batch-preloads active referenced users within the key read
transaction and rolls it back. SQLite uses BEGIN IMMEDIATE for both read and
write transactions, matching sqliteconfig.Default; Postgres keeps normal
transaction settings and supports connection-scoped nested savepoints. Expiry
also captures time after explicit transaction begin and commits before success.

Persistent list/mint/prefix/ID-expiry/delete futures now use owned completion,
and authorized CreatePreAuthKey owns its initial lookup through response
construction. Request reset does not abort started work; plaintext remains a
one-time result without an adapter cache. Process/runtime shutdown and exact
failure/resource/concurrency behavior remain unqualified.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. SHA-256:

- hscontrol/db/db.go: 141d70c4fb38ebfdfdbb072de70d56b1620a15d25357a5b012685a8df7bfc024
- hscontrol/db/sqliteconfig/config.go: b7de3e1c851e25cdc1d55fb9bf7699e631d6ed1ecbdc5aa45b760dbea3a55b45
- hscontrol/db/preauth_keys.go: 732667bea9f0f766aeeea919d894f0761bfe88b3e5babcdb4d4d3cd6d19ed4a6

This supersedes the earlier mint/list transaction and request-reset source gaps.
Credential lookup/preload/hash ordering, account/cache races, coherent native
node/side-metadata views, exact SQL/driver/savepoint/commit/rollback diagnostics,
resource/bind/pool/deadlock limits, native nil/zero/wide/invalid data, custom/
headless/direct-DB callers and all native/wire-only/package/container/client/
process/import/restart evidence remain incomplete or unqualified. Direct rustfmt
only; no build/test/validator/probe/advisory/dependency refresh. Existing notices
and licenses remain retained. Public wire/policy field types and the wire-only
DB/core graph are unchanged. All three release gates remain open.

## Credential preload and captured lookup — 2026-10-18

Verified SQLite/Postgres lookup now preloads the key user before bcrypt and maps
preload/identity decode failures to the findAuthKey record-not-found sentinel.
Missing users remain nil. ORDER BY primary ID/LIMIT 1 follows Gorm First for
modern-prefix and legacy-key queries. Pool connections are released before CPU
verification; supplied connection/transaction contexts are retained. GetPreAuthKey
adds no transaction, following the pinned path separately from ListPreAuthKeys.

Optional PreauthLookup and registration-store entry points retain native loaded
key/user state across serving validation and native planning without changing
RedeemOk, MachineRecord or policy/wire field types. Native metadata uses loaded
Username/ID. Selection errors precede captured expiry/reusable/used validation;
same-node refresh skips it. Old/custom/wire-only methods retain default fallback
behavior. Modern lookup snapshots omit bearer secrets and bcrypt hashes.
Native planners check key ID, retain the captured key/user, and preserve the
separate existing node user. Credential reads use owned completion.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. SHA-256:

- hscontrol/db/preauth_keys.go: 732667bea9f0f766aeeea919d894f0761bfe88b3e5babcdb4d4d3cd6d19ed4a6
- hscontrol/types/preauth_key.go: 75f5ec4e1e0d73c2ea4bd3760f006b7b0587db3ade380c43bf839e7daf22a130
- hscontrol/state/state.go: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01

Serving fetch/validation/planning no longer reread those associations. The
following captured-key commit batch supersedes the native write-time reread
gap; candidate-only compatibility callers retain their fallback.
Pre-write cancellation, native metadata coherence, headless/non-atomic/custom
paths, nil/zero/wide/byte imports, exact SQL/encoding/hash/resource errors and
failure/rollback/native/wire-only/package/container/client/process/import/restart
behavior remain incomplete or unqualified. Direct rustfmt only; no tests/builds/
probes/validators/advisory or dependency refresh. The wire-only DB/core graph
and existing notices/licenses are unchanged. All three release gates remain open.

Captured loaded key users also scope existing-node selection for tagged keys:
their matching user node takes precedence, followed by an existing tagged node;
a different sole user is not converted. Only a tagged key without a loaded user
uses the unambiguous user-node conversion fallback. Native planning uses the
captured owner directly, keeps tag-node storage ownership nil, and excludes raw
zero-owner rows from that anonymous conversion set. Label-only custom fallback
remains available. A key with neither a loaded user nor tags does not match an
existing tagged node. This additional selection implementation is unvalidated.

## Captured-key commit and node deletion timestamps — 2026-10-18

Native registration commits the authenticated lookup snapshot without current
credential rereads or bcrypt. Selected existing-node columns/new-node insertion
precede the one-shot `id AND used = false` claim; SQL NULL is not false. Existing
captured Used keys skip consumption; fresh non-reusable keys always claim. The
shared key Used flag advances after SQL, before commit. Existing live rollback
and operation contexts are retained. Accepted auth-key work now owns lock wait,
lookup, validation, planning, mutation and publication after caller disconnect.
Non-native/candidate-only compatibility entry points retain their fallback.

Correction: types.Node.DeletedAt is *time.Time and supplies no Gorm query/update
clauses. Native node queries and key cleanup include timestamp-marked rows;
user deletion counts them. Key cleanup advances node UpdatedAt and user-key
cleanup reuses the transactional/savepoint helper. User and Policy gorm.Model
scopes remain. The previous active-node soft-delete-scope claim was incorrect.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. SHA-256:

- hscontrol/types/node.go: b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab
- hscontrol/state/state.go: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01
- hscontrol/db/node.go: 9b1badd1eba80662eccb1eb5e2d0f039967b6469a30fab6fb3904466de234bb4
- hscontrol/db/users.go: 0ff7855161955a7a02d4b2a481d903861aad8ce4ce5045c777bf9cca04790da7
- hscontrol/db/preauth_keys.go: 732667bea9f0f766aeeea919d894f0761bfe88b3e5babcdb4d4d3cd6d19ed4a6
- hscontrol/db/db.go: 141d70c4fb38ebfdfdbb072de70d56b1620a15d25357a5b012685a8df7bfc024

Gorm v1.31.1 SHA-256:

- schema/schema.go: 1bd35cda0a2eb96ac87b4112ae1b0752f608736fe60f572108c720b4503998fd
- soft_delete.go: 24434822a9ac7cd0764ef9eed9faaff5e403029ee12906da248b0225ce96b845

Direct rustfmt only. No build/test/validator/probe/dependency/advisory refresh.
Native node/side-metadata coherence remains source work; headless/custom,
raw-writer/credential/account/cancellation/shutdown, invalid/nil/wide imports,
errors/resources and native/wire-only/package/container/client/process/import/
restart behavior are unqualified. No release gate closes. Existing source
licenses/notices apply; no public wire fields or DB/core feature edge changed.

Registration writer follow-through in the same unvalidated batch: selected
cached-node SQL projections are now prepared from the current NodeStore record
and native bundle inside its serialized writer. Captured-key tags are applied
against the current AuthKeyID/tags so a same-key relogin retains admin overrides.
New-node publication, existing registration and rollback move record, Hostinfo
and loaded associations in one writer operation. All use the state.go and
node.go references above. Coherent arbitrary snapshot reads and other lifecycle
metadata writes remain source work. Direct rustfmt only; no validation or release
gate change.

## Retained node metadata snapshots — 2026-10-18

Private MachineSnapshot retains the COW record, raw Hostinfo and native
association tables for map builds/rebuilds/deltas/encoding/profiles, policy
inputs/checks/approvals and SSH/registration planning. SnapshotMap keeps the
side tables immutable for existing readers without per-request record clones.
The public Arc<HashMap> snapshot API and existing wire fields are unchanged;
MachineRecord gains PartialEq for matching staged native row publication.
Admin-only metadata retains the wire-only DB/core feature boundary.

Native admin tag/route nil assignments now join the record in its writer;
encoding/SQL failure retains the quiet edit. Backfill joins records and loaded
metadata in one writer. SQL row conversions stage association/Hostinfo metadata;
matching direct/queued/auth writers install it with the record. Registration
scope cleanup and removed nodes discard unused staged entries. Standalone save
metadata refresh checks the captured record/side-table versions before replacing
a baseline. Runtime/policy saves capture their native values from one view;
gRPC retains an association view across async conversion.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. SHA-256:

- hscontrol/state/node_store.go: 5bef0767885748e96e3d0e7a9f2bb5bb6d623d1de8c8ef5afb2b49201aa95028
- hscontrol/state/state.go: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01
- hscontrol/mapper/mapper.go: ec191db53afd7a906aaf015bf32c372c75c0b110aa784e5277e45269d2496534
- hscontrol/types/types_clone.go: 7fe85453a69a466e1f1748b7b0e86e2ec2d218b0a3ffbcd74a0c5756ede4e049

No build/test/validator/probe/dependency/advisory refresh; direct rustfmt only.
Native admin result/association envelopes, policy/route/online/clock boundaries,
same-projection stage/raw/custom/headless writers, invalid/nil/wide imports and
failure/cancellation/shutdown/resource/native/wire-only/package/container/client/
process/import/restart behavior remain incomplete or unqualified. The new source
does not close any release gate or validate the accumulated implementation.
Existing notices/licenses apply; generic COW/snapshot scaffolding is authored
for this Rust implementation.

## Retained native admin response views — 2026-10-18

MachineAdminView pairs admin record/raw hostname/loaded user/key pointers;
checked get/list and mutation-view methods have compatibility defaults. Attached
SQLite/Postgres and Wire adapters capture a retained view for gRPC get/list and
tag/route/expiry/rename responses. Their proto conversion no longer rereads live
associations or hostname across awaits. Expiry retains its original writer view;
other attached native mutations retain the view reread under the save lock.
SQL failure still retains quiet live edits without success dispatch. Pure volatile
edits skip SQL/ID encoding and only update existing native-shape metadata.
Native NULL LastSeen remains nil; headless row views retain loaded associations
and project NULL CreatedAt as Go zero time. Headless/custom mutation fallback
retains the legacy operation-plus-reread boundary, requiring further work.

ListNodes user filtering now follows the resolved numeric user ID rather than
cached labels; tags remain excluded, as in NodeStore.nodesByUser. Label-only
custom fallback remains. Expiry/API-key protobuf deadline conversion normalizes
supported nanos like AsTime and expiry responses emit the applied normalized
instant. Existing record/wire fields and wire-only feature boundaries are
unchanged; the admin trait adds response-view/mutation methods with defaults.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. SHA-256:

- hscontrol/grpcv1.go: 1bb435c674a64b3a7d1382eddfc9b33d7fb8f646c414709d011508d0a2e883c3
- hscontrol/state/state.go: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01
- hscontrol/state/node_store.go: 5bef0767885748e96e3d0e7a9f2bb5bb6d623d1de8c8ef5afb2b49201aa95028
- hscontrol/types/node.go: b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab

Source and direct rustfmt only; no build/test/validator/probe/dependency/advisory
refresh. Headless/custom mutation and batch preload snapshots, lifecycle/policy/
route/online/clock/encoding/error/resource/raw-writer/wide-import/cancellation/
shutdown behavior and native/wire-only/package/container/client/process/import/
restart qualification remain incomplete or unqualified. All three release gates
remain open. Existing notices/licenses apply; no fresh advisory conclusion.

## Native mutation failures and removal dispatch — 2026-10-18

Native errors retain save/expiry/policy operation context and driver codes.
DbError.headscale_go_message provides the Go-facing envelope separately from
existing Rust Display; native node save/registration entry points retain raw
unique-constraint failures. SQLite uses result-code labels/extended code/BUSY
suffix as conn.errstr; Postgres uses severity/message/SQLSTATE like PgError.Error.
Captured auth-key commits use this formatter. Generic compatibility APIs retain
their prior adapters. Driver/source notices and licenses are in
NOTICE-GO-SQLITE/LICENSE-GO-SQLITE and NOTICE-PGX/LICENSE-PGX; no runtime dependency
or version changed, and the package's existing BSD/MIT expression applies.

Native RPC selectors preserve state validation order and operation-specific
Unknown/InvalidArgument status boundaries, including SetTags versus preauth
format errors. Native tag lowercase validation uses the existing Go Unicode
15.0.0 simple mapping. Accepted native mutation/deletion work owns lock waits
through completion. Deletion emits the explicit removal before returning a
later policy-refresh failure; durable/cache/address/session removal stays done.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. Existing grpcv1.go, state.go,
node_store.go, types/node.go and db/node.go hashes above apply.

Driver/source SHA-256:

- github.com/glebarez/go-sqlite v1.22.0 sqlite.go: e5b651b6a3e0357c0fdba2d500a75063cc858f2e113e0c435c84b481d6f8050a
- github.com/jackc/pgx/v5 v5.10.0 pgconn/errors.go: f41cc9624094ad0f35c58ddb8e1fdd7bd2da39cae285edebd2b87f4c4e9708c0
- libsqlite3-sys 0.30.1 sqlite3/sqlite3.c: c01235302fe80da901fb70c7622c39147e29d9f29b7f6eb746b23517f320c90d
- sqlx-core 0.8.6 src/error.rs: 30ecee2fca8e8bf9c64b947cb6b23274931b78b05fb27b4b948a71a4fd25a58b
- sqlx-postgres 0.8.6 src/error.rs: ca191fe80729f21150728c0e959428ed3ee293f77cb4a0933fdb066d016d47e4
- sqlx-sqlite 0.8.6 src/error.rs: fd16dc2ea81c3c4f081136f24c3e911057751ec742b2e2685932a09f0215a0be

Additional required source work found in Gorm v1.31.1: unrestricted fresh
Node.Save attempts belongs-to User/AuthKey inserts with ON CONFLICT DO NOTHING
before the node insert; selected cached-node updates skip those relations.
The Rust fresh save currently omits association inserts, so captured SQL
association material, auto clocks, conflict/trigger/FK and deletion-race behavior
remain incomplete. Source SHA-256:

- callbacks/associations.go: 88df3bc6753ca10987882ff7faecb8fd0e6b7094f5980b6714be4e75b5ad0e48
- callbacks/callbacks.go: 09e83125a790236a8fba7691d3d1c69ebfa9e9bce1e9bb904950c56553c9ed3c

Source/direct rustfmt only, no test/build/validator/probe/dependency/advisory
refresh. Driver/version/locale, encoding/connection/pool/resource errors,
mutation/concurrency/cancellation/shutdown/policy/online/clock/headless/custom
boundaries and native/wire-only/package/container/client/process/import/restart
qualification remain incomplete or unqualified. All three release gates remain
open. Existing Go/Gorm notices apply to state/association behavior.

## Captured fresh associations and OIDC return models — 2026-10-18

Fresh attached native registration uses the captured Gorm belongs-to model
material for User/AuthKey ON CONFLICT DO NOTHING inserts before the node save.
The transient credential envelope retains raw hash bytes, nil tags and precise
User timestamps; sanitized associations alone reach NodeStore. User zero model
clocks and nil PreAuthKey.CreatedAt receive create-callback clocks; ignored
conflicts still return mutated captured model values, and returned IDs rebind
node/key references. Native mint performs the same user association save and
binds non-pointer Key as an empty string. SQL JSONSerializer writes use Go's
HTML-safe JSON envelope; nil JSON SQL behavior is preserved.

The original CLI/OIDC first-snapshot authority wording is superseded by the
State user lookup boundary correction below. CLI/OIDC select a numeric user ID;
registration finds the pending entry, reads the state User by ID before machine
locking and carries that snapshot into fresh save. Confirmation retains only the
existing callback profile/CSRF DTO. OIDC persistence separates the
initial provider read from the create or UpdateUser transaction. Struct Updates
omits zero strings and uses its own update clock; the callback retains the
original model's UpdatedAt and claim-assigned empty display/picture fields.
Accepted user work owns its continuation after caller cancellation. Existing
public user/confirmation/wire/policy shapes remain unchanged and native fields
stay behind admin for wire-only builds.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335; gorm.io/gorm v1.31.1.
SHA-256:

- hscontrol/state/state.go: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01
- hscontrol/db/preauth_keys.go: 732667bea9f0f766aeeea919d894f0761bfe88b3e5babcdb4d4d3cd6d19ed4a6
- hscontrol/types/preauth_key.go: 75f5ec4e1e0d73c2ea4bd3760f006b7b0587db3ade380c43bf839e7daf22a130
- hscontrol/types/users.go: 36bc0f562c507336d3a2a309c94718ec3baa2db2c3432180596556ab512d69dd
- hscontrol/db/users.go: 0ff7855161955a7a02d4b2a481d903861aad8ce4ce5045c777bf9cca04790da7
- hscontrol/oidc.go: 88484e1fbbf5589433d858643ff52f630acc76d8a2ac94779f03db8cc5a7a591
- callbacks/associations.go: 88df3bc6753ca10987882ff7faecb8fd0e6b7094f5980b6714be4e75b5ad0e48
- callbacks/callbacks.go: 09e83125a790236a8fba7691d3d1c69ebfa9e9bce1e9bb904950c56553c9ed3c
- callbacks/create.go: c3c21f80a84e79ef164ebefc3df5bd298edef6af04f4f3a0474d205749ad39d8
- callbacks/update.go: 2e3f126b3884faf20941fb4427e9b0949ba21c1e1604ccb1ab52495dcfcae717
- schema/serializer.go: 9dadcf607eccadd1f6cab29f72a95d8ff7c683e20dd412f585a5b5d15797a1a8

This supersedes the earlier missing fresh-association source finding. Concurrent
account/key deletion can still be followed by a captured-model insert attempt,
as in upstream; immediate revocation across accepted operations is not promised.
Headless/candidate-only/custom fallbacks, malformed/null/wide imports, policy
phase/resource equality, SQL/driver/trigger/rounding/failure/race/resource/
cancellation/shutdown behavior and all native/wire-only/package/container/client/
process/import/restart qualification remain incomplete or unqualified. Source
reads/hashes and direct rustfmt only; no tests/builds/validators/probes/dependency
or advisory refresh. All three release gates stay open. Existing BSD/MIT notices
and LICENSE-GORM apply; no runtime Gorm dependency or version change was added.

## Headless and candidate-only captured saves — 2026-10-18

Built-in headless SQLite/Postgres registration now runs captured User/AuthKey
association writes in the fresh node transaction. Native and compatibility
inserts share returned-ID rebinding, auto-clock and conflict behavior. Headless
response conversion retains sanitized original associations instead of querying
them again. Captured key commits save the node then claim strictly used=false;
existing-node saves do not insert associations. Headless SQL node snapshot/name
selection and legacy full cached-update masks remain separate source gaps.

Candidate-only API/DB registration now captures one verified key/User model
before planning/writing, validates it and carries it through the save/claim.
There is no second credential read or mutable-hash/flag comparison inside the
write transaction. Already validated native lookups remain authoritative.
Metadata-only/custom/non-atomic callers that omit original material retain an
incomplete compatibility boundary. Raw credential material remains transient.

Preauth Reusable/Ephemeral SQL NULL maps to Go ordinary bool zero, including
single ephemeral lookups. Gorm scans through **bool and leaves a nil destination
at its zero value. Strict Used claims deliberately do not coalesce SQL NULL.
Node row projection preserves NULL CreatedAt as Go year-one zero, representable
pre-epoch times, and zero node expiry as non-expiring. Native nil LastSeen remains
separate metadata; headless non-optional MachineRecord uses a sentinel.

The previously pinned headscale v0.29.5 state.go/db/preauth_keys.go/types/node.go
and Gorm v1.31.1 association/create callback hashes apply. Additional SHA-256:

- gorm.io/gorm v1.31.1 schema/field.go: ab4f07b8fb8911e3f1bb19c292f0f46b48ae0130af845eb4ba13523cb5c71f37
- gorm.io/gorm v1.31.1 scan.go: 4ab60fcb86fa7aed67195eeef1d9cc812f55c86c050355ca9d4e77489b0fd027

Source reads/hashes and direct rustfmt only; no tests/builds/validators/probes or
fresh dependency/advisory checks. Full fallback/update-mask/SQL-authority, nil/
malformed/wide import, policy phase/resource, encoding/driver/trigger/rounding/
failure/race/cancellation/shutdown and native/wire-only/package/container/client/
process/import/restart behavior remain incomplete or unqualified. All three
release gates remain open. Existing BSD/MIT/Gorm notices apply; no version or
runtime dependency changed.

## Raw credential hashes and Go bcrypt inputs — 2026-10-18

Preauth/API-key SQL hash decoding now accepts Go's byte columns without a UTF-8
cast. Public String fields retain a lossy convenience projection; native
registration, connection-based preauth and all API bearer verification use raw
nullable bytes, as do original captured association saves. Raw wrapper types
have no Debug/Serialize implementation. Legacy plaintext preauth lookup does
not reject an unused arbitrary-byte hash.

src/go_bcrypt.rs adapts golang.org/x/crypto v0.53.0 bcrypt input behavior selected
by headscale v0.29.5 (commit 0f7d1e536bed9f01dd7161f7637af19bb0908335).
The wrapper implements byte-oriented length/version/cost/error order, accepted
minor/separator forms, padded non-strict salt decoding with CR/LF and Go error
offsets, fixed-size Hash copying/suffix handling and generation cost/version/
length behavior. Standard salts call bcrypt's raw function; shorter accepted
salts use the already-locked Blowfish bcrypt primitives with the same schedule.
The existing bounded blocking worker and cancellation-held permit remain.
Generation emits $2a$; comparison uses subtle constant-time equality. Direct
blowfish/subtle dependencies reuse locked 0.9.1/2.6.1 with no version updates.
BSD/MIT attribution and licenses are in NOTICE-BCRYPT, LICENSE-GO-CRYPTO,
LICENSE-BCRYPT and existing LICENSE-GO-STDLIB.

Source SHA-256:

- hscontrol/db/api_key.go: e1a3c76dfbc8a120a844882b489a244ecc6dc11a724178f4376b17c79098f0e1
- golang.org/x/crypto v0.53.0 bcrypt/bcrypt.go: 828a8f888c646bce098a2a9461043436c87b9f5c9ca54f6a881371efa58d57d4
- golang.org/x/crypto v0.53.0 bcrypt/base64.go: 403d60d80b8b42741d429fc5fb0bcfe961f1ca50a5adcf90b9c5b1e52bebeded
- golang.org/x/crypto v0.53.0 blowfish/cipher.go: c67e62fdf539aa94cd50c1055bdc1d4c6dc93f4b2d654addfd97ccd1d12f6e48
- Go 1.26.9 encoding/base64/base64.go: e6437c7716ecd1ae91c9d10037362cab186e5873a6365b713e2d8c57d8fc32fc
- bcrypt 0.16.0 src/bcrypt.rs: 60c4ca87e6ef11043e9b5c05b0e64ffdec9a47652d68e55db0bc8652a582cdfb
- bcrypt 0.16.0 src/lib.rs: f7887fbbdd0a4709319985c6b298c5c3fcfd2b8b7ff7773919d3839109650718
- blowfish 0.9.1 src/lib.rs: de83eb4f78298ff277f7e7aa686322fce905bdfe1be46dbbbf19a323beeed361
- subtle 2.6.1 src/lib.rs: ced6ebd3622af527cbbbb09feb57a2894751ff07e7ca8f97f22bad89401e5c8d

Source reads/hashes and direct rustfmt only; no tests/builds/validators/probes or
fresh dependency/advisory checks. This is an unqualified credential-parser and
hash-representation change, not cryptographic/auth/drop-in qualification. High
stored costs remain expensive within the existing worker budget; no DoS/resource
or compiler equality is claimed. Ordinary invalid byte strings, UTF-8 public
plaintext/key/prefix boundaries, other SQL coercions/scalars/nil/wide imports,
headless masks/SQL authority, policy phases/resources and all exact failure/
error/backend/race/resource/cancellation/shutdown/native/wire-only/package/
container/client/process/import/restart qualification remain incomplete or
unqualified. All three release gates stay open; historical reports predate this
batch and no fresh advisory conclusion is made.

## State user lookup boundary correction — 2026-10-18

The earlier claim that CLI/OIDC first-lookup models directly own registration
association saves is superseded. Pinned State.HandleNodeFromAuthPath obtains the
pending auth entry, calls DB.GetUserByID, then locks the machine. CLI grpcv1.go
GetUserByName and OIDC callback/confirmation data select the numeric ID only.
Native CLI and SQLite/Postgres OIDC now perform that separate state read before
lock waits and carry its snapshot into planning/fresh association saving.
Native registration lookup errors retain Go driver messages and operation
context. Accepted pending completions own the state read and lock waits through
publication after caller cancellation. Account changes/deletion before that
state read therefore affect registration; deletion after it retains the captured
association-save boundary. Verified auth-key preloads remain authoritative for
auth-key registration.

Removed the unneeded raw callback-user/confirmation wrapper types and methods.
Existing OIDC callback profile/CSRF DTOs and native claim-return versus SQL
struct-Updates behavior remain. Public pre-existing user/confirmation/wire/policy
fields and the wire-only dependency boundary stay unchanged. Registration saves
intentionally include Expiry; nodeUpdateColumns only omits it for ordinary
persistNode, not re-registration. Headless AuthKeyID masks and cached name/route/
SQL authority remain source work.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. Existing SHA-256 pins:

- hscontrol/state/state.go: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01
- hscontrol/grpcv1.go: 1bb435c674a64b3a7d1382eddfc9b33d7fb8f646c414709d011508d0a2e883c3
- hscontrol/oidc.go: 88484e1fbbf5589433d858643ff52f630acc76d8a2ac94779f03db8cc5a7a591
- hscontrol/db/users.go: 0ff7855161955a7a02d4b2a481d903861aad8ce4ce5045c777bf9cca04790da7

Direct source reads and rustfmt only; no tests/builds/validators/probes/dependency
or advisory refresh. Full ordering/cancellation/shutdown/race/clock/resource/
error, headless/custom/non-atomic/malformed/nil/wide-import/policy and native/
wire-only/package/container/client/process/import/restart qualification remains
incomplete or unqualified. All three release gates remain open. Existing Go
notices and licenses apply; no dependency or version change in this correction.

## Shared cached registration and native user preloads — 2026-10-18

Built-in headless registration shares the native typed cached mutation builder
and selected save mask for SQLite/Postgres. Web reauth omits retained non-null
AuthKeyID and explicitly clears nil; auth-key reauth sets its presented ID.
Expiry is included, CreatedAt/DeletedAt are excluded, and existing GivenName,
IPs/routes plus endpoint/disco/nil shapes follow native mutation rules. Cached
headless atomic completion saves then claims its captured key; missing SQL rows
are no-op saves, with typed response retention and no name reservation/recreation/
post-save SQL node reread. Built-in API cached registration no longer calls the
legacy full-update DB helper. Low-level compatibility DB APIs remain separate.

Headless auth planning no longer auto-approves routes or performs extra address
queries. Registration preserves existing approvals or starts fresh with none;
Go approves on map processing or policy replacement. SQL User/AuthKey.User
preloads now read the native pool regardless of optional UserAdmin. Nil loaded
associations remain separate from raw FK values. Uncaptured native registration
planning loads its User write material from that pool as well; an accepting
state-level captured user remains authoritative when supplied.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. State auth mutations, nodeUpdateColumns,
applyAuthNodeUpdate, HandleNodeFromPreAuthKey, updatePolicyManagerNodes and map/
policy auto-approval call sites were inspected. hscontrol/state/state.go SHA-256:
7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01. Existing node_store.go and db/node.go pins apply.

Source reads/hash and direct rustfmt only; no tests/builds/validators/probes or
fresh dependency/advisory checks. Headless SQL selection/preload versus retained
NodeStore, low-level compatibility masks, fresh headless naming/nil shapes,
custom selector/adapter/non-atomic/cancellation/shutdown/error/failure/resource/
clock/race/trigger/rounding behavior, malformed/nil/wide imports, policy phases/
resources and all native/wire-only/package/container/client/process/import/
restart qualification remain incomplete or unqualified. All three gates remain
open. Existing Go notices/licenses apply; no dependency/version change here.
## State-level user create and rename — 2026-10-18

src/users/state_mutations.rs implements State.CreateUser/UpdateUser semantics
separately from legacy db.CreateUser/RenameUser. It accepts the state RPC's raw
name/profile fields, preserves a valid empty provider identifier and retains the
original nanosecond create model. SQLite binds that clock; Postgres binds its
microsecond driver representation without replacing the returned model through
a SQL reread. Create failures keep the state creating-user context, including
transaction failures, without backend-independent unique-error substitution.

Rename loads the model inside its write transaction, assigns Name, then applies
Gorm's nonzero struct columns: empty Name is omitted in SQL, a valid empty
NullString is included, nonzero CreatedAt is retained, and UpdatedAt advances
with fractional precision. There is no OIDC restriction in State.RenameUser.
The zero-primary-key update-WHERE guard is retained. Neither affected-row
rejection nor a post-save node/user reread is added; the RPC owns its later
by-name lookup. Legacy helpers retain their existing interfaces/validation.
DestroyUser now loads its user model in the transaction, and SQLite no longer
rejects a successful zero-row final DELETE. Node.DeletedAt is a plain timestamp;
durable owned-node checks intentionally still include those rows.

Pinned source: github.com/juanfont/headscale v0.29.5 at
0f7d1e536bed9f01dd7161f7637af19bb0908335, with Gorm v1.31.1. SHA-256:
- hscontrol/state/state.go: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01
- hscontrol/db/users.go: 0ff7855161955a7a02d4b2a481d903861aad8ce4ce5045c777bf9cca04790da7
- gorm callbacks/update.go: 2e3f126b3884faf20941fb4427e9b0949ba21c1e1604ccb1ab52495dcfcae717
- gorm errors.go: 3d6a0cee03f75e796e237c0812b5cfdab08cbc95deae1f6b0beb8514eb15493b

Existing BSD/MIT notices and licenses apply. Source reads/edits/hashes and direct
rustfmt only; no tests/builds/validators/probes/dependency/advisory checks.
Driver/trigger/transaction/clock/constraint/failure/cancellation behavior,
Go-wide/malformed imports, full typed node/key preload qualification during user deletion,
feature/package/container/native/client/process/import/restart qualification and
all release gates remain incomplete or unqualified.

## User deletion preloads and state listing — 2026-10-18

src/users/delete_preloads.rs follows DestroyUser's read phases on its existing
write connection: typed owned nodes, AuthKey with nested User, then node User,
followed by the ownership decision; typed owned keys and User precede nested
key destruction. Gorm's sorted preload names determine phase order. Missing
associations remain nil and non-nil zero FK pointers remain identities. The
queries add neither node soft-delete filtering nor an artificial row order.
The loaded user model supplies the final delete identity; the zero primary key
WHERE guard runs after key cleanup and aborts the entire transaction.

Key destruction keeps native DELETE errors, retains the Go-facing nested
clearing-auth-key context, and binds Postgres UpdatedAt with microseconds as
the Go driver does. SQLite retains fractional nanoseconds.
src/users/state_queries.rs supplies the distinct ListUsers path: typed rows,
one SQL filter, no uniqueness assumption, no display/provider-name fallback,
and Gorm zero-field omission. The RPC owns filter priority and response sorting.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335;
Gorm v1.31.1. Existing db/users.go and db/preauth_keys.go pins apply. SHA-256:
- gorm callbacks/preload.go: e2e7b320051aeec846eb42b8b162272412656314e136ff9437f67b8d25821d81
- gorm callbacks/delete.go: 767f585b39bb74204dcfe7d205062dd89806f10c3f2afff5cb7a4382a4af1c92

Existing BSD/MIT notices and licenses apply. Source edits and direct rustfmt
only; no tests/builds/validators/probes or dependency/advisory checks. Existing
typed column projections do not establish all Go scalar/time/wide scan
behavior, row/column/error accumulation order, driver/trigger/transaction/
failure/cancellation/resource/clock/race behavior or native/wire-only/package/
container/client/process/import/restart qualification. All three gates stay open.

## API-key state saves and credential entropy — 2026-10-18

src/api_keys/state.rs implements the native API-key state save phases. Mint
prepares entropy/bcrypt before pooled acquisition, begins the save, assigns
CreatedAt, inserts and commits without a row reread. The returned model keeps
original nanosecond timestamps while Postgres bindings retain microseconds.
Gorm create does not raise not-found for an empty RETURNING scan; ID stays zero.
Begin/insert/commit failures retain saving-API-key context. Expire/delete load
the full key first, then mutate its captured primary ID in a write transaction.
A zero loaded ID hits the WHERE guard, while zero affected rows after a valid
lookup remain successful. Expiry's clock precedes pool acquisition. Prefix and
credential lookup use primary-ID First ordering; state listing leaves ordering
to the RPC. Existing generic ordered list interfaces remain available.

src/credential_entropy.rs follows Go util.GenerateRandomStringURLSafe: read n
bytes, raw-URL-base64 encode and truncate to n. Native API/preauth mint paths
propagate entropy/hash errors without an invented bcrypt operation prefix.
Public generator signatures remain panic-capable convenience interfaces.
Native strict preauth owner validation occurs inside the write transaction,
before user lookup/tag normalization; legacy selector interfaces stay separate.

Pinned headscale v0.29.5 at 0f7d1e536bed9f01dd7161f7637af19bb0908335,
Gorm v1.31.1. SHA-256:
- hscontrol/db/api_key.go: e1a3c76dfbc8a120a844882b489a244ecc6dc11a724178f4376b17c79098f0e1
- hscontrol/types/api_key.go: aee8b6ecf12134f8345bb974271015d45cdd57386385eac08311b7db3b2cf785
- hscontrol/util/string.go: f0a8db9bddf4c02775cc9a4011bb260f151c76c434e9ed8cc973a871312ff360
- gorm callbacks/create.go: c3c21f80a84e79ef164ebefc3df5bd298edef6af04f4f3a0474d205749ad39d8
- gorm callbacks/transaction.go: 6c4da53c1230dc89366a1d09ce506ab47b1a52d6fd08cf150b1ea17e1b3e8f67
- gorm scan.go: 4ab60fcb86fa7aed67195eeef1d9cc812f55c86c050355ca9d4e77489b0fd027

Existing update/delete/preauth source pins and original BSD/MIT licenses apply.
No dependency release changed. Source reads/edits/hashes/direct rustfmt only;
no tests/builds/validators/probes/advisory checks. Full scalar/time/wide-ID/byte/
scan-error behavior, detailed validation diagnostics, external transaction
nesting, trigger/driver/commit/failure/clock/race/resource/cancellation/shutdown
and all native/wire-only/feature/package/container/client/process/import/restart
qualification remain incomplete or unqualified. All three gates remain open.



## Bounded user-mutation source review — 2026-10-18

Source review of users/state_mutations.rs, state_queries.rs and delete_preloads.rs
against pinned Headscale State Create/Update/Destroy and Gorm callbacks found no
warranted edits in the inspected paths. Original model returns, Postgres clock
precision, valid-empty/null struct writes, primary-key guards, query predicates,
node soft-delete scope and nested preload ordering were reviewed only in source.
The native SQLx-core/Postgres execution changes are documented in vendor UPSTREAM
files and remain unvalidated. Rust keeps fail-closed shared user reads where
pinned db.GetUserByID discards non-record-not-found errors and may return partial
models. Signed i64 public ID bounds also differ from Go unsigned IDs.

Source SHA-256:
- Headscale v0.29.5 hscontrol/state/state.go:
  7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01
- hscontrol/db/users.go:
  0ff7855161955a7a02d4b2a481d903861aad8ce4ce5045c777bf9cca04790da7
- Gorm v1.31.1 callbacks/update.go:
  2e3f126b3884faf20941fb4427e9b0949ba21c1e1604ccb1ab52495dcfcae717
- callbacks/preload.go:
  e2e7b320051aeec846eb42b8b162272412656314e136ff9437f67b8d25821d81
- pgx v5.10.0 pgtype/timestamptz.go:
  6a70c860dd3f40dc56793243668e4bb3d59faa204acc369b978d3da56e5d490f

No tests/builds/Cargo/validators/probes or release qualification ran. Existing
upstream licenses/notices apply; no dependency version or public API changed.


## Atomic Go ledger/version publication — 2026-10-18

After the Postgres foundation migrator completes, Go migration-ledger stamping
and database_versions publication now run inside one SQLx transaction. Fresh
ledger table creation and all fresh IDs cannot become separately committed
prefixes if the task is cancelled before final publication. SQLx Drop queues
rollback; actual failure/cancellation/commit-ambiguity behavior remains
unqualified. Earlier partial ledgers, concurrent startup, foundation-step
interruption and direct Go handoff after interrupted Rust startup are not
qualified by this source change. No migration ID/checksum or public API changed.
Source/direct rustfmt only; no tests/builds/Cargo/validators/probes or gate closure.


## Pooled migration session isolation — 2026-10-18

The pooled foundation migration entry point marks its connection close-on-drop
before compatibility checks or migration work. SQLx Migrator::run_direct only
unlocks the session advisory lock on success; failed/cancelled startup must not
return that session to the reusable pool. Existing SQLx pool close-on-drop
cleanup closes the socket with its bounded cleanup timeout. The borrowed
connection entry point retains caller-owned cleanup. No migration SQL/checksum,
public API or dependency version changed. This follows the pinned SQLx 0.8.6
migrator/pool source, not new pgx or Go migration behavior. Source/direct rustfmt
only; failed/cancelled startup, concurrent migration and restart qualification
remain pending. All three parity gates stay open.


## Whole-startup locking and SQLite node expiry projection — 2026-10-18

The Postgres entry point owns SQLx's existing database advisory lock across
compatibility checks, normalization, foundation changes and final ledger/version
publication. Its private foundation Migrator disables the nested lock. Ordinary
failure attempts unlock and preserves the original error. Pooled cancellation
still uses session close-on-drop; borrowed-session ownership is unchanged.
This prevents a second cooperating Rust startup from observing the foundation
before publication or racing fresh Go-ledger table creation. Mixed Go/Rust
concurrency and interrupted startup remain unqualified.

SQLite NODE_COLUMNS preserves stored expiry rather than nulling all timestamps
with the 0001-01-01 prefix. SQL NULL stays NULL, exact Go zero stays representable,
and nonzero year-one expiries reach existing exact-zero checks as expired values.
Pinned Go v0.29.5 types/node.go IsExpiredAt and Proto are the source boundary;
SHA-256 b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab.
SQLx 0.8.6 source SHA-256: core/src/migrate/migrator.rs
803d469dd00bf43c1729450886bceb0df54953a558460e23e1f8ea6f8205b9a8;
postgres/src/migrate.rs
5e958e86890da58bbf7d7a9cc284256d1bb1e24ec58d58cdb47927ae3643508c.
Existing licenses/notices apply. No public API, migration ID/checksum or dependency
version changed. Source/direct rustfmt only; no tests/builds/Cargo/validators/
probes, restart/import/concurrency qualification or gate closure.


## Legacy SQLite upgrade connection isolation — 2026-10-18

The legacy converter marks its pool connection close-on-drop before work.
Rebuild disables connection-local foreign keys before its transaction and
restores them afterward; cancellation can skip that explicit restoration.
Closing the migration session prevents its reuse by application queries with
foreign keys disabled. Existing SQLx PoolConnection close-on-drop API is used;
backup/copy/rebuild SQL, migration checksums and public APIs are unchanged.
This is Rust converter cleanup, not a new upstream schema claim. Source/direct
rustfmt only; cancellation/worker shutdown/recovery/restart and all release
qualification remain pending. No tests/builds/Cargo/validators/probes ran.


## Timestamp SQL scan phase and legacy normalization — 2026-10-18

Source correction: normal Gorm model reads obtain `**time.Time` from their value
pool and call Rows.Scan before Field.Set. Driver strings not recognized by
parseTime therefore fail database/sql conversion; Gorm's now.Parse string setter
is not a fallback for these rows. Earlier layout/default/local-time claims were
based on the wrong phase and are superseded. Removed the unused Gorm fallback,
local timezone loader/archive work and now-specific attribution. Driver UTC
instant decoding needs no embedded/local zone database: its time.String form
already carries a numeric offset, with the native UTC-name override.

Private timestamp/layout.rs implements only the pinned SQLite driver's ordered
time.String and nine parseTime layouts. Invalid TEXT and native Go-shaped
INTEGER/REAL/BLOB timestamps produce typed scan causes. Native go_error rendering
uses measured SQLite model-column context for the database/sql envelope, whose
ordinal varies across fresh and migrated schemas. Missing/unsupported context
retains only the actual unsupported-Scan cause. Generic
Rust error rendering remains diagnostic. A private legacy_integer tag permits
old Rust-managed schemas identified by _sqlx_migrations; pure Go primary rows
reject INTEGER times. Node expiry keeps canonical instants, NULL and exact-zero
semantics; API/preauth convenience helpers prefer parsed deadlines.

The legacy SQLite converter normalizes integer time cells on transactional TEMP
copies before dropping primary tables or publishing Go migration/version rows.
It covers users/policies creation/update/deletion times, preauth expiration and
creation, API expiration/last_seen/creation, and node last_seen/expiry/creation/
update/deletion. Four-digit UTC timestamp TEXT replaces integer seconds; years
outside0000..9999 reject. Valid TEXT stays unchanged, including fractional
precision; malformed TEXT and REAL/BLOB reject. Indexed256-row batches bound
row-count storage. Existing backup and close-on-drop behavior remain; sidecar
copy still commits before primary rebuild. No migration SQL/checksum or public
API changed, and no dependency version/features were added.

Pinned source SHA-256:
- glebarez/go-sqlite v1.22.0 sqlite.go:
  e5b651b6a3e0357c0fdba2d500a75063cc858f2e113e0c435c84b481d6f8050a
- Gorm v1.31.1 schema/field.go:
  ab4f07b8fb8911e3f1bb19c292f0f46b48ae0130af845eb4ba13523cb5c71f37
- schema/pool.go:
  6b690decd519193445fa1026979a00f3723214c83a22b4384bd0c8ad06119ebd
- scan.go:
  4ab60fcb86fa7aed67195eeef1d9cc812f55c86c050355ca9d4e77489b0fd027
- Go1.26.9 database/sql/convert.go:
  8182862d20f5d28fbfc5922c861a34cc0d5081f21db2646ea845ad914c842d1f
- database/sql/sql.go:
  683b3e35d41b37f4c80500467fb5a56fab7cc5de922b2c3818aae6bfea971fba
- time/format.go:
  f288c56858ab25828551681778f006b591ed140fc12e60122b6a9a7e35b07eb7
Existing SQLite/Gorm/Go BSD notices apply. Source/direct rustfmt and independent
source audit only; no tests/builds/Cargo/validators/probes/fixture recapture.
Column ordinals, multiple-error aggregation, custom column declarations, invalid
UTF8, legacy/source-schema detection, scalar errors, large/malformed data,
rollback/cancellation/sidecar recovery, imported/fresh/restarted Go handoff and
all release/feature/package/client/process/security qualification remain open.
All three parity gates stay open.


## Measured SQLite scan envelope — 2026-10-18

The private SQLite expiration/expiry tuple includes pragma_table_info cid and
its physical column name. TimestampScanError attaches that measured nonnegative
context and native rendering uses the database/sql index/name envelope.
Missing/unsupported metadata retains cause-only rendering. Generic error Display
and public row fields/signatures remain diagnostic/stable.

Independent source audit confirms pinned ordinary model API/preauth/node reads
use SELECT * and Preload runs separate queries. Supported plain Headscale table
cid therefore matches the original Go driver column index, including differing
fresh/imported schema order. Joined/reordered projections, generated/hidden/
virtual columns, custom/case-altered declarations and multi-error ordering are
not qualified by this source change.

Additional pinned source SHA-256:
- Gorm v1.31.1 clause/select.go:
  ff049a1375c8e17b92cb473c6734b97fce3204bb6e8672c331b3f1602fdaf40c
- callbacks/preload.go:
  e2e7b320051aeec846eb42b8b162272412656314e136ff9437f67b8d25821d81
- Headscale v0.29.5 hscontrol/db/node.go:
  9b1badd1eba80662eccb1eb5e2d0f039967b6469a30fab6fb3904466de234bb4
- pinned modernc SQLite lib/sqlite_darwin_arm64.go (cid source reference):
  af4e5fb324d27d63f47d7e68b895ad0e441be1d33e01c3b027b53226668679f3
Existing Go database/sql/sql.go and convert.go pins/notices apply. Source/direct
rustfmt and peer audit only; no tests/builds/Cargo/validators/probes/fixtures or
process/runtime/restart/import/feature/security qualification. Three gates stay
open. NumericID PAK expire/delete source audit required no changes: native paths
already update/delete without loading malformed timestamp fields.
# Postgres repair adoption — 2026-10-18

Foundation imports adopt SQLx repair versions 7/9/11/12 only from their exact
Go migration IDs. They preserve already-repaired state, original SQLx checksums
and descriptions, and reject dirty/unknown/mismatched SQLx records. A pending
obsolete unique-index create/drop pair is atomically adopted at its final
dropped-index state; this is net-schema adoption, not a Go migration-ID claim.
Null-tag normalization is conditional on the historical owner repair remaining
pending. Absent and empty Go ledgers both receive the full fresh ledger during
final version publication. No migration SQL or checksum changed.

Pinned source SHA-256:
- Headscale v0.29.5 hscontrol/db/db.go:
  141d70c4fb38ebfdfdbb072de70d56b1620a15d25357a5b012685a8df7bfc024
- hscontrol/types/node.go:
  b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab
- Gormigrate v2.1.6 gormigrate.go:
  15a99c9aec5a36ac51ce1ffd8e6e703033766e8442160dcc9aacafd184748653

Independent source review/direct rustfmt only. Cancellation, concurrent startup,
upgrade/reopen and process qualification remain pending. Borrowed connection
cleanup remains caller-owned; pooled migration connections close on drop. All
three parity gates stay open.

# SQLite repair adoption — 2026-10-18

The native path outside the file-backed current-schema shortcut adopts SQLite
repair versions 14/15/18/19 only from the exact Go IDs used for Postgres repair
adoption. This preserves one-time semantics for supported older/ledger-only and
in-memory imports. A BEGIN IMMEDIATE transaction validates existing SQLx records,
seeds original immutable descriptions/checksums, and installs the obsolete
index16/index17 pair at its final dropped-index state. Pending migrations use the
same embedded migrator; normalizing null tags depends on pending owner repair14.
Original SQL/checksum and converter sources are unchanged.

Existing Headscale db.go/types/node.go source pins and BSD license/notices
apply. SQLx's SQLite migration lock is a no-op; the writer transaction serializes
adoption itself, not the entire subsequent migration/conversion process.
Selected sqlx-sqlite v0.8.6 src/migrate.rs SHA-256 (lock/apply reference):
02a0b9b81a7b4a313927b295d3722b7947176d16024f76873733a9b950da073e.
Source/direct rustfmt only; no tests/builds/Cargo/validators/probes/recapture or
runtime/import/restart/concurrency/cancellation/feature qualification. All three
parity gates stay open.

# Pending Postgres zero-expiry cutoff — 2026-10-18

Headscale db.go's clear-zero-time migration uses an unqualified '1900-01-01'
literal, interpreted in the session TimeZone for TIMESTAMPTZ expiry. The immutable
SQLx7 file instead pins UTC. Native connections preserve Go runtime parameters,
so these cutoffs differ for valid older imports in non-UTC sessions.

The locked preparation transaction now executes the exact Go predicate when
SQLx7 and its Go ID are both absent and nodes exists, and records the original
SQLx metadata/checksum atomically. This is pending repair execution, not ledger
adoption. Existing/adopted repairs do not run again; fresh no-nodes startup uses
the normal empty-table migration. No migration SQL/checksum or global session
timezone changed. Existing db.go SHA-256 and Headscale BSD notice apply.

Source/direct rustfmt only; no tests/builds/Cargo/validators/probes/recapture or
timezone/data/import/restart/feature qualification. Three parity gates stay open.

# Pending owner repair preserves raw nil tags — 2026-10-18

On expected SQLite/Postgres node schemas, a missing owner repair now executes
the exact Go predicate (`tags IS NOT NULL`, excluding '[]', '' and 'null') inside
the preparation transaction and records original SQLx14/PG9 completion metadata.
It runs only if both the SQLx version and exact Go repair ID are absent. Expected-column
checks scope execution to supported schemas. Existing/adopted repairs remain
untouched; fresh no-nodes retains the normal empty-table migration. The historical
null-to-empty normalization no longer changes the corrected supported import
state. No migration SQL/checksum changed.

Headscale v0.29.5 db.go719–729 is the predicate reference; existing db.go SHA-256
and Headscale BSD notice apply. This supersedes the earlier pending-owner
normalization source limitation for expected schemas. Source/direct rustfmt
only; no tests/builds/Cargo/validators/probes/recapture or raw-tag/data/import/
restart/feature qualification. All three parity gates remain open.

# SQLite logical backup boundary — 2026-10-18

Native legacy/import startup completes a logical primary snapshot before its
first ledger/repair/DDL/version write. The standalone converter also snapshots
its own input before auxiliary initialization. The helper reserves a create_new
Unix0600 target, VACUUMs outside an explicit transaction, and closes its session
before later pool-based work (including max_connections=1). Only successful
copies are usable backups; failed/cancelled copies stay to avoid unlink races
with the SQLite worker. No migration SQL/checksum changed.

Source references:
- bundled libsqlite3-sys v0.30.1 sqlite3.c VACUUM active-transaction rejection
  and existing nonempty destination rejection (existing empty files accepted):
  c01235302fe80da901fb70c7622c39147e29d9f29b7f6eb746b23517f320c90d
- sqlx-sqlite v0.8.6 src/connection/mod.rs worker-drop documentation:
  257459ec82510c6e90d0a56fa168dbf4cb162c246229d5c1d8b8d0ea3de593ff
- sqlx-core v0.8.6 src/pool/connection.rs close_on_drop:
  2f27ad58c0e7c666a2b934a29b404b8ebfae8c13e8ca69ef6a0c79b7bfe1fd3b

Logical state follows connection PRAGMAs/ATTACH; sidecars and pre-open bytes are
outside the backup. External writers are not globally serialized. Successful
native conversion keeps original and intermediate snapshots. Bounded peer
source review/direct rustfmt only; no tests/builds/Cargo/validators/probes or
recovery/import/restart/feature qualification. Three parity gates remain open.

# SQLite rebuild sequence floors — 2026-10-18

Native migration execution wraps the immutable SQLx9 nodes rebuild and SQLx12
nodes/pre_auth_keys rebuild with TEMP sequence snapshots and MAX floor restore.
SQLite ALTER RENAME moves the old sqlite_sequence name and DROP deletes it;
copying only surviving IDs can therefore reuse a previously allocated deleted
ID. The wrapper and original completion record share SQLx's existing apply
transaction, retaining original descriptions/checksums. The converter sees the
restored floors. File-backed runner sessions close on drop; memory connections
retain normal SQLx rollback handling. Migration SQL files are unchanged.
Previously completed migrations that already lost a floor require an original
backup; surviving rows cannot reveal deleted allocation history.

Source references (existing pins): bundled sqlite3.c ALTER rename sequence-name
update and DROP AUTOINCREMENT sequence deletion; sqlx-sqlite v0.8.6 migrate.rs
single transaction for script plus ledger. Headscale db/node.go hard-deletes
node IDs and db/preauth_keys.go hard-deletes key IDs, so deleted-highest-ID states
are ordinary supported inputs.

Independent source review/direct rustfmt only; no tests/builds/Cargo/validators,
probes/recapture or identity/allocation/rollback/cancellation/import/restart/
feature qualification. Three parity gates remain open.

