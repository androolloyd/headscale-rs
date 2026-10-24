# Headscale compatibility source provenance

The maintained API registration/tag/backfill implementation follows
`github.com/juanfont/headscale` v0.29.5, commit
`0f7d1e536bed9f01dd7161f7637af19bb0908335`.

- `hscontrol/state/state.go` covers fresh versus existing-node completion,
  user/tag ownership, clocks and post-backfill NodeStore refresh.
- `hscontrol/policy/v2/policy.go` distinguishes direct user/group ownership
  from resolved tag-owner node IP sets.
- `hscontrol/db/ip.go` supplies allocator/backfill ordering and error behavior.

The original Juan Font BSD notice and license are retained in
NOTICE-HEADSCALE-GO and LICENSE-HEADSCALE-GO. Package metadata records the BSD
addition and both runtime container recipes copy these notices. No external
dependency version changed. The shared ACL and database compatibility source
have their own UPSTREAM.md files and notices.

`src/tailscale_wire/web_registration.rs` exposes owned volatile completion
without changing existing wire field types. Persistent completions keep their
backend handlers. Backfill now plans changes under sorted machine guards and
commits all IP updates together. After a change it reloads every live database
node, decodes all records, then publishes a quiet NodeStore writer batch. The
merge preserves live Hostinfo by stable ID, prefers persisted NetInfo when
present, keeps stored Hostname separate, and leaves online connection tracking
intact. One COW publication avoids a full map clone per node.

Native key lookup prefers the loaded canonical node key's stable primary ID;
fallback database lookups normalize imported hex case and nullable zero keys.
Strict database key/Hostinfo decoding and fallible auth planning prevent malformed
snapshots from silently becoming defaults. The integer widths, nil Hostinfo and
explicit-unset distinctions of the public wire model remain narrower than Go.
Unsupported projection now returns an error. The existing wire field types and
wire-only dependency boundary are unchanged.

Cross-process writers, rows added during a guarded backfill, corrupt duplicate
key/index sets, unusual address representations, exact database diagnostics
and resource/lifecycle behavior remain incomplete or unqualified.

This implementation batch is unbuilt and unexecuted. Existing earlier reports
do not qualify these changes; no package, feature, license, container, client,
process, rollback or restart gate was run.

## Control request JSON and time

`src/tailscale_wire/request_json.rs` applies the pinned Tailscale v1.98.3
RegisterRequest/Auth/Oauth2Token and MapRequest schemas through the pure ACL
JSON decoder before projecting into unchanged public wire types. Register/map
requests now share native Hostinfo field folding, null/duplicate/object/slice
semantics and known-key/prefix validation. Unknown subtrees are scanned rather
than recursively materialized through serde. Byte signatures/certificates accept
Go base64/uint8 inputs. Key/opt.Bool/network/time custom unmarshal errors halt;
ordinary type errors are saved while Version decoding continues, as in Go.
Key diagnostics do not echo material. Service Proto/Port zero fields now emit
as required by tailcfg.Service. Direct public serde consumers still retain
serde's own decoding behavior.

`src/tailscale_wire/go_time.rs` follows Go 1.26.9 Time.UnmarshalJSON and its
currently disabled strict RFC3339 fallback: uppercase separators, fixed date/
minute/second widths, one/two-digit hours, comma/period fractions, nanosecond
truncation, valid calendar dates and timezone hour/minute bounds of 24/60.
JSON escapes and leap seconds reject. Accepted instants project to UTC through
the existing chrono dependency. Nil pointer versus scalar-null state is handled
by the shared field decoder; this is not an execution qualification.

Go 1.26.9 source SHA-256:

- `time/time.go`: `e8b6ea9e6e7cb890aeed1d24ee7163a2237b6fa78ffc564efb8688dba717f02a`.
- `time/format.go`: `f288c56858ab25828551681778f006b591ed140fc12e60122b6a9a7e35b07eb7`.
- `time/format_rfc3339.go`: `14b2a58fa295cca1a4f99467f5a5059418ed266a2298316124af97ffa014f271`.

NOTICE-GO-STDLIB/TAILSCALE and LICENSE-GO-STDLIB/TAILSCALE retain copyrights and
BSD terms and are included by both runtime container recipes. Shared schema,
key/P-256 and JSON source hashes are in the ACL/database provenance. Existing
base64/num-bigint releases were reused, with no external version change. Public
wire integer widths, nil Hostinfo/explicit-unset projection, SignatureType
canonicalization, exact errors/log bytes, uncommon time ranges, feature/lock/
license/container and downstream integration behavior remain incomplete or
unqualified. No tests, builds or executable validators covered this source work.

## SSH policy identity and successful reload side effects

`PolicyStore` now creates a new private SSH approval identity on successful
policy publication. The SSH handler evaluates the check rule and cache decision
under one policy read snapshot; a follow-up approval is stamped in that same
snapshot. Persisted timestamp precision cannot preserve an earlier approval
across a successful write. Native policy writes/reloads clear the auth cache.
A configured successful reload with empty/nil policy bytes retains the existing
policy but invalidates approvals and re-evaluates auto-approved routes, following
State.ReloadPolicy. A failed load/validation does not reach that success path.
The empty file-path case skips; unsupported Go policy modes supply nil bytes.

The existing public timestamp helpers remain available for legacy observation
and seeding. Production cache lookup requires a live policy stamp; custom
embedders can use RegistrationCache.record_ssh_auth_for_policy. Two existing
positive fixture calls were source-adjusted only. No public wire field changed.
The identity retains only Arc<()> ownership, not old policy content or secrets.

Pinned Headscale v0.29.5 sources:

- `hscontrol/state/state.go` (SetPolicy, ReloadPolicy, ClearSSHCheckAuth): `7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01`.
- `hscontrol/db/policy.go` (PolicyBytes): `59aca2ef1a9d8a0187ffd37df1c40ad12ed2a5b63c8f4c7825118a5809950746`.

SignatureType wire decoding delegates once to the shared ACL text adapter, and
zero omits the field. Its pinned non-idempotent conversion is not repeated by
the raw request schema. All of this is unbuilt/unexecuted. Concurrency, cache
retention, legacy/custom integrations, queued approvals, empty/failed reloads,
route failures, paired stock clients/process/restart and feature qualification
remain open; these changes do not close a parity gate.

## Policy route fan-out and retained notifications

The native/wire MachineAdmin auto-approval method reads selected live IDs,
acquires sorted machine guards, re-resolves after waiting and builds one route
plan from one policy document snapshot. Both address families reach NodeView.
Typed zero prefixes, duplicate comparison and order-only non-changes follow
policy.ApproveRoutesWithPolicy. Existing helper address fixtures were adapted
in source only. Native checked reads use the runtime registry; headless node
query failures propagate, including candidate policy validation. Legacy custom
adapters keep their list/batch fallback contracts.

MachineRegistry.apply_policy_route_approvals applies stable IDs in one quiet
NodeStore writer item, skips absent IDs and clears inactive route health. An
owned worker retains guards through per-node persistence. The ordering follows
State.autoApproveNodes: full live batch first, durable saves second; a database
failure can leave partial durable progress. Attached native stores now re-read
and save each current cached node under a registry-wide persistence mutex with
Go persistNode's selected-column mask. Expiry, auth-key references, CreatedAt and
DeletedAt are excluded. SQL updates never insert absent IDs or reject zero
affected rows. Headless adapters keep approvals-only persistence.

src/admin/machines/native_snapshot.rs records native nullable shapes during
hydration/committed publication, including the explicit CLI/OIDC publication
hook and backfill refresh. Ordinary wire reads do not refresh that state.
Unchanged projections preserve native address/owner/method/Hostinfo/slice/
LastSeen values; fieldwise Hostinfo changes retain unrelated explicit unset
values. Successful saves advance the baseline and absent-node deletion/GC
removes it. The fields and mutex are admin-only; public wire types stay fixed.
Custom same-value nil/unset transitions cannot all be expressed through the
public projection. Native timestamp fallbacks and exact JSON bytes remain
unqualified, as do cache/row equivalence, memory, lock, cancellation and restart
behavior. No tests, builds or executable validators covered this implementation.

Additional pinned Headscale v0.29.5 source SHA-256:

- `hscontrol/policy/policy.go`: `e5caa6ced4ebda898a5f79aa8da733103fb19bfbcdf2c9b5805838cac8fbe121`.
- `hscontrol/state/node_store.go`: `5bef0767885748e96e3d0e7a9f2bb5bb6d623d1de8c8ef5afb2b49201aa95028`.

PolicyStore has a watch channel beside its existing Notify API. Map streams
subscribe before initial processing and retain the receiver across chunk yields.
Policy publication/user refresh advance its watch version. Mutation handlers
notify after successful auto-approval; failed persistence leaves live state as
Go does without publishing success. This preserves edits made between polls.
No public wire field type or dependency version changed. Locks, batching, raw/
external writers, partial failure, cache persistence, receiver timing/coalescing,
resource, feature/client/process and restart behavior are unqualified. No build,
test or executable validator covered the source changes.

Native auth-path/runtime CreateParams now use the same fallible Hostinfo
encoding boundary as cached snapshots. Non-finite floats reject before serde's
null coercion, encoding errors propagate and no reduced fallback object is
substituted. Canonical Hostinfo fields are no longer removed based on differing
admin aliases. This remains unbuilt/unexecuted source behavior.

## Policy RPC write ordering and timestamp precision

The database SetPolicy RPC now follows pinned grpcv1.SetPolicy, State.SetPolicy,
State.ReloadPolicy and DB.SetPolicy: validate/install in memory, clear SSH
approvals, append policy history, re-read the actual latest row, apply the reload
and distribute only after success. An append/reload failure retains already
installed live policy; no rollback or success notification is fabricated.
Zero bytes skip document replacement but still clear approvals and traverse the
append/reload sequence. CheckPolicy accepts the no-policy sandbox for zero bytes.
The existing memory adapter retains its non-database contract.

PolicyPersistence has default precise-timestamp methods for legacy custom
backends. SQLite/Postgres overrides use the new TimedPolicyRow projection so
GetPolicy/SetPolicy keep fractional UpdatedAt; old PersistedPolicy and PolicyRow
fields and public wire types are unchanged. The database sources and precision
limits are described in ../headscale-db/UPSTREAM.md.

Headscale v0.29.5 additional source SHA-256:

- hscontrol/grpcv1.go: 1bb435c674a64b3a7d1382eddfc9b33d7fb8f646c414709d011508d0a2e883c3.
- hscontrol/types/policy.go: ae45869c30684f8a08388db3f0c97b9aab7c386abfe35137269a9b8119ec0ac9.

State/db policy source hashes and original BSD terms remain recorded above and
in NOTICE-HEADSCALE-GO/LICENSE-HEADSCALE-GO. No dependency version changed.
These are unbuilt/unexecuted source changes. Empty/failed writes, external
appends/deletion, reload errors, validation/SSH precedence, custom backends,
nullable/unusual dates, precise output, resources/cancellation, feature/container
and process/restart behavior remain unqualified. No parity gate is closed.

## Native admin mutation authority and save ordering

Attached persistent adapters now use NodeStore for get/raw hostname/ordinary
wire projection and registration-policy snapshots. Tags, approvals, rename and
custom advertised-route edits use one quiet writer mutation by stable ID, then
a fresh snapshot under the shared save mutex and Go persistNode's selected mask.
Name collision checks occur inside the writer before assignment. Explicit tag
ownership clearing and empty-approval nil intent survive failed SQL writes.
Expiry/disable-expiry use a narrow expiry/UpdatedAt save, following NodeSetExpiry.
Successful saves notify afterward; failure retains live state without success
dispatch. Owned workers retain machine guards. Headless adapters keep their
existing database behavior, and committed-row publication keeps its explicit
separate hook.

The public wire tag setter also sorts/compacts tags, clears user metadata even
for identical tags and supplies the origin node for self refresh. Single explicit
approval writes retain their mutation/notification on equal vectors. Approved
route health clearing uses announced intersect approved including exit routes,
as Go Node.AllApprovedRoutes does. One existing noop fixture now uses unchanged
advertised routes and one tag order expectation was source-adjusted only.

References at Headscale v0.29.5: state/state.go SetNodeTags, SetApprovedRoutes,
RenameNode, SetNodeExpiry and persistNode (hash above); db/node.go SHA-256
9b1badd1eba80662eccb1eb5e2d0f039967b6469a30fab6fb3904466de234bb4;
types/node.go SHA-256
b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab.
Existing Headscale BSD terms/notices cover the implementation. Public wire field
types and dependency versions are unchanged; the native writer helper is admin-only.

No build, test or executable validator covered this batch. Native FQDN length
validation and basic deletion/address release have since received source
implementation below; attached map/logout persistence has since received
source implementation too, while wider registration/cache authority remains open. Headless/custom behavior, held guards, fail/retry/
restart, malformed/duplicate/stale rows, raw/external writers, ownership/HA/online/
notification timing, resource, feature/wire-only and package/container behavior
remain unqualified. No parity gate is closed.

## Rename bounds, durable deletion and address release

The registry now accepts its configured given-name domain from production
preparation and control-router setup. Native/wire rename uses shared
headscale_api_acl::go_dnsname before mutation; map FQDN checks share that rule.
The leaf records Tailscale label and Headscale full-name source provenance.
No public wire field changed or dependency version was added.

Native admin deletion selects the live ID instead of requiring a SQL row,
retains machine guards and persistMu through DELETE/cache removal, and accepts
zero affected rows. A failed DELETE retains cache/session/IP state. Native
known-ID ephemeral deletion uses the same zero-row SQL behavior under the save
lock; its machine guard survives through the outer cache-removal worker. The
legacy no-ID fallback still checks the database row identity.

IpAllocator.release_addresses has a default no-op for existing custom adapters.
The registry stores a weak allocator reference, configured during preparation,
router setup and either gRPC builder order. Direct and queued deletes capture
the actually removed record, release addresses outside the NodeStore write lock,
then dispatch removal. Legacy ephemeral sweep removal has the same release
boundary; rekey does not release addresses. This follows State.DeleteNode and
IPAllocator.FreeIPs at the existing Headscale v0.29.5 pin, with original BSD
terms retained in this package and the CLI allocator package.

This source is unbuilt/unexecuted. FQDN/byte/error cases, missing/failed deletes,
external or raw writers, queue/delete/rekey/reconnect behavior, weak/callback
lifetime, manual/custom configuration, allocator reuse, unusual address shapes,
locking/cancellation/resources, features/wire-only/package/container and client/
process/restart behavior remain unqualified. Attached map/logout persistence
has since received source implementation below; wider registration/cache and
registration raw shapes and debug Hostinfo readback now have source implementation below; wider native cache authority, non-Hostinfo debug JSON and direct public serde remain incomplete or unqualified. No gate is closed.

## Native map saves and user logout ordering

Attached native runtime sync reads the fresh stable-ID NodeStore snapshot under
the shared save mutex, writes the existing CachedNodeSnapshot mask and returns
that live record. SQL rows no longer determine ownership, names, approvals or
client state on this path. The native nullable-shape baseline describes the live
snapshot before SQL, including failure. runtime_sync_returns_live_snapshot is a
default-compatible trait hook that skips the old post-SQL application for native
attached stores; headless/custom adapters keep their existing contract.

Map state is now quiet until persistence succeeds for every request. Streams
also wait for Connect before peer dispatch. Native auto names reserve inside
the NodeStore writer rather than a pre-writer snapshot. Request Hostinfo routes
keep order/duplicates/typed zero values while each item is canonicalized. The
primary advertiser map is compared by stable ID around the live edit so a route
announcement change can trigger policy fan-out without new approvals.

User-owned native logout applies expiry quietly first and uses an ID-based fresh
read plus the narrow expiry/UpdatedAt save under the shared mutex. The caller
publishes after success; SQL failure leaves live expiry in place. This follows
Headscale State.SetNodeExpiry and handleLogout. Ephemeral deletion and tagged
logout keep their existing distinct branches.

Additional pinned Headscale v0.29.5 source SHA-256:

- hscontrol/auth.go: b54d2e7541e24eeeb35df63ae4a6c5718b42d208e63e5786e3bdc5727755a3dd.
- hscontrol/state/maprequest.go: 77cd7b1a2e90a199bdab3ef7eecd96cc490dab0174ded3823348f1db5519c8d0.

hscontrol/state/state.go UpdateNodeFromMapRequest/persistNode/SetNodeExpiry and NodeStore
source hashes remain recorded above, with existing Headscale BSD notices/terms.
No public wire field type or dependency version changed. All changes are unbuilt
and unexecuted. Private raw map shapes/replacement and retained self-refreshes
now have source implementation as described below. Wider registration/cache
fresh-node authority and non-Hostinfo debug JSON/direct public serde remain source work;
custom hooks, primary/HA/clock/failure/cancellation/resource,
feature/wire-only/package/container and client/process/restart need qualification.
No parity gate is closed by these source edits.

## Private map Hostinfo and retained self-refresh dispatch

`src/tailscale_wire/hostinfo.rs`, `request_json.rs`, `mod.rs` and `map.rs`
retain typed Hostinfo alongside the unchanged public projection. Native row
publication seeds the private snapshot; the NodeStore writer installs complete
map replacements. Native persistence overlays this snapshot before selected-
column saves. Fieldwise admin edits use projection merging; map replacement
carries only nil NetInfo, preserving its native opt.Bool values. The pure ACL
comparison follows Headscale state/maprequest.go hostinfoEqual and
peerHostinfoEqual, Tailscale Hostinfo.Equal and NetInfo.BasicallyEqual. Nil roots,
Go scalar zero defaults, slice nilness and explicit-unset opt.Bool remain visible
to mutation/storage decisions despite the narrower public types.

DNS metadata IDs queue after the live mutation and before its save. Every change
dispatch drains sorted unique IDs as SelfUpdate, even when a successful map has
no peer delta. Errors before dispatch retain queued IDs for the next dispatch.
This follows State.DrainSelfRefreshes and Headscale.Change. The pinned
hscontrol/app.go SHA-256 is
381958868e878b30c1f43138808b7cb3daf27c05a3db762ed3d672bf9f779a85;
state.go, state/maprequest.go and Tailscale tailcfg/opt source hashes are above.

This is unbuilt/unexecuted. Wider registration/cache authority, public-only
custom storage/upsert semantics, non-Hostinfo debug JSON/direct public serde projection, integer widths, concurrency/cancellation/failure/restart and feature/
package/container behavior remain incomplete or unqualified. Notices retain the
Headscale/Tailscale BSD terms. No dependency release or parity gate changed.

Private Hostinfo response emission also covers initial/full/incremental framed
maps and non-streaming JSON. Self Node, Peers and PeersChanged are decorated
from the node snapshot using the shared typed Hostinfo marshaler. Pinned Node's
Hostinfo omitzero tag omits nil views; a non-nil empty view emits {}. Explicit
unset opt.Bool emits null; scalar and slice zero omission follow tailcfg tags.
MapNode.hostinfo's public type is unchanged and now defaults when omitted during
serde decoding. Compact ping/keepalive encoding remains separate. Debug Hostinfo
readback now has source implementation below; direct public serde stays narrow; policy/fallback stream
comparison now retains private typed peer snapshots as described below. Snapshot
coherence under raw/external writers, output bytes, resources and runtime/client/
restart behavior are unqualified. Direct rustfmt only; no executable validation.
Tailscale v1.98.3 tailcfg/tailcfg_view.go (HostinfoView.Valid/MarshalJSON) SHA-256:
31887b3c518f2ec3de1dd04d7b9cb05fa7d5cbecb76d90f626a0614640f74908.

Private PeerStateNode snapshots now carry each stream peer's typed Hostinfo
beside its public MapNode. Raw peer-field equality participates in incremental
comparison and patch eligibility, so a hidden nil-root/AppConnector opt.Bool
change forces a whole node under policy/fallback/batch paths too. Nil/empty
slice rules remain peer-specific. This follows the same pinned
state/maprequest.go peerHostinfoEqual field set; no public type changed.
Debug Hostinfo readback now has source implementation below; direct public
serde remains projection-based. Source only,
without build, execution, concurrency/resource or process/restart evidence.

## Registration Hostinfo and debug readback

RegisterRequest decoding retains the typed Hostinfo companion privately.
RegistrationCache owns it in the same immutable entry as the pending record;
web/CLI/OIDC completion captures both together before its owned worker. Optional
MachineRegistrationStore/MachineAdmin hooks preserve legacy custom defaults.
SQLite/Postgres auth-key and callback plans rebase native shapes onto producer
edits, preserve original omitted NetInfo and fresh-web RequestTags compaction,
and keep route-vector order/duplicates/typed zero prefixes. Nil requests complete
with a non-nil empty Hostinfo, matching the pinned state/auth paths.

After commit, native plans stage the pre-omitempty value for publication by
stable ID/key/matching projection. Native metadata captures consume this intent;
ordinary metadata replacement and deletion discard pending values. Volatile
completion installs the companion in the NodeStore writer and uses raw
peerHostinfoEqual when classifying a relogin. This prevents a public Option<bool>
projection from reducing a hidden peer change to a key-only patch. Native
existing registration SQL/cache authority, live-first rollback and prior raw
notification classification now have source implementation below; staging/callback/failure/external-writer
coherence is not qualified.

Debug dumps use the private response representation. The operator readback
projects supported MapResponse fields and separately normalizes/restores each
node's typed Hostinfo; it does not echo unknown file JSON. The public typed read
method stays available. .json byte suffixes, local timestamps with trimmed
nanosecond fractions and umask-respecting 0755 create modes follow the pinned
mapper. Existing paths are not chmodded. Complete non-Hostinfo Go JSON grammar,
field folding/duplicates/nulls/integer widths/errors and direct public serde
remain narrower or unqualified.

Headscale v0.29.5 SHA-256, in addition to state.go/auth.go/maprequest.go above:

- hscontrol/mapper/mapper.go: ec191db53afd7a906aaf015bf32c372c75c0b110aa784e5277e45269d2496534.
- hscontrol/debug.go: 032c61a16ce0da210153d6d430f60fc4bf31345e65586cc9c03329a9b7f5a845.

The same pinned Headscale/Tailscale BSD notices apply. No public wire field type
or external dependency release changed. Direct rustfmt only; no build, tests,
probes, executable parity validator, advisory/license/package/container or
process/restart qualification ran. All three release gates remain open.

## Existing native registration ordering and rollback

Attached registration planning and address preparation now construct native
planning projections from NodeStore records and private shapes. SQL node rows
are no longer selected as this path's authority; credential/user checks retain
their dedicated backend behavior. A quiet NodeStore writer rekeys and installs
Hostinfo/owner/tags/expiry before an existing-node save, retaining GivenName,
addresses, creation time, approvals and stable-ID connection tracking.

LiveRegistrationSave and the shared DB cached_registration adapter follow
state/state.go applyAuthNodeUpdate and RegisterNodeWithPreAuthKey: Expiry joins
the cached selected-column mask; AuthKeyID is written on auth-key registration
and otherwise omitted unless clearing it. Creation/deletion timestamps are not
selected. Missing SQL rows succeed without insertion or SQL name reservation.
Auth-key errors restore the prior cached record/key/Hostinfo/native metadata;
web/CLI/OIDC errors retain the quiet live edit. Credential validation/locking and
one-shot consumption remain in a transaction, including unused keys on a
skip-validation refresh. Auth-key reauth uses the presented key's ephemeral
property; user-to-tag conversion clears expiry.

Success retains before/raw peer data until publication. Publication uses current
live state, merges same-owner canonical profile fields, classifies hidden raw
peer changes through peerHostinfoEqual and skips SQL snapshot reapplication.
Deletion clears the pending snapshot. Existing map/session tracking remains
bound to the stable ID. The source references are the existing pinned state.go,
maprequest.go, node_store.go and types/node.go hashes and Headscale BSD terms.

This is unbuilt/unexecuted. Fresh-node name/approval/nil behavior now has source
implementation below. Exact policy lifecycle hashing/change counts, default/account clocks, wide/zero/
native values, duplicate keys, credential/cache races, delayed/failed completion
cleanup, encoding/SQL/rollback errors, concurrent/external writers, resources/
cancellation and feature/package/container/client/process/restart remain source
work or qualification gates. No public wire field type or external dependency
release changed. Direct rustfmt only; no executable validation or new advisory
review closes any release gate.

## Fresh registration publication — 2026-10-18

Attached fresh auth-key/CLI/OIDC registration now uses the dedicated DB
NewNodeRegistration insert. It preserves nil endpoints/tags/approvals, raw empty
scalar text, the sanitized initial GivenName and pre-marshal Hostinfo/time fields.
SQL assigns the ID and commits before PutNode publishes. Auth-key insertion and
one-shot consumption remain in one transaction. No SQL name lookup/reservation/
retry or row reread occurs on this native path; headless legacy helpers retain
their contracts.

The NodeStore writer resolves the initial name against earlier live writes,
including empty fallback and suffix bumps, while SQL retains the original seed
until a later cached save. Created/updated publication variants preserve raw
Hostinfo/nil metadata and avoid SQL reapplication; original verified wire owner
metadata is retained for fresh nodes. Registration does not auto-approve routes:
fresh nodes start nil and reauth keeps the existing vector and GivenName. Later
map/policy lifecycle behavior handles approvals. The signed AuthKeyID field type
in the recently added existing-node helper was corrected without changing any
public wire field.

Pinned Headscale v0.29.5 SHA-256:

- state/state.go createAndSaveNewNode: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01.
- state/node_store.go PutNode/resolveGivenName: 5bef0767885748e96e3d0e7a9f2bb5bb6d623d1de8c8ef5afb2b49201aa95028.

Gorm v1.31.1 schema/serializer.go JSONSerializer.Value nil-to-SQL-NULL behavior
has SHA-256 9dadcf607eccadd1f6cab29f72a95d8ff7c683e20dd412f585a5b5d15797a1a8.
Existing Headscale/Gorm/Tailscale BSD/MIT notices and terms remain packaged.
No external dependency release changed.

Unbuilt/unexecuted source only. Exact policy lifecycle hashes/change counts,
deferred/failed publication cleanup, credential/cache/account clocks, key/row
corruption, resource/cancellation, original versus stored timestamp precision,
initial SQL versus cached name behavior, nil/zero/wide values and feature/package/
container/client/process/import/restart remain incomplete or unqualified. Direct
rustfmt only; no tests/builds/probes/validators or new advisory evidence closes
any of the three release gates.

The Gorm JSONSerializer compatibility reference now carries LICENSE-GORM and
NOTICE-GORM in API and DB packages, and their SPDX expressions include MIT.
Existing container wildcard copies include these files. No package/image/license
validator ran, and no Gorm runtime dependency or release upgrade was added.

## Registration completion lifetime — 2026-10-18

The built-in completion workers retain a private revision-scoped cleanup owner
inside both registration guards. Return/failure/destruction discards newer matching
pending publication and staged Hostinfo bookkeeping without altering live/durable
nodes or dispatching successful changes. Direct/manual adapter callers outside
those scopes still require ownership; request resets retain the spawned worker.

CLI, SQLite/Postgres OIDC and volatile web handlers capture the original auth entry
with its pending record/Hostinfo before waiting for locks. Finish retains Go's
first-verdict-wins behavior after eviction, and returns the admitted mutation's
result even if its original waiter already expired. Pointer-identity cache removal
preserves a replacement entry under the same ID; this differs from Go's unconditional
Remove in that exceptional case. Callbacks admitted concurrently before completion
may both serialize and finish; later admissions fail. Public cache methods/wire
fields retain their contracts and no DB/core dependency was added to wire-only.

Fresh auth publication selects the single global policy change returned by
SetNodes/reauthChange. Existing completion compares ordered tags, numeric owner
identity and active route multisets retaining duplicate announcements. These are
local comparisons; exact prior policy inputs, resolved hashes, per-node route
invalidation and association-validity representation remain source work.

Pinned Headscale v0.29.5 SHA-256:

- hscontrol/types/common.go AuthRequest/FinishAuth: 0b660e6e4db2b32a6b136b33c710f4204f19c180d4e16b6db19ff7411ddfb08d.
- hscontrol/state/state.go authCache/HandleNodeFromAuthPath/reauthChange: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01.
- hscontrol/policy/v2/policy.go SetNodes: 1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e.
- hscontrol/types/node.go HasPolicyChange/route slices: b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab.

Existing Headscale BSD notice/license remain packaged. No dependency version or
release gate changed. Unbuilt/unexecuted; direct rustfmt only. Expiry/eviction,
duplicate/replaced IDs, SQL/error/publication sequencing, locking/cancellation/
resources and native/wire-only/custom/package/container/client/process/restart
remain unqualified. No test/build/validator/probe or fresh advisory evidence ran.

## Retained policy node inputs — 2026-10-18

src/policy/lifecycle.rs follows PolicyManager.SetNodes,
nodesHavePolicyAffectingChanges and NodeView.HasPolicyChange/HasNetworkChanges.
A private snapshot retains count, stable ID, raw owner, loaded numeric owner
association, ordered tags/IPs and sorted active/announced route multisets. Nil
and empty slices compare equally; duplicate announcements remain significant.
Previously compiled self/via category controls announcement-only invalidation.
Native shapes retain hidden raw ownership and nullable/zero/zoned address text.
The stable public association projection remains narrower than Go's independent
UserID and loaded User pointer.

The source-resolving per-node category follows compiled.go compileOneGrant and
compileOneViaGrant, including inert-source handling and raw nil-versus-empty App
presence. Policy/user changes recompile it; identical sorted PolicyUser facts
skip replacement. This is category/input tracking, not the complete upstream
compiled-filter/alias/SSH/CapMap cache or deephash implementation.

Serving startup, gRPC attachment and control routers bind the store after node
hydration. Successful native/volatile auth, native admin, substantive map refresh,
non-empty auto-approval, expiry and deletion boundaries advance it. Failed saves
retain the previous inputs. Repeated listener setup does not reset the same store.
Backfill deliberately retains its pinned no-policy-refresh behavior. Global policy
origins, tag origin and expiry merge content follow state.go and change.go.
Startup warning projection now uses the existing forced_tags wire field.

Additional pinned Headscale v0.29.5 source SHA-256:

- hscontrol/policy/v2/compiled.go: eebe64a7730e70428a3b63828aea9b9e1dd7a10e8d4ae9b9f8965ad8b781f7c7.
- hscontrol/types/change/change.go: 23f5812aeee446d15f5e2624ddb9e25171bb3ba4ff40c82feaa9e183c2d2dcba.
- hscontrol/types/users.go: 36bc0f562c507336d3a2a309c94718ec3baa2db2c3432180596556ab512d69dd.

Existing state.go, policy.go and node.go hashes and BSD license/notice apply.
No external dependency version, public wire field or wire-only DB/core boundary
changed. Unbuilt/unexecuted, direct rustfmt only. Full retained compilation and
live-evaluation authority, user-change reporting, exact hashes/logs/change counts,
errors/failures, remaining volatile/raw/custom refresh sites, association/nil/zero/
wide values, concurrency/resources/cancellation and native/wire-only/package/
container/client/process/restart remain incomplete or unqualified. No tests,
builds, probes, validators or fresh advisory evidence closes a release gate.

Quiet auth rekey publication retains the queue's final identity check and
performs policy input refresh before dispatch. Empty direct/queued rekey changes
skip wake calls so they do not prematurely drain pending self-refreshes. These
source edits have no build, concurrency, cancellation or process qualification.

## Retained serving policy and matchers — 2026-10-18

src/policy/runtime.rs now retains the global filter/resolver node snapshot and
per-node filter, SSH and matcher caches. Input-change recompilation, unchanged
policy cache retention and selective global network invalidation follow the
pinned policy.go FilterForNode/SSHPolicy/MatchersForNode/SetNodes/SetUsers paths.
SSH check lookup uses current policy-manager nodes, not arbitrary live caller
nodes. An SSH cache miss still receives the current target view while aliases
resolve against the retained list. Localpart rules use directory email keyed by
numeric account; principal grouping/order and tagged multiplicity follow filter.go.

Node attrs resolve target IP sets against all retained node IPs and cache stable
IDs. Changes accumulate across updates and drain with DNS self-refreshes.
Route/exit approval uses retained resolved IP sets; tag-owner queries use the
retained doc/nodes and current-user fallback. Approval batches own one snapshot.
Private matcher.rs follows MatchFromFilterRule and Node.CanAccess/CanAccessRoute:
source node/subnet identity, DstPorts plus CapGrant destinations, merged-prefix
internet coverage, fresh unreduced four-direction self/via peer maps and lazy
per-node route matchers. Via aliases retain resolved IP prefixes and the internet
marker separately from current candidate routes.

Bound PolicyStore notifications now dispatch through one weak registry link,
so batched streams receive a policy event even when approval count is zero.
Volatile approval fan-out uses a quiet stable-ID batch before dispatch. Native
adapters retain SQL ownership and map watchers do not invent another cache-only
approval; user refresh does not run reload approval fan-out. Volatile admin
mutations and explicit durable row publication refresh inputs before dispatch.
Trusted raw registry writes have an explicit refresh_policy_nodes hook. No public
wire field, dependency release or wire-only DB/core boundary changed.

Additional pinned Headscale v0.29.5 SHA-256:

- hscontrol/policy/matcher/matcher.go: 94466c4793a902b3d2ffbd9eda044c9cf3f328a925067e9f6132b88e6ac84189.
- hscontrol/policy/v2/filter.go: 5a3ff3d7a19888a58d4d40425cb6c5a7210758d9f9e2ed6181c555a1bccf7b4b.
- hscontrol/policy/v2/types.go: 57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.

The previously recorded policy.go, compiled.go, node.go, users.go, state.go and
change.go hashes and Headscale BSD notice/license apply. Direct rustfmt only;
unbuilt/unexecuted. Exact typed/nil/duplicate/error/rollback/hash/log/change-count
behavior, per-node resolver versus eager-compiler resources, SetUsers result
reporting, Unicode/localparts, association/zero/zoned/wide native shapes and raw/
custom/external-writer lifecycles remain incomplete or unqualified. Cache memory,
ordering/cancellation/weak ownership, feature/package/container and paired client/
process/restart gates remain open. No tests/builds/probes/validators or fresh
advisory evidence qualifies this batch.

## User refresh results and eager tag owners — 2026-10-18

PolicyUserChange now separates Go SetUsers' policy-change and peer-map-change
results. Sorted PolicyUser facts are ID/name/email/provider identity. Bound
change reporting compares retained global rules and canonical tag/approver IP
sets, with forced client refresh for SSH/per-node policies when user facts move.
Attribute changes keep their independent accumulated drain. Native create forces
PolicyChange; update uses the result without eagerly changing cached node user
profiles; delete falls back to UserRemoved. This follows policy.go SetUsers and
state.go CreateUser/UpdateUser/DeleteUser at the existing pinned hashes.

runtime.rs now flattens tag-owner topology before policy replacement, drops
cyclic back edges, sorts/deduplicates aliases and rejects undefined nested tags.
Bound tag checks use an eager canonical IP set plus direct-user fallback.
Route/exit sets also use canonical spans, with configured-empty versus nil exit
sets distinct. Fallible setters propagate static rejection through native file/
database startup, load/reload, policy RPC and admin policy writes. Legacy setters
log rejection while retaining active source/directory. Go quote handles tag/user
diagnostics. Dynamic resolver failures and partially updated runtime/error
restoration ordering remain incomplete, including resource/error fidelity for
retained Rust resolver work on per-node misses.

SSH localpart domains and JSON field names use the ACL leaf's pinned Go Unicode
15.0.0 SimpleFold/EqualFold implementation at UTF-8 boundaries. Go notices and
BSD terms apply; leaf UPSTREAM.md records the Unicode sources and hashes.
No external dependency release, public wire field or wire-only DB/core boundary
changed. These changes supersede preceding user-result/eager-tag/ASCII-fold
source gaps. Direct rustfmt only; unbuilt/unexecuted. Parsed nil/duplicate
representation, remaining native association/zero/zoned/wide values, exact logs/
hash/change counts, concurrency/resources, feature/package/container and paired
client/process/restart behavior remain incomplete or unqualified. No release
gate or advisory conclusion changes.

## Partial aliases and policy refresh errors — 2026-10-18

src/policy/resolution.rs follows v0.29.5 types.go Alias/Username/Group/Tag/
AutoGroup resolution: optional partial sets and errors are independent. Missing
users/groups yield usable empty sets. Packet-filter/SSH/tag/approver consumers
retain partial sets; compiled.go capability/via destinations skip errored aliases;
nodeAttrs rejects target errors. Self-grant admission distinguishes nil from
resolved-empty sources; capability destinations retain empty non-nil sets.
Source autogroup:self rejects the entire grant. Identity-address insertion strips
zones, while query membership rejects zones, following pinned netipx behavior.

SetUsers no longer repeats SetPolicy's broad reference validation. Caches clear
before compilation; failure restores only the directory while retaining earlier
global/approver phases. Lazy SSH and direct-user tag fallback read that restored
directory. SetPolicy failure restores/recompiles the previous document. SetNodes
keeps new node inputs after failure and preinvalidates global network or affected
raw-owner filter/matcher caches, including tagged-entry zero-owner behavior.
NodeAttrs errors preserve its old values and pending-diff union. These paths
follow policy.go updateLocked/SetUsers/SetPolicy/SetNodes/invalidateNodeCache at
the existing pinned hashes; eager-grant versus lazy-resolver fidelity remains
incomplete or unqualified.

New checked registry APIs propagate native startup/admin/saved-row/registration/
OIDC/auth-key/approval/map/expiry/deletion errors before success dispatch. Policy
errors map to gRPC Unknown/HTTP 500; earlier SQL/live writes are not implicitly
rolled back. Legacy public bool/log wrappers and remaining volatile/static-error/
custom callers still need complete propagation. Base invalid-IP diagnostics omit
Go4's stack trace; exact diagnostic and partial-phase order remain unqualified.

Additional go4.org/netipx v0.0.0-20231129151722-fdeea329fbba SHA-256:

- ipset.go: 01d0a58880b95e75f0b8e90e076eb9b56697bf9c9d075c030d422f2aafacd659.
- netipx.go: ff3005dd1e09a1169976c5996443b3797bba7ee4795362f7cce44cbbe8c8fb46.

NOTICE-NETIPX/LICENSE-NETIPX retain the original Inet.af Authors BSD notice/terms
in API and CLI packages. No dependency release or public wire field changed.
Direct rustfmt only, no builds/execution/validators/probes/advisory refresh.
Empty App/CapMap and parsed nil/duplicate policy representation, native loaded
association/zero/zoned/wide shapes, remaining lifecycles, resources/ordering/
cancellation and all native/wire-only/package/container/client/process/restart
evidence remain incomplete or unqualified. All release gates remain open.

## Volatile refresh and App nil shape — 2026-10-18

Built-in volatile create/rename/tag/routes/batches and interactive/auth-key
registration now propagate policy refresh errors before success dispatch/auth
completion, following the existing pinned State policy-refresh boundaries.
RegistryMutationError distinguishes input rejection from a late policy failure;
checked registry entry points expose that distinction to admin/HTTP adapters and
embedders. Bool/static-error compatibility entry points retain their signatures.
The checked ephemeral sweep completes address/connection cleanup and returns a
late policy error without success dispatch. Background sweeps log that error.

The ACL leaf's go_policy_shape.rs retains raw Grant.App map nilness and nil
capability value keys, supplementing the public map-of-vectors representation.
PolicyStore retains this shape through comparison, restoration and global/
per-node/unreduced compilation, including unbound recipient filters. Explicit
empty App on an IP grant emits the CapGrant rule; nil App does not. Capability
value null and [] remain distinct wire values. Self-source grants are rejected
in the app compiler as well. The leaf decoder accepts null App/value slices and
still validates empty App-only grants as missing ip/app, following types.go
validation and compiled.go compileOtherDests at the recorded v0.29.5 hashes.
Case-folded App fields retain opaque metadata payloads during stripping.

No dependency release, public wire/policy field type or wire-only DB/core
boundary changed. Existing Headscale BSD notices apply; ACL UPSTREAM.md records
the new shared source. Public canonical hashing remains a typed projection;
raw App shape serves the Go adapter separately. Direct rustfmt only; no build,
test, validator, probe, advisory refresh, feature/package/container/client/
process/restart evidence ran. Raw opaque JSON bytes, complete nil/duplicate/
backing-array policy representation, loaded native association/zero/zoned/wide
values, raw/custom/misbound/external writers, exact diagnostics/hash/change
counts, eager resources and concurrency/cancellation remain unqualified. No
release gate is closed.

## Policy JSON v2 boundary — 2026-10-18

The shared ACL decoder now follows v0.29.5 types.go policyJSONOpts' strict
duplicate rejection and delimiter-insensitive case matching. Ordered raw
preparation checks retained object names and known schema aliases before Serde
loses duplicate names; it reports JSON-pointer context and pinned truncation.
Metadata stripping exempts the literal app key only, correcting the prior
case-folded exemption. App shape extraction uses that same prepared input.
Supported null policy containers and member slices, default-empty nodeAttrs
targets/null entries and nil-versus-[] packet-filter defaults now follow the
pinned container boundary. Custom scalar null behavior remains separate.
HuJSON comments retain whitespace/newlines, trailing commas before comments
standardize, and unterminated block comments remain invalid syntax.

Policy JSON v2 rejects repeated names; JSON v1 reused-slot concerns remain at
the distinct wire/storage decoders. ACL UPSTREAM.md records the pinned JSON
experiment module, source hashes and BSD notices/licenses in ACL/API/CLI.
No dependency release, public field type or wire-only DB/core boundary changed.
Direct rustfmt only; no tests/builds/validators/probes or fresh advisory evidence.
Opaque byte/numeric/depth fidelity, remaining custom scalar/null/error ordering,
full nil hashing, native associations/zero/zoned/wide shapes, eager resources,
concurrency and feature/package/container/client/process/restart evidence remain
incomplete or unqualified. All release gates remain open.

## Opaque map-filter snapshots — 2026-10-18

src/policy/opaque.rs retains prepared App payload JSON separately from public
typed values. Private raw strings pass through filter compilation/reduction and
are serialized as validated JSON, following pinned tailcfg.RawMessage and Go
encoding/json compact/HTML behavior. Literal-app standardized whitespace also
participates in the retained shape. Trusted manual doc/raw pairs must project
to equal values before raw text is used; otherwise typed values are encoded.

Runtime global raw comparison and atomic per-node typed/raw entries share
refresh/failure boundaries. A miss computes both forms from one recipient view,
and concurrent misses return/publish each pair together. Immutable raw filters
use Arc ownership across frames. FilterSnapshot owns both forms under a single
policy read lock. Full/non-stream/incremental/rebuilt map responses and
native debug dump writes use that snapshot across serialization/compression;
an intervening policy write cannot replace payload text. Shared Go-style raw
compact/HTML/indent helpers retain lexical numbers/string escapes/object order.
ACL UPSTREAM.md records encoding/json/indent.go and tailcfg.go hashes; existing
Go/Tailscale/Headscale notices apply. Public wire/policy field types, dependency
releases and the wire-only DB/core boundary are unchanged.

This qualifies no execution claim: direct rustfmt only, no tests/builds/
validators/probes/advisory refresh. Typed opaque input range/depth is still
incomplete; direct public serializers and the surrounding debug readback
remain typed projections. Native opaque debug readback has source handling below.
Complete policy raw hashes/variant whitespace, nil/scalar/error order, root-field
bytes, native association/zero/zoned/wide state, eager compiler resources,
concurrency and native/wire-only/package/container/client/process/restart gates
remain open.

# Selected Go Unicode 15 hostname Lookup — 2026-10-18

The private hostname boundary now uses selected Go15 data and algorithms without
an ICU serving fallback: whole-domain mapping before ACE, selected categories/
STD3/nontransitional/contextJ, stream-safe NFC/Hangul/recomposition, bidi and
legacy signed32 Punycode. Go verifyDNSLength=false retains empty/root labels.
Raw compatibility-mapped ACE prefixes use the same phase as ordinary input;
the adapter-specific2000-byte decode limit is gone. Public policy/server/cache
APIs retain their shapes. The prior optional direct idna dependency/full feature/
lock edge was removed; no dependency version changed.

Implementation modules: tls/acme_hostname/{profile,trie,nfc,bidi,punycode,data}.rs.
The committed convert_go15.py reads ONLY the three SHA-pinned Go15 table sources
and emits static Rust arrays, preserving zero/keyed/sparse declarations, Go byte
strings and recomposition last-value semantics. Source artifact conversion ran;
no Go generator, runtime parser/buildscript, behavioral validation or network
was used. The copied tables select !go1.27, matching pinned Go1.26.9.

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

Go Authors2011/2016 BSD attribution/terms are retained in NOTICE-GO-STDLIB and
LICENSE-GO-STDLIB. This supersedes earlier newerICU/NFC/bidi/mappedACE/adapter
limit implementation residuals. It remains unbuilt/unexecuted; source conversion
does not qualify data equivalence or behavior. Allocation/resource/failure
equivalence, Go structured errors/partial sanitized output outside this Option
boundary, rustls rawSNI/alerts, eager configuration and cache/certificate variants
remain unqualified. Independent source reviews/direct rustfmt only, with no
tests/builds/Cargo/probes, handshake/process/feature qualification or gate closure.

# Per-server H2 lifecycle and quiet Noise — 2026-10-18

Selected Hyper1.8.1 is vendored with a default-off forwarding feature/setter;
vendor/hyper/UPSTREAM.md records source pins and MIT provenance. Root patch/
exclude and lock source are updated at the same version; both images copy its
MIT license. API full activates implementations, with tracked ordinary H2 opting
in to idle30s and native Noise to idleNone. Tonic/default/untracked ordinary
builders retain the original lifecycle. The earlier graceful feature's global
effect is corrected by a runtime per-builder flag. Client paths remain unchanged.
The outer quiet-Noise30s close was removed for all feature profiles, matching
Go Noise BaseConfig's lack of ReadTimeout/IdleTimeout; handshake30s remains.

h2 stream counts timestamp idle after preface and final protocol close and stop
it at new HEADERS. Native GOAWAY close clocks begin only after actual codec flush;
NO_ERROR additionally waits for protocol0 and empty queued send output. Error
GOAWAY does not wait for streams; frame discard retains DATA connection credit.
Timers are polled before write gates and expiry skips a new blocked flush. Native
peer GOAWAY queues current-IDNO_ERROR immediately. A source-review finding fixed
the Pending/remoteerror populated loop to yield to its registered close clock.

Existing Go bundled server/h2 pins and x/net server.go apply. Core accounting
correction: server.go1967 marks ALPN H2 core-active; h2_bundle.go4789 only calls
optional ConnState hooks. Headscale has no such hook, so existing native HTTP
work accounting already correctly waits actual H2 closure. Go idle30s derives
from ConfigureServer4310; postGOAWAY1s condition is bundle5114–5121/5553.

Remaining boundaries: count-close versus actual EOS write, existing h2 write/
read gate, general decoder/error phases and per-stream deadlines. Error-path
stream cancellation retains selected h2 behavior. The outer Noise stop still
performs a separate best-effort flush/drop. Independent source/peer reviews and
direct rustfmt only; no tests/builds/Cargo/probes, transport/runtime/resource,
feature/client/process/embedding/package qualification. Three gates stay open.

# Native async ACME preparation and ordinary RSA cache — 2026-10-18

Full-only additive AcmeCertificateProvider/AcmeHandshakeRequest APIs and a
private optional shared ReloadableServerConfig hook prepare certificates before
TLS completion. The native serve_with_acme_provider entry installs the provider
before spawning acceptance. Lazy initial material has an empty ordinary
resolver, empty PEM metadata and Go zero expiry, with a bound shared token
resolver; it performs no cache read, key generation or ACME request. Existing
serve/load/embedding entry points retain their previous contracts.

Request capture uses the accepted ClientHello's signature schemes, P-256 group
offer and exact selected-Go legacy ECDSA cipher list before rustls filters the
schemes against its configured suites. Ordinary kind is ECDSA or RSA; sole
acme-tls/1 remains the independent token path. Typed ordinary cache helpers use
the normalized one-root-dot-trimmed name, with +rsa for RSA, and require matching
leaf/private algorithms. Classified lookup distinguishes a miss from fatal
filesystem/private-key parse failure. Issued material can be validated into a
typed DTO without filesystem access, preserving first-issue versus renewal
cache-publication boundaries.

raw_tls::accept_tls_with_config retains the acceptor-owned transcript and IO,
awaits preparation, then completes that same handshake with the selected
configuration. Listener ALPN policy is retained. Public raw TLS still applies
one absolute 30s deadline/admission permit around the whole handshake. Preparation
failure emits the selected Go pre-ServerHello fatal internal_error alert and
ends only that connection. Static/non-full/unbound paths retain direct accept.
The native CLI shares the provider with its remote gRPC listener.

Sources: selected x/crypto v0.53.0 autocert.go257–378/440–516/566–644/1046–1067
and Go1.26.9 crypto/tls/handshake_server.go277–284,
handshake_server_tls13.go487–494. Existing autocert SHA-256 applies; TLS pins:

- handshake_server.go: 371e52320f1011df2b23f1ee942f0ef0e6130cb53c8e7b2f83b7aff69cae21cb
- handshake_server_tls13.go: 54cce7be02c286d397b9af1ded5a24ad356962ad5fbfb37bf8f93ded9c32aee0

Rustls still validates/lowercases wire SNI and requires signature_algorithms
before this snapshot. Raw Unicode/IP SNI, unsupported-client/version and error
phase fidelity, provider/X.509 acceptance, session state and resource scheduling
remain incomplete or unqualified. Existing public field types/signatures and
wire-only isolation remain. Source reviews/direct rustfmt only; no tests/builds/
probes, current-source feature/package/transport/process qualification or gate
closure. CLI issuer/lifecycle provenance is in headscale-cli/UPSTREAM.md.

# Native raw SETTINGS validation — 2026-10-18

The opted server arms a private native codec flag after its preface. Before
typed SETTINGS identifier collapse, the native loader checks ACK payload,
stream ID, modulo6 payload shape, first INITIAL_WINDOW_SIZE overflow, raw count
and duplicate IDs (including unknown IDs), then unique known values. Error
reasons/order follow selected Go parseSettingsFrame/processSettings/Valid:
FRAME_SIZE, PROTOCOL and FLOW_CONTROL where applicable. A fixed100-ID stack
array bounds duplicate detection without allocation. Default/Tonic/client and
feature-off codec paths retain their original loader.

Sources: Go1.26.9 h2_bundle.go2380/3659/5835 (existing bundled SHA-256) and
x/net v0.56.0 http2/frame.go766/server.go1606. frame.go SHA-256:
7087a540c7d8c93b142d0b97b6f3a6b780be48863cbd0cf2187de845743857b7.

vendor/h2 now retains Go BSD terms and an adaptation notice inside its own
package, in LICENSE-GO and LICENSE-GO-NOTICE alongside the original MIT LICENSE.
Its normalized/original package manifests record MIT AND BSD-3-Clause; existing
container LICENSE* globs copy both. No dependency version/resolution changed.

This supersedes the missing raw count/duplicate branch below. Codec-stage
validation versus Go dispatch during an already-failing GOAWAY, general decoder
errors and complete scheduler/timer/resource behavior remain unqualified.
Source reviews/direct rustfmt only; no tests/builds/probes, feature/package/
transport/process qualification or gate closure.

# Native TLS-ALPN persistent token cache — 2026-10-18

Full/native bound resolver factories retain the configured cache directory.
Sole acme-tls/1 requests read memory first, then hostname+token from disk under
the challenge-map read lock, without promotion. The Lookup-normalized token
domain retains its final root dot. Private cache eligibility now has a token
kind permitting RSA or ECDSA; normal entries remain ECDSA. Existing date, SAN,
PEM/DER, LE2022 and public/private-key checks apply. Critical challenge
extensions bypass ordinary WebPKI verification as in autocert.

Set/clear hold the map write lock while changing memory then performing
best-effort atomic put/delete. The existing random create_new0600 temporary
writer is reused with 0700 directory creation; names cannot escape that
directory. HTTP-01's private native resolver also carries the cache. Public
new/unbound resolvers and non-full builds keep disk access disabled. No CLI or
dependency/public-signature change was required. Renewal retains the same Arc.

Source: selected x/crypto v0.53.0 autocert/autocert.go216–219/277–285/517–549/
828–847/1101–1157 and autocert/cache.go. Existing SHA-256 pins:

- autocert.go: 175d3d5b0dd6278291bb924b55f1c9e6647b24f8e595394e2848dc6f50e07aea
- cache.go: b0350eeeac88823cb2c6558e710fac345379f7eee308ff661f1e68f05bee93a2

The new tls/acme_token_cache.rs retains Go Authors2016 attribution and existing
BSD terms. Synchronous filesystem work, Go context/worker cancellation,
stronger fsync, exact private-key bytes, parser/provider/resource/external writer
and runtime handoff/restart behavior remain unqualified. Source reviews/direct
rustfmt only; no tests/builds/probes or parity gate closure. Normal RSA selection,
lazy issuance and raw SNI remain source work.

# Native H2 input and pending controls — 2026-10-18

Native per-instance selection now enables immediate peer SETTINGS application
and coalesced ACK, private PONG/refusal FIFOs, and reads during Pending GOAWAY
or control output. An aggregate of the newly decoupled queues is bounded at
10000, including the original single pending slots; overflow exits as terminal
I/O without flushing blocked output. A 32-frame cooperative budget self-wakes
and yields through existing stream-output/flush handling. Default/Tonic/client
and feature-off paths retain their prior readiness gates and single slots.

Go1.26.9 bundled h2 processSettings5835ff, PING5712 and control limit5108 provide
the phase/limit evidence; existing bundled SHA-256 applies. This supplies the
remaining write-before-read source repair, with no public/dependency change.
The bound covers these new queues rather than every Go scheduler frame class.
Full ordering/counting, work/timing, generic decoder/error/buffering phases and
Noise outer teardown remain unqualified. The newer raw loader above supplies
more-than100/duplicate SETTINGS validation. Source peer reviews and
direct rustfmt only; no tests/builds/probes or parity qualification.

# Native HTTP/2 preface progress — 2026-10-18

The private native server handshake in vendor/h2/src/server.rs polls initial
SETTINGS flush and the exact 24-byte client preface independently. Pending
output no longer gates preface input. The same codec, including unwritten
output, moves to the protocol connection; terminal write errors terminate the
handshake. Default/Tonic/feature-off ordering stays unchanged. No queue or public
API was added. The independent outer preface budget remains in place.

Source: Go1.26.9 net/http/h2_bundle.go4990–5019 and selected x/net/http2/server.go.
Existing SHA-256 pins apply:

- bundled h2: a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e
- x/net server: cf07329cd7d5d95909a5404f3b29f10f4252189012b98ad4c8fdbfca384cb9d1

The newer pending-control implementation above supplies immediate native
SETTINGS/coalesced ACK and bounded PONG/refusal handling for later frame input.
Independent source review/direct rustfmt only; no tests/builds/probes,
transport/process qualification or parity gate closure.

# Native HTTP/2 per-stream deadlines — 2026-10-18

Additive hidden go_stream_timeouts(read,write) forwarding in selected Hyper/h2
applies only to opted native server builders. Tracked ordinary H2 uses30s/30s;
Noise/default/Tonic/client/untracked ordinary configurations retain no stream
timeouts. Write time is stamped at new server stream creation; read time after
request conversion. Stream close cancels deadlines; completed body EOF remains
sticky. Read expiry drains queued DATA then reports a body-only ioTimedOut and
discards later nonempty body DATA with connection credit returned. It does not
reset the stream. Write expiry queues INTERNAL_ERROR outside the protocol-abuse
reset budget. Existing public types/signatures remain unchanged.

One shared stream Sleep tracks the earliest deadline. Counts' private generation
invalidates cached scans on config/arm/EOF/close/expiry; ordinary per-frame polls
reuse the snapshot. Due/changed scans include retained reset entries. No detached
deadline tasks or per-stream timer allocations were introduced. A missing
cfg-gated Duration import in the earlier lifecycle helper was source-corrected.

Pinned Go1.26.9 h2_bundle.go3979/4035 (pipe drain-before-error),5986 (discarded
DATA credit),6059/6070 (read/write expiry),6182/6280 (timer phases),5797 (close)
provides semantics, with existing bundled-source hash. Writer completion can
occur while bytes remain buffered (startFrameWrite5397/wroteFrame5435); exact
codec/Go buffering boundaries remain unqualified. Per-handler response-controller
overrides and write error Cause wrapping are not implemented by this batch.
Existing read/write gating and resource/scheduling qualification remain open.
Independent source/peer review/direct rustfmt only; no tests/builds/Cargo,
deadline/frame/client/process/feature/package or resource qualification.

# Native ACME cache eligibility and publication — 2026-10-18

Native full cache loading now reads raw bytes into private acme_cache and
acme_cache/pem modules. Selected PEM first-private-key/block ordering, ignored
leading/inter-block text, strict final suffix and padded base64/trailing-bit
behavior are retained. Every subsequent PEM block contributes DER regardless
of label; all concatenated certs are parsed while original block grouping is
retained for TLS material. ECDSA normal-cache eligibility applies inclusive
NotBefore/NotAfter, Go SAN hostname/IP matching, the fixed2022 LE rule and
private key matching. No CA trust/EKU/network revocation check is invented.

The shared canonical entry helper mirrors selected ACME CERTIFICATE response
extraction and PEM encoding. The additive hostname-aware helper validates these
exact bytes before CLI atomic replacement, following authorizedCert680 before
cachePut. Invalid issued certificates leave an existing entry untouched. CLI
NotAfter equality and the existing valid-material layout assertion were
source-updated only. Static/nonfull/unbound behavior retains existing paths.

Source SHA-256:
- x/crypto0.53 acme/autocert/autocert.go (cacheGet470, authorizedCert680, validCert1101):
  175d3d5b0dd6278291bb924b55f1c9e6647b24f8e595394e2848dc6f50e07aea
- x/crypto0.53 acme/autocert/cache.go:
  b0350eeeac88823cb2c6558e710fac345379f7eee308ff661f1e68f05bee93a2
- x/crypto0.53 acme/rfc8555.go (certificate response extraction403):
  e898ab7e77ae19c5b28ec5abff60b876a07791cf6a87e1bd93263cf660e7727e
- Go1.26.9 encoding/pem/pem.go:
  536954f803f79d8972e8f86b792b25d4ac83167fbe4c3117954a4378e60521da
- Go1.26.9 crypto/x509/verify.go (hostname matching814–983):
  3fbc65e9ba1a710f1276d6b9e36483bbc9dd98f48817ed0991ca0894505783f9
- Go1.26.9 crypto/x509/parser.go:
  70ae7c65f68d17a59e7bacb0d1cc520e8e96e8eafee2b7224465180437ab3a35

Go Authors2009/2011/2016 BSD attribution is retained in NOTICE-GO-STDLIB and
LICENSE-GO-STDLIB. No dependency changes were needed. This is not a full Go
X.509 parser: selected ASN.1/extension/DN/time/keycurve/provider behavior still
differs; SPKI equality is stronger than coordinate/modulus checks. Grouped DER
may fail before Go's eventual TLS failure. RSA/token variants, eager issuance,
runtime certificate selection, diagnostics and race/resource/failure phases
remain unqualified. Independent source/peer reviews/direct rustfmt only; no
tests/builds/Cargo, certificate/renewal/client/process/feature qualification or
gate closure. Three parity gates stay open.

## Native loaded user associations — 2026-10-18

The native persistence snapshot now retains a loaded User separately from the
stored UserID foreign key. Checked SQLite/Postgres hydration, registration-plan
capture, normal save retention, auth-key rollback and backfill hydration preserve
that distinction. Native user reads retain raw stored names. OIDC publication
uses the captured identity instead of querying a newer account snapshot.

Policy lifecycle comparison, map peer/filter/SSH inputs, action checks, tag
checks, policy validation and route auto-approval use loaded association
validity/ID. Raw FK ownership remains available for SQL/cache comparison and
MapNode.User; native nil maps to zero. User profiles, registration User/Login and
gRPC users project the cached user, including nil-owner handling, stable profile
ordering and Username/Proto fallback. Public field types and wire-only
DB/core dependencies are unchanged.

Source reference: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. SHA-256:

- hscontrol/types/node.go: b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab
- hscontrol/types/users.go: 36bc0f562c507336d3a2a309c94718ec3baa2db2c3432180596556ab512d69dd
- hscontrol/mapper/mapper.go: ec191db53afd7a906aaf015bf32c372c75c0b110aa784e5277e45269d2496534
- hscontrol/auth.go: b54d2e7541e24eeeb35df63ae4a6c5718b42d208e63e5786e3bdc5727755a3dd

This supersedes the earlier missing independent native association source form.
Coherent concurrent node/side-metadata views, credential/account/cache races,
cached AuthKey.User, imported nil/orphan/soft-deleted/zero/wide shapes, custom/
headless adapters, failure/rollback, resources and native/wire-only/package/
container/client/process/restart qualification remain incomplete or unqualified.
Direct rustfmt only; no executable validation, advisory or dependency refresh.
The Headscale BSD notices and license remain retained; all release gates stay open.

## Native cached preauth-key associations — 2026-10-18

NativeNodePersistence now owns the loaded preauth key and its loaded user
independently of AuthKeyID and the node's own user association. Checked native
hydration accepts dangling key IDs as nil associations while propagating other
read/encoding failures. Native gRPC node projection retains loaded flags, tags,
nullable timestamps and user identity across ordinary key/user admin mutations.
Normal saves preserve them; registration replaces or clears them at the pinned
ownership boundaries; backfill reloads them. Successful one-shot completion
shares the Used flag across clones of that loaded key; rollback restores prior
metadata. Fresh key-owned identity shares the key user, while existing auth-key
reauth preserves the prior node user. Modern bearer secrets/hashes are excluded
from snapshots. The empty key-display fallback and independent reusable/used
projection follow pinned PreAuthKey.Proto. Public field types, dependency
versions and the wire-only DB/core graph are unchanged.

Source reference: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. SHA-256:

- hscontrol/types/preauth_key.go: 75f5ec4e1e0d73c2ea4bd3760f006b7b0587db3ade380c43bf839e7daf22a130
- hscontrol/types/types_clone.go: 7fe85453a69a466e1f1748b7b0e86e2ec2d218b0a3ffbcd74a0c5756ede4e049
- hscontrol/state/node_store.go: 5bef0767885748e96e3d0e7a9f2bb5bb6d623d1de8c8ef5afb2b49201aa95028
- hscontrol/db/preauth_keys.go: 732667bea9f0f766aeeea919d894f0761bfe88b3e5babcdb4d4d3cd6d19ed4a6

This supersedes the earlier missing native cached AuthKey.User source form.
Concurrent node/side-metadata and credential/account/cache/SQL snapshots,
malformed/nil/zero/wide native values, custom/headless/legacy paths, direct key
list/mint errors and projections, failure/rollback/resources and native/wire-only/
package/container/client/process/import/restart behavior remain incomplete or
unqualified. Direct rustfmt only; no tests/builds/probes/validators/advisory
refresh or dependency upgrade. Existing BSD notices/licenses remain retained.

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

## Provider discovery decoding — 2026-10-18

Private src/oidc/discovery.rs now follows coreos/go-oidc v3.18.0 providerJSON
and unmarshalResp with Go 1.26.9 JSON/MIME semantics. Fields are assigned in
document order using Go folded names. Duplicate null string fields preserve
the previous value, root null produces the zero model, string-array duplicates
reuse backing slots (including null elements after a shorter prior array), and
device_authorization_endpoint is type-checked even though the public metadata
DTO has no device-flow field. Invalid UTF-8/surrogates pass through the shared
Go unquoter; wrong field/root types use providerJSON diagnostic context. The
shared iterative Go scanner now supplies syntax/depth/EOF errors as well.

The JSON-specific Content-Type error is selected only when MIME parameters
parse successfully, including equal/unequal duplicate and quoted-value rules.
Content-Type and issuer mismatch text use Go quoting. An issuer is disabled
only when exactly empty; fallback warnings retain the creating-provider error
context and pinned message. The callback URL removes one terminal slash, as
upstream does. The public DTO and wire-only feature boundary are unchanged.

Original CoreOS NOTICE/Apache-2.0 terms are in NOTICE-GO-OIDC/LICENSE-GO-OIDC;
package metadata includes Apache-2.0. Go BSD notices remain in
NOTICE-GO-STDLIB/LICENSE-GO-STDLIB. NOTICE-GO-OIDC records all source hashes.
Existing container license globs include the new files. Source/direct rustfmt
only; no tests/builds/validators/probes/dependency/advisory checks. No new
dependency or version. Network/URL/TLS/IO errors, HTTP raw-status text, provider
transport/resources, feature/package/container and process qualification remain
open. The existing 1 MiB provider-body limit is retained and remains a declared
resource difference from Go's unbounded discovery read. No release gate closes.

## Shared fresh registration saves — 2026-10-18

Built-in detached SQLite/Postgres registration now shares the native
NewNodeRegistration insertion and returned-model projection. Web/CLI/OIDC and
atomic auth-key paths no longer fall through to compatibility CreateParams
insertion, SQL name reservation or its post-save SQL node reread. Fresh
GivenName is the sanitized seed, including an empty seed in SQL; empty returned
labels fall back to node. Tags/endpoints/routes retain the native nil encoding,
and captured user/key association results remain the projection authority.
The atomic path uses the same new-save/strict-used-claim transaction as the
attached path. The unused legacy Hostinfo staging shim was removed.

This supersedes the fresh detached insertion/nil-shape source gap above, within
the existing typed registration inputs. Detached selection/preload still reads
SQL, and it has no retained process NodeStore for name collisions or concurrent
mutations. Missing/explicit-empty shapes already flattened at public Vec/value
boundaries and legacy low-level DB compatibility APIs remain separate. Existing
Go state/node-store/source hashes and BSD notices apply. Source edits/reads and
direct rustfmt only; no tests/builds/validators/probes/dependency/advisory checks.
No native/wire-only/package/container/client/process/import/restart gate closes.

## Role-gated lifecycle and expiry refresh — 2026-10-18

Policy runtime now retains relay destination IPs from compiled global CapGrant
rules and via target tags from network grants with nonempty resolved sources.
An empty/unresolved via destination does not discard its target role, while an
app-only or empty-source via grant does not create one. These roles refresh with
the policy's compiled input snapshot, before a later nodeAttrs failure, and are
read by node address/tag membership rather than enabling a tailnet-wide flag.

Stream online/offline changes no longer unconditionally attach PolicyChange.
Ordinary nodes emit lightweight patches; active approved non-exit subnet
routers, relay targets and via targets additionally request runtime peer
computation. They do not resend full self/DERP/DNS configuration. Online/offline
patches carry no synthetic origin, while NodeAdded retains its origin. The map
builder's old self-policy-companion suppression was removed. Overlapping
Connect calls emit another lightweight update, as Go does, and an expired key
can hold a control stream without becoming online.

Scheduled expiration now selects by stable ID, revalidates expiry in one writer
batch, clears online flags together, and publishes per-node NodeAdded changes.
A formerly online router/target also requests runtime recomputation. A restored
key is not cleared by a stale candidate; final-presence pruning omits nodes
deleted later in the batch. Go zero expiry and strict After comparisons apply.
Native admin/volatile expiry edits recompute online state from active sessions
inside the quiet writer edit. That state remains live if a later DB save fails;
successful writes add role recomputation only if online state changed. Expiry
restoration can make an existing connected stream online again.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. SHA-256:
- hscontrol/policy/v2/compiled.go: eebe64a7730e70428a3b63828aea9b9e1dd7a10e8d4ae9b9f8965ad8b781f7c7
- hscontrol/policy/v2/policy.go: 1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e
- hscontrol/types/change/change.go: 23f5812aeee446d15f5e2624ddb9e25171bb3ba4ff40c82feaa9e183c2d2dcba
- hscontrol/state/state.go: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01
- hscontrol/types/node.go: b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab

Existing BSD attribution/terms remain in NOTICE-HEADSCALE-GO/LICENSE-HEADSCALE-GO.
No dependency or public wire-field change; new policy/lifecycle logic is usable
without admin features. Existing assertions for the superseded full-map,
overlapping-session and exact-expiry assumptions were source-adjusted only.
No tests/builds/validators/probes/dependency/advisory checks ran. Direct rustfmt
and source reads/edits/hashes only. All accumulated feature/client/process/
restart and policy phase/resource/race/cancellation/grace/shutdown/error
qualification remains open. No runtime performance or DoS-resistance result is
claimed, and all three replacement gates remain open.

## State sessions and disconnect saves — 2026-10-18

The registry now distinguishes batcher-attached channels from Go's state-owned
ActiveSessions. Acquisition runs in one NodeStore writer operation with epoch,
online, unhealthy-reset and cancellation-flag selection. Missing nodes acquire
no state or batcher ownership. SessionEpoch advances only on Connect; a newer
epoch never suppresses an older guard's required release. Each acquired guard
removes its channel immediately, then releases exactly one state session after
the upstream reconnect wait. Another attached channel, an expired key or a
missing node skips that wait. Reconnect is checked at one-second ticks, up to
the configured/default ten-second grace.

The last state release stamps LastSeen, clears online and unhealthy state, and
retains the offline notification even when expiry had already set online=false.
Other state sessions prevent that transition. Admin expiry restoration and both
ephemeral-GC paths read state sessions, including a deferred handler's ownership
during grace. Batcher eviction removes its channel bookkeeping, not the node's
state epoch/online facts; deletion removes both kinds of state. The legacy sweep
rechecks session/online facts within its writer operation instead of using an
earlier copied directory.

Disconnect now owns a best-effort save completion before change dispatch and
ephemeral scheduling. Attached SQLite/Postgres adapters share persistNode's
stable-ID re-read under the native save mutex, writing current selected columns
and omitting Expiry; they no longer issue only the supplied LastSeen UPDATE.
Missing cached nodes cannot be recreated. This reuses the ordinary runtime save
helper, whose existing map callers retain their initial request validation.
Router construction binds the weak registration-store edge independently of
ephemeral timers, avoiding a registry/store ownership cycle. Detached adapters
retain their timestamp-only compatibility interface.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. SHA-256:
- hscontrol/poll.go: 3590bf1a227f48c2e574e96ef8660889235448025c1f096f0388f1bbf7871b6b
- hscontrol/app.go: 381958868e878b30c1f43138808b7cb3daf27c05a3db762ed3d672bf9f779a85
- hscontrol/state/state.go: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01

Existing Headscale BSD notices/licenses apply. No dependency/version/public
wire-field change. Existing batcher fixtures now seed registered nodes, offline
writer fixtures call the state release, and cleanup expectations retain state
facts; these are source adjustments, not executed evidence. Direct rustfmt and
source reads/edits/hashes only. No tests/builds/validators/probes/dependency or
advisory checks. No-runtime/custom/detached store behavior, session/grace/clock/
DB-failure/cancellation/runtime-shutdown/GC races, diagnostics/resources and all
native/wire-only/package/container/client/process/import/restart qualification
remain incomplete or unqualified. All three replacement gates remain open.

## Logout expiry and guarded deletion phases — 2026-10-18

Wire logout now captures one quiet stable-ID expiry/online edit and retains its
accepted view plus original online transition. Built-in native persistence
re-reads cached expiry under the save mutex without applying another live edit.
After a successful save, the caller refreshes policy once and dispatches the
original NodeAdded/role recompute change. A database failure retains quiet
expiry/online state and emits no successful change; a later policy failure is
returned instead of being swallowed by the bool setter. The response uses the
accepted view rather than inventing a fallback record after a failed mutation.
The client sentinel is clamped when the owned operation runs. Tagged persistent
logout still skips expiry, and SetNodeTags deliberately leaves existing expiry
alone, matching its separate upstream contract.

Native admin, guarded ephemeral logout and guarded GC deletion now share one
SQL/cache removal helper. It holds the native save mutex through durable
deletion and quiet NodeStore removal, then releases the mutex before policy
refresh/dispatch. Quiet removal retains address/session/native-metadata cleanup;
the finishing phase dispatches explicit removal even if policy compilation
subsequently fails. Wire logout propagates that late failure with the pinned
handling-logout/deleting-ephemeral context. Non-ephemeral expiry failures retain
the setting-expiry context; native ephemeral SQL diagnostics use Go DB message
projection. Default/custom/headless compatibility callbacks remain supported,
and a second caller-side removal after a completed native deletion is a no-op.

Source: github.com/juanfont/headscale v0.29.5, commit
0f7d1e536bed9f01dd7161f7637af19bb0908335. SHA-256:
- hscontrol/auth.go: b54d2e7541e24eeeb35df63ae4a6c5718b42d208e63e5786e3bdc5727755a3dd
- hscontrol/db/node.go: 9b1badd1eba80662eccb1eb5e2d0f039967b6469a30fab6fb3904466de234bb4
- hscontrol/state/state.go: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01

Existing BSD attribution/terms remain in NOTICE-HEADSCALE-GO/LICENSE-HEADSCALE-GO.
No dependency/version or public wire-field change. The persist_wire_logout
contract now explicitly receives an already edited cache on expiry logout and
must not apply that live edit again. Octra crate sources have no direct call to
that method; no sibling feature/runtime qualification ran. Source reads/edits,
hashes and direct rustfmt only; no tests/builds/validators/probes/dependency or
advisory checks. SQL/driver/trigger, ownership/phase/error/resource, custom/
headless/no-runtime, concurrent auth/map/admin/policy/GC/cancellation/shutdown,
wire-only/package/container/client/process/import/restart qualification and all
three replacement gates remain open.

## State user RPC paths — 2026-10-18

ListUsers now calls a distinct provided UserAdmin.list_for_state method. Native
SQLite/Postgres adapters select all matching typed rows in SQL and preserve
stored names, including empty names and multiple users sharing a name. The
RPC retains name/email/nonzero-ID filter priority, User.Proto's fallback name,
and response ID sorting.
Native user deletion also uses the state error adapter: missing users remain
missing, while preload/constraint/driver/zero-primary errors retain Go-facing
messages without legacy username/OIDC/duplicate-error reclassification.
Default/custom adapters filter their all() snapshot. This removes the RPC's
unique-name lookup and fallback-name projection. Native errors use the shared
Go-facing envelope. Source implementation and direct rustfmt only; existing
list/delete/CLI assertions are unrecaptured and unexecuted. Full scalar/time/
wide-unsigned imports and driver/custom/native/process/package qualification
remain open. No dependency boundary or release gate changes.

NodeStore deletion now returns the actual removed model's stable ID and IPs
from direct/batched writers. The native state deletion caller keeps its save
mutex through cache removal, unlocks, then consumes that receipt to free IPs
before policy refresh/dispatch, matching State.DeleteNode's phase order.
Volatile deletion releases before refresh too. A failed batch-completion send
releases its undeliverable addresses. Worker panic/shutdown/fallback, allocator
callbacks, concurrent replacement/batch/final-presence/resource/race behavior
and all runtime/feature/package/client/process qualification remain unexecuted
or incomplete. Existing pinned state/state.go source/hash applies. Direct
rustfmt only; no tests/builds/validators/probes/advisory checks or gate closure.

UserAdmin now has provided state create/rename methods, overridden by SQLite,
Postgres and UserRegistry. Upstream RPC create uses the raw state path, including
empty/unusual names, rather than the legacy username validator. Native create
returns the accepted model's raw name and nanosecond CreatedAt. State rename
does not forbid OIDC accounts, applies Gorm's empty/nonzero update semantics and
keeps the later by-name lookup at the RPC layer. That lookup runs after policy
refresh and dispatch, so an empty struct-WHERE name selects all users and an
ambiguous/missing result cannot roll back the committed write. Native lookup
uses its original one-query registration/user model rather than a policy-user
list followed by another by-ID read. Direct native user errors retain Go text.

Native user deletion delegates durable ownership to DestroyUser's transaction;
the live NodeStore precheck is retained for adapters without a storage-owned
check. Initial rename/delete lookups use the native user snapshot path. User
directory updates still retain cached Node.User associations, matching Go's
UpdateUser TODO. Legacy create/rename methods and custom provided defaults remain
separate compatibility surfaces; no existing trait implementer must add methods.

Pinned source: github.com/juanfont/headscale v0.29.5 at
0f7d1e536bed9f01dd7161f7637af19bb0908335. hscontrol/grpcv1.go SHA-256:
1bb435c674a64b3a7d1382eddfc9b33d7fb8f646c414709d011508d0a2e883c3.
State/users/Gorm source hashes are recorded in headscale-db/UPSTREAM.md. Existing
upstream notices/licenses apply; no dependency/version or public wire-field
change. The admin feature boundary retains wire-only integration separation.
Source reads/edits/hashes/direct rustfmt only; no tests/builds/validators/probes,
dependency/advisory or sibling feature/runtime qualification. Existing raw-name,
OIDC/status/gateway/CLI assertions have not been recaptured or executed. All
transaction/trigger/clock/error/resource/race/malformed/custom/memory-identity,
native/wire-only/package/container/client/process/import/restart qualification
and all three release gates remain open.

## Checked key admin state paths — 2026-10-18

ApiKeyAdmin now provides checked validate_for_state/list_for_state methods;
native SQLite/Postgres override them while legacy bool/list interfaces remain.
The gRPC interceptor preserves validation-error versus authenticated-expiry
status: Internal validating-token versus Unauthenticated invalid-token. HTTP's
existing bool boundary still rejects failures. Key listing propagates native
scan/store errors; create/expiry/delete preserve raw Unknown errors, including
record-not-found text, rather than Internal or invented key-not-found labels.
Native API-key storage diagnostics use the shared Go envelope. API/preauth
mutation RPCs move accepted work into complete_state_mutation workers.

Native preauth owner validation now advertises its in-storage transaction
authority, so the RPC/adapter no longer rejects nil-owner/empty-tags before
BEGIN. Other adapters retain provided preliminary behavior. Its initial user
lookup uses the stored-model interface, and native preauth store errors retain
Go-facing messages. DB create/lookup/transaction/entropy phases and their source
pins are recorded in headscale-db/UPSTREAM.md. Public record/wire field types
and the admin feature boundary are preserved; no dependency release changed.

Pinned headscale v0.29.5 at 0f7d1e536bed9f01dd7161f7637af19bb0908335.
SHA-256:
- hscontrol/app.go: 381958868e878b30c1f43138808b7cb3daf27c05a3db762ed3d672bf9f779a85
- hscontrol/grpcv1.go: 1bb435c674a64b3a7d1382eddfc9b33d7fb8f646c414709d011508d0a2e883c3

Existing original licenses/notices apply. Source reads/edits/hashes and direct
rustfmt only; no tests/builds/validators/probes, fresh advisory/security or
sibling/feature qualification. Key/auth/status/gateway/CLI assertions remain
unrecaptured and unexecuted. Custom/default adapters, detailed credential
diagnostics, malformed/wide dates/IDs/scalars/bytes, driver/trigger/transaction/
failure/clock/race/resource/cancellation/shutdown and all native/wire-only/
feature/package/container/client/process/import/restart qualification remain
incomplete or unqualified. No release gate closes.

## Leading removals and captured map rebuild state — 2026-10-18

tailscale_wire/map.rs follows mapper.generateMapResponse/withRemovals for
computed policy/full peer-view removals. They lead the accompanying response
in a dedicated PeersRemoved-only frame, preserving delta-only watcher removal
notifications when a Node/DNS/SSH/full-peer response forces a netmap rebuild.
Full rebuilds calculate removed IDs even when a nonempty peer set remains.
Runtime policy updates follow policyChangeResponse by resending all visible
remaining peers as PeersChanged. Ordinary explicit deletion deltas retain
their existing path; a separate self/DNS prelude still precedes a runtime
policy removal/policy pair. The computed removal response adds no mapper
debug dump or builder-generation count, as in Go's post-builder wrapper.

Full rebuilds now return their encoded frames and corresponding peer/self
tracking state from the captured construction snapshot. Stream and batch
callers no longer recompute that remembered state from newer snapshots.
All component frames encode before new peer/self state is returned; a failed
encoding yields the existing keepalive fallback with prior peer/self state.
SSH deduplication follows connectionEntry.withSSHPolicyDelta's last-non-nil
model: comparison is side-effect-free, a successful encoding records only
an emitted non-nil policy, and a nil response does not clear the cache. Mapper
debug output retains the policy before per-connection wire deduplication.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335
SHA-256, in addition to existing mapper/source pins:
- hscontrol/mapper/batcher.go: 341d3824c49da1180b37e20e7c737ca5fe6e4aae8fe57838ab753a06a86c4f4a
- hscontrol/mapper/node_conn.go: d8d456c39d90fcf9508fc72e75ea48d0f0fe7d11966e1c1b90d600d3f43abec9

Original Headscale/Tailscale BSD notices and retained LICENSE-HEADSCALE-GO
and LICENSE-TAILSCALE apply. Source reads/hashes/edits and direct rustfmt only;
no tests/builds/validators/probes or fresh advisory review. Existing frame/
peer/SSH assertions are unrecaptured and unexecuted. Removal ordering,
projected/native self and SSH equality, generation-cursor retry after errors,
queue/network delivery, frame metrics, reconnect/rekey/policy churn,
cancellation/backpressure/resource/load/shutdown and broader node/policy/
filter/config snapshot coherence remain incomplete or unqualified. Native/
wire-only/feature/package/container/client/process/import/restart evidence
and all three release gates remain open. No dependency/public type changed.

## Native registration JSON encoding — 2026-10-18

tailscale_wire/register_json.rs follows pinned tailcfg.RegisterResponse,
User and Login declarations, types.User.TailscaleUser/TailscaleLogin and the
Noise registration handler's encoding/json.Encoder boundary. Native success,
follow-up, expiry and error responses share this encoder. User/Login IDs
convert to signed int64 with Go's 64-bit pattern; optional profile pictures
and zero User.Created omit. Other supplied UTC creation times use canonical
fractional digits through the existing private Go-shaped time parser.

All required RegisterResponse fields remain present, including false booleans,
empty strings and NodeKeySignature's nil/null versus non-nil empty base64
string. Nested User/Login fields follow declaration order. Shared Go compact/
HTML processing runs before the existing wrapper appends the Encoder.Encode
newline. Existing HTTP status/content-type and empty-body handling after an
encoding failure remain in place. Public response fields/types are unchanged.
SimpleUser/SimpleLogin reuse the signed-ID deserializer into their u64 public
projections; legacy unsigned input and direct serialization remain supported.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335
SHA-256, in addition to recorded tailcfg/Go encoding-json/time pins:
- hscontrol/auth.go: b54d2e7541e24eeeb35df63ae4a6c5718b42d208e63e5786e3bdc5727755a3dd
- hscontrol/noise.go: 5c277a92d413a8e362b75667d3c6b11faaf6d2438021b4c57a5c0c8264bccbbc
- hscontrol/types/users.go: 36bc0f562c507336d3a2a309c94718ec3baa2db2c3432180596556ab512d69dd

Original Headscale/Tailscale/Go BSD notices and retained LICENSE-HEADSCALE-GO,
LICENSE-TAILSCALE and LICENSE-GO-STDLIB apply. Source reads/hashes/edits and
direct rustfmt only; no tests/builds/validators/probes or fresh advisory review.
Registration assertions are unrecaptured and unexecuted. This encoder uses
existing producer UTC values, without restoring discarded storage timezone/
location metadata or qualifying complete user/owner associations. Full
timestamp/wide-ID metadata, strict direct public serde, malformed key/byte/
signature/Unicode inputs, error/log/flush/cancellation/resource/concurrency
and native/wire-only/feature/package/container/client/process/import/restart
qualification remain incomplete or unqualified. No dependency release,
public field type or release gate changed.

## Live signed IDs and zero-field encoding — 2026-10-18

tailscale_wire/map_json.rs follows types.NodeID.NodeID, NodeID.StableID and
NodeView.TailscaleUserID together with tailcfg's signed ID/int declarations.
Unsigned producer IDs convert to int64 with the same 64-bit pattern, including
above MaxInt64. This covers node/user/profile/patch IDs, removal slices and
integer map keys, sorted as decimal strings after conversion. StableID retains
the original unsigned decimal string. Public field types remain u64.

wire_ids.rs supplies private JSON deserializers for the public map ID fields,
removal slices and boolean maps, preserving signed input bits in those u64
projections. Nil containers and fresh null primitive values retain their zero
projection; map key aliases convert in input order. Existing unsigned inputs
and direct unsigned serialization remain supported, so these public adapters
are intentionally wider than strict Go int64 decoding. Registration/admin/SQL
ID boundaries are not qualified by this map-layer change.

The native map encoder now applies schema omitempty/omitzero, including
IsZero on non-nil peer-patch key/time pointers. Ordinary non-nil bool/int/
address pointers remain nonzero, while Node.LastSeen omitempty retains a
non-nil zero time. Explicit-unset opt.Bool remains null. Required missing
fields receive their zero/nil representation, including SSH fields and dial
candidates. Empty root Health and false omitDefaultRegions omit. Named filter
empty/deletion updates, required explicit arrays and existing extension fields
remain distinct. This supersedes the previous ordering-only omission behavior.

Existing pinned Headscale types/node.go and tailcfg/encoding-json source pins
and retained original BSD notices/licenses apply. Source reads/edits and
direct rustfmt only; no tests/builds/validators/probes or fresh advisory review.
Assertions remain unrecaptured and unexecuted. Full producer nil/empty origin
metadata, registration/admin/database wide IDs, strict direct public serde,
malformed numeric/key/time/network/Unicode inputs, error/resource/concurrency
and native/wire-only/feature/package/container/client/process/import/restart
qualification remain incomplete or unqualified. No dependency release,
public field type or release gate changed.

## Live map encoding and capability overlays — 2026-10-18

tailscale_wire/map_json.rs follows pinned tailcfg field declaration order at
the native live map boundary. Full/delta/ping/expired map responses and native
debug dumps share the ordered encoder, including nested node/patch/Hostinfo/
DNS/DERP/SSH records, filter rule/grant/port ordering, typed floats and time
fraction formatting. Captured opaque base filter bytes are inserted at the
declared PacketFilters position. Other named filters retain ordered fields;
null deletion markers and explicit empty arrays are preserved. The encoder
orders fields selected by native construction and preserves existing extension
fields, rather than applying debug readback's Go decoding/omission rules to
producer values. Existing framing/compression and public wire types remain.

map.rs follows policy/v2.PeerCapMap for every approved exit peer, regardless
of whether suggest-exit-node was explicitly granted. Its argument slice emits
null. Self capability overlays now follow types.NodeView.TailNode: baseline
and configuration defaults precede maps.Copy of policy flags, so explicit
policy attrs can override baseline/runtime capabilities with nil slices.
This includes default-auto-update and file-sharing under disabled Taildrop.
Baseline capability empty slices remain [] when no policy override exists.
MapNode/PeerChange's public Vec-valued capability maps now accept null maps
and null argument slices via a private deserializer. Nil values project into
empty vectors; their direct public reserialization remains shape-limited.

PolicyStore.node_attrs_snapshot captures the map snapshot's attributes under
one policy read. MachineSnapshot retains the immutable result for address
shaping, self/peer capability construction, requester DNS attributes and final
nil-slice encoding in hostinfo.rs. Final encoding does not reread policy.
Uncaptured private helpers retain their fallback lookup. The broader node/
policy/filter/config snapshot and publication sequence is not made atomic by
this attribute sidecar. Public vector fields and direct read/record/serde
interfaces remain unchanged, with their existing narrower native shapes.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335
SHA-256 (in addition to existing tailcfg/compiled/mapper pins):
- hscontrol/types/node.go: b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab
- hscontrol/policy/v2/tailnet_state_caps.go: 965c11071efbf501535ed1f28a1f382b3ccfa3f7d50d9b67a6313ee10ef19a25
- hscontrol/poll.go: 3590bf1a227f48c2e574e96ef8660889235448025c1f096f0388f1bbf7871b6b

Original Headscale/Tailscale/Go BSD notices and retained LICENSE-HEADSCALE-GO,
LICENSE-TAILSCALE and LICENSE-GO-STDLIB apply. Source reads/hashes/edits and
direct rustfmt only; no tests/builds/validators/probes or fresh advisory review.
Existing wire/debug/golden assertions are unrecaptured and unexecuted. Full
producer nil/empty/selected-field omission, signed-ID casts, wider/private
shapes, fallback/custom adapters, float/time/key/network/error fidelity,
snapshot/reload/cancellation/resource/load/shutdown behavior and native/
wire-only/feature/package/container/client/process/import/restart qualification
remain incomplete or unqualified. No dependency release or gate changed.

## Nested native debug response schemas — 2026-10-18

tailscale_wire/debug_schema.rs records the remaining pinned MapResponse
record declarations and tags: DNS/resolver/extra records, UserProfile,
PingRequest, display messages/actions, ClientVersion, ControlDialPlan and
candidates, Debug, TKAInfo, DERP map/home/region/node data and SSH policy/rule/
principal/action/recording-failure data. The private decoder in debug_nodes.rs
adds schema-driven pointer records, reused struct/pointer arrays and maps
with fresh per-entry values. It preserves required nil fields, repeated
outer-object map merges, signed integer map keys, sorted decimal key output,
nil pointer resets, null struct element reuse and declaration/omission order.
DNS route values retain null/[] and nullable resolver elements. SSH duration
uses Go JSON-v1's int64 nanosecond encoding; its format:nano tag does not
change the encoding/json integer path.

debug_json.rs no longer calls the public MapResponse projection or the old
debug Hostinfo conversion. Native readback now retains private typed state
for these nested records as well as the previously repaired node/filter
fields. Existing live Hostinfo operations, public wire field types and
wire-only dependency features remain unchanged.

debug_float.rs adapts encoding/json.floatEncoder's decimal cutoffs, signed
zero and exponent presentation to Rust's standard shortest decimal digits.
Typed values use decimal notation in [1e-6,1e21) and scientific notation
outside it, with a signed unpadded exponent. This includes Hostinfo typed
float maps as well as DERP/dial/debug values. Capability RawMessage payloads
still bypass Value and typed float conversion. Full parser/shortest-digit/
rounding equivalence is not established by this source-only implementation.

Pinned tailscale v1.101.0-pre SHA-256, in addition to the existing tailcfg,
dnstype and Go 1.26.9 encoding/json pins:
- tailcfg/derpmap.go: 860884479d72131dbbbdde892e5cbe3bbb7f59c79ac8165c3eb05bc249552e03
- tailcfg/tka.go: e8534dd7801a49a3928d4bc6079f9725f2a9af3ff89f76ee6a713051681166b2
- types/opt/bool.go: c2a3278ee70ce84d24eab7c4d54a8c37804a280dce718b3a8b222b138b798718

Original Tailscale/Go BSD notices and retained LICENSE-TAILSCALE and
LICENSE-GO-STDLIB apply. Source reads/hashes/edits and direct rustfmt only;
no tests/builds/validators/probes or fresh advisory review. Existing assertions
are unrecaptured and unexecuted. Exact float parser/rounding/formatting,
typed decoder diagnostics/error order, malformed Unicode/UTF-8/key/network/
time inputs, IO/resource/concurrency behavior, direct public read/serde,
live wire output and native/wire-only/feature/package/container/client/
process/import/restart qualification remain incomplete or unqualified. No
dependency release, public wire-field type or release gate changed.

## Native debug node and response state — 2026-10-18

tailscale_wire/debug_nodes.rs follows the pinned Node, PeerChange and DNS
Resolver declarations, generated HostinfoView.UnmarshalJSON, encoding/json
object/slice/pointer/byte decoding and omitempty/omitzero/IsZero emission.
It retains private signed IDs/int fields, required zero fields, nil versus
empty Addresses/AllowedIPs, nullable peer pointers, reused/truncated array
slots, repeated object/map merges and raw capability values. Public MapNode,
PeerChange and MapResponse types remain unchanged. Existing shared Go key and
network parsers normalize the typed text fields. Signature bytes support Go's
base64 and reused uint8-array inputs; resolver pointer arrays retain nulls.

HostinfoView initializes a valid empty view from null and rejects a second
initialization with already initialized, as in the generated pinned source.
Hostinfo, nested structs and services emit in declaration order through the
established typed Hostinfo schema. go_time.rs retains its existing UTC helper
and adds private local-time/offset state for debug encoding, trimming fractional
trailing zeroes and applying scalar/pointer null and IsZero semantics. Node
LastSeen's omitempty retains a non-nil zero time; peer-patch time/key omitzero
fields omit non-nil values whose IsZero method is true.

The directory reader now completes decoding before marshaling native node
state. Decode failures skip individual dump files; validly decoded offsets
that fail Time.MarshalJSON strict checks fail the final HTTP encoding instead.
Root field spelling/case folds and declaration order follow MapResponse.
Unknown root subtrees are scanned without Value allocation. Simple response
scalars, health/removal slices, signed-ID boolean maps, ControlTime and both
opt.Bool fields use private state, preserving merge/reuse/null behavior and
explicit-unset opt.Bool null emission. Native filters emit directly from their
private model; former projection presence markers are no longer needed.

Pinned tailscale v1.101.0-pre and Go 1.26.9 source SHA-256 (in addition to the
tailcfg/decode/encode/netip pins recorded below):
- tailcfg/tailcfg_view.go: 047f25258b20c07e3035e9d6d42f2f46f9de4a34b34cb8cace458e1587ccecc6
- types/dnstype/dnstype.go: bd770cbfa195f3a2eb0f14bf4554a6d7c714202d68faaf21ff01b45894763a2b
- time/time.go: e8b6ea9e6e7cb890aeed1d24ee7163a2237b6fa78ffc564efb8688dba717f02a
- time/format_rfc3339.go: 14b2a58fa295cca1a4f99467f5a5059418ed266a2298316124af97ffa014f271
- encoding/json/encode.go: 4012d78aa8236f3067a6330ddf2f719c7e59b262fcf4fff5e51b4abd1ccba235

Original Headscale/Tailscale/Go BSD notices and retained LICENSE-HEADSCALE-GO,
LICENSE-TAILSCALE and LICENSE-GO-STDLIB apply. Source reads/hashes/edits and
direct rustfmt only; no tests/builds/validators/probes or fresh advisory review.
Existing debug assertions are unrecaptured and unexecuted. Remaining nested
response schemas (DERP/DNS/SSH/profiles/display/debug/dial/client-version),
full float/typed error/log/IO/resource/concurrency fidelity, direct public
read/serde, live wire output and native/wire-only/feature/package/container/
client/process/import/restart qualification remain incomplete or unqualified.
No dependency release, public wire-field type or release gate changed.

## Stateful native debug filter decoding — 2026-10-18

tailscale_wire/debug_filters.rs adapts the pinned FilterRule, CapGrant,
NetPortRange and PortRange schemas, Go encoding/json array/object/literal
decoding, and netip.Prefix text semantics. It retains required nil/empty
SrcIPs/Dsts, ordinary scalar/struct null no-ops, optional Bits pointer reset,
reused nonempty slice elements (including truncated tail slots), case-folded
field matching, unknown-field skipping and Go declaration/omission order.
Private SrcBits/IPProto/Bits values use 64-bit Go ints while public wire field
types remain unchanged. Dsts uses the existing go_netip prefix parser.

Capability-map objects merge keys; repeated keys replace fresh []RawMessage
values. Named PacketFilters objects merge names, with each map value decoded
fresh, preserving null deletion markers and [] empty rules. The native debug
reader stores complete filter JSON outside the stable public projection,
using presence markers so neither wider integer casts nor opaque payloads
pass through its Value-based filter model. Node/PeerChange capability maps
share the private map decoder and merge repeated fields within each object.
Their presence marker avoids allocating one dummy Value per raw payload.
Final shared compact/HTML/indent processing and sorted map keys remain in use.

Pinned tailscale v1.101.0-pre and Go 1.26.9 source SHA-256:
- tailcfg/tailcfg.go: 83d0f9f69326e7da231eb6f5b2ea54257d87362e2718dad28f7e26d7c0167cf3
- encoding/json/decode.go: a91535f18f9a2c8380448b1c84c4c2017dbe3d530a10faf8babf03494042da48
- net/netip/netip.go: dbebdcbfd55f9619d57f55910b2af6240adb84dcd58bc76b9b396e479b91815e

Original Tailscale/Go BSD notices and retained LICENSE-TAILSCALE and
LICENSE-GO-STDLIB apply. Source reads/hashes/edits and direct rustfmt
only; no tests/builds/validators/probes or fresh advisory/security review.
Existing debug assertions are unrecaptured and unexecuted. Full surrounding
MapResponse/Node/Hostinfo schema/order/aliases/nulls/repeated-object and node
backing-slot semantics, direct public read/serde, exact error/log/IO/resource/
concurrency behavior and native/wire-only/feature/package/container/client/
process/import/restart qualification remain incomplete or unqualified. No
dependency release or public wire type changes, and no release gate closes.

## Required capability destinations and filter field order — 2026-10-18

tailcfg.CapGrant.Dsts has no omitempty tag. Go netipx.IPSet.Prefixes returns a
non-nil empty slice, so compiler-produced empty destinations serialize as
Dsts:[]. The public field remains Vec<String> and now emits empty vectors.
policy/opaque.rs writes FilterRule fields in Go declaration order (SrcIPs,
SrcBits, DstPorts, IPProto, CapGrant) and CapGrant fields as Dsts, Caps, CapMap.
It avoids Value map sorting, preserves the respective omission rules and
continues emitting retained raw capability payloads with sorted map keys.
NetPortRange/PortRange serialization retains the declared IP/Bits/Ports and
First/Last order through their typed serializers.

tailscale_wire/debug_json.rs retains required SrcIPs/Dsts nilness separately
from the stable public Vec projection and restores filter/grant field order.
Missing/null required slices emit null; non-nil empty arrays emit []. Fresh
null rule/grant elements retain their zero struct, and the covered nil optional
filter slices use their omitted projections. This does not establish complete
Go response decoding, duplicate/backing-slot reuse or public nil fidelity.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335,
tailscale v1.101.0-pre and go4.org/netipx fdeea329fbba. SHA-256:
- hscontrol/policy/v2/compiled.go: eebe64a7730e70428a3b63828aea9b9e1dd7a10e8d4ae9b9f8965ad8b781f7c7
- hscontrol/policy/v2/filter.go: 5a3ff3d7a19888a58d4d40425cb6c5a7210758d9f9e2ed6181c555a1bccf7b4b
- hscontrol/policy/v2/types.go: 57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4
- netipx/ipset.go: 01d0a58880b95e75f0b8e90e076eb9b56697bf9c9d075c030d422f2aafacd659

Existing tailcfg/encoding-json source pins and original Headscale/Tailscale/
Go/Go4 BSD notices/licenses apply. No dependency release or wire-only DB/core
boundary changed. Source reads/hashes/edits and direct rustfmt only; no tests/
builds/validators/probes or fresh security/advisory qualification. Filter/debug/
golden assertions are unrecaptured and unexecuted. Whole MapResponse/Node/
Hostinfo order, full aliases/null/duplicate/backing-slot handling, direct public
read/serde/nil shapes, wider values, errors/resources/concurrency and native/
wire-only/feature/package/container/client/process/import/restart qualification
remain incomplete or unqualified. All three release gates stay open.

## Opaque debug map-response readback — 2026-10-18

tailscale_wire/debug_json.rs follows mapper.ReadMapResponsesFromDirectory and
debug.go's mapresponses JSON boundary while retaining tailcfg RawMessage
payloads separately. It captures Node/PeerChange CapMap and legacy/named
FilterRule CapGrant.CapMap values, projects null placeholders through the
existing response/Hostinfo decoder, then emits the captured capability JSON.
Capability names sort lexically and repeated capability keys select their last
slice. Nil value slices emit null. Opaque numeric/string spelling and payload
object order/duplicates/depth/range do not pass through Serde Value. The final
native HTTP body uses shared Go compact/HTML/indent processing. Node-ID map
keys sort by decimal strings as encoding/json does. Root directory aliases are
processed in sorted order; unsigned decimal node names reject sign prefixes.
Partial node-directory enumeration errors skip that node as os.ReadDir errors
do upstream. Public read()/wire types and feature/dependency boundaries stay.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335,
tailscale v1.101.0-pre, Go 1.26.9. SHA-256:
- hscontrol/mapper/mapper.go: ec191db53afd7a906aaf015bf32c372c75c0b110aa784e5277e45269d2496534
- hscontrol/debug.go: 032c61a16ce0da210153d6d430f60fc4bf31345e65586cc9c03329a9b7f5a845
- tailcfg/tailcfg.go: 83d0f9f69326e7da231eb6f5b2ea54257d87362e2718dad28f7e26d7c0167cf3
- encoding/json/encode.go: 4012d78aa8236f3067a6330ddf2f719c7e59b262fcf4fff5e51b4abd1ccba235
- strconv/number.go: dda43e8c91d95f9dea0c46b2fec6637e5520cae099e40c5965dca0e41bbaab9e

Existing Headscale/Tailscale/Go BSD notices and licenses apply. Source reads/
hashes/edits and direct rustfmt only; no tests/builds/validators/probes or fresh
advisory/feature/package/container qualification. Existing debug assertions are
unrecaptured and unexecuted. The surrounding typed response still lacks full
Go field-order/alias/null/duplicate/backing-slot/required-empty/wide-value
fidelity. Direct public read/serde, exact decoder/log/IO/resource/concurrency,
native/wire-only/client/process/import/restart and all release gates remain
incomplete or unqualified.


## Per-connection self state and stream handoff — 2026-10-18

MapStateNode retains native Hostinfo for connectionEntry.withSelfDelta and
Node.Equal-style self comparisons. It compares all typed Hostinfo fields,
normalizes zero scalar creation/expiry times and optional zero machine/disco
keys, and excludes ExitNodeDNSResolvers and DataPlaneAuditLogID. Nil/empty
capability argument slices compare equally. A self/DNS prelude updates the
preview used to suppress a duplicate Node in the following policy frame;
full rebuilds use the same comparison. Debug capture precedes deduplication.
Only successfully encoded batches publish peer/self/SSH tracking state.

poll.go's serveLongPoll/writeMap stops on map serialization/write errors.
Incremental/full and ping encoding errors now propagate through try_unfold and end
the HTTP body instead of falling back to a keepalive. This supersedes the
older keepalive fallback documented above. Registry generation, batch and
DERP receivers now subscribe before the initial snapshot. DNS adds a private
retained watch channel, subscribes before that snapshot and preserves pending
edits between frames; legacy one-shot notify APIs remain available.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335,
tailscale v1.101.0-pre, SHA-256 in addition to existing mapper pins:
- hscontrol/poll.go: 3590bf1a227f48c2e574e96ef8660889235448025c1f096f0388f1bbf7871b6b
- tailcfg/tailcfg.go: 83d0f9f69326e7da231eb6f5b2ea54257d87362e2718dad28f7e26d7c0167cf3

Original Headscale/Tailscale BSD notices and retained licenses apply. Source
reads/edits and direct rustfmt only; no tests/builds/lint/validators/probes or
fresh advisory qualification. Native nil/slice/raw-payload and SSH time/
location/reflection shapes, initial/change/queue/network delivery, partial
frames, backpressure/reconnect/coalescing/shutdown and cross-component snapshot
coherence remain incomplete or unqualified. All release gates stay open.

## Native map slices, addresses and nullable LastSeen — 2026-10-18

MachineSnapshot reuses NativeNodePersistence endpoint/tag nilness and nullable
LastSeen while saved projections match. MapStateNode retains slice shape for
self/peer equality and avoids partial patches when a hidden shape changes.
Map identity prefixes use captured native typed addresses, including zeros,
actual families independent of database column and zone removal. Prefixes
without IP pointers is nil (Addresses:null); filtering a non-nil IPv4-only
source retains empty []. Empty Concat results omit AllowedIPs. Node attribute
snapshots and fallback consume the same native policy identity/addresses.

types.NodeView.TailNode filters identity IPv4 prefixes before concatenating
routes, sorts AllowedIPs with Prefix.Compare and preserves duplicates. Native
map construction now follows that order; selected route vectors share the
comparator. Peer Node.ID sorting follows signed tailcfg.NodeID order. Public
wire field types and feature/dependency boundaries remain unchanged.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335,
Go 1.26.9, SHA-256:
- hscontrol/types/node.go: b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab
- hscontrol/mapper/builder.go: 5e63d5d82eb590de006edf5146d75024a57f9b3cbc284f4e1a3eed450bfe0c50
- slices/slices.go: 8f2f5990f2189d57e530ddb8bf8224bab3e28e12d5da9f44e6d082c94228adcf
- net/netip/netip.go: dbebdcbfd55f9619d57f55910b2af6240adb84dcd58bc76b9b396e479b91815e

Existing Headscale/Tailscale/Go BSD notices and retained licenses apply. Source
reads/hashes/edits and direct rustfmt only; no tests/builds/lint/validators/
probes/advisory qualification. Online pointer/time-location/raw caps/SSH native
metadata, public/custom nil shapes, malformed imports and all concurrency/
delivery/native/wire-only/package/container/client/process/import/restart
qualification remain incomplete or unqualified. All release gates stay open.

## SSH policy acceptEnv reflection metadata — 2026-10-18

policy::NativeSshPolicy retains each compiled SSH rule's acceptEnv nilness
alongside the unchanged public SshPolicy. go_policy_shape captures missing/
null versus explicit [] from prepared policy source. Rule expansion and stable
check-first sorting carry the shape in lockstep. PolicyState invalidation and
rejected-write restoration include this metadata; CompiledRuntime captures it
with the SSH document and caches the complete snapshot. Native map initial,
incremental and full responses use one policy+shape capture for per-connection
withSSHPolicyDelta-style comparison. This preserves a reflect.DeepEqual
change hidden by omitempty without changing public fields or emitted JSON.
Cache updates retain last-non-nil behavior and require complete batch encoding.

Source review also confirms standard State startup and registration set
IsOnline to an explicit false pointer; no new standard pointer repair was
inferred from custom/direct node possibilities.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335,
SHA-256:
- hscontrol/policy/v2/filter.go: 5a3ff3d7a19888a58d4d40425cb6c5a7210758d9f9e2ed6181c555a1bccf7b4b
- hscontrol/policy/v2/policy.go: 1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e
- hscontrol/mapper/node_conn.go: d8d456c39d90fcf9508fc72e75ea48d0f0fe7d11966e1c1b90d600d3f43abec9
- hscontrol/state/state.go: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01

Existing Headscale/Tailscale BSD notices and retained licenses apply. Source
reads/hashes/edits and direct rustfmt only; no tests/builds/lint/validators/
probes or advisory qualification. Programmatic document/raw-shape mismatches,
custom/direct native fields and time/location, full compiler/cache/failure
phases, concurrent node/policy/queue/network delivery and all native/wire-only/
package/container/client/process/import/restart evidence remain incomplete
or unqualified. No release gate closes.

## SSH principal IP sets and checked alias errors — 2026-10-18

policy/ssh.rs follows groupSourcesByUser, ipSetToPrincipals and the localpart
self-access builder using Go-compatible address parsing. User/self IP sets
remove IPv6 zones via IPRangeFrom semantics; invalid typed addresses suppress
the corresponding builder output when its explicit error check fails.
Ordinary tagged principals instead retain Addr.String text, including zones
and typed zero "invalid IP", plus per-tag duplication. The underlying alias
resolver keeps usable partial results and errors as Go's IPSetBuilder does.

Map compilation continues to use partial alias sets. SSHCheckParams skips
any check rule whose source resolution errors, and skips a non-self destination
whose own resolution errors. ssh_check_period_for now makes those choices
explicit rather than sharing the compiler's partial-only resolution path.
sshRuleAllowsUser is evaluated directly for check authorization, independently
of whether groupSourcesByUser emits a source principal. Explicit root/nonroot/
literal names precede the untagged hydrated-owner requirement for localpart.
resolveLocalparts' entry-first/user-second last-match order is retained;
source domain order/multiplicity and existing Go EqualFold matching remain.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335,
go4.org/netipx v0.0.0-20231129151722-fdeea329fbba, SHA-256:
- hscontrol/policy/v2/filter.go: 5a3ff3d7a19888a58d4d40425cb6c5a7210758d9f9e2ed6181c555a1bccf7b4b
- hscontrol/policy/v2/policy.go: 1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e
- hscontrol/policy/v2/types.go: 57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4
- netipx/netipx.go: ff3005dd1e09a1169976c5996443b3797bba7ee4795362f7cce44cbbe8c8fb46
- netipx/ipset.go: 01d0a58880b95e75f0b8e90e076eb9b56697bf9c9d075c030d422f2aafacd659

Existing Headscale/Go/Go4 BSD notices and licenses apply. Source reads/hashes/
edits and direct rustfmt only; no tests/builds/lint/validators/probes or fresh
advisory qualification. Full partial/error/diagnostic behavior, malformed/
wide/custom/duplicate identities, zone/mapped/zero corpora, complete SSH auth/
revocation/replay/concurrency and all native/wire-only/package/container/client/
process/import/restart evidence remain incomplete or unqualified. No gate closes.

## SSH action HTTP, concrete hold user and entropy — 2026-10-18

SSHActionHandler/sshAction source behavior is implemented at the valid UTF-8
boundary with first-value query parsing, empty auth_id initial handling,
digit-only uint64 path IDs and pinned source/destination error text. Queries
are used after destination Noise machine authentication. Hold delegation
encodes concrete local_user (not $LOCAL_USER), uses Go QueryEscape and
lexical auth_id/local_user order. Policy/hold URL concatenation preserves
base trailing slashes; provider /auth URLs trim one. Hold/reject outcomes
share sshAction's initial forwarding flags. Public wire fields remain.

Action JSON uses the shared tailcfg SSH_ACTION schema/declaration order,
compact/HTML escaping and Encoder.Encode newline. Encoding failure retains
200 with empty body/log; text errors add nosniff. NewAuthID reads 24 random
bytes and truncates unpadded URL-safe base64 to 24 characters. RNG failure
returns Internal error without cache insertion. Dependency boundaries stay.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335,
Go 1.26.9, SHA-256:
- hscontrol/noise.go: 5c277a92d413a8e362b75667d3c6b11faaf6d2438021b4c57a5c0c8264bccbbc
- hscontrol/types/common.go: 0b660e6e4db2b32a6b136b33c710f4204f19c180d4e16b6db19ff7411ddfb08d
- hscontrol/util/string.go: f0a8db9bddf4c02775cc9a4011bb260f151c76c434e9ed8cc973a871312ff360
- hscontrol/handlers.go: dedcbcb85407d26adff5c8679c1b15c64cddf9702b694856a5c4b67247221b5e
- hscontrol/oidc.go: 88484e1fbbf5589433d858643ff52f630acc76d8a2ac94779f03db8cc5a7a591
- net/url/url.go: 7bec001746c2cd512275c7269bc293f3d36cb004ddb193d736e02e361a3778aa

Existing Headscale/Tailscale/Go BSD notices and retained licenses apply. Source
reads/hashes/edits and direct rustfmt only; no tests/builds/lint/validators/
probes/advisory qualification. Full URL parse/query/fragment/invalid-base
phases, invalid UTF-8/path extraction, header/flush/IO/RNG failures, auth
approval/replay/concurrency/resource/shutdown and all native/wire-only/package/
container/client/process/import/restart evidence remain incomplete or
unqualified. Existing fixtures are unrecaptured; no release gate closes.

## SSH delegation URL Parse/String and query values — 2026-10-18

Private tailscale_wire/ssh_url.rs adapts Go net/url Parse (viaRequest=false),
parseAuthority/parseHost, path/fragment encoded hints, escaping and String for
the immutable configured-base-plus-SSH-suffix input. It supports scheme
normalization, opaque forms, relative paths, OmitHost, userinfo/password,
raw host spelling, default strict HTTP colons/ports, typed IPv6/zone validation,
escaped path/fragment preservation and query placement. No URL resolver/network
operation is involved. Parsing now precedes auth-ID entropy/cache insertion
and returns Internal error on failure, as sshActionHoldAndDelegate does.

The existing query module now retains decoded byte Values and duplicate order
for ParseQuery/Encode. Malformed/semicolon pairs are discarded; default max
parameters is 10,000. Values.Set replaces auth_id/local_user and preserves
other usable pairs. Byte keys sort lexically and percent-decoded non-UTF-8
values are re-escaped without lossy String conversion. The earlier string-only
hold URL source gap is superseded; public wire fields/dependencies remain.

Pinned Go 1.26.9 SHA-256:
- net/url/url.go: 7bec001746c2cd512275c7269bc293f3d36cb004ddb193d736e02e361a3778aa
- net/url/gen_encoding_table.go: cd0f5020e4a5aa9741411afb4ab1bf73b9e9f40cd950e2bb9b369a773fdd9033
- net/url/encoding_table.go: 274e5ad203d6c38c41fe435eb9e5fc65ae1a38e98b44daa9b6355ba0d3fdac09
Existing headscale v0.29.5 noise.go and shared typed netip pins apply.
Original Go copyright/BSD terms remain in NOTICE-GO-STDLIB/LICENSE-GO-STDLIB;
new source retains copyright notices. No external dependency version changed.

Source reads/hashes/edits and direct rustfmt only; no tests/builds/lint/
validators/probes/advisory qualification. Exact logs/diagnostics, nondefault
GODEBUG URL modes, invalid-UTF-8 configuration/request/local-user bytes, URL
corpora, allocation/resource/entropy/cache/error/concurrency/shutdown and all
native/wire-only/package/container/client/process/import/restart evidence
remain incomplete or unqualified. No release gate closes.

## SSH raw query bytes and Chi path IDs — 2026-10-18

SSH query extraction preserves decoded byte auth IDs/local users in private
serde-skipped metadata. Public query/wire/policy field types and string method
signatures remain unchanged. Native SSHCheckParams-style evaluation compares
root/literals/localparts by bytes and shares nonroot handling with public
string wrappers; follow-up revalidation uses the same raw local user. Hold
query Values retain those bytes. No lossy UTF-8 conversion participates in
authorization. Public SshCheckBinding.local_user is only a projection (empty
for invalid UTF-8); cache/binding identity remains the src/dst pair.

AuthID.Validate checks byte prefix/length after the current-policy decision.
A shape-valid ID not representable as UTF-8 cannot match a generated/public
String-key cache entry, so it re-delegates as a missing session. Invalid shape
returns Invalid auth_id. The handler parses numeric IDs from the raw matched
URI, matching Chi's RawPath parameter route rather than Axum Path decoding.
Encoded numeric characters and invalid UTF-8 thus retain the pinned invalid
source/destination envelope when the route is matched.

Pinned headscale v0.29.5 noise.go/types/common.go/policy.go source pins above
apply. Headscale go.mod pins github.com/go-chi/chi/v5 v5.4.0; mux.go SHA-256:
cc44c2d620e6306b16d6d80f5f6c70f02b5814b357a4f5823372818f355ae67d.
Chi source was inspected for route behavior; no Chi code was copied.
Existing Headscale/Go notices and retained licenses apply. No dependency change.

Source reads/edits and direct rustfmt only; no tests/builds/lint/validators/
probes/advisory qualification. Unmatched/static-prefix/mount/rewrite routing,
HTTP request-target/HTTP2 validation, raw-byte/alias/URL/GODEBUG corpora,
public projection behavior, entropy/cache/resource/concurrency/shutdown and
all native/wire-only/package/container/client/process/import/restart evidence
remain incomplete or unqualified. No release gate closes.

## Self/peer route reducer and derived PrimaryRoutes — 2026-10-18

WithSelfNode uses State.Filter's global matchers to ReduceRoutes over global
primary subnets, then appends Node.ExitRoutes. policy::reduce_self_routes now
follows this distinction with captured native node/subnet identities and the
compiled global matcher cache. Peer State.RoutesForPeer applies viewer
matchers to global primaries plus exits before via/co-router additions; native
selection removes its unconditional exit bypass. The pinned function body
is authoritative here despite older Node.CanAccessRoute/ExitRoutes comments
that describe exits as unconditional. Self exit append behavior stays.

TailNode derives PrimaryRoutes from all returned non-exit routes, including
via-only routes; native peer projection now does the same. Reduction keeps
order. Via matching walks destination prefixes before announced routes and
appends approved exit matches for autogroup:internet; Include/Exclude retain
order/multiplicity. AllowedIPs concatenation remains Prefix.Compare-sorted
without deduplication. Announced/approved intersections now use announcement
order/multiplicity, and snapshot served routes avoid duplicate exit append or
set-normalization. PrimaryRouteState still owns its normalized election sets.
This supersedes earlier selected-route sorting descriptions.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335,
SHA-256 in addition to retained types/node.go and matcher pins:
- hscontrol/policy/policy.go: e5caa6ced4ebda898a5f79aa8da733103fb19bfbcdf2c9b5805838cac8fbe121
- hscontrol/state/state.go: 7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01
- hscontrol/policy/v2/compiled.go: eebe64a7730e70428a3b63828aea9b9e1dd7a10e8d4ae9b9f8965ad8b781f7c7
- hscontrol/policy/v2/policy.go: 1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e
- hscontrol/mapper/builder.go: 5e63d5d82eb590de006edf5146d75024a57f9b3cbc284f4e1a3eed450bfe0c50

Existing Headscale/Tailscale/Go notices and retained licenses apply. Public
wire fields and dependency boundaries remain unchanged. Source reads/hashes/
edits and direct rustfmt only; no tests/builds/lint/validators/probes/advisory
qualification. Full via alias/UsePrimary ordering, zero/malformed route states,
cache/error/phase/policy/co-router/HA churn, resources/concurrency/shutdown and
all native/wire-only/package/container/client/process/import/restart evidence
remain incomplete or unqualified. No release gate closes.

## Native ViaRoutesForPeer resolution and ordered passes — 2026-10-18

Private policy/via.rs follows pinned PolicyManager.ViaRoutesForPeer and
resolveViaDestinations under PolicyState's read lock. It resolves each alias
against the retained policy-node list, skips aliases with errors, emits each
usable destination IPSet's merged numeric prefixes, and retains internet as
an explicit exit flag. Viewer/peer NodeStore views remain independent of
retained alias/election candidates. The older pre-expanded CompiledRuntime
via_doc source path was removed; the public AclDoc helper remains available.

Ordered passes preserve policy grants, then ACL-to-grant destinations, and
Include/Exclude multiplicity. The scoped lowest-ID election uses Go's zero
sentinel and non-exit announced/approved candidate routes. UsePrimary follows
regular grant/destination/included order. Only explicit regular wildcard/
internet aliases lift exit exclusions; subnet-only election does not infer
exit candidates from an internet flag. NodeInput now retains original route
order, while equality/invalidation still compares multisets with duplicates.
IPSet.Prefixes reuses the existing numeric interval/CIDR encoder.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335:
existing policy/v2/policy.go (1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e),
compiled.go (eebe64a7730e70428a3b63828aea9b9e1dd7a10e8d4ae9b9f8965ad8b781f7c7),
types.go (57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4)
and Go4 IPSet source pins apply. Original Headscale/Go4 notices and retained
licenses remain. No public wire field/method/dependency boundary changed.

Source reads/edits and direct rustfmt only; no tests/builds/lint/validators/
probes/advisory qualification. Programmatic documents without parser-generated
network-grant rule projections, exact alias/error/partial diagnostics, zero/
malformed/native pointer states, policy/cache/HA/co-router churn, performance/
resource/concurrency/shutdown and all native/wire-only/package/container/client/
process/import/restart evidence remain incomplete or unqualified. No gate closes.

## Original ACL rows for native via conversion — 2026-10-18

PolicyState now retains original ACL rows beside the public PolicyDoc.rules
network-grant projections. go_policy_shape::original_acl_rules uses the shared
prepared JSON, metadata stripping, normalization and typed decoding boundary,
then requires source grants and the full generated-plus-original rule list
to match the supplied document. Without that match, explicitly supplied rules
remain the ACL input. This removes the native ViaRoutesForPeer assumption
that a counted prefix of programmatic rules must be generated grants.

The retained rows participate in invalidation and rejected-write restoration,
and private via conversion consumes them directly. Public policy/wire fields
and dependency boundaries remain unchanged. Pinned v0.29.5 policy.go's grants-
then-aclToGrants source behavior and existing parser provenance apply.
Original Headscale/Go notices and retained licenses remain. Source reads/edits/
direct rustfmt only; no tests/builds/lint/validators/probes/advisory qualification.
Broader typed/raw consistency, other compiler projection boundaries, exact
errors/resource/cache/rollback/concurrency and all native/wire-only/package/
container/client/process/import/restart evidence remain incomplete or
unqualified. No release gate closes.

## Private packet-filter compilation document — 2026-10-18

PolicyStore builds a private packet-filter document from network grants and
retained source ACL rows. Node-input category detection, global/per-recipient
filters and opaque compilation now share the generated grant prefix without
rewriting the public doc() model or raw source. Projection errors precede
publication; rejected SetPolicy restores the private model, and SetUsers keeps
its directory synchronized, including directory-only error restoration. Raw
nil/omitted filters select allow-all only for an empty typed rule/grant model.

Pinned headscale v0.29.5 compiled.go compileGrants compiles original grants
before ACL-to-grant conversions; its existing source hash
(eebe64a7730e70428a3b63828aea9b9e1dd7a10e8d4ae9b9f8965ad8b781f7c7)
and parser/policy provenance apply. Original notices/licenses remain. Public
field types/methods and wire-only dependency boundaries remain unchanged.
Source/direct rustfmt only; no tests/builds/lint/validators/probes/advisory
qualification. Standalone compiler typed-model assumptions, ambiguous raw/model
mismatches, exact errors/partial/cache/rollback/resource/concurrency behavior
and all native/wire-only/package/container/client/process/import/restart
evidence remain incomplete or unqualified. No release gate closes.

## Packet-filter source order and merge phases — 2026-10-18

Native filter/matcher/runtime source now follows buildSrcIPStrings numeric
range union, wildcard approved-route appends and per-alias non-wildcard
Strings appends. Destination/capability resolution retains alias order and
minimal numeric prefixes. Companion source prefixes retain per-alias order
and multiplicity. Empty companion inputs are no longer an omission gate.
mergeFilterRules preserves ordered SrcIPs/IPProto keys and appended DstPorts,
with CapGrant rules passed through. Removed field-wide sorting/deduplication
and the extra merge after recipient reduction. CapGrant narrowing alone
sorts/compacts destinations using numeric Prefix.Compare.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335:
- hscontrol/policy/v2/compiled.go SHA-256 eebe64a7730e70428a3b63828aea9b9e1dd7a10e8d4ae9b9f8965ad8b781f7c7
- hscontrol/policy/v2/filter.go SHA-256 5a3ff3d7a19888a58d4d40425cb6c5a7210758d9f9e2ed6181c555a1bccf7b4b
- hscontrol/policy/v2/types.go SHA-256 57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4
- hscontrol/policy/policyutil/reduce.go SHA-256 8131e92972157b23068c1cbb98d45f1aea9c928912351190f338816f9b83a6df

Existing Headscale/Go4 notices/licenses and netipx source pins remain. Public
wire/policy field types and dependency boundaries remain unchanged. Source/
direct rustfmt only; no tests/builds/lint/validators/probes/advisory review.
ProtocolPort grouping, self capability per-node grouping and exit-node self
capabilities, nil/empty encoding, invalid/zero/zone/error/partial/cache/rollback
behavior, resources/concurrency/shutdown and all native/wire-only/package/
container/client/process/import/restart evidence remain unqualified. No gate
closes and historical evidence does not qualify these edits.

## Original grant ProtocolPort and self-rule compilation — 2026-10-18

filter.rs now constructs an internal grant sequence directly from original
grants, then explicit ACL destination conversions, skipping synthetic model
rows. Each IP entry retains its ProtocolPort boundary and duplicate ports;
equal ranges no longer combine protocols. Admission/category detection uses
the same sequence. Regular network/app/companion output precedes self output.
Self network loops retain node/port/address order, and source membership uses
raw alias prefixes rather than wildcard route additions. Matched-node invalid
addresses suppress the self expansion on the builder-error boundary.

Self CapGrant output retains one entry per same-user node. The shared helper
also emits exit-node extras (including app-only self grants and companions)
for other users in ID order, without merging into the earlier merged batch.
Via compilation uses srcIPsWithRoutes rather than regular source appends,
per-alias numeric prefixes/duplicates, one final internet expansion and
prefix.String host suffixes in its DstPorts.

Pinned Headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335:
existing compiled.go/filter.go/types.go source hashes above apply to
compileGrants, compileOneGrant, compileSelfForUser, exitNodeSelfRules,
resolveViaDestinations, compileViaForNode, ProtocolPort and aclToGrants.
utils.go parsePortRange SHA-256:
264a06019ea2c9e2aa37ad2bad7040433e2c6baf32f7abaf18dcdff3b2b21b52.
Original Headscale/Go4 notices and retained licenses remain. Public policy/
wire field types, public methods and dependency boundaries remain unchanged.

Source/direct rustfmt only; no tests/builds/lint/validators/probes/advisory
qualification. Existing fixtures were not recaptured or run. Nil/empty shape,
raw/model and standalone compiler assumptions, complete malformed/zero/zone/
error/partial/cache/rollback/resource/concurrency/shutdown behavior and all
native/wire-only/package/container/client/process/import/restart evidence
remain incomplete or unqualified. No release gate closes.

## Strict filter parsing versus typed prefix construction — 2026-10-18

matcher.rs now distinguishes util.ParseIPSet(value, nil) filter strings from
typed Prefix/AddPrefix inputs. Filter-string construction follows wildcard,
slash, exactly-one-hyphen range and scalar-address branch order; requires
network CIDRs; keeps endpoints untrimmed; checks family/order; and removes
endpoint zones through the IPRangeFrom/PrefixFrom construction semantics.
Invalid entries contribute no span. Node membership rejects zoned queries.

RuleMatcher uses strict filter strings for SrcIPs/DstPorts and typed prefixes
for CapGrant destinations. Ordinary recipient reduction uses the same strict
parsed set for node IPs and all approved routes, including exits. Wildcard
requires an actual identity/route match; ranges overlap prefixes directly.
CapGrant reduction retains typed-prefix parsing/canonical text, subnet-only
route retention and the pinned Dsts/CapMap output shape. Policy-side generic
helpers use the shared Go parser while keeping host-bit masking distinct from
strict filter validation.

Pinned headscale v0.29.5 commit 0f7d1e536bed9f01dd7161f7637af19bb0908335:
- hscontrol/util/addr.go SHA-256 4808fab61e7ccd37b2aa18c7a721f2d5be2863c8ccde0b8cf25f216efb58166c
- hscontrol/policy/matcher/matcher.go SHA-256 94466c4793a902b3d2ffbd9eda044c9cf3f328a925067e9f6132b88e6ac84189
- hscontrol/policy/policyutil/reduce.go SHA-256 8131e92972157b23068c1cbb98d45f1aea9c928912351190f338816f9b83a6df
Existing Go netip/Go4 netipx source hashes apply. Original Headscale/Go4 and
borrowed Tailscale algorithm notices/licenses remain. Public field types,
methods and dependency boundaries remain unchanged.

Source/direct rustfmt only; no tests/builds/lint/validators/probes/advisory
qualification. Nil/empty shape, raw/model and standalone typed compilation
assumptions, complete invalid/error/partial/cache/rollback/resource/
concurrency/shutdown behavior and all accumulated native/wire-only/package/
container/client/process/import/restart evidence remain incomplete or
unqualified. Existing fixtures were not recaptured/run; no gate closes.

## Original ACL user-validation aliases — 2026-10-18

The additive validate_policy_user_references_for_source entrypoint validates
original source ACL aliases before packet-rule destination expansion. Native
gRPC set/reload/check, HTTP admin set/check, startup and direct CLI boundaries
supply their raw source. PolicyStore uses the same captured aliases before
candidate publication; typed/raw-mismatched input validates all explicit
rules rather than guessing that a prefix is synthetic. Compilation continues
using separately retained expanded ACL rows. Existing public field types,
methods/signatures and wire-only dependency boundaries remain intact.

Pinned v0.29.5 policy.go validateUserReferences checks each original ACL's
sources then destinations, and excludes original grant aliases from this
phase. Existing SHA-256 1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e
and shared parser/normalization source pins apply. Original Headscale/Go
notices/licenses remain. Source/direct rustfmt only; no tests/builds/lint/
validators/probes/advisory qualification. Source-less callers, raw/model
ambiguity, nil/empty/original-group policy-content identity, unordered-map
error ordering, full failure/cache/rollback/resource/concurrency/shutdown and
all native/wire-only/package/container/client/process/import/restart evidence
remain incomplete or unqualified. No gate closes.

## Original ACL content invalidation — 2026-10-18

PolicyState retains the source-bound OriginalAclIdentity beside expanded ACL
rows: original grouping/order, ACL/source/destination slice nilness, per-
destination ports, canonical protocol and original action. It participates in
SetPolicy invalidation and restores with the old public/private models after
a rejected candidate. Capturing all ACL details shares one prepared-source
pass. Policy.user/filter public field types, methods and wire-only dependency
boundaries remain unchanged.

Pinned v0.29.5 policy/v2/policy.go updateLocked includes the original typed
Policy in filterAndPolicy's deephash, independently of merged filter equality;
SHA-256 1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e.
policy/v2/types.go ACL/aclToGrants/unmarshalPolicy SHA-256:
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
Original notices/licenses remain. Source/direct rustfmt only; no tests/builds/
lint/validators/probes/advisory qualification. Full policy nil/empty/deephash
identity, explicit-null scalar parsing, raw/model ambiguity, exact errors/
cache/rollback/resources/concurrency/shutdown and all native/wire-only/package/
container/client/process/import/restart evidence remain unqualified. No gate
closes.

## Protocol zero after raw scalar decoding — 2026-10-18

The filter protocol encoder now preserves IANA number zero for signed-zero
Protocol spellings accepted by pinned Protocol.validate. Native raw protocol
normalization, action and check-period custom scalar parsing lives in the
shared ACL leaf with pinned source provenance in its UPSTREAM.md. Existing
public wire field types/methods and dependency boundaries remain unchanged.
Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification. Broader parser diagnostics/cache/failure phases and full native/
wire-only/package/container/client/process/import/restart evidence remain
unqualified. No release gate closes.

## Shared grant IP pattern translation — 2026-10-18

The API filter compiler now delegates grant IP pattern parsing to the ACL
leaf's additive go_policy_shape::grant_ip_patterns helper. Source-order
ProtocolPort groups remain separate, with literal validated protocols and
canonical numeric port/range patterns. This removes the API-only whitespace/
slash/prefix permissiveness and range-spelling losses at this boundary.
Pinned Headscale ProtocolPort/utils.go provenance is recorded in the leaf's
UPSTREAM.md. Public field types/methods and wire-only dependencies remain
unchanged. Source/direct rustfmt only; no builds/tests/lint/validators/probes/
advisory qualification or release gate closure. All package/client/process/
import/restart and failure/resource/concurrency evidence remains unqualified.

## Shared SSH check-period duration arithmetic — 2026-10-18

Live SSH check-period calculation now delegates to the shared ACL-leaf Go
duration parser used at policy decode/validation time. This removes a separate
integer-decimal fraction parser, preserving the same float64 nanosecond value,
precision and accumulation bounds across admission and runtime SSH timing.
The existing always/default/fallback and public interfaces remain in place.
Pinned time/format.go provenance/notices/licenses are recorded in the leaf's
UPSTREAM.md. No wire field type or wire-only dependency boundary changed.
Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification. Exact cache/approval/replay/concurrency/shutdown/resources and
all native/wire-only/package/container/client/process/import/restart evidence
remain unqualified. No release gate closes.

## Original ACL source-slice null identity — 2026-10-18

The shared ACL identity capture now treats an explicit Sources:null field as
a non-nil empty Aliases slice, distinct from omitted Sources, matching the
selected custom Aliases.UnmarshalJSON make-slice behavior. PolicyState's
existing private identity comparison and rejected-write restoration consume
that corrected shape. AliasEnc trimming/group decode changes live in the
leaf; its UPSTREAM.md records provenance. Public fields/methods and wire-only
dependency boundaries remain unchanged. Source/direct rustfmt only; no builds/
tests/validators/probes/advisory qualification, fixture recapture or release
gate closure. Complete policy identity and all package/client/process/import/
restart/failure/resource/concurrency evidence remain unqualified.

## Typed owner/auto-approver Username precedence — 2026-10-18

Tag-owner flattening no longer follows a tag-prefixed value containing @ as
an edge: parseOwner classifies that value as Username. Compiled route/exit
and tag-owner IP resolution use an owner-specific entrypoint that resolves
such user values before alias prefix classification. Group member Username
values use that same user resolver without reclassification. User-reference
ambiguity validation retains the group/owner/approver context, so prefixed
usernames are checked instead of silently skipped. Public APIs and wire-only
feature/dependency boundaries remain unchanged.

Pinned Headscale v0.29.5 policy/v2/policy.go validateUserReferences,
flattenTags/flattenTagOwners and userMatchesOwner SHA-256:
1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e.
The leaf UPSTREAM.md records matching types.go decoders and route-key pins.
Original Headscale notices and retained licenses apply.

Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification, fixture recapture or release gate closure. Other alias prefix
contexts, exact error/partial/cache/rollback/resources/concurrency/shutdown
and all native/wire-only/package/container/client/process/import/restart
qualification remain incomplete or unqualified.

## General alias kind precedence in resolution and validation — 2026-10-18

General policy resolution now uses the shared leaf parseAlias/Prefix.parseString
classification: literal prefix before Username, Username before namespaces,
then the existing alias expansion paths. A hosts entry cannot override a
literal IP. Owner/approver resolution keeps its own Username-first dispatch.
User-reference validation uses the typed context rather than skipping all
namespace-looking aliases. Conditional ACL/self/via ordering checks actual
AutoGroup kinds. Policy-check resolution and SSH-test self gating share the
Prefix/Username distinction and Go TrimSpace. Public APIs, model field types
and the wire-only feature/dependency boundary remain unchanged.

Pinned Headscale v0.29.5 policy/v2/types.go SHA-256:
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
The leaf UPSTREAM.md records test.go/utils.go and Go netip/Unicode provenance
for the shared parser and shape rules. Existing notices/licenses remain.
Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification, fixture recapture or release gate closure. Full error/partial/
cache/rollback/resources/concurrency/shutdown/native/wire-only/package/
container/client/process/import/restart qualification remains outstanding.

## Retained policy container-shape invalidation — 2026-10-18

PolicyState now keeps the additive leaf PolicyContainerShape beside original
ACL identity and app/SSH-env shape. The complete-source match excludes only
the attached user directory; mismatched supplied documents receive no new
container metadata. A change in nil/empty container shape invalidates retained
policy caches, and rejected policy writes restore the previous shape with
the other retained policy fields. Public document fields/methods and wire-only
feature/dependency boundaries remain unchanged. The leaf UPSTREAM.md records
selected policy/JSON/deephash source pins and canonical SSH duration handling.

Pinned Headscale v0.29.5 policy/v2/policy.go updateLocked/filterAndPolicy:
1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e.
Existing source notices/licenses apply. Source/direct rustfmt only; no builds/
tests/lint/validators/probes/advisory qualification or fixture recapture. This
is not full Go deephash/update equivalence. Legacy source metadata/raw-model
ambiguity and complete error/partial/cache/rollback/resources/concurrency/
shutdown/native/wire-only/package/container/client/process/import/restart
qualification remain incomplete or unqualified. No release gate closes.

## Fresh global ACL-test sandbox and source-aware entrypoints — 2026-10-18

ACL policy tests now compile a fresh global filter and resolve source and
destination IP sets through the shared resolver. Prefix overlap, IANA/default
protocol selection, DstPorts range containment and all-source-prefix admission
follow selected runPolicyTest/evalReachability/srcReachesDst helpers. CapGrant
entries alone do not allow packet traffic. The shared leaf destination parser
preserves the second JSON-string boundary and removes separate numeric-only
runtime parsing. Explicit source usernames must exist; the attached directory
and shared resolver retain provider precedence and ambiguity diagnostics.
Plain test source strings are not trimmed as AliasEnc. ACL failure labels and
error/accept-failure/deny-failure ordering follow selected result rendering.

Additive check_policy_semantics_for_source and boot-warning entrypoints retain
nil-default filtering, original ACL rows and app shapes for a complete matching
source. Native gRPC/REST paths pass source bytes; CLI wiring has its own package
provenance. Existing public entrypoints/model types/wire-only boundaries remain.
The fresh sandbox does not mutate PolicyStore/cache state. Its existing public
PolicyCheckNode lacks approved routes: compiler nodes currently have empty route
lists, so a further native snapshot input is required for routed cases.

Pinned Headscale v0.29.5 policy/v2/test.go evaluateTests/runPolicyTests/
resolveTestSource/evalReachability/source/proto/destination/port helpers:
7d90bc875a3c8209ebaae369bf48bbbcd376647a1dd8eade551b53863d19619d.
policy/v2/types.go AliasWithPorts/Username resolution/test shape:
57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4.
Existing compiled/filter/resolver/Go netip source pins/notices/licenses apply.
Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification, fixture recapture or release gate closure. Routed native node
inputs, source-less/mismatched projection, full SSH-test/combined-error/JSON
behavior and all filter/deephash/cache/failure/rollback/resources/concurrency/
shutdown/package/container/client/process/import/restart qualification remain
incomplete or unqualified.

## Route-bearing native policy-test inputs — 2026-10-18

The additive PolicyCheckNodeSnapshot pairs unchanged legacy node fields with
advertised/approved route facts. Snapshot-aware semantic-check and boot-warning
entrypoints supply announcement-ordered, duplicate-preserving approval
intersection to the fresh global ACL-test compiler. Private node/route pairing
uses entry order rather than an ID-map overwrite. Older public entrypoints
remain available without altering their argument or field types.

The registry constructor reads loaded associations, typed/zero addresses and
routes from one retained MachineSnapshot and preserves duplicate-ID checks and
native sorting. Registration's old policy-node projection reuses that capture.
MachineAdmin.policy_nodes_for_check adds a fallible record-list default and
native registry/SQLite/Postgres overrides using their existing native row/
association decoders. Native gRPC/REST policy validation uses these snapshots.
CLI direct/startup wiring is recorded in its package provenance. No backend
module is imported into the policy leaf and wire-only dependencies stay intact.

Pinned Headscale v0.29.5 hscontrol/types/node.go AnnouncedRoutes/SubnetRoutes/
AllApprovedRoutes and NodeView route getters SHA-256:
b3a82962818d085257ffce775dec3a86ab90dbe22279191a5d336f61a0c5ffab.
Existing policy/v2/test.go/compiled.go/filter.go/policy.go pins and source
notices/licenses apply to the fresh filter and route compiler consumers.
Source/direct rustfmt only; no builds/tests/lint/validators/probes/advisory
qualification or fixture recapture. Route edge cases, custom/legacy snapshots,
offline database/association consistency and full error/partial/cache/rollback/
resources/concurrency/shutdown/native/wire-only/package/container/client/
process/import/restart qualification remain incomplete or unqualified. No
release gate closes.

## Compiled SSH-test sandbox and combined errors — 2026-10-18

Policy checks now evaluate actual per-target compiled SSH rules, caching by
node ID per pass. Checked source/destination alias resolution, source-owner self
selection, node-ID deduplication, exact unzoned NodeIP principals and SSHUsers
map lookup follow pinned sshtest.go. Interval coverage/intersection avoids CIDR
host enumeration while retaining the first check counterexample. Result
rendering sorts usernames, preserves destination failure multiplicity and uses
the final AcceptOK membership for check diagnostics. No-assertion/source/dest
failures stop at their pinned boundaries. Source username ambiguity fails
before zero-user address resolution. ACL and SSH errors retain separate wrappers
inside the Tailscale multierr string. Existing public fields/signatures remain.

Pinned Headscale v0.29.5 hscontrol/policy/v2/sshtest.go SHA-256:
8375c3ebdd4cc751c7a13a2e57f9f6ed6023f2a178e781f92990d98f6232fc1a.
Tailscale v1.101.0-pre util/multierr/multierr.go SHA-256:
67413ab1031194eac91a5d7dd7ec28976d4989dc711b21b23015ca32c8ba898f.
Existing types.go/test.go/filter/compiler pins, BSD notices/licenses apply.
Source/direct rustfmt only; no execution validation or gate closure. Native
compiler parity, manually constructed invalid-policy error channels, legacy
projections, general error/JSON/deephash/cache/failure/rollback/resources/
concurrency/shutdown and all accumulated package/client/process/restart
qualification remain incomplete or unqualified.

## Native policy bytes and snapshot constructor compilation — 2026-10-18

The API HuJSON facade no longer parses/rewrites the whole policy before the leaf
custom decoder. Original duplicate names, opaque app tokens and raw SSHAction
escape/Unicode semantics reach the shared parser intact. Existing public/error
translation entrypoints remain. The preexisting escaped-whitespace expectation
was corrected from pinned source without execution. Opaque payload comparisons
use the additive leaf go_json.value builder, avoiding serde's private-number key
interpretation while preserving huge app numbers. Tagged SSH source principals
retain node input order/per-tag duplication; numeric user groups remain sorted.

The additive compile_policy_for_snapshot initializes an isolated PolicyStore
with snapshot-derived native identity/address/tag/announced/active route inputs
before candidate constructor compilation. It runs neither semantic tests nor boot
warnings and preserves existing public methods/fields. CLI wiring is recorded in
its own package provenance. NodeInput active routes preserve announcement order
and duplicates under approval membership.

Pinned Headscale v0.29.5 policy/v2/types.go SSHAction.UnmarshalJSON/Validate
SHA-256 57006e65ef42a99ba81e35381efc83a9ad8a416725a3d61a518350b9d8d3b9f4;
policy/v2/filter.go groupSourcesByUser SHA-256
5a3ff3d7a19888a58d4d40425cb6c5a7210758d9f9e2ed6181c555a1bccf7b4b;
policy/v2/policy.go constructor/updateLocked SHA-256
1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e.
Existing leaf JSON/Number pins and notices/licenses apply.
Source/direct rustfmt only; no tests/builds/Cargo/lint/validators/probes, fixture
recapture or gate closure. serde feature unification, generic Value readers,
numeric/canonical equality, recursive Value resources, malformed/combined/JSON
errors, legacy/custom projections, invalid-programmatic-action compiler errors
and all accumulated native/wire-only/package/client/process/import/restart/
rollback/cache/concurrency/shutdown qualification remain unqualified.

## Native JSON kind boundaries and policy constructor sequencing — 2026-10-18

Native OIDC raw selected fields bypass generic serde Value interpretation.
OAuth expiry and ID-token exp/aud/nbf/iat occurrences retain original kinds;
invalid early date/audience values cannot disappear behind later duplicates.
Null expiry duplicates preserve the prior value; expiry quoted-number grammar,
upper clamp and signed int32 narrowing follow oauth2. JWS/signature/header/JWK
objects use go-jose exact field names and direct duplicate checks. Generic extra
headers use strict-any duplicate/finite-float64 decoding. Unknown typed JWS/JWK
subtrees are skipped before allocating public Values; known scalar/list kinds
are checked before projection. Native JWK-set envelopes follow standard Go
keys matching while each contained JWK uses the strict fork. Protected raw bytes
remain the signing/auth input. Generic private Deserialize paths are unchanged.
Gateway body decoding now preserves an object-valued integer field as an object,
so a literal serde private-number key cannot turn it into a uint64 argument.

CheckPolicy captures users/nodes before parsing and compiles the constructor
sandbox before semantic assertions. Check/Set parse/test wrappers follow pinned
RPC status/context without local PolicyParseError display prefixes. Set/reload
and REST writes read the policy manager's retained user directory; constructor
checks load their independent directory. Public fields/signatures remain intact;
the added directory accessor is crate-private.

Pinned primary source SHA-256:
coreos/go-oidc v3.18.0 oidc/oidc.go
ad1c8f862558cdb25faaccd2d8feaf66f32d2834854e2a4b54d579ab06d90816;
golang.org/x/oauth2 v0.36.0 internal/token.go
98972e4d8b7a8807d2dc6ad760ad4bac346391b2d0bb155d6a7c62bfe6844a22;
go-jose v4.1.4 jws.go
c6853610e7807d2b663fd144ee1aa0c924406f5b44f0be76ea49704d0811c889;
shared.go 240a97eff4e21c55463cceee71269f2e79a29901cc2826b311800f7a6e29d0ba;
jwk.go 09825d9299db3a187aab55f9019d21747a36ad9cf3c27820941bd6a0a31f7c3c;
json/decode.go 2b8768b473ecf66b8e2319e912a9370d433ecc01c75c33aeaaf532d6912b1fc4;
protobuf v1.36.11 encoding/protojson/decode.go
41d2b009c5648973715d476e3668cd736a7c815c31a7b392ea4d7594ad3e81e5;
Headscale v0.29.5 hscontrol/grpcv1.go
1bb435c674a64b3a7d1382eddfc9b33d7fb8f646c414709d011508d0a2e883c3;
policy/v2/policy.go existing pin applies to constructor/SetPolicy retained users.
Existing upstream licenses/notices apply.

Source/direct rustfmt only; no tests/builds/Cargo/lint/validators/probes or fixture
recapture. Standard OAuth/claim folded-name and duplicate details, strict Unicode
versus replacement, Chrono date bounds, generic Deserialize consumers, public
Value resource behavior, malformed envelopes and all cache/rollback/cancellation/
concurrency/shutdown/native/wire-only/feature/package/container/client/process/
import/restart qualification remain incomplete. No fresh dependency/advisory/
security conclusion and no release gate closure.

## Standard OAuth/OIDC decoding and protobuf uint64 bodies — 2026-10-18

Native OAuth and ID-token fields now use raw source-order assignment with
standard Go tag folding, ordinary null-string preservation and custom decoder
occurrence handling. Claim maps merge/clear with Go map-element zeroing. Native
UserInfo performs coreos's profile/string/strict-boolean pass before Headscale's
flexible claims pass. Group slices are newly decoded per occurrence. OIDC/JWS/JWK
strings use explicit legacy replacement modes; policy-v2 strict decoding remains
separate. Unknown typed subtrees skip allocation. Numeric date/expiry strings
must satisfy numeric grammar before serde Number construction; Int64 precedes
Float64. IssuedAt accepts syntax/conversion-valid values outside Chrono's calendar
range because go-oidc does not date-compare that field. Expiry/nbf bounds remain.
Public structs/signatures and wire-only dependency boundary are preserved.

Gateway body uint64s use protobuf decimal digit shifting with integral fractions/
exponents, checked u64 arithmetic, i32 exponents and 20-digit normalized bounds.
Quoted values follow the actual first-token delimiter behavior. Path/query parsing
is separate. Null aliases count as seen protobuf field numbers; duplicate-name
checking ignores values instead of rebuilding generic trees.

Primary pinned SHA-256 sources:
Headscale v0.29.5 hscontrol/types/users.go
36bc0f562c507336d3a2a309c94718ec3baa2db2c3432180596556ab512d69dd;
hscontrol/oidc.go
88484e1fbbf5589433d858643ff52f630acc76d8a2ac94779f03db8cc5a7a591;
coreos/go-oidc v3.18.0 oidc/oidc.go
ad1c8f862558cdb25faaccd2d8feaf66f32d2834854e2a4b54d579ab06d90816;
oidc/verify.go
9c4b6e5de2883dcea4e44139d8ae2e34ee75dad15a9c9da4808c1ee2d68413d2;
Go 1.26.9 encoding/json/decode.go
 a91535f18f9a2c8380448b1c84c4c2017dbe3d530a10faf8babf03494042da48;
protobuf v1.36.11 encoding/protojson/decode.go
41d2b009c5648973715d476e3668cd736a7c815c31a7b392ea4d7594ad3e81e5;
internal/encoding/json/decode_number.go
 ae8d84879231dbbe42065f7d3852357046382ea3e290c8262fb475559638f2e0;
decode_token.go 1b60ca4b6380800bf748d2dfbf8c7b0dff8f52c8f223d3fe02c4879b2072f6b7;
decode.go 149097bfd4ae2cd52f8f8d5b36c850c3972124670c75aaabfaa32edb29512aa4.
Prior oauth2/go-jose source pins apply. New LICENSE/NOTICE-PROTOBUF-GO,
LICENSE/NOTICE-GO-OAUTH2, LICENSE/NOTICE-GO-JOSE and LICENSE-GO-JOSE-JSON retain
upstream terms/attribution; protobuf license SHA-256
4835612df0098ca95f8e7d9e3bffcb02358d435dbb38057c844c99d7f725eb20.

Source/direct rustfmt only; no tests/builds/Cargo/lint/validators/probes. Exact
raw/field/line/alias-order diagnostics, saved errors within nested maps, combined
core verifier versus application claims staging, Chrono expiry/nbf and overflow
architecture behavior, malformed protobuf number lexing versus initial scanner,
generic Deserialize consumers, public Value resources and all accumulated
native/wire-only/feature/package/container/client/process/import/restart/cache/
rollback/cancellation/concurrency/shutdown qualification remain unqualified.
No fresh dependency/security/advisory conclusion; all three gates remain open.

## Callback staging, browser errors and protobuf body lexer — 2026-10-18

Native ID-token decoding now separates core verification from the Headscale
application-claims pass after nonce binding and expiry selection. Responses after
nonce binding clear both callback cookies. Nested claim maps retain ordinary
saved errors while later entries assign, with zero map-element temporaries.
Request-cookie parsing and callback path/name rendering follow pinned Go source;
the default candidate limit is implemented without GODEBUG overrides.

OIDC browser errors adapt Headscale httpUserError/AuthError and elem-go rendering,
with generic messages and technical logs. error_style.css/error_logo.svg copy
the pinned Headscale assets. Custom HTTPError UserMsg overrides are not projected.
The private gateway request lexer adapts protobuf's token/number/string decoder,
keeps raw token spellings and known-field alias duplicate ordering, and scans
deeper unknown containers iteratively without retaining their full value trees.
Existing public types/methods, response serialization and wire-only dependencies
remain. Existing Go/Headscale/protobuf licenses and notices apply.

Additional pinned SHA-256 source files (existing pins above also apply):

- Headscale v0.29.5 hscontrol/handlers.go:
  dedcbcb85407d26adff5c8679c1b15c64cddf9702b694856a5c4b67247221b5e
- hscontrol/templates/auth_error.go:
  ddc4f32170f314ed6c92b26265a714084d2aea7fa4215c1e248e375023570dd5
- hscontrol/templates/general.go:
  59dee4f0320b4ee28138a968ea689fe34dd7fc8bb4be1ae10a0ccc830fc71993
- hscontrol/templates/design.go:
  f8bb3305757273a5d733e9def9e208995f8ae238d0a2f37310a9ed8fb40d3f44
- hscontrol/assets/style.css:
  c1e28c80b1f59cd6b73f5a4946312d5b9fcc44b0508b134e71c15d2734d67695
- hscontrol/assets/headscale.svg:
  4e0c69b020219e2e4ecb900d40c704130567d6a83abe61d85a826a7029e02354
- Go 1.26.9 net/http/cookie.go:
  a0b5b5a3be97de79e68a6bcd9df2c34dfb9bd09c6eb312b38ca1bbc79cca86dd
- net/http/status.go:
  7633ca0ca545767f3db3d8960a96ee4ecd68fb39439c88b7c03efcb3d1786297
- elem-go v0.31.0 elem.go:
  33cb335aa81d854df7bdd2f295d41b78ede15f3c57dd9ad1c34207fedda7507f
- styles/styles.go:
  a42a52de308a071346f9bd1c78fd9420047891e3080fe39dc0bca24bba1e9bf0
- utils.go:
  143292bb8b2b1275d2f4b3869b4a6fe434806835e8ca3d510683ffe3aee05b6d
- protobuf v1.36.11 internal/encoding/json/decode_string.go:
  99540744259eb12d78fc7431c506dcba4c4148eed66c21037b7a860a940bb6cd
- encoding/protojson/well_known_types.go:
  b0425d7be0da31c38914588bfdea03ce3452a9d547b2dc649fcd06982695912e
- encoding/protowire/wire.go:
  109e891e95fb059a3622e2ad97bb06f6829da7d4ac7fc13c36deb508d6f9ef40

Source/direct rustfmt only; no tests/builds/Cargo/lint/validators/probes. Eager
gateway full-body validation still changes some competing syntax/type failure
order; many scalar errors lack source positions, and invalid UTF-8 outside
strings has lossy diagnostic transport. Browser rendering, callback/cookie
lifecycle, nested-map diagnostics and all accumulated range/resource/native/
wire-only/feature/package/container/client/process/import/restart/security/
dependency/advisory qualifications remain open. No release gate is closed.


## Gateway typed-token validation and confirmation lifecycle — 2026-10-18

Current gateway body schemas identify string/bool/uint64/repeated-string and
Timestamp fields. Token-time validation preserves input order and source
positions before later duplicates or malformed input; known wrong containers
fail on opening tokens. Existing protobuf decode.go/well_known_types.go pins
apply. Timestamp dot-fraction length and diagnostics follow protobuf, with
Go-versus-Chrono parser acceptance still unqualified.

Confirmation GET has no-store and an additive async native route that reloads
users by ID after CSRF validation; POST reloads before completing registration.
SQLite/Postgres overrides use their native association lookup, missing users
return record not found, and the policy wrapper delegates. Existing synchronous
GET and custom stores preserve their fallback behavior. Branded confirmation and
success templates, absolute form action, empty-OS fallback, numeric user display
fallback and explicit spent-link message use the existing Headscale/elem-go pins.
HTML attribute escaping is deliberately retained even though pinned elem-go
writes attrs raw: AuthID validation only checks prefix/length. Unusual values may
therefore differ in rendered source bytes while remaining safe attributes.

PKCE-only early cache lookup now returns404 when the verifier state is absent;
nonPKCE callbacks validate the provider/core/nonce/application claims before
atomic state consumption. Confirmation cookie Path and attribute order follow
Go. Plain GODEBUG httpcookiemaxnum settings use the last assignment, signed
platform-int parse, zero-unlimited and default fallback for invalid values;
Go call-stack bisect #patterns and runtime counters are not projected.

FlexibleBoolean follows the standard-any overflow phase across nested and
replaced duplicate values before invalid-type formatting, and ParseBool invalid
string errors. Ordinary string errors preserve typed field contexts, with exact
names before Unicode folding. Iterative raw diagnostic formatting follows Go
fmt map sorting/array layout and general-float exponent conventions. Cross-runtime
shortest decimal details and repeated subtree scanning resources are unqualified.

Additional pinned SHA-256 sources:

- Headscale v0.29.5 hscontrol/templates/register_confirm.go:
  32c5d1ca13b29c021e348863f116c187d6d98050f7430511453ff414c2ce2cdc
- hscontrol/templates/auth_success.go:
  796c7a2871e03dbd60a2e40eff97ca2289fe115f984764a1afb2dbf53996ab10
- Go 1.26.9 src/internal/godebug/godebug.go:
  cd492e76ae63872ac4310fc09b2e097229588dbf114d14d713be3f027b0233c8
- src/strconv/number.go:
  dda43e8c91d95f9dea0c46b2fec6637e5520cae099e40c5965dca0e41bbaab9e
- src/internal/strconv/ftoa.go:
  2c12d1c3a17b9a978266a7c761862a4be8dd1f2fae14ad5bbdf6ff2dd8f3493d
- src/fmt/print.go:
  57250462a0d06d61f124b4530493bcdd150e9de29600bd60347e1c74457ac8a1

Existing Headscale/Go/protobuf notices and licenses apply. Source/direct rustfmt
only; no tests/builds/Cargo/lint/validators/probes. Native/custom/user-refresh
races, cookie/browser/env behavior, timestamp/float grammar, malformed UTF-8,
resource/feature/process/import/restart/security/dependency/advisory qualification
remains open. No release gate is closed.


### Source review corrections to the preceding batch

The real HTTP gateway decodes the first raw JSON value with Go encoding/json
before invoking protojson. The shared additive go_json::first_raw_value scanner
now implements that boundary, returning clean EOF for whitespace-only bodies,
strictly checking the first value and leaving later bytes ignored as the native
generated handler does. Typed protobuf validation then follows field order
inside that syntax-checked RawMessage. Bare malformed protobuf numeric spellings
are rejected by the outer scanner; quoted uint64 strings still use the protobuf
number decoder. This corrects the earlier assumption that typed errors should
precede malformed syntax anywhere in the same first value. Chrono leap seconds
are rejected before emitting invalid protobuf nanoseconds.

Native confirmation machine fingerprints now use Tailscale debug32 (five
standard-base64 digits, empty zero key), replacing the hex-prefix approximation.
Confirmation POST's additive query-aware route rejects malformed query escapes
and raw semicolons while leaving CSRF lookup strictly in the POST form. Existing
public handler signatures remain as compatibility wrappers. Query/body/media
error wording and precedence beyond the shared HTTP status remain unqualified.

Additional SHA-256 sources:

- grpc-gateway v2.29.0 runtime/marshal_jsonpb.go:
  64a8847a795ee97267d48d6a8904ea0e32e6b480e218fbe731ba7472e012962d
- Headscale v0.29.5 gen/go/headscale/v1/headscale.pb.gw.go:
  54ae24588b12563a82e86680b619574ac525e13d13f5550e63c573f413405b67
- Tailscale v1.101.0-pre types/key/machine.go:
  a9b6b19c9b51480f27959149e4903e266ee2ee922698a0abd4b03de796ca718b
- types/key/util.go:
  f635c220a4b75e16e01269994c92c8defc0ea1ad9b09ba71826b65ac86da80f9
- Go 1.26.9 src/net/http/request.go:
  4a34a9e157a606a046d5b9f8f761c571c4762668fa351d92048515a595939c38

LICENSE/NOTICE-GRPC-GATEWAY retain the upstream BSD terms and provenance;
existing Headscale/Go/Tailscale licenses apply. Container recipes already copy
API LICENSE*/NOTICE* files. Source/direct rustfmt only; no build/test/package/
container/license validator or execution evidence covers these changes.

Additional Go scanner source pins for the first-value adapter:
encoding/json/stream.go (readValue):
bb26b2442db6a686fc7f823ea9cc89babe26ac988ec7d8caf4a157aeb60d92f2;
encoding/json/scanner.go:
2b16dd215274dfa8e0806b53cca144684d5b9c8a02319cf5ce10120c50e6eef2.

Leap-second source: Go 1.26.9 time/format_rfc3339.go SHA-256
14b2a58fa295cca1a4f99467f5a5059418ed266a2298316124af97ffa014f271;
locked Chrono 0.4.44 format/parse.rs
0114cc8f7cee11af7fd091f874c609c71e2ba094e2d793459f440150bb3cb1ed.
These are source pins, not executed parser-equivalence evidence.


## Native timestamps, ParseForm and OAuth boundaries — 2026-10-18

Private grpc_gateway/timestamp.rs translates Go time.Parse(RFC3339Nano) fallback
and protobuf/query wrapping, replacing Chrono on request timestamp paths. It
retains optional one-digit hours, comma/dot fractions and nanosecond truncation,
24/60 offset boundaries, delayed day checks, year-zero civil conversion, error
contexts and separate protobuf dot-fraction/range admission. Timestamp responses
retain their existing formatter. Integer arithmetic is bounded by the four-digit
year and parsed field ranges; execution equivalence remains unqualified.

Private oidc/form.rs translates ParseForm MIME/body/query phases, recognized
form-only body limit, first-value/body-only CSRF extraction, byte-level URL
unescape, semicolon precedence and default/custom query parameter limits.
Shared MIME parsing preserves the base/error pair and raw parameter bytes for
confirmation, discovery, token and UserInfo paths. Signed UserInfo requires full
parse success; oauth2 ignores parameter errors while retaining the base.
Discovery error selection and Go quoting retain raw response header bytes.
Patterned GODEBUG values and runtime counters are not projected. Buffered input
cannot reproduce live body-reader errors/connection effects. Invalid-UTF8 CSRF
values become replacement text and cannot match native ASCII cookies.

Authorization and token request construction now uses Set replacement, sorted
Go QueryEscape encoding and source optional-field rules. Configured options
replace earlier values; native nonce is set last. OAuth response reading keeps
only the first 1MiB like io.LimitReader rather than rejecting Content-Length.
Typed token JSON finishes before the ignored-error optional Extra map stage.
A private id_token string-type flag preserves present-empty JSON/form behavior
versus absent/nonstring JSON, and form Extra numeric coercion follows signed
integer/decimal-or-hex Float64 parsing. Expiration diagnostics and narrowing
follow source. UserInfo Token.Type uses Go Unicode fold for bearer/basic/mac.
No existing public field type/method signature or dependency version changed.

Pinned SHA-256 sources (prior Headscale/coreos/protobuf pins also apply):

- Go 1.26.9 time/format.go:
  f288c56858ab25828551681778f006b591ed140fc12e60122b6a9a7e35b07eb7
- time/format_rfc3339.go:
  14b2a58fa295cca1a4f99467f5a5059418ed266a2298316124af97ffa014f271
- net/http/request.go:
  4a34a9e157a606a046d5b9f8f761c571c4762668fa351d92048515a595939c38
- net/url/url.go:
  7bec001746c2cd512275c7269bc293f3d36cb004ddb193d736e02e361a3778aa
- mime/mediatype.go:
  2179fd195097a382a2ac3cdcbcbc6961f2770dbd61adfabfc60535c1acc5faa0
- mime/grammar.go:
  85d1052199201e6ad52e27db50104842295dbf10e87f3914c803c6ce533772a6
- internal/strconv/atoi.go:
  eb5ad640903abe9e8c8b7fbce8dd3487176dbeb43e8b8b4efa6e73ecb5207ddc
- internal/strconv/atof.go:
  2c2205ccab8626b623a188144a7dcaf202ece77002a27a2cd6b0aaf5a61669a5
- strconv/quote.go:
  6602960ec8777de9926c1d02fbf5cb0828d4aefa38083865f4af17b6892c09a2
- x/oauth2 v0.36.0 oauth2.go:
  e6ccbbe51f721b73c65fe60597b024e01c2908353fb4d03919fd8899d3d3f968
- token.go:
  9715ac669ec1d80ae4549dd83379a95c7ea278542a9c96ad55e957e2e822c8db
- internal/token.go:
  98972e4d8b7a8807d2dc6ad760ad4bac346391b2d0bb155d6a7c62bfe6844a22
- grpc-gateway v2.29.0 runtime/query.go:
  cdb3c973f81862d47dacf2056cf0ac58c66c98f9c0b609efc9bc6f10f69510c6

Existing Go/oauth2/coreos/protobuf/grpc-gateway licenses/notices apply. Source
reads/edits/hashes/direct rustfmt only; no tests/builds/Cargo/lint/validators/
probes. Native/wire-only/feature/package/container/client/process/import/restart,
parser/numeric/resource/cancellation/concurrency, security/dependency/advisory
qualification remains open. None of the three release gates is closed.

Integration review also routed OAuth form token bodies through the shared strict
ParseQuery visitor/default/custom parameter limit. Only known token fields retain
their first value; arbitrary-byte values still meet the existing String DTO
boundary. Unknown parameters are syntax/limit-checked without retaining a map.
Raw discovery Content-Type error envelopes and Unicode Token.Type folding were
reviewed and integrated in source only. No new validation evidence is asserted.


## OIDC runtime diagnostic events — 2026-10-18

OIDC redirect, callback-state expiry, registration-kind/expiry and native SSH
rejection events follow pinned Headscale messages and auth/node/owner fields.
UserInfo provider failures emit the upstream ERROR event twice with the provider
error; second-pass Claims failure or subject mismatch emits it once without an
error field, matching the callback's retained err variable. Private DecodeError
keeps provider versus Claims phase without changing callback acceptance or
merge decisions. Unsupported UserInfo endpoints now log their provider error.

Pinned source SHA-256:
- Headscale v0.29.5 hscontrol/oidc.go:
  88484e1fbbf5589433d858643ff52f630acc76d8a2ac94779f03db8cc5a7a591
- hscontrol/util/log.go:
  a294c1fa35534c9b81ecb0b79512b027a6b824ad639878952430015ba644bbe3
- coreos/go-oidc v3.18.0 oidc/oidc.go:
  ad1c8f862558cdb25faaccd2d8feaf66f32d2834854e2a4b54d579ab06d90816
Existing notices/licenses apply. Public APIs and authentication/merge decisions
remain unchanged. Provider transport/signature errors, non200 response-body
text, caller paths and exact rendered output remain unqualified. Source/direct
rustfmt only; no tests/builds/Cargo/validators/probes/fixtures or gate closure.


## UserInfo response and transport diagnostics — 2026-10-18

UserInfo reads its bounded response before checking status, preserving read-error
precedence and status/reason/body diagnostics. An available hyper HTTP1
ReasonPhrase is retained. Native transport causes are included with Get and a
Go-quoted password-redacted URL; the shared provider body reader also retains
underlying native causes. Removed the private empty-token shortcut to follow
Provider.UserInfo; the exchange path still rejects missing access_token. New
helpers remain cfg(full); public APIs and wire-only dependencies are unchanged.

Pinned source SHA-256:
- go-oidc v3.18.0 oidc/oidc.go (UserInfo):
  ad1c8f862558cdb25faaccd2d8feaf66f32d2834854e2a4b54d579ab06d90816
- oauth2 v0.36.0 token.go (SetAuthHeader):
  9715ac669ec1d80ae4549dd83379a95c7ea278542a9c96ad55e957e2e822c8db
- oauth2.go (StaticTokenSource):
  e6ccbbe51f721b73c65fe60597b024e01c2908353fb4d03919fd8899d3d3f968
- internal/token.go (missing-access-token error):
  98972e4d8b7a8807d2dc6ad760ad4bac346391b2d0bb155d6a7c62bfe6844a22
- Go 1.26.9 net/http/client.go:
  908d9d964cd157899b60e7ba839befa4bfd398b4fb8f7ff5a1aa389eae75f652
- net/url/url.go:
  7bec001746c2cd512275c7269bc293f3d36cb004ddb193d736e02e361a3778aa
Existing notices/licenses apply. Actual Rust/Go OS/TLS/redirect/builder text,
unavailable reason phrase, byte projection and existing 1MiB/30s bounds remain
incomplete or unqualified. Source/direct rustfmt only; no tests/builds/Cargo/
validators/probes/fixture recapture or release gate closure.

## Empty-peer policy profiles — 2026-10-18

Policy map deltas omit UserProfiles when their current visible peer set is
empty, following mapper.policyChangeResponse. Nonempty peer sets and other
update types retain their existing profile refresh behavior.

Pinned Headscale v0.29.5 hscontrol/mapper/mapper.go SHA-256:
ec191db53afd7a906aaf015bf32c372c75c0b110aa784e5277e45269d2496534
Existing BSD notices/license apply. Source review/direct rustfmt only; no
tests/builds/process recapture or gate closure. Current wire behavior remains
unqualified.

## Policy-manager diagnostic stages — 2026-10-18

Private diagnostic snapshots emit the filter/tag-owner/route-approver/exit-set
change events, counts, aggregate flags and no-change trace. Retained runtime
and initial no-node paths use compiled rule/IP-set projections and policy plus
source shapes; user-directory serialization is excluded. The diagnostic flags
do not control publication, change returns or cache invalidation. Stage state
advances before nodeAttrs failure, with aggregate/no-change only after success.

Fingerprints use SHA-256 over Rust projections, not Tailscale's process-seeded
reflected-type deephash. Missing Go nil/type distinctions, staged Rust startup
producing provisional constructor events and earlier flattened-tag prevalidation
remain source boundaries. Exact startup lifecycle, caller/output bytes and
runtime resource/error behavior are unresolved or unqualified.

Pinned SHA-256:
- Headscale v0.29.5 hscontrol/policy/v2/policy.go:
  1d998cad76474250e3b66702998387e868dc430fb221d3420762b4cde49b302e
- tailscale.com v1.101.0-pre util/deephash/deephash.go:
  cc886c8db2085886058d59aa21532123ff45d8b3a12920c905d15ac1d9bbc2d2
Existing BSD notices/license apply. Independent source review/direct rustfmt
only; no tests/builds/validators/probes/recapture or gate closure.

## Deleted map-stream termination — 2026-10-18

Production Noise uses direct h2::server, not Hyper. A private map response
extension now carries the existing exact-session sticky cancellation flag and
an already-subscribed generation receiver. Noise dispatch selects deletion
alongside body polling and outbound DATA capacity waits, explicitly calling
SendStream::send_reset(INTERNAL_ERROR). Body errors explicitly reset too. The
deleted-node body itself returns an IO error instead of clean EOF. No background
task or extra response-frame buffer was introduced; ordinary rekey/shutdown
does not itself set the deletion flag. This supersedes the earlier Hyper-only
explanation and the missing Noise blocked-capacity cancellation source residual.

Hyper's body-error mapping still applies where it owns a response; that mapping
alone cannot interrupt its capacity-before-body-poll boundary. Native Noise
now has its own explicit cancellation path. Actual socket/reset delivery,
flow-control/cancellation/reconnect/guard/shutdown behavior remains unqualified.
No public API/dependency change. Independent source review/direct rustfmt only;
the existing direct-body deletion assertion was source-updated, not executed.
All parity gates stay open.

Pinned source SHA-256:
- Headscale v0.29.5 hscontrol/poll.go:
  3590bf1a227f48c2e574e96ef8660889235448025c1f096f0388f1bbf7871b6b
- x/net v0.56.0 http2/server.go:
  cf07329cd7d5d95909a5404f3b29f10f4252189012b98ad4c8fdbfca384cb9d1
- Hyper 1.8.1 src/proto/h2/mod.rs:
  180b83f135fe2e96df4b9299a14c09ccd45e7e7f12b5c13386593d77a249034d
- Hyper 1.8.1 src/error.rs:
  ded435e7d5ea8da4e32e22740cc96e1a9d185dfd93935afb3fc9214a3518dadb
- h2 0.4.19 src/share.rs (SendStream::send_reset):
  e313c11a24b649d4c9da937fb37e5c2cc7c689c53f6afd2470fd40fd030237c5
Existing source notices/licenses apply. No tests/builds/checks/probes ran.

## Full-input constructor boundary — 2026-10-18

Native SQLite/Postgres startup now uses additive from_initial_registry after
loading allocator, nodes, users and raw policy. It seeds final user/node inputs
without compilation, then installs a parsed policy (or nil policy) with one real
compile/nodeAttrs refresh. Initial failure returns without replacement rollback,
preserving the staged events without empty-policy restore logs. Ordinary public
SetPolicy replacement retains its existing restore/recompile/publication path.
Offline candidate compilation shares initial installation. Boot warnings follow
successful native construction; CheckPolicy/admin constructor validation emits
the corresponding warnings before its subsequent hard-test rejection. The public
compile helper stays warning-free and direct CLI keeps its explicit warnings.

This replaces native deferred-diagnostic replay and its missing partial-failure
events. The old optional public deferred APIs remain available with their prior
failure-before-completion limitation. SHA-256/Go-deephash, retained nil/type,
underlying row-association/helper errors and exact parser/driver/IO/output/lifecycle
behavior remain unqualified. Direct node hydration and policy-user list errors
now use native DB rendering; startup applies phase-specific wrappers.

Pinned Headscale v0.29.5 hscontrol/state/state.go SHA-256:
7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01
The policy.go pin above covers NewPolicyManager/updateLocked. Existing BSD
notices/license apply. Source/direct rustfmt and independent source review only;
no tests/builds/Cargo/validators/probes/recapture or gate closure.

## Retained map-session identity and idle timing — 2026-10-18

Map sessions resolve their current key by the guard's stable NodeID on relevant
wakes, matching NodeKeyRotated's self update without deleting the session.
Same-ID rekey preserves counters/generations. Private ownership epochs guard
active/deferred releases and post-save local dispatch. Actual retirement occurs
under each NodeStore writer/queued work item, covering same-key different-ID
replacement and intermediate delete/reinsert; notification follows lock release.
GC timers retain node/machine/epoch identity and validate after the mutation
guard and at conditional post-save cache deletion. Synchronous disconnect
publication and owned timer insertion use a protected NodeStore view; no epoch
or NodeStore lock crosses an await. Captured disconnect snapshots still decide
peer recomputation. An in-flight custom adapter's external side effects cannot
be revoked through the existing trait; local state/dispatch/GC are guarded.

Streaming keepalive base is now 50s plus one uniformly sampled 0..8999ms jitter
per session. A fixed deadline across empty wakes and an expired-deadline fallback
avoid indefinite postponement. Native Noise requests the next body frame after
the previous DATA handoff, supplying the reset boundary. Outer Hyper/direct
consumers do not expose actual write completion. OS entropy differs from Go's
math/rand/v2 sequence. Initial frame remains immediate; nonstreaming behavior
is unchanged. Existing two paused-time advances were source-adjusted, not run.

Pinned source SHA-256:
- Headscale v0.29.5 hscontrol/types/change/change.go:
  23f5812aeee446d15f5e2624ddb9e25171bb3ba4ff40c82feaa9e183c2d2dcba
- hscontrol/mapper/mapper.go:
  ec191db53afd7a906aaf015bf32c372c75c0b110aa784e5277e45269d2496534
- hscontrol/mapper/batcher.go:
  341d3824c49da1180b37e20e7c737ca5fe6e4aae8fe57838ab753a06a86c4f4a
- hscontrol/poll.go:
  3590bf1a227f48c2e574e96ef8660889235448025c1f096f0388f1bbf7871b6b
- hscontrol/state/state.go:
  7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01
- hscontrol/grpcv1.go (CheckPolicy constructor warning boundary):
  1bb435c674a64b3a7d1382eddfc9b33d7fb8f646c414709d011508d0a2e883c3
- Go 1.26.9 src/time/tick.go:
  c25a5f521f3925d21dedab88e8829cfed90b0fe6283e9c189d30a3f12942ed81
Existing BSD licenses/notices apply. Independent source review/direct rustfmt
only; no tests/builds/Cargo/validators/probes/recapture. Timer/load/flow-control,
concurrent mutation/rekey/reconnect/retirement, custom adapter effects, runtime
feature/process/client/import/restart qualification and all three gates stay open.
# Native non-streaming map completion — 2026-10-18

The native flat Noise map handler returns an empty HTTP 200 after non-streaming
mutation/dispatch, with or without OmitPeers. It bypasses full-map construction
and the keyed compatibility route's peer wait. Existing public handler
signatures and the keyed response contract remain stable. Source-adjusted one
existing flat-route assertion to check the empty body and committed endpoints;
not executed.

Pinned Headscale v0.29.5 source SHA-256:
- hscontrol/noise.go:
  5c277a92d413a8e362b75667d3c6b11faaf6d2438021b4c57a5c0c8264bccbbc
- hscontrol/poll.go:
  3590bf1a227f48c2e574e96ef8660889235448025c1f096f0388f1bbf7871b6b

Existing Headscale BSD license/notice applies. Source/direct rustfmt and peer
review only; no tests/builds/Cargo/validators/probes/client/process qualification.
This section supersedes the earlier unchanged-native-nonstreaming statement.
Three parity gates remain open.

# Native policy byte ownership — 2026-10-18

Additive byte policy constructors/replacement preserve original bytes separately
from valid compilation source. String methods retain their signatures; raw()
returns None for unrepresentable original bytes. Rollback retains old source;
String replacement clears the byte sidecar. File reload uses byte parsing;
gRPC policy retrieval rejects invalid UTF-8 at the upstream marshaling boundary.
Debug output writes original bytes as pinned hscontrol/debug.go does. Native
source selection now follows the fresh-read implementation described below.

HuJSON source/license pins live in headscale-api-acl/UPSTREAM.md. Existing Go
gRPC/protobuf licenses/notices apply to error projection. Source/direct rustfmt
only; no execution/runtime/reload/rollback/feature qualification. Three gates
remain open.

Pinned grpc-go v1.81.1 rpc_util.go SHA-256:
0e605aac7acc465edb8bab64b458729f0f07da8364757cc7ea1392f463578a97
Pinned protobuf-go v1.36.11 internal/impl/codec_field.go SHA-256:
d794d96c2d98db80f7230cebdd8f5b118d6ecd31e08ac445689b239dd110f65a

## Fresh debug source selection — 2026-10-18

Private boxed-future adapters in PolicyStore::Inner read configured native file
or database sources per debug request. Existing admin builders register them;
WireState/public signatures and wire-only dependencies remain unchanged. No
lock is held across I/O and no policy installation occurs. Empty file paths
return empty success; database no-row remains an error while an empty stored
row succeeds. Unsupported mode rejects; unconfigured embedding uses raw bytes
from its store. This supersedes the loaded-snapshot/file-reread source residual.

Pinned Headscale v0.29.5 SHA-256:
- hscontrol/state/debug.go:
  f3a0fe211e7ccb62f47f985b559c82412773d4395b0d59f098b69bfd9fab5316
- hscontrol/debug.go:
  032c61a16ce0da210153d6d430f60fc4bf31345e65586cc9c03329a9b7f5a845
- hscontrol/db/policy.go:
  59aca2ef1a9d8a0187ffd37df1c40ad12ed2a5b63c8f4c7825118a5809950746

Existing Headscale BSD license/notice applies. Source/direct rustfmt only;
runtime/persistence/custom-adapter/feature/process qualification remains pending.
No tests/builds/Cargo/validators/probes/recapture; three parity gates stay open.

# Native initial-map session acquisition — 2026-10-18

Native flat streaming requests use private quiet acquisition before self-map
validation, preserving counters/generation/epoch and cancelling ephemeral GC as
Go Connect does. Both request and connection changes stay deferred until actual
FullSelf-equivalent response construction succeeds; an epoch-validated NodeStore
read protects publication (request first, connection second) from node retirement.
Failure drops the acquired guard through existing grace/disconnect/GC cleanup,
without publishing initial changes or adding a pre-serving ended metric. Public
tracking helpers and keyed compatibility retain immediate publication. No
synchronous state guard crosses an await. This supersedes the native initial
FQDN-before-Connect source approximation.

Pinned Headscale v0.29.5 SHA-256:
- hscontrol/poll.go (Update, Connect, CancelGC, AddNode, then Change):
  3590bf1a227f48c2e574e96ef8660889235448025c1f096f0388f1bbf7871b6b
- hscontrol/mapper/batcher.go (initial generation/error cleanup):
  341d3824c49da1180b37e20e7c737ca5fe6e4aae8fe57838ab753a06a86c4f4a
- hscontrol/mapper/builder.go (WithSelfNode):
  5e63d5d82eb590de006edf5146d75024a57f9b3cbc284f4e1a3eed450bfe0c50
- hscontrol/state/state.go (Connect returns changes):
  7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01

Existing Headscale BSD license/notice applies. Source/direct rustfmt only; no
tests/builds/Cargo/validators/probes/recapture or concurrency/cancellation/GC/
runtime/process/client qualification. All three parity gates stay open.

# Native map shutdown cancellation and drain — 2026-10-18

The original Rust native_shutdown coordinator counts native map requests,
owned map mutations, direct Noise connections and acquired stream cleanup.
Tickets transfer through reconnect grace, LastSeen persistence and offline
publication without a zero-count gap. Shutdown closes GC before taking the
NodeStore writer, marks native work closed, cancels stream flags and waits for
drain while persistence/batcher state remains available. GC scheduling rechecks
closed under its timer lock so close cannot be followed by timer installation.
Noise request tasks select shutdown during input, router, output and capacity
waits; transport teardown offers one nonblocking final control-frame flush.

Pinned Headscale v0.29.5 source SHA-256:
- hscontrol/app.go (schedule cancellation, GC close, batcher close, stream wait):
  381958868e878b30c1f43138808b7cb3daf27c05a3db762ed3d672bf9f779a85
- hscontrol/poll.go (cancellation/deadline, grace and disconnect):
  3590bf1a227f48c2e574e96ef8660889235448025c1f096f0388f1bbf7871b6b
- hscontrol/mapper/batcher.go (Close):
  341d3824c49da1180b37e20e7c737ca5fe6e4aae8fe57838ab753a06a86c4f4a
- hscontrol/mapper/node_conn.go (stopConnection):
  d8d456c39d90fcf9508fc72e75ea48d0f0fe7d11966e1c1b90d600d3f43abec9
- hscontrol/state/state.go (Disconnect):
  7187cc9ce91c69110115bb2a38f8a60afac2b1ec22e418c09ed84689eaa71f01

Existing Headscale BSD license/notice applies to adapted lifecycle behavior.
Separate detached registration/OIDC/admin mutations and custom/keyed/public
paths do not gain a global drain. Final wire delivery is not guaranteed and
persistence drain has no timeout. Independent source reviews/direct rustfmt
only; no execution, cancellation/resource/process/feature qualification or gate
closure. Three parity gates remain open.

## Shutdown before response headers — 2026-10-18

Noise dispatch now explicitly sends INTERNAL_ERROR when native shutdown wins
while awaiting router response. h2 0.4.19's SendResponse -> StreamRef ->
OpaqueStreamRef drop -> maybe_cancel otherwise selects CANCEL before headers.
The poll_reset borrow is scoped to end before the explicit reset. Successful
router responses, peer-reset handling and drain ownership are unchanged.

Pinned Headscale poll.go stopFromBatcher sets the immediate write deadline;
its selected golang.org/x/net v0.56.0 http2/server.go SetWriteDeadline and
onWriteTimeout send ErrCodeInternal. Source SHA-256:
- x/net v0.56.0 http2/server.go:
  cf07329cd7d5d95909a5404f3b29f10f4252189012b98ad4c8fdbfca384cb9d1
- h2 v0.4.19 src/server.rs:
  6c288263c09ea51eabf87332a990547a8212bfd9d9301e5540d51cbe56b27d86
- h2 v0.4.19 src/proto/streams/streams.rs:
  d2f866b385ea8107ecb4a56e0089523abeabb6a5dc8e107c0a6c3eeb26955290

The change uses the existing h2 reset API; no h2 source was copied. Existing
Headscale BSD provenance applies to the adapted stop behavior. Independent
source review/direct rustfmt only; no tests/builds/Cargo/validators/probes or
wire-delivery/cancellation/shutdown/process qualification. Three gates stay open.

# Native ordinary HTTP shutdown — 2026-10-18

New http_shutdown.rs coordinates debug/main ordinary HTTP with one shared3s
deadline. The additive serve_with_shutdown returns the unchanged ServeHandle
plus an opaque control; original public serving and raw TLS signatures and
embedding behavior are preserved. Native plaintext/debug uses HTTP/1. Tracking
closes listener admission first, delays graceful close for StateNew, and applies
Go's strict stored-Unix-second age>5 rule only during the shutdown wait. Expiry
stops waiting without aborting active/fresh-new tasks. Request admission gates
reject late H1 handlers; a first-nonempty-write gate covers initial parser-error
responses without marking empty flushes active. Hyper's default30s header
timeout is retained.

Raw Noise/DERP admission becomes active before handoff. Raw101 remains HTTP
work through successful write+flush, then hijack releases that ticket. Hyper
completion also releases ordinary work even if upgraded IO survives. Weak
registrations retire on completion/drop; snapshot upgrades occur outside the
registry lock. No synchronous lock crosses an await. No new dependency/version
or existing public field type changed; wire-only dependencies remain isolated.

Source SHA-256:
- Go1.26.9 net/http/server.go (Shutdown, StateNew, request admission, Hijack):
  6f344ca40661ce5d31ce7f237dc23c53d4d34fe3043bd5e76bac50e6c97d91cb
- Headscale v0.29.5 hscontrol/app.go (shared3s and shutdown phases):
  381958868e878b30c1f43138808b7cb3daf27c05a3db762ed3d672bf9f779a85
- Tailscale v1.101.0-pre control/controlhttp/controlhttpserver/controlhttpserver.go:
  efbb2e95176cff08f8c528fe67e421edb1ba7dd75d0b8f25693813248be1ea1e
- Hyper1.8.1 src/proto/h1/conn.rs:
  bcd74686394c958ae2bbadd3d9f48dd6570843f5fe3e1ca76f256fe4f3753be8
- Hyper1.8.1 src/proto/h1/dispatch.rs:
  073a2bf94418e2eb2f000c5ffb7f2a95891c616ea3d025b7ebfaaaf7a8234038
- Hyper1.8.1 src/proto/h1/io.rs:
  d83c99b59dc2c672b45eecc83174948ce412589bad63efeff97b4e8972ccb2cd
- Hyper1.8.1 src/server/conn/http1.rs:
  7378c965101c3e316ed5d471921d2f9ff21e92e950a0456fbde859b283d6052f

Existing Go BSD license and updated NOTICE-GO-STDLIB cover adapted shutdown
behavior; no Hyper source was copied. Package/container notice globs already
include these files; package/image execution remains unqualified.

The subsequent ACME ordinary H2 implementation below supplies the negotiated
serving/ALPN gap; full H2 behavior remains incomplete. Headscale's selected
x/crypto v0.53.0 autocert TLSConfig advertises h2/http1/acme-tls.
Its autocert.go SHA-256 is
175d3d5b0dd6278291bb924b55f1c9e6647b24f8e595394e2848dc6f50e07aea.
Finer reused-request malformed-header/write races, body/read/write deadlines,
literal polling/RNG/scheduling, detached durable workers and resources remain
unqualified. Bounded independent source reviews/direct rustfmt only; no tests,
builds/Cargo/validators/probes or client/process/feature qualification. All three
parity gates stay open.

# ACME ordinary TLS HTTP/2 — 2026-10-18

ACME cache/bootstrap builders and the existing renewal call chain now retain
ALPN order h2/http1/acme-tls. A sole acme-tls/1 offer uses the challenge map;
mixed offers use normal certificate selection. HTTP01 configurations retain
an internal empty challenge resolver while keeping their public optional
resolver field None, rejecting sole token offers with no installed token.
Static/self-signed H1 and remote gRPC H2 builders remain separate.

raw_tls branches negotiated h2 immediately after TLS, before the H1 peek path,
into a private Hyper HTTP2 Router driver with ConnectInfo and TlsRequest. Native
tracking marks ALPN-selected H2 active before preface, bypasses H1 admission,
and keeps active tasks alive after the ordinary HTTP shutdown wait. A private
input observer reports the first24readbytes to an independent outer10s timer;
the budget also runs during blocked initial SETTINGS writes and ends after
the observation. It neither reads ahead of Hyper nor imposes a connection-wide
request timeout. Hyper http2 is explicitly activated for feature isolation;
no dependency version or public field/signature changes. Two existing ALPN
assertions were source-updated and remain unexecuted.

Source SHA-256:
- x/crypto v0.53.0 acme/autocert/autocert.go (ALPN228, selection253+, sole321):
  175d3d5b0dd6278291bb924b55f1c9e6647b24f8e595394e2848dc6f50e07aea
- rustls v0.23.46 src/server/hs.rs (server ALPN preference99–108):
  b1ed14e5e36ee46bfb843b86af58efda01cdaa71a7f25a2f647da21f52529f91
- Go1.26.9 net/http/h2_bundle.go (ordinary TLS H2, distinct from Noise x/net):
  a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e
- h2 v0.4.19 src/proto/connection.rs (two-stage GOAWAY629–650):
  e7b371737a3648fee2a0746deab015f99765cd9ec2cb2428ea536b803f097d3c
Existing Headscale app.go and Hyper source pins apply. Go BSD license and
updated NOTICE-GO-STDLIB cover adapted ALPN/preface behavior; existing Hyper
APIs are used, with no Hyper source copied.

Confirmed remaining source differences: h2 flushes server SETTINGS before
reading the preface, so a valid buffered preface behind blocked server output
can still time out differently from Go's concurrent reader/writer. Standard
Hyper graceful uses MAX-ID/PING then final GOAWAY, while Go sends current-ID
immediately. Go's idle ConnState, one-second post-drain and further first
SETTINGS/idle/per-stream timeout paths are not reproduced here. ACME SNI,
HostPolicy/IDNA and broader TLS/HTTP diagnostics also remain separate. These
are source gaps, not claims of wire equivalence. Bounded independent source
reviews/direct rustfmt only; no tests/builds/Cargo/validators/probes or
handshake/frame/renewal/client/process/native/wire-only/resource/package
qualification. Three parity gates stay open.

# Ordinary HTTP/2 initial-frame deadline — 2026-10-18

The private observer starts a two-second initial-frame budget at the observed
preface completion instant and tracks the nine-byte header plus its declared
payload. Partial input, same-read preface/frame and empty payloads are covered in
source without allocation or read-ahead. The outer timer runs independently of
output backpressure; only completed SETTINGS input disables this initial phase.

Pinned Go1.26.9 h2_bundle.go4112/5035/5066 supplies the timeout and completion
ordering; its existing SHA-256 above applies. The selected h2 0.4.19 source is
vendored with a default-off server-first-SETTINGS guard, enabled only by API
full. Decoded non-SETTINGS, including unknown/PRIORITY frames, reject through
existing PROTOCOL_ERROR handling before dispatch. Decoder errors precede the
guard; SETTINGS ACK retains normal validation. A partial first HEADERS block
cannot disable the timer while awaiting CONTINUATION. Clients and feature-off
codecs retain their behavior. Root workspace patch/exclude and the existing
lock package source are updated without a version change. vendor/h2/UPSTREAM.md
records original source hashes/VCS provenance; its MIT license and the Go BSD
notice are retained, including image license copies.

Go may use the offending first frame's ID in error GOAWAY; h2 retains its
last-processed ID. Processed versus received-frame timing, initial read/write
ordering, shutdown GOAWAY, idle/post-drain/per-stream behavior remain separate.
Full consumers outside the patched workspace need the vendored source; the
known wire-only profile does not activate this feature. No tests/builds/Cargo,
validators/probes or runtime/resource/package/embedding qualification; direct
rustfmt and independent source review only. All three gates stay open.

# ACME hostname policy and cache identity — 2026-10-18

Native ACME cache/bootstrap builders bind an immutable normalized configured
host policy. Ordinary resolve checks nonempty/multi-component SNI, Lookup
normalization and exact whitelist before returning the default certificate.
Sole-token requests normalize their challenge key and bypass ordinary policy.
Bound challenge set/clear/has operations normalize identically; TLSALPN renewal
retains the resolver and HTTP01 rebuilds a bound configuration. Public unbound
constructors, non-full and non-ACME profiles retain their behavior.

The additive full-only autocert_cache_hostname helper is shared with the CLI:
Lookup then one final-dot trim for certificate disk keys, ACME DNS identifiers,
TLSALPN challenge SANs/map/cleanup keys. Policy comparison retains the dot;
Rust-specific account filenames are unchanged. The optional direct idna1.1.0
dependency reuses the locked package, with UTS46 nontransitional STD3/hyphen/
joiner/bidi checks and DNS-length-ignore. No version resolution was run.

Source SHA-256:
- x/crypto0.53 autocert.go (HostWhitelist75, GetCertificate250, cache key297):
  175d3d5b0dd6278291bb924b55f1c9e6647b24f8e595394e2848dc6f50e07aea
- x/crypto0.53 autocert/cache.go:
  b0350eeeac88823cb2c6558e710fac345379f7eee308ff661f1e68f05bee93a2
- x/net0.56 idna/idna.go:
  c5aeb4b73731634a6f88502afd61d6fc30c391ab3cdfc170596375f039f6b06c
- x/net0.56 idna/tables15.0.0.go (!go1.27):
  79fb7af83a29255478a5e56fdc8d176276ccdb4d1ff1b1459646cbf8d52cc5f3
- locked idna1.1.0 src/uts46.rs:
  9726647c01f315215eca25b7cb706929ff829269d4143de06b4f4718538b6640
- locked icu_normalizer_data2.1.1 README.md (CLDR48/ICU78):
  54bd0542b605a252c6542cb5bc461e9786190c382d730ca0738e42c3c3335a24

Go selects Unicode15 while the Rust adapter uses newer ICU data. rustls validates
and lowercases wire SNI before resolve; raw Unicode SNI and TLS alert/error
fidelity remain different. Invalid configured names can fail eager CLI cache/
issuance; Go ignores invalid whitelist entries and issues lazily. API loading
retains its earlier invalid-name fallback with an ordinary-denying bound policy.
RSA/token disk variants, cached certificate/name validation and broader ACME
lifecycle remain unqualified. Go BSD attribution is in NOTICE-GO-STDLIB.
Independent source reviews/direct rustfmt only; no tests/builds/Cargo/probes or
handshake/renewal/process/feature/package qualification. Three gates stay open.

# HTTP/2 server limits — 2026-10-18

Ordinary ACME H2 explicitly sets 250 streams, a1MiB frame, 1MiB stream/connection
receive windows and 1MiB+320 header-list bytes. Noise likewise sets selected
x/net's 1MiB frame/windows and4096 header table in addition to its existing
matching stream/header limits. Hyper's selected defaults were200 streams and
16KiB frame/header limits; direct h2 Noise defaults had65535 receive windows
and a16KiB frame. Extended CONNECT stays disabled, matching the Go default.

Source SHA-256 (existing bundled Go pin also applies):
- x/net0.56 http2/config.go (configFromServer47, defaults100, headeradjust120):
  d167984b5523fecaf2b99b626c7a4be2d7fc2268b6719b01913263cb80ca4d5a
- Headscale0.29.5 hscontrol/noise.go (BaseConfig210, empty http2.Server214):
  5c277a92d413a8e362b75667d3c6b11faaf6d2438021b4c57a5c0c8264bccbbc
- Hyper1.8.1 src/proto/h2/server.rs (defaults36–74, builder132):
  10a9deb6729f4cdca57222234783447c823b6d73669147d0a7d1297caf7f6683
- Hyper1.8.1 src/server/conn/http2.rs (selected public setters):
  6bebea3f057d7c33fa55522b9923dceb361ebbb416a98262bec1dab847358171

Configured values match the selected defaults in source; literal SETTINGS
order/presence, flow-control replenishment, decoder behavior and resource use
are unqualified. No public APIs or dependency versions changed. Independent
source review/direct rustfmt only; no tests/builds/Cargo, frame/process/client/
wire-only/package qualification. All three gates stay open.

# HTTP/2 GOAWAY identity and native graceful selection — 2026-10-18

The private first-SETTINGS rejection side channel carries only successfully
decoded offending frame IDs from codec to connection error handling. The
existing error GOAWAY takes that ID, clamped to a previous advertised ceiling;
decoder failures acquire no invented context. Public error types are unchanged.

The new default-off go-server-graceful-current-id feature activates only through
API full. A private highest decoded odd HEADERS counter advances before stream
concurrency/refusal. Graceful shutdown queues current-ID NO_ERROR through the
existing stream-preserving go_away route, skips MAX-ID/PING and drops higher new
stream frames; DATA retains existing connection-credit accounting. Idle closure
keeps the advertised ID after refused streams. Client/feature-off paths retain
upstream behavior. The otherwise-unused ping_shutdown helper is feature gated.

Source: Go1.26.9 h2_bundle.go5505–5585/5640/5663/6118 and selected x/net0.56
http2/server.go, with existing hashes above. Selected original h2 connection.rs
SHA-256 is e7b371737a3648fee2a0746deab015f99765cd9ec2cb2428ea536b803f097d3c.
Local files are recorded in vendor/h2/UPSTREAM.md; original MIT and adapted Go
BSD attribution remain included. No versions or lock dependency edges changed
for this feature addition.

This closes the decoded-first-kind offending-ID and MAX/PING selection gaps
in source. General decoder-stage maximum IDs/error phases, prior-GOAWAY clamp
behavior, Go30s idle ConnState and1s after-flush/stream-drain close delay,
preface IO ordering, processed/received timing and per-stream deadlines remain
incomplete or unqualified. Independent source/peer review/direct rustfmt only;
no tests/builds/Cargo/validators/probes, frame/client/process/embedding/package
qualification or gate closure.

# Legacy ACME ACE labels — 2026-10-18

The private acme_hostname/punycode.rs ports selected x/net0.56 Punycode
decode/encode arithmetic: checked int32 multiply-add, bias adaptation, empty
and delimiter-ending returns,1024-rune insertion bound. Raw ASCII ACE labels
are case folded as Go premapping does, decoded, validated with an exact
Unicode round-trip identity guard, reencoded if non-ASCII and passed through
whole-domain validation. This supplies pre-Unicode16 all-basic/empty ACE
acceptance while refusing decoded case/width/NFC repair. Empty labels and root
dot placement are retained; non-ACE fast paths remain with the adapter.

Selected x/net0.56 idna/punycode.go SHA-256:
3e65858245f1a7d32e225aba714a305d3ef34496acb839956a7b15d1c7a34eb7
Existing idna.go/tables15/adapter source pins apply. Original Go BSD attribution
is retained in NOTICE-GO-STDLIB and LICENSE-GO-STDLIB. No dependency version,
manifest, CLI or public API changes for this step.

Full selected Go15 mapping/status/joiner/bidi data and stream-safe NFC remain
unimplemented; raw compatibility-mapped/non-ASCII ACE prefixes and the final
adapter's input/output bounds retain qualification. The Rust adapter's2000-byte
Punycode input limit can still differ from Go's insertion bound even though the
private decoder itself uses the selected arithmetic. Raw Unicode SNI, eager
issuance, RSA/token disk variants and certificate verification remain separate.
Independent source/peer review/direct rustfmt only; no tests/builds/Cargo,
hostname/handshake/process/feature or resource qualification. All three gates
remain open.


# Native raw ClientHello SNI — 2026-10-18

The exact selected rustls0.23.46 source is now vendored. Its default-off
`go-server-client-hello` feature is enabled by API full, with per-Acceptor
selection only on native certificate-provider handshakes. Static, Tonic,
client, unbound and feature-off connections retain strict parsing defaults.
A private Reader mode follows subreaders and HRR messages. Native SNI validates
full nonempty U16 framing, skips unknown name types, rejects duplicate hostname
entries/trailing ASCII dots and retains original hostname/extension bytes.
Original extension bytes survive transcript re-encoding; HRR uses exact raw
identity. Unicode/IP names receive the normal SNI acknowledgement. Typed DNS
access remains a strict projection; raw storage uses bounded owned copies.

AcmeHandshakeRequest and the bound challenge resolver use raw bytes before
the typed DNS fallback. Missing-name/component-count checks precede UTF-8/IDNA,
so malformed raw bytes keep selected Go hostname diagnostic phases. Native
TLS1.2/1.3 session tags bind raw identity and mode without altering default
ticket bytes; cross-name/default-native resumption is refused. Go tickets do
not bind serverName themselves: this intentionally preserves Rustls protection
and is not Go session-format equivalence.

Root patch/exclude and the exact lock package source were updated without
version/resolution/dependency-list changes. vendor/rustls/UPSTREAM.md records
VCS, original package/Go hashes and remaining boundaries. Original rustls
licenses remain, with Go BSD terms/adaptation notice inside the package;
manifest SPDX expressions and both image LICENSE* copies include them. Full
external embedders need the same vendored patch; wire-only does not opt in.
Missing signature-extension and other version/cipher/extension/alert phases,
X.509/provider/session/resource behavior remain separate source/qualification
boundaries. Independent source review/direct rustfmt only; no tests/builds,
handshake/HRR/PSK/session/feature/package/process qualification or gate closure.

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
alert sequencing, X.509/provider/session formats and resources remain source
or qualification boundaries. Independent source reviews/direct rustfmt only;
no builds/tests, handshake/HRR/PSK/client/feature/package/process qualification
or acceptance gate closure.

The API bridge implementation for this source batch is
src/tailscale_wire/raw_tls/acme_handshake.rs. The selected tokio-rustls0.26.4
TlsAcceptor::accept_with constructs ServerConnection before its closure and
performs no transport I/O before that closure. That documented source behavior
supports replacing its fresh state with the prepared original connection;
there is no tokio-rustls source patch. Original server.rs SHA-256:
8aae1fb57ff7563d10b7b3416da5d4fc7a9edfe3d2f4406bd1faecf240ee3e5c. This is a source premise, not executed handoff evidence.

Native phase integration local source SHA-256 — 2026-10-18:

- src/tailscale_wire/raw_tls.rs: bc2b6a503c6a0104a498d8ca9125522113e566c2a69241d8ed8f67fa210eda43
- src/tailscale_wire/raw_tls/acme_handshake.rs: d6afde525322ec6a32184ab48ec30d77cf44b8e1baad5fcf21a99b6ec5d88819
- src/tailscale_wire/tls.rs: 62a541b024dcf51ba7ee89902c11d0f7996f6ed23fabee4171f2fc271d419a90

## Native signer continuation follow-up — 2026-10-18

The existing API native acceptor now reaches the selected provider's owned
signer via Rustls's explicit native continuation. TLS 1.3 selects once before
ServerHello and reuses the signer for CertificateVerify. TLS 1.2 native ECDSA
can select the client-offered SHA-256/384/512 independently of curve, using the
exact selected aws-lc-rs1.18.2 optional adapter; RSA filters Go modulus-byte
minima. Native signing failures retain the preceding flight before alerts.
Default provider paths remain separate. No API public field/signature, core/DB
backedge or dependency version was changed by this signer follow-up.

Vendor rustls and aws-lc-rs UPSTREAM.md record exact source scope, terms and
remaining malformed decoder/HRR/session/signing/backend boundaries. This adds
source implementation and review only; no builds/tests, handshake/CA/client,
feature/wire-only/package/container/process or security qualification. Three
replacement gates remain open.

Native AWS TLS1.3 RSA-PSS failure alert follow-up — 2026-10-18:
Only after actual signing fails, the owned signer exposes Go's classification
using the validated modulus bit length divided by8 (floor), independent of the
ceiling-byte selection filter. The original partial flight is published before
HandshakeFailure for that small-PSS edge; other actual signing failures remain
InternalError. Default/custom hooks retain their fallback. Rustls/aws-lc-rs
provenance records the safe existing EVP bit-count chain and opt-in method.
No runtime or feature/backend/handshake qualification occurred.

## Grouped remaining-audit application changes — 2026-10-18

B1–B5 implement selected registration Followup precedence/path grammar, Go URL
provider-identifier rendering, mailbox admission preserving accepted claim text,
Unicode15 Letter/Nd byte-first username admission, first-value raw callback
queries, legacy JSON DNS records, Go resolver/query encoding and nil Hostinfo.
Shared private go_url has no HTTP/full/DB dependency. Existing public APIs and
wire-only boundary are preserved. Linux Inotify/AsyncFd watches path+parent,
rearms replacement watches and complements content polling independent of
mtime; non-Linux event latency remains partial. Existing locked nix0.29 adds
inotify to its feature selection; no versions/resolution changed.

F17 adds native control/Noise/raw-upgrade events and a private log-only RemoteAddr
bridge, separate from ConnectInfo auth/debug behavior. Selected realclientip
last-value/reverse-XFF, mapped-address/range and Unicode zone handling are
retained. Raw hijack guards record Noise101/DERPfast0 with zero counted bytes.
Merged gateway/HTTP01 routes are outside the control wrapper. Ordinary spawned
upgrade completion, physical writes, raw invalid-byte strings and broad runtime
phases remain incomplete or unqualified. OIDC/Noise resource bounds and all S01–S06
scope decisions remain. X01 guards optional GUI cookie-session JSON mutations
with the existing HMAC CSRF token header; native gateway topology is unchanged.

Independent source peers and direct rustfmt only; no execution, package/feature,
client/process/database/recovery/advisory or security qualification. All three
acceptance gates remain open. Prior Go/Headscale BSD licenses/notices remain;
realclientip's source license is 0BSD with no attribution requirement.

Selected pinned source SHA-256:

- Headscale0.29.5 hscontrol/auth.go: b54d2e7541e24eeeb35df63ae4a6c5718b42d208e63e5786e3bdc5727755a3dd
- Headscale0.29.5 hscontrol/oidc.go: 88484e1fbbf5589433d858643ff52f630acc76d8a2ac94779f03db8cc5a7a591
- Headscale0.29.5 hscontrol/types/users.go: 36bc0f562c507336d3a2a309c94718ec3baa2db2c3432180596556ab512d69dd
- Headscale0.29.5 hscontrol/util/dns.go: 7303e7bd4ef425f45323160d70ac8a2e3b06d13cd7b3ab8d80f1e6ddd999fda6
- Headscale0.29.5 hscontrol/dns/extrarecords.go: b104cda62072befbfb1a9f27d42e1ed77535decea02c8eb2159a561831b60e9a
- Headscale0.29.5 hscontrol/types/config.go: d27177817d7477525f78cd71fd98574aeb631bd6df39503858015c95768ea788
- Headscale0.29.5 hscontrol/mapper/mapper.go: ec191db53afd7a906aaf015bf32c372c75c0b110aa784e5277e45269d2496534
- Headscale0.29.5 hscontrol/app.go: 381958868e878b30c1f43138808b7cb3daf27c05a3db762ed3d672bf9f779a85
- Headscale0.29.5 hscontrol/realip.go: ba710450a46a7656c8508d86fa1ef440b9e5e300e20fdead7190c133a8a927be
- Go1.26.9 net/url/url.go: 7bec001746c2cd512275c7269bc293f3d36cb004ddb193d736e02e361a3778aa
- Go1.26.9 net/mail/message.go: 75c12f4394c36bbc1efa7dae6bc8da74b77507cd4967197247921b97ed30acd8
- Go1.26.9 mime/encodedword.go: 394cfb382ac4b68806b067757f6fa77ebb009392eab1d9d7a12db8e03fda838a
- Go1.26.9 unicode/tables.go: 6a88d48746c4b2c471cc04ae40559694b734770212e6f5ea5f1962adb0c0bdb1
- Go1.26.9 internal/godebug/godebug.go: cd492e76ae63872ac4310fc09b2e097229588dbf114d14d713be3f027b0233c8
- Go1.26.9 internal/bisect/bisect.go: 978d518986ba6867f5f96356531f35bfa59b865fbb363b98eb9052e862a2160c
- Go1.26.9 net/ipsock.go: 1d5cc127665695ab1351a96b015ceeddcc5adcbed91f35af0a6c6cd1552d846b
- Go1.26.9 net/ip.go: 7e26071410dd7265f58c27e9a13820b9e42b13187529db3f4a43eb48f94d1436
- realclientip-go1.0.0 realclientip.go: 90fe43767a80eabde4835e307c4ea15b4c036cfcebf2789a119d48c47f12bee0

Local grouped source SHA-256:

- headscale-api/Cargo.toml: 49693aee34a4c7f44203605cb64432525e9c9def016b86e6239f009627d87ccf
- headscale-api/src/lib.rs: daeb6cc293d74cee545af71ab734a71ae65286382cc277aefc85061dbd5c103d
- headscale-api/src/go_url.rs: 27a93144de66d38e05d22ec14d68e07719734e54d2bd2cb4654dd142f94c4d83
- headscale-api/src/go_url/godebug.rs: 43cc760c10d2cf398478c51fa4623f1d0e99a332a4353994f8676761b3426427
- headscale-api/src/oidc.rs: b5cc8f7cf15675913a5d76af29f0309c45d16cdd5b1f15b8bd3ea8c3855a4896
- headscale-api/src/oidc/form.rs: c1bfdca8bd1cd48a64267a7fbc3edf6dcb14bcf4c4279748a64cacc092b1cc3c
- headscale-api/src/oidc/mailbox.rs: f69140cc3f26bd787f07617426f7390c244f7cab847bd9fb45be0db550d28dca
- headscale-api/src/oidc/username.rs: 3dd90537f582b620eba666a3cb74f032e3f549cf76af93041d86a4eaa44ed1ce
- headscale-api/src/dns.rs: bd083fcda2a2ffd764e07a1c0bf25a1c4743a5cc362896cea449bada931eb32e
- headscale-api/src/dns/watch.rs: 5c9193b4747e79d07d6f5c14457dc3f0c1c94e97a34411ebd0ac2a305ea8a0df
- headscale-api/src/tailscale_wire/register.rs: 2ea312f11b5baa84740540abffde8f84acc09f9ea18d7fda51a2a9ac8a06a400
- headscale-api/src/tailscale_wire/map.rs: c1436c8f16134485df44c429eaabccbb0c1ae008c135a2f4966a861f691eb1d8
- headscale-api/src/tailscale_wire/mod.rs: 1b0b493d527594f66c9f9d32461aa461827c9fd0b94e50cec38b53e0936ba237
- headscale-api/src/tailscale_wire/serve.rs: 3e64ab14fe297359f4d754c514eaafc2cb95d8bfaec6621494993c0cfc0d3e26
- headscale-api/src/tailscale_wire/raw_tls.rs: 91090a19d745b7da72f7f9a072c38550ee2b360eea449cd74172269da5b8b578
- headscale-api/src/tailscale_wire/noise.rs: 18ab58c08ed04c82425f9211cfb413f844429f52eac0c0cdeeb9360c38f0268e
- headscale-api/src/tailscale_wire/request_log.rs: de1c38f806ec98507a94eea6553b0ee39549b4a85fd2d65ee86d56ce5b08916d
- headscale-api/src/admin/mod.rs: d86015b5d530be2e15d945901c899e97207be84291b8a4c442e17f6578c5c8b5

## Remaining-audit native DERP, events and logger ownership follow-up — 2026-10-18

This supersedes the preceding batch's named native DERP integer/nil-node and
merged-route/spawned-upgrade logging source gaps. New NativeDerpMap retains signed
64-bit IDs/ports, optional node slices and null nodes independently of public
wire structs. A single private DerpMapStore lock owns canonical and compatibility
views; native map frames, refreshed frames, debug maps/config and bootstrap DNS
use a captured canonical owner. Public new/set preserve original behavior and
clear native ownership. The public snapshot/summary types retain their original
narrow contract; they are not native identity storage. Signed embedded-region
metadata belongs to the canonical owner and overrides only its numeric config
JSON span, preserving existing struct declaration/pretty order.

Nonfinite YAML values remain typed until native response encoding rejects them;
error wording is local. Native bootstrap/debug return empty 500 on null pointer inputs, matching the
selected Go recoverer outcome without a Rust panic. Exact panic/error logging
and broader malformed-input/error boundaries remain explicit. No
public struct fields/signatures or deprecated core source were changed.

The native merged listener now owns one request event inside trusted-proxy
processing. A private extension suppresses inner duplicates; a response scope
and nonclone upgrade guards defer completion until body and spawned Noise/DERP
HTTP/WebSocket tasks finish. Raw upgrade guards remain. Dedicated HTTP01 stays
outside chi-equivalent logging, matching selected Go app.go1080. Body poll counts
are not proof of every successful-write/error byte count or physical-I/O phase.
Invalid-byte logging and broader cancellation/runtime details remain qualified.

F07 now adds safe kqueue/AsyncFd file+parent event ownership on nix-supported
BSD/Apple targets, with close-on-exec, vnode identity/reopen recovery and content
polling independent of mtime. Linux Inotify remains selected there. Other targets
retain content-poll fallback. Already-locked nix adds event/fs features only;
no package version or dependency resolution was changed. Event coalescing,
backoff/timing and resource behavior remain unexecuted.

Independent bounded source peers and direct rustfmt only. No tests/builds/Cargo,
validators/probes, new fixtures or fresh advisory/security evidence. Three
acceptance gates remain open.

Selected pinned source SHA-256:

- Headscale0.29.5 hscontrol/derp/derp.go: baaa75ae8aaa504ace47003b1f792c7af9d610eda6ae5b5b2079dabe9000b4d5
- Headscale0.29.5 hscontrol/derp/server/derp_server.go: 291e6e747512ac490956cb81424094651f0bc761925ab370bad997abe489dac3
- Headscale0.29.5 hscontrol/app.go: 381958868e878b30c1f43138808b7cb3daf27c05a3db762ed3d672bf9f779a85
- Tailscale1.101.0-pre tailcfg/derpmap.go: 860884479d72131dbbbdde892e5cbe3bbb7f59c79ac8165c3eb05bc249552e03
- chi5.4.0 middleware/logger.go: 40e7b7b01eb0363aad9930d3764880e3cf6f1f8aed6ad3fd918866ec34602729
- chi5.4.0 middleware/wrap_writer.go: 7b6ed24d3d5bfd362e00851d117e74273b02597a1d9e9eb243cbf7aae22597c8

Final parallel follow-up local source SHA-256 — 2026-10-18:

- headscale-api/Cargo.toml: af4316e734b05829e9a7dec20d410e4c5e150ed46c152ddf341dc1ae4d4227f9
- headscale-api/src/dns.rs: 2eca541544e1df4a479b8042ac48dc931618c0f2fff8cf488ad4eb62a3961f4b
- headscale-api/src/dns/watch.rs: 269ff41e0d61f28fee861ebcf937984ad73f7e1934df09183ac35b2190d8856d
- headscale-api/src/tailscale_wire/native_derp.rs: 5a961364ae41b41dc38bcb1298111877cd879dc09d04a1f42233a34743f477e3
- headscale-api/src/tailscale_wire/mod.rs: a60c5b83b1124308352a85008a857f895db94059228191b76ff3c2d2bc64e7c4
- headscale-api/src/tailscale_wire/map.rs: 9f6b695bae98883f03e68939b6dc7a3bc547c5f42d08d8684cc31a011623f04d
- headscale-api/src/tailscale_wire/map_json.rs: 9d5e2477d5bcc02467f4d63a03740b992e43661ca4ed9f0dcd2a4b5a167fe240
- headscale-api/src/tailscale_wire/basic_handlers.rs: de7ed1c2819214f938074f946e979ebb75893e79234b3fa6548e4bf4d305b20b
- headscale-api/src/tailscale_wire/serve.rs: 2c72cebfd19dabd2fc41618ffb5cb1c16ddfbf3b3aa0aff875a21ea9b0c0a1ac
- headscale-api/src/tailscale_wire/noise.rs: 5e309c2da54e4d0dae8cbbf41fa225c0636a1cebc8fcb8a1e901df0c3b35be01
- headscale-api/src/tailscale_wire/derp.rs: 7fca14f30ce3182049906654dd3f6829841534eb747c9c52c894d43300703700
- headscale-api/src/tailscale_wire/request_log.rs: 585c688eca0b38d5c13ae62142d1aaabce1ae3a316677deff88e3093a0c59e76

Diagnostic consumer follow-up: native /debug/derp JSON/text now use private
wide summaries; configured is true for an existing empty native owner. Native
region counts feed expvar/metrics/overview. Null region/node inputs return the
selected recovered empty500 status; no Rust panic is introduced. Text output
retains deterministic signed order rather than Go map iteration order. Public
summary types and projection-mode helpers retain their original shape. Final
independent source peer passed; no execution.

- Headscale0.29.5 hscontrol/debug.go: 032c61a16ce0da210153d6d430f60fc4bf31345e65586cc9c03329a9b7f5a845

- Headscale0.29.5 hscontrol/state/debug.go: f3a0fe211e7ccb62f47f985b559c82412773d4395b0d59f098b69bfd9fab5316

## Native DERP encoding and Android event follow-up — 2026-10-18

Native DERP nonfinite errors now retain Go floatEncoder text and declaration/
lexical-map traversal order. Native-only debug DERP/config uses the existing Go
compact/HTML/indent encoder, preserving config declaration order and exact wide
ServerRegionID replacement. The ordinary public projection paths are unchanged.
The already-locked nix Linux Inotify backend now also selects Android, matching
its supported platform export. No runtime/platform qualification was performed.
Go ResponseWriter.Write returns an application write count, potentially buffered;
current body-poll counters and physical socket bytes do not establish equivalence.

Selected Go1.26.9 encoding/json/encode.go SHA-256:
4012d78aa8236f3067a6330ddf2f719c7e59b262fcf4fff5e51b4abd1ccba235

Local source SHA-256 for this follow-up:

- headscale-api/src/dns.rs: e5a073ec6de52a11daa7d34bf4d5b2807a7d8762f40d7ba5ff9ce4b7b03bd575
- headscale-api/src/dns/watch.rs: 5f0cacb74742ce848fbe84fc22e83e8fda1ff45397a8a35a66a9ad5731e84d72
- headscale-api/src/tailscale_wire/native_derp.rs: ad74763ff271d2675cd17633deafc0d1bde9ed963ce280d443a6479aec024aeb
- headscale-api/src/tailscale_wire/basic_handlers.rs: fb3d855ce2b7b7c128868bd1615addd30b4fba7e88f98603035f69b003d384d5

## Native method admission follow-up — 2026-10-18

Private native_methods.rs follows selected chi5.4 methodMap and empty405
Header.Add(Allow) behavior before invoking GET handlers. A native-only outer
finalizer removes Axum's synthesized Allow for unsupported method tokens. The
root is explicit GET; native unknown paths use Go NotFound body/headers and HEAD
suppression. DERP probe/bootstrap mounting follows native server enablement.
Embedding routers retain their existing routes/fallback/implicit HEAD behavior.
The public options and API dependency boundary are unchanged. Custom overlapping
native extra routes now take precedence over this fallback-service wrapper;
production extra routes have disjoint paths. Escaped-path/backend framing,
physical execution and ResponseWriter.Write byte-return semantics remain
unqualified. Source peers passed; no builds/tests.

Original chi MIT terms are retained in LICENSE-GO-CHI/NOTICE-GO-CHI; original
Go BSD terms remain retained. Selected chi5.4 source SHA-256:

- mux.go: cc44c2d620e6306b16d6d80f5f6c70f02b5814b357a4f5823372818f355ae67d
- tree.go: f4b12b63b662fb8e36658172b36b35705cfb24eefae0665635f4fbd52e64fb79
- LICENSE: a2d51b7515acfaff2f7a88688650f2fc4fd99561383e72bba2305e3db59a1647

Local source SHA-256:

- headscale-api/src/tailscale_wire/mod.rs: 7b82729244ad0d3dabfeb4aa9ee8dd0bff16ff320991546f9bbd7f007ebac0c0
- headscale-api/src/tailscale_wire/native_methods.rs: 935d6fa5cf03a8d252375173de2a7386036ff056096a08f94eca0c2da15e6860
- headscale-api/LICENSE-GO-CHI: a2d51b7515acfaff2f7a88688650f2fc4fd99561383e72bba2305e3db59a1647
- headscale-api/NOTICE-GO-CHI: e8d0d43b0197f6081999e5332a534a37f63def2017caf0f625e6a69fcece79d4

## Authorized root transport dependency rebases — 2026-10-18

The root native profile now resolves locally patched http1.5.0, h2 0.4.20,
Hyper1.12.0, Hyper-util0.1.21 and Hyper-rustls0.27.10. Each package retains its
original licenses, exact new source inputs and a complete local source delta.
Default/native API isolation and private protocol adaptations are reconciled
with upstream channel/decoder/flow-control/idle changes through source reviews.
This does not establish runtime compatibility, CA/security or replacement parity.
Wire-only consumers remain a distinct qualification boundary, and standalone
harness workspaces do not inherit root Cargo patches. See the dependency upgrade
report for resolved identities and remaining behavior qualifications.
