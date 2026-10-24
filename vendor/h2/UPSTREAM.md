# h2 0.4.20 native adaptation rebase

This directory now starts from the exact authorized crates.io `h2` 0.4.20 archive, SHA-256 `7d29020232d6aa3fb1daca64c1127cf662cf97f254ae16c18c05b8ab635fc118`. Upstream `.cargo_vcs_info.json` is retained verbatim and identifies commit `b0e890842ac16d3c76836fd4fcc06421acb15fa7`. Upstream source, manifests, archive-supplied tests/examples and original licenses are retained; the registry cache marker is excluded. No tests or fixtures were authored for this rebase.

`LOCAL.patch` records the complete local source/manifest delta against this archive. Go-derived code retains LICENSE-GO and LICENSE-GO-NOTICE and the combined package license metadata.

All prior default-off Go server/client features and hidden runtime selection APIs remain. The rebase retains upstream 0.4.20's reserved-push accounting, adaptive DATA budget, duplicate Content-Length validation on default/server paths, missing response status rejection, shutdown race repair, GOAWAY stream-ID validation, and HPACK Huffman changes. The FrameDecoder refactor carries the native SETTINGS-validation bit inside the decoder while first-frame guards remain on FramedRead. Upstream RecvOutcome::Refused and connection-owned default refusal accounting are preserved. Selected native servers instead enqueue that outcome into their existing independent refusal FIFO, retaining their bounded control queue and prior native refusal policy. The existing native client local-error-reset budget override remains separate. New pop_frame flow checks precede the retained native header/output ownership markers.

Selected native clients instead normalize final response Content-Length according to pinned Go 1.26.9 `net/http/h2_bundle.go:9889-9924`: raw duplicate strings must be identical, the nonempty value is unsigned ASCII decimal within signed 63-bit range without whitespace/signs, invalid/conflicting values are removed, and valid duplicate values collapse to the first. Informational responses return before this interpretation; final HEAD fields are normalized while their independent no-body marker remains intact. This does not replace earlier HPACK/header canonicalization, malformed-header classification, transport diagnostics or representation limits, and is source implementation rather than executed equivalence evidence.

Pinned Go input SHA-256 for this normalization:
- `net/http/h2_bundle.go`: `a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e`
- `strconv/number.go`: `dda43e8c91d95f9dea0c46b2fec6637e5520cae099e40c5965dca0e41bbaab9e`
- `internal/strconv/atoi.go`: `eb5ad640903abe9e8c8b7fbce8dd3487176dbeb43e8b8b4efa6e73ecb5207ddc`

`SOURCE_SHA256SUMS` records the final vendored files, local patch and provenance hashes (excluding itself). The initial implementation records below are historical; their former package pins and statements that no version changed describe those earlier edits. This section and the current archive/inventory supersede those package pin statements. Existing qualification limits remain in force.

Only source comparison, three-way source merging, independent source review and direct rustfmt were used. No tests, builds, Cargo commands, probes, validators, benchmarks or executable parity qualification were run in this rebase lane.

## Current upstream source SHA-256 for adapted files

- `Cargo.toml`: `21f9c0931a0aecb68fd64ba5b3aa2c311055f54c55443fb669833379bb45ed16`
- `Cargo.toml.orig`: `98903ebe8ca104782b455e6d8c1b23d6c0f475db5aeb8db9205b25039f52983b`
- `src/client.rs`: `b82325ff9589700afc92f3bfc561f75bb9d9c0c78289921ca9a54c4d0cbaed8c`
- `src/codec/framed_read.rs`: `f9020eef96af3158f54349e05e3f159b4840281e7ed19d037f8415306271726b`
- `src/codec/framed_write.rs`: `032aab4c8c9108082e915885d0d582871bf4cdd95cd485bdcd7b717087c8ec35`
- `src/codec/mod.rs`: `806fc32706d789f8e48a6867df014d945c438334e981205ff8f43d5b7f8ce0ef`
- `src/error.rs`: `b05dc52f36a29b29b1b3e0705a3f1ecf102a89896e173356f3e5fb1165dd6090`
- `src/frame/headers.rs`: `207d6b1d88c792440dec619e39f5500717d54cac5ae7060fc4ad6f19a6400b30`
- `src/frame/priority.rs`: `9392b7aa2636157024dc645c92d0e450a4d3f7a53bc9de1188d3b61178c2b5fc`
- `src/frame/settings.rs`: `9aed52868a1ddbb5570025edde2e073d3da1291b58d8759bfed7f086d40ef293`
- `src/lib.rs`: `c8680fc4eb13ccb4ce944716042bd33c6554677cf8261c371442f91fbee352e0`
- `src/proto/connection.rs`: `89a31bd0ec294714c0ecda282fdaeed204bb8386768f2689720ffb7b535a0cfa`
- `src/proto/go_away.rs`: `51d467027bc30873fc76166ed731e968a23725e7b106b58ecadcb85044466a5f`
- `src/proto/mod.rs`: `592f8c60d97425946ff62cf694e3f36097a793863fc218fb4357dd440ed377e8`
- `src/proto/ping_pong.rs`: `fabf42b1b1062e361c4d45026e9bfc9c32a02a9074259c71b525e78d2113a148`
- `src/proto/settings.rs`: `0fef5d01aa0233100a0cda9c0b5080a15cfbaab16c42c991933f5ed7db06bf77`
- `src/proto/streams/buffer.rs`: `631aa4360b7b942c3899c6fb7455e682655c3ac099a170d5c3d566af3fec8318`
- `src/proto/streams/counts.rs`: `9c0a1326fe0edf1e0636e1664915ceeb09e762c90fa8184bc6af0ca6ad077449`
- `src/proto/streams/mod.rs`: `79b2b497bed11ea75997a02c8c626ba270e1520273ee677e944475d2fc8e594f`
- `src/proto/streams/prioritize.rs`: `6d6d85ccbd0e7d0a549b9212061dae0386a09d4ac18099e78253047fac442b80`
- `src/proto/streams/recv.rs`: `f8a3d085c88d117f510478c194e7c9375fde89033f0bfead9cc6805d6da3ffab`
- `src/proto/streams/send.rs`: `ee355358b86ea048fd0e64642595e7be6e7f03a39d96745e74503cba2f1b08ef`
- `src/proto/streams/state.rs`: `486b99b293d0f874b72724e1511cb0b11b44b3906ea20eb176fae1821772794d`
- `src/proto/streams/store.rs`: `cbce79b0c680b20a5b98fdd5b886c41caca0c773edb526d11caf4896b55dcff3`
- `src/proto/streams/stream.rs`: `fdf5a6b68fdf64edbbfe522759c1c9f345e72e5eaaf2abd860e357f66399d8ce`
- `src/proto/streams/streams.rs`: `b218674c27db6389adf6766e9b31a509429738e47cfd2a3bcf42cba5dceb8561`
- `src/server.rs`: `a567d950e49e897f844e865b945a748b3bf6226645c2d9c97af214d66118d596`
- `src/share.rs`: `e313c11a24b649d4c9da937fb37e5c2cc7c689c53f6afd2470fd40fd030237c5`

## Historical adaptation record

# Selected h2 source and local Go server behavior

Source: hyperium/h2 v0.4.19, registry VCS commit
`d57d1b852fec9dda6d42d3454502006d52104da8`.
Original MIT terms are retained in LICENSE and registry metadata is retained in
.cargo_vcs_info.json. Go-derived adaptations retain BSD terms in LICENSE-GO and
LICENSE-GO-NOTICE; package metadata records MIT AND BSD-3-Clause. No dependency
version was updated. Existing container LICENSE* globs include both licenses.

Local changes add the default-off `go-server-first-settings` feature in
Cargo.toml and private server/codec wiring in src/server.rs,
src/codec/mod.rs and src/codec/framed_read.rs. Server codecs enable the guard
after the client preface; clients and feature-off codecs retain upstream
behavior. The workspace enables this feature only through headscale-api/full.
Private codec metadata carries the successfully decoded offending frame's ID
through error GOAWAY handling; ordinary decoder errors retain their old context.

The default-off `go-server-graceful-current-id` implementation activates through
API full and requires per-builder native selection. Private changes in src/proto/connection.rs,
src/proto/go_away.rs, src/proto/ping_pong.rs and src/frame/priority.rs select
the highest decoded odd HEADERS ID before concurrency/refusal, queue one
current-ID graceful GOAWAY without MAX/PING, preserve accepted streams, discard
higher new stream frames and retain DATA credit return. Final idle closure
retains the already-advertised ID. Public types/signatures are preserved; those server features leave client paths
unchanged. A separate opt-in client-idle adaptation is described below.

The default-off `go-server-lifecycle` feature enables the graceful implementation
and the already-selected Tokio time feature. Its additive hidden builder setter
`go_native_server(Option<Duration>)` is off by default. Only selected native
server connections create timers; client/default/Tonic builders retain upstream
MAX-ID/PING behavior even when the features are compiled. The vendored Hyper
forwarder selects ordinary HTTP idle30s; direct Noise selects idleNone.

Selected native handshakes poll initial SETTINGS output and the exact 24-byte
preface read independently. Pending output no longer gates that read; the same
codec retains any unwritten bytes when passed to the protocol connection.
Terminal output errors still terminate the handshake. Default/Tonic and
feature-off handshakes retain their flush-before-read path. This follows
Go h2_bundle.go's SETTINGS scheduling before its independent readPreface.
Native steady-state input now also progresses through pending control output.

Per-instance native Settings applies peer parameters on receipt and coalesces
pending ACKs. Private PONG/refusal FIFOs retain replies while output is blocked.
The aggregate newly decoupled queues, including prior single slots, closes
without waiting for a flush when it exceeds 10000. A 32-frame read budget
self-wakes and yields through the stream-output/flush path. These changes are
in proto/connection.rs, settings.rs, ping_pong.rs and streams/{recv,streams}.rs;
default/Tonic/client and feature-off behavior retain upstream readiness gates.
Source: bundled Go processSettings5835ff, PING5712 and queue limit5108. This
does not assert exact Go scheduler ordering/counting of every control class.

Native codecs also select a private raw SETTINGS loader before typed identifier
collapse. It rejects >100 entries and duplicate IDs (including unknown IDs),
using a fixed100-ID stack array. Error ordering follows Go parseSettingsFrame
and processSettings: nonempty ACK FRAME_SIZE, streamID PROTOCOL, modulo6
FRAME_SIZE, first INITIAL_WINDOW_SIZE overflow FLOW_CONTROL, count/duplicates
PROTOCOL, then remaining known values. Default/Tonic/client and feature-off
codecs retain the original loader. New wiring in codec/{mod,framed_read}.rs
and frame/settings.rs is enabled by the native server only after its preface.
Source: bundled Go h2_bundle.go2380/3659/5835, x/net frame.go766/server.go1606.
Pinned x/net frame.go SHA-256:
7087a540c7d8c93b142d0b97b6f3a6b780be48863cbd0cf2187de845743857b7.

Private stream counts hold the optional idle deadline, starting after preface,
stopping at new HEADERS and restarting at final counted-stream close. GOAWAY
close delay starts after actual codec flush, with no pending GOAWAY; NO_ERROR
also requires no protocol streams or buffered send output. Error GOAWAY does
not wait for streams. The one-second timer is polled outside write gates and
closes without an additional blocked flush. Error-drain frames are discarded
with DATA connection credit retained. Native peer GOAWAY receives a current-ID
reply. Pending closure yields to its registered timer, avoiding rearming loops.
Additional local files: src/proto/streams/counts.rs and streams.rs.

An additive hidden `go_stream_timeouts(read, write)` builder setting enables
per-stream deadlines only for selected native servers. Ordinary HTTP selects
30s/30s; Noise and default/Tonic builders select neither. Private stream fields
record write creation/read-conversion deadlines and sticky body-read timeout.
Read expiry drains existing DATA before returning a timeout and discards later
body bytes with connection credit; write expiry queues INTERNAL_ERROR without
the protocol-abuse reset budget. A private generation cache and one earliest
Sleep avoid full store scans on each frame. Changed/due scans include retained
reset entries. Additional local files: src/proto/streams/stream.rs and recv.rs.

The guard follows Go 1.26.9 net/http/h2_bundle.go's first-frame type rule after
frame decoding and before dispatch. Non-SETTINGS frames, including normally
ignored unknown frames, take the existing PROTOCOL_ERROR GOAWAY path. SETTINGS
ACK proceeds to normal validation. Decoder errors precede the type guard and
partial header blocks remain pending. Go BSD attribution/terms are retained in
headscale-api/NOTICE-GO-STDLIB and headscale-api/LICENSE-GO-STDLIB.

Original selected source SHA-256:

- Cargo.toml: 33a920942741aae5d0e746f64fde6acfbeba037c9bb0da436063c728193b0a8f
- src/server.rs: 6c288263c09ea51eabf87332a990547a8212bfd9d9301e5540d51cbe56b27d86
- src/codec/mod.rs: 806fc32706d789f8e48a6867df014d945c438334e981205ff8f43d5b7f8ce0ef
- src/codec/framed_read.rs: 061131d2280ec0903507eb73b675791b79643ec312cefd5b8bf46dbe3b7707d2

This does not qualify complete Go HTTP/2 equivalence. First-frame IDs are
clamped after an earlier GOAWAY to retain h2's nonincreasing-ID invariant.
General decoder errors and HEADERS rejected before dispatch retain maximum-ID
and phase differences. Protocol count-close may precede written END_STREAM;
already-failing GOAWAY decoder phases, response-controller overrides, exact error causes
and other decoder behavior
remain separate boundaries. The outer Noise shutdown still has its independent
best-effort flush/drop path. Full consumers outside this workspace require its vendor
patch; published-package and embedding behavior remain unqualified. Changes
received source review and direct rustfmt only, with no builds/tests or probes.

## Native HTTP/2 client idle lifecycle — 2026-10-18

The default-off go-client-idle feature enables only existing Tokio time support.
A hidden client Builder timeout defaults to None. Selected native handshakes
flush the initial preface/settings/window output before configuring their initial
deadline; default handshakes keep their existing buffering. This client state is
separate from server idle/GOAWAY fields and controls.

Opaque activity handles reserve checked-out/queued requests under the existing
stream mutex. Extension clones share one reservation; admission consumes it
under the same lock as stream creation and disables the timer before waiting on
pending stream capacity. Locally admitted streams are counted separately from
protocol concurrency counts so pending-open streams remain protected. Request
validation/admission failure restores an idle deadline when no active stream
remains, including header conversion failure. Shared closed state prevents reuse
before the dispatcher notices physical closure. Native timeout checks no active
or reserved requests atomically, then terminates without sending GOAWAY. A
separate strict-greater-than wall-clock reuse guard starts with no last-idle
stamp, records it only after final completion, checks it at checkout and again
under admission lock, and clears it before admitting work. It does not mark the
physical connection closed or refresh an expired stamp on rejection.

A per-stream dirty-output set retains ownership of terminal streams whose frames
entered the codec but have not reached a successful native flush checkpoint.
The final pending completion releases only after flush. Clean, fully sent GETs
retire on response EOS without waiting for unrelated output. Default/server
streams do not allocate this state or select these rules.

Remaining concrete source boundaries include conservative flush checkpoints:
internal codec capacity flushes may complete bytes before the native checkpoint,
and later blocked output can delay dirty-stream retirement. Client read/write
progress under backpressure retains lower h2 scheduling differences from Go's
separate goroutines. Pool selection at stream/reservation saturation and Go's
pending-reset accounting are not fully reproduced by this idle-only activity
handle; native reservations protect lifetime without claiming Go's complete
capacity-based connection-selection policy. Closed H2 senders can remain in the bounded idle map until
checkout/eviction; Go's MarkDead/unused-connection retention and separate H2 pool
ownership are not fully implemented. Buffered response-body and reset/error
phases, TLS close notifications/force-close timing, cancellation, wall/monotonic
host-clock behavior and resource/scheduler equivalence remain unqualified.

Source reviews/direct rustfmt only. No build/test, feature/default/server/client,
package/container, process or replacement-parity qualification is established.

## Native client follow-up original source SHA-256

- Cargo.toml: 33a920942741aae5d0e746f64fde6acfbeba037c9bb0da436063c728193b0a8f
- Cargo.toml.orig: 6664ea9dee6a56004dc181d66b498653d9a00587680bf091327f74e6bb83e17e
- src/client.rs: f64c9089838886bb38aa6b2eaf7e10f84a98fbcdf06d6c4df6fae317de03377e
- src/proto/mod.rs: 592f8c60d97425946ff62cf694e3f36097a793863fc218fb4357dd440ed377e8
- src/proto/connection.rs: e7b371737a3648fee2a0746deab015f99765cd9ec2cb2428ea536b803f097d3c
- src/proto/streams/mod.rs: 3f7afa89a19943b1ac56052f64c4e220dbf0e951a4ac74405adbf83ea7050c27
- src/proto/streams/counts.rs: aba319047c01074d9e97afde4999c28e14f0ef21d1d39b7d6c6db4aebc786b79
- src/proto/streams/stream.rs: e31a59444ba7b885040556b89c19b308321e2adeab1cdb2cce720285701d56a0
- src/proto/streams/streams.rs: d2f866b385ea8107ecb4a56e0089523abeabb6a5dc8e107c0a6c3eeb26955290
- src/proto/streams/prioritize.rs: 5eba6fc5c252104676fa76e13fe07459fdbb9bc55df6483b1683fa99ad6fa674

Selected Go1.26.9 native client lifecycle:
- net/http/h2_bundle.go: a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e

Both independent bounded source reviews passed after the failed-admission,
closed-readiness, flush-retirement, feature-import and default-lock repairs.
Only source review and direct rustfmt were performed; no executable evidence.

## Native client capacity and control phases — 2026-10-18

A separate per-builder native-client flag now selects capacity/control state even
when the idle timeout is zero. Ordinary clients and server lifecycle state retain
their prior selection. Atomic availability distinguishes saturation from permanent
unavailability; reservations share stream-state locking with admission. Pending-open
streams remain active for idle ownership while excluded from open-stream capacity.
Native initial capacity is 100, followed by 1000 when the first remote SETTINGS
omits a maximum. Existing h2 allocation of pending stream identifiers supplies the
headroom already represented by Go's next-ID plus pending-request expression.

Private lifecycle observers retain stable connection identity independently of the
transport and notify the pool of closure. Selection and first allocated stream
are tracked separately, matching Go's reused versus next-stream-ID distinctions.
The selected native path also accounts for cancellation resets until any PING ACK,
blocks subsequent reset PING batches until HEADERS/DATA progress, and accepts a
transport-supplied random-payload callback without adding a dependency. No callback
in another embedding retains a fixed opaque payload and is not qualified as Go's
randomness policy; the workspace SDK explicitly supplies TLS-provider randomness.

An independent native client first-SETTINGS guard runs after successful decoding,
rejects unknown first types before ignore, accepts SETTINGS ACK and stays armed
after stream decoding errors. Server-only SETTINGS validation is not enabled.
Native reading can progress while ordinary writes are blocked. Received SETTINGS
waits for writer ownership before application, then emits one ACK and flushes;
SETTINGS ACK waits for the old writer without a reply. One PONG is flushed before
reading further frames. DATA receipt uses Go's 4 KiB-or-double-window credit
threshold, claims connection/stream refunds into a fixed pair, and commits terminal
receive EOF only after the required refund flush. Native EOF closes without waiting for generic writer shutdown, and every terminal
client future result notifies lifecycle observers even if the future is retained.
These are client phases; server
reply queues, ACK coalescing and shutdown timers are not selected for clients.

This supersedes the earlier named missing capacity/reset/lifecycle and ordinary
read-behind-blocked-write source branches; it does not qualify full wire or timing
equivalence. Per-request output-flight receipts and internal codec batching remain
concrete source boundaries. Generic h2 peer-reset/error cleanup can discard a
locally queued CANCEL before its captured reset-PING batch reaches the writer;
Go retains an independent captured reset+PING write. A native reset-flight queue
is still missing. Pending-open stream IDs are also allocated earlier than Go
allocates them after waiting for capacity, despite equivalent headroom accounting. Error-phase, receive/body/decoder, TLS close, resource,
cancellation and scheduler differences require further work or qualification.
Source edits/review and direct rustfmt only; no builds/tests or acceptance-gate
closure. Original selected net/http/h2_bundle.go SHA-256 remains
`a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e`.

## Native capacity/control follow-up original source SHA-256 — 2026-10-18

- src/proto/settings.rs: 0fef5d01aa0233100a0cda9c0b5080a15cfbaab16c42c991933f5ed7db06bf77
- src/proto/ping_pong.rs: fabf42b1b1062e361c4d45026e9bfc9c32a02a9074259c71b525e78d2113a148
- src/proto/streams/recv.rs: 49888eca03594469393d8b3bf328036007aff0e87df704f61a4556e4272386f8

## Native writer flights and sticky error phases — 2026-10-18

The explicit native client now seals each accepted HEADERS block (including its
CONTINUATION encoding) or DATA frame as one writer flight. Cloneable private
receipts retain pending/flushed/failed state independently of a later output
flight. Internal codec capacity flushes publish the same receipt completion;
retiring one request no longer requires a later global successful-flush checkpoint.
Explicit groups support one reset plus optional PING, or a receive-refund pair.
Default/server codecs keep their prior batching and allocate no receipt state.

Native startup now buffers the 24-byte client preface with initial SETTINGS and
connection-window output before its first flush. Output tracking starts only after
that startup flush succeeds. Ordinary SDK/client startup retains its existing path.

The native writer retains its first I/O failure. Later logical control writes and
flushes observe that failure without repolling the failed I/O object; old completed
receipts retain their completion. Read-side SETTINGS applies after acquiring the
prior writer even when that writer failed, and ignores its ACK write/flush failure.
Receive-refund failures also permit the reader to continue and publish deferred
EOF. PONG write failures remain fatal. Later real request/reset writer work and
request cleanup still observe the cached error. Writer readiness distinguishes
flow-blocked DATA and capacity-blocked HEADERS from work ready to acquire the
writer; buffered bytes alone do not force premature reader closure. Native global
error/EOF cleanup preserves an already received response EOS while failing its
unfinished sender, including when the completed connection future is retained.
Terminal closure/drop also fails any unfinished output receipt. This follows the selected Go
client's separate reader/writer error phases rather than treating every failed
control write as immediate reader termination.

Header-start visibility follows Go setting sentHeaders before writeHeaders,
including a blocked header flight. Independent captured cancellation reset/PING
flights retain request ownership through their writer completion even if generic
stream queues or peer errors remove the corresponding stream. Source peers repaired the
ordinary reset drain route, receipt refresh after internal poll_ready flushes,
stale canceled pending-open work, precise flow/slot readiness and fresh/cached
writer-error waiter notification. Exact source scope and remaining boundaries
are recorded in the parity ledger.

These source implementations supersede the earlier named conservative globalflush,
missing reset-flight queue, header-flush eligibility and ignored SETTINGS/refund
error-lifetime gaps. Body-consumer release WINDOW_UPDATE events still use generic
pending-window queues rather than Go's per-read synchronous pair/group, and h2
still allocates pending-open stream IDs earlier than Go. Error representation,
physical I/O/fragmentation, TLS shutdown, resources and scheduler/runtime behavior
remain unqualified, as do cross-runtime default sharing and accumulated feature/
backend/wire-only/package/container/client/process/import/restart/security gates.
No builds/tests, probes, validators, fixture recapture or dependency resolution.
Selected net/http/h2_bundle.go SHA-256 remains
`a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e`.

## Native writer follow-up original source SHA-256 — 2026-10-18

- src/codec/framed_write.rs: 032aab4c8c9108082e915885d0d582871bf4cdd95cd485bdcd7b717087c8ec35
- src/proto/streams/state.rs: 486b99b293d0f874b72724e1511cb0b11b44b3906ea20eb176fae1821772794d
- src/proto/streams/recv.rs: 49888eca03594469393d8b3bf328036007aff0e87df704f61a4556e4272386f8
- src/proto/streams/buffer.rs: 631aa4360b7b942c3899c6fb7455e682655c3ac099a170d5c3d566af3fec8318
- src/proto/streams/store.rs: 040005e8af13193db7bd89c20a44e28f5d18976a4b8562bf068dd8bd4a982668
- src/proto/streams/send.rs: ee355358b86ea048fd0e64642595e7be6e7f03a39d96745e74503cba2f1b08ef

## Native caller-sized bodies and delayed admission — 2026-10-18

The existing default-off go-client-idle selection now exposes hidden GoRead,
RecvStream.go_poll_read/go_poll_close/go_body_is_transport, and owned
client.GoSendRequest admission adapters. Ordinary public send_request and body
APIs retain their signatures. Private native metadata holds an ID-free FIFO,
initial header-flight ownership and independently cancelable admission guards.
A selected non-strict capacity race returns the original unsent request before
allocating an ID; response/send handles become available immediately after real
allocation while header ownership continues through the initial flush. ID-free
cancellation schedules the final writer/cached-error cleanup check without I/O
in Drop. Pre-ID errors retain the unsent request and wait for individual cleanup
completion before returning it; terminal closure completes those gates.

Native response state distinguishes transport, NoBody and MissingBody. Final
response Content-Length resets any informational-header value while preserving
HEAD. Late Close waiters retain an ID-keyed cleanup slot through the final writer
check; pre-header cancellation retains ownership until its writer abort check.
Reads drain
currently buffered DATA up to caller demand, preserving original frame-budget
length on split events. Declared length is checked at read time. Overflow consumes
but does not refund the original read bytes; short EOF is sticky UnexpectedEOF.
A per-read conn/stream credit pair has independent writer ownership and a completion
gate; read waits for that flush and ignores its writer error. Body Close breaks the
pipe, captures unread conn credit (including an empty writer flush below threshold)
and waits for request cleanup after its cached writer-error check. Special HEAD/
initial-EOS bodies neither abort on close nor acquire implicit final-ref CANCEL.
Closed/drop paths release completion gates and lazy body-state storage. Buffered
reads and late Close on a terminal connection complete newly captured gates
immediately; no absent driver is awaited. NoBody final-reference suppression
requires actual body detachment, preserving an abandoned response future's
cancellation. Cleanup signals done only at a released writer checkpoint after
checking the cached writer failure.

Default/server selection stays separate. The selected Go1.26.9 h2_bundle.go phases
are reqHeaderMu/writeRequest/awaitOpenSlotForStreamLocked, dataBuffer/pipe.Read,
handleResponse, transportResponseBody.Read/Close and cleanupWriteRequest. The
selected default StrictMaxConcurrentStreams is false; custom strict-mode waiting
is not introduced. Per-read outcome/gate retention handles Rust future cancellation
without duplicate credit. The existing native client receipts cover empty groups.
These hidden native reads own their credit: the same body must not mix GoRead
with ordinary poll_data/manual FlowControl release; canceled pending native
reads remain in the native adapter. The SDK uses that exclusive path. The hidden
Close API has no Go request-context/legacy-reqCancel argument, leaving those
specific Close return branches unexpressed.

Bounded source reviews and direct rustfmt only; no compilation, tests, runtime,
feature/default/embedding/package/container/client/process/CA/security qualification.
Broader malformed/reset/body/transport/TLS representations, physical I/O, scheduling
and resource equivalence remain incomplete or unqualified. No versions changed.

## Admission and body follow-up original source SHA-256 — 2026-10-18

- src/client.rs: f64c9089838886bb38aa6b2eaf7e10f84a98fbcdf06d6c4df6fae317de03377e
- src/lib.rs: c8680fc4eb13ccb4ce944716042bd33c6554677cf8261c371442f91fbee352e0
- src/share.rs: e313c11a24b649d4c9da937fb37e5c2cc7c689c53f6afd2470fd40fd030237c5
- src/proto/mod.rs: 592f8c60d97425946ff62cf694e3f36097a793863fc218fb4357dd440ed377e8
- src/proto/connection.rs: e7b371737a3648fee2a0746deab015f99765cd9ec2cb2428ea536b803f097d3c
- src/proto/streams/mod.rs: 3f7afa89a19943b1ac56052f64c4e220dbf0e951a4ac74405adbf83ea7050c27
- src/proto/streams/streams.rs: d2f866b385ea8107ecb4a56e0089523abeabb6a5dc8e107c0a6c3eeb26955290
- src/proto/streams/counts.rs: aba319047c01074d9e97afde4999c28e14f0ef21d1d39b7d6c6db4aebc786b79
- src/proto/streams/prioritize.rs: 5eba6fc5c252104676fa76e13fe07459fdbb9bc55df6483b1683fa99ad6fa674
- src/proto/streams/recv.rs: 49888eca03594469393d8b3bf328036007aff0e87df704f61a4556e4272386f8
- src/proto/streams/state.rs: 486b99b293d0f874b72724e1511cb0b11b44b3906ea20eb176fae1821772794d
- src/proto/streams/stream.rs: e31a59444ba7b885040556b89c19b308321e2adeab1cdb2cce720285701d56a0

## Native protocol resets and request-body phases — 2026-10-18

Native cleanup now captures local protocol reset codes independently of generic
stream queues, without cancellation PING accounting. Ordinary request-body errors
capture CANCEL with the existing pending-reset/PING rules; typed local reset
errors retain their code, and typed peer reset errors abort/forget the current
request without a wire echo while retaining their originating reset identity.
Unknown codec stream errors are ignored on the native client rather than creating
a synthetic stream or advancing request IDs. Existing parser classification is
retained; this is not a Go HEADERS/DATA/HPACK parser port.

Local pipe errors wait through the reset flush. Response abort errors and body
Close wait through final request cleanup and the cached writer-error check.
Buffered positive data, prior received EOF and sticky overflow/short-EOF readErr
remain independently readable; Close does not replace a sticky readErr. Actual
terminal EOS flights retain ownership through a pending writer and suppress a
late reset after successful terminal flush. A queued, unstarted EOS cannot use
an earlier nonterminal receipt as proof of completion.

Hidden native send-stream adapters support stopped-body NO_ERROR cleanup after
peer EOS, observed NoBody cleanup without abort, exact body-error classification
and cancellation of a held response. A separate initial-header completion gate
keeps request Body polling behind the header flush while response polling stays
independent. Abort wakes the body writer independently of a blocked header flush.
Native admission reads its ID from the already locked store, avoiding mutex
re-entry through the ordinary stream-ID accessor. Default/server selection stays
separate; all APIs/fields added here are hidden adapters or private state.

Sources are pinned Go1.26.9 h2_bundle.go handleResponseHeaders/writeRequest/
cleanupWriteRequest/readLoop/endStreamError and transportResponseBody. Existing
Go hash/terms apply. Source reviews/direct rustfmt only, no executable evidence.
Full error taxonomy/text, arbitrary request-body error objects, custom-body Close
versus Rust Drop, queued/unstarted EOS and broader physical-write scheduling,
resource/default/feature/client/process/database/security qualification remain
incomplete or unqualified. No versions or dependency resolution changed.

## Reset and upload follow-up original source SHA-256 — 2026-10-18

- Cargo.toml: 33a920942741aae5d0e746f64fde6acfbeba037c9bb0da436063c728193b0a8f
- Cargo.toml.orig: 6664ea9dee6a56004dc181d66b498653d9a00587680bf091327f74e6bb83e17e
- src/client.rs: f64c9089838886bb38aa6b2eaf7e10f84a98fbcdf06d6c4df6fae317de03377e
- src/codec/framed_read.rs: 061131d2280ec0903507eb73b675791b79643ec312cefd5b8bf46dbe3b7707d2
- src/codec/framed_write.rs: 032aab4c8c9108082e915885d0d582871bf4cdd95cd485bdcd7b717087c8ec35
- src/codec/mod.rs: 806fc32706d789f8e48a6867df014d945c438334e981205ff8f43d5b7f8ce0ef
- src/error.rs: b05dc52f36a29b29b1b3e0705a3f1ecf102a89896e173356f3e5fb1165dd6090
- src/frame/priority.rs: 9392b7aa2636157024dc645c92d0e450a4d3f7a53bc9de1188d3b61178c2b5fc
- src/frame/settings.rs: 9aed52868a1ddbb5570025edde2e073d3da1291b58d8759bfed7f086d40ef293
- src/lib.rs: c8680fc4eb13ccb4ce944716042bd33c6554677cf8261c371442f91fbee352e0
- src/proto/connection.rs: e7b371737a3648fee2a0746deab015f99765cd9ec2cb2428ea536b803f097d3c
- src/proto/go_away.rs: 51d467027bc30873fc76166ed731e968a23725e7b106b58ecadcb85044466a5f
- src/proto/mod.rs: 592f8c60d97425946ff62cf694e3f36097a793863fc218fb4357dd440ed377e8
- src/proto/ping_pong.rs: fabf42b1b1062e361c4d45026e9bfc9c32a02a9074259c71b525e78d2113a148
- src/proto/settings.rs: 0fef5d01aa0233100a0cda9c0b5080a15cfbaab16c42c991933f5ed7db06bf77
- src/proto/streams/buffer.rs: 631aa4360b7b942c3899c6fb7455e682655c3ac099a170d5c3d566af3fec8318
- src/proto/streams/counts.rs: aba319047c01074d9e97afde4999c28e14f0ef21d1d39b7d6c6db4aebc786b79
- src/proto/streams/mod.rs: 3f7afa89a19943b1ac56052f64c4e220dbf0e951a4ac74405adbf83ea7050c27
- src/proto/streams/prioritize.rs: 5eba6fc5c252104676fa76e13fe07459fdbb9bc55df6483b1683fa99ad6fa674
- src/proto/streams/recv.rs: 49888eca03594469393d8b3bf328036007aff0e87df704f61a4556e4272386f8
- src/proto/streams/send.rs: ee355358b86ea048fd0e64642595e7be6e7f03a39d96745e74503cba2f1b08ef
- src/proto/streams/state.rs: 486b99b293d0f874b72724e1511cb0b11b44b3906ea20eb176fae1821772794d
- src/proto/streams/store.rs: 040005e8af13193db7bd89c20a44e28f5d18976a4b8562bf068dd8bd4a982668
- src/proto/streams/stream.rs: e31a59444ba7b885040556b89c19b308321e2adeab1cdb2cce720285701d56a0
- src/proto/streams/streams.rs: d2f866b385ea8107ecb4a56e0089523abeabb6a5dc8e107c0a6c3eeb26955290
- src/server.rs: 6c288263c09ea51eabf87332a990547a8212bfd9d9301e5540d51cbe56b27d86
- src/share.rs: e313c11a24b649d4c9da937fb37e5c2cc7c689c53f6afd2470fd40fd030237c5

## Local adaptation SHA-256 — 2026-10-18

- Cargo.toml: 8f154f594fa94f01721f64f30bf1eb0132a30fa7be9deb8dde4e3f6cfd3f8e1a
- Cargo.toml.orig: 3779de3a560712fdec18199e1291f42458c5b78e2b24155b54a2b81a9cd899bf
- src/client.rs: 41769fdfc4ded834b83efab673181a25b9f5a33b57dc4a4c6b70cf52e0134938
- src/codec/framed_read.rs: bfa78bbea372e406aa7cdcb900a0e932bc94ee77161eeb76035c1498e7c3295a
- src/codec/framed_write.rs: 8bf024c3e72f3a667f95dbace80be421209fce0019451eda19fd3a222a5aedac
- src/codec/mod.rs: 14f82c1931595145b7ca9ce2d33550c3cbe0988ae135bb7144a99b56c0331c82
- src/error.rs: ee6a259500372c9d9f9a9f7db1ecf23dc3b9d55dee46a81e78a7d9e0ec0bd694
- src/frame/priority.rs: 0295fa56b3bf46313e8dd9bab814deacb615dcd467e6629a632f16711a38bbca
- src/frame/settings.rs: 361e49ad0a105823d6062b829a7d788c5b0f88f54d68a591714bf528f6d75be1
- src/lib.rs: b9b6f4d9254a9f7666eb6a30a5e68d802920ee1afc2f227942821bad7c6bd1cf
- src/proto/connection.rs: 68ac0de9dfdeb7788e35adf8e8d61aa8887f455d65e8dd7f249331b08925bdb4
- src/proto/go_away.rs: 64ace49ae96ce65b56078fdd783998f5d0d6e46e64a6f2dac6c88b858bd4c862
- src/proto/mod.rs: 556a00a7507954d5e3a60fb302a54d8676d9965314a01a923996e26b2269898c
- src/proto/ping_pong.rs: 27474224f5140c18949ff32d8c4051038c3ae7bd4ec6645ad236c42d6ec733b0
- src/proto/settings.rs: 7c44217a899a4112dfba4a358a440830d21312918913fbd1c30527f873dc5a88
- src/proto/streams/buffer.rs: 2b0b6f1d6ea96225427af735212fa0e00e6ec73e29cd120b0a1ed6e579385f11
- src/proto/streams/client_state.rs: ab8a474ee020fd492240696aa2bc39bbf026bd5fdf3a2c11c775d2e808d3b3c9
- src/proto/streams/counts.rs: d75eaa551a0087fd4fd129008d6a93e51b3634ff97f6f157bad3a4f42e0879e3
- src/proto/streams/mod.rs: 026a43c8419e30cc16f7fb17182caf31bef743bf85482527e44099c669ce8746
- src/proto/streams/prioritize.rs: c37257be6287e053090710ddbf7063bd57274e33db82ff15ccd9ad3adb242682
- src/proto/streams/recv.rs: 7ae06478a6ff747bb2989d445479c3872233e5508e21be2bf1ac3b32d28c339f
- src/proto/streams/send.rs: b1f4128d0cb542685837893a28d2154a11a64afb3923d6906353b55d61198f1b
- src/proto/streams/state.rs: c96fdc0e9894324866ad052c23e830d27618c51af1a9433f27588677bef95fe6
- src/proto/streams/store.rs: 57aec5cd091351398a0601a1d441c79cd8954cee83e4d70d884f32ec2d9fc835
- src/proto/streams/stream.rs: e066ce8577e6a159adafc5afe976c54a666360fcdd24e86de9bb7180103748eb
- src/proto/streams/streams.rs: b5fb7a8bbcaee31e43ea0d0de09f9e330e6688f6fcabbc5c025b17b40c79f167
- src/server.rs: 0cfb1808a3baffcba96131311e13bd1c873ac2e273fc9912048fa7b41e7ab038
- src/share.rs: cebdaf29ecdf9360a8bca0356c9fccd6d3ad1a4fa6b392fdd9563a33097cae03

