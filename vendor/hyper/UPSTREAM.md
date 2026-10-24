# Selected Hyper source and native Go adaptations

## Current selected source: Hyper 1.12.0

The authorized dependency upgrade rebases the retained native adaptations onto
the exact crates.io Hyper 1.12.0 archive. Archive SHA-256:
`2c3e324da4c95177d6291d4c8730197c0d1822f8a9766814a4a44fa5ab797c9c`.
Registry VCS metadata is retained verbatim at commit
`7f67699ce32d717081deb7018b4da7d679277ac0`. The MIT license and retained Go
BSD-3-Clause terms/notices remain included, with both package manifests
declaring the combined license. No authored tests or fixtures were added.

`LOCAL.patch` records the complete local source/manifest delta against that
archive. `SOURCE-HASHES.txt` records original and adapted source hashes.
The rebase used three-way source merges against the former exact Hyper 1.8.1
registry source and the existing local adaptations. Upstream-only source was
copied intact; the upstream-removed common/watch module and registry cache
marker are not retained. The existing native-only body/go_h1 module remains.

Conflict resolutions retain the new upstream body channel/receiver, HTTP/1
write fairness and second flush, HTTP/2 body-before-capacity polling with a
retained pending chunk, peer reset wake registration, default cancellation
channel, max_header_size support and new reset builder settings. The native
header-before-body and Stop/Cancel ownership gates remain explicit. Native
Stop/Cancel drops both the pinned source and any newly retained chunk before
awaiting captured cleanup. Native callback cancellation uses its existing
delivery-aware owner; default clients use the new upstream cancellation
channel. Native HTTP/1 EOF acknowledgement runs at both possible flush
checkpoints. Cargo.toml.orig also includes the existing default-off server
lifecycle feature, matching the normalized package manifest.

The new HTTP/1 max_header_size setting remains None by default, preserving
the existing native max_buf_size ceiling without adding an implicit 64-KiB
limit. Explicitly selecting that new setting also changes chunked trailer
admission; the rebase does not silently select a new trailer profile.

All local opt-ins remain off by default. Upstream default behavior and native
adaptations were source-reviewed separately. Source merges/comparisons and
direct rustfmt only; no tests, builds, benchmarks or runtime validation were
run. Dependency resolution/fetch were authorized separately and do not
establish behavioral, resource, feature or embedding qualification.

## Historical adaptation notes (Hyper 1.8.1 baseline)

Source: hyperium/hyper v1.8.1, registry VCS commit
`166c6cacc74b215674937e782b3ab2cbd8b69883`.
Original MIT terms are retained in LICENSE and registry metadata is retained
in .cargo_vcs_info.json. No dependency version was updated.

The default-off `go-server-lifecycle` feature enables the matching vendored h2
feature and provides an additive hidden HTTP/2 server builder setter:
`go_native_server(Option<Duration>)`. A private optional configuration field
forwards the selection to h2 only for builders that call the setter. `None`
selects native behavior with no idle expiry; `Some(timeout)` also selects that
idle timeout. Default builders, including Tonic's, retain upstream behavior.
Those server adaptations leave client configuration and HTTP/1 unchanged;
the separate opt-in client-idle adaptation is described below.
The matching hidden `go_stream_timeouts(read, write)` setter forwards an optional
private timeout pair only inside native server selection. Default/Tonic builders
retain disabled stream timeouts. Tracked ordinary HTTP selects30s/30s.

The original server adaptation changes Cargo.toml, src/server/conn/http2.rs
and src/proto/h2/server.rs; later client changes are recorded below.
The API's full profile activates this feature; wire-only embedding does not
request it. Full consumers outside this root workspace require both local
Hyper and h2 patches. Root patch/exclude and the existing lock source are
updated; both images include the MIT license.

Original source SHA-256:

- Cargo.toml: 802fefc9dbcbfb60e0bf547ea3efde93284840def02f69852a6d0ef15d12c8b1
- src/proto/h2/server.rs: 10a9deb6729f4cdca57222234783447c823b6d73669147d0a7d1297caf7f6683
- src/server/conn/http2.rs: 6bebea3f057d7c33fa55522b9923dceb361ebbb416a98262bec1dab847358171

See vendor/h2/UPSTREAM.md and docs/headscale-go-parity.md for lifecycle scope
and remaining differences. Source/direct rustfmt only; no builds/tests/Cargo,
runtime/feature/package/embedding or resource qualification is established.

## Native HTTP/2 client idle lifecycle — 2026-10-18

The new default-off go-client-idle feature forwards only the selected h2 package's
matching feature. A hidden HTTP/2 client builder timeout remains None by default.
Only explicitly selected native clients obtain the opaque h2 activity handle.
Hyper-util reserves its checked-out H2 sender before dispatch; direct native
Hyper sends reserve on demand. Cloning a sender does not duplicate a reservation.
The token moves through Request extensions into atomic h2 admission. Dropped
queued requests release their shared token once; retries discard a reservation
from the previous connection. Readiness consults the shared idle state before
using the ordinary dispatcher hint, avoiding an idle-closed checkout race.

The selected h2 implementation owns initial/stream/flush-aware idle deadlines and
silent idle closure, separate from the existing server GOAWAY lifecycle. Default
clients, Tonic and servers do not select the new policy. No extra native stream-
state mutex polling runs on the default protocol-connection path. Original MIT
terms remain intact; Go BSD notices/terms are included by the package LICENSE*
glob and both container license-copy recipes. No package/version or dependency
resolution update was performed.

Source reviews and direct rustfmt only. Full feature/default/embedding/package/
container/client/process and resource/runtime qualification remains pending.
See h2 and Hyper-util UPSTREAM.md for detailed timing and ownership boundaries.

## Native client follow-up original source SHA-256

- Cargo.toml: 802fefc9dbcbfb60e0bf547ea3efde93284840def02f69852a6d0ef15d12c8b1
- Cargo.toml.orig: 8ef7ebe4b1d923d9764f8004e72198059ce123261164be77de7378df1704d406
- src/client/conn/http2.rs: 4cd27c1e7e80928fb448c84a91fd3cc146e1a7e114f47c8950ec9d4739bfbc55
- src/proto/h2/client.rs: 5fa59359de28a055ab7e05c79f8046394602aeeb4427c5af48b3acec8e438202

Selected Go1.26.9 native client lifecycle:
- net/http/h2_bundle.go: a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e

Both independent bounded source reviews passed after the failed-admission,
closed-readiness, flush-retirement, feature-import and default-lock repairs.
Only source review and direct rustfmt were performed; no executable evidence.

## Native client capacity and lifecycle adapters — 2026-10-18

Hidden additive adapters now forward native availability, atomic reservation,
stable lifecycle observation and reset-PING payload callbacks. The native-client
flag is independent of a nonzero idle timeout. An unused connection failure is
reported as fatal without returning its unsent request for retry; an unavailable
reused connection can still return its original unsent request safely. Sender
clones do not duplicate reservation ownership. Ordinary clients and native server
flags retain their previous selection; no public struct field list was expanded.

The exact selected h2 implementation owns capacity, reset and receive-control
phases. This layer does not establish full Go transport error/timing equivalence.
Only source review/direct rustfmt; no builds/tests, feature qualification or gate
closure. Selected Go net/http/h2_bundle.go SHA-256 remains
`a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e`.

## Native delayed admission and caller-sized bodies — 2026-10-18

The selected native client task uses an ID-free h2 admission future. Its private
FIFO registers every queued callback's cancellation, continues draining dispatch
while the front waits, and attempts admission only at the front. Unsent capacity
rejections reconstruct the original request/body for retry after its final
writer/cached-error cleanup checkpoint. Requests canceled before construction of
the admission future use the same native ID-free cleanup. A separate cleanup
waiter queue polls each failed request independently after header ownership is
released, preserves callbacks when dispatch closes and does not self-wake for
blocked cleanup alone. An admitted request
starts ordinary response/body work before initial header flush. Default dispatch
and server paths retain their selection.

Hidden GoBodyRead and Incoming.go_poll_read/go_poll_close/go_body_is_transport
forward native H2 caller-size/read-credit/body-close/body-kind behavior. The HTTP/1
fallback retains unread channel tails, exposes them to ordinary Body polling and
size/end hints, and avoids decrementing content length twice. Its lower socket
framing/read/drain phases remain unqualified. Incoming special body markers let
the SDK skip gzip and preserve response headers on HEAD/NoBody/MissingBody.

Hidden native read and ordinary Body/manual-credit APIs must not be mixed on
one H2 body: native pending reads already own returned credit. The selected SDK
uses only native consuming reads.

Original MIT and Go BSD terms remain intact. No manifest/version/resolution update;
source reviews/direct rustfmt only. Accumulated feature/default/server/wire-only/
package/container/client/process/resource/security qualification remains pending.

## Admission and body follow-up original source SHA-256 — 2026-10-18

- src/body/mod.rs: 6e029d258d08b35a2f825235842da2f4d98fe90a9543851516382f019cfa4b8e
- src/body/incoming.rs: c472cf4f29f9acaddee1ddcea740a632de9b8d50687227ca9a34b48117786261
- src/proto/h2/client.rs: 5fa59359de28a055ab7e05c79f8046394602aeeb4427c5af48b3acec8e438202

## Native early-response and upload cancellation — 2026-10-18

Native final responses above 299 stop an ongoing request body; 1xx/2xx keep full
duplex behavior. The pipe drops its pinned body in place, retains its sender until
peer EOS, and waits for captured NO_ERROR/final cleanup. Request-body polling first
waits for the initial header flush, while response polling proceeds independently.
Ordinary body errors use CANCEL/PING, typed local h2 resets preserve exact codes
without PING, and typed peer resets abort the request without echoing a reset.

An actual known-empty native request with a Go NoBody response waits for donec
before delivering headers; MissingBody stays distinct. Held response cancellation
has a separate native guard from NoBody.Close. Native nonempty upload ownership
stays armed until the callback accepts the response. Callback prechecks and a
private accepted-send acknowledgement handle already-canceled and concurrent
callback closure; rejected delivery cancels the upload rather than abandoning it.
Delivered 2xx responses retain full duplex behavior. Defaults preserve the original
callback order and APIs. Native control objects allocate only for selected requests.

Rust Body has no Close method, so Go request-body Close maps to dropping the pinned
body. Known-empty uses is_end_stream, not a contradictory zero Content-Length.
Arbitrary custom body error objects are not retained as Go pipe error objects;
normal SDK fixed-byte request bodies are infallible. These embedding/representation
and broader buffering/scheduling/resource boundaries remain unqualified.

Source reviews/direct rustfmt only; no builds/tests/process/client/feature/default/
package/container/runtime/security evidence or acceptance gate closure. Source:
selected Go1.26.9 h2_bundle.go8758–8783, writeRequest and cleanupWriteRequest.
Original MIT and Go BSD terms remain intact; no dependency resolution update.

## Reset and upload follow-up original source SHA-256 — 2026-10-18

- Cargo.toml: 802fefc9dbcbfb60e0bf547ea3efde93284840def02f69852a6d0ef15d12c8b1
- Cargo.toml.orig: 8ef7ebe4b1d923d9764f8004e72198059ce123261164be77de7378df1704d406
- src/body/incoming.rs: c472cf4f29f9acaddee1ddcea740a632de9b8d50687227ca9a34b48117786261
- src/body/mod.rs: 6e029d258d08b35a2f825235842da2f4d98fe90a9543851516382f019cfa4b8e
- src/client/conn/http2.rs: 4cd27c1e7e80928fb448c84a91fd3cc146e1a7e114f47c8950ec9d4739bfbc55
- src/client/dispatch.rs: dcd5aa38ad58b201b35e7c32991d0b6f744f89f64a664341f9ca73140d1f0a9d
- src/proto/h2/client.rs: 5fa59359de28a055ab7e05c79f8046394602aeeb4427c5af48b3acec8e438202
- src/proto/h2/mod.rs: 180b83f135fe2e96df4b9299a14c09ccd45e7e7f12b5c13386593d77a249034d
- src/proto/h2/server.rs: 10a9deb6729f4cdca57222234783447c823b6d73669147d0a7d1297caf7f6683
- src/server/conn/http2.rs: 6bebea3f057d7c33fa55522b9923dceb361ebbb416a98262bec1dab847358171

## Native HTTP/1 body ownership — 2026-10-18

The hidden HTTP/1 builder selection is false by default. Native selected response
bodies share private consumer/driver state so decoder EOF does not authorize
reuse before the caller's EOF verdict. Bounded reads retain their private tail;
the final known-length bytes can carry EOF only when that tail is exhausted.
The caller's EOF waits for the driver reuse/retirement decision and, when
registered by HyperUtil, the actual pooled-connection handoff. Early Close
selects retirement instead of the ordinary opportunistic drain path.

The native driver permits current-request writes while waiting for the body
verdict, but cannot admit the next request. A pending write has Go's selected
50 ms reuse wait after consumer EOF. Drop guards wake abandoned consumers and
drivers; an optional hidden pool guard completes on pool return or retirement.
The ordinary Body path also supplies its consumer verdict. Default/server
builders retain their original policy. Existing go-client-idle now also selects
Tokio's already-locked time feature; no dependency versions/resolution changed.

Source: Go1.26.9 net/http/transport.go readLoop/bodyEOFSignal/wroteRequest and
net/http/transfer.go body.readLocked. Go's read-loop EOF acknowledgement precedes
its deferred socket close; this control is not a claim of physical socket/TLS
shutdown timing equivalence. Raw H1 read sizing, parser/trailer/error envelopes,
Go request-context cancellation, custom bodies, scheduling/resources and all
runtime/feature/default/client/process/package/security qualification remain
incomplete or unqualified. Source reviews/direct rustfmt only; no execution.

The implementation was frozen for the requested broad audit. Two source
differences remain in this new H1 boundary: an already nonreusable/closed
connection can still enter the flush/50 ms writer wait before retirement, and
implicit Incoming field destruction drops its channel before its consumer guard
publishes Early. The latter can permit a small opportunistic drain under a race;
the separate driver verdict still blocks reuse. These are audit findings, not
executed regressions or closed parity items.

Selected Go source SHA-256:

- net/http/transport.go: 643bce4b4fb016ed57c18e9d087e6c298faf3263d83728107c6b5cdaa398fe87
- net/http/transfer.go: 3e04744176d3cf5bef2827ab158b10aaeec3981ac5f4e7fb86e3dbf5f592eed7

Original Hyper source SHA-256:

- src/client/conn/http1.rs: 7f5b1ebf50dd77fef03579f0327c2f12074eeaa688334d6eae6b3267862ab6d4
- src/proto/h1/dispatch.rs: 073a2bf94418e2eb2f000c5ffb7f2a95891c616ea3d025b7ebfaaaf7a8234038
- src/proto/h1/conn.rs: bcd74686394c958ae2bbadd3d9f48dd6570843f5fe3e1ca76f256fe4f3753be8

## Local adaptation SHA-256 — 2026-10-18

- Cargo.toml: 564ec6ca709b65d5097e4adb9c2c425e6154bb61a04063f99572a7f453752a75
- Cargo.toml.orig: d42cb379776b4bd4d92995e55f1f8e23cf4f88bf85f51128e0f62c03846672a8
- src/body/go_h1.rs: e3b8e8bfcb3dfd176c327daab41170fa7651fb8b312267aa4a7bd00eecb4f56d
- src/body/incoming.rs: 275a08aaeffaa87317bc332bc897d924504c45efdce9a489542b55e0886ebe03
- src/body/mod.rs: fb482262a76d832a05b99c9e2fda1fce3bfbab5f482620dca6efd1cc9c5ca55a
- src/client/conn/http1.rs: 1e78cc3f7410cf44a416f31d373a5326d311aa537c102a873f427948522145d0
- src/client/conn/http2.rs: c3db8055c7c272eb05dc031902bb3b9ddf7422ef8c30bdc9affe448db94d00ac
- src/client/dispatch.rs: 406eb9f32e7ade4c4a23f925d255b2b59edea7a41f2cdb1f1a1080a70a4b7983
- src/proto/h1/conn.rs: 3d038df12c973b4cd87e489e45fed558add3cc2af405a6de8a847e8563d259ff
- src/proto/h1/dispatch.rs: 83f0a827784e13b9ac3472df02583247e94766832412044a6fddc4e42dc5fadf
- src/proto/h1/role.rs: 358914f7495915acce0f058504f43d1504656712dab50305a33c0c078794464c
- src/proto/h2/client.rs: 1833fe15fe5666072d5170462696a3960ea65cd6072a6f66433eb15b3fdc0691
- src/proto/h2/mod.rs: a4a65034917d5b22b7046a9db3106550a74ef9d460553491b7b330c413aa059c
- src/proto/h2/server.rs: 31016bb2b1646f725c9832e396fd604191c50e6fd9f763c3febab68fa02c7dc1
- src/server/conn/http2.rs: c2b4fb142ea5d4bf96b6951ebeeb86997a74f069244124cf05bdd09f3c74768b


## Grouped audit H1 ownership and response admission — 2026-10-18

This supersedes the two frozen H1 source differences described above (F15/F16).
Incoming's private native consumer field now drops before its channel, so Early
is published before ordinary channel-drop drain can begin. After consumer EOF,
a closed/nonreusable connection retires before the reusable path's writer/flush
wait. The default-false native selection and public APIs remain intact.

The selected native client's response profile accepts folded headers and uses a
10-MiB budget. Client parser scratch capacity grows with received line count,
up to the configured field cap, rather than allocating the maximum upfront.
HeaderMap reserve/append failures return Parse::TooLarge instead of panicking.
The existing Rust HeaderMap distinct-name limit is still narrower than Go's
byte-budget domain: F14 remains partial in that extreme domain. Server/default
parser policies remain unchanged. Physical framing/trailers, exact errors,
cancellation, scheduling and runtime/default/feature qualification remain open.
Independent source peer and direct rustfmt only; no tests/builds/probes ran.

Selected pinned source SHA-256:

- Go1.26.9 net/http/transport.go: 643bce4b4fb016ed57c18e9d087e6c298faf3263d83728107c6b5cdaa398fe87
- Go1.26.9 net/http/transfer.go: 3e04744176d3cf5bef2827ab158b10aaeec3981ac5f4e7fb86e3dbf5f592eed7

Grouped audit parser original source SHA-256:

- src/proto/h1/role.rs: 210ad28ef2e3c35f2268e3dac979e519c02193b4ba6f895de86442b26b802fad
