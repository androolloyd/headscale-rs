# Hyper-util 0.1.21 native client rebase

This directory now starts from the exact crates.io `hyper-util` 0.1.21 archive,
SHA-256 `ddc03d96684f9226b8a787cdb71488417b53ab5ea8fdb1dac946cb9431cc8bff`.
The retained upstream `.cargo_vcs_info.json` identifies commit
`23a868965964c1d6bb1b94f30ba4c420a4bebe7c`. The registry cache marker is
excluded. Upstream source, examples, tests, changelog and original MIT license
are retained. No new tests or fixtures were authored.

The complete local source/manifest delta against that archive is `LOCAL.patch`.
The prior 0.1.19 native adaptations below are rebased rather than removed:
request gzip/User-Agent/identity markers, capacity-aware separate H2 cache,
atomic checkout and closure observation, native idle/LRU scheduling, reset-PING
callback forwarding, and HTTP/1 consumer-EOF pool acknowledgement. The public
pool `Config` field list and native additive feature/API names are preserved.
The default-off `go-native-client` feature still forwards Hyper's client feature.
Local BSD-3-Clause Go adaptations retain LICENSE-GO and LICENSE-GO-NOTICE; the
combined package license declaration remains MIT AND BSD-3-Clause.

Rebase resolutions preserve both upstream's empty-pool idle-worker termination
and the native exact-deadline worker ownership protocol. The removed private
poll_fn shim is replaced by `std::future::poll_fn`. Dial URI construction retains
a pool-key clone because the native ALPN cache recheck still needs that key.

All other 0.1.21 changes are retained, including CONNECT response validation,
SOCKS/IPv6 fixes, composable-pool readiness/cancellation/FIFO repairs and new H2
builder forwarding APIs. Upstream's edition 2024/MSRV 1.85, dependency constraints
and tracing-executor behavior are retained: `tracing` alone no longer propagates
the active span to spawned connection tasks; the new upstream temporary
`rt-tracing-exec-force` opt-in is not enabled locally. This is an upstream behavior
change, not a claim that existing diagnostic timing is identical.

`SOURCE_SHA256SUMS` records the current source/manifests and local patch hashes.
Only source comparison/review and direct rustfmt were performed in this lane.
No tests, builds, Cargo commands, probes, validators, benchmarks or executable
qualification were run. Root workspace lockfile resolution is managed separately.
An independent bounded source peer found no actionable type, cfg, ownership or
native/default integration defect in the rebase. This is source evidence only.
Earlier version/resolution and hash statements below describe the historical
0.1.19 adaptation and are superseded for the current selected source by this
section and the current hash inventory.

## Original selected 0.1.21 source SHA-256

- `Cargo.toml`: `be68258b960525839b23a699362c550c7c5e73934cabd9dfe1b2a3fdebb37a2e`
- `Cargo.toml.orig`: `ecdace19ddd41ff8f9d3c2b87d4cdc3daa1c5820d64a268817f6431ab1ba856c`
- `src/client/legacy/client.rs`: `bc854508f0bee926f93adf5c00b0ecd4387d3047d8f748b3571a2a72dcbbb8a1`
- `src/client/legacy/mod.rs`: `a893df119a025ce5e8226868f76130b50b15dd0a4c8ae007556b14f29cd3520a`
- `src/client/legacy/pool.rs`: `7154a4688d94c5ac199e31560c1a6bda33dce5aaa4e3b10f38a22f9d37851191`

## Historical 0.1.19 adaptation record

# Local exact-version native client adaptation

Upstream hyper-util 0.1.19, VCS commit
`d5740116a55cbf7af13d1142b365c56b1d684f3a`.

This is the already-selected registry package. Root Cargo.toml patches/excludes
this copy; Cargo.lock removes only this package's registry source/checksum.
No dependency versions, package dependencies or resolution were changed.
The default-off go-native-client feature forwards the selected Hyper package's
default-off client-idle feature; no dependency version or package edge is added.
The native instant-acme feature explicitly enables it. Original MIT terms remain
in LICENSE; Go policy attribution/terms are retained in LICENSE-GO and
LICENSE-GO-NOTICE. Both native container recipes copy LICENSE* files.

## Selected source adaptation

Additive hidden request markers opt into connection-selected gzip and opaque
connection-pool identity. The gzip decision runs after connection checkout and
uses Go HTTP/1 first-value-empty versus HTTP/2 header-presence rules. Original
Accept-Encoding values are retained/restored across internal retries, and the
response carries whether that actual attempt requested automatic gzip. The
native SDK's decoder uses this response marker. Ordinary requests do not opt in.

The native pool key separates an opaque equality identity from the original dial
destination. The SDK encodes Go connectMethodKey field equality, including full
proxy URL, target scheme, canonical address and onlyH1; HTTP forward proxies omit
the target address while CONNECT/SOCKS tunnels retain it. Length-prefixed fields
avoid delimiter ambiguity. Debug output never renders opaque identity bytes,
which can contain proxy credentials. Default requests keep their original
scheme/authority equality and cannot share a native-key connection accidentally.

An additive hidden builder setting enables global insertion-LRU idle eviction.
The native SDK selects 100; zero preserves unlimited upstream defaults. Private
insertion sequence orders equal clock instants and rebases on overflow; eviction
scans the bounded idle entries under the existing pool mutex. The public pool
Config's field list and existing struct literals are unchanged. Shared HTTP/2
checkouts preserve insertion rank. Dropping an idle pool sender is not a claim
of exact Go HTTP/2 physical-socket lifetime, timer, cancellation or scheduler
behavior. Those resource/runtime boundaries remain unqualified.

Direct rustfmt/source review only. No builds/tests, feature/default/wire-only,
package/container, CA/client/process, security/advisory or replacement-parity
qualification. Downstream consumers need equivalent local patch configuration.

## Original package source SHA-256

- Cargo.toml: 83dd604464239981f64998ad99ed523e44841136158a79ed812816eaa2b27c81
- Cargo.toml.orig: 11e263b94c9036a7ae76ae45ba0a8fec87b53e032b5f42f1f126b4365f691141
- src/client/legacy/client.rs: fbc7cbe6693d1dbafcbbbe1cea79c69e6167c77f713e17da530e1af969ac09c0
- src/client/legacy/pool.rs: 6697416b7bc4b540d30b6ce4e81604c1d2c8d2a49f0a96d59a22635a443927a3
- src/client/legacy/mod.rs: a893df119a025ce5e8226868f76130b50b15dd0a4c8ae007556b14f29cd3520a

## Selected Go1.26.9 original source SHA-256

- net/http/transport.go: 643bce4b4fb016ed57c18e9d087e6c298faf3263d83728107c6b5cdaa398fe87
- net/http/internal/httpcommon/httpcommon.go: 20aedc8a3cde20f3cab6f392d33f9eb4e2fb9f663c7298fcbf0f9462c721c26a
- net/http/client.go: 908d9d964cd157899b60e7ba839befa4bfd398b4fb8f7ff5a1aa389eae75f652

Two independent bounded source reviews found no actionable defect in this
adaptation. The earlier shared-H2 checkout timestamp/periodic-expiry source gap is superseded
by explicit native connection-owned stream/flush-aware timers below. Default
native accounts also now share their pool within the production Tokio runtime;
Go's default transport shares across the process, including separate runtime
contexts for which this implementation keeps isolated pools. The configured 100-entry limit
therefore applies to this native pool instance, not every process socket.
HeaderMap cannot represent a present header key with a zero-length value vector;
an explicitly empty HeaderValue is preserved as Go's one-empty-value case.
No executable qualification was performed.

## Native pool deadline scheduling — 2026-10-18

An explicit private native-idle flag selects earliest-deadline expiry for the
pool-managed connections. Native expiry uses deadline equality, disables timeout
at zero and wakes at the earliest retained connection deadline without the
ordinary minimum polling period. After each wake it recomputes the next deadline;
when no eligible connections remain it clears worker ownership under the same
mutex as insertion. A later idle return starts a fresh worker. Uniform configured
timeout means a new idle return cannot introduce an earlier deadline. Ordinary
clients retain their upstream periodic/strict-greater-than expiry policy.

Poolable receives a default-false additive native connection-timer method, keeping
external implementors source-compatible. Selected HTTP/2 connections with their
own stream-aware timer are exempt from pool-checkout expiry and pool worker
expiry, and shared pool checkouts do not refresh that connection's idle timestamp.
The native client-idle configuration/stream lifecycle is recorded in the Hyper
and h2 provenance. The public pool Config field list remains unchanged.

Independent source reviews/direct rustfmt only. No executable or parity-gate
qualification, and no claim of complete Go idle/socket/scheduler equivalence.

## Native client follow-up original source SHA-256

- Cargo.toml: 83dd604464239981f64998ad99ed523e44841136158a79ed812816eaa2b27c81
- Cargo.toml.orig: 11e263b94c9036a7ae76ae45ba0a8fec87b53e032b5f42f1f126b4365f691141
- src/client/legacy/client.rs: fbc7cbe6693d1dbafcbbbe1cea79c69e6167c77f713e17da530e1af969ac09c0
- src/client/legacy/pool.rs: 6697416b7bc4b540d30b6ce4e81604c1d2c8d2a49f0a96d59a22635a443927a3
- src/client/legacy/mod.rs: a893df119a025ce5e8226868f76130b50b15dd0a4c8ae007556b14f29cd3520a

Selected Go1.26.9 native client lifecycle:
- net/http/h2_bundle.go: a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e

Both independent bounded source reviews passed after the failed-admission,
closed-readiness, flush-retirement, feature-import and default-lock repairs.
Only source review and direct rustfmt were performed; no executable evidence.

## Separate native HTTP/2 connection cache — 2026-10-18

Native request metadata supplies an opaque authorityAddr identity separately from
the general proxy-aware connection key. A private ordered cache owns canonical
H2 senders independently of the general idle-wrapper LRU. It retains saturated
healthy connections, atomically reserves the first eligible sender and supports
multiple connections per authority. General wrappers remain counted for idle
limits but are excluded from native H2 checkout/waiter delivery. Closure watchers
use stable lifecycle identities and honor the bounded unused-failure retention.
A per-authority dial owner wakes followers on completion or cancellation; canceled
waiters are pruned. The ordinary/default and HTTP/1 pool paths remain selected by
their existing policies. An ALPN-time cache recheck can discard a redundant TLS
connection before sending its H2 preface when existing capacity becomes available.

The native SDK supplies Go's authorityAddr bytes before backend URI normalization
and a reset-PING entropy callback through the additive Builder method. This cache
supersedes earlier named missing multi-H2 capacity selection, MarkDead and separate
physical ownership branches. It does not qualify complete Go pool scheduling,
custom/dynamic proxy paths, h2c, decoder/error/timing or TLS shutdown equivalence.
Cross-runtime default sharing and per-request codec flight receipt remain source
boundaries. Only source review/direct rustfmt; no executable or gate qualification.
Selected Go net/http/h2_bundle.go SHA-256 remains
`a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e`.

## Native HTTP/1 body pool acknowledgement — 2026-10-18

The existing native idle builder selection now also selects Hyper's hidden
HTTP/1 native client builder. Default builders keep the false selection.
Before returning a response, the client registers its optional native body pool
guard. The immediate and deferred on-idle paths both drop the pooled connection
before completing that guard, including the closed/error path. Thus native EOF
can wait for actual pool return/retirement after the H1 driver's decision rather
than only sender readiness. Direct Hyper usage need not register a pool guard.

Hyper's provenance records consumer EOF versus decoder EOF, early-close
retirement and the bounded writer wait. This does not qualify physical shutdown,
transport scheduling, parser/custom-body/context errors or all default/native/
feature/client/process/package/security behavior. Source reviews/direct rustfmt
only; no builds/tests/probes or executable parity evidence.
Go net/http/transport.go SHA-256:
643bce4b4fb016ed57c18e9d087e6c298faf3263d83728107c6b5cdaa398fe87.
Original MIT and Go BSD notices remain intact; no resolution/version changes.

## Local adaptation SHA-256 — 2026-10-18

- Cargo.toml: fef23b4010ba85675e33d54886bdc067a9af726ab364a90107dceb65b8277059
- Cargo.toml.orig: d8c68ac8f9fdc45eba3302dfdce961bf76880d989b45a054871283cbb33bd63e
- src/client/legacy/client.rs: fca1a5740d8c1da335a554be9ec5f941ec01d8a81eb984a922caa3556a779080
- src/client/legacy/client/go_h2.rs: 2974dc3054ef34d7f0e9faf504d0d9770db914d78996848463455ac7e26dfc10
- src/client/legacy/mod.rs: 8ab75f8d9cf7eafe5101927247a8dc15422a333b105b0abc61a83f86126186d2
- src/client/legacy/pool.rs: 01efc935b22b6837c5b57bc1c55c3b1d7f083378e4a66b32888b4cdb2fbd6b31


## Native GET protocol-selected User-Agent — 2026-10-18

The hidden additive GoAutoUserAgent request marker selects default Go HTTP/1.1
or HTTP/2.0 UA after actual pooled-connection protocol selection. A private
original-field snapshot survives safe internal retries. The first explicit field
wins; empty suppresses default, H1 trims space/tab after the nonempty decision
(including an emitted empty field for whitespace-only input), H2 keeps raw bytes.
Native redirects restore the marker per attempt. Only the new explicit GET
helper uses this marker; ordinary clients and ACME explicit UA are unchanged.
No public fields/signatures changed. Independent source peer/direct rustfmt only;
no tests/builds/probes or runtime/resource/security qualification.

Selected pinned source SHA-256:

- Go1.26.9 net/http/request.go: 4a34a9e157a606a046d5b9f8f761c571c4762668fa351d92048515a595939c38
- Go1.26.9 net/http/h2_bundle.go: a2525871d4dff10f9cb1205aa1f4af94845729643bc1aa411a1ccf31ea161e2e
- Go1.26.9 net/http/internal/httpcommon/httpcommon.go: 20aedc8a3cde20f3cab6f392d33f9eb4e2fb9f663c7298fcbf0f9462c721c26a
