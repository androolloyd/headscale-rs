# v0.29.5 remaining-work audit — 2026-10-18

**The initial source audit was completed before the grouped implementation below.** This pass found **17 source-confirmed differences in production paths, grouped into 10 implementation batches**, plus **2 CI/evidence fixes** and **1 conditional admin-extension security issue**. These are distinct findings, not a claim that exactly 17 patches finish parity.

Baseline: headscale-go **v0.29.5**, commit `0f7d1e536bed9f01dd7161f7637af19bb0908335`, verified from the module-cache origin record. Final comparisons use the immutable module cache and selected Go1.26.9 sources. The older sibling Go checkout was excluded.

Method: parallel source review and historical evidence inspection. No tests, builds, product execution, probes, validators, fixture recapture, dependency updates or fresh advisory scans. Source-reviewed controls are not an authentication-bypass proof or runtime qualification. All three existing acceptance gates remain open.

## Initial grouped implementation update — 2026-10-18

All ten audit batches now have source changes from parallel file ownership.
At that milestone, **13 findings had selected source implementations and four remained partial**. The parallel follow-up below supersedes the named gaps in this table:

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
ran. All three acceptance gates remain open.** The six scope decisions and
Q1–Q6 qualification matrix below still apply. Historical evidence predates these
changes. The original findings and source snapshot below describe the audit
baseline; they are retained for traceability, not current unresolved-code counts.

## Parallel follow-up to the partial findings — 2026-10-18

The native DERP path now owns a complete signed64/null model independently of
public compatibility structs. JSON/YAML and embedded configuration, startup,
refresh, map frames, bootstrap DNS, debug maps/config and counts retain that
owner. Bootstrap/debug null dereferences return the selected Go recoverer status
without a Rust panic. Native URL fetches now use the existing Go-profile
transport with total body timeout/Close and actual-protocol User-Agent.

DNS event wakeups now cover Linux/Android and nix-supported BSD/Apple targets; remaining
platforms retain content polling. Merged main-listener request logging and
spawned Noise/DERP upgrade lifetimes now share one event owner. ACME observation
also covers parsed URI rejection before backend construction. Independent
source peers reviewed these changes; no execution was performed.

The remaining header-capacity fix is prepared as an exact http1.4.0 source patch
at `tools/parity/patches/http-1.4.0-native-header-capacity.patch`. Applying it needs
a local dependency source override and Cargo.lock source change. That action is
pending the existing user question about the no-resolution-change constraint;
**the patch is not applied and the current HeaderMap limit remains**.

The next parallel source batch adds a private finite DERP YAML receiver using
the existing granit parser. It retains UTF-16/BOM input, YAML1.1 directives,
scalar styles/tags, legacy booleans, integer bases and selected float-to-int
assignment, null pointers/keys, duplicate fields, merges and typed alias-expansion
accounting before canonical allocation. The shared CLI YAML facade is unchanged.
JSON type errors now retain Go target/field/literal text and value-before-map-key
error ordering. Native nonfinite-number errors follow Go text and lexical
map-key traversal; native debug output uses Go HTML/line-separator escaping.
Original yaml.v3 licenses and source pins accompany this source adaptation.

Other residuals include unsupported event platforms, granit versus Go YAML
scanner/parser grammar and detailed aggregated diagnostics, invalid binary-string
projection, unestablished float-to-int behavior on other architectures, backend
errors and Go nondeterministic text ordering. Logging still counts body polls
rather than the return value of Go ResponseWriter.Write; socket-byte counters
cannot substitute for that buffered application-write contract. Physical I/O and
cancellation phases, and S01–S06/Q1–Q6 remain unqualified. Public narrow projection helpers are compatibility
views, not native identity storage. Tests/builds remain paused, no dependency
version/resolution changes were made, and all three acceptance gates stay open.
The header proposal now includes activation/lock/container-license changes and
an input-hash record; it remains unapplied pending the existing user question.

## Recommended implementation batches

| Order | Batch | Findings | Work |
|---|---|---|---|
| 1 | B1 | F01, F02 | Registration flow and Followup URL handling |
| 2 | B2 | F03, F04, F05 | OIDC persisted identity/profile normalization |
| 3 | B3 | F06 | OIDC callback query receiver |
| 4 | B4 | F07, F08 | DNS external-record reload and JSON receiver |
| 5 | B5 | F09, F10, F11 | DNS resolver/NextDNS projection |
| 6 | B6 | F12 | DERP configuration/source loading |
| 7 | B7 | F13 | Native issuer URL validation |
| 8 | B8 | F14 | Native HTTP response profile |
| 9 | B9 | F15, F16 | Frozen H1 ownership follow-up |
| 10 | B10 | F17 | Native diagnostic events |

Execute the application batches together with parallel file ownership: B1–B3 share registration/OIDC ownership; B4–B5 share DNS ownership; B6–B7 share config/DERP ownership; B8–B9 share transport ownership; B10 and assurance changes follow their stable APIs. Review the combined state, then perform one final qualification phase. Resume implementation only after this audit handoff; this report does not start another serial leaf-fix loop.

## Confirmed production source differences

### F01 · P1 · Followup loses precedence to a supplied auth key

A registration carrying both Followup and Auth.AuthKey can redeem the key instead of waiting for its existing interactive authorization.

**Evidence:** Rust [register.rs:345](/Users/androolloyd/Development/headscale-rs/headscale-api/src/tailscale_wire/register.rs:345), [register.rs:374](/Users/androolloyd/Development/headscale-rs/headscale-api/src/tailscale_wire/register.rs:374); pinned Go [auth.go:129](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/auth.go:129).

**Batch B1:** Select Followup after existing-node handling and before auth-key redemption, matching pinned handler order.

### F02 · P2 · Followup URL/path grammar differs

Escaped paths and extra path prefixes can produce different registration-ID acceptance and errors. Machine binding is a separate control and remains present.

**Evidence:** Rust [register.rs:1358](/Users/androolloyd/Development/headscale-rs/headscale-api/src/tailscale_wire/register.rs:1358); pinned Go [auth.go:309](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/auth.go:309).

**Batch B1:** Use native Go URL parsing, decoded Path and selected registration-ID transformation together with F01.

### F03 · P1 · OIDC provider identifier serialization differs

Manual URL splitting can persist a different provider_identifier, changing imported account lookup, owner continuity and policy references. Example source projection: a space in a subject is escaped by Go URL.String and left raw by Rust.

**Evidence:** Rust [oidc.rs:2803](/Users/androolloyd/Development/headscale-rs/headscale-api/src/oidc.rs:2803), [oidc_registration.rs:87](/Users/androolloyd/Development/headscale-rs/headscale-db/src/users/oidc_registration.rs:87); pinned Go [users.go:367](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/types/users.go:367).

**Batch B2:** Port the selected CleanIdentifier parse/clean/serialize behavior at the native identity boundary without changing public field types.

### F04 · P1 · OIDC email admission differs

The simple rsplit-at/no-whitespace check accepts malformed values such as a@@example.com that Go mail.ParseAddress rejects; the result enters persisted user/profile and policy identity state.

**Evidence:** Rust [oidc.rs:3473](/Users/androolloyd/Development/headscale-rs/headscale-api/src/oidc.rs:3473); pinned Go [users.go:442](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/types/users.go:442).

**Batch B2:** Implement selected mailbox parsing/admission and preserve original accepted claim text as Go does.

### F05 · P2 · OIDC username character categories differ

Rust Unicode alphabetic/numeric predicates and first-character handling differ from the selected Go byte-first check plus IsLetter/IsDigit. Persisted name and policy-alias outcomes can differ.

**Evidence:** Rust [oidc.rs:3443](/Users/androolloyd/Development/headscale-rs/headscale-api/src/oidc.rs:3443); pinned Go [dns.go:41](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/util/dns.go:41).

**Batch B2:** Share one pinned native username predicate for OIDC profile publication; do not infer Go categories from Rust generic predicates.

### F06 · P2 · OIDC callback repeated-query handling differs

Serde struct extraction rejects repeated code/state before the handler; Go URL.Query().Get selects the first value. This changes acceptance/status, with no demonstrated authentication bypass.

**Evidence:** Rust [oidc.rs:822](/Users/androolloyd/Development/headscale-rs/headscale-api/src/oidc.rs:822), [mod.rs:13257](/Users/androolloyd/Development/headscale-rs/headscale-api/src/tailscale_wire/mod.rs:13257); pinned Go [oidc.go:460](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/oidc.go:460).

**Batch B3:** Decode native callback queries using selected first-value/escape rules while retaining state, nonce and CSRF checks.

### F07 · P1 · DNS extra-record changes can remain stale

The five-second watcher only reloads on changed mtime. A write preserving mtime can be missed indefinitely; Go reacts to write/create/chmod and re-establishes replacement watches.

**Evidence:** Rust [dns.rs:1332](/Users/androolloyd/Development/headscale-rs/headscale-api/src/dns.rs:1332), [dns.rs:1352](/Users/androolloyd/Development/headscale-rs/headscale-api/src/dns.rs:1352); pinned Go [extrarecords.go:92](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/dns/extrarecords.go:92).

**Batch B4:** Replace mtime-only admission with equivalent event/rewatch semantics and content-aware recovery in one file-reload batch.

### F08 · P1 · DNS extra-record JSON receiver differs

Root null, empty objects, case-folded field names, null strings and duplicate-last assignment differ from Go decoding; supported startup/reload files can be rejected.

**Evidence:** Rust [dns.rs:390](/Users/androolloyd/Development/headscale-rs/headscale-api/src/dns.rs:390), [dns.rs:1294](/Users/androolloyd/Development/headscale-rs/headscale-api/src/dns.rs:1294); pinned Go [extrarecords.go:231](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/dns/extrarecords.go:231).

**Batch B4:** Apply selected Go JSON receiver semantics to file-backed records together with watcher changes, preserving empty/transient-read behavior.

### F09 · P2 · Configured DNS resolver URL validation is incomplete

Rejecting only SocketAddr accepts malformed URL input such as https://% that Go ignores. Both global and split resolver projection are affected.

**Evidence:** Rust [dns.rs:1146](/Users/androolloyd/Development/headscale-rs/headscale-api/src/dns.rs:1146); pinned Go [config.go:934](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/types/config.go:934), [config.go:964](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/types/config.go:964).

**Batch B5:** Use ParseAddr-or-successful-Go-URL admission and selected diagnostics for both resolver paths.

### F10 · P2 · NextDNS query parsing/encoding differs

Malformed escape and semicolon pairs are retained, and invalid decoded bytes are replaced by UTF-8 lossiness, whereas Go Query/Encode drops malformed pairs and preserves decoded bytes.

**Evidence:** Rust [dns.rs:996](/Users/androolloyd/Development/headscale-rs/headscale-api/src/dns.rs:996), [dns.rs:1008](/Users/androolloyd/Development/headscale-rs/headscale-api/src/dns.rs:1008); pinned Go [mapper.go:245](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/mapper/mapper.go:245), [url.go:959](/Users/androolloyd/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.darwin-arm64/src/net/url/url.go:959).

**Batch B5:** Reuse a byte-preserving native query parser/encoder rather than another bespoke string implementation.

### F11 · P1 · Nil Hostinfo changes NextDNS device_model

Imported NULL Hostinfo is projected to an empty OS and then overwrites/adds device_model; Go leaves that query key alone when Hostinfo is invalid.

**Evidence:** Rust [map.rs:297](/Users/androolloyd/Development/headscale-rs/headscale-api/src/tailscale_wire/map.rs:297); pinned Go [mapper.go:259](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/mapper/mapper.go:259).

**Batch B5:** Retain Hostinfo presence through requester projection and update metadata conditionally.

### F12 · P1 · DERP URL/map loading has different admission rules

Invalid configured URLs abort rather than log-and-skip; error-status bodies containing valid maps are rejected; lowercase JSON regions is missed; YAML region defaults/mismatches are changed or rejected rather than preserving decoded values.

**Evidence:** Rust [derp_config.rs:142](/Users/androolloyd/Development/headscale-rs/headscale-cli/src/derp_config.rs:142), [derp_config.rs:177](/Users/androolloyd/Development/headscale-rs/headscale-cli/src/derp_config.rs:177), [derp_config.rs:517](/Users/androolloyd/Development/headscale-rs/headscale-cli/src/derp_config.rs:517), [derp_config.rs:569](/Users/androolloyd/Development/headscale-rs/headscale-cli/src/derp_config.rs:569); pinned Go [config.go:748](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/types/config.go:748), [derp.go:18](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/derp/derp.go:18), [derp.go:43](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/derp/derp.go:43).

**Batch B6:** Implement one native DERP source-loading adapter covering URL admission, status/body handling and selected JSON/YAML receiver semantics.

### F13 · P2 · OIDC issuer configuration uses different URL grammar

WHATWG parsing trims inputs including leading control/space that Go URL parsing rejects during configuration, changing failure phase or optional-provider fallback.

**Evidence:** Rust [config.rs:395](/Users/androolloyd/Development/headscale-rs/headscale-core/src/config.rs:395); pinned Go [config.go:375](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/types/config.go:375), [url.go:432](/Users/androolloyd/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.darwin-arm64/src/net/url/url.go:432).

**Batch B7:** Add strict native validation/projection at the production configuration boundary; preserve generic embedding behavior and public signatures.

### F14 · P1 · Native HTTP response-header profile is still Hyper default

Native ACME clients retain H1 100-header and 417792-byte buffer limits and H2 16-KiB header-list limits versus Go default 10-MiB response-header budget. H1 obsolete folded-header acceptance also differs.

**Evidence:** Rust [lib.rs:230](/Users/androolloyd/Development/headscale-rs/vendor/instant-acme/src/lib.rs:230), [role.rs:31](/Users/androolloyd/Development/headscale-rs/vendor/hyper/src/proto/h1/role.rs:31), [io.rs:23](/Users/androolloyd/Development/headscale-rs/vendor/hyper/src/proto/h1/io.rs:23), [client.rs:52](/Users/androolloyd/Development/headscale-rs/vendor/hyper/src/proto/h2/client.rs:52); pinned Go [transport.go:329](/Users/androolloyd/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.darwin-arm64/src/net/http/transport.go:329).

**Batch B8:** Configure one native H1/H2 response-header/parser profile with the pinned budget/grammar; keep ordinary Hyper defaults unchanged.

### F15 · P2 · Implicit H1 body drop publishes retirement late

Incoming drops its channel before its consumer guard publishes Early. A concurrent driver can perform a small opportunistic drain before seeing retirement; the separate driver verdict still blocks reuse.

**Evidence:** Rust [incoming.rs:55](/Users/androolloyd/Development/headscale-rs/vendor/hyper/src/body/incoming.rs:55), [dispatch.rs:295](/Users/androolloyd/Development/headscale-rs/vendor/hyper/src/proto/h1/dispatch.rs:295); pinned Go [transport.go:3092](/Users/androolloyd/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.darwin-arm64/src/net/http/transport.go:3092).

**Batch B9:** Publish the selected early-drop verdict before channel destruction using a coherent private ownership change; retain explicit Close and pool acknowledgement.

### F16 · P2 · Closed H1 EOF can wait for an unnecessary write deadline

go_finish_eof can enter flush/50-ms writer wait for a connection already known nonreusable/closed. Go alive=false short-circuits wroteRequest and acknowledges read-loop exit.

**Evidence:** Rust [dispatch.rs:121](/Users/androolloyd/Development/headscale-rs/vendor/hyper/src/proto/h1/dispatch.rs:121); pinned Go [transport.go:2456](/Users/androolloyd/go/pkg/mod/golang.org/toolchain@v0.0.1-go1.26.9.darwin-arm64/src/net/http/transport.go:2456).

**Batch B9:** Decide nonreuse before writer waiting and preserve the bounded wait only for eligible reuse.

### F17 · P2 · Native startup/request/ACME diagnostic events remain different

Missing selected startup version/minimum-version fields, insecure remote-gRPC warning, per-request events and per-attempt ACME failure/status/body events. The three TLS scheme warnings already have implementations and are excluded.

**Evidence:** Rust [server.rs:337](/Users/androolloyd/Development/headscale-rs/headscale-cli/src/server.rs:337), [server.rs:2106](/Users/androolloyd/Development/headscale-rs/headscale-cli/src/server.rs:2106), [mod.rs:13584](/Users/androolloyd/Development/headscale-rs/headscale-api/src/tailscale_wire/mod.rs:13584), [lazy.rs:368](/Users/androolloyd/Development/headscale-rs/headscale-cli/src/acme_issuer/lazy.rs:368); pinned Go [app.go:640](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/app.go:640), [app.go:805](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/app.go:805), [app.go:1236](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/app.go:1236), [app.go:1279](/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.5/hscontrol/app.go:1279).

**Batch B10:** Implement a single native event/logging contract, preserving provider response bodies and sensitive-data handling, then compare output once after implementation batches.

## CI and evidence changes

### A01 · Real-client PR/push filters omit seven vendored HTTP/TLS packages

Only vendor/sqlx-core and vendor/sqlx-postgres are included. A change confined to h2, Hyper, Hyper-util, HyperRustls, Rustls, aws-lc-rs or instant-acme can skip the path-filtered real-client workflow; scheduled/manual execution remains configured.

Evidence: `.github/workflows/real-client-parity.yml:6,20`.

Cover every production vendor patch in the workflow trigger/enforcement metadata in one CI change.

### A02 · Historical paired reports do not establish the frozen source state

Inspected reports contain Go version/case results but no source-tree/dirty-diff or binary fingerprint sufficient to bind current WIP and all local vendor patches. The old passing reports are useful historical evidence, not qualification of this freeze.

Evidence: `target/real-client/cli-admin-output-diff-1792241585-14078/report.json; configtest-postgres-v0295-1792235510-13248/report.json; oidc-startup-deadline-1792244012-57734/report.json`.

Have the final qualification run record source, vendor, binary, toolchain, platform, feature and backend fingerprints with paired results.

## Security and optional extensions

### X01 · Optional admin JSON mutation routes accept cookie sessions without CSRF validation

guard_api accepts an authenticated session; JSON mutation handlers such as api_machines_expire do not call check_csrf, and read_json does not enforce JSON Content-Type. HTML forms do have CSRF checks. SameSite=Lax limits cross-site requests, but does not replace a same-site/untrusted-sibling origin check. This is a conditional exposure to investigate/repair when admin::router is mounted, not a demonstrated native serve authorization bypass.

Native serve production_extra_routes mounts the upstream grpc_gateway router, not this optional GUI router (headscale-cli/src/server.rs:2019).

Evidence: `headscale-api/src/admin/mod.rs:387`, `headscale-api/src/admin/mod.rs:959`, `headscale-api/src/admin/mod.rs:1642`, `headscale-api/src/admin/auth.rs:137`.

Require an explicit anti-CSRF/origin/content-type contract for session-authenticated extension mutations, preserving bearer-only upstream gateway behavior.

### X02 · Local vendor/crypto maintenance and current advisory status are unqualified

Nine locally patched packages are selected by root Cargo.toml. Original pins/licenses/provenance are retained, but upstream security fixes will need deliberate comparison against local changes. CI config contains advisory/license/source jobs and a lockfile-only RUSTSEC-2023-0071 exception; those files are not evidence of a current clean graph or a security audit. Custom native TLS/JSON/PEM/bcrypt/HTTP/SQL adapters need focused review and final feature/backend validation.

Production native server, ACME, OIDC and database paths; optional extensions separately.

Evidence: `Cargo.toml:36`, `.github/workflows/supply-chain.yml:19`, `deny.toml:1`, `docs/HARDENING.md:1`.

Perform the fresh dependency/advisory and vendor-delta security qualification in the final authorized validation phase. No new dependency versions or advisory claims in this audit.

## Compatibility decisions and narrower surfaces

These remain visible in a full replacement claim. They need a native representation or an explicit scope decision; they should not silently turn into an endless list of unrelated standard-library patches.

- **S01 — OIDC/Noise resource-policy differences.** OIDC discovery/UserInfo/JWKS have a 1-MiB cap; callbacks have a 128-permit limit; provider calls use 30-second deadlines; crypto workers are bounded. Noise also imposes a full-body deadline. These are deliberate bounds, not proof of Go-equivalent acceptance/timing. OAuth token response prefix limiting is separately Go-shaped. Resolve/document the compatibility policy instead of silently removing hardening. Evidence: `headscale-api/src/oidc.rs:1555,1811,2015,2123,2650; tailscale_wire/noise.rs; selected Go hscontrol/oidc.go`.
- **S02 — DERP IDs exceed current public u16 representation.** SourceDerpMap and public DERP projection cannot represent IDs such as 70000 that the selected Go int representation can hold. Requires an additive native wide-ID design under the public-field compatibility constraint. Evidence: `headscale-cli/src/derp_config.rs:181,499; selected tailcfg/derpmap.go`.
- **S03 — Raw byte/path/error representation.** Non-UTF-8 secret paths/content/environment and lower URI/DNS/TLS/OS error identities remain different or unqualified. Separate reachable native input support from generic custom driver/error surfaces. Evidence: `headscale-cli/src/config/secret_file.rs:32; headscale-db/src/lib.rs:418; vendor provenance residual sections`.
- **S04 — Cross-runtime default HTTP pool sharing.** Native ACME accounts share within a production runtime; this does not provide Go process-wide DefaultTransport ownership across multiple Rust runtimes. Normal single-runtime serve and arbitrary embedding should have separate acceptance statements. Evidence: `vendor/instant-acme/src/lib.rs:224; vendor/instant-acme/UPSTREAM.md`.
- **S05 — Go runtime observability is substituted, not implemented.** The /debug/pprof profile/trace handlers return Rust informational text, and symbol returns num_symbols:0. They are not a Go pprof CPU/heap/trace implementation. Choose useful tooling-compatible Rust profiling or explicitly exclude these runtime-specific endpoints from exact replacement claims. Evidence: `headscale-api/src/tailscale_wire/basic_handlers.rs:502,515,524,533,3125`.
- **S06 — Generic Postgres driver corners are not all Headscale requirements.** Custom codecs/explicit prepare/execute_many, missing FunctionCallResponse/CopyBoth variants, arbitrary ReadyForQuery statuses and invalid-byte metadata differ or remain unqualified. Concrete example: Rust rejects unknown transaction status while selected pgproto3 stores its byte. No normal Headscale SQL producing these backend messages was established. Cancellation/async cleanup differs at driver level; upstream ordinary DB mutations do not thread request contexts, and Rust durable mutations are shielded, so production reachability must be shown before treating every driver difference as a release blocker. Evidence: `vendor/sqlx-postgres/src/message/ready_for_query.rs:27; message/mod.rs:96; connection/mod.rs:192; headscale-db/src/lib.rs:572; selected pgproto3/ready_for_query.go:17; hscontrol/db/db.go:1185`.

## Database and final qualification matrix

The original beta-stamp concern is superseded: [version_guard.rs:15](/Users/androolloyd/Development/headscale-rs/headscale-db/src/version_guard.rs:15) targets `v0.29.5`. Production Postgres adapters/pool wiring exist; the generic `Database` type remaining SQLite-only is not evidence that production Postgres is absent. Existing paired imports/reopens are bounded historical evidence. This pass did not establish a new ordinary CRUD/schema defect; recovery and broader mutation/restart equivalence remain unqualified.

SQLite startup backs up before conversion, keeps Rust-only data in a sidecar, and isolates migration sessions. Postgres startup serializes cooperating Rust migrations and publishes final markers transactionally. These source controls do not prove interrupted/failed/mixed-version recovery: [sqlite_legacy_upgrade.rs:110](/Users/androolloyd/Development/headscale-rs/headscale-db/src/sqlite_legacy_upgrade.rs:110), [version_guard.rs:376](/Users/androolloyd/Development/headscale-rs/headscale-db/src/version_guard.rs:376), [lib.rs:630](/Users/androolloyd/Development/headscale-rs/headscale-db/src/lib.rs:630).

| Gate | Area | Required final evidence |
|---|---|---|
| Q1 | Frozen implementation build/feature matrix | Current workspace, admin/full, wire-only, H1-only/H2-only native/default combinations and selected crypto/backend profiles; sibling Octra wire-only integration remains a distinct boundary. |
| Q2 | Pinned functional behavior | Refresh paired policy/ACL/SSH fixtures and stock-client registration, lifecycle, routes, DNS, map-stream omission/churn and revocation behavior on the final source state. |
| Q3 | Database/drop-in and recovery | SQLite and Postgres fresh/imported v0.28/v0.29 historical shapes, Rust-to-Go and Go-to-Rust reopen, keys/users/routes/sessions, mutation/restart, sequence/NULL/timestamp state, interrupted migration, failed/ambiguous commit/rollback and sidecar/backup recovery. |
| Q4 | Process/CLI/transport | Final exact CLI/error/startup output, configured gRPC/Unix/TLS/ACME/provider/DNS/DERP listener topology, HTTP framing/body/header/cancellation and shutdown cases; existing source adapters are not runtime proof. |
| Q5 | Security/package/container | Current active dependency/advisory/license graph, default isolation, vendor patches and crypto boundary, package contents, CA behavior, both container recipes and operator-facing exposure. |
| Q6 | Evidence identity | One final paired qualification packet bound to exact source/vendor/binary/toolchain/feature/platform/backend fingerprints; preserve failed cases and unknowns. Do not infer completion from scenario counts. |

No qualification commands were run. The backlog remains **two P0s and one P2**: release behavior/drop-in qualification, broader Postgres process mutations/restarts, and CLI output/error residuals. The policy fixture item is historically complete and is not a fourth open backlog gate; refresh it against final source as part of Q2.

## Coverage and findings ruled out

| Area reviewed | Result of this source pass |
|---|---|
| Policy / ACL / grants / SSH compilation | No additional definite code gap established. Selected receiver paths, self/exit/capability compilation and cached runtime were inspected; final execution remains required. |
| Map / peer / route / lifecycle | No additional definite code gap established after checking the pinned v0.29.5 source. Connect/disconnect, expiry, deletion, epochs, GC and incremental projection remain subject to concurrency qualification. |
| Auth / OIDC / SSH / Noise | F01–F06. Source traces retain machine binding, SSH owner/pair/single-use/current-policy/epoch controls, and OIDC signature/issuer/audience/time/nonce, subject-matched UserInfo and confirmation-CSRF controls. No additional broad bypass was established. |
| DNS | F07–F11 cover reload, decoding and resolver/requester projection. |
| CLI / startup / DERP / transport | F12–F17, with scope decisions retained separately. |
| Storage / import / Postgres | Current v0.29.5 marker and production wiring confirmed; Q3 is still open. Rare custom/protocol driver differences are S06 rather than an assertion every Headscale mutation is missing. |
| Gateway / admin / deployment / dependencies | Native upstream gateway and remote gRPC require API keys; local Unix authentication bypass is an intentional socket-permission boundary. X01 concerns a separately mounted extension; X02 and A01–A02 remain. |

Ruled out or already implemented: native TLS DERP fast-start is intercepted in [raw_tls.rs:350](/Users/androolloyd/Development/headscale-rs/headscale-api/src/tailscale_wire/raw_tls.rs:350); the `derp.rs` 501 branch is a plaintext/synthetic fallback. Approved-exit PeerCapMap behavior, grant/self grouping, native TLS EOF selection and the three selected TLS scheme warnings already have source implementations. Do not reopen them from older append-only residual notes.

Still unknown: complete malformed H1/H2/HPACK/TLS/SQL/JSON cross-products, lower provider/OS error identity, all custom embedding profiles and current advisories. This audit inventories concrete work and qualification boundaries; it does not prove those unknowns correct or label all of them missing application code.

## Frozen source identity

- Source digest: `3664d9a147f6ba40f27849c39c62b390066e226ef439fe985d84b32333962775`.
- Files fingerprinted: **868** across the listed production source/manifests and CI roots; hashing does not mean every file received line-by-line review.
- Construction: sorted repository-relative path, NUL, per-file SHA-256, newline; SHA-256 over the resulting byte stream. Documentation is excluded to avoid self-reference.
- Full machine-readable findings, source anchors and included roots: [audit JSON](/Users/androolloyd/Development/headscale-rs/docs/headscale-v0295-remaining-audit-2026-10-18.json:1).

**Outcome:** the grouped source batch is saved and reviewed within the limits above. Full replacement parity remains incomplete; the four partial source findings, six scope decisions and final qualification gates remain. Testing is paused.

Final bounded source peer passed the private YAML typed assignments, merge-key
identity and alias-budget traversal on the recorded source hash. No actionable
source issue was found in that review; parser/platform/diagnostic and runtime
qualification boundaries above remain. No execution was performed.

## Combined method admission, diagnostics and evidence follow-up — 2026-10-18

The subsequent grouped source pass adds **F18**, a native method/path admission
difference found during the logger review. Axum's implicit HEAD-to-GET dispatch
could invoke authentication GET handlers that pinned chi rejects. Native control
routes now check selected methods before dispatch, return empty 405 responses
with separate Allow values, mount the root GET explicitly, return native unknown
path 404s, and omit DERP probe/bootstrap routes when the server is disabled.
The explicit ping HEAD and any-method DERP routes retain their selected behavior.
Public embedding behavior and option fields remain unchanged. This is a bounded
method/path fix; escaped-path, transport framing and logging qualifications remain.

The private YAML traversal now collects finite type/duplicate errors with source
lines and selected Go type/tag text, continues in decoder order, and allows later
fatal tag/alias/merge errors to supersede saved errors. That supersedes the named
missing finite diagnostic aggregation above. Go parser/scanner wording, arbitrary
invalid-byte text and unestablished architecture behavior remain qualified.

A02's source fingerprint now includes both container recipes, Docker ignore,
both Rust toolchain filename variants and local Cargo build configuration when
present. It remains a packet inventory rather than a per-row execution receipt.

F07's remaining event-backend platforms are outside the evidenced Linux
CI/deployment target; the native CLI currently contains unconditional Unix APIs.
The locked dependencies offer no safe Windows directory-change or Solaris FEN
file-association facade under the workspace's unsafe-code policy. No speculative
OS port was added. Existing Linux/Android and BSD/Apple backends remain unexecuted.

Source changes and independent bounded source reviews only. All three acceptance
gates remain open, tests/builds remain paused, and the http source override is
still unapplied at that milestone.

The user subsequently answered **“upgrade deps”**, authorizing dependency version
and resolution changes. Compatible registry updates are applied, and the header
capacity feature is rebased onto http1.5.0 and bound in the root lockfile. Existing
transport patches are retained on h2 0.4.20, Hyper1.12.0, Hyper-util0.1.21 and
Hyper-rustls0.27.10. SQLx's socket2 pin is0.6.5, allowing Tokio1.53.3. The root
and both standalone wire-only harness lockfiles are updated; the latter resolve
registry transports and do not constitute native CLI transport evidence.
The earlier pending question is resolved; the original
http1.4.0 proposal is retained as superseded history. Tests/builds remain paused.
The exact lock deltas, vendor bindings and source boundaries are recorded in
`docs/headscale-dependency-upgrade-2026-10-18.json`. Cargo resolution and source
review do not establish runtime, database, security or full replacement parity.

All five transport source rebases are now frozen after bounded independent
reviews. The final h2 upgrade repair retains native HEAD state and Go's final
response Content-Length sanitation; default/server validation is unchanged.
This completes the source/resolution batch, with all three acceptance gates
still open and no builds/tests performed.

## Execution pass — 2026-10-24 (first build and test of the frozen tree)

The statements above that tests and builds were paused describe the state at the
time they were written. On 2026-10-24 the frozen working tree (uncommitted, on
`fix/reregister-same-node-key`) was built and run for the first time. This
section records what that found. It does not close the acceptance gates: the
results below bind to the working tree of that day, not to a committed source,
vendor and binary fingerprint (finding A02 still stands).

### What the first build found

The tree did not compile. Fixes were needed in the vendored crates and in two
workspace crates before anything could run: `pin-project-lite` cannot put
`#[cfg]` on struct fields (two Hyper structs), the vendored aws-lc-rs key-size
accessor, h2 error handling and a borrow in the stream send path, the
instant-acme Send/Block fields, and the SQLx chrono/HRTB and timestamp-binding
changes. Once it compiled, 196 tests failed against 0 at committed HEAD
(2010 passing). Most were stale expectations (HEAD-era text, hand-edited
snapshots, fake short keys that Go's typed keys also reject). A minority were
real defects. Every disagreement was settled against the real headscale-go
v0.29.5 binary (built offline from the module cache and run as an oracle: CLI,
gRPC, HTTP gateway, policy checks, a registration-level Go harness) rather
than by reading Rust.

### Real defects found and fixed

- `grpc-go` clients over a unix socket were reset by h2, which rejected the
  percent-encoded `:authority`. The vendored h2 now exposes it as `Host` behind
  `go-server-lifecycle`.
- The HTTP gateway returned 500 for a bad bearer token; Go returns 401 with a
  plain `Unauthorized` body. gRPC returns `Internal "validating token"`.
- gRPC `SetPolicy`, `CheckPolicy` and the DB policy reload used the non-native
  policy parser, so error text differed from Go. They now use the native bytes
  parser.
- Go runs `State.AutoApproveRoutes` after registration on three paths (auth
  key, OIDC callback, gRPC `RegisterNode`). Rust ran it on none of them:
  autoApprovers never applied at registration. Fixed on all three, plus the
  volatile web-registration completion, with tests that fail without the fix.
- `ListNodes` omitted approved exit routes for offline and expired nodes.
- `/debug/routes` returned approved routes in announcement order; Go sorts with
  `netip.Prefix.Compare`.
- `serve` panicked on any `derp.urls` fetch because rustls had no process-level
  crypto provider with this crate's feature set. The provider is now installed
  at process start.
- Smaller items: `unknown field: "x"` wording, first-only reserved-range
  overlap in `ip_pool`, config-relative path joining and cleaning, a top-level
  `unix_socket` dropped when a `server:` block existed, log lines Go does not
  print (and one it does), the `derp.server.stun_listen_addr` fatal wording,
  `null` timestamps in `nodes list` and gateway bodies, the `/register/{id}`
  invalid-id body (`invalid auth id`), and the no-config warning timestamp
  (`Z` for UTC).

### Evidence

- `cargo test --workspace --all-targets --no-fail-fast`: 2114 passed, 0 failed,
  1 ignored (35 suites). Stable-toolchain runs of the CI jobs that are not part
  of that command also pass: wire-only and admin `headscale-api` lib tests, the
  gateway e2e target, the excluded crates, and the harness `cargo check`.
- `cargo clippy --workspace --all-targets -- -D warnings`, the three extra
  `headscale-api` configurations CI runs, and the excluded crates are clean on
  both the default nightly and stable 1.95; `cargo fmt --all --check` is clean.
  About 190 pedantic/nursery findings were cleared without blanket allows. The
  dead-code findings were each traced: refactor leftovers were removed, and the
  two that were real lost behaviours are the auto-approval gap and the DERP
  provider panic above.
- `scripts/headscale_go_diff.sh`: all 104 checked-in scenarios match Go and the
  golden file.
- Stock `tailscale/tailscale:v1.94.1` clients against the Rust wire harness:
  33 rows pass in the final run on the final tree (and the remaining tag, route-primary, route-via, ACL and exit-node rows passed in earlier batches on slightly earlier trees) (authkey and relogin family, randomize client
  port, ping, web-register family including route approval and restart, OIDC
  family including restart and route approval, online/last-seen, node-key
  expiry clear, restart persistence, tag rows, taildrop capmap, private DERP,
  ACL rows, route rows).
- Not a Rust failure: the MagicDNS, extra-records, DNS-edge and SSH rows cannot
  pass in this Docker environment (the container client cannot read the OS DNS
  configuration, and `tailscale ssh` exits 143); `magicdns` and `ssh` fail the
  same way against real headscale-go. The SSH-OIDC rows could not build their
  mock-OIDC helper because a pinned Go module contains test-data file names
  that macOS rejects.
- Postgres-backed smoke rows were not run in this pass (run on 2026-10-25;
  see "Evidence-gap pass" at the end).

### Residual differences (not fixed)

- `GET /api`, `/api/` and the trailing-slash `/api/v1/user/` without auth give
  404 where Go gives 401 (axum route matching does not backtrack).
- `GET /ts2021` without an upgrade gives 400; Go gives 500.
- JSON key order in gateway bodies is alphabetical; Go follows proto field order.
- `headscale version` prints the crate version rather than v0.29.5.
- DERP files are read at config load; Go reads them at serve.
- `serve` starts with an empty initial DERP map; Go aborts with
  `initial DERPMap is empty`.
- Rust rejects a certificate without a key and malformed listen addresses
  earlier in `serve` than Go does.
- Bypass-database CLI paths omit Go's `Opening database` INF line; pgx-specific
  Postgres connect error text differs.
- A registration whose IP collides now fails with the SQLite unique-index error
  wrapped as a storage error (Rust-only index; Go has none and never takes a
  caller-supplied IP).
- The DB-only rename fallback (no wire registry attached; not the production
  wiring) does no given-name validation.
- ~~The parity harness's Rust side uses its own filter compiler.~~ Fixed
  2026-10-25: it now reads the production compiler (see "Evidence-gap pass").
- The node-deletion change reason label is `peers removed` where Go says
  `node removed`; nothing externally visible depends on it.
- `route-via-same-tag` is nondeterministic by design. The two HA routers
  register concurrently and the first one online becomes primary (Go's
  `electPrimaryRoutes` keeps the previous primary and otherwise takes the lowest
  NodeID), while the row hard-codes client-1 as the owner. It passed 1 of 3
  runs on the final tree; in the failing runs the netmap showed client-2 as
  primary and client-1 as non-primary, with both routers approved. It could not
  be compared against Go here because the pinned Go helper does not build on
  this host, and committed HEAD's real-client harness does not compile
  (`registration_gate` missing from its `WireState` initializer).
- Vestigial plumbing remains (`NodeStoreBoolUpdateOutcome.change`,
  `pending_native_hostinfo`); clippy does not flag it.

## Follow-up — public assessment hardening (2026-10-25)

A public assessment (tailworm.com, "Tailscale v1.104.2 and headscale v0.29.5",
tested 2026-10-22 to 2026-10-24) was reviewed for findings that apply to this
control server. Its Tailscale client findings (tailscaled SSH forwarding races,
app connectors, `serve`, the DERP client) are out of scope here. Four items
apply and were patched, each with a test that failed before the change:

- Registration-cache flooding: per-source quota and eviction order (plus a
  per-registration cap on OIDC states).
- Unbounded remote response reads and over-long error text: the `derp.urls`
  fetch and the ACME client read whole bodies without a limit and now stream
  with one; the OIDC reads were already bounded (1 MiB) and only their error
  text is shortened.
- Embedded-DERP growth: Go's `sendHistory` has no Rust counterpart, but the
  relay had unbounded same-key sessions, an O(n^2) duplicate-health fan-out,
  blocking sends on session queues, oversized frame and WebSocket message
  limits and mesh-only frames accepted from regular clients; all limited or
  corrected.
- SSH forwarding flags: headscale-go sets all three on every accepted rule with
  no way to change it; headscale-rs keeps that default and adds
  `policy.ssh.allow_*_forwarding` to clear them. This is a control-plane
  mitigation only and does not fix the client-side component the report names.

These are intentional deviations from headscale-go. Limits and caveats are in
`HARDENING.md`. The report's numbers were not independently verified.

## Evidence-gap pass — 2026-10-25 (`/health`, packet-filter parity, Postgres)

An independent review found two places where the parity claim read stronger
than the evidence, and one untested backend. Each was checked against a
headscale-go v0.29.5 binary built offline from the module cache.

### `/health` never failed

Go's `HealthHandler` pings the database (`State.PingDB`, bounded at one second)
and answers 200 `{"status":"pass"}` or 500 `{"status":"fail"}`, both bodies
ending in the newline of `json.Encoder` and both with
`Content-Type: application/health+json; charset=utf-8` plus the usual security
headers. Rust answered `pass` unconditionally (and without the newline).

Now `/health` pings through `MachineRegistrationStore::ping_database`
(overridden by the SQLite and Postgres persistent stores) under the same
one-second bound, which the gRPC `Health` RPC shares. A wire surface with no
database-backed store (the wire-only build) still always passes; the only
change there is the trailing newline.

Evidence: with the Go and Rust servers each on their own Postgres database,
the database up gives identical status line, headers (names case-folded, `Date`
dropped) and body; after `DROP DATABASE ... WITH (FORCE)` under the running
server both answer 500 `{"status":"fail"}` with identical headers and body
(`tools/parity/health_db_down_diff.sh` repeats this). Not provoked: a failing
SQLite ping against Go (an open SQLite connection survives deleting its file);
the Rust SQLite path is covered by closing the pool. Tests that fail without
the change: `basic_handlers` health tests (fail, hang, pass bytes) and, through
the production wiring, `persistent_wire_runtime_health_follows_database_connectivity`
(SQLite) and its Postgres twin. HTTP/1.1 header *case and order* differ from Go
(hyper lower-cases names); only names, values and the body are compared.

### The differential did not run production code

`tools/parity/headscale-rs` carried its own filter compiler, so "104 scenarios
match Go" said nothing about the `PacketFilter` the server emits. The Rust side
now builds a `MachineRegistry` and `PolicyStore` exactly as startup does and
reads `PolicyStore::filter_rules` and the `PacketFilters["base"]` of every node
(`tailscale_wire::map::base_packet_filter_for_node`). Rule order is compared
exactly; the lists inside a rule are compared sorted, as the Go harness prints
them, and `PARITY_FILTER_ORDER=emitted` compares them unsorted on both sides.
Result: all 104 scenarios match in both modes, over 37 non-empty global
filters, 143 per-node filters (79 non-empty) and 29 named checks. No production
difference was found. `headscale-api/tests/packet_filter_golden.rs` runs the
same code against `golden/headscale-go-v0.29.5.json` under `cargo test`
(60 scenarios compile; the 44 rejected-policy scenarios are compared on error
class by the differential only). Breaking the production per-node reduction
turns both the differential and the golden test red. The golden gained a
`node_filters` field; everything else in it is unchanged.

### Postgres stock-client rows

Postgres is the production backend and had not been run. It could not even
start: every multi-column described query failed with SQLSTATE 08P01 `invalid
message format`, because the vendored sqlx-postgres `Bind` encoder wrote the
result-format count from the parameter-format slice (an upstream 0.8.6 defect
that per-column result formats exposed). Fixed in `vendor/sqlx-postgres`
(`UPSTREAM.md`) with `headscale-db/tests/postgres_go_pool.rs`, which opens the
pool the server uses. Nothing previously opened that pool against a live
database; the `HEADSCALE_DB_POSTGRES_TEST_URL` tests are skipped when it is
unset (CI's `cargo test` never sets it), and the `postgres-*` rows print
"skipping" and exit 0 in that case, so a green row can be vacuous.

Method: `postgres:16` container, `HEADSCALE_DB_POSTGRES_TEST_URL` set,
`REAL_CLIENT_TARGETS=rust`, one `smoke-matrix.sh` invocation per row (121 rows),
stock `tailscale/tailscale:v1.94.1` clients. Go comparison: the same row with
the Go target and `HEADSCALE_GO_BIN` set to the pinned build (the default Go
row builds an unpinned commit whose module zip macOS refuses to create).

Outcome: 86 of 121 passed on the first run, which overlapped heavy compiles.
Re-running the 35 failures on a quiet machine, then again after the fixes
below, leaves **105 passing and 16 failing**. Rust-only defects found and fixed:

| Row(s) | Cause | Fix |
|---|---|---|
| (server start) | `Bind` result-format count | vendored sqlx-postgres |
| `authkey-relogin-different-user` | new node whose hostname equals another node's given name hit the unique `given_name` index (SQLite too); Go bumps `-1`, `-2` in NodeStore | resolve the name before the insert (`headscale-db`), SQLite + Postgres tests |
| `route-primary-failover`, `-sticky` | `nodes approve-routes --routes ""` sent `[""]`; cobra `StringSlice` reads it as `[]` | `routes_from_flag` |
| `derp-private`, `derp-native-restart` | sidecar `derper` always got `-verify-clients` (needs a local tailscaled), rejecting every client even with the control `/verify` URL set | pass it only when no URL is configured |
| `user-node-lifecycle-restart` | row expected the owner name to change before restart; Go (and Rust) keep the hydrated owner until restart | row pinned for both targets |
| `invalid-fqdn-peer-restart` | row script handed libpq `PGSSLMODE=false` | map to `disable`/`require` |

Rows that passed on rerun with no change (load or a build racing the merge):
`online-lastseen`, `rejected-policy-filter`, `route-primary-restart`. The 8
`ssh-oidc-*` rows and `ssh-cli-check` failed only because their mock-OIDC
helper builds that same unpinned Go commit; with `HEADSCALE_GO_BIN` they pass.

The 16 remaining failures (15 also fail against Go, so they are not Rust
regressions; the row set exercises features this local Docker/macOS setup
cannot):

- DNS (`extra-records`, `dns-edge`, `dns-hot-reload`,
  `prefix-family-v4-to-dual-backfill-magicdns-restart`,
  `web-register-policy-config-map-churn-restart` at its MagicDNS step): the
  client container "failed to fetch the DNS configuration of your device:
  getting OS base config is not supported", on both targets. The last row's Go
  run stops earlier on a row-script error (`auth ID has invalid prefix`), so it
  is not a clean comparison.
- SSH (`ssh`, `ssh-accept-env`, `ssh-localpart`, `ssh-profile-variants`):
  `tailscale ssh` exits 143 or times out on both targets.
- Identical failure text on both targets: `node-rename` and
  `policy-rename-restart` ("timed out waiting for renamed node admin row"),
  `route-health-mixed-exit-reload` and `-all-unhealthy-reload` ("expected
  approved routes [0.0.0.0/0, ::/0], got []"), `route-primary-withdraw` and
  `route-health-both-offline-reconnect` ("No such container ...-exit").
- `derp-native-websocket` fails only on Rust: it is a Rust-only row (the Go row
  is a no-op) that forces websocket DERP with `TS_DEBUG_DERP_WS_CLIENT=1`, a
  knob the pinned `tailscale/tailscale:v1.94.1` image's `tailscaled` does not contain, so
  the clients use raw DERP (`raw_allowed=2, websocket_allowed=0`). The row cannot
  pass with this client image; websocket DERP is covered by unit tests only.

These rows were not made to pass; the shared failures need either a client
image with OS DNS/SSH support or row-script fixes, and are follow-ups.

### Live-database tests that had never run

With the URL set, 11 `headscale-db` / `headscale-cli` tests failed. All were
stale expectations, each checked against the Go binary: Go's `DebugCreateNode`
registers no routes, a rename changes `GivenName` (not `Name`), a key created
with no expiration is the zero time and so already expired, `ListNodes` shows
the old owner name until restart, never-used API keys print `lastSeen: null`,
the missing-policy bypass exits 1 with the shared snapshot text, and an
auth-path update stores exit routes as given. They now pass against
`postgres:16`. The two route auto-approval tests no longer exercise approval
(nothing is advertised); stock-client route rows cover that.

### Verification on the final tree

`cargo test --workspace --all-targets`: 2185 passed, 0 failed, 1 ignored with
`HEADSCALE_DB_POSTGRES_TEST_URL` set to a live `postgres:16` (the live-database
tests included), and passing without it; `cargo clippy ... -D warnings` clean
on nightly and stable for the workspace and CI's three extra `headscale-api`
configurations, `headscale-core` clippy and tests, `cargo fmt` over the member
crates and the harness, `scripts/headscale_go_diff.sh` (sorted and
`PARITY_FILTER_ORDER=emitted`) and the golden metadata check all pass.
(`cargo fmt --all` and the excluded-crate commands cannot run from a worktree
nested inside another workspace; they were run per package, and
`headscale-core` with a temporary empty `[workspace]` table.)

### Not done / follow-ups

- `ci.yml` should run the live-Postgres tests (add a service and set
  `HEADSCALE_DB_POSTGRES_TEST_URL`); today they never run in CI.
- Rows built on `authkey-smoke.sh` (authkey and relogin families) run the
  wire-only harness, not the production binary. `authkey-relogin-different-user`
  passed there on 2026-10-24 while the production server failed the same
  scenario on Postgres, and would on SQLite (the new SQLite `headscale-db` test
  fails without the fix), so the 33-row result did not cover that path.
- The shared-failure rows above, and a client image that supports OS DNS
  configuration and `tailscale ssh`.

