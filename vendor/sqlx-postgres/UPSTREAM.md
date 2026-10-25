# SQLx-postgres provenance and local changes

This is SQLx-postgres **0.8.6**, copied from the workspace's locked Cargo
registry source. Its original crates.io archive checksum is
`db58fcd5a53cf07c184b154801ff91347e4c30d17a3562a635ff028ad5deda46`. The retained `.cargo_vcs_info.json`
identifies Git revision `bab1b022bd56a64f9a08b46b36b97c5cff19d77e`, path
`sqlx-postgres`. Upstream MIT and Apache-2.0 licenses are retained.
The adapted pgx/service/passfile MIT notices are also collected in
`LICENSE-GO-PGX`, and the x/text BSD notice in `LICENSE-GO-TEXT`. Package license
metadata now includes the additional MIT/BSD obligations. Both container
recipes retain the vendor license files under `/usr/share/licenses/headscale-rs`.
Go standard-library PEM/x509 loading is adapted from Go 1.26.9 source; its BSD
notice is retained in `LICENSE-GO-STDLIB` and included by those container copies.

The root Cargo patch changes these files:

- `src/connection/mod.rs`: `transaction_status_is_idle()` exposes the latest
  ReadyForQuery status so the pool can reject raw/failed transaction blocks.
- `src/options/go_compat.rs`: explicit native constructor with pgx v5.10.0
  defaults, environment/service precedence, pgservicefile
  `5a60cdf6a761` parsing and pgpassfile v1.0.0 lookup. Their MIT notices are
  retained in the source. It rejects unsupported advanced driver controls.
- `src/options/mod.rs`: optional native settings and constructor registration;
  ordinary constructors keep their existing environment behavior. Debug output
  redacts passwords, arbitrary runtime settings and inline TLS material.
- `src/options/go_compat/connector.rs` and `src/options/connect.rs`: the native
  host/port list, TLS/plain preference chain, per-address-group deadlines,
  target-session selection and last-nonpreferred retry. The pgx MIT notice is
  retained in the connector source.
- `src/connection/stream.rs`: dial the selected resolved address or cleaned
  Unix socket path while retaining the original hostname for TLS verification.
- `src/connection/tls.rs`: native direct TLS with PostgreSQL ALPN, SNI control
  with pgx's verify-full exception and explicit Rustls backend selection.
- `src/connection/establish.rs`: native settings provide startup parameters
  without SQLx's extra implicit timezone/encoding/float settings. Generic
  SQLx construction retains those defaults. Native authentication checks its
  method policy before sending credentials or accepting unauthenticated Ok.
- `src/message/startup.rs`, `src/message/negotiate_protocol_version.rs`,
  `src/message/mod.rs` and `src/message/backend_key_data.rs`: native 3.0/3.2/latest
  selection, implicit maximum promotion for a higher minimum, minimum checking
  on negotiation and full variable-length backend-key retention. Option counts
  are bounded by available bytes without allocating from the count. Secret
  backend-key diagnostics are redacted. Ordinary startup still requests 3.0.
- `src/options/go_compat/pem.rs`: Go's first usable PEM block, header/whitespace
  and permissive-base64 handling, DEK-Info/sslpassword legacy decryption with
  MD5/first-eight-IV-byte derivation, and DER-based key-format detection before
  certificate validation/dialing. Client certificates accept PEM headers; CA
  blocks with headers are skipped, following the distinct Go loaders.
- `src/options/go_compat/auth.rs`: pinned require_auth positive/negative-list
  parsing, duplicate/mixed-list rejection and all seven method names; three
  channel-binding modes are parsed without dropping the restriction.
- `src/options/go_compat/query.rs`, `src/connection/go_query.rs`, its `text.rs`
  and `sanitize.rs`, and `src/connection/executor.rs`: all five native query-mode
  paths, a separate description LRU, signed-32-bit cache capacities with
  nonpositive disable semantics, argument-free simple queries, cache-error
  invalidation and deferred named-statement cleanup. Native parameters are
  converted from SQLx buffers to text, while described results remain binary;
  exec/simple results are text. The generic SQLx binary path remains separate.
  Complete query/extended frames are encoded before appending to the transport,
  so conversion/encoding failure cannot queue a partial Parse/Bind cycle.
  The pgx sanitizer port preserves quoted identifiers, ordinary/E strings,
  tagged dollar strings, nested comments, placeholder overflow/usage checks,
  quote escaping and argument-boundary spaces. Parameterized simple queries
  require reported UTF8 and standard_conforming_strings=on, as in pgx.
- `src/io/mod.rs`: native automatically cached statements use pgx's
  `stmtcache_` name followed by the first 24 SHA-256 bytes in lowercase hex.
  Generic SQLx and explicitly prepared statements without a cache retain
  numeric IDs. Native preparation and close batches are staged off-transport;
  `describe_exec` reparses the original SQL after custom-type metadata queries
  can replace the unnamed statement. A drop guard retires names when
  preparation fails or is cancelled, and close IDs remain queued until the
  complete close/ReadyForQuery cycle succeeds. Explicit cache clearing uses
  that same queue. ReadyForQuery accounting rejects underflow.
- `src/message/bind.rs`: the result-format count is taken from `result_formats`,
  not `formats`. Upstream 0.8.6 counted the parameter formats, which is only
  correct while both slices have one element; the native query paths send
  per-column result formats, so every multi-column described query reached
  PostgreSQL with trailing bytes and failed with SQLSTATE 08P01 `invalid
  message format`. Covered by `headscale-db/tests/postgres_go_pool.rs`.
- `src/message/data_row.rs`, `row_description.rs`, `parameter_description.rs`,
  `notification.rs`, `copy.rs`, `src/row.rs` and `src/value.rs`: inbound counts,
  value lengths and row indices are checked before allocation/indexing, and
  only -1 denotes a NULL value. Native parameter descriptions infer OIDs from
  complete body entries, matching pgx's wrapped-count handling. Native row
  counts must match statement metadata or the query cache is invalidated.
  COPY retains SQLx's signed column-count API; its full Go count range is not
  implemented.
- `src/types/{bool,float,oid,money,json,numeric,array,record,range,bit_vec}.rs`,
  `src/types/{chrono,time}/{date,datetime}.rs` and
  `src/types/geometry/{path,polygon}.rs`: checked primitive widths, JSONB version
  errors, numeric/array/record/bit-string/geometry body bounds and checked date
  arithmetic replace unchecked reads, assertions or overflowing operations.
  Text arrays preserve quoted `"NULL"`; text records preserve Unicode and
  trailing NULL fields, and obey their binary field count. Text ranges check
  bounds, quoting and field count. Multidimensional/non-one-based SQLx arrays,
  auxiliary/custom codecs and full Go row-conversion fidelity remain open.
- `src/connection/go_auth.rs`: native SCRAM and SCRAM-PLUS, GS2 capability
  headers, 18-byte random nonces, mandatory server nonce extension, the pinned
  ten-million-iteration ceiling and constant-time server-proof verification.
  Channel binding hashes the certificate from the actual Rustls connection,
  with Go's supported RSA/ECDSA/PSS signature-hash mapping and PSS constraints.
- `src/connection/go_auth/precis.rs` and `precis/tables.rs`: OpaqueString space
  mapping, stream-safe NFC and contextual checks from headscale's pinned
  golang.org/x/text v0.38.0, using its Unicode 15.0.0 table selected by Go 1.26.
  Invalid profiles fall back to original password bytes, as in pgx. The generated
  ranges retain the source SHA-256. `tools/import-go-precis.py` imports the
  pinned Go trie without executing Go/Rust. The Go BSD license is retained in
  `LICENSE-GO-TEXT`; source copyright notices are retained in the Rust files.
- `src/connection/sasl.rs`, `src/message/authentication.rs`,
  `src/message/ready_for_query.rs`, `src/message/backend_key_data.rs` and
  `src/connection/stream.rs`: reject malformed lengths/attributes rather than
  indexing short buffers. Generic SCRAM also checks nonce extension and bounds
  iterations, rejects PLUS-only advertisement without PLUS support, and reports
  invalid usernames instead of panicking.
- `Cargo.toml` and `Cargo.toml.orig`: a direct Unix `nix` 0.31.3 dependency
  with its `user` feature for safe real-UID account/home lookup. This version
  was already in the workspace lockfile; no package version was newly resolved.
  Native authentication also directly uses already-locked x509-parser 0.18.1
  without default features and unicode-normalization 0.1.25. The lockfile records
  these new dependency edges; no dependency or feature graph was executed.

The native constructor loads local service/password files before connection.
Scanner lines are bounded at Go's 64 KiB limit; whole files are not bounded.
It follows Go's ignored passfile load errors and first-match/empty-password
rules, including accepting file modes that generic SQLx's pgpass rejects.
Connection settings, service/password text and paths require UTF-8; other
credential byte strings fail explicitly. PEM input is scanned as bytes.
Parser errors do not print raw credential values. Host CSVs and URI authority
lists use corresponding ports and then the first port when the list is shorter.
All TLS variants and DNS candidates are expanded before dialing. Prefer/allow
fallbacks use fresh sockets, preserving adjacent-address deadline sharing and
the three terminal authentication/database/permission SQLSTATEs. Six
target-session modes use simple-protocol text probes; prefer-standby retries
the last nonpreferred candidate once after ordinary attempts fail. Rejected
connections have bounded, cancellation-owned cleanup.

Native configured CA files use SQLx-core's exclusive-root snapshot. `require`
with such a file maps to CA verification without hostname verification,
matching pgx's configured-root policy. CA files are read and parsed even for
disabled TCP TLS, before mode validation or dialing. Enabled client cert/key
pairs are parsed and matched before dialing, and canonical PEM inputs are
retained in immutable shared snapshots. Local material failures cannot select
a plaintext fallback. Unencrypted keys ignore `sslpassword`, as in pgx.
Encrypted legacy PEM inputs use the configured password and all five named
AES/DES CBC formats through SQLx-core's explicit Go PEM feature. Missing or
incorrect passwords, malformed inputs and mismatched keys fail before dialing.
The selected DER format is inferred independently of private-key label spelling.
The private SQLx-core Go DES path now accepts weak/degenerate keys in source.
The loader preserves pgx's unable-to-decrypt-key context, x509 header/mode/IV/
block/padding/password messages and Go hex first-invalid-byte versus odd-length
precedence. It does not add a password callback. All key/provider/PEM behavior
remains unqualified.
Verified modes without a CA file select OS roots. An explicit system-root
override replaces even an invalid SSL mode and forces endpoint verification.
Direct negotiation promotes prefer to require and uses PostgreSQL ALPN.
Other modes honor SNI suppression; verify-full retains DNS SNI through its
verification hostname, following pinned pgx. These trust inputs
use the companion SQLx-core patch and the newly enabled AWS-LC TLS feature.

The headscale-db native factory also performs Gorm's initial simple `-- ping`
before returning its first connection to the pool. Native SCRAM prefers PLUS
when TLS binding data and the server mechanism are available, honors disable,
and requires binding data/PLUS when require is selected. As in pgx, the binding
restriction is checked during SCRAM; require_auth separately determines whether
that exchange must occur. Kerberos options are inert for other methods. GSS
requests fail with the pinned no-provider error after method-policy checks:
headscale/Gorm register no GSS provider. There is no OAuth provider callback in
this native configuration, matching the pinned headscale path.

Protocol options now accept exactly empty/3.0 and 3.2/latest. The default maximum
stays 3.0 unless a higher minimum implicitly raises it to latest. An explicit
maximum below the minimum fails before dialing. Negotiation enforces Go's
minimum check and ignores the decoded unsupported-option names, while retaining
full backend cancellation keys. SQLx has no cancellation API using those keys.

All five query modes are now implemented in source: cache_statement,
cache_describe, describe_exec, exec and simple_protocol. Native cache capacities
use Go's signed-32-bit parser; nonpositive values disable the corresponding
cache. Parameter-free SQL always uses simple protocol. Parameterized cache
modes report the pinned disabled-cache errors. Cached descriptions drive
result-format counts; failed queries invalidate caches and retired named
statements close before the next operation. Clear-cache drains retired names
and clears descriptions too. The sanitizer quotes every converted nonnull
value, matching pgx's convertSimpleArgument path; logs retain the SQL template.

Native automatic cache names now match pgx's truncated SHA-256 scheme.
Preparation failure/cancellation retires names through a drop guard, while
interrupted close cycles retain their queue for a later retry. Preparation and
close messages are staged before transport append. Unnamed describe/execute
reparses after metadata lookup so the original statement survives SQLx's
intervening type queries. These are source changes without cancellation,
failure-order or server-resource evidence.

The decoder pass bounds received row/field/value counts before reads or
allocation, checks primitive binary widths and reports malformed JSONB and
out-of-range date/timestamp values. It also fixes quoted NULL array elements,
Unicode/trailing-NULL record fields and text-range boundary handling. These
guards are shared with generic SQLx where the same decoders are used. They do
not constitute a complete malformed-server or codec audit.

The text adapter supports null/scalar/text/bytes/JSON/UUID/numeric/date/time/
timestamp/interval/network values, arrays and selected enum/domain forms.
Auxiliary/custom codecs, per-type Go encoding plans and client-versus-server
cast errors, explicit preparation/per-query persistence behavior, explicit
statement naming/lifetimes, cancellation, schema drift and multi-result semantics remain
incomplete or unqualified. Weak/degenerate DES compatibility now has source
implementation through the private SQLx-core PEM path; it remains unqualified.
Protocol negotiation, variable-key framing, Unicode normalization/context/table import, certificate/PSS parser
equivalence, malformed server frames, auth failure/fallback ordering and text,
PBKDF2 resource/cancellation behavior, PEM layouts/algorithms, OS resolver and trust differences,
system-root cache timing, malformed URI/alias handling, diagnostic wording,
cleanup and deadline edges, platform identity and startup error ordering remain
unqualified. Local file reads and whole files are not bounded.

This local source patch changes configuration and native startup behavior.
It has not been built, tested, dependency-audited or process-qualified in this batch.
The opt-in headscale-db `go-pool-compat` feature requires both this patch and
the SQLx-core patch. Generic database embeddings do not enable that feature.
Future SQLx updates must review and rebase the listed changes and call sites.

## Legacy PEM diagnostic source pins — 2026-10-18

The loader preserves pgx's failed-PEM/password and unable-to-decrypt-key
contexts. Go x509 defines the named DEK-Info/mode/IV/block/padding/password
errors; encoding/hex supplies byte-before-odd-length precedence. Hex's byte
diagnostic follows fmt's literal printable-rune suffix and strconv's Latin-1
IsPrint rules. Private SQLx-core DES/TDEA now accepts every correctly sized
key, including weak/semi-weak/equal-subkey cases; its separate provenance
records implementation and original BSD license. AES remains locked AWS-LC.

Source SHA-256:
- pgx v5.10.0 pgconn/config.go: fb52662ed31e36ed82ff89b650fea4e66041f8f88b6362de5a4d5ab6d3aaa4ff
- Go 1.26.9 crypto/x509/pem_decrypt.go: 062b4025a467daf8eb1955f4afa4ce8ed19d7234274a28edf724062eae944b6f
- Go 1.26.9 encoding/hex/hex.go: b3344957ddc5d4090972f94b552a5a7a5bdfb8174a189df033adb0ede97002ba
- Go 1.26.9 fmt/format.go: a668c0d6bb23f6ac929b73ef661a65be2225a9f665052a2ce02c4c58339c3335
- Go 1.26.9 strconv/quote.go: 6602960ec8777de9926c1d02fbf5cb0828d4aefa38083865f4af17b6892c09a2

Source only, direct rustfmt; no tests/builds/validators/probes/cipher execution,
fresh dependency/advisory or package/container qualification. Error/callback/
driver/PEM/DER/resource/cancellation and all process/import/restart behavior
remain incomplete or unqualified. Existing Go/pgx licenses and notices apply.


## Native command/query execution and text codecs — 2026-10-18

Native PgConnection::execute now uses an internal command intent and returns the
final CommandTag while draining simple-protocol results through ReadyForQuery.
Argument-free Conn.Exec uses simple protocol; Conn.Query honors configured modes
except its separate empty-SQL override. Retired statement Close batches remain
queued during a failed transaction. SQLx-core pool execution delegates to its
acquired connection so this native override also applies to &Pool calls.
Generic PgConnection execute retains aggregate result folding.

Native CommandComplete validates the single final NUL and computes the trailing
decimal run using pgx signed-int64 wrapping; SQLx's public u64 result retains the
same raw bits. Generic SQLx framing/count parsing remains separate. Protocol
error handling and malformed-backend pool reuse remain unqualified.

Text argument conversion emits {} immediately for any validated zero-cardinality
array, avoiding shape-driven output amplification such as [large,0]. Quoting
matches pgx's empty/null/edge-space/special-character admission. TIME keeps six
fractional digits; timestamps retain trimmed fractions. Interval conditionally
emits month/day fields and signed clock/fraction text, retaining Go wrapping at
MinInt64. Float infinities use +Inf/-Inf. Numeric ndigits/dscale signedness and
zero projection follow pgx binary Numeric decoding before text conversion.
Original Go caller timezone/nanosecond/decimal metadata is not recovered from
SQLx's binary argument projection, and auxiliary codecs remain incomplete.

Pinned pgx v5.10.0 SHA-256 sources:

- conn.go: 921fff91b65930c2610400bf1c5b3c8ba3c55393ce544e60d87fe4fe79e55459
- pgconn/pgconn.go: e745f52517eb38cd98559a339565a4cf16831338f8917dd452962c31e637a001
- stdlib/sql.go: d98165aeaffa43147809f934e522a2a8a4e237aaa14c7c8803f51424f04b933c
- values.go: 4dd01aeed5fb3d0823b29bb02ae2e5b4da4042938fe6daf4cd8d842ddaf5b09e
- extended_query_builder.go: da076b82c5c9cc8dd2b13dc10fac6cdf491f72d2061c31a6c6bd2f8c57b79c2f
- pgtype/array.go: 74db3644e0353c395866bf0c8b09e7173414a8145b907480b3747675a8e5a9cb
- pgtype/array_codec.go: 7a5a2835fbbe47d496d738e05f91f6b88f470dba3b5111b7a9c3ab00499461d8
- pgtype/time.go: 0b58e27db3a2f800410855ed94ca424ddc6306ad3a44cf034d4f42474b6d0dfa
- pgtype/interval.go: 275bc7be93b025832db618684500ead7d05048e8899b937b3aae92691d911852
- pgtype/numeric.go: 6ca6c963cfadece1afe0f0dc4ad4f49ef6aa6f73c23487033f69ca406fd2ef1c
- pgtype/float4.go: 8624a25b419e896875dab34aa611e018264468551a24b22a1b51ae234324baee
- pgtype/float8.go: 0d9e2429e51bad47240bbac08b34b0a240f8c6f62a0a7784b114b79387cddf94

Existing SQLx and pgx licenses/notices apply. Source/direct rustfmt only; no
build/test/Cargo/lint/validator/probe, driver/pool/transaction/cache/cancellation,
feature/package/container/client/process/import/restart/security/dependency/
advisory qualification was performed. All three parity gates stay open.


Native described row queries now request databaseSQLResultFormats: binary for
Bool/Bytea/CID/Date/Float4/Float8/Int2/Int4/Int8/OID/Timestamp/Timestamptz/XID,
text for all other OIDs. Private PgRow optional format metadata selects each
column's format, preserving the existing PgValueRef/PgValue/AnyRow boundary.
Native RowDescription snapshots actual format0/1 and rejects other codes.
Generic rows keep the existing uniform format. ModeExec and SimpleProtocol
retain text; cached Conn.Exec still has uniform-binary result preferences, and
native fetch_many still exposes all simple-query results instead of pgx Query's
first-result/drain contract. Any backend execution retains its own dispatcher.
No public value/row field or API changed; no execution evidence qualifies text
extension/custom type decoding or these mode/cancellation boundaries.

Native CommandComplete framing follows pgproto3 and rejects missing/interior
NUL before row-count projection. Additional pgx v5.10.0 SHA-256 sources:
- pgproto3/command_complete.go:
  7d417a30d6d7dd7af90a9efb9e578639b546fc584a52e7fccfb519c97871da1d
- pgproto3/pgproto3.go:
  63cef8a0438d4343d99c3635345f9d93dfee8557b1b4d2763e445d06d5f4ae6c
Existing pgx license terms apply. Direct rustfmt only; no build, test, malformed
wire/fatality/pool-reuse, package or security qualification is asserted.


## First result, native failure state and Any execution — 2026-10-18

Native row intent now exposes only the first simple-query result/tag and drains
later results through ReadyForQuery, decoding messages and retaining late SQL
errors. Discarded results do not issue extra type-catalog lookups. Native command
intent still retains the final tag. Cached command formats follow pgx's default
registered codec map preferences, with binary arrays when element codecs support
it and text fallback for unknown/custom OIDs. Row QueryContext keeps the separate
stdlib result-format map. Custom codec registration remains unimplemented.

Any Postgres execute now reaches the concrete native command executor through a
private Execute wrapper retaining SQL, optional arguments and persistence. Native
rows are discarded as by PgPool execute. Non-native Pg Any keeps its prior
aggregate/row-conversion path; other Any backends inherit the additive default.
No existing public method/type signature changed. Any and execute_many abstraction
boundaries remain unqualified.

Native stream errors from receive/decode/protocol invariants leave sticky failure
state; the default pgx FATAL response behavior also marks it. Ordinary SQL errors
and client-side validation/encoding failures do not poison the connection. Pool
flush/drain rejects poisoned native state before idle admission, and owned close
paths drop without flushing queued statements. Discarded CommandComplete,
DataRow and RowDescription packets receive native validation during drain.
Buffer-only Sync and transaction rollback encoding stays available to Drop paths,
avoiding panic after poisoning; queued data is not flushed by poisoned close.
Generic SQLx paths retain their existing behavior. Other skipped body decoders,
CancelRequest/asynchronous cleanup and I/O/transport termination are unqualified.

Additional pinned pgx v5.10.0 SHA-256 sources:
- rows.go: 8c718001a9eaf5ef9fcede2a3d2bff2b716f38fd982e8177553b9bcdac1741c2
- pgtype/pgtype.go: b5662c33a0e5737c30d1d6343dc28fc5bf5cfb4995df5722c4baefe6040f99b2
- pgtype/pgtype_default.go: eb1e657c0c206808f0230682334f055f47693af802b6f26a9d5eba08259d725a
- pgtype/multirange.go: 38255ce3b547696a35efa35fd3144fb2d6cd0593dad829f64e7cd365cf984ca3
- pgtype/xml.go: 6352509ff0fe167afb90bf58f5176aac08d93abe9732bd8650ad01bbcc5957cc
- pgproto3/data_row.go: bbf4ee642054ff2c6c60e0a48a4f2cddd9e461137468b410fa6e5dff262eb151
- pgproto3/row_description.go: 91d6f3db66566f9881ace96c29a4becee309f374b37f3faef45f91f290fdd88d
Existing conn.go/pgconn.go/config.go/stdlib/sql.go and array_codec.go pins apply.

Source/direct rustfmt only; no build/test/Cargo/validator/probe, lifetimes,
malformed-wire/pool-reuse/transaction/cache/cancellation/resource, feature,
package/container/client/process/import/restart/security/dependency/advisory
qualification is asserted. All three release gates remain open.


## Native raw-frame validation and diagnostic decoding — 2026-10-18

Native backend ingress validates signed frame length and pgx's 0x3ffffffe body
cap before body reserve. New message/go_body.rs performs allocation-free
structural framing checks for represented packet kinds, including discarded
acks/notification/description messages. Native Notice/Error consumes all fields
with last duplicate wins and final S severity; V does not override FATAL handling.
Notice/ParameterStatus invalid UTF8 projects lossily into existing Rust strings.
Generic decoders retain their prior path. Query argument-count diagnostics now
use expected/got counts; command diagnostics retain EQB wording.

Adapted from pinned pgx v5.10.0 pgproto3 source; existing LICENSE-GO-PGX applies.
Additional SHA-256 pins:
- frontend.go: be88538ccbd1bf474c62663f1edef686b6f0580401cb48cc93e3fbafd2bb125b
- error_response.go: ca11c2b72e044fbff0d6629ed769a012bfa4f109327ae13cc5f3857f88727106
- notice_response.go: 4b9071daf5f9975eb936c370200709bb7433862c5d4a32d21db65620133f4a8e
- parameter_status.go: 54da26d564afed124eea76e70265a5f85267d0d54704d684e36f03056b3f3190
- parameter_description.go: 987f874a2b408abc2f076cf2e5e7ece261e9b704cdfe126abb420d51912a6162
- notification_response.go: 07d41c2e25f602d685868e608271c4ba85e2df2ac1f0251fcf5b96f07914ced4
- authentication_sasl.go: 27b3abf845759cf3960433eccad729ef7411cc9bed1b5c859715707a1b9397c3
Existing pgproto3.go, conn.go, stdlib/sql.go and
pgconn/config.go pins apply.

Absent FunctionCallResponse/CopyBoth variants, higher-level ReadyForQuery status,
invalidUTF8 column names, COPY count projection, SASL parser and error numeric
accessors remain bounded differences. Explicit prepare map/close lifecycle and
execute_many API semantics remain residuals; no production Headscale Postgres
callsites found. Source/direct rustfmt only; no tests/builds/Cargo/validators/
probes, protocol/transport/pool/cache/cancellation/package/security qualification
or gate closure. Existing notices/licenses apply.

## Authorized compatible Unicode normalization upgrade — 2026-10-18

Both manifests now pin unicode-normalization0.1.26 (from0.1.25). The public
normalization trait/API is unchanged; selected native SASLprep admission and
private tables remain in place. This source/resolution update does not qualify
new Unicode data or SCRAM behavior. No migration source/checksum was changed,
and no build/test/process/advisory validation ran.

Current manifest SHA-256:

- Cargo.toml: df473caad8ef020db1424598eacb896773fdced0c6726f307db921baed0fafce
- Cargo.toml.orig: 2e3f26c271c7a33c91124a2c2b371f29728b10e96b93d4d374a4b550035b6756
