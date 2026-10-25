# headscale-vendor-conformance

Behavioural conformance tests for the locally patched crates in `vendor/`.

The vendored crates (`h2`, `rustls`, `sqlx-postgres`, `http`, ...) carry
default-off "Go-exactness" features that make them behave like Go's standard
library / pgx instead of like the upstream crates. Their `UPSTREAM.md` files
say no tests were authored for the patches. This crate drives the *real*
patched code (through the root `[patch.crates-io]`, with the same feature set
the binaries enable) and asserts **both** the stock behaviour and the native
behaviour for the same input, so a test fails if

- a patch is reverted or rebased away,
- a native mode silently stops changing behaviour, or
- a stock code path regresses under the patch.

Run: `cargo test -p headscale-vendor-conformance` (about 2 s warm, no network,
no Postgres server). It is a normal workspace member, so
`cargo test --workspace --all-targets` and `cargo clippy --workspace --all-targets -- -D warnings`
cover it.

## Feature → test → Go reference

| Feature (vendored crate) | Test | What it proves | Go reference |
|---|---|---|---|
| h2 native server: SETTINGS validation (`Builder::go_native_server`) | `h2_native_server::native_server_validates_settings_like_go_and_stock_does_not` | 11 hand-built SETTINGS frames: duplicate known/unknown identifiers, >100 entries, oversize `INITIAL_WINDOW_SIZE` (and its precedence over duplicates), length not a multiple of 6, ACK with payload, non-zero stream. Stock h2 accepts several and maps every error to `PROTOCOL_ERROR`; native returns Go's codes (`FRAME_SIZE_ERROR`, `FLOW_CONTROL_ERROR`, `PROTOCOL_ERROR`). | `net/http/h2_bundle.go` `http2parseSettingsFrame` (`frame_settings_*`), `(*http2serverConn).processSettings` (`settings_big_or_dups`) |
| h2 first-frame guard (`go-server-first-settings`) | `h2_native_server::first_frame_other_than_settings_is_a_protocol_error` | HEADERS before SETTINGS ⇒ `GOAWAY(PROTOCOL_ERROR)` on stock and native servers. Compile-time feature, so not A/B-able in one binary. | `(*http2serverConn).processFrame` `first_settings` |
| h2 `:authority` that is not a URI authority (`go-server-lifecycle`, compile-time) | `h2_native_authority::{invalid_authority_is_kept_and_exposed_as_host_like_go, valid_authority_stays_in_the_uri_…, the_http_crate_rejects_the_authorities_the_native_server_keeps}` | Four authorities `http::uri::Authority` rejects (upstream `recv_invalid_authority` value, grpc-go's percent-encoded unix socket path, a raw `unix://` target, and one alongside a client `host` field): the request is delivered with `Host` = the raw authority (a client-sent `host` is not overwritten), no reset, and the next stream (3) is still served with the GOAWAY naming it. Without the feature (verified by building without it) stream 1 is reset with `PROTOCOL_ERROR` and never delivered; the stock `Builder` of this binary behaves like native because the switch is the cargo feature, not `go_native_server`. | `h2_bundle.go` `newWriterAndRequest` / `newWriterAndRequestNoBody` (`Host: rp.Authority`), `httpcommon.NewServerRequest` (only `@` is rejected) |
| h2 refusal accounting | `h2_native_server::native_server_refusals_use_an_independent_fifo_not_the_error_reset_budget` | Over-`max_concurrent_streams` HEADERS: stock charges each refusal to `max_local_error_reset_streams` and ends in `GOAWAY(ENHANCE_YOUR_CALM)`; native answers all of them, in arrival order, with `RST_STREAM(REFUSED_STREAM)` and no GOAWAY. | `processHeaders` `over_max_streams_race` |
| h2 bounded control queue | `h2_native_server::native_refusal_queue_is_bounded_when_the_peer_never_reads` | A peer that never reads: native closes with "too many control frames in send queue" past 10,000 queued controls; stock stays blocked on its single refusal slot. | `(*http2serverConn).serve` / `http2maxQueuedControlFrames` |
| h2 native client: `Content-Length` normalisation (`Builder::go_native_client`) | `h2_native_client::{identical_duplicate_…, conflicting_…, invalid_…_dropped_…, in_range_…_preserved, head_…, informational_…}` | Identical duplicates collapse to one field; conflicting or non-`ParseUint(…, 10, 63)` values (`abc`, `+5`, `-5`, ` 5`, empty, 2^63) are removed instead of resetting the stream; HEAD fields are normalised but the no-body marker is independent; 1xx responses are not interpreted; a declared length the body never reaches is an error (read through `go_poll_read`, as hyper-util does). Stock h2 resets the stream with `PROTOCOL_ERROR` in each rejected case. | `(*http2clientConnReadLoop).handleResponse` (pinned lines 9889-9924), `transportResponseBody.Read` |
| rustls native ClientHello / raw SNI (`Acceptor::go_server_client_hello`) | `rustls_raw_sni::{native_acceptor_parses_server_name_like_go_and_stock_stays_strict, malformed_…, absent_sni_and_opt_in_gating, native_acceptor_handles_a_byte_at_a_time_record}` | Unknown name types skipped, duplicate host_name rejected even across an unknown item, final dot rejected, arbitrary/non-DNS/IP/uppercase bytes kept verbatim in `raw_server_name()`; stock acceptor stays strict (rejects or hides those) and never exposes a raw name. | `crypto/tls/handshake_messages.go` `(*clientHelloMsg).unmarshal` `extensionServerName` |
| sqlx-postgres native pgx bridge: pgpass/service/env (`PgConnectOptions::from_headscale_go_url`) | `pgx_passfile::{passfile_url_parameter_…, passfile_environment_…, explicit_password_…, service_file_…, unix_socket_hosts_…}` | `passfile=` URL parameter, pgpassfile v1.0.0 matching (comments, trimmed lines, `\:`/`\\` escapes, wildcards, first match), `PGPASSFILE` < URL, `PGPASSWORD` < URL password, service file between environment and URL, `localhost` lookup for socket hosts. Observed end to end against a mock Postgres; stock SQLx has no `passfile=` parameter and resolves a different password. | pgx v5.10.0 `pgconn/config.go` 324-363, 486-495, 630-637; pgpassfile v1.0.0 `pgpass.go`; pgservicefile `5a60cdf6a761` |
| http `go-native-header-capacity` | `http_header_capacity::header_map_holds_more_distinct_fields_…` | `HeaderMap` holds 33,768 distinct fields (stock table: `1 << 15`). Compile-time feature; verified to fail with the feature off. | `net/http.Header` is an unbounded map |

## Known divergence (test is `#[ignore]`d)

`pgx_passfile::empty_url_password_overrides_pgpassword_like_pgx`: pgx treats a
URL password that is present but empty (`postgres://user:@host/db`) as an
explicit setting that overrides `PGPASSWORD` and then consults the passfile.
`PgConnectOptions::from_headscale_go_url` reads the password through
`url::Url::password()`, which reports `None` for an empty password, so
`PGPASSWORD` survives and the passfile is never read. Reachable only when
`PGPASSWORD` is set and the URL carries an empty `user:@` password. Not fixed
here (vendor sources are out of scope for this crate); run the test with
`cargo test -p headscale-vendor-conformance --test pgx_passfile -- --ignored --exact empty_url_password_overrides_pgpassword_like_pgx`
to see it fail, and remove the `#[ignore]` when `go_compat.rs::url_settings`
distinguishes `user:@` from `user@`.

## Notes

- `pgx_passfile` scenarios depend on process environment, so each runs in a
  child process re-executing the test binary with `env_clear()` (the
  `scenarios::*` tests are `#[ignore]`d and only started by the parent tests).
  No `unsafe` and no `std::env::set_var`.
- Not covered here: instant-acme's native Retry-After/status classification
  (needs an ACME server fixture); upstream suites of the vendored crates are
  exercised by the separate vendor CI job, not by this crate.
- Go line numbers for `h2_bundle.go` follow `vendor/h2/UPSTREAM.md` (Go 1.26.9
  pins) where it gives them; elsewhere the Go function and its `countError` tag
  are cited because the pinned 1.26.9 sources are not vendored.
