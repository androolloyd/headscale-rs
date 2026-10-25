//! Conformance tests for the native (Go-exact) HTTP/2 *client* mode of the
//! patched `h2` crate (`vendor/h2`, `Builder::go_native_client`), focused on
//! final-response `Content-Length` normalisation.
//!
//! A scripted raw-frame "server" sends the same response bytes to a stock
//! `h2::client::Builder` and to one with `go_native_client(true)`; the two must
//! differ exactly where Go's transport differs from stock h2.
//!
//! Go: `(*http2clientConnReadLoop).handleResponse` in `net/http/h2_bundle.go`
//! (pinned Go 1.26.9 lines 9889-9924, with `strconv/number.go` and
//! `internal/strconv/atoi.go`, hashes in `vendor/h2/UPSTREAM.md`): the
//! response's `Content-Length` is interpreted with `strconv.ParseUint(v, 10,
//! 63)`, i.e. an unsigned ASCII decimal in 0..=2^63-1 with no sign or
//! whitespace; anything else (or a disagreement between raw duplicates) leaves
//! `ContentLength` unknown instead of failing the stream; informational (1xx)
//! responses return earlier, before that interpretation. Rust:
//! `vendor/h2/src/frame/headers.rs` `Headers::go_normalize_content_length`,
//! called from `vendor/h2/src/proto/streams/recv.rs` `recv_headers`;
//! `vendor/h2/UPSTREAM.md` ("Selected native clients instead normalize final
//! response Content-Length ...").

mod common;

use bytes::Bytes;
use common::{
    FLAG_END_HEADERS, FLAG_END_STREAM, HEADERS, PREFACE, frame, read_frame, settings, settings_ack,
    write_all,
};
use http::{Method, Request};
use tokio::io::{AsyncReadExt, DuplexStream};

// --- HPACK helpers (RFC 7541), literal-without-indexing encodings only ------

/// `:status` as a literal with the static-table name index 8.
fn status(code: &str) -> Vec<u8> {
    let mut out = vec![0x08, u8::try_from(code.len()).expect("short")];
    out.extend_from_slice(code.as_bytes());
    out
}

/// `content-length` as a literal with the static-table name index 28
/// (4-bit prefix 15 + continuation byte 13).
fn content_length(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x0f, 0x0d, u8::try_from(value.len()).expect("short")];
    out.extend_from_slice(value);
    out
}

fn block(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.concat()
}

fn response_headers(header_block: &[u8], end_stream: bool) -> Vec<u8> {
    let flags = FLAG_END_HEADERS | if end_stream { FLAG_END_STREAM } else { 0 };
    frame(HEADERS, flags, 1, header_block)
}

fn data(payload: &[u8], end_stream: bool) -> Vec<u8> {
    frame(
        common::DATA,
        if end_stream { FLAG_END_STREAM } else { 0 },
        1,
        payload,
    )
}

// --- scripted peer -----------------------------------------------------------

/// Speak just enough HTTP/2 to answer one request with `script`.
async fn scripted_server(mut io: DuplexStream, script: Vec<Vec<u8>>) {
    write_all(&mut io, &settings(&[])).await;
    let mut preface = [0u8; 24];
    io.read_exact(&mut preface).await.expect("client preface");
    assert_eq!(&preface[..], PREFACE);
    while let Some(received) = read_frame(&mut io).await {
        if received.kind == common::SETTINGS && received.flags & common::FLAG_ACK == 0 {
            write_all(&mut io, &settings_ack()).await;
        }
        if received.kind == HEADERS && received.stream == 1 {
            for chunk in &script {
                write_all(&mut io, chunk).await;
            }
        }
    }
}

#[derive(Debug)]
enum Fetched {
    /// The request failed before a response was delivered.
    NoResponse(h2::Error),
    Response {
        status: u16,
        /// Every `content-length` field value the application can observe.
        content_length: Vec<String>,
        /// Body bytes, or the error that ended the body.
        body: Result<Vec<u8>, h2::Error>,
    },
}

async fn fetch(native: bool, method: Method, script: Vec<Vec<u8>>) -> Fetched {
    let (client_io, server_io) = tokio::io::duplex(1 << 20);
    let peer = tokio::spawn(scripted_server(server_io, script));

    let mut builder = h2::client::Builder::new();
    if native {
        builder.go_native_client(true);
    }
    let (send, connection) = builder
        .handshake::<_, Bytes>(client_io)
        .await
        .expect("client handshake");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut send = send.ready().await.expect("send ready");
    let request = Request::builder()
        .method(method)
        .uri("https://example.test/")
        .body(())
        .expect("request");
    let (response, _stream) = send.send_request(request, true).expect("send_request");

    let delivered = tokio::time::timeout(common::STEP, response)
        .await
        .unwrap_or_else(|_| panic!("native={native}: no response and no error in time"));
    let fetched = match delivered {
        Err(error) => Fetched::NoResponse(error),
        Ok(response) => {
            let status = response.status().as_u16();
            let content_length = response
                .headers()
                .get_all(http::header::CONTENT_LENGTH)
                .iter()
                .map(|value| value.to_str().expect("ascii").to_owned())
                .collect();
            let mut body = response.into_body();
            let mut collected = Vec::new();
            let result = if native {
                // The native client's body is consumed through Go's `Read`
                // contract (`go_poll_read`), exactly as hyper-util does; it
                // reports "declared more than delivered" itself.
                loop {
                    let read = tokio::time::timeout(
                        common::STEP,
                        std::future::poll_fn(|cx| body.go_poll_read(cx, 8192)),
                    )
                    .await
                    .unwrap_or_else(|_| panic!("native body neither finished nor failed"));
                    collected.extend_from_slice(&read.data);
                    if let Some(error) = read.error {
                        break Err(error);
                    }
                    if read.eof {
                        break Ok(collected);
                    }
                }
            } else {
                loop {
                    let next = tokio::time::timeout(common::STEP, body.data())
                        .await
                        .unwrap_or_else(|_| panic!("stock body neither finished nor failed"));
                    match next {
                        None => break Ok(collected),
                        Some(Ok(chunk)) => {
                            let _ = body.flow_control().release_capacity(chunk.len());
                            collected.extend_from_slice(&chunk);
                        }
                        Some(Err(error)) => break Err(error),
                    }
                }
            };
            Fetched::Response {
                status,
                content_length,
                body: result,
            }
        }
    };
    driver.abort();
    peer.abort();
    fetched
}

/// A final response is delivered with this status, these content-length field
/// values, and a body that ended cleanly with exactly these bytes.
#[track_caller]
fn assert_clean(
    fetched: &Fetched,
    want_status: u16,
    want_cl: &[&str],
    want_body: &[u8],
    who: &str,
) {
    match fetched {
        Fetched::Response {
            status,
            content_length,
            body: Ok(body),
        } => {
            assert_eq!(*status, want_status, "{who}: status");
            assert_eq!(content_length, want_cl, "{who}: content-length fields");
            assert_eq!(body, want_body, "{who}: body");
        }
        other => panic!("{who}: expected a clean response, got {other:?}"),
    }
}

/// The request or the body was killed by a `PROTOCOL_ERROR` stream reset (stock
/// h2's reaction to a malformed or conflicting `Content-Length`).
#[track_caller]
fn assert_rejected(fetched: &Fetched, who: &str) {
    let error = match fetched {
        Fetched::NoResponse(error)
        | Fetched::Response {
            body: Err(error), ..
        } => error,
        other @ Fetched::Response { .. } => {
            panic!("{who}: expected a stream error, got {other:?}")
        }
    };
    assert_eq!(
        error.reason(),
        Some(h2::Reason::PROTOCOL_ERROR),
        "{who}: {error}"
    );
}

/// Identical duplicate values collapse to a single field (`vendor/h2`
/// UPSTREAM.md: "valid duplicate values collapse to the first").
#[tokio::test]
async fn identical_duplicate_content_length_collapses_to_one_field() {
    let script = || {
        vec![
            response_headers(
                &block(&[status("200"), content_length(b"5"), content_length(b"5")]),
                false,
            ),
            data(b"hello", true),
        ]
    };
    let stock = fetch(false, Method::GET, script()).await;
    assert_clean(
        &stock,
        200,
        &["5", "5"],
        b"hello",
        "stock keeps both fields",
    );
    let native = fetch(true, Method::GET, script()).await;
    assert_clean(
        &native,
        200,
        &["5"],
        b"hello",
        "native collapses to the first",
    );
}

/// Conflicting values are *removed*, not a protocol error: the body is then
/// read until END_STREAM with no declared length.
#[tokio::test]
async fn conflicting_content_length_is_removed_not_rejected() {
    let script = || {
        vec![
            response_headers(
                &block(&[status("200"), content_length(b"5"), content_length(b"6")]),
                false,
            ),
            data(b"hello", true),
        ]
    };
    assert_rejected(&fetch(false, Method::GET, script()).await, "stock");
    let native = fetch(true, Method::GET, script()).await;
    assert_clean(
        &native,
        200,
        &[],
        b"hello",
        "native drops the conflicting field",
    );
}

/// Values that are not an unsigned ASCII decimal in 0..=i64::MAX are removed.
/// Each of these is a stream error in stock h2 (or, for the 2^63 case, a
/// declared length the body can never satisfy) and a plain delimited-by-EOF
/// body in the native client.
#[tokio::test]
async fn invalid_content_length_values_are_dropped_by_the_native_client() {
    let invalid: [&[u8]; 6] = [
        b"abc",
        b"+5",
        b"-5",
        b" 5",
        b"",
        // 2^63: a valid u64, but outside Go's signed 63-bit range.
        b"9223372036854775808",
    ];
    let mut failures = Vec::new();
    for value in invalid {
        let script = || {
            vec![
                response_headers(&block(&[status("200"), content_length(value)]), false),
                data(b"hello", true),
            ]
        };
        let shown = String::from_utf8_lossy(value);
        let stock = fetch(false, Method::GET, script()).await;
        // 2^63 is a valid u64 for stock h2, which then rejects the short body
        // (declared length never delivered); the rest fail at HEADERS time.
        let stock_failed = match &stock {
            Fetched::NoResponse(error) => error.reason() == Some(h2::Reason::PROTOCOL_ERROR),
            Fetched::Response { body, .. } => {
                body.as_ref().err().and_then(h2::Error::reason) == Some(h2::Reason::PROTOCOL_ERROR)
            }
        };
        if !stock_failed {
            failures.push(format!(
                "stock accepted Content-Length {shown:?}: {stock:?}"
            ));
        }
        match fetch(true, Method::GET, script()).await {
            Fetched::Response {
                status: 200,
                content_length,
                body: Ok(body),
            } if content_length.is_empty() && body == b"hello" => {}
            other => failures.push(format!(
                "native Content-Length {shown:?} should be dropped and the body read to EOF: {other:?}"
            )),
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// The largest in-range value and plain zero are *kept* (guards against the
/// native path over-eagerly stripping the field).
#[tokio::test]
async fn in_range_content_length_is_preserved() {
    let script = || {
        vec![
            response_headers(
                &block(&[status("200"), content_length(b"9223372036854775807")]),
                false,
            ),
            data(b"hello", true),
        ]
    };
    // 2^63-1 declared, 5 delivered: the declared length is still honoured by
    // both clients, so the body ends in a length-mismatch error either way.
    // What differs from the previous test is that the field survives.
    for native in [false, true] {
        match fetch(native, Method::GET, script()).await {
            Fetched::Response {
                content_length,
                body,
                ..
            } => {
                assert_eq!(content_length, ["9223372036854775807"], "native={native}");
                assert!(
                    body.is_err(),
                    "native={native}: short body must be rejected"
                );
            }
            other @ Fetched::NoResponse(_) => panic!("native={native}: {other:?}"),
        }
    }

    let zero = || {
        vec![response_headers(
            &block(&[status("204"), content_length(b"0")]),
            true,
        )]
    };
    for native in [false, true] {
        assert_clean(
            &fetch(native, Method::GET, zero()).await,
            204,
            &["0"],
            b"",
            if native { "native" } else { "stock" },
        );
    }
}

/// HEAD: the final response's fields are normalised like any other, but the
/// "no body" marker is independent of the field, so a HEAD reply may carry a
/// non-zero Content-Length with no body in both clients.
#[tokio::test]
async fn head_responses_normalise_the_field_but_keep_the_no_body_marker() {
    // Valid length on HEAD with END_STREAM: kept, no body, no error.
    let valid = || {
        vec![response_headers(
            &block(&[status("200"), content_length(b"5")]),
            true,
        )]
    };
    for native in [false, true] {
        assert_clean(
            &fetch(native, Method::HEAD, valid()).await,
            200,
            &["5"],
            b"",
            if native { "native" } else { "stock" },
        );
    }

    // Duplicate identical values on HEAD collapse only in the native client.
    let duplicate = || {
        vec![response_headers(
            &block(&[status("200"), content_length(b"5"), content_length(b"5")]),
            true,
        )]
    };
    assert_clean(
        &fetch(false, Method::HEAD, duplicate()).await,
        200,
        &["5", "5"],
        b"",
        "stock HEAD",
    );
    assert_clean(
        &fetch(true, Method::HEAD, duplicate()).await,
        200,
        &["5"],
        b"",
        "native HEAD",
    );

    // Conflicting values on HEAD: stock resets the stream, native drops them.
    let conflicting = || {
        vec![response_headers(
            &block(&[status("200"), content_length(b"5"), content_length(b"6")]),
            true,
        )]
    };
    assert_rejected(
        &fetch(false, Method::HEAD, conflicting()).await,
        "stock HEAD",
    );
    assert_clean(
        &fetch(true, Method::HEAD, conflicting()).await,
        200,
        &[],
        b"",
        "native HEAD",
    );
}

/// Informational (1xx) responses are returned before Go interprets
/// Content-Length, so a garbage field on a 1xx must not affect the exchange.
/// Stock h2 parses it on the informational HEADERS too and resets the stream.
#[tokio::test]
async fn informational_responses_are_not_interpreted_by_the_native_client() {
    let script = || {
        vec![
            // 103 Early Hints carrying a Content-Length that is not a number.
            response_headers(&block(&[status("103"), content_length(b"abc")]), false),
            response_headers(&block(&[status("200"), content_length(b"5")]), false),
            data(b"hello", true),
        ]
    };
    assert_rejected(&fetch(false, Method::GET, script()).await, "stock");
    let native = fetch(true, Method::GET, script()).await;
    assert_clean(&native, 200, &["5"], b"hello", "native");
}
