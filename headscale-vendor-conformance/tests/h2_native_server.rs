//! Conformance tests for the native (Go-exact) HTTP/2 *server* mode of the
//! patched `h2` crate (`vendor/h2`, enabled by `Builder::go_native_server`).
//!
//! Every test runs the same hand-written byte stream through a stock
//! `h2::server::Builder` and through one with `go_native_server`, so a test
//! fails if the patch is reverted *or* if native mode silently stops changing
//! behaviour. The peer is raw frames over `tokio::io::duplex`; no other HTTP/2
//! implementation is involved.
//!
//! Go reference: Go 1.26.9 `net/http/h2_bundle.go` (pins recorded in
//! `vendor/h2/UPSTREAM.md`). Citations below name the Go function and, where
//! Go emits one, its `countError` tag; line numbers are not repeated because
//! the pinned 1.26.9 file is not vendored.

mod common;

use bytes::Bytes;
use common::{
    ENHANCE_YOUR_CALM, FLAG_ACK, FLOW_CONTROL_ERROR, FRAME_SIZE_ERROR, Frame, PROTOCOL_ERROR,
    REFUSED_STREAM, SETTINGS, frame, read_frame, read_until_goaway, request_headers,
    settings_payload, write_all,
};
use h2::server::Builder;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinHandle;

fn builder(native: bool) -> Builder {
    let mut builder = h2::server::Builder::new();
    if native {
        // Same call the control-plane server makes (`noise.rs::control_h2_builder`).
        builder.go_native_server(None);
    }
    builder
}

/// Serve one connection, holding every accepted request open so its stream
/// stays counted against `max_concurrent_streams`.
fn serve<T>(io: T, builder: Builder) -> JoinHandle<Result<usize, h2::Error>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut connection = builder.handshake::<_, Bytes>(io).await?;
        let mut held = Vec::new();
        while let Some(accepted) = connection.accept().await {
            held.push(accepted?);
        }
        Ok(held.len())
    })
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The server acknowledged our SETTINGS frame.
    Acked,
    /// The server sent GOAWAY with this error code.
    GoAway(u32),
    /// The connection ended without either.
    Closed,
}

/// Send `bytes` to a fresh server and report how it reacted to the SETTINGS.
async fn settings_outcome(native: bool, bytes: &[u8]) -> Outcome {
    let (mut client, server_io) = tokio::io::duplex(1 << 20);
    let server = serve(server_io, builder(native));
    write_all(&mut client, bytes).await;
    let outcome = loop {
        match read_frame(&mut client).await {
            None => break Outcome::Closed,
            Some(frame) if frame.is_settings_ack() => break Outcome::Acked,
            Some(frame) => {
                if let Some((_, code)) = frame.goaway() {
                    break Outcome::GoAway(code);
                }
            }
        }
    };
    client.shutdown().await.expect("shutdown client half");
    drop(client);
    let _ = tokio::time::timeout(common::STEP, server)
        .await
        .expect("server task must finish after the client closes");
    outcome
}

fn prefix_with(settings_frame: &[u8]) -> Vec<u8> {
    let mut out = common::PREFACE.to_vec();
    out.extend_from_slice(settings_frame);
    out
}

struct Case {
    name: &'static str,
    frame: Vec<u8>,
    /// Stock h2's reaction.
    stock: Outcome,
    /// Native (Go-exact) reaction.
    native: Outcome,
}

/// SETTINGS validation: native mode applies Go's server-side rules and error
/// codes; stock h2 accepts several of these frames and reports every malformed
/// one as `PROTOCOL_ERROR`.
///
/// Go: `http2parseSettingsFrame` (`frame_settings_ack_with_length` and
/// `frame_settings_mod_6` → `FRAME_SIZE_ERROR`, `frame_settings_has_stream` →
/// `PROTOCOL_ERROR`, first `INITIAL_WINDOW_SIZE` above 2^31-1 →
/// `FLOW_CONTROL_ERROR`, checked before anything else counts the frame) and
/// `(*http2serverConn).processSettings` (`NumSettings() > 100 ||
/// HasDuplicates()` → `settings_big_or_dups` `PROTOCOL_ERROR`, over *raw*
/// identifiers, so unknown ones count). Rust: `vendor/h2/src/frame/settings.rs`
/// `Settings::load_go`; `vendor/h2/UPSTREAM.md` ("carries the native
/// SETTINGS-validation bit inside the decoder").
#[tokio::test]
async fn native_server_validates_settings_like_go_and_stock_does_not() {
    let unknown_pairs = |n: u16| -> Vec<(u16, u32)> { (0..n).map(|i| (0x100 + i, 1)).collect() };
    let cases = vec![
        Case {
            name: "valid distinct settings, including an unknown identifier",
            frame: common::settings(&[(0x3, 100), (0x4, 65_535), (0x99, 7)]),
            stock: Outcome::Acked,
            native: Outcome::Acked,
        },
        Case {
            name: "duplicate known identifier (MAX_CONCURRENT_STREAMS twice)",
            frame: common::settings(&[(0x3, 10), (0x3, 20)]),
            stock: Outcome::Acked,
            native: Outcome::GoAway(PROTOCOL_ERROR),
        },
        Case {
            name: "duplicate *unknown* identifier",
            frame: common::settings(&[(0x99, 1), (0x99, 2)]),
            stock: Outcome::Acked,
            native: Outcome::GoAway(PROTOCOL_ERROR),
        },
        Case {
            name: "101 distinct entries (Go caps a frame at 100)",
            frame: common::settings(&unknown_pairs(101)),
            stock: Outcome::Acked,
            native: Outcome::GoAway(PROTOCOL_ERROR),
        },
        Case {
            name: "exactly 100 distinct entries is fine",
            frame: common::settings(&unknown_pairs(100)),
            stock: Outcome::Acked,
            native: Outcome::Acked,
        },
        Case {
            name: "INITIAL_WINDOW_SIZE above 2^31-1 is a flow-control error in Go",
            frame: common::settings(&[(0x4, 0x8000_0000)]),
            stock: Outcome::GoAway(PROTOCOL_ERROR),
            native: Outcome::GoAway(FLOW_CONTROL_ERROR),
        },
        Case {
            // Go reads the *first* INITIAL_WINDOW_SIZE before it counts or
            // de-duplicates, so FLOW_CONTROL_ERROR wins over the duplicate.
            name: "oversized INITIAL_WINDOW_SIZE takes precedence over a duplicate",
            frame: common::settings(&[(0x4, 0x8000_0000), (0x99, 1), (0x99, 2)]),
            stock: Outcome::GoAway(PROTOCOL_ERROR),
            native: Outcome::GoAway(FLOW_CONTROL_ERROR),
        },
        Case {
            name: "SETTINGS payload that is not a multiple of 6 bytes",
            frame: frame(SETTINGS, 0, 0, &[0, 3, 0, 0, 0]),
            stock: Outcome::GoAway(PROTOCOL_ERROR),
            native: Outcome::GoAway(FRAME_SIZE_ERROR),
        },
        Case {
            name: "SETTINGS ACK carrying a payload",
            frame: frame(SETTINGS, FLAG_ACK, 0, &settings_payload(&[(0x3, 1)])),
            stock: Outcome::GoAway(PROTOCOL_ERROR),
            native: Outcome::GoAway(FRAME_SIZE_ERROR),
        },
        Case {
            name: "SETTINGS on a non-zero stream",
            frame: frame(SETTINGS, 0, 1, &settings_payload(&[(0x3, 1)])),
            stock: Outcome::GoAway(PROTOCOL_ERROR),
            native: Outcome::GoAway(PROTOCOL_ERROR),
        },
        Case {
            name: "MAX_FRAME_SIZE below 16384 (value error, PROTOCOL_ERROR in Go)",
            frame: common::settings(&[(0x5, 100)]),
            stock: Outcome::GoAway(PROTOCOL_ERROR),
            native: Outcome::GoAway(PROTOCOL_ERROR),
        },
    ];

    let mut failures = Vec::new();
    for case in cases {
        let bytes = prefix_with(&case.frame);
        let stock = settings_outcome(false, &bytes).await;
        let native = settings_outcome(true, &bytes).await;
        if stock != case.stock {
            failures.push(format!(
                "[{}] stock h2: expected {:?}, got {stock:?}",
                case.name, case.stock
            ));
        }
        if native != case.native {
            failures.push(format!(
                "[{}] native h2: expected {:?}, got {native:?}",
                case.name, case.native
            ));
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// The first frame after the preface must be SETTINGS (`go-server-first-settings`,
/// enabled for every server by headscale-api `full`). Go checks the first
/// *decoded* frame before dispatching it.
///
/// Go: `(*http2serverConn).processFrame` ("First frame received must be
/// SETTINGS") — the first frame that is not `*http2SettingsFrame` yields `countError("first_settings",
/// http2ConnectionError(http2ErrCodeProtocol))`. Rust:
/// `vendor/h2/src/codec/framed_read.rs` `require_first_settings`;
/// `vendor/h2/UPSTREAM.md` ("first-frame guards remain on FramedRead").
///
/// This guard is a compile-time feature, so stock-versus-native cannot be
/// compared in one build; the pristine crate would instead serve the request.
#[tokio::test]
async fn first_frame_other_than_settings_is_a_protocol_error() {
    for native in [false, true] {
        let (mut client, server_io) = tokio::io::duplex(1 << 20);
        let server = serve(server_io, builder(native));
        let mut bytes = common::PREFACE.to_vec();
        bytes.extend_from_slice(&request_headers(1, true));
        write_all(&mut client, &bytes).await;
        let goaway = read_until_goaway(&mut client)
            .await
            .unwrap_or_else(|| panic!("native={native}: expected GOAWAY for HEADERS-first"));
        assert_eq!(
            goaway.goaway().map(|(_, code)| code),
            Some(PROTOCOL_ERROR),
            "native={native}"
        );
        drop(client);
        let result = tokio::time::timeout(common::STEP, server)
            .await
            .expect("server finishes")
            .expect("server task joins");
        // The connection ends after the GOAWAY; whether the library surfaces an
        // error for it is not a Go-exactness property, so only require that it ends.
        drop(result);
    }
}

/// Everything the server wrote back for a burst of refused streams.
struct RefusalRun {
    rst: Vec<(u32, u32)>,
    goaway: Option<u32>,
}

/// Open stream 1 (left open), then send `refused` more HEADERS frames on odd
/// streams 3, 5, ... against a server that allows exactly one concurrent stream.
async fn refusal_run(native: bool, local_reset_budget: usize, refused: u32) -> RefusalRun {
    let mut b = builder(native);
    b.max_concurrent_streams(1)
        .max_local_error_reset_streams(Some(local_reset_budget));
    let (mut client, server_io) = tokio::io::duplex(1 << 20);
    let server = serve(server_io, b);

    let mut bytes = common::client_prefix(&[]);
    bytes.extend_from_slice(&request_headers(1, false));
    for index in 0..refused {
        bytes.extend_from_slice(&request_headers(3 + 2 * index, false));
    }
    write_all(&mut client, &bytes).await;

    let mut rst = Vec::new();
    let mut goaway = None;
    // Stop at GOAWAY, or once every refusal has been answered; the server never
    // closes on its own in the healthy case, so don't wait for EOF.
    while goaway.is_none() && rst.len() < refused as usize {
        let Some(frame) = read_frame(&mut client).await else {
            break;
        };
        if let Some(code) = frame.rst_code() {
            rst.push((frame.stream, code));
        } else if let Some((_, code)) = frame.goaway() {
            goaway = Some(code);
        }
    }
    drop(client);
    let _ = tokio::time::timeout(common::STEP, server).await;
    RefusalRun { rst, goaway }
}

/// Refusal accounting.
///
/// Stock h2 sends each over-limit stream's `RST_STREAM(REFUSED_STREAM)` from a
/// connection-owned slot and *counts it against the local error-reset budget*
/// (`max_local_error_reset_streams`), answering the overrun with
/// `GOAWAY(ENHANCE_YOUR_CALM)`. A native server enqueues the refusal into its
/// own independent FIFO (Go's per-connection control-frame queue): refusals are
/// never charged to the error-reset budget and are answered in arrival order.
///
/// The client below never ACKs the server's SETTINGS, which is the case where
/// Go treats an over-limit HEADERS as a network race and refuses the stream.
///
/// Go: `(*http2serverConn).processHeaders` — `sc.curClientStreams+1 >
/// sc.advMaxStreams` with `sc.unackedSettings != 0` →
/// `countError("over_max_streams_race", http2streamError(id,
/// http2ErrCodeRefusedStream))`. Rust: `vendor/h2/src/proto/streams/recv.rs`
/// `go_refused`/`send_pending_refusal` vs `proto/connection.rs`
/// `pending_refusal` + `Streams::count_pending_refusal`;
/// `vendor/h2/UPSTREAM.md` ("Selected native servers instead enqueue that
/// outcome into their existing independent refusal FIFO").
#[tokio::test]
async fn native_server_refusals_use_an_independent_fifo_not_the_error_reset_budget() {
    const BUDGET: usize = 2;
    const REFUSED: u32 = 6;

    let stock = refusal_run(false, BUDGET, REFUSED).await;
    // Stock: the first `BUDGET` refusals are sent, the next one trips the
    // budget and the connection is torn down with ENHANCE_YOUR_CALM.
    assert_eq!(
        stock.goaway,
        Some(ENHANCE_YOUR_CALM),
        "stock h2 must charge refusals to the local error-reset budget; got {:?}",
        stock.rst
    );
    assert!(
        stock.rst.len() <= BUDGET,
        "stock h2 sent more than {BUDGET} refusals before GOAWAY: {:?}",
        stock.rst
    );

    let native = refusal_run(true, BUDGET, REFUSED).await;
    assert_eq!(
        native.goaway, None,
        "native refusals must not consume the error-reset budget"
    );
    let expected: Vec<(u32, u32)> = (0..REFUSED).map(|i| (3 + 2 * i, REFUSED_STREAM)).collect();
    assert_eq!(
        native.rst, expected,
        "native refusals are answered in arrival order, one RST_STREAM each"
    );
}

/// The native refusal FIFO is bounded: when the peer stops reading, queued
/// controls pile up and the server closes the connection once more than 10,000
/// are pending, without waiting for output to drain. Stock h2 instead stops
/// reading input while its single refusal slot is unflushed, so it never grows
/// a queue and never errors on a stalled peer.
///
/// Go: `(*http2serverConn).serve` write loop — `sc.queuedControlFrames >
/// http2maxQueuedControlFrames` (10000) logs "too many control frames in send
/// queue, closing connection" and returns, with no GOAWAY. Rust:
/// `vendor/h2/src/proto/connection.rs` ("Bound them by Go's 10,000
/// control-frame limit and close without waiting for output").
#[tokio::test]
async fn native_refusal_queue_is_bounded_when_the_peer_never_reads() {
    // The server's 16 KiB codec write buffer absorbs ~1,260 RST_STREAM frames
    // before the stalled pipe blocks it; the remainder must sit in the native
    // refusal FIFO, so this needs to clear 10,000 by a comfortable margin.
    const REFUSED: u32 = 12_000;

    for native in [false, true] {
        let mut b = builder(native);
        // A budget the stock path can never exceed within this test, so the
        // only way for the connection to fail is the control-queue bound.
        b.max_concurrent_streams(1)
            .max_local_error_reset_streams(None);
        // Separate one-way pipes: a roomy client->server direction and a
        // 256-byte server->client direction the client never drains, so the
        // server's initial SETTINGS fits and nothing after it does.
        let (server_rx, mut client_tx) = tokio::io::simplex(1 << 20);
        let (_client_rx, server_tx) = tokio::io::simplex(256);
        let server = serve(tokio::io::join(server_rx, server_tx), b);

        let mut bytes = common::client_prefix(&[]);
        bytes.extend_from_slice(&request_headers(1, false));
        for index in 0..REFUSED {
            bytes.extend_from_slice(&request_headers(3 + 2 * index, false));
        }
        write_all(&mut client_tx, &bytes).await;

        // Native mode aborts promptly; the stock server is proven *not* to abort
        // by outlasting a short wait.
        let wait = if native {
            common::STEP
        } else {
            std::time::Duration::from_millis(1500)
        };
        let finished = tokio::time::timeout(wait, server).await;
        if native {
            let result = finished
                .expect("native server must abort once the control queue overflows")
                .expect("server task joins");
            let error = result.expect_err("native server must fail, not end cleanly");
            assert!(
                error.to_string().contains("too many control frames"),
                "unexpected native error: {error}"
            );
        } else {
            assert!(
                finished.is_err(),
                "stock h2 must stay blocked on its single refusal slot, not abort"
            );
        }
    }
}

#[tokio::test]
async fn frame_helper_round_trips() {
    // Guard against a broken test helper masquerading as a passing test.
    let encoded = frame(SETTINGS, FLAG_ACK, 0, &[]);
    let (mut a, mut b) = tokio::io::duplex(64);
    write_all(&mut a, &encoded).await;
    let decoded = read_frame(&mut b).await.expect("one frame");
    assert_eq!(
        decoded,
        Frame {
            kind: SETTINGS,
            flags: FLAG_ACK,
            stream: 0,
            payload: Vec::new()
        }
    );
}
