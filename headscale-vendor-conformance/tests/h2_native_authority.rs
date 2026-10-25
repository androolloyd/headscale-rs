//! Conformance test for the native server's treatment of an `:authority` that
//! is not a valid URI authority (`vendor/h2/src/server.rs`, the
//! `#[cfg(feature = "go-server-lifecycle")]` arm of the request conversion).
//!
//! Stock h2 turns such a HEADERS block into a malformed-request stream error.
//! Go's `net/http` HTTP/2 server accepts any `:authority` and exposes it as
//! `Request.Host`; grpc-go dials a unix socket with the percent-encoded socket
//! path as its authority, so a strict server would reset every stream from the
//! stock CLI. With `go-server-lifecycle` the request is kept, the unparseable
//! URI authority is dropped, and the raw authority becomes the `Host` header
//! unless the client sent its own.
//!
//! Go: `net/http/h2_bundle.go` `(*http2serverConn).newWriterAndRequest` (reads
//! `:authority` with `f.PseudoValue("authority")`, falls back to the `Host`
//! header only when it is empty) and `newWriterAndRequestNoBody` (`Host:
//! rp.Authority`); `net/http/internal/httpcommon/httpcommon.go`
//! `NewServerRequest` is the only validation, and it rejects `@` (userinfo,
//! `userinfo_in_authority`) and an unparsable `:path`, never any other
//! `:authority` content. Upstream h2's own tests `recv_invalid_authority` and
//! `recv_next_stream_id_updated_by_malformed_headers` fail on purpose under
//! this feature; this file pins the new behaviour positively. Rust:
//! `vendor/h2/src/server.rs`, request conversion, `Authority::from_maybe_shared`
//! error arm.
//!
//! The behaviour is selected by the compile-time feature `go-server-lifecycle`
//! (not by `Builder::go_native_server`), so the stock `Builder` of the same
//! binary exhibits it too; the "stock rejects" half is therefore a build-time
//! property. It is demonstrated by building without the feature (see README).

mod common;

use std::time::Duration;

use bytes::Bytes;
use common::{
    FLAG_END_HEADERS, FLAG_END_STREAM, HEADERS, PROTOCOL_ERROR, WINDOW_UPDATE, frame, read_frame,
    write_all,
};
use h2::server::Builder;
use http::header::HOST;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// What the application saw for one delivered request.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    path: String,
    uri_authority: Option<String>,
    host: Option<Vec<u8>>,
}

fn builder(native: bool) -> Builder {
    let mut builder = h2::server::Builder::new();
    if native {
        builder.go_native_server(None);
    }
    builder
}

/// Deliver every accepted request to `seen`, keeping the streams open.
fn serve<T>(io: T, builder: Builder, seen: mpsc::UnboundedSender<Seen>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut connection = builder.handshake::<_, Bytes>(io).await?;
        let mut held = Vec::new();
        while let Some(accepted) = connection.accept().await {
            let (request, respond) = accepted?;
            let _ = seen.send(Seen {
                path: request.uri().path().to_owned(),
                uri_authority: request.uri().authority().map(|a| a.as_str().to_owned()),
                host: request.headers().get(HOST).map(|v| v.as_bytes().to_vec()),
            });
            held.push((request, respond));
        }
        Ok::<usize, h2::Error>(held.len())
    });
}

/// HPACK literal-without-indexing field with a static-table name index.
fn indexed_name_literal(index: u8, value: &[u8]) -> Vec<u8> {
    // 4-bit prefix: indices below 15 fit in the first byte, larger ones add a
    // continuation byte (host = 38 -> 0x0f, 38 - 15).
    let mut out = if index < 15 {
        vec![index]
    } else {
        vec![0x0f, index - 15]
    };
    out.push(u8::try_from(value.len()).expect("short value"));
    out.extend_from_slice(value);
    out
}

/// `GET <path>` over `http` with the given raw `:authority` and optional
/// regular `host` field, END_STREAM on the HEADERS frame.
fn request(stream: u32, path: &str, authority: &[u8], host: Option<&[u8]>) -> Vec<u8> {
    let mut block = vec![0x82, 0x86]; // :method GET, :scheme http
    block.extend_from_slice(&indexed_name_literal(1, authority)); // :authority
    block.extend_from_slice(&indexed_name_literal(4, path.as_bytes())); // :path
    if let Some(host) = host {
        block.extend_from_slice(&indexed_name_literal(38, host)); // host
    }
    frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, stream, &block)
}

#[derive(Debug)]
struct Run {
    /// Requests delivered to the application, in order.
    delivered: Vec<Seen>,
    /// `RST_STREAM` frames the server sent: `(stream, error_code)`.
    resets: Vec<(u32, u32)>,
    /// `(last_stream_id, error_code)` of the GOAWAY that ended the run.
    goaway: (u32, u32),
}

/// Send a bad-authority request on stream 1 and a valid request on stream 3,
/// wait until the server has decided about both, then provoke a connection
/// error so the GOAWAY reveals the last processed stream id.
async fn run(native: bool, bad: &[u8], host: Option<&[u8]>) -> Run {
    let (mut client, server_io) = tokio::io::duplex(1 << 20);
    let (tx, mut rx) = mpsc::unbounded_channel();
    serve(server_io, builder(native), tx);

    let mut bytes = common::client_prefix(&[]);
    bytes.extend_from_slice(&request(1, "/bad", bad, host));
    bytes.extend_from_slice(&request(3, "/good", b"example.com", None));
    write_all(&mut client, &bytes).await;

    // The valid request comes last, so once it is delivered the bad one has
    // either been delivered before it or reset.
    let mut delivered = Vec::new();
    loop {
        let next = tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .unwrap_or_else(|_| panic!("native={native}: valid follow-up request never delivered"))
            .expect("server task alive");
        let last = next.path == "/good";
        delivered.push(next);
        if last {
            break;
        }
    }

    // WINDOW_UPDATE with a zero increment is a connection error (RFC 9113 6.9).
    write_all(&mut client, &frame(WINDOW_UPDATE, 0, 0, &[0, 0, 0, 0])).await;
    let mut resets = Vec::new();
    let goaway = loop {
        let frame = read_frame(&mut client)
            .await
            .unwrap_or_else(|| panic!("native={native}: connection closed without GOAWAY"));
        if let Some(code) = frame.rst_code() {
            resets.push((frame.stream, code));
        } else if let Some(goaway) = frame.goaway() {
            break goaway;
        }
    };
    Run {
        delivered,
        resets,
        goaway,
    }
}

/// One raw `:authority` and what the application must observe for it.
struct AuthorityCase {
    label: &'static str,
    authority: &'static [u8],
    /// A regular `host` field the client also sends, if any.
    host_field: Option<&'static [u8]>,
    /// Expected `Host` header value on the delivered request.
    want_host: &'static [u8],
}

fn seen(path: &str, uri_authority: Option<&str>, host: Option<&[u8]>) -> Seen {
    Seen {
        path: path.to_owned(),
        uri_authority: uri_authority.map(str::to_owned),
        host: host.map(<[u8]>::to_vec),
    }
}

fn good() -> Seen {
    seen("/good", Some("example.com"), None)
}

/// `:authority` values that `http::uri::Authority` rejects. For each, a
/// build without `go-server-lifecycle` resets stream 1 with `PROTOCOL_ERROR`;
/// with it the request is delivered with `Host` set to the raw authority, a
/// client-sent `host` field wins over the authority, and the next stream id
/// still advances (stream 3 is served and the GOAWAY names stream 3).
#[tokio::test]
async fn invalid_authority_is_kept_and_exposed_as_host_like_go() {
    let cases = [
        // The literal value from upstream h2's `recv_invalid_authority`.
        AuthorityCase {
            label: "upstream recv_invalid_authority value",
            authority: b"not:a/good authority",
            host_field: None,
            want_host: b"not:a/good authority",
        },
        // grpc-go's authority when dialling a unix socket: the socket path with
        // its slashes percent-escaped.
        AuthorityCase {
            label: "grpc-go percent-encoded unix socket path",
            authority: b"%2Fvar%2Frun%2Fheadscale%2Fheadscale.sock",
            host_field: None,
            want_host: b"%2Fvar%2Frun%2Fheadscale%2Fheadscale.sock",
        },
        // The unescaped socket target some clients put in :authority.
        AuthorityCase {
            label: "raw unix:// socket target",
            authority: b"unix:///var/run/headscale.sock",
            host_field: None,
            want_host: b"unix:///var/run/headscale.sock",
        },
        // Go would report the :authority as Request.Host even here; the patch
        // documents the opposite choice (surface the authority as `Host` only
        // when the client sent none), so a client `host` field is left alone.
        AuthorityCase {
            label: "client-supplied host field is not overwritten",
            authority: b"not:a/good authority",
            host_field: Some(b"client.example"),
            want_host: b"client.example",
        },
    ];

    let mut failures = Vec::new();
    for AuthorityCase {
        label,
        authority,
        host_field,
        want_host,
    } in cases
    {
        for native in [false, true] {
            let got = run(native, authority, host_field).await;
            let want_bad = seen("/bad", None, Some(want_host));
            let ok = got.delivered == [want_bad.clone(), good()]
                && got.resets.is_empty()
                && got.goaway == (3, PROTOCOL_ERROR);
            if !ok {
                failures.push(format!(
                    "[{label}] native={native}: expected [{want_bad:?}, {:?}], no resets, GOAWAY(3, PROTOCOL_ERROR); got {got:?}",
                    good()
                ));
            }
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// A *valid* authority is unaffected: it stays in the URI and no `Host` field
/// is synthesised (guards against the native arm over-reaching).
#[tokio::test]
async fn valid_authority_stays_in_the_uri_without_a_synthesised_host() {
    for native in [false, true] {
        let got = run(native, b"example.org:8443", None).await;
        assert_eq!(
            got.delivered,
            [seen("/bad", Some("example.org:8443"), None), good()],
            "native={native}"
        );
        assert!(got.resets.is_empty(), "native={native}: {:?}", got.resets);
    }
}

/// Premise of the "stock rejects" half: every raw authority used above is one
/// that `http::uri::Authority` (what stock h2 converts `:authority` with)
/// cannot parse, so a build without `go-server-lifecycle` resets the stream;
/// the valid control value parses.
#[test]
fn the_http_crate_rejects_the_authorities_the_native_server_keeps() {
    for bad in [
        &b"not:a/good authority"[..],
        b"%2Fvar%2Frun%2Fheadscale%2Fheadscale.sock",
        b"unix:///var/run/headscale.sock",
    ] {
        assert!(
            http::uri::Authority::try_from(bad).is_err(),
            "{:?} unexpectedly parses as a URI authority",
            String::from_utf8_lossy(bad)
        );
    }
    assert!(http::uri::Authority::try_from(&b"example.org:8443"[..]).is_ok());
}
