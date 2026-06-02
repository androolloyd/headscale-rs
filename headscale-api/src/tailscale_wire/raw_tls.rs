//! Raw `tokio-rustls` listener that bypasses `axum-server` /
//! `hyper-rustls` for the `/ts2021` upgrade path.
//!
//! ## Why this exists
//!
//! Stock `tailscale up` v1.78+ opens a TLS connection to `:443`, sends
//! `POST /ts2021` with `Upgrade: tailscale-control-protocol`, expects
//! a `101 Switching Protocols` response, then **immediately** writes
//! the Noise IK Initiation frame on the same TCP socket.
//!
//! When the underlying server runs through `axum-server::bind_rustls`
//! → `hyper::server::conn::http1::Builder::serve_connection`,
//! hyper-rustls' read buffer drains the Initiation bytes off the wire
//! between the 101 response and the moment our handler regains control
//! of the upgraded socket via `hyper::upgrade::OnUpgrade`. The handler
//! then waits forever for an Initiation frame that's already gone,
//! and the client times out (observed wall in
//! `docs/tailscale-interop-blocker.md` 2026-05-19 §"P0 batch shipped":
//! `WARN noise: ts2021 connection ended with error error=noise
//! handshake: read initiation frame: early eof`).
//!
//! ## The fix
//!
//! Run `tokio_rustls::TlsAcceptor` directly on `:443` and peek the
//! request line ourselves *before* committing the connection to any
//! HTTP server. If the first line is `POST /ts2021 ...` with the
//! expected Upgrade header, we write the `101` response by hand and
//! hand the unbuffered `TlsStream<TcpStream>` straight to
//! [`crate::tailscale_wire::noise::drive_ts2021`]. Otherwise we wrap
//! the stream in [`PrefixedStream`] (so the peek bytes survive) and
//! hand it to `hyper::server::conn::http1` with the existing axum
//! router as the tower service.
//!
//! ## Decision log
//!
//! - **Single new dep: `tokio-rustls = "0.26"`.** Matches the
//!   `rustls = "0.23"` already pinned. No additional crypto provider
//!   work — `rustls::crypto::aws_lc_rs::default_provider().install_default()`
//!   already runs from `tls::build_server_config`.
//! - **Peek with a fixed-size buffer, not `AsyncBufReadExt::fill_buf`.**
//!   The smallest valid HTTP request line we care about is the
//!   `/ts2021` POST (~80 bytes including the Upgrade header). 1 KiB
//!   covers everything we need to disambiguate; anything larger we
//!   defer to hyper. We don't actually parse headers in the upgrade
//!   path beyond a substring check for `tailscale-control-protocol` —
//!   the actual HTTP/1.1 parser stays in hyper for the non-/ts2021
//!   path.
//! - **`PrefixedStream<T>` for non-/ts2021 traffic.** A thin adapter
//!   that emits the peeked bytes from a small in-memory buffer before
//!   delegating reads to the underlying TLS stream. Keeps hyper's
//!   buffering model intact for the routes it still serves (`/key`,
//!   `/machine/*`, etc.).
//! - **Per-connection task isolation.** Accept loop spawns one task
//!   per connection. A handshake failure or a slow client cannot
//!   stall the listener.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use axum::Router;
use hyper::body::Incoming as HyperBody;
use hyper_util::rt::TokioIo;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tower::ServiceExt;

use super::WireState;
use super::noise::{UPGRADE_PROTOCOL, drive_ts2021_be_with_init};
use super::tls::ReloadableServerConfig;

/// HTTP header carrying a base64-encoded controlbase Initiation
/// frame. Stock Tailscale clients (v1.42+) populate this on the
/// `POST /ts2021` request so the server can decode the Initiation
/// up-front and avoid an extra RTT.
///
/// Sourced from `tailscale/control/controlhttp/controlhttpcommon/controlhttpcommon.go`:
/// `HandshakeHeaderName = "X-Tailscale-Handshake"`. The value is the
/// base64-StdEncoding of the entire controlbase-framed Initiation
/// (5-byte header + Noise body).
pub const HANDSHAKE_HEADER_NAME: &str = "X-Tailscale-Handshake";

/// How many bytes we read off a freshly-accepted TLS stream before
/// deciding whether to hijack it for `/ts2021`. 1 KiB is enough to
/// see the request line + `Upgrade:` header in any reasonable client
/// (the actual fields are well under 200 bytes).
const PEEK_BUFFER_BYTES: usize = 1024;

/// Bind a raw rustls listener on `addr` and dispatch per-connection.
///
/// `router` is the same axum router served on the plaintext :51821
/// path. Connections that aren't `/ts2021` upgrades get routed through
/// it via hyper-on-top-of-tokio-rustls; `/ts2021` upgrades bypass
/// hyper entirely and hand the unbuffered TLS stream to
/// [`drive_ts2021`].
///
/// Returns `Ok(())` only on listener shutdown (i.e., never under
/// normal operation). Individual connection failures are logged and
/// dropped.
pub async fn serve_raw_tls(
    addr: SocketAddr,
    tls: ReloadableServerConfig,
    router: Router,
    wire_state: WireState,
) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(
        target = "tailscale_wire::raw_tls",
        %addr,
        "raw rustls listener bound"
    );

    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                // EMFILE etc. — log and keep going.
                tracing::warn!(
                    target = "tailscale_wire::raw_tls",
                    error = %e,
                    "tcp accept failed; continuing"
                );
                continue;
            }
        };
        let acceptor = TlsAcceptor::from(tls.current());
        let router = router.clone();
        let wire_state = wire_state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_one(acceptor, tcp, peer, router, wire_state).await {
                tracing::debug!(
                    target = "tailscale_wire::raw_tls",
                    %peer,
                    error = %e,
                    "connection ended with error"
                );
            }
        });
    }
}

async fn handle_one(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    peer: SocketAddr,
    router: Router,
    wire_state: WireState,
) -> io::Result<()> {
    // 1. TLS handshake.
    let mut tls = acceptor.accept(tcp).await?;

    // 2. Peek bytes until we can identify the request line + Upgrade
    //    header. We keep reading until either we see "\r\n\r\n" (end
    //    of headers) or we exceed PEEK_BUFFER_BYTES (in which case we
    //    bail to hyper — anything that big isn't our /ts2021 path).
    let mut buf = Vec::with_capacity(PEEK_BUFFER_BYTES);
    let mut tmp = [0u8; 256];
    let mut saw_header_end = false;
    while buf.len() < PEEK_BUFFER_BYTES {
        let n = tls.read(&mut tmp).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if find_header_end(&buf).is_some() {
            saw_header_end = true;
            break;
        }
    }

    // Log the request line + dispatch decision so the docker harness
    // has a breadcrumb when things go sideways. Strip control chars
    // from the request line so we don't dump a noise frame into the
    // structured log.
    let preview_end = buf
        .iter()
        .position(|b| *b == b'\n' || *b == b'\r')
        .unwrap_or(buf.len().min(64));
    let preview = String::from_utf8_lossy(&buf[..preview_end]);
    tracing::debug!(
        target = "tailscale_wire::raw_tls",
        %peer,
        peek_len = buf.len(),
        saw_header_end,
        request_line = %preview,
        "peek complete"
    );

    // 3. Inspect the head of the request.
    let is_ts2021 = saw_header_end && is_ts2021_upgrade(&buf);

    if is_ts2021 {
        let body_after_headers = body_tail(&buf);
        // Extract the optional `X-Tailscale-Handshake` header — newer
        // clients (v1.42+) send the entire framed Initiation in this
        // base64-encoded header value, with an empty request body.
        // Older clients pipeline the Initiation as the request body
        // after the 101 response.
        let handshake_header = extract_header_value(&buf, HANDSHAKE_HEADER_NAME);
        let initial_frame = match handshake_header {
            Some(b64) => match base64_decode(&b64) {
                Ok(bytes) => Some(bytes),
                Err(e) => {
                    tracing::warn!(
                        target = "tailscale_wire::raw_tls",
                        %peer,
                        error = %e,
                        "X-Tailscale-Handshake header present but base64-decode failed; treating as pipelined client"
                    );
                    None
                }
            },
            None => None,
        };
        tracing::debug!(
            target = "tailscale_wire::raw_tls",
            %peer,
            post_header_bytes = body_after_headers.len(),
            fast_start = initial_frame.is_some(),
            "dispatching /ts2021 to drive_ts2021_be (BE-nonce transport)"
        );
        // 4a. Verify the Upgrade header is present *and* matches —
        //     `is_ts2021_upgrade` already does this. Write the 101
        //     by hand (bypassing hyper) so the post-101 bytes from the
        //     client land on the unbuffered TLS stream.
        write_101(&mut tls).await?;
        let stream = PrefixedStream::new(body_after_headers.to_vec(), tls);
        // `drive_ts2021_be_with_init` switches to BE-nonce transport
        // ChaCha20Poly1305 records after the snow IK handshake completes.
        // Closes Wall 4 from `docs/tailscale-interop-blocker.md`.
        drive_ts2021_be_with_init(wire_state, stream, initial_frame)
            .await
            .map_err(|e| io::Error::other(format!("ts2021: {e}")))?;
        return Ok(());
    }

    // 4b. Non-/ts2021 traffic — feed the prefixed stream into hyper
    //     http1 and hand requests off to the axum router as a tower
    //     service.
    let prefixed = PrefixedStream::new(buf, tls);
    let svc = hyper::service::service_fn(move |req: hyper::Request<HyperBody>| {
        let router = router.clone();
        async move {
            // axum 0.7 routers are tower::Service<Request<Body>>; the
            // request body type is `axum::body::Body`. Convert by
            // re-wrapping the hyper Incoming body.
            let (parts, body) = req.into_parts();
            let body = axum::body::Body::new(body);
            let mut axum_req = http::Request::from_parts(parts, body);
            axum_req
                .extensions_mut()
                .insert(axum::extract::ConnectInfo(peer));
            axum_req.extensions_mut().insert(TlsRequest);
            // `Router::oneshot` makes a fresh service for this request.
            let resp = router
                .oneshot(axum_req)
                .await
                .map_err(|e| io::Error::other(format!("router service: {e}")))?;
            Ok::<_, io::Error>(resp)
        }
    });
    hyper::server::conn::http1::Builder::new()
        .serve_connection(TokioIo::new(prefixed), svc)
        .with_upgrades()
        .await
        .map_err(|e| io::Error::other(format!("hyper http1: {e}")))?;
    Ok(())
}

/// Write the `101 Switching Protocols` response by hand. We don't go
/// through hyper for this — the whole point of this module is that
/// hyper's read buffer would otherwise eat the Initiation bytes that
/// follow on the same TCP socket.
async fn write_101<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    const RESP: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n\
        Connection: upgrade\r\n\
        Upgrade: tailscale-control-protocol\r\n\
        \r\n";
    w.write_all(RESP).await?;
    w.flush().await?;
    Ok(())
}

/// Locate the end of the HTTP header block. Returns the index of the
/// first byte *after* the `\r\n\r\n` sequence, or `None` if not
/// present.
fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// True iff the buffer starts with `POST /ts2021 ` and the header
/// block contains an `Upgrade:` header that names the Tailscale
/// control protocol.
fn is_ts2021_upgrade(buf: &[u8]) -> bool {
    // Match the request line — first whitespace-delimited path token.
    if !buf.starts_with(b"POST ") {
        return false;
    }
    // Extract just the headers block (everything up to \r\n\r\n).
    let Some(headers_end) = find_header_end(buf) else {
        return false;
    };
    let headers = &buf[..headers_end];

    // Path check: second token on the request line.
    let request_line_end = headers
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(headers.len());
    let request_line = &headers[..request_line_end];
    let mut tokens = request_line.split(|c| *c == b' ');
    let _method = tokens.next();
    let path = tokens.next().unwrap_or(b"");
    // Accept any path that *starts with* `/ts2021` so a `?key=` query
    // string variant (used by some client versions) still matches.
    // Also accept the knock-prefixed variant `/k/<knock>/ts2021` —
    // stock tailscale clients dial that path when the operator enables
    // the PSK gate (see `tailscale_wire::knock`). The knock itself is
    // VALIDATED downstream by the axum router; this peek-and-dispatch
    // step just needs to recognise the request as a ts2021 upgrade so
    // we hand the unbuffered TLS stream to `drive_ts2021` instead of
    // routing it through the hyper http1 fallback.
    let path_ok = path == b"/ts2021"
        || path.starts_with(b"/ts2021?")
        || path.starts_with(b"/ts2021/")
        || super::knock::path_is_knocked_ts2021(path);
    if !path_ok {
        return false;
    }

    // Scan headers for `Upgrade: tailscale-control-protocol` (case-
    // insensitive on the header name; the value compare is also
    // case-insensitive per RFC 7230 §3.2.4).
    for line in headers.split(|c| *c == b'\n') {
        let trimmed = trim_trailing_cr(line);
        if trimmed.is_empty() {
            continue;
        }
        let Some(colon) = trimmed.iter().position(|c| *c == b':') else {
            continue;
        };
        let name = &trimmed[..colon];
        let value = trim_ascii(&trimmed[colon + 1..]);
        if eq_ignore_ascii_case(name, b"upgrade")
            && eq_ignore_ascii_case(value, UPGRADE_PROTOCOL.as_bytes())
        {
            return true;
        }
    }
    false
}

/// Returns the bytes that appear *after* the `\r\n\r\n` header
/// terminator in the peek buffer. If the buffer doesn't contain a
/// terminator (shouldn't happen on the /ts2021 path), returns the
/// empty slice.
fn body_tail(buf: &[u8]) -> &[u8] {
    match find_header_end(buf) {
        Some(end) => &buf[end..],
        None => &[],
    }
}

fn trim_trailing_cr(b: &[u8]) -> &[u8] {
    match b.last() {
        Some(&b'\r') => &b[..b.len() - 1],
        _ => b,
    }
}

fn trim_ascii(b: &[u8]) -> &[u8] {
    let start = b
        .iter()
        .position(|c| !c.is_ascii_whitespace())
        .unwrap_or(b.len());
    let end = b
        .iter()
        .rposition(|c| !c.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    &b[start..end]
}

/// Scan the HTTP header block (ending at the first `\r\n\r\n` in
/// `buf`) for the given case-insensitive header name, returning the
/// value as a `String` if found. Returns `None` if the headers are
/// truncated or the header is absent.
fn extract_header_value(buf: &[u8], name: &str) -> Option<String> {
    let end = find_header_end(buf)?;
    let headers = &buf[..end];
    let name_bytes = name.as_bytes();
    for line in headers.split(|c| *c == b'\n') {
        let trimmed = trim_trailing_cr(line);
        let Some(colon) = trimmed.iter().position(|c| *c == b':') else {
            continue;
        };
        let key = &trimmed[..colon];
        let val = trim_ascii(&trimmed[colon + 1..]);
        if eq_ignore_ascii_case(key, name_bytes) {
            return Some(String::from_utf8_lossy(val).into_owned());
        }
    }
    None
}

/// Base64-StdEncoding decode, mirroring the encoding tailscale uses
/// for the `X-Tailscale-Handshake` header value.
fn base64_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s)
}

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y)| x.eq_ignore_ascii_case(y))
}

/// AsyncRead/AsyncWrite adapter that yields a fixed prefix of bytes
/// before delegating to the underlying stream. Used for both the
/// `/ts2021` path (the post-header tail is potentially the start of
/// the Initiation frame) and the non-/ts2021 path (the peek bytes
/// are the actual HTTP request and hyper needs to see them).
pub(crate) struct PrefixedStream<T> {
    prefix: Vec<u8>,
    prefix_offset: usize,
    inner: T,
}

impl<T> PrefixedStream<T> {
    pub(crate) fn new(prefix: Vec<u8>, inner: T) -> Self {
        Self {
            prefix,
            prefix_offset: 0,
            inner,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for PrefixedStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.prefix_offset < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_offset..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.prefix_offset += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// Aliasing module to keep the (already used) `TlsStream<TcpStream>`
// signature local to the module without forcing an import on the
// caller.
#[allow(dead_code)]
type RawTlsStream = TlsStream<TcpStream>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsRequest;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::tailscale_wire::noise::drive_ts2021;
    use crate::tailscale_wire::{
        MachineRegistry, WireState,
        noise::ServerNoiseKey,
        test_support::{MockIpAllocator, MockRedeemer},
    };
    use tokio::io::{AsyncWriteExt, duplex};

    fn fixture_state() -> (WireState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let state = WireState {
            server_noise_key: server,
            preauth: Arc::new(MockRedeemer::new()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
            registration_store: None,
            derp_map: crate::tailscale_wire::DerpMapStore::shared(
                crate::tailscale_wire::wire::DerpMap::default(),
            ),
            native_derp: None,
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: None,
            runtime_config: Arc::new(crate::tailscale_wire::RuntimeConfigSnapshot::default()),
            registration_cache: Arc::new(crate::tailscale_wire::RegistrationCache::new()),
            pings: Arc::new(crate::tailscale_wire::PingTracker::new()),
            mapresponse_debug: Arc::new(crate::tailscale_wire::MapResponseDebugStore::disabled()),
        };
        (state, dir)
    }

    #[test]
    fn detects_ts2021_upgrade_request() {
        let req = b"POST /ts2021 HTTP/1.1\r\n\
            Host: tsi-mesh-control\r\n\
            Upgrade: tailscale-control-protocol\r\n\
            Connection: Upgrade\r\n\
            Content-Length: 0\r\n\
            \r\n";
        assert!(is_ts2021_upgrade(req));
    }

    #[test]
    fn rejects_ts2021_without_upgrade_header() {
        let req = b"POST /ts2021 HTTP/1.1\r\n\
            Host: tsi-mesh-control\r\n\
            Content-Length: 0\r\n\
            \r\n";
        assert!(!is_ts2021_upgrade(req));
    }

    #[test]
    fn rejects_non_ts2021_path() {
        let req = b"GET /key?v=39 HTTP/1.1\r\n\
            Host: tsi-mesh-control\r\n\
            \r\n";
        assert!(!is_ts2021_upgrade(req));
    }

    #[test]
    fn detects_ts2021_with_query_string() {
        let req = b"POST /ts2021?v=39 HTTP/1.1\r\n\
            Host: tsi-mesh-control\r\n\
            Upgrade: tailscale-control-protocol\r\n\
            \r\n";
        assert!(is_ts2021_upgrade(req));
    }

    #[test]
    fn upgrade_header_case_insensitive() {
        let req = b"POST /ts2021 HTTP/1.1\r\n\
            UPGRADE: TAILSCALE-CONTROL-PROTOCOL\r\n\
            \r\n";
        assert!(is_ts2021_upgrade(req));
    }

    #[test]
    fn find_header_end_works() {
        // "abc" (3) + "\r\n\r\n" (4) → first byte after header block at index 7.
        assert_eq!(find_header_end(b"abc\r\n\r\ndef"), Some(7));
        assert_eq!(find_header_end(b"no terminator here"), None);
    }

    #[test]
    fn body_tail_extracts_post_header_bytes() {
        let buf = b"POST /ts2021 HTTP/1.1\r\n\r\nINITIATION_BYTES";
        assert_eq!(body_tail(buf), b"INITIATION_BYTES");
    }

    #[test]
    fn extract_header_value_finds_x_tailscale_handshake() {
        let req = b"POST /ts2021 HTTP/1.1\r\n\
            Host: tsi-mesh-control\r\n\
            Upgrade: tailscale-control-protocol\r\n\
            X-Tailscale-Handshake: AIUBAGA+OZnWaATWMG==\r\n\
            \r\n";
        let v = extract_header_value(req, HANDSHAKE_HEADER_NAME);
        assert_eq!(v.as_deref(), Some("AIUBAGA+OZnWaATWMG=="));
    }

    #[test]
    fn extract_header_value_is_case_insensitive() {
        let req = b"POST /ts2021 HTTP/1.1\r\n\
            x-tailscale-handshake: abc\r\n\
            \r\n";
        assert_eq!(
            extract_header_value(req, HANDSHAKE_HEADER_NAME).as_deref(),
            Some("abc")
        );
    }

    #[test]
    fn extract_header_value_absent_returns_none() {
        let req = b"POST /ts2021 HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(extract_header_value(req, HANDSHAKE_HEADER_NAME).is_none());
    }

    #[tokio::test]
    async fn prefixed_stream_yields_prefix_then_inner() {
        let (mut client_in, server_in) = duplex(64);
        let prefix = b"AAA".to_vec();
        let mut s = PrefixedStream::new(prefix, server_in);
        client_in.write_all(b"BBB").await.unwrap();
        drop(client_in); // signal eof after BBB

        let mut out = Vec::new();
        let mut buf = [0u8; 8];
        loop {
            let n = s.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        assert_eq!(&out, b"AAABBB");
    }

    /// Hand-drive `drive_ts2021` via a duplex pair, where the
    /// "server" side wraps the duplex in a `PrefixedStream` whose
    /// prefix carries the bytes a real client sent in the same TCP
    /// segment as the headers — proving the prefix is preserved and
    /// `drive_ts2021` correctly reads the Initiation frame from it.
    ///
    /// This is the unit-test equivalent of the wire-level bug we're
    /// fixing: the bytes after the `\r\n\r\n` must survive the peek.
    #[tokio::test]
    async fn ts2021_dispatch_preserves_initiation_bytes_across_peek() {
        use crate::tailscale_wire::controlbase::{FrameHeader, Framed, MsgType};

        let (state, _dir) = fixture_state();
        let server_pub = state.server_noise_key.public_bytes();

        // Build the initiation frame the way a real client would.
        let mut init = state
            .server_noise_key
            .build_initiator_for_version(&server_pub, 113)
            .unwrap();
        let mut init_body = vec![0u8; 1024];
        let n = init.write_message(b"", &mut init_body).unwrap();
        init_body.truncate(n);
        // Upstream layout: [version:u16be][type=1:u8][len:u16be][body...]
        let mut init_frame = Vec::new();
        init_frame.extend_from_slice(&113u16.to_be_bytes());
        init_frame.push(MsgType::Initiation as u8);
        init_frame.extend_from_slice(&(init_body.len() as u16).to_be_bytes());
        init_frame.extend_from_slice(&init_body);

        // Two duplex sockets: client side feeds the Reply reader; the
        // server side reads the Initiation frame from the prefix.
        let (client_io, server_io) = duplex(64 * 1024);

        // Server task: pretend the peek consumed the bytes already
        // and wrap the duplex in PrefixedStream to replay them.
        let state_clone = state.clone();
        let server_task = tokio::spawn(async move {
            let prefixed = PrefixedStream::new(init_frame, server_io);
            drive_ts2021(state_clone, prefixed).await
        });

        // Client side: read the Reply frame off the duplex.
        let mut framed = Framed::new(client_io);
        let (hdr, reply_body) = framed.read_frame().await.expect("read reply");
        assert!(matches!(
            hdr,
            FrameHeader::Regular {
                msg_type: MsgType::Reply,
                ..
            }
        ));
        let mut throw = vec![0u8; 1024];
        init.read_message(&reply_body, &mut throw)
            .expect("noise reply decrypts");
        assert!(init.is_handshake_finished());

        drop(framed);
        let _ = server_task.await;
    }
}
