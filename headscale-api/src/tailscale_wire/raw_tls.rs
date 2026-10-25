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
//!   `/ts2021` POST and `/derp` fast-start requests. 1 KiB covers
//!   everything we need to disambiguate; anything larger we defer to
//!   hyper. We only parse the small header subset needed to identify
//!   protocol hijacks — the actual HTTP/1.1 parser stays in hyper for
//!   the ordinary route path.
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
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tower::ServiceExt;

use super::WireState;
#[cfg(feature = "full")]
use super::derp::drive_native_derp;
use super::noise::{UPGRADE_PROTOCOL, drive_ts2021_be_with_init_remote_addr};
use super::tls::ReloadableServerConfig;

#[cfg(feature = "full")]
mod acme_handshake;

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
#[cfg(feature = "full")]
const DERP_UPGRADE_PROTOCOL: &[u8] = b"derp";
#[cfg(feature = "full")]
const DERP_FAST_START_HEADER: &str = "Derp-Fast-Start";

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
    let bound_addr = listener.local_addr()?;
    serve_bound_raw_tls(listener, bound_addr, tls, router, wire_state).await
}

/// Serve raw rustls connections from an already-bound TCP listener.
pub async fn serve_bound_raw_tls(
    listener: TcpListener,
    addr: SocketAddr,
    tls: ReloadableServerConfig,
    router: Router,
    wire_state: WireState,
) -> io::Result<()> {
    serve_bound_raw_tls_with_shutdown(
        listener,
        addr,
        tls,
        router,
        wire_state,
        None,
        super::serve::TrustedProxyConfig::default(),
    )
    .await
}

pub(super) async fn serve_bound_raw_tls_with_shutdown(
    listener: TcpListener,
    addr: SocketAddr,
    tls: ReloadableServerConfig,
    router: Router,
    wire_state: WireState,
    native: Option<(
        std::sync::Arc<super::http_shutdown::Group>,
        super::http_shutdown::ListenerWork,
    )>,
    trusted_proxies: super::serve::TrustedProxyConfig,
) -> io::Result<()> {
    let (group, _listener_work) = match native {
        Some((group, work)) => (Some(group), Some(work)),
        None => (None, None),
    };
    tracing::info!(
        target = "tailscale_wire::raw_tls",
        %addr,
        "raw rustls listener bound"
    );

    loop {
        let accepted = match &group {
            Some(group) => tokio::select! {
                biased;
                () = group.closing() => {
                    drop(listener);
                    return Ok(());
                },
                accepted = listener.accept() => accepted,
            },
            None => listener.accept().await,
        };
        let (tcp, peer) = match accepted {
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
        let tls = tls.clone();
        let router = router.clone();
        let wire_state = wire_state.clone();
        let trusted_proxies = trusted_proxies.clone();
        let tracking = match &group {
            Some(group) => match group.connection() {
                Some(connection) => Some(connection),
                None => continue,
            },
            None => None,
        };
        tokio::spawn(async move {
            let cancelled = tracking.clone();
            let connection = Box::pin(handle_one(
                tls,
                tcp,
                peer,
                router,
                wire_state,
                tracking,
                trusted_proxies,
            ));
            let result = match cancelled {
                Some(cancelled) => tokio::select! {
                    biased;
                    () = cancelled.cancelled() => Ok(()),
                    result = connection => result,
                },
                None => connection.await,
            };
            if let Err(e) = result {
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

/// Complete a TLS handshake using the reloader's optional native ACME provider.
/// The caller owns admission and the deadline for the entire handshake.
#[doc(hidden)]
pub async fn accept_tls_with_config<IO>(
    reloader: ReloadableServerConfig,
    io: IO,
) -> io::Result<TlsStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    #[cfg(feature = "full")]
    if let Some(provider) = reloader.certificate_provider() {
        return acme_handshake::accept(reloader.current(), provider, io).await;
    }

    TlsAcceptor::from(reloader.current()).accept(io).await
}

async fn handle_one(
    reloader: ReloadableServerConfig,
    tcp: TcpStream,
    peer: SocketAddr,
    router: Router,
    wire_state: WireState,
    tracking: Option<std::sync::Arc<super::http_shutdown::Connection>>,
    trusted_proxies: super::serve::TrustedProxyConfig,
) -> io::Result<()> {
    // 1. TLS handshake.
    let pending_handshake = wire_state
        .server_noise_key
        .handshake_permit()
        .map_err(io::Error::other)?;
    let deadline = tokio::time::Instant::now() + super::noise::CONTROL_HANDSHAKE_TIMEOUT;
    let mut tls = tokio::time::timeout_at(deadline, accept_tls_with_config(reloader, tcp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;

    if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
        drop(pending_handshake);
        return super::http_shutdown::serve_h2_connection(tls, router, peer, tracking).await;
    }

    // 2. Peek bytes until we can identify the request line + Upgrade
    //    header. We keep reading until either we see "\r\n\r\n" (end
    //    of headers) or we exceed PEEK_BUFFER_BYTES (in which case we
    //    bail to hyper — anything that big isn't our /ts2021 path).
    let mut buf = Vec::with_capacity(PEEK_BUFFER_BYTES);
    let mut tmp = [0u8; 256];
    let mut saw_header_end = false;
    while buf.len() < PEEK_BUFFER_BYTES {
        let n = tokio::time::timeout_at(deadline, tls.read(&mut tmp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP headers timed out"))??;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if find_header_end(&buf).is_some() {
            saw_header_end = true;
            break;
        }
    }
    drop(pending_handshake);

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

    // 3. Inspect the head of the request. Hijack only what Go's
    //    `controlhttpserver.acceptHTTP` hijacks: the control upgrade carrying
    //    a decodable `X-Tailscale-Handshake` (the whole framed Initiation,
    //    base64). A missing or undecodable header falls through to hyper,
    //    where the axum handler answers Go's 400 before any Noise state or
    //    handshake permit exists.
    let initial_frame = (saw_header_end && is_ts2021_upgrade(&buf))
        .then(|| extract_header_value(&buf, HANDSHAKE_HEADER_NAME))
        .flatten()
        .filter(|encoded| !encoded.is_empty())
        .and_then(|encoded| base64_decode(&encoded).ok());

    if let Some(initial_frame) = initial_frame {
        if tracking.as_ref().is_some_and(|tracking| !tracking.admit()) {
            return Ok(());
        }
        if !knock_admits(&buf, &wire_state.knock) {
            return write_knock_404(&mut tls).await;
        }
        let remote_addr = raw_request_log_remote_addr(&buf, peer, &trusted_proxies);
        let _request_event = wire_state
            .machines
            .policy_routes_require_persistence()
            .then(|| super::request_log::Event::raw(&buf, remote_addr.clone(), 101));
        let body_after_headers = body_tail(&buf);
        tracing::debug!(
            target = "tailscale_wire::raw_tls",
            %peer,
            post_header_bytes = body_after_headers.len(),
            "dispatching /ts2021 to drive_ts2021_be (BE-nonce transport)"
        );
        // 4a. Verify the Upgrade header is present *and* matches —
        //     `is_ts2021_upgrade` already does this. Write the 101
        //     by hand (bypassing hyper) so the post-101 bytes from the
        //     client land on the unbuffered TLS stream.
        write_101(&mut tls).await?;
        if let Some(tracking) = &tracking {
            tracking.hijack();
        }
        let stream = PrefixedStream::new(body_after_headers.to_vec(), tls);
        // `drive_ts2021_be_with_init` switches to BE-nonce transport
        // ChaCha20Poly1305 records after the snow IK handshake completes.
        // Closes Wall 4 from `docs/tailscale-interop-blocker.md`.
        drive_ts2021_be_with_init_remote_addr(
            wire_state,
            stream,
            Some(initial_frame),
            Some(remote_addr),
        )
        .await
        .map_err(|e| io::Error::other(format!("ts2021: {e}")))?;
        return Ok(());
    }

    #[cfg(feature = "full")]
    if saw_header_end && is_derp_fast_start_upgrade(&buf) {
        if tracking.as_ref().is_some_and(|tracking| !tracking.admit()) {
            return Ok(());
        }
        if !knock_admits(&buf, &wire_state.knock) {
            return write_knock_404(&mut tls).await;
        }
        let _request_event = wire_state
            .machines
            .policy_routes_require_persistence()
            .then(|| {
                super::request_log::Event::raw(
                    &buf,
                    raw_request_log_remote_addr(&buf, peer, &trusted_proxies),
                    0,
                )
            });
        let body_after_headers = body_tail(&buf);
        let Some(runtime) = wire_state.native_derp.clone() else {
            return Err(io::Error::other(
                "DERP fast-start requested but native DERP runtime is not configured",
            ));
        };
        tracing::debug!(
            target = "tailscale_wire::raw_tls",
            %peer,
            post_header_bytes = body_after_headers.len(),
            "dispatching /derp fast-start to native DERP runtime"
        );
        let stream = PrefixedStream::new(body_after_headers.to_vec(), tls);
        if let Some(tracking) = &tracking {
            tracking.hijack();
        }
        drive_native_derp(runtime, stream)
            .await
            .map_err(|e| io::Error::other(format!("DERP fast-start: {e}")))?;
        return Ok(());
    }

    // 4b. Non-/ts2021 traffic — feed the prefixed stream into hyper
    //     http1 and hand requests off to the axum router as a tower
    //     service.
    let prefixed = PrefixedStream::new(buf, tls);
    if let Some(tracking) = tracking {
        return super::http_shutdown::serve_connection(
            prefixed,
            router,
            peer,
            true,
            tracking,
            Some(super::noise::CONTROL_HANDSHAKE_TIMEOUT),
        )
        .await;
    }
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
        .timer(TokioTimer::new())
        .header_read_timeout(super::noise::CONTROL_HANDSHAKE_TIMEOUT)
        .serve_connection(TokioIo::new(prefixed), svc)
        .with_upgrades()
        .await
        .map_err(|e| io::Error::other(format!("hyper http1: {e}")))?;
    Ok(())
}

fn raw_request_log_remote_addr(
    head: &[u8],
    peer: SocketAddr,
    trusted: &super::serve::TrustedProxyConfig,
) -> super::request_log::RequestLogRemoteAddr {
    let mut headers = http::HeaderMap::new();
    let end = find_header_end(head).unwrap_or(head.len());
    for line in head[..end].split(|byte| *byte == b'\n') {
        let line = trim_trailing_cr(line);
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            continue;
        };
        for name in ["true-client-ip", "x-real-ip", "x-forwarded-for"] {
            if eq_ignore_ascii_case(&line[..colon], name.as_bytes())
                && let Ok(value) = http::HeaderValue::from_bytes(trim_ascii(&line[colon + 1..]))
            {
                headers.append(name, value);
                break;
            }
        }
    }
    super::serve::request_log_remote_addr(&headers, peer, trusted)
}

/// The knock gate is router middleware (`knock::wrap_router`), and the
/// hijacked upgrade paths above never reach the router. Apply its rule to
/// the peeked head instead: a `/k/<knock>/…` path must carry a valid
/// segment, any other path a valid [`knock::KNOCK_HEADER`]. A disabled
/// config admits everything, exactly like the router's pass-through.
fn knock_admits(buf: &[u8], cfg: &super::knock::KnockConfig) -> bool {
    if !cfg.enabled {
        return true;
    }
    let Some(headers_end) = find_header_end(buf) else {
        return false;
    };
    let Some(path) = request_path(&buf[..headers_end]) else {
        return false;
    };
    if let Some(rest) = path.strip_prefix(super::knock::KNOCK_PATH_PREFIX.as_bytes()) {
        let knock = rest.split(|byte| *byte == b'/').next().unwrap_or_default();
        return std::str::from_utf8(knock).is_ok_and(|knock| cfg.verify(knock));
    }
    extract_header_value(buf, super::knock::KNOCK_HEADER).is_some_and(|knock| cfg.verify(&knock))
}

/// The same canonical nginx 404 the router answers a failed knock with,
/// written by hand because this connection never reaches hyper.
async fn write_knock_404<W: AsyncWrite + Unpin>(w: &mut W) -> io::Result<()> {
    let body = super::knock::NGINX_404_BODY;
    let head = format!(
        "HTTP/1.1 404 Not Found\r\n\
         Server: nginx/1.18.0\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        body.len()
    );
    w.write_all(head.as_bytes()).await?;
    w.write_all(body.as_bytes()).await?;
    w.flush().await?;
    w.shutdown().await
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

/// True iff the buffer starts with an HTTP request for `/derp`, carries
/// `Upgrade: DERP`, and opts into Tailscale's no-HTTP-response DERP fast-start.
#[cfg(feature = "full")]
fn is_derp_fast_start_upgrade(buf: &[u8]) -> bool {
    let Some(headers_end) = find_header_end(buf) else {
        return false;
    };
    let headers = &buf[..headers_end];
    let Some(path) = request_path(headers) else {
        return false;
    };
    if path != b"/derp" && !path.starts_with(b"/derp?") {
        return false;
    }

    let mut upgrade_derp = false;
    let mut fast_start = false;
    for line in headers.split(|c| *c == b'\n') {
        let trimmed = trim_trailing_cr(line);
        let Some(colon) = trimmed.iter().position(|c| *c == b':') else {
            continue;
        };
        let name = &trimmed[..colon];
        let value = trim_ascii(&trimmed[colon + 1..]);
        if eq_ignore_ascii_case(name, b"upgrade")
            && eq_ignore_ascii_case(value, DERP_UPGRADE_PROTOCOL)
        {
            upgrade_derp = true;
        }
        if eq_ignore_ascii_case(name, DERP_FAST_START_HEADER.as_bytes()) && value == b"1" {
            fast_start = true;
        }
    }
    upgrade_derp && fast_start
}

fn request_path(headers: &[u8]) -> Option<&[u8]> {
    let request_line_end = headers
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(headers.len());
    let request_line = &headers[..request_line_end];
    let mut tokens = request_line.split(|c| *c == b' ');
    let _method = tokens.next()?;
    tokens.next()
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
    #[cfg(feature = "full")]
    use headscale_core::derp::{
        native::NativeDerpRelay,
        protocol::{
            ClientInfo, DerpNodeKeyPair, Frame, FrameDecoder, KEY_LEN, MAX_INFO_LEN, ServerInfo,
            encode_client_info_frame, open_server_info,
        },
    };
    #[cfg(feature = "full")]
    use tokio::io::AsyncRead;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    fn fixture_state() -> (WireState, tempfile::TempDir) {
        fixture_state_with_knock(crate::tailscale_wire::KnockConfig::disabled())
    }

    fn fixture_state_with_knock(
        knock: crate::tailscale_wire::KnockConfig,
    ) -> (WireState, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let state = WireState {
            server_noise_key: server,
            preauth: Arc::new(MockRedeemer::new()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
            registration_store: None,
            registration_gate: None,
            derp_map: crate::tailscale_wire::DerpMapStore::shared(
                crate::tailscale_wire::wire::DerpMap::default(),
            ),
            #[cfg(feature = "full")]
            native_derp: None,
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock,
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
        let req = b"GET /key?v=138 HTTP/1.1\r\n\
            Host: tsi-mesh-control\r\n\
            \r\n";
        assert!(!is_ts2021_upgrade(req));
    }

    #[test]
    #[cfg(feature = "full")]
    fn detects_derp_fast_start_upgrade_request() {
        let req = b"GET /derp HTTP/1.1\r\n\
            Host: derp.example\r\n\
            Upgrade: DERP\r\n\
            Connection: Upgrade\r\n\
            Derp-Fast-Start: 1\r\n\
            \r\n";
        assert!(is_derp_fast_start_upgrade(req));
    }

    #[test]
    #[cfg(feature = "full")]
    fn detects_derp_fast_start_with_query_string() {
        let req = b"GET /derp?mesh=1 HTTP/1.1\r\n\
            Host: derp.example\r\n\
            upgrade: derp\r\n\
            derp-fast-start: 1\r\n\
            \r\n";
        assert!(is_derp_fast_start_upgrade(req));
    }

    #[test]
    #[cfg(feature = "full")]
    fn rejects_derp_upgrade_without_fast_start() {
        let req = b"GET /derp HTTP/1.1\r\n\
            Host: derp.example\r\n\
            Upgrade: DERP\r\n\
            Connection: Upgrade\r\n\
            \r\n";
        assert!(!is_derp_fast_start_upgrade(req));
    }

    #[test]
    #[cfg(feature = "full")]
    fn rejects_derp_fast_start_websocket() {
        let req = b"GET /derp HTTP/1.1\r\n\
            Host: derp.example\r\n\
            Upgrade: websocket\r\n\
            Sec-WebSocket-Protocol: derp\r\n\
            Derp-Fast-Start: 1\r\n\
            \r\n";
        assert!(!is_derp_fast_start_upgrade(req));
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

    /// Send one HTTP/1.1 request over a fresh TLS connection and return the
    /// bytes the server answered with: the head plus a `Content-Length` body
    /// (or everything up to a close), or just the head of a `101`, which
    /// hands the socket to the Noise driver that then waits for frames.
    async fn raw_tls_exchange(
        addr: SocketAddr,
        connector: &tokio_rustls::TlsConnector,
        request: &str,
    ) -> String {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("test-host").unwrap();
        let mut tls = connector.connect(server_name, tcp).await.unwrap();
        tls.write_all(request.as_bytes()).await.unwrap();
        tls.flush().await.unwrap();
        let mut response = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read =
                tokio::time::timeout(std::time::Duration::from_secs(10), tls.read(&mut chunk))
                    .await
                    .expect("server answers within the timeout");
            match read {
                Ok(0) | Err(_) => break,
                Ok(n) => response.extend_from_slice(&chunk[..n]),
            }
            let Some(head_end) = find_header_end(&response) else {
                continue;
            };
            if response.starts_with(b"HTTP/1.1 101") {
                break;
            }
            let body_len = extract_header_value(&response, "content-length")
                .and_then(|value| value.parse::<usize>().ok());
            if body_len.is_some_and(|body_len| response.len() >= head_end + body_len) {
                break;
            }
        }
        String::from_utf8_lossy(&response).into_owned()
    }

    /// The knock gate is axum middleware; the hijacked `/ts2021` upgrade
    /// never reaches the router, so the raw listener must enforce the same
    /// rule itself. Without it an unauthenticated peer skips the PSK gate by
    /// speaking the upgrade directly over TLS.
    #[tokio::test]
    async fn raw_tls_hijack_enforces_knock_gate() {
        use crate::tailscale_wire::controlbase::MsgType;
        use crate::tailscale_wire::knock::{KNOCK_HEADER, KnockConfig, NGINX_404_BODY};
        use crate::tailscale_wire::tls::{ReloadableServerConfig, SanConfig, load_or_generate};
        use base64::Engine as _;
        use rustls::pki_types::{CertificateDer, pem::PemObject};

        let mut psk = [0u8; 32];
        for (i, byte) in psk.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let knock = KnockConfig::enabled(psk);
        let (state, dir) = fixture_state_with_knock(knock.clone());
        let material =
            load_or_generate(dir.path(), &SanConfig::with_hostname("test-host")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_bound_raw_tls(
            listener,
            addr,
            ReloadableServerConfig::new(Arc::clone(&material.server_config)),
            Router::new(),
            state.clone(),
        ));

        // A well-formed Initiation, as a stock client puts in the header.
        let server_pub = state.server_noise_key.public_bytes();
        let mut init = state
            .server_noise_key
            .build_initiator_for_version(&server_pub, 113)
            .unwrap();
        let mut init_body = vec![0u8; 1024];
        let n = init.write_message(b"", &mut init_body).unwrap();
        init_body.truncate(n);
        let mut init_frame = Vec::new();
        init_frame.extend_from_slice(&113u16.to_be_bytes());
        init_frame.push(MsgType::Initiation as u8);
        init_frame.extend_from_slice(&(init_body.len() as u16).to_be_bytes());
        init_frame.extend_from_slice(&init_body);
        let handshake = base64::engine::general_purpose::STANDARD.encode(&init_frame);

        let mut roots = rustls::RootCertStore::empty();
        let leaf = CertificateDer::pem_slice_iter(material.cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        roots.add(leaf).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let request = |path: &str, extra_header: &str| {
            format!(
                "POST {path} HTTP/1.1\r\n\
                 Host: test-host\r\n\
                 Upgrade: tailscale-control-protocol\r\n\
                 Connection: Upgrade\r\n\
                 {HANDSHAKE_HEADER_NAME}: {handshake}\r\n\
                 {extra_header}\
                 \r\n"
            )
        };

        // Bare path without the header, and a wrong path knock: the same
        // canonical nginx 404 the router answers, never a 101.
        let response = raw_tls_exchange(addr, &connector, &request("/ts2021", "")).await;
        assert!(
            response.starts_with("HTTP/1.1 404 "),
            "bare /ts2021 without a knock must not be hijacked: {response}"
        );
        assert!(response.ends_with(NGINX_404_BODY), "{response}");
        let response =
            raw_tls_exchange(addr, &connector, &request("/k/0000000000000000/ts2021", "")).await;
        assert!(
            response.starts_with("HTTP/1.1 404 "),
            "wrong path knock must not be hijacked: {response}"
        );
        assert!(response.ends_with(NGINX_404_BODY), "{response}");

        // A valid knock in either position still upgrades.
        let current = knock.current_knock();
        let response = raw_tls_exchange(
            addr,
            &connector,
            &request("/ts2021", &format!("{KNOCK_HEADER}: {current}\r\n")),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 101 "),
            "header knock must upgrade: {response}"
        );
        let response = raw_tls_exchange(
            addr,
            &connector,
            &request(&format!("/k/{current}/ts2021"), ""),
        )
        .await;
        assert!(
            response.starts_with("HTTP/1.1 101 "),
            "path knock must upgrade: {response}"
        );

        server.abort();
    }

    /// Go's `acceptHTTP` answers a missing or undecodable
    /// `X-Tailscale-Handshake` header with a 400 before hijacking. The raw
    /// listener must not write a 101 and park the socket in the Noise driver
    /// (holding a handshake permit for the 30 s deadline) for such a request.
    #[tokio::test]
    async fn raw_tls_ts2021_without_handshake_header_is_answered_before_hijack() {
        use crate::tailscale_wire::tls::{ReloadableServerConfig, SanConfig, load_or_generate};
        use rustls::pki_types::{CertificateDer, pem::PemObject};

        let (state, dir) = fixture_state();
        let material =
            load_or_generate(dir.path(), &SanConfig::with_hostname("test-host")).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(serve_bound_raw_tls(
            listener,
            addr,
            ReloadableServerConfig::new(Arc::clone(&material.server_config)),
            crate::tailscale_wire::router(state.clone()),
            state.clone(),
        ));
        let mut roots = rustls::RootCertStore::empty();
        let leaf = CertificateDer::pem_slice_iter(material.cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        roots.add(leaf).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let permits = state.server_noise_key.available_handshake_permits();

        for (handshake_header, expected) in [
            ("", "missing Tailscale handshake header\n"),
            (
                "X-Tailscale-Handshake: !!!\r\n",
                "invalid tailscale handshake header\n",
            ),
        ] {
            let request = format!(
                "POST /ts2021 HTTP/1.1\r\n\
                 Host: test-host\r\n\
                 Upgrade: tailscale-control-protocol\r\n\
                 Connection: Upgrade\r\n\
                 {handshake_header}\
                 \r\n"
            );
            let response = raw_tls_exchange(addr, &connector, &request).await;
            assert!(
                response.starts_with("HTTP/1.1 400 "),
                "{handshake_header:?}: {response}"
            );
            assert!(
                response.ends_with(expected),
                "{handshake_header:?}: {response}"
            );
            assert_eq!(
                state.server_noise_key.available_handshake_permits(),
                permits,
                "{handshake_header:?}: no handshake permit may stay held"
            );
        }

        server.abort();
    }

    #[tokio::test]
    #[cfg(feature = "full")]
    async fn derp_fast_start_dispatch_preserves_client_info_bytes_across_peek() {
        let runtime = Arc::new(crate::tailscale_wire::derp::NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let server_public = runtime.public_key();
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        let (client_io, server_io) = duplex(64 * 1024);
        let server_runtime = runtime.clone();
        let server_task = tokio::spawn(async move {
            let prefixed = PrefixedStream::new(client_info, server_io);
            crate::tailscale_wire::derp::drive_native_derp(server_runtime, prefixed).await
        });
        let (mut client_reader, client_writer) = tokio::io::split(client_io);
        let mut decoder = FrameDecoder::new(MAX_INFO_LEN);

        let server_key = read_derp_frame(&mut client_reader, &mut decoder).await;
        let Frame::ServerKey { key, extra } = server_key else {
            panic!("expected server-key frame");
        };
        assert_eq!(key, server_public);
        assert_eq!(extra, [] as [u8; 0]);

        let server_info = read_derp_frame(&mut client_reader, &mut decoder).await;
        assert_eq!(
            open_server_info(&client_key, &server_public, &server_info).unwrap(),
            ServerInfo::current()
        );

        drop(client_writer);
        drop(client_reader);
        assert!(server_task.await.unwrap().is_ok());
    }

    #[cfg(feature = "full")]
    async fn read_derp_frame<R>(reader: &mut R, decoder: &mut FrameDecoder) -> Frame
    where
        R: AsyncRead + Unpin,
    {
        let mut buf = [0u8; 1024];
        loop {
            if let Some(frame) = decoder.next_frame().unwrap() {
                return frame;
            }
            let n = reader.read(&mut buf).await.unwrap();
            assert!(n > 0, "DERP stream closed before next frame");
            decoder.push(&buf[..n]);
        }
    }
}
