// Copyright 2009 The Go Authors. All rights reserved.
// Go net/http shutdown polling adaptations; see LICENSE-GO-STDLIB.

use std::collections::BTreeMap;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::{Router, body::Body};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use parking_lot::Mutex;
use rand_core::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{Notify, oneshot};
use tokio::time::Instant;
use tower::ServiceExt;

use super::native_shutdown::{NativeShutdown, NativeWork};

/// Native CLI HTTP shutdown control. Existing embedding serve handles remain
/// unchanged. The deadline is shared by diagnostics and the main listeners.
#[doc(hidden)]
#[derive(Clone, Default)]
pub struct HttpShutdownControl {
    pub(super) debug: Arc<Group>,
    pub(super) main: Arc<Group>,
}

impl HttpShutdownControl {
    pub async fn shutdown(&self) {
        let deadline = Instant::now() + Duration::from_secs(3);
        if self.debug.configured.load(Ordering::SeqCst) {
            tracing::info!("shutting down debug http server");
            self.debug.shutdown(deadline, "debug").await;
        }
        tracing::info!("shutting down main http server");
        self.main.shutdown(deadline, "main").await;
    }
}

#[derive(Default)]
pub(super) struct Group {
    work: Arc<NativeShutdown>,
    configured: AtomicBool,
    listeners: Mutex<usize>,
    listener_changed: Notify,
    connections: Mutex<BTreeMap<usize, Weak<Connection>>>,
}

pub(super) struct ListenerWork {
    group: Arc<Group>,
    _work: NativeWork,
}

impl Drop for ListenerWork {
    fn drop(&mut self) {
        *self.group.listeners.lock() -= 1;
        self.group.listener_changed.notify_waiters();
    }
}

impl Group {
    pub(super) fn listener(self: &Arc<Self>) -> Option<ListenerWork> {
        let work = self.work.begin()?;
        self.configured.store(true, Ordering::SeqCst);
        *self.listeners.lock() += 1;
        Some(ListenerWork {
            group: self.clone(),
            _work: work,
        })
    }

    pub(super) fn connection(self: &Arc<Self>) -> Option<Arc<Connection>> {
        let work = self.work.begin()?;
        let connection = Arc::new(Connection {
            group: self.clone(),
            work: Mutex::new(Some(work)),
            accepted_second: chrono::Utc::now().timestamp(),
            first_header: AtomicBool::new(false),
            hijacked: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            changed: Notify::new(),
        });
        self.connections.lock().insert(
            Arc::as_ptr(&connection) as usize,
            Arc::downgrade(&connection),
        );
        Some(connection)
    }

    pub(super) async fn closing(&self) {
        self.work.closing().await;
    }

    async fn shutdown(&self, deadline: Instant, label: &str) {
        self.work.mark_closing();
        self.work.wake();
        // Go closes listeners and waits their accept loops before consulting
        // the shutdown context. Stop admission even if debug spent the budget.
        loop {
            let changed = self.listener_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if *self.listeners.lock() == 0 {
                break;
            }
            changed.await;
        }
        let mut interval = Duration::from_millis(1);
        loop {
            // StateNew remains new until complete headers, even after partial
            // reads. Go compares integer Unix seconds with a strict >5 age.
            let now = chrono::Utc::now().timestamp();
            // Drop upgraded references outside the registry lock: the final
            // Connection drop removes its own entry from that registry.
            let connections: Vec<_> = self.connections.lock().values().cloned().collect();
            for weak in connections {
                let Some(connection) = weak.upgrade() else {
                    continue;
                };
                if !connection.first_header.load(Ordering::SeqCst)
                    && !connection.hijacked.load(Ordering::SeqCst)
                    && connection.accepted_second < now.saturating_sub(5)
                {
                    connection.cancelled.store(true, Ordering::SeqCst);
                    connection.changed.notify_waiters();
                }
            }
            let jitter_limit = (interval.as_nanos() / 10) as u64;
            let limit = u64::MAX - u64::MAX % jitter_limit;
            let jitter = loop {
                let value = rand_core::OsRng.next_u64();
                if value < limit {
                    break value % jitter_limit;
                }
            };
            let pause = interval + Duration::from_nanos(jitter);
            interval = (interval * 2).min(Duration::from_millis(500));
            tokio::select! {
                biased;
                () = self.work.drained() => return,
                () = tokio::time::sleep_until(deadline) => {
                    // Timeout does not cancel active handlers or fresh New
                    // sockets. Stop polling New ages when this context ends.
                    if label == "debug" {
                        tracing::error!(error = "context deadline exceeded", "failed to shutdown prometheus http");
                    } else {
                        tracing::error!(error = "context deadline exceeded", "failed to shutdown http");
                    }
                    return;
                }
                () = tokio::time::sleep(pause) => {}
            }
        }
    }
}

pub(super) struct Connection {
    group: Arc<Group>,
    work: Mutex<Option<NativeWork>>,
    accepted_second: i64,
    first_header: AtomicBool,
    hijacked: AtomicBool,
    cancelled: AtomicBool,
    changed: Notify,
}

impl Connection {
    fn release_http_work(&self) {
        self.work.lock().take();
        self.group
            .connections
            .lock()
            .remove(&(std::ptr::from_ref::<Self>(self) as usize));
    }

    pub(super) fn hijack(&self) {
        self.hijacked.store(true, Ordering::SeqCst);
        self.release_http_work();
        self.changed.notify_waiters();
    }

    pub(super) fn admit(&self) -> bool {
        self.activate();
        !self.group.work.is_closing()
    }

    pub(super) fn activate(&self) {
        self.first_header.store(true, Ordering::SeqCst);
        self.changed.notify_waiters();
    }

    pub(super) async fn cancelled(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.cancelled.load(Ordering::SeqCst) && !self.hijacked.load(Ordering::SeqCst) {
                return;
            }
            changed.await;
        }
    }

    async fn headers_seen(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.first_header.load(Ordering::SeqCst) {
                return;
            }
            changed.await;
        }
    }
}

// Observe Hyper's preface reads without consuming bytes ahead of its parser.
// The outer driver owns the deadline independently of reads and writes. Native
// h2 reads the preface concurrently with its SETTINGS flush; other builders can
// still flush before reading, and later control writes can gate frame input.
struct H2PrefaceIo<I> {
    io: I,
    remaining: usize,
    prefaced: Option<oneshot::Sender<Instant>>,
    first_frame: Option<oneshot::Sender<()>>,
    frame_header: [u8; 9],
    frame_header_filled: usize,
    frame_payload_remaining: usize,
}

impl<I> H2PrefaceIo<I> {
    fn observe(&mut self, mut bytes: &[u8]) {
        if self.remaining > 0 {
            let consumed = self.remaining.min(bytes.len());
            self.remaining -= consumed;
            bytes = &bytes[consumed..];
            if self.remaining == 0
                && let Some(prefaced) = self.prefaced.take()
            {
                let _ = prefaced.send(Instant::now());
            }
        }
        if self.remaining > 0 || self.first_frame.is_none() {
            return;
        }
        if self.frame_header_filled < self.frame_header.len() {
            let consumed = (self.frame_header.len() - self.frame_header_filled).min(bytes.len());
            self.frame_header[self.frame_header_filled..self.frame_header_filled + consumed]
                .copy_from_slice(&bytes[..consumed]);
            self.frame_header_filled += consumed;
            bytes = &bytes[consumed..];
            if self.frame_header_filled < self.frame_header.len() {
                return;
            }
            // Observe wire completeness only. The full-feature vendored h2
            // decoder enforces first-frame SETTINGS before dispatch; ordinary
            // frame flags, stream ID, size and contents remain its responsibility.
            self.frame_payload_remaining = usize::from(self.frame_header[0]) << 16
                | usize::from(self.frame_header[1]) << 8
                | usize::from(self.frame_header[2]);
        }
        self.frame_payload_remaining = self.frame_payload_remaining.saturating_sub(bytes.len());
        // Only SETTINGS can finish this phase. A first HEADERS frame without
        // END_HEADERS remains inside the decoder awaiting CONTINUATION; keep
        // the deadline live instead of accepting that raw frame's completion.
        if self.frame_payload_remaining == 0
            && self.frame_header[3] == 0x4
            && let Some(first_frame) = self.first_frame.take()
        {
            let _ = first_frame.send(());
        }
    }
}

impl<I: AsyncRead + Unpin> AsyncRead for H2PrefaceIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.io).poll_read(cx, buf);
        this.observe(&buf.filled()[before..]);
        result
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for H2PrefaceIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

pub(super) async fn serve_h2_connection<I>(
    io: I,
    router: Router,
    peer: SocketAddr,
    connection: Option<Arc<Connection>>,
) -> io::Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if let Some(connection) = &connection {
        // net/http marks an ALPN-selected HTTP/2 connection active before
        // handing it to its HTTP/2 server, including while its preface stalls.
        connection.activate();
    }
    let service =
        hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
            let router = router.clone();
            async move {
                let (parts, body) = request.into_parts();
                let mut request = http::Request::from_parts(parts, Body::new(body));
                request
                    .extensions_mut()
                    .insert(axum::extract::ConnectInfo(peer));
                request.extensions_mut().insert(super::raw_tls::TlsRequest);
                router
                    .oneshot(request)
                    .await
                    .map_err(|error| io::Error::other(format!("router service: {error}")))
            }
        });
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder.timer(TokioTimer::new());
    #[cfg(feature = "full")]
    if connection.is_some() {
        builder
            .go_native_server(Some(Duration::from_secs(30)))
            .go_stream_timeouts(Some(Duration::from_secs(30)), Some(Duration::from_secs(30)));
    }
    // Go's bundled server defaults (configFromServer/setConfigDefaults),
    // including HTTP/1's 1 MiB header budget plus ten HPACK field overheads.
    // Hyper's defaults are smaller for frame/header sizes and stream count.
    builder
        .max_concurrent_streams(250)
        .max_frame_size(1024 * 1024)
        .max_header_list_size(1024 * 1024 + 10 * 32)
        .initial_stream_window_size(1024 * 1024)
        .initial_connection_window_size(1024 * 1024);
    let (prefaced, preface_ready) = oneshot::channel();
    let (first_frame, first_frame_ready) = oneshot::channel();
    let io = H2PrefaceIo {
        io,
        remaining: 24,
        prefaced: Some(prefaced),
        first_frame: Some(first_frame),
        frame_header: [0; 9],
        frame_header_filled: 0,
        frame_payload_remaining: 0,
    };
    let http = builder.serve_connection(TokioIo::new(io), service);
    tokio::pin!(http);
    let closing = async {
        match &connection {
            Some(connection) => connection.group.closing().await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(closing);
    tokio::pin!(preface_ready);
    tokio::pin!(first_frame_ready);
    let preface_deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(preface_deadline);
    let first_frame_deadline = tokio::time::sleep(Duration::ZERO);
    tokio::pin!(first_frame_deadline);
    let mut preface_observer_done = false;
    let mut preface_done = false;
    let mut first_frame_observer_done = false;
    let mut first_frame_done = false;
    let mut stopped = false;
    loop {
        tokio::select! {
            biased;
            result = &mut preface_ready, if !preface_observer_done => {
                preface_observer_done = true;
                if let Ok(observed_at) = result {
                    preface_done = true;
                    first_frame_deadline.as_mut().reset(observed_at + Duration::from_secs(2));
                }
            }
            result = &mut first_frame_ready, if !first_frame_observer_done => {
                first_frame_observer_done = true;
                first_frame_done = result.is_ok();
            }
            () = &mut preface_deadline, if !preface_done => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "HTTP/2 client preface timed out"));
            }
            () = &mut first_frame_deadline, if preface_done && !first_frame_done => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "HTTP/2 initial SETTINGS timed out"));
            }
            () = &mut closing, if !stopped => {
                stopped = true;
                // HTTP/2 uses GOAWAY and retains already accepted streams;
                // HTTP/1's late-header handler gate does not apply here.
                http.as_mut().graceful_shutdown();
            }
            result = &mut http => {
                if let Some(connection) = &connection {
                    connection.release_http_work();
                }
                return result.map_err(|error| io::Error::other(format!("hyper http2: {error}")));
            }
        }
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.group
            .connections
            .lock()
            .remove(&(std::ptr::from_ref::<Self>(self) as usize));
    }
}

// Hyper can generate parser-error responses without calling the service. Go
// checks shutdown after reading headers and before either that response or a
// handler. Only a nonempty write marks this path active; an empty flush may
// happen while Hyper is still waiting for the first request headers.
struct HttpIo<I> {
    io: I,
    connection: Arc<Connection>,
}

impl<I: AsyncRead + Unpin> AsyncRead for HttpIo<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for HttpIo<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !buf.is_empty()
            && !this.connection.first_header.load(Ordering::SeqCst)
            && !this.connection.admit()
        {
            return Poll::Ready(Err(io::Error::other("HTTP server is shutting down")));
        }
        Pin::new(&mut this.io).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if bufs.iter().any(|buf| !buf.is_empty())
            && !this.connection.first_header.load(Ordering::SeqCst)
            && !this.connection.admit()
        {
            return Poll::Ready(Err(io::Error::other("HTTP server is shutting down")));
        }
        Pin::new(&mut this.io).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

pub(super) async fn serve_listener(
    listener: TcpListener,
    router: Router,
    group: Arc<Group>,
    listener_work: ListenerWork,
) -> io::Result<()> {
    let result = loop {
        let (stream, peer) = tokio::select! {
            biased;
            () = group.closing() => break Ok(()),
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => break Err(error),
            },
        };
        let Some(connection) = group.connection() else {
            continue;
        };
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(error) =
                serve_connection(stream, router, peer, false, connection, None).await
            {
                tracing::debug!(%peer, %error, "native HTTP connection ended");
            }
        });
    };
    drop(listener);
    drop(listener_work);
    result
}

pub(super) async fn serve_connection<I>(
    io: I,
    router: Router,
    peer: SocketAddr,
    tls: bool,
    connection: Arc<Connection>,
    header_timeout: Option<Duration>,
) -> io::Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let requests = connection.clone();
    let service =
        hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
            let router = router.clone();
            let admitted = requests.admit();
            async move {
                if !admitted {
                    return Err(io::Error::other("HTTP server is shutting down"));
                }
                let (parts, body) = request.into_parts();
                let mut request = http::Request::from_parts(parts, Body::new(body));
                request
                    .extensions_mut()
                    .insert(axum::extract::ConnectInfo(peer));
                if tls {
                    request.extensions_mut().insert(super::raw_tls::TlsRequest);
                }
                router
                    .oneshot(request)
                    .await
                    .map_err(|error| io::Error::other(format!("router service: {error}")))
            }
        });
    // Native plain/debug and static TLS use HTTP/1.1 in Go. The original
    // embedding entrypoint retains Axum's existing protocol support.
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder.timer(TokioTimer::new());
    if let Some(timeout) = header_timeout {
        builder.header_read_timeout(timeout);
    }
    let http = builder
        .serve_connection(
            TokioIo::new(HttpIo {
                io,
                connection: connection.clone(),
            }),
            service,
        )
        .with_upgrades();
    tokio::pin!(http);
    let closing = connection.group.closing();
    tokio::pin!(closing);
    let headers = connection.headers_seen();
    tokio::pin!(headers);
    let mut stopped = false;
    let mut graceful = false;
    loop {
        tokio::select! {
            biased;
            () = connection.cancelled() => return Ok(()),
            () = &mut closing, if !stopped => {
                stopped = true;
                if connection.first_header.load(Ordering::SeqCst) {
                    http.as_mut().graceful_shutdown();
                    graceful = true;
                }
            }
            () = &mut headers, if stopped && !graceful => {
                http.as_mut().graceful_shutdown();
                graceful = true;
            }
            result = &mut http => {
                // Successful upgrades can retain HttpIo after the HTTP future
                // ends. Their independent protocol lifetime is not HTTP work.
                connection.release_http_work();
                return result.map_err(|error| io::Error::other(format!("hyper http1: {error}")));
            },
        }
    }
}
