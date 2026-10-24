// Copyright 2009 The Go Authors. All rights reserved.
// TCP family racing/deadline splitting adapts Go 1.26.9 net/dial.go.
// The BSD license and notice are retained in headscale-cli/LICENSE-GO-STDLIB.

//! Owned CLI connection attempts through TLS and the HTTP/2 server preface.

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::{oneshot, watch};
use tokio::time::Instant;
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
};
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

use super::{NoCertificateVerification, upstream_dns::DnsAuthority};

trait TransportIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TransportIo for T {}
type BoxIo = Box<dyn TransportIo>;

#[derive(Clone)]
pub(super) enum Destination {
    Address(SocketAddr),
    Host(String, u16),
    Dns {
        host: String,
        port: u16,
        resolver: DnsAuthority,
    },
    Unix(PathBuf),
}

impl Destination {
    async fn dial(self, deadline: Option<Instant>) -> io::Result<BoxIo> {
        match self {
            Self::Address(address) => {
                let stream = TcpStream::connect(address).await?;
                stream.set_nodelay(true)?;
                Ok(Box::new(stream))
            }
            Self::Host(host, port) => {
                let addresses = tokio::net::lookup_host((host.as_str(), port))
                    .await?
                    .collect();
                let stream = dial_host(addresses, deadline).await?;
                stream.set_nodelay(true)?;
                Ok(Box::new(stream))
            }
            Self::Dns { .. } => Err(io::Error::other(
                "DNS destinations require a resolved endpoint",
            )),
            Self::Unix(path) => Ok(Box::new(UnixStream::connect(path).await?)),
        }
    }
}

async fn dial_host(addresses: Vec<SocketAddr>, deadline: Option<Instant>) -> io::Result<TcpStream> {
    let primary_v6 = addresses.first().is_some_and(native_ipv6);
    let (primary, fallback): (Vec<_>, Vec<_>) = addresses
        .into_iter()
        .partition(|address| native_ipv6(address) == primary_v6);
    if fallback.is_empty() {
        return dial_serial(primary, deadline).await;
    }
    let primary = dial_serial(primary, deadline);
    tokio::pin!(primary);
    let primary_error = tokio::select! {
        result = &mut primary => match result { Ok(stream) => return Ok(stream), Err(error) => Some(error) },
        () = tokio::time::sleep(Duration::from_millis(300)) => None,
    };
    if let Some(error) = primary_error {
        // Exhausted primaries start the fallback without waiting for 300ms.
        return dial_serial(fallback, deadline).await.or(Err(error));
    }
    let fallback = dial_serial(fallback, deadline);
    tokio::pin!(fallback);
    tokio::select! {
        result = &mut primary => match result {
            Ok(stream) => Ok(stream),
            Err(error) => fallback.await.or(Err(error)),
        },
        result = &mut fallback => match result {
            Ok(stream) => Ok(stream),
            Err(_) => primary.await,
        },
    }
}

async fn dial_serial(
    addresses: Vec<SocketAddr>,
    deadline: Option<Instant>,
) -> io::Result<TcpStream> {
    let count = addresses.len();
    let mut first_error = None;
    for (index, address) in addresses.into_iter().enumerate() {
        let result = if let Some(deadline) = deadline {
            let now = Instant::now();
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                return Err(first_error.unwrap_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "TCP dial timed out")
                }));
            }
            let slice = Duration::from_nanos(
                (remaining.as_nanos() / (count - index) as u128).min(u128::from(u64::MAX)) as u64,
            );
            let slice = remaining.min(slice.max(Duration::from_secs(2)));
            tokio::time::timeout_at(now + slice, TcpStream::connect(address))
                .await
                .unwrap_or_else(|_| {
                    Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "TCP dial timed out",
                    ))
                })
        } else {
            TcpStream::connect(address).await
        };
        match result {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    Err(first_error
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "missing TCP address")))
}

pub(super) fn tls_config(insecure: bool) -> io::Result<Arc<ClientConfig>> {
    static SECURE: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    static INSECURE: OnceLock<Result<Arc<ClientConfig>, String>> = OnceLock::new();
    let cached = if insecure { &INSECURE } else { &SECURE };
    cached
        .get_or_init(|| {
            let builder = ClientConfig::builder_with_provider(Arc::new(
                tokio_rustls::rustls::crypto::aws_lc_rs::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|error| error.to_string())?;
            let mut config = if insecure {
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                    .with_no_client_auth()
            } else {
                let mut roots = RootCertStore::empty();
                roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
                if roots.is_empty() {
                    return Err("no native TLS trust roots found".into());
                }
                builder.with_root_certificates(roots).with_no_client_auth()
            };
            config.alpn_protocols.push(b"h2".to_vec());
            Ok(Arc::new(config))
        })
        .clone()
        .map_err(io::Error::other)
}

#[derive(Clone)]
pub(super) struct Recipe {
    origin: Uri,
    destination: Destination,
    tls: Option<Arc<ClientConfig>>,
    timeout: Duration,
}

impl Recipe {
    pub(super) fn dns(&self) -> Option<(String, u16, DnsAuthority)> {
        match &self.destination {
            Destination::Dns {
                host,
                port,
                resolver,
            } if host.parse::<std::net::IpAddr>().is_err() => {
                Some((host.clone(), *port, resolver.clone()))
            }
            _ => None,
        }
    }

    pub(super) fn endpoint(&self, address: SocketAddr) -> Self {
        let mut recipe = self.clone();
        recipe.destination = Destination::Address(address);
        recipe
    }

    pub(super) async fn dial(
        &self,
        budget: Duration,
        scope: &Scope,
    ) -> io::Result<ActiveTransport> {
        tokio::time::timeout(
            budget,
            connect_owned(
                self.origin.clone(),
                self.destination.clone(),
                self.tls.clone(),
                self.timeout,
                budget,
                scope,
            ),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "gRPC connection attempt timed out"))?
    }
}

pub(super) struct ActiveTransport {
    channel: Mutex<Channel>,
    pub(super) lease: Arc<TransportLease>,
    pub(super) closed: watch::Receiver<Option<String>>,
}

impl ActiveTransport {
    pub(super) fn alive(&self) -> bool {
        !self.lease.state.cancelled.load(Ordering::Acquire) && self.closed.borrow().is_none()
    }
    pub(super) fn retire(&self, error: String) {
        self.lease.state.finish(error);
    }
    pub(super) fn channel(&self) -> Channel {
        self.channel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

pub(super) struct TransportLease {
    state: Arc<AbortState>,
}

#[derive(Debug)]
pub(super) struct UnprocessedTransport;
impl std::fmt::Display for UnprocessedTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("gRPC transport is no longer accepting new streams")
    }
}
impl std::error::Error for UnprocessedTransport {}
impl Drop for TransportLease {
    fn drop(&mut self) {
        self.state.abort();
    }
}

#[derive(Default)]
pub(super) struct Scope {
    cancelled: AtomicBool,
    transports: Mutex<Vec<std::sync::Weak<AbortState>>>,
}

impl Scope {
    fn register(&self, state: &Arc<AbortState>) {
        let mut transports = self
            .transports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        transports.retain(|state| state.strong_count() != 0);
        if self.cancelled.load(Ordering::Acquire) {
            state.abort();
        }
        transports.push(Arc::downgrade(state));
    }
    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        let transports = self
            .transports
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for state in transports.iter().filter_map(std::sync::Weak::upgrade) {
            state.abort();
        }
    }
}

pub(super) async fn connect(
    origin: Uri,
    destination: Destination,
    tls: Option<Arc<ClientConfig>>,
    timeout: Duration,
    budget: Duration,
) -> io::Result<super::upstream_connection::Connection> {
    let deadline = Instant::now() + budget;
    let destination = match destination {
        Destination::Dns {
            host,
            port,
            resolver,
        } => match host.parse::<std::net::IpAddr>() {
            Ok(ip) => Destination::Address(SocketAddr::new(ip, port)),
            Err(_) => Destination::Dns {
                host,
                port,
                resolver,
            },
        },
        destination => destination,
    };
    let recipe = Recipe {
        origin,
        destination,
        tls,
        timeout,
    };
    let scope = Arc::new(Scope::default());
    let connection = if recipe.dns().is_some() {
        super::upstream_connection::Connection::managed_dns(recipe, scope)
    } else {
        let initial = recipe.dial(budget, &scope).await?;
        super::upstream_connection::Connection::managed(recipe, scope, initial)
    };
    connection
        .wait_initial(deadline)
        .await
        .map_err(io::Error::other)?;
    Ok(connection)
}

async fn connect_owned(
    origin: Uri,
    destination: Destination,
    tls: Option<Arc<ClientConfig>>,
    timeout: Duration,
    budget: Duration,
    scope: &Scope,
) -> io::Result<ActiveTransport> {
    let host = origin.host().unwrap_or("localhost");
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    let server_name = if tls.is_some() {
        Some(ServerName::try_from(host.to_string()).map_err(io::Error::other)?)
    } else {
        None
    };
    let state = Arc::new(AbortState::default());
    let connect_deadline = Instant::now() + budget;
    scope.register(&state);
    let mut guard = AbortGuard {
        state: state.clone(),
        armed: true,
    };
    let (send, received) = oneshot::channel();
    let send = Arc::new(Mutex::new(Some(send)));
    // TLS is performed by the connector, so the transport URI remains http.
    // The original authority/scheme is retained on actual gRPC requests.
    let endpoint = Endpoint::from(Uri::from_static("http://[::]:50051"))
        .origin(origin)
        .timeout(timeout);
    let channel = endpoint
        .connect_with_connector(service_fn(move |_: Uri| {
            let destination = destination.clone();
            let tls = tls.clone();
            let server_name = server_name.clone();
            let state = state.clone();
            let send = send.clone();
            async move {
                if state.cancelled.load(Ordering::Acquire) {
                    return Err(aborted());
                }
                if state.started.swap(true, Ordering::AcqRel) {
                    // One HTTP/2 transport per supervised Channel. Its owner
                    // creates the replacement; Tonic cannot redial this one.
                    state.finish("gRPC transport is no longer accepting new streams".into());
                    return Err(io::Error::new(
                        io::ErrorKind::NotConnected,
                        UnprocessedTransport,
                    ));
                }
                let io = dial_tls(destination, tls, server_name, Some(connect_deadline)).await?;
                let send = send
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
                Ok::<_, io::Error>(TokioIo::new(PrefaceIo::new(io, state, send)))
            }
        }))
        .await
        .map_err(io::Error::other)?;
    match received.await {
        Ok(Ok(())) => {
            let state = guard.state.clone();
            guard.armed = false;
            let closed = state.closed.subscribe();
            Ok(ActiveTransport {
                channel: Mutex::new(channel),
                lease: Arc::new(TransportLease { state }),
                closed,
            })
        }
        Ok(Err(error)) => Err(io::Error::other(error)),
        Err(_) => Err(io::Error::other(
            "gRPC connection closed before server SETTINGS",
        )),
    }
}

async fn dial_tls(
    destination: Destination,
    tls: Option<Arc<ClientConfig>>,
    server_name: Option<ServerName<'static>>,
    deadline: Option<Instant>,
) -> io::Result<BoxIo> {
    let raw = destination.dial(deadline).await?;
    if let (Some(config), Some(server_name)) = (tls, server_name) {
        let stream = TlsConnector::from(config).connect(server_name, raw).await?;
        if stream.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(io::Error::other(
                "gRPC TLS peer did not negotiate h2 via ALPN",
            ));
        }
        Ok(Box::new(stream))
    } else {
        Ok(raw)
    }
}

fn native_ipv6(address: &SocketAddr) -> bool {
    match address {
        SocketAddr::V4(_) => false,
        SocketAddr::V6(address) => address.ip().to_ipv4_mapped().is_none(),
    }
}

pub(super) fn interleave(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let first_v6 = addresses.first().is_some_and(native_ipv6);
    let (mut v6, mut v4): (VecDeque<_>, VecDeque<_>) = addresses.into_iter().partition(native_ipv6);
    let mut out = Vec::with_capacity(v6.len() + v4.len());
    let mut v6_turn = first_v6;
    while !v6.is_empty() || !v4.is_empty() {
        let next = if v6_turn {
            v6.pop_front().or_else(|| v4.pop_front())
        } else {
            v4.pop_front().or_else(|| v6.pop_front())
        };
        if let Some(address) = next {
            out.push(address);
        }
        v6_turn = !v6_turn;
    }
    out
}

struct AbortState {
    cancelled: AtomicBool,
    started: AtomicBool,
    readers: Mutex<[Option<Waker>; 2]>,
    closed: watch::Sender<Option<String>>,
}

impl Default for AbortState {
    fn default() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            started: AtomicBool::new(false),
            readers: Mutex::new([None, None]),
            closed: watch::channel(None).0,
        }
    }
}

impl AbortState {
    fn finish(&self, message: String) {
        self.closed.send_if_modified(|closed| {
            if closed.is_some() {
                false
            } else {
                *closed = Some(message);
                true
            }
        });
    }
    fn abort(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.finish("gRPC connection closed".into());
        let readers = std::mem::take(
            &mut *self
                .readers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for waker in readers.into_iter().flatten() {
            waker.wake();
        }
    }
    fn register(&self, index: usize, waker: &Waker) -> io::Result<()> {
        let mut readers = self
            .readers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.cancelled.load(Ordering::Acquire) {
            return Err(aborted());
        }
        if readers[index]
            .as_ref()
            .is_none_or(|old| !old.will_wake(waker))
        {
            readers[index] = Some(waker.clone());
        }
        Ok(())
    }
}

struct AbortGuard {
    state: Arc<AbortState>,
    armed: bool,
}
impl Drop for AbortGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.state.abort();
    }
}

type PrefaceSignal = oneshot::Sender<Result<(), String>>;

#[derive(Default)]
struct Frames {
    header: [u8; 9],
    header_len: usize,
    remaining: usize,
    goaway: bool,
}

impl Frames {
    fn observe(&mut self, mut bytes: &[u8], state: &AbortState) {
        while !bytes.is_empty() {
            if self.header_len < 9 {
                let length = bytes.len().min(9 - self.header_len);
                self.header[self.header_len..self.header_len + length]
                    .copy_from_slice(&bytes[..length]);
                self.header_len += length;
                bytes = &bytes[length..];
                if self.header_len < 9 {
                    return;
                }
                self.remaining = frame_len(&self.header);
                let stream = u32::from_be_bytes([
                    self.header[5],
                    self.header[6],
                    self.header[7],
                    self.header[8],
                ]) & 0x7fff_ffff;
                self.goaway = self.header[3] == 7 && stream == 0 && self.remaining >= 8;
            }
            let length = bytes.len().min(self.remaining);
            self.remaining -= length;
            bytes = &bytes[length..];
            if self.remaining == 0 {
                if self.goaway {
                    state.finish("HTTP/2 GOAWAY".into());
                }
                self.header_len = 0;
                self.goaway = false;
            }
        }
    }
}

struct PrefaceIo {
    inner: BoxIo,
    abort: Arc<AbortState>,
    signal: Option<PrefaceSignal>,
    ready: bool,
    header: [u8; 9],
    header_len: usize,
    remaining: usize,
    setting: [u8; 6],
    setting_len: usize,
    writer: Option<Waker>,
    client_preface_left: usize,
    client_header: [u8; 9],
    client_header_len: usize,
    client_payload_left: usize,
    frames: Frames,
}

impl PrefaceIo {
    fn new(inner: BoxIo, abort: Arc<AbortState>, signal: Option<PrefaceSignal>) -> Self {
        Self {
            inner,
            abort,
            signal,
            ready: false,
            header: [0; 9],
            header_len: 0,
            remaining: 0,
            setting: [0; 6],
            setting_len: 0,
            writer: None,
            client_preface_left: 24,
            client_header: [0; 9],
            client_header_len: 0,
            client_payload_left: 0,
            frames: Frames::default(),
        }
    }

    fn observe(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        if self.ready {
            self.frames.observe(bytes, &self.abort);
            return Ok(());
        }
        if self.header_len < 9 {
            let len = bytes.len().min(9 - self.header_len);
            self.header[self.header_len..self.header_len + len].copy_from_slice(&bytes[..len]);
            self.header_len += len;
            bytes = &bytes[len..];
            if self.header_len < 9 {
                return Ok(());
            }
            self.remaining = frame_len(&self.header);
            let stream = u32::from_be_bytes(
                self.header[5..9]
                    .try_into()
                    .map_err(|_| invalid_preface())?,
            ) & 0x7fff_ffff;
            if self.header[3] != 4
                || stream != 0
                || self.remaining > 16_384
                || !self.remaining.is_multiple_of(6)
                || (self.header[4] & 1 != 0 && self.remaining != 0)
            {
                return Err(invalid_preface());
            }
        }
        let consumed = bytes.len().min(self.remaining);
        for byte in bytes[..consumed].iter().copied() {
            self.setting[self.setting_len] = byte;
            self.setting_len += 1;
            self.remaining -= 1;
            if self.setting_len == 6 {
                let id = u16::from_be_bytes([self.setting[0], self.setting[1]]);
                let value = u32::from_be_bytes(
                    self.setting[2..6]
                        .try_into()
                        .map_err(|_| invalid_preface())?,
                );
                if matches!(id, 2 | 8) && value > 1
                    || id == 4 && value > 0x7fff_ffff
                    || id == 5 && !(16_384..=16_777_215).contains(&value)
                {
                    return Err(invalid_preface());
                }
                self.setting_len = 0;
            }
        }
        if self.remaining == 0 {
            self.ready = true;
            if let Some(signal) = self.signal.take() {
                let _ = signal.send(Ok(()));
            }
            if let Some(writer) = self.writer.take() {
                writer.wake();
            }
            self.frames.observe(&bytes[consumed..], &self.abort);
        }
        Ok(())
    }

    fn fail(&mut self, message: String) {
        self.abort.finish(message.clone());
        if let Some(signal) = self.signal.take() {
            let _ = signal.send(Err(message));
        }
    }

    fn write_limit(&self, len: usize) -> usize {
        if self.ready {
            len
        } else if self.client_preface_left > 0 {
            len.min(self.client_preface_left)
        } else if self.client_header_len < 9 {
            len.min(9 - self.client_header_len)
        } else {
            len.min(self.client_payload_left)
        }
    }

    fn wrote(&mut self, bytes: &[u8]) {
        if self.ready {
            return;
        }
        if self.client_preface_left > 0 {
            self.client_preface_left -= bytes.len();
        } else if self.client_header_len < 9 {
            let start = self.client_header_len;
            self.client_header[start..start + bytes.len()].copy_from_slice(bytes);
            self.client_header_len += bytes.len();
            if self.client_header_len == 9 {
                self.client_payload_left = frame_len(&self.client_header);
            }
        } else {
            self.client_payload_left -= bytes.len();
        }
    }
}

impl AsyncRead for PrefaceIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Err(error) = self.abort.register(0, cx.waker()) {
            return Poll::Ready(Err(error));
        }
        let before = buffer.filled().len();
        let capacity = buffer.remaining();
        match Pin::new(&mut self.inner).poll_read(cx, buffer) {
            Poll::Ready(Ok(())) => {
                let bytes = &buffer.filled()[before..];
                if bytes.is_empty() && capacity != 0 {
                    let message = if self.ready {
                        "gRPC connection closed"
                    } else {
                        "gRPC connection closed before server SETTINGS"
                    };
                    self.fail(message.into());
                }
                if let Err(error) = self.observe(bytes) {
                    self.fail(error.to_string());
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.fail(error.to_string());
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for PrefaceIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(error) = self.abort.register(1, cx.waker()) {
            return Poll::Ready(Err(error));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let limit = self.write_limit(bytes.len());
        if limit == 0 {
            // A TLS write may have accepted plaintext while encrypted bytes
            // still await socket capacity. Flush the permitted client preface
            // before waiting for the server, so the write gate cannot stall it.
            if let Poll::Ready(Err(error)) = Pin::new(&mut self.inner).poll_flush(cx) {
                self.fail(error.to_string());
                return Poll::Ready(Err(error));
            }
            self.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        match Pin::new(&mut self.inner).poll_write(cx, &bytes[..limit]) {
            Poll::Ready(Ok(written)) => {
                self.wrote(&bytes[..written]);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(error)) => {
                self.fail(error.to_string());
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(error) = self.abort.register(1, cx.waker()) {
            return Poll::Ready(Err(error));
        }
        match Pin::new(&mut self.inner).poll_flush(cx) {
            Poll::Ready(Err(error)) => {
                self.fail(error.to_string());
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.ready {
            self.abort.finish("gRPC connection shut down".into());
        } else {
            self.fail("gRPC connection shut down before server SETTINGS".into());
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for PrefaceIo {
    fn drop(&mut self) {
        self.fail(
            if self.ready {
                "gRPC connection closed"
            } else {
                "gRPC connection dropped before server SETTINGS"
            }
            .into(),
        );
    }
}

fn frame_len(header: &[u8; 9]) -> usize {
    (usize::from(header[0]) << 16) | (usize::from(header[1]) << 8) | usize::from(header[2])
}
fn invalid_preface() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid initial HTTP/2 SETTINGS frame",
    )
}
fn aborted() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "gRPC connection attempt cancelled",
    )
}
