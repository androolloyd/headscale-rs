// Copyright 2009, 2011, 2017, 2018 The Go Authors. All rights reserved.
// Native proxy selection and handshakes follow Go 1.26.9 net/http and its
// vendored x/net/http/httpproxy and internal/socks. See LICENSE-GO.

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use base64::prelude::{BASE64_STANDARD, Engine};
use http::{HeaderValue, Request, Uri, header::PROXY_AUTHORIZATION};
use hyper::rt;
use hyper_rustls::{HttpsConnector, MaybeHttpsStream};
use hyper_util::{
    client::legacy::connect::{Connected, Connection, HttpConnector},
    rt::TokioIo,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tower_service::Service;

use super::url::Url;

mod environment;
mod socks;
#[allow(dead_code)]
mod unicode;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type Stream = MaybeHttpsStream<TokioIo<TcpStream>>;

fn invalid(message: impl Into<String>) -> BoxError {
    io::Error::other(message.into()).into()
}

/// The underlying connector is HTTP-only; origin TLS remains in the outer
/// HttpsConnector, so a CONNECT tunnel never bypasses certificate verification.
#[derive(Clone)]
pub(crate) struct ProxyConnector {
    http: DialConnector,
    proxy_tls: HttpsConnector<DialConnector>,
}

impl ProxyConnector {
    pub(crate) fn new(http: HttpConnector, proxy_tls: HttpsConnector<HttpConnector>) -> Self {
        Self {
            http: DialConnector::new(http),
            proxy_tls: proxy_tls.go_map_http_connector(DialConnector::new),
        }
    }
}

/// Go DefaultTransport's net.Dialer budget covers DNS and TCP together, while
/// TLS has its own later deadline. The socket options apply to every first hop.
#[derive(Clone)]
struct DialConnector(HttpConnector);

impl DialConnector {
    fn new(mut http: HttpConnector) -> Self {
        http.set_keepalive(Some(Duration::from_secs(30)));
        http.set_keepalive_interval(Some(Duration::from_secs(15)));
        http.set_keepalive_retries(Some(9));
        http.set_nodelay(true);
        Self(http)
    }
}

impl Service<Uri> for DialConnector {
    type Response = TokioIo<TcpStream>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, BoxError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        self.0.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, destination: Uri) -> Self::Future {
        let connecting = self.0.call(destination);
        Box::pin(async move {
            tokio::time::timeout(Duration::from_secs(30), connecting)
                .await
                .map_err(|_| invalid("dial tcp: i/o timeout"))?
                .map_err(Into::into)
        })
    }
}

pub(crate) struct ProxyIo {
    inner: Stream,
    forward: bool,
    tunnel: bool,
}

impl Connection for ProxyIo {
    fn connected(&self) -> Connected {
        if self.tunnel {
            // Proxy TLS ALPN describes the proxy, not the tunneled origin.
            Connected::new()
        } else {
            self.inner.connected().proxy(self.forward)
        }
    }
}

impl rt::Read for ProxyIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl rt::Write for ProxyIo {
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
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
}

impl Service<Uri> for ProxyConnector {
    type Response = ProxyIo;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<ProxyIo, BoxError>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), BoxError>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, destination: Uri) -> Self::Future {
        let mut http = self.http.clone();
        let mut proxy_tls = self.proxy_tls.clone();
        Box::pin(async move {
            let origin =
                Url::parse(&destination.to_string()).map_err(|e| invalid(e.to_string()))?;
            let Some(proxy) = environment::select(&origin)? else {
                // HttpConnector accepts HTTPS destinations only with enforcement
                // disabled; outer HttpsConnector retains TLS responsibility.
                return Ok(ProxyIo {
                    inner: MaybeHttpsStream::Http(http.call(destination).await?),
                    forward: false,
                    tunnel: false,
                });
            };
            let (proxy_host, proxy_port) = environment::hostname_port(&proxy);
            let proxy_host = std::str::from_utf8(&proxy_host)
                .map_err(|_| invalid("proxy host is not valid UTF-8"))?;
            let scheme = proxy.scheme();
            if !matches!(scheme, "http" | "https" | "socks5" | "socks5h") {
                return Err(invalid(format!(
                    "proxyconnect tcp: unsupported proxy scheme {scheme}"
                )));
            }
            let proxy_uri: Uri = format!(
                "{}://{}/",
                if scheme == "https" { "https" } else { "http" },
                authority(proxy_host, &proxy_port)
            )
            .parse()
            .map_err(|e| invalid(format!("proxyconnect tcp: {e}")))?;
            let stream = if scheme == "https" {
                proxy_tls
                    .call(proxy_uri)
                    .await
                    .map_err(|e| invalid(format!("proxyconnect tcp: {e}")))?
            } else {
                MaybeHttpsStream::Http(
                    http.call(proxy_uri)
                        .await
                        .map_err(|e| invalid(format!("proxyconnect tcp: {e}")))?,
                )
            };
            if matches!(scheme, "socks5" | "socks5h") {
                let stream = socks::connect(stream, &origin, &proxy).await?;
                return Ok(ProxyIo {
                    inner: stream,
                    forward: false,
                    tunnel: true,
                });
            }
            if origin.scheme() == "http" {
                return Ok(ProxyIo {
                    inner: stream,
                    forward: true,
                    tunnel: false,
                });
            }
            let stream = tokio::time::timeout(
                Duration::from_secs(60),
                connect_tunnel(stream, &origin, &proxy),
            )
            .await
            .map_err(|_| invalid("context deadline exceeded"))??;
            Ok(ProxyIo {
                inner: stream,
                forward: false,
                tunnel: true,
            })
        })
    }
}

pub(super) fn authority(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn authorization(proxy: &Url) -> Option<String> {
    proxy.credentials().map(|(mut username, password)| {
        username.push(b':');
        username.extend(password);
        format!("Basic {}", BASE64_STANDARD.encode(username))
    })
}

/// Equality of Go connectMethodKey's four fields, encoded without delimiter
/// ambiguity. Proxy URL credentials can occur here; callers must keep this
/// identity opaque and must never render it in diagnostics or tracing.
pub(super) fn pool_identity(origin: &Url) -> Result<Vec<u8>, BoxError> {
    let proxy = environment::select(origin)?;
    let (host, port) = environment::hostname_port(origin);
    let mut address = Vec::new();
    if host.contains(&b':') {
        address.push(b'[');
        address.extend_from_slice(&host);
        address.push(b']');
    } else {
        address.extend_from_slice(&host);
    }
    address.push(b':');
    address.extend_from_slice(port.as_bytes());
    let mut proxy_url = Vec::new();
    if let Some(proxy) = proxy {
        if origin.scheme() == "http" && matches!(proxy.scheme(), "http" | "https") {
            // A forward proxy connection can serve other origin hosts. A
            // CONNECT or SOCKS tunnel remains tied to its target address.
            address.clear();
        }
        proxy_url = proxy.as_bytes();
    }
    let mut identity = Vec::new();
    for component in [proxy_url.as_slice(), origin.scheme().as_bytes(), &address] {
        identity.extend_from_slice(&(component.len() as u64).to_be_bytes());
        identity.extend_from_slice(component);
    }
    // This selected native client permits HTTP/2; Go's onlyH1 field is false.
    identity.push(0);
    Ok(identity)
}

/// Go mutates forward-proxy headers at each send; CONNECT auth is deliberately
/// absent from the tunneled origin request.
pub(super) fn apply_request_proxy_auth<B>(request: &mut Request<B>) -> Result<(), crate::Error> {
    let origin = Url::parse(&request.uri().to_string())?;
    let proxy = environment::select(&origin)
        .map_err(|error| super::super::native_error(error.to_string()))?;
    if origin.scheme() == "http" {
        if let Some(proxy) = proxy.filter(|proxy| matches!(proxy.scheme(), "http" | "https")) {
            if let Some(value) = authorization(&proxy) {
                request.headers_mut().insert(
                    PROXY_AUTHORIZATION,
                    HeaderValue::from_str(&value)
                        .map_err(|e| super::super::native_error(e.to_string()))?,
                );
            }
        }
    }
    Ok(())
}

async fn connect_tunnel(stream: Stream, origin: &Url, proxy: &Url) -> Result<Stream, BoxError> {
    let (host, port) = environment::hostname_port(origin);
    let host =
        std::str::from_utf8(&host).map_err(|_| invalid("CONNECT target is not valid UTF-8"))?;
    let target = authority(host, &port);
    let mut io = TokioIo::new(stream);
    let mut request = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: Go-http-client/1.1\r\n"
    );
    if let Some(auth) = authorization(proxy) {
        request.push_str("Proxy-Authorization: ");
        request.push_str(&auth);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    io.write_all(request.as_bytes()).await?;
    io.flush().await?;
    // Go ReadResponse uses a LimitedReader and a 4KiB bufio.Reader. Its buffered
    // suffix is discarded: a TLS origin must wait for our ClientHello.
    let mut reader = BufReader::with_capacity(4096, io.take(10 << 20));
    let status = read_line(&mut reader, None).await?;
    let Some(space) = status.iter().position(|b| *b == b' ') else {
        return Err(bad_string("malformed HTTP response", &status));
    };
    let protocol = &status[..space];
    let mut rest = &status[space + 1..];
    while rest.first() == Some(&b' ') {
        rest = &rest[1..];
    }
    let (code, reason) = match rest.iter().position(|b| *b == b' ') {
        Some(i) => (&rest[..i], &rest[i + 1..]),
        None => (rest, &b""[..]),
    };
    let status_code = std::str::from_utf8(code)
        .ok()
        .and_then(|code| code.parse::<i32>().ok());
    if code.len() != 3 || !status_code.is_some_and(|code| code >= 0) {
        return Err(bad_string("malformed HTTP status code", code));
    }
    if !valid_version(protocol) {
        return Err(bad_string("malformed HTTP version", protocol));
    }
    let headers = read_headers(&mut reader).await?;
    validate_transfer_headers(protocol, &headers)?;
    if status_code != Some(200) {
        if !rest.contains(&b' ') {
            return Err(invalid("unknown status code"));
        }
        return Err(invalid(String::from_utf8_lossy(reason).into_owned()));
    }
    Ok(reader.into_inner().into_inner().into_inner())
}

async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: Option<usize>,
) -> Result<Vec<u8>, BoxError> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            if line.is_empty() {
                return Err(invalid("unexpected EOF"));
            }
            // bufio.ReadLine returns a nonempty unterminated line without EOF;
            // the following line read observes EOF. Do not strip a bare CR.
            if limit.is_some_and(|limit| line.len() > limit) {
                return Err(invalid("message too large"));
            }
            return Ok(line);
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |at| at + 1);
        // The small first-header-line limit is checked on logical line bytes,
        // excluding the CRLF; a final CR may straddle an input buffer.
        if let Some(limit) = limit {
            let extra = usize::from(newline.is_some())
                + usize::from(newline.is_some_and(|at| {
                    if at == 0 {
                        line.last() == Some(&b'\r')
                    } else {
                        available[at - 1] == b'\r'
                    }
                }));
            if line.len() + count > limit.saturating_add(extra)
                && !(newline.is_none()
                    && line.len() + count == limit + 1
                    && available[count - 1] == b'\r')
            {
                return Err(invalid("message too large"));
            }
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline.is_some() {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
    }
}

fn bad_string(what: &str, value: &[u8]) -> BoxError {
    invalid(format!(
        "{what} {}",
        super::super::quote::quote_bytes(value)
    ))
}

fn quoted_values(values: &[&[u8]]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| super::super::quote::quote_bytes(value))
            .collect::<Vec<_>>()
            .join(" ")
    )
}

async fn read_headers<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>, BoxError> {
    // textproto checks the first physical line before continuation parsing.
    if matches!(reader.fill_buf().await?.first(), Some(b' ' | b'\t')) {
        let line = read_line(reader, Some(80)).await?;
        return Err(invalid(format!(
            "malformed MIME header initial line: {}",
            super::super::quote::quote_bytes(&line)
        )));
    }
    let mut headers = Vec::new();
    loop {
        let line = read_line(reader, None).await?;
        if line.is_empty() {
            return Ok(headers);
        }
        if !line.contains(&b':') {
            return Err(invalid(format!(
                "malformed MIME header: missing colon: {}",
                super::super::quote::quote_bytes(&line)
            )));
        }
        let mut unfolded = trim_header(&line).to_vec();
        loop {
            let mut skipped = false;
            loop {
                let available = reader.fill_buf().await?;
                let count = available
                    .iter()
                    .take_while(|byte| matches!(**byte, b' ' | b'\t'))
                    .count();
                if count == 0 {
                    break;
                }
                skipped = true;
                reader.consume(count);
            }
            if !skipped {
                break;
            }
            let continuation = read_line(reader, None).await?;
            unfolded.push(b' ');
            unfolded.extend_from_slice(trim_header(&continuation));
        }
        let colon = unfolded
            .iter()
            .position(|byte| *byte == b':')
            .expect("first physical line contained colon");
        let key = &unfolded[..colon];
        let key_valid =
            |byte: &u8| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte);
        if key.is_empty()
            || !key.iter().all(|byte| *byte == b' ' || key_valid(byte))
            || !valid_value(&unfolded[colon + 1..])
        {
            return Err(invalid(format!(
                "malformed MIME header line: {}",
                super::super::quote::quote_bytes(&unfolded)
            )));
        }
        // Go accepts a space-containing key but leaves it noncanonical. Keep
        // it distinct from recognized Transfer-Encoding/Content-Length names.
        let key = if key.contains(&b' ') {
            key.to_vec()
        } else {
            key.to_ascii_lowercase()
        };
        let value = trim_header_start(&unfolded[colon + 1..]).to_vec();
        headers.push((key, value));
    }
}

fn valid_version(protocol: &[u8]) -> bool {
    protocol.len() == 8
        && protocol.starts_with(b"HTTP/")
        && protocol[5].is_ascii_digit()
        && protocol[6] == b'.'
        && protocol[7].is_ascii_digit()
}

fn valid_value(value: &[u8]) -> bool {
    value.iter().all(|b| *b == b'\t' || *b >= 32 && *b != 127)
}

fn trim_header(mut value: &[u8]) -> &[u8] {
    value = trim_header_start(value);
    while matches!(value.last(), Some(b' ' | b'\t')) {
        value = &value[..value.len() - 1];
    }
    value
}

fn trim_header_start(mut value: &[u8]) -> &[u8] {
    while matches!(value.first(), Some(b' ' | b'\t')) {
        value = &value[1..];
    }
    value
}

fn validate_transfer_headers(
    protocol: &[u8],
    headers: &[(Vec<u8>, Vec<u8>)],
) -> Result<(), BoxError> {
    // ReadResponse performs transfer validation before the CONNECT status test,
    // even though Transport never reads the declared response body.
    let transfer: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name == b"transfer-encoding")
        .map(|(_, value)| value.as_slice())
        .collect();
    let modern =
        protocol[5] > b'1' || protocol[5] == b'1' && protocol[7] >= b'1' || protocol == b"HTTP/0.0";
    let chunked = modern && !transfer.is_empty();
    if chunked {
        if transfer.len() != 1 {
            return Err(invalid(format!(
                "too many transfer encodings: {}",
                quoted_values(&transfer)
            )));
        }
        if !transfer[0].eq_ignore_ascii_case(b"chunked") {
            return Err(invalid(format!(
                "unsupported transfer encoding: {}",
                super::super::quote::quote_bytes(transfer[0])
            )));
        }
    }
    let lengths: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name == b"content-length")
        .map(|(_, value)| value.as_slice())
        .collect();
    if let Some(first) = lengths.first() {
        let first = trim_header(first);
        if lengths.iter().any(|length| trim_header(length) != first) {
            return Err(invalid(format!(
                "http: message cannot contain multiple Content-Length headers; got {}",
                quoted_values(&lengths)
            )));
        }
        if first.is_empty() {
            let lax = matches!(
                super::super::godebug::lookup(b"httplaxcontentlength"),
                super::super::godebug::Resolution::Plain(value) if value == b"1"
            );
            // Stack-conditioned values retain the selected strict default;
            // the helper does not invent Go call-stack IDs for Rust callers.
            if !lax {
                return Err(bad_string("invalid empty Content-Length", first));
            }
        } else if !first.iter().all(u8::is_ascii_digit)
            || !std::str::from_utf8(first)
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|value| value <= i64::MAX as u64)
        {
            return Err(bad_string("bad Content-Length", first));
        }
    }
    if chunked {
        for (_, value) in headers.iter().filter(|(name, _)| name == b"trailer") {
            for name in value.split(|byte| *byte == b',').map(trim_header) {
                for reserved in [
                    b"Transfer-Encoding".as_slice(),
                    b"Trailer",
                    b"Content-Length",
                ] {
                    if name.eq_ignore_ascii_case(reserved) {
                        return Err(bad_string("bad trailer key", reserved));
                    }
                }
            }
        }
    }
    Ok(())
}
