use std::future::Future;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::BufMut;

pub use buffered::{BufferedSocket, WriteBuffer};

use crate::io::ReadBuf;

mod buffered;

pub trait Socket: Send + Sync + Unpin + 'static {
    /// The certificate from the completed TLS handshake, when available.
    /// Plain transports and backends without certificate access return None.
    fn tls_peer_certificate(&self) -> Option<&[u8]> {
        None
    }

    fn try_read(&mut self, buf: &mut dyn ReadBuf) -> io::Result<usize>;

    fn try_write(&mut self, buf: &[u8]) -> io::Result<usize>;

    fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    fn poll_write_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    fn poll_flush(&mut self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // `flush()` is a no-op for TCP/UDS
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>>;

    fn read<'a, B: ReadBuf>(&'a mut self, buf: &'a mut B) -> Read<'a, Self, B>
    where
        Self: Sized,
    {
        Read { socket: self, buf }
    }

    fn write<'a>(&'a mut self, buf: &'a [u8]) -> Write<'a, Self>
    where
        Self: Sized,
    {
        Write { socket: self, buf }
    }

    fn flush(&mut self) -> Flush<'_, Self>
    where
        Self: Sized,
    {
        Flush { socket: self }
    }

    fn shutdown(&mut self) -> Shutdown<'_, Self>
    where
        Self: Sized,
    {
        Shutdown { socket: self }
    }
}

pub struct Read<'a, S: ?Sized, B> {
    socket: &'a mut S,
    buf: &'a mut B,
}

impl<'a, S: ?Sized, B> Future for Read<'a, S, B>
where
    S: Socket,
    B: ReadBuf,
{
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        while this.buf.has_remaining_mut() {
            match this.socket.try_read(&mut *this.buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!(this.socket.poll_read_ready(cx))?;
                }
                ready => return Poll::Ready(ready),
            }
        }

        Poll::Ready(Ok(0))
    }
}

pub struct Write<'a, S: ?Sized> {
    socket: &'a mut S,
    buf: &'a [u8],
}

impl<'a, S: ?Sized> Future for Write<'a, S>
where
    S: Socket,
{
    type Output = io::Result<usize>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;

        while !this.buf.is_empty() {
            match this.socket.try_write(this.buf) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready!(this.socket.poll_write_ready(cx))?;
                }
                ready => return Poll::Ready(ready),
            }
        }

        Poll::Ready(Ok(0))
    }
}

pub struct Flush<'a, S: ?Sized> {
    socket: &'a mut S,
}

impl<'a, S: Socket + ?Sized> Future for Flush<'a, S> {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.socket.poll_flush(cx)
    }
}

pub struct Shutdown<'a, S: ?Sized> {
    socket: &'a mut S,
}

impl<'a, S: ?Sized> Future for Shutdown<'a, S>
where
    S: Socket,
{
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.socket.poll_shutdown(cx)
    }
}

pub trait WithSocket {
    type Output;

    fn with_socket<S: Socket>(
        self,
        socket: S,
    ) -> impl std::future::Future<Output = Self::Output> + Send;
}

pub struct SocketIntoBox;

impl WithSocket for SocketIntoBox {
    type Output = Box<dyn Socket>;

    async fn with_socket<S: Socket>(self, socket: S) -> Self::Output {
        Box::new(socket)
    }
}

impl<S: Socket + ?Sized> Socket for Box<S> {
    fn tls_peer_certificate(&self) -> Option<&[u8]> {
        (**self).tls_peer_certificate()
    }

    fn try_read(&mut self, buf: &mut dyn ReadBuf) -> io::Result<usize> {
        (**self).try_read(buf)
    }

    fn try_write(&mut self, buf: &[u8]) -> io::Result<usize> {
        (**self).try_write(buf)
    }

    fn poll_read_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        (**self).poll_read_ready(cx)
    }

    fn poll_write_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        (**self).poll_write_ready(cx)
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        (**self).poll_flush(cx)
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        (**self).poll_shutdown(cx)
    }
}

pub async fn connect_tcp<Ws: WithSocket>(
    host: &str,
    port: u16,
    with_socket: Ws,
) -> crate::Result<Ws::Output> {
    // IPv6 addresses in URLs will be wrapped in brackets and the `url` crate doesn't trim those.
    let host = host.trim_matches(&['[', ']'][..]);

    #[cfg(feature = "_rt-tokio")]
    if crate::rt::rt_tokio::available() {
        use tokio::net::TcpStream;

        let stream = TcpStream::connect((host, port)).await?;
        stream.set_nodelay(true)?;

        return Ok(with_socket.with_socket(stream).await);
    }

    #[cfg(feature = "_rt-async-std")]
    {
        use async_io::Async;
        use async_std::net::ToSocketAddrs;
        use std::net::TcpStream;

        let mut last_err = None;

        // Loop through all the Socket Addresses that the hostname resolves to
        for socket_addr in (host, port).to_socket_addrs().await? {
            let stream = Async::<TcpStream>::connect(socket_addr)
                .await
                .and_then(|s| {
                    s.get_ref().set_nodelay(true)?;
                    Ok(s)
                });
            match stream {
                Ok(stream) => return Ok(with_socket.with_socket(stream).await),
                Err(e) => last_err = Some(e),
            }
        }

        // If we reach this point, it means we failed to connect to any of the addresses.
        // Return the last error we encountered, or a custom error if the hostname didn't resolve to any address.
        match last_err {
            Some(err) => Err(err.into()),
            None => Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "Hostname did not resolve to any addresses",
            )
            .into()),
        }
    }

    #[cfg(not(feature = "_rt-async-std"))]
    {
        crate::rt::missing_rt((host, port, with_socket))
    }
}

/// Resolve TCP candidates separately from connecting so callers can retain a
/// hostname for TLS while trying each resolved socket address in order.
pub async fn resolve_tcp(host: &str, port: u16) -> crate::Result<Vec<std::net::SocketAddr>> {
    #[cfg(feature = "_rt-tokio")]
    if crate::rt::rt_tokio::available() {
        return Ok(tokio::net::lookup_host((host, port)).await?.collect());
    }
    #[cfg(feature = "_rt-async-std")]
    {
        use async_std::net::ToSocketAddrs;
        Ok((host, port).to_socket_addrs().await?.collect())
    }
    #[cfg(not(feature = "_rt-async-std"))]
    {
        crate::rt::missing_rt((host, port))
    }
}

#[cfg(all(
    any(unix, windows),
    any(feature = "_rt-tokio", feature = "_rt-async-std")
))]
fn go_tcp_keepalive(socket: socket2::SockRef<'_>) {
    let settings = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(15));
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "visionos",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "windows",
    ))]
    let settings = settings
        .with_interval(std::time::Duration::from_secs(15))
        .with_retries(9);
    // Go newTCPConn ignores socket-option errors. Keep that boundary for
    // platforms/kernels that cannot apply every keepalive option.
    let _ = socket.set_tcp_keepalive(&settings);
}

/// Connect an already-resolved TCP address without another hostname lookup,
/// using Go's TCP no-delay and keepalive defaults for the native DB bridge.
pub async fn connect_tcp_addr<Ws: WithSocket>(
    address: std::net::SocketAddr,
    with_socket: Ws,
) -> crate::Result<Ws::Output> {
    #[cfg(feature = "_rt-tokio")]
    if crate::rt::rt_tokio::available() {
        let stream = tokio::net::TcpStream::connect(address).await?;
        let _ = stream.set_nodelay(true);
        #[cfg(any(unix, windows))]
        go_tcp_keepalive(socket2::SockRef::from(&stream));
        return Ok(with_socket.with_socket(stream).await);
    }
    #[cfg(feature = "_rt-async-std")]
    {
        let stream = async_io::Async::<std::net::TcpStream>::connect(address).await?;
        let _ = stream.get_ref().set_nodelay(true);
        #[cfg(any(unix, windows))]
        go_tcp_keepalive(socket2::SockRef::from(stream.get_ref()));
        Ok(with_socket.with_socket(stream).await)
    }
    #[cfg(not(feature = "_rt-async-std"))]
    {
        crate::rt::missing_rt((address, with_socket))
    }
}

/// Connect a Unix Domain Socket at the given path.
///
/// Returns an error if Unix Domain Sockets are not supported on this platform.
pub async fn connect_uds<P: AsRef<Path>, Ws: WithSocket>(
    path: P,
    with_socket: Ws,
) -> crate::Result<Ws::Output> {
    #[cfg(unix)]
    {
        #[cfg(feature = "_rt-tokio")]
        if crate::rt::rt_tokio::available() {
            use tokio::net::UnixStream;

            let stream = UnixStream::connect(path).await?;

            return Ok(with_socket.with_socket(stream).await);
        }

        #[cfg(feature = "_rt-async-std")]
        {
            use async_io::Async;
            use std::os::unix::net::UnixStream;

            let stream = Async::<UnixStream>::connect(path).await?;

            Ok(with_socket.with_socket(stream).await)
        }

        #[cfg(not(feature = "_rt-async-std"))]
        {
            crate::rt::missing_rt((path, with_socket))
        }
    }

    #[cfg(not(unix))]
    {
        drop((path, with_socket));

        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Unix domain sockets are not supported on this platform",
        )
        .into())
    }
}
