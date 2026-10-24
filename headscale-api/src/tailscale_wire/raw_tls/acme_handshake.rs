// Copyright 2009, 2018 The Go Authors. All rights reserved.
// Native certificate phase ordering adapts crypto/tls; see LICENSE-GO-STDLIB.

//! Native certificate preparation at the TLS version/resumption phase.
//!
//! The original connection owns its transcript, session lookup and HRR state.
//! Only a real certificate request invokes the async provider. Once this phase
//! is complete, tokio-rustls continues that same connection before doing I/O.

use std::{
    future::poll_fn,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use rustls::{ServerConfig, ServerConnection};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use super::super::tls::{AcmeCertificateProvider, AcmeHandshakeRequest};

pub(super) async fn accept<IO>(
    base: Arc<ServerConfig>,
    provider: Arc<dyn AcmeCertificateProvider>,
    io: IO,
) -> io::Result<TlsStream<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let handshake = tokio_rustls::LazyConfigAcceptor::new(
        rustls::server::Acceptor::default().go_server_client_hello(),
        io,
    )
    .await?;
    let mut io = handshake.io;
    let mut connection = match handshake.accepted.go_into_connection(base.clone()) {
        Ok(connection) => connection,
        Err((error, mut alert)) => {
            let _ = poll_fn(|cx| {
                let mut writer = WriteAdapter { io: &mut io, cx };
                match alert.write(&mut writer) {
                    Ok(0) => Poll::Ready(Ok(())),
                    Ok(_) => {
                        writer.cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
                    Err(error) => Poll::Ready(Err(error)),
                }
            })
            .await;
            let _ = poll_fn(|cx| Pin::new(&mut io).poll_flush(cx)).await;
            return Err(io::Error::new(io::ErrorKind::InvalidData, error));
        }
    };
    let mut needs_flush = false;

    loop {
        let request = connection
            .go_certificate_request()
            .map(|hello| AcmeHandshakeRequest::from_client_hello(&hello));
        if let Some(request) = request {
            let selected = match request {
                Ok(request) => provider.prepare(request).await,
                Err(error) => Err(error),
            };
            let selected = match selected {
                Ok(selected) => selected,
                Err(error) => {
                    let _ =
                        connection.go_reject_certificate(rustls::Error::General(error.to_string()));
                    let _ =
                        poll_fn(|cx| flush_output(&mut connection, &mut io, cx, &mut needs_flush))
                            .await;
                    return Err(io::Error::other(error));
                }
            };
            if let Err(error) = connection.go_complete_certificate(selected) {
                let _ = poll_fn(|cx| flush_output(&mut connection, &mut io, cx, &mut needs_flush))
                    .await;
                return Err(io::Error::new(io::ErrorKind::InvalidData, error));
            }
        }
        if connection.go_certificate_phase_complete() {
            break;
        }
        if let Err(error) =
            poll_fn(|cx| poll_certificate_phase(&mut connection, &mut io, cx, &mut needs_flush))
                .await
        {
            let _ =
                poll_fn(|cx| flush_output(&mut connection, &mut io, cx, &mut needs_flush)).await;
            return Err(error);
        }
    }

    // Finish this phase's writes before handing over their flush state. Then
    // process any records the acceptor already read: tokio-rustls otherwise
    // calls read_tls before process_new_packets and could wait for fresh input
    // even though a following record is already buffered in this connection.
    poll_fn(|cx| flush_output(&mut connection, &mut io, cx, &mut needs_flush)).await?;
    if let Err(error) = connection.process_new_packets() {
        let _ = poll_fn(|cx| flush_output(&mut connection, &mut io, cx, &mut needs_flush)).await;
        return Err(io::Error::new(io::ErrorKind::InvalidData, error));
    }

    // accept_with constructs an empty initial connection and invokes this
    // closure before any I/O. Replace it with the actual owned state machine;
    // no certificate, ticket, message or transcript is fabricated or replayed.
    TlsAcceptor::from(base)
        .accept_with(io, move |fresh| *fresh = connection)
        .await
}

fn poll_certificate_phase<IO>(
    connection: &mut ServerConnection,
    io: &mut IO,
    cx: &mut Context<'_>,
    needs_flush: &mut bool,
) -> Poll<io::Result<()>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    // Bound synchronous progress without changing protocol admission limits.
    for _ in 0..32 {
        if connection.go_certificate_request().is_some()
            || connection.go_certificate_phase_complete()
        {
            return Poll::Ready(Ok(()));
        }
        match flush_output(connection, io, cx, needs_flush) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => return Poll::Pending,
        }
        // The initial acceptor can already have buffered records following
        // ClientHello. Consume those before waiting for another transport read.
        if let Err(error) = connection.process_new_packets() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
        }
        if connection.go_certificate_request().is_some()
            || connection.go_certificate_phase_complete()
        {
            return Poll::Ready(Ok(()));
        }
        if connection.wants_write() {
            continue;
        }
        // A pending certificate continuation must not consume following
        // messages. Its native state also disables further read admission.
        if !connection.wants_read() {
            return Poll::Ready(Err(io::Error::other(
                "native TLS certificate phase cannot make progress",
            )));
        }
        let mut reader = ReadAdapter {
            io: &mut *io,
            cx: &mut *cx,
        };
        match connection.read_tls(&mut reader) {
            Ok(0) => return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into())),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(error) => return Poll::Ready(Err(error)),
        }
        if let Err(error) = connection.process_new_packets() {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, error)));
        }
    }
    cx.waker().wake_by_ref();
    Poll::Pending
}

fn flush_output<IO>(
    connection: &mut ServerConnection,
    io: &mut IO,
    cx: &mut Context<'_>,
    needs_flush: &mut bool,
) -> Poll<io::Result<()>>
where
    IO: AsyncWrite + Unpin,
{
    for _ in 0..32 {
        if !connection.wants_write() {
            if *needs_flush {
                match Pin::new(&mut *io).poll_flush(cx) {
                    Poll::Ready(Ok(())) => *needs_flush = false,
                    result => return result,
                }
            }
            return Poll::Ready(Ok(()));
        }
        let mut writer = WriteAdapter {
            io: &mut *io,
            cx: &mut *cx,
        };
        match connection.write_tls(&mut writer) {
            Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
            Ok(_) => *needs_flush = true,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
            Err(error) => return Poll::Ready(Err(error)),
        }
    }
    cx.waker().wake_by_ref();
    Poll::Pending
}

struct ReadAdapter<'io, 'cx, 'task, IO> {
    io: &'io mut IO,
    cx: &'cx mut Context<'task>,
}

impl<IO: AsyncRead + Unpin> io::Read for ReadAdapter<'_, '_, '_, IO> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let mut buffer = ReadBuf::new(bytes);
        match Pin::new(&mut *self.io).poll_read(self.cx, &mut buffer) {
            Poll::Ready(Ok(())) => Ok(buffer.filled().len()),
            Poll::Ready(Err(error)) => Err(error),
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}

struct WriteAdapter<'io, 'cx, 'task, IO> {
    io: &'io mut IO,
    cx: &'cx mut Context<'task>,
}

impl<IO: AsyncWrite + Unpin> io::Write for WriteAdapter<'_, '_, '_, IO> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match Pin::new(&mut *self.io).poll_write(self.cx, bytes) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match Pin::new(&mut *self.io).poll_flush(self.cx) {
            Poll::Ready(result) => result,
            Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }
}
