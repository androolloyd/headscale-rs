//! Concurrent TLS preparation for the native ACME remote gRPC listener.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use headscale_api::tailscale_wire::raw_tls::accept_tls_with_config;
use headscale_api::tailscale_wire::tls::ReloadableServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::server::TlsStream;
use tokio_stream::Stream;

// Bound connection-owned handshake tasks. Certificate issuance itself is
// provider-owned and remains independent from cancellation of a waiting peer.
const MAX_HANDSHAKES: usize = 1024;

pub(super) fn incoming(
    listener: TcpListener,
    reloader: ReloadableServerConfig,
) -> impl Stream<Item = io::Result<TlsStream<TcpStream>>> + Send {
    Incoming {
        listener,
        reloader,
        handshakes: JoinSet::new(),
    }
}

struct Incoming {
    listener: TcpListener,
    reloader: ReloadableServerConfig,
    // Dropping the incoming stream requests cancellation of every tracked
    // connection future, instead of detaching live handshake handles.
    handshakes: JoinSet<io::Result<TlsStream<TcpStream>>>,
}

impl Stream for Incoming {
    type Item = io::Result<TlsStream<TcpStream>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if let Poll::Ready(Some(result)) = this.handshakes.poll_join_next(cx) {
            return Poll::Ready(Some(
                result.unwrap_or_else(|error| Err(io::Error::other(error))),
            ));
        }

        if this.handshakes.len() < MAX_HANDSHAKES {
            match this.listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, _))) => {
                    let reloader = this.reloader.clone();
                    this.handshakes
                        .spawn(async move { accept_tls_with_config(reloader, stream).await });

                    // An empty JoinSet does not register a completion waiter.
                    // Poll again after spawning so the first task can wake us.
                    if let Poll::Ready(Some(result)) = this.handshakes.poll_join_next(cx) {
                        return Poll::Ready(Some(
                            result.unwrap_or_else(|error| Err(io::Error::other(error))),
                        ));
                    }
                    // Admit another peer without waiting for this handshake;
                    // one spawn per poll keeps admission cooperative.
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Some(Err(error))),
                Poll::Pending => {}
            }
        }

        Poll::Pending
    }
}
