use std::fmt;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
#[cfg(any(
    all(
        any(feature = "http1", feature = "http2"),
        any(feature = "client", feature = "server")
    ),
    all(feature = "go-client-idle", feature = "client")
))]
use futures_core::ready;
use http_body::{Body, Frame, SizeHint};

#[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
use super::chan;
#[cfg(all(
    any(feature = "http1", feature = "http2"),
    any(feature = "client", feature = "server")
))]
use super::DecodedLength;
#[cfg(all(feature = "http2", any(feature = "client", feature = "server")))]
use crate::proto::h2::ping;

/// A stream of `Bytes`, used when receiving bodies from the network.
///
/// Note that Users should not instantiate this struct directly. When working with the hyper client,
/// `Incoming` is returned to you in responses. Similarly, when operating with the hyper server,
/// it is provided within requests.
///
/// # Examples
///
/// ```rust,ignore
/// async fn echo(
///    req: Request<hyper::body::Incoming>,
/// ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
///    //Here, you can process `Incoming`
/// }
/// ```
#[must_use = "streams do nothing unless polled"]
pub struct Incoming {
    // Publish native early retirement before dropping the channel receiver.
    // Rust drops fields in declaration order, including implicit Body drop.
    #[cfg(all(feature = "go-client-idle", feature = "client", feature = "http1"))]
    go_h1: Option<super::go_h1::Consumer>,
    kind: Kind,
    #[cfg(all(feature = "go-client-idle", feature = "client"))]
    go_read_pending: Bytes,
    #[cfg(all(feature = "go-client-idle", feature = "client", feature = "http1"))]
    go_h1_read: Option<GoBodyRead>,
}

/// One caller-sized read by the native client transport.
#[cfg(all(feature = "go-client-idle", feature = "client"))]
#[doc(hidden)]
#[derive(Debug)]
pub struct GoBodyRead {
    /// Data returned by this read, never exceeding the requested maximum.
    pub data: Bytes,
    /// A failure returned together with any data from the same read.
    pub error: Option<crate::Error>,
    /// The body has reached EOF.
    pub eof: bool,
}

enum Kind {
    Empty,
    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    Chan {
        content_length: DecodedLength,
        rx: chan::Receiver,
    },
    #[cfg(all(feature = "http2", any(feature = "client", feature = "server")))]
    H2 {
        content_length: DecodedLength,
        data_done: bool,
        ping: ping::Recorder,
        recv: h2::RecvStream,
    },
    #[cfg(feature = "ffi")]
    Ffi(crate::ffi::UserBody),
}

/// A sender half created through [`Body::channel()`].
///
/// Useful when wanting to stream chunks from another thread.
///
/// ## Body Closing
///
/// Note that the request body will always be closed normally when the sender is dropped (meaning
/// that the empty terminating chunk will be sent to the remote). If you desire to close the
/// connection with an incomplete response (e.g. in the case of an error during asynchronous
/// processing), call the [`Sender::abort()`] method to abort the body in an abnormal fashion.
///
/// [`Body::channel()`]: struct.Body.html#method.channel
/// [`Sender::abort()`]: struct.Sender.html#method.abort
#[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
pub(crate) use super::chan::Sender;

impl Incoming {
    /// Create a `Body` stream with an associated sender half.
    ///
    /// Useful when wanting to stream chunks from another thread.
    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    #[inline]
    #[cfg(test)]
    pub(crate) fn channel() -> (Sender, Incoming) {
        Self::new_channel(DecodedLength::CHUNKED, /*wanter =*/ false)
    }

    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    pub(crate) fn new_channel(content_length: DecodedLength, wanter: bool) -> (Sender, Incoming) {
        let (tx, rx) = chan::channel(wanter);
        let rx = Incoming::new(Kind::Chan { content_length, rx });

        (tx, rx)
    }

    fn new(kind: Kind) -> Incoming {
        Incoming {
            kind,
            #[cfg(all(feature = "go-client-idle", feature = "client"))]
            go_read_pending: Bytes::new(),
            #[cfg(all(feature = "go-client-idle", feature = "client", feature = "http1"))]
            go_h1: None,
            #[cfg(all(feature = "go-client-idle", feature = "client", feature = "http1"))]
            go_h1_read: None,
        }
    }

    #[cfg(all(feature = "go-client-idle", feature = "client", feature = "http1"))]
    pub(crate) fn go_h1_control(&mut self, control: super::go_h1::Consumer) {
        self.go_h1 = Some(control);
    }

    /// Register a native pool-return acknowledgement before exposing this body.
    #[cfg(all(feature = "go-client-idle", feature = "client", feature = "http1"))]
    #[doc(hidden)]
    pub fn go_h1_pool_wait(&self) -> Option<super::GoH1PoolWait> {
        self.go_h1.as_ref().map(super::go_h1::Consumer::pool_wait)
    }

    #[cfg(all(feature = "go-client-idle", feature = "client", feature = "http1"))]
    fn go_h1_finish_read(
        &mut self,
        cx: &Context<'_>,
        mut read: GoBodyRead,
        maximum: usize,
    ) -> Poll<GoBodyRead> {
        if let Some(control) = &self.go_h1 {
            if read.eof {
                control.verdict(super::go_h1::Verdict::Eof);
                if control.poll_done(cx).is_pending() {
                    self.go_h1_read = Some(read);
                    return Poll::Pending;
                }
            } else if read.error.is_some() {
                control.verdict(super::go_h1::Verdict::Early);
            }
        }
        if read.data.len() > maximum {
            let data = read.data.split_to(maximum);
            self.go_h1_read = Some(read);
            return Poll::Ready(GoBodyRead {
                data,
                error: None,
                eof: false,
            });
        }
        Poll::Ready(read)
    }

    /// Reads the selected native client body with the caller's exact demand.
    #[cfg(all(feature = "go-client-idle", feature = "client"))]
    #[doc(hidden)]
    pub fn go_poll_read(&mut self, cx: &mut Context<'_>, maximum: usize) -> Poll<GoBodyRead> {
        #[cfg(feature = "http1")]
        if self.go_h1.is_some() && matches!(self.kind, Kind::Empty) {
            return Poll::Ready(GoBodyRead {
                data: Bytes::new(),
                error: Some(crate::Error::new_body("http: read on closed response body")),
                eof: false,
            });
        }
        #[cfg(feature = "http1")]
        if let Some(read) = self.go_h1_read.take() {
            return self.go_h1_finish_read(cx, read, maximum);
        }
        #[cfg(feature = "http2")]
        if let Kind::H2 {
            recv,
            content_length,
            data_done,
            ping,
        } = &mut self.kind
        {
            let read = ready!(recv.go_poll_read(cx, maximum));
            content_length.sub_if(read.data.len() as u64);
            if !read.data.is_empty() {
                ping.record_data(read.data.len());
            }
            if read.eof {
                *data_done = true;
                ping.record_non_data();
            }
            return Poll::Ready(GoBodyRead {
                data: read.data,
                error: read.error.map(crate::Error::new_body),
                eof: read.eof,
            });
        }
        // HTTP/1's existing channel is frame-oriented. Retain its unread tail
        // without requesting the following channel chunk; the lower transport
        // still determines HTTP/1 socket read and framing boundaries.
        if maximum == 0 {
            let read = GoBodyRead {
                data: Bytes::new(),
                error: None,
                eof: self.go_read_pending.is_empty()
                    && {
                        #[cfg(feature = "http1")]
                        {
                            matches!(&self.kind, Kind::Chan { content_length, .. } if *content_length == DecodedLength::ZERO)
                                || matches!(self.kind, Kind::Empty)
                        }
                        #[cfg(not(feature = "http1"))]
                        {
                            self.is_end_stream()
                        }
                    },
            };
            #[cfg(feature = "http1")]
            return self.go_h1_finish_read(cx, read, 0);
            #[cfg(not(feature = "http1"))]
            return Poll::Ready(read);
        }
        loop {
            if !self.go_read_pending.is_empty() {
                let count = maximum.min(self.go_read_pending.len());
                let data = self.go_read_pending.split_to(count);
                #[cfg(feature = "http1")]
                let eof = self.go_read_pending.is_empty()
                    && matches!(&self.kind, Kind::Chan { content_length, .. } if *content_length == DecodedLength::ZERO);
                #[cfg(not(feature = "http1"))]
                let eof = false;
                let read = GoBodyRead {
                    data,
                    error: None,
                    eof,
                };
                #[cfg(feature = "http1")]
                return self.go_h1_finish_read(cx, read, maximum);
                #[cfg(not(feature = "http1"))]
                return Poll::Ready(read);
            }
            match ready!(Pin::new(&mut *self).poll_frame_inner(cx)) {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.go_read_pending = data;
                    }
                }
                Some(Err(error)) => {
                    let read = GoBodyRead {
                        data: Bytes::new(),
                        error: Some(error),
                        eof: false,
                    };
                    #[cfg(feature = "http1")]
                    return self.go_h1_finish_read(cx, read, maximum);
                    #[cfg(not(feature = "http1"))]
                    return Poll::Ready(read);
                }
                None => {
                    let read = GoBodyRead {
                        data: Bytes::new(),
                        error: None,
                        eof: true,
                    };
                    #[cfg(feature = "http1")]
                    return self.go_h1_finish_read(cx, read, maximum);
                    #[cfg(not(feature = "http1"))]
                    return Poll::Ready(read);
                }
            }
        }
    }

    /// Closes the selected native body, waiting for its receive-credit writer.
    #[cfg(all(feature = "go-client-idle", feature = "client"))]
    #[doc(hidden)]
    pub fn go_poll_close(&mut self, cx: &mut Context<'_>) -> Poll<crate::Result<()>> {
        #[cfg(feature = "http2")]
        if let Kind::H2 {
            recv, data_done, ..
        } = &mut self.kind
        {
            let result = ready!(recv.go_poll_close(cx)).map_err(crate::Error::new_body);
            *data_done = true;
            return Poll::Ready(result);
        }
        #[cfg(feature = "http1")]
        if let Some(control) = &self.go_h1 {
            control.verdict(super::go_h1::Verdict::Early);
            self.go_read_pending = Bytes::new();
            self.go_h1_read = None;
            self.kind = Kind::Empty;
            ready!(control.poll_done(cx));
            return Poll::Ready(Ok(()));
        }
        let _ = cx;
        self.go_read_pending = Bytes::new();
        self.kind = Kind::Empty;
        Poll::Ready(Ok(()))
    }

    /// Whether Go's native response selects its transport-body/gzip branch.
    #[cfg(all(feature = "go-client-idle", feature = "client"))]
    #[doc(hidden)]
    pub fn go_body_is_transport(&self) -> bool {
        match &self.kind {
            Kind::Empty => false,
            #[cfg(feature = "http2")]
            Kind::H2 { recv, .. } => recv.go_body_is_transport(),
            #[cfg(feature = "http1")]
            Kind::Chan { content_length, .. } => *content_length != DecodedLength::ZERO,
            #[cfg(feature = "ffi")]
            Kind::Ffi(..) => true,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn empty() -> Incoming {
        Incoming::new(Kind::Empty)
    }

    #[cfg(feature = "ffi")]
    pub(crate) fn ffi() -> Incoming {
        Incoming::new(Kind::Ffi(crate::ffi::UserBody::new()))
    }

    #[cfg(all(feature = "http2", any(feature = "client", feature = "server")))]
    pub(crate) fn h2(
        recv: h2::RecvStream,
        mut content_length: DecodedLength,
        ping: ping::Recorder,
    ) -> Self {
        // If the stream is already EOS, then the "unknown length" is clearly
        // actually ZERO.
        if !content_length.is_exact() && recv.is_end_stream() {
            content_length = DecodedLength::ZERO;
        }

        Incoming::new(Kind::H2 {
            data_done: false,
            ping,
            content_length,
            recv,
        })
    }

    #[cfg(feature = "ffi")]
    pub(crate) fn as_ffi_mut(&mut self) -> &mut crate::ffi::UserBody {
        if !matches!(self.kind, Kind::Ffi(_)) {
            self.kind = Kind::Ffi(crate::ffi::UserBody::new());
        }

        match &mut self.kind {
            Kind::Ffi(body) => body,
            _ => unreachable!(),
        }
    }
}

impl Incoming {
    fn poll_frame_inner(
        #[cfg_attr(
            not(all(
                any(feature = "http1", feature = "http2"),
                any(feature = "client", feature = "server")
            )),
            allow(unused_mut)
        )]
        mut self: Pin<&mut Self>,
        #[cfg_attr(
            not(all(
                any(feature = "http1", feature = "http2"),
                any(feature = "client", feature = "server")
            )),
            allow(unused_variables)
        )]
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, crate::Error>>> {
        #[cfg(all(feature = "go-client-idle", feature = "client"))]
        if !self.go_read_pending.is_empty() {
            return Poll::Ready(Some(Ok(Frame::data(std::mem::take(
                &mut self.go_read_pending,
            )))));
        }
        match &mut self.kind {
            Kind::Empty => Poll::Ready(None),
            #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
            Kind::Chan {
                content_length: len,
                rx,
            } => {
                if let Some(chunk) = ready!(rx.poll_next(cx)?) {
                    len.sub_if(chunk.len() as u64);
                    return Poll::Ready(Some(Ok(Frame::data(chunk))));
                }
                Poll::Ready(rx.take_trailers().map(Frame::trailers).map(Ok))
            }
            #[cfg(all(feature = "http2", any(feature = "client", feature = "server")))]
            Kind::H2 {
                data_done,
                ping,
                recv: h2,
                content_length: len,
            } => {
                if !*data_done {
                    match ready!(h2.poll_data(cx)) {
                        Some(Ok(bytes)) => {
                            let _ = h2.flow_control().release_capacity(bytes.len());
                            len.sub_if(bytes.len() as u64);
                            ping.record_data(bytes.len());
                            return Poll::Ready(Some(Ok(Frame::data(bytes))));
                        }
                        Some(Err(e)) => {
                            if let Some(h2::Reason::NO_ERROR) = e.reason() {
                                // As mentioned in RFC 7540 Section 8.1, a RST_STREAM with NO_ERROR
                                // indicates an early response, and should cause the body reading
                                // to stop, but not fail it:
                                return Poll::Ready(None);
                            } else {
                                return Poll::Ready(Some(Err(crate::Error::new_body(e))));
                            }
                        }
                        None => {
                            *data_done = true;
                            // fall through to trailers
                        }
                    }
                }

                // after data, check trailers
                match ready!(h2.poll_trailers(cx)) {
                    Ok(t) => {
                        ping.record_non_data();
                        Poll::Ready(Ok(t.map(Frame::trailers)).transpose())
                    }
                    Err(e) => {
                        if let Some(h2::Reason::NO_ERROR) = e.reason() {
                            // Same as above, a RST_STREAM with NO_ERROR indicates an early
                            // response, and should cause reading the trailers to stop, but
                            // not fail it:
                            Poll::Ready(None)
                        } else {
                            Poll::Ready(Some(Err(crate::Error::new_h2(e))))
                        }
                    }
                }
            }

            #[cfg(feature = "ffi")]
            Kind::Ffi(body) => body.poll_data(cx),
        }
    }
}

impl Body for Incoming {
    type Data = Bytes;
    type Error = crate::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, crate::Error>>> {
        #[cfg(all(feature = "go-client-idle", feature = "client", feature = "http1"))]
        if let Some(read) = self.go_h1_read.take() {
            let read = ready!(self.go_h1_finish_read(cx, read, usize::MAX));
            if !read.data.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(read.data))));
            }
            if let Some(error) = read.error {
                return Poll::Ready(Some(Err(error)));
            }
            if read.eof {
                return Poll::Ready(None);
            }
        }
        let result = self.as_mut().poll_frame_inner(cx);
        #[cfg(all(feature = "go-client-idle", feature = "client", feature = "http1"))]
        if let Some(control) = &self.go_h1 {
            match &result {
                Poll::Ready(None) => {
                    control.verdict(super::go_h1::Verdict::Eof);
                    ready!(control.poll_done(cx));
                }
                Poll::Ready(Some(Err(_))) => control.verdict(super::go_h1::Verdict::Early),
                _ => {}
            }
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        #[cfg(all(feature = "go-client-idle", feature = "client", feature = "http1"))]
        if self
            .go_h1_read
            .as_ref()
            .is_some_and(|read| !read.data.is_empty())
        {
            return false;
        }
        #[cfg(all(feature = "go-client-idle", feature = "client", feature = "http1"))]
        if self
            .go_h1
            .as_ref()
            .is_some_and(super::go_h1::Consumer::pending)
        {
            return false;
        }
        #[cfg(all(feature = "go-client-idle", feature = "client"))]
        if !self.go_read_pending.is_empty() {
            return false;
        }
        match &self.kind {
            Kind::Empty => true,
            #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
            Kind::Chan { content_length, .. } => *content_length == DecodedLength::ZERO,
            #[cfg(all(feature = "http2", any(feature = "client", feature = "server")))]
            Kind::H2 { recv: h2, .. } => h2.is_end_stream(),
            #[cfg(feature = "ffi")]
            Kind::Ffi(..) => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        #[cfg(all(
            any(feature = "http1", feature = "http2"),
            any(feature = "client", feature = "server")
        ))]
        fn opt_len(decoded_length: DecodedLength) -> SizeHint {
            if let Some(content_length) = decoded_length.into_opt() {
                SizeHint::with_exact(content_length)
            } else {
                SizeHint::default()
            }
        }

        let hint = match self.kind {
            Kind::Empty => SizeHint::with_exact(0),
            #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
            Kind::Chan { content_length, .. } => opt_len(content_length),
            #[cfg(all(feature = "http2", any(feature = "client", feature = "server")))]
            Kind::H2 { content_length, .. } => opt_len(content_length),
            #[cfg(feature = "ffi")]
            Kind::Ffi(..) => SizeHint::default(),
        };
        #[cfg(all(feature = "go-client-idle", feature = "client"))]
        if !self.go_read_pending.is_empty() {
            let extra = self.go_read_pending.len() as u64;
            let mut with_pending = SizeHint::new();
            with_pending.set_lower(hint.lower().saturating_add(extra));
            if let Some(upper) = hint.upper().and_then(|upper| upper.checked_add(extra)) {
                with_pending.set_upper(upper);
            }
            return with_pending;
        }
        hint
    }
}

impl fmt::Debug for Incoming {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(any(
            all(
                any(feature = "http1", feature = "http2"),
                any(feature = "client", feature = "server")
            ),
            feature = "ffi"
        ))]
        #[derive(Debug)]
        struct Streaming;
        #[derive(Debug)]
        struct Empty;

        let mut builder = f.debug_tuple("Body");
        match self.kind {
            Kind::Empty => builder.field(&Empty),
            #[cfg(any(
                all(
                    any(feature = "http1", feature = "http2"),
                    any(feature = "client", feature = "server")
                ),
                feature = "ffi"
            ))]
            _ => builder.field(&Streaming),
        };

        builder.finish()
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    use std::mem;
    #[cfg(all(feature = "nightly", not(miri)))]
    use std::pin::Pin;
    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    use std::task::Poll;

    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    use super::{Body, Incoming, SizeHint};
    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    use super::{DecodedLength, Sender};
    #[cfg(all(feature = "nightly", not(miri)))]
    use bytes::Bytes;
    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    use http_body_util::BodyExt;

    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    #[test]
    fn test_size_of() {
        // These are mostly to help catch *accidentally* increasing
        // the size by too much.

        let body_size = mem::size_of::<Incoming>();
        let body_expected_size = mem::size_of::<u64>() * 5;
        assert!(
            body_size <= body_expected_size,
            "Body size = {} <= {}",
            body_size,
            body_expected_size,
        );

        assert_eq!(
            mem::size_of::<Sender>(),
            mem::size_of::<usize>() * 2,
            "Sender"
        );

        assert_eq!(
            mem::size_of::<Sender>(),
            mem::size_of::<Option<Sender>>(),
            "Option<Sender>"
        );
    }

    #[cfg(all(feature = "nightly", not(miri)))]
    #[bench]
    fn bench_channel_create_and_drop(b: &mut test::Bencher) {
        b.iter(|| {
            let _ = test::black_box(Incoming::new_channel(
                DecodedLength::CHUNKED,
                /* wanter = */ false,
            ));
        });
    }

    #[cfg(all(feature = "nightly", not(miri)))]
    #[bench]
    fn bench_channel_data_handoff(b: &mut test::Bencher) {
        let (mut tx, mut body) =
            Incoming::new_channel(DecodedLength::CHUNKED, /* wanter = */ false);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());

        b.iter(|| {
            assert!(tx.poll_ready(&mut cx).is_ready());
            tx.try_send_data(Bytes::from_static(b"hello world"))
                .unwrap();
            let frame = match Pin::new(&mut body).poll_frame(&mut cx) {
                Poll::Ready(Some(Ok(frame))) => frame,
                unexpected => panic!("unexpected body poll: {unexpected:?}"),
            };
            test::black_box(frame);
        });
    }

    #[cfg(all(feature = "nightly", not(miri)))]
    #[bench]
    fn bench_channel_want_transition(b: &mut test::Bencher) {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());

        b.iter(|| {
            let (mut tx, mut body) =
                Incoming::new_channel(DecodedLength::CHUNKED, /* wanter = */ true);
            assert!(tx.poll_ready(&mut cx).is_pending());
            assert!(Pin::new(&mut body).poll_frame(&mut cx).is_pending());
            assert!(tx.poll_ready(&mut cx).is_ready());
            let _ = test::black_box((tx, body));
        });
    }

    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    #[test]
    fn size_hint() {
        fn eq(body: Incoming, b: SizeHint, note: &str) {
            let a = body.size_hint();
            assert_eq!(a.lower(), b.lower(), "lower for {:?}", note);
            assert_eq!(a.upper(), b.upper(), "upper for {:?}", note);
        }

        eq(Incoming::empty(), SizeHint::with_exact(0), "empty");

        eq(Incoming::channel().1, SizeHint::new(), "channel");

        eq(
            Incoming::new_channel(DecodedLength::new(4), /*wanter =*/ false).1,
            SizeHint::with_exact(4),
            "channel with length",
        );
    }

    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    #[cfg(not(miri))]
    #[tokio::test]
    async fn channel_abort() {
        let (tx, mut rx) = Incoming::channel();

        tx.abort();

        let err = rx.frame().await.unwrap().unwrap_err();
        assert!(err.is_body_write_aborted(), "{:?}", err);
    }

    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    #[cfg(all(not(miri), feature = "http1"))]
    #[tokio::test]
    async fn channel_abort_when_buffer_is_full() {
        let (mut tx, mut rx) = Incoming::channel();

        tx.try_send_data("chunk 1".into()).expect("send 1");
        // buffer is full, but can still send abort
        tx.abort();

        let chunk1 = rx
            .frame()
            .await
            .expect("item 1")
            .expect("chunk 1")
            .into_data()
            .unwrap();
        assert_eq!(chunk1, "chunk 1");

        let err = rx.frame().await.unwrap().unwrap_err();
        assert!(err.is_body_write_aborted(), "{:?}", err);
    }

    #[cfg(feature = "http1")]
    #[test]
    fn channel_buffers_one() {
        let (mut tx, _rx) = Incoming::channel();

        tx.try_send_data("chunk 1".into()).expect("send 1");

        // buffer is now full
        let chunk2 = tx.try_send_data("chunk 2".into()).expect_err("send 2");
        assert_eq!(chunk2, "chunk 2");
    }

    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    #[cfg(not(miri))]
    #[tokio::test]
    async fn channel_empty() {
        let (_, mut rx) = Incoming::channel();

        assert!(rx.frame().await.is_none());
    }

    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    #[test]
    fn channel_ready() {
        let (mut tx, _rx) = Incoming::new_channel(DecodedLength::CHUNKED, /*wanter = */ false);

        let mut tx_ready = tokio_test::task::spawn(tx.ready());

        assert!(tx_ready.poll().is_ready(), "tx is ready immediately");
    }

    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    #[test]
    fn channel_wanter() {
        let (mut tx, mut rx) =
            Incoming::new_channel(DecodedLength::CHUNKED, /*wanter = */ true);

        let mut tx_ready = tokio_test::task::spawn(tx.ready());
        let mut rx_data = tokio_test::task::spawn(rx.frame());

        assert!(
            tx_ready.poll().is_pending(),
            "tx isn't ready before rx has been polled"
        );

        assert!(rx_data.poll().is_pending(), "poll rx.data");
        assert!(tx_ready.is_woken(), "rx poll wakes tx");

        assert!(
            tx_ready.poll().is_ready(),
            "tx is ready after rx has been polled"
        );
    }

    #[cfg(all(feature = "http1", any(feature = "client", feature = "server")))]
    #[test]
    fn channel_notices_closure() {
        let (mut tx, rx) = Incoming::new_channel(DecodedLength::CHUNKED, /*wanter = */ true);

        let mut tx_ready = tokio_test::task::spawn(tx.ready());

        assert!(
            tx_ready.poll().is_pending(),
            "tx isn't ready before rx has been polled"
        );

        drop(rx);
        assert!(tx_ready.is_woken(), "dropping rx wakes tx");

        match &tx_ready.poll() {
            Poll::Ready(Err(e)) if e.is_closed() => (),
            unexpected => panic!("tx poll ready unexpected: {:?}", unexpected),
        }
    }
}
