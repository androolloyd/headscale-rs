use crate::codec::UserError;
use crate::codec::UserError::*;
use crate::frame::{self, Frame, FrameSize};
use crate::hpack;

use bytes::{Buf, BufMut, BytesMut};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::poll_write_buf;

use std::io::{self, Cursor};

#[cfg(feature = "go-client-idle")]
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Arc,
};

/// Completion of one native client's writer-owned output flight.
#[cfg(feature = "go-client-idle")]
#[derive(Clone, Debug)]
pub(crate) struct GoWriteReceipt(Arc<AtomicU8>);

#[cfg(feature = "go-client-idle")]
impl GoWriteReceipt {
    fn new() -> Self {
        Self(Arc::new(AtomicU8::new(0)))
    }

    pub(crate) fn is_flushed(&self) -> bool {
        self.0.load(Ordering::Acquire) == 1
    }

    pub(crate) fn is_failed(&self) -> bool {
        self.0.load(Ordering::Acquire) == 2
    }
}

#[cfg(feature = "go-client-idle")]
#[derive(Debug, Default)]
struct GoOutput {
    receipt: Option<GoWriteReceipt>,
    grouped: bool,
    sealed: bool,
    error: Option<Arc<io::Error>>,
}

#[cfg(feature = "go-client-idle")]
#[derive(Debug)]
struct GoWriteFailure(Arc<io::Error>);

#[cfg(feature = "go-client-idle")]
impl std::fmt::Display for GoWriteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), f)
    }
}

#[cfg(feature = "go-client-idle")]
impl std::error::Error for GoWriteFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

// A macro to get around a method needing to borrow &mut self
macro_rules! limited_write_buf {
    ($self:expr) => {{
        let limit = $self.max_frame_size() + frame::HEADER_LEN;
        $self.buf.get_mut().limit(limit)
    }};
}

#[derive(Debug)]
pub struct FramedWrite<T, B> {
    /// Upstream `AsyncWrite`
    inner: T,
    final_flush_done: bool,

    #[cfg(feature = "go-client-idle")]
    go_output: Option<GoOutput>,

    encoder: Encoder<B>,
}

#[derive(Debug)]
struct Encoder<B> {
    /// HPACK encoder
    hpack: hpack::Encoder,

    /// Write buffer
    ///
    /// TODO: Should this be a ring buffer?
    buf: Cursor<BytesMut>,

    /// Next frame to encode
    next: Option<Next<B>>,

    /// Last data frame
    last_data_frame: Option<frame::Data<B>>,

    /// Max frame size, this is specified by the peer
    max_frame_size: FrameSize,

    /// Chain payloads bigger than this.
    chain_threshold: usize,

    /// Min buffer required to attempt to write a frame
    min_buffer_capacity: usize,
}

#[derive(Debug)]
enum Next<B> {
    Data(frame::Data<B>),
    Continuation(frame::Continuation),
}

/// Initialize the connection with this amount of write buffer.
///
/// The minimum MAX_FRAME_SIZE is 16kb, so always be able to send a HEADERS
/// frame that big.
const DEFAULT_BUFFER_CAPACITY: usize = 16 * 1_024;

/// Chain payloads bigger than this when vectored I/O is enabled. The remote
/// will never advertise a max frame size less than this (well, the spec says
/// the max frame size can't be less than 16kb, so not even close).
const CHAIN_THRESHOLD: usize = 256;

/// Chain payloads bigger than this when vectored I/O is **not** enabled.
/// A larger value in this scenario will reduce the number of small and
/// fragmented data being sent, and hereby improve the throughput.
const CHAIN_THRESHOLD_WITHOUT_VECTORED_IO: usize = 1024;

// TODO: Make generic
impl<T, B> FramedWrite<T, B>
where
    T: AsyncWrite + Unpin,
    B: Buf,
{
    pub fn new(inner: T) -> FramedWrite<T, B> {
        let chain_threshold = if inner.is_write_vectored() {
            CHAIN_THRESHOLD
        } else {
            CHAIN_THRESHOLD_WITHOUT_VECTORED_IO
        };
        FramedWrite {
            inner,
            final_flush_done: false,
            #[cfg(feature = "go-client-idle")]
            go_output: None,
            encoder: Encoder {
                hpack: hpack::Encoder::default(),
                buf: Cursor::new(BytesMut::with_capacity(DEFAULT_BUFFER_CAPACITY)),
                next: None,
                last_data_frame: None,
                max_frame_size: frame::DEFAULT_MAX_FRAME_SIZE,
                chain_threshold,
                min_buffer_capacity: chain_threshold + frame::HEADER_LEN,
            },
        }
    }

    /// Returns `Ready` when `send` is able to accept a frame
    ///
    /// Calling this function may result in the current contents of the buffer
    /// to be flushed to `T`.
    pub fn poll_ready(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        #[cfg(feature = "go-client-idle")]
        if let Some(error) = self.go_client_write_error() {
            return Poll::Ready(Err(error));
        }
        if !self.has_capacity() {
            // Try flushing
            ready!(self.flush(cx))?;

            if !self.has_capacity() {
                return Poll::Pending;
            }
        }

        Poll::Ready(Ok(()))
    }

    /// Returns whether a frame can be buffered without first flushing the
    /// underlying I/O object.
    pub(crate) fn has_capacity(&self) -> bool {
        #[cfg(feature = "go-client-idle")]
        if self
            .go_output
            .as_ref()
            .is_some_and(|output| output.sealed || output.error.is_some())
        {
            return false;
        }
        self.encoder.has_capacity()
    }

    /// Buffer a frame.
    ///
    /// `poll_ready` must be called first to ensure that a frame may be
    /// accepted.
    pub fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        #[cfg(feature = "go-client-idle")]
        if let Some(output) = self.go_output.as_mut() {
            if output.error.is_some() {
                // bufio-style sticky failure: later logical writes fail
                // without touching the failed encoder or the transport.
                if !output.grouped {
                    let receipt = GoWriteReceipt::new();
                    receipt.0.store(2, Ordering::Release);
                    output.receipt = Some(receipt);
                }
                drop(item);
                return Ok(());
            }
        }
        #[cfg(feature = "go-client-idle")]
        if let Some(output) = self.go_output.as_ref() {
            // Like Encoder's capacity assertion, this requires poll_ready (or
            // has_capacity) before buffering. Never append to another owner.
            assert!(!output.sealed && output.error.is_none());
        }
        self.encoder.buffer(item)?;
        #[cfg(feature = "go-client-idle")]
        if let Some(output) = self.go_output.as_mut() {
            if !output.grouped {
                output.receipt = Some(GoWriteReceipt::new());
                output.sealed = true;
            }
        }
        Ok(())
    }

    /// Flush buffered data to the wire
    pub fn flush(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        #[cfg(feature = "go-client-idle")]
        if let Some(error) = self.go_client_write_error() {
            return Poll::Ready(Err(error));
        }
        let result = self.flush_inner(cx);
        #[cfg(feature = "go-client-idle")]
        if let Some(output) = self.go_output.as_mut() {
            match result {
                Poll::Ready(Ok(())) if output.sealed => {
                    if let Some(receipt) = &output.receipt {
                        receipt.0.store(1, Ordering::Release);
                    }
                    output.sealed = false;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => {
                    if let Some(receipt) = &output.receipt {
                        // Earlier successfully flushed receipts stay complete.
                        let _ =
                            receipt
                                .0
                                .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
                    }
                    output.error = Some(Arc::new(error));
                    return Poll::Ready(Err(self.go_client_write_error().unwrap()));
                }
                result => return result,
            }
        }
        result
    }

    fn flush_inner(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        let span = tracing::trace_span!("FramedWrite::flush");
        let _e = span.enter();

        loop {
            while !self.encoder.is_empty() {
                let n = match self.encoder.next {
                    Some(Next::Data(ref mut frame)) => {
                        tracing::trace!(queued_data_frame = true);
                        let mut buf = (&mut self.encoder.buf).chain(frame.payload_mut());
                        ready!(poll_write_buf(Pin::new(&mut self.inner), cx, &mut buf))?
                    }
                    _ => {
                        tracing::trace!(queued_data_frame = false);
                        ready!(poll_write_buf(
                            Pin::new(&mut self.inner),
                            cx,
                            &mut self.encoder.buf
                        ))?
                    }
                };
                if n == 0 {
                    // No progress is possible; retrying would busy-loop.
                    tracing::trace!("write returned zero, but non-zero bytes remaining");
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
            }

            match self.encoder.unset_frame() {
                ControlFlow::Continue => (),
                ControlFlow::Break => break,
            }
        }

        tracing::trace!("flushing buffer");
        // Flush the upstream
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;

        Poll::Ready(Ok(()))
    }

    /// Close the codec
    pub fn shutdown(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        if !self.final_flush_done {
            ready!(self.flush(cx))?;
            self.final_flush_done = true;
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_flush_through(
        &mut self,
        cx: &mut Context,
        receipt: &GoWriteReceipt,
    ) -> Poll<io::Result<()>> {
        if receipt.is_flushed() {
            return Poll::Ready(Ok(()));
        }
        if receipt.is_failed() {
            return Poll::Ready(Err(self.go_client_write_error().unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "HTTP/2 output flight failed")
            })));
        }
        // A group may internally flush to regain encoder capacity without
        // completing its owner's flight. Only its owner may seal it before
        // another task waits for completion.
        assert!(!self.go_output.as_ref().is_some_and(|output| output.grouped));
        self.flush(cx)
    }
}

#[must_use]
enum ControlFlow {
    Continue,
    Break,
}

impl<B> Encoder<B>
where
    B: Buf,
{
    fn unset_frame(&mut self) -> ControlFlow {
        // Clear internal buffer
        self.buf.set_position(0);
        self.buf.get_mut().clear();

        // The data frame has been written, so unset it
        match self.next.take() {
            Some(Next::Data(frame)) => {
                self.last_data_frame = Some(frame);
                debug_assert!(self.is_empty());
                ControlFlow::Break
            }
            Some(Next::Continuation(frame)) => {
                // Buffer the continuation frame, then try to write again
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = frame.encode(&mut buf) {
                    self.next = Some(Next::Continuation(continuation));
                }
                ControlFlow::Continue
            }
            None => ControlFlow::Break,
        }
    }

    fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        // Ensure that we have enough capacity to accept the write.
        assert!(self.has_capacity());
        let span = tracing::trace_span!("FramedWrite::buffer", frame = ?item);
        let _e = span.enter();

        tracing::debug!(frame = ?item, "send");

        match item {
            Frame::Data(mut v) => {
                // Ensure that the payload is not greater than the max frame.
                let len = v.payload().remaining();

                if len > self.max_frame_size() {
                    return Err(PayloadTooBig);
                }

                if len >= self.chain_threshold {
                    let head = v.head();

                    // Encode the frame head to the buffer
                    head.encode(len, self.buf.get_mut());

                    if self.buf.get_ref().remaining() < self.chain_threshold {
                        let extra_bytes = self.chain_threshold - self.buf.remaining();
                        self.buf.get_mut().put(v.payload_mut().take(extra_bytes));
                    }

                    // Save the data frame
                    self.next = Some(Next::Data(v));
                } else {
                    v.encode_chunk(self.buf.get_mut());

                    // The chunk has been fully encoded, so there is no need to
                    // keep it around
                    assert_eq!(v.payload().remaining(), 0, "chunk not fully encoded");

                    // Save off the last frame...
                    self.last_data_frame = Some(v);
                }
            }
            Frame::Headers(v) => {
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = v.encode(&mut self.hpack, &mut buf) {
                    self.next = Some(Next::Continuation(continuation));
                }
            }
            Frame::PushPromise(v) => {
                let mut buf = limited_write_buf!(self);
                if let Some(continuation) = v.encode(&mut self.hpack, &mut buf) {
                    self.next = Some(Next::Continuation(continuation));
                }
            }
            Frame::Settings(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded settings");
            }
            Frame::GoAway(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded go_away");
            }
            Frame::Ping(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded ping");
            }
            Frame::WindowUpdate(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded window_update");
            }

            Frame::Priority(_) => {
                /*
                v.encode(self.buf.get_mut());
                tracing::trace!("encoded priority; rem={:?}", self.buf.remaining());
                */
                unimplemented!();
            }
            Frame::Reset(v) => {
                v.encode(self.buf.get_mut());
                tracing::trace!(rem = self.buf.remaining(), "encoded reset");
            }
        }

        Ok(())
    }

    fn has_capacity(&self) -> bool {
        self.next.is_none()
            && (self.buf.get_ref().capacity() - self.buf.get_ref().len()
                >= self.min_buffer_capacity)
    }

    fn is_empty(&self) -> bool {
        match self.next {
            Some(Next::Data(ref frame)) => !frame.payload().has_remaining(),
            _ => !self.buf.has_remaining(),
        }
    }
}

impl<B> Encoder<B> {
    fn max_frame_size(&self) -> usize {
        self.max_frame_size as usize
    }
}

impl<T, B> FramedWrite<T, B> {
    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_fail_write_receipts(&mut self) {
        if let Some(receipt) = self
            .go_output
            .as_ref()
            .and_then(|output| output.receipt.as_ref())
        {
            // Read-side closure can terminate a writer before another write
            // polls the socket. Never leave its externally held receipt live.
            let _ = receipt
                .0
                .compare_exchange(0, 2, Ordering::AcqRel, Ordering::Acquire);
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_buffer_client_preface(&mut self) {
        // Native startup uses one buffered write/flush for the client magic,
        // initial SETTINGS and connection receive-window update. Tracking is
        // enabled only after that startup flush succeeds.
        assert!(self.go_output.is_none());
        assert!(self.encoder.buf.get_ref().is_empty() && self.encoder.next.is_none());
        self.encoder
            .buf
            .get_mut()
            .extend_from_slice(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_enable_client_output(&mut self) {
        if self.go_output.is_none() {
            self.go_output = Some(GoOutput::default());
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_write_receipt(&self) -> Option<GoWriteReceipt> {
        self.go_output.as_ref()?.receipt.clone()
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_write_error(&self) -> Option<io::Error> {
        let error = self.go_output.as_ref()?.error.as_ref()?;
        Some(match error.raw_os_error() {
            Some(code) => io::Error::from_raw_os_error(code),
            None => io::Error::new(error.kind(), GoWriteFailure(error.clone())),
        })
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_begin_write_flight(&mut self) -> Option<GoWriteReceipt> {
        let output = self.go_output.as_mut()?;
        assert!(!output.grouped && (!output.sealed || output.error.is_some()));
        let receipt = GoWriteReceipt::new();
        if output.error.is_some() {
            receipt.0.store(2, Ordering::Release);
        }
        output.receipt = Some(receipt.clone());
        output.grouped = true;
        output.sealed = false;
        Some(receipt)
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_end_write_flight(&mut self) -> Option<GoWriteReceipt> {
        let output = self.go_output.as_mut()?;
        assert!(output.grouped);
        output.grouped = false;
        output.sealed = output.error.is_none();
        output.receipt.clone()
    }

    /// Returns the max frame size that can be sent
    pub fn max_frame_size(&self) -> usize {
        self.encoder.max_frame_size()
    }

    /// Set the peer's max frame size.
    pub fn set_max_frame_size(&mut self, val: usize) {
        assert!(val <= frame::MAX_MAX_FRAME_SIZE as usize);
        self.encoder.max_frame_size = val as FrameSize;
    }

    /// Set the peer's header table size.
    pub fn set_header_table_size(&mut self, val: usize) {
        self.encoder.hpack.update_max_size(val);
    }

    /// Retrieve the last data frame that has been sent
    pub fn take_last_data_frame(&mut self) -> Option<frame::Data<B>> {
        self.encoder.last_data_frame.take()
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }
}

impl<T: AsyncRead + Unpin, B> AsyncRead for FramedWrite<T, B> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// We never project the Pin to `B`.
impl<T: Unpin, B> Unpin for FramedWrite<T, B> {}

#[cfg(feature = "go-client-idle")]
impl<T, B> Drop for FramedWrite<T, B> {
    fn drop(&mut self) {
        self.go_fail_write_receipts();
    }
}

#[cfg(feature = "unstable")]
mod unstable {
    use super::*;

    impl<T, B> FramedWrite<T, B> {
        pub fn get_ref(&self) -> &T {
            &self.inner
        }
    }
}
