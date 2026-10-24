use crate::codec::UserError;
use crate::frame::{Reason, StreamId};
use crate::{client, server};

use crate::frame::DEFAULT_INITIAL_WINDOW_SIZE;
use crate::proto::*;

use bytes::Bytes;
use futures_core::Stream;
#[cfg(any(feature = "go-server-lifecycle", feature = "go-client-idle"))]
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncRead;

/// An H2 connection
#[derive(Debug)]
pub(crate) struct Connection<T, P, B: Buf = Bytes>
where
    P: Peer,
{
    /// Read / write frame values
    codec: Codec<T, Prioritized<B>>,

    inner: ConnectionInner<P, B>,

    #[cfg(feature = "go-server-lifecycle")]
    go_lifecycle: Option<GoServerLifecycle>,
    #[cfg(feature = "go-client-idle")]
    go_client_idle_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    #[cfg(feature = "go-client-idle")]
    go_client_idle_enabled: bool,
    #[cfg(feature = "go-client-idle")]
    go_client_read_barrier: GoClientReadBarrier,
    #[cfg(feature = "go-client-idle")]
    go_body_refund: Option<GoBodyRefundFlight>,
}

#[cfg(feature = "go-client-idle")]
#[derive(Debug)]
struct GoBodyRefundFlight {
    refund: streams::GoBodyRefund,
    prior: Option<crate::codec::GoWriteReceipt>,
    receipt: Option<crate::codec::GoWriteReceipt>,
}

#[cfg(feature = "go-client-idle")]
#[derive(Debug, Default)]
enum GoClientReadBarrier {
    #[default]
    Ready,
    Acquire {
        control: GoClientReadControl,
        prior: Option<crate::codec::GoWriteReceipt>,
    },
    Flush {
        control: GoClientReadControlKind,
        receipt: crate::codec::GoWriteReceipt,
    },
}

#[cfg(feature = "go-client-idle")]
#[derive(Debug)]
enum GoClientReadControl {
    Settings(frame::Settings),
    Pong,
    Refund([Option<frame::WindowUpdate>; 2]),
}

#[cfg(feature = "go-client-idle")]
#[derive(Clone, Copy, Debug)]
enum GoClientReadControlKind {
    Settings,
    Pong,
    Refund,
}

#[cfg(feature = "go-server-lifecycle")]
#[derive(Debug, Default)]
struct GoServerLifecycle {
    stream_generation: Option<u64>,
    stream_deadline: Option<tokio::time::Instant>,
    stream_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    idle_deadline: Option<tokio::time::Instant>,
    idle_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    close_timer: Option<Pin<Box<tokio::time::Sleep>>>,
}

// Extracted part of `Connection` which does not depend on `T`. Reduces the amount of duplicated
// method instantiations.
#[derive(Debug)]
struct ConnectionInner<P, B: Buf = Bytes>
where
    P: Peer,
{
    /// Tracks the connection level state transitions.
    state: State,
    #[cfg(feature = "go-client-idle")]
    go_native_client: bool,

    /// An error to report back once complete.
    ///
    /// This exists separately from State in order to support
    /// graceful shutdown.
    error: Option<frame::GoAway>,

    /// Pending GOAWAY frames to write.
    go_away: GoAway,

    /// A refused stream to reset before receiving another frame.
    pending_refusal: Option<StreamId>,

    /// Ping/pong handler
    ping_pong: PingPong,

    /// Connection settings
    settings: Settings,

    #[cfg(feature = "go-server-first-settings")]
    first_settings_error_stream_id: Option<StreamId>,

    #[cfg(feature = "go-server-graceful-current-id")]
    max_client_stream_id: StreamId,

    #[cfg(feature = "go-server-graceful-current-id")]
    go_native_server: bool,

    /// Stream state handler
    streams: Streams<B, P>,

    /// A `tracing` span tracking the lifetime of the connection.
    span: tracing::Span,

    /// Client or server
    _phantom: PhantomData<P>,
}

struct DynConnection<'a, B: Buf = Bytes> {
    state: &'a mut State,
    #[cfg(feature = "go-client-idle")]
    go_native_client: &'a mut bool,

    go_away: &'a mut GoAway,

    streams: DynStreams<'a, B>,

    error: &'a mut Option<frame::GoAway>,

    ping_pong: &'a mut PingPong,

    #[cfg(feature = "go-server-first-settings")]
    first_settings_error_stream_id: &'a mut Option<StreamId>,

    #[cfg(feature = "go-server-graceful-current-id")]
    max_client_stream_id: &'a mut StreamId,

    #[cfg(feature = "go-server-graceful-current-id")]
    go_native_server: &'a mut bool,
}

#[derive(Debug, Clone)]
pub(crate) struct Config {
    pub next_stream_id: StreamId,
    pub initial_max_send_streams: usize,
    pub max_send_buffer_size: usize,
    pub reset_stream_duration: Duration,
    pub reset_stream_max: usize,
    pub remote_reset_stream_max: usize,
    pub local_error_reset_streams_max: Option<usize>,
    pub settings: frame::Settings,
    pub data_frame_budget: DataFrameBudget,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum DataFrameBudget {
    Auto,
    Configured(usize),
}

impl DataFrameBudget {
    pub(crate) fn resolve(self, connection_window: Option<WindowSize>) -> usize {
        match self {
            Self::Configured(budget) => budget,
            Self::Auto => {
                let window = connection_window.unwrap_or(DEFAULT_INITIAL_WINDOW_SIZE);
                let budget = window as usize / 2;

                budget.max(DEFAULT_DATA_FRAME_BUDGET)
            }
        }
    }

    pub(crate) fn is_auto(self) -> bool {
        matches!(self, Self::Auto)
    }
}

#[derive(Debug)]
enum State {
    /// Currently open in a sane state
    Open,

    /// The codec must be flushed
    Closing(Reason, Initiator),

    /// In a closed state
    Closed(Reason, Initiator),
}

impl<T, P, B> Connection<T, P, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    P: Peer,
    B: Buf,
{
    pub fn new(codec: Codec<T, Prioritized<B>>, config: Config) -> Connection<T, P, B> {
        fn streams_config(config: &Config) -> streams::Config {
            streams::Config {
                initial_max_send_streams: config.initial_max_send_streams,
                local_max_buffer_size: config.max_send_buffer_size,
                local_next_stream_id: config.next_stream_id,
                local_push_enabled: config.settings.is_push_enabled().unwrap_or(true),
                extended_connect_protocol_enabled: config
                    .settings
                    .is_extended_connect_protocol_enabled()
                    .unwrap_or(false),
                local_reset_duration: config.reset_stream_duration,
                local_reset_max: config.reset_stream_max,
                remote_reset_max: config.remote_reset_stream_max,
                remote_init_window_sz: DEFAULT_INITIAL_WINDOW_SIZE,
                remote_max_initiated: config
                    .settings
                    .max_concurrent_streams()
                    .map(|max| max as usize),
                local_max_error_reset_streams: config.local_error_reset_streams_max,
                data_frame_budget: config.data_frame_budget,
            }
        }
        let streams = Streams::new(streams_config(&config));
        let span = tracing::debug_span!(parent: None, "Connection", peer = %P::NAME);
        span.follows_from(tracing::Span::current());
        Connection {
            codec,
            #[cfg(feature = "go-server-lifecycle")]
            go_lifecycle: None,
            #[cfg(feature = "go-client-idle")]
            go_client_idle_timer: None,
            #[cfg(feature = "go-client-idle")]
            go_client_idle_enabled: false,
            #[cfg(feature = "go-client-idle")]
            go_client_read_barrier: GoClientReadBarrier::Ready,
            #[cfg(feature = "go-client-idle")]
            go_body_refund: None,
            inner: ConnectionInner {
                state: State::Open,
                #[cfg(feature = "go-client-idle")]
                go_native_client: false,
                error: None,
                go_away: GoAway::new(),
                pending_refusal: None,
                ping_pong: PingPong::new(),
                settings: Settings::new(config.settings),
                #[cfg(feature = "go-server-first-settings")]
                first_settings_error_stream_id: None,
                #[cfg(feature = "go-server-graceful-current-id")]
                max_client_stream_id: StreamId::ZERO,
                #[cfg(feature = "go-server-graceful-current-id")]
                go_native_server: false,
                streams,
                span,
                _phantom: PhantomData,
            },
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) async fn go_start_native_client(&mut self, timeout: Duration) -> Result<(), Error> {
        self.inner.go_native_client = true;
        self.codec.require_client_first_settings();
        self.inner
            .streams
            .as_dyn()
            .enable_go_native_client_receipts();
        self.inner.streams.configure_go_native_client(timeout);
        // Go initializes/flushed its preface/settings/window update before
        // returning the connection or starting its initial idle timer.
        crate::poll_fn(|cx| self.inner.streams.poll_complete(cx, &mut self.codec)).await?;
        self.codec.go_enable_client_output();
        self.inner.streams.go_client_initialized();
        self.go_client_idle_enabled = true;
        Ok(())
    }

    #[cfg(feature = "go-client-idle")]
    fn poll_go_client_read_barrier(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        loop {
            match &self.go_client_read_barrier {
                GoClientReadBarrier::Ready => return Poll::Ready(Ok(())),
                GoClientReadBarrier::Acquire { prior, .. } => {
                    let prior = prior.clone();
                    // Body.Read may already own the writer independently of
                    // the read loop; finish that captured operation first.
                    ready!(self.poll_go_body_refund(cx, false));
                    // A reset flight which already owns wmu finishes before
                    // the reader acquires it. Merely queued resets wait.
                    if self.inner.streams.go_client_reset_is_active() {
                        ready!(self
                            .inner
                            .streams
                            .poll_go_client_reset_flight(cx, &mut self.codec))?;
                    }
                    if let Some(receipt) = &prior {
                        // Acquiring wmu observes a terminal prior writer; its
                        // sticky failure does not skip SETTINGS application.
                        let _ = ready!(self.codec.go_flush_through(cx, receipt));
                    }
                }
                GoClientReadBarrier::Flush { control, receipt } => {
                    let result = ready!(self.codec.go_flush_through(cx, receipt));
                    if matches!(control, GoClientReadControlKind::Pong) {
                        result?;
                    }
                    if matches!(control, GoClientReadControlKind::Refund) {
                        self.inner.streams.as_dyn().go_client_recv_flush_completed();
                    }
                    self.inner.streams.go_client_refresh_receipts();
                    self.go_client_read_barrier = GoClientReadBarrier::Ready;
                    return Poll::Ready(Ok(()));
                }
            }
            let GoClientReadBarrier::Acquire { control, .. } =
                std::mem::take(&mut self.go_client_read_barrier)
            else {
                unreachable!();
            };
            let kind = match control {
                GoClientReadControl::Settings(frame) => {
                    if !self.inner.settings.recv_go_client_settings(
                        frame,
                        &mut self.codec,
                        &mut self.inner.streams,
                    )? {
                        return Poll::Ready(Ok(()));
                    }
                    // processSettings ignores both ACK write and flush errors.
                    if self.codec.go_client_write_error().is_some() {
                        return Poll::Ready(Ok(()));
                    }
                    self.codec
                        .buffer(frame::Settings::ack().into())
                        .expect("invalid settings ACK");
                    GoClientReadControlKind::Settings
                }
                GoClientReadControl::Pong => {
                    // Unlike SETTINGS/refunds, Go returns PONG writer errors.
                    if let Some(error) = self.codec.go_client_write_error() {
                        return Poll::Ready(Err(error.into()));
                    }
                    match self
                        .inner
                        .ping_pong
                        .send_pending_pong(cx, &mut self.codec)?
                    {
                        Poll::Ready(()) => {}
                        Poll::Pending => {
                            self.go_client_read_barrier = GoClientReadBarrier::Acquire {
                                control: GoClientReadControl::Pong,
                                prior: self.codec.go_write_receipt(),
                            };
                            return Poll::Pending;
                        }
                    }
                    GoClientReadControlKind::Pong
                }
                GoClientReadControl::Refund(updates) => {
                    // Go also ignores receive-side WINDOW_UPDATE errors, then
                    // makes any terminal DATA available to the response reader.
                    if self.codec.go_client_write_error().is_some() {
                        self.inner.streams.as_dyn().go_client_recv_flush_completed();
                        return Poll::Ready(Ok(()));
                    }
                    let _ = self.codec.go_begin_write_flight();
                    for update in updates.into_iter().flatten() {
                        self.codec
                            .buffer(update.into())
                            .expect("invalid receive refund");
                    }
                    let _ = self.codec.go_end_write_flight();
                    GoClientReadControlKind::Refund
                }
            };
            self.go_client_read_barrier = GoClientReadBarrier::Flush {
                control: kind,
                receipt: self
                    .codec
                    .go_write_receipt()
                    .expect("buffered control has a receipt"),
            };
        }
    }

    #[cfg(feature = "go-client-idle")]
    fn go_client_begin_read_control(&mut self, control: GoClientReadControl) {
        self.go_client_read_barrier = GoClientReadBarrier::Acquire {
            control,
            prior: self.codec.go_write_receipt(),
        };
    }

    #[cfg(feature = "go-client-idle")]
    fn poll_go_body_refund(&mut self, cx: &mut Context<'_>, start: bool) -> Poll<()> {
        if self.go_body_refund.is_none() {
            if !start {
                return Poll::Ready(());
            }
            let Some(refund) = self.inner.streams.take_go_body_refund() else {
                return Poll::Ready(());
            };
            self.go_body_refund = Some(GoBodyRefundFlight {
                refund,
                prior: self.codec.go_write_receipt(),
                receipt: None,
            });
        }
        let flight = self.go_body_refund.as_mut().unwrap();
        if flight.receipt.is_none() {
            if let Some(prior) = &flight.prior {
                let _ = ready!(self.codec.go_flush_through(cx, prior));
            }
            if self.codec.go_client_write_error().is_some() {
                // Body.Read and Close ignore their write/flush errors.
                self.go_body_refund = None;
                cx.waker().wake_by_ref();
                return Poll::Ready(());
            }
            let _ = self.codec.go_begin_write_flight();
            for update in flight.refund.updates.iter_mut().filter_map(Option::take) {
                self.codec.buffer(update.into()).expect("valid body refund");
            }
            flight.receipt = self.codec.go_end_write_flight();
        }
        let receipt = flight.receipt.as_ref().expect("native body refund flight");
        let _ = ready!(self.codec.go_flush_through(cx, receipt));
        // Dropping the owned event completes the caller's read/close gate.
        self.go_body_refund = None;
        self.inner.streams.go_client_refresh_receipts();
        cx.waker().wake_by_ref();
        Poll::Ready(())
    }

    #[cfg(feature = "go-client-idle")]
    fn poll_go_client_completions(&mut self, cx: &mut Context) -> Result<(), Error> {
        if self.go_client_idle_enabled {
            self.inner.streams.go_client_refresh_receipts();
            if matches!(self.go_client_read_barrier, GoClientReadBarrier::Ready) {
                if self
                    .inner
                    .streams
                    .go_client_has_writer_work(self.codec.max_send_frame_size())
                {
                    if let Some(error) = self.codec.go_client_write_error() {
                        let error: Error = error.into();
                        self.inner.streams.as_dyn().handle_error(error.clone());
                        return Err(error);
                    }
                }
                let writer_released = self.go_body_refund.is_none()
                    && !self.inner.streams.go_client_reset_is_active()
                    && self
                        .codec
                        .go_write_receipt()
                        .map_or(true, |receipt| receipt.is_flushed() || receipt.is_failed());
                if writer_released {
                    self.inner.streams.go_client_cleanup_checked();
                }
            }
        }
        let _ = cx;
        Ok(())
    }

    #[cfg(feature = "go-client-idle")]
    fn poll_go_client_idle(&mut self, cx: &mut Context) -> bool {
        if !self.go_client_idle_enabled {
            return false;
        }
        if self.inner.streams.close_go_client_if_unusable_idle() {
            self.go_client_idle_timer = None;
            self.inner.state = State::Closed(Reason::NO_ERROR, Initiator::Library);
            return true;
        }
        let Some(deadline) = self.inner.streams.go_client_idle_deadline(cx) else {
            self.go_client_idle_timer = None;
            return false;
        };
        let timer = self
            .go_client_idle_timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        if timer.deadline() != deadline {
            timer.as_mut().reset(deadline);
        }
        if timer.as_mut().poll(cx).is_pending() {
            return false;
        }
        if !self
            .inner
            .streams
            .close_go_client_if_idle(tokio::time::Instant::now())
        {
            self.go_client_idle_timer = None;
            return false;
        }
        // Client closeIfIdle closes transport without GOAWAY or waiting for
        // a blocked writer; shared state already rejects later admission.
        self.inner.state = State::Closed(Reason::NO_ERROR, Initiator::Library);
        true
    }

    /// connection flow control
    pub(crate) fn set_target_window_size(&mut self, size: WindowSize) {
        let _res = self.inner.streams.set_target_connection_window_size(size);
        // TODO: proper error handling
        debug_assert!(_res.is_ok());
    }

    /// Send a new SETTINGS frame with an updated initial window size.
    pub(crate) fn set_initial_window_size(&mut self, size: WindowSize) -> Result<(), UserError> {
        let mut settings = frame::Settings::default();
        settings.set_initial_window_size(Some(size));
        self.inner.settings.send_settings(settings)
    }

    /// Send a new SETTINGS frame with extended CONNECT protocol enabled.
    pub(crate) fn set_enable_connect_protocol(&mut self) -> Result<(), UserError> {
        let mut settings = frame::Settings::default();
        settings.set_enable_connect_protocol(Some(1));
        self.inner.settings.send_settings(settings)
    }

    /// Returns the maximum number of concurrent streams that may be initiated
    /// by this peer.
    pub(crate) fn max_send_streams(&self) -> usize {
        self.inner.streams.max_send_streams()
    }

    /// Returns the maximum number of concurrent streams that may be initiated
    /// by the remote peer.
    pub(crate) fn max_recv_streams(&self) -> usize {
        self.inner.streams.max_recv_streams()
    }

    #[cfg(feature = "unstable")]
    pub fn num_wired_streams(&self) -> usize {
        self.inner.streams.num_wired_streams()
    }

    /// Returns `Ready` when the connection is ready to receive a frame.
    ///
    /// Returns `Error` as this may raise errors that are caused by delayed
    /// processing of received frames.
    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        let _e = self.inner.span.enter();
        let span = tracing::trace_span!("poll_ready");
        let _e = span.enter();
        #[cfg(feature = "go-server-lifecycle")]
        if self.go_lifecycle.is_some() {
            // Go applies peer settings on receive; its coalesced ACK has
            // priority over queued control replies. Poll every writer so a
            // blocked class does not prevent another from registering work.
            let mut pending = false;
            pending |= self
                .inner
                .settings
                .poll_send(cx, &mut self.codec, &mut self.inner.streams)?
                .is_pending();
            pending |= self
                .inner
                .ping_pong
                .send_pending_pong(cx, &mut self.codec)?
                .is_pending();
            pending |= self
                .inner
                .ping_pong
                .send_pending_ping(cx, &mut self.codec)?
                .is_pending();
            pending |= self
                .inner
                .streams
                .send_pending_refusal(cx, &mut self.codec)?
                .is_pending();
            return if pending {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            };
        }
        // The order of these calls don't really matter too much
        ready!(self.inner.ping_pong.send_pending_pong(cx, &mut self.codec))?;
        ready!(self.inner.ping_pong.send_pending_ping(cx, &mut self.codec))?;
        ready!(self
            .inner
            .settings
            .poll_send(cx, &mut self.codec, &mut self.inner.streams))?;
        if let Some(id) = self.inner.pending_refusal {
            // Keep the refusal pending if making room requires socket progress.
            ready!(self.codec.poll_ready(cx))?;
            self.inner.streams.count_pending_refusal()?;
            self.codec
                .buffer(frame::Reset::new(id, Reason::REFUSED_STREAM).into())
                .expect("invalid RST_STREAM frame");
            self.inner.pending_refusal = None;
        }

        Poll::Ready(Ok(()))
    }

    /// Send any pending GOAWAY frames.
    ///
    /// This will return `Some(reason)` if the connection should be closed
    /// afterwards. If this is a graceful shutdown, this returns `None`.
    fn poll_go_away(&mut self, cx: &mut Context) -> Poll<Option<io::Result<Reason>>> {
        self.inner.go_away.send_pending_go_away(cx, &mut self.codec)
    }

    pub fn go_away_from_user(&mut self, e: Reason) {
        self.inner.as_dyn().go_away_from_user(e)
    }

    fn take_error(&mut self, ours: Reason, initiator: Initiator) -> Result<(), Error> {
        let (debug_data, theirs) = self
            .inner
            .error
            .take()
            .as_ref()
            .map_or((Bytes::new(), Reason::NO_ERROR), |frame| {
                (frame.debug_data().clone(), frame.reason())
            });

        match (ours, theirs) {
            (Reason::NO_ERROR, Reason::NO_ERROR) => Ok(()),
            (ours, Reason::NO_ERROR) => Err(Error::GoAway(Bytes::new(), ours, initiator)),
            // If both sides reported an error, give their
            // error back to th user. We assume our error
            // was a consequence of their error, and less
            // important.
            (_, theirs) => Err(Error::remote_go_away(debug_data, theirs)),
        }
    }

    /// Closes the connection by transitioning to a GOAWAY state
    /// iff there are no streams or references
    pub fn maybe_close_connection_if_no_streams(&mut self) {
        // If we poll() and realize that there are no streams or references
        // then we can close the connection by transitioning to GOAWAY
        if !self.inner.streams.has_streams_or_other_references() {
            self.inner.as_dyn().go_away_now(Reason::NO_ERROR);
        }
    }

    /// Checks if there are any streams
    pub fn has_streams(&self) -> bool {
        self.inner.streams.has_streams()
    }

    /// Checks if there are any streams or references left
    pub fn has_streams_or_other_references(&self) -> bool {
        // If we poll() and realize that there are no streams or references
        // then we can close the connection by transitioning to GOAWAY
        self.inner.streams.has_streams_or_other_references()
    }

    pub(crate) fn take_user_pings(&mut self) -> Option<UserPings> {
        self.inner.ping_pong.take_user_pings()
    }

    /// Advances the internal state of the connection.
    pub fn poll(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        // XXX(eliza): cloning the span is unfortunately necessary here in
        // order to placate the borrow checker — `self` is mutably borrowed by
        // `poll2`, which means that we can't borrow `self.span` to enter it.
        // The clone is just an atomic ref bump.
        let span = self.inner.span.clone();
        let _e = span.enter();
        let span = tracing::trace_span!("poll");
        let _e = span.enter();

        loop {
            #[cfg(feature = "go-client-idle")]
            if !matches!(self.inner.state, State::Closed(..)) {
                self.poll_go_client_completions(cx)?;
            }
            #[cfg(feature = "go-client-idle")]
            if !matches!(self.inner.state, State::Closed(..)) && self.poll_go_client_idle(cx) {
                continue;
            }
            #[cfg(feature = "go-server-lifecycle")]
            if !matches!(self.inner.state, State::Closed(..)) {
                if let Some(reason) = self.poll_go_server_timers(cx)? {
                    // GOAWAY was already flushed before this timer started.
                    // Go closes the transport at expiry instead of waiting
                    // for later queued control writes to become writable.
                    self.inner.state = State::Closed(reason, Initiator::Library);
                }
            }
            tracing::trace!(connection.state = ?self.inner.state);
            // TODO: probably clean up this glob of code
            match self.inner.state {
                // When open, continue to poll a frame
                State::Open => {
                    let result = match self.poll2(cx) {
                        Poll::Ready(result) => result,
                        // The connection is not ready to make progress
                        Poll::Pending => {
                            #[cfg(feature = "go-client-idle")]
                            if self.inner.go_native_client
                                && !matches!(
                                    self.go_client_read_barrier,
                                    GoClientReadBarrier::Ready
                                )
                            {
                                // The received control owns the writer until
                                // its flush completes. Do not append unrelated
                                // stream frames while waiting for that flush.
                                return Poll::Pending;
                            }
                            #[cfg(feature = "go-client-idle")]
                            if self.inner.go_native_client {
                                ready!(self.poll_go_body_refund(cx, false));
                            }
                            // Ensure all window updates have been sent.
                            //
                            // This will also handle flushing `self.codec`
                            #[cfg(feature = "go-client-idle")]
                            let skip_failed_idle_writer = self.inner.go_native_client
                                && self.codec.go_client_write_error().is_some()
                                && !self
                                    .inner
                                    .streams
                                    .go_client_has_writer_work(self.codec.max_send_frame_size());
                            #[cfg(not(feature = "go-client-idle"))]
                            let skip_failed_idle_writer = false;
                            if !skip_failed_idle_writer {
                                #[cfg(feature = "go-client-idle")]
                                if self.inner.go_native_client {
                                    ready!(self
                                        .inner
                                        .streams
                                        .poll_go_client_reset_flight(cx, &mut self.codec))?;
                                    ready!(self.poll_go_body_refund(cx, true));
                                }
                                if let Err(error) =
                                    ready!(self.inner.streams.poll_complete(cx, &mut self.codec))
                                {
                                    #[cfg(feature = "go-client-idle")]
                                    let ignored_credit_error = self.inner.go_native_client
                                        && self.codec.go_client_write_error().is_some()
                                        && !self.inner.streams.go_client_has_writer_work(
                                            self.codec.max_send_frame_size(),
                                        );
                                    #[cfg(not(feature = "go-client-idle"))]
                                    let ignored_credit_error = false;
                                    if !ignored_credit_error {
                                        let error: Error = error.into();
                                        #[cfg(feature = "go-client-idle")]
                                        if self.inner.go_native_client {
                                            self.inner.streams.as_dyn().handle_error(error.clone());
                                        }
                                        return Poll::Ready(Err(error));
                                    }
                                }
                            } else {
                                #[cfg(feature = "go-client-idle")]
                                if self.inner.go_native_client {
                                    ready!(self.poll_go_body_refund(cx, true));
                                }
                            }

                            #[cfg(feature = "go-server-lifecycle")]
                            if let Some(reason) = self.poll_go_server_timers(cx)? {
                                self.inner.state = State::Closed(reason, Initiator::Library);
                                continue;
                            }

                            if (self.inner.error.is_some()
                                || self.inner.go_away.should_close_on_idle())
                                && !self.inner.streams.has_streams()
                            {
                                #[cfg(feature = "go-server-lifecycle")]
                                if self.go_lifecycle.is_some()
                                    && self.inner.go_away.should_close_now()
                                {
                                    // Peer GOAWAY keeps `error` populated.
                                    // Once closing is armed, yield to the
                                    // registered timer instead of rearming in
                                    // an input-pending loop.
                                    return Poll::Pending;
                                }
                                self.inner.as_dyn().go_away_now(Reason::NO_ERROR);
                                continue;
                            }

                            return Poll::Pending;
                        }
                    };

                    #[cfg(any(feature = "go-server-lifecycle", feature = "go-client-idle"))]
                    if matches!(self.inner.state, State::Closed(..)) {
                        continue;
                    }

                    #[cfg(feature = "go-server-first-settings")]
                    {
                        self.inner.first_settings_error_stream_id =
                            self.codec.take_first_settings_error_stream_id();
                    }
                    self.inner.as_dyn().handle_poll2_result(result)?
                }
                State::Closing(reason, initiator) => {
                    tracing::trace!("connection closing after flush");
                    // Flush/shutdown the codec
                    ready!(self.codec.shutdown(cx))?;

                    // Transition the state to error
                    self.inner.state = State::Closed(reason, initiator);
                }
                State::Closed(reason, initiator) => {
                    #[cfg(feature = "go-client-idle")]
                    if self.inner.go_native_client {
                        self.go_body_refund = None;
                        self.inner.streams.abort_go_body_refunds();
                        self.codec.go_fail_write_receipts();
                        self.inner.streams.go_client_refresh_receipts();
                        self.inner.streams.go_client_closed();
                    }
                    return Poll::Ready(self.take_error(reason, initiator));
                }
            }
        }
    }

    fn poll2(&mut self, cx: &mut Context) -> Poll<Result<(), Error>> {
        // This happens outside of the loop to prevent needing to do a clock
        // check and then comparison of the queue possibly multiple times a
        // second (and thus, the clock wouldn't have changed enough to matter).
        self.clear_expired_reset_streams();

        #[cfg(feature = "go-server-lifecycle")]
        let native = self.go_lifecycle.is_some();
        #[cfg(not(feature = "go-server-lifecycle"))]
        let native = false;
        #[cfg(feature = "go-client-idle")]
        let native_client = self.inner.go_native_client;
        #[cfg(not(feature = "go-client-idle"))]
        let native_client = false;
        // Go's reader and writer run independently. Keep this single-task
        // driver cooperative when the peer continuously supplies frames.
        #[cfg(any(feature = "go-server-lifecycle", feature = "go-client-idle"))]
        let mut received = 0;

        loop {
            #[cfg(feature = "go-client-idle")]
            if native_client {
                ready!(self.poll_go_client_read_barrier(cx))?;
            }
            #[cfg(feature = "go-client-idle")]
            self.poll_go_client_completions(cx)?;
            #[cfg(feature = "go-client-idle")]
            if self.poll_go_client_idle(cx) {
                return Poll::Ready(Ok(()));
            }
            #[cfg(feature = "go-server-lifecycle")]
            if let Some(reason) = self.poll_go_server_timers(cx)? {
                self.inner.state = State::Closed(reason, Initiator::Library);
                return Poll::Ready(Ok(()));
            }
            // First, ensure that the `Connection` is able to receive a frame
            //
            // The order here matters:
            // - poll_go_away may buffer a graceful shutdown GOAWAY frame
            // - If it has, we've also added a PING to be sent in poll_ready
            let reason = match self.poll_go_away(cx) {
                Poll::Ready(reason) => reason.transpose()?,
                Poll::Pending if native => None,
                Poll::Pending => return Poll::Pending,
            };
            if let Some(reason) = reason {
                if self.inner.go_away.should_close_now() {
                    #[cfg(feature = "go-server-lifecycle")]
                    let delayed =
                        self.go_lifecycle.is_some() && !self.inner.go_away.is_user_initiated();
                    #[cfg(not(feature = "go-server-lifecycle"))]
                    let delayed = false;
                    if !delayed {
                        if self.inner.go_away.is_user_initiated() {
                            // A user initiated abrupt shutdown shouldn't return
                            // the same error back to the user.
                            return Poll::Ready(Ok(()));
                        } else {
                            return Poll::Ready(Err(Error::library_go_away(reason)));
                        }
                    }
                }
                // Only NO_ERROR should be waiting for idle
                debug_assert!(
                    native || reason == Reason::NO_ERROR,
                    "graceful GOAWAY should be NO_ERROR"
                );
            }
            #[cfg(feature = "go-server-lifecycle")]
            if let Some(reason) = self.poll_go_server_timers(cx)? {
                self.inner.state = State::Closed(reason, Initiator::Library);
                return Poll::Ready(Ok(()));
            }
            match self.poll_ready(cx)? {
                Poll::Pending if !native && !native_client => return Poll::Pending,
                Poll::Pending | Poll::Ready(()) => {}
            }

            match self
                .inner
                .as_dyn()
                .recv_frame(ready!(Pin::new(&mut self.codec).poll_next(cx)?))?
            {
                ReceivedFrame::Settings(frame) => {
                    #[cfg(feature = "go-client-idle")]
                    let frame = if native_client {
                        self.go_client_begin_read_control(GoClientReadControl::Settings(frame));
                        None
                    } else {
                        Some(frame)
                    };
                    #[cfg(not(feature = "go-client-idle"))]
                    let frame = Some(frame);
                    if let Some(frame) = frame {
                        self.inner.settings.recv_settings(
                            frame,
                            &mut self.codec,
                            &mut self.inner.streams,
                        )?;
                    }
                }
                ReceivedFrame::Refused(id) => {
                    #[cfg(feature = "go-server-lifecycle")]
                    let native_server = self.inner.go_native_server;
                    #[cfg(not(feature = "go-server-lifecycle"))]
                    let native_server = false;
                    if native_server {
                        #[cfg(feature = "go-server-lifecycle")]
                        self.inner.streams.as_dyn().go_queue_refusal(id);
                    } else {
                        debug_assert!(self.inner.pending_refusal.is_none());
                        self.inner.pending_refusal = Some(id);
                    }
                }
                ReceivedFrame::Continue => (),
                ReceivedFrame::Done => {
                    return Poll::Ready(Ok(()));
                }
            }
            #[cfg(feature = "go-client-idle")]
            if native_client {
                if self.inner.ping_pong.go_client_pong_pending() {
                    self.go_client_begin_read_control(GoClientReadControl::Pong);
                } else {
                    let updates = self.inner.streams.as_dyn().take_go_client_recv_updates();
                    if updates.iter().any(Option::is_some) {
                        self.go_client_begin_read_control(GoClientReadControl::Refund(updates));
                    }
                }
            }
            #[cfg(feature = "go-server-lifecycle")]
            if native {
                // These are the newly decoupled control queues, not all of
                // Go's writer-scheduler entries. Bound them by Go's 10,000
                // control-frame limit and close without waiting for output.
                let queued = self.inner.settings.go_pending_controls()
                    + self.inner.ping_pong.go_pending_controls()
                    + self.inner.streams.as_dyn().go_pending_controls();
                if queued > 10_000 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "too many control frames in send queue",
                    )
                    .into()));
                }
            }
            #[cfg(any(feature = "go-server-lifecycle", feature = "go-client-idle"))]
            if native || native_client {
                received += 1;
                if received == 32 {
                    // Yield through poll()'s stream-output/flush path; the
                    // read side may remain ready and provide no new wakeup.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
            }
        }
    }

    fn clear_expired_reset_streams(&mut self) {
        self.inner.streams.clear_expired_reset_streams();
    }

    #[cfg(feature = "go-server-lifecycle")]
    fn poll_go_server_timers(&mut self, cx: &mut Context<'_>) -> Result<Option<Reason>, Error> {
        if self.go_lifecycle.is_none() || self.inner.go_away.is_user_initiated() {
            return Ok(None);
        }
        let now = tokio::time::Instant::now();
        let generation = self.inner.streams.as_dyn().go_deadline_generation();
        let lifecycle = self.go_lifecycle.as_ref().unwrap();
        let changed = lifecycle.stream_generation != Some(generation);
        let due = lifecycle
            .stream_deadline
            .map_or(false, |deadline| deadline <= now);
        if changed || due {
            let (generation, deadline) = self.inner.streams.as_dyn().expire_go_stream_timeouts(now);
            let lifecycle = self.go_lifecycle.as_mut().unwrap();
            lifecycle.stream_generation = Some(generation);
            if lifecycle.stream_deadline != deadline {
                lifecycle.stream_deadline = deadline;
                lifecycle.stream_timer =
                    deadline.map(|deadline| Box::pin(tokio::time::sleep_until(deadline)));
            }
        }
        {
            let lifecycle = self.go_lifecycle.as_mut().unwrap();
            if lifecycle
                .stream_timer
                .as_mut()
                .map_or(false, |timer| timer.as_mut().poll(cx).is_ready())
            {
                cx.waker().wake_by_ref();
            }
        }
        let deadline = if self.inner.go_away.is_going_away() {
            None
        } else {
            self.inner.streams.as_dyn().go_idle_deadline()
        };
        let idle_expired = {
            let lifecycle = self.go_lifecycle.as_mut().unwrap();
            if lifecycle.idle_deadline != deadline {
                lifecycle.idle_deadline = deadline;
                lifecycle.idle_timer =
                    deadline.map(|deadline| Box::pin(tokio::time::sleep_until(deadline)));
            }
            lifecycle
                .idle_timer
                .as_mut()
                .map_or(false, |timer| timer.as_mut().poll(cx).is_ready())
        };
        if idle_expired {
            self.inner.streams.as_dyn().stop_go_idle();
            let id = self.inner.max_client_stream_id;
            self.inner.as_dyn().go_away(id, Reason::NO_ERROR);
        }
        let Some(going_away) = self.inner.go_away.going_away() else {
            return Ok(None);
        };
        let reason = going_away.reason();
        let lifecycle = self.go_lifecycle.as_mut().unwrap();
        if let Some(timer) = &mut lifecycle.close_timer {
            return Ok(timer.as_mut().poll(cx).is_ready().then_some(reason));
        }
        if !self.inner.go_away.has_pending_frame()
            && (reason != Reason::NO_ERROR
                || (!self.inner.streams.has_streams()
                    && self.inner.streams.as_dyn().is_buffer_empty()))
        {
            // Start only after GOAWAY and preceding writes reach the transport.
            // A pending write must not prevent reads or an already armed timer.
            match self.codec.flush(cx) {
                Poll::Ready(Ok(())) => {
                    let mut timer = Box::pin(tokio::time::sleep(Duration::from_secs(1)));
                    let _ = timer.as_mut().poll(cx);
                    lifecycle.close_timer = Some(timer);
                }
                Poll::Ready(Err(error)) => return Err(error.into()),
                Poll::Pending => {}
            }
        }
        Ok(None)
    }
}

impl<P, B> ConnectionInner<P, B>
where
    P: Peer,
    B: Buf,
{
    fn as_dyn(&mut self) -> DynConnection<'_, B> {
        let ConnectionInner {
            state,
            #[cfg(feature = "go-client-idle")]
            go_native_client,
            go_away,
            streams,
            error,
            ping_pong,
            #[cfg(feature = "go-server-first-settings")]
            first_settings_error_stream_id,
            #[cfg(feature = "go-server-graceful-current-id")]
            max_client_stream_id,
            #[cfg(feature = "go-server-graceful-current-id")]
            go_native_server,
            ..
        } = self;
        let streams = streams.as_dyn();
        DynConnection {
            state,
            #[cfg(feature = "go-client-idle")]
            go_native_client,
            go_away,
            streams,
            error,
            ping_pong,
            #[cfg(feature = "go-server-first-settings")]
            first_settings_error_stream_id,
            #[cfg(feature = "go-server-graceful-current-id")]
            max_client_stream_id,
            #[cfg(feature = "go-server-graceful-current-id")]
            go_native_server,
        }
    }
}

impl<B> DynConnection<'_, B>
where
    B: Buf,
{
    fn go_away(&mut self, id: StreamId, e: Reason) {
        let frame = frame::GoAway::new(id, e);
        self.streams.send_go_away(id);
        self.go_away.go_away(frame);
    }

    fn go_away_now(&mut self, e: Reason) {
        #[cfg(feature = "go-server-graceful-current-id")]
        let e = if *self.go_native_server {
            self.go_away
                .going_away()
                .filter(|previous| previous.reason() != Reason::NO_ERROR)
                .map_or(e, |previous| previous.reason())
        } else {
            e
        };
        let last_processed_id = self.streams.last_processed_id();
        #[cfg(feature = "go-server-graceful-current-id")]
        let last_processed_id = if *self.go_native_server {
            // Closing the now-idle graceful connection must not send a
            // second, lower-ID GOAWAY after a refused HEADERS frame.
            self.go_away
                .going_away()
                .map_or(last_processed_id, |previous| previous.last_stream_id())
        } else {
            last_processed_id
        };
        let frame = frame::GoAway::new(last_processed_id, e);
        self.go_away.go_away_now(frame);
    }

    fn go_away_now_data(&mut self, e: Reason, data: Bytes) {
        #[cfg(not(feature = "go-server-first-settings"))]
        let last_processed_id = self.streams.last_processed_id();
        #[cfg(feature = "go-server-first-settings")]
        let last_processed_id = if let Some(id) = self.first_settings_error_stream_id.take() {
            // A subsequent GOAWAY cannot increase its advertised stream ID.
            self.go_away
                .going_away()
                .map_or(id, |previous| id.min(previous.last_stream_id()))
        } else {
            self.streams.last_processed_id()
        };
        let frame = frame::GoAway::with_debug_data(last_processed_id, e, data);
        self.go_away.go_away_now(frame);
    }

    fn go_away_from_user(&mut self, e: Reason) {
        let last_processed_id = self.streams.last_processed_id();
        let frame = frame::GoAway::new(last_processed_id, e);
        self.go_away.go_away_from_user(frame);

        // Notify all streams of reason we're abruptly closing.
        self.streams.handle_error(Error::user_go_away(e));
    }

    fn handle_poll2_result(&mut self, result: Result<(), Error>) -> Result<(), Error> {
        match result {
            // The connection has shutdown normally
            Ok(()) => {
                *self.state = State::Closing(Reason::NO_ERROR, Initiator::Library);
                Ok(())
            }
            // Attempting to read a frame resulted in a connection level
            // error. This is handled by setting a GOAWAY frame followed by
            // terminating the connection.
            Err(Error::GoAway(debug_data, reason, initiator)) => {
                self.handle_go_away(reason, debug_data, initiator);
                Ok(())
            }
            // Attempting to read a frame resulted in a stream level error.
            // Locally detected stream errors are reported to the peer with
            // RST_STREAM. Remotely initiated resets have already been applied
            // by the streams state machine and must not be echoed back.
            Err(Error::Reset(id, reason, initiator)) => {
                #[cfg(feature = "go-client-idle")]
                if *self.go_native_client {
                    self.streams.go_client_received_stream_frame(id, false);
                }
                if initiator == Initiator::Remote {
                    tracing::trace!(?id, ?reason, ?initiator, "stream reset");
                    return Ok(());
                }

                debug_assert_eq!(initiator, Initiator::Library);
                tracing::trace!(?id, ?reason, ?initiator, "stream error");
                match self.streams.send_reset(id, reason) {
                    Ok(()) => (),
                    Err(crate::proto::error::GoAway { debug_data, reason }) => {
                        self.handle_go_away(reason, debug_data, Initiator::Library);
                    }
                }
                Ok(())
            }
            // Attempting to read a frame resulted in an I/O error. All
            // active streams must be reset.
            //
            // TODO: Are I/O errors recoverable?
            Err(Error::Io(kind, inner)) => {
                tracing::debug!(error = ?kind, "Connection::poll; IO error");
                let e = Error::Io(kind, inner);

                // Reset all active streams
                self.streams.handle_error(e.clone());

                // Some client implementations drop the connections without notifying its peer
                // Attempting to read after the client dropped the connection results in UnexpectedEof
                // If as a server, we don't have anything more to send, just close the connection
                // without error
                //
                // See https://github.com/hyperium/hyper/issues/3427
                if self.streams.is_buffer_empty()
                    && matches!(kind, io::ErrorKind::UnexpectedEof)
                    && (self.streams.is_server()
                        || self.error.as_ref().map(|f| f.reason() == Reason::NO_ERROR)
                            == Some(true))
                {
                    *self.state = State::Closed(Reason::NO_ERROR, Initiator::Library);
                    return Ok(());
                }

                // Return the error
                Err(e)
            }
        }
    }

    fn handle_go_away(&mut self, reason: Reason, debug_data: Bytes, initiator: Initiator) {
        let e = Error::GoAway(debug_data.clone(), reason, initiator);
        tracing::debug!(error = ?e, "Connection::poll; connection error");

        // We may have already sent a GOAWAY for this error,
        // if so, don't send another, just flush and close up.
        if self
            .go_away
            .going_away()
            .map_or(false, |frame| frame.reason() == reason)
        {
            tracing::trace!("    -> already going away");
            #[cfg(feature = "go-server-lifecycle")]
            if *self.go_native_server {
                return;
            }
            *self.state = State::Closing(reason, initiator);
            return;
        }

        // Reset all active streams
        self.streams.handle_error(e);
        self.go_away_now_data(reason, debug_data);
    }

    fn recv_frame(&mut self, frame: Option<Frame>) -> Result<ReceivedFrame, Error> {
        use crate::frame::Frame::*;
        #[cfg(feature = "go-server-lifecycle")]
        if *self.go_native_server
            && self
                .go_away
                .going_away()
                .map_or(false, |previous| previous.reason() != Reason::NO_ERROR)
        {
            return match frame {
                Some(Data(frame)) => {
                    self.streams.ignore_goaway_data(frame)?;
                    Ok(ReceivedFrame::Continue)
                }
                Some(_) => Ok(ReceivedFrame::Continue),
                None => {
                    self.streams.recv_eof(false).expect("mutex poisoned");
                    Ok(ReceivedFrame::Done)
                }
            };
        }
        #[cfg(feature = "go-server-graceful-current-id")]
        if *self.go_native_server {
            if let Some(previous) = self.go_away.going_away() {
                if previous.reason() == Reason::NO_ERROR {
                    let id = match &frame {
                        Some(Headers(frame)) => frame.stream_id(),
                        Some(Reset(frame)) => frame.stream_id(),
                        Some(PushPromise(frame)) => frame.stream_id(),
                        Some(WindowUpdate(frame)) => frame.stream_id(),
                        Some(Priority(frame)) => frame.stream_id(),
                        // DATA uses the existing stream receive ceiling so
                        // discarded bytes still return connection credit.
                        _ => StreamId::ZERO,
                    };
                    if id > previous.last_stream_id() {
                        return Ok(ReceivedFrame::Continue);
                    }
                }
            }
        }
        match frame {
            Some(Headers(frame)) => {
                tracing::trace!(?frame, "recv HEADERS");
                #[cfg(feature = "go-client-idle")]
                if *self.go_native_client {
                    self.streams
                        .go_client_received_stream_frame(frame.stream_id(), true);
                }
                #[cfg(feature = "go-server-graceful-current-id")]
                if *self.go_native_server
                    && frame.stream_id().is_client_initiated()
                    && frame.stream_id() > *self.max_client_stream_id
                {
                    // Go advances this before concurrency/refusal handling,
                    // rather than only after accepting a new stream.
                    *self.max_client_stream_id = frame.stream_id();
                    #[cfg(feature = "go-server-lifecycle")]
                    self.streams.stop_go_idle();
                }
                match self.streams.recv_headers(frame)? {
                    streams::RecvOutcome::Processed => (),
                    streams::RecvOutcome::Refused(id) => return Ok(ReceivedFrame::Refused(id)),
                }
            }
            Some(Data(frame)) => {
                tracing::trace!(?frame, "recv DATA");
                #[cfg(feature = "go-client-idle")]
                if *self.go_native_client {
                    self.streams
                        .go_client_received_stream_frame(frame.stream_id(), true);
                }
                self.streams.recv_data(frame)?;
            }
            Some(Reset(frame)) => {
                tracing::trace!(?frame, "recv RST_STREAM");
                #[cfg(feature = "go-client-idle")]
                if *self.go_native_client {
                    self.streams
                        .go_client_received_stream_frame(frame.stream_id(), false);
                }
                self.streams.recv_reset(frame)?;
            }
            Some(PushPromise(frame)) => {
                tracing::trace!(?frame, "recv PUSH_PROMISE");
                match self.streams.recv_push_promise(frame)? {
                    streams::RecvOutcome::Processed => (),
                    streams::RecvOutcome::Refused(id) => return Ok(ReceivedFrame::Refused(id)),
                }
            }
            Some(Settings(frame)) => {
                tracing::trace!(?frame, "recv SETTINGS");
                return Ok(ReceivedFrame::Settings(frame));
            }
            Some(GoAway(frame)) => {
                tracing::trace!(?frame, "recv GOAWAY");
                #[cfg(feature = "go-client-idle")]
                if *self.go_native_client {
                    self.streams.go_client_received_goaway();
                }
                // This should prevent starting new streams,
                // but should allow continuing to process current streams
                // until they are all EOS. Once they are, State should
                // transition to GoAway.
                self.streams.recv_go_away(&frame)?;
                #[cfg(feature = "go-server-graceful-current-id")]
                if *self.go_native_server && !self.go_away.is_going_away() {
                    let id = *self.max_client_stream_id;
                    self.go_away(id, Reason::NO_ERROR);
                }
                *self.error = Some(frame);
            }
            Some(Ping(frame)) => {
                tracing::trace!(?frame, "recv PING");
                #[cfg(feature = "go-client-idle")]
                if *self.go_native_client && frame.is_ack() {
                    self.streams.go_client_received_ping_ack();
                }
                let status = self.ping_pong.recv_ping(frame);
                if status.is_shutdown() {
                    assert!(
                        self.go_away.is_going_away(),
                        "received unexpected shutdown ping"
                    );

                    let last_processed_id = self.streams.last_processed_id();
                    self.go_away(last_processed_id, Reason::NO_ERROR);
                }
            }
            Some(WindowUpdate(frame)) => {
                tracing::trace!(?frame, "recv WINDOW_UPDATE");
                #[cfg(feature = "go-client-idle")]
                if *self.go_native_client && frame.stream_id() != StreamId::ZERO {
                    self.streams
                        .go_client_received_stream_frame(frame.stream_id(), false);
                }
                self.streams.recv_window_update(frame)?;
            }
            Some(Priority(frame)) => {
                tracing::trace!(?frame, "recv PRIORITY");
                // TODO: handle
            }
            None => {
                tracing::trace!("codec closed");
                self.streams.recv_eof(false).expect("mutex poisoned");
                #[cfg(feature = "go-client-idle")]
                if *self.go_native_client {
                    // Go's client read-loop cleanup closes the transport on
                    // EOF; do not wait for a blocked writer to shut down.
                    *self.state = State::Closed(Reason::NO_ERROR, Initiator::Library);
                }
                return Ok(ReceivedFrame::Done);
            }
        }
        Ok(ReceivedFrame::Continue)
    }
}

enum ReceivedFrame {
    Refused(StreamId),
    Settings(frame::Settings),
    Continue,
    Done,
}

impl<T, B> Connection<T, client::Peer, B>
where
    T: AsyncRead + AsyncWrite,
    B: Buf,
{
    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_fail_write_receipts(&mut self) {
        if self.inner.go_native_client {
            self.go_body_refund = None;
            self.inner.streams.abort_go_body_refunds();
            self.codec.go_fail_write_receipts();
            self.inner.streams.go_client_refresh_receipts();
        }
    }

    pub(crate) fn streams(&self) -> &Streams<B, client::Peer> {
        &self.inner.streams
    }
}

impl<T, B> Connection<T, server::Peer, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    B: Buf,
{
    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn go_native_server(&mut self, idle_timeout: Option<Duration>) {
        self.inner.go_native_server = true;
        self.go_lifecycle = Some(GoServerLifecycle::default());
        self.inner.settings.enable_go_native();
        self.inner.ping_pong.enable_go_native();
        self.inner.streams.as_dyn().enable_go_native_controls();
        self.inner.streams.as_dyn().configure_go_idle(idle_timeout);
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn go_stream_timeouts(&mut self, read: Option<Duration>, write: Option<Duration>) {
        self.inner
            .streams
            .as_dyn()
            .configure_go_stream_timeouts(read, write);
    }

    pub fn next_incoming(&mut self) -> Option<StreamRef<B>> {
        self.inner.streams.next_incoming()
    }

    // Graceful shutdown only makes sense for server peers.
    pub fn go_away_gracefully(&mut self) {
        if self.inner.go_away.is_going_away() {
            // No reason to start a new one.
            return;
        }

        #[cfg(feature = "go-server-graceful-current-id")]
        if self.inner.go_native_server {
            let id = self.inner.max_client_stream_id;
            self.inner.as_dyn().go_away(id, Reason::NO_ERROR);
            return;
        }

        {
            // According to http://httpwg.org/specs/rfc7540.html#GOAWAY:
            //
            // > A server that is attempting to gracefully shut down a connection
            // > SHOULD send an initial GOAWAY frame with the last stream
            // > identifier set to 2^31-1 and a NO_ERROR code. This signals to the
            // > client that a shutdown is imminent and that initiating further
            // > requests is prohibited. After allowing time for any in-flight
            // > stream creation (at least one round-trip time), the server can
            // > send another GOAWAY frame with an updated last stream identifier.
            // > This ensures that a connection can be cleanly shut down without
            // > losing requests.
            self.inner.as_dyn().go_away(StreamId::MAX, Reason::NO_ERROR);

            // We take the advice of waiting 1 RTT literally, and wait
            // for a pong before proceeding.
            self.inner.ping_pong.ping_shutdown();
        }
    }
}

impl<T, P, B> Drop for Connection<T, P, B>
where
    P: Peer,
    B: Buf,
{
    fn drop(&mut self) {
        // Ignore errors as this indicates that the mutex is poisoned.
        let _ = self.inner.streams.recv_eof(true);
        #[cfg(feature = "go-client-idle")]
        if self.inner.go_native_client {
            self.inner.streams.go_client_closed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_data_frame_budget_scales_with_connection_window() {
        assert_eq!(
            DataFrameBudget::Auto.resolve(None),
            DEFAULT_INITIAL_WINDOW_SIZE as usize / 2
        );
        assert_eq!(
            DataFrameBudget::Auto.resolve(Some(DEFAULT_INITIAL_WINDOW_SIZE)),
            DEFAULT_INITIAL_WINDOW_SIZE as usize / 2
        );
        assert_eq!(DataFrameBudget::Auto.resolve(Some(1024 * 1024)), 512 * 1024);
    }

    #[test]
    fn auto_data_frame_budget_has_minimum() {
        assert_eq!(
            DataFrameBudget::Auto.resolve(Some(1)),
            DEFAULT_DATA_FRAME_BUDGET
        );
        assert_eq!(
            DataFrameBudget::Auto.resolve(Some(MAX_WINDOW_SIZE)),
            MAX_WINDOW_SIZE as usize / 2
        );
    }

    #[test]
    fn configured_data_frame_budget_is_unchanged() {
        assert_eq!(
            DataFrameBudget::Configured(123).resolve(Some(MAX_WINDOW_SIZE)),
            123
        );
    }
}
