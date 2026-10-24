use super::recv::RecvHeaderBlockError;
use super::store::{self, Entry, Resolve, Store};
use super::{Buffer, BufferStatus, Config, Counts, Prioritized, Recv, Send, Stream, StreamId};
use crate::codec::{Codec, SendError, UserError};
use crate::ext::Protocol;
use crate::frame::{self, Frame, Reason};
use crate::proto::{peer, Error, Initiator, Open, Peer, WindowSize};
use crate::{client, proto, server};

use bytes::{Buf, Bytes};
use http::{HeaderMap, Request, Response};
use std::task::{Context, Poll, Waker};
#[cfg(any(feature = "go-server-lifecycle", feature = "go-client-idle"))]
use std::time::Duration;
use tokio::io::AsyncWrite;

use std::sync::{Arc, Mutex};
use std::{fmt, io};

#[derive(Debug)]
pub(crate) struct Streams<B, P>
where
    P: Peer,
{
    /// Holds most of the connection and stream related state for processing
    /// HTTP/2 frames associated with streams.
    inner: Arc<Mutex<Inner>>,

    /// This is the queue of frames to be written to the wire. This is split out
    /// to avoid requiring a `B` generic on all public API types even if `B` is
    /// not technically required.
    ///
    /// Currently, splitting this out requires a second `Arc` + `Mutex`.
    /// However, it should be possible to avoid this duplication with a little
    /// bit of unsafe code. This optimization has been postponed until it has
    /// been shown to be necessary.
    send_buffer: Arc<SendBuffer<B>>,

    _p: ::std::marker::PhantomData<P>,
}

// Like `Streams` but with a `peer::Dyn` field instead of a static `P: Peer` type parameter.
// Ensures that the methods only get one instantiation, instead of two (client and server)
#[derive(Debug)]
pub(crate) struct DynStreams<'a, B> {
    inner: &'a Mutex<Inner>,

    send_buffer: &'a SendBuffer<B>,

    peer: peer::Dyn,
}

/// Outcome of receiving a frame that can open a stream.
#[derive(Debug)]
#[must_use = "a refused stream must be reset by the connection"]
pub(crate) enum RecvOutcome {
    /// The frame was handled, including any intentional ignoring of it.
    Processed,
    /// The connection must send REFUSED_STREAM for this stream ID.
    Refused(StreamId),
}

/// Reference to the stream state
#[derive(Debug)]
pub(crate) struct StreamRef<B> {
    opaque: OpaqueStreamRef,
    send_buffer: Arc<SendBuffer<B>>,
}

/// Reference to the stream state that hides the send data chunk generic
pub(crate) struct OpaqueStreamRef {
    inner: Arc<Mutex<Inner>>,
    key: store::Key,
}

/// Fields needed to manage state related to managing the set of streams. This
/// is mostly split out to make ownership happy.
///
/// TODO: better name
#[derive(Debug)]
struct Inner {
    /// Tracks send & recv stream concurrency.
    counts: Counts,

    /// Connection level state and performs actions on streams
    actions: Actions,

    /// Stores stream state
    store: Store,

    /// The number of stream refs to this shared state.
    refs: usize,
}

#[derive(Debug)]
struct Actions {
    /// Manages state transitions initiated by receiving frames
    recv: Recv,

    /// Manages state transitions initiated by sending frames
    send: Send,

    /// Task that calls `poll_complete`.
    task: Option<Waker>,

    /// If the connection errors, a copy is kept for any StreamRefs.
    conn_error: Option<proto::Error>,
}

/// Contains the buffer of frames to be written to the wire.
#[derive(Debug)]
struct SendBuffer<B> {
    inner: Mutex<Buffer<Frame<B>>>,
}

// A queued native request owns no stream ID. Once admitted its queue entry
// transfers to the initial header flight until that writer releases reqHeaderMu.
#[cfg(feature = "go-client-idle")]
#[derive(Debug)]
pub(crate) struct GoHeaderAdmission {
    inner: std::sync::Weak<Mutex<Inner>>,
    key: Arc<()>,
    registered: bool,
}

#[cfg(feature = "go-client-idle")]
impl Drop for GoHeaderAdmission {
    fn drop(&mut self) {
        if !self.registered {
            return;
        }
        if let Some(inner) = self.inner.upgrade() {
            let mut inner = inner.lock().unwrap();
            if let Some(idle) = inner.counts.go_client_idle.as_mut() {
                if let Some(position) = idle
                    .header_waiters
                    .iter()
                    .position(|waiter| Arc::ptr_eq(&waiter.key, &self.key))
                {
                    idle.header_waiters.remove(position);
                    if position == 0 {
                        if let Some(next) = idle.header_waiters.front() {
                            next.waker.wake_by_ref();
                        }
                    }
                }
            }
        }
    }
}

// ===== impl Streams =====

// A reservation is shared by extension clones, but releases its one slot only
// once. No socket work or generic send-buffer access occurs in Drop.
#[cfg(feature = "go-client-idle")]
#[derive(Clone, Debug)]
pub(crate) struct GoClientIdleHandle(Arc<Mutex<Inner>>);

#[cfg(feature = "go-client-idle")]
#[derive(Clone, Debug)]
pub(crate) struct GoClientIdleReservation(Arc<GoClientReservation>);

#[cfg(feature = "go-client-idle")]
#[derive(Debug)]
struct GoClientReservation {
    inner: std::sync::Weak<Mutex<Inner>>,
    live: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "go-client-idle")]
impl GoClientIdleHandle {
    pub(crate) fn is_closed(&self) -> bool {
        self.availability() == crate::client::GoAvailability::Unusable
    }
    pub(crate) fn availability(&self) -> crate::client::GoAvailability {
        self.0.lock().unwrap().go_client_availability()
    }
    pub(crate) fn connection_state(&self) -> Arc<super::client_state::GoLifecycle> {
        self.0
            .lock()
            .unwrap()
            .counts
            .go_client_idle
            .as_ref()
            .unwrap()
            .lifecycle
            .clone()
    }
    pub(crate) fn try_reserve(
        &self,
    ) -> Result<GoClientIdleReservation, crate::client::GoAvailability> {
        let mut locked = self.0.lock().unwrap();
        let available = locked.go_client_availability();
        if available != crate::client::GoAvailability::Available {
            return Err(available);
        }
        let idle = locked.counts.go_client_idle.as_mut().unwrap();
        idle.reserved = idle
            .reserved
            .checked_add(1)
            .ok_or(crate::client::GoAvailability::Saturated)?;
        Ok(GoClientIdleReservation(Arc::new(GoClientReservation {
            inner: Arc::downgrade(&self.0),
            live: std::sync::atomic::AtomicBool::new(true),
        })))
    }
}

#[cfg(feature = "go-client-idle")]
impl GoClientIdleReservation {
    pub(crate) fn is_unestablished(&self) -> bool {
        if !self.0.live.load(std::sync::atomic::Ordering::Acquire) {
            return false;
        }
        let Some(inner) = self.0.inner.upgrade() else {
            return false;
        };
        let unestablished = inner.lock().unwrap().go_client_reportable_closed();
        unestablished
    }

    fn belongs_to(&self, inner: &Arc<Mutex<Inner>>) -> bool {
        self.0.inner.ptr_eq(&Arc::downgrade(inner))
    }

    fn consume(&self, inner: &mut Inner) {
        if self.0.live.swap(false, std::sync::atomic::Ordering::AcqRel) {
            if let Some(idle) = inner.counts.go_client_idle.as_mut() {
                debug_assert!(idle.reserved > 0);
                idle.reserved -= 1;
            }
        }
    }
}

#[cfg(feature = "go-client-idle")]
impl Drop for GoClientReservation {
    fn drop(&mut self) {
        if !self.live.swap(false, std::sync::atomic::Ordering::AcqRel) {
            return;
        }
        if let Some(inner) = self.inner.upgrade() {
            let mut inner = inner.lock().unwrap();
            if let Some(idle) = inner.counts.go_client_idle.as_mut() {
                debug_assert!(idle.reserved > 0);
                idle.reserved -= 1;
            }
            if let Some(task) = inner.actions.task.take() {
                task.wake();
            }
        }
    }
}

impl<B, P> Streams<B, P>
where
    B: Buf,
    P: Peer,
{
    pub fn new(config: Config) -> Self {
        let peer = P::r#dyn();

        Streams {
            inner: Inner::new(peer, config),
            send_buffer: Arc::new(SendBuffer::new()),
            _p: ::std::marker::PhantomData,
        }
    }

    pub fn set_target_connection_window_size(&mut self, size: WindowSize) -> Result<(), Reason> {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        me.actions
            .recv
            .set_target_connection_window(size, &mut me.actions.task)?;
        me.counts.set_target_connection_window_size(size);
        Ok(())
    }

    pub fn next_incoming(&mut self) -> Option<StreamRef<B>> {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;
        me.actions.recv.next_incoming(&mut me.store).map(|key| {
            let stream = &mut me.store.resolve(key);
            tracing::trace!(
                "next_incoming; id={:?}, state={:?}",
                stream.id,
                stream.state
            );
            // TODO: ideally, OpaqueStreamRefs::new would do this, but we're holding
            // the lock, so it can't.
            me.refs += 1;

            // Pending-accepted remotely-reset streams are counted.
            if stream.state.is_remote_reset() {
                me.counts.dec_num_remote_reset_streams();
            }

            StreamRef {
                opaque: OpaqueStreamRef::new(self.inner.clone(), stream),
                send_buffer: self.send_buffer.clone(),
            }
        })
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub fn send_pending_refusal<T>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, Prioritized<B>>,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
    {
        loop {
            let status = self
                .inner
                .lock()
                .unwrap()
                .actions
                .recv
                .send_pending_refusal(dst)?;
            match status {
                BufferStatus::Complete => return Poll::Ready(Ok(())),
                BufferStatus::CodecFull => ready!(dst.poll_ready(cx))?,
            }
        }
    }

    /// Count a refused stream toward the local error reset limit.
    pub fn count_pending_refusal(&mut self) -> Result<(), Error> {
        let mut me = self.inner.lock().unwrap();
        if !me.counts.can_inc_num_local_error_resets() {
            return Err(Error::library_go_away_data(
                Reason::ENHANCE_YOUR_CALM,
                "too_many_internal_resets",
            ));
        }
        me.counts.inc_num_local_error_resets();
        Ok(())
    }

    pub fn clear_expired_reset_streams(&mut self) {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;
        me.actions
            .recv
            .clear_expired_reset_streams(&mut me.store, &mut me.counts);
    }

    pub fn poll_complete<T>(
        &mut self,
        cx: &mut Context,
        dst: &mut Codec<T, Prioritized<B>>,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
    {
        loop {
            // Make any required socket progress before taking stream locks.
            ready!(dst.poll_ready(cx))?;

            let status = {
                let mut me = self.inner.lock().unwrap();
                #[cfg(feature = "go-client-idle")]
                {
                    me.counts.go_client_refresh_receipts();
                    // poll_ready just released the previous writer with no
                    // cached failure. Cleanup can acquire wmu before the next
                    // queued output flight starts.
                    me.counts.go_client_cleanup_checked();
                }
                let status = me.buffer_pending(&self.send_buffer, dst)?;

                // Register the task while holding the same lock used to
                // observe that all pending frames have been buffered. A
                // producer that queues another frame while the codec is being
                // flushed will then take and wake this task.
                if status == BufferStatus::Complete {
                    me.actions.task = Some(cx.waker().clone());
                }

                status
            };

            match status {
                BufferStatus::Complete => {}
                BufferStatus::CodecFull => continue,
            }

            // Flush any frames staged by `buffer_pending` without holding the
            // stream-state or send-buffer mutexes.
            ready!(dst.flush(cx))?;
            let reclaimed = {
                let mut me = self.inner.lock().unwrap();
                #[cfg(feature = "go-client-idle")]
                me.counts.go_client_flush_completed();
                me.reclaim_written_frame(&self.send_buffer, dst)
            };

            if !reclaimed {
                return Poll::Ready(Ok(()));
            }
        }
    }

    pub fn apply_remote_settings(
        &mut self,
        frame: &frame::Settings,
        is_initial: bool,
    ) -> Result<(), Error> {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        let mut send_buffer = self.send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        me.counts.apply_remote_settings(frame, is_initial);

        me.actions.send.apply_remote_settings(
            frame,
            send_buffer,
            &mut me.store,
            &mut me.counts,
            &mut me.actions.task,
        )
    }

    pub fn apply_local_settings(&mut self, frame: &frame::Settings) -> Result<(), Error> {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        me.actions.recv.apply_local_settings(frame, &mut me.store)
    }

    pub fn send_request(
        &mut self,
        mut request: Request<()>,
        end_of_stream: bool,
        pending: Option<&OpaqueStreamRef>,
    ) -> Result<(StreamRef<B>, bool), SendError> {
        #[cfg(feature = "go-client-idle")]
        let reservation = request
            .extensions_mut()
            .remove::<crate::client::GoIdleReservation>()
            .filter(|reservation| reservation.inner.belongs_to(&self.inner));
        let protocol = request.extensions_mut().remove::<Protocol>();

        // Clear before taking lock, incase extensions contain a StreamRef.
        request.extensions_mut().clear();

        // TODO: There is a hazard with assigning a stream ID before the
        // prioritize layer. If prioritization reorders new streams, this
        // implicitly closes the earlier stream IDs.
        //
        // See: hyperium/h2#11
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        let mut send_buffer = self.send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        #[cfg(feature = "go-client-idle")]
        {
            if me.go_client_reportable_closed() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "http2: client conn not established",
                )
                .into());
            }
            if let Some(reservation) = reservation.as_ref() {
                reservation.inner.consume(me);
            }
            if let Some(idle) = me.counts.go_client_idle.as_mut() {
                idle.lifecycle.active();
                if idle.closed || idle.too_idle() || idle.do_not_reuse {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "HTTP/2 connection closed on idle",
                    )
                    .into());
                }
                // Go stops its timer before waiting for an available stream slot.
                idle.set_deadline(None);
                idle.last_idle = None;
            }
        }
        self.send_request_locked(me, send_buffer, request, protocol, end_of_stream, pending)
    }

    fn send_request_locked(
        &self,
        me: &mut Inner,
        send_buffer: &mut Buffer<Frame<B>>,
        request: Request<()>,
        protocol: Option<Protocol>,
        end_of_stream: bool,
        pending: Option<&OpaqueStreamRef>,
    ) -> Result<(StreamRef<B>, bool), SendError> {
        use super::stream::ContentLength;
        use http::Method;
        let result = (|| {
            me.actions.ensure_no_conn_error()?;
            me.actions.send.ensure_next_stream_id()?;

            // The `pending` argument is provided by the `Client`, and holds
            // a store `Key` of a `Stream` that may have been not been opened
            // yet.
            //
            // If that stream is still pending, the Client isn't allowed to
            // queue up another pending stream. They should use `poll_ready`.
            if let Some(stream) = pending {
                if me.store.resolve(stream.key).is_pending_open {
                    return Err(UserError::Rejected.into());
                }
            }

            if me.counts.peer().is_server() {
                // Servers cannot open streams. PushPromise must first be reserved.
                return Err(UserError::UnexpectedFrameType.into());
            }

            let stream_id = me.actions.send.open()?;
            #[cfg(feature = "go-client-idle")]
            if let Some(idle) = me.counts.go_client_idle.as_mut() {
                idle.lifecycle.opened();
            }

            let mut stream = Stream::new(
                stream_id,
                me.actions.send.init_window_sz(),
                me.actions.recv.init_window_sz(),
            );

            if *request.method() == Method::HEAD {
                stream.content_length = ContentLength::Head;
            }

            // Convert the message
            let headers =
                client::Peer::convert_send_message(stream_id, request, protocol, end_of_stream)?;

            #[cfg(feature = "go-client-idle")]
            if let Some(idle) = me.counts.go_client_idle.as_mut() {
                idle.active += 1;
                stream.go_client_active = true;
                idle.stream_flights
                    .insert(stream.id, super::counts::GoStreamFlight::default());
            }
            let mut stream = me.store.insert(stream.id, stream);

            let sent = me.actions.send.send_headers(
                headers,
                send_buffer,
                &mut stream,
                &mut me.counts,
                &mut me.actions.task,
            );

            // send_headers can return a UserError, if it does,
            // we should forget about this stream.
            if let Err(err) = sent {
                #[cfg(feature = "go-client-idle")]
                if stream.go_client_active {
                    stream.go_client_active = false;
                    let idle = me.counts.go_client_idle.as_mut().unwrap();
                    idle.active -= 1;
                    idle.stream_flights.remove(&stream.id);
                }
                stream.unlink();
                stream.remove();
                return Err(err.into());
            }

            #[cfg(feature = "go-client-idle")]
            if stream.go_client_active && stream.is_pending_open {
                stream.go_client_waiting = true;
                me.counts.go_client_idle.as_mut().unwrap().waiting += 1;
            }

            // Given that the stream has been initialized, it should not be in the
            // closed state.
            debug_assert!(!stream.state.is_closed());

            // TODO: ideally, OpaqueStreamRefs::new would do this, but we're holding
            // the lock, so it can't.
            me.refs += 1;

            let is_full = me.counts.next_send_stream_will_reach_capacity();
            Ok((
                StreamRef {
                    opaque: OpaqueStreamRef::new(self.inner.clone(), &mut stream),
                    send_buffer: self.send_buffer.clone(),
                },
                is_full,
            ))
        })();
        #[cfg(feature = "go-client-idle")]
        if result.is_err() && me.actions.conn_error.is_none() {
            if let Some(idle) = me.counts.go_client_idle.as_mut() {
                if !idle.closed && !idle.too_idle() && idle.active == 0 {
                    // Header conversion / admission failure has no StreamRef
                    // whose later closure could restart the idle timer.
                    idle.restart();
                }
            }
        }
        result
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_poll_send_request(
        &mut self,
        cx: &Context<'_>,
        request: &mut Option<Request<()>>,
        protocol: &mut Option<Protocol>,
        reservation: Option<&crate::client::GoIdleReservation>,
        admission: &mut Option<GoHeaderAdmission>,
        end_of_stream: bool,
    ) -> Poll<Result<(StreamRef<B>, bool), (SendError, bool)>> {
        let mut locked = self.inner.lock().unwrap();
        let me = &mut *locked;
        me.counts.go_client_refresh_receipts();
        let Some(idle) = me.counts.go_client_idle.as_mut() else {
            return Poll::Ready(Err((
                io::Error::other("native HTTP/2 request admission requires native client mode")
                    .into(),
                true,
            )));
        };
        if admission.is_none() {
            let key = Arc::new(());
            idle.header_waiters
                .push_back(super::counts::GoHeaderWaiter {
                    key: key.clone(),
                    waker: cx.waker().clone(),
                });
            *admission = Some(GoHeaderAdmission {
                inner: Arc::downgrade(&self.inner),
                key,
                registered: true,
            });
        }
        let guard = admission.as_mut().unwrap();
        let position = idle
            .header_waiters
            .iter()
            .position(|waiter| Arc::ptr_eq(&waiter.key, &guard.key))
            .expect("registered native header admission");
        idle.header_waiters[position].waker = cx.waker().clone();
        if position != 0 {
            return Poll::Pending;
        }
        // Selected Go holds reqHeaderMu, stops its timer and consumes only
        // this request's reservation before checking default non-strict
        // capacity. A capacity race is UNSENT/unusable, not a pending stream.
        idle.set_deadline(None);
        if let Some(reservation) =
            reservation.filter(|reservation| reservation.inner.belongs_to(&self.inner))
        {
            reservation.inner.consume(me);
        }
        me.counts
            .go_client_idle
            .as_mut()
            .unwrap()
            .lifecycle
            .active();
        let fatal_unused = me.go_client_reportable_closed()
            && me.counts.go_client_idle.as_ref().unwrap().reserved == 0;
        if fatal_unused {
            return Poll::Ready(Err((
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "http2: client conn not established",
                )
                .into(),
                false,
            )));
        }
        if me.go_client_availability() != crate::client::GoAvailability::Available {
            return Poll::Ready(Err((
                io::Error::new(io::ErrorKind::BrokenPipe, "http2: client conn not usable").into(),
                true,
            )));
        }
        me.counts.go_client_idle.as_mut().unwrap().last_idle = None;
        let mut send_buffer = self.send_buffer.inner.lock().unwrap();
        let result = self.send_request_locked(
            me,
            &mut send_buffer,
            request
                .take()
                .expect("native request retained before admission"),
            protocol.take(),
            end_of_stream,
            None,
        );
        match result {
            Ok((stream, full)) => {
                let header_gate = super::recv::GoReadGate::default();
                let id = me.store[stream.opaque.key].id;
                me.store.resolve(stream.opaque.key).go_client_header_gate =
                    Some(header_gate.clone());
                let idle = me.counts.go_client_idle.as_mut().unwrap();
                idle.header_flight = Some(super::counts::GoHeaderFlight {
                    header_gate,
                    pipe_gate: None,
                    id,
                    receipt: None,
                    done_gate: None,
                    cleanup_required: false,
                    cancelled_before_start: false,
                });
                // The queue key is now retained by header metadata, independent
                // of the response/body handles or canceled admission future.
                guard.registered = false;
                Poll::Ready(Ok((stream, full)))
            }
            Err(error) => Poll::Ready(Err((error, false))),
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_unsent_cleanup(
        &self,
        reservation: Option<&crate::client::GoIdleReservation>,
        wait: bool,
    ) -> Option<super::recv::GoReadGate> {
        let mut locked = self.inner.lock().unwrap();
        let inner = &mut *locked;
        if let Some(reservation) =
            reservation.filter(|reservation| reservation.inner.belongs_to(&self.inner))
        {
            // writeRequest's reservation defer runs before cleanupWriteRequest.
            // Consume exactly once, independent of extension/guard clones.
            reservation.inner.consume(inner);
        }
        let idle = inner.counts.go_client_idle.as_mut()?;
        if idle.closed {
            return None;
        }
        let gate = if wait {
            let gate = super::recv::GoReadGate::default();
            idle.unsent_done.push_back(gate.clone());
            Some(gate)
        } else {
            None
        };
        // ID == 0 still acquires wmu and observes its sticky error. No stream,
        // reset, timer restart or I/O is introduced by this enqueue operation.
        idle.cleanup_work = true;
        if let Some(task) = idle.task.take() {
            task.wake();
        }
        if let Some(task) = inner.actions.task.take() {
            task.wake();
        }
        gate
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_idle_handle(&self) -> Option<GoClientIdleHandle> {
        self.inner.lock().unwrap().counts.go_client_idle.as_ref()?;
        Some(GoClientIdleHandle(self.inner.clone()))
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn configure_go_native_client(&mut self, timeout: Duration) {
        let mut inner = self.inner.lock().unwrap();
        inner.counts.go_client_disable_error_reset_limit();
        inner.counts.go_client_idle = Some(super::counts::GoClientIdle {
            timeout,
            last_idle: None,
            deadline: None,
            reserved: 0,
            active: 0,
            waiting: 0,
            pending_resets: 0,
            reset_pings_blocked: false,
            read_before_stream: StreamId::ZERO,
            reset_ping_payload: None,
            reset_flights: std::collections::VecDeque::new(),
            stream_flights: std::collections::HashMap::new(),
            pending_finished: std::collections::VecDeque::new(),
            cleanup_work: false,
            header_waiters: std::collections::VecDeque::new(),
            header_flight: None,
            cleanup_done: std::collections::HashMap::new(),
            unsent_done: std::collections::VecDeque::new(),
            do_not_reuse: false,
            lifecycle: Arc::new(super::client_state::GoLifecycle::new()),
            closed: false,
            task: None,
        });
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_set_reset_ping_payload(&self, payload: fn() -> [u8; 8]) {
        self.inner
            .lock()
            .unwrap()
            .counts
            .go_client_idle
            .as_mut()
            .unwrap()
            .reset_ping_payload = Some(payload);
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_initialized(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        let idle = inner.counts.go_client_idle.as_mut().unwrap();
        if !idle.timeout.is_zero() {
            idle.set_deadline(Some(tokio::time::Instant::now() + idle.timeout));
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_closed(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.counts.go_client_abort_reset_flights();
        if let Some(idle) = inner.counts.go_client_idle.as_mut() {
            idle.closed = true;
            idle.lifecycle.close(false, false, idle.timeout);
        }
    }

    #[cfg(feature = "go-client-idle")]
    fn go_client_finish_reset(&self, failed: bool) {
        let mut inner = self.inner.lock().unwrap();
        let Some(idle) = inner.counts.go_client_idle.as_mut() else {
            return;
        };
        let finished = if failed {
            let count = idle.reset_flights.len();
            for flight in idle.reset_flights.drain(..) {
                if let Some(gate) = flight.pipe_gate {
                    gate.complete();
                }
                idle.cleanup_done.insert(flight.id, flight.done_gate);
            }
            count
        } else {
            if let Some(flight) = idle.reset_flights.pop_front() {
                if let Some(gate) = flight.pipe_gate {
                    gate.complete();
                }
                idle.cleanup_done.insert(flight.id, flight.done_gate);
                1
            } else {
                0
            }
        };
        if finished != 0 {
            debug_assert!(idle.active >= finished);
            idle.active -= finished;
            idle.lifecycle.active();
            idle.cleanup_work = true;
            if idle.active == 0 {
                idle.restart();
            } else if let Some(task) = idle.task.take() {
                task.wake();
            }
        }
    }

    #[cfg(feature = "go-client-idle")]
    fn go_client_reset_error(&mut self, error: &io::Error) {
        self.go_client_finish_reset(true);
        // As in Go request cleanup, a cached writer error closes the
        // connection and wakes all request waiters, even if Future is retained.
        self.as_dyn()
            .handle_error(io::Error::new(error.kind(), error.to_string()).into());
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn poll_go_client_reset_flight<T>(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut Codec<T, Prioritized<B>>,
    ) -> Poll<io::Result<()>>
    where
        T: AsyncWrite + Unpin,
    {
        use super::counts::GoResetStage;
        loop {
            let stage = {
                let mut inner = self.inner.lock().unwrap();
                let inner = &mut *inner;
                let Some(idle) = inner.counts.go_client_idle.as_mut() else {
                    return Poll::Ready(Ok(()));
                };
                let Some(front) = idle.reset_flights.front_mut() else {
                    return Poll::Ready(Ok(()));
                };
                let id = front.id;
                if matches!(front.stage, GoResetStage::Queued) {
                    front.stage = GoResetStage::WaitingPrevious;
                    // Generic reset/error cleanup may later remove this Store
                    // entry. The independent FIFO retains ID and active owner.
                    if let Some(stream) = inner.store.find_mut(&id) {
                        let mut buffer = self.send_buffer.inner.lock().unwrap();
                        let actions = &mut inner.actions;
                        inner.counts.transition(stream, |counts, stream| {
                            actions
                                .send
                                .clear_go_owned_reset(&mut buffer, stream, counts);
                        });
                    }
                }
                inner
                    .counts
                    .go_client_idle
                    .as_ref()
                    .unwrap()
                    .reset_flights
                    .front()
                    .unwrap()
                    .stage
                    .clone()
            };
            match stage {
                GoResetStage::Queued => unreachable!(),
                GoResetStage::WaitingPrevious => {
                    match dst.poll_ready(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(error)) => {
                            self.go_client_reset_error(&error);
                            return Poll::Ready(Err(error));
                        }
                        Poll::Ready(Ok(())) => {}
                    }
                    let clean = {
                        let inner = self.inner.lock().unwrap();
                        inner
                            .counts
                            .go_client_idle
                            .as_ref()
                            .unwrap()
                            .reset_flights
                            .front()
                            .and_then(|flight| flight.clean_after.as_ref())
                            .is_some_and(|receipt| receipt.is_flushed())
                    };
                    if clean {
                        self.go_client_finish_reset(false);
                        cx.waker().wake_by_ref();
                        return Poll::Ready(Ok(()));
                    }
                    let (id, reason, ping, payload) = {
                        let inner = self.inner.lock().unwrap();
                        let idle = inner.counts.go_client_idle.as_ref().unwrap();
                        let front = idle.reset_flights.front().unwrap();
                        (front.id, front.reason, front.ping, idle.reset_ping_payload)
                    };
                    dst.go_begin_write_flight()
                        .expect("native output tracking enabled");
                    dst.buffer(frame::Reset::new(id, reason).into())
                        .expect("valid cancellation reset");
                    if ping {
                        let bytes = payload.map_or([0; 8], |payload| payload());
                        dst.buffer(frame::Ping::new(bytes).into())
                            .expect("valid cancellation PING");
                    }
                    let receipt = dst.go_end_write_flight().expect("native reset flight");
                    self.inner
                        .lock()
                        .unwrap()
                        .counts
                        .go_client_idle
                        .as_mut()
                        .unwrap()
                        .reset_flights
                        .front_mut()
                        .unwrap()
                        .stage = GoResetStage::Flushing(receipt);
                }
                GoResetStage::Flushing(receipt) => match dst.go_flush_through(cx, &receipt) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => {
                        self.go_client_reset_error(&error);
                        return Poll::Ready(Err(error));
                    }
                    Poll::Ready(Ok(())) => {
                        self.go_client_finish_reset(false);
                        // Release wmu after this captured flight. A received
                        // control may acquire it before another queued reset.
                        cx.waker().wake_by_ref();
                        return Poll::Ready(Ok(()));
                    }
                },
            }
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_refresh_receipts(&self) {
        self.inner
            .lock()
            .unwrap()
            .counts
            .go_client_refresh_receipts();
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_cleanup_checked(&self) {
        self.inner
            .lock()
            .unwrap()
            .counts
            .go_client_cleanup_checked();
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_reset_is_active(&self) -> bool {
        self.inner
            .lock()
            .unwrap()
            .counts
            .go_client_idle
            .as_ref()
            .is_some_and(|idle| {
                idle.reset_flights.front().is_some_and(|flight| {
                    !matches!(flight.stage, super::counts::GoResetStage::Queued)
                })
            })
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_has_writer_work(&self, max_frame_len: usize) -> bool {
        let inner = self.inner.lock().unwrap();
        let cleanup = inner.counts.go_client_idle.as_ref().is_some_and(|idle| {
            idle.cleanup_work
                || !idle.unsent_done.is_empty()
                || !idle.cleanup_done.is_empty()
                || idle
                    .header_flight
                    .as_ref()
                    .is_some_and(|flight| flight.cleanup_required)
                || !idle.reset_flights.is_empty()
                || idle.stream_flights.values().any(|flight| {
                    flight.queued_for_codec
                        || flight
                            .latest
                            .as_ref()
                            .is_some_and(|receipt| !receipt.is_flushed())
                })
        });
        cleanup
            || inner.actions.send.has_pending_output(
                &inner.store,
                &self.send_buffer.inner.lock().unwrap(),
                &inner.counts,
                max_frame_len,
            )
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn take_go_body_refund(&self) -> Option<super::recv::GoBodyRefund> {
        self.inner
            .lock()
            .unwrap()
            .actions
            .recv
            .take_go_body_refund()
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn abort_go_body_refunds(&self) {
        self.inner
            .lock()
            .unwrap()
            .actions
            .recv
            .abort_go_body_refunds();
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_idle_deadline(&self, cx: &Context) -> Option<tokio::time::Instant> {
        let mut inner = self.inner.lock().unwrap();
        let idle = inner.counts.go_client_idle.as_mut()?;
        idle.task = Some(cx.waker().clone());
        idle.deadline
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn close_go_client_if_unusable_idle(&mut self) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let Some(idle) = inner.counts.go_client_idle.as_mut() else {
            return false;
        };
        if !idle.do_not_reuse || idle.active != 0 || idle.reserved != 0 {
            return false;
        }
        idle.closed = true;
        idle.lifecycle.close(false, false, idle.timeout);
        inner.actions.conn_error = Some(
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "HTTP/2 connection no longer reusable",
            )
            .into(),
        );
        true
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn close_go_client_if_idle(&mut self, now: tokio::time::Instant) -> bool {
        let mut inner = self.inner.lock().unwrap();
        let Some(idle) = inner.counts.go_client_idle.as_mut() else {
            return false;
        };
        if !matches!(idle.deadline, Some(deadline) if deadline <= now) {
            return false;
        }
        // A fired Go AfterFunc is consumed even if a request is reserved.
        idle.deadline = None;
        if idle.active != 0 || idle.reserved != 0 {
            return false;
        }
        idle.closed = true;
        idle.lifecycle.close(true, false, idle.timeout);
        inner.actions.conn_error = Some(
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "HTTP/2 connection closed on idle",
            )
            .into(),
        );
        true
    }

    pub(crate) fn is_extended_connect_protocol_enabled(&self) -> bool {
        self.inner
            .lock()
            .unwrap()
            .actions
            .send
            .is_extended_connect_protocol_enabled()
    }

    pub fn current_max_send_streams(&self) -> usize {
        let me = self.inner.lock().unwrap();
        me.counts.max_send_streams()
    }

    pub fn current_max_recv_streams(&self) -> usize {
        let me = self.inner.lock().unwrap();
        me.counts.max_recv_streams()
    }
}

impl<B> DynStreams<'_, B> {
    #[cfg(feature = "go-client-idle")]
    pub(crate) fn enable_go_native_client_receipts(&mut self) {
        self.inner
            .lock()
            .unwrap()
            .actions
            .recv
            .enable_go_client_controls();
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_recv_flush_completed(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        let inner = &mut *inner;
        inner
            .actions
            .recv
            .commit_go_client_recv_eof(&mut inner.store, &mut inner.counts);
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn take_go_client_recv_updates(&mut self) -> [Option<frame::WindowUpdate>; 2] {
        self.inner
            .lock()
            .unwrap()
            .actions
            .recv
            .take_go_client_recv_updates()
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_received_stream_frame(&mut self, _id: StreamId, header_or_data: bool) {
        let mut inner = self.inner.lock().unwrap();
        let next = inner
            .actions
            .send
            .ensure_next_stream_id()
            .unwrap_or(StreamId::MAX);
        if let Some(idle) = inner.counts.go_client_idle.as_mut() {
            idle.read_before_stream = next;
            if header_or_data {
                idle.reset_pings_blocked = false;
            }
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_received_ping_ack(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(idle) = inner.counts.go_client_idle.as_mut() {
            if idle.pending_resets != 0 {
                idle.pending_resets = 0;
                idle.reset_pings_blocked = true;
            }
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_received_goaway(&mut self) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(idle) = inner.counts.go_client_idle.as_mut() {
            idle.do_not_reuse = true;
            idle.lifecycle.close(false, true, idle.timeout);
        }
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn enable_go_native_controls(&mut self) {
        self.inner.lock().unwrap().actions.recv.enable_go_native();
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn go_pending_controls(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .actions
            .recv
            .go_pending_controls()
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn go_queue_refusal(&mut self, id: StreamId) {
        self.inner.lock().unwrap().actions.recv.go_queue_refusal(id);
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn configure_go_stream_timeouts(
        &mut self,
        read: Option<Duration>,
        write: Option<Duration>,
    ) {
        self.inner
            .lock()
            .unwrap()
            .counts
            .configure_go_stream_timeouts(read, write);
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn expire_go_stream_timeouts(
        &mut self,
        now: tokio::time::Instant,
    ) -> (u64, Option<tokio::time::Instant>) {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;
        if !me.counts.go_stream_timeouts_enabled() {
            return (me.counts.go_deadline_generation(), None);
        }
        let mut next = None;
        let mut writes = Vec::new();
        let mut changed = false;
        me.store.for_each(|mut stream| {
            if stream.is_closed() {
                changed |= stream.go_read_deadline.is_some() || stream.go_write_deadline.is_some();
                stream.go_read_deadline = None;
                stream.go_write_deadline = None;
                return;
            }
            // A completed body already has sticky EOF; a later read timer
            // cannot replace it with a deadline error.
            if stream.state.is_recv_end_stream() {
                changed |= stream.go_read_deadline.is_some();
                stream.go_read_deadline = None;
            }
            if let Some(deadline) = stream.go_read_deadline {
                if deadline <= now {
                    stream.go_read_deadline = None;
                    changed = true;
                    stream.go_body_read_timed_out = true;
                    stream.notify_recv();
                } else {
                    next = Some(next.map_or(deadline, |previous: tokio::time::Instant| {
                        previous.min(deadline)
                    }));
                }
            }
            if let Some(deadline) = stream.go_write_deadline {
                if deadline <= now {
                    stream.go_write_deadline = None;
                    changed = true;
                    writes.push(stream.id);
                } else {
                    next = Some(next.map_or(deadline, |previous| previous.min(deadline)));
                }
            }
        });
        if changed {
            me.counts.go_deadlines_changed();
        }
        if !writes.is_empty() {
            let mut buffer = self.send_buffer.inner.lock().unwrap();
            for id in writes {
                if let Some(stream) = me.store.find_mut(&id) {
                    let actions = &mut me.actions;
                    me.counts.transition(stream, |counts, stream| {
                        // Deadline expiry is not a protocol-abuse reset and
                        // must not consume the lifetime local-error budget.
                        actions.send.send_reset(
                            Reason::INTERNAL_ERROR,
                            Initiator::Library,
                            &mut buffer,
                            stream,
                            counts,
                            &mut actions.task,
                        );
                        actions.recv.enqueue_reset_expiration(stream, counts);
                        stream.notify_recv();
                    });
                }
            }
        }
        (me.counts.go_deadline_generation(), next)
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn go_deadline_generation(&self) -> u64 {
        self.inner.lock().unwrap().counts.go_deadline_generation()
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn configure_go_idle(&mut self, timeout: Option<Duration>) {
        self.inner.lock().unwrap().counts.configure_go_idle(timeout);
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn stop_go_idle(&mut self) {
        self.inner.lock().unwrap().counts.stop_go_idle();
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn go_idle_deadline(&self) -> Option<tokio::time::Instant> {
        self.inner.lock().unwrap().counts.go_idle_deadline()
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(crate) fn ignore_goaway_data(&mut self, frame: frame::Data) -> Result<(), Error> {
        let size = frame.flow_controlled_len() as WindowSize;
        self.inner.lock().unwrap().actions.recv.ignore_data(size)
    }

    pub fn is_buffer_empty(&self) -> bool {
        self.send_buffer.is_empty()
    }

    pub fn is_server(&self) -> bool {
        self.peer.is_server()
    }

    /// Reports whether the connection must refuse the stream opened by the peer.
    pub fn recv_headers(&mut self, frame: frame::Headers) -> Result<RecvOutcome, Error> {
        let mut me = self.inner.lock().unwrap();

        me.recv_headers(self.peer, self.send_buffer, frame)
    }

    pub fn recv_data(&mut self, frame: frame::Data) -> Result<(), Error> {
        let mut me = self.inner.lock().unwrap();
        me.recv_data(self.peer, self.send_buffer, frame)
    }

    pub fn recv_reset(&mut self, frame: frame::Reset) -> Result<(), Error> {
        let mut locked = self.inner.lock().unwrap();
        let me = &mut *locked;
        #[cfg(feature = "go-client-idle")]
        if frame.reason() == Reason::PROTOCOL_ERROR && me.counts.go_client_idle.is_some() {
            let counts = &me.counts;
            let known = me.store.find_mut(&frame.stream_id()).is_some_and(|stream| {
                !stream.state.is_reset()
                    && (stream.go_client_active
                        || counts
                            .go_client_idle
                            .as_ref()
                            .unwrap()
                            .stream_flights
                            .get(&stream.id)
                            .is_some_and(|flight| flight.closing))
            });
            if known {
                me.counts.go_client_idle.as_mut().unwrap().do_not_reuse = true;
            }
        }

        me.recv_reset(self.send_buffer, frame)
    }

    /// Notify all streams that a connection-level error happened.
    pub fn handle_error(&mut self, err: proto::Error) -> StreamId {
        let mut me = self.inner.lock().unwrap();
        me.handle_error(self.send_buffer, err)
    }

    pub fn recv_go_away(&mut self, frame: &frame::GoAway) -> Result<(), Error> {
        let mut me = self.inner.lock().unwrap();
        me.recv_go_away(self.send_buffer, frame)
    }

    pub fn last_processed_id(&self) -> StreamId {
        self.inner.lock().unwrap().actions.recv.last_processed_id()
    }

    pub fn recv_window_update(&mut self, frame: frame::WindowUpdate) -> Result<(), Error> {
        let mut me = self.inner.lock().unwrap();
        me.recv_window_update(self.send_buffer, frame)
    }

    /// Reports whether the connection must refuse the promised stream.
    pub fn recv_push_promise(&mut self, frame: frame::PushPromise) -> Result<RecvOutcome, Error> {
        let mut me = self.inner.lock().unwrap();
        me.recv_push_promise(self.send_buffer, frame)
    }

    pub fn recv_eof(&mut self, clear_pending_accept: bool) -> Result<(), ()> {
        let mut me = self.inner.lock().map_err(|_| ())?;
        me.recv_eof(self.send_buffer, clear_pending_accept)
    }

    pub fn send_reset(
        &mut self,
        id: StreamId,
        reason: Reason,
    ) -> Result<(), crate::proto::error::GoAway> {
        let mut me = self.inner.lock().unwrap();
        me.send_reset(self.send_buffer, id, reason)
    }

    pub fn send_go_away(&mut self, last_processed_id: StreamId) {
        let mut me = self.inner.lock().unwrap();
        me.actions.recv.go_away(last_processed_id);
    }
}

impl Inner {
    #[cfg(feature = "go-client-idle")]
    fn go_client_reportable_closed(&self) -> bool {
        self.counts.go_client_idle.as_ref().is_some_and(|idle| {
            idle.lifecycle.snapshot_closed().is_some_and(|closed| {
                closed.never_used && !closed.closed_on_idle && !closed.go_away
            })
        })
    }

    #[cfg(feature = "go-client-idle")]
    fn go_client_availability(&mut self) -> crate::client::GoAvailability {
        self.counts.go_client_refresh_receipts();
        use crate::client::GoAvailability::{Available, Saturated, Unusable};
        let Some(idle) = self.counts.go_client_idle.as_ref() else {
            return Unusable;
        };
        if self.go_client_reportable_closed() && idle.reserved == 0 {
            return Available;
        }
        if idle.closed
            || idle.too_idle()
            || idle.do_not_reuse
            || self.actions.conn_error.is_some()
            || !matches!(self.actions.send.ensure_next_stream_id(), Ok(id) if id < StreamId::MAX)
        {
            return Unusable;
        }
        let current = idle
            .active
            .saturating_sub(idle.waiting)
            .saturating_add(idle.reserved)
            .saturating_add(idle.pending_resets);
        if current >= self.counts.max_send_streams() {
            Saturated
        } else {
            Available
        }
    }

    fn new(peer: peer::Dyn, config: Config) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Inner {
            counts: Counts::new(peer, &config),
            actions: Actions {
                recv: Recv::new(peer, &config),
                send: Send::new(&config),
                task: None,
                conn_error: None,
            },
            store: Store::new(),
            refs: 1,
        }))
    }

    fn recv_headers<B>(
        &mut self,
        peer: peer::Dyn,
        send_buffer: &SendBuffer<B>,
        frame: frame::Headers,
    ) -> Result<RecvOutcome, Error> {
        let id = frame.stream_id();

        // The GOAWAY process has begun. All streams with a greater ID than
        // specified as part of GOAWAY should be ignored.
        if id > self.actions.recv.max_stream_id() {
            tracing::trace!(
                "id ({:?}) > max_stream_id ({:?}), ignoring HEADERS",
                id,
                self.actions.recv.max_stream_id()
            );
            return Ok(RecvOutcome::Processed);
        }

        let key = match self.store.find_entry(id) {
            Entry::Occupied(e) => e.key(),
            Entry::Vacant(e) => {
                // Client: it's possible to send a request, and then send
                // a RST_STREAM while the response HEADERS were in transit.
                //
                // Server: we can't reset a stream before having received
                // the request headers, so don't allow.
                if !peer.is_server() {
                    // This may be response headers for a stream we've already
                    // forgotten about...
                    if self.actions.may_have_forgotten_stream(peer, id) {
                        tracing::debug!(
                            "recv_headers for old stream={:?}, sending STREAM_CLOSED",
                            id,
                        );
                        return Err(Error::library_reset(id, Reason::STREAM_CLOSED));
                    }
                }

                match self
                    .actions
                    .recv
                    .open(id, Open::Headers, &mut self.counts)?
                {
                    Some(stream_id) => {
                        #[allow(unused_mut)]
                        let mut stream = Stream::new(
                            stream_id,
                            self.actions.send.init_window_sz(),
                            self.actions.recv.init_window_sz(),
                        );
                        #[cfg(feature = "go-server-lifecycle")]
                        self.counts.start_go_write_timeout(&mut stream);

                        e.insert(stream)
                    }
                    None => return Ok(RecvOutcome::Refused(id)),
                }
            }
        };

        let stream = self.store.resolve(key);

        if stream.is_pending_open {
            proto_err!(conn: "recv_headers: received frame on idle stream {:?}", id);
            return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
        }

        if stream.state.is_local_error() {
            // Locally reset streams must ignore frames "for some time".
            // This is because the remote may have sent trailers before
            // receiving the RST_STREAM frame.
            tracing::trace!("recv_headers; ignoring trailers on {:?}", stream.id);
            return Ok(RecvOutcome::Processed);
        }

        let actions = &mut self.actions;

        self.counts.transition(stream, |counts, stream| {
            tracing::trace!(
                "recv_headers; stream={:?}; state={:?}",
                stream.id,
                stream.state
            );

            let res = if stream.state.is_recv_headers() {
                match actions.recv.recv_headers(frame, stream, counts) {
                    Ok(()) => Ok(()),
                    Err(RecvHeaderBlockError::Oversize) => {
                        if peer.is_server() {
                            let mut resp = frame::Headers::new(
                                stream.id,
                                frame::Pseudo::response(
                                    ::http::StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                                ),
                                HeaderMap::new(),
                            );
                            resp.set_end_stream();
                            let mut send_buffer = send_buffer.inner.lock().unwrap();
                            let sent = actions.send.send_headers(
                                resp, &mut send_buffer, stream, counts, &mut actions.task);
                            debug_assert!(sent.is_ok(), "oversize response should not fail");

                            actions.send.schedule_implicit_reset(
                                stream,
                                Reason::PROTOCOL_ERROR,
                                counts,
                                &mut actions.task);

                            actions.recv.enqueue_reset_expiration(stream, counts);

                            Ok(())
                        } else {
                            Err(Error::library_reset(stream.id, Reason::PROTOCOL_ERROR))
                        }
                    },
                    Err(RecvHeaderBlockError::State(err)) => Err(err),
                }
            } else {
                if !frame.is_end_stream() {
                    // Receiving trailers that don't set EOS is a "malformed"
                    // message. Malformed messages are a stream error.
                    proto_err!(stream: "recv_headers: trailers frame was not EOS; stream={:?}", stream.id);
                    return Err(Error::library_reset(stream.id, Reason::PROTOCOL_ERROR));
                }

                actions.recv.recv_trailers(frame, stream)
            };

            actions.reset_on_recv_stream_err_deferred(send_buffer, stream, counts, res)
        })?;

        Ok(RecvOutcome::Processed)
    }

    fn recv_data<B>(
        &mut self,
        peer: peer::Dyn,
        send_buffer: &SendBuffer<B>,
        frame: frame::Data,
    ) -> Result<(), Error> {
        let id = frame.stream_id();

        let stream = match self.store.find_mut(&id) {
            Some(stream) => stream,
            None => {
                // The GOAWAY process has begun. All streams with a greater ID
                // than specified as part of GOAWAY should be ignored.
                if id > self.actions.recv.max_stream_id() {
                    tracing::trace!(
                        "id ({:?}) > max_stream_id ({:?}), ignoring DATA",
                        id,
                        self.actions.recv.max_stream_id()
                    );

                    // We still need to account for connection-level flow control.
                    let sz = frame.flow_controlled_len();
                    assert!(sz <= super::MAX_WINDOW_SIZE as usize);
                    let sz = sz as WindowSize;
                    self.actions.recv.ignore_data(sz)?;

                    return Ok(());
                }

                if self.actions.may_have_forgotten_stream(peer, id) {
                    tracing::debug!("recv_data for old stream={:?}, sending STREAM_CLOSED", id,);

                    let sz = frame.flow_controlled_len();
                    // This should have been enforced at the codec::FramedRead layer, so
                    // this is just a sanity check.
                    assert!(sz <= super::MAX_WINDOW_SIZE as usize);
                    let sz = sz as WindowSize;
                    self.actions.recv.ignore_data(sz)?;

                    return Err(Error::library_reset(id, Reason::STREAM_CLOSED));
                }

                proto_err!(conn: "recv_data: stream not found; id={:?}", id);
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }
        };

        let actions = &mut self.actions;

        self.counts.transition(stream, |counts, stream| {
            let sz = frame.flow_controlled_len();
            let is_end_stream = frame.is_end_stream();
            let payload_len = frame.payload().len();
            let mut res = actions.recv.recv_data(frame, stream);
            // A stream can receive at most one final DATA frame, so it cannot
            // be used to create unbounded framing overhead on that stream.
            if res.is_ok() && !is_end_stream {
                res = counts.record_data_frame(payload_len).map_err(|_| {
                    tracing::debug!("too many small DATA frames");
                    Error::library_go_away_data(Reason::ENHANCE_YOUR_CALM, "too_many_data_frames")
                });
            }

            // Any stream error after receiving a DATA frame means
            // we won't give the data to the user, and so they can't
            // release the capacity. We do it automatically.
            if let Err(Error::Reset(..)) = res {
                actions
                    .recv
                    .release_connection_capacity(sz as WindowSize, &mut None);
            }
            actions.reset_on_recv_stream_err_deferred(send_buffer, stream, counts, res)
        })
    }

    fn recv_reset<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        frame: frame::Reset,
    ) -> Result<(), Error> {
        let id = frame.stream_id();

        if id.is_zero() {
            proto_err!(conn: "recv_reset: invalid stream ID 0");
            return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
        }

        // The GOAWAY process has begun. All streams with a greater ID than
        // specified as part of GOAWAY should be ignored.
        if id > self.actions.recv.max_stream_id() {
            tracing::trace!(
                "id ({:?}) > max_stream_id ({:?}), ignoring RST_STREAM",
                id,
                self.actions.recv.max_stream_id()
            );
            return Ok(());
        }

        let stream = match self.store.find_mut(&id) {
            Some(stream) => stream,
            None => {
                // TODO: Are there other error cases?
                self.actions
                    .ensure_not_idle(self.counts.peer(), id)
                    .map_err(Error::library_go_away)?;

                return Ok(());
            }
        };

        if stream.is_pending_open {
            proto_err!(conn: "recv_reset: received frame on idle stream {:?}", id);
            return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
        }

        let mut send_buffer = send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        let actions = &mut self.actions;

        self.counts.transition(stream, |counts, stream| {
            actions.recv.recv_reset(frame, stream, counts)?;
            actions.send.handle_error(send_buffer, stream, counts);
            assert!(stream.state.is_closed());
            Ok(())
        })
    }

    fn recv_window_update<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        frame: frame::WindowUpdate,
    ) -> Result<(), Error> {
        let id = frame.stream_id();

        let mut send_buffer = send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        if id.is_zero() {
            self.actions
                .send
                .recv_connection_window_update(frame, &mut self.store, &mut self.counts)
                .map_err(Error::library_go_away)?;
        } else {
            // The remote may send window updates for streams that the local now
            // considers closed. It's ok...
            if let Some(mut stream) = self.store.find_mut(&id) {
                if stream.is_pending_open {
                    proto_err!(conn: "recv_window_update: received frame on idle stream {:?}", id);
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }

                let res = self
                    .actions
                    .send
                    .recv_stream_window_update(
                        frame.size_increment(),
                        send_buffer,
                        &mut stream,
                        &mut self.counts,
                        &mut self.actions.task,
                    )
                    .map_err(|reason| Error::library_reset(id, reason));

                return self.actions.reset_on_recv_stream_err(
                    send_buffer,
                    &mut stream,
                    &mut self.counts,
                    res,
                );
            } else {
                self.actions
                    .ensure_not_idle(self.counts.peer(), id)
                    .map_err(Error::library_go_away)?;
            }
        }

        Ok(())
    }

    fn handle_error<B>(&mut self, send_buffer: &SendBuffer<B>, err: proto::Error) -> StreamId {
        let actions = &mut self.actions;
        let counts = &mut self.counts;
        let mut send_buffer = send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        let last_processed_id = actions.recv.last_processed_id();

        self.store.for_each(|stream| {
            counts.transition(stream, |counts, stream| {
                #[cfg(feature = "go-client-idle")]
                if counts.go_client_idle.is_some() {
                    actions.recv.go_client_handle_error(&err, &mut *stream);
                } else {
                    actions.recv.handle_error(&err, &mut *stream);
                }
                #[cfg(not(feature = "go-client-idle"))]
                actions.recv.handle_error(&err, &mut *stream);
                actions.send.handle_error(send_buffer, stream, counts);
            })
        });

        #[cfg(feature = "go-client-idle")]
        {
            if let Some(idle) = counts.go_client_idle.as_mut() {
                idle.closed = true;
                idle.lifecycle.close(false, false, idle.timeout);
            }
            counts.go_client_abort_reset_flights();
        }
        actions.conn_error = Some(err);

        last_processed_id
    }

    fn recv_go_away<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        frame: &frame::GoAway,
    ) -> Result<(), Error> {
        let actions = &mut self.actions;
        let counts = &mut self.counts;
        let mut send_buffer = send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        let last_stream_id = frame.last_stream_id();

        actions.send.recv_go_away(last_stream_id)?;

        let err = Error::remote_go_away(frame.debug_data().clone(), frame.reason());

        let peer = counts.peer();
        self.store.for_each(|stream| {
            if stream.id > last_stream_id && peer.is_local_init(stream.id) {
                counts.transition(stream, |counts, stream| {
                    actions.recv.handle_error(&err, &mut *stream);
                    actions.send.handle_error(send_buffer, stream, counts);
                })
            }
        });

        actions.conn_error = Some(err);

        Ok(())
    }

    fn recv_push_promise<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        frame: frame::PushPromise,
    ) -> Result<RecvOutcome, Error> {
        let id = frame.stream_id();
        let promised_id = frame.promised_id();

        // First, ensure that the initiating stream is still in a valid state.
        let parent_key = match self.store.find_mut(&id) {
            Some(stream) => {
                // The GOAWAY process has begun. All streams with a greater ID
                // than specified as part of GOAWAY should be ignored.
                if id > self.actions.recv.max_stream_id() {
                    tracing::trace!(
                        "id ({:?}) > max_stream_id ({:?}), ignoring PUSH_PROMISE",
                        id,
                        self.actions.recv.max_stream_id()
                    );
                    return Ok(RecvOutcome::Processed);
                }

                // The stream must be receive open
                if !stream.state.ensure_recv_open()? {
                    proto_err!(conn: "recv_push_promise: initiating stream is not opened");
                    return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
                }

                stream.key()
            }
            None => {
                proto_err!(conn: "recv_push_promise: initiating stream is in an invalid state");
                return Err(Error::library_go_away(Reason::PROTOCOL_ERROR));
            }
        };

        // Ensure that we can reserve streams
        self.actions.recv.ensure_can_reserve()?;

        // Next, open the stream.
        //
        // If `None` is returned, then the stream is being refused. There is no
        // further work to be done.
        if self
            .actions
            .recv
            .open(promised_id, Open::PushPromise, &mut self.counts)?
            .is_none()
        {
            return Ok(RecvOutcome::Refused(promised_id));
        }

        // Try to handle the frame and create a corresponding key for the pushed stream
        // this requires a bit of indirection to make the borrow checker happy.
        let child_key: Option<store::Key> = {
            // Create state for the stream
            let stream = self.store.insert(promised_id, {
                Stream::new(
                    promised_id,
                    self.actions.send.init_window_sz(),
                    self.actions.recv.init_window_sz(),
                )
            });

            let actions = &mut self.actions;

            self.counts.transition(stream, |counts, stream| {
                // RFC 9113 excludes reserved streams from the concurrent stream
                // count. Still, account reserved remote streams against the local
                // receive limit so a peer cannot create an unbounded number of
                // them by withholding the response HEADERS. `recv_headers` will
                // see `is_counted` and avoid counting the stream a second time.
                counts.inc_num_recv_streams(stream);
                let stream_valid = actions.recv.recv_push_promise(frame, stream);

                match stream_valid {
                    Ok(()) => Ok(Some(stream.key())),
                    _ => {
                        let mut send_buffer = send_buffer.inner.lock().unwrap();
                        actions
                            .reset_on_recv_stream_err(
                                &mut *send_buffer,
                                stream,
                                counts,
                                stream_valid,
                            )
                            .map(|()| None)
                    }
                }
            })?
        };
        // If we're successful, push the headers and stream...
        if let Some(child) = child_key {
            let mut ppp = self.store[parent_key].pending_push_promises.take();
            ppp.push(&mut self.store.resolve(child));

            let parent = &mut self.store.resolve(parent_key);
            parent.pending_push_promises = ppp;
            parent.notify_push();
        };

        Ok(RecvOutcome::Processed)
    }

    fn recv_eof<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        clear_pending_accept: bool,
    ) -> Result<(), ()> {
        let actions = &mut self.actions;
        let counts = &mut self.counts;
        let mut send_buffer = send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        if actions.conn_error.is_none() {
            actions.conn_error = Some(
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "connection closed because of a broken pipe",
                )
                .into(),
            );
        }

        tracing::trace!("Streams::recv_eof");

        self.store.for_each(|stream| {
            counts.transition(stream, |counts, stream| {
                #[cfg(feature = "go-client-idle")]
                if counts.go_client_idle.is_some() {
                    actions.recv.go_client_recv_eof(stream);
                } else {
                    actions.recv.recv_eof(stream);
                }
                #[cfg(not(feature = "go-client-idle"))]
                actions.recv.recv_eof(stream);

                // This handles resetting send state associated with the
                // stream
                actions.send.handle_error(send_buffer, stream, counts);
            })
        });

        #[cfg(feature = "go-client-idle")]
        {
            if let Some(idle) = counts.go_client_idle.as_mut() {
                idle.closed = true;
                idle.lifecycle.close(false, false, idle.timeout);
            }
            counts.go_client_abort_reset_flights();
        }
        actions.clear_queues(clear_pending_accept, &mut self.store, counts);
        Ok(())
    }

    fn buffer_pending<T, B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        dst: &mut Codec<T, Prioritized<B>>,
    ) -> io::Result<BufferStatus>
    where
        T: AsyncWrite + Unpin,
        B: Buf,
    {
        let mut send_buffer = send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        // Send WINDOW_UPDATE frames first
        //
        // TODO: It would probably be better to interleave updates w/ data
        // frames.
        if self
            .actions
            .recv
            .buffer_pending(&mut self.store, &mut self.counts, dst)?
            == BufferStatus::CodecFull
        {
            return Ok(BufferStatus::CodecFull);
        }

        // Send any other pending frames
        if self
            .actions
            .send
            .buffer_pending(send_buffer, &mut self.store, &mut self.counts, dst)?
            == BufferStatus::CodecFull
        {
            return Ok(BufferStatus::CodecFull);
        }

        Ok(BufferStatus::Complete)
    }

    fn reclaim_written_frame<T, B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        dst: &mut Codec<T, Prioritized<B>>,
    ) -> bool
    where
        B: Buf,
    {
        let mut send_buffer = send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        self.actions
            .send
            .reclaim_written_frame(send_buffer, &mut self.store, dst)
    }

    fn send_reset<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        id: StreamId,
        reason: Reason,
    ) -> Result<(), crate::proto::error::GoAway> {
        #[cfg(feature = "go-client-idle")]
        if self.counts.go_client_idle.is_some() {
            let known = self.store.find_mut(&id).is_some_and(|stream| {
                !stream.state.is_reset() && !self.counts.go_client_clean_eos(&stream)
            });
            if !known {
                // Go streamByID excludes unknown, aborted, and forgotten
                // completed streams, even while Rust body references survive.
                return Ok(());
            }
        }
        let key = match self.store.find_entry(id) {
            Entry::Occupied(e) => e.key(),
            Entry::Vacant(e) => {
                // Resetting a stream we don't know about? That could be OK...
                //
                // 1. As a server, we just received a request, but that request
                //    was bad, so we're resetting before even accepting it.
                //    This is totally fine.
                //
                // 2. The remote may have sent us a frame on new stream that
                //    it's *not* supposed to have done, and thus, we don't know
                //    the stream. In that case, sending a reset will "open" the
                //    stream in our store. Maybe that should be a connection
                //    error instead? At least for now, we need to update what
                //    our vision of the next stream is.
                if self.counts.peer().is_local_init(id) {
                    // We normally would open this stream, so update our
                    // next-send-id record.
                    self.actions.send.maybe_reset_next_stream_id(id);
                } else {
                    // We normally would recv this stream, so update our
                    // next-recv-id record.
                    self.actions.recv.maybe_reset_next_stream_id(id);
                }

                let stream = Stream::new(id, 0, 0);

                e.insert(stream)
            }
        };

        let stream = self.store.resolve(key);
        let mut send_buffer = send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;
        self.actions.send_reset(
            stream,
            reason,
            Initiator::Library,
            &mut self.counts,
            send_buffer,
        )
    }
}

impl<B> Streams<B, client::Peer>
where
    B: Buf,
{
    pub fn poll_pending_open(
        &mut self,
        cx: &Context,
        pending: Option<&OpaqueStreamRef>,
    ) -> Poll<Result<(), crate::Error>> {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        me.actions.ensure_no_conn_error()?;
        me.actions.send.ensure_next_stream_id()?;

        if let Some(pending) = pending {
            let mut stream = me.store.resolve(pending.key);
            tracing::trace!("poll_pending_open; stream = {:?}", stream.is_pending_open);
            if stream.is_pending_open {
                stream.wait_send(cx);
                return Poll::Pending;
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<B, P> Streams<B, P>
where
    P: Peer,
{
    pub fn as_dyn(&self) -> DynStreams<'_, B> {
        let Self {
            inner,
            send_buffer,
            _p,
        } = self;
        DynStreams {
            inner,
            send_buffer,
            peer: P::r#dyn(),
        }
    }

    /// This function is safe to call multiple times.
    ///
    /// A `Result` is returned to avoid panicking if the mutex is poisoned.
    pub fn recv_eof(&mut self, clear_pending_accept: bool) -> Result<(), ()> {
        self.as_dyn().recv_eof(clear_pending_accept)
    }

    pub(crate) fn max_send_streams(&self) -> usize {
        self.inner.lock().unwrap().counts.max_send_streams()
    }

    pub(crate) fn max_recv_streams(&self) -> usize {
        self.inner.lock().unwrap().counts.max_recv_streams()
    }

    #[cfg(feature = "unstable")]
    pub fn num_active_streams(&self) -> usize {
        let me = self.inner.lock().unwrap();
        me.store.num_active_streams()
    }

    pub fn has_streams(&self) -> bool {
        let me = self.inner.lock().unwrap();
        me.counts.has_streams()
    }

    pub fn has_streams_or_other_references(&self) -> bool {
        let me = self.inner.lock().unwrap();
        me.counts.has_streams() || me.refs > 1
    }

    #[cfg(feature = "unstable")]
    pub fn num_wired_streams(&self) -> usize {
        let me = self.inner.lock().unwrap();
        me.store.num_wired_streams()
    }
}

// no derive because we don't need B and P to be Clone.
impl<B, P> Clone for Streams<B, P>
where
    P: Peer,
{
    fn clone(&self) -> Self {
        self.inner.lock().unwrap().refs += 1;
        Streams {
            inner: self.inner.clone(),
            send_buffer: self.send_buffer.clone(),
            _p: ::std::marker::PhantomData,
        }
    }
}

impl<B, P> Drop for Streams<B, P>
where
    P: Peer,
{
    fn drop(&mut self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.refs -= 1;
            if inner.refs == 1 {
                if let Some(task) = inner.actions.task.take() {
                    task.wake();
                }
            }
        }
    }
}

// ===== impl StreamRef =====

impl<B> StreamRef<B> {
    pub fn send_data(&mut self, data: B, end_stream: bool) -> Result<(), UserError>
    where
        B: Buf,
    {
        let mut me = self.opaque.inner.lock().unwrap();
        let me = &mut *me;

        let stream = me.store.resolve(self.opaque.key);
        let actions = &mut me.actions;
        let mut send_buffer = self.send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        me.counts.transition(stream, |counts, stream| {
            // Create the data frame
            let mut frame = frame::Data::new(stream.id, data);
            frame.set_end_stream(end_stream);

            // Send the data frame
            actions
                .send
                .send_data(frame, send_buffer, stream, counts, &mut actions.task)
        })
    }

    pub fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), UserError> {
        let mut me = self.opaque.inner.lock().unwrap();
        let me = &mut *me;

        let stream = me.store.resolve(self.opaque.key);
        let actions = &mut me.actions;
        let mut send_buffer = self.send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        me.counts.transition(stream, |counts, stream| {
            // Create the trailers frame
            let frame = frame::Headers::trailers(stream.id, trailers);

            // Send the trailers frame
            actions
                .send
                .send_trailers(frame, send_buffer, stream, counts, &mut actions.task)
        })
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_poll_request_headers(
        &mut self,
        cx: &Context<'_>,
    ) -> Poll<Result<(), proto::Error>> {
        let mut locked = self.opaque.inner.lock().unwrap();
        let inner = &mut *locked;
        let mut stream = inner.store.resolve(self.opaque.key);
        // Go abortRequestBodyWrite closes the body independently of wmu.
        // An abort must interrupt the header wait, while reset cleanup keeps
        // its separate flight/donec ownership until the writer is released.
        inner.actions.ensure_no_conn_error()?;
        stream.state.go_client_ensure_send_open()?;
        if let Some(gate) = &stream.go_client_header_gate {
            if gate.poll_ready(cx).is_pending() {
                stream.wait_send(cx);
                return Poll::Pending;
            }
        }
        Poll::Ready(Ok(()))
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_send_protocol_reset(&mut self, reason: Reason) {
        let mut locked = self.opaque.inner.lock().unwrap();
        let inner = &mut *locked;
        if inner.counts.go_client_idle.is_none() {
            return;
        }
        let stream = inner.store.resolve(self.opaque.key);
        let mut buffer = self.send_buffer.inner.lock().unwrap();
        let actions = &mut inner.actions;
        inner.counts.transition(stream, |counts, stream| {
            if !stream.state.is_reset() {
                let _ = counts.go_client_protocol_reset(stream, reason, true);
                actions.send.send_reset(
                    reason,
                    Initiator::User,
                    &mut buffer,
                    stream,
                    counts,
                    &mut actions.task,
                );
                stream.notify_recv();
            }
        });
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_receive_request_body_error(&mut self, error: proto::Error) {
        let mut locked = self.opaque.inner.lock().unwrap();
        let inner = &mut *locked;
        if inner.counts.go_client_idle.is_none() {
            return;
        }
        let stream = inner.store.resolve(self.opaque.key);
        let mut buffer = self.send_buffer.inner.lock().unwrap();
        let actions = &mut inner.actions;
        inner.counts.transition(stream, |counts, stream| {
            if stream.state.is_reset()
                || stream.go_client_reset_owned
                || counts.go_client_clean_eos(stream)
            {
                return;
            }
            let done = counts.go_client_close_gate(stream.id);
            if !stream.go_client_headers_sent {
                // A pre-header abort must still pass the header writer's abort
                // check, but has no wire reset or PING to send.
                let _ = counts.go_client_protocol_reset(stream, Reason::NO_ERROR, false);
            }
            stream.go_client_reset_owned = true;
            stream.go_client_error_done_gate = done;
            // errFromPeer skips writeStreamReset and closes the pipe before
            // forgetStream/final wmu. Preserve the originating stream error.
            if !(stream.state.is_recv_end_stream() && stream.state.is_send_closed()) {
                actions.recv.go_client_handle_error(&error, stream);
            }
            actions.send.handle_error(&mut buffer, stream, counts);
        });
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_send_request_body_error(&mut self) {
        let mut locked = self.opaque.inner.lock().unwrap();
        let inner = &mut *locked;
        if inner.counts.go_client_idle.is_none() {
            return;
        }
        let stream = inner.store.resolve(self.opaque.key);
        let mut buffer = self.send_buffer.inner.lock().unwrap();
        let actions = &mut inner.actions;
        inner.counts.transition(stream, |counts, stream| {
            if !stream.state.is_reset() {
                let _ = counts.go_client_body_error(stream);
                actions.send.send_reset(
                    Reason::CANCEL,
                    Initiator::User,
                    &mut buffer,
                    stream,
                    counts,
                    &mut actions.task,
                );
                stream.notify_recv();
            }
        });
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_cancel_request_after_response(&mut self) {
        // Context cancellation is independent of NoBody.Close's no-op rule.
        self.send_reset(Reason::CANCEL);
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_poll_finish_request_body(
        &mut self,
        cx: &Context<'_>,
    ) -> Poll<Result<(), proto::Error>> {
        let mut locked = self.opaque.inner.lock().unwrap();
        let inner = &mut *locked;
        if inner.counts.go_client_idle.is_none() {
            return Poll::Ready(Err(io::Error::other(
                "native request cleanup requires native client mode",
            )
            .into()));
        }
        let stream = inner.store.resolve(self.opaque.key);
        let actions = &mut inner.actions;
        let mut buffer = self.send_buffer.inner.lock().unwrap();
        inner.counts.transition(stream, |counts, stream| {
            if stream.go_client_finish.is_none() {
                let error = match stream.state.ensure_recv_open() {
                    Ok(true) => {
                        stream.go_client_finish_task = Some(cx.waker().clone());
                        return Poll::Pending;
                    }
                    Ok(false) => None,
                    Err(error) => Some(error),
                };
                let gate = counts.go_client_close_gate(stream.id);
                if error.is_none() && !stream.state.is_send_closed() {
                    let _ = counts.go_client_protocol_reset(stream, Reason::NO_ERROR, false);
                    actions.send.send_reset(
                        Reason::NO_ERROR,
                        Initiator::User,
                        &mut buffer,
                        stream,
                        counts,
                        &mut actions.task,
                    );
                }
                stream.go_client_finish = Some((error, gate));
            }
            let (error, gate) = stream.go_client_finish.as_ref().unwrap();
            if let Some(gate) = gate {
                if gate.poll_ready(cx).is_pending() {
                    return Poll::Pending;
                }
            }
            Poll::Ready(match error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            })
        })
    }

    pub fn send_reset(&mut self, reason: Reason) {
        let mut me = self.opaque.inner.lock().unwrap();
        let me = &mut *me;

        let stream = me.store.resolve(self.opaque.key);
        let mut send_buffer = self.send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        match me
            .actions
            .send_reset(stream, reason, Initiator::User, &mut me.counts, send_buffer)
        {
            Ok(()) => (),
            Err(crate::proto::error::GoAway { .. }) => {
                // this should never happen, because Initiator::User resets do
                // not count toward the local limit.
                // we could perhaps make this state impossible, if we made the
                // initiator argument a generic, and so this could return
                // Infallible instead of an impossible GoAway, but oh well.
                unreachable!("Initiator::User should not error sending reset");
            }
        }
    }

    pub fn send_informational_headers(&mut self, frame: frame::Headers) -> Result<(), UserError> {
        let mut me = self.opaque.inner.lock().unwrap();
        let me = &mut *me;

        let stream = me.store.resolve(self.opaque.key);
        let actions = &mut me.actions;
        let mut send_buffer = self.send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        me.counts.transition(stream, |counts, stream| {
            // For informational responses (1xx), we need to send headers without
            // changing the stream state. This allows multiple informational responses
            // to be sent before the final response.

            // Validate that this is actually an informational response
            debug_assert!(
                frame.is_informational(),
                "Frame must be informational after conversion from informational response"
            );

            // Ensure the frame is not marked as end_stream for informational responses
            if frame.is_end_stream() {
                return Err(UserError::UnexpectedFrameType);
            }

            // Send the interim informational headers directly to the buffer without state changes
            // This bypasses the normal send_headers flow that would transition the stream state
            actions.send.send_interim_informational_headers(
                frame,
                send_buffer,
                stream,
                counts,
                &mut actions.task,
            )
        })
    }

    pub fn send_response(
        &mut self,
        mut response: Response<()>,
        end_of_stream: bool,
    ) -> Result<(), UserError> {
        // Clear before taking lock, incase extensions contain a StreamRef.
        response.extensions_mut().clear();
        let mut me = self.opaque.inner.lock().unwrap();
        let me = &mut *me;

        let stream = me.store.resolve(self.opaque.key);
        let actions = &mut me.actions;
        let mut send_buffer = self.send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        me.counts.transition(stream, |counts, stream| {
            let frame = server::Peer::convert_send_message(stream.id, response, end_of_stream);

            actions
                .send
                .send_headers(frame, send_buffer, stream, counts, &mut actions.task)
        })
    }

    pub fn send_push_promise(
        &mut self,
        mut request: Request<()>,
    ) -> Result<StreamRef<B>, UserError> {
        // Clear before taking lock, incase extensions contain a StreamRef.
        request.extensions_mut().clear();
        let mut me = self.opaque.inner.lock().unwrap();
        let me = &mut *me;

        let mut send_buffer = self.send_buffer.inner.lock().unwrap();
        let send_buffer = &mut *send_buffer;

        let actions = &mut me.actions;
        let promised_id = actions.send.reserve_local()?;

        let child_key = {
            let mut child_stream = me.store.insert(
                promised_id,
                Stream::new(
                    promised_id,
                    actions.send.init_window_sz(),
                    actions.recv.init_window_sz(),
                ),
            );
            child_stream.state.reserve_local()?;
            #[cfg(feature = "go-server-lifecycle")]
            me.counts.start_go_write_timeout(&mut child_stream);
            child_stream.is_pending_push = true;
            child_stream.key()
        };

        let pushed = {
            let mut stream = me.store.resolve(self.opaque.key);

            let frame = crate::server::Peer::convert_push_message(stream.id, promised_id, request)?;

            actions
                .send
                .send_push_promise(frame, send_buffer, &mut stream, &mut actions.task)
        };

        if let Err(err) = pushed {
            let mut child_stream = me.store.resolve(child_key);
            child_stream.unlink();
            child_stream.remove();
            return Err(err);
        }

        me.refs += 1;
        let opaque =
            OpaqueStreamRef::new(self.opaque.inner.clone(), &mut me.store.resolve(child_key));

        Ok(StreamRef {
            opaque,
            send_buffer: self.send_buffer.clone(),
        })
    }

    /// Called by the server after the stream is accepted. Given that clients
    /// initialize streams by sending HEADERS, the request will always be
    /// available.
    ///
    /// # Panics
    ///
    /// This function panics if the request isn't present.
    pub fn take_request(&self) -> Request<()> {
        let mut me = self.opaque.inner.lock().unwrap();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.opaque.key);
        me.actions.recv.take_request(&mut stream)
    }

    /// Called by a client to see if the current stream is pending open
    pub fn is_pending_open(&self) -> bool {
        let mut me = self.opaque.inner.lock().unwrap();
        me.store.resolve(self.opaque.key).is_pending_open
    }

    /// Request capacity to send data
    pub fn reserve_capacity(&mut self, capacity: WindowSize) {
        let mut me = self.opaque.inner.lock().unwrap();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.opaque.key);

        me.actions
            .send
            .reserve_capacity(capacity, &mut stream, &mut me.counts)
    }

    /// Returns the stream's current send capacity.
    pub fn capacity(&self) -> WindowSize {
        let mut me = self.opaque.inner.lock().unwrap();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.opaque.key);

        me.actions.send.capacity(&mut stream)
    }

    /// Request to be notified when the stream's capacity increases
    pub fn poll_capacity(&mut self, cx: &Context) -> Poll<Option<Result<WindowSize, UserError>>> {
        let mut me = self.opaque.inner.lock().unwrap();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.opaque.key);

        me.actions.send.poll_capacity(cx, &mut stream)
    }

    /// Request to be notified for if a `RST_STREAM` is received for this stream.
    pub(crate) fn poll_reset(
        &mut self,
        cx: &Context,
        mode: proto::PollReset,
    ) -> Poll<Result<Reason, crate::Error>> {
        let mut me = self.opaque.inner.lock().unwrap();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.opaque.key);

        me.actions.send.poll_reset(cx, &mut stream, mode)
    }

    pub fn clone_to_opaque(&self) -> OpaqueStreamRef {
        self.opaque.clone()
    }

    pub fn stream_id(&self) -> StreamId {
        self.opaque.stream_id()
    }
}

impl<B> Clone for StreamRef<B> {
    fn clone(&self) -> Self {
        StreamRef {
            opaque: self.opaque.clone(),
            send_buffer: self.send_buffer.clone(),
        }
    }
}

// ===== impl OpaqueStreamRef =====

impl OpaqueStreamRef {
    fn new(inner: Arc<Mutex<Inner>>, stream: &mut store::Ptr) -> OpaqueStreamRef {
        stream.ref_inc();
        OpaqueStreamRef {
            inner,
            key: stream.key(),
        }
    }
    /// Called by a client to check for a received response.
    pub fn poll_response(&mut self, cx: &Context) -> Poll<Result<Response<()>, proto::Error>> {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);

        let response = me.actions.recv.poll_response(cx, &mut stream);
        #[cfg(feature = "go-client-idle")]
        if matches!(&response, Poll::Ready(Err(_))) && me.counts.go_client_idle.is_some() {
            // ResponseFuture's abort path waits donec, unlike the pipe's error
            // close, which occurs immediately after its reset flush.
            if stream.go_client_error_done_gate.is_none() {
                stream.go_client_error_done_gate = me.counts.go_client_close_gate(stream.id);
            }
            if let Some(gate) = &stream.go_client_error_done_gate {
                if gate.poll_ready(cx).is_pending() {
                    return Poll::Pending;
                }
            }
        }
        response
    }

    /// Called by a client to check for informational responses (1xx status codes)
    pub fn poll_informational(
        &mut self,
        cx: &Context,
    ) -> Poll<Option<Result<Response<()>, proto::Error>>> {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);

        me.actions.recv.poll_informational(cx, &mut stream)
    }
    /// Called by a client to check for a pushed request.
    pub fn poll_pushed(
        &mut self,
        cx: &Context,
    ) -> Poll<Option<Result<(Request<()>, OpaqueStreamRef), proto::Error>>> {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);
        me.actions
            .recv
            .poll_pushed(cx, &mut stream)
            .map_ok(|(h, key)| {
                me.refs += 1;
                let opaque_ref =
                    OpaqueStreamRef::new(self.inner.clone(), &mut me.store.resolve(key));
                (h, opaque_ref)
            })
    }

    pub fn is_end_stream(&self) -> bool {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        let stream = me.store.resolve(self.key);

        me.actions.recv.is_end_stream(&stream)
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_poll_read(
        &mut self,
        cx: &Context<'_>,
        max: usize,
    ) -> Poll<super::recv::GoReadOutcome> {
        let mut locked = self.inner.lock().unwrap();
        let inner = &mut *locked;
        if inner.counts.go_client_idle.is_none() {
            return Poll::Ready(super::recv::GoReadOutcome {
                data: Bytes::new(),
                error: Some(
                    io::Error::other("native HTTP/2 body reader requires native client mode")
                        .into(),
                ),
                eof: false,
                gate: None,
                abort: false,
            });
        }
        let stream = inner.store.resolve(self.key);
        let actions = &mut inner.actions;
        inner.counts.transition(stream, |counts, stream| {
            let mut outcome = actions
                .recv
                .go_poll_read(cx, stream, max, counts, &mut actions.task);
            if let Poll::Ready(outcome) = &mut outcome {
                if outcome.data.is_empty()
                    && outcome.error.is_some()
                    && !outcome.abort
                    && stream.is_recv
                    && actions.recv.go_body_is_transport(stream)
                    && !actions.recv.go_body_has_read_error(stream)
                {
                    outcome.gate = stream.go_client_error_pipe_gate.clone();
                }
            }
            if matches!(&outcome, Poll::Ready(outcome) if outcome.abort) {
                let _ = counts.go_client_cancel(stream);
                actions.send.schedule_implicit_reset(
                    stream,
                    Reason::CANCEL,
                    counts,
                    &mut actions.task,
                );
            }
            if counts
                .go_client_idle
                .as_ref()
                .is_some_and(|idle| idle.closed)
            {
                // Buffered bytes remain readable after connection completion.
                // A newly captured refund has no writer and fails immediately;
                // Go's body reader ignores that writer error.
                actions.recv.abort_go_body_refunds();
            }
            outcome
        })
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_body_is_transport(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.counts.go_client_idle.is_some()
            && inner
                .actions
                .recv
                .go_body_is_transport(&inner.store[self.key])
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_body_is_no_body(&self) -> bool {
        let inner = self.inner.lock().unwrap();
        inner.counts.go_client_idle.is_some()
            && inner
                .actions
                .recv
                .go_body_is_no_body(&inner.store[self.key])
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_start_body_close(
        &mut self,
    ) -> (
        Option<super::recv::GoReadGate>,
        Option<super::recv::GoReadGate>,
    ) {
        let mut locked = self.inner.lock().unwrap();
        let inner = &mut *locked;
        if inner.counts.go_client_idle.is_none() {
            return (None, None);
        }
        let stream = inner.store.resolve(self.key);
        if !inner.actions.recv.go_body_is_transport(&stream) {
            return (None, None);
        }
        let done = inner.counts.go_client_close_gate(stream.id);
        let actions = &mut inner.actions;
        let refund = inner.counts.transition(stream, |counts, stream| {
            let _ = counts.go_client_cancel(stream);
            actions
                .send
                .schedule_implicit_reset(stream, Reason::CANCEL, counts, &mut actions.task);
            let refund = actions
                .recv
                .go_close_body(stream, counts, &mut actions.task);
            if counts
                .go_client_idle
                .as_ref()
                .is_some_and(|idle| idle.closed)
            {
                actions.recv.abort_go_body_refunds();
            }
            refund
        });
        (refund, done)
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_drop_body(&mut self, start: bool) {
        let mut locked = self.inner.lock().unwrap();
        let inner = &mut *locked;
        let mut stream = inner.store.resolve(self.key);
        let actions = &mut inner.actions;
        if start
            && inner.counts.go_client_idle.is_some()
            && actions.recv.go_body_is_transport(&stream)
        {
            inner.counts.transition(stream, |counts, stream| {
                let _ = counts.go_client_cancel(stream);
                actions.send.schedule_implicit_reset(
                    stream,
                    Reason::CANCEL,
                    counts,
                    &mut actions.task,
                );
                let _ = actions
                    .recv
                    .go_close_body(stream, counts, &mut actions.task);
                if counts
                    .go_client_idle
                    .as_ref()
                    .is_some_and(|idle| idle.closed)
                {
                    actions.recv.abort_go_body_refunds();
                }
                stream.is_recv = false;
                actions
                    .recv
                    .clear_recv_buffer(stream, &mut actions.task, counts);
            });
        } else {
            stream.is_recv = false;
            actions
                .recv
                .clear_recv_buffer(&mut stream, &mut actions.task, &mut inner.counts);
        }
    }

    pub fn poll_data(&mut self, cx: &Context) -> Poll<Option<Result<Bytes, proto::Error>>> {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);

        me.actions
            .recv
            .poll_data(cx, &mut stream)
            .map(|result| match result {
                Some(Ok(data)) => {
                    if data.is_budgeted {
                        me.counts.release_data_frame(data.budget_len());
                    }
                    Some(Ok(data.payload))
                }
                Some(Err(err)) => Some(Err(err)),
                None => None,
            })
    }

    pub fn poll_trailers(&mut self, cx: &Context) -> Poll<Option<Result<HeaderMap, proto::Error>>> {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);

        me.actions.recv.poll_trailers(cx, &mut stream)
    }

    pub(crate) fn available_recv_capacity(&self) -> isize {
        let me = self.inner.lock().unwrap();
        let me = &*me;

        let stream = &me.store[self.key];
        stream.recv_flow.available().into()
    }

    pub(crate) fn used_recv_capacity(&self) -> WindowSize {
        let me = self.inner.lock().unwrap();
        let me = &*me;

        let stream = &me.store[self.key];
        stream.in_flight_recv_data
    }

    /// Releases recv capacity back to the peer. This may result in sending
    /// WINDOW_UPDATE frames on both the stream and connection.
    pub fn release_capacity(&mut self, capacity: WindowSize) -> Result<(), UserError> {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);

        me.actions
            .recv
            .release_capacity(capacity, &mut stream, &mut me.actions.task)
    }

    /// Clear the receive queue and set the status to no longer receive data frames.
    #[cfg(not(feature = "go-client-idle"))]
    pub(crate) fn clear_recv_buffer(&mut self) {
        let mut me = self.inner.lock().unwrap();
        let me = &mut *me;

        let mut stream = me.store.resolve(self.key);
        stream.is_recv = false;
        me.actions
            .recv
            .clear_recv_buffer(&mut stream, &mut me.actions.task, &mut me.counts);
    }

    pub fn stream_id(&self) -> StreamId {
        self.inner.lock().unwrap().store[self.key].id
    }
}

impl fmt::Debug for OpaqueStreamRef {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use std::sync::TryLockError::*;

        match self.inner.try_lock() {
            Ok(me) => {
                let stream = &me.store[self.key];
                fmt.debug_struct("OpaqueStreamRef")
                    .field("stream_id", &stream.id)
                    .field("ref_count", &stream.ref_count)
                    .finish()
            }
            Err(Poisoned(_)) => fmt
                .debug_struct("OpaqueStreamRef")
                .field("inner", &"<Poisoned>")
                .finish(),
            Err(WouldBlock) => fmt
                .debug_struct("OpaqueStreamRef")
                .field("inner", &"<Locked>")
                .finish(),
        }
    }
}

impl Clone for OpaqueStreamRef {
    fn clone(&self) -> Self {
        // Increment the ref count
        let mut inner = self.inner.lock().unwrap();
        inner.store.resolve(self.key).ref_inc();
        inner.refs += 1;

        OpaqueStreamRef {
            inner: self.inner.clone(),
            key: self.key,
        }
    }
}

impl Drop for OpaqueStreamRef {
    fn drop(&mut self) {
        drop_stream_ref(&self.inner, self.key);
    }
}

// TODO: Move back in fn above
fn drop_stream_ref(inner: &Mutex<Inner>, key: store::Key) {
    let mut me = match inner.lock() {
        Ok(inner) => inner,
        Err(_) => {
            if ::std::thread::panicking() {
                tracing::trace!("StreamRef::drop; mutex poisoned");
                return;
            } else {
                panic!("StreamRef::drop; mutex poisoned");
            }
        }
    };

    let me = &mut *me;
    me.refs -= 1;
    let mut stream = me.store.resolve(key);

    tracing::trace!("drop_stream_ref; stream={:?}", stream);

    // decrement the stream's ref count by 1.
    stream.ref_dec();

    let actions = &mut me.actions;

    // If the stream is not referenced and it is already
    // closed (does not have to go through logic below
    // of canceling the stream), we should notify the task
    // (connection) so that it can close properly
    if stream.ref_count == 0 && stream.is_closed() {
        if let Some(task) = actions.task.take() {
            task.wake();
        }
    }

    me.counts.transition(stream, |counts, stream| {
        maybe_cancel(stream, actions, counts);

        if stream.ref_count == 0 {
            // Release any recv window back to connection, no one can access
            // it anymore.
            actions
                .recv
                .release_closed_capacity(stream, &mut actions.task, counts);

            // We won't be able to reach our push promises anymore
            let mut ppp = stream.pending_push_promises.take();
            while let Some(promise) = ppp.pop(stream.store_mut()) {
                counts.transition(promise, |counts, stream| {
                    maybe_cancel(stream, actions, counts);
                });
            }
        }
    });
}

fn maybe_cancel(stream: &mut store::Ptr, actions: &mut Actions, counts: &mut Counts) {
    #[cfg(feature = "go-client-idle")]
    if counts.go_client_idle.is_some() && stream.go_client_body_ignores_close && !stream.is_recv {
        return;
    }
    if stream.is_canceled_interest() {
        // Server is allowed to early respond without fully consuming the client input stream
        // But per the RFC, must send a RST_STREAM(NO_ERROR) in such cases. https://www.rfc-editor.org/rfc/rfc7540#section-8.1
        // Some other http2 implementation may interpret other error code as fatal if not respected (i.e: nginx https://trac.nginx.org/nginx/ticket/2376)
        let reason = if counts.peer().is_server()
            && stream.state.is_send_closed()
            && stream.state.is_recv_streaming()
        {
            Reason::NO_ERROR
        } else {
            Reason::CANCEL
        };

        #[cfg(feature = "go-client-idle")]
        if reason == Reason::CANCEL {
            let _ = counts.go_client_cancel(stream);
        }
        actions
            .send
            .schedule_implicit_reset(stream, reason, counts, &mut actions.task);
        actions.recv.enqueue_reset_expiration(stream, counts);
    }
}

// ===== impl SendBuffer =====

impl<B> SendBuffer<B> {
    fn new() -> Self {
        let inner = Mutex::new(Buffer::new());
        SendBuffer { inner }
    }

    pub fn is_empty(&self) -> bool {
        let buf = self.inner.lock().unwrap();
        buf.is_empty()
    }
}

// ===== impl Actions =====

impl Actions {
    fn send_reset<B>(
        &mut self,
        stream: store::Ptr,
        reason: Reason,
        initiator: Initiator,
        counts: &mut Counts,
        send_buffer: &mut Buffer<Frame<B>>,
    ) -> Result<(), crate::proto::error::GoAway> {
        counts.transition(stream, |counts, stream| {
            if initiator.is_library() {
                if counts.can_inc_num_local_error_resets() {
                    counts.inc_num_local_error_resets();
                } else {
                    tracing::warn!(
                        "locally-reset streams reached limit ({:?})",
                        counts.max_local_error_resets().unwrap(),
                    );
                    return Err(crate::proto::error::GoAway {
                        reason: Reason::ENHANCE_YOUR_CALM,
                        debug_data: "too_many_internal_resets".into(),
                    });
                }
            }

            #[cfg(feature = "go-client-idle")]
            if initiator == Initiator::User && reason == Reason::CANCEL && !stream.state.is_reset()
            {
                let _ = counts.go_client_cancel(stream);
            }
            self.send.send_reset(
                reason,
                initiator,
                send_buffer,
                stream,
                counts,
                &mut self.task,
            );
            self.recv.enqueue_reset_expiration(stream, counts);
            // if a RecvStream is parked, ensure it's notified
            stream.notify_recv();

            Ok(())
        })
    }

    fn reset_on_recv_stream_err_deferred<B>(
        &mut self,
        send_buffer: &SendBuffer<B>,
        stream: &mut store::Ptr,
        counts: &mut Counts,
        res: Result<(), Error>,
    ) -> Result<(), Error> {
        if matches!(res, Err(Error::Reset(..))) {
            let mut send_buffer = send_buffer.inner.lock().unwrap();
            self.reset_on_recv_stream_err(&mut send_buffer, stream, counts, res)
        } else {
            res
        }
    }

    fn reset_on_recv_stream_err<B>(
        &mut self,
        buffer: &mut Buffer<Frame<B>>,
        stream: &mut store::Ptr,
        counts: &mut Counts,
        res: Result<(), Error>,
    ) -> Result<(), Error> {
        if let Err(Error::Reset(stream_id, reason, initiator)) = res {
            debug_assert_eq!(stream_id, stream.id);

            if counts.can_inc_num_local_error_resets() {
                counts.inc_num_local_error_resets();

                // Reset the stream.
                self.send
                    .send_reset(reason, initiator, buffer, stream, counts, &mut self.task);
                self.recv.enqueue_reset_expiration(stream, counts);
                // if a RecvStream is parked, ensure it's notified
                stream.notify_recv();
                Ok(())
            } else {
                tracing::warn!(
                    "reset_on_recv_stream_err; locally-reset streams reached limit ({:?})",
                    counts.max_local_error_resets().unwrap(),
                );
                Err(Error::library_go_away_data(
                    Reason::ENHANCE_YOUR_CALM,
                    "too_many_internal_resets",
                ))
            }
        } else {
            res
        }
    }

    fn ensure_not_idle(&mut self, peer: peer::Dyn, id: StreamId) -> Result<(), Reason> {
        if peer.is_local_init(id) {
            self.send.ensure_not_idle(id)
        } else {
            self.recv.ensure_not_idle(id)
        }
    }

    fn ensure_no_conn_error(&self) -> Result<(), proto::Error> {
        if let Some(ref err) = self.conn_error {
            Err(err.clone())
        } else {
            Ok(())
        }
    }

    /// Check if we possibly could have processed and since forgotten this stream.
    ///
    /// If we send a RST_STREAM for a stream, we will eventually "forget" about
    /// the stream to free up memory. It's possible that the remote peer had
    /// frames in-flight, and by the time we receive them, our own state is
    /// gone. We *could* tear everything down by sending a GOAWAY, but it
    /// is more likely to be latency/memory constraints that caused this,
    /// and not a bad actor. So be less catastrophic, the spec allows
    /// us to send another RST_STREAM of STREAM_CLOSED.
    fn may_have_forgotten_stream(&self, peer: peer::Dyn, id: StreamId) -> bool {
        if id.is_zero() {
            return false;
        }
        if peer.is_local_init(id) {
            self.send.may_have_created_stream(id)
        } else {
            self.recv.may_have_created_stream(id)
        }
    }

    fn clear_queues(&mut self, clear_pending_accept: bool, store: &mut Store, counts: &mut Counts) {
        self.recv.clear_queues(clear_pending_accept, store, counts);
        self.send.clear_queues(store, counts);
    }
}
