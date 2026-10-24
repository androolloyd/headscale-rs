use super::*;

#[derive(Debug)]
struct Budget {
    spent: usize,
    max: usize,
}

#[derive(Debug)]
pub(super) struct BudgetExhausted;

impl Budget {
    fn new(max: usize) -> Self {
        Budget { spent: 0, max }
    }

    fn consume(&mut self, amount: usize) -> Result<(), BudgetExhausted> {
        let spent = self.spent.checked_add(amount).ok_or(BudgetExhausted)?;
        if spent > self.max {
            return Err(BudgetExhausted);
        }
        self.spent = spent;
        Ok(())
    }

    fn replenish(&mut self, amount: usize) {
        self.spent = self.spent.saturating_sub(amount);
    }

    fn set_max(&mut self, max: usize) {
        self.max = max;
    }

    #[cfg(test)]
    fn available(&self) -> usize {
        self.max.saturating_sub(self.spent)
    }
}

#[derive(Debug)]
pub(super) struct Counts {
    #[cfg(feature = "go-client-idle")]
    pub(super) go_client_idle: Option<GoClientIdle>,
    #[cfg(feature = "go-server-lifecycle")]
    go_idle_timeout: Option<Duration>,
    #[cfg(feature = "go-server-lifecycle")]
    go_idle_deadline: Option<tokio::time::Instant>,
    #[cfg(feature = "go-server-lifecycle")]
    go_read_timeout: Option<Duration>,
    #[cfg(feature = "go-server-lifecycle")]
    go_write_timeout: Option<Duration>,
    #[cfg(feature = "go-server-lifecycle")]
    go_deadline_generation: u64,
    /// Acting as a client or server. This allows us to track which values to
    /// inc / dec.
    peer: peer::Dyn,

    /// Maximum number of locally initiated streams
    max_send_streams: usize,

    /// Current number of remote initiated streams
    num_send_streams: usize,

    /// Maximum number of remote initiated streams
    max_recv_streams: usize,

    /// Current number of locally initiated streams
    num_recv_streams: usize,

    /// Maximum number of pending locally reset streams
    max_local_reset_streams: usize,

    /// Current number of pending locally reset streams
    num_local_reset_streams: usize,

    /// Max number of "pending accept" streams that were remotely reset
    max_remote_reset_streams: usize,

    /// Current number of "pending accept" streams that were remotely reset
    num_remote_reset_streams: usize,

    /// Maximum number of locally reset streams due to protocol error across
    /// the lifetime of the connection.
    ///
    /// When this gets exceeded, we issue GOAWAYs.
    max_local_error_reset_streams: Option<usize>,

    /// Total number of locally reset streams due to protocol error across the
    /// lifetime of the connection.
    num_local_error_reset_streams: usize,

    /// connection-level budget for DATA framing overhead.
    data_frame_budget: Budget,

    /// Whether the DATA frame budget follows the target connection window.
    data_frame_budget_is_auto: bool,

    /// Number of empty, non-final DATA frames received over the lifetime of
    /// the connection.
    num_recv_empty_data_frames: usize,
}

// Selected Go net/http/h2_bundle.go: the client timer is independent of
// concurrency limits and of the server's GOAWAY idle lifecycle.
#[cfg(feature = "go-client-idle")]
#[derive(Debug)]
pub(super) struct GoClientIdle {
    pub timeout: Duration,
    pub last_idle: Option<std::time::SystemTime>,
    pub deadline: Option<tokio::time::Instant>,
    pub reserved: usize,
    pub active: usize,
    pub waiting: usize,
    pub pending_resets: usize,
    pub reset_pings_blocked: bool,
    pub read_before_stream: StreamId,
    pub reset_ping_payload: Option<fn() -> [u8; 8]>,
    pub reset_flights: std::collections::VecDeque<GoResetFlight>,
    pub stream_flights: std::collections::HashMap<StreamId, GoStreamFlight>,
    pub pending_finished: std::collections::VecDeque<StreamId>,
    pub cleanup_work: bool,
    pub header_waiters: std::collections::VecDeque<GoHeaderWaiter>,
    pub header_flight: Option<GoHeaderFlight>,
    pub cleanup_done: std::collections::HashMap<StreamId, Option<super::recv::GoReadGate>>,
    pub unsent_done: std::collections::VecDeque<super::recv::GoReadGate>,
    pub do_not_reuse: bool,
    pub lifecycle: std::sync::Arc<super::client_state::GoLifecycle>,
    pub closed: bool,
    pub task: Option<std::task::Waker>,
}

#[cfg(feature = "go-client-idle")]
#[derive(Debug)]
pub(super) struct GoHeaderWaiter {
    pub key: std::sync::Arc<()>,
    pub waker: std::task::Waker,
}

#[cfg(feature = "go-client-idle")]
#[derive(Debug)]
pub(super) struct GoHeaderFlight {
    pub header_gate: super::recv::GoReadGate,
    pub id: StreamId,
    pub receipt: Option<crate::codec::GoWriteReceipt>,
    pub done_gate: Option<super::recv::GoReadGate>,
    pub pipe_gate: Option<super::recv::GoReadGate>,
    pub cleanup_required: bool,
    pub cancelled_before_start: bool,
}

#[cfg(feature = "go-client-idle")]
#[derive(Debug, Default)]
pub(super) struct GoStreamFlight {
    pub latest: Option<crate::codec::GoWriteReceipt>,
    pub queued_for_codec: bool,
    pub closing: bool,
    pub done_gate: Option<super::recv::GoReadGate>,
}

#[cfg(feature = "go-client-idle")]
#[derive(Debug)]
pub(super) struct GoResetFlight {
    pub id: StreamId,
    pub ping: bool,
    pub reason: crate::frame::Reason,
    pub clean_after: Option<crate::codec::GoWriteReceipt>,
    pub pipe_gate: Option<super::recv::GoReadGate>,
    pub stage: GoResetStage,
    pub done_gate: Option<super::recv::GoReadGate>,
}

#[cfg(feature = "go-client-idle")]
#[derive(Clone, Debug)]
pub(super) enum GoResetStage {
    Queued,
    WaitingPrevious,
    Flushing(crate::codec::GoWriteReceipt),
}

#[cfg(feature = "go-client-idle")]
impl GoClientIdle {
    pub fn finish_header(&mut self, id: StreamId) {
        if self
            .header_flight
            .as_ref()
            .is_some_and(|flight| flight.id == id)
        {
            if let Some(flight) = self.header_flight.take() {
                flight.header_gate.complete();
                if flight.cancelled_before_start {
                    debug_assert!(self.active > 0);
                    self.active -= 1;
                    self.lifecycle.active();
                    if self.active == 0 {
                        self.restart();
                    } else if let Some(task) = self.task.take() {
                        task.wake();
                    }
                }
                if let Some(gate) = flight.pipe_gate {
                    gate.complete();
                }
                if flight.cleanup_required {
                    self.cleanup_work = true;
                    self.cleanup_done.insert(id, flight.done_gate);
                }
            }
            self.header_waiters.pop_front();
            if let Some(next) = self.header_waiters.front() {
                next.waker.wake_by_ref();
            }
        }
    }

    pub fn close_headers(&mut self) {
        if let Some(flight) = self.header_flight.take() {
            flight.header_gate.complete();
            if flight.cancelled_before_start {
                debug_assert!(self.active > 0);
                self.active -= 1;
            }
            if let Some(gate) = flight.pipe_gate {
                gate.complete();
            }
            if let Some(gate) = flight.done_gate {
                gate.complete();
            }
            self.header_waiters.pop_front();
        }
        for waiter in &self.header_waiters {
            waiter.waker.wake_by_ref();
        }
    }

    pub fn too_idle(&self) -> bool {
        self.last_idle
            .and_then(|last| std::time::SystemTime::now().duration_since(last).ok())
            .is_some_and(|elapsed| elapsed > self.timeout)
    }

    pub fn restart(&mut self) {
        if self.timeout.is_zero() {
            self.last_idle = None;
            self.set_deadline(None);
        } else {
            self.last_idle = Some(std::time::SystemTime::now());
            self.set_deadline(Some(tokio::time::Instant::now() + self.timeout));
        }
    }

    pub fn set_deadline(&mut self, deadline: Option<tokio::time::Instant>) {
        self.deadline = deadline;
        if let Some(task) = self.task.take() {
            task.wake();
        }
    }
}

impl Counts {
    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_cleanup_checked(&mut self) {
        if let Some(idle) = self.go_client_idle.as_mut() {
            idle.cleanup_work = false;
            for gate in idle.unsent_done.drain(..) {
                gate.complete();
            }
            for (_, gate) in idle.cleanup_done.drain() {
                if let Some(gate) = gate {
                    gate.complete();
                }
            }
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_close_gate(&mut self, id: StreamId) -> Option<super::recv::GoReadGate> {
        let idle = self.go_client_idle.as_mut()?;
        if idle.closed {
            return None;
        }
        if let Some(flight) = idle.stream_flights.get_mut(&id) {
            return Some(
                flight
                    .done_gate
                    .get_or_insert_with(Default::default)
                    .clone(),
            );
        }
        if let Some(flight) = idle.reset_flights.iter_mut().find(|flight| flight.id == id) {
            return Some(
                flight
                    .done_gate
                    .get_or_insert_with(Default::default)
                    .clone(),
            );
        }
        if let Some(header) = idle
            .header_flight
            .as_mut()
            .filter(|header| header.id == id && header.cleanup_required)
        {
            return Some(
                header
                    .done_gate
                    .get_or_insert_with(Default::default)
                    .clone(),
            );
        }
        // forgetStream precedes the final wmu/werr check and donec close.
        // Keep an ID-keyed slot even when Close registers after wire retirement.
        Some(
            idle.cleanup_done
                .get_mut(&id)?
                .get_or_insert_with(Default::default)
                .clone(),
        )
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_cancel(&mut self, stream: &mut Stream) -> bool {
        self.go_client_capture_reset(stream, crate::frame::Reason::CANCEL, true)
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_protocol_reset(
        &mut self,
        stream: &mut Stream,
        reason: crate::frame::Reason,
        pipe_error: bool,
    ) -> bool {
        let already_owned = stream.go_client_reset_owned;
        if !self.go_client_capture_reset(stream, reason, false) {
            return false;
        }
        if pipe_error && !already_owned {
            self.go_client_attach_pipe_gate(stream);
        }
        true
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_body_error(&mut self, stream: &mut Stream) -> bool {
        let already_owned = stream.go_client_reset_owned;
        if !self.go_client_capture_reset(stream, crate::frame::Reason::CANCEL, true) {
            return false;
        }
        if !already_owned {
            self.go_client_attach_pipe_gate(stream);
        }
        true
    }

    #[cfg(feature = "go-client-idle")]
    fn go_client_attach_pipe_gate(&mut self, stream: &mut Stream) {
        let pipe = super::recv::GoReadGate::default();
        let done = self.go_client_close_gate(stream.id);
        stream.go_client_error_pipe_gate = Some(pipe.clone());
        stream.go_client_error_done_gate = done;
        let idle = self.go_client_idle.as_mut().unwrap();
        if let Some(flight) = idle
            .reset_flights
            .iter_mut()
            .find(|flight| flight.id == stream.id)
        {
            flight.pipe_gate = Some(pipe);
        } else if let Some(header) = idle
            .header_flight
            .as_mut()
            .filter(|header| header.id == stream.id)
        {
            header.pipe_gate = Some(pipe);
        } else {
            // The synchronous native API has no header writer to await.
            pipe.complete();
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_pending_clean_eos(&self, id: StreamId) -> bool {
        self.go_client_idle.as_ref().is_some_and(|idle| {
            idle.reset_flights
                .iter()
                .any(|flight| flight.id == id && flight.clean_after.is_some())
        })
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_clean_eos(&self, stream: &Stream) -> bool {
        !stream.go_client_active
            && stream.state.is_recv_end_stream()
            && stream.state.is_send_closed()
            && self.go_client_idle.as_ref().is_some_and(|idle| {
                idle.stream_flights.get(&stream.id).map_or(true, |flight| {
                    !flight.queued_for_codec
                        && flight
                            .latest
                            .as_ref()
                            .map_or(true, |receipt| receipt.is_flushed())
                })
            })
    }

    #[cfg(feature = "go-client-idle")]
    fn go_client_capture_reset(
        &mut self,
        stream: &mut Stream,
        reason: crate::frame::Reason,
        plain_cancel: bool,
    ) -> bool {
        let Some(idle) = self.go_client_idle.as_mut() else {
            return false;
        };
        if stream.go_client_reset_owned {
            return true;
        }
        // Go sets sentHeaders before writeHeaders, including blocked or failed
        // header flights. Cleanup waits for wmu before writing its reset.
        if idle.closed {
            return false;
        }
        let mut clean_after = None;
        if !stream.go_client_active {
            // State can reach both-end closure before the terminal write has
            // flushed. Go sentEndStream is still false at this abort phase.
            let owns_unfinished_write = idle.stream_flights.get(&stream.id).is_some_and(|flight| {
                flight.closing
                    && (flight.queued_for_codec
                        || flight
                            .latest
                            .as_ref()
                            .is_some_and(|receipt| !receipt.is_flushed()))
            });
            if !owns_unfinished_write {
                return false;
            }
            // cleanupWriteRequest runs only after the writer finishes this
            // terminal flight. A successful flush then suppresses the abort.
            clean_after = idle
                .stream_flights
                .get(&stream.id)
                .filter(|flight| !flight.queued_for_codec)
                .and_then(|flight| flight.latest.clone());
            // Transfer the retained active owner from normal terminal cleanup
            // to this captured reset; never decrement it twice.
            idle.pending_finished.retain(|id| *id != stream.id);
        }
        if !stream.go_client_headers_sent {
            // Native cleanup before sentHeaders emits neither HEADERS nor RST.
            stream.go_client_reset_owned = true;
            stream.go_client_active = false;
            if stream.go_client_waiting {
                stream.go_client_waiting = false;
                debug_assert!(idle.waiting > 0);
                idle.waiting -= 1;
            }
            let done_gate = idle
                .stream_flights
                .remove(&stream.id)
                .and_then(|flight| flight.done_gate);
            if let Some(header) = idle
                .header_flight
                .as_mut()
                .filter(|header| header.id == stream.id && header.receipt.is_none())
            {
                // encodeAndWriteHeaders must first acquire wmu before its abort
                // check. Until that writer checkpoint this request still owns
                // an active slot, even though it will emit no frame.
                header.cleanup_required = true;
                header.cancelled_before_start = true;
                header.done_gate = done_gate;
                if let Some(task) = idle.task.take() {
                    task.wake();
                }
            } else {
                // Compatibility for the original synchronous native API,
                // which has no private header-admission owner.
                idle.cleanup_done.insert(stream.id, done_gate);
                debug_assert!(idle.active > 0);
                idle.active -= 1;
                idle.lifecycle.active();
                idle.cleanup_work = true;
                if idle.active == 0 {
                    idle.restart();
                } else if let Some(task) = idle.task.take() {
                    task.wake();
                }
            }
            return true;
        }
        let ping = if plain_cancel
            && clean_after.is_none()
            && idle.read_before_stream <= stream.id
            && !idle.reset_pings_blocked
            && !idle.do_not_reuse
        {
            let first = idle.pending_resets == 0;
            idle.pending_resets += 1;
            first
        } else {
            false
        };
        stream.go_client_reset_owned = true;
        stream.go_client_active = false;
        if stream.go_client_waiting {
            stream.go_client_waiting = false;
            debug_assert!(idle.waiting > 0);
            idle.waiting -= 1;
        }
        let done_gate = idle
            .stream_flights
            .remove(&stream.id)
            .and_then(|flight| flight.done_gate);
        idle.reset_flights.push_back(GoResetFlight {
            id: stream.id,
            ping,
            reason,
            clean_after,
            pipe_gate: None,
            stage: GoResetStage::Queued,
            done_gate,
        });
        if let Some(task) = idle.task.take() {
            task.wake();
        }
        true
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_abort_reset_flights(&mut self) {
        if let Some(idle) = self.go_client_idle.as_mut() {
            idle.close_headers();
            for gate in idle.unsent_done.drain(..) {
                gate.complete();
            }
            for (_, gate) in idle.cleanup_done.drain() {
                if let Some(gate) = gate {
                    gate.complete();
                }
            }
            let held = idle.reset_flights.len();
            for flight in idle.reset_flights.drain(..) {
                if let Some(gate) = flight.pipe_gate {
                    gate.complete();
                }
                if let Some(gate) = flight.done_gate {
                    gate.complete();
                }
            }
            for flight in idle.stream_flights.values_mut() {
                if let Some(gate) = flight.done_gate.take() {
                    gate.complete();
                }
            }
            debug_assert!(idle.active >= held);
            idle.active -= held;
            if held != 0 {
                idle.cleanup_work = true;
                idle.lifecycle.active();
            }
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_refresh_receipts(&mut self) {
        let Some(idle) = self.go_client_idle.as_mut() else {
            return;
        };
        // reqHeaderMu covers allocating the ID through the initial header
        // flush. Keep its receipt separate from generic stream/reset cleanup.
        let finished_header = idle.header_flight.as_ref().and_then(|flight| {
            flight
                .receipt
                .as_ref()
                .filter(|receipt| receipt.is_flushed() || receipt.is_failed())
                .map(|_| flight.id)
        });
        if let Some(id) = finished_header {
            idle.finish_header(id);
        }
        let pending = idle.pending_finished.len();
        for _ in 0..pending {
            let id = idle.pending_finished.pop_front().unwrap();
            let ready = idle.stream_flights.get(&id).is_some_and(|flight| {
                !flight.queued_for_codec
                    && flight
                        .latest
                        .as_ref()
                        .map_or(true, |receipt| receipt.is_flushed() || receipt.is_failed())
            });
            if !ready {
                idle.pending_finished.push_back(id);
                continue;
            }
            if let Some(flight) = idle.stream_flights.remove(&id) {
                idle.cleanup_done.insert(id, flight.done_gate);
            }
            debug_assert!(idle.active > 0);
            idle.active -= 1;
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
    pub(crate) fn go_client_flush_completed(&mut self) {
        self.go_client_refresh_receipts();
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_outgoing(&mut self, id: StreamId) {
        if let Some(flight) = self
            .go_client_idle
            .as_mut()
            .and_then(|idle| idle.stream_flights.get_mut(&id))
        {
            flight.queued_for_codec = true;
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_client_record_output(
        &mut self,
        id: StreamId,
        receipt: crate::codec::GoWriteReceipt,
    ) {
        if let Some(idle) = self.go_client_idle.as_mut() {
            if let Some(header) = idle.header_flight.as_mut().filter(|header| header.id == id) {
                if header.receipt.is_none() {
                    header.receipt = Some(receipt.clone());
                }
            }
            if let Some(flight) = idle.stream_flights.get_mut(&id) {
                flight.queued_for_codec = false;
                flight.latest = Some(receipt);
            }
        }
        self.go_client_refresh_receipts();
    }

    /// Create a new `Counts` using the provided configuration values.
    pub fn new(peer: peer::Dyn, config: &Config) -> Self {
        Counts {
            #[cfg(feature = "go-client-idle")]
            go_client_idle: None,
            #[cfg(feature = "go-server-lifecycle")]
            go_idle_timeout: None,
            #[cfg(feature = "go-server-lifecycle")]
            go_idle_deadline: None,
            #[cfg(feature = "go-server-lifecycle")]
            go_read_timeout: None,
            #[cfg(feature = "go-server-lifecycle")]
            go_write_timeout: None,
            #[cfg(feature = "go-server-lifecycle")]
            go_deadline_generation: 0,
            peer,
            max_send_streams: config.initial_max_send_streams,
            num_send_streams: 0,
            max_recv_streams: config.remote_max_initiated.unwrap_or(usize::MAX),
            num_recv_streams: 0,
            max_local_reset_streams: config.local_reset_max,
            num_local_reset_streams: 0,
            max_remote_reset_streams: config.remote_reset_max,
            num_remote_reset_streams: 0,
            max_local_error_reset_streams: config.local_max_error_reset_streams,
            num_local_error_reset_streams: 0,
            data_frame_budget: Budget::new(config.data_frame_budget.resolve(None)),
            data_frame_budget_is_auto: config.data_frame_budget.is_auto(),
            num_recv_empty_data_frames: 0,
        }
    }

    pub fn set_target_connection_window_size(&mut self, size: WindowSize) {
        if self.data_frame_budget_is_auto {
            self.data_frame_budget
                .set_max(DataFrameBudget::Auto.resolve(Some(size)));
        }
    }

    /// Records the framing overhead of a DATA frame.
    pub fn record_data_frame(&mut self, payload_len: usize) -> Result<(), BudgetExhausted> {
        if payload_len == 0 {
            self.num_recv_empty_data_frames = self
                .num_recv_empty_data_frames
                .checked_add(1)
                .ok_or(BudgetExhausted)?;
            if self.num_recv_empty_data_frames > MAX_RECV_EMPTY_DATA_FRAMES {
                return Err(BudgetExhausted);
            }
            Ok(())
        } else if payload_len < DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD {
            self.data_frame_budget
                .consume(DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD - payload_len)
        } else {
            self.data_frame_budget
                .replenish(payload_len - DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD);
            Ok(())
        }
    }

    /// Releases the framing overhead of a DATA frame that is no longer
    /// buffered internally.
    pub fn release_data_frame(&mut self, payload_len: usize) {
        if payload_len != 0 && payload_len < DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD {
            self.data_frame_budget
                .replenish(DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD - payload_len);
        }
    }

    /// Returns true when the next opened stream will reach capacity of outbound streams
    ///
    /// The number of client send streams is incremented in prioritize; send_request has to guess if
    /// it should wait before allowing another request to be sent.
    pub fn next_send_stream_will_reach_capacity(&self) -> bool {
        self.max_send_streams <= (self.num_send_streams + 1)
    }

    /// Returns the current peer
    pub fn peer(&self) -> peer::Dyn {
        self.peer
    }

    pub fn has_streams(&self) -> bool {
        self.num_send_streams != 0 || self.num_recv_streams != 0
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(super) fn configure_go_idle(&mut self, timeout: Option<Duration>) {
        self.go_idle_timeout = timeout;
        self.go_idle_deadline = timeout.map(|timeout| tokio::time::Instant::now() + timeout);
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(super) fn stop_go_idle(&mut self) {
        self.go_idle_deadline = None;
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(super) fn go_idle_deadline(&self) -> Option<tokio::time::Instant> {
        self.go_idle_deadline
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(super) fn configure_go_stream_timeouts(
        &mut self,
        read: Option<Duration>,
        write: Option<Duration>,
    ) {
        if self.go_read_timeout != read || self.go_write_timeout != write {
            self.go_deadlines_changed();
        }
        self.go_read_timeout = read;
        self.go_write_timeout = write;
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(super) fn go_stream_timeouts_enabled(&self) -> bool {
        self.go_read_timeout.is_some() || self.go_write_timeout.is_some()
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(super) fn go_deadlines_changed(&mut self) {
        self.go_deadline_generation = self.go_deadline_generation.wrapping_add(1);
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(super) fn go_deadline_generation(&self) -> u64 {
        self.go_deadline_generation
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(super) fn start_go_write_timeout(&mut self, stream: &mut Stream) {
        stream.go_write_deadline = self
            .go_write_timeout
            .map(|timeout| tokio::time::Instant::now() + timeout);
        if stream.go_write_deadline.is_some() {
            self.go_deadlines_changed();
        }
    }

    #[cfg(feature = "go-server-lifecycle")]
    pub(super) fn start_go_read_timeout(&mut self, stream: &mut Stream) {
        if !stream.state.is_recv_end_stream() {
            stream.go_read_deadline = self
                .go_read_timeout
                .map(|timeout| tokio::time::Instant::now() + timeout);
            if stream.go_read_deadline.is_some() {
                self.go_deadlines_changed();
            }
        }
    }

    #[cfg(feature = "go-client-idle")]
    pub(super) fn go_client_disable_error_reset_limit(&mut self) {
        // Go's client read loop aborts individual local stream errors and
        // continues; it has no connection-wide local-error-reset budget.
        self.max_local_error_reset_streams = None;
    }

    /// Returns true if we can issue another local reset due to protocol error.
    pub fn can_inc_num_local_error_resets(&self) -> bool {
        if let Some(max) = self.max_local_error_reset_streams {
            max > self.num_local_error_reset_streams
        } else {
            true
        }
    }

    pub fn inc_num_local_error_resets(&mut self) {
        assert!(self.can_inc_num_local_error_resets());

        // Increment the number of remote initiated streams
        self.num_local_error_reset_streams += 1;
    }

    pub(crate) fn max_local_error_resets(&self) -> Option<usize> {
        self.max_local_error_reset_streams
    }

    /// Returns true if the receive stream concurrency can be incremented
    pub fn can_inc_num_recv_streams(&self) -> bool {
        self.max_recv_streams > self.num_recv_streams
    }

    /// Increments the number of concurrent receive streams.
    ///
    /// # Panics
    ///
    /// Panics on failure as this should have been validated before hand.
    pub fn inc_num_recv_streams(&mut self, stream: &mut store::Ptr) {
        #[cfg(feature = "go-server-lifecycle")]
        self.stop_go_idle();
        assert!(self.can_inc_num_recv_streams());
        assert!(!stream.is_counted);

        // Increment the number of remote initiated streams
        self.num_recv_streams += 1;
        stream.is_counted = true;
    }

    /// Returns true if the send stream concurrency can be incremented
    pub fn can_inc_num_send_streams(&self) -> bool {
        self.max_send_streams > self.num_send_streams
    }

    /// Increments the number of concurrent send streams.
    ///
    /// # Panics
    ///
    /// Panics on failure as this should have been validated before hand.
    pub fn inc_num_send_streams(&mut self, stream: &mut store::Ptr) {
        #[cfg(feature = "go-server-lifecycle")]
        self.stop_go_idle();
        assert!(self.can_inc_num_send_streams());
        assert!(!stream.is_counted);

        // Increment the number of remote initiated streams
        self.num_send_streams += 1;
        stream.is_counted = true;
        #[cfg(feature = "go-client-idle")]
        if stream.go_client_waiting {
            stream.go_client_waiting = false;
            let idle = self.go_client_idle.as_mut().unwrap();
            debug_assert!(idle.waiting > 0);
            idle.waiting -= 1;
        }
    }

    /// Returns true if the number of pending reset streams can be incremented.
    pub fn can_inc_num_reset_streams(&self) -> bool {
        self.max_local_reset_streams > self.num_local_reset_streams
    }

    /// Increments the number of pending reset streams.
    ///
    /// # Panics
    ///
    /// Panics on failure as this should have been validated before hand.
    pub fn inc_num_reset_streams(&mut self) {
        assert!(self.can_inc_num_reset_streams());

        self.num_local_reset_streams += 1;
    }

    pub(crate) fn max_remote_reset_streams(&self) -> usize {
        self.max_remote_reset_streams
    }

    /// Returns true if the number of pending REMOTE reset streams can be
    /// incremented.
    pub(crate) fn can_inc_num_remote_reset_streams(&self) -> bool {
        self.max_remote_reset_streams > self.num_remote_reset_streams
    }

    /// Increments the number of pending REMOTE reset streams.
    ///
    /// # Panics
    ///
    /// Panics on failure as this should have been validated before hand.
    pub(crate) fn inc_num_remote_reset_streams(&mut self) {
        assert!(self.can_inc_num_remote_reset_streams());

        self.num_remote_reset_streams += 1;
    }

    pub(crate) fn dec_num_remote_reset_streams(&mut self) {
        assert!(self.num_remote_reset_streams > 0);

        self.num_remote_reset_streams -= 1;
    }

    pub fn apply_remote_settings(&mut self, settings: &frame::Settings, is_initial: bool) {
        match settings.max_concurrent_streams() {
            Some(val) => self.max_send_streams = val as usize,
            None if is_initial => {
                #[cfg(feature = "go-client-idle")]
                if self.go_client_idle.is_some() {
                    self.max_send_streams = 1000;
                    return;
                }
                self.max_send_streams = usize::MAX;
            }
            None => {}
        }
    }

    /// Run a block of code that could potentially transition a stream's state.
    ///
    /// If the stream state transitions to closed, this function will perform
    /// all necessary cleanup.
    ///
    /// TODO: Is this function still needed?
    pub fn transition<F, U>(&mut self, mut stream: store::Ptr, f: F) -> U
    where
        F: FnOnce(&mut Self, &mut store::Ptr) -> U,
    {
        // TODO: Does this need to be computed before performing the action?
        let is_pending_reset = stream.is_pending_reset_expiration();

        // Run the action
        let ret = f(self, &mut stream);

        self.transition_after(stream, is_pending_reset);

        ret
    }

    // TODO: move this to macro?
    pub fn transition_after(&mut self, mut stream: store::Ptr, is_reset_counted: bool) {
        tracing::trace!(
            "transition_after; stream={:?}; state={:?}; is_closed={:?}; \
             pending_send_empty={:?}; buffered_send_data={}; \
             num_recv={}; num_send={}",
            stream.id,
            stream.state,
            stream.is_closed(),
            stream.pending_send.is_empty(),
            stream.buffered_send_data,
            self.num_recv_streams,
            self.num_send_streams
        );

        #[cfg(feature = "go-server-lifecycle")]
        if stream.state.is_recv_end_stream() && stream.go_read_deadline.take().is_some() {
            self.go_deadlines_changed();
        }
        #[cfg(feature = "go-client-idle")]
        if stream.state.is_recv_end_stream() || stream.state.is_reset() {
            if let Some(task) = stream.go_client_finish_task.take() {
                task.wake();
            }
        }
        #[cfg(feature = "go-client-idle")]
        if stream.go_client_active && stream.is_closed() && !stream.state.is_scheduled_reset() {
            stream.go_client_active = false;
            if let Some(idle) = self.go_client_idle.as_mut() {
                if stream.go_client_waiting {
                    stream.go_client_waiting = false;
                    debug_assert!(idle.waiting > 0);
                    idle.waiting -= 1;
                }
                if let Some(flight) = idle.stream_flights.get_mut(&stream.id) {
                    flight.closing = true;
                }
                idle.pending_finished.push_back(stream.id);
            }
            self.go_client_refresh_receipts();
        }
        if stream.is_closed() {
            #[cfg(feature = "go-server-lifecycle")]
            {
                if stream.go_read_deadline.is_some() || stream.go_write_deadline.is_some() {
                    self.go_deadlines_changed();
                }
                stream.go_read_deadline = None;
                stream.go_write_deadline = None;
            }
            if !stream.is_pending_reset_expiration() {
                stream.unlink();
                if is_reset_counted {
                    self.dec_num_reset_streams();
                }
            }

            if !stream.state.is_scheduled_reset() && stream.is_counted {
                tracing::trace!("dec_num_streams; stream={:?}", stream.id);
                // Decrement the number of active streams.
                self.dec_num_streams(&mut stream);
            }
        }

        // Release the stream if it requires releasing
        if stream.is_released() {
            stream.remove();
        }
    }

    /// Returns the maximum number of streams that can be initiated by this
    /// peer.
    pub(crate) fn max_send_streams(&self) -> usize {
        self.max_send_streams
    }

    /// Returns the maximum number of streams that can be initiated by the
    /// remote peer.
    pub(crate) fn max_recv_streams(&self) -> usize {
        self.max_recv_streams
    }

    fn dec_num_streams(&mut self, stream: &mut store::Ptr) {
        assert!(stream.is_counted);

        if self.peer.is_local_init(stream.id) {
            assert!(self.num_send_streams > 0);
            self.num_send_streams -= 1;
            stream.is_counted = false;
        } else {
            assert!(self.num_recv_streams > 0);
            self.num_recv_streams -= 1;
            stream.is_counted = false;
        }
        #[cfg(feature = "go-server-lifecycle")]
        if !self.has_streams() {
            self.go_idle_deadline = self
                .go_idle_timeout
                .map(|timeout| tokio::time::Instant::now() + timeout);
        }
    }

    fn dec_num_reset_streams(&mut self) {
        assert!(self.num_local_reset_streams > 0);
        self.num_local_reset_streams -= 1;
    }
}

impl Drop for Counts {
    fn drop(&mut self) {
        use std::thread;

        if !thread::panicking() {
            debug_assert!(!self.has_streams());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::DEFAULT_INITIAL_WINDOW_SIZE;

    fn counts_config() -> Config {
        Config {
            initial_max_send_streams: 0,
            local_max_buffer_size: 0,
            local_next_stream_id: 2.into(),
            local_push_enabled: false,
            extended_connect_protocol_enabled: false,
            local_reset_duration: Duration::ZERO,
            local_reset_max: 0,
            remote_reset_max: 0,
            remote_init_window_sz: DEFAULT_INITIAL_WINDOW_SIZE,
            remote_max_initiated: None,
            local_max_error_reset_streams: None,
            data_frame_budget: DataFrameBudget::Configured(DEFAULT_DATA_FRAME_BUDGET),
        }
    }

    fn counts() -> Counts {
        Counts::new(peer::Dyn::Server, &counts_config())
    }

    #[test]
    fn budget_is_bounded() {
        let mut budget = Budget::new(10);

        budget.consume(4).unwrap();
        budget.replenish(20);
        assert_eq!(budget.available(), 10);
    }

    #[test]
    fn budget_reports_exhaustion_without_underflowing() {
        let mut budget = Budget::new(10);

        budget.consume(10).unwrap();
        assert!(budget.consume(1).is_err());
        assert_eq!(budget.available(), 0);
    }

    #[test]
    fn resizing_budget_preserves_outstanding_charges() {
        let mut budget = Budget::new(100);
        budget.consume(60).unwrap();

        budget.set_max(200);
        assert_eq!(budget.available(), 140);

        budget.set_max(40);
        assert_eq!(budget.available(), 0);
        assert!(budget.consume(1).is_err());

        budget.replenish(30);
        assert_eq!(budget.available(), 10);
    }

    #[test]
    fn auto_budget_tracks_target_window_and_configured_budget_does_not() {
        let mut auto = Counts::new(
            peer::Dyn::Server,
            &Config {
                data_frame_budget: DataFrameBudget::Auto,
                ..counts_config()
            },
        );
        auto.set_target_connection_window_size(1024 * 1024);
        assert_eq!(auto.data_frame_budget.max, 512 * 1024);
        for _ in 0..1_000 {
            auto.record_data_frame(171).unwrap();
        }

        let mut configured = Counts::new(
            peer::Dyn::Server,
            &Config {
                data_frame_budget: DataFrameBudget::Configured(123),
                ..counts_config()
            },
        );
        configured.set_target_connection_window_size(1024 * 1024);
        assert_eq!(configured.data_frame_budget.max, 123);
    }

    #[test]
    fn good_sized_data_frames_do_not_exhaust_budget() {
        let mut counts = counts();

        for _ in 0..1_000_000 {
            counts
                .record_data_frame(DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD)
                .unwrap();
        }
    }

    #[test]
    fn consumed_small_data_frames_do_not_exhaust_budget() {
        let mut counts = counts();

        for _ in 0..1_000_000 {
            counts.record_data_frame(1).unwrap();
            counts.release_data_frame(1);
        }
    }

    #[test]
    fn empty_data_frames_do_not_consume_data_frame_budget() {
        let mut counts = counts();
        counts.data_frame_budget = Budget::new(0);

        for _ in 0..MAX_RECV_EMPTY_DATA_FRAMES {
            counts.record_data_frame(0).unwrap();
        }

        // Empty frames have their own limit, while a non-empty small frame
        // still consumes the independently configured DATA frame budget.
        assert!(counts.record_data_frame(0).is_err());
        assert!(counts.record_data_frame(1).is_err());
    }

    #[test]
    fn large_data_frames_do_not_replenish_empty_data_frame_limit() {
        let mut counts = counts();

        for _ in 0..MAX_RECV_EMPTY_DATA_FRAMES {
            counts.record_data_frame(0).unwrap();
            counts
                .record_data_frame(DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD * 2)
                .unwrap();
        }
        assert!(counts.record_data_frame(0).is_err());
    }
}
