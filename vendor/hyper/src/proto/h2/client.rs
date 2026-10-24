use std::{
    convert::Infallible,
    future::Future,
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use crate::rt::{Read, Write};
use bytes::Bytes;
use futures_channel::mpsc::{Receiver, Sender};
use futures_channel::{mpsc, oneshot};
use futures_core::{ready, FusedFuture, FusedStream, Stream};
use h2::client::{Builder, Connection, SendRequest};
use h2::SendStream;
use http::{Method, StatusCode};
use pin_project_lite::pin_project;

use super::ping::{Ponger, Recorder};
use super::{ping, PipeToSendStream, SendBuf};
use crate::body::{Body, Incoming as IncomingBody};
use crate::client::dispatch::{Callback, SendWhen, TrySendError};
use crate::common::either::Either;
use crate::common::io::Compat;
use crate::common::time::Time;
use crate::ext::Protocol;
use crate::headers;
use crate::proto::Dispatched;
use crate::rt::bounds::{Http2ClientConnExec, Http2UpgradedExec};
use crate::upgrade::Upgraded;
use crate::{Request, Response};
use h2::client::ResponseFuture;

type ClientRx<B> = crate::client::dispatch::Receiver<Request<B>, Response<IncomingBody>>;

///// An mpsc channel is used to help notify the `Connection` task when *all*
///// other handles to it have been dropped, so that it can shutdown.
type ConnDropRef = mpsc::Sender<Infallible>;

///// A oneshot channel watches the `Connection` task, and when it completes,
///// the "dispatch" task will be notified and can shutdown sooner.
type ConnEof = oneshot::Receiver<Infallible>;

// Our defaults are chosen for the "majority" case, which usually are not
// resource constrained, and so the spec default of 64kb can be too limiting
// for performance.
const DEFAULT_CONN_WINDOW: u32 = 1024 * 1024 * 5; // 5mb
const DEFAULT_STREAM_WINDOW: u32 = 1024 * 1024 * 2; // 2mb
const DEFAULT_MAX_FRAME_SIZE: u32 = 1024 * 16; // 16kb
const DEFAULT_MAX_SEND_BUF_SIZE: usize = 1024 * 1024; // 1mb
const DEFAULT_MAX_HEADER_LIST_SIZE: u32 = 1024 * 16; // 16kb

// The maximum number of concurrent streams that the client is allowed to open
// before it receives the initial SETTINGS frame from the server.
// This default value is derived from what the HTTP/2 spec recommends as the
// minimum value that endpoints advertise to their peers. It means that using
// this value will minimize the chance of the failure where the local endpoint
// attempts to open too many streams and gets rejected by the remote peer with
// the `REFUSED_STREAM` error.
const DEFAULT_INITIAL_MAX_SEND_STREAMS: usize = 100;

#[derive(Clone, Debug)]
pub(crate) struct Config {
    #[cfg(feature = "go-client-idle")]
    pub(crate) go_idle_timeout: Option<Duration>,
    #[cfg(feature = "go-client-idle")]
    pub(crate) go_native_client: bool,
    #[cfg(feature = "go-client-idle")]
    pub(crate) go_reset_ping_payload: Option<fn() -> [u8; 8]>,
    pub(crate) adaptive_window: bool,
    pub(crate) initial_conn_window_size: u32,
    pub(crate) initial_stream_window_size: u32,
    pub(crate) initial_max_send_streams: usize,
    pub(crate) max_frame_size: Option<u32>,
    pub(crate) max_header_list_size: u32,
    pub(crate) keep_alive_interval: Option<Duration>,
    pub(crate) keep_alive_timeout: Duration,
    pub(crate) keep_alive_while_idle: bool,
    pub(crate) max_concurrent_reset_streams: Option<usize>,
    pub(crate) max_send_buffer_size: usize,
    pub(crate) max_pending_accept_reset_streams: Option<usize>,
    pub(crate) max_local_error_reset_streams: Option<usize>,
    pub(crate) header_table_size: Option<u32>,
    pub(crate) max_concurrent_streams: Option<u32>,
    pub(crate) reset_stream_duration: Option<Duration>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            #[cfg(feature = "go-client-idle")]
            go_idle_timeout: None,
            #[cfg(feature = "go-client-idle")]
            go_native_client: false,
            #[cfg(feature = "go-client-idle")]
            go_reset_ping_payload: None,
            adaptive_window: false,
            initial_conn_window_size: DEFAULT_CONN_WINDOW,
            initial_stream_window_size: DEFAULT_STREAM_WINDOW,
            initial_max_send_streams: DEFAULT_INITIAL_MAX_SEND_STREAMS,
            max_frame_size: Some(DEFAULT_MAX_FRAME_SIZE),
            max_header_list_size: DEFAULT_MAX_HEADER_LIST_SIZE,
            keep_alive_interval: None,
            keep_alive_timeout: Duration::from_secs(20),
            keep_alive_while_idle: false,
            max_concurrent_reset_streams: None,
            max_send_buffer_size: DEFAULT_MAX_SEND_BUF_SIZE,
            max_pending_accept_reset_streams: None,
            max_local_error_reset_streams: Some(1024),
            header_table_size: None,
            max_concurrent_streams: None,
            reset_stream_duration: None,
        }
    }
}

fn new_builder(config: &Config) -> Builder {
    let mut builder = Builder::default();
    #[cfg(feature = "go-client-idle")]
    if let Some(timeout) = config.go_idle_timeout {
        builder.go_idle_timeout(timeout);
    }
    #[cfg(feature = "go-client-idle")]
    {
        builder.go_native_client(config.go_native_client);
        if let Some(payload) = config.go_reset_ping_payload {
            builder.go_reset_ping_payload(payload);
        }
    }
    builder
        .initial_max_send_streams(config.initial_max_send_streams)
        .initial_window_size(config.initial_stream_window_size)
        .initial_connection_window_size(config.initial_conn_window_size)
        .max_header_list_size(config.max_header_list_size)
        .max_send_buffer_size(config.max_send_buffer_size)
        .max_local_error_reset_streams(config.max_local_error_reset_streams)
        .enable_push(false);
    if let Some(max) = config.max_frame_size {
        builder.max_frame_size(max);
    }
    if let Some(max) = config.max_concurrent_reset_streams {
        builder.max_concurrent_reset_streams(max);
    }
    if let Some(max) = config.max_pending_accept_reset_streams {
        builder.max_pending_accept_reset_streams(max);
    }
    if let Some(size) = config.header_table_size {
        builder.header_table_size(size);
    }
    if let Some(max) = config.max_concurrent_streams {
        builder.max_concurrent_streams(max);
    }
    if let Some(dur) = config.reset_stream_duration {
        builder.reset_stream_duration(dur);
    }
    builder
}

fn new_ping_config(config: &Config) -> ping::Config {
    ping::Config {
        bdp_initial_window: if config.adaptive_window {
            Some(config.initial_stream_window_size)
        } else {
            None
        },
        keep_alive_interval: config.keep_alive_interval,
        keep_alive_timeout: config.keep_alive_timeout,
        keep_alive_while_idle: config.keep_alive_while_idle,
    }
}

pub(crate) async fn handshake<T, B, E>(
    io: T,
    req_rx: ClientRx<B>,
    config: &Config,
    mut exec: E,
    timer: Time,
) -> crate::Result<ClientTask<B, E, T>>
where
    T: Read + Write + Unpin,
    B: Body + 'static,
    B::Data: Send + 'static,
    E: Http2ClientConnExec<B, T> + Clone + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (h2_tx, mut conn) = new_builder(config)
        .handshake::<_, SendBuf<B::Data>>(Compat::new(io))
        .await
        .map_err(crate::Error::new_h2)?;

    // An mpsc channel is used entirely to detect when the
    // 'Client' has been dropped. This is to get around a bug
    // in h2 where dropping all SendRequests won't notify a
    // parked Connection.
    let (conn_drop_ref, conn_drop_rx) = mpsc::channel(1);
    let (cancel_tx, conn_eof) = oneshot::channel();

    let ping_config = new_ping_config(config);

    let (conn, ping) = if ping_config.is_enabled() {
        let pp = conn.ping_pong().expect("conn.ping_pong");
        let (recorder, ponger) = ping::channel(pp, ping_config, timer);

        let conn: Conn<_, B> = Conn::new(ponger, conn);
        (Either::left(conn), recorder)
    } else {
        (Either::right(conn), ping::disabled())
    };
    let conn: ConnMapErr<T, B> = ConnMapErr {
        conn,
        is_terminated: false,
    };

    exec.execute_h2_future(H2ClientFuture::Task {
        task: ConnTask::new(conn, conn_drop_rx, cancel_tx),
    });

    Ok(ClientTask {
        ping,
        conn_drop_ref,
        conn_eof,
        executor: exec,
        h2_tx,
        req_rx,
        fut_ctx: None,
        #[cfg(feature = "go-client-idle")]
        go_pending: std::collections::VecDeque::new(),
        #[cfg(feature = "go-client-idle")]
        go_cleanup: std::collections::VecDeque::new(),
        #[cfg(feature = "go-client-idle")]
        go_native_client: config.go_native_client,
        marker: PhantomData,
    })
}

pin_project! {
    struct Conn<T, B>
    where
        B: Body,
    {
        #[pin]
        ponger: Ponger,
        #[pin]
        conn: Connection<Compat<T>, SendBuf<<B as Body>::Data>>,
    }
}

impl<T, B> Conn<T, B>
where
    B: Body,
    T: Read + Write + Unpin,
{
    fn new(ponger: Ponger, conn: Connection<Compat<T>, SendBuf<<B as Body>::Data>>) -> Self {
        Conn { ponger, conn }
    }
}

impl<T, B> Future for Conn<T, B>
where
    B: Body,
    T: Read + Write + Unpin,
{
    type Output = Result<(), h2::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        match this.ponger.poll(cx) {
            Poll::Ready(ping::Ponged::SizeUpdate(wnd)) => {
                this.conn.set_target_window_size(wnd);
                this.conn.set_initial_window_size(wnd)?;
            }
            Poll::Ready(ping::Ponged::KeepAliveTimedOut) => {
                debug!("connection keep-alive timed out");
                return Poll::Ready(Ok(()));
            }
            Poll::Pending => {}
        }

        Pin::new(&mut this.conn).poll(cx)
    }
}

pin_project! {
    struct ConnMapErr<T, B>
    where
        B: Body,
        T: Read,
        T: Write,
        T: Unpin,
    {
        #[pin]
        conn: Either<Conn<T, B>, Connection<Compat<T>, SendBuf<<B as Body>::Data>>>,
        #[pin]
        is_terminated: bool,
    }
}

impl<T, B> Future for ConnMapErr<T, B>
where
    B: Body,
    T: Read + Write + Unpin,
{
    type Output = Result<(), ()>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        if *this.is_terminated {
            return Poll::Pending;
        }
        let polled = this.conn.poll(cx);
        if polled.is_ready() {
            *this.is_terminated = true;
        }
        polled.map_err(|_e| {
            debug!(error = %_e, "connection error");
        })
    }
}

impl<T, B> FusedFuture for ConnMapErr<T, B>
where
    B: Body,
    T: Read + Write + Unpin,
{
    fn is_terminated(&self) -> bool {
        self.is_terminated
    }
}

pin_project! {
    pub struct ConnTask<T, B>
    where
        B: Body,
        T: Read,
        T: Write,
        T: Unpin,
    {
        #[pin]
        drop_rx: Receiver<Infallible>,
        #[pin]
        cancel_tx: Option<oneshot::Sender<Infallible>>,
        #[pin]
        conn: ConnMapErr<T, B>,
    }
}

impl<T, B> ConnTask<T, B>
where
    B: Body,
    T: Read + Write + Unpin,
{
    fn new(
        conn: ConnMapErr<T, B>,
        drop_rx: Receiver<Infallible>,
        cancel_tx: oneshot::Sender<Infallible>,
    ) -> Self {
        Self {
            drop_rx,
            cancel_tx: Some(cancel_tx),
            conn,
        }
    }
}

impl<T, B> Future for ConnTask<T, B>
where
    B: Body,
    T: Read + Write + Unpin,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();

        if !this.conn.is_terminated() && Pin::new(&mut this.conn).poll(cx).is_ready() {
            // ok or err, the `conn` has finished.
            return Poll::Ready(());
        }

        if !this.drop_rx.is_terminated() && Pin::new(&mut this.drop_rx).poll_next(cx).is_ready() {
            // mpsc has been dropped, hopefully polling
            // the connection some more should start shutdown
            // and then close.
            trace!("send_request dropped, starting conn shutdown");
            drop(this.cancel_tx.take().expect("ConnTask Future polled twice"));
        }

        Poll::Pending
    }
}

pin_project! {
    #[project = H2ClientFutureProject]
    pub enum H2ClientFuture<B, T, E>
    where
        B: http_body::Body,
        B: 'static,
        B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
        T: Read,
        T: Write,
        T: Unpin,
    {
        Pipe {
            #[pin]
            pipe: PipeMap<B>,
        },
        Send {
            #[pin]
            send_when: SendWhen<B, E>,
        },
        Task {
            #[pin]
            task: ConnTask<T, B>,
        },
    }
}

impl<B, T, E> Future for H2ClientFuture<B, T, E>
where
    B: http_body::Body + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    T: Read + Write + Unpin,
    E: Http2UpgradedExec<B::Data>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();

        match this {
            H2ClientFutureProject::Pipe { pipe } => pipe.poll(cx),
            H2ClientFutureProject::Send { send_when } => send_when.poll(cx),
            H2ClientFutureProject::Task { task } => task.poll(cx),
        }
    }
}

struct FutCtx<B>
where
    B: Body,
{
    is_connect: bool,
    eos: bool,
    fut: ResponseFuture,
    body_tx: SendStream<SendBuf<B::Data>>,
    body: B,
    cb: Callback<Request<B>, Response<IncomingBody>>,
}

impl<B: Body> Unpin for FutCtx<B> {}

#[cfg(feature = "go-client-idle")]
struct GoPendingAdmission<B: Body> {
    future: h2::client::GoSendRequest<SendBuf<B::Data>>,
    body: B,
    cb: Callback<Request<B>, Response<IncomingBody>>,
    is_connect: bool,
    eos: bool,
}

#[cfg(feature = "go-client-idle")]
struct GoEmptyRequestSender<D: bytes::Buf> {
    sender: SendStream<SendBuf<D>>,
    waiting: bool,
}

#[cfg(feature = "go-client-idle")]
struct GoRequestBodyOwner {
    control: super::GoRequestBodyControl,
    pending: bool,
}

#[cfg(feature = "go-client-idle")]
impl Drop for GoRequestBodyOwner {
    fn drop(&mut self) {
        if self.pending {
            self.control.cancel();
        }
    }
}

#[cfg(feature = "go-client-idle")]
impl<D: bytes::Buf> Drop for GoEmptyRequestSender<D> {
    fn drop(&mut self) {
        if self.waiting {
            // Dropping the undelivered NoBody response is request cancellation,
            // unlike closing a NoBody response which was already returned.
            self.sender.go_cancel_request_after_response();
        }
    }
}

pub(crate) struct ClientTask<B, E, T>
where
    B: Body,
    E: Unpin,
{
    ping: ping::Recorder,
    conn_drop_ref: ConnDropRef,
    conn_eof: ConnEof,
    executor: E,
    h2_tx: SendRequest<SendBuf<B::Data>>,
    req_rx: ClientRx<B>,
    fut_ctx: Option<FutCtx<B>>,
    #[cfg(feature = "go-client-idle")]
    go_pending: std::collections::VecDeque<GoPendingAdmission<B>>,
    #[cfg(feature = "go-client-idle")]
    go_cleanup: std::collections::VecDeque<GoPendingAdmission<B>>,
    #[cfg(feature = "go-client-idle")]
    go_native_client: bool,
    marker: PhantomData<T>,
}

impl<B, E, T> ClientTask<B, E, T>
where
    B: Body + 'static,
    E: Http2ClientConnExec<B, T> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    T: Read + Write + Unpin,
{
    #[cfg(feature = "go-client-idle")]
    pub(crate) fn go_idle_handle(&self) -> Option<h2::client::GoIdleHandle> {
        self.h2_tx.go_idle_handle()
    }

    pub(crate) fn is_extended_connect_protocol_enabled(&self) -> bool {
        self.h2_tx.is_extended_connect_protocol_enabled()
    }
    pub(crate) fn current_max_send_streams(&self) -> usize {
        self.h2_tx.current_max_send_streams()
    }
    pub(crate) fn current_max_recv_streams(&self) -> usize {
        self.h2_tx.current_max_recv_streams()
    }
}

pin_project! {
    pub struct PipeMap<S>
    where
        S: Body,
    {
        #[pin]
        pipe: PipeToSendStream<S>,
        #[pin]
        conn_drop_ref: Option<Sender<Infallible>>,
        #[pin]
        ping: Option<Recorder>,
        cancel_rx: Option<oneshot::Receiver<()>>,
    }
}

impl<B> Future for PipeMap<B>
where
    B: http_body::Body,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> std::task::Poll<Self::Output> {
        let mut this = self.project();

        // Check if the client cancelled the request (e.g. dropped the
        // response future due to a timeout). If so, reset the h2 stream
        // so that a RST_STREAM is sent and flow-control capacity is freed.
        let cancel_result = this.cancel_rx.as_mut().map(|rx| Pin::new(rx).poll(cx));
        match cancel_result {
            Some(Poll::Ready(Ok(()))) => {
                debug!("client request body send cancelled, resetting stream");
                this.pipe.as_mut().send_reset(h2::Reason::CANCEL);
                drop(this.conn_drop_ref.take().expect("Future polled twice"));
                drop(this.ping.take().expect("Future polled twice"));
                return Poll::Ready(());
            }
            Some(Poll::Ready(Err(_))) => {
                // Sender dropped without cancelling (normal response or error).
                // Stop polling the receiver.
                *this.cancel_rx = None;
            }
            Some(Poll::Pending) | None => {}
        }

        match Pin::new(&mut this.pipe).poll(cx) {
            Poll::Ready(result) => {
                if let Err(_e) = result {
                    debug!("client request body error: {}", _e);
                }
                drop(this.conn_drop_ref.take().expect("Future polled twice"));
                drop(this.ping.take().expect("Future polled twice"));
                return Poll::Ready(());
            }
            Poll::Pending => (),
        }
        Poll::Pending
    }
}

impl<B, E, T> ClientTask<B, E, T>
where
    B: Body + 'static + Unpin,
    B::Data: Send,
    E: Http2ClientConnExec<B, T> + Clone + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    T: Read + Write + Unpin,
{
    #[cfg(feature = "go-client-idle")]
    fn poll_go_cleanup(&mut self, cx: &mut Context<'_>) {
        // These requests released reqHeaderMu before waiting for wmu. Poll
        // every independent waiter once; blocked cleanup must not hold the
        // admission FIFO, and Pending alone must never self-wake a loop.
        let pending = self.go_cleanup.len();
        for _ in 0..pending {
            let mut cleanup = self.go_cleanup.pop_front().unwrap();
            if cleanup.cb.poll_canceled(cx).is_ready() {
                continue;
            }
            match Pin::new(&mut cleanup.future).poll(cx) {
                Poll::Pending => self.go_cleanup.push_back(cleanup),
                Poll::Ready(Err((error, request))) => {
                    let message = request.map(|request| {
                        let (parts, ()) = request.into_parts();
                        Request::from_parts(parts, cleanup.body)
                    });
                    cleanup.cb.send(Err(TrySendError {
                        error: crate::Error::new_h2(error),
                        message,
                    }));
                }
                Poll::Ready(Ok(_)) => {
                    unreachable!("failed native admission cannot become successful")
                }
            }
        }
    }

    fn poll_pipe(&mut self, f: FutCtx<B>, cx: &mut Context<'_>) {
        let ping = self.ping.clone();

        #[cfg(feature = "go-client-idle")]
        let go_control = (self.go_native_client && !f.is_connect && !f.eos)
            .then(super::GoRequestBodyControl::default);
        #[cfg(feature = "go-client-idle")]
        let mut go_empty_request_sender = None;
        // A one-shot channel so that send_task can tell pipe_task to
        // reset the stream when the client cancels the request.
        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();

        let send_stream = if !f.is_connect {
            if !f.eos {
                let mut pipe = PipeToSendStream::new(f.body, f.body_tx);
                #[cfg(feature = "go-client-idle")]
                if let Some(control) = go_control.as_ref() {
                    pipe.go_control(control.clone());
                }

                // eagerly see if the body pipe is ready and
                // can thus skip allocating in the executor
                match Pin::new(&mut pipe).poll(cx) {
                    Poll::Ready(_) => (),
                    Poll::Pending => {
                        let conn_drop_ref = self.conn_drop_ref.clone();
                        // keep the ping recorder's knowledge of an
                        // "open stream" alive while this body is
                        // still sending...
                        let ping = ping.clone();

                        let pipe = PipeMap {
                            pipe,
                            conn_drop_ref: Some(conn_drop_ref),
                            ping: Some(ping),
                            cancel_rx: Some(cancel_rx),
                        };
                        // Clear send task
                        self.executor
                            .execute_h2_future(H2ClientFuture::Pipe { pipe });
                    }
                }
            } else {
                #[cfg(feature = "go-client-idle")]
                if self.go_native_client {
                    go_empty_request_sender = Some(GoEmptyRequestSender {
                        sender: f.body_tx,
                        waiting: false,
                    });
                }
            }

            None
        } else {
            Some(f.body_tx)
        };

        self.executor.execute_h2_future(H2ClientFuture::Send {
            send_when: SendWhen {
                when: ResponseFutMap {
                    fut: f.fut,
                    ping: Some(ping),
                    send_stream: Some(send_stream),
                    exec: self.executor.clone(),
                    #[cfg(feature = "go-client-idle")]
                    go_control: go_control.map(|control| GoRequestBodyOwner {
                        control,
                        pending: true,
                    }),
                    #[cfg(feature = "go-client-idle")]
                    go_empty_request_sender,
                    #[cfg(feature = "go-client-idle")]
                    go_response: None,
                    cancel_tx: Some(cancel_tx),
                },
                call_back: Some(f.cb),
            },
        });
    }
}

// pin-project-lite cannot attach `#[cfg]` to individual fields, so the
// Go-client-idle state lives in a feature-gated copy of the struct.
#[cfg(feature = "go-client-idle")]
pin_project! {
    pub(crate) struct ResponseFutMap<B, E>
    where
        B: Body,
        B: 'static,
    {
        #[pin]
        fut: ResponseFuture,
        ping: Option<Recorder>,
        #[pin]
        send_stream: Option<Option<SendStream<SendBuf<<B as Body>::Data>>>>,
        exec: E,
        go_control: Option<GoRequestBodyOwner>,
        go_empty_request_sender: Option<GoEmptyRequestSender<<B as Body>::Data>>,
        go_response: Option<Response<h2::RecvStream>>,
        cancel_tx: Option<oneshot::Sender<()>>,
    }
}

#[cfg(not(feature = "go-client-idle"))]
pin_project! {
    pub(crate) struct ResponseFutMap<B, E>
    where
        B: Body,
        B: 'static,
    {
        #[pin]
        fut: ResponseFuture,
        ping: Option<Recorder>,
        #[pin]
        send_stream: Option<Option<SendStream<SendBuf<<B as Body>::Data>>>>,
        exec: E,
        cancel_tx: Option<oneshot::Sender<()>>,
    }
}

#[cfg(feature = "go-client-idle")]
impl<B: Body + 'static, E> ResponseFutMap<B, E> {
    pub(crate) fn go_has_request_control(&self) -> bool {
        self.go_control.is_some() || self.go_empty_request_sender.is_some()
    }

    pub(crate) fn go_cancel_undelivered(self: Pin<&mut Self>) {
        let this = self.project();
        if let Some(owner) = this.go_control.as_mut() {
            owner.control.cancel();
            owner.pending = false;
        }
        if let Some(sender) = this.go_empty_request_sender.as_mut() {
            sender.sender.go_cancel_request_after_response();
            sender.waiting = false;
        }
    }

    pub(crate) fn go_response_delivered(self: Pin<&mut Self>) {
        if let Some(owner) = self.project().go_control.as_mut() {
            owner.pending = false;
        }
    }
}

impl<B: Body + 'static, E> ResponseFutMap<B, E> {
    /// Signal the `pipe_task` to reset the stream (e.g. on client cancellation).
    pub(crate) fn cancel(self: Pin<&mut Self>) {
        if let Some(cancel_tx) = self.project().cancel_tx.take() {
            let _ = cancel_tx.send(());
        }
    }
}

impl<B, E> Future for ResponseFutMap<B, E>
where
    B: Body + 'static,
    E: Http2UpgradedExec<B::Data>,
{
    type Output = Result<Response<crate::body::Incoming>, (crate::Error, Option<Request<B>>)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.as_mut().project();

        #[cfg(feature = "go-client-idle")]
        let result = if let Some(response) = this.go_response.take() {
            Ok(response)
        } else {
            ready!(this.fut.poll(cx))
        };
        #[cfg(not(feature = "go-client-idle"))]
        let result = ready!(this.fut.poll(cx));

        #[cfg(feature = "go-client-idle")]
        if let Ok(response) = &result {
            if response.status().as_u16() > 299 {
                if let Some(control) = this.go_control.as_ref() {
                    control.control.stop();
                }
            }
            if this.go_empty_request_sender.is_some() && response.body().go_body_is_no_body() {
                if let Some(sender) = this.go_empty_request_sender.as_mut() {
                    if sender.sender.go_poll_finish_request_body(cx).is_pending() {
                        sender.waiting = true;
                        // Go waits donec for noBody plus an actual empty request.
                        // A MissingBody response remains observable immediately.
                        *this.go_response = result.ok();
                        return Poll::Pending;
                    }
                    // waitDone observes completion, not cleanup's abort error.
                    sender.waiting = false;
                    this.go_empty_request_sender.take();
                }
            }
        }

        let ping = this.ping.take().expect("Future polled twice");
        let send_stream = this.send_stream.take().expect("Future polled twice");

        match result {
            Ok(res) => {
                // record that we got the response headers
                ping.record_non_data();

                let content_length = headers::content_length_parse_all(res.headers());
                if let (Some(mut send_stream), StatusCode::OK) = (send_stream, res.status()) {
                    if content_length.map_or(false, |len| len != 0) {
                        warn!("h2 connect response with non-zero body not supported");

                        send_stream.send_reset(h2::Reason::INTERNAL_ERROR);
                        return Poll::Ready(Err((
                            crate::Error::new_h2(h2::Reason::INTERNAL_ERROR.into()),
                            None::<Request<B>>,
                        )));
                    }
                    let (parts, recv_stream) = res.into_parts();
                    let mut res = Response::from_parts(parts, IncomingBody::empty());

                    let (pending, on_upgrade) = crate::upgrade::pending();

                    let (h2_up, up_task) = super::upgrade::pair(send_stream, recv_stream, ping);
                    self.exec.execute_upgrade(up_task);
                    let upgraded = Upgraded::new(h2_up, Bytes::new());

                    pending.fulfill(upgraded);
                    res.extensions_mut().insert(on_upgrade);

                    Poll::Ready(Ok(res))
                } else {
                    let res = res.map(|stream| {
                        let ping = ping.for_stream(&stream);
                        IncomingBody::h2(stream, content_length.into(), ping)
                    });
                    Poll::Ready(Ok(res))
                }
            }
            Err(err) => {
                ping.ensure_not_timed_out().map_err(|e| (e, None))?;

                debug!("client response error: {}", err);
                Poll::Ready(Err((crate::Error::new_h2(err), None::<Request<B>>)))
            }
        }
    }
}

impl<B, E, T> Future for ClientTask<B, E, T>
where
    B: Body + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    E: Http2ClientConnExec<B, T> + Clone + Unpin,
    T: Read + Write + Unpin,
{
    type Output = crate::Result<Dispatched>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        #[cfg(feature = "go-client-idle")]
        if self.go_native_client {
            self.poll_go_cleanup(cx);
        }
        #[cfg(feature = "go-client-idle")]
        self.go_pending
            .retain_mut(|pending| pending.cb.poll_canceled(cx).is_pending());
        #[cfg(feature = "go-client-idle")]
        let mut native_steps = 0;
        loop {
            #[cfg(feature = "go-client-idle")]
            if self.go_native_client {
                if native_steps == 32 {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                native_steps += 1;
            }
            #[cfg(feature = "go-client-idle")]
            if let Some(mut pending) = self.go_pending.pop_front() {
                if pending.cb.poll_canceled(cx).is_ready() {
                    // Dropping an ID-free admission releases its header
                    // queue/reservation and queues the final writer check;
                    // no stream ID or RST is created.
                    continue;
                }
                match Pin::new(&mut pending.future).poll(cx) {
                    Poll::Pending => {
                        if pending.future.go_waiting_cleanup() {
                            // This waiter owns no header lock; retain its
                            // original unsent error independently of admission.
                            self.go_cleanup.push_back(pending);
                            continue;
                        }
                        // Keep accepting/canceling ID-free requests while this
                        // header lock is held, as Go's independent waiters do.
                        self.go_pending.push_front(pending);
                    }
                    Poll::Ready(Ok((fut, body_tx))) => {
                        self.poll_pipe(
                            FutCtx {
                                is_connect: pending.is_connect,
                                eos: pending.eos,
                                fut,
                                body_tx,
                                body: pending.body,
                                cb: pending.cb,
                            },
                            cx,
                        );
                        continue;
                    }
                    Poll::Ready(Err((error, request))) => {
                        let message = request.map(|request| {
                            let (parts, ()) = request.into_parts();
                            Request::from_parts(parts, pending.body)
                        });
                        pending.cb.send(Err(TrySendError {
                            error: crate::Error::new_h2(error),
                            message,
                        }));
                        continue;
                    }
                }
            }
            #[cfg(feature = "go-client-idle")]
            let classic_ready = !self.go_native_client;
            #[cfg(not(feature = "go-client-idle"))]
            let classic_ready = true;
            if classic_ready {
                match ready!(self.h2_tx.poll_ready(cx)) {
                    Ok(()) => (),
                    Err(err) => {
                        self.ping.ensure_not_timed_out()?;
                        return if err.reason() == Some(::h2::Reason::NO_ERROR) {
                            trace!("connection gracefully shutdown");
                            Poll::Ready(Ok(Dispatched::Shutdown))
                        } else {
                            Poll::Ready(Err(crate::Error::new_h2(err)))
                        };
                    }
                };
            }

            // If we were waiting on pending open
            // continue where we left off.
            if let Some(f) = self.fut_ctx.take() {
                self.poll_pipe(f, cx);
                continue;
            }

            match self.req_rx.poll_recv(cx) {
                Poll::Ready(Some((req, cb))) => {
                    // check that future hasn't been canceled already
                    if cb.is_canceled() {
                        #[cfg(feature = "go-client-idle")]
                        if self.go_native_client {
                            self.h2_tx.go_cancel_unsent_request(&req);
                        }
                        trace!("request callback is canceled");
                        continue;
                    }
                    let (head, body) = req.into_parts();
                    let mut req = ::http::Request::from_parts(head, ());
                    super::strip_connection_headers(req.headers_mut(), super::MessageKind::Request);
                    if let Some(len) = body.size_hint().exact() {
                        if len != 0 || headers::method_has_defined_payload_semantics(req.method()) {
                            headers::set_content_length_if_missing(req.headers_mut(), len);
                        }
                    }

                    let is_connect = req.method() == Method::CONNECT;
                    let eos = body.is_end_stream();

                    if is_connect
                        && headers::content_length_parse_all(req.headers())
                            .map_or(false, |len| len != 0)
                    {
                        debug!("h2 connect request with non-zero body not supported");
                        #[cfg(feature = "go-client-idle")]
                        if self.go_native_client {
                            self.h2_tx.go_cancel_unsent_request(&req);
                        }
                        cb.send(Err(TrySendError {
                            error: crate::Error::new_user_invalid_connect(),
                            message: None,
                        }));
                        continue;
                    }

                    if let Some(protocol) = req.extensions_mut().remove::<Protocol>() {
                        req.extensions_mut().insert(protocol.into_inner());
                    }

                    #[cfg(feature = "go-client-idle")]
                    if self.go_native_client {
                        let mut pending = GoPendingAdmission {
                            future: self.h2_tx.go_send_request(req, !is_connect && eos),
                            body,
                            cb,
                            is_connect,
                            eos,
                        };
                        // Cancellation must wake this task even when another
                        // request's header flight owns reqHeaderMu indefinitely.
                        if pending.cb.poll_canceled(cx).is_pending() {
                            self.go_pending.push_back(pending);
                        }
                        continue;
                    }

                    let (fut, body_tx) = match self.h2_tx.send_request(req, !is_connect && eos) {
                        Ok(ok) => ok,
                        Err(err) => {
                            debug!("client send request error: {}", err);
                            cb.send(Err(TrySendError {
                                error: crate::Error::new_h2(err),
                                message: None,
                            }));
                            continue;
                        }
                    };

                    let f = FutCtx {
                        is_connect,
                        eos,
                        fut,
                        body_tx,
                        body,
                        cb,
                    };

                    // Check poll_ready() again.
                    // If the call to send_request() resulted in the new stream being pending open
                    // we have to wait for the open to complete before accepting new requests.
                    match self.h2_tx.poll_ready(cx) {
                        Poll::Pending => {
                            // Save Context
                            self.fut_ctx = Some(f);
                            return Poll::Pending;
                        }
                        Poll::Ready(Ok(())) => (),
                        Poll::Ready(Err(err)) => {
                            f.cb.send(Err(TrySendError {
                                error: crate::Error::new_h2(err),
                                message: None,
                            }));
                            continue;
                        }
                    }
                    self.poll_pipe(f, cx);
                }

                Poll::Ready(None) => {
                    #[cfg(feature = "go-client-idle")]
                    if !self.go_pending.is_empty() || !self.go_cleanup.is_empty() {
                        // An accepted request is still owned until admission or
                        // cancellation even after every dispatch sender drops.
                        return Poll::Pending;
                    }
                    trace!("client::dispatch::Sender dropped");
                    return Poll::Ready(Ok(Dispatched::Shutdown));
                }

                Poll::Pending => match ready!(Pin::new(&mut self.conn_eof).poll(cx)) {
                    // As of Rust 1.82, this pattern is no longer needed, and emits a warning.
                    // But we cannot remove it as long as MSRV is less than that.
                    #[allow(unused)]
                    Ok(never) => match never {},
                    Err(_conn_is_eof) => {
                        #[cfg(feature = "go-client-idle")]
                        if !self.go_cleanup.is_empty() {
                            // Terminal connection cleanup completed these gates.
                            // Deliver their retained original errors first.
                            self.poll_go_cleanup(cx);
                        }
                        trace!("connection task is closed, closing dispatch task");
                        return Poll::Ready(Ok(Dispatched::Shutdown));
                    }
                },
            }
        }
    }
}
