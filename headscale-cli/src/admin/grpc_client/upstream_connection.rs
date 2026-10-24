// Copyright 2014 gRPC authors.
// Licensed under the Apache License, Version 2.0. See LICENSE-GRPC-GO and
// NOTICE-GRPC-GO in the headscale-cli package for the license and notices.

//! Owned connection readiness before unary dispatch, following grpc-go's
//! picker_wrapper.go and clientconn.go connection/backoff lifecycle.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use http_body::{Frame, SizeHint};
use tokio::sync::{Notify, watch};
use tonic::Status;
use tonic::body::Body;
use tonic::codegen::{Body as HttpBody, BoxFuture, Bytes, Service, StdError, http};
use tonic::transport::Channel;
use tower::ServiceExt;

use super::UpstreamConnectBackoff;
use super::upstream_retry::CallPolicy;
use super::upstream_transport::{ActiveTransport, Recipe, Scope, TransportLease};

#[derive(Clone)]
pub(super) struct Connection {
    kind: Kind,
}

#[derive(Clone)]
enum Kind {
    Static(Channel),
    Managed(Arc<Owner>),
}

struct Owner {
    picker: watch::Receiver<Picker>,
    scope: Arc<Scope>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.scope.cancel();
        self.task.abort();
    }
}

#[derive(Clone)]
pub(super) enum Picker {
    Idle(Arc<IdleWake>),
    Connecting,
    Ready(Arc<ReadySet>),
    Failed(String),
}

pub(super) struct ReadySet {
    transports: Vec<Arc<ActiveTransport>>,
    next: AtomicU32,
}

pub(super) struct IdleWake {
    signal: Arc<Notify>,
    started: AtomicBool,
}

impl IdleWake {
    pub(super) fn new(signal: Arc<Notify>) -> Arc<Self> {
        Arc::new(Self {
            signal,
            started: AtomicBool::new(false),
        })
    }

    fn wake(&self) {
        // Go's idlePicker uses sync.OnceFunc. Concurrent RPCs using the same
        // idle picker must not leave a permit for a later idle episode.
        if !self.started.swap(true, Ordering::AcqRel) {
            self.signal.notify_one();
        }
    }
}

impl Picker {
    pub(super) fn ready(transports: Vec<Arc<ActiveTransport>>) -> Self {
        if transports.is_empty() {
            return Self::Connecting;
        }
        let next = super::upstream_service_config::random_below(transports.len()) as u32;
        Self::Ready(Arc::new(ReadySet {
            transports,
            next: AtomicU32::new(next),
        }))
    }

    pub(super) fn is_ready(&self) -> bool {
        matches!(self, Self::Ready(ready) if ready.transports.iter().any(|transport| transport.alive()))
    }

    pub(super) fn is_connecting(&self) -> bool {
        matches!(self, Self::Connecting)
    }
}

impl ReadySet {
    fn pick(&self) -> Option<Arc<ActiveTransport>> {
        if self.transports.is_empty() {
            return None;
        }
        // endpointsharding seeds the counter randomly, then increments before
        // each pick. A retiring transport can disappear before its state event.
        let next = self.next.fetch_add(1, Ordering::Relaxed).wrapping_add(1) as usize;
        for offset in 0..self.transports.len() {
            let transport = &self.transports[next.wrapping_add(offset) % self.transports.len()];
            if transport.alive() {
                return Some(transport.clone());
            }
        }
        None
    }
}

impl Connection {
    pub(super) fn from_channel(channel: Channel) -> Self {
        Self {
            kind: Kind::Static(channel),
        }
    }

    pub(super) fn managed(recipe: Recipe, scope: Arc<Scope>, initial: ActiveTransport) -> Self {
        let initial = Arc::new(initial);
        let state = if initial.alive() {
            Picker::ready(vec![initial.clone()])
        } else {
            Picker::Connecting
        };
        let (send, picker) = watch::channel(state);
        let task = tokio::spawn(supervise(recipe, scope.clone(), initial, send));
        Self {
            kind: Kind::Managed(Arc::new(Owner {
                picker,
                scope,
                task,
            })),
        }
    }

    pub(super) fn managed_dns(recipe: Recipe, scope: Arc<Scope>) -> Self {
        let (send, picker) = watch::channel(Picker::Connecting);
        let task = tokio::spawn(super::upstream_balancer::supervise(
            recipe,
            scope.clone(),
            send,
        ));
        Self {
            kind: Kind::Managed(Arc::new(Owner {
                picker,
                scope,
                task,
            })),
        }
    }

    pub(super) async fn wait_initial(&self, deadline: tokio::time::Instant) -> Result<(), Status> {
        if let Kind::Managed(owner) = &self.kind {
            owner.pick(true, Some(deadline)).await?;
        }
        Ok(())
    }
}

impl Service<http::Request<Body>> for Connection {
    type Response = http::Response<Body>;
    type Error = StdError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        match &mut self.kind {
            Kind::Static(channel) => channel.poll_ready(context).map_err(Into::into),
            // The request carries fail-fast/wait-for-ready and its deadline.
            // Pick inside call(), before forwarding any request to a transport.
            Kind::Managed(_) => Poll::Ready(Ok(())),
        }
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        match &mut self.kind {
            Kind::Static(channel) => {
                let response = channel.call(request);
                Box::pin(async move { response.await.map_err(Into::into) })
            }
            Kind::Managed(owner) => Box::pin(dispatch(owner.clone(), request)),
        }
    }
}

async fn supervise(
    recipe: Recipe,
    scope: Arc<Scope>,
    initial: Arc<ActiveTransport>,
    send: watch::Sender<Picker>,
) {
    let mut current = initial;
    let wake = Arc::new(Notify::new());
    loop {
        let mut closed = current.closed.clone();
        loop {
            let finished = closed.borrow_and_update().is_some();
            if finished {
                break;
            }
            if closed.changed().await.is_err() {
                break;
            }
        }
        let _ = send.send_replace(Picker::Idle(IdleWake::new(wake.clone())));
        // In-flight dispatch/body owners retain their transport lease.
        // The first new RPC wakes IDLE, then observes readiness or failure.
        drop(current);
        wake.notified().await;
        let _ = send.send_replace(Picker::Connecting);
        let mut backoff = UpstreamConnectBackoff::default();
        loop {
            let delay = backoff.next_delay();
            let budget = delay.max(Duration::from_secs(20));
            match recipe.dial(budget, &scope).await {
                Ok(transport) if transport.alive() => {
                    current = Arc::new(transport);
                    let _ = send.send_replace(Picker::ready(vec![current.clone()]));
                    break;
                }
                Ok(_) => {
                    let _ =
                        send.send_replace(Picker::Failed("connection closed during setup".into()));
                }
                Err(error) => {
                    let _ = send.send_replace(Picker::Failed(error.to_string()));
                }
            }
            // Keep the failure picker during backoff and subsequent attempts.
            // Fail-fast calls return; wait-for-ready calls keep waiting.
            tokio::time::sleep(delay).await;
        }
    }
}

impl Owner {
    async fn pick(
        &self,
        wait_for_ready: bool,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Arc<ActiveTransport>, Status> {
        let mut picker = self.picker.clone();
        let mut last_error = None;
        loop {
            if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
                return Err(Status::deadline_exceeded("context deadline exceeded"));
            }
            let state = picker.borrow_and_update().clone();
            match state {
                Picker::Ready(ready) => {
                    if let Some(transport) = ready.pick() {
                        return Ok(transport);
                    }
                }
                Picker::Failed(error) if !wait_for_ready => return Err(Status::unavailable(error)),
                Picker::Failed(error) => last_error = Some(error),
                Picker::Idle(wake) => wake.wake(),
                Picker::Connecting => {}
            }
            let changed = if let Some(deadline) = deadline {
                match tokio::time::timeout_at(deadline, picker.changed()).await {
                    Ok(changed) => changed,
                    Err(_) => {
                        return Err(Status::deadline_exceeded(last_error.map_or_else(
                            || "context deadline exceeded while waiting for connections to become ready".into(),
                            |error| format!("latest balancer error: {error}"),
                        )));
                    }
                }
            } else {
                picker.changed().await
            };
            changed.map_err(|_| Status::unavailable("gRPC connection supervisor stopped"))?;
        }
    }
}

async fn dispatch(
    owner: Arc<Owner>,
    request: http::Request<Body>,
) -> Result<http::Response<Body>, StdError> {
    let (wait_for_ready, deadline) = {
        let policy = request.extensions().get::<CallPolicy>();
        (
            policy.is_some_and(|policy| policy.wait_for_ready),
            policy.and_then(|policy| policy.deadline),
        )
    };
    loop {
        let selected = owner.pick(wait_for_ready, deadline).await?;
        let mut channel = selected.channel();
        if let Err(error) = channel.ready().await {
            // Nothing was dispatched. Repicking here cannot duplicate an RPC.
            selected.retire(error.to_string());
            continue;
        }
        if !selected.alive() {
            continue;
        }
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            return Err(Box::new(Status::deadline_exceeded(
                "context deadline exceeded",
            )));
        }
        let lease = selected.lease.clone();
        // Once call() consumes the request, replay belongs exclusively to the
        // retry layer's explicit uncommitted/REFUSED_STREAM rules.
        let response = channel.call(request).await?;
        return Ok(response.map(|inner| {
            Body::new(LeasedBody {
                inner,
                _lease: lease,
            })
        }));
    }
}

struct LeasedBody {
    inner: Body,
    _lease: Arc<TransportLease>,
}

impl HttpBody for LeasedBody {
    type Data = Bytes;
    type Error = Status;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        Pin::new(&mut self.inner).poll_frame(context)
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
