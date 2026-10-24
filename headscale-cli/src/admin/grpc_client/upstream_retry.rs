// Copyright 2014 gRPC authors.
// Licensed under the Apache License, Version 2.0. See LICENSE-GRPC-GO and
// NOTICE-GRPC-GO in the headscale-cli package for the license and notices.

//! Unary replay following the pinned grpc-go stream.go retry decisions.

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine;
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt;
use rand_core::{OsRng, RngCore};
use tonic::body::Body;
use tonic::codegen::{Body as HttpBody, BoxFuture, Bytes, Service, StdError, http};
use tonic::{Code, Status};
use tower::ServiceExt;

use super::upstream_connection::Connection;
use super::upstream_service_config::{RetryPolicy, RetryThrottler};

const REPLAY_LIMIT: usize = 256 * 1024;

#[derive(Clone, Debug)]
pub(super) struct CallPolicy {
    pub(super) deadline: Option<tokio::time::Instant>,
    pub(super) retry: Option<RetryPolicy>,
    pub(super) throttler: Option<Arc<RetryThrottler>>,
    pub(super) outcome: Arc<Mutex<Option<u32>>>,
    pub(super) wait_for_ready: bool,
}

#[derive(Debug)]
pub(super) struct RetryExhausted {
    pub(super) attempts: u32,
    pub(super) status: Status,
}

impl fmt::Display for RetryExhausted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "max retries exhausted: failed after {} attempts: {}",
            self.attempts, self.status
        )
    }
}
impl Error for RetryExhausted {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.status)
    }
}

#[derive(Clone)]
pub(super) struct RetryChannel {
    inner: Connection,
}

impl RetryChannel {
    pub(super) fn new(inner: Connection) -> Self {
        Self { inner }
    }
}

impl Service<http::Request<Body>> for RetryChannel {
    type Response = http::Response<Body>;
    type Error = StdError;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, context: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(context).map_err(Into::into)
    }

    fn call(&mut self, request: http::Request<Body>) -> Self::Future {
        let policy = request.extensions().get::<CallPolicy>().cloned();
        let Some(policy) = policy else {
            let response = self.inner.call(request);
            return Box::pin(async move { guard_response(response.await?) });
        };
        let replacement = self.inner.clone();
        let channel = std::mem::replace(&mut self.inner, replacement);
        Box::pin(send(channel, request, policy))
    }
}

async fn send(
    mut channel: Connection,
    request: http::Request<Body>,
    policy: CallPolicy,
) -> Result<http::Response<Body>, StdError> {
    let (head, mut body) = request.into_parts();
    let mut frames = VecDeque::new();
    let mut length = 0_usize;
    // Even without a configured retry policy, a buffered first attempt can be
    // transparently replayed after an explicit remote REFUSED_STREAM.
    while let Some(frame) = body.frame().await {
        let frame = ReplayFrame::from_frame(frame?)?;
        length = length.saturating_add(frame.length());
        frames.push_back(frame);
        if length > REPLAY_LIMIT {
            let request = request_from(
                &head,
                Body::new(ReplayBody {
                    frames,
                    rest: Some(body),
                }),
                &policy,
                0,
            );
            let response = channel.ready().await?.call(request).await?;
            return guard_response(response);
        }
    }
    let mut first = true;
    let mut retries = 0_u32;
    let mut since_pushback = 0_u32;
    loop {
        if policy
            .deadline
            .is_some_and(|deadline| tokio::time::Instant::now() >= deadline)
        {
            return Err(Box::new(Status::deadline_exceeded(
                "context deadline exceeded",
            )));
        }
        let request = request_from(
            &head,
            Body::new(ReplayBody {
                frames: frames.clone(),
                rest: None,
            }),
            &policy,
            retries,
        );
        let result = match channel.ready().await {
            Ok(channel) => channel.call(request).await,
            Err(error) => Err(error),
        };
        let failure = match result {
            Ok(response) => {
                let response = guard_response(response)?;
                // A non-final initial header block commits the RPC, even if
                // later trailers carry a retryable code. Never replay it.
                if !response.body().is_end_stream() {
                    return Ok(response);
                }
                let Some(code) = response
                    .headers()
                    .get("grpc-status")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u32>().ok())
                    .filter(|code| *code <= 16)
                else {
                    return Ok(response);
                };
                if code == Code::Ok as u32 {
                    return Ok(response);
                }
                FailedAttempt::Trailers { response, code }
            }
            Err(error) if transparent_error(error.as_ref(), first) => {
                first = false;
                continue;
            }
            // No initial HTTP response headers were delivered. grpc-go marks
            // such closed streams noHeaders, so an explicit retry policy may
            // replay them; no policy means no replay of an ambiguous failure.
            Err(error) => FailedAttempt::Transport(Status::from_error(error)),
        };
        let code = failure.code();
        let Ok(pushback) = failure.pushback() else {
            if let Some(throttler) = &policy.throttler {
                throttler.failed();
            }
            return failure.finish();
        };
        let Some(retry) = &policy.retry else {
            return failure.finish();
        };
        if !retry.codes.contains(&code) {
            return failure.finish();
        }
        if policy
            .throttler
            .as_ref()
            .is_some_and(|throttler| throttler.failed())
        {
            return failure.finish();
        }
        if retries + 1 >= retry.maximum_attempts {
            *policy
                .outcome
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(retries + 1);
            return failure.finish();
        }
        let delay = if let Some(nanos) = pushback {
            since_pushback = 0;
            nanos
        } else {
            // Go converts these nanosecond counts with float64(...) the same way.
            #[allow(clippy::cast_precision_loss)]
            let limit = ((retry.initial_nanos as f64)
                * retry.multiplier.powf(f64::from(since_pushback)))
            .min(retry.maximum_nanos as f64);
            since_pushback = since_pushback.saturating_add(1);
            #[allow(clippy::cast_precision_loss)]
            let random = (OsRng.next_u64() >> 11) as f64 / ((1_u64 << 53) as f64);
            go_delay(limit * 0.4f64.mul_add(random, 0.8))
        };
        // Drop the completed failed response before waiting or opening another
        // attempt. The same RPC deadline covers every backoff and replay.
        drop(failure);
        if let Some(deadline) = policy.deadline {
            tokio::time::timeout_at(deadline, tokio::time::sleep(delay))
                .await
                .map_err(|_| {
                    Box::new(Status::deadline_exceeded("context deadline exceeded")) as StdError
                })?;
        } else {
            tokio::time::sleep(delay).await;
        }
        retries += 1;
        first = false;
    }
}

enum FailedAttempt {
    Trailers {
        response: http::Response<Body>,
        code: u32,
    },
    Transport(Status),
}

impl FailedAttempt {
    fn code(&self) -> u32 {
        match self {
            Self::Trailers { code, .. } => *code,
            Self::Transport(status) => status.code() as u32,
        }
    }
    fn pushback(&self) -> Result<Option<Duration>, ()> {
        match self {
            Self::Trailers { response, .. } => pushback(response.headers()),
            Self::Transport(_) => Ok(None),
        }
    }
    fn finish(self) -> Result<http::Response<Body>, StdError> {
        match self {
            Self::Trailers { response, .. } => Ok(response),
            Self::Transport(status) => Err(Box::new(status)),
        }
    }
}

fn request_from(
    original: &http::request::Parts,
    body: Body,
    policy: &CallPolicy,
    retries: u32,
) -> http::Request<Body> {
    let mut request = http::Request::new(body);
    *request.method_mut() = original.method.clone();
    *request.uri_mut() = original.uri.clone();
    *request.version_mut() = original.version;
    *request.headers_mut() = original.headers.clone();
    *request.extensions_mut() = original.extensions.clone();
    request.headers_mut().remove("grpc-previous-rpc-attempts");
    if retries != 0
        && let Ok(value) = retries.to_string().parse()
    {
        request
            .headers_mut()
            .insert("grpc-previous-rpc-attempts", value);
    }
    if let Some(deadline) = policy.deadline {
        let mut timeout = tonic::Request::new(());
        timeout.set_timeout(deadline.saturating_duration_since(tokio::time::Instant::now()));
        if let Some(value) = timeout
            .metadata()
            .get("grpc-timeout")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
        {
            request.headers_mut().insert("grpc-timeout", value);
        }
    }
    request
}

fn pushback(headers: &http::HeaderMap) -> Result<Option<Duration>, ()> {
    let mut values = headers.get_all("grpc-retry-pushback-ms").iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let milliseconds = value
        .to_str()
        .map_err(|_| ())?
        .parse::<i64>()
        .map_err(|_| ())?;
    if milliseconds < 0 {
        return Err(());
    }
    // Go multiplies in its signed duration representation before constructing
    // the timer. An overflowed/nonpositive duration fires immediately.
    let nanos = milliseconds.wrapping_mul(1_000_000);
    Ok(Some(if nanos <= 0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(nanos as u64)
    }))
}

fn go_delay(nanos: f64) -> Duration {
    if !nanos.is_finite() || nanos >= 9_223_372_036_854_775_808.0 || nanos <= 0.0 {
        Duration::ZERO
    } else {
        Duration::from_nanos(nanos as u64)
    }
}

fn transparent_error(error: &(dyn Error + 'static), first: bool) -> bool {
    let mut cause = Some(error);
    while let Some(error) = cause {
        if error.is::<super::upstream_transport::UnprocessedTransport>() {
            // The connector rejected a replacement before a new stream or
            // socket existed. Go permits transparent retry independently of
            // the configured attempt count in this case.
            return true;
        }
        if let Some(error) = error.downcast_ref::<h2::Error>() {
            return first
                && error.is_remote()
                && error.is_reset()
                && error.reason() == Some(h2::Reason::REFUSED_STREAM);
        }
        cause = error.source();
    }
    false
}

fn guard_response(response: http::Response<Body>) -> Result<http::Response<Body>, StdError> {
    validate_status_details(response.headers()).map_err(|status| Box::new(status) as StdError)?;
    Ok(response.map(|inner| Body::new(GuardedBody { inner })))
}

fn validate_status_details(headers: &http::HeaderMap) -> Result<(), Status> {
    // Tonic 0.14.6's status parser expects valid base64 here. Reject malformed
    // input before that parser instead of letting a remote header panic.
    use base64::alphabet::STANDARD;
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    let decoder = GeneralPurpose::new(
        &STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    for value in headers.get_all("grpc-status-details-bin") {
        if decoder.decode(value.as_bytes()).is_err() {
            return Err(Status::internal("malformed gRPC status details"));
        }
    }
    Ok(())
}

struct GuardedBody {
    inner: Body,
}

impl HttpBody for GuardedBody {
    type Data = Bytes;
    type Error = Status;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        match Pin::new(&mut self.inner).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(trailers) = frame.trailers_ref()
                    && let Err(status) = validate_status_details(trailers)
                {
                    return Poll::Ready(Some(Err(status)));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            result => result,
        }
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[derive(Clone)]
enum ReplayFrame {
    Data(Bytes),
    Trailers(http::HeaderMap),
}

impl ReplayFrame {
    fn from_frame(frame: Frame<Bytes>) -> Result<Self, StdError> {
        match frame.into_data() {
            Ok(data) => Ok(Self::Data(data)),
            Err(frame) => frame.into_trailers().map(Self::Trailers).map_err(|_| {
                Box::new(Status::internal("unsupported outbound gRPC body frame")) as StdError
            }),
        }
    }
    fn length(&self) -> usize {
        match self {
            Self::Data(data) => data.len(),
            Self::Trailers(_) => 0,
        }
    }
    fn into_frame(self) -> Frame<Bytes> {
        match self {
            Self::Data(data) => Frame::data(data),
            Self::Trailers(headers) => Frame::trailers(headers),
        }
    }
}

struct ReplayBody {
    frames: VecDeque<ReplayFrame>,
    rest: Option<Body>,
}

impl HttpBody for ReplayBody {
    type Data = Bytes;
    type Error = Status;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Status>>> {
        if let Some(frame) = self.frames.pop_front() {
            return Poll::Ready(Some(Ok(frame.into_frame())));
        }
        match &mut self.rest {
            Some(body) => Pin::new(body).poll_frame(context),
            None => Poll::Ready(None),
        }
    }
    fn is_end_stream(&self) -> bool {
        self.frames.is_empty() && self.rest.as_ref().is_none_or(HttpBody::is_end_stream)
    }
    fn size_hint(&self) -> SizeHint {
        // Preserve Tonic EncodeBody's unspecified length. Advertising an
        // exact buffered size makes Hyper synthesize Content-Length, which
        // grpc-go does not send for these unary requests.
        SizeHint::default()
    }
}
