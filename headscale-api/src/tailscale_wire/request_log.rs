//! Native request events from Headscale v0.29.5 hscontrol/app.go's log formatter.
//! Count streamed application bytes without collecting long-poll bodies.

use axum::{
    body::Body,
    extract::{ConnectInfo, Request},
    middleware::Next,
    response::Response,
};
use http_body::{Body as HttpBody, Frame, SizeHint};
use parking_lot::Mutex;
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

#[derive(Clone, Debug)]
pub(super) struct RequestLogRemoteAddr(pub(super) String);

pub(super) struct Event {
    method: String,
    path: String,
    proto: String,
    remote: String,
    start: Instant,
}

impl Event {
    pub(super) fn raw(head: &[u8], remote: RequestLogRemoteAddr, status: u16) -> RawEvent {
        let line = head.split(|byte| *byte == b'\n').next().unwrap_or_default();
        let mut fields = line.split(|byte| *byte == b' ');
        let method = String::from_utf8_lossy(fields.next().unwrap_or_default()).into_owned();
        let target = String::from_utf8_lossy(fields.next().unwrap_or_default());
        let path = crate::go_url::Url::parse(&target).map_or_else(
            |_| target.into_owned(),
            |url| String::from_utf8_lossy(url.path()).into_owned(),
        );
        let proto = String::from_utf8_lossy(fields.next().unwrap_or_default())
            .trim_end_matches('\r')
            .to_string();
        RawEvent(
            Some(Self {
                method,
                path,
                proto,
                remote: remote.0,
                start: Instant::now(),
            }),
            status,
        )
    }

    pub(super) fn new(req: &Request) -> Self {
        let path = crate::go_url::Url::parse(&req.uri().to_string()).map_or_else(
            |_| req.uri().path().to_string(),
            |url| String::from_utf8_lossy(url.path()).into_owned(),
        );
        let remote = req
            .extensions()
            .get::<RequestLogRemoteAddr>()
            .map(|remote| remote.0.clone())
            .or_else(|| {
                req.extensions()
                    .get::<ConnectInfo<SocketAddr>>()
                    .map(|peer| peer.0.to_string())
            })
            .unwrap_or_default();
        Self {
            method: req.method().to_string(),
            path,
            proto: format!("{:?}", req.version()),
            remote,
            start: Instant::now(),
        }
    }

    fn write(self, status: u16, bytes: u64) {
        tracing::info!(
            method = self.method,
            path = self.path,
            proto = self.proto,
            remote = self.remote,
            status,
            bytes,
            elapsed = self.start.elapsed().as_secs_f64() * 1000.0,
            "http request"
        );
    }
}

/// Hijacked connection bytes bypass chi's response byte counter. The caller
/// supplies the status written before the hijack (Noise 101, DERP fast-start 0).
pub(super) struct RawEvent(Option<Event>, u16);

impl Drop for RawEvent {
    fn drop(&mut self) {
        if let Some(event) = self.0.take() {
            event.write(self.1, 0);
        }
    }
}

#[derive(Clone)]
struct RequestOwner(Arc<Mutex<SharedEvent>>);

struct SharedEvent {
    event: Option<Event>,
    status: u16,
    bytes: u64,
    body_done: bool,
    upgrades: usize,
}

impl RequestOwner {
    fn finish(&self, body_done: bool, release_upgrade: bool) {
        let event = {
            let mut state = self.0.lock();
            state.body_done |= body_done;
            if release_upgrade {
                state.upgrades -= 1;
            }
            if state.body_done && state.upgrades == 0 {
                let status = state.status;
                let bytes = state.bytes;
                state.event.take().map(|event| (event, status, bytes))
            } else {
                None
            }
        };
        if let Some((event, status, bytes)) = event {
            event.write(status, bytes);
        }
    }
}

/// The outer native listener owns merged routes; inner control/Noise routers
/// start their own event only when no enclosing owner is present.
pub(super) fn start(req: &mut Request) -> Option<RequestScope> {
    if req.extensions().get::<RequestOwner>().is_some() {
        return None;
    }
    let owner = RequestOwner(Arc::new(Mutex::new(SharedEvent {
        event: Some(Event::new(req)),
        status: 0,
        bytes: 0,
        body_done: false,
        upgrades: 0,
    })));
    req.extensions_mut().insert(owner.clone());
    Some(RequestScope(owner))
}

pub(super) async fn middleware(mut req: Request, next: Next) -> Response {
    let event = start(&mut req);
    wrap(event, next.run(req).await)
}

pub(super) struct RequestScope(RequestOwner);

impl Drop for RequestScope {
    fn drop(&mut self) {
        self.0.finish(true, false);
    }
}

/// Transfer the synchronous Go handler lifetime into a spawned Rust upgrade.
/// The response body can finish first without prematurely writing the event.
pub(super) fn defer(req: &Request) -> Option<UpgradeGuard> {
    let owner = req.extensions().get::<RequestOwner>()?.clone();
    {
        let mut state = owner.0.lock();
        state.event.as_ref()?;
        state.upgrades += 1;
    }
    Some(UpgradeGuard(owner))
}

pub(super) struct UpgradeGuard(RequestOwner);

impl Drop for UpgradeGuard {
    fn drop(&mut self) {
        self.0.finish(false, true);
    }
}

pub(super) fn wrap(event: Option<RequestScope>, response: Response) -> Response {
    let Some(event) = event else {
        return response;
    };
    let (parts, body) = response.into_parts();
    event.0.0.lock().status = parts.status.as_u16();
    Response::from_parts(
        parts,
        Body::new(LoggedBody {
            body: Box::pin(body),
            event: Some(event),
        }),
    )
}

struct LoggedBody {
    body: Pin<Box<Body>>,
    event: Option<RequestScope>,
}

impl LoggedBody {
    fn finish(&mut self) {
        drop(self.event.take());
    }
}

impl HttpBody for LoggedBody {
    type Data = bytes::Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = self.body.as_mut().poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && let Some(event) = &self.event
                {
                    event.0.0.lock().bytes += data.len() as u64;
                }
                if self.body.is_end_stream() {
                    self.finish();
                }
            }
            Poll::Ready(None | Some(Err(_))) => self.finish(),
            Poll::Pending => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

impl Drop for LoggedBody {
    fn drop(&mut self) {
        self.finish();
    }
}
