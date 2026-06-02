//! Native DERP HTTP upgrade and stream driver.
//!
//! The supported production relay path is still the upstream `derper` sidecar.
//! This module wires the first native Rust `/derp` path for parity work:
//! normal HTTP upgrade, DERP login frames, and local relay routing.
//! `Derp-Fast-Start` no-response hijack is handled by the production raw TLS
//! listener before requests reach this Hyper/Axum handler.

use std::{
    borrow::Cow,
    collections::hash_map::DefaultHasher,
    fmt, fs,
    hash::{Hash, Hasher},
    io::{ErrorKind, Write},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use axum::{
    body::Body,
    extract::{
        FromRequestParts, Request, State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderValue, Response, StatusCode, header},
    response::IntoResponse,
};
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use headscale_core::derp::{
    native::{NativeDerpRelay, NativeDerpSession},
    protocol::{
        DerpNodeKeyPair, Frame, FrameDecoder, KEY_LEN, MAX_INFO_LEN, PROTOCOL_VERSION, ServerInfo,
        encode_frame, encode_server_info_frame, encode_server_key_frame, open_client_info,
    },
};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{WireError, WireState};

const DERP_UPGRADE_PROTOCOL: &str = "derp";
const WEBSOCKET_UPGRADE_PROTOCOL: &str = "websocket";
const DERP_FAST_START_HEADER: &str = "Derp-Fast-Start";
const DERP_VERSION_HEADER: &str = "Derp-Version";
const DERP_PUBLIC_KEY_HEADER: &str = "Derp-Public-Key";
const READ_BUF_LEN: usize = 16 * 1024;
const DERP_PRIVATE_KEY_PREFIX: &str = "privkey:";
const WEBSOCKET_UNSUPPORTED_DATA: u16 = 1003;
const DEFAULT_DERP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);
const DEFAULT_DERP_KEEPALIVE_JITTER: Duration = Duration::from_secs(5);
const MIN_DERP_KEEPALIVE_INTERVAL: Duration = Duration::from_millis(1);
pub const NATIVE_DERP_SHUTDOWN_HEALTH_PROBLEM: &str = "server restarting";
pub const NATIVE_DERP_SHUTDOWN_RECONNECT_IN: Duration = Duration::from_secs(1);
pub const NATIVE_DERP_SHUTDOWN_TRY_FOR: Duration = Duration::from_secs(5);

type NativeDerpClientVerifier = Arc<dyn Fn(&[u8; KEY_LEN]) -> bool + Send + Sync>;

/// Delivery counts for server-originated native DERP lifecycle broadcasts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeDerpLifecycleDelivery {
    pub health: usize,
    pub restarting: usize,
}

impl NativeDerpLifecycleDelivery {
    /// Total frames accepted by active session queues.
    pub const fn delivered(self) -> usize {
        self.health + self.restarting
    }
}

/// Admission counts for native DERP verify-client checks by transport.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeDerpAdmissionSnapshot {
    pub raw_allowed: u64,
    pub raw_denied: u64,
    pub websocket_allowed: u64,
    pub websocket_denied: u64,
}

impl NativeDerpAdmissionSnapshot {
    /// Total admitted native DERP handshakes.
    pub const fn allowed(self) -> u64 {
        self.raw_allowed + self.websocket_allowed
    }

    /// Total rejected native DERP handshakes.
    pub const fn denied(self) -> u64 {
        self.raw_denied + self.websocket_denied
    }

    /// Total native DERP verify-client decisions.
    pub const fn total(self) -> u64 {
        self.allowed() + self.denied()
    }
}

/// Debug snapshot for the native DERP runtime.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeDerpRuntimeSnapshot {
    pub client_verification_enabled: bool,
    pub admissions: NativeDerpAdmissionSnapshot,
}

#[derive(Debug, Default)]
struct NativeDerpAdmissionCounters {
    raw_allowed: AtomicU64,
    raw_denied: AtomicU64,
    websocket_allowed: AtomicU64,
    websocket_denied: AtomicU64,
}

impl NativeDerpAdmissionCounters {
    fn record(&self, transport: NativeDerpTransport, admitted: bool) {
        let counter = match (transport, admitted) {
            (NativeDerpTransport::Raw, true) => &self.raw_allowed,
            (NativeDerpTransport::Raw, false) => &self.raw_denied,
            (NativeDerpTransport::WebSocket, true) => &self.websocket_allowed,
            (NativeDerpTransport::WebSocket, false) => &self.websocket_denied,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> NativeDerpAdmissionSnapshot {
        NativeDerpAdmissionSnapshot {
            raw_allowed: self.raw_allowed.load(Ordering::Relaxed),
            raw_denied: self.raw_denied.load(Ordering::Relaxed),
            websocket_allowed: self.websocket_allowed.load(Ordering::Relaxed),
            websocket_denied: self.websocket_denied.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum NativeDerpTransport {
    Raw,
    WebSocket,
}

/// Shared native DERP runtime.
#[derive(Clone)]
pub struct NativeDerpRuntime {
    server_key: Arc<DerpNodeKeyPair>,
    relay: NativeDerpRelay,
    client_verifier: Option<NativeDerpClientVerifier>,
    admissions: Arc<NativeDerpAdmissionCounters>,
    keepalive_interval: Duration,
    keepalive_jitter: Duration,
    connection_sequence: Arc<AtomicU64>,
    health_problem: Arc<Mutex<Option<String>>>,
}

impl fmt::Debug for NativeDerpRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NativeDerpRuntime")
            .field("server_key", &self.server_key)
            .field("relay", &self.relay)
            .field(
                "client_verifier",
                &self.client_verifier.as_ref().map(|_| "<configured>"),
            )
            .field("admission_snapshot", &self.admission_snapshot())
            .field("keepalive_interval", &self.keepalive_interval)
            .field("keepalive_jitter", &self.keepalive_jitter)
            .field(
                "connection_sequence",
                &self.connection_sequence.load(Ordering::Relaxed),
            )
            .field("health_problem", &self.health_problem)
            .finish()
    }
}

impl NativeDerpRuntime {
    /// Create a runtime with a generated DERP server key.
    pub fn generate() -> Self {
        Self::new(DerpNodeKeyPair::generate(), NativeDerpRelay::new())
    }

    /// Load a native DERP private key from `path`, generating and persisting one
    /// in Tailscale's `privkey:<64 lowercase hex chars>` format if absent.
    ///
    /// Parent directories are created when the key is generated. On Unix the
    /// generated file is written with mode `0600`.
    pub fn load_or_generate_key(path: impl AsRef<Path>) -> Result<DerpNodeKeyPair, WireError> {
        let path = path.as_ref();
        match fs::read_to_string(path) {
            Ok(contents) => parse_derp_private_key(path, &contents),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                if let Some(parent) = path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    fs::create_dir_all(parent)?;
                }

                let key = DerpNodeKeyPair::generate();
                let encoded = format!(
                    "{DERP_PRIVATE_KEY_PREFIX}{}\n",
                    hex::encode(key.private_key())
                );
                write_derp_private_key(path, encoded.as_bytes())?;
                Ok(key)
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Create a runtime using a persisted native DERP private key and explicit
    /// relay.
    pub fn load_or_generate(
        path: impl AsRef<Path>,
        relay: NativeDerpRelay,
    ) -> Result<Self, WireError> {
        Ok(Self::new(Self::load_or_generate_key(path)?, relay))
    }

    /// Create a runtime from explicit protocol pieces.
    pub fn new(server_key: DerpNodeKeyPair, relay: NativeDerpRelay) -> Self {
        Self {
            server_key: Arc::new(server_key),
            relay,
            client_verifier: None,
            admissions: Arc::new(NativeDerpAdmissionCounters::default()),
            keepalive_interval: DEFAULT_DERP_KEEPALIVE_INTERVAL,
            keepalive_jitter: DEFAULT_DERP_KEEPALIVE_JITTER,
            connection_sequence: Arc::new(AtomicU64::new(0)),
            health_problem: Arc::new(Mutex::new(None)),
        }
    }

    /// Public DERP server key bytes.
    pub fn public_key(&self) -> [u8; KEY_LEN] {
        self.server_key.public_key()
    }

    /// Install a fail-closed client verifier for native DERP admissions.
    ///
    /// The verifier receives the DERP client's public node key bytes after the
    /// encrypted `ClientInfo` frame is opened and before the client is registered
    /// in the relay.
    pub fn with_client_verifier<F>(mut self, verifier: F) -> Self
    where
        F: Fn(&[u8; KEY_LEN]) -> bool + Send + Sync + 'static,
    {
        self.client_verifier = Some(Arc::new(verifier));
        self
    }

    /// Override the native DERP keepalive interval.
    ///
    /// Tailscale DERP sends server-originated keepalives at least every 60s,
    /// with a small per-connection jitter. Tests may lower this interval.
    pub fn with_keepalive_interval(mut self, interval: Duration) -> Self {
        self.keepalive_interval = if interval.is_zero() {
            MIN_DERP_KEEPALIVE_INTERVAL
        } else {
            interval
        };
        self
    }

    /// Override the maximum per-connection keepalive jitter.
    pub fn with_keepalive_jitter(mut self, jitter: Duration) -> Self {
        self.keepalive_jitter = jitter;
        self
    }

    /// Whether a native DERP client verifier is configured.
    pub fn client_verification_enabled(&self) -> bool {
        self.client_verifier.is_some()
    }

    /// Return whether a client public key is admitted to the native relay.
    pub fn admit_client(&self, client_public: &[u8; KEY_LEN]) -> bool {
        match &self.client_verifier {
            Some(verifier) => verifier(client_public),
            None => true,
        }
    }

    /// Current native DERP verify-client decision counts by transport.
    pub fn admission_snapshot(&self) -> NativeDerpAdmissionSnapshot {
        self.admissions.snapshot()
    }

    /// Current native DERP runtime state for debug surfaces.
    pub fn debug_snapshot(&self) -> NativeDerpRuntimeSnapshot {
        NativeDerpRuntimeSnapshot {
            client_verification_enabled: self.client_verification_enabled(),
            admissions: self.admission_snapshot(),
        }
    }

    fn verify_client_for_transport(
        &self,
        transport: NativeDerpTransport,
        client_public: &[u8; KEY_LEN],
    ) -> bool {
        let admitted = self.admit_client(client_public);
        self.admissions.record(transport, admitted);
        admitted
    }

    /// Set the current server health problem and broadcast it to active
    /// sessions. Passing an empty string clears the health problem.
    pub async fn set_health_problem(&self, problem: impl Into<String>) -> usize {
        let problem = problem.into();
        let should_broadcast = {
            let mut guard = self
                .health_problem
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let had_problem = guard.is_some();
            if problem.is_empty() {
                *guard = None;
                had_problem
            } else {
                *guard = Some(problem.clone());
                true
            }
        };

        if should_broadcast {
            self.relay.broadcast_frame(Frame::Health(problem)).await
        } else {
            0
        }
    }

    /// Clear the current server health problem and notify active sessions that
    /// previously saw a problem.
    pub async fn clear_health_problem(&self) -> usize {
        self.set_health_problem(String::new()).await
    }

    /// Broadcast a server-restarting advisory to active DERP sessions.
    pub async fn announce_restarting(&self, reconnect_in: Duration, try_for: Duration) -> usize {
        self.relay
            .broadcast_frame(Frame::Restarting {
                reconnect_in_ms: duration_millis_u32(reconnect_in),
                try_for_ms: duration_millis_u32(try_for),
            })
            .await
    }

    /// Announce the production server shutdown/restart lifecycle to active
    /// native DERP clients.
    pub async fn announce_server_shutdown(&self) -> NativeDerpLifecycleDelivery {
        let health = self
            .set_health_problem(NATIVE_DERP_SHUTDOWN_HEALTH_PROBLEM)
            .await;
        let restarting = self
            .announce_restarting(
                NATIVE_DERP_SHUTDOWN_RECONNECT_IN,
                NATIVE_DERP_SHUTDOWN_TRY_FOR,
            )
            .await;

        NativeDerpLifecycleDelivery { health, restarting }
    }

    fn current_health_frame(&self) -> Option<Frame> {
        self.health_problem
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .map(Frame::Health)
    }

    fn next_keepalive_delay(&self, client_public: &[u8; KEY_LEN]) -> Duration {
        let max_jitter_nanos = self.keepalive_jitter.as_nanos();
        if max_jitter_nanos == 0 {
            return self.keepalive_interval;
        }

        let connection_id = self.connection_sequence.fetch_add(1, Ordering::Relaxed);
        let mut hasher = DefaultHasher::new();
        client_public.hash(&mut hasher);
        connection_id.hash(&mut hasher);

        let jitter_bound = max_jitter_nanos.min(u128::from(u64::MAX - 1)) as u64;
        let jitter = Duration::from_nanos(hasher.finish() % (jitter_bound + 1));
        self.keepalive_interval
            .checked_add(jitter)
            .unwrap_or(self.keepalive_interval)
    }
}

fn duration_millis_u32(duration: Duration) -> u32 {
    duration.as_millis().min(u128::from(u32::MAX)) as u32
}

fn parse_derp_private_key(path: &Path, contents: &str) -> Result<DerpNodeKeyPair, WireError> {
    let text = contents.trim();
    let Some(hex_key) = text.strip_prefix(DERP_PRIVATE_KEY_PREFIX) else {
        return Err(WireError::Internal(format!(
            "DERP private key at {} must start with {DERP_PRIVATE_KEY_PREFIX}",
            path.display()
        )));
    };
    if hex_key.len() != KEY_LEN * 2
        || !hex_key
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(WireError::Internal(format!(
            "DERP private key at {} must be {DERP_PRIVATE_KEY_PREFIX}<64 lowercase hex chars>",
            path.display()
        )));
    }

    let decoded = hex::decode(hex_key).map_err(|err| {
        WireError::Internal(format!(
            "parse DERP private key at {}: {err}",
            path.display()
        ))
    })?;
    let private: [u8; KEY_LEN] = decoded.try_into().map_err(|decoded: Vec<u8>| {
        WireError::Internal(format!(
            "DERP private key at {} decoded to {} bytes; expected {KEY_LEN}",
            path.display(),
            decoded.len()
        ))
    })?;
    DerpNodeKeyPair::from_private_key(private).map_err(|err| {
        WireError::Internal(format!(
            "invalid DERP private key at {}: {err}",
            path.display()
        ))
    })
}

fn write_derp_private_key(path: &Path, contents: &[u8]) -> Result<(), WireError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

/// Native `/derp` handler.
pub async fn handle_derp(State(state): State<WireState>, req: Request) -> Response<Body> {
    let Some(runtime) = state.native_derp else {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::empty())
            .unwrap();
    };

    let upgrade = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_ascii_lowercase);
    let Some(upgrade) = upgrade else {
        return derp_upgrade_required_response();
    };

    match upgrade.as_str() {
        DERP_UPGRADE_PROTOCOL => {}
        WEBSOCKET_UPGRADE_PROTOCOL => {
            if header_contains_derp_protocol(req.headers()) {
                return handle_derp_websocket_upgrade(runtime, req).await;
            }
            return derp_upgrade_required_response();
        }
        _ => return derp_upgrade_required_response(),
    }

    if req
        .headers()
        .get(DERP_FAST_START_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v == "1")
    {
        // Production raw TLS intercepts DERP fast-start before Hyper and
        // suppresses the HTTP response entirely. If a fast-start request reaches
        // this handler, we are on a synthetic/non-production Hyper path where
        // the upstream no-response hijack cannot be represented.
        return Response::builder()
            .status(StatusCode::NOT_IMPLEMENTED)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from("DERP fast-start upgrade not implemented\n"))
            .unwrap();
    }

    let on_upgrade = match req.extensions().get::<hyper::upgrade::OnUpgrade>() {
        Some(_) => req
            .into_parts()
            .0
            .extensions
            .remove::<hyper::upgrade::OnUpgrade>(),
        None => None,
    };
    let Some(on_upgrade) = on_upgrade else {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Body::from(
                "derp: hyper OnUpgrade extension missing - not an upgradable connection",
            ))
            .unwrap();
    };

    let public_key_header = format!("nodekey:{}", hex::encode(runtime.public_key()));

    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                if let Err(e) = drive_native_derp(runtime, io).await {
                    tracing::warn!(target = "tailscale_wire::derp", error = %e, "native DERP connection ended with error");
                }
            }
            Err(e) => {
                tracing::warn!(target = "tailscale_wire::derp", error = %e, "native DERP upgrade future failed");
            }
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, HeaderValue::from_static("upgrade"))
        .header(header::UPGRADE, HeaderValue::from_static("DERP"))
        .header(
            DERP_VERSION_HEADER,
            HeaderValue::from_str(&PROTOCOL_VERSION.to_string()).unwrap(),
        )
        .header(
            DERP_PUBLIC_KEY_HEADER,
            HeaderValue::from_str(&public_key_header).unwrap(),
        )
        .body(Body::empty())
        .unwrap()
}

async fn handle_derp_websocket_upgrade(
    runtime: Arc<NativeDerpRuntime>,
    req: Request,
) -> Response<Body> {
    let (mut parts, _body) = req.into_parts();
    let websocket = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(websocket) => websocket,
        Err(err) => return err.into_response(),
    };

    websocket
        .protocols([DERP_UPGRADE_PROTOCOL])
        .on_failed_upgrade(|err| {
            tracing::warn!(target = "tailscale_wire::derp", error = %err, "native DERP websocket upgrade failed");
        })
        .on_upgrade(move |socket| async move {
            if let Err(e) = drive_native_derp_websocket(runtime, socket).await {
                tracing::warn!(target = "tailscale_wire::derp", error = %e, "native DERP websocket connection ended with error");
            }
        })
}

/// Drive one upgraded native DERP stream.
pub async fn drive_native_derp<T>(runtime: Arc<NativeDerpRuntime>, io: T) -> Result<(), WireError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut reader, mut writer) = tokio::io::split(io);

    let server_key = encode_server_key_frame(&runtime.server_key)
        .map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?;
    writer.write_all(&server_key).await?;
    writer.flush().await?;

    let mut decoder = FrameDecoder::new(MAX_INFO_LEN);
    let first = read_next_frame(&mut reader, &mut decoder).await?;
    let (client_public, _client_info) = open_client_info(&runtime.server_key, &first)
        .map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?;
    if !runtime.verify_client_for_transport(NativeDerpTransport::Raw, &client_public) {
        return Err(WireError::Internal(
            "DERP client was not admitted by verifier".into(),
        ));
    }

    let session = runtime.relay.connect(client_public).await;
    let session_id = session.session_id();
    let result = async {
        let server_info =
            encode_server_info_frame(&runtime.server_key, &client_public, &ServerInfo::current())
                .map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?;
        writer.write_all(&server_info).await?;
        writer.flush().await?;
        if let Some(frame) = runtime.current_health_frame() {
            write_derp_frame(&mut writer, &frame).await?;
        }

        let keepalive_delay = runtime.next_keepalive_delay(&client_public);
        run_relay_loop(session, reader, writer, decoder, keepalive_delay).await
    }
    .await;
    runtime
        .relay
        .disconnect_session(&client_public, session_id)
        .await;
    result
}

/// Drive one upgraded native DERP WebSocket stream.
pub async fn drive_native_derp_websocket(
    runtime: Arc<NativeDerpRuntime>,
    socket: WebSocket,
) -> Result<(), WireError> {
    let (writer, reader) = socket.split();
    drive_native_derp_websocket_parts(runtime, writer, reader).await
}

async fn drive_native_derp_websocket_parts<W, R, WE, RE>(
    runtime: Arc<NativeDerpRuntime>,
    mut writer: W,
    mut reader: R,
) -> Result<(), WireError>
where
    W: Sink<Message, Error = WE> + Unpin,
    WE: std::fmt::Display,
    R: Stream<Item = Result<Message, RE>> + Unpin,
    RE: std::fmt::Display,
{
    let server_key = encode_server_key_frame(&runtime.server_key)
        .map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?;
    send_websocket_binary(&mut writer, server_key).await?;

    let mut decoder = FrameDecoder::new(MAX_INFO_LEN);
    let first = read_next_websocket_frame(&mut reader, &mut decoder).await?;
    let (client_public, _client_info) = open_client_info(&runtime.server_key, &first)
        .map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?;
    if !runtime.verify_client_for_transport(NativeDerpTransport::WebSocket, &client_public) {
        return Err(WireError::Internal(
            "DERP client was not admitted by verifier".into(),
        ));
    }

    let session = runtime.relay.connect(client_public).await;
    let session_id = session.session_id();
    let result = async {
        let server_info =
            encode_server_info_frame(&runtime.server_key, &client_public, &ServerInfo::current())
                .map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?;
        send_websocket_binary(&mut writer, server_info).await?;
        if let Some(frame) = runtime.current_health_frame() {
            send_websocket_derp_frame(&mut writer, &frame).await?;
        }

        let keepalive_delay = runtime.next_keepalive_delay(&client_public);
        run_websocket_relay_loop(session, reader, writer, decoder, keepalive_delay).await
    }
    .await;
    runtime
        .relay
        .disconnect_session(&client_public, session_id)
        .await;
    result
}

async fn run_relay_loop<R, W>(
    mut session: NativeDerpSession,
    mut reader: R,
    mut writer: W,
    mut decoder: FrameDecoder,
    keepalive_delay: Duration,
) -> Result<(), WireError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    enum RelayLoopEvent {
        Read(std::io::Result<usize>),
        Outbound(Option<Frame>),
        KeepAlive,
    }

    let mut buf = vec![0u8; READ_BUF_LEN];
    let keepalive_sleep = tokio::time::sleep(keepalive_delay);
    tokio::pin!(keepalive_sleep);
    loop {
        while let Some(frame) = decoder
            .next_frame()
            .map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?
        {
            session
                .handle_frame(frame)
                .await
                .map_err(|err| WireError::Internal(format!("DERP relay: {err}")))?;
        }

        let event = tokio::select! {
            read = reader.read(&mut buf) => RelayLoopEvent::Read(read),
            outbound = session.recv() => RelayLoopEvent::Outbound(outbound),
            () = &mut keepalive_sleep => RelayLoopEvent::KeepAlive,
        };

        match event {
            RelayLoopEvent::Read(read) => {
                let n = read?;
                if n == 0 {
                    return Ok(());
                }
                decoder.push(&buf[..n]);
            }
            RelayLoopEvent::Outbound(outbound) => {
                let Some(frame) = outbound else {
                    return Ok(());
                };
                write_derp_frame(&mut writer, &frame).await?;
            }
            RelayLoopEvent::KeepAlive => {
                write_derp_frame(&mut writer, &Frame::KeepAlive).await?;
                keepalive_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + keepalive_delay);
            }
        }
    }
}

async fn run_websocket_relay_loop<R, W, RE, WE>(
    mut session: NativeDerpSession,
    mut reader: R,
    mut writer: W,
    mut decoder: FrameDecoder,
    keepalive_delay: Duration,
) -> Result<(), WireError>
where
    R: Stream<Item = Result<Message, RE>> + Unpin,
    RE: std::fmt::Display,
    W: Sink<Message, Error = WE> + Unpin,
    WE: std::fmt::Display,
{
    enum WebsocketRelayLoopEvent {
        Incoming(Result<WebsocketInput, WireError>),
        Outbound(Option<Frame>),
        KeepAlive,
    }

    let keepalive_sleep = tokio::time::sleep(keepalive_delay);
    tokio::pin!(keepalive_sleep);
    loop {
        while let Some(frame) = decoder
            .next_frame()
            .map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?
        {
            session
                .handle_frame(frame)
                .await
                .map_err(|err| WireError::Internal(format!("DERP relay: {err}")))?;
        }

        let event = tokio::select! {
            incoming = next_websocket_input(&mut reader) => {
                WebsocketRelayLoopEvent::Incoming(incoming)
            }
            outbound = session.recv() => WebsocketRelayLoopEvent::Outbound(outbound),
            () = &mut keepalive_sleep => WebsocketRelayLoopEvent::KeepAlive,
        };

        match event {
            WebsocketRelayLoopEvent::Incoming(incoming) => match incoming? {
                WebsocketInput::Binary(bytes) => decoder.push(&bytes),
                WebsocketInput::Control => {}
                WebsocketInput::Closed => return Ok(()),
                WebsocketInput::Unsupported => {
                    let _ = send_websocket_close(
                        &mut writer,
                        WEBSOCKET_UNSUPPORTED_DATA,
                        "DERP websocket requires binary messages",
                    )
                    .await;
                    return Err(WireError::Internal(
                        "DERP websocket requires binary messages".into(),
                    ));
                }
            },
            WebsocketRelayLoopEvent::Outbound(outbound) => {
                let Some(frame) = outbound else {
                    return Ok(());
                };
                send_websocket_derp_frame(&mut writer, &frame).await?;
            }
            WebsocketRelayLoopEvent::KeepAlive => {
                send_websocket_derp_frame(&mut writer, &Frame::KeepAlive).await?;
                keepalive_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + keepalive_delay);
            }
        }
    }
}

async fn write_derp_frame<W>(writer: &mut W, frame: &Frame) -> Result<(), WireError>
where
    W: AsyncWrite + Unpin,
{
    let encoded =
        encode_frame(frame).map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_next_frame<R>(reader: &mut R, decoder: &mut FrameDecoder) -> Result<Frame, WireError>
where
    R: AsyncRead + Unpin,
{
    let mut buf = vec![0u8; READ_BUF_LEN];
    loop {
        if let Some(frame) = decoder
            .next_frame()
            .map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?
        {
            return Ok(frame);
        }
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Err(WireError::Internal(
                "DERP connection closed during handshake".into(),
            ));
        }
        decoder.push(&buf[..n]);
    }
}

async fn read_next_websocket_frame<R, RE>(
    reader: &mut R,
    decoder: &mut FrameDecoder,
) -> Result<Frame, WireError>
where
    R: Stream<Item = Result<Message, RE>> + Unpin,
    RE: std::fmt::Display,
{
    loop {
        if let Some(frame) = decoder
            .next_frame()
            .map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?
        {
            return Ok(frame);
        }
        match next_websocket_input(reader).await? {
            WebsocketInput::Binary(bytes) => decoder.push(&bytes),
            WebsocketInput::Control => {}
            WebsocketInput::Closed => {
                return Err(WireError::Internal(
                    "DERP websocket closed during handshake".into(),
                ));
            }
            WebsocketInput::Unsupported => {
                return Err(WireError::Internal(
                    "DERP websocket requires binary messages".into(),
                ));
            }
        }
    }
}

enum WebsocketInput {
    Binary(Vec<u8>),
    Control,
    Closed,
    Unsupported,
}

async fn next_websocket_input<R, RE>(reader: &mut R) -> Result<WebsocketInput, WireError>
where
    R: Stream<Item = Result<Message, RE>> + Unpin,
    RE: std::fmt::Display,
{
    match reader.next().await {
        Some(Ok(Message::Binary(bytes))) => Ok(WebsocketInput::Binary(bytes)),
        Some(Ok(Message::Text(_))) => Ok(WebsocketInput::Unsupported),
        Some(Ok(Message::Ping(_) | Message::Pong(_))) => Ok(WebsocketInput::Control),
        Some(Ok(Message::Close(_))) | None => Ok(WebsocketInput::Closed),
        Some(Err(err)) => Err(WireError::Internal(format!("DERP websocket: {err}"))),
    }
}

async fn send_websocket_binary<W, WE>(writer: &mut W, bytes: Vec<u8>) -> Result<(), WireError>
where
    W: Sink<Message, Error = WE> + Unpin,
    WE: std::fmt::Display,
{
    writer
        .send(Message::Binary(bytes))
        .await
        .map_err(|err| WireError::Internal(format!("DERP websocket: {err}")))
}

async fn send_websocket_derp_frame<W, WE>(writer: &mut W, frame: &Frame) -> Result<(), WireError>
where
    W: Sink<Message, Error = WE> + Unpin,
    WE: std::fmt::Display,
{
    let encoded =
        encode_frame(frame).map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?;
    send_websocket_binary(writer, encoded).await
}

async fn send_websocket_close<W, WE>(
    writer: &mut W,
    code: u16,
    reason: &'static str,
) -> Result<(), WireError>
where
    W: Sink<Message, Error = WE> + Unpin,
    WE: std::fmt::Display,
{
    writer
        .send(Message::Close(Some(CloseFrame {
            code,
            reason: Cow::Borrowed(reason),
        })))
        .await
        .map_err(|err| WireError::Internal(format!("DERP websocket: {err}")))
}

fn derp_upgrade_required_response() -> Response<Body> {
    Response::builder()
        .status(StatusCode::UPGRADE_REQUIRED)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from("DERP requires connection upgrade\n"))
        .unwrap()
}

fn header_contains_derp_protocol(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|protocols| {
            protocols
                .split(',')
                .any(|protocol| protocol.trim().eq_ignore_ascii_case("derp"))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::routing::any;
    use headscale_core::derp::native::DUPLICATE_CONNECTION_HEALTH;
    use headscale_core::derp::protocol::{
        ClientInfo, FrameType, PeerGoneReason, encode_client_info_frame, encode_raw_frame,
        open_server_info,
    };
    use http_body_util::BodyExt;
    use std::io;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    #[tokio::test]
    async fn derp_route_rejects_missing_upgrade_like_headscale_go() {
        let app = Router::new()
            .route("/derp", any(handle_derp))
            .with_state(test_state_with_native_derp());
        let resp = app
            .oneshot(Request::builder().uri("/derp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UPGRADE_REQUIRED);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"DERP requires connection upgrade\n");
    }

    #[tokio::test]
    async fn derp_route_rejects_websocket_without_derp_protocol() {
        let app = Router::new()
            .route("/derp", any(handle_derp))
            .with_state(test_state_with_native_derp());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/derp")
                    .header(header::UPGRADE, "websocket")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UPGRADE_REQUIRED);
    }

    #[tokio::test]
    async fn drive_native_derp_completes_login_and_routes_ping() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let allowed_public = client_key.public_key();
        let runtime = Arc::new(
            NativeDerpRuntime::new(
                DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
                NativeDerpRelay::new(),
            )
            .with_client_verifier(move |client_public| client_public == &allowed_public),
        );
        assert!(runtime.client_verification_enabled());
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_runtime = runtime.clone();
        let server =
            tokio::spawn(async move { drive_native_derp(server_runtime, server_io).await });
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);
        let mut decoder = FrameDecoder::new(MAX_INFO_LEN);

        let server_key = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap();
        let Frame::ServerKey {
            key: server_public,
            extra,
        } = server_key
        else {
            panic!("expected server-key frame");
        };
        assert_eq!(server_public, runtime.public_key());
        assert!(extra.is_empty());

        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        client_writer.write_all(&client_info).await.unwrap();
        client_writer.flush().await.unwrap();

        let server_info_frame = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap();
        let server_info =
            open_server_info(&client_key, &server_public, &server_info_frame).unwrap();
        assert_eq!(server_info, ServerInfo::current());

        client_writer
            .write_all(&encode_raw_frame(FrameType::Ping.code(), b"12345678").unwrap())
            .await
            .unwrap();
        client_writer.flush().await.unwrap();
        let pong = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap();
        assert_eq!(pong, Frame::Pong(*b"12345678"));

        drop(client_writer);
        drop(client_reader);
        assert!(server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn native_derp_verify_client_counts_raw_and_websocket_admissions() {
        let raw_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let raw_public = raw_key.public_key();
        let websocket_key = DerpNodeKeyPair::from_private_key([7u8; KEY_LEN]).unwrap();
        let websocket_public = websocket_key.public_key();
        let runtime = Arc::new(
            NativeDerpRuntime::new(
                DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
                NativeDerpRelay::new(),
            )
            .with_client_verifier(move |client_public| {
                client_public == &raw_public || client_public == &websocket_public
            }),
        );

        let raw = start_raw_derp_client(runtime.clone(), &raw_key).await;
        let websocket = start_websocket_derp_client(runtime.clone(), &websocket_key).await;

        assert_eq!(
            runtime.admission_snapshot(),
            NativeDerpAdmissionSnapshot {
                raw_allowed: 1,
                raw_denied: 0,
                websocket_allowed: 1,
                websocket_denied: 0,
            }
        );
        assert_eq!(runtime.admission_snapshot().allowed(), 2);
        assert_eq!(runtime.admission_snapshot().denied(), 0);
        assert_eq!(runtime.admission_snapshot().total(), 2);
        assert_eq!(runtime.relay.session_count().await, 2);

        drop(raw.writer);
        drop(raw.reader);
        assert!(raw.server.await.unwrap().is_ok());

        websocket.tx.send(Ok(Message::Close(None))).await.unwrap();
        assert!(websocket.server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn drive_native_derp_routes_packet_and_reports_source_disconnect() {
        let source_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let source_public = source_key.public_key();
        let destination_key = DerpNodeKeyPair::from_private_key([7u8; KEY_LEN]).unwrap();
        let destination_public = destination_key.public_key();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));

        let (source_client_io, source_server_io) = tokio::io::duplex(4096);
        let source_server_runtime = runtime.clone();
        let source_server = tokio::spawn(async move {
            drive_native_derp(source_server_runtime, source_server_io).await
        });
        let (mut source_reader, mut source_writer) = tokio::io::split(source_client_io);
        let mut source_decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: server_public, ..
        } = read_next_frame(&mut source_reader, &mut source_decoder)
            .await
            .unwrap()
        else {
            panic!("expected source server-key frame");
        };
        let source_info =
            encode_client_info_frame(&source_key, &server_public, &ClientInfo::regular()).unwrap();
        source_writer.write_all(&source_info).await.unwrap();
        source_writer.flush().await.unwrap();
        let server_info_frame = read_next_frame(&mut source_reader, &mut source_decoder)
            .await
            .unwrap();
        assert_eq!(
            open_server_info(&source_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );

        let (destination_client_io, destination_server_io) = tokio::io::duplex(4096);
        let destination_server_runtime = runtime.clone();
        let destination_server = tokio::spawn(async move {
            drive_native_derp(destination_server_runtime, destination_server_io).await
        });
        let (mut destination_reader, mut destination_writer) =
            tokio::io::split(destination_client_io);
        let mut destination_decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: destination_server_public,
            ..
        } = read_next_frame(&mut destination_reader, &mut destination_decoder)
            .await
            .unwrap()
        else {
            panic!("expected destination server-key frame");
        };
        assert_eq!(destination_server_public, server_public);
        let destination_info =
            encode_client_info_frame(&destination_key, &server_public, &ClientInfo::regular())
                .unwrap();
        destination_writer
            .write_all(&destination_info)
            .await
            .unwrap();
        destination_writer.flush().await.unwrap();
        let server_info_frame = read_next_frame(&mut destination_reader, &mut destination_decoder)
            .await
            .unwrap();
        assert_eq!(
            open_server_info(&destination_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );

        let packet = b"native derp packet over raw runtime".to_vec();
        let send_packet = encode_frame(&Frame::SendPacket {
            destination: destination_public,
            packet: packet.clone(),
        })
        .unwrap();
        source_writer.write_all(&send_packet).await.unwrap();
        source_writer.flush().await.unwrap();

        let received = tokio::time::timeout(
            Duration::from_millis(250),
            read_next_frame(&mut destination_reader, &mut destination_decoder),
        )
        .await
        .expect("timed out waiting for relayed DERP packet")
        .unwrap();
        assert_eq!(
            received,
            Frame::RecvPacket {
                source: source_public,
                packet
            }
        );

        drop(source_writer);
        drop(source_reader);
        assert!(source_server.await.unwrap().is_ok());

        let gone = tokio::time::timeout(
            Duration::from_millis(250),
            read_next_frame(&mut destination_reader, &mut destination_decoder),
        )
        .await
        .expect("timed out waiting for source disconnect PeerGone")
        .unwrap();
        assert_eq!(
            gone,
            Frame::PeerGone {
                peer: source_public,
                reason: PeerGoneReason::Disconnected,
            }
        );

        drop(destination_writer);
        drop(destination_reader);
        assert!(destination_server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn native_derp_mixed_transport_routes_websocket_packet_to_raw_and_reports_disconnect() {
        let source_key = DerpNodeKeyPair::from_private_key([6u8; KEY_LEN]).unwrap();
        let source_public = source_key.public_key();
        let destination_key = DerpNodeKeyPair::from_private_key([7u8; KEY_LEN]).unwrap();
        let destination_public = destination_key.public_key();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));

        let source = start_websocket_derp_client(runtime.clone(), &source_key).await;
        let mut destination = start_raw_derp_client(runtime.clone(), &destination_key).await;

        let packet = b"native derp packet from websocket to raw runtime".to_vec();
        let send_packet = encode_frame(&Frame::SendPacket {
            destination: destination_public,
            packet: packet.clone(),
        })
        .unwrap();
        source
            .tx
            .send(Ok(Message::Binary(send_packet)))
            .await
            .unwrap();

        let received = tokio::time::timeout(
            Duration::from_millis(500),
            read_next_frame(&mut destination.reader, &mut destination.decoder),
        )
        .await
        .expect("timed out waiting for websocket-to-raw relayed DERP packet")
        .unwrap();
        assert_eq!(
            received,
            Frame::RecvPacket {
                source: source_public,
                packet
            }
        );

        source.tx.send(Ok(Message::Close(None))).await.unwrap();
        assert!(source.server.await.unwrap().is_ok());

        let gone = tokio::time::timeout(
            Duration::from_millis(500),
            read_next_frame(&mut destination.reader, &mut destination.decoder),
        )
        .await
        .expect("timed out waiting for websocket source disconnect PeerGone")
        .unwrap();
        assert_eq!(
            gone,
            Frame::PeerGone {
                peer: source_public,
                reason: PeerGoneReason::Disconnected,
            }
        );

        drop(destination.writer);
        drop(destination.reader);
        assert!(destination.server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn native_derp_mixed_transport_routes_raw_packet_to_websocket_and_reports_disconnect() {
        let source_key = DerpNodeKeyPair::from_private_key([6u8; KEY_LEN]).unwrap();
        let source_public = source_key.public_key();
        let destination_key = DerpNodeKeyPair::from_private_key([7u8; KEY_LEN]).unwrap();
        let destination_public = destination_key.public_key();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));

        let mut source = start_raw_derp_client(runtime.clone(), &source_key).await;
        let destination = start_websocket_derp_client(runtime.clone(), &destination_key).await;

        let packet = b"native derp packet from raw to websocket runtime".to_vec();
        let send_packet = encode_frame(&Frame::SendPacket {
            destination: destination_public,
            packet: packet.clone(),
        })
        .unwrap();
        source.writer.write_all(&send_packet).await.unwrap();
        source.writer.flush().await.unwrap();

        wait_for_sent_messages(&destination.sent, 3).await;
        let received = decode_websocket_sent_frame(
            &destination.sent,
            2,
            "raw-to-websocket relayed packet decodes",
        );
        assert_eq!(
            received,
            Frame::RecvPacket {
                source: source_public,
                packet
            }
        );

        drop(source.writer);
        drop(source.reader);
        assert!(source.server.await.unwrap().is_ok());

        wait_for_sent_messages(&destination.sent, 4).await;
        let gone = decode_websocket_sent_frame(
            &destination.sent,
            3,
            "raw source disconnect PeerGone decodes",
        );
        assert_eq!(
            gone,
            Frame::PeerGone {
                peer: source_public,
                reason: PeerGoneReason::Disconnected,
            }
        );

        destination.tx.send(Ok(Message::Close(None))).await.unwrap();
        assert!(destination.server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn drive_native_derp_sends_scheduled_keepalive() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(
            NativeDerpRuntime::new(
                DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
                NativeDerpRelay::new(),
            )
            .with_keepalive_interval(Duration::from_millis(20))
            .with_keepalive_jitter(Duration::ZERO),
        );
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_runtime = runtime.clone();
        let server =
            tokio::spawn(async move { drive_native_derp(server_runtime, server_io).await });
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);
        let mut decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: server_public, ..
        } = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap()
        else {
            panic!("expected server-key frame");
        };
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        client_writer.write_all(&client_info).await.unwrap();
        client_writer.flush().await.unwrap();

        let server_info_frame = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap();
        assert_eq!(
            open_server_info(&client_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );

        let keepalive = tokio::time::timeout(
            Duration::from_millis(250),
            read_next_frame(&mut client_reader, &mut decoder),
        )
        .await
        .expect("timed out waiting for DERP keepalive")
        .unwrap();
        assert_eq!(keepalive, Frame::KeepAlive);

        drop(client_writer);
        drop(client_reader);
        assert!(server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn drive_native_derp_replays_current_health_before_keepalive() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(
            NativeDerpRuntime::new(
                DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
                NativeDerpRelay::new(),
            )
            .with_keepalive_interval(Duration::from_millis(20))
            .with_keepalive_jitter(Duration::ZERO),
        );
        assert_eq!(runtime.set_health_problem("BAD").await, 0);
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_runtime = runtime.clone();
        let server =
            tokio::spawn(async move { drive_native_derp(server_runtime, server_io).await });
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);
        let mut decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: server_public, ..
        } = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap()
        else {
            panic!("expected server-key frame");
        };
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        client_writer.write_all(&client_info).await.unwrap();
        client_writer.flush().await.unwrap();

        let server_info_frame = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap();
        assert_eq!(
            open_server_info(&client_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );
        assert_eq!(
            read_next_frame(&mut client_reader, &mut decoder)
                .await
                .unwrap(),
            Frame::Health("BAD".to_string())
        );

        let keepalive = tokio::time::timeout(
            Duration::from_millis(250),
            read_next_frame(&mut client_reader, &mut decoder),
        )
        .await
        .expect("timed out waiting for DERP keepalive")
        .unwrap();
        assert_eq!(keepalive, Frame::KeepAlive);

        drop(client_writer);
        drop(client_reader);
        assert!(server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn drive_native_derp_sends_health_state_and_restart_advisory() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
        assert_eq!(runtime.set_health_problem("BAD").await, 0);

        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_runtime = runtime.clone();
        let server =
            tokio::spawn(async move { drive_native_derp(server_runtime, server_io).await });
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);
        let mut decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: server_public, ..
        } = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap()
        else {
            panic!("expected server-key frame");
        };
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        client_writer.write_all(&client_info).await.unwrap();
        client_writer.flush().await.unwrap();

        let server_info_frame = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap();
        assert_eq!(
            open_server_info(&client_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );

        assert_eq!(
            read_next_frame(&mut client_reader, &mut decoder)
                .await
                .unwrap(),
            Frame::Health("BAD".to_string())
        );

        assert_eq!(runtime.clear_health_problem().await, 1);
        assert_eq!(
            read_next_frame(&mut client_reader, &mut decoder)
                .await
                .unwrap(),
            Frame::Health(String::new())
        );

        assert_eq!(
            runtime
                .announce_restarting(Duration::from_millis(1), Duration::from_millis(2))
                .await,
            1
        );
        assert_eq!(
            read_next_frame(&mut client_reader, &mut decoder)
                .await
                .unwrap(),
            Frame::Restarting {
                reconnect_in_ms: 1,
                try_for_ms: 2,
            }
        );

        drop(client_writer);
        drop(client_reader);
        assert!(server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn drive_native_derp_sends_server_shutdown_lifecycle() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_runtime = runtime.clone();
        let server =
            tokio::spawn(async move { drive_native_derp(server_runtime, server_io).await });
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);
        let mut decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: server_public, ..
        } = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap()
        else {
            panic!("expected server-key frame");
        };
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        client_writer.write_all(&client_info).await.unwrap();
        client_writer.flush().await.unwrap();

        let server_info_frame = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap();
        assert_eq!(
            open_server_info(&client_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );

        assert_eq!(
            runtime.announce_server_shutdown().await,
            NativeDerpLifecycleDelivery {
                health: 1,
                restarting: 1
            }
        );
        assert_eq!(
            read_next_frame(&mut client_reader, &mut decoder)
                .await
                .unwrap(),
            Frame::Health(NATIVE_DERP_SHUTDOWN_HEALTH_PROBLEM.to_string())
        );
        assert_eq!(
            read_next_frame(&mut client_reader, &mut decoder)
                .await
                .unwrap(),
            Frame::Restarting {
                reconnect_in_ms: NATIVE_DERP_SHUTDOWN_RECONNECT_IN.as_millis() as u32,
                try_for_ms: NATIVE_DERP_SHUTDOWN_TRY_FOR.as_millis() as u32,
            }
        );

        drop(client_writer);
        drop(client_reader);
        assert!(server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn drive_native_derp_replays_shutdown_health_to_late_session() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
        assert_eq!(
            runtime.announce_server_shutdown().await,
            NativeDerpLifecycleDelivery {
                health: 0,
                restarting: 0
            }
        );

        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_runtime = runtime.clone();
        let server =
            tokio::spawn(async move { drive_native_derp(server_runtime, server_io).await });
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);
        let mut decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: server_public, ..
        } = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap()
        else {
            panic!("expected server-key frame");
        };
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        client_writer.write_all(&client_info).await.unwrap();
        client_writer.flush().await.unwrap();

        let server_info_frame = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap();
        assert_eq!(
            open_server_info(&client_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );
        assert_eq!(
            read_next_frame(&mut client_reader, &mut decoder)
                .await
                .unwrap(),
            Frame::Health(NATIVE_DERP_SHUTDOWN_HEALTH_PROBLEM.to_string())
        );

        drop(client_writer);
        drop(client_reader);
        assert!(server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn drive_native_derp_cleans_session_when_server_info_write_fails() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
        let client_info =
            encode_client_info_frame(&client_key, &runtime.public_key(), &ClientInfo::regular())
                .unwrap();

        let err = drive_native_derp(runtime.clone(), ServerInfoWriteFailureIo::new(client_info))
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("failed writing DERP server info"),
            "{err:#}"
        );
        assert_eq!(runtime.relay.session_count().await, 0);
    }

    #[tokio::test]
    async fn drive_native_derp_reports_duplicate_connection_health_and_clear() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));

        let (client_one_io, server_one_io) = tokio::io::duplex(4096);
        let server_one_runtime = runtime.clone();
        let server_one =
            tokio::spawn(async move { drive_native_derp(server_one_runtime, server_one_io).await });
        let (mut one_reader, mut one_writer) = tokio::io::split(client_one_io);
        let mut one_decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: server_public, ..
        } = read_next_frame(&mut one_reader, &mut one_decoder)
            .await
            .unwrap()
        else {
            panic!("expected first server-key frame");
        };
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        one_writer.write_all(&client_info).await.unwrap();
        one_writer.flush().await.unwrap();
        let server_info_frame = read_next_frame(&mut one_reader, &mut one_decoder)
            .await
            .unwrap();
        assert_eq!(
            open_server_info(&client_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );

        let (client_two_io, server_two_io) = tokio::io::duplex(4096);
        let server_two_runtime = runtime.clone();
        let server_two =
            tokio::spawn(async move { drive_native_derp(server_two_runtime, server_two_io).await });
        let (mut two_reader, mut two_writer) = tokio::io::split(client_two_io);
        let mut two_decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: server_public_two,
            ..
        } = read_next_frame(&mut two_reader, &mut two_decoder)
            .await
            .unwrap()
        else {
            panic!("expected second server-key frame");
        };
        assert_eq!(server_public_two, server_public);
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        two_writer.write_all(&client_info).await.unwrap();
        two_writer.flush().await.unwrap();
        let server_info_frame = read_next_frame(&mut two_reader, &mut two_decoder)
            .await
            .unwrap();
        assert_eq!(
            open_server_info(&client_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );

        let duplicate = Frame::Health(DUPLICATE_CONNECTION_HEALTH.to_string());
        assert_eq!(
            read_next_frame(&mut one_reader, &mut one_decoder)
                .await
                .unwrap(),
            duplicate
        );
        assert_eq!(
            read_next_frame(&mut two_reader, &mut two_decoder)
                .await
                .unwrap(),
            duplicate
        );

        drop(two_writer);
        drop(two_reader);
        assert!(server_two.await.unwrap().is_ok());
        assert_eq!(
            read_next_frame(&mut one_reader, &mut one_decoder)
                .await
                .unwrap(),
            Frame::Health(String::new())
        );

        drop(one_writer);
        drop(one_reader);
        assert!(server_one.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn drive_native_derp_rejects_unverified_clients() {
        let runtime = Arc::new(
            NativeDerpRuntime::new(
                DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
                NativeDerpRelay::new(),
            )
            .with_client_verifier(|_| false),
        );
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_runtime = runtime.clone();
        let server =
            tokio::spawn(async move { drive_native_derp(server_runtime, server_io).await });
        let (mut client_reader, mut client_writer) = tokio::io::split(client_io);
        let mut decoder = FrameDecoder::new(MAX_INFO_LEN);

        let server_key = read_next_frame(&mut client_reader, &mut decoder)
            .await
            .unwrap();
        let Frame::ServerKey {
            key: server_public, ..
        } = server_key
        else {
            panic!("expected server-key frame");
        };
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        client_writer.write_all(&client_info).await.unwrap();
        client_writer.flush().await.unwrap();

        let err = tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("DERP client was not admitted by verifier"),
            "{err:#}"
        );
        assert_eq!(
            runtime.admission_snapshot(),
            NativeDerpAdmissionSnapshot {
                raw_allowed: 0,
                raw_denied: 1,
                websocket_allowed: 0,
                websocket_denied: 0,
            }
        );
        assert_eq!(runtime.relay.session_count().await, 0);
    }

    #[tokio::test]
    async fn drive_native_derp_websocket_completes_login_and_routes_ping() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let allowed_public = client_key.public_key();
        let runtime = Arc::new(
            NativeDerpRuntime::new(
                DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
                NativeDerpRelay::new(),
            )
            .with_client_verifier(move |client_public| client_public == &allowed_public),
        );
        let server_public = runtime.public_key();
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        let ping = encode_raw_frame(FrameType::Ping.code(), b"12345678").unwrap();
        let (tx, rx) = mpsc::channel(8);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let server_sent = sent.clone();
        let server_runtime = runtime.clone();
        let server = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                server_runtime,
                CollectWebsocketSink { sent: server_sent },
                MpscMessageStream { rx },
            )
            .await
        });

        tx.send(Ok(Message::Binary(client_info))).await.unwrap();
        tx.send(Ok(Message::Binary(ping))).await.unwrap();
        wait_for_sent_messages(&sent, 3).await;
        tx.send(Ok(Message::Close(None))).await.unwrap();

        let result = server.await.unwrap();
        assert!(result.is_ok());

        let messages = sent.lock().unwrap().clone();
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[0]), MAX_INFO_LEN)
                .expect("server key frame decodes");
        let Frame::ServerKey { key, extra } = frame else {
            panic!("expected server key frame");
        };
        assert_eq!(key, server_public);
        assert!(extra.is_empty());

        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[1]), MAX_INFO_LEN)
                .expect("server info frame decodes");
        assert_eq!(
            open_server_info(&client_key, &server_public, &frame).unwrap(),
            ServerInfo::current()
        );

        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[2]), MAX_INFO_LEN)
                .expect("pong frame decodes");
        assert_eq!(frame, Frame::Pong(*b"12345678"));
        assert_eq!(
            runtime.admission_snapshot(),
            NativeDerpAdmissionSnapshot {
                raw_allowed: 0,
                raw_denied: 0,
                websocket_allowed: 1,
                websocket_denied: 0,
            }
        );
    }

    #[tokio::test]
    async fn drive_native_derp_websocket_ignores_control_frames() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
        let server_public = runtime.public_key();
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        let ping = encode_raw_frame(FrameType::Ping.code(), b"12345678").unwrap();
        let (tx, rx) = mpsc::channel(8);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let server_sent = sent.clone();
        let server_runtime = runtime.clone();
        let server = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                server_runtime,
                CollectWebsocketSink { sent: server_sent },
                MpscMessageStream { rx },
            )
            .await
        });

        tx.send(Ok(Message::Ping(b"before-login".to_vec())))
            .await
            .unwrap();
        tx.send(Ok(Message::Pong(b"before-login".to_vec())))
            .await
            .unwrap();
        tx.send(Ok(Message::Binary(client_info))).await.unwrap();
        wait_for_sent_messages(&sent, 2).await;

        tx.send(Ok(Message::Ping(b"after-login".to_vec())))
            .await
            .unwrap();
        tx.send(Ok(Message::Pong(b"after-login".to_vec())))
            .await
            .unwrap();
        tx.send(Ok(Message::Binary(ping))).await.unwrap();
        wait_for_sent_messages(&sent, 3).await;
        tx.send(Ok(Message::Close(None))).await.unwrap();

        let result = server.await.unwrap();
        assert!(result.is_ok());

        let messages = sent.lock().unwrap().clone();
        assert_eq!(messages.len(), 3);
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[0]), MAX_INFO_LEN)
                .expect("server-key frame decodes");
        let Frame::ServerKey { key, extra } = frame else {
            panic!("expected server-key frame");
        };
        assert_eq!(key, server_public);
        assert!(extra.is_empty());

        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[1]), MAX_INFO_LEN)
                .expect("server-info frame decodes");
        assert_eq!(
            open_server_info(&client_key, &server_public, &frame).unwrap(),
            ServerInfo::current()
        );

        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[2]), MAX_INFO_LEN)
                .expect("pong frame decodes");
        assert_eq!(frame, Frame::Pong(*b"12345678"));
    }

    #[tokio::test]
    async fn drive_native_derp_websocket_sends_scheduled_keepalive() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(
            NativeDerpRuntime::new(
                DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
                NativeDerpRelay::new(),
            )
            .with_keepalive_interval(Duration::from_millis(20))
            .with_keepalive_jitter(Duration::ZERO),
        );
        let server_public = runtime.public_key();
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        let (tx, rx) = mpsc::channel(8);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let server_sent = sent.clone();
        let server_runtime = runtime.clone();
        let server = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                server_runtime,
                CollectWebsocketSink { sent: server_sent },
                MpscMessageStream { rx },
            )
            .await
        });

        tx.send(Ok(Message::Binary(client_info))).await.unwrap();
        wait_for_sent_messages(&sent, 3).await;
        tx.send(Ok(Message::Close(None))).await.unwrap();

        let result = server.await.unwrap();
        assert!(result.is_ok());

        let messages = sent.lock().unwrap().clone();
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[2]), MAX_INFO_LEN)
                .expect("keepalive frame decodes");
        assert_eq!(frame, Frame::KeepAlive);
    }

    #[tokio::test]
    async fn drive_native_derp_websocket_replays_current_health_before_keepalive() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(
            NativeDerpRuntime::new(
                DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
                NativeDerpRelay::new(),
            )
            .with_keepalive_interval(Duration::from_millis(20))
            .with_keepalive_jitter(Duration::ZERO),
        );
        assert_eq!(runtime.set_health_problem("BAD").await, 0);
        let server_public = runtime.public_key();
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        let (tx, rx) = mpsc::channel(8);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let server_sent = sent.clone();
        let server_runtime = runtime.clone();
        let server = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                server_runtime,
                CollectWebsocketSink { sent: server_sent },
                MpscMessageStream { rx },
            )
            .await
        });

        tx.send(Ok(Message::Binary(client_info))).await.unwrap();
        wait_for_sent_messages(&sent, 4).await;
        tx.send(Ok(Message::Close(None))).await.unwrap();

        let result = server.await.unwrap();
        assert!(result.is_ok());

        let messages = sent.lock().unwrap().clone();
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[2]), MAX_INFO_LEN)
                .expect("current health frame decodes");
        assert_eq!(frame, Frame::Health("BAD".to_string()));
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[3]), MAX_INFO_LEN)
                .expect("keepalive frame decodes");
        assert_eq!(frame, Frame::KeepAlive);
    }

    #[tokio::test]
    async fn drive_native_derp_websocket_sends_health_state_and_restart_advisory() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
        assert_eq!(runtime.set_health_problem("BAD").await, 0);
        let server_public = runtime.public_key();
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        let (tx, rx) = mpsc::channel(8);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let server_sent = sent.clone();
        let server_runtime = runtime.clone();
        let server = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                server_runtime,
                CollectWebsocketSink { sent: server_sent },
                MpscMessageStream { rx },
            )
            .await
        });

        tx.send(Ok(Message::Binary(client_info))).await.unwrap();
        wait_for_sent_messages(&sent, 3).await;

        assert_eq!(runtime.clear_health_problem().await, 1);
        wait_for_sent_messages(&sent, 4).await;

        assert_eq!(
            runtime
                .announce_restarting(Duration::from_millis(1), Duration::from_millis(2))
                .await,
            1
        );
        wait_for_sent_messages(&sent, 5).await;
        tx.send(Ok(Message::Close(None))).await.unwrap();

        let result = server.await.unwrap();
        assert!(result.is_ok());

        let messages = sent.lock().unwrap().clone();
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[2]), MAX_INFO_LEN)
                .expect("initial health frame decodes");
        assert_eq!(frame, Frame::Health("BAD".to_string()));
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[3]), MAX_INFO_LEN)
                .expect("health clear frame decodes");
        assert_eq!(frame, Frame::Health(String::new()));
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[4]), MAX_INFO_LEN)
                .expect("restarting frame decodes");
        assert_eq!(
            frame,
            Frame::Restarting {
                reconnect_in_ms: 1,
                try_for_ms: 2,
            }
        );
    }

    #[tokio::test]
    async fn drive_native_derp_websocket_sends_server_shutdown_lifecycle() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
        let server_public = runtime.public_key();
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        let (tx, rx) = mpsc::channel(8);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let server_sent = sent.clone();
        let server_runtime = runtime.clone();
        let server = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                server_runtime,
                CollectWebsocketSink { sent: server_sent },
                MpscMessageStream { rx },
            )
            .await
        });

        tx.send(Ok(Message::Binary(client_info))).await.unwrap();
        wait_for_sent_messages(&sent, 2).await;

        assert_eq!(
            runtime.announce_server_shutdown().await,
            NativeDerpLifecycleDelivery {
                health: 1,
                restarting: 1
            }
        );
        wait_for_sent_messages(&sent, 4).await;
        tx.send(Ok(Message::Close(None))).await.unwrap();

        let result = server.await.unwrap();
        assert!(result.is_ok());

        let messages = sent.lock().unwrap().clone();
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[2]), MAX_INFO_LEN)
                .expect("shutdown health frame decodes");
        assert_eq!(
            frame,
            Frame::Health(NATIVE_DERP_SHUTDOWN_HEALTH_PROBLEM.to_string())
        );
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[3]), MAX_INFO_LEN)
                .expect("shutdown restarting frame decodes");
        assert_eq!(
            frame,
            Frame::Restarting {
                reconnect_in_ms: NATIVE_DERP_SHUTDOWN_RECONNECT_IN.as_millis() as u32,
                try_for_ms: NATIVE_DERP_SHUTDOWN_TRY_FOR.as_millis() as u32,
            }
        );
    }

    #[tokio::test]
    async fn native_derp_shutdown_broadcast_reaches_raw_and_websocket_sessions() {
        let raw_client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let websocket_client_key = DerpNodeKeyPair::from_private_key([7u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));

        let (raw_client_io, raw_server_io) = tokio::io::duplex(4096);
        let raw_server_runtime = runtime.clone();
        let raw_server =
            tokio::spawn(async move { drive_native_derp(raw_server_runtime, raw_server_io).await });
        let (mut raw_reader, mut raw_writer) = tokio::io::split(raw_client_io);
        let mut raw_decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: server_public, ..
        } = read_next_frame(&mut raw_reader, &mut raw_decoder)
            .await
            .unwrap()
        else {
            panic!("expected raw server-key frame");
        };
        assert_eq!(server_public, runtime.public_key());
        let raw_client_info =
            encode_client_info_frame(&raw_client_key, &server_public, &ClientInfo::regular())
                .unwrap();
        raw_writer.write_all(&raw_client_info).await.unwrap();
        raw_writer.flush().await.unwrap();

        let server_info_frame = read_next_frame(&mut raw_reader, &mut raw_decoder)
            .await
            .unwrap();
        assert_eq!(
            open_server_info(&raw_client_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );

        let websocket_client_info = encode_client_info_frame(
            &websocket_client_key,
            &server_public,
            &ClientInfo::regular(),
        )
        .unwrap();
        let (tx, rx) = mpsc::channel(8);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let websocket_server_sent = sent.clone();
        let websocket_server_runtime = runtime.clone();
        let websocket_server = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                websocket_server_runtime,
                CollectWebsocketSink {
                    sent: websocket_server_sent,
                },
                MpscMessageStream { rx },
            )
            .await
        });

        tx.send(Ok(Message::Binary(websocket_client_info)))
            .await
            .unwrap();
        wait_for_sent_messages(&sent, 2).await;

        let delivery = runtime.announce_server_shutdown().await;
        assert_eq!(
            delivery,
            NativeDerpLifecycleDelivery {
                health: 2,
                restarting: 2
            }
        );
        assert_eq!(delivery.delivered(), 4);

        assert_eq!(
            read_next_frame(&mut raw_reader, &mut raw_decoder)
                .await
                .unwrap(),
            Frame::Health(NATIVE_DERP_SHUTDOWN_HEALTH_PROBLEM.to_string())
        );
        assert_eq!(
            read_next_frame(&mut raw_reader, &mut raw_decoder)
                .await
                .unwrap(),
            Frame::Restarting {
                reconnect_in_ms: NATIVE_DERP_SHUTDOWN_RECONNECT_IN.as_millis() as u32,
                try_for_ms: NATIVE_DERP_SHUTDOWN_TRY_FOR.as_millis() as u32,
            }
        );

        wait_for_sent_messages(&sent, 4).await;
        let messages = sent.lock().unwrap().clone();
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[2]), MAX_INFO_LEN)
                .expect("websocket shutdown health frame decodes");
        assert_eq!(
            frame,
            Frame::Health(NATIVE_DERP_SHUTDOWN_HEALTH_PROBLEM.to_string())
        );
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[3]), MAX_INFO_LEN)
                .expect("websocket shutdown restarting frame decodes");
        assert_eq!(
            frame,
            Frame::Restarting {
                reconnect_in_ms: NATIVE_DERP_SHUTDOWN_RECONNECT_IN.as_millis() as u32,
                try_for_ms: NATIVE_DERP_SHUTDOWN_TRY_FOR.as_millis() as u32,
            }
        );

        drop(raw_writer);
        drop(raw_reader);
        assert!(raw_server.await.unwrap().is_ok());

        tx.send(Ok(Message::Close(None))).await.unwrap();
        assert!(websocket_server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn drive_native_derp_websocket_reports_duplicate_connection_health_and_clear() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
        let server_public = runtime.public_key();
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();

        let (tx_one, rx_one) = mpsc::channel(8);
        let sent_one = Arc::new(Mutex::new(Vec::new()));
        let server_one_sent = sent_one.clone();
        let server_one_runtime = runtime.clone();
        let server_one = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                server_one_runtime,
                CollectWebsocketSink {
                    sent: server_one_sent,
                },
                MpscMessageStream { rx: rx_one },
            )
            .await
        });
        tx_one
            .send(Ok(Message::Binary(client_info.clone())))
            .await
            .unwrap();
        wait_for_sent_messages(&sent_one, 2).await;

        let (tx_two, rx_two) = mpsc::channel(8);
        let sent_two = Arc::new(Mutex::new(Vec::new()));
        let server_two_sent = sent_two.clone();
        let server_two_runtime = runtime.clone();
        let server_two = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                server_two_runtime,
                CollectWebsocketSink {
                    sent: server_two_sent,
                },
                MpscMessageStream { rx: rx_two },
            )
            .await
        });
        tx_two
            .send(Ok(Message::Binary(client_info.clone())))
            .await
            .unwrap();
        wait_for_sent_messages(&sent_one, 3).await;
        wait_for_sent_messages(&sent_two, 3).await;

        let duplicate = Frame::Health(DUPLICATE_CONNECTION_HEALTH.to_string());
        let messages_one = sent_one.lock().unwrap().clone();
        let (frame, _) = headscale_core::derp::protocol::decode_frame(
            binary_frame(&messages_one[2]),
            MAX_INFO_LEN,
        )
        .expect("first duplicate health frame decodes");
        assert_eq!(frame, duplicate);
        let messages_two = sent_two.lock().unwrap().clone();
        let (frame, _) = headscale_core::derp::protocol::decode_frame(
            binary_frame(&messages_two[2]),
            MAX_INFO_LEN,
        )
        .expect("second duplicate health frame decodes");
        assert_eq!(frame, duplicate);

        tx_two.send(Ok(Message::Close(None))).await.unwrap();
        assert!(server_two.await.unwrap().is_ok());
        wait_for_sent_messages(&sent_one, 4).await;
        let messages_one = sent_one.lock().unwrap().clone();
        let (frame, _) = headscale_core::derp::protocol::decode_frame(
            binary_frame(&messages_one[3]),
            MAX_INFO_LEN,
        )
        .expect("duplicate health clear frame decodes");
        assert_eq!(frame, Frame::Health(String::new()));

        tx_one.send(Ok(Message::Close(None))).await.unwrap();
        assert!(server_one.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn native_derp_mixed_transport_duplicate_reconnect_reissues_health() {
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));

        let (raw_client_io, raw_server_io) = tokio::io::duplex(4096);
        let raw_server_runtime = runtime.clone();
        let raw_server =
            tokio::spawn(async move { drive_native_derp(raw_server_runtime, raw_server_io).await });
        let (mut raw_reader, mut raw_writer) = tokio::io::split(raw_client_io);
        let mut raw_decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: server_public, ..
        } = read_next_frame(&mut raw_reader, &mut raw_decoder)
            .await
            .unwrap()
        else {
            panic!("expected raw server-key frame");
        };
        let client_info =
            encode_client_info_frame(&client_key, &server_public, &ClientInfo::regular()).unwrap();
        raw_writer.write_all(&client_info).await.unwrap();
        raw_writer.flush().await.unwrap();
        let server_info_frame = read_next_frame(&mut raw_reader, &mut raw_decoder)
            .await
            .unwrap();
        assert_eq!(
            open_server_info(&client_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );

        let duplicate = Frame::Health(DUPLICATE_CONNECTION_HEALTH.to_string());

        let (tx_one, rx_one) = mpsc::channel(8);
        let sent_one = Arc::new(Mutex::new(Vec::new()));
        let server_one_sent = sent_one.clone();
        let server_one_runtime = runtime.clone();
        let server_one = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                server_one_runtime,
                CollectWebsocketSink {
                    sent: server_one_sent,
                },
                MpscMessageStream { rx: rx_one },
            )
            .await
        });
        tx_one
            .send(Ok(Message::Binary(client_info.clone())))
            .await
            .unwrap();
        wait_for_sent_messages(&sent_one, 3).await;

        assert_eq!(
            read_next_frame(&mut raw_reader, &mut raw_decoder)
                .await
                .unwrap(),
            duplicate
        );
        let messages_one = sent_one.lock().unwrap().clone();
        let (frame, _) = headscale_core::derp::protocol::decode_frame(
            binary_frame(&messages_one[2]),
            MAX_INFO_LEN,
        )
        .expect("first websocket duplicate health frame decodes");
        assert_eq!(frame, duplicate);

        tx_one.send(Ok(Message::Close(None))).await.unwrap();
        assert!(server_one.await.unwrap().is_ok());
        assert_eq!(
            read_next_frame(&mut raw_reader, &mut raw_decoder)
                .await
                .unwrap(),
            Frame::Health(String::new())
        );

        let (tx_two, rx_two) = mpsc::channel(8);
        let sent_two = Arc::new(Mutex::new(Vec::new()));
        let server_two_sent = sent_two.clone();
        let server_two_runtime = runtime.clone();
        let server_two = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                server_two_runtime,
                CollectWebsocketSink {
                    sent: server_two_sent,
                },
                MpscMessageStream { rx: rx_two },
            )
            .await
        });
        tx_two
            .send(Ok(Message::Binary(client_info.clone())))
            .await
            .unwrap();
        wait_for_sent_messages(&sent_two, 3).await;

        assert_eq!(
            read_next_frame(&mut raw_reader, &mut raw_decoder)
                .await
                .unwrap(),
            duplicate
        );
        let messages_two = sent_two.lock().unwrap().clone();
        let (frame, _) = headscale_core::derp::protocol::decode_frame(
            binary_frame(&messages_two[2]),
            MAX_INFO_LEN,
        )
        .expect("reconnected websocket duplicate health frame decodes");
        assert_eq!(frame, duplicate);

        tx_two.send(Ok(Message::Close(None))).await.unwrap();
        assert!(server_two.await.unwrap().is_ok());
        assert_eq!(
            read_next_frame(&mut raw_reader, &mut raw_decoder)
                .await
                .unwrap(),
            Frame::Health(String::new())
        );

        drop(raw_writer);
        drop(raw_reader);
        assert!(raw_server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn native_derp_duplicate_source_remains_routable_and_reports_disconnect_after_clear() {
        let source_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let source_public = source_key.public_key();
        let destination_key = DerpNodeKeyPair::from_private_key([7u8; KEY_LEN]).unwrap();
        let destination_public = destination_key.public_key();
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));

        let mut source = start_raw_derp_client(runtime.clone(), &source_key).await;
        let mut destination = start_raw_derp_client(runtime.clone(), &destination_key).await;

        let duplicate = start_websocket_derp_client(runtime.clone(), &source_key).await;
        let duplicate_health = Frame::Health(DUPLICATE_CONNECTION_HEALTH.to_string());
        assert_eq!(
            tokio::time::timeout(
                Duration::from_millis(500),
                read_next_frame(&mut source.reader, &mut source.decoder),
            )
            .await
            .expect("timed out waiting for duplicate health on source")
            .unwrap(),
            duplicate_health
        );
        wait_for_sent_messages(&duplicate.sent, 3).await;
        assert_eq!(
            decode_websocket_sent_frame(&duplicate.sent, 2, "duplicate health frame decodes"),
            duplicate_health
        );

        duplicate.tx.send(Ok(Message::Close(None))).await.unwrap();
        assert!(duplicate.server.await.unwrap().is_ok());
        assert_eq!(
            tokio::time::timeout(
                Duration::from_millis(500),
                read_next_frame(&mut source.reader, &mut source.decoder),
            )
            .await
            .expect("timed out waiting for duplicate health clear on source")
            .unwrap(),
            Frame::Health(String::new())
        );

        let packet = b"remaining duplicate source stays routable".to_vec();
        let send_packet = encode_frame(&Frame::SendPacket {
            destination: destination_public,
            packet: packet.clone(),
        })
        .unwrap();
        source.writer.write_all(&send_packet).await.unwrap();
        source.writer.flush().await.unwrap();

        let received = tokio::time::timeout(
            Duration::from_millis(500),
            read_next_frame(&mut destination.reader, &mut destination.decoder),
        )
        .await
        .expect("timed out waiting for relayed DERP packet after duplicate clear")
        .unwrap();
        assert_eq!(
            received,
            Frame::RecvPacket {
                source: source_public,
                packet
            }
        );

        drop(source.writer);
        drop(source.reader);
        assert!(source.server.await.unwrap().is_ok());

        let gone = tokio::time::timeout(
            Duration::from_millis(500),
            read_next_frame(&mut destination.reader, &mut destination.decoder),
        )
        .await
        .expect("timed out waiting for source disconnect PeerGone after duplicate clear")
        .unwrap();
        assert_eq!(
            gone,
            Frame::PeerGone {
                peer: source_public,
                reason: PeerGoneReason::Disconnected,
            }
        );

        drop(destination.writer);
        drop(destination.reader);
        assert!(destination.server.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn drive_native_derp_websocket_rejects_unverified_clients() {
        let runtime = Arc::new(
            NativeDerpRuntime::new(
                DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
                NativeDerpRelay::new(),
            )
            .with_client_verifier(|_| false),
        );
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let client_info =
            encode_client_info_frame(&client_key, &runtime.public_key(), &ClientInfo::regular())
                .unwrap();
        let (tx, rx) = mpsc::channel(8);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let server_sent = sent.clone();
        let server_runtime = runtime.clone();
        let server = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                server_runtime,
                CollectWebsocketSink { sent: server_sent },
                MpscMessageStream { rx },
            )
            .await
        });

        tx.send(Ok(Message::Binary(client_info))).await.unwrap();

        let err = tokio::time::timeout(std::time::Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("DERP client was not admitted by verifier"),
            "{err:#}"
        );
        let messages = sent.lock().unwrap().clone();
        assert_eq!(messages.len(), 1);
        let (frame, _) =
            headscale_core::derp::protocol::decode_frame(binary_frame(&messages[0]), MAX_INFO_LEN)
                .expect("server key frame decodes");
        assert!(matches!(frame, Frame::ServerKey { .. }));
        assert_eq!(
            runtime.admission_snapshot(),
            NativeDerpAdmissionSnapshot {
                raw_allowed: 0,
                raw_denied: 0,
                websocket_allowed: 0,
                websocket_denied: 1,
            }
        );
        assert_eq!(runtime.relay.session_count().await, 0);
    }

    #[tokio::test]
    async fn drive_native_derp_websocket_rejects_text_messages() {
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
        let client_info =
            encode_client_info_frame(&client_key, &runtime.public_key(), &ClientInfo::regular())
                .unwrap();
        let (tx, rx) = mpsc::channel(8);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let server_sent = sent.clone();
        let server = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                runtime,
                CollectWebsocketSink { sent: server_sent },
                MpscMessageStream { rx },
            )
            .await
        });

        tx.send(Ok(Message::Binary(client_info))).await.unwrap();
        wait_for_sent_messages(&sent, 2).await;
        tx.send(Ok(Message::Text("not derp".to_string())))
            .await
            .unwrap();

        let err = server.await.unwrap().unwrap_err();
        assert!(
            format!("{err:#}").contains("DERP websocket requires binary messages"),
            "{err:#}"
        );
        let messages = sent.lock().unwrap().clone();
        assert!(matches!(
            messages.last(),
            Some(Message::Close(Some(close))) if close.code == WEBSOCKET_UNSUPPORTED_DATA
        ));
    }

    #[test]
    fn native_derp_public_key_is_reflected() {
        let runtime = NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([7u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        );
        assert_eq!(runtime.public_key(), runtime.server_key.public_key());
    }

    #[test]
    fn native_derp_client_verifier_defaults_open_and_can_deny() {
        let runtime = NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([7u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        );
        let client_public = [8u8; KEY_LEN];
        assert!(!runtime.client_verification_enabled());
        assert!(runtime.admit_client(&client_public));

        let runtime = runtime.with_client_verifier(|_| false);
        assert!(runtime.client_verification_enabled());
        assert!(!runtime.admit_client(&client_public));
    }

    #[test]
    fn native_derp_load_or_generate_key_creates_and_reloads_text_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("derp.private");

        let generated = NativeDerpRuntime::load_or_generate_key(&path).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents,
            format!("privkey:{}\n", hex::encode(generated.private_key()))
        );

        let reloaded = NativeDerpRuntime::load_or_generate_key(&path).unwrap();
        assert_eq!(reloaded.private_key(), generated.private_key());
    }

    #[test]
    fn native_derp_load_or_generate_key_loads_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("derp.key");
        let private = [6u8; KEY_LEN];
        std::fs::write(&path, format!("privkey:{}\n", hex::encode(private))).unwrap();

        let loaded = NativeDerpRuntime::load_or_generate_key(&path).unwrap();
        assert_eq!(loaded.private_key(), private);

        let runtime = NativeDerpRuntime::load_or_generate(&path, NativeDerpRelay::new()).unwrap();
        assert_eq!(runtime.public_key(), loaded.public_key());
    }

    #[test]
    fn native_derp_load_or_generate_key_rejects_malformed_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("derp.key");

        for contents in [
            "not-a-key",
            "privkey:abc",
            "privkey:0000000000000000000000000000000000000000000000000000000000000000",
            "privkey:FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        ] {
            std::fs::write(&path, contents).unwrap();
            assert!(
                NativeDerpRuntime::load_or_generate_key(&path).is_err(),
                "expected malformed key to be rejected: {contents}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_derp_load_or_generate_key_writes_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("derp.key");
        NativeDerpRuntime::load_or_generate_key(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    struct CollectWebsocketSink {
        sent: Arc<Mutex<Vec<Message>>>,
    }

    impl Sink<Message> for CollectWebsocketSink {
        type Error = io::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.sent.lock().unwrap().push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    struct MpscMessageStream {
        rx: mpsc::Receiver<Result<Message, io::Error>>,
    }

    impl Stream for MpscMessageStream {
        type Item = Result<Message, io::Error>;

        fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.rx.poll_recv(cx)
        }
    }

    struct ServerInfoWriteFailureIo {
        read: Vec<u8>,
        read_pos: usize,
        writes: usize,
    }

    impl ServerInfoWriteFailureIo {
        fn new(read: Vec<u8>) -> Self {
            Self {
                read,
                read_pos: 0,
                writes: 0,
            }
        }
    }

    impl tokio::io::AsyncRead for ServerInfoWriteFailureIo {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.read_pos >= self.read.len() {
                return Poll::Ready(Ok(()));
            }

            let remaining = &self.read[self.read_pos..];
            let len = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..len]);
            self.read_pos += len;
            Poll::Ready(Ok(()))
        }
    }

    impl tokio::io::AsyncWrite for ServerInfoWriteFailureIo {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.writes += 1;
            if self.writes == 1 {
                Poll::Ready(Ok(buf.len()))
            } else {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "failed writing DERP server info",
                )))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    async fn wait_for_sent_messages(sent: &Arc<Mutex<Vec<Message>>>, expected: usize) {
        for _ in 0..50 {
            if sent.lock().unwrap().len() >= expected {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for {expected} websocket messages");
    }

    fn binary_frame(message: &Message) -> &[u8] {
        let Message::Binary(bytes) = message else {
            panic!("expected binary websocket message, got {message:?}");
        };
        bytes
    }

    struct RawDerpClient {
        reader: tokio::io::ReadHalf<tokio::io::DuplexStream>,
        writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
        decoder: FrameDecoder,
        server: tokio::task::JoinHandle<Result<(), WireError>>,
    }

    async fn start_raw_derp_client(
        runtime: Arc<NativeDerpRuntime>,
        client_key: &DerpNodeKeyPair,
    ) -> RawDerpClient {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_runtime = runtime.clone();
        let server =
            tokio::spawn(async move { drive_native_derp(server_runtime, server_io).await });
        let (mut reader, mut writer) = tokio::io::split(client_io);
        let mut decoder = FrameDecoder::new(MAX_INFO_LEN);

        let Frame::ServerKey {
            key: server_public, ..
        } = read_next_frame(&mut reader, &mut decoder).await.unwrap()
        else {
            panic!("expected raw server-key frame");
        };
        assert_eq!(server_public, runtime.public_key());
        let client_info =
            encode_client_info_frame(client_key, &server_public, &ClientInfo::regular()).unwrap();
        writer.write_all(&client_info).await.unwrap();
        writer.flush().await.unwrap();
        let server_info_frame = read_next_frame(&mut reader, &mut decoder).await.unwrap();
        assert_eq!(
            open_server_info(client_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );

        RawDerpClient {
            reader,
            writer,
            decoder,
            server,
        }
    }

    struct WebsocketDerpClient {
        tx: mpsc::Sender<Result<Message, io::Error>>,
        sent: Arc<Mutex<Vec<Message>>>,
        server: tokio::task::JoinHandle<Result<(), WireError>>,
    }

    async fn start_websocket_derp_client(
        runtime: Arc<NativeDerpRuntime>,
        client_key: &DerpNodeKeyPair,
    ) -> WebsocketDerpClient {
        let server_public = runtime.public_key();
        let client_info =
            encode_client_info_frame(client_key, &server_public, &ClientInfo::regular()).unwrap();
        let (tx, rx) = mpsc::channel(16);
        let sent = Arc::new(Mutex::new(Vec::new()));
        let server_sent = sent.clone();
        let server = tokio::spawn(async move {
            drive_native_derp_websocket_parts(
                runtime,
                CollectWebsocketSink { sent: server_sent },
                MpscMessageStream { rx },
            )
            .await
        });

        tx.send(Ok(Message::Binary(client_info))).await.unwrap();
        wait_for_sent_messages(&sent, 2).await;
        let frame = decode_websocket_sent_frame(&sent, 0, "websocket server-key frame decodes");
        let Frame::ServerKey { key, extra } = frame else {
            panic!("expected websocket server-key frame");
        };
        assert_eq!(key, server_public);
        assert!(extra.is_empty());
        let server_info_frame =
            decode_websocket_sent_frame(&sent, 1, "websocket server-info frame decodes");
        assert_eq!(
            open_server_info(client_key, &server_public, &server_info_frame).unwrap(),
            ServerInfo::current()
        );

        WebsocketDerpClient { tx, sent, server }
    }

    fn decode_websocket_sent_frame(
        sent: &Arc<Mutex<Vec<Message>>>,
        index: usize,
        expected: &str,
    ) -> Frame {
        let messages = sent.lock().unwrap().clone();
        let (frame, _) = headscale_core::derp::protocol::decode_frame(
            binary_frame(&messages[index]),
            MAX_INFO_LEN,
        )
        .unwrap_or_else(|err| panic!("{expected}: {err}"));
        frame
    }

    fn test_state_with_native_derp() -> WireState {
        let dir = tempfile::tempdir().unwrap();
        WireState {
            server_noise_key: Arc::new(
                crate::tailscale_wire::noise::ServerNoiseKey::load_or_generate(dir.path()).unwrap(),
            ),
            preauth: Arc::new(crate::tailscale_wire::test_support::MockRedeemer::new()),
            ip_allocator: Arc::new(crate::tailscale_wire::test_support::MockIpAllocator),
            machines: Arc::new(crate::tailscale_wire::MachineRegistry::new()),
            registration_store: None,
            derp_map: crate::tailscale_wire::DerpMapStore::shared(
                crate::tailscale_wire::wire::DerpMap::default(),
            ),
            native_derp: Some(Arc::new(NativeDerpRuntime::generate())),
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: None,
            runtime_config: Arc::new(crate::tailscale_wire::RuntimeConfigSnapshot::default()),
            registration_cache: Arc::new(crate::tailscale_wire::RegistrationCache::new()),
            pings: Arc::new(crate::tailscale_wire::PingTracker::new()),
            mapresponse_debug: Arc::new(crate::tailscale_wire::MapResponseDebugStore::disabled()),
        }
    }
}
