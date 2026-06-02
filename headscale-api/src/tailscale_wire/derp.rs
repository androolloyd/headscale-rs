//! Native DERP HTTP upgrade and stream driver.
//!
//! The supported production relay path is still the upstream `derper` sidecar.
//! This module wires the first native Rust `/derp` path for parity work:
//! normal HTTP upgrade, DERP login frames, and local relay routing. Upstream's
//! `Derp-Fast-Start` no-response hijack remains open.

use std::{
    borrow::Cow,
    fs,
    io::{ErrorKind, Write},
    path::Path,
    sync::Arc,
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

/// Shared native DERP runtime.
#[derive(Clone, Debug)]
pub struct NativeDerpRuntime {
    server_key: Arc<DerpNodeKeyPair>,
    relay: NativeDerpRelay,
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
        }
    }

    /// Public DERP server key bytes.
    pub fn public_key(&self) -> [u8; KEY_LEN] {
        self.server_key.public_key()
    }
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

    let session = runtime.relay.connect(client_public).await;
    let server_info =
        encode_server_info_frame(&runtime.server_key, &client_public, &ServerInfo::current())
            .map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?;
    writer.write_all(&server_info).await?;
    writer.flush().await?;

    let result = run_relay_loop(session, reader, writer, decoder).await;
    runtime.relay.disconnect(&client_public).await;
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

    let session = runtime.relay.connect(client_public).await;
    let server_info =
        encode_server_info_frame(&runtime.server_key, &client_public, &ServerInfo::current())
            .map_err(|err| WireError::Internal(format!("DERP protocol: {err}")))?;
    send_websocket_binary(&mut writer, server_info).await?;

    let result = run_websocket_relay_loop(session, reader, writer, decoder).await;
    runtime.relay.disconnect(&client_public).await;
    result
}

async fn run_relay_loop<R, W>(
    mut session: NativeDerpSession,
    mut reader: R,
    mut writer: W,
    mut decoder: FrameDecoder,
) -> Result<(), WireError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; READ_BUF_LEN];
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

        tokio::select! {
            read = reader.read(&mut buf) => {
                let n = read?;
                if n == 0 {
                    return Ok(());
                }
                decoder.push(&buf[..n]);
            }
            outbound = session.recv() => {
                let Some(frame) = outbound else {
                    return Ok(());
                };
                let encoded = encode_frame(&frame).map_err(|err| {
                    WireError::Internal(format!("DERP protocol: {err}"))
                })?;
                writer.write_all(&encoded).await?;
                writer.flush().await?;
            }
        }
    }
}

async fn run_websocket_relay_loop<R, W, RE, WE>(
    mut session: NativeDerpSession,
    mut reader: R,
    mut writer: W,
    mut decoder: FrameDecoder,
) -> Result<(), WireError>
where
    R: Stream<Item = Result<Message, RE>> + Unpin,
    RE: std::fmt::Display,
    W: Sink<Message, Error = WE> + Unpin,
    WE: std::fmt::Display,
{
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

        tokio::select! {
            incoming = next_websocket_input(&mut reader) => {
                match incoming? {
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
                }
            }
            outbound = session.recv() => {
                let Some(frame) = outbound else {
                    return Ok(());
                };
                let encoded = encode_frame(&frame).map_err(|err| {
                    WireError::Internal(format!("DERP protocol: {err}"))
                })?;
                send_websocket_binary(&mut writer, encoded).await?;
            }
        }
    }
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
    use headscale_core::derp::protocol::{
        ClientInfo, FrameType, encode_client_info_frame, encode_raw_frame, open_server_info,
    };
    use http_body_util::BodyExt;
    use std::io;
    use std::pin::Pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll};
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
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
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
    async fn drive_native_derp_websocket_completes_login_and_routes_ping() {
        let runtime = Arc::new(NativeDerpRuntime::new(
            DerpNodeKeyPair::from_private_key([9u8; KEY_LEN]).unwrap(),
            NativeDerpRelay::new(),
        ));
        let client_key = DerpNodeKeyPair::from_private_key([8u8; KEY_LEN]).unwrap();
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
