//! TS2021 Noise IK handshake helpers.
//!
//! Tailscale's TS2021 protocol uses the `Noise_IK_25519_ChaChaPoly_BLAKE2s`
//! pattern with a Tailscale-specific prologue string mixed in via
//! `MixHash`. The full wire-level upgrade also involves:
//!
//!   1. An HTTP `Upgrade: tailscale-control-protocol` POST or browser
//!      `Upgrade: websocket` GET to `/ts2021`.
//!   2. A custom 3-byte header framing
//!      (`[msgType:u8][len:u16be]`, or 5-byte for `Initiation` carrying
//!      a `protocolVersion:u16be`) wrapping each Noise message.
//!   3. HTTP/2 spoken over the Noise stream once the handshake completes.
//!
//! Native and WebSocket upgrades both use the same framed Noise responder
//! and encrypted HTTP/2 dispatcher. WebSocket binary messages are bridged
//! into an asynchronous byte stream before the Noise handshake.
//!
//! ## Decision log
//!
//! - **Pattern is `Noise_IK_25519_ChaChaPoly_BLAKE2s` exactly.** Sourced
//!   from
//!   `tailscale/control/controlbase/handshake.go:protocolName`. snow's
//!   `Builder::new("Noise_IK_25519_ChaChaPoly_BLAKE2s".parse()…)` maps
//!   1:1.
//! - **Prologue is `"Tailscale Control Protocol v<N>"` where N is the
//!   decimal capability version.** From
//!   `tailscale/control/controlbase/handshake.go:protocolVersionPrologue`.
//!   We pin N to 39 (`NoiseCapabilityVersion`) because that's what
//!   headscale upstream targets; future clients may advance it but the
//!   Noise key is the same.
//! - **Static key persistence:** legacy Rust state uses 32 raw bytes at
//!   `<state_dir>/noise_static.key`. A configured `noise.private_key_path`
//!   uses headscale-go's `privkey:<hex>` encoding so a Go server can keep
//!   the same Noise identity across a handoff.

use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use axum::{
    Router,
    body::Body,
    extract::DefaultBodyLimit,
    extract::{
        FromRequestParts, Request, State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderValue, Response, StatusCode, header},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use snow::{Builder, params::NoiseParams};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use super::be_transport::{BeNoiseStream, BeTransport};
use super::controlbase::{FrameHeader, Framed, MsgType};
use super::request_log::RequestLogRemoteAddr;
use super::wire::{is_supported_capability_version, unsupported_client_error};
use super::{WireError, WireState};

fn request_log_remote_addr(req: &Request) -> Option<RequestLogRemoteAddr> {
    req.extensions()
        .get::<RequestLogRemoteAddr>()
        .cloned()
        .or_else(|| {
            req.extensions()
                .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
                .map(|peer| RequestLogRemoteAddr(peer.0.to_string()))
        })
}

/// Hand the connection's resolved peer address to the inner request as the key
/// pending interactive registrations are accounted against (F-REGCACHE).
///
/// `remote_addr` is the address the outer HTTP layer resolved for the
/// `/ts2021` upgrade: the TCP peer, or the client address a trusted proxy
/// forwarded, never a header from an untrusted peer. It is fixed for the life
/// of the connection, so every h2 request on one Noise session carries the same
/// source. An address that does not parse leaves the extension off, and the
/// register handler then files the request under the shared `Unknown` source.
fn attach_registration_source(
    extensions: &mut http::Extensions,
    remote_addr: &RequestLogRemoteAddr,
) {
    if let Some(source) = super::RegistrationSource::from_remote_addr(&remote_addr.0) {
        extensions.insert(source);
    }
}

/// Machine key learned from the client's TS2021 Noise static key.
/// Inner h2 requests carry this through axum extensions so `/register`
/// can persist the real machine identity instead of an empty placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoisePeerMachineKey(pub String);

#[derive(Clone, Debug)]
pub struct NoiseRequestCancellation {
    cancelled: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl NoiseRequestCancellation {
    pub(crate) fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub(crate) fn cancel(&self) {
        if !self.cancelled.swap(true, Ordering::SeqCst) {
            self.notify.notify_waiters();
        }
    }

    pub(crate) async fn cancelled(&self) {
        loop {
            let notified = self.notify.notified();
            if self.cancelled.load(Ordering::SeqCst) {
                return;
            }
            notified.await;
        }
    }
}

/// The Tailscale capability version we advertise in the Noise
/// prologue. Pinned at 39 to match juanfont/headscale upstream
/// (`hscontrol/handlers.go:NoiseCapabilityVersion`). Stock
/// `tailscale up` advertises a higher capability version on `GET /key?v=…`
/// (138 as of 2026-05), but the prologue version is a property of *our*
/// implementation, not the client's.
pub const NOISE_CAPABILITY_VERSION: u16 = 39;

/// Maximum request body size accepted by handlers inside the Noise
/// HTTP/2 tunnel. Mirrors upstream headscale's `noiseBodyLimit`.
pub const NOISE_BODY_LIMIT: usize = 1024 * 1024;
pub(crate) const CONTROL_HANDSHAKE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);
// Bound only unfinished handshakes. Established control/map sessions do not
// retain a permit and therefore do not impose a tailnet-size limit.
const MAX_PENDING_CONTROL_HANDSHAKES: usize = 1024;
// Match the pinned Go x/net/http2 defaults used by its Noise listener.
const MAX_CONTROL_H2_STREAMS: u32 = 250;
const MAX_CONTROL_H2_HEADER_BYTES: u32 = 1024 * 1024 + 10 * 32;
const MAX_CONTROL_H2_FRAME_BYTES: u32 = 1024 * 1024;
const CONTROL_H2_RECEIVE_WINDOW: u32 = 1024 * 1024;

/// Noise pattern string. `Noise_IK_25519_ChaChaPoly_BLAKE2s` is the
/// exact instantiation TS2021 uses. Sourced from
/// `tailscale/control/controlbase/handshake.go`.
pub const NOISE_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// Default file name for the persisted long-term static key under the
/// caller-supplied `state_dir`.
pub const NOISE_STATIC_KEY_FILENAME: &str = "noise_static.key";

/// Server's long-term Noise X25519 keypair.
///
/// Construct once via [`ServerNoiseKey::load_or_generate`]; share by
/// `Arc`. Cheap to clone.
pub struct ServerNoiseKey {
    /// 32-byte X25519 private scalar. Held under a mutex only because
    /// `snow`'s Builder borrows it by `&[u8]`; the mutex is held only
    /// during builder construction, which is fast.
    private: Mutex<Vec<u8>>,
    /// 32-byte X25519 public point. Cached so `/key` doesn't have to
    /// re-derive on every request.
    public: [u8; 32],
    pending_handshakes: Arc<Semaphore>,
}

impl ServerNoiseKey {
    /// Load the server's long-term static key from
    /// `<state_dir>/noise_static.key`, generating + persisting a fresh
    /// one if the file is absent.
    ///
    /// `state_dir` is created if it doesn't exist. On Unix the key file
    /// is written with mode `0600`.
    pub fn load_or_generate(state_dir: impl AsRef<Path>) -> Result<Self, WireError> {
        Self::load_or_generate_with_configured_path(state_dir, None)
    }

    /// Select the configured Go key when present, retaining an existing raw
    /// Rust key when an old deployment has not yet created its configured key.
    pub fn effective_key_path(state_dir: &Path, configured_path: Option<&Path>) -> PathBuf {
        let legacy = state_dir.join(NOISE_STATIC_KEY_FILENAME);
        match configured_path {
            Some(path) if path.exists() || !legacy.exists() => path.to_path_buf(),
            _ => legacy,
        }
    }

    /// Load the configured Go-format key, or generate one in that format.
    /// An existing legacy raw key takes precedence when the configured file
    /// does not exist, preserving a Rust server's established identity.
    pub fn load_or_generate_with_configured_path(
        state_dir: impl AsRef<Path>,
        configured_path: Option<&Path>,
    ) -> Result<Self, WireError> {
        let dir = state_dir.as_ref();
        ensure_key_dir(dir)?;
        let path = Self::effective_key_path(dir, configured_path);
        let use_go_format = configured_path.is_some_and(|configured| configured == path);

        let private = match fs::read(&path) {
            Ok(bytes) if bytes.len() == 32 => bytes,
            Ok(bytes) if use_go_format => {
                let text = std::str::from_utf8(&bytes).map_err(|_| {
                    WireError::Internal(format!("invalid noise private key at {}", path.display()))
                })?;
                let hex_key = text
                    .strip_suffix('\n')
                    .unwrap_or(text)
                    .strip_prefix("privkey:")
                    .ok_or_else(|| {
                        WireError::Internal(format!(
                            "invalid noise private key at {}: expected privkey: prefix",
                            path.display()
                        ))
                    })?;
                if hex_key.len() != 64 || !hex_key.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                    return Err(WireError::Internal(format!(
                        "invalid noise private key at {}: expected 64 hex digits",
                        path.display()
                    )));
                }
                hex::decode(hex_key).map_err(|_| {
                    WireError::Internal(format!("invalid noise private key at {}", path.display()))
                })?
            }
            Ok(bytes) => {
                return Err(WireError::Internal(format!(
                    "noise static key at {} has length {}; expected 32",
                    path.display(),
                    bytes.len()
                )));
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                tracing::info!(path = %path.display(), "no private key file at path, creating...");
                let mut kp = Builder::new(NOISE_PATTERN.parse().map_err(noise_err)?)
                    .generate_keypair()
                    .map_err(noise_err)?;
                if use_go_format {
                    // Tailscale's MachinePrivate marshals a clamped scalar.
                    kp.private[0] &= 0b1111_1000;
                    kp.private[31] &= 127;
                    kp.private[31] |= 64;
                }
                if let Some(parent) = path.parent() {
                    ensure_key_dir(parent)?;
                }
                let contents = if use_go_format {
                    format!("privkey:{}\n", hex::encode(&kp.private)).into_bytes()
                } else {
                    kp.private.clone()
                };
                super::tls::write_atomic(&path, &contents, 0o600)?;
                kp.private
            }
            Err(e) => return Err(e.into()),
        };

        // Derive the public key from the private. snow doesn't
        // expose a public-from-private helper directly, so we use a
        // throwaway IK round-trip: we run our own private key as the
        // *responder* (which doesn't need a remote static), then
        // observe the responder's static via the initiator's
        // `get_remote_static` after the first message.
        let public: [u8; 32] = derive_x25519_public(&private)?;

        Ok(Self {
            private: Mutex::new(private),
            public,
            pending_handshakes: Arc::new(Semaphore::new(MAX_PENDING_CONTROL_HANDSHAKES)),
        })
    }

    /// 32-byte X25519 public key. Cheap to copy.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
    }

    /// Permits not held by an in-progress handshake; test-only probe.
    #[cfg(test)]
    pub(crate) fn available_handshake_permits(&self) -> usize {
        self.pending_handshakes.available_permits()
    }

    pub(crate) fn handshake_permit(&self) -> Result<OwnedSemaphorePermit, WireError> {
        Arc::clone(&self.pending_handshakes)
            .try_acquire_owned()
            .map_err(|_| WireError::Noise("too many pending control handshakes".into()))
    }

    /// Hex-encoded public key (lowercase, no prefix). The `/key`
    /// handler prepends `mkey:` to match Tailscale's machine-key
    /// envelope format.
    pub fn public_hex(&self) -> String {
        hex::encode(self.public)
    }

    /// Build an IK initiator targeting `remote_static` (the peer's
    /// 32-byte X25519 public). Useful for tests and (eventually) for
    /// the wire-frame layer.
    pub fn build_initiator(
        &self,
        remote_static: &[u8; 32],
    ) -> Result<snow::HandshakeState, WireError> {
        self.build_initiator_for_version(remote_static, NOISE_CAPABILITY_VERSION)
    }

    /// Build an IK initiator targeting `remote_static` with an
    /// explicit protocol version in the prologue. This is primarily
    /// useful for parity tests that need to exercise the current
    /// upstream-supported client capability floor.
    pub fn build_initiator_for_version(
        &self,
        remote_static: &[u8; 32],
        protocol_version: u16,
    ) -> Result<snow::HandshakeState, WireError> {
        let priv_g = self.private.lock();
        let params: NoiseParams = NOISE_PATTERN.parse().map_err(noise_err)?;
        Builder::new(params)
            .local_private_key(&priv_g)
            .remote_public_key(remote_static)
            .prologue(&prologue_bytes(protocol_version))
            .build_initiator()
            .map_err(noise_err)
    }

    /// Build an IK responder. Used by `/ts2021` once the frame layer
    /// is wired.
    ///
    /// The prologue MUST match the value the client computed for the
    /// same handshake — upstream
    /// `tailscale/control/controlbase/handshake.go::Server` calls
    /// `s.MixHash(protocolVersionPrologue(clientVersion))` where
    /// `clientVersion` is the version advertised in the Initiation
    /// frame's 2-byte header. Use
    /// [`Self::build_responder_for_version`] from the actual upgrade
    /// handler; this default keeps the pinned [`NOISE_CAPABILITY_VERSION`]
    /// for the existing in-process round-trip tests.
    pub fn build_responder(&self) -> Result<snow::HandshakeState, WireError> {
        self.build_responder_for_version(NOISE_CAPABILITY_VERSION)
    }

    /// Build an IK responder using the client-advertised
    /// `protocol_version` as the prologue input. Mirrors upstream's
    /// `protocolVersionPrologue(clientVersion)` call in
    /// `controlbase/handshake.go::Server`.
    pub fn build_responder_for_version(
        &self,
        protocol_version: u16,
    ) -> Result<snow::HandshakeState, WireError> {
        let priv_g = self.private.lock();
        let params: NoiseParams = NOISE_PATTERN.parse().map_err(noise_err)?;
        Builder::new(params)
            .local_private_key(&priv_g)
            .prologue(&prologue_bytes(protocol_version))
            .build_responder()
            .map_err(noise_err)
    }
}

/// Go's `util.EnsureDir` creates a missing key directory (and any missing
/// parent) 0700 and skips one that already exists, leaving its mode as found.
/// `readOrCreatePrivateKey` applies it to the Noise and DERP server keys.
pub(super) fn ensure_key_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)
}

/// Tailscale's prologue format: ASCII string
/// `"Tailscale Control Protocol v<N>"` with N the decimal capability
/// version.
fn prologue_bytes(cap_ver: u16) -> Vec<u8> {
    format!("Tailscale Control Protocol v{cap_ver}").into_bytes()
}

/// Derive an X25519 public key from a 32-byte private scalar.
///
/// `snow` doesn't expose a direct private-to-public helper, but the
/// IK initiator's first handshake message (`-> e, es, s, ss`) carries
/// the initiator's static public — encrypted under `es`, but the
/// responder decrypts it as part of `read_message` and the recovered
/// value is exposed via `get_remote_static`. We use that as a
/// public-derivation oracle:
///
///   1. Generate a throwaway keypair for the responder side.
///   2. Build an initiator that locally uses *our* private key and
///      targets the throwaway responder.
///   3. Run one handshake message.
///   4. Read the recovered static from the responder side.
///
/// More verbose than `x25519-dalek::PublicKey::from(&priv)`, but the
/// blocker doc forbids any new dep besides `snow`. Cost is one
/// curve-mult + one ChaPoly decrypt at startup — trivial.
fn derive_x25519_public(private: &[u8]) -> Result<[u8; 32], WireError> {
    use snow::Builder;
    let params: NoiseParams = NOISE_PATTERN.parse().map_err(noise_err)?;

    // Throwaway responder keypair; the only thing we need is for it
    // to be a valid X25519 public so the initiator can run `es`.
    let throwaway_resp = Builder::new(params.clone())
        .generate_keypair()
        .map_err(noise_err)?;

    let mut init = Builder::new(params.clone())
        .local_private_key(private)
        .remote_public_key(&throwaway_resp.public)
        .build_initiator()
        .map_err(noise_err)?;

    let mut resp = Builder::new(params)
        .local_private_key(&throwaway_resp.private)
        .build_responder()
        .map_err(noise_err)?;

    let mut msg = [0u8; 1024];
    let n = init.write_message(&[], &mut msg).map_err(noise_err)?;
    let mut payload = [0u8; 1024];
    resp.read_message(&msg[..n], &mut payload)
        .map_err(noise_err)?;
    let recovered = resp.get_remote_static().ok_or_else(|| {
        WireError::Noise("responder could not recover initiator static after read_message".into())
    })?;
    if recovered.len() != 32 {
        return Err(WireError::Noise(format!(
            "recovered static has length {}; expected 32",
            recovered.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(recovered);
    Ok(out)
}

fn noise_err<E: std::fmt::Display>(e: E) -> WireError {
    WireError::Noise(e.to_string())
}

/// Generate a fresh X25519 public key (32 bytes) suitable for use as
/// the `NodeKeyChallenge` field in the EarlyNoise frame.
///
/// Matches the upstream `key.NewChallenge()` semantics: a fresh
/// keypair on every call, public-only return. We discard the private
/// half because the client never proves possession of the
/// corresponding shared secret in the stock interop flow (the
/// challenge is only meaningful when paired with a follow-up
/// `NodeChallengeReply` later in the flow, which we don't implement).
pub(crate) fn generate_x25519_public() -> Result<[u8; 32], WireError> {
    let params: NoiseParams = NOISE_PATTERN.parse().map_err(noise_err)?;
    let kp = Builder::new(params).generate_keypair().map_err(noise_err)?;
    if kp.public.len() != 32 {
        return Err(WireError::Noise(format!(
            "generated x25519 public has len {}; expected 32",
            kp.public.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&kp.public);
    Ok(out)
}

/// HTTP header the client sends to request the TS2021 upgrade.
pub const UPGRADE_PROTOCOL: &str = "tailscale-control-protocol";

/// Magic prefix on the EarlyNoise frame. Sourced from
/// `tailscale/tailcfg/early.go`: the framing is
/// `[\xff\xff\xff TS] [json_len:u32 be] [json]`, sent **inside** the
/// Noise transport stream before HTTP/2 starts.
///
/// Stock `tailscale` discards this if absent for older protocolVersions,
/// but newer clients (post protocolVersion 28) require it as a sign that
/// the server understands the new wire revision. We send it
/// unconditionally — empty `NodeKeyChallenge` works for the interop
/// test path.
const EARLY_NOISE_MAGIC: [u8; 5] = [0xff, 0xff, 0xff, b'T', b'S'];

fn build_early_noise_frame() -> Result<Vec<u8>, WireError> {
    let challenge_pub = generate_x25519_public()
        .map_err(|e| WireError::Noise(format!("generate early-noise challenge: {e}")))?;
    // `nodeKeyChallenge` matches the JSON tag on upstream
    // `tailcfg.EarlyNoise.NodeKeyChallenge`.
    let early_json = serde_json::json!({
        "nodeKeyChallenge": format!("chalpub:{}", hex::encode(challenge_pub))
    })
    .to_string();
    let early_bytes = early_json.as_bytes();
    let mut early = Vec::with_capacity(5 + 4 + early_bytes.len());
    early.extend_from_slice(&EARLY_NOISE_MAGIC);
    early.extend_from_slice(&(early_bytes.len() as u32).to_be_bytes());
    early.extend_from_slice(early_bytes);
    Ok(early)
}

/// `/ts2021` upgrade handler.
///
/// Verifies the `Upgrade: tailscale-control-protocol` header, returns
/// `101 Switching Protocols`, and on the hijacked socket performs:
///
///   1. Read a 5-byte Initiation frame off the wire.
///   2. Drive the Noise IK responder to completion (single round-trip).
///   3. Write the 3-byte Reply frame.
///   4. Wrap the socket in [`NoiseStream`] (encrypts each Record frame).
///   5. Send the EarlyNoise prefix + JSON inside the encrypted stream.
///   6. Hand the socket to `h2::server::handshake` and dispatch each
///      request to the existing `axum::Router` via `tower::ServiceExt::oneshot`.
///
/// Step 6 is undocumented territory: tailscale's actual HTTP/2-over-Noise
/// frame shapes are inferred from headscale-Go and may need tweaks.
/// See `docs/tailscale-interop-blocker.md` 2026-05-19 continuation
/// section for what we observed in practice.
pub async fn handle_ts2021_post(State(state): State<WireState>, req: Request) -> Response<Body> {
    let remote_addr = request_log_remote_addr(&req);
    let request_event = super::request_log::defer(&req);
    // headscale-go's NoiseUpgradeHandler answers an absent Upgrade header
    // with 500 "Internal error" (its reverse-proxy hint). Everything after
    // that is `controlhttpserver.acceptHTTP`, which rejects an unknown next
    // protocol and a missing or undecodable `X-Tailscale-Handshake` with
    // `http.Error(..., 400)` *before* hijacking, so a bad request never holds
    // a connection or a Noise handshake permit.
    let upgrade = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if upgrade.is_empty() {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from("Internal error\n"))
            .unwrap();
    }
    if !upgrade.eq_ignore_ascii_case(UPGRADE_PROTOCOL) {
        return http_error(StatusCode::BAD_REQUEST, "unknown next protocol");
    }

    // Current controlhttp clients put the framed IK initiation in this
    // header. The raw TLS listener already handles that form; the ordinary
    // HTTP listener must pass it into the same BE transport driver too.
    let Some(encoded) = req
        .headers()
        .get(super::raw_tls::HANDSHAKE_HEADER_NAME)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
    else {
        return http_error(
            StatusCode::BAD_REQUEST,
            "missing Tailscale handshake header",
        );
    };
    let initial_frame = {
        use base64::Engine;
        match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(target = "tailscale_wire::noise", %error, "invalid X-Tailscale-Handshake header");
                return http_error(
                    StatusCode::BAD_REQUEST,
                    "invalid tailscale handshake header",
                );
            }
        }
    };

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
                "ts2021: hyper OnUpgrade extension missing — not an upgradable connection",
            ))
            .unwrap();
    };

    let state_for_task = state;
    tokio::spawn(async move {
        let _request_event = request_event;
        match on_upgrade.await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                // `drive_ts2021_be` switches to the BE-nonce transport
                // after the snow IK handshake — closes Wall 4
                // (`docs/tailscale-interop-blocker.md`). The
                // hyper-upgrade path is exercised by tests that don't
                // care about post-handshake h2 (the snow-backed
                // sibling `drive_ts2021` is kept for the existing
                // in-process tests that talk Noise spec).
                if let Err(e) = drive_ts2021_be_with_init_remote_addr(
                    state_for_task,
                    io,
                    Some(initial_frame),
                    remote_addr,
                )
                .await
                {
                    tracing::warn!(target = "tailscale_wire::noise", error = %e, "ts2021 connection ended with error");
                }
            }
            Err(e) => {
                tracing::warn!(target = "tailscale_wire::noise", error = %e, "ts2021 upgrade future failed");
            }
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, HeaderValue::from_static("upgrade"))
        .header(header::UPGRADE, HeaderValue::from_static(UPGRADE_PROTOCOL))
        .body(Body::empty())
        .unwrap()
}

/// Go's `http.Error`: plain text with `nosniff` and a trailing newline.
fn http_error(status: StatusCode, message: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .body(Body::from(format!("{message}\n")))
        .expect("static plain error response is valid")
}

/// Browser/WASM control clients send the deferred Noise initiation in the
/// WebSocket URL and then run the same encrypted HTTP/2 stream over binary
/// WebSocket messages.
pub async fn handle_ts2021_websocket(
    State(state): State<WireState>,
    req: Request,
) -> Response<Body> {
    let remote_addr = request_log_remote_addr(&req);
    let request_event = super::request_log::defer(&req);
    let offered_protocol = req
        .headers()
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(',')
                .any(|protocol| protocol.trim() == UPGRADE_PROTOCOL)
        });
    let initial_frame = req
        .uri()
        .query()
        .and_then(|query| super::query::first_value(query, super::raw_tls::HANDSHAKE_HEADER_NAME))
        .and_then(|value| String::from_utf8(value).ok());
    let (mut parts, _body) = req.into_parts();
    let websocket = match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
        Ok(websocket) => websocket,
        Err(error) => return error.into_response(),
    };

    websocket
        .protocols([UPGRADE_PROTOCOL])
        .on_upgrade(move |mut socket| async move {
            let _request_event = request_event;
            if !offered_protocol {
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: 1008,
                        reason: "client must speak the control subprotocol".into(),
                    })))
                    .await;
                return;
            }
            let Some(initial_frame) = initial_frame else {
                let _ = socket
                    .send(Message::Close(Some(CloseFrame {
                        code: 1008,
                        reason: "missing Tailscale handshake parameter".into(),
                    })))
                    .await;
                return;
            };
            let initial_frame = {
                use base64::Engine;
                if let Ok(frame) = base64::engine::general_purpose::STANDARD.decode(initial_frame) {
                    frame
                } else {
                        let _ = socket
                            .send(Message::Close(Some(CloseFrame {
                                code: 1008,
                                reason: "invalid tailscale handshake parameter".into(),
                            })))
                            .await;
                        return;
                }
            };
            if let Err(error) = drive_ts2021_websocket(state, socket, initial_frame, remote_addr).await {
                tracing::warn!(target = "tailscale_wire::noise", %error, "ts2021 WebSocket connection ended with error");
            }
        })
}

async fn drive_ts2021_websocket(
    state: WireState,
    socket: WebSocket,
    initial_frame: Vec<u8>,
    remote_addr: Option<RequestLogRemoteAddr>,
) -> Result<(), WireError> {
    let (noise_io, websocket_io) = tokio::io::duplex(128 * 1024);
    let (mut websocket_read, mut websocket_write) = tokio::io::split(websocket_io);
    let (mut sink, mut stream) = socket.split();
    let bridge = tokio::spawn(async move {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            tokio::select! {
                incoming = stream.next() => match incoming {
                    Some(Ok(Message::Binary(bytes))) => {
                        if websocket_write.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Ping(bytes))) => {
                        if sink.send(Message::Pong(bytes)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    _ => break,
                },
                outgoing = websocket_read.read(&mut buffer) => match outgoing {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        if sink.send(Message::Binary(buffer[..count].to_vec())).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
    });
    let result =
        drive_ts2021_be_with_init_remote_addr(state, noise_io, Some(initial_frame), remote_addr)
            .await;
    bridge.abort();
    let _ = bridge.await;
    result
}

/// The actual handshake + h2 dispatch driver. Pulled out of the axum
/// handler so we can unit-test it against a pair of `tokio::io::duplex`
/// sockets without spinning up a real listener.
pub async fn drive_ts2021<T>(state: WireState, io: T) -> Result<(), WireError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    drive_ts2021_with_init(state, io, None).await
}

/// Variant of [`drive_ts2021`] that accepts an optionally pre-decoded
/// Initiation frame (the entire controlbase-framed message including
/// the 5-byte header).
///
/// Newer Tailscale clients (v1.42+ over `controlhttp.AcceptHTTP`) send
/// the Initiation as a base64-encoded value in the
/// `X-Tailscale-Handshake` request header instead of as the body of
/// the upgrade request. The raw-rustls listener extracts that header,
/// base64-decodes it, and passes the resulting bytes here so we don't
/// wait forever on `read_frame()`.
///
/// Sourced from `tailscale/control/controlhttp/controlhttpserver.go`
/// (`acceptHTTP`) + `tailscale/control/controlbase/handshake.go`
/// (`Server`, `optionalInit` parameter). The framed Initiation
/// includes a 5-byte controlbase header (`[type=1:u8][version:u16be][len:u16be]`)
/// followed by the Noise body.
pub async fn drive_ts2021_with_init<T>(
    state: WireState,
    io: T,
    initial_frame: Option<Vec<u8>>,
) -> Result<(), WireError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let pending_handshake = state.server_noise_key.handshake_permit()?;
    let deadline = tokio::time::Instant::now() + CONTROL_HANDSHAKE_TIMEOUT;
    let mut framed = Framed::new(io);

    // Step 1: source the Initiation. The header-fast-start path
    // delivers the entire framed Initiation (5-byte header + body)
    // up front; the pipelined path reads it off the wire.
    let (hdr, init_body) = match initial_frame {
        Some(bytes) => {
            tracing::debug!(
                target = "tailscale_wire::noise",
                len = bytes.len(),
                "ts2021 using pre-decoded Initiation from X-Tailscale-Handshake header"
            );
            parse_initiation_frame(&bytes)?
        }
        None => handshake_io(deadline, "read initiation frame", framed.read_frame()).await?,
    };
    let proto_version = match hdr {
        FrameHeader::Initiation {
            protocol_version, ..
        } => protocol_version,
        other @ FrameHeader::Regular { .. } => {
            return Err(WireError::Noise(format!(
                "expected Initiation frame first, got {other:?}"
            )));
        }
    };
    tracing::debug!(
        target = "tailscale_wire::noise",
        proto_version,
        len = init_body.len(),
        "ts2021 received initiation"
    );
    reject_unsupported_noise_capability(proto_version)?;

    // Step 2: drive Noise IK responder. The prologue must be derived
    // from the client-advertised protocol version, not a server
    // constant — upstream
    // `tailscale/control/controlbase/handshake.go::Server` does
    // `s.MixHash(protocolVersionPrologue(clientVersion))`.
    let mut responder = state
        .server_noise_key
        .build_responder_for_version(proto_version)?;
    let mut payload_buf = vec![0u8; 65535];
    let _payload_len = responder
        .read_message(&init_body, &mut payload_buf)
        .map_err(noise_err)?;
    let machine_key_hex = responder_remote_static_hex(&responder)?;

    // Step 3: write Reply.
    let mut reply_body = vec![0u8; 65535];
    let reply_len = responder
        .write_message(&[], &mut reply_body)
        .map_err(noise_err)?;
    reply_body.truncate(reply_len);
    handshake_io(
        deadline,
        "write reply frame",
        framed.write_frame(MsgType::Reply, &reply_body),
    )
    .await?;

    let transport = responder.into_transport_mode().map_err(noise_err)?;
    let mut noise_stream = framed.into_transport(transport);

    // Step 5: send the EarlyNoise frame before HTTP/2 starts. Format:
    // [0xff 0xff 0xff 'T' 'S'] [json_len:u32be] [json].
    //
    // Upstream `hscontrol/noise.go::earlyNoise` marshals a
    // `tailcfg.EarlyNoise{NodeKeyChallenge: ns.challenge.Public()}`
    // where `challenge` is a freshly-generated X25519 challenge key
    // (`key.NewChallenge()`). The client uses this challenge to prove
    // node-key possession in a follow-up request later in the flow;
    // for the stock `tailscale up` interop test the value just needs
    // to be a *well-formed* X25519 public key — a degenerate
    // all-zeros key may be rejected by the client's curve25519
    // validation.
    //
    // We generate a fresh challenge per /ts2021 connection via
    // `snow::Builder::generate_keypair` (already a workspace dep) so
    // we don't depend on x25519-dalek. The challenge is ephemeral —
    // there's no need to persist it.
    // `NodeKeyChallenge` is a `key.ChallengePublic` — see
    // `tailscale/types/key/chal.go`. Its text marshaling is
    // `chalpub:<hex>`; JSON uses the same shape via Go's default
    // `MarshalText` plumbing (the unmarshaler in the client expects a
    // bare string, not an object — we shipped an object first and
    // the client logged a json-unmarshal error on the EarlyNoise read).
    let early = build_early_noise_frame()?;
    use tokio::io::AsyncWriteExt;
    handshake_io(
        deadline,
        "write early-noise",
        noise_stream.write_all(&early),
    )
    .await?;
    handshake_io(deadline, "flush early-noise", noise_stream.flush()).await?;
    let h2_conn = handshake_io(
        deadline,
        "h2 handshake",
        control_h2_builder().handshake(noise_stream),
    )
    .await?;
    drop(pending_handshake);
    serve_noise_h2(state, h2_conn, machine_key_hex, None).await
}

async fn handshake_io<F, T, E>(
    deadline: tokio::time::Instant,
    stage: &str,
    operation: F,
) -> Result<T, WireError>
where
    F: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    tokio::time::timeout_at(deadline, operation)
        .await
        .map_err(|_| WireError::Noise(format!("{stage}: handshake timed out")))?
        .map_err(|err| WireError::Noise(format!("{stage}: {err}")))
}

fn control_h2_builder() -> h2::server::Builder {
    let mut builder = h2::server::Builder::new();
    #[cfg(feature = "full")]
    builder.go_native_server(None);
    builder
        .max_concurrent_streams(MAX_CONTROL_H2_STREAMS)
        .max_header_list_size(MAX_CONTROL_H2_HEADER_BYTES)
        .max_frame_size(MAX_CONTROL_H2_FRAME_BYTES)
        .initial_window_size(CONTROL_H2_RECEIVE_WINDOW)
        .initial_connection_window_size(CONTROL_H2_RECEIVE_WINDOW)
        .header_table_size(4096);
    builder
}

async fn serve_noise_h2<T>(
    state: WireState,
    mut connection: h2::server::Connection<T, bytes::Bytes>,
    machine_key_hex: String,
    remote_addr: Option<RequestLogRemoteAddr>,
) -> Result<(), WireError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let machines = state.machines.clone();
    let Some(_native_connection) = machines.begin_native_work() else {
        return Ok(());
    };
    let router = inner_router(state);
    let mut requests = tokio::task::JoinSet::new();
    let shutdown = machines.native_shutdown_started();
    tokio::pin!(shutdown);
    let mut closing = false;
    loop {
        while requests.try_join_next().is_some() {}
        if closing && requests.is_empty() {
            // Requests have queued their resets and dropped their bodies.
            // Give control frames one nonblocking flush opportunity; a peer
            // that stopped reading must not hold local shutdown indefinitely.
            let _ =
                std::future::poll_fn(|cx| std::task::Poll::Ready(connection.poll_closed(cx))).await;
            break;
        }
        tokio::select! {
            biased;
            () = &mut shutdown, if !closing => {
                closing = true;
                connection.graceful_shutdown();
            }
            result = connection.accept() => {
                let Some(result) = result else {
                    if closing {
                        while requests.join_next().await.is_some() {}
                    }
                    break;
                };
                let (request, mut response) = result.map_err(|err| WireError::Noise(format!("h2 accept: {err}")))?;
                if closing || requests.len() >= MAX_CONTROL_H2_STREAMS as usize {
                    response.send_reset(h2::Reason::REFUSED_STREAM);
                    continue;
                }
                let router = router.clone();
                let machine_key = machine_key_hex.clone();
                let remote_addr = remote_addr.clone();
                let machines = machines.clone();
                requests.spawn(async move {
                    if let Err(err) = dispatch_h2_request(router, machine_key, request, &mut response, machines, remote_addr).await {
                        tracing::debug!(target = "tailscale_wire::noise", error = %err, "h2 request ended");
                    }
                });
            }
            _ = requests.join_next(), if !requests.is_empty() => {}
        }
    }
    // Native shutdown joins requests above. Unexpected transport closure drops
    // the JoinSet and releases their guards; owned map mutations and deferred
    // disconnect persistence retain their own shutdown work tickets.
    Ok(())
}

/// Drain an h2 request body, hand it to `router.oneshot(...)`, send
/// the response back via the h2 SendResponse.
///
/// **Wall 5 fix (2026-05-19):** the response body is forwarded
/// frame-by-frame instead of `collect()`-ed up-front. The long-poll
/// `/machine/map` handler returns a never-terminating
/// `futures_util::stream::unfold` body (initial MapResponse + 30s
/// keepalives, no natural EOF). Buffering it via
/// `BodyExt::collect().await` therefore blocked forever, the h2
/// `SendResponse` never carried response headers back to the client,
/// and stock `tailscale up` timed out 20s into its first map call.
async fn dispatch_h2_request(
    router: Router,
    machine_key_hex: String,
    req: http::Request<h2::RecvStream>,
    respond: &mut h2::server::SendResponse<bytes::Bytes>,
    machines: Arc<super::MachineRegistry>,
    remote_addr: Option<RequestLogRemoteAddr>,
) -> Result<(), WireError> {
    use bytes::{Bytes, BytesMut};
    use http_body::Body as HttpBody;
    use tower::ServiceExt;

    let (mut parts, mut body) = req.into_parts();

    let req_method = parts.method.clone();
    let req_uri = parts.uri.clone();
    let shutdown = machines.native_shutdown_started();
    tokio::pin!(shutdown);
    tracing::debug!(
        target = "tailscale_wire::noise",
        method = %req_method,
        uri = %req_uri,
        "h2 dispatch begin"
    );

    // Drain the request body into a Bytes — the existing handlers all
    // expect a fully-buffered body anyway (`Json<...>` / `Bytes`
    // extractors). Register and map bodies are <2 KiB.
    let mut body_bytes = BytesMut::new();
    let body_deadline = tokio::time::Instant::now() + CONTROL_HANDSHAKE_TIMEOUT;
    loop {
        let chunk = tokio::select! {
            biased;
            () = &mut shutdown => {
                respond.send_reset(h2::Reason::INTERNAL_ERROR);
                return Ok(());
            }
            chunk = tokio::time::timeout_at(body_deadline, body.data()) => {
                chunk.map_err(|_| WireError::Noise("h2 request body timed out".into()))?
            }
        };
        let Some(chunk) = chunk else {
            break;
        };
        let chunk = chunk.map_err(|e| WireError::Noise(format!("h2 body read: {e}")))?;
        let n = chunk.len();
        if body_bytes.len().saturating_add(n) > NOISE_BODY_LIMIT {
            let _ = body.flow_control().release_capacity(n);
            send_plain_h2_response(
                respond,
                StatusCode::PAYLOAD_TOO_LARGE,
                "request body too large\n",
            )?;
            tracing::warn!(
                target = "tailscale_wire::noise",
                uri = %req_uri,
                limit = NOISE_BODY_LIMIT,
                "h2 dispatch request body exceeded limit"
            );
            return Ok(());
        }
        body_bytes.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(n);
    }
    let body_bytes = body_bytes.freeze();

    // Build the axum Request to drive through oneshot.
    let axum_body = Body::from(body_bytes);
    let cancellation = NoiseRequestCancellation::new();
    parts
        .extensions
        .insert(NoisePeerMachineKey(machine_key_hex));
    parts.extensions.insert(cancellation.clone());
    if let Some(remote_addr) = remote_addr {
        attach_registration_source(&mut parts.extensions, &remote_addr);
        parts.extensions.insert(remote_addr);
    }
    let axum_req = http::Request::from_parts(parts, axum_body);

    let router_response = router.oneshot(axum_req);
    tokio::pin!(router_response);
    let resp = {
        let reset = std::future::poll_fn(|cx| respond.poll_reset(cx));
        tokio::pin!(reset);
        tokio::select! {
            biased;
            () = &mut shutdown => None,
            resp = &mut router_response => {
                Some(resp.map_err(|e| WireError::Noise(format!("router oneshot: {e}")))?)
            }
            reset = &mut reset => {
                cancellation.cancel();
                match reset {
                    Ok(reason) => {
                        tracing::debug!(
                            target = "tailscale_wire::noise",
                            uri = %req_uri,
                            reason = ?reason,
                            "h2 stream reset before response"
                        );
                        return Ok(());
                    }
                    Err(e) => return Err(WireError::Noise(format!("h2 poll_reset: {e}"))),
                }
            }
        }
    };
    let Some(resp) = resp else {
        cancellation.cancel();
        // Dropping an unanswered h2 SendResponse implicitly sends CANCEL.
        // Go's expired write deadline uses INTERNAL_ERROR for stopped maps.
        respond.send_reset(h2::Reason::INTERNAL_ERROR);
        return Ok(());
    };

    let (mut resp_parts, mut resp_body) = resp.into_parts();
    let deletion = resp_parts
        .extensions
        .remove::<super::map::MapStreamDeletion>();
    let deletion = async move {
        match deletion {
            Some(deletion) => deletion.deleted().await,
            None => std::future::pending::<()>().await,
        }
    };
    tokio::pin!(deletion);
    let mut head = http::Response::builder().status(resp_parts.status);
    {
        let hdrs = head.headers_mut().expect("builder is valid");
        for (k, v) in &resp_parts.headers {
            hdrs.append(k.clone(), v.clone());
        }
    }
    let head: http::Response<()> = head.body(()).unwrap();

    // Send response headers IMMEDIATELY so the client can advance its
    // state machine while we keep streaming body frames. `end_of_stream
    // = false` because the body may carry one or more frames (and for
    // `/machine/map` Stream=true, infinitely many).
    let mut send = respond
        .send_response(head, false)
        .map_err(|e| WireError::Noise(format!("h2 send_response: {e}")))?;
    tracing::debug!(
        target = "tailscale_wire::noise",
        uri = %req_uri,
        "h2 dispatch sent response headers; streaming body frames"
    );

    // Forward already-framed map updates under HTTP/2 flow control. Polling
    // the body directly preserves the initial full response, incremental
    // updates and keepalives without collecting the never-ending stream.
    let mut frame_count: u64 = 0;
    loop {
        let frame_opt = tokio::select! {
            biased;
            () = &mut deletion => {
                // Go's immediate write deadline resets deleted sessions even
                // when no further response-body frame can be consumed.
                send.send_reset(h2::Reason::INTERNAL_ERROR);
                cancellation.cancel();
                return Ok(());
            }
            () = &mut shutdown => {
                send.send_reset(h2::Reason::INTERNAL_ERROR);
                cancellation.cancel();
                return Ok(());
            }
            frame = std::future::poll_fn(|cx| std::pin::Pin::new(&mut resp_body).poll_frame(cx)) => frame,
            reset = std::future::poll_fn(|cx| send.poll_reset(cx)) => {
                cancellation.cancel();
                return reset.map(|_| ()).map_err(|error| WireError::Noise(format!("h2 response reset: {error}")));
            }
        };
        match frame_opt {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    if !data.is_empty() {
                        let chunk: Bytes = data;
                        // Capacity waits must remain interruptible by the
                        // owning map session's sticky deletion signal.
                        let sent = tokio::select! {
                            biased;
                            () = &mut deletion => None,
                            () = &mut shutdown => None,
                            result = send_h2_data(&mut send, chunk, false) => Some(result),
                        };
                        if let Some(result) = sent {
                            result?;
                        } else {
                            send.send_reset(h2::Reason::INTERNAL_ERROR);
                            cancellation.cancel();
                            return Ok(());
                        }
                        frame_count += 1;
                    }
                }
                Err(_trailers_frame) => {
                    // We don't emit trailers for the streaming map
                    // response, but if any handler ever does, just
                    // skip — h2 will close the stream cleanly on the
                    // next iteration when poll_frame returns None.
                }
            },
            Some(Err(e)) => {
                send.send_reset(h2::Reason::INTERNAL_ERROR);
                tracing::warn!(
                    target = "tailscale_wire::noise",
                    uri = %req_uri,
                    error = %e,
                    "h2 dispatch body error"
                );
                return Err(WireError::Noise(format!("body frame: {e}")));
            }
            None => {
                // Body ended naturally — for register/non-streaming
                // map this is the common path. Close the stream by
                // sending an empty final frame with end_of_stream=true.
                send_h2_data(&mut send, Bytes::new(), true).await?;
                break;
            }
        }
    }
    tracing::debug!(
        target = "tailscale_wire::noise",
        uri = %req_uri,
        frames = frame_count,
        "h2 dispatch complete"
    );
    Ok(())
}

/// Respect the peer's receive window instead of buffering an unbounded
/// sequence of map updates behind a slow or stalled client.
async fn send_h2_data(
    stream: &mut h2::SendStream<bytes::Bytes>,
    mut data: bytes::Bytes,
    end_stream: bool,
) -> Result<(), WireError> {
    if data.is_empty() {
        if end_stream {
            stream
                .send_data(data, true)
                .map_err(|error| WireError::Noise(format!("h2 send_data eof: {error}")))?;
        }
        return Ok(());
    }
    while !data.is_empty() {
        stream.reserve_capacity(data.len());
        let capacity = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(|| WireError::Noise("h2 response stream closed".into()))?
            .map_err(|error| WireError::Noise(format!("h2 send capacity: {error}")))?;
        if capacity == 0 {
            continue;
        }
        let chunk = data.split_to(capacity.min(data.len()));
        stream
            .send_data(chunk, end_stream && data.is_empty())
            .map_err(|error| WireError::Noise(format!("h2 send_data: {error}")))?;
    }
    Ok(())
}

fn send_plain_h2_response(
    respond: &mut h2::server::SendResponse<bytes::Bytes>,
    status: StatusCode,
    body: &'static str,
) -> Result<(), WireError> {
    let head = http::Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(())
        .expect("plain h2 response builder is valid");
    let mut send = respond
        .send_response(head, false)
        .map_err(|e| WireError::Noise(format!("h2 send_response error: {e}")))?;
    send.send_data(bytes::Bytes::from_static(body.as_bytes()), true)
        .map_err(|e| WireError::Noise(format!("h2 send_data error: {e}")))?;
    Ok(())
}

async fn not_implemented_handler() -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "Not implemented yet\n",
    )
}

/// Construct an inner router that maps just the per-machine endpoints
/// served behind /ts2021. The `/key` and `/ts2021` routes deliberately
/// aren't mounted here — they live on the outer public router.
pub(crate) fn inner_router(state: WireState) -> Router {
    use axum::routing::{get, patch, post};
    let metrics_registry = Arc::clone(&state.machines);
    Router::new()
        // Keyed variants — kept for legacy / direct-test paths.
        .route(
            "/machine/:node_key/register",
            post(super::register::handle_register),
        )
        .route("/machine/:node_key/map", post(super::map::handle_map))
        // Flat v1.78+ paths — what stock `tailscale up` actually POSTs
        // through the noise-h2 tunnel. NodeKey lives in the request
        // body, not the URL.
        .route(
            "/machine/register",
            post(super::register::handle_register_flat),
        )
        .route("/machine/map", post(super::map::handle_map_flat))
        .route(
            "/machine/ssh/action/:src_node_id/to/:dst_node_id",
            get(super::ssh::handle_ssh_action),
        )
        .route("/machine/whoami", get(not_implemented_handler))
        .route("/machine/set-dns", post(not_implemented_handler))
        .route("/machine/set-device-attr", patch(not_implemented_handler))
        .route("/machine/audit-log", post(not_implemented_handler))
        .route("/machine/id-token", post(not_implemented_handler))
        .route("/machine/feature/query", post(not_implemented_handler))
        .route("/machine/update-health", post(not_implemented_handler))
        .route("/machine/c2n", post(not_implemented_handler))
        .layer(DefaultBodyLimit::max(NOISE_BODY_LIMIT))
        .with_state(state)
        .layer(axum::middleware::from_fn(
            move |req: Request, next: axum::middleware::Next| {
                let metrics_registry = Arc::clone(&metrics_registry);
                async move { super::record_http_metrics(metrics_registry, req, next, true).await }
            },
        ))
}

/// Like [`drive_ts2021_with_init`] but uses the **big-endian-nonce**
/// post-handshake transport ([`BeTransport`]) instead of `snow`'s
/// spec-faithful little-endian transport. This is the variant
/// production wires up: stock `tailscale up` v1.78+ writes its
/// transport records with BE nonces (see
/// `tailscale/control/controlbase/conn.go::nonce`), so we have to
/// match or the very first decrypt-after-handshake fails with a tag
/// mismatch.
///
/// The IK handshake itself still runs through `snow` — that part is
/// fully spec-compliant and well-tested by upstream snow users. We
/// only deviate from `snow` at the `Split()` boundary: extract the
/// two ChaCha20Poly1305 keys via `dangerously_get_raw_split()`, hand
/// them to `BeTransport`, then run record encryption/decryption with
/// BE nonces.
pub async fn drive_ts2021_be_with_init<T>(
    state: WireState,
    io: T,
    initial_frame: Option<Vec<u8>>,
) -> Result<(), WireError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    drive_ts2021_be_with_init_remote_addr(state, io, initial_frame, None).await
}

/// Native upgrades pin the outer router's resolved RemoteAddr across the
/// hijack, exactly as the Go Noise overrideRemoteAddr middleware does.
pub(super) async fn drive_ts2021_be_with_init_remote_addr<T>(
    state: WireState,
    io: T,
    initial_frame: Option<Vec<u8>>,
    remote_addr: Option<RequestLogRemoteAddr>,
) -> Result<(), WireError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let pending_handshake = state.server_noise_key.handshake_permit()?;
    let deadline = tokio::time::Instant::now() + CONTROL_HANDSHAKE_TIMEOUT;
    let mut framed = Framed::new(io);

    // Step 1: source the Initiation (header-fast-start or pipelined).
    let (hdr, init_body) = match initial_frame {
        Some(bytes) => {
            tracing::debug!(
                target = "tailscale_wire::noise",
                len = bytes.len(),
                "ts2021/be using pre-decoded Initiation from X-Tailscale-Handshake header"
            );
            parse_initiation_frame(&bytes)?
        }
        None => handshake_io(deadline, "read initiation frame", framed.read_frame()).await?,
    };
    let proto_version = match hdr {
        FrameHeader::Initiation {
            protocol_version, ..
        } => protocol_version,
        other @ FrameHeader::Regular { .. } => {
            return Err(WireError::Noise(format!(
                "expected Initiation frame first, got {other:?}"
            )));
        }
    };
    tracing::debug!(
        target = "tailscale_wire::noise",
        proto_version,
        len = init_body.len(),
        "ts2021/be received initiation"
    );
    reject_unsupported_noise_capability(proto_version)?;

    // Step 2: drive Noise IK responder via snow (handshake stays
    // spec-faithful).
    let mut responder = state
        .server_noise_key
        .build_responder_for_version(proto_version)?;
    let mut payload_buf = vec![0u8; 65535];
    let _payload_len = responder
        .read_message(&init_body, &mut payload_buf)
        .map_err(noise_err)?;
    let machine_key_hex = responder_remote_static_hex(&responder)?;

    // Step 3: write Reply frame.
    let mut reply_body = vec![0u8; 65535];
    let reply_len = responder
        .write_message(&[], &mut reply_body)
        .map_err(noise_err)?;
    reply_body.truncate(reply_len);
    handshake_io(
        deadline,
        "write reply frame",
        framed.write_frame(MsgType::Reply, &reply_body),
    )
    .await?;

    // Step 4: extract split keys *before* converting into transport
    // mode (snow's transport_state_mut path is private; the public
    // accessor is on HandshakeState). `dangerously_get_raw_split`
    // returns (k1, k2) where k1 = initiator-egress and k2 =
    // responder-egress per Noise spec `Split()`. Behind the
    // `risky-raw-split` feature in our Cargo.toml.
    let (k1_init_egress, k2_resp_egress) = responder.dangerously_get_raw_split();
    tracing::debug!(
        target = "tailscale_wire::noise",
        "ts2021/be split keys extracted; switching to BE-nonce transport"
    );
    // We are the responder: send_key = k2, recv_key = k1.
    let be_transport = BeTransport::from_split_responder(k1_init_egress, k2_resp_egress);
    let inner_io = framed.into_inner();
    let mut noise_stream = BeNoiseStream::new(inner_io, be_transport);

    // Step 5: send the EarlyNoise frame. Same payload as the
    // snow-backed path. With the BE transport this is what stock
    // `tailscale up` actually expects to decrypt first.
    // `NodeKeyChallenge` is a `key.ChallengePublic` — see
    // `tailscale/types/key/chal.go`. Its text marshaling is
    // `chalpub:<hex>`; JSON uses the same shape via Go's default
    // `MarshalText` plumbing (the unmarshaler in the client expects a
    // bare string, not an object — we shipped an object first and
    // the client logged a json-unmarshal error on the EarlyNoise read).
    let early = build_early_noise_frame()?;
    use tokio::io::AsyncWriteExt;
    handshake_io(
        deadline,
        "write early-noise",
        noise_stream.write_all(&early),
    )
    .await?;
    handshake_io(deadline, "flush early-noise", noise_stream.flush()).await?;
    let h2_conn = handshake_io(
        deadline,
        "h2 handshake",
        control_h2_builder().handshake(noise_stream),
    )
    .await?;
    drop(pending_handshake);
    serve_noise_h2(state, h2_conn, machine_key_hex, remote_addr).await
}

/// Convenience wrapper for the no-pre-decoded-Initiation case.
pub async fn drive_ts2021_be<T>(state: WireState, io: T) -> Result<(), WireError>
where
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    drive_ts2021_be_with_init(state, io, None).await
}

fn responder_remote_static_hex(responder: &snow::HandshakeState) -> Result<String, WireError> {
    let remote = responder
        .get_remote_static()
        .ok_or_else(|| WireError::Noise("missing remote machine key in TS2021 IK".into()))?;
    if remote.len() != 32 {
        return Err(WireError::Noise(format!(
            "remote machine key has length {}; expected 32",
            remote.len()
        )));
    }
    Ok(hex::encode(remote))
}

fn reject_unsupported_noise_capability(protocol_version: u16) -> Result<(), WireError> {
    let version = u32::from(protocol_version);
    if is_supported_capability_version(version) {
        return Ok(());
    }
    Err(WireError::Noise(unsupported_client_error(version)))
}

/// Decode a pre-fetched controlbase-framed Initiation (the bytes that
/// arrived in the `X-Tailscale-Handshake` header). Returns the same
/// `(FrameHeader::Initiation { .. }, body)` shape `Framed::read_frame`
/// produces.
///
/// The wire format mirrors upstream `controlbase/messages.go::initiationMessage`
/// (and our updated `Framed::write_initiation`):
///   `[protocol_version:u16be][msg_type=1:u8][len:u16be][body...]`
fn parse_initiation_frame(bytes: &[u8]) -> Result<(FrameHeader, Vec<u8>), WireError> {
    if bytes.len() < 5 {
        return Err(WireError::Noise(format!(
            "X-Tailscale-Handshake init too short: {} bytes",
            bytes.len()
        )));
    }
    let protocol_version = u16::from_be_bytes([bytes[0], bytes[1]]);
    let msg_type = bytes[2];
    if msg_type != MsgType::Initiation as u8 {
        return Err(WireError::Noise(format!(
            "X-Tailscale-Handshake init: expected msg type 1 at offset 2, got {msg_type}"
        )));
    }
    let body_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if bytes.len() != 5 + body_len {
        return Err(WireError::Noise(format!(
            "X-Tailscale-Handshake init length mismatch: header says {}, total bytes {}",
            5 + body_len,
            bytes.len()
        )));
    }
    let body = bytes[5..].to_vec();
    Ok((
        FrameHeader::Initiation {
            protocol_version,
            len: body_len as u16,
        },
        body,
    ))
}

/// Compatibility alias for the old `handle_ts2021_stub` name. Returns
/// 501 if invoked via a non-upgrading client; the upgrade-aware handler
/// is `handle_ts2021_post`. Kept so external integration tests that
/// still POST without Upgrade headers can see a deterministic status.
pub async fn handle_ts2021_stub(State(_s): State<WireState>) -> impl IntoResponse {
    (
        StatusCode::NOT_IMPLEMENTED,
        "ts2021 upgrade not yet wired; see docs/tailscale-interop-blocker.md",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tailscale_wire::{
        MachineRegistry, WireState,
        test_support::{MockIpAllocator, MockRedeemer},
    };
    use axum::body::to_bytes;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tower::ServiceExt;

    fn fixture_state() -> (WireState, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());
        let state = WireState {
            server_noise_key: server,
            preauth: Arc::new(MockRedeemer::new()),
            ip_allocator: Arc::new(MockIpAllocator),
            machines: Arc::new(MachineRegistry::new()),
            registration_store: None,
            registration_gate: None,
            derp_map: crate::tailscale_wire::DerpMapStore::shared(
                crate::tailscale_wire::wire::DerpMap::default(),
            ),
            #[cfg(feature = "full")]
            native_derp: None,
            policy: Arc::new(crate::policy::PolicyStore::new()),
            knock: crate::tailscale_wire::KnockConfig::disabled(),
            dns: Arc::new(crate::dns::DnsStore::new()),
            public_control_url: None,
            runtime_config: Arc::new(crate::tailscale_wire::RuntimeConfigSnapshot::default()),
            registration_cache: Arc::new(crate::tailscale_wire::RegistrationCache::new()),
            pings: Arc::new(crate::tailscale_wire::PingTracker::new()),
            mapresponse_debug: Arc::new(crate::tailscale_wire::MapResponseDebugStore::disabled()),
        };
        (state, dir)
    }

    #[test]
    fn server_key_persists_across_loads() {
        let dir = tempdir().unwrap();
        let a = ServerNoiseKey::load_or_generate(dir.path()).unwrap();
        let pub_a = a.public_bytes();
        drop(a);
        let b = ServerNoiseKey::load_or_generate(dir.path()).unwrap();
        assert_eq!(
            pub_a,
            b.public_bytes(),
            "static key must persist across loads"
        );
    }

    #[test]
    fn configured_go_key_is_used_across_restart() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("go/noise_private.key");
        let private = [7u8; 32];
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("privkey:{}", hex::encode(private))).unwrap();
        let first =
            ServerNoiseKey::load_or_generate_with_configured_path(dir.path(), Some(&path)).unwrap();
        let expected = derive_x25519_public(&private).unwrap();
        assert_eq!(first.public_bytes(), expected);
        assert!(!dir.path().join(NOISE_STATIC_KEY_FILENAME).exists());
        let second =
            ServerNoiseKey::load_or_generate_with_configured_path(dir.path(), Some(&path)).unwrap();
        assert_eq!(second.public_bytes(), expected);
    }

    #[test]
    fn configured_key_generation_is_go_compatible_and_preserves_legacy_identity() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("go/noise_private.key");
        let first =
            ServerNoiseKey::load_or_generate_with_configured_path(dir.path(), Some(&path)).unwrap();
        let encoded = fs::read_to_string(&path).unwrap();
        assert_eq!(encoded.trim_end_matches('\n').len(), "privkey:".len() + 64);
        assert!(encoded.starts_with("privkey:"));
        let second =
            ServerNoiseKey::load_or_generate_with_configured_path(dir.path(), Some(&path)).unwrap();
        assert_eq!(first.public_bytes(), second.public_bytes());

        let legacy_dir = tempdir().unwrap();
        let legacy = ServerNoiseKey::load_or_generate(legacy_dir.path()).unwrap();
        let missing = legacy_dir.path().join("missing.key");
        let reopened = ServerNoiseKey::load_or_generate_with_configured_path(
            legacy_dir.path(),
            Some(&missing),
        )
        .unwrap();
        assert_eq!(legacy.public_bytes(), reopened.public_bytes());
        assert!(!missing.exists());
    }

    /// Go's `util.EnsureDir` (hscontrol/util/file.go) creates a missing key
    /// directory 0700 and leaves an existing one alone;
    /// `readOrCreatePrivateKey` (hscontrol/app.go) applies it to the Noise
    /// key's directory.
    #[cfg(unix)]
    #[test]
    fn key_directories_are_created_0700_like_go_ensure_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;

        let root = tempdir().unwrap();
        let state_dir = root.path().join("state");
        ServerNoiseKey::load_or_generate(&state_dir).unwrap();
        assert_eq!(mode(&state_dir), 0o700);

        let configured_state_dir = root.path().join("configured-state");
        let configured = root.path().join("go/keys/noise_private.key");
        ServerNoiseKey::load_or_generate_with_configured_path(
            &configured_state_dir,
            Some(&configured),
        )
        .unwrap();
        assert_eq!(mode(&configured_state_dir), 0o700);
        assert_eq!(mode(&root.path().join("go")), 0o700);
        assert_eq!(mode(&root.path().join("go/keys")), 0o700);

        // EnsureDir skips an existing directory, whose mode stays as found.
        let existing = root.path().join("existing");
        fs::create_dir(&existing).unwrap();
        fs::set_permissions(&existing, fs::Permissions::from_mode(0o755)).unwrap();
        ServerNoiseKey::load_or_generate(&existing).unwrap();
        assert_eq!(mode(&existing), 0o755);
    }

    #[test]
    fn malformed_configured_key_fails_closed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("noise_private.key");
        fs::write(&path, "privkey:invalid").unwrap();
        assert!(
            ServerNoiseKey::load_or_generate_with_configured_path(dir.path(), Some(&path)).is_err()
        );
        assert!(!dir.path().join(NOISE_STATIC_KEY_FILENAME).exists());
    }

    #[test]
    fn server_key_public_hex_is_64_chars() {
        let dir = tempdir().unwrap();
        let k = ServerNoiseKey::load_or_generate(dir.path()).unwrap();
        let h = k.public_hex();
        assert_eq!(h.len(), 64, "32-byte key → 64 hex chars");
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// The decisive Noise test: a snow IK round-trip between an
    /// initiator that knows the responder's static (the server's
    /// `ServerNoiseKey`) and a responder using that same key produces
    /// matching transport ciphers.
    #[test]
    fn ik_round_trip() {
        let dir = tempdir().unwrap();
        let server = Arc::new(ServerNoiseKey::load_or_generate(dir.path()).unwrap());

        // Initiator (client) needs to know the server's static public.
        let server_pub = server.public_bytes();
        let mut init = server.build_initiator(&server_pub).unwrap();
        let mut resp = server.build_responder().unwrap();

        // -> e, es, s, ss
        let mut buf1 = [0u8; 1024];
        let n1 = init.write_message(b"", &mut buf1).unwrap();
        let mut payload = [0u8; 1024];
        let n_in = resp.read_message(&buf1[..n1], &mut payload).unwrap();
        assert_eq!(n_in, 0);

        // <- e, ee, se
        let mut buf2 = [0u8; 1024];
        let n2 = resp.write_message(b"", &mut buf2).unwrap();
        let n_in2 = init.read_message(&buf2[..n2], &mut payload).unwrap();
        assert_eq!(n_in2, 0);

        // Both sides must now be in transport mode and agree.
        let mut init_t = init.into_transport_mode().unwrap();
        let mut resp_t = resp.into_transport_mode().unwrap();

        // Initiator → responder.
        let plaintext = b"hello tailscale";
        let mut ct = [0u8; 1024];
        let nc = init_t.write_message(plaintext, &mut ct).unwrap();
        let mut pt = [0u8; 1024];
        let nd = resp_t.read_message(&ct[..nc], &mut pt).unwrap();
        assert_eq!(&pt[..nd], plaintext);

        // Responder → initiator.
        let plaintext2 = b"hello octra";
        let nc2 = resp_t.write_message(plaintext2, &mut ct).unwrap();
        let nd2 = init_t.read_message(&ct[..nc2], &mut pt).unwrap();
        assert_eq!(&pt[..nd2], plaintext2);
    }

    #[test]
    fn prologue_format_matches_tailscale() {
        // Sanity-check the prologue against the upstream format
        // sourced in the module doc.
        let p = prologue_bytes(39);
        assert_eq!(p, b"Tailscale Control Protocol v39".to_vec());
    }

    #[test]
    fn early_noise_frame_uses_tailcfg_json_tag() {
        let frame = build_early_noise_frame().unwrap();
        assert!(frame.starts_with(&EARLY_NOISE_MAGIC));
        let len = u32::from_be_bytes(frame[5..9].try_into().unwrap()) as usize;
        assert_eq!(frame.len(), 9 + len);

        let json: serde_json::Value = serde_json::from_slice(&frame[9..]).unwrap();
        assert!(json.get("NodeKeyChallenge").is_none());
        let challenge = json
            .get("nodeKeyChallenge")
            .and_then(serde_json::Value::as_str)
            .expect("early-noise challenge");
        let challenge_hex = challenge
            .strip_prefix("chalpub:")
            .expect("challenge public-key prefix");
        assert_eq!(challenge_hex.len(), 64);
        assert!(challenge_hex.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn unsupported_noise_capability_is_rejected() {
        let err = reject_unsupported_noise_capability(112).unwrap_err();
        assert_eq!(
            err.to_string(),
            "noise handshake: unsupported client version:  (112)"
        );
        reject_unsupported_noise_capability(113).unwrap();
    }

    #[tokio::test]
    async fn ts2021_without_upgrade_header_matches_headscale_go_error_shape() {
        let (state, _dir) = fixture_state();
        let app = crate::tailscale_wire::router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/ts2021")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), b"Internal error\n");
    }

    /// `controlhttpserver.acceptHTTP` (tailscale control/controlhttp/
    /// controlhttpserver/controlhttpserver.go:42-64) rejects an unknown
    /// `Upgrade` value and a missing or undecodable `X-Tailscale-Handshake`
    /// header with `http.Error(..., 400)` before it hijacks the connection,
    /// so no Noise handshake state is held for such a request.
    #[tokio::test]
    async fn ts2021_header_errors_match_go_accept_http() {
        let (state, _dir) = fixture_state();
        let cases: [(&str, Option<&str>, &str); 3] = [
            (
                "not-the-control-protocol",
                Some("AAAA"),
                "unknown next protocol\n",
            ),
            (
                UPGRADE_PROTOCOL,
                None,
                "missing Tailscale handshake header\n",
            ),
            (
                UPGRADE_PROTOCOL,
                Some("!!!"),
                "invalid tailscale handshake header\n",
            ),
        ];
        for (upgrade, handshake, expected) in cases {
            let app = crate::tailscale_wire::router(state.clone());
            let mut request = axum::http::Request::builder()
                .method("POST")
                .uri("/ts2021")
                .header(header::CONNECTION, "Upgrade")
                .header(header::UPGRADE, upgrade);
            if let Some(handshake) = handshake {
                request = request.header(
                    crate::tailscale_wire::raw_tls::HANDSHAKE_HEADER_NAME,
                    handshake,
                );
            }
            let resp = app
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "{upgrade:?} {handshake:?}"
            );
            assert_eq!(
                resp.headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("text/plain; charset=utf-8"),
                "{upgrade:?} {handshake:?}"
            );
            let body = to_bytes(resp.into_body(), 4096).await.unwrap();
            assert_eq!(
                body.as_ref(),
                expected.as_bytes(),
                "{upgrade:?} {handshake:?}"
            );
            assert_eq!(
                state.server_noise_key.available_handshake_permits(),
                MAX_PENDING_CONTROL_HANDSHAKES,
                "a rejected request must not hold a handshake permit"
            );
        }
    }

    #[tokio::test]
    async fn ts2021_websocket_get_reaches_upgrade_handler() {
        let (state, _dir) = fixture_state();
        let app = crate::tailscale_wire::router(state);
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/ts2021?X-Tailscale-Handshake=AAAA")
                    .header("Connection", "Upgrade")
                    .header("Upgrade", "websocket")
                    .header("Sec-WebSocket-Version", "13")
                    .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                    .header("Sec-WebSocket-Protocol", UPGRADE_PROTOCOL)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn inner_router_exposes_upstream_not_implemented_control_routes() {
        let (state, _dir) = fixture_state();
        let cases = [
            ("GET", "/machine/whoami"),
            ("POST", "/machine/set-dns"),
            ("PATCH", "/machine/set-device-attr"),
            ("POST", "/machine/audit-log"),
            ("POST", "/machine/id-token"),
            ("POST", "/machine/feature/query"),
            ("POST", "/machine/update-health"),
            ("POST", "/machine/c2n"),
        ];

        for (method, uri) in cases {
            let app = inner_router(state.clone());
            let resp = app
                .oneshot(
                    axum::http::Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED, "{method} {uri}");
            let body = to_bytes(resp.into_body(), 4096).await.unwrap();
            assert_eq!(body.as_ref(), b"Not implemented yet\n", "{method} {uri}");
        }
    }

    #[tokio::test]
    async fn inner_router_control_routes_keep_upstream_method_boundaries() {
        let (state, _dir) = fixture_state();
        let cases = [
            ("POST", "/machine/whoami"),
            ("GET", "/machine/set-dns"),
            ("POST", "/machine/set-device-attr"),
            ("GET", "/machine/audit-log"),
            ("GET", "/machine/id-token"),
            ("GET", "/machine/feature/query"),
            ("GET", "/machine/update-health"),
            ("GET", "/machine/c2n"),
        ];

        for (method, uri) in cases {
            let app = inner_router(state.clone());
            let resp = app
                .oneshot(
                    axum::http::Request::builder()
                        .method(method)
                        .uri(uri)
                        .body(axum::body::Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "{method} {uri}"
            );
            let body = to_bytes(resp.into_body(), 4096).await.unwrap();
            assert!(
                body.is_empty(),
                "{method} {uri} must not hit the 501 placeholder handler"
            );
        }
    }

    #[tokio::test]
    async fn inner_router_keeps_webclient_unimplemented_as_404() {
        let (state, _dir) = fixture_state();
        let resp = inner_router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("GET")
                    .uri("/machine/webclient")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn inner_router_rejects_oversized_noise_bodies() {
        let (state, _dir) = fixture_state();
        let oversized = vec![b'x'; NOISE_BODY_LIMIT + 1];
        let resp = inner_router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/machine/map")
                    .body(axum::body::Body::from(oversized))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Drive `POST /machine/register` through the inner router the way
    /// `dispatch_h2_request` does: the outer layer resolves the connection's
    /// peer address, `attach_registration_source` carries it in, the handler
    /// files the pending entry under it.
    async fn post_interactive_register(
        state: &WireState,
        node_key_hex: &str,
        remote_addr: &str,
    ) -> StatusCode {
        let remote_addr = RequestLogRemoteAddr(remote_addr.to_owned());
        let app = inner_router(state.clone()).layer(axum::middleware::from_fn(
            move |mut req: Request, next: axum::middleware::Next| {
                let remote_addr = remote_addr.clone();
                async move {
                    req.extensions_mut()
                        .insert(NoisePeerMachineKey("00".repeat(32)));
                    attach_registration_source(req.extensions_mut(), &remote_addr);
                    next.run(req).await
                }
            },
        ));
        let body = serde_json::json!({
            "Version": 113,
            "NodeKey": format!("nodekey:{node_key_hex}"),
            "Hostinfo": { "Hostname": "pending" },
        });
        app.oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/machine/register")
                .body(axum::body::Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    #[tokio::test]
    async fn noise_requests_are_accounted_to_the_connections_resolved_peer_address() {
        use crate::tailscale_wire::{
            REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE, RegistrationSource,
        };

        let (state, _dir) = fixture_state();
        let cache = state.registration_cache.clone();
        let excess = 5;

        for i in 0..(REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE + excess) {
            // IPv4: every request carries a new port.
            let status = post_interactive_register(
                &state,
                &format!("{:064x}", 0x1000 + i),
                &format!("203.0.113.7:{}", 2000 + i),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            // IPv6: every request carries a new address inside one /64.
            let status = post_interactive_register(
                &state,
                &format!("{:064x}", 0x2000 + i),
                &format!("[2001:db8:5:6::{:x}]:443", i + 1),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
        }
        // An address the logger could not resolve lands in the shared bucket.
        assert_eq!(
            post_interactive_register(&state, &format!("{:064x}", 0x3000), "not an address").await,
            StatusCode::OK
        );

        let v4 = RegistrationSource::from_remote_addr("203.0.113.7:1").unwrap();
        let v6 = RegistrationSource::from_remote_addr("[2001:db8:5:6::99]:1").unwrap();
        assert_eq!(
            cache.pending_from_source(v4),
            REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE
        );
        assert_eq!(
            cache.pending_from_source(v6),
            REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE
        );
        assert_eq!(cache.pending_from_source(RegistrationSource::Unknown), 1);
        assert_eq!(
            cache.len(),
            2 * REGISTRATION_CACHE_MAX_PENDING_PER_SOURCE + 1
        );
    }

    #[test]
    fn registration_source_extension_follows_the_resolved_address() {
        let mut extensions = http::Extensions::new();
        attach_registration_source(
            &mut extensions,
            &RequestLogRemoteAddr("198.51.100.4:50000".into()),
        );
        assert_eq!(
            extensions.get::<crate::tailscale_wire::RegistrationSource>(),
            crate::tailscale_wire::RegistrationSource::from_remote_addr("198.51.100.4").as_ref()
        );

        let mut extensions = http::Extensions::new();
        attach_registration_source(&mut extensions, &RequestLogRemoteAddr("garbage".into()));
        assert!(
            extensions
                .get::<crate::tailscale_wire::RegistrationSource>()
                .is_none()
        );
    }
}
