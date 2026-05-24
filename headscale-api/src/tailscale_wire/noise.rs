//! TS2021 Noise IK handshake helpers.
//!
//! Tailscale's TS2021 protocol uses the `Noise_IK_25519_ChaChaPoly_BLAKE2s`
//! pattern with a Tailscale-specific prologue string mixed in via
//! `MixHash`. The full wire-level upgrade also involves:
//!
//!   1. An HTTP `Upgrade: tailscale-control-protocol` request to
//!      `/ts2021`.
//!   2. A custom 3-byte header framing
//!      (`[msgType:u8][len:u16be]`, or 5-byte for `Initiation` carrying
//!      a `protocolVersion:u16be`) wrapping each Noise message.
//!   3. HTTP/2 spoken over the hijacked socket once the handshake
//!      completes.
//!
//! This module implements **layer (1) only**: an in-process initiator /
//! responder pair on top of `snow`, with the Tailscale prologue
//! correctly bound in. The framing layer (2) and the HTTP/2 hijack (3)
//! are *not* wired here — see the decision log in `mod.rs` for why,
//! and `docs/tailscale-interop-blocker.md` for the gap. With just (1)
//! we can prove the Noise math, write a round-trip test, and persist
//! the server's long-term static key. Adding (2) is mechanical;
//! adding (3) requires a Rust HTTP/2 server that can take a hijacked
//! `tokio::io::AsyncRead+AsyncWrite` connection (no crate exposes
//! this cleanly today — `h2` requires its own Connection type).
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
//! - **Static key persistence:** `<state_dir>/noise_static.key`,
//!   32 raw bytes (no PEM, no JSON envelope). The file is created
//!   `0600` on Unix; on Windows we rely on the default ACL inherited
//!   from the parent dir. We chose raw bytes rather than a JSON
//!   envelope because there's exactly one consumer (this module) and
//!   the simpler format is harder to corrupt.

use std::{
    fs,
    io::{ErrorKind, Read, Write},
    path::{Path, PathBuf},
};

use axum::{
    Router,
    body::Body,
    extract::DefaultBodyLimit,
    extract::{Request, State},
    http::{HeaderValue, Response, StatusCode, header},
    response::IntoResponse,
};
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use snow::{Builder, params::NoiseParams};

use super::be_transport::{BeNoiseStream, BeTransport};
use super::controlbase::{FrameHeader, Framed, MsgType};
use super::wire::{is_supported_capability_version, unsupported_client_error};
use super::{WireError, WireState};

/// Machine key learned from the client's TS2021 Noise static key.
/// Inner h2 requests carry this through axum extensions so `/register`
/// can persist the real machine identity instead of an empty placeholder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NoisePeerMachineKey(pub String);

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
}

impl ServerNoiseKey {
    /// Load the server's long-term static key from
    /// `<state_dir>/noise_static.key`, generating + persisting a fresh
    /// one if the file is absent.
    ///
    /// `state_dir` is created if it doesn't exist. On Unix the key file
    /// is written with mode `0600`.
    pub fn load_or_generate(state_dir: impl AsRef<Path>) -> Result<Self, WireError> {
        let dir: PathBuf = state_dir.as_ref().into();
        fs::create_dir_all(&dir)?;
        let path = dir.join(NOISE_STATIC_KEY_FILENAME);

        let private = match fs::File::open(&path) {
            Ok(mut f) => {
                let mut buf = Vec::with_capacity(32);
                f.read_to_end(&mut buf)?;
                if buf.len() != 32 {
                    return Err(WireError::Internal(format!(
                        "noise static key at {} has length {}; expected 32",
                        path.display(),
                        buf.len()
                    )));
                }
                buf
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let kp = Builder::new(NOISE_PATTERN.parse().map_err(noise_err)?)
                    .generate_keypair()
                    .map_err(noise_err)?;
                // Persist atomically: write to .tmp then rename. Avoids
                // a partial file on a crash mid-write.
                let tmp = path.with_extension("key.tmp");
                {
                    let mut f = fs::File::create(&tmp)?;
                    f.write_all(&kp.private)?;
                    f.sync_all()?;
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perm = fs::metadata(&tmp)?.permissions();
                    perm.set_mode(0o600);
                    fs::set_permissions(&tmp, perm)?;
                }
                fs::rename(&tmp, &path)?;
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
        })
    }

    /// 32-byte X25519 public key. Cheap to copy.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.public
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
fn generate_x25519_public() -> Result<[u8; 32], WireError> {
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
    // Verify the upgrade header before we commit to the hijack path.
    let wants_upgrade = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.eq_ignore_ascii_case(UPGRADE_PROTOCOL));
    if !wants_upgrade {
        return Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from("Internal error\n"))
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
                "ts2021: hyper OnUpgrade extension missing — not an upgradable connection",
            ))
            .unwrap();
    };

    let state_for_task = state;
    tokio::spawn(async move {
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
                if let Err(e) = drive_ts2021_be(state_for_task, io).await {
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
        None => framed
            .read_frame()
            .await
            .map_err(|e| WireError::Noise(format!("read initiation frame: {e}")))?,
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
    framed
        .write_frame(MsgType::Reply, &reply_body)
        .await
        .map_err(|e| WireError::Noise(format!("write reply frame: {e}")))?;

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
    let challenge_pub = generate_x25519_public()
        .map_err(|e| WireError::Noise(format!("generate early-noise challenge: {e}")))?;
    // `NodeKeyChallenge` is a `key.ChallengePublic` — see
    // `tailscale/types/key/chal.go`. Its text marshaling is
    // `chalpub:<hex>`; JSON uses the same shape via Go's default
    // `MarshalText` plumbing (the unmarshaler in the client expects a
    // bare string, not an object — we shipped an object first and
    // the client logged a json-unmarshal error on the EarlyNoise read).
    let early_json = serde_json::json!({
        "NodeKeyChallenge": format!("chalpub:{}", hex::encode(challenge_pub))
    })
    .to_string();
    let early_bytes = early_json.as_bytes();
    let mut early = Vec::with_capacity(5 + 4 + early_bytes.len());
    early.extend_from_slice(&EARLY_NOISE_MAGIC);
    early.extend_from_slice(&(early_bytes.len() as u32).to_be_bytes());
    early.extend_from_slice(early_bytes);
    use tokio::io::AsyncWriteExt;
    noise_stream
        .write_all(&early)
        .await
        .map_err(|e| WireError::Noise(format!("write early-noise: {e}")))?;
    noise_stream
        .flush()
        .await
        .map_err(|e| WireError::Noise(format!("flush early-noise: {e}")))?;

    // Step 6: h2 handshake + per-request dispatch.
    let mut h2_conn = h2::server::handshake(noise_stream)
        .await
        .map_err(|e| WireError::Noise(format!("h2 handshake: {e}")))?;

    // Build the machine-control router dispatched inside Noise h2.
    // These endpoints are deliberately not mounted on the outer public
    // router; upstream headscale only serves them behind TS2021.
    let router = inner_router(state.clone());

    while let Some(result) = h2_conn.accept().await {
        let (req, mut respond) = match result {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(target = "tailscale_wire::noise", error = %e, "h2 accept failed");
                break;
            }
        };
        let router_for_req = router.clone();
        let machine_key_hex = machine_key_hex.clone();
        tokio::spawn(async move {
            if let Err(e) =
                dispatch_h2_request(router_for_req, machine_key_hex, req, &mut respond).await
            {
                tracing::warn!(target = "tailscale_wire::noise", error = %e, "h2 dispatch failed");
            }
        });
    }
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
) -> Result<(), WireError> {
    use bytes::{Bytes, BytesMut};
    use http_body::Body as HttpBody;
    use tower::ServiceExt;

    let (mut parts, mut body) = req.into_parts();

    let req_method = parts.method.clone();
    let req_uri = parts.uri.clone();
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
    while let Some(chunk) = body.data().await {
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
    parts
        .extensions
        .insert(NoisePeerMachineKey(machine_key_hex));
    let axum_req = http::Request::from_parts(parts, axum_body);

    let resp = router
        .oneshot(axum_req)
        .await
        .map_err(|e| WireError::Noise(format!("router oneshot: {e}")))?;

    let (resp_parts, mut resp_body) = resp.into_parts();
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

    // Forward body frames as they arrive. We poll the underlying
    // `http_body::Body` directly (rather than going through
    // `BodyExt::collect`) so a non-terminating stream — the
    // `Stream=true` long-poll body — keeps the h2 stream open and
    // delivers keepalive `\n` chunks the client expects every 30s.
    //
    // Per `tailscale/control/controlclient/direct.go::sendMapRequest`,
    // the client uses `json.NewDecoder(resp.Body).Decode(&mr)` on a
    // streaming JSON decoder — pure newline-delimited JSON is
    // tolerated as whitespace between documents. The first
    // MapResponse frame unblocks the daemon's state-machine transition
    // to "Up"; subsequent frames carry registry-change deltas (we emit
    // a fresh full MapResponse on every wake — incremental Peers{Patch,Changed}
    // is documented as upstream-equivalent-but-unimplemented in
    // `wire.rs`).
    let mut frame_count: u64 = 0;
    loop {
        let frame_opt =
            std::future::poll_fn(|cx| std::pin::Pin::new(&mut resp_body).poll_frame(cx)).await;
        match frame_opt {
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => {
                    if !data.is_empty() {
                        let chunk: Bytes = data;
                        send.send_data(chunk, false)
                            .map_err(|e| WireError::Noise(format!("h2 send_data: {e}")))?;
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
                send.send_data(Bytes::new(), true)
                    .map_err(|e| WireError::Noise(format!("h2 send_data eof: {e}")))?;
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
        None => framed
            .read_frame()
            .await
            .map_err(|e| WireError::Noise(format!("read initiation frame: {e}")))?,
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
    framed
        .write_frame(MsgType::Reply, &reply_body)
        .await
        .map_err(|e| WireError::Noise(format!("write reply frame: {e}")))?;

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
    let challenge_pub = generate_x25519_public()
        .map_err(|e| WireError::Noise(format!("generate early-noise challenge: {e}")))?;
    // `NodeKeyChallenge` is a `key.ChallengePublic` — see
    // `tailscale/types/key/chal.go`. Its text marshaling is
    // `chalpub:<hex>`; JSON uses the same shape via Go's default
    // `MarshalText` plumbing (the unmarshaler in the client expects a
    // bare string, not an object — we shipped an object first and
    // the client logged a json-unmarshal error on the EarlyNoise read).
    let early_json = serde_json::json!({
        "NodeKeyChallenge": format!("chalpub:{}", hex::encode(challenge_pub))
    })
    .to_string();
    let early_bytes = early_json.as_bytes();
    let mut early = Vec::with_capacity(5 + 4 + early_bytes.len());
    early.extend_from_slice(&EARLY_NOISE_MAGIC);
    early.extend_from_slice(&(early_bytes.len() as u32).to_be_bytes());
    early.extend_from_slice(early_bytes);
    use tokio::io::AsyncWriteExt;
    noise_stream
        .write_all(&early)
        .await
        .map_err(|e| WireError::Noise(format!("write early-noise (be): {e}")))?;
    noise_stream
        .flush()
        .await
        .map_err(|e| WireError::Noise(format!("flush early-noise (be): {e}")))?;

    // Step 6: h2 over BE-nonce noise stream + per-request dispatch.
    let mut h2_conn = h2::server::handshake(noise_stream)
        .await
        .map_err(|e| WireError::Noise(format!("h2 handshake: {e}")))?;

    let router = inner_router(state.clone());
    while let Some(result) = h2_conn.accept().await {
        let (req, mut respond) = match result {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(target = "tailscale_wire::noise", error = %e, "h2 accept failed");
                break;
            }
        };
        let router_for_req = router.clone();
        let machine_key_hex = machine_key_hex.clone();
        tokio::spawn(async move {
            if let Err(e) =
                dispatch_h2_request(router_for_req, machine_key_hex, req, &mut respond).await
            {
                tracing::warn!(target = "tailscale_wire::noise", error = %e, "h2 dispatch failed");
            }
        });
    }
    Ok(())
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
            derp_map: crate::tailscale_wire::DerpMapStore::shared(
                crate::tailscale_wire::wire::DerpMap::default(),
            ),
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
}
