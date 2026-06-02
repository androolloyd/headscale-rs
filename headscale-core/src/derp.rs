//! DERP client for relay fallback when direct connections fail.
//!
//! DERP (Designated Encrypted Relay for Packets) provides a relay service
//! for WireGuard packets when direct UDP connections aren't possible.
//! This is a simplified implementation compatible with Tailscale's DERP protocol.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{RwLock, broadcast, mpsc};

use crate::config::EmbeddedDerpConfig;
use crate::stun::StunListener;

/// Default DERP port (HTTPS).
pub const DERP_PORT: u16 = 443;

/// DERP frame types.
const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_KEEP_ALIVE: u8 = 0x06;
const FRAME_PEER_GONE: u8 = 0x08;
const FRAME_PEER_PRESENT: u8 = 0x09;

/// Clean-room DERP wire protocol helpers for the native relay path.
///
/// This module intentionally models frame bytes and payload shapes only. The
/// sidecar runtime remains the default relay implementation until a native
/// session registry and `/derp` upgrade handler are layered on top.
pub mod protocol {
    /// Maximum packet payload visible to DERP, excluding frame headers.
    pub const MAX_PACKET_SIZE: usize = 64 << 10;
    /// DERP frame header size: one type byte plus a big-endian u32 length.
    pub const FRAME_HEADER_LEN: usize = 5;
    /// DERP node public-key length.
    pub const KEY_LEN: usize = 32;
    /// naclbox nonce length used by client/server info envelopes.
    pub const NONCE_LEN: usize = 24;
    /// Maximum encrypted client info envelope length accepted by servers.
    pub const MAX_CLIENT_INFO_LEN: usize = 256 << 10;
    /// Maximum encrypted server info envelope length accepted by clients.
    pub const MAX_INFO_LEN: usize = 1 << 20;
    /// Modern protocol version where received packets include a source key.
    pub const PROTOCOL_VERSION: u8 = 2;
    /// Server greeting magic bytes: `DERP` plus the UTF-8 key emoji.
    pub const MAGIC: &[u8; 8] = b"DERP\xF0\x9F\x94\x91";

    /// DERP frame type byte values.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub enum FrameType {
        /// 8B magic + 32B server public key + optional future bytes.
        ServerKey = 0x01,
        /// 32B client public key + 24B nonce + encrypted JSON.
        ClientInfo = 0x02,
        /// 24B nonce + encrypted JSON.
        ServerInfo = 0x03,
        /// 32B destination public key + packet bytes.
        SendPacket = 0x04,
        /// 32B source public key + packet bytes.
        RecvPacket = 0x05,
        /// Empty keep-alive frame.
        KeepAlive = 0x06,
        /// 1 byte boolean home-node preference.
        NotePreferred = 0x07,
        /// 32B peer public key + optional 1 byte reason.
        PeerGone = 0x08,
        /// 32B peer public key + optional endpoint + optional flags.
        PeerPresent = 0x09,
        /// 32B source public key + 32B destination public key + packet bytes.
        ForwardPacket = 0x0a,
        /// Subscribe to regional connection state.
        WatchConns = 0x10,
        /// Privileged request to close a peer.
        ClosePeer = 0x11,
        /// 8B ping payload.
        Ping = 0x12,
        /// 8B pong payload.
        Pong = 0x13,
        /// UTF-8-ish health/problem string; empty clears health state.
        Health = 0x14,
        /// Two u32 millisecond durations: reconnect-in and try-for.
        Restarting = 0x15,
    }

    impl FrameType {
        /// Numeric DERP frame type code.
        pub const fn code(self) -> u8 {
            self as u8
        }

        /// Convert a raw type byte into a known DERP frame type.
        pub const fn from_code(code: u8) -> Option<Self> {
            match code {
                0x01 => Some(Self::ServerKey),
                0x02 => Some(Self::ClientInfo),
                0x03 => Some(Self::ServerInfo),
                0x04 => Some(Self::SendPacket),
                0x05 => Some(Self::RecvPacket),
                0x06 => Some(Self::KeepAlive),
                0x07 => Some(Self::NotePreferred),
                0x08 => Some(Self::PeerGone),
                0x09 => Some(Self::PeerPresent),
                0x0a => Some(Self::ForwardPacket),
                0x10 => Some(Self::WatchConns),
                0x11 => Some(Self::ClosePeer),
                0x12 => Some(Self::Ping),
                0x13 => Some(Self::Pong),
                0x14 => Some(Self::Health),
                0x15 => Some(Self::Restarting),
                _ => None,
            }
        }
    }

    /// Reason byte carried by `PeerGone`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub enum PeerGoneReason {
        /// Peer disconnected from this server.
        Disconnected = 0x00,
        /// Server does not know the requested peer.
        NotHere = 0x01,
        /// Mesh watcher synthetic value used off-wire by Tailscale clients.
        MeshConnBroke = 0xf0,
        /// Future or unknown reason byte.
        Unknown(u8),
    }

    impl PeerGoneReason {
        /// Numeric reason code.
        pub const fn code(self) -> u8 {
            match self {
                Self::Disconnected => 0x00,
                Self::NotHere => 0x01,
                Self::MeshConnBroke => 0xf0,
                Self::Unknown(code) => code,
            }
        }

        /// Convert a reason byte to the typed representation.
        pub const fn from_code(code: u8) -> Self {
            match code {
                0x00 => Self::Disconnected,
                0x01 => Self::NotHere,
                0xf0 => Self::MeshConnBroke,
                other => Self::Unknown(other),
            }
        }
    }

    /// Optional flags carried by modern `PeerPresent` frames.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct PeerPresentFlags(pub u8);

    impl PeerPresentFlags {
        /// Regular client connection flag.
        pub const IS_REGULAR: u8 = 1 << 0;
        /// Regional mesh peer connection flag.
        pub const IS_MESH_PEER: u8 = 1 << 1;
        /// Prober connection flag.
        pub const IS_PROBER: u8 = 1 << 2;
        /// Client connected to a non-ideal DERP node.
        pub const NOT_IDEAL: u8 = 1 << 3;

        /// Whether this flag byte marks a regular client connection.
        pub const fn is_regular(self) -> bool {
            self.0 & Self::IS_REGULAR != 0
        }
    }

    /// Endpoint bytes carried in modern `PeerPresent` frames.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct PeerEndpoint {
        /// IPv6-mapped address bytes.
        pub ip: [u8; 16],
        /// Big-endian TCP/UDP port.
        pub port: u16,
    }

    /// Parsed DERP frame.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Frame {
        /// Server greeting.
        ServerKey {
            /// Server public key.
            key: [u8; KEY_LEN],
            /// Future extension bytes after the key.
            extra: Vec<u8>,
        },
        /// Encrypted client info envelope.
        ClientInfo {
            /// Client public key.
            public_key: [u8; KEY_LEN],
            /// 24B nonce + encrypted JSON.
            encrypted_info: Vec<u8>,
        },
        /// Encrypted server info envelope.
        ServerInfo {
            /// 24B nonce + encrypted JSON.
            encrypted_info: Vec<u8>,
        },
        /// Client packet to a destination peer.
        SendPacket {
            /// Destination peer key.
            destination: [u8; KEY_LEN],
            /// DERP packet bytes.
            packet: Vec<u8>,
        },
        /// Mesh node forwarded packet.
        ForwardPacket {
            /// Source peer key.
            source: [u8; KEY_LEN],
            /// Destination peer key.
            destination: [u8; KEY_LEN],
            /// DERP packet bytes.
            packet: Vec<u8>,
        },
        /// Server packet to a client.
        RecvPacket {
            /// Source peer key.
            source: [u8; KEY_LEN],
            /// DERP packet bytes.
            packet: Vec<u8>,
        },
        /// Keep-alive no-op.
        KeepAlive,
        /// Home-node preference.
        NotePreferred(bool),
        /// Peer gone notification.
        PeerGone {
            /// Peer key.
            peer: [u8; KEY_LEN],
            /// Gone reason.
            reason: PeerGoneReason,
        },
        /// Peer present notification.
        PeerPresent {
            /// Peer key.
            peer: [u8; KEY_LEN],
            /// Optional endpoint included by modern servers.
            endpoint: Option<PeerEndpoint>,
            /// Optional peer flags included by modern servers.
            flags: Option<PeerPresentFlags>,
            /// Future extension bytes.
            extra: Vec<u8>,
        },
        /// Watch regional connections.
        WatchConns,
        /// Close a peer connection.
        ClosePeer {
            /// Peer key to close.
            peer: [u8; KEY_LEN],
        },
        /// Ping payload.
        Ping([u8; 8]),
        /// Pong payload.
        Pong([u8; 8]),
        /// Health/problem text.
        Health(String),
        /// Server restarting advisory.
        Restarting {
            /// Delay before reconnecting, in milliseconds.
            reconnect_in_ms: u32,
            /// Total retry duration, in milliseconds.
            try_for_ms: u32,
        },
        /// Unknown future frame; callers may ignore it.
        Unknown {
            /// Raw frame type byte.
            frame_type: u8,
            /// Raw payload.
            payload: Vec<u8>,
        },
    }

    /// DERP frame parsing/encoding error.
    #[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
    pub enum ProtocolError {
        /// Fewer than five bytes were provided for the frame header.
        #[error("truncated DERP frame header: got {actual} bytes")]
        TruncatedHeader {
            /// Actual bytes available.
            actual: usize,
        },
        /// Payload length in the header exceeds the configured read limit.
        #[error("DERP frame length {len} exceeds limit {max}")]
        FrameTooLarge {
            /// Header-declared payload length.
            len: usize,
            /// Caller-provided maximum.
            max: usize,
        },
        /// Header was complete but the full payload was not available.
        #[error("incomplete DERP frame payload: need {expected} bytes, got {actual}")]
        IncompleteFrame {
            /// Total frame bytes required.
            expected: usize,
            /// Actual bytes available.
            actual: usize,
        },
        /// Known frame type had an invalid payload shape.
        #[error("invalid DERP {frame_type:?} payload: {reason}")]
        InvalidPayload {
            /// Frame type.
            frame_type: FrameType,
            /// Reason.
            reason: &'static str,
        },
        /// Payload was too large to encode as a DERP frame.
        #[error("DERP payload too large: {0} bytes")]
        PayloadTooLarge(usize),
        /// DERP packet payload exceeded the protocol packet cap.
        #[error("DERP packet too large: {len} bytes exceeds {max}")]
        PacketTooLarge {
            /// Actual packet bytes.
            len: usize,
            /// Protocol maximum packet bytes.
            max: usize,
        },
    }

    /// Build a DERP frame header.
    pub fn encode_header(frame_type: u8, payload_len: u32) -> [u8; FRAME_HEADER_LEN] {
        let mut header = [0u8; FRAME_HEADER_LEN];
        header[0] = frame_type;
        header[1..].copy_from_slice(&payload_len.to_be_bytes());
        header
    }

    /// Build a complete raw frame from a type byte and payload.
    pub fn encode_raw_frame(frame_type: u8, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
        let payload_len = u32::try_from(payload.len())
            .map_err(|_| ProtocolError::PayloadTooLarge(payload.len()))?;
        let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
        out.extend_from_slice(&encode_header(frame_type, payload_len));
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Build a complete typed frame.
    pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
        validate_frame_for_encode(frame)?;
        let (frame_type, payload) = frame.to_raw_parts();
        encode_raw_frame(frame_type, &payload)
    }

    /// Decode one complete frame from the beginning of `data`.
    ///
    /// Returns the parsed frame and the number of bytes consumed. Unknown frame
    /// types are returned as [`Frame::Unknown`] so callers can ignore future
    /// extensions without losing stream alignment.
    pub fn decode_frame(
        data: &[u8],
        max_payload_len: usize,
    ) -> Result<(Frame, usize), ProtocolError> {
        if data.len() < FRAME_HEADER_LEN {
            return Err(ProtocolError::TruncatedHeader { actual: data.len() });
        }
        let frame_type = data[0];
        let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        if len > max_payload_len {
            return Err(ProtocolError::FrameTooLarge {
                len,
                max: max_payload_len,
            });
        }
        let expected = FRAME_HEADER_LEN + len;
        if data.len() < expected {
            return Err(ProtocolError::IncompleteFrame {
                expected,
                actual: data.len(),
            });
        }
        let payload = &data[FRAME_HEADER_LEN..expected];
        let frame = if let Some(known) = FrameType::from_code(frame_type) {
            parse_payload(known, payload)?
        } else {
            Frame::Unknown {
                frame_type,
                payload: payload.to_vec(),
            }
        };
        Ok((frame, expected))
    }

    /// Incremental DERP frame decoder for TCP/HTTP-upgrade streams.
    #[derive(Debug)]
    pub struct FrameDecoder {
        buffer: Vec<u8>,
        max_payload_len: usize,
    }

    impl FrameDecoder {
        /// Create a stream decoder with a maximum accepted payload size.
        pub fn new(max_payload_len: usize) -> Self {
            Self {
                buffer: Vec::new(),
                max_payload_len,
            }
        }

        /// Queue more stream bytes.
        pub fn push(&mut self, bytes: &[u8]) {
            self.buffer.extend_from_slice(bytes);
        }

        /// Current queued byte count.
        pub fn buffered_len(&self) -> usize {
            self.buffer.len()
        }

        /// Decode the next complete frame when enough bytes are buffered.
        pub fn next_frame(&mut self) -> Result<Option<Frame>, ProtocolError> {
            if self.buffer.len() < FRAME_HEADER_LEN {
                return Ok(None);
            }
            let len = u32::from_be_bytes([
                self.buffer[1],
                self.buffer[2],
                self.buffer[3],
                self.buffer[4],
            ]) as usize;
            if len > self.max_payload_len {
                return Err(ProtocolError::FrameTooLarge {
                    len,
                    max: self.max_payload_len,
                });
            }
            let expected = FRAME_HEADER_LEN + len;
            if self.buffer.len() < expected {
                return Ok(None);
            }

            let (frame, consumed) = decode_frame(&self.buffer[..expected], self.max_payload_len)?;
            self.buffer.drain(..consumed);
            Ok(Some(frame))
        }
    }

    impl Frame {
        fn to_raw_parts(&self) -> (u8, Vec<u8>) {
            match self {
                Self::ServerKey { key, extra } => {
                    let mut payload = Vec::with_capacity(MAGIC.len() + KEY_LEN + extra.len());
                    payload.extend_from_slice(MAGIC);
                    payload.extend_from_slice(key);
                    payload.extend_from_slice(extra);
                    (FrameType::ServerKey.code(), payload)
                }
                Self::ClientInfo {
                    public_key,
                    encrypted_info,
                } => {
                    let mut payload = Vec::with_capacity(KEY_LEN + encrypted_info.len());
                    payload.extend_from_slice(public_key);
                    payload.extend_from_slice(encrypted_info);
                    (FrameType::ClientInfo.code(), payload)
                }
                Self::ServerInfo { encrypted_info } => {
                    (FrameType::ServerInfo.code(), encrypted_info.clone())
                }
                Self::SendPacket {
                    destination,
                    packet,
                } => {
                    let mut payload = Vec::with_capacity(KEY_LEN + packet.len());
                    payload.extend_from_slice(destination);
                    payload.extend_from_slice(packet);
                    (FrameType::SendPacket.code(), payload)
                }
                Self::ForwardPacket {
                    source,
                    destination,
                    packet,
                } => {
                    let mut payload = Vec::with_capacity(KEY_LEN * 2 + packet.len());
                    payload.extend_from_slice(source);
                    payload.extend_from_slice(destination);
                    payload.extend_from_slice(packet);
                    (FrameType::ForwardPacket.code(), payload)
                }
                Self::RecvPacket { source, packet } => {
                    let mut payload = Vec::with_capacity(KEY_LEN + packet.len());
                    payload.extend_from_slice(source);
                    payload.extend_from_slice(packet);
                    (FrameType::RecvPacket.code(), payload)
                }
                Self::KeepAlive => (FrameType::KeepAlive.code(), Vec::new()),
                Self::NotePreferred(preferred) => {
                    (FrameType::NotePreferred.code(), vec![u8::from(*preferred)])
                }
                Self::PeerGone { peer, reason } => {
                    let mut payload = Vec::with_capacity(KEY_LEN + 1);
                    payload.extend_from_slice(peer);
                    payload.push(reason.code());
                    (FrameType::PeerGone.code(), payload)
                }
                Self::PeerPresent {
                    peer,
                    endpoint,
                    flags,
                    extra,
                } => {
                    let mut payload = Vec::with_capacity(KEY_LEN + 18 + 1 + extra.len());
                    payload.extend_from_slice(peer);
                    if let Some(endpoint) = endpoint {
                        payload.extend_from_slice(&endpoint.ip);
                        payload.extend_from_slice(&endpoint.port.to_be_bytes());
                    }
                    if let Some(flags) = flags {
                        payload.push(flags.0);
                    }
                    payload.extend_from_slice(extra);
                    (FrameType::PeerPresent.code(), payload)
                }
                Self::WatchConns => (FrameType::WatchConns.code(), Vec::new()),
                Self::ClosePeer { peer } => (FrameType::ClosePeer.code(), peer.to_vec()),
                Self::Ping(payload) => (FrameType::Ping.code(), payload.to_vec()),
                Self::Pong(payload) => (FrameType::Pong.code(), payload.to_vec()),
                Self::Health(problem) => (FrameType::Health.code(), problem.as_bytes().to_vec()),
                Self::Restarting {
                    reconnect_in_ms,
                    try_for_ms,
                } => {
                    let mut payload = Vec::with_capacity(8);
                    payload.extend_from_slice(&reconnect_in_ms.to_be_bytes());
                    payload.extend_from_slice(&try_for_ms.to_be_bytes());
                    (FrameType::Restarting.code(), payload)
                }
                Self::Unknown {
                    frame_type,
                    payload,
                } => (*frame_type, payload.clone()),
            }
        }
    }

    fn parse_payload(frame_type: FrameType, payload: &[u8]) -> Result<Frame, ProtocolError> {
        match frame_type {
            FrameType::ServerKey => parse_server_key(payload),
            FrameType::ClientInfo => parse_client_info(payload),
            FrameType::ServerInfo => parse_server_info(payload),
            FrameType::SendPacket => parse_send_packet(payload),
            FrameType::RecvPacket => parse_recv_packet(payload),
            FrameType::KeepAlive => require_empty(frame_type, payload).map(|()| Frame::KeepAlive),
            FrameType::NotePreferred => parse_note_preferred(payload),
            FrameType::PeerGone => parse_peer_gone(payload),
            FrameType::PeerPresent => parse_peer_present(payload),
            FrameType::ForwardPacket => parse_forward_packet(payload),
            FrameType::WatchConns => require_empty(frame_type, payload).map(|()| Frame::WatchConns),
            FrameType::ClosePeer => parse_close_peer(payload),
            FrameType::Ping => parse_ping_or_pong(frame_type, payload).map(Frame::Ping),
            FrameType::Pong => parse_ping_or_pong(frame_type, payload).map(Frame::Pong),
            FrameType::Health => Ok(Frame::Health(String::from_utf8_lossy(payload).into_owned())),
            FrameType::Restarting => parse_restarting(payload),
        }
    }

    fn parse_server_key(payload: &[u8]) -> Result<Frame, ProtocolError> {
        if payload.len() < MAGIC.len() + KEY_LEN {
            return invalid(
                FrameType::ServerKey,
                "server greeting is shorter than magic plus key",
            );
        }
        if &payload[..MAGIC.len()] != MAGIC {
            return invalid(FrameType::ServerKey, "server greeting magic mismatch");
        }
        let (key, extra) = split_key(&payload[MAGIC.len()..], FrameType::ServerKey)?;
        Ok(Frame::ServerKey {
            key,
            extra: extra.to_vec(),
        })
    }

    fn parse_client_info(payload: &[u8]) -> Result<Frame, ProtocolError> {
        if payload.len() < KEY_LEN + NONCE_LEN {
            return invalid(
                FrameType::ClientInfo,
                "missing client key or encrypted info nonce",
            );
        }
        let (public_key, encrypted_info) = split_key(payload, FrameType::ClientInfo)?;
        if encrypted_info.len() > NONCE_LEN + MAX_CLIENT_INFO_LEN {
            return invalid(FrameType::ClientInfo, "encrypted client info is too large");
        }
        Ok(Frame::ClientInfo {
            public_key,
            encrypted_info: encrypted_info.to_vec(),
        })
    }

    fn parse_server_info(payload: &[u8]) -> Result<Frame, ProtocolError> {
        if payload.len() < NONCE_LEN {
            return invalid(FrameType::ServerInfo, "missing encrypted server info nonce");
        }
        if payload.len() > NONCE_LEN + MAX_INFO_LEN {
            return invalid(FrameType::ServerInfo, "encrypted server info is too large");
        }
        Ok(Frame::ServerInfo {
            encrypted_info: payload.to_vec(),
        })
    }

    fn parse_send_packet(payload: &[u8]) -> Result<Frame, ProtocolError> {
        let (destination, packet) = split_key(payload, FrameType::SendPacket)?;
        validate_packet_len(packet.len())?;
        Ok(Frame::SendPacket {
            destination,
            packet: packet.to_vec(),
        })
    }

    fn parse_forward_packet(payload: &[u8]) -> Result<Frame, ProtocolError> {
        let (source, rest) = split_key(payload, FrameType::ForwardPacket)?;
        let (destination, packet) = split_key(rest, FrameType::ForwardPacket)?;
        validate_packet_len(packet.len())?;
        Ok(Frame::ForwardPacket {
            source,
            destination,
            packet: packet.to_vec(),
        })
    }

    fn parse_recv_packet(payload: &[u8]) -> Result<Frame, ProtocolError> {
        let (source, packet) = split_key(payload, FrameType::RecvPacket)?;
        validate_packet_len(packet.len())?;
        Ok(Frame::RecvPacket {
            source,
            packet: packet.to_vec(),
        })
    }

    fn parse_note_preferred(payload: &[u8]) -> Result<Frame, ProtocolError> {
        if payload.len() != 1 {
            return invalid(FrameType::NotePreferred, "expected one boolean byte");
        }
        Ok(Frame::NotePreferred(payload[0] != 0))
    }

    fn parse_peer_gone(payload: &[u8]) -> Result<Frame, ProtocolError> {
        let (peer, rest) = split_key(payload, FrameType::PeerGone)?;
        let reason = rest
            .first()
            .copied()
            .map_or(PeerGoneReason::Disconnected, PeerGoneReason::from_code);
        Ok(Frame::PeerGone { peer, reason })
    }

    fn parse_peer_present(payload: &[u8]) -> Result<Frame, ProtocolError> {
        let (peer, rest) = split_key(payload, FrameType::PeerPresent)?;
        let endpoint = if rest.len() >= 18 {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&rest[..16]);
            Some(PeerEndpoint {
                ip,
                port: u16::from_be_bytes([rest[16], rest[17]]),
            })
        } else {
            None
        };
        let flags = (rest.len() >= 19).then(|| PeerPresentFlags(rest[18]));
        let extra_start = if flags.is_some() {
            19
        } else if endpoint.is_some() {
            18
        } else {
            0
        };
        Ok(Frame::PeerPresent {
            peer,
            endpoint,
            flags,
            extra: rest[extra_start..].to_vec(),
        })
    }

    fn parse_close_peer(payload: &[u8]) -> Result<Frame, ProtocolError> {
        let (peer, _) = split_key(payload, FrameType::ClosePeer)?;
        Ok(Frame::ClosePeer { peer })
    }

    fn parse_ping_or_pong(frame_type: FrameType, payload: &[u8]) -> Result<[u8; 8], ProtocolError> {
        if payload.len() < 8 {
            return invalid(frame_type, "expected at least eight payload bytes");
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&payload[..8]);
        Ok(out)
    }

    fn parse_restarting(payload: &[u8]) -> Result<Frame, ProtocolError> {
        if payload.len() < 8 {
            return invalid(
                FrameType::Restarting,
                "expected two u32 millisecond durations",
            );
        }
        Ok(Frame::Restarting {
            reconnect_in_ms: u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]),
            try_for_ms: u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]),
        })
    }

    fn require_empty(frame_type: FrameType, payload: &[u8]) -> Result<(), ProtocolError> {
        if payload.is_empty() {
            Ok(())
        } else {
            invalid(frame_type, "expected empty payload")
        }
    }

    fn validate_frame_for_encode(frame: &Frame) -> Result<(), ProtocolError> {
        match frame {
            Frame::SendPacket { packet, .. }
            | Frame::ForwardPacket { packet, .. }
            | Frame::RecvPacket { packet, .. } => validate_packet_len(packet.len()),
            Frame::ClientInfo { encrypted_info, .. }
                if encrypted_info.len() > NONCE_LEN + MAX_CLIENT_INFO_LEN =>
            {
                invalid(FrameType::ClientInfo, "encrypted client info is too large")
            }
            Frame::ServerInfo { encrypted_info }
                if encrypted_info.len() > NONCE_LEN + MAX_INFO_LEN =>
            {
                invalid(FrameType::ServerInfo, "encrypted server info is too large")
            }
            _ => Ok(()),
        }
    }

    fn validate_packet_len(len: usize) -> Result<(), ProtocolError> {
        if len <= MAX_PACKET_SIZE {
            Ok(())
        } else {
            Err(ProtocolError::PacketTooLarge {
                len,
                max: MAX_PACKET_SIZE,
            })
        }
    }

    fn split_key(
        payload: &[u8],
        frame_type: FrameType,
    ) -> Result<([u8; KEY_LEN], &[u8]), ProtocolError> {
        if payload.len() < KEY_LEN {
            return invalid(frame_type, "payload is shorter than a DERP key");
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&payload[..KEY_LEN]);
        Ok((key, &payload[KEY_LEN..]))
    }

    fn invalid<T>(frame_type: FrameType, reason: &'static str) -> Result<T, ProtocolError> {
        Err(ProtocolError::InvalidPayload { frame_type, reason })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn header_uses_big_endian_payload_length() {
            assert_eq!(
                encode_header(FrameType::Ping.code(), 0x0102_0304),
                [0x12, 0x01, 0x02, 0x03, 0x04]
            );
            assert_eq!(
                encode_header(FrameType::Health.code(), 5),
                [0x14, 0, 0, 0, 5]
            );
            assert_eq!(
                encode_header(FrameType::PeerPresent.code(), 51),
                [0x09, 0, 0, 0, 0x33]
            );
        }

        #[test]
        fn server_key_greeting_round_trips_magic_key_and_future_bytes() {
            let mut key = [0u8; KEY_LEN];
            for (i, byte) in key.iter_mut().enumerate() {
                *byte = i as u8;
            }
            let frame = Frame::ServerKey {
                key,
                extra: vec![0xff],
            };
            let encoded = encode_frame(&frame).unwrap();
            assert_eq!(
                &encoded[..FRAME_HEADER_LEN],
                &[FrameType::ServerKey.code(), 0, 0, 0, 41]
            );
            assert_eq!(
                &encoded[FRAME_HEADER_LEN..FRAME_HEADER_LEN + MAGIC.len()],
                MAGIC
            );
            assert_eq!(
                &encoded[FRAME_HEADER_LEN + MAGIC.len()..FRAME_HEADER_LEN + MAGIC.len() + KEY_LEN],
                &key
            );

            let (decoded, consumed) = decode_frame(&encoded, MAX_INFO_LEN).unwrap();
            assert_eq!(consumed, encoded.len());
            assert_eq!(decoded, frame);
        }

        #[test]
        fn client_info_requires_public_key_and_encrypted_nonce() {
            let mut payload = vec![4u8; KEY_LEN + NONCE_LEN];
            payload.extend_from_slice(b"encrypted-json");
            let encoded = encode_raw_frame(FrameType::ClientInfo.code(), &payload).unwrap();

            let (decoded, _) = decode_frame(&encoded, MAX_INFO_LEN).unwrap();
            assert_eq!(
                decoded,
                Frame::ClientInfo {
                    public_key: [4u8; KEY_LEN],
                    encrypted_info: payload[KEY_LEN..].to_vec(),
                }
            );

            let short = encode_raw_frame(FrameType::ClientInfo.code(), &[0u8; KEY_LEN]).unwrap();
            assert!(matches!(
                decode_frame(&short, MAX_INFO_LEN),
                Err(ProtocolError::InvalidPayload {
                    frame_type: FrameType::ClientInfo,
                    ..
                })
            ));

            let too_large = Frame::ClientInfo {
                public_key: [1u8; KEY_LEN],
                encrypted_info: vec![0u8; NONCE_LEN + MAX_CLIENT_INFO_LEN + 1],
            };
            assert!(matches!(
                encode_frame(&too_large),
                Err(ProtocolError::InvalidPayload {
                    frame_type: FrameType::ClientInfo,
                    ..
                })
            ));
        }

        #[test]
        fn go_client_recv_vectors_decode() {
            for (frame, expected) in [
                (
                    vec![FrameType::Ping.code(), 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8],
                    Frame::Ping([1, 2, 3, 4, 5, 6, 7, 8]),
                ),
                (
                    vec![FrameType::Pong.code(), 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8],
                    Frame::Pong([1, 2, 3, 4, 5, 6, 7, 8]),
                ),
                (
                    vec![FrameType::Health.code(), 0, 0, 0, 3, b'B', b'A', b'D'],
                    Frame::Health("BAD".to_string()),
                ),
                (
                    vec![FrameType::Health.code(), 0, 0, 0, 0],
                    Frame::Health(String::new()),
                ),
                (
                    vec![
                        FrameType::Restarting.code(),
                        0,
                        0,
                        0,
                        8,
                        0,
                        0,
                        0,
                        1,
                        0,
                        0,
                        0,
                        2,
                    ],
                    Frame::Restarting {
                        reconnect_in_ms: 1,
                        try_for_ms: 2,
                    },
                ),
            ] {
                let (decoded, consumed) = decode_frame(&frame, MAX_INFO_LEN).unwrap();
                assert_eq!(consumed, frame.len());
                assert_eq!(decoded, expected);
            }
        }

        #[test]
        fn packet_frame_shapes_round_trip() {
            let source = [1u8; KEY_LEN];
            let destination = [2u8; KEY_LEN];
            let packet = b"wireguard-packet".to_vec();

            let send = Frame::SendPacket {
                destination,
                packet: packet.clone(),
            };
            let (decoded, _) =
                decode_frame(&encode_frame(&send).unwrap(), MAX_PACKET_SIZE).unwrap();
            assert_eq!(decoded, send);

            let recv = Frame::RecvPacket {
                source,
                packet: packet.clone(),
            };
            let (decoded, _) =
                decode_frame(&encode_frame(&recv).unwrap(), MAX_PACKET_SIZE).unwrap();
            assert_eq!(decoded, recv);

            let forward = Frame::ForwardPacket {
                source,
                destination,
                packet,
            };
            let (decoded, _) =
                decode_frame(&encode_frame(&forward).unwrap(), MAX_PACKET_SIZE).unwrap();
            assert_eq!(decoded, forward);

            let oversized = Frame::SendPacket {
                destination,
                packet: vec![0; MAX_PACKET_SIZE + 1],
            };
            assert!(matches!(
                encode_frame(&oversized),
                Err(ProtocolError::PacketTooLarge {
                    len,
                    max: MAX_PACKET_SIZE,
                }) if len == MAX_PACKET_SIZE + 1
            ));

            let mut raw_oversized = Vec::with_capacity(KEY_LEN + MAX_PACKET_SIZE + 1);
            raw_oversized.extend_from_slice(&destination);
            raw_oversized.extend_from_slice(&vec![0; MAX_PACKET_SIZE + 1]);
            let encoded = encode_raw_frame(FrameType::SendPacket.code(), &raw_oversized).unwrap();
            assert!(matches!(
                decode_frame(&encoded, KEY_LEN + MAX_PACKET_SIZE + 1),
                Err(ProtocolError::PacketTooLarge {
                    len,
                    max: MAX_PACKET_SIZE,
                }) if len == MAX_PACKET_SIZE + 1
            ));
        }

        #[test]
        fn peer_state_frames_parse_legacy_and_modern_shapes() {
            let peer = [9u8; KEY_LEN];
            let gone_legacy = encode_raw_frame(FrameType::PeerGone.code(), &peer).unwrap();
            assert_eq!(
                decode_frame(&gone_legacy, MAX_INFO_LEN).unwrap().0,
                Frame::PeerGone {
                    peer,
                    reason: PeerGoneReason::Disconnected,
                }
            );

            let mut modern_present_payload = Vec::new();
            modern_present_payload.extend_from_slice(&peer);
            modern_present_payload.extend_from_slice(&[0; 15]);
            modern_present_payload.push(1);
            modern_present_payload.extend_from_slice(&443u16.to_be_bytes());
            modern_present_payload.push(PeerPresentFlags::IS_REGULAR);
            modern_present_payload.extend_from_slice(&[0xaa, 0xbb]);
            let modern_present =
                encode_raw_frame(FrameType::PeerPresent.code(), &modern_present_payload).unwrap();

            assert_eq!(
                decode_frame(&modern_present, MAX_INFO_LEN).unwrap().0,
                Frame::PeerPresent {
                    peer,
                    endpoint: Some(PeerEndpoint {
                        ip: {
                            let mut ip = [0u8; 16];
                            ip[15] = 1;
                            ip
                        },
                        port: 443,
                    }),
                    flags: Some(PeerPresentFlags(PeerPresentFlags::IS_REGULAR)),
                    extra: vec![0xaa, 0xbb],
                }
            );
        }

        #[test]
        fn incomplete_and_oversized_frames_are_errors() {
            assert!(matches!(
                decode_frame(&[FrameType::Ping.code(), 0], MAX_INFO_LEN),
                Err(ProtocolError::TruncatedHeader { actual: 2 })
            ));
            assert!(matches!(
                decode_frame(&[FrameType::Ping.code(), 0, 0, 0, 8, 1, 2], MAX_INFO_LEN),
                Err(ProtocolError::IncompleteFrame {
                    expected: 13,
                    actual: 7
                })
            ));
            assert!(matches!(
                decode_frame(&[FrameType::Ping.code(), 0, 0, 0, 9], 8),
                Err(ProtocolError::FrameTooLarge { len: 9, max: 8 })
            ));
        }

        #[test]
        fn unknown_frame_preserves_payload_for_future_compatibility() {
            let encoded = encode_raw_frame(0xfe, b"future").unwrap();
            assert_eq!(
                decode_frame(&encoded, MAX_INFO_LEN).unwrap().0,
                Frame::Unknown {
                    frame_type: 0xfe,
                    payload: b"future".to_vec(),
                }
            );
        }

        #[test]
        fn stream_decoder_handles_split_and_coalesced_frames() {
            let ping = encode_frame(&Frame::Ping([0, 1, 2, 3, 4, 5, 6, 7])).unwrap();
            let health = encode_frame(&Frame::Health("ERR".to_string())).unwrap();
            let mut decoder = FrameDecoder::new(MAX_INFO_LEN);

            decoder.push(&ping[..2]);
            assert_eq!(decoder.next_frame().unwrap(), None);
            assert_eq!(decoder.buffered_len(), 2);

            decoder.push(&ping[2..7]);
            assert_eq!(decoder.next_frame().unwrap(), None);

            decoder.push(&ping[7..]);
            assert_eq!(
                decoder.next_frame().unwrap(),
                Some(Frame::Ping([0, 1, 2, 3, 4, 5, 6, 7]))
            );
            assert_eq!(decoder.next_frame().unwrap(), None);

            let mut coalesced = Vec::new();
            coalesced.extend_from_slice(&ping);
            coalesced.extend_from_slice(&health);
            decoder.push(&coalesced);
            assert_eq!(
                decoder.next_frame().unwrap(),
                Some(Frame::Ping([0, 1, 2, 3, 4, 5, 6, 7]))
            );
            assert_eq!(
                decoder.next_frame().unwrap(),
                Some(Frame::Health("ERR".to_string()))
            );
            assert_eq!(decoder.buffered_len(), 0);
        }

        #[test]
        fn stream_decoder_rejects_oversized_header_before_payload() {
            let mut decoder = FrameDecoder::new(8);
            decoder.push(&[FrameType::Health.code(), 0, 0, 0, 9]);

            assert!(matches!(
                decoder.next_frame(),
                Err(ProtocolError::FrameTooLarge { len: 9, max: 8 })
            ));
        }
    }
}

/// A DERP server entry.
#[derive(Debug, Clone)]
pub struct DerpServer {
    /// Server name/ID.
    pub name: String,
    /// Server hostname.
    pub hostname: String,
    /// Server address.
    pub addr: SocketAddr,
    /// Region code (e.g., "us-east", "eu-west").
    pub region: String,
    /// Whether STUN is available on this server.
    pub stun_enabled: bool,
}

/// DERP connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerpState {
    /// Not connected.
    Disconnected,
    /// Connecting to server.
    Connecting,
    /// Connected and authenticated.
    Connected,
    /// Connection failed.
    Failed,
}

/// Events from the DERP client.
#[derive(Debug, Clone)]
pub enum DerpEvent {
    /// Connected to a DERP server.
    Connected { server: String },
    /// Disconnected from a DERP server.
    Disconnected { server: String, reason: String },
    /// Received a packet from a peer via DERP.
    PacketReceived { peer_key: [u8; 32], data: Vec<u8> },
    /// A peer is now reachable via this DERP server.
    PeerPresent { peer_key: [u8; 32] },
    /// A peer is no longer reachable via this DERP server.
    PeerGone { peer_key: [u8; 32] },
}

/// DERP client for relay connections.
pub struct DerpClient {
    /// Our WireGuard public key.
    local_key: [u8; 32],
    /// Available DERP servers.
    servers: Vec<DerpServer>,
    /// Active connections by server name.
    connections: RwLock<HashMap<String, DerpConnection>>,
    /// Event sender.
    event_tx: broadcast::Sender<DerpEvent>,
    /// Preferred server (closest/lowest latency).
    preferred_server: RwLock<Option<String>>,
}

/// An active connection to a DERP server.
struct DerpConnection {
    /// Server name.
    _server_name: String,
    /// Connection state.
    state: DerpState,
    /// Channel to send packets.
    tx: mpsc::Sender<DerpFrame>,
    /// Server's public key.
    _server_key: Option<[u8; 32]>,
    /// Last activity time.
    _last_activity: Instant,
}

/// A DERP frame to send.
#[derive(Debug)]
enum DerpFrame {
    /// Send a packet to a peer.
    Send { peer_key: [u8; 32], data: Vec<u8> },
}

impl DerpClient {
    /// Create a new DERP client.
    pub fn new(local_key: [u8; 32], servers: Vec<DerpServer>) -> Self {
        let (event_tx, _) = broadcast::channel(256);

        Self {
            local_key,
            servers,
            connections: RwLock::new(HashMap::new()),
            event_tx,
            preferred_server: RwLock::new(None),
        }
    }

    /// Subscribe to DERP events.
    pub fn subscribe(&self) -> broadcast::Receiver<DerpEvent> {
        self.event_tx.subscribe()
    }

    /// Get available servers.
    pub fn servers(&self) -> &[DerpServer] {
        &self.servers
    }

    /// Get the preferred server.
    pub async fn preferred_server(&self) -> Option<String> {
        self.preferred_server.read().await.clone()
    }

    /// Connect to a DERP server.
    pub async fn connect(&self, server_name: &str) -> Result<(), DerpError> {
        let server = self
            .servers
            .iter()
            .find(|s| s.name == server_name)
            .ok_or_else(|| DerpError::ServerNotFound(server_name.to_string()))?
            .clone();

        // Check if already connected
        {
            let connections = self.connections.read().await;
            if let Some(conn) = connections.get(server_name)
                && conn.state == DerpState::Connected
            {
                return Ok(());
            }
        }

        tracing::info!(server = %server_name, addr = %server.addr, "Connecting to DERP server");

        // Connect to the server
        let stream = TcpStream::connect(server.addr).await?;

        // Create channels for communication
        let (tx, rx) = mpsc::channel(256);

        // Store the connection
        {
            let mut connections = self.connections.write().await;
            connections.insert(
                server_name.to_string(),
                DerpConnection {
                    _server_name: server_name.to_string(),
                    state: DerpState::Connecting,
                    tx,
                    _server_key: None,
                    _last_activity: Instant::now(),
                },
            );
        }

        // Spawn connection handler
        let local_key = self.local_key;
        let event_tx = self.event_tx.clone();
        let server_name_owned = server_name.to_string();

        tokio::spawn(async move {
            // Box::pin to keep the spawned future's stack footprint small —
            // `handle_derp_connection` has a 64 KiB packet buffer + per-stream
            // rustls state, so dropping it on the stack triggers
            // `clippy::large_futures` and risks stack overflow under deep tasks.
            if let Err(e) = Box::pin(handle_derp_connection(
                stream,
                local_key,
                rx,
                event_tx.clone(),
            ))
            .await
            {
                tracing::warn!(server = %server_name_owned, error = %e, "DERP connection failed");
                let _ = event_tx.send(DerpEvent::Disconnected {
                    server: server_name_owned,
                    reason: e.to_string(),
                });
            }
        });

        // Update preferred server if this is first connection
        {
            let mut preferred = self.preferred_server.write().await;
            if preferred.is_none() {
                *preferred = Some(server_name.to_string());
            }
        }

        Ok(())
    }

    /// Disconnect from a DERP server.
    pub async fn disconnect(&self, server_name: &str) -> Result<(), DerpError> {
        let mut connections = self.connections.write().await;
        if connections.remove(server_name).is_some() {
            tracing::info!(server = %server_name, "Disconnected from DERP server");
            let _ = self.event_tx.send(DerpEvent::Disconnected {
                server: server_name.to_string(),
                reason: "User requested".to_string(),
            });
        }
        Ok(())
    }

    /// Send a packet to a peer via DERP relay.
    pub async fn send_to_peer(&self, peer_key: &[u8; 32], data: &[u8]) -> Result<(), DerpError> {
        // Find a connected server
        let connections = self.connections.read().await;

        // Try preferred server first
        let preferred = self.preferred_server.read().await;
        let server_name = preferred.as_ref().and_then(|name| {
            connections
                .get(name)
                .filter(|c| c.state == DerpState::Connected)
                .map(|_| name.clone())
        });

        // Or find any connected server
        let server_name = server_name.or_else(|| {
            connections
                .iter()
                .find(|(_, c)| c.state == DerpState::Connected)
                .map(|(name, _)| name.clone())
        });

        let server_name = server_name.ok_or(DerpError::NotConnected)?;
        let conn = connections
            .get(&server_name)
            .ok_or(DerpError::NotConnected)?;

        conn.tx
            .send(DerpFrame::Send {
                peer_key: *peer_key,
                data: data.to_vec(),
            })
            .await
            .map_err(|_| DerpError::SendFailed)?;

        Ok(())
    }

    /// Get connection state for a server.
    pub async fn connection_state(&self, server_name: &str) -> DerpState {
        let connections = self.connections.read().await;
        connections
            .get(server_name)
            .map_or(DerpState::Disconnected, |c| c.state)
    }

    /// Get all connected servers.
    pub async fn connected_servers(&self) -> Vec<String> {
        let connections = self.connections.read().await;
        connections
            .iter()
            .filter(|(_, c)| c.state == DerpState::Connected)
            .map(|(name, _)| name.clone())
            .collect()
    }
}

/// Handle a DERP connection.
async fn handle_derp_connection(
    mut stream: TcpStream,
    local_key: [u8; 32],
    mut rx: mpsc::Receiver<DerpFrame>,
    event_tx: broadcast::Sender<DerpEvent>,
) -> Result<(), DerpError> {
    // Send client info
    send_client_info(&mut stream, &local_key).await?;

    // Wait for server key
    let _server_key = recv_server_key(&mut stream).await?;

    // Connection established
    let _ = event_tx.send(DerpEvent::Connected {
        server: "unknown".to_string(),
    });

    // Main loop. 64 KiB stack buffer for one DERP frame — protocol-mandated
    // upper bound, allocated once per connection. clippy::large_stack_arrays
    // warns at 16 KiB; this lives inside an `async fn` already pinned via
    // `Box::pin` at the call site, so the stack pressure is bounded.
    #[allow(clippy::large_stack_arrays)]
    let mut buf = [0u8; 65536];
    let mut keepalive_interval = tokio::time::interval(Duration::from_secs(60));

    loop {
        tokio::select! {
            // Handle incoming frames
            result = stream.read(&mut buf) => {
                let n = result?;
                if n == 0 {
                    return Err(DerpError::ConnectionClosed);
                }

                if let Some(event) = parse_derp_frame(&buf[..n]) {
                    let _ = event_tx.send(event);
                }
            }

            // Handle outgoing frames
            Some(frame) = rx.recv() => {
                match frame {
                    DerpFrame::Send { peer_key, data } => {
                        send_packet(&mut stream, &peer_key, &data).await?;
                    }
                }
            }

            // Send keepalives
            _ = keepalive_interval.tick() => {
                send_keepalive(&mut stream).await?;
            }
        }
    }
}

/// Send client info frame.
async fn send_client_info(stream: &mut TcpStream, key: &[u8; 32]) -> Result<(), DerpError> {
    let mut frame = Vec::with_capacity(37);
    frame.push(FRAME_CLIENT_INFO);
    frame.extend_from_slice(&32u32.to_be_bytes());
    frame.extend_from_slice(key);

    stream.write_all(&frame).await?;
    Ok(())
}

/// Receive server key frame.
async fn recv_server_key(stream: &mut TcpStream) -> Result<[u8; 32], DerpError> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;

    if header[0] != FRAME_SERVER_KEY {
        return Err(DerpError::Protocol(format!(
            "Expected server key, got frame type {}",
            header[0]
        )));
    }

    let len = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len != 32 {
        return Err(DerpError::Protocol(format!(
            "Invalid server key length: {len}"
        )));
    }

    let mut key = [0u8; 32];
    stream.read_exact(&mut key).await?;

    Ok(key)
}

/// Send a packet to a peer.
async fn send_packet(
    stream: &mut TcpStream,
    peer_key: &[u8; 32],
    data: &[u8],
) -> Result<(), DerpError> {
    let len = (32 + data.len()) as u32;
    let mut frame = Vec::with_capacity(5 + 32 + data.len());
    frame.push(FRAME_SEND_PACKET);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(peer_key);
    frame.extend_from_slice(data);

    stream.write_all(&frame).await?;
    Ok(())
}

/// Send a keepalive frame.
async fn send_keepalive(stream: &mut TcpStream) -> Result<(), DerpError> {
    let frame = [FRAME_KEEP_ALIVE, 0, 0, 0, 0];
    stream.write_all(&frame).await?;
    Ok(())
}

/// Parse a DERP frame into an event.
/// Exposed as pub for fuzzing.
pub fn parse_derp_frame(data: &[u8]) -> Option<DerpEvent> {
    if data.len() < 5 {
        return None;
    }

    let frame_type = data[0];
    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;

    if data.len() < 5 + len {
        return None;
    }

    let payload = &data[5..5 + len];

    match frame_type {
        FRAME_RECV_PACKET if payload.len() >= 32 => {
            let mut peer_key = [0u8; 32];
            peer_key.copy_from_slice(&payload[..32]);
            let data = payload[32..].to_vec();
            Some(DerpEvent::PacketReceived { peer_key, data })
        }
        FRAME_PEER_PRESENT if payload.len() >= 32 => {
            let mut peer_key = [0u8; 32];
            peer_key.copy_from_slice(&payload[..32]);
            Some(DerpEvent::PeerPresent { peer_key })
        }
        FRAME_PEER_GONE if payload.len() >= 32 => {
            let mut peer_key = [0u8; 32];
            peer_key.copy_from_slice(&payload[..32]);
            Some(DerpEvent::PeerGone { peer_key })
        }
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DerpError {
    #[error("Server not found: {0}")]
    ServerNotFound(String),

    #[error("Not connected to any DERP server")]
    NotConnected,

    #[error("Failed to send packet")]
    SendFailed,

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Embedded DERP/STUN runtime.
///
/// The Rust runtime owns the lightweight STUN responder. DERP relay traffic is
/// delegated to the upstream `derper` binary because DERP's relay protocol has
/// no maintained Rust implementation in this repository.
pub struct EmbeddedDerpRuntime {
    cfg: EmbeddedDerpConfig,
    stun: Option<StunListener>,
    sidecar: Option<DerperSidecar>,
}

impl EmbeddedDerpRuntime {
    /// Start with a config whose `derper_config_path` is already resolved.
    pub async fn start(cfg: EmbeddedDerpConfig) -> Result<Self, EmbeddedDerpError> {
        validate_embedded_derp_config(&cfg)?;

        if !cfg.enabled {
            return Ok(Self {
                cfg,
                stun: None,
                sidecar: None,
            });
        }

        let stun = match cfg.stun_addr {
            Some(addr) => Some(StunListener::bind(addr).await?),
            None => None,
        };
        let sidecar = if cfg.relay_enabled() {
            Some(DerperSidecar::spawn(&cfg)?)
        } else {
            None
        };

        Ok(Self { cfg, stun, sidecar })
    }

    /// Resolve the `derper -c` config path under `state_dir` before starting.
    pub async fn start_with_state_dir(
        cfg: EmbeddedDerpConfig,
        state_dir: impl AsRef<Path>,
    ) -> Result<Self, EmbeddedDerpError> {
        Self::start(cfg.with_default_derper_config_path(state_dir.as_ref())).await
    }

    /// Runtime config after default path resolution.
    pub fn config(&self) -> &EmbeddedDerpConfig {
        &self.cfg
    }

    /// Local STUN bind address when the embedded STUN listener is active.
    pub fn stun_local_addr(&self) -> Option<SocketAddr> {
        self.stun.as_ref().and_then(|stun| stun.local_addr().ok())
    }

    /// Sidecar process status when a DERP relay sidecar was started.
    pub fn sidecar_status(&self) -> Option<SidecarStatus> {
        self.sidecar.as_ref().map(DerperSidecar::status)
    }
}

fn validate_embedded_derp_config(cfg: &EmbeddedDerpConfig) -> Result<(), EmbeddedDerpError> {
    if !cfg.enabled {
        return Ok(());
    }
    if cfg.host_name.trim().is_empty() {
        return Err(EmbeddedDerpError::MissingHostName);
    }
    if cfg.stun_addr.is_none() {
        return Err(EmbeddedDerpError::MissingStunAddress);
    }
    if cfg.relay_enabled() {
        if cfg.derper_binary.as_os_str().is_empty() {
            return Err(EmbeddedDerpError::MissingDerperBinary(PathBuf::new()));
        }
        if !cfg.derper_binary.is_file() {
            return Err(EmbeddedDerpError::MissingDerperBinary(
                cfg.derper_binary.clone(),
            ));
        }
        if cfg.derper_config_path.as_os_str().is_empty() {
            return Err(EmbeddedDerpError::MissingDerperConfigPath);
        }
    }
    Ok(())
}

/// Embedded DERP runtime errors.
#[derive(Debug, thiserror::Error)]
pub enum EmbeddedDerpError {
    #[error("embedded DERP host_name is required when enabled")]
    MissingHostName,

    #[error("embedded DERP stun_addr is required when enabled")]
    MissingStunAddress,

    #[error("embedded DERP derper_binary is missing or not a file: {0:?}")]
    MissingDerperBinary(PathBuf),

    #[error("embedded DERP derper_config_path is required when the relay sidecar is enabled")]
    MissingDerperConfigPath,

    #[error("embedded DERP/STUN I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Current status of the upstream `derper` sidecar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidecarStatus {
    Running { pid: u32 },
    Exited { code: Option<i32> },
    NotStarted,
}

/// `derper` subprocess lifecycle.
pub struct DerperSidecar {
    child: Arc<Mutex<Option<std::process::Child>>>,
    status: Arc<Mutex<SidecarStatus>>,
}

impl DerperSidecar {
    /// Spawn the configured upstream `derper` binary.
    pub fn spawn(cfg: &EmbeddedDerpConfig) -> Result<Self, EmbeddedDerpError> {
        validate_embedded_derp_config(cfg)?;

        let mut command = Command::new(&cfg.derper_binary);
        command
            .arg("-a")
            .arg(cfg.derper_listen_addr.to_string())
            .arg("-hostname")
            .arg(&cfg.host_name)
            .arg("-stun=false")
            .arg("-http-port=-1")
            .arg("-c")
            .arg(&cfg.derper_config_path)
            .arg("-certmode")
            .arg(&cfg.derper_cert_mode)
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        if let Some(cert_dir) = &cfg.derper_cert_dir {
            command.arg("-certdir").arg(cert_dir);
        }
        if cfg.verify_clients {
            command.arg("-verify-clients");
        }
        if let Some(url) = &cfg.verify_client_url {
            command
                .arg("-verify-client-url")
                .arg(url)
                .arg("-verify-client-url-fail-open=false");
        }

        let child = command.spawn()?;
        let pid = child.id();
        let child = Arc::new(Mutex::new(Some(child)));
        let status = Arc::new(Mutex::new(SidecarStatus::Running { pid }));

        watch_sidecar(Arc::clone(&child), Arc::clone(&status));

        Ok(Self { child, status })
    }

    /// Return the latest observed process status.
    pub fn status(&self) -> SidecarStatus {
        lock_or_recover(&self.status).clone()
    }

    /// Stop the sidecar process. Idempotent.
    pub fn terminate(&self) {
        let mut guard = lock_or_recover(&self.child);
        let Some(child) = guard.as_mut() else {
            return;
        };
        let _ = child.kill();
        let _ = child.wait();
        *guard = None;
        *lock_or_recover(&self.status) = SidecarStatus::NotStarted;
    }
}

impl Drop for DerperSidecar {
    fn drop(&mut self) {
        self.terminate();
    }
}

fn watch_sidecar(
    child: Arc<Mutex<Option<std::process::Child>>>,
    status: Arc<Mutex<SidecarStatus>>,
) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            let exit_code = {
                let mut guard = lock_or_recover(&child);
                let Some(child) = guard.as_mut() else {
                    return;
                };
                match child.try_wait() {
                    Ok(Some(exit)) => {
                        *guard = None;
                        Some(exit.code())
                    }
                    Ok(None) => None,
                    Err(err) => {
                        tracing::warn!(error = %err, "derper sidecar try_wait failed");
                        None
                    }
                }
            };

            if let Some(code) = exit_code {
                *lock_or_recover(&status) = SidecarStatus::Exited { code };
                return;
            }
        }
    });
}

fn lock_or_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_recv_packet() {
        let peer_key = [42u8; 32];
        let packet_data = b"hello";

        let mut frame = Vec::new();
        frame.push(FRAME_RECV_PACKET);
        frame.extend_from_slice(&((32 + 5) as u32).to_be_bytes());
        frame.extend_from_slice(&peer_key);
        frame.extend_from_slice(packet_data);

        let event = parse_derp_frame(&frame).unwrap();
        match event {
            DerpEvent::PacketReceived { peer_key: pk, data } => {
                assert_eq!(pk, peer_key);
                assert_eq!(data, packet_data);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_parse_peer_present() {
        let peer_key = [99u8; 32];

        let mut frame = Vec::new();
        frame.push(FRAME_PEER_PRESENT);
        frame.extend_from_slice(&32u32.to_be_bytes());
        frame.extend_from_slice(&peer_key);

        let event = parse_derp_frame(&frame).unwrap();
        match event {
            DerpEvent::PeerPresent { peer_key: pk } => {
                assert_eq!(pk, peer_key);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_derp_server() {
        let server = DerpServer {
            name: "nyc1".to_string(),
            hostname: "derp1.example.com".to_string(),
            addr: "1.2.3.4:443".parse().unwrap(),
            region: "us-east".to_string(),
            stun_enabled: true,
        };

        assert_eq!(server.name, "nyc1");
        assert!(server.stun_enabled);
    }

    #[tokio::test]
    async fn embedded_runtime_disabled_starts_no_listeners() {
        let runtime = EmbeddedDerpRuntime::start(EmbeddedDerpConfig::default())
            .await
            .unwrap();

        assert!(runtime.stun_local_addr().is_none());
        assert!(runtime.sidecar_status().is_none());
    }

    #[tokio::test]
    async fn embedded_runtime_stun_only_binds_udp_listener() {
        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "derp.local".to_string(),
            stun_addr: Some("127.0.0.1:0".parse().unwrap()),
            stun_only: true,
            ..EmbeddedDerpConfig::default()
        };

        let runtime = EmbeddedDerpRuntime::start(cfg).await.unwrap();
        let addr = runtime.stun_local_addr().unwrap();

        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0);
        assert!(runtime.sidecar_status().is_none());
    }

    #[tokio::test]
    async fn embedded_runtime_requires_derper_binary_for_relay() {
        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "derp.local".to_string(),
            stun_addr: Some("127.0.0.1:0".parse().unwrap()),
            derper_config_path: "/tmp/headscale-rs-test-derper.key".into(),
            ..EmbeddedDerpConfig::default()
        };

        let result = EmbeddedDerpRuntime::start(cfg).await;

        assert!(matches!(
            result,
            Err(EmbeddedDerpError::MissingDerperBinary(_))
        ));
    }

    #[tokio::test]
    async fn embedded_runtime_requires_stun_addr_when_enabled() {
        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "derp.local".to_string(),
            ..EmbeddedDerpConfig::default()
        };

        let result = EmbeddedDerpRuntime::start(cfg).await;

        assert!(matches!(result, Err(EmbeddedDerpError::MissingStunAddress)));
    }

    #[test]
    fn embedded_derp_config_resolves_default_sidecar_config_path() {
        let cfg = EmbeddedDerpConfig::default()
            .with_default_derper_config_path(std::path::Path::new("/var/lib/headscale"));

        assert_eq!(
            cfg.derper_config_path,
            std::path::PathBuf::from("/var/lib/headscale/derper.key")
        );
    }

    #[tokio::test]
    async fn sidecar_verify_url_is_fail_closed_for_admission_tests() {
        use std::io::Write;

        let unique = format!(
            "headscale-rs-derper-args-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).unwrap();
        let args_file = dir.join("args.txt");
        let fake_derper = dir.join("derper-fake.sh");
        let escaped_args_file = args_file.display().to_string().replace('\'', "'\\''");
        let mut file = std::fs::File::create(&fake_derper).unwrap();
        writeln!(
            file,
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\nsleep 30\n",
            escaped_args_file
        )
        .unwrap();
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&fake_derper).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&fake_derper, perms).unwrap();
        }

        let cfg = EmbeddedDerpConfig {
            enabled: true,
            host_name: "derp.local".to_string(),
            stun_addr: Some("127.0.0.1:0".parse().unwrap()),
            derper_binary: fake_derper,
            derper_listen_addr: "127.0.0.1:0".parse().unwrap(),
            derper_config_path: dir.join("derper.key"),
            derper_cert_mode: "manual".to_string(),
            verify_client_url: Some("http://127.0.0.1:51821/verify".to_string()),
            ..EmbeddedDerpConfig::default()
        };

        let sidecar = DerperSidecar::spawn(&cfg).unwrap();
        let mut args = String::new();
        for _ in 0..20 {
            if let Ok(raw) = std::fs::read_to_string(&args_file)
                && raw.contains("-verify-client-url-fail-open=false")
            {
                args = raw;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        sidecar.terminate();
        let _ = std::fs::remove_dir_all(&dir);

        assert!(args.contains("-verify-client-url\n"));
        assert!(args.contains("http://127.0.0.1:51821/verify\n"));
        assert!(args.contains("-verify-client-url-fail-open=false\n"));
    }
}
