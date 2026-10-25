//! Minimal hand-rolled HTTP/2 framing used to talk to the patched `h2` crate
//! without going through any other implementation of the protocol.

#![allow(dead_code)]

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// RFC 9113 §3.4 client connection preface.
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

pub const DATA: u8 = 0x0;
pub const HEADERS: u8 = 0x1;
pub const RST_STREAM: u8 = 0x3;
pub const SETTINGS: u8 = 0x4;
pub const PING: u8 = 0x6;
pub const GOAWAY: u8 = 0x7;
pub const WINDOW_UPDATE: u8 = 0x8;

pub const FLAG_END_STREAM: u8 = 0x1;
pub const FLAG_ACK: u8 = 0x1;
pub const FLAG_END_HEADERS: u8 = 0x4;

// RFC 9113 §7 error codes.
pub const NO_ERROR: u32 = 0x0;
pub const PROTOCOL_ERROR: u32 = 0x1;
pub const FLOW_CONTROL_ERROR: u32 = 0x3;
pub const FRAME_SIZE_ERROR: u32 = 0x6;
pub const REFUSED_STREAM: u32 = 0x7;
pub const ENHANCE_YOUR_CALM: u32 = 0xb;

/// Upper bound for every wait so a regression fails instead of hanging.
pub const STEP: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub flags: u8,
    pub stream: u32,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn is_settings_ack(&self) -> bool {
        self.kind == SETTINGS && self.flags & FLAG_ACK != 0
    }

    /// `(last_stream_id, error_code)` of a GOAWAY frame.
    pub fn goaway(&self) -> Option<(u32, u32)> {
        if self.kind != GOAWAY || self.payload.len() < 8 {
            return None;
        }
        let last = u32::from_be_bytes(self.payload[0..4].try_into().ok()?) & 0x7fff_ffff;
        let code = u32::from_be_bytes(self.payload[4..8].try_into().ok()?);
        Some((last, code))
    }

    /// Error code of an RST_STREAM frame.
    pub fn rst_code(&self) -> Option<u32> {
        if self.kind != RST_STREAM || self.payload.len() != 4 {
            return None;
        }
        Some(u32::from_be_bytes(self.payload[..].try_into().ok()?))
    }
}

pub fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("test payload fits in 24 bits");
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&length.to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// SETTINGS frame body from raw `(identifier, value)` pairs, in wire order.
pub fn settings_payload(entries: &[(u16, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(entries.len() * 6);
    for (id, value) in entries {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&value.to_be_bytes());
    }
    out
}

pub fn settings(entries: &[(u16, u32)]) -> Vec<u8> {
    frame(SETTINGS, 0, 0, &settings_payload(entries))
}

pub fn settings_ack() -> Vec<u8> {
    frame(SETTINGS, FLAG_ACK, 0, &[])
}

/// `:method GET`, `:scheme http`, `:path /` from the HPACK static table.
pub const REQUEST_HEADER_BLOCK: &[u8] = &[0x82, 0x86, 0x84];

pub fn request_headers(stream: u32, end_stream: bool) -> Vec<u8> {
    let flags = FLAG_END_HEADERS | if end_stream { FLAG_END_STREAM } else { 0 };
    frame(HEADERS, flags, stream, REQUEST_HEADER_BLOCK)
}

/// Read one frame; `None` on clean EOF at a frame boundary.
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Option<Frame> {
    let mut head = [0u8; 9];
    let header = tokio::time::timeout(STEP, reader.read_exact(&mut head))
        .await
        .expect("timed out waiting for an HTTP/2 frame header");
    if header.is_err() {
        return None;
    }
    let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let mut payload = vec![0u8; length];
    tokio::time::timeout(STEP, reader.read_exact(&mut payload))
        .await
        .expect("timed out waiting for an HTTP/2 frame payload")
        .expect("peer closed in the middle of a frame");
    Some(Frame {
        kind: head[3],
        flags: head[4],
        stream: u32::from_be_bytes([head[5] & 0x7f, head[6], head[7], head[8]]),
        payload,
    })
}

/// Read frames until EOF. Panics (via `read_frame`) if the peer stalls.
pub async fn read_to_end<R: AsyncRead + Unpin>(reader: &mut R) -> Vec<Frame> {
    let mut frames = Vec::new();
    while let Some(frame) = read_frame(reader).await {
        frames.push(frame);
    }
    frames
}

/// Read frames until the first GOAWAY and return it, or `None` if the peer
/// closes (or stalls past [`STEP`]) without one.
pub async fn read_until_goaway<R: AsyncRead + Unpin>(reader: &mut R) -> Option<Frame> {
    loop {
        let mut head = [0u8; 9];
        match tokio::time::timeout(STEP, reader.read_exact(&mut head)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => return None,
        }
        let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let mut payload = vec![0u8; length];
        reader.read_exact(&mut payload).await.ok()?;
        if head[3] == GOAWAY {
            return Some(Frame {
                kind: head[3],
                flags: head[4],
                stream: 0,
                payload,
            });
        }
    }
}

pub async fn write_all<W: AsyncWrite + Unpin>(writer: &mut W, bytes: &[u8]) {
    writer
        .write_all(bytes)
        .await
        .expect("duplex peer accepts test frames");
    writer.flush().await.expect("duplex flush");
}

/// Build a client-side hand-rolled connection prefix: preface + SETTINGS.
pub fn client_prefix(entries: &[(u16, u32)]) -> Vec<u8> {
    let mut out = PREFACE.to_vec();
    out.extend_from_slice(&settings(entries));
    out
}
