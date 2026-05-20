//! Minimal STUN responder (RFC 5389 binding-request / binding-response).
//!
//! Upstream `tailscale.com/net/stun` exposes `Request` /
//! `Response(txid, addr)` helpers; we re-implement the same byte
//! stream here. Just enough to let a Tailscale client measure its
//! reflexive address against the embedded DERP region.
//!
//! ## Wire format
//!
//! STUN message header is 20 bytes:
//! ```text
//!   00..02  message type      (0x0001 = binding request)
//!   02..04  message length    (attributes only, header excluded)
//!   04..08  magic cookie      0x2112_a442
//!   08..20  transaction ID    96 bits
//! ```
//! Plus zero-or-more attributes.
//!
//! The binding-response we emit carries exactly one attribute —
//! XOR-MAPPED-ADDRESS (0x0020, RFC 5389 §15.2), encoded against the
//! magic cookie + transaction ID. We deliberately skip
//! SOFTWARE / FINGERPRINT / MESSAGE-INTEGRITY: matches upstream's
//! `stun.Response()` helper.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// STUN magic cookie. RFC 5389 §6.
pub const STUN_MAGIC_COOKIE: u32 = 0x2112_a442;

/// STUN binding-request message type.
pub const MSG_TYPE_BINDING_REQUEST: u16 = 0x0001;

/// STUN binding-response (success) message type.
pub const MSG_TYPE_BINDING_RESPONSE: u16 = 0x0101;

/// XOR-MAPPED-ADDRESS attribute type.
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// IPv4 family constant inside an XOR-MAPPED-ADDRESS attribute.
pub const FAMILY_IPV4: u8 = 0x01;
/// IPv6 family constant.
pub const FAMILY_IPV6: u8 = 0x02;

#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error("packet shorter than 20-byte STUN header")]
    Truncated,
    #[error("not a STUN message (wrong magic cookie)")]
    BadMagic,
    #[error("unsupported message type 0x{0:04x}")]
    UnsupportedType(u16),
}

/// Parse a STUN binding-request. Returns the 12-byte transaction ID
/// on success. Attribute payload (if any) is ignored.
pub fn decode_stun_binding_request(pkt: &[u8]) -> Result<[u8; 12], StunError> {
    if pkt.len() < 20 {
        return Err(StunError::Truncated);
    }
    let msg_type = u16::from_be_bytes([pkt[0], pkt[1]]);
    if msg_type != MSG_TYPE_BINDING_REQUEST {
        return Err(StunError::UnsupportedType(msg_type));
    }
    let cookie = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    if cookie != STUN_MAGIC_COOKIE {
        return Err(StunError::BadMagic);
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&pkt[8..20]);
    Ok(txid)
}

/// Encode a binding-response success message carrying a single
/// XOR-MAPPED-ADDRESS attribute for `addr`. Supports both v4 and v6.
pub fn encode_stun_binding_response(txid: [u8; 12], addr: SocketAddr) -> Vec<u8> {
    let attr_body = encode_xor_mapped_address(txid, addr);
    let attr_len = attr_body.len() as u16;
    let mut out = Vec::with_capacity(20 + 4 + attr_body.len());
    out.extend_from_slice(&MSG_TYPE_BINDING_RESPONSE.to_be_bytes());
    let msg_len = (4 + attr_body.len()) as u16;
    out.extend_from_slice(&msg_len.to_be_bytes());
    out.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    out.extend_from_slice(&txid);
    out.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    out.extend_from_slice(&attr_len.to_be_bytes());
    out.extend_from_slice(&attr_body);
    out
}

/// Inner XOR-MAPPED-ADDRESS body (no attribute header). Returns 8
/// bytes for IPv4, 20 bytes for IPv6.
fn encode_xor_mapped_address(txid: [u8; 12], addr: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20);
    buf.push(0);
    match addr {
        SocketAddr::V4(_) => buf.push(FAMILY_IPV4),
        SocketAddr::V6(_) => buf.push(FAMILY_IPV6),
    }
    let x_port = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    buf.extend_from_slice(&x_port.to_be_bytes());
    match addr.ip() {
        IpAddr::V4(v4) => {
            let raw = u32::from(v4);
            let xored = raw ^ STUN_MAGIC_COOKIE;
            buf.extend_from_slice(&xored.to_be_bytes());
        }
        IpAddr::V6(v6) => {
            let raw = v6.octets();
            let mut mask = [0u8; 16];
            mask[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            mask[4..16].copy_from_slice(&txid);
            let mut xored = [0u8; 16];
            for (i, b) in raw.iter().enumerate() {
                xored[i] = b ^ mask[i];
            }
            buf.extend_from_slice(&xored);
        }
    }
    buf
}

/// UDP STUN responder bound to one socket. Background task handles
/// every received packet; drop the listener to abort.
pub struct StunListener {
    socket: Arc<UdpSocket>,
    handle: JoinHandle<()>,
}

impl StunListener {
    /// Bind a UDP socket at `addr` and start serving binding-request
    /// packets.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let socket_clone = Arc::clone(&socket);
        let handle = tokio::spawn(async move {
            serve_loop(socket_clone).await;
        });
        Ok(Self { socket, handle })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Manually invoke the responder against a single packet — used
    /// by tests. Returns `Ok(Some(response))` for a well-formed
    /// binding-request, `Ok(None)` for a packet we should silently
    /// drop.
    pub fn handle_packet(pkt: &[u8], remote: SocketAddr) -> Result<Option<Vec<u8>>, StunError> {
        match decode_stun_binding_request(pkt) {
            Ok(txid) => Ok(Some(encode_stun_binding_response(txid, remote))),
            Err(StunError::Truncated | StunError::BadMagic) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl Drop for StunListener {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn serve_loop(socket: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 1500];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, remote)) => {
                if let Ok(Some(resp)) = StunListener::handle_packet(&buf[..n], remote) {
                    let _ = socket.send_to(&resp, remote).await;
                }
            }
            Err(e) => {
                tracing::warn!("stun recv_from failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}
