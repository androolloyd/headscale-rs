//! Post-handshake Noise transport layer with **big-endian** nonces.
//!
//! Tailscale's `controlbase` deviates from the canonical Noise spec in
//! exactly one place after the IK handshake: the 12-byte
//! ChaCha20Poly1305 nonce has the 64-bit counter encoded as
//! **big-endian**, not little-endian as the Noise spec mandates. Upstream
//! Go reference:
//! [`tailscale/control/controlbase/conn.go::nonce`](https://github.com/tailscale/tailscale/blob/main/control/controlbase/conn.go):
//!
//! ```go
//! type nonce [chp.NonceSize]byte
//! func (n *nonce) Increment() {
//!     // ...
//!     binary.BigEndian.PutUint64(n[4:], 1+binary.BigEndian.Uint64(n[4:]))
//! }
//! ```
//!
//! The `snow` crate follows the Noise spec faithfully (little-endian),
//! so its `TransportState` produces ciphertexts whose nonce/AAD don't
//! match what stock `tailscale up` writes/expects. We therefore extract
//! the two ChaCha20Poly1305 keys produced by `Split()` (via the
//! `risky-raw-split` snow feature) and run the transport encrypt/decrypt
//! ourselves with the big-endian nonce convention. We do NOT implement
//! any cipher primitive — the audited [`chacha20poly1305`] crate does
//! all the math.
//!
//! ## Wire format (one record)
//!
//! Per `tailscale/control/controlbase/conn.go`:
//!
//! ```text
//! [msg_type=4:u8][len:u16 BE][ciphertext]
//! ```
//!
//! where `len = plaintext_len + 16` (the ChaCha20Poly1305 tag is
//! appended to the ciphertext per the IETF AEAD construction). The
//! per-record maxima upstream uses are:
//!
//! - `maxMessageSize`   = 4096                                (total frame bytes)
//! - `maxCiphertextSize` = `maxMessageSize - 3`        = 4093 (frame minus 3-byte header)
//! - `maxPlaintextSize`  = `maxCiphertextSize - 16`    = 4077 (ciphertext minus tag)
//!
//! We replicate the 4077-byte plaintext cap so chunks we produce
//! round-trip cleanly through stock `tailscale up`'s read loop. The
//! constants are pinned literally from
//! `tailscale/control/controlbase/conn.go` so a future upstream tweak
//! is easy to spot.
//!
//! ## Replay handling
//!
//! Upstream `controlbase` uses **strict monotonic** nonce incrementing
//! on both directions — there is no sliding window. From `conn.go`:
//!
//! > Once a decryption has failed, our Conn is no longer synchronized
//! > with our peer.
//!
//! That is, any nonce reuse or out-of-order delivery aborts the
//! connection. We mirror that behavior: `decrypt` rejects any input
//! whose implicit counter doesn't match the next-expected receive
//! counter. The original spec asked for a 32-bit sliding window; we
//! deviated for interop correctness (the sliding window is reserved
//! for lossy datagram transports like WireGuard, not the strictly-
//! ordered TCP+TLS stream `/ts2021` rides on). See the module-level
//! decision log in `mod.rs`'s `be_transport` registration for the
//! rationale.
//!
//! ## Key direction
//!
//! `snow::HandshakeState::dangerously_get_raw_split()` returns
//! `(k1, k2)` where `k1` is the **initiator's egress** cipher key and
//! `k2` is the **responder's egress** cipher key (per the Noise
//! spec's `Split()` definition, sourced in
//! `snow/src/symmetricstate.rs::split_raw`). So for an **initiator**
//! side: `send_key = k1, recv_key = k2`. For a **responder** side
//! (which is what `/ts2021` is): `send_key = k2, recv_key = k1`. The
//! [`BeTransport::from_split_responder`] / [`BeTransport::from_split_initiator`]
//! helpers wrap this so callers never have to reason about it.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::controlbase::MsgType;

/// AEAD tag length for ChaCha20Poly1305.
pub const TAG_LEN: usize = 16;

/// Max total frame bytes on the wire (header + ciphertext). Pinned
/// from `controlbase/conn.go::maxMessageSize`.
pub const MAX_MESSAGE_SIZE: usize = 4096;

/// Max ciphertext payload (plaintext + tag) we'll accept on `decrypt`
/// or write through `encrypt`. `MAX_MESSAGE_SIZE - 3` per upstream.
pub const MAX_CIPHERTEXT_PER_RECORD: usize = MAX_MESSAGE_SIZE - 3;

/// Max plaintext per `encrypt` call. Larger plaintexts must be chunked
/// by the caller (the AsyncWrite wrapper does this automatically).
/// `MAX_CIPHERTEXT_PER_RECORD - TAG_LEN` per upstream.
pub const MAX_PLAINTEXT_PER_RECORD: usize = MAX_CIPHERTEXT_PER_RECORD - TAG_LEN;

/// Errors from `BeTransport::decrypt`. `encrypt` is infallible from
/// the caller's perspective (key + nonce always combine correctly;
/// nonce overflow is the only theoretical failure and we panic on it
/// rather than return an error because it indicates a 2^64-record
/// connection — vanishingly unlikely and a programmer bug if hit).
#[derive(Debug, Error)]
pub enum BeTransportError {
    /// AEAD authentication failed. Bad key, corrupted ciphertext, or
    /// counter desync.
    #[error("be_transport: AEAD decrypt failed (bad tag, key, or counter desync)")]
    Decrypt,
    /// The provided ciphertext is shorter than the AEAD tag (16 bytes).
    #[error("be_transport: ciphertext too short ({0} < {TAG_LEN} bytes)")]
    ShortCiphertext(usize),
    /// The provided ciphertext exceeds the per-record cap.
    #[error(
        "be_transport: ciphertext too long ({got} > {} bytes)",
        MAX_CIPHERTEXT_PER_RECORD
    )]
    TooLong { got: usize },
    /// Send/receive nonce counter would overflow u64. 2^64 records on
    /// a single Tailscale connection is operationally impossible, but
    /// we surface it explicitly rather than silently wrap.
    #[error("be_transport: nonce counter exhausted")]
    NonceExhausted,
}

/// Encode a u64 counter into the 12-byte ChaCha20Poly1305 nonce in
/// **big-endian** layout. THE one-line deviation from the Noise spec
/// that makes the whole Tailscale transport work.
///
/// Layout: first 4 bytes zero, last 8 bytes = `counter.to_be_bytes()`.
/// Sourced from `tailscale/control/controlbase/conn.go::Increment`.
#[inline]
fn nonce_be(counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[4..12].copy_from_slice(&counter.to_be_bytes());
    n
}

/// Tailscale-flavoured ChaCha20Poly1305 transport state.
///
/// One instance per Noise session — holds both directions' keys + the
/// per-direction monotonic counters. Cheap to construct
/// (`KeyInit::new` just clones the key into a `ChaCha20Poly1305`
/// instance internally).
pub struct BeTransport {
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
    send_counter: u64,
    recv_counter: u64,
}

impl BeTransport {
    /// Construct from the raw split keys (initiator's side).
    ///
    /// For symmetry with `from_split_responder`; the wire layer (which
    /// is a responder) uses `from_split_responder`. Tests + clients use
    /// this one.
    pub fn from_split_initiator(k1_init_egress: [u8; 32], k2_resp_egress: [u8; 32]) -> Self {
        Self::new(k1_init_egress, k2_resp_egress)
    }

    /// Construct from the raw split keys (responder's side).
    ///
    /// `/ts2021` is always the responder. Swaps the key direction so
    /// `send` uses the responder-egress key and `recv` uses the
    /// initiator-egress key.
    pub fn from_split_responder(k1_init_egress: [u8; 32], k2_resp_egress: [u8; 32]) -> Self {
        Self::new(k2_resp_egress, k1_init_egress)
    }

    fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        let send_cipher = ChaCha20Poly1305::new(Key::from_slice(&send_key));
        let recv_cipher = ChaCha20Poly1305::new(Key::from_slice(&recv_key));
        Self {
            send_cipher,
            recv_cipher,
            send_counter: 0,
            recv_counter: 0,
        }
    }

    /// Encrypt one application chunk. Output is `ciphertext || tag`
    /// (the standard IETF AEAD construction; `chacha20poly1305` crate
    /// appends the tag).
    ///
    /// Panics if `plaintext.len() > MAX_PLAINTEXT_PER_RECORD`. The
    /// `AsyncWrite` wrapper splits oversized writes upstream of this
    /// call.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, BeTransportError> {
        assert!(
            plaintext.len() <= MAX_PLAINTEXT_PER_RECORD,
            "be_transport::encrypt called with {} bytes; caller must chunk to {}",
            plaintext.len(),
            MAX_PLAINTEXT_PER_RECORD,
        );
        let nonce_bytes = nonce_be(self.send_counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        // chacha20poly1305 0.10's `encrypt` cannot fail given a
        // correctly-sized key + nonce + bounded plaintext. We still
        // surface the error rather than unwrap to keep the API
        // honest.
        let ct = self
            .send_cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| BeTransportError::Decrypt)?;
        self.send_counter = self
            .send_counter
            .checked_add(1)
            .ok_or(BeTransportError::NonceExhausted)?;
        Ok(ct)
    }

    /// Decrypt one received transport record. Expects `ciphertext ||
    /// tag` (i.e. `ciphertext.len() >= TAG_LEN`). Returns the
    /// recovered plaintext.
    ///
    /// Mirrors upstream's strict-monotonic semantic: the implicit
    /// counter is the receiver's next-expected value, advanced by 1 on
    /// success. Out-of-order or replayed frames will fail the AEAD
    /// check (different counter → different keystream → tag mismatch)
    /// and abort the stream.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, BeTransportError> {
        if ciphertext.len() < TAG_LEN {
            return Err(BeTransportError::ShortCiphertext(ciphertext.len()));
        }
        if ciphertext.len() > MAX_CIPHERTEXT_PER_RECORD {
            return Err(BeTransportError::TooLong {
                got: ciphertext.len(),
            });
        }
        let nonce_bytes = nonce_be(self.recv_counter);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let pt = self
            .recv_cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| BeTransportError::Decrypt)?;
        self.recv_counter = self
            .recv_counter
            .checked_add(1)
            .ok_or(BeTransportError::NonceExhausted)?;
        Ok(pt)
    }

    /// Current send-side counter. Test/diagnostic only.
    pub fn send_counter(&self) -> u64 {
        self.send_counter
    }

    /// Current recv-side counter. Test/diagnostic only.
    pub fn recv_counter(&self) -> u64 {
        self.recv_counter
    }
}

/// AsyncRead+AsyncWrite wrapper that frames each application-layer
/// write into one (or more) Tailscale Record frames + encrypts them
/// with [`BeTransport`]. The reverse on the read path.
///
/// Mirrors the `controlbase::NoiseStream` API but routes through
/// `BeTransport` (BE nonces) instead of `snow::TransportState`
/// (LE nonces). This is the type production wires up after the IK
/// handshake completes.
///
/// State machine matches `controlbase::NoiseStream`:
///
/// - **Read:** `Header` (3 bytes) → `Body { len }` → decrypt →
///   `ServingPlaintext` → drain → back to `Header`.
/// - **Write:** `Idle` → `Flushing { framed_ciphertext }` → write_all
///   → `Idle`.
///
/// Plaintext-per-record cap: [`MAX_PLAINTEXT_PER_RECORD`] (4080,
/// matches upstream `controlbase/conn.go::maxPlaintextSize`).
pub struct BeNoiseStream<T> {
    inner: T,
    transport: BeTransport,
    read_state: BeReadState,
    write_state: BeWriteState,
}

enum BeReadState {
    Header { buf: [u8; 3], filled: usize },
    Body { buf: Vec<u8>, filled: usize },
    ServingPlaintext { buf: Vec<u8>, pos: usize },
    Eof,
}

enum BeWriteState {
    Idle,
    Flushing { buf: Vec<u8>, pos: usize },
}

impl<T> BeNoiseStream<T> {
    /// Construct a new BeNoiseStream from an already-handshake-
    /// completed transport state + the underlying socket.
    ///
    /// The caller is responsible for having driven the Noise IK
    /// handshake to completion and extracted the split keys via
    /// `snow::HandshakeState::dangerously_get_raw_split()`; see
    /// `noise::drive_ts2021_be_with_init` for the standard wiring.
    pub fn new(inner: T, transport: BeTransport) -> Self {
        Self {
            inner,
            transport,
            read_state: BeReadState::Header {
                buf: [0u8; 3],
                filled: 0,
            },
            write_state: BeWriteState::Idle,
        }
    }

    /// Reclaim the underlying socket + transport state.
    pub fn into_parts(self) -> (T, BeTransport) {
        (self.inner, self.transport)
    }
}

impl<T> AsyncRead for BeNoiseStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let cur = std::mem::replace(
                &mut self.read_state,
                BeReadState::Header {
                    buf: [0u8; 3],
                    filled: 0,
                },
            );
            match cur {
                BeReadState::Eof => {
                    self.read_state = BeReadState::Eof;
                    return Poll::Ready(Ok(()));
                }
                BeReadState::ServingPlaintext { buf, pos } => {
                    let remaining = &buf[pos..];
                    let n = remaining.len().min(out.remaining());
                    if n == 0 {
                        self.read_state = BeReadState::ServingPlaintext { buf, pos };
                        return Poll::Ready(Ok(()));
                    }
                    out.put_slice(&remaining[..n]);
                    let new_pos = pos + n;
                    if new_pos == buf.len() {
                        self.read_state = BeReadState::Header {
                            buf: [0u8; 3],
                            filled: 0,
                        };
                    } else {
                        self.read_state = BeReadState::ServingPlaintext { buf, pos: new_pos };
                    }
                    return Poll::Ready(Ok(()));
                }
                BeReadState::Header {
                    mut buf,
                    mut filled,
                } => {
                    let mut rb = ReadBuf::new(&mut buf[filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => {
                            self.read_state = BeReadState::Header { buf, filled };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.read_state = BeReadState::Header { buf, filled };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                if filled == 0 {
                                    self.read_state = BeReadState::Eof;
                                    return Poll::Ready(Ok(()));
                                }
                                self.read_state = BeReadState::Header { buf, filled };
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "be_noise: EOF mid-header",
                                )));
                            }
                            filled += n;
                            if filled < 3 {
                                self.read_state = BeReadState::Header { buf, filled };
                                continue;
                            }
                            // Validate msg type (must be Record post-handshake).
                            let mt_byte = buf[0];
                            if mt_byte != MsgType::Record as u8 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "be_noise: expected Record (4) in transport mode, got {mt_byte}"
                                    ),
                                )));
                            }
                            let len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
                            if len == 0 {
                                self.read_state = BeReadState::Header {
                                    buf: [0u8; 3],
                                    filled: 0,
                                };
                                continue;
                            }
                            if len > MAX_CIPHERTEXT_PER_RECORD {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!(
                                        "be_noise: record body {len} exceeds max ciphertext {MAX_CIPHERTEXT_PER_RECORD}",
                                    ),
                                )));
                            }
                            self.read_state = BeReadState::Body {
                                buf: vec![0u8; len],
                                filled: 0,
                            };
                        }
                    }
                }
                BeReadState::Body {
                    mut buf,
                    mut filled,
                } => {
                    let mut rb = ReadBuf::new(&mut buf[filled..]);
                    match Pin::new(&mut self.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => {
                            self.read_state = BeReadState::Body { buf, filled };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.read_state = BeReadState::Body { buf, filled };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(())) => {
                            let n = rb.filled().len();
                            if n == 0 {
                                self.read_state = BeReadState::Body { buf, filled };
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::UnexpectedEof,
                                    "be_noise: EOF mid-body",
                                )));
                            }
                            filled += n;
                            if filled < buf.len() {
                                self.read_state = BeReadState::Body { buf, filled };
                                continue;
                            }
                            // Full ciphertext. Decrypt with BE-nonce
                            // transport.
                            let pt = match self.transport.decrypt(&buf) {
                                Ok(p) => p,
                                Err(e) => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        format!("be_noise decrypt: {e}"),
                                    )));
                                }
                            };
                            self.read_state = BeReadState::ServingPlaintext { buf: pt, pos: 0 };
                        }
                    }
                }
            }
        }
    }
}

impl<T> AsyncWrite for BeNoiseStream<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let cur = std::mem::replace(&mut self.write_state, BeWriteState::Idle);
            match cur {
                BeWriteState::Idle => {
                    if bytes.is_empty() {
                        self.write_state = BeWriteState::Idle;
                        return Poll::Ready(Ok(0));
                    }
                    let take = bytes.len().min(MAX_PLAINTEXT_PER_RECORD);
                    let ciphertext = match self.transport.encrypt(&bytes[..take]) {
                        Ok(c) => c,
                        Err(e) => {
                            return Poll::Ready(Err(io::Error::other(format!(
                                "be_noise encrypt: {e}"
                            ))));
                        }
                    };
                    let mut framed = Vec::with_capacity(3 + ciphertext.len());
                    framed.push(MsgType::Record as u8);
                    framed.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
                    framed.extend_from_slice(&ciphertext);
                    self.write_state = BeWriteState::Flushing {
                        buf: framed,
                        pos: 0,
                    };
                }
                BeWriteState::Flushing { buf, pos } => {
                    let rem = &buf[pos..];
                    match Pin::new(&mut self.inner).poll_write(cx, rem) {
                        Poll::Pending => {
                            self.write_state = BeWriteState::Flushing { buf, pos };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.write_state = BeWriteState::Flushing { buf, pos };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(0)) => {
                            self.write_state = BeWriteState::Flushing { buf, pos };
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "be_noise: inner write returned 0",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            let new_pos = pos + n;
                            if new_pos == buf.len() {
                                self.write_state = BeWriteState::Idle;
                                let consumed = bytes.len().min(MAX_PLAINTEXT_PER_RECORD);
                                return Poll::Ready(Ok(consumed));
                            }
                            self.write_state = BeWriteState::Flushing { buf, pos: new_pos };
                        }
                    }
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let cur = std::mem::replace(&mut self.write_state, BeWriteState::Idle);
            match cur {
                BeWriteState::Idle => {
                    return Pin::new(&mut self.inner).poll_flush(cx);
                }
                BeWriteState::Flushing { buf, pos } => {
                    let rem = &buf[pos..];
                    match Pin::new(&mut self.inner).poll_write(cx, rem) {
                        Poll::Pending => {
                            self.write_state = BeWriteState::Flushing { buf, pos };
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(e)) => {
                            self.write_state = BeWriteState::Flushing { buf, pos };
                            return Poll::Ready(Err(e));
                        }
                        Poll::Ready(Ok(0)) => {
                            self.write_state = BeWriteState::Flushing { buf, pos };
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "be_noise: inner write returned 0",
                            )));
                        }
                        Poll::Ready(Ok(n)) => {
                            let new_pos = pos + n;
                            if new_pos == buf.len() {
                                self.write_state = BeWriteState::Idle;
                            } else {
                                self.write_state = BeWriteState::Flushing { buf, pos: new_pos };
                            }
                        }
                    }
                }
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match Pin::new(&mut *self).poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (BeTransport, BeTransport) {
        // Two distinct deterministic keys. We use the responder's
        // perspective for `server` so the key-direction wiring matches
        // production.
        let k1 = [1u8; 32];
        let k2 = [2u8; 32];
        let init = BeTransport::from_split_initiator(k1, k2);
        let resp = BeTransport::from_split_responder(k1, k2);
        (init, resp)
    }

    #[test]
    fn encrypt_decrypt_round_trip() {
        let (mut a, mut b) = pair();
        let pt = b"hello tailscale";
        let ct = a.encrypt(pt).unwrap();
        let recovered = b.decrypt(&ct).unwrap();
        assert_eq!(recovered, pt);
    }

    /// Pin the nonce-encoding deviation: an encrypted record with
    /// counter=1 must match `ChaCha20Poly1305::encrypt(Nonce(BE), pt)`
    /// byte-for-byte. This is the regression guard for the entire
    /// reason this module exists.
    #[test]
    fn nonce_is_big_endian() {
        let key = [3u8; 32];
        let mut tx = BeTransport::from_split_initiator(key, [0u8; 32]);

        // First send → counter=0. Second send → counter=1. We assert
        // the on-the-wire bytes of the second send match what
        // `ChaCha20Poly1305` produces with a hand-built BE nonce for
        // counter=1.
        let pt = b"counter=1 payload";

        let _first = tx.encrypt(b"counter=0 throwaway").unwrap();
        let actual = tx.encrypt(pt).unwrap();

        let mut expected_nonce = [0u8; 12];
        expected_nonce[4..12].copy_from_slice(&1u64.to_be_bytes());
        let expected = ChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(Nonce::from_slice(&expected_nonce), pt.as_ref())
            .unwrap();

        assert_eq!(
            actual, expected,
            "encrypt output must match raw chacha20poly1305 with BE nonce"
        );

        // And confirm it does NOT match an LE-nonce encryption with the
        // same counter — that's the bug we're guarding against.
        let mut le_nonce = [0u8; 12];
        le_nonce[4..12].copy_from_slice(&1u64.to_le_bytes());
        let le_expected = ChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(Nonce::from_slice(&le_nonce), pt.as_ref())
            .unwrap();
        assert_ne!(
            actual, le_expected,
            "LE-nonce output must differ from BE-nonce"
        );
    }

    #[test]
    fn counter_increments_per_send() {
        let (mut a, _) = pair();
        let _c0 = a.encrypt(b"a").unwrap();
        let _c1 = a.encrypt(b"a").unwrap();
        let _c2 = a.encrypt(b"a").unwrap();
        assert_eq!(a.send_counter(), 3);
        // And the three ciphertexts are pairwise distinct (different
        // nonces → different keystreams → different ciphertexts even
        // for the same plaintext).
        let mut b_send_only = BeTransport::from_split_initiator([7u8; 32], [0u8; 32]);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..3 {
            let ct = b_send_only.encrypt(b"same plaintext").unwrap();
            assert!(seen.insert(ct), "counter must produce distinct ciphertexts");
        }
    }

    /// Counter desync = AEAD failure. Upstream comment:
    /// "Once a decryption has failed, our Conn is no longer
    /// synchronized with our peer." We mirror that: any second-decrypt
    /// of the same record fails because the receiver's counter has
    /// moved on.
    #[test]
    fn replay_rejects_seen_record() {
        let (mut a, mut b) = pair();
        let ct = a.encrypt(b"once").unwrap();
        // First decrypt succeeds.
        let _ = b.decrypt(&ct).unwrap();
        // Replay the same bytes — receiver's counter is now 1, so the
        // AEAD check fails.
        let err = b.decrypt(&ct).unwrap_err();
        assert!(matches!(err, BeTransportError::Decrypt));
    }

    /// Strict-ordering: any out-of-order delivery fails. (Spec asked
    /// for a 32-bit sliding window, but upstream upstream does
    /// strict-monotonic — see the module doc for why. Pin the
    /// behaviour we ACTUALLY implement so a future refactor doesn't
    /// silently regress.)
    #[test]
    fn out_of_order_rejected() {
        let (mut a, mut b) = pair();
        let _ct0 = a.encrypt(b"zero").unwrap();
        let ct1 = a.encrypt(b"one").unwrap();
        // Receiver hasn't seen counter=0 yet; trying to decrypt
        // counter=1 fails the AEAD check (different keystream).
        let err = b.decrypt(&ct1).unwrap_err();
        assert!(matches!(err, BeTransportError::Decrypt));
    }

    /// Direct cross-check: the encrypt path produces exactly what the
    /// underlying `chacha20poly1305` crate produces. This is the
    /// "proof we're not introducing crypto bugs" guard called out in
    /// the implementation spec.
    #[test]
    fn cross_check_vs_chacha20poly1305_directly() {
        let key = [0x42u8; 32];
        let mut tx = BeTransport::from_split_initiator(key, [0u8; 32]);
        let payloads: &[&[u8]] = &[
            b"",
            b"x",
            b"sixteen bytes!!!",
            &[0xAB; MAX_PLAINTEXT_PER_RECORD], // exactly MAX_PLAINTEXT_PER_RECORD
        ];
        for (expected_counter, pt) in payloads.iter().enumerate() {
            let actual = tx.encrypt(pt).unwrap();
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&(expected_counter as u64).to_be_bytes());
            let expected = ChaCha20Poly1305::new(Key::from_slice(&key))
                .encrypt(Nonce::from_slice(&nonce), *pt)
                .unwrap();
            assert_eq!(actual, expected, "mismatch at counter={expected_counter}");
        }
    }

    #[test]
    fn rejects_short_ciphertext() {
        let (_, mut b) = pair();
        // Anything < 16 bytes can't be a valid AEAD output.
        let err = b.decrypt(&[1, 2, 3]).unwrap_err();
        assert!(matches!(err, BeTransportError::ShortCiphertext(3)));
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let (mut a, mut b) = pair();
        let ct = a.encrypt(b"").unwrap();
        // ChaCha20Poly1305 of empty plaintext is just the 16-byte tag.
        assert_eq!(ct.len(), TAG_LEN);
        let pt = b.decrypt(&ct).unwrap();
        assert_eq!(pt, b"");
    }

    /// End-to-end snow-handshake → BeTransport.
    ///
    /// Drives a snow IK round-trip in-process, extracts both sides'
    /// split keys via `dangerously_get_raw_split`, builds the
    /// initiator + responder BeTransports, and round-trips records in
    /// both directions. This is the integration sanity-check that the
    /// key-direction wiring matches between the two sides.
    #[test]
    fn snow_split_keys_feed_be_transport() {
        use snow::Builder;
        let params: snow::params::NoiseParams =
            "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().unwrap();

        // Generate a responder static keypair.
        let resp_static = Builder::new(params.clone()).generate_keypair().unwrap();

        // Build initiator + responder.
        let mut init = Builder::new(params.clone())
            .local_private_key(
                &Builder::new(params.clone())
                    .generate_keypair()
                    .unwrap()
                    .private,
            )
            .remote_public_key(&resp_static.public)
            .build_initiator()
            .unwrap();
        let mut resp = Builder::new(params)
            .local_private_key(&resp_static.private)
            .build_responder()
            .unwrap();

        // IK is one round-trip.
        let mut m1 = [0u8; 1024];
        let n1 = init.write_message(b"", &mut m1).unwrap();
        let mut throw = [0u8; 1024];
        resp.read_message(&m1[..n1], &mut throw).unwrap();
        let mut m2 = [0u8; 1024];
        let n2 = resp.write_message(b"", &mut m2).unwrap();
        init.read_message(&m2[..n2], &mut throw).unwrap();

        assert!(init.is_handshake_finished());
        assert!(resp.is_handshake_finished());

        // Extract split keys from both sides. They must agree.
        let (i_k1, i_k2) = init.dangerously_get_raw_split();
        let (r_k1, r_k2) = resp.dangerously_get_raw_split();
        assert_eq!(i_k1, r_k1, "k1 must agree between sides");
        assert_eq!(i_k2, r_k2, "k2 must agree between sides");

        let mut tx = BeTransport::from_split_initiator(i_k1, i_k2);
        let mut rx = BeTransport::from_split_responder(r_k1, r_k2);

        // Initiator → responder.
        let pt1 = b"client to server, BE-nonce";
        let ct1 = tx.encrypt(pt1).unwrap();
        let rec1 = rx.decrypt(&ct1).unwrap();
        assert_eq!(rec1, pt1);

        // Responder → initiator.
        let pt2 = b"server to client";
        let ct2 = rx.encrypt(pt2).unwrap();
        let rec2 = tx.decrypt(&ct2).unwrap();
        assert_eq!(rec2, pt2);
    }

    /// BeNoiseStream framing round-trip over a tokio duplex pair.
    /// Confirms the AsyncRead/AsyncWrite wrapper produces the
    /// `[type=4][len:u16 BE][ciphertext]` shape we expect, with
    /// BE-nonced encryption.
    #[tokio::test]
    async fn be_noise_stream_round_trip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

        let k1 = [0x11u8; 32];
        let k2 = [0x22u8; 32];
        let init_tx = BeTransport::from_split_initiator(k1, k2);
        let resp_rx = BeTransport::from_split_responder(k1, k2);

        let (a, b) = duplex(64 * 1024);
        let mut client = BeNoiseStream::new(a, init_tx);
        let mut server = BeNoiseStream::new(b, resp_rx);

        // Client → server.
        client.write_all(b"hello tailscale").await.unwrap();
        client.flush().await.unwrap();
        let mut got = [0u8; 15];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"hello tailscale");

        // Server → client (reuses the same pair — responder side encrypts).
        // Note: we use the same BeTransport for both directions in
        // this test by relying on responder.send_counter starting
        // fresh; that's fine because BeTransport is per-direction
        // already.
        server.write_all(b"hi back").await.unwrap();
        server.flush().await.unwrap();
        let mut got2 = [0u8; 7];
        client.read_exact(&mut got2).await.unwrap();
        assert_eq!(&got2, b"hi back");
    }

    /// Large payload > MAX_PLAINTEXT_PER_RECORD splits into multiple
    /// Record frames + reassembles transparently.
    #[tokio::test]
    async fn be_noise_stream_chunks_large_writes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

        let k1 = [0x33u8; 32];
        let k2 = [0x44u8; 32];
        let init_tx = BeTransport::from_split_initiator(k1, k2);
        let resp_rx = BeTransport::from_split_responder(k1, k2);

        let pipe_bytes = (MAX_PLAINTEXT_PER_RECORD * 3) + 64 * 1024;
        let (a, b) = duplex(pipe_bytes);
        let mut client = BeNoiseStream::new(a, init_tx);
        let mut server = BeNoiseStream::new(b, resp_rx);

        let payload_len = MAX_PLAINTEXT_PER_RECORD + 1024;
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        let payload_clone = payload.clone();

        let writer = tokio::spawn(async move {
            client.write_all(&payload_clone).await.unwrap();
            client.flush().await.unwrap();
        });

        let mut out = vec![0u8; payload_len];
        server.read_exact(&mut out).await.unwrap();
        writer.await.unwrap();
        assert_eq!(out, payload);
    }
}
