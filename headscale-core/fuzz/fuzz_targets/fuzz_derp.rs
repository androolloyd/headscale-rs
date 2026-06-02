#![no_main]

use arbitrary::Arbitrary;
use headscale_core::derp::{
    parse_derp_frame,
    protocol::{
        decode_frame, encode_frame, encode_raw_frame, Frame, FrameDecoder, FrameType, PeerEndpoint,
        PeerGoneReason, PeerPresentFlags, KEY_LEN, MAX_INFO_LEN, NONCE_LEN,
    },
};
use libfuzzer_sys::fuzz_target;

const STRUCTURED_BYTES_CAP: usize = 4096;
const STREAM_DRAIN_LIMIT: usize = 64;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    raw_bytes: Vec<u8>,
    raw_frame_type: u8,
    raw_payload: Vec<u8>,
    split_seed: u8,
    frame: FuzzFrame,
}

#[derive(Debug, Arbitrary)]
enum FuzzFrame {
    ServerKey {
        key: [u8; KEY_LEN],
        extra: Vec<u8>,
    },
    ClientInfo {
        public_key: [u8; KEY_LEN],
        encrypted_info: Vec<u8>,
    },
    ServerInfo {
        encrypted_info: Vec<u8>,
    },
    SendPacket {
        destination: [u8; KEY_LEN],
        packet: Vec<u8>,
    },
    ForwardPacket {
        source: [u8; KEY_LEN],
        destination: [u8; KEY_LEN],
        packet: Vec<u8>,
    },
    RecvPacket {
        source: [u8; KEY_LEN],
        packet: Vec<u8>,
    },
    KeepAlive,
    NotePreferred(bool),
    PeerGone {
        peer: [u8; KEY_LEN],
        reason: u8,
    },
    PeerPresent {
        peer: [u8; KEY_LEN],
        ip: [u8; 16],
        port: u16,
        flags: Option<u8>,
        extra: Vec<u8>,
    },
    WatchConns,
    ClosePeer {
        peer: [u8; KEY_LEN],
    },
    Ping([u8; 8]),
    Pong([u8; 8]),
    Health(String),
    Restarting {
        reconnect_in_ms: u32,
        try_for_ms: u32,
    },
    Unknown {
        frame_type: u8,
        payload: Vec<u8>,
    },
}

fuzz_target!(|input: FuzzInput| {
    // Legacy DERP client parser should remain panic-free for arbitrary bytes.
    let _ = parse_derp_frame(&input.raw_bytes);

    // New protocol decoder should tolerate arbitrary byte input.
    let _ = decode_frame(&input.raw_bytes, MAX_INFO_LEN);

    // Raw frame construction feeds arbitrary type/payload pairs through both
    // single-frame and stream decoders.
    if let Ok(encoded_raw) = encode_raw_frame(
        input.raw_frame_type,
        capped(&input.raw_payload, STRUCTURED_BYTES_CAP),
    ) {
        let _ = decode_frame(&encoded_raw, MAX_INFO_LEN);
        feed_split_stream(&encoded_raw, input.split_seed);
    }

    // Typed frames exercise encode/decode round trips for valid protocol shapes.
    let frame = input.frame.into_frame();
    if let Ok(encoded) = encode_frame(&frame) {
        if let Ok((decoded, consumed)) = decode_frame(&encoded, MAX_INFO_LEN) {
            assert_eq!(consumed, encoded.len());
            assert_eq!(decoded, frame);
        }

        feed_split_stream(&encoded, input.split_seed);

        // Coalesced stream: duplicate a valid frame and require both copies to decode.
        let mut coalesced = encoded.clone();
        coalesced.extend_from_slice(&encoded);
        let mut decoder = FrameDecoder::new(MAX_INFO_LEN);
        decoder.push(&coalesced);
        assert_eq!(decoder.next_frame().unwrap(), Some(frame.clone()));
        assert_eq!(decoder.next_frame().unwrap(), Some(frame));
    }
});

impl FuzzFrame {
    fn into_frame(self) -> Frame {
        match self {
            Self::ServerKey { key, extra } => Frame::ServerKey {
                key,
                extra: capped_owned(extra, STRUCTURED_BYTES_CAP),
            },
            Self::ClientInfo {
                public_key,
                encrypted_info,
            } => Frame::ClientInfo {
                public_key,
                encrypted_info: with_nonce(encrypted_info),
            },
            Self::ServerInfo { encrypted_info } => Frame::ServerInfo {
                encrypted_info: with_nonce(encrypted_info),
            },
            Self::SendPacket {
                destination,
                packet,
            } => Frame::SendPacket {
                destination,
                packet: capped_owned(packet, STRUCTURED_BYTES_CAP),
            },
            Self::ForwardPacket {
                source,
                destination,
                packet,
            } => Frame::ForwardPacket {
                source,
                destination,
                packet: capped_owned(packet, STRUCTURED_BYTES_CAP),
            },
            Self::RecvPacket { source, packet } => Frame::RecvPacket {
                source,
                packet: capped_owned(packet, STRUCTURED_BYTES_CAP),
            },
            Self::KeepAlive => Frame::KeepAlive,
            Self::NotePreferred(preferred) => Frame::NotePreferred(preferred),
            Self::PeerGone { peer, reason } => Frame::PeerGone {
                peer,
                reason: PeerGoneReason::from_code(reason),
            },
            Self::PeerPresent {
                peer,
                ip,
                port,
                flags,
                extra,
            } => Frame::PeerPresent {
                peer,
                endpoint: Some(PeerEndpoint { ip, port }),
                flags: Some(PeerPresentFlags(flags.unwrap_or_default())),
                extra: capped_owned(extra, STRUCTURED_BYTES_CAP),
            },
            Self::WatchConns => Frame::WatchConns,
            Self::ClosePeer { peer } => Frame::ClosePeer { peer },
            Self::Ping(payload) => Frame::Ping(payload),
            Self::Pong(payload) => Frame::Pong(payload),
            Self::Health(problem) => Frame::Health(problem),
            Self::Restarting {
                reconnect_in_ms,
                try_for_ms,
            } => Frame::Restarting {
                reconnect_in_ms,
                try_for_ms,
            },
            Self::Unknown {
                frame_type,
                payload,
            } => Frame::Unknown {
                frame_type: unknown_frame_type(frame_type),
                payload: capped_owned(payload, STRUCTURED_BYTES_CAP),
            },
        }
    }
}

fn capped(bytes: &[u8], cap: usize) -> &[u8] {
    &bytes[..bytes.len().min(cap)]
}

fn capped_owned(mut bytes: Vec<u8>, cap: usize) -> Vec<u8> {
    bytes.truncate(cap);
    bytes
}

fn with_nonce(bytes: Vec<u8>) -> Vec<u8> {
    let mut encrypted_info = vec![0; NONCE_LEN];
    encrypted_info.extend_from_slice(capped(&bytes, STRUCTURED_BYTES_CAP));
    encrypted_info
}

fn unknown_frame_type(frame_type: u8) -> u8 {
    if FrameType::from_code(frame_type).is_some() {
        0xfe
    } else {
        frame_type
    }
}

fn feed_split_stream(encoded: &[u8], split_seed: u8) {
    let split_at = usize::from(split_seed).min(encoded.len());
    let mut decoder = FrameDecoder::new(MAX_INFO_LEN);

    decoder.push(&encoded[..split_at]);
    let _ = decoder.next_frame();
    decoder.push(&encoded[split_at..]);

    for _ in 0..STREAM_DRAIN_LIMIT {
        match decoder.next_frame() {
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => break,
        }
    }
}
