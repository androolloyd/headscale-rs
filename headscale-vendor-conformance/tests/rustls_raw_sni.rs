//! Conformance tests for the native ClientHello / raw-SNI path of the patched
//! `rustls` crate (`vendor/rustls`, default-off feature `go-server-client-hello`,
//! opted into per acceptor with `Acceptor::go_server_client_hello()`).
//!
//! Hand-built ClientHello records are fed to a stock `Acceptor::default()` and
//! to one that opted in; the two must differ exactly where Go's `crypto/tls`
//! ClientHello parser differs from stock rustls, and the stock acceptor must
//! stay strict and expose no raw name.
//!
//! Go: Go 1.26.9 `crypto/tls/handshake_messages.go` `(*clientHelloMsg).unmarshal`,
//! `extensionServerName` case (hashes in `vendor/rustls/UPSTREAM.md`): the
//! `server_name_list` must be a non-empty u16-prefixed list of non-empty
//! (u8 type, u16-prefixed name) items; items whose type is not host_name (0)
//! are skipped; a second host_name is rejected; a host_name ending in `.` is
//! rejected; the hostname is otherwise kept as arbitrary bytes. Rust:
//! `vendor/rustls/src/msgs/handshake.rs` `ServerNamePayload::read_go`;
//! `vendor/rustls/UPSTREAM.md` "Native raw SNI scope".

use rustls::server::Acceptor;

const HOST_NAME: u8 = 0;
const OTHER_NAME_TYPE: u8 = 7;

fn u16_be(value: usize) -> [u8; 2] {
    u16::try_from(value)
        .expect("test value fits in u16")
        .to_be_bytes()
}

fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&u16_be(body.len()));
    out.extend_from_slice(body);
    out
}

/// `server_name` extension body from raw `(name_type, name_bytes)` items.
fn server_name_body(items: &[(u8, &[u8])]) -> Vec<u8> {
    let mut list = Vec::new();
    for (name_type, name) in items {
        list.push(*name_type);
        list.extend_from_slice(&u16_be(name.len()));
        list.extend_from_slice(name);
    }
    let mut body = u16_be(list.len()).to_vec();
    body.extend_from_slice(&list);
    body
}

/// A TLS 1.3-capable ClientHello record carrying `server_name_body` verbatim
/// (or no SNI extension when `None`).
fn client_hello(server_name_body: Option<&[u8]>) -> Vec<u8> {
    let mut extensions = Vec::new();
    if let Some(body) = server_name_body {
        extensions.extend_from_slice(&extension(0x0000, body));
    }
    // supported_groups: x25519, secp256r1
    extensions.extend_from_slice(&extension(0x000a, &[0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]));
    // signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256
    extensions.extend_from_slice(&extension(0x000d, &[0x00, 0x04, 0x04, 0x03, 0x08, 0x04]));
    // supported_versions: TLS 1.3, TLS 1.2
    extensions.extend_from_slice(&extension(0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]));
    // key_share: one x25519 share
    let mut share = vec![0x00, 0x1d];
    share.extend_from_slice(&u16_be(32));
    share.extend_from_slice(&[0x42; 32]);
    let mut key_share = u16_be(share.len()).to_vec();
    key_share.extend_from_slice(&share);
    extensions.extend_from_slice(&extension(0x0033, &key_share));

    let mut body = vec![0x03, 0x03]; // legacy_version
    body.extend_from_slice(&[0x11; 32]); // random
    body.push(0); // empty legacy_session_id
    body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0xc0, 0x2b]); // two suites
    body.extend_from_slice(&[0x01, 0x00]); // null compression
    body.extend_from_slice(&u16_be(extensions.len()));
    body.extend_from_slice(&extensions);

    let mut handshake = vec![0x01]; // ClientHello
    handshake.extend_from_slice(&u32::try_from(body.len()).expect("small").to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&u16_be(handshake.len()));
    record.extend_from_slice(&handshake);
    record
}

#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    Hello {
        /// rustls' strict, DNS-validated name.
        server_name: Option<String>,
        /// The native raw-name accessor.
        raw: Option<Vec<u8>>,
    },
    /// `Acceptor::accept` failed (the peer would receive a decode_error alert).
    Rejected,
}

fn parse(native: bool, record: &[u8]) -> Parsed {
    let mut acceptor = Acceptor::default();
    if native {
        acceptor = acceptor.go_server_client_hello();
    }
    let mut input = record;
    acceptor.read_tls(&mut input).expect("buffer the record");
    match acceptor.accept() {
        Ok(Some(accepted)) => {
            let hello = accepted.client_hello();
            Parsed::Hello {
                server_name: hello.server_name().map(str::to_owned),
                raw: hello.raw_server_name().map(<[u8]>::to_vec),
            }
        }
        Ok(None) => panic!("a complete ClientHello record must be accepted or rejected"),
        Err(_) => Parsed::Rejected,
    }
}

fn hello(server_name: Option<&str>, raw: Option<&[u8]>) -> Parsed {
    Parsed::Hello {
        server_name: server_name.map(str::to_owned),
        raw: raw.map(<[u8]>::to_vec),
    }
}

struct Case {
    name: &'static str,
    items: Vec<(u8, Vec<u8>)>,
    stock: Parsed,
    native: Parsed,
}

fn items<'a>(case: &'a [(u8, &'a [u8])]) -> Vec<(u8, Vec<u8>)> {
    case.iter()
        .map(|(kind, name)| (*kind, name.to_vec()))
        .collect()
}

/// Table-driven: every ClientHello is fed to both acceptors.
#[test]
fn native_acceptor_parses_server_name_like_go_and_stock_stays_strict() {
    let cases = vec![
        Case {
            name: "ordinary host_name: same everywhere, raw name only when opted in",
            items: items(&[(HOST_NAME, b"example.com")]),
            stock: hello(Some("example.com"), None),
            native: hello(Some("example.com"), Some(b"example.com")),
        },
        Case {
            // Go skips non-host_name items; stock rustls cannot skip an item of
            // unknown type (its length encoding is unknown), so it stops
            // reading with no host_name and fails the handshake with an
            // illegal_parameter alert.
            name: "unknown name type before the host_name is skipped",
            items: items(&[(OTHER_NAME_TYPE, b"ignored"), (HOST_NAME, b"example.com")]),
            stock: Parsed::Rejected,
            native: hello(Some("example.com"), Some(b"example.com")),
        },
        Case {
            name: "unknown name type after the host_name is skipped",
            items: items(&[(HOST_NAME, b"example.com"), (OTHER_NAME_TYPE, b"ignored")]),
            stock: hello(Some("example.com"), None),
            native: hello(Some("example.com"), Some(b"example.com")),
        },
        Case {
            // Go rejects a second host_name even when another item sits
            // between them; stock rustls stops at the unknown item and never
            // sees the duplicate.
            name: "duplicate host_name separated by an unknown-type item",
            items: items(&[
                (HOST_NAME, b"a.example"),
                (OTHER_NAME_TYPE, b"x"),
                (HOST_NAME, b"b.example"),
            ]),
            stock: hello(Some("a.example"), None),
            native: Parsed::Rejected,
        },
        Case {
            name: "adjacent duplicate host_name entries are rejected by both",
            items: items(&[(HOST_NAME, b"a.example"), (HOST_NAME, b"b.example")]),
            stock: Parsed::Rejected,
            native: Parsed::Rejected,
        },
        Case {
            // Go: "An SNI value may not include a trailing dot."; stock rustls
            // accepts the rooted name.
            name: "host_name with a final dot is rejected by Go (and so natively)",
            items: items(&[(HOST_NAME, b"example.com.")]),
            stock: hello(Some("example.com."), None),
            native: Parsed::Rejected,
        },
        Case {
            // Go keeps the bytes verbatim; stock rustls validates a DNS name and
            // fails the handshake on anything else. Natively the strict
            // `server_name()` projection is absent but the raw bytes survive.
            name: "non-DNS bytes are retained verbatim as the raw name",
            items: items(&[(HOST_NAME, b"\xff\xfe not a host")]),
            stock: Parsed::Rejected,
            native: hello(None, Some(b"\xff\xfe not a host")),
        },
        Case {
            name: "IP-address literal is kept verbatim natively, hidden by stock",
            items: items(&[(HOST_NAME, b"192.0.2.1")]),
            stock: hello(None, None),
            native: hello(None, Some(b"192.0.2.1")),
        },
        Case {
            // The raw name keeps its case; the strict projection is lowercased.
            name: "uppercase labels keep their case in the raw name only",
            items: items(&[(HOST_NAME, b"Node_1.Example.COM")]),
            stock: hello(Some("node_1.example.com"), None),
            native: hello(Some("node_1.example.com"), Some(b"Node_1.Example.COM")),
        },
    ];

    let mut failures = Vec::new();
    for case in cases {
        let borrowed: Vec<(u8, &[u8])> = case
            .items
            .iter()
            .map(|(kind, name)| (*kind, name.as_slice()))
            .collect();
        let record = client_hello(Some(&server_name_body(&borrowed)));
        for (native, want) in [(false, &case.stock), (true, &case.native)] {
            let got = parse(native, &record);
            if &got != want {
                failures.push(format!(
                    "[{}] native={native}: expected {want:?}, got {got:?}",
                    case.name
                ));
            }
        }
    }
    assert!(failures.is_empty(), "\n{}", failures.join("\n"));
}

/// Malformed `server_name` framing is a `decode_error` for both acceptors; the
/// native parser must not become *more* permissive than Go here.
#[test]
fn malformed_server_name_framing_is_rejected_by_both() {
    let bodies: Vec<(&str, Vec<u8>)> = vec![
        ("empty server_name_list", vec![0x00, 0x00]),
        // list length says 3 but the item needs 4+ bytes
        ("truncated item", vec![0x00, 0x03, 0x00, 0x00, 0x05]),
        (
            "zero-length host_name",
            server_name_body(&[(HOST_NAME, b"")]),
        ),
    ];
    for (name, body) in bodies {
        let record = client_hello(Some(&body));
        assert_eq!(parse(false, &record), Parsed::Rejected, "stock: {name}");
        assert_eq!(parse(true, &record), Parsed::Rejected, "native: {name}");
    }
}

/// With no `server_name` extension both acceptors report no name, and an
/// acceptor that did not opt in never exposes a raw name.
#[test]
fn absent_sni_and_opt_in_gating() {
    let record = client_hello(None);
    assert_eq!(parse(false, &record), hello(None, None));
    assert_eq!(parse(true, &record), hello(None, None));

    // Opting in is per acceptor: a stock acceptor handed a perfectly valid raw
    // name still reports `raw_server_name() == None`.
    let record = client_hello(Some(&server_name_body(&[(HOST_NAME, b"example.com")])));
    match parse(false, &record) {
        Parsed::Hello { raw, .. } => assert_eq!(raw, None),
        Parsed::Rejected => panic!("stock acceptor must accept an ordinary ClientHello"),
    }
}

/// The record can arrive in arbitrary fragments; the native acceptor must reach
/// the same answer when the ClientHello is delivered one byte at a time.
#[test]
fn native_acceptor_handles_a_byte_at_a_time_record() {
    let record = client_hello(Some(&server_name_body(&[
        (OTHER_NAME_TYPE, b"skip"),
        (HOST_NAME, b"example.com"),
    ])));
    let mut acceptor = Acceptor::default().go_server_client_hello();
    let mut accepted = None;
    for byte in &record {
        let mut one: &[u8] = std::slice::from_ref(byte);
        acceptor.read_tls(&mut one).expect("buffer one byte");
        if let Some(done) = acceptor.accept().expect("no decode error") {
            accepted = Some(done);
            break;
        }
    }
    let accepted = accepted.expect("ClientHello completes before the record ends");
    assert_eq!(
        accepted.client_hello().raw_server_name(),
        Some(&b"example.com"[..])
    );
}
