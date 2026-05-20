//! Unit tests for the embedded DERP layer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use axum::http::StatusCode;

use super::*;
use crate::tailscale_wire::derp::stun::{
    ATTR_XOR_MAPPED_ADDRESS, FAMILY_IPV4, FAMILY_IPV6, MSG_TYPE_BINDING_REQUEST,
    MSG_TYPE_BINDING_RESPONSE, STUN_MAGIC_COOKIE, decode_stun_binding_request,
    encode_stun_binding_response,
};

fn make_binding_request(txid: [u8; 12]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(20);
    pkt.extend_from_slice(&MSG_TYPE_BINDING_REQUEST.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    pkt.extend_from_slice(&txid);
    pkt
}

fn enabled_cfg(host: &str) -> DerpConfig {
    DerpConfig {
        enabled: true,
        host_name: host.to_string(),
        ..DerpConfig::default()
    }
}

#[test]
fn stun_decode_binding_request_extracts_txid() {
    let txid = *b"abcdefghijkl";
    let pkt = make_binding_request(txid);
    let got = decode_stun_binding_request(&pkt).unwrap();
    assert_eq!(got, txid);
}

#[test]
fn stun_decode_rejects_truncated_packet() {
    let pkt = vec![0u8; 12];
    assert!(matches!(
        decode_stun_binding_request(&pkt),
        Err(stun::StunError::Truncated)
    ));
}

#[test]
fn stun_decode_rejects_bad_magic() {
    let mut pkt = make_binding_request([0u8; 12]);
    pkt[4] = 0xff;
    assert!(matches!(
        decode_stun_binding_request(&pkt),
        Err(stun::StunError::BadMagic)
    ));
}

#[test]
fn stun_decode_rejects_wrong_type() {
    let mut pkt = make_binding_request([0u8; 12]);
    pkt[0] = 0x01;
    pkt[1] = 0x11;
    assert!(matches!(
        decode_stun_binding_request(&pkt),
        Err(stun::StunError::UnsupportedType(_))
    ));
}

#[test]
fn stun_v4_response_round_trip() {
    let txid = *b"0123456789ab";
    let remote: SocketAddr = "203.0.113.7:54321".parse().unwrap();
    let resp = encode_stun_binding_response(txid, remote);
    assert_eq!(resp.len(), 32);
    assert_eq!(
        u16::from_be_bytes([resp[0], resp[1]]),
        MSG_TYPE_BINDING_RESPONSE
    );
    let msg_len = u16::from_be_bytes([resp[2], resp[3]]);
    assert_eq!(msg_len, 12);
    let cookie = u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]);
    assert_eq!(cookie, STUN_MAGIC_COOKIE);
    assert_eq!(&resp[8..20], &txid);
    let attr_type = u16::from_be_bytes([resp[20], resp[21]]);
    assert_eq!(attr_type, ATTR_XOR_MAPPED_ADDRESS);
    let attr_len = u16::from_be_bytes([resp[22], resp[23]]);
    assert_eq!(attr_len, 8);
    assert_eq!(resp[24], 0);
    assert_eq!(resp[25], FAMILY_IPV4);
    let x_port = u16::from_be_bytes([resp[26], resp[27]]);
    // 54321 in hex literal form — clippy::decimal_bitwise_operands rejects
    // `54321u16 ^ …`. The encoded port in the binding-response uses the
    // remote endpoint's port (54321) XOR-ed with the top 16 bits of
    // STUN's magic cookie.
    let expected = 0xD431_u16 ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    assert_eq!(x_port, expected);
    let x_addr = u32::from_be_bytes([resp[28], resp[29], resp[30], resp[31]]);
    let ip_raw = u32::from(Ipv4Addr::new(203, 0, 113, 7));
    assert_eq!(x_addr, ip_raw ^ STUN_MAGIC_COOKIE);
}

#[test]
fn stun_v6_response_uses_family_v6_and_full_xor_mask() {
    let txid = *b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b";
    let remote: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
    let resp = encode_stun_binding_response(txid, remote);
    assert_eq!(resp.len(), 44);
    let attr_len = u16::from_be_bytes([resp[22], resp[23]]);
    assert_eq!(attr_len, 20);
    assert_eq!(resp[24], 0);
    assert_eq!(resp[25], FAMILY_IPV6);
    let mut mask = [0u8; 16];
    mask[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
    mask[4..16].copy_from_slice(&txid);
    let mut recovered = [0u8; 16];
    for i in 0..16 {
        recovered[i] = resp[28 + i] ^ mask[i];
    }
    assert_eq!(IpAddr::V6(Ipv6Addr::from(recovered)), remote.ip());
}

#[test]
fn stun_handle_packet_drops_unknown_gracefully() {
    let pkt = b"GET / HTTP/1.1\r\n\r\n";
    let res = stun::StunListener::handle_packet(pkt, "127.0.0.1:1".parse().unwrap()).unwrap();
    assert!(res.is_none());
}

#[test]
fn stun_handle_packet_returns_response_for_valid_request() {
    let txid = *b"AAAABBBBCCCC";
    let pkt = make_binding_request(txid);
    let remote: SocketAddr = "198.51.100.42:1234".parse().unwrap();
    let resp = stun::StunListener::handle_packet(&pkt, remote)
        .unwrap()
        .expect("valid request must produce a response");
    assert_eq!(&resp[8..20], &txid);
}

#[tokio::test]
async fn stun_listener_round_trip_over_udp() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = stun::StunListener::bind(addr).await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_local = client.local_addr().unwrap();
    let txid = *b"txid12345678";
    let pkt = make_binding_request(txid);
    client.send_to(&pkt, server_addr).await.unwrap();

    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut buf),
    )
    .await
    .expect("timeout")
    .expect("recv");
    let resp = &buf[..n];
    assert_eq!(
        u16::from_be_bytes([resp[0], resp[1]]),
        MSG_TYPE_BINDING_RESPONSE
    );
    assert_eq!(&resp[8..20], &txid);
    assert_eq!(resp[25], FAMILY_IPV4);
    let x_port = u16::from_be_bytes([resp[26], resp[27]]);
    let decoded_port = x_port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
    assert_eq!(decoded_port, client_local.port());
    let x_addr = u32::from_be_bytes([resp[28], resp[29], resp[30], resp[31]]);
    let decoded_ip = Ipv4Addr::from(x_addr ^ STUN_MAGIC_COOKIE);
    assert_eq!(IpAddr::V4(decoded_ip), client_local.ip());
}

#[test]
fn config_disabled_yields_empty_region() {
    let cfg = DerpConfig::disabled();
    assert!(!cfg.enabled);
    assert!(cfg.derp_region().is_none());
}

#[test]
fn config_enabled_yields_region_with_stun_port() {
    let cfg = DerpConfig {
        enabled: true,
        host_name: "derp.example.com".into(),
        derp_port: 443,
        stun_addr: Some("0.0.0.0:3478".parse().unwrap()),
        region_id: 901,
        region_code: "test".into(),
        region_name: "Test Region".into(),
        ..DerpConfig::default()
    };
    let region = cfg.derp_region().expect("region populated");
    assert_eq!(region.region_id, 901);
    assert_eq!(region.region_code, "test");
    assert_eq!(region.nodes.len(), 1);
    let node = &region.nodes[0];
    assert_eq!(node.host_name, "derp.example.com");
    assert_eq!(node.region_id, 901);
    assert_eq!(node.name, "901");
    assert_eq!(node.derp_port, 0);
    assert_eq!(node.stun_port, 3478);
}

#[test]
fn config_non_default_derp_port_round_trips() {
    let cfg = DerpConfig {
        enabled: true,
        host_name: "derp.example.com".into(),
        derp_port: 8443,
        ..DerpConfig::default()
    };
    let region = cfg.derp_region().unwrap();
    assert_eq!(region.nodes[0].derp_port, 8443);
}

#[test]
fn config_round_trips_through_toml() {
    let block = r#"
        enabled = true
        host_name = "relay.example.org"
        derp_port = 443
        sidecar_listen_addr = "127.0.0.1:8443"
        derper_binary = "/usr/local/bin/derper"
        stun_addr = "0.0.0.0:3478"
        region_id = 950
        region_code = "us-w-1"
        region_name = "US West"
    "#;
    let cfg: DerpConfig = toml::from_str(block).unwrap();
    assert!(cfg.enabled);
    assert_eq!(cfg.host_name, "relay.example.org");
    assert_eq!(cfg.derp_port, 443);
    assert_eq!(cfg.region_id, 950);
    assert_eq!(
        cfg.sidecar_listen_addr,
        "127.0.0.1:8443".parse::<SocketAddr>().unwrap()
    );
    assert!(cfg.has_sidecar());
    let region = cfg.derp_region().unwrap();
    assert_eq!(region.region_code, "us-w-1");
}

#[test]
fn config_empty_block_disables_layer() {
    let cfg: DerpConfig = toml::from_str("").unwrap();
    assert!(!cfg.enabled);
    assert!(cfg.stun_addr.is_none());
    assert!(!cfg.has_sidecar());
}

#[tokio::test]
async fn derp_server_disabled_skips_stun_bind() {
    let cfg = DerpConfig::disabled();
    let srv = DerpServer::start(cfg).await.unwrap();
    assert!(srv.stun_local_addr().is_none());
    assert!(srv.sidecar_status().is_none());
}

#[tokio::test]
async fn derp_server_enabled_binds_stun_when_configured() {
    let cfg = DerpConfig {
        stun_addr: Some("127.0.0.1:0".parse().unwrap()),
        ..enabled_cfg("derp.local")
    };
    let srv = DerpServer::start(cfg).await.unwrap();
    let stun_addr = srv.stun_local_addr().expect("stun bound");
    assert_eq!(stun_addr.ip().to_string(), "127.0.0.1");
    assert_ne!(stun_addr.port(), 0);
}

#[tokio::test]
async fn derp_server_missing_binary_does_not_crash_startup() {
    let cfg = DerpConfig {
        derper_binary: std::path::PathBuf::from("/nonexistent/derper"),
        ..enabled_cfg("derp.local")
    };
    let srv = DerpServer::start(cfg).await.unwrap();
    assert!(srv.sidecar_status().is_none());
}

#[test]
fn bootstrap_dns_response_is_a_json_map() {
    let mut r = BootstrapDnsResponse::default();
    r.insert(
        "derp.example.org",
        vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))],
    );
    let s = serde_json::to_string(&r).unwrap();
    assert!(s.starts_with('{'));
    assert!(s.contains("derp.example.org"));
    assert!(s.contains("192.0.2.1"));
    let back: BootstrapDnsResponse = serde_json::from_str(&s).unwrap();
    assert_eq!(back.get("derp.example.org"), r.get("derp.example.org"));
}

#[test]
fn verify_request_response_serde_shape() {
    let req: VerifyRequest =
        serde_json::from_str(r#"{"ClientPublic":"nodekey:abc"}"#).unwrap();
    assert_eq!(req.client_public, "nodekey:abc");
    let resp = VerifyResponse { allow: true };
    let s = serde_json::to_string(&resp).unwrap();
    assert_eq!(s, r#"{"Allow":true}"#);
}

#[tokio::test]
async fn router_disabled_is_empty() {
    let state = DerpHttpState::disabled();
    let r = router(state);
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;
    let req = Request::builder()
        .uri("/derp/probe")
        .body(Body::empty())
        .unwrap();
    let resp = r.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn router_probe_returns_200_with_cors() {
    let state = DerpHttpState::new(enabled_cfg("derp.local"));
    let r = router(state);
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;
    let req = Request::builder()
        .uri("/derp/probe")
        .body(Body::empty())
        .unwrap();
    let resp = r.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cors = resp
        .headers()
        .get("access-control-allow-origin")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(cors, "*");
}

#[tokio::test]
async fn router_verify_allows_well_formed_key() {
    let state = DerpHttpState::new(enabled_cfg("derp.local"));
    let r = router(state);
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let body = serde_json::to_vec(&VerifyRequest {
        client_public: "nodekey:1234".into(),
    })
    .unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/verify")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = r.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(parsed.allow);
}

#[tokio::test]
async fn router_verify_rejects_empty_key() {
    let state = DerpHttpState::new(enabled_cfg("derp.local"));
    let r = router(state);
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let body = serde_json::to_vec(&VerifyRequest {
        client_public: String::new(),
    })
    .unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/verify")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = r.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: VerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(!parsed.allow);
}

#[tokio::test]
async fn router_derp_placeholder_503_when_sidecar_absent() {
    let state = DerpHttpState::new(enabled_cfg("derp.local"));
    let r = router(state);
    use axum::body::Body;
    use http::Request;
    use tower::ServiceExt;
    let req = Request::builder()
        .uri("/derp")
        .body(Body::empty())
        .unwrap();
    let resp = r.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn router_bootstrap_dns_cached_hit_returns_map() {
    let state = DerpHttpState::new(enabled_cfg("derp.example.org"));
    {
        let mut w = state.bootstrap_dns.write();
        w.insert(
            "derp.example.org",
            vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))],
        );
    }
    let r = router(state);
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let req = Request::builder()
        .uri("/bootstrap-dns")
        .body(Body::empty())
        .unwrap();
    let resp = r.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let parsed: BootstrapDnsResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(
        parsed.get("derp.example.org"),
        Some(&vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))])
    );
}
