//! WireGuard tunnel test node.
//!
//! This binary can be run on multiple machines to test the mesh networking layer.
//!
//! Usage:
//!   # Generate keys:
//!   cargo run --example tunnel_node -- keygen
//!
//!   # On machine 1 (responder):
//!   cargo run --example tunnel_node -- responder --listen 0.0.0.0:51820
//!
//!   # On machine 2 (initiator):
//!   cargo run --example tunnel_node -- initiator --peer-pubkey <PEER_PUB> --peer-endpoint <IP:PORT>

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use base64::prelude::*;
use boringtun::noise::{Tunn, TunnResult};
use headscale_core::keys_wg::WgKeyPair;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "help" | "--help" | "-h" => print_usage(),
        "keygen" => keygen(),
        "initiator" => run_initiator(&args[2..]),
        "responder" => run_responder(&args[2..]),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
        }
    }
}

fn print_usage() {
    println!(
        r#"
WireGuard Tunnel Test Node

COMMANDS:
    keygen                      Generate a new WireGuard keypair
    initiator [OPTIONS]         Run as initiator (client)
    responder [OPTIONS]         Run as responder (server)

INITIATOR OPTIONS:
    --peer-pubkey <KEY>         Peer's public key (base64)
    --peer-endpoint <IP:PORT>   Peer's UDP endpoint
    --listen <IP:PORT>          Local listen address (default: 0.0.0.0:51821)
    --secret <KEY>              Use specific secret key (base64)

RESPONDER OPTIONS:
    --listen <IP:PORT>          Local listen address (default: 0.0.0.0:51820)
    --secret <KEY>              Use specific secret key (base64)

EXAMPLES:
    # Generate keys on both machines:
    cargo run --example tunnel_node -- keygen

    # On machine 1 (responder):
    cargo run --example tunnel_node -- responder --listen 0.0.0.0:51820

    # On machine 2 (initiator):
    cargo run --example tunnel_node -- initiator \
        --peer-pubkey <RESPONDER_PUB_KEY> \
        --peer-endpoint 192.168.1.100:51820
"#
    );
}

fn keygen() {
    let keypair = WgKeyPair::generate();
    println!("Generated WireGuard keypair:");
    println!(
        "  Private key: {}",
        BASE64_STANDARD.encode(keypair.secret_bytes())
    );
    println!("  Public key:  {}", keypair.public_key_base64());
    println!();
    println!("Share the public key with your peer.");
}

fn parse_args(
    args: &[String],
) -> (
    SocketAddr,
    Option<String>,
    Option<SocketAddr>,
    Option<String>,
) {
    let mut listen_addr: SocketAddr = "0.0.0.0:51820".parse().unwrap();
    let mut peer_pubkey: Option<String> = None;
    let mut peer_endpoint: Option<SocketAddr> = None;
    let mut secret_key: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--listen" => {
                i += 1;
                if i < args.len() {
                    listen_addr = args[i].parse().expect("Invalid listen address");
                }
            }
            "--peer-pubkey" => {
                i += 1;
                if i < args.len() {
                    peer_pubkey = Some(args[i].clone());
                }
            }
            "--peer-endpoint" => {
                i += 1;
                if i < args.len() {
                    peer_endpoint = Some(args[i].parse().expect("Invalid peer endpoint"));
                }
            }
            "--secret" => {
                i += 1;
                if i < args.len() {
                    secret_key = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    (listen_addr, peer_pubkey, peer_endpoint, secret_key)
}

fn get_or_generate_keypair(secret_key: Option<String>) -> WgKeyPair {
    match secret_key {
        Some(key) => {
            let bytes = BASE64_STANDARD
                .decode(&key)
                .expect("Invalid base64 secret key");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            WgKeyPair::from_secret(arr)
        }
        None => WgKeyPair::generate(),
    }
}

fn run_responder(args: &[String]) {
    let (listen_addr, _, _, secret_key) = parse_args(args);

    println!("=== WireGuard Responder ===");
    println!("Listen address: {}", listen_addr);

    // Generate or use provided keypair
    let keypair = get_or_generate_keypair(secret_key);
    println!("Our public key: {}", keypair.public_key_base64());
    println!(
        "Our private key: {}",
        BASE64_STANDARD.encode(keypair.secret_bytes())
    );
    println!();
    println!("Share the PUBLIC key with the initiator.");
    println!("Waiting for incoming connections...");
    println!();

    // Bind UDP socket
    let socket = UdpSocket::bind(listen_addr).expect("Failed to bind socket");
    socket.set_read_timeout(Some(Duration::from_secs(1))).ok();

    let mut buf = [0u8; 2048];
    let mut dst_buf = [0u8; 2048];

    // We need peer info, so we'll wait for the first packet and create tunnel dynamically
    // For simplicity, we'll prompt for peer pubkey
    println!("Enter initiator's public key (base64):");
    let mut peer_pubkey_input = String::new();
    std::io::stdin()
        .read_line(&mut peer_pubkey_input)
        .expect("Failed to read input");
    let peer_pubkey_input = peer_pubkey_input.trim();

    let peer_key_bytes = BASE64_STANDARD
        .decode(peer_pubkey_input)
        .expect("Invalid peer public key");
    let peer_key_array: [u8; 32] = peer_key_bytes
        .try_into()
        .expect("Public key must be 32 bytes");
    let peer_key = x25519_dalek::PublicKey::from(peer_key_array);

    // Create tunnel (boringtun 0.7.x `Tunn::new` returns `Self`, not `Result`)
    let mut tunn = Tunn::new(
        keypair.secret_key_x25519(),
        peer_key,
        None,     // preshared key
        Some(25), // persistent keepalive
        0,        // index
        None,     // rate limiter
    );

    println!("Tunnel created, waiting for handshake...");

    let mut peer_addr: Option<SocketAddr> = None;
    let start = Instant::now();

    loop {
        // Handle incoming packets
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                println!("[RECV] {} bytes from {}", len, src);
                peer_addr = Some(src);

                match tunn.decapsulate(None, &buf[..len], &mut dst_buf) {
                    TunnResult::Done => {
                        println!("[INFO] Packet processed (no output)");
                    }
                    TunnResult::WriteToNetwork(data) => {
                        socket.send_to(data, src).ok();
                        println!("[SEND] {} bytes to {}", data.len(), src);
                    }
                    TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                        println!(
                            "[DATA] Received {} bytes: {:?}",
                            data.len(),
                            String::from_utf8_lossy(data)
                        );

                        // Echo it back
                        let echo_msg = format!("ECHO: {}", String::from_utf8_lossy(data));
                        let mut echo_buf = [0u8; 2048];
                        if let TunnResult::WriteToNetwork(response) =
                            tunn.encapsulate(echo_msg.as_bytes(), &mut echo_buf)
                        {
                            socket.send_to(response, src).ok();
                            println!("[ECHO] Sent {} bytes back", response.len());
                        }
                    }
                    TunnResult::Err(e) => {
                        println!("[ERROR] Decapsulate error: {:?}", e);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout - run timer tick
                if let TunnResult::WriteToNetwork(data) = tunn.update_timers(&mut dst_buf)
                    && let Some(addr) = peer_addr
                {
                    socket.send_to(data, addr).ok();
                    println!("[TIMER] Sent {} bytes", data.len());
                }
            }
            Err(e) => {
                eprintln!("[ERROR] Socket error: {}", e);
            }
        }

        // Run for 120 seconds
        if start.elapsed() > Duration::from_secs(120) {
            println!("\n[DONE] Test complete after 120 seconds");
            break;
        }
    }
}

fn run_initiator(args: &[String]) {
    let (mut listen_addr, peer_pubkey, peer_endpoint, secret_key) = parse_args(args);

    // Default to different port for initiator
    if listen_addr.port() == 51820 {
        listen_addr.set_port(51821);
    }

    let peer_pubkey = peer_pubkey.expect("--peer-pubkey is required");
    let peer_endpoint = peer_endpoint.expect("--peer-endpoint is required");

    println!("=== WireGuard Initiator ===");
    println!("Listen address: {}", listen_addr);
    println!("Peer endpoint: {}", peer_endpoint);
    println!("Peer pubkey: {}", peer_pubkey);

    // Generate or use provided keypair
    let keypair = get_or_generate_keypair(secret_key);
    println!("Our public key: {}", keypair.public_key_base64());
    println!();

    // Parse peer public key
    let peer_key_bytes = BASE64_STANDARD
        .decode(&peer_pubkey)
        .expect("Invalid peer public key");
    let peer_key_array: [u8; 32] = peer_key_bytes
        .try_into()
        .expect("Public key must be 32 bytes");
    let peer_key = x25519_dalek::PublicKey::from(peer_key_array);

    // Create tunnel (boringtun 0.7.x `Tunn::new` returns `Self`, not `Result`)
    let mut tunn = Tunn::new(
        keypair.secret_key_x25519(),
        peer_key,
        None,     // preshared key
        Some(25), // persistent keepalive every 25s
        0,        // index
        None,     // rate limiter
    );

    // Bind UDP socket
    let socket = UdpSocket::bind(listen_addr).expect("Failed to bind socket");
    socket.set_read_timeout(Some(Duration::from_secs(1))).ok();

    let mut buf = [0u8; 2048];
    let mut dst_buf = [0u8; 2048];

    // Initiate handshake
    println!("[INFO] Initiating handshake...");
    match tunn.format_handshake_initiation(&mut dst_buf, false) {
        TunnResult::WriteToNetwork(data) => {
            socket
                .send_to(data, peer_endpoint)
                .expect("Failed to send handshake");
            println!("[SEND] Handshake initiation ({} bytes)", data.len());
        }
        _ => {
            eprintln!("[ERROR] Failed to create handshake");
            return;
        }
    }

    let mut handshake_complete = false;
    let start = Instant::now();
    let mut last_ping = Instant::now();
    let mut ping_count = 0;

    loop {
        // Handle incoming packets
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                println!("[RECV] {} bytes from {}", len, src);

                match tunn.decapsulate(None, &buf[..len], &mut dst_buf) {
                    TunnResult::Done => {
                        if !handshake_complete {
                            handshake_complete = true;
                            println!("[SUCCESS] Handshake complete! Tunnel established.");
                            println!();
                        }
                    }
                    TunnResult::WriteToNetwork(data) => {
                        socket.send_to(data, peer_endpoint).ok();
                        println!("[SEND] {} bytes (handshake response)", data.len());
                        if !handshake_complete {
                            handshake_complete = true;
                            println!("[SUCCESS] Handshake complete! Tunnel established.");
                            println!();
                        }
                    }
                    TunnResult::WriteToTunnelV4(data, _) | TunnResult::WriteToTunnelV6(data, _) => {
                        println!(
                            "[DATA] Received {} bytes: {:?}",
                            data.len(),
                            String::from_utf8_lossy(data)
                        );
                    }
                    TunnResult::Err(e) => {
                        println!("[ERROR] Decapsulate error: {:?}", e);
                    }
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Timeout - run timer tick
                if let TunnResult::WriteToNetwork(data) = tunn.update_timers(&mut dst_buf) {
                    socket.send_to(data, peer_endpoint).ok();
                    println!("[TIMER] Sent {} bytes", data.len());
                }
            }
            Err(e) => {
                eprintln!("[ERROR] Socket error: {}", e);
            }
        }

        // Send test data periodically after handshake
        if handshake_complete && last_ping.elapsed() > Duration::from_secs(5) {
            ping_count += 1;
            let test_data = format!(
                "PING #{} from initiator at {:?}",
                ping_count,
                start.elapsed()
            );

            match tunn.encapsulate(test_data.as_bytes(), &mut dst_buf) {
                TunnResult::WriteToNetwork(encrypted) => {
                    socket.send_to(encrypted, peer_endpoint).ok();
                    println!(
                        "[PING] Sent: {} ({} encrypted bytes)",
                        test_data,
                        encrypted.len()
                    );
                }
                _ => {
                    println!("[WARN] Could not encapsulate ping");
                }
            }
            last_ping = Instant::now();
        }

        // Exit after 60 seconds
        if start.elapsed() > Duration::from_secs(60) {
            println!();
            println!("[DONE] Test complete after 60 seconds");
            println!(
                "  Handshake: {}",
                if handshake_complete {
                    "SUCCESS"
                } else {
                    "FAILED"
                }
            );
            println!("  Pings sent: {}", ping_count);
            break;
        }
    }
}
