//! STUN endpoint discovery test against public servers.
//!
//! Tests NAT traversal by discovering our public endpoint.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use headscale_core::stun::{build_binding_request, parse_binding_response};
use rand_core::{OsRng, RngCore};

const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

fn generate_transaction_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    OsRng.fill_bytes(&mut id);
    id
}

fn main() {
    println!("=== STUN Endpoint Discovery Test ===\n");

    // Bind to a local UDP socket
    let socket = UdpSocket::bind("0.0.0.0:0").expect("Failed to bind socket");
    socket.set_read_timeout(Some(Duration::from_secs(3))).ok();

    let local_addr = socket.local_addr().unwrap();
    println!("Local socket: {local_addr}\n");

    let mut success_count = 0;

    for server in STUN_SERVERS {
        println!("Testing STUN server: {server}");

        // Resolve server address
        let server_addr: SocketAddr = match std::net::ToSocketAddrs::to_socket_addrs(server) {
            Ok(mut addrs) => {
                if let Some(addr) = addrs.next() {
                    addr
                } else {
                    println!("  [FAIL] Could not resolve {server}\n");
                    continue;
                }
            }
            Err(e) => {
                println!("  [FAIL] DNS error: {e}\n");
                continue;
            }
        };

        // Generate transaction ID and build request
        let txn_id = generate_transaction_id();
        let request = build_binding_request(&txn_id);

        if let Err(e) = socket.send_to(&request, server_addr) {
            println!("  [FAIL] Send error: {e}\n");
            continue;
        }
        println!("  Sent binding request ({} bytes)", request.len());

        // Receive response
        let mut buf = [0u8; 1024];
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                println!("  Received {len} bytes from {from}");

                // Parse the response
                match parse_binding_response(&buf[..len], &txn_id) {
                    Ok(mapped_addr) => {
                        println!("  [SUCCESS] Mapped address: {mapped_addr}");
                        println!("  Our public endpoint is: {mapped_addr}\n");
                        success_count += 1;
                    }
                    Err(e) => {
                        println!("  [FAIL] Parse error: {e}\n");
                    }
                }
            }
            Err(e) => {
                println!("  [FAIL] Receive timeout/error: {e}\n");
            }
        }
    }

    println!("=== Test Complete ===");
    println!(
        "Successful discoveries: {}/{}",
        success_count,
        STUN_SERVERS.len()
    );

    if success_count > 0 {
        println!("\nSTUN endpoint discovery is working!");
    } else {
        println!("\nNo STUN servers responded. Check network connectivity.");
    }
}
