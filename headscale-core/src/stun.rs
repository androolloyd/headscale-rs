//! STUN client for NAT traversal and endpoint discovery.
//!
//! Implements a minimal STUN client (RFC 5389) to discover the public
//! IP address and port mappings for NAT traversal.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// Default STUN server port.
pub const STUN_PORT: u16 = 3478;

/// Default timeout for STUN requests.
pub const STUN_TIMEOUT: Duration = Duration::from_secs(3);

/// STUN message types.
pub const STUN_BINDING_REQUEST: u16 = 0x0001;
pub const STUN_BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute types.
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// IPv4 family constant inside MAPPED-ADDRESS/XOR-MAPPED-ADDRESS.
pub const STUN_FAMILY_IPV4: u8 = 0x01;

/// IPv6 family constant inside MAPPED-ADDRESS/XOR-MAPPED-ADDRESS.
pub const STUN_FAMILY_IPV6: u8 = 0x02;

/// STUN magic cookie (RFC 5389).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Well-known public STUN servers.
pub static DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun.cloudflare.com:3478",
];

/// STUN client for discovering public endpoints.
pub struct StunClient {
    /// STUN servers to query.
    servers: Vec<SocketAddr>,
    /// Timeout for STUN requests.
    timeout: Duration,
}

impl StunClient {
    /// Create a new STUN client with default servers.
    pub async fn new() -> Result<Self, StunError> {
        let mut servers = Vec::new();

        for server in DEFAULT_STUN_SERVERS {
            if let Ok(mut addrs) = tokio::net::lookup_host(server).await
                && let Some(addr) = addrs.next()
            {
                servers.push(addr);
            }
        }

        if servers.is_empty() {
            return Err(StunError::NoServers);
        }

        Ok(Self {
            servers,
            timeout: STUN_TIMEOUT,
        })
    }

    /// Create a STUN client with custom servers.
    pub fn with_servers(servers: Vec<SocketAddr>) -> Result<Self, StunError> {
        if servers.is_empty() {
            return Err(StunError::NoServers);
        }

        Ok(Self {
            servers,
            timeout: STUN_TIMEOUT,
        })
    }

    /// Set the timeout for STUN requests.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Discover the public endpoint for a local socket.
    ///
    /// Sends STUN binding requests to discover how our local socket
    /// appears to external servers (reflexive address).
    pub async fn discover_endpoint(&self, socket: &UdpSocket) -> Result<SocketAddr, StunError> {
        for server in &self.servers {
            match self.query_server(socket, *server).await {
                Ok(endpoint) => {
                    tracing::debug!(
                        server = %server,
                        endpoint = %endpoint,
                        "STUN endpoint discovered"
                    );
                    return Ok(endpoint);
                }
                Err(e) => {
                    tracing::debug!(
                        server = %server,
                        error = %e,
                        "STUN server query failed"
                    );
                }
            }
        }

        Err(StunError::AllServersFailed)
    }

    /// Query a single STUN server.
    async fn query_server(
        &self,
        socket: &UdpSocket,
        server: SocketAddr,
    ) -> Result<SocketAddr, StunError> {
        // Generate transaction ID (12 bytes)
        let transaction_id = generate_transaction_id();

        // Build STUN binding request
        let request = build_binding_request(&transaction_id);

        // Send request
        socket.send_to(&request, server).await?;

        // Receive response with timeout
        let mut buf = [0u8; 548]; // STUN max message size
        let (len, _) = timeout(self.timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| StunError::Timeout)??;

        // Parse response
        parse_binding_response(&buf[..len], &transaction_id)
    }

    /// Get the list of STUN servers.
    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }
}

/// Generate a random 12-byte transaction ID.
fn generate_transaction_id() -> [u8; 12] {
    use rand_core::{OsRng, RngCore};
    let mut id = [0u8; 12];
    OsRng.fill_bytes(&mut id);
    id
}

/// Build a STUN binding request message.
/// Exposed as pub for testing.
pub fn build_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);

    // Message Type: Binding Request
    msg.extend_from_slice(&STUN_BINDING_REQUEST.to_be_bytes());

    // Message Length: 0 (no attributes in request)
    msg.extend_from_slice(&0u16.to_be_bytes());

    // Magic Cookie
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());

    // Transaction ID
    msg.extend_from_slice(transaction_id);

    msg
}

/// Parse a STUN binding request and return its transaction ID.
pub fn decode_binding_request(data: &[u8]) -> Result<[u8; 12], StunRequestError> {
    if data.len() < 20 {
        return Err(StunRequestError::Truncated);
    }

    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != STUN_BINDING_REQUEST {
        return Err(StunRequestError::UnsupportedType(msg_type));
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        return Err(StunRequestError::Truncated);
    }

    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunRequestError::BadMagic);
    }

    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&data[8..20]);
    Ok(transaction_id)
}

/// Encode a STUN binding response with one XOR-MAPPED-ADDRESS attribute.
pub fn encode_binding_response(transaction_id: &[u8; 12], addr: SocketAddr) -> Vec<u8> {
    let attr_body = encode_xor_mapped_address(transaction_id, addr);
    let attr_len = attr_body.len() as u16;
    let msg_len = 4 + attr_body.len() as u16;

    let mut msg = Vec::with_capacity(20 + msg_len as usize);
    msg.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
    msg.extend_from_slice(&msg_len.to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(transaction_id);
    msg.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    msg.extend_from_slice(&attr_len.to_be_bytes());
    msg.extend_from_slice(&attr_body);
    msg
}

fn encode_xor_mapped_address(transaction_id: &[u8; 12], addr: SocketAddr) -> Vec<u8> {
    let mut data = Vec::with_capacity(20);
    data.push(0);
    match addr.ip() {
        IpAddr::V4(ip) => {
            data.push(STUN_FAMILY_IPV4);
            let port = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            data.extend_from_slice(&port.to_be_bytes());
            let ip = u32::from(ip) ^ MAGIC_COOKIE;
            data.extend_from_slice(&ip.to_be_bytes());
        }
        IpAddr::V6(ip) => {
            data.push(STUN_FAMILY_IPV6);
            let port = addr.port() ^ ((MAGIC_COOKIE >> 16) as u16);
            data.extend_from_slice(&port.to_be_bytes());

            let mut mask = [0u8; 16];
            mask[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..16].copy_from_slice(transaction_id);

            let raw = ip.octets();
            let mut xored = [0u8; 16];
            for i in 0..16 {
                xored[i] = raw[i] ^ mask[i];
            }
            data.extend_from_slice(&xored);
        }
    }
    data
}

/// UDP STUN binding responder. Drop it to abort the background task.
pub struct StunListener {
    socket: Arc<UdpSocket>,
    handle: JoinHandle<()>,
}

impl StunListener {
    /// Bind a UDP socket and start serving STUN binding requests.
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let task_socket = Arc::clone(&socket);
        let handle = tokio::spawn(async move {
            serve_stun(task_socket).await;
        });

        Ok(Self { socket, handle })
    }

    /// Return the local bound UDP address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Handle one packet. Well-formed binding requests return a response;
    /// non-STUN probe traffic is silently dropped.
    pub fn handle_packet(
        data: &[u8],
        remote: SocketAddr,
    ) -> Result<Option<Vec<u8>>, StunRequestError> {
        match decode_binding_request(data) {
            Ok(transaction_id) => Ok(Some(encode_binding_response(&transaction_id, remote))),
            Err(StunRequestError::Truncated | StunRequestError::BadMagic) => Ok(None),
            Err(err) => Err(err),
        }
    }
}

impl Drop for StunListener {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn serve_stun(socket: Arc<UdpSocket>) {
    let mut buf = vec![0u8; 1500];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, remote)) => {
                if let Ok(Some(response)) = StunListener::handle_packet(&buf[..len], remote) {
                    let _ = socket.send_to(&response, remote).await;
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "STUN listener recv_from failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Parse a STUN binding response and extract the mapped address.
/// Exposed as pub for fuzzing.
pub fn parse_binding_response(
    data: &[u8],
    expected_txn_id: &[u8; 12],
) -> Result<SocketAddr, StunError> {
    if data.len() < 20 {
        return Err(StunError::InvalidResponse("Message too short".to_string()));
    }

    // Check message type
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != STUN_BINDING_RESPONSE {
        return Err(StunError::InvalidResponse(format!(
            "Unexpected message type: 0x{msg_type:04x}"
        )));
    }

    // Check message length
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        return Err(StunError::InvalidResponse("Message truncated".to_string()));
    }

    // Check magic cookie
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::InvalidResponse(
            "Invalid magic cookie".to_string(),
        ));
    }

    // Check transaction ID
    if &data[8..20] != expected_txn_id {
        return Err(StunError::InvalidResponse(
            "Transaction ID mismatch".to_string(),
        ));
    }

    // Parse attributes
    let mut offset = 20;
    while offset + 4 <= data.len() {
        let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        if offset + attr_len > data.len() {
            break;
        }

        let attr_data = &data[offset..offset + attr_len];

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                return parse_xor_mapped_address(attr_data, expected_txn_id);
            }
            ATTR_MAPPED_ADDRESS => {
                return parse_mapped_address(attr_data);
            }
            _ => {} // Ignore unknown attributes
        }

        // Move to next attribute (4-byte aligned)
        offset += (attr_len + 3) & !3;
    }

    Err(StunError::InvalidResponse(
        "No mapped address in response".to_string(),
    ))
}

/// Parse MAPPED-ADDRESS attribute.
/// Exposed as pub for fuzzing.
pub fn parse_mapped_address(data: &[u8]) -> Result<SocketAddr, StunError> {
    if data.len() < 8 {
        return Err(StunError::InvalidResponse(
            "MAPPED-ADDRESS too short".to_string(),
        ));
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            // IPv4
            let ip = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return Err(StunError::InvalidResponse(
                    "IPv6 address too short".to_string(),
                ));
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&data[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(addr.into()), port))
        }
        _ => Err(StunError::InvalidResponse(format!(
            "Unknown address family: {family}"
        ))),
    }
}

/// Parse XOR-MAPPED-ADDRESS attribute per RFC 8489.
///
/// For IPv4: XOR with magic cookie only.
/// For IPv6: XOR with (magic cookie || transaction ID) - the full 16 bytes.
///
/// Exposed as pub for fuzzing.
pub fn parse_xor_mapped_address(
    data: &[u8],
    transaction_id: &[u8; 12],
) -> Result<SocketAddr, StunError> {
    if data.len() < 8 {
        return Err(StunError::InvalidResponse(
            "XOR-MAPPED-ADDRESS too short".to_string(),
        ));
    }

    let family = data[1];
    let xor_port = u16::from_be_bytes([data[2], data[3]]);
    let port = xor_port ^ ((MAGIC_COOKIE >> 16) as u16);

    match family {
        0x01 => {
            // IPv4: XOR with magic cookie (4 bytes)
            let xor_ip = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
            let ip = Ipv4Addr::from(xor_ip ^ MAGIC_COOKIE);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        0x02 => {
            // IPv6: XOR with (magic cookie || transaction ID) per RFC 8489
            // The XOR mask is: magic_cookie (4 bytes) || transaction_id (12 bytes) = 16 bytes
            if data.len() < 20 {
                return Err(StunError::InvalidResponse(
                    "IPv6 address too short".to_string(),
                ));
            }

            // Build the 16-byte XOR mask: magic cookie (4 bytes) + transaction ID (12 bytes)
            let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
            let mut xor_mask = [0u8; 16];
            xor_mask[0..4].copy_from_slice(&cookie_bytes);
            xor_mask[4..16].copy_from_slice(transaction_id);

            // XOR the address with the mask
            let mut addr = [0u8; 16];
            for i in 0..16 {
                addr[i] = data[4 + i] ^ xor_mask[i];
            }

            Ok(SocketAddr::new(IpAddr::V6(addr.into()), port))
        }
        _ => Err(StunError::InvalidResponse(format!(
            "Unknown address family: {family}"
        ))),
    }
}

/// STUN binding-request decode errors for the embedded responder.
#[derive(Debug, thiserror::Error)]
pub enum StunRequestError {
    #[error("packet shorter than a 20-byte STUN header")]
    Truncated,

    #[error("not a STUN message: invalid magic cookie")]
    BadMagic,

    #[error("unsupported STUN message type 0x{0:04x}")]
    UnsupportedType(u16),
}

#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error("No STUN servers configured")]
    NoServers,

    #[error("All STUN servers failed")]
    AllServersFailed,

    #[error("STUN request timed out")]
    Timeout,

    #[error("Invalid STUN response: {0}")]
    InvalidResponse(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request() {
        let txn_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let request = build_binding_request(&txn_id);

        assert_eq!(request.len(), 20);
        assert_eq!(request[0..2], STUN_BINDING_REQUEST.to_be_bytes());
        assert_eq!(request[2..4], [0, 0]); // Length = 0
        assert_eq!(request[4..8], MAGIC_COOKIE.to_be_bytes());
        assert_eq!(request[8..20], txn_id);
    }

    #[test]
    fn test_decode_binding_request_extracts_transaction_id() {
        let txn_id = *b"abcdefghijkl";
        let request = build_binding_request(&txn_id);

        assert_eq!(decode_binding_request(&request).unwrap(), txn_id);
    }

    #[test]
    fn test_decode_binding_request_rejects_bad_magic() {
        let txn_id = [0u8; 12];
        let mut request = build_binding_request(&txn_id);
        request[4] = 0xff;

        assert!(matches!(
            decode_binding_request(&request),
            Err(StunRequestError::BadMagic)
        ));
    }

    #[test]
    fn test_parse_mapped_address_v4() {
        // Family: IPv4, Port: 12345, IP: 1.2.3.4
        let data = [0x00, 0x01, 0x30, 0x39, 1, 2, 3, 4];
        let addr = parse_mapped_address(&data).unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 12345)
        );
    }

    #[test]
    fn test_parse_xor_mapped_address_v4() {
        // Port: 0x3039 XOR 0x2112 = 0x112B (4395)
        // IP: 0x01020304 XOR 0x2112A442 = 0x2010A746
        let txn_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let xor_port = 0x3039u16 ^ ((MAGIC_COOKIE >> 16) as u16);
        let xor_ip = (1u32 << 24 | 2 << 16 | 3 << 8 | 4) ^ MAGIC_COOKIE;

        let mut data = [0u8; 8];
        data[1] = 0x01; // IPv4
        data[2..4].copy_from_slice(&xor_port.to_be_bytes());
        data[4..8].copy_from_slice(&xor_ip.to_be_bytes());

        let addr = parse_xor_mapped_address(&data, &txn_id).unwrap();
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 12345)
        );
    }

    #[test]
    fn test_parse_xor_mapped_address_v6() {
        // Test IPv6 XOR-MAPPED-ADDRESS per RFC 8489
        // The IPv6 address is XOR'd with (magic cookie || transaction ID)
        use std::net::Ipv6Addr;

        let txn_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let port = 54321u16;
        let ipv6 = Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
        );

        // Build the XOR mask: magic cookie (4 bytes) || transaction ID (12 bytes)
        let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
        let mut xor_mask = [0u8; 16];
        xor_mask[0..4].copy_from_slice(&cookie_bytes);
        xor_mask[4..16].copy_from_slice(&txn_id);

        // XOR the port with top 16 bits of magic cookie
        let xor_port = port ^ ((MAGIC_COOKIE >> 16) as u16);

        // XOR the IPv6 address with the full mask
        let ipv6_bytes = ipv6.octets();
        let mut xor_ipv6 = [0u8; 16];
        for i in 0..16 {
            xor_ipv6[i] = ipv6_bytes[i] ^ xor_mask[i];
        }

        // Build the attribute data
        let mut data = [0u8; 20];
        data[0] = 0x00; // Reserved
        data[1] = 0x02; // IPv6 family
        data[2..4].copy_from_slice(&xor_port.to_be_bytes());
        data[4..20].copy_from_slice(&xor_ipv6);

        // Parse and verify we get the original address back
        let addr = parse_xor_mapped_address(&data, &txn_id).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V6(ipv6), port));
    }

    #[test]
    fn test_parse_binding_response() {
        let txn_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

        // Build a valid response with XOR-MAPPED-ADDRESS
        let mut response = Vec::new();

        // Header
        response.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        response.extend_from_slice(&12u16.to_be_bytes()); // Length
        response.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response.extend_from_slice(&txn_id);

        // XOR-MAPPED-ADDRESS attribute
        response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response.extend_from_slice(&8u16.to_be_bytes()); // Attr length

        let port = 12345u16;
        let xor_port = port ^ ((MAGIC_COOKIE >> 16) as u16);
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let xor_ip = u32::from(ip) ^ MAGIC_COOKIE;

        response.push(0x00); // Reserved
        response.push(0x01); // IPv4
        response.extend_from_slice(&xor_port.to_be_bytes());
        response.extend_from_slice(&xor_ip.to_be_bytes());

        let addr = parse_binding_response(&response, &txn_id).unwrap();
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(ip), port));
    }

    #[test]
    fn test_encode_binding_response_round_trips_v4() {
        let txn_id = *b"txid12345678";
        let remote: SocketAddr = "198.51.100.42:54321".parse().unwrap();

        let response = encode_binding_response(&txn_id, remote);
        let parsed = parse_binding_response(&response, &txn_id).unwrap();

        assert_eq!(parsed, remote);
        assert_eq!(response[25], STUN_FAMILY_IPV4);
    }

    #[test]
    fn test_stun_listener_handle_packet_drops_non_stun_probe() {
        let response =
            StunListener::handle_packet(b"GET / HTTP/1.1\r\n\r\n", "127.0.0.1:1".parse().unwrap())
                .unwrap();

        assert!(response.is_none());
    }

    #[tokio::test]
    async fn test_stun_listener_round_trip_over_udp() {
        let listener = StunListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let server_addr = listener.local_addr().unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let txn_id = *b"udp123456789";
        let request = build_binding_request(&txn_id);

        client.send_to(&request, server_addr).await.unwrap();
        let mut buf = [0u8; 1500];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let response = &buf[..len];

        assert_eq!(
            parse_binding_response(response, &txn_id).unwrap(),
            client_addr
        );
    }
}
