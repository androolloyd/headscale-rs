//! WireGuard tunnel management using boringtun.
//!
//! This module provides a high-level interface for managing WireGuard tunnels
//! with multiple peers using the userspace boringtun implementation.

use crate::keys_wg::WgKeyPair;
use crate::routing::{Route, RoutingTable, host_route};
use boringtun::noise::{Tunn, TunnResult};
use ipnet::IpNet;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;
use tokio::sync::{RwLock, broadcast};

/// Default WireGuard port.
pub const DEFAULT_WG_PORT: u16 = 51820;

/// Maximum transmission unit for WireGuard packets.
pub const WG_MTU: usize = 1420;

/// Buffer size for packet handling.
pub const PACKET_BUFFER_SIZE: usize = 2048;

/// Tunnel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    /// No active session.
    Disconnected,
    /// Handshake in progress.
    Connecting,
    /// Active session established.
    Connected,
    /// Connection failed.
    Failed,
}

/// Statistics for a tunnel.
#[derive(Debug, Clone, Default)]
pub struct TunnelStats {
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub tx_packets: usize,
    pub rx_packets: usize,
    pub last_handshake: Option<Instant>,
    pub last_rx: Option<Instant>,
    pub last_tx: Option<Instant>,
}

/// A single WireGuard tunnel to a peer.
pub struct Tunnel {
    /// The boringtun tunnel instance.
    tunn: Tunn,
    /// Peer identifier (DID or node ID).
    peer_id: String,
    /// Peer's WireGuard public key.
    peer_public_key: [u8; 32],
    /// Current endpoint for the peer.
    endpoint: Option<SocketAddr>,
    /// Allowed IPs for this peer (CIDR prefixes).
    allowed_ips: Vec<IpNet>,
    /// Current tunnel state.
    state: TunnelState,
    /// Tunnel statistics.
    stats: TunnelStats,
    /// Persistent keepalive interval (seconds).
    #[allow(dead_code)]
    keepalive: Option<u16>,
}

impl Tunnel {
    /// Create a new tunnel to a peer.
    pub fn new(
        local_keypair: &WgKeyPair,
        peer_id: String,
        peer_public_key: [u8; 32],
        index: u32,
        keepalive: Option<u16>,
    ) -> Result<Self, TunnelError> {
        // Convert our key types to boringtun types
        let static_secret = boringtun::x25519::StaticSecret::from(local_keypair.secret_bytes());
        let peer_public = boringtun::x25519::PublicKey::from(peer_public_key);

        // boringtun 0.7.x changed `Tunn::new` to be infallible (returns `Self`
        // directly instead of `Result<Self, _>`). Keep the function signature
        // `Result<Self, TunnelError>` for forward compat with peer-id /
        // keypair validation that the caller still relies on.
        let tunn = Tunn::new(static_secret, peer_public, None, keepalive, index, None);

        Ok(Self {
            tunn,
            peer_id,
            peer_public_key,
            endpoint: None,
            allowed_ips: Vec::new(),
            state: TunnelState::Disconnected,
            stats: TunnelStats::default(),
            keepalive,
        })
    }

    /// Get the peer ID.
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Get the peer's public key.
    pub fn peer_public_key(&self) -> &[u8; 32] {
        &self.peer_public_key
    }

    /// Get the current endpoint.
    pub fn endpoint(&self) -> Option<SocketAddr> {
        self.endpoint
    }

    /// Set the endpoint for this peer.
    pub fn set_endpoint(&mut self, endpoint: SocketAddr) {
        self.endpoint = Some(endpoint);
    }

    /// Get the current state.
    pub fn state(&self) -> TunnelState {
        self.state
    }

    /// Get tunnel statistics.
    pub fn stats(&self) -> &TunnelStats {
        &self.stats
    }

    /// Get allowed IPs (CIDR prefixes).
    pub fn allowed_ips(&self) -> &[IpNet] {
        &self.allowed_ips
    }

    /// Add an allowed IP prefix.
    pub fn add_allowed_ip(&mut self, prefix: IpNet) {
        if !self.allowed_ips.contains(&prefix) {
            self.allowed_ips.push(prefix);
        }
    }

    /// Add a host route (/32 for IPv4, /128 for IPv6).
    pub fn add_allowed_host(&mut self, ip: IpAddr) {
        let prefix = host_route(ip);
        self.add_allowed_ip(prefix);
    }

    /// Encapsulate an IP packet for sending to the peer.
    ///
    /// Returns the encrypted WireGuard packet to send over UDP.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let result = self.tunn.encapsulate(src, dst);

        match &result {
            TunnResult::WriteToNetwork(_) => {
                self.stats.tx_packets += 1;
                self.stats.tx_bytes += src.len();
                self.stats.last_tx = Some(Instant::now());
                if self.state == TunnelState::Disconnected {
                    self.state = TunnelState::Connecting;
                }
            }
            TunnResult::Err(_) => {
                self.state = TunnelState::Failed;
            }
            // `Done` (no action) and any new boringtun variant fall through.
            _ => {}
        }

        result
    }

    /// Decapsulate a WireGuard packet received from the network.
    ///
    /// Returns the decrypted IP packet to write to the TUN device.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        let result = self.tunn.decapsulate(src_addr, datagram, dst);

        match &result {
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                self.stats.rx_packets += 1;
                self.stats.last_rx = Some(Instant::now());
                if self.state != TunnelState::Connected {
                    self.state = TunnelState::Connected;
                    self.stats.last_handshake = Some(Instant::now());
                }
            }
            TunnResult::WriteToNetwork(_) => {
                // Response packet (handshake or keepalive)
                self.stats.tx_packets += 1;
                self.stats.last_tx = Some(Instant::now());
            }
            TunnResult::Done | TunnResult::Err(_) => {}
        }

        result
    }

    /// Generate a handshake initiation packet.
    pub fn initiate_handshake<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.state = TunnelState::Connecting;
        self.tunn.format_handshake_initiation(dst, false)
    }

    /// Handle timer updates (keepalives, retransmissions).
    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunn.update_timers(dst)
    }

    /// Check if the tunnel has expired.
    pub fn is_expired(&self) -> bool {
        self.tunn.is_expired()
    }
}

/// Manages multiple WireGuard tunnels.
pub struct TunnelManager {
    /// Our WireGuard key pair.
    local_keypair: WgKeyPair,
    /// Active tunnels indexed by peer ID.
    tunnels: RwLock<HashMap<String, Tunnel>>,
    /// Peer public key to peer ID mapping.
    pubkey_to_peer: RwLock<HashMap<[u8; 32], String>>,
    /// Routing table with LPM support for CIDR routes.
    routing_table: Arc<RwLock<RoutingTable>>,
    /// Counter for generating unique tunnel indices.
    next_index: AtomicU32,
    /// Event sender for tunnel state changes.
    event_tx: broadcast::Sender<TunnelEvent>,
    /// UDP listen port.
    listen_port: u16,
}

/// Events emitted by the tunnel manager.
#[derive(Debug, Clone)]
pub enum TunnelEvent {
    /// A new tunnel was created.
    TunnelCreated { peer_id: String },
    /// Tunnel state changed.
    StateChanged {
        peer_id: String,
        old_state: TunnelState,
        new_state: TunnelState,
    },
    /// Tunnel was removed.
    TunnelRemoved { peer_id: String },
    /// Handshake completed.
    HandshakeComplete { peer_id: String },
    /// Endpoint changed.
    EndpointChanged {
        peer_id: String,
        endpoint: SocketAddr,
    },
}

impl TunnelManager {
    /// Create a new tunnel manager.
    pub fn new(local_keypair: WgKeyPair, listen_port: u16) -> Self {
        let (event_tx, _) = broadcast::channel(256);

        Self {
            local_keypair,
            tunnels: RwLock::new(HashMap::new()),
            pubkey_to_peer: RwLock::new(HashMap::new()),
            routing_table: Arc::new(RwLock::new(RoutingTable::new())),
            next_index: AtomicU32::new(1),
            event_tx,
            listen_port,
        }
    }

    /// Get a reference to the routing table.
    pub fn routing_table(&self) -> Arc<RwLock<RoutingTable>> {
        self.routing_table.clone()
    }

    /// Get the local public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.local_keypair.public_key_bytes()
    }

    /// Get the local public key in base64.
    pub fn public_key_base64(&self) -> String {
        self.local_keypair.public_key_base64()
    }

    /// Get the listen port.
    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// Subscribe to tunnel events.
    pub fn subscribe(&self) -> broadcast::Receiver<TunnelEvent> {
        self.event_tx.subscribe()
    }

    /// Add a new peer tunnel.
    ///
    /// `allowed_ips` can be CIDR prefixes (e.g., "10.0.0.0/24", "0.0.0.0/0").
    /// For host routes, use /32 (IPv4) or /128 (IPv6).
    pub async fn add_peer(
        &self,
        peer_id: String,
        peer_public_key: [u8; 32],
        endpoint: Option<SocketAddr>,
        allowed_ips: Vec<IpNet>,
        keepalive: Option<u16>,
    ) -> Result<(), TunnelError> {
        let index = self.next_index.fetch_add(1, Ordering::SeqCst);

        let mut tunnel = Tunnel::new(
            &self.local_keypair,
            peer_id.clone(),
            peer_public_key,
            index,
            keepalive,
        )?;

        tunnel.endpoint = endpoint;
        for prefix in &allowed_ips {
            tunnel.add_allowed_ip(*prefix);
        }

        // Update mappings
        {
            let mut tunnels = self.tunnels.write().await;
            tunnels.insert(peer_id.clone(), tunnel);
        }
        {
            let mut pubkey_map = self.pubkey_to_peer.write().await;
            pubkey_map.insert(peer_public_key, peer_id.clone());
        }
        {
            // Add routes to the routing table
            let mut routing = self.routing_table.write().await;
            for prefix in allowed_ips {
                routing.add_route(Route {
                    prefix,
                    peer_id: peer_id.clone(),
                    priority: 0,
                    approved: true,
                    advertised: false,
                });
            }
        }

        let _ = self.event_tx.send(TunnelEvent::TunnelCreated {
            peer_id: peer_id.clone(),
        });

        tracing::info!(
            peer_id = %peer_id,
            public_key = %base64_encode(&peer_public_key),
            "Added peer tunnel"
        );

        Ok(())
    }

    /// Add a peer with simple host IPs (convenience method).
    ///
    /// Each IP is converted to a /32 (IPv4) or /128 (IPv6) host route.
    pub async fn add_peer_with_ips(
        &self,
        peer_id: String,
        peer_public_key: [u8; 32],
        endpoint: Option<SocketAddr>,
        ips: Vec<IpAddr>,
        keepalive: Option<u16>,
    ) -> Result<(), TunnelError> {
        let allowed_ips: Vec<IpNet> = ips.into_iter().map(host_route).collect();
        self.add_peer(peer_id, peer_public_key, endpoint, allowed_ips, keepalive)
            .await
    }

    /// Remove a peer tunnel.
    pub async fn remove_peer(&self, peer_id: &str) -> Result<(), TunnelError> {
        let tunnel = {
            let mut tunnels = self.tunnels.write().await;
            tunnels.remove(peer_id)
        };

        if let Some(tunnel) = tunnel {
            // Remove from pubkey mapping
            {
                let mut pubkey_map = self.pubkey_to_peer.write().await;
                pubkey_map.remove(&tunnel.peer_public_key);
            }
            // Remove all routes for this peer
            {
                let mut routing = self.routing_table.write().await;
                routing.remove_peer_routes(peer_id);
            }

            let _ = self.event_tx.send(TunnelEvent::TunnelRemoved {
                peer_id: peer_id.to_string(),
            });

            tracing::info!(peer_id = %peer_id, "Removed peer tunnel");
            Ok(())
        } else {
            Err(TunnelError::PeerNotFound(peer_id.to_string()))
        }
    }

    /// Update a peer's endpoint.
    pub async fn update_endpoint(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
    ) -> Result<(), TunnelError> {
        let mut tunnels = self.tunnels.write().await;
        let tunnel = tunnels
            .get_mut(peer_id)
            .ok_or_else(|| TunnelError::PeerNotFound(peer_id.to_string()))?;

        tunnel.set_endpoint(endpoint);

        let _ = self.event_tx.send(TunnelEvent::EndpointChanged {
            peer_id: peer_id.to_string(),
            endpoint,
        });

        Ok(())
    }

    /// Get a peer's tunnel state.
    pub async fn get_state(&self, peer_id: &str) -> Option<TunnelState> {
        let tunnels = self.tunnels.read().await;
        tunnels.get(peer_id).map(Tunnel::state)
    }

    /// Get tunnel statistics for a peer.
    pub async fn get_stats(&self, peer_id: &str) -> Option<TunnelStats> {
        let tunnels = self.tunnels.read().await;
        tunnels.get(peer_id).map(|t| t.stats().clone())
    }

    /// Get all peer IDs.
    pub async fn list_peers(&self) -> Vec<String> {
        let tunnels = self.tunnels.read().await;
        tunnels.keys().cloned().collect()
    }

    /// Find which peer should receive a packet based on destination IP.
    ///
    /// Uses longest-prefix-match: the most specific route wins.
    /// Supports /32 host routes, subnet routes, and 0.0.0.0/0 default routes.
    pub async fn route_by_ip(&self, dst_ip: IpAddr) -> Option<String> {
        let routing = self.routing_table.read().await;
        routing.lookup(dst_ip).map(std::string::ToString::to_string)
    }

    /// Check whether a peer is allowed to send packets claiming `ip` as source.
    pub async fn peer_allows_ip(&self, peer_id: &str, ip: IpAddr) -> Result<bool, TunnelError> {
        let tunnels = self.tunnels.read().await;
        let tunnel = tunnels
            .get(peer_id)
            .ok_or_else(|| TunnelError::PeerNotFound(peer_id.to_string()))?;

        Ok(tunnel.allowed_ips.iter().any(|prefix| prefix.contains(&ip)))
    }

    /// Add an advertised route for a peer (e.g., subnet route or exit route).
    ///
    /// The route is not used until approved.
    pub async fn advertise_route(
        &self,
        peer_id: &str,
        prefix: IpNet,
        approved: bool,
    ) -> Result<(), TunnelError> {
        // Verify peer exists
        {
            let tunnels = self.tunnels.read().await;
            if !tunnels.contains_key(peer_id) {
                return Err(TunnelError::PeerNotFound(peer_id.to_string()));
            }
        }

        let mut routing = self.routing_table.write().await;
        routing.add_route(Route {
            prefix,
            peer_id: peer_id.to_string(),
            priority: 100, // Advertised routes have lower priority than direct routes
            approved,
            advertised: true,
        });

        tracing::info!(
            peer_id = %peer_id,
            prefix = %prefix,
            approved = approved,
            "Route advertised"
        );

        Ok(())
    }

    /// Approve or revoke an advertised route.
    pub async fn set_route_approved(
        &self,
        peer_id: &str,
        prefix: &IpNet,
        approved: bool,
    ) -> Result<(), TunnelError> {
        let mut routing = self.routing_table.write().await;

        // Remove and re-add with new approval status
        routing.remove_route(prefix, peer_id);
        routing.add_route(Route {
            prefix: *prefix,
            peer_id: peer_id.to_string(),
            priority: 100,
            approved,
            advertised: true,
        });

        tracing::info!(
            peer_id = %peer_id,
            prefix = %prefix,
            approved = approved,
            "Route approval updated"
        );

        Ok(())
    }

    /// Find a peer by their public key.
    pub async fn peer_by_pubkey(&self, pubkey: &[u8; 32]) -> Option<String> {
        let pubkey_map = self.pubkey_to_peer.read().await;
        pubkey_map.get(pubkey).cloned()
    }

    /// Encapsulate a packet for a specific peer.
    pub async fn encapsulate_for_peer<'a>(
        &self,
        peer_id: &str,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Result<EncapsulateResult<'a>, TunnelError> {
        let mut tunnels = self.tunnels.write().await;
        let tunnel = tunnels
            .get_mut(peer_id)
            .ok_or_else(|| TunnelError::PeerNotFound(peer_id.to_string()))?;

        let endpoint = tunnel.endpoint;
        let result = tunnel.encapsulate(src, dst);

        Ok(EncapsulateResult { result, endpoint })
    }

    /// Decapsulate a packet from the network for a specific peer.
    pub async fn decapsulate_for_peer<'a>(
        &self,
        peer_id: &str,
        src_addr: SocketAddr,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, TunnelError> {
        let mut tunnels = self.tunnels.write().await;
        let tunnel = tunnels
            .get_mut(peer_id)
            .ok_or_else(|| TunnelError::PeerNotFound(peer_id.to_string()))?;

        let result = tunnel.decapsulate(Some(src_addr.ip()), datagram, dst);

        // Update endpoint if we got valid data
        match &result {
            TunnResult::WriteToTunnelV4(_, _)
            | TunnResult::WriteToTunnelV6(_, _)
            | TunnResult::WriteToNetwork(_)
                if tunnel.endpoint != Some(src_addr) =>
            {
                tunnel.set_endpoint(src_addr);
                let _ = self.event_tx.send(TunnelEvent::EndpointChanged {
                    peer_id: peer_id.to_string(),
                    endpoint: src_addr,
                });
            }
            _ => {}
        }

        Ok(result)
    }

    /// Find which peer a packet belongs to by receiver index.
    ///
    /// WireGuard packets contain a receiver index that identifies the tunnel.
    pub async fn find_peer_for_packet(&self, datagram: &[u8]) -> Option<String> {
        if datagram.len() < 8 {
            return None;
        }

        // Get receiver index from the packet (bytes 4-7 for most packet types)
        let packet_type = u32::from_le_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]);

        // packet_type 1 = handshake init (no receiver index, must try all peers);
        // 2..=4 = handshake response / cookie reply / data — we have a receiver
        // index but the caller still tries all peers today; everything else is
        // unknown. All three branches collapse to "let caller fan out", so we
        // just return `None` unconditionally and keep `packet_type` for the
        // logging that will hang off this site once receiver-index lookup lands.
        let _ = packet_type;
        None
    }

    /// Run timer updates for all tunnels.
    ///
    /// Returns packets that need to be sent (keepalives, handshake retries).
    pub async fn tick(&self) -> Vec<(String, SocketAddr, Vec<u8>)> {
        let mut packets = Vec::new();
        let mut tunnels = self.tunnels.write().await;

        for (peer_id, tunnel) in tunnels.iter_mut() {
            let mut buf = vec![0u8; PACKET_BUFFER_SIZE];
            // `Done` and any other (Err / new boringtun) variant ends the tick
            // for this tunnel.
            while let TunnResult::WriteToNetwork(data) = tunnel.update_timers(&mut buf) {
                if let Some(endpoint) = tunnel.endpoint {
                    packets.push((peer_id.clone(), endpoint, data.to_vec()));
                }
            }
        }

        packets
    }

    /// Initiate handshake with a peer.
    pub async fn initiate_handshake(
        &self,
        peer_id: &str,
    ) -> Result<(SocketAddr, Vec<u8>), TunnelError> {
        let mut tunnels = self.tunnels.write().await;
        let tunnel = tunnels
            .get_mut(peer_id)
            .ok_or_else(|| TunnelError::PeerNotFound(peer_id.to_string()))?;

        let endpoint = tunnel
            .endpoint
            .ok_or_else(|| TunnelError::NoEndpoint(peer_id.to_string()))?;

        let mut buf = vec![0u8; PACKET_BUFFER_SIZE];
        match tunnel.initiate_handshake(&mut buf) {
            TunnResult::WriteToNetwork(data) => Ok((endpoint, data.to_vec())),
            TunnResult::Err(e) => Err(TunnelError::Handshake(format!("{e:?}"))),
            _ => Err(TunnelError::Handshake("Unexpected result".to_string())),
        }
    }
}

/// Result of encapsulating a packet.
pub struct EncapsulateResult<'a> {
    pub result: TunnResult<'a>,
    pub endpoint: Option<SocketAddr>,
}

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("Failed to create tunnel: {0}")]
    Creation(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("No endpoint configured for peer: {0}")]
    NoEndpoint(String),

    #[error("Unknown packet (no matching peer)")]
    UnknownPacket,

    #[error("Handshake failed: {0}")]
    Handshake(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64::prelude::*;
    BASE64_STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_tunnel_manager_creation() {
        let keypair = WgKeyPair::generate();
        let manager = TunnelManager::new(keypair, DEFAULT_WG_PORT);

        assert_eq!(manager.listen_port(), DEFAULT_WG_PORT);
        assert!(!manager.public_key_base64().is_empty());
    }

    #[tokio::test]
    async fn test_add_remove_peer() {
        let local_keypair = WgKeyPair::generate();
        let peer_keypair = WgKeyPair::generate();
        let manager = TunnelManager::new(local_keypair, DEFAULT_WG_PORT);

        let peer_id = "test-peer".to_string();
        let endpoint = "10.0.0.2:51820".parse().unwrap();

        // Add peer with host route
        manager
            .add_peer_with_ips(
                peer_id.clone(),
                peer_keypair.public_key_bytes(),
                Some(endpoint),
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
                Some(25),
            )
            .await
            .unwrap();

        // Verify peer exists
        let peers = manager.list_peers().await;
        assert_eq!(peers.len(), 1);
        assert!(peers.contains(&peer_id));

        // Check state
        let state = manager.get_state(&peer_id).await;
        assert_eq!(state, Some(TunnelState::Disconnected));

        // Remove peer. `Box::pin` to keep the test future small —
        // `remove_peer` carries the full Tunn state on the stack and the
        // `large_futures` lint complains otherwise.
        Box::pin(manager.remove_peer(&peer_id)).await.unwrap();
        let peers = manager.list_peers().await;
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn test_ip_routing() {
        let local_keypair = WgKeyPair::generate();
        let peer_keypair = WgKeyPair::generate();
        let manager = TunnelManager::new(local_keypair, DEFAULT_WG_PORT);

        let peer_id = "routed-peer".to_string();
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));

        manager
            .add_peer_with_ips(
                peer_id.clone(),
                peer_keypair.public_key_bytes(),
                None,
                vec![peer_ip],
                None,
            )
            .await
            .unwrap();

        // Routing should work
        let routed = manager.route_by_ip(peer_ip).await;
        assert_eq!(routed, Some(peer_id.clone()));

        // Unknown IP should not route
        let unknown = manager
            .route_by_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
            .await;
        assert_eq!(unknown, None);
    }

    #[tokio::test]
    async fn test_peer_source_ip_ownership() {
        let local_keypair = WgKeyPair::generate();
        let peer_keypair = WgKeyPair::generate();
        let manager = TunnelManager::new(local_keypair, DEFAULT_WG_PORT);

        let peer_id = "owned-peer".to_string();
        manager
            .add_peer_with_ips(
                peer_id.clone(),
                peer_keypair.public_key_bytes(),
                None,
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))],
                None,
            )
            .await
            .unwrap();

        assert!(
            manager
                .peer_allows_ip(&peer_id, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
                .await
                .unwrap()
        );
        assert!(
            !manager
                .peer_allows_ip(&peer_id, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6)))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_subnet_routing() {
        let local_keypair = WgKeyPair::generate();
        let peer_keypair = WgKeyPair::generate();
        let manager = TunnelManager::new(local_keypair, DEFAULT_WG_PORT);

        let peer_id = "subnet-peer".to_string();

        // Add peer with subnet route
        manager
            .add_peer(
                peer_id.clone(),
                peer_keypair.public_key_bytes(),
                None,
                vec!["192.168.1.0/24".parse().unwrap()],
                None,
            )
            .await
            .unwrap();

        // Any IP in subnet should route
        assert_eq!(
            manager
                .route_by_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)))
                .await,
            Some(peer_id.clone())
        );
        assert_eq!(
            manager
                .route_by_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)))
                .await,
            Some(peer_id.clone())
        );

        // IP outside subnet should not route
        assert_eq!(
            manager
                .route_by_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1)))
                .await,
            None
        );
    }

    #[tokio::test]
    async fn test_longest_prefix_match() {
        let local_keypair = WgKeyPair::generate();
        let manager = TunnelManager::new(local_keypair, DEFAULT_WG_PORT);

        // Add exit node with default route
        let exit_keypair = WgKeyPair::generate();
        manager
            .add_peer(
                "exit-node".to_string(),
                exit_keypair.public_key_bytes(),
                None,
                vec!["0.0.0.0/0".parse().unwrap()],
                None,
            )
            .await
            .unwrap();

        // Add peer with specific host route
        let peer_keypair = WgKeyPair::generate();
        manager
            .add_peer(
                "specific-peer".to_string(),
                peer_keypair.public_key_bytes(),
                None,
                vec!["10.0.0.5/32".parse().unwrap()],
                None,
            )
            .await
            .unwrap();

        // Specific route should win
        assert_eq!(
            manager
                .route_by_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
                .await,
            Some("specific-peer".to_string())
        );

        // Other IPs go to exit
        assert_eq!(
            manager
                .route_by_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
                .await,
            Some("exit-node".to_string())
        );
    }

    #[tokio::test]
    async fn test_advertised_routes() {
        let local_keypair = WgKeyPair::generate();
        let peer_keypair = WgKeyPair::generate();
        let manager = TunnelManager::new(local_keypair, DEFAULT_WG_PORT);

        let peer_id = "exit-peer".to_string();

        // Add peer with host route
        manager
            .add_peer_with_ips(
                peer_id.clone(),
                peer_keypair.public_key_bytes(),
                None,
                vec![IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))],
                None,
            )
            .await
            .unwrap();

        // Advertise exit route (unapproved)
        manager
            .advertise_route(&peer_id, "0.0.0.0/0".parse().unwrap(), false)
            .await
            .unwrap();

        // Should not route through unapproved exit
        assert_eq!(
            manager
                .route_by_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
                .await,
            None
        );

        // Approve the route
        manager
            .set_route_approved(&peer_id, &"0.0.0.0/0".parse().unwrap(), true)
            .await
            .unwrap();

        // Now it should route
        assert_eq!(
            manager
                .route_by_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
                .await,
            Some(peer_id.clone())
        );
    }

    #[tokio::test]
    async fn test_pubkey_lookup() {
        let local_keypair = WgKeyPair::generate();
        let peer_keypair = WgKeyPair::generate();
        let manager = TunnelManager::new(local_keypair, DEFAULT_WG_PORT);

        let peer_id = "pubkey-peer".to_string();
        let peer_pubkey = peer_keypair.public_key_bytes();

        manager
            .add_peer(peer_id.clone(), peer_pubkey, None, vec![], None)
            .await
            .unwrap();

        // Should find by pubkey
        let found = manager.peer_by_pubkey(&peer_pubkey).await;
        assert_eq!(found, Some(peer_id));

        // Unknown pubkey should not find
        let unknown_key = [99u8; 32];
        let not_found = manager.peer_by_pubkey(&unknown_key).await;
        assert_eq!(not_found, None);
    }
}
