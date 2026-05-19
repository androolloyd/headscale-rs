//! Packet routing between TUN device and WireGuard tunnels.
//!
//! This module provides the PacketRouter which handles the flow of IP packets
//! between the local TUN device and encrypted WireGuard tunnels to peers.

use crate::acl::{AclContext, AclDestination, AclEvaluator};
use crate::authorization::{ForwardDecision, authorize_forward};
use crate::tun_device::{TunDevice, TunError};
use crate::tunnel::{PACKET_BUFFER_SIZE, TunnelManager};
use boringtun::noise::TunnResult;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;

/// Events emitted by the packet router.
#[derive(Debug, Clone)]
pub enum RouterEvent {
    /// Packet sent to a peer.
    PacketSent { peer_id: String, bytes: usize },
    /// Packet received from a peer.
    PacketReceived { peer_id: String, bytes: usize },
    /// Error occurred while routing.
    Error { message: String },
}

/// Routes packets between TUN device and WireGuard tunnels.
pub struct PacketRouter {
    /// UDP socket for WireGuard traffic.
    socket: Arc<UdpSocket>,
    /// Tunnel manager for handling WireGuard encryption.
    tunnel_manager: Arc<TunnelManager>,
    /// Event sender.
    event_tx: broadcast::Sender<RouterEvent>,
}

impl PacketRouter {
    /// Create a new packet router.
    pub async fn new(
        tunnel_manager: Arc<TunnelManager>,
        bind_addr: SocketAddr,
    ) -> Result<Self, RouterError> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let (event_tx, _) = broadcast::channel(256);

        tracing::info!(bind_addr = %bind_addr, "Packet router UDP socket bound");

        Ok(Self {
            socket: Arc::new(socket),
            tunnel_manager,
            event_tx,
        })
    }

    /// Subscribe to router events.
    pub fn subscribe(&self) -> broadcast::Receiver<RouterEvent> {
        self.event_tx.subscribe()
    }

    /// Get the local UDP address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Get a reference to the tunnel manager.
    pub fn tunnel_manager(&self) -> &Arc<TunnelManager> {
        &self.tunnel_manager
    }

    /// Send an IP packet to a peer.
    ///
    /// The packet is encrypted using the WireGuard tunnel and sent over UDP.
    /// This is a low-level primitive: callers must perform ACL and routing
    /// authorization before calling it. Prefer [`Self::send_authorized`] for
    /// policy-aware forwarding.
    pub async fn send_to_peer(&self, peer_id: &str, packet: &[u8]) -> Result<(), RouterError> {
        let mut buf = vec![0u8; PACKET_BUFFER_SIZE];

        let result = self
            .tunnel_manager
            .encapsulate_for_peer(peer_id, packet, &mut buf)
            .await?;

        match result.result {
            TunnResult::WriteToNetwork(data) => {
                if let Some(endpoint) = result.endpoint {
                    self.socket.send_to(data, endpoint).await?;
                    let _ = self.event_tx.send(RouterEvent::PacketSent {
                        peer_id: peer_id.to_string(),
                        bytes: packet.len(),
                    });
                    Ok(())
                } else {
                    Err(RouterError::NoEndpoint(peer_id.to_string()))
                }
            }
            TunnResult::Err(e) => Err(RouterError::Tunnel(format!("{e:?}"))),
            _ => Ok(()), // Done or other result
        }
    }

    /// Authorize and send an IP packet using ACL evaluation and approved routing.
    pub async fn send_authorized(
        &self,
        acl: &AclEvaluator,
        ctx: &AclContext,
        packet: &[u8],
    ) -> Result<ForwardDecision, RouterError> {
        let dst_ip = parse_destination(packet).ok_or(RouterError::InvalidPacket)?;
        let dst = AclDestination::ip_only(dst_ip);
        let routing = self.tunnel_manager.routing_table();
        let routes = routing.read().await;
        let decision = authorize_forward(acl, &routes, ctx, &dst);
        drop(routes);

        if let ForwardDecision::Allow { peer_id } = &decision {
            self.send_to_peer(peer_id, packet).await?;
        }

        Ok(decision)
    }

    /// Receive a packet from the network and decrypt it.
    ///
    /// Returns the decrypted IP packet and source peer info.
    pub async fn recv(&self) -> Result<ReceivedPacket, RouterError> {
        let mut udp_buf = vec![0u8; PACKET_BUFFER_SIZE];
        let mut decrypt_buf = vec![0u8; PACKET_BUFFER_SIZE];

        loop {
            let (len, src_addr) = self.socket.recv_from(&mut udp_buf).await?;
            let datagram = &udp_buf[..len];

            // Try to find the peer this packet belongs to
            // For now, try all peers (could optimize with receiver index lookup)
            let peers = self.tunnel_manager.list_peers().await;

            for peer_id in peers {
                match self
                    .tunnel_manager
                    .decapsulate_for_peer(&peer_id, src_addr, datagram, &mut decrypt_buf)
                    .await
                {
                    Ok(TunnResult::WriteToTunnelV4(data, addr)) => {
                        let src_ip = parse_source(data).unwrap_or(IpAddr::V4(addr));
                        if !self
                            .tunnel_manager
                            .peer_allows_ip(&peer_id, src_ip)
                            .await
                            .unwrap_or(false)
                        {
                            let _ = self.event_tx.send(RouterEvent::Error {
                                message: format!(
                                    "Rejected packet from {peer_id}: unauthorized source {src_ip}"
                                ),
                            });
                            continue;
                        }
                        let _ = self.event_tx.send(RouterEvent::PacketReceived {
                            peer_id: peer_id.clone(),
                            bytes: data.len(),
                        });
                        return Ok(ReceivedPacket {
                            data: data.to_vec(),
                            src_ip: IpAddr::V4(addr),
                            peer_id,
                        });
                    }
                    Ok(TunnResult::WriteToTunnelV6(data, addr)) => {
                        let src_ip = parse_source(data).unwrap_or(IpAddr::V6(addr));
                        if !self
                            .tunnel_manager
                            .peer_allows_ip(&peer_id, src_ip)
                            .await
                            .unwrap_or(false)
                        {
                            let _ = self.event_tx.send(RouterEvent::Error {
                                message: format!(
                                    "Rejected packet from {peer_id}: unauthorized source {src_ip}"
                                ),
                            });
                            continue;
                        }
                        let _ = self.event_tx.send(RouterEvent::PacketReceived {
                            peer_id: peer_id.clone(),
                            bytes: data.len(),
                        });
                        return Ok(ReceivedPacket {
                            data: data.to_vec(),
                            src_ip: IpAddr::V6(addr),
                            peer_id,
                        });
                    }
                    Ok(TunnResult::WriteToNetwork(response)) => {
                        // Handshake response or keepalive - send it back
                        self.socket.send_to(response, src_addr).await?;
                    }
                    // Done = not for this peer; Err/Decrypt errors = skip and try
                    // the next peer. The outer `for` advances on fall-through.
                    Ok(TunnResult::Done | TunnResult::Err(_)) | Err(_) => {}
                }
            }
            // Packet didn't match any peer, continue listening
        }
    }

    /// Send a handshake initiation to a peer.
    pub async fn initiate_handshake(&self, peer_id: &str) -> Result<(), RouterError> {
        let (endpoint, data) = self.tunnel_manager.initiate_handshake(peer_id).await?;
        self.socket.send_to(&data, endpoint).await?;
        Ok(())
    }

    /// Run timer tick for all tunnels and send any pending packets.
    pub async fn tick(&self) -> Result<usize, RouterError> {
        let packets = self.tunnel_manager.tick().await;
        let mut sent = 0;

        for (peer_id, endpoint, data) in packets {
            if let Err(e) = self.socket.send_to(&data, endpoint).await {
                tracing::warn!(
                    peer_id = %peer_id,
                    error = %e,
                    "Failed to send timer packet"
                );
            } else {
                sent += 1;
            }
        }

        Ok(sent)
    }

    /// Run the packet router main loop.
    ///
    /// This spawns tasks for:
    /// - Receiving packets from network and writing to TUN
    /// - Timer ticks for keepalives
    pub async fn run(
        self: Arc<Self>,
        mut tun_device: TunDevice,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<(), RouterError> {
        let router = self.clone();

        // Spawn network receive task
        let net_router = router.clone();
        let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

        let net_handle = tokio::spawn(async move {
            loop {
                match net_router.recv().await {
                    Ok(packet) => {
                        if tun_tx.send(packet.data).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Network receive error");
                    }
                }
            }
        });

        // Spawn timer tick task
        let tick_router = router.clone();
        let tick_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
            loop {
                interval.tick().await;
                if let Err(e) = tick_router.tick().await {
                    tracing::warn!(error = %e, "Timer tick error");
                }
            }
        });

        // Main loop: write decrypted packets to TUN device
        loop {
            tokio::select! {
                Some(packet) = tun_rx.recv() => {
                    if let Err(e) = tun_device.write(&packet).await {
                        tracing::warn!(error = %e, "TUN write error");
                    }
                }
                _ = shutdown.recv() => {
                    tracing::info!("Packet router shutting down");
                    break;
                }
            }
        }

        net_handle.abort();
        tick_handle.abort();

        Ok(())
    }

    /// Run the packet router with policy-aware outbound forwarding.
    ///
    /// This mode reads packets from TUN, authorizes each packet with
    /// [`Self::send_authorized`], and only then encrypts and sends it to the
    /// selected peer. Inbound decrypted packets are still source-checked before
    /// they are written to TUN.
    #[cfg(not(target_os = "windows"))]
    pub async fn run_authorized(
        self: Arc<Self>,
        tun_device: TunDevice,
        acl: Arc<AclEvaluator>,
        local_ctx: Arc<AclContext>,
        mut shutdown: broadcast::Receiver<()>,
    ) -> Result<(), RouterError> {
        let (mut tun_reader, mut tun_writer) = tun_device.split();

        let net_router = self.clone();
        let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
        let net_handle = tokio::spawn(async move {
            loop {
                match net_router.recv().await {
                    Ok(packet) => {
                        if tun_tx.send(packet.data).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Network receive error");
                    }
                }
            }
        });

        let tick_router = self.clone();
        let tick_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(250));
            loop {
                interval.tick().await;
                if let Err(e) = tick_router.tick().await {
                    tracing::warn!(error = %e, "Timer tick error");
                }
            }
        });

        let outbound_router = self.clone();
        let outbound_acl = acl.clone();
        let outbound_ctx = local_ctx.clone();
        let mut outbound_shutdown = shutdown.resubscribe();
        let outbound_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; PACKET_BUFFER_SIZE];
            loop {
                tokio::select! {
                    read = tun_reader.read(&mut buf) => {
                        match read {
                            Ok(0) => {}
                            Ok(len) => {
                                match outbound_router
                                    .send_authorized(&outbound_acl, &outbound_ctx, &buf[..len])
                                    .await
                                {
                                    Ok(ForwardDecision::Allow { .. }) => {}
                                    Ok(decision) => {
                                        tracing::debug!(?decision, "Outbound packet denied");
                                    }
                                    Err(e) => {
                                        tracing::warn!(error = %e, "Outbound packet send error");
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(error = %e, "TUN read error");
                            }
                        }
                    }
                    _ = outbound_shutdown.recv() => break,
                }
            }
        });

        loop {
            tokio::select! {
                Some(packet) = tun_rx.recv() => {
                    if let Err(e) = tun_writer.write(&packet).await {
                        tracing::warn!(error = %e, "TUN write error");
                    }
                }
                _ = shutdown.recv() => {
                    tracing::info!("Policy-aware packet router shutting down");
                    break;
                }
            }
        }

        net_handle.abort();
        tick_handle.abort();
        outbound_handle.abort();

        Ok(())
    }
}

/// A packet received from a peer.
#[derive(Debug)]
pub struct ReceivedPacket {
    /// The decrypted IP packet data.
    pub data: Vec<u8>,
    /// Source IP address from the packet.
    pub src_ip: IpAddr,
    /// The peer ID that sent this packet.
    pub peer_id: String,
}

/// Parse destination IP from an IP packet.
pub fn parse_destination(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    match packet[0] >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ))),
        6 if packet.len() >= 40 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(addr)))
        }
        _ => None,
    }
}

/// Parse source IP from an IP packet.
pub fn parse_source(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    match packet[0] >> 4 {
        4 if packet.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ))),
        6 if packet.len() >= 40 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&packet[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(addr)))
        }
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TUN error: {0}")]
    Tun(#[from] TunError),

    #[error("Tunnel error: {0}")]
    Tunnel(String),

    #[error("No endpoint for peer: {0}")]
    NoEndpoint(String),

    #[error("Invalid IP packet")]
    InvalidPacket,
}

impl From<crate::tunnel::TunnelError> for RouterError {
    fn from(e: crate::tunnel::TunnelError) -> Self {
        Self::Tunnel(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AclPolicy, AclRule, Route, RoutingTable, WgKeyPair};
    use ipnet::IpNet;

    #[test]
    fn test_parse_ipv4_destination() {
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // IPv4
        packet[16] = 10;
        packet[17] = 0;
        packet[18] = 0;
        packet[19] = 1;

        assert_eq!(
            parse_destination(&packet),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn test_parse_ipv4_source() {
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // IPv4
        packet[12] = 192;
        packet[13] = 168;
        packet[14] = 1;
        packet[15] = 100;

        assert_eq!(
            parse_source(&packet),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)))
        );
    }

    #[test]
    fn test_parse_ipv6() {
        let mut packet = [0u8; 40];
        packet[0] = 0x60; // IPv6

        // Source: ::1
        packet[23] = 1;

        // Destination: ::2
        packet[39] = 2;

        assert_eq!(parse_source(&packet), Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));

        assert_eq!(
            parse_destination(&packet),
            Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2)))
        );
    }

    #[test]
    fn test_invalid_packets() {
        assert_eq!(parse_destination(&[]), None);
        assert_eq!(parse_source(&[]), None);
        assert_eq!(parse_destination(&[0u8; 10]), None);
    }

    #[test]
    fn test_authorization_contract_selects_routed_peer() {
        let acl = AclEvaluator::new(AclPolicy {
            acls: vec![AclRule {
                action: crate::AclAction::Accept,
                src: vec!["user:node-a".to_string()],
                dst: vec!["10.0.0.2:*".to_string()],
                proto: None,
            }],
            ..AclPolicy::deny_all()
        });
        let mut routes = RoutingTable::new();
        routes.add_route(Route {
            prefix: "10.0.0.2/32".parse::<IpNet>().unwrap(),
            peer_id: "peer-a".to_string(),
            priority: 0,
            approved: true,
            advertised: false,
        });
        let ctx = AclContext::from_node("node-a", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let dst = AclDestination::ip_only(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));

        assert_eq!(
            authorize_forward(&acl, &routes, &ctx, &dst),
            ForwardDecision::Allow {
                peer_id: "peer-a".to_string()
            }
        );
    }

    #[tokio::test]
    async fn test_peer_source_ip_ownership_used_by_router_dependencies() {
        let local_keypair = WgKeyPair::generate();
        let peer_keypair = WgKeyPair::generate();
        let manager = TunnelManager::new(local_keypair, crate::tunnel::DEFAULT_WG_PORT);
        manager
            .add_peer_with_ips(
                "peer-a".to_string(),
                peer_keypair.public_key_bytes(),
                None,
                vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
                None,
            )
            .await
            .unwrap();

        assert!(
            manager
                .peer_allows_ip("peer-a", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
                .await
                .unwrap()
        );
        assert!(
            !manager
                .peer_allows_ip("peer-a", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)))
                .await
                .unwrap()
        );
    }
}
