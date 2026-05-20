//! Swarm transport over mesh network.
//!
//! This module provides a transport layer for swarm messaging that uses
//! the WireGuard mesh for direct node-to-node communication. It implements
//! a generic transport abstraction for the integration layer.
//!
//! The mesh transport provides:
//! - Low latency direct connections via WireGuard
//! - Automatic peer discovery via mesh coordinator
//! - Fallback to DERP relay when direct connections fail
//! - Message serialization and framing

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::mesh::MeshCoordinator;

/// Message categories for routing decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageCategory {
    /// Control plane messages (heartbeat, discovery).
    Control,
    /// Task-related messages (assignment, progress, completion).
    Task,
    /// Swarm coordination (invitation, join).
    Coordination,
    /// Bulk data transfer.
    BulkData,
    /// Unknown/other.
    Other,
}

/// A message that can be sent over the mesh transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshMessage {
    /// Source node ID.
    pub from: String,
    /// Destination node ID (empty for broadcast).
    pub to: String,
    /// Message category.
    pub category: MessageCategory,
    /// Raw message payload.
    pub payload: Vec<u8>,
    /// Timestamp when sent.
    pub timestamp: u64,
    /// Optional correlation ID for request-response patterns.
    pub correlation_id: Option<String>,
}

impl MeshMessage {
    /// Create a new mesh message.
    pub fn new(from: impl Into<String>, to: impl Into<String>, payload: Vec<u8>) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            category: MessageCategory::Other,
            payload,
            timestamp: now(),
            correlation_id: None,
        }
    }

    /// Set the message category.
    pub fn with_category(mut self, category: MessageCategory) -> Self {
        self.category = category;
        self
    }

    /// Set a correlation ID for request-response tracking.
    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Check if this is a broadcast message.
    pub fn is_broadcast(&self) -> bool {
        self.to.is_empty() || self.to == "*"
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MeshTransportError> {
        serde_json::to_vec(self).map_err(|e| MeshTransportError::Serialization(e.to_string()))
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, MeshTransportError> {
        serde_json::from_slice(data).map_err(|e| MeshTransportError::Serialization(e.to_string()))
    }
}

/// Transport statistics.
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    /// Total messages sent.
    pub messages_sent: u64,
    /// Total messages received.
    pub messages_received: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of currently connected peers.
    pub connected_peers: usize,
    /// Last activity timestamp.
    pub last_activity: u64,
}

/// Errors from the mesh transport.
#[derive(Debug, Error)]
pub enum MeshTransportError {
    #[error("Node not reachable: {0}")]
    Unreachable(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Transport unavailable")]
    Unavailable,

    #[error("Timeout")]
    Timeout,

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Connection to a peer over the mesh.
struct PeerConnection {
    node_id: String,
    mesh_addr: SocketAddr,
    last_activity: u64,
    stream: Option<TcpStream>,
}

impl PeerConnection {
    fn new(node_id: String, mesh_addr: SocketAddr) -> Self {
        Self {
            node_id,
            mesh_addr,
            last_activity: now(),
            stream: None,
        }
    }

    fn connect(&mut self, timeout: Duration) -> Result<&mut TcpStream, MeshTransportError> {
        if self.stream.is_none() {
            let stream = TcpStream::connect_timeout(&self.mesh_addr, timeout)
                .map_err(|e| MeshTransportError::ConnectionFailed(e.to_string()))?;
            stream.set_read_timeout(Some(timeout)).ok();
            stream.set_write_timeout(Some(timeout)).ok();
            self.stream = Some(stream);
        }
        self.last_activity = now();
        Ok(self.stream.as_mut().unwrap())
    }

    fn close(&mut self) {
        self.stream = None;
    }
}

/// Mesh transport for swarm messaging.
///
/// Provides reliable message delivery over the WireGuard mesh network.
/// Messages are sent via TCP connections to mesh IP addresses.
pub struct MeshTransport {
    /// Local node ID.
    local_node_id: String,
    /// Reference to mesh coordinator.
    mesh: Arc<MeshCoordinator>,
    /// Active peer connections.
    connections: RwLock<HashMap<String, PeerConnection>>,
    /// Transport statistics.
    stats: RwLock<TransportStats>,
    /// Connection timeout.
    connect_timeout: Duration,
    /// Read/write timeout.
    io_timeout: Duration,
    /// Port for mesh transport (same for all nodes).
    transport_port: u16,
    /// Message receiver channel.
    message_tx: broadcast::Sender<MeshMessage>,
    /// Whether transport is available.
    available: RwLock<bool>,
}

impl MeshTransport {
    /// Default transport port.
    pub const DEFAULT_PORT: u16 = 9473;

    /// Create a new mesh transport.
    pub fn new(local_node_id: impl Into<String>, mesh: Arc<MeshCoordinator>) -> Self {
        let (message_tx, _) = broadcast::channel(1024);
        Self {
            local_node_id: local_node_id.into(),
            mesh,
            connections: RwLock::new(HashMap::new()),
            stats: RwLock::new(TransportStats::default()),
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(30),
            transport_port: Self::DEFAULT_PORT,
            message_tx,
            available: RwLock::new(true),
        }
    }

    /// Set custom transport port.
    pub fn with_port(mut self, port: u16) -> Self {
        self.transport_port = port;
        self
    }

    /// Set connection timeout.
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Set I/O timeout.
    pub fn with_io_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = timeout;
        self
    }

    /// Get transport name.
    pub fn name(&self) -> &str {
        "mesh"
    }

    /// Check if a node is reachable via mesh.
    pub async fn can_reach(&self, node_id: &str) -> bool {
        // Check if we have the node in our mesh
        let nodes = self.mesh.list_nodes().await;
        nodes
            .iter()
            .any(|n| n.id == node_id && n.online && !n.addresses.is_empty())
    }

    /// Send a message to a specific node.
    pub async fn send(&self, to: &str, message: MeshMessage) -> Result<(), MeshTransportError> {
        if !*self.available.read().unwrap() {
            return Err(MeshTransportError::Unavailable);
        }

        // Find the target node's mesh address
        let nodes = self.mesh.list_nodes().await;
        let target = nodes
            .iter()
            .find(|n| n.id == to)
            .ok_or_else(|| MeshTransportError::Unreachable(to.to_string()))?;

        let mesh_ip = target
            .addresses
            .first()
            .ok_or_else(|| MeshTransportError::Unreachable(to.to_string()))?;

        let mesh_addr = SocketAddr::new(*mesh_ip, self.transport_port);

        // Serialize message
        let data = message.to_bytes()?;
        let frame = Self::frame_message(&data);

        // Get or create connection
        let mut connections = self.connections.write().unwrap();
        let conn = connections
            .entry(to.to_string())
            .or_insert_with(|| PeerConnection::new(to.to_string(), mesh_addr));

        // Connect and send
        let stream = conn.connect(self.connect_timeout)?;
        stream.write_all(&frame).map_err(|e| {
            conn.close();
            MeshTransportError::Io(e)
        })?;

        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.messages_sent += 1;
            stats.bytes_sent += frame.len() as u64;
            stats.last_activity = now();
        }

        debug!("Sent message to {} ({} bytes)", to, frame.len());
        Ok(())
    }

    /// Broadcast a message to all reachable nodes.
    pub async fn broadcast(&self, message: MeshMessage) -> Result<usize, MeshTransportError> {
        if !*self.available.read().unwrap() {
            return Err(MeshTransportError::Unavailable);
        }

        let nodes = self.mesh.list_nodes().await;
        let mut sent = 0;

        for node in nodes {
            if node.id == self.local_node_id || !node.online || node.addresses.is_empty() {
                continue;
            }

            let mut msg = message.clone();
            msg.to = node.id.clone();

            match self.send(&node.id, msg).await {
                Ok(()) => sent += 1,
                Err(e) => {
                    warn!("Failed to broadcast to {}: {}", node.id, e);
                }
            }
        }

        Ok(sent)
    }

    /// Get transport statistics.
    pub fn stats(&self) -> TransportStats {
        self.stats.read().map(|s| s.clone()).unwrap_or_default()
    }

    /// Check if transport is available.
    pub fn is_available(&self) -> bool {
        *self.available.read().unwrap()
    }

    /// Set transport availability.
    pub fn set_available(&self, available: bool) {
        if let Ok(mut a) = self.available.write() {
            *a = available;
        }
    }

    /// Get list of reachable nodes.
    pub async fn reachable_nodes(&self) -> Vec<String> {
        let nodes = self.mesh.list_nodes().await;
        nodes
            .into_iter()
            .filter(|n| n.id != self.local_node_id && n.online && !n.addresses.is_empty())
            .map(|n| n.id)
            .collect()
    }

    /// Subscribe to incoming messages.
    pub fn subscribe(&self) -> broadcast::Receiver<MeshMessage> {
        self.message_tx.subscribe()
    }

    /// Process an incoming message (called by listener).
    pub fn handle_incoming(&self, message: MeshMessage) {
        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.messages_received += 1;
            stats.bytes_received += message.payload.len() as u64;
            stats.last_activity = now();
        }

        // Broadcast to subscribers
        let _ = self.message_tx.send(message);
    }

    /// Get connected peer count.
    pub fn connected_peers(&self) -> usize {
        self.connections
            .read()
            .map(|c| c.values().filter(|p| p.stream.is_some()).count())
            .unwrap_or(0)
    }

    /// Close a peer connection.
    pub fn disconnect(&self, node_id: &str) {
        if let Ok(mut connections) = self.connections.write() {
            if let Some(conn) = connections.get_mut(node_id) {
                conn.close();
            }
        }
    }

    /// Close all connections.
    pub fn disconnect_all(&self) {
        if let Ok(mut connections) = self.connections.write() {
            for conn in connections.values_mut() {
                conn.close();
            }
        }
    }

    /// Frame a message for wire transmission.
    /// Format: [length: 4 bytes BE][payload]
    fn frame_message(data: &[u8]) -> Vec<u8> {
        let len = data.len() as u32;
        let mut frame = Vec::with_capacity(4 + data.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(data);
        frame
    }

    /// Read a framed message from a stream.
    pub fn read_framed_message(stream: &mut TcpStream) -> Result<Vec<u8>, MeshTransportError> {
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;

        if len > 16 * 1024 * 1024 {
            // 16MB max
            return Err(MeshTransportError::Internal(
                "Message too large".to_string(),
            ));
        }

        let mut data = vec![0u8; len];
        stream.read_exact(&mut data)?;
        Ok(data)
    }
}

/// Builder for MeshTransport.
pub struct MeshTransportBuilder {
    local_node_id: String,
    mesh: Arc<MeshCoordinator>,
    port: u16,
    connect_timeout: Duration,
    io_timeout: Duration,
}

impl MeshTransportBuilder {
    pub fn new(local_node_id: impl Into<String>, mesh: Arc<MeshCoordinator>) -> Self {
        Self {
            local_node_id: local_node_id.into(),
            mesh,
            port: MeshTransport::DEFAULT_PORT,
            connect_timeout: Duration::from_secs(5),
            io_timeout: Duration::from_secs(30),
        }
    }

    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn io_timeout(mut self, timeout: Duration) -> Self {
        self.io_timeout = timeout;
        self
    }

    pub fn build(self) -> MeshTransport {
        MeshTransport::new(self.local_node_id, self.mesh)
            .with_port(self.port)
            .with_connect_timeout(self.connect_timeout)
            .with_io_timeout(self.io_timeout)
    }
}

/// Get current timestamp in seconds.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = MeshMessage::new("node1", "node2", vec![1, 2, 3])
            .with_category(MessageCategory::Task)
            .with_correlation_id("req-123");

        let bytes = msg.to_bytes().unwrap();
        let restored = MeshMessage::from_bytes(&bytes).unwrap();

        assert_eq!(restored.from, "node1");
        assert_eq!(restored.to, "node2");
        assert_eq!(restored.payload, vec![1, 2, 3]);
        assert_eq!(restored.category, MessageCategory::Task);
        assert_eq!(restored.correlation_id, Some("req-123".to_string()));
    }

    #[test]
    fn test_message_framing() {
        let data = vec![1, 2, 3, 4, 5];
        let framed = MeshTransport::frame_message(&data);

        assert_eq!(framed.len(), 4 + 5);
        assert_eq!(&framed[0..4], &[0, 0, 0, 5]); // length
        assert_eq!(&framed[4..], &[1, 2, 3, 4, 5]); // payload
    }

    #[test]
    fn test_broadcast_detection() {
        let msg1 = MeshMessage::new("node1", "", vec![]);
        assert!(msg1.is_broadcast());

        let msg2 = MeshMessage::new("node1", "*", vec![]);
        assert!(msg2.is_broadcast());

        let msg3 = MeshMessage::new("node1", "node2", vec![]);
        assert!(!msg3.is_broadcast());
    }

    #[test]
    fn test_transport_stats_default() {
        let stats = TransportStats::default();
        assert_eq!(stats.messages_sent, 0);
        assert_eq!(stats.messages_received, 0);
        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.connected_peers, 0);
    }
}
