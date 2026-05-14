//! Topology event bus for mesh network state changes.
//!
//! This module provides a centralized event system for broadcasting
//! topology changes across the mesh network components.

use std::net::{IpAddr, SocketAddr};
use tokio::sync::broadcast;

/// Events that can occur in the mesh network topology.
#[derive(Debug, Clone)]
pub enum TopologyEvent {
    /// A new node joined the mesh.
    NodeJoined {
        node_id: String,
        name: String,
        wg_pubkey: String,
        addresses: Vec<IpAddr>,
    },
    /// A node left the mesh.
    NodeLeft {
        node_id: String,
        reason: String,
    },
    /// A node's status changed.
    NodeStatusChanged {
        node_id: String,
        online: bool,
    },
    /// A node's endpoint changed.
    EndpointChanged {
        node_id: String,
        old_endpoint: Option<SocketAddr>,
        new_endpoint: SocketAddr,
    },
    /// A peer connection was established.
    PeerConnected {
        local_node: String,
        remote_node: String,
    },
    /// A peer connection was lost.
    PeerDisconnected {
        local_node: String,
        remote_node: String,
        reason: String,
    },
    /// WireGuard handshake completed.
    HandshakeComplete {
        node_id: String,
        peer_id: String,
    },
    /// Connection upgraded from relay to direct.
    ConnectionUpgraded {
        peer_id: String,
        from_relay: String,
        to_direct: SocketAddr,
    },
    /// Connection downgraded from direct to relay.
    ConnectionDowngraded {
        peer_id: String,
        to_relay: String,
    },
    /// DERP server availability changed.
    DerpAvailabilityChanged {
        server: String,
        available: bool,
    },
    /// Mesh IP pool changed.
    IpPoolChanged {
        available: u32,
        total: u32,
    },
}

/// Centralized event bus for topology changes.
pub struct TopologyEventBus {
    /// Broadcast sender for topology events.
    tx: broadcast::Sender<TopologyEvent>,
}

impl TopologyEventBus {
    /// Create a new event bus.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(512);
        Self { tx }
    }

    /// Create a new event bus with custom capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    /// Subscribe to topology events.
    pub fn subscribe(&self) -> broadcast::Receiver<TopologyEvent> {
        self.tx.subscribe()
    }

    /// Publish an event to all subscribers.
    pub fn publish(&self, event: TopologyEvent) {
        // Ignore errors if no subscribers
        let _ = self.tx.send(event);
    }

    /// Get the number of active subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Publish a node joined event.
    pub fn node_joined(
        &self,
        node_id: impl Into<String>,
        name: impl Into<String>,
        wg_pubkey: impl Into<String>,
        addresses: Vec<IpAddr>,
    ) {
        self.publish(TopologyEvent::NodeJoined {
            node_id: node_id.into(),
            name: name.into(),
            wg_pubkey: wg_pubkey.into(),
            addresses,
        });
    }

    /// Publish a node left event.
    pub fn node_left(&self, node_id: impl Into<String>, reason: impl Into<String>) {
        self.publish(TopologyEvent::NodeLeft {
            node_id: node_id.into(),
            reason: reason.into(),
        });
    }

    /// Publish a node status changed event.
    pub fn node_status_changed(&self, node_id: impl Into<String>, online: bool) {
        self.publish(TopologyEvent::NodeStatusChanged {
            node_id: node_id.into(),
            online,
        });
    }

    /// Publish an endpoint changed event.
    pub fn endpoint_changed(
        &self,
        node_id: impl Into<String>,
        old_endpoint: Option<SocketAddr>,
        new_endpoint: SocketAddr,
    ) {
        self.publish(TopologyEvent::EndpointChanged {
            node_id: node_id.into(),
            old_endpoint,
            new_endpoint,
        });
    }

    /// Publish a peer connected event.
    pub fn peer_connected(&self, local_node: impl Into<String>, remote_node: impl Into<String>) {
        self.publish(TopologyEvent::PeerConnected {
            local_node: local_node.into(),
            remote_node: remote_node.into(),
        });
    }

    /// Publish a peer disconnected event.
    pub fn peer_disconnected(
        &self,
        local_node: impl Into<String>,
        remote_node: impl Into<String>,
        reason: impl Into<String>,
    ) {
        self.publish(TopologyEvent::PeerDisconnected {
            local_node: local_node.into(),
            remote_node: remote_node.into(),
            reason: reason.into(),
        });
    }

    /// Publish a handshake complete event.
    pub fn handshake_complete(&self, node_id: impl Into<String>, peer_id: impl Into<String>) {
        self.publish(TopologyEvent::HandshakeComplete {
            node_id: node_id.into(),
            peer_id: peer_id.into(),
        });
    }

    /// Publish a connection upgraded event.
    pub fn connection_upgraded(
        &self,
        peer_id: impl Into<String>,
        from_relay: impl Into<String>,
        to_direct: SocketAddr,
    ) {
        self.publish(TopologyEvent::ConnectionUpgraded {
            peer_id: peer_id.into(),
            from_relay: from_relay.into(),
            to_direct,
        });
    }

    /// Publish a connection downgraded event.
    pub fn connection_downgraded(&self, peer_id: impl Into<String>, to_relay: impl Into<String>) {
        self.publish(TopologyEvent::ConnectionDowngraded {
            peer_id: peer_id.into(),
            to_relay: to_relay.into(),
        });
    }
}

impl Default for TopologyEventBus {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TopologyEventBus {
    fn clone(&self) -> Self {
        Self {
            tx: self.tx.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_event_bus_publish_subscribe() {
        let bus = TopologyEventBus::new();
        let mut rx = bus.subscribe();

        bus.node_joined(
            "node-1",
            "Test Node",
            "pubkey123",
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        );

        let event = rx.recv().await.unwrap();
        match event {
            TopologyEvent::NodeJoined {
                node_id,
                name,
                wg_pubkey,
                addresses,
            } => {
                assert_eq!(node_id, "node-1");
                assert_eq!(name, "Test Node");
                assert_eq!(wg_pubkey, "pubkey123");
                assert_eq!(addresses.len(), 1);
            }
            _ => panic!("Wrong event type"),
        }
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let bus = TopologyEventBus::new();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.node_status_changed("node-1", true);

        // Both subscribers should receive the event
        let event1 = rx1.recv().await.unwrap();
        let event2 = rx2.recv().await.unwrap();

        match (event1, event2) {
            (
                TopologyEvent::NodeStatusChanged {
                    node_id: id1,
                    online: o1,
                },
                TopologyEvent::NodeStatusChanged {
                    node_id: id2,
                    online: o2,
                },
            ) => {
                assert_eq!(id1, "node-1");
                assert_eq!(id2, "node-1");
                assert!(o1);
                assert!(o2);
            }
            _ => panic!("Wrong event types"),
        }
    }

    #[test]
    fn test_subscriber_count() {
        let bus = TopologyEventBus::new();
        assert_eq!(bus.subscriber_count(), 0);

        let _rx1 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);

        let _rx2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);
    }

    #[test]
    fn test_clone() {
        let bus1 = TopologyEventBus::new();
        let bus2 = bus1.clone();

        let _rx = bus1.subscribe();

        // Clone shares the same channel
        assert_eq!(bus2.subscriber_count(), 1);
    }
}
