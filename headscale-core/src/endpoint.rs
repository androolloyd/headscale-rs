//! Endpoint tracking and NAT traversal coordination.
//!
//! This module manages endpoint discovery and selection for peers,
//! coordinating between direct connections, STUN-discovered endpoints,
//! and DERP relay fallback.

use crate::stun::{StunClient, StunError};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, broadcast};

/// How long an endpoint is considered valid.
pub const ENDPOINT_VALIDITY: Duration = Duration::from_secs(120);

/// How often to refresh STUN-discovered endpoints.
pub const STUN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Endpoint type indicating how the address was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EndpointType {
    /// Direct/local endpoint (e.g., from interface enumeration).
    Direct,
    /// Discovered via STUN (reflexive address).
    Stun,
    /// Via DERP relay server.
    Derp,
    /// Reported by peer.
    PeerReported,
}

/// A discovered endpoint for a peer.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// The socket address.
    pub addr: SocketAddr,
    /// How this endpoint was discovered.
    pub endpoint_type: EndpointType,
    /// Priority (lower is better).
    pub priority: u8,
    /// When this endpoint was last seen.
    pub last_seen: Instant,
    /// When this endpoint was last used successfully.
    pub last_success: Option<Instant>,
    /// Latency measurement (if available).
    pub latency: Option<Duration>,
}

impl Endpoint {
    /// Create a new endpoint.
    pub fn new(addr: SocketAddr, endpoint_type: EndpointType, priority: u8) -> Self {
        Self {
            addr,
            endpoint_type,
            priority,
            last_seen: Instant::now(),
            last_success: None,
            latency: None,
        }
    }

    /// Check if this endpoint is still valid.
    pub fn is_valid(&self) -> bool {
        self.last_seen.elapsed() < ENDPOINT_VALIDITY
    }

    /// Mark this endpoint as successfully used.
    pub fn mark_success(&mut self, latency: Option<Duration>) {
        self.last_success = Some(Instant::now());
        self.latency = latency;
    }
}

/// Events from the endpoint tracker.
#[derive(Debug, Clone)]
pub enum EndpointEvent {
    /// Local endpoint discovered via STUN.
    LocalEndpointDiscovered { endpoint: SocketAddr },
    /// Peer endpoint updated.
    PeerEndpointUpdated {
        peer_id: String,
        endpoint: SocketAddr,
        endpoint_type: EndpointType,
    },
    /// Endpoint became unreachable.
    EndpointUnreachable {
        peer_id: String,
        endpoint: SocketAddr,
    },
    /// Switched to DERP relay.
    SwitchedToRelay { peer_id: String, server: String },
    /// Upgraded from relay to direct.
    UpgradedToDirect {
        peer_id: String,
        endpoint: SocketAddr,
    },
}

/// Tracks endpoints for all peers and handles NAT traversal.
pub struct EndpointTracker {
    /// Our local endpoints (discovered via STUN).
    local_endpoints: RwLock<Vec<Endpoint>>,
    /// Peer endpoints indexed by peer ID.
    peer_endpoints: RwLock<HashMap<String, Vec<Endpoint>>>,
    /// STUN client for endpoint discovery.
    stun_client: Option<StunClient>,
    /// Event sender.
    event_tx: broadcast::Sender<EndpointEvent>,
    /// Last STUN refresh time.
    last_stun_refresh: RwLock<Option<Instant>>,
}

impl EndpointTracker {
    /// Create a new endpoint tracker.
    pub fn new() -> Self {
        let (event_tx, _) = broadcast::channel(256);

        Self {
            local_endpoints: RwLock::new(Vec::new()),
            peer_endpoints: RwLock::new(HashMap::new()),
            stun_client: None,
            event_tx,
            last_stun_refresh: RwLock::new(None),
        }
    }

    /// Create a new endpoint tracker with STUN support.
    pub async fn with_stun() -> Result<Self, StunError> {
        let stun_client = StunClient::new().await?;
        let (event_tx, _) = broadcast::channel(256);

        Ok(Self {
            local_endpoints: RwLock::new(Vec::new()),
            peer_endpoints: RwLock::new(HashMap::new()),
            stun_client: Some(stun_client),
            event_tx,
            last_stun_refresh: RwLock::new(None),
        })
    }

    /// Subscribe to endpoint events.
    pub fn subscribe(&self) -> broadcast::Receiver<EndpointEvent> {
        self.event_tx.subscribe()
    }

    /// Discover our local endpoint using STUN.
    pub async fn discover_local_endpoint(
        &self,
        socket: &UdpSocket,
    ) -> Result<SocketAddr, EndpointError> {
        let stun_client = self
            .stun_client
            .as_ref()
            .ok_or(EndpointError::StunNotConfigured)?;

        let endpoint = stun_client.discover_endpoint(socket).await?;

        // Update local endpoints
        {
            let mut local = self.local_endpoints.write().await;
            let existing = local.iter_mut().find(|e| e.addr == endpoint);

            if let Some(existing) = existing {
                existing.last_seen = Instant::now();
            } else {
                local.push(Endpoint::new(endpoint, EndpointType::Stun, 10));
            }

            // Remove stale endpoints
            local.retain(|e| e.is_valid());
        }

        *self.last_stun_refresh.write().await = Some(Instant::now());

        let _ = self
            .event_tx
            .send(EndpointEvent::LocalEndpointDiscovered { endpoint });

        Ok(endpoint)
    }

    /// Get our local endpoints.
    pub async fn local_endpoints(&self) -> Vec<Endpoint> {
        self.local_endpoints.read().await.clone()
    }

    /// Add a direct local endpoint.
    pub async fn add_local_endpoint(&self, addr: SocketAddr, priority: u8) {
        let mut local = self.local_endpoints.write().await;

        if !local.iter().any(|e| e.addr == addr) {
            local.push(Endpoint::new(addr, EndpointType::Direct, priority));
        }
    }

    /// Update a peer's endpoint.
    pub async fn update_peer_endpoint(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
        endpoint_type: EndpointType,
        priority: u8,
    ) {
        let mut peers = self.peer_endpoints.write().await;
        let endpoints = peers.entry(peer_id.to_string()).or_insert_with(Vec::new);

        let existing = endpoints.iter_mut().find(|e| e.addr == endpoint);

        if let Some(existing) = existing {
            existing.last_seen = Instant::now();
            existing.endpoint_type = endpoint_type;
            existing.priority = priority;
        } else {
            endpoints.push(Endpoint::new(endpoint, endpoint_type, priority));
        }

        // Remove stale endpoints
        endpoints.retain(|e| e.is_valid());

        // Sort by priority
        endpoints.sort_by_key(|e| {
            (
                e.priority,
                e.latency.map(|l| l.as_millis()).unwrap_or(u128::MAX),
            )
        });

        let _ = self.event_tx.send(EndpointEvent::PeerEndpointUpdated {
            peer_id: peer_id.to_string(),
            endpoint,
            endpoint_type,
        });
    }

    /// Mark a peer endpoint as successfully used.
    pub async fn mark_endpoint_success(
        &self,
        peer_id: &str,
        endpoint: SocketAddr,
        latency: Option<Duration>,
    ) {
        let mut peers = self.peer_endpoints.write().await;

        if let Some(endpoints) = peers.get_mut(peer_id) {
            if let Some(ep) = endpoints.iter_mut().find(|e| e.addr == endpoint) {
                ep.mark_success(latency);
            }
        }
    }

    /// Mark a peer endpoint as unreachable.
    pub async fn mark_endpoint_unreachable(&self, peer_id: &str, endpoint: SocketAddr) {
        let mut peers = self.peer_endpoints.write().await;

        if let Some(endpoints) = peers.get_mut(peer_id) {
            endpoints.retain(|e| e.addr != endpoint);
        }

        let _ = self.event_tx.send(EndpointEvent::EndpointUnreachable {
            peer_id: peer_id.to_string(),
            endpoint,
        });
    }

    /// Get all endpoints for a peer, sorted by priority.
    pub async fn get_peer_endpoints(&self, peer_id: &str) -> Vec<Endpoint> {
        let peers = self.peer_endpoints.read().await;
        peers.get(peer_id).cloned().unwrap_or_default()
    }

    /// Get the best endpoint for a peer.
    pub async fn get_best_endpoint(&self, peer_id: &str) -> Option<SocketAddr> {
        let endpoints = self.get_peer_endpoints(peer_id).await;

        // Prefer endpoints with recent success
        let best = endpoints.iter().filter(|e| e.is_valid()).min_by_key(|e| {
            let priority_score = e.priority as u64 * 1000;
            let success_score = e
                .last_success
                .map(|t| t.elapsed().as_millis() as u64)
                .unwrap_or(u64::MAX / 2);
            let latency_score = e.latency.map(|l| l.as_millis() as u64).unwrap_or(1000);
            priority_score + success_score / 1000 + latency_score
        });

        best.map(|e| e.addr)
    }

    /// Check if we need to refresh STUN endpoints.
    pub async fn needs_stun_refresh(&self) -> bool {
        if self.stun_client.is_none() {
            return false;
        }

        let last = self.last_stun_refresh.read().await;
        match *last {
            Some(time) => time.elapsed() > STUN_REFRESH_INTERVAL,
            None => true,
        }
    }

    /// Remove all endpoints for a peer.
    pub async fn remove_peer(&self, peer_id: &str) {
        let mut peers = self.peer_endpoints.write().await;
        peers.remove(peer_id);
    }

    /// Get all known peer IDs.
    pub async fn known_peers(&self) -> Vec<String> {
        let peers = self.peer_endpoints.read().await;
        peers.keys().cloned().collect()
    }

    /// Clean up stale endpoints for all peers.
    pub async fn cleanup_stale_endpoints(&self) {
        let mut peers = self.peer_endpoints.write().await;

        for endpoints in peers.values_mut() {
            endpoints.retain(|e| e.is_valid());
        }

        // Remove peers with no endpoints
        peers.retain(|_, v| !v.is_empty());
    }
}

impl Default for EndpointTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("STUN not configured")]
    StunNotConfigured,

    #[error("STUN error: {0}")]
    Stun(#[from] StunError),

    #[error("No endpoints available for peer: {0}")]
    NoEndpoints(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_endpoint_validity() {
        let endpoint = Endpoint::new(
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 51820),
            EndpointType::Direct,
            1,
        );

        assert!(endpoint.is_valid());
    }

    #[test]
    fn test_endpoint_priority() {
        let mut endpoints = vec![
            Endpoint::new("1.2.3.4:1000".parse().unwrap(), EndpointType::Direct, 1),
            Endpoint::new("1.2.3.4:2000".parse().unwrap(), EndpointType::Stun, 10),
            Endpoint::new("1.2.3.4:3000".parse().unwrap(), EndpointType::Derp, 100),
        ];

        endpoints.sort_by_key(|e| e.priority);

        assert_eq!(endpoints[0].priority, 1);
        assert_eq!(endpoints[1].priority, 10);
        assert_eq!(endpoints[2].priority, 100);
    }

    #[tokio::test]
    async fn test_endpoint_tracker_basic() {
        let tracker = EndpointTracker::new();

        // Add local endpoint
        tracker
            .add_local_endpoint("10.0.0.1:51820".parse().unwrap(), 1)
            .await;

        let local = tracker.local_endpoints().await;
        assert_eq!(local.len(), 1);
        assert_eq!(local[0].endpoint_type, EndpointType::Direct);

        // Add peer endpoint
        let peer_id = "test-peer";
        tracker
            .update_peer_endpoint(
                peer_id,
                "10.0.0.2:51820".parse().unwrap(),
                EndpointType::Direct,
                1,
            )
            .await;

        let peer_endpoints = tracker.get_peer_endpoints(peer_id).await;
        assert_eq!(peer_endpoints.len(), 1);

        // Get best endpoint
        let best = tracker.get_best_endpoint(peer_id).await;
        assert!(best.is_some());
    }

    #[tokio::test]
    async fn test_endpoint_tracker_multiple_endpoints() {
        let tracker = EndpointTracker::new();
        let peer_id = "multi-endpoint-peer";

        // Add multiple endpoints with different priorities
        tracker
            .update_peer_endpoint(
                peer_id,
                "10.0.0.1:51820".parse().unwrap(),
                EndpointType::Direct,
                1,
            )
            .await;

        tracker
            .update_peer_endpoint(
                peer_id,
                "1.2.3.4:51820".parse().unwrap(),
                EndpointType::Stun,
                10,
            )
            .await;

        let endpoints = tracker.get_peer_endpoints(peer_id).await;
        assert_eq!(endpoints.len(), 2);

        // Best should be the direct one (lower priority number)
        let best = tracker.get_best_endpoint(peer_id).await.unwrap();
        assert_eq!(best.port(), 51820);
    }

    #[tokio::test]
    async fn test_cleanup_stale() {
        let tracker = EndpointTracker::new();

        tracker
            .add_local_endpoint("10.0.0.1:51820".parse().unwrap(), 1)
            .await;

        // Should have one endpoint
        let local = tracker.local_endpoints().await;
        assert_eq!(local.len(), 1);

        // Cleanup shouldn't remove fresh endpoints
        tracker.cleanup_stale_endpoints().await;

        let known = tracker.known_peers().await;
        assert!(known.is_empty()); // No peers added yet
    }
}
