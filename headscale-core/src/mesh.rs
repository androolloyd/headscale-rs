//! Mesh coordinator - manages the network topology.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use ipnet::{IpNet, Ipv4Net};
use tokio::sync::RwLock;

use crate::derp::DerpServer;
use crate::events::TopologyEventBus;
#[cfg(test)]
use crate::node::NodeCapabilities;
use crate::node::{
    DerpMap, DerpNode, DerpRegion, Node, PeerInfo, RegisterRequest, RegisterResponse,
};

const DEFAULT_MESH_CIDR: &str = "100.64.0.0/10";

/// Coordinates the mesh network.
pub struct MeshCoordinator {
    /// All registered nodes
    nodes: Arc<RwLock<HashMap<String, Node>>>,
    /// IP allocator
    ip_allocator: Arc<RwLock<IpAllocator>>,
    /// Topology event bus
    event_bus: TopologyEventBus,
    /// DERP servers
    derp_servers: Arc<RwLock<Vec<DerpServer>>>,
}

impl MeshCoordinator {
    /// Create a mesh coordinator. Invalid CIDRs fall back to the default
    /// Tailscale CGNAT range for backwards compatibility; new callers
    /// should prefer [`Self::try_new`] so configuration errors are surfaced.
    pub fn new(mesh_cidr: &str) -> Self {
        Self::try_new(mesh_cidr).unwrap_or_else(|e| {
            tracing::warn!(
                mesh_cidr,
                error = %e,
                fallback = DEFAULT_MESH_CIDR,
                "Invalid mesh CIDR, falling back to default"
            );
            Self::try_new(DEFAULT_MESH_CIDR).expect("default mesh CIDR must parse")
        })
    }

    /// Create a mesh coordinator and reject invalid CIDR configuration.
    pub fn try_new(mesh_cidr: &str) -> Result<Self, MeshError> {
        Ok(Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            ip_allocator: Arc::new(RwLock::new(IpAllocator::new(mesh_cidr)?)),
            event_bus: TopologyEventBus::new(),
            derp_servers: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Create with an existing event bus.
    pub fn with_event_bus(mesh_cidr: &str, event_bus: TopologyEventBus) -> Self {
        match IpAllocator::new(mesh_cidr) {
            Ok(ip_allocator) => Self::from_allocator(ip_allocator, event_bus),
            Err(e) => {
                tracing::warn!(
                    mesh_cidr,
                    error = %e,
                    fallback = DEFAULT_MESH_CIDR,
                    "Invalid mesh CIDR, falling back to default"
                );
                Self::from_allocator(
                    IpAllocator::new(DEFAULT_MESH_CIDR).expect("default mesh CIDR must parse"),
                    event_bus,
                )
            }
        }
    }

    /// Create with an existing event bus and reject invalid CIDR configuration.
    pub fn try_with_event_bus(
        mesh_cidr: &str,
        event_bus: TopologyEventBus,
    ) -> Result<Self, MeshError> {
        Ok(Self::from_allocator(
            IpAllocator::new(mesh_cidr)?,
            event_bus,
        ))
    }

    fn from_allocator(ip_allocator: IpAllocator, event_bus: TopologyEventBus) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            ip_allocator: Arc::new(RwLock::new(ip_allocator)),
            event_bus,
            derp_servers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get the event bus for subscribing to topology events.
    pub fn event_bus(&self) -> &TopologyEventBus {
        &self.event_bus
    }

    /// Add a DERP server.
    pub async fn add_derp_server(&self, server: DerpServer) {
        let mut servers = self.derp_servers.write().await;
        if !servers.iter().any(|s| s.name == server.name) {
            servers.push(server);
        }
    }

    /// Get DERP servers.
    pub async fn derp_servers(&self) -> Vec<DerpServer> {
        self.derp_servers.read().await.clone()
    }

    /// Register a new node.
    pub async fn register(&self, req: RegisterRequest) -> Result<RegisterResponse, MeshError> {
        let mut nodes = self.nodes.write().await;
        let mut allocator = self.ip_allocator.write().await;

        // Check if new node or existing
        let is_new = !nodes.contains_key(&req.id);

        // Allocate IP if new node
        let addresses = if let Some(existing) = nodes.get(&req.id) {
            existing.addresses.clone()
        } else {
            vec![allocator.allocate()?]
        };

        let node = Node {
            id: req.id.clone(),
            name: req.name.clone(),
            wg_pubkey: req.wg_pubkey.clone(),
            addresses: addresses.clone(),
            endpoints: req.endpoints,
            last_seen: now(),
            capabilities: req.capabilities,
            online: true,
        };

        nodes.insert(req.id.clone(), node);

        // Emit event
        if is_new {
            self.event_bus
                .node_joined(&req.id, &req.name, &req.wg_pubkey, addresses.clone());
        } else {
            self.event_bus.node_status_changed(&req.id, true);
        }

        // Build peer list
        let peers: Vec<PeerInfo> = nodes
            .values()
            .filter(|n| n.id != req.id)
            .map(|n| PeerInfo {
                id: n.id.clone(),
                wg_pubkey: n.wg_pubkey.clone(),
                addresses: n.addresses.clone(),
                endpoints: n.endpoints.clone(),
                allowed_ips: n.addresses.iter().map(|ip| format!("{ip}/32")).collect(),
            })
            .collect();

        // Build DERP map from configured servers
        let derp_servers = self.derp_servers.read().await;
        let derp_map = if derp_servers.is_empty() {
            None
        } else {
            // Group servers by region
            let mut regions_map: HashMap<String, Vec<DerpNode>> = HashMap::new();
            for server in derp_servers.iter() {
                let node = DerpNode {
                    name: server.name.clone(),
                    url: format!("https://{}", server.hostname),
                    stun_port: if server.stun_enabled { 3478 } else { 0 },
                };
                regions_map
                    .entry(server.region.clone())
                    .or_default()
                    .push(node);
            }

            let regions: Vec<DerpRegion> = regions_map
                .into_iter()
                .enumerate()
                .map(|(idx, (name, nodes))| DerpRegion {
                    id: (idx + 1) as u32,
                    name,
                    nodes,
                })
                .collect();

            Some(DerpMap { regions })
        };

        Ok(RegisterResponse {
            addresses,
            peers,
            derp_map,
        })
    }

    /// Update node status.
    pub async fn heartbeat(&self, node_id: &str) -> Result<(), MeshError> {
        let mut nodes = self.nodes.write().await;
        if let Some(node) = nodes.get_mut(node_id) {
            node.last_seen = now();
            node.online = true;
            Ok(())
        } else {
            Err(MeshError::NodeNotFound(node_id.to_string()))
        }
    }

    /// Get all nodes.
    pub async fn list_nodes(&self) -> Vec<Node> {
        self.nodes.read().await.values().cloned().collect()
    }

    /// Get nodes with specific capability.
    pub async fn nodes_with_capability(&self, cap: &str) -> Vec<Node> {
        self.nodes
            .read()
            .await
            .values()
            .filter(|n| match cap {
                "relay" => n.capabilities.relay,
                "inference" => n.capabilities.inference,
                "storage" => n.capabilities.storage,
                "compute" => n.capabilities.compute,
                "seed" => n.capabilities.seed,
                _ => false,
            })
            .cloned()
            .collect()
    }
}

/// Simple IP allocator for the mesh.
struct IpAllocator {
    next: Option<u32>,
    end: u32,
}

impl IpAllocator {
    fn new(cidr: &str) -> Result<Self, MeshError> {
        let net = match cidr
            .parse::<IpNet>()
            .map_err(|e| MeshError::Config(format!("invalid mesh CIDR {cidr:?}: {e}")))?
        {
            IpNet::V4(net) => net,
            IpNet::V6(_) => {
                return Err(MeshError::Config(format!(
                    "mesh CIDR must be IPv4, got {cidr:?}"
                )));
            }
        };

        Self::from_ipv4_net(net)
    }

    fn from_ipv4_net(net: Ipv4Net) -> Result<Self, MeshError> {
        let start = u32::from(net.network());
        let end = u32::from(net.broadcast());
        let prefix = net.prefix_len();

        let (first, last) = match prefix {
            0..=30 => {
                if end <= start + 1 {
                    return Err(MeshError::IpExhausted);
                }
                (start + 1, end - 1)
            }
            31 | 32 => (start, end),
            _ => {
                return Err(MeshError::Config(format!(
                    "invalid IPv4 prefix length: {prefix}"
                )));
            }
        };

        Ok(Self {
            next: Some(first),
            end: last,
        })
    }

    fn allocate(&mut self) -> Result<IpAddr, MeshError> {
        let ip = self.next.ok_or(MeshError::IpExhausted)?;
        self.next = if ip == self.end { None } else { Some(ip + 1) };
        Ok(IpAddr::V4(Ipv4Addr::from(ip)))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("Node not found: {0}")]
    NodeNotFound(String),
    #[error("IP addresses exhausted")]
    IpExhausted,
    #[error("Invalid configuration: {0}")]
    Config(String),
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::TopologyEvent;

    #[test]
    fn allocator_rejects_invalid_cidr_without_panicking() {
        assert!(IpAllocator::new("not-a-cidr").is_err());
        assert!(IpAllocator::new("fd7a:115c:a1e0::/48").is_err());
        assert!(IpAllocator::new("10.0.0.0/33").is_err());
    }

    #[test]
    fn allocator_skips_network_and_broadcast_for_subnets() {
        let mut allocator = IpAllocator::new("10.0.0.0/30").unwrap();

        assert_eq!(
            allocator.allocate().unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(
            allocator.allocate().unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))
        );
        assert!(matches!(allocator.allocate(), Err(MeshError::IpExhausted)));
    }

    #[test]
    fn allocator_supports_single_host_prefix() {
        let mut allocator = IpAllocator::new("10.0.0.7/32").unwrap();

        assert_eq!(
            allocator.allocate().unwrap(),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))
        );
        assert!(matches!(allocator.allocate(), Err(MeshError::IpExhausted)));
    }

    #[tokio::test]
    async fn try_new_surfaces_invalid_config() {
        assert!(MeshCoordinator::try_new("bad").is_err());
    }

    #[tokio::test]
    async fn with_event_bus_fallback_preserves_supplied_bus() {
        let bus = TopologyEventBus::new();
        let mut rx = bus.subscribe();
        let coordinator = MeshCoordinator::with_event_bus("bad", bus);

        coordinator
            .register(RegisterRequest {
                id: "node-1".to_string(),
                name: "node".to_string(),
                wg_pubkey: "pubkey".to_string(),
                endpoints: Vec::new(),
                capabilities: NodeCapabilities::default(),
            })
            .await
            .unwrap();

        assert!(matches!(
            rx.recv().await.unwrap(),
            TopologyEvent::NodeJoined { .. }
        ));
    }
}
