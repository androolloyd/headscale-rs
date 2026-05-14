//! Mesh coordinator - manages the network topology.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::derp::DerpServer;
use crate::events::TopologyEventBus;
use crate::node::{DerpMap, DerpNode, DerpRegion, Node, PeerInfo, RegisterRequest, RegisterResponse};

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
    pub fn new(mesh_cidr: &str) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            ip_allocator: Arc::new(RwLock::new(IpAllocator::new(mesh_cidr))),
            event_bus: TopologyEventBus::new(),
            derp_servers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Create with an existing event bus.
    pub fn with_event_bus(mesh_cidr: &str, event_bus: TopologyEventBus) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            ip_allocator: Arc::new(RwLock::new(IpAllocator::new(mesh_cidr))),
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
            self.event_bus.node_joined(
                &req.id,
                &req.name,
                &req.wg_pubkey,
                addresses.clone(),
            );
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
                allowed_ips: n
                    .addresses
                    .iter()
                    .map(|ip| format!("{}/32", ip))
                    .collect(),
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
                    .or_insert_with(Vec::new)
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
    base: u32,
    mask: u32,
    next: u32,
}

impl IpAllocator {
    fn new(cidr: &str) -> Self {
        // Parse CIDR (simplified)
        let parts: Vec<&str> = cidr.split('/').collect();
        let ip_parts: Vec<u8> = parts[0]
            .split('.')
            .map(|s| s.parse().unwrap_or(0))
            .collect();
        let prefix: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(24);

        let base = u32::from_be_bytes([ip_parts[0], ip_parts[1], ip_parts[2], ip_parts[3]]);
        let mask = !((1u32 << (32 - prefix)) - 1);

        Self {
            base,
            mask,
            next: base + 1, // Skip network address
        }
    }

    fn allocate(&mut self) -> Result<IpAddr, MeshError> {
        let ip = self.next;
        self.next += 1;

        // Check we're still in range
        if (ip & self.mask) != (self.base & self.mask) {
            return Err(MeshError::IpExhausted);
        }

        let bytes = ip.to_be_bytes();
        Ok(IpAddr::V4(std::net::Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        )))
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
