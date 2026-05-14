//! Node management for the mesh.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// A node in the mesh network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// Unique node ID (DID)
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// WireGuard public key
    pub wg_pubkey: String,
    /// Assigned mesh IP addresses
    pub addresses: Vec<IpAddr>,
    /// Endpoints for direct connection
    pub endpoints: Vec<String>,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Online status
    pub online: bool,
}

/// What a node can provide to the mesh.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Can route traffic for others
    pub relay: bool,
    /// Provides inference (LLM)
    pub inference: bool,
    /// Provides storage
    pub storage: bool,
    /// Provides compute
    pub compute: bool,
    /// Is a seed node
    pub seed: bool,
}

/// Node registration request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub id: String,
    pub name: String,
    pub wg_pubkey: String,
    pub endpoints: Vec<String>,
    pub capabilities: NodeCapabilities,
}

/// Node registration response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterResponse {
    pub addresses: Vec<IpAddr>,
    pub peers: Vec<PeerInfo>,
    pub derp_map: Option<DerpMap>,
}

/// Info about a peer for WireGuard config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: String,
    pub wg_pubkey: String,
    pub addresses: Vec<IpAddr>,
    pub endpoints: Vec<String>,
    pub allowed_ips: Vec<String>,
}

/// DERP server map for NAT traversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpMap {
    pub regions: Vec<DerpRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpRegion {
    pub id: u32,
    pub name: String,
    pub nodes: Vec<DerpNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerpNode {
    pub name: String,
    pub url: String,
    pub stun_port: u16,
}
