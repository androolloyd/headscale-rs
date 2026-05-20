//! Headscale-rs Core
//!
//! Mesh coordination and WireGuard control plane.
//!
//! This crate handles:
//! - Node registration and authentication
//! - WireGuard key management
//! - Mesh topology and routing
//! - Peer discovery and NAT traversal
//! - Bandwidth metering (transport layer only)
//!
//! # Architecture Note
//!
//! Headscale-rs owns the **transport layer** (WireGuard mesh, bandwidth
//! metering). Business logic (escrow, payments, settlements) belongs
//! in an external integration crate that consumes `MeteringSnapshot`
//! events from the `metering` module.

pub mod acl;
pub mod authorization;
pub mod config;
pub mod derp;
pub mod endpoint;
pub mod events;
pub mod keys_wg;
pub mod mesh;
pub mod metering;
pub mod metrics;
pub mod node;
pub mod packet;
pub mod routing;
pub mod stun;
pub mod swarm_transport;
pub mod tun_device;
pub mod tunnel;

// Metering interface — the integration point for external payment /
// settlement layers.
pub use metering::{
    MeteringConfig, MeteringError, MeteringService, MeteringSession, MeteringSessionId,
    MeteringSnapshot,
};

// Core exports
pub use acl::{AclContext, AclDestination, AclEvaluator, AclPolicy, AclRule, Action as AclAction};
pub use config::Config;
pub use derp::{DerpClient, DerpEvent, DerpServer, DerpState};
pub use endpoint::{Endpoint, EndpointTracker, EndpointType};
pub use events::{TopologyEvent, TopologyEventBus};
pub use keys_wg::WgKeyPair;
pub use mesh::MeshCoordinator;
pub use metrics::{MeshMetrics, mesh_metrics};
pub use node::Node;
pub use packet::PacketRouter;
pub use routing::{Route, RoutingTable};
pub use stun::StunClient;
pub use swarm_transport::{
    MeshMessage, MeshTransport, MeshTransportError, MessageCategory,
    TransportStats as MeshTransportStats,
};
pub use tun_device::{TunConfig, TunDevice};
pub use tunnel::{TunnelEvent, TunnelManager, TunnelState};
