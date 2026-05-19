//! Headscale-rs API
//!
//! gRPC and HTTP control plane for mesh coordination.
//!
//! This crate provides:
//! - REST API for node management
//! - gRPC API for high-performance operations
//! - WebSocket for real-time updates
//! - Health and metrics endpoints
//! - L7 Resource Gateway for inference, compute, and storage

// Generated protobuf code (gated behind `full`: built from tonic at
// build time, not needed by Tailscale-wire-only consumers).
#[cfg(feature = "full")]
pub mod generated;

#[cfg(feature = "full")]
pub mod gateway;
#[cfg(feature = "full")]
pub mod grpc;
#[cfg(feature = "full")]
pub mod http;
#[cfg(feature = "full")]
pub mod server;
pub mod tailscale_wire;

#[cfg(feature = "full")]
pub use gateway::ResourceGateway;
#[cfg(feature = "full")]
pub use server::Server;
pub use tailscale_wire::{router as tailscale_wire_router, WireState};
