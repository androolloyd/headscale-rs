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

// Generated protobuf code
pub mod generated;

pub mod gateway;
pub mod grpc;
pub mod http;
pub mod server;

pub use gateway::ResourceGateway;
pub use server::Server;
