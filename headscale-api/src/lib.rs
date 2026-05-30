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

// Keep compatibility with downstream toolchains that predate
// Duration::from_mins/from_hours while newer clippy versions prefer them.
#![allow(unknown_lints, clippy::duration_suboptimal_units)]

// Generated protobuf code (gated behind `full`: built from tonic at
// build time, not needed by Tailscale-wire-only consumers).
#[cfg(feature = "full")]
pub mod generated;

#[cfg(feature = "full")]
pub mod control_auth;
#[cfg(feature = "full")]
pub mod gateway;
#[cfg(feature = "full")]
pub mod grpc;
#[cfg(all(feature = "admin", feature = "full"))]
pub mod grpc_gateway;
#[cfg(feature = "full")]
pub mod http;
#[cfg(feature = "full")]
pub mod server;
pub mod tailscale_wire;

// Tailnet ACL policy storage + hujson parser + ACL → FilterRule
// translation + live-reload broadcast. Consumed by `tailscale_wire`
// (to populate `MapResponse.packet_filter`) and by `admin` (CRUD).
// Stays in the wire-default feature set: a wire-only embedder still
// needs the policy store to populate the packet filter.
pub mod policy;

// MagicDNS / `tailcfg.DNSConfig` build + hot-reload. Consumed by
// `tailscale_wire::map` to populate `MapResponse.DNSConfig` on every
// rebuild. Closes the P1 entry in `docs/headscale-gap-analysis.md`
// (§MagicDNS). Lives in the wire-default feature set: a wire-only
// embedder still needs the DnsStore to emit MagicDNS records.
pub mod dns;
pub mod oidc;

// Admin GUI v0 — Tailscale-admin-equivalent web panel + JSON API.
// Gated behind the `admin` feature (default-on); downstream wire-only
// consumers can disable it with `default-features = false`. See
// `admin::router` for the mount surface; recommended dedicated port is
// `127.0.0.1:51822` (NEVER 443 / 51820 / 51821).
#[cfg(feature = "admin")]
pub mod admin;

#[cfg(feature = "full")]
pub use gateway::ResourceGateway;
#[cfg(feature = "full")]
pub use server::Server;
pub use tailscale_wire::{WireState, router as tailscale_wire_router};
