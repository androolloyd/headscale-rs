//! Headscale-rs Resources
//!
//! Resource registry, metering, and allocation for mesh nodes.
//!
//! This crate handles:
//! - Resource capability registration
//! - Usage metering and tracking
//! - Resource allocation and scheduling
//! - Capacity management

pub mod allocation;
pub mod metering;
pub mod metrics;
pub mod registry;
pub mod types;

pub use allocation::ResourceAllocator;
pub use metering::Meter;
pub use metrics::{ResourceMetrics, global_metrics};
pub use registry::ResourceRegistry;
pub use types::*;
