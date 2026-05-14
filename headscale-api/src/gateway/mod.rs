//! L7 Resource Gateway
//!
//! Provides authenticated, metered access to provider resources without L3 mesh peering.
//! Renters access resources (inference, compute, storage) via HTTP/gRPC through
//! this gateway, which handles:
//!
//! - Authentication (lease tokens or DID signatures)
//! - Authorization (quota/ACL checks)
//! - Metering (usage tracking per request)
//! - Proxying (forwarding to backend services)
//! - Receipts (signed usage proofs)

pub mod auth;
pub mod inference;
pub mod quota;
pub mod router;
pub mod types;

pub use auth::{AuthLayer, GatewayIdentity};
pub use inference::InferenceHandler;
pub use quota::{QuotaCheck, QuotaManager};
pub use router::ResourceGateway;
pub use types::*;
