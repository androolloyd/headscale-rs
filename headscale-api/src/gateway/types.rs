//! Gateway types for resource access.

use serde::{Deserialize, Serialize};

/// Resource types accessible through the gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayResourceType {
    Inference,
    Compute,
    Storage,
    Bandwidth,
}

impl std::fmt::Display for GatewayResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayResourceType::Inference => write!(f, "inference"),
            GatewayResourceType::Compute => write!(f, "compute"),
            GatewayResourceType::Storage => write!(f, "storage"),
            GatewayResourceType::Bandwidth => write!(f, "bandwidth"),
        }
    }
}

/// Metering units for usage tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeteringUnit {
    /// Tokens for inference (input + output)
    Tokens,
    /// CPU seconds for compute
    CpuSeconds,
    /// GPU seconds for compute
    GpuSeconds,
    /// Memory GB-seconds for compute
    MemoryGbSeconds,
    /// Bytes stored for storage
    BytesStored,
    /// Request count for storage
    Requests,
    /// Bytes transferred for bandwidth/egress
    BytesTransferred,
}

impl std::fmt::Display for MeteringUnit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeteringUnit::Tokens => write!(f, "tokens"),
            MeteringUnit::CpuSeconds => write!(f, "cpu_seconds"),
            MeteringUnit::GpuSeconds => write!(f, "gpu_seconds"),
            MeteringUnit::MemoryGbSeconds => write!(f, "memory_gb_seconds"),
            MeteringUnit::BytesStored => write!(f, "bytes_stored"),
            MeteringUnit::Requests => write!(f, "requests"),
            MeteringUnit::BytesTransferred => write!(f, "bytes_transferred"),
        }
    }
}

/// Usage recorded for a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    /// Lease ID this usage is for
    pub lease_id: String,
    /// Resource type
    pub resource_type: GatewayResourceType,
    /// Metering unit
    pub unit: MeteringUnit,
    /// Amount used
    pub amount: u64,
    /// Unix timestamp (millis)
    pub timestamp: u64,
    /// Request ID for correlation
    pub request_id: String,
    /// Additional metadata
    #[serde(default)]
    pub metadata: std::collections::HashMap<String, String>,
}

/// Error response format.
#[derive(Debug, Serialize)]
pub struct GatewayErrorResponse {
    pub error: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub used: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after: Option<u64>,
}

impl GatewayErrorResponse {
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            error: "unauthorized".to_string(),
            message: message.into(),
            limit: None,
            used: None,
            retry_after: None,
        }
    }

    pub fn quota_exceeded(limit: u64, used: u64) -> Self {
        Self {
            error: "quota_exceeded".to_string(),
            message: "Quota exceeded".to_string(),
            limit: Some(limit),
            used: Some(used),
            retry_after: None,
        }
    }

    pub fn rate_limited(retry_after: u64) -> Self {
        Self {
            error: "rate_limited".to_string(),
            message: "Too many requests".to_string(),
            limit: None,
            used: None,
            retry_after: Some(retry_after),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            error: "not_found".to_string(),
            message: message.into(),
            limit: None,
            used: None,
            retry_after: None,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            error: "internal".to_string(),
            message: message.into(),
            limit: None,
            used: None,
            retry_after: None,
        }
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self {
            error: "unavailable".to_string(),
            message: message.into(),
            limit: None,
            used: None,
            retry_after: None,
        }
    }
}

/// Backend service registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceBackend {
    /// Unique backend ID
    pub id: String,
    /// Resource type this backend provides
    pub resource_type: GatewayResourceType,
    /// Backend URL
    pub url: String,
    /// Health check endpoint
    pub health_check: String,
    /// Current status
    pub status: BackendStatus,
    /// Capacity info
    pub capacity: BackendCapacity,
}

/// Backend health status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Unknown,
}

/// Capacity information for a backend.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BackendCapacity {
    /// For inference: models available
    #[serde(default)]
    pub models: Vec<String>,
    /// For compute: available CPU cores
    #[serde(default)]
    pub cpu_cores: u32,
    /// For compute: available GPUs
    #[serde(default)]
    pub gpu_count: u32,
    /// For compute: available memory in GB
    #[serde(default)]
    pub memory_gb: u32,
    /// For storage: available space in GB
    #[serde(default)]
    pub storage_gb: u64,
}

/// Lease token for authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseTokenPayload {
    /// Lease ID
    pub lease_id: String,
    /// Renter DID
    pub renter_did: String,
    /// Resource type
    pub resource_type: GatewayResourceType,
    /// Expiry timestamp (unix millis)
    pub expires_at: u64,
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
