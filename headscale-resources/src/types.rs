//! Resource types for the mesh.

use serde::{Deserialize, Serialize};

/// Types of resources available in the mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    /// LLM inference
    Inference(InferenceSpec),
    /// Persistent storage
    Storage(StorageSpec),
    /// Compute resources
    Compute(ComputeSpec),
    /// Network bandwidth
    Bandwidth(BandwidthSpec),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceSpec {
    pub model: String,
    pub max_context: u64,
    pub tokens_per_second: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageSpec {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub storage_type: StorageType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageType {
    Ssd,
    Hdd,
    Nvme,
    Ram,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputeSpec {
    pub cpu_cores: u32,
    pub cpu_threads: u32,
    pub memory_bytes: u64,
    pub gpu: Option<GpuSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuSpec {
    pub model: String,
    pub memory_bytes: u64,
    pub compute_capability: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BandwidthSpec {
    pub upload_mbps: u32,
    pub download_mbps: u32,
}

/// Resource usage record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub resource_type: ResourceType,
    pub consumer: String, // DID
    pub provider: String, // DID
    pub started_at: u64,
    pub ended_at: Option<u64>,
    pub units_consumed: u64,
    pub cost_millitokens: u64,
}

/// Pricing for a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePricing {
    pub resource_type: ResourceType,
    pub price_per_unit: u64, // millitokens
    pub unit_description: String,
    pub minimum_units: u64,
}
