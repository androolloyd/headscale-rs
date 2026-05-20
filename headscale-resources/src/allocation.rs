//! Resource allocation and scheduling.

use crate::registry::ResourceRegistry;
use crate::types::ResourceType;

/// Allocates resources from the mesh.
pub struct ResourceAllocator {
    registry: ResourceRegistry,
}

impl ResourceAllocator {
    pub fn new(registry: ResourceRegistry) -> Self {
        Self { registry }
    }

    /// Allocate a resource for a consumer.
    pub async fn allocate(
        &self,
        consumer: &str,
        resource_type: &ResourceType,
        strategy: AllocationStrategy,
    ) -> Result<Allocation, AllocationError> {
        let provider = match strategy {
            AllocationStrategy::Cheapest => self.registry.cheapest_provider(resource_type).await,
            AllocationStrategy::Fastest => {
                // For now, same as cheapest - would need latency data
                self.registry.cheapest_provider(resource_type).await
            }
            AllocationStrategy::Preferred(did) => {
                let providers = self.registry.find_providers(resource_type).await;
                providers.into_iter().find(|p| p.provider == did)
            }
        };

        let provider = provider.ok_or(AllocationError::NoProviderAvailable)?;

        Ok(Allocation {
            consumer: consumer.to_string(),
            provider: provider.provider,
            resource_type: resource_type.clone(),
            pricing: provider.pricing,
            allocated_at: now(),
        })
    }

    /// Release an allocation.
    pub async fn release(&self, allocation: &Allocation) {
        // Mark provider resource as available again if needed
        // In practice, most resources can be shared
        tracing::info!(
            "Released allocation from {} to {}",
            allocation.consumer,
            allocation.provider
        );
    }
}

/// Strategy for allocating resources.
#[derive(Debug, Clone)]
pub enum AllocationStrategy {
    /// Choose the cheapest provider
    Cheapest,
    /// Choose the fastest provider (lowest latency)
    Fastest,
    /// Prefer a specific provider
    Preferred(String),
}

/// An allocated resource.
#[derive(Debug, Clone)]
pub struct Allocation {
    pub consumer: String,
    pub provider: String,
    pub resource_type: ResourceType,
    pub pricing: crate::types::ResourcePricing,
    pub allocated_at: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum AllocationError {
    #[error("No provider available for requested resource")]
    NoProviderAvailable,
    #[error("Provider rejected allocation")]
    ProviderRejected,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
