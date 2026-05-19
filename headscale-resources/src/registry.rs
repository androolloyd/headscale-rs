//! Resource registry - tracks what resources are available.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::types::{ResourcePricing, ResourceType};

/// Registry of available resources in the mesh.
pub struct ResourceRegistry {
    /// Provider DID → their resources
    providers: Arc<RwLock<HashMap<String, Vec<ProviderResource>>>>,
}

/// A resource offered by a provider.
#[derive(Debug, Clone)]
pub struct ProviderResource {
    pub provider: String,
    pub resource_type: ResourceType,
    pub pricing: ResourcePricing,
    pub available: bool,
    pub last_updated: u64,
}

impl ResourceRegistry {
    pub fn new() -> Self {
        Self {
            providers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a resource from a provider.
    pub async fn register(&self, provider: &str, resource: ResourceType, pricing: ResourcePricing) {
        let mut providers = self.providers.write().await;
        let resources = providers.entry(provider.to_string()).or_default();

        resources.push(ProviderResource {
            provider: provider.to_string(),
            resource_type: resource,
            pricing,
            available: true,
            last_updated: now(),
        });
    }

    /// Find providers for a resource type.
    pub async fn find_providers(&self, resource_type: &ResourceType) -> Vec<ProviderResource> {
        let providers = self.providers.read().await;

        providers
            .values()
            .flatten()
            .filter(|r| matches_resource_type(&r.resource_type, resource_type) && r.available)
            .cloned()
            .collect()
    }

    /// Get cheapest provider for a resource.
    pub async fn cheapest_provider(
        &self,
        resource_type: &ResourceType,
    ) -> Option<ProviderResource> {
        let mut providers = self.find_providers(resource_type).await;
        providers.sort_by_key(|p| p.pricing.price_per_unit);
        providers.into_iter().next()
    }

    /// Mark a resource as unavailable.
    pub async fn mark_unavailable(&self, provider: &str, resource_type: &ResourceType) {
        let mut providers = self.providers.write().await;
        if let Some(resources) = providers.get_mut(provider) {
            for r in resources {
                if matches_resource_type(&r.resource_type, resource_type) {
                    r.available = false;
                    r.last_updated = now();
                }
            }
        }
    }
}

impl Default for ResourceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

fn matches_resource_type(a: &ResourceType, b: &ResourceType) -> bool {
    match (a, b) {
        (ResourceType::Inference(a), ResourceType::Inference(b)) => a.model == b.model,
        (ResourceType::Storage(_), ResourceType::Storage(_))
        | (ResourceType::Compute(_), ResourceType::Compute(_))
        | (ResourceType::Bandwidth(_), ResourceType::Bandwidth(_)) => true,
        _ => false,
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
