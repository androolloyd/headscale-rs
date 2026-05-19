//! Quota management for gateway resources.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

use super::types::GatewayResourceType;

/// Quota configuration for a lease.
#[derive(Debug, Clone)]
pub struct Quota {
    /// Resource type
    pub resource_type: GatewayResourceType,
    /// Maximum units allowed
    pub limit: u64,
    /// Reset period (None = no reset, quota is lifetime)
    pub reset_period: Option<Duration>,
}

/// Quota state tracking usage.
pub struct QuotaState {
    config: Quota,
    used: AtomicU64,
    last_reset: RwLock<Instant>,
}

impl QuotaState {
    pub fn new(config: Quota) -> Self {
        Self {
            config,
            used: AtomicU64::new(0),
            last_reset: RwLock::new(Instant::now()),
        }
    }

    /// Check if the requested amount is within quota.
    pub async fn check(&self, requested: u64) -> Result<(), QuotaError> {
        // Check if reset is needed
        if let Some(period) = self.config.reset_period {
            let mut last_reset = self.last_reset.write().await;
            if last_reset.elapsed() >= period {
                self.used.store(0, Ordering::Relaxed);
                *last_reset = Instant::now();
            }
        }

        let used = self.used.load(Ordering::Relaxed);
        if used + requested > self.config.limit {
            return Err(QuotaError::Exceeded {
                limit: self.config.limit,
                used,
                requested,
            });
        }

        Ok(())
    }

    /// Consume quota units.
    pub fn consume(&self, amount: u64) {
        self.used.fetch_add(amount, Ordering::Relaxed);
    }

    /// Get remaining quota.
    pub fn remaining(&self) -> u64 {
        let used = self.used.load(Ordering::Relaxed);
        self.config.limit.saturating_sub(used)
    }

    /// Get current usage.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Relaxed)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QuotaError {
    #[error("Quota exceeded: limit={limit}, used={used}, requested={requested}")]
    Exceeded {
        limit: u64,
        used: u64,
        requested: u64,
    },
    #[error("No quota configured for this resource")]
    NotConfigured,
}

/// Check result for quota validation.
#[derive(Debug, Clone)]
pub struct QuotaCheck {
    /// Whether the check passed
    pub allowed: bool,
    /// Remaining quota after this request
    pub remaining: u64,
    /// Total limit
    pub limit: u64,
    /// Currently used
    pub used: u64,
}

/// Quota manager for all leases.
pub struct QuotaManager {
    /// Quotas by lease ID and resource type
    quotas: RwLock<HashMap<String, HashMap<GatewayResourceType, Arc<QuotaState>>>>,
    /// Default quotas for new leases
    defaults: HashMap<GatewayResourceType, Quota>,
}

impl QuotaManager {
    pub fn new() -> Self {
        Self {
            quotas: RwLock::new(HashMap::new()),
            defaults: Self::default_quotas(),
        }
    }

    fn default_quotas() -> HashMap<GatewayResourceType, Quota> {
        let mut defaults = HashMap::new();

        // Default inference: 1M tokens per day
        defaults.insert(
            GatewayResourceType::Inference,
            Quota {
                resource_type: GatewayResourceType::Inference,
                limit: 1_000_000,
                reset_period: Some(Duration::from_secs(86400)),
            },
        );

        // Default compute: 3600 CPU-seconds per day (1 hour)
        defaults.insert(
            GatewayResourceType::Compute,
            Quota {
                resource_type: GatewayResourceType::Compute,
                limit: 3600,
                reset_period: Some(Duration::from_secs(86400)),
            },
        );

        // Default storage: 10 GB
        defaults.insert(
            GatewayResourceType::Storage,
            Quota {
                resource_type: GatewayResourceType::Storage,
                limit: 10 * 1024 * 1024 * 1024,
                reset_period: None, // No reset for storage
            },
        );

        // Default bandwidth: 100 GB per day
        defaults.insert(
            GatewayResourceType::Bandwidth,
            Quota {
                resource_type: GatewayResourceType::Bandwidth,
                limit: 100 * 1024 * 1024 * 1024,
                reset_period: Some(Duration::from_secs(86400)),
            },
        );

        defaults
    }

    /// Configure quota for a lease.
    pub async fn set_quota(&self, lease_id: &str, quota: Quota) {
        let mut quotas = self.quotas.write().await;
        let lease_quotas = quotas.entry(lease_id.to_string()).or_default();
        lease_quotas.insert(quota.resource_type, Arc::new(QuotaState::new(quota)));
    }

    /// Get or create quota state for a lease/resource.
    async fn get_or_create_quota(
        &self,
        lease_id: &str,
        resource_type: GatewayResourceType,
    ) -> Arc<QuotaState> {
        let mut quotas = self.quotas.write().await;
        let lease_quotas = quotas.entry(lease_id.to_string()).or_default();

        if let Some(state) = lease_quotas.get(&resource_type) {
            return state.clone();
        }

        // Create from defaults
        let default = self.defaults.get(&resource_type).cloned().unwrap_or(Quota {
            resource_type,
            limit: 0, // No quota = blocked
            reset_period: None,
        });

        let state = Arc::new(QuotaState::new(default));
        lease_quotas.insert(resource_type, state.clone());
        state
    }

    /// Check if a request is within quota.
    pub async fn check(
        &self,
        lease_id: &str,
        resource_type: GatewayResourceType,
        requested: u64,
    ) -> Result<QuotaCheck, QuotaError> {
        let state = self.get_or_create_quota(lease_id, resource_type).await;
        state.check(requested).await?;

        Ok(QuotaCheck {
            allowed: true,
            remaining: state.remaining().saturating_sub(requested),
            limit: state.config.limit,
            used: state.used(),
        })
    }

    /// Consume quota after successful request.
    pub async fn consume(&self, lease_id: &str, resource_type: GatewayResourceType, amount: u64) {
        let state = self.get_or_create_quota(lease_id, resource_type).await;
        state.consume(amount);
    }

    /// Get current quota status.
    pub async fn status(
        &self,
        lease_id: &str,
        resource_type: GatewayResourceType,
    ) -> Option<QuotaCheck> {
        let quotas = self.quotas.read().await;
        let lease_quotas = quotas.get(lease_id)?;
        let state = lease_quotas.get(&resource_type)?;

        Some(QuotaCheck {
            allowed: state.remaining() > 0,
            remaining: state.remaining(),
            limit: state.config.limit,
            used: state.used(),
        })
    }
}

impl Default for QuotaManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_quota_check() {
        let state = QuotaState::new(Quota {
            resource_type: GatewayResourceType::Inference,
            limit: 1000,
            reset_period: None,
        });

        // Should allow
        assert!(state.check(500).await.is_ok());
        state.consume(500);

        // Should still allow
        assert!(state.check(400).await.is_ok());
        state.consume(400);

        // Should deny - would exceed
        assert!(state.check(200).await.is_err());

        // Can still use remaining
        assert!(state.check(100).await.is_ok());
    }

    #[tokio::test]
    async fn test_quota_manager() {
        let manager = QuotaManager::new();

        // Set custom quota
        manager
            .set_quota(
                "lease_123",
                Quota {
                    resource_type: GatewayResourceType::Inference,
                    limit: 5000,
                    reset_period: None,
                },
            )
            .await;

        // Check quota
        let result = manager
            .check("lease_123", GatewayResourceType::Inference, 1000)
            .await;
        assert!(result.is_ok());
        let check = result.unwrap();
        assert_eq!(check.limit, 5000);

        // Consume
        manager
            .consume("lease_123", GatewayResourceType::Inference, 1000)
            .await;

        // Check remaining
        let status = manager
            .status("lease_123", GatewayResourceType::Inference)
            .await;
        assert!(status.is_some());
        let status = status.unwrap();
        assert_eq!(status.used, 1000);
        assert_eq!(status.remaining, 4000);
    }

    #[tokio::test]
    async fn test_default_quotas() {
        let manager = QuotaManager::new();

        // New lease should get default quota
        let result = manager
            .check("new_lease", GatewayResourceType::Inference, 100)
            .await;
        assert!(result.is_ok());
        let check = result.unwrap();
        assert_eq!(check.limit, 1_000_000); // Default inference limit
    }
}
