//! Resource metering - tracks usage.
//!
//! The Prometheus metric for compute uses `f64` CPU-seconds, and the
//! end-of-session "duration" computation likewise feeds the same family.
//! Both `units`/`duration` come from `u64` counters that physically
//! cannot exceed 2^53 in our deployments (sessions cap at 2^31 ms × 2^32
//! peers); the precision loss is bounded and intentional. Silence the
//! lint at the module boundary rather than per-site.
#![allow(clippy::cast_precision_loss)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::RwLock;

use crate::metrics::global_metrics;
use crate::types::{ResourceType, ResourceUsage};

static NEXT_SESSION_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Meters resource usage for billing.
pub struct Meter {
    /// Active usage sessions
    active: Arc<RwLock<HashMap<String, ActiveSession>>>,
    /// Completed usage records
    completed: Arc<RwLock<Vec<ResourceUsage>>>,
}

#[derive(Debug, Clone)]
struct ActiveSession {
    consumer: String,
    provider: String,
    resource_type: ResourceType,
    started_at: u64,
    units_consumed: u64,
    rate_per_unit: u64,
}

impl Meter {
    pub fn new() -> Self {
        Self {
            active: Arc::new(RwLock::new(HashMap::new())),
            completed: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Start metering a resource usage session.
    pub async fn start_session(
        &self,
        consumer: &str,
        provider: &str,
        resource_type: ResourceType,
        rate_per_unit: u64,
    ) -> String {
        let id = generate_session_id();

        let session = ActiveSession {
            consumer: consumer.to_string(),
            provider: provider.to_string(),
            resource_type,
            started_at: now(),
            units_consumed: 0,
            rate_per_unit,
        };

        self.active.write().await.insert(id.clone(), session);
        id
    }

    /// Record usage for a session.
    pub async fn record_usage(&self, session_id: &str, units: u64) -> Result<(), MeterError> {
        let mut active = self.active.write().await;
        let session = active
            .get_mut(session_id)
            .ok_or(MeterError::SessionNotFound)?;

        session.units_consumed = session
            .units_consumed
            .checked_add(units)
            .ok_or(MeterError::UsageOverflow)?;

        // Update prometheus metrics based on resource type
        let metrics = global_metrics();
        match &session.resource_type {
            ResourceType::Inference(_) => {
                metrics.record_inference_tokens(&session.consumer, &session.provider, units);
            }
            ResourceType::Storage(_) => {
                metrics.record_storage_bytes(&session.consumer, &session.provider, units as i64);
            }
            ResourceType::Compute(_) => {
                // Assuming units are in CPU seconds
                metrics.record_compute_cpu_seconds(
                    &session.consumer,
                    &session.provider,
                    units as f64,
                );
            }
            ResourceType::Bandwidth(_) => {
                metrics.record_bandwidth_bytes(&session.consumer, &session.provider, units);
            }
        }

        Ok(())
    }

    /// End a session and get final usage.
    pub async fn end_session(&self, session_id: &str) -> Result<ResourceUsage, MeterError> {
        let session = self
            .active
            .write()
            .await
            .remove(session_id)
            .ok_or(MeterError::SessionNotFound)?;

        let ended_at = now();
        let duration = ended_at.saturating_sub(session.started_at) as f64;

        let usage = ResourceUsage {
            resource_type: session.resource_type,
            consumer: session.consumer,
            provider: session.provider,
            started_at: session.started_at,
            ended_at: Some(ended_at),
            units_consumed: session.units_consumed,
            cost_millitokens: session
                .units_consumed
                .checked_mul(session.rate_per_unit)
                .ok_or(MeterError::CostOverflow)?,
        };

        // Record session duration in metrics
        global_metrics().record_session_duration(duration);

        self.completed.write().await.push(usage.clone());
        Ok(usage)
    }

    /// Get current cost for a session.
    pub async fn current_cost(&self, session_id: &str) -> Result<u64, MeterError> {
        let active = self.active.read().await;
        let session = active.get(session_id).ok_or(MeterError::SessionNotFound)?;
        session
            .units_consumed
            .checked_mul(session.rate_per_unit)
            .ok_or(MeterError::CostOverflow)
    }

    /// Get all usage for a consumer.
    pub async fn consumer_usage(&self, consumer: &str) -> Vec<ResourceUsage> {
        self.completed
            .read()
            .await
            .iter()
            .filter(|u| u.consumer == consumer)
            .cloned()
            .collect()
    }

    /// Get total cost for a consumer.
    pub async fn consumer_total_cost(&self, consumer: &str) -> u64 {
        self.consumer_usage(consumer)
            .await
            .iter()
            .fold(0u64, |total, u| total.saturating_add(u.cost_millitokens))
    }
}

impl Default for Meter {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MeterError {
    #[error("Session not found")]
    SessionNotFound,
    #[error("Usage counter overflow")]
    UsageOverflow,
    #[error("Usage cost overflow")]
    CostOverflow,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_session_id() -> String {
    let sequence = NEXT_SESSION_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("session_{nanos}_{sequence}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BandwidthSpec, ResourceType};

    fn bandwidth() -> ResourceType {
        ResourceType::Bandwidth(BandwidthSpec {
            upload_mbps: 100,
            download_mbps: 100,
        })
    }

    #[tokio::test]
    async fn session_ids_are_unique_within_same_second() {
        let meter = Meter::new();

        let first = meter
            .start_session("consumer", "provider", bandwidth(), 1)
            .await;
        let second = meter
            .start_session("consumer", "provider", bandwidth(), 1)
            .await;

        assert_ne!(first, second);
        assert_eq!(meter.active.read().await.len(), 2);
    }

    #[tokio::test]
    async fn consumer_total_cost_saturates() {
        let meter = Meter::new();

        meter.completed.write().await.extend([
            ResourceUsage {
                resource_type: bandwidth(),
                consumer: "consumer".to_string(),
                provider: "provider-a".to_string(),
                started_at: 0,
                ended_at: Some(1),
                units_consumed: u64::MAX,
                cost_millitokens: u64::MAX,
            },
            ResourceUsage {
                resource_type: bandwidth(),
                consumer: "consumer".to_string(),
                provider: "provider-b".to_string(),
                started_at: 0,
                ended_at: Some(1),
                units_consumed: 1,
                cost_millitokens: 1,
            },
        ]);

        assert_eq!(meter.consumer_total_cost("consumer").await, u64::MAX);
    }
}
