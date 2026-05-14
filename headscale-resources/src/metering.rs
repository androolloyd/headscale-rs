//! Resource metering - tracks usage.

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::metrics::global_metrics;
use crate::types::{ResourceType, ResourceUsage};

/// Meters resource usage for billing.
pub struct Meter {
    /// Active usage sessions
    active: Arc<RwLock<HashMap<String, ActiveSession>>>,
    /// Completed usage records
    completed: Arc<RwLock<Vec<ResourceUsage>>>,
}

#[derive(Debug, Clone)]
struct ActiveSession {
    id: String,
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
            id: id.clone(),
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

        session.units_consumed += units;

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
                metrics.record_compute_cpu_seconds(&session.consumer, &session.provider, units as f64);
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
            cost_millitokens: session.units_consumed * session.rate_per_unit,
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
        Ok(session.units_consumed * session.rate_per_unit)
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
            .map(|u| u.cost_millitokens)
            .sum()
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
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_session_id() -> String {
    format!("session_{}", now())
}
