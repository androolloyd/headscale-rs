//! Bandwidth metering for mesh transport.
//!
//! This module provides transport-layer metering. Escrow, payment,
//! and settlement live in an external integration layer that consumes
//! `MeteringSnapshot` events from this service.
//!
//! # Responsibilities
//!
//! Headscale-rs (this module):
//! - Track bytes in/out per session
//! - Surface `MeteringSnapshot` events to consumers
//! - Rate limiting based on caller-provided limits
//!
//! Integration layer (out-of-tree):
//! - Session lifecycle / escrow / settlement
//! - Payment rail selection
//! - Fund release on close

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Unique identifier for a metering session.
/// The integration layer supplies this — typically its escrow / work ID.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MeteringSessionId(pub String);

impl MeteringSessionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl std::fmt::Display for MeteringSessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Configuration for a metering session (supplied by the integration layer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeteringConfig {
    /// Maximum bytes allowed (None = unlimited).
    pub bandwidth_limit: Option<u64>,
    /// Rate limit in bytes per second (None = unlimited).
    pub rate_limit: Option<u64>,
    /// Consumer DID (for logging/attribution).
    pub consumer_did: String,
    /// Provider DID (for logging/attribution).
    pub provider_did: String,
}

impl Default for MeteringConfig {
    fn default() -> Self {
        Self {
            bandwidth_limit: None,
            rate_limit: None,
            consumer_did: String::new(),
            provider_did: String::new(),
        }
    }
}

/// A metering session tracks bandwidth for a single integration-layer work item.
#[derive(Debug)]
pub struct MeteringSession {
    /// Session ID (supplied by the integration layer).
    pub id: MeteringSessionId,
    /// Configuration.
    pub config: MeteringConfig,
    /// Bytes received.
    pub bytes_in: AtomicU64,
    /// Bytes sent.
    pub bytes_out: AtomicU64,
    /// Session start time.
    pub started_at: Instant,
    /// Last activity time.
    pub last_activity: RwLock<Instant>,
    /// Whether session is active.
    pub active: bool,
}

impl MeteringSession {
    /// Create a new metering session.
    pub fn new(id: MeteringSessionId, config: MeteringConfig) -> Self {
        let now = Instant::now();
        Self {
            id,
            config,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            started_at: now,
            last_activity: RwLock::new(now),
            active: true,
        }
    }

    /// Record incoming bytes.
    pub fn record_incoming(&self, bytes: u64) -> Result<(), MeteringError> {
        if !self.active {
            return Err(MeteringError::SessionInactive);
        }

        if let Some(limit) = self.config.bandwidth_limit {
            let current = self.total_bytes();
            if current + bytes > limit {
                return Err(MeteringError::BandwidthExceeded {
                    limit,
                    current,
                    requested: bytes,
                });
            }
        }

        self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
        Ok(())
    }

    /// Record outgoing bytes.
    pub fn record_outgoing(&self, bytes: u64) -> Result<(), MeteringError> {
        if !self.active {
            return Err(MeteringError::SessionInactive);
        }

        if let Some(limit) = self.config.bandwidth_limit {
            let current = self.total_bytes();
            if current + bytes > limit {
                return Err(MeteringError::BandwidthExceeded {
                    limit,
                    current,
                    requested: bytes,
                });
            }
        }

        self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
        Ok(())
    }

    /// Record bidirectional bytes.
    pub fn record_bidirectional(&self, bytes_in: u64, bytes_out: u64) -> Result<(), MeteringError> {
        if !self.active {
            return Err(MeteringError::SessionInactive);
        }

        let total_new = bytes_in + bytes_out;
        if let Some(limit) = self.config.bandwidth_limit {
            let current = self.total_bytes();
            if current + total_new > limit {
                return Err(MeteringError::BandwidthExceeded {
                    limit,
                    current,
                    requested: total_new,
                });
            }
        }

        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
        Ok(())
    }

    /// Get total bytes (in + out).
    pub fn total_bytes(&self) -> u64 {
        self.bytes_in.load(Ordering::Relaxed) + self.bytes_out.load(Ordering::Relaxed)
    }

    /// Get remaining bandwidth (if limited).
    pub fn remaining_bandwidth(&self) -> Option<u64> {
        self.config.bandwidth_limit.map(|limit| {
            limit.saturating_sub(self.total_bytes())
        })
    }

    /// Get session duration.
    pub fn duration_secs(&self) -> u64 {
        self.started_at.elapsed().as_secs()
    }

    /// Create a snapshot of the session state.
    pub fn snapshot(&self) -> MeteringSnapshot {
        MeteringSnapshot {
            session_id: self.id.clone(),
            consumer_did: self.config.consumer_did.clone(),
            provider_did: self.config.provider_did.clone(),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
            bandwidth_limit: self.config.bandwidth_limit,
            remaining: self.remaining_bandwidth(),
            duration_secs: self.duration_secs(),
            active: self.active,
        }
    }
}

/// Snapshot of metering state (for reporting to an external billing layer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeteringSnapshot {
    pub session_id: MeteringSessionId,
    pub consumer_did: String,
    pub provider_did: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub bandwidth_limit: Option<u64>,
    pub remaining: Option<u64>,
    pub duration_secs: u64,
    pub active: bool,
}

impl MeteringSnapshot {
    /// Total bytes (in + out).
    pub fn total_bytes(&self) -> u64 {
        self.bytes_in + self.bytes_out
    }

    /// Convert to KB (for billing purposes).
    pub fn total_kb(&self) -> u64 {
        (self.total_bytes() + 1023) / 1024
    }
}

/// Metering errors.
#[derive(Debug, thiserror::Error)]
pub enum MeteringError {
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Session inactive")]
    SessionInactive,

    #[error("Bandwidth exceeded: limit={limit}, current={current}, requested={requested}")]
    BandwidthExceeded {
        limit: u64,
        current: u64,
        requested: u64,
    },

    #[error("Rate limit exceeded")]
    RateLimitExceeded,
}

/// The metering service tracks bandwidth for all active sessions.
///
/// The integration layer uses this to:
/// 1. Start metering sessions (tied to its escrow/work IDs)
/// 2. Query current usage
/// 3. End sessions and get final totals
pub struct MeteringService {
    /// Active sessions.
    sessions: Arc<RwLock<HashMap<MeteringSessionId, MeteringSession>>>,
}

impl MeteringService {
    /// Create a new metering service.
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Start a new metering session.
    ///
    /// The session_id is supplied by the caller (e.g., escrow ID or work ID).
    pub async fn start_session(
        &self,
        session_id: MeteringSessionId,
        config: MeteringConfig,
    ) -> Result<(), MeteringError> {
        let session = MeteringSession::new(session_id.clone(), config);
        self.sessions.write().await.insert(session_id, session);
        Ok(())
    }

    /// Record bandwidth usage for a session.
    pub async fn record_usage(
        &self,
        session_id: &MeteringSessionId,
        bytes_in: u64,
        bytes_out: u64,
    ) -> Result<(), MeteringError> {
        let sessions = self.sessions.read().await;
        let session = sessions
            .get(session_id)
            .ok_or_else(|| MeteringError::SessionNotFound(session_id.to_string()))?;

        session.record_bidirectional(bytes_in, bytes_out)
    }

    /// Get current usage for a session.
    pub async fn get_usage(&self, session_id: &MeteringSessionId) -> Option<MeteringSnapshot> {
        self.sessions.read().await.get(session_id).map(|s| s.snapshot())
    }

    /// End a metering session and return final snapshot.
    pub async fn end_session(
        &self,
        session_id: &MeteringSessionId,
    ) -> Result<MeteringSnapshot, MeteringError> {
        let mut sessions = self.sessions.write().await;
        let mut session = sessions
            .remove(session_id)
            .ok_or_else(|| MeteringError::SessionNotFound(session_id.to_string()))?;

        session.active = false;
        Ok(session.snapshot())
    }

    /// Get all active sessions.
    pub async fn active_sessions(&self) -> Vec<MeteringSnapshot> {
        self.sessions
            .read()
            .await
            .values()
            .filter(|s| s.active)
            .map(|s| s.snapshot())
            .collect()
    }

    /// Get sessions for a consumer.
    pub async fn consumer_sessions(&self, consumer_did: &str) -> Vec<MeteringSnapshot> {
        self.sessions
            .read()
            .await
            .values()
            .filter(|s| s.config.consumer_did == consumer_did)
            .map(|s| s.snapshot())
            .collect()
    }

    /// Get sessions for a provider.
    pub async fn provider_sessions(&self, provider_did: &str) -> Vec<MeteringSnapshot> {
        self.sessions
            .read()
            .await
            .values()
            .filter(|s| s.config.provider_did == provider_did)
            .map(|s| s.snapshot())
            .collect()
    }

    /// Get total bytes metered for a provider (across all sessions).
    pub async fn provider_total_bytes(&self, provider_did: &str) -> u64 {
        self.provider_sessions(provider_did)
            .await
            .iter()
            .map(|s| s.total_bytes())
            .sum()
    }
}

impl Default for MeteringService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metering_session_lifecycle() {
        let service = MeteringService::new();

        let session_id = MeteringSessionId::new("escrow-123");
        let config = MeteringConfig {
            bandwidth_limit: Some(1_000_000), // 1MB
            rate_limit: None,
            consumer_did: "did:key:alice".to_string(),
            provider_did: "did:key:bob".to_string(),
        };

        // Start session
        service.start_session(session_id.clone(), config).await.unwrap();

        // Record usage
        service.record_usage(&session_id, 10_000, 5_000).await.unwrap();
        service.record_usage(&session_id, 20_000, 15_000).await.unwrap();

        // Check usage
        let usage = service.get_usage(&session_id).await.unwrap();
        assert_eq!(usage.bytes_in, 30_000);
        assert_eq!(usage.bytes_out, 20_000);
        assert_eq!(usage.total_bytes(), 50_000);
        assert_eq!(usage.remaining, Some(950_000));

        // End session
        let final_usage = service.end_session(&session_id).await.unwrap();
        assert_eq!(final_usage.total_bytes(), 50_000);
        assert!(!final_usage.active);

        // Session should be gone
        assert!(service.get_usage(&session_id).await.is_none());
    }

    #[tokio::test]
    async fn test_bandwidth_limit_enforcement() {
        let service = MeteringService::new();

        let session_id = MeteringSessionId::new("limited-session");
        let config = MeteringConfig {
            bandwidth_limit: Some(10_000), // 10KB
            rate_limit: None,
            consumer_did: "did:key:alice".to_string(),
            provider_did: "did:key:bob".to_string(),
        };

        service.start_session(session_id.clone(), config).await.unwrap();

        // Use most of bandwidth
        service.record_usage(&session_id, 8_000, 0).await.unwrap();

        // Exceed limit should fail
        let result = service.record_usage(&session_id, 5_000, 0).await;
        assert!(matches!(result, Err(MeteringError::BandwidthExceeded { .. })));

        // Can still use remaining
        service.record_usage(&session_id, 2_000, 0).await.unwrap();

        let usage = service.get_usage(&session_id).await.unwrap();
        assert_eq!(usage.remaining, Some(0));
    }

    #[tokio::test]
    async fn test_multiple_sessions() {
        let service = MeteringService::new();

        // Start sessions for different work items
        for i in 0..3 {
            let session_id = MeteringSessionId::new(format!("work-{}", i));
            let config = MeteringConfig {
                bandwidth_limit: None,
                rate_limit: None,
                consumer_did: "did:key:alice".to_string(),
                provider_did: "did:key:bob".to_string(),
            };
            service.start_session(session_id.clone(), config).await.unwrap();
            service.record_usage(&session_id, 1000 * (i + 1) as u64, 0).await.unwrap();
        }

        // Check provider total
        let total = service.provider_total_bytes("did:key:bob").await;
        assert_eq!(total, 6000); // 1000 + 2000 + 3000

        // Check active sessions
        let active = service.active_sessions().await;
        assert_eq!(active.len(), 3);
    }

    #[test]
    fn test_snapshot_kb_conversion() {
        let snapshot = MeteringSnapshot {
            session_id: MeteringSessionId::new("test"),
            consumer_did: String::new(),
            provider_did: String::new(),
            bytes_in: 1500,
            bytes_out: 500,
            bandwidth_limit: None,
            remaining: None,
            duration_secs: 0,
            active: true,
        };

        assert_eq!(snapshot.total_bytes(), 2000);
        assert_eq!(snapshot.total_kb(), 2); // Rounds up
    }
}
