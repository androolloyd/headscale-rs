//! Database policy source shared by the HTTP admin API and the gRPC service.
//!
//! Custom backends keep the whole-second [`PersistedPolicy`] contract. The
//! native SQLite/Postgres pools override the precise methods with the
//! `TimedPolicyRow` projection so gRPC `GetPolicy`/`SetPolicy` keep fractional
//! `UpdatedAt`; the gRPC layer converts the instant to its wire timestamp.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// The latest stored policy text and its whole-second update time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedPolicy {
    pub policy: String,
    pub updated_at: i64,
}

/// Append-only policy storage. Writes commit before the live policy changes.
#[async_trait]
pub trait PolicyPersistence: Send + Sync {
    async fn get_latest_policy(&self) -> Result<Option<PersistedPolicy>, String>;
    async fn set_policy(&self, policy: &str) -> Result<PersistedPolicy, String>;

    // Existing custom backends retain their whole-second contract. Native
    // pools override these methods without changing PersistedPolicy fields.
    async fn get_latest_policy_with_timestamp(
        &self,
    ) -> Result<Option<(PersistedPolicy, DateTime<Utc>)>, String> {
        self.get_latest_policy().await.map(|policy| {
            policy.map(|policy| {
                let updated_at = whole_seconds(policy.updated_at);
                (policy, updated_at)
            })
        })
    }

    async fn set_policy_with_timestamp(
        &self,
        policy: &str,
    ) -> Result<(PersistedPolicy, DateTime<Utc>), String> {
        self.set_policy(policy).await.map(|policy| {
            let updated_at = whole_seconds(policy.updated_at);
            (policy, updated_at)
        })
    }
}

/// A whole-second instant. Saturate only for sentinel values outside the
/// representable range so the second count a legacy backend reported survives.
fn whole_seconds(updated_at: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(updated_at, 0).unwrap_or(if updated_at < 0 {
        DateTime::<Utc>::MIN_UTC
    } else {
        DateTime::<Utc>::MAX_UTC
    })
}

#[cfg(feature = "admin")]
fn policy_with_timestamp(
    value: headscale_db::policies::TimedPolicyRow,
) -> (PersistedPolicy, DateTime<Utc>) {
    let updated_at = value
        .updated_at_datetime()
        .unwrap_or_else(|| whole_seconds(value.row.updated_at));
    (
        PersistedPolicy {
            policy: value.row.data,
            updated_at: value.row.updated_at,
        },
        updated_at,
    )
}

#[cfg(feature = "admin")]
#[async_trait]
impl PolicyPersistence for sqlx::SqlitePool {
    async fn get_latest_policy(&self) -> Result<Option<PersistedPolicy>, String> {
        self.get_latest_policy_with_timestamp()
            .await
            .map(|value| value.map(|(policy, _)| policy))
    }

    async fn set_policy(&self, policy: &str) -> Result<PersistedPolicy, String> {
        self.set_policy_with_timestamp(policy)
            .await
            .map(|(policy, _)| policy)
    }

    async fn get_latest_policy_with_timestamp(
        &self,
    ) -> Result<Option<(PersistedPolicy, DateTime<Utc>)>, String> {
        headscale_db::policies::get_latest_with_timestamp(self)
            .await
            .map(|value| value.map(policy_with_timestamp))
            .map_err(|error| error.to_string())
    }

    async fn set_policy_with_timestamp(
        &self,
        policy: &str,
    ) -> Result<(PersistedPolicy, DateTime<Utc>), String> {
        headscale_db::policies::set_with_timestamp(self, policy)
            .await
            .map(policy_with_timestamp)
            .map_err(|error| error.to_string())
    }
}

#[cfg(feature = "postgres-sqlx")]
#[async_trait]
impl PolicyPersistence for sqlx::PgPool {
    async fn get_latest_policy(&self) -> Result<Option<PersistedPolicy>, String> {
        self.get_latest_policy_with_timestamp()
            .await
            .map(|value| value.map(|(policy, _)| policy))
    }

    async fn set_policy(&self, policy: &str) -> Result<PersistedPolicy, String> {
        self.set_policy_with_timestamp(policy)
            .await
            .map(|(policy, _)| policy)
    }

    async fn get_latest_policy_with_timestamp(
        &self,
    ) -> Result<Option<(PersistedPolicy, DateTime<Utc>)>, String> {
        headscale_db::policies::get_latest_postgres_with_timestamp(self)
            .await
            .map(|value| value.map(policy_with_timestamp))
            .map_err(|error| error.to_string())
    }

    async fn set_policy_with_timestamp(
        &self,
        policy: &str,
    ) -> Result<(PersistedPolicy, DateTime<Utc>), String> {
        headscale_db::policies::set_postgres_with_timestamp(self, policy)
            .await
            .map(policy_with_timestamp)
            .map_err(|error| error.to_string())
    }
}
