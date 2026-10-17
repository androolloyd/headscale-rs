//! Shared database policy adapters for HTTP and gRPC embedders.
use async_trait::async_trait;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedPolicy {
    pub policy: String,
    pub updated_at: i64,
}

#[async_trait]
pub trait PolicyPersistence: Send + Sync {
    async fn get_latest_policy(&self) -> Result<Option<PersistedPolicy>, String>;
    async fn set_policy(&self, policy: &str) -> Result<PersistedPolicy, String>;
}

#[async_trait]
impl PolicyPersistence for sqlx::SqlitePool {
    async fn get_latest_policy(&self) -> Result<Option<PersistedPolicy>, String> {
        headscale_db::policies::get_latest(self)
            .await
            .map(|row| {
                row.map(|policy| PersistedPolicy {
                    policy: policy.data,
                    updated_at: policy.updated_at,
                })
            })
            .map_err(|e| e.to_string())
    }

    async fn set_policy(&self, policy: &str) -> Result<PersistedPolicy, String> {
        headscale_db::policies::set(self, policy)
            .await
            .map(|policy| PersistedPolicy {
                policy: policy.data,
                updated_at: policy.updated_at,
            })
            .map_err(|e| e.to_string())
    }
}

#[cfg(feature = "postgres-sqlx")]
#[async_trait]
impl PolicyPersistence for sqlx::PgPool {
    async fn get_latest_policy(&self) -> Result<Option<PersistedPolicy>, String> {
        headscale_db::policies::get_latest_postgres(self)
            .await
            .map(|row| {
                row.map(|policy| PersistedPolicy {
                    policy: policy.data,
                    updated_at: policy.updated_at,
                })
            })
            .map_err(|e| e.to_string())
    }

    async fn set_policy(&self, policy: &str) -> Result<PersistedPolicy, String> {
        headscale_db::policies::set_postgres(self, policy)
            .await
            .map(|policy| PersistedPolicy {
                policy: policy.data,
                updated_at: policy.updated_at,
            })
            .map_err(|e| e.to_string())
    }
}
