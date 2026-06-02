//! Admin API-key surface backed by headscale-go-compatible keys.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKeyAdminKey {
    pub id: u64,
    pub prefix: String,
    pub expiration: Option<i64>,
    pub created_at: i64,
    pub last_seen: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKeyMintRequest {
    pub expiration: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKeyCreated {
    pub api_key: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ApiKeyAdminError {
    #[error("api key not found")]
    NotFound,
    #[error("api key store error: {0}")]
    Store(String),
}

#[async_trait]
pub trait ApiKeyAdmin: Send + Sync + 'static {
    async fn validate(&self, candidate: &str) -> bool;
    async fn mint(&self, req: ApiKeyMintRequest) -> Result<ApiKeyCreated, ApiKeyAdminError>;
    async fn list(&self) -> Vec<ApiKeyAdminKey>;
    async fn expire_by_id(&self, id: u64) -> Result<(), ApiKeyAdminError>;
    async fn expire_by_prefix(&self, prefix: &str) -> Result<(), ApiKeyAdminError>;
    async fn delete_by_id(&self, id: u64) -> Result<(), ApiKeyAdminError>;
    async fn delete_by_prefix(&self, prefix: &str) -> Result<(), ApiKeyAdminError>;
}

#[derive(Default)]
pub struct NoopApiKeyAdmin;

#[async_trait]
impl ApiKeyAdmin for NoopApiKeyAdmin {
    async fn validate(&self, _candidate: &str) -> bool {
        false
    }

    async fn mint(&self, _req: ApiKeyMintRequest) -> Result<ApiKeyCreated, ApiKeyAdminError> {
        Err(ApiKeyAdminError::Store(
            "api key store not configured".into(),
        ))
    }

    async fn list(&self) -> Vec<ApiKeyAdminKey> {
        Vec::new()
    }

    async fn expire_by_prefix(&self, _prefix: &str) -> Result<(), ApiKeyAdminError> {
        Err(ApiKeyAdminError::NotFound)
    }

    async fn expire_by_id(&self, _id: u64) -> Result<(), ApiKeyAdminError> {
        Err(ApiKeyAdminError::NotFound)
    }

    async fn delete_by_prefix(&self, _prefix: &str) -> Result<(), ApiKeyAdminError> {
        Err(ApiKeyAdminError::NotFound)
    }

    async fn delete_by_id(&self, _id: u64) -> Result<(), ApiKeyAdminError> {
        Err(ApiKeyAdminError::NotFound)
    }
}

#[derive(Clone)]
pub struct PersistentApiKeyAdmin {
    pool: sqlx::SqlitePool,
    cost: u32,
}

impl PersistentApiKeyAdmin {
    pub fn new(pool: sqlx::SqlitePool) -> Self {
        Self {
            pool,
            cost: headscale_db::api_keys::BCRYPT_COST_DEFAULT,
        }
    }

    pub fn new_for_test(pool: sqlx::SqlitePool) -> Self {
        Self {
            pool,
            cost: headscale_db::api_keys::BCRYPT_COST_TEST,
        }
    }
}

#[async_trait]
impl ApiKeyAdmin for PersistentApiKeyAdmin {
    async fn validate(&self, candidate: &str) -> bool {
        headscale_db::api_keys::validate(&self.pool, candidate)
            .await
            .unwrap_or(false)
    }

    async fn mint(&self, req: ApiKeyMintRequest) -> Result<ApiKeyCreated, ApiKeyAdminError> {
        let created = headscale_db::api_keys::create_with_cost(
            &self.pool,
            headscale_db::api_keys::CreateParams {
                expiration: req.expiration,
            },
            self.cost,
        )
        .await
        .map_err(map_db_err)?;
        Ok(ApiKeyCreated {
            api_key: created.plaintext,
        })
    }

    async fn list(&self) -> Vec<ApiKeyAdminKey> {
        match headscale_db::api_keys::list(&self.pool).await {
            Ok(rows) => rows.iter().map(row_to_admin).collect(),
            Err(e) => {
                tracing::warn!(?e, "api key list failed");
                Vec::new()
            }
        }
    }

    async fn expire_by_prefix(&self, prefix: &str) -> Result<(), ApiKeyAdminError> {
        headscale_db::api_keys::expire_by_prefix(&self.pool, prefix)
            .await
            .map_err(map_db_err)
    }

    async fn expire_by_id(&self, id: u64) -> Result<(), ApiKeyAdminError> {
        let id = i64::try_from(id)
            .map_err(|_| ApiKeyAdminError::Store("api key id overflows i64".into()))?;
        headscale_db::api_keys::expire(&self.pool, id)
            .await
            .map_err(map_db_err)
    }

    async fn delete_by_prefix(&self, prefix: &str) -> Result<(), ApiKeyAdminError> {
        headscale_db::api_keys::destroy_by_prefix(&self.pool, prefix)
            .await
            .map_err(map_db_err)
    }

    async fn delete_by_id(&self, id: u64) -> Result<(), ApiKeyAdminError> {
        let id = i64::try_from(id)
            .map_err(|_| ApiKeyAdminError::Store("api key id overflows i64".into()))?;
        headscale_db::api_keys::destroy(&self.pool, id)
            .await
            .map_err(map_db_err)
    }
}

#[cfg(feature = "postgres-sqlx")]
#[derive(Clone)]
pub struct PersistentPostgresApiKeyAdmin {
    pool: sqlx::PgPool,
    cost: u32,
}

#[cfg(feature = "postgres-sqlx")]
impl PersistentPostgresApiKeyAdmin {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self {
            pool,
            cost: headscale_db::api_keys::BCRYPT_COST_DEFAULT,
        }
    }

    pub fn new_for_test(pool: sqlx::PgPool) -> Self {
        Self {
            pool,
            cost: headscale_db::api_keys::BCRYPT_COST_TEST,
        }
    }
}

#[cfg(feature = "postgres-sqlx")]
#[async_trait]
impl ApiKeyAdmin for PersistentPostgresApiKeyAdmin {
    async fn validate(&self, candidate: &str) -> bool {
        headscale_db::api_keys::validate_postgres(&self.pool, candidate)
            .await
            .unwrap_or(false)
    }

    async fn mint(&self, req: ApiKeyMintRequest) -> Result<ApiKeyCreated, ApiKeyAdminError> {
        let created = headscale_db::api_keys::create_postgres_with_cost(
            &self.pool,
            headscale_db::api_keys::CreateParams {
                expiration: req.expiration,
            },
            self.cost,
        )
        .await
        .map_err(map_db_err)?;
        Ok(ApiKeyCreated {
            api_key: created.plaintext,
        })
    }

    async fn list(&self) -> Vec<ApiKeyAdminKey> {
        match headscale_db::api_keys::list_postgres(&self.pool).await {
            Ok(rows) => rows.iter().map(row_to_admin).collect(),
            Err(e) => {
                tracing::warn!(?e, "api key list failed");
                Vec::new()
            }
        }
    }

    async fn expire_by_prefix(&self, prefix: &str) -> Result<(), ApiKeyAdminError> {
        headscale_db::api_keys::expire_postgres_by_prefix(&self.pool, prefix)
            .await
            .map_err(map_db_err)
    }

    async fn expire_by_id(&self, id: u64) -> Result<(), ApiKeyAdminError> {
        let id = i64::try_from(id)
            .map_err(|_| ApiKeyAdminError::Store("api key id overflows i64".into()))?;
        headscale_db::api_keys::expire_postgres(&self.pool, id)
            .await
            .map_err(map_db_err)
    }

    async fn delete_by_prefix(&self, prefix: &str) -> Result<(), ApiKeyAdminError> {
        headscale_db::api_keys::destroy_postgres_by_prefix(&self.pool, prefix)
            .await
            .map_err(map_db_err)
    }

    async fn delete_by_id(&self, id: u64) -> Result<(), ApiKeyAdminError> {
        let id = i64::try_from(id)
            .map_err(|_| ApiKeyAdminError::Store("api key id overflows i64".into()))?;
        headscale_db::api_keys::destroy_postgres(&self.pool, id)
            .await
            .map_err(map_db_err)
    }
}

fn row_to_admin(row: &headscale_db::api_keys::ApiKeyRow) -> ApiKeyAdminKey {
    ApiKeyAdminKey {
        id: u64::try_from(row.id).unwrap_or_default(),
        prefix: row.display_prefix(),
        expiration: row.expiration,
        created_at: row.created_at,
        last_seen: row.last_seen,
    }
}

fn map_db_err(e: headscale_db::DbError) -> ApiKeyAdminError {
    match e {
        headscale_db::DbError::NotFound(_) => ApiKeyAdminError::NotFound,
        headscale_db::DbError::General(msg) => ApiKeyAdminError::Store(msg),
        other => ApiKeyAdminError::Store(other.to_string()),
    }
}
