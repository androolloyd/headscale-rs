//! Admin API-key surface backed by headscale-go-compatible keys.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApiKeyAdminKey {
    pub id: u64,
    pub prefix: String,
    pub expiration: Option<i64>,
    #[serde(skip)]
    pub expiration_precise: Option<DateTime<Utc>>,
    pub created_at: i64,
    #[serde(skip)]
    pub created_at_precise: Option<DateTime<Utc>>,
    pub last_seen: Option<i64>,
    #[serde(skip)]
    pub last_seen_precise: Option<DateTime<Utc>>,
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
    async fn validate_for_state(&self, candidate: &str) -> Result<bool, ApiKeyAdminError> {
        Ok(self.validate(candidate).await)
    }
    async fn mint(&self, req: ApiKeyMintRequest) -> Result<ApiKeyCreated, ApiKeyAdminError>;
    async fn mint_precise(
        &self,
        req: ApiKeyMintRequest,
        _expiration: Option<DateTime<Utc>>,
    ) -> Result<ApiKeyCreated, ApiKeyAdminError> {
        self.mint(req).await
    }
    async fn list(&self) -> Vec<ApiKeyAdminKey>;
    /// Go ListAPIKeys propagates storage/scan errors. Existing embedders keep
    /// their list contract; native stores override this checked state path.
    async fn list_for_state(&self) -> Result<Vec<ApiKeyAdminKey>, ApiKeyAdminError> {
        Ok(self.list().await)
    }
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
        self.validate_for_state(candidate).await.unwrap_or(false)
    }

    async fn validate_for_state(&self, candidate: &str) -> Result<bool, ApiKeyAdminError> {
        headscale_db::api_keys::validate(&self.pool, candidate)
            .await
            .map_err(|error| ApiKeyAdminError::Store(error.to_string()))
    }

    async fn mint(&self, req: ApiKeyMintRequest) -> Result<ApiKeyCreated, ApiKeyAdminError> {
        self.mint_precise(req, None).await
    }

    async fn mint_precise(
        &self,
        req: ApiKeyMintRequest,
        expiration: Option<DateTime<Utc>>,
    ) -> Result<ApiKeyCreated, ApiKeyAdminError> {
        let created = headscale_db::api_keys::create_with_cost_precise(
            &self.pool,
            headscale_db::api_keys::CreateParams {
                expiration: req.expiration,
            },
            self.cost,
            expiration,
        )
        .await
        .map_err(map_db_err)?;
        Ok(ApiKeyCreated {
            api_key: created.plaintext,
        })
    }

    async fn list(&self) -> Vec<ApiKeyAdminKey> {
        match self.list_for_state().await {
            Ok(mut keys) => {
                keys.sort_by_key(|key| key.id);
                keys
            }
            Err(e) => {
                tracing::warn!(?e, "api key list failed");
                Vec::new()
            }
        }
    }

    async fn list_for_state(&self) -> Result<Vec<ApiKeyAdminKey>, ApiKeyAdminError> {
        let rows = headscale_db::api_keys::list_for_state(&self.pool)
            .await
            .map_err(map_db_err)?;
        Ok(rows.iter().map(row_to_admin).collect())
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
        self.validate_for_state(candidate).await.unwrap_or(false)
    }

    async fn validate_for_state(&self, candidate: &str) -> Result<bool, ApiKeyAdminError> {
        headscale_db::api_keys::validate_postgres(&self.pool, candidate)
            .await
            .map_err(|error| ApiKeyAdminError::Store(error.to_string()))
    }

    async fn mint(&self, req: ApiKeyMintRequest) -> Result<ApiKeyCreated, ApiKeyAdminError> {
        self.mint_precise(req, None).await
    }

    async fn mint_precise(
        &self,
        req: ApiKeyMintRequest,
        expiration: Option<DateTime<Utc>>,
    ) -> Result<ApiKeyCreated, ApiKeyAdminError> {
        let created = headscale_db::api_keys::create_postgres_with_cost_precise(
            &self.pool,
            headscale_db::api_keys::CreateParams {
                expiration: req.expiration,
            },
            self.cost,
            expiration,
        )
        .await
        .map_err(map_db_err)?;
        Ok(ApiKeyCreated {
            api_key: created.plaintext,
        })
    }

    async fn list(&self) -> Vec<ApiKeyAdminKey> {
        match self.list_for_state().await {
            Ok(mut keys) => {
                keys.sort_by_key(|key| key.id);
                keys
            }
            Err(e) => {
                tracing::warn!(?e, "api key list failed");
                Vec::new()
            }
        }
    }

    async fn list_for_state(&self) -> Result<Vec<ApiKeyAdminKey>, ApiKeyAdminError> {
        let rows = headscale_db::api_keys::list_postgres_for_state(&self.pool)
            .await
            .map_err(map_db_err)?;
        Ok(rows.iter().map(row_to_admin).collect())
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
        expiration_precise: row.expiration_datetime(),
        created_at: row.created_at,
        created_at_precise: row.created_at_datetime(),
        last_seen: row.last_seen,
        last_seen_precise: row.last_seen_datetime(),
    }
}

fn map_db_err(e: headscale_db::DbError) -> ApiKeyAdminError {
    match e {
        headscale_db::DbError::NotFound(_) => ApiKeyAdminError::NotFound,
        error => ApiKeyAdminError::Store(error.headscale_go_message()),
    }
}
