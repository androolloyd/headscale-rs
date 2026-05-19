//! Gateway router - assembles all resource handlers.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};

use super::auth::{AuthLayer, InMemoryLeaseStore, LeaseStore};
use super::inference::{self, InferenceHandler};
use super::quota::QuotaManager;
use super::types::{GatewayErrorResponse, ServiceBackend};

/// Resource Gateway state.
#[derive(Clone)]
pub struct GatewayState {
    /// Inference handler
    pub inference: InferenceHandler,
    /// Quota manager
    pub quota: Arc<QuotaManager>,
    /// Lease store
    pub lease_store: Arc<dyn LeaseStore>,
}

/// Resource Gateway - routes requests to appropriate backends.
pub struct ResourceGateway {
    state: GatewayState,
}

impl ResourceGateway {
    /// Create a new gateway with default components.
    pub fn new() -> Self {
        let lease_store = Arc::new(InMemoryLeaseStore::new());
        let quota = Arc::new(QuotaManager::new());
        let inference = InferenceHandler::new(quota.clone());

        Self {
            state: GatewayState {
                inference,
                quota,
                lease_store,
            },
        }
    }

    /// Create with custom lease store.
    pub fn with_lease_store(lease_store: Arc<dyn LeaseStore>) -> Self {
        let quota = Arc::new(QuotaManager::new());
        let inference = InferenceHandler::new(quota.clone());

        Self {
            state: GatewayState {
                inference,
                quota,
                lease_store,
            },
        }
    }

    /// Get access to the quota manager.
    pub fn quota(&self) -> &Arc<QuotaManager> {
        &self.state.quota
    }

    /// Get access to the inference handler.
    pub fn inference(&self) -> &InferenceHandler {
        &self.state.inference
    }

    /// Register an inference backend.
    pub async fn register_inference_backend(&self, backend: ServiceBackend) {
        self.state.inference.register_backend(backend).await;
    }

    /// Build the Axum router for the gateway.
    pub fn build_router(self) -> Router {
        let auth_layer = AuthLayer::new(self.state.lease_store.clone());
        let inference_state = self.state.inference.clone();
        let gateway_state = self.state.clone();

        // Inference routes (protected by auth)
        let inference_routes = Router::new()
            .route("/chat", post(inference::chat_completions))
            .route("/chat/completions", post(inference::chat_completions))
            .route("/embeddings", post(inference::embeddings))
            .route("/models", get(inference::list_models_handler))
            .with_state(inference_state)
            .layer(auth_layer.clone());

        // Compute routes (stub for now)
        let compute_routes = Router::new()
            .route("/jobs", post(submit_job))
            .route("/jobs/:id", get(get_job).delete(cancel_job))
            .with_state(gateway_state.clone())
            .layer(auth_layer.clone());

        // Storage routes (stub for now)
        // NOTE: axum 0.7 uses `/*path` for catch-all (0.8 brace syntax `/{*path}`
        // is not yet supported by this workspace's axum pin).
        let storage_routes = Router::new()
            .route(
                "/*path",
                get(storage_get).put(storage_put).delete(storage_delete),
            )
            .with_state(gateway_state.clone())
            .layer(auth_layer.clone());

        // Health/status routes (no auth required)
        let health_routes = Router::new()
            .route("/health", get(health_check))
            .route("/status", get(gateway_status))
            .with_state(gateway_state);

        // Assemble the full router
        Router::new()
            .nest("/v1/inference", inference_routes)
            .nest("/v1/compute", compute_routes)
            .nest("/v1/storage", storage_routes)
            .merge(health_routes)
    }
}

impl Default for ResourceGateway {
    fn default() -> Self {
        Self::new()
    }
}

// Compute handlers (stubs)

#[derive(serde::Deserialize)]
pub struct JobRequest {
    pub image: String,
    pub command: Vec<String>,
    #[serde(default)]
    pub resources: JobResources,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
}

fn default_timeout() -> u64 {
    3600
}

#[derive(Debug, Default, serde::Deserialize)]
pub struct JobResources {
    #[serde(default = "default_cpu")]
    pub cpu: String,
    #[serde(default = "default_memory")]
    pub memory: String,
    #[serde(default)]
    pub gpu: Option<String>,
}

fn default_cpu() -> String {
    "1".to_string()
}

fn default_memory() -> String {
    "1Gi".to_string()
}

#[derive(serde::Serialize)]
pub struct JobResponse {
    pub job_id: String,
    pub status: String,
    pub created_at: u64,
}

async fn submit_job(State(_state): State<GatewayState>, Json(_req): Json<JobRequest>) -> Response {
    // Stub: In production, this would submit to compute backend
    let response = JobResponse {
        job_id: format!("job_{}", super::types::now_secs()),
        status: "pending".to_string(),
        created_at: super::types::now_secs() * 1000,
    };

    (StatusCode::ACCEPTED, Json(response)).into_response()
}

async fn get_job(
    State(_state): State<GatewayState>,
    axum::extract::Path(job_id): axum::extract::Path<String>,
) -> Response {
    // Stub
    let response = serde_json::json!({
        "job_id": job_id,
        "status": "running",
        "started_at": super::types::now_secs() * 1000 - 5000,
        "usage": {
            "cpu_seconds": 5.0,
            "gpu_seconds": 0.0,
            "memory_gb_seconds": 5.0
        }
    });

    (StatusCode::OK, Json(response)).into_response()
}

async fn cancel_job(
    State(_state): State<GatewayState>,
    axum::extract::Path(_job_id): axum::extract::Path<String>,
) -> Response {
    // Stub
    (StatusCode::NO_CONTENT, ()).into_response()
}

// Storage handlers (stubs)

async fn storage_get(
    State(_state): State<GatewayState>,
    axum::extract::Path(_path): axum::extract::Path<String>,
) -> Response {
    // Stub: In production, proxy to MinIO/S3
    (
        StatusCode::NOT_FOUND,
        Json(GatewayErrorResponse::not_found("Object not found")),
    )
        .into_response()
}

async fn storage_put(
    State(_state): State<GatewayState>,
    axum::extract::Path(_path): axum::extract::Path<String>,
    _body: axum::body::Bytes,
) -> Response {
    // Stub
    (
        StatusCode::OK,
        Json(serde_json::json!({ "etag": "mock-etag" })),
    )
        .into_response()
}

async fn storage_delete(
    State(_state): State<GatewayState>,
    axum::extract::Path(_path): axum::extract::Path<String>,
) -> Response {
    // Stub
    (StatusCode::NO_CONTENT, ()).into_response()
}

// Health handlers

async fn health_check() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "healthy",
            "timestamp": super::types::now_secs()
        })),
    )
        .into_response()
}

async fn gateway_status(State(state): State<GatewayState>) -> Response {
    let models = state.inference.list_models().await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "operational",
            "inference": {
                "models_available": models.len(),
                "models": models
            },
            "compute": {
                "status": "stub"
            },
            "storage": {
                "status": "stub"
            }
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::super::types::{BackendCapacity, BackendStatus, GatewayResourceType};
    use super::*;

    #[tokio::test]
    async fn test_gateway_creation() {
        let gateway = ResourceGateway::new();

        // Register a backend
        gateway
            .register_inference_backend(ServiceBackend {
                id: "test-backend".to_string(),
                resource_type: GatewayResourceType::Inference,
                url: "http://localhost:11434".to_string(),
                health_check: "/health".to_string(),
                status: BackendStatus::Healthy,
                capacity: BackendCapacity {
                    models: vec!["llama3".to_string()],
                    ..Default::default()
                },
            })
            .await;

        let models = gateway.inference().list_models().await;
        assert!(models.contains(&"llama3".to_string()));
    }

    #[tokio::test]
    async fn test_router_builds() {
        let gateway = ResourceGateway::new();
        let _router = gateway.build_router();
        // Router builds successfully
    }
}
