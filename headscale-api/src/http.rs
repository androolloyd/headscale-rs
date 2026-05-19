//! HTTP/REST API endpoints.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
};
use serde::Serialize;

use crate::control_auth::{
    NonceStore, SignedRegisterRequest, SignedTransferRequest, verify_node_heartbeat,
    verify_node_registration, verify_transfer,
};
use headscale_core::{MeshCoordinator, Node, mesh_metrics};
use headscale_payments::Ledger;
use headscale_resources::{ResourceRegistry, global_metrics};

/// Shared state for handlers.
#[derive(Clone)]
pub struct AppState {
    mesh: Arc<MeshCoordinator>,
    ledger: Arc<Ledger>,
    _resources: Arc<ResourceRegistry>,
    node_nonces: Arc<NonceStore>,
}

/// Build the HTTP router.
pub fn build_router(
    mesh: Arc<MeshCoordinator>,
    ledger: Arc<Ledger>,
    resources: Arc<ResourceRegistry>,
) -> Router {
    let state = AppState {
        mesh,
        ledger,
        _resources: resources,
        node_nonces: Arc::new(NonceStore::new()),
    };

    Router::new()
        // Node management
        .route("/api/v1/nodes", get(list_nodes).post(register_node))
        .route("/api/v1/register", post(register_node))
        .route("/api/v1/nodes/:id", get(get_node))
        .route("/api/v1/nodes/:id/heartbeat", post(heartbeat))
        // Payments
        .route("/api/v1/balance/:did", get(get_balance))
        .route("/api/v1/transfer", post(transfer))
        // Health and observability
        .route("/health", get(health))
        .route("/health/ready", get(readiness))
        .route("/health/live", get(liveness))
        .route("/metrics", get(metrics))
        .route("/api/v1/status", get(detailed_status))
        .with_state(state)
}

// Node handlers

async fn list_nodes(State(state): State<AppState>) -> Json<Vec<Node>> {
    Json(state.mesh.list_nodes().await)
}

async fn register_node(
    State(state): State<AppState>,
    Json(req): Json<SignedRegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    verify_node_registration(&req, &state.node_nonces)
        .map_err(|e| ApiError::Unauthorized(e.to_string()))?;

    let response = state
        .mesh
        .register(req.request)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(RegisterResponse {
        addresses: response.addresses.iter().map(|a| a.to_string()).collect(),
        peer_count: response.peers.len(),
    }))
}

async fn get_node(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Node>, ApiError> {
    let nodes = state.mesh.list_nodes().await;
    nodes
        .into_iter()
        .find(|n| n.id == id)
        .map(Json)
        .ok_or(ApiError::NotFound("Node not found".to_string()))
}

async fn heartbeat(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<HeartbeatResponse>, ApiError> {
    let path = format!("/api/v1/nodes/{id}/heartbeat");
    verify_node_heartbeat(&headers, "POST", &path, &id, &state.node_nonces)
        .map_err(|e| ApiError::Unauthorized(e.to_string()))?;

    state
        .mesh
        .heartbeat(&id)
        .await
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    Ok(Json(HeartbeatResponse { ok: true }))
}

// Payment handlers

async fn get_balance(
    State(state): State<AppState>,
    Path(did): Path<String>,
) -> Json<BalanceResponse> {
    let balance = state.ledger.balance(&did).await;
    let available = state.ledger.available(&did).await;

    Json(BalanceResponse { balance, available })
}

async fn transfer(
    State(state): State<AppState>,
    Json(req): Json<SignedTransferRequest>,
) -> Result<Json<TransferResponse>, ApiError> {
    verify_transfer(&req, &state.node_nonces).map_err(|e| ApiError::Unauthorized(e.to_string()))?;

    let tx = state
        .ledger
        .transfer(&req.from, &req.to, req.amount, &req.description)
        .await
        .map_err(|e| ApiError::Payment(e.to_string()))?;

    Ok(Json(TransferResponse { tx_id: tx.id }))
}

// Health handlers

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        timestamp: now(),
    })
}

/// Kubernetes readiness probe
async fn readiness(State(state): State<AppState>) -> Result<Json<HealthResponse>, ApiError> {
    // Check if we can access the mesh coordinator
    let _nodes = state.mesh.list_nodes().await;

    Ok(Json(HealthResponse {
        status: "ready".to_string(),
        timestamp: now(),
    }))
}

/// Kubernetes liveness probe
async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "alive".to_string(),
        timestamp: now(),
    })
}

/// Detailed status endpoint
async fn detailed_status(State(state): State<AppState>) -> Json<DetailedStatus> {
    let nodes = state.mesh.list_nodes().await;
    let online_count = nodes.iter().filter(|n| n.online).count();
    let derp_servers = state.mesh.derp_servers().await;

    Json(DetailedStatus {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: 0, // TODO: Track actual uptime
        nodes_registered: nodes.len(),
        nodes_online: online_count,
        derp_servers: derp_servers.len(),
        capabilities: StatusCapabilities {
            inference: nodes.iter().any(|n| n.capabilities.inference),
            storage: nodes.iter().any(|n| n.capabilities.storage),
            compute: nodes.iter().any(|n| n.capabilities.compute),
            relay: nodes.iter().any(|n| n.capabilities.relay),
        },
    })
}

async fn metrics(State(state): State<AppState>) -> String {
    // Combine resource and mesh metrics
    let resource_metrics = global_metrics().encode();
    let mesh_metrics_output = mesh_metrics().encode();

    // Update mesh node counts from current state
    let nodes = state.mesh.list_nodes().await;
    let online_count = nodes.iter().filter(|n| n.online).count();
    mesh_metrics().nodes_registered.set(nodes.len() as i64);
    mesh_metrics().nodes_online.set(online_count as i64);

    format!("{}\n{}", resource_metrics, mesh_metrics_output)
}

// Request/Response types

#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub addresses: Vec<String>,
    pub peer_count: usize,
}

#[derive(Debug, Serialize)]
pub struct HeartbeatResponse {
    pub ok: bool,
}

#[derive(Debug, Serialize)]
pub struct BalanceResponse {
    pub balance: i64,
    pub available: i64,
}

#[derive(Debug, Serialize)]
pub struct TransferResponse {
    pub tx_id: String,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: u64,
}

#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub nodes_online: u64,
    pub total_balance: i64,
    pub active_channels: u64,
}

#[derive(Debug, Serialize)]
pub struct DetailedStatus {
    pub version: String,
    pub uptime_seconds: u64,
    pub nodes_registered: usize,
    pub nodes_online: usize,
    pub derp_servers: usize,
    pub capabilities: StatusCapabilities,
}

#[derive(Debug, Serialize)]
pub struct StatusCapabilities {
    pub inference: bool,
    pub storage: bool,
    pub compute: bool,
    pub relay: bool,
}

// Error handling

#[derive(Debug)]
pub enum ApiError {
    Unauthorized(String),
    NotFound(String),
    Payment(String),
    Internal(String),
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ApiError::Unauthorized(msg) => (axum::http::StatusCode::UNAUTHORIZED, msg),
            ApiError::NotFound(msg) => (axum::http::StatusCode::NOT_FOUND, msg),
            ApiError::Payment(msg) => (axum::http::StatusCode::BAD_REQUEST, msg),
            ApiError::Internal(msg) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = serde_json::json!({ "error": message });
        (status, Json(body)).into_response()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
