//! Inference API handler (OpenAI-compatible).

use std::sync::Arc;

use axum::{
    Json,
    extract::{Extension, State},
    http::StatusCode,
    response::{
        IntoResponse, Response,
        sse::{Event, Sse},
    },
};
use futures::stream;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::auth::GatewayIdentity;
use super::quota::QuotaManager;
use super::types::{BackendStatus, GatewayErrorResponse, GatewayResourceType, ServiceBackend};

/// Inference handler state.
#[derive(Clone)]
pub struct InferenceHandler {
    /// Available backends
    backends: Arc<RwLock<Vec<ServiceBackend>>>,
    /// Quota manager
    quota: Arc<QuotaManager>,
    /// HTTP client for backend calls
    _client: reqwest::Client,
}

impl InferenceHandler {
    pub fn new(quota: Arc<QuotaManager>) -> Self {
        Self {
            backends: Arc::new(RwLock::new(Vec::new())),
            quota,
            _client: reqwest::Client::new(),
        }
    }

    /// Register a backend.
    pub async fn register_backend(&self, backend: ServiceBackend) {
        self.backends.write().await.push(backend);
    }

    /// Find a backend that supports the requested model.
    async fn find_backend(&self, model: &str) -> Option<ServiceBackend> {
        let backends = self.backends.read().await;
        backends
            .iter()
            .find(|b| {
                b.status == BackendStatus::Healthy
                    && b.resource_type == GatewayResourceType::Inference
                    && b.capacity.models.iter().any(|m| m == model)
            })
            .cloned()
    }

    /// List available models.
    pub async fn list_models(&self) -> Vec<String> {
        let backends = self.backends.read().await;
        backends
            .iter()
            .filter(|b| b.status == BackendStatus::Healthy)
            .flat_map(|b| b.capacity.models.clone())
            .collect()
    }
}

/// Chat completion request (OpenAI-compatible).
#[derive(Debug, Clone, Deserialize)]
pub struct ChatRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub stream: bool,
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
}

fn default_max_tokens() -> u32 {
    1024
}

fn default_temperature() -> f32 {
    0.7
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// Chat completion response.
#[derive(Debug, Clone, Serialize)]
pub struct ChatResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChatChoice>,
    pub usage: TokenUsage,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatChoice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Streaming response chunk.
#[derive(Debug, Clone, Serialize)]
pub struct ChatChunk {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<ChunkChoice>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<TokenUsage>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChunkChoice {
    pub index: u32,
    pub delta: ChunkDelta,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChunkDelta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

/// Embeddings request.
#[derive(Debug, Clone, Deserialize)]
pub struct EmbeddingsRequest {
    pub model: String,
    pub input: EmbeddingsInput,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum EmbeddingsInput {
    Single(String),
    Multiple(Vec<String>),
}

/// Embeddings response.
#[derive(Debug, Clone, Serialize)]
pub struct EmbeddingsResponse {
    pub object: String,
    pub data: Vec<EmbeddingData>,
    pub model: String,
    pub usage: EmbeddingsUsage,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmbeddingData {
    pub object: String,
    pub embedding: Vec<f32>,
    pub index: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EmbeddingsUsage {
    pub prompt_tokens: u32,
    pub total_tokens: u32,
}

/// Handler for POST /v1/inference/chat
pub async fn chat_completions(
    State(handler): State<InferenceHandler>,
    Extension(identity): Extension<GatewayIdentity>,
    Json(req): Json<ChatRequest>,
) -> Response {
    // Get lease ID (required for quota)
    let lease_id = match &identity.lease_id {
        Some(id) => id.clone(),
        None => {
            // For DID-authenticated requests, use DID as lease ID
            identity.renter_did.clone()
        }
    };

    // Estimate tokens (simple approximation)
    let prompt_tokens: u32 = req
        .messages
        .iter()
        .map(|m| (m.content.len() / 4) as u32)
        .sum();
    let estimated_total = prompt_tokens + req.max_tokens;

    // Check quota
    match handler
        .quota
        .check(
            &lease_id,
            GatewayResourceType::Inference,
            estimated_total as u64,
        )
        .await
    {
        Ok(_) => {}
        Err(super::quota::QuotaError::Exceeded { limit, used, .. }) => {
            return (
                StatusCode::PAYMENT_REQUIRED,
                Json(GatewayErrorResponse::quota_exceeded(limit, used)),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GatewayErrorResponse::internal("Quota check failed")),
            )
                .into_response();
        }
    }

    // Find backend
    let backend = match handler.find_backend(&req.model).await {
        Some(b) => b,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(GatewayErrorResponse::not_found(format!(
                    "Model '{}' not available",
                    req.model
                ))),
            )
                .into_response();
        }
    };

    if req.stream {
        // Streaming response
        handle_streaming_chat(&handler, &lease_id, &backend, &req).await
    } else {
        // Non-streaming response
        handle_blocking_chat(&handler, &lease_id, &backend, &req).await
    }
}

async fn handle_blocking_chat(
    handler: &InferenceHandler,
    lease_id: &str,
    _backend: &ServiceBackend,
    req: &ChatRequest,
) -> Response {
    // In production, this would proxy to the actual backend.
    // For now, return a mock response.
    let prompt_tokens: u32 = req
        .messages
        .iter()
        .map(|m| (m.content.len() / 4) as u32)
        .sum();
    let completion_tokens = 10; // Mock

    // Record usage
    handler
        .quota
        .consume(
            lease_id,
            GatewayResourceType::Inference,
            (prompt_tokens + completion_tokens) as u64,
        )
        .await;

    let response = ChatResponse {
        id: format!("chatcmpl-{}", super::types::now_secs()),
        object: "chat.completion".to_string(),
        created: super::types::now_secs(),
        model: req.model.clone(),
        choices: vec![ChatChoice {
            index: 0,
            message: ChatMessage {
                role: "assistant".to_string(),
                content: "This is a mock response. In production, this would proxy to the backend."
                    .to_string(),
            },
            finish_reason: "stop".to_string(),
        }],
        usage: TokenUsage {
            prompt_tokens,
            completion_tokens,
            total_tokens: prompt_tokens + completion_tokens,
        },
    };

    // Add usage headers
    (
        StatusCode::OK,
        [
            (
                "X-Usage-Units",
                (prompt_tokens + completion_tokens).to_string(),
            ),
            ("X-Usage-Type", "tokens".to_string()),
            (
                "X-Quota-Remaining",
                handler
                    .quota
                    .status(lease_id, GatewayResourceType::Inference)
                    .await
                    .map(|s| s.remaining.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
            ),
        ],
        Json(response),
    )
        .into_response()
}

async fn handle_streaming_chat(
    _handler: &InferenceHandler,
    _lease_id: &str,
    _backend: &ServiceBackend,
    req: &ChatRequest,
) -> Response {
    let model = req.model.clone();
    let created = super::types::now_secs();
    let id = format!("chatcmpl-{}", created);

    // Create a mock stream
    let chunks = vec![
        ChunkDelta {
            role: Some("assistant".to_string()),
            content: None,
        },
        ChunkDelta {
            role: None,
            content: Some("This ".to_string()),
        },
        ChunkDelta {
            role: None,
            content: Some("is ".to_string()),
        },
        ChunkDelta {
            role: None,
            content: Some("a mock ".to_string()),
        },
        ChunkDelta {
            role: None,
            content: Some("streaming response.".to_string()),
        },
    ];

    let stream = stream::iter(chunks.into_iter().enumerate().map(move |(i, delta)| {
        let is_last = i == 4;
        let chunk = ChatChunk {
            id: id.clone(),
            object: "chat.completion.chunk".to_string(),
            created,
            model: model.clone(),
            choices: vec![ChunkChoice {
                index: 0,
                delta,
                finish_reason: if is_last {
                    Some("stop".to_string())
                } else {
                    None
                },
            }],
            usage: if is_last {
                Some(TokenUsage {
                    prompt_tokens: 10,
                    completion_tokens: 8,
                    total_tokens: 18,
                })
            } else {
                None
            },
        };

        let data = serde_json::to_string(&chunk).unwrap();
        Ok::<_, std::convert::Infallible>(Event::default().data(data))
    }));

    Sse::new(stream).into_response()
}

/// Handler for POST /v1/inference/embeddings
pub async fn embeddings(
    State(handler): State<InferenceHandler>,
    Extension(identity): Extension<GatewayIdentity>,
    Json(req): Json<EmbeddingsRequest>,
) -> Response {
    let lease_id = identity.lease_id.unwrap_or(identity.renter_did);

    let inputs = match req.input {
        EmbeddingsInput::Single(s) => vec![s],
        EmbeddingsInput::Multiple(v) => v,
    };

    // Estimate tokens
    let total_tokens: u32 = inputs.iter().map(|s| (s.len() / 4) as u32).sum();

    // Check quota
    match handler
        .quota
        .check(
            &lease_id,
            GatewayResourceType::Inference,
            total_tokens as u64,
        )
        .await
    {
        Ok(_) => {}
        Err(super::quota::QuotaError::Exceeded { limit, used, .. }) => {
            return (
                StatusCode::PAYMENT_REQUIRED,
                Json(GatewayErrorResponse::quota_exceeded(limit, used)),
            )
                .into_response();
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(GatewayErrorResponse::internal("Quota check failed")),
            )
                .into_response();
        }
    }

    // Record usage
    handler
        .quota
        .consume(
            &lease_id,
            GatewayResourceType::Inference,
            total_tokens as u64,
        )
        .await;

    // Mock embeddings (in production, proxy to backend)
    let data: Vec<EmbeddingData> = inputs
        .iter()
        .enumerate()
        .map(|(i, _)| EmbeddingData {
            object: "embedding".to_string(),
            embedding: vec![0.0; 1536], // Mock 1536-dim embedding
            index: i,
        })
        .collect();

    let response = EmbeddingsResponse {
        object: "list".to_string(),
        data,
        model: req.model,
        usage: EmbeddingsUsage {
            prompt_tokens: total_tokens,
            total_tokens,
        },
    };

    (StatusCode::OK, Json(response)).into_response()
}

/// Handler for GET /v1/inference/models
pub async fn list_models_handler(State(handler): State<InferenceHandler>) -> Response {
    let models = handler.list_models().await;

    #[derive(Serialize)]
    struct ModelsResponse {
        object: String,
        data: Vec<ModelInfo>,
    }

    #[derive(Serialize)]
    struct ModelInfo {
        id: String,
        object: String,
        owned_by: String,
    }

    let response = ModelsResponse {
        object: "list".to_string(),
        data: models
            .into_iter()
            .map(|id| ModelInfo {
                id,
                object: "model".to_string(),
                owned_by: "provider".to_string(),
            })
            .collect(),
    };

    (StatusCode::OK, Json(response)).into_response()
}

#[cfg(test)]
mod tests {
    use super::super::types::BackendCapacity;
    use super::*;

    #[tokio::test]
    async fn test_inference_handler() {
        let quota = Arc::new(QuotaManager::new());
        let handler = InferenceHandler::new(quota);

        // Register a backend
        handler
            .register_backend(ServiceBackend {
                id: "ollama-1".to_string(),
                resource_type: GatewayResourceType::Inference,
                url: "http://localhost:11434".to_string(),
                health_check: "/health".to_string(),
                status: BackendStatus::Healthy,
                capacity: BackendCapacity {
                    models: vec!["llama3.1-70b".to_string(), "mistral".to_string()],
                    ..Default::default()
                },
            })
            .await;

        // List models
        let models = handler.list_models().await;
        assert!(models.contains(&"llama3.1-70b".to_string()));

        // Find backend
        let backend = handler.find_backend("llama3.1-70b").await;
        assert!(backend.is_some());
        assert_eq!(backend.unwrap().id, "ollama-1");

        // Non-existent model
        let backend = handler.find_backend("gpt-5").await;
        assert!(backend.is_none());
    }
}
