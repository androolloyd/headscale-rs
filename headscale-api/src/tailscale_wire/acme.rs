//! ACME challenge-serving primitives.
//!
//! Full certificate issuance is still owned by the server runtime. This module
//! provides the public HTTP-01 serving surface that an issuer can populate while
//! preserving headscale-go's `/.well-known/acme-challenge/{token}` behavior.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::{
    Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use parking_lot::RwLock;

/// In-memory HTTP-01 challenge material keyed by ACME token.
#[derive(Clone, Debug, Default)]
pub struct AcmeHttp01ChallengeStore {
    challenges: Arc<RwLock<BTreeMap<String, String>>>,
}

impl AcmeHttp01ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert or replace the key authorization for `token`.
    pub fn insert(&self, token: impl Into<String>, key_authorization: impl Into<String>) {
        self.challenges
            .write()
            .insert(token.into(), key_authorization.into());
    }

    /// Remove a token after validation has completed or failed.
    pub fn remove(&self, token: &str) -> Option<String> {
        self.challenges.write().remove(token)
    }

    pub fn get(&self, token: &str) -> Option<String> {
        self.challenges.read().get(token).cloned()
    }
}

pub fn http01_router(store: AcmeHttp01ChallengeStore) -> Router {
    Router::new()
        .route(
            "/.well-known/acme-challenge/:token",
            get(handle_http01_challenge),
        )
        .with_state(store)
}

async fn handle_http01_challenge(
    State(store): State<AcmeHttp01ChallengeStore>,
    Path(token): Path<String>,
) -> Response {
    let Some(key_authorization) = store.get(&token) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        key_authorization,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use tower::ServiceExt;

    #[tokio::test]
    async fn http01_router_serves_registered_key_authorization() {
        let store = AcmeHttp01ChallengeStore::new();
        store.insert("token-123", "token-123.thumbprint");
        let app = http01_router(store);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/acme-challenge/token-123")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok()),
            Some("text/plain; charset=utf-8")
        );
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        assert_eq!(body.as_ref(), b"token-123.thumbprint");
    }

    #[tokio::test]
    async fn http01_router_returns_not_found_for_unknown_or_removed_token() {
        let store = AcmeHttp01ChallengeStore::new();
        store.insert("token-123", "token-123.thumbprint");
        assert_eq!(
            store.remove("token-123").as_deref(),
            Some("token-123.thumbprint")
        );
        let app = http01_router(store);

        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/acme-challenge/token-123")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
