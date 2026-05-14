//! Gateway authentication middleware.
//!
//! Supports two authentication methods:
//! 1. Lease tokens (preferred) - Bearer tokens with signed lease info
//! 2. DID signatures - For one-off requests without pre-established lease

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use tower::{Layer, Service};

// Note: headscale_identity::Did is available for DID operations

use super::types::{GatewayErrorResponse, GatewayResourceType, LeaseTokenPayload};

/// Identity extracted from authentication.
#[derive(Debug, Clone)]
pub struct GatewayIdentity {
    /// The lease ID (if using lease token auth)
    pub lease_id: Option<String>,
    /// The renter's DID
    pub renter_did: String,
    /// Allowed resource type (from lease or negotiated)
    pub resource_type: Option<GatewayResourceType>,
    /// Token expiry timestamp
    pub expires_at: Option<u64>,
}

/// Lease store for validating tokens.
pub trait LeaseStore: Send + Sync {
    /// Validate a lease token and return the payload if valid.
    fn validate_token(&self, token: &str) -> Result<LeaseTokenPayload, AuthError>;

    /// Check if a renter DID has credit balance for one-off requests.
    fn has_credit(&self, renter_did: &str) -> bool;
}

/// In-memory lease store for testing.
#[derive(Default)]
pub struct InMemoryLeaseStore {
    tokens: std::sync::RwLock<std::collections::HashMap<String, LeaseTokenPayload>>,
    credits: std::sync::RwLock<std::collections::HashSet<String>>,
}

impl InMemoryLeaseStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a valid token.
    pub fn add_token(&self, token: String, payload: LeaseTokenPayload) {
        self.tokens.write().unwrap().insert(token, payload);
    }

    /// Grant credit to a DID.
    pub fn grant_credit(&self, did: &str) {
        self.credits.write().unwrap().insert(did.to_string());
    }
}

impl LeaseStore for InMemoryLeaseStore {
    fn validate_token(&self, token: &str) -> Result<LeaseTokenPayload, AuthError> {
        let tokens = self.tokens.read().unwrap();
        let payload = tokens.get(token).ok_or(AuthError::InvalidToken)?;

        // Check expiry
        let now = super::types::now_secs() * 1000; // convert to millis
        if payload.expires_at < now {
            return Err(AuthError::TokenExpired);
        }

        Ok(payload.clone())
    }

    fn has_credit(&self, renter_did: &str) -> bool {
        self.credits.read().unwrap().contains(renter_did)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Missing authorization header")]
    MissingAuth,
    #[error("Invalid authorization format")]
    InvalidFormat,
    #[error("Invalid token")]
    InvalidToken,
    #[error("Token expired")]
    TokenExpired,
    #[error("Invalid DID signature")]
    InvalidSignature,
    #[error("Timestamp too old")]
    TimestampTooOld,
    #[error("No credit balance")]
    NoCredit,
    #[error("Resource type mismatch")]
    ResourceMismatch,
}

/// Authentication layer for the gateway.
#[derive(Clone)]
pub struct AuthLayer<S> {
    store: Arc<dyn LeaseStore>,
    _marker: std::marker::PhantomData<S>,
}

impl<S> AuthLayer<S> {
    pub fn new(store: Arc<dyn LeaseStore>) -> Self {
        Self {
            store,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S> Layer<S> for AuthLayer<S> {
    type Service = AuthMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthMiddleware {
            inner,
            store: self.store.clone(),
        }
    }
}

/// Authentication middleware.
#[derive(Clone)]
pub struct AuthMiddleware<S> {
    inner: S,
    store: Arc<dyn LeaseStore>,
}

impl<S> AuthMiddleware<S> {
    /// Extract identity from request headers.
    fn authenticate(&self, headers: &HeaderMap) -> Result<GatewayIdentity, AuthError> {
        // Try Bearer token first
        if let Some(auth) = headers.get(header::AUTHORIZATION) {
            let auth_str = auth.to_str().map_err(|_| AuthError::InvalidFormat)?;

            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let payload = self.store.validate_token(token)?;
                return Ok(GatewayIdentity {
                    lease_id: Some(payload.lease_id),
                    renter_did: payload.renter_did,
                    resource_type: Some(payload.resource_type),
                    expires_at: Some(payload.expires_at),
                });
            }
        }

        // Try DID signature
        if let (Some(sig), Some(timestamp)) = (
            headers.get("X-DID-Signature"),
            headers.get("X-DID-Timestamp"),
        ) {
            return self.validate_did_signature(headers, sig, timestamp);
        }

        Err(AuthError::MissingAuth)
    }

    fn validate_did_signature(
        &self,
        headers: &HeaderMap,
        sig: &axum::http::HeaderValue,
        timestamp: &axum::http::HeaderValue,
    ) -> Result<GatewayIdentity, AuthError> {
        // Parse timestamp
        let timestamp_str = timestamp.to_str().map_err(|_| AuthError::InvalidFormat)?;
        let timestamp_millis: u64 = timestamp_str
            .parse()
            .map_err(|_| AuthError::InvalidFormat)?;

        // Check timestamp is within 5 minutes
        let now = super::types::now_secs() * 1000;
        let five_minutes = 5 * 60 * 1000;
        if now.saturating_sub(timestamp_millis) > five_minutes {
            return Err(AuthError::TimestampTooOld);
        }

        // Parse DID from signature (format: did:key:...|base64sig)
        let sig_str = sig.to_str().map_err(|_| AuthError::InvalidFormat)?;
        let parts: Vec<&str> = sig_str.split('|').collect();
        if parts.len() != 2 {
            return Err(AuthError::InvalidFormat);
        }

        let renter_did = parts[0].to_string();

        // In production, we'd verify the signature here using the DID's public key.
        // For now, just check if the DID has credit.
        if !self.store.has_credit(&renter_did) {
            return Err(AuthError::NoCredit);
        }

        Ok(GatewayIdentity {
            lease_id: None,
            renter_did,
            resource_type: None, // No specific resource type for DID auth
            expires_at: None,
        })
    }
}

impl<S> Service<Request<Body>> for AuthMiddleware<S>
where
    S: Service<Request<Body>, Response = Response> + Clone + Send + 'static,
    S::Future: Send,
{
    type Response = Response;
    type Error = S::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        let store = self.store.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            // Authenticate
            let auth_middleware = AuthMiddleware {
                inner: (),
                store,
            };

            match auth_middleware.authenticate(req.headers()) {
                Ok(identity) => {
                    // Add identity to request extensions
                    req.extensions_mut().insert(identity);
                    inner.call(req).await
                }
                Err(e) => {
                    let response = match e {
                        AuthError::MissingAuth | AuthError::InvalidFormat => {
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(GatewayErrorResponse::unauthorized("Missing or invalid authorization")),
                            )
                                .into_response()
                        }
                        AuthError::InvalidToken | AuthError::InvalidSignature => {
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(GatewayErrorResponse::unauthorized("Invalid credentials")),
                            )
                                .into_response()
                        }
                        AuthError::TokenExpired | AuthError::TimestampTooOld => {
                            (
                                StatusCode::UNAUTHORIZED,
                                Json(GatewayErrorResponse::unauthorized("Credentials expired")),
                            )
                                .into_response()
                        }
                        AuthError::NoCredit => {
                            (
                                StatusCode::PAYMENT_REQUIRED,
                                Json(GatewayErrorResponse::quota_exceeded(0, 0)),
                            )
                                .into_response()
                        }
                        AuthError::ResourceMismatch => {
                            (
                                StatusCode::FORBIDDEN,
                                Json(GatewayErrorResponse::unauthorized("Resource not allowed for this lease")),
                            )
                                .into_response()
                        }
                    };
                    Ok(response)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_store() {
        let store = InMemoryLeaseStore::new();

        // Add a token
        store.add_token(
            "test_token".to_string(),
            LeaseTokenPayload {
                lease_id: "lease_123".to_string(),
                renter_did: "did:key:test".to_string(),
                resource_type: GatewayResourceType::Inference,
                expires_at: super::super::types::now_secs() * 1000 + 3600000, // 1 hour from now
            },
        );

        // Validate
        let result = store.validate_token("test_token");
        assert!(result.is_ok());
        let payload = result.unwrap();
        assert_eq!(payload.lease_id, "lease_123");
    }

    #[test]
    fn test_expired_token() {
        let store = InMemoryLeaseStore::new();

        // Add expired token
        store.add_token(
            "expired_token".to_string(),
            LeaseTokenPayload {
                lease_id: "lease_123".to_string(),
                renter_did: "did:key:test".to_string(),
                resource_type: GatewayResourceType::Inference,
                expires_at: 1000, // Far in the past
            },
        );

        let result = store.validate_token("expired_token");
        assert!(matches!(result, Err(AuthError::TokenExpired)));
    }

    #[test]
    fn test_credit_check() {
        let store = InMemoryLeaseStore::new();
        assert!(!store.has_credit("did:key:test"));

        store.grant_credit("did:key:test");
        assert!(store.has_credit("did:key:test"));
    }
}
