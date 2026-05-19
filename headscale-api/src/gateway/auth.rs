//! Gateway authentication middleware.
//!
//! Supports two authentication methods:
//! 1. Lease tokens (preferred) - Bearer tokens with signed lease info
//! 2. DID signatures - For one-off requests without pre-established lease

use std::sync::Arc;
use std::task::{Context, Poll};

use axum::{
    Json,
    body::Body,
    extract::Request,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::prelude::*;
use headscale_identity::{Did, KeyPair};
use tower::{Layer, Service};

const DID_HEADER: &str = "X-DID";
const DID_SIGNATURE_HEADER: &str = "X-DID-Signature";
const DID_TIMESTAMP_HEADER: &str = "X-DID-Timestamp";
const DID_NONCE_HEADER: &str = "X-DID-Nonce";
const DID_SIGNATURE_WINDOW_MILLIS: u64 = 5 * 60 * 1000;

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

    /// Atomically record a DID-auth nonce. Returns false on replay.
    fn check_and_store_nonce(&self, renter_did: &str, nonce: &str, timestamp_millis: u64) -> bool;
}

/// In-memory lease store for testing.
#[derive(Default)]
pub struct InMemoryLeaseStore {
    tokens: std::sync::RwLock<std::collections::HashMap<String, LeaseTokenPayload>>,
    credits: std::sync::RwLock<std::collections::HashSet<String>>,
    nonces: std::sync::RwLock<
        std::collections::HashMap<String, std::collections::HashMap<String, u64>>,
    >,
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

    fn check_and_store_nonce(&self, renter_did: &str, nonce: &str, timestamp_millis: u64) -> bool {
        if nonce.is_empty() || nonce.len() > 128 {
            return false;
        }

        let mut nonces = self.nonces.write().unwrap();
        let did_nonces = nonces.entry(renter_did.to_string()).or_default();
        let oldest_allowed = timestamp_millis.saturating_sub(DID_SIGNATURE_WINDOW_MILLIS);
        did_nonces.retain(|_, seen_at| *seen_at >= oldest_allowed);

        if did_nonces.contains_key(nonce) {
            return false;
        }

        did_nonces.insert(nonce.to_string(), timestamp_millis);
        true
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
    #[error("Signature nonce was already used")]
    NonceReplay,
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
    fn authenticate(&self, req: &Request<Body>) -> Result<GatewayIdentity, AuthError> {
        let headers = req.headers();

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
        if let (Some(did), Some(sig), Some(timestamp), Some(nonce)) = (
            headers.get(DID_HEADER),
            headers.get(DID_SIGNATURE_HEADER),
            headers.get(DID_TIMESTAMP_HEADER),
            headers.get(DID_NONCE_HEADER),
        ) {
            return self.validate_did_signature(
                req.method().as_str(),
                req.uri()
                    .path_and_query()
                    .map_or("/", http::uri::PathAndQuery::as_str),
                did,
                sig,
                timestamp,
                nonce,
            );
        }

        Err(AuthError::MissingAuth)
    }

    fn validate_did_signature(
        &self,
        method: &str,
        path_and_query: &str,
        did: &axum::http::HeaderValue,
        sig: &axum::http::HeaderValue,
        timestamp: &axum::http::HeaderValue,
        nonce: &axum::http::HeaderValue,
    ) -> Result<GatewayIdentity, AuthError> {
        // Parse timestamp
        let timestamp_str = timestamp.to_str().map_err(|_| AuthError::InvalidFormat)?;
        let timestamp_millis: u64 = timestamp_str
            .parse()
            .map_err(|_| AuthError::InvalidFormat)?;

        // Check timestamp is within 5 minutes
        let now = super::types::now_secs() * 1000;
        if timestamp_millis > now.saturating_add(DID_SIGNATURE_WINDOW_MILLIS)
            || now.saturating_sub(timestamp_millis) > DID_SIGNATURE_WINDOW_MILLIS
        {
            return Err(AuthError::TimestampTooOld);
        }

        let renter_did = did
            .to_str()
            .map_err(|_| AuthError::InvalidFormat)?
            .to_string();
        let did = Did::parse(&renter_did).map_err(|_| AuthError::InvalidFormat)?;
        let public_key = did.public_key().map_err(|_| AuthError::InvalidFormat)?;
        let nonce = nonce.to_str().map_err(|_| AuthError::InvalidFormat)?;
        if nonce.is_empty() || nonce.len() > 128 || nonce.bytes().any(|b| !b.is_ascii_graphic()) {
            return Err(AuthError::InvalidFormat);
        }

        let sig_str = sig.to_str().map_err(|_| AuthError::InvalidFormat)?;
        let sig_bytes = BASE64_STANDARD
            .decode(sig_str)
            .map_err(|_| AuthError::InvalidSignature)?;
        let signature: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| AuthError::InvalidSignature)?;

        let message = canonical_did_auth_message(
            method,
            path_and_query,
            &renter_did,
            timestamp_millis,
            nonce,
        );
        if !KeyPair::verify(&public_key, &message, &signature) {
            return Err(AuthError::InvalidSignature);
        }

        if !self
            .store
            .check_and_store_nonce(&renter_did, nonce, timestamp_millis)
        {
            return Err(AuthError::NonceReplay);
        }

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

/// Canonical bytes signed for one-off DID-authenticated gateway requests.
pub fn canonical_did_auth_message(
    method: &str,
    path_and_query: &str,
    did: &str,
    timestamp_millis: u64,
    nonce: &str,
) -> Vec<u8> {
    format!(
        "headscale-gateway-did-auth-v1\n{method}\n{path_and_query}\n{did}\n{timestamp_millis}\n{nonce}\n"
    )
    .into_bytes()
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
            let auth_middleware = AuthMiddleware { inner: (), store };

            match auth_middleware.authenticate(&req) {
                Ok(identity) => {
                    // Add identity to request extensions
                    req.extensions_mut().insert(identity);
                    inner.call(req).await
                }
                Err(e) => {
                    let response = match e {
                        AuthError::MissingAuth | AuthError::InvalidFormat => (
                            StatusCode::UNAUTHORIZED,
                            Json(GatewayErrorResponse::unauthorized(
                                "Missing or invalid authorization",
                            )),
                        )
                            .into_response(),
                        AuthError::InvalidToken | AuthError::InvalidSignature => (
                            StatusCode::UNAUTHORIZED,
                            Json(GatewayErrorResponse::unauthorized("Invalid credentials")),
                        )
                            .into_response(),
                        AuthError::TokenExpired
                        | AuthError::TimestampTooOld
                        | AuthError::NonceReplay => (
                            StatusCode::UNAUTHORIZED,
                            Json(GatewayErrorResponse::unauthorized("Credentials expired")),
                        )
                            .into_response(),
                        AuthError::NoCredit => (
                            StatusCode::PAYMENT_REQUIRED,
                            Json(GatewayErrorResponse::quota_exceeded(0, 0)),
                        )
                            .into_response(),
                        AuthError::ResourceMismatch => (
                            StatusCode::FORBIDDEN,
                            Json(GatewayErrorResponse::unauthorized(
                                "Resource not allowed for this lease",
                            )),
                        )
                            .into_response(),
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
    use axum::http::Method;

    fn signed_request(keypair: &KeyPair, method: Method, uri: &str, nonce: &str) -> Request<Body> {
        let did = keypair.did().to_string();
        let timestamp = super::super::types::now_secs() * 1000;
        let message = canonical_did_auth_message(method.as_str(), uri, &did, timestamp, nonce);
        let signature = BASE64_STANDARD.encode(keypair.sign(&message));

        Request::builder()
            .method(method)
            .uri(uri)
            .header(DID_HEADER, did)
            .header(DID_TIMESTAMP_HEADER, timestamp.to_string())
            .header(DID_NONCE_HEADER, nonce)
            .header(DID_SIGNATURE_HEADER, signature)
            .body(Body::empty())
            .unwrap()
    }

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
                expires_at: super::super::types::now_secs() * 1000 + 3_600_000, // 1 hour from now
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

    #[test]
    fn test_did_signature_authenticates_request() {
        let keypair = KeyPair::generate();
        let did = keypair.did().to_string();
        let store = Arc::new(InMemoryLeaseStore::new());
        store.grant_credit(&did);

        let middleware = AuthMiddleware { inner: (), store };
        let req = signed_request(&keypair, Method::POST, "/v1/inference/chat", "nonce-1");

        let identity = middleware.authenticate(&req).unwrap();
        assert_eq!(identity.renter_did, did);
        assert_eq!(identity.lease_id, None);
    }

    #[test]
    fn test_did_signature_rejects_replay() {
        let keypair = KeyPair::generate();
        let did = keypair.did().to_string();
        let store = Arc::new(InMemoryLeaseStore::new());
        store.grant_credit(&did);

        let middleware = AuthMiddleware { inner: (), store };
        let req = signed_request(&keypair, Method::POST, "/v1/inference/chat", "nonce-2");
        let replay = signed_request(&keypair, Method::POST, "/v1/inference/chat", "nonce-2");

        assert!(middleware.authenticate(&req).is_ok());
        assert!(matches!(
            middleware.authenticate(&replay),
            Err(AuthError::NonceReplay)
        ));
    }

    #[test]
    fn test_did_signature_binds_method_and_path() {
        let keypair = KeyPair::generate();
        let did = keypair.did().to_string();
        let store = Arc::new(InMemoryLeaseStore::new());
        store.grant_credit(&did);

        let middleware = AuthMiddleware { inner: (), store };
        let signed = signed_request(&keypair, Method::POST, "/v1/inference/chat", "nonce-3");
        let mut tampered = signed;
        *tampered.uri_mut() = "/v1/inference/models".parse().unwrap();

        assert!(matches!(
            middleware.authenticate(&tampered),
            Err(AuthError::InvalidSignature)
        ));
    }

    #[test]
    fn test_did_signature_requires_credit_after_signature_verification() {
        let keypair = KeyPair::generate();
        let middleware = AuthMiddleware {
            inner: (),
            store: Arc::new(InMemoryLeaseStore::new()),
        };
        let req = signed_request(&keypair, Method::POST, "/v1/inference/chat", "nonce-4");

        assert!(matches!(
            middleware.authenticate(&req),
            Err(AuthError::NoCredit)
        ));
    }
}
